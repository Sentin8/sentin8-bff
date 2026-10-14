// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Push subscription sink (BFF-5, bff DESIGN §10): a third subscription
//! transport alongside SSE. A client registers a device token with
//! `POST /subscribe/push` (session-bound); the bridge task forwards every
//! subscription event for that session to Sentin8:Post's `POST /v1/send`
//! (M2M `bff-post`, scope `sentin8:post:write`) as a `push`-channel
//! message — Post's gateway adapter delivers it (stub today, real FCM/
//! APNs adapters drop in behind the same contract, POST-4).
//!
//! Delivery rides the DBX pattern: the bridge enqueues into BFF's LOCAL
//! `post_outbox` and the `bff-post` pusher drains it (no direct
//! `post.inbox` writes — the producer holds no grant on Post's tables).

use sqlx::PgPool;
use uuid::Uuid;

/// Register (or replace) a device token for the caller's session. One
/// token per session — re-registering replaces it.
pub async fn register_push_token(
    pool: &PgPool,
    env_id: Uuid,
    session_id: &str,
    user_id: &str,
    token: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("pool: {e}"),
        )
    })?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO push_tokens (env_id, session_id, user_id, device_token)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (env_id, session_id) DO UPDATE
             SET device_token = EXCLUDED.device_token, user_id = EXCLUDED.user_id,
                 updated_at = now()"#,
    )
    .bind(env_id)
    .bind(session_id)
    .bind(user_id)
    .bind(token)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("insert: {e}"),
        )
    })?;
    tx.commit().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("commit: {e}"),
        )
    })?;
    Ok(())
}

/// Remove a session's push registration (logout/unsubscribe).
pub async fn delete_push_token(
    pool: &PgPool,
    env_id: Uuid,
    session_id: &str,
) -> Result<u64, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("pool: {e}"),
        )
    })?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let n = sqlx::query("DELETE FROM push_tokens WHERE env_id = $1 AND session_id = $2")
        .bind(env_id)
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("delete: {e}"),
            )
        })?
        .rows_affected();
    tx.commit().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("commit: {e}"),
        )
    })?;
    Ok(n)
}

/// Resolve a session's device token + user id (the bridge calls this per
/// event). `None` = no push registration for the session.
pub async fn push_token_for_session(
    pool: &PgPool,
    session_id: &str,
) -> Option<(Uuid, String, String)> {
    let mut tx = pool.begin().await.ok()?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await
        .ok()?;
    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        r#"SELECT env_id, user_id, device_token
             FROM push_tokens
            WHERE session_id = $1
            ORDER BY updated_at DESC LIMIT 1"#,
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()?;
    tx.commit().await.ok()?;
    Some(row)
}

/// Spawn the push bridge: drains BFF's local `post_outbox` (rows the
/// event fan-out enqueues for push-registered sessions) to Post's
/// `POST /v1/send` with the process-lifetime `bff-post` M2M token source
/// (`sentin8:post:write`). Mirrors the sys-post pusher (sys DESIGN §10).
pub fn spawn_push_bridger(pool: PgPool, post_url: String, auth_issuer: String) {
    tokio::spawn(async move {
        // auth DESIGN §4.3f: the `bff-post` CERTIFICATE is the
        // identity — ensure it once (mint retries while Acme comes up),
        // then build the ONE cert-presenting client for the task
        // lifetime. No token exists on this path.
        let cert = loop {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &auth_issuer,
                "bff-post",
                &sentin8::auth::m2m::platform_ca_path(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    tracing::debug!(error = %e, "bff: post push certificate not ready yet");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        let client = match sentin8::middleware::mtls::build_mtls_client(&mtls) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "bff: post push transport build failed — bridge disabled");
                return;
            }
        };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            if let Err(e) = drain_and_push(&pool, &client, &post_url).await {
                tracing::warn!(error = %e, "bff: push bridge pass failed");
            }
        }
    });
}

/// One drain pass: list envs with unpushed rows (SECURITY DEFINER
/// helper), read each batch under its env's context, push each to
/// `POST /v1/send` (per-row `X-Sentin8-Env-Id`), mark pushed on 2xx.
async fn drain_and_push(
    pool: &PgPool,
    client: &reqwest::Client,
    post_url: &str,
) -> anyhow::Result<usize> {
    let envs: Vec<Uuid> = sqlx::query_scalar("SELECT env_id FROM bff_post_outbox_unpushed_envs()")
        .fetch_all(pool)
        .await?;
    let mut pushed = 0usize;
    for env_id in envs {
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let rows = sqlx::query_as::<
            _,
            (
                uuid::Uuid,
                Uuid,
                Option<uuid::Uuid>,
                Option<String>,
                String,
                String,
                serde_json::Value,
            ),
        >(
            r#"SELECT id, env_id, recipient_user_id, recipient_device_token,
                      subject, body, metadata
                 FROM post_outbox WHERE pushed = false ORDER BY created_at LIMIT 50"#,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        for (id, _env, recipient_user_id, recipient_device_token, subject, body, metadata) in rows {
            let payload = serde_json::json!({
                "message_type": "bff:subscription:event",
                "category": "system",
                "priority": "normal",
                "recipient_user_id": recipient_user_id,
                "recipient_device_token": recipient_device_token,
                "subject": subject,
                "body": body,
                "metadata": metadata,
            });
            let resp = client
                .post(format!("{}/v1/send", post_url.trim_end_matches('/')))
                .header("X-Sentin8-Env-Id", env_id.to_string())
                .json(&payload)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let mut tx = pool.begin().await?;
                    let _ = sqlx::query(
                        "SELECT sentin8_set_tenant_context($1, '', '', '', false, false)",
                    )
                    .bind(env_id)
                    .execute(&mut *tx)
                    .await;
                    let n = sqlx::query(
                        "UPDATE post_outbox SET pushed = true, pushed_at = now() WHERE id = $1 AND pushed = false",
                    )
                    .bind(id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                    tx.commit().await?;
                    pushed += n as usize;
                }
                Ok(r) => {
                    tracing::warn!(status = %r.status(), message_id = %id, "bff: post push send rejected — will retry");
                }
                Err(e) => {
                    tracing::warn!(error = %e, message_id = %id, "bff: post push send failed — will retry");
                }
            }
            if pushed >= 100 {
                return Ok(pushed);
            }
        }
    }
    Ok(pushed)
}


/// Process-global pool handle for the fan-out tap (set at boot; the SSE
/// `push_event` spawns best-effort enqueues through it).
static POOL: std::sync::OnceLock<PgPool> = std::sync::OnceLock::new();

/// Set the process pool handle (called at boot, once).
pub fn set_pool(pool: PgPool) {
    let _ = POOL.set(pool);
}

/// The process pool handle (the fan-out tap reads it).
pub fn pool_handle() -> Option<PgPool> {
    POOL.get().cloned()
}

/// Enqueue a subscription event for a session's push registration
/// (BFF-5). Best-effort: no registration → Ok(false); DB error → Err
/// (logged by the caller, the SSE stream is unaffected). The event's
/// `type` field becomes the subject; the payload rides `metadata`.
pub async fn enqueue_for_session(
    pool: &PgPool,
    session_id: &str,
    event: &serde_json::Value,
) -> Result<bool, sqlx::Error> {
    let Some((env_id, user_id, device_token)) = push_token_for_session(pool, session_id).await
    else {
        return Ok(false);
    };
    let event_type = event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("subscription.event")
        .to_string();
    let body = serde_json::to_string(event).unwrap_or_default();
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO post_outbox (env_id, message_type, category, priority,
           recipient_user_id, recipient_device_token, subject, body, metadata)
           VALUES ($1, $2, 'system', 'normal', $3, $4, $5, $6, $7)"#,
    )
    .bind(env_id)
    .bind("bff:subscription:event")
    .bind(uuid::Uuid::parse_str(&user_id).ok())
    .bind(&device_token)
    .bind(&event_type)
    .bind(body.chars().take(2000).collect::<String>())
    .bind(event)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}
