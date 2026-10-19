// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Delegation push - background CIBA poll task that pushes results over SSE.
//!
//! When a client calls `POST /delegate/start` and has an active SSE
//! subscription (`GET /subscribe?types=sentin8:delegation.result`), BFF starts a
//! background poll task that polls Auth's CIBA token endpoint and pushes
//! the result over the SSE subscription stream when the poll completes.
//! This eliminates the need for client-side polling.
//!
//! Design:

use crate::subscribe::sse::push_event;

/// Start a background delegation poll task that pushes the result over
/// the client's SSE subscription stream.
///
/// Called from `ciba::delegate_start` when the SSE stream is active. Polls
/// Auth's CIBA token endpoint at the specified interval and pushes the
/// result via `push_event` when the status changes.
pub async fn start_delegation_poll(
    session_id: String,
    delegation_id: String,
    auth_req_id: String,
    sentin8_auth_url: String,
    oauth_client_id: String,
    interval_secs: u64,
    valkey_url: String,
) {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(_) => return,
        };

        let max_polls = 60; // 5 min at 5s interval
        for _ in 0..max_polls {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            let form = vec![
                (
                    "grant_type".to_string(),
                    // RFC 9126 registered CIBA URN - must match the grant router in
                    // Sentin8:Auth (oauth.rs) and `ciba.rs` delegate_poll. The previous
                    // `urn:openid:params:...` name returned 400 unsupported_grant_type
                    // forever, so the delegated token was never minted.
                    "urn:ietf:params:oauth:grant-type:ciba".to_string(),
                ),
                ("auth_req_id".to_string(), auth_req_id.clone()),
                ("client_id".to_string(), oauth_client_id.clone()),
            ];

            // - under `fapi_2` the CIBA grant requires a DPoP proof
            // for non-exempt clients (same as ciba.rs delegate_poll).
            let dpop = match sentin8::auth::fapi::dpop_proof(
                "POST",
                &format!("{}/oauth/token", sentin8_auth_url.trim_end_matches('/')),
                None,
                &crate::handlers::dpop_key_pem(),
                jsonwebtoken::Algorithm::ES256,
            ) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let resp = match client
                .post(format!(
                    "{}/oauth/token",
                    sentin8_auth_url.trim_end_matches('/')
                ))
                .header("DPoP", dpop)
                .form(&form)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let status_code = resp.status();
            let body: serde_json::Value = match resp.json().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if status_code == axum::http::StatusCode::BAD_REQUEST {
                let error = body["error"].as_str().unwrap_or("unknown");
                if error == "authorization_pending" || error == "slow_down" {
                    continue;
                }
                if error == "access_denied" {
                    push_event(
                        &session_id,
                        serde_json::json!({
                            "type": "sentin8:delegation:result",
                            "delegation_id": delegation_id,
                            "status": "denied",
                        }),
                    )
                    .await;
                    return;
                }
                if error == "expired_token" {
                    push_event(
                        &session_id,
                        serde_json::json!({
                            "type": "sentin8:delegation:result",
                            "delegation_id": delegation_id,
                            "status": "expired",
                        }),
                    )
                    .await;
                    return;
                }
                // Unknown 400 (e.g. unsupported_grant_type / invalid_client)
                // is a configuration defect, not a transient condition -
                // pushing a terminal error makes it visible instead of
                // silently burning the whole retry budget.
                push_event(
                    &session_id,
                    serde_json::json!({
                        "type": "sentin8:delegation:result",
                        "delegation_id": delegation_id,
                        "status": "failed",
                        "error": error,
                    }),
                )
                .await;
                return;
            }

            if !status_code.is_success() {
                continue;
            }

            // Success - customer approved.
            let delegation_token = body["access_token"].as_str().unwrap_or("");
            let expires_in = body["expires_in"].as_u64().unwrap_or(300);
            let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;

            // Cache the delegation token in Valkey.
            if !delegation_token.is_empty() {
                let valkey_client =
                    match sentin8::middleware::valkey_client(&valkey_url, "sentin8:bff").await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                let conn = match Ok::<_, glide::GlideError>(valkey_client.clone()) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                use glide::AsyncCommands;
                let token_key = format!("bff:delegation_token:{delegation_id}");
                let _: () = conn
                    .set_ex(&token_key, delegation_token, expires_in)
                    .await
                    .unwrap_or(());
                let meta_key = format!("bff:delegation_token:{delegation_id}:meta");
                let scope = body["scope"].as_str().unwrap_or("");
                let meta = serde_json::json!({
                    "expires_at": expires_at,
                    "scope": scope,
                    "delegation_id": delegation_id,
                });
                let _: () = conn
                    .set_ex(&meta_key, meta.to_string(), expires_in)
                    .await
                    .unwrap_or(());
            }

            push_event(
                &session_id,
                serde_json::json!({
                    "type": "sentin8:delegation:result",
                    "delegation_id": delegation_id,
                    "status": "approved",
                    "expires_at": expires_at,
                }),
            )
            .await;
            return;
        }

        // Timed out - push expired.
        push_event(
            &session_id,
            serde_json::json!({
                "type": "sentin8:delegation:result",
                "delegation_id": delegation_id,
                "status": "expired",
            }),
        )
        .await;
    });
}
