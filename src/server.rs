// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for BFF.

use std::sync::Arc;

use axum::routing::{get, post, Router};
use tower_http::cors::CorsLayer;

use crate::chat;
use crate::ciba;
use crate::config::Bff8Config;
use crate::subscribe;
use sentin8::middleware::http_client::Sentin8HttpClient;

use crate::handlers::{self, AppState};
use crate::proxy::ProxyState;
use crate::session::SessionStore;
use crate::sessions;

pub async fn serve(
    config: Bff8Config,
    addr: String,
    tls: sentin8::tls::Sentin8Tls,
) -> anyhow::Result<()> {
    let store = SessionStore::new(&config.valkey_url, config.session_idle_ttl).await?;
    // KeyRing rotation (bff DESIGN §6.2): spawn the session re-wrap task
    // when retained keys are configured - old-key blobs are re-encrypted
    // under the current key in the background.
    if !config.retained_encryption_keys.is_empty() {
        crate::key_rotation::spawn_session_rewrap(
            store.clone(),
            config.encryption_key.clone(),
            config.retained_encryption_keys.clone(),
        );
    }
    let pool = sentin8::config::pg_pool::connect(&config.database_url).await?;
    // Enforce PostgreSQL 18+ (the platform's required database version).
    sentin8::config::Sentin8Config::enforce_postgres_version(&pool)
        .await
        .expect("PostgreSQL 18+ required");

    // auth DESIGN §4.3f: the `bff-delegator` CERTIFICATE is
    // the identity - ensured (load-or-mint from Acme) in the background;
    // the Delegation Gateway presents it on every call. The old
    // env-credential override (`SENTIN8_BFF_M2M_CLIENT_ID/SECRET`) is
    // retired with the workload M2M token it fed.
    register_delegator_m2m_client(&config).await;

    // ── Sentin8:Policy (- boot_full): bff is a custom-boot
    // binary (cookie sessions, no shell serve), so it runs the ONE shared
    // boot helper itself - same four steps the shell runs for every other
    // service. No second engine may be constructed.
    let policy_engine = sentin8::shield::runtime::engine_for("sentin8:bff");
    sentin8::shield::runtime::boot_full(
        &pool,
        &config.sentin8_auth_base_url,
        "sentin8:bff",
        &policy_engine,
    )
    .await?;

    let app_state = AppState {
        config: Arc::new(config.clone()),
        store: store.clone(),
        pool: pool.clone(),
        // the `bff` workload CERTIFICATE is the identity.
        sentin8_bus_consumer_client: sentin8::bus::client::BusClient::for_workload(
            &sentin8::config::Sentin8Config::from_env().sentin8_bus_url(),
            &config.sentin8_auth_base_url,
            "bff",
        )
        .await
        .expect("bff bus consumer certificate"),
        policy: policy_engine,
    };

    // Clone valkey_url before config is moved into Arc::new(config).
    let valkey_url = config.valkey_url.clone();

    // Session-reaper (bff DESIGN §10, continuous access evaluation):
    // subscribes to the `auth` stream family and kills cached BFF
    // sessions for subjects whose Auth sessions/tokens were revoked
    // (`sentin8:auth:session:revoked`, group `bff-session-reaper`).
    // Spawned before the states are moved into the router - the store
    // and bus client are shared clones, not move-outs.
    subscribe::session_revocation::spawn(
        app_state.sentin8_bus_consumer_client.clone(),
        store.clone(),
    );

    // Push subscription sink (BFF-5): the bff-post pusher drains BFF's local
    // `post_outbox` to Post's send API (M2M, `sentin8:post:write`) - no
    // direct post.inbox writes. Identity + token source resolve lazily on
    // the first pass (a boot-time DCR failure only delays the drain; rows
    // stay queued).
    {
        let cfg0 = sentin8::config::Sentin8Config::from_env();
        subscribe::push::spawn_push_bridger(
            app_state.pool.clone(),
            cfg0.sentin8_post_url(),
            cfg0.sentin8_auth_issuer(),
        );
        subscribe::push::set_pool(app_state.pool.clone());
    }

    // Backend service URLs are resolved dynamically per-request from the
    // request hostname (which encodes the tenant env domain). BFF serves
    // multiple tenants - each at `bff.{env_domain}` - so the backend URL
    // for service X is `https://{svc}.{env_domain}`. This ensures all
    // traffic goes through TLS with the correct tenant context.
    let proxy_state = Arc::new(ProxyState {
        store,
        config: Arc::new(config),
        pool: pool.clone(),
        //server-side tagging. Default to a no-op tagger;
        // app-instance-specific taggers are wired per request in production.
        tagger: Arc::new(crate::tagging::NoopTagger),
        // Shared pooled HTTP client for all proxy forwards (avoids building a
        // fresh reqwest::Client per request, which starves the connection pool
        // and causes intermittent 502s under load).
        http: Sentin8HttpClient::new(),
    });

    let counter = sentin8::middleware::RequestCounter::new();
    sentin8::middleware::spawn_flush_loop(
        counter.clone(),
        // override → else the plane-derived URL.
        std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(sentin8::config::service_valkey_url),
        10,
    );

    let auth_routes = Router::new()
        .route("/auth/login", get(handlers::auth_login))
        .route("/auth/sign-up", get(handlers::auth_sign_up))
        .route("/auth/callback", get(handlers::auth_callback))
        .route("/auth/session", get(handlers::auth_session))
        .route("/auth/sign-out", post(handlers::auth_sign_out))
        .route("/auth/refresh", post(handlers::auth_refresh))
        // Multi-session device management (bff DESIGN §4): the caller's active
        // sessions, per-session detail, per-session revoke (record destroy +
        // stored refresh-token revoke), revoke-all-others (current excluded).
        .route(
            "/v1/auth/sessions",
            get(sessions::list_sessions).delete(sessions::revoke_other_sessions),
        )
        .route(
            "/v1/auth/sessions/{id}",
            get(sessions::get_session).delete(sessions::revoke_session),
        )
        // Generic service action proxy - forwards to any registered
        // service action (registered via `sentin8-cli vertical enroll`).
        // The frontend calls POST /bff/action/{action} with a JSON body;
        // BFF looks up the target URL/method from the registry and proxies.
        .route("/bff/action/{action}", post(handlers::service_action))
        // Delegation Gateway - replaces CIBA endpoints
        .route("/delegate/start", post(ciba::delegate_start))
        .route("/delegate/poll", post(ciba::delegate_poll))
        .route("/delegate/status", get(ciba::delegate_status))
        .route("/delegate/send-link", post(ciba::delegate_send_link))
        // SCIM proxy - full SCIM 2.0 operations proxied to env-scoped Auth
        .route(
            "/delegate/scim/users",
            get(ciba::delegate_scim_list).post(ciba::delegate_scim_create),
        )
        .route(
            "/delegate/scim/users/{id}",
            get(ciba::delegate_scim_get)
                .put(ciba::delegate_scim_replace)
                .patch(ciba::delegate_scim_patch)
                .delete(ciba::delegate_scim_delete),
        )
        // SSE subscription tier - (SSE migration)
        // GET /subscribe opens the SSE stream; POST/DELETE manage the
        // subscription set via HTTP/2 mutations.
        .route(
            "/subscribe",
            get(subscribe::subscribe_handler)
                .post(subscribe::subscribe_change)
                .delete(subscribe::subscribe_close),
        )
        // Push subscription sink (BFF-5): session-bound device-token registry -
        // subscription events bridge to Post's push gateway via the local
        // post_outbox + bff-post pusher.
        .route(
            "/subscribe/push",
            post(subscribe::subscribe_push_register).delete(subscribe::subscribe_push_delete),
        )
        // WebSocket chat tier - (chat-only)
        .route("/ws", get(chat::ws_handler))
        .route("/audit", post(handlers::audit_event))
        .route("/v1/health", get(handlers::health))
        .route("/readiness", get(handlers::readiness))
        .route("/metrics", get(handlers::metrics))
        .with_state(app_state);

    // Use `fallback` for the catch-all proxy. `Router::route("/{*path}", ...)`
    // would conflict with the static routes above because axum requires
    // catch-all parameters to be registered last. `fallback` is the
    // canonical place for a last-resort handler.
    let app = Router::new()
        .merge(auth_routes)
        .fallback(axum::routing::any(crate::proxy::proxy))
        .with_state(proxy_state)
        // Traffic counter - counts every inbound request (excludes health checks).
        .layer(axum::middleware::from_fn_with_state(
            counter,
            sentin8::middleware::traffic_counter_layer,
        ))
        // Correlation / tenant context / per-request logging
        .layer(axum::middleware::from_fn(
            sentin8::middleware::sentin8_tls_context,
        ))
        .layer(axum::middleware::from_fn_with_state(
            sentin8::tls::ContextMiddlewareState {
                resolver: tls.host_context_resolver(),
            },
            sentin8::tls::context_middleware,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::request_logging,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::correlation_id,
        ))
        // CORS: with credentials: include, Access-Control-Allow-Origin: *
        // and Access-Control-Allow-Headers: * are NOT valid. We must
        // explicitly allow the origin, methods, and list all custom headers.
        // In development, we reflect the request origin (any subdomain
        // of local.sentin8.dev) and allow all custom headers.
        .layer({
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                    axum::http::Method::PATCH,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    axum::http::HeaderName::from_static("x-bff-csrf"),
                    axum::http::HeaderName::from_static("x-sentin8-correlation-id"),
                    axum::http::HeaderName::from_static("x-bff-target-org-id"),
                    axum::http::HeaderName::from_static("x-bff-target-env-id"),
                    // Option A - CIBA delegation attach.
                    // Missing here made every delegated app call fail the
                    // CORS preflight at the browser (TypeError: Failed to
                    // fetch).
                    axum::http::HeaderName::from_static("x-bff-delegation"),
                    axum::http::HeaderName::from_static("authorization"),
                ])
                .allow_credentials(true)
        });

    tracing::info!("bff listening on {addr}");

    // Spawn the stat rollups Valkey subscriber - replaces the Bus
    // stat.traffic.snapshot path. Listens to `stat:rollups:minute`
    // and pushes to all active SSE sessions subscribed to
    // `stat.traffic.snapshot`.
    subscribe::stat_valkey::spawn(valkey_url);

    tls.serve(&addr, app, "bff").await?;
    Ok(())
}

///Register BFF's delegator M2M client via DCR (RFC 7591).
///
/// Returns immediately. If credentials aren't in the DB yet, spawns a
/// background task that retries DCR until Auth is reachable (which
/// requires the TLS listener to be serving). When DCR succeeds, the
/// auth DESIGN §4.3f: ensure the `bff-delegator` workload
/// CERTIFICATE (load-or-mint from Acme - the certificate IS the identity;
/// no DCR, no M2M token) and install the cert paths + the mTLS auth
/// client for the Delegation Gateway. Delegation calls present the
/// certificate; the delegated JWT flow (RFC 8693) keeps its own tokens.
/// The mint retries while Acme comes up - the gateway degrades until the
/// identity exists, then heals without a restart.
async fn register_delegator_m2m_client(config: &Bff8Config) {
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let auth_url = config.sentin8_auth_base_url.clone();
    let bg_auth_client = config.auth_client.clone();
    tokio::spawn(async move {
        loop {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &auth_url,
                "bff-delegator",
                &ca_cert_path,
            )
            .await
            {
                Ok(cert) => {
                    crate::proxy::set_m2m_cert_paths(
                        cert.cert_path.clone(),
                        cert.key_path.clone(),
                        ca_cert_path.clone(),
                    );
                    // - delegation calls must present the client cert.
                    crate::proxy::install_mtls_auth_client(
                        &bg_auth_client,
                        &cert.cert_path,
                        &cert.key_path,
                        &ca_cert_path,
                    );
                    tracing::info!(
                        workload = "bff-delegator",
                        "bff-delegator: certificate identity installed (Delegation Gateway ready)"
                    );
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "bff-delegator: certificate not ready yet");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
    });
}
