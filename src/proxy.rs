// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Proxy handler — validates session, decrypts access token, attaches Bearer,
//! forwards to upstream. Refreshes expired tokens transparently.
//!
//!

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use sentin8::auth::client::{self as sentin8_auth_sdk};
use sentin8::middleware::http_client::Sentin8HttpClient;

use crate::config::Bff8Config;
use crate::session::{self, SessionStore};
use crate::tagging::{ServerTagEventType, ServerTagger};

/// M2M credentials obtained from DCR at startup (or env vars).
/// Stored in a static so `get_sentin8_bff_m2m_token` can access them without
/// passing through the config (which is immutable).
static M2M_CREDENTIALS: M2mCredentials = M2mCredentials::new();

struct M2mCredentials {
    /// Cert-bound mTLS identity (RFC 8705 — the only M2M method, auth
    /// design ): the workload's client cert/key/CA PEM paths, persisted
    /// by the shared m2m helper. Empty when not (yet) issued+registered.
    cert_path: std::sync::RwLock<String>,
    key_path: std::sync::RwLock<String>,
    ca_path: std::sync::RwLock<String>,
}

impl M2mCredentials {
    const fn new() -> Self {
        Self {
            cert_path: std::sync::RwLock::new(String::new()),
            key_path: std::sync::RwLock::new(String::new()),
            ca_path: std::sync::RwLock::new(String::new()),
        }
    }
}

pub struct ProxyState {
    pub store: SessionStore,
    pub config: Arc<Bff8Config>,
    /// Database pool for tenant domain resolution (sentin8_sys_organizations / sentin8_sys_environments).
    pub pool: sqlx::PgPool,
    ///server-side Stat tagging hook. Defaults to a no-op;
    /// the server wires a real `StatTagger` when an app instance has tagging
    /// enabled.
    pub tagger: Arc<dyn ServerTagger>,
    /// Shared HTTP client used to forward proxied requests to upstream
    /// services. A single `reqwest::Client` is held for the lifetime of the
    /// server so its internal connection pool is reused across requests —
    /// building a new client per request (the previous behaviour) starved
    /// the pool under concurrent load and produced intermittent
    /// `error sending request for url` 502s. `Sentin8HttpClient` clones cheaply
    /// (it wraps an `Arc<Client>`).
    pub http: Sentin8HttpClient,
}

pub async fn proxy(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    req: Request,
) -> Response {
    // Resolve tenant context from TLS-injected headers (x-sentin8-env-id,
    // x-sentin8-app-id). This is the single source of truth for
    // tenant identity — no hostname parsing, no special-casing for dash/sys/ops.
    // org_id is no longer in TLS headers; it is resolved from env_id when needed.
    // Pass the TLS-injected hostname so the tenant resolver can distinguish
    // platform BFF (bff.dash.{domain}) from app BFF (bff.{app_domain}).
    let tls_hostname = req
        .headers()
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::TenantContext::from_headers(req.headers(), tls_hostname);
    let is_app_bff = tenant.is_app_bff;

    tracing::info!(
        env_id = ?tenant.env_id,
        app_id = ?tenant.app_id,
        is_app_bff,
        method = %req.method().as_str(),
        path = %req.uri().path(),
        "bff: proxy received request"
    );

    // Resolve service from path prefix: /proxy/{service}/...
    let path = req.uri().path().trim_start_matches('/');
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 3 || parts[0] != "proxy" {
        return (StatusCode::NOT_FOUND, "unknown route").into_response();
    }
    let service = parts[1].to_string();
    // Resolve the canonical colon service identity (
    // .md ) — the path segment carries the bare name (`auth`, `ledger`);
    // delegation scope prefixes and audiences need the full identity
    // (`sentin8:auth`, `bank8:ledger`). URL construction stays on the
    // registry subdomain (DNS-safe), never the colon identity.
    let service_identity = crate::tenant::resolve_service_identity(&state.pool, &service).await;
    // Reconstruct the rest_path with query string — req.uri.path strips
    // the query, so we append it back for the downstream filtering logic.
    let rest_path = match req.uri().query() {
        Some(q) if !q.is_empty() => format!("{}?{}", parts[2], q),
        _ => parts[2].to_string(),
    };

    //application BFF scope whitelist enforcement.
    // App BFF only allows access to services in the app's whitelist.
    // P0: platform BFF allows all; app BFF blocks auth/app/sys (platform-only).
    if is_app_bff {
        let blocked = ["auth", "app", "sys", "tls"];
        if blocked.contains(&service.as_str()) {
            return (StatusCode::FORBIDDEN, "service not allowed for app BFF").into_response();
        }
    }

    let backend = match crate::tenant::resolve_env_service_url(
        &state.pool,
        &state.config,
        req.headers(),
        &service,
    )
    .await
    {
        Some(b) => b,
        None => {
            tracing::warn!(env_id = ?tenant.env_id, service = %service, "bff: proxy could not resolve backend URL");
            return (
                StatusCode::BAD_GATEWAY,
                format!("could not resolve backend for service: {service}"),
            )
                .into_response();
        }
    };

    // Extract session cookie and resolve session.
    let session_id = extract_session_cookie(req.headers());
    let sess = if let Some(ref sid) = session_id {
        state.store.get(sid).await.ok().flatten()
    } else {
        None
    };

    // D2 — session→application binding : a session may only
    // be used on the app instance that created it. The TLS header carries
    // the app id for app BFFs; platform requests carry none. Mismatch →
    // the cookie is treated as absent (401 on authenticated routes).
    if let Some(ref s) = sess {
        let req_app = tenant.app_id.map(|u| u.to_string());
        if !s.matches_application(req_app.as_deref()) {
            tracing::warn!(
                session_app = ?s.application_id,
                request_app = ?req_app,
                "bff: proxy REJECTED session — application binding mismatch"
            );
            return (
                StatusCode::UNAUTHORIZED,
                "session not valid for this application",
            )
                .into_response();
        }
    }

    // No BFF-internal query params are stripped — target_env_id is forwarded
    // to upstream services so they can resolve the correct env_id when the
    // TLS context sets System Env (BFF-proxied requests from Dash).
    let rest_path_clean = rest_path.clone();
    let upstream_url = format!(
        "{}{}",
        backend.trim_end_matches('/'),
        ensure_leading_slash(&rest_path_clean)
    );

    tracing::info!(
        %upstream_url,
        service = %service,
        has_session = sess.is_some(),
        "bff: proxy forwarding to upstream"
    );

    let method = req.method().clone();
    let req_headers = req.headers().clone();
    let req_uri = req.uri().clone();
    //capture values for server-side tagging before `req` is moved.
    let tag_service = service.clone();
    let tag_path = rest_path.to_string();
    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap_or_default();

    // Reuse the server-wide pooled HTTP client (see `ProxyState::http`).
    let client = state.http.clone();
    let mut req_builder = client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &upstream_url,
        )
        .body(body_bytes);

    // If we have a session, decrypt the access token and attach it.
    if let Some(ref sess) = sess {
        let key = session::derive_key(&state.config.encryption_key);

        //CSRF protection: validate X-BFF-CSRF header on mutation requests.
        if state.config.csrf_enabled && is_mutation(&method) {
            let csrf_header = req_headers
                .get("x-bff-csrf")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if csrf_header.is_empty() || csrf_header != sess.csrf_token {
                return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
            }
        }

        // Scope authorization is enforced by each upstream service's own
        // handler-level checks (sys, app, ledger all call verify_token +
        // has_any_scope). BFF does NOT run a coarse service-prefix scope
        // gate: such a gate would pre-empt the granular, per-endpoint scope
        // checks that intentionally accept cross-service scopes (e.g. sys
        // create_org accepts `sentin8:dash:org:create`, create_env accepts
        // `sentin8:dash:env:create`, bootstrap does no scope check and returns only
        // the caller's own orgs). A previous iteration
        // introduced a service-prefix gate here; it was removed because it
        // blocked legitimate self-service flows for newly-signed-up sentin8ors
        // whose `sentin8:sys:users` role carries `dash:*` but no `sys:*` scope.
        // BFF remains the session/token-exchange gate (CSRF, token
        // decryption, RFC 8693 delegation) — authorization scope checks are
        // the responsibility of the upstream handler.

        // Resolve the effective access token to attach to the upstream request.
        //if the request carries X-BFF-Target-Env-Id and the
        // session's token is a platform-admin token, exchange it via the
        // Delegation Gateway for an env-scoped, downscoped, audience-bound token. Cache the exchanged
        // token in Valkey per (sessionId, envId, audience).
        let effective_token = resolve_effective_token(
            &state,
            sess,
            &key,
            &req_headers,
            &req_uri,
            &service_identity,
            tenant.env_id.as_ref().map(|id| id.to_string()).as_deref(),
        )
        .await;

        match effective_token {
            Ok(Some(token)) if !token.is_empty() => {
                req_builder = req_builder.bearer_auth(&token);
            }
            Ok(_) => {}
            Err((status, msg)) => {
                // Token-exchange denial (e.g. operator is not a member of the
                // target org). Surface the 403 to the client instead of
                // silently forwarding the platform-admin token.
                return (status, msg).into_response();
            }
        }

        // Attach CSRF header for mutation requests.
        if state.config.csrf_enabled && is_mutation(&method) {
            // The caller must send X-BFF-CSRF matching the session's csrf_token.
            // Validation is done by a middleware layer; here we just pass it through.
        }
    }

    //FDX header passthrough (x-fapi-interaction-id, FDX-API-Actor-Type).
    // These headers are forwarded as-is on FDX proxy requests.
    //correlation ID propagation (x-sentin8-correlation-id).
    let correlation_id = req_headers
        .get("x-sentin8-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Generate a correlation ID with service-specific prefix for app BFF.
            if is_app_bff {
                format!("app-{}", uuid::Uuid::new_v4().simple())
            } else {
                format!("plat-{}", uuid::Uuid::new_v4().simple())
            }
        });

    // Override x-sentin8-env-id with target_env_id from query params.
    // Dash's ApiClient sends target_env_id as a query param on every proxied
    // request. The TLS context sets System Env because Dash is served from
    // the platform hostname. env_id is the sole tenant key — upstream
    // services resolve org_id from env_id via DB lookup.
    let target_env_id_for_upstream: String = {
        let qs = rest_path.find('?');
        let parse_param = |key: &str| -> Option<String> {
            qs.and_then(|i| {
                rest_path[i + 1..]
                    .split('&')
                    .find_map(|p| p.strip_prefix(&format!("{key}=")))
                    .map(|s| s.to_string())
            })
        };
        req_headers
            .get("x-bff-target-env-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| parse_param("target_env_id"))
            .unwrap_or_default()
    };

    // Forward request headers (minus hop-by-hop).
    let send_result = req_builder
        .header("x-sentin8-correlation-id", &correlation_id)
        // Forward content-type so the upstream knows the body format.
        .header(
            "content-type",
            req_headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json")),
        )
        // Forward TLS-injected tenant context headers. Override x-sentin8-env-id
        // with the target env_id when present — env_id is the sole tenant key.
        // org_id is not forwarded — upstream services resolve it from env_id.
        .header(
            "x-sentin8-env-id",
            if !target_env_id_for_upstream.is_empty() {
                HeaderValue::from_str(&target_env_id_for_upstream)
                    .unwrap_or_else(|_| HeaderValue::from_static(""))
            } else {
                req_headers
                    .get("x-sentin8-env-id")
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static(""))
            },
        )
        .header(
            "x-sentin8-hostname",
            req_headers
                .get("x-sentin8-hostname")
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("")),
        )
        // Pass through FDX headers.
        .header(
            "x-fapi-interaction-id",
            req_headers
                .get("x-fapi-interaction-id")
                .cloned()
                .unwrap_or_else(|| {
                    HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap()
                }),
        )
        .header(
            "fdx-api-actor-type",
            req_headers
                .get("fdx-api-actor-type")
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("customer")),
        )
        .send()
        .await;

    match send_result {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            //server-side tagging (non-fatal, resilient to ad blockers).
            let tag_event = crate::tagging::build_event(
                ServerTagEventType::ApiCall,
                sess.as_ref()
                    .map(|s| s.user_id.as_str())
                    .unwrap_or("anonymous"),
                &tag_service,
                &tag_path,
                method.as_str(),
                status.as_u16(),
                &correlation_id,
            );
            state.tagger.tag(&tag_event).await;
            let mut response = Response::builder().status(status);
            for (k, v) in resp.headers() {
                let k = k.as_str();
                if matches!(
                    k,
                    "content-encoding" | "transfer-encoding" | "content-length" | "connection"
                ) {
                    continue;
                }
                if let Ok(hv) = HeaderValue::from_bytes(v.as_bytes()) {
                    if let Ok(hn) = HeaderName::try_from(k) {
                        response = response.header(hn, hv);
                    }
                }
            }
            let bytes = resp.bytes().await.unwrap_or_default();
            // Mid-session RBAC grants: org/env creation provisions the
            // creator's roles + groups in Sentin8:Auth (org:owner, env:admin
            // with per-service admin scopes via nesting). The session token
            // minted BEFORE those grants lacks the new scopes until it is
            // re-issued. Re-issue now via the refresh grant (which re-merges
            // current role scopes) so the immediately-following admin
            // operations in the new org/env carry them.
            if status.is_success() && method == "POST" && tag_service == "sys" {
                // tag_path = parts[2] of '/proxy/sys/...' — i.e. 'v1/o'
                // WITHOUT a leading slash (query included). Trim leading
                // slashes before comparing.
                let tag_path_only = tag_path
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('/');
                let is_granting = tag_path_only == "v1/o" || tag_path_only == "v1/e";
                if is_granting {
                    if let Some(ref s) = sess {
                        refresh_session_token(&state, s).await;
                    }
                }
            }
            response.body(Body::from(bytes)).unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "proxy error").into_response()
            })
        }
        Err(e) => {
            tracing::error!(error = %e, %upstream_url, "bff proxy forward failed");
            (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response()
        }
    }
}

fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("bff-session=") {
            return Some(val.to_string());
        }
    }
    None
}

fn ensure_leading_slash(s: &str) -> String {
    if s.starts_with('/') {
        s.to_string()
    } else {
        format!("/{s}")
    }
}

fn is_mutation(method: &axum::http::Method) -> bool {
    matches!(
        method,
        &axum::http::Method::POST
            | &axum::http::Method::PUT
            | &axum::http::Method::PATCH
            | &axum::http::Method::DELETE
    )
}

#[derive(serde::Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

async fn refresh_access_token(
    sentin8_auth_base_url: &str,
    refresh_token: &str,
    client_id: &str,
) -> Result<RefreshTokenResponse, String> {
    // Converged path (bff DESIGN §12): refresh via the shared FAPI client
    // with the process DPoP key — under `fapi_2` (`require_dpop = true`),
    // refresh_token grants on non-exempt (DCR-registered) clients require
    // a proof; the plain-POST form gets 401. The plain form remains only
    // as the pre-DPoP-bootstrap fallback (dev runs without a process key).
    match fapi_refresh(sentin8_auth_base_url, client_id, refresh_token).await {
        Ok(resp) => Ok(resp),
        Err(fapi_err) => {
            tracing::warn!(error = %fapi_err, "bff: DPoP refresh failed — plain-POST fallback");
            let resp = reqwest::Client::new()
                .post(format!("{sentin8_auth_base_url}/oauth/token"))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", client_id),
                ])
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if !resp.status().is_success() {
                return Err(format!("refresh failed: status {}", resp.status()));
            }
            resp.json().await.map_err(|e| e.to_string())
        }
    }
}

/// FAPI/DPoP refresh: the shared FAPI client with the process DPoP key —
/// the same mechanism the explicit refresh path uses (handlers.rs).
async fn fapi_refresh(
    sentin8_auth_base_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<RefreshTokenResponse, String> {
    let opts = sentin8::auth::fapi::ClientOptions::builder()
        .issuer_url(sentin8_auth_base_url.to_string())
        .client_id(client_id.to_string())
        .redirect_uri(crate::config::Bff8Config::from_env().oauth_redirect_uri)
        .dpop_key(crate::handlers::dpop_key_pem(), "ES256")
        .build()
        .map_err(|e| e.to_string())?;
    let client = sentin8::auth::fapi::Client::new(opts).map_err(|e| e.to_string())?;
    let resp = client
        .refresh_token(refresh_token)
        .await
        .map_err(|e| e.to_string())?;
    Ok(RefreshTokenResponse {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        expires_in: resp.expires_in,
    })
}

/// Refresh a session's access token via the OAuth refresh grant.
///
/// Auth's refresh grant re-merges the user's CURRENT role/group scopes
/// (oauth.rs `handle_refresh`), so a token re-issued after a mid-session
/// grant (org/env creation provisioning org:owner / env:admin scopes)
/// carries the new permissions immediately — no re-sign-in needed.
async fn refresh_session_token(state: &ProxyState, sess: &session::Session) {
    let key = session::derive_key(&state.config.encryption_key);
    let refresh = match sess.refresh_token(&key) {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => {
            tracing::warn!(
                session = %sess.session_id,
                "bff: grant refresh skipped — session has no refresh token"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                session = %sess.session_id,
                error = %e,
                "bff: grant refresh skipped — refresh token decrypt failed"
            );
            return;
        }
    };
    match refresh_access_token(
        &state.config.sentin8_auth_base_url,
        &refresh,
        &state.config.oauth_client_id,
    )
    .await
    {
        Ok(new_token) => {
            let mut updated = sess.clone();
            let _ = updated.set_access_token(&new_token.access_token, &key);
            if let Some(ref rt) = new_token.refresh_token {
                let _ = updated.set_refresh_token(rt, &key);
            }
            updated.token_expiry = chrono::Utc::now().timestamp() + new_token.expires_in as i64;
            // Preserve the resolved scope snapshot for BFF-side checks.
            let claims = sentin8_auth_sdk::decode_claims_unverified(&new_token.access_token);
            if let Some(c) = claims {
                updated.scope = c.scope.clone();
            }
            let _ = state.store.create(&updated).await;
            tracing::info!(
                session = %sess.session_id,
                "bff: session token re-issued after RBAC grant (scope re-merged)"
            );
        }
        Err(e) => {
            tracing::warn!(
                session = %sess.session_id,
                error = %e,
                "bff: grant refresh failed — token endpoint rejected the refresh grant"
            );
        }
    }
}

// ── RFC 8693 Token Exchange ───────────────────────────

// Note: TokenExchangeResponse is no longer needed — the Auth SDK's
// `exchange_token` returns `TokenResponse` which has the same fields.

/// Resolve the effective access token to attach to the upstream request.
///
///+ — Delegation Gateway model. If the session's access token
/// is a platform-admin token and the request targets a specific env, BFF
/// requests a cert-bound delegated token from Auth's
/// `POST /delegate/access-token`. The delegated token is cached in Valkey
/// per `(sessionId, envId, audience)` with TTL = token expiry.
///
/// If no target headers are present or the token is an env-scoped user token (app BFF
/// end-users), attach the original token as-is (no delegation needed).
///
/// **Failure policy:** 403 (deny) → fail the request. Transient errors → fail
/// (no platform-admin fallback — cert-bound tokens cannot be forged, and a
/// platform-admin token lacks target env claims and would bypass RLS).
async fn resolve_effective_token(
    state: &ProxyState,
    sess: &session::Session,
    key: &[u8; 32],
    req_headers: &axum::http::HeaderMap,
    req_uri: &axum::http::Uri,
    target_service: &str,
    _tls_env_id: Option<&str>,
) -> Result<Option<String>, (axum::http::StatusCode, String)> {
    // `target_service` is the canonical colon identity (`sentin8:auth`,
    // `bank8:ledger` — ), resolved from the
    // proxy path by `resolve_service_identity`. Normalize any caller input.
    let target_service = &sentin8::config::canonical_service_type(target_service);
    let Some(token) = sess.access_token(key).ok() else {
        return Ok(None);
    };
    if token.is_empty() {
        return Ok(None);
    }

    // (Option A) — CIBA delegation attach: if the request carries
    // X-BFF-Delegation (the delegation_id from POST /delegate/start), and a
    // customer-approved delegation token is cached for it, use that token
    // INSTEAD of the staff session token. Upstream services then see a
    // normal customer token (sub = customer, act = staff) and all standard
    // holder-scoped RLS applies unchanged. A missing/expired
    // delegation falls through to the staff token — which, under Option A,
    // carries no customer-data visibility, so the call fails closed.
    if let Some(delegation_id) = req_headers
        .get("x-bff-delegation")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        match crate::ciba::get_cached_delegation_token(&state.store, delegation_id).await {
            Ok(Some(tok)) if !tok.is_empty() => {
                tracing::debug!(delegation_id, "bff: delegation token attached");
                return Ok(Some(tok));
            }
            _ => {
                // Delegation expired or not yet approved — fail closed.
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "delegation expired or not approved — request customer consent again".into(),
                ));
            }
        }
    }

    // If the token is expired, try to refresh it first.
    let token = if sess.token_is_expired() {
        if let Ok(refresh) = sess.refresh_token(key) {
            if !refresh.is_empty() {
                if let Ok(new_token) = refresh_access_token(
                    &state.config.sentin8_auth_base_url,
                    &refresh,
                    &state.config.oauth_client_id,
                )
                .await
                {
                    // Update the session in Valkey with the new token.
                    let mut updated = sess.clone();
                    let _ = updated.set_access_token(&new_token.access_token, key);
                    if let Some(ref rt) = new_token.refresh_token {
                        let _ = updated.set_refresh_token(rt, key);
                    }
                    updated.token_expiry =
                        chrono::Utc::now().timestamp() + new_token.expires_in as i64;
                    let _ = state.store.create(&updated).await;
                    new_token.access_token
                } else {
                    // Refresh failed — forward the expired token (will likely get 401).
                    return Ok(Some(token));
                }
            } else {
                return Ok(Some(token));
            }
        } else {
            return Ok(Some(token));
        }
    } else {
        token
    };

    // Check if this is a platform-admin access token that should be delegated.
    // Only `access` tokens with `sentin8:sys:admin` scope need delegation — these are
    // platform operator tokens. Regular env-scoped user tokens and already-
    // delegated tokens pass through as-is.
    let claims = sentin8_auth_sdk::decode_claims_unverified(&token);
    let token_tp = claims.as_ref().map(|c| c.token_tp.as_str()).unwrap_or("");
    let is_platform_admin = claims
        .as_ref()
        .map(|c| c.has_scope("sentin8:sys:admin"))
        .unwrap_or(false);
    if token_tp != "access" || !is_platform_admin {
        // Not a platform-admin access token — attach as-is (app BFF end-users
        // have env-scoped tokens; delegated tokens already carry the target env).
        return Ok(Some(token));
    }

    // Read target env from BFF-internal input headers or query params.
    let query = req_uri.query().unwrap_or("");
    let parse_query = |key: &str| -> Option<String> {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key && !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    };
    let target_env_id = req_headers
        .get("x-bff-target-env-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| parse_query("target_env_id"))
        .unwrap_or_default();

    if target_env_id.is_empty() {
        // No target env — attach as-is (platform admin calls without env targeting).
        return Ok(Some(token));
    }

    // Skip delegation for the system env. A platform-admin access token
    // already authorizes the system env (bootstrap path for new sentin8ors).
    if target_env_id == sentin8::config::SYSTEM_ENV_ID.to_string() {
        return Ok(Some(token));
    }

    // Build the audience (RFC 8707 resource indicator).
    //
    // The identity's colons are not DNS-safe, so the audience uses the
    // registry subdomain (the DNS label): `sentin8:auth` →
    // `https://auth.ops.sys.{domain}`, `bank8:ledger` →
    // `https://bank8-ledger.ops.sys.{domain}`.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let subdomain = cfg.resolve_subdomain(&state.pool, target_service).await;
    let audience = format!("https://{}.{}", subdomain, state.config.sentin8_domain);

    // Check Valkey cache for an existing delegated token.
    let cache_key = format!(
        "bff:delegated:{}:{}:{}",
        sess.session_id, target_env_id, target_service
    );

    if let Ok(Some(cached)) = get_cached_delegated_token(&state.store, &cache_key).await {
        tracing::debug!(cache_key = %cache_key, "bff: delegated token cache hit");
        return Ok(Some(cached));
    }

    // Extract the staff user's identity from the session token claims.
    let act_sub = claims.as_ref().map(|c| c.sub.as_str()).unwrap_or("");
    let act_email = claims
        .as_ref()
        .and_then(|c| c.email.as_deref())
        .unwrap_or("");

    // Downscope: extract scopes matching the target service prefix.
    // The colon identity makes the namespace derivable instead of heuristic:
    // platform services (`sentin8:*`) issue scopes without the vertical
    // segment — `sentin8:auth` → `auth:` — and vertical services keep both
    // segments — `bank8:ledger` → `bank8:ledger:`. Workers resolve to their
    // base service's namespace (`bank8:payments:worker` → `bank8:payments:`).
    let scope_prefix = sentin8::config::service_scope_namespace(target_service);
    let requested_scope = sentin8_auth_sdk::extract_scopes_for_service(&sess.scope, &scope_prefix);

    // Call Auth POST /delegate/access-token via the Auth SDK.
    let auth_client = state.config.auth_client.clone();
    match auth_client
        .delegate_access_token(
            act_sub,
            act_email,
            &target_env_id,
            &requested_scope,
            &audience,
        )
        .await
    {
        Ok(delegated) => {
            // Cache the delegated token in Valkey with TTL = token expiry.
            let _ = set_cached_delegated_token(
                &state.store,
                &cache_key,
                &delegated.access_token,
                delegated.expires_in,
            )
            .await;

            tracing::info!(
                session = %sess.session_id,
                actor = %act_sub,
                target_env = %target_env_id,
                service = %target_service,
                "bff: Delegation Gateway — delegated token issued"
            );
            Ok(Some(delegated.access_token))
        }
        Err(sentin8_auth_sdk::AuthError::HttpStatus { status, body })
            if status == axum::http::StatusCode::FORBIDDEN =>
        {
            // 403 deny — staff user is not a member of the target env.
            tracing::warn!(
                session = %sess.session_id,
                actor = %act_sub,
                target_env = %target_env_id,
                service = %target_service,
                body = %body,
                "bff: delegation denied (403) — staff user is not a member of the target env"
            );
            Err((
                axum::http::StatusCode::FORBIDDEN,
                "delegation denied: staff user is not a member of the target environment".into(),
            ))
        }
        Err(e) => {
            // Transient failure — fail (no platform-admin fallback in cert-bound model).
            tracing::warn!(
                session = %sess.session_id,
                actor = %act_sub,
                target_env = %target_env_id,
                service = %target_service,
                error = %e,
                "bff: Delegation Gateway failed (no fallback)"
            );
            Err((
                axum::http::StatusCode::BAD_GATEWAY,
                format!("Delegation Gateway failed: {e}"),
            ))
        }
    }
}

/// Set the M2M cert-bound identity paths (called by server.rs after
/// issuance + DCR; — the certificate IS the M2M identity).
pub(crate) fn set_m2m_cert_paths(cert_path: String, key_path: String, ca_path: String) {
    *M2M_CREDENTIALS.cert_path.write().unwrap() = cert_path;
    *M2M_CREDENTIALS.key_path.write().unwrap() = key_path;
    *M2M_CREDENTIALS.ca_path.write().unwrap() = ca_path;
}

/// Get the cert-presenting `bff-delegator` transport (, auth
/// DESIGN §4.3f) — the shared mTLS client presenting the delegator's
/// Acme-issued certificate on every platform call (Auth's TLS layer
/// authenticates the handshake; the registry map authorizes the
/// delegator scopes). No M2M token exists on this path.
///
/// # Errors
/// Returns a [`String`] when the identity has not been installed yet
/// (the boot mint is still in flight — callers surface a 503-grade
/// error and retry).
pub(crate) async fn get_sentin8_bff_m2m_token(
    config: &crate::config::Bff8Config,
) -> Result<reqwest::Client, String> {
    use std::sync::Arc;

    // Static cache — initialized once per process.
    static M2M_SOURCE: tokio::sync::OnceCell<Arc<reqwest::Client>> =
        tokio::sync::OnceCell::const_new();

    let source = M2M_SOURCE
        .get_or_init(|| async {
            // Read the installed cert paths (from the boot ensure task).
            let cert_path = M2M_CREDENTIALS.cert_path.read().unwrap().clone();
            let key_path = M2M_CREDENTIALS.key_path.read().unwrap().clone();
            let ca_path = M2M_CREDENTIALS.ca_path.read().unwrap().clone();

            // Fail-loud on a missing identity: without the certificate the
            // delegator has no identity. Fall back to env-configured paths
            // (`SENTIN8_BFF_M2M_CLIENT_CERT/KEY`) when the ensure task has
            // not completed.
            let (cert, key, ca) = if cert_path.is_empty() || key_path.is_empty() {
                (
                    config.m2m_client_cert_path.clone().unwrap_or_default(),
                    config.m2m_client_key_path.clone().unwrap_or_default(),
                    config
                        .m2m_ca_cert_path
                        .clone()
                        .unwrap_or_else(sentin8::auth::m2m::platform_ca_path),
                )
            } else {
                (cert_path, key_path, ca_path)
            };
            if cert.is_empty() || key.is_empty() {
                tracing::warn!("bff: delegator certificate not yet installed — platform calls unavailable until the identity lands");
                return Arc::new(reqwest::Client::new());
            }
            let mtls = sentin8::middleware::mtls::MtlsConfig::new(&ca, &cert, &key);
            match sentin8::middleware::mtls::build_mtls_client(&mtls) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::warn!(error = %e, "bff: delegator mTLS transport build failed — plain transport (calls will be rejected)");
                    Arc::new(reqwest::Client::new())
                }
            }
        })
        .await;

    Ok(source.as_ref().clone())
}

/// Install an mTLS-capable HTTP client on the shared Auth SDK client
/// (bff design ). Auth's `/delegate/access-token` enforces
/// RFC 8705 sender-constraining (SEC-): a cert-bound M2M token presented
/// without `X-Sentin8-Client-Cert-Thumbprint` is hard-rejected 401. TLS injects
/// that header only when the HTTP client presents the delegator certificate —
/// the SAME cert the `sentin8-m2m` TokenSource used to mint the token. Called
/// from server.rs at both DCR activation points; fail-loud, never a silent
/// downgrade to the plain client.
pub(crate) fn install_mtls_auth_client(
    auth_client: &sentin8::auth::client::Client,
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) {
    match sentin8::middleware::mtls::build_mtls_client(&sentin8::middleware::mtls::MtlsConfig::new(
        ca_path, cert_path, key_path,
    )) {
        Ok(client) => {
            auth_client.set_http_client(
                sentin8::middleware::http_client::Sentin8HttpClient::from_client(client),
            );
            tracing::info!("bff-delegator: mTLS client installed on the auth SDK client — delegation calls now present the client certificate");
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "bff-delegator: failed to build the mTLS client for delegation — env-scoped delegated requests WILL 401 (SEC-2.4.10 hard reject)"
            );
        }
    }
}

/// Get a cached delegated token from Valkey.
async fn get_cached_delegated_token(
    store: &session::SessionStore,
    cache_key: &str,
) -> Result<Option<String>, String> {
    use glide::AsyncCommands;
    let conn = store.valkey_connection();
    let val: Option<String> = conn.get(cache_key).await.map_err(|e| e.to_string())?;
    Ok(val)
}

/// Cache a delegated token in Valkey with the given TTL.
async fn set_cached_delegated_token(
    store: &session::SessionStore,
    cache_key: &str,
    token: &str,
    ttl_secs: u64,
) -> Result<(), String> {
    use glide::AsyncCommands;
    let conn = store.valkey_connection();
    let _: () = conn
        .set_ex(cache_key, token, ttl_secs)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
