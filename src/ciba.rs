// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! BFF Delegation endpoints --.
//!
//! BFF is the Delegation Gateway - it brokers customer-delegated access
//! for staff applications (eTeller) by calling two Auth instances directly:
//!
//! - **Customer Auth** (env-scoped) - initiates CIBA (`POST /oauth/bc-authorize`),
//! polls the token endpoint (`POST /oauth/token` with CIBA grant).
//! - **Staff Auth** (org-scoped or operator-configured) - the staff token is
//! already in the BFF session; the customer token's `act` claim records
//! the staff identity.
//!
//! No separate "Delegation Gateway service" is needed - BFF has the staff
//! session, can call the customer Auth, and caches the delegation token in
//! Valkey. The delegation token IS the customer CIBA token (with `act`=staff
//! embedded by Auth's CIBA grant).
//!
//! Flow:
//! 1. `POST /delegate/start` - BFF calls customer Auth `POST /oauth/bc-authorize`
//! with `delivery=ciba|assisted_link`. Returns `delegation_id`, `auth_req_id`,
//! `verification_uri_complete?`, `short_code?`.
//! 2. `POST /delegate/poll` - BFF calls customer Auth `POST /oauth/token` with
//! the CIBA grant. Returns `status` + `delegation_token` on approval.
//! 3. BFF caches the delegation token in Valkey and attaches it to proxied
//! Ledger/Payments calls that touch customer data.
//!
//! Design: ,
//! `bank8/design/sentin8-app-eteller-app-technical-design.md` ,

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use glide::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;
use crate::proxy::get_sentin8_bff_m2m_token;

/// Valkey key prefix for cached delegation tokens.
const DELEGATION_TOKEN_KEY_PREFIX: &str = "bff:delegation_token:";

/// Valkey key prefix for cached CIBA auth_req_id (so poll can find it).
const DELEGATION_AUTHREQ_KEY_PREFIX: &str = "bff:delegation_authreq:";

/// Default TTL for cached delegation tokens (5 minutes).
const DELEGATION_TOKEN_TTL: u64 = 300;

/// Extract a cookie value from the Cookie header.
fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&format!("{name}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// Request body for `POST /delegate/start`.
#[derive(Debug, Deserialize)]
pub struct DelegateStartRequest {
    /// Ledger customer record ID (for audit/display).
    pub customer_id: String,
    /// Delegation flow: `ciba` or `assisted_login`.
    pub flow: String,
    /// Requested scopes (customer-approved subset).
    pub scope: String,
    /// Human-readable operation description shown to the customer.
    pub binding_message: String,
    /// Customer's login_hint (email or phone).
    pub login_hint: String,
    /// Staff-provided reason (audit).
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response from `POST /delegate/start`.
#[derive(Debug, Serialize)]
pub struct DelegateStartResponse {
    pub delegation_id: String,
    pub auth_req_id: String,
    pub expires_in: u64,
    pub interval: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_code: Option<String>,
}

/// Request body for `POST /delegate/poll`.
#[derive(Debug, Deserialize)]
pub struct DelegatePollRequest {
    pub delegation_id: String,
}

/// Response from `POST /delegate/poll`.
#[derive(Debug, Serialize)]
pub struct DelegatePollResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Response from `GET /delegate/status`.
#[derive(Debug, Serialize)]
pub struct DelegateStatusResponse {
    pub has_token: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
}

/// `POST /delegate/start` - start a delegation flow.
///
/// Calls the customer (env-scoped) Auth `POST /oauth/bc-authorize` directly.
pub async fn delegate_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DelegateStartRequest>,
) -> Result<Json<DelegateStartResponse>, (StatusCode, String)> {
    // Validate flow.
    if req.flow != "ciba" && req.flow != "assisted_login" {
        return Err((
            StatusCode::BAD_REQUEST,
            "flow must be 'ciba' or 'assisted_login'".into(),
        ));
    }
    if req.binding_message.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "binding_message is required".into(),
        ));
    }

    // Resolve the env-scoped (customer) Auth URL.
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;

    // Determine delivery mode.
    let delivery = if req.flow == "assisted_login" {
        "assisted_link"
    } else {
        "decoupled_device"
    };

    // Generate a delegation_id (used as the Valkey key for this session).
    let delegation_id = Uuid::new_v4().to_string();

    // Call customer Auth bc-authorize.
    let client = reqwest::Client::builder().build().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HTTP client build failed: {e}"),
        )
    })?;

    // (Option A): resolve the initiating staff member from the BFF
    // session (authenticated identity - never from the staff app's request
    // body). Their user id + email become the CIBA token's `act` claim, so
    // every customer-data access is attributable to a human. A CIBA request
    // without a staff session is a plain decoupled-device self-approval.
    let mut act_sub: Option<String> = None;
    let mut act_email: Option<String> = None;
    if let Some(sid) = extract_cookie(&headers, "bff-session") {
        if let Ok(Some(sess)) = state.store.get(&sid).await {
            if !sess.user_id.is_empty() && sess.user_id != "anonymous" {
                act_sub = Some(sess.user_id.clone());
                // Decrypt the session's access token to read the email claim
                // (audit-only; failure degrades to a missing email, never
                // blocks the flow).
                let key = crate::session::derive_key(&state.config.encryption_key);
                if let Ok(token) = sess.access_token(&key) {
                    if let Some(claims) = sentin8::auth::client::decode_claims_unverified(&token) {
                        act_email = claims.email;
                    }
                }
            }
        }
    }

    // Design table - Assisted-Login/CIBA always targets the env-scoped
    // (customer) Sentin8:Auth using the app instance's DCR-registered OAuth
    // client (`oauth_client_id`, public PKCE - same client the instance's
    // other OIDC flows use). The platform delegator client lives in the
    // PLATFORM env only, so authenticating here with it fails the env-scoped
    // client lookup (RLS) - the actual 401 seen in bank8 e2e.
    let info = crate::handlers::resolve_app_auth_info(&state, &headers).await;
    // Staff-mode instances register a SEPARATE CIBA client at the CUSTOMER
    // env's auth (the sign-in client lives at the staff auth); CIBA
    // bc-authorize targets the customer auth, so the CIBA client wins when
    // present. Env-scoped apps share the single sign-in client.
    let instance_cid = if info.ciba_oauth_client_id.is_empty() {
        info.oauth_client_id
    } else {
        info.ciba_oauth_client_id
    };
    let client_id = if instance_cid.is_empty() {
        state.config.oauth_client_id.clone()
    } else {
        instance_cid
    };

    let json_body = serde_json::json!({
        "client_id": client_id,
        "login_hint": req.login_hint,
        "scope": req.scope,
        "binding_message": req.binding_message,
        "delivery": delivery,
        "verification_uri_base": sentin8_auth_url.trim_end_matches('/'),
        "act_sub": act_sub,
        "act_email": act_email,
    });

    let resp = client
        .post(format!(
            "{}/oauth/bc-authorize",
            sentin8_auth_url.trim_end_matches('/')
        ))
        .header("content-type", "application/json")
        .json(&json_body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth bc-authorize failed: {e}"),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("auth bc-authorize returned {status}: {body}"),
        ));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("auth bc-authorize bad json: {e}"),
        )
    })?;

    let auth_req_id = body["auth_req_id"]
        .as_str()
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "auth bc-authorize missing auth_req_id".into(),
            )
        })?
        .to_string();
    let expires_in = body["expires_in"].as_u64().unwrap_or(DELEGATION_TOKEN_TTL);
    let interval = body["interval"].as_u64().unwrap_or(5);
    let short_code = body["short_code"].as_str().map(String::from);

    // Override the verification_uri_complete with the env-scoped Auth URL.
    // Auth generates the link using its own config.issuer (platform Auth),
    // but the customer should be directed to the env-scoped Auth that BFF
    // used for the bc-authorize call. BFF knows the correct URL since it
    // resolved it via resolve_env_sentin8_auth_url.
    let verification_uri_complete = if delivery == "assisted_link" {
        Some(format!(
            "{}/ciba/assisted/{}",
            sentin8_auth_url.trim_end_matches('/'),
            auth_req_id
        ))
    } else {
        body["verification_uri_complete"].as_str().map(String::from)
    };

    // Cache the auth_req_id in Valkey keyed by delegation_id so poll can find it.
    let valkey_key = format!("{DELEGATION_AUTHREQ_KEY_PREFIX}{delegation_id}");
    let conn = state.store.valkey_connection();
    let _: () = conn
        .set_ex(&valkey_key, &auth_req_id, expires_in)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("valkey set failed: {e}"),
            )
        })?;

    tracing::info!(
        delegation_id = %delegation_id,
        auth_req_id = %auth_req_id,
        flow = %req.flow,
        "bff: delegate_start issued"
    );

    // (SSE migration) - start a background poll task so the
    // result is pushed to the client over the SSE subscription stream (no
    // client-side polling needed). The client still falls back to POST
    // /delegate/poll if SSE is not connected.
    if let Some(session_id) = extract_cookie(&headers, "bff-session") {
        crate::subscribe::start_delegation_poll(
            session_id,
            delegation_id.clone(),
            auth_req_id.clone(),
            sentin8_auth_url.clone(),
            client_id.clone(),
            interval,
            state.config.valkey_url.clone(),
        )
        .await;
    }

    Ok(Json(DelegateStartResponse {
        delegation_id,
        auth_req_id,
        expires_in,
        interval,
        verification_uri_complete,
        short_code,
    }))
}

/// `POST /delegate/poll` - poll delegation status.
///
/// Calls the customer (env-scoped) Auth `POST /oauth/token` with the CIBA grant.
/// On approval, caches the delegation token in Valkey.
pub async fn delegate_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DelegatePollRequest>,
) -> Result<Json<DelegatePollResponse>, (StatusCode, String)> {
    // Retrieve the auth_req_id from Valkey (cached by delegate_start).
    let valkey_key = format!("{DELEGATION_AUTHREQ_KEY_PREFIX}{}", req.delegation_id);
    let conn = state.store.valkey_connection();
    let auth_req_id: Option<String> = conn.get(&valkey_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey get failed: {e}"),
        )
    })?;

    let auth_req_id = auth_req_id.filter(|s| !s.is_empty()).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "delegation session not found or expired".into(),
        )
    })?;

    // Resolve the env-scoped (customer) Auth URL.
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;

    // Poll the CIBA token endpoint.
    let client = reqwest::Client::builder().build().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HTTP client build failed: {e}"),
        )
    })?;

    let token_url = format!("{}/oauth/token", sentin8_auth_url.trim_end_matches('/'));
    tracing::info!(%token_url, %auth_req_id, "bff: polling CIBA token");
    // Design - the poll uses the same env-scoped app-instance client
    // as bc-authorize (public PKCE client registered in the customer env).
    let poll_info = crate::handlers::resolve_app_auth_info(&state, &headers).await;
    // Same CIBA-client preference as delegate_start (the poll authenticates
    // the SAME client at the customer auth).
    let poll_instance_cid = if poll_info.ciba_oauth_client_id.is_empty() {
        poll_info.oauth_client_id
    } else {
        poll_info.ciba_oauth_client_id
    };
    let poll_client_id = if poll_instance_cid.is_empty() {
        state.config.oauth_client_id.clone()
    } else {
        poll_instance_cid
    };
    let form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Aciba&auth_req_id={}&client_id={}",
        auth_req_id, poll_client_id,
    );
    // - under `fapi_2` (`require_dpop = true`) the
    // CIBA grant is a user-facing grant: non-exempt clients MUST present a
    // DPoP proof on the token request. The BFF (the delegation broker) signs
    // with its process ES256 key - the proof's embedded `jwk` lets Auth
    // verify self-contained, and the issued delegation token is
    // sender-constrained to the BFF (`cnf.jkt`).
    let dpop_proof = sentin8::auth::fapi::dpop_proof(
        "POST",
        &token_url,
        None,
        &crate::handlers::dpop_key_pem(),
        jsonwebtoken::Algorithm::ES256,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dpop proof failed: {e}"),
        )
    })?;
    let resp = client
        .post(&token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .body(form_body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth token poll failed: {e}"),
            )
        })?;

    let status_code = resp.status();
    let resp_text = resp.text().await.unwrap_or_default();

    // Handle pending / denied / expired (RFC 8705 / RFC 8628). Auth returns
    // these as HTTP 400 with a JSON body `{"error": "..."}`. Parse the error
    // code defensively - some OIDC providers return a plain-text body
    // (just the error code) instead of JSON, so accept both.
    if status_code == StatusCode::BAD_REQUEST {
        let error = serde_json::from_str::<serde_json::Value>(&resp_text)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| resp_text.trim().to_string());
        if error == "authorization_pending" || error == "slow_down" {
            return Ok(Json(DelegatePollResponse {
                status: "pending".into(),
                delegation_token: None,
                expires_at: None,
            }));
        }
        if error == "access_denied" {
            return Ok(Json(DelegatePollResponse {
                status: "denied".into(),
                delegation_token: None,
                expires_at: None,
            }));
        }
        if error == "expired_token" {
            return Ok(Json(DelegatePollResponse {
                status: "expired".into(),
                delegation_token: None,
                expires_at: None,
            }));
        }
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("auth token poll error: {error}"),
        ));
    }

    if !status_code.is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("auth token poll returned {status_code}: {resp_text}"),
        ));
    }

    // Success - customer approved. Parse the JSON token response.
    let body: serde_json::Value = serde_json::from_str(&resp_text)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("auth token poll bad json: {e} - body: {resp_text} - url: {sentin8_auth_url} - status: {status_code}")))?;

    let delegation_token = body["access_token"]
        .as_str()
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "auth token poll missing access_token".into(),
            )
        })?
        .to_string();
    let expires_in = body["expires_in"].as_u64().unwrap_or(DELEGATION_TOKEN_TTL);
    let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;

    // Cache the delegation token in Valkey keyed by delegation_id.
    let token_key = format!("{DELEGATION_TOKEN_KEY_PREFIX}{}", req.delegation_id);
    let _: () = conn
        .set_ex(&token_key, &delegation_token, expires_in)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("valkey set token failed: {e}"),
            )
        })?;

    // Also store metadata for /delegate/status.
    let meta_key = format!("{DELEGATION_TOKEN_KEY_PREFIX}{}:meta", req.delegation_id);
    let scope = body["scope"].as_str().unwrap_or("").to_string();
    let meta = serde_json::json!({
        "expires_at": expires_at,
        "scope": scope,
        "delegation_id": req.delegation_id,
    });
    let _: () = conn
        .set_ex(&meta_key, meta.to_string(), expires_in)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("valkey set meta failed: {e}"),
            )
        })?;

    tracing::info!(
        delegation_id = %req.delegation_id,
        "bff: delegate_poll approved - delegation token cached"
    );

    Ok(Json(DelegatePollResponse {
        status: "approved".into(),
        delegation_token: Some(delegation_token),
        expires_at: Some(expires_at),
    }))
}

/// `GET /delegate/status` - check cached delegation token status.
pub async fn delegate_status(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<DelegatePollRequest>,
) -> Result<Json<DelegateStatusResponse>, (StatusCode, String)> {
    let valkey_key = format!("{DELEGATION_TOKEN_KEY_PREFIX}{}", q.delegation_id);
    let conn = state.store.valkey_connection();

    let token: Option<String> = conn.get(&valkey_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey get failed: {e}"),
        )
    })?;

    if token.is_none() || token.as_deref() == Some("") {
        return Ok(Json(DelegateStatusResponse {
            has_token: false,
            expires_at: None,
            scope: None,
            customer_sub: None,
            delegation_id: None,
        }));
    }

    let meta_key = format!("{DELEGATION_TOKEN_KEY_PREFIX}{}:meta", q.delegation_id);
    let meta_str: Option<String> = conn.get(&meta_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey get meta failed: {e}"),
        )
    })?;
    let meta: serde_json::Value = meta_str
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Ok(Json(DelegateStatusResponse {
        has_token: true,
        expires_at: meta["expires_at"].as_i64(),
        scope: meta["scope"].as_str().map(String::from),
        customer_sub: None,
        delegation_id: meta["delegation_id"].as_str().map(String::from),
    }))
}

/// (Option A) - read the cached CIBA delegation token for a
/// delegation session. Used by the proxy (`resolve_effective_token`) to
/// attach the customer-approved token instead of the staff session token.
/// Returns `Ok(None)` when the delegation is missing/expired (fail closed).
pub async fn get_cached_delegation_token(
    store: &crate::session::SessionStore,
    delegation_id: &str,
) -> Result<Option<String>, String> {
    let valkey_key = format!("{DELEGATION_TOKEN_KEY_PREFIX}{delegation_id}");
    let conn = store.valkey_connection();
    let token: Option<String> = conn
        .get(&valkey_key)
        .await
        .map_err(|e| format!("valkey get delegation token failed: {e}"))?;
    Ok(token.filter(|t| !t.is_empty()))
}

/// `POST /delegate/send-link` - forward the Assisted Login link (convenience).
#[derive(Debug, Deserialize)]
pub struct SendLinkRequest {
    pub delegation_id: String,
    pub channel: String,
    #[serde(default)]
    pub destination: Option<String>,
}

pub async fn delegate_send_link(
    State(_state): State<AppState>,
    Json(req): Json<SendLinkRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!(
        delegation_id = %req.delegation_id,
        channel = %req.channel,
        destination = ?req.destination,
        "bff: delegate_send_link requested (delivery integration wired per deployment)"
    );
    Ok(Json(serde_json::json!({
        "status": "sent",
        "channel": req.channel,
        "delegation_id": req.delegation_id,
    })))
}

// ── SCIM Proxy ───────────────────────────────────────

/// Generic SCIM proxy - forwards all SCIM operations to the env-scoped Auth
/// using BFF's cert-bound M2M token (`bff-delegator` with `sentin8:scim:read`/
/// `sentin8:scim:write` scope).
///
/// Routes (registered in server.rs):
/// GET /delegate/scim/users → Auth GET /scim/v2/Users
/// POST /delegate/scim/users → Auth POST /scim/v2/Users
/// GET /delegate/scim/users/:id → Auth GET /scim/v2/Users/:id
/// PUT /delegate/scim/users/:id → Auth PUT /scim/v2/Users/:id
/// PATCH /delegate/scim/users/:id → Auth PATCH /scim/v2/Users/:id
/// DELETE /delegate/scim/users/:id → Auth DELETE /scim/v2/Users/:id
/// BFF injects the M2M token and forwards the request body/query params
/// as-is. The response (SCIM JSON) is returned directly to the caller.
//
// Query params for `GET /delegate/scim/users` (SCIM list/search):
#[derive(Debug, Deserialize)]
pub struct ScimSearchRequest {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub start_index: Option<u32>,
    #[serde(default)]
    pub count: Option<u32>,
}

/// `GET /delegate/scim/users` - list/search users via SCIM.
pub async fn delegate_scim_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ScimSearchRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!("{}/scim/v2/Users", sentin8_auth_url.trim_end_matches('/'));
    let mut req_builder = client
        .get(&scim_url)
        .header("accept", "application/scim+json");

    let mut params: Vec<(&str, String)> = vec![];
    if let Some(ref f) = q.filter {
        if !f.is_empty() {
            params.push(("filter", f.clone()));
        }
    }
    if let Some(si) = q.start_index {
        params.push(("startIndex", si.to_string()));
    }
    if let Some(c) = q.count {
        params.push(("count", c.to_string()));
    }
    if !params.is_empty() {
        req_builder = req_builder.query(&params);
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("auth SCIM failed: {e}")))?;
    scim_response(resp).await
}

/// `POST /delegate/scim/users` - create a user via SCIM.
pub async fn delegate_scim_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!("{}/scim/v2/Users", sentin8_auth_url.trim_end_matches('/'));
    let resp = client
        .post(&scim_url)
        .header("content-type", "application/scim+json")
        .header("accept", "application/scim+json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth SCIM create failed: {e}"),
            )
        })?;

    let status = resp.status();
    let body = scim_response_value(resp).await?;
    Ok((
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::CREATED),
        Json(body),
    ))
}

/// `GET /delegate/scim/users/:id` - get a single user via SCIM.
pub async fn delegate_scim_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!(
        "{}/scim/v2/Users/{}",
        sentin8_auth_url.trim_end_matches('/'),
        id
    );
    let resp = client
        .get(&scim_url)
        .header("accept", "application/scim+json")
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth SCIM get failed: {e}"),
            )
        })?;

    scim_response(resp).await
}

/// `PUT /delegate/scim/users/:id` - replace a user via SCIM.
pub async fn delegate_scim_replace(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!(
        "{}/scim/v2/Users/{}",
        sentin8_auth_url.trim_end_matches('/'),
        id
    );
    let resp = client
        .put(&scim_url)
        .header("content-type", "application/scim+json")
        .header("accept", "application/scim+json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth SCIM replace failed: {e}"),
            )
        })?;

    scim_response(resp).await
}

/// `PATCH /delegate/scim/users/:id` - partial update via SCIM.
pub async fn delegate_scim_patch(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!(
        "{}/scim/v2/Users/{}",
        sentin8_auth_url.trim_end_matches('/'),
        id
    );
    let resp = client
        .patch(&scim_url)
        .header("content-type", "application/scim+json")
        .header("accept", "application/scim+json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("auth SCIM patch failed: {e}"),
            )
        })?;

    scim_response(resp).await
}

/// `DELETE /delegate/scim/users/:id` - deactivate a user via SCIM.
pub async fn delegate_scim_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let sentin8_auth_url = resolve_env_sentin8_auth_url(&state, &headers).await;
    let client = get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let scim_url = format!(
        "{}/scim/v2/Users/{}",
        sentin8_auth_url.trim_end_matches('/'),
        id
    );
    let resp = client.delete(&scim_url).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("auth SCIM delete failed: {e}"),
        )
    })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body,
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Helper: parse a reqwest response into a SCIM JSON value or error.
async fn scim_response(
    resp: reqwest::Response,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let status = resp.status();
    let body = scim_response_value(resp).await?;
    if !status.is_success() {
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body.to_string(),
        ));
    }
    Ok(Json(body))
}

/// Helper: extract JSON body from a reqwest response.
async fn scim_response_value(
    resp: reqwest::Response,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let text = resp
        .text()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if text.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&text).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("SCIM response parse failed: {e} - body: {text}"),
        )
    })
}

/// Resolve the env-scoped (customer) Auth URL for CIBA calls.
///
/// Always uses the env-scoped Auth - never the staff Auth - regardless of
/// the app's auth mode. Customer tokens must come from the customer's own env.
async fn resolve_env_sentin8_auth_url(state: &AppState, headers: &HeaderMap) -> String {
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok());
    // org_id is no longer in TLS headers - resolve from env_id via DB when needed.
    let env_id = match env_id {
        Some(e) => e,
        _ => return state.config.sentin8_auth_base_url.clone(),
    };
    let url = format!(
        "{}/v1/env/{}/auth-domain",
        state.config.sentin8_sys_base_url.trim_end_matches('/'),
        env_id
    );

    // BFF-only surface - present the delegator CERTIFICATE identity
    // (the transport authenticates at the TLS layer).
    // Best-effort: on identity failure fall back to the platform auth
    // issuer as before.
    let client = match get_sentin8_bff_m2m_token(&state.config).await {
        Ok(c) => c,
        Err(_) => return state.config.sentin8_auth_base_url.clone(),
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let domain = data["auth_domain"].as_str().unwrap_or("");
                if !domain.is_empty() {
                    return domain.to_string();
                }
            }
        }
        _ => {}
    }
    state.config.sentin8_auth_base_url.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegate_start_request() {
        let req = DelegateStartRequest {
            customer_id: "cust-123".into(),
            flow: "ciba".into(),
            scope: "openid".into(),
            binding_message: "Test".into(),
            reason: Some("support".into()),
            login_hint: "customer@example.com".into(),
        };
        assert_eq!(req.flow, "ciba");
        assert_eq!(req.login_hint, "customer@example.com");
    }

    #[test]
    fn delegate_poll_response_pending() {
        let resp = DelegatePollResponse {
            status: "pending".into(),
            delegation_token: None,
            expires_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "pending");
        assert!(json.get("delegation_token").is_none());
    }

    #[test]
    fn delegate_poll_response_approved() {
        let resp = DelegatePollResponse {
            status: "approved".into(),
            delegation_token: Some("token123".into()),
            expires_at: Some(1234567890),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "approved");
        assert_eq!(json["delegation_token"], "token123");
    }

    #[test]
    fn delegate_status_response_no_token() {
        let resp = DelegateStatusResponse {
            has_token: false,
            expires_at: None,
            scope: None,
            customer_sub: None,
            delegation_id: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["has_token"], false);
    }
}
