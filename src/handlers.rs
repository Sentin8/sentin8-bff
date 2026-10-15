// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for BFF session management and auth callbacks.
//!
//!–, , , .

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use sqlx::Row;

use crate::config::Bff8Config;
use crate::session::{self, Session, SessionStore};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Bff8Config>,
    pub store: SessionStore,
    pub pool: sqlx::PgPool,
    /// Bus client for the WS consumer (M2M token with bus:consume scope).
    pub sentin8_bus_consumer_client: sentin8::bus::client::BusClient,
    /// Shield engine ( — ): additional gate for admin
    /// endpoints (the proxy data path stays scope-gated; no policy on hot path).
    pub policy: Arc<crate::policy::Engine>,
}

// ── Auth login ──────────────────────────────────────────────────────────

/// `GET /auth/login` — redirect to Auth `/oauth/authorize` with PKCE.
///
///: Initiates the OAuth code flow.
pub async fn auth_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Result<Response, (StatusCode, String)> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // org_id is no longer in TLS headers — resolve from env_id via DB.
    let org_id = if !env_id.is_empty() {
        crate::tenant::resolve_org_id_from_env_id(&state.pool, env_id)
            .await
            .map(|id| id.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    tracing::info!(
        %host,
        %hostname,
        org_id = %org_id,
        env_id = %env_id,
        "bff: auth_login received request"
    );
    // Resolve the app instance's auth_domain (selected at install time) and
    // OAuth client ID from Sys. If auth_domain is set, use it directly;
    // otherwise fall back to the env-scoped Auth URL.
    let info = resolve_app_auth_info(&state, &headers).await;
    let (auth_domain, instance_cid) = (info.auth_domain, info.oauth_client_id);
    let sentin8_auth_base_url = if !auth_domain.is_empty() {
        if auth_domain.starts_with("http") {
            auth_domain.clone()
        } else {
            format!("https://{}", auth_domain)
        }
    } else {
        resolve_tenant_sentin8_auth_url(&state, &headers).await?
    };
    let oauth_client_id = if !instance_cid.is_empty() {
        instance_cid
    } else {
        state.config.oauth_client_id.clone()
    };
    tracing::info!(%sentin8_auth_base_url, %oauth_client_id, "bff: resolved auth URL");
    // Derive the app frontend URL from the TLS hostname header.
    // e.g. "sentin8-bff.sentin8-dash.ops.sys.sentin8.local" → "https://sentin8-dash.ops.sys.sentin8.local"
    // This is used as the OAuth `state` so the callback knows where to
    // redirect after the session is created.
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let app_frontend_url = derive_app_frontend_url(hostname, &state.config.sentin8_domain);
    // Check for a custom domain (e.g. www.ibank.local) — if set, use that
    // instead of the derived app hostname for the post-login redirect.
    let custom_domain_url = resolve_app_custom_domain(&state, &org_id, env_id, hostname).await;
    let oauth_state = if !custom_domain_url.is_empty() {
        custom_domain_url
    } else if app_frontend_url.is_empty() {
        q.state.clone()
    } else {
        app_frontend_url.clone()
    };

    // Derive the redirect_uri from the tls hostname header so the
    // OAuth callback goes back to the same BFF instance that initiated
    // the flow. e.g. "sentin8-bff.sentin8-dash.ops.sys.sentin8.local" → "https://sentin8-bff.sentin8-dash.ops.sys.sentin8.local/auth/callback"
    // Fall back to static config if no hostname header.
    let redirect_uri = if hostname.is_empty() {
        state.config.oauth_redirect_uri.clone()
    } else {
        format!("https://{}/auth/callback", hostname)
    };
    tracing::info!(%redirect_uri, %oauth_state, "bff: auth_login redirect_uri and state");

    // Generate PKCE verifier + challenge.
    let verifier = sentin8::auth::client::generate_pkce_verifier();
    let _challenge = sentin8::auth::client::pkce_s256_challenge(&verifier);

    // Store the verifier in a short-lived cookie for the callback.
    // For sentin8.local subdomains (e.g. sentin8-bff.sentin8-dash.ops.sys.sentin8.local), use Domain=.sentin8.local
    // so the cookie is shared across subdomains.
    // For custom domains (e.g. bff.www.ibank.local), use the parent domain
    // (e.g. .www.ibank.local) so the cookie is shared across the custom
    // domain's subdomains. The leading "bff." is just the BFF
    // host prefix; everything after it is the parent's host pattern.
    // If the hostname doesn't match any known pattern, omit Domain entirely
    // (scoped to the exact host).
    let pkce_domain = if hostname.ends_with(&state.config.sentin8_domain) {
        state.config.sentin8_domain.clone()
    } else if let Some(rest) = hostname.strip_prefix("bff.") {
        rest.to_string()
    } else {
        state.config.sentin8_domain.clone()
    };
    let pkce_cookie = format!(
        "bff-pkce={}; Path=/; Domain=.{pkce_domain}; HttpOnly; Secure; SameSite=None; Max-Age=300",
        verifier
    );

    //use the fapiclient SDK for OIDC discovery-driven
    // authorize URL construction. This reads endpoint URLs from the Auth OIDC
    // discovery document instead of constructing from assumptions.
    //
    // TLS trust: the workspace uses `rustls-tls-native-roots`, so reqwest
    // automatically trusts CAs installed in the OS trust store (via
    // `update-ca-certificates`). No explicit CA loading or
    // `danger_accept_invalid_certs` is needed.
    let fapi_builder = sentin8::auth::fapi::Client::builder()
        .issuer_url(sentin8_auth_base_url)
        .client_id(oauth_client_id)
        .redirect_uri(redirect_uri.clone());
    let fapi_opts = fapi_builder
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fapi_client = sentin8::auth::fapi::Client::new(fapi_opts)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Resolve the app instance's allowed_scopes so the authorize request
    // carries the app's required scopes (e.g. `fdx:recipient:read`). Auth
    // UNIONS requested scopes into the access token (see auth
    // `merge_scopes`), so requesting them here is what places them in the
    // session token — the FDX recipient API then authorizes on them.
    let scope_string = if !q.scope.is_empty() {
        q.scope.clone()
    } else {
        let allowed = resolve_app_scopes(&state, hostname).await;
        if allowed.is_empty() {
            "openid profile email offline_access".to_string()
        } else {
            // Always include the OIDC baseline, then the app scopes (deduped).
            let mut all: Vec<&str> = ["openid", "profile", "email", "offline_access"].to_vec();
            for s in &allowed {
                if !all.contains(&s.as_str()) {
                    all.push(s.as_str());
                }
            }
            all.join(" ")
        }
    };
    tracing::info!(scope = %scope_string, "bff: auth_login resolved authorize scope");

    let authorize_url = fapi_client
        .authorize_url(&verifier, &scope_string, &oauth_state)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "bff: auth_login fapi authorize_url failed");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    tracing::info!(%authorize_url, "bff: auth_login redirecting to auth authorize URL");

    Ok((
        StatusCode::FOUND,
        [("location", authorize_url), ("set-cookie", pkce_cookie)],
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
}

/// `GET /auth/sign-up` — redirect to Auth `/sign-up` page.
///
/// Apps like eBank redirect here to initiate customer sign-up.
/// We simply forward to the Auth hosted sign-up page with the same
/// OAuth parameters as login (PKCE, client_id, redirect_uri).
pub async fn auth_sign_up(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Result<Response, (StatusCode, String)> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // org_id is no longer in TLS headers — resolve from env_id via DB.
    let org_id = if !env_id.is_empty() {
        crate::tenant::resolve_org_id_from_env_id(&state.pool, env_id)
            .await
            .map(|id| id.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    tracing::info!(
        %host,
        %hostname,
        org_id = %org_id,
        env_id = %env_id,
        "bff: auth_sign_up received request"
    );
    // Resolve the app instance's auth_domain and OAuth client ID (same as login).
    let info = resolve_app_auth_info(&state, &headers).await;
    let (auth_domain, instance_cid) = (info.auth_domain, info.oauth_client_id);
    let sentin8_auth_base_url = if !auth_domain.is_empty() {
        if auth_domain.starts_with("http") {
            auth_domain.clone()
        } else {
            format!("https://{}", auth_domain)
        }
    } else {
        resolve_tenant_sentin8_auth_url(&state, &headers).await?
    };
    let oauth_client_id = if !instance_cid.is_empty() {
        instance_cid
    } else {
        state.config.oauth_client_id.clone()
    };
    tracing::info!(%sentin8_auth_base_url, %oauth_client_id, "bff: auth_sign_up resolved auth URL and client ID");

    // Reuse the login flow but redirect to /sign-up instead of /oauth/authorize.
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let app_frontend_url = derive_app_frontend_url(hostname, &state.config.sentin8_domain);
    // Check for a custom domain (e.g. www.ibank.local) — if set, use that
    // instead of the derived app hostname for the post-signup redirect.
    let custom_domain_url = resolve_app_custom_domain(&state, &org_id, env_id, hostname).await;
    let oauth_state = if !custom_domain_url.is_empty() {
        custom_domain_url
    } else if app_frontend_url.is_empty() {
        q.state.clone()
    } else {
        app_frontend_url.clone()
    };

    // Derive the redirect_uri from the tls hostname header (same as login).
    let redirect_uri = if hostname.is_empty() {
        state.config.oauth_redirect_uri.clone()
    } else {
        format!("https://{}/auth/callback", hostname)
    };

    let verifier = sentin8::auth::client::generate_pkce_verifier();
    // Derive PKCE cookie domain (same logic as auth_login).
    let pkce_domain = if hostname.ends_with(&state.config.sentin8_domain) {
        state.config.sentin8_domain.clone()
    } else if let Some(rest) = hostname.strip_prefix("bff.") {
        rest.to_string()
    } else {
        state.config.sentin8_domain.clone()
    };
    let pkce_cookie = format!(
        "bff-pkce={}; Path=/; Domain=.{pkce_domain}; HttpOnly; Secure; SameSite=None; Max-Age=300",
        verifier
    );

    let fapi_builder = sentin8::auth::fapi::Client::builder()
        .issuer_url(sentin8_auth_base_url.clone())
        .client_id(oauth_client_id.clone())
        .redirect_uri(redirect_uri.clone());
    let fapi_opts = fapi_builder
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fapi_client = sentin8::auth::fapi::Client::new(fapi_opts)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Resolve the app instance's allowed_scopes so the sign-up authorize
    // request carries the app's required scopes (e.g.
    // `fdx:recipient:read`), exactly like auth_login does. Without this,
    // the token issued at sign-up only carries the OIDC baseline scopes
    // and the app sees empty data (e.g. "No providers available." on the
    // eFintech Providers page) until the user signs in again.
    let scope_string = if !q.scope.is_empty() {
        q.scope.clone()
    } else {
        let allowed = resolve_app_scopes(&state, hostname).await;
        if allowed.is_empty() {
            "openid profile email offline_access".to_string()
        } else {
            // Always include the OIDC baseline, then the app scopes (deduped).
            let mut all: Vec<&str> = ["openid", "profile", "email", "offline_access"].to_vec();
            for s in &allowed {
                if !all.contains(&s.as_str()) {
                    all.push(s.as_str());
                }
            }
            all.join(" ")
        }
    };
    tracing::info!(scope = %scope_string, "bff: auth_sign_up resolved authorize scope");

    // Build the authorize URL via the FAPI client (uses PAR when required).
    // We keep the `/oauth/authorize` endpoint in the URL so Auth resolves the
    // PAR session server-side and can re-inline the full OAuth params
    // (redirect_uri, state, code_challenge) when redirecting to the hosted
    // sign-up page. The `screen_hint=signup` query param tells Auth to route
    // the user to `/sign-up` instead of `/sign-in`.
    let authorize_url = fapi_client
        .authorize_url(&verifier, &scope_string, &oauth_state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let sign_up_url = format!("{}&screen_hint=signup", authorize_url);

    Ok((
        StatusCode::FOUND,
        [("location", sign_up_url), ("set-cookie", pkce_cookie)],
    )
        .into_response())
}

/// Resolve the app instance's auth_domain and OAuth client ID from Sys.
///
/// Returns `(auth_domain, oauth_client_id)`. `auth_domain` is the hostname
/// selected at install time (e.g. `auth.staff.ibank.local`). When empty,
/// the BFF falls back to the env-scoped Auth URL. `oauth_client_id` is the
/// DCR-registered client ID for this instance (empty → use BFF's global client).
/// Uses the Sys HTTP API `GET /v1/app-instance/auth-mode`.
pub(crate) struct AppAuthInfo {
    /// The instance's auth_domain (staff mode) — empty when env-scoped.
    pub auth_domain: String,
    /// The app-instance OAuth client at the instance's auth env
    /// (sign-in flows).
    pub oauth_client_id: String,
    /// The app-instance CIBA client at the CUSTOMER env's auth
    /// (staff-mode only; equals oauth_client_id for env-scoped apps).
    pub ciba_oauth_client_id: String,
}

pub(crate) async fn resolve_app_auth_info(state: &AppState, headers: &HeaderMap) -> AppAuthInfo {
    const NONE: fn() -> AppAuthInfo = || AppAuthInfo {
        auth_domain: String::new(),
        oauth_client_id: String::new(),
        ciba_oauth_client_id: String::new(),
    };
    let app_id = headers
        .get("x-sentin8-app-id")
        .and_then(|v| v.to_str().ok());
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if app_id.is_none() && hostname.is_empty() {
        return NONE();
    }
    let client = match crate::proxy::get_sentin8_bff_m2m_token(&state.config).await {
        Ok(t) => t,
        Err(_) => return NONE(),
    };
    let url = if let Some(id) = app_id {
        format!(
            "{}/v1/app-instance/auth-mode?app_id={}",
            state.config.sentin8_sys_base_url.trim_end_matches('/'),
            id
        )
    } else {
        format!(
            "{}/v1/app-instance/auth-mode?hostname={}",
            state.config.sentin8_sys_base_url.trim_end_matches('/'),
            hostname
        )
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(data) => AppAuthInfo {
                auth_domain: data["auth_domain"].as_str().unwrap_or("").to_string(),
                oauth_client_id: data["oauth_client_id"].as_str().unwrap_or("").to_string(),
                ciba_oauth_client_id: data["ciba_oauth_client_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            },
            Err(_) => NONE(),
        },
        _ => NONE(),
    }
}

async fn resolve_tenant_sentin8_auth_url(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok());
    let env_id = match env_id {
        // No tenant headers → platform BFF (e.g. sentin8-bff.sentin8-dash.ops.sys.sentin8.local).
        // Use the platform auth issuer.
        None => {
            tracing::info!("bff: no tls env header, using platform auth");
            return Ok(state.config.sentin8_auth_base_url.clone());
        }
        Some(e) => e,
    };
    // org_id is no longer in TLS headers — resolve from env_id via DB.
    let org_id = crate::tenant::resolve_org_id_from_env_id(&state.pool, env_id)
        .await
        .map(|id| id.to_string())
        .unwrap_or_default();
    // System org / ops env → platform BFF (e.g. bff.dash.ops.sys.sentin8.local).
    // The system env has no custom auth_domain in Sys; use the platform auth issuer.
    if org_id == sentin8::config::SYSTEM_ORG_ID.to_string()
        && env_id == sentin8::config::SYSTEM_ENV_ID.to_string()
    {
        tracing::info!("bff: system org/env detected, using platform auth");
        return Ok(state.config.sentin8_auth_base_url.clone());
    }
    // Tenant headers present — resolve the env's auth domain from Sys.
    // Fail fast on any error: silently falling back to the platform
    // `auth.{sentin8_domain}` caused tenant logins to land on the wrong auth.
    let sentin8_sys_url = format!(
        "{}/v1/env/{}/auth-domain",
        state.config.sentin8_sys_base_url.trim_end_matches('/'),
        env_id
    );
    // BFF-only surface — present the delegator CERTIFICATE identity
    // (the transport authenticates at Sys's TLS layer).
    let client = crate::proxy::get_sentin8_bff_m2m_token(&state.config)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to get BFF M2M token: {e}"),
            )
        })?;
    let resp = client.get(&sentin8_sys_url).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Sys auth-domain request failed: {e}"),
        )
    })?;
    if !resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Sys auth-domain request failed: status {}", resp.status()),
        ));
    }
    let data = resp.json::<serde_json::Value>().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Sys auth-domain response decode failed: {e}"),
        )
    })?;
    let domain = data["auth_domain"].as_str().unwrap_or("");
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Sys returned empty auth_domain for org/env (env not found or misconfigured)".into(),
        ));
    }
    tracing::info!(domain = %domain, "bff: resolved tenant auth_domain via Sys");
    Ok(domain.to_string())
}

/// Resolve an app instance's OAuth `allowed_scopes` from Sys by hostname.
///
/// Mirrors `resolve_tenant_sentin8_auth_url`: BFF stays decoupled from Sys's DB
/// schema by calling the Sys HTTP endpoint. Returns the instance's
/// `allowed_scopes` (empty if the instance is unknown / not yet provisioned).
async fn resolve_app_scopes(state: &AppState, hostname: &str) -> Vec<String> {
    if hostname.is_empty() {
        return Vec::new();
    }
    let url = format!(
        "{}/v1/app-instance/scopes?hostname={}",
        state.config.sentin8_sys_base_url.trim_end_matches('/'),
        hostname
    );
    let client = match crate::proxy::get_sentin8_bff_m2m_token(&state.config).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "bff: failed to get delegator transport for instance scopes");
            return Vec::new();
        }
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(data) => data
                .get("allowed_scopes")
                .and_then(|s| s.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, "bff: instance scopes response decode failed");
                Vec::new()
            }
        },
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "bff: instance scopes request failed");
            Vec::new()
        }
        Err(e) => {
            tracing::warn!(error = %e, "bff: instance scopes request error");
            Vec::new()
        }
    }
}

// ── Session hardening helpers ──────────────────────

/// Full app-instance identity for the session-hardening checks.
#[derive(Debug, Clone, Default)]
struct AppInstanceInfo {
    application_id: String,
    org_id: String,
    env_id: String,
    instance_name: String,
    app_slug: String,
    auth_domain: String,
    /// F-A gate mode from `app_instances.group_gate` (see BFF design
    /// ): "strict" → app-group membership required (fail-closed);
    /// "self_service" → authentication + D3 auth-env match is sufficient
    /// (first-party platform surfaces such as the platform Dash).
    group_gate: String,
}

/// Resolve the app instance for the request hostname via Sys
/// `GET /v1/app-instance/auth-mode` (returns application_id, org_id,
/// env_id, instance_name, app_slug, auth_domain since 12.).
/// Returns `None` when no instance matches (platform BFF bootstrap).
async fn resolve_app_instance(state: &AppState, headers: &HeaderMap) -> Option<AppInstanceInfo> {
    let app_id = headers
        .get("x-sentin8-app-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if app_id.is_empty() && hostname.is_empty() {
        return None;
    }
    let client = match crate::proxy::get_sentin8_bff_m2m_token(&state.config).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "bff: failed to get delegator transport for instance lookup");
            return None;
        }
    };
    let url = if !app_id.is_empty() {
        format!(
            "{}/v1/app-instance/auth-mode?app_id={}",
            state.config.sentin8_sys_base_url.trim_end_matches('/'),
            app_id
        )
    } else {
        format!(
            "{}/v1/app-instance/auth-mode?hostname={}",
            state.config.sentin8_sys_base_url.trim_end_matches('/'),
            hostname
        )
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(data) => {
                let application_id = data["application_id"].as_str().unwrap_or("").to_string();
                if application_id.is_empty() {
                    // No instance matched — platform BFF (Dash) bootstrap.
                    return None;
                }
                Some(AppInstanceInfo {
                    application_id,
                    org_id: data["org_id"].as_str().unwrap_or("").to_string(),
                    env_id: data["env_id"].as_str().unwrap_or("").to_string(),
                    instance_name: data["instance_name"].as_str().unwrap_or("").to_string(),
                    app_slug: data["app_slug"].as_str().unwrap_or("").to_string(),
                    auth_domain: data["auth_domain"].as_str().unwrap_or("").to_string(),
                    group_gate: data["group_gate"].as_str().unwrap_or("strict").to_string(),
                })
            }
            Err(e) => {
                tracing::warn!(error = %e, "bff: instance lookup response decode failed");
                None
            }
        },
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "bff: instance lookup request failed");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "bff: instance lookup request error");
            None
        }
    }
}

/// OWNER API client for session enrichment (DBX — no auth.* grants):
/// resolves the caller's profile, roles, groups, and LIVE effective scopes
/// from Auth's `GET /oauth/userinfo` using the session's own user access
/// token as the bearer. Auth verifies the token server-side (SEC-).
async fn auth_userinfo(state: &AppState, user_token: &str) -> Result<serde_json::Value, String> {
    let url = format!(
        "{}/oauth/userinfo",
        state.config.sentin8_auth_base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let resp = client
        .get(&url)
        .bearer_auth(user_token)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("userinfo status {status}"));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("decode: {e}"))
}

/// D3 — auth-env match. The token's env must belong to the
/// instance's org. When the instance uses a dedicated `auth_domain`
/// (staff-auth apps like eTeller via `auth.staff.{org_domain}`), the token
/// env must BE the auth env — a prod-env customer token is rejected.
///
/// The auth env is resolved from the auth_domain hostname pattern
/// `auth.{env_slug}.{org_domain}` (see app setup_instance). When the
/// auth_domain is empty (customer apps), only the org match is enforced
/// (the app uses the install env's Auth, so a same-org foreign-env token
/// is still rejected by the group gate — the app group lives in the
/// install env).
async fn auth_env_matches(state: &AppState, inst: &AppInstanceInfo, token_env_id: &str) -> bool {
    let token_env: uuid::Uuid = match uuid::Uuid::parse_str(token_env_id) {
        Ok(u) => u,
        Err(_) => return false,
    };
    // Instance env parse — a malformed instance env_id means we cannot
    // establish the tenant relationship; fail-closed unless auth_domain
    // is also empty (platform bootstrap).
    let inst_env_ok = uuid::Uuid::parse_str(&inst.env_id).is_ok();
    if !inst_env_ok && !inst.auth_domain.is_empty() {
        tracing::warn!(instance_env = %inst.env_id, "bff: invalid instance env_id — rejecting");
        return false;
    }
    // Org match first: the token env must belong to the instance's org.
    // Context-first read : the context is
    // transaction-local and the connection-level default is empty, so an
    // autocommit read sees zero rows under FORCE RLS.
    let token_org: Option<uuid::Uuid> =
        crate::tenant::resolve_org_id_from_env_id(&state.pool, token_env_id).await;
    let Some(token_org) = token_org else {
        tracing::warn!(token_env = %token_env_id, "bff: token env not found in environments");
        return false;
    };
    if token_org.to_string() != inst.org_id {
        tracing::warn!(
            token_org = %token_org,
            instance_org = %inst.org_id,
            "bff: token org does not match the app instance's org"
        );
        return false;
    }
    // Staff-auth app (auth_domain set): token env must be the auth env.
    if !inst.auth_domain.is_empty() {
        // auth_domain looks like auth.{env_slug}.{org_domain} — resolve the
        // env whose Auth hostname matches. The app service resolves it the
        // same way at install (matching auth.{env_slug}.{org.domain}).
        let org: uuid::Uuid = match uuid::Uuid::parse_str(&inst.org_id) {
            Ok(u) => u,
            Err(_) => {
                tracing::warn!(org_id = %inst.org_id, "bff: invalid instance org_id");
                return false;
            }
        };
        // Context-first reads : the org-wide
        // branch of sys_environments_select admits rows only when the
        // context's env belongs to that org — set the token env's context
        // (the verified tenant of this request) in the same transaction.
        // Both resolution queries (hostname-pattern + slug fallback) run on
        // that one transaction connection.
        let auth_env: Option<uuid::Uuid> = (async {
            let mut tx = state.pool.begin().await.ok()?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', true, false)")
                .bind(token_env)
                .execute(&mut *tx)
                .await;
            let first: Option<uuid::Uuid> = sqlx::query_scalar(
                r#"SELECT e.id FROM sys.environments e
                     JOIN sys.organizations o ON o.id = e.org_id
                    WHERE e.org_id = $1
                      AND LOWER('auth.' || e.slug || '.' || o.domain) = LOWER($2)"#,
            )
            .bind(org)
            .bind(
                inst.auth_domain
                    .trim_start_matches("https://")
                    .trim_start_matches("http://"),
            )
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            let resolved = match first {
                Some(e) => Some(e),
                None => {
                    // Fallback: derive the env from the auth_domain's
                    // second label (env slug) + org domain, when the
                    // pattern match missed (custom auth domains).
                    let host = inst
                        .auth_domain
                        .trim_start_matches("https://")
                        .trim_start_matches("http://");
                    let labels: Vec<&str> = host.split('.').collect();
                    if labels.len() >= 3 {
                        sqlx::query_scalar(
                            r#"SELECT e.id FROM sys.environments e
                                 JOIN sys.organizations o ON o.id = e.org_id
                                WHERE e.slug = $1 AND o.id = $2"#,
                        )
                        .bind(labels[1])
                        .bind(org)
                        .fetch_optional(&mut *tx)
                        .await
                        .ok()
                        .flatten()
                    } else {
                        None
                    }
                }
            };
            tx.rollback().await.ok()?;
            resolved
        })
        .await;
        match auth_env {
            Some(ae) if ae == token_env => true,
            Some(ae) => {
                tracing::warn!(
                    token_env = %token_env_id,
                    auth_env = %ae,
                    auth_domain = %inst.auth_domain,
                    "bff: token env is not the app's auth environment"
                );
                false
            }
            None => {
                // Cannot resolve the auth env from the auth_domain —
                // fail-closed: refuse the session rather than mint one
                // against an unverifiable auth environment.
                tracing::warn!(auth_domain = %inst.auth_domain, "bff: cannot resolve auth env from auth_domain — rejecting");
                false
            }
        }
    } else {
        true
    }
}

/// F-A — app-group membership gate. How strictly the gate
/// applies is a declarative property of the instance itself
/// (`app_instances.group_gate`, resolved via Sys auth-mode):
///
/// - `strict` (default, every app instance): the user must be a member of
///
/// the instance's `sentin8:app:{instance_id}` group in the token's
/// auth env — fail-closed. Customer apps never see the gate (users are
/// auto-added at sign-up); staff apps enforce explicit membership (the
///
/// "Ben must not silently become a teller" rule).
/// - `self_service`: authentication itself is the authorization — any user
///
/// who completed the OAuth flow (and passed the D3 auth-env check in the
/// caller) obtains a session. Used for first-party platform surfaces
///
/// (platform Dash) whose self-service users create their first org
/// before any group membership can exist.
///
/// Returns Err(status, message) on rejection.
///
/// Note: the group catalog is env-scoped (`groups.env_id`); the
/// group lives in the app's AUTH env (staff groups in the staff env,
/// customer groups in the install env — see app setup_instance). We query
/// by the token's env: the token was just validated to come from the
/// auth env (D3), so the group must exist there.
async fn check_app_group_membership(
    state: &AppState,
    inst: &AppInstanceInfo,
    token_env_id: &str,
    user_id: &str,
) -> Result<(), String> {
    // Group name mirrors app setup_instance: sentin8:app:{instance_id}
    // ( — the name embeds the instance UUID; the display-name-derived
    // snake_case form is retired — its three implementations had drifted,
    // AUTH-3).
    if inst.application_id.is_empty() {
        return Ok(()); // nothing to gate on (should not happen)
    }
    let group_name = format!("sentin8:app:{}", inst.application_id);
    // Declarative gate mode — data on the instance, never app-specific
    // knowledge in the BFF. Unknown/missing values default to
    // 'strict' (fail-closed) for instances provisioned before the column.
    if inst.group_gate == "self_service" {
        tracing::debug!(
            group = %group_name,
            "bff: gate mode self_service — authentication + D3 suffice"
        );
        return Ok(());
    }
    let user: uuid::Uuid = match uuid::Uuid::parse_str(user_id) {
        Ok(u) => u,
        Err(_) => return Err("invalid user id".to_string()),
    };
    let token_env: uuid::Uuid = match uuid::Uuid::parse_str(token_env_id) {
        Ok(u) => u,
        Err(_) => return Err("invalid token env".to_string()),
    };
    // Distinguish "group not provisioned" from "user not a member":
    // - Group MISSING in the token's auth env → allow with a warning. All
    // platform apps now provision their group (Dash is seeded in
    // sys init SQL; app instances at install time via app
    // setup_instance) — so a missing group means an unregistered/legacy
    // install, not an intended exception. Keeping allow here avoids
    // bricking sign-in if provisioning raced or was skipped; the
    // warn makes it visible.
    // - Group EXISTS but the user is not a member → reject (fail-closed).
    // Same-transaction context (rule 2): `auth.groups` is FORCE-RLS'd with
    // a `sentin8_context_initialized()` gate — both lookups run inside ONE
    // explicit transaction with the token env's context set on the same
    // connection (a bare-pool read sees zero rows: the gate silently
    // skipped for EVERY app and the customer auto-add never fired).
    let (group_exists, member): (bool, bool) = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| format!("app-group tx begin failed: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', 'user', '')")
            .bind(token_env)
            .execute(&mut *tx)
            .await;
        let ge: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                  SELECT 1 FROM auth.groups g
                   WHERE g.env_id = $1 AND g.name = $2
               )"#,
        )
        .bind(token_env)
        .bind(&group_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("app-group lookup failed: {e}"))?;
        let m: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                  SELECT 1 FROM auth.group_members gm
                    JOIN auth.groups g ON g.id = gm.group_id
                   WHERE gm.user_id = $1
                     AND g.env_id = $2
                     AND g.name = $3
               )"#,
        )
        .bind(user)
        .bind(token_env)
        .bind(&group_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("app-group check failed: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("app-group tx commit failed: {e}"))?;
        (ge, m)
    };
    if !group_exists {
        tracing::info!(group = %group_name, "bff: app group not provisioned — gate skipped (legacy/platform app)");
        return Ok(());
    }
    if member {
        Ok(())
    // F-A customer auto-add (BFF design): a first-party CUSTOMER app
    // (no dedicated staff auth_domain) must never lock out the user who
    // just completed its own OAuth consent — add the member on the spot
    // through Auth's provisioning API (`sentin8:auth:admin:write`, the
    // `bff-provision` workload; no direct auth-table writes). STAFF apps
    // (auth_domain set) keep the fail-closed membership requirement — an
    // org-admin who is not a teller can never obtain a teller session.
    } else if inst.auth_domain.is_empty() {
        match crate::auth_provision::Provisioner::shared().await {
            Some(p) => match p.group_member(token_env, &group_name, user).await {
                Ok(_) => {
                    tracing::info!(
                        group = %group_name,
                        user_id = %user_id,
                        "bff: customer auto-added to the app instance group (F-A)"
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!(error = %e, group = %group_name, "bff: customer auto-add failed — denying (fail-closed)");
                    Err(format!(
                        "not a member of this app ({group_name}) and auto-add failed"
                    ))
                }
            },
            None => {
                tracing::warn!(group = %group_name, "bff: auth provisioner unavailable — denying (fail-closed)");
                Err(format!("not a member of this app ({group_name})"))
            }
        }
    } else {
        Err(format!("not a member of this app ({group_name})"))
    }
}

// ── DPoP key provisioning (design ) ──────────────────────

/// Process-global DPoP signing key (ES256 P-256, PKCS#8 PEM).
///
/// Generated once per process on first use. Sentin8:Auth verifies DPoP
/// proofs against the `jwk` embedded in the proof header — self-contained,
/// no key registration — so an ephemeral per-process keypair is correct:
/// every proof the BFF signs during its lifetime verifies, and restarts
/// simply rotate the key (old tokens already carry their `cnf.jkt`).
pub(crate) fn dpop_key_pem() -> String {
    use std::sync::OnceLock;
    static DPOP_KEY: OnceLock<Result<String, String>> = OnceLock::new();
    match DPOP_KEY.get_or_init(|| {
        sentin8::auth::fapi::generate_dpop_key_pem()
            .map_err(|e| e.to_string())
            .inspect_err(|e| {
                tracing::error!(error = %e, "bff: DPoP key generation failed — DPoP-required exchanges will fail");
            })
    }) {
        Ok(pem) => pem.clone(),
 // Unreachable in practice — keygen only fails on RNG/serialization
 // errors. Fail loud: an empty key would send an invalid proof.
        Err(e) => panic!("DPoP key generation failed: {e}"),
    }
}

// ── Auth callback ────────────────────────────────────────────────────────

/// `GET /auth/callback` — OAuth code exchange, session creation, cookie set.
///
///: Exchanges the auth code for tokens (server-side), creates
/// an encrypted session in Valkey, sets the `__Host-bff-session` cookie.
pub async fn auth_callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // org_id is no longer in TLS headers — resolve from env_id via DB.
    let org_id = if !env_id.is_empty() {
        crate::tenant::resolve_org_id_from_env_id(&state.pool, env_id)
            .await
            .map(|id| id.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    tracing::info!(
        %host,
        %hostname,
        org_id = %org_id,
        env_id = %env_id,
        code = %q.code,
        "bff: auth_callback received OAuth code"
    );
    // Extract the PKCE verifier from the cookie.
    let pkce_verifier = extract_cookie(&headers, "bff-pkce").unwrap_or_default();
    if pkce_verifier.is_empty() {
        tracing::warn!("bff: auth_callback no PKCE verifier cookie found");
    }

    // Exchange the code for tokens at Auth.
    // Resolve the same auth URL that the login handler used — if the app
    // instance has an auth_domain set, use it; otherwise fall back to the
    // env-scoped Auth URL.
    let info = resolve_app_auth_info(&state, &headers).await;
    let (auth_domain, instance_cid) = (info.auth_domain, info.oauth_client_id);
    let sentin8_auth_base_url = if !auth_domain.is_empty() {
        if auth_domain.starts_with("http") {
            auth_domain.clone()
        } else {
            format!("https://{}", auth_domain)
        }
    } else {
        match resolve_tenant_sentin8_auth_url(&state, &headers).await {
            Ok(url) => url,
            Err((status, msg)) => return (status, msg).into_response(),
        }
    };
    let token_url = format!("{}/oauth/token", sentin8_auth_base_url);
    // Derive the redirect_uri from the tls hostname (must match what was
    // used in the authorize request).
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let redirect_uri = if hostname.is_empty() {
        state.config.oauth_redirect_uri.clone()
    } else {
        format!("https://{}/auth/callback", hostname)
    };
    // Use the app instance's DCR-registered OAuth client ID (must match the
    // client_id used in the authorize request).
    let oauth_client_id = if !instance_cid.is_empty() {
        instance_cid
    } else {
        state.config.oauth_client_id.clone()
    };

    // — exchange via the fapiclient SDK, which
    // discovery-drives the token endpoint and attaches a DPoP proof when
    // `dpop_signing_alg_values_supported` is advertised. Under the `fapi_2`
    // platform profile, DPoP is REQUIRED for user-facing grants on every
    // non-exempt client — all DCR-registered app-instance clients — so a
    // plain form POST gets `401 DPoP proof required for this grant`. The
    // BFF holds its own ES256 key (startup-generated, in-process); Auth
    // verifies proofs against the embedded `jwk` and binds `cnf.jkt`.
    let fapi_opts = match sentin8::auth::fapi::ClientOptions::builder()
        .issuer_url(sentin8_auth_base_url.clone())
        .client_id(oauth_client_id.clone())
        .redirect_uri(redirect_uri.clone())
        .dpop_key(dpop_key_pem(), "ES256")
        .build()
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = ?e, "bff: auth_callback fapi options build failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("fapi client build failed: {e}"),
            )
                .into_response();
        }
    };
    let fapi_client = match sentin8::auth::fapi::Client::new(fapi_opts) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "bff: auth_callback fapi client build failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("fapi client build failed: {e}"),
            )
                .into_response();
        }
    };
    let exchange_result = fapi_client
        .exchange_code(&q.code, &pkce_verifier, None)
        .await;

    // fapiclient's TokenResponse → the callback's internal shape (id_token
    // is not consumed here — the session stores access/refresh only).
    let token_data: TokenExchangeResponse = match exchange_result {
        Ok(d) => {
            tracing::info!(%token_url, "bff: auth_callback token exchange succeeded");
            TokenExchangeResponse {
                access_token: d.access_token,
                refresh_token: d.refresh_token,
                token_type: d.token_type,
                expires_in: d.expires_in,
                scope: d.scope,
            }
        }
        Err(e) => {
            tracing::error!(%token_url, error = %e, "bff: auth_callback token exchange failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("Auth token exchange failed: {e}"),
            )
                .into_response();
        }
    };

    // Decode the access token to extract claims (user_id, org_id, env_id).
    // D4 (fail-closed): undecodable claims or a missing env_id REJECT the
    // callback — a broken token never yields a session.
    let (user_id, org_id, token_env_id) =
        match decode_token_claims(&token_data.access_token, &state.pool).await {
            Some(claims) => claims,
            None => {
                tracing::error!(
                    "bff: auth_callback token claims undecodable — rejecting (fail-closed)"
                );
                return (
                    StatusCode::FORBIDDEN,
                    "token claims undecodable".to_string(),
                )
                    .into_response();
            }
        };
    tracing::info!(
        %user_id,
        %org_id,
        %token_env_id,
        scope = ?token_data.scope,
        "bff: auth_callback decoded token claims"
    );

    // ── Session hardening ─────────────────────────────
    // Resolve the app instance from the request hostname. The BFF already
    // resolved auth_domain/client_id above; this extended lookup also
    // returns the instance id, env, and instance name for the binding,
    // auth-env, and group checks below.
    let instance_info = resolve_app_instance(&state, &headers).await;

    // D3 — auth-env match (fail-closed). The token's env must belong to the
    // instance's org, and when the instance uses a dedicated auth_domain
    // (staff-auth apps), the token env must BE the auth env. A prod-env
    // customer token presented to eTeller (auth.staff.*) is rejected here.
    if let Some(inst) = &instance_info {
        if !inst.env_id.is_empty()
            && !token_env_id.is_empty()
            && !auth_env_matches(&state, inst, &token_env_id).await
        {
            tracing::warn!(
                hostname = %hostname,
                token_env = %token_env_id,
                instance_env = %inst.env_id,
                "bff: auth_callback REJECTED — token env does not match the app's auth environment"
            );
            return (
                StatusCode::FORBIDDEN,
                "authenticated against the wrong auth environment".to_string(),
            )
                .into_response();
        }

        // F-A — app-group membership gate (fail-closed by default). The
        // gate mode is declarative on the instance (strict/self_service,
        // see check_app_group_membership): staff apps require explicit
        // membership — an org-admin who is not a teller can never obtain
        // a teller session — while self_service platform surfaces satisfy
        // the gate via authentication + D3.
        if let Err(status_msg) =
            check_app_group_membership(&state, inst, &token_env_id, &user_id).await
        {
            tracing::warn!(
                hostname = %hostname,
                user_id = %user_id,
                "bff: auth_callback REJECTED — {}",
                status_msg
            );
            return (StatusCode::FORBIDDEN, status_msg).into_response();
        }
    }

    // Create an encrypted session.
    let key = session::derive_key(&state.config.encryption_key);
    let mut sess = Session::new(user_id, org_id, token_env_id.clone());
    // D2 — bind the session to the creating app instance.
    if let Some(inst) = &instance_info {
        if !inst.application_id.is_empty() {
            sess.application_id = Some(inst.application_id.clone());
        }
    }
    sess.scope = token_data.scope.clone().unwrap_or_default();
    sess.token_expiry = chrono::Utc::now().timestamp() + token_data.expires_in as i64;
    sess.subject_type = "user".into();

    if let Err(e) = sess.set_access_token(&token_data.access_token, &key) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encryption error: {e}"),
        )
            .into_response();
    }
    if let Some(ref rt) = token_data.refresh_token {
        if let Err(e) = sess.set_refresh_token(rt, &key) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encryption error: {e}"),
            )
                .into_response();
        }
    }

    // Store the session in Valkey.
    if let Err(e) = state.store.create(&sess).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("session store error: {e}"),
        )
            .into_response();
    }

    // Redirect to the frontend with the session cookie set.
    // If state is empty or absent, default to "/" (the Dash homepage).
    let redirect_to = q
        .state
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    tracing::info!(
        %redirect_to,
        session_id = %sess.session_id,
        "bff: auth_callback creating session and redirecting to frontend"
    );

    // Build the response manually — Axum's tuple with [(name, value); N]
    // uses header `insert` (overwrite), so two `set-cookie` entries would
    // clobber each other. Using `Response::builder.header` appends.
    //
    // F-C — cookie domain scoped to the app instance's domain (design
    // ): strip exactly the leading `bff.` label so the cookie is
    // visible on the app frontend + its BFF host and nothing else. The
    // previous derivation short-circuited to the platform root
    // (.sentin8.local), letting one app's session cookie replay at every
    // other BFF in the platform. Hostnames that don't match the
    // app-instance pattern omit the Domain attribute (exact-host cookie).
    let cookie_domain = session::app_cookie_domain_for_host(hostname).unwrap_or_default();
    let pkce_clear = if cookie_domain.is_empty() {
        "bff-pkce=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0".to_string()
    } else {
        format!(
            "bff-pkce=; Path=/; Domain=.{cookie_domain}; HttpOnly; Secure; SameSite=None; Max-Age=0"
        )
    };
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", redirect_to)
        .header("set-cookie", sess.cookie(&cookie_domain))
        .header("set-cookie", pkce_clear)
        .body(Body::empty())
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
        })
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

// ── Auth session ────────────────────────────────────────────────────────

/// `GET /auth/session` — return session metadata (never tokens).
///
///
pub async fn auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let session_id = match extract_cookie(&headers, session::SESSION_COOKIE) {
        Some(s) => s,
        None => return Err((StatusCode::UNAUTHORIZED, "no session".into())),
    };

    let sess = state
        .store
        .get(&session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // D2 — session→application binding : the session must
    // belong to the app instance resolved from this request. Mismatch →
    // 401 (the app frontend treats it as signed-out and shows the landing
    // page). The x-sentin8-app-id header is injected by TLS per hostname.
    if let Some(ref s) = sess {
        let req_app = headers
            .get("x-sentin8-app-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty());
        if !s.matches_application(req_app) {
            tracing::warn!(
                session_app = ?s.application_id,
                request_app = ?req_app,
                "bff: /auth/session REJECTED session — application binding mismatch"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "session not valid for this application".into(),
            ));
        }
    }

    match sess {
        Some(s) => {
            let scopes: Vec<String> = if s.scope.is_empty() {
                vec![]
            } else {
                s.scope.split_whitespace().map(|s| s.to_string()).collect()
            };
            //fetch the user's groups + profile so the app
            // frontend can check sentin8:app:{instance_id} membership.
            // OWNER API path (DBX — the BFF holds NO grants on auth's
            // tables): Auth's `GET /oauth/userinfo` resolves roles/groups/
            // profile LIVE from the verified bearer (the session's own user
            // access token). A failed call degrades to empty enrichment,
            // never a 500 — the session metadata itself is already valid.
            let key = session::derive_key(&state.config.encryption_key);
            let (email, first_name, last_name, groups) = match s
                .access_token(&key)
                .ok()
                .filter(|t| !t.is_empty())
            {
                Some(token) => match auth_userinfo(&state, &token).await {
                    Ok(info) => (
                        info.get("email")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        info.get("given_name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        info.get("family_name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        info.get("groups")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|g| g.as_str().map(|s| s.to_string()))
                                    .collect::<Vec<String>>()
                            })
                            .unwrap_or_default(),
                    ),
                    Err(e) => {
                        tracing::warn!(error = %e, "bff: /auth/session userinfo unavailable — degrading to bare session metadata");
                        (None, None, None, vec![])
                    }
                },
                None => {
                    tracing::warn!("bff: /auth/session has no access token — degrading to bare session metadata");
                    (None, None, None, vec![])
                }
            };
            let display_name = match (first_name.as_deref(), last_name.as_deref()) {
                (Some(f), Some(l)) => format!("{f} {l}"),
                (Some(f), None) => f.to_string(),
                (None, Some(l)) => l.to_string(),
                (None, None) => email.clone().unwrap_or_default(),
            };
            // Session response for Dash's AuthProvider / NavShell.
            // All JSON keys are snake_case.
            Ok(Json(serde_json::json!({
                "user": {
                    "id": s.user_id,
                    "org_id": s.org_id,
                    "env_id": s.env_id,
                    "subject_type": s.subject_type,
                    "groups": groups,
                    "email": email,
                    "display_name": display_name,
                    "displayName": display_name,
                },
                "org_id": s.org_id,
                "env_id": s.env_id,
                "scopes": scopes,
                "csrf_token": s.csrf_token,
                "expires_at": s.token_expiry,
            })))
        }
        None => Err((StatusCode::UNAUTHORIZED, "session not found".into())),
    }
}

// ── Generic service action proxy ────────────────────────────────────────

/// `POST /bff/action/{action}` — proxy a registered service action.
///
/// This is a generic authenticated proxy. The frontend sends the action name
/// as a path parameter and the request body as JSON. BFF:
/// 1. Validates the session
/// 2. Looks up the action in `sentin8_service_actions` (registered by
///
/// `sentin8-cli vertical enroll`) to get the target URL, method, and scope
/// 3. Forwards the request body + access token to the registered service
/// 4. Returns the response
///
/// No vertical-specific knowledge is hardcoded — the action name, URL, method,
/// and scope all come from the registry at runtime.
pub async fn service_action(
    State(state): State<AppState>,
    axum::extract::Path(action): axum::extract::Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    // Validate session — extract the session cookie.
    let session_id = match extract_cookie(&headers, session::SESSION_COOKIE) {
        Some(s) => s,
        None => return Err((StatusCode::UNAUTHORIZED, "no session".into())),
    };
    let sess = state
        .store
        .get(&session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "session not found".into()))?;

    // Decrypt the access token from the session.
    let key = session::derive_key(&state.config.encryption_key);
    let access_token = sess.access_token(&key).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("token decrypt: {e}"),
        )
    })?;

    // Look up the service action

    // ── Step 5 — Shield decides (design ). The
    // registered action's scope is the Shield action id; the enforced
    // scope-mirror set over the caller's LIVE effective scope set
    // is the only gate. The session's decrypted Bearer rides the headers so
    // the shared deps resolve live identity.
    {
        let mut hdrs = axum::http::HeaderMap::new();
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {access_token}")) {
            hdrs.insert(axum::http::header::AUTHORIZATION, v);
        }
        let env_uuid = uuid::Uuid::parse_str(&sess.env_id)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "session env is not a uuid".into()))?;
        sentin8::shield::runtime::evaluate_full(
            &state.policy,
            &sess.user_id,
            env_uuid,
            "access",
            &sess.scope,
            &hdrs,
            &action,
        )
        .await?;
    }

    // Look up the service action from the registry (no hardcoded URLs).
    let action_row = sqlx::query(
        r#"SELECT platform_domain_key, endpoint, method, scope
             FROM service_actions
            WHERE action = $1"#,
    )
    .bind(&action)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("service action query: {e}"),
        )
    })?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("no service action registered for '{action}'"),
    ))?;

    let platform_domain_key: String = action_row.get("platform_domain_key");
    let endpoint: String = action_row.get("endpoint");
    let method: String = action_row.get("method");

    // Build the service URL from the platform domain key.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let service_url = format!(
        "https://{}{}",
        cfg.platform_domain(&platform_domain_key),
        endpoint
    );

    // Forward the request to the registered service.
    let client = reqwest::Client::new();
    let req_builder = match method.as_str() {
        "POST" => client.post(&service_url),
        "PUT" => client.put(&service_url),
        "PATCH" => client.patch(&service_url),
        "DELETE" => client.delete(&service_url),
        _ => client.get(&service_url),
    };

    // Parse the body as JSON if non-empty, otherwise forward as-is.
    let resp = if body.is_empty() {
        req_builder.bearer_auth(&access_token).send().await
    } else {
        let json_body: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?;
        req_builder
            .bearer_auth(&access_token)
            .json(&json_body)
            .send()
            .await
    };

    let resp = resp.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("service action '{action}': {e}"),
        )
    })?;

    let status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("response read: {e}")))?;

    tracing::info!(action = %action, service_url = %service_url, status = %status, "bff: service action proxied");

    // Return the upstream response — status + body as-is.
    Ok((
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        resp_body,
    )
        .into_response())
}

/// URL-encode a string for use in query parameters.
fn urlencoding(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

// ── Auth sign-out ────────────────────────────────────────────────────────

/// `POST /auth/sign-out` — session termination + token revocation.
///
///
pub async fn auth_sign_out(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_cookie(&headers, session::SESSION_COOKIE) {
        // Get the session to find the refresh token.
        if let Ok(Some(sess)) = state.store.get(&session_id).await {
            // Revoke the refresh token at Auth.
            let key = session::derive_key(&state.config.encryption_key);
            if let Ok(rt) = sess.refresh_token(&key) {
                if !rt.is_empty() {
                    let _ = reqwest::Client::new()
                        .post(format!(
                            "{}/oauth/revoke",
                            state.config.sentin8_auth_base_url
                        ))
                        .form(&[("token", &rt)])
                        .send()
                        .await;
                }
            }
        }
        // Destroy the session in Valkey.
        let _ = state.store.destroy(&session_id).await;
    }
    // Clear BOTH session cookies so apps route sign-out through BFF only
    // (they never call Auth directly):
    // - BFF's own session cookie
    // - Auth's `__session` cookie — Auth sets it on the registrable
    // domain; if left in place, Auth's /oauth/authorize silently
    // re-authenticates the user from the stale cookie.
    // F-C: the BFF session cookie Domain is the app instance's domain
    // (strip the leading `bff.` label) — must match the callback's
    // Set-Cookie derivation exactly, or the browser keeps the session
    // cookie alive. Auth's `__session` uses the registrable domain
    // (one label deeper). Exact-host fallback (empty Domain) for
    // non-app-pattern hostnames.
    let host = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    // BFF session cookie: app-instance domain (may be empty → exact-host).
    let session_domain = session::app_cookie_domain_for_host(host).unwrap_or_default();
    // Auth __session cookie domain: registrable domain (strip one label).
    let domain = session::cookie_domain_for_host(host, &state.config.sentin8_domain);
    let mut resp = (
        StatusCode::OK,
        Json(serde_json::json!({"status": "signed out"})),
    )
        .into_response();
    let hdrs = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&Session::clear_cookie(&session_domain)) {
        hdrs.append("set-cookie", v);
    }
    if let Ok(v) = HeaderValue::from_str(&Session::clear_sentin8_auth_cookie(&domain)) {
        hdrs.append("set-cookie", v);
    }
    resp
}

// ── Health ──────────────────────────────────────────────────────────────

pub async fn health() -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"status": "ok", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()}),
    )
}

/// `GET /bff/readiness` — readiness check.
pub async fn readiness(State(state): State<AppState>) -> Json<serde_json::Value> {
    let valkey_ok = state.store.ping().await;
    Json(serde_json::json!({
        "status": if valkey_ok { "ready" } else { "not_ready" },
        "valkey": valkey_ok,
    }))
}

/// `POST /bff/auth/refresh` — force token refresh.
pub async fn auth_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let cookie = extract_cookie(&headers, session::SESSION_COOKIE)
        .or_else(|| extract_cookie(&headers, "sentin8_session"))
        .ok_or((StatusCode::UNAUTHORIZED, "no session cookie".into()))?;

    let session = state
        .store
        .get(&cookie)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "session not found".into()))?;

    let enc_key = session::derive_key(&state.config.encryption_key);
    let refresh_token = session
        .refresh_token(&enc_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if refresh_token.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "no refresh token in session".into(),
        ));
    }

    // — refresh via fapiclient with the process DPoP
    // key. Under `fapi_2` (`require_dpop = true`), refresh_token grants on
    // non-exempt (DCR-registered app-instance) clients require a proof — a
    // plain refresh POST gets 401. Uses the platform auth issuer (the
    // session does not record the issuer; refresh tokens are issued by the
    // same Auth the callback used, and the platform issuer verifies its own
    // tokens' signatures for grant replay — for tenant issuers the browser
    // re-authenticates on expiry instead).
    let fapi_opts = sentin8::auth::fapi::ClientOptions::builder()
        .issuer_url(state.config.sentin8_auth_base_url.clone())
        .client_id(state.config.oauth_client_id.clone())
        .redirect_uri(state.config.oauth_redirect_uri.clone())
        .dpop_key(dpop_key_pem(), "ES256")
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("fapi client build failed: {e}"),
            )
        })?;
    let fapi_client = sentin8::auth::fapi::Client::new(fapi_opts).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("fapi client build failed: {e}"),
        )
    })?;
    let token_resp = fapi_client
        .refresh_token(&refresh_token)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Auth refresh failed: {e}")))?;

    let new_access_token = &token_resp.access_token;
    let new_refresh_token = token_resp.refresh_token.as_deref();

    // Update the session with new tokens.
    let mut updated_session = session;
    updated_session
        .set_access_token(new_access_token, &enc_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(rt) = new_refresh_token {
        updated_session
            .set_refresh_token(rt, &enc_key)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    // Update the scope in the session so BFF's scope enforcement uses the
    // refreshed scopes (which include new group memberships like org-admin).
    if let Some(ref scope) = token_resp.scope {
        updated_session.scope = scope.clone();
    }
    // Update token expiry.
    updated_session.token_expiry = chrono::Utc::now().timestamp() + token_resp.expires_in as i64;

    state
        .store
        .put(&cookie, &updated_session)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "refreshed",
        "expires_in": token_resp.expires_in,
    }))
    .into_response())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// `GET /bff/metrics` — Prometheus metrics.
///
/// Returns basic metrics in Prometheus text format: session count,
/// proxy latency histogram (P0: simple counter), token refresh rate.
pub async fn metrics(State(state): State<AppState>) -> Result<String, (StatusCode, String)> {
    // P0: return static metrics — a full implementation would use prometheus crate.
    let session_count = count_sessions(&state.store).await;
    let metrics_text = format!(
        "# HELP sentin8_bff_sessions_active Number of active BFF sessions\n\
         # TYPE sentin8_bff_sessions_active gauge\n\
         sentin8_bff_sessions_active {session_count}\n\
         # HELP sentin8_bff_token_refreshes_total Total token refreshes\n\
         # TYPE sentin8_bff_token_refreshes_total counter\n\
         sentin8_bff_token_refreshes_total 0\n\
         # HELP sentin8_bff_proxy_requests_total Total proxy requests\n\
         # TYPE sentin8_bff_proxy_requests_total counter\n\
         sentin8_bff_proxy_requests_total 0\n"
    );
    Ok(metrics_text)
}

/// Count active sessions in Valkey (P0: scan for bff:session:* keys).
async fn count_sessions(_store: &SessionStore) -> u64 {
    // P0: return 0 — a full implementation would use SCAN.
    0
}

/// `POST /bff/audit` — emit an audit event.
///
/// Records audit events for session create/destroy, token refresh, proxy mutations.
#[derive(Debug, Deserialize)]
pub struct AuditEventRequest {
    pub action: String,
    #[serde(default)]
    pub actor_user_id: Option<String>,
    #[serde(default)]
    pub target_resource_type: Option<String>,
    #[serde(default)]
    pub target_resource_id: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

pub async fn audit_event(
    State(_state): State<AppState>,
    Json(req): Json<AuditEventRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // P0: log the audit event — a full implementation would write to a DB table.
    tracing::info!(
        action = %req.action,
        actor = ?req.actor_user_id,
        target = ?req.target_resource_type,
        "audit event"
    );
    Ok(Json(
        serde_json::json!({"status": "logged", "action": req.action}),
    ))
}

/// Extract a cookie value from the Cookie header.
pub(crate) fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&format!("{name}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// Derive the app frontend URL from the BFF hostname.
/// e.g. "sentin8-bff.sentin8-dash.ops.sys.sentin8.local" → "https://sentin8-dash.ops.sys.sentin8.local"
/// For platform BFF ("sentin8-bff.ops.sys.sentin8.local"), returns empty (no app context).
/// For custom domain BFF ("bff.www.ibank.local") → "https://www.ibank.local"
fn derive_app_frontend_url(hostname: &str, sentin8_domain: &str) -> String {
    // Strip the BFF prefix to derive the app frontend URL.
    //
    // Handles three hostname patterns:
    // 1. Platform BFF: bff.dash.{sentin8_domain} → https://dash.{sentin8_domain}
    // (e.g. sentin8-bff.sentin8-dash.ops.sys.sentin8.local → https://sentin8-dash.ops.sys.sentin8.local)
    // 2. App BFF: bff.{env}.{org}.{app}.app.{sentin8_domain}
    // → https://{env}.{org}.{app}.app.{sentin8_domain}
    // (e.g. bff.prod.ibank.ebank.sentin8-app.ops.sys.sentin8.local
    // → https://prod.ibank.ebank.sentin8-app.ops.sys.sentin8.local)
    // 3. Custom domain BFF: bff.{custom_domain} → https://{custom_domain}
    // (e.g. bff.www.ibank.local → https://www.ibank.local)
    //
    // The derived URL is used as the OAuth `state` so the BFF callback
    // redirects the browser back to the app frontend after token exchange.
    // Returns an empty string for unrecognized patterns (the caller falls
    // back to the original query `state`).
    for prefix in ["bff."] {
        if let Some(rest) = hostname.strip_prefix(prefix) {
            if rest.is_empty() || rest == "bff" {
                continue;
            }
            // Pattern 1 & 2: hostname ends with.{sentin8_domain}
            if let Some(app_slug) = rest.strip_suffix(format!(".{sentin8_domain}").as_str()) {
                if !app_slug.is_empty() && app_slug != "bff" {
                    return format!("https://{app_slug}.{sentin8_domain}");
                }
            }
            // Pattern 3: custom domain — strip the bff. prefix and use the rest.
            // This handles bff.www.ibank.local → https://www.ibank.local
            // Only applies when the hostname doesn't end with.{sentin8_domain}
            // (i.e. it's not a sentin8.local subdomain).
            if !rest.ends_with(sentin8_domain) {
                return format!("https://{rest}");
            }
        }
    }
    String::new()
}

/// Resolve the custom domain for an app instance from the database.
/// If the app instance has a custom_domain (e.g. "www.ibank.local"), return
/// "https://www.ibank.local". Otherwise return empty string (caller falls
/// back to the derived app_frontend_url from the hostname).
async fn resolve_app_custom_domain(
    state: &AppState,
    org_id: &str,
    env_id: &str,
    hostname: &str,
) -> String {
    // Only look up custom domains for app BFF hostnames (bff.*.app.*).
    if !hostname.contains(".app.") {
        return String::new();
    }
    if org_id.is_empty() || env_id.is_empty() {
        return String::new();
    }
    // Call Sys HTTP endpoint for app custom domain resolution.
    // BFF-only surface — attach the delegator M2M token (sys design ;
    // the unauthenticated call was 401ing after ).
    let sentin8_sys_url = format!(
        "{}/v1/env/{}/app-custom-domain",
        state.config.sentin8_sys_base_url.trim_end_matches('/'),
        env_id
    );
    {
        let client = match crate::proxy::get_sentin8_bff_m2m_token(&state.config).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "bff: failed to get M2M token for app-custom-domain");
                return String::new();
            }
        };
        match client.get(&sentin8_sys_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let domain = data["custom_domain"].as_str().unwrap_or("");
                    if !domain.is_empty() {
                        tracing::info!(domain = %domain, "bff: resolved app custom domain via Sys");
                        return format!("https://{domain}");
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "bff: Sys app-custom-domain request failed")
            }
            Err(e) => tracing::warn!(error = %e, "bff: Sys app-custom-domain request error"),
        }
    }
    String::new()
}

// PKCE helpers are imported from the Auth SDK (sentin8::auth::client).
// No local duplication — use sentin8::auth::client::generate_pkce_verifier
// and sentin8::auth::client::pkce_s256_challenge.

const SYSTEM_ORG_ID: &str = "00000000-0000-0000-0000-000000000001";
const SYSTEM_ENV_ID: &str = "00000000-0000-0000-0000-000000000002";

/// Decode JWT claims (without signature verification — the resource server
/// verifies via JWKS). Extracts sub, env_id from the access token.
/// Uses the Auth SDK's `decode_claims_unverified` helper.
/// org_id is resolved from env_id via sentin8_sys_environments (no longer in JWT).
async fn decode_token_claims(token: &str, pool: &sqlx::PgPool) -> Option<(String, String, String)> {
    let claims = sentin8::auth::client::decode_claims_unverified(token)?;
    let sub = if claims.sub.is_empty() {
        "unknown".to_string()
    } else {
        claims.sub
    };
    let env_id = claims.env_id.unwrap_or_else(|| SYSTEM_ENV_ID.to_string());
    // Resolve org_id from env_id via sentin8_sys_environments.
    // Context-first read — the autocommit
    // variant sees zero rows under FORCE RLS; falls back to the platform
    // org only when the env row genuinely does not exist.
    let org_id = crate::tenant::resolve_org_id_from_env_id(pool, &env_id)
        .await
        .map(|id: uuid::Uuid| id.to_string())
        .unwrap_or_else(|| SYSTEM_ORG_ID.to_string());
    Some((sub, org_id, env_id))
}
