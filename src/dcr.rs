// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! DCR (Dynamic Client Registration) for BFF .
//!
//! BFF uses DCR to auto-register OAuth clients with Auth when provisioning
//! app instances. This module implements the DCR client, registry table,
//! and lazy registration logic.

use sentin8::middleware::http_client::Sentin8HttpClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// DCR client for registering OAuth clients with Auth.
#[derive(Clone)]
pub struct DcrClient {
    sentin8_auth_base_url: String,
    http: Sentin8HttpClient,
}

impl DcrClient {
    pub fn new(sentin8_auth_base_url: impl Into<String>) -> Self {
        Self {
            sentin8_auth_base_url: sentin8_auth_base_url
                .into()
                .trim_end_matches('/')
                .to_string(),
            http: Sentin8HttpClient::new(),
        }
    }

    /// Register an OAuth client via DCR (RFC 7591) - `POST /oauth/register`.
    pub async fn register(
        &self,
        req: &DcrRegisterRequest,
    ) -> Result<DcrRegisterResponse, DcrError> {
        let resp = self
            .http
            .post(format!("{}/oauth/register", self.sentin8_auth_base_url))
            .json(req)
            .send()
            .await
            .map_err(|e| DcrError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DcrError::Http(format!("DCR failed: {body}")));
        }

        resp.json()
            .await
            .map_err(|e| DcrError::Decode(e.to_string()))
    }

    /// Delete a registered client via DCR Management (RFC 7592).
    pub async fn delete(
        &self,
        registration_access_token: &str,
        registration_uri: &str,
    ) -> Result<(), DcrError> {
        let resp = self
            .http
            .delete(registration_uri)
            .bearer_auth(registration_access_token)
            .send()
            .await
            .map_err(|e| DcrError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DcrError::Http(format!(
                "DCR delete failed: status {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Update a registered client via DCR Management (RFC 7592) -
    /// PUT to the registration_client_uri with the registration_access_token.
    pub async fn update(
        &self,
        registration_access_token: &str,
        registration_uri: &str,
        req: &DcrRegisterRequest,
    ) -> Result<DcrRegisterResponse, DcrError> {
        let resp = self
            .http
            .put(registration_uri)
            .bearer_auth(registration_access_token)
            .json(req)
            .send()
            .await
            .map_err(|e| DcrError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DcrError::Http(format!(
                "DCR update failed: status {}",
                resp.status()
            )));
        }

        resp.json::<DcrRegisterResponse>()
            .await
            .map_err(|e| DcrError::Decode(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DcrError {
    #[error("DCR HTTP error: {0}")]
    Http(String),
    #[error("DCR decode error: {0}")]
    Decode(String),
    #[error("DCR database error: {0}")]
    Database(String),
}

/// DCR registration request (RFC 7591).
#[derive(Debug, Serialize)]
pub struct DcrRegisterRequest {
    pub client_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,
    /// Space-separated scope string (RFC 7591 `scope` parameter).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
    // ── mTLS fields (RFC 8705,) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed_tls_client_auth_thumbprint: Option<String>,
}

fn default_token_endpoint_auth_method() -> String {
    "none".to_string()
}

/// DCR registration response (RFC 7591).
#[derive(Debug, Deserialize, Serialize)]
pub struct DcrRegisterResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    pub client_id_issued_at: i64,
}

/// DCR registry entry stored in PostgreSQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcrClientEntry {
    pub id: Uuid,
    pub sentin8_auth_domain: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub registration_access_token_enc: Vec<u8>,
    pub org_id: Uuid,
    pub env_id: Uuid,
    pub app_slug: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// DCR registry - stores registered clients keyed by sentin8_auth_domain.
pub struct DcrRegistry {
    pool: PgPool,
    encryption_key: [u8; 32],
}

impl DcrRegistry {
    pub fn new(pool: PgPool, encryption_key: &[u8; 32]) -> Self {
        Self {
            pool,
            encryption_key: *encryption_key,
        }
    }

    /// Look up a DCR client by sentin8_auth_domain.
    pub async fn find_by_domain(
        &self,
        sentin8_auth_domain: &str,
    ) -> Result<Option<DcrClientEntry>, DcrError> {
        let row = sqlx::query(
            r#"SELECT id, sentin8_auth_domain, client_id, client_name, redirect_uris, scopes,
                      registration_access_token_enc, org_id, env_id,
                      app_slug, created_at, updated_at
               FROM dcr_clients WHERE sentin8_auth_domain = $1"#,
        )
        .bind(sentin8_auth_domain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DcrError::Database(e.to_string()))?;

        match row {
            Some(r) => {
                use sqlx::Row;
                Ok(Some(DcrClientEntry {
                    id: r.get("id"),
                    sentin8_auth_domain: r.get("sentin8_auth_domain"),
                    client_id: r.get("client_id"),
                    client_name: r.get("client_name"),
                    redirect_uris: r.get("redirect_uris"),
                    scopes: r.get("scopes"),
                    registration_access_token_enc: r.get("registration_access_token_enc"),
                    org_id: r.get("org_id"),
                    env_id: r.get("env_id"),
                    app_slug: r.get("app_slug"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                }))
            }
            None => Ok(None),
        }
    }

    /// Insert a new DCR client entry.
    pub async fn insert(&self, entry: &DcrClientEntry) -> Result<(), DcrError> {
        sqlx::query(
            r#"INSERT INTO dcr_clients
               (id, sentin8_auth_domain, client_id, client_name, redirect_uris, scopes,
                registration_access_token_enc, org_id, env_id, app_slug)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (sentin8_auth_domain) DO UPDATE SET
                   client_id = EXCLUDED.client_id,
                   client_name = EXCLUDED.client_name,
                   redirect_uris = EXCLUDED.redirect_uris,
                   scopes = EXCLUDED.scopes,
                   registration_access_token_enc = EXCLUDED.registration_access_token_enc,
                   updated_at = now()"#,
        )
        .bind(entry.id)
        .bind(&entry.sentin8_auth_domain)
        .bind(&entry.client_id)
        .bind(&entry.client_name)
        .bind(&entry.redirect_uris)
        .bind(&entry.scopes)
        .bind(&entry.registration_access_token_enc)
        .bind(entry.org_id)
        .bind(entry.env_id)
        .bind(entry.app_slug.as_ref())
        .execute(&self.pool)
        .await
        .map_err(|e| DcrError::Database(e.to_string()))?;
        Ok(())
    }

    /// Encrypt a registration access token using AES-256-GCM.
    fn encrypt_token(&self, token: &str) -> Vec<u8> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.encryption_key));
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let mut result = nonce_bytes.to_vec();
        let ciphertext = cipher.encrypt(&nonce, token.as_bytes()).unwrap_or_default();
        result.extend(ciphertext);
        result
    }
}

/// Pre-provision Dash platform OAuth client.
/// Creates a `dash` client on `auth.{domain}` out-of-band (no DCR).
pub fn pre_provision_dash_platform_config(sentin8_domain: &str) -> (String, String) {
    let client_id = "dash".to_string();
    let sentin8_auth_domain = format!("auth.{sentin8_domain}");
    (client_id, sentin8_auth_domain)
}

/// Pre-provision org-scoped Dash OAuth client.
/// Creates `dash-{org-slug}` on `{org-slug}.auth.{domain}` out-of-band.
pub fn pre_provision_dash_org_config(org_slug: &str, sentin8_domain: &str) -> (String, String) {
    let client_id = format!("dash-{org_slug}");
    let sentin8_auth_domain = format!("{org_slug}.auth.{sentin8_domain}");
    (client_id, sentin8_auth_domain)
}

/// App app BFF hostname resolution.
/// Parse `bff.{app_domain}` → resolve the Auth domain for the app's org/env.
/// E.g. `bff.www.ibank.local` → `auth.prod.ibank.local` (derived from app_domain).
pub fn resolve_app_sentin8_auth_domain(app_domain: &str, sentin8_domain: &str) -> String {
    // app_domain is e.g. `www.ibank.local` - strip subdomain parts to find org domain.
    // P0: simple heuristic - the app_domain is `{app_slug}.{env_slug}.e.{org_slug}.o.{sentin8_domain}`.
    // The auth domain is `auth.{env_slug}.e.{org_slug}.o.{sentin8_domain}`.
    let parts: Vec<&str> = app_domain.split('.').collect();
    if parts.len() >= 5 {
        // www. prod. e. ibank. o. local.sentin8.dev
        // [0] [1] [2] [3] [4] [5..]
        let env_slug = parts[1];
        let org_slug = parts[3];
        let rest = parts[5..].join(".");
        format!("auth.{env_slug}.e.{org_slug}.o.{rest}")
    } else {
        // Fallback: platform auth domain.
        format!("auth.{sentin8_domain}")
    }
}

/// App app BFF frontend URL resolution.
/// Strip `bff.` prefix from hostname → app domain for post-callback redirect.
/// E.g. `bff.www.ibank.local` → `www.ibank.local`.
pub fn resolve_app_frontend_url(host: &str) -> String {
    host.strip_prefix("bff.").unwrap_or(host).to_string()
}
pub async fn lazy_dcr_register(
    dcr_client: &DcrClient,
    registry: &DcrRegistry,
    sentin8_auth_domain: &str,
    client_name: &str,
    redirect_uris: &[String],
    scopes: &[String],
    org_id: Uuid,
    env_id: Uuid,
    app_slug: Option<&str>,
) -> Result<DcrClientEntry, DcrError> {
    // Check if already registered.
    if let Some(existing) = registry.find_by_domain(sentin8_auth_domain).await? {
        return Ok(existing);
    }

    // Register with Auth.
    let req = DcrRegisterRequest {
        client_name: client_name.to_string(),
        redirect_uris: redirect_uris.to_vec(),
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        scope: scopes.join(" "),
        token_endpoint_auth_method: "none".to_string(),
        tls_client_auth_subject_dn: None,
        self_signed_tls_client_auth_thumbprint: None,
    };

    let resp = dcr_client.register(&req).await?;

    // Encrypt the registration access token.
    let rat_enc = match resp.registration_access_token.as_ref() {
        Some(token) => registry.encrypt_token(token),
        None => vec![],
    };

    let entry = DcrClientEntry {
        id: Uuid::new_v4(),
        sentin8_auth_domain: sentin8_auth_domain.to_string(),
        client_id: resp.client_id,
        client_name: resp.client_name,
        redirect_uris: resp.redirect_uris,
        scopes: resp.scopes,
        registration_access_token_enc: rat_enc,
        org_id,
        env_id,
        app_slug: app_slug.map(|s| s.to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    registry.insert(&entry).await?;
    Ok(entry)
}
