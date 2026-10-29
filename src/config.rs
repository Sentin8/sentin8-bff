// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! BFF configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
pub struct Bff8Config {
    pub port: u16,
    pub valkey_url: String,
    pub encryption_key: String,
    /// Retained OLD key passphrases (decrypt-only; most recent first).
    pub retained_encryption_keys: Vec<String>,
    pub sentin8_auth_base_url: String,
    pub session_idle_ttl: u64,
    pub session_absolute_ttl: u64,
    pub csrf_enabled: bool,
    pub sentin8_domain: String,
    /// OAuth client ID for BFF's own auth flow.
    pub oauth_client_id: String,
    /// OAuth client secret for BFF's own auth flow.
    pub oauth_client_secret: String,
    /// OAuth redirect URI (the BFF callback URL).
    pub oauth_redirect_uri: String,
    /// Database URL for legacy lookups (being phased out - use Sys HTTP endpoints).
    pub database_url: String,
    /// Sys base URL for tenant resolution HTTP calls.
    pub sentin8_sys_base_url: String,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub auth_client: AuthClient,
    // ── Delegation Gateway M2M config ──
    /// BFF's M2M client_id for the Delegation Gateway (cert-bound).
    pub m2m_client_id: String,
    /// BFF's M2M client secret (used when mTLS is not configured).
    pub m2m_client_secret: String,
    /// Path to the mTLS client certificate PEM (Delegation Gateway cert-bound).
    pub m2m_client_cert_path: Option<String>,
    /// Path to the mTLS client private key PEM.
    pub m2m_client_key_path: Option<String>,
    /// Path to the trusted CA certificate PEM.
    pub m2m_ca_cert_path: Option<String>,
}

impl Bff8Config {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let sentin8_domain = cfg.domain().to_string();
        Self {
            port: env::var("SENTIN8_BFF_PORT")
                .expect("SENTIN8_BFF_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_BFF_PORT must be a valid u16"),
            // (group DESIGN.md §3.1): explicit env override,
            // else the plane-derived URL - the historical `/2` DB number was
            // inert (GLIDE connects at DB 0; ACLs are the isolation).
            valkey_url: env::var("SENTIN8_BFF_VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(sentin8::config::service_valkey_url),
            encryption_key: env::var("SENTIN8_BFF_ENCRYPTION_KEY")
                .unwrap_or_else(|_| "change-me-32-bytes-of-random-key-material".into()),
            // Retained OLD passphrases (comma-separated) - decrypt-only
            // (bff DESIGN §6.2 KeyRing). New writes always use
            // `encryption_key`; a background re-wrap migrates old blobs.
            retained_encryption_keys: env::var("SENTIN8_BFF_RETAINED_ENCRYPTION_KEYS")
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            sentin8_auth_base_url: env::var("SENTIN8_BFF_SENTIN8_AUTH_BASE_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_url()),
            session_idle_ttl: env::var("SENTIN8_BFF_SESSION_IDLE_TTL")
                .unwrap_or("604800".into())
                .parse()
                .unwrap_or(604800),
            session_absolute_ttl: env::var("SENTIN8_BFF_SESSION_ABSOLUTE_TTL")
                .unwrap_or("2592000".into())
                .parse()
                .unwrap_or(2592000),
            csrf_enabled: env::var("SENTIN8_BFF_CSRF_ENABLED")
                .map(|v| v != "false")
                .unwrap_or(true),
            oauth_client_id: env::var("SENTIN8_BFF_OAUTH_CLIENT_ID")
                .unwrap_or_else(|_| "dash".into()),
            oauth_client_secret: String::new(),
            oauth_redirect_uri: env::var("SENTIN8_BFF_OAUTH_REDIRECT_URI")
                .unwrap_or_else(|_| format!("{}/auth/callback", cfg.sentin8_bff_url())),
            // DBX-CLI-6: BFF connects with its own NOBYPASSRLS role when the
            // per-service DSN is present (search_path = bff, sys, public - it
            // resolves env→org from sys.environments); falls back to the
            // shared DATABASE_URL for pre-DBX harnesses.
            database_url: env::var("SENTIN8_BFF_DATABASE_URL")
                .or_else(|_| env::var("DATABASE_URL"))
                .unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                }),
            sentin8_sys_base_url: env::var("SENTIN8_BFF_SYS_BASE_URL")
                .unwrap_or_else(|_| cfg.sentin8_sys_url()),
            sentin8_domain,
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_BFF_SENTIN8_AUTH_BASE_URL")
                    .unwrap_or_else(|_| cfg.sentin8_auth_url()),
                ..Default::default()
            }),
            m2m_client_id: env::var("SENTIN8_BFF_M2M_CLIENT_ID").unwrap_or_default(),
            m2m_client_secret: env::var("SENTIN8_BFF_M2M_CLIENT_SECRET").unwrap_or_default(),
            m2m_client_cert_path: env::var("SENTIN8_BFF_M2M_CLIENT_CERT").ok(),
            m2m_client_key_path: env::var("SENTIN8_BFF_M2M_CLIENT_KEY").ok(),
            m2m_ca_cert_path: env::var("SENTIN8_CA_CERT").ok(),
        }
    }
}
