// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Valkey-backed encrypted session store.
//!
//! Sessions are stored in Valkey keyed by `bff:session:{sessionId}` with a
//! TTL matching the session idle timeout. Tokens are encrypted at rest with
//! AES-256-GCM.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use uuid::Uuid;

/// Session cookie name.
///
/// Not using the `__Host-` prefix because the cookie must be shared between
/// the app's two hosts: the frontend `{app}.{env}.{org}.{tld}` and the API
/// host `bff.{app}.{env}.{org}.{tld}`. The `__Host-` prefix forbids the
/// `Domain` attribute, so we use a plain name with an explicit Domain
/// scoped to the app instance's domain (see `app_cookie_domain_for_host`,
/// design ).
pub const SESSION_COOKIE: &str = "bff-session";

/// Auth's session cookie name. BFF clears it on sign-out so apps can
/// route sign-out through BFF only - they never call Auth directly.
pub const SENTIN8_AUTH_SESSION_COOKIE: &str = "__session";

/// Derive the cookie domain from a hostname (mirrors
/// `auth_server::sessions::cookie_domain_for_host`). Strips the leading
/// label so a tenant host like `auth.ibank.local` → `ibank.local`.
/// Used for Auth's `__session` cookie domain on sign-out. Falls back to
/// `fallback` when the host is empty or has < 3 labels.
pub fn cookie_domain_for_host(host: &str, fallback: &str) -> String {
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        return fallback.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 3 {
        return fallback.to_string();
    }
    labels[1..].join(".")
}

/// Derive the BFF session cookie domain from the request hostname -
/// scoped to the **app instance's domain**, never the platform root
/// .
///
/// Strips exactly the leading `bff.` label (if present) so the cookie is
/// visible on the app's frontend host and its `bff.` API host and NOTHING
/// else:
///
/// ```text
/// bff.bank8-eteller.prod.ibank38385734.local.sentin8.dev
/// → .bank8-eteller.prod.ibank38385734.local.sentin8.dev
/// bff.dash.ops.sys.local.sentin8.dev
/// → .dash.ops.sys.local.sentin8.dev
/// ```
/// A platform-root fallback (`Domain=.{sentin8_domain}`) is prohibited:
/// it makes every BFF in the platform share one cookie jar, which is
/// exactly the cross-app replay defect. When the hostname has fewer than
/// 4 labels (no app-instance pattern), fall back to the exact host -
/// the caller should then use `cookie_exact_host` (no Domain attribute).
pub fn app_cookie_domain_for_host(host: &str) -> Option<String> {
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    let stripped = host.strip_prefix("bff.").unwrap_or(host);
    // The app-instance pattern needs at least 4 labels:
    // {app}.{env}.{org-slug}.{tld...}. Platform Dash is
    // dash.ops.sys.local.sentin8.dev - also 4+.
    let labels: Vec<&str> = stripped.split('.').collect();
    if labels.len() < 4 {
        return None;
    }
    Some(stripped.to_string())
}

/// True when the cookie must omit the Domain attribute (bound to the
/// exact host). Used when the hostname does not match the app-instance
/// pattern (fewer than 4 labels).
pub fn use_exact_host_cookie(host: &str) -> bool {
    app_cookie_domain_for_host(host).is_none()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub org_id: String,
    pub env_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    pub access_token_enc: Vec<u8>,
    pub refresh_token_enc: Vec<u8>,
    pub token_expiry: i64,
    pub scope: String,
    pub roles: String,
    pub subject_type: String,
    pub csrf_token: String,
    pub created_at: i64,
    pub last_accessed_at: i64,
}

impl Session {
    pub fn new(user_id: String, org_id: String, env_id: String) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            user_id,
            org_id,
            env_id,
            application_id: None,
            access_token_enc: vec![],
            refresh_token_enc: vec![],
            token_expiry: 0,
            scope: String::new(),
            roles: String::new(),
            subject_type: String::new(),
            csrf_token: Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().timestamp(),
            last_accessed_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Set the encrypted access token.
    pub fn set_access_token(&mut self, token: &str, key: &[u8; 32]) -> Result<(), String> {
        self.access_token_enc = encrypt(key, token.as_bytes())?;
        Ok(())
    }

    /// Set the encrypted refresh token.
    pub fn set_refresh_token(&mut self, token: &str, key: &[u8; 32]) -> Result<(), String> {
        self.refresh_token_enc = encrypt(key, token.as_bytes())?;
        Ok(())
    }

    /// Decrypt and return the access token.
    pub fn access_token(&self, key: &[u8; 32]) -> Result<String, String> {
        if self.access_token_enc.is_empty() {
            return Ok(String::new());
        }
        let bytes = decrypt(key, &self.access_token_enc)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    /// Decrypt and return the access token trying every ring key (rotation).
    pub fn access_token_with_ring(
        &self,
        _key: &[u8; 32],
        ring_keys: &[&[u8; 32]],
    ) -> Result<String, String> {
        if self.access_token_enc.is_empty() {
            return Ok(String::new());
        }
        let bytes = decrypt_with_keys(&self.access_token_enc, ring_keys)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    /// Decrypt and return the refresh token.
    pub fn refresh_token(&self, key: &[u8; 32]) -> Result<String, String> {
        if self.refresh_token_enc.is_empty() {
            return Ok(String::new());
        }
        let bytes = decrypt(key, &self.refresh_token_enc)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    /// Decrypt and return the refresh token trying every ring key (rotation).
    pub fn refresh_token_with_ring(
        &self,
        _key: &[u8; 32],
        ring_keys: &[&[u8; 32]],
    ) -> Result<String, String> {
        if self.refresh_token_enc.is_empty() {
            return Ok(String::new());
        }
        let bytes = decrypt_with_keys(&self.refresh_token_enc, ring_keys)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    /// Build the Set-Cookie header value.
    ///
    /// `domain` is the **app instance's domain** : the cookie
    /// is visible only on `{app}.{env}.{org}.{tld}` and its `bff.` host.
    /// When `domain` is empty the Domain attribute is omitted - the cookie
    /// is then bound to the exact response host (fallback for hostnames
    /// that don't match the app-instance pattern).
    pub fn cookie(&self, domain: &str) -> String {
        let domain_attr = if domain.is_empty() {
            String::new()
        } else {
            format!("; Domain=.{domain}")
        };
        format!(
            "{}={}; Path=/{}; HttpOnly; Secure; SameSite=None; Max-Age={}",
            SESSION_COOKIE, self.session_id, domain_attr, 86400,
        )
    }

    /// Build a cookie header that clears the session cookie.
    /// `domain` semantics match [`Session::cookie`] - empty means no
    /// Domain attribute (exact-host cookie).
    pub fn clear_cookie(domain: &str) -> String {
        let domain_attr = if domain.is_empty() {
            String::new()
        } else {
            format!("; Domain=.{domain}")
        };
        format!(
            "{}=; Path=/{}; HttpOnly; Secure; SameSite=None; Max-Age=0",
            SESSION_COOKIE, domain_attr
        )
    }

    /// Session→application binding check.
    ///
    /// A session is usable on a BFF surface only when it was created for
    /// the same app instance. `session_application_id` is the instance id
    /// stored in the session (`None` = platform bootstrap/legacy);
    /// `request_application_id` is the instance resolved from the request
    /// hostname (`None` = no app instance matched, e.g. the platform Dash
    /// BFF).
    ///
    /// Rules:
    /// - session with an application_id must match the request's instance
    /// - a session without application_id is only usable where no app
    ///   instance matches (the platform BFF) - never on an app BFF
    pub fn matches_application(&self, request_application_id: Option<&str>) -> bool {
        match (&self.application_id, request_application_id) {
            (Some(sess_app), Some(req_app)) => sess_app == req_app,
            // No binding recorded and the request doesn't belong to any app
            // instance → platform BFF hosting legacy sessions: allow.
            (None, None) => true,
            // A bound session reaching another app's BFF → reject.
            (Some(_), None) => false,
            // An unbound session at an app BFF → reject (fail-closed).
            (None, Some(_)) => false,
        }
    }

    /// Build a cookie header that clears Auth's `__session` cookie (set by
    /// Auth on the registrable domain). BFF emits this on sign-out so apps
    /// can route sign-out through BFF only.
    pub fn clear_sentin8_auth_cookie(domain: &str) -> String {
        format!(
            "{}=; Path=/; Domain=.{domain}; HttpOnly; Secure; SameSite=None; Max-Age=0",
            SENTIN8_AUTH_SESSION_COOKIE,
        )
    }

    /// True if the access token is expired.
    pub fn token_is_expired(&self) -> bool {
        self.token_expiry > 0 && chrono::Utc::now().timestamp() >= self.token_expiry
    }
}

/// AES-256-GCM encrypt. The nonce is prepended to the ciphertext.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let mut result = nonce_bytes.to_vec();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| e.to_string())?;
    result.extend(ciphertext);
    Ok(result)
}

/// AES-256-GCM decrypt. The nonce is read from the first 12 bytes.
fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("ciphertext too short".into());
    }
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce: [u8; 12] = data[..12]
        .try_into()
        .map_err(|_| "nonce length".to_string())?;
    cipher
        .decrypt(&Nonce::from(nonce), &data[12..])
        .map_err(|e| e.to_string())
}

/// Decrypt with the KeyRing (bff DESIGN §6.2): session blobs carry no key
/// ID, so the ring's current key is tried first and retained keys follow.
/// `keys` = ring.all_keys() ordered current-first.
pub fn decrypt_with_keys(data: &[u8], keys: &[&[u8; 32]]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no keys provided");
    for k in keys {
        match decrypt(k, data) {
            Ok(b) => return Ok(b),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Derive a 32-byte encryption key from a passphrase string.
pub fn derive_key(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

#[derive(Clone)]
pub struct SessionStore {
    valkey: Arc<glide::GlideClient>,
    ttl_seconds: u64,
}

impl SessionStore {
    pub async fn new(valkey_url: &str, ttl_seconds: u64) -> Result<Self, glide::GlideError> {
        // Certificate identity (group DESIGN.md §3.1): the session store
        // presents the bff workload's pair. The pair is ensured FIRST -
        // a fresh platform (or one enrolled before the Valkey-plane
        // identities existed) has no persisted pair yet. The mint rides
        // the bootstrap-enrollment channel, which races Acme's own boot:
        // retry with bounded backoff (10s interval, 10-minute deadline)
        // so a BFF that spawns before Acme listens waits for it instead
        // of crash-looping (the same mint-or-load loop the identity mint
        // pattern specifies).
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &issuer,
                "sentin8:bff",
                &ca_cert_path,
            )
            .await
            {
                Ok(_) => break,
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(glide::GlideError::Connection(format!(
                            "session store workload identity: {e}"
                        )));
                    }
                    tracing::warn!(
                        error = %e,
                        "bff: Valkey workload identity mint pending (acme boot race) - retrying in 10s"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
        let manager = sentin8::middleware::valkey_client(valkey_url, "sentin8:bff")
            .await
            .map_err(|e| {
                glide::GlideError::Connection(format!("session store client construction: {e}"))
            })?;
        Ok(Self {
            valkey: Arc::new(manager),
            ttl_seconds,
        })
    }

    pub async fn create(&self, session: &Session) -> Result<(), glide::GlideError> {
        let key = format!("bff:session:{}", session.session_id);
        let value = serde_json::to_string(session).unwrap_or_default();
        let conn = (*self.valkey).clone();
        use glide::AsyncCommands;
        let _: () = conn.set_ex(key, value, self.ttl_seconds).await?;
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<Session>, glide::GlideError> {
        let key = format!("bff:session:{session_id}");
        let conn = (*self.valkey).clone();
        use glide::AsyncCommands;
        let value: Option<String> = conn.get(key).await?;
        match value {
            Some(v) => {
                let session: Session = serde_json::from_str(&v).map_err(|e| {
                    glide::GlideError::Request(format!("session decode failed: {e}"))
                })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    pub async fn destroy(&self, session_id: &str) -> Result<(), glide::GlideError> {
        let key = format!("bff:session:{session_id}");
        let conn = (*self.valkey).clone();
        use glide::AsyncCommands;
        let _: usize = conn.del(key).await?;
        Ok(())
    }

    /// Update an existing session (replaces the value).
    pub async fn put(&self, session_id: &str, session: &Session) -> Result<(), glide::GlideError> {
        let key = format!("bff:session:{session_id}");
        let value = serde_json::to_string(session).unwrap_or_default();
        let conn = (*self.valkey).clone();
        use glide::AsyncCommands;
        let _: () = conn.set_ex(key, value, self.ttl_seconds).await?;
        Ok(())
    }

    /// List session ids via SCAN (bounded - re-wrap scan pass). SCAN keeps
    /// the shared Valkey responsive (KEYS would block under load).
    pub async fn list_session_ids(&self, limit: usize) -> Result<Vec<String>, glide::GlideError> {
        let conn = (*self.valkey).clone();
        let mut ids = Vec::new();
        let mut cursor = String::from("0");
        loop {
            let (next, keys): (String, Vec<String>) = glide::cmd("SCAN")
                .arg(&cursor)
                .arg("MATCH")
                .arg("bff:session:*")
                .arg("COUNT")
                .arg(100)
                .query_async(&conn)
                .await?;
            ids.extend(
                keys.iter()
                    .map(|k| k.trim_start_matches("bff:session:").to_string()),
            );
            cursor = next;
            if cursor == "0" || ids.len() >= limit {
                break;
            }
        }
        ids.truncate(limit);
        Ok(ids)
    }

    /// Ping Valkey to check connectivity.
    pub async fn ping(&self) -> bool {
        let conn = (*self.valkey).clone();
        use glide::AsyncCommands;
        let result: Result<String, _> = conn.get("_ping").await;
        result.is_ok()
    }

    /// Get a cloned Valkey connection for direct operations (e.g. token-exchange cache).
    ///used by the proxy to cache exchanged tokens.
    pub fn valkey_connection(&self) -> glide::GlideClient {
        (*self.valkey).clone()
    }
}
