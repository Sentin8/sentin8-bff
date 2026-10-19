// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Encryption key rotation -
//!
//! Supports 24h key rotation with old keys retained for decryption.
//! New encryptions use the current (primary) key; decryptions try
//! the key ID embedded in the ciphertext, falling back to trying
//! all retained keys.
//!
//! Key format: encrypted blob = `v1:{key_id}:{ciphertext_base64}`
//! where `key_id` is a date-based identifier (e.g. `20260101`).

use chrono::{Datelike, Utc};
use sha2::{Digest, Sha256};

/// A key entry with its ID and derived 32-byte key.
#[derive(Clone)]
pub struct KeyEntry {
    pub id: String,
    pub key: [u8; 32],
}

/// Key ring holding the current key + retained old keys.
#[derive(Clone)]
pub struct KeyRing {
    /// The current (primary) key - used for all new encryptions.
    pub current: KeyEntry,
    /// Old keys retained for decryption (most recent first).
    pub retained: Vec<KeyEntry>,
}

impl KeyRing {
    /// Build a key ring from a list of passphrases. The last one is the
    /// current key; the rest are retained (oldest first → retained in
    /// reverse order so most-recent-old is first).
    pub fn from_passphrases(passphrases: &[String]) -> Self {
        let mut keys: Vec<KeyEntry> = passphrases
            .iter()
            .map(|p| KeyEntry {
                id: derive_key_id(p),
                key: derive_key(p),
            })
            .collect();
        if keys.is_empty() {
            return Self {
                current: KeyEntry {
                    id: "default".into(),
                    key: derive_key("change-me-32-bytes-of-random-key-material"),
                },
                retained: vec![],
            };
        }
        let current = keys.pop().unwrap();
        // Retained keys in reverse order (most recent first).
        keys.reverse();
        Self {
            current,
            retained: keys,
        }
    }

    /// Build a key ring from a single passphrase (no rotation).
    pub fn single(passphrase: &str) -> Self {
        Self {
            current: KeyEntry {
                id: derive_key_id(passphrase),
                key: derive_key(passphrase),
            },
            retained: vec![],
        }
    }

    /// Get the current key ID.
    pub fn current_id(&self) -> &str {
        &self.current.id
    }

    /// Find a key by ID - checks current first, then retained.
    pub fn find_key(&self, id: &str) -> Option<&[u8; 32]> {
        if self.current.id == id {
            return Some(&self.current.key);
        }
        self.retained.iter().find(|k| k.id == id).map(|k| &k.key)
    }

    /// Get the current key for encryption.
    pub fn current_key(&self) -> &[u8; 32] {
        &self.current.key
    }

    /// Try to decrypt by trying all keys (current + retained) when the
    /// key ID is unknown or missing.
    pub fn all_keys(&self) -> Vec<&[u8; 32]> {
        let mut keys = vec![&self.current.key];
        for k in &self.retained {
            keys.push(&k.key);
        }
        keys
    }
}

/// Derive a 32-byte key from a passphrase (same as session::derive_key).
fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Derive a key ID from a passphrase (first 8 hex chars of SHA-256).
fn derive_key_id(passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let hash = hasher.finalize();
    hex_encode(&hash[..4])
}

/// Generate the current date-based key ID (YYYYMMDD format).
pub fn date_key_id(now: chrono::DateTime<Utc>) -> String {
    format!("{:04}{:02}{:02}", now.year(), now.month(), now.day())
}

/// Encrypt data with the key ring's current key, embedding the key ID.
/// Format: `v1:{key_id}:{ciphertext_hex}`
pub fn encrypt_with_keyring(ring: &KeyRing, plaintext: &[u8]) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*ring.current_key()));
    let nonce_bytes = [0u8; 12]; // Static nonce for simplicity (P0)
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "v1:{}:{}",
        ring.current_id(),
        hex_encode(&ciphertext)
    ))
}

/// Decrypt data encrypted with `encrypt_with_keyring`. Tries the embedded
/// key ID first, then falls back to all retained keys.
pub fn decrypt_with_keyring(ring: &KeyRing, blob: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    let parts: Vec<&str> = blob.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err("invalid encrypted blob format".into());
    }
    let key_id = parts[1];
    let ciphertext = hex_decode(parts[2])?;
    let nonce = Nonce::from([0u8; 12]);

    // Try the embedded key ID first.
    if let Some(key) = ring.find_key(key_id) {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        return cipher
            .decrypt(&nonce, ciphertext.as_slice())
            .map_err(|e| e.to_string());
    }

    // Fall back to trying all keys.
    for key in ring.all_keys() {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        if let Ok(plaintext) = cipher.decrypt(&nonce, ciphertext.as_slice()) {
            return Ok(plaintext);
        }
    }

    Err("decryption failed - no key matches".into())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("invalid hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Build the operational ring from the config: retained (older)
/// passphrases first, the current one last - `KeyRing::from_passphrases`
/// treats the last entry as current.
pub fn ring_from_config(current: &str, retained: &[String]) -> KeyRing {
    let mut passphrases: Vec<String> = retained.to_vec();
    passphrases.push(current.to_string());
    KeyRing::from_passphrases(&passphrases)
}

/// Spawn the session-token re-wrap task (bff DESIGN §6.2): every
/// `REWRAP_INTERVAL_SECS`, scan session blobs written under a retained
/// (old) key and re-encrypt them with the current key, `REWRAP_BATCH` ids
/// per pass. Trial-decrypt identifies the writer key; a scan failure
/// leaves sessions queued for the next pass.
pub fn spawn_session_rewrap(
    store: crate::session::SessionStore,
    current: String,
    retained: Vec<String>,
) {
    const REWRAP_INTERVAL_SECS: u64 = 600;
    const REWRAP_BATCH: usize = 100;
    tokio::spawn(async move {
        let ring = ring_from_config(&current, &retained);
        if ring.retained.is_empty() {
            return; // No rotation in effect - nothing to re-wrap.
        }
        let current_key = ring.current_key();
        let keys = ring.all_keys();
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(REWRAP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let ids = match store.list_session_ids(REWRAP_BATCH).await {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(error = %e, "bff: re-wrap scan failed - sessions stay queued");
                    continue;
                }
            };
            let mut rewrapped = 0usize;
            for id in ids {
                let Ok(Some(mut s)) = store.get(&id).await else {
                    continue;
                };
                // Fresh under the current key → skip.
                if s.access_token(current_key).is_ok() && s.refresh_token(current_key).is_ok() {
                    continue;
                }
                // Old-key blobs: decrypt across the ring, re-encrypt under
                // the current key, persist.
                let access = s.access_token_with_ring(current_key, &keys);
                let refresh = s.refresh_token_with_ring(current_key, &keys);
                if let (Ok(at), Ok(rt)) = (access, refresh) {
                    let _ = s.set_access_token(&at, current_key);
                    let _ = s.set_refresh_token(&rt, current_key);
                    if store.put(&id, &s).await.is_ok() {
                        rewrapped += 1;
                    }
                }
            }
            if rewrapped > 0 {
                tracing::debug!(rewrapped, "bff: session re-wrap pass");
            }
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ring_single() {
        let ring = KeyRing::single("my-secret-key");
        assert!(!ring.current_id().is_empty());
        assert!(ring.retained.is_empty());
    }

    #[test]
    fn key_ring_multiple_passphrases() {
        let ring = KeyRing::from_passphrases(&[
            "old-key-1".into(),
            "old-key-2".into(),
            "current-key".into(),
        ]);
        assert_eq!(ring.retained.len(), 2);
        // Current key is the last one.
        assert_ne!(ring.current_id(), "old-key-1");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ring = KeyRing::single("test-key");
        let plaintext = b"hello world";
        let encrypted = encrypt_with_keyring(&ring, plaintext).unwrap();
        assert!(encrypted.starts_with("v1:"));
        let decrypted = decrypt_with_keyring(&ring, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_old_key() {
        // Encrypt with old key ring, decrypt with new key ring that retains the old key.
        let old_ring = KeyRing::single("old-passphrase");
        let encrypted = encrypt_with_keyring(&old_ring, b"secret data").unwrap();

        // New ring retains the old key.
        let new_ring =
            KeyRing::from_passphrases(&["old-passphrase".into(), "new-passphrase".into()]);
        let decrypted = decrypt_with_keyring(&new_ring, &encrypted).unwrap();
        assert_eq!(decrypted, b"secret data");
    }

    #[test]
    fn decrypt_fails_without_key() {
        let old_ring = KeyRing::single("old-passphrase");
        let encrypted = encrypt_with_keyring(&old_ring, b"secret data").unwrap();

        // New ring does NOT retain the old key.
        let new_ring = KeyRing::single("completely-different-passphrase");
        assert!(decrypt_with_keyring(&new_ring, &encrypted).is_err());
    }

    #[test]
    fn date_key_id_format() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(date_key_id(now), "20260115");
    }

    #[test]
    fn invalid_blob_format() {
        let ring = KeyRing::single("test-key");
        assert!(decrypt_with_keyring(&ring, "invalid").is_err());
        assert!(decrypt_with_keyring(&ring, "v2:key:data").is_err());
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = vec![0x00, 0xff, 0xab, 0xcd];
        let encoded = hex_encode(&data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
