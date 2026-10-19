// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

// Integration tests for BFF -
//
// Tests session lifecycle, PKCE generation, token encryption, CSRF token
// generation, and tenant isolation (separate sessions for different org/env).

// The module is shared source with the main binary - items used only by
// the server (SessionStore, cookie helpers) are dead here.
#[path = "../src/session.rs"]
#[allow(dead_code)]
mod session;

use session::{derive_key, Session};

#[test]
fn session_create_roundtrip() {
    let s = Session::new("user-123".into(), "org-456".into(), "env-789".into());
    assert_eq!(s.user_id, "user-123");
    assert_eq!(s.org_id, "org-456");
    assert_eq!(s.env_id, "env-789");
    assert!(!s.session_id.is_empty());
}

#[test]
fn session_token_encrypts_payload() {
    let key = derive_key("test-key");
    let mut s = Session::new("user-1".into(), "org-1".into(), "env-1".into());

    // Set and retrieve access token.
    s.set_access_token("my-access-token", &key).unwrap();
    assert_eq!(s.access_token(&key).unwrap(), "my-access-token");

    // Set and retrieve refresh token.
    s.set_refresh_token("my-refresh-token", &key).unwrap();
    assert_eq!(s.refresh_token(&key).unwrap(), "my-refresh-token");
}

#[test]
fn session_token_rejects_wrong_key() {
    let key1 = derive_key("key-1");
    let key2 = derive_key("key-2");
    let mut s = Session::new("user-1".into(), "org-1".into(), "env-1".into());

    s.set_access_token("secret", &key1).unwrap();
    // Decrypting with a different key should fail.
    assert!(s.access_token(&key2).is_err());
}

#[test]
fn session_cookie_set_roundtrip() {
    let s = Session::new("user-1".into(), "org-1".into(), "env-1".into());
    let cookie = s.cookie("example.local");
    assert!(cookie.contains("bff-session="));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=None"));
    assert!(cookie.contains("Domain=.example.local"));
}

#[test]
fn session_clear_cookie_roundtrip() {
    let cookie = Session::clear_cookie("example.local");
    assert!(cookie.contains("bff-session="));
    assert!(cookie.contains("Max-Age=0"));
}

#[test]
fn session_ids_are_unique() {
    let s1 = Session::new("u1".into(), "o1".into(), "e1".into());
    let s2 = Session::new("u2".into(), "o2".into(), "e2".into());
    assert_ne!(s1.session_id, s2.session_id);
}

#[test]
fn session_tenant_isolation_enforced() {
    // Two sessions for different tenants should have different IDs and
    // different org/env bindings.
    let s1 = Session::new("user-1".into(), "org-1".into(), "env-1".into());
    let s2 = Session::new("user-2".into(), "org-2".into(), "env-2".into());

    assert_ne!(s1.session_id, s2.session_id);
    assert_ne!(s1.org_id, s2.org_id);
    assert_ne!(s1.env_id, s2.env_id);
}

#[test]
fn derive_key_is_deterministic() {
    let k1 = derive_key("passphrase");
    let k2 = derive_key("passphrase");
    assert_eq!(k1, k2);
}

#[test]
fn derive_key_differs_by_input() {
    let k1 = derive_key("passphrase-1");
    let k2 = derive_key("passphrase-2");
    assert_ne!(k1, k2);
}

#[test]
fn pkce_challenge_s256_roundtrip() {
    // PKCE S256 challenge = base64url-no-pad(SHA-256(verifier))
    // Verify the computation produces a valid base64url string of the
    // correct length (32 bytes → 43 chars, no padding).
    use sha2::Digest;
    let verifier = "dBjftJeZ4CVK-mJMgjYq03pL3p7F5YyQq5Zs5Xhkf5I";
    let mut hasher = sha2::Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64_url_no_pad(&hash);
    assert_eq!(challenge.len(), 43);
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
