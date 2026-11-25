// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Native session handoff (WS1, design `docs/01-bff-native-session.md`).
//!
//! A native client has no browser cookie jar, so it cannot acquire the
//! `bff-session` cookie that every browser request carries. Rather than hand
//! the app OAuth tokens (which would break the platform's core invariant that
//! tokens never reach a client), the BFF performs the OAuth dance itself and
//! then delivers the resulting **opaque session id** to the app:
//!
//! ```text
//!   app  --POST /auth/native/start-->  BFF   (mints flow_id, stores a device challenge)
//!   app  --opens authorize_url in the system browser-->  Auth  (unchanged hosted UI)
//!   Auth --302 /auth/callback?code=-->  BFF   (existing handler, `state=native:<flow>`)
//!   BFF  --302 com.bank8.ebank:/oauth2redirect?handoff=…-->  browser → app
//!   app  --POST /auth/native/exchange {handoff, proof}-->  BFF
//!   BFF  --200 {session_token, csrf_token, expires_at}-->  app
//! ```
//!
//! Two properties matter:
//!
//! * **Nothing secret crosses the custom-scheme boundary.** The handoff code is
//!   single-use, expires in 60 s, and is useless without the device key that
//!   hashed into the challenge at `start`.
//! * **Sentin8:Auth is untouched.** Its registered `redirect_uri` stays the
//!   https callback; the custom-scheme hop is minted *after* the callback by
//!   this module, so no RFC 8252 client registration or public-client support is
//!   required.

use axum::http::HeaderMap;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Valkey key prefix for an in-flight enrollment flow.
pub const FLOW_PREFIX: &str = "bff:native_flow:";
/// Valkey key prefix for a minted, unredeemed handoff code.
pub const HANDOFF_PREFIX: &str = "bff:native_handoff:";

/// Lifetime of the whole enrollment flow (start → callback).
pub const FLOW_TTL_SECS: u64 = 300;
/// Lifetime of a minted handoff code (callback → exchange). Deliberately short:
/// the app redeems it within a second of receiving the custom-scheme intent.
pub const HANDOFF_TTL_SECS: u64 = 60;

/// What `start` records for the flow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowRecord {
    /// `base64url(sha256(SPKI))` of the device's proof-of-possession key.
    pub device_challenge: String,
    /// The app id resolved from the TLS context of the `start` call. The
    /// handoff is bound to THIS instance.
    pub app_id: String,
    /// The env id, for the same reason.
    pub env_id: String,
    /// App-declared, display-only.
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
}

/// What a minted handoff records until it is redeemed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandoffRecord {
    pub session_id: String,
    pub device_challenge: String,
    pub device_id: String,
    pub app_id: String,
    pub env_id: String,
}

/// Parse the `state` value a native flow uses.
///
/// Returns `Some(flow_id)` only for the exact `native:<uuid-ish>` shape. Any
/// other value - including a caller-supplied URL, which is what the browser
/// flow uses `state` for - returns `None`. This is the narrowing that keeps the
/// existing `state`-as-redirect-target behaviour from becoming an open redirect.
pub fn parse_native_state(state: &str) -> Option<&str> {
    let rest = state.strip_prefix("native:")?.trim();
    if rest.is_empty() || rest.len() > 128 {
        return None;
    }
    Some(rest)
}

/// Build the `state` value for a native flow.
pub fn native_state(flow_id: &str) -> String {
    format!("native:{flow_id}")
}

/// `base64url(sha256(bytes))`, no padding - the form used for the device
/// challenge and compared against the client's public key.
pub fn challenge_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time-ish comparison for the device challenge.
///
/// The values are public (a hash of a public key), so timing here is not a
/// secret-leak concern; the length check avoids the `==` early-exit purely so
/// the function reads as a deliberate comparison rather than an accident.
pub fn challenge_matches(expected: &str, presented: &str) -> bool {
    expected.len() == presented.len() && expected.as_bytes() == presented.as_bytes()
}

/// Random 32-byte handoff code, hex encoded.
pub fn mint_handoff_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Random 16-byte flow id, hex encoded.
pub fn mint_flow_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the tenant identity the TLS layer injected for THIS request.
///
/// The flow and the handoff are both bound to it, so a handoff minted on one
/// app instance cannot be redeemed on another (the D2 rule applied to
/// enrollment).
pub fn tenant_from_headers(headers: &HeaderMap) -> (String, String) {
    let app_id = headers
        .get("x-sentin8-app-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (app_id, env_id)
}

/// Verify an ES256 signature over `message` against a base64url SPKI hash.
///
/// `spki_der` is the SEC1-uncompressed public key the client presents at
/// `exchange` (its own key material, public by definition). We hash it and
/// compare against the challenge recorded at `start`; then we verify
/// `signature` over `message`.
///
/// Returns `Ok(())` only when BOTH hold. A failure deliberately does not say
/// which check failed - the response is a flat 401 so an attacker learns
/// nothing about which half they got wrong.
pub fn verify_device_proof(
    expected_challenge: &str,
    spki_der: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    // 1. The presented key must be the one committed to at `start`.
    let presented = challenge_of(spki_der);
    if !challenge_matches(expected_challenge, &presented) {
        return Err("device proof: key does not match the enrolled challenge".into());
    }

    // 2. The signature must verify under that key.
    let key = VerifyingKey::from_sec1_bytes(spki_der)
        .map_err(|_| "device proof: malformed public key".to_string())?;
    let sig = Signature::from_der(signature_der)
        .or_else(|_| Signature::from_slice(signature_der))
        .map_err(|_| "device proof: malformed signature".to_string())?;
    key.verify(message, &sig)
        .map_err(|_| "device proof: signature does not verify".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_state_round_trips() {
        let flow = mint_flow_id();
        let state = native_state(&flow);
        assert_eq!(parse_native_state(&state), Some(flow.as_str()));
    }

    #[test]
    fn foreign_state_is_not_native() {
        // The browser flow uses `state` as a redirect target. That must never
        // be treated as a native flow id.
        assert_eq!(parse_native_state("https://evil.example.com/"), None);
        assert_eq!(parse_native_state("native:"), None);
        assert_eq!(parse_native_state("native:   "), None);
        assert_eq!(parse_native_state(""), None);
        assert_eq!(parse_native_state("Native:abc"), None);
    }

    #[test]
    fn state_length_is_bounded() {
        let long = format!("native:{}", "a".repeat(200));
        assert_eq!(parse_native_state(&long), None);
    }

    #[test]
    fn challenge_is_stable_and_distinct() {
        let a = challenge_of(b"key-a");
        let b = challenge_of(b"key-b");
        assert_eq!(a, challenge_of(b"key-a"));
        assert_ne!(a, b);
        // base64url without padding
        assert!(!a.contains('=') && !a.contains('+') && !a.contains('/'));
    }

    #[test]
    fn handoff_codes_are_unique_and_256_bit() {
        let a = mint_handoff_code();
        let b = mint_handoff_code();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "32 bytes hex-encoded");
    }

    #[test]
    fn proof_rejects_wrong_key_and_wrong_signature() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let signing = SigningKey::random(&mut rand::thread_rng());
        let spki = signing.verifying_key().to_encoded_point(false);
        let spki_bytes = spki.as_bytes();
        let challenge = challenge_of(spki_bytes);
        let message = b"handoff-code";

        // Correct key + correct signature verifies.
        let sig: Signature = signing.sign(message);
        assert!(verify_device_proof(&challenge, spki_bytes, message, sig.to_der().as_bytes()).is_ok());

        // Wrong message fails.
        assert!(verify_device_proof(&challenge, spki_bytes, b"other", sig.to_der().as_bytes()).is_err());

        // A DIFFERENT key fails even with a valid signature over the same
        // message, because its hash does not match the enrolled challenge.
        let other = SigningKey::random(&mut rand::thread_rng());
        let other_spki = other.verifying_key().to_encoded_point(false);
        let other_sig: Signature = other.sign(message);
        assert!(verify_device_proof(
            &challenge,
            other_spki.as_bytes(),
            message,
            other_sig.to_der().as_bytes()
        )
        .is_err());

        // Garbage signature fails.
        assert!(verify_device_proof(&challenge, spki_bytes, message, &[1, 2, 3]).is_err());
    }

    #[test]
    fn tenant_headers_are_read_verbatim() {
        let mut h = HeaderMap::new();
        h.insert("x-sentin8-app-id", "app-1".parse().unwrap());
        h.insert("x-sentin8-env-id", "env-1".parse().unwrap());
        let (app, env) = tenant_from_headers(&h);
        assert_eq!(app, "app-1");
        assert_eq!(env, "env-1");
    }
}
