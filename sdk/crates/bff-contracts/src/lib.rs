// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! # bff-contracts
//!
//! Rust types for the BFF Backend-for-Frontend service - session
//! metadata and dynamic-client-registration wire types.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Session metadata returned by `GET /bff/auth/session` - never includes tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// The authenticated user's id.
    pub user_id: String,
    /// The user's email, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The session's organization.
    pub org_id: String,
    /// The session's environment (the tenant key).
    pub env_id: String,
    /// The session's effective scopes.
    pub scopes: Vec<String>,
    /// The app instance the session is bound to, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// CSRF token for state-changing calls.
    pub csrf_token: String,
    /// Session expiry (UTC).
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Request body for DCR registration (`POST /dcr/register`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcrRegisterRequest {
    /// The Auth domain the client registers against.
    pub sentin8_auth_domain: String,
    /// Human-facing client name.
    pub client_name: String,
    /// The OAuth redirect URI for the code flow.
    pub redirect_uri: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
}

/// Response from DCR registration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcrRegisterResponse {
    /// The registered client id (no secret - public PKCE clients).
    pub client_id: String,
    /// The Auth domain the client was registered on.
    pub sentin8_auth_domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn sample() -> SessionMetadata {
        SessionMetadata {
            user_id: "user-1".into(),
            email: Some("u@example.com".into()),
            org_id: "org-1".into(),
            env_id: "env-1".into(),
            scopes: vec![
                "sentin8:auth:user:read".into(),
                "bank8:ledger:accounts:read".into(),
            ],
            application_id: Some("app-1".into()),
            csrf_token: "csrf-abc".into(),
            expires_at: utc("2026-01-01T01:00:00Z"),
        }
    }

    #[test]
    fn session_metadata_never_carries_tokens() {
        // Serialize the full struct and assert no token-ish field exists.
        let v = serde_json::to_value(sample()).unwrap();
        for banned in [
            "access_token",
            "refresh_token",
            "id_token",
            "authorization",
            "bearer",
            "password",
            "secret",
        ] {
            assert!(
                v.get(banned).is_none(),
                "SessionMetadata leaked a `{banned}` field - tokens must never reach the client"
            );
        }
    }

    #[test]
    fn session_metadata_roundtrip() {
        let m = sample();
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["csrf_token"], "csrf-abc");
        let back: SessionMetadata = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn session_metadata_email_optional() {
        let mut m = sample();
        m.email = None;
        m.application_id = None;
        let v = serde_json::to_value(&m).unwrap();
        assert!(v.get("email").is_none());
        assert!(v.get("application_id").is_none());
        let back: SessionMetadata = serde_json::from_value(v).unwrap();
        assert!(back.email.is_none());
    }

    #[test]
    fn dcr_roundtrip() {
        let req = DcrRegisterRequest {
            sentin8_auth_domain: "auth.ops.sys.example.com".into(),
            client_name: "eBank Web".into(),
            redirect_uri: "https://ebank.prod.ibank.local/auth/callback".into(),
            scopes: vec!["openid".into(), "ledger:accounts:read".into()],
        };
        let v = serde_json::to_value(&req).unwrap();
        let back: DcrRegisterRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back, req);

        let resp = DcrRegisterResponse {
            client_id: "dcr-client-1".into(),
            sentin8_auth_domain: "auth.ops.sys.example.com".into(),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["client_id"], "dcr-client-1");
        let back: DcrRegisterResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back, resp);
    }
}
