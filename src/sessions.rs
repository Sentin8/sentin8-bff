// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Multi-session device management (bff DESIGN §4 "Session (cookie + D2
//! binding)").
//!
//! `GET /v1/auth/sessions` lists the caller's active cached sessions,
//! `GET /v1/auth/sessions/{id}` returns one, `DELETE /v1/auth/sessions/{id}`
//! destroys a record and revokes its stored refresh token, and
//! `DELETE /v1/auth/sessions` revokes every session except the caller's
//! current one. The store has no subject index, so listing uses the bounded
//! SCAN (`SessionStore::list_session_ids`) filtered by `user_id` — the same
//! shape the session-reaper (`subscribe/session_revocation.rs`) uses for
//! subject-scope kills.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::Value;

use crate::handlers::{extract_cookie, AppState};
use crate::session::{self, Session};

/// Bounded SCAN limit for the subject-scoped session listing (matches the
/// session-reaper's `list_session_ids(1000)` batch — SCAN keeps the shared
/// Valkey responsive, `KEYS` would block under load).
const SESSION_SCAN_LIMIT: usize = 1000;

// ── Caller resolution ───────────────────────────────────────────────────

/// Resolve the caller from the BFF session cookie (bff DESIGN §5):
/// cookie → store lookup → D2 application-binding check. Every operation
/// in this module is scoped to the resolved `user_id`; requests that
/// cannot resolve a session are rejected, never defaulted.
async fn caller_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Session, (StatusCode, String)> {
    let session_id = extract_cookie(headers, session::SESSION_COOKIE)
        .ok_or((StatusCode::UNAUTHORIZED, "no session".to_string()))?;
    let sess = state
        .store
        .get(&session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "session not found".to_string()))?;
    // D2 — session→application binding (bff DESIGN §8.2): the caller's
    // session must belong to the app instance resolved from this request
    // (fail-closed, same predicate as `auth_session`).
    let req_app = headers
        .get("x-sentin8-app-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());
    if !sess.matches_application(req_app) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "session not valid for this application".into(),
        ));
    }
    Ok(sess)
}

// ── Pure predicates + shapes (unit-tested below) ────────────────────────

/// 404 predicate for single-session routes: a session is addressable only
/// when the record exists AND belongs to the caller. Missing and
/// foreign-owned are the same `None` — no existence oracle across users
/// (bff DESIGN §8.9).
fn owned_session(sess: Option<Session>, caller_user_id: &str) -> Option<Session> {
    match sess {
        Some(s) if s.user_id == caller_user_id => Some(s),
        _ => None,
    }
}

/// Current-exclusion predicate for "revoke all others": a record is
/// revocable only when owned by the caller AND it is not the caller's
/// current session — the current session always survives (bff DESIGN §8.9).
fn revocable_other(sess: &Session, caller_user_id: &str, current_session_id: &str) -> bool {
    sess.user_id == caller_user_id && sess.session_id != current_session_id
}

/// Build one listing entry — metadata only, never tokens (bff DESIGN §8.1:
/// tokens never reach the browser).
fn session_entry(sess: &Session, current_session_id: &str) -> Value {
    serde_json::json!({
        "session_id": sess.session_id,
        "created_at": sess.created_at,
        "last_seen": sess.last_accessed_at,
        "current": sess.session_id == current_session_id,
    })
}

// ── Revocation ──────────────────────────────────────────────────────────

/// Revoke one stored refresh token at Auth — the same best-effort
/// `POST /oauth/revoke` (form `token`) sign-out uses. Best-effort by
/// design: the destroyed store record already makes the cached tokens
/// unusable, so a failed revoke call never blocks the record delete.
async fn revoke_refresh_token(client: &reqwest::Client, auth_base_url: &str, refresh_token: &str) {
    if refresh_token.is_empty() {
        return;
    }
    let _ = client
        .post(format!("{}/oauth/revoke", auth_base_url))
        .form(&[("token", refresh_token)])
        .send()
        .await;
}

/// Destroy a session record and revoke its stored refresh token the same
/// way sign-out does (bff DESIGN §4 "Session" revoke semantics).
async fn revoke_session_record(state: &AppState, client: &reqwest::Client, sess: &Session) {
    let key = session::derive_key(&state.config.encryption_key);
    if let Ok(rt) = sess.refresh_token(&key) {
        revoke_refresh_token(client, &state.config.sentin8_auth_base_url, &rt).await;
    }
    let _ = state.store.destroy(&sess.session_id).await;
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `GET /v1/auth/sessions` — list the caller's active sessions.
///
/// Returns `{sessions: [{session_id, created_at, last_seen, current}]}`
/// for every cached record owned by the caller (`user_id` filter over the
/// bounded SCAN), newest first, with `current` marking the calling
/// session. Tokens are never included.
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, String)> {
    let caller = caller_session(&state, &headers).await?;
    let ids = state
        .store
        .list_session_ids(SESSION_SCAN_LIMIT)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut owned: Vec<Session> = Vec::new();
    for id in ids {
        // Scan-race guard: a record can expire between SCAN and GET.
        if let Ok(Some(s)) = state.store.get(&id).await {
            if s.user_id == caller.user_id {
                owned.push(s);
            }
        }
    }
    owned.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let sessions: Vec<Value> = owned
        .iter()
        .map(|s| session_entry(s, &caller.session_id))
        .collect();
    Ok(Json(serde_json::json!({ "sessions": sessions })))
}

/// `GET /v1/auth/sessions/{id}` — one session's metadata.
///
/// 404 when the record is missing or owned by another user.
pub async fn get_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, String)> {
    let caller = caller_session(&state, &headers).await?;
    let fetched = state
        .store
        .get(&session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sess = owned_session(fetched, &caller.user_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    Ok(Json(session_entry(&sess, &caller.session_id)))
}

/// `DELETE /v1/auth/sessions/{id}` — revoke one session.
///
/// Destroys the store record and revokes its stored refresh token at Auth
/// (the sign-out revocation path). 404 when the record is missing or
/// owned by another user.
pub async fn revoke_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, String)> {
    let caller = caller_session(&state, &headers).await?;
    let fetched = state
        .store
        .get(&session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sess = owned_session(fetched, &caller.user_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    let client = reqwest::Client::new();
    revoke_session_record(&state, &client, &sess).await;
    tracing::info!(
        target = %sess.session_id,
        actor = %caller.user_id,
        "bff: session revoked by user"
    );
    Ok(Json(
        serde_json::json!({"status": "revoked", "session_id": sess.session_id}),
    ))
}

/// `DELETE /v1/auth/sessions` — revoke every session except the current.
///
/// Destroys each record owned by the caller other than the calling
/// session (current-exclusion, bff DESIGN §8.9) and revokes its stored
/// refresh token; the caller stays signed in on this device.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, String)> {
    let caller = caller_session(&state, &headers).await?;
    let ids = state
        .store
        .list_session_ids(SESSION_SCAN_LIMIT)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let client = reqwest::Client::new();
    let mut revoked = 0usize;
    for id in ids {
        // Scan-race guard: a record can expire between SCAN and GET.
        if let Ok(Some(s)) = state.store.get(&id).await {
            if revocable_other(&s, &caller.user_id, &caller.session_id) {
                revoke_session_record(&state, &client, &s).await;
                revoked += 1;
            }
        }
    }
    tracing::info!(revoked, actor = %caller.user_id, "bff: revoked other sessions");
    Ok(Json(
        serde_json::json!({"status": "revoked", "revoked_count": revoked}),
    ))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(user: &str) -> Session {
        let mut s = Session::new(user.to_string(), "org-1".into(), "env-1".into());
        s.created_at = 1_700_000_000;
        s.last_accessed_at = 1_700_000_100;
        s
    }

    #[test]
    fn owned_session_rejects_missing_and_foreign() {
        let mine = sess("user-1");
        let theirs = sess("user-2");
        assert!(owned_session(Some(mine.clone()), "user-1").is_some());
        assert!(owned_session(Some(theirs), "user-1").is_none());
        assert!(owned_session(None, "user-1").is_none());
    }

    #[test]
    fn revocable_other_keeps_current_and_foreign() {
        let current = sess("user-1");
        let other_mine = sess("user-1");
        let foreign = sess("user-2");
        assert!(!revocable_other(&current, "user-1", &current.session_id));
        assert!(revocable_other(&other_mine, "user-1", &current.session_id));
        assert!(!revocable_other(&foreign, "user-1", &current.session_id));
    }

    #[test]
    fn session_entry_marks_current_and_carries_no_tokens() {
        let mut s = sess("user-1");
        let key = session::derive_key("test-key");
        s.set_access_token("access-token-value", &key).unwrap();
        s.set_refresh_token("refresh-token-value", &key).unwrap();
        let entry = session_entry(&s, &s.session_id);
        let v = serde_json::to_value(&entry).unwrap();
        for banned in [
            "access_token",
            "refresh_token",
            "access_token_enc",
            "refresh_token_enc",
        ] {
            assert!(
                v.get(banned).is_none(),
                "session entry leaked `{banned}` — tokens never reach the client"
            );
        }
        assert_eq!(v["current"], true);
        assert_eq!(v["last_seen"], s.last_accessed_at);
        assert_eq!(v["created_at"], s.created_at);
    }

    #[test]
    fn session_entry_shape_is_pinned() {
        let s = sess("user-1");
        let v = serde_json::to_value(session_entry(&s, "another-session")).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["created_at", "current", "last_seen", "session_id"]
        );
        assert_eq!(v["current"], false);
    }
}
