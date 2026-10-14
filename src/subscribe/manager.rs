// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Subscription lifecycle management — `POST /subscribe` and `DELETE /subscribe`.
//!
//! These are normal HTTP/2 mutations (the Queries & Mutations tier) that
//! modify the active session's subscription set. The SSE stream (`GET
//! /subscribe`) reflects changes in real time — no reconnect needed.
//!
//! Design:

use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::handlers::AppState;
use crate::session::SESSION_COOKIE;
use axum::http::HeaderMap;

/// Request body for `POST /subscribe`.
#[derive(Debug, Deserialize)]
pub struct SubscriptionChange {
    /// `add` = add types to the set, `remove` = remove types,
    /// `replace` = clear and set the new types.
    pub action: String,
    /// Event types to add/remove/replace.
    #[serde(default)]
    pub types: Vec<String>,
    /// Optional resource_id filter for page-scoped events.
    #[serde(default)]
    pub resource_id: Option<String>,
}

/// Response from `POST /subscribe`.
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    /// The active subscription set after the change.
    pub types: Vec<String>,
    /// The active resource_id filter (if any).
    pub resource_id: Option<String>,
}

/// `POST /subscribe` — add/remove/replace event types on the active
/// session's subscription set.
pub async fn subscribe_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(change): Json<SubscriptionChange>,
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let session_id = match extract_cookie(&headers, SESSION_COOKIE) {
        Some(s) => s,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Validate the session.
    match state.store.get(&session_id).await {
        Ok(Some(_)) => {}
        _ => return Err(StatusCode::UNAUTHORIZED),
    }

    // Look up the subscription state for this session.
    let map = crate::subscribe::sse::sub_map();
    let map = map.read().await;
    let sub_state = match map.get(&session_id) {
        Some(s) => s.clone(),
        None => {
            // No active SSE stream — the client must open one first.
            return Err(StatusCode::CONFLICT);
        }
    };
    drop(map);

    // Apply the change.
    let mut sub_set = sub_state.subscriptions.write().await;
    match change.action.as_str() {
        "add" => {
            for t in &change.types {
                if crate::subscribe::is_valid_event_type(t) {
                    sub_set.insert(t.clone());
                }
            }
        }
        "remove" => {
            for t in &change.types {
                sub_set.remove(t);
            }
        }
        "replace" => {
            sub_set.clear();
            for t in &change.types {
                if crate::subscribe::is_valid_event_type(t) {
                    sub_set.insert(t.clone());
                }
            }
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    // Update the resource_id filter.
    if let Some(rid) = change.resource_id.as_deref() {
        if rid.is_empty() {
            *sub_state.resource_id.write().await = None;
        } else {
            *sub_state.resource_id.write().await = Some(rid.to_string());
        }
    }

    let result_types: Vec<String> = sub_set.iter().cloned().collect();
    let result_rid = sub_state.resource_id.read().await.clone();

    tracing::info!(
        session_id = %session_id,
        action = %change.action,
        types = ?result_types,
        "bff: subscription changed"
    );

    Ok(Json(SubscriptionResponse {
        types: result_types,
        resource_id: result_rid,
    }))
}

/// `DELETE /subscribe` — close the SSE stream and clear the session's
/// subscription set.
pub async fn subscribe_close(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let session_id = match extract_cookie(&headers, SESSION_COOKIE) {
        Some(s) => s,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Validate the session.
    match state.store.get(&session_id).await {
        Ok(Some(_)) => {}
        _ => return Err(StatusCode::UNAUTHORIZED),
    }

    // Remove the subscription state — the SSE stream will detect the
    // removal (broadcast channel dropped) and end.
    let map = crate::subscribe::sse::sub_map();
    let mut map = map.write().await;
    map.remove(&session_id);

    tracing::info!(session_id = %session_id, "bff: subscription closed");

    Ok(StatusCode::NO_CONTENT)
}

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

// ── Push subscription sink (BFF-5) ─────────────────────────────────────

/// Request body of `POST /subscribe/push`.
#[derive(Debug, Deserialize)]
pub struct PushRegisterRequest {
    /// The device token issued by the platform push provider (FCM/APNs —
    /// opaque to the BFF; forwarded to Post's push gateway).
    pub device_token: String,
}

/// Response of `POST /subscribe/push` / `DELETE /subscribe/push`.
#[derive(Debug, Serialize)]
pub struct PushRegisterResponse {
    /// Whether a push token is registered for the session.
    pub registered: bool,
}

/// `POST /subscribe/push` — register a device token for the session
/// (BFF-5). Subscription events for this session are bridged to Post's
/// push gateway through the local post_outbox + bff-post pusher.
pub async fn subscribe_push_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PushRegisterRequest>,
) -> Result<Json<PushRegisterResponse>, StatusCode> {
    let session_id = extract_cookie(&headers, SESSION_COOKIE).ok_or(StatusCode::UNAUTHORIZED)?;
    let sess = state
        .store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let env_id = sess
        .env_id
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)
        .map_err(|e: StatusCode| e)?;
    crate::subscribe::push::register_push_token(
        &state.pool,
        env_id,
        &session_id,
        &sess.user_id,
        &req.device_token,
    )
    .await
    .map_err(|(_, e)| {
        tracing::error!(error = %e, "bff: push token register failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tracing::info!(session_id = %session_id, "bff: push token registered");
    Ok(Json(PushRegisterResponse { registered: true }))
}

/// `DELETE /subscribe/push` — remove the session's push registration.
pub async fn subscribe_push_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PushRegisterResponse>, StatusCode> {
    let session_id = extract_cookie(&headers, SESSION_COOKIE).ok_or(StatusCode::UNAUTHORIZED)?;
    let sess = state
        .store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let env_id = sess.env_id.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    crate::subscribe::push::delete_push_token(&state.pool, env_id, &session_id)
        .await
        .map_err(|(_, e)| {
            tracing::error!(error = %e, "bff: push token delete failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    tracing::info!(session_id = %session_id, "bff: push token removed");
    Ok(Json(PushRegisterResponse { registered: false }))
}
