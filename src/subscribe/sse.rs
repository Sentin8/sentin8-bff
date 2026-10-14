// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! SSE subscription stream — (SSE migration).
//!
//! `GET /subscribe` — Server-Sent Events stream for real-time push to apps.
//! Authenticated via the BFF session cookie. This is the **Subscriptions**
//! tier of the three-tier client↔BFF transport model :
//!
//! - Queries & Mutations → HTTP/2 (`/proxy/*`)
//! - **Subscriptions → SSE (`GET /subscribe`, `text/event-stream`)**
//! - Chat → WebSocket (`GET /ws`)
//!
//! The SSE stream is read-only from the client's side. To change
//! subscriptions, the client issues a normal HTTP/2 mutation (`POST
//! /subscribe` with the desired `types`/`resource_id`) or opens a new
//! `GET /subscribe` with updated query parameters.
//!
//! ## SSE wire format
//!
//! ```text
//! id: {event-id}
//! event: {type}
//! data: {json payload}\n\n
//! ```
//!
//! - `id` — opaque, monotonically increasing per stream. On reconnect,
//! the client sends `Last-Event-ID: {id}` and BFF resumes after that
//! cursor.
//! - `event` — the event `type` from the catalog. Maps to the SSE event
//! field; clients can register per-type listeners via
//! `EventSource.addEventListener(type, ...)`.
//! - `data` — the JSON payload, single line.
//! - Heartbeats: BFF sends `: heartbeat\n\n` every 15s during idle
//! periods to keep the HTTP/2 stream open and defeat idle proxy
//! timeouts.
//!
//! Design:

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{
        sse::{Event as SseEvent, KeepAlive},
        Sse,
    },
};
use futures_util::stream;
use futures_util::Stream;
use serde::Deserialize;
use tokio::sync::{broadcast, RwLock};

use crate::handlers::AppState;
use crate::session::SESSION_COOKIE;

/// Query parameters for `GET /subscribe`.
#[derive(Debug, Deserialize)]
pub struct SubscribeQuery {
    /// Comma-separated list of event types to subscribe to.
    /// If empty or missing, the client receives all events.
    #[serde(default)]
    pub types: Option<String>,
    /// Optional resource_id filter for page-scoped event types.
    #[serde(default)]
    pub resource_id: Option<String>,
}

/// State shared between the SSE stream and the POST/DELETE subscription
/// management endpoints. Stored in a global map keyed by session_id.
#[derive(Clone)]
pub struct SubscriptionState {
    /// The event types the client is subscribed to.
    /// Empty set = receive all events.
    pub subscriptions: Arc<RwLock<HashSet<String>>>,
    /// Optional resource_id filter for page-scoped events.
    pub resource_id: Arc<RwLock<Option<String>>>,
    /// Broadcast sender — events sent here are forwarded to the SSE stream.
    pub tx: broadcast::Sender<serde_json::Value>,
    /// Monotonic event ID counter for SSE `id:` field + Last-Event-ID.
    pub event_id: Arc<std::sync::atomic::AtomicU64>,
}

/// Global map: session_id → subscription state.
/// Used by POST/DELETE /subscribe to modify the active subscription set
/// and by background tasks (delegation poll) to push events.
type SubMap = Arc<RwLock<std::collections::HashMap<String, SubscriptionState>>>;

static SUB_MAP: std::sync::OnceLock<SubMap> = std::sync::OnceLock::new();

pub fn sub_map() -> SubMap {
    SUB_MAP
        .get_or_init(|| Arc::new(RwLock::new(std::collections::HashMap::new())))
        .clone()
}

/// `GET /subscribe` — open the SSE subscription stream.
///
/// Validates the BFF session cookie, parses `types` and `resource_id`
/// query params, spawns the Bus consumer task, and returns a
/// `text/event-stream` response.
pub async fn subscribe_handler(
    State(state): State<AppState>,
    Query(query): Query<SubscribeQuery>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, axum::Error>>>, axum::http::StatusCode> {
    // Extract the session cookie.
    let session_id = match extract_cookie(&headers, SESSION_COOKIE) {
        Some(s) => s,
        None => return Err(axum::http::StatusCode::UNAUTHORIZED),
    };

    // Validate the session.
    let sess = match state.store.get(&session_id).await {
        Ok(Some(s)) => s,
        _ => return Err(axum::http::StatusCode::UNAUTHORIZED),
    };

    // D2 — session→application binding : reject sessions
    // created by another app instance.
    {
        let req_app = headers
            .get("x-sentin8-app-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty());
        if !sess.matches_application(req_app) {
            tracing::warn!(
                session_app = ?sess.application_id,
                request_app = ?req_app,
                "bff: SSE subscribe REJECTED session — application binding mismatch"
            );
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }

    tracing::info!(
        session_id = %session_id,
        user_id = %sess.user_id,
        "bff: SSE subscribe — session validated"
    );

    // Parse types from query param (convention-based validation).
    let initial_types: HashSet<String> = query
        .types
        .as_deref()
        .map(|t| {
            t.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .filter(|s| crate::subscribe::is_valid_event_type(s))
                .collect()
        })
        .unwrap_or_default();

    // Create a broadcast channel for this session.
    let (tx, rx) = broadcast::channel::<serde_json::Value>(256);

    let sub_state = SubscriptionState {
        subscriptions: Arc::new(RwLock::new(initial_types)),
        resource_id: Arc::new(RwLock::new(query.resource_id)),
        tx: tx.clone(),
        event_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };

    // Register in the global map.
    {
        let map = sub_map();
        let mut guard = map.write().await;
        guard.insert(session_id.clone(), sub_state.clone());
    }

    // Query the user's org memberships for RBAC filtering.
    let accessible_org_ids: Vec<String> = if sess
        .scope
        .split_whitespace()
        .any(|s| s == "sentin8:sys:admin")
    {
        Vec::new()
    } else {
        sqlx::query_scalar::<_, String>(
            r#"SELECT DISTINCT g.org_id::text
                 FROM groups g
                 JOIN group_members gm ON gm.group_id = g.id
                WHERE gm.user_id = $1"#,
        )
        .bind(&sess.user_id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    };
    let mut org_ids = accessible_org_ids;
    if !org_ids.contains(&sess.org_id) {
        org_ids.push(sess.org_id.clone());
    }

    let session_info = crate::subscribe::bus::SessionInfo {
        session_id: session_id.clone(),
        user_id: sess.user_id.clone(),
        org_id: sess.org_id.clone(),
        env_id: sess.env_id.clone(),
        subject_type: sess.subject_type.clone(),
        scope: sess.scope.clone(),
        accessible_org_ids: org_ids,
    };

    // Spawn the Bus consumer task (Tier 1: domain events via Bus SSE).
    let _sentin8_bus_task = crate::subscribe::bus::spawn_consumer(
        state.sentin8_bus_consumer_client.clone(),
        session_info,
        sub_state.subscriptions.clone(),
        sub_state.resource_id.clone(),
        tx.clone(),
    );

    // Build the SSE stream from the broadcast channel using
    // `futures_util::stream::unfold` (no tokio-stream dependency needed).
    let sub_state_clone = sub_state.clone();
    let session_id_clone = session_id.clone();
    let sub_map_clone = sub_map();

    let event_stream = stream::unfold(rx, move |mut rx| {
        let sub_state = sub_state_clone.clone();
        let session_id = session_id_clone.clone();
        let sub_map = sub_map_clone.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // Check subscription filter.
                        let event_type = event["type"].as_str().unwrap_or("").to_string();
                        let sub_set = sub_state.subscriptions.read().await;
                        let subscribed = sub_set.contains(&event_type) || sub_set.is_empty();
                        drop(sub_set);
                        if !subscribed {
                            continue;
                        }

                        // Check resource_id filter for page-scoped events.
                        if crate::subscribe::is_page_scoped(&event_type) {
                            let rid = sub_state.resource_id.read().await;
                            if let Some(ref filter_id) = *rid {
                                let event_rid = event["resource_id"]
                                    .as_str()
                                    .or_else(|| event["account_id"].as_str())
                                    .or_else(|| event["customer_id"].as_str())
                                    .or_else(|| event["payment_id"].as_str())
                                    .or_else(|| event["consent_id"].as_str())
                                    .unwrap_or("");
                                if event_rid != filter_id.as_str() {
                                    drop(rid);
                                    continue;
                                }
                            }
                            drop(rid);
                        }

                        // Build the SSE event with id + event + data.
                        let id = sub_state
                            .event_id
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let data = serde_json::to_string(&event).unwrap_or_default();
                        let sse_event = SseEvent::default()
                            .id(id.to_string())
                            .event(event_type)
                            .data(data);
                        return Some((Ok(sse_event), rx));
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed — stream ends.
                        // Clean up the subscription state.
                        let mut guard = sub_map.write().await;
                        guard.remove(&session_id);
                        return None;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Skipped some events — continue.
                        continue;
                    }
                }
            }
        }
    });

    // Use axum's Sse with KeepAlive for heartbeats.
    let sse = Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    );

    Ok(sse)
}

/// Push an event to a specific session's SSE stream (if active).
///
/// Called by background tasks (e.g. delegation poll) to push results to the
/// connected client. If the session has no active SSE stream, the event is
/// silently dropped (the client can fall back to polling).
pub async fn push_event(session_id: &str, event: serde_json::Value) {
    let map = sub_map();
    let map = map.read().await;
    if let Some(state) = map.get(session_id) {
        let _ = state.tx.send(event.clone());
    }
    drop(map);
    // Push sink (BFF-5): a session with a registered device token ALSO
    // receives the event through Post's push gateway — the bridge enqueues
    // into BFF's local `post_outbox` and the bff-post pusher relays it.
    // Best-effort: a push enqueue failure never affects the SSE stream.
    if let Some(pool) = crate::subscribe::push::pool_handle() {
        let pool = pool.clone();
        let session_id = session_id.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                crate::subscribe::push::enqueue_for_session(&pool, &session_id, &event).await
            {
                tracing::debug!(error = %e, "bff: push enqueue skipped");
            }
        });
    }
}

/// Check if a session has an active SSE subscription stream.
pub async fn has_subscription(session_id: &str) -> bool {
    let map = sub_map();
    let map = map.read().await;
    map.contains_key(session_id)
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
