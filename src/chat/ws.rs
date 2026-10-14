// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! WebSocket chat handler — `GET /ws` .
//!
//! This is the **Chat** tier of the three-tier client↔BFF transport
//! model. It handles bidirectional, low-latency conversational exchange
//! between users. One-way push (domain events, notifications, metrics,
//! delegation results) lives on the SSE subscription tier , not
//! here.
//!
//! ## Chat frame types
//!
//! | `type` | Direction | Payload |
//! |--------|-----------|---------|
//! | `chat.message` | client→server / server→client | `conversation_id`, `message_id`, `sender_id`, `text`, `timestamp` |
//! | `chat.typing` | client→server / server→client | `conversation_id`, `user_id`, `is_typing` |
//! | `chat.presence` | server→client | `conversation_id`, `user_id`, `status` |
//! | `chat.hi` | client→server (request) / server→client (response) | `conversation_id`, `before?`, `limit?` |
//! | `chat.delivered` | server→client | `message_id`, `conversation_id` |
//! | `chat.read` | client→server / server→client | `conversation_id`, `message_id` |
//! | `chat.error` | server→client | `code`, `message` |
//!
//! ## Room model
//!
//! The client joins conversations via `{"action": "join", "conversation_ids": [...]}`
//! and leaves with `{"action": "leave", "conversation_ids": [...]}`. BFF
//! only pushes chat frames for conversations the client has joined.
//!
//! Domain events (`chat.message.sent`, `chat.conversation.created`) are
//! NOT on this channel — they go to Bus → SSE subscription tier.
//!
//! Design:

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};

use crate::handlers::AppState;
use crate::session::SESSION_COOKIE;

/// Broadcast channel for per-connection chat frames.
type ChatSender = broadcast::Sender<serde_json::Value>;

/// Per-connection state: which conversations the client has joined.
type JoinedRooms = Arc<RwLock<HashSet<String>>>;

/// Global map: conversation_id → broadcast sender (for fan-out to all
/// participants in a conversation).
type RoomMap = Arc<RwLock<HashMap<String, ChatSender>>>;

static ROOMS: std::sync::OnceLock<RoomMap> = std::sync::OnceLock::new();

fn rooms() -> RoomMap {
    ROOMS
        .get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

/// `GET /ws` — WebSocket upgrade handler for chat.
///
/// Validates the BFF session cookie on upgrade. If valid, establishes a
/// WS connection and enters the chat event loop.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let session_id = match extract_cookie(&headers, SESSION_COOKIE) {
        Some(s) => s,
        None => {
            return axum::response::IntoResponse::into_response((
                axum::http::StatusCode::UNAUTHORIZED,
                "no session",
            ))
        }
    };

    // Validate the session.
    match _state.store.get(&session_id).await {
        Ok(Some(s)) => {
            // D2 — session→application binding : reject
            // sessions created by another app instance.
            let req_app = headers
                .get("x-sentin8-app-id")
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty());
            if !s.matches_application(req_app) {
                tracing::warn!(
                    session_app = ?s.application_id,
                    request_app = ?req_app,
                    "bff: ws chat REJECTED session — application binding mismatch"
                );
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::UNAUTHORIZED,
                    "session not valid for this application",
                ));
            }
        }
        _ => {
            return axum::response::IntoResponse::into_response((
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid session",
            ))
        }
    }

    tracing::info!(
        session_id = %session_id,
        "bff: ws chat upgrade — session validated"
    );

    ws.on_upgrade(move |socket| chat_connection(socket, session_id))
}

/// The per-connection chat event loop.
async fn chat_connection(socket: WebSocket, session_id: String) {
    let (tx, mut rx) = broadcast::channel::<serde_json::Value>(64);
    let joined: JoinedRooms = Arc::new(RwLock::new(HashSet::new()));

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Forward task: broadcast → ws_sender.
    let joined_clone = joined.clone();
    let forward_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(frame) => {
                    // Only forward frames for joined conversations.
                    let conv_id = frame["conversation_id"].as_str().unwrap_or("").to_string();
                    let rooms = joined_clone.read().await;
                    if conv_id.is_empty() || rooms.contains(&conv_id) {
                        drop(rooms);
                        let msg = serde_json::to_string(&frame).unwrap_or_default();
                        if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    // Ping task (every 30s).
    let ping_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
        }
    });

    // Main loop: receive chat frames from the client.
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    let action = parsed["action"].as_str().unwrap_or("");
                    match action {
                        "join" => {
                            if let Some(conv_ids) = parsed["conversation_ids"].as_array() {
                                let mut joined_rooms = joined.write().await;
                                let global_rooms = rooms();
                                for cid in conv_ids {
                                    if let Some(id) = cid.as_str() {
                                        joined_rooms.insert(id.to_string());
                                        // Register in the global room map.
                                        let mut global = global_rooms.write().await;
                                        global.entry(id.to_string()).or_insert_with(|| {
                                            let (rtx, _) = broadcast::channel(64);
                                            rtx
                                        });
                                    }
                                }
                                tracing::info!(
                                    session_id = %session_id,
                                    rooms = ?joined_rooms,
                                    "bff: chat join"
                                );
                            }
                        }
                        "leave" => {
                            if let Some(conv_ids) = parsed["conversation_ids"].as_array() {
                                let mut rooms = joined.write().await;
                                for cid in conv_ids {
                                    if let Some(id) = cid.as_str() {
                                        rooms.remove(id);
                                    }
                                }
                            }
                        }
                        "ping" => {
                            let _ = tx.send(serde_json::json!({"type": "pong"}));
                        }
                        _ => {
                            // Chat frame (chat.message, chat.typing, etc.)
                            // — forward to all participants in the
                            // conversation via the global room channel.
                            let conv_id =
                                parsed["conversation_id"].as_str().unwrap_or("").to_string();
                            if !conv_id.is_empty() {
                                let global = rooms();
                                let global = global.read().await;
                                if let Some(room_tx) = global.get(&conv_id) {
                                    let _ = room_tx.send(parsed.clone());
                                }
                            }
                        }
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    // Cleanup.
    forward_task.abort();
    ping_task.abort();
    tracing::info!(session_id = %session_id, "bff: ws chat disconnected");
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
