// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Bus SSE consumer - Tier 1 domain events.
//!
//! Each SSE subscription stream (`GET /subscribe`) spawns a background Bus
//! consumer task that drains events from the stream families matching the
//! client's subscriptions. Events are pushed to the session's broadcast
//! channel (which the SSE stream forwards to the client).
//!
//! The consumer uses the server's M2M-backed `BusClient` (`sentin8:bus:consume`
//! scope). The consumer group is namespaced per session: `sse-{session_id}`
//! (renamed from `ws-{session_id}` per the three-tier transport model).
//!
//! Design: ,

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Duration;

/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Poll interval for checking subscription changes.
const SUB_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Info extracted from the session, needed by the Bus consumer for
/// RBAC filtering.
#[derive(Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub org_id: String,
    pub env_id: String,
    pub subject_type: String,
    pub scope: String,
    /// All org IDs the user is a member of (via `sentin8_auth_group_members` →
    /// `sentin8_auth_groups.org_id`). Used for RBAC filtering of
    /// `sentin8:stat.traffic.snapshot` events. Platform admins (scope contains
    /// `sentin8:sys:admin`) bypass this - they see all orgs.
    pub accessible_org_ids: Vec<String>,
}

/// Spawn a Bus SSE consumer background task for an SSE subscription.
pub fn spawn_consumer(
    client: sentin8::bus::client::BusClient,
    session: SessionInfo,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    _resource_id: Arc<RwLock<Option<String>>>,
    tx: tokio::sync::broadcast::Sender<serde_json::Value>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_consumer(client, session, subscriptions, tx).await;
    })
}

/// Run the consumer loop: connect to Bus SSE, receive pushed messages,
/// reconnect on disconnect or subscription change.
async fn run_consumer(
    client: sentin8::bus::client::BusClient,
    session: SessionInfo,
    subscriptions: Arc<RwLock<HashSet<String>>>,
    tx: tokio::sync::broadcast::Sender<serde_json::Value>,
) {
    // Consumer group: sse-{session_id_suffix} (renamed from ws- per the
    // three-tier transport model).
    let consumer_group = format!(
        "sse-{}",
        &session.session_id[session.session_id.len().min(8)..]
    );

    tracing::info!(
        session_id = %session.session_id,
        user_id = %session.user_id,
        "bff: bus SSE consumer started (consumer_group={})", consumer_group
    );

    let mut connected_families: HashSet<String> = HashSet::new();

    loop {
        let sub_set = subscriptions.read().await;
        if sub_set.is_empty() {
            drop(sub_set);
            tokio::time::sleep(SUB_CHECK_INTERVAL).await;
            continue;
        }

        let mut families: HashSet<String> = HashSet::new();
        for event_type in sub_set.iter() {
            if let Some(family) = crate::subscribe::event_type_to_stream_family(event_type) {
                families.insert(family.to_string());
            }
        }
        drop(sub_set);

        if families == connected_families {
            tokio::time::sleep(SUB_CHECK_INTERVAL).await;
            continue;
        }

        connected_families = families.clone();

        for family in &families {
            let resp = match client.sse_consume(family, &consumer_group).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, family = %family, "bff: bus SSE consume failed");
                    continue;
                }
            };

            tracing::info!(family = %family, "bff: bus SSE connected");

            let tx_clone = tx.clone();
            let session_clone = session.clone();
            let family_clone = family.clone();
            let client_clone = client.clone();
            let group_clone = consumer_group.clone();
            let subs_clone = subscriptions.clone();
            let connected_clone = connected_families.clone();

            let handle = tokio::spawn(async move {
                sse_consume_loop(
                    resp,
                    &family_clone,
                    &group_clone,
                    &session_clone,
                    &tx_clone,
                    &client_clone,
                    &subs_clone,
                    &connected_clone,
                )
                .await;
            });

            let _ = handle.await;
        }
    }
}

/// Process messages from a single Bus SSE connection.
async fn sse_consume_loop(
    resp: reqwest::Response,
    family: &str,
    consumer_group: &str,
    session: &SessionInfo,
    tx: &tokio::sync::broadcast::Sender<serde_json::Value>,
    client: &sentin8::bus::client::BusClient,
    subscriptions: &Arc<RwLock<HashSet<String>>>,
    connected_families: &HashSet<String>,
) {
    let mut buffer = String::new();
    let mut stream = resp.bytes_stream();

    let mut sub_check = tokio::time::interval(Duration::from_secs(5));
    sub_check.tick().await;

    loop {
        tokio::select! {
                   _ = sub_check.tick() => {
                       let current_subs = subscriptions.read().await;
                       let mut current_families = HashSet::new();
                       for event_type in current_subs.iter() {
                           if let Some(family) = crate::subscribe::event_type_to_stream_family(event_type) {
                               current_families.insert(family.to_string());
                           }
                       }
                       if current_families != *connected_families {
                           tracing::info!(family = %family, "bff: bus SSE disconnecting (subscriptions changed)");
                           return;
                       }
                   }
                   chunk_result = stream.next() => {
                       let chunk = match chunk_result {
                           Some(Ok(c)) => c,
                           Some(Err(e)) => {
                               tracing::warn!(error = %e, family = %family, "bff: bus SSE stream error");
                               return;
                           }
                           None => {
                               tracing::info!(family = %family, "bff: bus SSE stream ended");
                               return;
                           }
                       };
                       buffer.push_str(&String::from_utf8_lossy(&chunk));

                       while let Some(pos) = buffer.find("\n\n") {
                           let event_text = buffer[..pos].to_string();
                           buffer = buffer[pos + 2..].to_string();

                           let mut data_line = String::new();
                           for line in event_text.lines() {
                               if let Some(d) = line.strip_prefix("data: ") {
                                   data_line = d.to_string();
                               }
                           }

                           if data_line.is_empty() {
                               continue;
                           }

                           let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                               Ok(v) => v,
                               Err(_) => continue,
                           };

                           let event_type = msg["event_type"].as_str().unwrap_or("").to_string();
                           let message_id = msg["message_id"].as_str().unwrap_or("").to_string();

                           let mut event = serde_json::json!({
                               "type": event_type,
                               "stream_family": msg["stream_family"],
                               "org_id": msg["org_id"],
                               "env_id": msg["env_id"],
                               "message_id": message_id,
                               "produced_at": msg["produced_at"],
                               "produced_by": msg["produced_by"],
        // Pass publisher_subject to the client for audit/activity
        // feeds. Do NOT pass publisher_id_token -
        // that token is server-side only and must never reach
        // the browser. See (privacy).
                               "publisher_subject": msg["publisher_subject"],
                           });

                           if let Some(obj) = msg["payload"].as_object() {
                               for (k, v) in obj {
                                   event[k] = v.clone();
                               }
                           }

        // Filter sentin8:notification:received and sentin8:notification:read by user_id.
                           if event_type == "sentin8:notification:received"
                               || event_type == "sentin8:notification:read"
                           {
                               let target_user = event["user_id"].as_str().unwrap_or("");
                               if !target_user.is_empty() && target_user != session.user_id {
                                   let _ = client.ack(family, consumer_group, &message_id).await;
                                   continue;
                               }
                           }

        // Per-user filtering for vertical events (platform
        // ): any event carrying an explicit `user_id`
        // identity claim reaches ONLY the session user -
        // unless the caller is a platform admin (cross-tenant
        // operator view). This is what lets per-user vertical
        // events (`email8:push:state:changed`,
        // `email8:mail:share:granted`, …) fan out to the
        // owning session without the vertical running its own
        // SSE fan-out. Events without a `user_id` claim fall
        // back to the existing tenant/RBAC isolation.
                           {
                               let is_platform_admin = session
                                   .scope
                                   .split_whitespace()
                                   .any(|s| s == "sentin8:sys:admin");
                               if !is_platform_admin {
                                   let target_user = event["user_id"].as_str().unwrap_or("");
                                   if !target_user.is_empty() && target_user != session.user_id {
                                       let _ = client.ack(family, consumer_group, &message_id).await;
                                       continue;
                                   }
                               }
                           }

        // RBAC filter for stat.traffic.snapshot.
                           if event_type == "sentin8:stat:traffic:snapshot" {
                               let snap_org = event["org_id"].as_str().unwrap_or("");
                               let snap_env = event["env_id"].as_str().unwrap_or("");
                               let is_platform_admin = session
                                   .scope
                                   .split_whitespace()
                                   .any(|s| s == "sentin8:sys:admin");
                               if !is_platform_admin {
                                   if !snap_org.is_empty()
                                       && !session.accessible_org_ids.iter().any(|o| o == snap_org)
                                   {
                                       let _ = client.ack(family, consumer_group, &message_id).await;
                                       continue;
                                   }
                                   if !snap_env.is_empty()
                                       && !session.env_id.is_empty()
                                       && snap_env != session.env_id
                                   {
                                       let _ = client.ack(family, consumer_group, &message_id).await;
                                       continue;
                                   }
                               }
                           }

        // Push to the SSE broadcast channel.
                           let _ = tx.send(event);

        // ACK via HTTP to advance the consumer cursor.
                           let _ = client.ack(family, consumer_group, &message_id).await;
                       }
                   }
               }
    }
}
