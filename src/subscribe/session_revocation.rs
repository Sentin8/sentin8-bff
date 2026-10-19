// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Session-reaper - Bus subscription that kills cached BFF sessions.
//!
//! Continuous access evaluation (bff DESIGN §10): when Sentin8:Auth
//! revokes a user's session or tokens (sign-out, OAuth revoke, password
//! reset, admin terminate) it emits `sentin8:auth:session:revoked` onto
//! the `auth` stream family. This background subscription consumes those
//! events (consumer group `bff-session-reaper`) and destroys every cached
//! BFF session for the subject - role/consent changes therefore take
//! effect immediately instead of at the session TTL. The stored refresh
//! token dies with the cached session (the record carries only encrypted
//! token blobs; destroying the record revokes their usability).

use std::time::Duration;

use futures_util::StreamExt;

/// Stream family carrying `sentin8:auth:session:revoked`.
const STREAM_FAMILY: &str = "auth";
/// Consumer group for this subscription (cursor persists across restarts).
const CONSUMER_GROUP: &str = "bff-session-reaper";
/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Spawn the background session-reaper: subscribes to the `auth` stream
/// family and kills cached BFF sessions for every
/// `sentin8:auth:session:revoked` subject. Runs until process shutdown;
/// reconnection is handled by the retry loop. A dead Bus or a Valkey
/// outage degrades to the TTL fallback - revocation is never lost, only
/// delayed to the store's idle timeout.
pub fn spawn(bus: sentin8::bus::client::BusClient, store: crate::session::SessionStore) {
    tokio::spawn(async move {
        tracing::info!(
            stream_family = STREAM_FAMILY,
            consumer_group = CONSUMER_GROUP,
            "bff: session-reaper Bus consumer starting"
        );
        loop {
            let resp = match bus.sse_consume(STREAM_FAMILY, CONSUMER_GROUP).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bff: session-reaper sse_consume failed; retrying in 2s"
                    );
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };

            tracing::info!(
                stream_family = STREAM_FAMILY,
                "bff: session-reaper connected"
            );

            let mut buffer = String::new();
            let mut stream = resp.bytes_stream();

            let mut stream_error = false;
            while let Some(chunk_result) = stream.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "bff: session-reaper stream error");
                        stream_error = true;
                        break;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // Process complete SSE events (separated by \n\n).
                while let Some(pos) = buffer.find("\n\n") {
                    let event_text = buffer[..pos].to_string();
                    buffer = buffer[pos + 2..].to_string();

                    let mut data_line = String::new();
                    for line in event_text.lines() {
                        if let Some(d) = line.strip_prefix("data: ") {
                            data_line = d.to_string();
                        }
                        // `id:` lines and `:` comments (heartbeats) are skipped -
                        // ACKs use message_id from the JSON data.
                    }

                    if data_line.is_empty() {
                        continue;
                    }

                    let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let message_id = msg["message_id"].as_str().unwrap_or("").to_string();
                    let event_type = msg["event_type"].as_str().unwrap_or("");

                    if event_type != "sentin8:auth:session:revoked" {
                        // Not ours - ACK to advance the cursor.
                        let _ = bus.ack(STREAM_FAMILY, CONSUMER_GROUP, &message_id).await;
                        continue;
                    }

                    match handle_revocation(&store, &msg["payload"]).await {
                        Ok(n) => {
                            tracing::info!(
                                subject = %msg["payload"]["subject_id"].as_str().unwrap_or(""),
                                killed = n,
                                "bff: session-reaper killed cached sessions"
                            );
                            let _ = bus.ack(STREAM_FAMILY, CONSUMER_GROUP, &message_id).await;
                        }
                        Err(e) => {
                            // Valkey outage - Nack so Bus tracks the retry
                            // (backoff → DLQ); the event is replayed.
                            tracing::warn!(error = %e, "bff: session-reaper kill failed");
                            let _ = bus
                                .nack(STREAM_FAMILY, CONSUMER_GROUP, &message_id, Some(5))
                                .await;
                        }
                    }
                }
            }
            if !stream_error {
                tracing::info!(
                    stream_family = STREAM_FAMILY,
                    "bff: session-reaper stream ended"
                );
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });
}

/// Kill every cached BFF session for the event's subject.
///
/// Payload shape (auth DESIGN §10): `{subject_id, env_id, session_id,
/// revoked_by, reason}`. The BFF store has no subject index, so the scan
/// uses the bounded `list_session_ids` (SCAN, re-wrap batch size) and
/// destroys every record whose `user_id` matches - including the record
/// named by `session_id`, whose id IS the BFF session id when the event
/// carries one.
async fn handle_revocation(
    store: &crate::session::SessionStore,
    payload: &serde_json::Value,
) -> Result<usize, glide::GlideError> {
    let subject_id = payload["subject_id"].as_str().unwrap_or("");
    if subject_id.is_empty() {
        // Malformed event - nothing to kill; treat as success so the
        // cursor advances (the event carries no actionable identity).
        return Ok(0);
    }
    let mut killed = 0usize;
    for id in store.list_session_ids(1000).await? {
        let Some(sess) = store.get(&id).await? else {
            continue;
        };
        if sess.user_id == subject_id {
            store.destroy(&id).await?;
            killed += 1;
        }
    }
    Ok(killed)
}
