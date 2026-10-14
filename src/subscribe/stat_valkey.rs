// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Valkey subscriber for stat rollups — replaces the Bus stat.traffic.snapshot path.
//!
//! Subscribes to `stat:rollups:minute` and pushes events to all active
//! SSE sessions that are subscribed to `stat.traffic.snapshot`.

use std::time::Duration;

use super::sse::sub_map;

/// Spawn a background task that subscribes to `stat:rollups:minute` on Valkey
/// and pushes the events to all active SSE sessions subscribed to
/// `sentin8:stat.traffic.snapshot`.
pub fn spawn(valkey_url: String) {
    if valkey_url.is_empty() {
        tracing::info!("bff: stat rollups Valkey subscriber disabled (no VALKEY_URL)");
        return;
    }

    tokio::spawn(async move {
        // GLIDE pubsub: a pubsub-enabled client; connect-time
        // subscriptions survive reconnects (group DESIGN.md §3.1).
        let client = match sentin8::middleware::valkey_client_pubsub(&valkey_url, "sentin8:bff")
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "bff: failed to open Valkey client for stat rollups");
                return;
            }
        };

        loop {
            use glide::PubSubCommands as _;
            if let Err(e) = client.subscribe(&["stat:rollups:minute"]).await {
                tracing::warn!(error = %e, "bff: subscribe to stat:rollups:minute failed");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }

            tracing::info!("bff: subscribed to stat:rollups:minute");

            loop {
                let payload: String = match client.get_pubsub_message().await {
                    Ok(m) => String::from_utf8_lossy(&m.payload).into_owned(),
                    Err(_) => {
                        tracing::warn!(
                            "bff: stat rollups Valkey channel ended; reconnecting in 3s"
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        break;
                    }
                };

                let parsed: serde_json::Value = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "bff: failed to parse stat rollup message");
                        continue;
                    }
                };

                // Build the event that Dash expects: same shape as the old
                // Bus `sentin8:stat.traffic.snapshot` event.
                let event = serde_json::json!({
                    "type": "sentin8:stat:traffic:snapshot",
                    "data": parsed,
                });

                // Push to all active sessions subscribed to sentin8:stat.traffic.snapshot.
                let map = sub_map();
                let guard = map.read().await;
                for state in guard.values() {
                    let subs = state.subscriptions.read().await;
                    if subs.contains("sentin8:stat:traffic:snapshot") {
                        let _ = state.tx.send(event.clone());
                    }
                }
            }
        }
    });
}
