// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Telemetry SSE fan-out — Tier 2 (Log/Stat `/v1/live`).
//!
//! Log and Stat expose `/v1/live` as SSE endpoints for high-volume
//! telemetry (metric snapshots, graph snapshots, log entries). BFF
//! holds the token server-side, opens upstream SSE connections to
//! Log/Stat, and fans events out to the client's SSE subscription
//! stream (`GET /subscribe`).
//!
//! These are best-effort, high-volume streams that intentionally bypass
//! Bus (routing them through `inbox` would cause DB write
//! amplification and Valkey Stream bloat).
//!
//! Design: (Two-Tier
//! Sourcing Model — Tier 2)

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Spawn a telemetry SSE fan-out task for Log/Stat `/v1/live`.
///
/// This task is only spawned if the client subscribes to telemetry event
/// types (`sentin8:log.metrics.snapshot`, `sentin8:log.graph.snapshot`, `sentin8:stat.metric`,
/// `sentin8:log.entry`). It connects to the upstream SSE endpoint and pushes
/// events to the session's broadcast channel.
///
/// NOTE: In the current implementation, Log/Stat `/v1/live` SSE proxying
/// is future work (10, .12). The BFF design specifies
/// that BFF proxies these as SSE sources, but the Log/Stat servers
/// need to expose `/v1/live` as SSE first. For now, telemetry events are
/// pushed via the Bus consumer (curated alerts) and internal tasks.
pub fn spawn_telemetry_fanout(
    _sentin8_log_url: String,
    _sentin8_stat_url: String,
    _session: crate::subscribe::bus::SessionInfo,
    _subscriptions: Arc<RwLock<std::collections::HashSet<String>>>,
    _tx: tokio::sync::broadcast::Sender<serde_json::Value>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // TODO: When Log/Stat /v1/live SSE endpoints are implemented:
        // 1. Open an SSE connection to Log /v1/live (text/event-stream)
        // using the BFF M2M token (log:live scope).
        // 2. Open an SSE connection to Stat /v1/live (text/event-stream)
        // using the BFF M2M token (stat:live scope).
        // 3. Parse SSE events from each upstream.
        // 4. Push events to the session's broadcast channel.
        // 5. Reconnect on disconnect.
        //
        // For now, this is a no-op — telemetry events arrive via Bus
        // (curated alerts) or internal tasks.
        tracing::info!(
            "bff: telemetry SSE fan-out task started (no-op — Log/Stat /v1/live SSE proxy is future work)"
        );
        std::future::pending::<()>().await;
    })
}
