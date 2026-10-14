// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Subscribe module — SSE subscription tier.
//!
//! This module implements the **Subscriptions** tier of the three-tier
//! client↔BFF transport model:
//!
//! - Queries & Mutations → HTTP/2 (`/proxy/*`)
//! - **Subscriptions → SSE (`GET /subscribe`, `text/event-stream`)**
//! - Chat → WebSocket (`GET /ws`)
//!
//! ## Submodules
//!
//! - `sse` — `GET /subscribe` SSE stream handler
//! - `manager` — `POST /subscribe` / `DELETE /subscribe` lifecycle
//! - `bus` — Tier 1: Bus SSE consumer (domain events)
//! - `telemetry` — Tier 2: Log/Stat `/v1/live` SSE fan-out (future)
//!
//! Design:

pub mod bus;
pub mod delegation;
pub mod manager;
pub mod push;
pub mod session_revocation;
pub mod sse;
pub mod stat_valkey;
pub mod telemetry;

// Re-export key types for use in server.rs and other modules.
pub use delegation::start_delegation_poll;
pub use manager::{
    subscribe_change, subscribe_close, subscribe_push_delete, subscribe_push_register,
};
pub use sse::subscribe_handler;

// ── Convention-driven event validation ────────────────────────────────
//
// The BFF does **not** maintain a static allowlist of event types.
// Any vertical (sentin8, bank8, hotel8, …) can introduce new events without
// registering them here. Validation is **convention-based**:
//
// `{vertical}:{service}.{entity}.{operation}`
//
// Authorisation is enforced by the Bus itself (RBAC scopes + RLS tenant
// isolation), not by the BFF's subscription filter.
//
// Two special families that the BFF manages internally (not Bus-sourced):
//
// `sentin8:delegation.*` — pushed by the BFF delegation polling task
// `sentin8:bff.*` — pushed by the BFF session lifecycle task

/// Known vertical prefixes (used for logging / telemetry, not for
/// validation — unknown verticals are accepted as long as the format
/// is correct). Always includes "sentin8". Additional verticals are
/// loaded from Valkey (`captain:known_verticals` set) at startup by
/// `load_known_verticals`.
pub fn load_known_verticals(valkey_url: &str) -> Vec<String> {
    let mut verticals = vec!["sentin8".to_string()];
    // The sync GLIDE factory (a boot-time, non-async caller site).
    if let Ok(client) = sentin8::middleware::valkey_client_sync(valkey_url, "sentin8:bff") {
        use glide::Commands as _;
        let registered: Vec<String> = client
            .smembers::<_, Vec<String>>("captain:known_verticals")
            .unwrap_or_default();
        verticals.extend(registered);
    }
    verticals
}

/// Event types that the BFF pushes internally (not sourced from Bus).
/// These are handled by dedicated BFF tasks (delegation polling, session
/// lifecycle), not the Bus consumer.
pub const BFF_INTERNAL_TYPES: &[&str] = &[
    "sentin8:delegation:result",
    "sentin8:delegation:expired",
    "sentin8:bff:session:expired",
];

/// Event-type segments that are page-scoped (support `resource_id`
/// filtering). Determined by the entity segment (the part after the
/// service prefix), not the full event type — so any module can add a
/// page-scoped entity without registering it here.
const PAGE_SCOPED_ENTITIES: &[&str] = &["account", "payment", "instruction", "consent", "user"];

/// Check if an event type follows the `{vertical}:{service}:{resource}:{operation}` convention.
///
/// This is a *format* check, not an allowlist — any vertical/service that
/// follows the naming convention is accepted. The Bus itself enforces
/// RBAC scopes and RLS tenant isolation on the server side.
pub fn is_valid_event_type(event_type: &str) -> bool {
    // BFF-internal types are always valid.
    if BFF_INTERNAL_TYPES.contains(&event_type) {
        return true;
    }
    // Convention: `{vertical}:{service}:{resource}:{operation}`
    // At minimum: `vertical:service:resource`
    let parts: Vec<&str> = event_type.split(':').collect();
    parts.len() >= 3 && parts.iter().all(|p| !p.is_empty())
}

/// Check if an event type is page-scoped (supports `resource_id` filtering).
///
/// Page-scoping is derived from the **resource** segment of the event type
/// (e.g. `account` in `bank8:ledger:account:updated`), not from a static
/// allowlist. This lets any vertical add page-scoped entities without
/// registering them here.
pub fn is_page_scoped(event_type: &str) -> bool {
    // BFF-internal types are never page-scoped.
    if BFF_INTERNAL_TYPES.contains(&event_type) {
        return false;
    }
    // Extract the resource segment: `{vertical}:{service}:{resource}:{operation}`
    let parts: Vec<&str> = event_type.split(':').collect();
    if parts.len() < 3 {
        return false;
    }
    PAGE_SCOPED_ENTITIES.contains(&parts[2])
}

/// Map an event type to the Bus stream family.
///
/// The stream family is derived from the `{service}` segment after the
/// vertical prefix (e.g. `bank8:ledger:account:created` → `ledger`).
/// BFF-internal types return a scout that the consumer ignores.
pub fn event_type_to_stream_family(event_type: &str) -> Option<&'static str> {
    // BFF-internal types are not Bus-sourced.
    if BFF_INTERNAL_TYPES.contains(&event_type) {
        return None;
    }
    // Extract `{service}` from `{vertical}:{service}:{resource}:{operation}`
    let parts: Vec<&str> = event_type.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let service = parts[1];
    // Map known service prefixes to stream families. Unknown services
    // fall through and are returned as-is (the Bus will create the stream
    // on first produce).
    match service {
        "ledger" => Some("ledger"),
        "payments" => Some("payments"),
        "fdx" => Some("fdx"),
        "auth" => Some("auth"),
        "log" => Some("log"),
        "stat" => Some("stat"),
        "app" => Some("app"),
        "notification" => Some("notifications"),
        "sys" => Some("sys"),
        "cron" => Some("cron"),
        "db" => Some("db"),
        "func" => Some("func"),
        "storage" => Some("storage"),
        "acme" => Some("acme"),
        "flow" => Some("flow"),
        "distrib" => Some("distrib"),
        "loyalty" => Some("loyalty"),
        "pms" => Some("pms"),
        "pos" => Some("pos"),
        "meta" => Some("meta"),
        "upsell" => Some("upsell"),
        _ => None, // Unknown service — not Bus-sourced (BFF can't route it)
    }
}

/// Check if an event type is Bus-sourced (consumed by the background Bus
/// consumer task) vs. BFF-internal (pushed by BFF tasks).
///
/// An event is Bus-sourced if it follows the convention and its service
/// segment maps to a known Bus stream family.
pub fn is_bus_sourced(event_type: &str) -> bool {
    event_type_to_stream_family(event_type).is_some()
}
