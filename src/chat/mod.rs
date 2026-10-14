// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Chat module — WebSocket chat tier.
//!
//! This module implements the **Chat** tier of the three-tier
//! client↔BFF transport model. It handles bidirectional, low-latency
//! conversational exchange between users. One-way push (domain events,
//! notifications, metrics, delegation results) lives on the SSE
//! subscription tier , not here.
//!
//! ## Submodules
//!
//! - `ws` — `GET /ws` WebSocket chat handler
//! - `rooms` — Conversation join/leave + participant filtering
//!
//! Design:

pub mod rooms;
pub mod ws;

// Re-export the WS handler for use in server.rs.
pub use ws::ws_handler;
