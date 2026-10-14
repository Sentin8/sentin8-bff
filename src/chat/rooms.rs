// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Chat room management — conversation join/leave + participant filtering.
//!
//! BFF only pushes chat frames for conversations the client has joined.
//! Membership is enforced server-side against the conversation's
//! participant list (owned by the chat back-end service).
//!
//! Design: "Subscription
//! Model (Chat Rooms)"

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Per-connection joined rooms state.
pub type JoinedRooms = Arc<RwLock<HashSet<String>>>;

/// Check if a user is a participant in a conversation.
///
/// In a full implementation, this queries the chat back-end service's
/// participant list. For now, we use a simple "if you joined it, you're
/// in it" model — the client explicitly joins conversations and BFF
/// enforces that only joined conversations receive frames.
pub async fn is_participant(joined: &JoinedRooms, conversation_id: &str) -> bool {
    joined.read().await.contains(conversation_id)
}

/// Join one or more conversations.
pub async fn join_rooms(joined: &JoinedRooms, conversation_ids: &[String]) {
    let mut rooms = joined.write().await;
    for id in conversation_ids {
        rooms.insert(id.clone());
    }
}

/// Leave one or more conversations.
pub async fn leave_rooms(joined: &JoinedRooms, conversation_ids: &[String]) {
    let mut rooms = joined.write().await;
    for id in conversation_ids {
        rooms.remove(id);
    }
}
