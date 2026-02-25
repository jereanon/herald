//! Hierarchical session model: sessions contain threads, threads contain turns.
//!
//! This module overlays a thread/turn structure on top of orra's flat
//! `Session` (which stores messages as a `Vec<Message>`). Thread state is
//! tracked in `session.metadata["thread"]` and turns are derived by
//! scanning the message history for user→assistant exchanges.

use chrono::{DateTime, Utc};
use orra::message::Role;
use orra::store::Session;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Thread state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of a session thread.
///
/// ```text
///              ┌──────────────────────────┐
///              │         Idle             │
///              └──────────┬───────────────┘
///                         │ user message
///                         ▼
///              ┌──────────────────────────┐
///         ┌────│       Processing         │────┐
///         │    └──────────┬───────────────┘    │
///         │               │                    │ error / cancel
///         │ tool approval │ done               │
///         ▼               ▼                    ▼
/// ┌───────────────┐ ┌────────────┐   ┌──────────────┐
/// │AwaitingApproval│ │ Completed  │   │ Interrupted  │
/// └───────┬───────┘ └────────────┘   └──────────────┘
///         │ approved/denied                    │
///         └────────────────────────────────────┘
///                     → Processing / Idle
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadState {
    /// No active request — waiting for user input.
    Idle,
    /// LLM is processing a response (possibly executing tools).
    Processing,
    /// A tool call requires explicit user approval before continuing.
    AwaitingApproval,
    /// The assistant finished responding; thread is dormant until the
    /// next user message transitions it back to Processing.
    Completed,
    /// Processing was interrupted (error, timeout, or user cancel).
    Interrupted,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self::Idle
    }
}

impl std::fmt::Display for ThreadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Processing => write!(f, "processing"),
            Self::AwaitingApproval => write!(f, "awaiting_approval"),
            Self::Completed => write!(f, "completed"),
            Self::Interrupted => write!(f, "interrupted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Turn — a user→assistant exchange
// ---------------------------------------------------------------------------

/// A single conversational turn: one user message and the assistant's full
/// response (including any intermediate tool-call/tool-result messages).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Turn {
    /// Zero-based turn index within the session.
    pub index: usize,
    /// Index of the user message in `session.messages`.
    pub user_message_idx: usize,
    /// Index range of the assistant response messages (inclusive).
    /// Covers the assistant reply plus any tool_call/tool_result pairs.
    pub response_start_idx: Option<usize>,
    pub response_end_idx: Option<usize>,
    /// Timestamp of the user message.
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ThreadInfo — metadata stored in session.metadata["thread"]
// ---------------------------------------------------------------------------

/// Thread metadata persisted in `session.metadata["thread"]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Current state of the thread.
    pub state: ThreadState,
    /// Number of completed turns.
    pub turn_count: usize,
    /// Timestamp when the thread entered its current state.
    pub state_changed_at: DateTime<Utc>,
    /// Optional checkpoint: message index to which the session can be
    /// rolled back (undo). `None` if no checkpoint has been set.
    pub checkpoint_idx: Option<usize>,
}

impl Default for ThreadInfo {
    fn default() -> Self {
        Self {
            state: ThreadState::Idle,
            turn_count: 0,
            state_changed_at: Utc::now(),
            checkpoint_idx: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reading thread/turn info from a session
// ---------------------------------------------------------------------------

/// Extract the thread info from a session's metadata.
/// Returns the default (Idle, 0 turns) if no thread info is stored.
pub fn thread_info(session: &Session) -> ThreadInfo {
    session
        .metadata
        .get("thread")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Persist thread info into a session's metadata.
pub fn set_thread_info(session: &mut Session, info: &ThreadInfo) {
    if let Ok(val) = serde_json::to_value(info) {
        session.metadata.insert("thread".into(), val);
    }
}

/// Parse the flat message history into turns.
///
/// A turn starts with a `User` message and includes all subsequent
/// messages until the next `User` message (or end of history). System
/// messages at the start are skipped.
pub fn parse_turns(session: &Session) -> Vec<Turn> {
    let msgs = &session.messages;
    let mut turns = Vec::new();
    let mut turn_index: usize = 0;

    let mut i = 0;
    // Skip leading system messages
    while i < msgs.len() && msgs[i].role == Role::System {
        i += 1;
    }

    while i < msgs.len() {
        // A real user turn starts with a User message that has actual content.
        // Tool-result messages have Role::User but empty content — they are
        // internal protocol messages and belong to the preceding turn's response.
        let is_human_turn = msgs[i].role == Role::User && !msgs[i].content.is_empty();
        if !is_human_turn {
            i += 1;
            continue;
        }

        let user_idx = i;
        let timestamp = msgs[i].timestamp;
        i += 1;

        // Collect all response messages until the next real user message.
        // Tool-result (User-role) messages are part of the response, not new turns.
        let response_start = if i < msgs.len()
            && !(msgs[i].role == Role::User && !msgs[i].content.is_empty())
        {
            Some(i)
        } else {
            None
        };
        let mut response_end = response_start;

        while i < msgs.len()
            && !(msgs[i].role == Role::User && !msgs[i].content.is_empty())
        {
            response_end = Some(i);
            i += 1;
        }

        turns.push(Turn {
            index: turn_index,
            user_message_idx: user_idx,
            response_start_idx: response_start,
            response_end_idx: response_end,
            timestamp,
        });
        turn_index += 1;
    }

    turns
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

/// Transition the thread to a new state, updating metadata.
pub fn transition(session: &mut Session, new_state: ThreadState) {
    let mut info = thread_info(session);
    info.state = new_state;
    info.state_changed_at = Utc::now();
    set_thread_info(session, &info);
}

/// Mark the current message index as a checkpoint for undo.
pub fn set_checkpoint(session: &mut Session) {
    let mut info = thread_info(session);
    info.checkpoint_idx = Some(session.messages.len());
    set_thread_info(session, &info);
}

/// Undo to the last checkpoint by truncating messages.
/// Returns `true` if undo was performed, `false` if no checkpoint exists.
pub fn undo_to_checkpoint(session: &mut Session) -> bool {
    let info = thread_info(session);
    if let Some(idx) = info.checkpoint_idx {
        if idx < session.messages.len() {
            session.messages.truncate(idx);
            let mut new_info = thread_info(session);
            new_info.checkpoint_idx = None;
            new_info.state = ThreadState::Idle;
            new_info.state_changed_at = Utc::now();
            new_info.turn_count = parse_turns(session).len();
            set_thread_info(session, &new_info);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Session view — combines session + thread data for API responses
// ---------------------------------------------------------------------------

/// A rich view of a session including thread state and parsed turns.
#[derive(Debug, Serialize)]
pub struct SessionView {
    pub namespace: String,
    pub thread: ThreadInfo,
    pub turns: Vec<Turn>,
    pub message_count: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionView {
    pub fn from_session(session: &Session) -> Self {
        let turns = parse_turns(session);
        let info = thread_info(session);
        Self {
            namespace: session.namespace.key(),
            thread: info,
            turns,
            message_count: session.messages.len(),
            created_at: session.created_at,
            updated_at: session.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orra::message::Message;
    use orra::namespace::Namespace;

    fn make_session(messages: Vec<Message>) -> Session {
        let mut session = Session::new(Namespace::parse("test:session"));
        for m in messages {
            session.push_message(m);
        }
        session
    }

    #[test]
    fn empty_session_has_no_turns() {
        let session = make_session(vec![]);
        let turns = parse_turns(&session);
        assert!(turns.is_empty());
    }

    #[test]
    fn single_turn() {
        let session = make_session(vec![
            Message::user("Hello"),
            Message::assistant("Hi there!"),
        ]);
        let turns = parse_turns(&session);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].index, 0);
        assert_eq!(turns[0].user_message_idx, 0);
        assert_eq!(turns[0].response_start_idx, Some(1));
        assert_eq!(turns[0].response_end_idx, Some(1));
    }

    #[test]
    fn multiple_turns() {
        let session = make_session(vec![
            Message::user("Hello"),
            Message::assistant("Hi!"),
            Message::user("How are you?"),
            Message::assistant("I'm good!"),
        ]);
        let turns = parse_turns(&session);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[1].user_message_idx, 2);
        assert_eq!(turns[1].response_start_idx, Some(3));
    }

    #[test]
    fn turn_with_tool_calls() {
        let session = make_session(vec![
            Message::user("Search for cats"),
            Message::assistant_with_tool_calls("Let me search...", vec![]),
            Message::tool_result(vec![]),
            Message::assistant("Here are the results"),
        ]);
        let turns = parse_turns(&session);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].response_start_idx, Some(1));
        assert_eq!(turns[0].response_end_idx, Some(3));
    }

    #[test]
    fn skips_leading_system_messages() {
        let session = make_session(vec![
            Message::system("You are helpful"),
            Message::user("Hello"),
            Message::assistant("Hi!"),
        ]);
        let turns = parse_turns(&session);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].user_message_idx, 1);
    }

    #[test]
    fn user_message_without_response() {
        let session = make_session(vec![Message::user("Hello")]);
        let turns = parse_turns(&session);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].response_start_idx, None);
        assert_eq!(turns[0].response_end_idx, None);
    }

    #[test]
    fn thread_info_default() {
        let session = make_session(vec![]);
        let info = thread_info(&session);
        assert_eq!(info.state, ThreadState::Idle);
        assert_eq!(info.turn_count, 0);
        assert!(info.checkpoint_idx.is_none());
    }

    #[test]
    fn thread_state_roundtrip() {
        let mut session = make_session(vec![]);
        let info = ThreadInfo {
            state: ThreadState::Processing,
            turn_count: 3,
            state_changed_at: Utc::now(),
            checkpoint_idx: Some(5),
        };
        set_thread_info(&mut session, &info);

        let loaded = thread_info(&session);
        assert_eq!(loaded.state, ThreadState::Processing);
        assert_eq!(loaded.turn_count, 3);
        assert_eq!(loaded.checkpoint_idx, Some(5));
    }

    #[test]
    fn state_transition() {
        let mut session = make_session(vec![]);
        transition(&mut session, ThreadState::Processing);
        assert_eq!(thread_info(&session).state, ThreadState::Processing);

        transition(&mut session, ThreadState::AwaitingApproval);
        assert_eq!(thread_info(&session).state, ThreadState::AwaitingApproval);

        transition(&mut session, ThreadState::Completed);
        assert_eq!(thread_info(&session).state, ThreadState::Completed);
    }

    #[test]
    fn checkpoint_and_undo() {
        let mut session = make_session(vec![
            Message::user("Hello"),
            Message::assistant("Hi!"),
        ]);
        set_checkpoint(&mut session);

        // Add more messages
        session.push_message(Message::user("Delete everything"));
        session.push_message(Message::assistant("Done!"));
        assert_eq!(session.messages.len(), 4);

        // Undo
        let undone = undo_to_checkpoint(&mut session);
        assert!(undone);
        assert_eq!(session.messages.len(), 2);
        assert_eq!(thread_info(&session).state, ThreadState::Idle);
    }

    #[test]
    fn undo_without_checkpoint_is_noop() {
        let mut session = make_session(vec![
            Message::user("Hello"),
            Message::assistant("Hi!"),
        ]);
        let undone = undo_to_checkpoint(&mut session);
        assert!(!undone);
        assert_eq!(session.messages.len(), 2);
    }

    #[test]
    fn session_view_construction() {
        let mut session = make_session(vec![
            Message::user("Hello"),
            Message::assistant("Hi!"),
            Message::user("Bye"),
            Message::assistant("Goodbye!"),
        ]);
        transition(&mut session, ThreadState::Completed);

        let view = SessionView::from_session(&session);
        assert_eq!(view.turns.len(), 2);
        assert_eq!(view.thread.state, ThreadState::Completed);
        assert_eq!(view.message_count, 4);
    }

    #[test]
    fn thread_state_display() {
        assert_eq!(ThreadState::Idle.to_string(), "idle");
        assert_eq!(ThreadState::Processing.to_string(), "processing");
        assert_eq!(ThreadState::AwaitingApproval.to_string(), "awaiting_approval");
        assert_eq!(ThreadState::Completed.to_string(), "completed");
        assert_eq!(ThreadState::Interrupted.to_string(), "interrupted");
    }
}
