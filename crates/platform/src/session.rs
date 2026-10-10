//! The session model shared by every backend.
//!
//! A backend's only job is to translate whatever the OS reports into these
//! events; all usage accounting and enforcement logic in the agent is written
//! against this model and never looks at the platform again.

/// Session lifecycle events emitted by the platform [`crate::SessionMonitor`].
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Every graphical session present when the monitor started. Always sent
    /// first so the agent can reconcile its DB before any `SessionStarted`.
    StartupSnapshot { sessions: Vec<(u32, String)> },
    SessionStarted { uid: u32, session_id: String },
    SessionEnded { uid: u32, session_id: String },
    StateChanged { uid: u32, session_id: String, state: SessionUsageState },
    /// The machine is about to suspend (`true`) or has just resumed (`false`).
    PrepareForSleep { suspend: bool },
}

/// Whether a single session is currently consuming screen time.
///
/// Each field is `None` when the platform could not determine it; the counting
/// rules below then fail closed (no usage counted) rather than guessing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionUsageState {
    pub active: Option<bool>,
    pub locked: Option<bool>,
    pub idle: Option<bool>,
}

pub fn session_counts_usage(state: &SessionUsageState) -> bool {
    state.active == Some(true)
        && state.locked == Some(false)
        && state.idle == Some(false)
}

pub fn uid_counts_usage<'a>(
    states: impl IntoIterator<Item = &'a SessionUsageState>,
) -> bool {
    states.into_iter().any(session_counts_usage)
}

#[cfg(test)]
mod tests {
    use super::{session_counts_usage, uid_counts_usage, SessionUsageState};

    fn state(active: bool, locked: bool, idle: bool) -> SessionUsageState {
        SessionUsageState {
            active: Some(active),
            locked: Some(locked),
            idle: Some(idle),
        }
    }

    #[test]
    fn active_unlocked_non_idle_session_counts() {
        assert!(session_counts_usage(&state(true, false, false)));
    }

    #[test]
    fn active_locked_non_idle_session_does_not_count() {
        assert!(!session_counts_usage(&state(true, true, false)));
    }

    #[test]
    fn inactive_unlocked_non_idle_session_does_not_count() {
        assert!(!session_counts_usage(&state(false, false, false)));
    }

    #[test]
    fn active_unlocked_idle_session_does_not_count() {
        assert!(!session_counts_usage(&state(true, false, true)));
    }

    #[test]
    fn inactive_locked_non_idle_session_does_not_count() {
        assert!(!session_counts_usage(&state(false, true, false)));
    }

    #[test]
    fn locked_idle_session_does_not_count() {
        assert!(!session_counts_usage(&state(true, true, true)));
    }

    #[test]
    fn one_qualifying_session_makes_uid_count() {
        let states = [state(false, false, false), state(true, false, false)];
        assert!(uid_counts_usage(&states));
    }

    #[test]
    fn no_qualifying_sessions_make_uid_not_count() {
        let states = [state(true, true, false), state(false, false, false)];
        assert!(!uid_counts_usage(&states));
    }

    #[test]
    fn multiple_qualifying_sessions_still_make_one_uid_count() {
        let states = [state(true, false, false), state(true, false, false)];
        assert!(uid_counts_usage(&states));
    }

    #[test]
    fn unknown_property_fails_closed() {
        let states = [SessionUsageState {
            active: Some(true),
            locked: None,
            idle: Some(false),
        }];
        assert!(!uid_counts_usage(&states));
    }
}
