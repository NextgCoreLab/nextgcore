//! HSS Event Definitions
//!
//! Port of src/hss/hss-event.h and hss-event.c - Event definitions for HSS

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for HSS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HssEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// DBI poll timer event
    DbiPollTimer,
    /// DBI message event (change stream notification)
    DbiMessage,
}

impl HssEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            HssEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            HssEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            HssEventId::DbiPollTimer => "HSS_EVENT_DBI_POLL_TIMER",
            HssEventId::DbiMessage => "HSS_EVENT_DBI_MESSAGE",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => HssEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => HssEventId::FsmExit,
            _ => HssEventId::DbiPollTimer, // Default
        }
    }
}

/// Timer IDs for HSS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HssTimerId {
    /// DBI poll change stream timer
    DbiPollChangeStream,
}

impl HssTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            HssTimerId::DbiPollChangeStream => "HSS_TIMER_DBI_POLL_CHANGE_STREAM",
        }
    }
}

/// DBI event data for change stream notifications
#[derive(Debug, Clone)]
pub struct DbiEventData {
    /// BSON document from change stream (serialized)
    pub document: Option<Vec<u8>>,
}

/// HSS Event structure
#[derive(Debug, Clone)]
pub struct HssEvent {
    /// Event ID
    pub id: HssEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<HssTimerId>,
    /// DBI event data
    pub dbi: Option<DbiEventData>,
}

impl HssEvent {
    /// Create a new HSS event
    pub fn new(id: HssEventId) -> Self {
        Self {
            id,
            timer_id: None,
            dbi: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(HssEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(HssEventId::FsmExit)
    }

    /// Create a DBI poll timer event
    pub fn dbi_poll_timer(timer_id: HssTimerId) -> Self {
        Self {
            id: HssEventId::DbiPollTimer,
            timer_id: Some(timer_id),
            dbi: None,
        }
    }

    /// Create a DBI message event
    pub fn dbi_message(document: Vec<u8>) -> Self {
        Self {
            id: HssEventId::DbiMessage,
            timer_id: None,
            dbi: Some(DbiEventData {
                document: Some(document),
            }),
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }
}

impl Default for HssEvent {
    fn default() -> Self {
        Self::new(HssEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn hss_event_get_name(event: &HssEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = HssEvent::new(HssEventId::DbiPollTimer);
        assert_eq!(event.id, HssEventId::DbiPollTimer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = HssEvent::entry();
        assert_eq!(entry.id, HssEventId::FsmEntry);

        let exit = HssEvent::exit();
        assert_eq!(exit.id, HssEventId::FsmExit);
    }

    #[test]
    fn test_dbi_poll_timer_event() {
        let event = HssEvent::dbi_poll_timer(HssTimerId::DbiPollChangeStream);
        assert_eq!(event.id, HssEventId::DbiPollTimer);
        assert_eq!(event.timer_id, Some(HssTimerId::DbiPollChangeStream));
    }

    #[test]
    fn test_dbi_message_event() {
        let doc = vec![1, 2, 3, 4];
        let event = HssEvent::dbi_message(doc.clone());
        assert_eq!(event.id, HssEventId::DbiMessage);
        assert!(event.dbi.is_some());
        assert_eq!(event.dbi.unwrap().document, Some(doc));
    }

    #[test]
    fn test_event_name() {
        let event = HssEvent::new(HssEventId::DbiMessage);
        assert_eq!(event.name(), "HSS_EVENT_DBI_MESSAGE");
    }

    #[test]
    fn test_timer_name() {
        assert_eq!(
            HssTimerId::DbiPollChangeStream.name(),
            "HSS_TIMER_DBI_POLL_CHANGE_STREAM"
        );
    }
}
