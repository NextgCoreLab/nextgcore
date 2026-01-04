//! PCRF Event Definitions
//!
//! Port of src/pcrf/pcrf-event.h and src/pcrf/pcrf-event.c

/// PCRF Event ID enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PcrfEventId {
    /// Base event ID for PCRF
    Base = 0,
    /// Entry event - triggers state machine initialization
    Entry = 1,
    /// Exit event - triggers state machine finalization
    Exit = 2,
    /// SBI server event
    SbiServer = 3,
    /// SBI client event
    SbiClient = 4,
    /// SBI timer event
    SbiTimer = 5,
}

impl PcrfEventId {
    /// Get event name as string
    pub fn name(&self) -> &'static str {
        match self {
            PcrfEventId::Base => "PCRF_EVT_BASE",
            PcrfEventId::Entry => "OGS_FSM_ENTRY_SIG",
            PcrfEventId::Exit => "OGS_FSM_EXIT_SIG",
            PcrfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            PcrfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            PcrfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }
}

impl From<u32> for PcrfEventId {
    fn from(value: u32) -> Self {
        match value {
            0 => PcrfEventId::Base,
            1 => PcrfEventId::Entry,
            2 => PcrfEventId::Exit,
            3 => PcrfEventId::SbiServer,
            4 => PcrfEventId::SbiClient,
            5 => PcrfEventId::SbiTimer,
            _ => PcrfEventId::Base,
        }
    }
}

/// PCRF Event structure
#[derive(Debug, Clone)]
pub struct PcrfEvent {
    /// Event ID
    pub id: PcrfEventId,
    /// Event data (optional)
    pub data: Option<PcrfEventData>,
}

/// PCRF Event data variants
#[derive(Debug, Clone)]
pub enum PcrfEventData {
    /// No data
    None,
    /// Session ID
    SessionId(String),
    /// Timer expiry data
    Timer { timer_id: u32, context: Option<String> },
}

impl PcrfEvent {
    /// Create a new event with the given ID
    pub fn new(id: PcrfEventId) -> Self {
        Self { id, data: None }
    }

    /// Create an entry event
    pub fn entry() -> Self {
        Self::new(PcrfEventId::Entry)
    }

    /// Create an exit event
    pub fn exit() -> Self {
        Self::new(PcrfEventId::Exit)
    }

    /// Create a timer event
    pub fn timer(timer_id: u32, context: Option<String>) -> Self {
        Self {
            id: PcrfEventId::SbiTimer,
            data: Some(PcrfEventData::Timer { timer_id, context }),
        }
    }

    /// Get event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Check if this is an entry event
    pub fn is_entry(&self) -> bool {
        self.id == PcrfEventId::Entry
    }

    /// Check if this is an exit event
    pub fn is_exit(&self) -> bool {
        self.id == PcrfEventId::Exit
    }
}

impl Default for PcrfEvent {
    fn default() -> Self {
        Self::new(PcrfEventId::Base)
    }
}

/// Get event name from event ID
pub fn pcrf_event_get_name(id: PcrfEventId) -> &'static str {
    id.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_name() {
        assert_eq!(PcrfEventId::Base.name(), "PCRF_EVT_BASE");
        assert_eq!(PcrfEventId::Entry.name(), "OGS_FSM_ENTRY_SIG");
        assert_eq!(PcrfEventId::Exit.name(), "OGS_FSM_EXIT_SIG");
    }

    #[test]
    fn test_event_id_from_u32() {
        assert_eq!(PcrfEventId::from(0), PcrfEventId::Base);
        assert_eq!(PcrfEventId::from(1), PcrfEventId::Entry);
        assert_eq!(PcrfEventId::from(2), PcrfEventId::Exit);
        assert_eq!(PcrfEventId::from(999), PcrfEventId::Base); // Unknown maps to Base
    }

    #[test]
    fn test_event_new() {
        let event = PcrfEvent::new(PcrfEventId::Entry);
        assert_eq!(event.id, PcrfEventId::Entry);
        assert!(event.data.is_none());
    }

    #[test]
    fn test_event_entry_exit() {
        let entry = PcrfEvent::entry();
        assert!(entry.is_entry());
        assert!(!entry.is_exit());

        let exit = PcrfEvent::exit();
        assert!(!exit.is_entry());
        assert!(exit.is_exit());
    }

    #[test]
    fn test_event_timer() {
        let event = PcrfEvent::timer(1, Some("test-context".to_string()));
        assert_eq!(event.id, PcrfEventId::SbiTimer);
        match event.data {
            Some(PcrfEventData::Timer { timer_id, context }) => {
                assert_eq!(timer_id, 1);
                assert_eq!(context, Some("test-context".to_string()));
            }
            _ => panic!("Expected Timer data"),
        }
    }

    #[test]
    fn test_event_default() {
        let event = PcrfEvent::default();
        assert_eq!(event.id, PcrfEventId::Base);
    }
}
