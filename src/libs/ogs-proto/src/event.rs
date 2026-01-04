//! Event definitions for the protocol library

/// Event name constants
pub const EVENT_NAME_SBI_SERVER: &str = "OGS_EVENT_NAME_SBI_SERVER";
pub const EVENT_NAME_SBI_CLIENT: &str = "OGS_EVENT_NAME_SBI_CLIENT";
pub const EVENT_NAME_SBI_TIMER: &str = "OGS_EVENT_NAME_SBI_TIMER";

/// FSM signal names
pub const FSM_NAME_INIT_SIG: &str = "OGS_FSM_INIT_SIG";
pub const FSM_NAME_ENTRY_SIG: &str = "OGS_FSM_ENTRY_SIG";
pub const FSM_NAME_EXIT_SIG: &str = "OGS_FSM_EXIT_SIG";

/// Event IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI server event
    SbiServer,
    /// SBI client event
    SbiClient,
    /// SBI timer event
    SbiTimer,
    /// Custom event with ID
    Custom(i32),
}

impl EventId {
    /// Get the numeric value of the event ID
    pub fn as_i32(&self) -> i32 {
        match self {
            EventId::FsmEntry => 0,
            EventId::FsmExit => 1,
            EventId::SbiServer => 2,
            EventId::SbiClient => 3,
            EventId::SbiTimer => 4,
            EventId::Custom(id) => *id,
        }
    }

    /// Create from numeric value
    pub fn from_i32(id: i32) -> Self {
        match id {
            0 => EventId::FsmEntry,
            1 => EventId::FsmExit,
            2 => EventId::SbiServer,
            3 => EventId::SbiClient,
            4 => EventId::SbiTimer,
            _ => EventId::Custom(id),
        }
    }
}

/// SBI event data
#[derive(Debug, Clone, Default)]
pub struct SbiEventData {
    /// Request data (opaque pointer in C)
    pub request: Option<usize>,
    /// Response data (opaque pointer in C)
    pub response: Option<usize>,
    /// Custom data
    pub data: Option<usize>,
    /// State
    pub state: i32,
    /// Message data
    pub message: Option<usize>,
}

/// Event structure
#[derive(Debug, Clone)]
pub struct Event {
    /// Event ID
    pub id: EventId,
    /// Timer ID (for timer events)
    pub timer_id: i32,
    /// SBI event data
    pub sbi: SbiEventData,
}

impl Event {
    /// Create a new event
    pub fn new(id: EventId) -> Self {
        Self {
            id,
            timer_id: 0,
            sbi: SbiEventData::default(),
        }
    }

    /// Create a new event with custom ID
    pub fn with_id(id: i32) -> Self {
        Self {
            id: EventId::from_i32(id),
            timer_id: 0,
            sbi: SbiEventData::default(),
        }
    }

    /// Get the event name
    pub fn get_name(&self) -> &'static str {
        match self.id {
            EventId::FsmEntry => FSM_NAME_ENTRY_SIG,
            EventId::FsmExit => FSM_NAME_EXIT_SIG,
            EventId::SbiServer => EVENT_NAME_SBI_SERVER,
            EventId::SbiClient => EVENT_NAME_SBI_CLIENT,
            EventId::SbiTimer => EVENT_NAME_SBI_TIMER,
            EventId::Custom(_) => "UNKNOWN_EVENT",
        }
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new(EventId::Custom(0))
    }
}

/// Get event name from event reference
pub fn event_get_name(event: Option<&Event>) -> &'static str {
    match event {
        None => FSM_NAME_INIT_SIG,
        Some(e) => e.get_name(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_conversion() {
        assert_eq!(EventId::SbiServer.as_i32(), 2);
        assert_eq!(EventId::from_i32(2), EventId::SbiServer);
    }

    #[test]
    fn test_event_new() {
        let event = Event::new(EventId::SbiClient);
        assert_eq!(event.id, EventId::SbiClient);
        assert_eq!(event.timer_id, 0);
    }

    #[test]
    fn test_event_get_name() {
        let event = Event::new(EventId::SbiServer);
        assert_eq!(event.get_name(), EVENT_NAME_SBI_SERVER);
    }

    #[test]
    fn test_event_get_name_none() {
        assert_eq!(event_get_name(None), FSM_NAME_INIT_SIG);
    }
}
