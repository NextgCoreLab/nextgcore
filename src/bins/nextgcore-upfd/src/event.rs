//! UPF Event Definitions
//!
//! Port of src/upf/event.h and event.c - Event definitions for UPF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for UPF
/// Port of upf_event_e from event.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpfEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// N4 (PFCP) message event
    N4Message,
    /// N4 timer event
    N4Timer,
    /// N4 no heartbeat event
    N4NoHeartbeat,
}

impl UpfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            UpfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            UpfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            UpfEventId::N4Message => "UPF_EVT_N4_MESSAGE",
            UpfEventId::N4Timer => "UPF_EVT_N4_TIMER",
            UpfEventId::N4NoHeartbeat => "UPF_EVT_N4_NO_HEARTBEAT",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => UpfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => UpfEventId::FsmExit,
            _ => UpfEventId::N4Message,
        }
    }
}

/// Timer IDs for UPF
/// Port of upf_timer_e from timer.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpfTimerId {
    /// PFCP association timer
    Association,
    /// PFCP no heartbeat timer
    NoHeartbeat,
}

impl UpfTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            UpfTimerId::Association => "UPF_TIMER_ASSOCIATION",
            UpfTimerId::NoHeartbeat => "UPF_TIMER_NO_HEARTBEAT",
        }
    }
}

/// PFCP message data for events
#[derive(Debug, Clone, Default)]
pub struct PfcpEventData {
    /// PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// PFCP transaction ID
    pub pfcp_xact_id: Option<u64>,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// UPF Event structure
/// Port of upf_event_t from event.h
#[derive(Debug, Clone)]
pub struct UpfEvent {
    /// Event ID
    pub id: UpfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<UpfTimerId>,
    /// PFCP event data
    pub pfcp: Option<PfcpEventData>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
}

impl UpfEvent {
    /// Create a new UPF event
    pub fn new(id: UpfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            pfcp: None,
            sess_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(UpfEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(UpfEventId::FsmExit)
    }

    /// Create an N4 message event
    pub fn n4_message(pfcp_node_id: u64, pfcp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: UpfEventId::N4Message,
            timer_id: None,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: Some(pfcp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            sess_id: None,
        }
    }

    /// Create an N4 timer event
    pub fn n4_timer(timer_id: UpfTimerId, pfcp_node_id: Option<u64>) -> Self {
        Self {
            id: UpfEventId::N4Timer,
            timer_id: Some(timer_id),
            pfcp: pfcp_node_id.map(|id| PfcpEventData {
                pfcp_node_id: Some(id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            sess_id: None,
        }
    }

    /// Create an N4 no heartbeat event
    pub fn n4_no_heartbeat(pfcp_node_id: u64) -> Self {
        Self {
            id: UpfEventId::N4NoHeartbeat,
            timer_id: None,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            sess_id: None,
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Set session ID
    pub fn with_sess(mut self, sess_id: u64) -> Self {
        self.sess_id = Some(sess_id);
        self
    }
}

impl Default for UpfEvent {
    fn default() -> Self {
        Self::new(UpfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn upf_event_get_name(event: &UpfEvent) -> &'static str {
    event.name()
}

/// Get the name of a timer (for logging)
pub fn upf_timer_get_name(timer_id: UpfTimerId) -> &'static str {
    timer_id.name()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_names() {
        assert_eq!(UpfEventId::FsmEntry.name(), "OGS_FSM_ENTRY_SIG");
        assert_eq!(UpfEventId::FsmExit.name(), "OGS_FSM_EXIT_SIG");
        assert_eq!(UpfEventId::N4Message.name(), "UPF_EVT_N4_MESSAGE");
        assert_eq!(UpfEventId::N4Timer.name(), "UPF_EVT_N4_TIMER");
        assert_eq!(UpfEventId::N4NoHeartbeat.name(), "UPF_EVT_N4_NO_HEARTBEAT");
    }

    #[test]
    fn test_timer_id_names() {
        assert_eq!(UpfTimerId::Association.name(), "UPF_TIMER_ASSOCIATION");
        assert_eq!(UpfTimerId::NoHeartbeat.name(), "UPF_TIMER_NO_HEARTBEAT");
    }

    #[test]
    fn test_event_creation() {
        let entry = UpfEvent::entry();
        assert_eq!(entry.id, UpfEventId::FsmEntry);

        let exit = UpfEvent::exit();
        assert_eq!(exit.id, UpfEventId::FsmExit);

        let n4_msg = UpfEvent::n4_message(1, 2, vec![0x01, 0x02]);
        assert_eq!(n4_msg.id, UpfEventId::N4Message);
        assert!(n4_msg.pfcp.is_some());
        let pfcp = n4_msg.pfcp.unwrap();
        assert_eq!(pfcp.pfcp_node_id, Some(1));
        assert_eq!(pfcp.pfcp_xact_id, Some(2));

        let n4_timer = UpfEvent::n4_timer(UpfTimerId::Association, Some(3));
        assert_eq!(n4_timer.id, UpfEventId::N4Timer);
        assert_eq!(n4_timer.timer_id, Some(UpfTimerId::Association));

        let no_hb = UpfEvent::n4_no_heartbeat(4);
        assert_eq!(no_hb.id, UpfEventId::N4NoHeartbeat);
    }

    #[test]
    fn test_event_with_sess() {
        let event = UpfEvent::n4_message(1, 2, vec![]).with_sess(100);
        assert_eq!(event.sess_id, Some(100));
    }

    #[test]
    fn test_from_signal() {
        assert_eq!(UpfEventId::from_signal(OGS_FSM_ENTRY_SIG), UpfEventId::FsmEntry);
        assert_eq!(UpfEventId::from_signal(OGS_FSM_EXIT_SIG), UpfEventId::FsmExit);
        assert_eq!(UpfEventId::from_signal(99), UpfEventId::N4Message);
    }
}
