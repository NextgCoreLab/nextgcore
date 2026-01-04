//! SGWU Event Definitions
//!
//! Port of src/sgwu/event.h and event.c - Event definitions for SGWU

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for SGWU
/// Port of sgwu_event_e from event.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgwuEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SXA (PFCP) message event
    SxaMessage,
    /// SXA timer event
    SxaTimer,
    /// SXA no heartbeat event
    SxaNoHeartbeat,
}

impl SgwuEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            SgwuEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            SgwuEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            SgwuEventId::SxaMessage => "SGWU_EVT_SXA_MESSAGE",
            SgwuEventId::SxaTimer => "SGWU_EVT_SXA_TIMER",
            SgwuEventId::SxaNoHeartbeat => "SGWU_EVT_SXA_NO_HEARTBEAT",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => SgwuEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => SgwuEventId::FsmExit,
            _ => SgwuEventId::SxaMessage,
        }
    }
}

/// Timer IDs for SGWU
/// Port of sgwu_timer_e from timer.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SgwuTimerId {
    /// PFCP association timer
    Association,
    /// PFCP no heartbeat timer
    NoHeartbeat,
}

impl SgwuTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            SgwuTimerId::Association => "SGWU_TIMER_ASSOCIATION",
            SgwuTimerId::NoHeartbeat => "SGWU_TIMER_NO_HEARTBEAT",
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

/// SGWU Event structure
/// Port of sgwu_event_t from event.h
#[derive(Debug, Clone)]
pub struct SgwuEvent {
    /// Event ID
    pub id: SgwuEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<SgwuTimerId>,
    /// PFCP event data
    pub pfcp: Option<PfcpEventData>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// Bearer ID (pool ID)
    pub bearer_id: Option<u64>,
}

impl SgwuEvent {
    /// Create a new SGWU event
    pub fn new(id: SgwuEventId) -> Self {
        Self {
            id,
            timer_id: None,
            pfcp: None,
            sess_id: None,
            bearer_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(SgwuEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(SgwuEventId::FsmExit)
    }

    /// Create an SXA message event
    pub fn sxa_message(pfcp_node_id: u64, pfcp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SgwuEventId::SxaMessage,
            timer_id: None,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: Some(pfcp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            sess_id: None,
            bearer_id: None,
        }
    }

    /// Create an SXA timer event
    pub fn sxa_timer(timer_id: SgwuTimerId, pfcp_node_id: Option<u64>) -> Self {
        Self {
            id: SgwuEventId::SxaTimer,
            timer_id: Some(timer_id),
            pfcp: pfcp_node_id.map(|id| PfcpEventData {
                pfcp_node_id: Some(id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            sess_id: None,
            bearer_id: None,
        }
    }

    /// Create an SXA no heartbeat event
    pub fn sxa_no_heartbeat(pfcp_node_id: u64) -> Self {
        Self {
            id: SgwuEventId::SxaNoHeartbeat,
            timer_id: None,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            sess_id: None,
            bearer_id: None,
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

    /// Set bearer ID
    pub fn with_bearer(mut self, bearer_id: u64) -> Self {
        self.bearer_id = Some(bearer_id);
        self
    }
}

impl Default for SgwuEvent {
    fn default() -> Self {
        Self::new(SgwuEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn sgwu_event_get_name(event: &SgwuEvent) -> &'static str {
    event.name()
}

/// Get the name of a timer (for logging)
pub fn sgwu_timer_get_name(timer_id: SgwuTimerId) -> &'static str {
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
        assert_eq!(SgwuEventId::FsmEntry.name(), "OGS_FSM_ENTRY_SIG");
        assert_eq!(SgwuEventId::FsmExit.name(), "OGS_FSM_EXIT_SIG");
        assert_eq!(SgwuEventId::SxaMessage.name(), "SGWU_EVT_SXA_MESSAGE");
        assert_eq!(SgwuEventId::SxaTimer.name(), "SGWU_EVT_SXA_TIMER");
        assert_eq!(SgwuEventId::SxaNoHeartbeat.name(), "SGWU_EVT_SXA_NO_HEARTBEAT");
    }

    #[test]
    fn test_timer_id_names() {
        assert_eq!(SgwuTimerId::Association.name(), "SGWU_TIMER_ASSOCIATION");
        assert_eq!(SgwuTimerId::NoHeartbeat.name(), "SGWU_TIMER_NO_HEARTBEAT");
    }

    #[test]
    fn test_event_creation() {
        let entry = SgwuEvent::entry();
        assert_eq!(entry.id, SgwuEventId::FsmEntry);

        let exit = SgwuEvent::exit();
        assert_eq!(exit.id, SgwuEventId::FsmExit);

        let sxa_msg = SgwuEvent::sxa_message(1, 2, vec![0x01, 0x02]);
        assert_eq!(sxa_msg.id, SgwuEventId::SxaMessage);
        assert!(sxa_msg.pfcp.is_some());
        let pfcp = sxa_msg.pfcp.unwrap();
        assert_eq!(pfcp.pfcp_node_id, Some(1));
        assert_eq!(pfcp.pfcp_xact_id, Some(2));

        let sxa_timer = SgwuEvent::sxa_timer(SgwuTimerId::Association, Some(3));
        assert_eq!(sxa_timer.id, SgwuEventId::SxaTimer);
        assert_eq!(sxa_timer.timer_id, Some(SgwuTimerId::Association));

        let no_hb = SgwuEvent::sxa_no_heartbeat(4);
        assert_eq!(no_hb.id, SgwuEventId::SxaNoHeartbeat);
    }

    #[test]
    fn test_event_with_sess() {
        let event = SgwuEvent::sxa_message(1, 2, vec![]).with_sess(100);
        assert_eq!(event.sess_id, Some(100));
    }

    #[test]
    fn test_event_with_bearer() {
        let event = SgwuEvent::sxa_message(1, 2, vec![]).with_bearer(200);
        assert_eq!(event.bearer_id, Some(200));
    }

    #[test]
    fn test_from_signal() {
        assert_eq!(SgwuEventId::from_signal(OGS_FSM_ENTRY_SIG), SgwuEventId::FsmEntry);
        assert_eq!(SgwuEventId::from_signal(OGS_FSM_EXIT_SIG), SgwuEventId::FsmExit);
        assert_eq!(SgwuEventId::from_signal(99), SgwuEventId::SxaMessage);
    }
}
