//! SGWC Event Definitions
//!
//! Port of src/sgwc/event.h and event.c - Event definitions for SGWC

/// Event types for SGWC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgwcEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// S11 (GTPv2-C from MME) message event
    S11Message,
    /// S5-C (GTPv2-C from PGW) message event
    S5cMessage,
    /// SXA (PFCP) message event
    SxaMessage,
    /// SXA timer event
    SxaTimer,
    /// SXA no heartbeat event
    SxaNoHeartbeat,
}

impl SgwcEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            SgwcEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            SgwcEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            SgwcEventId::S11Message => "SGWC_EVT_S11_MESSAGE",
            SgwcEventId::S5cMessage => "SGWC_EVT_S5C_MESSAGE",
            SgwcEventId::SxaMessage => "SGWC_EVT_SXA_MESSAGE",
            SgwcEventId::SxaTimer => "SGWC_EVT_SXA_TIMER",
            SgwcEventId::SxaNoHeartbeat => "SGWC_EVT_SXA_NO_HEARTBEAT",
        }
    }
}

/// Timer IDs for SGWC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SgwcTimerId {
    /// PFCP association timer
    PfcpAssociation,
    /// PFCP no heartbeat timer
    PfcpNoHeartbeat,
}

impl SgwcTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            SgwcTimerId::PfcpAssociation => "SGWC_TIMER_PFCP_ASSOCIATION",
            SgwcTimerId::PfcpNoHeartbeat => "SGWC_TIMER_PFCP_NO_HEARTBEAT",
        }
    }
}

/// GTP message data
#[derive(Debug, Clone, Default)]
pub struct GtpEventData {
    /// GTP node ID
    pub gnode_id: Option<u64>,
    /// GTP transaction ID
    pub gtp_xact_id: Option<u64>,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// PFCP message data
#[derive(Debug, Clone, Default)]
pub struct PfcpEventData {
    /// PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// PFCP transaction ID
    pub pfcp_xact_id: Option<u64>,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// SGWC Event structure
#[derive(Debug, Clone)]
pub struct SgwcEvent {
    /// Event ID
    pub id: SgwcEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<SgwcTimerId>,
    /// GTP event data (for S11/S5C messages)
    pub gtp: Option<GtpEventData>,
    /// PFCP event data (for SXA messages)
    pub pfcp: Option<PfcpEventData>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// UE ID (pool ID)
    pub sgwc_ue_id: Option<u64>,
}

impl SgwcEvent {
    /// Create a new SGWC event
    pub fn new(id: SgwcEventId) -> Self {
        Self {
            id,
            timer_id: None,
            gtp: None,
            pfcp: None,
            sess_id: None,
            sgwc_ue_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(SgwcEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(SgwcEventId::FsmExit)
    }

    /// Create an S11 message event
    pub fn s11_message(gnode_id: u64, gtp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SgwcEventId::S11Message,
            gtp: Some(GtpEventData {
                gnode_id: Some(gnode_id),
                gtp_xact_id: Some(gtp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SgwcEventId::S11Message)
        }
    }

    /// Create an S5-C message event
    pub fn s5c_message(gnode_id: u64, gtp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SgwcEventId::S5cMessage,
            gtp: Some(GtpEventData {
                gnode_id: Some(gnode_id),
                gtp_xact_id: Some(gtp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SgwcEventId::S5cMessage)
        }
    }

    /// Create an SXA message event
    pub fn sxa_message(pfcp_node_id: u64, pfcp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SgwcEventId::SxaMessage,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: Some(pfcp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SgwcEventId::SxaMessage)
        }
    }

    /// Create an SXA timer event
    pub fn sxa_timer(timer_id: SgwcTimerId, pfcp_node_id: u64) -> Self {
        Self {
            id: SgwcEventId::SxaTimer,
            timer_id: Some(timer_id),
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            ..Self::new(SgwcEventId::SxaTimer)
        }
    }

    /// Create an SXA no heartbeat event
    pub fn sxa_no_heartbeat(pfcp_node_id: u64) -> Self {
        Self {
            id: SgwcEventId::SxaNoHeartbeat,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            ..Self::new(SgwcEventId::SxaNoHeartbeat)
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

    /// Set UE ID
    pub fn with_sgwc_ue(mut self, sgwc_ue_id: u64) -> Self {
        self.sgwc_ue_id = Some(sgwc_ue_id);
        self
    }
}

impl Default for SgwcEvent {
    fn default() -> Self {
        Self::new(SgwcEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn sgwc_event_get_name(event: &SgwcEvent) -> &'static str {
    event.name()
}

/// Get the name of a timer (for logging)
pub fn sgwc_timer_get_name(timer_id: SgwcTimerId) -> &'static str {
    timer_id.name()
}
