//! SEPP Event Definitions
//!
//! Port of src/sepp/event.h and event.c - Event definitions for SEPP

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
#[allow(dead_code)]
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for SEPP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeppEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI server event (incoming request)
    SbiServer,
    /// SBI client event (response from forwarded request)
    SbiClient,
    /// SBI timer event
    SbiTimer,
}

impl SeppEventId {
    pub fn name(&self) -> &'static str {
        match self {
            SeppEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            SeppEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            SeppEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            SeppEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            SeppEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => SeppEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => SeppEventId::FsmExit,
            _ => SeppEventId::SbiServer,
        }
    }
}

/// Timer IDs for SEPP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeppTimerId {
    /// Timer for peer SEPP establishment retry
    PeerEstablish,
    /// NF instance registration interval
    NfInstanceRegistrationInterval,
    /// NF instance heartbeat interval
    NfInstanceHeartbeatInterval,
    /// NF instance no heartbeat
    NfInstanceNoHeartbeat,
    /// NF instance validity
    NfInstanceValidity,
    /// Subscription validity
    SubscriptionValidity,
    /// Subscription patch
    SubscriptionPatch,
    /// SBI client wait
    SbiClientWait,
}

impl SeppTimerId {
    pub fn name(&self) -> &'static str {
        match self {
            SeppTimerId::PeerEstablish => "SEPP_TIMER_PEER_ESTABLISH",
            SeppTimerId::NfInstanceRegistrationInterval => "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL",
            SeppTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            SeppTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            SeppTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            SeppTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            SeppTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            SeppTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// SBI message data for events
#[derive(Debug, Clone, Default)]
pub struct SbiEventData {
    pub request: Option<SbiRequest>,
    pub response: Option<SbiResponse>,
    pub message: Option<SbiMessage>,
    pub stream_id: Option<u64>,
    pub data: Option<u64>,
    pub state: Option<i32>,
}

/// Simplified SBI request representation
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub uri: String,
    pub body: Option<String>,
}

/// Simplified SBI response representation
#[derive(Debug, Clone)]
pub struct SbiResponse {
    pub status: u16,
    pub body: Option<String>,
}

/// Simplified SBI message representation
#[derive(Debug, Clone, Default)]
pub struct SbiMessage {
    pub service_name: String,
    pub api_version: String,
    pub resource_components: Vec<String>,
    pub method: String,
    pub res_status: Option<u16>,
    pub uri: Option<String>,
}

/// SEPP Event structure
/// Port of sepp_event_t from event.h
#[derive(Debug, Clone)]
pub struct SeppEvent {
    pub id: SeppEventId,
    pub timer_id: Option<SeppTimerId>,
    pub sbi: Option<SbiEventData>,
    /// SEPP node ID (for handshake events)
    pub sepp_node_id: Option<u64>,
    /// Association ID (pool ID)
    pub assoc_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl SeppEvent {
    pub fn new(id: SeppEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            sepp_node_id: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn entry() -> Self {
        Self::new(SeppEventId::FsmEntry)
    }

    pub fn exit() -> Self {
        Self::new(SeppEventId::FsmExit)
    }

    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: SeppEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                stream_id: Some(stream_id),
                ..Default::default()
            }),
            sepp_node_id: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: SeppEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                response: Some(response),
                data: Some(data),
                ..Default::default()
            }),
            sepp_node_id: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn sbi_timer(timer_id: SeppTimerId) -> Self {
        Self {
            id: SeppEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            sepp_node_id: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    pub fn with_sepp_node(mut self, node_id: u64) -> Self {
        self.sepp_node_id = Some(node_id);
        self
    }

    pub fn with_assoc(mut self, assoc_id: u64) -> Self {
        self.assoc_id = Some(assoc_id);
        self
    }

    pub fn with_sbi_message(mut self, message: SbiMessage) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.message = Some(message);
        } else {
            self.sbi = Some(SbiEventData {
                message: Some(message),
                ..Default::default()
            });
        }
        self
    }

    pub fn with_sbi_data(mut self, data: u64) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.data = Some(data);
        } else {
            self.sbi = Some(SbiEventData {
                data: Some(data),
                ..Default::default()
            });
        }
        self
    }

    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.stream_id = Some(stream_id);
        } else {
            self.sbi = Some(SbiEventData {
                stream_id: Some(stream_id),
                ..Default::default()
            });
        }
        self
    }

    pub fn with_nf_instance(mut self, nf_instance_id: String) -> Self {
        self.nf_instance_id = Some(nf_instance_id);
        self
    }

    pub fn with_subscription(mut self, subscription_id: String) -> Self {
        self.subscription_id = Some(subscription_id);
        self
    }
}

impl Default for SeppEvent {
    fn default() -> Self {
        Self::new(SeppEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn sepp_event_get_name(event: &SeppEvent) -> &'static str {
    event.name()
}
