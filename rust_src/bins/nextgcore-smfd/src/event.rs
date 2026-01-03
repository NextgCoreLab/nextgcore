//! SMF Event Definitions
//!
//! Port of src/smf/event.h and event.c - Event definitions for SMF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for SMF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmfEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// S5-C (GTPv2-C) message event
    S5cMessage,
    /// S6b (Diameter) message event
    S6bMessage,
    /// Gn (GTPv1-C) message event
    GnMessage,
    /// Gx (Diameter) message event
    GxMessage,
    /// Gy (Diameter) message event
    GyMessage,
    /// N4 (PFCP) message event
    N4Message,
    /// N4 timer event
    N4Timer,
    /// N4 no heartbeat event
    N4NoHeartbeat,
    /// NGAP message event
    NgapMessage,
    /// NGAP timer event
    NgapTimer,
    /// 5GSM message event
    GsmMessage,
    /// 5GSM timer event
    GsmTimer,
    /// Session release event
    SessionRelease,
    /// SBI server event
    SbiServer,
    /// SBI client event
    SbiClient,
    /// SBI timer event
    SbiTimer,
}

impl SmfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            SmfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            SmfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            SmfEventId::S5cMessage => "SMF_EVT_S5C_MESSAGE",
            SmfEventId::S6bMessage => "SMF_EVT_S6B_MESSAGE",
            SmfEventId::GnMessage => "SMF_EVT_GN_MESSAGE",
            SmfEventId::GxMessage => "SMF_EVT_GX_MESSAGE",
            SmfEventId::GyMessage => "SMF_EVT_GY_MESSAGE",
            SmfEventId::N4Message => "SMF_EVT_N4_MESSAGE",
            SmfEventId::N4Timer => "SMF_EVT_N4_TIMER",
            SmfEventId::N4NoHeartbeat => "SMF_EVT_N4_NO_HEARTBEAT",
            SmfEventId::NgapMessage => "SMF_EVT_NGAP_MESSAGE",
            SmfEventId::NgapTimer => "SMF_EVT_NGAP_TIMER",
            SmfEventId::GsmMessage => "SMF_EVT_5GSM_MESSAGE",
            SmfEventId::GsmTimer => "SMF_EVT_5GSM_TIMER",
            SmfEventId::SessionRelease => "SMF_EVT_SESSION_RELEASE",
            SmfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            SmfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            SmfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => SmfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => SmfEventId::FsmExit,
            _ => SmfEventId::SbiServer,
        }
    }
}

/// Timer IDs for SMF
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmfTimerId {
    // SBI timers (from ogs-proto)
    /// NF instance registration interval timer
    NfInstanceRegistrationInterval,
    /// NF instance heartbeat interval timer
    NfInstanceHeartbeatInterval,
    /// NF instance no heartbeat timer
    NfInstanceNoHeartbeat,
    /// NF instance validity timer
    NfInstanceValidity,
    /// Subscription validity timer
    SubscriptionValidity,
    /// Subscription patch timer
    SubscriptionPatch,
    /// SBI client wait timer
    SbiClientWait,

    // SMF-specific timers
    /// PFCP association timer
    PfcpAssociation,
    /// PFCP no heartbeat timer
    PfcpNoHeartbeat,
    /// PFCP no establishment response timer
    PfcpNoEstablishmentResponse,
    /// PFCP no deletion response timer
    PfcpNoDeletionResponse,
}

impl SmfTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            SmfTimerId::NfInstanceRegistrationInterval => {
                "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            SmfTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            SmfTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            SmfTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            SmfTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            SmfTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            SmfTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
            SmfTimerId::PfcpAssociation => "SMF_TIMER_PFCP_ASSOCIATION",
            SmfTimerId::PfcpNoHeartbeat => "SMF_TIMER_PFCP_NO_HEARTBEAT",
            SmfTimerId::PfcpNoEstablishmentResponse => "SMF_TIMER_PFCP_NO_ESTABLISHMENT_RESPONSE",
            SmfTimerId::PfcpNoDeletionResponse => "SMF_TIMER_PFCP_NO_DELETION_RESPONSE",
        }
    }

    /// Check if this is a PFCP timer
    pub fn is_pfcp_timer(&self) -> bool {
        matches!(
            self,
            SmfTimerId::PfcpAssociation
                | SmfTimerId::PfcpNoHeartbeat
                | SmfTimerId::PfcpNoEstablishmentResponse
                | SmfTimerId::PfcpNoDeletionResponse
        )
    }
}

/// SBI message data for events
#[derive(Debug, Clone, Default)]
pub struct SbiEventData {
    /// Request data (if any)
    pub request: Option<SbiRequest>,
    /// Response data (if any)
    pub response: Option<SbiResponse>,
    /// Message data (if any)
    pub message: Option<SbiMessage>,
    /// Stream ID
    pub stream_id: Option<u64>,
    /// Generic data pointer (for xact, nf_instance, etc.)
    pub data: Option<u64>,
    /// State for multi-step operations
    pub state: Option<i32>,
}

/// Simplified SBI request representation
#[derive(Debug, Clone)]
pub struct SbiRequest {
    /// HTTP method
    pub method: String,
    /// URI
    pub uri: String,
    /// Body content
    pub body: Option<String>,
}

/// Simplified SBI response representation
#[derive(Debug, Clone)]
pub struct SbiResponse {
    /// HTTP status code
    pub status: u16,
    /// Body content
    pub body: Option<String>,
}

/// Simplified SBI message representation
#[derive(Debug, Clone, Default)]
pub struct SbiMessage {
    /// Service name
    pub service_name: String,
    /// API version
    pub api_version: String,
    /// Resource components
    pub resource_components: Vec<String>,
    /// HTTP method
    pub method: String,
    /// Response status (for client responses)
    pub res_status: Option<u16>,
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
    /// PFCP node
    pub pfcp_node_id: Option<u64>,
    /// PFCP transaction ID
    pub pfcp_xact_id: Option<u64>,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// Diameter message data
#[derive(Debug, Clone, Default)]
pub struct DiameterEventData {
    /// Command code
    pub cmd_code: u32,
    /// CC request type (for credit control)
    pub cc_request_type: Option<u32>,
    /// Result code
    pub result_code: Option<u32>,
}

/// NGAP event data
#[derive(Debug, Clone, Default)]
pub struct NgapEventData {
    /// Message type
    pub message_type: Option<i32>,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// NAS 5GSM event data
#[derive(Debug, Clone, Default)]
pub struct NasEventData {
    /// Message type
    pub message_type: u8,
    /// Message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// Session release trigger
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionReleaseTrigger {
    /// UE requested release
    UeRequested,
    /// PCF initiated release
    PcfInitiated,
    /// SMF initiated release
    SmfInitiated,
    /// Error indication from 5G-AN
    ErrorIndicationFrom5gAn,
}

/// SMF Event structure
#[derive(Debug, Clone)]
pub struct SmfEvent {
    /// Event ID
    pub id: SmfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<SmfTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// GTP event data
    pub gtp: Option<GtpEventData>,
    /// PFCP event data
    pub pfcp: Option<PfcpEventData>,
    /// Diameter event data (Gx/Gy/S6b)
    pub diameter: Option<DiameterEventData>,
    /// NGAP event data
    pub ngap: Option<NgapEventData>,
    /// NAS event data
    pub nas: Option<NasEventData>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// UE ID (pool ID)
    pub smf_ue_id: Option<u64>,
    /// Session release trigger
    pub release_trigger: Option<SessionReleaseTrigger>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl SmfEvent {
    /// Create a new SMF event
    pub fn new(id: SmfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            gtp: None,
            pfcp: None,
            diameter: None,
            ngap: None,
            nas: None,
            sess_id: None,
            smf_ue_id: None,
            release_trigger: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(SmfEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(SmfEventId::FsmExit)
    }

    /// Create an S5-C message event
    pub fn s5c_message(gnode_id: u64, gtp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SmfEventId::S5cMessage,
            gtp: Some(GtpEventData {
                gnode_id: Some(gnode_id),
                gtp_xact_id: Some(gtp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SmfEventId::S5cMessage)
        }
    }

    /// Create a Gn message event
    pub fn gn_message(gnode_id: u64, gtp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SmfEventId::GnMessage,
            gtp: Some(GtpEventData {
                gnode_id: Some(gnode_id),
                gtp_xact_id: Some(gtp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SmfEventId::GnMessage)
        }
    }

    /// Create a Gx message event
    pub fn gx_message(sess_id: u64, cmd_code: u32, cc_request_type: Option<u32>) -> Self {
        Self {
            id: SmfEventId::GxMessage,
            sess_id: Some(sess_id),
            diameter: Some(DiameterEventData {
                cmd_code,
                cc_request_type,
                result_code: None,
            }),
            ..Self::new(SmfEventId::GxMessage)
        }
    }

    /// Create a Gy message event
    pub fn gy_message(sess_id: u64, cmd_code: u32, cc_request_type: Option<u32>) -> Self {
        Self {
            id: SmfEventId::GyMessage,
            sess_id: Some(sess_id),
            diameter: Some(DiameterEventData {
                cmd_code,
                cc_request_type,
                result_code: None,
            }),
            ..Self::new(SmfEventId::GyMessage)
        }
    }

    /// Create an S6b message event
    pub fn s6b_message(sess_id: u64, cmd_code: u32) -> Self {
        Self {
            id: SmfEventId::S6bMessage,
            sess_id: Some(sess_id),
            diameter: Some(DiameterEventData {
                cmd_code,
                cc_request_type: None,
                result_code: None,
            }),
            ..Self::new(SmfEventId::S6bMessage)
        }
    }

    /// Create an N4 message event
    pub fn n4_message(pfcp_node_id: u64, pfcp_xact_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SmfEventId::N4Message,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: Some(pfcp_xact_id),
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SmfEventId::N4Message)
        }
    }

    /// Create an N4 timer event
    pub fn n4_timer(timer_id: SmfTimerId, sess_id: Option<u64>) -> Self {
        Self {
            id: SmfEventId::N4Timer,
            timer_id: Some(timer_id),
            sess_id,
            ..Self::new(SmfEventId::N4Timer)
        }
    }

    /// Create an N4 no heartbeat event
    pub fn n4_no_heartbeat(pfcp_node_id: u64) -> Self {
        Self {
            id: SmfEventId::N4NoHeartbeat,
            pfcp: Some(PfcpEventData {
                pfcp_node_id: Some(pfcp_node_id),
                pfcp_xact_id: None,
                pkbuf: None,
            }),
            ..Self::new(SmfEventId::N4NoHeartbeat)
        }
    }

    /// Create a 5GSM message event
    pub fn gsm_message(sess_id: u64, message_type: u8, pkbuf: Vec<u8>) -> Self {
        Self {
            id: SmfEventId::GsmMessage,
            sess_id: Some(sess_id),
            nas: Some(NasEventData {
                message_type,
                pkbuf: Some(pkbuf),
            }),
            ..Self::new(SmfEventId::GsmMessage)
        }
    }

    /// Create a session release event
    pub fn session_release(sess_id: u64, trigger: SessionReleaseTrigger) -> Self {
        Self {
            id: SmfEventId::SessionRelease,
            sess_id: Some(sess_id),
            release_trigger: Some(trigger),
            ..Self::new(SmfEventId::SessionRelease)
        }
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: SmfEventId::SbiServer,
            sbi: Some(SbiEventData {
                request: Some(request),
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
                state: None,
            }),
            ..Self::new(SmfEventId::SbiServer)
        }
    }

    /// Create an SBI client event
    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: SmfEventId::SbiClient,
            sbi: Some(SbiEventData {
                request: None,
                response: Some(response),
                message: None,
                stream_id: None,
                data: Some(data),
                state: None,
            }),
            ..Self::new(SmfEventId::SbiClient)
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: SmfTimerId) -> Self {
        Self {
            id: SmfEventId::SbiTimer,
            timer_id: Some(timer_id),
            ..Self::new(SmfEventId::SbiTimer)
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
    pub fn with_smf_ue(mut self, smf_ue_id: u64) -> Self {
        self.smf_ue_id = Some(smf_ue_id);
        self
    }

    /// Set NF instance ID
    pub fn with_nf_instance(mut self, nf_instance_id: String) -> Self {
        self.nf_instance_id = Some(nf_instance_id);
        self
    }

    /// Set subscription ID
    pub fn with_subscription(mut self, subscription_id: String) -> Self {
        self.subscription_id = Some(subscription_id);
        self
    }

    /// Set SBI message
    pub fn with_sbi_message(mut self, message: SbiMessage) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.message = Some(message);
        } else {
            self.sbi = Some(SbiEventData {
                request: None,
                response: None,
                message: Some(message),
                stream_id: None,
                data: None,
                state: None,
            });
        }
        self
    }

    /// Set SBI data
    pub fn with_sbi_data(mut self, data: u64) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.data = Some(data);
        } else {
            self.sbi = Some(SbiEventData {
                request: None,
                response: None,
                message: None,
                stream_id: None,
                data: Some(data),
                state: None,
            });
        }
        self
    }

    /// Set SBI state
    pub fn with_sbi_state(mut self, state: i32) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.state = Some(state);
        } else {
            self.sbi = Some(SbiEventData {
                request: None,
                response: None,
                message: None,
                stream_id: None,
                data: None,
                state: Some(state),
            });
        }
        self
    }

    /// Set stream ID
    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        if let Some(ref mut sbi) = self.sbi {
            sbi.stream_id = Some(stream_id);
        } else {
            self.sbi = Some(SbiEventData {
                request: None,
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
                state: None,
            });
        }
        self
    }
}

impl Default for SmfEvent {
    fn default() -> Self {
        Self::new(SmfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn smf_event_get_name(event: &SmfEvent) -> &'static str {
    event.name()
}

/// Get the name of a timer (for logging)
pub fn smf_timer_get_name(timer_id: SmfTimerId) -> &'static str {
    timer_id.name()
}
