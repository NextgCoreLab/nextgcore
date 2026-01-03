//! AMF Event Definitions
//!
//! Port of src/amf/event.h and event.c - Event definitions for AMF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for AMF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmfEventId {
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
    /// NGAP message event
    NgapMessage,
    /// NGAP timer event
    NgapTimer,
    /// 5GMM timer event
    GmmTimer,
}

impl AmfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            AmfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            AmfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            AmfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            AmfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            AmfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
            AmfEventId::NgapMessage => "AMF_EVENT_NGAP_MESSAGE",
            AmfEventId::NgapTimer => "AMF_EVENT_NGAP_TIMER",
            AmfEventId::GmmTimer => "AMF_EVENT_5GMM_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => AmfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => AmfEventId::FsmExit,
            _ => AmfEventId::SbiServer,
        }
    }
}

/// Timer IDs for AMF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmfTimerId {
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

    // AMF-specific timers
    /// NG delayed send timer
    NgDelayedSend,
    /// NG holding timer
    NgHolding,
    /// T3513 timer (Paging)
    T3513,
    /// T3522 timer (Deregistration)
    T3522,
    /// T3550 timer (Registration Accept)
    T3550,
    /// T3555 timer (Configuration Update Command)
    T3555,
    /// T3560 timer (Authentication/Security Mode)
    T3560,
    /// T3570 timer (Identity Request)
    T3570,
    /// Mobile reachable timer
    MobileReachable,
    /// Implicit deregistration timer
    ImplicitDeregistration,
}

impl AmfTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            AmfTimerId::NfInstanceRegistrationInterval => {
                "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            AmfTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            AmfTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            AmfTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            AmfTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            AmfTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            AmfTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
            AmfTimerId::NgDelayedSend => "AMF_TIMER_NG_DELAYED_SEND",
            AmfTimerId::NgHolding => "AMF_TIMER_NG_HOLDING",
            AmfTimerId::T3513 => "AMF_TIMER_T3513",
            AmfTimerId::T3522 => "AMF_TIMER_T3522",
            AmfTimerId::T3550 => "AMF_TIMER_T3550",
            AmfTimerId::T3555 => "AMF_TIMER_T3555",
            AmfTimerId::T3560 => "AMF_TIMER_T3560",
            AmfTimerId::T3570 => "AMF_TIMER_T3570",
            AmfTimerId::MobileReachable => "AMF_TIMER_MOBILE_REACHABLE",
            AmfTimerId::ImplicitDeregistration => "AMF_TIMER_IMPLICIT_DEREGISTRATION",
        }
    }

    /// Check if this is a GMM timer
    pub fn is_gmm_timer(&self) -> bool {
        matches!(
            self,
            AmfTimerId::T3513
                | AmfTimerId::T3522
                | AmfTimerId::T3550
                | AmfTimerId::T3555
                | AmfTimerId::T3560
                | AmfTimerId::T3570
                | AmfTimerId::MobileReachable
                | AmfTimerId::ImplicitDeregistration
        )
    }

    /// Check if this is an NGAP timer
    pub fn is_ngap_timer(&self) -> bool {
        matches!(self, AmfTimerId::NgDelayedSend | AmfTimerId::NgHolding)
    }
}

/// Timer configuration
#[derive(Debug, Clone, Default)]
pub struct AmfTimerCfg {
    /// Timer is configured
    pub have: bool,
    /// Maximum retry count
    pub max_count: i32,
    /// Timer duration (milliseconds)
    pub duration: u64,
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

/// NGAP event data
#[derive(Debug, Clone, Default)]
pub struct NgapEventData {
    /// gNB ID
    pub gnb_id: Option<u64>,
    /// RAN UE ID
    pub ran_ue_id: Option<u64>,
    /// AMF UE ID
    pub amf_ue_id: Option<u64>,
    /// NGAP message buffer
    pub pkbuf: Option<Vec<u8>>,
}

/// AMF Event structure
#[derive(Debug, Clone)]
pub struct AmfEvent {
    /// Event ID
    pub id: AmfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<AmfTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// NGAP event data
    pub ngap: Option<NgapEventData>,
    /// gNB ID (pool ID)
    pub gnb_id: Option<u64>,
    /// RAN UE ID (pool ID)
    pub ran_ue_id: Option<u64>,
    /// AMF UE ID (pool ID)
    pub amf_ue_id: Option<u64>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl AmfEvent {
    /// Create a new AMF event
    pub fn new(id: AmfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            ngap: None,
            gnb_id: None,
            ran_ue_id: None,
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(AmfEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(AmfEventId::FsmExit)
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: AmfEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
                state: None,
            }),
            ngap: None,
            gnb_id: None,
            ran_ue_id: None,
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI client event
    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: AmfEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: None,
                response: Some(response),
                message: None,
                stream_id: None,
                data: Some(data),
                state: None,
            }),
            ngap: None,
            gnb_id: None,
            ran_ue_id: None,
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: AmfTimerId) -> Self {
        Self {
            id: AmfEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            ngap: None,
            gnb_id: None,
            ran_ue_id: None,
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an NGAP message event
    pub fn ngap_message(gnb_id: u64, pkbuf: Vec<u8>) -> Self {
        Self {
            id: AmfEventId::NgapMessage,
            timer_id: None,
            sbi: None,
            ngap: Some(NgapEventData {
                gnb_id: Some(gnb_id),
                ran_ue_id: None,
                amf_ue_id: None,
                pkbuf: Some(pkbuf),
            }),
            gnb_id: Some(gnb_id),
            ran_ue_id: None,
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an NGAP timer event
    pub fn ngap_timer(timer_id: AmfTimerId, ran_ue_id: u64) -> Self {
        Self {
            id: AmfEventId::NgapTimer,
            timer_id: Some(timer_id),
            sbi: None,
            ngap: None,
            gnb_id: None,
            ran_ue_id: Some(ran_ue_id),
            amf_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create a GMM timer event
    pub fn gmm_timer(timer_id: AmfTimerId, amf_ue_id: u64) -> Self {
        Self {
            id: AmfEventId::GmmTimer,
            timer_id: Some(timer_id),
            sbi: None,
            ngap: None,
            gnb_id: None,
            ran_ue_id: None,
            amf_ue_id: Some(amf_ue_id),
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Set gNB ID
    pub fn with_gnb(mut self, gnb_id: u64) -> Self {
        self.gnb_id = Some(gnb_id);
        self
    }

    /// Set RAN UE ID
    pub fn with_ran_ue(mut self, ran_ue_id: u64) -> Self {
        self.ran_ue_id = Some(ran_ue_id);
        self
    }

    /// Set AMF UE ID
    pub fn with_amf_ue(mut self, amf_ue_id: u64) -> Self {
        self.amf_ue_id = Some(amf_ue_id);
        self
    }

    /// Set session ID
    pub fn with_sess(mut self, sess_id: u64) -> Self {
        self.sess_id = Some(sess_id);
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

impl Default for AmfEvent {
    fn default() -> Self {
        Self::new(AmfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn amf_event_get_name(event: &AmfEvent) -> &'static str {
    event.name()
}

/// Get the name of a timer (for logging)
pub fn amf_timer_get_name(timer_id: AmfTimerId) -> &'static str {
    timer_id.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = AmfEvent::new(AmfEventId::SbiServer);
        assert_eq!(event.id, AmfEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = AmfEvent::entry();
        assert_eq!(entry.id, AmfEventId::FsmEntry);

        let exit = AmfEvent::exit();
        assert_eq!(exit.id, AmfEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = AmfEvent::sbi_timer(AmfTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, AmfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(AmfTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_gmm_timer_event() {
        let event = AmfEvent::gmm_timer(AmfTimerId::T3513, 123);
        assert_eq!(event.id, AmfEventId::GmmTimer);
        assert_eq!(event.timer_id, Some(AmfTimerId::T3513));
        assert_eq!(event.amf_ue_id, Some(123));
    }

    #[test]
    fn test_ngap_message_event() {
        let event = AmfEvent::ngap_message(456, vec![1, 2, 3]);
        assert_eq!(event.id, AmfEventId::NgapMessage);
        assert_eq!(event.gnb_id, Some(456));
        assert!(event.ngap.is_some());
    }

    #[test]
    fn test_event_name() {
        let event = AmfEvent::new(AmfEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_timer_is_gmm() {
        assert!(AmfTimerId::T3513.is_gmm_timer());
        assert!(AmfTimerId::T3522.is_gmm_timer());
        assert!(AmfTimerId::MobileReachable.is_gmm_timer());
        assert!(!AmfTimerId::NgHolding.is_gmm_timer());
        assert!(!AmfTimerId::SbiClientWait.is_gmm_timer());
    }

    #[test]
    fn test_timer_is_ngap() {
        assert!(AmfTimerId::NgDelayedSend.is_ngap_timer());
        assert!(AmfTimerId::NgHolding.is_ngap_timer());
        assert!(!AmfTimerId::T3513.is_ngap_timer());
    }

    #[test]
    fn test_event_with_amf_ue() {
        let event = AmfEvent::new(AmfEventId::SbiServer).with_amf_ue(123);
        assert_eq!(event.amf_ue_id, Some(123));
    }

    #[test]
    fn test_event_with_sess() {
        let event = AmfEvent::new(AmfEventId::SbiServer).with_sess(456);
        assert_eq!(event.sess_id, Some(456));
    }

    #[test]
    fn test_sbi_server_event() {
        let request = SbiRequest {
            method: "POST".to_string(),
            uri: "/namf-comm/v1/ue-contexts".to_string(),
            body: None,
        };
        let event = AmfEvent::sbi_server(456, request);
        assert_eq!(event.id, AmfEventId::SbiServer);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().stream_id, Some(456));
    }

    #[test]
    fn test_sbi_client_event() {
        let response = SbiResponse {
            status: 200,
            body: None,
        };
        let event = AmfEvent::sbi_client(response, 789);
        assert_eq!(event.id, AmfEventId::SbiClient);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().data, Some(789));
    }

    #[test]
    fn test_timer_names() {
        assert_eq!(AmfTimerId::T3513.name(), "AMF_TIMER_T3513");
        assert_eq!(AmfTimerId::NgHolding.name(), "AMF_TIMER_NG_HOLDING");
        assert_eq!(
            AmfTimerId::ImplicitDeregistration.name(),
            "AMF_TIMER_IMPLICIT_DEREGISTRATION"
        );
    }
}
