//! UDM Event Definitions
//!
//! Port of src/udm/event.h and event.c - Event definitions for UDM

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for UDM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmEventId {
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
}

impl UdmEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            UdmEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            UdmEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            UdmEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            UdmEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            UdmEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => UdmEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => UdmEventId::FsmExit,
            _ => UdmEventId::SbiServer,
        }
    }
}

/// Timer IDs for UDM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmTimerId {
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
}

impl UdmTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            UdmTimerId::NfInstanceRegistrationInterval => {
                "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            UdmTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            UdmTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            UdmTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            UdmTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            UdmTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            UdmTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// SBI message data for events
#[derive(Debug, Clone)]
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

impl Default for SbiEventData {
    fn default() -> Self {
        Self {
            request: None,
            response: None,
            message: None,
            stream_id: None,
            data: None,
            state: None,
        }
    }
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
#[derive(Debug, Clone)]
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
    /// Number of dataset names (for SDM queries)
    pub num_of_dataset_names: usize,
}

impl Default for SbiMessage {
    fn default() -> Self {
        Self {
            service_name: String::new(),
            api_version: String::new(),
            resource_components: Vec::new(),
            method: String::new(),
            res_status: None,
            num_of_dataset_names: 0,
        }
    }
}


/// UDM Event structure
#[derive(Debug, Clone)]
pub struct UdmEvent {
    /// Event ID
    pub id: UdmEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<UdmTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// UDM UE ID (pool ID)
    pub udm_ue_id: Option<u64>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl UdmEvent {
    /// Create a new UDM event
    pub fn new(id: UdmEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            udm_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(UdmEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(UdmEventId::FsmExit)
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: UdmEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
                state: None,
            }),
            udm_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI client event
    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: UdmEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: None,
                response: Some(response),
                message: None,
                stream_id: None,
                data: Some(data),
                state: None,
            }),
            udm_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: UdmTimerId) -> Self {
        Self {
            id: UdmEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            udm_ue_id: None,
            sess_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Set UDM UE ID
    pub fn with_udm_ue(mut self, udm_ue_id: u64) -> Self {
        self.udm_ue_id = Some(udm_ue_id);
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

impl Default for UdmEvent {
    fn default() -> Self {
        Self::new(UdmEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn udm_event_get_name(event: &UdmEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = UdmEvent::new(UdmEventId::SbiServer);
        assert_eq!(event.id, UdmEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = UdmEvent::entry();
        assert_eq!(entry.id, UdmEventId::FsmEntry);

        let exit = UdmEvent::exit();
        assert_eq!(exit.id, UdmEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = UdmEvent::sbi_timer(UdmTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, UdmEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(UdmTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = UdmEvent::new(UdmEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_udm_ue() {
        let event = UdmEvent::new(UdmEventId::SbiServer).with_udm_ue(123);
        assert_eq!(event.udm_ue_id, Some(123));
    }

    #[test]
    fn test_event_with_sess() {
        let event = UdmEvent::new(UdmEventId::SbiServer).with_sess(456);
        assert_eq!(event.sess_id, Some(456));
    }

    #[test]
    fn test_sbi_server_event() {
        let request = SbiRequest {
            method: "POST".to_string(),
            uri: "/nudm-ueau/v1/suci-0-001-01/security-information".to_string(),
            body: None,
        };
        let event = UdmEvent::sbi_server(456, request);
        assert_eq!(event.id, UdmEventId::SbiServer);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().stream_id, Some(456));
    }

    #[test]
    fn test_sbi_client_event() {
        let response = SbiResponse {
            status: 200,
            body: None,
        };
        let event = UdmEvent::sbi_client(response, 789);
        assert_eq!(event.id, UdmEventId::SbiClient);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().data, Some(789));
    }
}
