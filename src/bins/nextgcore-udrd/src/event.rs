//! UDR Event Definitions
//!
//! Port of src/udr/event.h and event.c - Event definitions for UDR

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for UDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrEventId {
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

impl UdrEventId {
    /// Get the name of the event
    ///
    /// Port of udr_event_get_name()
    pub fn name(&self) -> &'static str {
        match self {
            UdrEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            UdrEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            UdrEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            UdrEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            UdrEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => UdrEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => UdrEventId::FsmExit,
            _ => UdrEventId::SbiServer,
        }
    }
}

/// Timer IDs for UDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrTimerId {
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

impl UdrTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            UdrTimerId::NfInstanceRegistrationInterval => {
                "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            UdrTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            UdrTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            UdrTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            UdrTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            UdrTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            UdrTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// SBI message data for events
#[derive(Debug, Clone)]
#[derive(Default)]
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
#[derive(Debug, Clone)]
#[derive(Default)]
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


/// UDR Event structure
///
/// Port of udr_event_t
#[derive(Debug, Clone)]
pub struct UdrEvent {
    /// Event ID
    pub id: UdrEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<UdrTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl UdrEvent {
    /// Create a new UDR event
    ///
    /// Port of udr_event_new()
    pub fn new(id: UdrEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(UdrEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(UdrEventId::FsmExit)
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: UdrEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
                state: None,
            }),
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI client event
    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: UdrEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: None,
                response: Some(response),
                message: None,
                stream_id: None,
                data: Some(data),
                state: None,
            }),
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: UdrTimerId) -> Self {
        Self {
            id: UdrEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Get the event name
    ///
    /// Port of udr_event_get_name()
    pub fn name(&self) -> &'static str {
        self.id.name()
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

impl Default for UdrEvent {
    fn default() -> Self {
        Self::new(UdrEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
///
/// Port of udr_event_get_name()
pub fn udr_event_get_name(event: &UdrEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = UdrEvent::new(UdrEventId::SbiServer);
        assert_eq!(event.id, UdrEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = UdrEvent::entry();
        assert_eq!(entry.id, UdrEventId::FsmEntry);

        let exit = UdrEvent::exit();
        assert_eq!(exit.id, UdrEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = UdrEvent::sbi_timer(UdrTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, UdrEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(UdrTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = UdrEvent::new(UdrEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_nf_instance() {
        let event = UdrEvent::new(UdrEventId::SbiTimer)
            .with_nf_instance("test-nf".to_string());
        assert_eq!(event.nf_instance_id, Some("test-nf".to_string()));
    }

    #[test]
    fn test_sbi_server_event() {
        let request = SbiRequest {
            method: "GET".to_string(),
            uri: "/nudr-dr/v1/subscription-data/imsi-001010000000001".to_string(),
            body: None,
        };
        let event = UdrEvent::sbi_server(456, request);
        assert_eq!(event.id, UdrEventId::SbiServer);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().stream_id, Some(456));
    }

    #[test]
    fn test_sbi_client_event() {
        let response = SbiResponse {
            status: 200,
            body: None,
        };
        let event = UdrEvent::sbi_client(response, 789);
        assert_eq!(event.id, UdrEventId::SbiClient);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().data, Some(789));
    }

    #[test]
    fn test_event_id_from_signal() {
        assert_eq!(UdrEventId::from_signal(OGS_FSM_ENTRY_SIG), UdrEventId::FsmEntry);
        assert_eq!(UdrEventId::from_signal(OGS_FSM_EXIT_SIG), UdrEventId::FsmExit);
        assert_eq!(UdrEventId::from_signal(99), UdrEventId::SbiServer);
    }
}
