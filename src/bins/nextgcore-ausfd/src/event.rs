//! AUSF Event Definitions
//!
//! Port of src/ausf/event.h and event.c - Event definitions for AUSF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for AUSF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfEventId {
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

impl AusfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            AusfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            AusfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            AusfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            AusfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            AusfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => AusfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => AusfEventId::FsmExit,
            _ => AusfEventId::SbiServer,
        }
    }
}

/// Timer IDs for AUSF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfTimerId {
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

impl AusfTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            AusfTimerId::NfInstanceRegistrationInterval => {
                "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            AusfTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            AusfTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            AusfTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            AusfTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            AusfTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            AusfTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
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
}

impl Default for SbiEventData {
    fn default() -> Self {
        Self {
            request: None,
            response: None,
            message: None,
            stream_id: None,
            data: None,
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
}

/// AUSF Event structure
#[derive(Debug, Clone)]
pub struct AusfEvent {
    /// Event ID
    pub id: AusfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<AusfTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// AUSF UE ID (pool ID)
    pub ausf_ue_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl AusfEvent {
    /// Create a new AUSF event
    pub fn new(id: AusfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            ausf_ue_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an FSM entry event
    pub fn entry() -> Self {
        Self::new(AusfEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(AusfEventId::FsmExit)
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: AusfEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                response: None,
                message: None,
                stream_id: Some(stream_id),
                data: None,
            }),
            ausf_ue_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI client event
    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: AusfEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: None,
                response: Some(response),
                message: None,
                stream_id: None,
                data: Some(data),
            }),
            ausf_ue_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: AusfTimerId) -> Self {
        Self {
            id: AusfEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            ausf_ue_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Set AUSF UE ID
    pub fn with_ausf_ue(mut self, ausf_ue_id: u64) -> Self {
        self.ausf_ue_id = Some(ausf_ue_id);
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
            });
        }
        self
    }
}

impl Default for AusfEvent {
    fn default() -> Self {
        Self::new(AusfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn ausf_event_get_name(event: &AusfEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = AusfEvent::new(AusfEventId::SbiServer);
        assert_eq!(event.id, AusfEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = AusfEvent::entry();
        assert_eq!(entry.id, AusfEventId::FsmEntry);

        let exit = AusfEvent::exit();
        assert_eq!(exit.id, AusfEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = AusfEvent::sbi_timer(AusfTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, AusfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(AusfTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = AusfEvent::new(AusfEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_ausf_ue() {
        let event = AusfEvent::new(AusfEventId::SbiServer).with_ausf_ue(123);
        assert_eq!(event.ausf_ue_id, Some(123));
    }

    #[test]
    fn test_sbi_server_event() {
        let request = SbiRequest {
            method: "POST".to_string(),
            uri: "/nausf-auth/v1/ue-authentications".to_string(),
            body: None,
        };
        let event = AusfEvent::sbi_server(456, request);
        assert_eq!(event.id, AusfEventId::SbiServer);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().stream_id, Some(456));
    }

    #[test]
    fn test_sbi_client_event() {
        let response = SbiResponse {
            status: 200,
            body: None,
        };
        let event = AusfEvent::sbi_client(response, 789);
        assert_eq!(event.id, AusfEventId::SbiClient);
        assert!(event.sbi.is_some());
        assert_eq!(event.sbi.as_ref().unwrap().data, Some(789));
    }
}
