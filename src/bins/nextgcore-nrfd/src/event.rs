//! NRF Event Definitions
//!
//! Port of src/nrf/event.h and event.c - Event definitions for NRF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for NRF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrfEventId {
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

impl NrfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            NrfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            NrfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            NrfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            NrfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            NrfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    /// Convert from i32 signal
    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => NrfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => NrfEventId::FsmExit,
            _ => NrfEventId::SbiServer, // Default to SBI server
        }
    }
}

/// Timer IDs for NRF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrfTimerId {
    /// NF instance no heartbeat timer
    NfInstanceNoHeartbeat,
    /// Subscription validity timer
    SubscriptionValidity,
    /// SBI client wait timer
    SbiClientWait,
}

impl NrfTimerId {
    /// Get the name of the timer
    pub fn name(&self) -> &'static str {
        match self {
            NrfTimerId::NfInstanceNoHeartbeat => "NRF_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            NrfTimerId::SubscriptionValidity => "NRF_TIMER_SUBSCRIPTION_VALIDITY",
            NrfTimerId::SbiClientWait => "NRF_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// SBI message data for events
#[derive(Debug, Clone)]
pub struct SbiEventData {
    /// Request data (if any)
    pub request: Option<SbiRequest>,
    /// Message data (if any)
    pub message: Option<SbiMessage>,
    /// Stream ID
    pub stream_id: Option<u64>,
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
}

/// NRF Event structure
#[derive(Debug, Clone)]
pub struct NrfEvent {
    /// Event ID
    pub id: NrfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<NrfTimerId>,
    /// SBI event data
    pub sbi: Option<SbiEventData>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl NrfEvent {
    /// Create a new NRF event
    pub fn new(id: NrfEventId) -> Self {
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
        Self::new(NrfEventId::FsmEntry)
    }

    /// Create an FSM exit event
    pub fn exit() -> Self {
        Self::new(NrfEventId::FsmExit)
    }

    /// Create an SBI server event
    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: NrfEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                message: None,
                stream_id: Some(stream_id),
            }),
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: NrfTimerId) -> Self {
        Self {
            id: NrfEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    /// Create an SBI timer event for NF instance no heartbeat
    pub fn nf_instance_no_heartbeat(nf_instance_id: String) -> Self {
        Self {
            id: NrfEventId::SbiTimer,
            timer_id: Some(NrfTimerId::NfInstanceNoHeartbeat),
            sbi: None,
            nf_instance_id: Some(nf_instance_id),
            subscription_id: None,
        }
    }

    /// Create an SBI timer event for subscription validity
    pub fn subscription_validity(subscription_id: String) -> Self {
        Self {
            id: NrfEventId::SbiTimer,
            timer_id: Some(NrfTimerId::SubscriptionValidity),
            sbi: None,
            nf_instance_id: None,
            subscription_id: Some(subscription_id),
        }
    }

    /// Get the event name
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
                message: Some(message),
                stream_id: None,
            });
        }
        self
    }
}

impl Default for NrfEvent {
    fn default() -> Self {
        Self::new(NrfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn nrf_event_get_name(event: &NrfEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = NrfEvent::new(NrfEventId::SbiServer);
        assert_eq!(event.id, NrfEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = NrfEvent::entry();
        assert_eq!(entry.id, NrfEventId::FsmEntry);

        let exit = NrfEvent::exit();
        assert_eq!(exit.id, NrfEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = NrfEvent::sbi_timer(NrfTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, NrfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(NrfTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = NrfEvent::new(NrfEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_nf_instance_no_heartbeat() {
        let event = NrfEvent::nf_instance_no_heartbeat("test-nf-id".to_string());
        assert_eq!(event.id, NrfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(NrfTimerId::NfInstanceNoHeartbeat));
        assert_eq!(event.nf_instance_id, Some("test-nf-id".to_string()));
    }

    #[test]
    fn test_subscription_validity() {
        let event = NrfEvent::subscription_validity("sub-123".to_string());
        assert_eq!(event.id, NrfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(NrfTimerId::SubscriptionValidity));
        assert_eq!(event.subscription_id, Some("sub-123".to_string()));
    }
}
