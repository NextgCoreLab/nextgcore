//! SCP Event Definitions
//!
//! Port of src/scp/event.h and event.c - Event definitions for SCP

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
#[allow(dead_code)]
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for SCP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpEventId {
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

impl ScpEventId {
    pub fn name(&self) -> &'static str {
        match self {
            ScpEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            ScpEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            ScpEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            ScpEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            ScpEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => ScpEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => ScpEventId::FsmExit,
            _ => ScpEventId::SbiServer,
        }
    }
}

/// Timer IDs for SCP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpTimerId {
    NfInstanceRegistrationInterval,
    NfInstanceHeartbeatInterval,
    NfInstanceNoHeartbeat,
    NfInstanceValidity,
    SubscriptionValidity,
    SubscriptionPatch,
    SbiClientWait,
}

impl ScpTimerId {
    pub fn name(&self) -> &'static str {
        match self {
            ScpTimerId::NfInstanceRegistrationInterval => "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL",
            ScpTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            ScpTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            ScpTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            ScpTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            ScpTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            ScpTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
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

/// SCP Event structure
/// Port of scp_event_t from event.h
#[derive(Debug, Clone)]
pub struct ScpEvent {
    pub id: ScpEventId,
    pub timer_id: Option<ScpTimerId>,
    pub sbi: Option<SbiEventData>,
    /// Association ID (pool ID)
    pub assoc_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
    /// SBI transaction ID
    pub sbi_xact_id: Option<u64>,
}

impl ScpEvent {
    pub fn new(id: ScpEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn entry() -> Self {
        Self::new(ScpEventId::FsmEntry)
    }

    pub fn exit() -> Self {
        Self::new(ScpEventId::FsmExit)
    }

    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: ScpEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                stream_id: Some(stream_id),
                ..Default::default()
            }),
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: ScpEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                response: Some(response),
                data: Some(data),
                ..Default::default()
            }),
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn sbi_timer(timer_id: ScpTimerId) -> Self {
        Self {
            id: ScpEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            assoc_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.id.name()
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

    pub fn with_sbi_xact(mut self, sbi_xact_id: u64) -> Self {
        self.sbi_xact_id = Some(sbi_xact_id);
        self
    }
}

impl Default for ScpEvent {
    fn default() -> Self {
        Self::new(ScpEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
#[allow(dead_code)]
pub fn scp_event_get_name(event: &ScpEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = ScpEvent::new(ScpEventId::SbiServer);
        assert_eq!(event.id, ScpEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = ScpEvent::entry();
        assert_eq!(entry.id, ScpEventId::FsmEntry);

        let exit = ScpEvent::exit();
        assert_eq!(exit.id, ScpEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = ScpEvent::sbi_timer(ScpTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, ScpEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(ScpTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = ScpEvent::new(ScpEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_assoc() {
        let event = ScpEvent::new(ScpEventId::SbiServer).with_assoc(123);
        assert_eq!(event.assoc_id, Some(123));
    }

    #[test]
    fn test_event_with_sbi_xact() {
        let event = ScpEvent::new(ScpEventId::SbiClient).with_sbi_xact(456);
        assert_eq!(event.sbi_xact_id, Some(456));
    }
}
