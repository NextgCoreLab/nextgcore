//! NSSF Event Definitions
//!
//! Port of src/nssf/event.h and event.c - Event definitions for NSSF

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
#[allow(dead_code)]
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for NSSF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssfEventId {
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

impl NssfEventId {
    pub fn name(&self) -> &'static str {
        match self {
            NssfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            NssfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            NssfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            NssfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            NssfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => NssfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => NssfEventId::FsmExit,
            _ => NssfEventId::SbiServer,
        }
    }
}

/// Timer IDs for NSSF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssfTimerId {
    NfInstanceRegistrationInterval,
    NfInstanceHeartbeatInterval,
    NfInstanceNoHeartbeat,
    NfInstanceValidity,
    SubscriptionValidity,
    SubscriptionPatch,
    SbiClientWait,
}

impl NssfTimerId {
    pub fn name(&self) -> &'static str {
        match self {
            NssfTimerId::NfInstanceRegistrationInterval => "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL",
            NssfTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            NssfTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            NssfTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            NssfTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            NssfTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            NssfTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
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

/// NSSF Event structure
/// Port of nssf_event_t from event.h
#[derive(Debug, Clone)]
pub struct NssfEvent {
    pub id: NssfEventId,
    pub timer_id: Option<NssfTimerId>,
    pub sbi: Option<SbiEventData>,
    /// Home context ID (pool ID)
    pub home_id: Option<u64>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
    /// SBI transaction ID
    pub sbi_xact_id: Option<u64>,
}

impl NssfEvent {
    pub fn new(id: NssfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            home_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn entry() -> Self {
        Self::new(NssfEventId::FsmEntry)
    }

    pub fn exit() -> Self {
        Self::new(NssfEventId::FsmExit)
    }

    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: NssfEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                stream_id: Some(stream_id),
                ..Default::default()
            }),
            home_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: NssfEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                response: Some(response),
                data: Some(data),
                ..Default::default()
            }),
            home_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn sbi_timer(timer_id: NssfTimerId) -> Self {
        Self {
            id: NssfEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            home_id: None,
            nf_instance_id: None,
            subscription_id: None,
            sbi_xact_id: None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    pub fn with_home(mut self, home_id: u64) -> Self {
        self.home_id = Some(home_id);
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

impl Default for NssfEvent {
    fn default() -> Self {
        Self::new(NssfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
#[allow(dead_code)]
pub fn nssf_event_get_name(event: &NssfEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = NssfEvent::new(NssfEventId::SbiServer);
        assert_eq!(event.id, NssfEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = NssfEvent::entry();
        assert_eq!(entry.id, NssfEventId::FsmEntry);

        let exit = NssfEvent::exit();
        assert_eq!(exit.id, NssfEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = NssfEvent::sbi_timer(NssfTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, NssfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(NssfTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = NssfEvent::new(NssfEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_home() {
        let event = NssfEvent::new(NssfEventId::SbiServer).with_home(123);
        assert_eq!(event.home_id, Some(123));
    }

    #[test]
    fn test_event_with_sbi_xact() {
        let event = NssfEvent::new(NssfEventId::SbiClient).with_sbi_xact(456);
        assert_eq!(event.sbi_xact_id, Some(456));
    }
}
