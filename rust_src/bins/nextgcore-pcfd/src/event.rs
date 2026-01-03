//! PCF Event Definitions
//!
//! Port of src/pcf/event.h and event.c - Event definitions for PCF

use crate::context::PcfApp;

/// FSM signal types (from ogs-core)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// Event types for PCF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfEventId {
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

impl PcfEventId {
    pub fn name(&self) -> &'static str {
        match self {
            PcfEventId::FsmEntry => "OGS_FSM_ENTRY_SIG",
            PcfEventId::FsmExit => "OGS_FSM_EXIT_SIG",
            PcfEventId::SbiServer => "OGS_EVENT_SBI_SERVER",
            PcfEventId::SbiClient => "OGS_EVENT_SBI_CLIENT",
            PcfEventId::SbiTimer => "OGS_EVENT_SBI_TIMER",
        }
    }

    pub fn from_signal(signal: i32) -> Self {
        match signal {
            OGS_FSM_ENTRY_SIG => PcfEventId::FsmEntry,
            OGS_FSM_EXIT_SIG => PcfEventId::FsmExit,
            _ => PcfEventId::SbiServer,
        }
    }
}

/// Timer IDs for PCF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfTimerId {
    NfInstanceRegistrationInterval,
    NfInstanceHeartbeatInterval,
    NfInstanceNoHeartbeat,
    NfInstanceValidity,
    SubscriptionValidity,
    SubscriptionPatch,
    SbiClientWait,
}

impl PcfTimerId {
    pub fn name(&self) -> &'static str {
        match self {
            PcfTimerId::NfInstanceRegistrationInterval => "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL",
            PcfTimerId::NfInstanceHeartbeatInterval => "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL",
            PcfTimerId::NfInstanceNoHeartbeat => "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            PcfTimerId::NfInstanceValidity => "OGS_TIMER_NF_INSTANCE_VALIDITY",
            PcfTimerId::SubscriptionValidity => "OGS_TIMER_SUBSCRIPTION_VALIDITY",
            PcfTimerId::SubscriptionPatch => "OGS_TIMER_SUBSCRIPTION_PATCH",
            PcfTimerId::SbiClientWait => "OGS_TIMER_SBI_CLIENT_WAIT",
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

/// PCF Event structure
/// Port of pcf_event_t from event.h
#[derive(Debug, Clone)]
pub struct PcfEvent {
    pub id: PcfEventId,
    pub timer_id: Option<PcfTimerId>,
    pub sbi: Option<SbiEventData>,
    /// PCF UE AM ID (pool ID)
    pub pcf_ue_am_id: Option<u64>,
    /// PCF UE SM ID (pool ID)
    pub pcf_ue_sm_id: Option<u64>,
    /// Session ID (pool ID)
    pub sess_id: Option<u64>,
    /// App session (for policy authorization)
    pub app: Option<PcfApp>,
    /// NF instance ID (for NF-related events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription events)
    pub subscription_id: Option<String>,
}

impl PcfEvent {
    pub fn new(id: PcfEventId) -> Self {
        Self {
            id,
            timer_id: None,
            sbi: None,
            pcf_ue_am_id: None,
            pcf_ue_sm_id: None,
            sess_id: None,
            app: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn entry() -> Self {
        Self::new(PcfEventId::FsmEntry)
    }

    pub fn exit() -> Self {
        Self::new(PcfEventId::FsmExit)
    }

    pub fn sbi_server(stream_id: u64, request: SbiRequest) -> Self {
        Self {
            id: PcfEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(request),
                stream_id: Some(stream_id),
                ..Default::default()
            }),
            pcf_ue_am_id: None,
            pcf_ue_sm_id: None,
            sess_id: None,
            app: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn sbi_client(response: SbiResponse, data: u64) -> Self {
        Self {
            id: PcfEventId::SbiClient,
            timer_id: None,
            sbi: Some(SbiEventData {
                response: Some(response),
                data: Some(data),
                ..Default::default()
            }),
            pcf_ue_am_id: None,
            pcf_ue_sm_id: None,
            sess_id: None,
            app: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn sbi_timer(timer_id: PcfTimerId) -> Self {
        Self {
            id: PcfEventId::SbiTimer,
            timer_id: Some(timer_id),
            sbi: None,
            pcf_ue_am_id: None,
            pcf_ue_sm_id: None,
            sess_id: None,
            app: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.id.name()
    }

    pub fn with_pcf_ue_am(mut self, pcf_ue_am_id: u64) -> Self {
        self.pcf_ue_am_id = Some(pcf_ue_am_id);
        self
    }

    pub fn with_sess(mut self, sess_id: u64) -> Self {
        self.sess_id = Some(sess_id);
        self
    }

    pub fn with_app(mut self, app: PcfApp) -> Self {
        self.app = Some(app);
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

impl Default for PcfEvent {
    fn default() -> Self {
        Self::new(PcfEventId::FsmEntry)
    }
}

/// Get the name of an event (for logging)
pub fn pcf_event_get_name(event: &PcfEvent) -> &'static str {
    event.name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = PcfEvent::new(PcfEventId::SbiServer);
        assert_eq!(event.id, PcfEventId::SbiServer);
        assert!(event.timer_id.is_none());
    }

    #[test]
    fn test_entry_exit_events() {
        let entry = PcfEvent::entry();
        assert_eq!(entry.id, PcfEventId::FsmEntry);

        let exit = PcfEvent::exit();
        assert_eq!(exit.id, PcfEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = PcfEvent::sbi_timer(PcfTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, PcfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(PcfTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        let event = PcfEvent::new(PcfEventId::SbiServer);
        assert_eq!(event.name(), "OGS_EVENT_SBI_SERVER");
    }

    #[test]
    fn test_event_with_pcf_ue_am() {
        let event = PcfEvent::new(PcfEventId::SbiServer).with_pcf_ue_am(123);
        assert_eq!(event.pcf_ue_am_id, Some(123));
    }

    #[test]
    fn test_event_with_sess() {
        let event = PcfEvent::new(PcfEventId::SbiServer).with_sess(456);
        assert_eq!(event.sess_id, Some(456));
    }
}
