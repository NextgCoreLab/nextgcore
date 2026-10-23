//! PCF Event Definitions
//!
//! Port of src/pcf/event.h and event.c - Event definitions for PCF.
//!
//! The live SBI path is the async `app::pcf_sbi_request_handler`; the C-port
//! FSM receives only its own entry/exit and the timer events of
//! `app::run_event_loop_async`. The SBI server/client events and the per-UE /
//! per-session FSMs they fed were unreachable and re-took the PCF context lock
//! they held (#655), so they were deleted.

/// Event types for PCF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI timer event
    SbiTimer,
}

impl PcfEventId {
    pub fn name(&self) -> &'static str {
        match self {
            PcfEventId::FsmEntry => "NEXTGCORE_FSM_ENTRY_SIG",
            PcfEventId::FsmExit => "NEXTGCORE_FSM_EXIT_SIG",
            PcfEventId::SbiTimer => "NEXTGCORE_EVENT_SBI_TIMER",
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
            PcfTimerId::NfInstanceRegistrationInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            PcfTimerId::NfInstanceHeartbeatInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL"
            }
            PcfTimerId::NfInstanceNoHeartbeat => "NEXTGCORE_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            PcfTimerId::NfInstanceValidity => "NEXTGCORE_TIMER_NF_INSTANCE_VALIDITY",
            PcfTimerId::SubscriptionValidity => "NEXTGCORE_TIMER_SUBSCRIPTION_VALIDITY",
            PcfTimerId::SubscriptionPatch => "NEXTGCORE_TIMER_SUBSCRIPTION_PATCH",
            PcfTimerId::SbiClientWait => "NEXTGCORE_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// PCF Event structure
/// Port of pcf_event_t from event.h
#[derive(Debug, Clone)]
pub struct PcfEvent {
    pub id: PcfEventId,
    pub timer_id: Option<PcfTimerId>,
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

    pub fn sbi_timer(timer_id: PcfTimerId) -> Self {
        Self {
            timer_id: Some(timer_id),
            ..Self::new(PcfEventId::SbiTimer)
        }
    }

    pub fn name(&self) -> &'static str {
        self.id.name()
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
    fn test_entry_exit_events() {
        assert_eq!(PcfEvent::entry().id, PcfEventId::FsmEntry);
        assert_eq!(PcfEvent::exit().id, PcfEventId::FsmExit);
        assert_eq!(PcfEvent::default().id, PcfEventId::FsmEntry);
    }

    #[test]
    fn test_timer_event() {
        let event = PcfEvent::sbi_timer(PcfTimerId::NfInstanceNoHeartbeat)
            .with_nf_instance("nf".to_string())
            .with_subscription("sub".to_string());
        assert_eq!(event.id, PcfEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(PcfTimerId::NfInstanceNoHeartbeat));
        assert_eq!(event.nf_instance_id.as_deref(), Some("nf"));
        assert_eq!(event.subscription_id.as_deref(), Some("sub"));
        assert_eq!(pcf_event_get_name(&event), "NEXTGCORE_EVENT_SBI_TIMER");
    }

    #[test]
    fn test_timer_names() {
        assert_eq!(
            PcfTimerId::SbiClientWait.name(),
            "NEXTGCORE_TIMER_SBI_CLIENT_WAIT"
        );
    }
}
