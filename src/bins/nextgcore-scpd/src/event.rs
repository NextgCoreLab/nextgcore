//! SCP Event Definitions
//!
//! The SCP state machine is driven only by FSM lifecycle signals and the timer
//! loop (see [`crate::scp_sm`]); the live forwarding path does not route SBI
//! requests through the machine. The former `SbiServer` / `SbiClient` event
//! kinds and their message payloads (`SbiEventData` / `SbiMessage`) were
//! removed with the handlers that consumed them (scpd-#102). What remains is
//! the event vocabulary `main.rs` and `scp_sm` actually exercise.

/// Event types for SCP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI timer event
    SbiTimer,
}

impl ScpEventId {
    pub fn name(&self) -> &'static str {
        match self {
            ScpEventId::FsmEntry => "NEXTGCORE_FSM_ENTRY_SIG",
            ScpEventId::FsmExit => "NEXTGCORE_FSM_EXIT_SIG",
            ScpEventId::SbiTimer => "NEXTGCORE_EVENT_SBI_TIMER",
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
            ScpTimerId::NfInstanceRegistrationInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            ScpTimerId::NfInstanceHeartbeatInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL"
            }
            ScpTimerId::NfInstanceNoHeartbeat => "NEXTGCORE_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            ScpTimerId::NfInstanceValidity => "NEXTGCORE_TIMER_NF_INSTANCE_VALIDITY",
            ScpTimerId::SubscriptionValidity => "NEXTGCORE_TIMER_SUBSCRIPTION_VALIDITY",
            ScpTimerId::SubscriptionPatch => "NEXTGCORE_TIMER_SUBSCRIPTION_PATCH",
            ScpTimerId::SbiClientWait => "NEXTGCORE_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// SCP Event structure
#[derive(Debug, Clone)]
pub struct ScpEvent {
    pub id: ScpEventId,
    pub timer_id: Option<ScpTimerId>,
    /// NF instance ID (for NF-related timer events)
    pub nf_instance_id: Option<String>,
    /// Subscription data ID (for subscription timer events)
    pub subscription_id: Option<String>,
}

impl ScpEvent {
    pub fn new(id: ScpEventId) -> Self {
        Self {
            id,
            timer_id: None,
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    pub fn entry() -> Self {
        Self::new(ScpEventId::FsmEntry)
    }

    pub fn exit() -> Self {
        Self::new(ScpEventId::FsmExit)
    }

    pub fn sbi_timer(timer_id: ScpTimerId) -> Self {
        Self {
            id: ScpEventId::SbiTimer,
            timer_id: Some(timer_id),
            nf_instance_id: None,
            subscription_id: None,
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

impl Default for ScpEvent {
    fn default() -> Self {
        Self::new(ScpEventId::FsmEntry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_exit_events() {
        assert_eq!(ScpEvent::entry().id, ScpEventId::FsmEntry);
        assert_eq!(ScpEvent::exit().id, ScpEventId::FsmExit);
    }

    #[test]
    fn test_timer_event() {
        let event = ScpEvent::sbi_timer(ScpTimerId::NfInstanceNoHeartbeat);
        assert_eq!(event.id, ScpEventId::SbiTimer);
        assert_eq!(event.timer_id, Some(ScpTimerId::NfInstanceNoHeartbeat));
    }

    #[test]
    fn test_event_name() {
        assert_eq!(
            ScpEvent::sbi_timer(ScpTimerId::SbiClientWait).name(),
            "NEXTGCORE_EVENT_SBI_TIMER"
        );
    }

    #[test]
    fn test_event_with_nf_instance() {
        let event = ScpEvent::sbi_timer(ScpTimerId::NfInstanceValidity)
            .with_nf_instance("nf-42".to_string());
        assert_eq!(event.nf_instance_id.as_deref(), Some("nf-42"));
    }

    #[test]
    fn test_event_with_subscription() {
        let event = ScpEvent::sbi_timer(ScpTimerId::SubscriptionValidity)
            .with_subscription("sub-1".to_string());
        assert_eq!(event.subscription_id.as_deref(), Some("sub-1"));
    }
}
