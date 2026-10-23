//! AUSF Event Definitions
//!
//! Port of src/ausf/event.h and event.c - Event definitions for AUSF

/// Event types for AUSF.
///
/// The live SBI path is the async `app::ausf_sbi_request_handler`; the
/// C-port FSM receives only its own entry/exit and the timer events of
/// `app::run_event_loop_async` (#654). There are no SBI server/client events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI timer event
    SbiTimer,
}

impl AusfEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            AusfEventId::FsmEntry => "NEXTGCORE_FSM_ENTRY_SIG",
            AusfEventId::FsmExit => "NEXTGCORE_FSM_EXIT_SIG",
            AusfEventId::SbiTimer => "NEXTGCORE_EVENT_SBI_TIMER",
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
                "NEXTGCORE_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            AusfTimerId::NfInstanceHeartbeatInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL"
            }
            AusfTimerId::NfInstanceNoHeartbeat => "NEXTGCORE_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            AusfTimerId::NfInstanceValidity => "NEXTGCORE_TIMER_NF_INSTANCE_VALIDITY",
            AusfTimerId::SubscriptionValidity => "NEXTGCORE_TIMER_SUBSCRIPTION_VALIDITY",
            AusfTimerId::SubscriptionPatch => "NEXTGCORE_TIMER_SUBSCRIPTION_PATCH",
            AusfTimerId::SbiClientWait => "NEXTGCORE_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// AUSF Event structure
#[derive(Debug, Clone)]
pub struct AusfEvent {
    /// Event ID
    pub id: AusfEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<AusfTimerId>,
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

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: AusfTimerId) -> Self {
        Self {
            id: AusfEventId::SbiTimer,
            timer_id: Some(timer_id),
            nf_instance_id: None,
            subscription_id: None,
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
        let event = AusfEvent::new(AusfEventId::SbiTimer);
        assert_eq!(event.id, AusfEventId::SbiTimer);
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
        let event = AusfEvent::sbi_timer(AusfTimerId::SbiClientWait);
        assert_eq!(event.name(), "NEXTGCORE_EVENT_SBI_TIMER");
    }

    #[test]
    fn test_event_with_nf_instance_and_subscription() {
        let event = AusfEvent::sbi_timer(AusfTimerId::SubscriptionValidity)
            .with_nf_instance("nf".to_string())
            .with_subscription("sub".to_string());
        assert_eq!(event.nf_instance_id.as_deref(), Some("nf"));
        assert_eq!(event.subscription_id.as_deref(), Some("sub"));
    }
}
