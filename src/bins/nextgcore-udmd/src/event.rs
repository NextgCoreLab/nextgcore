//! UDM Event Definitions
//!
//! Port of src/udm/event.h and event.c - Event definitions for UDM
//!
//! ## Why this is smaller than its sibling NFs' `event.rs` (#242)
//!
//! Every other NF in the workspace carries `SbiServer` / `SbiClient` event kinds
//! and the `SbiEventData` / `SbiRequest` / `SbiResponse` / `SbiMessage` payloads
//! that go with them, because their state machines really do serve requests. In
//! `udmd` they were **never produced**: `grep` for `UdmEvent::sbi_server` and
//! `UdmEvent::sbi_client` found only their own definitions and their own unit
//! tests, and the only event `app.rs` ever dispatches is `UdmEvent::sbi_timer`.
//!
//! `udmd` serves Nudm through the live async HTTP dispatcher
//! `app.rs::udm_sbi_route`, which owns its own request parsing and its own
//! responses. So the divergence from the sibling NFs is the accurate description
//! of the daemon, and the previous symmetry was the misleading part — it is what
//! made ~2100 lines of unreachable routing (`udm_sm.rs`'s SBI half, `ue_sm.rs`,
//! `sess_sm.rs`, `nudr_handler.rs`, `sbi_response.rs`) read as a working path.
//!
//! If udmd is ever converted to an event-driven request path, these types come
//! back **with** their producer, which is the order #242 argues for.

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
                "NEXTGCORE_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL"
            }
            UdmTimerId::NfInstanceHeartbeatInterval => {
                "NEXTGCORE_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL"
            }
            UdmTimerId::NfInstanceNoHeartbeat => "NEXTGCORE_TIMER_NF_INSTANCE_NO_HEARTBEAT",
            UdmTimerId::NfInstanceValidity => "NEXTGCORE_TIMER_NF_INSTANCE_VALIDITY",
            UdmTimerId::SubscriptionValidity => "NEXTGCORE_TIMER_SUBSCRIPTION_VALIDITY",
            UdmTimerId::SubscriptionPatch => "NEXTGCORE_TIMER_SUBSCRIPTION_PATCH",
            UdmTimerId::SbiClientWait => "NEXTGCORE_TIMER_SBI_CLIENT_WAIT",
        }
    }
}

/// Event types for UDM.
///
/// These are the only three the daemon produces — see the module doc for why
/// there is no `SbiServer` / `SbiClient` pair here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmEventId {
    /// FSM entry signal
    FsmEntry,
    /// FSM exit signal
    FsmExit,
    /// SBI timer event
    SbiTimer,
}

impl UdmEventId {
    /// Get the name of the event
    pub fn name(&self) -> &'static str {
        match self {
            UdmEventId::FsmEntry => "NEXTGCORE_FSM_ENTRY_SIG",
            UdmEventId::FsmExit => "NEXTGCORE_FSM_EXIT_SIG",
            UdmEventId::SbiTimer => "NEXTGCORE_EVENT_SBI_TIMER",
        }
    }
}

/// UDM Event structure.
///
/// #242 also removed the `udm_ue_id` / `sess_id` fields and their `with_udm_ue` /
/// `with_sess` builders: they existed so the main FSM could tell the per-UE and
/// per-session child FSMs which context an SBI request belonged to, and with
/// those children gone nothing writes them and nothing reads them.
#[derive(Debug, Clone)]
pub struct UdmEvent {
    /// Event ID
    pub id: UdmEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<UdmTimerId>,
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

    /// Create an SBI timer event
    pub fn sbi_timer(timer_id: UdmTimerId) -> Self {
        Self {
            id: UdmEventId::SbiTimer,
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

impl Default for UdmEvent {
    fn default() -> Self {
        Self::new(UdmEventId::FsmEntry)
    }
}

// #242 also removed `udm_event_get_name(&UdmEvent) -> &'static str`, a one-line
// alias for `UdmEvent::name`. Its production callers were the "unknown event"
// error arms of the deleted `ue_sm.rs` / `sess_sm.rs`; the surviving logger
// (`udm_sm::udm_sm_debug`) calls `name()` directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = UdmEvent::new(UdmEventId::SbiTimer);
        assert_eq!(event.id, UdmEventId::SbiTimer);
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
        let event = UdmEvent::sbi_timer(UdmTimerId::SbiClientWait);
        assert_eq!(event.name(), "NEXTGCORE_EVENT_SBI_TIMER");
    }

    #[test]
    fn test_event_with_nf_instance_and_subscription() {
        let event = UdmEvent::sbi_timer(UdmTimerId::NfInstanceValidity)
            .with_nf_instance("nf-1".to_string());
        assert_eq!(event.nf_instance_id.as_deref(), Some("nf-1"));
        assert_eq!(event.subscription_id, None);

        let event = UdmEvent::sbi_timer(UdmTimerId::SubscriptionValidity)
            .with_subscription("sub-1".to_string());
        assert_eq!(event.subscription_id.as_deref(), Some("sub-1"));
        assert_eq!(event.nf_instance_id, None);
    }

    /// **Issue #242.** Every timer id has a distinct name, and every event id has
    /// one — the names are what the daemon logs, so a duplicated one would make
    /// two different expiries indistinguishable in an operator's log.
    #[test]
    fn every_event_and_timer_id_has_a_distinct_name() {
        let event_names: Vec<&str> = [
            UdmEventId::FsmEntry,
            UdmEventId::FsmExit,
            UdmEventId::SbiTimer,
        ]
        .iter()
        .map(|id| id.name())
        .collect();
        let mut unique = event_names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), event_names.len(), "{event_names:?}");

        let timer_names: Vec<&str> = [
            UdmTimerId::NfInstanceRegistrationInterval,
            UdmTimerId::NfInstanceHeartbeatInterval,
            UdmTimerId::NfInstanceNoHeartbeat,
            UdmTimerId::NfInstanceValidity,
            UdmTimerId::SubscriptionValidity,
            UdmTimerId::SubscriptionPatch,
            UdmTimerId::SbiClientWait,
        ]
        .iter()
        .map(|id| id.name())
        .collect();
        let mut unique = timer_names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), timer_names.len(), "{timer_names:?}");
    }
}
