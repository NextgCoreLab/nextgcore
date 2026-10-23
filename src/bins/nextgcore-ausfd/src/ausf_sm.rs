//! AUSF Main State Machine
//!
//! Port of src/ausf/ausf-sm.c - Main AUSF state machine implementation.
//!
//! Only the NF-level part of the C state machine is ported: entry, exit and
//! the timer events dispatched by `app::run_event_loop_async`. The SBI
//! server/client routing and the per-UE FSM (`ue-sm.c`) are not: the live
//! Nausf_UEAuthentication path is the async `app::ausf_sbi_request_handler`,
//! and the old FSM copy was unreachable and re-took the AUSF context lock it
//! held (#654), so it was deleted.

use crate::event::{AusfEvent, AusfEventId, AusfTimerId};

/// AUSF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// AUSF state machine context
pub struct AusfSmContext {
    /// Current state
    state: AusfState,
}

impl AusfSmContext {
    /// Create a new AUSF state machine context
    pub fn new() -> Self {
        Self {
            state: AusfState::Initial,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("AUSF SM: Initializing");
        self.state = AusfState::Initial;

        // Process initial state - transition to operational
        let mut event = AusfEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("AUSF SM: Finalizing");
        let mut event = AusfEvent::exit();
        self.dispatch(&mut event);
        self.state = AusfState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut AusfEvent) {
        ausf_sm_debug(event);

        match self.state {
            AusfState::Initial => {
                self.handle_initial_state(event);
            }
            AusfState::Operational => {
                self.handle_operational_state(event);
            }
            AusfState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> AusfState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == AusfState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut AusfEvent) {
        // Transition to operational state
        log::info!("AUSF SM: Transitioning from Initial to Operational");
        self.state = AusfState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut AusfEvent) {
        log::debug!("AUSF SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut AusfEvent) {
        match event.id {
            AusfEventId::FsmEntry => {
                log::info!("AUSF entering operational state");
            }

            AusfEventId::FsmExit => {
                log::info!("AUSF exiting operational state");
            }

            AusfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut AusfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            AusfTimerId::NfInstanceRegistrationInterval
            | AusfTimerId::NfInstanceHeartbeatInterval
            | AusfTimerId::NfInstanceNoHeartbeat
            | AusfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                }
            }
            AusfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                }
            }
            AusfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                }
            }
            AusfTimerId::SbiClientWait => {
                // The live Nudm client calls in `app` carry their own request
                // timeouts and answer the AMF themselves; there is no FSM
                // stream to answer here.
                log::error!("Cannot receive SBI message");
            }
        }
    }
}

impl Default for AusfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ausf_sm_debug(event: &AusfEvent) {
    log::trace!("AUSF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ausf_sm_context_new() {
        let ctx = AusfSmContext::new();
        assert_eq!(ctx.state(), AusfState::Initial);
    }

    #[test]
    fn test_ausf_sm_init() {
        let mut ctx = AusfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_dispatch_entry_exit() {
        let mut ctx = AusfSmContext::new();
        ctx.init();

        ctx.dispatch(&mut AusfEvent::entry());
        assert!(ctx.is_operational());
        ctx.dispatch(&mut AusfEvent::exit());
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_fini() {
        let mut ctx = AusfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), AusfState::Final);
    }

    #[test]
    fn test_ausf_sm_every_timer_keeps_it_operational() {
        let mut ctx = AusfSmContext::new();
        ctx.init();

        for timer in [
            AusfTimerId::NfInstanceRegistrationInterval,
            AusfTimerId::NfInstanceHeartbeatInterval,
            AusfTimerId::NfInstanceNoHeartbeat,
            AusfTimerId::NfInstanceValidity,
            AusfTimerId::SubscriptionValidity,
            AusfTimerId::SubscriptionPatch,
            AusfTimerId::SbiClientWait,
        ] {
            let mut event = AusfEvent::sbi_timer(timer)
                .with_nf_instance("test-nf".to_string())
                .with_subscription("test-subscription".to_string());
            ctx.dispatch(&mut event);
            assert!(ctx.is_operational(), "{timer:?}");
        }

        // A timer event without a timer id is logged and ignored.
        ctx.dispatch(&mut AusfEvent::new(AusfEventId::SbiTimer));
        assert!(ctx.is_operational());
    }
}
