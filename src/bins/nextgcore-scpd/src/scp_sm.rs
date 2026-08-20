//! SCP Main State Machine
//!
//! The live SCP forwarding path runs inline in [`crate::proxy::ScpProxy`]; the
//! state machine is driven only by the timer loop in `main.rs`. The former
//! `SbiServer` / `SbiClient` event handlers (nnrf-nfm / nnrf-disc dispatch)
//! were compiled but never reached — no code ever dispatched a `SbiServer` or
//! `SbiClient` event into the machine — so they were removed (scpd-#102). What
//! remains is the FSM lifecycle and the timer handling that `main.rs` actually
//! exercises.

use crate::event::{ScpEvent, ScpEventId, ScpTimerId};
use crate::sbi_response::send_gateway_timeout_response;

/// SCP state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpState {
    Initial,
    Operational,
    Final,
}

/// SCP state machine context
pub struct ScpSmContext {
    state: ScpState,
}

impl ScpSmContext {
    pub fn new() -> Self {
        Self {
            state: ScpState::Initial,
        }
    }

    pub fn init(&mut self) {
        log::debug!("SCP SM: Initializing");
        self.state = ScpState::Initial;
        let mut event = ScpEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("SCP SM: Finalizing");
        let mut event = ScpEvent::exit();
        self.dispatch(&mut event);
        self.state = ScpState::Final;
    }

    pub fn dispatch(&mut self, event: &mut ScpEvent) {
        scp_sm_debug(event);

        match self.state {
            ScpState::Initial => self.handle_initial_state(event),
            ScpState::Operational => self.handle_operational_state(event),
            ScpState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> ScpState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == ScpState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut ScpEvent) {
        log::info!("SCP SM: Transitioning from Initial to Operational");
        self.state = ScpState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut ScpEvent) {
        log::debug!("SCP SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut ScpEvent) {
        match event.id {
            ScpEventId::FsmEntry => {
                log::info!("SCP entering operational state");
            }
            ScpEventId::FsmExit => {
                log::info!("SCP exiting operational state");
            }
            ScpEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut ScpEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            ScpTimerId::NfInstanceRegistrationInterval
            | ScpTimerId::NfInstanceHeartbeatInterval
            | ScpTimerId::NfInstanceNoHeartbeat
            | ScpTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                }
            }
            ScpTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                }
            }
            ScpTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                }
            }
            ScpTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }
}

impl Default for ScpSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn scp_sm_debug(event: &ScpEvent) {
    log::trace!("SCP SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_sm_context_new() {
        let ctx = ScpSmContext::new();
        assert_eq!(ctx.state(), ScpState::Initial);
    }

    #[test]
    fn test_scp_sm_init() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_scp_sm_dispatch_timer() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        let mut event = ScpEvent::sbi_timer(ScpTimerId::NfInstanceHeartbeatInterval)
            .with_nf_instance("nf-1".to_string());
        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_scp_sm_fini() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), ScpState::Final);
    }
}
