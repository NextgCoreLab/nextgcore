//! PCF Main State Machine
//!
//! Port of src/pcf/pcf-sm.c - Main PCF state machine implementation.
//!
//! Only the NF-level part of the C state machine is ported: entry, exit and
//! the timer events dispatched by `app::run_event_loop_async`. The SBI
//! server/client routing and the AM/SM per-UE FSMs (`am-sm.c`, `sm-sm.c`) are
//! not: the live Npcf/Nudr/Nbsf paths are the async handlers in `app`, and the
//! old FSM copy was unreachable and re-took the PCF context lock it held
//! (#655), so it was deleted.

use crate::event::{PcfEvent, PcfEventId, PcfTimerId};

/// PCF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfState {
    Initial,
    Operational,
    Final,
}

/// PCF state machine context
pub struct PcfSmContext {
    state: PcfState,
}

impl PcfSmContext {
    pub fn new() -> Self {
        Self {
            state: PcfState::Initial,
        }
    }

    pub fn init(&mut self) {
        log::debug!("PCF SM: Initializing");
        self.state = PcfState::Initial;
        let mut event = PcfEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("PCF SM: Finalizing");
        let mut event = PcfEvent::exit();
        self.dispatch(&mut event);
        self.state = PcfState::Final;
    }

    pub fn dispatch(&mut self, event: &mut PcfEvent) {
        pcf_sm_debug(event);

        match self.state {
            PcfState::Initial => self.handle_initial_state(event),
            PcfState::Operational => self.handle_operational_state(event),
            PcfState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> PcfState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == PcfState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut PcfEvent) {
        log::info!("PCF SM: Transitioning from Initial to Operational");
        self.state = PcfState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut PcfEvent) {
        log::debug!("PCF SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut PcfEvent) {
        match event.id {
            PcfEventId::FsmEntry => {
                log::info!("PCF entering operational state");
            }
            PcfEventId::FsmExit => {
                log::info!("PCF exiting operational state");
            }
            PcfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut PcfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            PcfTimerId::NfInstanceRegistrationInterval
            | PcfTimerId::NfInstanceHeartbeatInterval
            | PcfTimerId::NfInstanceNoHeartbeat
            | PcfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                }
            }
            PcfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                }
            }
            PcfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                }
            }
            PcfTimerId::SbiClientWait => {
                // The live SBI client calls in `app` / `sbi_path` carry their
                // own request timeouts; there is no FSM stream to answer here.
                log::error!("Cannot receive SBI message");
            }
        }
    }
}

impl Default for PcfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn pcf_sm_debug(event: &PcfEvent) {
    log::trace!("PCF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcf_sm_context_new() {
        let ctx = PcfSmContext::new();
        assert_eq!(ctx.state(), PcfState::Initial);
    }

    #[test]
    fn test_pcf_sm_init() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_dispatch_entry_exit() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        ctx.dispatch(&mut PcfEvent::entry());
        assert!(ctx.is_operational());
        ctx.dispatch(&mut PcfEvent::exit());
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_fini() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), PcfState::Final);
    }

    #[test]
    fn test_pcf_sm_every_timer_keeps_it_operational() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        for timer in [
            PcfTimerId::NfInstanceRegistrationInterval,
            PcfTimerId::NfInstanceHeartbeatInterval,
            PcfTimerId::NfInstanceNoHeartbeat,
            PcfTimerId::NfInstanceValidity,
            PcfTimerId::SubscriptionValidity,
            PcfTimerId::SubscriptionPatch,
            PcfTimerId::SbiClientWait,
        ] {
            let mut event = PcfEvent::sbi_timer(timer)
                .with_nf_instance("test-nf".to_string())
                .with_subscription("test-subscription".to_string());
            ctx.dispatch(&mut event);
            assert!(ctx.is_operational(), "{timer:?}");
        }
        ctx.dispatch(&mut PcfEvent::new(PcfEventId::SbiTimer));
        assert!(ctx.is_operational());
    }
}
