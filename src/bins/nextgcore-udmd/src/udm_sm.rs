//! UDM lifecycle + timer state machine.
//!
//! Originally a port of `src/udm/udm-sm.c`, which in Open5GS is the daemon's
//! *request* path: an SBI server event arrives, the main FSM routes it by service
//! name, and per-UE / per-session child FSMs serve it.
//!
//! **In this tree that half never existed.** `udmd` serves every Nudm request
//! through the live async HTTP dispatcher `app.rs::udm_sbi_route`, and nothing
//! ever constructed the `UdmEvent::sbi_server` / `UdmEvent::sbi_client` that this
//! module's routing half switched on — so `handle_sbi_server_event`,
//! `handle_nudm_request`, the per-UE (`ue_sm.rs`) and per-session (`sess_sm.rs`)
//! child machines and the `nudr_handler.rs` they called were **structurally
//! unreachable**, while reading as an authoritative Nudm/Nudr request path. Issue
//! #242 removed all of it; see `specs/fix-udmd-delete-unreachable-state-machine-sbi-half.md`
//! for the enumeration and the delete-vs-wire reasoning.
//!
//! What survives is what `app.rs` really drives: the Initial -> Operational ->
//! Final lifecycle (`app.rs:333`) and the expired-timer branch fed from
//! `run_event_loop_async` (`app.rs:3504`).

use crate::event::{UdmEvent, UdmEventId, UdmTimerId};

/// UDM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// UDM state machine context
pub struct UdmSmContext {
    /// Current state
    state: UdmState,
}

impl UdmSmContext {
    /// Create a new UDM state machine context
    pub fn new() -> Self {
        Self {
            state: UdmState::Initial,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("UDM SM: Initializing");
        self.state = UdmState::Initial;

        // Process initial state - transition to operational
        let mut event = UdmEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("UDM SM: Finalizing");
        let mut event = UdmEvent::exit();
        self.dispatch(&mut event);
        self.state = UdmState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdmEvent) {
        udm_sm_debug(event);

        match self.state {
            UdmState::Initial => {
                self.handle_initial_state(event);
            }
            UdmState::Operational => {
                self.handle_operational_state(event);
            }
            UdmState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdmState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == UdmState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut UdmEvent) {
        // Transition to operational state
        log::info!("UDM SM: Transitioning from Initial to Operational");
        self.state = UdmState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut UdmEvent) {
        log::debug!("UDM SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdmEvent) {
        match event.id {
            UdmEventId::FsmEntry => {
                log::info!("UDM entering operational state");
            }

            UdmEventId::FsmExit => {
                log::info!("UDM exiting operational state");
            }

            UdmEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    /// Handle SBI timer events.
    ///
    /// Every arm is observational. `app.rs::run_event_loop_async` builds the
    /// event as `UdmEvent::sbi_timer(timer_id)` plus, for the NF-instance timers,
    /// `with_nf_instance` — so the NF-instance arm logs, and the two subscription
    /// arms and `SbiClientWait` cannot say anything useful because nothing
    /// populates `subscription_id` on the timer path. Acting on any of them needs
    /// the NRF NF-instance FSM that `udmd` does not have; the arms are kept
    /// because the timers really do expire and a silent expiry is worse than a
    /// logged one.
    fn handle_sbi_timer_event(&mut self, event: &mut UdmEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            UdmTimerId::NfInstanceRegistrationInterval
            | UdmTimerId::NfInstanceHeartbeatInterval
            | UdmTimerId::NfInstanceNoHeartbeat
            | UdmTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                    // Note: NF instance FSM dispatch requires NRF integration
                }
            }
            // These two used to log only `if let Some(subscription_id)`, and
            // nothing on the timer path populates one -- `run_event_loop_async`
            // attaches `with_nf_instance` and nothing else -- so an expiry that
            // really does happen produced NO output at all. Logged unconditionally
            // now, naming the missing id, because a silent expiry is the same
            // invisible-state problem #242 is about.
            UdmTimerId::SubscriptionValidity => {
                log::error!(
                    "Subscription validity expired [{}] (renewal requires NRF integration)",
                    event.subscription_id.as_deref().unwrap_or("no id attached")
                );
            }
            UdmTimerId::SubscriptionPatch => {
                log::info!(
                    "Subscription needs update [{}] (patch requires NRF integration)",
                    event.subscription_id.as_deref().unwrap_or("no id attached")
                );
            }
            UdmTimerId::SbiClientWait => {
                // #242: this used to answer 504 Gateway Timeout on the waiting
                // stream. It could not: the stream id came from `event.sbi`,
                // which only the removed `UdmEvent::sbi_server` constructor ever
                // populated, and the sink (`sbi_path::send_sbi_response`) was a
                // logging placeholder that sent nothing over the wire. Restoring
                // a real 504 needs the transaction/stream plumbing `udmd` has
                // never had, so the expiry is logged rather than answered.
                log::error!(
                    "SBI client wait timer expired (no stream to answer: udmd's request \
                     path is app.rs::udm_sbi_route, which owns its own response)"
                );
            }
        }
    }
}

impl Default for UdmSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug helper for state machine events
pub fn udm_sm_debug(event: &UdmEvent) {
    log::trace!("UDM SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udm_sm_context_new() {
        let ctx = UdmSmContext::new();
        assert_eq!(ctx.state(), UdmState::Initial);
    }

    #[test]
    fn test_udm_sm_init() {
        let mut ctx = UdmSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_udm_sm_dispatch_entry() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_dispatch_exit() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_dispatch_timer() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::sbi_timer(UdmTimerId::NfInstanceNoHeartbeat)
            .with_nf_instance("test-nf".to_string());
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_fini() {
        let mut ctx = UdmSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), UdmState::Final);
    }

    /// **Issue #242.** The state machine handles exactly the events `app.rs`
    /// dispatches, and every timer id survives a dispatch without panicking.
    ///
    /// The point of this test is the ENUMERATION: `UdmEventId` now has three
    /// variants and `handle_operational_state` matches all three exhaustively, so
    /// re-adding an `SbiServer` variant without a producer would fail to compile
    /// here rather than reintroducing a silently unreachable arm.
    #[test]
    fn operational_state_handles_every_event_the_daemon_dispatches() {
        let mut ctx = UdmSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());

        for id in [UdmEventId::FsmEntry, UdmEventId::FsmExit] {
            let mut event = UdmEvent::new(id);
            ctx.dispatch(&mut event);
            assert!(ctx.is_operational(), "{id:?} must not change state");
        }

        for timer_id in [
            UdmTimerId::NfInstanceRegistrationInterval,
            UdmTimerId::NfInstanceHeartbeatInterval,
            UdmTimerId::NfInstanceNoHeartbeat,
            UdmTimerId::NfInstanceValidity,
            UdmTimerId::SubscriptionValidity,
            UdmTimerId::SubscriptionPatch,
            UdmTimerId::SbiClientWait,
        ] {
            let mut event = UdmEvent::sbi_timer(timer_id);
            ctx.dispatch(&mut event);
            assert!(ctx.is_operational(), "{timer_id:?} must not change state");
        }

        // A timer event with no timer id is rejected, not unwrapped.
        let mut malformed = UdmEvent::new(UdmEventId::SbiTimer);
        assert_eq!(malformed.timer_id, None);
        ctx.dispatch(&mut malformed);
        assert!(ctx.is_operational());
    }
}
