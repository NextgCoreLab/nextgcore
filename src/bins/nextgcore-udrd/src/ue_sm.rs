//! UDR UE State Machine
//!
//! Per-UE state machine for tracking subscriber data requests.
//! Unlike UDM, UDR is mostly stateless, but per-UE tracking enables:
//! - Subscription data change notifications
//! - Multi-step query correlation
//! - Request deduplication

use crate::event::{UdrEvent, UdrEventId};

/// UDR UE state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrUeState {
    /// Initial state
    Initial,
    /// Operational state - actively handling requests
    Operational,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// UDR UE state machine context
pub struct UdrUeSmContext {
    /// Current state
    state: UdrUeState,
    /// SUPI for this UE
    supi: String,
}

impl UdrUeSmContext {
    /// Create a new UDR UE state machine context
    pub fn new(supi: &str) -> Self {
        let mut ctx = Self {
            state: UdrUeState::Initial,
            supi: supi.to_string(),
        };
        ctx.init();
        ctx
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("[{}] UDR UE SM: Initializing", self.supi);
        self.state = UdrUeState::Initial;
        self.transition(UdrUeState::Operational);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("[{}] UDR UE SM: Finalizing", self.supi);
        self.state = UdrUeState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdrEvent) {
        log::trace!("[{}] UDR UE SM event: {}", self.supi, event.name());

        match self.state {
            UdrUeState::Initial => {
                self.transition(UdrUeState::Operational);
            }
            UdrUeState::Operational => {
                self.handle_operational_state(event);
            }
            UdrUeState::Exception => {
                self.handle_exception_state(event);
            }
            UdrUeState::Final => {
                log::debug!("[{}] UDR UE SM: In final state", self.supi);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdrUeState {
        self.state
    }

    /// Get SUPI
    pub fn supi(&self) -> &str {
        &self.supi
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: UdrUeState) {
        log::debug!(
            "[{}] UDR UE SM: {:?} -> {:?}",
            self.supi, self.state, new_state
        );
        self.state = new_state;
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdrEvent) {
        match event.id {
            UdrEventId::FsmEntry => {
                log::debug!("[{}] UDR UE entering operational state", self.supi);
            }
            UdrEventId::FsmExit => {
                log::debug!("[{}] UDR UE exiting operational state", self.supi);
            }
            UdrEventId::SbiServer => {
                // Server requests for this UE are dispatched through the main SM
                // and routed to nudr_handler functions. The UE SM tracks the UE
                // lifecycle and can be extended for notification support.
                log::debug!("[{}] UDR UE SM: SBI server event", self.supi);
            }
            UdrEventId::SbiClient => {
                log::debug!("[{}] UDR UE SM: SBI client event", self.supi);
            }
            UdrEventId::SbiTimer => {
                log::debug!("[{}] UDR UE SM: Timer event", self.supi);
            }
        }
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut UdrEvent) {
        match event.id {
            UdrEventId::FsmEntry => {
                log::debug!("[{}] UDR UE entering exception state", self.supi);
            }
            UdrEventId::FsmExit => {
                log::debug!("[{}] UDR UE exiting exception state", self.supi);
            }
            _ => {
                log::error!("[{}] UDR UE SM: Unexpected event in exception: {}", self.supi, event.name());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udr_ue_sm_new() {
        let ctx = UdrUeSmContext::new("imsi-001010000000001");
        assert_eq!(ctx.state(), UdrUeState::Operational);
        assert_eq!(ctx.supi(), "imsi-001010000000001");
    }

    #[test]
    fn test_udr_ue_sm_dispatch_entry() {
        let mut ctx = UdrUeSmContext::new("imsi-001010000000001");
        let mut event = UdrEvent::entry();
        ctx.dispatch(&mut event);
        assert_eq!(ctx.state(), UdrUeState::Operational);
    }

    #[test]
    fn test_udr_ue_sm_dispatch_exit() {
        let mut ctx = UdrUeSmContext::new("imsi-001010000000001");
        let mut event = UdrEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udr_ue_sm_fini() {
        let mut ctx = UdrUeSmContext::new("imsi-001010000000001");
        ctx.fini();
        assert_eq!(ctx.state(), UdrUeState::Final);
    }
}
