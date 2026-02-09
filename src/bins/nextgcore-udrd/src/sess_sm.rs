//! UDR Session State Machine
//!
//! Per-session state machine for tracking PDU session data requests.
//! Tracks session-level operations like SMF registration context
//! and session management subscription data queries.

use crate::event::{UdrEvent, UdrEventId};

/// UDR Session state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrSessState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// UDR Session state machine context
pub struct UdrSessSmContext {
    /// Current state
    state: UdrSessState,
    /// SUPI of the parent UE
    supi: String,
    /// PDU Session Identifier
    psi: u8,
    /// DNN (Data Network Name)
    dnn: Option<String>,
}

impl UdrSessSmContext {
    /// Create a new UDR session state machine context
    pub fn new(supi: &str, psi: u8, dnn: Option<&str>) -> Self {
        let mut ctx = Self {
            state: UdrSessState::Initial,
            supi: supi.to_string(),
            psi,
            dnn: dnn.map(|s| s.to_string()),
        };
        ctx.init();
        ctx
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("[{}:{}] UDR Sess SM: Initializing", self.supi, self.psi);
        self.state = UdrSessState::Initial;
        self.transition(UdrSessState::Operational);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("[{}:{}] UDR Sess SM: Finalizing", self.supi, self.psi);
        self.state = UdrSessState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdrEvent) {
        log::trace!("[{}:{}] UDR Sess SM event: {}", self.supi, self.psi, event.name());

        match self.state {
            UdrSessState::Initial => {
                self.transition(UdrSessState::Operational);
            }
            UdrSessState::Operational => {
                self.handle_operational_state(event);
            }
            UdrSessState::Exception => {
                self.handle_exception_state(event);
            }
            UdrSessState::Final => {
                log::debug!("[{}:{}] UDR Sess SM: In final state", self.supi, self.psi);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdrSessState {
        self.state
    }

    /// Get SUPI
    pub fn supi(&self) -> &str {
        &self.supi
    }

    /// Get PSI
    pub fn psi(&self) -> u8 {
        self.psi
    }

    /// Get DNN
    pub fn dnn(&self) -> Option<&str> {
        self.dnn.as_deref()
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: UdrSessState) {
        log::debug!(
            "[{}:{}] UDR Sess SM: {:?} -> {:?}",
            self.supi, self.psi, self.state, new_state
        );
        self.state = new_state;
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdrEvent) {
        match event.id {
            UdrEventId::FsmEntry => {
                log::debug!("[{}:{}] UDR Session entering operational state", self.supi, self.psi);
            }
            UdrEventId::FsmExit => {
                log::debug!("[{}:{}] UDR Session exiting operational state", self.supi, self.psi);
            }
            UdrEventId::SbiServer => {
                // Session-level server requests (SMF registrations, SM data queries)
                log::debug!("[{}:{}] UDR Sess SM: SBI server event", self.supi, self.psi);
            }
            UdrEventId::SbiClient => {
                log::debug!("[{}:{}] UDR Sess SM: SBI client event", self.supi, self.psi);
            }
            UdrEventId::SbiTimer => {
                log::debug!("[{}:{}] UDR Sess SM: Timer event", self.supi, self.psi);
            }
        }
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut UdrEvent) {
        match event.id {
            UdrEventId::FsmEntry => {
                log::debug!("[{}:{}] UDR Session entering exception state", self.supi, self.psi);
            }
            UdrEventId::FsmExit => {
                log::debug!("[{}:{}] UDR Session exiting exception state", self.supi, self.psi);
            }
            _ => {
                log::error!(
                    "[{}:{}] UDR Sess SM: Unexpected event in exception: {}",
                    self.supi, self.psi, event.name()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udr_sess_sm_new() {
        let ctx = UdrSessSmContext::new("imsi-001010000000001", 5, Some("internet"));
        assert_eq!(ctx.state(), UdrSessState::Operational);
        assert_eq!(ctx.supi(), "imsi-001010000000001");
        assert_eq!(ctx.psi(), 5);
        assert_eq!(ctx.dnn(), Some("internet"));
    }

    #[test]
    fn test_udr_sess_sm_no_dnn() {
        let ctx = UdrSessSmContext::new("imsi-001010000000001", 1, None);
        assert_eq!(ctx.state(), UdrSessState::Operational);
        assert_eq!(ctx.dnn(), None);
    }

    #[test]
    fn test_udr_sess_sm_dispatch_entry() {
        let mut ctx = UdrSessSmContext::new("imsi-001010000000001", 5, Some("internet"));
        let mut event = UdrEvent::entry();
        ctx.dispatch(&mut event);
        assert_eq!(ctx.state(), UdrSessState::Operational);
    }

    #[test]
    fn test_udr_sess_sm_dispatch_exit() {
        let mut ctx = UdrSessSmContext::new("imsi-001010000000001", 5, Some("internet"));
        let mut event = UdrEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udr_sess_sm_fini() {
        let mut ctx = UdrSessSmContext::new("imsi-001010000000001", 5, Some("internet"));
        ctx.fini();
        assert_eq!(ctx.state(), UdrSessState::Final);
    }
}
