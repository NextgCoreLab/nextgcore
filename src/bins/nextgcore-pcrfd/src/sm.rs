//! PCRF State Machine
//!
//! Port of src/pcrf/pcrf-sm.c - Simple state machine with initial, operational, and final states

use crate::event::{PcrfEvent, PcrfEventId};

/// PCRF State enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrfState {
    /// Initial state - before initialization
    Initial,
    /// Operational state - normal operation
    Operational,
    /// Final state - after shutdown
    Final,
    /// Exception state - error condition
    Exception,
}

impl PcrfState {
    /// Get state name as string
    pub fn name(&self) -> &'static str {
        match self {
            PcrfState::Initial => "Initial",
            PcrfState::Operational => "Operational",
            PcrfState::Final => "Final",
            PcrfState::Exception => "Exception",
        }
    }
}

/// PCRF State Machine Context
pub struct PcrfSmContext {
    /// Current state
    state: PcrfState,
    /// Debug mode enabled
    debug: bool,
}

impl PcrfSmContext {
    /// Create a new state machine context
    pub fn new() -> Self {
        Self {
            state: PcrfState::Initial,
            debug: false,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self, _use_mongodb_change_stream: bool) {
        self.state = PcrfState::Initial;
        log::debug!("PCRF state machine initialized in {:?} state", self.state);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        self.state = PcrfState::Final;
        log::debug!("PCRF state machine finalized");
    }

    /// Get current state
    pub fn state(&self) -> PcrfState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == PcrfState::Operational
    }

    /// Enable/disable debug mode
    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut PcrfEvent) {
        if self.debug {
            log::debug!(
                "PCRF SM: state={:?}, event={}",
                self.state,
                event.name()
            );
        }

        match self.state {
            PcrfState::Initial => self.state_initial(event),
            PcrfState::Operational => self.state_operational(event),
            PcrfState::Final => self.state_final(event),
            PcrfState::Exception => self.state_exception(event),
        }
    }

    /// Initial state handler
    fn state_initial(&mut self, event: &mut PcrfEvent) {
        match event.id {
            PcrfEventId::Entry => {
                log::info!("PCRF transitioning to Operational state");
                self.state = PcrfState::Operational;
            }
            PcrfEventId::Exit => {
                log::info!("PCRF transitioning to Final state");
                self.state = PcrfState::Final;
            }
            _ => {
                log::warn!(
                    "Unexpected event {} in Initial state",
                    event.name()
                );
            }
        }
    }

    /// Operational state handler
    fn state_operational(&mut self, event: &mut PcrfEvent) {
        match event.id {
            PcrfEventId::Entry => {
                // Already in operational state, ignore
                log::debug!("PCRF already in Operational state");
            }
            PcrfEventId::Exit => {
                log::info!("PCRF transitioning to Final state");
                self.state = PcrfState::Final;
            }
            PcrfEventId::SbiServer => {
                // Handle SBI server events
                log::debug!("PCRF handling SBI server event");
            }
            PcrfEventId::SbiClient => {
                // Handle SBI client events
                log::debug!("PCRF handling SBI client event");
            }
            PcrfEventId::SbiTimer => {
                // Handle timer events
                log::debug!("PCRF handling timer event");
            }
            _ => {
                log::debug!("PCRF ignoring event {} in Operational state", event.name());
            }
        }
    }

    /// Final state handler
    fn state_final(&mut self, event: &mut PcrfEvent) {
        match event.id {
            PcrfEventId::Entry => {
                // Cleanup operations
                log::debug!("PCRF Final state entry - cleanup");
            }
            _ => {
                log::debug!("PCRF ignoring event {} in Final state", event.name());
            }
        }
    }

    /// Exception state handler
    fn state_exception(&mut self, event: &mut PcrfEvent) {
        log::error!(
            "PCRF in Exception state, event: {}",
            event.name()
        );
        // Try to recover by transitioning to Final state
        if event.id == PcrfEventId::Exit {
            self.state = PcrfState::Final;
        }
    }
}

impl Default for PcrfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Enable debug mode for PCRF state machine
pub fn pcrf_sm_debug(level: i32) {
    if level > 0 {
        log::info!("PCRF state machine debug enabled (level={level})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcrf_state_name() {
        assert_eq!(PcrfState::Initial.name(), "Initial");
        assert_eq!(PcrfState::Operational.name(), "Operational");
        assert_eq!(PcrfState::Final.name(), "Final");
        assert_eq!(PcrfState::Exception.name(), "Exception");
    }

    #[test]
    fn test_sm_context_new() {
        let sm = PcrfSmContext::new();
        assert_eq!(sm.state(), PcrfState::Initial);
        assert!(!sm.is_operational());
    }

    #[test]
    fn test_sm_init_fini() {
        let mut sm = PcrfSmContext::new();
        sm.init(false);
        assert_eq!(sm.state(), PcrfState::Initial);

        sm.fini();
        assert_eq!(sm.state(), PcrfState::Final);
    }

    #[test]
    fn test_sm_transition_to_operational() {
        let mut sm = PcrfSmContext::new();
        sm.init(false);

        let mut entry_event = PcrfEvent::entry();
        sm.dispatch(&mut entry_event);

        assert_eq!(sm.state(), PcrfState::Operational);
        assert!(sm.is_operational());
    }

    #[test]
    fn test_sm_transition_to_final() {
        let mut sm = PcrfSmContext::new();
        sm.init(false);

        // First go to operational
        let mut entry_event = PcrfEvent::entry();
        sm.dispatch(&mut entry_event);
        assert!(sm.is_operational());

        // Then exit to final
        let mut exit_event = PcrfEvent::exit();
        sm.dispatch(&mut exit_event);
        assert_eq!(sm.state(), PcrfState::Final);
    }

    #[test]
    fn test_sm_debug_mode() {
        let mut sm = PcrfSmContext::new();
        sm.set_debug(true);
        sm.init(false);

        let mut entry_event = PcrfEvent::entry();
        sm.dispatch(&mut entry_event);
        // Debug output should be generated (check logs)
    }

    #[test]
    fn test_sm_operational_events() {
        let mut sm = PcrfSmContext::new();
        sm.init(false);

        let mut entry_event = PcrfEvent::entry();
        sm.dispatch(&mut entry_event);
        assert!(sm.is_operational());

        // Timer event should be handled without state change
        let mut timer_event = PcrfEvent::timer(1, None);
        sm.dispatch(&mut timer_event);
        assert!(sm.is_operational());
    }
}
