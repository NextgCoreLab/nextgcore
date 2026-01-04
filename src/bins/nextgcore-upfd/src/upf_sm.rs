//! UPF State Machine
//!
//! Port of src/upf/upf-sm.c - Main UPF state machine

use crate::event::{UpfEvent, UpfEventId};

// ============================================================================
// UPF FSM States
// ============================================================================

/// UPF FSM state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpfState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
    /// Exception state
    Exception,
}

impl Default for UpfState {
    fn default() -> Self {
        Self::Initial
    }
}

// ============================================================================
// UPF State Machine Context
// ============================================================================

/// UPF state machine context
#[derive(Debug, Default)]
pub struct UpfSmContext {
    /// Current state
    pub state: UpfState,
}

impl UpfSmContext {
    /// Create a new UPF state machine context
    pub fn new() -> Self {
        Self {
            state: UpfState::Initial,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("UPF SM: init");
        self.state = UpfState::Initial;
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("UPF SM: fini");
        self.state = UpfState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &UpfEvent) -> UpfSmResult {
        log::debug!("UPF SM: dispatch event {:?} in state {:?}", event.id, self.state);

        match self.state {
            UpfState::Initial => self.state_initial(event),
            UpfState::Operational => self.state_operational(event),
            UpfState::Final => self.state_final(event),
            UpfState::Exception => self.state_exception(event),
        }
    }

    /// Initial state handler
    /// Port of upf_state_initial from upf-sm.c
    fn state_initial(&mut self, event: &UpfEvent) -> UpfSmResult {
        log::debug!("upf_state_initial: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                // Transition to operational state
                self.state = UpfState::Operational;
                UpfSmResult::Transition(UpfState::Operational)
            }
            UpfEventId::FsmExit => UpfSmResult::Ok,
            _ => {
                log::warn!("Unexpected event {:?} in initial state", event.id);
                UpfSmResult::Ok
            }
        }
    }

    /// Final state handler
    /// Port of upf_state_final from upf-sm.c
    fn state_final(&mut self, event: &UpfEvent) -> UpfSmResult {
        log::debug!("upf_state_final: {:?}", event.id);
        // Final state does nothing
        UpfSmResult::Ok
    }

    /// Operational state handler
    /// Port of upf_state_operational from upf-sm.c
    fn state_operational(&mut self, event: &UpfEvent) -> UpfSmResult {
        log::debug!("upf_state_operational: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                log::info!("UPF entering operational state");
                UpfSmResult::Ok
            }
            UpfEventId::FsmExit => {
                log::info!("UPF exiting operational state");
                UpfSmResult::Ok
            }
            UpfEventId::N4Message => {
                // Handle N4 (PFCP) message
                // In the C code, this dispatches to the PFCP node's state machine
                if let Some(ref pfcp) = event.pfcp {
                    log::debug!(
                        "N4 message from node {:?}, xact {:?}",
                        pfcp.pfcp_node_id,
                        pfcp.pfcp_xact_id
                    );
                    // The actual handling is done by the PFCP state machine
                    UpfSmResult::DispatchToPfcp
                } else {
                    log::error!("N4 message event without PFCP data");
                    UpfSmResult::Error("Missing PFCP data".to_string())
                }
            }
            UpfEventId::N4Timer => {
                // Handle N4 timer event
                if let Some(ref pfcp) = event.pfcp {
                    log::debug!("N4 timer for node {:?}", pfcp.pfcp_node_id);
                    UpfSmResult::DispatchToPfcp
                } else {
                    log::error!("N4 timer event without PFCP data");
                    UpfSmResult::Error("Missing PFCP data".to_string())
                }
            }
            UpfEventId::N4NoHeartbeat => {
                // Handle N4 no heartbeat event
                if let Some(ref pfcp) = event.pfcp {
                    log::warn!("N4 no heartbeat from node {:?}", pfcp.pfcp_node_id);
                    UpfSmResult::DispatchToPfcp
                } else {
                    log::error!("N4 no heartbeat event without PFCP data");
                    UpfSmResult::Error("Missing PFCP data".to_string())
                }
            }
        }
    }

    /// Exception state handler
    /// Port of upf_state_exception from upf-sm.c
    fn state_exception(&mut self, event: &UpfEvent) -> UpfSmResult {
        log::debug!("upf_state_exception: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => UpfSmResult::Ok,
            UpfEventId::FsmExit => UpfSmResult::Ok,
            _ => {
                log::error!("Unknown event {:?} in exception state", event.id);
                UpfSmResult::Ok
            }
        }
    }

    /// Check if in exception state
    pub fn is_exception(&self) -> bool {
        self.state == UpfState::Exception
    }

    /// Check if in final state
    pub fn is_final(&self) -> bool {
        self.state == UpfState::Final
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == UpfState::Operational
    }
}

// ============================================================================
// State Machine Result
// ============================================================================

/// Result of state machine dispatch
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpfSmResult {
    /// Operation completed successfully
    Ok,
    /// State transition occurred
    Transition(UpfState),
    /// Event should be dispatched to PFCP state machine
    DispatchToPfcp,
    /// Error occurred
    Error(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upf_sm_init() {
        let mut sm = UpfSmContext::new();
        assert_eq!(sm.state, UpfState::Initial);
        
        sm.init();
        assert_eq!(sm.state, UpfState::Initial);
    }

    #[test]
    fn test_upf_sm_fini() {
        let mut sm = UpfSmContext::new();
        sm.fini();
        assert_eq!(sm.state, UpfState::Final);
    }

    #[test]
    fn test_upf_sm_initial_to_operational() {
        let mut sm = UpfSmContext::new();
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::Transition(UpfState::Operational));
        assert_eq!(sm.state, UpfState::Operational);
    }

    #[test]
    fn test_upf_sm_operational_entry_exit() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Operational;
        
        let entry = UpfEvent::entry();
        assert_eq!(sm.dispatch(&entry), UpfSmResult::Ok);
        
        let exit = UpfEvent::exit();
        assert_eq!(sm.dispatch(&exit), UpfSmResult::Ok);
    }

    #[test]
    fn test_upf_sm_operational_n4_message() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Operational;
        
        let event = UpfEvent::n4_message(1, 2, vec![0x01, 0x02]);
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::DispatchToPfcp);
    }

    #[test]
    fn test_upf_sm_operational_n4_timer() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Operational;
        
        let event = UpfEvent::n4_timer(crate::event::UpfTimerId::Association, Some(1));
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::DispatchToPfcp);
    }

    #[test]
    fn test_upf_sm_operational_n4_no_heartbeat() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Operational;
        
        let event = UpfEvent::n4_no_heartbeat(1);
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::DispatchToPfcp);
    }

    #[test]
    fn test_upf_sm_final_state() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Final;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::Ok);
        assert!(sm.is_final());
    }

    #[test]
    fn test_upf_sm_exception_state() {
        let mut sm = UpfSmContext::new();
        sm.state = UpfState::Exception;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, UpfSmResult::Ok);
        assert!(sm.is_exception());
    }

    #[test]
    fn test_upf_sm_state_checks() {
        let mut sm = UpfSmContext::new();
        
        sm.state = UpfState::Operational;
        assert!(sm.is_operational());
        assert!(!sm.is_final());
        assert!(!sm.is_exception());
        
        sm.state = UpfState::Final;
        assert!(!sm.is_operational());
        assert!(sm.is_final());
        assert!(!sm.is_exception());
        
        sm.state = UpfState::Exception;
        assert!(!sm.is_operational());
        assert!(!sm.is_final());
        assert!(sm.is_exception());
    }
}
