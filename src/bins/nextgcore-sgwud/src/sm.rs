//! SGWU State Machine
//!
//! Port of src/sgwu/sgwu-sm.c - Main SGWU state machine with initial, final, and operational states

use crate::event::{SgwuEvent, SgwuEventId};

// ============================================================================
// FSM State Types
// ============================================================================

/// SGWU FSM state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgwuState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Operational state
    Operational,
}

impl Default for SgwuState {
    fn default() -> Self {
        Self::Initial
    }
}

// ============================================================================
// SGWU State Machine
// ============================================================================

/// SGWU state machine
#[derive(Debug, Default)]
pub struct SgwuStateMachine {
    /// Current state
    state: SgwuState,
}

impl SgwuStateMachine {
    /// Create a new SGWU state machine
    pub fn new() -> Self {
        Self {
            state: SgwuState::Initial,
        }
    }

    /// Get current state
    pub fn state(&self) -> SgwuState {
        self.state
    }

    /// Check if in initial state
    pub fn is_initial(&self) -> bool {
        self.state == SgwuState::Initial
    }

    /// Check if in final state
    pub fn is_final(&self) -> bool {
        self.state == SgwuState::Final
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == SgwuState::Operational
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        self.state = SgwuState::Initial;
        log::debug!("SGWU state machine initialized");
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        self.state = SgwuState::Final;
        log::debug!("SGWU state machine finalized");
    }

    /// Dispatch event to state machine
    pub fn dispatch(&mut self, event: &SgwuEvent) -> SgwuSmResult {
        sgwu_sm_debug(event);

        match self.state {
            SgwuState::Initial => self.state_initial(event),
            SgwuState::Final => self.state_final(event),
            SgwuState::Operational => self.state_operational(event),
        }
    }

    /// Initial state handler
    /// Port of sgwu_state_initial from sgwu-sm.c
    fn state_initial(&mut self, event: &SgwuEvent) -> SgwuSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                // Transition to operational state
                self.state = SgwuState::Operational;
                log::debug!("SGWU FSM: Initial -> Operational");
                SgwuSmResult::StateChanged(SgwuState::Operational)
            }
            SgwuEventId::FsmExit => {
                SgwuSmResult::Ok
            }
            _ => {
                log::warn!("Unexpected event {} in initial state", event.name());
                SgwuSmResult::Ok
            }
        }
    }

    /// Final state handler
    /// Port of sgwu_state_final from sgwu-sm.c
    fn state_final(&mut self, event: &SgwuEvent) -> SgwuSmResult {
        match event.id {
            SgwuEventId::FsmEntry | SgwuEventId::FsmExit => {
                SgwuSmResult::Ok
            }
            _ => {
                log::warn!("Unexpected event {} in final state", event.name());
                SgwuSmResult::Ok
            }
        }
    }

    /// Operational state handler
    /// Port of sgwu_state_operational from sgwu-sm.c
    fn state_operational(&mut self, event: &SgwuEvent) -> SgwuSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                log::debug!("SGWU FSM: Entering operational state");
                SgwuSmResult::Ok
            }
            SgwuEventId::FsmExit => {
                log::debug!("SGWU FSM: Exiting operational state");
                SgwuSmResult::Ok
            }
            SgwuEventId::SxaMessage => {
                // Handle SXA (PFCP) message
                self.handle_sxa_message(event)
            }
            SgwuEventId::SxaTimer => {
                // Handle SXA timer
                self.handle_sxa_timer(event)
            }
            SgwuEventId::SxaNoHeartbeat => {
                // Handle no heartbeat
                self.handle_sxa_no_heartbeat(event)
            }
        }
    }

    /// Handle SXA message event
    fn handle_sxa_message(&self, event: &SgwuEvent) -> SgwuSmResult {
        if let Some(ref pfcp) = event.pfcp {
            log::debug!(
                "SGWU: Received SXA message from PFCP node {:?}",
                pfcp.pfcp_node_id
            );
            // In the C implementation, this dispatches to the PFCP node's state machine
            // The actual message handling is done in pfcp-sm.c
            SgwuSmResult::DispatchToPfcpNode(pfcp.pfcp_node_id.unwrap_or(0))
        } else {
            log::error!("SXA message event without PFCP data");
            SgwuSmResult::Error("Missing PFCP data".to_string())
        }
    }

    /// Handle SXA timer event
    fn handle_sxa_timer(&self, event: &SgwuEvent) -> SgwuSmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("SGWU: Timer {} expired", timer_id.name());
            if let Some(ref pfcp) = event.pfcp {
                SgwuSmResult::DispatchToPfcpNode(pfcp.pfcp_node_id.unwrap_or(0))
            } else {
                SgwuSmResult::Ok
            }
        } else {
            log::error!("SXA timer event without timer ID");
            SgwuSmResult::Error("Missing timer ID".to_string())
        }
    }

    /// Handle SXA no heartbeat event
    fn handle_sxa_no_heartbeat(&self, event: &SgwuEvent) -> SgwuSmResult {
        if let Some(ref pfcp) = event.pfcp {
            log::warn!(
                "SGWU: No heartbeat from PFCP node {:?}",
                pfcp.pfcp_node_id
            );
            SgwuSmResult::DispatchToPfcpNode(pfcp.pfcp_node_id.unwrap_or(0))
        } else {
            log::error!("SXA no heartbeat event without PFCP data");
            SgwuSmResult::Error("Missing PFCP data".to_string())
        }
    }
}

// ============================================================================
// State Machine Result
// ============================================================================

/// Result of state machine dispatch
#[derive(Debug, Clone, PartialEq)]
pub enum SgwuSmResult {
    /// Operation completed successfully
    Ok,
    /// State changed
    StateChanged(SgwuState),
    /// Dispatch to PFCP node state machine
    DispatchToPfcpNode(u64),
    /// Error occurred
    Error(String),
}

// ============================================================================
// Debug Helper
// ============================================================================

/// Debug helper for state machine events
/// Port of sgwu_sm_debug from sgwu-sm.c
pub fn sgwu_sm_debug(event: &SgwuEvent) {
    log::trace!("SGWU SM: Event {}", event.name());
    if let Some(timer_id) = event.timer_id {
        log::trace!("  Timer: {}", timer_id.name());
    }
    if let Some(ref pfcp) = event.pfcp {
        if let Some(node_id) = pfcp.pfcp_node_id {
            log::trace!("  PFCP Node: {}", node_id);
        }
        if let Some(xact_id) = pfcp.pfcp_xact_id {
            log::trace!("  PFCP Xact: {}", xact_id);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SgwuTimerId;

    #[test]
    fn test_state_machine_init() {
        let mut sm = SgwuStateMachine::new();
        assert!(sm.is_initial());

        // Dispatch entry event to transition to operational
        let event = SgwuEvent::entry();
        let result = sm.dispatch(&event);
        assert_eq!(result, SgwuSmResult::StateChanged(SgwuState::Operational));
        assert!(sm.is_operational());
    }

    #[test]
    fn test_state_machine_operational() {
        let mut sm = SgwuStateMachine::new();
        
        // Transition to operational
        sm.dispatch(&SgwuEvent::entry());
        assert!(sm.is_operational());

        // Test SXA message handling
        let event = SgwuEvent::sxa_message(100, 1, vec![]);
        let result = sm.dispatch(&event);
        assert_eq!(result, SgwuSmResult::DispatchToPfcpNode(100));

        // Test SXA timer handling
        let event = SgwuEvent::sxa_timer(SgwuTimerId::Association, Some(200));
        let result = sm.dispatch(&event);
        assert_eq!(result, SgwuSmResult::DispatchToPfcpNode(200));

        // Test no heartbeat handling
        let event = SgwuEvent::sxa_no_heartbeat(300);
        let result = sm.dispatch(&event);
        assert_eq!(result, SgwuSmResult::DispatchToPfcpNode(300));
    }

    #[test]
    fn test_state_machine_final() {
        let mut sm = SgwuStateMachine::new();
        sm.fini();
        assert!(sm.is_final());

        // Events in final state should be handled gracefully
        let event = SgwuEvent::entry();
        let result = sm.dispatch(&event);
        assert_eq!(result, SgwuSmResult::Ok);
    }

    #[test]
    fn test_state_machine_entry_exit() {
        let mut sm = SgwuStateMachine::new();
        
        // Transition to operational
        sm.dispatch(&SgwuEvent::entry());
        
        // Entry event in operational state
        let result = sm.dispatch(&SgwuEvent::entry());
        assert_eq!(result, SgwuSmResult::Ok);

        // Exit event in operational state
        let result = sm.dispatch(&SgwuEvent::exit());
        assert_eq!(result, SgwuSmResult::Ok);
    }
}
