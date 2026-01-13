//! SGWC State Machine
//!
//! Port of src/sgwc/sgwc-sm.c - Main SGWC state machine handling S11/S5C/SXA messages

use crate::event::{SgwcEvent, SgwcEventId};

/// FSM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgwcState {
    Initial,
    Operational,
    Final,
}

/// SGWC FSM context
#[derive(Debug)]
pub struct SgwcFsm {
    pub state: SgwcState,
}

impl Default for SgwcFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl SgwcFsm {
    pub fn new() -> Self {
        Self {
            state: SgwcState::Initial,
        }
    }

    /// Dispatch event to state machine
    pub fn dispatch(&mut self, event: &SgwcEvent) {
        match self.state {
            SgwcState::Initial => self.state_initial(event),
            SgwcState::Operational => self.state_operational(event),
            SgwcState::Final => self.state_final(event),
        }
    }

    /// Initial state handler
    fn state_initial(&mut self, event: &SgwcEvent) {
        sgwc_sm_debug(event);

        match event.id {
            SgwcEventId::FsmEntry => {
                // Transition to operational state
                self.state = SgwcState::Operational;
                log::info!("SGWC state machine: Initial -> Operational");
            }
            _ => {}
        }
    }

    /// Operational state handler
    fn state_operational(&mut self, event: &SgwcEvent) {
        sgwc_sm_debug(event);

        match event.id {
            SgwcEventId::FsmEntry => {
                log::debug!("SGWC operational state entry");
            }
            SgwcEventId::FsmExit => {
                log::debug!("SGWC operational state exit");
            }
            SgwcEventId::S11Message => {
                self.handle_s11_message(event);
            }
            SgwcEventId::S5cMessage => {
                self.handle_s5c_message(event);
            }
            SgwcEventId::SxaMessage => {
                self.handle_sxa_message(event);
            }
            SgwcEventId::SxaTimer | SgwcEventId::SxaNoHeartbeat => {
                self.handle_sxa_timer(event);
            }
        }
    }

    /// Final state handler
    fn state_final(&mut self, event: &SgwcEvent) {
        sgwc_sm_debug(event);
        // Nothing to do in final state
    }

    /// Handle S11 message (from MME)
    fn handle_s11_message(&self, event: &SgwcEvent) {
        let _gtp = match &event.gtp {
            Some(gtp) => gtp,
            None => {
                log::error!("S11 message event without GTP data");
                return;
            }
        };

        // Note: GTP message parsed and dispatched by s11_handler module
        // Create Session Request -> create bearer context, send PFCP session establishment
        // Modify Bearer Request -> update bearer, send PFCP session modification
        // Delete Session Request -> teardown bearer, send PFCP session deletion
        // Create/Update/Delete Bearer Response -> handle PGW-initiated bearer operations
        // Release Access Bearers Request -> release U-plane resources
        // Downlink Data Notification Ack -> process paging acknowledgment
        // Create/Delete Indirect Data Forwarding Tunnel -> handover support
        // Bearer Resource Command -> QoS resource requests
        log::debug!("S11 message received");
    }

    /// Handle S5-C message (from PGW)
    fn handle_s5c_message(&self, event: &SgwcEvent) {
        let _gtp = match &event.gtp {
            Some(gtp) => gtp,
            None => {
                log::error!("S5C message event without GTP data");
                return;
            }
        };

        // Note: GTP message parsed and dispatched by s5c_handler module
        // Create Session Response -> complete session setup, notify MME
        // Modify Bearer Response -> complete bearer modification, notify MME
        // Delete Session Response -> complete teardown, notify MME
        // Create/Update/Delete Bearer Request -> handle PGW-initiated bearer operations
        // Bearer Resource Failure Indication -> notify MME of resource failure
        log::debug!("S5C message received");
    }

    /// Handle SXA message/timer (PFCP)
    fn handle_sxa_message(&self, event: &SgwcEvent) {
        let _pfcp = match &event.pfcp {
            Some(pfcp) => pfcp,
            None => {
                log::error!("SXA message event without PFCP data");
                return;
            }
        };

        // Note: Dispatch to PFCP state machine via pfcp_sm.dispatch(event)
        // PFCP node lookup by pfcp_node_id, then dispatch to appropriate PfcpFsm instance
        log::debug!("SXA message received");
    }

    /// Handle SXA timer events
    fn handle_sxa_timer(&self, event: &SgwcEvent) {
        let _pfcp = match &event.pfcp {
            Some(pfcp) => pfcp,
            None => {
                log::error!("SXA timer event without PFCP data");
                return;
            }
        };

        // Note: Dispatch to PFCP state machine via pfcp_sm.dispatch(event)
        // Timer events trigger association retry or heartbeat send based on timer_id
        log::debug!("SXA timer event: {:?}", event.timer_id);
    }
}

/// Debug logging for state machine events
pub fn sgwc_sm_debug(event: &SgwcEvent) {
    log::trace!("SGWC SM event: {}", event.name());
}

// ============================================================================
// Echo Request/Response Handlers
// ============================================================================

/// Handle GTP Echo Request
pub fn sgwc_handle_echo_request(_xact_id: u64, _recovery: u8) {
    log::debug!("[SGW] Receiving Echo Request");
    // Note: Echo Response sent via gtp_handler::send_echo_response
    // Response includes local recovery counter for path management
}

/// Handle GTP Echo Response
pub fn sgwc_handle_echo_response(_xact_id: u64) {
    log::debug!("[SGW] Receiving Echo Response");
    // Not implemented in original
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsm_initial_to_operational() {
        let mut fsm = SgwcFsm::new();
        assert_eq!(fsm.state, SgwcState::Initial);

        let event = SgwcEvent::entry();
        fsm.dispatch(&event);
        assert_eq!(fsm.state, SgwcState::Operational);
    }

    #[test]
    fn test_fsm_operational_events() {
        let mut fsm = SgwcFsm::new();
        fsm.state = SgwcState::Operational;

        // Test S11 message handling (should not crash)
        let event = SgwcEvent::s11_message(1, 1, vec![]);
        fsm.dispatch(&event);

        // Test S5C message handling
        let event = SgwcEvent::s5c_message(1, 1, vec![]);
        fsm.dispatch(&event);

        // Test SXA message handling
        let event = SgwcEvent::sxa_message(1, 1, vec![]);
        fsm.dispatch(&event);
    }
}
