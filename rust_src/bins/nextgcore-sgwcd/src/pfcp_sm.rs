//! SGWC PFCP State Machine
//!
//! Port of src/sgwc/pfcp-sm.c - PFCP state machine for SGW-U association

use crate::event::{SgwcEvent, SgwcEventId, SgwcTimerId};

/// PFCP FSM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfcpState {
    Initial,
    WillAssociate,
    Associated,
    Exception,
    Final,
}

/// PFCP FSM context for a single PFCP node
#[derive(Debug)]
pub struct PfcpFsm {
    pub state: PfcpState,
    pub node_id: u64,
    /// Restoration required flag
    pub restoration_required: bool,
}

impl PfcpFsm {
    pub fn new(node_id: u64) -> Self {
        Self {
            state: PfcpState::Initial,
            node_id,
            restoration_required: false,
        }
    }

    /// Dispatch event to state machine
    pub fn dispatch(&mut self, event: &SgwcEvent) {
        match self.state {
            PfcpState::Initial => self.state_initial(event),
            PfcpState::WillAssociate => self.state_will_associate(event),
            PfcpState::Associated => self.state_associated(event),
            PfcpState::Exception => self.state_exception(event),
            PfcpState::Final => self.state_final(event),
        }
    }

    /// Check if in associated state
    pub fn is_associated(&self) -> bool {
        self.state == PfcpState::Associated
    }

    /// Initial state handler
    fn state_initial(&mut self, event: &SgwcEvent) {
        pfcp_sm_debug(event, self.state);

        match event.id {
            SgwcEventId::FsmEntry => {
                // Create no-heartbeat timer (would be done in real impl)
                // Transition to will_associate state
                self.state = PfcpState::WillAssociate;
                log::info!("PFCP[{}] state: Initial -> WillAssociate", self.node_id);
            }
            _ => {}
        }
    }

    /// Final state handler
    fn state_final(&mut self, event: &SgwcEvent) {
        pfcp_sm_debug(event, self.state);

        match event.id {
            SgwcEventId::FsmEntry => {
                // Delete no-heartbeat timer
                log::info!("PFCP[{}] state machine finalized", self.node_id);
            }
            _ => {}
        }
    }

    /// Will Associate state handler
    fn state_will_associate(&mut self, event: &SgwcEvent) {
        pfcp_sm_debug(event, self.state);

        match event.id {
            SgwcEventId::FsmEntry => {
                // Start association timer and send association setup request
                log::debug!("PFCP[{}] will_associate entry - sending association setup", self.node_id);
                // TODO: Start timer and send PFCP Association Setup Request
            }
            SgwcEventId::FsmExit => {
                // Stop association timer
                log::debug!("PFCP[{}] will_associate exit", self.node_id);
            }
            SgwcEventId::SxaTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        SgwcTimerId::PfcpAssociation => {
                            log::warn!("PFCP[{}] association retry", self.node_id);
                            // TODO: Restart timer and resend association setup request
                        }
                        _ => {
                            log::error!("Unknown timer in will_associate: {:?}", timer_id);
                        }
                    }
                }
            }
            SgwcEventId::SxaMessage => {
                // Handle PFCP messages
                self.handle_will_associate_message(event);
            }
            _ => {
                log::error!("Unknown event in will_associate: {}", event.name());
            }
        }
    }

    /// Handle PFCP messages in will_associate state
    fn handle_will_associate_message(&mut self, _event: &SgwcEvent) {
        // TODO: Parse PFCP message type
        // Handle:
        // - Heartbeat Request/Response
        // - Association Setup Request/Response
        
        // For now, simulate successful association
        log::debug!("PFCP[{}] received message in will_associate", self.node_id);
        
        // On successful association setup, transition to associated
        // self.state = PfcpState::Associated;
    }

    /// Associated state handler
    fn state_associated(&mut self, event: &SgwcEvent) {
        pfcp_sm_debug(event, self.state);

        match event.id {
            SgwcEventId::FsmEntry => {
                log::info!("PFCP[{}] associated", self.node_id);
                // Start no-heartbeat timer
                // Send heartbeat request
                
                if self.restoration_required {
                    self.pfcp_restoration();
                    self.restoration_required = false;
                    log::error!("PFCP restoration");
                }
            }
            SgwcEventId::FsmExit => {
                log::info!("PFCP[{}] de-associated", self.node_id);
                // Stop no-heartbeat timer
            }
            SgwcEventId::SxaMessage => {
                self.handle_associated_message(event);
            }
            SgwcEventId::SxaTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        SgwcTimerId::PfcpNoHeartbeat => {
                            log::debug!("PFCP[{}] sending heartbeat", self.node_id);
                            // TODO: Send heartbeat request
                        }
                        _ => {
                            log::error!("Unknown timer in associated: {:?}", timer_id);
                        }
                    }
                }
            }
            SgwcEventId::SxaNoHeartbeat => {
                log::warn!("PFCP[{}] no heartbeat from SGW-U", self.node_id);
                self.state = PfcpState::WillAssociate;
            }
            _ => {
                log::error!("Unknown event in associated: {}", event.name());
            }
        }
    }

    /// Handle PFCP messages in associated state
    fn handle_associated_message(&mut self, _event: &SgwcEvent) {
        // TODO: Parse PFCP message type and handle:
        // - Heartbeat Request/Response
        // - Association Setup Request/Response (already associated warning)
        // - Session Establishment Response
        // - Session Modification Response
        // - Session Deletion Response
        // - Session Report Request
        
        log::debug!("PFCP[{}] received message in associated", self.node_id);
        
        // Check for restoration requirement after heartbeat
        if self.restoration_required {
            // If we have association timer, go back to will_associate
            // Otherwise, perform restoration immediately
            self.pfcp_restoration();
            self.restoration_required = false;
            log::error!("PFCP restoration");
        }
    }

    /// Exception state handler
    fn state_exception(&mut self, event: &SgwcEvent) {
        pfcp_sm_debug(event, self.state);
        // Nothing to do in exception state
    }

    /// Perform PFCP restoration
    fn pfcp_restoration(&self) {
        log::info!("PFCP[{}] performing restoration", self.node_id);
        // TODO: Re-establish sessions for all UEs using this PFCP node
        // For each session with this pfcp_node:
        //   Send Session Establishment Request with RESTORATION_INDICATION
    }
}

/// Debug logging for PFCP state machine events
fn pfcp_sm_debug(event: &SgwcEvent, state: PfcpState) {
    log::trace!("PFCP SM event: {} (state: {:?})", event.name(), state);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfcp_fsm_initial_to_will_associate() {
        let mut fsm = PfcpFsm::new(1);
        assert_eq!(fsm.state, PfcpState::Initial);

        let event = SgwcEvent::entry();
        fsm.dispatch(&event);
        assert_eq!(fsm.state, PfcpState::WillAssociate);
    }

    #[test]
    fn test_pfcp_fsm_associated_no_heartbeat() {
        let mut fsm = PfcpFsm::new(1);
        fsm.state = PfcpState::Associated;

        let event = SgwcEvent::sxa_no_heartbeat(1);
        fsm.dispatch(&event);
        assert_eq!(fsm.state, PfcpState::WillAssociate);
    }

    #[test]
    fn test_pfcp_fsm_is_associated() {
        let mut fsm = PfcpFsm::new(1);
        assert!(!fsm.is_associated());

        fsm.state = PfcpState::Associated;
        assert!(fsm.is_associated());
    }
}
