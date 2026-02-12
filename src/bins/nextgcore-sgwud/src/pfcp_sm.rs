//! SGWU PFCP State Machine
//!
//! Port of src/sgwu/pfcp-sm.c - PFCP state machine with will_associate, associated, and exception states

use crate::context::sgwu_self;
use crate::event::{SgwuEvent, SgwuEventId, SgwuTimerId};

// ============================================================================
// PFCP Message Types (from ogs-pfcp)
// ============================================================================

/// PFCP message types
pub mod pfcp_message_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP FSM State Types
// ============================================================================

/// PFCP FSM state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfcpState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Will associate state (attempting association)
    WillAssociate,
    /// Associated state (association established)
    Associated,
    /// Exception state (error condition)
    Exception,
}

impl Default for PfcpState {
    fn default() -> Self {
        Self::Initial
    }
}

// ============================================================================
// PFCP Node Info
// ============================================================================

/// PFCP node information
#[derive(Debug, Clone, Default)]
pub struct PfcpNodeInfo {
    /// Node ID
    pub id: u64,
    /// Node address (string representation)
    pub addr: String,
    /// Association timer handle
    pub t_association: Option<u64>,
    /// No heartbeat timer handle
    pub t_no_heartbeat: Option<u64>,
    /// Restoration required flag
    pub restoration_required: bool,
}

// ============================================================================
// PFCP State Machine
// ============================================================================

/// PFCP state machine for SGWU
/// Port of sgwu_pfcp_state_* functions from pfcp-sm.c
#[derive(Debug, Default)]
pub struct PfcpStateMachine {
    /// Current state
    state: PfcpState,
    /// PFCP node info
    node: PfcpNodeInfo,
}

impl PfcpStateMachine {
    /// Create a new PFCP state machine
    pub fn new(node_id: u64) -> Self {
        Self {
            state: PfcpState::Initial,
            node: PfcpNodeInfo {
                id: node_id,
                ..Default::default()
            },
        }
    }

    /// Get current state
    pub fn state(&self) -> PfcpState {
        self.state
    }

    /// Get node info
    pub fn node(&self) -> &PfcpNodeInfo {
        &self.node
    }

    /// Get mutable node info
    pub fn node_mut(&mut self) -> &mut PfcpNodeInfo {
        &mut self.node
    }

    /// Check if in initial state
    pub fn is_initial(&self) -> bool {
        self.state == PfcpState::Initial
    }

    /// Check if in final state
    pub fn is_final(&self) -> bool {
        self.state == PfcpState::Final
    }

    /// Check if in will_associate state
    pub fn is_will_associate(&self) -> bool {
        self.state == PfcpState::WillAssociate
    }

    /// Check if in associated state
    pub fn is_associated(&self) -> bool {
        self.state == PfcpState::Associated
    }

    /// Check if in exception state
    pub fn is_exception(&self) -> bool {
        self.state == PfcpState::Exception
    }

    /// Dispatch event to state machine
    pub fn dispatch(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        pfcp_sm_debug(event, &self.node);

        match self.state {
            PfcpState::Initial => self.state_initial(event),
            PfcpState::Final => self.state_final(event),
            PfcpState::WillAssociate => self.state_will_associate(event),
            PfcpState::Associated => self.state_associated(event),
            PfcpState::Exception => self.state_exception(event),
        }
    }

    /// Initial state handler
    /// Port of sgwu_pfcp_state_initial from pfcp-sm.c
    fn state_initial(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                // Create no heartbeat timer
                log::debug!("PFCP FSM: Creating no heartbeat timer for node {}", self.node.id);
                
                // Transition to will_associate state
                self.state = PfcpState::WillAssociate;
                log::debug!("PFCP FSM: Initial -> WillAssociate");
                PfcpSmResult::StateChanged(PfcpState::WillAssociate)
            }
            SgwuEventId::FsmExit => {
                PfcpSmResult::Ok
            }
            _ => {
                log::warn!("Unexpected event {} in PFCP initial state", event.name());
                PfcpSmResult::Ok
            }
        }
    }

    /// Final state handler
    /// Port of sgwu_pfcp_state_final from pfcp-sm.c
    fn state_final(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                // Delete no heartbeat timer
                log::debug!("PFCP FSM: Deleting no heartbeat timer for node {}", self.node.id);
                PfcpSmResult::Ok
            }
            SgwuEventId::FsmExit => {
                PfcpSmResult::Ok
            }
            _ => {
                log::warn!("Unexpected event {} in PFCP final state", event.name());
                PfcpSmResult::Ok
            }
        }
    }

    /// Will associate state handler
    /// Port of sgwu_pfcp_state_will_associate from pfcp-sm.c
    fn state_will_associate(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                // Start association timer and send association setup request
                if self.node.t_association.is_some() {
                    log::debug!("PFCP FSM: Starting association timer");
                    // In real implementation: start timer and send association setup request
                    return PfcpSmResult::SendAssociationSetupRequest;
                }
                PfcpSmResult::Ok
            }
            SgwuEventId::FsmExit => {
                // Stop association timer
                if self.node.t_association.is_some() {
                    log::debug!("PFCP FSM: Stopping association timer");
                }
                PfcpSmResult::Ok
            }
            SgwuEventId::SxaTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        SgwuTimerId::Association => {
                            log::warn!("Retry association with peer failed {}", self.node.addr);
                            // Restart timer and retry
                            return PfcpSmResult::SendAssociationSetupRequest;
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in will_associate state");
                        }
                    }
                }
                PfcpSmResult::Ok
            }
            SgwuEventId::SxaMessage => {
                self.handle_will_associate_message(event)
            }
            _ => {
                log::error!("Unknown event {} in will_associate state", event.name());
                PfcpSmResult::Ok
            }
        }
    }

    /// Handle message in will_associate state
    fn handle_will_associate_message(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        // In real implementation, parse the PFCP message and handle accordingly
        // For now, simulate message type handling
        if let Some(ref pfcp) = event.pfcp {
            if let Some(ref pkbuf) = pfcp.pkbuf {
                if !pkbuf.is_empty() {
                    let msg_type = pkbuf[0];
                    match msg_type {
                        pfcp_message_type::HEARTBEAT_REQUEST => {
                            log::debug!("PFCP: Handling heartbeat request");
                            return PfcpSmResult::SendHeartbeatResponse;
                        }
                        pfcp_message_type::HEARTBEAT_RESPONSE => {
                            log::debug!("PFCP: Handling heartbeat response");
                            return PfcpSmResult::Ok;
                        }
                        pfcp_message_type::ASSOCIATION_SETUP_REQUEST => {
                            log::debug!("PFCP: Handling association setup request");
                            self.state = PfcpState::Associated;
                            return PfcpSmResult::StateChanged(PfcpState::Associated);
                        }
                        pfcp_message_type::ASSOCIATION_SETUP_RESPONSE => {
                            log::debug!("PFCP: Handling association setup response");
                            self.state = PfcpState::Associated;
                            return PfcpSmResult::StateChanged(PfcpState::Associated);
                        }
                        _ => {
                            log::warn!("Cannot handle PFCP message type {msg_type} in will_associate");
                        }
                    }
                }
            }
        }
        PfcpSmResult::Ok
    }

    /// Associated state handler
    /// Port of sgwu_pfcp_state_associated from pfcp-sm.c
    fn state_associated(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        match event.id {
            SgwuEventId::FsmEntry => {
                log::info!("PFCP associated {}", self.node.addr);
                // Start no heartbeat timer and send heartbeat request
                log::debug!("PFCP FSM: Starting no heartbeat timer");
                
                if self.node.restoration_required {
                    self.pfcp_restoration();
                    self.node.restoration_required = false;
                    log::error!("PFCP restoration");
                }
                
                PfcpSmResult::SendHeartbeatRequest
            }
            SgwuEventId::FsmExit => {
                log::info!("PFCP de-associated {}", self.node.addr);
                // Stop no heartbeat timer
                log::debug!("PFCP FSM: Stopping no heartbeat timer");
                PfcpSmResult::Ok
            }
            SgwuEventId::SxaMessage => {
                self.handle_associated_message(event)
            }
            SgwuEventId::SxaTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        SgwuTimerId::NoHeartbeat => {
                            log::debug!("PFCP: No heartbeat timer expired, sending heartbeat");
                            return PfcpSmResult::SendHeartbeatRequest;
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in associated state");
                        }
                    }
                }
                PfcpSmResult::Ok
            }
            SgwuEventId::SxaNoHeartbeat => {
                log::warn!("No Heartbeat from SGW-C {}", self.node.addr);
                self.state = PfcpState::WillAssociate;
                PfcpSmResult::StateChanged(PfcpState::WillAssociate)
            }
        }
    }

    /// Handle message in associated state
    fn handle_associated_message(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        if let Some(ref pfcp) = event.pfcp {
            if let Some(ref pkbuf) = pfcp.pkbuf {
                if !pkbuf.is_empty() {
                    let msg_type = pkbuf[0];
                    match msg_type {
                        pfcp_message_type::HEARTBEAT_REQUEST => {
                            log::debug!("PFCP: Handling heartbeat request");
                            if self.node.restoration_required {
                                if self.node.t_association.is_some() {
                                    // Need to re-associate first
                                    self.state = PfcpState::WillAssociate;
                                    return PfcpSmResult::StateChanged(PfcpState::WillAssociate);
                                } else {
                                    self.pfcp_restoration();
                                    self.node.restoration_required = false;
                                    log::error!("PFCP restoration");
                                }
                            }
                            return PfcpSmResult::SendHeartbeatResponse;
                        }
                        pfcp_message_type::HEARTBEAT_RESPONSE => {
                            log::debug!("PFCP: Handling heartbeat response");
                            if self.node.restoration_required {
                                if self.node.t_association.is_some() {
                                    self.state = PfcpState::WillAssociate;
                                    return PfcpSmResult::StateChanged(PfcpState::WillAssociate);
                                } else {
                                    self.pfcp_restoration();
                                    self.node.restoration_required = false;
                                    log::error!("PFCP restoration");
                                }
                            }
                            return PfcpSmResult::Ok;
                        }
                        pfcp_message_type::ASSOCIATION_SETUP_REQUEST => {
                            log::warn!("PFCP[REQ] has already been associated {}", self.node.addr);
                            return PfcpSmResult::SendAssociationSetupResponse;
                        }
                        pfcp_message_type::ASSOCIATION_SETUP_RESPONSE => {
                            log::warn!("PFCP[RSP] has already been associated {}", self.node.addr);
                            return PfcpSmResult::Ok;
                        }
                        pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST => {
                            log::debug!("PFCP: Handling session establishment request");
                            return PfcpSmResult::HandleSessionEstablishment;
                        }
                        pfcp_message_type::SESSION_MODIFICATION_REQUEST => {
                            log::debug!("PFCP: Handling session modification request");
                            return PfcpSmResult::HandleSessionModification;
                        }
                        pfcp_message_type::SESSION_DELETION_REQUEST => {
                            log::debug!("PFCP: Handling session deletion request");
                            return PfcpSmResult::HandleSessionDeletion;
                        }
                        pfcp_message_type::SESSION_REPORT_RESPONSE => {
                            log::debug!("PFCP: Handling session report response");
                            return PfcpSmResult::HandleSessionReportResponse;
                        }
                        _ => {
                            log::error!("Not implemented PFCP message type {msg_type}");
                        }
                    }
                }
            }
        }
        PfcpSmResult::Ok
    }

    /// Exception state handler
    /// Port of sgwu_pfcp_state_exception from pfcp-sm.c
    fn state_exception(&mut self, event: &SgwuEvent) -> PfcpSmResult {
        match event.id {
            SgwuEventId::FsmEntry | SgwuEventId::FsmExit => {
                PfcpSmResult::Ok
            }
            _ => {
                log::error!("Unknown event {} in exception state", event.name());
                PfcpSmResult::Ok
            }
        }
    }

    /// PFCP restoration - remove all sessions for this node
    /// Port of pfcp_restoration from pfcp-sm.c
    fn pfcp_restoration(&self) {
        log::info!("PFCP restoration for node {}", self.node.id);
        sgwu_self().sess_remove_all_for_pfcp_node(self.node.id);
    }

    /// Transition to exception state
    pub fn transition_to_exception(&mut self) {
        self.state = PfcpState::Exception;
        log::error!("PFCP state machine exception");
    }

    /// Set node address
    pub fn set_node_addr(&mut self, addr: &str) {
        self.node.addr = addr.to_string();
    }

    /// Set association timer
    pub fn set_association_timer(&mut self, timer_id: u64) {
        self.node.t_association = Some(timer_id);
    }

    /// Set no heartbeat timer
    pub fn set_no_heartbeat_timer(&mut self, timer_id: u64) {
        self.node.t_no_heartbeat = Some(timer_id);
    }

    /// Set restoration required flag
    pub fn set_restoration_required(&mut self, required: bool) {
        self.node.restoration_required = required;
    }
}

// ============================================================================
// State Machine Result
// ============================================================================

/// Result of PFCP state machine dispatch
#[derive(Debug, Clone, PartialEq)]
pub enum PfcpSmResult {
    /// Operation completed successfully
    Ok,
    /// State changed
    StateChanged(PfcpState),
    /// Send association setup request
    SendAssociationSetupRequest,
    /// Send association setup response
    SendAssociationSetupResponse,
    /// Send heartbeat request
    SendHeartbeatRequest,
    /// Send heartbeat response
    SendHeartbeatResponse,
    /// Handle session establishment
    HandleSessionEstablishment,
    /// Handle session modification
    HandleSessionModification,
    /// Handle session deletion
    HandleSessionDeletion,
    /// Handle session report response
    HandleSessionReportResponse,
    /// Error occurred
    Error(String),
}

// ============================================================================
// Debug Helper
// ============================================================================

/// Debug helper for PFCP state machine events
fn pfcp_sm_debug(event: &SgwuEvent, node: &PfcpNodeInfo) {
    log::trace!("PFCP SM [node {}]: Event {}", node.id, event.name());
    if let Some(timer_id) = event.timer_id {
        log::trace!("  Timer: {}", timer_id.name());
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfcp_sm_init() {
        let mut sm = PfcpStateMachine::new(1);
        assert!(sm.is_initial());

        // Dispatch entry event to transition to will_associate
        let event = SgwuEvent::entry();
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::StateChanged(PfcpState::WillAssociate));
        assert!(sm.is_will_associate());
    }

    #[test]
    fn test_pfcp_sm_association() {
        let mut sm = PfcpStateMachine::new(1);
        
        // Transition to will_associate
        sm.dispatch(&SgwuEvent::entry());
        assert!(sm.is_will_associate());

        // Simulate association setup response
        let event = SgwuEvent::sxa_message(
            1, 1, 
            vec![pfcp_message_type::ASSOCIATION_SETUP_RESPONSE]
        );
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::StateChanged(PfcpState::Associated));
        assert!(sm.is_associated());
    }

    #[test]
    fn test_pfcp_sm_no_heartbeat() {
        let mut sm = PfcpStateMachine::new(1);
        
        // Transition to associated
        sm.dispatch(&SgwuEvent::entry());
        let event = SgwuEvent::sxa_message(
            1, 1, 
            vec![pfcp_message_type::ASSOCIATION_SETUP_RESPONSE]
        );
        sm.dispatch(&event);
        assert!(sm.is_associated());

        // No heartbeat event should transition back to will_associate
        let event = SgwuEvent::sxa_no_heartbeat(1);
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::StateChanged(PfcpState::WillAssociate));
        assert!(sm.is_will_associate());
    }

    #[test]
    fn test_pfcp_sm_session_messages() {
        let mut sm = PfcpStateMachine::new(1);
        
        // Transition to associated
        sm.dispatch(&SgwuEvent::entry());
        let event = SgwuEvent::sxa_message(
            1, 1, 
            vec![pfcp_message_type::ASSOCIATION_SETUP_RESPONSE]
        );
        sm.dispatch(&event);
        assert!(sm.is_associated());

        // Test session establishment
        let event = SgwuEvent::sxa_message(
            1, 2, 
            vec![pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST]
        );
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::HandleSessionEstablishment);

        // Test session modification
        let event = SgwuEvent::sxa_message(
            1, 3, 
            vec![pfcp_message_type::SESSION_MODIFICATION_REQUEST]
        );
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::HandleSessionModification);

        // Test session deletion
        let event = SgwuEvent::sxa_message(
            1, 4, 
            vec![pfcp_message_type::SESSION_DELETION_REQUEST]
        );
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::HandleSessionDeletion);
    }

    #[test]
    fn test_pfcp_sm_heartbeat() {
        let mut sm = PfcpStateMachine::new(1);
        
        // Transition to associated
        sm.dispatch(&SgwuEvent::entry());
        let event = SgwuEvent::sxa_message(
            1, 1, 
            vec![pfcp_message_type::ASSOCIATION_SETUP_RESPONSE]
        );
        sm.dispatch(&event);

        // Heartbeat request should return response action
        let event = SgwuEvent::sxa_message(
            1, 5, 
            vec![pfcp_message_type::HEARTBEAT_REQUEST]
        );
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::SendHeartbeatResponse);

        // Timer expiry should trigger heartbeat request
        let event = SgwuEvent::sxa_timer(SgwuTimerId::NoHeartbeat, Some(1));
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::SendHeartbeatRequest);
    }

    #[test]
    fn test_pfcp_sm_exception() {
        let mut sm = PfcpStateMachine::new(1);
        sm.transition_to_exception();
        assert!(sm.is_exception());

        // Events in exception state should be handled gracefully
        let event = SgwuEvent::entry();
        let result = sm.dispatch(&event);
        assert_eq!(result, PfcpSmResult::Ok);
    }

    #[test]
    fn test_pfcp_node_info() {
        let mut sm = PfcpStateMachine::new(100);
        assert_eq!(sm.node().id, 100);

        sm.set_node_addr("192.168.1.1:8805");
        assert_eq!(sm.node().addr, "192.168.1.1:8805");

        sm.set_association_timer(1);
        assert_eq!(sm.node().t_association, Some(1));

        sm.set_no_heartbeat_timer(2);
        assert_eq!(sm.node().t_no_heartbeat, Some(2));

        sm.set_restoration_required(true);
        assert!(sm.node().restoration_required);
    }
}
