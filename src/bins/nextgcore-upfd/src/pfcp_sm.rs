//! UPF PFCP State Machine
//!
//! Port of src/upf/pfcp-sm.c - PFCP state machine for UPF

use crate::event::{UpfEvent, UpfEventId, UpfTimerId};

// ============================================================================
// PFCP Message Types (from ogs-pfcp)
// ============================================================================

/// PFCP message types
pub mod pfcp_msg_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const PFD_MANAGEMENT_REQUEST: u8 = 3;
    pub const PFD_MANAGEMENT_RESPONSE: u8 = 4;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    pub const VERSION_NOT_SUPPORTED_RESPONSE: u8 = 11;
    pub const NODE_REPORT_REQUEST: u8 = 12;
    pub const NODE_REPORT_RESPONSE: u8 = 13;
    pub const SESSION_SET_DELETION_REQUEST: u8 = 14;
    pub const SESSION_SET_DELETION_RESPONSE: u8 = 15;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP FSM States
// ============================================================================

/// PFCP FSM state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfcpState {
    /// Initial state
    Initial,
    /// Will associate state (attempting association)
    WillAssociate,
    /// Associated state (association established)
    Associated,
    /// Final state
    Final,
    /// Exception state
    Exception,
}

impl Default for PfcpState {
    fn default() -> Self {
        Self::Initial
    }
}

// ============================================================================
// PFCP State Machine Context
// ============================================================================

/// PFCP state machine context
/// Port of PFCP node state machine from pfcp-sm.c
#[derive(Debug)]
pub struct PfcpSmContext {
    /// Current state
    pub state: PfcpState,
    /// PFCP node ID
    pub node_id: u64,
    /// Association timer active
    pub association_timer_active: bool,
    /// No heartbeat timer active
    pub no_heartbeat_timer_active: bool,
    /// Restoration required flag
    pub restoration_required: bool,
    /// Has association timer (node initiates association)
    pub has_association_timer: bool,
}

impl Default for PfcpSmContext {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PfcpSmContext {
    /// Create a new PFCP state machine context
    pub fn new(node_id: u64) -> Self {
        Self {
            state: PfcpState::Initial,
            node_id,
            association_timer_active: false,
            no_heartbeat_timer_active: false,
            restoration_required: false,
            has_association_timer: false,
        }
    }

    /// Initialize the state machine
    /// Port of upf_pfcp_state_initial from pfcp-sm.c
    pub fn init(&mut self) {
        log::debug!("PFCP SM: init for node {}", self.node_id);
        self.state = PfcpState::Initial;
    }

    /// Finalize the state machine
    /// Port of upf_pfcp_state_final from pfcp-sm.c
    pub fn fini(&mut self) {
        log::debug!("PFCP SM: fini for node {}", self.node_id);
        self.no_heartbeat_timer_active = false;
        self.state = PfcpState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!(
            "PFCP SM: dispatch event {:?} in state {:?} for node {}",
            event.id,
            self.state,
            self.node_id
        );

        match self.state {
            PfcpState::Initial => self.state_initial(event),
            PfcpState::WillAssociate => self.state_will_associate(event),
            PfcpState::Associated => self.state_associated(event),
            PfcpState::Final => self.state_final(event),
            PfcpState::Exception => self.state_exception(event),
        }
    }

    /// Initial state handler
    /// Port of upf_pfcp_state_initial from pfcp-sm.c
    fn state_initial(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!("upf_pfcp_state_initial: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                // Create no heartbeat timer
                self.no_heartbeat_timer_active = false;
                // Transition to will_associate
                self.state = PfcpState::WillAssociate;
                PfcpSmResult::Transition(PfcpState::WillAssociate)
            }
            UpfEventId::FsmExit => PfcpSmResult::Ok,
            _ => {
                log::warn!("Unexpected event {:?} in initial state", event.id);
                PfcpSmResult::Ok
            }
        }
    }

    /// Final state handler
    /// Port of upf_pfcp_state_final from pfcp-sm.c
    fn state_final(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!("upf_pfcp_state_final: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                // Delete no heartbeat timer
                self.no_heartbeat_timer_active = false;
                PfcpSmResult::Ok
            }
            UpfEventId::FsmExit => PfcpSmResult::Ok,
            _ => PfcpSmResult::Ok,
        }
    }

    /// Will associate state handler
    /// Port of upf_pfcp_state_will_associate from pfcp-sm.c
    fn state_will_associate(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!("upf_pfcp_state_will_associate: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                if self.has_association_timer {
                    // Start association timer
                    self.association_timer_active = true;
                    // Send association setup request
                    log::info!("PFCP: Sending association setup request to node {}", self.node_id);
                    PfcpSmResult::SendAssociationSetupRequest
                } else {
                    PfcpSmResult::Ok
                }
            }
            UpfEventId::FsmExit => {
                if self.has_association_timer {
                    // Stop association timer
                    self.association_timer_active = false;
                }
                PfcpSmResult::Ok
            }
            UpfEventId::N4Timer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        UpfTimerId::Association => {
                            log::warn!("PFCP: Retry association with node {}", self.node_id);
                            // Restart association timer and resend request
                            self.association_timer_active = true;
                            PfcpSmResult::SendAssociationSetupRequest
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in will_associate state");
                            PfcpSmResult::Ok
                        }
                    }
                } else {
                    PfcpSmResult::Ok
                }
            }
            UpfEventId::N4Message => {
                // Handle PFCP message
                self.handle_will_associate_message(event)
            }
            _ => {
                log::error!("Unknown event {:?} in will_associate state", event.id);
                PfcpSmResult::Ok
            }
        }
    }

    /// Handle message in will_associate state
    fn handle_will_associate_message(&mut self, event: &UpfEvent) -> PfcpSmResult {
        // In real implementation, would parse the message type from pkbuf
        // For now, we simulate based on event data
        if let Some(ref pfcp) = event.pfcp {
            if let Some(ref pkbuf) = pfcp.pkbuf {
                if !pkbuf.is_empty() {
                    let msg_type = pkbuf[0];
                    match msg_type {
                        pfcp_msg_type::HEARTBEAT_REQUEST => {
                            log::debug!("PFCP: Handling heartbeat request");
                            PfcpSmResult::HandleHeartbeatRequest
                        }
                        pfcp_msg_type::HEARTBEAT_RESPONSE => {
                            log::debug!("PFCP: Handling heartbeat response");
                            PfcpSmResult::HandleHeartbeatResponse
                        }
                        pfcp_msg_type::ASSOCIATION_SETUP_REQUEST => {
                            log::info!("PFCP: Handling association setup request");
                            self.state = PfcpState::Associated;
                            PfcpSmResult::HandleAssociationSetupRequest
                        }
                        pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE => {
                            log::info!("PFCP: Handling association setup response");
                            self.state = PfcpState::Associated;
                            PfcpSmResult::HandleAssociationSetupResponse
                        }
                        _ => {
                            log::warn!("Cannot handle PFCP message type {msg_type} in will_associate");
                            PfcpSmResult::Ok
                        }
                    }
                } else {
                    PfcpSmResult::Ok
                }
            } else {
                PfcpSmResult::Ok
            }
        } else {
            PfcpSmResult::Ok
        }
    }

    /// Associated state handler
    /// Port of upf_pfcp_state_associated from pfcp-sm.c
    fn state_associated(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!("upf_pfcp_state_associated: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => {
                log::info!("PFCP: Associated with node {}", self.node_id);
                // Start no heartbeat timer
                self.no_heartbeat_timer_active = true;
                // Send heartbeat request
                if self.restoration_required {
                    // Perform PFCP restoration
                    log::error!("PFCP restoration required");
                    self.restoration_required = false;
                    PfcpSmResult::PerformRestoration
                } else {
                    PfcpSmResult::SendHeartbeatRequest
                }
            }
            UpfEventId::FsmExit => {
                log::info!("PFCP: De-associated from node {}", self.node_id);
                // Stop no heartbeat timer
                self.no_heartbeat_timer_active = false;
                PfcpSmResult::Ok
            }
            UpfEventId::N4Message => {
                self.handle_associated_message(event)
            }
            UpfEventId::N4Timer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        UpfTimerId::NoHeartbeat => {
                            log::debug!("PFCP: No heartbeat timer expired, sending heartbeat");
                            PfcpSmResult::SendHeartbeatRequest
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in associated state");
                            PfcpSmResult::Ok
                        }
                    }
                } else {
                    PfcpSmResult::Ok
                }
            }
            UpfEventId::N4NoHeartbeat => {
                log::warn!("PFCP: No heartbeat from node {}", self.node_id);
                // Transition back to will_associate
                self.state = PfcpState::WillAssociate;
                PfcpSmResult::Transition(PfcpState::WillAssociate)
            }
        }
    }

    /// Handle message in associated state
    fn handle_associated_message(&mut self, event: &UpfEvent) -> PfcpSmResult {
        if let Some(ref pfcp) = event.pfcp {
            if let Some(ref pkbuf) = pfcp.pkbuf {
                if !pkbuf.is_empty() {
                    let msg_type = pkbuf[0];
                    match msg_type {
                        pfcp_msg_type::HEARTBEAT_REQUEST => {
                            log::debug!("PFCP: Handling heartbeat request");
                            let result = PfcpSmResult::HandleHeartbeatRequest;
                            // Check if restoration required after heartbeat
                            if self.restoration_required {
                                if self.has_association_timer {
                                    self.state = PfcpState::WillAssociate;
                                    return PfcpSmResult::Transition(PfcpState::WillAssociate);
                                } else {
                                    self.restoration_required = false;
                                    return PfcpSmResult::PerformRestoration;
                                }
                            }
                            result
                        }
                        pfcp_msg_type::HEARTBEAT_RESPONSE => {
                            log::debug!("PFCP: Handling heartbeat response");
                            let result = PfcpSmResult::HandleHeartbeatResponse;
                            // Check if restoration required after heartbeat
                            if self.restoration_required {
                                if self.has_association_timer {
                                    self.state = PfcpState::WillAssociate;
                                    return PfcpSmResult::Transition(PfcpState::WillAssociate);
                                } else {
                                    self.restoration_required = false;
                                    return PfcpSmResult::PerformRestoration;
                                }
                            }
                            result
                        }
                        pfcp_msg_type::ASSOCIATION_SETUP_REQUEST => {
                            log::warn!("PFCP: Already associated, handling association setup request");
                            PfcpSmResult::HandleAssociationSetupRequest
                        }
                        pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE => {
                            log::warn!("PFCP: Already associated, handling association setup response");
                            PfcpSmResult::HandleAssociationSetupResponse
                        }
                        pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST => {
                            log::debug!("PFCP: Handling session establishment request");
                            PfcpSmResult::HandleSessionEstablishmentRequest
                        }
                        pfcp_msg_type::SESSION_MODIFICATION_REQUEST => {
                            log::debug!("PFCP: Handling session modification request");
                            PfcpSmResult::HandleSessionModificationRequest
                        }
                        pfcp_msg_type::SESSION_DELETION_REQUEST => {
                            log::debug!("PFCP: Handling session deletion request");
                            PfcpSmResult::HandleSessionDeletionRequest
                        }
                        pfcp_msg_type::SESSION_REPORT_RESPONSE => {
                            log::debug!("PFCP: Handling session report response");
                            PfcpSmResult::HandleSessionReportResponse
                        }
                        _ => {
                            log::error!("Not implemented PFCP message type {msg_type}");
                            PfcpSmResult::Ok
                        }
                    }
                } else {
                    PfcpSmResult::Ok
                }
            } else {
                PfcpSmResult::Ok
            }
        } else {
            PfcpSmResult::Ok
        }
    }

    /// Exception state handler
    /// Port of upf_pfcp_state_exception from pfcp-sm.c
    fn state_exception(&mut self, event: &UpfEvent) -> PfcpSmResult {
        log::debug!("upf_pfcp_state_exception: {:?}", event.id);

        match event.id {
            UpfEventId::FsmEntry => PfcpSmResult::Ok,
            UpfEventId::FsmExit => PfcpSmResult::Ok,
            _ => {
                log::error!("Unknown event {:?} in exception state", event.id);
                PfcpSmResult::Ok
            }
        }
    }

    /// Check if in exception state
    pub fn is_exception(&self) -> bool {
        self.state == PfcpState::Exception
    }

    /// Check if in final state
    pub fn is_final(&self) -> bool {
        self.state == PfcpState::Final
    }

    /// Check if associated
    pub fn is_associated(&self) -> bool {
        self.state == PfcpState::Associated
    }

    /// Set restoration required flag
    pub fn set_restoration_required(&mut self, required: bool) {
        self.restoration_required = required;
    }
}

// ============================================================================
// State Machine Result
// ============================================================================

/// Result of PFCP state machine dispatch
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfcpSmResult {
    /// Operation completed successfully
    Ok,
    /// State transition occurred
    Transition(PfcpState),
    /// Send association setup request
    SendAssociationSetupRequest,
    /// Send heartbeat request
    SendHeartbeatRequest,
    /// Handle heartbeat request
    HandleHeartbeatRequest,
    /// Handle heartbeat response
    HandleHeartbeatResponse,
    /// Handle association setup request
    HandleAssociationSetupRequest,
    /// Handle association setup response
    HandleAssociationSetupResponse,
    /// Handle session establishment request
    HandleSessionEstablishmentRequest,
    /// Handle session modification request
    HandleSessionModificationRequest,
    /// Handle session deletion request
    HandleSessionDeletionRequest,
    /// Handle session report response
    HandleSessionReportResponse,
    /// Perform PFCP restoration
    PerformRestoration,
    /// Error occurred
    Error(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PfcpEventData;

    #[test]
    fn test_pfcp_sm_init() {
        let mut sm = PfcpSmContext::new(1);
        assert_eq!(sm.state, PfcpState::Initial);
        
        sm.init();
        assert_eq!(sm.state, PfcpState::Initial);
    }

    #[test]
    fn test_pfcp_sm_fini() {
        let mut sm = PfcpSmContext::new(1);
        sm.fini();
        assert_eq!(sm.state, PfcpState::Final);
        assert!(!sm.no_heartbeat_timer_active);
    }

    #[test]
    fn test_pfcp_sm_initial_to_will_associate() {
        let mut sm = PfcpSmContext::new(1);
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::Transition(PfcpState::WillAssociate));
        assert_eq!(sm.state, PfcpState::WillAssociate);
    }

    #[test]
    fn test_pfcp_sm_will_associate_entry_with_timer() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::WillAssociate;
        sm.has_association_timer = true;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::SendAssociationSetupRequest);
        assert!(sm.association_timer_active);
    }

    #[test]
    fn test_pfcp_sm_will_associate_association_timer() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::WillAssociate;
        sm.has_association_timer = true;
        
        let event = UpfEvent::n4_timer(UpfTimerId::Association, Some(1));
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::SendAssociationSetupRequest);
    }

    #[test]
    fn test_pfcp_sm_will_associate_to_associated() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::WillAssociate;
        
        // Simulate association setup response
        let mut event = UpfEvent::new(UpfEventId::N4Message);
        event.pfcp = Some(PfcpEventData {
            pfcp_node_id: Some(1),
            pfcp_xact_id: Some(1),
            pkbuf: Some(vec![pfcp_msg_type::ASSOCIATION_SETUP_RESPONSE]),
        });
        
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::HandleAssociationSetupResponse);
        assert_eq!(sm.state, PfcpState::Associated);
    }

    #[test]
    fn test_pfcp_sm_associated_entry() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::SendHeartbeatRequest);
        assert!(sm.no_heartbeat_timer_active);
    }

    #[test]
    fn test_pfcp_sm_associated_no_heartbeat_timer() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let event = UpfEvent::n4_timer(UpfTimerId::NoHeartbeat, Some(1));
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::SendHeartbeatRequest);
    }

    #[test]
    fn test_pfcp_sm_associated_no_heartbeat_event() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let event = UpfEvent::n4_no_heartbeat(1);
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::Transition(PfcpState::WillAssociate));
        assert_eq!(sm.state, PfcpState::WillAssociate);
    }

    #[test]
    fn test_pfcp_sm_associated_session_establishment() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let mut event = UpfEvent::new(UpfEventId::N4Message);
        event.pfcp = Some(PfcpEventData {
            pfcp_node_id: Some(1),
            pfcp_xact_id: Some(1),
            pkbuf: Some(vec![pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST]),
        });
        
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::HandleSessionEstablishmentRequest);
    }

    #[test]
    fn test_pfcp_sm_associated_session_modification() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let mut event = UpfEvent::new(UpfEventId::N4Message);
        event.pfcp = Some(PfcpEventData {
            pfcp_node_id: Some(1),
            pfcp_xact_id: Some(1),
            pkbuf: Some(vec![pfcp_msg_type::SESSION_MODIFICATION_REQUEST]),
        });
        
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::HandleSessionModificationRequest);
    }

    #[test]
    fn test_pfcp_sm_associated_session_deletion() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        
        let mut event = UpfEvent::new(UpfEventId::N4Message);
        event.pfcp = Some(PfcpEventData {
            pfcp_node_id: Some(1),
            pfcp_xact_id: Some(1),
            pkbuf: Some(vec![pfcp_msg_type::SESSION_DELETION_REQUEST]),
        });
        
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::HandleSessionDeletionRequest);
    }

    #[test]
    fn test_pfcp_sm_restoration_required() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Associated;
        sm.restoration_required = true;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::PerformRestoration);
        assert!(!sm.restoration_required);
    }

    #[test]
    fn test_pfcp_sm_state_checks() {
        let mut sm = PfcpSmContext::new(1);
        
        sm.state = PfcpState::Associated;
        assert!(sm.is_associated());
        assert!(!sm.is_final());
        assert!(!sm.is_exception());
        
        sm.state = PfcpState::Final;
        assert!(!sm.is_associated());
        assert!(sm.is_final());
        assert!(!sm.is_exception());
        
        sm.state = PfcpState::Exception;
        assert!(!sm.is_associated());
        assert!(!sm.is_final());
        assert!(sm.is_exception());
    }

    #[test]
    fn test_pfcp_sm_exception_state() {
        let mut sm = PfcpSmContext::new(1);
        sm.state = PfcpState::Exception;
        
        let event = UpfEvent::entry();
        let result = sm.dispatch(&event);
        
        assert_eq!(result, PfcpSmResult::Ok);
    }
}
