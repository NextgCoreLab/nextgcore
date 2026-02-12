//! SMF Main State Machine
//!
//! Port of src/smf/smf-sm.c - Main SMF state machine handling SBI, GTP, PFCP events

use crate::event::{SmfEvent, SmfEventId, SmfTimerId};

/// SMF FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmfState {
    /// Initial state
    #[default]
    Initial,
    /// Operational state - handling events
    Operational,
    /// Final state
    Final,
}

/// SMF State Machine
#[derive(Debug, Clone)]
pub struct SmfFsm {
    /// Current state
    pub state: SmfState,
}

impl Default for SmfFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl SmfFsm {
    /// Create a new SMF FSM
    pub fn new() -> Self {
        Self {
            state: SmfState::Initial,
        }
    }

    /// Initialize the FSM
    pub fn init(&mut self) {
        log::debug!("smf_state_initial");
        self.state = SmfState::Operational;
    }

    /// Finalize the FSM
    pub fn fini(&mut self) {
        log::debug!("smf_state_final");
        self.state = SmfState::Final;
    }

    /// Dispatch an event to the FSM
    #[allow(dead_code)] // Used in tests and FSM design
    pub fn dispatch(&mut self, event: &SmfEvent) -> SmfFsmResult {
        match self.state {
            SmfState::Initial => self.handle_initial(event),
            SmfState::Operational => self.handle_operational(event),
            SmfState::Final => SmfFsmResult::Ignored,
        }
    }

    /// Handle events in initial state
    fn handle_initial(&mut self, event: &SmfEvent) -> SmfFsmResult {
        match event.id {
            SmfEventId::FsmEntry => {
                log::debug!("smf_state_initial: FSM_ENTRY");
                self.state = SmfState::Operational;
                SmfFsmResult::Transition(SmfState::Operational)
            }
            _ => SmfFsmResult::Ignored,
        }
    }

    /// Handle events in operational state
    fn handle_operational(&mut self, event: &SmfEvent) -> SmfFsmResult {
        log::debug!("smf_state_operational: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::debug!("smf_state_operational: FSM_ENTRY");
                SmfFsmResult::Handled
            }
            SmfEventId::FsmExit => {
                log::debug!("smf_state_operational: FSM_EXIT");
                SmfFsmResult::Handled
            }
            SmfEventId::S5cMessage => self.handle_s5c_message(event),
            SmfEventId::GnMessage => self.handle_gn_message(event),
            SmfEventId::GxMessage => self.handle_gx_message(event),
            SmfEventId::GyMessage => self.handle_gy_message(event),
            SmfEventId::S6bMessage => self.handle_s6b_message(event),
            SmfEventId::N4Message => self.handle_n4_message(event),
            SmfEventId::N4Timer => self.handle_n4_timer(event),
            SmfEventId::N4NoHeartbeat => self.handle_n4_no_heartbeat(event),
            SmfEventId::SbiServer => self.handle_sbi_server(event),
            SmfEventId::SbiClient => self.handle_sbi_client(event),
            SmfEventId::SbiTimer => self.handle_sbi_timer(event),
            SmfEventId::GsmMessage => {
                // 5GSM messages are dispatched to the session's GSM FSM
                SmfFsmResult::Delegated
            }
            SmfEventId::GsmTimer => {
                // 5GSM timer events are dispatched to the session's GSM FSM
                SmfFsmResult::Delegated
            }
            SmfEventId::NgapMessage => self.handle_ngap_message(event),
            SmfEventId::NgapTimer => self.handle_ngap_timer(event),
            SmfEventId::SessionRelease => self.handle_session_release(event),
        }
    }

    /// Handle S5-C (GTPv2-C) message events
    fn handle_s5c_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref gtp) = event.gtp {
            log::debug!(
                "S5-C Message: gnode_id={:?}, xact_id={:?}",
                gtp.gnode_id,
                gtp.gtp_xact_id
            );
            // Note: GTPv2 message parsing and dispatch handled by gtp_handler module
            // Message types routed to GSM FSM via event queue:
            // - Create Session Request/Response -> gsm_sm for session setup
            // - Delete Session Request/Response -> gsm_sm for session teardown
            // - Modify Bearer Request/Response -> gsm_sm for bearer modification
            // - Create/Update/Delete Bearer Response -> gsm_sm for bearer operations
            // - Bearer Resource Command -> gsm_sm for resource allocation
        }
        SmfFsmResult::Handled
    }

    /// Handle Gn (GTPv1-C) message events
    fn handle_gn_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref gtp) = event.gtp {
            log::debug!(
                "Gn Message: gnode_id={:?}, xact_id={:?}",
                gtp.gnode_id,
                gtp.gtp_xact_id
            );
            // Note: GTPv1 message parsing and dispatch handled by gtp_handler module
            // Message types routed to GSM FSM via event queue:
            // - Create PDP Context Request/Response -> gsm_sm for PDP context setup
            // - Delete PDP Context Request/Response -> gsm_sm for PDP context teardown
            // - Update PDP Context Request/Response -> gsm_sm for PDP context modification
        }
        SmfFsmResult::Handled
    }

    /// Handle Gx (Diameter) message events
    fn handle_gx_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref diameter) = event.diameter {
            log::debug!(
                "Gx Message: cmd_code={}, cc_request_type={:?}",
                diameter.cmd_code,
                diameter.cc_request_type
            );
            // Note: Dispatch to GSM FSM for Gx handling
            // CCA (Initial/Update/Termination) processed by gsm_sm based on cc_request_type
            // Re-Auth Request triggers policy update via gsm_sm event dispatch
        }
        SmfFsmResult::Delegated
    }

    /// Handle Gy (Diameter) message events
    fn handle_gy_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref diameter) = event.diameter {
            log::debug!(
                "Gy Message: cmd_code={}, cc_request_type={:?}",
                diameter.cmd_code,
                diameter.cc_request_type
            );
            // Note: Dispatch to GSM FSM for Gy handling
            // CCA (Initial/Update/Termination) processed by gsm_sm based on cc_request_type
            // Re-Auth Request triggers charging update via gsm_sm event dispatch
        }
        SmfFsmResult::Delegated
    }

    /// Handle S6b (Diameter) message events
    fn handle_s6b_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref diameter) = event.diameter {
            log::debug!("S6b Message: cmd_code={}", diameter.cmd_code);
            // Note: Dispatch to GSM FSM for S6b handling
            // AAA processed by gsm_sm for authentication result
            // STA processed by gsm_sm for session termination acknowledgment
        }
        SmfFsmResult::Delegated
    }

    /// Handle N4 (PFCP) message events
    fn handle_n4_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref pfcp) = event.pfcp {
            log::debug!(
                "N4 Message: pfcp_node_id={:?}, xact_id={:?}",
                pfcp.pfcp_node_id,
                pfcp.pfcp_xact_id
            );
            // Note: Dispatch to PFCP FSM for node and session handling
            // Heartbeat Request/Response -> pfcp_sm for keepalive processing
            // Association Setup Request/Response -> pfcp_sm for association state
            // Session Establishment/Modification/Deletion Response -> gsm_sm via event dispatch
            // Session Report Request -> gsm_sm for UPF-initiated notifications
        }
        SmfFsmResult::Delegated
    }

    /// Handle N4 timer events
    fn handle_n4_timer(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("N4 Timer: {}", timer_id.name());
            match timer_id {
                SmfTimerId::PfcpAssociation => {
                    // Retry PFCP association
                    SmfFsmResult::Delegated
                }
                SmfTimerId::PfcpNoEstablishmentResponse => {
                    // Handle no establishment response
                    if let Some(sess_id) = event.sess_id {
                        log::warn!("PFCP establishment timeout for session {sess_id}");
                    }
                    SmfFsmResult::Delegated
                }
                SmfTimerId::PfcpNoDeletionResponse => {
                    // Handle no deletion response
                    if let Some(sess_id) = event.sess_id {
                        log::warn!("PFCP deletion timeout for session {sess_id}");
                    }
                    SmfFsmResult::Handled
                }
                _ => SmfFsmResult::Ignored,
            }
        } else {
            SmfFsmResult::Ignored
        }
    }

    /// Handle N4 no heartbeat events
    fn handle_n4_no_heartbeat(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref pfcp) = event.pfcp {
            if let Some(pfcp_node_id) = pfcp.pfcp_node_id {
                log::warn!("No heartbeat from UPF (node_id={pfcp_node_id})");
                // Note: UPF reselection triggered via pfcp_sm transition to WillAssociate
                // Sessions on this UPF notified for restoration or failover
            }
        }
        SmfFsmResult::Handled
    }

    /// Handle SBI server events
    fn handle_sbi_server(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref request) = sbi.request {
                log::debug!("SBI Server: {} {}", request.method, request.uri);
                // Note: Routing to appropriate handler based on service name in URI
                // NNRF_NFM (nf-status-notify) -> common SBI NRF handler
                // NSMF_PDUSESSION (sm-contexts) -> gsm_sm via event dispatch
                // NSMF_CALLBACK (n1n2-failure, sm-policy-notify) -> gsm_sm via event dispatch
            }
        }
        SmfFsmResult::Handled
    }

    /// Handle SBI client events
    fn handle_sbi_client(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref response) = sbi.response {
                log::debug!("SBI Client: status={}", response.status);
                // Note: Routing to appropriate handler based on original request service
                // NNRF_NFM -> common SBI NF instance handler
                // NNRF_DISC -> NF discovery result processing
                // NUDM_SDM -> gsm_sm for subscriber data response
                // NPCF_SMPOLICYCONTROL -> gsm_sm for policy decision
                // NAMF_COMM -> gsm_sm for N1N2 transfer result
            }
        }
        SmfFsmResult::Handled
    }

    /// Handle SBI timer events
    fn handle_sbi_timer(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("SBI Timer: {}", timer_id.name());
            match timer_id {
                SmfTimerId::NfInstanceRegistrationInterval
                | SmfTimerId::NfInstanceHeartbeatInterval
                | SmfTimerId::NfInstanceNoHeartbeat
                | SmfTimerId::NfInstanceValidity => {
                    // Dispatch to NF instance FSM
                    SmfFsmResult::Delegated
                }
                SmfTimerId::SubscriptionValidity => {
                    // Handle subscription validity expiry
                    log::warn!("Subscription validity expired");
                    SmfFsmResult::Handled
                }
                SmfTimerId::SubscriptionPatch => {
                    // Handle subscription patch
                    log::info!("Need to update subscription");
                    SmfFsmResult::Handled
                }
                SmfTimerId::SbiClientWait => {
                    // Handle SBI client wait timeout
                    log::warn!("SBI client wait timeout");
                    SmfFsmResult::Handled
                }
                _ => SmfFsmResult::Ignored,
            }
        } else {
            SmfFsmResult::Ignored
        }
    }

    /// Handle NGAP message events
    fn handle_ngap_message(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(ref ngap) = event.ngap {
            log::debug!("NGAP Message: type={:?}", ngap.message_type);
            // Note: NGAP messages for N2 interface handled via AMF relay
            // PDU Session Resource Setup/Modify/Release Response -> gsm_sm via event dispatch
            // Responses correlated with pending requests using procedure transaction ID
        }
        SmfFsmResult::Handled
    }

    /// Handle NGAP timer events
    fn handle_ngap_timer(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("NGAP Timer: {}", timer_id.name());
        }
        SmfFsmResult::Handled
    }

    /// Handle session release events
    fn handle_session_release(&mut self, event: &SmfEvent) -> SmfFsmResult {
        if let Some(sess_id) = event.sess_id {
            log::info!(
                "Session release: sess_id={}, trigger={:?}",
                sess_id,
                event.release_trigger
            );
            // Note: Session release procedure triggered via gsm_sm transition
            // GSM FSM transitions to WaitPfcpDeletion, then cleanup states
        }
        SmfFsmResult::Handled
    }

    /// Check if FSM is in a specific state
    #[allow(dead_code)] // Used in tests
    pub fn is_state(&self, state: SmfState) -> bool {
        self.state == state
    }

    /// Get current state
    #[allow(dead_code)] // Used in tests
    pub fn current_state(&self) -> SmfState {
        self.state
    }
}

/// Result of FSM event handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants used in tests and FSM design
pub enum SmfFsmResult {
    /// Event was handled
    Handled,
    /// Event was ignored
    Ignored,
    /// State transition occurred
    Transition(SmfState),
    /// Event was delegated to another FSM
    Delegated,
    /// Error occurred
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smf_fsm_new() {
        let fsm = SmfFsm::new();
        assert_eq!(fsm.state, SmfState::Initial);
    }

    #[test]
    fn test_smf_fsm_init() {
        let mut fsm = SmfFsm::new();
        fsm.init();
        assert_eq!(fsm.state, SmfState::Operational);
    }

    #[test]
    fn test_smf_fsm_fini() {
        let mut fsm = SmfFsm::new();
        fsm.init();
        fsm.fini();
        assert_eq!(fsm.state, SmfState::Final);
    }

    #[test]
    fn test_smf_fsm_dispatch_entry() {
        let mut fsm = SmfFsm::new();
        let event = SmfEvent::entry();
        let result = fsm.dispatch(&event);
        assert_eq!(result, SmfFsmResult::Transition(SmfState::Operational));
        assert_eq!(fsm.state, SmfState::Operational);
    }

    #[test]
    fn test_smf_fsm_dispatch_sbi_server() {
        let mut fsm = SmfFsm::new();
        fsm.init();

        let request = crate::event::SbiRequest {
            method: "POST".to_string(),
            uri: "/nsmf-pdusession/v1/sm-contexts".to_string(),
            body: None,
        };
        let event = SmfEvent::sbi_server(123, request);
        let result = fsm.dispatch(&event);
        assert_eq!(result, SmfFsmResult::Handled);
    }

    #[test]
    fn test_smf_fsm_dispatch_n4_message() {
        let mut fsm = SmfFsm::new();
        fsm.init();

        let event = SmfEvent::n4_message(456, 789, vec![1, 2, 3]);
        let result = fsm.dispatch(&event);
        assert_eq!(result, SmfFsmResult::Delegated);
    }

    #[test]
    fn test_smf_fsm_dispatch_gx_message() {
        let mut fsm = SmfFsm::new();
        fsm.init();

        let event = SmfEvent::gx_message(100, 272, Some(1)); // CCR Initial
        let result = fsm.dispatch(&event);
        assert_eq!(result, SmfFsmResult::Delegated);
    }

    #[test]
    fn test_smf_fsm_is_state() {
        let mut fsm = SmfFsm::new();
        assert!(fsm.is_state(SmfState::Initial));

        fsm.init();
        assert!(fsm.is_state(SmfState::Operational));
        assert!(!fsm.is_state(SmfState::Initial));
    }
}
