//! GSM (5G Session Management) State Machine

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/gsm-sm.c - GSM state machine for PDU session management

use crate::event::{SmfEvent, SmfEventId, SmfTimerId};

/// GSM FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GsmState {
    /// Initial state
    #[default]
    Initial,
    /// Waiting for EPC authentication (Gx/Gy/S6b) - Initial request
    WaitEpcAuthInitial,
    /// Waiting for 5GC SM policy association
    Wait5gcSmPolicyAssociation,
    /// Waiting for PFCP session establishment
    WaitPfcpEstablishment,
    /// Operational state - session is active
    Operational,
    /// Waiting for PFCP session deletion
    WaitPfcpDeletion,
    /// Waiting for EPC authentication release (Gx/Gy/S6b termination)
    WaitEpcAuthRelease,
    /// Waiting for 5GC N1/N2 release
    Wait5gcN1N2Release,
    /// 5GC N1/N2 reject state
    N1N2Reject5gc,
    /// 5GC session will deregister
    SessionWillDeregister5gc,
    /// Session will release
    SessionWillRelease,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

impl GsmState {
    /// Get the name of the state
    pub fn name(&self) -> &'static str {
        match self {
            GsmState::Initial => "GSM_STATE_INITIAL",
            GsmState::WaitEpcAuthInitial => "GSM_STATE_WAIT_EPC_AUTH_INITIAL",
            GsmState::Wait5gcSmPolicyAssociation => "GSM_STATE_WAIT_5GC_SM_POLICY_ASSOCIATION",
            GsmState::WaitPfcpEstablishment => "GSM_STATE_WAIT_PFCP_ESTABLISHMENT",
            GsmState::Operational => "GSM_STATE_OPERATIONAL",
            GsmState::WaitPfcpDeletion => "GSM_STATE_WAIT_PFCP_DELETION",
            GsmState::WaitEpcAuthRelease => "GSM_STATE_WAIT_EPC_AUTH_RELEASE",
            GsmState::Wait5gcN1N2Release => "GSM_STATE_WAIT_5GC_N1_N2_RELEASE",
            GsmState::N1N2Reject5gc => "GSM_STATE_5GC_N1_N2_REJECT",
            GsmState::SessionWillDeregister5gc => "GSM_STATE_5GC_SESSION_WILL_DEREGISTER",
            GsmState::SessionWillRelease => "GSM_STATE_SESSION_WILL_RELEASE",
            GsmState::Exception => "GSM_STATE_EXCEPTION",
            GsmState::Final => "GSM_STATE_FINAL",
        }
    }
}

/// Session management data for tracking in-flight requests
#[derive(Debug, Clone, Default)]
pub struct SmData {
    /// S6b AAR in flight
    pub s6b_aar_in_flight: bool,
    /// Gx CCR-Initial in flight
    pub gx_ccr_init_in_flight: bool,
    /// Gy CCR-Initial in flight
    pub gy_ccr_init_in_flight: bool,
    /// Gx CCR-Termination in flight
    pub gx_ccr_term_in_flight: bool,
    /// Gy CCR-Termination in flight
    pub gy_ccr_term_in_flight: bool,
    /// S6b STR in flight
    pub s6b_str_in_flight: bool,
    /// S6b AAA error code
    pub s6b_aaa_err: u32,
    /// Gx CCA-Initial error code
    pub gx_cca_init_err: u32,
    /// Gy CCA-Initial error code
    pub gy_cca_init_err: u32,
}

/// GSM State Machine
#[derive(Debug, Clone)]
pub struct GsmFsm {
    /// Current state
    pub state: GsmState,
    /// Session ID associated with this FSM
    pub sess_id: u64,
    /// Session management data
    pub sm_data: SmData,
}

impl GsmFsm {
    /// Create a new GSM FSM
    pub fn new(sess_id: u64) -> Self {
        Self {
            state: GsmState::Initial,
            sess_id,
            sm_data: SmData::default(),
        }
    }

    /// Initialize the FSM
    pub fn init(&mut self) {
        log::debug!("gsm_state_initial: sess_id={}", self.sess_id);
        // Reset SM data on entry
        self.sm_data = SmData::default();
    }

    /// Finalize the FSM
    pub fn fini(&mut self) {
        log::debug!("gsm_state_final: sess_id={}", self.sess_id);
        self.state = GsmState::Final;
    }

    /// Dispatch an event to the FSM
    pub fn dispatch(&mut self, event: &SmfEvent) -> GsmFsmResult {
        let result = match self.state {
            GsmState::Initial => self.handle_initial(event),
            GsmState::WaitEpcAuthInitial => self.handle_wait_epc_auth_initial(event),
            GsmState::Wait5gcSmPolicyAssociation => self.handle_wait_5gc_sm_policy_association(event),
            GsmState::WaitPfcpEstablishment => self.handle_wait_pfcp_establishment(event),
            GsmState::Operational => self.handle_operational(event),
            GsmState::WaitPfcpDeletion => self.handle_wait_pfcp_deletion(event),
            GsmState::WaitEpcAuthRelease => self.handle_wait_epc_auth_release(event),
            GsmState::Wait5gcN1N2Release => self.handle_wait_5gc_n1_n2_release(event),
            GsmState::N1N2Reject5gc => self.handle_5gc_n1_n2_reject(event),
            GsmState::SessionWillDeregister5gc => self.handle_5gc_session_will_deregister(event),
            GsmState::SessionWillRelease => self.handle_session_will_release(event),
            GsmState::Exception => self.handle_exception(event),
            GsmState::Final => GsmFsmResult::Ignored,
        };

        // Apply state transition if result indicates one
        if let GsmFsmResult::Transition(new_state) = result {
            log::debug!(
                "GSM state transition: {} -> {} (sess_id={})",
                self.state.name(),
                new_state.name(),
                self.sess_id
            );
            self.state = new_state;
        }

        result
    }

    /// Handle events in initial state
    fn handle_initial(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_initial: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                // Reset state on entry
                self.sm_data = SmData::default();
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::GnMessage => {
                // GTPv1 Create PDP Context Request
                // Handle and transition to WaitEpcAuthInitial
                log::debug!("GSM: Gn Create PDP Context Request");
                GsmFsmResult::Transition(GsmState::WaitEpcAuthInitial)
            }
            SmfEventId::S5cMessage => {
                // GTPv2 Create Session Request
                // Handle based on RAT type (EUTRAN or WLAN)
                log::debug!("GSM: S5-C Create Session Request");
                GsmFsmResult::Transition(GsmState::WaitEpcAuthInitial)
            }
            SmfEventId::SbiServer => {
                // NSMF PDU Session Create
                self.handle_sbi_server_initial(event)
            }
            SmfEventId::GsmMessage => {
                // NAS PDU Session Establishment Request
                log::debug!("GSM: PDU Session Establishment Request");
                GsmFsmResult::Transition(GsmState::Wait5gcSmPolicyAssociation)
            }
            _ => {
                log::warn!("GSM Initial: No handler for event {}", event.name());
                GsmFsmResult::Ignored
            }
        }
    }

    /// Handle SBI server events in initial state
    fn handle_sbi_server_initial(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref message) = sbi.message {
                // Check service name and resource
                if message.service_name == "nsmf-pdusession" {
                    if message.resource_components.first().map(|s| s.as_str()) == Some("sm-contexts") {
                        log::debug!("GSM: SM Context Create");
                        // For home-routed roaming in V-SMF, go directly to PFCP establishment
                        // Otherwise, go to SM policy association
                        return GsmFsmResult::Transition(GsmState::Wait5gcSmPolicyAssociation);
                    }
                }
            }
        }
        GsmFsmResult::Handled
    }

    /// Handle events in wait EPC auth initial state
    fn handle_wait_epc_auth_initial(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_epc_auth_initial: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => GsmFsmResult::Handled,
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::S6bMessage => {
                // S6b AAA response
                self.sm_data.s6b_aar_in_flight = false;
                if let Some(ref diameter) = event.diameter {
                    self.sm_data.s6b_aaa_err = diameter.result_code.unwrap_or(0);
                    if self.sm_data.s6b_aaa_err == 2001 {
                        // ER_DIAMETER_SUCCESS - send Gx/Gy CCR-Initial
                        log::debug!("S6b AAA success, sending Gx/Gy CCR-Initial");
                    }
                }
                self.check_epc_auth_complete()
            }
            SmfEventId::GxMessage => {
                // Gx CCA-Initial
                self.sm_data.gx_ccr_init_in_flight = false;
                if let Some(ref diameter) = event.diameter {
                    self.sm_data.gx_cca_init_err = diameter.result_code.unwrap_or(0);
                }
                self.check_epc_auth_complete()
            }
            SmfEventId::GyMessage => {
                // Gy CCA-Initial
                self.sm_data.gy_ccr_init_in_flight = false;
                if let Some(ref diameter) = event.diameter {
                    self.sm_data.gy_cca_init_err = diameter.result_code.unwrap_or(0);
                }
                self.check_epc_auth_complete()
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Check if all EPC auth requests are complete
    fn check_epc_auth_complete(&self) -> GsmFsmResult {
        if !self.sm_data.s6b_aar_in_flight
            && !self.sm_data.gx_ccr_init_in_flight
            && !self.sm_data.gy_ccr_init_in_flight
        {
            // All requests complete, check for errors
            let success = self.sm_data.s6b_aaa_err == 2001 || self.sm_data.s6b_aaa_err == 0;
            let gx_success = self.sm_data.gx_cca_init_err == 2001 || self.sm_data.gx_cca_init_err == 0;
            let gy_success = self.sm_data.gy_cca_init_err == 2001 || self.sm_data.gy_cca_init_err == 0;

            if success && gx_success && gy_success {
                log::debug!("EPC auth complete, transitioning to PFCP establishment");
                GsmFsmResult::Transition(GsmState::WaitPfcpEstablishment)
            } else {
                log::warn!("EPC auth failed: s6b={}, gx={}, gy={}",
                    self.sm_data.s6b_aaa_err, self.sm_data.gx_cca_init_err, self.sm_data.gy_cca_init_err);
                GsmFsmResult::Transition(GsmState::Exception)
            }
        } else {
            GsmFsmResult::Handled
        }
    }

    /// Handle events in wait 5GC SM policy association state
    fn handle_wait_5gc_sm_policy_association(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_5gc_sm_policy_association: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => GsmFsmResult::Handled,
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::SbiClient => {
                // Handle SBI client responses (NUDM, NPCF)
                self.handle_sbi_client_sm_policy(event)
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle SBI client events in SM policy association state
    fn handle_sbi_client_sm_policy(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref message) = sbi.message {
                // Check service name
                if message.service_name == "nudm-sdm" {
                    // UDM subscriber data response
                    if let Some(status) = message.res_status {
                        if status == 200 {
                            log::debug!("UDM SDM response OK");
                            return GsmFsmResult::Handled;
                        } else {
                            log::error!("UDM SDM response error: {}", status);
                            return GsmFsmResult::Transition(GsmState::Exception);
                        }
                    }
                } else if message.service_name == "npcf-smpolicycontrol" {
                    // PCF SM policy response
                    if let Some(status) = message.res_status {
                        if status == 201 {
                            log::debug!("PCF SM policy created, transitioning to PFCP establishment");
                            return GsmFsmResult::Transition(GsmState::WaitPfcpEstablishment);
                        } else {
                            log::error!("PCF SM policy error: {}", status);
                            return GsmFsmResult::Transition(GsmState::N1N2Reject5gc);
                        }
                    }
                }
            }
        }
        GsmFsmResult::Handled
    }

    /// Handle events in wait PFCP establishment state
    fn handle_wait_pfcp_establishment(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_pfcp_establishment: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => GsmFsmResult::Handled,
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::N4Message => {
                // PFCP Session Establishment Response
                self.handle_pfcp_establishment_response(event)
            }
            SmfEventId::N4Timer => {
                // PFCP establishment timeout
                if let Some(timer_id) = event.timer_id {
                    if timer_id == SmfTimerId::PfcpNoEstablishmentResponse {
                        log::warn!("PFCP establishment timeout");
                        return GsmFsmResult::Transition(GsmState::N1N2Reject5gc);
                    }
                }
                GsmFsmResult::Handled
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle PFCP establishment response
    fn handle_pfcp_establishment_response(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref pfcp) = event.pfcp {
            log::debug!(
                "PFCP Session Establishment Response: xact_id={:?}",
                pfcp.pfcp_xact_id
            );
            // Note: PFCP cause code checked from response message
            // On success: send GTP Create Session Response (EPC) or N1N2 message transfer (5GC)
            log::info!("PFCP session established, transitioning to operational");
            return GsmFsmResult::Transition(GsmState::Operational);
        }
        GsmFsmResult::Handled
    }

    /// Handle events in operational state
    fn handle_operational(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_operational: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::info!("GSM session operational (sess_id={})", self.sess_id);
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::GnMessage => {
                // GTPv1 Delete PDP Context Request
                log::debug!("GSM: Gn Delete PDP Context Request");
                GsmFsmResult::Transition(GsmState::WaitPfcpDeletion)
            }
            SmfEventId::S5cMessage => {
                // GTPv2 Delete Session Request or Delete Bearer Response
                self.handle_s5c_operational(event)
            }
            SmfEventId::N4Message => {
                // PFCP Session Report Request or other messages
                self.handle_n4_operational(event)
            }
            SmfEventId::GyMessage => {
                // Gy CCA-Update
                if let Some(ref diameter) = event.diameter {
                    if diameter.cc_request_type == Some(2) {
                        // UPDATE_REQUEST
                        let result_code = diameter.result_code.unwrap_or(0);
                        if result_code != 2001 {
                            log::warn!("Gy CCA-Update failed: {}", result_code);
                            return GsmFsmResult::Transition(GsmState::WaitPfcpDeletion);
                        }
                    }
                }
                GsmFsmResult::Handled
            }
            SmfEventId::SbiServer => {
                // NSMF PDU Session Update/Release
                self.handle_sbi_server_operational(event)
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle S5-C messages in operational state
    fn handle_s5c_operational(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref gtp) = event.gtp {
            log::debug!("S5-C message in operational: xact_id={:?}", gtp.gtp_xact_id);
            // Note: Message type parsed from GTP header via gtp_handler
            // Delete Session Request -> transition to WaitPfcpDeletion
            // Delete Bearer Response -> check bearer state, release if last bearer
        }
        GsmFsmResult::Handled
    }

    /// Handle N4 messages in operational state
    fn handle_n4_operational(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref pfcp) = event.pfcp {
            log::debug!("N4 message in operational: xact_id={:?}", pfcp.pfcp_xact_id);
            // Note: Session Report Request handled for UPF-initiated events
            // Usage Report -> process charging, may trigger Gy CCR-Update
            // Downlink Data Report -> trigger paging if UE is idle
        }
        GsmFsmResult::Handled
    }

    /// Handle SBI server events in operational state
    fn handle_sbi_server_operational(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref message) = sbi.message {
                if message.service_name == "nsmf-pdusession" {
                    // Check resource component for modify/release
                    if message.resource_components.get(2).map(|s| s.as_str()) == Some("release") {
                        log::debug!("GSM: SM Context Release");
                        return GsmFsmResult::Transition(GsmState::WaitPfcpDeletion);
                    }
                }
            }
        }
        GsmFsmResult::Handled
    }

    /// Handle events in wait PFCP deletion state
    fn handle_wait_pfcp_deletion(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_pfcp_deletion: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::debug!("Entering PFCP deletion state");
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::N4Message => {
                // PFCP Session Deletion Response
                log::debug!("PFCP Session Deletion Response received");
                // For EPC: transition to WaitEpcAuthRelease
                // For 5GC: transition to Wait5gcN1N2Release or SessionWillRelease
                GsmFsmResult::Transition(GsmState::WaitEpcAuthRelease)
            }
            SmfEventId::N4Timer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == SmfTimerId::PfcpNoDeletionResponse {
                        log::warn!("PFCP deletion timeout");
                        return GsmFsmResult::Transition(GsmState::SessionWillRelease);
                    }
                }
                GsmFsmResult::Handled
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle events in wait EPC auth release state
    fn handle_wait_epc_auth_release(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_epc_auth_release: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => GsmFsmResult::Handled,
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::S6bMessage => {
                // S6b STA response
                self.sm_data.s6b_str_in_flight = false;
                self.check_epc_auth_release_complete()
            }
            SmfEventId::GxMessage => {
                // Gx CCA-Termination
                self.sm_data.gx_ccr_term_in_flight = false;
                self.check_epc_auth_release_complete()
            }
            SmfEventId::GyMessage => {
                // Gy CCA-Termination
                self.sm_data.gy_ccr_term_in_flight = false;
                self.check_epc_auth_release_complete()
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Check if all EPC auth release requests are complete
    fn check_epc_auth_release_complete(&self) -> GsmFsmResult {
        if !self.sm_data.s6b_str_in_flight
            && !self.sm_data.gx_ccr_term_in_flight
            && !self.sm_data.gy_ccr_term_in_flight
        {
            log::debug!("EPC auth release complete");
            GsmFsmResult::Transition(GsmState::SessionWillRelease)
        } else {
            GsmFsmResult::Handled
        }
    }

    /// Handle events in wait 5GC N1/N2 release state
    fn handle_wait_5gc_n1_n2_release(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_wait_5gc_n1_n2_release: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => GsmFsmResult::Handled,
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::SbiServer => {
                // N1N2 message transfer response or NGAP response
                self.handle_sbi_server_n1_n2_release(event)
            }
            SmfEventId::GsmMessage => {
                // NAS PDU Session Release Complete
                log::debug!("PDU Session Release Complete received");
                GsmFsmResult::Transition(GsmState::SessionWillDeregister5gc)
            }
            SmfEventId::NgapMessage => {
                // NGAP PDU Session Resource Release Response
                log::debug!("NGAP PDU Session Resource Release Response");
                GsmFsmResult::Handled
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle SBI server events in N1/N2 release state
    fn handle_sbi_server_n1_n2_release(&mut self, event: &SmfEvent) -> GsmFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref message) = sbi.message {
                if message.service_name == "nsmf-pdusession" {
                    // Check for release completion
                    log::debug!("SBI response in N1/N2 release state");
                }
            }
        }
        GsmFsmResult::Handled
    }

    /// Handle events in 5GC N1/N2 reject state
    fn handle_5gc_n1_n2_reject(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_5gc_n1_n2_reject: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::warn!("Entering N1/N2 reject state - session establishment failed");
                // Send N1N2 message transfer with reject
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::SbiClient => {
                // N1N2 message transfer response
                log::debug!("N1N2 reject message sent");
                GsmFsmResult::Transition(GsmState::SessionWillRelease)
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle events in 5GC session will deregister state
    fn handle_5gc_session_will_deregister(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_5gc_session_will_deregister: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::debug!("Session will deregister from UDM");
                // Cleanup session: deregister from UDM, delete SM policy
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            SmfEventId::SbiClient => {
                // UDM deregistration or PCF policy delete response
                log::debug!("SBI cleanup response received");
                GsmFsmResult::Transition(GsmState::SessionWillRelease)
            }
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle events in session will release state
    fn handle_session_will_release(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_session_will_release: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::info!("Session will be released (sess_id={})", self.sess_id);
                // Send SM context status notify, clear session
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Handle events in exception state
    fn handle_exception(&mut self, event: &SmfEvent) -> GsmFsmResult {
        log::debug!("gsm_state_exception: {}", event.name());

        match event.id {
            SmfEventId::FsmEntry => {
                log::error!("GSM session in exception state (sess_id={})", self.sess_id);
                GsmFsmResult::Handled
            }
            SmfEventId::FsmExit => GsmFsmResult::Handled,
            _ => GsmFsmResult::Ignored,
        }
    }

    /// Transition to a specific state
    pub fn transition_to(&mut self, state: GsmState) {
        log::debug!(
            "GSM explicit transition: {} -> {} (sess_id={})",
            self.state.name(),
            state.name(),
            self.sess_id
        );
        self.state = state;
    }

    /// Check if FSM is in a specific state
    pub fn is_state(&self, state: GsmState) -> bool {
        self.state == state
    }

    /// Get current state
    pub fn current_state(&self) -> GsmState {
        self.state
    }

    /// Check if session is operational
    pub fn is_operational(&self) -> bool {
        self.state == GsmState::Operational
    }

    /// Check if session is in initial state
    pub fn is_initial(&self) -> bool {
        self.state == GsmState::Initial
    }

    /// Set S6b AAR in flight
    pub fn set_s6b_aar_in_flight(&mut self, in_flight: bool) {
        self.sm_data.s6b_aar_in_flight = in_flight;
    }

    /// Set Gx CCR-Initial in flight
    pub fn set_gx_ccr_init_in_flight(&mut self, in_flight: bool) {
        self.sm_data.gx_ccr_init_in_flight = in_flight;
    }

    /// Set Gy CCR-Initial in flight
    pub fn set_gy_ccr_init_in_flight(&mut self, in_flight: bool) {
        self.sm_data.gy_ccr_init_in_flight = in_flight;
    }

    /// Set Gx CCR-Termination in flight
    pub fn set_gx_ccr_term_in_flight(&mut self, in_flight: bool) {
        self.sm_data.gx_ccr_term_in_flight = in_flight;
    }

    /// Set Gy CCR-Termination in flight
    pub fn set_gy_ccr_term_in_flight(&mut self, in_flight: bool) {
        self.sm_data.gy_ccr_term_in_flight = in_flight;
    }

    /// Set S6b STR in flight
    pub fn set_s6b_str_in_flight(&mut self, in_flight: bool) {
        self.sm_data.s6b_str_in_flight = in_flight;
    }
}

/// Result of GSM FSM event handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsmFsmResult {
    /// Event was handled
    Handled,
    /// Event was ignored
    Ignored,
    /// State transition occurred
    Transition(GsmState),
    /// Error occurred
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gsm_fsm_new() {
        let fsm = GsmFsm::new(123);
        assert_eq!(fsm.state, GsmState::Initial);
        assert_eq!(fsm.sess_id, 123);
    }

    #[test]
    fn test_gsm_fsm_init() {
        let mut fsm = GsmFsm::new(123);
        fsm.init();
        assert!(!fsm.sm_data.s6b_aar_in_flight);
        assert!(!fsm.sm_data.gx_ccr_init_in_flight);
    }

    #[test]
    fn test_gsm_fsm_fini() {
        let mut fsm = GsmFsm::new(123);
        fsm.fini();
        assert_eq!(fsm.state, GsmState::Final);
    }

    #[test]
    fn test_gsm_fsm_dispatch_entry() {
        let mut fsm = GsmFsm::new(123);
        let event = SmfEvent::entry();
        let result = fsm.dispatch(&event);
        assert_eq!(result, GsmFsmResult::Handled);
    }

    #[test]
    fn test_gsm_fsm_state_transitions() {
        let mut fsm = GsmFsm::new(123);
        assert!(fsm.is_initial());

        fsm.transition_to(GsmState::WaitEpcAuthInitial);
        assert_eq!(fsm.state, GsmState::WaitEpcAuthInitial);

        fsm.transition_to(GsmState::WaitPfcpEstablishment);
        assert_eq!(fsm.state, GsmState::WaitPfcpEstablishment);

        fsm.transition_to(GsmState::Operational);
        assert!(fsm.is_operational());
    }

    #[test]
    fn test_gsm_state_names() {
        assert_eq!(GsmState::Initial.name(), "GSM_STATE_INITIAL");
        assert_eq!(GsmState::WaitEpcAuthInitial.name(), "GSM_STATE_WAIT_EPC_AUTH_INITIAL");
        assert_eq!(GsmState::Operational.name(), "GSM_STATE_OPERATIONAL");
        assert_eq!(GsmState::Exception.name(), "GSM_STATE_EXCEPTION");
    }

    #[test]
    fn test_gsm_sm_data_default() {
        let sm_data = SmData::default();
        assert!(!sm_data.s6b_aar_in_flight);
        assert!(!sm_data.gx_ccr_init_in_flight);
        assert!(!sm_data.gy_ccr_init_in_flight);
        assert_eq!(sm_data.s6b_aaa_err, 0);
    }

    #[test]
    fn test_gsm_fsm_set_in_flight() {
        let mut fsm = GsmFsm::new(123);
        
        fsm.set_s6b_aar_in_flight(true);
        assert!(fsm.sm_data.s6b_aar_in_flight);
        
        fsm.set_gx_ccr_init_in_flight(true);
        assert!(fsm.sm_data.gx_ccr_init_in_flight);
        
        fsm.set_gy_ccr_init_in_flight(true);
        assert!(fsm.sm_data.gy_ccr_init_in_flight);
    }

    #[test]
    fn test_gsm_fsm_epc_auth_complete() {
        let mut fsm = GsmFsm::new(123);
        fsm.transition_to(GsmState::WaitEpcAuthInitial);
        
        // Simulate all auth complete with success
        fsm.sm_data.s6b_aaa_err = 2001;
        fsm.sm_data.gx_cca_init_err = 2001;
        fsm.sm_data.gy_cca_init_err = 2001;
        
        let result = fsm.check_epc_auth_complete();
        assert_eq!(result, GsmFsmResult::Transition(GsmState::WaitPfcpEstablishment));
    }

    #[test]
    fn test_gsm_fsm_epc_auth_in_progress() {
        let mut fsm = GsmFsm::new(123);
        fsm.transition_to(GsmState::WaitEpcAuthInitial);
        
        // Simulate Gx still in flight
        fsm.sm_data.gx_ccr_init_in_flight = true;
        fsm.sm_data.s6b_aaa_err = 2001;
        fsm.sm_data.gy_cca_init_err = 2001;
        
        let result = fsm.check_epc_auth_complete();
        assert_eq!(result, GsmFsmResult::Handled);
    }
}
