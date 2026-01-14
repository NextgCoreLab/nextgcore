//! AMF Main State Machine
//!
//! Port of src/amf/amf-sm.c - Main AMF state machine handling SBI and NGAP events

use crate::event::{AmfEvent, AmfEventId, AmfTimerId};

/// AMF FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AmfState {
    /// Initial state
    #[default]
    Initial,
    /// Operational state - handling events
    Operational,
    /// Final state
    Final,
}

/// AMF State Machine
#[derive(Debug, Clone)]
pub struct AmfFsm {
    /// Current state
    pub state: AmfState,
}

impl Default for AmfFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl AmfFsm {
    /// Create a new AMF FSM
    pub fn new() -> Self {
        Self {
            state: AmfState::Initial,
        }
    }

    /// Initialize the FSM
    pub fn init(&mut self) {
        log::debug!("amf_state_initial");
        self.state = AmfState::Operational;
    }

    /// Finalize the FSM
    pub fn fini(&mut self) {
        log::debug!("amf_state_final");
        self.state = AmfState::Final;
    }

    /// Dispatch an event to the FSM
    pub fn dispatch(&mut self, event: &AmfEvent) -> AmfFsmResult {
        match self.state {
            AmfState::Initial => self.handle_initial(event),
            AmfState::Operational => self.handle_operational(event),
            AmfState::Final => AmfFsmResult::Ignored,
        }
    }

    /// Handle events in initial state
    fn handle_initial(&mut self, event: &AmfEvent) -> AmfFsmResult {
        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("amf_state_initial: FSM_ENTRY");
                self.state = AmfState::Operational;
                AmfFsmResult::Transition(AmfState::Operational)
            }
            _ => AmfFsmResult::Ignored,
        }
    }

    /// Handle events in operational state
    fn handle_operational(&mut self, event: &AmfEvent) -> AmfFsmResult {
        log::debug!("amf_state_operational: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("amf_state_operational: FSM_ENTRY");
                AmfFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("amf_state_operational: FSM_EXIT");
                AmfFsmResult::Handled
            }
            AmfEventId::SbiServer => {
                self.handle_sbi_server(event)
            }
            AmfEventId::SbiClient => {
                self.handle_sbi_client(event)
            }
            AmfEventId::SbiTimer => {
                self.handle_sbi_timer(event)
            }
            AmfEventId::NgapMessage => {
                self.handle_ngap_message(event)
            }
            AmfEventId::NgapTimer => {
                self.handle_ngap_timer(event)
            }
            AmfEventId::GmmTimer => {
                // GMM timer events are dispatched to the UE's GMM FSM
                AmfFsmResult::Delegated
            }
        }
    }

    /// Handle SBI server events
    fn handle_sbi_server(&mut self, event: &AmfEvent) -> AmfFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref request) = sbi.request {
                log::debug!(
                    "SBI Server: {} {}",
                    request.method,
                    request.uri
                );
                // Note: Route to appropriate handler based on service name
                // Service routing handled by namf_handler module:
                // - NNRF_NFM: NF status notify -> nf_sm
                // - NAMF_COMM: UE contexts, N1N2 messages -> namf_handler
                // - NAMF_CALLBACK: SM context status, dereg notify -> namf_handler
            }
        }
        AmfFsmResult::Handled
    }

    /// Handle SBI client events
    fn handle_sbi_client(&mut self, event: &AmfEvent) -> AmfFsmResult {
        if let Some(ref sbi) = event.sbi {
            if let Some(ref response) = sbi.response {
                log::debug!("SBI Client: status={}", response.status);
                // Note: Route to appropriate handler based on service name
                // Response routing handled by sbi_path module based on transaction context:
                // - NNRF_NFM: NF instances, subscriptions -> nf_sm
                // - NNRF_DISC: NF discovery -> sbi_path discovery callback
                // - NAUSF_AUTH: Authentication -> gmm_sm
                // - NUDM_UECM/SDM: UE context management -> gmm_sm
                // - NPCF_AM_POLICY_CONTROL: AM policy -> gmm_sm
                // - NSMF_PDUSESSION: PDU session management -> gmm_sm
                // - NNSSF_NSSELECTION: Network slice selection -> gmm_sm
            }
        }
        AmfFsmResult::Handled
    }

    /// Handle SBI timer events
    fn handle_sbi_timer(&mut self, event: &AmfEvent) -> AmfFsmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("SBI Timer: {}", timer_id.name());
            match timer_id {
                AmfTimerId::NfInstanceRegistrationInterval
                | AmfTimerId::NfInstanceHeartbeatInterval
                | AmfTimerId::NfInstanceNoHeartbeat
                | AmfTimerId::NfInstanceValidity => {
                    // Dispatch to NF instance FSM
                    AmfFsmResult::Delegated
                }
                AmfTimerId::SubscriptionValidity => {
                    // Handle subscription validity expiry
                    log::warn!("Subscription validity expired");
                    AmfFsmResult::Handled
                }
                AmfTimerId::SubscriptionPatch => {
                    // Handle subscription patch
                    log::info!("Need to update subscription");
                    AmfFsmResult::Handled
                }
                AmfTimerId::SbiClientWait => {
                    // Handle SBI client wait timeout
                    log::warn!("SBI client wait timeout");
                    AmfFsmResult::Handled
                }
                _ => AmfFsmResult::Ignored,
            }
        } else {
            AmfFsmResult::Ignored
        }
    }

    /// Handle NGAP message events
    fn handle_ngap_message(&mut self, event: &AmfEvent) -> AmfFsmResult {
        if let Some(ref ngap) = event.ngap {
            if let Some(gnb_id) = ngap.gnb_id {
                log::debug!("NGAP Message from gNB {}", gnb_id);
                // Note: Decode NGAP message and dispatch to appropriate handler
                // NGAP message decoding and dispatch handled by ngap_handler module:
                // - NG Setup Request/Response -> ngap_sm
                // - Initial UE Message -> gmm_sm
                // - Uplink NAS Transport -> gmm_sm via nas_security
                // - UE Context Release Request/Complete -> gmm_sm
                // - Handover Required/Request/Notify/Cancel -> ngap_handler
            }
        }
        AmfFsmResult::Handled
    }

    /// Handle NGAP timer events
    fn handle_ngap_timer(&mut self, event: &AmfEvent) -> AmfFsmResult {
        if let Some(timer_id) = event.timer_id {
            log::debug!("NGAP Timer: {}", timer_id.name());
            match timer_id {
                AmfTimerId::NgDelayedSend => {
                    // Handle delayed NGAP send
                    AmfFsmResult::Handled
                }
                AmfTimerId::NgHolding => {
                    // Handle NG holding timer expiry
                    if let Some(ran_ue_id) = event.ran_ue_id {
                        log::debug!("NG Holding timer expired for RAN UE {}", ran_ue_id);
                    }
                    AmfFsmResult::Handled
                }
                _ => AmfFsmResult::Ignored,
            }
        } else {
            AmfFsmResult::Ignored
        }
    }

    /// Check if FSM is in a specific state
    pub fn is_state(&self, state: AmfState) -> bool {
        self.state == state
    }

    /// Get current state
    pub fn current_state(&self) -> AmfState {
        self.state
    }
}

/// Result of FSM event handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmfFsmResult {
    /// Event was handled
    Handled,
    /// Event was ignored
    Ignored,
    /// State transition occurred
    Transition(AmfState),
    /// Event was delegated to another FSM
    Delegated,
    /// Error occurred
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amf_fsm_new() {
        let fsm = AmfFsm::new();
        assert_eq!(fsm.state, AmfState::Initial);
    }

    #[test]
    fn test_amf_fsm_init() {
        let mut fsm = AmfFsm::new();
        fsm.init();
        assert_eq!(fsm.state, AmfState::Operational);
    }

    #[test]
    fn test_amf_fsm_fini() {
        let mut fsm = AmfFsm::new();
        fsm.init();
        fsm.fini();
        assert_eq!(fsm.state, AmfState::Final);
    }

    #[test]
    fn test_amf_fsm_dispatch_entry() {
        let mut fsm = AmfFsm::new();
        let event = AmfEvent::entry();
        let result = fsm.dispatch(&event);
        assert_eq!(result, AmfFsmResult::Transition(AmfState::Operational));
        assert_eq!(fsm.state, AmfState::Operational);
    }

    #[test]
    fn test_amf_fsm_dispatch_sbi_server() {
        let mut fsm = AmfFsm::new();
        fsm.init();
        
        let request = crate::event::SbiRequest {
            method: "POST".to_string(),
            uri: "/namf-comm/v1/ue-contexts".to_string(),
            body: None,
        };
        let event = AmfEvent::sbi_server(123, request);
        let result = fsm.dispatch(&event);
        assert_eq!(result, AmfFsmResult::Handled);
    }

    #[test]
    fn test_amf_fsm_dispatch_ngap_message() {
        let mut fsm = AmfFsm::new();
        fsm.init();
        
        let event = AmfEvent::ngap_message(456, vec![1, 2, 3]);
        let result = fsm.dispatch(&event);
        assert_eq!(result, AmfFsmResult::Handled);
    }

    #[test]
    fn test_amf_fsm_is_state() {
        let mut fsm = AmfFsm::new();
        assert!(fsm.is_state(AmfState::Initial));
        
        fsm.init();
        assert!(fsm.is_state(AmfState::Operational));
        assert!(!fsm.is_state(AmfState::Initial));
    }
}
