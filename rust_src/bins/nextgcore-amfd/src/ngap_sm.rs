//! NGAP State Machine
//!
//! Port of src/amf/ngap-sm.c - NGAP state machine for gNB connection management

use crate::event::{AmfEvent, AmfEventId, AmfTimerId};

/// NGAP FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NgapState {
    /// Initial state
    #[default]
    Initial,
    /// Operational state - gNB is connected and operational
    Operational,
    /// Exception state - error condition
    Exception,
    /// Final state
    Final,
}

impl NgapState {
    /// Get the name of the state
    pub fn name(&self) -> &'static str {
        match self {
            NgapState::Initial => "NGAP_STATE_INITIAL",
            NgapState::Operational => "NGAP_STATE_OPERATIONAL",
            NgapState::Exception => "NGAP_STATE_EXCEPTION",
            NgapState::Final => "NGAP_STATE_FINAL",
        }
    }
}

/// NGAP State Machine for gNB
#[derive(Debug, Clone)]
pub struct NgapFsm {
    /// Current state
    pub state: NgapState,
    /// gNB ID associated with this FSM
    pub gnb_id: u64,
}

impl NgapFsm {
    /// Create a new NGAP FSM
    pub fn new(gnb_id: u64) -> Self {
        Self {
            state: NgapState::Initial,
            gnb_id,
        }
    }

    /// Initialize the FSM
    pub fn init(&mut self) {
        log::debug!("ngap_state_initial: gnb_id={}", self.gnb_id);
        self.state = NgapState::Operational;
    }

    /// Finalize the FSM
    pub fn fini(&mut self) {
        log::debug!("ngap_state_final: gnb_id={}", self.gnb_id);
        self.state = NgapState::Final;
    }

    /// Dispatch an event to the FSM
    pub fn dispatch(&mut self, event: &AmfEvent) -> NgapFsmResult {
        let result = match self.state {
            NgapState::Initial => self.handle_initial(event),
            NgapState::Operational => self.handle_operational(event),
            NgapState::Exception => self.handle_exception(event),
            NgapState::Final => NgapFsmResult::Ignored,
        };

        // Apply state transition if result indicates one
        if let NgapFsmResult::Transition(new_state) = result {
            log::debug!(
                "NGAP state transition: {} -> {} (gnb_id={})",
                self.state.name(),
                new_state.name(),
                self.gnb_id
            );
            self.state = new_state;
        }

        result
    }

    /// Handle events in initial state
    fn handle_initial(&mut self, event: &AmfEvent) -> NgapFsmResult {
        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("ngap_state_initial: FSM_ENTRY");
                NgapFsmResult::Transition(NgapState::Operational)
            }
            _ => NgapFsmResult::Ignored,
        }
    }

    /// Handle events in operational state
    fn handle_operational(&mut self, event: &AmfEvent) -> NgapFsmResult {
        log::debug!("ngap_state_operational: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("ngap_state_operational: FSM_ENTRY");
                NgapFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("ngap_state_operational: FSM_EXIT");
                NgapFsmResult::Handled
            }
            AmfEventId::NgapMessage => {
                self.handle_ngap_message(event)
            }
            AmfEventId::NgapTimer => {
                self.handle_ngap_timer(event)
            }
            _ => NgapFsmResult::Ignored,
        }
    }

    /// Handle NGAP message events
    fn handle_ngap_message(&mut self, event: &AmfEvent) -> NgapFsmResult {
        if let Some(ref ngap) = event.ngap {
            if let Some(ref _pkbuf) = ngap.pkbuf {
                log::debug!("NGAP message received for gNB {}", self.gnb_id);
                // TODO: Decode NGAP message and handle based on procedure code
                // Initiating messages:
                // - NGSetupRequest
                // - InitialUEMessage
                // - UplinkNASTransport
                // - UEContextReleaseRequest
                // - HandoverRequired
                // - HandoverCancel
                // - PathSwitchRequest
                // - NGReset
                // - ErrorIndication
                // - etc.
                //
                // Successful outcomes:
                // - NGSetupResponse
                // - InitialContextSetupResponse
                // - UEContextReleaseComplete
                // - HandoverRequestAcknowledge
                // - HandoverNotify
                // - etc.
                //
                // Unsuccessful outcomes:
                // - NGSetupFailure
                // - InitialContextSetupFailure
                // - HandoverFailure
                // - etc.
            }
        }
        NgapFsmResult::Handled
    }

    /// Handle NGAP timer events
    fn handle_ngap_timer(&mut self, event: &AmfEvent) -> NgapFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::NgDelayedSend => {
                    log::debug!("NG delayed send timer expired");
                    NgapFsmResult::Handled
                }
                AmfTimerId::NgHolding => {
                    log::debug!("NG holding timer expired");
                    NgapFsmResult::Handled
                }
                _ => NgapFsmResult::Ignored,
            }
        } else {
            NgapFsmResult::Ignored
        }
    }

    /// Handle events in exception state
    fn handle_exception(&mut self, event: &AmfEvent) -> NgapFsmResult {
        log::debug!("ngap_state_exception: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::warn!("ngap_state_exception: FSM_ENTRY - gNB in exception state");
                NgapFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("ngap_state_exception: FSM_EXIT");
                NgapFsmResult::Handled
            }
            AmfEventId::NgapMessage => {
                // In exception state, we might still receive some messages
                // Handle NG Reset to recover
                log::debug!("NGAP message in exception state");
                NgapFsmResult::Handled
            }
            _ => NgapFsmResult::Ignored,
        }
    }

    /// Transition to operational state
    pub fn transition_to_operational(&mut self) {
        self.state = NgapState::Operational;
    }

    /// Transition to exception state
    pub fn transition_to_exception(&mut self) {
        self.state = NgapState::Exception;
    }

    /// Check if FSM is in a specific state
    pub fn is_state(&self, state: NgapState) -> bool {
        self.state == state
    }

    /// Get current state
    pub fn current_state(&self) -> NgapState {
        self.state
    }

    /// Check if gNB is operational
    pub fn is_operational(&self) -> bool {
        self.state == NgapState::Operational
    }

    /// Check if gNB is in exception state
    pub fn is_exception(&self) -> bool {
        self.state == NgapState::Exception
    }
}

/// Result of NGAP FSM event handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgapFsmResult {
    /// Event was handled
    Handled,
    /// Event was ignored
    Ignored,
    /// State transition occurred
    Transition(NgapState),
    /// Error occurred
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngap_fsm_new() {
        let fsm = NgapFsm::new(456);
        assert_eq!(fsm.state, NgapState::Initial);
        assert_eq!(fsm.gnb_id, 456);
    }

    #[test]
    fn test_ngap_fsm_init() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();
        assert_eq!(fsm.state, NgapState::Operational);
    }

    #[test]
    fn test_ngap_fsm_fini() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();
        fsm.fini();
        assert_eq!(fsm.state, NgapState::Final);
    }

    #[test]
    fn test_ngap_fsm_dispatch_entry() {
        let mut fsm = NgapFsm::new(456);
        let event = AmfEvent::entry();
        let result = fsm.dispatch(&event);
        assert_eq!(result, NgapFsmResult::Transition(NgapState::Operational));
        assert_eq!(fsm.state, NgapState::Operational);
    }

    #[test]
    fn test_ngap_fsm_dispatch_ngap_message() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();

        let event = AmfEvent::ngap_message(456, vec![1, 2, 3]);
        let result = fsm.dispatch(&event);
        assert_eq!(result, NgapFsmResult::Handled);
    }

    #[test]
    fn test_ngap_fsm_dispatch_ngap_timer() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();

        let event = AmfEvent::ngap_timer(AmfTimerId::NgHolding, 789);
        let result = fsm.dispatch(&event);
        assert_eq!(result, NgapFsmResult::Handled);
    }

    #[test]
    fn test_ngap_fsm_state_transitions() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();
        assert!(fsm.is_operational());

        fsm.transition_to_exception();
        assert!(fsm.is_exception());

        fsm.transition_to_operational();
        assert!(fsm.is_operational());
    }

    #[test]
    fn test_ngap_state_names() {
        assert_eq!(NgapState::Initial.name(), "NGAP_STATE_INITIAL");
        assert_eq!(NgapState::Operational.name(), "NGAP_STATE_OPERATIONAL");
        assert_eq!(NgapState::Exception.name(), "NGAP_STATE_EXCEPTION");
        assert_eq!(NgapState::Final.name(), "NGAP_STATE_FINAL");
    }

    #[test]
    fn test_ngap_fsm_exception_state() {
        let mut fsm = NgapFsm::new(456);
        fsm.init();
        fsm.transition_to_exception();

        let event = AmfEvent::ngap_message(456, vec![1, 2, 3]);
        let result = fsm.dispatch(&event);
        assert_eq!(result, NgapFsmResult::Handled);
    }
}
