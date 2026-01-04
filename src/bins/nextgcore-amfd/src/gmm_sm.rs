//! GMM (5G Mobility Management) State Machine
//!
//! Port of src/amf/gmm-sm.c - GMM state machine for UE registration and mobility

use crate::event::{AmfEvent, AmfEventId, AmfTimerId};

/// GMM FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GmmState {
    /// Initial state
    #[default]
    Initial,
    /// De-registered state - UE is not registered
    DeRegistered,
    /// Authentication state - performing authentication
    Authentication,
    /// Security mode state - establishing security
    SecurityMode,
    /// Initial context setup state - setting up initial context
    InitialContextSetup,
    /// Registered state - UE is registered
    Registered,
    /// UE context will remove state - preparing to remove UE context
    UeContextWillRemove,
    /// Exception state - error condition
    Exception,
    /// Final state
    Final,
}

impl GmmState {
    /// Get the name of the state
    pub fn name(&self) -> &'static str {
        match self {
            GmmState::Initial => "GMM_STATE_INITIAL",
            GmmState::DeRegistered => "GMM_STATE_DE_REGISTERED",
            GmmState::Authentication => "GMM_STATE_AUTHENTICATION",
            GmmState::SecurityMode => "GMM_STATE_SECURITY_MODE",
            GmmState::InitialContextSetup => "GMM_STATE_INITIAL_CONTEXT_SETUP",
            GmmState::Registered => "GMM_STATE_REGISTERED",
            GmmState::UeContextWillRemove => "GMM_STATE_UE_CONTEXT_WILL_REMOVE",
            GmmState::Exception => "GMM_STATE_EXCEPTION",
            GmmState::Final => "GMM_STATE_FINAL",
        }
    }
}

/// GMM State Machine
#[derive(Debug, Clone)]
pub struct GmmFsm {
    /// Current state
    pub state: GmmState,
    /// AMF UE ID associated with this FSM
    pub amf_ue_id: u64,
}

impl GmmFsm {
    /// Create a new GMM FSM
    pub fn new(amf_ue_id: u64) -> Self {
        Self {
            state: GmmState::Initial,
            amf_ue_id,
        }
    }

    /// Initialize the FSM
    pub fn init(&mut self) {
        log::debug!("gmm_state_initial: amf_ue_id={}", self.amf_ue_id);
        self.state = GmmState::DeRegistered;
    }

    /// Finalize the FSM
    pub fn fini(&mut self) {
        log::debug!("gmm_state_final: amf_ue_id={}", self.amf_ue_id);
        self.state = GmmState::Final;
    }

    /// Dispatch an event to the FSM
    pub fn dispatch(&mut self, event: &AmfEvent) -> GmmFsmResult {
        let result = match self.state {
            GmmState::Initial => self.handle_initial(event),
            GmmState::DeRegistered => self.handle_de_registered(event),
            GmmState::Authentication => self.handle_authentication(event),
            GmmState::SecurityMode => self.handle_security_mode(event),
            GmmState::InitialContextSetup => self.handle_initial_context_setup(event),
            GmmState::Registered => self.handle_registered(event),
            GmmState::UeContextWillRemove => self.handle_ue_context_will_remove(event),
            GmmState::Exception => self.handle_exception(event),
            GmmState::Final => GmmFsmResult::Ignored,
        };

        // Apply state transition if result indicates one
        if let GmmFsmResult::Transition(new_state) = result {
            log::debug!(
                "GMM state transition: {} -> {} (amf_ue_id={})",
                self.state.name(),
                new_state.name(),
                self.amf_ue_id
            );
            self.state = new_state;
        }

        result
    }

    /// Handle events in initial state
    fn handle_initial(&mut self, event: &AmfEvent) -> GmmFsmResult {
        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_initial: FSM_ENTRY");
                GmmFsmResult::Transition(GmmState::DeRegistered)
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle events in de-registered state
    fn handle_de_registered(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_de_registered: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_de_registered: FSM_ENTRY - clearing UE state");
                // Clear paging info, N2 transfer, 5GSM messages, timers
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_de_registered: FSM_EXIT");
                GmmFsmResult::Handled
            }
            AmfEventId::GmmTimer => {
                self.handle_gmm_timer_de_registered(event)
            }
            AmfEventId::SbiClient => {
                // Handle SBI responses in de-registered state
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle GMM timer events in de-registered state
    fn handle_gmm_timer_de_registered(&mut self, event: &AmfEvent) -> GmmFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::T3570 => {
                    // Identity request retransmission
                    log::warn!("T3570 expired in de-registered state");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                AmfTimerId::T3522 => {
                    // De-registration request retransmission
                    log::warn!("T3522 expired in de-registered state");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                AmfTimerId::MobileReachable => {
                    log::warn!("Mobile reachable timer expired");
                    GmmFsmResult::Handled
                }
                AmfTimerId::ImplicitDeregistration => {
                    log::warn!("Implicit de-registration timer expired");
                    GmmFsmResult::Handled
                }
                _ => GmmFsmResult::Ignored,
            }
        } else {
            GmmFsmResult::Ignored
        }
    }

    /// Handle events in authentication state
    fn handle_authentication(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_authentication: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_authentication: FSM_ENTRY");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_authentication: FSM_EXIT");
                GmmFsmResult::Handled
            }
            AmfEventId::GmmTimer => {
                self.handle_gmm_timer_authentication(event)
            }
            AmfEventId::SbiClient => {
                // Handle AUSF authentication response
                // On success: transition to SecurityMode
                // On failure: transition to Exception or DeRegistered
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle GMM timer events in authentication state
    fn handle_gmm_timer_authentication(&mut self, event: &AmfEvent) -> GmmFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::T3560 => {
                    // Authentication request retransmission
                    log::warn!("T3560 expired - authentication timeout");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                _ => GmmFsmResult::Ignored,
            }
        } else {
            GmmFsmResult::Ignored
        }
    }

    /// Handle events in security mode state
    fn handle_security_mode(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_security_mode: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_security_mode: FSM_ENTRY");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_security_mode: FSM_EXIT");
                GmmFsmResult::Handled
            }
            AmfEventId::GmmTimer => {
                self.handle_gmm_timer_security_mode(event)
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle GMM timer events in security mode state
    fn handle_gmm_timer_security_mode(&mut self, event: &AmfEvent) -> GmmFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::T3560 => {
                    // Security mode command retransmission
                    log::warn!("T3560 expired - security mode timeout");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                _ => GmmFsmResult::Ignored,
            }
        } else {
            GmmFsmResult::Ignored
        }
    }

    /// Handle events in initial context setup state
    fn handle_initial_context_setup(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_initial_context_setup: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_initial_context_setup: FSM_ENTRY");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_initial_context_setup: FSM_EXIT");
                GmmFsmResult::Handled
            }
            AmfEventId::GmmTimer => {
                self.handle_gmm_timer_initial_context_setup(event)
            }
            AmfEventId::SbiClient => {
                // Handle UDM/PCF responses
                // On success: transition to Registered
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle GMM timer events in initial context setup state
    fn handle_gmm_timer_initial_context_setup(&mut self, event: &AmfEvent) -> GmmFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::T3550 => {
                    // Registration accept retransmission
                    log::warn!("T3550 expired - registration accept timeout");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                _ => GmmFsmResult::Ignored,
            }
        } else {
            GmmFsmResult::Ignored
        }
    }

    /// Handle events in registered state
    fn handle_registered(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_registered: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_registered: FSM_ENTRY");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_registered: FSM_EXIT");
                GmmFsmResult::Handled
            }
            AmfEventId::GmmTimer => {
                self.handle_gmm_timer_registered(event)
            }
            AmfEventId::SbiClient => {
                // Handle various SBI responses in registered state
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle GMM timer events in registered state
    fn handle_gmm_timer_registered(&mut self, event: &AmfEvent) -> GmmFsmResult {
        if let Some(timer_id) = event.timer_id {
            match timer_id {
                AmfTimerId::T3513 => {
                    // Paging retransmission
                    log::warn!("T3513 expired - paging timeout");
                    GmmFsmResult::Handled
                }
                AmfTimerId::T3522 => {
                    // De-registration request retransmission
                    log::warn!("T3522 expired - de-registration timeout");
                    GmmFsmResult::Transition(GmmState::Exception)
                }
                AmfTimerId::T3555 => {
                    // Configuration update command retransmission
                    log::warn!("T3555 expired - config update timeout");
                    GmmFsmResult::Handled
                }
                AmfTimerId::MobileReachable => {
                    log::warn!("Mobile reachable timer expired");
                    GmmFsmResult::Handled
                }
                AmfTimerId::ImplicitDeregistration => {
                    log::warn!("Implicit de-registration timer expired");
                    GmmFsmResult::Transition(GmmState::DeRegistered)
                }
                _ => GmmFsmResult::Ignored,
            }
        } else {
            GmmFsmResult::Ignored
        }
    }

    /// Handle events in UE context will remove state
    fn handle_ue_context_will_remove(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_ue_context_will_remove: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::debug!("gmm_state_ue_context_will_remove: FSM_ENTRY");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_ue_context_will_remove: FSM_EXIT");
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Handle events in exception state
    fn handle_exception(&mut self, event: &AmfEvent) -> GmmFsmResult {
        log::debug!("gmm_state_exception: {}", event.name());

        match event.id {
            AmfEventId::FsmEntry => {
                log::warn!("gmm_state_exception: FSM_ENTRY - UE in exception state");
                GmmFsmResult::Handled
            }
            AmfEventId::FsmExit => {
                log::debug!("gmm_state_exception: FSM_EXIT");
                GmmFsmResult::Handled
            }
            _ => GmmFsmResult::Ignored,
        }
    }

    /// Transition to authentication state
    pub fn transition_to_authentication(&mut self) {
        self.state = GmmState::Authentication;
    }

    /// Transition to security mode state
    pub fn transition_to_security_mode(&mut self) {
        self.state = GmmState::SecurityMode;
    }

    /// Transition to initial context setup state
    pub fn transition_to_initial_context_setup(&mut self) {
        self.state = GmmState::InitialContextSetup;
    }

    /// Transition to registered state
    pub fn transition_to_registered(&mut self) {
        self.state = GmmState::Registered;
    }

    /// Transition to de-registered state
    pub fn transition_to_de_registered(&mut self) {
        self.state = GmmState::DeRegistered;
    }

    /// Transition to exception state
    pub fn transition_to_exception(&mut self) {
        self.state = GmmState::Exception;
    }

    /// Check if FSM is in a specific state
    pub fn is_state(&self, state: GmmState) -> bool {
        self.state == state
    }

    /// Get current state
    pub fn current_state(&self) -> GmmState {
        self.state
    }

    /// Check if UE is registered
    pub fn is_registered(&self) -> bool {
        self.state == GmmState::Registered
    }

    /// Check if UE is de-registered
    pub fn is_de_registered(&self) -> bool {
        self.state == GmmState::DeRegistered
    }
}

/// Result of GMM FSM event handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmmFsmResult {
    /// Event was handled
    Handled,
    /// Event was ignored
    Ignored,
    /// State transition occurred
    Transition(GmmState),
    /// Error occurred
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmm_fsm_new() {
        let fsm = GmmFsm::new(123);
        assert_eq!(fsm.state, GmmState::Initial);
        assert_eq!(fsm.amf_ue_id, 123);
    }

    #[test]
    fn test_gmm_fsm_init() {
        let mut fsm = GmmFsm::new(123);
        fsm.init();
        assert_eq!(fsm.state, GmmState::DeRegistered);
    }

    #[test]
    fn test_gmm_fsm_fini() {
        let mut fsm = GmmFsm::new(123);
        fsm.init();
        fsm.fini();
        assert_eq!(fsm.state, GmmState::Final);
    }

    #[test]
    fn test_gmm_fsm_dispatch_entry() {
        let mut fsm = GmmFsm::new(123);
        let event = AmfEvent::entry();
        let result = fsm.dispatch(&event);
        assert_eq!(result, GmmFsmResult::Transition(GmmState::DeRegistered));
        assert_eq!(fsm.state, GmmState::DeRegistered);
    }

    #[test]
    fn test_gmm_fsm_state_transitions() {
        let mut fsm = GmmFsm::new(123);
        fsm.init();
        assert!(fsm.is_de_registered());

        fsm.transition_to_authentication();
        assert_eq!(fsm.state, GmmState::Authentication);

        fsm.transition_to_security_mode();
        assert_eq!(fsm.state, GmmState::SecurityMode);

        fsm.transition_to_initial_context_setup();
        assert_eq!(fsm.state, GmmState::InitialContextSetup);

        fsm.transition_to_registered();
        assert!(fsm.is_registered());
    }

    #[test]
    fn test_gmm_fsm_timer_in_registered() {
        let mut fsm = GmmFsm::new(123);
        fsm.init();
        fsm.transition_to_registered();

        let event = AmfEvent::gmm_timer(AmfTimerId::ImplicitDeregistration, 123);
        let result = fsm.dispatch(&event);
        assert_eq!(result, GmmFsmResult::Transition(GmmState::DeRegistered));
        assert_eq!(fsm.state, GmmState::DeRegistered);
    }

    #[test]
    fn test_gmm_state_names() {
        assert_eq!(GmmState::Initial.name(), "GMM_STATE_INITIAL");
        assert_eq!(GmmState::DeRegistered.name(), "GMM_STATE_DE_REGISTERED");
        assert_eq!(GmmState::Authentication.name(), "GMM_STATE_AUTHENTICATION");
        assert_eq!(GmmState::Registered.name(), "GMM_STATE_REGISTERED");
    }
}
