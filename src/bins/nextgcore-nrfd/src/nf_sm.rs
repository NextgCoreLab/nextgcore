//! NF Instance State Machine
//!
//! Port of src/nrf/nf-sm.c - NF instance state machine for managing registered NFs

use crate::event::{NrfEvent, NrfEventId, NrfTimerId, SbiMessage};
use crate::timer::timer_manager;
use std::time::Duration;

/// NF instance state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfState {
    /// Initial state
    Initial,
    /// Waiting for registration
    WillRegister,
    /// Registered and active
    Registered,
    /// De-registered
    DeRegistered,
    /// Exception/error state
    Exception,
    /// Final state
    Final,
}

/// NF instance state machine context
pub struct NfSmContext {
    /// NF instance ID
    pub nf_instance_id: String,
    /// Current state
    state: NfState,
    /// Heartbeat interval (seconds)
    pub heartbeat_interval: u32,
    /// No heartbeat timer ID
    pub t_no_heartbeat: Option<u64>,
}

impl NfSmContext {
    /// Create a new NF state machine context
    pub fn new(nf_instance_id: String) -> Self {
        Self {
            nf_instance_id,
            state: NfState::Initial,
            heartbeat_interval: 0,
            t_no_heartbeat: None,
        }
    }

    /// Get the NF instance ID
    pub fn id(&self) -> &str {
        &self.nf_instance_id
    }

    /// Get current state
    pub fn state(&self) -> NfState {
        self.state
    }

    /// Check if in registered state
    pub fn is_registered(&self) -> bool {
        self.state == NfState::Registered
    }

    /// Check if in will_register state
    pub fn is_will_register(&self) -> bool {
        self.state == NfState::WillRegister
    }

    /// Check if in de_registered state
    pub fn is_de_registered(&self) -> bool {
        self.state == NfState::DeRegistered
    }

    /// Check if in exception state
    pub fn is_exception(&self) -> bool {
        self.state == NfState::Exception
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut NrfEvent) {
        nrf_nf_sm_debug(self, event);

        match self.state {
            NfState::Initial => self.handle_initial_state(event),
            NfState::WillRegister => self.handle_will_register_state(event),
            NfState::Registered => self.handle_registered_state(event),
            NfState::DeRegistered => self.handle_de_registered_state(event),
            NfState::Exception => self.handle_exception_state(event),
            NfState::Final => self.handle_final_state(event),
        }
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut NrfEvent) {
        // Add no heartbeat timer
        let timer_mgr = timer_manager();
        self.t_no_heartbeat = timer_mgr.add_timer(
            NrfTimerId::NfInstanceNoHeartbeat,
            Duration::from_secs(3600), // Will be updated when heartbeat interval is set
            self.nf_instance_id.clone(),
        );

        // Transition to will_register state
        log::debug!("[{}] Transitioning to will_register state", self.nf_instance_id);
        self.state = NfState::WillRegister;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut NrfEvent) {
        // Delete no heartbeat timer
        if let Some(timer_id) = self.t_no_heartbeat.take() {
            let timer_mgr = timer_manager();
            timer_mgr.delete_timer(timer_id);
        }
    }

    /// Handle will_register state
    fn handle_will_register_state(&mut self, event: &mut NrfEvent) {
        match event.id {
            NrfEventId::FsmEntry => {
                log::debug!("[{}] Entering will_register state", self.nf_instance_id);
            }

            NrfEventId::FsmExit => {
                log::debug!("[{}] Exiting will_register state", self.nf_instance_id);
            }

            NrfEventId::SbiServer => {
                if let Some(ref sbi) = event.sbi {
                    if let Some(ref message) = sbi.message {
                        self.handle_will_register_sbi_server(message);
                    }
                }
            }

            _ => {
                log::error!(
                    "[{}] Unknown event {} in will_register state",
                    self.nf_instance_id,
                    event.name()
                );
                self.state = NfState::Exception;
            }
        }
    }

    /// Handle SBI server events in will_register state
    fn handle_will_register_sbi_server(&mut self, message: &SbiMessage) {
        if message.service_name != "nnrf-nfm" {
            log::error!(
                "[{}] Invalid API name: {}",
                self.nf_instance_id,
                message.service_name
            );
            self.state = NfState::Exception;
            return;
        }

        let resource = message.resource_components.first().map(|s| s.as_str());
        if resource != Some("nf-instances") {
            log::error!(
                "[{}] Invalid resource name: {:?}",
                self.nf_instance_id,
                resource
            );
            self.state = NfState::Exception;
            return;
        }

        match message.method.as_str() {
            "PUT" => {
                // NF registration
                log::info!("[{}] NF registration request received", self.nf_instance_id);
                // TODO: Call nrf_nnrf_handle_nf_register
                // On success, transition to registered state
                self.state = NfState::Registered;
            }
            _ => {
                log::error!(
                    "[{}] Invalid HTTP method: {}",
                    self.nf_instance_id,
                    message.method
                );
                self.state = NfState::Exception;
            }
        }
    }

    /// Handle registered state
    fn handle_registered_state(&mut self, event: &mut NrfEvent) {
        match event.id {
            NrfEventId::FsmEntry => {
                log::info!(
                    "[{}] NF registered [Heartbeat:{}s]",
                    self.nf_instance_id,
                    self.heartbeat_interval
                );

                // Start no heartbeat timer if heartbeat interval is set
                if self.heartbeat_interval > 0 {
                    if let Some(timer_id) = self.t_no_heartbeat {
                        let timer_mgr = timer_manager();
                        // Add margin to heartbeat interval (default 3 seconds)
                        let no_heartbeat_margin = 3;
                        let duration =
                            Duration::from_secs((self.heartbeat_interval + no_heartbeat_margin) as u64);
                        timer_mgr.restart_timer(timer_id, duration);
                    }
                }

                // TODO: Send NF status notify (NF_REGISTERED) to all subscribers
            }

            NrfEventId::FsmExit => {
                log::info!("[{}] NF de-registered", self.nf_instance_id);

                // Stop no heartbeat timer
                if self.heartbeat_interval > 0 {
                    if let Some(timer_id) = self.t_no_heartbeat {
                        let timer_mgr = timer_manager();
                        timer_mgr.stop_timer(timer_id);
                    }
                }

                // TODO: Send NF status notify (NF_DEREGISTERED) to all subscribers
            }

            NrfEventId::SbiServer => {
                if let Some(ref sbi) = event.sbi {
                    if let Some(ref message) = sbi.message {
                        self.handle_registered_sbi_server(message);
                    }
                }
            }

            _ => {
                log::error!(
                    "[{}] Unknown event {} in registered state",
                    self.nf_instance_id,
                    event.name()
                );
                self.state = NfState::Exception;
            }
        }
    }

    /// Handle SBI server events in registered state
    fn handle_registered_sbi_server(&mut self, message: &SbiMessage) {
        if message.service_name != "nnrf-nfm" {
            log::error!(
                "[{}] Invalid API name: {}",
                self.nf_instance_id,
                message.service_name
            );
            self.state = NfState::Exception;
            return;
        }

        let resource = message.resource_components.first().map(|s| s.as_str());
        if resource != Some("nf-instances") {
            log::error!(
                "[{}] Invalid resource name: {:?}",
                self.nf_instance_id,
                resource
            );
            self.state = NfState::Exception;
            return;
        }

        match message.method.as_str() {
            "PUT" | "PATCH" => {
                // NF update (heartbeat or profile update)
                log::debug!("[{}] NF update request received", self.nf_instance_id);

                // Restart no heartbeat timer
                if self.heartbeat_interval > 0 {
                    if let Some(timer_id) = self.t_no_heartbeat {
                        let timer_mgr = timer_manager();
                        let no_heartbeat_margin = 3;
                        let duration =
                            Duration::from_secs((self.heartbeat_interval + no_heartbeat_margin) as u64);
                        timer_mgr.restart_timer(timer_id, duration);
                    }
                }

                // TODO: Call nrf_nnrf_handle_nf_update
            }
            "DELETE" => {
                // NF deregistration
                log::info!("[{}] NF deregistration request received", self.nf_instance_id);
                // TODO: Send response
                self.state = NfState::DeRegistered;
            }
            _ => {
                log::error!(
                    "[{}] Invalid HTTP method: {}",
                    self.nf_instance_id,
                    message.method
                );
                self.state = NfState::Exception;
            }
        }
    }

    /// Handle de_registered state
    fn handle_de_registered_state(&mut self, event: &mut NrfEvent) {
        match event.id {
            NrfEventId::FsmEntry => {
                log::debug!("[{}] Entering de_registered state", self.nf_instance_id);
            }
            NrfEventId::FsmExit => {
                log::debug!("[{}] Exiting de_registered state", self.nf_instance_id);
            }
            _ => {
                log::error!(
                    "[{}] Unknown event {} in de_registered state",
                    self.nf_instance_id,
                    event.name()
                );
            }
        }
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut NrfEvent) {
        match event.id {
            NrfEventId::FsmEntry => {
                log::error!("[{}] Entering exception state", self.nf_instance_id);
            }
            NrfEventId::FsmExit => {
                log::debug!("[{}] Exiting exception state", self.nf_instance_id);
            }
            _ => {
                log::error!(
                    "[{}] Unknown event {} in exception state",
                    self.nf_instance_id,
                    event.name()
                );
            }
        }
    }
}

/// Initialize NF instance FSM
pub fn nrf_nf_fsm_init(ctx: &mut NfSmContext) {
    let mut event = NrfEvent::entry().with_nf_instance(ctx.nf_instance_id.clone());
    ctx.dispatch(&mut event);
}

/// Finalize NF instance FSM
pub fn nrf_nf_fsm_fini(ctx: &mut NfSmContext) {
    ctx.state = NfState::Final;
    let mut event = NrfEvent::exit().with_nf_instance(ctx.nf_instance_id.clone());
    ctx.dispatch(&mut event);
}

/// Debug helper for NF state machine events
fn nrf_nf_sm_debug(ctx: &NfSmContext, event: &NrfEvent) {
    log::trace!("[{}] NF SM event: {}", ctx.nf_instance_id, event.name());
}

/// Check if NF is in de_registered state
pub fn is_de_registered(ctx: &NfSmContext) -> bool {
    ctx.is_de_registered()
}

/// Check if NF is in exception state
pub fn is_exception(ctx: &NfSmContext) -> bool {
    ctx.is_exception()
}

/// Check if NF is in registered state
pub fn is_registered(ctx: &NfSmContext) -> bool {
    ctx.is_registered()
}

/// Check if NF is in will_register state
pub fn is_will_register(ctx: &NfSmContext) -> bool {
    ctx.is_will_register()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_sm_context_new() {
        let ctx = NfSmContext::new("test-nf-id".to_string());
        assert_eq!(ctx.nf_instance_id, "test-nf-id");
        assert_eq!(ctx.state(), NfState::Initial);
    }

    #[test]
    fn test_nf_sm_init() {
        let mut ctx = NfSmContext::new("test-nf-id".to_string());
        nrf_nf_fsm_init(&mut ctx);
        // After init, should be in will_register state
        assert!(ctx.is_will_register());
    }

    #[test]
    fn test_nf_sm_fini() {
        let mut ctx = NfSmContext::new("test-nf-id".to_string());
        nrf_nf_fsm_init(&mut ctx);
        nrf_nf_fsm_fini(&mut ctx);
        assert_eq!(ctx.state(), NfState::Final);
    }

    #[test]
    fn test_nf_sm_state_checks() {
        let mut ctx = NfSmContext::new("test-nf-id".to_string());
        nrf_nf_fsm_init(&mut ctx);

        assert!(is_will_register(&ctx));
        assert!(!is_registered(&ctx));
        assert!(!is_de_registered(&ctx));
        assert!(!is_exception(&ctx));
    }

    #[test]
    fn test_nf_sm_transition_to_registered() {
        let mut ctx = NfSmContext::new("test-nf-id".to_string());
        nrf_nf_fsm_init(&mut ctx);

        // Simulate PUT request for registration
        let message = SbiMessage {
            service_name: "nnrf-nfm".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string(), "test-nf-id".to_string()],
            method: "PUT".to_string(),
        };

        let mut event = NrfEvent::new(NrfEventId::SbiServer).with_sbi_message(message);
        ctx.dispatch(&mut event);

        assert!(is_registered(&ctx));
    }

    #[test]
    fn test_nf_sm_transition_to_de_registered() {
        let mut ctx = NfSmContext::new("test-nf-id".to_string());
        nrf_nf_fsm_init(&mut ctx);

        // First register
        ctx.state = NfState::Registered;

        // Then deregister
        let message = SbiMessage {
            service_name: "nnrf-nfm".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string(), "test-nf-id".to_string()],
            method: "DELETE".to_string(),
        };

        let mut event = NrfEvent::new(NrfEventId::SbiServer).with_sbi_message(message);
        ctx.dispatch(&mut event);

        assert!(is_de_registered(&ctx));
    }
}
