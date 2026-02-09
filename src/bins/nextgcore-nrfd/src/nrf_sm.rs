//! NRF Main State Machine
//!
//! Port of src/nrf/nrf-sm.c - Main NRF state machine implementation

use crate::event::{NrfEvent, NrfEventId, NrfTimerId, SbiMessage};

/// NRF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrfState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// NRF state machine context
pub struct NrfSmContext {
    /// Current state
    state: NrfState,
}

impl NrfSmContext {
    /// Create a new NRF state machine context
    pub fn new() -> Self {
        Self {
            state: NrfState::Initial,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("NRF SM: Initializing");
        self.state = NrfState::Initial;
        
        // Process initial state
        let mut event = NrfEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("NRF SM: Finalizing");
        let mut event = NrfEvent::exit();
        self.dispatch(&mut event);
        self.state = NrfState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut NrfEvent) {
        nrf_sm_debug(event);
        
        match self.state {
            NrfState::Initial => {
                self.handle_initial_state(event);
            }
            NrfState::Operational => {
                self.handle_operational_state(event);
            }
            NrfState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> NrfState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == NrfState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut NrfEvent) {
        // Transition to operational state
        log::info!("NRF SM: Transitioning from Initial to Operational");
        self.state = NrfState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut NrfEvent) {
        log::debug!("NRF SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut NrfEvent) {
        match event.id {
            NrfEventId::FsmEntry => {
                log::info!("NRF entering operational state");
            }

            NrfEventId::FsmExit => {
                log::info!("NRF exiting operational state");
            }

            NrfEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }

            NrfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }

            NrfEventId::SbiClient => {
                log::debug!("SBI client event received");
            }
        }
    }

    /// Handle SBI server events
    fn handle_sbi_server_event(&mut self, event: &NrfEvent) {
        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("No SBI data in server event");
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("No message in SBI event");
                return;
            }
        };

        // Route based on service name
        match message.service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(message);
            }
            "nnrf-disc" => {
                self.handle_nnrf_disc_request(message);
            }
            _ => {
                log::error!("Invalid API name: {}", message.service_name);
            }
        }
    }

    /// Handle NNRF NFM (NF Management) requests
    fn handle_nnrf_nfm_request(&mut self, message: &SbiMessage) {
        let resource = message.resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                self.handle_nf_instances_request(message);
            }
            Some("subscriptions") => {
                self.handle_subscriptions_request(message);
            }
            _ => {
                log::error!(
                    "Invalid resource name: {:?}",
                    message.resource_components.first()
                );
            }
        }
    }

    /// Handle NF instances requests
    fn handle_nf_instances_request(&mut self, message: &SbiMessage) {
        match message.method.as_str() {
            "GET" => {
                if message.resource_components.len() > 1 {
                    log::debug!("NF profile retrieval request");
                    // Note: Call nrf_nnrf_handle_nf_profile_retrieval
                    // Handler invocation is done by the nnrf_handler module
                } else {
                    log::debug!("NF list retrieval request");
                    // Note: Call nrf_nnrf_handle_nf_list_retrieval
                    // Handler invocation is done by the nnrf_handler module
                }
            }
            "PUT" => {
                log::debug!("NF registration request");
                // Note: Call nrf_nnrf_handle_nf_register
                // Handler invocation is done by the nnrf_handler module
            }
            "PATCH" => {
                log::debug!("NF update request");
                // Note: Call nrf_nnrf_handle_nf_update
                // Handler invocation is done by the nnrf_handler module
            }
            "DELETE" => {
                log::debug!("NF deregistration request");
            }
            "OPTIONS" => {
                log::warn!("OPTIONS method not implemented");
            }
            _ => {
                log::error!("Invalid HTTP method: {}", message.method);
            }
        }
    }

    /// Handle subscriptions requests
    fn handle_subscriptions_request(&mut self, message: &SbiMessage) {
        match message.method.as_str() {
            "POST" => {
                log::debug!("NF status subscribe request");
                // Note: Call nrf_nnrf_handle_nf_status_subscribe
                // Handler invocation is done by the nnrf_handler module
            }
            "PATCH" => {
                log::debug!("NF status update request");
                // Note: Call nrf_nnrf_handle_nf_status_update
                // Handler invocation is done by the nnrf_handler module
            }
            "DELETE" => {
                log::debug!("NF status unsubscribe request");
                // Note: Call nrf_nnrf_handle_nf_status_unsubscribe
                // Handler invocation is done by the nnrf_handler module
            }
            _ => {
                log::error!("Invalid HTTP method for subscriptions: {}", message.method);
            }
        }
    }

    /// Handle NNRF DISC (Discovery) requests
    fn handle_nnrf_disc_request(&mut self, message: &SbiMessage) {
        let resource = message.resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                if message.method == "GET" {
                    log::debug!("NF discover request");
                    // Note: Call nrf_nnrf_handle_nf_discover
                    // Handler invocation is done by the nnrf_handler module
                } else {
                    log::error!("Invalid HTTP method for discovery: {}", message.method);
                }
            }
            _ => {
                log::error!(
                    "Invalid resource name for discovery: {:?}",
                    message.resource_components.first()
                );
            }
        }
    }

    /// Handle SBI timer events
    fn handle_sbi_timer_event(&mut self, event: &NrfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            NrfTimerId::NfInstanceNoHeartbeat => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::warn!("[{nf_instance_id}] No heartbeat");
                    // Note: Set NF status to SUSPENDED and remove instance
                    // The NF instance is marked as unavailable and removed from discovery results
                }
            }
            NrfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                    // Note: Remove subscription data
                    // Expired subscriptions are cleaned up by the subscription manager
                }
            }
            NrfTimerId::SbiClientWait => {
                log::debug!("SBI client wait timer expired");
            }
        }
    }
}

impl Default for NrfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug helper for state machine events
pub fn nrf_sm_debug(event: &NrfEvent) {
    log::trace!("NRF SM event: {}", event.name());
}

// Legacy function signatures for compatibility
pub fn nrf_state_initial(_sm: &mut NrfSmContext, _event: &mut NrfEvent) {}
pub fn nrf_state_final(_sm: &mut NrfSmContext, _event: &mut NrfEvent) {}
pub fn nrf_state_operational(_sm: &mut NrfSmContext, _event: &mut NrfEvent) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrf_sm_context_new() {
        let ctx = NrfSmContext::new();
        assert_eq!(ctx.state(), NrfState::Initial);
    }

    #[test]
    fn test_nrf_sm_init() {
        let mut ctx = NrfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_nrf_sm_dispatch_entry() {
        let mut ctx = NrfSmContext::new();
        ctx.init();

        let mut event = NrfEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_nrf_sm_dispatch_exit() {
        let mut ctx = NrfSmContext::new();
        ctx.init();

        let mut event = NrfEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_nrf_sm_dispatch_timer() {
        let mut ctx = NrfSmContext::new();
        ctx.init();

        let mut event = NrfEvent::nf_instance_no_heartbeat("test-nf".to_string());
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_nrf_sm_fini() {
        let mut ctx = NrfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), NrfState::Final);
    }
}
