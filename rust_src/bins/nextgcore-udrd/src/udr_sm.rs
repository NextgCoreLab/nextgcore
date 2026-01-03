//! UDR Main State Machine
//!
//! Port of src/udr/udr-sm.c - Main UDR state machine implementation
//!
//! UDR is simpler than UDM - it's a stateless data repository.
//! It handles SBI server requests directly without UE/session state machines.

use crate::event::{UdrEvent, UdrEventId, UdrTimerId};
use crate::nudr_handler;

/// UDR state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// UDR state machine context
pub struct UdrSmContext {
    /// Current state
    state: UdrState,
}

impl UdrSmContext {
    /// Create a new UDR state machine context
    pub fn new() -> Self {
        Self {
            state: UdrState::Initial,
        }
    }

    /// Initialize the state machine
    ///
    /// Port of udr_state_initial()
    pub fn init(&mut self) {
        log::debug!("UDR SM: Initializing");
        self.state = UdrState::Initial;

        // Process initial state - transition to operational
        let mut event = UdrEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    ///
    /// Port of udr_state_final()
    pub fn fini(&mut self) {
        log::debug!("UDR SM: Finalizing");
        let mut event = UdrEvent::exit();
        self.dispatch(&mut event);
        self.state = UdrState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdrEvent) {
        udr_sm_debug(event);

        match self.state {
            UdrState::Initial => {
                self.handle_initial_state(event);
            }
            UdrState::Operational => {
                self.handle_operational_state(event);
            }
            UdrState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdrState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == UdrState::Operational
    }

    /// Handle initial state
    ///
    /// Port of udr_state_initial()
    fn handle_initial_state(&mut self, _event: &mut UdrEvent) {
        // Transition to operational state
        // In C: OGS_FSM_TRAN(s, &udr_state_operational);
        log::info!("UDR SM: Transitioning from Initial to Operational");
        self.state = UdrState::Operational;
    }

    /// Handle final state
    ///
    /// Port of udr_state_final()
    fn handle_final_state(&mut self, _event: &mut UdrEvent) {
        log::debug!("UDR SM: In final state");
    }

    /// Handle operational state
    ///
    /// Port of udr_state_operational()
    fn handle_operational_state(&mut self, event: &mut UdrEvent) {
        match event.id {
            UdrEventId::FsmEntry => {
                log::info!("UDR entering operational state");
            }

            UdrEventId::FsmExit => {
                log::info!("UDR exiting operational state");
            }

            UdrEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }

            UdrEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }

            UdrEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    /// Handle SBI server events
    ///
    /// Port of udr_state_operational() case OGS_EVENT_SBI_SERVER
    fn handle_sbi_server_event(&mut self, event: &mut UdrEvent) {
        let (stream_id, service_name, api_version, resource_components) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("No SBI data in server event");
                    return;
                }
            };

            let stream_id = match sbi.stream_id {
                Some(id) => id,
                None => {
                    log::error!("No stream ID in SBI event");
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

            (
                stream_id,
                message.service_name.clone(),
                message.api_version.clone(),
                message.resource_components.clone(),
            )
        };

        // Check API version
        // In C: if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0)
        if api_version != "v1" {
            log::error!("Not supported version [{}]", api_version);
            // TODO: Send error response
            return;
        }

        // Route based on service name
        // In C: SWITCH(message.h.service.name)
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(event, &resource_components, stream_id);
            }
            "nudr-dr" => {
                self.handle_nudr_dr_request(event, &resource_components, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
                // TODO: Send error response
            }
        }
    }

    /// Handle NNRF NFM (NF Management) requests
    ///
    /// Port of udr_state_operational() CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)
    fn handle_nnrf_nfm_request(
        &mut self,
        _event: &mut UdrEvent,
        resource_components: &[String],
        _stream_id: u64,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            // In C: CASE(OGS_SBI_RESOURCE_NAME_NF_STATUS_NOTIFY)
            Some("nf-status-notify") => {
                log::debug!("NF status notify received");
                // In C: ogs_nnrf_nfm_handle_nf_status_notify(stream, &message);
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
                // TODO: Send error response
            }
        }
    }

    /// Handle NUDR DR (Data Repository) requests
    ///
    /// Port of udr_state_operational() CASE(OGS_SBI_SERVICE_NAME_NUDR_DR)
    fn handle_nudr_dr_request(
        &mut self,
        event: &mut UdrEvent,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            // In C: CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTION_DATA)
            Some("subscription-data") => {
                let resource2 = resource_components.get(2).map(|s| s.as_str());

                match resource2 {
                    // In C: CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_DATA)
                    Some("authentication-data") => {
                        nudr_handler::handle_subscription_authentication(event, stream_id);
                    }
                    // In C: CASE(OGS_SBI_RESOURCE_NAME_CONTEXT_DATA)
                    Some("context-data") => {
                        nudr_handler::handle_subscription_context(event, stream_id);
                    }
                    _ => {
                        // Check for provisioned-data at component[3]
                        let resource3 = resource_components.get(3).map(|s| s.as_str());
                        match resource3 {
                            // In C: CASE(OGS_SBI_RESOURCE_NAME_PROVISIONED_DATA)
                            Some("provisioned-data") => {
                                let method = event.sbi.as_ref()
                                    .and_then(|s| s.message.as_ref())
                                    .map(|m| m.method.as_str())
                                    .unwrap_or("");

                                if method == "GET" {
                                    nudr_handler::handle_subscription_provisioned(event, stream_id);
                                } else {
                                    log::error!("Invalid HTTP method [{}]", method);
                                    // TODO: Send error response
                                }
                            }
                            _ => {
                                log::error!(
                                    "Invalid resource name [{:?}]",
                                    resource_components.get(2)
                                );
                                // TODO: Send error response
                            }
                        }
                    }
                }
            }
            // In C: CASE(OGS_SBI_RESOURCE_NAME_POLICY_DATA)
            Some("policy-data") => {
                nudr_handler::handle_policy_data(event, stream_id);
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
                // TODO: Send error response
            }
        }
    }

    /// Handle SBI client events
    ///
    /// Port of udr_state_operational() case OGS_EVENT_SBI_CLIENT
    fn handle_sbi_client_event(&mut self, event: &mut UdrEvent) {
        let (service_name, api_version, resource_components, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("No SBI data in client event");
                    return;
                }
            };

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("No message in SBI client event");
                    return;
                }
            };

            (
                message.service_name.clone(),
                message.api_version.clone(),
                message.resource_components.clone(),
                message.res_status,
            )
        };

        // Check API version
        if api_version != "v1" {
            log::error!("Not supported version [{}]", api_version);
            return;
        }

        // Route based on service name
        // In C: SWITCH(message.h.service.name)
        match service_name.as_str() {
            // In C: CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_response(&resource_components, res_status);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
            }
        }
    }

    /// Handle NNRF NFM responses
    ///
    /// Port of udr_state_operational() CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM) for client
    fn handle_nnrf_nfm_response(&mut self, resource_components: &[String], res_status: Option<u16>) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            // In C: CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                // In C: Dispatch to NF instance FSM
                // nf_instance = e->h.sbi.data;
                // if (OGS_FSM_STATE(&nf_instance->sm)) {
                //     e->h.sbi.message = &message;
                //     ogs_fsm_dispatch(&nf_instance->sm, e);
                // }
            }
            // In C: CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS)
            Some("subscriptions") => {
                log::debug!("Subscriptions response received, status: {:?}", res_status);
                // In C: Handle subscription response based on method
                // POST: ogs_nnrf_nfm_handle_nf_status_subscribe
                // PATCH: ogs_nnrf_nfm_handle_nf_status_update
                // DELETE: ogs_sbi_subscription_data_remove
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle SBI timer events
    ///
    /// Port of udr_state_operational() case OGS_EVENT_SBI_TIMER
    fn handle_sbi_timer_event(&mut self, event: &mut UdrEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            // In C: case OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
            // case OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
            // case OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT:
            // case OGS_TIMER_NF_INSTANCE_VALIDITY:
            UdrTimerId::NfInstanceRegistrationInterval
            | UdrTimerId::NfInstanceHeartbeatInterval
            | UdrTimerId::NfInstanceNoHeartbeat
            | UdrTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance timer: {:?}", nf_instance_id, timer_id);
                    // In C: nf_instance = e->h.sbi.data;
                    // ogs_fsm_dispatch(&nf_instance->sm, e);
                    // if (OGS_FSM_CHECK(&nf_instance->sm, ogs_sbi_nf_state_exception))
                    //     ogs_error("[%s] State machine exception [%d]",
                    //             nf_instance->id, e->h.timer_id);
                }
            }
            // In C: case OGS_TIMER_SUBSCRIPTION_VALIDITY:
            UdrTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{}] Subscription validity expired", subscription_id);
                    // In C: ogs_nnrf_nfm_send_nf_status_subscribe(...)
                    // ogs_sbi_subscription_data_remove(subscription_data);
                }
            }
            // In C: case OGS_TIMER_SUBSCRIPTION_PATCH:
            UdrTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{}] Need to update Subscription", subscription_id);
                    // In C: ogs_nnrf_nfm_send_nf_status_update(subscription_data);
                }
            }
            UdrTimerId::SbiClientWait => {
                log::error!("SBI client wait timer expired");
            }
        }
    }
}

impl Default for UdrSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug helper for state machine events
///
/// Port of udr_sm_debug()
pub fn udr_sm_debug(event: &UdrEvent) {
    log::trace!("UDR SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udr_sm_context_new() {
        let ctx = UdrSmContext::new();
        assert_eq!(ctx.state(), UdrState::Initial);
    }

    #[test]
    fn test_udr_sm_init() {
        let mut ctx = UdrSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_udr_sm_dispatch_entry() {
        let mut ctx = UdrSmContext::new();
        ctx.init();

        let mut event = UdrEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udr_sm_dispatch_exit() {
        let mut ctx = UdrSmContext::new();
        ctx.init();

        let mut event = UdrEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udr_sm_dispatch_timer() {
        let mut ctx = UdrSmContext::new();
        ctx.init();

        let mut event = UdrEvent::sbi_timer(UdrTimerId::NfInstanceNoHeartbeat)
            .with_nf_instance("test-nf".to_string());
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udr_sm_fini() {
        let mut ctx = UdrSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), UdrState::Final);
    }
}
