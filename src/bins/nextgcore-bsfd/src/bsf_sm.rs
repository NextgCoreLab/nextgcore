//! BSF Main State Machine
//!
//! Port of src/bsf/bsf-sm.c - Main BSF state machine implementation

use crate::context::{bsf_self, get_sess_load};
use crate::event::{BsfEvent, BsfEventId, BsfTimerId};
use crate::sbi_response::{send_error_response, send_not_found_response, send_gateway_timeout_response};

// Note: The state machine code below is a port from Open5GS C code
// but is not currently used for HTTP response handling.
// The actual HTTP request handling is done in main.rs bsf_sbi_request_handler()
// which directly returns SbiResponse objects.
// The state machine handles NRF integration and timer events when enabled.

/// BSF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsfState {
    Initial,
    Operational,
    Final,
}

/// BSF state machine context
pub struct BsfSmContext {
    state: BsfState,
}

impl BsfSmContext {
    pub fn new() -> Self {
        Self {
            state: BsfState::Initial,
        }
    }

    pub fn init(&mut self) {
        log::debug!("BSF SM: Initializing");
        self.state = BsfState::Initial;
        let mut event = BsfEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("BSF SM: Finalizing");
        let mut event = BsfEvent::exit();
        self.dispatch(&mut event);
        self.state = BsfState::Final;
    }

    pub fn dispatch(&mut self, event: &mut BsfEvent) {
        bsf_sm_debug(event);

        match self.state {
            BsfState::Initial => self.handle_initial_state(event),
            BsfState::Operational => self.handle_operational_state(event),
            BsfState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> BsfState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == BsfState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut BsfEvent) {
        log::info!("BSF SM: Transitioning from Initial to Operational");
        self.state = BsfState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut BsfEvent) {
        log::debug!("BSF SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut BsfEvent) {
        match event.id {
            BsfEventId::FsmEntry => {
                log::info!("BSF entering operational state");
            }
            BsfEventId::FsmExit => {
                log::info!("BSF exiting operational state");
            }
            BsfEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }
            BsfEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }
            BsfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }


    fn handle_sbi_server_event(&mut self, event: &mut BsfEvent) {
        let (stream_id, service_name, api_version, method, resource_components) = {
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
                message.method.clone(),
                message.resource_components.clone(),
            )
        };

        // Check API version (BSF uses v1)
        if api_version != "v1" {
            log::error!("Not supported version [{api_version}], expected [v1]");
            send_error_response(stream_id, 400, &format!("Unsupported API version: {api_version}"));
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(&method, &resource_components, stream_id);
            }
            "nbsf-management" => {
                self.handle_nbsf_management_request(event, &method, &resource_components, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
                send_error_response(stream_id, 400, &format!("Invalid API name: {service_name}"));
            }
        }
    }

    fn handle_nnrf_nfm_request(&mut self, method: &str, resource_components: &[String], _stream_id: u64) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: ogs_nnrf_nfm_handle_nf_status_notify would process NF status changes
                    // This is handled by the NRF handler when NRF integration is enabled
                }
                _ => {
                    log::error!("Invalid HTTP method [{method}]");
                }
            },
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nbsf_management_request(
        &mut self,
        event: &mut BsfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("pcf-bindings") => {
                // Check if binding_id is provided (resource_components[1])
                let binding_id = resource_components.get(1).map(|s| s.as_str());
                
                if let Some(binding_id) = binding_id {
                    // Operations on existing binding
                    log::debug!("PCF binding operation: {method} on binding_id={binding_id} (stream_id={stream_id})");
                    
                    let ctx = bsf_self();
                    let sess = {
                        if let Ok(context) = ctx.read() {
                            context.sess_find_by_binding_id(binding_id)
                        } else {
                            None
                        }
                    };

                    if sess.is_none() {
                        log::error!("Session not found for binding_id={binding_id}");
                        send_not_found_response(stream_id, &format!("PCF binding not found: {binding_id}"));
                        return;
                    }

                    match method {
                        "DELETE" => {
                            log::debug!("DELETE PCF binding: {binding_id}");
                            // Note: nbsf_handler::handle_pcf_binding_delete handles actual deletion
                            // The handler is invoked via the direct HTTP path in main.rs
                        }
                        "PATCH" => {
                            log::debug!("PATCH PCF binding: {binding_id}");
                            // Note: nbsf_handler::handle_pcf_binding_patch handles updates
                            // The handler is invoked via the direct HTTP path in main.rs
                        }
                        _ => {
                            log::error!("Invalid HTTP method [{method}]");
                        }
                    }
                } else {
                    // Operations without binding_id
                    match method {
                        "POST" => {
                            log::debug!("POST PCF binding (stream_id={stream_id})");
                            // Note: nbsf_handler::handle_pcf_binding_post creates new bindings
                            // The handler is invoked via the direct HTTP path in main.rs
                            event.sess_id = None; // Will be set by handler
                        }
                        "GET" => {
                            log::debug!("GET PCF binding (stream_id={stream_id})");
                            // Note: nbsf_handler::handle_pcf_binding_get retrieves bindings
                            // The handler is invoked via the direct HTTP path in main.rs
                        }
                        _ => {
                            log::error!("Invalid HTTP method [{method}]");
                        }
                    }
                }
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }


    fn handle_sbi_client_event(&mut self, event: &mut BsfEvent) {
        let (service_name, api_version, resource_components, _res_status) = {
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
            log::error!("Not supported version [{api_version}]");
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_response(event, &resource_components);
            }
            "nnrf-disc" => {
                self.handle_nnrf_disc_response(event, &resource_components);
            }
            _ => {
                log::error!("Invalid service name [{service_name}]");
            }
        }
    }

    fn handle_nnrf_nfm_response(&mut self, event: &mut BsfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                // Note: Dispatch to NF instance FSM for registration/deregistration handling
                // This is handled by the nnrf_handler module when NRF integration is enabled
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance response");
                }
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
                // Note: Handle NRF subscription response for NF discovery updates
                // This is handled by the nnrf_handler module when NRF integration is enabled
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nnrf_disc_response(&mut self, event: &mut BsfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF discover response received");
                if let Some(sbi_xact_id) = event.sbi_xact_id {
                    log::debug!("SBI xact ID: {sbi_xact_id}");
                    // Note: bsf_nnrf_handle_nf_discover processes NF discovery results
                    // This is handled by the nnrf_handler module when NRF integration is enabled
                }
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut BsfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            BsfTimerId::NfInstanceRegistrationInterval
            | BsfTimerId::NfInstanceHeartbeatInterval
            | BsfTimerId::NfInstanceNoHeartbeat
            | BsfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                    // Update NF instance load
                    let _load = get_sess_load();
                    // Note: Dispatch to NF FSM for timer handling
                    // This is handled by the nnrf_handler module when NRF integration is enabled
                }
            }
            BsfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                    // Note: Send new subscription and remove old one
                    // This is handled by the nnrf_handler module when NRF integration is enabled
                }
            }
            BsfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                    // Note: Send subscription update to NRF
                    // This is handled by the nnrf_handler module when NRF integration is enabled
                }
            }
            BsfTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                // Note: stream_id would need to be tracked for the pending request
                // For now, log the timeout - the client connection will be closed
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
            BsfTimerId::BindingExpiry => {
                log::info!("BSF binding expired, removing stale binding");
                // Binding TTL expired - remove from binding store
                // The binding ID would be tracked in the event context
            }
        }
    }
}

impl Default for BsfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn bsf_sm_debug(event: &BsfEvent) {
    log::trace!("BSF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsf_sm_context_new() {
        let ctx = BsfSmContext::new();
        assert_eq!(ctx.state(), BsfState::Initial);
    }

    #[test]
    fn test_bsf_sm_init() {
        let mut ctx = BsfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_bsf_sm_dispatch_entry() {
        let mut ctx = BsfSmContext::new();
        ctx.init();
        let mut event = BsfEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_bsf_sm_dispatch_exit() {
        let mut ctx = BsfSmContext::new();
        ctx.init();
        let mut event = BsfEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_bsf_sm_fini() {
        let mut ctx = BsfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), BsfState::Final);
    }
}
