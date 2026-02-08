//! SCP Main State Machine
//!
//! Port of src/scp/scp-sm.c - Main SCP state machine implementation

use crate::event::{ScpEvent, ScpEventId, ScpTimerId};
use crate::sbi_response::{send_error_response, send_gateway_timeout_response};

/// SCP state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpState {
    Initial,
    Operational,
    Final,
}

/// SCP state machine context
pub struct ScpSmContext {
    state: ScpState,
}

impl ScpSmContext {
    pub fn new() -> Self {
        Self {
            state: ScpState::Initial,
        }
    }

    pub fn init(&mut self) {
        log::debug!("SCP SM: Initializing");
        self.state = ScpState::Initial;
        let mut event = ScpEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("SCP SM: Finalizing");
        let mut event = ScpEvent::exit();
        self.dispatch(&mut event);
        self.state = ScpState::Final;
    }

    pub fn dispatch(&mut self, event: &mut ScpEvent) {
        scp_sm_debug(event);

        match self.state {
            ScpState::Initial => self.handle_initial_state(event),
            ScpState::Operational => self.handle_operational_state(event),
            ScpState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> ScpState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == ScpState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut ScpEvent) {
        log::info!("SCP SM: Transitioning from Initial to Operational");
        self.state = ScpState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut ScpEvent) {
        log::debug!("SCP SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut ScpEvent) {
        match event.id {
            ScpEventId::FsmEntry => {
                log::info!("SCP entering operational state");
            }
            ScpEventId::FsmExit => {
                log::info!("SCP exiting operational state");
            }
            ScpEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }
            ScpEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }
            ScpEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut ScpEvent) {
        let (stream_id, service_name, api_version, _method, _resource_components) = {
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

        // Check API version (SCP uses v1)
        if api_version != "v1" {
            log::error!("Not supported version [{}], expected [v1]", api_version);
            send_error_response(stream_id, 400, &format!("Unsupported API version: {}", api_version));
            return;
        }

        // SCP primarily handles nnrf-nfm notifications
        // Most requests are forwarded to target NFs via sbi_path handlers
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(event, stream_id);
            }
            _ => {
                // SCP forwards most requests - this is handled in sbi_path.rs
                log::debug!("SCP forwarding request for service [{}]", service_name);
            }
        }
    }

    fn handle_nnrf_nfm_request(&mut self, event: &mut ScpEvent, _stream_id: u64) {
        let (method, resource_components) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (message.method.clone(), message.resource_components.clone())
        };

        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method.as_str() {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: Call ogs_nnrf_nfm_handle_nf_status_notify
                    // NF status notify processing is handled by the nnrf integration module
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                }
            },
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_sbi_client_event(&mut self, event: &mut ScpEvent) {
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
            log::error!("Not supported version [{}]", api_version);
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
                // SCP forwards responses back to original requester
                log::debug!("SCP forwarding response for service [{}]", service_name);
            }
        }
    }

    fn handle_nnrf_nfm_response(&mut self, event: &mut ScpEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance response", nf_instance_id);
                }
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nnrf_disc_response(&mut self, event: &mut ScpEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF discover response received");
                if let Some(sbi_xact_id) = event.sbi_xact_id {
                    log::debug!("SBI xact ID: {}", sbi_xact_id);
                    // Note: Handle NF discovery result and forward original request
                    // Discovery result processing is handled by the sbi_path module's handle_nf_discover_response
                }
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut ScpEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            ScpTimerId::NfInstanceRegistrationInterval
            | ScpTimerId::NfInstanceHeartbeatInterval
            | ScpTimerId::NfInstanceNoHeartbeat
            | ScpTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance timer: {:?}", nf_instance_id, timer_id);
                    // Note: Dispatch to NF FSM
                    // NF instance timer handling is done by the nnrf integration module
                }
            }
            ScpTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{}] Subscription validity expired", subscription_id);
                    // Note: Send new subscription and remove old one
                    // Subscription renewal is handled by the nnrf integration module
                }
            }
            ScpTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{}] Need to update Subscription", subscription_id);
                    // Note: Send subscription update
                    // Subscription update is handled by the nnrf integration module
                }
            }
            ScpTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }
}

impl Default for ScpSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn scp_sm_debug(event: &ScpEvent) {
    log::trace!("SCP SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_sm_context_new() {
        let ctx = ScpSmContext::new();
        assert_eq!(ctx.state(), ScpState::Initial);
    }

    #[test]
    fn test_scp_sm_init() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_scp_sm_dispatch_entry() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        let mut event = ScpEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_scp_sm_dispatch_exit() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        let mut event = ScpEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_scp_sm_fini() {
        let mut ctx = ScpSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), ScpState::Final);
    }
}
