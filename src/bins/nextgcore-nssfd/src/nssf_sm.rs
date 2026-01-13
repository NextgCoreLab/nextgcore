//! NSSF Main State Machine
//!
//! Port of src/nssf/nssf-sm.c - Main NSSF state machine implementation

use crate::context::{nssf_self, get_nsi_load};
use crate::event::{NssfEvent, NssfEventId, NssfTimerId};
use crate::sbi_response::{send_error_response, send_gateway_timeout_response};

/// NSSF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssfState {
    Initial,
    Operational,
    Final,
}

/// NSSF state machine context
pub struct NssfSmContext {
    state: NssfState,
}

impl NssfSmContext {
    pub fn new() -> Self {
        Self {
            state: NssfState::Initial,
        }
    }

    pub fn init(&mut self) {
        log::debug!("NSSF SM: Initializing");
        self.state = NssfState::Initial;
        let mut event = NssfEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("NSSF SM: Finalizing");
        let mut event = NssfEvent::exit();
        self.dispatch(&mut event);
        self.state = NssfState::Final;
    }

    pub fn dispatch(&mut self, event: &mut NssfEvent) {
        nssf_sm_debug(event);

        match self.state {
            NssfState::Initial => self.handle_initial_state(event),
            NssfState::Operational => self.handle_operational_state(event),
            NssfState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> NssfState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == NssfState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut NssfEvent) {
        log::info!("NSSF SM: Transitioning from Initial to Operational");
        self.state = NssfState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut NssfEvent) {
        log::debug!("NSSF SM: In final state");
    }


    fn handle_operational_state(&mut self, event: &mut NssfEvent) {
        match event.id {
            NssfEventId::FsmEntry => {
                log::info!("NSSF entering operational state");
            }
            NssfEventId::FsmExit => {
                log::info!("NSSF exiting operational state");
            }
            NssfEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }
            NssfEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }
            NssfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut NssfEvent) {
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

        // Check API version based on service
        let expected_version = if service_name == "nnssf-nsselection" {
            "v2"
        } else {
            "v1"
        };

        if api_version != expected_version {
            log::error!("Not supported version [{}], expected [{}]", api_version, expected_version);
            send_error_response(stream_id, 400, &format!("Unsupported API version: {}", api_version));
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(&method, &resource_components, stream_id);
            }
            "nnssf-nsselection" => {
                self.handle_nnssf_nsselection_request(event, &method, &resource_components, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
                send_error_response(stream_id, 400, &format!("Invalid API name: {}", service_name));
            }
        }
    }

    fn handle_nnrf_nfm_request(&mut self, method: &str, resource_components: &[String], _stream_id: u64) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: ogs_nnrf_nfm_handle_nf_status_notify processes NF status changes
                    // This is handled by the nnrf integration when NRF is enabled
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

    fn handle_nnssf_nsselection_request(
        &mut self,
        _event: &mut NssfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("network-slice-information") => match method {
                "GET" => {
                    log::debug!("NS selection GET request received (stream_id={})", stream_id);
                    // Note: nssf_nnrf_nsselection_handle_get_from_amf_or_vnssf handles slice selection
                    // The handler is invoked via the direct HTTP path in main.rs
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


    fn handle_sbi_client_event(&mut self, event: &mut NssfEvent) {
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

        // Check API version based on service
        let expected_version = if service_name == "nnssf-nsselection" {
            "v2"
        } else {
            "v1"
        };

        if api_version != expected_version {
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
            "nnssf-nsselection" => {
                self.handle_nnssf_nsselection_response(event, &resource_components);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
            }
        }
    }

    fn handle_nnrf_nfm_response(&mut self, event: &mut NssfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                // Note: Dispatch to NF instance FSM for registration handling
                // This is handled by the nnrf integration when NRF is enabled
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance response", nf_instance_id);
                }
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
                // Note: Handle NRF subscription response for NF discovery updates
                // This is handled by the nnrf integration when NRF is enabled
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nnrf_disc_response(&mut self, event: &mut NssfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF discover response received");
                if let Some(sbi_xact_id) = event.sbi_xact_id {
                    log::debug!("SBI xact ID: {}", sbi_xact_id);
                    // Note: nssf_nnrf_handle_nf_discover processes NF discovery results
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nnssf_nsselection_response(&mut self, event: &mut NssfEvent, _resource_components: &[String]) {
        // Handle response from H-NSSF
        if let Some(home_id) = event.home_id {
            let ctx = nssf_self();
            let home_info = {
                if let Ok(context) = ctx.read() {
                    context.home_find_by_id(home_id).map(|home| {
                        (home.plmn_id.mcc.clone(), home.plmn_id.mnc.clone(), home.s_nssai.sst)
                    })
                } else {
                    None
                }
            };

            if let Some((mcc, mnc, sst)) = home_info {
                log::debug!(
                    "NS selection response for home (plmn={}{}, sst={})",
                    mcc, mnc, sst
                );
                // Note: nssf_nnrf_nsselection_handle_get_from_hnssf handles H-NSSF response
                // This is invoked when V-NSSF receives slice info from H-NSSF
            } else {
                log::error!("Home Network Context has already been removed");
            }
        }
    }


    fn handle_sbi_timer_event(&mut self, event: &mut NssfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            NssfTimerId::NfInstanceRegistrationInterval
            | NssfTimerId::NfInstanceHeartbeatInterval
            | NssfTimerId::NfInstanceNoHeartbeat
            | NssfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance timer: {:?}", nf_instance_id, timer_id);
                    // Update NF instance load
                    let _load = get_nsi_load();
                    // Note: Dispatch to NF FSM for timer handling
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            NssfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{}] Subscription validity expired", subscription_id);
                    // Note: Send new subscription and remove old one
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            NssfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{}] Need to update Subscription", subscription_id);
                    // Note: Send subscription update to NRF
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            NssfTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }
}

impl Default for NssfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn nssf_sm_debug(event: &NssfEvent) {
    log::trace!("NSSF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nssf_sm_context_new() {
        let ctx = NssfSmContext::new();
        assert_eq!(ctx.state(), NssfState::Initial);
    }

    #[test]
    fn test_nssf_sm_init() {
        let mut ctx = NssfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_nssf_sm_dispatch_entry() {
        let mut ctx = NssfSmContext::new();
        ctx.init();
        let mut event = NssfEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_nssf_sm_dispatch_exit() {
        let mut ctx = NssfSmContext::new();
        ctx.init();
        let mut event = NssfEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_nssf_sm_fini() {
        let mut ctx = NssfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), NssfState::Final);
    }
}
