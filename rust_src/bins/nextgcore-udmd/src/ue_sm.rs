//! UDM UE State Machine
//!
//! Port of src/udm/ue-sm.c - UE state machine implementation

use crate::context::udm_self;
use crate::event::{UdmEvent, UdmEventId};
use crate::nudm_handler;
use crate::nudr_handler;

/// UDM UE state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmUeState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// UDM UE state machine context
pub struct UdmUeSmContext {
    /// Current state
    state: UdmUeState,
    /// UDM UE ID
    udm_ue_id: u64,
}

impl UdmUeSmContext {
    /// Create a new UDM UE state machine context
    pub fn new(udm_ue_id: u64) -> Self {
        let mut ctx = Self {
            state: UdmUeState::Initial,
            udm_ue_id,
        };
        ctx.init();
        ctx
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("UDM UE SM [{}]: Initializing", self.udm_ue_id);
        self.state = UdmUeState::Initial;

        // Process initial state - transition to operational
        let mut event = UdmEvent::entry().with_udm_ue(self.udm_ue_id);
        self.handle_initial_state(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("UDM UE SM [{}]: Finalizing", self.udm_ue_id);
        let mut event = UdmEvent::exit().with_udm_ue(self.udm_ue_id);
        self.handle_final_state(&mut event);
        self.state = UdmUeState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdmEvent) {
        udm_ue_sm_debug(event, self.udm_ue_id);

        match self.state {
            UdmUeState::Initial => {
                self.handle_initial_state(event);
            }
            UdmUeState::Operational => {
                self.handle_operational_state(event);
            }
            UdmUeState::Exception => {
                self.handle_exception_state(event);
            }
            UdmUeState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdmUeState {
        self.state
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: UdmUeState) {
        log::debug!(
            "UDM UE SM [{}]: {:?} -> {:?}",
            self.udm_ue_id,
            self.state,
            new_state
        );
        self.state = new_state;
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        if let Some(udm_ue) = context.ue_find_by_id(self.udm_ue_id) {
            log::debug!("[{}] UDM UE SM: Initial state", udm_ue.suci);
        }

        // Transition to operational state
        self.transition(UdmUeState::Operational);
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        if let Some(udm_ue) = context.ue_find_by_id(self.udm_ue_id) {
            log::debug!("[{}] UDM UE SM: Final state", udm_ue.suci);
        }
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let udm_ue = match context.ue_find_by_id(self.udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UDM UE not found [{}]", self.udm_ue_id);
                return;
            }
        };

        match event.id {
            UdmEventId::FsmEntry => {
                log::debug!("[{}] UDM UE entering operational state", udm_ue.suci);
            }

            UdmEventId::FsmExit => {
                log::debug!("[{}] UDM UE exiting operational state", udm_ue.suci);
            }

            UdmEventId::SbiServer => {
                drop(context); // Release lock before calling handlers
                self.handle_sbi_server_event(event);
            }

            UdmEventId::SbiClient => {
                drop(context); // Release lock before calling handlers
                self.handle_sbi_client_event(event);
            }

            _ => {
                log::error!(
                    "[{}] Unknown event {}",
                    udm_ue.suci,
                    crate::event::udm_event_get_name(event)
                );
            }
        }
    }


    /// Handle SBI server events in operational state
    fn handle_sbi_server_event(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let udm_ue = match context.ue_find_by_id(self.udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UDM UE not found [{}]", self.udm_ue_id);
                return;
            }
        };

        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("[{}] No SBI data in server event", udm_ue.suci);
                return;
            }
        };

        let stream_id = match sbi.stream_id {
            Some(id) => id,
            None => {
                log::error!("[{}] No stream ID in SBI event", udm_ue.suci);
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("[{}] No message in SBI event", udm_ue.suci);
                return;
            }
        };

        let service_name = message.service_name.clone();
        let method = message.method.clone();
        let resource_components = message.resource_components.clone();
        let num_of_dataset_names = message.num_of_dataset_names;

        drop(context); // Release lock before calling handlers

        match service_name.as_str() {
            "nudm-ueau" => {
                self.handle_nudm_ueau_request(&method, &resource_components, stream_id);
            }
            "nudm-uecm" => {
                self.handle_nudm_uecm_request(&method, &resource_components, stream_id);
            }
            "nudm-sdm" => {
                self.handle_nudm_sdm_request(&method, &resource_components, stream_id, num_of_dataset_names);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
                // TODO: Send error response
            }
        }
    }

    /// Handle NUDM UEAU requests
    fn handle_nudm_ueau_request(
        &mut self,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        let udm_ue = context.ue_find_by_id(self.udm_ue_id);
        let suci = udm_ue.as_ref().map(|u| u.suci.clone()).unwrap_or_default();
        drop(context);

        match method {
            "POST" => {
                let resource = resource_components.get(1).map(|s| s.as_str());
                match resource {
                    Some("security-information") => {
                        // TODO: Parse AuthenticationInfoRequest from HTTP body
                        let request = nudm_handler::AuthenticationInfoRequest::default();
                        let (_result, _state) = nudm_handler::udm_nudm_ueau_handle_get(
                            self.udm_ue_id, stream_id, &request);
                    }
                    Some("auth-events") => {
                        // TODO: Parse AuthEventRequest from HTTP body
                        let request = nudm_handler::AuthEventRequest::default();
                        let _result = nudm_handler::udm_nudm_ueau_handle_result_confirmation_inform(
                            self.udm_ue_id, stream_id, &request);
                    }
                    _ => {
                        log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                        // TODO: Send error response
                    }
                }
            }
            "PUT" => {
                let resource = resource_components.get(1).map(|s| s.as_str());
                match resource {
                    Some("auth-events") => {
                        // TODO: Parse AuthEventRequest from HTTP body
                        let request = nudm_handler::AuthEventRequest::default();
                        let _result = nudm_handler::udm_nudm_ueau_handle_result_confirmation_inform(
                            self.udm_ue_id, stream_id, &request);
                    }
                    _ => {
                        log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                        // TODO: Send error response
                    }
                }
            }
            _ => {
                log::error!("[{}] Invalid HTTP method [{}]", suci, method);
                // TODO: Send 403 Forbidden error
            }
        }
    }

    /// Handle NUDM UECM requests
    fn handle_nudm_uecm_request(
        &mut self,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        let udm_ue = context.ue_find_by_id(self.udm_ue_id);
        let suci = udm_ue.as_ref().map(|u| u.suci.clone()).unwrap_or_default();
        drop(context);

        let resource = resource_components.get(1).map(|s| s.as_str());

        match method {
            "PUT" => match resource {
                Some("registrations") => {
                    // TODO: Parse Amf3GppAccessRegistrationRequest from HTTP body
                    let request = nudm_handler::Amf3GppAccessRegistrationRequest::default();
                    let _result = nudm_handler::udm_nudm_uecm_handle_amf_registration(
                        self.udm_ue_id, stream_id, &request);
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                    // TODO: Send error response
                }
            },
            "PATCH" => match resource {
                Some("registrations") => {
                    // TODO: Parse Amf3GppAccessRegistrationModificationRequest from HTTP body
                    let request = nudm_handler::Amf3GppAccessRegistrationModificationRequest::default();
                    let _result = nudm_handler::udm_nudm_uecm_handle_amf_registration_update(
                        self.udm_ue_id, stream_id, &request);
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                    // TODO: Send error response
                }
            },
            "GET" => match resource {
                Some("registrations") => {
                    let resource_name = resource_components.get(2).map(|s| s.as_str()).unwrap_or("registrations");
                    let (result, _registration) = nudm_handler::udm_nudm_uecm_handle_amf_registration_get(
                        self.udm_ue_id, stream_id, resource_name);
                    if !result.success {
                        log::error!("[{}] Invalid UE Identifier", suci);
                        // TODO: Send 403 Forbidden error
                    }
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                    // TODO: Send error response
                }
            },
            _ => {
                log::error!("[{}] Invalid HTTP method [{}]", suci, method);
                // TODO: Send 403 Forbidden error
            }
        }
    }

    /// Handle NUDM SDM requests
    fn handle_nudm_sdm_request(
        &mut self,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
        num_of_dataset_names: usize,
    ) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        let udm_ue = context.ue_find_by_id(self.udm_ue_id);
        let suci = udm_ue.as_ref().map(|u| u.suci.clone()).unwrap_or_default();
        drop(context);

        let resource = resource_components.get(1).map(|s| s.as_str());

        match method {
            "GET" => {
                // Check for dataset names query
                if num_of_dataset_names > 0 && resource.is_none() {
                    let _result = nudr_handler::udm_nudr_dr_query_subscription_provisioned(
                        self.udm_ue_id,
                        stream_id,
                        nudr_handler::UdmSbiState::UeProvisionedDatasets,
                    );
                    return;
                }

                match resource {
                    Some("am-data") | Some("smf-select-data") | Some("sm-data") => {
                        let _result = nudr_handler::udm_nudr_dr_query_subscription_provisioned(
                            self.udm_ue_id,
                            stream_id,
                            nudr_handler::UdmSbiState::NoState,
                        );
                    }
                    Some("nssai") => {
                        let _result = nudr_handler::udm_nudr_dr_query_subscription_provisioned(
                            self.udm_ue_id,
                            stream_id,
                            nudr_handler::UdmSbiState::UeProvisionedNssaiOnly,
                        );
                    }
                    Some("ue-context-in-smf-data") => {
                        let _result = nudm_handler::udm_nudm_sdm_handle_subscription_provisioned(
                            self.udm_ue_id,
                            stream_id,
                            "ue-context-in-smf-data",
                        );
                    }
                    _ => {
                        log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                        // TODO: Send error response
                    }
                }
            }
            "POST" => match resource {
                Some("sdm-subscriptions") => {
                    // TODO: Parse SdmSubscriptionRequest from HTTP body
                    let request = nudm_handler::SdmSubscriptionRequest::default();
                    let (_result, _subscription) = nudm_handler::udm_nudm_sdm_handle_subscription_create(
                        self.udm_ue_id, stream_id, &request);
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                    // TODO: Send error response
                }
            },
            "DELETE" => match resource {
                Some("sdm-subscriptions") => {
                    let subscription_id = resource_components.get(2).map(|s| s.as_str());
                    let _result = nudm_handler::udm_nudm_sdm_handle_subscription_delete(
                        self.udm_ue_id, stream_id, subscription_id);
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
                    // TODO: Send error response
                }
            },
            _ => {
                log::error!("[{}] Invalid HTTP method [{}]", suci, method);
                // TODO: Send 404 Not Found error
            }
        }
    }


    /// Handle SBI client events in operational state
    fn handle_sbi_client_event(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let udm_ue = match context.ue_find_by_id(self.udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UDM UE not found [{}]", self.udm_ue_id);
                return;
            }
        };

        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("[{}] No SBI data in client event", udm_ue.suci);
                return;
            }
        };

        let stream_id = match sbi.stream_id {
            Some(id) => id,
            None => {
                log::error!("[{}] No stream ID in SBI client event", udm_ue.suci);
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("[{}] No message in SBI client event", udm_ue.suci);
                return;
            }
        };

        let service_name = message.service_name.clone();
        let resource_components = message.resource_components.clone();
        let state = sbi.state;
        let suci = udm_ue.suci.clone();

        drop(context); // Release lock before calling handlers

        match service_name.as_str() {
            "nudr-dr" => {
                self.handle_nudr_dr_response(&suci, &resource_components, stream_id, state);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
                // TODO: Send error response
            }
        }
    }

    /// Handle NUDR DR responses
    fn handle_nudr_dr_response(
        &mut self,
        suci: &str,
        resource_components: &[String],
        stream_id: u64,
        state: Option<i32>,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("subscription-data") => {
                let resource2 = resource_components.get(2).map(|s| s.as_str());
                match resource2 {
                    Some("authentication-data") => {
                        let resource3 = resource_components.get(3).map(|s| s.as_str()).unwrap_or("");
                        // TODO: Get actual HTTP method and status from response
                        let (result, _auth_info) = nudr_handler::udm_nudr_dr_handle_subscription_authentication(
                            self.udm_ue_id,
                            stream_id,
                            "GET", // HTTP method
                            resource3,
                            200, // HTTP status
                            None, // AuthenticationSubscription from response
                        );
                        if !result.success {
                            log::warn!(
                                "udm_nudr_dr_handle_subscription_authentication() failed"
                            );
                            self.transition(UdmUeState::Exception);
                        }
                    }
                    Some("context-data") => {
                        let resource3 = resource_components.get(3).map(|s| s.as_str()).unwrap_or("");
                        // TODO: Get actual HTTP method and status from response
                        let (_result, _registration) = nudr_handler::udm_nudr_dr_handle_subscription_context(
                            self.udm_ue_id,
                            stream_id,
                            "PUT", // HTTP method
                            resource3,
                            204, // HTTP status
                        );
                    }
                    _ => {
                        // Check for provisioned-data
                        let resource3 = resource_components.get(3).map(|s| s.as_str());
                        match resource3 {
                            Some("provisioned-data") => {
                                let resource4 = resource_components.get(4).map(|s| s.as_str()).unwrap_or("");
                                let sbi_state: nudr_handler::UdmSbiState = state.unwrap_or(0).into();
                                // TODO: Get actual data from response
                                let _result = nudr_handler::udm_nudr_dr_handle_subscription_provisioned(
                                    self.udm_ue_id,
                                    stream_id,
                                    sbi_state,
                                    resource4,
                                    200, // HTTP status
                                    None, // ProvisionedDataSets
                                    None, // AccessAndMobilitySubscriptionData
                                    None, // SmfSelectionSubscriptionData
                                    None, // SessionManagementSubscriptionData
                                );
                            }
                            _ => {
                                log::error!(
                                    "[{}] Invalid resource name [{:?}]",
                                    suci,
                                    resource2
                                );
                            }
                        }
                    }
                }
            }
            _ => {
                log::error!("[{}] Invalid resource name [{:?}]", suci, resource);
            }
        }
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let udm_ue = match context.ue_find_by_id(self.udm_ue_id) {
            Some(ue) => ue,
            None => return,
        };

        match event.id {
            UdmEventId::FsmEntry => {
                log::debug!("[{}] UDM UE entering exception state", udm_ue.suci);
            }
            UdmEventId::FsmExit => {
                log::debug!("[{}] UDM UE exiting exception state", udm_ue.suci);
            }
            _ => {
                log::error!(
                    "[{}] Unknown event {}",
                    udm_ue.suci,
                    crate::event::udm_event_get_name(event)
                );
            }
        }
    }
}

/// Debug helper for UE state machine events
pub fn udm_ue_sm_debug(event: &UdmEvent, udm_ue_id: u64) {
    log::trace!("UDM UE SM [{}] event: {}", udm_ue_id, event.name());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::udm_context_init;

    fn setup() {
        udm_context_init(100, 200);
    }

    #[test]
    fn test_udm_ue_sm_new() {
        setup();
        let ctx = UdmUeSmContext::new(1);
        assert_eq!(ctx.state(), UdmUeState::Operational);
    }

    #[test]
    fn test_udm_ue_sm_dispatch_entry() {
        setup();
        let mut ctx = UdmUeSmContext::new(1);

        let mut event = UdmEvent::entry().with_udm_ue(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_ue_sm_dispatch_exit() {
        setup();
        let mut ctx = UdmUeSmContext::new(1);

        let mut event = UdmEvent::exit().with_udm_ue(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_ue_sm_fini() {
        setup();
        let mut ctx = UdmUeSmContext::new(1);
        ctx.fini();
        assert_eq!(ctx.state(), UdmUeState::Final);
    }
}
