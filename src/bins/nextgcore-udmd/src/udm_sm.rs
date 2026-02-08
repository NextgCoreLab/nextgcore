//! UDM Main State Machine
//!
//! Port of src/udm/udm-sm.c - Main UDM state machine implementation

use crate::context::{udm_self, UdmUe};
use crate::event::{UdmEvent, UdmEventId, UdmTimerId};
use crate::sbi_response::{send_error_response, send_gateway_timeout_response, send_not_found_response};
use crate::sess_sm::{UdmSessSmContext, UdmSessState};
use crate::ue_sm::{UdmUeSmContext, UdmUeState};

/// UDM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// UDM state machine context
pub struct UdmSmContext {
    /// Current state
    state: UdmState,
    /// UE state machines (keyed by UE ID)
    ue_sms: std::collections::HashMap<u64, UdmUeSmContext>,
    /// Session state machines (keyed by session ID)
    sess_sms: std::collections::HashMap<u64, UdmSessSmContext>,
}

impl UdmSmContext {
    /// Create a new UDM state machine context
    pub fn new() -> Self {
        Self {
            state: UdmState::Initial,
            ue_sms: std::collections::HashMap::new(),
            sess_sms: std::collections::HashMap::new(),
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("UDM SM: Initializing");
        self.state = UdmState::Initial;

        // Process initial state - transition to operational
        let mut event = UdmEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("UDM SM: Finalizing");
        let mut event = UdmEvent::exit();
        self.dispatch(&mut event);
        self.state = UdmState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdmEvent) {
        udm_sm_debug(event);

        match self.state {
            UdmState::Initial => {
                self.handle_initial_state(event);
            }
            UdmState::Operational => {
                self.handle_operational_state(event);
            }
            UdmState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdmState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == UdmState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut UdmEvent) {
        // Transition to operational state
        log::info!("UDM SM: Transitioning from Initial to Operational");
        self.state = UdmState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut UdmEvent) {
        log::debug!("UDM SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdmEvent) {
        match event.id {
            UdmEventId::FsmEntry => {
                log::info!("UDM entering operational state");
            }

            UdmEventId::FsmExit => {
                log::info!("UDM exiting operational state");
            }

            UdmEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }

            UdmEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }

            UdmEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }


    /// Handle SBI server events
    fn handle_sbi_server_event(&mut self, event: &mut UdmEvent) {
        let (stream_id, service_name, api_version, method, resource_components, num_of_dataset_names) = {
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
                message.num_of_dataset_names,
            )
        };

        // Check API version based on service
        let expected_version = if service_name == "nudm-sdm" { "v2" } else { "v1" };
        if api_version != expected_version {
            log::error!("Not supported version [{api_version}]");
            send_error_response(stream_id, 400, &format!("Unsupported API version: {api_version}"));
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(&method, &resource_components, stream_id);
            }
            "nudm-ueau" | "nudm-uecm" | "nudm-sdm" => {
                self.handle_nudm_request(
                    event,
                    &service_name,
                    &method,
                    &resource_components,
                    stream_id,
                    num_of_dataset_names,
                );
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
                send_error_response(stream_id, 400, &format!("Invalid API name: {service_name}"));
            }
        }
    }

    /// Handle NNRF NFM (NF Management) requests
    fn handle_nnrf_nfm_request(
        &mut self,
        method: &str,
        resource_components: &[String],
        _stream_id: u64,
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: NF status notify handling requires NRF integration to dispatch to NF FSM
                }
                _ => {
                    log::error!("Invalid HTTP method [{method}]");
                }
            },
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NUDM requests (UEAU, UECM, SDM)
    fn handle_nudm_request(
        &mut self,
        event: &mut UdmEvent,
        _service_name: &str,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
        num_of_dataset_names: usize,
    ) {
        // First resource component should be SUPI or SUCI
        let supi_or_suci = match resource_components.first() {
            Some(s) => s,
            None => {
                log::error!("Not found [{method}]");
                send_not_found_response(stream_id, "SUPI/SUCI not specified");
                return;
            }
        };

        // Check for auth-events with ctx_id
        let mut udm_ue: Option<UdmUe> = None;

        if num_of_dataset_names == 0 {
            if let Some(resource1) = resource_components.get(1) {
                if resource1 == "auth-events" {
                    if let Some(ctx_id) = resource_components.get(2) {
                        let ctx = udm_self();
                        let context = ctx.read().unwrap();
                        udm_ue = context.ue_find_by_ctx_id(ctx_id);
                    }
                }
            }
        }

        // If not found by ctx_id, try SUPI/SUCI
        if udm_ue.is_none() {
            let ctx = udm_self();
            let context = ctx.read().unwrap();

            // Try to find by SUPI first
            let supi = extract_supi(supi_or_suci);
            if let Some(ref s) = supi {
                udm_ue = context.ue_find_by_supi(s);
            }

            // If not found, try to add for POST/GET methods
            if udm_ue.is_none() {
                drop(context);
                match method {
                    "POST" | "GET" => {
                        let ctx = udm_self();
                        let context = ctx.read().unwrap();
                        udm_ue = context.ue_add(supi_or_suci);
                        if udm_ue.is_none() {
                            log::error!("Invalid Request [{supi_or_suci}]");
                        }
                    }
                    _ => {
                        log::error!("Invalid HTTP method [{method}]");
                    }
                }
            }
        }

        let udm_ue = match udm_ue {
            Some(ue) => ue,
            None => {
                log::error!("Not found [{method}]");
                send_not_found_response(stream_id, "UDM UE not found");
                return;
            }
        };

        // Check if this is a session-related request (SMF registrations)
        if let Some(resource2) = resource_components.get(2) {
            if resource2 == "smf-registrations" {
                if let Some(psi_str) = resource_components.get(3) {
                    if let Ok(psi) = psi_str.parse::<u8>() {
                        self.handle_sess_request(event, &udm_ue, psi, stream_id);
                        return;
                    }
                }
            }
        }

        // Handle UE-level request
        self.handle_ue_request(event, &udm_ue, stream_id);
    }


    /// Handle UE-level request
    fn handle_ue_request(&mut self, event: &mut UdmEvent, udm_ue: &UdmUe, stream_id: u64) {
        // Get or create UE state machine
        let ue_sm = self
            .ue_sms
            .entry(udm_ue.id)
            .or_insert_with(|| UdmUeSmContext::new(udm_ue.id));

        // Set event data
        event.udm_ue_id = Some(udm_ue.id);
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to UE state machine
        ue_sm.dispatch(event);

        // Check for exception state
        if ue_sm.state() == UdmUeState::Exception {
            log::error!("[{}] State machine exception", udm_ue.suci);
            self.ue_sms.remove(&udm_ue.id);
            let ctx = udm_self();
            let context = ctx.read().unwrap();
            context.ue_remove(udm_ue.id);
        }
    }

    /// Handle session-level request
    fn handle_sess_request(
        &mut self,
        event: &mut UdmEvent,
        udm_ue: &UdmUe,
        psi: u8,
        stream_id: u64,
    ) {
        // Find or create session
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let sess = match context.sess_find_by_psi(udm_ue.id, psi) {
            Some(s) => s,
            None => {
                drop(context);
                let ctx = udm_self();
                let context = ctx.read().unwrap();
                match context.sess_add(udm_ue.id, psi) {
                    Some(s) => {
                        log::debug!("[{}:{}] UDM session added", udm_ue.supi.as_deref().unwrap_or(&udm_ue.suci), psi);
                        s
                    }
                    None => {
                        log::error!("Failed to add session");
                        return;
                    }
                }
            }
        };

        // Get or create session state machine
        let sess_sm = self
            .sess_sms
            .entry(sess.id)
            .or_insert_with(|| UdmSessSmContext::new(sess.id, udm_ue.id));

        // Set event data
        event.sess_id = Some(sess.id);
        event.udm_ue_id = Some(udm_ue.id);
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to session state machine
        sess_sm.dispatch(event);

        // Check for exception state
        if sess_sm.state() == UdmSessState::Exception {
            log::error!("[{}:{}] State machine exception", udm_ue.suci, psi);
            self.sess_sms.remove(&sess.id);
            let ctx = udm_self();
            let context = ctx.read().unwrap();
            context.sess_remove(sess.id);
        }
    }

    /// Handle SBI client events
    fn handle_sbi_client_event(&mut self, event: &mut UdmEvent) {
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
        let expected_version = if service_name == "nudm-sdm" { "v2" } else { "v1" };
        if api_version != expected_version {
            log::error!("Not supported version [{api_version}]");
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_response(&resource_components);
            }
            "nnrf-disc" => {
                self.handle_nnrf_disc_response(event, &resource_components);
            }
            "nudr-dr" => {
                self.handle_nudr_dr_response(event, &resource_components);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
            }
        }
    }

    /// Handle NNRF NFM responses
    fn handle_nnrf_nfm_response(&mut self, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                // Note: NF instance FSM dispatch requires NRF integration
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
                // Note: Subscription handling requires NRF integration
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NNRF DISC responses
    fn handle_nnrf_disc_response(&mut self, _event: &mut UdmEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF discover response received");
                // Note: NF discover handling requires NRF integration
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NUDR DR responses
    fn handle_nudr_dr_response(&mut self, event: &mut UdmEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("subscription-data") => {
                // Check if this is a session-related response (SMF registrations)
                if let Some(resource3) = resource_components.get(3) {
                    if resource3 == "smf-registrations" {
                        self.handle_nudr_sess_response(event);
                        return;
                    }
                }
                // Otherwise, it's a UE-level response
                self.handle_nudr_ue_response(event);
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NUDR UE-level response
    fn handle_nudr_ue_response(&mut self, event: &mut UdmEvent) {
        let udm_ue_id = match event.udm_ue_id {
            Some(id) => id,
            None => {
                log::error!("No UDM UE ID in event");
                return;
            }
        };

        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let udm_ue = match context.ue_find_by_id(udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UE Context has already been removed");
                return;
            }
        };

        // Get UE state machine
        let ue_sm = match self.ue_sms.get_mut(&udm_ue_id) {
            Some(sm) => sm,
            None => {
                log::error!("UE state machine not found");
                return;
            }
        };

        // Dispatch to UE state machine
        ue_sm.dispatch(event);

        // Check for exception state
        if ue_sm.state() == UdmUeState::Exception {
            log::warn!("[{}] State machine exception", udm_ue.suci);
            self.ue_sms.remove(&udm_ue_id);
            context.ue_remove(udm_ue_id);
        }
    }

    /// Handle NUDR session-level response
    fn handle_nudr_sess_response(&mut self, event: &mut UdmEvent) {
        let sess_id = match event.sess_id {
            Some(id) => id,
            None => {
                log::error!("No session ID in event");
                return;
            }
        };

        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let sess = match context.sess_find_by_id(sess_id) {
            Some(s) => s,
            None => {
                log::error!("SESS Context has already been removed");
                return;
            }
        };

        let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UE Context has already been removed");
                return;
            }
        };

        // Get session state machine
        let sess_sm = match self.sess_sms.get_mut(&sess_id) {
            Some(sm) => sm,
            None => {
                log::error!("Session state machine not found");
                return;
            }
        };

        // Dispatch to session state machine
        sess_sm.dispatch(event);

        // Check for exception state
        if sess_sm.state() == UdmSessState::Exception {
            log::error!("[{}:{}] State machine exception", udm_ue.suci, sess.psi);
            self.sess_sms.remove(&sess_id);
            context.sess_remove(sess_id);
        }
    }


    /// Handle SBI timer events
    fn handle_sbi_timer_event(&mut self, event: &mut UdmEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            UdmTimerId::NfInstanceRegistrationInterval
            | UdmTimerId::NfInstanceHeartbeatInterval
            | UdmTimerId::NfInstanceNoHeartbeat
            | UdmTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                    // Note: NF instance FSM dispatch requires NRF integration
                }
            }
            UdmTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                    // Note: Subscription renewal requires NRF integration
                }
            }
            UdmTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                    // Note: Subscription update requires NRF integration
                }
            }
            UdmTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                // Send gateway timeout if we have stream context
                if let Some(ref sbi) = event.sbi {
                    if let Some(stream_id) = sbi.stream_id {
                        send_gateway_timeout_response(stream_id, "SBI client timeout");
                    }
                }
            }
        }
    }

    /// Initialize UE state machine
    pub fn ue_sm_init(&mut self, udm_ue_id: u64) {
        let ue_sm = UdmUeSmContext::new(udm_ue_id);
        self.ue_sms.insert(udm_ue_id, ue_sm);
    }

    /// Finalize UE state machine
    pub fn ue_sm_fini(&mut self, udm_ue_id: u64) {
        if let Some(mut ue_sm) = self.ue_sms.remove(&udm_ue_id) {
            ue_sm.fini();
        }
    }

    /// Initialize session state machine
    pub fn sess_sm_init(&mut self, sess_id: u64, udm_ue_id: u64) {
        let sess_sm = UdmSessSmContext::new(sess_id, udm_ue_id);
        self.sess_sms.insert(sess_id, sess_sm);
    }

    /// Finalize session state machine
    pub fn sess_sm_fini(&mut self, sess_id: u64) {
        if let Some(mut sess_sm) = self.sess_sms.remove(&sess_id) {
            sess_sm.fini();
        }
    }
}

impl Default for UdmSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract SUPI from SUCI or SUPI string
fn extract_supi(suci_or_supi: &str) -> Option<String> {
    if suci_or_supi.starts_with("imsi-") {
        Some(suci_or_supi.to_string())
    } else if suci_or_supi.starts_with("suci-") {
        // For SUCI, we would need to decode it - for now return None
        None
    } else {
        None
    }
}

/// Debug helper for state machine events
pub fn udm_sm_debug(event: &UdmEvent) {
    log::trace!("UDM SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udm_sm_context_new() {
        let ctx = UdmSmContext::new();
        assert_eq!(ctx.state(), UdmState::Initial);
    }

    #[test]
    fn test_udm_sm_init() {
        let mut ctx = UdmSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_udm_sm_dispatch_entry() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_dispatch_exit() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_dispatch_timer() {
        let mut ctx = UdmSmContext::new();
        ctx.init();

        let mut event = UdmEvent::sbi_timer(UdmTimerId::NfInstanceNoHeartbeat)
            .with_nf_instance("test-nf".to_string());
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sm_fini() {
        let mut ctx = UdmSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), UdmState::Final);
    }
}
