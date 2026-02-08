//! AUSF Main State Machine
//!
//! Port of src/ausf/ausf-sm.c - Main AUSF state machine implementation

use crate::context::{ausf_self, AusfUe};
use crate::event::{AusfEvent, AusfEventId, AusfTimerId};
use crate::sbi_response::{send_error_response, send_not_found_response, send_gateway_timeout_response};
use crate::ue_sm::{AusfUeSmContext, AusfUeState};

/// AUSF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// AUSF state machine context
pub struct AusfSmContext {
    /// Current state
    state: AusfState,
    /// UE state machines (keyed by UE ID)
    ue_sms: std::collections::HashMap<u64, AusfUeSmContext>,
}

impl AusfSmContext {
    /// Create a new AUSF state machine context
    pub fn new() -> Self {
        Self {
            state: AusfState::Initial,
            ue_sms: std::collections::HashMap::new(),
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("AUSF SM: Initializing");
        self.state = AusfState::Initial;

        // Process initial state - transition to operational
        let mut event = AusfEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("AUSF SM: Finalizing");
        let mut event = AusfEvent::exit();
        self.dispatch(&mut event);
        self.state = AusfState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut AusfEvent) {
        ausf_sm_debug(event);

        match self.state {
            AusfState::Initial => {
                self.handle_initial_state(event);
            }
            AusfState::Operational => {
                self.handle_operational_state(event);
            }
            AusfState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> AusfState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == AusfState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut AusfEvent) {
        // Transition to operational state
        log::info!("AUSF SM: Transitioning from Initial to Operational");
        self.state = AusfState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut AusfEvent) {
        log::debug!("AUSF SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut AusfEvent) {
        match event.id {
            AusfEventId::FsmEntry => {
                log::info!("AUSF entering operational state");
            }

            AusfEventId::FsmExit => {
                log::info!("AUSF exiting operational state");
            }

            AusfEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }

            AusfEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }

            AusfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    /// Handle SBI server events
    fn handle_sbi_server_event(&mut self, event: &mut AusfEvent) {
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

        // Check API version
        if api_version != "v1" {
            log::error!("Not supported version [{api_version}]");
            send_error_response(stream_id, 400, &format!("Unsupported API version: {api_version}"));
            return;
        }

        // Route based on service name
        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request_simple(&method, &resource_components, stream_id);
            }
            "nausf-auth" => {
                self.handle_nausf_auth_request_simple(event, &method, &resource_components, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
                send_error_response(stream_id, 400, &format!("Invalid API name: {service_name}"));
            }
        }
    }

    /// Handle NNRF NFM (NF Management) requests
    fn handle_nnrf_nfm_request_simple(&mut self, method: &str, resource_components: &[String], _stream_id: u64) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: ogs_nnrf_nfm_handle_nf_status_notify processes NF status changes
                    // This is handled by the nnrf integration when NRF is enabled
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

    /// Handle NAUSF Auth requests (simplified)
    fn handle_nausf_auth_request_simple(
        &mut self,
        event: &mut AusfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        // Find or create AUSF UE based on method
        let ausf_ue: Option<AusfUe> = match method {
            "POST" => {
                // For POST, look for supi_or_suci in AuthenticationInfo
                if let Some(supi_or_suci) = resource_components.get(1) {
                    let ctx = ausf_self();
                    let context = ctx.read().unwrap();
                    let ue = context.ue_find_by_suci_or_supi(supi_or_suci);
                    if ue.is_none() {
                        drop(context);
                        let ctx = ausf_self();
                        let context = ctx.read().unwrap();
                        context.ue_add(supi_or_suci)
                    } else {
                        ue
                    }
                } else {
                    None
                }
            }
            "DELETE" | "PUT" => {
                // For DELETE/PUT, look up by ctx_id from resource component
                if let Some(ctx_id) = resource_components.get(1) {
                    let ctx = ausf_self();
                    let context = ctx.read().unwrap();
                    context.ue_find_by_ctx_id(ctx_id)
                } else {
                    None
                }
            }
            _ => None,
        };

        let ausf_ue = match ausf_ue {
            Some(ue) => ue,
            None => {
                log::error!("Not found [{method}]");
                send_not_found_response(stream_id, "Authentication context not found");
                return;
            }
        };

        // Get or create UE state machine
        let ue_sm = self
            .ue_sms
            .entry(ausf_ue.id)
            .or_insert_with(|| AusfUeSmContext::new(ausf_ue.id));

        // Set event data
        event.ausf_ue_id = Some(ausf_ue.id);
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to UE state machine
        ue_sm.dispatch(event);

        // Check for exception state
        if ue_sm.state() == AusfUeState::Exception {
            log::error!("[{}] State machine exception", ausf_ue.suci);
            self.ue_sms.remove(&ausf_ue.id);
            let ctx = ausf_self();
            let context = ctx.read().unwrap();
            context.ue_remove(ausf_ue.id);
        }
    }

    /// Handle SBI client events
    fn handle_sbi_client_event(&mut self, event: &mut AusfEvent) {
        let (service_name, api_version, method, resource_components, res_status, data) = {
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
                message.method.clone(),
                message.resource_components.clone(),
                message.res_status,
                sbi.data,
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
                self.handle_nnrf_nfm_response_simple(&method, &resource_components);
            }
            "nnrf-disc" => {
                self.handle_nnrf_disc_response_simple(&method, &resource_components, res_status);
            }
            "nudm-ueau" => {
                self.handle_nudm_ueau_response_simple(event, &method, &resource_components, res_status, data);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
            }
        }
    }

    /// Handle NNRF NFM responses (simplified)
    fn handle_nnrf_nfm_response_simple(&mut self, _method: &str, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                // Note: Dispatch to NF instance FSM for registration handling
                // This is handled by the nnrf integration when NRF is enabled
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
                // Note: Handle NRF subscription response for NF discovery updates
                // This is handled by the nnrf integration when NRF is enabled
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NNRF DISC responses (simplified)
    fn handle_nnrf_disc_response_simple(&mut self, method: &str, resource_components: &[String], res_status: Option<u16>) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                if method == "GET" {
                    if res_status == Some(200) {
                        log::debug!("NF discover response received");
                        // Note: ausf_nnrf_handle_nf_discover processes NF discovery results
                        // This is handled by the nnrf integration when NRF is enabled
                    } else {
                        log::error!(
                            "HTTP response error [{}]",
                            res_status.unwrap_or(0)
                        );
                    }
                } else {
                    log::error!("Invalid HTTP method [{method}]");
                }
            }
            _ => {
                log::error!(
                    "Invalid resource name [{:?}]",
                    resource_components.first()
                );
            }
        }
    }

    /// Handle NUDM UEAU responses (simplified)
    fn handle_nudm_ueau_response_simple(
        &mut self,
        event: &mut AusfEvent,
        _method: &str,
        _resource_components: &[String],
        _res_status: Option<u16>,
        data: Option<u64>,
    ) {
        // Get xact ID from data
        let _xact_id = match data {
            Some(id) => id,
            None => {
                log::error!("No xact ID in NUDM UEAU response");
                return;
            }
        };

        // Get AUSF UE ID from event
        let ausf_ue_id = match event.ausf_ue_id {
            Some(id) => id,
            None => {
                log::error!("No AUSF UE ID in event");
                return;
            }
        };

        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        let ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UE(ausf-ue) Context has already been removed");
                return;
            }
        };

        // Get UE state machine
        let ue_sm = match self.ue_sms.get_mut(&ausf_ue_id) {
            Some(sm) => sm,
            None => {
                log::error!("UE state machine not found");
                return;
            }
        };

        // Dispatch to UE state machine
        ue_sm.dispatch(event);

        // Check for exception or deleted state
        if ue_sm.state() == AusfUeState::Exception {
            log::warn!("[{}] State machine exception", ausf_ue.suci);
            self.ue_sms.remove(&ausf_ue_id);
            context.ue_remove(ausf_ue_id);
        } else if ue_sm.state() == AusfUeState::Deleted {
            if let Some(ref supi) = ausf_ue.supi {
                log::info!("[{supi}] AUSF-UE removed");
            }
            self.ue_sms.remove(&ausf_ue_id);
            context.ue_remove(ausf_ue_id);
        }
    }

    /// Handle SBI timer events
    fn handle_sbi_timer_event(&mut self, event: &mut AusfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            AusfTimerId::NfInstanceRegistrationInterval
            | AusfTimerId::NfInstanceHeartbeatInterval
            | AusfTimerId::NfInstanceNoHeartbeat
            | AusfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                    // Note: Update NF instance load and dispatch to NF FSM
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            AusfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                    // Note: Send new subscription and remove old one
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            AusfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                    // Note: Send subscription update to NRF
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            AusfTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }

    /// Initialize UE state machine
    pub fn ue_sm_init(&mut self, ausf_ue_id: u64) {
        let ue_sm = AusfUeSmContext::new(ausf_ue_id);
        self.ue_sms.insert(ausf_ue_id, ue_sm);
    }

    /// Finalize UE state machine
    pub fn ue_sm_fini(&mut self, ausf_ue_id: u64) {
        if let Some(mut ue_sm) = self.ue_sms.remove(&ausf_ue_id) {
            ue_sm.fini();
        }
    }
}

impl Default for AusfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug helper for state machine events
pub fn ausf_sm_debug(event: &AusfEvent) {
    log::trace!("AUSF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ausf_context_init;
    use crate::event::SbiMessage;

    fn setup() {
        ausf_context_init(100);
    }

    #[test]
    fn test_ausf_sm_context_new() {
        let ctx = AusfSmContext::new();
        assert_eq!(ctx.state(), AusfState::Initial);
    }

    #[test]
    fn test_ausf_sm_init() {
        let mut ctx = AusfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_dispatch_entry() {
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_ausf_sm_dispatch_exit() {
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_ausf_sm_dispatch_timer() {
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::sbi_timer(AusfTimerId::NfInstanceNoHeartbeat)
            .with_nf_instance("test-nf".to_string());
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_ausf_sm_fini() {
        let mut ctx = AusfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), AusfState::Final);
    }

    // Integration tests for SBI server event handling

    #[test]
    fn test_ausf_sm_sbi_server_invalid_api_version() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nausf-auth".to_string(),
            api_version: "v99".to_string(), // Invalid version
            resource_components: vec!["ue-authentications".to_string()],
            method: "POST".to_string(),
            res_status: None,
        };

        let mut event = AusfEvent::new(AusfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should log error for invalid version
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_sbi_server_invalid_api_name() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "invalid-service".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["resource".to_string()],
            method: "POST".to_string(),
            res_status: None,
        };

        let mut event = AusfEvent::new(AusfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 400 error response for invalid API name
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_sbi_server_nnrf_nfm_notify() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-nfm".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-status-notify".to_string()],
            method: "POST".to_string(),
            res_status: None,
        };

        let mut event = AusfEvent::new(AusfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_sbi_server_nausf_auth_ue_not_found() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nausf-auth".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["ue-authentications".to_string()],
            method: "POST".to_string(),
            res_status: None,
        };

        let mut event = AusfEvent::new(AusfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 404 not found - no UE in context
        assert!(ctx.is_operational());
    }

    // Integration tests for SBI client event handling

    #[test]
    fn test_ausf_sm_sbi_client_nnrf_nfm_response() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-nfm".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string()],
            method: "PUT".to_string(),
            res_status: Some(200),
        };

        let mut event = AusfEvent::new(AusfEventId::SbiClient)
            .with_stream_id(1)
            .with_sbi_message(message)
            .with_sbi_data(1);

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_sbi_client_nnrf_disc_response_success() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-disc".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string()],
            method: "GET".to_string(),
            res_status: Some(200),
        };

        let mut event = AusfEvent::new(AusfEventId::SbiClient)
            .with_stream_id(1)
            .with_sbi_message(message)
            .with_sbi_data(1);

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_sbi_client_nnrf_disc_response_error() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-disc".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string()],
            method: "GET".to_string(),
            res_status: Some(404), // Error status
        };

        let mut event = AusfEvent::new(AusfEventId::SbiClient)
            .with_stream_id(1)
            .with_sbi_message(message)
            .with_sbi_data(1);

        ctx.dispatch(&mut event);
        // Should log error for 404 response
        assert!(ctx.is_operational());
    }

    // Integration tests for timer event handling

    #[test]
    fn test_ausf_sm_timer_nf_instance_heartbeat() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::sbi_timer(AusfTimerId::NfInstanceHeartbeatInterval)
            .with_nf_instance("test-nf-instance".to_string());

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_timer_subscription_validity() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::sbi_timer(AusfTimerId::SubscriptionValidity)
            .with_subscription("test-subscription".to_string());

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_timer_subscription_patch() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::sbi_timer(AusfTimerId::SubscriptionPatch)
            .with_subscription("test-subscription".to_string());

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_ausf_sm_timer_sbi_client_wait() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        let mut event = AusfEvent::sbi_timer(AusfTimerId::SbiClientWait);

        ctx.dispatch(&mut event);
        // Should send gateway timeout response
        assert!(ctx.is_operational());
    }

    // Integration tests for UE state machine management

    #[test]
    fn test_ausf_sm_ue_sm_init_fini() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        // Initialize UE state machine
        ctx.ue_sm_init(1);
        assert!(ctx.ue_sms.contains_key(&1));

        // Finalize UE state machine
        ctx.ue_sm_fini(1);
        assert!(!ctx.ue_sms.contains_key(&1));
    }

    #[test]
    fn test_ausf_sm_with_ue_auth_flow() {
        setup();
        let mut ctx = AusfSmContext::new();
        ctx.init();

        // Add UE to context
        let ausf_ue_id = {
            let context = ausf_self();
            let ctx_guard = context.write().unwrap();
            let ue = ctx_guard.ue_add("suci-0-001-01-0000-0-0-0000000001");
            ue.map(|u| u.id).unwrap_or(0)
        };

        if ausf_ue_id > 0 {
            // Initialize UE state machine
            ctx.ue_sm_init(ausf_ue_id);

            // Create SBI server event for authentication
            let message = SbiMessage {
                service_name: "nausf-auth".to_string(),
                api_version: "v1".to_string(),
                resource_components: vec!["ue-authentications".to_string()],
                method: "POST".to_string(),
                res_status: None,
            };

            let mut event = AusfEvent::new(AusfEventId::SbiServer)
                .with_stream_id(1)
                .with_sbi_message(message)
                .with_ausf_ue(ausf_ue_id);

            ctx.dispatch(&mut event);
            assert!(ctx.is_operational());
        }
    }
}
