//! PCF Main State Machine
//!
//! Port of src/pcf/pcf-sm.c - Main PCF state machine implementation

use crate::am_sm::{PcfAmSmContext, PcfAmState};
use crate::context::{pcf_self, PcfApp, PcfSess, PcfUeAm, PcfUeSm};
use crate::event::{PcfEvent, PcfEventId, PcfTimerId};
use crate::sbi_response::{send_error_response, send_not_found_response, send_user_unknown_response, send_gateway_timeout_response};
use crate::sm_sm::{PcfSmSmContext, PcfSmState};

/// PCF state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfState {
    Initial,
    Operational,
    Final,
}

/// PCF state machine context
pub struct PcfSmContext {
    state: PcfState,
    /// AM state machines (keyed by UE AM ID)
    am_sms: std::collections::HashMap<u64, PcfAmSmContext>,
    /// SM state machines (keyed by session ID)
    sm_sms: std::collections::HashMap<u64, PcfSmSmContext>,
}

impl PcfSmContext {
    pub fn new() -> Self {
        Self {
            state: PcfState::Initial,
            am_sms: std::collections::HashMap::new(),
            sm_sms: std::collections::HashMap::new(),
        }
    }

    pub fn init(&mut self) {
        log::debug!("PCF SM: Initializing");
        self.state = PcfState::Initial;
        let mut event = PcfEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("PCF SM: Finalizing");
        let mut event = PcfEvent::exit();
        self.dispatch(&mut event);
        self.state = PcfState::Final;
    }

    pub fn dispatch(&mut self, event: &mut PcfEvent) {
        pcf_sm_debug(event);

        match self.state {
            PcfState::Initial => self.handle_initial_state(event),
            PcfState::Operational => self.handle_operational_state(event),
            PcfState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> PcfState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == PcfState::Operational
    }

    fn handle_initial_state(&mut self, _event: &mut PcfEvent) {
        log::info!("PCF SM: Transitioning from Initial to Operational");
        self.state = PcfState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut PcfEvent) {
        log::debug!("PCF SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut PcfEvent) {
        match event.id {
            PcfEventId::FsmEntry => {
                log::info!("PCF entering operational state");
            }
            PcfEventId::FsmExit => {
                log::info!("PCF exiting operational state");
            }
            PcfEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }
            PcfEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }
            PcfEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut PcfEvent) {
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
                self.handle_nnrf_nfm_request(&method, &resource_components, stream_id);
            }
            "npcf-am-policy-control" => {
                self.handle_am_policy_control_request(event, &method, &resource_components, stream_id);
            }
            "npcf-smpolicycontrol" => {
                self.handle_smpolicycontrol_request(event, &method, &resource_components, stream_id);
            }
            "npcf-policyauthorization" => {
                self.handle_policyauthorization_request(event, &method, &resource_components, stream_id);
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
                    // Note: ogs_nnrf_nfm_handle_nf_status_notify processes NF status changes
                    // This is handled by the nnrf integration when NRF is enabled
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

    fn handle_am_policy_control_request(
        &mut self,
        event: &mut PcfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let ctx = pcf_self();
        let context = ctx.read().unwrap();

        let pcf_ue_am: Option<PcfUeAm> = match method {
            "POST" => {
                // Extract SUPI from PolicyAssociationRequest
                // For now, use resource component as SUPI placeholder
                let supi = resource_components.first().map(|s| s.as_str()).unwrap_or("unknown");
                drop(context);
                let ctx = pcf_self();
                let context = ctx.read().unwrap();
                context.ue_am_find_by_supi(supi).or_else(|| context.ue_am_add(supi))
            }
            "DELETE" => {
                // Find by association ID
                resource_components.get(1).and_then(|assoc_id| context.ue_am_find_by_association_id(assoc_id))
            }
            _ => None,
        };

        let pcf_ue_am = match pcf_ue_am {
            Some(ue) => ue,
            None => {
                log::error!("Not found [{method}]");
                send_not_found_response(stream_id, "AM policy association not found");
                return;
            }
        };

        // Get or create AM state machine
        let am_sm = self.am_sms.entry(pcf_ue_am.id).or_insert_with(|| PcfAmSmContext::new(pcf_ue_am.id));

        // Set event data
        event.pcf_ue_am_id = Some(pcf_ue_am.id);
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to AM state machine
        am_sm.dispatch(event);

        // Check for exception or deleted state
        if am_sm.state() == PcfAmState::Exception {
            log::error!("[{}] State machine exception", pcf_ue_am.supi);
            self.am_sms.remove(&pcf_ue_am.id);
            let ctx = pcf_self();
            let context = ctx.read().unwrap();
            context.ue_am_remove(pcf_ue_am.id);
        } else if am_sm.state() == PcfAmState::Deleted {
            log::debug!("[{}] PCF-AM removed", pcf_ue_am.supi);
            self.am_sms.remove(&pcf_ue_am.id);
            let ctx = pcf_self();
            let context = ctx.read().unwrap();
            context.ue_am_remove(pcf_ue_am.id);
        }
    }


    fn handle_smpolicycontrol_request(
        &mut self,
        event: &mut PcfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        // Find or create session
        let (sess, pcf_ue_sm): (Option<PcfSess>, Option<PcfUeSm>) = if resource_components.get(1).is_none() {
            // POST /sm-policies - need SUPI and PSI from SmPolicyContextData
            // For now, use placeholder
            let supi = resource_components.first().map(|s| s.as_str()).unwrap_or("unknown");
            let psi = 1u8; // Placeholder

            // First try to find existing UE SM
            let ctx = pcf_self();
            let context = ctx.read().unwrap();
            let mut pcf_ue_sm = context.ue_sm_find_by_supi(supi);
            drop(context);

            // Create if not found and method is POST
            if pcf_ue_sm.is_none() && method == "POST" {
                let ctx = pcf_self();
                let context = ctx.read().unwrap();
                pcf_ue_sm = context.ue_sm_add(supi);
            }

            if let Some(ref ue_sm) = pcf_ue_sm {
                // First try to find existing session
                let ctx = pcf_self();
                let context = ctx.read().unwrap();
                let mut sess = context.sess_find_by_psi(ue_sm.id, psi);
                drop(context);

                // Create if not found and method is POST
                if sess.is_none() && method == "POST" {
                    let ctx = pcf_self();
                    let context = ctx.read().unwrap();
                    sess = context.sess_add(ue_sm.id, psi);
                }
                (sess, Some(ue_sm.clone()))
            } else {
                (None, None)
            }
        } else {
            // Operations on existing policy - find by sm_policy_id
            let sm_policy_id = resource_components.get(1).unwrap();
            let ctx = pcf_self();
            let context = ctx.read().unwrap();
            let sess = context.sess_find_by_sm_policy_id(sm_policy_id);
            let pcf_ue_sm = sess.as_ref().and_then(|s| context.ue_sm_find_by_id(s.pcf_ue_sm_id));
            (sess, pcf_ue_sm)
        };

        let sess = match sess {
            Some(s) => s,
            None => {
                log::error!("Not found [{method}]");
                send_user_unknown_response(stream_id);
                return;
            }
        };

        let pcf_ue_sm = match pcf_ue_sm {
            Some(u) => u,
            None => {
                log::error!("UE SM not found");
                return;
            }
        };

        // Get or create SM state machine
        let sm_sm = self.sm_sms.entry(sess.id).or_insert_with(|| PcfSmSmContext::new(sess.id, pcf_ue_sm.id));

        // Set event data
        event.sess_id = Some(sess.id);
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to SM state machine
        sm_sm.dispatch(event);

        // Check for exception state
        if sm_sm.state() == PcfSmState::Exception {
            log::error!("[{}:{}] State machine exception", pcf_ue_sm.supi, sess.psi);
            self.sm_sms.remove(&sess.id);
            self.clear_session(&sess, &pcf_ue_sm);
        }
    }

    fn handle_policyauthorization_request(
        &mut self,
        event: &mut PcfEvent,
        method: &str,
        resource_components: &[String],
        stream_id: u64,
    ) {
        let ctx = pcf_self();
        let context = ctx.read().unwrap();

        // Find session by IP address or app_session_id
        let (sess, app_session): (Option<PcfSess>, Option<PcfApp>) = if resource_components.get(1).is_none() {
            // POST /app-sessions - find by IP address
            // For now, use placeholder
            (None, None)
        } else {
            // Operations on existing app session
            let app_session_id = resource_components.get(1).unwrap();
            let app = context.app_find_by_app_session_id(app_session_id);
            let sess = app.as_ref().and_then(|a| context.sess_find_by_id(a.sess_id));
            (sess, app)
        };

        let sess = match sess {
            Some(s) => s,
            None => {
                log::error!("Not found [{method}]");
                send_not_found_response(stream_id, "Policy authorization session not found");
                return;
            }
        };

        let pcf_ue_sm = match context.ue_sm_find_by_id(sess.pcf_ue_sm_id) {
            Some(u) => u,
            None => {
                log::error!("UE SM not found");
                return;
            }
        };

        // Get or create SM state machine
        let sm_sm = self.sm_sms.entry(sess.id).or_insert_with(|| PcfSmSmContext::new(sess.id, pcf_ue_sm.id));

        // Set event data
        event.sess_id = Some(sess.id);
        event.app = app_session;
        if let Some(ref mut sbi) = event.sbi {
            sbi.stream_id = Some(stream_id);
        }

        // Dispatch to SM state machine
        sm_sm.dispatch(event);

        // Check for exception state
        if sm_sm.state() == PcfSmState::Exception {
            log::error!("[{}:{}] State machine exception", pcf_ue_sm.supi, sess.psi);
            self.sm_sms.remove(&sess.id);
            self.clear_session(&sess, &pcf_ue_sm);
        }
    }

    fn handle_sbi_client_event(&mut self, event: &mut PcfEvent) {
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
                self.handle_nnrf_nfm_response(&resource_components);
            }
            "nnrf-disc" => {
                self.handle_nnrf_disc_response(event, &resource_components);
            }
            "nudr-dr" => {
                self.handle_nudr_dr_response(event, &resource_components);
            }
            "nbsf-management" => {
                self.handle_nbsf_management_response(event, &resource_components);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
            }
        }
    }

    fn handle_nnrf_nfm_response(&mut self, resource_components: &[String]) {
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
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nnrf_disc_response(&mut self, _event: &mut PcfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF discover response received");
                // Note: pcf_nnrf_handle_nf_discover processes NF discovery results
                // This is handled by the nnrf integration when NRF is enabled
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource_components.first());
            }
        }
    }

    fn handle_nudr_dr_response(&mut self, event: &mut PcfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());
        let resource3 = resource_components.get(3).map(|s| s.as_str());

        match resource {
            Some("policy-data") => {
                match resource3 {
                    Some("am-data") => {
                        // AM data response - dispatch to AM state machine
                        if let Some(pcf_ue_am_id) = event.pcf_ue_am_id {
                            if let Some(am_sm) = self.am_sms.get_mut(&pcf_ue_am_id) {
                                am_sm.dispatch(event);
                                if am_sm.state() == PcfAmState::Exception {
                                    let ctx = pcf_self();
                                    let context = ctx.read().unwrap();
                                    if let Some(pcf_ue_am) = context.ue_am_find_by_id(pcf_ue_am_id) {
                                        log::error!("[{}] State machine exception", pcf_ue_am.supi);
                                    }
                                    self.am_sms.remove(&pcf_ue_am_id);
                                    context.ue_am_remove(pcf_ue_am_id);
                                }
                            }
                        }
                    }
                    Some("sm-data") => {
                        // SM data response - dispatch to SM state machine
                        if let Some(sess_id) = event.sess_id {
                            if let Some(sm_sm) = self.sm_sms.get_mut(&sess_id) {
                                sm_sm.dispatch(event);
                                self.check_sm_state(sess_id);
                            }
                        }
                    }
                    _ => {
                        log::error!("Invalid resource name [{resource3:?}]");
                    }
                }
            }
            _ => {
                log::error!("Invalid resource name [{resource:?}]");
            }
        }
    }

    fn handle_nbsf_management_response(&mut self, event: &mut PcfEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("pcf-bindings") => {
                if let Some(sess_id) = event.sess_id {
                    if let Some(sm_sm) = self.sm_sms.get_mut(&sess_id) {
                        sm_sm.dispatch(event);
                        self.check_sm_state(sess_id);
                    }
                }
            }
            _ => {
                log::error!("Invalid resource name [{resource:?}]");
            }
        }
    }

    fn check_sm_state(&mut self, sess_id: u64) {
        if let Some(sm_sm) = self.sm_sms.get(&sess_id) {
            if sm_sm.state() == PcfSmState::Exception || sm_sm.state() == PcfSmState::Deleted {
                let ctx = pcf_self();
                let context = ctx.read().unwrap();
                if let Some(sess) = context.sess_find_by_id(sess_id) {
                    if let Some(pcf_ue_sm) = context.ue_sm_find_by_id(sess.pcf_ue_sm_id) {
                        if sm_sm.state() == PcfSmState::Exception {
                            log::error!("[{}:{}] State machine exception", pcf_ue_sm.supi, sess.psi);
                        } else {
                            log::debug!("[{}:{}] PCF session removed", pcf_ue_sm.supi, sess.psi);
                        }
                        drop(context);
                        self.sm_sms.remove(&sess_id);
                        self.clear_session(&sess, &pcf_ue_sm);
                    }
                }
            }
        }
    }

    fn clear_session(&self, sess: &PcfSess, pcf_ue_sm: &PcfUeSm) {
        let ctx = pcf_self();
        let context = ctx.read().unwrap();
        if pcf_ue_sm.is_last_session() {
            context.ue_sm_remove(pcf_ue_sm.id);
        } else {
            context.sess_remove(sess.id);
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut PcfEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            PcfTimerId::NfInstanceRegistrationInterval
            | PcfTimerId::NfInstanceHeartbeatInterval
            | PcfTimerId::NfInstanceNoHeartbeat
            | PcfTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{nf_instance_id}] NF instance timer: {timer_id:?}");
                    // Note: Update NF instance load and dispatch to NF FSM
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            PcfTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{subscription_id}] Subscription validity expired");
                    // Note: Send new subscription and remove old one
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            PcfTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{subscription_id}] Need to update Subscription");
                    // Note: Send subscription update to NRF
                    // This is handled by the nnrf integration when NRF is enabled
                }
            }
            PcfTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                // Note: stream_id would need to be tracked for the pending request
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }
}

impl Default for PcfSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn pcf_sm_debug(event: &PcfEvent) {
    log::trace!("PCF SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::pcf_context_init;
    use crate::event::SbiMessage;

    fn setup() {
        pcf_context_init(100, 100);
    }

    #[test]
    fn test_pcf_sm_context_new() {
        let ctx = PcfSmContext::new();
        assert_eq!(ctx.state(), PcfState::Initial);
    }

    #[test]
    fn test_pcf_sm_init() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_dispatch_entry() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        let mut event = PcfEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_pcf_sm_dispatch_exit() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        let mut event = PcfEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_pcf_sm_fini() {
        let mut ctx = PcfSmContext::new();
        ctx.init();
        ctx.fini();
        assert_eq!(ctx.state(), PcfState::Final);
    }

    // Integration tests for SBI server event handling

    #[test]
    fn test_pcf_sm_sbi_server_invalid_api_version() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        // Create SBI server event with invalid API version
        let message = SbiMessage {
            service_name: "npcf-am-policy-control".to_string(),
            api_version: "v99".to_string(), // Invalid version
            resource_components: vec!["policies".to_string()],
            method: "POST".to_string(),
            res_status: None,
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 400 error response for invalid version
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_sbi_server_invalid_api_name() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "invalid-service".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["resource".to_string()],
            method: "POST".to_string(),
            res_status: None,
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 400 error response for invalid API name
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_sbi_server_am_policy_not_found() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "npcf-am-policy-control".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["policies".to_string(), "non-existent-id".to_string()],
            method: "DELETE".to_string(),
            res_status: None,
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 404 not found response
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_sbi_server_sm_policy_not_found() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "npcf-smpolicycontrol".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["sm-policies".to_string(), "non-existent-id".to_string()],
            method: "POST".to_string(),
            res_status: None,
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send user unknown response
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_sbi_server_policy_auth_not_found() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "npcf-policyauthorization".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["app-sessions".to_string(), "non-existent-id".to_string()],
            method: "DELETE".to_string(),
            res_status: None,
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiServer)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        // Should send 404 not found response
        assert!(ctx.is_operational());
    }

    // Integration tests for SBI client event handling

    #[test]
    fn test_pcf_sm_sbi_client_nnrf_nfm_response() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-nfm".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string()],
            method: "PUT".to_string(),
            res_status: Some(200),
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiClient)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_sbi_client_nnrf_disc_response() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let message = SbiMessage {
            service_name: "nnrf-disc".to_string(),
            api_version: "v1".to_string(),
            resource_components: vec!["nf-instances".to_string()],
            method: "GET".to_string(),
            res_status: Some(200),
            uri: None,
        };

        let mut event = PcfEvent::new(PcfEventId::SbiClient)
            .with_stream_id(1)
            .with_sbi_message(message);

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    // Integration tests for timer event handling

    #[test]
    fn test_pcf_sm_timer_nf_instance() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let mut event = PcfEvent::sbi_timer(PcfTimerId::NfInstanceHeartbeatInterval)
            .with_nf_instance("test-nf-instance".to_string());

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_timer_subscription_validity() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let mut event = PcfEvent::sbi_timer(PcfTimerId::SubscriptionValidity)
            .with_subscription("test-subscription".to_string());

        ctx.dispatch(&mut event);
        assert!(ctx.is_operational());
    }

    #[test]
    fn test_pcf_sm_timer_sbi_client_wait() {
        setup();
        let mut ctx = PcfSmContext::new();
        ctx.init();

        let mut event = PcfEvent::sbi_timer(PcfTimerId::SbiClientWait);

        ctx.dispatch(&mut event);
        // Should send gateway timeout response
        assert!(ctx.is_operational());
    }
}
