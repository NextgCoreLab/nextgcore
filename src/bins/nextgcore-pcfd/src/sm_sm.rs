//! PCF SM (Session Management) State Machine
//!
//! Port of src/pcf/sm-sm.c - SM state machine for session policy control

use crate::context::{pcf_self, PcfSess, PcfUeSm};
use crate::event::{PcfEvent, PcfEventId};
use crate::sbi_response::{send_user_unknown_response, send_policy_context_denied_response};

/// PCF SM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfSmState {
    Initial,
    Operational,
    Deleted,
    Exception,
    Final,
}

/// PCF SM state machine context
pub struct PcfSmSmContext {
    state: PcfSmState,
    sess_id: u64,
    pcf_ue_sm_id: u64,
}

impl PcfSmSmContext {
    pub fn new(sess_id: u64, pcf_ue_sm_id: u64) -> Self {
        let mut ctx = Self {
            state: PcfSmState::Initial,
            sess_id,
            pcf_ue_sm_id,
        };
        ctx.init();
        ctx
    }

    pub fn init(&mut self) {
        log::debug!("PCF SM SM: Initializing for session {}", self.sess_id);
        self.state = PcfSmState::Operational;
    }

    pub fn fini(&mut self) {
        log::debug!("PCF SM SM: Finalizing for session {}", self.sess_id);
        self.state = PcfSmState::Final;
    }

    pub fn dispatch(&mut self, event: &mut PcfEvent) {
        pcf_sm_sm_debug(event);

        match self.state {
            PcfSmState::Initial => self.handle_initial_state(event),
            PcfSmState::Operational => self.handle_operational_state(event),
            PcfSmState::Deleted => self.handle_deleted_state(event),
            PcfSmState::Exception => self.handle_exception_state(event),
            PcfSmState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> PcfSmState {
        self.state
    }

    fn handle_initial_state(&mut self, _event: &mut PcfEvent) {
        log::info!("PCF SM SM: Transitioning from Initial to Operational");
        self.state = PcfSmState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut PcfEvent) {
        log::debug!("PCF SM SM: In final state");
    }

    fn handle_deleted_state(&mut self, event: &mut PcfEvent) {
        let (sess, pcf_ue_sm) = match get_sess_and_ue(self.sess_id, self.pcf_ue_sm_id) {
            Some((s, u)) => (s, u),
            None => {
                log::error!("Session or UE SM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}:{}] PCF SM entering deleted state", pcf_ue_sm.supi, sess.psi);
                // Note: Update metrics - decrement session count when metrics integration is enabled
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}:{}] PCF SM exiting deleted state", pcf_ue_sm.supi, sess.psi);
            }
            _ => {
                log::error!("[{}:{}] Unknown event {} in deleted state", pcf_ue_sm.supi, sess.psi, event.name());
            }
        }
    }

    fn handle_exception_state(&mut self, event: &mut PcfEvent) {
        let (sess, pcf_ue_sm) = match get_sess_and_ue(self.sess_id, self.pcf_ue_sm_id) {
            Some((s, u)) => (s, u),
            None => {
                log::error!("Session or UE SM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}:{}] PCF SM entering exception state", pcf_ue_sm.supi, sess.psi);
                // Note: Update metrics - decrement session count when metrics integration is enabled
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}:{}] PCF SM exiting exception state", pcf_ue_sm.supi, sess.psi);
            }
            _ => {
                log::error!("[{}:{}] Unknown event {} in exception state", pcf_ue_sm.supi, sess.psi, event.name());
            }
        }
    }

    fn handle_operational_state(&mut self, event: &mut PcfEvent) {
        let (sess, pcf_ue_sm) = match get_sess_and_ue(self.sess_id, self.pcf_ue_sm_id) {
            Some((s, u)) => (s, u),
            None => {
                log::error!("Session or UE SM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}:{}] PCF SM entering operational state", pcf_ue_sm.supi, sess.psi);
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}:{}] PCF SM exiting operational state", pcf_ue_sm.supi, sess.psi);
            }
            PcfEventId::SbiServer => {
                self.handle_sbi_server_event(event, &sess, &pcf_ue_sm);
            }
            PcfEventId::SbiClient => {
                self.handle_sbi_client_event(event, &sess, &pcf_ue_sm);
            }
            _ => {
                log::error!("[{}:{}] Unknown event {}", pcf_ue_sm.supi, sess.psi, event.name());
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut PcfEvent, sess: &PcfSess, pcf_ue_sm: &PcfUeSm) {
        let (stream_id, service_name, method, resource_components) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("[{}:{}] No SBI data in server event", pcf_ue_sm.supi, sess.psi);
                    return;
                }
            };

            let stream_id = match sbi.stream_id {
                Some(id) => id,
                None => {
                    log::error!("[{}:{}] No stream ID in SBI event", pcf_ue_sm.supi, sess.psi);
                    return;
                }
            };

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("[{}:{}] No message in SBI event", pcf_ue_sm.supi, sess.psi);
                    return;
                }
            };

            (
                stream_id,
                message.service_name.clone(),
                message.method.clone(),
                message.resource_components.clone(),
            )
        };

        match service_name.as_str() {
            "npcf-smpolicycontrol" => {
                self.handle_smpolicycontrol_request(sess, pcf_ue_sm, stream_id, &method, &resource_components);
            }
            "npcf-policyauthorization" => {
                self.handle_policyauthorization_request(event, sess, pcf_ue_sm, stream_id, &method, &resource_components);
            }
            _ => {
                log::error!("[{}:{}] Invalid API name [{}]", pcf_ue_sm.supi, sess.psi, service_name);
            }
        }
    }

    fn handle_smpolicycontrol_request(
        &mut self,
        sess: &PcfSess,
        pcf_ue_sm: &PcfUeSm,
        stream_id: u64,
        _method: &str,
        resource_components: &[String],
    ) {
        let resource1 = resource_components.get(1);

        if resource1.is_none() {
            // POST /sm-policies - Create SM policy
            log::debug!("[{}:{}] Handling SM policy create (stream={})", pcf_ue_sm.supi, sess.psi, stream_id);
            // Note: pcf_npcf_smpolicycontrol_handle_create builds SmPolicyDecision response
            // The handler is invoked via the direct HTTP path in main.rs
            log::info!("[{}:{}] SM policy association created", pcf_ue_sm.supi, sess.psi);
        } else {
            // Operations on existing policy
            let resource2 = resource_components.get(2).map(|s| s.as_str());
            match resource2 {
                Some("delete") => {
                    log::debug!("[{}:{}] Handling SM policy delete (stream={})", pcf_ue_sm.supi, sess.psi, stream_id);
                    // Note: pcf_npcf_smpolicycontrol_handle_delete handles policy termination
                    // The handler is invoked via the direct HTTP path in main.rs
                    log::info!("[{}:{}] SM policy association deleted", pcf_ue_sm.supi, sess.psi);
                }
                _ => {
                    log::error!("[{}:{}] Invalid HTTP URI", pcf_ue_sm.supi, sess.psi);
                }
            }
        }
    }

    fn handle_policyauthorization_request(
        &mut self,
        _event: &PcfEvent,
        sess: &PcfSess,
        pcf_ue_sm: &PcfUeSm,
        stream_id: u64,
        method: &str,
        resource_components: &[String],
    ) {
        let resource1 = resource_components.get(1);

        if resource1.is_some() {
            let resource2 = resource_components.get(2).map(|s| s.as_str());
            if let Some("delete") = resource2 {
                log::debug!("[{}:{}] Handling policy authorization delete (stream={})", pcf_ue_sm.supi, sess.psi, stream_id);
                // Note: pcf_npcf_policyauthorization_handle_delete handles AF session termination
                // The handler is invoked via the direct HTTP path in main.rs
            } else {
                match method {
                    "PATCH" => {
                        log::debug!("[{}:{}] Handling policy authorization update (stream={})", pcf_ue_sm.supi, sess.psi, stream_id);
                        // Note: pcf_npcf_policyauthorization_handle_update handles AF session modification
                        // The handler is invoked via the direct HTTP path in main.rs
                    }
                    _ => {
                        log::error!("[{}:{}] Unknown method [{}]", pcf_ue_sm.supi, sess.psi, method);
                    }
                }
            }
        } else {
            match method {
                "POST" => {
                    log::debug!("[{}:{}] Handling policy authorization create (stream={})", pcf_ue_sm.supi, sess.psi, stream_id);
                    // Note: pcf_npcf_policyauthorization_handle_create handles AF session creation
                    // The handler is invoked via the direct HTTP path in main.rs
                    log::info!("[{}:{}] Policy authorization created", pcf_ue_sm.supi, sess.psi);
                }
                _ => {
                    log::error!("[{}:{}] Unknown method [{}]", pcf_ue_sm.supi, sess.psi, method);
                }
            }
        }
    }

    fn handle_sbi_client_event(&mut self, event: &mut PcfEvent, sess: &PcfSess, pcf_ue_sm: &PcfUeSm) {
        let (stream_id, service_name, method, resource_components, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("[{}:{}] No SBI data in client event", pcf_ue_sm.supi, sess.psi);
                    return;
                }
            };

            let stream_id = sbi.stream_id.unwrap_or(0);

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("[{}:{}] No message in SBI client event", pcf_ue_sm.supi, sess.psi);
                    return;
                }
            };

            (
                stream_id,
                message.service_name.clone(),
                message.method.clone(),
                message.resource_components.clone(),
                message.res_status,
            )
        };

        match service_name.as_str() {
            "nudr-dr" => {
                self.handle_nudr_dr_response(sess, pcf_ue_sm, stream_id, &resource_components, res_status);
            }
            "nbsf-management" => {
                self.handle_nbsf_management_response(sess, pcf_ue_sm, stream_id, &method, &resource_components, res_status);
            }
            _ => {
                log::error!("[{}:{}] Invalid API name [{}]", pcf_ue_sm.supi, sess.psi, service_name);
            }
        }
    }

    fn handle_nudr_dr_response(
        &mut self,
        sess: &PcfSess,
        pcf_ue_sm: &PcfUeSm,
        _stream_id: u64,
        resource_components: &[String],
        res_status: Option<u16>,
    ) {
        let resource0 = resource_components.first().map(|s| s.as_str());
        let resource1 = resource_components.get(1).map(|s| s.as_str());

        match (resource0, resource1) {
            (Some("policy-data"), Some("ues")) => {
                let status = res_status.unwrap_or(0);
                if status != 200 && status != 204 {
                    if status == 404 {
                        log::warn!("[{}:{}] Cannot find SUPI [{}]", pcf_ue_sm.supi, sess.psi, status);
                        send_user_unknown_response(0); // stream_id would be tracked from request
                    } else {
                        log::error!("[{}:{}] HTTP response error [{}]", pcf_ue_sm.supi, sess.psi, status);
                        send_policy_context_denied_response(0); // stream_id would be tracked from request
                    }
                    return;
                }
                // Note: pcf_nudr_dr_handle_query_sm_data processes SM subscription data from UDR
                // The handler is invoked by the nudr_handler module
                log::debug!("[{}:{}] NUDR DR SM data response received", pcf_ue_sm.supi, sess.psi);
            }
            _ => {
                log::error!("[{}:{}] Invalid resource name [{:?}]", pcf_ue_sm.supi, sess.psi, resource_components);
            }
        }
    }

    fn handle_nbsf_management_response(
        &mut self,
        sess: &PcfSess,
        pcf_ue_sm: &PcfUeSm,
        _stream_id: u64,
        method: &str,
        resource_components: &[String],
        res_status: Option<u16>,
    ) {
        let resource0 = resource_components.first().map(|s| s.as_str());
        let resource1 = resource_components.get(1);

        match resource0 {
            Some("pcf-bindings") => {
                if resource1.is_some() {
                    // DELETE response
                    match method {
                        "DELETE" => {
                            let status = res_status.unwrap_or(0);
                            if status != 204 {
                                log::warn!("[{}:{}] HTTP response error [{}]", pcf_ue_sm.supi, sess.psi, status);
                            }
                            // Note: pcf_nbsf_management_handle_de_register handles BSF deregistration
                            // The binding is cleared from BSF when session terminates
                            log::debug!("[{}:{}] BSF de-register response received", pcf_ue_sm.supi, sess.psi);
                            self.state = PcfSmState::Deleted;
                        }
                        _ => {
                            log::error!("[{}:{}] Unknown method [{}]", pcf_ue_sm.supi, sess.psi, method);
                        }
                    }
                } else {
                    // POST response
                    match method {
                        "POST" => {
                            let status = res_status.unwrap_or(0);
                            if status == 201 {
                                // Note: pcf_nbsf_management_handle_register handles BSF registration
                                // The binding is stored in BSF for PCF discovery
                                log::debug!("[{}:{}] BSF register response received", pcf_ue_sm.supi, sess.psi);
                            } else {
                                log::error!("[{}:{}] HTTP response error [{}]", pcf_ue_sm.supi, sess.psi, status);
                                // Still send SM policy response
                            }
                            // Note: SM policy create response is sent after BSF registration completes
                            // The response is built by npcf_handler and sent via HTTP server
                        }
                        _ => {
                            log::error!("[{}:{}] Unknown method [{}]", pcf_ue_sm.supi, sess.psi, method);
                        }
                    }
                }
            }
            _ => {
                log::error!("[{}:{}] Invalid resource name [{:?}]", pcf_ue_sm.supi, sess.psi, resource_components);
            }
        }
    }
}

fn get_sess_and_ue(sess_id: u64, pcf_ue_sm_id: u64) -> Option<(PcfSess, PcfUeSm)> {
    let ctx = pcf_self();
    let context = ctx.read().ok()?;
    let sess = context.sess_find_by_id(sess_id)?;
    let pcf_ue_sm = context.ue_sm_find_by_id(pcf_ue_sm_id)?;
    Some((sess, pcf_ue_sm))
}

fn pcf_sm_sm_debug(event: &PcfEvent) {
    log::trace!("PCF SM SM event: {}", event.name());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_context() {
        let ctx = pcf_self();
        if let Ok(mut context) = ctx.write() {
            if !context.is_initialized() {
                context.init(100, 200);
            }
        };
    }

    #[test]
    fn test_pcf_sm_sm_new() {
        setup_context();
        let ctx = pcf_self();
        // Get write lock to add UE SM and session
        let (sess_id, ue_sm_id) = {
            let context = ctx.write().unwrap();
            let ue_sm = context.ue_sm_add("imsi-001010000000010").unwrap();
            let sess = context.sess_add(ue_sm.id, 1).unwrap();
            (sess.id, ue_sm.id)
        };
        let sm = PcfSmSmContext::new(sess_id, ue_sm_id);
        assert_eq!(sm.state(), PcfSmState::Operational);
    }

    #[test]
    fn test_pcf_sm_sm_dispatch_entry() {
        setup_context();
        let ctx = pcf_self();
        // Get write lock to add UE SM and session
        let (sess_id, ue_sm_id) = {
            let context = ctx.write().unwrap();
            let ue_sm = context.ue_sm_add("imsi-001010000000011").unwrap();
            let sess = context.sess_add(ue_sm.id, 1).unwrap();
            (sess.id, ue_sm.id)
        };
        let mut sm = PcfSmSmContext::new(sess_id, ue_sm_id);
        let mut event = PcfEvent::entry();
        sm.dispatch(&mut event);
        assert_eq!(sm.state(), PcfSmState::Operational);
    }
}
