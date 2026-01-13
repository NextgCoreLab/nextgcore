//! PCF AM (Access Management) State Machine
//!
//! Port of src/pcf/am-sm.c - AM state machine for UE AM policy control

use crate::context::{pcf_self, PcfUeAm};
use crate::event::{PcfEvent, PcfEventId};
use crate::sbi_response::send_error_response;

/// PCF AM state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcfAmState {
    Initial,
    Operational,
    Deleted,
    Exception,
    Final,
}

/// PCF AM state machine context
pub struct PcfAmSmContext {
    state: PcfAmState,
    pcf_ue_am_id: u64,
}

impl PcfAmSmContext {
    pub fn new(pcf_ue_am_id: u64) -> Self {
        let mut ctx = Self {
            state: PcfAmState::Initial,
            pcf_ue_am_id,
        };
        // Auto-transition to operational
        ctx.init();
        ctx
    }

    pub fn init(&mut self) {
        log::debug!("PCF AM SM: Initializing for UE AM {}", self.pcf_ue_am_id);
        self.state = PcfAmState::Operational;
    }

    pub fn fini(&mut self) {
        log::debug!("PCF AM SM: Finalizing for UE AM {}", self.pcf_ue_am_id);
        self.state = PcfAmState::Final;
    }

    pub fn dispatch(&mut self, event: &mut PcfEvent) {
        pcf_am_sm_debug(event);

        match self.state {
            PcfAmState::Initial => self.handle_initial_state(event),
            PcfAmState::Operational => self.handle_operational_state(event),
            PcfAmState::Deleted => self.handle_deleted_state(event),
            PcfAmState::Exception => self.handle_exception_state(event),
            PcfAmState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> PcfAmState {
        self.state
    }

    fn handle_initial_state(&mut self, _event: &mut PcfEvent) {
        log::info!("PCF AM SM: Transitioning from Initial to Operational");
        self.state = PcfAmState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut PcfEvent) {
        log::debug!("PCF AM SM: In final state");
    }

    fn handle_deleted_state(&mut self, event: &mut PcfEvent) {
        let pcf_ue_am = match get_pcf_ue_am(self.pcf_ue_am_id) {
            Some(ue) => ue,
            None => {
                log::error!("PCF UE AM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}] PCF AM entering deleted state", pcf_ue_am.supi);
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}] PCF AM exiting deleted state", pcf_ue_am.supi);
            }
            _ => {
                log::error!("[{}] Unknown event {} in deleted state", pcf_ue_am.supi, event.name());
            }
        }
    }

    fn handle_exception_state(&mut self, event: &mut PcfEvent) {
        let pcf_ue_am = match get_pcf_ue_am(self.pcf_ue_am_id) {
            Some(ue) => ue,
            None => {
                log::error!("PCF UE AM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}] PCF AM entering exception state", pcf_ue_am.supi);
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}] PCF AM exiting exception state", pcf_ue_am.supi);
            }
            _ => {
                log::error!("[{}] Unknown event {} in exception state", pcf_ue_am.supi, event.name());
            }
        }
    }

    fn handle_operational_state(&mut self, event: &mut PcfEvent) {
        let pcf_ue_am = match get_pcf_ue_am(self.pcf_ue_am_id) {
            Some(ue) => ue,
            None => {
                log::error!("PCF UE AM not found");
                return;
            }
        };

        match event.id {
            PcfEventId::FsmEntry => {
                log::debug!("[{}] PCF AM entering operational state", pcf_ue_am.supi);
            }
            PcfEventId::FsmExit => {
                log::debug!("[{}] PCF AM exiting operational state", pcf_ue_am.supi);
            }
            PcfEventId::SbiServer => {
                self.handle_sbi_server_event(event, &pcf_ue_am);
            }
            PcfEventId::SbiClient => {
                self.handle_sbi_client_event(event, &pcf_ue_am);
            }
            _ => {
                log::error!("[{}] Unknown event {}", pcf_ue_am.supi, event.name());
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut PcfEvent, pcf_ue_am: &PcfUeAm) {
        let (stream_id, method) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("[{}] No SBI data in server event", pcf_ue_am.supi);
                    return;
                }
            };

            let stream_id = match sbi.stream_id {
                Some(id) => id,
                None => {
                    log::error!("[{}] No stream ID in SBI event", pcf_ue_am.supi);
                    return;
                }
            };

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("[{}] No message in SBI event", pcf_ue_am.supi);
                    return;
                }
            };

            (stream_id, message.method.clone())
        };

        match method.as_str() {
            "POST" => {
                log::debug!("[{}] Handling AM policy control create (stream={})", pcf_ue_am.supi, stream_id);
                // Note: pcf_npcf_am_policy_control_handle_create builds PolicyAssociation response
                // The handler is invoked via the direct HTTP path in main.rs
                log::info!("[{}] AM policy association created", pcf_ue_am.supi);
            }
            "DELETE" => {
                log::debug!("[{}] Handling AM policy control delete (stream={})", pcf_ue_am.supi, stream_id);
                // Note: HTTP 204 No Content response is sent by the HTTP handler in main.rs
                log::info!("[{}] AM policy association deleted", pcf_ue_am.supi);
                self.state = PcfAmState::Deleted;
            }
            _ => {
                log::error!("[{}] Invalid HTTP method [{}]", pcf_ue_am.supi, method);
                send_error_response(stream_id, 405, &format!("Method not allowed: {}", method));
            }
        }
    }

    fn handle_sbi_client_event(&mut self, event: &mut PcfEvent, pcf_ue_am: &PcfUeAm) {
        let (stream_id, service_name, resource_components, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("[{}] No SBI data in client event", pcf_ue_am.supi);
                    return;
                }
            };

            let stream_id = sbi.stream_id.unwrap_or(0);

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("[{}] No message in SBI client event", pcf_ue_am.supi);
                    return;
                }
            };

            (
                stream_id,
                message.service_name.clone(),
                message.resource_components.clone(),
                message.res_status,
            )
        };

        match service_name.as_str() {
            "nudr-dr" => {
                self.handle_nudr_dr_response(pcf_ue_am, stream_id, &resource_components, res_status);
            }
            _ => {
                log::error!("[{}] Invalid API name [{}]", pcf_ue_am.supi, service_name);
            }
        }
    }

    fn handle_nudr_dr_response(
        &mut self,
        pcf_ue_am: &PcfUeAm,
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
                        log::warn!("[{}] Cannot find SUPI [{}]", pcf_ue_am.supi, status);
                    } else {
                        log::error!("[{}] HTTP response error [{}]", pcf_ue_am.supi, status);
                    }
                    send_error_response(0, status, &format!("UDR query failed: {}", status));
                    return;
                }
                // Note: pcf_nudr_dr_handle_query_am_data processes AM subscription data from UDR
                // The handler is invoked by the nudr_handler module
                log::debug!("[{}] NUDR DR AM data response received", pcf_ue_am.supi);
            }
            _ => {
                log::error!("[{}] Invalid resource name [{:?}]", pcf_ue_am.supi, resource_components);
            }
        }
    }
}

fn get_pcf_ue_am(id: u64) -> Option<PcfUeAm> {
    let ctx = pcf_self();
    let context = ctx.read().ok()?;
    context.ue_am_find_by_id(id)
}

fn pcf_am_sm_debug(event: &PcfEvent) {
    log::trace!("PCF AM SM event: {}", event.name());
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
    fn test_pcf_am_sm_new() {
        setup_context();
        let ctx = pcf_self();
        // Get write lock to add UE AM
        let ue_am_id = {
            let context = ctx.write().unwrap();
            let ue_am = context.ue_am_add("imsi-001010000000020").unwrap();
            ue_am.id
        };
        let sm = PcfAmSmContext::new(ue_am_id);
        assert_eq!(sm.state(), PcfAmState::Operational);
    }

    #[test]
    fn test_pcf_am_sm_dispatch_entry() {
        setup_context();
        let ctx = pcf_self();
        // Get write lock to add UE AM
        let ue_am_id = {
            let context = ctx.write().unwrap();
            let ue_am = context.ue_am_add("imsi-001010000000021").unwrap();
            ue_am.id
        };
        let mut sm = PcfAmSmContext::new(ue_am_id);
        let mut event = PcfEvent::entry();
        sm.dispatch(&mut event);
        assert_eq!(sm.state(), PcfAmState::Operational);
    }
}
