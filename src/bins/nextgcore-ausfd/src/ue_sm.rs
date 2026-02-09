//! AUSF UE State Machine
//!
//! Port of src/ausf/ue-sm.c - UE state machine implementation

use crate::context::ausf_self;
use crate::event::{AusfEvent, AusfEventId};
use crate::nausf_handler;
use crate::nudm_handler;
use crate::sbi_response::{send_error_response, send_forbidden_response};

/// AUSF UE state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AusfUeState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Deleted state
    Deleted,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// AUSF UE state machine context
pub struct AusfUeSmContext {
    /// Current state
    state: AusfUeState,
    /// AUSF UE ID
    ausf_ue_id: u64,
}

impl AusfUeSmContext {
    /// Create a new AUSF UE state machine context
    pub fn new(ausf_ue_id: u64) -> Self {
        let mut ctx = Self {
            state: AusfUeState::Initial,
            ausf_ue_id,
        };
        ctx.init();
        ctx
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!("AUSF UE SM [{}]: Initializing", self.ausf_ue_id);
        self.state = AusfUeState::Initial;

        // Process initial state - transition to operational
        let mut event = AusfEvent::entry().with_ausf_ue(self.ausf_ue_id);
        self.handle_initial_state(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("AUSF UE SM [{}]: Finalizing", self.ausf_ue_id);
        let mut event = AusfEvent::exit().with_ausf_ue(self.ausf_ue_id);
        self.handle_final_state(&mut event);
        self.state = AusfUeState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut AusfEvent) {
        ausf_ue_sm_debug(event, self.ausf_ue_id);

        match self.state {
            AusfUeState::Initial => {
                self.handle_initial_state(event);
            }
            AusfUeState::Operational => {
                self.handle_operational_state(event);
            }
            AusfUeState::Deleted => {
                self.handle_deleted_state(event);
            }
            AusfUeState::Exception => {
                self.handle_exception_state(event);
            }
            AusfUeState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> AusfUeState {
        self.state
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: AusfUeState) {
        log::debug!(
            "AUSF UE SM [{}]: {:?} -> {:?}",
            self.ausf_ue_id,
            self.state,
            new_state
        );
        self.state = new_state;
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut AusfEvent) {
        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        if let Some(ausf_ue) = context.ue_find_by_id(self.ausf_ue_id) {
            log::debug!("[{}] AUSF UE SM: Initial state", ausf_ue.suci);
        }

        // Transition to operational state
        self.transition(AusfUeState::Operational);
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut AusfEvent) {
        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        if let Some(ausf_ue) = context.ue_find_by_id(self.ausf_ue_id) {
            log::debug!("[{}] AUSF UE SM: Final state", ausf_ue.suci);
        }
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut AusfEvent) {
        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        let ausf_ue = match context.ue_find_by_id(self.ausf_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("AUSF UE not found [{}]", self.ausf_ue_id);
                return;
            }
        };

        match event.id {
            AusfEventId::FsmEntry => {
                log::debug!("[{}] AUSF UE entering operational state", ausf_ue.suci);
            }

            AusfEventId::FsmExit => {
                log::debug!("[{}] AUSF UE exiting operational state", ausf_ue.suci);
            }

            AusfEventId::SbiServer => {
                self.handle_sbi_server_event(event, &ausf_ue);
            }

            AusfEventId::SbiClient => {
                self.handle_sbi_client_event(event, &ausf_ue);
            }

            _ => {
                log::error!(
                    "[{}] Unknown event {}",
                    ausf_ue.suci,
                    crate::event::ausf_event_get_name(event)
                );
            }
        }
    }

    /// Handle SBI server events in operational state
    fn handle_sbi_server_event(
        &mut self,
        event: &mut AusfEvent,
        ausf_ue: &crate::context::AusfUe,
    ) {
        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("[{}] No SBI data in server event", ausf_ue.suci);
                return;
            }
        };

        let stream_id = match sbi.stream_id {
            Some(id) => id,
            None => {
                log::error!("[{}] No stream ID in SBI event", ausf_ue.suci);
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("[{}] No message in SBI event", ausf_ue.suci);
                return;
            }
        };

        match message.method.as_str() {
            "POST" => {
                let handled =
                    nausf_handler::ausf_nausf_auth_handle_authenticate(self.ausf_ue_id, stream_id);
                if !handled {
                    log::error!("[{}] Cannot handle SBI message", ausf_ue.suci);
                    self.transition(AusfUeState::Exception);
                }
            }
            "PUT" => {
                if ausf_ue.supi.is_none() {
                    log::error!("[{}] No SUPI", ausf_ue.suci);
                    send_error_response(stream_id, 400, "Missing SUPI");
                    self.transition(AusfUeState::Exception);
                    return;
                }

                let handled = nausf_handler::ausf_nausf_auth_handle_authenticate_confirmation(
                    self.ausf_ue_id,
                    stream_id,
                );
                if !handled {
                    log::error!("[{}] Cannot handle SBI message", ausf_ue.suci);
                    self.transition(AusfUeState::Exception);
                }
            }
            "DELETE" => {
                if ausf_ue.supi.is_none() {
                    log::error!("[{}] No SUPI", ausf_ue.suci);
                    send_error_response(stream_id, 400, "Missing SUPI");
                    self.transition(AusfUeState::Exception);
                    return;
                }

                let handled = nausf_handler::ausf_nausf_auth_handle_authenticate_delete(
                    self.ausf_ue_id,
                    stream_id,
                );
                if !handled {
                    log::error!("[{}] Cannot handle SBI message", ausf_ue.suci);
                    self.transition(AusfUeState::Exception);
                }
            }
            _ => {
                log::error!(
                    "[{}] Invalid HTTP method [{}]",
                    ausf_ue.suci,
                    message.method
                );
                send_forbidden_response(stream_id, &format!("Method not allowed: {}", message.method));
            }
        }
    }

    /// Handle SBI client events in operational state
    fn handle_sbi_client_event(
        &mut self,
        event: &mut AusfEvent,
        ausf_ue: &crate::context::AusfUe,
    ) {
        // Extract all needed data from event first to avoid borrow conflicts
        let (stream_id, service_name, method, resource_components, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => {
                    log::error!("[{}] No SBI data in client event", ausf_ue.suci);
                    return;
                }
            };

            let stream_id = match sbi.stream_id {
                Some(id) => id,
                None => {
                    log::error!("[{}] No stream ID in SBI client event", ausf_ue.suci);
                    return;
                }
            };

            let message = match &sbi.message {
                Some(msg) => msg,
                None => {
                    log::error!("[{}] No message in SBI client event", ausf_ue.suci);
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
            "nudm-ueau" => {
                self.handle_nudm_ueau_response(ausf_ue, &method, &resource_components, res_status, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
            }
        }
    }

    /// Handle NUDM UEAU responses
    fn handle_nudm_ueau_response(
        &mut self,
        ausf_ue: &crate::context::AusfUe,
        method: &str,
        resource_components: &[String],
        res_status: Option<u16>,
        stream_id: u64,
    ) {
        // Check response status
        let status = res_status.unwrap_or(0);
        if status != 200 && status != 201 && status != 204 {
            if status == 404 {
                log::warn!("[{}] Cannot find SUPI [{}]", ausf_ue.suci, status);
            } else {
                log::error!("[{}] HTTP response error [{}]", ausf_ue.suci, status);
            }
            send_error_response(stream_id, status, &format!("UDM UEAU error: {status}"));
            self.transition(AusfUeState::Exception);
            return;
        }

        // Route based on method and resource
        match method {
            "PUT" => {
                let resource = resource_components.get(1).map(|s| s.as_str());
                match resource {
                    Some("auth-events") => {
                        nudm_handler::ausf_nudm_ueau_handle_auth_removal_ind(
                            self.ausf_ue_id,
                            stream_id,
                        );
                        self.transition(AusfUeState::Deleted);
                    }
                    _ => {
                        log::error!("[{}] Invalid HTTP method [{}]", ausf_ue.suci, method);
                    }
                }
            }
            _ => {
                let resource = resource_components.get(1).map(|s| s.as_str());
                match resource {
                    Some("security-information") => {
                        nudm_handler::ausf_nudm_ueau_handle_get(self.ausf_ue_id, stream_id);
                    }
                    Some("auth-events") => {
                        nudm_handler::ausf_nudm_ueau_handle_result_confirmation_inform(
                            self.ausf_ue_id,
                            stream_id,
                        );
                    }
                    _ => {
                        log::error!("[{}] Invalid HTTP method [{}]", ausf_ue.suci, method);
                    }
                }
            }
        }
    }

    /// Handle deleted state
    fn handle_deleted_state(&mut self, event: &mut AusfEvent) {
        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        let ausf_ue = match context.ue_find_by_id(self.ausf_ue_id) {
            Some(ue) => ue,
            None => return,
        };

        match event.id {
            AusfEventId::FsmEntry => {
                log::debug!("[{}] AUSF UE entering deleted state", ausf_ue.suci);
            }
            AusfEventId::FsmExit => {
                log::debug!("[{}] AUSF UE exiting deleted state", ausf_ue.suci);
            }
            _ => {
                if let Some(ref supi) = ausf_ue.supi {
                    log::error!(
                        "[{}] Unknown event {}",
                        supi,
                        crate::event::ausf_event_get_name(event)
                    );
                }
            }
        }
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut AusfEvent) {
        let ctx = ausf_self();
        let context = ctx.read().unwrap();

        let ausf_ue = match context.ue_find_by_id(self.ausf_ue_id) {
            Some(ue) => ue,
            None => return,
        };

        match event.id {
            AusfEventId::FsmEntry => {
                log::debug!("[{}] AUSF UE entering exception state", ausf_ue.suci);
            }
            AusfEventId::FsmExit => {
                log::debug!("[{}] AUSF UE exiting exception state", ausf_ue.suci);
            }
            _ => {
                log::error!(
                    "[{}] Unknown event {}",
                    ausf_ue.suci,
                    crate::event::ausf_event_get_name(event)
                );
            }
        }
    }
}

/// Debug helper for UE state machine events
pub fn ausf_ue_sm_debug(event: &AusfEvent, ausf_ue_id: u64) {
    log::trace!("AUSF UE SM [{}] event: {}", ausf_ue_id, event.name());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ausf_context_init;

    fn setup() {
        ausf_context_init(100);
    }

    #[test]
    fn test_ausf_ue_sm_new() {
        setup();
        let ctx = AusfUeSmContext::new(1);
        assert_eq!(ctx.state(), AusfUeState::Operational);
    }

    #[test]
    fn test_ausf_ue_sm_dispatch_entry() {
        setup();
        let mut ctx = AusfUeSmContext::new(1);

        let mut event = AusfEvent::entry().with_ausf_ue(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_ausf_ue_sm_dispatch_exit() {
        setup();
        let mut ctx = AusfUeSmContext::new(1);

        let mut event = AusfEvent::exit().with_ausf_ue(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_ausf_ue_sm_fini() {
        setup();
        let mut ctx = AusfUeSmContext::new(1);
        ctx.fini();
        assert_eq!(ctx.state(), AusfUeState::Final);
    }
}
