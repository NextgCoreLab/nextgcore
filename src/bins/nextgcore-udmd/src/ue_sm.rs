//! UDM UE State Machine
//!
//! Port of src/udm/ue-sm.c - UE state machine implementation

use crate::context::udm_self;
use crate::event::{UdmEvent, UdmEventId};
use crate::sbi_response::send_error_response;

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
                self.handle_nudm_sdm_request(
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

    /// Handle NUDM UEAU requests
    ///
    /// udmd-04: UECM/SDM/UEAU operations are handled by the live async HTTP
    /// dispatcher in `main.rs`. The state-machine branch is a legacy Open5GS
    /// port that was never wired to the HTTP path. All handler calls have been
    /// removed; the structure is kept for future extension only.
    fn handle_nudm_ueau_request(
        &mut self,
        _method: &str,
        _resource_components: &[String],
        _stream_id: u64,
    ) {
        log::debug!(
            "UDM UE SM [{}]: UEAU request on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id
        );
    }

    /// Handle NUDM UECM requests
    ///
    /// udmd-04: see `handle_nudm_ueau_request`.
    fn handle_nudm_uecm_request(
        &mut self,
        _method: &str,
        _resource_components: &[String],
        _stream_id: u64,
    ) {
        log::debug!(
            "UDM UE SM [{}]: UECM request on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id
        );
    }

    /// Handle NUDM SDM requests
    ///
    /// udmd-04: see `handle_nudm_ueau_request`.
    fn handle_nudm_sdm_request(
        &mut self,
        _method: &str,
        _resource_components: &[String],
        _stream_id: u64,
        _num_of_dataset_names: usize,
    ) {
        log::debug!(
            "UDM UE SM [{}]: SDM request on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id
        );
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
                log::error!("Invalid API name [{service_name}]");
                send_error_response(stream_id, 400, &format!("Invalid API name: {service_name}"));
            }
        }
    }

    /// Handle NUDR DR responses
    ///
    /// udmd-04: see `handle_nudm_ueau_request`.
    fn handle_nudr_dr_response(
        &mut self,
        _suci: &str,
        _resource_components: &[String],
        _stream_id: u64,
        _state: Option<i32>,
    ) {
        log::debug!(
            "UDM UE SM [{}]: NUDR-DR response on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id
        );
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
