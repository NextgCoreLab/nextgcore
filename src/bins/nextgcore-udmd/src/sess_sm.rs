//! UDM Session State Machine
//!
//! Port of src/udm/sess-sm.c - Session state machine implementation

use crate::context::udm_self;
use crate::event::{UdmEvent, UdmEventId};
use crate::sbi_response::send_error_response;

/// UDM Session state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmSessState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Exception state
    Exception,
    /// Final state
    Final,
}

/// UDM Session state machine context
pub struct UdmSessSmContext {
    /// Current state
    state: UdmSessState,
    /// Session ID
    sess_id: u64,
    /// Parent UDM UE ID
    udm_ue_id: u64,
}

impl UdmSessSmContext {
    /// Create a new UDM session state machine context
    pub fn new(sess_id: u64, udm_ue_id: u64) -> Self {
        let mut ctx = Self {
            state: UdmSessState::Initial,
            sess_id,
            udm_ue_id,
        };
        ctx.init();
        ctx
    }

    /// Initialize the state machine
    pub fn init(&mut self) {
        log::debug!(
            "UDM Sess SM [{}:{}]: Initializing",
            self.udm_ue_id,
            self.sess_id
        );
        self.state = UdmSessState::Initial;

        // Process initial state - transition to operational
        let mut event = UdmEvent::entry()
            .with_udm_ue(self.udm_ue_id)
            .with_sess(self.sess_id);
        self.handle_initial_state(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!(
            "UDM Sess SM [{}:{}]: Finalizing",
            self.udm_ue_id,
            self.sess_id
        );
        let mut event = UdmEvent::exit()
            .with_udm_ue(self.udm_ue_id)
            .with_sess(self.sess_id);
        self.handle_final_state(&mut event);
        self.state = UdmSessState::Final;
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut UdmEvent) {
        udm_sess_sm_debug(event, self.udm_ue_id, self.sess_id);

        match self.state {
            UdmSessState::Initial => {
                self.handle_initial_state(event);
            }
            UdmSessState::Operational => {
                self.handle_operational_state(event);
            }
            UdmSessState::Exception => {
                self.handle_exception_state(event);
            }
            UdmSessState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> UdmSessState {
        self.state
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: UdmSessState) {
        log::debug!(
            "UDM Sess SM [{}:{}]: {:?} -> {:?}",
            self.udm_ue_id,
            self.sess_id,
            self.state,
            new_state
        );
        self.state = new_state;
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        if let Some(sess) = context.sess_find_by_id(self.sess_id) {
            if let Some(udm_ue) = context.ue_find_by_id(sess.udm_ue_id) {
                log::debug!("[{}:{}] UDM Sess SM: Initial state", udm_ue.suci, sess.psi);
            }
        }

        // Transition to operational state
        self.transition(UdmSessState::Operational);
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        if let Some(sess) = context.sess_find_by_id(self.sess_id) {
            if let Some(udm_ue) = context.ue_find_by_id(sess.udm_ue_id) {
                log::debug!("[{}:{}] UDM Sess SM: Final state", udm_ue.suci, sess.psi);
            }
        }
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let sess = match context.sess_find_by_id(self.sess_id) {
            Some(s) => s,
            None => {
                log::error!("UDM Session not found [{}]", self.sess_id);
                return;
            }
        };

        let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
            Some(ue) => ue,
            None => {
                log::error!("UDM UE not found [{}]", sess.udm_ue_id);
                return;
            }
        };

        match event.id {
            UdmEventId::FsmEntry => {
                log::debug!(
                    "[{}:{}] UDM Session entering operational state",
                    udm_ue.suci,
                    sess.psi
                );
            }

            UdmEventId::FsmExit => {
                log::debug!(
                    "[{}:{}] UDM Session exiting operational state",
                    udm_ue.suci,
                    sess.psi
                );
            }

            UdmEventId::SbiServer => {
                let suci = udm_ue.suci.clone();
                let psi = sess.psi;
                drop(context); // Release lock before calling handlers
                self.handle_sbi_server_event(event, &suci, psi);
            }

            UdmEventId::SbiClient => {
                let suci = udm_ue.suci.clone();
                let supi = udm_ue.supi.clone();
                let psi = sess.psi;
                drop(context); // Release lock before calling handlers
                self.handle_sbi_client_event(event, &suci, supi.as_deref(), psi);
            }

            _ => {
                log::error!(
                    "[{}:{}] Unknown event {}",
                    udm_ue.suci,
                    sess.psi,
                    crate::event::udm_event_get_name(event)
                );
            }
        }
    }

    /// Handle SBI server events in operational state
    fn handle_sbi_server_event(&mut self, event: &mut UdmEvent, suci: &str, psi: u8) {
        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("[{suci}:{psi}] No SBI data in server event");
                return;
            }
        };

        let stream_id = match sbi.stream_id {
            Some(id) => id,
            None => {
                log::error!("[{suci}:{psi}] No stream ID in SBI event");
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("[{suci}:{psi}] No message in SBI event");
                return;
            }
        };

        let service_name = message.service_name.clone();
        let method = message.method.clone();
        let resource_components = message.resource_components.clone();

        match service_name.as_str() {
            "nudm-uecm" => {
                self.handle_nudm_uecm_request(suci, psi, &method, &resource_components, stream_id);
            }
            _ => {
                log::error!("Invalid API name [{service_name}]");
                send_error_response(stream_id, 400, &format!("Invalid API name: {service_name}"));
            }
        }
    }

    /// Handle NUDM UECM requests for session
    ///
    /// udmd-04 / #236: SMF registration and deregistration are handled by the
    /// live async HTTP dispatcher (`app.rs::udm_sbi_route` ->
    /// [`crate::uecm::process_smf_registration`] /
    /// [`crate::uecm::process_smf_deregistration`]). The state-machine branch is
    /// a legacy Open5GS port that was never wired to the HTTP path — nothing in
    /// the tree constructs a `UdmEvent::sbi_server`, so this is unreachable. It
    /// used to call `nudm_handler`'s own second implementation of both
    /// procedures, and did so with a **default-constructed**
    /// `SmfRegistrationRequest` (the removed body-parsing was never written), so
    /// had it ever been reached it would have registered an empty SMF. The
    /// handler calls have been removed with those handlers; the structure is
    /// kept for future extension only, matching `ue_sm.rs`.
    fn handle_nudm_uecm_request(
        &mut self,
        _suci: &str,
        _psi: u8,
        _method: &str,
        _resource_components: &[String],
        _stream_id: u64,
    ) {
        log::debug!(
            "UDM Sess SM [{}:{}]: UECM request on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id,
            self.sess_id
        );
    }

    /// Handle SBI client events in operational state
    fn handle_sbi_client_event(
        &mut self,
        event: &mut UdmEvent,
        suci: &str,
        supi: Option<&str>,
        psi: u8,
    ) {
        let sbi = match &event.sbi {
            Some(sbi) => sbi,
            None => {
                log::error!("[{suci}:{psi}] No SBI data in client event");
                return;
            }
        };

        let stream_id = match sbi.stream_id {
            Some(id) => id,
            None => {
                log::error!("[{suci}:{psi}] No stream ID in SBI client event");
                return;
            }
        };

        let message = match &sbi.message {
            Some(msg) => msg,
            None => {
                log::error!("[{suci}:{psi}] No message in SBI client event");
                return;
            }
        };

        let service_name = message.service_name.clone();
        let resource_components = message.resource_components.clone();

        match service_name.as_str() {
            "nudr-dr" => {
                self.handle_nudr_dr_response(suci, supi, psi, &resource_components, stream_id);
            }
            _ => {
                log::error!(
                    "[{}:{}] Invalid API name [{}]",
                    supi.unwrap_or(suci),
                    psi,
                    service_name
                );
            }
        }
    }

    /// Handle NUDR DR responses for session
    ///
    /// udmd-04 / #236: see [`Self::handle_nudm_uecm_request`]. The removed body
    /// hardcoded the HTTP method to `"PUT"` and the status to `204` rather than
    /// reading either from the response it was dispatched for, so it could only
    /// ever have reported one outcome.
    fn handle_nudr_dr_response(
        &mut self,
        _suci: &str,
        _supi: Option<&str>,
        _psi: u8,
        _resource_components: &[String],
        _stream_id: u64,
    ) {
        log::debug!(
            "UDM Sess SM [{}:{}]: NUDR-DR response on state-machine path — handled by HTTP dispatcher",
            self.udm_ue_id,
            self.sess_id
        );
    }

    /// Handle exception state
    fn handle_exception_state(&mut self, event: &mut UdmEvent) {
        let ctx = udm_self();
        let context = ctx.read().unwrap();

        let sess = match context.sess_find_by_id(self.sess_id) {
            Some(s) => s,
            None => return,
        };

        let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
            Some(ue) => ue,
            None => return,
        };

        match event.id {
            UdmEventId::FsmEntry => {
                log::debug!(
                    "[{}:{}] UDM Session entering exception state",
                    udm_ue.suci,
                    sess.psi
                );
            }
            UdmEventId::FsmExit => {
                log::debug!(
                    "[{}:{}] UDM Session exiting exception state",
                    udm_ue.suci,
                    sess.psi
                );
            }
            _ => {
                log::error!(
                    "[{}:{}] Unknown event {}",
                    udm_ue.suci,
                    sess.psi,
                    crate::event::udm_event_get_name(event)
                );
            }
        }
    }
}

/// Debug helper for session state machine events
pub fn udm_sess_sm_debug(event: &UdmEvent, udm_ue_id: u64, sess_id: u64) {
    log::trace!(
        "UDM Sess SM [{}:{}] event: {}",
        udm_ue_id,
        sess_id,
        event.name()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::udm_context_init;

    fn setup() {
        udm_context_init(100, 200);
    }

    #[test]
    fn test_udm_sess_sm_new() {
        setup();
        let ctx = UdmSessSmContext::new(1, 1);
        assert_eq!(ctx.state(), UdmSessState::Operational);
    }

    #[test]
    fn test_udm_sess_sm_dispatch_entry() {
        setup();
        let mut ctx = UdmSessSmContext::new(1, 1);

        let mut event = UdmEvent::entry().with_udm_ue(1).with_sess(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sess_sm_dispatch_exit() {
        setup();
        let mut ctx = UdmSessSmContext::new(1, 1);

        let mut event = UdmEvent::exit().with_udm_ue(1).with_sess(1);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_udm_sess_sm_fini() {
        setup();
        let mut ctx = UdmSessSmContext::new(1, 1);
        ctx.fini();
        assert_eq!(ctx.state(), UdmSessState::Final);
    }
}
