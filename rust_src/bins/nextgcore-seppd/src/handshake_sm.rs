//! SEPP N32c Handshake State Machine
//!
//! Port of src/sepp/handshake-sm.c - N32c handshake state machine implementation
//!
//! States:
//! - Initial: Entry state
//! - WillEstablish: Attempting to establish connection with peer SEPP
//! - Established: Successfully negotiated security capability
//! - Terminated: Connection terminated, may retry
//! - Exception: Error state, will retry with longer interval
//! - Final: Exit state

use crate::context::{sepp_self, SecurityCapability};
use crate::event::{SeppEvent, SeppEventId, SeppTimerId};

/// Handshake state type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeState {
    #[default]
    Initial,
    WillEstablish,
    Established,
    Terminated,
    Exception,
    Final,
}

impl HandshakeState {
    pub fn name(&self) -> &'static str {
        match self {
            HandshakeState::Initial => "Initial",
            HandshakeState::WillEstablish => "WillEstablish",
            HandshakeState::Established => "Established",
            HandshakeState::Terminated => "Terminated",
            HandshakeState::Exception => "Exception",
            HandshakeState::Final => "Final",
        }
    }
}

/// Handshake state machine context
pub struct HandshakeSmContext {
    state: HandshakeState,
    node_id: u64,
    try_to_establish: bool,
    timer_active: bool,
}

impl HandshakeSmContext {
    pub fn new(node_id: u64) -> Self {
        Self {
            state: HandshakeState::Initial,
            node_id,
            try_to_establish: false,
            timer_active: false,
        }
    }

    /// Initialize the handshake FSM
    /// Port of sepp_handshake_fsm_init
    pub fn init(&mut self, try_to_establish: bool) {
        log::debug!("Handshake SM: Initializing for node {} (try_to_establish={})", 
            self.node_id, try_to_establish);
        
        self.try_to_establish = try_to_establish;
        self.state = HandshakeState::Initial;
        
        if try_to_establish {
            self.timer_active = true;
        }
        
        // Transition to WillEstablish
        let mut event = SeppEvent::entry().with_sepp_node(self.node_id);
        self.dispatch(&mut event);
    }

    /// Finalize the handshake FSM
    /// Port of sepp_handshake_fsm_fini
    pub fn fini(&mut self) {
        log::debug!("Handshake SM: Finalizing for node {}", self.node_id);
        
        // If established, send termination request
        if self.state == HandshakeState::Established {
            log::info!("[node_id={}] Sending termination request", self.node_id);
            // TODO: sepp_n32c_handshake_send_security_capability_request(sepp_node, true)
        }
        
        let mut event = SeppEvent::exit().with_sepp_node(self.node_id);
        self.dispatch(&mut event);
        
        self.timer_active = false;
        self.state = HandshakeState::Final;
    }

    pub fn dispatch(&mut self, event: &mut SeppEvent) {
        handshake_sm_debug(event, self.node_id);

        match self.state {
            HandshakeState::Initial => self.handle_initial_state(event),
            HandshakeState::WillEstablish => self.handle_will_establish_state(event),
            HandshakeState::Established => self.handle_established_state(event),
            HandshakeState::Terminated => self.handle_terminated_state(event),
            HandshakeState::Exception => self.handle_exception_state(event),
            HandshakeState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn is_established(&self) -> bool {
        self.state == HandshakeState::Established
    }

    pub fn is_exception(&self) -> bool {
        self.state == HandshakeState::Exception
    }

    fn handle_initial_state(&mut self, _event: &mut SeppEvent) {
        log::debug!("[node_id={}] Transitioning from Initial to WillEstablish", self.node_id);
        self.state = HandshakeState::WillEstablish;
    }

    fn handle_final_state(&mut self, _event: &mut SeppEvent) {
        log::debug!("[node_id={}] In final state", self.node_id);
    }

    /// Handle WillEstablish state
    /// Port of sepp_handshake_state_will_establish
    fn handle_will_establish_state(&mut self, event: &mut SeppEvent) {
        match event.id {
            SeppEventId::FsmEntry => {
                if self.timer_active {
                    log::debug!("[node_id={}] Starting establish timer", self.node_id);
                    // TODO: Start timer
                    // TODO: Send security capability request
                    log::info!("[node_id={}] Sending security capability request", self.node_id);
                }
            }
            SeppEventId::FsmExit => {
                if self.timer_active {
                    log::debug!("[node_id={}] Stopping establish timer", self.node_id);
                    // TODO: Stop timer
                }
            }
            SeppEventId::SbiServer => {
                self.handle_will_establish_server_event(event);
            }
            SeppEventId::SbiClient => {
                self.handle_will_establish_client_event(event);
            }
            SeppEventId::SbiTimer => {
                self.handle_will_establish_timer_event(event);
            }
        }
    }

    fn handle_will_establish_server_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, method) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.method.clone(),
            )
        };

        if service_name != "n32c-handshake" {
            log::error!("[node_id={}] Invalid API name [{}]", self.node_id, service_name);
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => match method.as_str() {
                "POST" => {
                    // Handle security capability request from peer
                    let handled = self.handle_security_capability_request(event);
                    if !handled {
                        log::error!("[node_id={}] Cannot handle SBI message", self.node_id);
                        self.state = HandshakeState::Exception;
                        return;
                    }

                    // Check negotiated security scheme
                    let negotiated_scheme = self.get_negotiated_security_scheme();
                    
                    match negotiated_scheme {
                        SecurityCapability::Tls => {
                            log::info!("[node_id={}] TLS negotiated, transitioning to Established", self.node_id);
                            self.send_security_capability_response();
                            self.state = HandshakeState::Established;
                        }
                        SecurityCapability::Prins => {
                            log::error!("[node_id={}] PRINS is not supported", self.node_id);
                            // TODO: Send error response
                        }
                        SecurityCapability::None => {
                            log::warn!("[node_id={}] SEPP has not been established (NONE)", self.node_id);
                            self.send_security_capability_response();
                            // Stay in WillEstablish
                        }
                        _ => {
                            log::error!("[node_id={}] Unknown security capability", self.node_id);
                        }
                    }
                }
                _ => {
                    log::error!("[node_id={}] Invalid HTTP method [{}]", self.node_id, method);
                }
            },
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    fn handle_will_establish_client_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, method, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.method.clone(),
                message.res_status,
            )
        };

        if service_name != "n32c-handshake" {
            log::error!("[node_id={}] Invalid API name [{}]", self.node_id, service_name);
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => match method.as_str() {
                "POST" => {
                    if res_status == Some(200) {
                        let handled = self.handle_security_capability_response(event);
                        if !handled {
                            log::error!("[node_id={}] Cannot handle SBI message", self.node_id);
                            self.state = HandshakeState::Exception;
                            return;
                        }

                        let negotiated_scheme = self.get_negotiated_security_scheme();
                        
                        match negotiated_scheme {
                            SecurityCapability::Tls => {
                                log::info!("[node_id={}] TLS negotiated, transitioning to Established", self.node_id);
                                self.state = HandshakeState::Established;
                            }
                            SecurityCapability::Prins => {
                                log::error!("[node_id={}] PRINS is not supported", self.node_id);
                            }
                            SecurityCapability::None => {
                                log::warn!("[node_id={}] SEPP has not been established (NONE)", self.node_id);
                            }
                            _ => {}
                        }
                    } else {
                        log::error!("[node_id={}] HTTP Response Status Code [{:?}]", 
                            self.node_id, res_status);
                    }
                }
                _ => {
                    log::error!("[node_id={}] Invalid HTTP method [{}]", self.node_id, method);
                }
            },
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    fn handle_will_establish_timer_event(&mut self, event: &mut SeppEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => return,
        };

        match timer_id {
            SeppTimerId::PeerEstablish => {
                log::warn!("[node_id={}] Retry establishment with Peer SEPP", self.node_id);
                // TODO: Restart timer and send request
            }
            _ => {
                log::error!("[node_id={}] Unknown timer [{:?}]", self.node_id, timer_id);
            }
        }
    }

    /// Handle Established state
    /// Port of sepp_handshake_state_established
    fn handle_established_state(&mut self, event: &mut SeppEvent) {
        match event.id {
            SeppEventId::FsmEntry => {
                log::info!("[node_id={}] SEPP established", self.node_id);
            }
            SeppEventId::FsmExit => {
                log::info!("[node_id={}] SEPP terminated", self.node_id);
            }
            SeppEventId::SbiServer => {
                self.handle_established_server_event(event);
            }
            SeppEventId::SbiClient => {
                self.handle_established_client_event(event);
            }
            _ => {
                log::error!("[node_id={}] Unknown event {}", self.node_id, event.name());
            }
        }
    }

    fn handle_established_server_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, method) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.method.clone(),
            )
        };

        if service_name != "n32c-handshake" {
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => match method.as_str() {
                "POST" => {
                    let handled = self.handle_security_capability_request(event);
                    if !handled {
                        log::error!("[node_id={}] Cannot handle SBI message", self.node_id);
                        self.state = HandshakeState::Exception;
                        return;
                    }

                    let negotiated_scheme = self.get_negotiated_security_scheme();
                    
                    match negotiated_scheme {
                        SecurityCapability::Tls => {
                            log::warn!("[node_id={}] SEPP has already been established", self.node_id);
                            self.send_security_capability_response();
                        }
                        SecurityCapability::Prins => {
                            log::error!("[node_id={}] PRINS is not supported", self.node_id);
                        }
                        SecurityCapability::None => {
                            log::info!("[node_id={}] Transitioning to Terminated", self.node_id);
                            self.send_security_capability_response();
                            self.state = HandshakeState::Terminated;
                        }
                        _ => {}
                    }
                }
                _ => {
                    log::error!("[node_id={}] Invalid HTTP method [{}]", self.node_id, method);
                }
            },
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    fn handle_established_client_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.res_status,
            )
        };

        if service_name != "n32c-handshake" {
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => {
                if res_status == Some(200) {
                    log::warn!("[node_id={}] SEPP has already been established", self.node_id);
                } else {
                    log::error!("[node_id={}] HTTP Response Status Code [{:?}]", 
                        self.node_id, res_status);
                }
            }
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    /// Handle Terminated state
    /// Port of sepp_handshake_state_terminated
    fn handle_terminated_state(&mut self, event: &mut SeppEvent) {
        match event.id {
            SeppEventId::FsmEntry => {
                if self.timer_active {
                    log::debug!("[node_id={}] Starting reconnect timer", self.node_id);
                    // TODO: Start timer
                }
            }
            SeppEventId::FsmExit => {
                if self.timer_active {
                    log::debug!("[node_id={}] Stopping reconnect timer", self.node_id);
                    // TODO: Stop timer
                }
            }
            SeppEventId::SbiServer => {
                self.handle_terminated_server_event(event);
            }
            SeppEventId::SbiClient => {
                self.handle_terminated_client_event(event);
            }
            SeppEventId::SbiTimer => {
                self.handle_terminated_timer_event(event);
            }
        }
    }

    fn handle_terminated_server_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, method) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.method.clone(),
            )
        };

        if service_name != "n32c-handshake" {
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => match method.as_str() {
                "POST" => {
                    let handled = self.handle_security_capability_request(event);
                    if !handled {
                        log::error!("[node_id={}] Cannot handle SBI message", self.node_id);
                        self.state = HandshakeState::Exception;
                        return;
                    }

                    let negotiated_scheme = self.get_negotiated_security_scheme();
                    
                    match negotiated_scheme {
                        SecurityCapability::Tls => {
                            log::info!("[node_id={}] TLS negotiated, transitioning to Established", self.node_id);
                            self.send_security_capability_response();
                            self.state = HandshakeState::Established;
                        }
                        SecurityCapability::Prins => {
                            log::error!("[node_id={}] PRINS is not supported", self.node_id);
                        }
                        SecurityCapability::None => {
                            log::warn!("[node_id={}] SEPP has not been established (NONE)", self.node_id);
                            self.send_security_capability_response();
                        }
                        _ => {}
                    }
                }
                _ => {
                    log::error!("[node_id={}] Invalid HTTP method [{}]", self.node_id, method);
                }
            },
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    fn handle_terminated_client_event(&mut self, event: &mut SeppEvent) {
        let (service_name, resource, res_status) = {
            let sbi = match &event.sbi {
                Some(sbi) => sbi,
                None => return,
            };
            let message = match &sbi.message {
                Some(msg) => msg,
                None => return,
            };
            (
                message.service_name.clone(),
                message.resource_components.first().cloned(),
                message.res_status,
            )
        };

        if service_name != "n32c-handshake" {
            return;
        }

        match resource.as_deref() {
            Some("exchange-capability") => {
                if res_status == Some(200) {
                    log::warn!("[node_id={}] SEPP was terminated", self.node_id);
                } else {
                    log::error!("[node_id={}] HTTP Response Status Code [{:?}]", 
                        self.node_id, res_status);
                }
            }
            _ => {
                log::error!("[node_id={}] Invalid resource name [{:?}]", self.node_id, resource);
            }
        }
    }

    fn handle_terminated_timer_event(&mut self, event: &mut SeppEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => return,
        };

        match timer_id {
            SeppTimerId::PeerEstablish => {
                log::warn!("[node_id={}] Retry establishment with Peer SEPP", self.node_id);
                self.state = HandshakeState::WillEstablish;
            }
            _ => {
                log::error!("[node_id={}] Unknown timer [{:?}]", self.node_id, timer_id);
            }
        }
    }

    /// Handle Exception state
    /// Port of sepp_handshake_state_exception
    fn handle_exception_state(&mut self, event: &mut SeppEvent) {
        match event.id {
            SeppEventId::FsmEntry => {
                if self.timer_active {
                    log::debug!("[node_id={}] Starting exception reconnect timer", self.node_id);
                    // TODO: Start timer with longer interval
                }
            }
            SeppEventId::FsmExit => {
                if self.timer_active {
                    log::debug!("[node_id={}] Stopping exception reconnect timer", self.node_id);
                    // TODO: Stop timer
                }
            }
            SeppEventId::SbiTimer => {
                let timer_id = match event.timer_id {
                    Some(id) => id,
                    None => return,
                };

                match timer_id {
                    SeppTimerId::PeerEstablish => {
                        log::warn!("[node_id={}] Retry establishment with Peer SEPP (from exception)", 
                            self.node_id);
                        self.state = HandshakeState::WillEstablish;
                    }
                    _ => {
                        log::error!("[node_id={}] Unknown timer [{:?}]", self.node_id, timer_id);
                    }
                }
            }
            SeppEventId::SbiServer | SeppEventId::SbiClient => {
                log::error!("[node_id={}] SEPP exception state", self.node_id);
            }
        }
    }

    // Helper methods

    fn handle_security_capability_request(&mut self, _event: &mut SeppEvent) -> bool {
        // TODO: Implement actual request handling
        // This would parse SecNegotiateReqData and negotiate security capability
        // For now, return true to indicate success
        log::debug!("[node_id={}] Handling security capability request", self.node_id);
        true
    }

    fn handle_security_capability_response(&mut self, _event: &mut SeppEvent) -> bool {
        // TODO: Implement actual response handling
        // This would parse SecNegotiateRspData
        log::debug!("[node_id={}] Handling security capability response", self.node_id);
        true
    }

    fn send_security_capability_response(&self) {
        // TODO: Implement actual response sending
        log::debug!("[node_id={}] Sending security capability response", self.node_id);
    }

    fn get_negotiated_security_scheme(&self) -> SecurityCapability {
        // Get from context
        let ctx = sepp_self();
        if let Ok(context) = ctx.read() {
            if let Some(node) = context.node_find(self.node_id) {
                return node.negotiated_security_scheme;
            }
        }
        SecurityCapability::Null
    }
}

fn handshake_sm_debug(event: &SeppEvent, node_id: u64) {
    log::trace!("[node_id={}] Handshake SM event: {}", node_id, event.name());
}
