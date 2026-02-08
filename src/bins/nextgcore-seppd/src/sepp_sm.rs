//! SEPP Main State Machine
//!
//! Port of src/sepp/sepp-sm.c - Main SEPP state machine implementation

use crate::context::{sepp_self, SeppNode};
use crate::event::{SeppEvent, SeppEventId, SeppTimerId};
use crate::handshake_sm::{HandshakeSmContext, HandshakeState};
use crate::sbi_response::{send_error_response, send_gateway_timeout_response};

/// SEPP state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeppState {
    Initial,
    Operational,
    Final,
}

/// SEPP state machine context
pub struct SeppSmContext {
    state: SeppState,
    /// Handshake state machines for each peer node (by node ID)
    handshake_contexts: std::collections::HashMap<u64, HandshakeSmContext>,
}

impl SeppSmContext {
    pub fn new() -> Self {
        Self {
            state: SeppState::Initial,
            handshake_contexts: std::collections::HashMap::new(),
        }
    }

    pub fn init(&mut self) {
        log::debug!("SEPP SM: Initializing");
        self.state = SeppState::Initial;
        let mut event = SeppEvent::entry();
        self.dispatch(&mut event);
    }

    pub fn fini(&mut self) {
        log::debug!("SEPP SM: Finalizing");
        
        // Finalize all handshake state machines
        for (node_id, handshake_ctx) in self.handshake_contexts.iter_mut() {
            log::debug!("Finalizing handshake SM for node {}", node_id);
            handshake_ctx.fini();
        }
        self.handshake_contexts.clear();
        
        let mut event = SeppEvent::exit();
        self.dispatch(&mut event);
        self.state = SeppState::Final;
    }

    pub fn dispatch(&mut self, event: &mut SeppEvent) {
        sepp_sm_debug(event);

        match self.state {
            SeppState::Initial => self.handle_initial_state(event),
            SeppState::Operational => self.handle_operational_state(event),
            SeppState::Final => self.handle_final_state(event),
        }
    }

    pub fn state(&self) -> SeppState {
        self.state
    }

    pub fn is_operational(&self) -> bool {
        self.state == SeppState::Operational
    }

    /// Initialize handshake FSM for a peer node
    pub fn init_handshake_fsm(&mut self, node_id: u64, try_to_establish: bool) {
        let mut handshake_ctx = HandshakeSmContext::new(node_id);
        handshake_ctx.init(try_to_establish);
        self.handshake_contexts.insert(node_id, handshake_ctx);
        log::info!("Initialized handshake FSM for node {} (try_to_establish={})", 
            node_id, try_to_establish);
    }

    /// Finalize handshake FSM for a peer node
    pub fn fini_handshake_fsm(&mut self, node_id: u64) {
        if let Some(mut ctx) = self.handshake_contexts.remove(&node_id) {
            ctx.fini();
            log::info!("Finalized handshake FSM for node {}", node_id);
        }
    }

    /// Get handshake state for a node
    pub fn get_handshake_state(&self, node_id: u64) -> Option<HandshakeState> {
        self.handshake_contexts.get(&node_id).map(|ctx| ctx.state())
    }

    /// Check if handshake is established for a node
    pub fn is_handshake_established(&self, node_id: u64) -> bool {
        self.handshake_contexts
            .get(&node_id)
            .map(|ctx| ctx.is_established())
            .unwrap_or(false)
    }

    fn handle_initial_state(&mut self, _event: &mut SeppEvent) {
        log::info!("SEPP SM: Transitioning from Initial to Operational");
        self.state = SeppState::Operational;
    }

    fn handle_final_state(&mut self, _event: &mut SeppEvent) {
        log::debug!("SEPP SM: In final state");
    }

    fn handle_operational_state(&mut self, event: &mut SeppEvent) {
        match event.id {
            SeppEventId::FsmEntry => {
                log::info!("SEPP entering operational state");
            }
            SeppEventId::FsmExit => {
                log::info!("SEPP exiting operational state");
            }
            SeppEventId::SbiServer => {
                self.handle_sbi_server_event(event);
            }
            SeppEventId::SbiClient => {
                self.handle_sbi_client_event(event);
            }
            SeppEventId::SbiTimer => {
                self.handle_sbi_timer_event(event);
            }
        }
    }

    fn handle_sbi_server_event(&mut self, event: &mut SeppEvent) {
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
            log::error!("Not supported version [{}], expected [v1]", api_version);
            send_error_response(stream_id, 400, &format!("Unsupported API version: {}", api_version));
            return;
        }

        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_request(event, stream_id, &method, &resource_components);
            }
            "n32c-handshake" => {
                self.handle_n32c_handshake_request(event, stream_id, &method, &resource_components);
            }
            _ => {
                log::error!("Invalid API name [{}]", service_name);
            }
        }
    }

    fn handle_nnrf_nfm_request(
        &mut self,
        _event: &mut SeppEvent,
        _stream_id: u64,
        method: &str,
        resource_components: &[String],
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-status-notify") => match method {
                "POST" => {
                    log::debug!("NF status notify received");
                    // Note: NF status notification handled by common SBI NRF handler module
                    // Updates NF instance status based on notification type (registered/deregistered/profile changed)
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                }
            },
            _ => {
                log::error!("Invalid resource name [{:?}]", resource);
            }
        }
    }

    fn handle_n32c_handshake_request(
        &mut self,
        event: &mut SeppEvent,
        stream_id: u64,
        method: &str,
        resource_components: &[String],
    ) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("exchange-capability") => match method {
                "POST" => {
                    // Find or create SEPP node based on sender in request
                    let node_id = self.find_or_create_sepp_node_from_request(event);
                    
                    if let Some(node_id) = node_id {
                        // Dispatch to handshake state machine
                        if let Some(handshake_ctx) = self.handshake_contexts.get_mut(&node_id) {
                            let mut handshake_event = event.clone().with_sepp_node(node_id);
                            handshake_ctx.dispatch(&mut handshake_event);
                            
                            if handshake_ctx.is_exception() {
                                log::error!("Handshake state machine exception for node {}", node_id);
                            }
                        } else {
                            log::error!("No handshake context for node {}", node_id);
                        }
                    } else {
                        log::error!("Could not find or create SEPP node for stream {}", stream_id);
                    }
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                }
            },
            _ => {
                log::error!("Invalid resource name [{:?}]", resource);
            }
        }
    }

    fn find_or_create_sepp_node_from_request(&mut self, _event: &SeppEvent) -> Option<u64> {
        // Note: Sender extracted from SecNegotiateReqData in request body via n32c_handler
        // Implementation flow:
        // 1. Parse SecNegotiateReqData.sender from JSON body
        // 2. Look up node via context.node_find_by_receiver(sender)
        // 3. If not found, create new node via context.node_add(sender)
        // 4. Initialize handshake FSM via self.init_handshake_fsm(node_id, false)
        // For now, return None - requires actual message body parsing

        None
    }

    fn handle_sbi_client_event(&mut self, event: &mut SeppEvent) {
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
            log::error!("Not supported version [{}]", api_version);
            return;
        }

        match service_name.as_str() {
            "nnrf-nfm" => {
                self.handle_nnrf_nfm_response(event, &resource_components);
            }
            "n32c-handshake" => {
                self.handle_n32c_handshake_response(event, &resource_components);
            }
            _ => {
                log::error!("Invalid service name [{}]", service_name);
            }
        }
    }

    fn handle_nnrf_nfm_response(&mut self, event: &mut SeppEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("nf-instances") => {
                log::debug!("NF instances response received");
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance response", nf_instance_id);
                    
                    // After successful NRF registration, initialize handshake FSMs for all peer nodes
                    self.initialize_peer_handshakes();
                }
            }
            Some("subscriptions") => {
                log::debug!("Subscriptions response received");
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource);
            }
        }
    }

    fn handle_n32c_handshake_response(&mut self, event: &mut SeppEvent, resource_components: &[String]) {
        let resource = resource_components.first().map(|s| s.as_str());

        match resource {
            Some("exchange-capability") => {
                if let Some(node_id) = event.sepp_node_id {
                    if let Some(handshake_ctx) = self.handshake_contexts.get_mut(&node_id) {
                        handshake_ctx.dispatch(event);
                    }
                }
            }
            _ => {
                log::error!("Invalid resource name [{:?}]", resource);
            }
        }
    }

    fn handle_sbi_timer_event(&mut self, event: &mut SeppEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            SeppTimerId::PeerEstablish => {
                if let Some(node_id) = event.sepp_node_id {
                    log::warn!("Retry establishment with Peer SEPP (node_id={})", node_id);
                    
                    if let Some(handshake_ctx) = self.handshake_contexts.get_mut(&node_id) {
                        handshake_ctx.dispatch(event);
                        
                        if handshake_ctx.is_exception() {
                            log::error!("State machine exception for node {}", node_id);
                        }
                    }
                }
            }
            SeppTimerId::NfInstanceRegistrationInterval
            | SeppTimerId::NfInstanceHeartbeatInterval
            | SeppTimerId::NfInstanceNoHeartbeat
            | SeppTimerId::NfInstanceValidity => {
                if let Some(ref nf_instance_id) = event.nf_instance_id {
                    log::debug!("[{}] NF instance timer: {:?}", nf_instance_id, timer_id);
                    // Note: Dispatch to NF FSM handled by common SBI NF state machine module
                    // Triggers registration retry, heartbeat send, or validity check based on timer type
                }
            }
            SeppTimerId::SubscriptionValidity => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::error!("[{}] Subscription validity expired", subscription_id);
                }
            }
            SeppTimerId::SubscriptionPatch => {
                if let Some(ref subscription_id) = event.subscription_id {
                    log::info!("[{}] Need to update Subscription", subscription_id);
                }
            }
            SeppTimerId::SbiClientWait => {
                log::error!("Cannot receive SBI message");
                send_gateway_timeout_response(0, "SBI client wait timeout");
            }
        }
    }

    /// Initialize handshake FSMs for all configured peer nodes
    fn initialize_peer_handshakes(&mut self) {
        let ctx = sepp_self();
        let nodes: Vec<SeppNode> = {
            if let Ok(context) = ctx.read() {
                context.node_list()
            } else {
                Vec::new()
            }
        };

        for node in nodes {
            if !self.handshake_contexts.contains_key(&node.id) {
                self.init_handshake_fsm(node.id, true);
            }
        }
    }
}

impl Default for SeppSmContext {
    fn default() -> Self {
        Self::new()
    }
}

fn sepp_sm_debug(event: &SeppEvent) {
    log::trace!("SEPP SM event: {}", event.name());
}
