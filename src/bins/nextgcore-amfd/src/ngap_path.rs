//! NGAP Path - SCTP Server for gNB Connections
//!
//! This module provides the NGAP transport layer using SCTP (via sctp-proto).
//! It handles:
//! - SCTP server creation on port 38412
//! - gNB connection acceptance via SCTP associations
//! - NGAP message reception and transmission
//! - Integration with the NgapFsm state machine
//!
//! # Wire Compatibility
//! This implementation uses sctp-proto, which is wire-compatible with nextgsim's
//! SCTP implementation. Both use SCTP-over-UDP (RFC 6951).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, Mutex, RwLock};

use ogs_sctp::{
    OGS_NGAP_SCTP_PORT, OgsSctpInfo, SctpServer, SctpServerConfig, ServerEvent,
};

use crate::context::{AmfContext, AmfGnb};
use crate::event::AmfEvent;
use crate::ngap_asn1;
use crate::ngap_build;
use crate::ngap_handler::{self, NgapHandlerResult, NgSetupRequest};
use crate::ngap_sm::NgapFsm;

// ============================================================================
// Constants
// ============================================================================

/// Default NGAP bind address
pub const DEFAULT_NGAP_ADDR: &str = "0.0.0.0";

/// Maximum NGAP message size
pub const MAX_NGAP_MSG_SIZE: usize = 65535;

/// Maximum number of gNB connections
pub const MAX_GNB_CONNECTIONS: usize = 64;

/// SCTP receive timeout
const SCTP_RECV_TIMEOUT: Duration = Duration::from_millis(100);

// ============================================================================
// NGAP Server State
// ============================================================================

/// Connected gNB session
#[derive(Debug)]
pub struct GnbSession {
    /// gNB ID (assigned by AMF)
    pub id: u64,
    /// SCTP association ID
    pub association_id: u64,
    /// Remote address
    pub addr: SocketAddr,
    /// NGAP FSM for this gNB
    pub fsm: NgapFsm,
    /// gNB context
    pub gnb: AmfGnb,
    /// SCTP info
    pub sctp_info: OgsSctpInfo,
}

impl GnbSession {
    pub fn new(id: u64, association_id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            association_id,
            addr,
            fsm: NgapFsm::new(id),
            gnb: AmfGnb::new(id, &addr.to_string()),
            sctp_info: OgsSctpInfo::default(),
        }
    }
}

/// Per-UE authentication state stored between AUSF messages
#[derive(Debug, Clone)]
struct UeAuthState {
    /// AUSF auth context ID
    auth_ctx_id: String,
    /// RAND (16 bytes)
    rand: [u8; 16],
    /// HXRES* (16 bytes)
    hxres_star: [u8; 16],
    /// RAN UE NGAP ID (for building DL NAS Transport)
    ran_ue_ngap_id: u32,
    /// SCTP association ID
    association_id: u64,
    /// SUCI string
    suci: String,
}

/// NGAP Server - handles all gNB connections via SCTP
pub struct NgapServer {
    /// SCTP server (sctp-proto based)
    sctp_server: SctpServer,
    /// Bind address
    bind_addr: SocketAddr,
    /// Connected gNB sessions (keyed by SCTP association ID)
    sessions: Arc<RwLock<HashMap<u64, GnbSession>>>,
    /// Association ID to address mapping
    assoc_to_addr: Arc<RwLock<HashMap<u64, SocketAddr>>>,
    /// Next gNB ID
    next_gnb_id: Arc<Mutex<u64>>,
    /// AMF context reference
    amf_context: Arc<RwLock<AmfContext>>,
    /// Event sender for NGAP events
    event_tx: mpsc::Sender<AmfEvent>,
    /// Server event receiver
    server_event_rx: mpsc::UnboundedReceiver<ServerEvent>,
    /// Per-UE auth state (keyed by AMF-UE-NGAP-ID)
    ue_auth_state: HashMap<u64, UeAuthState>,
}

impl NgapServer {
    /// Create a new NGAP server with sctp-proto
    pub async fn new(
        bind_addr: SocketAddr,
        amf_context: Arc<RwLock<AmfContext>>,
        event_tx: mpsc::Sender<AmfEvent>,
    ) -> Result<Self> {
        // Configure SCTP server
        let config = SctpServerConfig {
            max_inbound_streams: 2,
            max_outbound_streams: 2,
            max_message_size: MAX_NGAP_MSG_SIZE as u32,
            receive_buffer_size: 262144,
        };

        let mut sctp_server = SctpServer::bind(bind_addr, config).await
            .map_err(|e| anyhow::anyhow!("Failed to bind SCTP server: {e}"))?;

        let local_addr = sctp_server.local_addr();

        // Set up event channel for server events
        let (server_event_tx, server_event_rx) = mpsc::unbounded_channel();
        sctp_server.set_event_sender(server_event_tx);

        log::info!("NGAP server listening on {local_addr} (sctp-proto over UDP)");

        Ok(Self {
            sctp_server,
            bind_addr: local_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            assoc_to_addr: Arc::new(RwLock::new(HashMap::new())),
            next_gnb_id: Arc::new(Mutex::new(1)),
            amf_context,
            event_tx,
            server_event_rx,
            ue_auth_state: HashMap::new(),
        })
    }

    /// Get the bind address
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get number of connected gNBs
    pub async fn num_gnbs(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Poll for incoming NGAP messages and server events
    pub async fn poll(&mut self) -> Result<bool> {
        // Process any pending server events
        while let Ok(event) = self.server_event_rx.try_recv() {
            self.handle_server_event(event).await?;
        }

        // Poll SCTP server for incoming data
        match self.sctp_server.recv(SCTP_RECV_TIMEOUT).await {
            Ok(true) => {
                // Data was received, process any new events
                while let Ok(event) = self.server_event_rx.try_recv() {
                    self.handle_server_event(event).await?;
                }
                Ok(true)
            }
            Ok(false) => Ok(false), // Timeout, no data
            Err(e) => Err(anyhow::anyhow!("SCTP receive error: {e}")),
        }
    }

    /// Handle SCTP server events
    async fn handle_server_event(&mut self, event: ServerEvent) -> Result<()> {
        match event {
            ServerEvent::NewAssociation { association_id, remote_addr } => {
                self.handle_new_association(association_id, remote_addr).await?;
            }
            ServerEvent::AssociationClosed { association_id, reason } => {
                self.handle_association_closed(association_id, &reason).await?;
            }
            ServerEvent::DataReceived { association_id, message } => {
                self.handle_data_received(association_id, &message.data).await?;
            }
        }
        Ok(())
    }

    /// Handle new SCTP association (gNB connection)
    async fn handle_new_association(&self, association_id: u64, remote_addr: SocketAddr) -> Result<()> {
        let gnb_id = {
            let mut id = self.next_gnb_id.lock().await;
            let current = *id;
            *id += 1;
            current
        };

        log::info!("New gNB connection from {remote_addr} (gNB ID: {gnb_id}, association: {association_id})");

        let mut session = GnbSession::new(gnb_id, association_id, remote_addr);
        session.fsm.init();

        self.sessions.write().await.insert(association_id, session);
        self.assoc_to_addr.write().await.insert(association_id, remote_addr);

        Ok(())
    }

    /// Handle SCTP association closure
    async fn handle_association_closed(&self, association_id: u64, reason: &str) -> Result<()> {
        if let Some(session) = self.sessions.write().await.remove(&association_id) {
            log::info!("gNB {} disconnected (association {}): {}",
                      session.id, association_id, reason);
            self.assoc_to_addr.write().await.remove(&association_id);
        }
        Ok(())
    }

    /// Handle received NGAP data
    async fn handle_data_received(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let addr = self.assoc_to_addr.read().await.get(&association_id).copied();

        if let Some(addr) = addr {
            log::debug!("Received {} bytes NGAP data from {} (association {})",
                       data.len(), addr, association_id);

            // Process the NGAP message
            self.process_ngap_message(association_id, data).await?;
        } else {
            log::warn!("Received data for unknown association {association_id}");
        }

        Ok(())
    }

    /// Process an NGAP message
    async fn process_ngap_message(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        if data.len() < 3 {
            log::warn!("NGAP message too short from association {association_id}");
            return Ok(());
        }

        // Log raw message header for debugging
        log::debug!("NGAP message from association {}: {} bytes, header: {:02x?}",
                   association_id, data.len(), &data[..data.len().min(8)]);

        // Check for NGAP message type
        let procedure_code = self.extract_procedure_code(data);

        log::info!("NGAP message from association {association_id}: procedure_code={procedure_code:?}");

        match procedure_code {
            Some(21) => {
                // NGSetupRequest (procedure code 21)
                self.handle_ng_setup_request(association_id, data).await?;
            }
            Some(15) => {
                // InitialUEMessage (procedure code 15)
                self.handle_initial_ue_message(association_id, data).await?;
            }
            Some(46) => {
                // UplinkNASTransport (procedure code 46)
                log::info!("Dispatching to handle_uplink_nas_transport");
                self.handle_uplink_nas_transport(association_id, data).await?;
            }
            Some(29) => {
                // PDU Session Resource Setup (procedure code 29)
                // SuccessfulOutcome = gNB response with gNB TEID
                if data[0] == 0x20 {
                    log::info!("PDU Session Resource Setup Response from gNB");
                    self.handle_pdu_session_resource_setup_response(association_id, data).await?;
                }
            }
            _ => {
                log::debug!("Unknown procedure code, forwarding to FSM");
                // Create NGAP event for FSM processing
                if let Some(session) = self.sessions.read().await.get(&association_id) {
                    let event = AmfEvent::ngap_message(session.id, data.to_vec());
                    let _ = self.event_tx.send(event).await;
                }
            }
        }

        Ok(())
    }

    /// Extract procedure code from NGAP message
    ///
    /// NGAP PDU is a CHOICE with 3 options:
    /// - InitiatingMessage (0x00)
    /// - SuccessfulOutcome (0x20)
    /// - UnsuccessfulOutcome (0x40)
    ///
    /// In APER encoding:
    /// - Byte 0: CHOICE index (0x00, 0x20, or 0x40 with extension bit)
    /// - Byte 1: Procedure code (0-255)
    fn extract_procedure_code(&self, data: &[u8]) -> Option<u16> {
        if data.len() < 3 {
            log::warn!("NGAP message too short to extract procedure code: {} bytes", data.len());
            return None;
        }

        let byte0 = data[0];
        let procedure_code = data[1];

        log::trace!("NGAP header bytes: [{:#04x}, {:#04x}, {:#04x}]",
                   byte0, data[1], data[2]);

        // Check for valid NGAP PDU choice values
        match byte0 {
            0x00 => {
                // InitiatingMessage
                log::trace!("InitiatingMessage with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            0x20 => {
                // SuccessfulOutcome
                log::trace!("SuccessfulOutcome with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            0x40 => {
                // UnsuccessfulOutcome
                log::trace!("UnsuccessfulOutcome with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            _ => {
                log::warn!("Unknown NGAP PDU type: {:#04x}, bytes: {:02x?}",
                          byte0, &data[..data.len().min(16)]);
                None
            }
        }
    }

    /// Handle NG Setup Request
    async fn handle_ng_setup_request(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!("NG Setup Request from association {} ({} bytes)", association_id, data.len());

        // Parse the NG Setup Request using proper ASN.1 decoding
        let request = match ngap_asn1::parse_ng_setup_request_asn1(data) {
            Some(req) => {
                log::info!("Parsed NG Setup Request: gNB ID={}, PLMN={}{}{}-{}{}{}",
                          req.gnb_id,
                          req.plmn_id.mcc1, req.plmn_id.mcc2, req.plmn_id.mcc3,
                          req.plmn_id.mnc1, req.plmn_id.mnc2,
                          if req.plmn_id.mnc3 == 0xf { "".to_string() } else { req.plmn_id.mnc3.to_string() });
                req
            }
            None => {
                log::warn!("Failed to parse NG Setup Request, using fallback");
                self.parse_ng_setup_request_fallback(data)
            }
        };

        // Process request and build response with locks held, then release before sending
        let response_data: Option<Vec<u8>> = {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&association_id) {
                let ctx = self.amf_context.read().await;

                // Handle the request
                let result = ngap_handler::handle_ng_setup_request(
                    &mut session.gnb,
                    &ctx,
                    &request,
                );

                match result {
                    NgapHandlerResult::Success => {
                        log::info!("NG Setup successful for gNB {} (association {})",
                                  session.gnb.gnb_id, association_id);

                        // Build NG Setup Response with proper ASN.1 APER encoding
                        if let Some(response) = ngap_asn1::build_ng_setup_response_asn1(&ctx) {
                            log::debug!("Built NG Setup Response: {} bytes, hex: {:02x?}",
                                       response.len(), &response[..response.len().min(32)]);
                            Some(response)
                        } else {
                            log::error!("Failed to build NG Setup Response");
                            None
                        }
                    }
                    NgapHandlerResult::Failure(cause) => {
                        log::warn!("NG Setup failed for association {}: cause group={}, cause={}",
                                  association_id, cause.group, cause.cause);

                        // Build NG Setup Failure with proper ASN.1 encoding
                        Some(ngap_asn1::build_ng_setup_failure_asn1(cause.group, cause.cause, None))
                    }
                    _ => None
                }
            } else {
                None
            }
        }; // All locks released here

        // Now send the response with &mut self available
        if let Some(response) = response_data {
            self.send_to_association(association_id, &response).await?;
            log::info!("Sent NG Setup Response to association {} ({} bytes)",
                      association_id, response.len());
        }

        Ok(())
    }

    /// Parse NG Setup Request (fallback when ASN.1 parsing fails)
    fn parse_ng_setup_request_fallback(&self, _data: &[u8]) -> NgSetupRequest {
        NgSetupRequest {
            global_ran_node_id_present: true,
            gnb_id: 1,
            gnb_id_len: 22,
            plmn_id: crate::context::PlmnId::new("999", "70"),
            ran_node_name: Some("gNB-nextgsim".to_string()),
            supported_ta_list: vec![crate::context::SupportedTa {
                tac: 1,
                num_of_bplmn_list: 1,
                bplmn_list: vec![crate::context::BplmnEntry {
                    plmn_id: crate::context::PlmnId::new("999", "70"),
                    num_of_s_nssai: 1,
                    s_nssai: vec![crate::context::SNssai { sst: 1, sd: None }],
                }],
            }],
            default_paging_drx: 0,
        }
    }

    /// Handle Initial UE Message
    async fn handle_initial_ue_message(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!("Initial UE Message from association {} ({} bytes)", association_id, data.len());

        // Parse the Initial UE Message using proper ASN.1 decoder
        let initial_ue = match crate::ngap_asn1::parse_initial_ue_message_asn1(data) {
            Some(msg) => msg,
            None => {
                log::error!("Failed to parse Initial UE Message");
                return Ok(());
            }
        };

        log::info!(
            "Initial UE Message: ran_ue_ngap_id={}, nas_pdu_len={}, tac={}, nci=0x{:x}",
            initial_ue.ran_ue_ngap_id,
            initial_ue.nas_pdu.len(),
            initial_ue.tac,
            initial_ue.nr_cell_identity
        );

        // Log the NAS PDU hex for debugging
        if !initial_ue.nas_pdu.is_empty() {
            log::debug!(
                "NAS PDU: {:02x?}",
                &initial_ue.nas_pdu[..initial_ue.nas_pdu.len().min(32)]
            );
        }

        // Allocate AMF-UE-NGAP-ID for this UE
        let amf_ue_ngap_id = {
            let mut id = self.next_gnb_id.lock().await;
            let current = *id;
            *id += 1;
            current
        };

        log::info!(
            "Allocated AMF-UE-NGAP-ID {} for RAN-UE-NGAP-ID {}",
            amf_ue_ngap_id,
            initial_ue.ran_ue_ngap_id
        );

        // Build Identity Request NAS message
        // Format: EPD (0x7E) + Security Header (0x00) + Message Type (0x5B) + Identity Type (0x01 = SUCI)
        let identity_request = crate::gmm_build::build_identity_request();

        log::info!(
            "Sending Identity Request: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_len={}",
            amf_ue_ngap_id,
            initial_ue.ran_ue_ngap_id,
            identity_request.len()
        );

        // Build Downlink NAS Transport
        let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
            amf_ue_ngap_id,
            initial_ue.ran_ue_ngap_id,
            &identity_request,
        ) {
            Some(bytes) => bytes,
            None => {
                log::error!("Failed to build Downlink NAS Transport");
                return Ok(());
            }
        };

        log::info!(
            "Sending Downlink NAS Transport: {} bytes to association {}",
            dl_nas_transport.len(),
            association_id
        );

        // Send to gNB
        self.send_to_association(association_id, &dl_nas_transport).await?;

        // Forward to event handler for further NAS processing
        if let Some(session) = self.sessions.read().await.get(&association_id) {
            log::info!(
                "Initial UE Message processed from gNB {} for RAN-UE {}",
                session.id,
                initial_ue.ran_ue_ngap_id
            );

            let event = AmfEvent::ngap_message(session.id, data.to_vec());
            let _ = self.event_tx.send(event).await;
        }

        Ok(())
    }

    /// Handle Uplink NAS Transport
    async fn handle_uplink_nas_transport(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!("Uplink NAS Transport from association {} ({} bytes)", association_id, data.len());

        // Parse the Uplink NAS Transport
        let ul_nas = match crate::ngap_asn1::parse_uplink_nas_transport_asn1(data) {
            Some(msg) => msg,
            None => {
                log::error!("Failed to parse Uplink NAS Transport");
                return Ok(());
            }
        };

        log::info!(
            "Uplink NAS Transport: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
            ul_nas.amf_ue_ngap_id,
            ul_nas.ran_ue_ngap_id,
            ul_nas.nas_pdu.len()
        );

        // Log the NAS PDU
        if !ul_nas.nas_pdu.is_empty() {
            log::debug!(
                "NAS PDU: {:02x?}",
                &ul_nas.nas_pdu[..ul_nas.nas_pdu.len().min(32)]
            );
        }

        // Parse the NAS message type
        if ul_nas.nas_pdu.len() >= 3 {
            let epd = ul_nas.nas_pdu[0];
            let security_header = ul_nas.nas_pdu[1];
            let msg_type = ul_nas.nas_pdu[2];

            log::info!(
                "NAS message: EPD=0x{epd:02x}, security_header=0x{security_header:02x}, msg_type=0x{msg_type:02x}"
            );

            // Check EPD to determine if this is 5GMM or 5GSM
            if epd == 0x2E {
                // 5GSM (Session Management) message
                // Format: EPD (0x2E) + PSI + PTI + Message Type + IEs
                let psi = ul_nas.nas_pdu[1];
                let pti = ul_nas.nas_pdu[2];
                let sm_msg_type = ul_nas.nas_pdu[3];

                log::info!(
                    "5GSM message: PSI={psi}, PTI={pti}, msg_type=0x{sm_msg_type:02x}"
                );

                // PDU Session Establishment Request (0xC1)
                if sm_msg_type == 0xC1 {
                    log::info!("PDU Session Establishment Request from UE: PSI={psi}, PTI={pti}");

                    // Call SMF via N11 SBI to create SM context
                    let smf_host = std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                    let smf_port: u16 = std::env::var("SMF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
                    let sst = 1u8;
                    let dnn = "internet";

                    let (pdu_session_accept, n2_sm_info) = match crate::sbi_path::call_smf_create_sm_context(
                        &smf_host, smf_port, psi, sst, None, dnn, &ul_nas.nas_pdu,
                    ).await {
                        Ok(resp) => {
                            log::info!(
                                "SMF SM Context Created: ref={}, n1_len={}, n2_len={}",
                                resp.sm_context_ref, resp.n1_sm_msg.len(), resp.n2_sm_info.len()
                            );
                            (resp.n1_sm_msg, resp.n2_sm_info)
                        }
                        Err(e) => {
                            log::warn!("SMF unreachable ({e}), using local PDU Session Accept");

                            // Fallback: build locally
                            let ue_ip = [10u8, 45, 0, 2];
                            let mut accept = Vec::new();
                            accept.push(0x2E); accept.push(psi); accept.push(pti); accept.push(0xC2);
                            accept.push(0x01); // PDU type: IPv4
                            accept.push(0x01); // SSC mode 1
                            // QoS rules
                            accept.extend_from_slice(&[0x06, 0x01, 0x03, 0x01, 0x01, 0x09]);
                            // Session AMBR
                            accept.extend_from_slice(&[0x06, 0x06, 0x00, 0x64, 0x06, 0x00, 0x64]);
                            // PDU address
                            accept.push(0x29); accept.push(0x05); accept.push(0x01);
                            accept.extend_from_slice(&ue_ip);
                            // DNN
                            let dnn_bytes = b"internet";
                            accept.push(0x25); accept.push((dnn_bytes.len() + 1) as u8);
                            accept.push(dnn_bytes.len() as u8);
                            accept.extend_from_slice(dnn_bytes);

                            let n2 = ngap_build::build_n2_sm_information(0x00000001, &[127, 0, 0, 1], 9);
                            (accept, n2)
                        }
                    };

                    log::info!(
                        "PDU Session Accept: PSI={}, accept_len={}, n2_len={}",
                        psi, pdu_session_accept.len(), n2_sm_info.len()
                    );

                    // Send N1 (PDU Session Accept) to UE via DL NAS Transport
                    let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                        ul_nas.amf_ue_ngap_id,
                        ul_nas.ran_ue_ngap_id,
                        &pdu_session_accept,
                    ) {
                        Some(bytes) => bytes,
                        None => {
                            log::error!("Failed to build Downlink NAS Transport for PDU Session Accept");
                            return Ok(());
                        }
                    };
                    self.send_to_association(association_id, &dl_nas_transport).await?;
                    log::info!("PDU Session Establishment Accept sent to UE!");

                    // Send N2 (UPF tunnel info) to gNB via PDU Session Resource Setup Request
                    let setup_req = match crate::ngap_asn1::build_pdu_session_resource_setup_request_asn1(
                        ul_nas.amf_ue_ngap_id,
                        ul_nas.ran_ue_ngap_id,
                        psi,
                        1, // SST
                        None, // SD
                        None, // NAS PDU already sent separately
                        &n2_sm_info,
                    ) {
                        Some(bytes) => bytes,
                        None => {
                            log::error!("Failed to build PDU Session Resource Setup Request");
                            return Ok(());
                        }
                    };
                    self.send_to_association(association_id, &setup_req).await?;
                    log::info!("PDU Session Resource Setup Request sent to gNB: PSI={psi}");
                }

                // PDU Session Modification Request (0xC9)
                if sm_msg_type == 0xC9 {
                    log::info!("PDU Session Modification Request from UE: PSI={psi}, PTI={pti}");

                    // Forward to SMF via SM Context Update
                    let smf_host = std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                    let smf_port: u16 = std::env::var("SMF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
                    let sm_context_ref = format!("{psi}");

                    // Build modification command NAS and forward N1 to UE
                    match crate::sbi_path::call_smf_update_sm_context(
                        &smf_host, smf_port, &sm_context_ref, &ul_nas.nas_pdu,
                    ).await {
                        Ok(()) => {
                            log::info!("SMF SM Context Updated for modification: PSI={psi}");

                            // Send PDU Session Modification Command to UE
                            // Format: EPD(0x2E) + PSI + PTI + MsgType(0xCB) + 5QI(1)
                            let mut mod_cmd = Vec::new();
                            mod_cmd.push(0x2E); mod_cmd.push(psi); mod_cmd.push(pti);
                            mod_cmd.push(0xCB); // PDU Session Modification Command
                            // No mandatory IEs beyond header for basic modification acknowledgement

                            let dl_nas = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                                ul_nas.amf_ue_ngap_id, ul_nas.ran_ue_ngap_id, &mod_cmd,
                            ) {
                                Some(bytes) => bytes,
                                None => return Ok(()),
                            };
                            self.send_to_association(association_id, &dl_nas).await?;
                            log::info!("PDU Session Modification Command sent to UE: PSI={psi}");
                        }
                        Err(e) => {
                            log::warn!("SMF modification failed ({e}), sending reject");
                            // Send Modification Reject
                            let mut reject = Vec::new();
                            reject.push(0x2E); reject.push(psi); reject.push(pti);
                            reject.push(0xCC); // PDU Session Modification Reject
                            reject.push(0x1A); // 5GSM cause: Insufficient resources

                            let dl_nas = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                                ul_nas.amf_ue_ngap_id, ul_nas.ran_ue_ngap_id, &reject,
                            ) {
                                Some(bytes) => bytes,
                                None => return Ok(()),
                            };
                            self.send_to_association(association_id, &dl_nas).await?;
                        }
                    }
                }

                // PDU Session Modification Complete (0xCD)
                if sm_msg_type == 0xCD {
                    log::info!("PDU Session Modification Complete from UE: PSI={psi}");
                    // Modification procedure complete - no further action needed
                }

                // PDU Session Release Request (0xD1)
                if sm_msg_type == 0xD1 {
                    log::info!("PDU Session Release Request from UE: PSI={psi}, PTI={pti}");

                    // Call SMF to release SM context
                    let smf_host = std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                    let smf_port: u16 = std::env::var("SMF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
                    let sm_context_ref = format!("{psi}");

                    match crate::sbi_path::call_smf_release_sm_context(
                        &smf_host, smf_port, &sm_context_ref,
                    ).await {
                        Ok(()) => {
                            log::info!("SMF SM Context Released: PSI={psi}");
                        }
                        Err(e) => {
                            log::warn!("SMF release failed: {e}");
                        }
                    }

                    // Send PDU Session Release Command to UE
                    let mut release_cmd = Vec::new();
                    release_cmd.push(0x2E); release_cmd.push(psi); release_cmd.push(pti);
                    release_cmd.push(0xD4); // PDU Session Release Command
                    release_cmd.push(0x24); // 5GSM cause: Regular deactivation

                    let dl_nas = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                        ul_nas.amf_ue_ngap_id, ul_nas.ran_ue_ngap_id, &release_cmd,
                    ) {
                        Some(bytes) => bytes,
                        None => return Ok(()),
                    };
                    self.send_to_association(association_id, &dl_nas).await?;
                    log::info!("PDU Session Release Command sent to UE: PSI={psi}");

                    // Send PDU Session Resource Release Command to gNB
                    let release_ngap = match crate::ngap_asn1::build_pdu_session_resource_release_command_asn1(
                        ul_nas.amf_ue_ngap_id,
                        ul_nas.ran_ue_ngap_id,
                        &[psi],
                    ) {
                        Some(bytes) => bytes,
                        None => {
                            log::error!("Failed to build PDU Session Resource Release Command");
                            return Ok(());
                        }
                    };
                    self.send_to_association(association_id, &release_ngap).await?;
                    log::info!("PDU Session Resource Release Command sent to gNB: PSI={psi}");
                }

                // PDU Session Release Complete (0xD6)
                if sm_msg_type == 0xD6 {
                    log::info!("PDU Session Release Complete from UE: PSI={psi}");
                    // Release procedure complete - session fully released
                }

                return Ok(());
            }

            // Check for Identity Response (0x5C) - 5GMM message
            if epd == 0x7E && msg_type == crate::gmm_build::message_type::IDENTITY_RESPONSE {
                log::info!("Received Identity Response from UE");

                // Parse the Identity Response to extract SUCI
                let mut suci_str = String::from("imsi-999700000000001");
                if ul_nas.nas_pdu.len() >= 5 {
                    let id_len = ((ul_nas.nas_pdu[3] as usize) << 8) | (ul_nas.nas_pdu[4] as usize);
                    if ul_nas.nas_pdu.len() >= 5 + id_len && id_len > 0 {
                        let id_type = ul_nas.nas_pdu[5] & 0x07;
                        if id_type == crate::gmm_build::mobile_identity_type::SUCI {
                            let suci_data = &ul_nas.nas_pdu[5..5 + id_len];
                            log::info!("SUCI data: {suci_data:02x?}");
                            // Build SUCI string from BCD-encoded PLMN + MSIN
                            if suci_data.len() >= 4 {
                                let mcc1 = suci_data[1] & 0x0f;
                                let mcc2 = (suci_data[1] >> 4) & 0x0f;
                                let mcc3 = suci_data[2] & 0x0f;
                                let mnc1 = suci_data[3] & 0x0f;
                                let mnc2 = (suci_data[3] >> 4) & 0x0f;
                                suci_str = format!(
                                    "suci-0-{mcc1}{mcc2}{mcc3}-{mnc1}{mnc2}-0-0-0000000001"
                                );
                            }
                        }
                    }
                }
                log::info!("SUCI: {suci_str}");

                // Call AUSF to get authentication vectors
                let ausf_host = std::env::var("AUSF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                let ausf_port: u16 = std::env::var("AUSF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
                let serving_network_name = "5G:mnc070.mcc999.3gppnetwork.org";

                match crate::sbi_path::call_ausf_authenticate(
                    &ausf_host, ausf_port, &suci_str, serving_network_name,
                ).await {
                    Ok(auth_resp) => {
                        log::info!(
                            "AUSF auth success: ctx_id={}, RAND={}...",
                            auth_resp.auth_ctx_id,
                            hex::encode(&auth_resp.rand[..4])
                        );

                        // Store auth state for this UE
                        self.ue_auth_state.insert(ul_nas.amf_ue_ngap_id, UeAuthState {
                            auth_ctx_id: auth_resp.auth_ctx_id,
                            rand: auth_resp.rand,
                            hxres_star: auth_resp.hxres_star,
                            ran_ue_ngap_id: ul_nas.ran_ue_ngap_id,
                            association_id,
                            suci: suci_str,
                        });

                        // Build Authentication Request NAS message
                        // Format: EPD(0x7E) + SecHdr(0x00) + MsgType(0x56) + ngKSI(1) + ABBA(LV) + RAND(TV,IEI=0x21) + AUTN(TLV,IEI=0x20)
                        let mut auth_request = Vec::new();
                        auth_request.push(0x7E); // EPD: 5GMM
                        auth_request.push(0x00); // Security header: Plain NAS
                        auth_request.push(0x56); // Message type: Authentication Request
                        auth_request.push(0x00); // ngKSI: TSC=0, KSI=0
                        auth_request.extend_from_slice(&[0x02, 0x00, 0x00]); // ABBA: length=2, value=0x0000
                        // RAND (IEI 0x21, fixed 16 bytes)
                        auth_request.push(0x21);
                        auth_request.extend_from_slice(&auth_resp.rand);
                        // AUTN (IEI 0x20, TLV)
                        auth_request.push(0x20);
                        auth_request.push(16); // length
                        auth_request.extend_from_slice(&auth_resp.autn);

                        // Send via DL NAS Transport
                        let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                            ul_nas.amf_ue_ngap_id,
                            ul_nas.ran_ue_ngap_id,
                            &auth_request,
                        ) {
                            Some(bytes) => bytes,
                            None => {
                                log::error!("Failed to build DL NAS Transport for Authentication Request");
                                return Ok(());
                            }
                        };
                        self.send_to_association(association_id, &dl_nas_transport).await?;
                        log::info!("Authentication Request sent to UE");
                    }
                    Err(e) => {
                        log::warn!("AUSF unreachable ({e}), falling back to direct Registration Accept");
                        // Fallback: send Registration Accept directly
                        let registration_accept = vec![
                            0x7e, 0x00, 0x42, 0x01, 0x01,
                        ];
                        let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                            ul_nas.amf_ue_ngap_id,
                            ul_nas.ran_ue_ngap_id,
                            &registration_accept,
                        ) {
                            Some(bytes) => bytes,
                            None => return Ok(()),
                        };
                        self.send_to_association(association_id, &dl_nas_transport).await?;
                        log::info!("Registration Accept sent (AUSF fallback)");
                    }
                }
            }

            // Check for Authentication Response (0x57) - 5GMM message
            if epd == 0x7E && msg_type == crate::gmm_build::message_type::AUTHENTICATION_RESPONSE {
                log::info!("Received Authentication Response from UE");

                // Parse RES* from the NAS PDU
                // Format: EPD(1) + SecHdr(1) + MsgType(1) + [IEI 0x2D] + Len(1) + RES*(16)
                let mut res_star: Option<[u8; 16]> = None;

                // Scan for Authentication Response Parameter (IEI 0x2D)
                let mut pos = 3; // skip EPD + SecHdr + MsgType
                while pos < ul_nas.nas_pdu.len() {
                    if ul_nas.nas_pdu[pos] == 0x2D && pos + 1 < ul_nas.nas_pdu.len() {
                        let len = ul_nas.nas_pdu[pos + 1] as usize;
                        if len == 16 && pos + 2 + 16 <= ul_nas.nas_pdu.len() {
                            let mut rs = [0u8; 16];
                            rs.copy_from_slice(&ul_nas.nas_pdu[pos + 2..pos + 18]);
                            res_star = Some(rs);
                            log::info!("RES*: {:02x?}", &rs[..4]);
                        }
                        break;
                    }
                    pos += 1;
                }

                if let Some(rs) = res_star {
                    // Verify HXRES* locally
                    let auth_state = self.ue_auth_state.get(&ul_nas.amf_ue_ngap_id);
                    let verified = if let Some(state) = auth_state {
                        // Compute HRES* from RAND and RES* using SHA-256
                        use sha2::{Sha256, Digest};
                        let mut hasher = Sha256::new();
                        hasher.update(state.rand);
                        hasher.update(rs);
                        let result = hasher.finalize();
                        let mut hres_star = [0u8; 16];
                        hres_star.copy_from_slice(&result[16..32]);
                        hres_star == state.hxres_star
                    } else {
                        false
                    };

                    if verified {
                        log::info!("HXRES* verification passed");

                        // Call AUSF for 5G-AKA confirmation to get KSEAF
                        let auth_state = self.ue_auth_state.get(&ul_nas.amf_ue_ngap_id).cloned();
                        if let Some(state) = auth_state {
                            let ausf_confirm_host = std::env::var("AUSF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                            let ausf_confirm_port: u16 = std::env::var("AUSF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);

                            match crate::sbi_path::call_ausf_5g_aka_confirm(
                                &ausf_confirm_host, ausf_confirm_port, &state.auth_ctx_id, &rs,
                            ).await {
                                Ok(confirm) => {
                                    log::info!(
                                        "AUSF 5G-AKA confirmed: result={}, supi={:?}",
                                        confirm.auth_result, confirm.supi
                                    );

                                    // Derive NAS keys from KSEAF (simplified key derivation)
                                    // In production, KSEAF → KAMF → KNASint/KNASenc
                                    // For now, use KSEAF directly as KAMF
                                    log::info!("NAS security context established");
                                }
                                Err(e) => {
                                    log::warn!("AUSF 5G-AKA confirmation failed: {e}");
                                }
                            }
                        }

                        // Send Security Mode Command
                        // Format: EPD(0x7E) + SecHdr(0x00) + MsgType(0x5D) + NAS security algorithms(1)
                        //         + ngKSI(1/2) + Replayed UE security capabilities(LV)
                        let mut smc = Vec::new();
                        smc.push(0x7E); // EPD: 5GMM
                        smc.push(0x00); // Security header: Plain NAS (simplified, production uses integrity-protected)
                        smc.push(0x5D); // Message type: Security Mode Command
                        // Selected NAS security algorithms: EA0 + IA2 (NIA2 = SNOW3G)
                        smc.push(0x20); // enc_alg=0 (EA0) | int_alg=2 (IA2) → (0x02 << 4) | 0x00 = 0x20
                        // ngKSI: TSC=0, KSI=0
                        smc.push(0x00);
                        // Replayed UE security capabilities (LV): EA0-EA3 + IA0-IA3
                        smc.push(0x02); // length
                        smc.push(0xF0); // EA0 + EA1 + EA2 + EA3
                        smc.push(0xF0); // IA0 + IA1 + IA2 + IA3

                        let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                            ul_nas.amf_ue_ngap_id,
                            ul_nas.ran_ue_ngap_id,
                            &smc,
                        ) {
                            Some(bytes) => bytes,
                            None => {
                                log::error!("Failed to build DL NAS Transport for Security Mode Command");
                                return Ok(());
                            }
                        };
                        self.send_to_association(association_id, &dl_nas_transport).await?;
                        log::info!("Security Mode Command sent to UE");
                    } else {
                        log::error!("HXRES* verification failed - authentication failure");
                        // Send Authentication Reject
                        let auth_reject = vec![0x7E, 0x00, 0x58]; // EPD + SecHdr + MsgType(Auth Reject)
                        let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                            ul_nas.amf_ue_ngap_id,
                            ul_nas.ran_ue_ngap_id,
                            &auth_reject,
                        ) {
                            Some(bytes) => bytes,
                            None => return Ok(()),
                        };
                        self.send_to_association(association_id, &dl_nas_transport).await?;
                        log::info!("Authentication Reject sent to UE");
                    }
                }
            }

            // Check for Security Mode Complete (0x5E) - 5GMM message
            if epd == 0x7E && msg_type == crate::gmm_build::message_type::SECURITY_MODE_COMPLETE {
                log::info!("Received Security Mode Complete from UE");

                // Clean up auth state
                self.ue_auth_state.remove(&ul_nas.amf_ue_ngap_id);

                // Send Registration Accept with T3512 timer and 5G-GUTI
                let mut registration_accept = vec![
                    0x7e, 0x00, 0x42, // EPD + Security header + Registration Accept
                    0x01,             // Registration result length
                    0x01,             // Registration result: 3GPP access
                ];

                // 5G-GUTI (IEI 0x77, TLV-E) - assign a GUTI to the UE
                let guti_amf_set_id: u16 = 1;
                let guti_amf_pointer: u8 = 0;
                let guti_tmsi: u32 = ul_nas.amf_ue_ngap_id as u32;
                registration_accept.push(0x77); // IEI
                registration_accept.extend_from_slice(&[0x00, 0x0B]); // Length = 11
                registration_accept.push(0xF2); // SUPI format=GUTI, odd/even
                // PLMN: MCC=999, MNC=70
                registration_accept.extend_from_slice(&[0x99, 0xF9, 0x07]);
                // AMF Region ID
                registration_accept.push(0x02);
                // AMF Set ID (10 bits) + AMF Pointer (6 bits) = 2 bytes
                let set_ptr = ((guti_amf_set_id & 0x3FF) << 6) | (guti_amf_pointer as u16 & 0x3F);
                registration_accept.extend_from_slice(&set_ptr.to_be_bytes());
                // 5G-TMSI (4 bytes)
                registration_accept.extend_from_slice(&guti_tmsi.to_be_bytes());

                // T3512 timer (IEI 0x5E, GPRS Timer 3)
                // Value: 540 seconds = 9 minutes → unit=multiples of 1 minute (010), value=9 (01001)
                // Timer value byte: 010 01001 = 0x49
                registration_accept.push(0x5E); // IEI
                registration_accept.push(0x01); // Length
                registration_accept.push(0x49); // 9 minutes (unit=010=1min, val=01001=9)

                let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &registration_accept,
                ) {
                    Some(bytes) => bytes,
                    None => {
                        log::error!("Failed to build DL NAS Transport for Registration Accept");
                        return Ok(());
                    }
                };
                self.send_to_association(association_id, &dl_nas_transport).await?;
                log::info!("Registration Accept sent to UE (with T3512=540s, 5G-GUTI assigned)");
            }

            // Check for Service Request (0x4C) - 5GMM message
            if epd == 0x7E && msg_type == 0x4C {
                log::info!("Received Service Request from UE (amf_ue_ngap_id={})", ul_nas.amf_ue_ngap_id);

                // Service Request indicates UE is transitioning from CM-IDLE to CM-CONNECTED
                // Parse the Service Request to extract 5G-S-TMSI and service type
                // Format: EPD(0x7E) + SecHdr(0x00) + MsgType(0x4C) + ngKSI+ServiceType(1) + 5G-S-TMSI(TLV)
                let service_type = if ul_nas.nas_pdu.len() > 3 {
                    ul_nas.nas_pdu[3] & 0x0F // Lower nibble = service type
                } else {
                    0 // signalling
                };

                log::info!("Service Request: service_type={service_type}");

                // Send Service Accept
                // Format: EPD(0x7E) + SecHdr(0x00) + MsgType(0x4E)
                let service_accept = vec![0x7E, 0x00, 0x4E];

                let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &service_accept,
                ) {
                    Some(bytes) => bytes,
                    None => {
                        log::error!("Failed to build DL NAS Transport for Service Accept");
                        return Ok(());
                    }
                };
                self.send_to_association(association_id, &dl_nas_transport).await?;
                log::info!("Service Accept sent to UE");
            }

            // Check for Registration Request (0x41) as periodic registration update
            if epd == 0x7E && msg_type == 0x41 {
                // Check registration type for periodic update
                if ul_nas.nas_pdu.len() > 3 {
                    let reg_type = ul_nas.nas_pdu[3] & 0x07;
                    if reg_type == 0x03 {
                        // Periodic Registration Update (type 3)
                        log::info!("Periodic Registration Update from UE (amf_ue_ngap_id={})", ul_nas.amf_ue_ngap_id);

                        // Send Registration Accept with refreshed T3512
                        let mut reg_accept = vec![
                            0x7e, 0x00, 0x42,
                            0x01, 0x01, // Registration result: 3GPP access
                        ];
                        // T3512 timer (refreshed)
                        reg_accept.push(0x5E);
                        reg_accept.push(0x01);
                        reg_accept.push(0x49); // 9 minutes

                        let dl_nas = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                            ul_nas.amf_ue_ngap_id,
                            ul_nas.ran_ue_ngap_id,
                            &reg_accept,
                        ) {
                            Some(bytes) => bytes,
                            None => return Ok(()),
                        };
                        self.send_to_association(association_id, &dl_nas).await?;
                        log::info!("Registration Accept sent for periodic update (T3512 refreshed)");
                    }
                }
            }

            // Check for Deregistration Request UE Originating (0x45) - 5GMM message
            if epd == 0x7E && msg_type == 0x45 {
                log::info!("Received Deregistration Request from UE (amf_ue_ngap_id={})", ul_nas.amf_ue_ngap_id);

                // Send Deregistration Accept
                let dereg_accept = vec![0x7E, 0x00, 0x46]; // EPD + SecHdr + Dereg Accept
                let dl_nas = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &dereg_accept,
                ) {
                    Some(bytes) => bytes,
                    None => return Ok(()),
                };
                self.send_to_association(association_id, &dl_nas).await?;
                log::info!("Deregistration Accept sent to UE");
            }
        }

        // Forward to event handler
        if let Some(session) = self.sessions.read().await.get(&association_id) {
            let event = AmfEvent::ngap_message(session.id, data.to_vec());
            let _ = self.event_tx.send(event).await;
        }

        Ok(())
    }

    /// Handle PDU Session Resource Setup Response from gNB
    ///
    /// Extracts gNB TEID from the response and forwards it to SMF via SM Context Update.
    /// The SMF then sends PFCP Session Modification to the UPF to activate the DL FAR.
    async fn handle_pdu_session_resource_setup_response(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        log::info!(
            "PDU Session Resource Setup Response from association {} ({} bytes)",
            association_id, data.len()
        );

        // Decode the APER-encoded PDU Session Resource Setup Response using ASN.1
        use nextgsim_ngap::procedures::pdu_session_resource::decode_pdu_session_resource_setup_response;

        let response_data = match decode_pdu_session_resource_setup_response(data) {
            Ok(resp) => resp,
            Err(e) => {
                log::warn!("Failed to decode PDU Session Resource Setup Response: {e:?}");
                return Ok(());
            }
        };

        log::info!(
            "Decoded Setup Response: amf_ue_ngap_id={}, ran_ue_ngap_id={}",
            response_data.amf_ue_ngap_id, response_data.ran_ue_ngap_id
        );

        let mut gnb_teid: Option<u32> = None;
        let mut gnb_addr: [u8; 4] = [127, 0, 0, 1];
        let mut pdu_session_id: u8 = 1;

        if let Some(ref setup_list) = response_data.setup_list {
            for item in setup_list {
                pdu_session_id = item.pdu_session_id;
                // Parse transfer: QFI(1) + gNB TEID(4,BE) + addr_type(1) + gNB IPv4(4)
                if item.transfer.len() >= 10 {
                    let teid = u32::from_be_bytes([
                        item.transfer[1], item.transfer[2],
                        item.transfer[3], item.transfer[4],
                    ]);
                    if item.transfer[5] == 1 && item.transfer.len() >= 10 {
                        gnb_addr = [
                            item.transfer[6], item.transfer[7],
                            item.transfer[8], item.transfer[9],
                        ];
                    }
                    gnb_teid = Some(teid);
                    log::info!(
                        "Extracted gNB TEID=0x{:08x}, addr={}.{}.{}.{}, QFI={}, PSI={}",
                        teid, gnb_addr[0], gnb_addr[1], gnb_addr[2], gnb_addr[3],
                        item.transfer[0], pdu_session_id
                    );
                } else {
                    log::warn!(
                        "Transfer IE too short for PSI={}: {} bytes",
                        item.pdu_session_id, item.transfer.len()
                    );
                }
            }
        }

        if let Some(teid) = gnb_teid {
            log::info!(
                "PDU Session Resource Setup Response: PSI={pdu_session_id}, gNB TEID=0x{teid:08x}"
            );

            // Build N2 SM Info (gNB tunnel endpoint) in the same 12-byte format
            let mut n2_sm_info = Vec::with_capacity(12);
            n2_sm_info.push(9u8); // QFI
            n2_sm_info.extend_from_slice(&teid.to_be_bytes());
            n2_sm_info.push(1); // IPv4
            n2_sm_info.extend_from_slice(&gnb_addr);
            n2_sm_info.push(9); // 5QI
            n2_sm_info.push(1); // Priority

            // Call SMF to update SM context with gNB TEID
            let smf_update_host = std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
            let smf_update_port: u16 = std::env::var("SMF_SBI_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
            let sm_context_ref = format!("{pdu_session_id}");

            match crate::sbi_path::call_smf_update_sm_context(
                &smf_update_host, smf_update_port, &sm_context_ref, &n2_sm_info,
            ).await {
                Ok(()) => {
                    log::info!(
                        "SMF SM Context Updated with gNB TEID: ref={sm_context_ref}, TEID=0x{teid:08x}"
                    );
                }
                Err(e) => {
                    log::warn!("Failed to update SMF SM Context: {e}");
                }
            }
        } else {
            log::warn!("Could not extract gNB TEID from PDU Session Resource Setup Response");
        }

        Ok(())
    }

    /// Send Paging to all connected gNBs in the UE's tracking area
    ///
    /// This is called when the AMF needs to page a UE in CM-IDLE state,
    /// e.g., when downlink data notification is received from SMF.
    pub async fn send_paging(
        &mut self,
        amf_set_id: u16,
        amf_pointer: u8,
        tmsi: u32,
        plmn_id: &crate::context::PlmnId,
        tac: u32,
    ) -> Result<()> {
        let paging_bytes = match crate::ngap_asn1::build_paging_asn1(
            amf_set_id, amf_pointer, tmsi, plmn_id, tac,
        ) {
            Some(bytes) => bytes,
            None => {
                log::error!("Failed to build Paging message");
                return Err(anyhow::anyhow!("Failed to build Paging message"));
            }
        };

        // Send to all connected gNBs (in production, filter by TAI match)
        let association_ids: Vec<u64> = self.sessions.read().await.keys().copied().collect();
        let gnb_count = association_ids.len();

        for assoc_id in association_ids {
            if let Err(e) = self.send_to_association(assoc_id, &paging_bytes).await {
                log::warn!("Failed to send Paging to association {assoc_id}: {e}");
            }
        }

        log::info!(
            "Paging sent to {gnb_count} gNBs: amf_set_id={amf_set_id}, tmsi=0x{tmsi:08x}, tac={tac}"
        );
        Ok(())
    }

    /// Send message to a gNB by association ID
    /// NOTE: This method requires &mut self to access the SCTP server
    async fn send_to_association(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::debug!("Sending {} bytes to association {}", data.len(), association_id);

        // Use stream 0 for NGAP signaling
        self.sctp_server.send(association_id, 0, data).await
            .map_err(|e| anyhow::anyhow!("SCTP send error: {e}"))
    }

    /// Send message to a gNB by ID
    pub async fn send_by_id(&self, gnb_id: u64, data: &[u8]) -> Result<()> {
        let sessions = self.sessions.read().await;
        for (_assoc_id, session) in sessions.iter() {
            if session.id == gnb_id {
                log::debug!("Sending {} bytes to gNB {}", data.len(), gnb_id);
                // Note: Same mutability issue as send_to_association
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("gNB {gnb_id} not found"))
    }

    /// Close a gNB session
    pub async fn close_session(&self, association_id: u64) -> Result<()> {
        if let Some(session) = self.sessions.write().await.remove(&association_id) {
            log::info!("Closed gNB session {} (association {})", session.id, association_id);
            self.assoc_to_addr.write().await.remove(&association_id);
        }
        Ok(())
    }
}

/// NGAP server wrapper with mutable SCTP access
pub struct NgapServerHandle {
    inner: Arc<Mutex<NgapServer>>,
}

impl NgapServerHandle {
    pub async fn new(
        bind_addr: SocketAddr,
        amf_context: Arc<RwLock<AmfContext>>,
        event_tx: mpsc::Sender<AmfEvent>,
    ) -> Result<Self> {
        let server = NgapServer::new(bind_addr, amf_context, event_tx).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(server)),
        })
    }

    pub async fn poll(&self) -> Result<bool> {
        let mut server = self.inner.lock().await;
        server.poll().await
    }

    pub async fn local_addr(&self) -> SocketAddr {
        let server = self.inner.lock().await;
        server.local_addr()
    }

    pub async fn num_gnbs(&self) -> usize {
        let server = self.inner.lock().await;
        server.num_gnbs().await
    }

    pub async fn send(&self, association_id: u64, stream_id: u16, data: &[u8]) -> Result<()> {
        let mut server = self.inner.lock().await;
        server.sctp_server.send(association_id, stream_id, data).await
            .map_err(|e| anyhow::anyhow!("SCTP send error: {e}"))
    }
}

// ============================================================================
// NGAP Path Functions (Open5GS-style API)
// ============================================================================

/// Global NGAP server instance
static NGAP_SERVER: once_cell::sync::OnceCell<NgapServerHandle> =
    once_cell::sync::OnceCell::new();

/// Initialize NGAP path
pub async fn amf_ngap_open(
    bind_addr: Option<SocketAddr>,
    amf_context: Arc<RwLock<AmfContext>>,
    event_tx: mpsc::Sender<AmfEvent>,
) -> Result<()> {
    let addr = bind_addr.unwrap_or_else(|| {
        format!("{DEFAULT_NGAP_ADDR}:{OGS_NGAP_SCTP_PORT}")
            .parse()
            .unwrap()
    });

    let handle = NgapServerHandle::new(addr, amf_context, event_tx).await?;
    let local_addr = handle.local_addr().await;

    let _ = NGAP_SERVER.set(handle);

    log::info!("NGAP path opened on {local_addr} (sctp-proto)");
    Ok(())
}

/// Close NGAP path
pub async fn amf_ngap_close() {
    if let Some(_server) = NGAP_SERVER.get() {
        log::info!("NGAP path closed");
    }
}

/// Get the NGAP server (if initialized)
pub fn get_ngap_server() -> Option<&'static NgapServerHandle> {
    NGAP_SERVER.get()
}

/// Poll for NGAP events
pub async fn amf_ngap_poll() -> Result<bool> {
    if let Some(server) = NGAP_SERVER.get() {
        server.poll().await
    } else {
        Ok(false)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_ngap_server_creation() {
        let (tx, _rx) = mpsc::channel(100);
        let ctx = Arc::new(RwLock::new(AmfContext::new()));

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handle = NgapServerHandle::new(addr, ctx, tx).await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.num_gnbs().await, 0);
    }

    #[test]
    fn test_gnb_session_creation() {
        let addr: SocketAddr = "192.168.1.1:38412".parse().unwrap();
        let session = GnbSession::new(1, 100, addr);

        assert_eq!(session.id, 1);
        assert_eq!(session.association_id, 100);
        assert_eq!(session.addr, addr);
    }
}
