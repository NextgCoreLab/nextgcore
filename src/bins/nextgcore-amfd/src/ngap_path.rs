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
            .map_err(|e| anyhow::anyhow!("Failed to bind SCTP server: {}", e))?;

        let local_addr = sctp_server.local_addr();

        // Set up event channel for server events
        let (server_event_tx, server_event_rx) = mpsc::unbounded_channel();
        sctp_server.set_event_sender(server_event_tx);

        log::info!("NGAP server listening on {} (sctp-proto over UDP)", local_addr);

        Ok(Self {
            sctp_server,
            bind_addr: local_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            assoc_to_addr: Arc::new(RwLock::new(HashMap::new())),
            next_gnb_id: Arc::new(Mutex::new(1)),
            amf_context,
            event_tx,
            server_event_rx,
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
            Err(e) => Err(anyhow::anyhow!("SCTP receive error: {}", e)),
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

        log::info!("New gNB connection from {} (gNB ID: {}, association: {})",
                  remote_addr, gnb_id, association_id);

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
            log::warn!("Received data for unknown association {}", association_id);
        }

        Ok(())
    }

    /// Process an NGAP message
    async fn process_ngap_message(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        if data.len() < 3 {
            log::warn!("NGAP message too short from association {}", association_id);
            return Ok(());
        }

        // Log raw message header for debugging
        log::debug!("NGAP message from association {}: {} bytes, header: {:02x?}",
                   association_id, data.len(), &data[..data.len().min(8)]);

        // Check for NGAP message type
        let procedure_code = self.extract_procedure_code(data);

        log::info!("NGAP message from association {}: procedure_code={:?}",
                   association_id, procedure_code);

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
                log::trace!("InitiatingMessage with procedure code {}", procedure_code);
                Some(procedure_code as u16)
            }
            0x20 => {
                // SuccessfulOutcome
                log::trace!("SuccessfulOutcome with procedure code {}", procedure_code);
                Some(procedure_code as u16)
            }
            0x40 => {
                // UnsuccessfulOutcome
                log::trace!("UnsuccessfulOutcome with procedure code {}", procedure_code);
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
                "NAS message: EPD=0x{:02x}, security_header=0x{:02x}, msg_type=0x{:02x}",
                epd, security_header, msg_type
            );

            // Check EPD to determine if this is 5GMM or 5GSM
            if epd == 0x2E {
                // 5GSM (Session Management) message
                // Format: EPD (0x2E) + PSI + PTI + Message Type + IEs
                let psi = ul_nas.nas_pdu[1];
                let pti = ul_nas.nas_pdu[2];
                let sm_msg_type = ul_nas.nas_pdu[3];

                log::info!(
                    "5GSM message: PSI={}, PTI={}, msg_type=0x{:02x}",
                    psi, pti, sm_msg_type
                );

                // PDU Session Establishment Request (0xC1)
                if sm_msg_type == 0xC1 {
                    log::info!("PDU Session Establishment Request from UE: PSI={}, PTI={}", psi, pti);

                    // For now, we'll respond with a simple PDU Session Establishment Accept
                    // In a full implementation, this would go through SMF/UPF

                    // Allocate an IP address (simple static assignment for testing)
                    let ue_ip = [10u8, 45, 0, 2]; // 10.45.0.2

                    // Build PDU Session Establishment Accept
                    // Format: EPD (0x2E) + PSI + PTI + Message Type (0xC2) + IEs
                    let mut pdu_session_accept = Vec::new();
                    pdu_session_accept.push(0x2E);  // EPD: 5GSM
                    pdu_session_accept.push(psi);   // PDU Session ID
                    pdu_session_accept.push(pti);   // PTI
                    pdu_session_accept.push(0xC2);  // Message Type: PDU Session Establishment Accept

                    // Mandatory IE: Selected PDU session type (9.11.4.11)
                    pdu_session_accept.push(0x01);  // IPv4

                    // Mandatory IE: Selected SSC mode (9.11.4.16)
                    pdu_session_accept.push(0x01);  // SSC mode 1

                    // Mandatory IE: Authorized QoS rules (9.11.4.13) - simplified
                    pdu_session_accept.push(0x06);  // Length
                    pdu_session_accept.push(0x01);  // QoS rule ID
                    pdu_session_accept.push(0x03);  // Rule length
                    pdu_session_accept.push(0x01);  // Rule operation: create new
                    pdu_session_accept.push(0x01);  // DQR=1, packet filter list length=0
                    pdu_session_accept.push(0x09);  // Default QFI=9

                    // Mandatory IE: Session AMBR (9.11.4.14)
                    pdu_session_accept.push(0x06);  // Length
                    pdu_session_accept.push(0x06);  // Unit: 1 Mbps DL
                    pdu_session_accept.push(0x00);  // DL session AMBR value (high)
                    pdu_session_accept.push(0x64);  // DL session AMBR value (low) = 100 Mbps
                    pdu_session_accept.push(0x06);  // Unit: 1 Mbps UL
                    pdu_session_accept.push(0x00);  // UL session AMBR value (high)
                    pdu_session_accept.push(0x64);  // UL session AMBR value (low) = 100 Mbps

                    // Optional IE: PDU address (9.11.4.10) - IEI 0x29
                    pdu_session_accept.push(0x29);  // IEI
                    pdu_session_accept.push(0x05);  // Length
                    pdu_session_accept.push(0x01);  // PDU session type: IPv4
                    pdu_session_accept.extend_from_slice(&ue_ip);  // IPv4 address

                    // Optional IE: DNN (9.11.4.13) - IEI 0x25
                    let dnn = b"internet";
                    pdu_session_accept.push(0x25);  // IEI
                    pdu_session_accept.push((dnn.len() + 1) as u8);  // Length
                    pdu_session_accept.push(dnn.len() as u8);  // DNN length
                    pdu_session_accept.extend_from_slice(dnn);

                    log::info!(
                        "Sending PDU Session Establishment Accept: PSI={}, IP={}.{}.{}.{}, len={}",
                        psi, ue_ip[0], ue_ip[1], ue_ip[2], ue_ip[3], pdu_session_accept.len()
                    );

                    // Build Downlink NAS Transport
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

                    // Send to gNB
                    self.send_to_association(association_id, &dl_nas_transport).await?;
                    log::info!("PDU Session Establishment Accept sent!");
                }

                return Ok(());
            }

            // Check for Identity Response (0x5C) - 5GMM message
            if epd == 0x7E && msg_type == crate::gmm_build::message_type::IDENTITY_RESPONSE {
                log::info!("Received Identity Response from UE");

                // Parse the Identity Response to extract SUCI
                // Format: EPD (1) + Security Header (1) + Message Type (1) + Mobile Identity length (2) + Mobile Identity
                if ul_nas.nas_pdu.len() >= 5 {
                    let id_len = ((ul_nas.nas_pdu[3] as usize) << 8) | (ul_nas.nas_pdu[4] as usize);
                    log::info!("Identity length: {}", id_len);

                    if ul_nas.nas_pdu.len() >= 5 + id_len && id_len > 0 {
                        let id_type = ul_nas.nas_pdu[5] & 0x07;
                        log::info!("Identity type: {}", id_type);

                        if id_type == crate::gmm_build::mobile_identity_type::SUCI {
                            // Parse SUCI
                            let suci_data = &ul_nas.nas_pdu[5..5 + id_len];
                            log::info!("SUCI data: {:02x?}", suci_data);

                            // Extract PLMN from SUCI
                            if suci_data.len() >= 4 {
                                let mcc1 = suci_data[1] & 0x0f;
                                let mcc2 = (suci_data[1] >> 4) & 0x0f;
                                let mcc3 = suci_data[2] & 0x0f;
                                let mnc3 = (suci_data[2] >> 4) & 0x0f;
                                let mnc1 = suci_data[3] & 0x0f;
                                let mnc2 = (suci_data[3] >> 4) & 0x0f;

                                log::info!(
                                    "SUCI PLMN: {}{}{}-{}{}{}",
                                    mcc1, mcc2, mcc3, mnc1, mnc2,
                                    if mnc3 == 0xf { "".to_string() } else { mnc3.to_string() }
                                );
                            }
                        }
                    }
                }

                // Now send Registration Accept
                log::info!(
                    "Sending Registration Accept: amf_ue_ngap_id={}, ran_ue_ngap_id={}",
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id
                );

                // Build a simple Registration Accept NAS message
                // Format: EPD (0x7E) + Security Header (0x00) + Message Type (0x42) + Registration result
                let registration_accept = vec![
                    0x7e,       // EPD: 5GMM
                    0x00,       // Security header: Plain NAS
                    0x42,       // Message type: Registration Accept
                    0x01,       // Registration result length
                    0x01,       // Registration result: 3GPP access (0x01)
                ];

                // Build Downlink NAS Transport
                let dl_nas_transport = match crate::ngap_asn1::build_downlink_nas_transport_asn1(
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &registration_accept,
                ) {
                    Some(bytes) => bytes,
                    None => {
                        log::error!("Failed to build Downlink NAS Transport for Registration Accept");
                        return Ok(());
                    }
                };

                log::info!(
                    "Sending Registration Accept via Downlink NAS Transport: {} bytes to association {}",
                    dl_nas_transport.len(),
                    association_id
                );

                // Send to gNB
                self.send_to_association(association_id, &dl_nas_transport).await?;
                log::info!("Registration Accept sent successfully!");
            }
        }

        // Forward to event handler
        if let Some(session) = self.sessions.read().await.get(&association_id) {
            let event = AmfEvent::ngap_message(session.id, data.to_vec());
            let _ = self.event_tx.send(event).await;
        }

        Ok(())
    }

    /// Send message to a gNB by association ID
    /// NOTE: This method requires &mut self to access the SCTP server
    async fn send_to_association(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::debug!("Sending {} bytes to association {}", data.len(), association_id);

        // Use stream 0 for NGAP signaling
        self.sctp_server.send(association_id, 0, data).await
            .map_err(|e| anyhow::anyhow!("SCTP send error: {}", e))
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
        Err(anyhow::anyhow!("gNB {} not found", gnb_id))
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
            .map_err(|e| anyhow::anyhow!("SCTP send error: {}", e))
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
        format!("{}:{}", DEFAULT_NGAP_ADDR, OGS_NGAP_SCTP_PORT)
            .parse()
            .unwrap()
    });

    let handle = NgapServerHandle::new(addr, amf_context, event_tx).await?;
    let local_addr = handle.local_addr().await;

    let _ = NGAP_SERVER.set(handle);

    log::info!("NGAP path opened on {} (sctp-proto)", local_addr);
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
