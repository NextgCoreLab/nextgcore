//! UPF PFCP Path Management
//!
//! Port of src/upf/pfcp-path.c - PFCP path management for UPF

use crate::n4_build::{
    build_association_setup_response, build_heartbeat_response,
    build_session_deletion_response, build_session_establishment_response,
    build_session_modification_response, build_session_report_request,
    parse_create_far, parse_create_pdr, pfcp_ie, pfcp_type, CreatedPdr, FSeid, FTeid, NodeId,
    ParsedFSeid, ParsedIe, ParsedPfcpHeader, PfcpCause, UserPlaneReport,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ============================================================================
// PFCP Header
// ============================================================================

/// PFCP message header
#[derive(Debug, Clone, Default)]
pub struct PfcpHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: u16,
    pub seid: u64,
    pub sequence_number: u32,
}

impl PfcpHeader {
    /// Create a new PFCP header
    pub fn new(msg_type: u8, seid: u64, seq: u32) -> Self {
        Self {
            version: 1,
            msg_type,
            length: 0,
            seid,
            sequence_number: seq,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, payload_len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        let flags = (self.version << 5) | 0x01; // SEID present
        buf.push(flags);
        buf.push(self.msg_type);
        let total_len = (12 + payload_len) as u16; // header after length + payload
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&self.seid.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes()[1..4]); // 3 bytes
        buf.push(0); // spare
        buf
    }
}

// ============================================================================
// PFCP Transaction
// ============================================================================

/// PFCP transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XactState {
    Initial,
    Pending,
    Complete,
    Timeout,
}

/// PFCP transaction
#[derive(Debug, Clone)]
pub struct PfcpXact {
    pub id: u64,
    pub sequence_number: u32,
    pub msg_type: u8,
    pub state: XactState,
    pub local: bool,
    pub remote_addr: Option<SocketAddr>,
    pub seid: u64,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

impl PfcpXact {
    /// Create a new local transaction
    pub fn local_create(seq: u32, seid: u64) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: true,
            remote_addr: None,
            seid,
            request: None,
            response: None,
        }
    }

    /// Create a new remote transaction
    pub fn remote_create(seq: u32, seid: u64, remote_addr: SocketAddr) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: false,
            remote_addr: Some(remote_addr),
            seid,
            request: None,
            response: None,
        }
    }

    /// Update transaction with TX message
    pub fn update_tx(&mut self, header: &PfcpHeader, payload: Vec<u8>) {
        self.msg_type = header.msg_type;
        let mut msg = header.encode(payload.len());
        msg.extend(payload);
        if self.local {
            self.request = Some(msg);
        } else {
            self.response = Some(msg);
        }
        self.state = XactState::Pending;
    }

    /// Commit transaction (send message)
    pub fn commit(&mut self) -> Result<Vec<u8>, &'static str> {
        self.state = XactState::Complete;
        if self.local {
            self.request.clone().ok_or("No request to send")
        } else {
            self.response.clone().ok_or("No response to send")
        }
    }
}

// ============================================================================
// PFCP Node
// ============================================================================

/// PFCP peer node
#[derive(Debug, Clone)]
pub struct PfcpNode {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub recovery_time_stamp: u32,
    pub associated: bool,
    pub restoration_required: bool,
}

impl Default for PfcpNode {
    fn default() -> Self {
        Self {
            node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8805),
            recovery_time_stamp: 0,
            associated: false,
            restoration_required: false,
        }
    }
}

// ============================================================================
// PFCP Path Context
// ============================================================================

/// PFCP path context for UPF
#[derive(Debug, Default)]
pub struct PfcpPathContext {
    pub local_node_id: NodeId,
    pub local_addr: Option<SocketAddr>,
    pub recovery_time_stamp: u32,
    pub peer_nodes: HashMap<String, PfcpNode>,
    pub next_sequence: u32,
    pub transactions: HashMap<u32, PfcpXact>,
}

impl PfcpPathContext {
    /// Create a new PFCP path context
    pub fn new() -> Self {
        Self {
            local_node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            local_addr: None,
            recovery_time_stamp: 0,
            peer_nodes: HashMap::new(),
            next_sequence: 1,
            transactions: HashMap::new(),
        }
    }

    /// Get next sequence number
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence == 0 {
            self.next_sequence = 1;
        }
        seq
    }

    /// Create a local transaction
    pub fn create_local_xact(&mut self, seid: u64) -> u32 {
        let seq = self.next_seq();
        let xact = PfcpXact::local_create(seq, seid);
        self.transactions.insert(seq, xact);
        seq
    }

    /// Find transaction by sequence number
    pub fn find_xact(&mut self, seq: u32) -> Option<&mut PfcpXact> {
        self.transactions.get_mut(&seq)
    }

    /// Remove transaction
    pub fn remove_xact(&mut self, seq: u32) -> Option<PfcpXact> {
        self.transactions.remove(&seq)
    }
}

// ============================================================================
// PFCP Send Functions
// ============================================================================

/// Send Session Establishment Response
/// Port of upf_pfcp_send_session_establishment_response
pub fn send_session_establishment_response(
    ctx: &mut PfcpPathContext,
    xact: &mut PfcpXact,
    upf_n4_seid: u64,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let f_seid = FSeid {
        seid: upf_n4_seid,
        ipv4: match &ctx.local_node_id {
            NodeId::Ipv4(addr) => Some(*addr),
            _ => None,
        },
        ipv6: match &ctx.local_node_id {
            NodeId::Ipv6(addr) => Some(*addr),
            _ => None,
        },
    };

    let payload = build_session_establishment_response(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        upf_n4_seid,
        &ctx.local_node_id,
        &f_seid,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Modification Response
/// Port of upf_pfcp_send_session_modification_response
pub fn send_session_modification_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_modification_response(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Deletion Response
/// Port of upf_pfcp_send_session_deletion_response
pub fn send_session_deletion_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    usage_reports: &[crate::n4_build::UsageReport],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_deletion_response(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        usage_reports,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Report Request
/// Port of upf_pfcp_send_session_report_request
pub fn send_session_report_request(
    ctx: &mut PfcpPathContext,
    smf_n4_seid: u64,
    report: &UserPlaneReport,
) -> Result<(u32, Vec<u8>), &'static str> {
    let seq = ctx.create_local_xact(smf_n4_seid);
    
    let payload = build_session_report_request(
        crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST,
        report,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST,
        smf_n4_seid,
        seq,
    );

    if let Some(xact) = ctx.find_xact(seq) {
        xact.update_tx(&header, payload);
        let msg = xact.commit()?;
        Ok((seq, msg))
    } else {
        Err("Transaction not found")
    }
}

// ============================================================================
// PFCP Open/Close
// ============================================================================

/// Open PFCP path (initialize)
/// Port of upf_pfcp_open
pub fn pfcp_open(ctx: &mut PfcpPathContext, local_addr: SocketAddr) -> Result<(), &'static str> {
    ctx.local_addr = Some(local_addr);
    ctx.local_node_id = match local_addr {
        SocketAddr::V4(addr) => NodeId::Ipv4(*addr.ip()),
        SocketAddr::V6(addr) => NodeId::Ipv6(*addr.ip()),
    };
    ctx.recovery_time_stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    log::info!("PFCP path opened on {local_addr}");
    Ok(())
}

/// Close PFCP path (cleanup)
/// Port of upf_pfcp_close
pub fn pfcp_close(ctx: &mut PfcpPathContext) {
    ctx.peer_nodes.clear();
    ctx.transactions.clear();
    ctx.local_addr = None;
    log::info!("PFCP path closed");
}

// ============================================================================
// PFCP Session Event (for data plane notification)
// ============================================================================

/// Event sent to data plane when PFCP session is created/modified/deleted
#[derive(Debug, Clone)]
pub enum PfcpSessionEvent {
    /// Session established - create forwarding rules
    SessionEstablished {
        upf_seid: u64,
        smf_seid: u64,
        /// UE IPv4 address assigned
        ue_ipv4: Option<Ipv4Addr>,
        /// Uplink TEID (UPF receives from gNB)
        ul_teid: u32,
        /// Downlink TEID (UPF sends to gNB)
        dl_teid: u32,
        /// gNB address for downlink
        gnb_addr: Option<Ipv4Addr>,
    },
    /// Session modified - update forwarding rules
    SessionModified {
        upf_seid: u64,
        /// Updated downlink TEID
        dl_teid: Option<u32>,
        /// Updated gNB address
        gnb_addr: Option<Ipv4Addr>,
    },
    /// Session deleted - remove forwarding rules
    SessionDeleted {
        upf_seid: u64,
        ue_ipv4: Option<Ipv4Addr>,
    },
}

// ============================================================================
// Async PFCP Server
// ============================================================================

/// Async PFCP server for handling SMF requests
pub struct PfcpServer {
    socket: Arc<UdpSocket>,
    _local_addr: SocketAddr,
    local_node_id: NodeId,
    recovery_time_stamp: u32,
    next_seid: AtomicU64,
    next_teid: AtomicU32,
    shutdown: Arc<AtomicBool>,
    /// Channel to send session events to data plane
    session_tx: mpsc::Sender<PfcpSessionEvent>,
    /// Active sessions: UPF SEID -> SessionInfo
    sessions: tokio::sync::RwLock<HashMap<u64, PfcpSessionInfo>>,
}

/// PFCP session information stored in server
#[derive(Debug, Clone)]
pub struct PfcpSessionInfo {
    pub upf_seid: u64,
    pub smf_seid: u64,
    pub smf_addr: SocketAddr,
    pub ue_ipv4: Option<Ipv4Addr>,
    pub ul_teid: u32,
    pub dl_teid: u32,
    pub gnb_addr: Option<Ipv4Addr>,
}

impl PfcpServer {
    /// Create a new PFCP server
    pub async fn new(
        local_addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        session_tx: mpsc::Sender<PfcpSessionEvent>,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(local_addr).await?;
        log::info!("PFCP server bound to {local_addr}");

        let local_node_id = match local_addr {
            SocketAddr::V4(addr) => NodeId::Ipv4(*addr.ip()),
            SocketAddr::V6(addr) => NodeId::Ipv6(*addr.ip()),
        };

        let recovery_time_stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Ok(Self {
            socket: Arc::new(socket),
            _local_addr: local_addr,
            local_node_id,
            recovery_time_stamp,
            next_seid: AtomicU64::new(1),
            next_teid: AtomicU32::new(0x10000), // Start TEIDs from 0x10000
            shutdown,
            session_tx,
            sessions: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Allocate a new SEID
    fn alloc_seid(&self) -> u64 {
        self.next_seid.fetch_add(1, Ordering::SeqCst)
    }

    /// Allocate a new TEID
    fn alloc_teid(&self) -> u32 {
        self.next_teid.fetch_add(1, Ordering::SeqCst)
    }

    /// Run the PFCP server main loop
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let mut buf = vec![0u8; 65536];
        log::info!("PFCP server starting main loop");

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                log::info!("PFCP server shutting down");
                break;
            }

            // Use timeout to check shutdown periodically
            let recv_result = tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                self.socket.recv_from(&mut buf),
            )
            .await;

            match recv_result {
                Ok(Ok((len, src_addr))) => {
                    let data = &buf[..len];
                    log::debug!("PFCP received {len} bytes from {src_addr}");

                    if let Err(e) = self.handle_message(data, src_addr).await {
                        log::error!("PFCP message handling error: {e}");
                    }
                }
                Ok(Err(e)) => {
                    log::error!("PFCP socket error: {e}");
                }
                Err(_) => {
                    // Timeout - continue loop
                }
            }
        }

        Ok(())
    }

    /// Handle incoming PFCP message
    async fn handle_message(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), String> {
        let (header, payload) = ParsedPfcpHeader::parse(data).map_err(|e| e.to_string())?;

        log::debug!(
            "PFCP message: type={}, seq={}, seid={:#x}",
            header.msg_type,
            header.sequence_number,
            header.seid
        );

        match header.msg_type {
            pfcp_type::HEARTBEAT_REQUEST => {
                self.handle_heartbeat_request(&header, src_addr).await?;
            }
            pfcp_type::ASSOCIATION_SETUP_REQUEST => {
                self.handle_association_setup_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_ESTABLISHMENT_REQUEST => {
                self.handle_session_establishment_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_MODIFICATION_REQUEST => {
                self.handle_session_modification_request(&header, payload, src_addr)
                    .await?;
            }
            pfcp_type::SESSION_DELETION_REQUEST => {
                self.handle_session_deletion_request(&header, payload, src_addr)
                    .await?;
            }
            _ => {
                log::warn!("Unhandled PFCP message type: {}", header.msg_type);
            }
        }

        Ok(())
    }

    /// Handle Heartbeat Request
    async fn handle_heartbeat_request(
        &self,
        header: &ParsedPfcpHeader,
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::debug!("Handling Heartbeat Request from {src_addr}");

        let payload = build_heartbeat_response(self.recovery_time_stamp);
        let response = self.build_response(
            pfcp_type::HEARTBEAT_RESPONSE,
            0, // No SEID for heartbeat
            header.sequence_number,
            &payload,
            false, // No SEID in header
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        log::debug!("Sent Heartbeat Response to {src_addr}");
        Ok(())
    }

    /// Handle Association Setup Request
    async fn handle_association_setup_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Association Setup Request from {src_addr}");

        // Parse Node ID from request
        let ies = ParsedIe::parse_all(payload);
        if let Some(ie) = ParsedIe::find_ie(&ies, pfcp_ie::NODE_ID) {
            log::debug!("SMF Node ID: {:?}", ie.value);
        }

        let resp_payload = build_association_setup_response(
            &self.local_node_id,
            self.recovery_time_stamp,
            PfcpCause::RequestAccepted,
        );

        let response = self.build_response(
            pfcp_type::ASSOCIATION_SETUP_RESPONSE,
            0,
            header.sequence_number,
            &resp_payload,
            false,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        log::info!("PFCP Association established with {src_addr}");
        Ok(())
    }

    /// Handle Session Establishment Request
    async fn handle_session_establishment_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        log::info!("Handling Session Establishment Request from {src_addr}");

        let ies = ParsedIe::parse_all(payload);

        // Parse CP F-SEID (SMF's SEID)
        let smf_seid = if let Some(ie) = ParsedIe::find_ie(&ies, pfcp_ie::F_SEID) {
            let f_seid = ParsedFSeid::parse(&ie.value).map_err(|e| e.to_string())?;
            log::debug!("SMF F-SEID: {:#x}", f_seid.seid);
            f_seid.seid
        } else {
            return Err("Missing CP F-SEID".to_string());
        };

        // Allocate UPF SEID
        let upf_seid = self.alloc_seid();
        log::debug!("Allocated UPF SEID: {upf_seid:#x}");

        // Parse Create PDRs
        let mut ue_ipv4: Option<Ipv4Addr> = None;
        let mut ul_teid: u32 = 0;
        let mut created_pdrs = Vec::new();

        for pdr_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_PDR) {
            match parse_create_pdr(&pdr_ie.value) {
                Ok(pdr) => {
                    log::debug!(
                        "PDR {}: src_if={}, precedence={}",
                        pdr.pdr_id,
                        pdr.pdi.source_interface,
                        pdr.precedence
                    );

                    // Check if this PDR needs a local F-TEID (uplink PDR)
                    let local_f_teid = if let Some(ref fteid) = pdr.pdi.local_f_teid {
                        if fteid.ch {
                            // CHOOSE flag - allocate TEID
                            ul_teid = self.alloc_teid();
                            log::debug!("Allocated uplink TEID: {ul_teid:#x}");
                            Some(FTeid {
                                teid: ul_teid,
                                ipv4: match &self.local_node_id {
                                    NodeId::Ipv4(addr) => Some(*addr),
                                    _ => None,
                                },
                                ipv6: None,
                                choose: false,
                                choose_id: None,
                            })
                        } else {
                            ul_teid = fteid.teid;
                            None
                        }
                    } else {
                        None
                    };

                    // Extract UE IP address
                    if let Some(ref ue_ip) = pdr.pdi.ue_ip_address {
                        if let Some(addr) = ue_ip.ipv4 {
                            ue_ipv4 = Some(addr);
                            log::debug!("UE IPv4: {addr}");
                        }
                    }

                    created_pdrs.push(CreatedPdr {
                        pdr_id: pdr.pdr_id,
                        local_f_teid,
                        ue_ip_address: None,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to parse PDR: {e}");
                }
            }
        }

        // Parse Create FARs to get downlink info
        let mut dl_teid: u32 = 0;
        let mut gnb_addr: Option<Ipv4Addr> = None;

        for far_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::CREATE_FAR) {
            match parse_create_far(&far_ie.value) {
                Ok(far) => {
                    log::debug!("FAR {}: apply_action={:#x}", far.far_id, far.apply_action);

                    if let Some(ref fp) = far.forwarding_parameters {
                        if let Some(ref ohc) = fp.outer_header_creation {
                            dl_teid = ohc.teid;
                            gnb_addr = ohc.ipv4;
                            log::debug!("Downlink: TEID={dl_teid:#x}, gNB={gnb_addr:?}");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse FAR: {e}");
                }
            }
        }

        // Build response
        let f_seid = FSeid {
            seid: upf_seid,
            ipv4: match &self.local_node_id {
                NodeId::Ipv4(addr) => Some(*addr),
                _ => None,
            },
            ipv6: None,
        };

        let resp_payload = build_session_establishment_response(
            pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            upf_seid,
            &self.local_node_id,
            &f_seid,
            &created_pdrs,
        );

        let response = self.build_response(
            pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Store session info
        let session_info = PfcpSessionInfo {
            upf_seid,
            smf_seid,
            smf_addr: src_addr,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(upf_seid, session_info.clone());
        }

        // Notify data plane
        let event = PfcpSessionEvent::SessionEstablished {
            upf_seid,
            smf_seid,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
        };

        if let Err(e) = self.session_tx.send(event).await {
            log::error!("Failed to send session event: {e}");
        }

        log::info!(
            "Session established: UPF_SEID={upf_seid:#x}, SMF_SEID={smf_seid:#x}, UE_IP={ue_ipv4:?}, UL_TEID={ul_teid:#x}, DL_TEID={dl_teid:#x}"
        );

        Ok(())
    }

    /// Handle Session Modification Request
    async fn handle_session_modification_request(
        &self,
        header: &ParsedPfcpHeader,
        payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        let upf_seid = header.seid;
        log::info!(
            "Handling Session Modification Request for SEID {upf_seid:#x}"
        );

        let ies = ParsedIe::parse_all(payload);

        // Parse Update FARs
        let mut updated_dl_teid: Option<u32> = None;
        let mut updated_gnb_addr: Option<Ipv4Addr> = None;

        // Update FAR IE type = 10
        for far_ie in ParsedIe::find_all_ies(&ies, pfcp_ie::UPDATE_FAR) {
            match parse_create_far(&far_ie.value) {
                Ok(far) => {
                    log::debug!("Update FAR {}: apply_action={:#x}", far.far_id, far.apply_action);
                    if let Some(ref fp) = far.forwarding_parameters {
                        if let Some(ref ohc) = fp.outer_header_creation {
                            updated_dl_teid = Some(ohc.teid);
                            updated_gnb_addr = ohc.ipv4;
                            log::debug!(
                                "Updated downlink: TEID={:#x}, gNB={:?}",
                                ohc.teid,
                                ohc.ipv4
                            );
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse Update FAR: {e}");
                }
            }
        }

        // Update session info
        let smf_seid = {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&upf_seid) {
                if let Some(teid) = updated_dl_teid {
                    session.dl_teid = teid;
                }
                if let Some(addr) = updated_gnb_addr {
                    session.gnb_addr = Some(addr);
                }
                session.smf_seid
            } else {
                return Err(format!("Session {upf_seid:#x} not found"));
            }
        };

        // Build response
        let resp_payload = build_session_modification_response(
            pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[], // No created PDRs for modification
        );

        let response = self.build_response(
            pfcp_type::SESSION_MODIFICATION_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Notify data plane
        if updated_dl_teid.is_some() || updated_gnb_addr.is_some() {
            let event = PfcpSessionEvent::SessionModified {
                upf_seid,
                dl_teid: updated_dl_teid,
                gnb_addr: updated_gnb_addr,
            };

            if let Err(e) = self.session_tx.send(event).await {
                log::error!("Failed to send session event: {e}");
            }
        }

        log::info!("Session {upf_seid:#x} modified");
        Ok(())
    }

    /// Handle Session Deletion Request
    async fn handle_session_deletion_request(
        &self,
        header: &ParsedPfcpHeader,
        _payload: &[u8],
        src_addr: SocketAddr,
    ) -> Result<(), String> {
        let upf_seid = header.seid;
        log::info!("Handling Session Deletion Request for SEID {upf_seid:#x}");

        // Remove session
        let session_info = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&upf_seid)
        };

        let smf_seid = session_info
            .as_ref()
            .map(|s| s.smf_seid)
            .unwrap_or(0);
        let ue_ipv4 = session_info.as_ref().and_then(|s| s.ue_ipv4);

        // Build response (no usage reports for now)
        let resp_payload = build_session_deletion_response(
            pfcp_type::SESSION_DELETION_RESPONSE,
            &[], // Usage reports would go here
        );

        let response = self.build_response(
            pfcp_type::SESSION_DELETION_RESPONSE,
            smf_seid,
            header.sequence_number,
            &resp_payload,
            true,
        );

        self.socket
            .send_to(&response, src_addr)
            .await
            .map_err(|e| format!("Send error: {e}"))?;

        // Notify data plane
        let event = PfcpSessionEvent::SessionDeleted { upf_seid, ue_ipv4 };

        if let Err(e) = self.session_tx.send(event).await {
            log::error!("Failed to send session event: {e}");
        }

        log::info!("Session {upf_seid:#x} deleted");
        Ok(())
    }

    /// Build PFCP response message
    fn build_response(
        &self,
        msg_type: u8,
        seid: u64,
        seq: u32,
        payload: &[u8],
        seid_present: bool,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(16 + payload.len());

        // Flags: version=1, SEID present flag
        let flags = if seid_present { 0x21 } else { 0x20 };
        response.push(flags);
        response.push(msg_type);

        // Length (will be calculated)
        let length = if seid_present {
            12 + payload.len() as u16
        } else {
            4 + payload.len() as u16
        };
        response.extend_from_slice(&length.to_be_bytes());

        // SEID if present
        if seid_present {
            response.extend_from_slice(&seid.to_be_bytes());
        }

        // Sequence number (3 bytes) + spare
        response.extend_from_slice(&seq.to_be_bytes()[1..4]);
        response.push(0); // spare

        // Payload
        response.extend_from_slice(payload);

        response
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_pfcp_header_new() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.msg_type, 51);
        assert_eq!(header.seid, 0x1234);
        assert_eq!(header.sequence_number, 1);
    }

    #[test]
    fn test_pfcp_header_encode() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        let encoded = header.encode(10);
        assert_eq!(encoded[0], 0x21); // version=1, SEID present
        assert_eq!(encoded[1], 51);   // msg_type
        // length = 12 + 10 = 22
        assert_eq!(&encoded[2..4], &22u16.to_be_bytes());
    }

    #[test]
    fn test_pfcp_xact_local_create() {
        let xact = PfcpXact::local_create(1, 0x1234);
        assert_eq!(xact.sequence_number, 1);
        assert_eq!(xact.seid, 0x1234);
        assert!(xact.local);
        assert_eq!(xact.state, XactState::Initial);
    }

    #[test]
    fn test_pfcp_xact_remote_create() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let xact = PfcpXact::remote_create(1, 0x1234, addr);
        assert!(!xact.local);
        assert_eq!(xact.remote_addr, Some(addr));
    }

    #[test]
    fn test_pfcp_xact_update_tx_and_commit() {
        let mut xact = PfcpXact::local_create(1, 0x1234);
        let header = PfcpHeader::new(56, 0x1234, 1);
        xact.update_tx(&header, vec![1, 2, 3]);
        assert_eq!(xact.state, XactState::Pending);
        
        let msg = xact.commit().unwrap();
        assert!(!msg.is_empty());
        assert_eq!(xact.state, XactState::Complete);
    }

    #[test]
    fn test_pfcp_path_context_new() {
        let ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_sequence, 1);
        assert!(ctx.peer_nodes.is_empty());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_path_context_next_seq() {
        let mut ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_seq(), 1);
        assert_eq!(ctx.next_seq(), 2);
        assert_eq!(ctx.next_seq(), 3);
    }

    #[test]
    fn test_pfcp_path_context_create_local_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        assert_eq!(seq, 1);
        assert!(ctx.transactions.contains_key(&1));
    }

    #[test]
    fn test_pfcp_path_context_find_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.find_xact(seq);
        assert!(xact.is_some());
        assert_eq!(xact.unwrap().seid, 0x1234);
    }

    #[test]
    fn test_pfcp_path_context_remove_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.remove_xact(seq);
        assert!(xact.is_some());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_open() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let result = pfcp_open(&mut ctx, addr);
        assert!(result.is_ok());
        assert_eq!(ctx.local_addr, Some(addr));
        assert!(ctx.recovery_time_stamp > 0);
    }

    #[test]
    fn test_pfcp_close() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        ctx.create_local_xact(0x1234);
        
        pfcp_close(&mut ctx);
        
        assert!(ctx.local_addr.is_none());
        assert!(ctx.transactions.is_empty());
        assert!(ctx.peer_nodes.is_empty());
    }

    #[test]
    fn test_send_session_establishment_response() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        
        let seq = ctx.create_local_xact(0x1234);
        // Set up the xact first
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let created_pdrs = vec![
            CreatedPdr {
                pdr_id: 1,
                local_f_teid: None,
                ue_ip_address: None,
            },
        ];
        
        // Now get xact again and call the function
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let node_id = ctx.local_node_id.clone();
        
        let f_seid = FSeid {
            seid: 0x5678,
            ipv4: match &node_id {
                NodeId::Ipv4(addr) => Some(*addr),
                _ => None,
            },
            ipv6: None,
        };
        
        let payload = build_session_establishment_response(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x5678,
            &node_id,
            &f_seid,
            &created_pdrs,
        );
        
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_modification_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_modification_response(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_deletion_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_deletion_response(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_report_request() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        
        let report = UserPlaneReport::default();
        let result = send_session_report_request(&mut ctx, 0x1234, &report);
        
        assert!(result.is_ok());
        let (seq, msg) = result.unwrap();
        assert_eq!(seq, 1);
        assert!(!msg.is_empty());
    }
}
