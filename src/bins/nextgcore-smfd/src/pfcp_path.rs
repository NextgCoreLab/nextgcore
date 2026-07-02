//! PFCP Path Management — the SMF's N4 transaction engine (TS 29.244)
//!
//! Replaces the former dead parallel-builder module: all PFCP messages now
//! leave the SMF through exactly one code path. Session message bodies are
//! built by `n4_build`; node-level messages (Heartbeat, Association
//! Setup/Release) use the nextgcore-pfcp library codec directly.
//!
//! Responsibilities:
//! - request/response transaction matching by sequence number
//! - T1 retransmission up to N1 attempts, exhaustion = abnormal action
//!   (TS 29.244 7.2.1; configured in `timer::SmfTimerConfigs`)
//! - PFCP Association Setup / Release with the UPF
//! - Heartbeat in both directions with Recovery Time Stamp staleness
//!   detection (peer restart ⇒ local session state flushed)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use nextgcore_pfcp::message::{
    build_message, AssociationReleaseRequest, AssociationSetupRequest, AssociationSetupResponse,
    HeartbeatRequest, HeartbeatResponse, PfcpMessage,
};
use nextgcore_pfcp::types::{CpFunctionFeatures, NodeId, UpFunctionFeatures};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::context::smf_self;
use crate::timer::SmfTimerConfigs;

// ============================================================================
// PFCP Message Types (TS 29.244 Table 7.3-1)
// ============================================================================

/// PFCP Message types
pub mod pfcp_message_type {
    pub const HEARTBEAT_REQUEST: u8 = 1;
    pub const HEARTBEAT_RESPONSE: u8 = 2;
    pub const PFD_MANAGEMENT_REQUEST: u8 = 3;
    pub const PFD_MANAGEMENT_RESPONSE: u8 = 4;
    pub const ASSOCIATION_SETUP_REQUEST: u8 = 5;
    pub const ASSOCIATION_SETUP_RESPONSE: u8 = 6;
    pub const ASSOCIATION_UPDATE_REQUEST: u8 = 7;
    pub const ASSOCIATION_UPDATE_RESPONSE: u8 = 8;
    pub const ASSOCIATION_RELEASE_REQUEST: u8 = 9;
    pub const ASSOCIATION_RELEASE_RESPONSE: u8 = 10;
    pub const VERSION_NOT_SUPPORTED_RESPONSE: u8 = 11;
    pub const NODE_REPORT_REQUEST: u8 = 12;
    pub const NODE_REPORT_RESPONSE: u8 = 13;
    pub const SESSION_SET_DELETION_REQUEST: u8 = 14;
    pub const SESSION_SET_DELETION_RESPONSE: u8 = 15;
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_ESTABLISHMENT_RESPONSE: u8 = 51;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_MODIFICATION_RESPONSE: u8 = 53;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_DELETION_RESPONSE: u8 = 55;
    pub const SESSION_REPORT_REQUEST: u8 = 56;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

/// Is this message type a response (solicited by one of our requests)?
fn is_response_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        2 | 4 | 6 | 8 | 10 | 11 | 13 | 15 | 51 | 53 | 55 | 57
    )
}

// ============================================================================
// Wire helpers
// ============================================================================

/// Minimal decoded view of a PFCP datagram header
#[derive(Debug, Clone, Copy)]
pub struct WireHeader {
    pub version: u8,
    pub msg_type: u8,
    pub seid_present: bool,
    pub seid: u64,
    pub sequence_number: u32,
    /// Offset of the IE payload within the datagram
    pub body_offset: usize,
}

/// Parse the PFCP header of a raw datagram (TS 29.244 7.2.2).
pub fn parse_wire_header(pkt: &[u8]) -> Option<WireHeader> {
    if pkt.len() < 8 {
        return None;
    }
    let version = pkt[0] >> 5;
    let seid_present = pkt[0] & 0x01 != 0;
    let msg_type = pkt[1];
    if seid_present {
        if pkt.len() < 16 {
            return None;
        }
        let seid = u64::from_be_bytes(pkt[4..12].try_into().ok()?);
        let seq = u32::from_be_bytes([0, pkt[12], pkt[13], pkt[14]]);
        Some(WireHeader {
            version,
            msg_type,
            seid_present,
            seid,
            sequence_number: seq,
            body_offset: 16,
        })
    } else {
        let seq = u32::from_be_bytes([0, pkt[4], pkt[5], pkt[6]]);
        Some(WireHeader {
            version,
            msg_type,
            seid_present,
            seid: 0,
            sequence_number: seq,
            body_offset: 8,
        })
    }
}

/// Encode a complete PFCP datagram from a message body built by `n4_build`.
pub fn encode_wire_message(msg_type: u8, seid: Option<u64>, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16 + body.len());
    match seid {
        Some(seid) => {
            pkt.push(0x21); // version=1, S=1
            pkt.push(msg_type);
            pkt.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&seid.to_be_bytes());
        }
        None => {
            pkt.push(0x20); // version=1, S=0
            pkt.push(msg_type);
            pkt.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        }
    }
    pkt.extend_from_slice(&seq.to_be_bytes()[1..4]);
    pkt.push(0); // spare
    pkt.extend_from_slice(body);
    pkt
}

/// Scan a PFCP message body for the Cause IE (type 19) and return its value.
pub fn parse_cause(body: &[u8]) -> Option<u8> {
    find_ie(body, 19).and_then(|v| v.first().copied())
}

/// Scan a flat TLV body for the first IE of the given type.
pub fn find_ie(body: &[u8], ie_type: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let t = u16::from_be_bytes([body[off], body[off + 1]]);
        let l = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let start = off + 4;
        let end = start + l;
        if end > body.len() {
            return None;
        }
        if t == ie_type {
            return Some(&body[start..end]);
        }
        off = end;
    }
    None
}

/// PFCP cause values used on the N4 reply paths (TS 29.244 8.2.1)
pub mod pfcp_cause {
    pub const REQUEST_ACCEPTED: u8 = 1;
    pub const REQUEST_REJECTED: u8 = 64;
    pub const SESSION_CONTEXT_NOT_FOUND: u8 = 65;
    pub const MANDATORY_IE_MISSING: u8 = 66;
    pub const NO_ESTABLISHED_PFCP_ASSOCIATION: u8 = 72;
}

/// Human-readable PFCP cause name for error reporting
pub fn cause_name(cause: u8) -> &'static str {
    match cause {
        1 => "Request accepted",
        64 => "Request rejected",
        65 => "Session context not found",
        66 => "Mandatory IE missing",
        67 => "Conditional IE missing",
        68 => "Invalid length",
        69 => "Mandatory IE incorrect",
        70 => "Invalid Forwarding Policy",
        71 => "Invalid F-TEID allocation option",
        72 => "No established PFCP Association",
        73 => "Rule creation/modification failure",
        74 => "PFCP entity in congestion",
        75 => "No resources available",
        76 => "Service not supported",
        77 => "System failure",
        78 => "Redirection requested",
        _ => "Unknown cause",
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Failure modes of an N4 transaction
#[derive(Debug)]
pub enum PfcpRequestError {
    /// No response after N1 retransmissions — peer unreachable
    Timeout { attempts: u32 },
    /// Peer answered with a non-accepted cause
    Rejected { cause: u8 },
    /// Local I/O or state error
    Local(String),
    /// No PFCP association established with the peer
    NotAssociated,
}

impl std::fmt::Display for PfcpRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { attempts } => {
                write!(f, "no PFCP response after {attempts} attempts")
            }
            Self::Rejected { cause } => {
                write!(
                    f,
                    "PFCP request rejected: cause {cause} ({})",
                    cause_name(*cause)
                )
            }
            Self::Local(e) => write!(f, "local PFCP error: {e}"),
            Self::NotAssociated => write!(f, "no established PFCP association"),
        }
    }
}

impl std::error::Error for PfcpRequestError {}

// ============================================================================
// Association state
// ============================================================================

/// State of the N4 association with the UPF
#[derive(Debug, Clone, Default)]
pub struct AssociationState {
    pub associated: bool,
    /// Recovery Time Stamp the peer reported at association / heartbeat
    pub peer_recovery_time_stamp: Option<u32>,
    /// UP Function Features advertised by the UPF
    pub up_function_features: Option<UpFunctionFeatures>,
}

// ============================================================================
// PFCP client (transaction engine)
// ============================================================================

/// The SMF's PFCP endpoint: one shared socket for requests and responses,
/// transactions matched on sequence number.
pub struct PfcpClient {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    node_ip: [u8; 4],
    /// Our own Recovery Time Stamp (seconds since the epoch at startup)
    pub recovery_time_stamp: u32,
    pending: Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>,
    assoc: RwLock<AssociationState>,
    timers: SmfTimerConfigs,
}

static PFCP_CLIENT: OnceLock<Arc<PfcpClient>> = OnceLock::new();

/// Install the process-wide PFCP client (once, at startup).
pub fn set_global_client(client: Arc<PfcpClient>) {
    let _ = PFCP_CLIENT.set(client);
}

/// The process-wide PFCP client, if initialised.
pub fn global_client() -> Option<Arc<PfcpClient>> {
    PFCP_CLIENT.get().cloned()
}

impl PfcpClient {
    /// Create a client bound to an existing N4 socket.
    pub fn new(socket: Arc<UdpSocket>, peer: SocketAddr, node_ip: [u8; 4]) -> Self {
        let recovery_time_stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1);
        Self {
            socket,
            peer,
            node_ip,
            recovery_time_stamp,
            pending: Mutex::new(HashMap::new()),
            assoc: RwLock::new(AssociationState::default()),
            timers: SmfTimerConfigs::default(),
        }
    }

    /// The UPF endpoint this client talks to.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Our Node ID address.
    pub fn node_ip(&self) -> [u8; 4] {
        self.node_ip
    }

    /// Whether the N4 association is currently established.
    pub async fn is_associated(&self) -> bool {
        self.assoc.read().await.associated
    }

    /// Snapshot of the association state.
    pub async fn association(&self) -> AssociationState {
        self.assoc.read().await.clone()
    }

    /// T1/N1 parameters for a given request type.
    fn retransmit_params(&self, msg_type: u8) -> (Duration, u32) {
        let cfg = match msg_type {
            pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST
            | pfcp_message_type::SESSION_MODIFICATION_REQUEST => {
                &self.timers.pfcp_no_establishment_response
            }
            pfcp_message_type::SESSION_DELETION_REQUEST => &self.timers.pfcp_no_deletion_response,
            pfcp_message_type::HEARTBEAT_REQUEST => &self.timers.pfcp_no_heartbeat,
            _ => &self.timers.pfcp_association,
        };
        (cfg.duration, cfg.max_count)
    }

    /// Send a request and wait for the matching response, retransmitting on
    /// T1 expiry up to N1 times (TS 29.244 7.2.1). Returns the response
    /// message type and body.
    pub async fn request(
        &self,
        msg_type: u8,
        seid: Option<u64>,
        body: &[u8],
    ) -> Result<(u8, Vec<u8>), PfcpRequestError> {
        let seq = crate::PFCP_SEQ.fetch_add(1, Ordering::Relaxed) & 0x00FF_FFFF;
        let pkt = encode_wire_message(msg_type, seid, seq, body);
        let (t1, n1) = self.retransmit_params(msg_type);

        // attempts = first transmission + up to N1 retransmissions
        let max_attempts = n1 + 1;
        let mut attempt = 0u32;

        let result = loop {
            attempt += 1;

            // (Re-)register the response slot for this sequence number
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(seq, tx);

            if let Err(e) = self.socket.send_to(&pkt, self.peer).await {
                self.pending.lock().await.remove(&seq);
                break Err(PfcpRequestError::Local(format!("send failed: {e}")));
            }
            if attempt > 1 {
                log::warn!(
                    "PFCP T1 expired: retransmitting type={msg_type} seq={seq} \
                     (attempt {attempt}/{max_attempts})"
                );
            }

            match tokio::time::timeout(t1, rx).await {
                Ok(Ok((resp_type, resp_body))) => break Ok((resp_type, resp_body)),
                Ok(Err(_)) => break Err(PfcpRequestError::Local("response channel closed".into())),
                Err(_) => {
                    // T1 expired
                    self.pending.lock().await.remove(&seq);
                    if attempt >= max_attempts {
                        log::error!(
                            "PFCP request type={msg_type} seq={seq} exhausted \
                             {max_attempts} attempts — peer {} unreachable",
                            self.peer
                        );
                        break Err(PfcpRequestError::Timeout {
                            attempts: max_attempts,
                        });
                    }
                }
            }
        };

        // Exhaustion abnormal action: a node-level silence means the peer is
        // gone — drop the association so new sessions are refused until the
        // association is re-established.
        if matches!(result, Err(PfcpRequestError::Timeout { .. })) {
            let mut assoc = self.assoc.write().await;
            if assoc.associated {
                log::error!("Marking PFCP association with {} as DOWN", self.peer);
                assoc.associated = false;
            }
        }

        result
    }

    /// Feed an incoming datagram into the engine. Returns true when the
    /// datagram was consumed (response to a pending request, or a node-level
    /// request that was handled here).
    pub async fn on_datagram(&self, pkt: &[u8], from: SocketAddr) -> bool {
        let header = match parse_wire_header(pkt) {
            Some(h) => h,
            None => return false,
        };

        // Version check (TS 29.244 7.2.2): only v1 is supported
        if header.version != 1 {
            log::warn!("PFCP version {} from {from} not supported", header.version);
            let resp = encode_wire_message(
                pfcp_message_type::VERSION_NOT_SUPPORTED_RESPONSE,
                None,
                header.sequence_number,
                &[],
            );
            let _ = self.socket.send_to(&resp, from).await;
            return true;
        }

        let body = &pkt[header.body_offset.min(pkt.len())..];

        // Responses: complete the matching pending transaction
        if is_response_type(header.msg_type) {
            if let Some(tx) = self.pending.lock().await.remove(&header.sequence_number) {
                let _ = tx.send((header.msg_type, body.to_vec()));
                return true;
            }
            log::debug!(
                "PFCP response type={} seq={} with no pending transaction",
                header.msg_type,
                header.sequence_number
            );
            return true;
        }

        // Node-level requests handled by the engine
        match header.msg_type {
            pfcp_message_type::HEARTBEAT_REQUEST => {
                // Staleness detection on the peer's Recovery Time Stamp
                if let Some(rts) = find_ie(body, 96)
                    .filter(|v| v.len() >= 4)
                    .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                {
                    self.check_peer_restart(rts).await;
                }
                let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(
                    self.recovery_time_stamp,
                ));
                let resp = build_message(&msg, header.sequence_number, None);
                if let Err(e) = self.socket.send_to(&resp, from).await {
                    log::warn!("Failed to send Heartbeat Response: {e}");
                } else {
                    log::debug!("Heartbeat Response sent to {from}");
                }
                true
            }
            pfcp_message_type::ASSOCIATION_RELEASE_REQUEST => {
                log::warn!("PFCP Association Release Request from {from}");
                // Respond Node ID + Cause accepted via the library codec
                let msg = PfcpMessage::AssociationReleaseResponse(
                    nextgcore_pfcp::message::AssociationReleaseResponse::new(
                        NodeId::new_ipv4(self.node_ip),
                        nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                    ),
                );
                let resp = build_message(&msg, header.sequence_number, None);
                let _ = self.socket.send_to(&resp, from).await;
                self.teardown_association("association released by peer")
                    .await;
                true
            }
            _ => false, // e.g. Session Report Request — handled by main.rs
        }
    }

    /// Compare a peer Recovery Time Stamp with the stored value; a change
    /// means the UPF restarted: all sessions on it are gone (TS 23.527 4.2).
    pub async fn check_peer_restart(&self, rts: u32) {
        let restarted = {
            let assoc = self.assoc.read().await;
            matches!(assoc.peer_recovery_time_stamp, Some(stored) if stored != rts)
        };
        if restarted {
            log::error!(
                "UPF {} restarted (recovery time stamp changed to {rts})",
                self.peer
            );
            self.teardown_association("peer restarted").await;
            // Remember the new incarnation so re-association succeeds
            self.assoc.write().await.peer_recovery_time_stamp = Some(rts);
        }
    }

    /// Mark the association down and flush all PFCP session state.
    async fn teardown_association(&self, reason: &str) {
        {
            let mut assoc = self.assoc.write().await;
            assoc.associated = false;
        }
        let cleared = clear_pfcp_sessions();
        log::warn!("PFCP association torn down ({reason}); {cleared} stale sessions flushed");
    }

    /// Run the PFCP Association Setup procedure (TS 29.244 6.2.6).
    pub async fn associate(&self) -> Result<(), PfcpRequestError> {
        let mut req =
            AssociationSetupRequest::new(NodeId::new_ipv4(self.node_ip), self.recovery_time_stamp);
        // CP Function Features: none of the optional CP features (LOAD,
        // OVRL, …) are implemented, so all bits are honestly zero.
        req.cp_function_features = Some(CpFunctionFeatures::default());
        let msg = PfcpMessage::AssociationSetupRequest(req);
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);

        let (resp_type, resp_body) = self
            .request(pfcp_message_type::ASSOCIATION_SETUP_REQUEST, None, &buf)
            .await?;

        if resp_type != pfcp_message_type::ASSOCIATION_SETUP_RESPONSE {
            return Err(PfcpRequestError::Local(format!(
                "unexpected response type {resp_type} to Association Setup"
            )));
        }

        let mut body = Bytes::copy_from_slice(&resp_body);
        let resp = AssociationSetupResponse::decode(&mut body)
            .map_err(|e| PfcpRequestError::Local(format!("malformed response: {e}")))?;

        if resp.cause != nextgcore_pfcp::types::PfcpCause::RequestAccepted {
            return Err(PfcpRequestError::Rejected {
                cause: resp.cause as u8,
            });
        }

        // Restart detection against any previously stored timestamp
        self.check_peer_restart(resp.recovery_time_stamp).await;

        let mut assoc = self.assoc.write().await;
        assoc.associated = true;
        assoc.peer_recovery_time_stamp = Some(resp.recovery_time_stamp);
        assoc.up_function_features = resp.up_function_features;
        log::info!(
            "PFCP association established with {} (peer RTS={}, UP features={:?})",
            self.peer,
            resp.recovery_time_stamp,
            assoc
                .up_function_features
                .as_ref()
                .map(|f| (f.ftup, f.empu, f.bucp))
        );
        Ok(())
    }

    /// Run the PFCP Association Release procedure (TS 29.244 6.2.9).
    pub async fn release_association(&self) -> Result<(), PfcpRequestError> {
        if !self.is_associated().await {
            return Ok(());
        }
        let msg = PfcpMessage::AssociationReleaseRequest(AssociationReleaseRequest::new(
            NodeId::new_ipv4(self.node_ip),
        ));
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);

        let result = self
            .request(pfcp_message_type::ASSOCIATION_RELEASE_REQUEST, None, &buf)
            .await;

        // Whether the peer answered or not, the association is gone locally
        self.teardown_association("association release requested locally")
            .await;

        match result {
            Ok((_, body)) => match parse_cause(&body) {
                Some(pfcp_cause::REQUEST_ACCEPTED) | None => Ok(()),
                Some(cause) => Err(PfcpRequestError::Rejected { cause }),
            },
            Err(e) => Err(e),
        }
    }

    /// Send one Heartbeat Request and validate the response (TS 29.244
    /// 6.2.2). Returns Ok(true) if the peer is alive, Err on timeout.
    pub async fn heartbeat_once(&self) -> Result<bool, PfcpRequestError> {
        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(self.recovery_time_stamp));
        let mut buf = bytes::BytesMut::new();
        msg.encode_body(&mut buf);

        let (_, resp_body) = self
            .request(pfcp_message_type::HEARTBEAT_REQUEST, None, &buf)
            .await?;

        // Recovery Time Stamp staleness detection
        if let Some(rts) = find_ie(&resp_body, 96)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        {
            self.check_peer_restart(rts).await;
        } else {
            log::warn!("Heartbeat Response missing Recovery Time Stamp (mandatory IE)");
        }
        Ok(true)
    }
}

/// Flush all stored PFCP sessions (UPF restarted / association lost).
/// Returns the number of sessions removed.
pub fn clear_pfcp_sessions() -> usize {
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut sessions) = ctx.pfcp_sessions.write() {
            let n = sessions.len();
            sessions.clear();
            return n;
        }
    }
    0
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn body_with_cause(cause: u8) -> Vec<u8> {
        vec![0x00, 19, 0x00, 0x01, cause]
    }

    #[test]
    fn test_parse_wire_header_with_seid() {
        let pkt = encode_wire_message(50, Some(0x1122334455667788), 0x00ABCDEF, &[1, 2, 3]);
        let h = parse_wire_header(&pkt).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.msg_type, 50);
        assert!(h.seid_present);
        assert_eq!(h.seid, 0x1122334455667788);
        assert_eq!(h.sequence_number, 0x00ABCDEF);
        assert_eq!(&pkt[h.body_offset..], &[1, 2, 3]);
    }

    #[test]
    fn test_parse_wire_header_without_seid() {
        let pkt = encode_wire_message(1, None, 42, &[]);
        let h = parse_wire_header(&pkt).unwrap();
        assert_eq!(h.msg_type, 1);
        assert!(!h.seid_present);
        assert_eq!(h.sequence_number, 42);
        assert_eq!(h.body_offset, 8);
    }

    #[test]
    fn test_parse_cause() {
        assert_eq!(parse_cause(&body_with_cause(1)), Some(1));
        assert_eq!(parse_cause(&body_with_cause(72)), Some(72));
        assert_eq!(parse_cause(&[]), None);
        // Truncated IE must not be mis-parsed
        assert_eq!(parse_cause(&[0x00, 19, 0x00, 0x05, 1]), None);
    }

    #[test]
    fn test_is_response_type() {
        assert!(is_response_type(pfcp_message_type::HEARTBEAT_RESPONSE));
        assert!(is_response_type(
            pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE
        ));
        assert!(!is_response_type(pfcp_message_type::HEARTBEAT_REQUEST));
        assert!(!is_response_type(pfcp_message_type::SESSION_REPORT_REQUEST));
    }

    async fn make_client_with_peer() -> (Arc<PfcpClient>, UdpSocket) {
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Arc::new(PfcpClient::new(Arc::new(local), peer_addr, [127, 0, 0, 1]));

        // Pump incoming datagrams into the engine
        let c = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = c.socket.recv_from(&mut buf).await else {
                    break;
                };
                c.on_datagram(&buf[..len], from).await;
            }
        });
        (client, peer_sock)
    }

    /// Association Setup round-trip against a fake UPF answering with the
    /// library-encoded response (mandatory Node ID, Cause, Recovery TS, plus
    /// UP Function Features).
    #[tokio::test]
    async fn test_association_setup_roundtrip() {
        let (client, upf) = make_client_with_peer().await;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_SETUP_REQUEST);
            // The request must carry Node ID (60) and Recovery Time Stamp (96)
            let body = &buf[h.body_offset..len];
            assert!(find_ie(body, 60).is_some(), "Node ID mandatory");
            let node_id = find_ie(body, 60).unwrap();
            assert_eq!(node_id[0], 0, "Node ID type octet = IPv4");
            assert_eq!(&node_id[1..5], &[127, 0, 0, 1]);
            assert!(find_ie(body, 96).is_some(), "Recovery Time Stamp mandatory");

            let mut resp = AssociationSetupResponse::new(
                NodeId::new_ipv4([127, 0, 0, 4]),
                nextgcore_pfcp::types::PfcpCause::RequestAccepted,
                777,
            );
            resp.up_function_features = Some(UpFunctionFeatures {
                ftup: true,
                empu: true,
                ..Default::default()
            });
            let msg = PfcpMessage::AssociationSetupResponse(resp);
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        client.associate().await.expect("association must succeed");
        assert!(client.is_associated().await);
        let st = client.association().await;
        assert_eq!(st.peer_recovery_time_stamp, Some(777));
        assert!(st.up_function_features.unwrap().ftup);
    }

    /// A rejected Association Setup must surface the real cause value.
    #[tokio::test]
    async fn test_association_setup_rejected_cause() {
        let (client, upf) = make_client_with_peer().await;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            let resp = AssociationSetupResponse::new(
                NodeId::new_ipv4([127, 0, 0, 4]),
                nextgcore_pfcp::types::PfcpCause::NoResourcesAvailable,
                778,
            );
            let msg = PfcpMessage::AssociationSetupResponse(resp);
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        match client.associate().await {
            Err(PfcpRequestError::Rejected { cause }) => {
                assert_eq!(
                    cause,
                    nextgcore_pfcp::types::PfcpCause::NoResourcesAvailable as u8
                )
            }
            other => panic!("expected rejection, got {other:?}"),
        }
        assert!(!client.is_associated().await);
    }

    /// T1 retransmission: the fake UPF stays silent for the first two
    /// transmissions and answers the third — the transaction must succeed
    /// and exactly 3 datagrams must have hit the wire.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_t1_retransmission_then_success() {
        let (client, upf) = make_client_with_peer().await;

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut count = 0u32;
            loop {
                let (len, from) = upf.recv_from(&mut buf).await.unwrap();
                count += 1;
                if count == 3 {
                    let h = parse_wire_header(&buf[..len]).unwrap();
                    let pkt = encode_wire_message(
                        pfcp_message_type::SESSION_DELETION_RESPONSE,
                        Some(7),
                        h.sequence_number,
                        &body_with_cause(1),
                    );
                    upf.send_to(&pkt, from).await.unwrap();
                    return count;
                }
            }
        });

        let (resp_type, body) = client
            .request(pfcp_message_type::SESSION_DELETION_REQUEST, Some(7), &[])
            .await
            .expect("3rd attempt must succeed");
        assert_eq!(resp_type, pfcp_message_type::SESSION_DELETION_RESPONSE);
        assert_eq!(parse_cause(&body), Some(1));
        assert_eq!(handle.await.unwrap(), 3, "exactly 3 transmissions");
    }

    /// Retransmission exhaustion: a silent peer must produce a Timeout error
    /// after 1 + N1 attempts, and the association must be marked down.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_retransmission_exhaustion_marks_peer_down() {
        let (client, upf) = make_client_with_peer().await;
        // Pretend we were associated
        {
            let mut a = client.assoc.write().await;
            a.associated = true;
            a.peer_recovery_time_stamp = Some(1);
        }

        // Count datagrams without ever answering
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c2 = counter.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if upf.recv_from(&mut buf).await.is_err() {
                    break;
                }
                c2.fetch_add(1, Ordering::SeqCst);
            }
        });

        let start = std::time::Instant::now();
        let res = client
            .request(pfcp_message_type::SESSION_DELETION_REQUEST, Some(9), &[])
            .await;
        match res {
            Err(PfcpRequestError::Timeout { attempts }) => assert_eq!(attempts, 4),
            other => panic!("expected timeout, got {other:?}"),
        }
        // 4 attempts × T1 (3s) ≈ 12s — allow generous lower bound
        assert!(start.elapsed() >= Duration::from_secs(9));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            4,
            "1 initial + 3 retransmits"
        );
        assert!(
            !client.is_associated().await,
            "exhaustion must mark the association down"
        );
    }

    /// Heartbeat staleness: a Heartbeat Response with a changed Recovery
    /// Time Stamp must tear the association down (peer restarted).
    #[tokio::test]
    async fn test_heartbeat_detects_peer_restart() {
        let (client, upf) = make_client_with_peer().await;
        {
            let mut a = client.assoc.write().await;
            a.associated = true;
            a.peer_recovery_time_stamp = Some(100);
        }

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, from) = upf.recv_from(&mut buf).await.unwrap();
            let h = parse_wire_header(&buf[..len]).unwrap();
            assert_eq!(h.msg_type, pfcp_message_type::HEARTBEAT_REQUEST);
            // Respond with a NEW recovery time stamp → restart
            let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(200));
            let pkt = build_message(&msg, h.sequence_number, None);
            upf.send_to(&pkt, from).await.unwrap();
        });

        client.heartbeat_once().await.expect("heartbeat answered");
        assert!(
            !client.is_associated().await,
            "restart must tear down the association"
        );
        assert_eq!(
            client.association().await.peer_recovery_time_stamp,
            Some(200),
            "new incarnation timestamp stored"
        );
    }

    /// Inbound Heartbeat Request must be answered with our recovery
    /// timestamp via the library codec.
    #[tokio::test]
    async fn test_inbound_heartbeat_request_answered() {
        let (client, upf) = make_client_with_peer().await;
        let local_addr = client.socket.local_addr().unwrap();

        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(555));
        let pkt = build_message(&msg, 33, None);
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("heartbeat response expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::HEARTBEAT_RESPONSE);
        assert_eq!(h.sequence_number, 33, "response echoes the request seq");
        let rts = find_ie(&buf[h.body_offset..len], 96).expect("recovery TS mandatory");
        let rts = u32::from_be_bytes([rts[0], rts[1], rts[2], rts[3]]);
        assert_eq!(rts, client.recovery_time_stamp);
        assert!(rts > 0, "recovery timestamp must be real");
    }

    /// Inbound Association Release Request must be acknowledged and drop
    /// the association.
    #[tokio::test]
    async fn test_inbound_association_release() {
        let (client, upf) = make_client_with_peer().await;
        client.assoc.write().await.associated = true;
        let local_addr = client.socket.local_addr().unwrap();

        let msg = PfcpMessage::AssociationReleaseRequest(AssociationReleaseRequest::new(
            NodeId::new_ipv4([127, 0, 0, 4]),
        ));
        let pkt = build_message(&msg, 44, None);
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("release response expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(h.msg_type, pfcp_message_type::ASSOCIATION_RELEASE_RESPONSE);
        assert_eq!(
            parse_cause(&buf[h.body_offset..len]),
            Some(pfcp_cause::REQUEST_ACCEPTED)
        );
        assert!(!client.is_associated().await);
    }

    /// An unsupported PFCP version must be answered with Version Not
    /// Supported Response (type 11).
    #[tokio::test]
    async fn test_version_not_supported() {
        let (client, upf) = make_client_with_peer().await;
        let local_addr = client.socket.local_addr().unwrap();

        // version=2 header
        let mut pkt = encode_wire_message(pfcp_message_type::HEARTBEAT_REQUEST, None, 5, &[]);
        pkt[0] = 2 << 5; // version 2
        upf.send_to(&pkt, local_addr).await.unwrap();

        let mut buf = vec![0u8; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), upf.recv_from(&mut buf))
            .await
            .expect("version-not-supported expected")
            .unwrap();
        let h = parse_wire_header(&buf[..len]).unwrap();
        assert_eq!(
            h.msg_type,
            pfcp_message_type::VERSION_NOT_SUPPORTED_RESPONSE
        );
    }
}
