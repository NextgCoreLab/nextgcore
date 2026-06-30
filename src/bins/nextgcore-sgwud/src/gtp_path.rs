//! SGWU GTP-U Path Management (TS 29.281)
//!
//! Port of src/sgwu/gtp-path.c. Owns the real GTP-U UDP socket (port 2152)
//! and the user-plane forwarding path: G-PDU in -> PDR match by TEID ->
//! FAR apply (FORW/BUFF/DROP) -> G-PDU out. All wire framing goes through
//! the ogs-gtp GTPv1-U codec; Echo Response carries the mandatory Recovery
//! IE and Error Indication carries Tunnel Endpoint Identifier Data I +
//! GTP-U Peer Address as proper IEs (TS 29.281 Section 7.3.1).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;

use ogs_gtp::v1::header::{Gtp1cMessageType, Gtp1uMessageType};
use ogs_gtp::v1::message::{ErrorIndication, Gtp1Message};
use ogs_gtp::GTPV1_U_UDP_PORT;

use crate::context::{apply_action, sgwu_self, SgwuFar, SgwuPdr};
use crate::pfcp_path;
use crate::sxa_build::{LocalFTeid, UserPlaneReport};

/// Default GTP-U bind address (TS 29.281 Section 4.4.2.3)
const DEFAULT_GTPU_BIND: &str = "0.0.0.0:2152";

// ============================================================================
// GTP-U Receive Result
// ============================================================================

/// Outcome of processing one received GTP-U datagram
#[derive(Debug)]
pub enum GtpuRecvResult {
    /// Packet handled (echo, end marker, ...)
    Handled,
    /// Echo response sent
    EchoResponse,
    /// G-PDU forwarded per FAR
    Forwarded,
    /// G-PDU buffered per FAR (BUFF)
    Buffered,
    /// Error Indication sent (no PDR matched)
    ErrorIndication,
    /// A Session Report was sent to the SGW-C
    SessionReport(UserPlaneReport),
    /// Packet dropped
    Dropped(String),
}

// ============================================================================
// GTP-U Server
// ============================================================================

struct GtpuInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    /// Destination UDP port for forwarded G-PDUs (2152 in deployment;
    /// configurable so tests can target ephemeral peers)
    peer_port: u16,
    running: AtomicBool,
}

/// GTP-U server bound to the S1-U/S5-U interface
#[derive(Clone)]
pub struct GtpuServer {
    inner: Arc<GtpuInner>,
}

impl GtpuServer {
    /// Bind the GTP-U socket and start the receive loop
    pub fn open(bind: &str, peer_port: u16) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| e.to_string())?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

        let inner = Arc::new(GtpuInner {
            socket,
            local_addr,
            peer_port,
            running: AtomicBool::new(true),
        });

        {
            let inner = inner.clone();
            std::thread::Builder::new()
                .name("sgwu-gtpu-recv".into())
                .spawn(move || {
                    let server = GtpuServer {
                        inner: inner.clone(),
                    };
                    let mut buf = [0u8; 9000];
                    while inner.running.load(Ordering::SeqCst) {
                        match inner.socket.recv_from(&mut buf) {
                            Ok((len, peer)) => {
                                handle_gtpu_packet(&server, &buf[..len], peer);
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => {
                                if inner.running.load(Ordering::SeqCst) {
                                    log::error!("GTP-U recv error: {e}");
                                }
                            }
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }

        log::info!("GTP-U server listening on {local_addr}");
        Ok(Self { inner })
    }

    /// Stop the receive loop
    pub fn close(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Local bound address
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> Result<(), String> {
        self.inner
            .socket
            .send_to(packet, peer)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Resolve a FAR's Outer Header Creation into a peer socket address
    fn far_peer(&self, far: &SgwuFar) -> Option<(u32, SocketAddr)> {
        let (teid, v4, v6) = far.outer_header_creation.as_ref()?;
        let ip: IpAddr = match (v4, v6) {
            (Some(v4), _) => IpAddr::V4(*v4),
            (None, Some(v6)) => IpAddr::V6(*v6),
            (None, None) => return None,
        };
        Some((*teid, SocketAddr::new(ip, self.inner.peer_port)))
    }

    /// Forward a payload as a G-PDU per the FAR's Outer Header Creation
    fn forward_gpdu(&self, far: &SgwuFar, payload: &[u8]) -> Result<(), String> {
        let (teid, peer) = self
            .far_peer(far)
            .ok_or_else(|| format!("FAR {} has no outer header creation", far.far_id))?;
        let packet = Gtp1Message::gpdu(teid, Bytes::copy_from_slice(payload)).encode();
        self.send_to(&packet, peer)?;
        log::trace!(
            "FORW G-PDU FAR {} -> TEID=0x{:x} peer={} len={}",
            far.far_id,
            teid,
            peer,
            packet.len()
        );
        Ok(())
    }

    /// Send an End Marker through a FAR (TS 23.214 / TS 29.281 Section 7.3.2)
    pub fn send_end_marker(&self, sess_id: u64, far_id: u32) -> Result<(), String> {
        let ctx = sgwu_self();
        let far = ctx
            .far_find(sess_id, far_id)
            .ok_or_else(|| format!("FAR {far_id} not found"))?;
        let (teid, peer) = self
            .far_peer(&far)
            .ok_or_else(|| format!("FAR {far_id} has no outer header creation"))?;
        let packet = Gtp1Message::end_marker(teid).encode();
        self.send_to(&packet, peer)?;
        log::debug!("End Marker FAR {far_id} -> TEID=0x{teid:x} peer={peer}");
        Ok(())
    }

    /// Send any packets buffered on a FAR (BUFF -> FORW transition,
    /// TS 29.244 Section 5.3.1)
    pub fn send_buffered_packets(&self, sess_id: u64, far_id: u32) -> usize {
        let ctx = sgwu_self();
        let Some(far) = ctx.far_find(sess_id, far_id) else {
            return 0;
        };
        let buffered = ctx.far_take_buffered(sess_id, far_id);
        let mut sent = 0;
        for payload in &buffered {
            match self.forward_gpdu(&far, payload) {
                Ok(()) => sent += 1,
                Err(e) => log::error!("Failed to send buffered packet: {e}"),
            }
        }
        if sent > 0 {
            log::debug!("Sent {sent} buffered packets for FAR {far_id}");
        }
        sent
    }
}

// ============================================================================
// Global server instance (process lifecycle)
// ============================================================================

static GTPU_SERVER: OnceLock<GtpuServer> = OnceLock::new();

/// Get the global GTP-U server, if open
pub fn gtpu_server() -> Option<&'static GtpuServer> {
    GTPU_SERVER.get()
}

/// Initialize GTP-U subsystem
/// Port of sgwu_gtp_init
pub fn gtp_init() -> Result<(), String> {
    log::info!("GTP-U subsystem initialized");
    Ok(())
}

/// Finalize GTP-U subsystem
/// Port of sgwu_gtp_final
pub fn gtp_final() {
    log::info!("GTP-U subsystem finalized");
}

/// Open the GTP-U server socket
/// Port of sgwu_gtp_open
pub fn gtp_open() -> Result<(), String> {
    if GTPU_SERVER.get().is_some() {
        return Ok(());
    }

    let bind = std::env::var("SGWU_GTPU_BIND").unwrap_or_else(|_| DEFAULT_GTPU_BIND.to_string());
    let server = GtpuServer::open(&bind, GTPV1_U_UDP_PORT)?;

    // Advertise the bound address in allocated F-TEIDs, unless a distinct
    // advertise address is configured (e.g. behind NAT or wildcard bind)
    let ctx = sgwu_self();
    let advertised = match server.local_addr().ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => std::env::var("SGWU_GTPU_ADVERTISE")
            .ok()
            .and_then(|v| v.parse::<Ipv4Addr>().ok()),
    };
    ctx.set_gtpu_address(advertised);

    GTPU_SERVER
        .set(server)
        .map_err(|_| "GTP-U server already open".to_string())?;
    Ok(())
}

/// Close the GTP-U server socket
/// Port of sgwu_gtp_close
pub fn gtp_close() {
    if let Some(server) = GTPU_SERVER.get() {
        server.close();
    }
    log::info!("GTP-U server closed");
}

// ============================================================================
// Packet processing
// ============================================================================

/// Handle one received GTP-U datagram
/// Port of _gtpv1_u_recv_cb
pub fn handle_gtpu_packet(server: &GtpuServer, data: &[u8], peer: SocketAddr) -> GtpuRecvResult {
    let mut bytes = Bytes::copy_from_slice(data);
    let msg = match Gtp1Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("[DROP] Cannot decode GTP-U packet from {peer}: {e}");
            return GtpuRecvResult::Dropped(format!("decode: {e}"));
        }
    };

    let msg_type = msg.header.message_type;
    match msg_type {
        t if t == Gtp1cMessageType::EchoRequest as u8 => handle_echo_request(server, &msg, peer),
        t if t == Gtp1cMessageType::EchoResponse as u8 => {
            // TS 29.281 Section 8.2: the Recovery value in GTP-U shall be
            // ignored by the receiver; the response just confirms the path.
            log::debug!("[RECV] GTP-U Echo Response from {peer}");
            GtpuRecvResult::Handled
        }
        t if t == Gtp1uMessageType::ErrorIndication as u8 => handle_error_indication(&msg, peer),
        t if t == Gtp1uMessageType::EndMarker as u8 => handle_end_marker(server, &msg, peer),
        t if t == Gtp1uMessageType::GPdu as u8 => handle_gpdu(server, &msg, peer),
        other => {
            log::error!("[DROP] Invalid GTP-U message type [{other}] from {peer}");
            GtpuRecvResult::Dropped(format!("unknown type {other}"))
        }
    }
}

/// Echo Request -> Echo Response with the mandatory Recovery IE.
/// Per TS 29.281 Section 8.2 the restart counter value shall be set to 0
/// and ignored by the receiver.
fn handle_echo_request(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    log::debug!("[RECV] GTP-U Echo Request from {peer}");
    let seq = msg.header.sequence_number.unwrap_or(0);
    let response = Gtp1Message::echo_response(0, seq, 0);
    match server.send_to(&response.encode(), peer) {
        Ok(()) => {
            log::debug!("[SEND] GTP-U Echo Response to {peer}");
            GtpuRecvResult::EchoResponse
        }
        Err(e) => {
            log::error!("Echo Response to {peer} failed: {e}");
            GtpuRecvResult::Dropped(e)
        }
    }
}

/// Error Indication: the peer has no context for a TEID we are sending to.
/// Map it back to the FAR carrying that TEID and report ERIR to the SGW-C
/// (TS 29.244 Section 5.10).
fn handle_error_indication(msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let parsed = match ErrorIndication::decode(msg) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[DROP] Malformed Error Indication from {peer}: {e}");
            return GtpuRecvResult::Dropped(format!("malformed error indication: {e}"));
        }
    };

    log::warn!(
        "[RECV] Error Indication from {} for TEID 0x{:x}",
        peer,
        parsed.teid
    );

    let ctx = sgwu_self();
    let Some(far) = ctx.far_find_by_ohc_teid(parsed.teid) else {
        log::warn!("Error Indication TEID 0x{:x} matches no FAR", parsed.teid);
        return GtpuRecvResult::Handled;
    };
    let Some(sess) = ctx.sess_find_by_id(far.sess_id) else {
        return GtpuRecvResult::Handled;
    };

    let peer_v4 = match peer.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    };
    let report = UserPlaneReport {
        error_indication_report: true,
        remote_f_teid: Some(LocalFTeid {
            teid: parsed.teid,
            ipv4: peer_v4,
            ipv6: None,
        }),
        ..Default::default()
    };
    if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
        log::error!("Session Report (ERIR) failed: {e}");
    }
    GtpuRecvResult::SessionReport(report)
}

/// End Marker: forward along the same path as G-PDUs for the matched PDR
fn handle_end_marker(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let teid = msg.header.teid;
    log::debug!("[RECV] End Marker from {peer} TEID=0x{teid:x}");

    let ctx = sgwu_self();
    let Some(pdr) = ctx.pdr_find_by_teid(teid) else {
        return send_error_indication(server, teid, peer);
    };
    let far = pdr.far_id.and_then(|fid| ctx.far_find(pdr.sess_id, fid));
    if let Some(far) = far {
        if far.apply_action & apply_action::FORW != 0 {
            if let Some((out_teid, out_peer)) = server.far_peer(&far) {
                let packet = Gtp1Message::end_marker(out_teid).encode();
                if let Err(e) = server.send_to(&packet, out_peer) {
                    log::error!("End Marker forward failed: {e}");
                }
            }
        }
    }
    GtpuRecvResult::Handled
}

/// G-PDU: PDR lookup by TEID, then apply the linked FAR
fn handle_gpdu(server: &GtpuServer, msg: &Gtp1Message, peer: SocketAddr) -> GtpuRecvResult {
    let teid = msg.header.teid;
    let payload = match &msg.payload {
        Some(p) => p.as_ref(),
        None => {
            log::warn!("[DROP] G-PDU without payload from {peer}");
            return GtpuRecvResult::Dropped("empty G-PDU".to_string());
        }
    };
    log::trace!(
        "[RECV] G-PDU from {} TEID=0x{:x} len={}",
        peer,
        teid,
        payload.len()
    );

    let ctx = sgwu_self();
    let Some(pdr) = ctx.pdr_find_by_teid(teid) else {
        log::warn!("[DROP] No PDR for TEID 0x{teid:x}: sending Error Indication");
        return send_error_indication(server, teid, peer);
    };

    apply_far(server, &pdr, payload)
}

/// Apply the FAR linked to a PDR to a received payload
fn apply_far(server: &GtpuServer, pdr: &SgwuPdr, payload: &[u8]) -> GtpuRecvResult {
    let ctx = sgwu_self();
    let Some(far_id) = pdr.far_id else {
        log::warn!("[DROP] PDR {} has no FAR", pdr.pdr_id);
        return GtpuRecvResult::Dropped("no FAR".to_string());
    };
    let Some(far) = ctx.far_find(pdr.sess_id, far_id) else {
        log::warn!("[DROP] FAR {far_id} not installed");
        return GtpuRecvResult::Dropped("FAR not found".to_string());
    };

    if far.apply_action & apply_action::DROP != 0 {
        log::trace!("DROP per FAR {far_id}");
        return GtpuRecvResult::Dropped("FAR action DROP".to_string());
    }

    if far.apply_action & apply_action::BUFF != 0 {
        let count = ctx
            .far_buffer_packet(pdr.sess_id, far_id, payload.to_vec())
            .unwrap_or(0);
        log::debug!("BUFF per FAR {far_id} (buffered={count})");
        // First buffered packet triggers a Downlink Data Report unless the
        // SGW-C suppressed notification (NOCP)
        if count == 1 && far.apply_action & apply_action::NOCP == 0 {
            if let Some(sess) = ctx.sess_find_by_id(pdr.sess_id) {
                let report = UserPlaneReport {
                    downlink_data_report: true,
                    pdr_id: Some(pdr.pdr_id),
                    ..Default::default()
                };
                if let Err(e) = pfcp_path::send_session_report_request(&sess, &report) {
                    log::error!("Session Report (DLDR) failed: {e}");
                }
                return GtpuRecvResult::SessionReport(report);
            }
        }
        return GtpuRecvResult::Buffered;
    }

    if far.apply_action & apply_action::FORW != 0 {
        return match server.forward_gpdu(&far, payload) {
            Ok(()) => GtpuRecvResult::Forwarded,
            Err(e) => {
                log::error!("FORW per FAR {far_id} failed: {e}");
                GtpuRecvResult::Dropped(e)
            }
        };
    }

    GtpuRecvResult::Dropped(format!(
        "FAR {far_id} has no applicable action (0x{:x})",
        far.apply_action
    ))
}

/// Send an Error Indication for a G-PDU that matched no PDR
/// (TS 29.281 Section 7.3.1: TEID Data I + GTP-U Peer Address IEs)
fn send_error_indication(server: &GtpuServer, teid: u32, peer: SocketAddr) -> GtpuRecvResult {
    let local_addr: Vec<u8> = match sgwu_self()
        .gtpu_address()
        .map(IpAddr::V4)
        .unwrap_or_else(|| server.local_addr().ip())
    {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let msg = Gtp1Message::error_indication(0, teid, &local_addr);
    match server.send_to(&msg.encode(), peer) {
        Ok(()) => {
            log::debug!("[SEND] Error Indication to {peer} for TEID 0x{teid:x}");
            GtpuRecvResult::ErrorIndication
        }
        Err(e) => {
            log::error!("Error Indication to {peer} failed: {e}");
            GtpuRecvResult::Dropped(e)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{FSeid, SgwuFar, SgwuPdr};

    fn test_server(peer_port: u16) -> GtpuServer {
        GtpuServer::open("127.0.0.1:0", peer_port).unwrap()
    }

    fn client() -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock
    }

    fn recv_msg(sock: &UdpSocket) -> Gtp1Message {
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        Gtp1Message::decode(&mut bytes).unwrap()
    }

    /// Install a session with a PDR (local TEID) linked to a FAR
    fn provision(seid: u64, local_teid: u32, far: SgwuFar) -> (u64, u32) {
        let ctx = sgwu_self();
        let f_seid = FSeid::with_ipv4(seid, Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        let far_id = far.far_id;
        ctx.far_install(SgwuFar {
            sess_id: sess.id,
            ..far
        });
        ctx.pdr_install(SgwuPdr {
            sess_id: sess.id,
            pdr_id: 1,
            precedence: 255,
            source_interface: 0,
            local_teid,
            local_addr: Some(Ipv4Addr::new(127, 0, 0, 1)),
            outer_header_removal: Some(0),
            far_id: Some(far_id),
            qer_id: None,
        });
        (sess.id, far_id)
    }

    #[test]
    fn test_echo_request_response_carries_recovery_ie() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let sock = client();

        let echo = Gtp1Message::echo_request(0, 0x42);
        sock.send_to(&echo.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&sock);
        assert_eq!(
            response.header.message_type,
            Gtp1cMessageType::EchoResponse as u8
        );
        assert_eq!(response.header.sequence_number, Some(0x42));
        // Recovery IE is mandatory in GTP-U Echo Response
        // (TS 29.281 Section 7.2.2); its value shall be 0
        let recovery = response.get_ie(14).expect("Recovery IE missing");
        assert_eq!(recovery.value[0], 0);

        server.close();
    }

    #[test]
    fn test_gpdu_forwarded_per_far() {
        // Fake PGW peer to receive the forwarded G-PDU
        let pgw = client();
        let pgw_port = pgw.local_addr().unwrap().port();

        let server = test_server(pgw_port);
        let enb = client();

        let (_sess, _far) = provision(
            0xA001,
            0x1001,
            SgwuFar {
                far_id: 10,
                apply_action: apply_action::FORW,
                destination_interface: 1,
                outer_header_creation: Some((0x2002, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        let payload = [0x45, 0x00, 0x00, 0x1c, 0xDE, 0xAD, 0xBE, 0xEF];
        let gpdu = Gtp1Message::gpdu(0x1001, Bytes::copy_from_slice(&payload));
        enb.send_to(&gpdu.encode(), server.local_addr()).unwrap();

        let forwarded = recv_msg(&pgw);
        assert_eq!(forwarded.header.message_type, Gtp1uMessageType::GPdu as u8);
        assert_eq!(forwarded.header.teid, 0x2002); // outer header creation TEID
        assert_eq!(forwarded.payload.as_deref(), Some(&payload[..]));

        server.close();
    }

    #[test]
    fn test_gpdu_unknown_teid_triggers_error_indication() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let enb = client();

        let gpdu = Gtp1Message::gpdu(0xDEAD_BEEF, Bytes::from_static(&[1, 2, 3, 4]));
        enb.send_to(&gpdu.encode(), server.local_addr()).unwrap();

        let response = recv_msg(&enb);
        assert_eq!(
            response.header.message_type,
            Gtp1uMessageType::ErrorIndication as u8
        );
        // Header TEID is 0; the offending TEID is in TEID Data I
        assert_eq!(response.header.teid, 0);
        let parsed = ErrorIndication::decode(&response).unwrap();
        assert_eq!(parsed.teid, 0xDEAD_BEEF);
        assert!(!parsed.gsn_address.is_empty()); // GTP-U Peer Address present

        server.close();
    }

    #[test]
    fn test_gpdu_buffered_per_far_and_reported_once() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let ctx = sgwu_self();

        let (sess_id, far_id) = provision(
            0xA002,
            0x1002,
            SgwuFar {
                far_id: 20,
                apply_action: apply_action::BUFF,
                destination_interface: 0,
                outer_header_creation: None,
                ..Default::default()
            },
        );

        let pdr = ctx.pdr_find_by_teid(0x1002).unwrap();

        // First buffered packet triggers a Downlink Data Report
        let gpdu1 = Gtp1Message::gpdu(0x1002, Bytes::from_static(&[1, 1]));
        let result =
            handle_gtpu_packet(&server, &gpdu1.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::SessionReport(_)));

        // Second packet is buffered silently
        let gpdu2 = Gtp1Message::gpdu(0x1002, Bytes::from_static(&[2, 2]));
        let result =
            handle_gtpu_packet(&server, &gpdu2.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Buffered));

        let far = ctx.far_find(sess_id, far_id).unwrap();
        assert_eq!(far.buffered.len(), 2);
        let _ = pdr;

        server.close();
    }

    #[test]
    fn test_buffered_packets_drained_on_forw_transition() {
        // Fake eNB peer that receives the drained downlink packets
        let enb = client();
        let enb_port = enb.local_addr().unwrap().port();
        let server = test_server(enb_port);
        let ctx = sgwu_self();

        let (sess_id, far_id) = provision(
            0xA003,
            0x1003,
            SgwuFar {
                far_id: 30,
                apply_action: apply_action::BUFF,
                destination_interface: 0,
                outer_header_creation: None,
                ..Default::default()
            },
        );

        // Buffer two downlink packets
        for payload in [&[1u8, 1][..], &[2u8, 2][..]] {
            let gpdu = Gtp1Message::gpdu(0x1003, Bytes::copy_from_slice(payload));
            handle_gtpu_packet(&server, &gpdu.encode(), "127.0.0.1:9999".parse().unwrap());
        }

        // SGW-C activates the bearer: FORW with the eNB outer header
        ctx.far_update_with(sess_id, far_id, |far| {
            far.apply_action = apply_action::FORW;
            far.outer_header_creation = Some((0xE0B1, Some(Ipv4Addr::new(127, 0, 0, 1)), None));
        });
        let sent = server.send_buffered_packets(sess_id, far_id);
        assert_eq!(sent, 2);

        let first = recv_msg(&enb);
        assert_eq!(first.header.teid, 0xE0B1);
        assert_eq!(first.payload.as_deref(), Some(&[1u8, 1][..]));
        let second = recv_msg(&enb);
        assert_eq!(second.payload.as_deref(), Some(&[2u8, 2][..]));

        // Buffer is drained
        assert!(ctx.far_find(sess_id, far_id).unwrap().buffered.is_empty());

        server.close();
    }

    #[test]
    fn test_gpdu_dropped_per_far() {
        let server = test_server(GTPV1_U_UDP_PORT);

        provision(
            0xA004,
            0x1004,
            SgwuFar {
                far_id: 40,
                apply_action: apply_action::DROP,
                ..Default::default()
            },
        );

        let gpdu = Gtp1Message::gpdu(0x1004, Bytes::from_static(&[9]));
        let result = handle_gtpu_packet(&server, &gpdu.encode(), "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Dropped(_)));

        server.close();
    }

    #[test]
    fn test_received_error_indication_reported_to_sgwc() {
        let server = test_server(GTPV1_U_UDP_PORT);

        let (_sess, _far) = provision(
            0xA005,
            0x1005,
            SgwuFar {
                far_id: 50,
                apply_action: apply_action::FORW,
                outer_header_creation: Some((0x5005, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        // Peer reports it has no context for the TEID we forward to
        let err_ind = Gtp1Message::error_indication(0, 0x5005, &[127, 0, 0, 1]);
        let result = handle_gtpu_packet(
            &server,
            &err_ind.encode(),
            "127.0.0.1:2152".parse().unwrap(),
        );
        match result {
            GtpuRecvResult::SessionReport(report) => {
                assert!(report.error_indication_report);
                assert_eq!(report.remote_f_teid.unwrap().teid, 0x5005);
            }
            other => panic!("expected SessionReport, got {other:?}"),
        }

        server.close();
    }

    #[test]
    fn test_end_marker_forwarded() {
        let peer = client();
        let peer_port = peer.local_addr().unwrap().port();
        let server = test_server(peer_port);

        provision(
            0xA006,
            0x1006,
            SgwuFar {
                far_id: 60,
                apply_action: apply_action::FORW,
                outer_header_creation: Some((0x6006, Some(Ipv4Addr::new(127, 0, 0, 1)), None)),
                ..Default::default()
            },
        );

        let end_marker = Gtp1Message::end_marker(0x1006);
        handle_gtpu_packet(
            &server,
            &end_marker.encode(),
            "127.0.0.1:9999".parse().unwrap(),
        );

        let forwarded = recv_msg(&peer);
        assert_eq!(
            forwarded.header.message_type,
            Gtp1uMessageType::EndMarker as u8
        );
        assert_eq!(forwarded.header.teid, 0x6006);

        server.close();
    }

    #[test]
    fn test_malformed_packet_dropped() {
        let server = test_server(GTPV1_U_UDP_PORT);
        let result = handle_gtpu_packet(&server, &[0x00], "127.0.0.1:9999".parse().unwrap());
        assert!(matches!(result, GtpuRecvResult::Dropped(_)));
        server.close();
    }
}
