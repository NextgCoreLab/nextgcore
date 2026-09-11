//! SGWC SXA Message Builder
//!
//! Port of src/sgwc/sxa-build.c - Build PFCP messages for SXA interface
//!
//! #54: these builders used to emit **no IE headers at all**. `build_create_pdr` pushed a
//! bare PDR id, a bare interface octet and a bare TEID with no type/length in front of
//! any of them; `build_session_report_response` pushed the cause as a lone octet. That is
//! not PFCP, and it was invisible because `send_pfcp_message` discarded every buffer
//! before it reached a socket — the bodies were never parsed by anything, including our
//! own tests.
//!
//! With a real transport (this issue) the same bytes would go on the wire, and the SGW-U
//! has decoded with the shared `nextgcore-pfcp` codec since #59: it would find zero IEs,
//! create a session with no PDRs and no FARs, and answer `REQUEST_ACCEPTED`. So the
//! bodies are now built by the library's message types, which is the same decision #59
//! took for the SGW-U — one codec for one interface, rather than a second hand-rolled one
//! that drifts.

use bytes::BytesMut;

use nextgcore_pfcp::message::{
    SessionDeletionRequest as LibSessionDeletionRequest,
    SessionEstablishmentRequest as LibSessionEstablishmentRequest,
    SessionModificationRequest as LibSessionModificationRequest, SessionReportResponse,
};
use nextgcore_pfcp::types::{
    ApplyAction, CreateFar, CreatePdr, DestinationInterface, FSeid, FTeid, ForwardingParameters,
    NodeId, OuterHeaderCreation, OuterHeaderRemoval, OuterHeaderRemovalDescription, Pdi, PfcpCause,
    RemoveFar, RemovePdr, SourceInterface, UpdateFar, UpdatePdr,
};

use crate::context::{sgwc_self, SgwcSess, SgwcTunnel};

// ============================================================================
// PFCP Message Types
// ============================================================================

pub mod pfcp_type {
    pub const SESSION_ESTABLISHMENT_REQUEST: u8 = 50;
    pub const SESSION_MODIFICATION_REQUEST: u8 = 52;
    pub const SESSION_DELETION_REQUEST: u8 = 54;
    pub const SESSION_REPORT_RESPONSE: u8 = 57;
}

// ============================================================================
// PFCP IE Types
// ============================================================================

pub mod pfcp_ie {
    pub const CREATE_PDR: u16 = 1;
    pub const PDI: u16 = 2;
    pub const CREATE_FAR: u16 = 3;
    pub const FORWARDING_PARAMETERS: u16 = 4;
    pub const UPDATE_PDR: u16 = 9;
    pub const UPDATE_FAR: u16 = 10;
    pub const REMOVE_PDR: u16 = 15;
    pub const REMOVE_FAR: u16 = 16;
    pub const F_SEID: u16 = 57;
    pub const F_TEID: u16 = 21;
    pub const PDR_ID: u16 = 56;
    pub const FAR_ID: u16 = 108;
    pub const SOURCE_INTERFACE: u16 = 20;
    pub const DESTINATION_INTERFACE: u16 = 42;
    pub const OUTER_HEADER_CREATION: u16 = 84;
    pub const OUTER_HEADER_REMOVAL: u16 = 95;
    pub const APPLY_ACTION: u16 = 44;
}

// ============================================================================
// PFCP Apply Action Flags
// ============================================================================

pub mod apply_action {
    pub const DROP: u8 = 0x01;
    pub const FORW: u8 = 0x02;
    pub const BUFF: u8 = 0x04;
    pub const NOCP: u8 = 0x08;
    pub const DUPL: u8 = 0x10;
}

// ============================================================================
// PFCP Interface Types
// ============================================================================

pub mod pfcp_interface {
    pub const ACCESS: u8 = 0;
    pub const CORE: u8 = 1;
    pub const SGI_LAN_N6_LAN: u8 = 2;
    pub const CP_FUNCTION: u8 = 3;
}

/// PFCPSMReq-Flags (TS 29.244 §8.2.50).
pub mod smreq_flags {
    /// DROBU: drop the packets buffered for this session.
    pub const DROBU: u8 = 0x02;
}

// ============================================================================
// Message Builder Result
// ============================================================================

/// Built PFCP message
#[derive(Debug, Clone)]
pub struct PfcpMessage {
    pub msg_type: u8,
    pub seid: u64,
    pub data: Vec<u8>,
}

impl PfcpMessage {
    pub fn new(msg_type: u8, seid: u64) -> Self {
        Self {
            msg_type,
            seid,
            data: Vec::new(),
        }
    }
}

/// A source/destination interface octet as the library's typed enums.
fn source_interface(value: u8) -> SourceInterface {
    match value {
        pfcp_interface::CORE => SourceInterface::Core,
        pfcp_interface::SGI_LAN_N6_LAN => SourceInterface::SgiLanN6Lan,
        pfcp_interface::CP_FUNCTION => SourceInterface::CpFunction,
        _ => SourceInterface::Access,
    }
}

fn destination_interface(value: u8) -> DestinationInterface {
    match value {
        pfcp_interface::CORE => DestinationInterface::Core,
        pfcp_interface::SGI_LAN_N6_LAN => DestinationInterface::SgiLanN6Lan,
        pfcp_interface::CP_FUNCTION => DestinationInterface::CpFunction,
        _ => DestinationInterface::Access,
    }
}

/// The tunnel's own F-TEID, which is what the SGW-U matches an inbound G-PDU on.
fn local_f_teid(tunnel: &SgwcTunnel) -> Option<FTeid> {
    let addr = tunnel.local_addr?;
    Some(FTeid::new_ipv4(tunnel.local_teid, addr.octets()))
}

/// The peer endpoint a forwarded packet is sent to.
fn outer_header_creation(tunnel: &SgwcTunnel) -> Option<OuterHeaderCreation> {
    if tunnel.remote_teid == 0 {
        return None;
    }
    // Without the peer's ADDRESS there is no header to create: a TEID alone names no
    // destination, and emitting one would make the FAR look provisioned while the SGW-U
    // had nowhere to forward to.
    let addr = tunnel.remote_ip.ipv4?;
    Some(OuterHeaderCreation::new_gtpu_ipv4(
        tunnel.remote_teid,
        addr.octets(),
    ))
}

/// FORW once the peer endpoint is known; BUFF + NOCP until then.
///
/// BUFF is what makes idle-mode downlink data arrive at all: the SGW-U holds the packet
/// and reports it (TS 23.401 §5.3.4.2), which is the Downlink Data Report this SGW-C
/// turns into a paging request.
fn apply_action_for(tunnel: &SgwcTunnel) -> ApplyAction {
    if tunnel.remote_teid != 0 {
        ApplyAction::forward()
    } else {
        let mut aa = ApplyAction::buffer();
        aa.nocp = true;
        aa
    }
}

// ============================================================================
// SXA Message Builders
// ============================================================================

/// Build Session Establishment Request
/// Port of sgwc_sxa_build_session_establishment_request
pub fn build_session_establishment_request(sess: &SgwcSess) -> Option<PfcpMessage> {
    let ctx = sgwc_self();

    // SEID is 0 for establishment request (peer SEID not known yet)
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_ESTABLISHMENT_REQUEST, 0);

    // The Node ID and the CP F-SEID both name THIS SGW-C on Sxa. `SGWC_PFCP_NODE_IP` is
    // the same override `pfcp_open` binds with, so the address we advertise is the address
    // we listen on -- a Node ID naming an interface we do not serve makes the SGW-U send
    // its Session Report somewhere else.
    let node_ip: std::net::Ipv4Addr = std::env::var("SGWC_PFCP_NODE_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
    let mut req = LibSessionEstablishmentRequest::new(
        NodeId::new_ipv4(node_ip.octets()),
        FSeid::new_ipv4(sess.sgwc_sxa_seid, node_ip.octets()),
    );

    // Create PDRs and FARs for each bearer
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // DL Tunnel (S5/S8 SGW GTP-U)
            if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                push_create_rules(
                    &mut req,
                    &dl_tunnel,
                    pfcp_interface::CORE,
                    pfcp_interface::ACCESS,
                );
            }

            // UL Tunnel (S1-U SGW GTP-U)
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                push_create_rules(
                    &mut req,
                    &ul_tunnel,
                    pfcp_interface::ACCESS,
                    pfcp_interface::CORE,
                );
            }
        }
    }

    let mut body = BytesMut::new();
    req.encode(&mut body);
    msg.data = body.to_vec();
    log::debug!(
        "Built Session Establishment Request: cp_seid=0x{:x}, {} PDR(s), {} FAR(s), \
         data_len={}",
        sess.sgwc_sxa_seid,
        req.create_pdrs.len(),
        req.create_fars.len(),
        msg.data.len()
    );

    Some(msg)
}

/// Build Session Modification Request for bearer list
/// Port of sgwc_sxa_build_bearer_to_modify_list
pub fn build_bearer_to_modify_list(
    sess: &SgwcSess,
    modify_flags: u64,
    bearer_ids: &[u64],
) -> Option<PfcpMessage> {
    let ctx = sgwc_self();

    let mut msg = PfcpMessage::new(pfcp_type::SESSION_MODIFICATION_REQUEST, sess.sgwu_sxa_seid);
    let mut req = LibSessionModificationRequest::new();

    // Process each bearer to modify
    for bearer_id in bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            for (tunnel, src, dst) in [
                (
                    ctx.dl_tunnel_in_bearer(bearer.id),
                    pfcp_interface::CORE,
                    pfcp_interface::ACCESS,
                ),
                (
                    ctx.ul_tunnel_in_bearer(bearer.id),
                    pfcp_interface::ACCESS,
                    pfcp_interface::CORE,
                ),
            ] {
                let Some(tunnel) = tunnel else { continue };
                if modify_flags & crate::sxa_handler::pfcp_modify::CREATE != 0 {
                    let mut create = LibSessionEstablishmentRequest::new(
                        NodeId::new_ipv4([0, 0, 0, 0]),
                        FSeid::new_ipv4(0, [0, 0, 0, 0]),
                    );
                    push_create_rules(&mut create, &tunnel, src, dst);
                    req.create_pdrs.extend(create.create_pdrs);
                    req.create_fars.extend(create.create_fars);
                } else if modify_flags & crate::sxa_handler::pfcp_modify::REMOVE != 0 {
                    if let Some(pdr_id) = tunnel.pdr_id {
                        req.remove_pdrs.push(RemovePdr::new(pdr_id));
                    }
                    if let Some(far_id) = tunnel.far_id {
                        req.remove_fars.push(RemoveFar::new(far_id));
                    }
                } else {
                    if let Some(pdr_id) = tunnel.pdr_id {
                        let mut update = UpdatePdr::new(pdr_id);
                        update.outer_header_removal = Some(OuterHeaderRemoval {
                            description: OuterHeaderRemovalDescription::GtpUUdpIpv4,
                            pdu_session_container: false,
                        });
                        update.far_id = tunnel.far_id;
                        req.update_pdrs.push(update);
                    }
                    if let Some(far_id) = tunnel.far_id {
                        let mut update = UpdateFar::new(far_id);
                        update.apply_action = Some(update_apply_action(&tunnel, modify_flags));
                        if let Some(ohc) = outer_header_creation(&tunnel) {
                            let mut fp = ForwardingParameters::new(destination_interface(dst));
                            fp.outer_header_creation = Some(ohc);
                            update.forwarding_parameters = Some(fp);
                        }
                        req.update_fars.push(update);
                    }
                }
            }
        }
    }

    let mut body = BytesMut::new();
    req.encode(&mut body);
    msg.data = body.to_vec();
    log::debug!(
        "Built Session Modification Request: seid=0x{:x}, flags=0x{:x}, data_len={}",
        msg.seid,
        modify_flags,
        msg.data.len()
    );

    Some(msg)
}

/// Build a Session Modification Request that discards the session's buffered downlink
/// packets (TS 29.244 §8.2.50 DROBU, TS 23.401 §5.3.4.2). Issue #54.
pub fn build_drop_buffered_packets_request(sess: &SgwcSess) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_MODIFICATION_REQUEST, sess.sgwu_sxa_seid);
    let mut req = LibSessionModificationRequest::new();
    req.pfcp_smreq_flags = Some(smreq_flags::DROBU);
    let mut body = BytesMut::new();
    req.encode(&mut body);
    msg.data = body.to_vec();
    Some(msg)
}

/// Build Session Deletion Request
/// Port of sgwc_sxa_build_session_deletion_request
pub fn build_session_deletion_request(sess: &SgwcSess) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_DELETION_REQUEST, sess.sgwu_sxa_seid);

    // TS 29.244 Table 7.5.6.1-1: no IEs in the request; the SEID in the header names
    // the session.
    let mut body = BytesMut::new();
    LibSessionDeletionRequest::new().encode(&mut body);
    msg.data = body.to_vec();
    log::debug!("Built Session Deletion Request: seid=0x{:x}", msg.seid);

    Some(msg)
}

/// Build Session Report Response
///
/// #54: the cause used to be a bare octet with no IE header, so a conformant SGW-U could
/// not find the mandatory Cause at all (TS 29.244 §7.5.9).
pub fn build_session_report_response(sess: &SgwcSess, cause: u8) -> Option<PfcpMessage> {
    let mut msg = PfcpMessage::new(pfcp_type::SESSION_REPORT_RESPONSE, sess.sgwu_sxa_seid);

    let mut body = BytesMut::new();
    SessionReportResponse::new(PfcpCause::from_wire(cause)).encode(&mut body);
    msg.data = body.to_vec();
    log::debug!(
        "Built Session Report Response: seid=0x{:x}, cause={}",
        msg.seid,
        cause
    );

    Some(msg)
}

// ============================================================================
// Helper Functions for Building IEs
// ============================================================================

/// Add the Create PDR + Create FAR pair for one tunnel.
///
/// The PDR matches inbound traffic on the tunnel's own F-TEID and strips the GTP-U
/// header; the FAR forwards it to the peer endpoint, or buffers when there is not one yet.
/// Build the Session Modification that installs the indirect data-forwarding rules
/// (#48, TS 23.401 §5.5.1.2).
///
/// One Create PDR / Create FAR pair per forwarding tunnel. The direction mapping is the
/// forwarding path's, not the serving path's:
///
/// - the DL forwarding tunnel receives from the SOURCE eNB (ACCESS) and forwards to the
///   TARGET eNB (also ACCESS) -- both ends are radio, which is what makes indirect
///   forwarding an eNB-to-eNB relay through the SGW-U rather than a core-bound path;
/// - the UL forwarding tunnel is the mirror.
///
/// So both PDI source and FAR destination are ACCESS, unlike every other rule this
/// module builds. Getting that wrong would send forwarded user data out of the SGi
/// interface.
pub fn build_indirect_forwarding_rules(sess: &SgwcSess, bearer_ids: &[u64]) -> Option<PfcpMessage> {
    let ctx = sgwc_self();

    let mut msg = PfcpMessage::new(pfcp_type::SESSION_MODIFICATION_REQUEST, sess.sgwu_sxa_seid);
    let mut req = LibSessionModificationRequest::new();
    let mut rules = 0usize;

    for bearer_id in bearer_ids {
        let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
            continue;
        };
        for tunnel_id in &bearer.tunnel_ids {
            let Some(tunnel) = ctx.tunnel_find_by_id(*tunnel_id) else {
                continue;
            };
            if !matches!(
                tunnel.interface_type,
                crate::context::gtp_interface::SGW_GTP_U_DL_DATA_FORWARDING
                    | crate::context::gtp_interface::SGW_GTP_U_UL_DATA_FORWARDING
            ) {
                continue;
            }
            let mut create = LibSessionEstablishmentRequest::new(
                NodeId::new_ipv4([0, 0, 0, 0]),
                FSeid::new_ipv4(0, [0, 0, 0, 0]),
            );
            push_create_rules(
                &mut create,
                &tunnel,
                pfcp_interface::ACCESS,
                pfcp_interface::ACCESS,
            );
            rules += create.create_pdrs.len();
            req.create_pdrs.extend(create.create_pdrs);
            req.create_fars.extend(create.create_fars);
        }
    }

    // No rules means no forwarding tunnel had a usable PDR id, so there is nothing to
    // install. Sending an empty modification would be answered `REQUEST_ACCEPTED` and
    // would gate the S11 answer on a message that provisioned nothing.
    if rules == 0 {
        log::error!(
            "No indirect forwarding rules to install for session {}",
            sess.id
        );
        return None;
    }

    let mut body = BytesMut::new();
    req.encode(&mut body);
    msg.data = body.to_vec();
    log::debug!(
        "Built indirect forwarding Session Modification: seid=0x{:x}, rules={rules}, len={}",
        msg.seid,
        msg.data.len()
    );
    Some(msg)
}

fn push_create_rules(
    req: &mut LibSessionEstablishmentRequest,
    tunnel: &SgwcTunnel,
    src_interface: u8,
    dst_interface: u8,
) {
    let Some(pdr_id) = tunnel.pdr_id else {
        return;
    };
    let mut pdi = Pdi::new(source_interface(src_interface));
    pdi.local_f_teid = local_f_teid(tunnel);
    let mut pdr = CreatePdr::new(pdr_id, 255, pdi);
    pdr.outer_header_removal = Some(OuterHeaderRemoval {
        description: OuterHeaderRemovalDescription::GtpUUdpIpv4,
        pdu_session_container: false,
    });
    pdr.far_id = tunnel.far_id;
    req.create_pdrs.push(pdr);

    if let Some(far_id) = tunnel.far_id {
        let mut far = CreateFar::new(far_id, apply_action_for(tunnel));
        let mut fp = ForwardingParameters::new(destination_interface(dst_interface));
        fp.outer_header_creation = outer_header_creation(tunnel);
        far.forwarding_parameters = Some(fp);
        req.create_fars.push(far);
    }
}

/// The Apply Action an Update FAR carries: the modify flags decide, and the tunnel's
/// endpoint decides when they do not.
fn update_apply_action(tunnel: &SgwcTunnel, modify_flags: u64) -> ApplyAction {
    if modify_flags & crate::sxa_handler::pfcp_modify::ACTIVATE != 0 {
        ApplyAction::forward()
    } else if modify_flags & crate::sxa_handler::pfcp_modify::DEACTIVATE != 0 {
        let mut aa = ApplyAction::buffer();
        aa.nocp = true;
        aa
    } else {
        apply_action_for(tunnel)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_pfcp_message_new() {
        let msg = PfcpMessage::new(pfcp_type::SESSION_ESTABLISHMENT_REQUEST, 0x1234);
        assert_eq!(msg.msg_type, pfcp_type::SESSION_ESTABLISHMENT_REQUEST);
        assert_eq!(msg.seid, 0x1234);
        assert!(msg.data.is_empty());
    }

    /// #54: the built bodies are real PFCP, i.e. the SGW-U's decoder can read them back.
    ///
    /// The old builders emitted bare values with no IE headers, and nothing noticed
    /// because `send_pfcp_message` discarded every buffer. Decoding with the LIBRARY —
    /// which is what the SGW-U has used since #59 — is the assertion that separates "the
    /// bytes were produced" from "a peer can parse them".
    #[test]
    fn a_built_session_report_response_decodes_as_pfcp() {
        let sess = SgwcSess {
            id: 1,
            sgwu_sxa_seid: 0x2000,
            ..Default::default()
        };
        let msg =
            build_session_report_response(&sess, crate::sxa_handler::pfcp_cause::REQUEST_ACCEPTED)
                .expect("built");
        let mut body = Bytes::copy_from_slice(&msg.data);
        let decoded = SessionReportResponse::decode(&mut body)
            .expect("a Session Report Response must carry a decodable Cause IE");
        assert_eq!(decoded.cause, PfcpCause::RequestAccepted);
    }

    /// A Session Modification carrying DROBU round-trips, so the SGW-U actually sees the
    /// flag that tells it to discard the buffered packets.
    #[test]
    fn the_buffered_packet_discard_carries_drobu_on_the_wire() {
        let sess = SgwcSess {
            id: 1,
            sgwu_sxa_seid: 0x2000,
            ..Default::default()
        };
        let msg = build_drop_buffered_packets_request(&sess).expect("built");
        let mut body = Bytes::copy_from_slice(&msg.data);
        let decoded = LibSessionModificationRequest::decode(&mut body).expect("decodable");
        assert_eq!(
            decoded.pfcp_smreq_flags,
            Some(smreq_flags::DROBU),
            "without DROBU on the wire the SGW-U keeps the buffered packets forever"
        );
    }
}
