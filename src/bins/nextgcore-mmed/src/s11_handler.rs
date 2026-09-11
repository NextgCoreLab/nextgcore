//! S11 (GTP-C) Message Handling
//!
//! Port of src/mme/mme-s11-handler.c - GTP-C message handling for S11 interface

use crate::s11_build::{ie_type, message_type};
use std::net::SocketAddr;

// ============================================================================
// Error Types
// ============================================================================

/// S11 handler error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S11Error {
    ContextNotFound,
    MandatoryIeMissing(String),
    InvalidMessageFormat,
    InvalidCause(u8),
    TransactionError,
    InternalError(String),
}

impl std::fmt::Display for S11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContextNotFound => write!(f, "Context not found"),
            Self::MandatoryIeMissing(ie) => write!(f, "Mandatory IE missing: {ie}"),
            Self::InvalidMessageFormat => write!(f, "Invalid message format"),
            Self::InvalidCause(c) => write!(f, "Invalid cause: {c}"),
            Self::TransactionError => write!(f, "Transaction error"),
            Self::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for S11Error {}

pub type S11Result<T> = Result<T, S11Error>;

// ============================================================================
// ESM Cause Mapping
// ============================================================================

/// ESM cause codes (3GPP TS 24.301)
pub mod esm_cause {
    pub const OPERATOR_DETERMINED_BARRING: u8 = 8;
    pub const INSUFFICIENT_RESOURCES: u8 = 26;
    pub const MISSING_OR_UNKNOWN_APN: u8 = 27;
    pub const USER_AUTHENTICATION_FAILED: u8 = 29;
    pub const REQUEST_REJECTED_BY_SERVING_GW_OR_PDN_GW: u8 = 30;
    pub const SERVICE_OPTION_NOT_SUPPORTED: u8 = 32;
    pub const REGULAR_DEACTIVATION: u8 = 36;
    pub const NETWORK_FAILURE: u8 = 38;
    pub const SEMANTIC_ERROR_IN_THE_TFT_OPERATION: u8 = 41;
    pub const SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION: u8 = 42;
    pub const INVALID_EPS_BEARER_IDENTITY: u8 = 43;
    pub const SEMANTIC_ERRORS_IN_PACKET_FILTERS: u8 = 44;
    pub const SYNTACTICAL_ERROR_IN_PACKET_FILTERS: u8 = 45;
}

/// Convert a GTP-C cause (TS 29.274 §8.4) to the ESM cause the UE is owed
/// (TS 24.301 §9.9.4.4).
///
/// #51: 78 was absent, so an SGW rejecting a session for "Missing or unknown APN"
/// reached the UE as `NETWORK_FAILURE` (38) — which tells the subscriber's handset
/// to retry a request that can never succeed, and tells the operator nothing about
/// the APN that is actually misconfigured. Every mapping below is a cause where the
/// UE can do something different for knowing it.
pub fn esm_cause_from_gtp(gtp_cause: u8) -> u8 {
    match gtp_cause {
        64 => esm_cause::INVALID_EPS_BEARER_IDENTITY,
        68 => esm_cause::SERVICE_OPTION_NOT_SUPPORTED,
        // TS 29.274 §8.4 cause 73 "No resources available" is a capacity refusal, and
        // §9.9.4.4 cause 26 says exactly that to the UE.
        73 => esm_cause::INSUFFICIENT_RESOURCES,
        74 => esm_cause::SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
        75 => esm_cause::SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION,
        76 => esm_cause::SEMANTIC_ERRORS_IN_PACKET_FILTERS,
        77 => esm_cause::SYNTACTICAL_ERROR_IN_PACKET_FILTERS,
        // The one the issue names.
        78 => esm_cause::MISSING_OR_UNKNOWN_APN,
        // A refusal by the SGW/PGW that names no more specific reason. Distinct from
        // NETWORK_FAILURE, which claims the network broke rather than declined.
        94 => esm_cause::REQUEST_REJECTED_BY_SERVING_GW_OR_PDN_GW,
        _ => esm_cause::NETWORK_FAILURE,
    }
}

// ============================================================================
// Parsed Message Structures
// ============================================================================

/// Parsed Create Session Response
#[derive(Debug, Clone, Default)]
pub struct CreateSessionResponseData {
    pub cause: u8,
    pub sgw_s11_teid: u32,
    pub sgw_s11_ipv4: Option<[u8; 4]>,
    pub pgw_s5c_teid: u32,
    pub pgw_s5c_ipv4: Option<[u8; 4]>,
    pub paa_pdn_type: u8,
    pub paa_ipv4: Option<[u8; 4]>,
    pub paa_ipv6: Option<[u8; 16]>,
    pub bearer_contexts: Vec<BearerContextCreated>,
    pub ambr_uplink: u64,
    pub ambr_downlink: u64,
    pub pco: Option<Vec<u8>>,
    pub epco: Option<Vec<u8>>,
}

/// Bearer context created
#[derive(Debug, Clone, Default)]
pub struct BearerContextCreated {
    pub ebi: u8,
    pub cause: u8,
    pub sgw_s1u_teid: u32,
    pub sgw_s1u_ipv4: Option<[u8; 4]>,
    pub pgw_s5u_teid: u32,
    pub pgw_s5u_ipv4: Option<[u8; 4]>,
    pub qci: u8,
    pub arp_priority: u8,
    pub arp_pec: u8,
    pub arp_pev: u8,
}

/// Parsed Modify Bearer Response
#[derive(Debug, Clone, Default)]
pub struct ModifyBearerResponseData {
    pub cause: u8,
    pub bearer_contexts: Vec<BearerContextModified>,
}

/// Bearer context modified
#[derive(Debug, Clone, Default)]
pub struct BearerContextModified {
    pub ebi: u8,
    pub cause: u8,
}

/// Parsed Delete Session Response
#[derive(Debug, Clone, Default)]
pub struct DeleteSessionResponseData {
    pub cause: u8,
}

/// Parsed Create Bearer Request
#[derive(Debug, Clone, Default)]
pub struct CreateBearerRequestData {
    pub linked_ebi: u8,
    pub pti: u8,
    pub bearer_context: BearerContextToBeCreated,
}

/// Bearer context to be created
#[derive(Debug, Clone, Default)]
pub struct BearerContextToBeCreated {
    pub ebi: u8,
    pub sgw_s1u_teid: u32,
    pub sgw_s1u_ipv4: Option<[u8; 4]>,
    pub pgw_s5u_teid: u32,
    pub pgw_s5u_ipv4: Option<[u8; 4]>,
    pub qci: u8,
    pub arp_priority: u8,
    pub arp_pec: u8,
    pub arp_pev: u8,
    pub mbr_uplink: u64,
    pub mbr_downlink: u64,
    pub gbr_uplink: u64,
    pub gbr_downlink: u64,
    pub tft: Vec<u8>,
}

/// Parsed Update Bearer Request
#[derive(Debug, Clone, Default)]
pub struct UpdateBearerRequestData {
    pub pti: u8,
    pub bearer_context: BearerContextToBeUpdated,
}

/// Bearer context to be updated
#[derive(Debug, Clone, Default)]
pub struct BearerContextToBeUpdated {
    pub ebi: u8,
    pub qci: Option<u8>,
    pub arp_priority: Option<u8>,
    pub arp_pec: Option<u8>,
    pub arp_pev: Option<u8>,
    pub mbr_uplink: Option<u64>,
    pub mbr_downlink: Option<u64>,
    pub gbr_uplink: Option<u64>,
    pub gbr_downlink: Option<u64>,
    pub tft: Option<Vec<u8>>,
}

/// Parsed Delete Bearer Request
#[derive(Debug, Clone, Default)]
pub struct DeleteBearerRequestData {
    pub linked_ebi: Option<u8>,
    pub ebi: Option<u8>,
    pub pti: u8,
}

/// Parsed Release Access Bearers Response
#[derive(Debug, Clone, Default)]
pub struct ReleaseAccessBearersResponseData {
    pub cause: u8,
}

/// Parsed Downlink Data Notification
#[derive(Debug, Clone, Default)]
pub struct DownlinkDataNotificationData {
    pub ebi: u8,
    pub cause: Option<u8>,
}

// ============================================================================
// Datagram dispatch (#51)
// ============================================================================

/// Route a triggered (response) message that the transaction layer has already
/// correlated to one of this MME's outstanding requests.
///
/// Correlation happens BEFORE this is called, in `gtp_path::handle_datagram`, and
/// that ordering is the point: an uncorrelated response is one this MME did not ask
/// for, and letting it reach here would allow a stray datagram to mutate session
/// state.
///
/// The raw datagram is passed rather than the decoded `Gtp2Message` so the existing,
/// tested IE walk in this module keeps parsing it. That leaves two decoders for the
/// same message — the library's, used for correlation, and this one, used for
/// content — which is a real cost and NOT what #51 asks to remove (criterion 7 names
/// `s11_build.rs`'s builder). See the spec's Ceilings.
pub fn dispatch_triggered(raw: &[u8], msg_type: u8, sequence_number: u32, peer: SocketAddr) {
    use crate::s11_build::message_type as mt;

    match msg_type {
        mt::CREATE_SESSION_RESPONSE => match handle_create_session_response(raw) {
            // The LOCAL S11 TEID comes from the header this MME told the SGW to
            // address, so it is read from the same bytes rather than trusted from
            // the body.
            Ok(data) => {
                let local_teid = parse_gtp_header(raw)
                    .map(|(_, teid, _, _)| teid)
                    .unwrap_or(0);
                apply_create_session_response(&data, local_teid, sequence_number, peer)
            }
            Err(e) => log::error!("S11 Create Session Response from {peer} unparsable: {e:?}"),
        },
        mt::MODIFY_BEARER_RESPONSE => match handle_modify_bearer_response(raw) {
            Ok(data) => log::info!(
                "S11 Modify Bearer Response from {peer} (seq={sequence_number}) cause={}",
                data.cause
            ),
            Err(e) => log::error!("S11 Modify Bearer Response from {peer} unparsable: {e:?}"),
        },
        mt::DELETE_SESSION_RESPONSE => match handle_delete_session_response(raw) {
            Ok(data) => log::info!(
                "S11 Delete Session Response from {peer} (seq={sequence_number}) cause={}",
                data.cause
            ),
            Err(e) => log::error!("S11 Delete Session Response from {peer} unparsable: {e:?}"),
        },
        mt::RELEASE_ACCESS_BEARERS_RESPONSE => match handle_release_access_bearers_response(raw) {
            Ok(data) => log::info!(
                "S11 Release Access Bearers Response from {peer} (seq={sequence_number}) \
                     cause={}",
                data.cause
            ),
            Err(e) => {
                log::error!("S11 Release Access Bearers Response from {peer} unparsable: {e:?}")
            }
        },
        other => log::info!(
            "S11 triggered message type={other} seq={sequence_number} from {peer} correlated but \
             not acted on: this MME has no handler for it"
        ),
    }
}

/// Apply a Create Session Response to the session and bearer it answers.
///
/// This is what makes the response *useful* rather than merely received: the SGW's
/// S11 control F-TEID is what every later Modify Bearer / Delete Session Request has
/// to be addressed to, and the S1-U F-TEID plus the PAA are what the Initial Context
/// Setup and the ESM Activate Default Bearer Context Request carry to the UE.
///
/// The session is found by the LOCAL S11 TEID the response is addressed to
/// (`mme_ue_find_by_s11_local_teid`), not by anything in the body: the TEID in the
/// header is the one this MME told the SGW to use, so it is the only field that
/// cannot be attributed to the wrong UE by a malformed body.
fn apply_create_session_response(
    data: &CreateSessionResponseData,
    local_teid: u32,
    sequence_number: u32,
    peer: SocketAddr,
) {
    let ctx = crate::context::mme_self();

    if data.cause != 16 {
        // TS 29.274 §8.4: 16 is "Request accepted". Anything else means no bearer
        // was created, and the UE is owed the mapped ESM cause rather than a wait.
        log::warn!(
            "S11 Create Session Response from {peer} (seq={sequence_number}) rejected: GTP cause \
             {} -> ESM cause {}",
            data.cause,
            esm_cause_from_gtp(data.cause)
        );
        return;
    }

    let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(local_teid) else {
        log::warn!(
            "S11 Create Session Response for local TEID {local_teid:#x} matches no UE context"
        );
        return;
    };

    if let Ok(mut pool) = ctx.mme_ue_pool.write() {
        if let Some(ue) = pool.get_mut(&mme_ue_id) {
            log::info!(
                "[{}] S11 session created: SGW S11 C-TEID {:#x}",
                ue.imsi_bcd,
                data.sgw_s11_teid
            );
        }
    }
    ctx.set_sgw_s11_teid_for_ue(mme_ue_id, data.sgw_s11_teid);

    for bearer in &data.bearer_contexts {
        if !ctx.set_sgw_s1u_for_bearer(
            mme_ue_id,
            bearer.ebi,
            bearer.sgw_s1u_teid,
            bearer.sgw_s1u_ipv4,
        ) {
            log::warn!(
                "S11 Create Session Response named EBI {} which this UE does not hold",
                bearer.ebi
            );
        }
    }

    // #329: continue the procedure that asked for this session. Everything above is
    // bookkeeping the response supplies; everything below is the UE's answer, which
    // before #329 was never sent because nothing tracked what the request was for.
    let Some(pending) = crate::gtp_path::take_pending_create(sequence_number) else {
        // Either a response to a request this MME did not send, or a duplicate whose
        // record a first copy already consumed. Both are reasons not to continue: the
        // TEIDs above are idempotent, an Attach Accept is not.
        log::debug!(
            "S11 Create Session Response (seq={sequence_number}) has no pending create \
             record; TEIDs applied, no procedure continued"
        );
        return;
    };

    // The PAA is the UE's IP address, and it is the reason the UE attached at all.
    // Stored BEFORE the Attach Accept is built: `esm_build::encode_pdn_address` reads
    // `sess.paa`, so an accept built first would carry an unset address and the UE
    // would complete an attach with no usable bearer.
    store_paa(ctx, pending.sess_id, data);

    match pending.create_action {
        crate::s11_build::GtpCreateAction::AttachRequest => {
            continue_attach(ctx, mme_ue_id, &pending);
        }
        other => {
            // A TAU, a standalone PDN connectivity request and a path switch each have
            // their own continuation, and none of them is an Attach Accept. Naming the
            // action rather than staying silent, because "session created and nothing
            // happened" is otherwise indistinguishable from a missing call site — which
            // is exactly the defect #329 fixed.
            log::info!(
                "S11 session created for create action {other:?}; no attach continuation \
                 applies (its own procedure owns the next step)"
            );
        }
    }
}

/// Store the PDN Address Allocation the PGW granted on the session (#329).
///
/// The PDN type is taken from the response rather than from what the UE requested:
/// TS 29.274 §8.14 lets the network grant a narrower type than was asked for (an
/// IPv4v6 request answered with IPv4 only), and honouring the request instead would
/// have the MME tell the UE it has an address family the PGW did not allocate.
fn store_paa(ctx: &crate::context::MmeContext, sess_id: u64, data: &CreateSessionResponseData) {
    use crate::esm_build::PdnType;

    let pdn_type = match data.paa_pdn_type {
        1 => PdnType::Ipv4,
        2 => PdnType::Ipv6,
        3 => PdnType::Ipv4v6,
        5 => PdnType::NonIp,
        6 => PdnType::Ethernet,
        other => {
            log::warn!(
                "S11 Create Session Response carried PDN type {other}, which TS 29.274 §8.14 \
                 does not define; treating the session as having no allocated address"
            );
            return;
        }
    };

    let Ok(mut pool) = ctx.sess_pool.write() else {
        log::error!("session pool poisoned; PAA not stored");
        return;
    };
    let Some(sess) = pool.get_mut(&sess_id) else {
        log::warn!("S11 Create Session Response PAA is for session {sess_id}, which is gone");
        return;
    };
    sess.paa.pdn_type = pdn_type;
    if let Some(v4) = data.paa_ipv4 {
        sess.paa.addr = v4;
    }
    if let Some(v6) = data.paa_ipv6 {
        sess.paa.addr6 = v6;
    }
    log::info!(
        "S11 PAA stored on session {sess_id}: pdn_type={pdn_type:?}, ipv4={:?}",
        data.paa_ipv4
    );
}

/// Answer the UE that started this attach: Initial Context Setup carrying the Attach
/// Accept (#329, TS 23.401 §5.3.2.1 steps 16-17).
///
/// `nas_eps_send_attach_accept` builds the ESM Activate Default Bearer Context Request,
/// the EMM Attach Accept, applies NAS security AND wraps the result in an Initial
/// Context Setup Request, so this one call is the whole step rather than half of it.
fn continue_attach(
    ctx: &crate::context::MmeContext,
    mme_ue_id: u64,
    pending: &crate::gtp_path::PendingCreate,
) {
    let Some(sess) = ctx.sess_find_by_id(pending.sess_id) else {
        log::warn!("attach continuation: session {} is gone", pending.sess_id);
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(pending.enb_ue_id) else {
        // The S1 context went away while the SGW was answering — the UE is no longer
        // reachable, so there is nowhere to send the accept.
        log::warn!(
            "attach continuation: eNB UE context {} is gone, so the Attach Accept has \
             nowhere to go",
            pending.enb_ue_id
        );
        return;
    };
    // The DEFAULT bearer, which is the one the Initial Context Setup builds an E-RAB
    // for. Taken as the session's lowest EBI: TS 24.301 §6.4.1 makes the default
    // bearer the first activated for the PDN connection.
    let Some(bearer) = sess
        .bearer_list
        .iter()
        .filter_map(|id| ctx.bearer_find_by_id(*id))
        .min_by_key(|b| b.ebi)
    else {
        log::warn!(
            "attach continuation: session {} holds no bearer to build an E-RAB from",
            pending.sess_id
        );
        return;
    };

    let Ok(mut pool) = ctx.mme_ue_pool.write() else {
        log::error!("UE pool poisoned; Attach Accept not sent");
        return;
    };
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        log::warn!("attach continuation: UE context {mme_ue_id} is gone");
        return;
    };

    match crate::nas_path::nas_eps_send_attach_accept(mme_ue, &enb_ue, &sess, &bearer) {
        Ok(()) => log::info!(
            "[{}] Attach Accept sent in an Initial Context Setup Request (EBI {})",
            mme_ue.imsi_bcd,
            bearer.ebi
        ),
        Err(e) => log::error!("[{}] Attach Accept failed: {e:?}", mme_ue.imsi_bcd),
    }
}

/// Route an initial message the SGW-C originated.
pub fn dispatch_initial(raw: &[u8], msg_type: u8, sequence_number: u32, peer: SocketAddr) {
    use crate::s11_build::message_type as mt;

    match msg_type {
        mt::DOWNLINK_DATA_NOTIFICATION => match handle_downlink_data_notification(raw) {
            Ok(data) => {
                log::info!(
                    "S11 Downlink Data Notification from {peer} (seq={sequence_number}) for EBI {}",
                    data.ebi
                );
                // TS 29.274 §7.2.11: the Ack is a TRIGGERED message and must echo
                // the notification's sequence number. Before #51 the Ack builder was
                // called with `ctx.next_pool_id()` in the sequence position, which is
                // a pool index — so even if it had been transmitted, the SGW-C could
                // not have matched it to the notification it answered.
                let local_teid = parse_gtp_header(raw)
                    .map(|(_, teid, _, _)| teid)
                    .unwrap_or(0);
                if let Err(e) = crate::gtp_path::send_downlink_data_notification_ack_to(
                    peer,
                    local_teid,
                    sequence_number,
                    crate::s11_build::GtpCause::RequestAccepted,
                ) {
                    log::error!("S11 Downlink Data Notification Ack to {peer} failed: {e}");
                }
            }
            Err(e) => log::error!("S11 Downlink Data Notification from {peer} unparsable: {e:?}"),
        },
        other => log::info!(
            "S11 initial message type={other} seq={sequence_number} from {peer} not handled: this \
             MME originates no procedure for it"
        ),
    }
}

// ============================================================================
// Parsing Helper Functions
// ============================================================================

/// Parse GTP-C message header
pub fn parse_gtp_header(data: &[u8]) -> S11Result<(u8, u32, u32, &[u8])> {
    if data.len() < 8 {
        return Err(S11Error::InvalidMessageFormat);
    }

    let flags = data[0];
    let msg_type = data[1];
    let has_teid = (flags & 0x08) != 0;

    if has_teid {
        if data.len() < 12 {
            return Err(S11Error::InvalidMessageFormat);
        }
        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq_num = ((data[8] as u32) << 16) | ((data[9] as u32) << 8) | (data[10] as u32);
        let payload = &data[12..];
        Ok((msg_type, teid, seq_num, payload))
    } else {
        let seq_num = ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32);
        let payload = &data[8..];
        Ok((msg_type, 0, seq_num, payload))
    }
}

/// Parse IE header
pub fn parse_ie_header(data: &[u8]) -> Option<(u8, u16, u8, &[u8])> {
    if data.len() < 4 {
        return None;
    }

    let ie_type = data[0];
    let length = u16::from_be_bytes([data[1], data[2]]);
    let instance = data[3] & 0x0f;

    if data.len() < 4 + length as usize {
        return None;
    }

    let value = &data[4..4 + length as usize];
    Some((ie_type, length, instance, value))
}

/// Parse F-TEID IE
pub fn parse_f_teid(data: &[u8]) -> Option<(u8, u32, Option<[u8; 4]>, Option<[u8; 16]>)> {
    if data.len() < 5 {
        return None;
    }

    let flags = data[0];
    let interface_type = flags & 0x3f;
    let has_v4 = (flags & 0x80) != 0;
    let has_v6 = (flags & 0x40) != 0;

    let teid = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    let mut offset = 5;
    let ipv4 = if has_v4 {
        if data.len() < offset + 4 {
            return None;
        }
        let addr = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        offset += 4;
        Some(addr)
    } else {
        None
    };

    let ipv6 = if has_v6 {
        if data.len() < offset + 16 {
            return None;
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[offset..offset + 16]);
        Some(addr)
    } else {
        None
    };

    Some((interface_type, teid, ipv4, ipv6))
}

/// Parse Cause IE
pub fn parse_cause(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    Some(data[0])
}

/// Parse EBI IE
pub fn parse_ebi(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    Some(data[0] & 0x0f)
}

/// Parse PAA IE
pub fn parse_paa(data: &[u8]) -> Option<(u8, Option<[u8; 4]>, Option<[u8; 16]>)> {
    if data.is_empty() {
        return None;
    }

    let pdn_type = data[0] & 0x07;

    match pdn_type {
        1 => {
            // IPv4
            if data.len() < 5 {
                return None;
            }
            let addr = [data[1], data[2], data[3], data[4]];
            Some((pdn_type, Some(addr), None))
        }
        2 => {
            // IPv6
            if data.len() < 18 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[2..18]);
            Some((pdn_type, None, Some(addr)))
        }
        3 => {
            // IPv4v6
            if data.len() < 22 {
                return None;
            }
            let mut addr6 = [0u8; 16];
            addr6.copy_from_slice(&data[2..18]);
            let addr4 = [data[18], data[19], data[20], data[21]];
            Some((pdn_type, Some(addr4), Some(addr6)))
        }
        _ => Some((pdn_type, None, None)),
    }
}

/// Parse AMBR IE
pub fn parse_ambr(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 8 {
        return None;
    }

    let uplink = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64 * 1000;
    let downlink = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64 * 1000;

    Some((uplink, downlink))
}

/// Parse Bearer QoS IE
pub fn parse_bearer_qos(data: &[u8]) -> Option<(u8, u8, u8, u8, u64, u64, u64, u64)> {
    if data.len() < 22 {
        return None;
    }

    let arp = data[0];
    let arp_pec = (arp >> 6) & 0x01;
    let arp_priority = (arp >> 2) & 0x0f;
    let arp_pev = arp & 0x01;

    let qci = data[1];

    let mbr_ul = parse_bitrate(&data[2..7]);
    let mbr_dl = parse_bitrate(&data[7..12]);
    let gbr_ul = parse_bitrate(&data[12..17]);
    let gbr_dl = parse_bitrate(&data[17..22]);

    Some((
        qci,
        arp_priority,
        arp_pec,
        arp_pev,
        mbr_ul,
        mbr_dl,
        gbr_ul,
        gbr_dl,
    ))
}

/// Parse bitrate from 5-byte format
fn parse_bitrate(data: &[u8]) -> u64 {
    if data.len() < 5 {
        return 0;
    }
    let kbps = ((data[0] as u64) << 32)
        | ((data[1] as u64) << 24)
        | ((data[2] as u64) << 16)
        | ((data[3] as u64) << 8)
        | (data[4] as u64);
    kbps * 1000
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle Echo Request
pub fn handle_echo_request(recovery: u8) -> S11Result<u8> {
    Ok(recovery)
}

/// Handle Echo Response
pub fn handle_echo_response(recovery: u8) -> S11Result<u8> {
    Ok(recovery)
}

/// Handle Create Session Response
pub fn handle_create_session_response(data: &[u8]) -> S11Result<CreateSessionResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;

    if msg_type != message_type::CREATE_SESSION_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = CreateSessionResponseData::default();
    let mut offset = 0;

    while offset < payload.len() {
        if let Some((ie_t, length, instance, value)) = parse_ie_header(&payload[offset..]) {
            match ie_t {
                ie_type::CAUSE => {
                    if let Some(cause) = parse_cause(value) {
                        result.cause = cause;
                    }
                }
                ie_type::F_TEID => {
                    if let Some((iface_type, teid, ipv4, _)) = parse_f_teid(value) {
                        match (iface_type, instance) {
                            (11, 0) => {
                                result.sgw_s11_teid = teid;
                                result.sgw_s11_ipv4 = ipv4;
                            }
                            (7, 1) => {
                                result.pgw_s5c_teid = teid;
                                result.pgw_s5c_ipv4 = ipv4;
                            }
                            _ => {}
                        }
                    }
                }
                ie_type::PAA => {
                    if let Some((pdn_type, ipv4, ipv6)) = parse_paa(value) {
                        result.paa_pdn_type = pdn_type;
                        result.paa_ipv4 = ipv4;
                        result.paa_ipv6 = ipv6;
                    }
                }
                ie_type::AMBR => {
                    if let Some((ul, dl)) = parse_ambr(value) {
                        result.ambr_uplink = ul;
                        result.ambr_downlink = dl;
                    }
                }
                ie_type::PCO => {
                    result.pco = Some(value.to_vec());
                }
                ie_type::EPCO => {
                    result.epco = Some(value.to_vec());
                }
                _ => {}
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    if result.cause == 0 {
        return Err(S11Error::MandatoryIeMissing("Cause".to_string()));
    }

    Ok(result)
}

/// Handle Modify Bearer Response
pub fn handle_modify_bearer_response(data: &[u8]) -> S11Result<ModifyBearerResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;

    if msg_type != message_type::MODIFY_BEARER_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = ModifyBearerResponseData::default();
    let mut offset = 0;

    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    Ok(result)
}

/// Handle Delete Session Response
pub fn handle_delete_session_response(data: &[u8]) -> S11Result<DeleteSessionResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;

    if msg_type != message_type::DELETE_SESSION_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = DeleteSessionResponseData::default();
    let mut offset = 0;

    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    Ok(result)
}

/// Handle Release Access Bearers Response
pub fn handle_release_access_bearers_response(
    data: &[u8],
) -> S11Result<ReleaseAccessBearersResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;

    if msg_type != message_type::RELEASE_ACCESS_BEARERS_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = ReleaseAccessBearersResponseData::default();
    let mut offset = 0;

    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    Ok(result)
}

/// Act on a Downlink Data Notification: page the idle UE it names (issue #47).
///
/// TS 23.401 §5.3.4.3: the SGW has downlink data for a UE in ECM-IDLE, so the MME
/// pages it and answers the notification. The parser below has existed all along
/// with no action attached, so the notification was decoded and the data dropped.
///
/// The UE is found by the S11 TEID in the GTP header — the local TEID the MME gave
/// the SGW when the session was created. Returns the number of eNBs paged.
///
/// Nothing calls this yet in a running daemon: the S11 transport that would deliver
/// a DDN is #51. It is wired here rather than in that issue because the trigger
/// belongs to the paging procedure, and it is exercised by tests that hand it a
/// notification directly.
pub fn process_downlink_data_notification(
    ctx: &crate::context::MmeContext,
    data: &[u8],
) -> S11Result<usize> {
    let (_, _, teid, _) = parse_gtp_header(data)?;
    let notification = handle_downlink_data_notification(data)?;

    let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(teid) else {
        log::warn!("Downlink Data Notification for unknown S11 TEID 0x{teid:08x}");
        return Err(S11Error::ContextNotFound);
    };

    log::info!(
        "Downlink data for idle UE {mme_ue_id} on EBI {}; paging",
        notification.ebi
    );
    Ok(crate::paging::page_ue(
        ctx,
        mme_ue_id,
        crate::context::PagingType::DownlinkDataNotification,
    ))
}

/// Handle Downlink Data Notification
pub fn handle_downlink_data_notification(data: &[u8]) -> S11Result<DownlinkDataNotificationData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;

    if msg_type != message_type::DOWNLINK_DATA_NOTIFICATION {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = DownlinkDataNotificationData::default();
    let mut offset = 0;

    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            match ie_t {
                ie_type::EBI => {
                    if let Some(ebi) = parse_ebi(value) {
                        result.ebi = ebi;
                    }
                }
                ie_type::CAUSE => {
                    if let Some(cause) = parse_cause(value) {
                        result.cause = Some(cause);
                    }
                }
                _ => {}
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    if result.ebi == 0 {
        return Err(S11Error::MandatoryIeMissing("EPS Bearer ID".to_string()));
    }

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s11_build::*;

    #[test]
    fn test_esm_cause_from_gtp() {
        assert_eq!(
            esm_cause_from_gtp(64),
            esm_cause::INVALID_EPS_BEARER_IDENTITY
        );
        assert_eq!(
            esm_cause_from_gtp(68),
            esm_cause::SERVICE_OPTION_NOT_SUPPORTED
        );
        assert_eq!(esm_cause_from_gtp(0), esm_cause::NETWORK_FAILURE);
    }

    #[test]
    fn test_handle_echo_request() {
        let result = handle_echo_request(5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    /// The builders return a `Gtp2Message` since #51, so these encode through the
    /// library and then parse with THIS module's header reader — which is exactly the
    /// pairing the live path uses, and therefore the thing worth pinning.
    #[test]
    fn test_parse_gtp_header_with_teid() {
        let encoded = build_release_access_bearers_request(0x12345678, 100).encode();
        let (msg_type, teid, seq_num, _) = parse_gtp_header(&encoded).unwrap();

        assert_eq!(msg_type, message_type::RELEASE_ACCESS_BEARERS_REQUEST);
        assert_eq!(teid, 0x12345678);
        assert_eq!(seq_num, 100);
    }

    #[test]
    fn test_parse_gtp_header_no_teid() {
        let encoded = nextgcore_gtp::v2::Gtp2Message::echo_request(123).encode();
        let (msg_type, teid, seq_num, _) = parse_gtp_header(&encoded).unwrap();

        assert_eq!(msg_type, message_type::ECHO_REQUEST);
        assert_eq!(teid, 0);
        assert_eq!(seq_num, 123);
    }

    /// #51 criterion 6: GTP cause 78 must reach the UE as ESM cause 27, not as
    /// `NETWORK_FAILURE`.
    ///
    /// The difference is what the subscriber's handset does next. `NETWORK_FAILURE`
    /// invites a retry of a request that can never succeed; `MISSING_OR_UNKNOWN_APN`
    /// names the misconfiguration, which is the only thing an operator can act on.
    #[test]
    fn gtp_cause_78_maps_to_missing_or_unknown_apn() {
        assert_eq!(
            esm_cause_from_gtp(78),
            esm_cause::MISSING_OR_UNKNOWN_APN,
            "GTP 78 must not degrade to NETWORK_FAILURE"
        );
        assert_ne!(esm_cause_from_gtp(78), esm_cause::NETWORK_FAILURE);
    }

    /// Every GTP cause with a distinct ESM meaning keeps it, so adding a mapping
    /// cannot silently collapse a neighbouring one.
    #[test]
    fn distinct_gtp_causes_keep_distinct_esm_causes() {
        for (gtp, esm) in [
            (64u8, esm_cause::INVALID_EPS_BEARER_IDENTITY),
            (68, esm_cause::SERVICE_OPTION_NOT_SUPPORTED),
            (73, esm_cause::INSUFFICIENT_RESOURCES),
            (74, esm_cause::SEMANTIC_ERROR_IN_THE_TFT_OPERATION),
            (75, esm_cause::SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION),
            (76, esm_cause::SEMANTIC_ERRORS_IN_PACKET_FILTERS),
            (77, esm_cause::SYNTACTICAL_ERROR_IN_PACKET_FILTERS),
            (78, esm_cause::MISSING_OR_UNKNOWN_APN),
            (94, esm_cause::REQUEST_REJECTED_BY_SERVING_GW_OR_PDN_GW),
        ] {
            assert_eq!(
                esm_cause_from_gtp(gtp),
                esm,
                "GTP cause {gtp} lost its distinct ESM mapping"
            );
        }
        // A cause TS 29.274 does not define really is a network failure.
        assert_eq!(esm_cause_from_gtp(200), esm_cause::NETWORK_FAILURE);
    }

    #[test]
    fn test_parse_cause() {
        assert_eq!(parse_cause(&[16]), Some(16));
        assert_eq!(parse_cause(&[64]), Some(64));
        assert_eq!(parse_cause(&[]), None);
    }

    #[test]
    fn test_parse_ebi() {
        assert_eq!(parse_ebi(&[5]), Some(5));
        assert_eq!(parse_ebi(&[0x15]), Some(5));
        assert_eq!(parse_ebi(&[]), None);
    }

    #[test]
    fn test_parse_paa_ipv4() {
        let data = [1, 10, 0, 0, 1];
        let (pdn_type, ipv4, ipv6) = parse_paa(&data).unwrap();
        assert_eq!(pdn_type, 1);
        assert_eq!(ipv4, Some([10, 0, 0, 1]));
        assert!(ipv6.is_none());
    }

    #[test]
    fn test_parse_ambr() {
        let data = [0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x4E, 0x20];
        let (ul, dl) = parse_ambr(&data).unwrap();
        assert_eq!(ul, 10_000_000);
        assert_eq!(dl, 20_000_000);
    }

    #[test]
    fn test_parse_f_teid() {
        let data = [0x80 | 11, 0x12, 0x34, 0x56, 0x78, 192, 168, 1, 1];
        let (iface_type, teid, ipv4, ipv6) = parse_f_teid(&data).unwrap();
        assert_eq!(iface_type, 11);
        assert_eq!(teid, 0x12345678);
        assert_eq!(ipv4, Some([192, 168, 1, 1]));
        assert!(ipv6.is_none());
    }
    // ------------------------------------------------------------------
    // Create Session Response continuation (#329)
    // ------------------------------------------------------------------
    //
    // These drive `apply_create_session_response` against the PROCESS-GLOBAL
    // `mme_self()` context, which is what the live path uses, so they hold
    // `gtp_path::S11_TEST_LOCK` — the one agreement about the S11 globals, shared with
    // `gtp_path`'s own tests rather than re-declared here (a second lock over the same
    // variables hung the suite in #276).

    /// Seed the GLOBAL context with one UE, session and default bearer, and return
    /// `(mme_ue_id, enb_ue_id, sess_id, bearer_id, local_s11_teid)`.
    ///
    /// The local S11 TEID is READ BACK from the context rather than chosen: `mme_ue_add`
    /// allocates it and registers it in `mme_s11_teid_hash`, and writing the field
    /// directly would leave the index pointing elsewhere — a fixture that disagrees with
    /// itself and reproduces by hand the exact defect #329 fixed.
    fn seed_global_ue(ebi: u8) -> (u64, u64, u64, u64, u32) {
        let ctx = crate::context::mme_self();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 300);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
        let local_teid = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("the UE just added")
            .mme_s11_teid;
        assert_ne!(local_teid, 0, "mme_ue_add must allocate an S11 TEID");

        let sess_id = ctx.sess_add(mme_ue_id, 9);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        if let Ok(mut pool) = ctx.mme_ue_pool.write() {
            if let Some(ue) = pool.get_mut(&mme_ue_id) {
                ue.sgw_ue_id = sgw_ue_id;
                ue.imsi_bcd = format!("99970000000{mme_ue_id:04}");
                ue.sess_list.push(sess_id);
            }
        }
        if let Ok(mut pool) = ctx.sess_pool.write() {
            if let Some(sess) = pool.get_mut(&sess_id) {
                sess.apn = "internet".to_string();
                sess.bearer_list.push(bearer_id);
            }
        }
        if let Ok(mut pool) = ctx.bearer_pool.write() {
            if let Some(bearer) = pool.get_mut(&bearer_id) {
                bearer.ebi = ebi;
                bearer.qos.qci = 9;
                bearer.qos.arp.priority_level = 8;
            }
        }
        (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid)
    }

    /// Release what `seed_global_ue` added, so the shared global context does not
    /// accumulate UEs across the suite.
    fn release_global_ue(mme_ue_id: u64, sess_id: u64, bearer_id: u64) {
        let ctx = crate::context::mme_self();
        ctx.bearer_remove(bearer_id);
        ctx.sess_remove(sess_id);
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// An accepted Create Session Response carrying a PAA and one bearer context.
    fn accepted_response(ebi: u8, paa: [u8; 4]) -> CreateSessionResponseData {
        CreateSessionResponseData {
            cause: 16,
            sgw_s11_teid: 0x0000_ABCD,
            paa_pdn_type: 1, // IPv4
            paa_ipv4: Some(paa),
            bearer_contexts: vec![BearerContextCreated {
                ebi,
                cause: 16,
                sgw_s1u_teid: 0x0000_1111,
                sgw_s1u_ipv4: Some([10, 0, 0, 9]),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// The PAA is the UE's IP address, and it was being DROPPED: the response was
    /// parsed into `paa_ipv4` and never written to the session, so an Attach Accept
    /// would have carried an unset PDN address.
    #[test]
    fn the_paa_from_a_create_session_response_reaches_the_session() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let ctx = crate::context::mme_self();
        assert_eq!(
            ctx.sess_find_by_id(sess_id).unwrap().paa.addr,
            [0, 0, 0, 0],
            "precondition: the session has no allocated address before the response"
        );

        // A pending record is required for the continuation to run at all, which is
        // what carries the create action.
        crate::gtp_path::record_pending_create_for_test(
            4242,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );

        apply_create_session_response(
            &accepted_response(5, [10, 45, 0, 7]),
            local_teid,
            4242,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let sess = ctx.sess_find_by_id(sess_id).expect("session");
        assert_eq!(
            sess.paa.addr,
            [10, 45, 0, 7],
            "the PGW-allocated address must be stored on the session"
        );
        assert_eq!(sess.paa.pdn_type, crate::esm_build::PdnType::Ipv4);

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// The PDN type comes from the RESPONSE, not from what the UE asked for.
    ///
    /// TS 29.274 §8.14 lets the network grant a narrower type than requested, and
    /// honouring the request would tell the UE it has an address family the PGW never
    /// allocated.
    #[test]
    fn an_undefined_pdn_type_leaves_the_session_without_an_address() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        crate::gtp_path::record_pending_create_for_test(
            4243,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );

        let mut data = accepted_response(5, [10, 45, 0, 8]);
        data.paa_pdn_type = 7; // not defined by TS 29.274 §8.14
        apply_create_session_response(&data, local_teid, 4243, "127.0.0.1:2123".parse().unwrap());

        assert_eq!(
            crate::context::mme_self()
                .sess_find_by_id(sess_id)
                .unwrap()
                .paa
                .addr,
            [0, 0, 0, 0],
            "an undefined PDN type must not be paired with the address anyway"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// An `AttachRequest` create action reaches the Attach Accept; the encoded message
    /// is left in T3450's retransmission buffer, which is where the UE's copy lives.
    ///
    /// Asserted from `mme_ue.t3450` — the UE context's own state — rather than from a
    /// log line or from the S1AP send queue: `s1ap_path::install_send_queue` is
    /// once-per-process and a sibling test already consumes that slot, so the queue is
    /// not a reliable observable here.
    #[test]
    fn an_attach_create_action_drives_the_attach_accept() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        // EBI 7, not 5: the simplified builder fabricates 5, so with 5 the wrong and
        // right answers coincide and the assertion below could not tell them apart.
        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(7);
        let ctx = crate::context::mme_self();
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .t3450
                .pkbuf
                .is_none(),
            "precondition: T3450 holds nothing before the accept"
        );

        crate::gtp_path::record_pending_create_for_test(
            4244,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );
        apply_create_session_response(
            &accepted_response(7, [10, 45, 0, 9]),
            local_teid,
            4244,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let pkbuf = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .t3450
            .pkbuf
            .expect("an attach continuation must leave the Attach Accept in T3450");
        assert!(
            !pkbuf.is_empty(),
            "the buffered Attach Accept must carry the encoded message"
        );

        // And it must carry the ESM message built from THIS session's REAL bearer.
        //
        // Asserted as a subsequence of what the production path buffered, not by
        // calling the builder and checking the builder's own output: a direct builder
        // assertion passes whichever builder `nas_eps_send_attach_accept` chose, which
        // is how the fabricated-EBI defect survived. Reverting the accept path to the
        // simplified builder makes this fail, because that one names EBI 5.
        let sess = ctx.sess_find_by_id(sess_id).expect("session");
        let bearer = ctx.bearer_find_by_id(bearer_id).expect("bearer");
        assert_eq!(bearer.ebi, 7, "precondition: not the fabricated EBI 5");
        let expected_esm =
            crate::esm_build::build_activate_default_bearer_context_request_with_params(
                &sess,
                &bearer,
                crate::esm_build::CreateAction::InAttachRequest,
            );
        assert!(
            pkbuf
                .windows(expected_esm.len())
                .any(|w| w == expected_esm.as_slice()),
            "the buffered Attach Accept must contain the ESM Activate Default Bearer \
             Context Request for the session's own bearer (EBI {}); it did not, so the \
             accept was built from a different bearer than the MME created",
            bearer.ebi
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// A NON-attach create action must NOT produce an Attach Accept.
    ///
    /// A TAU, a standalone PDN connectivity request and a path switch each own their
    /// continuation; emitting an Attach Accept for any of them would answer a procedure
    /// the UE did not start. This is the gate the revert table exercises.
    #[test]
    fn a_tau_create_action_does_not_drive_the_attach_accept() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        crate::gtp_path::record_pending_create_for_test(
            4245,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::TrackingAreaUpdate,
                enb_ue_id,
                sess_id,
            },
        );
        apply_create_session_response(
            &accepted_response(5, [10, 45, 0, 10]),
            local_teid,
            4245,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let ctx = crate::context::mme_self();
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .t3450
                .pkbuf
                .is_none(),
            "a TAU-triggered session creation must NOT emit an Attach Accept"
        );
        // The bookkeeping still happened: the TEIDs and the PAA are the response's
        // content regardless of which procedure asked for them.
        assert_eq!(
            ctx.sess_find_by_id(sess_id).unwrap().paa.addr,
            [10, 45, 0, 10],
            "the PAA belongs to the session whichever procedure created it"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// A response with no pending record applies the TEIDs and continues NOTHING.
    ///
    /// That covers a duplicate (whose record the first copy consumed) and a response to
    /// a request this MME never sent. The TEIDs are idempotent; an Attach Accept is not.
    #[test]
    fn a_response_without_a_pending_record_continues_nothing() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, _enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        apply_create_session_response(
            &accepted_response(5, [10, 45, 0, 11]),
            local_teid,
            9999, // no record was ever made for this sequence
            "127.0.0.1:2123".parse().unwrap(),
        );

        let ctx = crate::context::mme_self();
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .t3450
                .pkbuf
                .is_none(),
            "an uncorrelated response must not drive a procedure"
        );
        assert_eq!(
            ctx.sess_find_by_id(sess_id).unwrap().paa.addr,
            [0, 0, 0, 0],
            "and it must not store a PAA either: without a record there is no session \
             to attribute it to, so the store is skipped with the continuation"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
    }

    /// The Attach Accept's ESM Activate Default Bearer Context Request must carry the
    /// PGW-allocated address AND the session's real EBI, asserted from the ENCODED
    /// NAS bytes.
    ///
    /// Built through `build_activate_default_bearer_context_request_with_params` —
    /// **the same function `nas_eps_send_attach_accept` calls** — rather than through
    /// the simplified `build_activate_default_bearer_context_request` helper. The
    /// helper fabricates `ebi: 5` because it has no bearer to name, so asserting
    /// against it would be testing a function production no longer uses on this path,
    /// and would pass whatever the wiring did.
    ///
    /// EBI 7, not 5: with 5 the fabricated value and the real one coincide, so the
    /// assertion would hold for the pre-#329 call too.
    #[test]
    fn the_activate_default_bearer_request_carries_the_stored_paa_and_real_ebi() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(7);
        crate::gtp_path::record_pending_create_for_test(
            4246,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );
        apply_create_session_response(
            &accepted_response(7, [10, 45, 0, 12]),
            local_teid,
            4246,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let ctx = crate::context::mme_self();
        let sess = ctx.sess_find_by_id(sess_id).expect("session");
        let bearer = ctx.bearer_find_by_id(bearer_id).expect("bearer");
        assert_eq!(
            bearer.ebi, 7,
            "precondition: the real EBI is not the fabricated 5"
        );

        let esm = crate::esm_build::build_activate_default_bearer_context_request_with_params(
            &sess,
            &bearer,
            crate::esm_build::CreateAction::InAttachRequest,
        );

        // The four address octets appear contiguously in the encoded PDN Address IE.
        assert!(
            esm.windows(4).any(|w| w == [10, 45, 0, 12]),
            "the encoded Activate Default Bearer Context Request must carry the \
             PGW-allocated address; found none in {esm:02x?}"
        );
        // This module writes the EPS bearer identity as a WHOLE octet followed by the
        // protocol discriminator (`esm_build.rs:559-560`), rather than packing both into
        // octet 1 as TS 24.301 §9.3.1 does. That spelling is this build's existing
        // convention across every ESM builder and is not #329's to change; the
        // assertion follows the code's actual layout rather than the spec's, and says so.
        assert_eq!(
            esm.first().copied(),
            Some(7),
            "the message must name the bearer the MME actually created, not a \
             fabricated EBI 5"
        );
        assert_eq!(
            esm.get(1).copied(),
            Some(crate::emm_build::NAS_PROTOCOL_DISCRIMINATOR_ESM),
            "and the octet after it is the ESM discriminator, which is what makes the \
             first one the bearer identity rather than a coincidence"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// The simplified helper must NOT panic on a session with no subscribed QoS.
    ///
    /// It used to `.expect("value expected")` on `sess.session`, which is absent for
    /// any session the HSS has not populated — a reachable panic on the Attach Accept
    /// path, surviving only because that path had no caller. A crashing MME is worse
    /// than a default-QoS bearer.
    #[test]
    fn a_session_without_subscribed_qos_does_not_panic_the_esm_builder() {
        let sess = crate::context::MmeSess {
            apn: "internet".to_string(),
            ..Default::default()
        };
        assert!(
            sess.session.is_none(),
            "precondition: no subscription record, as an un-provisioned session has"
        );
        let esm = crate::esm_build::build_activate_default_bearer_context_request(
            &sess,
            crate::nas_path::GtpCreateAction::InAttachRequest,
        );
        assert!(!esm.is_empty(), "it must still produce a message");
    }
}
