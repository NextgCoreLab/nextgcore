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
    /// Change Reporting Action (TS 29.274 §8.61), when the PDN GW sent one.
    pub change_reporting_action: Option<u8>,
}

/// One bearer's forwarding endpoints from a Create Indirect Data Forwarding Tunnel
/// Response (TS 29.274 Table 7.2.19-2).
#[derive(Debug, Clone, Default)]
pub struct IndirectForwardingBearer {
    pub ebi: u8,
    pub cause: u8,
    /// SGW DL data-forwarding TEID (instance 0 or 3, interface type 23)
    pub sgw_dl_teid: u32,
    pub sgw_dl_ipv4: Option<[u8; 4]>,
    /// SGW UL data-forwarding TEID (instance 4 or 5, interface type 28)
    pub sgw_ul_teid: u32,
    pub sgw_ul_ipv4: Option<[u8; 4]>,
}

/// A parsed Create Indirect Data Forwarding Tunnel Response.
#[derive(Debug, Clone, Default)]
pub struct CreateIndirectTunnelResponseData {
    pub cause: u8,
    pub bearers: Vec<IndirectForwardingBearer>,
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
    /// Bearer Contexts modified (instance 0, Table 7.2.8-1), each with its own
    /// Cause (#730).
    pub bearer_contexts: Vec<BearerContextModified>,
    /// Bearer Contexts marked for removal (instance 1): the SGW does not hold
    /// these bearers, so they were not switched (#730).
    pub bearers_marked_for_removal: Vec<u8>,
    /// Change Reporting Action (TS 29.274 Table 7.2.8-1, §8.61), when the PDN
    /// GW starts or stops location change reporting here (#593).
    pub change_reporting_action: Option<u8>,
}

/// Parsed Change Notification Response (TS 29.274 §7.3.15, #593).
#[derive(Debug, Clone, Default)]
pub struct ChangeNotificationResponseData {
    pub cause: u8,
    /// Change Reporting Action (C, Table 7.3.15-1).
    pub change_reporting_action: Option<u8>,
}

/// Bearer context modified
#[derive(Debug, Clone, Default)]
pub struct BearerContextModified {
    pub ebi: u8,
    /// The bearer's own Cause; `None` when the context carries none.
    pub cause: Option<u8>,
}

/// The EBI and Cause of a grouped Bearer Context IE's `value`.
fn parse_bearer_context_ebi_cause(value: &[u8]) -> Option<BearerContextModified> {
    let mut bearer = BearerContextModified::default();
    let mut have_ebi = false;
    let mut offset = 0;
    while offset < value.len() {
        let Some((ie_t, length, _, inner)) = parse_ie_header(&value[offset..]) else {
            break;
        };
        match ie_t {
            ie_type::EBI => {
                if let Some(ebi) = parse_ebi(inner) {
                    bearer.ebi = ebi;
                    have_ebi = true;
                }
            }
            ie_type::CAUSE => bearer.cause = parse_cause(inner),
            _ => {}
        }
        offset += 4 + length as usize;
    }
    have_ebi.then_some(bearer)
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
            Ok(data) => {
                log::info!(
                    "S11 Modify Bearer Response from {peer} (seq={sequence_number}) cause={}",
                    data.cause
                );
                // #730: a Path Switch Request (or a completed S1 handover)
                // waits on this response (TS 23.401 §5.5.1.1.2 step 5).
                if let Some(pending) =
                    crate::gtp_path::take_pending_handover_modification(sequence_number)
                {
                    crate::handover_switch::on_modify_bearer_response(
                        crate::context::mme_self(),
                        pending,
                        &data,
                    );
                }
                // #584: an E-UTRAN initiated E-RAB modification waits on this
                // response for its confirm (TS 23.401 §5.4.7 step 5).
                if let Some(pending) =
                    crate::gtp_path::take_pending_erab_modification(sequence_number)
                {
                    if let Some(send) = crate::s1ap_handler::erab_modification_confirm(
                        crate::context::mme_self(),
                        pending,
                        &data,
                    ) {
                        crate::s1ap_path::s1ap_send(send);
                    }
                }
                // #593: the PDN GW may start or stop location change reporting in
                // a Modify Bearer Response too (Table 7.2.8-1).
                if data.change_reporting_action.is_some() {
                    let local_teid = parse_gtp_header(raw)
                        .map(|(_, teid, _, _)| teid)
                        .unwrap_or(0);
                    let ctx = crate::context::mme_self();
                    if let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(local_teid) {
                        if let Some(send) = apply_change_reporting_action(
                            ctx,
                            mme_ue_id,
                            &sessions_of_ue(ctx, mme_ue_id),
                            data.change_reporting_action,
                        ) {
                            crate::s1ap_path::s1ap_send(send);
                        }
                    }
                }
            }
            Err(e) => log::error!("S11 Modify Bearer Response from {peer} unparsable: {e:?}"),
        },
        mt::CHANGE_NOTIFICATION_RESPONSE => match handle_change_notification_response(raw) {
            Ok(data) => apply_change_notification_response(&data, sequence_number, peer),
            Err(e) => log::error!("S11 Change Notification Response from {peer} unparsable: {e:?}"),
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
        mt::CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE => {
            match handle_create_indirect_tunnel_response(raw) {
                Ok(data) => {
                    let local_teid = parse_gtp_header(raw)
                        .map(|(_, teid, _, _)| teid)
                        .unwrap_or(0);
                    apply_indirect_forwarding_response(&data, local_teid, peer)
                }
                Err(e) => log::error!(
                    "S11 Create Indirect Data Forwarding Tunnel Response from {peer} \
                     unparsable: {e:?}"
                ),
            }
        }
        // #591: the triggered Request of a Delete Bearer Command / Bearer Resource
        // Command. It closed the Command; it still needs its own answer.
        mt::DELETE_BEARER_REQUEST => handle_delete_bearer_request(raw, sequence_number, peer),
        // A Bearer Resource Command's triggered Create / Update Bearer Request is
        // handled exactly as the initial one would be.
        mt::CREATE_BEARER_REQUEST | mt::UPDATE_BEARER_REQUEST => {
            dispatch_initial(raw, msg_type, sequence_number, peer)
        }
        mt::DELETE_BEARER_FAILURE_INDICATION
        | mt::BEARER_RESOURCE_FAILURE_INDICATION
        | mt::MODIFY_BEARER_FAILURE_INDICATION => {
            let cause = failure_indication_cause(raw);
            log::warn!(
                "S11 Failure Indication type={msg_type} seq={sequence_number} from {peer}: the \
                 Command was refused, cause={cause:?} (TS 29.274 §7.2.6/§7.2.14.2/§7.2.17.2)"
            );
        }
        other => log::info!(
            "S11 triggered message type={other} seq={sequence_number} from {peer} correlated but \
             not acted on: this MME has no handler for it"
        ),
    }
}

/// The Cause value of a Failure Indication, if it carries one.
pub fn failure_indication_cause(raw: &[u8]) -> Option<u8> {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).ok()?;
    msg.get_ie(nextgcore_gtp::v2::Gtp2IeType::Cause as u8, 0)
        .and_then(|ie| ie.value.first().copied())
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
        reject_create_session(ctx, local_teid, sequence_number, data.cause);
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
        // TS 29.274 §8.4 / Table 7.2.2-2: a bearer context's own Cause says whether
        // THAT bearer was created. One that was not has no usable S1-U endpoint.
        if bearer.cause != 16 {
            log::warn!(
                "S11 Create Session Response: EBI {} not created (bearer cause {})",
                bearer.ebi,
                bearer.cause
            );
            continue;
        }
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

    // #584: the PDN GW's Change Reporting Action (TS 29.274 §8.61) is what asks
    // this MME for ECGI change reporting, which the eNB does with LOCATION
    // REPORTING CONTROL (TS 36.413 §8.11.1, TS 23.401 §5.9.2).
    //
    // #593: the action is kept on the PDN connection it came for, so a later
    // LOCATION REPORT is forwarded to this PDN GW (Change Notification Request).
    let created: Vec<u8> = data.bearer_contexts.iter().map(|b| b.ebi).collect();
    let sess_ids = sessions_of_bearers(ctx, mme_ue_id, &created);
    if let Some(send) =
        apply_change_reporting_action(ctx, mme_ue_id, &sess_ids, data.change_reporting_action)
    {
        crate::s1ap_path::s1ap_send(send);
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

/// The LOCATION REPORTING CONTROL a Change Reporting Action asks for (#584):
/// "Start Reporting ECGI" (4) or "Start Reporting TAI and ECGI" (6) start
/// change-of-serve-cell reporting at the serving eNB; "Stop Reporting" (0)
/// stops it if it is active. Every other action names a RAT or granularity
/// the eNB's location reporting does not serve (CGI/SAI, RAI, TAI alone,
/// macro eNB ID), and is not answered on S1.
pub fn location_reporting_for_action(
    ctx: &crate::context::MmeContext,
    mme_ue_id: u64,
    action: Option<u8>,
) -> Option<crate::s1ap_handler::S1apSend> {
    const STOP: u8 = 0;
    const START_ECGI: u8 = 4;
    const START_TAI_AND_ECGI: u8 = 6;
    match action? {
        START_ECGI | START_TAI_AND_ECGI => {
            crate::s1ap_handler::location_reporting_control(ctx, mme_ue_id, true)
        }
        // Another PDN GW of this UE may still want ECGI changes (#593).
        STOP if ctx
            .mme_ue_find_by_id(mme_ue_id)
            .is_some_and(|ue| ue.location_reporting_active)
            && !sessions_of_ue(ctx, mme_ue_id)
                .into_iter()
                .any(|id| reports_ecgi(session_action(ctx, id))) =>
        {
            crate::s1ap_handler::location_reporting_control(ctx, mme_ue_id, false)
        }
        other => {
            log::debug!("Change Reporting Action {other} needs no Location Reporting Control");
            None
        }
    }
}

/// Change Reporting Action values this MME acts on (TS 29.274 §8.61).
pub mod change_reporting_action {
    pub const STOP_REPORTING: u8 = 0;
    pub const START_REPORTING_TAI: u8 = 3;
    pub const START_REPORTING_ECGI: u8 = 4;
    pub const START_REPORTING_TAI_AND_ECGI: u8 = 6;
}

/// Whether `action` asks to be told about ECGI changes.
pub fn reports_ecgi(action: Option<u8>) -> bool {
    use change_reporting_action as a;
    matches!(
        action,
        Some(a::START_REPORTING_ECGI | a::START_REPORTING_TAI_AND_ECGI)
    )
}

/// Whether `action` asks to be told about TAI changes.
pub fn reports_tai(action: Option<u8>) -> bool {
    use change_reporting_action as a;
    matches!(
        action,
        Some(a::START_REPORTING_TAI | a::START_REPORTING_TAI_AND_ECGI)
    )
}

/// The stored Change Reporting Action of session `sess_id`.
fn session_action(ctx: &crate::context::MmeContext, sess_id: u64) -> Option<u8> {
    ctx.sess_find_by_id(sess_id)
        .and_then(|s| s.change_reporting_action)
}

/// Every PDN connection of `mme_ue_id`.
pub fn sessions_of_ue(ctx: &crate::context::MmeContext, mme_ue_id: u64) -> Vec<u64> {
    ctx.mme_ue_find_by_id(mme_ue_id)
        .map(|ue| ue.sess_list)
        .unwrap_or_default()
}

/// The PDN connections holding the bearers `ebis`, or, when none of them
/// names a known bearer, every PDN connection of the UE.
fn sessions_of_bearers(ctx: &crate::context::MmeContext, mme_ue_id: u64, ebis: &[u8]) -> Vec<u64> {
    let mut ids: Vec<u64> = ebis
        .iter()
        .filter_map(|ebi| ctx.bearer_find_by_ebi(mme_ue_id, *ebi))
        .filter_map(|id| ctx.bearer_find_by_id(id))
        .map(|b| b.sess_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        sessions_of_ue(ctx, mme_ue_id)
    } else {
        ids
    }
}

/// Store a PDN GW's Change Reporting Action on the PDN connections `sess_ids`
/// and drive the eNB's location reporting from it (#584, #593). An absent
/// action changes nothing (TS 29.274 §8.61 is sent only to start or stop).
pub fn apply_change_reporting_action(
    ctx: &crate::context::MmeContext,
    mme_ue_id: u64,
    sess_ids: &[u64],
    action: Option<u8>,
) -> Option<crate::s1ap_handler::S1apSend> {
    let action = action?;
    if let Ok(mut pool) = ctx.sess_pool.write() {
        for id in sess_ids {
            if let Some(sess) = pool.get_mut(id) {
                sess.change_reporting_action = Some(action);
            }
        }
    }
    location_reporting_for_action(ctx, mme_ue_id, Some(action))
}

/// The PDN connections of `mme_ue_id` whose PDN GW asked to be told about the
/// location change just stored (TS 23.401 §5.9.2): an ECGI change for "start
/// reporting ECGI" / "TAI and ECGI", a TAI change for "start reporting TAI" /
/// "TAI and ECGI".
pub fn sessions_to_notify(
    ctx: &crate::context::MmeContext,
    mme_ue_id: u64,
    tai_changed: bool,
    ecgi_changed: bool,
) -> Vec<u64> {
    sessions_of_ue(ctx, mme_ue_id)
        .into_iter()
        .filter(|id| {
            let action = session_action(ctx, *id);
            (ecgi_changed && reports_ecgi(action)) || (tai_changed && reports_tai(action))
        })
        .collect()
}

/// Act on a Change Notification Response (TS 29.274 §7.3.15, #593): a new
/// Change Reporting Action replaces the PDN connection's, and a refusal is
/// reported. "Context not found" is not acted on beyond the log, since tearing
/// down the PDN connection from here is a decision this MME does not own.
fn apply_change_notification_response(
    data: &ChangeNotificationResponseData,
    sequence_number: u32,
    peer: SocketAddr,
) {
    let ctx = crate::context::mme_self();
    let Some(sess_id) = crate::gtp_path::take_pending_change_notification(sequence_number) else {
        log::debug!(
            "S11 Change Notification Response seq={sequence_number} from {peer} has no pending \
             record"
        );
        return;
    };
    if data.cause != 16 {
        log::warn!(
            "S11 Change Notification Response from {peer} (seq={sequence_number}) refused the \
             location change for session {sess_id}: cause {}",
            data.cause
        );
    } else {
        log::info!(
            "S11 Change Notification Response from {peer} (seq={sequence_number}) accepted the \
             location change for session {sess_id}"
        );
    }
    let Some(mme_ue_id) = ctx.sess_find_by_id(sess_id).map(|s| s.mme_ue_id) else {
        return;
    };
    if let Some(send) =
        apply_change_reporting_action(ctx, mme_ue_id, &[sess_id], data.change_reporting_action)
    {
        crate::s1ap_path::s1ap_send(send);
    }
}

/// Answer the UE when the SGW/PGW refused its session (#492).
///
/// The rejection used to be logged and dropped, so the UE waited out T3410 (15 s)
/// and retried into the same failure. TS 24.301 §5.5.1.2.5 / §6.5.1.4 and TS 23.401
/// §5.3.2.1: when the default bearer cannot be established during an attach, the MME
/// sends ATTACH REJECT with EMM cause #19 "ESM failure" and the PDN CONNECTIVITY
/// REJECT (the mapped ESM cause) in the ESM container — `nas_eps_send_attach_reject`
/// then releases the UE context (#473). A standalone PDN connectivity request is
/// answered with PDN CONNECTIVITY REJECT on its own, and its session is discarded.
///
/// The pending-create record is taken here as on the accepted path, so a late
/// duplicate response cannot trigger a second answer.
fn reject_create_session(
    ctx: &crate::context::MmeContext,
    local_teid: u32,
    sequence_number: u32,
    gtp_cause: u8,
) {
    use crate::nas_path::GtpCreateAction as NasCreateAction;
    use crate::s11_build::GtpCreateAction;

    let Some(pending) = crate::gtp_path::take_pending_create(sequence_number) else {
        log::debug!(
            "rejected S11 Create Session Response (seq={sequence_number}) has no pending create \
             record; nothing to answer"
        );
        return;
    };
    let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(local_teid) else {
        log::warn!("rejected Create Session Response for local TEID {local_teid:#x} matches no UE");
        return;
    };
    let nas_action = match pending.create_action {
        GtpCreateAction::AttachRequest => NasCreateAction::InAttachRequest,
        GtpCreateAction::UplinkNasTransport => NasCreateAction::InPdnConnectivity,
        other => {
            // A TAU or a path switch owns its own failure handling; neither is
            // answered with an ESM reject.
            log::warn!(
                "Create Session for create action {other:?} rejected (GTP cause {gtp_cause}); \
                 that procedure handles the failure itself"
            );
            return;
        }
    };
    let (Some(enb_ue), Some(sess)) = (
        ctx.enb_ue_find_by_id(pending.enb_ue_id),
        ctx.sess_find_by_id(pending.sess_id),
    ) else {
        log::warn!(
            "rejected Create Session Response: the UE's S1 connection or session is gone, so the \
             reject has nowhere to go"
        );
        return;
    };
    let esm_cause = esm_cause_enum(esm_cause_from_gtp(gtp_cause));

    {
        // A snapshot, not a pool guard: a standalone PDN CONNECTIVITY REJECT is
        // protected under the live context, which takes the pool's write lock (#497).
        let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
            return;
        };
        log::warn!(
            "[{}] answering the refused PDN connection with ESM cause {esm_cause:?} ({:?})",
            mme_ue.imsi_bcd,
            nas_action
        );
        if let Err(e) = crate::nas_path::nas_eps_send_pdn_connectivity_reject(
            ctx, &sess, &mme_ue, &enb_ue, esm_cause, nas_action,
        ) {
            log::error!("PDN Connectivity / Attach Reject send failed: {e}");
        }
    }

    if nas_action == NasCreateAction::InPdnConnectivity {
        // The refused standalone PDN connection must not linger as a session.
        for bearer_id in &sess.bearer_list {
            ctx.bearer_remove(*bearer_id);
        }
        ctx.sess_remove(sess.id);
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.sess_list.retain(|id| *id != sess.id);
        }
    }
}

/// The ESM cause value from `esm_cause_from_gtp` as the NAS builder's enum.
fn esm_cause_enum(value: u8) -> crate::esm_build::EsmCause {
    use crate::esm_build::EsmCause as C;
    match value {
        esm_cause::OPERATOR_DETERMINED_BARRING => C::OperatorDeterminedBarring,
        esm_cause::INSUFFICIENT_RESOURCES => C::InsufficientResources,
        esm_cause::MISSING_OR_UNKNOWN_APN => C::MissingOrUnknownApn,
        esm_cause::USER_AUTHENTICATION_FAILED => C::UserAuthenticationFailed,
        esm_cause::REQUEST_REJECTED_BY_SERVING_GW_OR_PDN_GW => C::RequestRejectedByGw,
        esm_cause::SERVICE_OPTION_NOT_SUPPORTED => C::ServiceOptionNotSupported,
        esm_cause::REGULAR_DEACTIVATION => C::RegularDeactivation,
        esm_cause::SEMANTIC_ERROR_IN_THE_TFT_OPERATION => C::SemanticErrorInTftOperation,
        esm_cause::SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION => C::SyntacticalErrorInTftOperation,
        esm_cause::INVALID_EPS_BEARER_IDENTITY => C::InvalidEpsBearerIdentity,
        esm_cause::SEMANTIC_ERRORS_IN_PACKET_FILTERS => C::SemanticErrorsInPacketFilters,
        esm_cause::SYNTACTICAL_ERROR_IN_PACKET_FILTERS => C::SyntacticalErrorsInPacketFilters,
        _ => C::NetworkFailure,
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

    // GTPv2 code points (TS 29.274 §8.14 / §8.34): Non-IP is 4 and Ethernet 5 —
    // not ESM's 5 and 6, which this used to read, so a Non-IP grant was stored as
    // Ethernet and an Ethernet one dropped as undefined.
    let pdn_type = match data.paa_pdn_type {
        1 => PdnType::Ipv4,
        2 => PdnType::Ipv6,
        3 => PdnType::Ipv4v6,
        4 => PdnType::NonIp,
        5 => PdnType::Ethernet,
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

    // TS 23.401 §5.3.2.1 step 17: the Initial Context Setup tells the eNB where the
    // SGW's S1-U endpoint is. A default bearer the SGW gave no S1-U F-TEID for cannot
    // be set up, so the attach is refused here rather than sent with TEID 0 (#495).
    if bearer.sgw_s1u_teid == 0 {
        log::error!(
            "[{}] Create Session Response gave EBI {} no S1-U SGW F-TEID; the default \
             bearer cannot be set up, attach rejected",
            mme_ue.imsi_bcd,
            bearer.ebi
        );
        reject_attach_after_create(ctx, &sess, mme_ue, &enb_ue);
        return;
    }

    match crate::nas_path::nas_eps_send_attach_accept(mme_ue, &enb_ue, &sess, &bearer) {
        Ok(()) => log::info!(
            "[{}] Attach Accept sent in an Initial Context Setup Request (EBI {})",
            mme_ue.imsi_bcd,
            bearer.ebi
        ),
        Err(e) => {
            // The accept is only armed for retransmission once the Initial Context
            // Setup carrying it was built (#495), so a failure here leaves nothing
            // half-sent; the UE is answered instead of waiting out T3410.
            log::error!(
                "[{}] Attach Accept failed: {e:?}; attach rejected",
                mme_ue.imsi_bcd
            );
            reject_attach_after_create(ctx, &sess, mme_ue, &enb_ue);
        }
    }
}

/// Answer an attach whose session was created but whose Attach Accept cannot be
/// delivered: ATTACH REJECT #19 carrying PDN CONNECTIVITY REJECT with ESM cause #38
/// (network failure), and the S1 release #473 attaches to every ATTACH REJECT.
fn reject_attach_after_create(
    ctx: &crate::context::MmeContext,
    sess: &crate::context::MmeSess,
    mme_ue: &crate::context::MmeUe,
    enb_ue: &crate::context::EnbUe,
) {
    if let Err(e) = crate::nas_path::nas_eps_send_pdn_connectivity_reject(
        ctx,
        sess,
        mme_ue,
        enb_ue,
        crate::esm_build::EsmCause::NetworkFailure,
        crate::nas_path::GtpCreateAction::InAttachRequest,
    ) {
        log::error!("[{}] Attach Reject send failed: {e}", mme_ue.imsi_bcd);
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
        mt::DELETE_BEARER_REQUEST => handle_delete_bearer_request(raw, sequence_number, peer),
        other => log::info!(
            "S11 initial message type={other} seq={sequence_number} from {peer} not handled: this \
             MME originates no procedure for it"
        ),
    }
}

/// A Delete Bearer Request from the Serving GW (TS 29.274 §7.2.9.2).
///
/// Reached two ways (#591): as the triggered message of this MME's Delete Bearer
/// Command (TS 29.274 §7.6: same sequence number, it closes the Command), routed
/// by [`dispatch_triggered`]; or as an initial message, routed by
/// [`dispatch_initial`]. The handling is the same; only the transaction differs.
///
/// Bearers the eNB released are deleted and acknowledged as in TS 23.401 §5.4.4.2
/// (#584). Any other request is a PGW-initiated deactivation (§5.4.4.1), which
/// [`network_initiated_bearer_deletion`] decides (#688). Every request is
/// answered: before #688 such a request got no Delete Bearer Response at all.
fn handle_delete_bearer_request(raw: &[u8], sequence_number: u32, peer: SocketAddr) {
    let local_teid = parse_gtp_header(raw)
        .map(|(_, teid, _, _)| teid)
        .unwrap_or(0);
    let ctx = crate::context::mme_self();
    let ebis = delete_bearer_request_ebis(raw);
    use crate::s11_build::GtpCause;
    let rsp = if let Some((sgw_teid, deleted)) = delete_enb_released_bearers(ctx, local_teid, &ebis)
    {
        crate::s11_build::build_delete_bearer_response_for_ebis(
            sgw_teid,
            &deleted,
            GtpCause::RequestAccepted,
            sequence_number,
        )
    } else {
        match network_initiated_bearer_deletion(ctx, local_teid, raw) {
            DeleteBearerAction::DetachUe {
                mme_ue_id,
                sgw_teid,
                lbi,
                detach_type,
            } => {
                crate::network_detach::mme_initiated_detach(
                    ctx,
                    mme_ue_id,
                    detach_type,
                    &format!("a Delete Bearer Request for its last PDN connection (LBI {lbi})"),
                );
                crate::s11_build::build_delete_bearer_response_for_lbi(
                    sgw_teid,
                    lbi,
                    GtpCause::RequestAccepted,
                    sequence_number,
                )
            }
            DeleteBearerAction::PdnDeletedLocally { sgw_teid, lbi } => {
                crate::s11_build::build_delete_bearer_response_for_lbi(
                    sgw_teid,
                    lbi,
                    GtpCause::RequestAccepted,
                    sequence_number,
                )
            }
            DeleteBearerAction::BearersDeletedLocally { sgw_teid, ebis } => {
                crate::s11_build::build_delete_bearer_response_for_ebis(
                    sgw_teid,
                    &ebis,
                    GtpCause::RequestAccepted,
                    sequence_number,
                )
            }
            DeleteBearerAction::NoContext { sgw_teid, lbi } => {
                log::warn!(
                    "S11 Delete Bearer Request seq={sequence_number} from {peer} (TEID \
                     {local_teid:#x}, EBIs {ebis:?}) names no PDN connection or bearer this MME \
                     holds; answering Context Not Found"
                );
                match lbi {
                    Some(lbi) => crate::s11_build::build_delete_bearer_response_for_lbi(
                        sgw_teid,
                        lbi,
                        GtpCause::ContextNotFound,
                        sequence_number,
                    ),
                    None => crate::s11_build::build_delete_bearer_response_for_ebis(
                        sgw_teid,
                        &ebis,
                        GtpCause::ContextNotFound,
                        sequence_number,
                    ),
                }
            }
        }
    };
    match rsp {
        Ok(rsp) => {
            if let Err(e) = crate::gtp_path::send_response_to_sgwc(peer, &rsp) {
                log::error!("S11 Delete Bearer Response to {peer} failed: {e}");
            }
        }
        Err(e) => log::error!("Delete Bearer Response build failed: {e}"),
    }
}

/// GTPv2 cause "Reactivation requested" (TS 29.274 Table 8.4-1, value 8).
pub const GTP_CAUSE_REACTIVATION_REQUESTED: u8 = 8;

/// What a PGW-initiated Delete Bearer Request asks of this MME (#688).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteBearerAction {
    /// The default bearer of the UE's LAST PDN connection: TS 23.401 §5.4.4.1
    /// has the MME run the MME-initiated detach (§5.3.8.3) instead of deactivating
    /// the bearer, "re-attach required" when the cause is Reactivation requested
    /// (TS 24.301 §5.5.2.3.1).
    DetachUe {
        /// The UE to detach.
        mme_ue_id: u64,
        /// The Serving GW's S11 TEID, for the response.
        sgw_teid: u32,
        /// The LBI the request named.
        lbi: u8,
        /// The detach type the cause calls for.
        detach_type: crate::emm_build::DetachTypeToUe,
    },
    /// A PDN connection that is not the UE's last, deleted in the MME only. The
    /// ESM DEACTIVATE EPS BEARER CONTEXT REQUEST toward the UE is not implemented
    /// here, and is logged as such.
    PdnDeletedLocally {
        /// The Serving GW's S11 TEID.
        sgw_teid: u32,
        /// The LBI the request named.
        lbi: u8,
    },
    /// Dedicated bearers, deleted in the MME only (no ESM signalling, as above).
    BearersDeletedLocally {
        /// The Serving GW's S11 TEID.
        sgw_teid: u32,
        /// The EBIs found and deleted.
        ebis: Vec<u8>,
    },
    /// No such UE, PDN connection or bearer.
    NoContext {
        /// The Serving GW's S11 TEID, when the UE is known (else 0).
        sgw_teid: u32,
        /// The LBI the request named, if it named one.
        lbi: Option<u8>,
    },
}

/// The Cause a GTPv2-C message carries, if any.
fn message_cause(raw: &[u8]) -> Option<u8> {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).ok()?;
    msg.get_ie(nextgcore_gtp::v2::Gtp2IeType::Cause as u8, 0)
        .and_then(|ie| ie.value.first().copied())
}

/// Whether a Delete Bearer Request names its bearers by EBI (instance 1) rather
/// than its PDN connection by LBI (instance 0) (TS 29.274 Table 7.2.9.2-1).
fn names_dedicated_bearers(raw: &[u8]) -> bool {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let Ok(msg) = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes) else {
        return false;
    };
    msg.get_ies(nextgcore_gtp::v2::Gtp2IeType::Ebi as u8)
        .into_iter()
        .any(|ie| ie.instance == 1)
}

/// Decide and apply (in the MME's own contexts) a PGW-initiated Delete Bearer
/// Request for the UE whose S11 TEID is `mme_s11_teid` (TS 23.401 §5.4.4.1, #688).
/// The detach itself is left to the caller, which owns the S11 response.
pub fn network_initiated_bearer_deletion(
    ctx: &crate::context::MmeContext,
    mme_s11_teid: u32,
    raw: &[u8],
) -> DeleteBearerAction {
    let ebis = delete_bearer_request_ebis(raw);
    let dedicated = names_dedicated_bearers(raw);
    let lbi = (!dedicated).then(|| ebis.first().copied()).flatten();
    let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(mme_s11_teid) else {
        return DeleteBearerAction::NoContext { sgw_teid: 0, lbi };
    };
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return DeleteBearerAction::NoContext { sgw_teid: 0, lbi };
    };
    let sgw_teid = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .map(|s| s.sgw_s11_teid)
        .unwrap_or(0);

    if let Some(lbi) = lbi {
        // The PDN connection whose default (first) bearer is the LBI.
        let sess = mme_ue.sess_list.iter().copied().find(|sess_id| {
            ctx.sess_find_by_id(*sess_id)
                .and_then(|s| s.bearer_list.first().copied())
                .and_then(|b| ctx.bearer_find_by_id(b))
                .is_some_and(|b| b.ebi == lbi)
        });
        let Some(sess_id) = sess else {
            return DeleteBearerAction::NoContext {
                sgw_teid,
                lbi: Some(lbi),
            };
        };
        if mme_ue.sess_list.len() <= 1 {
            let cause = message_cause(raw);
            let detach_type = if cause == Some(GTP_CAUSE_REACTIVATION_REQUESTED) {
                crate::emm_build::DetachTypeToUe::ReAttachRequired
            } else {
                crate::emm_build::DetachTypeToUe::ReAttachNotRequired
            };
            log::warn!(
                "[{}] Delete Bearer Request (cause {cause:?}) for the default bearer of the last \
                 PDN connection (LBI {lbi}): MME-initiated detach, {detach_type:?} (TS 23.401 \
                 §5.4.4.1, §5.3.8.3)",
                mme_ue.imsi_bcd
            );
            return DeleteBearerAction::DetachUe {
                mme_ue_id,
                sgw_teid,
                lbi,
                detach_type,
            };
        }
        if let Some(sess) = ctx.sess_find_by_id(sess_id) {
            for b in &sess.bearer_list {
                ctx.bearer_remove(*b);
            }
        }
        ctx.sess_remove(sess_id);
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            ue.sess_list.retain(|id| *id != sess_id);
        }
        log::warn!(
            "[{}] PDN connection LBI {lbi} deleted by the gateway and in this MME; the UE is not \
             told: ESM DEACTIVATE EPS BEARER CONTEXT REQUEST is not implemented here",
            mme_ue.imsi_bcd
        );
        return DeleteBearerAction::PdnDeletedLocally { sgw_teid, lbi };
    }

    let mut deleted = Vec::new();
    for ebi in &ebis {
        let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, *ebi) else {
            continue;
        };
        if let Some(bearer) = ctx.bearer_find_by_id(bearer_id) {
            if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&bearer.sess_id) {
                sess.bearer_list.retain(|id| *id != bearer_id);
            }
        }
        ctx.bearer_remove(bearer_id);
        deleted.push(*ebi);
    }
    if deleted.is_empty() {
        return DeleteBearerAction::NoContext {
            sgw_teid,
            lbi: None,
        };
    }
    log::warn!(
        "[{}] dedicated bearers {deleted:?} deleted by the gateway and in this MME; the UE is \
         not told: ESM DEACTIVATE EPS BEARER CONTEXT REQUEST is not implemented here",
        mme_ue.imsi_bcd
    );
    DeleteBearerAction::BearersDeletedLocally {
        sgw_teid,
        ebis: deleted,
    }
}

/// The EBIs a Delete Bearer Request names: the EPS Bearer IDs (EBI instance 1)
/// for dedicated bearers, else the Linked EBI (instance 0), per TS 29.274
/// Table 7.2.9.2-1.
pub fn delete_bearer_request_ebis(raw: &[u8]) -> Vec<u8> {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let Ok(msg) = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes) else {
        return Vec::new();
    };
    let ebi = nextgcore_gtp::v2::Gtp2IeType::Ebi as u8;
    let dedicated: Vec<u8> = msg
        .get_ies(ebi)
        .into_iter()
        .filter(|ie| ie.instance == 1)
        .filter_map(|ie| ie.value.first().map(|v| v & 0x0F))
        .collect();
    if !dedicated.is_empty() {
        return dedicated;
    }
    msg.get_ie(ebi, 0)
        .and_then(|ie| ie.value.first().map(|v| v & 0x0F))
        .into_iter()
        .collect()
}

/// TS 23.401 §5.4.4.2 steps 6-8 for bearers the eNB released (#584): of the
/// `ebis` a Delete Bearer Request names for the UE whose S11 TEID is
/// `mme_s11_teid`, delete the ones marked `released_by_enb` -- locally, with no
/// NAS signalling, because step 7 "is omitted if the bearer deactivation was
/// triggered by the eNodeB" -- and return the Serving GW's S11 TEID and the
/// EBIs to acknowledge. `None` when no named bearer is one the eNB released.
pub fn delete_enb_released_bearers(
    ctx: &crate::context::MmeContext,
    mme_s11_teid: u32,
    ebis: &[u8],
) -> Option<(u32, Vec<u8>)> {
    let mme_ue_id = ctx.mme_ue_find_by_s11_local_teid(mme_s11_teid)?;
    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id)?;
    let sgw_teid = ctx
        .sgw_ue_find_by_id(mme_ue.sgw_ue_id)
        .map(|s| s.sgw_s11_teid)
        .unwrap_or(0);
    let mut deleted = Vec::new();
    for ebi in ebis {
        let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, *ebi) else {
            continue;
        };
        let Some(bearer) = ctx.bearer_find_by_id(bearer_id) else {
            continue;
        };
        if !bearer.released_by_enb {
            continue;
        }
        if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&bearer.sess_id) {
            sess.bearer_list.retain(|id| *id != bearer_id);
        }
        ctx.bearer_remove(bearer_id);
        deleted.push(*ebi);
    }
    if deleted.is_empty() {
        None
    } else {
        log::info!(
            "[{}] EPS bearers {deleted:?} released by the eNB are deleted (TS 23.401 §5.4.4.2 \
             step 8)",
            mme_ue.imsi_bcd
        );
        Some((sgw_teid, deleted))
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
                ie_type::CHANGE_REPORTING_ACTION => {
                    result.change_reporting_action = value.first().copied();
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
                // Bearer Contexts created (M, instance 0; Table 7.2.2-2). Instance 1
                // is "Bearer Contexts marked for removal", which this MME never asks
                // for. Not parsed before #495, so the default bearer kept SGW S1-U
                // TEID 0 and the Initial Context Setup could not be built.
                ie_type::BEARER_CONTEXT if instance == 0 => {
                    if let Some(bearer) = parse_created_bearer(value) {
                        result.bearer_contexts.push(bearer);
                    }
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

/// Parse one Bearer Context created of a Create Session Response
/// (TS 29.274 Table 7.2.2-2): EBI (M), Cause (M), S1-U SGW F-TEID (C, instance 0),
/// S5/S8-U PGW F-TEID (C, instance 2) and Bearer QoS (C, instance 0).
///
/// The F-TEIDs are keyed by instance AND checked against their interface type
/// (§8.22: 1 = S1-U SGW GTP-U, 5 = S5/S8 PGW GTP-U), as the CIDFT parser does, so a
/// contradictory pair is ignored rather than installed as the wrong tunnel. A
/// bearer context without an EBI is unusable and is dropped.
fn parse_created_bearer(value: &[u8]) -> Option<BearerContextCreated> {
    use crate::s11_build::f_teid_interface as iface;

    let mut bearer = BearerContextCreated::default();
    let mut have_ebi = false;
    let mut offset = 0;
    while offset < value.len() {
        let Some((ie_t, length, instance, inner)) = parse_ie_header(&value[offset..]) else {
            break;
        };
        match ie_t {
            ie_type::EBI => {
                if let Some(ebi) = parse_ebi(inner) {
                    bearer.ebi = ebi;
                    have_ebi = true;
                }
            }
            ie_type::CAUSE => {
                if let Some(cause) = parse_cause(inner) {
                    bearer.cause = cause;
                }
            }
            ie_type::F_TEID => {
                if let Some((iface_type, teid, ipv4, _)) = parse_f_teid(inner) {
                    match (instance, iface_type) {
                        (0, iface::S1U_SGW_GTP_U) => {
                            bearer.sgw_s1u_teid = teid;
                            bearer.sgw_s1u_ipv4 = ipv4;
                        }
                        (2, iface::S5_S8_PGW_GTP_U) => {
                            bearer.pgw_s5u_teid = teid;
                            bearer.pgw_s5u_ipv4 = ipv4;
                        }
                        (other, t) => log::debug!(
                            "Create Session Response bearer F-TEID at instance {other} with \
                             interface type {t} ignored: not an endpoint this MME uses"
                        ),
                    }
                }
            }
            ie_type::BEARER_QOS => {
                if let Some((qci, prio, pec, pev, ..)) = parse_bearer_qos(inner) {
                    bearer.qci = qci;
                    bearer.arp_priority = prio;
                    bearer.arp_pec = pec;
                    bearer.arp_pev = pev;
                }
            }
            _ => {}
        }
        offset += 4 + length as usize;
    }
    have_ebi.then_some(bearer)
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
        if let Some((ie_t, length, instance, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            } else if ie_t == ie_type::CHANGE_REPORTING_ACTION {
                result.change_reporting_action = value.first().copied();
            } else if ie_t == ie_type::BEARER_CONTEXT {
                if let Some(bc) = parse_bearer_context_ebi_cause(value) {
                    match instance {
                        0 => result.bearer_contexts.push(bc),
                        1 => result.bearers_marked_for_removal.push(bc.ebi),
                        _ => {}
                    }
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }

    Ok(result)
}

/// Parse a Change Notification Response (TS 29.274 §7.3.15, #593).
pub fn handle_change_notification_response(
    data: &[u8],
) -> S11Result<ChangeNotificationResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    if msg_type != message_type::CHANGE_NOTIFICATION_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }
    let mut result = ChangeNotificationResponseData::default();
    let mut offset = 0;
    while offset < payload.len() {
        let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) else {
            break;
        };
        if ie_t == ie_type::CAUSE {
            if let Some(cause) = parse_cause(value) {
                result.cause = cause;
            }
        } else if ie_t == ie_type::CHANGE_REPORTING_ACTION {
            result.change_reporting_action = value.first().copied();
        }
        offset += 4 + length as usize;
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
/// Parse a Create Indirect Data Forwarding Tunnel Response (TS 29.274 §7.2.19).
///
/// The SGW's forwarding endpoints are keyed by INSTANCE, per Table 7.2.19-2: DL at
/// instance 0 (S1-U) or 3 (target-selected SGW), UL at 4 (S1-U) or 5 (SGW). NOTE 3 and
/// NOTE 4 also fix the interface types at 23 for DL and 28 for UL, and both are
/// checked -- an F-TEID whose instance says "UL" and whose interface type says "DL" is
/// contradictory, and taking the instance's word for it would install a forwarding rule
/// in the wrong direction. NOTE 1/NOTE 2 permit the SGW to send SEVERAL instances when
/// it cannot decide which applies, so the first match wins and later ones are ignored
/// rather than overwriting it.
pub fn handle_create_indirect_tunnel_response(
    data: &[u8],
) -> S11Result<CreateIndirectTunnelResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    if msg_type != message_type::CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }

    let mut result = CreateIndirectTunnelResponseData::default();
    let mut offset = 0;
    while offset < payload.len() {
        let Some((ie_t, length, _instance, value)) = parse_ie_header(&payload[offset..]) else {
            break;
        };
        match ie_t {
            ie_type::CAUSE => {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            ie_type::BEARER_CONTEXT => {
                if let Some(bearer) = parse_indirect_forwarding_bearer(value) {
                    result.bearers.push(bearer);
                }
            }
            _ => {}
        }
        offset += 4 + length as usize;
    }

    if result.cause == 0 {
        return Err(S11Error::MandatoryIeMissing("Cause".to_string()));
    }
    Ok(result)
}

/// Parse one Bearer Context of a CIDFT Response (Table 7.2.19-2).
fn parse_indirect_forwarding_bearer(value: &[u8]) -> Option<IndirectForwardingBearer> {
    use crate::s11_build::f_teid_interface as iface;

    let mut bearer = IndirectForwardingBearer::default();
    let mut have_ebi = false;
    let mut offset = 0;
    while offset < value.len() {
        let Some((ie_t, length, instance, inner)) = parse_ie_header(&value[offset..]) else {
            break;
        };
        match ie_t {
            ie_type::EBI => {
                if let Some(ebi) = parse_ebi(inner) {
                    bearer.ebi = ebi;
                    have_ebi = true;
                }
            }
            ie_type::CAUSE => {
                if let Some(cause) = parse_cause(inner) {
                    bearer.cause = cause;
                }
            }
            ie_type::F_TEID => {
                if let Some((iface_type, teid, ipv4, _)) = parse_f_teid(inner) {
                    match instance {
                        // DL: S1-U (0) or target-selected SGW (3)
                        0 | 3
                            if iface_type == iface::SGW_GTP_U_DL_DATA_FORWARDING
                                && bearer.sgw_dl_teid == 0 =>
                        {
                            bearer.sgw_dl_teid = teid;
                            bearer.sgw_dl_ipv4 = ipv4;
                        }
                        // UL: S1-U (4) or SGW (5)
                        4 | 5
                            if iface_type == iface::SGW_GTP_U_UL_DATA_FORWARDING
                                && bearer.sgw_ul_teid == 0 =>
                        {
                            bearer.sgw_ul_teid = teid;
                            bearer.sgw_ul_ipv4 = ipv4;
                        }
                        other => log::debug!(
                            "CIDFT Response F-TEID at instance {other} with interface type \
                             {iface_type} ignored: not a forwarding endpoint this MME uses"
                        ),
                    }
                }
            }
            _ => {}
        }
        offset += 4 + length as usize;
    }

    have_ebi.then_some(bearer)
}

/// Record the SGW's forwarding endpoints and send the Handover Command that was
/// deferred waiting for them (#48, TS 23.401 §5.5.1.2.2).
///
/// The command could not be sent at Handover Request Acknowledge time because the
/// endpoints the source eNB must forward to are the SGW's, and only this response
/// carries them. The UE is found by the LOCAL S11 TEID in the header for the same
/// reason `apply_create_session_response` does: it is the TEID this MME told the SGW to
/// use, so a malformed body cannot attribute the response to another UE.
fn apply_indirect_forwarding_response(
    data: &CreateIndirectTunnelResponseData,
    local_teid: u32,
    peer: std::net::SocketAddr,
) {
    let ctx = crate::context::mme_self();

    let Some(mme_ue_id) = ctx.mme_ue_find_by_s11_local_teid(local_teid) else {
        log::error!(
            "CIDFT Response from {peer} for unknown local S11 TEID {local_teid:#x}: no UE to \
             complete the handover for"
        );
        return;
    };

    // TS 29.274 §8.4: 16 is "Request accepted". Anything else means no forwarding
    // tunnels exist, and the handover must still proceed -- a UE that cannot get its
    // buffered downlink data forwarded is better off attached to the target than stuck
    // between cells. So the command goes out with an EMPTY forwarding list, and the
    // loss is logged rather than hidden.
    if data.cause != 16 {
        log::error!(
            "SGW refused indirect forwarding tunnels (cause={}); completing the handover WITHOUT \
             data forwarding, so buffered downlink data is lost",
            data.cause
        );
    } else {
        for bearer in &data.bearers {
            let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, bearer.ebi) else {
                log::warn!(
                    "CIDFT Response names EBI {} which this UE does not have",
                    bearer.ebi
                );
                continue;
            };
            if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                b.sgw_dl_teid = bearer.sgw_dl_teid;
                b.sgw_dl_ip = ipv4_to_context_ip(bearer.sgw_dl_ipv4);
                b.sgw_ul_teid = bearer.sgw_ul_teid;
                b.sgw_ul_ip = ipv4_to_context_ip(bearer.sgw_ul_ipv4);
            }
        }
    }

    // The prepared target is the one this UE is moving to; the command goes to its
    // SOURCE.
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return;
    };
    let Some(source_ue) = ctx.enb_ue_find_by_id(mme_ue.enb_ue_id) else {
        log::error!("CIDFT Response with no source eNB UE context");
        return;
    };
    let target_ue_id = source_ue.target_ue_id;
    if target_ue_id == crate::context::NEXTGCORE_INVALID_POOL_ID {
        log::error!(
            "CIDFT Response for mme_ue_id={mme_ue_id} with no handover in preparation: the \
             forwarding tunnels are recorded but there is no Handover Command to send"
        );
        return;
    }
    // Confirm the target context still exists before building a command that names it;
    // the supervision sweep may have released it while the SGW was answering.
    if ctx.enb_ue_find_by_id(target_ue_id).is_none() {
        log::warn!(
            "CIDFT Response for target enb_ue_id={target_ue_id} that no longer exists; the \
             preparation was released while the SGW was answering"
        );
        return;
    }

    let forwarding_list = if data.cause == 16 {
        crate::s1ap_handler::sgw_forwarding_list(ctx, mme_ue_id)
    } else {
        Vec::new()
    };

    // The Handover Request Acknowledge's failed-E-RAB list and target-to-source
    // container were consumed when the ack arrived, so they are replayed from what the
    // deferral stored on the target context.
    // TAKEN, not cloned: TS 29.274 §7.6 makes a GTP-C response retransmittable, and a
    // second Handover Command for one handover would have the source eNB hand the UE
    // over twice. Clearing it here makes the send idempotent.
    let pending = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        match pool.get_mut(&target_ue_id) {
            Some(target) => target.pending_handover_command.take(),
            None => None,
        }
    };
    let Some(pending) = pending else {
        log::warn!(
            "CIDFT Response for a handover with no stored Handover Request Acknowledge: either \
             the command already went out (a retransmitted response) or the preparation is gone"
        );
        return;
    };

    let command = nextgcore_s1ap::HandoverCommand {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        handover_type: pending.handover_type,
        erab_subject_to_forwarding_list: forwarding_list,
        erab_to_release_list: pending.erab_to_release_list,
        target_to_source_container: pending.target_to_source_container,
    };
    match crate::s1ap_gen::build_handover_command(&command, &source_ue.handover_required_notify) {
        Ok(pdu) => {
            log::info!(
                "Indirect forwarding tunnels ready; sending the deferred Handover Command to \
                 source eNB {}",
                source_ue.enb_id
            );
            crate::s1ap_path::s1ap_send(crate::s1ap_handler::S1apSend {
                enb_id: source_ue.enb_id,
                pdu,
            });
        }
        Err(e) => log::error!("Failed to build the deferred Handover Command: {e}"),
    }
}

/// A context IP from an optional wire IPv4 address.
fn ipv4_to_context_ip(ipv4: Option<[u8; 4]>) -> crate::context::IpAddr {
    let mut ip = crate::context::IpAddr::default();
    ip.ipv4 = ipv4;
    ip
}

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

    /// Bearer Contexts created, parsed from octets derived BY HAND from TS 29.274
    /// (§5.1 header, Table 7.2.2-2, §8.4 Cause, §8.8 EBI, §8.22 F-TEID) rather than
    /// from any encoder in this tree (#495). Before #495 the IE was skipped, so the
    /// default bearer kept SGW S1-U TEID 0.
    #[test]
    fn bearer_contexts_created_parse_from_hand_derived_octets() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            // GTPv2 header: v2, T=1; type 33 Create Session Response; length 42
            // (8 octets of TEID/seq/spare + 34 of IEs); TEID 4; sequence 3.
            0x48, 0x21, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00,
            // Cause (2), length 2, instance 0: 16 "Request accepted", flags 0.
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            // Bearer Context (93), length 24, instance 0 = "created":
            0x5d, 0x00, 0x18, 0x00,
            //   EBI (73), length 1, instance 0: EBI 5.
            0x49, 0x00, 0x01, 0x00, 0x05,
            //   Cause (2): 16.
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            //   F-TEID (87), length 9, instance 0: V4 | interface 1 (S1-U SGW
            //   GTP-U), TEID 0xaabbccdd, 10.0.0.5.
            0x57, 0x00, 0x09, 0x00, 0x81, 0xaa, 0xbb, 0xcc, 0xdd, 0x0a, 0x00, 0x00, 0x05,
        ];
        let parsed = handle_create_session_response(wire).expect("parses");
        assert_eq!(parsed.cause, 16);
        assert_eq!(
            parsed.bearer_contexts.len(),
            1,
            "the bearer context must be parsed"
        );
        let b = &parsed.bearer_contexts[0];
        assert_eq!(b.ebi, 5);
        assert_eq!(b.cause, 16);
        assert_eq!(b.sgw_s1u_teid, 0xaabb_ccdd);
        assert_eq!(b.sgw_s1u_ipv4, Some([10, 0, 0, 5]));
    }

    /// The same IE as the Serving GW actually emits it: built with nextgcore-gtp's
    /// `Gtp2BearerContextIe`, the encoder sgwcd's `build_create_session_response`
    /// uses, so the two sides of S11 cannot drift apart unnoticed (#495). Also
    /// checks the S5/S8-U PGW F-TEID (instance 2) and Bearer QoS, and that an
    /// F-TEID whose interface type contradicts its instance is ignored.
    #[test]
    fn bearer_contexts_created_parse_as_sgwcd_encodes_them() {
        use nextgcore_gtp::v2::header::{Gtp2Header, Gtp2MessageType};
        use nextgcore_gtp::v2::ie::{
            Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2FTeidIe,
        };
        use nextgcore_gtp::v2::message::Gtp2Message;

        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateSessionResponse as u8,
            7,
            9,
        ));
        msg.add_ie(Gtp2CauseIe::new(16).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(6);
        bc.set_cause(&Gtp2CauseIe::new(16));
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(1, 0x0102_0304, [192, 0, 2, 1]));
        bc.set_fteid(2, &Gtp2FTeidIe::new_ipv4(5, 0x0506_0708, [192, 0, 2, 2]));
        // Instance 0 again but interface type 5: contradictory, must not overwrite.
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(5, 0xdead_beef, [198, 51, 100, 9]));
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        msg.add_bearer_context(0, &bc);

        let wire = msg.encode();
        let parsed = handle_create_session_response(&wire).expect("parses");
        assert_eq!(parsed.bearer_contexts.len(), 1);
        let b = &parsed.bearer_contexts[0];
        assert_eq!(b.ebi, 6);
        assert_eq!(
            b.sgw_s1u_teid, 0x0102_0304,
            "instance 0 interface 1 is the S1-U SGW"
        );
        assert_eq!(b.sgw_s1u_ipv4, Some([192, 0, 2, 1]));
        assert_eq!(b.pgw_s5u_teid, 0x0506_0708);
        assert_eq!(b.pgw_s5u_ipv4, Some([192, 0, 2, 2]));
        assert_eq!(b.qci, 9);
    }

    /// A default bearer the SGW gave no S1-U F-TEID cannot be set up: the attach is
    /// refused and the ATTACH ACCEPT is NOT armed in T3450, so it can never be
    /// retransmitted bare over Downlink NAS Transport (#495).
    #[test]
    fn an_attach_without_an_s1u_endpoint_is_rejected_not_half_sent() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let ctx = crate::context::mme_self();
        crate::gtp_path::record_pending_create_for_test(
            4251,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );
        let mut response = accepted_response(5, [10, 45, 0, 9]);
        response.bearer_contexts[0].sgw_s1u_teid = 0;
        response.bearer_contexts[0].sgw_s1u_ipv4 = None;
        apply_create_session_response(
            &response,
            local_teid,
            4251,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(
            ue.t3450.pkbuf.is_none(),
            "no ATTACH ACCEPT may be armed for retransmission when its Initial Context \
             Setup could not be built"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// Release what `seed_global_ue` added, so the shared global context does not
    /// accumulate UEs across the suite.
    fn release_global_ue(mme_ue_id: u64, sess_id: u64, bearer_id: u64) {
        let ctx = crate::context::mme_self();
        ctx.bearer_remove(bearer_id);
        ctx.sess_remove(sess_id);
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #593: a Change Notification Request reaches the Serving GW on a real S11
    /// socket, and the Change Notification Response closes it, its Change
    /// Reporting Action replacing the PDN connection's.
    #[test]
    fn a_change_notification_is_answered_and_its_action_applied() {
        use nextgcore_gtp::v2::{Gtp2Header, Gtp2IeType, Gtp2Message};
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, _, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let ctx = crate::context::mme_self();
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .change_reporting_action = Some(4);

        let sgw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sgw.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let server = crate::gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            7,
        )
        .unwrap();
        let seq = crate::gtp_path::send_change_notification_on(
            &server,
            sgw.local_addr().unwrap(),
            ctx,
            mme_ue_id,
            sess_id,
        )
        .expect("sent");

        let mut buf = [0u8; 2048];
        let (len, from) = sgw.recv_from(&mut buf).expect("the SGW receives it");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let cnr = Gtp2Message::decode(&mut bytes).unwrap();
        assert_eq!(cnr.header.message_type, 38);
        assert_eq!(cnr.header.sequence_number, seq);
        assert_eq!(
            cnr.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap().value.as_ref(),
            &[5]
        );

        // The PDN GW stops reporting in its answer.
        let mut rsp = Gtp2Message::new(Gtp2Header::new(39, local_teid, seq));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Cause as u8,
            0,
            &[16, 0],
        ));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(131, 0, &[0]));
        sgw.send_to(&rsp.encode(), from).unwrap();
        for _ in 0..200 {
            if server.outstanding() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(server.outstanding(), 0, "the response closes the request");
        for _ in 0..200 {
            if ctx
                .sess_find_by_id(sess_id)
                .unwrap()
                .change_reporting_action
                == Some(0)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            ctx.sess_find_by_id(sess_id)
                .unwrap()
                .change_reporting_action,
            Some(0),
            "the response's Change Reporting Action replaces the session's"
        );
        assert!(crate::gtp_path::take_pending_change_notification(seq).is_none());
        server.close();
        release_global_ue(mme_ue_id, sess_id, bearer_id);
    }

    /// #593: a Change Reporting Action in a Modify Bearer Response is honoured.
    #[test]
    fn a_modify_bearer_response_change_reporting_action_is_honoured() {
        use nextgcore_gtp::v2::{Gtp2Header, Gtp2IeType, Gtp2Message};
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, _, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let mut rsp = Gtp2Message::new(Gtp2Header::new(35, local_teid, 0x593));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Cause as u8,
            0,
            &[16, 0],
        ));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(131, 0, &[6]));
        let raw = rsp.encode();
        assert_eq!(
            handle_modify_bearer_response(&raw)
                .unwrap()
                .change_reporting_action,
            Some(6)
        );
        dispatch_triggered(&raw, 35, 0x593, "127.0.0.1:2123".parse().unwrap());
        assert_eq!(
            crate::context::mme_self()
                .sess_find_by_id(sess_id)
                .unwrap()
                .change_reporting_action,
            Some(6)
        );
        release_global_ue(mme_ue_id, sess_id, bearer_id);
    }

    #[test]
    fn a_change_notification_response_parses_cause_and_action() {
        let mut rsp =
            nextgcore_gtp::v2::Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(39, 1, 2));
        rsp.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(2, 0, &[64, 0]));
        let parsed = handle_change_notification_response(&rsp.encode()).unwrap();
        assert_eq!(parsed.cause, 64);
        assert_eq!(parsed.change_reporting_action, None);
        assert!(handle_change_notification_response(
            &nextgcore_gtp::v2::Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(35, 1, 2))
                .encode()
        )
        .is_err());
    }

    /// #593: the Create Session Response's Change Reporting Action is kept on the
    /// PDN connection it was sent for.
    #[test]
    fn a_create_session_response_action_is_kept_on_its_session() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();
        let (mme_ue_id, _, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let mut data = accepted_response(5, [10, 45, 0, 9]);
        data.change_reporting_action = Some(6);
        apply_create_session_response(&data, local_teid, 4593, "127.0.0.1:2123".parse().unwrap());
        assert_eq!(
            crate::context::mme_self()
                .sess_find_by_id(sess_id)
                .unwrap()
                .change_reporting_action,
            Some(6)
        );
        release_global_ue(mme_ue_id, sess_id, bearer_id);
    }

    /// #591: the Delete Bearer Request that answers this MME's Delete Bearer
    /// Command is routed as the Command's triggered message, and it still deletes
    /// the bearer the eNB released (TS 23.401 §5.4.4.2 steps 6-8). Before #591
    /// the transaction layer never matched it, and once it does, a
    /// `dispatch_triggered` without this arm would only log it.
    #[test]
    fn a_triggered_delete_bearer_request_deletes_the_released_bearer() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, _, sess_id, bearer_id, local_teid) = seed_global_ue(6);
        let ctx = crate::context::mme_self();
        if let Ok(mut pool) = ctx.bearer_pool.write() {
            pool.get_mut(&bearer_id).unwrap().released_by_enb = true;
        }

        let mut req = nextgcore_gtp::v2::Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            crate::s11_build::message_type::DELETE_BEARER_REQUEST,
            local_teid,
            0x0591,
        ));
        req.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            nextgcore_gtp::v2::Gtp2IeType::Ebi as u8,
            1,
            &[6],
        ));
        dispatch_triggered(
            &req.encode(),
            crate::s11_build::message_type::DELETE_BEARER_REQUEST,
            0x0591,
            "127.0.0.1:2123".parse().unwrap(),
        );

        assert!(
            ctx.bearer_find_by_id(bearer_id).is_none(),
            "the triggered Delete Bearer Request must delete bearer 6"
        );
        assert!(ctx.sess_find_by_id(sess_id).unwrap().bearer_list.is_empty());
        release_global_ue(mme_ue_id, sess_id, bearer_id);
    }

    /// A Failure Indication's cause is read from its Cause IE.
    #[test]
    fn a_failure_indication_cause_is_read() {
        let mut fi = nextgcore_gtp::v2::Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            crate::s11_build::message_type::DELETE_BEARER_FAILURE_INDICATION,
            1,
            2,
        ));
        fi.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            nextgcore_gtp::v2::Gtp2IeType::Cause as u8,
            0,
            &[64, 0],
        ));
        assert_eq!(failure_indication_cause(&fi.encode()), Some(64));
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

    /// #492: a REJECTED Create Session Response for an attach must answer the UE:
    /// ATTACH REJECT #19 with the mapped ESM cause, then the S1 release (#473). It
    /// used to be logged and dropped, leaving the UE to wait out T3410.
    ///
    /// Observed through the eNB UE context the reject path releases (the S1AP send
    /// queue is once-per-process and not a reliable observable here, see below).
    #[test]
    fn a_rejected_attach_create_session_is_answered_with_attach_reject() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        let ctx = crate::context::mme_self();
        crate::gtp_path::record_pending_create_for_test(
            4250,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::AttachRequest,
                enb_ue_id,
                sess_id,
            },
        );

        let rejected = CreateSessionResponseData {
            cause: 109, // Mandatory/Conditional IE missing, as smfd answered "No PAA"
            ..Default::default()
        };
        apply_create_session_response(
            &rejected,
            local_teid,
            4250,
            "127.0.0.1:2123".parse().unwrap(),
        );

        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).expect("eNB UE");
        assert_eq!(
            enb_ue.ue_ctx_rel_action,
            crate::context::UeCtxRelAction::UeContextRemove,
            "the ATTACH REJECT path must run and release the UE"
        );
        assert!(
            crate::gtp_path::take_pending_create(4250).is_none(),
            "the pending record is consumed, so a duplicate cannot answer twice"
        );
        assert_eq!(
            esm_cause_enum(esm_cause_from_gtp(109)),
            crate::esm_build::EsmCause::NetworkFailure
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// #492: a rejected standalone PDN connectivity is answered with PDN CONNECTIVITY
    /// REJECT, without releasing the UE, and its session does not linger.
    #[test]
    fn a_rejected_standalone_create_session_discards_its_session() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(6);
        let ctx = crate::context::mme_self();
        crate::gtp_path::record_pending_create_for_test(
            4251,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::UplinkNasTransport,
                enb_ue_id,
                sess_id,
            },
        );

        let rejected = CreateSessionResponseData {
            cause: 78, // Missing or unknown APN
            ..Default::default()
        };
        apply_create_session_response(
            &rejected,
            local_teid,
            4251,
            "127.0.0.1:2123".parse().unwrap(),
        );

        assert!(
            ctx.sess_find_by_id(sess_id).is_none(),
            "the refused session is discarded"
        );
        assert_ne!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().ue_ctx_rel_action,
            crate::context::UeCtxRelAction::UeContextRemove,
            "a standalone reject does not release the UE"
        );

        release_global_ue(mme_ue_id, sess_id, bearer_id);
        crate::gtp_path::clear_pending_creates_for_test();
    }

    /// GTPv2 PDN type code points (TS 29.274 §8.14): Non-IP 4, Ethernet 5.
    #[test]
    fn a_non_ip_grant_is_stored_as_non_ip() {
        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();
        let (mme_ue_id, enb_ue_id, sess_id, bearer_id, local_teid) = seed_global_ue(5);
        crate::gtp_path::record_pending_create_for_test(
            4252,
            crate::gtp_path::PendingCreate {
                create_action: GtpCreateAction::UplinkNasTransport,
                enb_ue_id,
                sess_id,
            },
        );
        let mut data = accepted_response(5, [0; 4]);
        data.paa_pdn_type = 4;
        data.paa_ipv4 = None;
        apply_create_session_response(&data, local_teid, 4252, "127.0.0.1:2123".parse().unwrap());
        assert_eq!(
            crate::context::mme_self()
                .sess_find_by_id(sess_id)
                .unwrap()
                .paa
                .pdn_type,
            crate::esm_build::PdnType::NonIp
        );
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
        // Octet 1 packs the EPS bearer identity (bits 8-5) with PD 2 (bits 4-1),
        // TS 24.301 §9.3.1. Until #496 every ESM builder wrote them as two
        // octets and this test pinned that layout; it now pins the spec's.
        assert_eq!(
            esm.first().copied(),
            Some(0x72),
            "octet 1 must name the bearer the MME actually created (EBI 7, not a \
             fabricated 5) packed with the ESM discriminator"
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

/// #688: a PGW-initiated Delete Bearer Request is decided and answered.
#[cfg(test)]
mod pgw_initiated_delete_bearer_tests {
    use super::*;
    use crate::context::MmeContext;
    use crate::emm_build::DetachTypeToUe;
    use nextgcore_gtp::v2::ie::Gtp2Ie;
    use nextgcore_gtp::v2::{Gtp2Header, Gtp2IeType, Gtp2Message};

    fn ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
    }

    /// An attached, connected UE with one PDN connection per entry of `default_ebis`.
    fn ue(ctx: &MmeContext, default_ebis: &[u8]) -> (u64, u32) {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.set_sgw_s11_teid_for_ue(mme_ue_id, 0x5ca1);
        for (pti, ebi) in default_ebis.iter().enumerate() {
            let sess_id = ctx.sess_add(mme_ue_id, pti as u8 + 1);
            let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
            ctx.bearer_pool
                .write()
                .unwrap()
                .get_mut(&bearer_id)
                .unwrap()
                .ebi = *ebi;
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess_id)
                .unwrap()
                .bearer_list
                .push(bearer_id);
            ctx.mme_ue_pool
                .write()
                .unwrap()
                .get_mut(&mme_ue_id)
                .unwrap()
                .sess_list
                .push(sess_id);
        }
        let teid = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().mme_s11_teid;
        (mme_ue_id, teid)
    }

    /// Delete Bearer Request naming `lbi` (instance 0) with `cause`.
    fn dbr_lbi(teid: u32, lbi: u8, cause: Option<u8>) -> Vec<u8> {
        let mut m = Gtp2Message::new(Gtp2Header::new(
            crate::s11_build::message_type::DELETE_BEARER_REQUEST,
            teid,
            0x688,
        ));
        m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[lbi]));
        if let Some(c) = cause {
            m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[c, 0]));
        }
        m.encode().to_vec()
    }

    #[test]
    fn the_default_bearer_of_the_last_pdn_with_reactivation_requested_detaches_re_attach_required()
    {
        let ctx = ctx();
        let (mme_ue_id, teid) = ue(&ctx, &[5]);
        let action = network_initiated_bearer_deletion(
            &ctx,
            teid,
            &dbr_lbi(teid, 5, Some(GTP_CAUSE_REACTIVATION_REQUESTED)),
        );
        assert_eq!(
            action,
            DeleteBearerAction::DetachUe {
                mme_ue_id,
                sgw_teid: 0x5ca1,
                lbi: 5,
                detach_type: DetachTypeToUe::ReAttachRequired,
            }
        );
    }

    #[test]
    fn another_cause_detaches_re_attach_not_required() {
        let ctx = ctx();
        let (_, teid) = ue(&ctx, &[5]);
        let action = network_initiated_bearer_deletion(&ctx, teid, &dbr_lbi(teid, 5, Some(16)));
        assert!(matches!(
            action,
            DeleteBearerAction::DetachUe {
                detach_type: DetachTypeToUe::ReAttachNotRequired,
                ..
            }
        ));
    }

    #[test]
    fn a_pdn_that_is_not_the_last_is_deleted_without_a_detach() {
        let ctx = ctx();
        let (mme_ue_id, teid) = ue(&ctx, &[5, 6]);
        let action = network_initiated_bearer_deletion(&ctx, teid, &dbr_lbi(teid, 6, Some(8)));
        assert_eq!(
            action,
            DeleteBearerAction::PdnDeletedLocally {
                sgw_teid: 0x5ca1,
                lbi: 6
            }
        );
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(ue.sess_list.len(), 1, "only LBI 6's PDN connection goes");
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 6).is_none());
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 5).is_some());
    }

    #[test]
    fn an_unknown_lbi_or_teid_is_context_not_found() {
        let ctx = ctx();
        let (_, teid) = ue(&ctx, &[5]);
        assert_eq!(
            network_initiated_bearer_deletion(&ctx, teid, &dbr_lbi(teid, 9, Some(8))),
            DeleteBearerAction::NoContext {
                sgw_teid: 0x5ca1,
                lbi: Some(9)
            }
        );
        assert_eq!(
            network_initiated_bearer_deletion(&ctx, 0xdead, &dbr_lbi(0xdead, 5, Some(8))),
            DeleteBearerAction::NoContext {
                sgw_teid: 0,
                lbi: Some(5)
            }
        );
    }

    #[test]
    fn a_dedicated_bearer_is_deleted_and_acknowledged() {
        let ctx = ctx();
        let (mme_ue_id, teid) = ue(&ctx, &[5]);
        let sess_id = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().sess_list[0];
        let ded = ctx.bearer_add(sess_id, mme_ue_id);
        ctx.bearer_pool.write().unwrap().get_mut(&ded).unwrap().ebi = 7;
        let mut m = Gtp2Message::new(Gtp2Header::new(
            crate::s11_build::message_type::DELETE_BEARER_REQUEST,
            teid,
            1,
        ));
        m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 1, &[7]));
        assert_eq!(
            network_initiated_bearer_deletion(&ctx, teid, &m.encode()),
            DeleteBearerAction::BearersDeletedLocally {
                sgw_teid: 0x5ca1,
                ebis: vec![7]
            }
        );
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 7).is_none());
    }

    /// The response for an LBI request carries the Cause and the LBI, and no
    /// Bearer Context (TS 29.274 Table 7.2.10.2-1).
    #[test]
    fn the_lbi_response_carries_cause_and_lbi() {
        let rsp = crate::s11_build::build_delete_bearer_response_for_lbi(
            0x5ca1,
            5,
            crate::s11_build::GtpCause::RequestAccepted,
            0x688,
        )
        .unwrap();
        assert_eq!(rsp.header.teid, Some(0x5ca1));
        assert_eq!(rsp.header.sequence_number, 0x688);
        assert_eq!(rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value[0], 16);
        assert_eq!(rsp.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap().value[..], [5]);
        assert!(rsp.get_ie(Gtp2IeType::BearerContext as u8, 0).is_none());
    }

    /// End to end through the S11 dispatch on the process-global context: the UE
    /// is sent DETACH REQUEST (re-attach required) and its PDN is gone.
    #[test]
    fn a_dispatched_delete_bearer_request_detaches_the_ue() {
        let _guard = crate::gtp_path::lock_s11();
        let ctx = crate::context::mme_self();
        let (mme_ue_id, teid) = ue(ctx, &[5]);
        dispatch_initial(
            &dbr_lbi(teid, 5, Some(GTP_CAUSE_REACTIVATION_REQUESTED)),
            crate::s11_build::message_type::DELETE_BEARER_REQUEST,
            0x688,
            "127.0.0.1:2123".parse().unwrap(),
        );
        let ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("kept until DETACH ACCEPT");
        assert!(ue.sess_list.is_empty());
        assert!(ue.t3422.is_running());
        let nas = ue.t3422.pkbuf.clone().unwrap();
        assert_eq!(&nas[nas.len() - 5..nas.len() - 2], &[0x07, 0x45, 0x01]);
        ctx.mme_ue_remove(mme_ue_id);
    }
}
