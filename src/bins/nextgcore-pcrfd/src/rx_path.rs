//! PCRF Rx Interface Path
//!
//! Port of src/pcrf/pcrf-rx-path.c - Rx interface (AAR/AAA, STR/STA,
//! ASR/ASA handling), 3GPP TS 29.214.
//!
//! All messages on this path are real Diameter messages (RFC 6733 wire
//! format). An AAR binds the AF session to the Gx (IP-CAN) session via the
//! UE IP address and pushes the derived PCC rules to the PCEF with a Gx
//! RAR (Charging-Rule-Install). An STR triggers a Gx RAR carrying
//! Charging-Rule-Remove for the rules installed for that AF session.

use bytes::Bytes;

use ogs_diameter::avp::{find_all_avps, find_avp, Avp, AvpData};
use ogs_diameter::common::avp_code;
use ogs_diameter::message::DiameterMessage;
use ogs_diameter::rx::{avp as rx_avp, cmd as rx_cmd, RX_APPLICATION_ID};
use ogs_diameter::OGS_3GPP_VENDOR_ID;

use crate::context::{pcrf_self, PccRule, OGS_IPV6_LEN};
use crate::fd_path::{pcrf_diam_stats, LocalIdentity};
use crate::gx_path::{
    self, base_avp, derive_pcc_rules, result_code as gx_result_code, ImsData, MediaComponent,
    MediaSubComponent, RarAction,
};

/// Abort cause values (3GPP TS 29.214 section 5.3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AbortCause {
    /// Bearer released
    BearerReleased = 0,
    /// Insufficient server resources
    InsufficientServerResources = 1,
    /// Insufficient bearer resources
    InsufficientBearerResources = 2,
    /// PS to CS handover
    PsToCsHandover = 3,
    /// Sponsored connectivity data limit reached
    SponsoredDataConnectivityDisallowed = 4,
}

impl From<u32> for AbortCause {
    fn from(value: u32) -> Self {
        match value {
            0 => AbortCause::BearerReleased,
            1 => AbortCause::InsufficientServerResources,
            2 => AbortCause::InsufficientBearerResources,
            3 => AbortCause::PsToCsHandover,
            4 => AbortCause::SponsoredDataConnectivityDisallowed,
            _ => AbortCause::BearerReleased,
        }
    }
}

/// Termination cause values (RFC 6733 section 8.15)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TerminationCause {
    /// Diameter logout
    DiameterLogout = 1,
    /// Service not provided
    ServiceNotProvided = 2,
    /// Bad answer
    BadAnswer = 3,
    /// Administrative
    Administrative = 4,
    /// Link broken
    LinkBroken = 5,
    /// Auth expired
    AuthExpired = 6,
    /// User moved
    UserMoved = 7,
    /// Session timeout
    SessionTimeout = 8,
}

/// Flow usage values (TS 29.214 section 5.3.12)
pub mod flow_usage {
    pub const NO_INFO: i32 = 0;
    pub const RTCP: i32 = 1;
    pub const AF_SIGNALLING: i32 = 2;
}

/// Diameter result codes used on the Rx path
pub mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
    pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    /// Experimental (vendor 10415): IP-CAN session not available (TS 29.214)
    pub const DIAMETER_IP_CAN_SESSION_NOT_AVAILABLE: u32 = 5065;
    /// Experimental (vendor 10415): requested service not authorized
    pub const DIAMETER_REQUESTED_SERVICE_NOT_AUTHORIZED: u32 = 5063;
}

// ============================================================================
// Request validation errors
// ============================================================================

/// Errors detected while validating an Rx request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RxRequestError {
    /// A mandatory AVP is absent; carries the missing AVP code
    MissingAvp(u32),
    /// Auth-Application-Id does not match the Rx application
    ApplicationUnsupported,
    /// Rx session unknown to the PCRF
    UnknownSession,
    /// No Gx session bound to the UE IP address (Experimental-Result 5065)
    IpCanSessionNotAvailable,
    /// PCC rule installation toward the PCEF failed (Experimental-Result 5063)
    ServiceNotAuthorized,
}

impl RxRequestError {
    /// Standard Result-Code (None when the error is an Experimental-Result)
    pub fn result_code(&self) -> Option<u32> {
        match self {
            RxRequestError::MissingAvp(_) => Some(result_code::DIAMETER_MISSING_AVP),
            RxRequestError::ApplicationUnsupported => {
                Some(gx_result_code::DIAMETER_APPLICATION_UNSUPPORTED)
            }
            RxRequestError::UnknownSession => Some(result_code::DIAMETER_UNKNOWN_SESSION_ID),
            RxRequestError::IpCanSessionNotAvailable | RxRequestError::ServiceNotAuthorized => None,
        }
    }

    /// Experimental-Result-Code (vendor 10415) when applicable
    pub fn experimental_result_code(&self) -> Option<u32> {
        match self {
            RxRequestError::IpCanSessionNotAvailable => {
                Some(result_code::DIAMETER_IP_CAN_SESSION_NOT_AVAILABLE)
            }
            RxRequestError::ServiceNotAuthorized => {
                Some(result_code::DIAMETER_REQUESTED_SERVICE_NOT_AUTHORIZED)
            }
            _ => None,
        }
    }

    /// AVP code to report in Failed-AVP (if applicable)
    pub fn failed_avp_code(&self) -> Option<u32> {
        match self {
            RxRequestError::MissingAvp(code) => Some(*code),
            _ => None,
        }
    }
}

// ============================================================================
// AAR parsing (TS 29.214 section 5.6.1)
// ============================================================================

/// Parsed AAR content
#[derive(Debug, Clone, Default)]
pub struct AarInfo {
    /// Session-Id
    pub session_id: String,
    /// Origin-Host of the AF
    pub origin_host: String,
    /// Origin-Realm of the AF
    pub origin_realm: String,
    /// Framed-IP-Address of the UE
    pub framed_ipv4: Option<[u8; 4]>,
    /// Framed-IPv6-Prefix of the UE
    pub framed_ipv6: Option<[u8; OGS_IPV6_LEN]>,
    /// Media components describing the AF session
    pub media_components: Vec<MediaComponent>,
}

/// Parse and validate an AAR against the TS 29.214 section 5.6.1 message
/// table. Mandatory AVPs: Session-Id, Auth-Application-Id, Origin-Host,
/// Origin-Realm, Destination-Realm.
pub fn parse_aar(msg: &DiameterMessage) -> Result<AarInfo, RxRequestError> {
    let session_id = msg
        .session_id()
        .ok_or(RxRequestError::MissingAvp(avp_code::SESSION_ID))?
        .to_string();

    let auth_app = msg
        .find_avp(avp_code::AUTH_APPLICATION_ID)
        .and_then(|a| a.as_u32())
        .ok_or(RxRequestError::MissingAvp(avp_code::AUTH_APPLICATION_ID))?;
    if auth_app != RX_APPLICATION_ID {
        return Err(RxRequestError::ApplicationUnsupported);
    }

    let origin_host = msg
        .origin_host()
        .ok_or(RxRequestError::MissingAvp(avp_code::ORIGIN_HOST))?
        .to_string();
    let origin_realm = msg
        .origin_realm()
        .ok_or(RxRequestError::MissingAvp(avp_code::ORIGIN_REALM))?
        .to_string();
    if msg.destination_realm().is_none() {
        return Err(RxRequestError::MissingAvp(avp_code::DESTINATION_REALM));
    }

    let framed_ipv4 = msg
        .find_avp(rx_avp::FRAMED_IP_ADDRESS)
        .and_then(|a| a.as_octet_string())
        .and_then(|b| {
            if b.len() >= 4 {
                Some([b[0], b[1], b[2], b[3]])
            } else {
                None
            }
        });

    let framed_ipv6 = msg
        .find_avp(rx_avp::FRAMED_IPV6_PREFIX)
        .and_then(|a| a.as_octet_string())
        .and_then(|b| {
            if b.len() < 2 {
                return None;
            }
            let mut prefix = [0u8; OGS_IPV6_LEN];
            let n = (b.len() - 2).min(OGS_IPV6_LEN);
            prefix[..n].copy_from_slice(&b[2..2 + n]);
            Some(prefix)
        });

    let mut media_components = Vec::new();
    for mcd in find_all_avps(&msg.avps, rx_avp::MEDIA_COMPONENT_DESCRIPTION) {
        if let Ok(mc) = parse_media_component(mcd) {
            media_components.push(mc);
        }
    }

    Ok(AarInfo {
        session_id,
        origin_host,
        origin_realm,
        framed_ipv4,
        framed_ipv6,
        media_components,
    })
}

/// Parse a Media-Component-Description grouped AVP (TS 29.214 section 5.3.16)
pub fn parse_media_component(avp: &Avp) -> Result<MediaComponent, RxRequestError> {
    let members = avp
        .parse_grouped()
        .map_err(|_| RxRequestError::MissingAvp(rx_avp::MEDIA_COMPONENT_DESCRIPTION))?;

    let media_component_number = find_avp(&members, rx_avp::MEDIA_COMPONENT_NUMBER)
        .and_then(|a| a.as_u32())
        .ok_or(RxRequestError::MissingAvp(rx_avp::MEDIA_COMPONENT_NUMBER))?
        as i32;

    let media_type = find_avp(&members, rx_avp::MEDIA_TYPE)
        .and_then(|a| a.as_i32())
        .unwrap_or(crate::gx_path::media_type::OTHER);
    let max_requested_bandwidth_dl = find_avp(&members, rx_avp::MAX_REQUESTED_BANDWIDTH_DL)
        .and_then(|a| a.as_u32())
        .unwrap_or(0);
    let max_requested_bandwidth_ul = find_avp(&members, rx_avp::MAX_REQUESTED_BANDWIDTH_UL)
        .and_then(|a| a.as_u32())
        .unwrap_or(0);
    let flow_status = find_avp(&members, rx_avp::FLOW_STATUS)
        .and_then(|a| a.as_i32())
        .unwrap_or(0);

    let mut sub_components = Vec::new();
    for msc in find_all_avps(&members, rx_avp::MEDIA_SUB_COMPONENT) {
        if let Ok(sub_members) = msc.parse_grouped() {
            let flow_number = find_avp(&sub_members, rx_avp::FLOW_NUMBER)
                .and_then(|a| a.as_u32())
                .unwrap_or(0) as i32;
            let sub_flow_usage = find_avp(&sub_members, rx_avp::FLOW_USAGE)
                .and_then(|a| a.as_i32())
                .unwrap_or(flow_usage::NO_INFO);
            let flows = find_all_avps(&sub_members, rx_avp::FLOW_DESCRIPTION)
                .iter()
                .filter_map(|a| {
                    a.as_octet_string()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                })
                .collect();
            sub_components.push(MediaSubComponent {
                flow_number,
                flow_usage: sub_flow_usage,
                flows,
            });
        }
    }

    Ok(MediaComponent {
        media_component_number,
        media_type,
        max_requested_bandwidth_dl,
        max_requested_bandwidth_ul,
        flow_status,
        sub_components,
    })
}

// ============================================================================
// STR parsing (RFC 6733 section 8.4.1)
// ============================================================================

/// Parsed STR content
#[derive(Debug, Clone, Default)]
pub struct StrInfo {
    /// Session-Id
    pub session_id: String,
    /// Origin-Host of the AF
    pub origin_host: String,
    /// Termination-Cause
    pub termination_cause: u32,
}

/// Parse and validate an STR. Mandatory AVPs (RFC 6733 section 8.4.1):
/// Session-Id, Origin-Host, Origin-Realm, Destination-Realm,
/// Auth-Application-Id, Termination-Cause.
pub fn parse_str(msg: &DiameterMessage) -> Result<StrInfo, RxRequestError> {
    let session_id = msg
        .session_id()
        .ok_or(RxRequestError::MissingAvp(avp_code::SESSION_ID))?
        .to_string();
    let origin_host = msg
        .origin_host()
        .ok_or(RxRequestError::MissingAvp(avp_code::ORIGIN_HOST))?
        .to_string();
    if msg.origin_realm().is_none() {
        return Err(RxRequestError::MissingAvp(avp_code::ORIGIN_REALM));
    }
    if msg.destination_realm().is_none() {
        return Err(RxRequestError::MissingAvp(avp_code::DESTINATION_REALM));
    }
    let auth_app = msg
        .find_avp(avp_code::AUTH_APPLICATION_ID)
        .and_then(|a| a.as_u32())
        .ok_or(RxRequestError::MissingAvp(avp_code::AUTH_APPLICATION_ID))?;
    if auth_app != RX_APPLICATION_ID {
        return Err(RxRequestError::ApplicationUnsupported);
    }
    let termination_cause = msg
        .find_avp(avp_code::TERMINATION_CAUSE)
        .and_then(|a| a.as_u32())
        .ok_or(RxRequestError::MissingAvp(avp_code::TERMINATION_CAUSE))?;

    Ok(StrInfo {
        session_id,
        origin_host,
        termination_cause,
    })
}

// ============================================================================
// Answer builders
// ============================================================================

/// Append Session-Id, Auth-Application-Id, Origin-Host, Origin-Realm
fn add_rx_answer_base_avps(
    answer: &mut DiameterMessage,
    request: &DiameterMessage,
    local: &LocalIdentity,
) {
    if let Some(sid) = request.session_id() {
        answer.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(local.host.clone()),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(local.realm.clone()),
    ));
}

/// Build a successful answer (AAA or STA) for the given request
pub fn build_rx_answer_success(
    request: &DiameterMessage,
    local: &LocalIdentity,
) -> DiameterMessage {
    let mut answer = DiameterMessage::new_answer(request);
    add_rx_answer_base_avps(&mut answer, request, local);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(result_code::DIAMETER_SUCCESS),
    ));
    answer
}

/// Build an error answer (AAA or STA) carrying the correct Result-Code or
/// Experimental-Result, plus Failed-AVP where applicable.
pub fn build_rx_answer_error(
    request: &DiameterMessage,
    local: &LocalIdentity,
    error: &RxRequestError,
) -> DiameterMessage {
    let mut answer = DiameterMessage::new_answer(request);
    add_rx_answer_base_avps(&mut answer, request, local);

    if let Some(code) = error.result_code() {
        // The E-bit is only set for protocol errors (3xxx), RFC 6733 7.1.3
        if (3000..4000).contains(&code) {
            answer.header.set_error();
        }
        answer.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(code),
        ));
    } else if let Some(exp_code) = error.experimental_result_code() {
        answer.add_avp(Avp::mandatory(
            avp_code::EXPERIMENTAL_RESULT,
            AvpData::Grouped(vec![
                Avp::mandatory(avp_code::VENDOR_ID, AvpData::Unsigned32(OGS_3GPP_VENDOR_ID)),
                Avp::mandatory(
                    avp_code::EXPERIMENTAL_RESULT_CODE,
                    AvpData::Unsigned32(exp_code),
                ),
            ]),
        ));
    }

    if let Some(code) = error.failed_avp_code() {
        answer.add_avp(Avp::mandatory(
            base_avp::FAILED_AVP,
            AvpData::Grouped(vec![Avp::mandatory(
                code,
                AvpData::OctetString(Bytes::new()),
            )]),
        ));
    }

    answer
}

// ============================================================================
// AAR handling (TS 29.214 section 4.4.1)
// ============================================================================

/// Handle an AA-Request: bind the AF session to the Gx session by UE IP
/// address, derive PCC rules from the media components and push them to
/// the PCEF with a Gx RAR (Charging-Rule-Install), then answer with AAA.
pub async fn handle_aar(msg: &DiameterMessage, local: &LocalIdentity) -> DiameterMessage {
    pcrf_diam_stats().rx.inc_rx_aar();

    let info = match parse_aar(msg) {
        Ok(info) => info,
        Err(e) => {
            log::warn!("AAR rejected: {e:?}");
            pcrf_diam_stats().rx.inc_rx_aar_error();
            return build_rx_answer_error(msg, local, &e);
        }
    };

    // Bind to the Gx session by UE IP address
    let gx_sid = {
        if let Some(addr) = info.framed_ipv4 {
            crate::context::pcrf_sess_find_by_ipv4(&addr)
        } else if let Some(addr) = info.framed_ipv6 {
            crate::context::pcrf_sess_find_by_ipv6(&addr)
        } else {
            None
        }
    };
    let gx_sid = match gx_sid {
        Some(sid) => sid,
        None => {
            log::warn!(
                "AAR {}: no Gx session for the UE IP address",
                info.session_id
            );
            pcrf_diam_stats().rx.inc_rx_aar_error();
            return build_rx_answer_error(msg, local, &RxRequestError::IpCanSessionNotAvailable);
        }
    };

    // Derive PCC rules from the AF media components
    let ims_data = ImsData {
        media_components: info.media_components.clone(),
    };
    let rules = derive_pcc_rules(&ims_data, &format!("rx-{}", info.session_id));

    // Create / update the Rx session binding
    {
        let ctx = pcrf_self();
        let context = match ctx.read() {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to read context: {e}");
                pcrf_diam_stats().rx.inc_rx_aar_error();
                return build_rx_answer_error(msg, local, &RxRequestError::UnknownSession);
            }
        };
        let gx_idx = match context.gx_session_get_idx(&gx_sid) {
            Some(idx) => idx,
            None => {
                pcrf_diam_stats().rx.inc_rx_aar_error();
                return build_rx_answer_error(
                    msg,
                    local,
                    &RxRequestError::IpCanSessionNotAvailable,
                );
            }
        };
        context.rx_session_add(&info.session_id, gx_idx);
        context.rx_session_update(&info.session_id, |session| {
            session.peer_host = Some(info.origin_host.clone());
            session.pcc_rules = rules
                .iter()
                .map(|r| PccRule {
                    name: r.name.clone(),
                    qos_index: r.qos_index,
                    flow_status: r.flow_status,
                    precedence: r.precedence,
                    num_of_flow: r.flows.len(),
                })
                .collect();
        });
    }

    // Push the rules to the PCEF (Gx RAR with Charging-Rule-Install)
    if !rules.is_empty() {
        match gx_path::pcrf_gx_send_rar(&gx_sid, RarAction::Install(rules)).await {
            Ok(code) if code == gx_result_code::DIAMETER_SUCCESS => {}
            Ok(code) => {
                log::warn!(
                    "RAR install for Rx session {} failed with result code {code}",
                    info.session_id
                );
                remove_rx_session(&info.session_id);
                pcrf_diam_stats().rx.inc_rx_aar_error();
                return build_rx_answer_error(msg, local, &RxRequestError::ServiceNotAuthorized);
            }
            Err(e) => {
                log::warn!("RAR install for Rx session {} failed: {e}", info.session_id);
                remove_rx_session(&info.session_id);
                pcrf_diam_stats().rx.inc_rx_aar_error();
                return build_rx_answer_error(msg, local, &RxRequestError::ServiceNotAuthorized);
            }
        }
    }

    pcrf_diam_stats().rx.inc_tx_aaa();
    build_rx_answer_success(msg, local)
}

fn remove_rx_session(rx_sid: &str) {
    let ctx = pcrf_self();
    if let Ok(context) = ctx.read() {
        context.rx_session_remove(rx_sid);
    };
}

// ============================================================================
// STR handling (TS 29.214 section 4.4.4)
// ============================================================================

/// Handle a Session-Termination-Request: send a Gx RAR carrying
/// Charging-Rule-Remove for the PCC rules installed for this AF session,
/// unbind the Rx session and answer with STA.
pub async fn handle_str(msg: &DiameterMessage, local: &LocalIdentity) -> DiameterMessage {
    pcrf_diam_stats().rx.inc_rx_str();

    let info = match parse_str(msg) {
        Ok(info) => info,
        Err(e) => {
            log::warn!("STR rejected: {e:?}");
            pcrf_diam_stats().rx.inc_rx_str_error();
            return build_rx_answer_error(msg, local, &e);
        }
    };

    // Look up the Rx session and its Gx binding
    let (gx_sid, rule_names) = {
        let ctx = pcrf_self();
        let context = match ctx.read() {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to read context: {e}");
                pcrf_diam_stats().rx.inc_rx_str_error();
                return build_rx_answer_error(msg, local, &RxRequestError::UnknownSession);
            }
        };
        let rx_session = match context.rx_session_find_by_sid(&info.session_id) {
            Some(s) => s,
            None => {
                log::warn!("STR for unknown Rx session: {}", info.session_id);
                pcrf_diam_stats().rx.inc_rx_str_error();
                return build_rx_answer_error(msg, local, &RxRequestError::UnknownSession);
            }
        };
        let gx_sid = context
            .gx_session_find_by_idx(rx_session.gx_session_idx)
            .map(|s| s.sid);
        let rule_names: Vec<String> = rx_session
            .pcc_rules
            .iter()
            .map(|r| r.name.clone())
            .collect();
        (gx_sid, rule_names)
    };

    // Remove the PCC rules from the PCEF (Gx RAR with Charging-Rule-Remove)
    if let Some(gx_sid) = gx_sid {
        if !rule_names.is_empty() {
            match gx_path::pcrf_gx_send_rar(&gx_sid, RarAction::Remove(rule_names)).await {
                Ok(code) if code == gx_result_code::DIAMETER_SUCCESS => {}
                Ok(code) => {
                    // Removal failures do not block session termination;
                    // the PCEF state is cleaned up when the IP-CAN session
                    // terminates (TS 29.214 section 4.4.4)
                    log::warn!(
                        "RAR remove for Rx session {} returned result code {code}",
                        info.session_id
                    );
                }
                Err(e) => {
                    log::warn!("RAR remove for Rx session {} failed: {e}", info.session_id);
                }
            }
        }
    } else {
        log::warn!("STR {}: bound Gx session no longer exists", info.session_id);
    }

    remove_rx_session(&info.session_id);

    pcrf_diam_stats().rx.inc_tx_sta();
    build_rx_answer_success(msg, local)
}

// ============================================================================
// ASR / ASA (TS 29.214 section 4.4.6)
// ============================================================================

/// Build an Abort-Session-Request toward the AF.
///
/// Mandatory AVPs (RFC 6733 section 8.5.1 + TS 29.214): Session-Id,
/// Origin-Host, Origin-Realm, Destination-Realm, Destination-Host,
/// Auth-Application-Id, Abort-Cause.
pub fn build_asr(
    rx_sid: &str,
    local: &LocalIdentity,
    dest_host: &str,
    dest_realm: &str,
    abort_cause: AbortCause,
) -> DiameterMessage {
    let mut asr = DiameterMessage::new_request(rx_cmd::ABORT_SESSION, RX_APPLICATION_ID);
    asr.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(rx_sid.to_string()),
    ));
    asr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(local.host.clone()),
    ));
    asr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(local.realm.clone()),
    ));
    asr.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    asr.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    asr.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));
    asr.add_avp(Avp::vendor_mandatory(
        rx_avp::ABORT_CAUSE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(abort_cause as i32),
    ));
    asr
}

/// Parse an Abort-Session-Answer, returning the Result-Code
pub fn parse_asa(msg: &DiameterMessage) -> Result<u32, String> {
    msg.result_code()
        .ok_or_else(|| "ASA carries no Result-Code".to_string())
}

/// Send an ASR for an Rx session whose IP-CAN session terminated.
pub async fn pcrf_rx_send_asr_for_target(target: &gx_path::RxAbortTarget, local: &LocalIdentity) {
    let Some(ref peer_host) = target.peer_host else {
        log::warn!("Cannot send ASR for {}: no AF peer host", target.rx_sid);
        return;
    };
    let dest_realm = target
        .peer_realm
        .clone()
        .unwrap_or_else(|| local.realm.clone());

    let asr = build_asr(
        &target.rx_sid,
        local,
        peer_host,
        &dest_realm,
        AbortCause::BearerReleased,
    );

    pcrf_diam_stats().rx.inc_tx_asr();
    match crate::fd_path::pcrf_fd_send_request(peer_host, asr).await {
        Ok(asa) => {
            pcrf_diam_stats().rx.inc_rx_asa();
            match parse_asa(&asa) {
                Ok(code) if code == result_code::DIAMETER_SUCCESS => {
                    log::info!("ASA success for Rx session {}", target.rx_sid);
                }
                Ok(code) => {
                    log::warn!("ASA error for Rx session {}: {code}", target.rx_sid);
                }
                Err(e) => log::warn!("Malformed ASA for {}: {e}", target.rx_sid),
            }
        }
        Err(e) => {
            log::warn!("Failed to send ASR for {}: {e}", target.rx_sid);
        }
    }
}

// ============================================================================
// Init / final
// ============================================================================

/// Initialize Rx interface
pub fn pcrf_rx_init() -> Result<(), String> {
    log::info!("PCRF Rx interface initialized (application id {RX_APPLICATION_ID})");
    Ok(())
}

/// Finalize Rx interface
pub fn pcrf_rx_final() {
    log::info!("PCRF Rx interface finalized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gx_path::media_type;

    fn local() -> LocalIdentity {
        LocalIdentity {
            host: "pcrf.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
            realm: "epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        }
    }

    fn roundtrip(msg: &DiameterMessage) -> DiameterMessage {
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        DiameterMessage::decode(&mut bytes).expect("decode")
    }

    fn build_test_aar(session_id: &str, ue_ip: [u8; 4]) -> DiameterMessage {
        let mut aar = ogs_diameter::rx::create_aar(
            session_id,
            "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );
        aar.header.hop_by_hop_id = 0xa1;
        aar.header.end_to_end_id = 0xa2;
        aar.add_avp(Avp::mandatory(
            rx_avp::FRAMED_IP_ADDRESS,
            AvpData::OctetString(Bytes::copy_from_slice(&ue_ip)),
        ));
        // One audio media component with two flow descriptions
        let msc = Avp::vendor_mandatory(
            rx_avp::MEDIA_SUB_COMPONENT,
            OGS_3GPP_VENDOR_ID,
            AvpData::Grouped(vec![
                Avp::vendor_mandatory(
                    rx_avp::FLOW_NUMBER,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::Unsigned32(1),
                ),
                Avp::vendor_mandatory(
                    rx_avp::FLOW_DESCRIPTION,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::OctetString(Bytes::from_static(
                        b"permit out 17 from 10.0.0.1 5004 to 10.45.0.2 6000",
                    )),
                ),
                Avp::vendor_mandatory(
                    rx_avp::FLOW_DESCRIPTION,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::OctetString(Bytes::from_static(
                        b"permit in 17 from 10.45.0.2 6000 to 10.0.0.1 5004",
                    )),
                ),
            ]),
        );
        let mcd = Avp::vendor_mandatory(
            rx_avp::MEDIA_COMPONENT_DESCRIPTION,
            OGS_3GPP_VENDOR_ID,
            AvpData::Grouped(vec![
                Avp::vendor_mandatory(
                    rx_avp::MEDIA_COMPONENT_NUMBER,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::Unsigned32(1),
                ),
                Avp::vendor_mandatory(
                    rx_avp::MEDIA_TYPE,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::Enumerated(media_type::AUDIO),
                ),
                Avp::vendor_mandatory(
                    rx_avp::MAX_REQUESTED_BANDWIDTH_DL,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::Unsigned32(64000),
                ),
                Avp::vendor_mandatory(
                    rx_avp::MAX_REQUESTED_BANDWIDTH_UL,
                    OGS_3GPP_VENDOR_ID,
                    AvpData::Unsigned32(64000),
                ),
                msc,
            ]),
        );
        aar.add_avp(mcd);
        aar
    }

    fn build_test_str(session_id: &str) -> DiameterMessage {
        let mut str_msg = ogs_diameter::rx::create_str(
            session_id,
            "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            TerminationCause::DiameterLogout as u32,
        );
        str_msg.header.hop_by_hop_id = 0xb1;
        str_msg.header.end_to_end_id = 0xb2;
        str_msg
    }

    // ------------------------------------------------------------------
    // AAR parse / round trip
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_aar_roundtrip() {
        let aar = roundtrip(&build_test_aar("rx-parse-1", [10, 45, 0, 2]));
        let info = parse_aar(&aar).expect("parse_aar");
        assert_eq!(info.session_id, "rx-parse-1");
        assert_eq!(info.origin_host, "pcscf.ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(info.framed_ipv4, Some([10, 45, 0, 2]));
        assert_eq!(info.media_components.len(), 1);
        let mc = &info.media_components[0];
        assert_eq!(mc.media_component_number, 1);
        assert_eq!(mc.media_type, media_type::AUDIO);
        assert_eq!(mc.max_requested_bandwidth_dl, 64000);
        assert_eq!(mc.sub_components.len(), 1);
        assert_eq!(mc.sub_components[0].flows.len(), 2);
        assert!(mc.sub_components[0].flows[0].starts_with("permit out"));
    }

    #[test]
    fn test_parse_aar_missing_mandatory() {
        // Missing everything but Session-Id
        let mut aar = DiameterMessage::new_request(rx_cmd::AA, RX_APPLICATION_ID);
        aar.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("rx-strict-1".to_string()),
        ));
        let err = parse_aar(&roundtrip(&aar)).unwrap_err();
        assert_eq!(
            err,
            RxRequestError::MissingAvp(avp_code::AUTH_APPLICATION_ID)
        );
    }

    #[test]
    fn test_parse_str_roundtrip() {
        let str_msg = roundtrip(&build_test_str("rx-str-1"));
        let info = parse_str(&str_msg).expect("parse_str");
        assert_eq!(info.session_id, "rx-str-1");
        assert_eq!(
            info.termination_cause,
            TerminationCause::DiameterLogout as u32
        );
    }

    #[test]
    fn test_parse_str_missing_termination_cause() {
        let mut str_msg = build_test_str("rx-str-2");
        str_msg
            .avps
            .retain(|a| a.code != avp_code::TERMINATION_CAUSE);
        let err = parse_str(&roundtrip(&str_msg)).unwrap_err();
        assert_eq!(err, RxRequestError::MissingAvp(avp_code::TERMINATION_CAUSE));
    }

    // ------------------------------------------------------------------
    // Handler error paths (no transport available in unit tests)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_handle_aar_no_gx_session() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        // No Gx session bound to this IP
        let aar = roundtrip(&build_test_aar("rx-no-gx", [203, 0, 113, 99]));
        let aaa = roundtrip(&handle_aar(&aar, &local()).await);

        assert!(aaa.header.is_answer());
        assert_eq!(aaa.header.command_code, rx_cmd::AA);
        assert_eq!(aaa.header.hop_by_hop_id, 0xa1);
        // Experimental-Result with IP_CAN_SESSION_NOT_AVAILABLE
        assert!(aaa.result_code().is_none());
        let exp = aaa
            .find_avp(avp_code::EXPERIMENTAL_RESULT)
            .expect("Experimental-Result");
        let members = exp.parse_grouped().unwrap();
        assert_eq!(
            find_avp(&members, avp_code::EXPERIMENTAL_RESULT_CODE).and_then(|a| a.as_u32()),
            Some(result_code::DIAMETER_IP_CAN_SESSION_NOT_AVAILABLE)
        );
    }

    #[tokio::test]
    async fn test_handle_str_unknown_session() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let str_msg = roundtrip(&build_test_str("rx-unknown-str"));
        let sta = roundtrip(&handle_str(&str_msg, &local()).await);
        assert_eq!(
            sta.result_code(),
            Some(result_code::DIAMETER_UNKNOWN_SESSION_ID)
        );
    }

    #[tokio::test]
    async fn test_handle_str_missing_avp_failed_avp() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let mut str_msg = build_test_str("rx-str-missing");
        str_msg
            .avps
            .retain(|a| a.code != avp_code::TERMINATION_CAUSE);
        let sta = roundtrip(&handle_str(&roundtrip(&str_msg), &local()).await);
        assert_eq!(sta.result_code(), Some(result_code::DIAMETER_MISSING_AVP));
        let failed = sta.find_avp(base_avp::FAILED_AVP).expect("Failed-AVP");
        let members = failed.parse_grouped().unwrap();
        assert_eq!(members[0].code, avp_code::TERMINATION_CAUSE);
    }

    // ------------------------------------------------------------------
    // ASR / ASA round trip
    // ------------------------------------------------------------------

    #[test]
    fn test_build_asr_roundtrip() {
        let asr = build_asr(
            "rx-asr-1",
            &local(),
            "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            AbortCause::BearerReleased,
        );
        let asr = roundtrip(&asr);
        assert!(asr.header.is_request());
        assert_eq!(asr.header.command_code, rx_cmd::ABORT_SESSION);
        assert_eq!(asr.header.application_id, RX_APPLICATION_ID);
        assert_eq!(asr.session_id(), Some("rx-asr-1"));
        assert_eq!(
            asr.destination_host(),
            Some("pcscf.ims.mnc001.mcc001.3gppnetwork.org")
        );
        let abort_cause = asr
            .find_vendor_avp(rx_avp::ABORT_CAUSE, OGS_3GPP_VENDOR_ID)
            .expect("Abort-Cause");
        assert_eq!(
            abort_cause.as_i32(),
            Some(AbortCause::BearerReleased as i32)
        );
    }

    #[test]
    fn test_parse_asa() {
        let asr = build_asr(
            "rx-asa-1",
            &local(),
            "af.example.com",
            "example.com",
            AbortCause::BearerReleased,
        );
        let mut asa = DiameterMessage::new_answer(&asr);
        asa.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(result_code::DIAMETER_SUCCESS),
        ));
        assert_eq!(
            parse_asa(&roundtrip(&asa)),
            Ok(result_code::DIAMETER_SUCCESS)
        );
        let empty = DiameterMessage::new_answer(&asr);
        assert!(parse_asa(&roundtrip(&empty)).is_err());
    }

    #[test]
    fn test_abort_cause_from_u32() {
        assert_eq!(AbortCause::from(0), AbortCause::BearerReleased);
        assert_eq!(AbortCause::from(1), AbortCause::InsufficientServerResources);
        assert_eq!(AbortCause::from(2), AbortCause::InsufficientBearerResources);
        assert_eq!(AbortCause::from(99), AbortCause::BearerReleased);
    }

    #[test]
    fn test_pcrf_rx_init_final() {
        assert!(pcrf_rx_init().is_ok());
        pcrf_rx_final();
    }
}
