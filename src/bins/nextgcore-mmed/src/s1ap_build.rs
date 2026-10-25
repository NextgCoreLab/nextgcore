//! S1AP Message Building
//!
//! Port of src/mme/s1ap-build.c - S1AP message building functions.
//!
//! All messages are APER-encoded via the `nextgcore-s1ap` codec per 3GPP TS 36.413.
//! This module converts MME context types into `nextgcore-s1ap` message structures
//! and returns the encoded wire bytes. There is no bespoke byte layout here:
//! every builder goes through the generated codec in `s1ap_gen`.

use crate::context::{
    ECgi, EnbUe, EpsTai, IpAddr, MmeBearer, MmeContext, MmeUe, PlmnId, S1apCause, S1apCauseGroup,
};
#[cfg(test)]
use crate::s1ap_gen::test_codec::builder;
use crate::sbc_message::SbcPwsData;
use nextgcore_s1ap::{
    AllocationRetentionPriority, Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork,
    CauseTransport, CnDomain, CsFallbackIndicator, ErabItem, ErabLevelQosParameters,
    ErabModifyRequest, ErabReleaseCommand, ErabSetupRequest, ErabToBeModifiedItem,
    ErabToBeSetupItem, ErrorIndication, EutranCgi, GbrQosInformation, InitialContextSetupRequest,
    KillRequest, OverloadAction, Paging, PagingDrx, S1apResult, STmsi, Tai, TimeToWait, UeAmbr,
    UeContextModificationRequest, UePagingId, UeS1apIds, UeSecurityCapabilities, WarningAreaList,
    WriteReplaceWarningRequest,
};

// ============================================================================
// S1AP Cause Values (TS 36.413 §9.2.1.3)
// ============================================================================

/// Radio Network cause values
pub mod radio_network_cause {
    pub const UNSPECIFIED: i64 = 0;
    pub const TX2_RELOCOVERALL_EXPIRY: i64 = 1;
    pub const SUCCESSFUL_HANDOVER: i64 = 2;
    pub const RELEASE_DUE_TO_EUTRAN_GENERATED_REASON: i64 = 3;
    pub const HANDOVER_CANCELLED: i64 = 4;
    pub const PARTIAL_HANDOVER: i64 = 5;
    pub const HO_FAILURE_IN_TARGET_EPC_ENB_OR_TARGET_SYSTEM: i64 = 6;
    pub const HO_TARGET_NOT_ALLOWED: i64 = 7;
    pub const TS1_RELOCOVERALL_EXPIRY: i64 = 8;
    pub const TS1_RELOCPREP_EXPIRY: i64 = 9;
    pub const CELL_NOT_AVAILABLE: i64 = 10;
    pub const UNKNOWN_TARGET_ID: i64 = 11;
    pub const NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL: i64 = 12;
    pub const UNKNOWN_MME_UE_S1AP_ID: i64 = 13;
    pub const UNKNOWN_ENB_UE_S1AP_ID: i64 = 14;
    pub const UNKNOWN_PAIR_UE_S1AP_ID: i64 = 15;
    pub const HANDOVER_DESIRABLE_FOR_RADIO_REASON: i64 = 16;
    pub const TIME_CRITICAL_HANDOVER: i64 = 17;
    pub const RESOURCE_OPTIMISATION_HANDOVER: i64 = 18;
    pub const REDUCE_LOAD_IN_SERVING_CELL: i64 = 19;
    pub const USER_INACTIVITY: i64 = 20;
    pub const RADIO_CONNECTION_WITH_UE_LOST: i64 = 21;
    pub const LOAD_BALANCING_TAU_REQUIRED: i64 = 22;
    pub const CS_FALLBACK_TRIGGERED: i64 = 23;
    pub const UE_NOT_AVAILABLE_FOR_PS_SERVICE: i64 = 24;
    pub const RADIO_RESOURCES_NOT_AVAILABLE: i64 = 25;
    pub const FAILURE_IN_RADIO_INTERFACE_PROCEDURE: i64 = 26;
    pub const INVALID_QOS_COMBINATION: i64 = 27;
    pub const INTERRAT_REDIRECTION: i64 = 28;
    pub const INTERACTION_WITH_OTHER_PROCEDURE: i64 = 29;
    pub const UNKNOWN_E_RAB_ID: i64 = 30;
    pub const MULTIPLE_E_RAB_ID_INSTANCES: i64 = 31;
    pub const ENCRYPTION_AND_OR_INTEGRITY_PROTECTION_ALGORITHMS_NOT_SUPPORTED: i64 = 32;
    pub const S1_INTRA_SYSTEM_HANDOVER_TRIGGERED: i64 = 33;
    pub const S1_INTER_SYSTEM_HANDOVER_TRIGGERED: i64 = 34;
    pub const X2_HANDOVER_TRIGGERED: i64 = 35;
}

/// Transport cause values
pub mod transport_cause {
    pub const TRANSPORT_RESOURCE_UNAVAILABLE: i64 = 0;
    pub const UNSPECIFIED: i64 = 1;
}

/// NAS cause values
pub mod nas_cause {
    pub const NORMAL_RELEASE: i64 = 0;
    pub const AUTHENTICATION_FAILURE: i64 = 1;
    pub const DETACH: i64 = 2;
    pub const UNSPECIFIED: i64 = 3;
    pub const CSG_SUBSCRIPTION_EXPIRY: i64 = 4;
}

/// Protocol cause values
pub mod protocol_cause {
    pub const TRANSFER_SYNTAX_ERROR: i64 = 0;
    pub const ABSTRACT_SYNTAX_ERROR_REJECT: i64 = 1;
    pub const ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY: i64 = 2;
    pub const MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE: i64 = 3;
    pub const SEMANTIC_ERROR: i64 = 4;
    pub const ABSTRACT_SYNTAX_ERROR_FALSELY_CONSTRUCTED_MESSAGE: i64 = 5;
    pub const UNSPECIFIED: i64 = 6;
}

/// Misc cause values
pub mod misc_cause {
    pub const CONTROL_PROCESSING_OVERLOAD: i64 = 0;
    pub const NOT_ENOUGH_USER_PLANE_PROCESSING_RESOURCES: i64 = 1;
    pub const HARDWARE_FAILURE: i64 = 2;
    pub const OM_INTERVENTION: i64 = 3;
    pub const UNSPECIFIED: i64 = 4;
    pub const UNKNOWN_PLMN: i64 = 5;
}

// ============================================================================
// Context Type <-> nextgcore-s1ap Type Conversions
// ============================================================================

/// Encode PLMN ID to 3 bytes (TS 36.413 §9.2.3.8 TBCD encoding)
pub fn encode_plmn_id(plmn: &PlmnId) -> [u8; 3] {
    let mut bytes = [0u8; 3];
    bytes[0] = (plmn.mcc2 << 4) | plmn.mcc1;
    if plmn.mnc3 == 0x0f {
        bytes[1] = 0xf0 | plmn.mcc3;
    } else {
        bytes[1] = (plmn.mnc3 << 4) | plmn.mcc3;
    }
    bytes[2] = (plmn.mnc2 << 4) | plmn.mnc1;
    bytes
}

/// Decode PLMN ID from 3 bytes
pub fn decode_plmn_id(bytes: &[u8; 3]) -> PlmnId {
    PlmnId {
        mcc1: bytes[0] & 0x0f,
        mcc2: (bytes[0] >> 4) & 0x0f,
        mcc3: bytes[1] & 0x0f,
        mnc3: (bytes[1] >> 4) & 0x0f,
        mnc1: bytes[2] & 0x0f,
        mnc2: (bytes[2] >> 4) & 0x0f,
    }
}

/// Convert context TAI into the nextgcore-s1ap TAI
pub fn tai_to_s1ap(tai: &EpsTai) -> Tai {
    Tai {
        plmn_identity: encode_plmn_id(&tai.plmn_id),
        tac: tai.tac,
    }
}

/// Convert nextgcore-s1ap TAI into the context TAI
pub fn tai_from_s1ap(tai: &Tai) -> EpsTai {
    EpsTai {
        plmn_id: decode_plmn_id(&tai.plmn_identity),
        tac: tai.tac,
    }
}

/// Convert context E-CGI into the nextgcore-s1ap EUTRAN-CGI
pub fn ecgi_to_s1ap(ecgi: &ECgi) -> EutranCgi {
    EutranCgi {
        plmn_identity: encode_plmn_id(&ecgi.plmn_id),
        cell_identity: ecgi.cell_id & 0x0fff_ffff,
    }
}

/// Convert nextgcore-s1ap EUTRAN-CGI into the context E-CGI
pub fn ecgi_from_s1ap(cgi: &EutranCgi) -> ECgi {
    ECgi {
        plmn_id: decode_plmn_id(&cgi.plmn_identity),
        cell_id: cgi.cell_identity & 0x0fff_ffff,
    }
}

/// Convert a (group, value) cause pair into the nextgcore-s1ap Cause CHOICE.
///
/// Out-of-range values fall back to the group's `unspecified` value so that
/// a valid cause is always emitted on the wire.
pub fn cause_to_s1ap(group: S1apCauseGroup, value: i64) -> Cause {
    match group {
        S1apCauseGroup::RadioNetwork | S1apCauseGroup::Nothing => Cause::RadioNetwork(
            CauseRadioNetwork::try_from(value).unwrap_or(CauseRadioNetwork::Unspecified),
        ),
        S1apCauseGroup::Transport => Cause::Transport(match value {
            transport_cause::TRANSPORT_RESOURCE_UNAVAILABLE => {
                CauseTransport::TransportResourceUnavailable
            }
            _ => CauseTransport::Unspecified,
        }),
        S1apCauseGroup::Nas => Cause::Nas(match value {
            nas_cause::NORMAL_RELEASE => CauseNas::NormalRelease,
            nas_cause::AUTHENTICATION_FAILURE => CauseNas::AuthenticationFailure,
            nas_cause::DETACH => CauseNas::Detach,
            nas_cause::CSG_SUBSCRIPTION_EXPIRY => CauseNas::CsgSubscriptionExpiry,
            _ => CauseNas::Unspecified,
        }),
        S1apCauseGroup::Protocol => {
            Cause::Protocol(CauseProtocol::try_from(value).unwrap_or(CauseProtocol::Unspecified))
        }
        S1apCauseGroup::Misc => {
            Cause::Misc(CauseMisc::try_from(value).unwrap_or(CauseMisc::Unspecified))
        }
    }
}

/// Convert an nextgcore-s1ap Cause CHOICE into the context (group, value) pair
pub fn cause_from_s1ap(cause: &Cause) -> S1apCause {
    match cause {
        Cause::RadioNetwork(v) => S1apCause {
            group: S1apCauseGroup::RadioNetwork,
            cause: *v as i64,
        },
        Cause::Transport(v) => S1apCause {
            group: S1apCauseGroup::Transport,
            cause: *v as i64,
        },
        Cause::Nas(v) => S1apCause {
            group: S1apCauseGroup::Nas,
            cause: *v as i64,
        },
        Cause::Protocol(v) => S1apCause {
            group: S1apCauseGroup::Protocol,
            cause: *v as i64,
        },
        Cause::Misc(v) => S1apCause {
            group: S1apCauseGroup::Misc,
            cause: *v as i64,
        },
    }
}

/// Convert a context IP address into an S1AP TransportLayerAddress payload
pub fn ip_to_transport_address(ip: &IpAddr) -> Vec<u8> {
    if let Some(v4) = ip.ipv4 {
        v4.to_vec()
    } else if let Some(v6) = ip.ipv6 {
        v6.to_vec()
    } else {
        Vec::new()
    }
}

/// Convert an S1AP TransportLayerAddress payload into a context IP address
pub fn transport_address_to_ip(addr: &[u8]) -> IpAddr {
    let mut ip = IpAddr::default();
    if addr.len() == 4 {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(addr);
        ip.ipv4 = Some(v4);
    } else if addr.len() == 16 {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(addr);
        ip.ipv6 = Some(v6);
    } else if addr.len() == 20 {
        // #948, TS 36.413 §9.2.2.1: 160 bits, the IPv4 address then the IPv6
        // one (a dual-stack endpoint).
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&addr[..4]);
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(&addr[4..]);
        ip.ipv4 = Some(v4);
        ip.ipv6 = Some(v6);
    }
    ip
}

/// Build the S1AP UE Security Capabilities from the UE's replayed NAS
/// capability bitmaps (TS 36.413 §9.2.1.40).
///
/// The NAS bitmap carries EEA0/EIA0 in the MSB; the S1AP BIT STRING starts
/// at 128-EEA1/128-EIA1, so the bitmap is shifted left past the EA0 bit.
pub fn ue_security_capabilities_from(mme_ue: &MmeUe) -> UeSecurityCapabilities {
    UeSecurityCapabilities {
        encryption_algorithms: (mme_ue.ue_network_capability.eea as u16) << 9,
        integrity_algorithms: (mme_ue.ue_network_capability.eia as u16) << 9,
    }
}

/// Build the E-RAB Level QoS Parameters from a bearer context
pub fn erab_qos_from_bearer(bearer: &MmeBearer) -> ErabLevelQosParameters {
    let gbr_qos_info = if bearer.qos.gbr.downlink > 0 || bearer.qos.gbr.uplink > 0 {
        Some(GbrQosInformation {
            erab_max_bitrate_dl: bearer.qos.mbr.downlink,
            erab_max_bitrate_ul: bearer.qos.mbr.uplink,
            erab_guaranteed_bitrate_dl: bearer.qos.gbr.downlink,
            erab_guaranteed_bitrate_ul: bearer.qos.gbr.uplink,
        })
    } else {
        None
    };

    ErabLevelQosParameters {
        qci: bearer.qos.qci,
        arp: AllocationRetentionPriority {
            priority_level: bearer.qos.arp.priority_level,
            // #1180: the context holds the GTP/NAS coding (TS 29.274 §8.15: PCI or
            // PVI 1 = disabled); TS 36.413 §9.2.1.60 codes 1 as
            // may-trigger-pre-emption / pre-emptable. A 0 here is enabled.
            pre_emption_capability: bearer.qos.arp.pre_emption_capability == 0,
            pre_emption_vulnerability: bearer.qos.arp.pre_emption_vulnerability == 0,
        },
        gbr_qos_info,
    }
}

/// UE Identity Index Value per TS 36.304 §7.1: IMSI mod 1024 (10 bits),
/// where the IMSI is interpreted as a decimal integer.
pub fn ue_identity_index_from_imsi(imsi_bcd: &str) -> u16 {
    let mut index: u32 = 0;
    for c in imsi_bcd.chars() {
        if let Some(d) = c.to_digit(10) {
            index = (index * 10 + d) % 1024;
        }
    }
    index as u16
}

/// Encode an IMSI BCD string as TBCD bytes (for the IMSI UE Paging Identity)
pub fn imsi_bcd_to_tbcd(imsi_bcd: &str) -> Vec<u8> {
    let digits: Vec<u8> = imsi_bcd
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    let mut out = Vec::with_capacity(digits.len().div_ceil(2));
    for pair in digits.chunks(2) {
        let low = pair[0];
        let high = if pair.len() == 2 { pair[1] } else { 0x0f };
        out.push((high << 4) | low);
    }
    out
}

// ============================================================================
// S1 Setup (§8.7.3)
// ============================================================================

/// The served GUMMEIs of the MME context, in [`crate::s1ap_gen`]'s terms.
fn served_gummeis(ctx: &MmeContext) -> Vec<crate::s1ap_gen::ServedGummei> {
    ctx.served_gummei
        .iter()
        .map(|gummei| crate::s1ap_gen::ServedGummei {
            plmns: gummei.plmn_id.iter().map(encode_plmn_id).collect(),
            group_ids: gummei.mme_gid.clone(),
            codes: gummei.mme_code.clone(),
        })
        .collect()
}

fn gen_err(e: asn1_codecs::PerCodecError) -> nextgcore_s1ap::S1apError {
    nextgcore_s1ap::S1apError::AsnError(e.to_string())
}

/// Build S1 Setup Response from the MME context configuration (generated
/// codec, #514).
pub fn build_setup_response(ctx: &MmeContext) -> S1apResult<Vec<u8>> {
    build_setup_response_with_diagnostics(ctx, &[])
}

/// Build S1 Setup Response, reporting `notify` (unknown ignore-and-notify IEs
/// of the request) in its Criticality Diagnostics (TS 36.413 §10.3.4.2).
pub fn build_setup_response_with_diagnostics(
    ctx: &MmeContext,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_s1_setup_response(
        ctx.mme_name.as_deref(),
        &served_gummeis(ctx),
        ctx.relative_capacity,
        notify,
    )
    .map_err(gen_err)
}

/// Build S1 Setup Failure (generated codec, #514)
pub fn build_setup_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> S1apResult<Vec<u8>> {
    build_setup_failure_with_diagnostics(cause_group, cause_value, time_to_wait, &[])
}

/// Build S1 Setup Failure carrying `reject` in its Criticality Diagnostics
/// (TS 36.413 §10.3.4.2).
pub fn build_setup_failure_with_diagnostics(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
    reject: &[crate::s1ap_gen::DiagnosedIe],
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_s1_setup_failure(
        cause_to_s1ap(cause_group, cause_value),
        time_to_wait,
        reject,
    )
    .map_err(gen_err)
}

/// The pre-#514 hand-written S1 Setup Response, kept as the byte-equivalence
/// oracle for the generated one.
#[cfg(test)]
pub(crate) fn hand_written_build_setup_response(ctx: &MmeContext) -> S1apResult<Vec<u8>> {
    let served_gummeis = ctx
        .served_gummei
        .iter()
        .map(|gummei| nextgcore_s1ap::ServedGummeiItem {
            served_plmns: gummei.plmn_id.iter().map(encode_plmn_id).collect(),
            served_group_ids: gummei.mme_gid.clone(),
            served_mmec_codes: gummei.mme_code.clone(),
        })
        .collect();

    builder::build_s1_setup_response(&nextgcore_s1ap::S1SetupResponse {
        mme_name: ctx.mme_name.clone(),
        served_gummeis,
        relative_mme_capacity: ctx.relative_capacity,
    })
}

/// The pre-#514 hand-written S1 Setup Failure, kept as the oracle.
#[cfg(test)]
pub(crate) fn hand_written_build_setup_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> S1apResult<Vec<u8>> {
    builder::build_s1_setup_failure(&nextgcore_s1ap::S1SetupFailure {
        cause: cause_to_s1ap(cause_group, cause_value),
        time_to_wait,
    })
}

// ============================================================================
// NAS Transport (§8.6)
// ============================================================================

/// Build Downlink NAS Transport for an eNB UE context
pub fn build_downlink_nas_transport(enb_ue: &EnbUe, nas_pdu: &[u8]) -> S1apResult<Vec<u8>> {
    build_downlink_nas_transport_with_ids(enb_ue.enb_ue_s1ap_id, enb_ue.mme_ue_s1ap_id, nas_pdu)
}

/// Build Downlink NAS Transport with explicit UE S1AP IDs
pub fn build_downlink_nas_transport_with_ids(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu: &[u8],
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_downlink_nas_transport(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_pdu)
        .map_err(gen_err)
}

/// The pre-#514 hand-written DOWNLINK NAS TRANSPORT, kept as the oracle.
#[cfg(test)]
pub(crate) fn hand_written_build_downlink_nas_transport(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu: &[u8],
) -> S1apResult<Vec<u8>> {
    builder::build_downlink_nas_transport(&nextgcore_s1ap::DlNasTransport {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        nas_pdu: nas_pdu.to_vec(),
    })
}

// ============================================================================
// Initial Context Setup (§8.3.1)
// ============================================================================

/// The UE-AMBR the MME signals (TS 23.401 §4.7.3, #811): "the sum of the
/// APN-AMBR of all active APNs up to the value of the subscribed UE-AMBR", per
/// direction. An APN-AMBR sum of zero (none known) falls back to the subscribed
/// value, and a zero subscribed value (none received) to the sum.
pub fn ue_ambr(
    subscribed: &crate::context::Bitrate,
    active_apn_ambrs: impl IntoIterator<Item = crate::context::Bitrate>,
) -> UeAmbr {
    let (mut dl, mut ul) = (0u64, 0u64);
    for a in active_apn_ambrs {
        dl = dl.saturating_add(a.downlink);
        ul = ul.saturating_add(a.uplink);
    }
    let cap = |sum: u64, sub: u64| match (sum, sub) {
        // Neither known: 0 would tell the eNB to allow nothing (the IE is
        // mandatory in Initial Context Setup and Handover Request), so the
        // maximum the IE can carry (TS 36.413 §9.2.1.20, 10 Gbit/s) is sent and
        // enforcement is left to the gateways' APN-AMBR (#869 review).
        (0, 0) => UE_AMBR_UNKNOWN,
        (0, s) | (s, 0) => s,
        (s, sub) => s.min(sub),
    };
    // Above BitRate's 10 Gbit/s (TS 36.413 §9.2.1.20) the value travels in the
    // Extended UE-AMBR IEs (Rel-15, ExtendedBitRate up to 4 Tbit/s; the encoder
    // writes them, with the legacy IE at its maximum). Only a value beyond
    // ExtendedBitRate is clamped, and said so.
    let clamp = |v: u64, dir: &str| {
        if v > UE_AMBR_MAX {
            log::warn!(
                "UE-AMBR {dir} of {v} bit/s exceeds the largest Extended Bit Rate (TS 36.413 \
                 §9.2.1.20); signalling {UE_AMBR_MAX} bit/s"
            );
        }
        v.min(UE_AMBR_MAX)
    };
    let unknown = (dl == 0 && subscribed.downlink == 0) || (ul == 0 && subscribed.uplink == 0);
    let ambr = UeAmbr {
        dl: clamp(cap(dl, subscribed.downlink), "downlink"),
        ul: clamp(cap(ul, subscribed.uplink), "uplink"),
    };
    if unknown {
        log::warn!(
            "UE-AMBR unknown in a direction (no subscribed UE-AMBR and no APN-AMBR): signalling \
             {UE_AMBR_UNKNOWN} bit/s, the largest legacy Bit Rate"
        );
    }
    ambr
}

/// The UE-AMBR signalled when neither the subscription nor any APN-AMBR gives
/// one: the largest Bit Rate (TS 36.413 §9.2.1.20, BitRate ::= INTEGER
/// (0..10000000000)), so a legacy eNB reads it without the extension.
pub const UE_AMBR_UNKNOWN: u64 = 10_000_000_000;

/// The ceiling of any UE-AMBR this MME signals: the largest Extended Bit Rate
/// (TS 36.413 §9.2.1.20, ExtendedBitRate ::= INTEGER (10000000001..4000000000000)).
pub const UE_AMBR_MAX: u64 = 4_000_000_000_000;

/// [`ue_ambr`] for `mme_ue`'s ACTIVE PDN connections: those whose bearers have a
/// Serving GW S1-U endpoint (a Create Session completed). `sess_list` also holds
/// the not yet connected sessions materialised from the subscription, whose
/// APN-AMBR does not count. Reads only the session and bearer pools, so it is
/// safe under an `mme_ue_pool` guard.
pub fn ue_ambr_of(ctx: &crate::context::MmeContext, mme_ue: &MmeUe) -> UeAmbr {
    ue_ambr(
        &mme_ue.ambr,
        mme_ue
            .sess_list
            .iter()
            .filter_map(|id| ctx.sess_find_by_id(*id))
            .filter(|s| {
                s.bearer_list
                    .iter()
                    .filter_map(|b| ctx.bearer_find_by_id(*b))
                    .any(|b| b.sgw_s1u_teid != 0)
            })
            .map(|s| s.ambr),
    )
}

/// Build Initial Context Setup Request.
///
/// The E-RAB To Be Setup list is populated from the UE's bearer contexts
/// (SGW S1-U downlink endpoints); the NAS PDU rides on the first E-RAB.
pub fn build_initial_context_setup_request(
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    bearers: &[MmeBearer],
    nas_pdu: Option<&[u8]>,
    ue_ambr: UeAmbr,
) -> S1apResult<Vec<u8>> {
    let erab_list = bearers
        .iter()
        .enumerate()
        .map(|(i, bearer)| ErabToBeSetupItem {
            erab_id: bearer.ebi,
            erab_qos: erab_qos_from_bearer(bearer),
            transport_layer_address: ip_to_transport_address(&bearer.sgw_s1u_ip),
            gtp_teid: bearer.sgw_s1u_teid,
            nas_pdu: if i == 0 {
                nas_pdu.map(|pdu| pdu.to_vec())
            } else {
                None
            },
        })
        .collect();

    let req = InitialContextSetupRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        // #811: the UE-AMBR of the active APNs (§4.7.3), not the subscribed
        // value as such.
        ue_ambr,
        erab_list,
        ue_security_capabilities: ue_security_capabilities_from(mme_ue),
        security_key: mme_ue.kenb,
    };
    crate::s1ap_gen::build_initial_context_setup_request(&req).map_err(gen_err)
}

// ============================================================================
// UE Context Release (§8.3.3)
// ============================================================================

/// Build UE Context Release Command
pub fn build_ue_context_release_command(
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: u32,
    cause_group: S1apCauseGroup,
    cause_value: i64,
) -> S1apResult<Vec<u8>> {
    let ue_s1ap_ids = match enb_ue_s1ap_id {
        Some(enb_ue_s1ap_id) => UeS1apIds::Pair {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
        },
        None => UeS1apIds::MmeOnly { mme_ue_s1ap_id },
    };

    // Generated codec (#514 stage 5).
    crate::s1ap_gen::build_ue_context_release_command(
        &ue_s1ap_ids,
        cause_to_s1ap(cause_group, cause_value),
    )
    .map_err(gen_err)
}

// ============================================================================
// E-RAB Management (§8.2)
// ============================================================================

/// Build E-RAB Setup Request for a bearer (NAS PDU is mandatory per item)
/// `ue_ambr` is the UE-AMBR to signal when it changes, i.e. when the bearer is
/// the default bearer of a new PDN connection (TS 23.401 §5.10.2 step 9,
/// §4.7.3; #811); `None` for a dedicated bearer.
pub fn build_e_rab_setup_request(
    enb_ue: &EnbUe,
    bearer: &MmeBearer,
    nas_pdu: &[u8],
    ue_ambr: Option<UeAmbr>,
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_erab_setup_request(&ErabSetupRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr,
        erab_list: vec![ErabToBeSetupItem {
            erab_id: bearer.ebi,
            erab_qos: erab_qos_from_bearer(bearer),
            transport_layer_address: ip_to_transport_address(&bearer.sgw_s1u_ip),
            gtp_teid: bearer.sgw_s1u_teid,
            nas_pdu: Some(nas_pdu.to_vec()),
        }],
    })
    .map_err(gen_err)
}

/// Build E-RAB Modify Request for a bearer
pub fn build_e_rab_modify_request(
    enb_ue: &EnbUe,
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_erab_modify_request(&ErabModifyRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: None,
        erab_list: vec![ErabToBeModifiedItem {
            erab_id: bearer.ebi,
            erab_qos: erab_qos_from_bearer(bearer),
            nas_pdu: nas_pdu.to_vec(),
        }],
    })
    .map_err(gen_err)
}

/// Build E-RAB Release Command for a bearer
/// `ue_ambr`: the UE-AMBR after the release, when a PDN connection goes (its
/// default bearer, TS 23.401 §4.7.3; #811); `None` for a dedicated bearer.
pub fn build_e_rab_release_command(
    enb_ue: &EnbUe,
    ebi: u8,
    cause_group: S1apCauseGroup,
    cause_value: i64,
    nas_pdu: Option<&[u8]>,
    ue_ambr: Option<UeAmbr>,
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_erab_release_command(&ErabReleaseCommand {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr,
        erab_list: vec![ErabItem {
            erab_id: ebi,
            cause: cause_to_s1ap(cause_group, cause_value),
        }],
        nas_pdu: nas_pdu.map(|pdu| pdu.to_vec()),
    })
    .map_err(gen_err)
}

// ============================================================================
// Paging (§8.5)
// ============================================================================

/// Build Paging.
///
/// UE Identity Index Value = IMSI mod 1024 (TS 36.304 §7.1). The UE Paging
/// Identity is the S-TMSI when one is allocated, otherwise the IMSI.
pub fn build_paging(
    mme_ue: &MmeUe,
    cn_domain: CnDomain,
    tai_list: &[EpsTai],
    paging_drx: Option<PagingDrx>,
) -> S1apResult<Vec<u8>> {
    let ue_paging_id = if mme_ue.current.m_tmsi.is_some() {
        UePagingId::STmsi(STmsi {
            mmec: mme_ue.current.guti.mme_code,
            m_tmsi: mme_ue.current.guti.m_tmsi,
        })
    } else {
        UePagingId::Imsi(imsi_bcd_to_tbcd(&mme_ue.imsi_bcd))
    };

    // Generated codec (#514 stage 7).
    crate::s1ap_gen::build_paging(&Paging {
        ue_identity_index: ue_identity_index_from_imsi(&mme_ue.imsi_bcd),
        ue_paging_id,
        paging_drx,
        cn_domain,
        tai_list: tai_list.iter().map(tai_to_s1ap).collect(),
    })
    .map_err(gen_err)
}

// ============================================================================
// Configuration Update (§8.7.4)
// ============================================================================

/// Build eNB Configuration Update Acknowledge (TS 36.413 §9.1.8.8)
pub fn build_enb_configuration_update_acknowledge() -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_enb_configuration_update_acknowledge(&[]).map_err(gen_err)
}

/// Build eNB Configuration Update Failure (TS 36.413 §9.1.8.9)
pub fn build_enb_configuration_update_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_enb_configuration_update_failure(
        cause_to_s1ap(cause_group, cause_value),
        time_to_wait,
        &[],
    )
    .map_err(gen_err)
}

// ============================================================================
// UE Context Modification (§8.3.4)
// ============================================================================

/// Build UE Context Modification Request carrying the CS Fallback Indicator
/// (TS 36.413 §9.1.4.8, TS 23.272 §7.3).
///
/// This is the MT CSFB trigger: it tells the eNB to move the UE to the CS
/// domain for an incoming circuit-switched call. Only the indicator is sent —
/// nothing else about the UE has changed, and an unnecessary `SecurityKey` here
/// would make the eNB rekey a UE mid-call.
pub fn build_ue_context_modification_for_csfb(
    enb_ue: &EnbUe,
    high_priority: bool,
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_ue_context_modification_request(&UeContextModificationRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        security_key: None,
        subscriber_profile_id_for_rfp: None,
        ue_ambr: None,
        cs_fallback_indicator: Some(if high_priority {
            CsFallbackIndicator::CsFallbackHighPriority
        } else {
            CsFallbackIndicator::CsFallbackRequired
        }),
        ue_security_capabilities: None,
    })
    .map_err(gen_err)
}

/// Build a UE CONTEXT MODIFICATION REQUEST carrying only a new UE-AMBR
/// (TS 36.413 §8.3.4, #811): the HSS-initiated subscribed QoS modification of
/// TS 23.401 §5.4.2.2, when only the UE-AMBR changes.
pub fn build_ue_context_modification_for_ue_ambr(
    enb_ue: &EnbUe,
    ue_ambr: UeAmbr,
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_ue_context_modification_request(&UeContextModificationRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        security_key: None,
        subscriber_profile_id_for_rfp: None,
        ue_ambr: Some(ue_ambr),
        cs_fallback_indicator: None,
        ue_security_capabilities: None,
    })
    .map_err(gen_err)
}

// ============================================================================
// Overload (§8.7.6)
// ============================================================================

/// Build Overload Start (TS 36.413 §9.1.8.13)
pub fn build_overload_start(action: OverloadAction) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_overload_start(action).map_err(gen_err)
}

/// Build Overload Stop (TS 36.413 §9.1.8.14)
pub fn build_overload_stop() -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_overload_stop().map_err(gen_err)
}

// ============================================================================
// PWS: Write-Replace Warning / Kill (§8.12)
// ============================================================================

/// Build a Write-Replace Warning Request for one eNB from the CBC's PWS data
/// (TS 36.413 §9.1.13.1, TS 23.041).
///
/// `warning_tais` is the subset of the CBC's warning area this eNB actually
/// serves. It may only be empty when the CBC named no area at all, which per
/// TS 23.041 means every cell the eNB serves.
pub fn build_write_replace_warning(
    sbc_pws: &SbcPwsData,
    warning_tais: &[EpsTai],
) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_write_replace_warning_request(&WriteReplaceWarningRequest {
        message_identifier: sbc_pws.message_id,
        serial_number: sbc_pws.serial_number,
        warning_area: warning_area_from(sbc_pws, warning_tais)?,
        // The SBc-AP fields are wider than the S1AP IEs they feed
        // (RepetitionPeriod is INTEGER(0..4095), NumberofBroadcastRequest is
        // INTEGER(0..65535)), so they are clamped rather than truncated: a
        // wrapped repetition period would silently change how long an
        // emergency alert is broadcast.
        repetition_period: sbc_pws.repetition_period.min(PWS_MAX_REPETITION_PERIOD) as u16,
        number_of_broadcast_request: sbc_pws.number_of_broadcast.min(u16::MAX as u32) as u16,
        warning_type: sbc_pws.warning_type.map(|wt| wt.encode()),
        warning_security_info: None,
        data_coding_scheme: Some(sbc_pws.data_coding_scheme),
        warning_message_contents: (!sbc_pws.message_contents.is_empty())
            .then(|| sbc_pws.message_contents.clone()),
        concurrent_warning_message_indicator: sbc_pws.concurrent_warning_message_indicator,
    })
    .map_err(gen_err)
}

/// Build a Kill Request for one eNB (TS 36.413 §9.1.13.3).
pub fn build_kill(sbc_pws: &SbcPwsData, warning_tais: &[EpsTai]) -> S1apResult<Vec<u8>> {
    crate::s1ap_gen::build_kill_request(&KillRequest {
        message_identifier: sbc_pws.message_id,
        serial_number: sbc_pws.serial_number,
        warning_area: warning_area_from(sbc_pws, warning_tais)?,
        // Only this (message id, serial number) is cancelled, never every
        // warning the eNB holds: a Stop Warning Request from the CBC names one
        // message, so killing them all would cancel unrelated live alerts.
        kill_all_warning_messages: false,
    })
    .map_err(gen_err)
}

/// `RepetitionPeriod ::= INTEGER (0..4095)` (TS 36.413 §9.2.1.49)
const PWS_MAX_REPETITION_PERIOD: u32 = 4095;

/// The Warning Area List for a set of TAIs.
///
/// `None` means "omit the IE", which per TS 23.041 tells the eNB to broadcast in
/// **every cell it serves**. That is only correct when the CBC itself named no
/// area, so an empty `warning_tais` for a request that *did* name TAIs is an
/// error rather than an omission: silently widening a targeted emergency alert to
/// an entire eNB is worse than not sending it. `TAIListforWarning` is
/// `SIZE(1..maxnoofTAIforWarning)` and cannot encode an empty list anyway.
fn warning_area_from(
    sbc_pws: &SbcPwsData,
    warning_tais: &[EpsTai],
) -> S1apResult<Option<WarningAreaList>> {
    if warning_tais.is_empty() {
        if sbc_pws.no_of_tai > 0 {
            return Err(nextgcore_s1ap::S1apError::InvalidIeValue {
                ie_name: "WarningAreaList",
                reason: format!(
                    "the CBC named {} TAI(s) but none of them match this eNB; refusing to \
                     broadcast to every cell instead",
                    sbc_pws.no_of_tai
                ),
            });
        }
        return Ok(None);
    }
    Ok(Some(WarningAreaList::TrackingAreaListForWarning(
        warning_tais.iter().map(tai_to_s1ap).collect(),
    )))
}

// ============================================================================
// Error Indication (§8.7.2)
// ============================================================================

/// Build Error Indication
pub fn build_error_indication(
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    cause_group: S1apCauseGroup,
    cause_value: i64,
    criticality_diagnostics: Option<nextgcore_s1ap::CriticalityDiagnostics>,
) -> S1apResult<Vec<u8>> {
    // Generated codec (#514 stage 9).
    crate::s1ap_gen::build_error_indication(&ErrorIndication {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause: Some(cause_to_s1ap(cause_group, cause_value)),
        criticality_diagnostics,
    })
    .map_err(gen_err)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Bitrate, ServedGummei, TmsiInfo};
    use crate::s1ap_gen::test_codec::decode_s1ap_pdu;
    use nextgcore_s1ap::S1apMessage;

    fn test_plmn() -> PlmnId {
        PlmnId::new("310", "410")
    }

    fn test_bearer() -> MmeBearer {
        MmeBearer {
            id: 1,
            ebi: 5,
            sgw_s1u_teid: 0x1234_5678,
            sgw_s1u_ip: IpAddr {
                ipv4: Some([10, 0, 0, 1]),
                ipv6: None,
            },
            qos: crate::context::Qos {
                qci: 9,
                arp: crate::context::Arp {
                    priority_level: 8,
                    pre_emption_capability: 1,
                    pre_emption_vulnerability: 0,
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_mme_ue() -> MmeUe {
        let mut mme_ue = MmeUe {
            id: 1,
            imsi_bcd: "001010123456789".to_string(),
            ambr: Bitrate {
                downlink: 1_000_000_000,
                uplink: 500_000_000,
            },
            kenb: [0xAB; 32],
            ..Default::default()
        };
        mme_ue.ue_network_capability.eea = 0x70; // 128-EEA1/2/3
        mme_ue.ue_network_capability.eia = 0x70; // 128-EIA1/2/3
        mme_ue
    }

    fn test_enb_ue() -> EnbUe {
        EnbUe {
            id: 1,
            enb_ue_s1ap_id: 7,
            mme_ue_s1ap_id: 42,
            ..Default::default()
        }
    }

    #[test]
    fn test_plmn_id_roundtrip() {
        let plmn = test_plmn();
        let encoded = encode_plmn_id(&plmn);
        let decoded = decode_plmn_id(&encoded);
        assert_eq!(plmn, decoded);
    }

    #[test]
    fn test_ue_identity_index_imsi_mod_1024() {
        // TS 36.304 §7.1: UE_ID = IMSI mod 1024 (IMSI as decimal integer)
        assert_eq!(
            ue_identity_index_from_imsi("001010123456789"),
            (1_010_123_456_789u64 % 1024) as u16
        );
        // 1010000000000 is an exact multiple of 1024
        assert_eq!(ue_identity_index_from_imsi("001010000000000"), 0);
        assert_eq!(
            ue_identity_index_from_imsi("001010000001234"),
            (1_010_000_001_234u64 % 1024) as u16
        );
        assert_eq!(ue_identity_index_from_imsi("0"), 0);
        // 15-digit max IMSI must not overflow
        assert_eq!(
            ue_identity_index_from_imsi("999999999999999"),
            (999_999_999_999_999u64 % 1024) as u16
        );
    }

    #[test]
    fn test_imsi_tbcd_encoding() {
        // Digit pairs are nibble-swapped; the odd 15th digit gets a 0xF filler
        assert_eq!(
            imsi_bcd_to_tbcd("001010123456789"),
            vec![0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9]
        );
    }

    #[test]
    fn test_build_setup_response_roundtrip() {
        let mut ctx = MmeContext::new();
        ctx.mme_name = Some("nextg-mme".to_string());
        ctx.relative_capacity = 100;
        ctx.served_gummei = vec![ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![test_plmn()],
            num_of_mme_gid: 1,
            mme_gid: vec![2],
            num_of_mme_code: 1,
            mme_code: vec![1],
        }];
        ctx.num_of_served_gummei = 1;

        let bytes = build_setup_response(&ctx).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::S1SetupResponse(rsp) => {
                assert_eq!(rsp.mme_name.as_deref(), Some("nextg-mme"));
                assert_eq!(rsp.relative_mme_capacity, 100);
                assert_eq!(rsp.served_gummeis.len(), 1);
                assert_eq!(
                    rsp.served_gummeis[0].served_plmns[0],
                    encode_plmn_id(&test_plmn())
                );
                assert_eq!(rsp.served_gummeis[0].served_group_ids, vec![2]);
                assert_eq!(rsp.served_gummeis[0].served_mmec_codes, vec![1]);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_setup_failure_roundtrip() {
        let bytes = build_setup_failure(
            S1apCauseGroup::Misc,
            misc_cause::UNKNOWN_PLMN,
            Some(TimeToWait::V10s),
        )
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::S1SetupFailure(failure) => {
                assert_eq!(failure.cause, Cause::Misc(CauseMisc::UnknownPlmn));
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V10s));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_downlink_nas_transport_roundtrip() {
        let nas_pdu = vec![0x07, 0x41, 0x00];
        let bytes = build_downlink_nas_transport_with_ids(7, 42, &nas_pdu).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::DownlinkNasTransport(dl) => {
                assert_eq!(dl.mme_ue_s1ap_id, 42);
                assert_eq!(dl.enb_ue_s1ap_id, 7);
                assert_eq!(dl.nas_pdu, nas_pdu);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// #811, TS 23.401 §4.7.3: min(subscribed, sum of APN-AMBRs), per
    /// direction, with the zero (unknown) fallbacks.
    #[test]
    fn the_ue_ambr_is_the_sum_of_apn_ambrs_up_to_the_subscribed_value() {
        let b = |downlink, uplink| crate::context::Bitrate { downlink, uplink };
        let sub = b(100, 60);
        assert_eq!(
            ue_ambr(&sub, [b(10, 5), b(20, 5)]),
            UeAmbr { dl: 30, ul: 10 }
        );
        assert_eq!(
            ue_ambr(&sub, [b(80, 50), b(40, 40)]),
            UeAmbr { dl: 100, ul: 60 }
        );
        assert_eq!(
            ue_ambr(&sub, []),
            UeAmbr { dl: 100, ul: 60 },
            "no APN-AMBR known"
        );
        assert_eq!(
            ue_ambr(&b(0, 0), [b(7, 3)]),
            UeAmbr { dl: 7, ul: 3 },
            "none subscribed"
        );
        assert_eq!(
            ue_ambr(&b(0, 0), []),
            UeAmbr {
                dl: UE_AMBR_UNKNOWN,
                ul: UE_AMBR_UNKNOWN
            },
            "nothing known: the maximum, never 0 bit/s"
        );
        assert_eq!(
            ue_ambr(&b(u64::MAX, u64::MAX), [b(u64::MAX, 1), b(1, 1)]),
            UeAmbr {
                dl: UE_AMBR_MAX,
                ul: 2
            },
            "no overflow, and clamped to the Extended Bit Rate range"
        );
        assert_eq!(
            ue_ambr(
                &b(20_000_000_000, 20_000_000_000),
                [b(15_000_000_000, 1_000)]
            ),
            UeAmbr {
                dl: 15_000_000_000,
                ul: 1_000
            },
            "above 10 Gbit/s is kept: it travels in the Extended UE-AMBR IEs"
        );
    }

    #[test]
    fn test_build_initial_context_setup_request_roundtrip() {
        let mme_ue = test_mme_ue();
        let enb_ue = test_enb_ue();
        let bearer = test_bearer();
        let nas_pdu = vec![0x27, 0x01, 0x02];

        let ambr = ue_ambr(&mme_ue.ambr, []);
        let bytes =
            build_initial_context_setup_request(&mme_ue, &enb_ue, &[bearer], Some(&nas_pdu), ambr)
                .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::InitialContextSetupRequest(req) => {
                assert_eq!(req.mme_ue_s1ap_id, 42);
                assert_eq!(req.enb_ue_s1ap_id, 7);
                // AMBR is carried in bit/s, not divided
                assert_eq!(req.ue_ambr.dl, 1_000_000_000);
                assert_eq!(req.ue_ambr.ul, 500_000_000);
                assert_eq!(req.erab_list.len(), 1);
                assert_eq!(req.erab_list[0].erab_id, 5);
                assert_eq!(req.erab_list[0].gtp_teid, 0x1234_5678);
                assert_eq!(req.erab_list[0].transport_layer_address, vec![10, 0, 0, 1]);
                assert_eq!(req.erab_list[0].erab_qos.qci, 9);
                // #1180: test_bearer has PCI 1 (GTP: disabled) and PVI 0 (enabled):
                // shall-not-trigger-pre-emption, pre-emptable (TS 36.413 §9.2.1.60).
                assert!(!req.erab_list[0].erab_qos.arp.pre_emption_capability);
                assert!(req.erab_list[0].erab_qos.arp.pre_emption_vulnerability);
                assert_eq!(
                    req.erab_list[0].nas_pdu.as_deref(),
                    Some(nas_pdu.as_slice())
                );
                // NAS EEA/EIA bitmap (EEA0 at MSB) shifted past EA0 for S1AP
                assert_eq!(req.ue_security_capabilities.encryption_algorithms, 0xE000);
                assert_eq!(req.ue_security_capabilities.integrity_algorithms, 0xE000);
                assert_eq!(req.security_key, [0xAB; 32]);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// #1180, TS 36.413 §9.2.1.60 / TS 29.274 §8.15: an E-RAB SETUP REQUEST's ARP
    /// on the wire. A bearer whose PGW said PCI 0 (may pre-empt), PVI 1 (not
    /// pre-emptable) is sent as may-trigger-pre-emption (1), not-pre-emptable
    /// (0), and the reverse.
    #[test]
    fn erab_arp_flags_follow_ts36413_coding() {
        use nextgcore_s1ap_gen::generated as g;
        let enb_ue = test_enb_ue();
        for (pci, pvi, cap, vul) in [(0u8, 1u8, 1u8, 0u8), (1, 0, 0, 1)] {
            let mut bearer = test_bearer();
            bearer.qos.arp.pre_emption_capability = pci;
            bearer.qos.arp.pre_emption_vulnerability = pvi;
            let bytes = build_e_rab_setup_request(&enb_ue, &bearer, &[0x27], None).unwrap();
            let pdu = nextgcore_s1ap_gen::decode(&bytes).unwrap();
            let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                value: g::InitiatingMessageValue::Id_E_RABSetup(req),
                ..
            }) = pdu
            else {
                panic!("not an E-RAB SETUP REQUEST");
            };
            let arp = req
                .protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    g::E_RABSetupRequestProtocolIEs_EntryValue::Id_E_RABToBeSetupListBearerSUReq(l) => {
                        l.0.first().map(|e| {
                            let g::E_RABToBeSetupListBearerSUReq_EntryValue::Id_E_RABToBeSetupItemBearerSUReq(i) = &e.value;
                            i.e_ra_blevel_qo_s_parameters.allocation_retention_priority.clone()
                        })
                    }
                    _ => None,
                })
                .expect("an E-RAB to be set up");
            assert_eq!(
                (
                    arp.pre_emption_capability.0,
                    arp.pre_emption_vulnerability.0
                ),
                (cap, vul),
                "GTP PCI {pci} PVI {pvi}"
            );
        }
    }

    #[test]
    fn test_build_ue_context_release_command_roundtrip() {
        let bytes =
            build_ue_context_release_command(Some(7), 42, S1apCauseGroup::Nas, nas_cause::DETACH)
                .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => {
                assert_eq!(
                    cmd.ue_s1ap_ids,
                    UeS1apIds::Pair {
                        mme_ue_s1ap_id: 42,
                        enb_ue_s1ap_id: 7
                    }
                );
                assert_eq!(cmd.cause, Cause::Nas(CauseNas::Detach));
            }
            other => panic!("unexpected message: {other:?}"),
        }

        // MME-only variant
        let bytes =
            build_ue_context_release_command(None, 42, S1apCauseGroup::Nas, nas_cause::DETACH)
                .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => {
                assert_eq!(cmd.ue_s1ap_ids, UeS1apIds::MmeOnly { mme_ue_s1ap_id: 42 });
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_e_rab_setup_request_roundtrip() {
        let enb_ue = test_enb_ue();
        let bearer = test_bearer();
        let nas_pdu = vec![0x27, 0xAA];
        let bytes = build_e_rab_setup_request(&enb_ue, &bearer, &nas_pdu, None).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::ErabSetupRequest(req) => {
                assert_eq!(req.mme_ue_s1ap_id, 42);
                assert_eq!(req.erab_list.len(), 1);
                assert_eq!(req.erab_list[0].erab_id, 5);
                assert_eq!(
                    req.erab_list[0].nas_pdu.as_deref(),
                    Some(nas_pdu.as_slice())
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_e_rab_modify_request_roundtrip() {
        let enb_ue = test_enb_ue();
        let bearer = test_bearer();
        let nas_pdu = vec![0x27, 0xBB];
        let bytes = build_e_rab_modify_request(&enb_ue, &bearer, &nas_pdu).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::ErabModifyRequest(req) => {
                assert_eq!(req.erab_list.len(), 1);
                assert_eq!(req.erab_list[0].erab_id, 5);
                assert_eq!(req.erab_list[0].nas_pdu, nas_pdu);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_e_rab_release_command_roundtrip() {
        let enb_ue = test_enb_ue();
        let nas_pdu = vec![0x27, 0xCC];
        let bytes = build_e_rab_release_command(
            &enb_ue,
            5,
            S1apCauseGroup::Nas,
            nas_cause::NORMAL_RELEASE,
            Some(&nas_pdu),
            None,
        )
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::ErabReleaseCommand(cmd) => {
                assert_eq!(cmd.erab_list.len(), 1);
                assert_eq!(cmd.erab_list[0].erab_id, 5);
                assert_eq!(cmd.erab_list[0].cause, Cause::Nas(CauseNas::NormalRelease));
                assert_eq!(cmd.nas_pdu.as_deref(), Some(nas_pdu.as_slice()));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_paging_stmsi_roundtrip() {
        let mut mme_ue = test_mme_ue();
        mme_ue.current = TmsiInfo {
            m_tmsi: Some(0xC0FF_EE01),
            ..Default::default()
        };
        mme_ue.current.guti.mme_code = 1;
        mme_ue.current.guti.m_tmsi = 0xC0FF_EE01;
        let tai = EpsTai {
            plmn_id: test_plmn(),
            tac: 0x0001,
        };

        let bytes = build_paging(&mme_ue, CnDomain::Ps, std::slice::from_ref(&tai), None).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::Paging(paging) => {
                assert_eq!(
                    paging.ue_identity_index,
                    ue_identity_index_from_imsi("001010123456789")
                );
                assert_eq!(
                    paging.ue_paging_id,
                    UePagingId::STmsi(STmsi {
                        mmec: 1,
                        m_tmsi: 0xC0FF_EE01
                    })
                );
                assert_eq!(paging.cn_domain, CnDomain::Ps);
                assert_eq!(paging.tai_list.len(), 1);
                assert_eq!(tai_from_s1ap(&paging.tai_list[0]), tai);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_paging_imsi_identity() {
        // No TMSI allocated -> page with IMSI
        let mme_ue = test_mme_ue();
        let tai = EpsTai {
            plmn_id: test_plmn(),
            tac: 1,
        };
        let bytes = build_paging(&mme_ue, CnDomain::Ps, &[tai], None).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::Paging(paging) => {
                assert_eq!(
                    paging.ue_paging_id,
                    UePagingId::Imsi(imsi_bcd_to_tbcd("001010123456789"))
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// The MT CSFB trigger (TS 23.272 §7.3): a UE Context Modification carrying
    /// only the CS Fallback Indicator. Anything else in it would ask the eNB to
    /// change something about the UE that has not actually changed — a
    /// `SecurityKey` here would rekey a UE mid-call.
    #[test]
    fn test_build_ue_context_modification_for_csfb_roundtrip() {
        let enb_ue = test_enb_ue();

        let bytes = build_ue_context_modification_for_csfb(&enb_ue, false).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextModificationRequest(req) => {
                assert_eq!(req.mme_ue_s1ap_id, 42);
                assert_eq!(req.enb_ue_s1ap_id, 7);
                assert_eq!(
                    req.cs_fallback_indicator,
                    Some(nextgcore_s1ap::CsFallbackIndicator::CsFallbackRequired)
                );
                assert!(req.security_key.is_none(), "the UE must not be rekeyed");
                assert!(req.ue_ambr.is_none());
                assert!(req.ue_security_capabilities.is_none());
                assert!(req.subscriber_profile_id_for_rfp.is_none());
            }
            other => panic!("unexpected message: {other:?}"),
        }

        // An emergency CS fallback asks for priority handling instead.
        let bytes = build_ue_context_modification_for_csfb(&enb_ue, true).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextModificationRequest(req) => {
                assert_eq!(
                    req.cs_fallback_indicator,
                    Some(nextgcore_s1ap::CsFallbackIndicator::CsFallbackHighPriority)
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_overload_start_and_stop_roundtrip() {
        let bytes = build_overload_start(OverloadAction::RejectDelayTolerantAccess).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::OverloadStart(start) => {
                assert_eq!(
                    start.overload_action,
                    OverloadAction::RejectDelayTolerantAccess
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }

        let bytes = build_overload_stop().unwrap();
        assert!(matches!(
            decode_s1ap_pdu(&bytes).unwrap(),
            S1apMessage::OverloadStop(_)
        ));
    }

    #[test]
    fn test_build_enb_configuration_update_ack_and_failure_roundtrip() {
        let bytes = build_enb_configuration_update_acknowledge().unwrap();
        assert!(matches!(
            decode_s1ap_pdu(&bytes).unwrap(),
            S1apMessage::EnbConfigurationUpdateAcknowledge(_)
        ));

        let bytes = build_enb_configuration_update_failure(
            S1apCauseGroup::Misc,
            misc_cause::UNKNOWN_PLMN,
            Some(TimeToWait::V10s),
        )
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::EnbConfigurationUpdateFailure(failure) => {
                assert_eq!(failure.cause, Cause::Misc(CauseMisc::UnknownPlmn));
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V10s));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_build_error_indication_roundtrip() {
        let bytes = build_error_indication(
            Some(7),
            Some(42),
            S1apCauseGroup::Protocol,
            protocol_cause::SEMANTIC_ERROR,
            None,
        )
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::ErrorIndication(ind) => {
                assert_eq!(ind.mme_ue_s1ap_id, Some(42));
                assert_eq!(ind.enb_ue_s1ap_id, Some(7));
                assert_eq!(
                    ind.cause,
                    Some(Cause::Protocol(CauseProtocol::SemanticError))
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_cause_mapping_roundtrip() {
        let cause = cause_to_s1ap(
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::X2_HANDOVER_TRIGGERED,
        );
        assert_eq!(
            cause,
            Cause::RadioNetwork(CauseRadioNetwork::X2HandoverTriggered)
        );
        let back = cause_from_s1ap(&cause);
        assert_eq!(back.group, S1apCauseGroup::RadioNetwork);
        assert_eq!(back.cause, radio_network_cause::X2_HANDOVER_TRIGGERED);

        // Out-of-range values fall back to the group's unspecified value
        let cause = cause_to_s1ap(S1apCauseGroup::RadioNetwork, 9999);
        assert_eq!(cause, Cause::RadioNetwork(CauseRadioNetwork::Unspecified));
    }

    #[test]
    fn test_strict_decode_rejects_garbage() {
        assert!(decode_s1ap_pdu(&[]).is_err());
        assert!(decode_s1ap_pdu(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn test_strict_decode_rejects_missing_mandatory_ie() {
        // Hand-craft a Downlink NAS Transport whose container only carries
        // the UE S1AP IDs (no NAS-PDU): a strict peer must reject it.
        use g::DownlinkNASTransportProtocolIEs_EntryValue as V;
        use nextgcore_s1ap_gen::generated as g;
        let pdu = g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            procedure_code: g::ProcedureCode(11),
            criticality: g::Criticality(g::Criticality::IGNORE),
            value: g::InitiatingMessageValue::Id_downlinkNASTransport(g::DownlinkNASTransport {
                protocol_i_es: g::DownlinkNASTransportProtocolIEs(vec![
                    g::DownlinkNASTransportProtocolIEs_Entry {
                        id: g::ProtocolIE_ID(0),
                        criticality: g::Criticality(g::Criticality::REJECT),
                        value: V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(42)),
                    },
                    g::DownlinkNASTransportProtocolIEs_Entry {
                        id: g::ProtocolIE_ID(8),
                        criticality: g::Criticality(g::Criticality::REJECT),
                        value: V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(7)),
                    },
                ]),
            }),
        });
        let bytes = nextgcore_s1ap_gen::encode(&pdu).unwrap();

        match decode_s1ap_pdu(&bytes) {
            Err(nextgcore_s1ap::S1apError::MissingMandatoryIe(name)) => {
                assert_eq!(name, "NAS-PDU")
            }
            other => panic!("expected MissingMandatoryIe(NAS-PDU), got {other:?}"),
        }
    }
}
