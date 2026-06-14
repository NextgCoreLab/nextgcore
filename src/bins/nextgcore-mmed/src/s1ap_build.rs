//! S1AP Message Building
//!
//! Port of src/mme/s1ap-build.c - S1AP message building functions.
//!
//! All messages are APER-encoded via the `ogs-s1ap` codec per 3GPP TS 36.413.
//! This module converts MME context types into `ogs-s1ap` message structures
//! and returns the encoded wire bytes. There is no bespoke byte layout here:
//! every builder goes through `ogs_s1ap::builder`.

use crate::context::{
    ECgi, EnbUe, EpsTai, IpAddr, MmeBearer, MmeContext, MmeUe, PlmnId, S1apCause, S1apCauseGroup,
};
use ogs_s1ap::{
    builder, AllocationRetentionPriority, Cause, CauseMisc, CauseNas, CauseProtocol,
    CauseRadioNetwork, CauseTransport, CnDomain, DlNasTransport, ErabItem, ErabLevelQosParameters,
    ErabModifyRequest, ErabReleaseCommand, ErabSetupRequest, ErabToBeModifiedItem,
    ErabToBeSetupItem, ErrorIndication, EutranCgi, GbrQosInformation, InitialContextSetupRequest,
    Paging, PagingDrx, S1SetupFailure, S1SetupResponse, S1apResult, STmsi, ServedGummeiItem, Tai,
    TimeToWait, UeAmbr, UeContextReleaseCommand, UePagingId, UeS1apIds, UeSecurityCapabilities,
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
// Context Type <-> ogs-s1ap Type Conversions
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

/// Convert context TAI into the ogs-s1ap TAI
pub fn tai_to_s1ap(tai: &EpsTai) -> Tai {
    Tai {
        plmn_identity: encode_plmn_id(&tai.plmn_id),
        tac: tai.tac,
    }
}

/// Convert ogs-s1ap TAI into the context TAI
pub fn tai_from_s1ap(tai: &Tai) -> EpsTai {
    EpsTai {
        plmn_id: decode_plmn_id(&tai.plmn_identity),
        tac: tai.tac,
    }
}

/// Convert context E-CGI into the ogs-s1ap EUTRAN-CGI
pub fn ecgi_to_s1ap(ecgi: &ECgi) -> EutranCgi {
    EutranCgi {
        plmn_identity: encode_plmn_id(&ecgi.plmn_id),
        cell_identity: ecgi.cell_id & 0x0fff_ffff,
    }
}

/// Convert ogs-s1ap EUTRAN-CGI into the context E-CGI
pub fn ecgi_from_s1ap(cgi: &EutranCgi) -> ECgi {
    ECgi {
        plmn_id: decode_plmn_id(&cgi.plmn_identity),
        cell_id: cgi.cell_identity & 0x0fff_ffff,
    }
}

/// Convert a (group, value) cause pair into the ogs-s1ap Cause CHOICE.
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

/// Convert an ogs-s1ap Cause CHOICE into the context (group, value) pair
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
            pre_emption_capability: bearer.qos.arp.pre_emption_capability != 0,
            pre_emption_vulnerability: bearer.qos.arp.pre_emption_vulnerability != 0,
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

/// Build S1 Setup Response from the MME context configuration
pub fn build_setup_response(ctx: &MmeContext) -> S1apResult<Vec<u8>> {
    let served_gummeis = ctx
        .served_gummei
        .iter()
        .map(|gummei| ServedGummeiItem {
            served_plmns: gummei.plmn_id.iter().map(encode_plmn_id).collect(),
            served_group_ids: gummei.mme_gid.clone(),
            served_mmec_codes: gummei.mme_code.clone(),
        })
        .collect();

    builder::build_s1_setup_response(&S1SetupResponse {
        mme_name: ctx.mme_name.clone(),
        served_gummeis,
        relative_mme_capacity: ctx.relative_capacity,
    })
}

/// Build S1 Setup Failure
pub fn build_setup_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> S1apResult<Vec<u8>> {
    builder::build_s1_setup_failure(&S1SetupFailure {
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
    builder::build_downlink_nas_transport(&DlNasTransport {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        nas_pdu: nas_pdu.to_vec(),
    })
}

// ============================================================================
// Initial Context Setup (§8.3.1)
// ============================================================================

/// Build Initial Context Setup Request.
///
/// The E-RAB To Be Setup list is populated from the UE's bearer contexts
/// (SGW S1-U downlink endpoints); the NAS PDU rides on the first E-RAB.
pub fn build_initial_context_setup_request(
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    bearers: &[MmeBearer],
    nas_pdu: Option<&[u8]>,
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

    builder::build_initial_context_setup_request(&InitialContextSetupRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: UeAmbr {
            dl: mme_ue.ambr.downlink,
            ul: mme_ue.ambr.uplink,
        },
        erab_list,
        ue_security_capabilities: ue_security_capabilities_from(mme_ue),
        security_key: mme_ue.kenb,
    })
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

    builder::build_ue_context_release_command(&UeContextReleaseCommand {
        ue_s1ap_ids,
        cause: cause_to_s1ap(cause_group, cause_value),
    })
}

// ============================================================================
// E-RAB Management (§8.2)
// ============================================================================

/// Build E-RAB Setup Request for a bearer (NAS PDU is mandatory per item)
pub fn build_e_rab_setup_request(
    enb_ue: &EnbUe,
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> S1apResult<Vec<u8>> {
    builder::build_erab_setup_request(&ErabSetupRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: None,
        erab_list: vec![ErabToBeSetupItem {
            erab_id: bearer.ebi,
            erab_qos: erab_qos_from_bearer(bearer),
            transport_layer_address: ip_to_transport_address(&bearer.sgw_s1u_ip),
            gtp_teid: bearer.sgw_s1u_teid,
            nas_pdu: Some(nas_pdu.to_vec()),
        }],
    })
}

/// Build E-RAB Modify Request for a bearer
pub fn build_e_rab_modify_request(
    enb_ue: &EnbUe,
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> S1apResult<Vec<u8>> {
    builder::build_erab_modify_request(&ErabModifyRequest {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: None,
        erab_list: vec![ErabToBeModifiedItem {
            erab_id: bearer.ebi,
            erab_qos: erab_qos_from_bearer(bearer),
            nas_pdu: nas_pdu.to_vec(),
        }],
    })
}

/// Build E-RAB Release Command for a bearer
pub fn build_e_rab_release_command(
    enb_ue: &EnbUe,
    ebi: u8,
    cause_group: S1apCauseGroup,
    cause_value: i64,
    nas_pdu: Option<&[u8]>,
) -> S1apResult<Vec<u8>> {
    builder::build_erab_release_command(&ErabReleaseCommand {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: None,
        erab_list: vec![ErabItem {
            erab_id: ebi,
            cause: cause_to_s1ap(cause_group, cause_value),
        }],
        nas_pdu: nas_pdu.map(|pdu| pdu.to_vec()),
    })
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

    builder::build_paging(&Paging {
        ue_identity_index: ue_identity_index_from_imsi(&mme_ue.imsi_bcd),
        ue_paging_id,
        paging_drx,
        cn_domain,
        tai_list: tai_list.iter().map(tai_to_s1ap).collect(),
    })
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
) -> S1apResult<Vec<u8>> {
    builder::build_error_indication(&ErrorIndication {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause: Some(cause_to_s1ap(cause_group, cause_value)),
    })
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Bitrate, ServedGummei, TmsiInfo};
    use ogs_s1ap::{decode_s1ap_pdu, S1apMessage};

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

    #[test]
    fn test_build_initial_context_setup_request_roundtrip() {
        let mme_ue = test_mme_ue();
        let enb_ue = test_enb_ue();
        let bearer = test_bearer();
        let nas_pdu = vec![0x27, 0x01, 0x02];

        let bytes =
            build_initial_context_setup_request(&mme_ue, &enb_ue, &[bearer], Some(&nas_pdu))
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
                assert!(req.erab_list[0].erab_qos.arp.pre_emption_capability);
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
        let bytes = build_e_rab_setup_request(&enb_ue, &bearer, &nas_pdu).unwrap();
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

    #[test]
    fn test_build_error_indication_roundtrip() {
        let bytes = build_error_indication(
            Some(7),
            Some(42),
            S1apCauseGroup::Protocol,
            protocol_cause::SEMANTIC_ERROR,
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
        use ogs_asn1c::per::{AperEncode, AperEncoder};
        use ogs_asn1c::s1ap::ies::ProtocolIeContainer;
        use ogs_asn1c::s1ap::pdu::{InitiatingMessage, InitiatingMessageValue, S1apPdu};
        use ogs_asn1c::s1ap::types::{Criticality, ProcedureCode};

        let mut container = ProtocolIeContainer::new();
        ogs_s1ap::ie::encode_mme_ue_s1ap_id(&mut container, 42, Criticality::Reject).unwrap();
        ogs_s1ap::ie::encode_enb_ue_s1ap_id(&mut container, 7, Criticality::Reject).unwrap();

        let pdu = S1apPdu::InitiatingMessage(InitiatingMessage {
            procedure_code: ProcedureCode::DOWNLINK_NAS_TRANSPORT,
            criticality: Criticality::Ignore,
            value: InitiatingMessageValue::DownlinkNasTransport(container),
        });
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes().to_vec();

        match decode_s1ap_pdu(&bytes) {
            Err(ogs_s1ap::S1apError::MissingMandatoryIe(name)) => assert_eq!(name, "NAS-PDU"),
            other => panic!("expected MissingMandatoryIe(NAS-PDU), got {other:?}"),
        }
    }
}
