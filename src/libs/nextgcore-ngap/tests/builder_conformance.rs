//! Hand-written builder conformance against TS 38.413's own object sets.
//!
//! #417: moved here from `nextgcore-ngap-gen` -- its subject is this crate's
//! builders, so it lives (and is deleted) with them.
//!
//! For each hand-written `nextgcore-ngap` builder this checks two things the
//! codecs cannot vouch for themselves:
//!
//! 1. every IE's (id, criticality) is the pair the message's object set in
//!    `asn/ngap-17.9.asn` declares. The table is parsed from the schema text at
//!    test time, so it shares nothing with either encoder;
//! 2. the generated codec decodes the PDU and re-encodes it byte for byte. Its
//!    decode refuses an IE id outside the message's object set, so a wrong IE id
//!    fails here even when its criticality happens to match.
//!
//! Every message is built with its optional IEs present, so each IE the
//! builder can emit is checked.

use std::collections::HashMap;

use nextgcore_asn1c::ngap::cause::{Cause, CauseMisc, CauseRadioNetwork};
use nextgcore_asn1c::ngap::pdu::NgapPdu;
use nextgcore_asn1c::ngap::types::Criticality;
use nextgcore_asn1c::per::{AperDecode, AperDecoder};
use nextgcore_ngap::builder;
use nextgcore_ngap::ie::MulticastGroupPagingArea;
use nextgcore_ngap::mbs_transfer::MbsSessionId;
use nextgcore_ngap::types::*;

use nextgcore_ngap_gen::{decode, encode};

const SCHEMA: &str = include_str!("../../nextgcore-ngap-gen/asn/ngap-17.9.asn");

/// `id-Foo ProtocolIE-ID ::= n` for every IE id in the schema.
fn schema_ids() -> HashMap<String, u16> {
    SCHEMA
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.trim().split_once(char::is_whitespace)?;
            let n = rest.trim().strip_prefix("ProtocolIE-ID ::=")?.trim();
            Some((name.to_string(), n.parse().ok()?))
        })
        .collect()
}

/// The `{ ID id-x CRITICALITY c ... }` entries of `set_name NGAP-PROTOCOL-IES`.
fn object_set(set_name: &str) -> HashMap<u16, Criticality> {
    let ids = schema_ids();
    let header = format!("{set_name} NGAP-PROTOCOL-IES ::= {{");
    let start = SCHEMA
        .find(&header)
        .unwrap_or_else(|| panic!("object set {set_name} not in the schema"));
    let body = &SCHEMA[start + header.len()..];
    let body = &body[..body.find("\n}").expect("object set closes")];
    body.split("{ ID")
        .skip(1)
        .map(|entry| {
            let mut words = entry.split_whitespace();
            let id_name = words.next().expect("IE id name");
            assert_eq!(words.next(), Some("CRITICALITY"), "{set_name}: {id_name}");
            let crit = match words.next() {
                Some("reject") => Criticality::Reject,
                Some("ignore") => Criticality::Ignore,
                Some("notify") => Criticality::Notify,
                other => panic!("{set_name}: {id_name}: criticality {other:?}"),
            };
            (ids[id_name], crit)
        })
        .collect()
}

/// Assert every IE in `bytes` matches `set_name`, that the IEs in `expect_ids`
/// are all present (so the optional ones under test were really emitted), and
/// that the generated codec decodes and re-encodes the PDU byte for byte.
fn check(builder_name: &str, set_name: &str, bytes: &[u8], expect_ids: &[u16]) {
    let set = object_set(set_name);
    let pdu = NgapPdu::decode_aper(&mut AperDecoder::new(bytes))
        .unwrap_or_else(|e| panic!("{builder_name}: hand-written decode: {e:?}"));
    let ies = &pdu.protocol_ies().ies;
    for field in ies {
        let want = set
            .get(&field.id.0)
            .unwrap_or_else(|| panic!("{builder_name}: IE id {} is not in {set_name}", field.id.0));
        assert_eq!(
            &field.criticality, want,
            "{builder_name}: IE id {} criticality (TS 38.413 {set_name})",
            field.id.0
        );
    }
    for id in expect_ids {
        assert!(
            ies.iter().any(|f| f.id.0 == *id),
            "{builder_name}: IE id {id} was not emitted"
        );
    }
    let generated = decode(bytes)
        .unwrap_or_else(|e| panic!("{builder_name}: generated codec rejected it: {e:?}"));
    assert_eq!(
        encode(&generated).expect("re-encode"),
        bytes,
        "{builder_name}: generated re-encoding must be byte-identical"
    );
}

fn plmn() -> [u8; 3] {
    [0x00, 0xF1, 0x10]
}
fn tac() -> [u8; 3] {
    [0x00, 0x00, 0x01]
}
fn uli() -> UserLocationInformation {
    UserLocationInformation::Nr {
        nr_cgi_plmn: plmn(),
        nr_cell_identity: 0x0_0000_0010,
        tai_plmn: plmn(),
        tai_tac: tac(),
    }
}
fn caps() -> UeSecurityCapabilities {
    UeSecurityCapabilities {
        nr_encryption_algorithms: 0xE000,
        nr_integrity_algorithms: 0xE000,
        eutra_encryption_algorithms: 0xE000,
        eutra_integrity_algorithms: 0xE000,
    }
}
fn guami() -> Guami {
    Guami {
        plmn_identity: plmn(),
        amf_region_id: 0x02,
        amf_set_id: 0x001,
        amf_pointer: 0x01,
    }
}
fn nssai() -> Vec<SNssai> {
    vec![SNssai {
        sst: 1,
        sd: Some([0x00, 0x00, 0x01]),
    }]
}
fn cause() -> Cause {
    Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
}
/// A transfer value. The generated codec decodes each transfer OCTET STRING as
/// its CONTAINING type only where it is asked to, so opaque octets suffice.
fn transfer() -> Vec<u8> {
    vec![0x00]
}

// IE ids, from the schema (asserted against `schema_ids()` by `ids_are_the_schemas`).
const ID_NAS_PDU: u16 = 38;
const ID_USER_LOCATION_INFORMATION: u16 = 121;
const ID_NAS_SECURITY_PARAMETERS_FROM_NGRAN: u16 = 39;
const ID_TO_RELEASE_LIST_HO_CMD: u16 = 78;
const ID_TRAFFIC_LOAD_REDUCTION: u16 = 9;
const ID_UE_RADIO_CAPABILITY_FOR_PAGING: u16 = 118;
const ID_PAGING_ORIGIN: u16 = 51;
const ID_ASSISTANCE_DATA_FOR_PAGING: u16 = 11;
const ID_GUAMI: u16 = 28;

#[test]
fn ids_are_the_schemas() {
    let ids = schema_ids();
    for (name, id) in [
        ("id-NAS-PDU", ID_NAS_PDU),
        ("id-UserLocationInformation", ID_USER_LOCATION_INFORMATION),
        (
            "id-NASSecurityParametersFromNGRAN",
            ID_NAS_SECURITY_PARAMETERS_FROM_NGRAN,
        ),
        (
            "id-PDUSessionResourceToReleaseListHOCmd",
            ID_TO_RELEASE_LIST_HO_CMD,
        ),
        (
            "id-AMFTrafficLoadReductionIndication",
            ID_TRAFFIC_LOAD_REDUCTION,
        ),
        (
            "id-UERadioCapabilityForPaging",
            ID_UE_RADIO_CAPABILITY_FOR_PAGING,
        ),
        ("id-PagingOrigin", ID_PAGING_ORIGIN),
        ("id-AssistanceDataForPaging", ID_ASSISTANCE_DATA_FOR_PAGING),
        ("id-GUAMI", ID_GUAMI),
    ] {
        assert_eq!(ids[name], id, "{name}");
    }
}

#[test]
fn initial_ue_message() {
    let bytes = builder::build_initial_ue_message(&InitialUeMessage {
        ran_ue_ngap_id: 1,
        nas_pdu: vec![0x7e, 0x00, 0x41],
        user_location_info: uli(),
        rrc_establishment_cause: RrcEstablishmentCause::MoSignalling,
        ue_context_request: Some(true),
        allowed_nssai: nssai(),
    })
    .unwrap();
    check(
        "initial_ue_message",
        "InitialUEMessage-IEs",
        &bytes,
        &[ID_USER_LOCATION_INFORMATION],
    );
}

#[test]
fn initial_context_setup_request_response_failure() {
    let req = builder::build_initial_context_setup_request(&InitialContextSetupRequest {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        guami: guami(),
        allowed_nssai: nssai(),
        ue_security_capabilities: caps(),
        security_key: [0x11; 32],
        nas_pdu: Some(vec![0x7e, 0x02]),
        ue_ambr: Some(UeAmbrInfo {
            dl: 1_000_000,
            ul: 1_000_000,
        }),
    })
    .unwrap();
    check(
        "initial_context_setup_request",
        "InitialContextSetupRequestIEs",
        &req,
        &[ID_NAS_PDU, ID_GUAMI],
    );
    let rsp = builder::build_initial_context_setup_response(&InitialContextSetupResponse {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
    })
    .unwrap();
    check(
        "initial_context_setup_response",
        "InitialContextSetupResponseIEs",
        &rsp,
        &[],
    );
    let fail = builder::build_initial_context_setup_failure(&InitialContextSetupFailure {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        cause: cause(),
    })
    .unwrap();
    check(
        "initial_context_setup_failure",
        "InitialContextSetupFailureIEs",
        &fail,
        &[],
    );
}

#[test]
fn pdu_session_resource_responses_and_release_command() {
    let failed = vec![PduSessionResourceFailedItem {
        pdu_session_id: 6,
        transfer: transfer(),
    }];
    let setup =
        builder::build_pdu_session_resource_setup_response(&PduSessionResourceSetupResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            setup_list: vec![PduSessionResourceSetupResponseItem {
                pdu_session_id: 5,
                transfer: transfer(),
            }],
            failed_list: failed.clone(),
        })
        .unwrap();
    check(
        "pdu_session_resource_setup_response",
        "PDUSessionResourceSetupResponseIEs",
        &setup,
        &[],
    );
    let modify =
        builder::build_pdu_session_resource_modify_response(&PduSessionResourceModifyResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            modify_list: vec![PduSessionResourceModifyResponseItem {
                pdu_session_id: 5,
                transfer: transfer(),
            }],
            failed_list: failed.clone(),
        })
        .unwrap();
    check(
        "pdu_session_resource_modify_response",
        "PDUSessionResourceModifyResponseIEs",
        &modify,
        &[],
    );
    let confirm =
        builder::build_pdu_session_resource_modify_confirm(&PduSessionResourceModifyConfirm {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            confirm_list: vec![PduSessionResourceModifyConfirmItem {
                pdu_session_id: 5,
                transfer: transfer(),
            }],
            failed_list: failed,
        })
        .unwrap();
    check(
        "pdu_session_resource_modify_confirm",
        "PDUSessionResourceModifyConfirmIEs",
        &confirm,
        &[],
    );
    let command =
        builder::build_pdu_session_resource_release_command(&PduSessionResourceReleaseCommand {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            nas_pdu: Some(vec![0x7e, 0x02]),
            pdu_session_list: vec![PduSessionResourceReleaseItem {
                pdu_session_id: 5,
                transfer: transfer(),
            }],
        })
        .unwrap();
    check(
        "pdu_session_resource_release_command",
        "PDUSessionResourceReleaseCommandIEs",
        &command,
        &[ID_NAS_PDU],
    );
    let released =
        builder::build_pdu_session_resource_release_response(&PduSessionResourceReleaseResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            released_list: vec![PduSessionResourceReleasedItem {
                pdu_session_id: 5,
                transfer: transfer(),
            }],
        })
        .unwrap();
    check(
        "pdu_session_resource_release_response",
        "PDUSessionResourceReleaseResponseIEs",
        &released,
        &[],
    );
}

#[test]
fn ue_context_release_complete_and_error_indication() {
    let complete = builder::build_ue_context_release_complete(&UeContextReleaseComplete {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
    })
    .unwrap();
    check(
        "ue_context_release_complete",
        "UEContextReleaseComplete-IEs",
        &complete,
        &[],
    );
    let err = builder::build_error_indication(&ErrorIndication {
        amf_ue_ngap_id: Some(1),
        ran_ue_ngap_id: Some(2),
        cause: Some(Cause::Misc(CauseMisc::Unspecified)),
        criticality_diagnostics: None,
    })
    .unwrap();
    check("error_indication", "ErrorIndicationIEs", &err, &[]);
}

#[test]
fn handover_family() {
    let ack = builder::build_handover_request_acknowledge(&HandoverRequestAcknowledge {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        admitted_list: vec![PduSessionResourceAdmittedItemHoAck {
            pdu_session_id: 5,
            transfer: transfer(),
        }],
        failed_list: Some(vec![PduSessionResourceFailedItem {
            pdu_session_id: 6,
            transfer: transfer(),
        }]),
        target_to_source_container: vec![0x01, 0x02],
    })
    .unwrap();
    check(
        "handover_request_acknowledge",
        "HandoverRequestAcknowledgeIEs",
        &ack,
        &[],
    );
    let failure = builder::build_handover_failure(&HandoverFailure {
        amf_ue_ngap_id: 1,
        cause: cause(),
        criticality_diagnostics: None,
    })
    .unwrap();
    check("handover_failure", "HandoverFailureIEs", &failure, &[]);
    let command = builder::build_handover_command(&HandoverCommand {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        handover_type: HandoverType::Intra5gs,
        nas_security_parameters_from_ngran: Some(vec![0x00, 0x01]),
        pdu_session_list: vec![PduSessionResourceHandoverItem {
            pdu_session_id: 5,
            transfer: transfer(),
        }],
        release_list: Some(vec![PduSessionResourceReleaseItem {
            pdu_session_id: 6,
            transfer: transfer(),
        }]),
        target_to_source_container: vec![0x01, 0x02],
    })
    .unwrap();
    check(
        "handover_command",
        "HandoverCommandIEs",
        &command,
        &[
            ID_NAS_SECURITY_PARAMETERS_FROM_NGRAN,
            ID_TO_RELEASE_LIST_HO_CMD,
        ],
    );
    let cancel_ack = builder::build_handover_cancel_acknowledge(&HandoverCancelAcknowledge {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        criticality_diagnostics: None,
    })
    .unwrap();
    check(
        "handover_cancel_acknowledge",
        "HandoverCancelAcknowledgeIEs",
        &cancel_ack,
        &[],
    );
    let prep_fail = builder::build_handover_preparation_failure(&HandoverPreparationFailure {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        cause: cause(),
        criticality_diagnostics: None,
    })
    .unwrap();
    check(
        "handover_preparation_failure",
        "HandoverPreparationFailureIEs",
        &prep_fail,
        &[],
    );
}

#[test]
fn overload_start() {
    let bytes = builder::build_overload_start(&OverloadStart {
        traffic_load_reduction: Some(50),
    })
    .unwrap();
    check(
        "overload_start",
        "OverloadStartIEs",
        &bytes,
        &[ID_TRAFFIC_LOAD_REDUCTION],
    );
}

#[test]
fn paging() {
    let bytes = builder::build_paging(&Paging {
        ue_paging_identity: UePagingIdentity::FiveGSTmsi {
            amf_set_id: 0x001,
            amf_pointer: 0x01,
            tmsi: 0x1234_5678,
        },
        paging_drx: Some(PagingDrx::V128),
        tai_list: vec![TaiListItem {
            tai_plmn: plmn(),
            tai_tac: tac(),
        }],
        paging_priority: Some(PagingPriority::Priolevel1),
        // UERadioCapabilityForPaging { uERadioCapabilityForPagingOfNR '0102'H }:
        // extension bit 0, presence bits 1 0 0, pad -> 0x40; length 2; contents.
        ue_radio_capability: Some(vec![0x40, 0x02, 0x01, 0x02]),
        paging_origin: Some(PagingOrigin::Non3gpp),
        // AssistanceDataForPaging {}: extension bit 0, three absent optionals.
        assistance_data: Some(vec![0x00]),
    })
    .unwrap();
    check(
        "paging",
        "PagingIEs",
        &bytes,
        &[
            ID_UE_RADIO_CAPABILITY_FOR_PAGING,
            ID_PAGING_ORIGIN,
            ID_ASSISTANCE_DATA_FOR_PAGING,
        ],
    );
}

#[test]
fn ran_configuration_update_and_nas_non_delivery() {
    let update = builder::build_ran_configuration_update(&RanConfigurationUpdate {
        ran_node_name: Some("gnb".to_string()),
        supported_ta_list: None,
        default_paging_drx: Some(PagingDrx::V128),
        global_ran_node_id: Some(GlobalRanNodeId::GlobalGnbId {
            plmn_identity: plmn(),
            gnb_id: 1,
            gnb_id_len: 22,
        }),
    })
    .unwrap();
    check(
        "ran_configuration_update",
        "RANConfigurationUpdateIEs",
        &update,
        &[],
    );
    let nas = builder::build_nas_non_delivery_indication(&NasNonDeliveryIndication {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        nas_pdu: vec![0x7e, 0x00],
        cause: cause(),
    })
    .unwrap();
    check(
        "nas_non_delivery_indication",
        "NASNonDeliveryIndication-IEs",
        &nas,
        &[ID_NAS_PDU],
    );
}

#[test]
fn path_switch_family() {
    let req = builder::build_path_switch_request(&PathSwitchRequest {
        ran_ue_ngap_id: 2,
        source_amf_ue_ngap_id: 1,
        user_location_info: uli(),
        ue_security_capabilities: caps(),
        pdu_session_list: vec![PduSessionResourceSwitchItem {
            pdu_session_id: 5,
            transfer: transfer(),
        }],
        failed_list: Some(vec![PduSessionResourceFailedItem {
            pdu_session_id: 6,
            transfer: transfer(),
        }]),
    })
    .unwrap();
    check("path_switch_request", "PathSwitchRequestIEs", &req, &[]);
    let ack = builder::build_path_switch_request_acknowledge(&PathSwitchRequestAcknowledge {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        ue_security_capabilities: Some(caps()),
        security_context: SecurityContext {
            next_hop_chaining_count: 1,
            next_hop: [0x22; 32],
        },
        switched_list: vec![PduSessionResourceSwitchedItem {
            pdu_session_id: 5,
            transfer: transfer(),
        }],
        released_list: Some(vec![PduSessionResourceReleasedItem {
            pdu_session_id: 6,
            transfer: transfer(),
        }]),
        allowed_nssai: nssai(),
    })
    .unwrap();
    check(
        "path_switch_request_acknowledge",
        "PathSwitchRequestAcknowledgeIEs",
        &ack,
        &[],
    );
    let fail = builder::build_path_switch_request_failure(&PathSwitchRequestFailure {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        released_list: Some(vec![PduSessionResourceReleasedItem {
            pdu_session_id: 5,
            transfer: transfer(),
        }]),
        criticality_diagnostics: None,
    })
    .unwrap();
    check(
        "path_switch_request_failure",
        "PathSwitchRequestFailureIEs",
        &fail,
        &[],
    );
}

#[test]
fn multicast_group_paging() {
    let bytes = builder::build_multicast_group_paging(
        &MbsSessionId::new(plmn(), [0x00, 0x00, 0x01]),
        &[MulticastGroupPagingArea {
            area_tai_list: vec![TaiListItem {
                tai_plmn: plmn(),
                tai_tac: tac(),
            }],
        }],
    )
    .unwrap();
    check(
        "multicast_group_paging",
        "MulticastGroupPagingIEs",
        &bytes,
        &[],
    );
}

/// The Paging amfd sends (UEPagingIdentity + TAIListForPaging), against octets
/// derived from X.691 by hand rather than from either encoder:
///
/// - `00` InitiatingMessage (extensible CHOICE: ext 0, index 00), padded;
///   `18` procedure 24; `40` criticality ignore; `19` value length 25.
/// - value: `00` SEQUENCE extension bit + pad; `00 02` two IEs.
/// - IE 115 `00 73`, ignore `40`, length `07`, UEPagingIdentity:
///   CHOICE index `0` (two alternatives, not extensible), FiveG-S-TMSI ext `0`,
///   iE-Extensions absent `0`, aMFSetID `0000000001`, aMFPointer `000001`
///   = 19 bits -> `00 08 20`; fiveG-TMSI OCTET STRING (SIZE(4)) octet-aligned
///   (X.691 §17.6) -> `12 34 56 78`.
/// - IE 103 `00 67`, ignore `40`, length `07`: list count 1 in 1..16 -> `0000`,
///   item ext/iE-Extensions `0 0`, TAI ext/iE-Extensions `0 0` = 8 bits `00`;
///   PLMN `00 f1 10`; TAC `00 00 01`.
#[test]
fn paging_as_amfd_sends_it_matches_hand_derived_octets() {
    let bytes = builder::build_paging(&Paging {
        ue_paging_identity: UePagingIdentity::FiveGSTmsi {
            amf_set_id: 0x001,
            amf_pointer: 0x01,
            tmsi: 0x1234_5678,
        },
        paging_drx: None,
        tai_list: vec![TaiListItem {
            tai_plmn: plmn(),
            tai_tac: tac(),
        }],
        paging_priority: None,
        ue_radio_capability: None,
        paging_origin: None,
        assistance_data: None,
    })
    .unwrap();
    let expected: [u8; 29] = [
        0x00, 0x18, 0x40, 0x19, // PDU header
        0x00, 0x00, 0x02, // value: extension bit, 2 IEs
        0x00, 0x73, 0x40, 0x07, 0x00, 0x08, 0x20, 0x12, 0x34, 0x56, 0x78, // UEPagingIdentity
        0x00, 0x67, 0x40, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01, // TAIListForPaging
    ];
    assert_eq!(bytes, expected);
    check("paging (amfd shape)", "PagingIEs", &bytes, &[]);
}

/// SecurityContext { nextHopChainingCount 1, nextHopNH } in Path Switch Request
/// Acknowledge, against hand-derived octets: extension `0`, iE-Extensions absent
/// `0`, count `001` in 0..7, then the 256-bit SecurityKey octet-aligned
/// (X.691 §16.10) -> `08` followed by the 32 key octets unshifted.
#[test]
fn security_context_key_is_octet_aligned() {
    let bytes = builder::build_path_switch_request_acknowledge(&PathSwitchRequestAcknowledge {
        amf_ue_ngap_id: 1,
        ran_ue_ngap_id: 2,
        ue_security_capabilities: None,
        security_context: SecurityContext {
            next_hop_chaining_count: 1,
            next_hop: [0x22; 32],
        },
        switched_list: vec![PduSessionResourceSwitchedItem {
            pdu_session_id: 5,
            transfer: transfer(),
        }],
        released_list: None,
        allowed_nssai: nssai(),
    })
    .unwrap();
    let pdu = NgapPdu::decode_aper(&mut AperDecoder::new(&bytes)).unwrap();
    let ctx = pdu
        .protocol_ies()
        .ies
        .iter()
        .find(|f| f.id.0 == 93)
        .expect("SecurityContext (IE 93)");
    let mut expected = vec![0x08];
    expected.extend_from_slice(&[0x22; 32]);
    assert_eq!(ctx.value, expected);
}
