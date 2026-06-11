//! Round-trip and strict-reject tests for every S1AP message (TS 36.413).
//!
//! DoD level (a): encode/decode round-trip for every message touched.
//! DoD level (b): strict-peer rejection of messages missing mandatory IEs and
//!     of malformed/truncated input (Err, never panic).
//! DoD level (c): no public byte-exact S1AP vector is bundled with this repo
//!     (Open5GS test captures are not vendored); byte-level conformance is
//!     covered by the symmetric APER primitives validated in ogs-asn1c.

use ogs_asn1c::per::{AperEncode, AperEncoder};
use ogs_asn1c::s1ap::ies::ProtocolIeContainer;
use ogs_asn1c::s1ap::pdu::{
    InitiatingMessage, InitiatingMessageValue, S1apPdu, SuccessfulOutcome, SuccessfulOutcomeValue,
    UnsuccessfulOutcome, UnsuccessfulOutcomeValue,
};
use ogs_asn1c::s1ap::types::{Criticality, ProcedureCode};
use ogs_s1ap::*;
use proptest::prelude::*;

const PLMN: [u8; 3] = [0x00, 0xF1, 0x10];

fn sample_tai() -> Tai {
    Tai {
        plmn_identity: PLMN,
        tac: 0x0001,
    }
}

fn sample_cgi() -> EutranCgi {
    EutranCgi {
        plmn_identity: PLMN,
        cell_identity: 0x0ABC_DEF1,
    }
}

fn sample_qos(gbr: bool) -> ErabLevelQosParameters {
    ErabLevelQosParameters {
        qci: 9,
        arp: AllocationRetentionPriority {
            priority_level: 8,
            pre_emption_capability: true,
            pre_emption_vulnerability: false,
        },
        gbr_qos_info: gbr.then_some(GbrQosInformation {
            erab_max_bitrate_dl: 10_000_000_000,
            erab_max_bitrate_ul: 5_000_000_000,
            erab_guaranteed_bitrate_dl: 1_000_000,
            erab_guaranteed_bitrate_ul: 500_000,
        }),
    }
}

fn sample_cause() -> Cause {
    Cause::RadioNetwork(CauseRadioNetwork::UserInactivity)
}

// ============================================================================
// S1 Setup
// ============================================================================

#[test]
fn s1_setup_request_roundtrip() {
    let msg = S1SetupRequest {
        global_enb_id: GlobalEnbId {
            plmn_identity: PLMN,
            enb_id: EnbId::Macro(0x12345),
        },
        enb_name: Some("TestENodeB".to_string()),
        supported_tas: vec![SupportedTaItem {
            tac: 0x0001,
            broadcast_plmns: vec![PLMN, [0x99, 0xF9, 0x99]],
        }],
        default_paging_drx: PagingDrx::V128,
    };
    let bytes = build_s1_setup_request(&msg).unwrap();
    assert!(!bytes.is_empty());
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::S1SetupRequest(decoded) => {
            assert_eq!(decoded.global_enb_id, msg.global_enb_id);
            assert_eq!(decoded.enb_name.as_deref(), Some("TestENodeB"));
            assert_eq!(decoded.supported_tas.len(), 1);
            assert_eq!(decoded.supported_tas[0].tac, 0x0001);
            assert_eq!(decoded.supported_tas[0].broadcast_plmns.len(), 2);
            assert_eq!(decoded.default_paging_drx, PagingDrx::V128);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn s1_setup_request_home_enb_roundtrip() {
    let msg = S1SetupRequest {
        global_enb_id: GlobalEnbId {
            plmn_identity: PLMN,
            enb_id: EnbId::Home(0x0FED_CBA9 & 0x0FFF_FFFF),
        },
        enb_name: None,
        supported_tas: vec![SupportedTaItem {
            tac: 0xFFFE,
            broadcast_plmns: vec![PLMN],
        }],
        default_paging_drx: PagingDrx::V32,
    };
    let bytes = build_s1_setup_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::S1SetupRequest(decoded) => {
            assert_eq!(decoded.global_enb_id, msg.global_enb_id);
            assert!(decoded.enb_name.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn s1_setup_response_roundtrip() {
    let msg = S1SetupResponse {
        mme_name: Some("mme01.nextgcore".to_string()),
        served_gummeis: vec![ServedGummeiItem {
            served_plmns: vec![PLMN],
            served_group_ids: vec![0x0002, 0x0004],
            served_mmec_codes: vec![1, 2],
        }],
        relative_mme_capacity: 255,
    };
    let bytes = build_s1_setup_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::S1SetupResponse(decoded) => {
            assert_eq!(decoded.mme_name.as_deref(), Some("mme01.nextgcore"));
            assert_eq!(decoded.served_gummeis.len(), 1);
            assert_eq!(decoded.served_gummeis[0].served_plmns, vec![PLMN]);
            assert_eq!(decoded.served_gummeis[0].served_group_ids, vec![2, 4]);
            assert_eq!(decoded.served_gummeis[0].served_mmec_codes, vec![1, 2]);
            assert_eq!(decoded.relative_mme_capacity, 255);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn s1_setup_failure_roundtrip() {
    let msg = S1SetupFailure {
        cause: Cause::Misc(CauseMisc::UnknownPlmn),
        time_to_wait: Some(TimeToWait::V10s),
    };
    let bytes = build_s1_setup_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::S1SetupFailure(decoded) => {
            assert_eq!(decoded.cause, Cause::Misc(CauseMisc::UnknownPlmn));
            assert_eq!(decoded.time_to_wait, Some(TimeToWait::V10s));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// NAS transport
// ============================================================================

#[test]
fn initial_ue_message_roundtrip() {
    let msg = InitialUeMessage {
        enb_ue_s1ap_id: 0xFF_FFFF,
        nas_pdu: vec![0x07, 0x41, 0x71, 0x08],
        tai: sample_tai(),
        eutran_cgi: sample_cgi(),
        rrc_establishment_cause: RrcEstablishmentCause::MoSignalling,
        s_tmsi: Some(STmsi {
            mmec: 0x01,
            m_tmsi: 0xC000_0001,
        }),
    };
    let bytes = build_initial_ue_message(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::InitialUeMessage(decoded) => {
            assert_eq!(decoded.enb_ue_s1ap_id, 0xFF_FFFF);
            assert_eq!(decoded.nas_pdu, msg.nas_pdu);
            assert_eq!(decoded.tai, msg.tai);
            assert_eq!(decoded.eutran_cgi, msg.eutran_cgi);
            assert_eq!(
                decoded.rrc_establishment_cause,
                RrcEstablishmentCause::MoSignalling
            );
            assert_eq!(decoded.s_tmsi, msg.s_tmsi);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn downlink_nas_transport_roundtrip() {
    let msg = DlNasTransport {
        mme_ue_s1ap_id: 0xFFFF_FFFF,
        enb_ue_s1ap_id: 1,
        nas_pdu: vec![0x07, 0x52, 0x00],
    };
    let bytes = build_downlink_nas_transport(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::DownlinkNasTransport(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 0xFFFF_FFFF);
            assert_eq!(decoded.enb_ue_s1ap_id, 1);
            assert_eq!(decoded.nas_pdu, msg.nas_pdu);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn uplink_nas_transport_roundtrip() {
    let msg = UlNasTransport {
        mme_ue_s1ap_id: 42,
        enb_ue_s1ap_id: 24,
        nas_pdu: vec![0x07, 0x53],
        eutran_cgi: sample_cgi(),
        tai: sample_tai(),
    };
    let bytes = build_uplink_nas_transport(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UplinkNasTransport(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 42);
            assert_eq!(decoded.enb_ue_s1ap_id, 24);
            assert_eq!(decoded.nas_pdu, msg.nas_pdu);
            assert_eq!(decoded.eutran_cgi, msg.eutran_cgi);
            assert_eq!(decoded.tai, msg.tai);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn nas_non_delivery_indication_roundtrip() {
    let msg = NasNonDeliveryIndication {
        mme_ue_s1ap_id: 7,
        enb_ue_s1ap_id: 8,
        nas_pdu: vec![0x07, 0x46],
        cause: Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost),
    };
    let bytes = build_nas_non_delivery_indication(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::NasNonDeliveryIndication(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 7);
            assert_eq!(decoded.enb_ue_s1ap_id, 8);
            assert_eq!(decoded.nas_pdu, msg.nas_pdu);
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Initial Context Setup
// ============================================================================

#[test]
fn initial_context_setup_request_roundtrip() {
    let msg = InitialContextSetupRequest {
        mme_ue_s1ap_id: 100,
        enb_ue_s1ap_id: 200,
        ue_ambr: UeAmbr {
            dl: 10_000_000_000,
            ul: 1_000_000_000,
        },
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 5,
            erab_qos: sample_qos(true),
            transport_layer_address: vec![10, 45, 0, 1],
            gtp_teid: 0xDEAD_BEEF,
            nas_pdu: Some(vec![0x27, 0x01]),
        }],
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0xE000,
            integrity_algorithms: 0xC000,
        },
        security_key: [0xAB; 32],
    };
    let bytes = build_initial_context_setup_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::InitialContextSetupRequest(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 100);
            assert_eq!(decoded.enb_ue_s1ap_id, 200);
            assert_eq!(decoded.ue_ambr.dl, 10_000_000_000);
            assert_eq!(decoded.ue_ambr.ul, 1_000_000_000);
            assert_eq!(decoded.erab_list.len(), 1);
            let item = &decoded.erab_list[0];
            assert_eq!(item.erab_id, 5);
            assert_eq!(item.erab_qos.qci, 9);
            assert_eq!(item.erab_qos.arp.priority_level, 8);
            assert!(item.erab_qos.arp.pre_emption_capability);
            assert!(!item.erab_qos.arp.pre_emption_vulnerability);
            let gbr = item.erab_qos.gbr_qos_info.as_ref().unwrap();
            assert_eq!(gbr.erab_max_bitrate_dl, 10_000_000_000);
            assert_eq!(item.transport_layer_address, vec![10, 45, 0, 1]);
            assert_eq!(item.gtp_teid, 0xDEAD_BEEF);
            assert_eq!(item.nas_pdu.as_deref(), Some(&[0x27, 0x01][..]));
            assert_eq!(decoded.ue_security_capabilities.encryption_algorithms, 0xE000);
            assert_eq!(decoded.ue_security_capabilities.integrity_algorithms, 0xC000);
            assert_eq!(decoded.security_key, [0xAB; 32]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn initial_context_setup_response_roundtrip() {
    let msg = InitialContextSetupResponse {
        mme_ue_s1ap_id: 100,
        enb_ue_s1ap_id: 200,
        erab_setup_list: vec![ErabSetupItem {
            erab_id: 5,
            // 16-byte IPv6 transport address
            transport_layer_address: vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            gtp_teid: 0x0000_0001,
        }],
        erab_failed_list: vec![ErabFailedItem {
            erab_id: 6,
            cause: Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable),
        }],
    };
    let bytes = build_initial_context_setup_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::InitialContextSetupResponse(decoded) => {
            assert_eq!(decoded.erab_setup_list.len(), 1);
            assert_eq!(decoded.erab_setup_list[0].transport_layer_address.len(), 16);
            assert_eq!(decoded.erab_failed_list.len(), 1);
            assert_eq!(decoded.erab_failed_list[0].erab_id, 6);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn initial_context_setup_failure_roundtrip() {
    let msg = InitialContextSetupFailure {
        mme_ue_s1ap_id: 100,
        enb_ue_s1ap_id: 200,
        cause: Cause::RadioNetwork(
            CauseRadioNetwork::EncryptionAndOrIntegrityProtectionAlgorithmsNotSupported,
        ),
    };
    let bytes = build_initial_context_setup_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::InitialContextSetupFailure(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 100);
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// UE Context Release
// ============================================================================

#[test]
fn ue_context_release_request_roundtrip() {
    let msg = UeContextReleaseRequest {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        cause: Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
    };
    let bytes = build_ue_context_release_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextReleaseRequest(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 1);
            assert_eq!(decoded.enb_ue_s1ap_id, 2);
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn ue_context_release_command_pair_roundtrip() {
    let msg = UeContextReleaseCommand {
        ue_s1ap_ids: UeS1apIds::Pair {
            mme_ue_s1ap_id: 11,
            enb_ue_s1ap_id: 22,
        },
        cause: Cause::Nas(CauseNas::Detach),
    };
    let bytes = build_ue_context_release_command(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextReleaseCommand(decoded) => {
            assert_eq!(decoded.ue_s1ap_ids, msg.ue_s1ap_ids);
            assert_eq!(decoded.cause, Cause::Nas(CauseNas::Detach));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn ue_context_release_command_mme_only_roundtrip() {
    let msg = UeContextReleaseCommand {
        ue_s1ap_ids: UeS1apIds::MmeOnly { mme_ue_s1ap_id: 33 },
        cause: Cause::Nas(CauseNas::NormalRelease),
    };
    let bytes = build_ue_context_release_command(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextReleaseCommand(decoded) => {
            assert_eq!(decoded.ue_s1ap_ids, msg.ue_s1ap_ids);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn ue_context_release_complete_roundtrip() {
    let msg = UeContextReleaseComplete {
        mme_ue_s1ap_id: 11,
        enb_ue_s1ap_id: 22,
    };
    let bytes = build_ue_context_release_complete(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextReleaseComplete(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 11);
            assert_eq!(decoded.enb_ue_s1ap_id, 22);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// E-RAB management
// ============================================================================

#[test]
fn erab_setup_request_roundtrip() {
    let msg = ErabSetupRequest {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        ue_ambr: Some(UeAmbr {
            dl: 100_000_000,
            ul: 50_000_000,
        }),
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 6,
            erab_qos: sample_qos(false),
            transport_layer_address: vec![192, 168, 0, 1],
            gtp_teid: 0x1234_5678,
            nas_pdu: Some(vec![0x27, 0xC1]),
        }],
    };
    let bytes = build_erab_setup_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabSetupRequest(decoded) => {
            assert_eq!(decoded.ue_ambr, msg.ue_ambr);
            assert_eq!(decoded.erab_list.len(), 1);
            assert_eq!(decoded.erab_list[0].erab_id, 6);
            assert_eq!(decoded.erab_list[0].nas_pdu.as_deref(), Some(&[0x27, 0xC1][..]));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn erab_setup_request_rejects_missing_nas_pdu() {
    // NAS-PDU is mandatory per E-RABToBeSetupItemBearerSUReq
    let msg = ErabSetupRequest {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        ue_ambr: None,
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 6,
            erab_qos: sample_qos(false),
            transport_layer_address: vec![192, 168, 0, 1],
            gtp_teid: 1,
            nas_pdu: None,
        }],
    };
    assert!(build_erab_setup_request(&msg).is_err());
}

#[test]
fn erab_setup_response_roundtrip() {
    let msg = ErabSetupResponse {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        erab_setup_list: vec![ErabSetupItem {
            erab_id: 6,
            transport_layer_address: vec![192, 168, 0, 2],
            gtp_teid: 0x9ABC_DEF0,
        }],
        erab_failed_list: vec![],
    };
    let bytes = build_erab_setup_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabSetupResponse(decoded) => {
            assert_eq!(decoded.erab_setup_list.len(), 1);
            assert_eq!(decoded.erab_setup_list[0].gtp_teid, 0x9ABC_DEF0);
            assert!(decoded.erab_failed_list.is_empty());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn erab_modify_request_roundtrip() {
    let msg = ErabModifyRequest {
        mme_ue_s1ap_id: 3,
        enb_ue_s1ap_id: 4,
        ue_ambr: None,
        erab_list: vec![ErabToBeModifiedItem {
            erab_id: 7,
            erab_qos: sample_qos(true),
            nas_pdu: vec![0x27, 0xCA],
        }],
    };
    let bytes = build_erab_modify_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabModifyRequest(decoded) => {
            assert_eq!(decoded.erab_list.len(), 1);
            assert_eq!(decoded.erab_list[0].erab_id, 7);
            assert!(decoded.erab_list[0].erab_qos.gbr_qos_info.is_some());
            assert_eq!(decoded.erab_list[0].nas_pdu, vec![0x27, 0xCA]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn erab_modify_response_roundtrip() {
    let msg = ErabModifyResponse {
        mme_ue_s1ap_id: 3,
        enb_ue_s1ap_id: 4,
        erab_modify_list: vec![7],
        erab_failed_list: vec![ErabFailedItem {
            erab_id: 8,
            cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownERabId),
        }],
    };
    let bytes = build_erab_modify_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabModifyResponse(decoded) => {
            assert_eq!(decoded.erab_modify_list, vec![7]);
            assert_eq!(decoded.erab_failed_list.len(), 1);
            assert_eq!(decoded.erab_failed_list[0].erab_id, 8);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn erab_release_command_roundtrip() {
    let msg = ErabReleaseCommand {
        mme_ue_s1ap_id: 5,
        enb_ue_s1ap_id: 6,
        ue_ambr: Some(UeAmbr {
            dl: 1_000_000,
            ul: 1_000_000,
        }),
        erab_list: vec![ErabItem {
            erab_id: 9,
            cause: Cause::Nas(CauseNas::NormalRelease),
        }],
        nas_pdu: Some(vec![0x27, 0xCD]),
    };
    let bytes = build_erab_release_command(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabReleaseCommand(decoded) => {
            assert_eq!(decoded.erab_list.len(), 1);
            assert_eq!(decoded.erab_list[0].erab_id, 9);
            assert_eq!(decoded.nas_pdu, msg.nas_pdu);
            assert_eq!(decoded.ue_ambr, msg.ue_ambr);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn erab_release_response_roundtrip() {
    let msg = ErabReleaseResponse {
        mme_ue_s1ap_id: 5,
        enb_ue_s1ap_id: 6,
        erab_release_list: vec![9],
        erab_failed_list: vec![],
    };
    let bytes = build_erab_release_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErabReleaseResponse(decoded) => {
            assert_eq!(decoded.erab_release_list, vec![9]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Paging
// ============================================================================

#[test]
fn paging_s_tmsi_roundtrip() {
    let msg = Paging {
        ue_identity_index: 0x03FF,
        ue_paging_id: UePagingId::STmsi(STmsi {
            mmec: 2,
            m_tmsi: 0xC123_4567,
        }),
        paging_drx: Some(PagingDrx::V256),
        cn_domain: CnDomain::Ps,
        tai_list: vec![sample_tai(), Tai {
            plmn_identity: PLMN,
            tac: 0x0002,
        }],
    };
    let bytes = build_paging(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Paging(decoded) => {
            assert_eq!(decoded.ue_identity_index, 0x03FF);
            assert_eq!(decoded.ue_paging_id, msg.ue_paging_id);
            assert_eq!(decoded.paging_drx, Some(PagingDrx::V256));
            assert_eq!(decoded.cn_domain, CnDomain::Ps);
            assert_eq!(decoded.tai_list.len(), 2);
            assert_eq!(decoded.tai_list[1].tac, 0x0002);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn paging_imsi_roundtrip() {
    let msg = Paging {
        ue_identity_index: 1,
        ue_paging_id: UePagingId::Imsi(vec![0x00, 0x1F, 0x01, 0x23, 0x45, 0x67, 0x89]),
        paging_drx: None,
        cn_domain: CnDomain::Cs,
        tai_list: vec![sample_tai()],
    };
    let bytes = build_paging(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Paging(decoded) => {
            assert_eq!(decoded.ue_paging_id, msg.ue_paging_id);
            assert_eq!(decoded.cn_domain, CnDomain::Cs);
            assert!(decoded.paging_drx.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Reset / Error Indication
// ============================================================================

#[test]
fn reset_s1_interface_roundtrip() {
    let msg = Reset {
        cause: Cause::Misc(CauseMisc::OmIntervention),
        reset_type: ResetType::S1Interface,
    };
    let bytes = build_reset(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Reset(decoded) => {
            assert_eq!(decoded.cause, Cause::Misc(CauseMisc::OmIntervention));
            assert_eq!(decoded.reset_type, ResetType::S1Interface);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn reset_partial_roundtrip() {
    let msg = Reset {
        cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        reset_type: ResetType::PartOfS1Interface(vec![
            UeAssociatedLogicalS1Connection {
                mme_ue_s1ap_id: Some(1),
                enb_ue_s1ap_id: Some(2),
            },
            UeAssociatedLogicalS1Connection {
                mme_ue_s1ap_id: Some(3),
                enb_ue_s1ap_id: None,
            },
        ]),
    };
    let bytes = build_reset(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Reset(decoded) => {
            assert_eq!(decoded.reset_type, msg.reset_type);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn reset_acknowledge_roundtrip() {
    let msg = ResetAcknowledge {
        ue_associated_connections: vec![UeAssociatedLogicalS1Connection {
            mme_ue_s1ap_id: Some(1),
            enb_ue_s1ap_id: Some(2),
        }],
    };
    let bytes = build_reset_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ResetAcknowledge(decoded) => {
            assert_eq!(
                decoded.ue_associated_connections,
                msg.ue_associated_connections
            );
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn reset_acknowledge_empty_roundtrip() {
    let msg = ResetAcknowledge {
        ue_associated_connections: vec![],
    };
    let bytes = build_reset_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ResetAcknowledge(decoded) => {
            assert!(decoded.ue_associated_connections.is_empty());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn error_indication_roundtrip() {
    let msg = ErrorIndication {
        mme_ue_s1ap_id: Some(99),
        enb_ue_s1ap_id: None,
        cause: Some(Cause::Protocol(CauseProtocol::SemanticError)),
    };
    let bytes = build_error_indication(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErrorIndication(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, Some(99));
            assert!(decoded.enb_ue_s1ap_id.is_none());
            assert_eq!(decoded.cause, Some(Cause::Protocol(CauseProtocol::SemanticError)));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Handover family
// ============================================================================

#[test]
fn handover_required_roundtrip() {
    let msg = HandoverRequired {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        handover_type: HandoverType::IntraLte,
        cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
        target_id: TargetId::TargetEnbId {
            global_enb_id: GlobalEnbId {
                plmn_identity: PLMN,
                enb_id: EnbId::Macro(0x54321),
            },
            selected_tai: sample_tai(),
        },
        source_to_target_container: vec![1, 2, 3, 4, 5],
    };
    let bytes = build_handover_required(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverRequired(decoded) => {
            assert_eq!(decoded.handover_type, HandoverType::IntraLte);
            assert_eq!(decoded.target_id, msg.target_id);
            assert_eq!(decoded.source_to_target_container, vec![1, 2, 3, 4, 5]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_required_target_rnc_roundtrip() {
    let msg = HandoverRequired {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        handover_type: HandoverType::LteToUtran,
        cause: Cause::RadioNetwork(CauseRadioNetwork::TimeCriticalHandover),
        target_id: TargetId::TargetRncId {
            plmn_identity: PLMN,
            lac: 0x1234,
            rac: Some(0x42),
            rnc_id: 5000, // > 4095, exercises extendedRNC-ID
        },
        source_to_target_container: vec![9, 9],
    };
    let bytes = build_handover_required(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverRequired(decoded) => {
            assert_eq!(decoded.target_id, msg.target_id);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_required_target_cgi_roundtrip() {
    let msg = HandoverRequired {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        handover_type: HandoverType::LteToGeran,
        cause: Cause::RadioNetwork(CauseRadioNetwork::ResourceOptimisationHandover),
        target_id: TargetId::Cgi {
            plmn_identity: PLMN,
            lac: 0x0001,
            ci: 0x0002,
            rac: None,
        },
        source_to_target_container: vec![7],
    };
    let bytes = build_handover_required(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverRequired(decoded) => {
            assert_eq!(decoded.target_id, msg.target_id);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_command_roundtrip() {
    let msg = HandoverCommand {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        handover_type: HandoverType::IntraLte,
        erab_subject_to_forwarding_list: vec![ErabDataForwardingItem {
            erab_id: 5,
            dl_transport_layer_address: Some(vec![10, 0, 0, 1]),
            dl_gtp_teid: Some(0x1111_2222),
            ul_transport_layer_address: None,
            ul_gtp_teid: None,
        }],
        erab_to_release_list: vec![ErabItem {
            erab_id: 6,
            cause: Cause::RadioNetwork(CauseRadioNetwork::NoRadioResourcesAvailableInTargetCell),
        }],
        target_to_source_container: vec![0xAA, 0xBB],
    };
    let bytes = build_handover_command(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverCommand(decoded) => {
            assert_eq!(decoded.erab_subject_to_forwarding_list.len(), 1);
            let fwd = &decoded.erab_subject_to_forwarding_list[0];
            assert_eq!(fwd.dl_transport_layer_address.as_deref(), Some(&[10, 0, 0, 1][..]));
            assert_eq!(fwd.dl_gtp_teid, Some(0x1111_2222));
            assert!(fwd.ul_gtp_teid.is_none());
            assert_eq!(decoded.erab_to_release_list.len(), 1);
            assert_eq!(decoded.target_to_source_container, vec![0xAA, 0xBB]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_preparation_failure_roundtrip() {
    let msg = HandoverPreparationFailure {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        cause: Cause::RadioNetwork(CauseRadioNetwork::HoTargetNotAllowed),
    };
    let bytes = build_handover_preparation_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverPreparationFailure(decoded) => {
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_request_roundtrip() {
    let msg = HandoverRequest {
        mme_ue_s1ap_id: 77,
        handover_type: HandoverType::IntraLte,
        cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
        ue_ambr: UeAmbr {
            dl: 500_000_000,
            ul: 100_000_000,
        },
        erab_list: vec![ErabToBeSetupItemHoReq {
            erab_id: 5,
            transport_layer_address: vec![10, 45, 0, 1],
            gtp_teid: 0x3333_4444,
            erab_qos: sample_qos(false),
        }],
        source_to_target_container: vec![1, 2, 3],
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0xE000,
            integrity_algorithms: 0xE000,
        },
        security_context: SecurityContext {
            next_hop_chaining_count: 3,
            next_hop_parameter: [0x5C; 32],
        },
    };
    let bytes = build_handover_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverRequest(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 77);
            assert_eq!(decoded.erab_list.len(), 1);
            assert_eq!(decoded.erab_list[0].gtp_teid, 0x3333_4444);
            assert_eq!(decoded.security_context.next_hop_chaining_count, 3);
            assert_eq!(decoded.security_context.next_hop_parameter, [0x5C; 32]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_request_acknowledge_roundtrip() {
    let msg = HandoverRequestAcknowledge {
        mme_ue_s1ap_id: 77,
        enb_ue_s1ap_id: 88,
        erab_admitted_list: vec![ErabAdmittedItem {
            erab_id: 5,
            transport_layer_address: vec![10, 45, 0, 2],
            gtp_teid: 0x5555_6666,
            dl_transport_layer_address: Some(vec![10, 45, 0, 3]),
            dl_gtp_teid: Some(0x7777_8888),
            ul_transport_layer_address: None,
            ul_gtp_teid: None,
        }],
        erab_failed_list: vec![ErabFailedItem {
            erab_id: 6,
            cause: Cause::RadioNetwork(CauseRadioNetwork::NoRadioResourcesAvailableInTargetCell),
        }],
        target_to_source_container: vec![4, 5, 6],
    };
    let bytes = build_handover_request_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverRequestAcknowledge(decoded) => {
            assert_eq!(decoded.erab_admitted_list.len(), 1);
            let adm = &decoded.erab_admitted_list[0];
            assert_eq!(adm.gtp_teid, 0x5555_6666);
            assert_eq!(adm.dl_gtp_teid, Some(0x7777_8888));
            assert_eq!(decoded.erab_failed_list.len(), 1);
            assert_eq!(decoded.target_to_source_container, vec![4, 5, 6]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_failure_roundtrip() {
    let msg = HandoverFailure {
        mme_ue_s1ap_id: 77,
        cause: Cause::RadioNetwork(CauseRadioNetwork::NoRadioResourcesAvailableInTargetCell),
    };
    let bytes = build_handover_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverFailure(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 77);
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_notify_roundtrip() {
    let msg = HandoverNotify {
        mme_ue_s1ap_id: 77,
        enb_ue_s1ap_id: 99,
        eutran_cgi: sample_cgi(),
        tai: sample_tai(),
    };
    let bytes = build_handover_notify(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverNotify(decoded) => {
            assert_eq!(decoded.eutran_cgi, msg.eutran_cgi);
            assert_eq!(decoded.tai, msg.tai);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn path_switch_request_roundtrip() {
    let msg = PathSwitchRequest {
        enb_ue_s1ap_id: 10,
        erab_switched_dl_list: vec![ErabSwitchedItem {
            erab_id: 5,
            transport_layer_address: vec![172, 16, 0, 1],
            gtp_teid: 0xAAAA_BBBB,
        }],
        source_mme_ue_s1ap_id: 20,
        eutran_cgi: sample_cgi(),
        tai: sample_tai(),
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0x8000,
            integrity_algorithms: 0x4000,
        },
    };
    let bytes = build_path_switch_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::PathSwitchRequest(decoded) => {
            assert_eq!(decoded.enb_ue_s1ap_id, 10);
            assert_eq!(decoded.source_mme_ue_s1ap_id, 20);
            assert_eq!(decoded.erab_switched_dl_list.len(), 1);
            assert_eq!(decoded.erab_switched_dl_list[0].gtp_teid, 0xAAAA_BBBB);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn path_switch_request_acknowledge_roundtrip() {
    let msg = PathSwitchRequestAcknowledge {
        mme_ue_s1ap_id: 20,
        enb_ue_s1ap_id: 10,
        erab_switched_ul_list: vec![ErabSwitchedItem {
            erab_id: 5,
            transport_layer_address: vec![172, 16, 0, 2],
            gtp_teid: 0xCCCC_DDDD,
        }],
        security_context: SecurityContext {
            next_hop_chaining_count: 1,
            next_hop_parameter: [0x77; 32],
        },
    };
    let bytes = build_path_switch_request_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::PathSwitchRequestAcknowledge(decoded) => {
            assert_eq!(decoded.erab_switched_ul_list.len(), 1);
            assert_eq!(decoded.security_context.next_hop_chaining_count, 1);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn path_switch_request_failure_roundtrip() {
    let msg = PathSwitchRequestFailure {
        mme_ue_s1ap_id: 20,
        enb_ue_s1ap_id: 10,
        cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId),
    };
    let bytes = build_path_switch_request_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::PathSwitchRequestFailure(decoded) => {
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_cancel_roundtrip() {
    let msg = HandoverCancel {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverCancelled),
    };
    let bytes = build_handover_cancel(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverCancel(decoded) => {
            assert_eq!(decoded.cause, msg.cause);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn handover_cancel_acknowledge_roundtrip() {
    let msg = HandoverCancelAcknowledge {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
    };
    let bytes = build_handover_cancel_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::HandoverCancelAcknowledge(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 1);
            assert_eq!(decoded.enb_ue_s1ap_id, 2);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// UE Capability Info Indication
// ============================================================================

#[test]
fn ue_capability_info_indication_roundtrip() {
    let msg = UeCapabilityInfoIndication {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 2,
        ue_radio_capability: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };
    let bytes = build_ue_capability_info_indication(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeCapabilityInfoIndication(decoded) => {
            assert_eq!(decoded.ue_radio_capability, msg.ue_radio_capability);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Strict-reject: missing mandatory IEs
// ============================================================================

fn encode_raw_pdu(pdu: &S1apPdu) -> Vec<u8> {
    let mut encoder = AperEncoder::new();
    pdu.encode_aper(&mut encoder).unwrap();
    encoder.align();
    encoder.into_bytes().to_vec()
}

fn empty_initiating(code: ProcedureCode) -> Vec<u8> {
    encode_raw_pdu(&S1apPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: code,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(ProtocolIeContainer::new()),
    }))
}

fn empty_successful(code: ProcedureCode) -> Vec<u8> {
    encode_raw_pdu(&S1apPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: code,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(ProtocolIeContainer::new()),
    }))
}

fn empty_unsuccessful(code: ProcedureCode) -> Vec<u8> {
    encode_raw_pdu(&S1apPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: code,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(ProtocolIeContainer::new()),
    }))
}

/// Every message with mandatory IEs must be rejected when those IEs are absent.
#[test]
fn strict_reject_missing_mandatory_ies() {
    let initiating = [
        ProcedureCode::S1_SETUP,
        ProcedureCode::INITIAL_UE_MESSAGE,
        ProcedureCode::DOWNLINK_NAS_TRANSPORT,
        ProcedureCode::UPLINK_NAS_TRANSPORT,
        ProcedureCode::NAS_NON_DELIVERY_INDICATION,
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        ProcedureCode::UE_CONTEXT_RELEASE_REQUEST,
        ProcedureCode::UE_CONTEXT_RELEASE,
        ProcedureCode::E_RAB_SETUP,
        ProcedureCode::E_RAB_MODIFY,
        ProcedureCode::E_RAB_RELEASE,
        ProcedureCode::PAGING,
        ProcedureCode::RESET,
        ProcedureCode::HANDOVER_PREPARATION,
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        ProcedureCode::HANDOVER_NOTIFICATION,
        ProcedureCode::PATH_SWITCH_REQUEST,
        ProcedureCode::HANDOVER_CANCEL,
        ProcedureCode::UE_CAPABILITY_INFO_INDICATION,
    ];
    for code in initiating {
        let bytes = empty_initiating(code);
        assert!(
            decode_s1ap_pdu(&bytes).is_err(),
            "initiating procedure {} with no IEs must be rejected",
            code.0
        );
    }

    let successful = [
        ProcedureCode::S1_SETUP,
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        ProcedureCode::UE_CONTEXT_RELEASE,
        ProcedureCode::E_RAB_SETUP,
        ProcedureCode::E_RAB_MODIFY,
        ProcedureCode::E_RAB_RELEASE,
        ProcedureCode::HANDOVER_PREPARATION,
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        ProcedureCode::PATH_SWITCH_REQUEST,
        ProcedureCode::HANDOVER_CANCEL,
    ];
    for code in successful {
        let bytes = empty_successful(code);
        assert!(
            decode_s1ap_pdu(&bytes).is_err(),
            "successful outcome {} with no IEs must be rejected",
            code.0
        );
    }

    let unsuccessful = [
        ProcedureCode::S1_SETUP,
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        ProcedureCode::HANDOVER_PREPARATION,
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        ProcedureCode::PATH_SWITCH_REQUEST,
    ];
    for code in unsuccessful {
        let bytes = empty_unsuccessful(code);
        assert!(
            decode_s1ap_pdu(&bytes).is_err(),
            "unsuccessful outcome {} with no IEs must be rejected",
            code.0
        );
    }
}

/// ResetAcknowledge and ErrorIndication carry only optional IEs - an empty
/// container is valid for them.
#[test]
fn optional_only_messages_accept_empty_container() {
    let reset_ack = empty_successful(ProcedureCode::RESET);
    assert!(matches!(
        decode_s1ap_pdu(&reset_ack).unwrap(),
        S1apMessage::ResetAcknowledge(_)
    ));

    let error_ind = empty_initiating(ProcedureCode::ERROR_INDICATION);
    assert!(matches!(
        decode_s1ap_pdu(&error_ind).unwrap(),
        S1apMessage::ErrorIndication(_)
    ));
}

/// A message that decodes through a typed PDU variant but is missing one
/// specific mandatory IE (not just all of them) must also be rejected.
#[test]
fn strict_reject_partially_populated_message() {
    // InitialUEMessage with only the eNB-UE-S1AP-ID (missing NAS-PDU, TAI, ...)
    let mut container = ProtocolIeContainer::new();
    ogs_s1ap::ie::encode_enb_ue_s1ap_id(&mut container, 1, Criticality::Reject).unwrap();
    let bytes = encode_raw_pdu(&S1apPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::INITIAL_UE_MESSAGE,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::InitialUeMessage(container),
    }));
    let err = decode_s1ap_pdu(&bytes).unwrap_err();
    assert!(err.to_string().contains("NAS-PDU"), "got: {err}");

    // UEContextReleaseCommand with cause but no UE-S1AP-IDs
    let mut container = ProtocolIeContainer::new();
    ogs_s1ap::ie::encode_cause(&mut container, &sample_cause()).unwrap();
    let bytes = encode_raw_pdu(&S1apPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::UE_CONTEXT_RELEASE,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::UeContextReleaseCommand(container),
    }));
    assert!(decode_s1ap_pdu(&bytes).is_err());
}

// ============================================================================
// Malformed input never panics
// ============================================================================

#[test]
fn truncated_messages_return_err() {
    let msg = InitialContextSetupRequest {
        mme_ue_s1ap_id: 100,
        enb_ue_s1ap_id: 200,
        ue_ambr: UeAmbr {
            dl: 1_000_000,
            ul: 1_000_000,
        },
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 5,
            erab_qos: sample_qos(false),
            transport_layer_address: vec![10, 0, 0, 1],
            gtp_teid: 1,
            nas_pdu: None,
        }],
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0xE000,
            integrity_algorithms: 0xE000,
        },
        security_key: [0; 32],
    };
    let bytes = build_initial_context_setup_request(&msg).unwrap();
    // Every strict prefix must fail cleanly (no panic)
    for len in 0..bytes.len() {
        assert!(
            decode_s1ap_pdu(&bytes[..len]).is_err(),
            "truncated prefix of length {len} unexpectedly decoded"
        );
    }
}

#[test]
fn unknown_procedure_code_is_reported_not_rejected() {
    let bytes = empty_initiating(ProcedureCode::WRITE_REPLACE_WARNING);
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Unknown {
            procedure_code,
            message_type,
        } => {
            assert_eq!(procedure_code, ProcedureCode::WRITE_REPLACE_WARNING.0);
            assert_eq!(message_type, "InitiatingMessage");
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

proptest! {
    /// Decoding arbitrary bytes must never panic (Wave 0 made the APER
    /// primitives panic-free; this layer must stay panic-free too).
    #[test]
    fn random_data_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_s1ap_pdu(&data);
    }

    /// Bit-flipped valid messages must never panic.
    #[test]
    fn bitflipped_valid_message_does_not_panic(byte_index in 0usize..64, bit in 0u8..8) {
        let msg = DlNasTransport {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 2,
            nas_pdu: vec![0x07, 0x52, 0x00, 0x01, 0x02, 0x03],
        };
        let mut bytes = build_downlink_nas_transport(&msg).unwrap();
        if byte_index < bytes.len() {
            bytes[byte_index] ^= 1 << bit;
        }
        let _ = decode_s1ap_pdu(&bytes);
    }
}
