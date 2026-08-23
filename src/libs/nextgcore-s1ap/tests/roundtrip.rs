//! Round-trip and strict-reject tests for every S1AP message (TS 36.413).
//!
//! DoD level (a): encode/decode round-trip for every message touched.
//! DoD level (b): strict-peer rejection of messages missing mandatory IEs and
//!     of malformed/truncated input (Err, never panic).
//! DoD level (c): no public byte-exact S1AP vector is bundled with this repo
//!     (Open5GS test captures are not vendored); byte-level conformance is
//!     covered by the symmetric APER primitives validated in nextgcore-asn1c.

use nextgcore_asn1c::per::{AperEncode, AperEncoder};
use nextgcore_asn1c::s1ap::ies::ProtocolIeContainer;
use nextgcore_asn1c::s1ap::pdu::{
    InitiatingMessage, InitiatingMessageValue, S1apPdu, SuccessfulOutcome, SuccessfulOutcomeValue,
    UnsuccessfulOutcome, UnsuccessfulOutcomeValue,
};
use nextgcore_asn1c::s1ap::types::{Criticality, ProcedureCode};
use nextgcore_s1ap::*;
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
            assert_eq!(
                decoded.ue_security_capabilities.encryption_algorithms,
                0xE000
            );
            assert_eq!(
                decoded.ue_security_capabilities.integrity_algorithms,
                0xC000
            );
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
            assert_eq!(
                decoded.erab_list[0].nas_pdu.as_deref(),
                Some(&[0x27, 0xC1][..])
            );
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
        tai_list: vec![
            sample_tai(),
            Tai {
                plmn_identity: PLMN,
                tac: 0x0002,
            },
        ],
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
        criticality_diagnostics: None,
    };
    let bytes = build_error_indication(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErrorIndication(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, Some(99));
            assert!(decoded.enb_ue_s1ap_id.is_none());
            assert_eq!(
                decoded.cause,
                Some(Cause::Protocol(CauseProtocol::SemanticError))
            );
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
            assert_eq!(
                fwd.dl_transport_layer_address.as_deref(),
                Some(&[10, 0, 0, 1][..])
            );
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
// eNB / MME Configuration Update (§9.1.8.7-9.1.8.12)
// ============================================================================

#[test]
fn enb_configuration_update_roundtrip() {
    let msg = EnbConfigurationUpdate {
        enb_name: Some("reconfigured-enb".to_string()),
        supported_tas: Some(vec![
            SupportedTaItem {
                tac: 0x0007,
                broadcast_plmns: vec![PLMN],
            },
            SupportedTaItem {
                tac: 0x0008,
                broadcast_plmns: vec![PLMN, [0x99, 0xF9, 0x99]],
            },
        ]),
        default_paging_drx: Some(PagingDrx::V256),
    };
    let bytes = build_enb_configuration_update(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::EnbConfigurationUpdate(decoded) => {
            assert_eq!(decoded.enb_name.as_deref(), Some("reconfigured-enb"));
            let tas = decoded.supported_tas.expect("SupportedTAs was present");
            assert_eq!(tas.len(), 2);
            assert_eq!(tas[0].tac, 0x0007);
            assert_eq!(tas[1].tac, 0x0008);
            assert_eq!(tas[1].broadcast_plmns.len(), 2);
            assert_eq!(decoded.default_paging_drx, Some(PagingDrx::V256));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// An update that carries only a new name must decode with `supported_tas`
/// **absent**, not empty: the two mean different things to the MME (unchanged
/// vs. serves nothing), and conflating them erases the eNB's TA list.
#[test]
fn enb_configuration_update_absent_ta_list_is_not_an_empty_one() {
    let msg = EnbConfigurationUpdate {
        enb_name: Some("renamed-only".to_string()),
        supported_tas: None,
        default_paging_drx: None,
    };
    let bytes = build_enb_configuration_update(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::EnbConfigurationUpdate(decoded) => {
            assert_eq!(decoded.enb_name.as_deref(), Some("renamed-only"));
            assert!(
                decoded.supported_tas.is_none(),
                "an omitted SupportedTAs must stay None, never Some(vec![])"
            );
            assert!(decoded.default_paging_drx.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn enb_configuration_update_acknowledge_roundtrip() {
    let msg = EnbConfigurationUpdateAcknowledge {
        criticality_diagnostics: Some(CriticalityDiagnostics {
            procedure_code: Some(29),
            triggering_message: Some(triggering_message::INITIATING_MESSAGE),
            procedure_criticality: Some(0),
            ies: vec![IeCriticalityDiagnostics {
                ie_criticality: Criticality::Reject,
                ie_id: 64,
                type_of_error: TypeOfError::NotUnderstood,
            }],
        }),
    };
    let bytes = build_enb_configuration_update_acknowledge(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::EnbConfigurationUpdateAcknowledge(decoded) => {
            let diag = decoded
                .criticality_diagnostics
                .expect("diagnostics present");
            assert_eq!(diag.procedure_code, Some(29));
            assert_eq!(diag.ies.len(), 1);
            assert_eq!(diag.ies[0].ie_id, 64);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn enb_configuration_update_failure_roundtrip() {
    let msg = EnbConfigurationUpdateFailure {
        cause: Cause::Misc(CauseMisc::UnknownPlmn),
        time_to_wait: Some(TimeToWait::V20s),
        criticality_diagnostics: None,
    };
    let bytes = build_enb_configuration_update_failure(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::EnbConfigurationUpdateFailure(decoded) => {
            assert_eq!(decoded.cause, Cause::Misc(CauseMisc::UnknownPlmn));
            assert_eq!(decoded.time_to_wait, Some(TimeToWait::V20s));
            assert!(decoded.criticality_diagnostics.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn mme_configuration_update_roundtrip() {
    let msg = MmeConfigurationUpdate {
        mme_name: Some("mme02.nextgcore".to_string()),
        served_gummeis: Some(vec![ServedGummeiItem {
            served_plmns: vec![PLMN],
            served_group_ids: vec![0x0002],
            served_mmec_codes: vec![7],
        }]),
        relative_mme_capacity: Some(64),
    };
    let bytes = build_mme_configuration_update(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::MmeConfigurationUpdate(decoded) => {
            assert_eq!(decoded.mme_name.as_deref(), Some("mme02.nextgcore"));
            let gummeis = decoded.served_gummeis.expect("ServedGUMMEIs present");
            assert_eq!(gummeis.len(), 1);
            assert_eq!(gummeis[0].served_mmec_codes, vec![7]);
            assert_eq!(decoded.relative_mme_capacity, Some(64));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn mme_configuration_update_acknowledge_and_failure_roundtrip() {
    let ack_bytes =
        build_mme_configuration_update_acknowledge(&MmeConfigurationUpdateAcknowledge::default())
            .unwrap();
    assert!(matches!(
        decode_s1ap_pdu(&ack_bytes).unwrap(),
        S1apMessage::MmeConfigurationUpdateAcknowledge(_)
    ));

    let failure_bytes = build_mme_configuration_update_failure(&MmeConfigurationUpdateFailure {
        cause: Cause::Protocol(CauseProtocol::SemanticError),
        time_to_wait: None,
        criticality_diagnostics: None,
    })
    .unwrap();
    match decode_s1ap_pdu(&failure_bytes).unwrap() {
        S1apMessage::MmeConfigurationUpdateFailure(decoded) => {
            assert_eq!(decoded.cause, Cause::Protocol(CauseProtocol::SemanticError));
            assert!(decoded.time_to_wait.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// UE Context Modification (§9.1.4.8-9.1.4.10)
// ============================================================================

#[test]
fn ue_context_modification_request_roundtrip() {
    let msg = UeContextModificationRequest {
        mme_ue_s1ap_id: 0x0001_0203,
        enb_ue_s1ap_id: 0x0004_0506,
        security_key: Some([0x5A; 32]),
        subscriber_profile_id_for_rfp: Some(256),
        ue_ambr: Some(UeAmbr {
            dl: 1_000_000_000,
            ul: 500_000_000,
        }),
        cs_fallback_indicator: Some(CsFallbackIndicator::CsFallbackRequired),
        ue_security_capabilities: Some(UeSecurityCapabilities {
            encryption_algorithms: 0xE000,
            integrity_algorithms: 0xE000,
        }),
    };
    let bytes = build_ue_context_modification_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextModificationRequest(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 0x0001_0203);
            assert_eq!(decoded.enb_ue_s1ap_id, 0x0004_0506);
            assert_eq!(decoded.security_key, Some([0x5A; 32]));
            // The IE is INTEGER (1..256): the upper bound must survive.
            assert_eq!(decoded.subscriber_profile_id_for_rfp, Some(256));
            assert_eq!(decoded.ue_ambr.map(|a| a.dl), Some(1_000_000_000));
            assert_eq!(
                decoded.cs_fallback_indicator,
                Some(CsFallbackIndicator::CsFallbackRequired)
            );
            assert_eq!(
                decoded
                    .ue_security_capabilities
                    .map(|c| c.integrity_algorithms),
                Some(0xE000)
            );
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// Only the two mandatory IDs: every optional IE must come back absent rather
/// than defaulted, or a modification that changed nothing would look like one
/// that zeroed the UE's AMBR.
#[test]
fn ue_context_modification_request_minimal_roundtrip() {
    let msg = UeContextModificationRequest {
        mme_ue_s1ap_id: 9,
        enb_ue_s1ap_id: 10,
        security_key: None,
        subscriber_profile_id_for_rfp: None,
        ue_ambr: None,
        cs_fallback_indicator: None,
        ue_security_capabilities: None,
    };
    let bytes = build_ue_context_modification_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextModificationRequest(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 9);
            assert!(decoded.security_key.is_none());
            assert!(decoded.subscriber_profile_id_for_rfp.is_none());
            assert!(decoded.ue_ambr.is_none());
            assert!(decoded.cs_fallback_indicator.is_none());
            assert!(decoded.ue_security_capabilities.is_none());
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// `cs-fallback-high-priority` is an ASN.1 **extension addition**, so it is
/// encoded as extension index 0 rather than root value 1. Asserting both
/// variants is what distinguishes a correct extensible enumeration from one
/// that silently encodes the high-priority case as the required case.
#[test]
fn cs_fallback_indicator_extension_value_roundtrips_distinctly() {
    let mut required = None;
    let mut high_priority = None;
    for indicator in [
        CsFallbackIndicator::CsFallbackRequired,
        CsFallbackIndicator::CsFallbackHighPriority,
    ] {
        let bytes = build_ue_context_modification_request(&UeContextModificationRequest {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 2,
            security_key: None,
            subscriber_profile_id_for_rfp: None,
            ue_ambr: None,
            cs_fallback_indicator: Some(indicator),
            ue_security_capabilities: None,
        })
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextModificationRequest(decoded) => {
                assert_eq!(decoded.cs_fallback_indicator, Some(indicator));
            }
            other => panic!("unexpected message: {other:?}"),
        }
        match indicator {
            CsFallbackIndicator::CsFallbackRequired => required = Some(bytes),
            CsFallbackIndicator::CsFallbackHighPriority => high_priority = Some(bytes),
        }
    }
    assert_ne!(
        required.unwrap(),
        high_priority.unwrap(),
        "the two indicator values must differ on the wire"
    );
}

#[test]
fn ue_context_modification_response_and_failure_roundtrip() {
    let bytes = build_ue_context_modification_response(&UeContextModificationResponse {
        mme_ue_s1ap_id: 11,
        enb_ue_s1ap_id: 12,
        criticality_diagnostics: None,
    })
    .unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextModificationResponse(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 11);
            assert_eq!(decoded.enb_ue_s1ap_id, 12);
        }
        other => panic!("unexpected message: {other:?}"),
    }

    let bytes = build_ue_context_modification_failure(&UeContextModificationFailure {
        mme_ue_s1ap_id: 13,
        enb_ue_s1ap_id: 14,
        cause: Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable),
        criticality_diagnostics: None,
    })
    .unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::UeContextModificationFailure(decoded) => {
            assert_eq!(decoded.mme_ue_s1ap_id, 13);
            assert_eq!(
                decoded.cause,
                Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable)
            );
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

// ============================================================================
// Overload Start / Stop (§9.1.8.13-9.1.8.14)
// ============================================================================

/// Every Overload Action must round-trip, including the four that are ASN.1
/// extension additions (values 3..=6) rather than root values.
#[test]
fn overload_start_roundtrips_every_action_including_extensions() {
    for action in [
        OverloadAction::RejectNonEmergencyMoDt,
        OverloadAction::RejectRrcCrSignalling,
        OverloadAction::PermitEmergencySessionsAndMtOnly,
        OverloadAction::PermitHighPrioritySessionsAndMtOnly,
        OverloadAction::RejectDelayTolerantAccess,
        OverloadAction::PermitHighPrioritySessionsAndExceptionReportingAndMtOnly,
        OverloadAction::NotAcceptMoDataOrDelayTolerantAccessFromCpCiot,
    ] {
        let bytes = build_overload_start(&OverloadStart {
            overload_action: action,
        })
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::OverloadStart(decoded) => {
                assert_eq!(decoded.overload_action, action, "action {action:?}");
            }
            other => panic!("unexpected message for {action:?}: {other:?}"),
        }
    }
}

/// Overload Stop has no mandatory IE, so an empty container is conformant and
/// must decode rather than be rejected as malformed.
#[test]
fn overload_stop_roundtrip() {
    let bytes = build_overload_stop(&OverloadStop).unwrap();
    assert!(matches!(
        decode_s1ap_pdu(&bytes).unwrap(),
        S1apMessage::OverloadStop(_)
    ));
}

// ============================================================================
// PWS: Write-Replace Warning / Kill (§9.1.13)
// ============================================================================

fn sample_etws_warning() -> WriteReplaceWarningRequest {
    WriteReplaceWarningRequest {
        message_identifier: 0x1100, // ETWS earthquake (TS 23.041)
        serial_number: 0x3000,
        warning_area: Some(WarningAreaList::TrackingAreaListForWarning(vec![
            sample_tai(),
        ])),
        repetition_period: 4095,
        number_of_broadcast_request: 65535,
        warning_type: Some([0x00, 0x01]),
        warning_security_info: Some([0xAB; 50]),
        data_coding_scheme: Some(0x0F),
        warning_message_contents: Some(b"Earthquake. Take cover.".to_vec()),
        concurrent_warning_message_indicator: true,
    }
}

#[test]
fn write_replace_warning_request_roundtrip() {
    let msg = sample_etws_warning();
    let bytes = build_write_replace_warning_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::WriteReplaceWarningRequest(decoded) => {
            assert_eq!(decoded.message_identifier, 0x1100);
            assert_eq!(decoded.serial_number, 0x3000);
            assert_eq!(
                decoded.warning_area,
                Some(WarningAreaList::TrackingAreaListForWarning(vec![
                    sample_tai()
                ]))
            );
            // Both bounds of their constrained ranges must survive.
            assert_eq!(decoded.repetition_period, 4095);
            assert_eq!(decoded.number_of_broadcast_request, 65535);
            assert_eq!(decoded.warning_type, Some([0x00, 0x01]));
            assert_eq!(decoded.warning_security_info, Some([0xAB; 50]));
            assert_eq!(decoded.data_coding_scheme, Some(0x0F));
            assert_eq!(
                decoded.warning_message_contents.as_deref(),
                Some(b"Earthquake. Take cover.".as_slice())
            );
            assert!(decoded.concurrent_warning_message_indicator);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// A CMAS-style request with only the mandatory IEs and no warning area, which
/// per TS 23.041 means every cell the eNB serves.
#[test]
fn write_replace_warning_request_minimal_roundtrip() {
    let msg = WriteReplaceWarningRequest {
        message_identifier: 0x1112,
        serial_number: 0x0001,
        warning_area: None,
        repetition_period: 0,
        number_of_broadcast_request: 0,
        warning_type: None,
        warning_security_info: None,
        data_coding_scheme: None,
        warning_message_contents: None,
        concurrent_warning_message_indicator: false,
    };
    let bytes = build_write_replace_warning_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::WriteReplaceWarningRequest(decoded) => {
            assert_eq!(decoded.message_identifier, 0x1112);
            assert!(
                decoded.warning_area.is_none(),
                "no warning area means all cells, not an empty list"
            );
            assert_eq!(decoded.repetition_period, 0);
            assert!(!decoded.concurrent_warning_message_indicator);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// All three Warning Area List alternatives must round-trip: a CBC may target
/// cells, tracking areas, or emergency areas.
#[test]
fn warning_area_list_roundtrips_every_alternative() {
    let areas = [
        WarningAreaList::CellIdList(vec![sample_cgi(), sample_cgi()]),
        WarningAreaList::TrackingAreaListForWarning(vec![sample_tai()]),
        WarningAreaList::EmergencyAreaIdList(vec![[0x01, 0x02, 0x03], [0xFF, 0xFE, 0xFD]]),
    ];
    for area in areas {
        let bytes = build_kill_request(&KillRequest {
            message_identifier: 0x1100,
            serial_number: 1,
            warning_area: Some(area.clone()),
            kill_all_warning_messages: false,
        })
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::KillRequest(decoded) => {
                assert_eq!(decoded.warning_area, Some(area.clone()), "area {area:?}");
            }
            other => panic!("unexpected message for {area:?}: {other:?}"),
        }
    }
}

#[test]
fn write_replace_warning_response_roundtrip() {
    let msg = WriteReplaceWarningResponse {
        message_identifier: 0x1100,
        serial_number: 0x3000,
        broadcast_completed_area: Some(BroadcastCompletedAreaList::TaiBroadcast(vec![
            TaiBroadcastItem {
                tai: sample_tai(),
                completed_cells: vec![sample_cgi()],
            },
        ])),
        criticality_diagnostics: None,
    };
    let bytes = build_write_replace_warning_response(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::WriteReplaceWarningResponse(decoded) => {
            assert_eq!(decoded.message_identifier, 0x1100);
            assert_eq!(
                decoded.broadcast_completed_area,
                msg.broadcast_completed_area
            );
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn broadcast_completed_area_list_roundtrips_every_alternative() {
    let areas = [
        BroadcastCompletedAreaList::CellIdBroadcast(vec![sample_cgi()]),
        BroadcastCompletedAreaList::TaiBroadcast(vec![TaiBroadcastItem {
            tai: sample_tai(),
            completed_cells: vec![sample_cgi(), sample_cgi()],
        }]),
        BroadcastCompletedAreaList::EmergencyAreaIdBroadcast(vec![EmergencyAreaIdBroadcastItem {
            emergency_area_id: [0x0A, 0x0B, 0x0C],
            completed_cells: vec![sample_cgi()],
        }]),
    ];
    for area in areas {
        let bytes = build_write_replace_warning_response(&WriteReplaceWarningResponse {
            message_identifier: 1,
            serial_number: 2,
            broadcast_completed_area: Some(area.clone()),
            criticality_diagnostics: None,
        })
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::WriteReplaceWarningResponse(decoded) => {
                assert_eq!(
                    decoded.broadcast_completed_area,
                    Some(area.clone()),
                    "area {area:?}"
                );
            }
            other => panic!("unexpected message for {area:?}: {other:?}"),
        }
    }
}

#[test]
fn kill_request_roundtrip() {
    let msg = KillRequest {
        message_identifier: 0x1100,
        serial_number: 0x3000,
        warning_area: Some(WarningAreaList::CellIdList(vec![sample_cgi()])),
        kill_all_warning_messages: true,
    };
    let bytes = build_kill_request(&msg).unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::KillRequest(decoded) => {
            assert_eq!(decoded.message_identifier, 0x1100);
            assert_eq!(decoded.serial_number, 0x3000);
            assert_eq!(decoded.warning_area, msg.warning_area);
            assert!(decoded.kill_all_warning_messages);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

/// The cancelled area lists differ from the completed ones by carrying
/// `numberOfBroadcasts` per cell — how far the alert got before it was killed.
#[test]
fn kill_response_roundtrips_every_cancelled_alternative() {
    let cell = || CellIdCancelledItem {
        ecgi: sample_cgi(),
        number_of_broadcasts: 65535,
    };
    let areas = [
        BroadcastCancelledAreaList::CellIdCancelled(vec![cell()]),
        BroadcastCancelledAreaList::TaiCancelled(vec![TaiCancelledItem {
            tai: sample_tai(),
            cancelled_cells: vec![cell(), cell()],
        }]),
        BroadcastCancelledAreaList::EmergencyAreaIdCancelled(vec![EmergencyAreaIdCancelledItem {
            emergency_area_id: [0x11, 0x22, 0x33],
            cancelled_cells: vec![cell()],
        }]),
    ];
    for area in areas {
        let bytes = build_kill_response(&KillResponse {
            message_identifier: 0x1100,
            serial_number: 7,
            broadcast_cancelled_area: Some(area.clone()),
            criticality_diagnostics: None,
        })
        .unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::KillResponse(decoded) => {
                assert_eq!(decoded.message_identifier, 0x1100);
                assert_eq!(
                    decoded.broadcast_cancelled_area,
                    Some(area.clone()),
                    "area {area:?}"
                );
            }
            other => panic!("unexpected message for {area:?}: {other:?}"),
        }
    }
}

/// `WarningMessageContents ::= OCTET STRING (SIZE(1..9600))` — a zero-length
/// message is not encodable, and an over-long one must be refused rather than
/// silently truncated onto the wire.
#[test]
fn warning_message_contents_bounds_are_enforced() {
    let mut msg = sample_etws_warning();

    msg.warning_message_contents = Some(Vec::new());
    assert!(
        build_write_replace_warning_request(&msg).is_err(),
        "an empty warning message must be refused, not encoded as SIZE(0)"
    );

    msg.warning_message_contents = Some(vec![0x41; 9601]);
    assert!(
        build_write_replace_warning_request(&msg).is_err(),
        "a warning message over 9600 octets must be refused"
    );

    msg.warning_message_contents = Some(vec![0x41; 9600]);
    assert!(
        build_write_replace_warning_request(&msg).is_ok(),
        "exactly 9600 octets is the upper bound and must encode"
    );
}

/// The PWS area lists are bounded at 65535, not the 256 that bounds every E-RAB
/// list. Encoding one with more than 256 entries and reading it back proves the
/// list helpers are not using the E-RAB bound for their length determinant.
#[test]
fn warning_area_list_exceeds_the_erab_list_bound() {
    let cells: Vec<EutranCgi> = (0..300)
        .map(|i| EutranCgi {
            plmn_identity: PLMN,
            cell_identity: i,
        })
        .collect();
    let bytes = build_kill_request(&KillRequest {
        message_identifier: 0x1100,
        serial_number: 1,
        warning_area: Some(WarningAreaList::CellIdList(cells.clone())),
        kill_all_warning_messages: false,
    })
    .unwrap();
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::KillRequest(decoded) => match decoded.warning_area {
            Some(WarningAreaList::CellIdList(decoded_cells)) => {
                assert_eq!(decoded_cells.len(), 300);
                assert_eq!(decoded_cells, cells);
            }
            other => panic!("expected a cell-id list, got {other:?}"),
        },
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
        ProcedureCode::UE_CONTEXT_MODIFICATION,
        ProcedureCode::OVERLOAD_START,
        ProcedureCode::WRITE_REPLACE_WARNING,
        ProcedureCode::KILL,
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
        ProcedureCode::UE_CONTEXT_MODIFICATION,
        ProcedureCode::WRITE_REPLACE_WARNING,
        ProcedureCode::KILL,
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
        ProcedureCode::ENB_CONFIGURATION_UPDATE,
        ProcedureCode::MME_CONFIGURATION_UPDATE,
        ProcedureCode::UE_CONTEXT_MODIFICATION,
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

    // Both Configuration Updates and their Acknowledges are all-optional too
    // (TS 36.413 §9.1.8.7-9.1.8.11), as is Overload Stop (§9.1.8.14). Rejecting
    // an empty one of these would break a conformant peer that is only asking
    // us to re-confirm the configuration we already hold.
    assert!(matches!(
        decode_s1ap_pdu(&empty_initiating(ProcedureCode::ENB_CONFIGURATION_UPDATE)).unwrap(),
        S1apMessage::EnbConfigurationUpdate(_)
    ));
    assert!(matches!(
        decode_s1ap_pdu(&empty_initiating(ProcedureCode::MME_CONFIGURATION_UPDATE)).unwrap(),
        S1apMessage::MmeConfigurationUpdate(_)
    ));
    assert!(matches!(
        decode_s1ap_pdu(&empty_successful(ProcedureCode::ENB_CONFIGURATION_UPDATE)).unwrap(),
        S1apMessage::EnbConfigurationUpdateAcknowledge(_)
    ));
    assert!(matches!(
        decode_s1ap_pdu(&empty_successful(ProcedureCode::MME_CONFIGURATION_UPDATE)).unwrap(),
        S1apMessage::MmeConfigurationUpdateAcknowledge(_)
    ));
    assert!(matches!(
        decode_s1ap_pdu(&empty_initiating(ProcedureCode::OVERLOAD_STOP)).unwrap(),
        S1apMessage::OverloadStop(_)
    ));
}

/// A message that decodes through a typed PDU variant but is missing one
/// specific mandatory IE (not just all of them) must also be rejected.
#[test]
fn strict_reject_partially_populated_message() {
    // InitialUEMessage with only the eNB-UE-S1AP-ID (missing NAS-PDU, TAI, ...)
    let mut container = ProtocolIeContainer::new();
    nextgcore_s1ap::ie::encode_enb_ue_s1ap_id(&mut container, 1, Criticality::Reject).unwrap();
    let bytes = encode_raw_pdu(&S1apPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::INITIAL_UE_MESSAGE,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::InitialUeMessage(container),
    }));
    let err = decode_s1ap_pdu(&bytes).unwrap_err();
    assert!(err.to_string().contains("NAS-PDU"), "got: {err}");

    // UEContextReleaseCommand with cause but no UE-S1AP-IDs
    let mut container = ProtocolIeContainer::new();
    nextgcore_s1ap::ie::encode_cause(&mut container, &sample_cause()).unwrap();
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
    // TRACE START (§8.11.1) is a Class-2 procedure this codec does not model.
    // This test used to use WRITE-REPLACE WARNING for the same purpose; that
    // stopped being an unsupported code when #49 implemented it, so the stand-in
    // moved rather than the assertion.
    let bytes = empty_initiating(ProcedureCode::TRACE_START);
    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::Unknown {
            procedure_code,
            message_type,
        } => {
            assert_eq!(procedure_code, ProcedureCode::TRACE_START.0);
            assert_eq!(message_type, "InitiatingMessage");
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

proptest! {
    /// Decoding arbitrary bytes must never panic (the APER
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

/// Criticality Diagnostics survives a round trip (TS 36.413 §9.2.1.21).
///
/// The IE had no encoder at all before, so an Error Indication could never say
/// which procedure or which IEs a protocol error was about.
#[test]
fn error_indication_criticality_diagnostics_roundtrip() {
    use nextgcore_s1ap::{
        triggering_message, CriticalityDiagnostics, IeCriticalityDiagnostics, TypeOfError,
    };

    let diagnostics = CriticalityDiagnostics {
        procedure_code: Some(9),
        triggering_message: Some(triggering_message::INITIATING_MESSAGE),
        procedure_criticality: Some(0),
        ies: vec![
            IeCriticalityDiagnostics {
                ie_criticality: nextgcore_asn1c::s1ap::types::Criticality::Reject,
                ie_id: 8,
                type_of_error: TypeOfError::Missing,
            },
            IeCriticalityDiagnostics {
                ie_criticality: nextgcore_asn1c::s1ap::types::Criticality::Ignore,
                ie_id: 100,
                type_of_error: TypeOfError::NotUnderstood,
            },
        ],
    };

    let bytes = build_error_indication(&ErrorIndication {
        mme_ue_s1ap_id: Some(5),
        enb_ue_s1ap_id: Some(6),
        cause: Some(Cause::Protocol(CauseProtocol::AbstractSyntaxErrorReject)),
        criticality_diagnostics: Some(diagnostics.clone()),
    })
    .unwrap();

    match decode_s1ap_pdu(&bytes).unwrap() {
        S1apMessage::ErrorIndication(decoded) => {
            assert_eq!(decoded.criticality_diagnostics, Some(diagnostics));
        }
        other => panic!("expected ErrorIndication, got {other:?}"),
    }
}
