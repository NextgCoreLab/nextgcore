//! Input sweeps over the S1AP messages #514 stage 1 cross-checked (#514 stage
//! 13b). Until the hand-written codec was deleted these lived in
//! `nextgcore-s1ap-gen` and fed the hand-written builders' bytes to the
//! generated codec. Now the bytes come from `test_codec`'s builders, so each
//! case checks that the domain -> generated mapping yields a PDU the generated
//! codec decodes and re-encodes byte for byte with no IE reported unknown, and
//! (through `test_codec`'s checked builders) that messages mmed sends decode
//! back to their input.

use super::test_codec::builder::*;
use nextgcore_s1ap::cause::{Cause, CauseMisc, CauseNas, CauseRadioNetwork};
use nextgcore_s1ap::types::*;
use nextgcore_s1ap_gen::generated::S1AP_PDU;
use nextgcore_s1ap_gen::{decode, decode_with_unknown_ies, encode};

/// (outcome index, procedure code) of a decoded PDU.
fn shape(pdu: &S1AP_PDU) -> (u8, u8) {
    match pdu {
        S1AP_PDU::InitiatingMessage(m) => (0, m.procedure_code.0),
        S1AP_PDU::SuccessfulOutcome(m) => (1, m.procedure_code.0),
        S1AP_PDU::UnsuccessfulOutcome(m) => (2, m.procedure_code.0),
    }
}

fn round_trip(bytes: &[u8], expect: (u8, u8)) {
    let pdu = decode(bytes).unwrap_or_else(|e| panic!("generated decode failed: {e:?}"));
    assert_eq!(shape(&pdu), expect, "wrong CHOICE arm / procedure code");
    assert_eq!(encode(&pdu).unwrap(), bytes, "generated re-encode differs");
    let (again, unknown) = decode_with_unknown_ies(bytes).unwrap();
    assert_eq!(again, pdu);
    assert!(
        unknown.is_empty(),
        "a schema IE was reported unknown: {unknown:?}"
    );
}

const PLMN: [u8; 3] = [0x99, 0xf9, 0x07];

fn tai() -> Tai {
    Tai {
        plmn_identity: PLMN,
        tac: 1,
    }
}

fn cgi() -> EutranCgi {
    EutranCgi {
        plmn_identity: PLMN,
        cell_identity: 0x019B_0100,
    }
}

#[test]
fn s1_setup_messages_round_trip_over_a_sweep() {
    for name_len in [1usize, 2, 3, 40, 150] {
        for gummeis in 1..=3usize {
            let bytes = build_s1_setup_response(&S1SetupResponse {
                mme_name: Some("m".repeat(name_len)),
                served_gummeis: (0..gummeis)
                    .map(|i| ServedGummeiItem {
                        served_plmns: vec![PLMN; i + 1],
                        served_group_ids: vec![2, 0xFFFF],
                        served_mmec_codes: vec![1, 0xFF],
                    })
                    .collect(),
                relative_mme_capacity: u8::try_from(name_len % 256).unwrap(),
            })
            .unwrap();
            round_trip(&bytes, (1, 17));
        }
    }
    for cause in [
        Cause::Misc(CauseMisc::UnknownPlmn),
        Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        Cause::Nas(CauseNas::NormalRelease),
    ] {
        for ttw in [None, Some(TimeToWait::V1s), Some(TimeToWait::V60s)] {
            let bytes = build_s1_setup_failure(&S1SetupFailure {
                cause,
                time_to_wait: ttw,
            })
            .unwrap();
            round_trip(&bytes, (2, 17));
        }
    }
}

#[test]
fn nas_transport_round_trips_over_a_sweep() {
    // 16,000 is near the hand-written encoder's ceiling: it has no X.691
    // §11.9.3.8 fragmentation and refuses an open type past 16,383 octets (see
    // `the_generated_codec_carries_a_nas_pdu_past_16k`).
    for len in [1usize, 2, 127, 128, 255, 1000, 16_000] {
        let nas = vec![0x5A; len];
        for ids in [(0u32, 0u32), (1, 1), (0xFF_FFFF, 0xFFFF_FFFF)] {
            round_trip(
                &build_downlink_nas_transport(&DlNasTransport {
                    mme_ue_s1ap_id: ids.1,
                    enb_ue_s1ap_id: ids.0,
                    nas_pdu: nas.clone(),
                })
                .unwrap(),
                (0, 11),
            );
            round_trip(
                &build_uplink_nas_transport(&UlNasTransport {
                    mme_ue_s1ap_id: ids.1,
                    enb_ue_s1ap_id: ids.0,
                    nas_pdu: nas.clone(),
                    eutran_cgi: cgi(),
                    tai: tai(),
                })
                .unwrap(),
                (0, 13),
            );
        }
        for s_tmsi in [
            None,
            Some(STmsi {
                mmec: 1,
                m_tmsi: 0xDEAD_BEEF,
            }),
        ] {
            round_trip(
                &build_initial_ue_message(&InitialUeMessage {
                    enb_ue_s1ap_id: 7,
                    nas_pdu: nas.clone(),
                    tai: tai(),
                    eutran_cgi: cgi(),
                    rrc_establishment_cause: RrcEstablishmentCause::MoSignalling,
                    s_tmsi,
                })
                .unwrap(),
                (0, 12),
            );
        }
    }
}

#[test]
fn initial_context_setup_round_trips_over_a_sweep() {
    for erabs in 1..=3u8 {
        for gbr in [false, true] {
            for nas in [None, Some(vec![0x27, 0x01, 0x02])] {
                let bytes = build_initial_context_setup_request(&InitialContextSetupRequest {
                    mme_ue_s1ap_id: 1,
                    enb_ue_s1ap_id: 1,
                    ue_ambr: UeAmbr {
                        dl: 10_000_000_000,
                        ul: 1,
                    },
                    erab_list: (0..erabs)
                        .map(|i| ErabToBeSetupItem {
                            erab_id: 5 + i,
                            erab_qos: ErabLevelQosParameters {
                                qci: if gbr { 1 } else { 9 },
                                arp: AllocationRetentionPriority {
                                    priority_level: 15,
                                    pre_emption_capability: true,
                                    pre_emption_vulnerability: true,
                                },
                                gbr_qos_info: gbr.then_some(GbrQosInformation {
                                    erab_max_bitrate_dl: 1_000_000,
                                    erab_max_bitrate_ul: 500_000,
                                    erab_guaranteed_bitrate_dl: 64_000,
                                    erab_guaranteed_bitrate_ul: 64_000,
                                }),
                            },
                            transport_layer_address: vec![10, 0, 0, 1 + i],
                            gtp_teid: 0x1000 + u32::from(i),
                            nas_pdu: nas.clone(),
                        })
                        .collect(),
                    ue_security_capabilities: UeSecurityCapabilities {
                        encryption_algorithms: 0xE000,
                        integrity_algorithms: 0x6000,
                    },
                    security_key: [0xA5; 32],
                })
                .unwrap();
                round_trip(&bytes, (0, 9));
            }
        }
    }
}
