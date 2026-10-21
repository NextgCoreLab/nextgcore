//! #475: the hand-written HandoverRequestAcknowledgeTransfer (TS 38.413 §9.3.4.11) — what
//! smfd reads the target NG-RAN's DL N3 endpoint from in a PREPARED update — and the
//! PDUSessionResourceSetupRequestTransfer's DirectForwardingPathAvailability, against the
//! generated codec. Each case must be byte-identical in both codecs.

use bitvec::prelude::*;
use nextgcore_ngap::transfer::{
    AllocationAndRetentionPriority, GtpTunnel, HandoverRequestAcknowledgeTransfer,
    NonDynamic5qiDescriptor, PduSessionResourceSetupRequestTransfer, PduSessionType,
    PreEmptionCapability, PreEmptionVulnerability, QosCharacteristics,
    QosFlowItemWithDataForwarding, QosFlowLevelQosParameters, QosFlowSetupRequestItem,
    TransportLayerAddress, UpTransportLayerInformation,
};
use nextgcore_ngap_gen::generated as g;
use nextgcore_ngap_gen::{decode_contained, encode_contained};

fn tunnel(address: [u8; 4], teid: u32) -> UpTransportLayerInformation {
    UpTransportLayerInformation::GtpTunnel(GtpTunnel {
        transport_layer_address: TransportLayerAddress::from_ipv4(address),
        gtp_teid: teid.to_be_bytes(),
    })
}

fn g_tunnel(address: [u8; 4], teid: u32) -> g::UPTransportLayerInformation {
    let bits: BitVec<u8, Msb0> = BitVec::from_slice(&address);
    g::UPTransportLayerInformation::GTPTunnel(g::GTPTunnel {
        transport_layer_address: g::TransportLayerAddress(bits),
        gtp_teid: g::GTP_TEID(teid.to_be_bytes().to_vec()),
        ie_extensions: None,
    })
}

#[test]
fn handover_request_acknowledge_transfer_matches_the_generated_codec() {
    for (forward, flows) in [(false, vec![5u8]), (true, vec![5, 6, 63])] {
        let hand = HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: tunnel([10, 1, 2, 3], 0xABCD),
            dl_forwarding_up_tnl_information: forward.then(|| tunnel([10, 9, 9, 9], 7)),
            security_result: None,
            qos_flow_setup_response_list: flows
                .iter()
                .map(|&qfi| QosFlowItemWithDataForwarding {
                    qos_flow_identifier: qfi,
                    data_forwarding_accepted: forward,
                })
                .collect(),
            qos_flow_failed_to_setup_list: Vec::new(),
            data_forwarding_response_drb_list: Vec::new(),
        };
        let generated = g::HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: g_tunnel([10, 1, 2, 3], 0xABCD),
            dl_forwarding_up_tnl_information: forward.then(|| g_tunnel([10, 9, 9, 9], 7)),
            security_result: None,
            qos_flow_setup_response_list: g::QosFlowListWithDataForwarding(
                flows
                    .iter()
                    .map(|&qfi| g::QosFlowItemWithDataForwarding {
                        qos_flow_identifier: g::QosFlowIdentifier(qfi),
                        data_forwarding_accepted: forward.then_some(g::DataForwardingAccepted(
                            g::DataForwardingAccepted::DATA_FORWARDING_ACCEPTED,
                        )),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
            qos_flow_failed_to_setup_list: None,
            data_forwarding_response_drb_list: None,
            ie_extensions: None,
        };
        let hand_bytes = hand.encode().unwrap();
        assert_eq!(
            hand_bytes,
            encode_contained(&generated).unwrap(),
            "forwarding={forward}, flows={flows:?}"
        );
        // The generated codec reads the hand-written bytes, and the hand-written decoder
        // reads the generated codec's.
        let back = decode_contained::<g::HandoverRequestAcknowledgeTransfer>(&hand_bytes).unwrap();
        assert_eq!(back.qos_flow_setup_response_list.0.len(), flows.len());
        assert_eq!(
            HandoverRequestAcknowledgeTransfer::decode(&encode_contained(&generated).unwrap())
                .unwrap(),
            hand
        );
    }
}

#[test]
fn direct_forwarding_path_availability_matches_the_generated_codec() {
    let hand = PduSessionResourceSetupRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: None,
        ul_ngu_up_tnl_information: tunnel([10, 45, 0, 1], 0x3475),
        data_forwarding_not_possible: false,
        pdu_session_type: PduSessionType::Ipv4,
        security_indication: None,
        network_instance: None,
        qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
            qos_flow_identifier: 5,
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(
                    NonDynamic5qiDescriptor::new(9),
                ),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: 8,
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_information: None,
                reflective_qos_attribute: false,
                additional_qos_flow_information: false,
            },
            e_rab_id: Some(5),
        }],
        direct_forwarding_path_availability: true,
    };
    let bytes = hand.encode().unwrap();
    let decoded = decode_contained::<g::PDUSessionResourceSetupRequestTransfer>(&bytes).unwrap();
    let ies = &decoded.protocol_i_es.0;
    let has = |want: u16| ies.iter().any(|ie| ie.id.0 == want);
    assert!(
        has(22),
        "IE 22 DirectForwardingPathAvailability reaches the generated codec"
    );
    let dfpa = ies.iter().find(|ie| ie.id.0 == 22).unwrap();
    assert_eq!(dfpa.criticality.0, g::Criticality::IGNORE);
    // And the generated codec re-encodes the same octets.
    assert_eq!(encode_contained(&decoded).unwrap(), bytes);
}
