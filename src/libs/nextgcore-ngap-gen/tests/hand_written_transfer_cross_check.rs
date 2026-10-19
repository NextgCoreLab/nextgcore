//! #462: the hand-written PDU-session transfer codec (`nextgcore-ngap`'s
//! `transfer.rs`, the one the SMF builds and parses N2 SM transfers with)
//! against the generated codec, over the two members it used to get wrong:
//! the extensible PacketLossRate in GBR-QosInformation, and the Additional DL
//! QoS Flow per TNL Information list in the Setup and Modify Response
//! Transfers. Each case must encode to the same bytes in both codecs and
//! decode, in each, from the other's bytes.

use bitvec::prelude::*;
use nextgcore_ngap::transfer::{
    AllocationAndRetentionPriority, AssociatedQosFlowItem, GbrQosInformation, GtpTunnel,
    NonDynamic5qiDescriptor, PduSessionResourceModifyResponseTransfer,
    PduSessionResourceSetupRequestTransfer, PduSessionResourceSetupResponseTransfer,
    PduSessionType, PreEmptionCapability, PreEmptionVulnerability, QosCharacteristics,
    QosFlowLevelQosParameters, QosFlowPerTnlInformation, QosFlowSetupRequestItem,
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

fn per_tnl(address: [u8; 4], teid: u32, qfi: u8) -> QosFlowPerTnlInformation {
    QosFlowPerTnlInformation {
        up_transport_layer_information: tunnel(address, teid),
        associated_qos_flow_list: vec![AssociatedQosFlowItem {
            qos_flow_identifier: qfi,
            qos_flow_mapping_indication: None,
        }],
    }
}

fn g_per_tnl(address: [u8; 4], teid: u32, qfi: u8) -> g::QosFlowPerTNLInformation {
    g::QosFlowPerTNLInformation {
        up_transport_layer_information: g_tunnel(address, teid),
        associated_qos_flow_list: g::AssociatedQosFlowList(vec![g::AssociatedQosFlowItem {
            qos_flow_identifier: g::QosFlowIdentifier(qfi),
            qos_flow_mapping_indication: None,
            ie_extensions: None,
        }]),
        ie_extensions: None,
    }
}

fn g_list(items: Vec<g::QosFlowPerTNLInformation>) -> Option<g::QosFlowPerTNLInformationList> {
    (!items.is_empty()).then(|| {
        g::QosFlowPerTNLInformationList(
            items
                .into_iter()
                .map(
                    |qos_flow_per_tnl_information| g::QosFlowPerTNLInformationItem {
                        qos_flow_per_tnl_information,
                        ie_extensions: None,
                    },
                )
                .collect(),
        )
    })
}

/// 0..=3 additional DL tunnels on the Setup Response Transfer.
#[test]
fn setup_response_additional_dl_tunnels_agree() {
    for n in 0..=3u8 {
        let additional: Vec<_> = (0..n)
            .map(|i| ([10, 45, 1, i], 0x100 + u32::from(i), 1 + i))
            .collect();
        let hand = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: per_tnl([10, 45, 0, 3], 0xdead_beef, 9),
            additional_dl_qos_flow_per_tnl_information: additional
                .iter()
                .map(|&(a, t, q)| per_tnl(a, t, q))
                .collect(),
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        };
        let generated = g::PDUSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: g_per_tnl([10, 45, 0, 3], 0xdead_beef, 9),
            additional_dl_qos_flow_per_tnl_information: g_list(
                additional
                    .iter()
                    .map(|&(a, t, q)| g_per_tnl(a, t, q))
                    .collect(),
            ),
            security_result: None,
            qos_flow_failed_to_setup_list: None,
            ie_extensions: None,
        };
        let old = hand.encode().expect("hand-written encode");
        let new = encode_contained(&generated).expect("generated encode");
        assert_eq!(old, new, "{n} additional");
        assert_eq!(
            decode_contained::<g::PDUSessionResourceSetupResponseTransfer>(&old).expect("decode"),
            generated,
            "{n} additional"
        );
        assert_eq!(
            PduSessionResourceSetupResponseTransfer::decode(&new).expect("decode"),
            hand,
            "{n} additional"
        );
    }
}

/// 0..=3 additional DL tunnels on the Modify Response Transfer, alone and
/// after a DL tunnel.
#[test]
fn modify_response_additional_dl_tunnels_agree() {
    for with_dl in [false, true] {
        for n in 0..=3u8 {
            let additional: Vec<_> = (0..n)
                .map(|i| ([10, 45, 2, i], 0x200 + u32::from(i), 10 + i))
                .collect();
            let hand = PduSessionResourceModifyResponseTransfer {
                dl_ngu_up_tnl_information: with_dl.then(|| tunnel([10, 45, 0, 9], 7)),
                additional_dl_qos_flow_per_tnl_information: additional
                    .iter()
                    .map(|&(a, t, q)| per_tnl(a, t, q))
                    .collect(),
                ..Default::default()
            };
            let generated = g::PDUSessionResourceModifyResponseTransfer {
                dl_ngu_up_tnl_information: with_dl.then(|| g_tunnel([10, 45, 0, 9], 7)),
                ul_ngu_up_tnl_information: None,
                qos_flow_add_or_modify_response_list: None,
                additional_dl_qos_flow_per_tnl_information: g_list(
                    additional
                        .iter()
                        .map(|&(a, t, q)| g_per_tnl(a, t, q))
                        .collect(),
                ),
                qos_flow_failed_to_add_or_modify_list: None,
                ie_extensions: None,
            };
            let old = hand.encode().expect("hand-written encode");
            let new = encode_contained(&generated).expect("generated encode");
            assert_eq!(old, new, "dl {with_dl}, {n} additional");
            assert_eq!(
                PduSessionResourceModifyResponseTransfer::decode(&new).expect("decode"),
                hand,
                "dl {with_dl}, {n} additional"
            );
        }
    }
}

/// A GBR flow with PacketLossRate at the root's bounds and either side of an
/// octet boundary, DL and UL, with and without Notification Control, inside a
/// Setup Request Transfer.
#[test]
fn packet_loss_rates_agree_in_a_setup_request_transfer() {
    let rates = [
        None,
        Some(0u16),
        Some(1),
        Some(255),
        Some(256),
        Some(999),
        Some(1000),
    ];
    let mut cases = 0;
    for dl in rates {
        for ul in rates {
            for notification_control in [false, true] {
                let gbr = GbrQosInformation {
                    maximum_flow_bit_rate_dl: 128_000,
                    maximum_flow_bit_rate_ul: 64_000,
                    guaranteed_flow_bit_rate_dl: 64_000,
                    guaranteed_flow_bit_rate_ul: 0,
                    notification_control,
                    maximum_packet_loss_rate_dl: dl,
                    maximum_packet_loss_rate_ul: ul,
                };
                let hand = PduSessionResourceSetupRequestTransfer {
                    pdu_session_aggregate_maximum_bit_rate: None,
                    ul_ngu_up_tnl_information: tunnel([10, 45, 0, 1], 0x1234),
                    data_forwarding_not_possible: false,
                    pdu_session_type: PduSessionType::Ipv4,
                    security_indication: None,
                    network_instance: None,
                    qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
                        qos_flow_identifier: 1,
                        qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                            qos_characteristics: QosCharacteristics::NonDynamic5qi(
                                NonDynamic5qiDescriptor::new(1),
                            ),
                            allocation_and_retention_priority: AllocationAndRetentionPriority {
                                priority_level_arp: 2,
                                pre_emption_capability:
                                    PreEmptionCapability::ShallNotTriggerPreEmption,
                                pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                            },
                            gbr_qos_information: Some(gbr),
                            reflective_qos_attribute: false,
                            additional_qos_flow_information: false,
                        },
                        e_rab_id: None,
                    }],
                };
                let old = hand.encode().expect("hand-written encode");
                // The generated decoder reads the hand-written bytes to the
                // same loss rates, and re-encodes them byte for byte.
                let generated = decode_contained::<g::PDUSessionResourceSetupRequestTransfer>(&old)
                    .expect("generated decode");
                assert_eq!(
                    encode_contained(&generated).expect("encode"),
                    old,
                    "{dl:?} {ul:?}"
                );
                let qos = generated
                    .protocol_i_es
                    .0
                    .iter()
                    .find_map(|ie| match &ie.value {
                        g::PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_QosFlowSetupRequestList(l) => Some(l),
                        _ => None,
                    })
                    .expect("QosFlowSetupRequestList");
                let g_gbr = qos.0[0]
                    .qos_flow_level_qos_parameters
                    .gbr_qos_information
                    .as_ref()
                    .expect("GBR");
                assert_eq!(g_gbr.maximum_packet_loss_rate_dl.as_ref().map(|r| r.0), dl);
                assert_eq!(g_gbr.maximum_packet_loss_rate_ul.as_ref().map(|r| r.0), ul);
                assert_eq!(
                    PduSessionResourceSetupRequestTransfer::decode(&old).expect("decode"),
                    hand
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 7 * 7 * 2);
}
