//! #417 stage B: plain-value reads of the transfers smfd sends, for the
//! handler tests that used to decode them with the hand-written
//! `nextgcore-ngap` codec. Strict generated decode (an unknown IE fails the
//! read), then only the members those tests assert on. The bytes themselves
//! are pinned by `golden_tests.rs`; these views let a handler test say which
//! session values reached the transfer.

use super::{endpoint, DlEndpoint};
use nextgcore_ngap_gen::generated as g;

/// One QosFlowLevelQosParameters, as numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowQos {
    /// `None` for a Dynamic 5QI descriptor.
    pub five_qi: Option<u8>,
    pub priority_level_arp: u8,
    pub may_trigger_pre_emption: bool,
    pub pre_emptable: bool,
    /// (MFBR DL, MFBR UL, GFBR DL, GFBR UL).
    pub gbr: Option<(u64, u64, u64, u64)>,
}

fn flow_qos(q: &g::QosFlowLevelQosParameters) -> FlowQos {
    let arp = &q.allocation_and_retention_priority;
    FlowQos {
        five_qi: match &q.qos_characteristics {
            g::QosCharacteristics::NonDynamic5QI(d) => Some(d.five_qi.0),
            _ => None,
        },
        priority_level_arp: arp.priority_level_arp.0,
        may_trigger_pre_emption: arp.pre_emption_capability.0
            == g::Pre_emptionCapability::MAY_TRIGGER_PRE_EMPTION,
        pre_emptable: arp.pre_emption_vulnerability.0 == g::Pre_emptionVulnerability::PRE_EMPTABLE,
        gbr: q.gbr_qos_information.as_ref().map(|b| {
            (
                b.maximum_flow_bit_rate_dl.0,
                b.maximum_flow_bit_rate_ul.0,
                b.guaranteed_flow_bit_rate_dl.0,
                b.guaranteed_flow_bit_rate_ul.0,
            )
        }),
    }
}

fn ambr(a: &g::PDUSessionAggregateMaximumBitRate) -> (u64, u64) {
    (
        a.pdu_session_aggregate_maximum_bit_rate_dl.0,
        a.pdu_session_aggregate_maximum_bit_rate_ul.0,
    )
}

/// A PDUSessionResourceSetupRequestTransfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupRequestView {
    pub ambr: Option<(u64, u64)>,
    pub ul: DlEndpoint,
    /// (QFI, its QoS, E-RAB ID) per flow, in order.
    pub flows: Vec<(u8, FlowQos, Option<u8>)>,
    pub data_forwarding_not_possible: bool,
    pub direct_forwarding_path_availability: bool,
}

impl SetupRequestView {
    pub(crate) fn qfis(&self) -> Vec<u8> {
        self.flows.iter().map(|f| f.0).collect()
    }
}

pub(crate) fn setup_request(bytes: &[u8]) -> SetupRequestView {
    use g::PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie;
    let t =
        nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceSetupRequestTransfer>(bytes)
            .expect("a PDUSessionResourceSetupRequestTransfer");
    let mut v = SetupRequestView {
        ambr: None,
        ul: DlEndpoint {
            teid: 0,
            address: Vec::new(),
            bit_len: 0,
            qfis: Vec::new(),
        },
        flows: Vec::new(),
        data_forwarding_not_possible: false,
        direct_forwarding_path_availability: false,
    };
    for ie in t.protocol_i_es.0 {
        match ie.value {
            Ie::Id_PDUSessionAggregateMaximumBitRate(a) => v.ambr = Some(ambr(&a)),
            Ie::Id_UL_NGU_UP_TNLInformation(t) => {
                v.ul = endpoint("view", t, Vec::new()).expect("a GTP tunnel")
            }
            Ie::Id_DataForwardingNotPossible(_) => v.data_forwarding_not_possible = true,
            Ie::Id_DirectForwardingPathAvailability(_) => {
                v.direct_forwarding_path_availability = true
            }
            Ie::Id_QosFlowSetupRequestList(l) => {
                v.flows =
                    l.0.iter()
                        .map(|f| {
                            (
                                f.qos_flow_identifier.0,
                                flow_qos(&f.qos_flow_level_qos_parameters),
                                f.e_rab_id.as_ref().map(|e| e.0),
                            )
                        })
                        .collect()
            }
            _ => {}
        }
    }
    v
}

/// A PDUSessionResourceModifyRequestTransfer: the Session-AMBR and, per added
/// or modified flow, its QFI and QoS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModifyRequestView {
    pub ambr: Option<(u64, u64)>,
    pub flows: Vec<(u8, Option<FlowQos>)>,
}

pub(crate) fn modify_request(bytes: &[u8]) -> ModifyRequestView {
    use g::PDUSessionResourceModifyRequestTransferProtocolIEs_EntryValue as Ie;
    let t =
        nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceModifyRequestTransfer>(bytes)
            .expect("a PDUSessionResourceModifyRequestTransfer");
    let mut v = ModifyRequestView {
        ambr: None,
        flows: Vec::new(),
    };
    for ie in t.protocol_i_es.0 {
        match ie.value {
            Ie::Id_PDUSessionAggregateMaximumBitRate(a) => v.ambr = Some(ambr(&a)),
            Ie::Id_QosFlowAddOrModifyRequestList(l) => {
                v.flows =
                    l.0.iter()
                        .map(|f| {
                            (
                                f.qos_flow_identifier.0,
                                f.qos_flow_level_qos_parameters.as_ref().map(flow_qos),
                            )
                        })
                        .collect()
            }
            _ => {}
        }
    }
    v
}

/// A PDUSessionResourceModifyConfirmTransfer: the confirmed QFIs and the UL
/// tunnel.
pub(crate) fn modify_confirm(bytes: &[u8]) -> (Vec<u8>, DlEndpoint) {
    let t =
        nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceModifyConfirmTransfer>(bytes)
            .expect("a PDUSessionResourceModifyConfirmTransfer");
    (
        t.qos_flow_modify_confirm_list
            .0
            .iter()
            .map(|f| f.qos_flow_identifier.0)
            .collect(),
        endpoint("view", t.ulngu_up_tnl_information, Vec::new()).expect("a GTP tunnel"),
    )
}
