//! The N2 SM transfers amfd's tests build or read, the Initial Context Setup
//! Request amfd sends, and the framing helpers they need past 16K octets --
//! each derived by hand from `ngap-17.9.asn` and X.691 ALIGNED (see
//! [`crate::amf_pdus`] and [`crate::aper_golden`] for the shared layout
//! facts). Nothing here is taken from an encoder: each function writes the
//! bits its doc comment derives.
//!
//! Integer widths used below (X.691 §11.5.7, ALIGNED; a `...` in the
//! constraint adds a leading extension bit `0` for a root value, §13.2.1):
//! - range <= 255: the fewest bits that hold range-1, not aligned
//!   (PriorityLevelQos `1..127` 7 bits, pERScalar/pERExponent `0..9` 4 bits,
//!   E-RAB-ID `0..15` 4 bits, QosFlowIdentifier `0..63` 6 bits,
//!   PriorityLevelARP `1..15` 4 bits);
//! - range exactly 256: one aligned octet (FiveQI `0..255`, NetworkInstance
//!   `1..256` as n-1, PDUSessionID `0..255`);
//! - range 257..65536: two aligned octets (AveragingWindow and the
//!   MaximumDataBurstVolume root `0..4095`, PacketDelayBudget `0..1023`,
//!   PacketLossRate `0..1000`).

use crate::aper_golden::{amf_ue_ngap_id, ran_ue_ngap_id, Bits};
use nextgcore_ngap::types as t;

/// Run `f` on a fresh sink and return its complete encoding (§11.1: padded to
/// an octet).
pub(crate) fn encoding(f: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut b = Bits::default();
    f(&mut b);
    b.finish()
}

/// An unconstrained length determinant and its octets, fragmented past 16K
/// (X.691 §11.9.3.8, ALIGNED so the determinant is octet-aligned):
/// - below 16384 octets: [`Bits::open`] (`0xxxxxxx` below 128, `10xxxxxx
///   xxxxxxxx` below 16384);
/// - otherwise, while 16384 or more remain: one octet `11` + m in six bits,
///   m the number of 16K blocks in this fragment, as many as fit and at most
///   4, then those m x 16384 octets; then the remainder with its own
///   determinant as above, a remainder of zero included, written `00`: a
///   length that is a multiple of 16K still ends in a final, empty part.
pub(crate) fn open_any(b: &mut Bits, inner: &[u8]) {
    const K16: usize = 16 * 1024;
    let mut rest = inner;
    while rest.len() >= K16 {
        let m = (rest.len() / K16).min(4);
        b.octets(&[0xC0 | m as u8]);
        b.octets(&rest[..m * K16]);
        rest = &rest[m * K16..];
    }
    b.open(rest);
}

/// An NGAP-PDU as [`crate::aper_golden::pdu`] writes it, but with every open
/// type and the message value through [`open_any`], so any length frames.
pub(crate) fn pdu_any(
    choice: u64,
    procedure: u8,
    criticality: u8,
    ies: &[(u16, u8, Vec<u8>)],
) -> Vec<u8> {
    let value = encoding(|v| {
        v.bit(false).octets(&(ies.len() as u16).to_be_bytes());
        for (id, c, value) in ies {
            v.octets(&id.to_be_bytes()).field(u64::from(*c), 2);
            open_any(v, value);
        }
    });
    encoding(|b| {
        b.bit(false)
            .field(choice, 2)
            .octets(&[procedure])
            .field(u64::from(criticality), 2);
        open_any(b, &value);
    })
}

/// The vendored schema, the one the generated codec is compiled from.
const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../libs/nextgcore-ngap-gen/asn/ngap-17.9.asn"
));

/// The root and extension-addition identifiers of `ENUMERATED` type `name`,
/// read off the schema text in declaration order.
fn enumerated(name: &str) -> (Vec<String>, Vec<String>) {
    let head = format!("\n{name} ::= ENUMERATED {{");
    let start = SCHEMA.find(&head).expect("type in the schema") + head.len();
    let body = &SCHEMA[start..start + SCHEMA[start..].find('}').expect("closing brace")];
    let (mut root, mut additions, mut past_marker) = (Vec::new(), Vec::new(), false);
    for item in body.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if item == "..." {
            past_marker = true;
        } else if past_marker {
            additions.push(item.to_string());
        } else {
            root.push(item.to_string());
        }
    }
    (root, additions)
}

/// An ASN.1 identifier or a Rust variant name, compared without case and
/// hyphens. The schema spells one CauseRadioNetwork value `unkown-qos-flow-ID`
/// (sic); the domain type names it `UnknownQosFlowId`.
fn normalised(name: &str) -> String {
    name.replace('-', "")
        .to_ascii_lowercase()
        .replace("unkownqos", "unknownqos")
}

/// A domain Cause as (choice index, ENUMERATED type name, variant name).
fn cause_parts(c: &t::Cause) -> (u8, &'static str, String) {
    match c {
        t::Cause::RadioNetwork(v) => (0, "CauseRadioNetwork", format!("{v:?}")),
        t::Cause::Transport(v) => (1, "CauseTransport", format!("{v:?}")),
        t::Cause::Nas(v) => (2, "CauseNas", format!("{v:?}")),
        t::Cause::Protocol(v) => (3, "CauseProtocol", format!("{v:?}")),
        t::Cause::Misc(v) => (4, "CauseMisc", format!("{v:?}")),
    }
}

/// A Cause (§9.3.1.2), any group and value. CHOICE of six, not extensible
/// (choice-Extensions is a root alternative): three bits. The group's
/// ENUMERATED, extensible: a root value is extension `0` + its index in the
/// fewest bits that hold the root count (radioNetwork 45 -> 6, transport 2
/// -> 1, nas 4 -> 2, protocol 7 -> 3, misc 6 -> 3); an extension addition is
/// extension `1` + its addition index as a normally small number, `0` + six
/// bits (§11.6.1, §14.3). The index is the value's position in the schema's
/// list, found by name, so nothing depends on the domain enum's discriminants.
pub(crate) fn cause(b: &mut Bits, c: &t::Cause) {
    let (choice, type_name, variant) = cause_parts(c);
    let (root, additions) = enumerated(type_name);
    let find = |list: &[String]| {
        list.iter()
            .position(|n| normalised(n) == normalised(&variant))
    };
    b.field(u64::from(choice), 3);
    if let Some(i) = find(&root) {
        let width = usize::BITS - (root.len() - 1).leading_zeros();
        b.bit(false).field(i as u64, width);
    } else {
        let i = find(&additions).unwrap_or_else(|| panic!("{variant} not in {type_name}"));
        b.bit(true).bit(false).field(i as u64, 6);
    }
}

/// [`cause`] as a whole value.
pub(crate) fn cause_value(c: &t::Cause) -> Vec<u8> {
    encoding(|b| cause(b, c))
}

/// The (group, number) the production decoder reports for a Cause: the
/// choice index and the value's position in the schema's list, root then
/// additions continuing the count, found by name as in [`cause`].
pub(crate) fn cause_numbers(c: &t::Cause) -> (u8, i64) {
    let (group, type_name, variant) = cause_parts(c);
    let (root, additions) = enumerated(type_name);
    let index = root
        .iter()
        .chain(additions.iter())
        .position(|n| normalised(n) == normalised(&variant))
        .unwrap_or_else(|| panic!("{variant} not in {type_name}"));
    (group, index as i64)
}

/// BitRate `INTEGER (0..4000000000000, ...)`, a root value: extension `0`,
/// the octet count n (1..6, since 4e12 < 2^42) as n-1 in three bits (the
/// count range 1..6), then the value in its minimal n octets, aligned
/// (§11.5.7.4, §13.2.6). A value past the root is not derived.
pub(crate) const BIT_RATE_MAX: u64 = 4_000_000_000_000;
pub(crate) fn bit_rate(b: &mut Bits, v: u64) {
    assert!(
        v <= BIT_RATE_MAX,
        "a BitRate extension value is not derived"
    );
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    b.bit(false)
        .field((8 - skip) as u64 - 1, 3)
        .octets(&be[skip..]);
}

/// A GTP tunnel endpoint: `bits` address bits taken MSB first from `address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tunnel {
    pub address: Vec<u8>,
    pub bits: usize,
    pub teid: u32,
}

/// UPTransportLayerInformation (§9.3.2.2), gTPTunnel: CHOICE of two, not
/// extensible, index `0`; GTPTunnel extension `0`, iE-Extensions `0`;
/// TransportLayerAddress `BIT STRING (SIZE(1..160, ...))`: size extension
/// `0`, length-1 in eight bits (range 160), then the bits, octet-aligned
/// whatever their number (§16.11); GTP-TEID `OCTET STRING (SIZE(4))`, fixed
/// and longer than two octets, so aligned with no length (§17.6).
pub(crate) fn tunnel(b: &mut Bits, t: &Tunnel) {
    assert!((1..=160).contains(&t.bits));
    b.bit(false).bit(false).bit(false);
    b.bit(false).field(t.bits as u64 - 1, 8).align();
    for i in 0..t.bits {
        b.bit(t.address[i / 8] & (0x80 >> (i % 8)) != 0);
    }
    b.octets(&t.teid.to_be_bytes());
}

/// QosCharacteristics (§9.3.1.12): CHOICE of three, not extensible, two bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Qos {
    /// `00` NonDynamic5QIDescriptor: extension `0`, presence priorityLevelQos,
    /// averagingWindow, maximumDataBurstVolume, iE-Extensions `0`; FiveQI;
    /// then the present optionals in that order.
    NonDynamic {
        five_qi: u8,
        priority: Option<u8>,
        window: Option<u16>,
        burst: Option<u16>,
    },
    /// `01` Dynamic5QIDescriptor: extension `0`, presence fiveQI,
    /// delayCritical, averagingWindow, maximumDataBurstVolume, iE-Extensions
    /// `0`; PriorityLevelQos; PacketDelayBudget; PacketErrorRate (extension
    /// `0`, iE-Extensions `0`, scalar and exponent each extension `0` + four
    /// bits); then the optionals. `delay_critical` is the DelayCritical
    /// index: 0 delay-critical, 1 non-delay-critical (extension `0` + one
    /// bit).
    Dynamic {
        priority: u8,
        delay_budget: u16,
        per_scalar: u8,
        per_exponent: u8,
        five_qi: Option<u8>,
        delay_critical: Option<u8>,
        window: Option<u16>,
        burst: Option<u16>,
    },
}

/// GBR-QosInformation (§9.3.1.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gbr {
    pub mfbr_dl: u64,
    pub mfbr_ul: u64,
    pub gfbr_dl: u64,
    pub gfbr_ul: u64,
    pub notification: bool,
    pub loss_dl: Option<u16>,
    pub loss_ul: Option<u16>,
}

/// One QosFlowSetupRequestItem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Flow {
    pub qfi: u8,
    pub qos: Qos,
    pub arp: u8,
    pub may_trigger_pre_emption: bool,
    pub pre_emptable: bool,
    pub gbr: Option<Gbr>,
    pub reflective: bool,
    pub additional: bool,
    pub e_rab_id: Option<u8>,
}

/// SecurityIndication (§9.3.1.27) by ENUMERATED index: integrity and
/// confidentiality 0 required, 1 preferred, 2 not-needed; the UL rate 0
/// bitrate64kbs, 1 maximum-UE-rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Security {
    pub integrity: u8,
    pub confidentiality: u8,
    pub max_rate_ul: Option<u8>,
}

/// A PDUSessionResourceSetupRequestTransfer (§9.3.4.1). `pdu_session_type`
/// is the PDUSessionType index: 0 ipv4, 1 ipv6, 2 ipv4v6, 3 ethernet, 4
/// unstructured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupRequestTransfer {
    pub ambr: Option<(u64, u64)>,
    pub ul: Tunnel,
    pub data_forwarding_not_possible: bool,
    pub pdu_session_type: u8,
    pub security: Option<Security>,
    pub network_instance: Option<u16>,
    pub flows: Vec<Flow>,
}

/// Extension `0` then a two-aligned-octet value: AveragingWindow,
/// MaximumDataBurstVolume (root), PacketDelayBudget, PacketLossRate.
fn two_octet_ext(b: &mut Bits, v: u16) {
    b.bit(false).octets(&v.to_be_bytes());
}

/// Extension `0` then one aligned octet: FiveQI.
fn five_qi(b: &mut Bits, v: u8) {
    b.bit(false).octets(&[v]);
}

/// Extension `0` then priority-1 in seven bits: PriorityLevelQos `1..127`.
fn priority_qos(b: &mut Bits, p: u8) {
    assert!((1..=127).contains(&p));
    b.bit(false).field(u64::from(p) - 1, 7);
}

/// MaximumDataBurstVolume `INTEGER (0..4095, ..., 4096..2000000)`, a root
/// value: as [`two_octet_ext`].
fn burst_volume(b: &mut Bits, v: u16) {
    assert!(v <= 4095, "a burst volume past the root is not derived");
    two_octet_ext(b, v);
}

/// QosFlowLevelQosParameters (§9.3.1.12): extension `0`; presence
/// gBR-QosInformation, reflectiveQosAttribute, additionalQosFlowInformation,
/// iE-Extensions `0`; [`Qos`]; AllocationAndRetentionPriority (extension
/// `0`, iE-Extensions `0`, PriorityLevelARP `INTEGER (1..15)` level-1 in
/// four bits, NOT extensible; Pre-emptionCapability and
/// Pre-emptionVulnerability each extension `0` + one bit);
/// GBR-QosInformation (extension `0`; presence notificationControl,
/// maximumPacketLossRateDL/UL, iE-Extensions `0`; four BitRates;
/// NotificationControl `ENUMERATED {notification-requested, ...}` is its
/// extension bit alone, a one-value root taking no index bits; the loss
/// rates); ReflectiveQosAttribute and AdditionalQosFlowInformation, one-value
/// roots, the extension bit alone.
fn qos_parameters(b: &mut Bits, f: &Flow) {
    b.bit(false)
        .bit(f.gbr.is_some())
        .bit(f.reflective)
        .bit(f.additional)
        .bit(false);
    match &f.qos {
        Qos::NonDynamic {
            five_qi: q,
            priority,
            window,
            burst,
        } => {
            b.field(0, 2)
                .bit(false)
                .bit(priority.is_some())
                .bit(window.is_some())
                .bit(burst.is_some())
                .bit(false);
            five_qi(b, *q);
            if let Some(p) = priority {
                priority_qos(b, *p);
            }
            if let Some(w) = window {
                two_octet_ext(b, *w);
            }
            if let Some(v) = burst {
                burst_volume(b, *v);
            }
        }
        Qos::Dynamic {
            priority,
            delay_budget,
            per_scalar,
            per_exponent,
            five_qi: q,
            delay_critical,
            window,
            burst,
        } => {
            b.field(1, 2)
                .bit(false)
                .bit(q.is_some())
                .bit(delay_critical.is_some())
                .bit(window.is_some())
                .bit(burst.is_some())
                .bit(false);
            priority_qos(b, *priority);
            two_octet_ext(b, *delay_budget);
            b.bit(false).bit(false);
            b.bit(false).field(u64::from(*per_scalar), 4);
            b.bit(false).field(u64::from(*per_exponent), 4);
            if let Some(q) = q {
                five_qi(b, *q);
            }
            if let Some(d) = delay_critical {
                b.bit(false).field(u64::from(*d), 1);
            }
            if let Some(w) = window {
                two_octet_ext(b, *w);
            }
            if let Some(v) = burst {
                burst_volume(b, *v);
            }
        }
    }
    b.bit(false)
        .bit(false)
        .field(u64::from(f.arp) - 1, 4)
        .bit(false)
        .bit(f.may_trigger_pre_emption)
        .bit(false)
        .bit(f.pre_emptable);
    if let Some(g) = &f.gbr {
        b.bit(false)
            .bit(g.notification)
            .bit(g.loss_dl.is_some())
            .bit(g.loss_ul.is_some())
            .bit(false);
        for r in [g.mfbr_dl, g.mfbr_ul, g.gfbr_dl, g.gfbr_ul] {
            bit_rate(b, r);
        }
        if g.notification {
            b.bit(false);
        }
        for loss in [g.loss_dl, g.loss_ul].into_iter().flatten() {
            two_octet_ext(b, loss);
        }
    }
    if f.reflective {
        b.bit(false);
    }
    if f.additional {
        b.bit(false);
    }
}

/// PDUSessionResourceSetupRequestTransfer (§9.3.4.1): extension `0`, the IE
/// count in two aligned octets, then in object-set order, every IE
/// criticality reject (`PDUSessionResourceSetupRequestTransferIEs`):
/// - id 130 PDUSessionAggregateMaximumBitRate: extension `0`, iE-Extensions
///   `0`, BitRate DL, BitRate UL;
/// - id 139 UL-NGU-UP-TNLInformation: [`tunnel`];
/// - id 127 DataForwardingNotPossible: a one-value root, the extension bit
///   alone, padded -> `00`;
/// - id 134 PDUSessionType: extension `0` + the index in three bits (five
///   values);
/// - id 138 SecurityIndication: extension `0`, presence
///   maximumIntegrityProtectedDataRate-UL, iE-Extensions `0`; the two
///   indications, each extension `0` + two bits; the rate, extension `0` +
///   one bit;
/// - id 129 NetworkInstance `INTEGER (1..256, ...)`: extension `0`, n-1 in
///   one aligned octet (range 256);
/// - id 136 QosFlowSetupRequestList `SIZE(1..64)`: count-1 in six bits; per
///   item extension `0`, presence e-RAB-ID, iE-Extensions `0`; QFI (extension
///   `0` + six bits); [`qos_parameters`]; E-RAB-ID, extension `0` + four
///   bits.
///
/// The transfer is a complete encoding of its own (`OCTET STRING
/// (CONTAINING ...)`), so padded to an octet.
pub(crate) fn setup_request_transfer(r: &SetupRequestTransfer) -> Vec<u8> {
    let mut ies: Vec<(u16, u8, Vec<u8>)> = Vec::new();
    if let Some((dl, ul)) = r.ambr {
        ies.push((
            130,
            0,
            encoding(|b| {
                b.bit(false).bit(false);
                bit_rate(b, dl);
                bit_rate(b, ul);
            }),
        ));
    }
    ies.push((139, 0, encoding(|b| tunnel(b, &r.ul))));
    if r.data_forwarding_not_possible {
        ies.push((
            127,
            0,
            encoding(|b| {
                b.bit(false);
            }),
        ));
    }
    ies.push((
        134,
        0,
        encoding(|b| {
            b.bit(false).field(u64::from(r.pdu_session_type), 3);
        }),
    ));
    if let Some(s) = &r.security {
        ies.push((
            138,
            0,
            encoding(|b| {
                b.bit(false).bit(s.max_rate_ul.is_some()).bit(false);
                b.bit(false).field(u64::from(s.integrity), 2);
                b.bit(false).field(u64::from(s.confidentiality), 2);
                if let Some(rate) = s.max_rate_ul {
                    b.bit(false).field(u64::from(rate), 1);
                }
            }),
        ));
    }
    if let Some(n) = r.network_instance {
        assert!((1..=256).contains(&n));
        ies.push((
            129,
            0,
            encoding(|b| {
                b.bit(false).octets(&[(n - 1) as u8]);
            }),
        ));
    }
    assert!((1..=64).contains(&r.flows.len()));
    ies.push((
        136,
        0,
        encoding(|b| {
            b.field(r.flows.len() as u64 - 1, 6);
            for f in &r.flows {
                b.bit(false).bit(f.e_rab_id.is_some()).bit(false);
                b.bit(false).field(u64::from(f.qfi), 6);
                qos_parameters(b, f);
                if let Some(e) = f.e_rab_id {
                    b.bit(false).field(u64::from(e), 4);
                }
            }
        }),
    ));
    encoding(|b| {
        b.bit(false).octets(&(ies.len() as u16).to_be_bytes());
        for (id, c, v) in &ies {
            b.ie(*id, *c, v);
        }
    })
}

/// The transfer `build_n2_sm_setup_request_transfer` describes: one non-GBR
/// flow, IPv4 UL tunnel, PDU session type ipv4, no optional IE; the QFI's
/// non-dynamic 5QI with no optional member, ARP `arp` shall-not-trigger /
/// not-pre-emptable.
pub(crate) fn single_flow_setup_request_transfer(
    teid: u32,
    address: [u8; 4],
    qfi: u8,
    five_qi: u8,
    arp: u8,
) -> SetupRequestTransfer {
    SetupRequestTransfer {
        ambr: None,
        ul: Tunnel {
            address: address.to_vec(),
            bits: 32,
            teid,
        },
        data_forwarding_not_possible: false,
        pdu_session_type: 0,
        security: None,
        network_instance: None,
        flows: vec![Flow {
            qfi,
            qos: Qos::NonDynamic {
                five_qi,
                priority: None,
                window: None,
                burst: None,
            },
            arp,
            may_trigger_pre_emption: false,
            pre_emptable: false,
            gbr: None,
            reflective: false,
            additional: false,
            e_rab_id: None,
        }],
    }
}

/// One AssociatedQosFlowItem: the QFI and the qosFlowMappingIndication
/// index (`ENUMERATED {ul, dl, ...}`: 0 ul, 1 dl).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssociatedFlow {
    pub qfi: u8,
    pub mapping: Option<u8>,
}

/// One QosFlowPerTNLInformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PerTnl {
    pub tunnel: Tunnel,
    pub flows: Vec<AssociatedFlow>,
}

/// A PDUSessionResourceSetupResponseTransfer (§9.3.4.2). `security_result`
/// is (integrity, confidentiality), each 0 performed, 1 not-performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupResponseTransfer {
    pub dl: PerTnl,
    pub additional: Vec<PerTnl>,
    pub security_result: Option<(u8, u8)>,
    pub failed: Vec<(u8, t::Cause)>,
}

/// QosFlowPerTNLInformation (§9.3.2.8): extension `0`, iE-Extensions `0`;
/// the [`tunnel`]; AssociatedQosFlowList `SIZE(1..64)`, count-1 in six bits;
/// per item extension `0`, presence qosFlowMappingIndication, iE-Extensions
/// `0`, the QFI (extension `0` + six bits), the indication (extension `0` +
/// one bit).
fn per_tnl(b: &mut Bits, p: &PerTnl) {
    assert!((1..=64).contains(&p.flows.len()));
    b.bit(false).bit(false);
    tunnel(b, &p.tunnel);
    b.field(p.flows.len() as u64 - 1, 6);
    for f in &p.flows {
        b.bit(false).bit(f.mapping.is_some()).bit(false);
        b.bit(false).field(u64::from(f.qfi), 6);
        if let Some(m) = f.mapping {
            b.bit(false).field(u64::from(m), 1);
        }
    }
}

/// PDUSessionResourceSetupResponseTransfer (§9.3.4.2): extension `0`;
/// presence additionalDLQosFlowPerTNLInformation, securityResult,
/// qosFlowFailedToSetupList, iE-Extensions `0`; the DL [`per_tnl`]; the
/// additional list `SIZE(1..3)` (maxnoofMultiConnectivityMinusOne), count-1
/// in two bits, per item extension `0`, iE-Extensions `0`, the [`per_tnl`];
/// SecurityResult extension `0`, iE-Extensions `0`, the two results each
/// extension `0` + one bit; QosFlowListWithCause `SIZE(1..64)`, count-1 in
/// six bits, per item extension `0`, iE-Extensions `0`, the QFI, the
/// [`cause`].
pub(crate) fn setup_response_transfer(r: &SetupResponseTransfer) -> Vec<u8> {
    encoding(|b| {
        b.bit(false)
            .bit(!r.additional.is_empty())
            .bit(r.security_result.is_some())
            .bit(!r.failed.is_empty())
            .bit(false);
        per_tnl(b, &r.dl);
        if !r.additional.is_empty() {
            assert!(r.additional.len() <= 3);
            b.field(r.additional.len() as u64 - 1, 2);
            for p in &r.additional {
                b.bit(false).bit(false);
                per_tnl(b, p);
            }
        }
        if let Some((i, c)) = r.security_result {
            b.bit(false).bit(false);
            b.bit(false).field(u64::from(i), 1);
            b.bit(false).field(u64::from(c), 1);
        }
        if !r.failed.is_empty() {
            assert!(r.failed.len() <= 64);
            b.field(r.failed.len() as u64 - 1, 6);
            for (qfi, c) in &r.failed {
                b.bit(false).bit(false);
                b.bit(false).field(u64::from(*qfi), 6);
                cause(b, c);
            }
        }
    })
}

/// A setup response transfer of one DL tunnel and its QFIs, nothing else.
pub(crate) fn plain_setup_response_transfer(tunnel: Tunnel, qfis: &[u8]) -> SetupResponseTransfer {
    SetupResponseTransfer {
        dl: PerTnl {
            tunnel,
            flows: qfis
                .iter()
                .map(|&qfi| AssociatedFlow { qfi, mapping: None })
                .collect(),
        },
        additional: Vec::new(),
        security_result: None,
        failed: Vec::new(),
    }
}

/// S-NSSAI (§9.3.1.24): extension `0`, presence sD, iE-Extensions `0`; SST
/// `OCTET STRING (SIZE(1))`, fixed and at most two octets, so NOT aligned
/// (§17.6); SD `OCTET STRING (SIZE(3))`, fixed and longer, aligned. The AMF
/// context holds the SD as a u32 whose low 24 bits are the octets, MSB first.
pub(crate) fn s_nssai(b: &mut Bits, s: &crate::context::SNssai) {
    b.bit(false).bit(s.sd.is_some()).bit(false);
    b.field(u64::from(s.sst), 8);
    if let Some(sd) = s.sd {
        b.octets(&sd.to_be_bytes()[1..]);
    }
}

/// PDU SESSION RESOURCE SETUP REQUEST (§9.2.1.1) as
/// `build_pdu_session_resource_setup_request_asn1` sends it with no NAS-PDU:
/// initiatingMessage, id-PDUSessionResourceSetup 29, reject; ids 10, 85
/// (reject); id 74 PDUSessionResourceSetupListSUReq (reject), `SIZE(1..256)`
/// so count-1 in one aligned octet (range 256); the item extension `0`,
/// presence pDUSessionNAS-PDU `0`, iE-Extensions `0`; PDUSessionID one
/// aligned octet; the [`s_nssai`]; the transfer `OCTET STRING (CONTAINING
/// ...)`, an unconstrained length, so [`open_any`] -- the reason this lives
/// beside the transfers: past 16K both the transfer and the message value
/// fragment.
pub(crate) fn pdu_session_resource_setup_request(
    amf: u64,
    ran: u32,
    psi: u8,
    s: &crate::context::SNssai,
    transfer: &[u8],
) -> Vec<u8> {
    let list = encoding(|b| {
        b.octets(&[0]);
        b.bit(false).bit(false).bit(false).octets(&[psi]);
        s_nssai(b, s);
        open_any(b, transfer);
    });
    pdu_any(
        0,
        29,
        0,
        &[
            (10, 0, amf_ue_ngap_id(amf)),
            (85, 0, ran_ue_ngap_id(ran)),
            (74, 0, list),
        ],
    )
}

/// PDU SESSION RESOURCE SETUP RESPONSE (§9.2.1.2) with transfers of any
/// length: successfulOutcome, id-PDUSessionResourceSetup 29, reject; ids 10,
/// 85 (ignore); id 75 PDUSessionResourceSetupListSURes and id 58
/// PDUSessionResourceFailedToSetupListSURes (ignore), each `SIZE(1..256)`,
/// count-1 in one aligned octet; per item extension `0`, iE-Extensions `0`,
/// PDUSessionID one aligned octet, the transfer through [`open_any`].
pub(crate) fn pdu_session_resource_setup_response(
    amf: u64,
    ran: u32,
    setup: &[(u8, Vec<u8>)],
    failed: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let list = |items: &[(u8, Vec<u8>)]| {
        encoding(|b| {
            b.octets(&[(items.len() - 1) as u8]);
            for (psi, transfer) in items {
                b.bit(false).bit(false).octets(&[*psi]);
                open_any(b, transfer);
            }
        })
    };
    let mut ies = vec![(10, 1, amf_ue_ngap_id(amf)), (85, 1, ran_ue_ngap_id(ran))];
    if !setup.is_empty() {
        ies.push((75, 1, list(setup)));
    }
    if !failed.is_empty() {
        ies.push((58, 1, list(failed)));
    }
    pdu_any(1, 29, 0, &ies)
}

/// The first served GUAMI of the context (§9.3.3.3): extension `0`,
/// iE-Extensions `0`; PLMNIdentity `OCTET STRING (SIZE(3))` aligned; then
/// AMFRegionID `BIT STRING (SIZE(8))`, AMFSetID `(SIZE(10))`, AMFPointer
/// `(SIZE(6))`, each fixed and at most sixteen bits, so NOT aligned (§16.9):
/// 24 bits run on from the PLMN. A context value wider than its field
/// contributes its low bits ([`Bits::field`] writes the low `n`).
fn guami(b: &mut Bits, g: &crate::context::Guami) {
    let p = &g.plmn_id;
    // PLMNIdentity (§9.3.3.5, TS 24.008 §10.5.1.13): MCC2 MCC1 | MNC3 MCC3 |
    // MNC2 MNC1, a 2-digit MNC's third digit held as 0xF.
    let plmn = [
        p.mcc2 << 4 | p.mcc1,
        p.mnc3 << 4 | p.mcc3,
        p.mnc2 << 4 | p.mnc1,
    ];
    b.bit(false).bit(false).octets(&plmn);
    b.field(u64::from(g.amf_id.region), 8)
        .field(u64::from(g.amf_id.set), 10)
        .field(u64::from(g.amf_id.pointer), 6);
}

/// NR/E-UTRA algorithm bits from a NAS UE security capability octet
/// (§9.3.1.86, TS 24.501 §9.11.3.54): the octet's bit 8 is the null
/// algorithm (5G-EA0/EEA0), which NGAP's 16-bit string does not carry; bits
/// 7 down to 1 are algorithms 1..7, which are NGAP's first seven bits. So the
/// low seven bits of the octet, moved to the top of sixteen.
fn algorithms(octet: u8) -> u64 {
    u64::from(octet & 0x7F) << 9
}

/// INITIAL CONTEXT SETUP REQUEST (§9.2.2.1) as amfd sends it, or `None`
/// where the schema has no encoding for the inputs: no served GUAMI (GUAMI is
/// mandatory), an AMF UE NGAP ID past `2^40-1`, an Allowed NSSAI outside
/// `SIZE(1..8)`, or a UE AMBR past the BitRate root (the extension is for
/// later releases; amfd refuses rather than sending one).
///
/// initiatingMessage, id-InitialContextSetup 14, reject; the IEs in
/// `InitialContextSetupRequestIEs` order with its criticalities:
/// - id 10 AMF-UE-NGAP-ID, id 85 RAN-UE-NGAP-ID (reject);
/// - id 110 UEAggregateMaximumBitRate (reject), when given: extension `0`,
///   iE-Extensions `0`, BitRate DL, BitRate UL;
/// - id 28 GUAMI (reject): [`guami`];
/// - id 0 AllowedNSSAI (reject) `SIZE(1..8)`: count-1 in three bits; per
///   item extension `0`, iE-Extensions `0`, the [`s_nssai`];
/// - id 119 UESecurityCapabilities (reject): extension `0`, iE-Extensions
///   `0`, then four `BIT STRING (SIZE(16, ...))`, each its size extension
///   `0` and sixteen bits, not aligned (§16.9): [`algorithms`] of ea, ia,
///   eea, eia;
/// - id 94 SecurityKey (reject) `BIT STRING (SIZE(256))`: fixed and past
///   sixteen bits, so aligned with no length (§16.10): the 32 key octets;
/// - id 38 NAS-PDU (ignore), when given: unconstrained OCTET STRING,
///   [`open_any`].
///
/// The whole PDU frames through [`pdu_any`], so a NAS-PDU near 16K fragments
/// the message value too.
#[allow(clippy::too_many_arguments)]
pub(crate) fn initial_context_setup_request(
    ctx: &crate::context::AmfContext,
    amf: u64,
    ran: u32,
    allowed: &[crate::context::SNssai],
    caps: &crate::context::UeSecurityCapability,
    key: &[u8; 32],
    nas: Option<&[u8]>,
    ambr: Option<(u64, u64)>,
) -> Option<Vec<u8>> {
    let served = ctx.served_guami.first()?;
    if amf > (1 << 40) - 1 || !(1..=8).contains(&allowed.len()) {
        return None;
    }
    if ambr.is_some_and(|(dl, ul)| dl > BIT_RATE_MAX || ul > BIT_RATE_MAX) {
        return None;
    }
    let mut ies = vec![(10, 0, amf_ue_ngap_id(amf)), (85, 0, ran_ue_ngap_id(ran))];
    if let Some((dl, ul)) = ambr {
        ies.push((
            110,
            0,
            encoding(|b| {
                b.bit(false).bit(false);
                bit_rate(b, dl);
                bit_rate(b, ul);
            }),
        ));
    }
    ies.push((28, 0, encoding(|b| guami(b, served))));
    ies.push((
        0,
        0,
        encoding(|b| {
            b.field(allowed.len() as u64 - 1, 3);
            for s in allowed {
                b.bit(false).bit(false);
                s_nssai(b, s);
            }
        }),
    ));
    ies.push((
        119,
        0,
        encoding(|b| {
            b.bit(false).bit(false);
            for octet in [caps.ea, caps.ia, caps.eea, caps.eia] {
                b.bit(false).field(algorithms(octet), 16);
            }
        }),
    ));
    ies.push((
        94,
        0,
        encoding(|b| {
            b.octets(key);
        }),
    ));
    if let Some(nas) = nas {
        ies.push((38, 1, encoding(|b| open_any(b, nas))));
    }
    Some(pdu_any(0, 14, 0, &ies))
}

/// An NGAP-PDU split along its framing alone (the NGAP-PDU envelope and
/// X.691's open types, nothing message-specific): (choice, procedure code,
/// criticality, the protocol IEs as (id, criticality, value octets)).
pub(crate) type Envelope = (u64, u8, u8, Vec<(u16, u8, Vec<u8>)>);

/// One aligned length determinant at `at`, short or two-octet form; a
/// fragmented one is not read here.
fn length(bytes: &[u8], at: &mut usize) -> usize {
    let first = bytes[*at];
    assert!(first & 0xC0 != 0xC0, "fragmented lengths are not read here");
    if first & 0x80 == 0 {
        *at += 1;
        usize::from(first)
    } else {
        let n = usize::from(u16::from_be_bytes([first & 0x3F, bytes[*at + 1]]));
        *at += 2;
        n
    }
}

/// See [`Envelope`]. Octet 0 is the PDU's extension bit, the two-bit choice
/// and padding; octet 1 the procedure code; octet 2 the criticality in its
/// top two bits and padding; then the open type holding the message value:
/// its extension bit and padding, the IE count in two octets, then per IE
/// two id octets, a criticality octet, and the value as an open type.
pub(crate) fn split(bytes: &[u8]) -> Envelope {
    let choice = u64::from(bytes[0] >> 5 & 0b11);
    let (procedure, criticality) = (bytes[1], bytes[2] >> 6);
    let mut at = 3;
    let len = length(bytes, &mut at);
    assert_eq!(at + len, bytes.len(), "one PDU, nothing after it");
    let count = u16::from_be_bytes([bytes[at + 1], bytes[at + 2]]);
    at += 3;
    let mut ies = Vec::new();
    for _ in 0..count {
        let id = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let c = bytes[at + 2] >> 6;
        at += 3;
        let n = length(bytes, &mut at);
        ies.push((id, c, bytes[at..at + n].to_vec()));
        at += n;
    }
    (choice, procedure, criticality, ies)
}

/// The [`Envelope`] framed again, as [`pdu_any`] frames.
pub(crate) fn join((choice, procedure, criticality, ies): &Envelope) -> Vec<u8> {
    pdu_any(*choice, *procedure, *criticality, ies)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing and the Cause derivation against octets worked out by
    /// hand without them.
    #[test]
    fn the_framing_and_causes_are_the_hand_worked_octets() {
        // 16,385 octets: `C1` + 16,384 octets, then `01` + the last one.
        let long: Vec<u8> = (0..16_385).map(|i| i as u8).collect();
        let framed = encoding(|b| open_any(b, &long));
        assert_eq!(
            (framed[0], framed[16_385], framed.len()),
            (0xC1, 0x01, 16_387)
        );
        // Exactly 4 x 16K: `C4`, the octets, then the empty final part `00`.
        let framed = encoding(|b| open_any(b, &[0; 65_536]));
        assert_eq!(
            (framed[0], framed[65_537], framed.len()),
            (0xC4, 0x00, 65_538)
        );
        // 70,000 = 4 x 16K + 4,464 (0x1170): `C4`, then `91 70`.
        let framed = encoding(|b| open_any(b, &[0; 70_000]));
        assert_eq!(&framed[65_537..65_539], &[0x91, 0x70]);

        // radioNetwork handover-cancelled, index 5 of 45: `000` `0` `000101`
        // + pad -> `01 40`; misc unspecified, 5 of 6: `100` `0` `101` ->
        // `8a`; radioNetwork n26-interface-not-available, the first addition:
        // `000` `1` `0` `000000` + pad -> `10 00`.
        assert_eq!(
            cause_value(&t::Cause::RadioNetwork(
                t::CauseRadioNetwork::HandoverCancelled
            )),
            [0x01, 0x40]
        );
        assert_eq!(
            cause_value(&t::Cause::Misc(t::CauseMisc::Unspecified)),
            [0x8A]
        );
        assert_eq!(
            cause_value(&t::Cause::RadioNetwork(
                t::CauseRadioNetwork::N26InterfaceNotAvailable
            )),
            [0x10, 0x00]
        );
        // The schema's `unkown-qos-flow-ID` is radioNetwork value 27.
        assert_eq!(
            cause_numbers(&t::Cause::RadioNetwork(
                t::CauseRadioNetwork::UnknownQosFlowId
            )),
            (0, 27)
        );
    }

    /// The single-flow Setup Request Transfer (TEID 1, 10.0.0.1, QFI 1, 5QI
    /// 9, ARP 8), octet by octet:
    /// - `00` extension + pad, `00 03` three IEs;
    /// - id 139 `00 8b`, reject `00`, length 10: choice `0`, GTPTunnel
    ///   extension and iE-Extensions `00`, size extension `0`, then
    ///   length-1 = 31 as `00011111` -> `0000 0001` `1111` + pad = `01 f0`;
    ///   `0a 00 00 01`; TEID `00 00 00 01`;
    /// - id 134 `00 86`, reject, length 1: extension `0`, ipv4 `000` -> `00`;
    /// - id 136 `00 88`, reject, length 7: count-1 `000000`, item extension,
    ///   e-RAB-ID, iE-Extensions `000`, QFI extension `0` + `000001` -> `00
    ///   01`; QosFlowLevelQosParameters `00000`, nonDynamic5QI `00`,
    ///   descriptor extension and four presence bits `00000`, FiveQI
    ///   extension `0`, pad -> `00 00`, `09`; ARP extension, iE-Extensions
    ///   `00`, level-1 = 7 `0111`, capability `00`, vulnerability `00` ->
    ///   `0001 1100` `00` + pad -> `1c 00`.
    #[test]
    fn the_single_flow_setup_request_transfer_is_the_hand_worked_octets() {
        let t = setup_request_transfer(&single_flow_setup_request_transfer(
            1,
            [10, 0, 0, 1],
            1,
            9,
            8,
        ));
        assert_eq!(
            t,
            [
                0x00, 0x00, 0x03, // extension, three IEs
                0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x01, // 139
                0x00, 0x86, 0x00, 0x01, 0x00, // 134
                0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x09, 0x1c, 0x00, // 136
            ]
        );
    }

    /// A Setup Response Transfer: 10.45.0.3 TEID 7, QFI 9 mapped dl, Security
    /// Result (performed, not-performed), one failed flow, QFI 2 with
    /// transport unspecified. The bits in order:
    /// - `0` extension; presence additional `0`, securityResult `1`, failed
    ///   list `1`, iE-Extensions `0`; per-TNL extension, iE-Extensions `00`;
    ///   choice gTPTunnel `0`, GTPTunnel extension, iE-Extensions `00`, size
    ///   extension `0`; length-1 = 31 `00011111`; pad:
    ///   `00110000 00000011 11100000` -> `30 03 e0`;
    /// - the address `0a 2d 00 03`, the TEID `00 00 00 07`, aligned;
    /// - AssociatedQosFlowList count-1 `000000`; item extension `0`, mapping
    ///   present `1`, iE-Extensions `0`; QFI extension `0` + `001001`;
    ///   mapping extension `0` + dl `1`;
    /// - SecurityResult extension, iE-Extensions `00`; performed `0 0`,
    ///   not-performed `0 1`;
    /// - failed list count-1 `000000`; item extension, iE-Extensions `00`;
    ///   QFI `0 000010`; Cause transport `001`, extension `0`, unspecified
    ///   `1`; pad:
    ///   `00000001 00001001 01000001 00000000 00000100 0101`+`0000`
    ///   -> `01 09 41 00 04 50`.
    #[test]
    fn a_setup_response_transfer_is_the_hand_worked_octets() {
        let r = SetupResponseTransfer {
            dl: PerTnl {
                tunnel: Tunnel {
                    address: vec![10, 45, 0, 3],
                    bits: 32,
                    teid: 7,
                },
                flows: vec![AssociatedFlow {
                    qfi: 9,
                    mapping: Some(1),
                }],
            },
            additional: Vec::new(),
            security_result: Some((0, 1)),
            failed: vec![(2, t::Cause::Transport(t::CauseTransport::Unspecified))],
        };
        assert_eq!(
            setup_response_transfer(&r),
            [
                0x30, 0x03, 0xe0, 0x0a, 0x2d, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x01, 0x09, 0x41,
                0x00, 0x04, 0x50
            ]
        );
    }

    /// PDU Session Resource Setup Request (AMF 42, RAN 1001, PSI 5, SST 1 SD
    /// 000001, a one-octet transfer `aa`), octet by octet:
    /// - `00 1d 00 1e`: initiatingMessage, procedure 29, reject, length 30;
    ///   `00 00 03`: extension, three IEs;
    /// - `00 0a 00 02 00 2a`: AMF-UE-NGAP-ID 42; `00 55 00 03 40 03 e9`:
    ///   RAN-UE-NGAP-ID 1001, two octets so n-1 = 1 `01` + pad -> `40`;
    /// - `00 4a 00 0a`, list of 10: count-1 `00`; item extension, NAS-PDU
    ///   presence, iE-Extensions `000` + pad -> `00`; PSI `05`; S-NSSAI
    ///   extension `0`, SD present `1`, iE-Extensions `0`, SST `00000001`
    ///   unaligned, pad -> `0100 0000` `0010 0000` = `40 20`; SD `00 00 01`;
    ///   the transfer, length `01`, `aa`.
    #[test]
    fn a_setup_request_and_response_are_the_hand_worked_octets() {
        assert_eq!(
            pdu_session_resource_setup_request(
                42,
                1001,
                5,
                &crate::context::SNssai {
                    sst: 1,
                    sd: Some(1)
                },
                &[0xaa]
            ),
            [
                0x00, 0x1d, 0x00, 0x1e, 0x00, 0x00, 0x03, // PDU, three IEs
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, // AMF-UE-NGAP-ID
                0x00, 0x55, 0x00, 0x03, 0x40, 0x03, 0xe9, // RAN-UE-NGAP-ID
                0x00, 0x4a, 0x00, 0x0a, 0x00, 0x00, 0x05, 0x40, 0x20, 0x00, 0x00, 0x01, 0x01,
                0xaa, // the list
            ]
        );
        // The Setup Response (AMF 7, RAN 9, PSI 3 set up with transfer `bb`,
        // PSI 6 failed with `cc`): `20` successfulOutcome, `1d`, `00`
        // reject, length 33; three-octet value head `00 00 04`; ids 10 and
        // 85 at ignore (`40`) with one-octet values; ids 75 and 58 at
        // ignore, each list count-1 `00`, item preamble `00`, PSI, transfer
        // length `01` and its octet.
        assert_eq!(
            pdu_session_resource_setup_response(7, 9, &[(3, vec![0xbb])], &[(6, vec![0xcc])]),
            [
                0x20, 0x1d, 0x00, 0x21, 0x00, 0x00, 0x04, // PDU, four IEs
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x07, // AMF-UE-NGAP-ID
                0x00, 0x55, 0x40, 0x02, 0x00, 0x09, // RAN-UE-NGAP-ID
                0x00, 0x4b, 0x40, 0x05, 0x00, 0x00, 0x03, 0x01, 0xbb, // set up
                0x00, 0x3a, 0x40, 0x05, 0x00, 0x00, 0x06, 0x01, 0xcc, // failed
            ]
        );
        // The framing split reads the response back into its IEs.
        let (choice, procedure, criticality, ies) = split(&pdu_session_resource_setup_response(
            7,
            9,
            &[(3, vec![0xbb])],
            &[],
        ));
        assert_eq!((choice, procedure, criticality), (1, 29, 0));
        assert_eq!(
            ies.iter().map(|(id, c, _)| (*id, *c)).collect::<Vec<_>>(),
            [(10, 1), (85, 1), (75, 1)]
        );
    }
}
