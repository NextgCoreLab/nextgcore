//! #417 stage B: the N2 SM transfers as octets derived by hand from the
//! TS 38.413 V17.9 schema (`libs/nextgcore-ngap-gen/asn/ngap-17.9.asn`) and
//! X.691 ALIGNED PER. They are the reference the generated codec is checked
//! against now that the hand-written `nextgcore-ngap` transfer codec is gone
//! from this crate's dependencies. Nothing here is taken from either encoder:
//! every function writes the bits its doc comment derives from the schema.
//!
//! The transfers carry lists and integers whose width depends on the value, so
//! the derivations are written against [`Bits`], a bit sink with exactly the
//! X.691 primitives they need and nothing schema-aware: each function below
//! says which schema member each call encodes and which X.691 clause fixes its
//! width.
//!
//! Shared layout facts (X.691 ALIGNED):
//! - a SEQUENCE with `...` opens with its extension bit `0`, then one presence
//!   bit per OPTIONAL member, in declaration order (§19.1-§19.3);
//! - an ENUMERATED with `...` is its extension bit, then the root index in the
//!   fewest bits that hold the root count (§14.3, §11.5.7.2); a root of one
//!   value takes no bits at all;
//! - a CHOICE without `...` is its index in the fewest bits that hold the
//!   alternative count (§23.6); `choice-Extensions` is an ordinary root
//!   alternative, so UPTransportLayerInformation is one bit and Cause three;
//! - `INTEGER (a..b, ...)` with range <= 255 is the extension bit and a
//!   bit-field (§13.2.1, §11.5.7.2); range exactly 256 is one aligned octet
//!   (§11.5.7.2); range 256..65536 is two aligned octets (§11.5.7.3);
//! - BitRate `INTEGER (0..4000000000000, ...)` is past 64K: the extension bit,
//!   the octet count n (1..6, since 4e12 < 2^42) as n-1 in a 3-bit field, then
//!   the value in n aligned octets, n minimal (§11.5.7.4, §13.2.6);
//! - `SEQUENCE (SIZE(1..64)) OF` is count-1 in a 6-bit field and SIZE(1..3) in
//!   a 2-bit one (§20.6, §11.9.4.1), not aligned;
//! - ProtocolIE-Container `SEQUENCE (SIZE(0..65535)) OF` is the count in two
//!   aligned octets; each field is ProtocolIE-ID `INTEGER (0..65535)` in two
//!   aligned octets, Criticality `ENUMERATED {reject, ignore, notify}` (not
//!   extensible) in two bits, then the value as an open type: the value's own
//!   complete encoding padded to an octet, preceded by its aligned length
//!   determinant, one octet below 128 (§11.2, §11.9.3.6). A
//!   ProtocolExtensionContainer is the same with SIZE(1..65535), so count-1;
//! - TransportLayerAddress `BIT STRING (SIZE(1..160, ...))`: the extension
//!   bit, length-1 in an 8-bit field (range 160), then the bits octet-aligned
//!   since they are longer than 16 (§16.11); GTP-TEID `OCTET STRING (SIZE(4))`
//!   is fixed and longer than two octets, so aligned with no length (§17.6).

use super::{QosFlowSetup, QosMonitoringRequest, SetupRequest, SmfCause};

/// An X.691 ALIGNED bit sink. It knows bits, fields, alignment and the
/// open-type length determinant; the schema lives in the functions that drive
/// it.
#[derive(Default)]
pub(crate) struct Bits(Vec<bool>);

impl Bits {
    /// One bit: an extension bit, a presence bit, a one-bit index.
    pub(crate) fn bit(&mut self, b: bool) -> &mut Self {
        self.0.push(b);
        self
    }

    /// `value` as an `n`-bit field, most significant bit first.
    pub(crate) fn field(&mut self, value: u64, n: u32) -> &mut Self {
        for i in (0..n).rev() {
            self.0.push(value >> i & 1 == 1);
        }
        self
    }

    /// Zero bits up to the next octet boundary.
    pub(crate) fn align(&mut self) -> &mut Self {
        while !self.0.len().is_multiple_of(8) {
            self.0.push(false);
        }
        self
    }

    /// Octet-aligned octets.
    pub(crate) fn octets(&mut self, o: &[u8]) -> &mut Self {
        self.align();
        for b in o {
            self.field(u64::from(*b), 8);
        }
        self
    }

    /// An open type holding `inner`, an already complete encoding: aligned
    /// length determinant (short form below 128, two-octet `10` form below
    /// 16384, §11.9.3.6-§11.9.3.7), then the octets.
    pub(crate) fn open(&mut self, inner: &[u8]) -> &mut Self {
        assert!(
            inner.len() < 16384,
            "fragmented open types are not derived here"
        );
        if inner.len() < 128 {
            self.octets(&[inner.len() as u8]);
        } else {
            self.octets(&(0x8000 | inner.len() as u16).to_be_bytes());
        }
        self.octets(inner)
    }

    /// The complete encoding: padded to an octet (§11.1).
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.align();
        self.0
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |o, b| o << 1 | u8::from(*b)))
            .collect()
    }
}

/// Run `f` on a fresh sink and return its complete encoding.
fn encoding(f: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut b = Bits::default();
    f(&mut b);
    b.finish()
}

/// One ProtocolIE-Field / ProtocolExtensionField: id in two aligned octets,
/// criticality (0 reject, 1 ignore, 2 notify) in two bits, the open type.
fn field(b: &mut Bits, id: u16, criticality: u8, value: &[u8]) {
    b.octets(&id.to_be_bytes())
        .field(u64::from(criticality), 2)
        .open(value);
}

/// QosFlowIdentifier `INTEGER (0..63, ...)`: extension bit, six bits.
fn qfi(b: &mut Bits, q: u8) {
    b.bit(false).field(u64::from(q), 6);
}

/// BitRate (see the module doc). A rate past 4e12 is sent as 4e12: that is
/// smfd's #1163 policy (`nextgcore_ngap_gen::bit_rate`), not an encoding rule,
/// so it is applied here before deriving.
pub(crate) const BIT_RATE_MAX: u64 = 4_000_000_000_000;
fn bit_rate(b: &mut Bits, v: u64) {
    let v = v.min(BIT_RATE_MAX);
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    let n = (8 - skip) as u64;
    b.bit(false).field(n - 1, 3).octets(&be[skip..]);
}

/// UPTransportLayerInformation (§9.3.2.2) gTPTunnel with an IPv4 address:
/// CHOICE index `0`; GTPTunnel extension `0`, iE-Extensions `0`;
/// TransportLayerAddress extension `0`, length-1 = 31 in eight bits; the four
/// address octets aligned; the TEID.
fn tunnel(b: &mut Bits, (teid, address): (u32, [u8; 4])) {
    b.bit(false).bit(false).bit(false);
    b.bit(false)
        .field(31, 8)
        .octets(&address)
        .octets(&teid.to_be_bytes());
}

/// QosFlowLevelQosParameters (§9.3.1.12) as smfd fills it:
/// - extension `0`; presence gBR-QosInformation, reflectiveQosAttribute `0`,
///   additionalQosFlowInformation `0`, iE-Extensions (QoS monitoring);
/// - QosCharacteristics CHOICE of three, nonDynamic5QI `00`;
///   NonDynamic5QIDescriptor extension `0`, presence `0000`; FiveQI extension
///   `0` then one aligned octet (range 256);
/// - AllocationAndRetentionPriority extension `0`, iE-Extensions `0`;
///   PriorityLevelARP `INTEGER (1..15)` as level-1 in four bits;
///   Pre-emptionCapability extension `0` + one bit (shall-not `0`, may `1`);
///   Pre-emptionVulnerability extension `0` + one bit (not `0`,
///   pre-emptable `1`);
/// - GBR-QosInformation extension `0`, presence notificationControl,
///   maximumPacketLossRateDL/UL, iE-Extensions `0000`, then MFBR DL, MFBR UL,
///   GFBR DL, GFBR UL;
/// - the iE-Extensions container: count-1 `00 00`, one field id 181
///   (QosMonitoringRequest, criticality ignore) whose value is
///   `ENUMERATED {ul, dl, both, ..., stop}`: root values extension `0` + two
///   bits; `stop` is the first extension addition, extension `1` then the
///   normally small number 0 as `0` + six bits (§11.6.1).
fn qos_parameters(b: &mut Bits, f: &QosFlowSetup) {
    b.bit(false)
        .bit(f.gbr.is_some())
        .bit(false)
        .bit(false)
        .bit(f.qos_monitoring.is_some());
    b.field(0, 2).bit(false).field(0, 4);
    b.bit(false).octets(&[f.five_qi as u8]);
    b.bit(false)
        .bit(false)
        .field(u64::from(f.arp.priority_level) - 1, 4);
    b.bit(false).bit(f.arp.may_trigger_pre_emption);
    b.bit(false).bit(f.arp.pre_emptable);
    if let Some(g) = f.gbr {
        b.bit(false).field(0, 4);
        for r in [g.mfbr_dl, g.mfbr_ul, g.gfbr_dl, g.gfbr_ul] {
            bit_rate(b, r);
        }
    }
    if let Some(m) = f.qos_monitoring {
        let value = encoding(|v| {
            match m {
                QosMonitoringRequest::Ul => v.bit(false).field(0, 2),
                QosMonitoringRequest::Dl => v.bit(false).field(1, 2),
                QosMonitoringRequest::Both => v.bit(false).field(2, 2),
                QosMonitoringRequest::Stop => v.bit(true).bit(false).field(0, 6),
            };
        });
        b.octets(&[0x00, 0x00]);
        field(b, 181, 1, &value);
    }
}

/// `PDUSessionResourceSetupRequestTransfer` (§9.3.4.1), in the order smfd
/// sends its IEs:
///
/// - extension `0`, padded; the IE count in two aligned octets;
/// - id 130 PDUSessionAggregateMaximumBitRate (reject), when there is an AMBR:
///   extension `0`, iE-Extensions `0`, BitRate DL, BitRate UL;
/// - id 139 UL-NGU-UP-TNLInformation (reject): the tunnel;
/// - id 127 DataForwardingNotPossible (reject), when set:
///   `ENUMERATED {data-forwarding-not-possible, ...}` is one extension bit
///   `0` and no index, padded -> `00`;
/// - id 134 PDUSessionType (reject): ipv4 is extension `0` + index `000` of a
///   five-value root -> `00`;
/// - id 136 QosFlowSetupRequestList (reject): count-1 in six bits; per item,
///   extension `0`, presence e-RAB-ID, iE-Extensions `0`, the QFI, the
///   QosFlowLevelQosParameters, then E-RAB-ID `INTEGER (0..15, ...)` as
///   extension `0` + four bits;
/// - id 22 DirectForwardingPathAvailability (ignore), when set: one extension
///   bit, padded -> `00`.
pub(crate) fn setup_request_octets(r: &SetupRequest) -> Vec<u8> {
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
    ies.push((139, 0, encoding(|b| tunnel(b, r.ul_tunnel))));
    if r.data_forwarding_not_possible {
        ies.push((127, 0, vec![0x00]));
    }
    ies.push((134, 0, vec![0x00]));
    ies.push((
        136,
        0,
        encoding(|b| {
            b.field(r.flows.len() as u64 - 1, 6);
            for f in &r.flows {
                b.bit(false).bit(f.e_rab_id.is_some()).bit(false);
                qfi(b, f.qfi);
                qos_parameters(b, f);
                if let Some(e) = f.e_rab_id {
                    b.bit(false).field(u64::from(e), 4);
                }
            }
        }),
    ));
    if r.direct_forwarding_path_availability {
        ies.push((22, 1, vec![0x00]));
    }
    container(&ies)
}

/// A transfer whose only root member is a ProtocolIE-Container: extension
/// `0`, the count in two aligned octets, the fields.
fn container(ies: &[(u16, u8, Vec<u8>)]) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).octets(&(ies.len() as u16).to_be_bytes());
        for (id, criticality, value) in ies {
            field(b, *id, *criticality, value);
        }
    })
}

/// `PDUSessionResourceModifyRequestTransfer` (§9.3.4.3) as
/// `modify_request_transfer` sends it:
///
/// - extension `0`, padded; the IE count in two aligned octets;
/// - id 130 PDUSessionAggregateMaximumBitRate (reject), as in
///   [`setup_request_octets`];
/// - id 135 QosFlowAddOrModifyRequestList (reject), when there are QFIs:
///   count-1 in six bits; per item, extension `0`, presence
///   qosFlowLevelQosParameters `0`, e-RAB-ID `0`, iE-Extensions `0`, the QFI.
pub(crate) fn modify_request_octets(ambr: Option<(u64, u64)>, qfis: &[u8]) -> Vec<u8> {
    let mut ies = Vec::new();
    if let Some((dl, ul)) = ambr {
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
    if !qfis.is_empty() {
        ies.push((
            135,
            0,
            encoding(|b| {
                b.field(qfis.len() as u64 - 1, 6);
                for &q in qfis {
                    b.bit(false).field(0, 3);
                    qfi(b, q);
                }
            }),
        ));
    }
    container(&ies)
}

/// `PDUSessionResourceModifyConfirmTransfer` (§9.3.4.4):
///
/// - extension `0`; presence additionalNG-UUPTNLInformation,
///   qosFlowFailedToModifyList, iE-Extensions `0`;
/// - QosFlowModifyConfirmList: count-1 in six bits; per item, extension `0`,
///   iE-Extensions `0`, the QFI;
/// - uLNGU-UP-TNLInformation: the tunnel;
/// - UPTransportLayerInformationPairList `SIZE(1..3)`: count-1 in two bits; per
///   item, extension `0`, iE-Extensions `0`, the UL then the DL tunnel;
/// - QosFlowListWithCause: count-1 in six bits; per item, extension `0`,
///   iE-Extensions `0`, the QFI, then Cause radioNetwork (index `000`) and
///   CauseRadioNetwork extension `0` + unkown-qos-flow-ID, root index 27 of 45
///   in six bits.
pub(crate) fn modify_confirm_octets(
    qfis: &[u8],
    ul: (u32, [u8; 4]),
    additional: &[((u32, [u8; 4]), (u32, [u8; 4]))],
    failed: &[u8],
) -> Vec<u8> {
    encoding(|b| {
        b.bit(false)
            .bit(!additional.is_empty())
            .bit(!failed.is_empty())
            .bit(false);
        b.field(qfis.len() as u64 - 1, 6);
        for &q in qfis {
            b.bit(false).bit(false);
            qfi(b, q);
        }
        tunnel(b, ul);
        if !additional.is_empty() {
            b.field(additional.len() as u64 - 1, 2);
            for &(u, d) in additional {
                b.bit(false).bit(false);
                tunnel(b, u);
                tunnel(b, d);
            }
        }
        if !failed.is_empty() {
            b.field(failed.len() as u64 - 1, 6);
            for &q in failed {
                b.bit(false).bit(false);
                qfi(b, q);
                b.field(0, 3).bit(false).field(27, 6);
            }
        }
    })
}

/// A Cause (§9.3.1.2) as smfd sends it: CHOICE of six (not extensible) in
/// three bits, then the ENUMERATED's extension bit `0` and its root index:
/// - nas (2), CauseNas root of four, normal-release 0 in two bits;
/// - transport (1), CauseTransport root of two, transport-resource-unavailable
///   0 / unspecified 1 in one bit;
/// - protocol (3), CauseProtocol root of seven,
///   abstract-syntax-error-falsely-constructed-message 5 in three bits;
/// - misc (4), CauseMisc root of six, unspecified 5 in three bits.
fn cause(b: &mut Bits, c: SmfCause) {
    let (choice, index, width) = match c {
        SmfCause::NasNormalRelease => (2, 0, 2),
        SmfCause::TransportResourceUnavailable => (1, 0, 1),
        SmfCause::TransportUnspecified => (1, 1, 1),
        SmfCause::ProtocolFalselyConstructedMessage => (3, 5, 3),
        SmfCause::MiscUnspecified => (4, 5, 3),
    };
    b.field(choice, 3).bit(false).field(index, width);
}

/// `PDUSessionResourceModifyIndicationUnsuccessfulTransfer` (§9.3.4.13) and
/// `PDUSessionResourceReleaseCommandTransfer` (§9.3.4.12) share a layout:
/// extension `0`, iE-Extensions `0`, the Cause, padded.
///
/// - nas/normal-release: `00 010 0 00` -> `10`;
/// - transport/transport-resource-unavailable: `00 001 0 0` -> `08`;
/// - transport/unspecified: `00 001 0 1` -> `0a`;
/// - protocol/falsely-constructed: `00 011 0 101` -> `1a 80`;
/// - misc/unspecified: `00 100 0 101` -> `22 80`.
pub(crate) fn cause_transfer_octets(c: SmfCause) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(false);
        cause(b, c);
    })
}

/// QosFlowPerTNLInformation (§9.3.2.8): extension `0`, iE-Extensions `0`, the
/// tunnel, then AssociatedQosFlowList: count-1 in six bits; per item,
/// extension `0`, presence qosFlowMappingIndication `0`, iE-Extensions `0`,
/// the QFI.
fn per_tnl(b: &mut Bits, t: (u32, [u8; 4]), qfis: &[u8]) {
    b.bit(false).bit(false);
    tunnel(b, t);
    b.field(qfis.len() as u64 - 1, 6);
    for &q in qfis {
        b.bit(false).bit(false).bit(false);
        qfi(b, q);
    }
}

/// QosFlowPerTNLInformationList `SIZE(1..3)`: count-1 in two bits; per item,
/// extension `0`, iE-Extensions `0`, the QosFlowPerTNLInformation.
fn per_tnl_list(b: &mut Bits, additional: &[((u32, [u8; 4]), Vec<u8>)]) {
    b.field(additional.len() as u64 - 1, 2);
    for (t, q) in additional {
        b.bit(false).bit(false);
        per_tnl(b, *t, q);
    }
}

/// `PDUSessionResourceSetupResponseTransfer` (§9.3.4.2), as a gNB sends it:
/// extension `0`; presence additionalDLQosFlowPerTNLInformation,
/// securityResult `0`, qosFlowFailedToSetupList `0`, iE-Extensions `0`; the
/// DL QosFlowPerTNLInformation; the additional list.
pub(crate) fn setup_response_octets(
    dl: (u32, [u8; 4]),
    qfis: &[u8],
    additional: &[((u32, [u8; 4]), Vec<u8>)],
) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(!additional.is_empty()).field(0, 3);
        per_tnl(b, dl, qfis);
        if !additional.is_empty() {
            per_tnl_list(b, additional);
        }
    })
}

/// `PDUSessionResourceModifyIndicationTransfer` (§9.3.4.5): extension `0`;
/// presence additionalDLQosFlowPerTNLInformation, iE-Extensions `0`; then as
/// [`setup_response_octets`].
pub(crate) fn modify_indication_octets(
    dl: (u32, [u8; 4]),
    qfis: &[u8],
    additional: &[((u32, [u8; 4]), Vec<u8>)],
) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(!additional.is_empty()).bit(false);
        per_tnl(b, dl, qfis);
        if !additional.is_empty() {
            per_tnl_list(b, additional);
        }
    })
}

/// `HandoverRequestAcknowledgeTransfer` (§9.3.4.11), as a target gNB sends
/// it: extension `0`; presence dLForwardingUP-TNLInformation, securityResult
/// `0`, qosFlowFailedToSetupList `0`, dataForwardingResponseDRBList `0`,
/// iE-Extensions `0`; the DL tunnel; the forwarding tunnel; then
/// QosFlowListWithDataForwarding: count-1 in six bits; per item, extension
/// `0`, presence dataForwardingAccepted, iE-Extensions `0`, the QFI, and
/// `ENUMERATED {data-forwarding-accepted, ...}` as its one extension bit `0`.
pub(crate) fn handover_request_acknowledge_octets(
    dl: (u32, [u8; 4]),
    forwarding: Option<(u32, [u8; 4])>,
    flows: &[(u8, bool)],
) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(forwarding.is_some()).field(0, 4);
        tunnel(b, dl);
        if let Some(f) = forwarding {
            tunnel(b, f);
        }
        b.field(flows.len() as u64 - 1, 6);
        for &(q, accepted) in flows {
            b.bit(false).bit(accepted).bit(false);
            qfi(b, q);
            if accepted {
                b.bit(false);
            }
        }
    })
}

/// `PathSwitchRequestTransfer` (§9.3.4.8), as a target gNB sends it:
///
/// - extension `0`; presence dL-NGU-TNLInformationReused `0`,
///   userPlaneSecurityInformation, iE-Extensions `0`;
/// - the DL tunnel;
/// - UserPlaneSecurityInformation, when present: extension `0`, iE-Extensions
///   `0`; SecurityResult extension `0`, iE-Extensions `0`,
///   IntegrityProtectionResult performed (extension `0` + `0` of two),
///   ConfidentialityProtectionResult performed (the same); SecurityIndication
///   extension `0`, presence maximumIntegrityProtectedDataRate-UL `0`,
///   iE-Extensions `0`, IntegrityProtectionIndication required (extension `0`
///   then `00`, index 0 of three), ConfidentialityProtectionIndication
///   required (the same);
/// - QosFlowAcceptedList: count-1 in six bits; per item, extension `0`,
///   iE-Extensions `0`, the QFI.
pub(crate) fn path_switch_request_octets(
    dl: (u32, [u8; 4]),
    qfis: &[u8],
    security: bool,
) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(false).bit(security).bit(false);
        tunnel(b, dl);
        if security {
            b.bit(false).bit(false);
            b.bit(false).bit(false).field(0, 2).field(0, 2);
            b.bit(false).bit(false).bit(false).field(0, 3).field(0, 3);
        }
        b.field(qfis.len() as u64 - 1, 6);
        for &q in qfis {
            b.bit(false).bit(false);
            qfi(b, q);
        }
    })
}

/// `PathSwitchRequestAcknowledgeTransfer` (§9.3.4.9): extension `0`; presence
/// uL-NGU-UP-TNLInformation, securityIndication `0`, iE-Extensions `0`; the
/// UL tunnel. With no tunnel it is the one octet `00`.
pub(crate) fn path_switch_request_acknowledge_octets(ul: Option<(u32, [u8; 4])>) -> Vec<u8> {
    encoding(|b| {
        b.bit(false).bit(ul.is_some()).bit(false).bit(false);
        if let Some(t) = ul {
            tunnel(b, t);
        }
    })
}
