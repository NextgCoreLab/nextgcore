//! #417 stage B3.2: the handover, path switch, RAN configuration and error
//! PDUs amfd sends, derived by hand. See [`crate::amf_pdus`] for the release.
//!
//! Layout facts used throughout (X.691 ALIGNED, beyond those listed in
//! [`crate::aper_golden`]):
//! - `INTEGER (0..255)` (ProcedureCode, PDUSessionID) is one aligned octet
//!   (§11.5.7.2, range 256); `INTEGER (0..65535)` (ProtocolIE-ID) two aligned
//!   octets (§11.5.7.3);
//! - a `SEQUENCE (SIZE(1..256)) OF` count is count-1 in one aligned octet
//!   (range 256, §11.5.7.2), a `SIZE(1..8)` count is count-1 in three bits
//!   (§11.5.7.1 small range: a bit-field, not aligned);
//! - an `OCTET STRING` with no SIZE, or `(CONTAINING ...)`, is an aligned
//!   length determinant then the octets (§17.8, §11.9.3.6);
//! - `OCTET STRING (SIZE(n))` with n <= 2 is n*8 bits NOT aligned, n > 2 is
//!   aligned with no length (§17.6-§17.7); the same holds for a fixed
//!   `BIT STRING (SIZE(n))` with n <= 16 / n > 16 bits (§16.9-§16.10);
//! - an extensible `ENUMERATED` root value is `0` and its index in the
//!   fewest bits holding the root; an extension addition is `1` and its
//!   addition index as a normally small number, `0` + six bits (§14.2-§14.3,
//!   §11.6.1).

use crate::aper_golden::{amf_ue_ngap_id, pdu, ran_ue_ngap_id, Bits};
use crate::ngap_asn1::IeDiagnostic;
use crate::ngap_types as t;
use nextgcore_ngap_gen::generated as g;

/// The vendored V17.9.0 module the generated codec compiles.
const ASN1: &str = include_str!("../../../../libs/nextgcore-ngap-gen/asn/ngap-17.9.asn");

/// The identifiers of `name ::= ENUMERATED { ... }` in the vendored module,
/// normalised (hyphens dropped, lower case), and how many are in the root
/// (before the `...`).
fn enumerated(name: &str) -> (Vec<String>, usize) {
    let head = format!("\n{name} ::= ENUMERATED {{");
    let start = ASN1.find(&head).expect("the ENUMERATED is in the module") + head.len();
    let body = &ASN1[start..start + ASN1[start..].find('}').expect("closed")];
    let mut names = Vec::new();
    let mut root = None;
    for item in body.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if item == "..." {
            root = Some(names.len());
        } else {
            names.push(item.replace('-', "").to_lowercase());
        }
    }
    let root = root.unwrap_or(names.len());
    (names, root)
}

const CAUSE_GROUPS: [&str; 5] = [
    "CauseRadioNetwork",
    "CauseTransport",
    "CauseNas",
    "CauseProtocol",
    "CauseMisc",
];

/// A Cause (§9.3.1.2) as the CHOICE index and the ENUMERATED index the
/// vendored ASN.1 gives its NAME: the wire numbers come from the module, not
/// from the domain enum's discriminants. The CHOICE is radioNetwork 0,
/// transport 1, nas 2, protocol 3, misc 4, in the module's order. One
/// identifier is spelt `unkown-qos-flow-ID` in the module; it is matched as
/// `unknown`.
pub(crate) fn asn1_cause(c: &t::Cause) -> (u8, u8) {
    let (choice, variant) = match c {
        t::Cause::RadioNetwork(v) => (0, format!("{v:?}")),
        t::Cause::Transport(v) => (1, format!("{v:?}")),
        t::Cause::Nas(v) => (2, format!("{v:?}")),
        t::Cause::Protocol(v) => (3, format!("{v:?}")),
        t::Cause::Misc(v) => (4, format!("{v:?}")),
    };
    let group = CAUSE_GROUPS[usize::from(choice)];
    let want = variant.to_lowercase();
    let index = enumerated(group)
        .0
        .iter()
        .position(|n| n.replace("unkown", "unknown") == want)
        .unwrap_or_else(|| panic!("{group} has no {variant}"));
    (choice, index as u8)
}

/// The generated Cause the vendored ASN.1 names `c` with.
pub(crate) fn asn1_generated_cause(c: &t::Cause) -> g::Cause {
    match asn1_cause(c) {
        (0, i) => g::Cause::RadioNetwork(g::CauseRadioNetwork(i)),
        (1, i) => g::Cause::Transport(g::CauseTransport(i)),
        (2, i) => g::Cause::Nas(g::CauseNas(i)),
        (3, i) => g::Cause::Protocol(g::CauseProtocol(i)),
        (_, i) => g::Cause::Misc(g::CauseMisc(i)),
    }
}

/// The fewest bits that hold `0..n-1`.
fn width(n: usize) -> u32 {
    usize::BITS - (n - 1).leading_zeros()
}

/// Cause `choice`/`index`: the CHOICE has six alternatives and no extension
/// marker (choice-Extensions is an ordinary alternative), so three bits; then
/// the group ENUMERATED, extensible: a root index as `0` + the index in the
/// fewest bits holding the root (from the module: radioNetwork 45 -> 6,
/// transport 2 -> 1, nas 4 -> 2, protocol 7 -> 3, misc 6 -> 3), an addition
/// as `1` + `0` + its addition index in six bits.
fn cause_bits(b: &mut Bits, choice: u8, index: u8) {
    let root = enumerated(CAUSE_GROUPS[usize::from(choice)]).1;
    b.field(u64::from(choice), 3);
    if usize::from(index) < root {
        b.bit(false).field(u64::from(index), width(root));
    } else {
        b.bit(true)
            .bit(false)
            .field(u64::from(index) - root as u64, 6);
    }
}

/// A domain Cause as its IE value, numbered by name from the module.
pub(crate) fn cause(c: &t::Cause) -> Vec<u8> {
    let (choice, index) = asn1_cause(c);
    let mut b = Bits::default();
    cause_bits(&mut b, choice, index);
    b.finish()
}

/// A generated Cause (whose numbers are the wire numbers) as its IE value.
pub(crate) fn generated_cause(c: &g::Cause) -> Vec<u8> {
    let (choice, index) = match c {
        g::Cause::RadioNetwork(v) => (0, v.0),
        g::Cause::Transport(v) => (1, v.0),
        g::Cause::Nas(v) => (2, v.0),
        g::Cause::Protocol(v) => (3, v.0),
        g::Cause::Misc(v) => (4, v.0),
        g::Cause::Choice_Extensions(_) => panic!("no Cause extension is derived here"),
    };
    let mut b = Bits::default();
    cause_bits(&mut b, choice, index);
    b.finish()
}

/// CriticalityDiagnostics (§9.3.1.3): extension `0`, five presence bits
/// (procedureCode, triggeringMessage, procedureCriticality,
/// iEsCriticalityDiagnostics, iE-Extensions); ProcedureCode one aligned
/// octet; TriggeringMessage `ENUMERATED` of three, not extensible, two bits;
/// Criticality two bits; CriticalityDiagnostics-IE-List `SIZE(1..256)`:
/// count-1 in one aligned octet; per item extension `0`, iE-Extensions `0`,
/// iECriticality two bits, iE-ID two aligned octets, TypeOfError
/// `ENUMERATED {not-understood, missing, ...}` `0` + one bit.
/// `procedure` is (procedureCode, triggeringMessage, procedureCriticality).
pub(crate) fn criticality_diagnostics(
    procedure: Option<(u8, u8, u8)>,
    ies: &[IeDiagnostic],
) -> Vec<u8> {
    let mut b = Bits::default();
    b.bit(false)
        .bit(procedure.is_some())
        .bit(procedure.is_some())
        .bit(procedure.is_some())
        .bit(!ies.is_empty())
        .bit(false);
    if let Some((code, trigger, criticality)) = procedure {
        b.octets(&[code])
            .field(u64::from(trigger), 2)
            .field(u64::from(criticality), 2);
    }
    if !ies.is_empty() {
        assert!(ies.len() <= 256);
        b.octets(&[(ies.len() - 1) as u8]);
        for d in ies {
            b.field(0, 2)
                .field(u64::from(d.criticality), 2)
                .octets(&d.ie_id.to_be_bytes())
                .bit(false)
                .field(u64::from(d.type_of_error), 1);
        }
    }
    b.finish()
}

/// A `SEQUENCE (SIZE(1..256)) OF` list whose items are { pDUSessionID, an
/// `OCTET STRING (CONTAINING ...)` transfer, iE-Extensions OPTIONAL, ... }
/// -- the handover, to-release, switched, released and failed lists: count-1
/// in one aligned octet; per item extension `0`, iE-Extensions `0`, the PDU
/// session ID octet, the transfer's aligned length and octets.
pub(crate) fn session_items(items: &[(u8, &[u8])]) -> Vec<u8> {
    assert!((1..=256).contains(&items.len()));
    let mut b = Bits::default();
    b.octets(&[(items.len() - 1) as u8]);
    for (psi, transfer) in items {
        b.field(0, 2).octets(&[*psi]).open(transfer);
    }
    b.finish()
}

/// HandoverType `ENUMERATED {intra5gs, fivegs-to-eps, eps-to-5gs, ...,
/// fivegs-to-utran}`: `0` + two bits.
fn handover_type(h: t::HandoverType) -> Vec<u8> {
    let mut b = Bits::default();
    b.bit(false).field(
        match h {
            t::HandoverType::Intra5gs => 0,
            t::HandoverType::FivegsToEps => 1,
            t::HandoverType::EpsTo5gs => 2,
        },
        2,
    );
    b.finish()
}

/// S-NSSAI (§9.3.1.24): extension `0`, presence of sD, iE-Extensions `0`;
/// SST `OCTET STRING (SIZE(1))` eight bits not aligned; SD `(SIZE(3))`
/// aligned.
fn s_nssai(b: &mut Bits, s: &t::SNssai) {
    b.bit(false)
        .bit(s.sd.is_some())
        .bit(false)
        .field(u64::from(s.sst), 8);
    if let Some(sd) = s.sd {
        b.octets(&sd);
    }
}

/// AllowedNSSAI `SIZE(1..8)`: count-1 in three bits; per item extension `0`,
/// iE-Extensions `0`, the S-NSSAI.
fn allowed_nssai(list: &[t::SNssai]) -> Vec<u8> {
    assert!((1..=8).contains(&list.len()));
    let mut b = Bits::default();
    b.field(list.len() as u64 - 1, 3);
    for s in list {
        b.field(0, 2);
        s_nssai(&mut b, s);
    }
    b.finish()
}

/// UESecurityCapabilities (§9.3.1.86): extension `0`, iE-Extensions `0`,
/// four `BIT STRING (SIZE(16, ...))`: each its size-extension bit `0` and
/// sixteen bits, not aligned (§16.9).
fn ue_security_capabilities(c: &t::UeSecurityCapabilities) -> Vec<u8> {
    let mut b = Bits::default();
    b.field(0, 2);
    for set in [
        c.nr_encryption_algorithms,
        c.nr_integrity_algorithms,
        c.eutra_encryption_algorithms,
        c.eutra_integrity_algorithms,
    ] {
        b.bit(false).field(u64::from(set), 16);
    }
    b.finish()
}

/// SecurityContext (§9.3.1.88): extension `0`, iE-Extensions `0`;
/// NextHopChainingCount `INTEGER (0..7)` three bits; SecurityKey
/// `BIT STRING (SIZE(256))`, fixed and past sixteen bits, so aligned with no
/// length.
fn security_context(s: &t::SecurityContext) -> Vec<u8> {
    let mut b = Bits::default();
    b.field(0, 2)
        .field(u64::from(s.next_hop_chaining_count), 3)
        .octets(&s.next_hop);
    b.finish()
}

/// GUAMI (§9.3.3.3): extension `0`, iE-Extensions `0`; PLMN aligned;
/// AMFRegionID `BIT STRING (SIZE(8))`, AMFSetID `(SIZE(10))`, AMFPointer
/// `(SIZE(6))`, each fixed and at most sixteen bits, so not aligned; the low
/// bits of each value.
fn guami(gu: &t::Guami) -> Vec<u8> {
    let mut b = Bits::default();
    b.field(0, 2)
        .octets(&gu.plmn_identity)
        .field(u64::from(gu.amf_region_id), 8)
        .field(u64::from(gu.amf_set_id), 10)
        .field(u64::from(gu.amf_pointer), 6);
    b.finish()
}

/// HANDOVER REQUEST (§9.2.3.4): initiatingMessage,
/// id-HandoverResourceAllocation 13, reject; in `HandoverRequestIEs` order:
/// - id 10 AMF-UE-NGAP-ID (reject); id 29 HandoverType (reject); id 15
///   Cause (ignore);
/// - id 110 UEAggregateMaximumBitRate (reject): extension `0`,
///   iE-Extensions `0`, DL then UL [`crate::aper_golden::bit_rate`];
/// - id 119 UESecurityCapabilities (reject); id 93 SecurityContext (reject);
/// - id 73 PDUSessionResourceSetupListHOReq (reject): `SIZE(1..256)` count-1
///   in one aligned octet; per item extension `0`, iE-Extensions `0`, the
///   PDU session ID octet, the S-NSSAI, the transfer's aligned length and
///   octets;
/// - id 0 AllowedNSSAI (reject); id 101 SourceToTarget container (reject);
///   id 28 GUAMI (reject).
pub(crate) fn handover_request(m: &t::HandoverRequest) -> Vec<u8> {
    let mut ambr = Bits::default();
    ambr.field(0, 2);
    crate::aper_golden::bit_rate(&mut ambr, m.ue_ambr.dl);
    crate::aper_golden::bit_rate(&mut ambr, m.ue_ambr.ul);
    assert!((1..=256).contains(&m.pdu_session_list.len()));
    let mut sessions = Bits::default();
    sessions.octets(&[(m.pdu_session_list.len() - 1) as u8]);
    for s in &m.pdu_session_list {
        sessions.field(0, 2).octets(&[s.pdu_session_id]);
        s_nssai(&mut sessions, &s.s_nssai);
        sessions.open(&s.transfer);
    }
    pdu(
        0,
        13,
        0,
        &[
            (10, 0, amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (29, 0, handover_type(m.handover_type)),
            (15, 1, cause(&m.cause)),
            (110, 0, ambr.finish()),
            (
                119,
                0,
                ue_security_capabilities(&m.ue_security_capabilities),
            ),
            (93, 0, security_context(&m.security_context)),
            (73, 0, sessions.finish()),
            (0, 0, allowed_nssai(&m.allowed_nssai)),
            (
                101,
                0,
                crate::aper_golden::open_value(&m.source_to_target_container),
            ),
            (28, 0, guami(&m.guami)),
        ],
    )
}

/// HANDOVER COMMAND (§9.2.3.2): successfulOutcome, id-HandoverPreparation
/// 12, reject; ids 10, 85, 29 (reject); id 39
/// NASSecurityParametersFromNGRAN (reject), an OCTET STRING, when present;
/// id 59 PDUSessionResourceHandoverList (ignore) and id 78
/// PDUSessionResourceToReleaseListHOCmd (ignore), [`session_items`], each
/// optional with `SIZE(1..)` so left out when empty; id 106
/// TargetToSource container (reject).
pub(crate) fn handover_command(m: &t::HandoverCommand) -> Vec<u8> {
    let mut ies = vec![
        (10, 0, amf_ue_ngap_id(m.amf_ue_ngap_id)),
        (85, 0, ran_ue_ngap_id(m.ran_ue_ngap_id)),
        (29, 0, handover_type(m.handover_type)),
    ];
    if let Some(p) = &m.nas_security_parameters_from_ngran {
        ies.push((39, 0, crate::aper_golden::open_value(p)));
    }
    if !m.pdu_session_list.is_empty() {
        let items: Vec<(u8, &[u8])> = m
            .pdu_session_list
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect();
        ies.push((59, 1, session_items(&items)));
    }
    if let Some(release) = m.release_list.as_ref().filter(|r| !r.is_empty()) {
        let items: Vec<(u8, &[u8])> = release
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect();
        ies.push((78, 1, session_items(&items)));
    }
    ies.push((
        106,
        0,
        crate::aper_golden::open_value(&m.target_to_source_container),
    ));
    pdu(1, 12, 0, &ies)
}

/// DOWNLINK RAN STATUS TRANSFER (§9.2.3.14): initiatingMessage,
/// id-DownlinkRANStatusTransfer 7, ignore; ids 10, 85 (reject); id 84
/// RANStatusTransfer-TransparentContainer (reject). The container is a
/// SEQUENCE, so the open type holds `container`, its complete encoding.
pub(crate) fn downlink_ran_status_transfer(amf: u64, ran: u32, container: &[u8]) -> Vec<u8> {
    pdu(
        0,
        7,
        1,
        &[
            (10, 0, amf_ue_ngap_id(amf)),
            (85, 0, ran_ue_ngap_id(ran)),
            (84, 0, container.to_vec()),
        ],
    )
}

/// PATH SWITCH REQUEST ACKNOWLEDGE (§9.2.3.9): successfulOutcome,
/// id-PathSwitchRequest 25, reject; in `PathSwitchRequestAcknowledgeIEs`
/// order: ids 10, 85 (ignore); id 119 UESecurityCapabilities (reject) when
/// present; id 93 SecurityContext (reject); id 77
/// PDUSessionResourceSwitchedList (ignore); id 68
/// PDUSessionResourceReleasedListPSAck (ignore) when non-empty; id 0
/// AllowedNSSAI (reject); id 19 CriticalityDiagnostics (ignore), IE list
/// only, when there is something to report.
pub(crate) fn path_switch_request_acknowledge(
    m: &t::PathSwitchRequestAcknowledge,
    notify: &[IeDiagnostic],
) -> Vec<u8> {
    let mut ies = vec![
        (10, 1, amf_ue_ngap_id(m.amf_ue_ngap_id)),
        (85, 1, ran_ue_ngap_id(m.ran_ue_ngap_id)),
    ];
    if let Some(c) = &m.ue_security_capabilities {
        ies.push((119, 0, ue_security_capabilities(c)));
    }
    ies.push((93, 0, security_context(&m.security_context)));
    let switched: Vec<(u8, &[u8])> = m
        .switched_list
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    ies.push((77, 1, session_items(&switched)));
    if let Some(released) = m.released_list.as_ref().filter(|r| !r.is_empty()) {
        let items: Vec<(u8, &[u8])> = released
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect();
        ies.push((68, 1, session_items(&items)));
    }
    ies.push((0, 0, allowed_nssai(&m.allowed_nssai)));
    if !notify.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, notify)));
    }
    pdu(1, 25, 0, &ies)
}

/// PATH SWITCH REQUEST FAILURE (§9.2.3.10): unsuccessfulOutcome,
/// id-PathSwitchRequest 25, reject; ids 10, 85 (ignore); id 69
/// PDUSessionResourceReleasedListPSFail (ignore), [`session_items`]; id 19
/// CriticalityDiagnostics (ignore), IE list only, when non-empty.
pub(crate) fn path_switch_request_failure(
    amf: u64,
    ran: u32,
    released: &[t::PduSessionResourceReleasedItem],
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    let items: Vec<(u8, &[u8])> = released
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    let mut ies = vec![
        (10, 1, amf_ue_ngap_id(amf)),
        (85, 1, ran_ue_ngap_id(ran)),
        (69, 1, session_items(&items)),
    ];
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(2, 25, 0, &ies)
}

/// RAN CONFIGURATION UPDATE ACKNOWLEDGE (§9.2.6.5): successfulOutcome,
/// id-RANConfigurationUpdate 35, reject; id 19 CriticalityDiagnostics
/// (ignore), IE list only, when there is something to report.
pub(crate) fn ran_configuration_update_acknowledge(notify: &[IeDiagnostic]) -> Vec<u8> {
    let mut ies = Vec::new();
    if !notify.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, notify)));
    }
    pdu(1, 35, 0, &ies)
}

/// RAN CONFIGURATION UPDATE FAILURE (§9.2.6.6): unsuccessfulOutcome,
/// id-RANConfigurationUpdate 35, reject; id 15 Cause (ignore); id 107
/// TimeToWait (ignore) when given: `ENUMERATED {v1s, v2s, v5s, v10s, v20s,
/// v60s, ...}`, `0` + three bits; id 19 CriticalityDiagnostics (ignore), IE
/// list only, when non-empty.
pub(crate) fn ran_configuration_update_failure(
    c: &t::Cause,
    time_to_wait: Option<t::TimeToWait>,
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    let mut ies = vec![(15, 1, cause(c))];
    if let Some(ttw) = time_to_wait {
        // The index by name, from the module's list.
        let (names, root) = enumerated("TimeToWait");
        let index = names
            .iter()
            .position(|n| *n == format!("{ttw:?}").to_lowercase())
            .expect("a TimeToWait the module names");
        assert!(index < root && root == 6);
        let mut b = Bits::default();
        b.bit(false).field(index as u64, 3);
        ies.push((107, 1, b.finish()));
    }
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(2, 35, 0, &ies)
}

/// ERROR INDICATION (§9.2.6.13): initiatingMessage, id-ErrorIndication 9,
/// ignore; each present IE ignore, in `ErrorIndicationIEs` order: id 10
/// AMF-UE-NGAP-ID, id 85 RAN-UE-NGAP-ID, id 15 Cause (the octets given), id
/// 19 CriticalityDiagnostics (the octets given).
pub(crate) fn error_indication(
    amf: Option<u64>,
    ran: Option<u32>,
    cause: Option<Vec<u8>>,
    diagnostics: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut ies = Vec::new();
    if let Some(id) = amf {
        ies.push((10, 1, amf_ue_ngap_id(id)));
    }
    if let Some(id) = ran {
        ies.push((85, 1, ran_ue_ngap_id(id)));
    }
    if let Some(c) = cause {
        ies.push((15, 1, c));
    }
    if let Some(d) = diagnostics {
        ies.push((19, 1, d));
    }
    pdu(0, 9, 1, &ies)
}

/// PATH SWITCH REQUEST (§9.2.3.8) from a gNB, with its optional failed list:
/// initiatingMessage, id-PathSwitchRequest 25, reject; id 85 RAN-UE-NGAP-ID
/// and id 100 SourceAMF-UE-NGAP-ID (reject); id 121 UserLocationInformation
/// (ignore, as [`crate::gnb_pdus::user_location`]); id 119
/// UESecurityCapabilities (ignore); id 76
/// PDUSessionResourceToBeSwitchedDLList (reject) and, when given, id 57
/// PDUSessionResourceFailedToSetupListPSReq (ignore), both
/// [`session_items`]. ([`crate::gnb_pdus::path_switch_request`] is the
/// no-failed-list case.)
pub(crate) fn path_switch_request(m: &t::PathSwitchRequest) -> Vec<u8> {
    let switched: Vec<(u8, &[u8])> = m
        .pdu_session_list
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    let mut ies = vec![
        (85, 0, ran_ue_ngap_id(m.ran_ue_ngap_id)),
        (100, 0, amf_ue_ngap_id(m.source_amf_ue_ngap_id)),
        (
            121,
            1,
            crate::gnb_pdus::user_location(&m.user_location_info),
        ),
        (
            119,
            1,
            ue_security_capabilities(&m.ue_security_capabilities),
        ),
        (76, 0, session_items(&switched)),
    ];
    if let Some(failed) = &m.failed_list {
        let items: Vec<(u8, &[u8])> = failed
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect();
        ies.push((57, 1, session_items(&items)));
    }
    pdu(0, 25, 0, &ies)
}

#[cfg(test)]
mod tests {
    //! Each derivation against a vector worked out octet by octet, without
    //! the sink, and against the generated codec's strict decode.
    use super::*;

    fn decodes(bytes: &[u8]) {
        nextgcore_ngap_gen::decode(bytes)
            .unwrap_or_else(|e| panic!("the generated codec refused {bytes:02x?}: {e:?}"));
    }

    /// The Cause numbering by name: handover-desirable-for-radio-reason is
    /// radioNetwork root index 16 (`000 0 010000` -> `04 00`);
    /// n26-interface-not-available is the first radioNetwork addition (`000 1
    /// 0 000000` -> `10 00`); uE-not-in-PLMN-serving-area the first nas
    /// addition (`010 1 0 000000` -> `50 00`); misc unspecified root index 5
    /// of 6 (`100 0 101` -> `8a`).
    #[test]
    fn causes_are_numbered_by_their_asn1_names() {
        use t::{Cause as C, CauseMisc, CauseNas, CauseRadioNetwork as Rn};
        assert_eq!(
            cause(&C::RadioNetwork(Rn::HandoverDesirableForRadioReason)),
            [0x04, 0x00]
        );
        assert_eq!(
            cause(&C::RadioNetwork(Rn::N26InterfaceNotAvailable)),
            [0x10, 0x00]
        );
        assert_eq!(
            cause(&C::Nas(CauseNas::UeNotInPlmnServingArea)),
            [0x50, 0x00]
        );
        assert_eq!(cause(&C::Misc(CauseMisc::Unspecified)), [0x8a]);
        // The module's `unkown-qos-flow-ID` is radioNetwork 27.
        assert_eq!(asn1_cause(&C::RadioNetwork(Rn::UnknownQosFlowId)), (0, 27));
    }

    /// Criticality Diagnostics with a procedure (code 42, initiating message,
    /// ignore) and one IE (4000, reject, missing): `0 1 1 1 1 0` + pad `78`;
    /// `2a`; trigger `00`, criticality `01` + pad `10`; count-1 `00`; item
    /// extension, iE-Extensions, criticality `00` + pad `00`; id `0f a0`;
    /// TypeOfError extension `0`, missing `1` + pad `40`.
    #[test]
    fn criticality_diagnostics_is_the_worked_vector() {
        let d = criticality_diagnostics(
            Some((42, 0, 1)),
            &[IeDiagnostic {
                ie_id: 4000,
                criticality: 0,
                type_of_error: 1,
            }],
        );
        assert_eq!(d, [0x78, 0x2a, 0x10, 0x00, 0x00, 0x0f, 0xa0, 0x40]);
    }

    /// HANDOVER COMMAND, AMF UE 1, RAN UE 2, intra5gs, one session (PSI 1,
    /// transfer `00 01`), container `ab`: `20` successfulOutcome, `0c`
    /// procedure 12, `00` reject, length 36; `00`, five IEs `00 05`; id 10
    /// reject length 2 `00 01`; id 85 `00 02`; id 29 length 1 `00`; id 59
    /// ignore length 6: count-1 `00`, item bits + pad `00`, PSI `01`, length
    /// `02`, `00 01`; id 106 reject length 2: `01 ab`.
    #[test]
    fn handover_command_is_the_worked_vector() {
        let m = t::HandoverCommand {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            handover_type: t::HandoverType::Intra5gs,
            nas_security_parameters_from_ngran: None,
            pdu_session_list: vec![t::PduSessionResourceHandoverItem {
                pdu_session_id: 1,
                transfer: vec![0x00, 0x01],
            }],
            release_list: None,
            target_to_source_container: vec![0xab],
        };
        let expected = [
            0x20, 0x0c, 0x00, 0x24, 0x00, 0x00, 0x05, // PDU, 5 IEs
            0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, // AMF UE NGAP ID
            0x00, 0x55, 0x00, 0x02, 0x00, 0x02, // RAN UE NGAP ID
            0x00, 0x1d, 0x00, 0x01, 0x00, // HandoverType
            0x00, 0x3b, 0x40, 0x06, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01, // handover list
            0x00, 0x6a, 0x00, 0x02, 0x01, 0xab, // TargetToSource
        ];
        assert_eq!(handover_command(&m), expected);
        decodes(&expected);
    }

    /// HANDOVER REQUEST, the minimal shape: AMF UE 1, intra5gs, cause
    /// handover-desirable-for-radio-reason, AMBR 1/1, NR encryption `e000`
    /// and the other sets 0, NCC 0 with a zero key, one session (PSI 1, SST
    /// 1, transfer `00`), allowed SST 1, container `ab`, GUAMI 999/70 region
    /// 1 set 1 pointer 1:
    /// - `00 0d 00` + length 112; `00 00 0a`;
    /// - id 10 `00 0a 00 02 00 01`; id 29 `00 1d 00 01 00`; id 15 ignore
    ///   `00 0f 40 02 04 00`;
    /// - id 110 length 4: AMBR extension and iE-Extensions, DL extension `0`
    ///   and count `000` + pad `00`, `01`; UL `00 01`;
    /// - id 119 length 9: `000` then `e000` from bit 3: `1c`, then zeros
    ///   (70 bits, padded to nine octets);
    /// - id 93 length 33: `00 000` + pad `00`, then the 32-octet key;
    /// - id 73 length 7: count-1 `00`, item bits + pad `00`, PSI `01`,
    ///   S-NSSAI `000` + SST `0000 0001` -> `00 20`, length `01`, `00`;
    /// - id 0 length 2: count-1 `000`, item `00`, S-NSSAI `000`, SST: `00 01`;
    /// - id 101 `01 ab`; id 28 length 7: `00`, `99 f9 07`, region `01`, set
    ///   `00 0000 0001`, pointer `00 0001` -> `01 00 41`.
    #[test]
    fn handover_request_is_the_worked_vector() {
        let m = t::HandoverRequest {
            amf_ue_ngap_id: 1,
            handover_type: t::HandoverType::Intra5gs,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverDesirableForRadioReason),
            ue_ambr: t::UeAmbrInfo { dl: 1, ul: 1 },
            ue_security_capabilities: t::UeSecurityCapabilities {
                nr_encryption_algorithms: 0xe000,
                nr_integrity_algorithms: 0,
                eutra_encryption_algorithms: 0,
                eutra_integrity_algorithms: 0,
            },
            security_context: t::SecurityContext {
                next_hop_chaining_count: 0,
                next_hop: [0; 32],
            },
            pdu_session_list: vec![t::PduSessionResourceSetupItemHoReq {
                pdu_session_id: 1,
                s_nssai: t::SNssai { sst: 1, sd: None },
                transfer: vec![0x00],
            }],
            allowed_nssai: vec![t::SNssai { sst: 1, sd: None }],
            source_to_target_container: vec![0xab],
            guami: t::Guami {
                plmn_identity: [0x99, 0xf9, 0x07],
                amf_region_id: 1,
                amf_set_id: 1,
                amf_pointer: 1,
            },
        };
        let mut expected = vec![0x00, 0x0d, 0x00, 0x70, 0x00, 0x00, 0x0a];
        expected.extend([0x00, 0x0a, 0x00, 0x02, 0x00, 0x01]);
        expected.extend([0x00, 0x1d, 0x00, 0x01, 0x00]);
        expected.extend([0x00, 0x0f, 0x40, 0x02, 0x04, 0x00]);
        expected.extend([0x00, 0x6e, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);
        expected.extend([0x00, 0x77, 0x00, 0x09, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend([0x00, 0x5d, 0x00, 0x21, 0x00]);
        expected.extend([0x00; 32]);
        expected.extend([
            0x00, 0x49, 0x00, 0x07, 0x00, 0x00, 0x01, 0x00, 0x20, 0x01, 0x00,
        ]);
        expected.extend([0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);
        expected.extend([0x00, 0x65, 0x00, 0x02, 0x01, 0xab]);
        expected.extend([
            0x00, 0x1c, 0x00, 0x07, 0x00, 0x99, 0xf9, 0x07, 0x01, 0x00, 0x41,
        ]);
        assert_eq!(expected.len(), 116);
        assert_eq!(handover_request(&m), expected);
        decodes(&expected);
    }

    /// PATH SWITCH REQUEST ACKNOWLEDGE, AMF UE 1, RAN UE 2, no capabilities,
    /// NCC 3 and key `a5`*32, one switched session (PSI 1, `00 01`), allowed
    /// SST 1: `20 19 00` + length 68, `00 00 05`; ids 10/85 ignore; id 93
    /// reject length 33: `00 011` + pad `18`, the key; id 77 ignore length 6;
    /// id 0 reject `00 01`.
    #[test]
    fn path_switch_request_acknowledge_is_the_worked_vector() {
        let m = t::PathSwitchRequestAcknowledge {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            ue_security_capabilities: None,
            security_context: t::SecurityContext {
                next_hop_chaining_count: 3,
                next_hop: [0xa5; 32],
            },
            switched_list: vec![t::PduSessionResourceSwitchedItem {
                pdu_session_id: 1,
                transfer: vec![0x00, 0x01],
            }],
            released_list: None,
            allowed_nssai: vec![t::SNssai { sst: 1, sd: None }],
        };
        let mut expected = vec![0x20, 0x19, 0x00, 0x44, 0x00, 0x00, 0x05];
        expected.extend([0x00, 0x0a, 0x40, 0x02, 0x00, 0x01]);
        expected.extend([0x00, 0x55, 0x40, 0x02, 0x00, 0x02]);
        expected.extend([0x00, 0x5d, 0x00, 0x21, 0x18]);
        expected.extend([0xa5; 32]);
        expected.extend([0x00, 0x4d, 0x40, 0x06, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01]);
        expected.extend([0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);
        assert_eq!(path_switch_request_acknowledge(&m, &[]), expected);
        decodes(&expected);
    }

    /// PATH SWITCH REQUEST FAILURE, AMF UE 1, RAN UE 2, one released session
    /// (PSI 1, `00 e0`): `40` unsuccessfulOutcome, `19`, `00`, length 25;
    /// `00 00 03`; ids 10/85 ignore; id 69 ignore length 6: `00 00 01 02 00
    /// e0`.
    #[test]
    fn path_switch_request_failure_is_the_worked_vector() {
        let expected = [
            0x40, 0x19, 0x00, 0x19, 0x00, 0x00, 0x03, //
            0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
            0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
            0x00, 0x45, 0x40, 0x06, 0x00, 0x00, 0x01, 0x02, 0x00, 0xe0,
        ];
        let released = [t::PduSessionResourceReleasedItem {
            pdu_session_id: 1,
            transfer: vec![0x00, 0xe0],
        }];
        assert_eq!(path_switch_request_failure(1, 2, &released, &[]), expected);
        decodes(&expected);
    }

    /// RAN CONFIGURATION UPDATE ACKNOWLEDGE with one notify diagnostic (9999,
    /// not-understood): `20 23 00` length 13, `00 00 01`; id 19 ignore length
    /// 6: `0 000 1 0` + pad `08`, count-1 `00`, item `00 10` + pad `20`, id
    /// `27 0f`, TypeOfError `00`. With nothing to report: `20 23 00 03 00 00
    /// 00`.
    #[test]
    fn ran_configuration_update_acknowledge_is_the_worked_vector() {
        let notify = [IeDiagnostic {
            ie_id: 9999,
            criticality: 2,
            type_of_error: 0,
        }];
        let expected = [
            0x20, 0x23, 0x00, 0x0d, 0x00, 0x00, 0x01, //
            0x00, 0x13, 0x40, 0x06, 0x08, 0x00, 0x20, 0x27, 0x0f, 0x00,
        ];
        assert_eq!(ran_configuration_update_acknowledge(&notify), expected);
        assert_eq!(
            ran_configuration_update_acknowledge(&[]),
            [0x20, 0x23, 0x00, 0x03, 0x00, 0x00, 0x00]
        );
        decodes(&expected);
    }

    /// RAN CONFIGURATION UPDATE FAILURE, misc unspecified, v1s: `40 23 00`
    /// length 13, `00 00 02`; id 15 ignore `8a`; id 107 ignore `0 000` + pad
    /// `00`.
    #[test]
    fn ran_configuration_update_failure_is_the_worked_vector() {
        let expected = [
            0x40, 0x23, 0x00, 0x0d, 0x00, 0x00, 0x02, //
            0x00, 0x0f, 0x40, 0x01, 0x8a, 0x00, 0x6b, 0x40, 0x01, 0x00,
        ];
        assert_eq!(
            ran_configuration_update_failure(
                &t::Cause::Misc(t::CauseMisc::Unspecified),
                Some(t::TimeToWait::V1s),
                &[]
            ),
            expected
        );
        decodes(&expected);
    }

    /// The failed-list PATH SWITCH REQUEST is the no-failed-list derivation
    /// of [`crate::gnb_pdus::path_switch_request`] (written independently)
    /// with one more IE: id 57 `00 39`, ignore `40`, length 6, count-1 `00`,
    /// item `00`, PSI `14`, length `02`, `00 14`; IE count and open-type
    /// length grow by one and ten.
    #[test]
    fn a_path_switch_request_with_a_failed_list_is_the_gnb_stand_in_plus_ie_57() {
        let mut m = t::PathSwitchRequest {
            ran_ue_ngap_id: 2,
            source_amf_ue_ngap_id: 1,
            user_location_info: t::UserLocationInformation::Nr {
                nr_cgi_plmn: [0x99, 0xf9, 0x07],
                nr_cell_identity: 1,
                tai_plmn: [0x99, 0xf9, 0x07],
                tai_tac: [0, 0, 7],
            },
            ue_security_capabilities: t::UeSecurityCapabilities {
                nr_encryption_algorithms: 0xe000,
                nr_integrity_algorithms: 0x6000,
                eutra_encryption_algorithms: 0xf000,
                eutra_integrity_algorithms: 0x7001,
            },
            pdu_session_list: vec![t::PduSessionResourceSwitchItem {
                pdu_session_id: 1,
                transfer: vec![0x00, 0x01, 0x33],
            }],
            failed_list: None,
        };
        let plain = crate::gnb_pdus::path_switch_request(&m);
        assert_eq!(path_switch_request(&m), plain);
        m.failed_list = Some(vec![t::PduSessionResourceFailedItem {
            pdu_session_id: 20,
            transfer: vec![0x00, 0x14],
        }]);
        let mut expected = plain.clone();
        assert!(expected[3] < 0x80 - 10, "short-form length");
        expected[3] += 10;
        expected[6] += 1;
        expected.extend([0x00, 0x39, 0x40, 0x06, 0x00, 0x00, 0x14, 0x02, 0x00, 0x14]);
        assert_eq!(path_switch_request(&m), expected);
        decodes(&expected);
    }
}
