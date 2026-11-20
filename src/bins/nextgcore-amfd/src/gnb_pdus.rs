//! #417 stage B3.3: the NGAP PDUs amfd's tests stand in for a gNB or a CBCF
//! with. They are octets derived by hand from the TS 38.413 ASN.1 and
//! X.691 ALIGNED, through [`crate::aper_golden::Bits`], with the derivation
//! written beside each builder. They used to come from the hand-written
//! `nextgcore-ngap` builders.
//!
//! Each builder is pinned twice in this module's tests: by a vector worked out
//! octet by octet in the test, and by the generated codec's strict decode,
//! which has to read those octets as the PDU the builder says they are.
//!
//! Which release: the ASN.1 is V17.9.0, the module vendored at
//! `libs/nextgcore-ngap-gen/asn/ngap-17.9.asn` (see its `PROVENANCE.md`), which
//! is what the generated codec is compiled from. The § numbers cite the prose
//! of TS 38.413 V19.3.0 (`38413-j30`), the text kept with the specs; the message
//! and IE sections cited here carry the same numbers there.

use crate::aper_golden::{pdu, Bits};

/// MessageIdentifier / SerialNumber `BIT STRING (SIZE(16))`: fixed, sixteen
/// bits, so as the whole IE value two octets.
fn sixteen_bits(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// NR-CGI (§9.3.1.7): extension `0`, iE-Extensions `0`; PLMNIdentity
/// `OCTET STRING (SIZE(3))` aligned with no length (§17.6); NRCellIdentity
/// `BIT STRING (SIZE(36))`, fixed and longer than sixteen bits, so aligned
/// with no length (§16.10).
fn nr_cgi(b: &mut Bits, plmn: [u8; 3], nci: u64) {
    b.field(0, 2).octets(&plmn).align().field(nci, 36);
}

/// WRITE-REPLACE WARNING REQUEST (§9.2.8.1) as a CBCF sends it, with a Data
/// Coding Scheme and Warning Message Contents and no area list:
///
/// - initiatingMessage, id-WriteReplaceWarning 51, reject;
/// - id 35 MessageIdentifier, id 95 SerialNumber (reject): two octets each;
/// - id 87 RepetitionPeriod (reject): `INTEGER (0..131071)` is past 64K, so
///   the octet count n (1..3) as n-1 in two bits, padded, then n octets;
/// - id 47 NumberOfBroadcastsRequested (reject): `INTEGER (0..65535)`, range
///   65536, two aligned octets (§11.5.7.3);
/// - id 20 DataCodingScheme (ignore): `BIT STRING (SIZE(8))`, one octet;
/// - id 123 WarningMessageContents (ignore): `OCTET STRING (SIZE(1..9600))`,
///   so its length is a constrained whole number, length-1 in two aligned
///   octets (range 9600, §11.5.7.3, §17.8), then the octets.
pub(crate) fn write_replace_warning_request(
    message_identifier: u16,
    serial_number: u16,
    repetition_period: u32,
    broadcasts: u16,
    data_coding_scheme: u8,
    contents: &[u8],
) -> Vec<u8> {
    assert!((1..=9600).contains(&contents.len()));
    let repetition = crate::aper_golden::long_integer(u64::from(repetition_period), 2);
    let mut warning = Bits::default();
    warning
        .octets(&(contents.len() as u16 - 1).to_be_bytes())
        .octets(contents);
    pdu(
        0,
        51,
        0,
        &[
            (35, 0, sixteen_bits(message_identifier)),
            (95, 0, sixteen_bits(serial_number)),
            (87, 0, repetition),
            (47, 0, broadcasts.to_be_bytes().to_vec()),
            (20, 1, vec![data_coding_scheme]),
            (123, 1, warning.finish()),
        ],
    )
}

/// PWS CANCEL REQUEST (§9.2.8.3), no area list: initiatingMessage, id-PWSCancel
/// 32, reject; ids 35 and 95 as above; id 14 CancelAllWarningMessages (reject)
/// when cancelling all, `ENUMERATED {true, ...}`, one extension bit, padded `00`.
pub(crate) fn pws_cancel_request(
    message_identifier: u16,
    serial_number: u16,
    cancel_all: bool,
) -> Vec<u8> {
    let mut ies = vec![
        (35, 0, sixteen_bits(message_identifier)),
        (95, 0, sixteen_bits(serial_number)),
    ];
    if cancel_all {
        ies.push((14, 0, vec![0x00]));
    }
    pdu(0, 32, 0, &ies)
}

/// PWS FAILURE INDICATION (§9.2.8.6) from a gNB, one failed NR cell:
///
/// - initiatingMessage, id-PWSFailureIndication 33, ignore;
/// - id 81 PWSFailedCellIDList (reject): CHOICE of three (not extensible)
///   nR-CGI-PWSFailedList `01`, padded; NR-CGIList `SIZE(1..16384)`, count-1 in
///   two aligned octets (range 16384); the NR-CGI;
/// - id 27 GlobalRANNodeID (reject): CHOICE of four globalGNB-ID `00`;
///   GlobalGNB-ID extension `0`, iE-Extensions `0`; the PLMN; GNB-ID CHOICE of
///   two gNB-ID `0`; `BIT STRING (SIZE(22..32))`: length-22 in four bits
///   (range 11), then the bits aligned (§16.11). The gNB ID is the low
///   `gnb_id_len` bits of `gnb_id`.
pub(crate) fn pws_failure_indication(
    plmn: [u8; 3],
    failed_nci: u64,
    gnb_id: u32,
    gnb_id_len: u32,
) -> Vec<u8> {
    assert!((22..=32).contains(&gnb_id_len));
    let mut cells = Bits::default();
    cells.field(1, 2).octets(&[0x00, 0x00]);
    nr_cgi(&mut cells, plmn, failed_nci);
    let mut node = Bits::default();
    node.field(0, 2).field(0, 2).octets(&plmn);
    node.bit(false)
        .field(u64::from(gnb_id_len - 22), 4)
        .align()
        .field(u64::from(gnb_id), gnb_id_len);
    pdu(0, 33, 1, &[(81, 0, cells.finish()), (27, 0, node.finish())])
}

/// WRITE-REPLACE WARNING RESPONSE (§9.2.8.2) from a gNB:
///
/// - successfulOutcome, id-WriteReplaceWarning 51, reject; ids 35 and 95;
/// - id 13 BroadcastCompletedAreaList (ignore), when there are cells: CHOICE of
///   seven (not extensible) cellIDBroadcastNR `011`, padded; CellIDBroadcastNR
///   `SIZE(1..65535)`, count-1 in two aligned octets; per item extension `0`,
///   iE-Extensions `0`, then the NR-CGI.
pub(crate) fn write_replace_warning_response(
    message_identifier: u16,
    serial_number: u16,
    completed: Option<([u8; 3], &[u64])>,
) -> Vec<u8> {
    let mut ies = vec![
        (35, 0, sixteen_bits(message_identifier)),
        (95, 0, sixteen_bits(serial_number)),
    ];
    if let Some((plmn, cells)) = completed {
        let mut area = Bits::default();
        area.field(3, 3)
            .octets(&(cells.len() as u16 - 1).to_be_bytes());
        for &nci in cells {
            area.field(0, 2);
            nr_cgi(&mut area, plmn, nci);
        }
        ies.push((13, 1, area.finish()));
    }
    pdu(1, 51, 0, &ies)
}

// ---------------------------------------------------------------------------
// UE-associated stand-ins (#417 stage B3.3b). These take amfd's NGAP domain
// values (`nextgcore_ngap::types`, which move into amfd in stage B3.1) and
// derive the bytes themselves; no hand-written builder is involved.
// ---------------------------------------------------------------------------

use nextgcore_ngap::types as t;

/// A Cause (§9.3.1.2): CHOICE of six (not extensible) in three bits, then the
/// group ENUMERATED's extension bit `0` and its root index in the fewest bits
/// that hold the root (radioNetwork 45 values, six bits; transport 2, one;
/// nas 4, two; protocol 7, three; misc 6, three). The indices are read off the
/// V17.9 ASN.1 lists; only the causes the tests send are derived, any other
/// panics so its index is worked out before it is used.
pub(crate) fn cause(b: &mut Bits, c: &t::Cause) {
    let (choice, index, width) = match c {
        t::Cause::RadioNetwork(t::CauseRadioNetwork::Unspecified) => (0, 0, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverCancelled) => (0, 5, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::HoTargetNotAllowed) => (0, 8, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::TngrelocprepExpiry) => (0, 10, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::CellNotAvailable) => (0, 11, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::NoRadioResourcesAvailableInTargetCell) => {
            (0, 13, 6)
        }
        t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverDesirableForRadioReason) => (0, 16, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::UserInactivity) => (0, 20, 6),
        t::Cause::RadioNetwork(t::CauseRadioNetwork::RadioConnectionWithUeLost) => (0, 21, 6),
        t::Cause::Transport(t::CauseTransport::TransportResourceUnavailable) => (1, 0, 1),
        t::Cause::Transport(t::CauseTransport::Unspecified) => (1, 1, 1),
        t::Cause::Nas(t::CauseNas::NormalRelease) => (2, 0, 2),
        t::Cause::Protocol(t::CauseProtocol::SemanticError) => (3, 4, 3),
        t::Cause::Misc(t::CauseMisc::OmIntervention) => (4, 3, 3),
        t::Cause::Misc(t::CauseMisc::Unspecified) => (4, 5, 3),
        other => panic!("derive the ASN.1 index of {other:?} before using it"),
    };
    b.field(choice, 3).bit(false).field(index, width);
}

fn cause_value(c: &t::Cause) -> Vec<u8> {
    let mut b = Bits::default();
    cause(&mut b, c);
    b.finish()
}

/// UserLocationInformation (§9.3.1.16) from an NR cell: CHOICE of four (not
/// extensible) userLocationInformationNR `01`; UserLocationInformationNR
/// extension `0`, timeStamp `0`, iE-Extensions `0`; the NR-CGI; TAI extension
/// `0`, iE-Extensions `0`, the PLMN and TAC `OCTET STRING (SIZE(3))`, aligned.
pub(crate) fn user_location(loc: &t::UserLocationInformation) -> Vec<u8> {
    let t::UserLocationInformation::Nr {
        nr_cgi_plmn,
        nr_cell_identity,
        tai_plmn,
        tai_tac,
    } = loc;
    let mut b = Bits::default();
    b.field(1, 2).field(0, 3);
    nr_cgi(&mut b, *nr_cgi_plmn, *nr_cell_identity);
    b.field(0, 2).octets(tai_plmn).octets(tai_tac);
    b.finish()
}

/// INITIAL UE MESSAGE (§9.2.5.1): initiatingMessage, id-InitialUEMessage 15,
/// ignore; id 85 RAN-UE-NGAP-ID (reject); id 38 NAS-PDU (reject); id 121
/// UserLocationInformation (reject); id 90 RRCEstablishmentCause (ignore):
/// `ENUMERATED` with ten root values and two additions, so a root value is
/// extension `0` + four bits, and notAvailable (the first addition) is
/// extension `1` + the normally small number 0, `0` + six bits (§11.6.1);
/// id 112 UEContextRequest (ignore) when requested: `ENUMERATED {requested,
/// ...}`, one extension bit, `00`.
pub(crate) fn initial_ue_message(m: &t::InitialUeMessage) -> Vec<u8> {
    assert!(
        m.allowed_nssai.is_empty(),
        "Allowed NSSAI is not derived here"
    );
    let mut rrc = Bits::default();
    match m.rrc_establishment_cause {
        t::RrcEstablishmentCause::NotAvailable => rrc.bit(true).bit(false).field(0, 6),
        root => {
            let index = match root {
                t::RrcEstablishmentCause::Emergency => 0,
                t::RrcEstablishmentCause::HighPriorityAccess => 1,
                t::RrcEstablishmentCause::MtAccess => 2,
                t::RrcEstablishmentCause::MoSignalling => 3,
                t::RrcEstablishmentCause::MoData => 4,
                t::RrcEstablishmentCause::MoVoiceCall => 5,
                t::RrcEstablishmentCause::MoVideoCall => 6,
                t::RrcEstablishmentCause::MoSms => 7,
                t::RrcEstablishmentCause::MpsPriorityAccess => 8,
                t::RrcEstablishmentCause::McsPriorityAccess => 9,
                t::RrcEstablishmentCause::NotAvailable => unreachable!(),
            };
            rrc.bit(false).field(index, 4)
        }
    };
    let mut ies = vec![
        (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
        (38, 0, crate::aper_golden::open_value(&m.nas_pdu)),
        (121, 0, user_location(&m.user_location_info)),
        (90, 1, rrc.finish()),
    ];
    if m.ue_context_request == Some(true) {
        ies.push((112, 1, vec![0x00]));
    }
    pdu(0, 15, 1, &ies)
}

/// UPLINK NAS TRANSPORT (§9.2.5.3): initiatingMessage, id-UplinkNASTransport
/// 46, ignore; ids 10 AMF-UE-NGAP-ID, 85 RAN-UE-NGAP-ID and 38 NAS-PDU
/// (reject); id 121 UserLocationInformation (ignore).
pub(crate) fn uplink_nas_transport(m: &t::UplinkNasTransport) -> Vec<u8> {
    pdu(
        0,
        46,
        1,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (38, 0, crate::aper_golden::open_value(&m.nas_pdu)),
            (121, 1, user_location(&m.user_location_info)),
        ],
    )
}

/// UE CONTEXT RELEASE COMPLETE (§9.2.2.6): successfulOutcome,
/// id-UEContextRelease 41, reject; ids 10 and 85, both ignore.
pub(crate) fn ue_context_release_complete(m: &t::UeContextReleaseComplete) -> Vec<u8> {
    pdu(
        1,
        41,
        0,
        &[
            (10, 1, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 1, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
        ],
    )
}

/// UE CONTEXT RELEASE REQUEST (§9.2.2.4): initiatingMessage,
/// id-UEContextReleaseRequest 42, ignore; ids 10 and 85 (reject); id 15 Cause
/// (ignore). No PDU session list.
pub(crate) fn ue_context_release_request(m: &t::UeContextReleaseRequest) -> Vec<u8> {
    pdu(
        0,
        42,
        1,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (15, 1, cause_value(&m.cause)),
        ],
    )
}

/// NG RESET (§9.2.6.11) from a gNB: initiatingMessage, id-NGReset 20, reject;
/// id 15 Cause (ignore); id 88 ResetType (reject), a CHOICE of three (not
/// extensible):
/// - nG-Interface `00`, ResetAll `ENUMERATED {reset-all, ...}` one extension
///   bit, padded -> `00`;
/// - partOfNG-Interface `01`; UE-associatedLogicalNG-connectionList
///   `SIZE(1..65536)`: the upper bound is 64K, not below it, so the count is
///   NOT a constrained whole number but a general length determinant
///   (§11.9.4.2, §11.9.3.6): the count itself, one aligned octet below 128.
///   (My first derivation took it as count-1 in two octets, as for
///   SIZE(1..65535); the generated decoder then read an empty list.) Per item
///   extension `0`, presence AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, iE-Extensions
///   `0`, then each ID present as in [`crate::aper_golden::long_integer`]:
///   its length bits unaligned, its octets aligned.
pub(crate) fn ng_reset(m: &t::NgReset) -> Vec<u8> {
    let mut reset = Bits::default();
    match &m.reset_type {
        t::ResetType::NgInterface => {
            reset.field(0, 2).bit(false);
        }
        t::ResetType::PartOfNgInterface(items) => {
            assert!(items.len() < 128, "longer lists are not derived here");
            reset.field(1, 2).octets(&[items.len() as u8]);
            for item in items {
                reset
                    .bit(false)
                    .bit(item.amf_ue_ngap_id.is_some())
                    .bit(item.ran_ue_ngap_id.is_some())
                    .bit(false);
                if let Some(amf) = item.amf_ue_ngap_id {
                    long_integer_into(&mut reset, amf, 3);
                }
                if let Some(ran) = item.ran_ue_ngap_id {
                    long_integer_into(&mut reset, u64::from(ran), 2);
                }
            }
        }
    }
    pdu(
        0,
        20,
        0,
        &[(15, 1, cause_value(&m.cause)), (88, 0, reset.finish())],
    )
}

/// [`crate::aper_golden::long_integer`] written in place, mid-encoding: n-1 in
/// `width` bits where the sink is, then the octets aligned.
fn long_integer_into(b: &mut Bits, value: u64, width: u32) {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    b.field((8 - skip) as u64 - 1, width).octets(&be[skip..]);
}

/// GlobalRANNodeID (§9.3.1.5): CHOICE of four (not extensible):
/// - globalGNB-ID `00`: GlobalGNB-ID extension `0`, iE-Extensions `0`, the
///   PLMN, GNB-ID CHOICE of two gNB-ID `0`, `BIT STRING (SIZE(22..32))` as
///   length-22 in four bits then the bits aligned (§16.11);
/// - globalNgENB-ID `01`: GlobalNgENB-ID extension `0`, iE-Extensions `0`, the
///   PLMN, then [`ng_enb_id`].
pub(crate) fn global_ran_node_id(b: &mut Bits, id: &t::GlobalRanNodeId) {
    match id {
        t::GlobalRanNodeId::GlobalGnbId {
            plmn_identity,
            gnb_id,
            gnb_id_len,
        } => {
            let len = u32::from(*gnb_id_len);
            assert!((22..=32).contains(&len));
            b.field(0, 2).field(0, 2).octets(plmn_identity);
            b.bit(false)
                .field(u64::from(len - 22), 4)
                .align()
                .field(u64::from(*gnb_id), len);
        }
        t::GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
        } => {
            b.field(1, 2).field(0, 2).octets(plmn_identity);
            ng_enb_id_bits(b, ng_enb_id);
        }
    }
}

/// NgENB-ID (within Global ng-eNB ID, §9.3.1.8): CHOICE of four (not extensible), macroNgENB-ID `00`
/// `BIT STRING (SIZE(20))`, shortMacroNgENB-ID `01` `(SIZE(18))`,
/// longMacroNgENB-ID `10` `(SIZE(21))`; each fixed and longer than sixteen
/// bits, so aligned with no length (§16.10).
fn ng_enb_id_bits(b: &mut Bits, id: &t::NgEnbId) {
    let (choice, value, width) = match id {
        t::NgEnbId::Macro(v) => (0, *v, 20),
        t::NgEnbId::ShortMacro(v) => (1, *v, 18),
        t::NgEnbId::LongMacro(v) => (2, *v, 21),
    };
    b.field(choice, 2).align().field(u64::from(value), width);
}

/// One `SEQUENCE (SIZE(1..256)) OF` PDU session item list as the handover
/// messages carry them: count-1 in one aligned octet (range 256,
/// §11.5.7.2); per item extension `0`, iE-Extensions `0`, PDUSessionID
/// `INTEGER (0..255)` one aligned octet, then its transfer, an
/// `OCTET STRING (CONTAINING ...)` with its aligned length.
fn session_list(items: &[(u8, &[u8])]) -> Vec<u8> {
    assert!((1..=256).contains(&items.len()));
    let mut b = Bits::default();
    b.octets(&[(items.len() - 1) as u8]);
    for (psi, transfer) in items {
        b.field(0, 2).octets(&[*psi]).open(transfer);
    }
    b.finish()
}

/// HANDOVER REQUIRED (§9.2.3.1): initiatingMessage, id-HandoverPreparation
/// 12, reject:
/// - ids 10, 85 (reject);
/// - id 29 HandoverType (reject): `ENUMERATED {intra5gs, fivegs-to-eps,
///   eps-to-5gs, ..., fivegs-to-utran}`, extension `0` + two bits;
/// - id 15 Cause (ignore);
/// - id 105 TargetID (reject): CHOICE of three (not extensible),
///   targetRANNodeID `00` (extension `0`, iE-Extensions `0`, the
///   GlobalRANNodeID, the selected TAI as in [`user_location`]) or
///   targeteNB-ID `01` (extension `0`, iE-Extensions `0`, GlobalNgENB-ID
///   extension `0`, iE-Extensions `0`, the PLMN, the NgENB-ID; EPS-TAI
///   extension `0`, iE-Extensions `0`, the PLMN, EPS-TAC `OCTET STRING
///   (SIZE(2))`, fixed and at most two octets, so NOT aligned, §17.6);
/// - id 22 DirectForwardingPathAvailability (ignore), when present: one
///   extension bit, `00`;
/// - id 61 PDUSessionResourceListHORqd (reject): [`session_list`];
/// - id 101 SourceToTarget-TransparentContainer (reject): OCTET STRING.
pub(crate) fn handover_required(m: &t::HandoverRequired) -> Vec<u8> {
    let mut kind = Bits::default();
    kind.bit(false).field(
        match m.handover_type {
            t::HandoverType::Intra5gs => 0,
            t::HandoverType::FivegsToEps => 1,
            t::HandoverType::EpsTo5gs => 2,
        },
        2,
    );
    let mut target = Bits::default();
    match &m.target_id {
        t::TargetId::TargetRanNodeId {
            global_ran_node_id,
            selected_tai,
        } => {
            target.field(0, 2).field(0, 2);
            self::global_ran_node_id(&mut target, global_ran_node_id);
            target
                .field(0, 2)
                .octets(&selected_tai.tai_plmn)
                .octets(&selected_tai.tai_tac);
        }
        t::TargetId::TargetGlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
            selected_eps_tai,
        } => {
            target
                .field(1, 2)
                .field(0, 2)
                .field(0, 2)
                .octets(plmn_identity);
            ng_enb_id_bits(&mut target, ng_enb_id);
            target
                .field(0, 2)
                .octets(&selected_eps_tai.plmn_identity)
                .field(u64::from(u16::from_be_bytes(selected_eps_tai.tac)), 16);
        }
    }
    let sessions: Vec<(u8, &[u8])> = m
        .pdu_session_list
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    let mut ies = vec![
        (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
        (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
        (29, 0, kind.finish()),
        (15, 1, cause_value(&m.cause)),
        (105, 0, target.finish()),
    ];
    if m.direct_forwarding_path_availability.is_some() {
        ies.push((22, 1, vec![0x00]));
    }
    ies.push((61, 0, session_list(&sessions)));
    ies.push((
        101,
        0,
        crate::aper_golden::open_value(&m.source_to_target_container),
    ));
    pdu(0, 12, 0, &ies)
}

/// HANDOVER REQUEST ACKNOWLEDGE (§9.2.3.5): successfulOutcome,
/// id-HandoverResourceAllocation 13, reject; ids 10, 85 (ignore); id 53
/// PDUSessionResourceAdmittedList (ignore) and, when present, id 56
/// PDUSessionResourceFailedToSetupListHOAck (ignore), both [`session_list`];
/// id 106 TargetToSource-TransparentContainer (reject).
pub(crate) fn handover_request_acknowledge(m: &t::HandoverRequestAcknowledge) -> Vec<u8> {
    let admitted: Vec<(u8, &[u8])> = m
        .admitted_list
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    let mut ies = vec![
        (10, 1, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
        (85, 1, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
        (53, 1, session_list(&admitted)),
    ];
    if let Some(failed) = &m.failed_list {
        let failed: Vec<(u8, &[u8])> = failed
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect();
        ies.push((56, 1, session_list(&failed)));
    }
    ies.push((
        106,
        0,
        crate::aper_golden::open_value(&m.target_to_source_container),
    ));
    pdu(1, 13, 0, &ies)
}

/// HANDOVER CANCEL (§9.2.3.11): initiatingMessage, id-HandoverCancel 10,
/// reject; ids 10, 85 (reject); id 15 Cause (ignore).
pub(crate) fn handover_cancel(m: &t::HandoverCancel) -> Vec<u8> {
    pdu(
        0,
        10,
        0,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (15, 1, cause_value(&m.cause)),
        ],
    )
}

/// HANDOVER FAILURE (§9.2.3.6): unsuccessfulOutcome,
/// id-HandoverResourceAllocation 13, reject; id 10 (ignore); id 15 Cause
/// (ignore). No Criticality Diagnostics.
pub(crate) fn handover_failure(m: &t::HandoverFailure) -> Vec<u8> {
    assert!(
        m.criticality_diagnostics.is_none(),
        "Criticality Diagnostics are not derived here"
    );
    pdu(
        2,
        13,
        0,
        &[
            (10, 1, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (15, 1, cause_value(&m.cause)),
        ],
    )
}

/// HANDOVER NOTIFY (§9.2.3.7): initiatingMessage, id-HandoverNotification 11,
/// ignore; ids 10, 85 (reject); id 121 UserLocationInformation (ignore).
pub(crate) fn handover_notify(m: &t::HandoverNotify) -> Vec<u8> {
    pdu(
        0,
        11,
        1,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (121, 1, user_location(&m.user_location_info)),
        ],
    )
}

/// PATH SWITCH REQUEST (§9.2.3.8): initiatingMessage, id-PathSwitchRequest
/// 25, reject:
/// - id 85 RAN-UE-NGAP-ID, id 100 SourceAMF-UE-NGAP-ID (reject);
/// - id 121 UserLocationInformation (ignore);
/// - id 119 UESecurityCapabilities (ignore): extension `0`, iE-Extensions
///   `0`, then the four algorithm sets, each `BIT STRING (SIZE(16, ...))`: its
///   size-extension bit `0` and sixteen bits, fixed and at most sixteen bits,
///   so NOT aligned (§16.9);
/// - id 76 PDUSessionResourceToBeSwitchedDLList (reject): [`session_list`].
pub(crate) fn path_switch_request(m: &t::PathSwitchRequest) -> Vec<u8> {
    assert!(
        m.failed_list.is_none(),
        "the failed list is not derived here"
    );
    let c = &m.ue_security_capabilities;
    let mut caps = Bits::default();
    caps.field(0, 2);
    for set in [
        c.nr_encryption_algorithms,
        c.nr_integrity_algorithms,
        c.eutra_encryption_algorithms,
        c.eutra_integrity_algorithms,
    ] {
        caps.bit(false).field(u64::from(set), 16);
    }
    let sessions: Vec<(u8, &[u8])> = m
        .pdu_session_list
        .iter()
        .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
        .collect();
    pdu(
        0,
        25,
        0,
        &[
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (
                100,
                0,
                crate::aper_golden::amf_ue_ngap_id(m.source_amf_ue_ngap_id),
            ),
            (121, 1, user_location(&m.user_location_info)),
            (119, 1, caps.finish()),
            (76, 0, session_list(&sessions)),
        ],
    )
}

/// An NR-CGIList `SIZE(1..16384)`: count-1 in two aligned octets (range
/// 16384, §11.5.7.3), then each NR-CGI.
fn nr_cgi_list(b: &mut Bits, cells: &[t::NrCgi]) {
    assert!(!cells.is_empty());
    b.octets(&(cells.len() as u16 - 1).to_be_bytes());
    for c in cells {
        nr_cgi(b, c.plmn_identity, c.nr_cell_identity);
    }
}

fn nr_cells(list: &t::PwsCellList) -> &[t::NrCgi] {
    match list {
        t::PwsCellList::Nr(cells) => cells,
        t::PwsCellList::Eutra(_) => panic!("E-UTRA cell lists are not derived here"),
    }
}

fn global_ran_node_id_value(id: &t::GlobalRanNodeId) -> Vec<u8> {
    let mut b = Bits::default();
    global_ran_node_id(&mut b, id);
    b.finish()
}

/// PWS RESTART INDICATION (§9.2.8.5) from a gNB: initiatingMessage,
/// id-PWSRestartIndication 34, ignore:
/// - id 16 CellIDListForRestart (reject): CHOICE of three (not extensible)
///   nR-CGIListforRestart `01`, padded, then [`nr_cgi_list`];
/// - id 27 GlobalRANNodeID (reject): [`global_ran_node_id`];
/// - id 104 TAIListForRestart (reject): `SIZE(1..2048)`, count-1 in two
///   aligned octets (range 2048); per TAI extension `0`, iE-Extensions `0`,
///   the PLMN and TAC. No Emergency Area ID list.
pub(crate) fn pws_restart_indication(m: &t::PwsRestartIndication) -> Vec<u8> {
    assert!(
        m.emergency_area_id_list_for_restart.is_empty(),
        "the Emergency Area ID list is not derived here"
    );
    let mut cells = Bits::default();
    cells.field(1, 2);
    nr_cgi_list(&mut cells, nr_cells(&m.cell_list));
    let mut tais = Bits::default();
    tais.octets(&(m.tai_list_for_restart.len() as u16 - 1).to_be_bytes());
    for tai in &m.tai_list_for_restart {
        tais.field(0, 2).octets(&tai.tai_plmn).octets(&tai.tai_tac);
    }
    pdu(
        0,
        34,
        1,
        &[
            (16, 0, cells.finish()),
            (27, 0, global_ran_node_id_value(&m.global_ran_node_id)),
            (104, 0, tais.finish()),
        ],
    )
}

/// PWS FAILURE INDICATION (§9.2.8.6) for any number of failed NR cells: as
/// [`pws_failure_indication`], with the list's count-1 in its two octets.
pub(crate) fn pws_failure(m: &t::PwsFailureIndication) -> Vec<u8> {
    let mut cells = Bits::default();
    cells.field(1, 2);
    nr_cgi_list(&mut cells, nr_cells(&m.failed_cell_list));
    pdu(
        0,
        33,
        1,
        &[
            (81, 0, cells.finish()),
            (27, 0, global_ran_node_id_value(&m.global_ran_node_id)),
        ],
    )
}

/// [`write_replace_warning_request`] from the domain struct: only the members
/// that derivation covers may be set.
pub(crate) fn write_replace_warning(m: &t::WriteReplaceWarningRequest) -> Vec<u8> {
    assert!(
        m.warning_area_list.is_none()
            && m.warning_type.is_none()
            && m.warning_security_info.is_none()
            && !m.concurrent_warning_message_indicator
            && m.warning_area_coordinates.is_none(),
        "only the Data Coding Scheme and Warning Message Contents options are derived here"
    );
    write_replace_warning_request(
        m.message_identifier,
        m.serial_number,
        m.repetition_period,
        m.number_of_broadcasts_requested,
        m.data_coding_scheme.expect("a Data Coding Scheme"),
        m.warning_message_contents.as_deref().expect("contents"),
    )
}

/// [`write_replace_warning_response`] from the domain struct, with no
/// Broadcast Completed Area List and no Criticality Diagnostics.
pub(crate) fn write_replace_warning_answer(m: &t::WriteReplaceWarningResponse) -> Vec<u8> {
    assert!(
        m.broadcast_completed_area_list.is_none() && m.criticality_diagnostics.is_none(),
        "the optional lists are not derived here"
    );
    write_replace_warning_response(m.message_identifier, m.serial_number, None)
}

/// PWS CANCEL RESPONSE (§9.2.8.4): successfulOutcome, id-PWSCancel 32,
/// reject; ids 35 and 95 (reject). No Broadcast Cancelled Area List, no
/// Criticality Diagnostics.
pub(crate) fn pws_cancel_response(m: &t::PwsCancelResponse) -> Vec<u8> {
    assert!(
        m.broadcast_cancelled_area_list.is_none() && m.criticality_diagnostics.is_none(),
        "the optional lists are not derived here"
    );
    pdu(
        1,
        32,
        0,
        &[
            (35, 0, sixteen_bits(m.message_identifier)),
            (95, 0, sixteen_bits(m.serial_number)),
        ],
    )
}

/// The PDU session item lists of a session-management response: each
/// `SEQUENCE (SIZE(1..256)) OF` an item of the same shape (pDUSessionID, its
/// transfer as an `OCTET STRING (CONTAINING ...)`, iE-Extensions, `...`), so
/// [`session_list`]; an empty list is the optional IE left out.
macro_rules! items {
    ($list:expr) => {
        $list
            .iter()
            .map(|i| (i.pdu_session_id, i.transfer.as_slice()))
            .collect::<Vec<(u8, &[u8])>>()
    };
}

/// The two UE NGAP IDs at `criticality`, then each non-empty list as its IE.
fn session_response(
    amf: u64,
    ran: u32,
    id_criticality: u8,
    lists: &[(u16, u8, Vec<(u8, &[u8])>)],
) -> Vec<(u16, u8, Vec<u8>)> {
    let mut ies = vec![
        (10, id_criticality, crate::aper_golden::amf_ue_ngap_id(amf)),
        (85, id_criticality, crate::aper_golden::ran_ue_ngap_id(ran)),
    ];
    for (id, criticality, items) in lists {
        if !items.is_empty() {
            ies.push((*id, *criticality, session_list(items)));
        }
    }
    ies
}

/// PDU SESSION RESOURCE SETUP RESPONSE (§9.2.1.2): successfulOutcome,
/// id-PDUSessionResourceSetup 29, reject; ids 10, 85 (ignore); id 75
/// PDUSessionResourceSetupListSURes and id 58
/// PDUSessionResourceFailedToSetupListSURes (ignore).
pub(crate) fn pdu_session_resource_setup_response(
    m: &t::PduSessionResourceSetupResponse,
) -> Vec<u8> {
    let ies = session_response(
        m.amf_ue_ngap_id,
        m.ran_ue_ngap_id,
        1,
        &[
            (75, 1, items!(m.setup_list)),
            (58, 1, items!(m.failed_list)),
        ],
    );
    pdu(1, 29, 0, &ies)
}

/// PDU SESSION RESOURCE MODIFY RESPONSE (§9.2.1.6): successfulOutcome,
/// id-PDUSessionResourceModify 26, reject; ids 10, 85 (ignore); id 65
/// PDUSessionResourceModifyListModRes and id 54
/// PDUSessionResourceFailedToModifyListModRes (ignore).
pub(crate) fn pdu_session_resource_modify_response(
    m: &t::PduSessionResourceModifyResponse,
) -> Vec<u8> {
    let ies = session_response(
        m.amf_ue_ngap_id,
        m.ran_ue_ngap_id,
        1,
        &[
            (65, 1, items!(m.modify_list)),
            (54, 1, items!(m.failed_list)),
        ],
    );
    pdu(1, 26, 0, &ies)
}

/// PDU SESSION RESOURCE RELEASE RESPONSE (§9.2.1.4): successfulOutcome,
/// id-PDUSessionResourceRelease 28, reject; ids 10, 85 (ignore); id 70
/// PDUSessionResourceReleasedListRelRes (ignore, mandatory).
pub(crate) fn pdu_session_resource_release_response(
    m: &t::PduSessionResourceReleaseResponse,
) -> Vec<u8> {
    assert!(
        !m.released_list.is_empty(),
        "the released list is mandatory"
    );
    let ies = session_response(
        m.amf_ue_ngap_id,
        m.ran_ue_ngap_id,
        1,
        &[(70, 1, items!(m.released_list))],
    );
    pdu(1, 28, 0, &ies)
}

/// PDU SESSION RESOURCE NOTIFY (§9.2.1.7): initiatingMessage,
/// id-PDUSessionResourceNotify 30, ignore; ids 10, 85 (reject); id 66
/// PDUSessionResourceNotifyList (reject); id 67
/// PDUSessionResourceReleasedListNot (ignore).
pub(crate) fn pdu_session_resource_notify(m: &t::PduSessionResourceNotify) -> Vec<u8> {
    let ies = session_response(
        m.amf_ue_ngap_id,
        m.ran_ue_ngap_id,
        0,
        &[
            (66, 0, items!(m.notify_list)),
            (67, 1, items!(m.released_list)),
        ],
    );
    pdu(0, 30, 1, &ies)
}

/// PDU SESSION RESOURCE MODIFY INDICATION (§9.2.1.8): initiatingMessage,
/// id-PDUSessionResourceModifyIndication 27, reject; ids 10, 85 (reject); id
/// 63 PDUSessionResourceModifyListModInd (reject, mandatory).
pub(crate) fn pdu_session_resource_modify_indication(
    m: &t::PduSessionResourceModifyIndication,
) -> Vec<u8> {
    assert!(!m.modify_list.is_empty(), "the modify list is mandatory");
    let ies = session_response(
        m.amf_ue_ngap_id,
        m.ran_ue_ngap_id,
        0,
        &[(63, 0, items!(m.modify_list))],
    );
    pdu(0, 27, 0, &ies)
}

/// INITIAL CONTEXT SETUP RESPONSE (§9.2.2.2) with no session lists:
/// successfulOutcome, id-InitialContextSetup 14, reject; ids 10, 85 (ignore).
pub(crate) fn initial_context_setup_response(m: &t::InitialContextSetupResponse) -> Vec<u8> {
    pdu(
        1,
        14,
        0,
        &session_response(m.amf_ue_ngap_id, m.ran_ue_ngap_id, 1, &[]),
    )
}

/// INITIAL CONTEXT SETUP FAILURE (§9.2.2.3) with no session list:
/// unsuccessfulOutcome, id-InitialContextSetup 14, reject; ids 10, 85 and id
/// 15 Cause, all ignore.
pub(crate) fn initial_context_setup_failure(m: &t::InitialContextSetupFailure) -> Vec<u8> {
    let mut ies = session_response(m.amf_ue_ngap_id, m.ran_ue_ngap_id, 1, &[]);
    ies.push((15, 1, cause_value(&m.cause)));
    pdu(2, 14, 0, &ies)
}

/// RANNodeName, the ASN.1 `PrintableString (SIZE(1..150, ...))`: the size
/// extension bit `0`, length-1 in an 8-bit field (range 150, a constrained
/// whole number, not aligned), then the characters. PrintableString has 74
/// characters, so b = 7 and the ALIGNED variant rounds it to 8 bits per
/// character (§30.5.2); ub x 8 = 1200 bits is past 16, so the characters are
/// octet-aligned (§30.5.7), each its ASCII octet.
fn ran_node_name(name: &str) -> Vec<u8> {
    assert!((1..=150).contains(&name.len()) && name.is_ascii());
    let mut b = Bits::default();
    b.bit(false)
        .field(name.len() as u64 - 1, 8)
        .octets(name.as_bytes());
    b.finish()
}

/// SupportedTAList (the ASN.1 `SupportedTAList`, carried by NG Setup and RAN
/// Configuration Update):
/// - `SIZE(1..256)`: count-1 in one aligned octet (range 256);
/// - SupportedTAItem: extension `0`, iE-Extensions `0`; TAC `OCTET STRING
///   (SIZE(3))` aligned; BroadcastPLMNList `SIZE(1..12)`: count-1 in four bits;
/// - BroadcastPLMNItem: extension `0`, iE-Extensions `0`; the PLMN aligned;
///   SliceSupportList `SIZE(1..1024)`: ub 1024 is below 64K, so count-1 in two
///   aligned octets (range 1024);
/// - SliceSupportItem: extension `0`, iE-Extensions `0`; S-NSSAI extension
///   `0`, presence sD, iE-Extensions `0`; SST `OCTET STRING (SIZE(1))`, fixed
///   and at most two octets, so eight bits NOT aligned (§17.6); SD
///   `OCTET STRING (SIZE(3))` aligned.
fn supported_ta_list(items: &[t::SupportedTaItem]) -> Vec<u8> {
    assert!((1..=256).contains(&items.len()));
    let mut b = Bits::default();
    b.octets(&[(items.len() - 1) as u8]);
    for item in items {
        assert!((1..=12).contains(&item.broadcast_plmn_list.len()));
        b.field(0, 2)
            .octets(&item.tac)
            .field(item.broadcast_plmn_list.len() as u64 - 1, 4);
        for plmn in &item.broadcast_plmn_list {
            let slices = &plmn.tai_slice_support_list;
            assert!((1..=1024).contains(&slices.len()));
            b.field(0, 2)
                .octets(&plmn.plmn_identity)
                .octets(&(slices.len() as u16 - 1).to_be_bytes());
            for slice in slices {
                b.field(0, 2)
                    .bit(false)
                    .bit(slice.sd.is_some())
                    .bit(false)
                    .field(u64::from(slice.sst), 8);
                if let Some(sd) = slice.sd {
                    b.octets(&sd);
                }
            }
        }
    }
    b.finish()
}

/// PagingDRX `ENUMERATED {v32, v64, v128, v256, ...}`: extension `0` + two
/// bits, padded.
fn paging_drx(drx: t::PagingDrx) -> Vec<u8> {
    let index = match drx {
        t::PagingDrx::V32 => 0,
        t::PagingDrx::V64 => 1,
        t::PagingDrx::V128 => 2,
        t::PagingDrx::V256 => 3,
    };
    let mut b = Bits::default();
    b.bit(false).field(index, 2);
    b.finish()
}

/// NG SETUP REQUEST (§9.2.6.1): initiatingMessage, id-NGSetup 21, reject; id
/// 27 GlobalRANNodeID (reject); id 82 RANNodeName (ignore) when named; id 102
/// SupportedTAList (reject); id 21 DefaultPagingDRX (ignore).
pub(crate) fn ng_setup_request(m: &t::NgSetupRequest) -> Vec<u8> {
    let mut ies = vec![(27, 0, global_ran_node_id_value(&m.global_ran_node_id))];
    if let Some(name) = &m.ran_node_name {
        ies.push((82, 1, ran_node_name(name)));
    }
    ies.push((102, 0, supported_ta_list(&m.supported_ta_list)));
    ies.push((21, 1, paging_drx(m.default_paging_drx)));
    pdu(0, 21, 0, &ies)
}

/// RAN CONFIGURATION UPDATE (§9.2.6.4): initiatingMessage,
/// id-RANConfigurationUpdate 35, reject; each present member as its IE: id 82
/// RANNodeName (ignore), id 102 SupportedTAList (reject), id 21
/// DefaultPagingDRX (ignore), id 27 GlobalRANNodeID (ignore).
pub(crate) fn ran_configuration_update(m: &t::RanConfigurationUpdate) -> Vec<u8> {
    let mut ies = Vec::new();
    if let Some(name) = &m.ran_node_name {
        ies.push((82, 1, ran_node_name(name)));
    }
    if let Some(list) = &m.supported_ta_list {
        ies.push((102, 0, supported_ta_list(list)));
    }
    if let Some(drx) = m.default_paging_drx {
        ies.push((21, 1, paging_drx(drx)));
    }
    if let Some(id) = &m.global_ran_node_id {
        ies.push((27, 1, global_ran_node_id_value(id)));
    }
    pdu(0, 35, 0, &ies)
}

/// UPLINK RAN STATUS TRANSFER (§9.2.3.13): initiatingMessage,
/// id-UplinkRANStatusTransfer 49, ignore; ids 10, 85 (reject); id 84
/// RANStatusTransfer-TransparentContainer (reject). The container is a
/// SEQUENCE, not an OCTET STRING, so the IE's open type holds the caller's
/// octets, which must already be its complete encoding, directly.
pub(crate) fn uplink_ran_status_transfer(m: &t::RanStatusTransfer) -> Vec<u8> {
    pdu(
        0,
        49,
        1,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(m.amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(m.ran_ue_ngap_id)),
            (84, 0, m.container.clone()),
        ],
    )
}

/// UPLINK UE ASSOCIATED NRPPA TRANSPORT (§9.2.9.2): initiatingMessage,
/// id-UplinkUEAssociatedNRPPaTransport 50, ignore; ids 10, 85 (reject); id 89
/// RoutingID and id 46 NRPPa-PDU (reject), both unconstrained OCTET STRINGs.
pub(crate) fn uplink_ue_associated_nrppa_transport(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    routing_id: &[u8],
    nrppa_pdu: &[u8],
) -> Vec<u8> {
    pdu(
        0,
        50,
        1,
        &[
            (10, 0, crate::aper_golden::amf_ue_ngap_id(amf_ue_ngap_id)),
            (85, 0, crate::aper_golden::ran_ue_ngap_id(ran_ue_ngap_id)),
            (89, 0, crate::aper_golden::open_value(routing_id)),
            (46, 0, crate::aper_golden::open_value(nrppa_pdu)),
        ],
    )
}

/// UPLINK NON UE ASSOCIATED NRPPA TRANSPORT (§9.2.9.4): initiatingMessage,
/// id-UplinkNonUEAssociatedNRPPaTransport 47, ignore; id 89 RoutingID and id
/// 46 NRPPa-PDU (reject).
pub(crate) fn uplink_non_ue_associated_nrppa_transport(
    routing_id: &[u8],
    nrppa_pdu: &[u8],
) -> Vec<u8> {
    pdu(
        0,
        47,
        1,
        &[
            (89, 0, crate::aper_golden::open_value(routing_id)),
            (46, 0, crate::aper_golden::open_value(nrppa_pdu)),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_ngap_gen::generated as g;

    /// The IE ids of a PDU the generated codec decodes strictly, by message.
    fn ids(bytes: &[u8]) -> (u8, Vec<u16>) {
        macro_rules! ies {
            ($m:expr) => {
                $m.protocol_i_es.0.iter().map(|ie| ie.id.0).collect()
            };
        }
        match nextgcore_ngap_gen::decode(bytes).expect("strict generated decode") {
            g::NGAP_PDU::InitiatingMessage(m) => match m.value {
                g::InitiatingMessageValue::Id_WriteReplaceWarning(v) => (51, ies!(v)),
                g::InitiatingMessageValue::Id_PWSCancel(v) => (32, ies!(v)),
                g::InitiatingMessageValue::Id_PWSFailureIndication(v) => (33, ies!(v)),
                g::InitiatingMessageValue::Id_InitialUEMessage(v) => (15, ies!(v)),
                g::InitiatingMessageValue::Id_UplinkNASTransport(v) => (46, ies!(v)),
                g::InitiatingMessageValue::Id_UEContextReleaseRequest(v) => (42, ies!(v)),
                g::InitiatingMessageValue::Id_NGReset(v) => (20, ies!(v)),
                g::InitiatingMessageValue::Id_HandoverPreparation(v) => (12, ies!(v)),
                g::InitiatingMessageValue::Id_HandoverCancel(v) => (10, ies!(v)),
                g::InitiatingMessageValue::Id_HandoverNotification(v) => (11, ies!(v)),
                g::InitiatingMessageValue::Id_PathSwitchRequest(v) => (25, ies!(v)),
                g::InitiatingMessageValue::Id_PWSRestartIndication(v) => (34, ies!(v)),
                g::InitiatingMessageValue::Id_NGSetup(v) => (21, ies!(v)),
                g::InitiatingMessageValue::Id_RANConfigurationUpdate(v) => (35, ies!(v)),
                g::InitiatingMessageValue::Id_UplinkRANStatusTransfer(v) => (49, ies!(v)),
                g::InitiatingMessageValue::Id_UplinkUEAssociatedNRPPaTransport(v) => (50, ies!(v)),
                g::InitiatingMessageValue::Id_UplinkNonUEAssociatedNRPPaTransport(v) => {
                    (47, ies!(v))
                }
                g::InitiatingMessageValue::Id_PDUSessionResourceNotify(v) => (30, ies!(v)),
                g::InitiatingMessageValue::Id_PDUSessionResourceModifyIndication(v) => {
                    (27, ies!(v))
                }
                other => panic!("unexpected {other:?}"),
            },
            g::NGAP_PDU::SuccessfulOutcome(m) => match m.value {
                g::SuccessfulOutcomeValue::Id_WriteReplaceWarning(v) => (51, ies!(v)),
                g::SuccessfulOutcomeValue::Id_UEContextRelease(v) => (41, ies!(v)),
                g::SuccessfulOutcomeValue::Id_PWSCancel(v) => (32, ies!(v)),
                g::SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(v) => (29, ies!(v)),
                g::SuccessfulOutcomeValue::Id_PDUSessionResourceModify(v) => (26, ies!(v)),
                g::SuccessfulOutcomeValue::Id_PDUSessionResourceRelease(v) => (28, ies!(v)),
                g::SuccessfulOutcomeValue::Id_InitialContextSetup(v) => (14, ies!(v)),
                g::SuccessfulOutcomeValue::Id_HandoverResourceAllocation(v) => (13, ies!(v)),
                other => panic!("unexpected {other:?}"),
            },
            g::NGAP_PDU::UnsuccessfulOutcome(m) => match m.value {
                g::UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(v) => (13, ies!(v)),
                g::UnsuccessfulOutcomeValue::Id_InitialContextSetup(v) => (14, ies!(v)),
                other => panic!("unexpected {other:?}"),
            },
        }
    }

    #[test]
    fn write_replace_warning_request_is_the_worked_octets() {
        let pdu = write_replace_warning_request(0x1234, 0x5678, 32, 3, 0x01, b"TSUNAMI");
        assert_eq!(
            pdu,
            [
                0x00, 0x33, 0x00, 0x2d, // initiatingMessage, 51, reject, length 45
                0x00, 0x00, 0x06, // six IEs
                0x00, 0x23, 0x00, 0x02, 0x12, 0x34, // MessageIdentifier
                0x00, 0x5f, 0x00, 0x02, 0x56, 0x78, // SerialNumber
                0x00, 0x57, 0x00, 0x02, 0x00, 0x20, // RepetitionPeriod: n=1 `00`, 32
                0x00, 0x2f, 0x00, 0x02, 0x00, 0x03, // NumberOfBroadcastsRequested
                0x00, 0x14, 0x40, 0x01, 0x01, // DataCodingScheme, ignore
                0x00, 0x7b, 0x40, 0x09, 0x00, 0x06, // WarningMessageContents, length-1 6
                b'T', b'S', b'U', b'N', b'A', b'M', b'I',
            ]
        );
        assert_eq!(ids(&pdu), (51, vec![35, 95, 87, 47, 20, 123]));
    }

    #[test]
    fn pws_cancel_request_is_the_worked_octets() {
        let all = pws_cancel_request(0xA396, 0xC396, true);
        assert_eq!(
            all,
            [
                0x00, 0x20, 0x00, 0x14, // initiatingMessage, 32, reject, length 20
                0x00, 0x00, 0x03, //
                0x00, 0x23, 0x00, 0x02, 0xa3, 0x96, //
                0x00, 0x5f, 0x00, 0x02, 0xc3, 0x96, //
                0x00, 0x0e, 0x00, 0x01, 0x00, // CancelAllWarningMessages true
            ]
        );
        assert_eq!(ids(&all), (32, vec![35, 95, 14]));
        assert_eq!(ids(&pws_cancel_request(1, 2, false)), (32, vec![35, 95]));
    }

    #[test]
    fn pws_failure_indication_is_the_worked_octets() {
        let pdu = pws_failure_indication([0x00, 0xF1, 0x10], 0x396, 0x396, 32);
        assert_eq!(
            pdu,
            [
                0x00, 0x21, 0x40, 0x20, // initiatingMessage, 33, ignore, length 32
                0x00, 0x00, 0x02, //
                0x00, 0x51, 0x00, 0x0c, // PWSFailedCellIDList, reject, length 12
                0x40, 0x00, 0x00, // nR-CGI-PWSFailedList `01`, count-1 0
                0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x39, 0x60, // NR-CGI
                0x00, 0x1b, 0x00, 0x09, // GlobalRANNodeID, reject, length 9
                0x00, 0x00, 0xf1, 0x10, // globalGNB-ID `00`, `00`, the PLMN
                0x50, 0x00, 0x00, 0x03, 0x96, // gNB-ID `0` + length-22 `1010`, 32 bits
            ]
        );
        assert_eq!(ids(&pdu), (33, vec![81, 27]));
        // A 22-bit gNB ID: length-22 `0000`, then 22 bits padded.
        let short = pws_failure_indication([0x00, 0xF1, 0x10], 1, 0x2A_AAAA, 22);
        assert_eq!(&short[short.len() - 4..], [0x00, 0xaa, 0xaa, 0xa8]);
        assert_eq!(ids(&short), (33, vec![81, 27]));
    }

    #[test]
    fn write_replace_warning_response_is_the_worked_octets() {
        let pdu =
            write_replace_warning_response(0xE396, 0x1397, Some(([0x00, 0xF1, 0x10], &[0x399])));
        assert_eq!(
            pdu,
            [
                0x20, 0x33, 0x00, 0x1f, // successfulOutcome, 51, reject, length 31
                0x00, 0x00, 0x03, //
                0x00, 0x23, 0x00, 0x02, 0xe3, 0x96, //
                0x00, 0x5f, 0x00, 0x02, 0x13, 0x97, //
                0x00, 0x0d, 0x40, 0x0c, // BroadcastCompletedAreaList, ignore, length 12
                0x60, 0x00, 0x00, // cellIDBroadcastNR `011`, count-1 0
                0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x39, 0x90, // item + NR-CGI
            ]
        );
        assert_eq!(ids(&pdu), (51, vec![35, 95, 13]));
        assert_eq!(
            ids(&write_replace_warning_response(1, 2, None)),
            (51, vec![35, 95])
        );
    }

    fn loc() -> t::UserLocationInformation {
        t::UserLocationInformation::Nr {
            nr_cgi_plmn: [0x00, 0xF1, 0x10],
            nr_cell_identity: 1,
            tai_plmn: [0x00, 0xF1, 0x10],
            tai_tac: [0x00, 0x00, 0x01],
        }
    }

    /// UserLocationInformation for NR-CGI 00f110/1, TAI 00f110/000001:
    /// `01 000 00` + pad -> `40`, PLMN, NCI 36 bits `00 00 00 00 1` + TAI `00`
    /// + pad -> `00 00 00 00 10`, PLMN, TAC.
    const ULI: [u8; 15] = [
        0x40, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn uplink_nas_transport_is_the_worked_octets() {
        let pdu = uplink_nas_transport(&t::UplinkNasTransport {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            nas_pdu: vec![0x7e, 0x00, 0x43],
            user_location_info: loc(),
        });
        let mut expected = vec![
            0x00, 0x2e, 0x40, 0x2a, // initiatingMessage, 46, ignore, length 42
            0x00, 0x00, 0x04, //
            0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, // AMF-UE-NGAP-ID 1
            0x00, 0x55, 0x00, 0x02, 0x00, 0x02, // RAN-UE-NGAP-ID 2
            0x00, 0x26, 0x00, 0x04, 0x03, 0x7e, 0x00, 0x43, // NAS-PDU
            0x00, 0x79, 0x40, 0x0f, // UserLocationInformation, ignore, 15
        ];
        expected.extend_from_slice(&ULI);
        assert_eq!(pdu, expected);
        assert_eq!(ids(&pdu), (46, vec![10, 85, 38, 121]));
    }

    #[test]
    fn initial_ue_message_is_the_worked_octets() {
        let m = |cause, ue_context_request| t::InitialUeMessage {
            ran_ue_ngap_id: 512,
            nas_pdu: vec![0x7e, 0x00, 0x41],
            user_location_info: loc(),
            rrc_establishment_cause: cause,
            ue_context_request,
            allowed_nssai: Vec::new(),
        };
        let pdu = initial_ue_message(&m(t::RrcEstablishmentCause::MoSignalling, Some(true)));
        let mut expected = vec![
            0x00, 0x0f, 0x40, 0x2f, // initiatingMessage, 15, ignore, length 47
            0x00, 0x00, 0x05, //
            0x00, 0x55, 0x00, 0x03, 0x40, 0x02, 0x00, // RAN-UE-NGAP-ID 512: n=2 `01`
            0x00, 0x26, 0x00, 0x04, 0x03, 0x7e, 0x00, 0x41, // NAS-PDU
            0x00, 0x79, 0x00, 0x0f, // UserLocationInformation, reject, 15
        ];
        expected.extend_from_slice(&ULI);
        expected.extend_from_slice(&[0x00, 0x5a, 0x40, 0x01, 0x18]); // mo-Signalling `0 0011`
        expected.extend_from_slice(&[0x00, 0x70, 0x40, 0x01, 0x00]); // UEContextRequest
        assert_eq!(pdu, expected);
        assert_eq!(ids(&pdu), (15, vec![85, 38, 121, 90, 112]));
        // notAvailable, the first extension addition: `1 0 000000`, eight bits ->
        // `80`, one octet.
        let na = initial_ue_message(&m(t::RrcEstablishmentCause::NotAvailable, None));
        assert_eq!(&na[na.len() - 5..], [0x00, 0x5a, 0x40, 0x01, 0x80]);
        assert_eq!(ids(&na), (15, vec![85, 38, 121, 90]));
    }

    #[test]
    fn ue_context_release_pdus_are_the_worked_octets() {
        let complete = ue_context_release_complete(&t::UeContextReleaseComplete {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
        });
        assert_eq!(
            complete,
            [
                0x20, 0x29, 0x00, 0x0f, 0x00, 0x00, 0x02, // successfulOutcome, 41, reject
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02,
            ]
        );
        assert_eq!(ids(&complete), (41, vec![10, 85]));
        let request = ue_context_release_request(&t::UeContextReleaseRequest {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::UserInactivity),
        });
        assert_eq!(
            request,
            [
                0x00, 0x2a, 0x40, 0x15, 0x00, 0x00, 0x03, // initiatingMessage, 42, ignore
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
                0x00, 0x0f, 0x40, 0x02, 0x05, 0x00, // radioNetwork `000 0 010100`
            ]
        );
        assert_eq!(ids(&request), (42, vec![10, 85, 15]));
    }

    #[test]
    fn ng_reset_is_the_worked_octets() {
        let cause = t::Cause::Transport(t::CauseTransport::TransportResourceUnavailable);
        let whole = ng_reset(&t::NgReset {
            cause,
            reset_type: t::ResetType::NgInterface,
        });
        assert_eq!(
            whole,
            [
                0x00, 0x14, 0x00, 0x0d, 0x00, 0x00, 0x02, // initiatingMessage, 20, reject
                0x00, 0x0f, 0x40, 0x01, 0x20, // transport `001 0 0`
                0x00, 0x58, 0x00, 0x01, 0x00, // nG-Interface `00` reset-all `0`
            ]
        );
        assert_eq!(ids(&whole), (20, vec![15, 88]));
        let part = ng_reset(&t::NgReset {
            cause,
            reset_type: t::ResetType::PartOfNgInterface(vec![
                t::UeAssociatedLogicalNgConnectionItem {
                    amf_ue_ngap_id: Some(1),
                    ran_ue_ngap_id: Some(2),
                },
                t::UeAssociatedLogicalNgConnectionItem {
                    amf_ue_ngap_id: None,
                    ran_ue_ngap_id: Some(0x0102),
                },
            ]),
        });
        // `01` + pad, count `02`; item 1 `0 1 1 0` + AMF n=1 `000` + pad, `01`,
        // RAN n=1 `00` + pad, `02`; item 2 `0 0 1 0` + RAN n=2 `01` + pad,
        // `01 02`.
        assert_eq!(
            &part[part.len() - 11..],
            [0x00, 0x09, 0x40, 0x02, 0x60, 0x01, 0x00, 0x02, 0x24, 0x01, 0x02]
        );
        assert_eq!(ids(&part), (20, vec![15, 88]));
        // The production (generated) decoder reads the items back.
        let crate::ngap_asn1::NgResetDecode::Proceed { reset, .. } =
            crate::ngap_asn1::decode_ng_reset_asn1(&part)
        else {
            panic!("the derived NG Reset decodes");
        };
        let t::ResetType::PartOfNgInterface(items) = reset.reset_type else {
            panic!("partOfNG-Interface");
        };
        assert_eq!(
            items
                .iter()
                .map(|i| (i.amf_ue_ngap_id, i.ran_ue_ngap_id))
                .collect::<Vec<_>>(),
            [(Some(1), Some(2)), (None, Some(0x0102))]
        );
    }

    fn plmn() -> [u8; 3] {
        [0x00, 0xF1, 0x10]
    }

    fn required(target_id: t::TargetId) -> t::HandoverRequired {
        t::HandoverRequired {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            handover_type: t::HandoverType::Intra5gs,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id,
            pdu_session_list: vec![t::PduSessionResourceItemHoRqd {
                pdu_session_id: 5,
                transfer: vec![0x00],
            }],
            source_to_target_container: vec![0xAB, 0xCD],
            direct_forwarding_path_availability: None,
        }
    }

    #[test]
    fn handover_required_is_the_worked_octets() {
        let gnb = handover_required(&required(t::TargetId::TargetRanNodeId {
            global_ran_node_id: t::GlobalRanNodeId::GlobalGnbId {
                plmn_identity: plmn(),
                gnb_id: 0x7_4402,
                gnb_id_len: 22,
            },
            selected_tai: t::TaiListItem {
                tai_plmn: plmn(),
                tai_tac: [0x00, 0x00, 0x01],
            },
        }));
        assert_eq!(
            gnb,
            [
                0x00, 0x0c, 0x00, 0x3c, // initiatingMessage, 12, reject, length 60
                0x00, 0x00, 0x07, //
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
                0x00, 0x1d, 0x00, 0x01, 0x00, // HandoverType intra5gs `0 00`
                0x00, 0x0f, 0x40, 0x02, 0x04, 0x00, // radioNetwork 16 `000 0 010000`
                // TargetID (reject, 14): `00 00 00 00` -> `00`; PLMN; gNB-ID `0` +
                // length-22 `0000`, padded -> `00`; the 22 bits of 0x74402
                // `0001110100010000000010` + TAI `00` -> `1d 10 08`; PLMN; TAC.
                0x00, 0x69, 0x00, 0x0e, //
                0x00, 0x00, 0xf1, 0x10, 0x00, 0x1d, 0x10, 0x08, 0x00, 0xf1, 0x10, 0x00, 0x00,
                0x01, //
                // Session list (reject, 5): count-1 `00`, item `00` padded, PSI 5,
                // transfer length 1 `00`.
                0x00, 0x3d, 0x00, 0x05, 0x00, 0x00, 0x05, 0x01, 0x00, //
                0x00, 0x65, 0x00, 0x03, 0x02, 0xab, 0xcd, // container
            ]
        );
        assert_eq!(ids(&gnb), (12, vec![10, 85, 29, 15, 105, 61, 101]));
        // targeteNB-ID: `01 00 00` padded -> `40`; PLMN; macro `00` padded; 20
        // bits 0x12345 + EPS-TAI `00` -> `12 34 50`; PLMN; EPS-TAC unaligned,
        // here already on a boundary, `00 07`.
        let enb = handover_required(&required(t::TargetId::TargetGlobalNgEnbId {
            plmn_identity: plmn(),
            ng_enb_id: t::NgEnbId::Macro(0x1_2345),
            selected_eps_tai: t::EpsTai {
                plmn_identity: plmn(),
                tac: [0x00, 0x07],
            },
        }));
        let target = [
            0x00, 0x69, 0x00, 0x0d, 0x40, 0x00, 0xf1, 0x10, 0x00, 0x12, 0x34, 0x50, 0x00, 0xf1,
            0x10, 0x00, 0x07,
        ];
        assert!(enb.windows(target.len()).any(|w| w == target), "{enb:02x?}");
        assert_eq!(ids(&enb), (12, vec![10, 85, 29, 15, 105, 61, 101]));
    }

    #[test]
    fn handover_resource_allocation_outcomes_are_the_worked_octets() {
        let ack = handover_request_acknowledge(&t::HandoverRequestAcknowledge {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            admitted_list: vec![t::PduSessionResourceAdmittedItemHoAck {
                pdu_session_id: 5,
                transfer: vec![0xa1],
            }],
            failed_list: Some(vec![t::PduSessionResourceFailedItem {
                pdu_session_id: 2,
                transfer: vec![0xf2],
            }]),
            target_to_source_container: vec![0xc0, 0xfe],
        });
        assert_eq!(
            ack,
            [
                0x20, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x05, // successfulOutcome, 13, reject
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x35, 0x40, 0x05, 0x00, 0x00, 0x05, 0x01, 0xa1, // admitted
                0x00, 0x38, 0x40, 0x05, 0x00, 0x00, 0x02, 0x01, 0xf2, // failed
                0x00, 0x6a, 0x00, 0x03, 0x02, 0xc0, 0xfe,
            ]
        );
        assert_eq!(ids(&ack), (13, vec![10, 85, 53, 56, 106]));
        let failure = handover_failure(&t::HandoverFailure {
            amf_ue_ngap_id: 7,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::CellNotAvailable),
            criticality_diagnostics: None,
        });
        assert_eq!(
            failure,
            [
                0x40, 0x0d, 0x00, 0x0f, 0x00, 0x00, 0x02, // unsuccessfulOutcome `0 10`
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x07, //
                0x00, 0x0f, 0x40, 0x02, 0x02, 0xc0, // radioNetwork 11 `000 0 001011`
            ]
        );
        assert_eq!(ids(&failure), (13, vec![10, 15]));
    }

    #[test]
    fn handover_cancel_and_notify_are_the_worked_octets() {
        let cancel = handover_cancel(&t::HandoverCancel {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverCancelled),
        });
        assert_eq!(
            cancel,
            [
                0x00, 0x0a, 0x00, 0x15, 0x00, 0x00, 0x03, // initiatingMessage, 10, reject
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
                0x00, 0x0f, 0x40, 0x02, 0x01, 0x40, // radioNetwork 5 `000 0 000101`
            ]
        );
        assert_eq!(ids(&cancel), (10, vec![10, 85, 15]));
        let notify = handover_notify(&t::HandoverNotify {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            user_location_info: loc(),
        });
        let mut expected = vec![
            0x00, 0x0b, 0x40, 0x22, 0x00, 0x00, 0x03, // initiatingMessage, 11, ignore, 34
            0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
            0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
            0x00, 0x79, 0x40, 0x0f,
        ];
        expected.extend_from_slice(&ULI);
        assert_eq!(notify, expected);
        assert_eq!(ids(&notify), (11, vec![10, 85, 121]));
    }

    #[test]
    fn path_switch_request_is_the_worked_octets() {
        let pdu = path_switch_request(&t::PathSwitchRequest {
            ran_ue_ngap_id: 2,
            source_amf_ue_ngap_id: 1,
            user_location_info: loc(),
            ue_security_capabilities: t::UeSecurityCapabilities {
                nr_encryption_algorithms: 0xF000,
                nr_integrity_algorithms: 0xF000,
                eutra_encryption_algorithms: 0,
                eutra_integrity_algorithms: 0,
            },
            pdu_session_list: vec![t::PduSessionResourceSwitchItem {
                pdu_session_id: 1,
                transfer: vec![0x00],
            }],
            failed_list: None,
        });
        let mut expected = vec![
            0x00, 0x19, 0x00, 0x38, 0x00, 0x00, 0x05, // initiatingMessage, 25, reject, 56
            0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
            0x00, 0x64, 0x00, 0x02, 0x00, 0x01, // SourceAMF-UE-NGAP-ID
            0x00, 0x79, 0x40, 0x0f,
        ];
        expected.extend_from_slice(&ULI);
        // UESecurityCapabilities (ignore, 9): `00`, then `0` + f000, `0` + f000,
        // `0` + 0000, `0` + 0000, unaligned: `000 1111 0` `0000 0000` `0000 1111`,
        // zeros.
        expected.extend_from_slice(&[
            0x00, 0x77, 0x40, 0x09, 0x1e, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[0x00, 0x4c, 0x00, 0x05, 0x00, 0x00, 0x01, 0x01, 0x00]);
        assert_eq!(pdu, expected);
        assert_eq!(ids(&pdu), (25, vec![85, 100, 121, 119, 76]));
    }

    #[test]
    fn pws_restart_and_cancel_response_are_the_worked_octets() {
        let gnb = t::GlobalRanNodeId::GlobalGnbId {
            plmn_identity: plmn(),
            gnb_id: 0x686,
            gnb_id_len: 32,
        };
        let restart = pws_restart_indication(&t::PwsRestartIndication {
            cell_list: t::PwsCellList::Nr(vec![t::NrCgi {
                plmn_identity: plmn(),
                nr_cell_identity: 0x686,
            }]),
            global_ran_node_id: gnb.clone(),
            tai_list_for_restart: vec![t::TaiListItem {
                tai_plmn: plmn(),
                tai_tac: [0x00, 0x00, 0x74],
            }],
            emergency_area_id_list_for_restart: Vec::new(),
        });
        assert_eq!(
            restart,
            [
                0x00, 0x22, 0x40, 0x2d, 0x00, 0x00, 0x03, // initiatingMessage, 34, ignore, 45
                // CellIDListForRestart (reject, 12): `01` + pad, count-1 `00 00`,
                // NR-CGI `00` + pad, PLMN, NCI 0x686 in 36 bits.
                0x00, 0x10, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00,
                0x68, 0x60, //
                // GlobalRANNodeID (reject, 9): `00 00` + pad, PLMN, `0 1010` + pad, 32 bits.
                0x00, 0x1b, 0x00, 0x09, 0x00, 0x00, 0xf1, 0x10, 0x50, 0x00, 0x00, 0x06, 0x86,
                // TAIListForRestart (reject, 9): count-1 `00 00`, `00` + pad, PLMN, TAC.
                0x00, 0x68, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x74,
            ]
        );
        assert_eq!(ids(&restart), (34, vec![16, 27, 104]));
        // The two-cell failure indication: count-1 `00 01`.
        let failure = pws_failure(&t::PwsFailureIndication {
            failed_cell_list: t::PwsCellList::Nr(vec![
                t::NrCgi {
                    plmn_identity: plmn(),
                    nr_cell_identity: 1,
                },
                t::NrCgi {
                    plmn_identity: plmn(),
                    nr_cell_identity: 2,
                },
            ]),
            global_ran_node_id: gnb,
        });
        assert_eq!(&failure[11..14], [0x40, 0x00, 0x01]);
        assert_eq!(ids(&failure), (33, vec![81, 27]));
        let cancel = pws_cancel_response(&t::PwsCancelResponse {
            message_identifier: 0xB399,
            serial_number: 0xC399,
            broadcast_cancelled_area_list: None,
            criticality_diagnostics: None,
        });
        assert_eq!(
            cancel,
            [
                0x20, 0x20, 0x00, 0x0f, 0x00, 0x00, 0x02, // successfulOutcome, 32, reject
                0x00, 0x23, 0x00, 0x02, 0xb3, 0x99, //
                0x00, 0x5f, 0x00, 0x02, 0xc3, 0x99,
            ]
        );
        assert_eq!(ids(&cancel), (32, vec![35, 95]));
    }

    #[test]
    fn session_management_responses_are_the_worked_octets() {
        // Setup Response, one set-up session (PSI 1, transfer `a1`) and one
        // failed (PSI 2, `c1`): successfulOutcome `20`, 29 `1d`, reject.
        let setup = pdu_session_resource_setup_response(&t::PduSessionResourceSetupResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            setup_list: vec![t::PduSessionResourceSetupResponseItem {
                pdu_session_id: 1,
                transfer: vec![0xa1],
            }],
            failed_list: vec![t::PduSessionResourceFailedItem {
                pdu_session_id: 2,
                transfer: vec![0xc1],
            }],
        });
        assert_eq!(
            setup,
            [
                0x20, 0x1d, 0x00, 0x21, 0x00, 0x00, 0x04, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x4b, 0x40, 0x05, 0x00, 0x00, 0x01, 0x01, 0xa1, // id 75
                0x00, 0x3a, 0x40, 0x05, 0x00, 0x00, 0x02, 0x01, 0xc1, // id 58
            ]
        );
        assert_eq!(ids(&setup), (29, vec![10, 85, 75, 58]));
        // Notify: initiatingMessage, 30 `1e`, ignore; ids at reject; the notify
        // list at reject, no released list.
        let notify = pdu_session_resource_notify(&t::PduSessionResourceNotify {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            notify_list: vec![t::PduSessionResourceNotifyItem {
                pdu_session_id: 5,
                transfer: vec![0x51],
            }],
            released_list: Vec::new(),
        });
        assert_eq!(
            notify,
            [
                0x00, 0x1e, 0x40, 0x18, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
                0x00, 0x42, 0x00, 0x05, 0x00, 0x00, 0x05, 0x01, 0x51, // id 66
            ]
        );
        assert_eq!(ids(&notify), (30, vec![10, 85, 66]));
        let modify = pdu_session_resource_modify_response(&t::PduSessionResourceModifyResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            modify_list: vec![t::PduSessionResourceModifyResponseItem {
                pdu_session_id: 2,
                transfer: vec![0x21],
            }],
            failed_list: Vec::new(),
        });
        assert_eq!(&modify[..4], [0x20, 0x1a, 0x00, 0x18]);
        assert_eq!(ids(&modify), (26, vec![10, 85, 65]));
        let release =
            pdu_session_resource_release_response(&t::PduSessionResourceReleaseResponse {
                amf_ue_ngap_id: 1,
                ran_ue_ngap_id: 2,
                released_list: vec![t::PduSessionResourceReleasedItem {
                    pdu_session_id: 3,
                    transfer: Vec::new(),
                }],
            });
        // An empty transfer is its zero length octet.
        assert_eq!(
            &release[release.len() - 8..],
            [0x00, 0x46, 0x40, 0x04, 0x00, 0x00, 0x03, 0x00]
        );
        assert_eq!(ids(&release), (28, vec![10, 85, 70]));
        let indication =
            pdu_session_resource_modify_indication(&t::PduSessionResourceModifyIndication {
                amf_ue_ngap_id: 1,
                ran_ue_ngap_id: 2,
                modify_list: vec![t::PduSessionResourceModifyIndicationItem {
                    pdu_session_id: 6,
                    transfer: vec![0x61],
                }],
            });
        assert_eq!(&indication[..4], [0x00, 0x1b, 0x00, 0x18]);
        assert_eq!(ids(&indication), (27, vec![10, 85, 63]));
    }

    #[test]
    fn initial_context_setup_outcomes_are_the_worked_octets() {
        let response = initial_context_setup_response(&t::InitialContextSetupResponse {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
        });
        assert_eq!(
            response,
            [
                0x20, 0x0e, 0x00, 0x0f, 0x00, 0x00, 0x02, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02,
            ]
        );
        assert_eq!(ids(&response), (14, vec![10, 85]));
        let failure = initial_context_setup_failure(&t::InitialContextSetupFailure {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::Unspecified),
        });
        // unsuccessfulOutcome `40`; Cause radioNetwork 0 `000 0 000000` -> `00 00`.
        assert_eq!(
            failure,
            [
                0x40, 0x0e, 0x00, 0x15, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x0f, 0x40, 0x02, 0x00, 0x00,
            ]
        );
        assert_eq!(ids(&failure), (14, vec![10, 85, 15]));
    }

    /// R44 on #2213: Handover Required with Direct Forwarding Path
    /// Availability. IE 22 (ignore) goes between TargetID and the session list
    /// as `ENUMERATED {direct-path-available, ...}`: one extension bit,
    /// padded, `00`.
    #[test]
    fn handover_required_with_direct_forwarding_is_the_worked_octets() {
        let mut m = required(t::TargetId::TargetRanNodeId {
            global_ran_node_id: t::GlobalRanNodeId::GlobalGnbId {
                plmn_identity: plmn(),
                gnb_id: 0x7_4402,
                gnb_id_len: 22,
            },
            selected_tai: t::TaiListItem {
                tai_plmn: plmn(),
                tai_tac: [0x00, 0x00, 0x01],
            },
        });
        let without = handover_required(&m);
        m.direct_forwarding_path_availability =
            Some(t::DirectForwardingPathAvailability::DirectPathAvailable);
        let with = handover_required(&m);
        // The TargetID IE is the last of the first 48 octets of `without`
        // (header 4 + count 3 + ids 12 + type 5 + cause 6 + target 18): the
        // DFPA IE `00 16 40 01 00` follows it, the IE count goes 7 -> 8 and
        // the PDU length 60 -> 65.
        let mut expected = without.clone();
        expected[3] = 0x41;
        expected[6] = 0x08;
        expected.splice(48..48, [0x00, 0x16, 0x40, 0x01, 0x00]);
        assert_eq!(with, expected);
        assert_eq!(ids(&with), (12, vec![10, 85, 29, 15, 105, 22, 61, 101]));
        let crate::ngap_asn1::NasTransportDecode::Proceed { message, .. } =
            crate::ngap_asn1::decode_handover_required_asn1(&with)
        else {
            panic!("the derived Handover Required decodes");
        };
        assert!(message.direct_forwarding_path_availability.is_some());
    }

    /// R44 on #2213: the shortMacro (`01`, 18 bits) and longMacro (`10`, 21
    /// bits) ng-eNB ID arms, as the TargetID IE value of a Handover Required:
    /// `01 00 00` + pad -> `40`; PLMN; the arm's index, padded; the ID bits
    /// aligned; EPS-TAI `00`; padded; PLMN; EPS-TAC `00 07`.
    #[test]
    fn the_short_and_long_macro_ng_enb_ids_are_the_worked_octets() {
        let target = |id| {
            let pdu = handover_required(&required(t::TargetId::TargetGlobalNgEnbId {
                plmn_identity: plmn(),
                ng_enb_id: id,
                selected_eps_tai: t::EpsTai {
                    plmn_identity: plmn(),
                    tac: [0x00, 0x07],
                },
            }));
            assert_eq!(ids(&pdu), (12, vec![10, 85, 29, 15, 105, 61, 101]));
            let at = pdu
                .windows(2)
                .position(|w| w == [0x00, 0x69])
                .expect("TargetID");
            let len = pdu[at + 3] as usize;
            pdu[at + 4..at + 4 + len].to_vec()
        };
        // shortMacro 0x2ABCD in 18 bits `10 1010 1011 1100 1101`, then EPS-TAI
        // `00`: `1010 1010 1111 0011 0100` -> `aa f3 40`.
        assert_eq!(
            target(t::NgEnbId::ShortMacro(0x2_ABCD)),
            [0x40, 0x00, 0xf1, 0x10, 0x40, 0xaa, 0xf3, 0x40, 0x00, 0xf1, 0x10, 0x00, 0x07]
        );
        // longMacro 0x1ABCDE in 21 bits `1 1010 1011 1100 1101 1110`, then
        // EPS-TAI `00`: `1101 0101 1110 0110 1111 0000` -> `d5 e6 f0`.
        assert_eq!(
            target(t::NgEnbId::LongMacro(0x1A_BCDE)),
            [0x40, 0x00, 0xf1, 0x10, 0x80, 0xd5, 0xe6, 0xf0, 0x00, 0xf1, 0x10, 0x00, 0x07]
        );
    }

    /// NG Setup Request and RAN Configuration Update, by hand and read back
    /// through the generated decoder value by value (the SIZE(1..65536) lesson:
    /// an id-level decode check passes a wrong count).
    #[test]
    fn ng_setup_and_ran_configuration_update_are_the_worked_octets() {
        let ta = |tac: [u8; 3], sst: u8, sd: Option<[u8; 3]>| t::SupportedTaItem {
            tac,
            broadcast_plmn_list: vec![t::BroadcastPlmnItem {
                plmn_identity: [0x99, 0xf9, 0x07],
                tai_slice_support_list: vec![t::SNssai { sst, sd }],
            }],
        };
        let setup = ng_setup_request(&t::NgSetupRequest {
            global_ran_node_id: t::GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x99, 0xf9, 0x07],
                gnb_id: 1,
                gnb_id_len: 32,
            },
            ran_node_name: Some("g1".to_string()),
            supported_ta_list: vec![ta([0, 0, 1], 1, None)],
            default_paging_drx: t::PagingDrx::V128,
        });
        assert_eq!(
            setup,
            [
                0x00, 0x15, 0x00, 0x2e, 0x00, 0x00, 0x04, // initiatingMessage, 21, reject, 46
                // GlobalRANNodeID (reject, 9).
                0x00, 0x1b, 0x00, 0x09, 0x00, 0x99, 0xf9, 0x07, 0x50, 0x00, 0x00, 0x00, 0x01,
                // RANNodeName (ignore, 4): `0` + length-1 `00000001`, pad; "g1".
                0x00, 0x52, 0x40, 0x04, 0x00, 0x80, b'g', b'1', //
                // SupportedTAList (reject, 10): count-1 `00`; item `00` pad; TAC;
                // BPLMN count-1 `0000` + item `00` + pad; PLMN; slices count-1
                // `00 00`; `00` + `0 0 0` + SST `00000001` -> `00 08`.
                0x00, 0x66, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x99, 0xf9, 0x07, 0x00,
                0x00, 0x00, 0x08, //
                // DefaultPagingDRX (ignore, 1): v128 `0 10` -> `40`.
                0x00, 0x15, 0x40, 0x01, 0x40,
            ]
        );
        let g::NGAP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_NGSetup(req),
            ..
        }) = nextgcore_ngap_gen::decode(&setup).expect("strict decode")
        else {
            panic!("NG Setup Request");
        };
        use g::NGSetupRequestProtocolIEs_EntryValue as Ie;
        for ie in req.protocol_i_es.0 {
            match ie.value {
                Ie::Id_RANNodeName(n) => assert_eq!(n.0, "g1"),
                Ie::Id_SupportedTAList(l) => {
                    let item = &l.0[0];
                    assert_eq!(item.tac.0, [0, 0, 1]);
                    let bplmn = &item.broadcast_plmn_list.0[0];
                    assert_eq!(bplmn.plmn_identity.0, [0x99, 0xf9, 0x07]);
                    let s = &bplmn.tai_slice_support_list.0[0].s_nssai;
                    assert_eq!((s.sst.0.clone(), s.sd.is_none()), (vec![1], true));
                }
                Ie::Id_DefaultPagingDRX(d) => assert_eq!(d.0, g::PagingDRX::V128),
                Ie::Id_GlobalRANNodeID(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        // RAN Configuration Update with two TAs, the second with an SD.
        let rcu = ran_configuration_update(&t::RanConfigurationUpdate {
            ran_node_name: None,
            supported_ta_list: Some(vec![
                ta([0, 0, 7], 1, None),
                ta([0, 0, 8], 2, Some([1, 2, 3])),
            ]),
            default_paging_drx: None,
            global_ran_node_id: None,
        });
        assert_eq!(ids(&rcu), (35, vec![102]));
        let g::NGAP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_RANConfigurationUpdate(update),
            ..
        }) = nextgcore_ngap_gen::decode(&rcu).expect("strict decode")
        else {
            panic!("RAN Configuration Update");
        };
        let g::RANConfigurationUpdateProtocolIEs_EntryValue::Id_SupportedTAList(list) =
            &update.protocol_i_es.0[0].value
        else {
            panic!("SupportedTAList");
        };
        let read: Vec<_> = list
            .0
            .iter()
            .map(|item| {
                let s = &item.broadcast_plmn_list.0[0].tai_slice_support_list.0[0].s_nssai;
                (
                    item.tac.0.clone(),
                    s.sst.0.clone(),
                    s.sd.as_ref().map(|d| d.0.clone()),
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                (vec![0, 0, 7], vec![1], None),
                (vec![0, 0, 8], vec![2], Some(vec![1, 2, 3])),
            ]
        );
    }

    #[test]
    fn status_transfer_and_nrppa_transports_are_the_worked_octets() {
        let status = uplink_ran_status_transfer(&t::RanStatusTransfer {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            container: vec![
                0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x45, 0x00, 0x04, 0x56, 0x00, 0x78,
            ],
        });
        assert_eq!(&status[..4], [0x00, 0x31, 0x40, 0x1f]);
        assert_eq!(
            &status[status.len() - 16..],
            [
                0x00, 0x54, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x45, 0x00, 0x04, 0x56,
                0x00, 0x78
            ]
        );
        assert_eq!(ids(&status), (49, vec![10, 85, 84]));
        let ue = uplink_ue_associated_nrppa_transport(1, 2, b"r1", &[0x20, 0x0b]);
        assert_eq!(
            ue,
            [
                0x00, 0x32, 0x40, 0x1d, 0x00, 0x00, 0x04, // initiatingMessage, 50, ignore, 29
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x02, //
                0x00, 0x59, 0x00, 0x03, 0x02, b'r', b'1', // RoutingID
                0x00, 0x2e, 0x00, 0x03, 0x02, 0x20, 0x0b, // NRPPa-PDU
            ]
        );
        assert_eq!(ids(&ue), (50, vec![10, 85, 89, 46]));
        let non_ue = uplink_non_ue_associated_nrppa_transport(b"r1", &[0x20, 0x0b]);
        assert_eq!(
            non_ue,
            [
                0x00, 0x2f, 0x40, 0x11, 0x00, 0x00, 0x02, // initiatingMessage, 47, ignore, 17
                0x00, 0x59, 0x00, 0x03, 0x02, b'r', b'1', //
                0x00, 0x2e, 0x00, 0x03, 0x02, 0x20, 0x0b,
            ]
        );
        assert_eq!(ids(&non_ue), (47, vec![89, 46]));
    }
}
