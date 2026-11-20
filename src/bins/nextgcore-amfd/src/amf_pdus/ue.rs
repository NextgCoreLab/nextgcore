//! UE-associated NAS and session PDUs: DOWNLINK NAS TRANSPORT, PDU SESSION
//! RESOURCE MODIFY REQUEST and the EPS->5GS HANDOVER REQUEST the AMF sends,
//! and the INITIAL UE MESSAGE (with Allowed NSSAI, or past 16K) and UPLINK NAS
//! TRANSPORT (past 16K) a gNB sends, the shapes [`crate::gnb_pdus`] does not
//! derive. See
//! [`crate::amf_pdus`] for the release and the method.
//!
//! Every open type and OCTET STRING here may pass 16K octets (a NAS-PDU of
//! 70000 octets is in the Downlink NAS matrix); [`Bits::open`] derives the
//! fragmented length determinant (X.691 §11.9.3.8).

use crate::aper_golden::{amf_ue_ngap_id, ran_ue_ngap_id, Bits};

/// AMF-UE-NGAP-ID `INTEGER (0..1099511627775)`: anything past it has no
/// encoding, so a derivation is never asked for one.
fn amf_id(v: u64) -> Vec<u8> {
    assert!(v < 1 << 40, "AMF-UE-NGAP-ID past 2^40-1 has no encoding");
    amf_ue_ngap_id(v)
}

/// DOWNLINK NAS TRANSPORT (§9.2.5.2): initiatingMessage,
/// id-DownlinkNASTransport 4, ignore (class 2); id 10 AMF-UE-NGAP-ID, id 85
/// RAN-UE-NGAP-ID and id 38 NAS-PDU, all reject
/// (`DownlinkNASTransport-IEs`); none of the optional IEs.
pub(crate) fn downlink_nas_transport(amf: u64, ran: u32, nas: &[u8]) -> Vec<u8> {
    crate::aper_golden::pdu(
        0,
        4,
        1,
        &[
            (10, 0, amf_id(amf)),
            (85, 0, ran_ue_ngap_id(ran)),
            (38, 0, crate::aper_golden::open_value(nas)),
        ],
    )
}

/// PDU SESSION RESOURCE MODIFY REQUEST (§9.2.1.5) with one session:
/// initiatingMessage, id-PDUSessionResourceModify 26, reject; ids 10 and 85
/// (reject); id 64 PDUSessionResourceModifyListModReq (reject):
/// `SEQUENCE (SIZE(1..256)) OF`, so count-1 in one aligned octet (range 256,
/// §11.5.7.2); the item `PDUSessionResourceModifyItemModReq` opens with its
/// extension bit, the nAS-PDU presence bit and the iE-Extensions presence
/// bit; PDUSessionID `INTEGER (0..255)` one aligned octet; the NAS-PDU when
/// present; the transfer, an `OCTET STRING (CONTAINING ...)`, which is
/// encoded as an unconstrained OCTET STRING.
pub(crate) fn pdu_session_resource_modify_request(
    amf: u64,
    ran: u32,
    psi: u8,
    nas: Option<&[u8]>,
    transfer: &[u8],
) -> Vec<u8> {
    let mut list = Bits::default();
    list.octets(&[0])
        .bit(false)
        .bit(nas.is_some())
        .bit(false)
        .octets(&[psi]);
    if let Some(nas) = nas {
        list.open(nas);
    }
    list.open(transfer);
    crate::aper_golden::pdu(
        0,
        26,
        0,
        &[
            (10, 0, amf_id(amf)),
            (85, 0, ran_ue_ngap_id(ran)),
            (64, 0, list.finish()),
        ],
    )
}

/// S-NSSAI (§9.3.1.24): extension `0`, the sD presence bit, iE-Extensions
/// `0`; SST `OCTET STRING (SIZE(1))`, fixed and at most two octets, so eight
/// bits NOT aligned (§17.6); SD `OCTET STRING (SIZE(3))`, fixed and longer
/// than two octets, so aligned with no length (§17.7). The AMF context keeps
/// the SD as a u32, its low 24 bits the three octets.
pub(crate) fn s_nssai(b: &mut Bits, s: &crate::context::SNssai) {
    b.bit(false)
        .bit(s.sd.is_some())
        .bit(false)
        .field(u64::from(s.sst), 8);
    if let Some(sd) = s.sd {
        b.octets(&sd.to_be_bytes()[1..]);
    }
}

/// AllowedNSSAI `SEQUENCE (SIZE(1..8)) OF AllowedNSSAI-Item`: count-1 as a
/// constrained whole number of range 8, three bits, not aligned (§11.5.7.2,
/// the range is below 256); each item opens with its extension bit and the
/// iE-Extensions presence bit, then the S-NSSAI.
pub(crate) fn allowed_nssai(slices: &[crate::context::SNssai]) -> Vec<u8> {
    assert!((1..=8).contains(&slices.len()));
    let mut b = Bits::default();
    b.field(slices.len() as u64 - 1, 3);
    for s in slices {
        b.bit(false).bit(false);
        s_nssai(&mut b, s);
    }
    b.finish()
}

/// The NGAP 16-bit algorithm bitmap (§9.3.1.86) for a NAS UE security
/// capability octet (TS 24.501 §9.11.3.54). NAS bit 8 is the null algorithm,
/// which has no NGAP bit; NAS bits 7, 6, 5 (algorithms 1, 2, 3) are NGAP's
/// first, second and third bits, the most significant of the sixteen. NAS
/// bits 4..1 (algorithms 4..7) map to bits NGAP leaves reserved, so octets
/// using them are not derived here.
pub(crate) fn ngap_algorithms(nas_octet: u8) -> u16 {
    assert_eq!(nas_octet & 0x0F, 0, "algorithms 4..7 are not derived here");
    u16::from((nas_octet << 1) & 0xE0) << 8
}

/// The EPS->5GS HANDOVER REQUEST of TS 38.413 §9.2.3.4 / TS 33.501 §8.4.2
/// step 4, derived member by member: initiatingMessage,
/// id-HandoverResourceAllocation 13, reject, the IEs in
/// `HandoverRequestIEs` order:
/// - id 10 AMF-UE-NGAP-ID (reject);
/// - id 29 HandoverType (reject): `ENUMERATED {intra5gs, fivegs-to-eps,
///   eps-to-5gs, ..., fivegs-to-utran}`, extension `0` + two bits, eps-to-5gs
///   index 2: `0 10` -> `40`;
/// - id 15 Cause (ignore): CHOICE of six in three bits, radioNetwork `000`;
///   CauseRadioNetwork extension `0` + six bits (45 root values),
///   handover-desirable-for-radio-reason index 16: `000 0 010000` -> `04 00`;
/// - id 110 UEAggregateMaximumBitRate (reject): extension `0`,
///   iE-Extensions `0`, DL then UL [`crate::aper_golden::bit_rate`];
/// - id 119 UESecurityCapabilities (reject): extension `0`, iE-Extensions
///   `0`, then four `BIT STRING (SIZE(16, ...))`, each the size extension bit
///   `0` and sixteen bits, not aligned (a fixed size of at most 16 bits,
///   §16.9): NR encryption, NR integrity, E-UTRA encryption, E-UTRA
///   integrity, through [`ngap_algorithms`];
/// - id 93 SecurityContext (reject): extension `0`, iE-Extensions `0`,
///   NextHopChainingCount `INTEGER (0..7)` three bits, 0 by step 4;
///   SecurityKey `BIT STRING (SIZE(256))`, fixed and past sixteen bits, so
///   aligned with no length (§16.10);
/// - id 41 NewSecurityContextInd (reject): `ENUMERATED {true, ...}`,
///   extension `0` and a single root value in zero bits -> `00`;
/// - id 37 NASC (reject): NAS-PDU;
/// - id 73 PDUSessionResourceSetupListHOReq (reject): count-1 in one aligned
///   octet (range 256); each item extension `0`, iE-Extensions `0`,
///   PDUSessionID one aligned octet, the [`s_nssai`], the
///   handoverRequestTransfer as an OCTET STRING;
/// - id 0 AllowedNSSAI (reject): [`allowed_nssai`];
/// - id 101 SourceToTarget-TransparentContainer (reject): OCTET STRING;
/// - id 28 GUAMI (reject): extension `0`, iE-Extensions `0`, PLMNIdentity
///   three aligned octets, AMFRegionID `BIT STRING (SIZE(8))`, AMFSetID
///   `(SIZE(10))`, AMFPointer `(SIZE(6))`, each at most sixteen bits so not
///   aligned.
///
/// `ue_ambr` is what goes on the wire, clamping (if any) already applied by
/// the caller; `guami` is (PLMN octets, region, set, pointer).
pub(crate) fn eps_to_5gs_handover_request(
    r: &crate::ngap_asn1::EpsToFivegsHandoverRequest,
    ue_ambr: (u64, u64),
    guami: ([u8; 3], u8, u16, u8),
) -> Vec<u8> {
    let mut cause = Bits::default();
    cause.field(0, 3).bit(false).field(16, 6);

    let mut ambr = Bits::default();
    ambr.bit(false).bit(false);
    crate::aper_golden::bit_rate(&mut ambr, ue_ambr.0);
    crate::aper_golden::bit_rate(&mut ambr, ue_ambr.1);

    let caps = &r.ue_security_capability;
    let mut sec = Bits::default();
    sec.bit(false).bit(false);
    for octet in [caps.ea, caps.ia, caps.eea, caps.eia] {
        sec.bit(false).field(u64::from(ngap_algorithms(octet)), 16);
    }

    let mut context = Bits::default();
    context
        .bit(false)
        .bit(false)
        .field(0, 3)
        .octets(&r.next_hop);

    assert!((1..=256).contains(&r.sessions.len()));
    let mut sessions = Bits::default();
    sessions.octets(&[(r.sessions.len() - 1) as u8]);
    for s in &r.sessions {
        sessions.bit(false).bit(false).octets(&[s.pdu_session_id]);
        s_nssai(&mut sessions, &s.s_nssai);
        sessions.open(&s.transfer);
    }

    let (plmn, region, set, pointer) = guami;
    let mut g = Bits::default();
    g.bit(false)
        .bit(false)
        .octets(&plmn)
        .field(u64::from(region), 8)
        .field(u64::from(set), 10)
        .field(u64::from(pointer), 6);

    crate::aper_golden::pdu(
        0,
        13,
        0,
        &[
            (10, 0, amf_id(r.amf_ue_ngap_id)),
            (29, 0, vec![0x40]),
            (15, 1, cause.finish()),
            (110, 0, ambr.finish()),
            (119, 0, sec.finish()),
            (93, 0, context.finish()),
            (41, 0, vec![0x00]),
            (37, 0, crate::aper_golden::open_value(&r.nas_container)),
            (73, 0, sessions.finish()),
            (0, 0, allowed_nssai(&r.allowed_nssai)),
            (
                101,
                0,
                crate::aper_golden::open_value(&r.source_to_target_container),
            ),
            (28, 0, g.finish()),
        ],
    )
}

/// INITIAL UE MESSAGE (§9.2.5.1) in the two shapes
/// [`crate::gnb_pdus::initial_ue_message`] does not derive -- with an
/// Allowed NSSAI, or with a NAS-PDU long enough that the IE's open type
/// passes 16K and fragments -- the IEs in `InitialUEMessage-IEs` order:
/// initiatingMessage, id-InitialUEMessage 15, ignore; id 85 RAN-UE-NGAP-ID,
/// id 38 NAS-PDU, id 121 UserLocationInformation (reject; `location` is the
/// IE value, as [`crate::gnb_pdus::user_location`] derives it); id 90
/// RRCEstablishmentCause (ignore), here always mo-Signalling: extension `0`
/// and root index 3 in four bits (ten root values), `0 0011` -> `18`; id 0
/// AllowedNSSAI (reject), [`allowed_nssai`], unless `slices` is empty.
pub(crate) fn initial_ue_message_mo_signalling(
    ran: u32,
    nas: &[u8],
    location: &[u8],
    slices: &[crate::context::SNssai],
) -> Vec<u8> {
    let mut ies = vec![
        (85, 0, ran_ue_ngap_id(ran)),
        (38, 0, crate::aper_golden::open_value(nas)),
        (121, 0, location.to_vec()),
        (90, 1, vec![0x18]),
    ];
    if !slices.is_empty() {
        ies.push((0, 0, allowed_nssai(slices)));
    }
    crate::aper_golden::pdu(0, 15, 1, &ies)
}

/// UPLINK NAS TRANSPORT (§9.2.5.3) through the fragmenting [`pdu`], for a
/// NAS-PDU past what [`crate::gnb_pdus::uplink_nas_transport`] derives:
/// initiatingMessage, id-UplinkNASTransport 46, ignore; ids 10, 85 and 38
/// (reject); id 121 UserLocationInformation (ignore), `location` the IE
/// value.
pub(crate) fn uplink_nas_transport(amf: u64, ran: u32, nas: &[u8], location: &[u8]) -> Vec<u8> {
    crate::aper_golden::pdu(
        0,
        46,
        1,
        &[
            (10, 0, amf_id(amf)),
            (85, 0, ran_ue_ngap_id(ran)),
            (38, 0, crate::aper_golden::open_value(nas)),
            (121, 1, location.to_vec()),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SNssai;

    /// The length determinant at each of its forms, worked out by hand:
    /// 0 -> `00`; 127 -> `7f`; 128 -> `80 80`; 16383 -> `bf ff`; 16384 ->
    /// `c1`, 16K octets, `00`; 16385 -> `c1`, 16K, `01`, one octet; 70000 =
    /// 65536 + 4464 -> `c4`, 64K octets, `91 70` (0x8000 | 4464), 4464
    /// octets.
    #[test]
    fn the_length_determinant_fragments_from_16k() {
        let lens = |n: usize| crate::aper_golden::open_value(&vec![0xa5; n]);
        assert_eq!(lens(0), [0x00]);
        assert_eq!(lens(127)[0], 0x7f);
        assert_eq!(lens(128)[..2], [0x80, 0x80]);
        assert_eq!(lens(16_383)[..2], [0xbf, 0xff]);
        let f = lens(16_384);
        assert_eq!(
            (f[0], f.len(), f[f.len() - 1]),
            (0xc1, 1 + 16_384 + 1, 0x00)
        );
        let f = lens(16_385);
        assert_eq!(
            (f[0], f[1 + 16_384], f.len()),
            (0xc1, 0x01, 1 + 16_384 + 1 + 1)
        );
        let f = lens(70_000);
        assert_eq!(f[0], 0xc4);
        assert_eq!(f[1 + 65_536..1 + 65_536 + 2], [0x91, 0x70]);
        assert_eq!(f.len(), 1 + 65_536 + 2 + 4_464);
    }

    /// DOWNLINK NAS TRANSPORT, AMF id 1, RAN id 2, NAS `7e 00`, octet by
    /// octet: `00` initiatingMessage, `04` procedure, `40` ignore, `16`
    /// length 22; `00` extension + pad, `00 03` three IEs; `00 0a` id 10,
    /// `00` reject, `02` length, `00 01` (n-1 = 0 in three bits, pad, 01);
    /// `00 55` id 85, `00`, `02`, `00 02`; `00 26` id 38, `00`, `03`, `02 7e
    /// 00`.
    #[test]
    fn a_downlink_nas_transport_is_the_worked_vector() {
        assert_eq!(
            downlink_nas_transport(1, 2, &[0x7e, 0x00]),
            [
                0x00, 0x04, 0x40, 0x16, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x00,
                0x55, 0x00, 0x02, 0x00, 0x02, 0x00, 0x26, 0x00, 0x03, 0x02, 0x7e, 0x00,
            ]
        );
    }

    /// INITIAL UE MESSAGE, RAN id 1, NAS `7e`, location `aa` (an opaque
    /// value here), Allowed NSSAI SST 2: `00 0f 40`, length 31 `1f` (3 + 6 + 6 + 5 + 5 + 6); `00 00
    /// 05`; `00 55 00 02 00 01`; `00 26 00 02 01 7e`; `00 79 00 01 aa`; `00
    /// 5a 40 01 18`; `00 00 00 02 00 02` (count-1 `000`, `00`, `000`, SST 2).
    /// Without the slice: four IEs, length 25 `19`. UPLINK NAS TRANSPORT, AMF 1,
    /// RAN 1, NAS `7e`, location `aa`: `00 2e 40 1a` (3 + 6 + 6 + 6 + 5) `00 00 04`, `00 0a 00 02
    /// 00 01`, `00 55 00 02 00 01`, `00 26 00 02 01 7e`, `00 79 40 01 aa`.
    #[test]
    fn the_uplink_stand_ins_are_the_worked_vectors() {
        assert_eq!(
            initial_ue_message_mo_signalling(1, &[0x7e], &[0xaa], &[SNssai { sst: 2, sd: None }]),
            [
                0x00, 0x0f, 0x40, 0x1f, 0x00, 0x00, 0x05, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x26, 0x00, 0x02, 0x01, 0x7e, //
                0x00, 0x79, 0x00, 0x01, 0xaa, //
                0x00, 0x5a, 0x40, 0x01, 0x18, //
                0x00, 0x00, 0x00, 0x02, 0x00, 0x02,
            ]
        );
        assert_eq!(
            initial_ue_message_mo_signalling(1, &[0x7e], &[0xaa], &[])[..7],
            [0x00, 0x0f, 0x40, 0x19, 0x00, 0x00, 0x04]
        );
        assert_eq!(
            uplink_nas_transport(1, 1, &[0x7e], &[0xaa]),
            [
                0x00, 0x2e, 0x40, 0x1a, 0x00, 0x00, 0x04, //
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x26, 0x00, 0x02, 0x01, 0x7e, //
                0x00, 0x79, 0x40, 0x01, 0xaa,
            ]
        );
    }

    /// MODIFY REQUEST, AMF 1, RAN 1, PSI 5, NAS `7e`, transfer `aa`: `00 1a
    /// 00`, length 26 `1a`; `00 00 03`; `00 0a 00 02 00 01`; `00 55 00 02 00
    /// 01`; `00 40` id 64, `00` reject, length `07`: count-1 `00`; item
    /// extension `0`, nAS-PDU present `1`, iE-Extensions `0`, pad -> `40`;
    /// PSI `05`; NAS `01 7e`; transfer `01 aa`.
    #[test]
    fn a_modify_request_with_a_nas_pdu_is_the_worked_vector() {
        assert_eq!(
            pdu_session_resource_modify_request(1, 1, 5, Some(&[0x7e]), &[0xaa]),
            [
                0x00, 0x1a, 0x00, 0x1a, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x40, 0x00, 0x07, 0x00, 0x40, 0x05, 0x01, 0x7e, 0x01, 0xaa,
            ]
        );
    }

    /// A whole EPS->5GS Handover Request, octet by octet: AMF id 1, UE-AMBR
    /// 1/1, capabilities EA 0xE0, IA 0x60, EEA 0xF0, EIA 0x70, NH all zero,
    /// NASC `01`, session 1 (SST 1, transfer `00`), Allowed NSSAI SST 1,
    /// container `40`, GUAMI 001/01 region 2 set 1 pointer 0.
    /// - `00 0d 00` initiatingMessage, procedure 13, reject; value length 123
    ///   `7b`; `00` extension + pad, `00 0c` twelve IEs;
    /// - `00 0a 00 02 00 01` AMF-UE-NGAP-ID;
    /// - `00 1d 00 01 40` HandoverType eps-to-5gs;
    /// - `00 0f 40 02 04 00` Cause (ignore `40`);
    /// - `00 6e 00 04`: UE-AMBR `0 0` + DL `0 000` + pad `00`, `01`; UL `0
    ///   000` + pad `00`, `01`;
    /// - `00 77 00 09`: `00`, then `0` + 16 bits four times: c000, c000,
    ///   e000, e000 -> `18 00 0c 00 07 00 03 80 00` (70 bits);
    /// - `00 5d 00 21`: `0 0 000` + pad `00`, the 32 NH octets;
    /// - `00 29 00 01 00` NSCI true; `00 25 00 02 01 01` NASC;
    /// - `00 49 00 07`: count-1 `00`; item `0 0` + pad `00`; PSI `01`;
    ///   S-NSSAI `0 0 0` + SST `0000 0001` + pad -> `00 20`; transfer `01 00`;
    /// - `00 00 00 02`: count-1 `000`, item `00`, S-NSSAI `000`, SST: `00 01`;
    /// - `00 65 00 02 01 40` the container;
    /// - `00 1c 00 07`: `00`, `00 f1 10`, region `02`, set `00 0000 0001` +
    ///   pointer `00 0000` -> `00 40`.
    #[test]
    fn an_eps_to_5gs_handover_request_is_the_worked_vector() {
        use crate::ngap_asn1::{EpsToFivegsHandoverRequest, HandoverRequestSession};
        let slice = SNssai { sst: 1, sd: None };
        let r = EpsToFivegsHandoverRequest {
            amf_ue_ngap_id: 1,
            ue_ambr_bps: (1, 1),
            ue_security_capability: crate::context::UeSecurityCapability {
                ea: 0xE0,
                ia: 0x60,
                eea: 0xF0,
                eia: 0x70,
            },
            next_hop: [0; 32],
            nas_container: vec![0x01],
            sessions: vec![HandoverRequestSession {
                pdu_session_id: 1,
                s_nssai: slice.clone(),
                transfer: vec![0x00],
            }],
            allowed_nssai: vec![slice],
            source_to_target_container: vec![0x40],
        };
        let mut expected = vec![
            0x00, 0x0d, 0x00, 0x7b, 0x00, 0x00, 0x0c, //
            0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
            0x00, 0x1d, 0x00, 0x01, 0x40, //
            0x00, 0x0f, 0x40, 0x02, 0x04, 0x00, //
            0x00, 0x6e, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, //
            0x00, 0x77, 0x00, 0x09, 0x18, 0x00, 0x0c, 0x00, 0x07, 0x00, 0x03, 0x80, 0x00, //
            0x00, 0x5d, 0x00, 0x21, 0x00,
        ];
        expected.extend_from_slice(&[0; 32]);
        expected.extend_from_slice(&[
            0x00, 0x29, 0x00, 0x01, 0x00, //
            0x00, 0x25, 0x00, 0x02, 0x01, 0x01, //
            0x00, 0x49, 0x00, 0x07, 0x00, 0x00, 0x01, 0x00, 0x20, 0x01, 0x00, //
            0x00, 0x00, 0x00, 0x02, 0x00, 0x01, //
            0x00, 0x65, 0x00, 0x02, 0x01, 0x40, //
            0x00, 0x1c, 0x00, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x40,
        ]);
        assert_eq!(
            eps_to_5gs_handover_request(&r, (1, 1), ([0x00, 0xf1, 0x10], 2, 1, 0)),
            expected
        );
    }

    /// Members of the EPS->5GS Handover Request, worked out by hand:
    /// - AllowedNSSAI of SST 1, SD 000001: count-1 `000`, item extension and
    ///   iE-Extensions `00`, S-NSSAI extension `0`, sD present `1`,
    ///   iE-Extensions `0` -> `0000 0010` = `02`; SST, unaligned, `01`; SD
    ///   aligned `00 00 01`.
    /// - BitRate 100000000 = 0x05F5E100, four octets: extension `0`, n-1 = 3
    ///   `011`, pad -> `30`; `05 f5 e1 00`.
    /// - NAS 0xE0 (EA0..EA2) and 0x60 (IA1, IA2) -> NGAP `c0 00`; 0xF0 -> `e0
    ///   00`.
    #[test]
    fn the_handover_request_members_are_the_worked_vectors() {
        assert_eq!(
            allowed_nssai(&[SNssai {
                sst: 1,
                sd: Some(1)
            }]),
            [0x02, 0x01, 0x00, 0x00, 0x01]
        );
        let mut b = Bits::default();
        crate::aper_golden::bit_rate(&mut b, 100_000_000);
        assert_eq!(b.finish(), [0x30, 0x05, 0xf5, 0xe1, 0x00]);
        assert_eq!(ngap_algorithms(0xE0), 0xC000);
        assert_eq!(ngap_algorithms(0x60), 0xC000);
        assert_eq!(ngap_algorithms(0xF0), 0xE000);
    }
}
