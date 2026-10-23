//! A fixed-layout IE's declared length governs what it consumes (#613).
//!
//! Before #613 these decoders read their fixed fields whatever the length octet
//! said: a length below the IE minimum borrowed octets of the next IE, and
//! octets beyond the known fields were left to be parsed as the next IE. Each
//! test pins one IE family against its TS 24.501 / TS 24.301 / TS 24.008
//! length:
//!
//! - a length below the minimum is `InvalidIeLength`;
//! - for an IE the spec fixes ("a length of N octets") any other length is too;
//! - for an IE the spec lets grow (optional or spare trailing octets) the extra
//!   octets are skipped inside the IE, and the octet after it is untouched.

use bytes::Bytes;
use nextgcore_nas::common::types::{
    Abba, AuthenticationResponseParameter, GprsTimer2, GprsTimer3, UeSecurityCapability,
};
use nextgcore_nas::eps::{self, EpsMobileIdentity, UeNetworkCapability};
use nextgcore_nas::fiveg::{
    self, AiMlCapability, AllowedPduSessionStatus, FiveGmmCapability, IsacParameter,
    MobileIdentity, NtnAccessBarring, NtnTimingAdvance, PduAddress, PduSessionStatus,
    RegistrationResult, SemanticCommParameter, SessionAmbr, SubThzBandParameter, UplinkDataStatus,
};
use nextgcore_nas::{NasError, NasResult};

/// A marker octet after the IE: what is left once the IE is decoded.
const NEXT: u8 = 0x7e;

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

/// `v` followed by [`NEXT`].
fn with_next(v: &[u8]) -> Bytes {
    let mut out = v.to_vec();
    out.push(NEXT);
    Bytes::from(out)
}

/// The `(expected, actual)` of an `InvalidIeLength`, or a panic naming what came back.
fn len_err<T: std::fmt::Debug>(r: NasResult<T>) -> (usize, usize) {
    match r {
        Err(NasError::InvalidIeLength { expected, actual }) => (expected, actual),
        other => panic!("expected InvalidIeLength, got {other:?}"),
    }
}

/// The IE decoded and only [`NEXT`] is left.
fn consumed_exactly<T>(buf: &Bytes, r: NasResult<T>) -> T {
    let v = r.unwrap_or_else(|e| panic!("decode failed: {e}"));
    assert_eq!(buf.as_ref(), &[NEXT], "the IE must consume its own length");
    v
}

#[test]
fn psi_bitmaps_reject_a_short_length_and_skip_spare_octets() {
    // TS 24.501 §9.11.3.44 / .57 / .13: 4 to 34 octets, octets 5-34 spare.
    type Dec = fn(&mut Bytes) -> NasResult<u16>;
    let decoders: [(&str, Dec); 3] = [
        ("PDU session status", |b| {
            PduSessionStatus::decode(b).map(|v| v.psi)
        }),
        ("Uplink data status", |b| {
            UplinkDataStatus::decode(b).map(|v| v.psi)
        }),
        ("Allowed PDU session status", |b| {
            AllowedPduSessionStatus::decode(b).map(|v| v.psi)
        }),
    ];
    for (name, decode) in decoders {
        // Length 1: only octet 3; octet 4 would be the next IE's octet.
        let mut buf = b(&[0x01, 0x02, 0x00, 0x00]);
        assert_eq!(len_err(decode(&mut buf)), (2, 1), "{name}");
        let mut buf = b(&[0x00, 0x02, 0x00]);
        assert_eq!(len_err(decode(&mut buf)), (2, 0), "{name}");

        // Length 4: two spare octets, skipped inside the IE.
        let mut buf = with_next(&[0x04, 0x02, 0x80, 0x00, 0x00]);
        let psi = decode(&mut buf);
        assert_eq!(consumed_exactly(&buf, psi), 0x8002, "{name}");
    }
}

#[test]
fn session_ambr_length_is_exactly_six() {
    // TS 24.501 §9.11.4.14: "a length of 8 octets".
    let mut buf = b(&[0x05, 1, 0, 1, 1, 0, 1, 0]);
    assert_eq!(len_err(SessionAmbr::decode(&mut buf)), (6, 5));
    let mut buf = b(&[0x07, 1, 0, 1, 1, 0, 1, 0]);
    assert_eq!(len_err(SessionAmbr::decode(&mut buf)), (6, 7));

    let mut buf = with_next(&[0x06, 0x06, 0x00, 0x64, 0x06, 0x00, 0x32]);
    let ambr = SessionAmbr::decode(&mut buf);
    let ambr = consumed_exactly(&buf, ambr);
    assert_eq!((ambr.dl_value, ambr.ul_value), (100, 50));
}

#[test]
fn gprs_timers_2_and_3_hold_exactly_one_octet() {
    // TS 24.008 §10.5.7.4 / §10.5.7.4a: "3 octets length".
    for bad in [0u8, 2] {
        let mut buf = b(&[bad, 0x21, 0x22]);
        assert_eq!(len_err(GprsTimer2::decode(&mut buf)), (1, bad as usize));
        let mut buf = b(&[bad, 0x21, 0x22]);
        assert_eq!(len_err(GprsTimer3::decode(&mut buf)), (1, bad as usize));
    }
    let mut buf = with_next(&[0x01, 0x21]);
    let t = GprsTimer3::decode(&mut buf);
    let t = consumed_exactly(&buf, t);
    assert_eq!((t.unit, t.value), (1, 1));
}

#[test]
fn registration_result_holds_exactly_one_octet() {
    // TS 24.501 §9.11.3.6: "a length of 3 octets".
    let mut buf = b(&[0x02, 0x09, 0x00]);
    assert_eq!(len_err(RegistrationResult::decode(&mut buf)), (1, 2));
    let mut buf = b(&[0x00, 0x09]);
    assert_eq!(len_err(RegistrationResult::decode(&mut buf)), (1, 0));
}

#[test]
fn ue_security_capability_needs_ea_and_ia_and_skips_spare_octets() {
    // TS 24.501 §9.11.3.54: 4 to 10 octets; octets 5-6 optional, 7-10 spare.
    // Length 1 used to read IA from the next IE.
    let mut buf = b(&[0x01, 0xf0, 0x70]);
    assert_eq!(len_err(UeSecurityCapability::decode(&mut buf)), (2, 1));

    let mut buf = with_next(&[0x06, 0xf0, 0x70, 0xe0, 0x60, 0x00, 0x00]);
    let cap = UeSecurityCapability::decode(&mut buf);
    let cap = consumed_exactly(&buf, cap);
    assert_eq!(
        (cap.ea, cap.ia, cap.eea, cap.eia),
        (0xf0, 0x70, Some(0xe0), Some(0x60))
    );

    // Length 2: no EPS octets, and the next IE is not taken for them.
    let mut buf = with_next(&[0x02, 0xf0, 0x70]);
    let cap = UeSecurityCapability::decode(&mut buf);
    let cap = consumed_exactly(&buf, cap);
    assert_eq!((cap.eea, cap.eia), (None, None));
}

#[test]
fn five_gmm_capability_needs_octet_3_and_keeps_later_octets() {
    // TS 24.501 §9.11.3.1: 3 to 15 octets, octets 4-15 optional.
    let mut buf = b(&[0x00, 0x07]);
    assert_eq!(len_err(FiveGmmCapability::decode(&mut buf)), (1, 0));

    let mut buf = with_next(&[0x03, 0x07, 0xaa, 0xbb]);
    let cap = FiveGmmCapability::decode(&mut buf);
    let cap = consumed_exactly(&buf, cap);
    assert!(cap.s1_mode && cap.ho_attach && cap.lpp);
    assert_eq!(cap.additional, vec![0xaa, 0xbb]);
}

#[test]
fn pdu_address_needs_a_type_and_an_ipv4_address() {
    // TS 24.501 §9.11.4.10: 7 to 31 octets.
    let mut buf = b(&[0x01, 0x01, 10, 0, 0, 1]);
    assert_eq!(len_err(PduAddress::decode(&mut buf)), (5, 1));

    let mut buf = with_next(&[0x05, 0x01, 10, 45, 0, 2]);
    let addr = PduAddress::decode(&mut buf);
    assert_eq!(consumed_exactly(&buf, addr).address, vec![10, 45, 0, 2]);
}

#[test]
fn abba_and_res_lengths_are_bounded() {
    // TS 24.501 §9.11.3.10: ABBA is at least 2 octets.
    let mut buf = b(&[0x01, 0x00, 0x00]);
    assert_eq!(len_err(Abba::decode(&mut buf)), (2, 1));
    // TS 24.301 §9.9.3.4: RES is 4 to 16 octets.
    let mut buf = b(&[0x03, 1, 2, 3]);
    assert_eq!(
        len_err(AuthenticationResponseParameter::decode(&mut buf)),
        (4, 3)
    );
    let mut long = vec![17u8];
    long.extend_from_slice(&[0u8; 17]);
    assert_eq!(
        len_err(AuthenticationResponseParameter::decode(&mut b(&long))),
        (16, 17)
    );
}

#[test]
fn six_g_extension_ies_need_their_fixed_fields_and_skip_extra_octets() {
    // No 3GPP definition: the fields the encoder writes must be present, and
    // octets after them stay inside the IE.
    type Dec = fn(&mut Bytes) -> bool;
    let decoders: [(&str, usize, Dec); 6] = [
        ("AI/ML capability", 3, |b| AiMlCapability::decode(b).is_ok()),
        ("ISAC parameter", 3, |b| IsacParameter::decode(b).is_ok()),
        ("Semantic comm", 2, |b| {
            SemanticCommParameter::decode(b).is_ok()
        }),
        ("Sub-THz band", 4, |b| {
            SubThzBandParameter::decode(b).is_ok()
        }),
        ("NTN timing advance", 5, |b| {
            NtnTimingAdvance::decode(b).is_ok()
        }),
        ("NTN access barring", 5, |b| {
            NtnAccessBarring::decode(b).is_ok()
        }),
    ];
    for (name, n, decode) in decoders {
        // One octet short, with enough octets after it to fill the fields.
        let mut short = vec![(n - 1) as u8];
        short.extend(std::iter::repeat_n(0x11, n + 2));
        assert!(!decode(&mut b(&short)), "{name}: length {} accepted", n - 1);

        let mut long = vec![(n + 2) as u8];
        long.extend(std::iter::repeat_n(0x11, n + 2));
        let mut buf = with_next(&long);
        assert!(decode(&mut buf), "{name}: length {} rejected", n + 2);
        assert_eq!(buf.as_ref(), &[NEXT], "{name}");
    }
}

/// 5GS mobile identity value part: LV-E length, then `contents`.
fn five_gs_identity(len: u16, contents: &[u8]) -> Bytes {
    let mut v = len.to_be_bytes().to_vec();
    v.extend_from_slice(contents);
    with_next(&v)
}

#[test]
fn five_gs_mobile_identities_have_their_exact_lengths() {
    // TS 24.501 §9.11.3.4. 5G-S-TMSI: type octet + AMF Set ID/Pointer + 5G-TMSI.
    let tmsi = [0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04];
    let mut buf = five_gs_identity(7, &tmsi);
    let id = MobileIdentity::decode(&mut buf);
    assert!(matches!(
        consumed_exactly(&buf, id),
        MobileIdentity::FiveGSTmsi(t) if t.tmsi == 0x01020304
    ));

    // One stray octet inside the declared length: an erroneous IE, not a
    // 5G-S-TMSI that leaves the octet behind as the next IEI.
    let mut long = tmsi.to_vec();
    long.push(0x00);
    assert_eq!(
        len_err(MobileIdentity::decode(&mut five_gs_identity(8, &long))),
        (7, 8)
    );

    // 5G-GUTI is 11 octets; 10 is short.
    let guti = [
        0xf2, 0x00, 0xf1, 0x10, 0x01, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04,
    ];
    assert!(MobileIdentity::decode(&mut five_gs_identity(11, &guti)).is_ok());
    assert_eq!(
        len_err(MobileIdentity::decode(&mut five_gs_identity(
            10,
            &guti[..10]
        ))),
        (11, 10)
    );
    let mut long = guti.to_vec();
    long.push(0x00);
    assert_eq!(
        len_err(MobileIdentity::decode(&mut five_gs_identity(12, &long))),
        (11, 12)
    );

    // IMEISV is 16 digits: 9 octets.
    let imeisv = [0x35, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5];
    assert!(MobileIdentity::decode(&mut five_gs_identity(9, &imeisv)).is_ok());
    let mut long = imeisv.to_vec();
    long.push(0x00);
    assert_eq!(
        len_err(MobileIdentity::decode(&mut five_gs_identity(10, &long))),
        (9, 10)
    );
}

#[test]
fn eps_mobile_identities_have_their_exact_lengths() {
    // TS 24.301 §9.9.3.12: GUTI is octets 3-13 (11 value octets).
    let guti = [
        0xf6, 0x00, 0xf1, 0x10, 0x80, 0x01, 0x01, 0x01, 0x02, 0x03, 0x04,
    ];
    let mut v = vec![11u8];
    v.extend_from_slice(&guti);
    let mut buf = with_next(&v);
    let id = EpsMobileIdentity::decode(&mut buf);
    assert!(matches!(
        consumed_exactly(&buf, id),
        EpsMobileIdentity::Guti(g) if g.m_tmsi == 0x01020304
    ));

    let mut v = vec![12u8];
    v.extend_from_slice(&guti);
    v.push(0x00);
    assert_eq!(len_err(EpsMobileIdentity::decode(&mut b(&v))), (11, 12));

    // TS 24.008 §10.5.1.4: IMEI is 15 digits, 8 octets.
    let imei = [0x3a, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43];
    let mut v = vec![9u8];
    v.extend_from_slice(&imei);
    v.push(0x00);
    assert_eq!(len_err(EpsMobileIdentity::decode(&mut b(&v))), (8, 9));

    // IMSI is at most 15 digits, 8 octets.
    let mut v = vec![9u8, 0x29];
    v.extend_from_slice(&[0x11; 8]);
    assert_eq!(len_err(EpsMobileIdentity::decode(&mut b(&v))), (8, 9));
}

#[test]
fn ue_network_capability_needs_eea_and_eia_and_keeps_later_octets() {
    // TS 24.301 §9.9.3.34: 4 to 15 octets, octets 5-15 optional.
    let mut buf = b(&[0x01, 0xf0, 0x70]);
    assert_eq!(len_err(UeNetworkCapability::decode(&mut buf)), (2, 1));

    let mut buf = with_next(&[0x05, 0xf0, 0x70, 0xc0, 0x40, 0x19]);
    let cap = UeNetworkCapability::decode(&mut buf);
    let cap = consumed_exactly(&buf, cap);
    assert_eq!((cap.uea, cap.uia), (Some(0xc0), Some(0x40)));
    assert_eq!(cap.additional, vec![0x19]);
}

#[test]
fn registration_request_ue_status_holds_one_octet() {
    // Registration type + ngKSI, then a 5G-S-TMSI mobile identity.
    let mut body = vec![0x01, 0x00, 0x07, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04];
    // TS 24.501 §9.11.3.56: UE status (IEI 0x2B) is "a length of 3 octets".
    let mut ok = body.clone();
    ok.extend_from_slice(&[0x2b, 0x01, 0x03]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&ok)).unwrap();
    assert_eq!(msg.ue_status, Some(0x03));

    // Length 2 is an erroneous IE. It is optional, so it is treated as not
    // present (§7.7.1, #630) and the PDU session status after it is decoded.
    body.extend_from_slice(&[0x2b, 0x02, 0x03, 0x00, 0x50, 0x02, 0x02, 0x00]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.ue_status, None);
    assert_eq!(msg.pdu_session_status.map(|s| s.psi), Some(0x0002));
}

#[test]
fn authentication_failure_parameter_is_the_14_octet_auts() {
    // TS 24.008 §10.5.3.2.2: "a length of 16 octets". 5GMM cause #21, then
    // the IE (0x30) one octet short.
    // Optional, so the short IE is not present (§7.7.1, #630).
    let mut body = vec![0x15, 0x30, 13];
    body.extend_from_slice(&[0u8; 13]);
    let msg = fiveg::AuthenticationFailure::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.authentication_failure_parameter, None);
    // The EPS message, same IE (TS 24.301 §9.9.3.1).
    let msg = eps::EpsAuthenticationFailure::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.authentication_failure_parameter, None);

    let mut ok = vec![0x15, 0x30, 14];
    ok.extend_from_slice(&[0xab; 14]);
    let msg = fiveg::AuthenticationFailure::decode(&mut b(&ok)).unwrap();
    assert_eq!(msg.authentication_failure_parameter, Some(vec![0xab; 14]));
}

#[test]
fn eps_attach_accept_plmn_list_is_decoded_inside_its_length() {
    // Attach result, T3412, empty TAI list, empty ESM container, then an
    // Equivalent PLMNs list (0x4A) of length 4: one PLMN and a stray octet,
    // then EMM cause (0x53). Before #613 the stray octet was read as an IEI
    // and the walk lost the EMM cause.
    let mut body = vec![0x01, 0x21, 0x00, 0x00, 0x00];
    body.extend_from_slice(&[0x4a, 0x04, 0x00, 0xf1, 0x10, 0xee]);
    body.extend_from_slice(&[0x53, 0x0a]);
    let msg = eps::AttachAccept::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.equivalent_plmns.as_ref().map(Vec::len), Some(1));
    assert_eq!(msg.emm_cause, Some(0x0a));

    // TS 24.008 §10.5.1.13: at least one PLMN. Length 2 is syntactically
    // incorrect, so the optional list is absent (TS 24.301 §7.7.1, #630) and
    // the EMM cause after it still decodes.
    let body = [
        0x01, 0x21, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x00, 0xf1, 0x53, 0x0a,
    ];
    let msg = eps::AttachAccept::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.equivalent_plmns, None);
    assert_eq!(msg.emm_cause, Some(0x0a));
}

#[test]
fn eps_bearer_context_status_holds_two_octets() {
    // Extended Service Request: service type + KSI, the M-TMSI (TS 24.008
    // Mobile identity, type 4), then EPS bearer context status (0x57) with
    // length 1 (TS 24.301 §9.9.2.1: "4 octets length").
    let mut body = vec![0x01, 5, 0xf4, 1, 2, 3, 4];
    let mut ok = body.clone();
    ok.extend_from_slice(&[0x57, 0x02, 0x20, 0x00]);
    let msg = eps::ExtendedServiceRequest::decode(&mut b(&ok)).unwrap();
    assert_eq!(msg.eps_bearer_context_status, Some(0x2000));

    // Length 1 is syntactically incorrect. The IE is optional, so it is
    // absent (TS 24.301 §7.7.1, #630), and the CSFB response after it still
    // decodes.
    body.extend_from_slice(&[0x57, 0x01, 0x20, 0xB1]);
    let msg = eps::ExtendedServiceRequest::decode(&mut b(&body)).unwrap();
    assert_eq!(msg.eps_bearer_context_status, None);
    assert_eq!(msg.csfb_response, Some(1));
}
