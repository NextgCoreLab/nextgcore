//! A syntactically incorrect optional IE is treated as not present (#630).
//!
//! TS 24.501 §7.7.1 and TS 24.301 §7.7.1: "The UE shall treat all optional IEs
//! that are syntactically incorrect in a message as not present in the
//! message. The network shall take the same approach." Before #630 every IE
//! error failed the whole message decode.
//!
//! What stays an error:
//! - a bad mandatory IE (§7.5, "invalid mandatory information");
//! - an optional IE whose own length runs past the message, because then the
//!   message is truncated, not the IE.

use bytes::Bytes;
use nextgcore_nas::{eps, fiveg};

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

/// Registration type + ngKSI, then a 5G-S-TMSI as the mandatory 5GS mobile identity.
const REG_HEAD: &[u8] = &[0x01, 0x00, 0x07, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04];
/// PDU session status (0x50) with PSI 1 active: the IE after the bad one.
const PDU_SESSION_STATUS: &[u8] = &[0x50, 0x02, 0x02, 0x00];

fn reg(optional: &[&[u8]]) -> Vec<u8> {
    let mut v = REG_HEAD.to_vec();
    for ie in optional {
        v.extend_from_slice(ie);
    }
    v
}

#[test]
fn bad_optional_tlv_is_absent_and_the_next_ie_still_decodes() {
    // UE security capability (0x2E) of length 1: below the §9.11.3.54 minimum.
    let wire = reg(&[&[0x2e, 0x01, 0xf0], PDU_SESSION_STATUS]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.ue_security_capability, None);
    assert_eq!(msg.pdu_session_status.map(|s| s.psi), Some(0x0002));

    // The same IE well formed is kept: absence is only for the bad one.
    let wire = reg(&[&[0x2e, 0x02, 0xf0, 0x70], PDU_SESSION_STATUS]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.ue_security_capability.map(|c| c.ia), Some(0x70));
}

#[test]
fn bad_optional_tlv_e_is_absent_and_the_next_ie_still_decodes() {
    // Additional GUTI (0x77, TLV-E): a 5G-S-TMSI with one stray octet, which
    // is not a valid §9.11.3.4 identity length.
    let tmsi8 = [
        0x77, 0x00, 0x08, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04, 0x00,
    ];
    let wire = reg(&[&tmsi8, PDU_SESSION_STATUS]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.additional_guti, None);
    assert_eq!(msg.pdu_session_status.map(|s| s.psi), Some(0x0002));
}

#[test]
fn bad_inner_element_makes_the_whole_optional_ie_absent() {
    // Requested NSSAI (0x2F) of length 3 whose S-NSSAI claims 4 octets: the
    // NSSAI is syntactically incorrect as a whole.
    let wire = reg(&[&[0x2f, 0x03, 0x04, 0x01, 0x00], PDU_SESSION_STATUS]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.requested_nssai, None);
    assert_eq!(msg.pdu_session_status.map(|s| s.psi), Some(0x0002));
}

#[test]
fn optional_ie_running_past_the_message_is_still_an_error() {
    // PDU session status declaring 2 octets with 1 left: the message is truncated.
    let wire = reg(&[&[0x50, 0x02, 0x02]]);
    assert!(fiveg::RegistrationRequest::decode(&mut b(&wire)).is_err());
}

#[test]
fn bad_mandatory_ie_still_fails_the_message() {
    // The mandatory 5GS mobile identity itself with the stray octet (§7.5).
    let wire = [
        0x01, 0x00, 0x08, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04, 0x00,
    ];
    assert!(fiveg::RegistrationRequest::decode(&mut b(&wire)).is_err());
}

#[test]
fn eps_bad_optional_ie_is_absent_and_the_next_ie_still_decodes() {
    // Attach Request: attach type + KSI, IMSI (LV 8), UE network capability
    // (LV 2), empty ESM container (LV-E), then an Additional GUTI (0x50) of
    // length 12 (TS 24.301 §9.9.3.12: a GUTI is 11), then last visited TAI (0x52, TV 6).
    let mut wire = vec![0x71, 0x08, 0x29, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10];
    wire.extend_from_slice(&[0x02, 0xf0, 0x70, 0x00, 0x00]);
    wire.extend_from_slice(&[
        0x50, 0x0c, 0xf6, 0x00, 0xf1, 0x10, 0x80, 0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00,
    ]);
    wire.extend_from_slice(&[0x52, 0x00, 0xf1, 0x10, 0x00, 0x2a]);
    let msg = eps::AttachRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.additional_guti, None);
    assert_eq!(msg.last_visited_tai.map(|t| t.tac), Some(0x002a));
}

#[test]
fn bad_optional_plmn_list_is_absent_and_the_next_ie_still_decodes() {
    // Registration Accept: registration result (LV 1), then Equivalent PLMNs
    // (0x4A) of length 2, below one PLMN (TS 24.008 §10.5.1.13), then
    // Allowed NSSAI (0x15) with one SST.
    let wire = [0x01, 0x01, 0x4a, 0x02, 0x00, 0xf1, 0x15, 0x02, 0x01, 0x01];
    let msg = fiveg::RegistrationAccept::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.equivalent_plmns, None);
    let allowed = msg.allowed_nssai.expect("Allowed NSSAI after the bad IE");
    assert_eq!(allowed.s_nssai_list.len(), 1);
    assert_eq!(allowed.s_nssai_list[0].sst, 1);
}

#[test]
fn bad_optional_ue_os_id_is_absent_in_ue_state_indication() {
    // TS 24.501 D.8.7.1 applies the same rule to UE policy delivery messages.
    use fiveg::ue_policy::{UePolicyClassmark, UeStateIndication, UpsiList};
    let usi = UeStateIndication {
        pti: 0x01,
        upsi_list: UpsiList::default(),
        classmark: UePolicyClassmark::default(),
        os_ids: vec![[0x22; 16]],
    };
    let mut wire = usi.encode().unwrap();
    let decoded = UeStateIndication::decode(&wire).unwrap();
    assert_eq!(decoded.os_ids, vec![[0x22; 16]]);

    // UE OS Id of length 17: not a multiple of 16 (D.6.6).
    let len_at = wire.len() - 17;
    assert_eq!(wire[len_at], 16);
    wire[len_at] = 17;
    wire.push(0x00);
    let decoded = UeStateIndication::decode(&wire).unwrap();
    assert!(decoded.os_ids.is_empty());
    assert_eq!(decoded.pti, 0x01);

    // Running past the message is still an error.
    let short = &wire[..wire.len() - 1];
    assert!(UeStateIndication::decode(short).is_err());
}

#[test]
fn fivegsm_bad_optional_ie_is_absent_and_the_next_ie_still_decodes() {
    // PDU SESSION ESTABLISHMENT ACCEPT: SSC mode 1 + IPv4, QoS rules (LV-E 6),
    // Session-AMBR (LV 6), then a PDU address (0x29) of length 1, below the
    // §9.11.4.10 minimum, then DNN (0x25) "int".
    let mut wire = vec![0x11, 0x00, 0x06, 0x01, 0x00, 0x06, 0x31, 0x31, 0x01];
    wire.extend_from_slice(&[0x06, 0x06, 0x00, 0x64, 0x06, 0x00, 0x32]);
    wire.extend_from_slice(&[0x29, 0x01, 0x01]);
    wire.extend_from_slice(&[0x25, 0x04, 0x03, b'i', b'n', b't']);
    let msg = fiveg::PduSessionEstablishmentAccept::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.pdu_address, None);
    assert!(msg.dnn.is_some(), "the DNN after the bad IE still decodes");
    assert_eq!(msg.session_ambr.dl_value, 100);
}

#[test]
fn a_repeated_optional_ie_keeps_the_first_instance() {
    // TS 24.501 §7.6.3: only the first instance of a repeated IE is handled.
    let psi = |wire: &[u8]| {
        fiveg::RegistrationRequest::decode(&mut b(wire))
            .unwrap()
            .pdu_session_status
            .map(|s| s.psi)
    };
    // A good first instance survives a bad repetition ...
    assert_eq!(
        psi(&reg(&[PDU_SESSION_STATUS, &[0x50, 0x01, 0x00]])),
        Some(0x0002)
    );
    // ... and a good one.
    assert_eq!(
        psi(&reg(&[PDU_SESSION_STATUS, &[0x50, 0x02, 0x04, 0x00]])),
        Some(0x0002)
    );
    // A bad first instance is not present (§7.7.1), so the good repetition is
    // the first one present.
    assert_eq!(
        psi(&reg(&[&[0x50, 0x01, 0x00], PDU_SESSION_STATUS])),
        Some(0x0002)
    );
}
