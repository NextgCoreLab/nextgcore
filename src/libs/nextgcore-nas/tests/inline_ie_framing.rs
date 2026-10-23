//! Opaque and unknown optional IEs are framed by their own length (#784).
//!
//! Before #784, the inline opaque arms (Extended PCO, LADN information,
//! network names, ...) skipped an IE whose length ran past the message
//! without advancing, and the walk then re-read its value octets as IEIs.
//! The unknown-IE skip clamped an overrunning length to what was left. Both
//! hid a truncated message. Now:
//! - a length past the message is an error (the message is truncated);
//! - a repeated opaque IE keeps its first instance (TS 24.501 / 24.301 §7.6.3);
//! - an unknown type 1 IE (IEI >= 0x80) is one octet, also in the EPS decoders.

use bytes::Bytes;
use nextgcore_nas::{eps, fiveg};

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

/// PDU SESSION ESTABLISHMENT ACCEPT: SSC mode 1 + IPv4, QoS rules (LV-E 6),
/// Session-AMBR (LV 6).
fn accept_head() -> Vec<u8> {
    let mut v = vec![0x11, 0x00, 0x06, 0x01, 0x00, 0x06, 0x31, 0x31, 0x01];
    v.extend_from_slice(&[0x06, 0x06, 0x00, 0x64, 0x06, 0x00, 0x32]);
    v
}

#[test]
fn an_overrunning_extended_pco_is_an_error_not_a_misparse() {
    // Extended PCO (0x7B, TLV-E) declaring 16 octets with 2 left.
    let mut wire = accept_head();
    wire.extend_from_slice(&[0x7b, 0x00, 0x10, 0x80, 0x00]);
    assert!(fiveg::PduSessionEstablishmentAccept::decode(&mut b(&wire)).is_err());

    // Well formed, it is kept, and the DNN after it decodes.
    let mut wire = accept_head();
    wire.extend_from_slice(&[0x7b, 0x00, 0x02, 0x80, 0x00]);
    wire.extend_from_slice(&[0x25, 0x04, 0x03, b'i', b'n', b't']);
    let msg = fiveg::PduSessionEstablishmentAccept::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.extended_pco, Some(vec![0x80, 0x00]));
    assert!(msg.dnn.is_some());
}

#[test]
fn a_repeated_opaque_ie_keeps_the_first_instance() {
    let mut wire = accept_head();
    wire.extend_from_slice(&[0x7b, 0x00, 0x01, 0xaa]);
    wire.extend_from_slice(&[0x7b, 0x00, 0x01, 0xbb]);
    let msg = fiveg::PduSessionEstablishmentAccept::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.extended_pco, Some(vec![0xaa]));
}

#[test]
fn an_overrunning_unknown_ie_is_an_error() {
    // Registration request with a 5G-S-TMSI, then an unknown TLV (0x30)
    // declaring 5 octets with 1 left.
    let mut wire = vec![0x01, 0x00, 0x07, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04];
    wire.extend_from_slice(&[0x30, 0x05, 0x00]);
    assert!(fiveg::RegistrationRequest::decode(&mut b(&wire)).is_err());

    // Inside the message it is skipped and the next IE decodes.
    let mut wire = vec![0x01, 0x00, 0x07, 0xf4, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04];
    wire.extend_from_slice(&[0x30, 0x01, 0x00]);
    wire.extend_from_slice(&[0x50, 0x02, 0x02, 0x00]);
    let msg = fiveg::RegistrationRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.pdu_session_status.map(|s| s.psi), Some(0x0002));
}

#[test]
fn an_unknown_eps_type_1_ie_is_one_octet() {
    // Attach Request: attach type + KSI, IMSI (LV 8), UE network capability
    // (LV 2), empty ESM container (LV-E), then an unknown type 1 IE (0xF1),
    // then last visited TAI (0x52, TV 6). The EPS unknown arm used to read the
    // octet after 0xF1 as a length and swallow the TAI.
    let mut wire = vec![0x71, 0x08, 0x29, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10];
    wire.extend_from_slice(&[0x02, 0xf0, 0x70, 0x00, 0x00]);
    wire.push(0xf1);
    wire.extend_from_slice(&[0x52, 0x00, 0xf1, 0x10, 0x00, 0x2a]);
    let msg = eps::AttachRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.last_visited_tai.map(|t| t.tac), Some(0x002a));
}
