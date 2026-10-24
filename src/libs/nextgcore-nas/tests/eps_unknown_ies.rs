//! EPS decoders ignore an unknown optional IE and keep walking (#810).
//!
//! Eleven EPS decoders ended their IE loop with `_ => break`, so the first IE
//! they did not model ended the walk and every later IE was lost, including
//! modelled ones. TS 24.301 §7.6.1 says an unknown IE that is not
//! comprehension required is ignored. Each loop now skips an unknown IE by its
//! format, and the type 3 (TV) IEs of its clause 8 table that are not
//! modelled have explicit fixed-length arms, so they are not read as TLV.

use bytes::Bytes;
use nextgcore_nas::eps;

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

#[test]
fn service_reject_with_t3442_still_decodes_t3346() {
    // EMM cause, T3442 (0x5B, TV 2, conditional, not modelled), T3346 (0x5F).
    let wire = [0x0a, 0x5b, 0x21, 0x5f, 0x01, 0x21];
    let msg = eps::EpsServiceReject::decode(&mut b(&wire)).unwrap();
    assert!(msg.t3346_value.is_some(), "T3346 after T3442 is decoded");
}

#[test]
fn tracking_area_update_accept_with_a_lai_still_decodes_t3412() {
    // EPS update result, LAI (0x13, TV 6), T3412 (0x5A, TV 2).
    let wire = [0x00, 0x13, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x5a, 0x21];
    let msg = eps::TrackingAreaUpdateAccept::decode(&mut b(&wire)).unwrap();
    assert!(msg.t3412_value.is_some(), "T3412 after the LAI is decoded");
}

#[test]
fn emm_information_skips_an_unknown_tlv() {
    // An unknown TLV (0x3E), then local time zone (0x46, TV 2).
    let wire = [0x3e, 0x01, 0x00, 0x46, 0x21];
    let msg = eps::EmmInformation::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.local_time_zone, Some(0x21));
}

#[test]
fn an_unknown_type_1_ie_is_one_octet() {
    // An unknown half-octet IE (0xF1), then local time zone.
    let wire = [0xf1, 0x46, 0x21];
    let msg = eps::EmmInformation::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.local_time_zone, Some(0x21));
}

#[test]
fn modify_eps_bearer_context_request_skips_llc_sapi() {
    // Negotiated LLC SAPI (0x32, TV 2, not modelled), then TFT (0x36).
    let wire = [0x32, 0x05, 0x36, 0x01, 0xaa];
    let msg = eps::ModifyEpsBearerContextRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.tft, Some(vec![0xaa]));
}
