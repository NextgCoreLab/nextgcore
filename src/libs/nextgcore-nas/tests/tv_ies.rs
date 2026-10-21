//! IEs the message tables list as TV are coded without a length octet (#629).
//!
//! Each vector is laid out by hand from the spec message table, not taken
//! from this crate's encoder: the encoder and decoder both inserted a length
//! octet, so they agreed with each other and with no real peer.

use bytes::{Bytes, BytesMut};
use nextgcore_nas::common::types::SecurityAlgorithms;
use nextgcore_nas::eps::{
    EpsMobileIdentity, EpsSecurityModeCommand, EpsTmsi, ExtendedServiceRequest,
};
use nextgcore_nas::fiveg::{
    DlNasTransport, PayloadContainer, PayloadContainerType, SecurityModeCommand, UlNasTransport,
};

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

/// UL NAS TRANSPORT body (TS 24.501 §8.2.10): payload container type 1
/// (N1 SM), payload container `2e 01`, then PDU session ID `12 05` and old PDU
/// session ID `59 03`, both TV 2 (§9.11.3.41), then request type `81`.
const UL_NAS_TRANSPORT: &[u8] = &[0x01, 0x00, 0x02, 0x2e, 0x01, 0x12, 0x05, 0x59, 0x03, 0x81];

#[test]
fn ul_nas_transport_pdu_session_ids_are_tv() {
    let msg = UlNasTransport::decode(&mut b(UL_NAS_TRANSPORT)).unwrap();
    assert_eq!(msg.pdu_session_id, Some(5));
    assert_eq!(msg.old_pdu_session_id, Some(3));
    assert!(msg.request_type.is_some(), "the IE walk stayed aligned");

    let mut out = BytesMut::new();
    msg.encode(&mut out);
    assert_eq!(&out[..], UL_NAS_TRANSPORT);
}

#[test]
fn dl_nas_transport_pdu_session_id_is_tv() {
    // §8.2.11: payload container type, payload container, PDU session ID TV 2,
    // then 5GMM cause `58 1b` (TV 2).
    let wire = [0x01, 0x00, 0x01, 0x2e, 0x12, 0x07, 0x58, 0x1b];
    let msg = DlNasTransport::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.pdu_session_id, Some(7));
    assert_eq!(msg.gmm_cause, Some(0x1b));

    let enc = DlNasTransport {
        payload_container_type: PayloadContainerType::N1SmInformation,
        payload_container: PayloadContainer::new(vec![0x2e]),
        pdu_session_id: Some(7),
        ..Default::default()
    };
    let mut out = BytesMut::new();
    enc.encode(&mut out);
    assert_eq!(&out[..], &wire[..6]);
}

#[test]
fn security_mode_command_selected_eps_algorithms_is_tv() {
    // §8.2.25: selected NAS algorithms, ngKSI, replayed UE security capability
    // (LV, 2 octets), then selected EPS NAS security algorithms `57 11` (TV 2)
    // and additional 5G security information `36 01 01` (TLV 3).
    let wire = [0x21, 0x00, 0x02, 0xf0, 0x70, 0x57, 0x11, 0x36, 0x01, 0x01];
    let msg = SecurityModeCommand::decode(&mut b(&wire)).unwrap();
    assert_eq!(
        msg.selected_eps_nas_security_algorithms,
        Some(SecurityAlgorithms::decode(0x11))
    );
    assert_eq!(msg.additional_5g_security_information, Some(0x01));

    let mut out = BytesMut::new();
    msg.encode(&mut out);
    assert_eq!(&out[..], &wire[..]);
}

#[test]
fn eps_security_mode_command_nonces_are_tv() {
    // TS 24.301 §8.2.20: selected algorithms, KSI, replayed UE network
    // capability (LV, 2 octets), then Replayed nonceUE `55` and NonceMME `56`,
    // each TV 5.
    let wire = [
        0x11, 0x00, 0x02, 0xf0, 0x70, 0x55, 0xa1, 0xa2, 0xa3, 0xa4, 0x56, 0xb1, 0xb2, 0xb3, 0xb4,
    ];
    let msg = EpsSecurityModeCommand::decode(&mut b(&wire)).unwrap();
    assert_eq!(msg.replayed_nonce_ue, Some([0xa1, 0xa2, 0xa3, 0xa4]));
    assert_eq!(msg.nonce_mme, Some([0xb1, 0xb2, 0xb3, 0xb4]));

    let mut out = BytesMut::new();
    msg.encode(&mut out);
    assert_eq!(&out[..], &wire[..]);
}

#[test]
fn extended_service_request_carries_an_m_tmsi() {
    // TS 24.301 §8.2.15: service type 1 / KSI 0, then M-TMSI as a TS 24.008
    // §10.5.1.4 Mobile identity: LV 6, octet 3 `f4` (type 4), 4 TMSI octets.
    let wire = [0x01, 0x05, 0xf4, 0xde, 0xad, 0xbe, 0xef];
    let msg = ExtendedServiceRequest::decode(&mut b(&wire)).unwrap();
    assert_eq!(
        msg.m_tmsi,
        EpsMobileIdentity::Tmsi(EpsTmsi { tmsi: 0xdeadbeef })
    );

    let mut out = BytesMut::new();
    msg.encode(&mut out);
    assert_eq!(&out[..], &wire[..]);

    // The EPS mobile identity IE (§9.9.3.12) still has no type 4.
    assert!(EpsMobileIdentity::decode(&mut b(&wire[1..])).is_err());
}
