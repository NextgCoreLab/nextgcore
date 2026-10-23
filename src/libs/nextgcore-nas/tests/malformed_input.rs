//! Malformed NAS from the UE must decode to `Err`, never panic (#595).
//!
//! NAS is UE-controlled, so a decoder panic lets one UE take down the AMF/MME
//! decoding task. The named repros are the crashing inputs the
//! `fuzz_nas_message` target found (the leading selector byte stripped); the
//! sweep feeds every message decoder every short input over a small alphabet.

use bytes::Bytes;
use nextgcore_nas::common::types::SNssai;
use nextgcore_nas::{eps, fiveg};

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

#[test]
fn nssai_auth_result_with_short_snssai_is_err() {
    // fuzz repro `1c 00 00 0a`: S-NSSAI length 0x0a over a 1-octet remainder.
    assert!(
        fiveg::NetworkSliceSpecificAuthenticationResult::decode(&mut b(&[0x00, 0x00, 0x0a]))
            .is_err()
    );
}

#[test]
fn snssai_length_zero_is_err() {
    // Length 0 has no SST octet; before #595 this read the next IE's octet and
    // underflowed `len - 1`.
    assert!(SNssai::decode(&mut b(&[0x00, 0x01])).is_err());
}

#[test]
fn snssai_consumes_exactly_its_length() {
    // Length 3 (SST + 2 stray octets): no SD, but both octets belong to the IE.
    let mut buf = b(&[0x03, 0x01, 0xaa, 0xbb, 0x7e]);
    let s = SNssai::decode(&mut buf).unwrap();
    assert_eq!(s.sst, 0x01);
    assert_eq!(buf.as_ref(), &[0x7e]);
}

#[test]
fn eps_attach_request_with_empty_mobile_identity_is_err() {
    // fuzz repro `31 00 00`: EPS mobile identity length 0, nothing to peek.
    assert!(eps::AttachRequest::decode(&mut b(&[0x00, 0x00])).is_err());
}

#[test]
fn authentication_request_truncated_autn_is_err() {
    // fuzz repro `09 9f 00 20`: AUTN IEI with no length octet.
    assert!(fiveg::AuthenticationRequest::decode(&mut b(&[0x9f, 0x00, 0x20])).is_err());
}

#[test]
fn authentication_request_autn_wrong_length_is_err() {
    let mut body = vec![0x00, 0x00, 0x20, 17];
    body.extend_from_slice(&[0u8; 17]);
    assert!(fiveg::AuthenticationRequest::decode(&mut b(&body)).is_err());
}

#[test]
fn authentication_request_truncated_rand_is_err() {
    assert!(fiveg::AuthenticationRequest::decode(&mut b(&[0x00, 0x00, 0x21, 0x01])).is_err());
}

#[test]
fn configuration_update_nssai_overrunning_its_length_is_absent() {
    // fuzz repro `75 31 01 02 00 10`: an NSSAI of length 1 whose S-NSSAI claims
    // 2 octets; the running `remaining -= ...` count underflowed. The NSSAI is
    // syntactically incorrect and optional, so since #630 it is treated as not
    // present (TS 24.501 §7.7.1) rather than failing the message.
    let msg = fiveg::ConfigurationUpdateCommand::decode(&mut b(&[0x31, 0x01, 0x02])).unwrap();
    assert_eq!(msg.configured_nssai, None);
    // The full repro ends in `00 10`: an unknown IE whose 16-octet length runs
    // past the message. That is a truncated message, so an error (#784), and
    // still no panic.
    assert!(
        fiveg::ConfigurationUpdateCommand::decode(&mut b(&[0x31, 0x01, 0x02, 0x00, 0x10])).is_err()
    );
}

type Decoder = fn(&mut Bytes) -> bool;

const DECODERS: &[Decoder] = &[
    |b| fiveg::parse_5gmm_message(b).is_ok(),
    |b| fiveg::parse_5gsm_message(b).is_ok(),
    |b| eps::parse_emm_message(b).is_ok(),
    |b| eps::parse_esm_message(b).is_ok(),
    |b| fiveg::RegistrationRequest::decode(b).is_ok(),
    |b| fiveg::RegistrationAccept::decode(b).is_ok(),
    |b| fiveg::AuthenticationRequest::decode(b).is_ok(),
    |b| fiveg::ConfigurationUpdateCommand::decode(b).is_ok(),
    |b| fiveg::DlNasTransport::decode(b).is_ok(),
    |b| fiveg::UlNasTransport::decode(b).is_ok(),
    |b| fiveg::PduSessionEstablishmentAccept::decode(b).is_ok(),
    |b| fiveg::NetworkSliceSpecificAuthenticationResult::decode(b).is_ok(),
    |b| eps::AttachRequest::decode(b).is_ok(),
    |b| eps::AttachAccept::decode(b).is_ok(),
    |b| eps::TrackingAreaUpdateRequest::decode(b).is_ok(),
    |b| eps::EpsAuthenticationRequest::decode(b).is_ok(),
    |b| eps::PdnConnectivityRequest::decode(b).is_ok(),
];

/// Every input of length 0..=4 over an alphabet of boundary octets and common
/// IEIs. Passing means "no panic"; the result itself is not checked.
#[test]
fn short_inputs_never_panic() {
    const ALPHABET: &[u8] = &[0x00, 0x01, 0x02, 0x10, 0x20, 0x21, 0x31, 0x7e, 0x80, 0xff];
    let mut inputs: Vec<Vec<u8>> = vec![vec![]];
    let mut frontier = inputs.clone();
    for _ in 0..4 {
        frontier = frontier
            .iter()
            .flat_map(|p| {
                ALPHABET.iter().map(move |&o| {
                    let mut v = p.clone();
                    v.push(o);
                    v
                })
            })
            .collect();
        inputs.extend(frontier.iter().cloned());
    }
    for decode in DECODERS {
        for input in &inputs {
            let _ = decode(&mut b(input));
        }
    }
}
