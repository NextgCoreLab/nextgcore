//! Codec checks for the generated LPP codec (#515).
//!
//! Hand-derived X.691 UPER octets pin the encoder. `cross_codec_vectors.txt` holds
//! every LPP-Message lmfd built with the hand-written `nextgcore-asn1c::lpp` codec,
//! captured from that encoder before it was deleted: `EXACT` messages carry no
//! extension addition and must re-encode byte for byte; `VALUE` messages carry
//! Rel-16+ additions, where the generated presence bitmap is as long as the Rel-19
//! schema's additions (X.691 §19.7), so they must decode and re-encode to a value
//! that decodes back to itself.

use super::{decode, encode};

/// RequestCapabilities { commonIEs, ecid } from the target device, transaction 1.
/// UPER, hand-derived: LPP-Message preamble 1001 | transactionID ext 0,
/// targetDevice 01, 00000001 | endTransaction 0 | body c1 0, index 0 0000 |
/// criticalExtensions c1 0, r9 00 | r9-IEs ext 0, opts 10010 |
/// CommonIEsRequestCapabilities ext 0 | ECID-RequestCapabilities ext 0.
const REQUEST_CAPABILITIES: [u8; 4] = [0x92, 0x02, 0x00, 0x48];

/// ProvideCapabilities { commonIEs, ecid '11000'B }, end of transaction:
/// as above with endTransaction 1 and body index 1 (0001), then
/// ECID-ProvideCapabilities ext 0, SIZE(1..8) length-1 = 4 (100), bits 11000.
const PROVIDE_CAPABILITIES: [u8; 5] = [0x92, 0x03, 0x08, 0x48, 0x98];

/// RequestLocationInformation { ecid '11000'B } from the location server,
/// transaction 0, end of transaction -- the vector nextgcore-asn1c derived.
const REQUEST_LOCATION_INFORMATION: [u8; 5] = [0x90, 0x01, 0x20, 0x09, 0x30];

/// ProvideLocationInformation { ecid { signalMeasurementInformation {
/// measuredResultsList [ { physCellId 42, arfcnEUTRA 1850, rsrp 50, rsrq 20 } ] } } }
/// from the target device, transaction 7, end of transaction: preamble 1001 |
/// tid 0 01 00000111 | end 1 | c1 0, index 5 0101 | crit 0 00 | r9-IEs ext 0,
/// opts 00010 | ECID-Provide ext 0, opts 10 | SignalMeas ext 0, opt 0 |
/// list SIZE(1..32) 00000 | element ext 0, opts 00110, physCellId 9 bits,
/// arfcnEUTRA 16 bits, rsrp 7 bits, rsrq 6 bits | pad.
const PROVIDE_LOCATION_INFORMATION: [u8; 11] = [
    0x92, 0x0f, 0x28, 0x09, 0x00, 0x18, 0x54, 0x0e, 0x74, 0xc9, 0x40,
];

fn roundtrip_exact(bytes: &[u8]) {
    let msg = decode(bytes).expect("decodes");
    assert_eq!(encode(&msg).expect("encodes"), bytes);
}

#[test]
fn request_capabilities_matches_x691() {
    roundtrip_exact(&REQUEST_CAPABILITIES);
}

#[test]
fn provide_capabilities_matches_x691() {
    roundtrip_exact(&PROVIDE_CAPABILITIES);
}

#[test]
fn request_location_information_matches_x691() {
    roundtrip_exact(&REQUEST_LOCATION_INFORMATION);
}

#[test]
fn provide_location_information_matches_x691() {
    roundtrip_exact(&PROVIDE_LOCATION_INFORMATION);
}

/// The smallest message: no transaction, no body, endTransaction FALSE.
#[test]
fn minimal_message_matches_x691() {
    roundtrip_exact(&[0x00]);
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_message_the_hand_written_codec_built_decodes_here() {
    let (mut exact, mut value) = (0, 0);
    for line in include_str!("cross_codec_vectors.txt").lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let bytes = unhex(f[2]);
        let msg = decode(&bytes).unwrap_or_else(|e| panic!("{}: decode {e:?}", f[1]));
        let again = encode(&msg).unwrap_or_else(|e| panic!("{}: encode {e:?}", f[1]));
        match f[0] {
            "EXACT" => {
                assert_eq!(again, bytes, "{}: re-encode differs", f[1]);
                exact += 1;
            }
            "VALUE" => {
                assert_eq!(
                    decode(&again).expect("re-decodes"),
                    msg,
                    "{}: value drifts",
                    f[1]
                );
                value += 1;
            }
            other => panic!("{other}"),
        }
    }
    assert_eq!((exact, value), (20, 7));
}
