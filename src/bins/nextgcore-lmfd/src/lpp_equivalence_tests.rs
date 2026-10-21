//! #515: lmfd's LPP on the generated codec, pinned to what the pre-migration
//! hand-written code produced.
//!
//! The hand-written LPP codec (`nextgcore-asn1c::lpp`) and its oracle copy of the
//! old builders and adapters are deleted. Before deletion, every builder output and
//! every report fixture's adapted measurements were captured from that code into
//! `lpp_golden_vectors.txt` -- the generated path was already proven equal to it
//! (#544). These tests hold the generated path to those captures, so the deletion
//! changes nothing observable.
//!
//! Requests carrying an extension addition (nr-Multi-RTT, nr-DL-TDOA) are pinned to
//! the generated encoding: its presence bitmap is as long as the additions the
//! Rel-19 schema knows (X.691 §19.7), which is conformant and was value-equal to
//! the old builder's.

use crate::codec_glue::{self, LppMethod, UeLppCapability};

const VECTORS: &str = include_str!("lpp_golden_vectors.txt");

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn lines(tag: &str) -> impl Iterator<Item = &'static str> + '_ {
    VECTORS
        .lines()
        .filter(move |l| l.starts_with(tag))
        .map(move |l| &l[tag.len() + 1..])
}

#[test]
fn requests_are_byte_identical_to_the_captured_builders() {
    let mut n = 0;
    for l in lines("REQ") {
        let f: Vec<&str> = l.split(' ').collect();
        let txn: u8 = f[1].parse().unwrap();
        let method = match f[0] {
            "ecid" => LppMethod::Ecid,
            "rtt" => LppMethod::MultiRtt,
            "tdoa" => LppMethod::DlTdoa,
            other => panic!("{other}"),
        };
        assert_eq!(
            codec_glue::build_lpp_request(method, txn).unwrap(),
            unhex(f[2]),
            "{l}"
        );
        if method == LppMethod::Ecid {
            assert_eq!(
                codec_glue::build_lpp_ecid_request(txn).unwrap(),
                unhex(f[2]),
                "{l}"
            );
        }
        n += 1;
    }
    assert_eq!(n, 6 + 4 + 4);
}

#[test]
fn provide_assistance_data_is_byte_identical_to_the_captured_builder() {
    let mut n = 0;
    for l in lines("PAD") {
        let f: Vec<&str> = l.split(' ').collect();
        let (lat, lon, unc): (f64, f64, f64) = (
            f[0].parse().unwrap(),
            f[1].parse().unwrap(),
            f[2].parse().unwrap(),
        );
        let txn: u8 = f[3].parse().unwrap();
        assert_eq!(
            codec_glue::build_lpp_provide_assistance_data(txn, lat, lon, unc).unwrap(),
            unhex(f[4]),
            "{l}"
        );
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
fn every_report_adapts_as_the_old_adapters_did() {
    let mut n = 0;
    for l in lines("RPT") {
        let f: Vec<&str> = l.split('\t').collect();
        let bytes = unhex(f[0]);
        let g = codec_glue::decode_lpp(&bytes).expect("decodes");
        assert_eq!(
            format!("{:?}", codec_glue::lpp_ecid_provide_to_measurements(&g)),
            f[1],
            "E-CID {}",
            f[0]
        );
        assert_eq!(
            format!(
                "{:?}",
                codec_glue::lpp_multi_rtt_provide_to_measurements(&g)
            ),
            f[2],
            "Multi-RTT {}",
            f[0]
        );
        assert_eq!(
            format!("{:?}", codec_glue::lpp_dl_tdoa_provide_to_measurements(&g)),
            f[3],
            "DL-TDOA {}",
            f[0]
        );
        let (id, _) = codec_glue::decode_lpp_provide_report(&bytes).unwrap();
        assert_eq!(Some(id), codec_glue::extract_lpp_request_id(&g));
        n += 1;
    }
    assert_eq!(n, 8 + 18 + 18);
}

/// The Rel-18 finer-granularity arms (kMinus6..kMinus1) no hand-written codec could
/// carry: `v × 2^k × T_c` with a negative k, and the RSTD keeps its midpoint.
#[test]
fn rel18_fine_granularity_arms_convert() {
    use codec_glue::{nrrstd_to_ns, nrrstd_to_signed_ns, TimeReport};
    let tc = 1_000_000_000.0 / (480_000.0 * 4_096.0);
    assert_eq!(
        nrrstd_to_signed_ns(TimeReport {
            v: 985_024 * 64,
            k: -6
        }),
        0.0
    );
    assert!(
        (nrrstd_to_signed_ns(TimeReport {
            v: 985_024 * 64 + 64,
            k: -6
        }) - tc)
            .abs()
            < 1e-9
    );
    assert_eq!(
        nrrstd_to_ns(TimeReport { v: 2_000, k: -1 }),
        (1_000.0 * tc) as u64
    );
}

/// A ProvideCapabilities with commonIEs and E-CID (rsrp, rsrq) is E-CID only; one
/// without E-CID is unknown. Bytes captured from the hand-written encoder.
#[test]
fn capability_classification_reads_the_generated_report() {
    use nextgcore_lpp_gen::generated as lpp;
    let caps = |h: &str| match codec_glue::decode_lpp(&unhex(h)).unwrap().lpp_message_body {
        Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideCapabilities(p))) => p,
        other => panic!("not ProvideCapabilities: {other:?}"),
    };
    assert_eq!(
        codec_glue::classify_ue_capability(&caps("9203084858")),
        UeLppCapability::EcidOnly
    );
    assert_eq!(
        codec_glue::classify_ue_capability(&caps("92030840")),
        UeLppCapability::Unknown
    );
}

/// `build_lpp_ecid_request(0)` derived by hand from X.691 (UPER, TS 37.355):
///
/// | bits | field |
/// |------|-------|
/// | `1001` | LPP-Message optional bitmap: transactionID, ¬sequenceNumber, ¬acknowledgement, lpp-MessageBody |
/// | `0 0 0` | LPP-TransactionID ext bit; Initiator ext bit, value locationServer (1 bit) |
/// | `00000000` | transactionNumber 0, INTEGER(0..255) |
/// | `0` | endTransaction FALSE |
/// | `0 0100` | lpp-MessageBody c1; c1 index 4 = requestLocationInformation (4 bits) |
/// | `0 00` | criticalExtensions c1; requestLocationInformation-r9 (2 bits) |
/// | `0 00010` | r9-IEs ext bit; optional bitmap: only ecid-RequestLocationInformation |
/// | `0 001 11` | ECID ext bit; BIT STRING SIZE(1..8) length 2 as 3 bits; rsrpReq, rsrqReq |
///
/// 36 bits, padded: `90 00 20 08 70`.
#[test]
fn ecid_request_matches_x691() {
    assert_eq!(
        codec_glue::build_lpp_ecid_request(0).unwrap(),
        vec![0x90, 0x00, 0x20, 0x08, 0x70]
    );
}
