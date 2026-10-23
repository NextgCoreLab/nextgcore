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
            "nrecid" => LppMethod::NrEcid,
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
    assert_eq!(n, 6 + 6 + 4 + 4);
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

/// The captured adapter output as field → value text, one map per cell.
fn cells_of(debug: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    debug
        .split("CellMeasurement { ")
        .skip(1)
        .map(|c| {
            let body = &c[..c.find(" }").expect("a closing brace")];
            body.split(", ")
                .map(|f| {
                    let (k, v) = f.split_once(": ").expect("field: value");
                    (k.to_string(), v.to_string())
                })
                .collect()
        })
        .collect()
}

/// `new` minus the fields #713 and #714 added: the Rx–Tx halves, which must be
/// absent here, and `dl_prs_id`, which must agree with a `prs-<id>` key.
fn without_new_fields(
    mut new: Vec<std::collections::BTreeMap<String, String>>,
    what: &str,
) -> Vec<std::collections::BTreeMap<String, String>> {
    for c in &mut new {
        for k in ["ue_rx_tx_ns", "gnb_rx_tx_ns"] {
            assert_eq!(c.remove(k).as_deref(), Some("None"), "{what}: {k}");
        }
        check_dl_prs_id(c, what);
        check_eutra(c, what);
        if what != "E-CID" {
            assert_eq!(c.remove("ecid_rtt_ns").as_deref(), Some("None"), "{what}");
        }
        check_rstd_reference(c, what);
    }
    new
}

/// Remove `dl_prs_id`, checking it against the key: an E-CID cell has none,
/// and an LPP NR cell keyed `prs-<id>` carries that id.
fn check_dl_prs_id(c: &mut std::collections::BTreeMap<String, String>, what: &str) {
    let id = c.remove("dl_prs_id").expect("dl_prs_id");
    if what == "E-CID" {
        assert_eq!(id, "None", "{what}");
    } else if let Some(prs) = c["nr_cgi"].trim_matches('"').strip_prefix("prs-") {
        assert_eq!(id, format!("Some({prs})"), "{what}");
    } else {
        assert!(id.starts_with("Some("), "{what}: {id}");
    }
}

/// Remove `eutra` (#715): only the E-UTRA E-CID adapter's cells are E-UTRA.
fn check_eutra(c: &mut std::collections::BTreeMap<String, String>, what: &str) {
    let want = if what == "E-CID" { "true" } else { "false" };
    assert_eq!(c.remove("eutra").as_deref(), Some(want), "{what}");
}

/// Remove `rstd_reference` (#824 review): only DL-TDOA cells carry one, and all
/// cells of one DL-TDOA report carry the same.
fn check_rstd_reference(c: &mut std::collections::BTreeMap<String, String>, what: &str) {
    let r = c.remove("rstd_reference").expect("rstd_reference");
    if what == "DL-TDOA" {
        assert!(r.starts_with("Some("), "{what}: {r}");
    } else {
        assert_eq!(r, "None", "{what}");
    }
}

fn some_f64(v: &str) -> f64 {
    v.strip_prefix("Some(")
        .and_then(|v| v.strip_suffix(')'))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("not Some(number): {v}"))
}

/// E-CID and DL-TDOA adapt exactly as the captured hand-written adapters did.
///
/// Multi-RTT does not, on purpose (#713). The old adapter read
/// `nr-UE-RxTxTimeDiff` as an unsigned magnitude, `⌊v·2^k·T_c⌋`, and called it
/// an RTT. The new one decodes the signed TS 38.133 §10.1.25.3 value
/// `(v·2^k − 985024)·T_c` as the UE half (`ue_rx_tx_ns`) and leaves `rtt_ns`
/// empty. So each captured `rtt_ns` R must satisfy
/// `R ≤ ue_rx_tx_ns + 985024·T_c < R + 1`, with every other field unchanged.
#[test]
fn every_report_adapts_as_the_old_adapters_did() {
    let tc = 1_000_000_000.0 / (480_000.0 * 4_096.0);
    let mut n = 0;
    for l in lines("RPT") {
        let f: Vec<&str> = l.split('\t').collect();
        let bytes = unhex(f[0]);
        let g = codec_glue::decode_lpp(&bytes).expect("decodes");
        let ecid = cells_of(&format!(
            "{:?}",
            codec_glue::lpp_ecid_provide_to_measurements(&g)
        ));
        // #832: the captured raw `timing_advance` (the UE Rx-Tx report value) is
        // now decoded per TS 36.133 §9.1.9.2 into `ecid_rtt_ns`.
        let mut captured = cells_of(f[1]);
        let mut new = without_new_fields(ecid, "E-CID");
        for (n_cell, c_cell) in new.iter_mut().zip(captured.iter_mut()) {
            let raw = c_cell.remove("timing_advance").expect("timing_advance");
            let want = match raw.as_str() {
                "None" => None,
                v => crate::positioning::eutra_time_report_to_ns(
                    some_f64(v) as u32,
                    crate::positioning::EUTRA_UE_RX_TX_MAX,
                )
                .map(|(mid, _)| mid),
            };
            assert_eq!(n_cell.remove("timing_advance").as_deref(), Some("None"));
            assert_eq!(
                n_cell.remove("ecid_rtt_ns").expect("ecid_rtt_ns"),
                format!("{want:?}"),
                "E-CID {}",
                f[0]
            );
        }
        assert_eq!(new, captured, "E-CID {}", f[0]);

        let rtt = cells_of(&format!(
            "{:?}",
            codec_glue::lpp_multi_rtt_provide_to_measurements(&g)
        ));
        let captured = cells_of(f[2]);
        assert_eq!(rtt.len(), captured.len(), "Multi-RTT {}", f[0]);
        for (mut new, old) in rtt.into_iter().zip(captured) {
            let r = some_f64(&old["rtt_ns"]);
            match new.remove("ue_rx_tx_ns").expect("ue_rx_tx_ns").as_str() {
                // An open-ended report value (TS 38.133 §10.1.25.3) is not decoded:
                // the captured value was the first bin (0) or the last (≈ 1002018 ns
                // at k0 and above).
                "None" => assert!(
                    r == 0.0 || r >= 1_002_017.0,
                    "Multi-RTT {}: captured rtt_ns {r} is not an open-ended bin",
                    f[0]
                ),
                v => {
                    let ue = some_f64(v);
                    let unsigned = ue + 985_024.0 * tc;
                    assert!(
                        r <= unsigned + 1e-6 && unsigned < r + 1.0,
                        "Multi-RTT {}: captured rtt_ns {r}, new ue_rx_tx_ns {ue}",
                        f[0]
                    );
                }
            }
            assert_eq!(new.remove("rtt_ns").as_deref(), Some("None"));
            assert_eq!(new.remove("gnb_rx_tx_ns").as_deref(), Some("None"));
            check_dl_prs_id(&mut new, "Multi-RTT");
            check_eutra(&mut new, "Multi-RTT");
            assert_eq!(new.remove("ecid_rtt_ns").as_deref(), Some("None"));
            check_rstd_reference(&mut new, "Multi-RTT");
            let mut old = old;
            old.remove("rtt_ns");
            assert_eq!(new, old, "Multi-RTT {}", f[0]);
        }

        let tdoa = cells_of(&format!(
            "{:?}",
            codec_glue::lpp_dl_tdoa_provide_to_measurements(&g)
        ));
        // An open-ended RSTD report value (TS 38.133 §10.1.23.3) is no longer
        // decoded: where the new adapter gives None, the captured value must be
        // a first or last bin, ≈ ±501009 ns.
        let mut captured = cells_of(f[3]);
        let new = without_new_fields(tdoa, "DL-TDOA");
        for (n_cell, c_cell) in new.iter().zip(captured.iter_mut()) {
            if n_cell["rstd_ns"] == "None" && c_cell["rstd_ns"] != "None" {
                let x = some_f64(&c_cell["rstd_ns"]);
                assert!(
                    x.abs() >= 501_009.0,
                    "DL-TDOA {}: {x} is not an open-ended bin",
                    f[0]
                );
                c_cell.insert("rstd_ns".into(), "None".into());
            }
        }
        assert_eq!(new, captured, "DL-TDOA {}", f[0]);
        let (id, _) = codec_glue::decode_lpp_provide_report(&bytes).unwrap();
        assert_eq!(Some(id), codec_glue::extract_lpp_request_id(&g));
        n += 1;
    }
    assert_eq!(n, 8 + 18 + 18);
}

/// The Rel-18 finer-granularity arms (kMinus6..kMinus1) no hand-written codec could
/// carry: `v × 2^k × T_c` with a negative k, and both RSTD and UE Rx–Tx keep their
/// midpoint.
#[test]
fn rel18_fine_granularity_arms_convert() {
    use codec_glue::{nrrstd_to_signed_ns, ue_rx_tx_to_signed_ns, TimeReport};
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
    // #713: the UE Rx–Tx keeps the same midpoint at the finer step.
    assert!(
        (ue_rx_tx_to_signed_ns(TimeReport { v: 2_000, k: -1 }).unwrap()
            - (1_000.0 - 985_024.0) * tc)
            .abs()
            < 1e-6
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
/// | `0 010 111` | ECID ext bit; BIT STRING SIZE(1..8) length 3 as `3 − 1` in 3 bits; rsrpReq, rsrqReq, ueRxTxReq (#715) |
///
/// 37 bits, padded: `90 00 20 08 B8`. (Before #715, length 2 and no ueRxTxReq:
/// `0 001 11`, 36 bits, `90 00 20 08 70`.)
#[test]
fn ecid_request_matches_x691() {
    assert_eq!(
        codec_glue::build_lpp_ecid_request(0).unwrap(),
        vec![0x90, 0x00, 0x20, 0x08, 0xB8]
    );
    assert_eq!(
        codec_glue::build_lpp_request(LppMethod::Ecid, 0).unwrap(),
        vec![0x90, 0x00, 0x20, 0x08, 0xB8]
    );
}

/// `build_lpp_request(NrEcid, 0)` derived by hand from X.691 (UPER, TS 37.355
/// Rel-16, #715). The first 26 bits are as in [`ecid_request_matches_x691`]
/// (`1001 000 00000000 0 0 0100 0 00`), then:
///
/// | bits | field |
/// |------|-------|
/// | `1` | r9-IEs extension bit: extension additions present |
/// | `00000` | root optional bitmap: none of the five root members |
/// | `0 000010` | X.691 §19.8: extension-addition bitmap length, normally small, `3 − 1` (three groups: r13, r16, r19) |
/// | `010` | only the Rel-16 group is present |
/// | `00000010` | X.691 §19.9: the group as an open type, length 2 octets |
/// | `1000` | the group's presence bitmap: nr-ECID present, nr-Multi-RTT, nr-DL-AoD, nr-DL-TDOA absent |
/// | `0 001 11` | NR-ECID-RequestLocationInformation-r16: ext bit; BIT STRING SIZE(1..8) length 2; ssrsrpReq, ssrsrqReq |
/// | `000000` | padding of the open type to an octet |
///
/// `90 00 20 80 12 02 81 C0`.
#[test]
fn nr_ecid_request_matches_x691() {
    assert_eq!(
        codec_glue::build_lpp_request(LppMethod::NrEcid, 0).unwrap(),
        vec![0x90, 0x00, 0x20, 0x80, 0x12, 0x02, 0x81, 0xC0]
    );
}
