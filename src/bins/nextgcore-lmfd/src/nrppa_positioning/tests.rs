//! #807: the Multi-RTT answers from NG-RAN, decoded on the generated codec.

use super::test_support::*;
use super::*;

const TC_NS: f64 = 1e9 / (480_000.0 * 4_096.0);

/// TS 38.455 §9.2.40 / TS 38.133: a k1 gNB Rx-Tx report v is (2v − 985024)·T_c.
#[test]
fn a_gnb_rx_tx_report_decodes_signed_like_the_ue_half() {
    let bytes = measurement_response(
        4,
        77,
        &[(1, 492_512 + 500, 700, 12), (2, 492_512 - 10, 3, 0)],
    );
    let halves = decode_measurement_response(&bytes, 77).expect("decodes");
    assert_eq!(halves.len(), 2);
    assert_eq!(halves[0].trp_id, 1);
    assert!((halves[0].rx_tx_ns.unwrap() - 1000.0 * TC_NS).abs() < 1e-9);
    assert!((halves[1].rx_tx_ns.unwrap() + 20.0 * TC_NS).abs() < 1e-9);
    assert_eq!(
        halves[0].time,
        Some(SlotTime {
            sfn: 700,
            slot: 12,
            slots_per_frame: 20
        })
    );
}

/// The first and last report values are open-ended bins (TS 38.133), not
/// measurements, and give no half (#812 review rule, gNB side).
#[test]
fn open_ended_gnb_reports_are_not_decoded() {
    let bytes = measurement_response(
        4,
        77,
        &[(1, 0, 0, 0), (2, 985_025, 0, 0), (3, 985_024, 0, 0)],
    );
    let halves = decode_measurement_response(&bytes, 77).unwrap();
    assert_eq!(halves[0].rx_tx_ns, None);
    assert_eq!(halves[1].rx_tx_ns, None);
    assert!(
        halves[2].rx_tx_ns.is_some(),
        "the last bin below the maximum is a value"
    );
}

/// A response for another measurement would pair a TRP's gNB half with another
/// UE's UE half: refused.
#[test]
fn a_response_for_another_measurement_is_refused() {
    let bytes = measurement_response(4, 78, &[(1, 492_512, 0, 0)]);
    assert!(decode_measurement_response(&bytes, 77).is_err());
}

/// TRP Information: PCI and the high-accuracy position (lat = N·90/2^31,
/// lon = N·180/2^31, altitude in cm), with the bin centre taken.
#[test]
fn trp_information_gives_the_pci_and_the_position() {
    let lat = (51.4778_f64 * f64::from(1u32 << 31) / 90.0).floor() as i32;
    let lon = (-0.0015_f64 * f64::from(1u32 << 31) / 180.0).floor() as i32;
    let bytes = trp_information_response(3, &[(9, 501, lat, lon, 1234)]);
    let trps = decode_trp_information_response(&bytes).expect("decodes");
    assert_eq!(trps.len(), 1);
    assert_eq!(trps[0].trp_id, 9);
    assert_eq!(trps[0].pci, Some(501));
    let c = trps[0].coord.expect("a direct position");
    assert!((c.lat_deg - 51.4778).abs() < 1e-7);
    assert!((c.lon_deg + 0.0015).abs() < 1e-7);
    assert!((c.height_m - 12.34).abs() < 1e-9);
}

/// Semi-persistent SRS is activated by its set id; periodic needs nothing.
#[test]
fn the_srs_to_activate_follows_the_configured_resource_type() {
    use crate::nrppa_downlink::SrsActivation;
    assert_eq!(
        srs_activation(&srs_configuration(5)),
        Some(SrsActivation::SemiPersistent(5))
    );
    let mut periodic = srs_configuration(5);
    let set = &mut periodic.srs_carrier_list.0[0]
        .active_ulbwp
        .srs_config
        .pos_srs_resource_set_list
        .as_mut()
        .unwrap()
        .0[0];
    set.posresource_set_type =
        nrppa::PosResourceSetType::Periodic(nrppa::PosResourceSetTypePeriodic {
            posperiodic_set: nrppa::PosResourceSetTypePeriodicPosperiodicSet(0),
            ie_extensions: None,
        });
    assert_eq!(srs_activation(&periodic), None);
}

/// The SFN wraps at 1024 frames: SFN 1023 and SFN 0 are 10 ms apart.
#[test]
fn time_stamps_are_compared_across_the_sfn_wrap() {
    let t = |sfn, slot| SlotTime {
        sfn,
        slot,
        slots_per_frame: 20,
    };
    assert!((t(1023, 0).distance_ms(&t(0, 0)) - 10.0).abs() < 1e-9);
    assert!((t(700, 11).distance_ms(&t(700, 12)) - 0.5).abs() < 1e-9);
    assert!((t(0, 0).distance_ms(&t(512, 0)) - 5120.0).abs() < 1e-9);
}

/// Answers are routed by (kind, procedure, transaction) read off the header.
#[test]
fn the_header_names_the_exchange() {
    let bytes = positioning_activation_response(321);
    assert_eq!(
        header(&bytes),
        Some((Kind::Successful, nrppa::ID_POSITIONING_ACTIVATION, 321))
    );
    assert_eq!(header(&[0xff, 0x00]), None);
}
