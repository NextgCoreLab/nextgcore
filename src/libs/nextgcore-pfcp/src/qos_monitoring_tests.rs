//! Spec-vector tests for the QoS-monitoring, GTP-U path monitoring and N6
//! delay IEs. Every expected byte string is written out by hand from the
//! TS 29.244 V20.0.0 figure or table it names, not produced by the encoder
//! under test; each test then checks encode == vector and decode(vector) ==
//! value, so a codec that agrees with itself but not with the spec fails.

use super::*;

fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
    let mut out = t.to_be_bytes().to_vec();
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    out
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// encode_ie(value) == the hand-built TLV, and decode_ie(TLV) == value.
fn assert_vector<T: TypedIe + PartialEq + std::fmt::Debug>(value: &T, ie_type: u16, v: &[u8]) {
    let want = tlv(ie_type, v);
    let mut buf = BytesMut::new();
    value.encode_ie(&mut buf);
    assert_eq!(&buf[..], &want[..], "encode of {value:?}");
    let mut wire = Bytes::from(want);
    assert_eq!(&T::decode_ie(&mut wire).unwrap(), value);
    assert!(!wire.has_remaining());
}

// ---------------------------------------------------------------- leaf IEs

#[test]
fn ie_type_values_match_table_8_1_2_1() {
    let table: &[(IeType, u16)] = &[
        (IeType::AveragePacketDelay, 234),
        (IeType::MinimumPacketDelay, 235),
        (IeType::MaximumPacketDelay, 236),
        (IeType::QosReportTrigger, 237),
        (IeType::GtpUPathQosControlInformation, 238),
        (IeType::GtpUPathQosReport, 239),
        (IeType::QosInformationInGtpUPathQosReport, 240),
        (IeType::GtpUPathInterfaceType, 241),
        (IeType::QosMonitoringPerQosFlowControlInformation, 242),
        (IeType::RequestedQosMonitoring, 243),
        (IeType::ReportingFrequency, 244),
        (IeType::PacketDelayThresholds, 245),
        (IeType::MinimumWaitTime, 246),
        (IeType::QosMonitoringReport, 247),
        (IeType::QosMonitoringMeasurement, 248),
        (IeType::TransportDelayReporting, 271),
        (IeType::N6DelayMeasurementProtocols, 354),
        (IeType::N6DelayMeasurementControlInformation, 355),
        (IeType::N6DelayMeasurementReport, 356),
        (IeType::N6DelayMeasurementInformation, 357),
        (IeType::MeasurementEndpointAddress, 358),
        (IeType::MeasurementReportingType, 375),
        (IeType::N6DelayMeasurementFailureInformation, 376),
        (IeType::N6DelayMeasurementControlInformationId, 377),
        (IeType::ProtocolSpecificConfigurationParameters, 378),
        (IeType::MeasurementEndpointPortNumber, 379),
    ];
    for (t, v) in table {
        assert_eq!(*t as u16, *v, "{t:?}");
    }
}

#[test]
fn packet_delay_ies_234_to_236_and_246_are_u32() {
    // Figures 8.2.162-1 .. 8.2.164-1: octets 5-8 the delay in ms.
    assert_vector(&AveragePacketDelay(0x0102_0304), 234, &[1, 2, 3, 4]);
    assert_vector(&MinimumPacketDelay(7), 235, &[0, 0, 0, 7]);
    assert_vector(&MaximumPacketDelay(65_536), 236, &[0, 1, 0, 0]);
    // Figure 8.2.170-1: octets 5-8 the wait in seconds.
    assert_vector(&MinimumWaitTime(30), 246, &[0, 0, 0, 30]);
}

#[test]
fn qos_report_trigger_237_bits() {
    // Figure 8.2.165-1: bit 1 PER, bit 2 THR, bit 3 IRE.
    assert_vector(
        &QosReportTrigger {
            per: true,
            ..Default::default()
        },
        237,
        &[0x01],
    );
    assert_vector(
        &QosReportTrigger {
            thr: true,
            ..Default::default()
        },
        237,
        &[0x02],
    );
    assert_vector(
        &QosReportTrigger {
            ire: true,
            ..Default::default()
        },
        237,
        &[0x04],
    );
}

#[test]
fn gtpu_path_interface_type_241_bits() {
    // Figure 8.2.166-1: bit 1 N9, bit 2 N3.
    assert_vector(
        &GtpUPathInterfaceType {
            n9: true,
            n3: false,
        },
        241,
        &[0x01],
    );
    assert_vector(
        &GtpUPathInterfaceType {
            n9: false,
            n3: true,
        },
        241,
        &[0x02],
    );
}

#[test]
fn requested_qos_monitoring_243_is_minimal_length() {
    // Figure 8.2.167-1 octet 5: DLPD ULPD RPPD GTPUPM DLCI ULCI DLDR ULDR.
    let delay = RequestedQosMonitoring {
        dlpd: true,
        ulpd: true,
        rppd: true,
        ..Default::default()
    };
    // Table 8.1.2-1 lists a fixed part of 1 octet: no octet 6 unless needed.
    assert_vector(&delay, 243, &[0x07]);
    let all5 = RequestedQosMonitoring {
        dlpd: true,
        ulpd: true,
        rppd: true,
        gtpupm: true,
        dlci: true,
        ulci: true,
        dldr: true,
        uldr: true,
        ..Default::default()
    };
    assert_vector(&all5, 243, &[0xff]);
    // Octet 6: bit 1 DLAB, bit 2 ULAB.
    let ab = RequestedQosMonitoring {
        dlpd: true,
        ulab: true,
        ..Default::default()
    };
    assert_vector(&ab, 243, &[0x01, 0x02]);
    // Spare bits of octet 6 are ignored.
    assert_eq!(
        RequestedQosMonitoring::decode_value(&[0x08, 0xfc]).unwrap(),
        RequestedQosMonitoring {
            gtpupm: true,
            ..Default::default()
        }
    );
}

#[test]
fn reporting_frequency_244_ignores_the_reserved_bit() {
    // Figure 8.2.168-1: bit 1 EVETT, bit 2 PERIO, bit 3 Reserved.
    assert_vector(
        &ReportingFrequency {
            evett: true,
            perio: false,
        },
        244,
        &[0x01],
    );
    assert_vector(
        &ReportingFrequency {
            evett: false,
            perio: true,
        },
        244,
        &[0x02],
    );
    assert_eq!(
        ReportingFrequency::decode_value(&[0x06]).unwrap(),
        ReportingFrequency {
            evett: false,
            perio: true
        }
    );
}

#[test]
fn packet_delay_thresholds_245_flags_select_fields() {
    // Figure 8.2.169-1: flags DL(1) UL(2) RP(3), then DL, UL, RP as u32.
    let t = PacketDelayThresholds {
        downlink: Some(10),
        uplink: None,
        round_trip: Some(0x0000_0100),
    };
    assert_vector(&t, 245, &[0x05, 0, 0, 0, 10, 0, 0, 1, 0]);
    let all = PacketDelayThresholds {
        downlink: Some(1),
        uplink: Some(2),
        round_trip: Some(3),
    };
    assert_vector(&all, 245, &[0x07, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    // A flagged field that is not there is an error, not a zero.
    assert!(PacketDelayThresholds::decode_value(&[0x02, 0, 0]).is_err());
}

#[test]
fn qos_monitoring_measurement_248_all_fields_in_figure_order() {
    // Figure 8.2.171-1: flags then DL/UL/RP delay (4 each), DL/UL congestion
    // (2 each), average DL/UL data rate (5 each).
    let m = QosMonitoringMeasurement {
        downlink_packet_delay: Some(5),
        uplink_packet_delay: Some(6),
        round_trip_packet_delay: Some(11),
        packet_delay_measurement_failure: false,
        downlink_congestion: Some(9574),
        uplink_congestion: Some(10_000),
        average_downlink_data_rate: Some(0x01_0000_0002),
        average_uplink_data_rate: Some(1000),
    };
    let v = [
        0xf7, // ULDR DLDR ULCI DLCI, PLMF clear, RPPD ULPD DLPD
        0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 11, // delays
        0x25, 0x66, 0x27, 0x10, // 9574, 10000
        0x01, 0, 0, 0, 0x02, // DL rate, 5 octets
        0, 0, 0, 0x03, 0xe8, // UL rate 1000
    ];
    assert_vector(&m, 248, &v);
}

#[test]
fn qos_monitoring_measurement_248_failure_and_partial() {
    // PLMF (bit 4) alone: no delay fields.
    let plmf = QosMonitoringMeasurement {
        packet_delay_measurement_failure: true,
        ..Default::default()
    };
    assert_vector(&plmf, 248, &[0x08]);
    // UL delay only.
    let ul = QosMonitoringMeasurement {
        uplink_packet_delay: Some(42),
        ..Default::default()
    };
    assert_vector(&ul, 248, &[0x02, 0, 0, 0, 42]);
    // The 5-octet rate saturates rather than wrapping.
    let big = QosMonitoringMeasurement {
        average_uplink_data_rate: Some(u64::MAX),
        ..Default::default()
    };
    let mut buf = BytesMut::new();
    big.encode_value(&mut buf);
    assert_eq!(&buf[..], &[0x80, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Truncated rate field.
    assert!(QosMonitoringMeasurement::decode_value(&[0x40, 0, 0, 0, 1]).is_err());
}

#[test]
fn n6_delay_measurement_protocols_354_bits() {
    // Figure 8.2.246-1: TWAMP(1) OWAMP(2) STAMP(3) OTHER(4).
    let p = N6DelayMeasurementProtocols {
        twamp: true,
        stamp: true,
        ..Default::default()
    };
    assert_vector(&p, 354, &[0x05]);
    assert_vector(
        &N6DelayMeasurementProtocols {
            other: true,
            owamp: true,
            ..Default::default()
        },
        354,
        &[0x0a],
    );
}

#[test]
fn n6_delay_measurement_information_357_average_always_present() {
    // Figure 8.2.247-1: flags MIND(1) MAXD(2); octets 6-9 average; then min, max.
    let i = N6DelayMeasurementInformation {
        average_packet_delay: 12,
        minimum_packet_delay: None,
        maximum_packet_delay: Some(40),
    };
    assert_vector(&i, 357, &[0x02, 0, 0, 0, 12, 0, 0, 0, 40]);
    let both = N6DelayMeasurementInformation {
        average_packet_delay: 12,
        minimum_packet_delay: Some(3),
        maximum_packet_delay: Some(40),
    };
    assert_vector(&both, 357, &[0x03, 0, 0, 0, 12, 0, 0, 0, 3, 0, 0, 0, 40]);
    assert!(N6DelayMeasurementInformation::decode_value(&[0x00, 0, 0]).is_err());
}

#[test]
fn measurement_endpoint_address_358_v4_is_bit_1() {
    // Figure 8.2.248-1: bit 1 V4, bit 2 V6 (the reverse of Remote GTP-U Peer).
    let v4 = MeasurementEndpointAddress {
        ipv4: Some([192, 0, 2, 10]),
        ipv6: None,
    };
    assert_vector(&v4, 358, &[0x01, 192, 0, 2, 10]);
    let a6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dual = MeasurementEndpointAddress {
        ipv4: Some([192, 0, 2, 10]),
        ipv6: Some(a6),
    };
    let mut v = vec![0x03, 192, 0, 2, 10];
    v.extend_from_slice(&a6);
    assert_vector(&dual, 358, &v);
    // "Either the V4 flag or the V6 flag shall be set to 1."
    assert!(MeasurementEndpointAddress::decode_value(&[0x00]).is_err());
}

#[test]
fn n6_member_leaves_375_to_379() {
    // Figure 8.2.262-1: PER(1) EVT(2) IRE(3).
    assert_vector(
        &MeasurementReportingType {
            evt: true,
            ire: true,
            ..Default::default()
        },
        375,
        &[0x06],
    );
    // Figure 8.2.263-1 / Table 8.2.263-1.
    let lost = N6DelayMeasurementFailureInformation { cause: 2 };
    assert_vector(&lost, 376, &[0x02]);
    assert_eq!(
        lost.effective_cause(),
        N6DelayMeasurementFailureInformation::CONNECTION_LOST
    );
    // "If the receiver cannot comprehend the value ... unspecified."
    assert_eq!(
        N6DelayMeasurementFailureInformation { cause: 9 }.effective_cause(),
        0
    );
    // Figures 8.2.264-1 and 8.2.265-1: fixed 2 octets.
    assert_vector(
        &N6DelayMeasurementControlInformationId(0x0102),
        377,
        &[1, 2],
    );
    assert_vector(&MeasurementEndpointPortNumber(862), 379, &[0x03, 0x5e]);
}

#[test]
fn shared_members_tlm_and_timer() {
    // §8.2.12: ToS/Traffic Class then mask 0xFC. DSCP 46 (EF) -> ToS 0xB8.
    let ef = TransportLevelMarking::from_dscp(46);
    assert_vector(&ef, 30, &[0xb8, 0xfc]);
    assert_eq!(ef.dscp(), 46);
    // §8.2.35: unit bits 6-8, value bits 1-5. Unit 1 (minute), value 3.
    assert_vector(&Timer { unit: 1, value: 3 }, 55, &[0x23]);
}

#[test]
fn extendable_leaves_ignore_trailing_octets() {
    // §8.1.2: "Extendable" IEs may carry octets this release does not define.
    assert_eq!(
        QosReportTrigger::decode_value(&[0x01, 0xaa, 0xbb]).unwrap(),
        QosReportTrigger {
            per: true,
            ..Default::default()
        }
    );
    assert_eq!(
        AveragePacketDelay::decode_value(&[0, 0, 0, 9, 0xff])
            .unwrap()
            .0,
        9
    );
    assert_eq!(
        N6DelayMeasurementProtocols::decode_value(&[0xf1, 0x00]).unwrap(),
        N6DelayMeasurementProtocols {
            twamp: true,
            ..Default::default()
        }
    );
}

#[test]
fn empty_values_are_rejected_not_panicking() {
    assert!(QosReportTrigger::decode_value(&[]).is_err());
    assert!(GtpUPathInterfaceType::decode_value(&[]).is_err());
    assert!(RequestedQosMonitoring::decode_value(&[]).is_err());
    assert!(ReportingFrequency::decode_value(&[]).is_err());
    assert!(PacketDelayThresholds::decode_value(&[]).is_err());
    assert!(QosMonitoringMeasurement::decode_value(&[]).is_err());
    assert!(MinimumWaitTime::decode_value(&[0, 0, 1]).is_err());
    assert!(N6DelayMeasurementControlInformationId::decode_value(&[1]).is_err());
    assert!(MeasurementEndpointPortNumber::decode_value(&[]).is_err());
    assert!(TransportLevelMarking::decode_value(&[0xb8]).is_err());
}

#[test]
fn decode_ie_rejects_the_wrong_type() {
    let mut wire = Bytes::from(tlv(236, &[0, 0, 0, 1]));
    assert!(matches!(
        AveragePacketDelay::decode_ie(&mut wire),
        Err(PfcpError::InvalidIeType(236))
    ));
}

// ------------------------------------------------------------- grouped IEs

fn peer_v4(a: [u8; 4]) -> RemoteGtpUPeer {
    RemoteGtpUPeer {
        ipv4: Some(a),
        ..Default::default()
    }
}

#[test]
fn gtpu_path_qos_control_information_238_table_7_4_4_1_3_1() {
    let ie = GtpUPathQosControlInformation {
        remote_gtpu_peers: vec![peer_v4([10, 0, 0, 1]), peer_v4([10, 0, 0, 2])],
        gtpu_path_interface_type: Some(GtpUPathInterfaceType {
            n9: false,
            n3: true,
        }),
        qos_report_trigger: QosReportTrigger {
            per: true,
            thr: true,
            ire: false,
        },
        dscp: vec![TransportLevelMarking::from_dscp(46)],
        measurement_period: Some(10),
        average_packet_delay_threshold: Some(20),
        minimum_packet_delay_threshold: None,
        maximum_packet_delay_threshold: Some(50),
        minimum_waiting_time: Some(Timer { unit: 0, value: 5 }),
        extra: vec![],
    };
    let v = cat(&[
        tlv(103, &[0x02, 10, 0, 0, 1]),
        tlv(103, &[0x02, 10, 0, 0, 2]),
        tlv(241, &[0x02]),
        tlv(237, &[0x03]),
        tlv(30, &[0xb8, 0xfc]),
        tlv(64, &[0, 0, 0, 10]),
        tlv(234, &[0, 0, 0, 20]),
        tlv(236, &[0, 0, 0, 50]),
        tlv(55, &[0x05]),
    ]);
    assert_vector(&ie, 238, &v);
    // NOTE: at least one Remote GTP-U Peer or GTP-U Path Interface Type.
    let by_type = cat(&[tlv(241, &[0x01]), tlv(237, &[0x04])]);
    assert!(GtpUPathQosControlInformation::decode_value(&by_type).is_ok());
    assert!(matches!(
        GtpUPathQosControlInformation::decode_value(&tlv(237, &[0x04])),
        Err(PfcpError::MissingMandatoryIe(_))
    ));
    // QoS Report Trigger is M.
    let no_trigger = cat(&[tlv(103, &[0x02, 10, 0, 0, 1])]);
    assert!(matches!(
        GtpUPathQosControlInformation::decode_value(&no_trigger),
        Err(PfcpError::MissingMandatoryIe(_))
    ));
}

#[test]
fn gtpu_path_qos_report_239_with_qos_information_240() {
    let ie = GtpUPathQosReport {
        remote_gtpu_peer: peer_v4([10, 0, 0, 9]),
        gtpu_path_interface_type: Some(GtpUPathInterfaceType {
            n9: true,
            n3: false,
        }),
        qos_report_trigger: QosReportTrigger {
            per: true,
            ..Default::default()
        },
        time_stamp: 0xe8a0_0000,
        start_time: Some(0xe89f_fff0),
        qos_information: vec![
            QosInformationInGtpUPathQosReport {
                average_packet_delay: 4,
                minimum_packet_delay: Some(2),
                maximum_packet_delay: Some(9),
                dscp: Some(TransportLevelMarking::from_dscp(46)),
                extra: vec![],
            },
            QosInformationInGtpUPathQosReport {
                average_packet_delay: 7,
                ..Default::default()
            },
        ],
        extra: vec![],
    };
    let qi1 = cat(&[
        tlv(234, &[0, 0, 0, 4]),
        tlv(235, &[0, 0, 0, 2]),
        tlv(236, &[0, 0, 0, 9]),
        tlv(30, &[0xb8, 0xfc]),
    ]);
    let qi2 = tlv(234, &[0, 0, 0, 7]);
    let v = cat(&[
        tlv(103, &[0x02, 10, 0, 0, 9]),
        tlv(241, &[0x01]),
        tlv(237, &[0x01]),
        tlv(156, &[0xe8, 0xa0, 0, 0]),
        tlv(75, &[0xe8, 0x9f, 0xff, 0xf0]),
        tlv(240, &qi1),
        tlv(240, &qi2),
    ]);
    assert_vector(&ie, 239, &v);
    // QoS Information is M (at least one), and its Average Packet Delay is M.
    let no_qi = cat(&[
        tlv(103, &[0x02, 10, 0, 0, 9]),
        tlv(237, &[0x01]),
        tlv(156, &[0, 0, 0, 1]),
    ]);
    assert!(GtpUPathQosReport::decode_value(&no_qi).is_err());
    assert!(QosInformationInGtpUPathQosReport::decode_value(&tlv(235, &[0, 0, 0, 1])).is_err());
}

#[test]
fn transport_delay_reporting_271_table_7_5_2_2_6() {
    let ie = TransportDelayReporting {
        preceding_ul_gtpu_peer: RemoteGtpUPeer {
            ipv4: Some([10, 45, 0, 7]),
            network_instance: Some(b"n9".to_vec()),
            ..Default::default()
        },
        dscp: Some(TransportLevelMarking::from_dscp(34)),
        extra: vec![],
    };
    // Remote GTP-U Peer: flags NI|V4 = 0x0a, IPv4, NI length (2 octets), NI.
    let v = cat(&[
        tlv(103, &[0x0a, 10, 45, 0, 7, 0, 2, b'n', b'9']),
        tlv(30, &[0x88, 0xfc]),
    ]);
    assert_vector(&ie, 271, &v);
    // The DSCP is O.
    let bare = TransportDelayReporting {
        preceding_ul_gtpu_peer: peer_v4([10, 45, 0, 7]),
        ..Default::default()
    };
    assert_vector(&bare, 271, &tlv(103, &[0x02, 10, 45, 0, 7]));
    // The Preceding UL GTP-U Peer is M.
    assert!(TransportDelayReporting::decode_value(&tlv(30, &[0x88, 0xfc])).is_err());
}

#[test]
fn qos_monitoring_per_qos_flow_control_information_242_table_7_5_2_9_3() {
    let ie = QosMonitoringPerQosFlowControlInformation {
        qfis: vec![1, 9],
        requested_qos_monitoring: RequestedQosMonitoring {
            ulpd: true,
            dlpd: true,
            ..Default::default()
        },
        reporting_frequency: ReportingFrequency {
            evett: true,
            perio: true,
        },
        packet_delay_thresholds: Some(PacketDelayThresholds {
            uplink: Some(15),
            ..Default::default()
        }),
        minimum_wait_time: Some(5),
        measurement_period: Some(10),
        // Measurement Indication (337), DQFI: a Rel-18 member kept byte-exact.
        extra: vec![RawIe::new(337, Bytes::from_static(&[0x01]))],
    };
    let v = cat(&[
        tlv(124, &[1]),
        tlv(124, &[9]),
        tlv(243, &[0x03]),
        tlv(244, &[0x03]),
        tlv(245, &[0x02, 0, 0, 0, 15]),
        tlv(246, &[0, 0, 0, 5]),
        tlv(64, &[0, 0, 0, 10]),
        tlv(337, &[0x01]),
    ]);
    assert_vector(&ie, 242, &v);
    // QFI, Requested QoS Monitoring and Reporting Frequency are M.
    for drop in [124u16, 243, 244] {
        let partial: Vec<u8> = [tlv(124, &[1]), tlv(243, &[0x03]), tlv(244, &[0x03])]
            .into_iter()
            .filter(|t| u16::from_be_bytes([t[0], t[1]]) != drop)
            .collect::<Vec<_>>()
            .concat();
        assert!(
            matches!(
                QosMonitoringPerQosFlowControlInformation::decode_value(&partial),
                Err(PfcpError::MissingMandatoryIe(_))
            ),
            "dropping {drop} must fail"
        );
    }
    // QFI spare bits (7-8) are ignored.
    let spare = cat(&[tlv(124, &[0xc5]), tlv(243, &[0x01]), tlv(244, &[0x01])]);
    assert_eq!(
        QosMonitoringPerQosFlowControlInformation::decode_value(&spare)
            .unwrap()
            .qfis,
        vec![5]
    );
}

#[test]
fn qos_monitoring_report_247_table_7_5_8_6_3() {
    let ie = QosMonitoringReport {
        qfi: 9,
        qos_monitoring_measurement: QosMonitoringMeasurement {
            downlink_packet_delay: Some(3),
            uplink_packet_delay: Some(4),
            ..Default::default()
        },
        time_stamp: 0xe8a0_0001,
        start_time: None,
        extra: vec![],
    };
    let v = cat(&[
        tlv(124, &[9]),
        tlv(248, &[0x03, 0, 0, 0, 3, 0, 0, 0, 4]),
        tlv(156, &[0xe8, 0xa0, 0, 1]),
    ]);
    assert_vector(&ie, 247, &v);
    let with_start = QosMonitoringReport {
        start_time: Some(0xe8a0_0000),
        ..ie.clone()
    };
    let v2 = cat(&[v, tlv(75, &[0xe8, 0xa0, 0, 0])]);
    assert_vector(&with_start, 247, &v2);
    // Time Stamp is M.
    let no_ts = cat(&[tlv(124, &[9]), tlv(248, &[0x08])]);
    assert!(QosMonitoringReport::decode_value(&no_ts).is_err());
}

#[test]
fn n6_delay_measurement_control_information_355_table_7_4_4_1_4_1() {
    // Protocol Specific Configuration Parameters (378), Measurement Protocol
    // STAMP + port 862: unmodelled, kept byte-exact.
    let pscp = cat(&[tlv(354, &[0x04]), tlv(379, &[0x03, 0x5e])]);
    let ie = N6DelayMeasurementControlInformation {
        id: 1,
        measurement_endpoint_addresses: vec![
            MeasurementEndpointAddress {
                ipv4: Some([198, 51, 100, 7]),
                ipv6: None,
            },
            MeasurementEndpointAddress {
                ipv4: Some([198, 51, 100, 8]),
                ipv6: None,
            },
        ],
        network_instance: b"internet".to_vec(),
        measurement_protocols: vec![N6DelayMeasurementProtocols {
            stamp: true,
            ..Default::default()
        }],
        measurement_reporting_type: MeasurementReportingType {
            per: true,
            ..Default::default()
        },
        measurement_period: Some(5),
        average_packet_delay_threshold: None,
        minimum_packet_delay_threshold: None,
        maximum_packet_delay_threshold: None,
        minimum_waiting_time: None,
        extra: vec![RawIe::new(378, Bytes::from(pscp.clone()))],
    };
    let v = cat(&[
        tlv(377, &[0, 1]),
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(358, &[0x01, 198, 51, 100, 8]),
        tlv(22, b"internet"),
        tlv(354, &[0x04]),
        tlv(375, &[0x01]),
        tlv(64, &[0, 0, 0, 5]),
        tlv(378, &pscp),
    ]);
    assert_vector(&ie, 355, &v);

    // Event-triggered with thresholds and a minimum waiting time.
    let evt = N6DelayMeasurementControlInformation {
        measurement_reporting_type: MeasurementReportingType {
            evt: true,
            ..Default::default()
        },
        measurement_period: None,
        average_packet_delay_threshold: Some(20),
        minimum_packet_delay_threshold: Some(1),
        maximum_packet_delay_threshold: Some(80),
        minimum_waiting_time: Some(Timer { unit: 0, value: 2 }),
        extra: vec![],
        ..ie.clone()
    };
    let v_evt = cat(&[
        tlv(377, &[0, 1]),
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(358, &[0x01, 198, 51, 100, 8]),
        tlv(22, b"internet"),
        tlv(354, &[0x04]),
        tlv(375, &[0x02]),
        tlv(234, &[0, 0, 0, 20]),
        tlv(235, &[0, 0, 0, 1]),
        tlv(236, &[0, 0, 0, 80]),
        tlv(55, &[0x02]),
    ]);
    assert_vector(&evt, 355, &v_evt);

    // All five M members are enforced.
    let full = [
        tlv(377, &[0, 1]),
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(22, b"internet"),
        tlv(354, &[0x04]),
        tlv(375, &[0x01]),
    ];
    for i in 0..full.len() {
        let partial: Vec<u8> = full
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, t)| t.clone())
            .collect();
        assert!(
            matches!(
                N6DelayMeasurementControlInformation::decode_value(&partial),
                Err(PfcpError::MissingMandatoryIe(_))
            ),
            "dropping member {i} must fail"
        );
    }
}

#[test]
fn n6_delay_measurement_report_356_table_7_4_5_1_8_1() {
    let ok = N6DelayMeasurementReport {
        measurement_endpoint_address: MeasurementEndpointAddress {
            ipv4: Some([198, 51, 100, 7]),
            ipv6: None,
        },
        network_instance: b"internet".to_vec(),
        measurement_reporting_type: MeasurementReportingType {
            per: true,
            ..Default::default()
        },
        time_stamp: 0xe8a0_0010,
        start_time: Some(0xe8a0_000b),
        information: Some(N6DelayMeasurementInformation {
            average_packet_delay: 12,
            minimum_packet_delay: Some(9),
            maximum_packet_delay: Some(19),
        }),
        failure_information: None,
        measurement_endpoint_port_number: Some(862),
        extra: vec![],
    };
    let v = cat(&[
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(22, b"internet"),
        tlv(375, &[0x01]),
        tlv(156, &[0xe8, 0xa0, 0, 0x10]),
        tlv(75, &[0xe8, 0xa0, 0, 0x0b]),
        tlv(357, &[0x03, 0, 0, 0, 12, 0, 0, 0, 9, 0, 0, 0, 19]),
        tlv(379, &[0x03, 0x5e]),
    ]);
    assert_vector(&ok, 356, &v);

    let failed = N6DelayMeasurementReport {
        start_time: None,
        information: None,
        failure_information: Some(N6DelayMeasurementFailureInformation { cause: 1 }),
        measurement_endpoint_port_number: None,
        ..ok.clone()
    };
    let vf = cat(&[
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(22, b"internet"),
        tlv(375, &[0x01]),
        tlv(156, &[0xe8, 0xa0, 0, 0x10]),
        tlv(376, &[0x01]),
    ]);
    assert_vector(&failed, 356, &vf);

    // Time Stamp is M.
    let no_ts = cat(&[
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(22, b"internet"),
        tlv(375, &[0x01]),
        tlv(376, &[0x01]),
    ]);
    assert!(matches!(
        N6DelayMeasurementReport::decode_value(&no_ts),
        Err(PfcpError::MissingMandatoryIe(_))
    ));
    // NOTE: exactly one of Information (357) and Failure Information (376).
    let head = cat(&[
        tlv(358, &[0x01, 198, 51, 100, 7]),
        tlv(22, b"internet"),
        tlv(375, &[0x01]),
        tlv(156, &[0xe8, 0xa0, 0, 0x10]),
    ]);
    assert!(N6DelayMeasurementReport::decode_value(&head).is_err());
    let both = cat(&[
        head.clone(),
        tlv(357, &[0x00, 0, 0, 0, 12]),
        tlv(376, &[0x01]),
    ]);
    assert!(N6DelayMeasurementReport::decode_value(&both).is_err());
}

#[test]
fn grouped_ies_reject_a_truncated_member() {
    // A member header claiming more octets than the group holds.
    let bad = [0x00, 0xed, 0x00, 0x05, 0x01];
    assert!(GtpUPathQosControlInformation::decode_value(&bad).is_err());
    assert!(QosMonitoringReport::decode_value(&bad).is_err());
    assert!(N6DelayMeasurementReport::decode_value(&bad).is_err());
}

// ------------------------------------------------- Remote GTP-U Peer (103)

#[test]
fn remote_gtpu_peer_di_ni_rts_follow_figure_8_2_70_1() {
    // Flags: V6(1) V4(2) DI(3) NI(4) RTS(5); fields IPv4, IPv6, DI length (2) +
    // DI, NI length (2) + NI, Recovery Timestamp (4).
    let p = RemoteGtpUPeer {
        ipv4: Some([10, 0, 0, 5]),
        ipv6: None,
        destination_interface: Some(1), // Core
        network_instance: Some(b"n9".to_vec()),
        recovery_time_stamp: Some(0xe8a0_0000),
    };
    let v = [
        0x1e, 10, 0, 0, 5, 0, 1, 0x01, 0, 2, b'n', b'9', 0xe8, 0xa0, 0, 0,
    ];
    assert_vector(&p, 103, &v);
    // Without the optional fields the encoding is the pre-#1386 one.
    let mut buf = BytesMut::new();
    peer_v4([10, 0, 0, 5]).encode(&mut buf);
    assert_eq!(&buf[..], &[0x02, 10, 0, 0, 5]);
    // The pre-#1386 decoder ignored everything after the addresses, so a
    // truncated or empty trailing field still yields the addresses (no new
    // failure mode reachable from the existing Node Report path), and never
    // panics.
    for wire in [
        &[0x06, 10, 0, 0, 5][..],
        &[0x06, 10, 0, 0, 5, 0, 0],
        &[0x0a, 10, 0, 0, 5, 0, 3, b'n'],
        &[0x12, 10, 0, 0, 5, 0xe8],
    ] {
        assert_eq!(
            RemoteGtpUPeer::decode(wire).unwrap(),
            peer_v4([10, 0, 0, 5])
        );
    }
    // A truncated address is still an error, as before.
    assert!(RemoteGtpUPeer::decode(&[0x02, 10, 0]).is_err());
}
