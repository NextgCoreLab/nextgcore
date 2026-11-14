//! #1502: N6 delay measurement, the SMF half. Handler tests on real PFCP bytes
//! against a stand-in UPF socket.

use super::*;
use crate::pfcp_path::stand_in::{client_with_silent_peer, client_with_silent_peer_timed};
use crate::pfcp_path::{associate_and_provision, encode_wire_message, find_ie, parse_wire_header};
use nextgcore_pfcp::message::{AssociationSetupResponse, PfcpMessage};
use nextgcore_pfcp::qos_monitoring::{
    N6DelayMeasurementFailureInformation, N6DelayMeasurementInformation,
};
use nextgcore_pfcp::types::UpFunctionFeatures;
use tokio::net::UdpSocket;

const IE_355: u16 = IeType::N6DelayMeasurementControlInformation as u16;
const IE_356: u16 = IeType::N6DelayMeasurementReport as u16;

fn yaml(text: &str) -> Result<N6DelayConfig, String> {
    serde_yaml::from_str::<N6DelayYaml>(text)
        .map_err(|e| e.to_string())?
        .validate()
}

/// The block the handler tests provision: three EAS endpoints, two on the default
/// STAMP port and one on 8620, periodic every 2 s plus an immediate first report.
const DEMO_BLOCK: &str = "\
endpoints:
  - address: 10.60.0.11
  - address: 10.60.0.12
  - address: 10.60.0.13
    port: 8620
network_instance: dn
reporting: [immediate, periodic]
period: 2
";

fn v4(a: [u8; 4]) -> MeasurementEndpointAddress {
    MeasurementEndpointAddress {
        ipv4: Some(a),
        ipv6: None,
    }
}

/// #1502: the block becomes one IE 355 instance per port, IDs from 1, each with the
/// Network Instance, STAMP, the reporting type and the period. The port goes in IE
/// 378 only when one is configured (upfd defaults to 862).
#[test]
fn the_block_validates_into_one_instance_per_port_1502() {
    let c = yaml(DEMO_BLOCK).expect("valid");
    assert_eq!(c.instances.len(), 2);
    let (default_port, other) = (&c.instances[0], &c.instances[1]);
    assert_eq!(default_port.id, 1);
    assert_eq!(
        default_port.measurement_endpoint_addresses,
        vec![v4([10, 60, 0, 11]), v4([10, 60, 0, 12])]
    );
    assert!(default_port.extra.is_empty(), "no IE 378 without a port");
    assert_eq!(other.id, 2);
    assert_eq!(
        other.measurement_endpoint_addresses,
        vec![v4([10, 60, 0, 13])]
    );
    for i in &c.instances {
        assert_eq!(i.network_instance, b"dn");
        assert_eq!(
            i.measurement_protocols,
            vec![N6DelayMeasurementProtocols {
                stamp: true,
                ..Default::default()
            }]
        );
        assert_eq!(
            i.measurement_reporting_type,
            MeasurementReportingType {
                per: true,
                evt: false,
                ire: true
            }
        );
        assert_eq!(i.measurement_period, Some(2));
        assert_eq!(i.minimum_waiting_time, None);
    }
    // IE 378 = IE 354 (STAMP) + IE 379 (8620), as upfd's parser reads it.
    assert_eq!(other.extra.len(), 1);
    assert_eq!(
        other.extra[0].ie_type,
        IeType::ProtocolSpecificConfigurationParameters as u16
    );
    assert_eq!(
        other.extra[0].data.as_ref(),
        &[0x01, 0x62, 0x00, 0x01, 0x04, 0x01, 0x7B, 0x00, 0x02, 0x21, 0xAC]
    );
    // And the instance round-trips through the shared codec.
    let mut b = BytesMut::new();
    other.encode_ie(&mut b);
    let back = N6DelayMeasurementControlInformation::decode_ie(&mut b.freeze()).unwrap();
    assert_eq!(&back, other);
    // The Network Instance defaults to the shipped DNN.
    let c = yaml("endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\n").unwrap();
    assert_eq!(c.instances[0].network_instance, b"internet");
}

/// #1502: event reporting carries the thresholds and the Minimum Waiting Time.
#[test]
fn event_reporting_carries_thresholds_and_the_minimum_wait_1502() {
    let c = yaml(
        "endpoints: [{address: '2001:db8::7'}]\nreporting: [event]\nthresholds: {average: 8, maximum: 20}\nminimum_wait_time: 5\n",
    )
    .unwrap();
    let i = &c.instances[0];
    assert_eq!(
        i.measurement_endpoint_addresses[0].ipv6,
        Some(
            "2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        )
    );
    assert_eq!(i.average_packet_delay_threshold, Some(8));
    assert_eq!(i.minimum_packet_delay_threshold, None);
    assert_eq!(i.maximum_packet_delay_threshold, Some(20));
    assert_eq!(i.measurement_period, None);
    // 5 s in 2 s units, rounded up: 3 x 2 s.
    assert_eq!(i.minimum_waiting_time, Some(Timer { unit: 0, value: 3 }));
}

/// #1502: the Timer IE takes the smallest unit that fits, rounding up, and refuses
/// what no unit holds.
#[test]
fn the_minimum_wait_is_coded_in_the_smallest_timer_unit_1502() {
    assert_eq!(timer_for_secs(0), Ok(Timer { unit: 0, value: 0 }));
    assert_eq!(timer_for_secs(62), Ok(Timer { unit: 0, value: 31 }));
    assert_eq!(timer_for_secs(63), Ok(Timer { unit: 1, value: 2 }));
    assert_eq!(timer_for_secs(1860), Ok(Timer { unit: 1, value: 31 }));
    assert_eq!(timer_for_secs(1861), Ok(Timer { unit: 2, value: 4 }));
    assert!(timer_for_secs(31 * 36_000 + 1).is_err());
}

/// #1502: a block that the UPF could not act on, or that would provision something
/// other than what it says, fails startup.
#[test]
fn an_invalid_block_is_refused_1502() {
    for (text, why) in [
        ("endpoints: []\nreporting: [immediate]\n", "no endpoints"),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [periodic, event]\nperiod: 2\nthresholds: {average: 1}\n",
            "exclusive",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [periodic]\n",
            "period",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [periodic]\nperiod: 0\n",
            "period",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\nperiod: 2\n",
            "only meaningful",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\nthresholds: {average: 3}\n",
            "only meaningful",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [sometimes]\n",
            "not one of",
        ),
        ("endpoints: [{address: 10.0.0.1}]\nreporting: []\n", "names no type"),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\nprotocol: twamp\n",
            "only \"stamp\"",
        ),
        (
            "endpoints: [{address: eas-local}]\nreporting: [immediate]\n",
            "not an IP address",
        ),
        (
            "endpoints: [{address: 10.0.0.1}, {address: 10.0.0.1}]\nreporting: [immediate]\n",
            "twice",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\nnetwork_instance: ''\n",
            "empty",
        ),
        (
            "endpoints: [{address: 10.0.0.1}]\nreporting: [immediate]\nperoid: 2\n",
            "unknown field",
        ),
    ] {
        let err = yaml(text).expect_err(text);
        assert!(err.contains(why), "{text}: {err}");
    }
}

/// A Setup Response advertising `features`, then an accepted Update Response when
/// `answer_update`, from a stand-in UPF on `upf`. Returns every request it received
/// until it has heard nothing for `quiet_ms`.
fn answer_setup_and_update(
    upf: UdpSocket,
    features: UpFunctionFeatures,
    answer_update: bool,
    quiet_ms: u64,
) -> tokio::task::JoinHandle<Vec<(u8, Vec<u8>)>> {
    tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 4096];
        // The association, and the Update if one follows within the window.
        while let Ok(Ok((len, from))) = tokio::time::timeout(
            std::time::Duration::from_millis(quiet_ms),
            upf.recv_from(&mut buf),
        )
        .await
        {
            let h = parse_wire_header(&buf[..len]).unwrap();
            seen.push((h.msg_type, buf[h.body_offset..len].to_vec()));
            let reply = match h.msg_type {
                pfcp_message_type::ASSOCIATION_SETUP_REQUEST => {
                    let mut resp = AssociationSetupResponse::new(
                        NodeId::new_ipv4([127, 0, 0, 4]),
                        PfcpCause::RequestAccepted,
                        0x1502,
                    );
                    resp.up_function_features = Some(features);
                    nextgcore_pfcp::message::build_message(
                        &PfcpMessage::AssociationSetupResponse(resp),
                        h.sequence_number,
                        None,
                    )
                    .to_vec()
                }
                pfcp_message_type::ASSOCIATION_UPDATE_REQUEST if answer_update => {
                    let mut b = BytesMut::new();
                    AssociationUpdateResponse {
                        node_id: NodeId::new_ipv4([127, 0, 0, 4]),
                        cause: PfcpCause::RequestAccepted,
                        up_function_features: None,
                        cp_function_features: None,
                    }
                    .encode(&mut b);
                    encode_wire_message(
                        pfcp_message_type::ASSOCIATION_UPDATE_RESPONSE,
                        None,
                        h.sequence_number,
                        &b,
                    )
                }
                _ => continue,
            };
            upf.send_to(&reply, from).await.unwrap();
        }
        seen
    })
}

fn un6dm() -> UpFunctionFeatures {
    UpFunctionFeatures {
        ftup: true,
        un6dm: true,
        ..Default::default()
    }
}

/// Associate a fresh client with a stand-in UPF advertising `features`; the requests
/// the UPF received, in order.
async fn associate_with(features: UpFunctionFeatures) -> Vec<(u8, Vec<u8>)> {
    let (client, upf) = client_with_silent_peer().await;
    let answering = answer_setup_and_update(upf, features, true, 300);
    let provisioning = associate_and_provision(&client).await.expect("associated");
    provisioning.await.unwrap();
    assert!(client.is_associated().await);
    answering.await.unwrap()
}

/// #1502, TS 29.244 §5.33.8.2: a UPF whose Setup Response advertises UN6DM gets, as
/// the SMF's next request, an Association Update Request carrying the configured IE
/// 355 instances, exactly as the shared codec decodes them, and this SMF's Node ID.
///
/// REVERT-VERIFIED: without the `provision` task in `associate_and_provision`, the
/// UPF sees only the Setup.
#[tokio::test]
async fn a_un6dm_upf_gets_an_association_update_with_the_configured_ie355_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    let config = yaml(DEMO_BLOCK).unwrap();
    set_config(Some(config.clone()));

    let seen = associate_with(un6dm()).await;
    reset_for_test();

    let types: Vec<u8> = seen.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        vec![
            pfcp_message_type::ASSOCIATION_SETUP_REQUEST,
            pfcp_message_type::ASSOCIATION_UPDATE_REQUEST
        ]
    );
    let update = &seen[1].1;
    let req = AssociationUpdateRequest::decode(&mut Bytes::copy_from_slice(update)).unwrap();
    assert_eq!(req.node_id, NodeId::new_ipv4([127, 0, 0, 1]));
    assert_eq!(req.up_function_features, None);
    assert_eq!(req.pfcp_association_release_request, None);
    let mut instances = Vec::new();
    let mut off = 0;
    while off + 4 <= update.len() {
        let t = u16::from_be_bytes([update[off], update[off + 1]]);
        let l = usize::from(u16::from_be_bytes([update[off + 2], update[off + 3]]));
        if t == IE_355 {
            instances.push(
                N6DelayMeasurementControlInformation::decode_value(&update[off + 4..off + 4 + l])
                    .unwrap(),
            );
        }
        off += 4 + l;
    }
    assert_eq!(instances, config.instances);
}

/// #1502: without the block, or against a UPF that does not advertise UN6DM, no
/// Association Update is sent, and the Association Setup Request is byte-identical
/// with and without the block.
///
/// REVERT-VERIFIED: with the UN6DM check in `provision` removed, the second case sends
/// an Update.
#[tokio::test]
async fn no_block_or_no_un6dm_sends_no_association_update_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();

    let unconfigured = associate_with(un6dm()).await;
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let unsupported = associate_with(UpFunctionFeatures {
        ftup: true,
        ..Default::default()
    })
    .await;
    reset_for_test();

    for seen in [&unconfigured, &unsupported] {
        let types: Vec<u8> = seen.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![pfcp_message_type::ASSOCIATION_SETUP_REQUEST]);
    }
    assert_eq!(
        unconfigured[0].1, unsupported[0].1,
        "the Setup Request does not change with the block"
    );
    assert!(find_ie(&unconfigured[0].1, IE_355).is_none());
}

/// An N6 Delay Measurement Report IE for `endpoint`: a measurement, or a failure.
fn report_ie(endpoint: [u8; 4], measured: Option<(u32, u32, u32)>, failure: Option<u8>) -> Vec<u8> {
    let mut b = BytesMut::new();
    N6DelayMeasurementReport {
        measurement_endpoint_address: v4(endpoint),
        network_instance: b"dn".to_vec(),
        measurement_reporting_type: MeasurementReportingType {
            per: true,
            ..Default::default()
        },
        time_stamp: 0xE9_00_00_00,
        information: measured.map(|(avg, min, max)| N6DelayMeasurementInformation {
            average_packet_delay: avg,
            minimum_packet_delay: Some(min),
            maximum_packet_delay: Some(max),
        }),
        failure_information: failure.map(|cause| N6DelayMeasurementFailureInformation { cause }),
        ..Default::default()
    }
    .encode_ie(&mut b);
    b.to_vec()
}

/// A Node Report Request: Node ID 127.0.0.4, Node Report Type `report_type`, then
/// `ies` as they are.
fn node_report(seq: u32, report_type: u8, ies: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0, 60, 0, 5, 0, 127, 0, 0, 4, 0, 101, 0, 1, report_type];
    for ie in ies {
        body.extend_from_slice(ie);
    }
    encode_wire_message(pfcp_message_type::NODE_REPORT_REQUEST, None, seq, &body)
}

/// Deliver `pkt` from the UPF socket to the client's engine; the response the UPF
/// receives: (Cause, Offending IE).
async fn deliver(client: &PfcpClient, upf: &UdpSocket, pkt: &[u8]) -> (Option<u8>, Option<u16>) {
    assert!(client.on_datagram(pkt, upf.local_addr().unwrap()).await);
    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(std::time::Duration::from_secs(2), upf.recv_from(&mut buf))
        .await
        .expect("a Node Report Response")
        .unwrap();
    let h = parse_wire_header(&buf[..len]).unwrap();
    assert_eq!(h.msg_type, pfcp_message_type::NODE_REPORT_RESPONSE);
    let body = &buf[h.body_offset..len];
    (
        find_ie(body, 19).and_then(|v| v.first().copied()),
        find_ie(body, 40).map(|v| u16::from_be_bytes([v[0], v[1]])),
    )
}

/// #1502, TS 29.244 §5.33.8.3, Table 7.4.5.1.8-1: an N6DR Node Report is accepted;
/// each endpoint's one-way delay is stored and exported on `/metrics`; a failure
/// report drops that endpoint's value and is counted.
///
/// REVERT-VERIFIED: without the N6DR arm in `parse_node_report` (or the
/// `on_reports` call in `on_node_report`), nothing is stored and the metric is
/// absent.
#[tokio::test]
async fn an_n6dr_node_report_is_stored_and_exported_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    let key = client.recovery_time_stamp_key();
    let local: IpAddr = "10.60.0.11".parse().unwrap();
    let regional: IpAddr = "10.60.0.12".parse().unwrap();

    let first = deliver(
        &client,
        &upf,
        &node_report(
            1,
            0x40,
            &[
                report_ie([10, 60, 0, 11], Some((9, 8, 11)), None),
                report_ie([10, 60, 0, 12], Some((4, 3, 6)), None),
            ],
        ),
    )
    .await;
    let stored_local = result_for_test(&key, local);
    let stored_regional = result_for_test(&key, regional);
    let metrics_after_first = crate::render_metrics();

    let second = deliver(
        &client,
        &upf,
        &node_report(2, 0x40, &[report_ie([10, 60, 0, 11], None, Some(1))]),
    )
    .await;
    let after_failure = result_for_test(&key, local);
    let metrics_after_failure = crate::render_metrics();
    reset_for_test();

    assert_eq!(first, (Some(1), None), "accepted");
    assert_eq!(
        stored_local,
        Some(Measured {
            average_ms: 9,
            minimum_ms: Some(8),
            maximum_ms: Some(11)
        })
    );
    assert_eq!(stored_regional.map(|m| m.average_ms), Some(4));
    for stat in ["avg\"} 9", "min\"} 8", "max\"} 11"] {
        let line = format!("smf_n6_delay_ms{{upf=\"{key}\",endpoint=\"10.60.0.11\",stat=\"{stat}");
        assert!(
            metrics_after_first.contains(&line),
            "{line}\n{metrics_after_first}"
        );
    }
    assert_eq!(second, (Some(1), None), "a failure report is accepted too");
    assert_eq!(after_failure, None, "the stale value is dropped");
    assert!(metrics_after_failure.contains(&format!(
        "smf_n6_delay_failures_total{{upf=\"{key}\",endpoint=\"10.60.0.11\"}} 1"
    )));
    assert!(metrics_after_failure.contains(&format!(
        "smf_n6_delay_ms{{upf=\"{key}\",endpoint=\"10.60.0.12\",stat=\"avg\"}} 4"
    )));
}

/// #1502, Table 7.4.5.1.1-1 and Table 7.4.5.1.8-1: N6DR without an IE 356 is refused
/// with Conditional IE missing (67), and an IE 356 that does not decode, or that
/// carries both a measurement and a failure, with Mandatory IE incorrect (69); each
/// names IE 356. Nothing is stored, and the association stays up.
///
/// REVERT-VERIFIED: without the N6DR arm, all three are accepted (cause 1).
#[tokio::test]
async fn a_malformed_n6dr_report_is_refused_with_the_offending_ie_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    let key = client.recovery_time_stamp_key();

    let none = deliver(&client, &upf, &node_report(1, 0x40, &[])).await;
    // IE 356 holding only an endpoint: the Network Instance, type and stamp are missing.
    let truncated = {
        let mut ie = vec![0x01, 0x64, 0x00, 0x09];
        ie.extend_from_slice(&[0x01, 0x66, 0x00, 0x05, 0x01, 10, 60, 0, 11]);
        ie
    };
    let short = deliver(&client, &upf, &node_report(2, 0x40, &[truncated])).await;
    let both = deliver(
        &client,
        &upf,
        &node_report(
            3,
            0x40,
            &[report_ie([10, 60, 0, 11], Some((9, 8, 11)), Some(1))],
        ),
    )
    .await;
    let stored = result_for_test(&key, "10.60.0.11".parse().unwrap());
    let associated = client.is_associated().await;
    reset_for_test();

    assert_eq!(none, (Some(67), Some(IE_356)));
    assert_eq!(short, (Some(69), Some(IE_356)));
    assert_eq!(both, (Some(69), Some(IE_356)));
    assert_eq!(stored, None);
    assert!(associated);
}

/// #1502: losing the association drops that UPF's N6 results (a restart detected by
/// a changed Recovery Time Stamp here); they would otherwise be exported as current.
///
/// REVERT-VERIFIED: without the `forget_upf` call in the teardown, the value survives.
#[tokio::test]
async fn association_loss_forgets_the_upfs_n6_results_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    client.seed_peer_recovery_time_stamp(100).await;
    let key = client.recovery_time_stamp_key();
    let ip: IpAddr = "10.60.0.11".parse().unwrap();
    let accepted = deliver(
        &client,
        &upf,
        &node_report(
            1,
            0x40,
            &[report_ie([10, 60, 0, 11], Some((9, 8, 11)), None)],
        ),
    )
    .await;
    let before = result_for_test(&key, ip);
    on_reports(
        "another-upf:8805",
        &[
            N6DelayMeasurementReport::decode_ie(&mut Bytes::from(report_ie(
                [10, 60, 0, 11],
                Some((5, 5, 5)),
                None,
            )))
            .unwrap(),
        ],
    );

    client.check_peer_restart(200).await;
    let after = result_for_test(&key, ip);
    let other = result_for_test("another-upf:8805", ip);
    reset_for_test();

    assert_eq!(accepted, (Some(1), None));
    assert!(before.is_some());
    assert!(
        !client.is_associated().await,
        "the restart tore the association down"
    );
    assert_eq!(after, None);
    assert_eq!(
        other.map(|m| m.average_ms),
        Some(5),
        "another UPF's are kept"
    );
}

/// #1502: `smf.n6_delay_measurement` is read by the real config loader, and an
/// invalid block fails startup instead of leaving the measurement unconfigured.
///
/// REVERT-VERIFIED: with the block's `validate` error ignored in `load_config`, the
/// invalid file loads.
#[test]
fn the_config_loader_reads_the_block_and_refuses_an_invalid_one_1502() {
    let dir = std::env::temp_dir().join(format!("smf-1502-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let indent = |block: &str| {
        block
            .lines()
            .map(|l| format!("    {l}\n"))
            .collect::<String>()
    };
    let good = dir.join("good.yaml");
    std::fs::write(
        &good,
        format!("smf:\n  n6_delay_measurement:\n{}", indent(DEMO_BLOCK)),
    )
    .unwrap();
    let bad = dir.join("bad.yaml");
    std::fs::write(
        &bad,
        "smf:\n  n6_delay_measurement:\n    endpoints: [{address: 10.0.0.1}]\n    reporting: [sometimes]\n",
    )
    .unwrap();
    let none = dir.join("none.yaml");
    std::fs::write(&none, "smf:\n  mtu: 1400\n").unwrap();

    let loaded = crate::load_config(good.to_str().unwrap()).map(|c| c.n6_delay);
    let refused = crate::load_config(bad.to_str().unwrap()).err();
    let absent = crate::load_config(none.to_str().unwrap()).map(|c| c.n6_delay);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(loaded.unwrap(), Some(yaml(DEMO_BLOCK).unwrap()));
    assert!(
        refused.is_some_and(|e| e.to_string().contains("not one of")),
        "an invalid block fails startup"
    );
    assert_eq!(absent.unwrap(), None);
}

/// #1502 review M1: a UPF that advertises UN6DM but never answers the Association
/// Update stays associated. The Update is retransmitted under T1/N1 and its
/// exhaustion is reported as `Failed`, never run as the node-level abnormal action.
/// It runs off the association loop, so `associate_and_provision` returns at once.
///
/// REVERT-VERIFIED: with `optional_request` marking down on exhaustion, the
/// association is down afterwards; with the provisioning awaited inline, the call
/// takes the full T1 x (N1 + 1).
#[tokio::test]
async fn an_unanswered_association_update_leaves_the_association_up_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let t1 = std::time::Duration::from_millis(400);
    let (client, upf) = client_with_silent_peer_timed(t1, 1).await;
    let answering = answer_setup_and_update(upf, un6dm(), false, 1500);

    let started = std::time::Instant::now();
    let provisioning = associate_and_provision(&client).await.expect("associated");
    let returned_after = started.elapsed();
    let outcome = provisioning.await.unwrap();
    let associated = client.is_associated().await;
    let seen = answering.await.unwrap();
    reset_for_test();

    assert!(
        returned_after < t1,
        "the association returns before the Update's T1: {returned_after:?}"
    );
    assert_eq!(outcome, Provisioned::Failed);
    assert!(
        associated,
        "an ignored optional Update does not mark the association down"
    );
    let types: Vec<u8> = seen.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        vec![
            pfcp_message_type::ASSOCIATION_SETUP_REQUEST,
            pfcp_message_type::ASSOCIATION_UPDATE_REQUEST,
            pfcp_message_type::ASSOCIATION_UPDATE_REQUEST
        ],
        "sent, then retransmitted once (N1 = 1)"
    );
}

/// #1502 review M2: a heartbeat loss (N1 exhaustion, no teardown) drops the UPF's
/// N6 results and failure counts, so `/metrics` never shows a dead UPF's delay.
///
/// REVERT-VERIFIED: without the `forget_upf` call in `publish_associated`, the value
/// and the failure count survive the loss.
#[tokio::test]
async fn a_heartbeat_loss_forgets_the_upfs_n6_results_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let (client, upf) =
        client_with_silent_peer_timed(std::time::Duration::from_millis(50), 1).await;
    client.set_assoc_state_for_test(true, None, None).await;
    let key = client.recovery_time_stamp_key();
    let reported = deliver(
        &client,
        &upf,
        &node_report(
            1,
            0x40,
            &[
                report_ie([10, 60, 0, 11], Some((9, 8, 11)), None),
                report_ie([10, 60, 0, 12], None, Some(2)),
            ],
        ),
    )
    .await;
    let before = store_sizes_for_test();

    let heartbeat = client.heartbeat_once().await;
    let associated = client.is_associated().await;
    let after = store_sizes_for_test();
    let metrics = crate::render_metrics();
    reset_for_test();

    assert_eq!(reported, (Some(1), None));
    assert_eq!(before, (1, 1), "one value, one failure count");
    assert!(heartbeat.is_err(), "the silent peer exhausts the heartbeat");
    assert!(!associated);
    assert_eq!(after, (0, 0), "both go with the association");
    assert!(!metrics.contains(&format!("upf=\"{key}\"")), "{metrics}");
}

/// #1502 review M3: a report naming an endpoint this SMF did not provision is
/// accepted (TS 29.244 §6.2.9.3; no §8.2.1 cause fits a well-formed unrequested
/// report) but neither stored nor exported, only counted, so a UPF naming many
/// endpoints cannot grow the store or the series.
///
/// REVERT-VERIFIED: without the configured-endpoint check in `on_reports`, all 201
/// endpoints are stored and exported.
#[tokio::test]
async fn reports_for_unprovisioned_endpoints_are_ignored_and_counted_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    let mut ies: Vec<Vec<u8>> = (0..200u8)
        .map(|i| report_ie([10, 99, 0, i], Some((1, 1, 1)), None))
        .collect();
    ies.push(report_ie([10, 60, 0, 11], Some((9, 8, 11)), None));
    let answer = deliver(&client, &upf, &node_report(1, 0x40, &ies)).await;
    let sizes = store_sizes_for_test();
    let metrics = crate::render_metrics();
    reset_for_test();

    assert_eq!(answer, (Some(1), None));
    assert_eq!(sizes, (1, 0), "only the provisioned endpoint");
    let series = metrics
        .lines()
        .filter(|l| l.starts_with("smf_n6_delay_ms{"))
        .count();
    assert_eq!(series, 3, "avg/min/max of 10.60.0.11 only");
    assert!(!metrics.contains("10.99.0."));
    assert!(metrics.contains("smf_n6_delay_reports_ignored_total 200"));
}

/// #1502 review M3: without the block, a valid N6DR report is still answered, but
/// nothing is stored and `/metrics` carries no N6 family at all.
///
/// REVERT-VERIFIED: with `render` keyed on the store again, and reports stored
/// without a block, the families appear.
#[tokio::test]
async fn without_the_block_nothing_is_stored_or_exported_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    let answer = deliver(
        &client,
        &upf,
        &node_report(
            1,
            0x40,
            &[
                report_ie([10, 60, 0, 11], Some((9, 8, 11)), None),
                report_ie([10, 60, 0, 12], None, Some(1)),
            ],
        ),
    )
    .await;
    let sizes = store_sizes_for_test();
    let metrics = crate::render_metrics();
    reset_for_test();

    assert_eq!(answer, (Some(1), None));
    assert_eq!(sizes, (0, 0));
    assert!(!metrics.contains("smf_n6_"), "{metrics}");
}

/// #1502 review MINORs, TS 29.244 §7.6.7 and §7.6.8:
/// - an IE 356 whose endpoint carries neither V4 nor V6 → 69, Offending IE 356;
/// - an IE 356 whose member's Length runs past the IE 356 → 68 (Invalid length);
/// - an IE 356, last in the message, whose Length runs past the message → 68.
///
/// REVERT-VERIFIED: with `members_fit` not checked and the overrun IE skipped, the
/// two length cases answer 69 and 67.
#[tokio::test]
async fn length_and_address_errors_in_ie356_get_their_causes_1502() {
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _n4 = crate::pfcp_path::N4_TEST_LOCK.lock().await;
    let _n6 = N6_TEST_LOCK.lock().await;
    reset_for_test();
    set_config(Some(yaml(DEMO_BLOCK).unwrap()));
    let (client, upf) = client_with_silent_peer().await;
    client.set_assoc_state_for_test(true, None, None).await;
    let good = report_ie([10, 60, 0, 11], Some((9, 8, 11)), None);
    // The IE 358 member starts right after the IE 356 header: flags octet 5.
    let mut no_family = good.clone();
    assert_eq!(&no_family[4..6], &[0x01, 0x66]);
    no_family[8] = 0x00;
    // The first member's Length grows by one, past the end of the IE 356 value.
    let mut member_overrun = good.clone();
    member_overrun[7] += 1;
    // The IE 356 header claims 16 octets more than the message holds.
    let mut ie_overrun = good.clone();
    let l = u16::from_be_bytes([ie_overrun[2], ie_overrun[3]]) + 16;
    ie_overrun[2..4].copy_from_slice(&l.to_be_bytes());

    let a = deliver(&client, &upf, &node_report(1, 0x40, &[no_family])).await;
    let b = deliver(&client, &upf, &node_report(2, 0x40, &[member_overrun])).await;
    let c = deliver(&client, &upf, &node_report(3, 0x40, &[ie_overrun])).await;
    let sizes = store_sizes_for_test();
    reset_for_test();

    assert_eq!(a, (Some(69), Some(IE_356)));
    assert_eq!(b, (Some(68), Some(IE_356)));
    assert_eq!(c, (Some(68), Some(IE_356)));
    assert_eq!(sizes, (0, 0));
}
