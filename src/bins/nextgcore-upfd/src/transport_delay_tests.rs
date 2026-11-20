//! #1450: Transport Delay Reporting, unit level. Golden bytes are derived by hand
//! from TS 38.415 Figure 5.5.2.2-1 (UL PDU SESSION INFORMATION) and TS 29.281
//! §5.1 / §5.2.1 / §5.2.2.7 (GTP-U header, extension header framing); each
//! derivation is written beside its vector.

use super::*;
use crate::data_plane::build_relay_gpdu;
use nextgcore_gtp::v1::types::{PduSessionContainer, UlPduSessionInformation};
use nextgcore_pfcp::qos_monitoring::{TransportDelayReporting, TransportLevelMarking};
use nextgcore_pfcp::types::RemoteGtpUPeer;

/// UL PDU SESSION INFORMATION, QFI 9, DL Delay Result 2 ms, UL Delay Result 3 ms:
/// - octet 1: PDU Type 1 (bits 8-5 = 0001), QMP 0, DL Delay Ind 1, UL Delay Ind 1,
///   SNP 0 -> 0001 0110 = 0x16;
/// - octet 2: N3/N9 Delay Ind 0, New IE Flag 0, QFI 9 (00 1001) -> 0x09;
/// - DL Delay Result, Unsigned32 (§5.5.3.14): 00 00 00 02;
/// - UL Delay Result (§5.5.3.16): 00 00 00 03.
///
/// Ten octets; with the length and next-type octets twelve, a multiple of 4
/// (TS 29.281 §5.2.1), so no padding.
const RAN_FRAME: [u8; 10] = [0x16, 0x09, 0, 0, 0, 2, 0, 0, 0, 3];

#[test]
fn the_delay_is_inserted_where_figure_5_5_2_2_1_puts_it() {
    // + 7 ms: octet 2 gains N3/N9 Delay Ind (bit 8) -> 0x89, and the N3/N9 Delay
    // Result (§5.5.3.21, Unsigned32 ms) 00 00 00 07 follows the UL Delay Result
    // (no UL QFI Sequence Number, SNP 0). Fourteen octets: 16 with length and
    // next type, still a multiple of 4.
    let want = [0x16, 0x89, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 7];
    assert_eq!(add_n3_n9_delay(&RAN_FRAME, 7, false).unwrap(), want);
    assert_eq!(n3_n9_delay(&want), Some(7));
    assert_eq!(n3_n9_delay(&RAN_FRAME), None);
    // The library codec reads the field back where it was put.
    match PduSessionContainer::decode_content(&want).unwrap() {
        PduSessionContainer::Ul(ul) => {
            assert_eq!(ul.n3_n9_delay_result, Some(7));
            assert_eq!((ul.dl_delay_result, ul.ul_delay_result), (Some(2), Some(3)));
            assert_eq!(ul.qfi, 9);
        }
        other => panic!("UL frame, got {other:?}"),
    }
}

#[test]
fn a_second_i_upf_sums_into_the_field_the_first_wrote() {
    // The first I-UPF's 7 ms, then 5 ms more: 00 00 00 0c, nothing else moves.
    let first = add_n3_n9_delay(&RAN_FRAME, 7, false).unwrap();
    let second = add_n3_n9_delay(&first, 5, false).unwrap();
    assert_eq!(second, [0x16, 0x89, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 12]);
    // Saturating, never wrapping to a small delay.
    let mut big = first.clone();
    big[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        n3_n9_delay(&add_n3_n9_delay(&big, 5, false).unwrap()),
        Some(u32::MAX)
    );
}

#[test]
fn the_offset_counts_time_stamps_and_the_sequence_number() {
    // QMP 1, DL and UL Delay Ind 1, SNP 1: octet 1 = 0001 1111 = 0x1f. Octet 2 =
    // QFI 9. Then T1, T2, T3 (3 x 8 octets), the two Delay Results (2 x 4) and the
    // UL QFI Sequence Number (3): the N3/N9 Delay Result goes at 2 + 24 + 8 + 3 =
    // 37. 37 octets + 2 = 39, padded to 40 with one zero after the SN.
    let mut frame = vec![0x1f, 0x09];
    frame.extend_from_slice(&[0x11; 8]);
    frame.extend_from_slice(&[0x22; 8]);
    frame.extend_from_slice(&[0x33; 8]);
    frame.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 3]);
    frame.extend_from_slice(&[0x0a, 0x0b, 0x0c]);
    frame.push(0); // padding
    let out = add_n3_n9_delay(&frame, 9, false).unwrap();
    assert_eq!(out.len(), frame.len() + 4);
    assert_eq!(out[1], 0x89);
    assert_eq!(&out[..1], &frame[..1]);
    assert_eq!(&out[2..37], &frame[2..37]);
    assert_eq!(&out[37..41], &[0, 0, 0, 9]);
    assert_eq!(&out[41..], &[0], "the padding stays at the end");
    match PduSessionContainer::decode_content(&out).unwrap() {
        PduSessionContainer::Ul(ul) => {
            assert_eq!(ul.n3_n9_delay_result, Some(9));
            assert_eq!(ul.ul_qfi_sequence_number, Some(0x0a0b0c));
        }
        other => panic!("UL frame, got {other:?}"),
    }
}

#[test]
fn new_ie_flags_and_what_follows_are_kept() {
    // New IE Flag (octet 2 bit 7) set: 0x49 = 0100 1001. After the UL Delay
    // Result: the New IE Flags octet 0x02 (bit 1, UL Congestion Information
    // present) and the 2-octet UL Congestion Information aa bb; 13 octets, padded
    // to 14. The N3/N9 Delay Result goes BEFORE the New IE Flags octet (Figure
    // 5.5.2.2-1), so they and the congestion field move up four octets intact.
    let frame = [0x16, 0x49, 0, 0, 0, 2, 0, 0, 0, 3, 0x02, 0xaa, 0xbb, 0];
    let out = add_n3_n9_delay(&frame, 7, false).unwrap();
    assert_eq!(
        out,
        [0x16, 0xc9, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 7, 0x02, 0xaa, 0xbb, 0]
    );
}

#[test]
fn only_a_ul_frame_with_a_ran_delay_result_is_changed() {
    // §5.24.5.3: "for UL GTP-U packets with the PDU Session Container extension
    // header including the RAN Uplink and/or Downlink fields".
    let ul_only = [0x12, 0x09, 0, 0, 0, 3];
    assert!(add_n3_n9_delay(&ul_only, 1, false).is_some());
    let dl_only = [0x14, 0x09, 0, 0, 0, 2];
    assert!(add_n3_n9_delay(&dl_only, 1, false).is_some());
    // No RAN Delay Result (just a QFI): unchanged.
    let bare = PduSessionContainer::Ul(UlPduSessionInformation {
        qfi: 9,
        ..Default::default()
    })
    .encode_content();
    assert_eq!(add_n3_n9_delay(&bare, 1, false), None);
    // A DL frame (PDU Type 0) whose bits would read as delay flags: unchanged.
    let dl = [0x06, 0x09];
    assert_eq!(add_n3_n9_delay(&dl, 1, false), None);
    // Truncated: unchanged, not a panic.
    assert_eq!(add_n3_n9_delay(&[0x16, 0x89, 0, 0], 1, false), None);
    assert_eq!(add_n3_n9_delay(&[0x16], 1, false), None);
}

#[test]
fn a_relayed_g_pdu_is_laid_out_per_ts_29_281() {
    // TEID 0x0000abcd, container = the 14 octets of the first test, payload de ad
    // be ef:
    // - 34: Version 1, PT 1, E 1 (§5.1); ff: G-PDU;
    // - Length (everything after octet 8) = 4 (Sequence Number, N-PDU Number,
    //   Next Extension Header Type) + 16 (container: length octet, 14, next type)
    //   + 4 (payload) = 24 = 00 18;
    // - TEID 00 00 ab cd; Sequence Number 00 00, N-PDU Number 00, next type 85
    //   (PDU Session Container, §5.2.1 Figure 5.2.1-3);
    // - 04: the container is 16 octets = 4 units; the 14 content octets; 00: no
    //   further extension header; then the T-PDU.
    let content = [0x16, 0x89, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 7];
    let got = build_relay_gpdu(0xabcd, Some(&content), &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    let mut want = vec![
        0x34, 0xff, 0x00, 0x18, 0, 0, 0xab, 0xcd, 0, 0, 0, 0x85, 0x04,
    ];
    want.extend_from_slice(&content);
    want.push(0);
    want.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(got, want);
    // A dummy (no T-PDU) keeps the container: Length = 4 + 16 = 20.
    let dummy = build_relay_gpdu(0xabcd, Some(&content), &[]).unwrap();
    assert_eq!(&dummy[2..4], &[0x00, 0x14]);
    assert_eq!(dummy.len(), 8 + 20);
    // Unpadded content is padded: 11 octets + 2 = 13 -> 16, three zeros.
    let odd = build_relay_gpdu(1, Some(&[0x10; 11]), &[]).unwrap();
    assert_eq!(odd[12], 4);
    assert_eq!(&odd[13 + 11..13 + 14], &[0, 0, 0]);
    assert_eq!(odd[13 + 14], 0, "next extension header type");
    // No container: the plain 8-octet header (§5.1), Length = payload.
    assert_eq!(
        build_relay_gpdu(1, None, &[9, 9]),
        Some(vec![0x30, 0xff, 0, 2, 0, 0, 0, 1, 9, 9])
    );
    // #2197 review m1: what does not fit one extension header (255 units) or the
    // 16-bit Length is refused, not sent with a wrapped length.
    assert_eq!(
        build_relay_gpdu(1, Some(&[0x10; MAX_CONTAINER_CONTENT]), &[]).map(|p| p[12]),
        Some(255)
    );
    assert_eq!(
        build_relay_gpdu(1, Some(&[0x10; MAX_CONTAINER_CONTENT + 1]), &[]),
        None
    );
    assert_eq!(build_relay_gpdu(1, None, &vec![0; 65_536]), None);
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pdr(peer: &str) -> TransportDelayPdr {
    TransportDelayPdr {
        peer: ip(peer),
        dscp: None,
    }
}

#[test]
fn the_ie_names_the_peer_and_the_dscp() {
    let ie = TransportDelayReporting {
        preceding_ul_gtpu_peer: RemoteGtpUPeer {
            ipv4: Some([10, 45, 0, 7]),
            ..Default::default()
        },
        dscp: Some(TransportLevelMarking::from_dscp(34)),
        extra: vec![],
    };
    assert_eq!(
        TransportDelayPdr::from_ie(&ie),
        Some(TransportDelayPdr {
            peer: ip("10.45.0.7"),
            dscp: Some(34),
        })
    );
    // An IPv4-mapped IPv6 peer is the IPv4 peer (the probe's answer comes from it).
    let v6 = TransportDelayReporting {
        preceding_ul_gtpu_peer: RemoteGtpUPeer {
            ipv6: Some(
                "::ffff:10.45.0.7"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            ),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        TransportDelayPdr::from_ie(&v6).unwrap().peer,
        ip("10.45.0.7")
    );
    // No address: nothing to probe.
    assert_eq!(
        TransportDelayPdr::from_ie(&TransportDelayReporting::default()),
        None
    );
}

#[test]
fn the_delay_is_half_the_echo_round_trip_of_that_peer() {
    let mut m = TransportDelayMonitor::default();
    assert!(!m.is_active());
    m.set_pdr(1, 1, Some(pdr("10.0.0.5")));
    assert!(m.is_active());
    assert_eq!(m.delay_for(1, 1), None, "not measured yet");
    let t0 = Instant::now();
    let probes = m.probes(t0);
    assert_eq!(probes.len(), 1);
    let (to, dscp, seq) = probes[0];
    assert_eq!(to, "10.0.0.5:2152".parse().unwrap());
    assert_eq!(dscp, None);
    // Another peer, or another sequence number, answers nothing.
    assert_eq!(
        m.on_echo_response("10.0.0.6:2152".parse().unwrap(), seq, t0),
        None
    );
    assert_eq!(m.on_echo_response(to, seq ^ 1, t0), None);
    // RTT 14 ms -> 7 ms (TS 23.501 §5.33.3.3: RTT/2 plus processing time, 0).
    assert_eq!(
        m.on_echo_response(to, seq, t0 + Duration::from_millis(14)),
        Some(7)
    );
    assert_eq!(m.delay_for(1, 1), Some(7));
    assert_eq!(m.delay_for(1, 2), None, "another PDR");
    assert_eq!(m.delay_for(2, 1), None, "another session");
    // Answered once only.
    assert_eq!(
        m.on_echo_response(to, seq, t0 + Duration::from_millis(30)),
        None
    );
}

#[test]
fn an_unanswered_probe_makes_the_delay_unknown() {
    let mut m = TransportDelayMonitor::default();
    m.set_pdr(1, 1, Some(pdr("10.0.0.5")));
    let t0 = Instant::now();
    let (to, _, seq) = m.probes(t0)[0];
    m.on_echo_response(to, seq, t0 + Duration::from_millis(4));
    assert_eq!(m.delay_for(1, 1), Some(2));
    // The next probe goes unanswered for PROBE_TIMEOUT: the round after drops it,
    // and the delay with it.
    let t1 = t0 + Duration::from_secs(1);
    m.probes(t1);
    assert_eq!(m.delay_for(1, 1), Some(2), "still within the timeout");
    m.probes(t1 + PROBE_TIMEOUT);
    assert_eq!(m.delay_for(1, 1), None);
}

#[test]
fn one_probe_per_peer_and_state_follows_the_pdrs() {
    let mut m = TransportDelayMonitor::default();
    m.set_pdr(1, 1, Some(pdr("10.0.0.5")));
    m.set_pdr(1, 2, Some(pdr("10.0.0.5")));
    m.set_pdr(2, 1, Some(pdr("10.0.0.9")));
    let t0 = Instant::now();
    let probes = m.probes(t0);
    let to: Vec<SocketAddr> = probes.iter().map(|(a, _, _)| *a).collect();
    assert_eq!(
        to,
        vec![
            "10.0.0.5:2152".parse::<SocketAddr>().unwrap(),
            "10.0.0.9:2152".parse().unwrap()
        ]
    );
    // One answer serves both PDRs naming that peer.
    m.on_echo_response(probes[0].0, probes[0].2, t0 + Duration::from_millis(6));
    assert_eq!((m.delay_for(1, 1), m.delay_for(1, 2)), (Some(3), Some(3)));
    // Deactivated on one PDR: the other keeps it.
    m.set_pdr(1, 1, None);
    assert_eq!((m.delay_for(1, 1), m.delay_for(1, 2)), (None, Some(3)));
    // The session goes: its peer is no longer probed.
    m.remove_session(1);
    assert_eq!(m.probes(t0).len(), 1);
    m.clear();
    assert!(!m.is_active());
    assert!(m.probes(t0).is_empty());
}

/// The three Echo Request sequence spaces stay apart over a whole wrap of each:
/// the §7.2 path table 1..=0x7FFF (pinned by its own `data_plane` test), the
/// GTP-U path QoS probes 0x8000..=0xBFFF and these 0xC000..=0xFFFF.
#[test]
fn the_probe_sequence_space_is_disjoint_from_the_path_qos_one() {
    let mut m = TransportDelayMonitor::default();
    m.set_pdr(1, 1, Some(pdr("10.0.0.5")));
    let mut q = crate::path_qos::PathQosMonitor::default();
    let peer: SocketAddr = "10.0.0.5:2152".parse().unwrap();
    let t0 = Instant::now();
    for _ in 0..0x4001 {
        let s = m.probes(t0)[0].2;
        assert!(s >= 0xC000, "transport delay probe {s:#x}");
        let p = q.probe_sent(peer, t0, true);
        assert!((0x8000..0xC000).contains(&p), "path QoS probe {p:#x}");
    }
}

/// #2197 review m2: from the NG-RAN, a present N3/N9 Delay Result is not one a
/// UPF wrote (TS 38.415 §5.5.3.21 "reported by the I-UPF"; TS 29.244 §5.24.5.3
/// NOTE "The RAN does not report the N3 path delay"): it is overwritten, not
/// summed. Behind an I-UPF it is summed.
///
/// REVERT-VERIFIED: with `from_ran` ignored (always summed), the RAN's 500 ms
/// survives into the field.
#[test]
fn a_value_the_ran_set_is_overwritten_not_summed() {
    let forged = [0x16, 0x89, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0x01, 0xf4]; // 500 ms
    let out = add_n3_n9_delay(&forged, 7, true).unwrap();
    assert_eq!(n3_n9_delay(&out), Some(7));
    let out = add_n3_n9_delay(&forged, 7, false).unwrap();
    assert_eq!(n3_n9_delay(&out), Some(507));
}

/// #2197 review m1: the length octet counts 4-octet units (TS 29.281 §5.2.1), so
/// a container is at most 1018 content octets. One that the inserted field would
/// push past that goes on unchanged, rather than with a wrapped length octet.
///
/// REVERT-VERIFIED: without the bound, a 1022-octet content comes back.
#[test]
fn an_insert_that_would_not_fit_one_extension_header_is_refused() {
    assert_eq!(MAX_CONTAINER_CONTENT, 1018);
    let mut full = RAN_FRAME.to_vec();
    full.resize(MAX_CONTAINER_CONTENT, 0);
    assert_eq!(add_n3_n9_delay(&full, 7, false), None);
    // A present field is overwritten in place, which always fits.
    let mut present = add_n3_n9_delay(&RAN_FRAME, 7, false).unwrap();
    present.resize(MAX_CONTAINER_CONTENT, 0);
    assert!(add_n3_n9_delay(&present, 1, false).is_some());
    // Four octets short of the limit still fits.
    let mut room = RAN_FRAME.to_vec();
    room.resize(MAX_CONTAINER_CONTENT - 4, 0);
    assert_eq!(
        add_n3_n9_delay(&room, 7, false).map(|c| c.len()),
        Some(MAX_CONTAINER_CONTENT)
    );
}

/// #2197 review (DSCP): one probe series per (peer, DSCP), each marked with its
/// DSCP, and a PDR's delay is the one measured with its own DSCP.
///
/// REVERT-VERIFIED: with the peers keyed by address alone, one probe goes out
/// and both PDRs read the same delay.
#[test]
fn each_dscp_is_probed_and_measured_on_its_own() {
    let mut m = TransportDelayMonitor::default();
    let ef = TransportDelayPdr {
        peer: ip("10.0.0.5"),
        dscp: Some(46),
    };
    m.set_pdr(1, 1, Some(pdr("10.0.0.5")));
    m.set_pdr(1, 2, Some(ef));
    let t0 = Instant::now();
    let probes = m.probes(t0);
    let marks: Vec<Option<u8>> = probes.iter().map(|(_, d, _)| *d).collect();
    assert_eq!(marks, vec![None, Some(46)]);
    m.on_echo_response(probes[0].0, probes[0].2, t0 + Duration::from_millis(20));
    m.on_echo_response(probes[1].0, probes[1].2, t0 + Duration::from_millis(4));
    assert_eq!((m.delay_for(1, 1), m.delay_for(1, 2)), (Some(10), Some(2)));
}

/// #2208 (R43 M1 on #2249): a PDI's Source Interface Type (IE 160, TS 29.244
/// §8.2.118) is parsed, its 6-bit value, so the data plane can tell an N3
/// preceding peer from an N9 one.
#[test]
fn a_pdi_s_source_interface_type_is_parsed_2208() {
    let tlv = |t: u16, v: &[u8]| {
        let mut b = t.to_be_bytes().to_vec();
        b.extend_from_slice(&(v.len() as u16).to_be_bytes());
        b.extend_from_slice(v);
        b
    };
    let mut pdi = tlv(20, &[0]);
    pdi.extend(tlv(160, &[0xcf])); // spare bits set: value 15 (N9)
    let mut pdr = tlv(56, &1u16.to_be_bytes());
    pdr.extend(tlv(29, &100u32.to_be_bytes()));
    pdr.extend(tlv(2, &pdi));
    pdr.extend(tlv(108, &1u32.to_be_bytes()));
    let p = crate::n4_build::parse_create_pdr(&pdr).unwrap();
    assert_eq!(p.pdi.source_interface_type, Some(15));
    let mut bare = tlv(56, &1u16.to_be_bytes());
    bare.extend(tlv(29, &100u32.to_be_bytes()));
    bare.extend(tlv(2, &tlv(20, &[0])));
    bare.extend(tlv(108, &1u32.to_be_bytes()));
    assert_eq!(
        crate::n4_build::parse_create_pdr(&bare)
            .unwrap()
            .pdi
            .source_interface_type,
        None
    );
}
