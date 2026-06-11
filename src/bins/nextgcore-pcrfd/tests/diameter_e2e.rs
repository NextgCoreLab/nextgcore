//! Wire-level integration tests for the PCRF Diameter stack.
//!
//! A real PCRF listener is started; mock PCEF (Gx) and AF (Rx) peers
//! connect over TCP, perform the RFC 6733 CER/CEA capabilities exchange
//! and then exercise the full message plane:
//!
//! - CCR-I / CCR-U / CCR-T -> CCA with Charging-Rule-Install,
//!   Default-EPS-Bearer-QoS, QoS-Information and Event-Trigger AVPs
//! - AAR -> Gx RAR (Charging-Rule-Install) toward the PCEF -> AAA
//! - STR -> Gx RAR (Charging-Rule-Remove) toward the PCEF -> STA
//! - CCR-T with a live Rx binding -> ASR toward the AF
//! - strict-peer rejection of a CCR missing mandatory AVPs
//!
//! No external reference byte vectors (e.g. seagull / open-source PCEF
//! captures) are vendored in this repository; wire conformance is
//! asserted by decoding the messages with the shared RFC 6733 codec and
//! checking vendor-id 10415 and the M/V flags on the 3GPP grouped AVPs.

use bytes::Bytes;

use ogs_diameter::avp::{find_all_avps, find_avp, Avp, AvpData};
use ogs_diameter::common::avp_code;
use ogs_diameter::config::DiameterConfig;
use ogs_diameter::gx::{avp as gx_avp, cmd as gx_cmd, GX_APPLICATION_ID};
use ogs_diameter::message::DiameterMessage;
use ogs_diameter::peer::{DiameterPeer, PeerEvent};
use ogs_diameter::rx::{avp as rx_avp, cmd as rx_cmd, RX_APPLICATION_ID};
use ogs_diameter::transport::DiameterTransport;
use ogs_diameter::OGS_3GPP_VENDOR_ID;

use nextgcore_pcrfd::{pcrf_context_init, pcrf_fd_listen, LocalIdentity};

const REALM: &str = "epc.mnc001.mcc001.3gppnetwork.org";

fn peer_config(host: &str) -> DiameterConfig {
    DiameterConfig {
        diameter_id: host.to_string(),
        diameter_realm: REALM.to_string(),
        timer_tc: 30,
        ..Default::default()
    }
}

/// Connect a mock peer to the PCRF and complete CER/CEA
async fn connect_peer(addr: std::net::SocketAddr, host: &str) -> DiameterPeer {
    let transport = DiameterTransport::connect(addr).await.expect("connect");
    let mut peer = DiameterPeer::new_initiator(transport, &peer_config(host));
    peer.start().await.expect("CER");
    match peer.next_event().await.expect("CEA") {
        PeerEvent::Established { .. } => peer,
        other => panic!("expected Established, got {other:?}"),
    }
}

/// Wait for the next application message from the peer
async fn next_message(peer: &mut DiameterPeer) -> DiameterMessage {
    loop {
        match peer.next_event().await.expect("peer event") {
            PeerEvent::Message(msg) => return msg,
            PeerEvent::WatchdogAck => continue,
            other => panic!("unexpected peer event: {other:?}"),
        }
    }
}

fn build_ccr(session_id: &str, host: &str, cc_type: u32, cc_number: u32, ue_ip: [u8; 4]) -> DiameterMessage {
    let mut ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
    ccr.header.hop_by_hop_id = 0x1000 + cc_number;
    ccr.header.end_to_end_id = 0x2000 + cc_number;
    ccr.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(session_id.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(GX_APPLICATION_ID),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        gx_avp::CC_REQUEST_TYPE,
        AvpData::Enumerated(cc_type as i32),
    ));
    ccr.add_avp(Avp::mandatory(
        gx_avp::CC_REQUEST_NUMBER,
        AvpData::Unsigned32(cc_number),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::SUBSCRIPTION_ID,
        AvpData::Grouped(vec![
            Avp::mandatory(avp_code::SUBSCRIPTION_ID_TYPE, AvpData::Enumerated(1)),
            Avp::mandatory(
                avp_code::SUBSCRIPTION_ID_DATA,
                AvpData::Utf8String("001010123456789".to_string()),
            ),
        ]),
    ));
    ccr.add_avp(Avp::mandatory(
        gx_avp::CALLED_STATION_ID,
        AvpData::Utf8String("internet".to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        gx_avp::FRAMED_IP_ADDRESS,
        AvpData::OctetString(Bytes::copy_from_slice(&ue_ip)),
    ));
    ccr
}

fn build_aar(session_id: &str, host: &str, ue_ip: [u8; 4]) -> DiameterMessage {
    let mut aar = DiameterMessage::new_request(rx_cmd::AA, RX_APPLICATION_ID);
    aar.header.hop_by_hop_id = 0x3000;
    aar.header.end_to_end_id = 0x4000;
    aar.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(session_id.to_string()),
    ));
    aar.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));
    aar.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host.to_string()),
    ));
    aar.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    aar.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    aar.add_avp(Avp::mandatory(
        rx_avp::FRAMED_IP_ADDRESS,
        AvpData::OctetString(Bytes::copy_from_slice(&ue_ip)),
    ));
    // Audio media component with explicit flow descriptions
    aar.add_avp(Avp::vendor_mandatory(
        rx_avp::MEDIA_COMPONENT_DESCRIPTION,
        OGS_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                rx_avp::MEDIA_COMPONENT_NUMBER,
                OGS_3GPP_VENDOR_ID,
                AvpData::Unsigned32(1),
            ),
            Avp::vendor_mandatory(
                rx_avp::MEDIA_TYPE,
                OGS_3GPP_VENDOR_ID,
                AvpData::Enumerated(0), // AUDIO
            ),
            Avp::vendor_mandatory(
                rx_avp::MAX_REQUESTED_BANDWIDTH_DL,
                OGS_3GPP_VENDOR_ID,
                AvpData::Unsigned32(64000),
            ),
            Avp::vendor_mandatory(
                rx_avp::MAX_REQUESTED_BANDWIDTH_UL,
                OGS_3GPP_VENDOR_ID,
                AvpData::Unsigned32(64000),
            ),
            Avp::vendor_mandatory(
                rx_avp::MEDIA_SUB_COMPONENT,
                OGS_3GPP_VENDOR_ID,
                AvpData::Grouped(vec![
                    Avp::vendor_mandatory(
                        rx_avp::FLOW_NUMBER,
                        OGS_3GPP_VENDOR_ID,
                        AvpData::Unsigned32(1),
                    ),
                    Avp::vendor_mandatory(
                        rx_avp::FLOW_DESCRIPTION,
                        OGS_3GPP_VENDOR_ID,
                        AvpData::OctetString(Bytes::from_static(
                            b"permit out 17 from 10.0.0.1 5004 to 10.45.0.9 6000",
                        )),
                    ),
                    Avp::vendor_mandatory(
                        rx_avp::FLOW_DESCRIPTION,
                        OGS_3GPP_VENDOR_ID,
                        AvpData::OctetString(Bytes::from_static(
                            b"permit in 17 from 10.45.0.9 6000 to 10.0.0.1 5004",
                        )),
                    ),
                ]),
            ),
        ]),
    ));
    aar
}

fn build_str_msg(session_id: &str, host: &str) -> DiameterMessage {
    let mut str_msg =
        DiameterMessage::new_request(rx_cmd::SESSION_TERMINATION, RX_APPLICATION_ID);
    str_msg.header.hop_by_hop_id = 0x5000;
    str_msg.header.end_to_end_id = 0x6000;
    str_msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(session_id.to_string()),
    ));
    str_msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host.to_string()),
    ));
    str_msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    str_msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    str_msg.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));
    str_msg.add_avp(Avp::mandatory(
        avp_code::TERMINATION_CAUSE,
        AvpData::Enumerated(1), // DIAMETER_LOGOUT
    ));
    str_msg
}

/// Answer a received Gx RAR with a successful RAA, returning the RAR
fn build_raa(rar: &DiameterMessage, host: &str) -> DiameterMessage {
    let mut raa = DiameterMessage::new_answer(rar);
    if let Some(sid) = rar.session_id() {
        raa.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    raa.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    raa.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host.to_string()),
    ));
    raa.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    raa
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_gx_rx_full_wire_flow() {
    pcrf_context_init(1024);
    let identity = LocalIdentity {
        host: "pcrf-e2e.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        realm: REALM.to_string(),
    };
    let addr = pcrf_fd_listen(identity, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen");

    let pcef_host = "pgw-e2e.epc.mnc001.mcc001.3gppnetwork.org";
    let af_host = "pcscf-e2e.ims.mnc001.mcc001.3gppnetwork.org";
    let ue_ip = [10, 45, 0, 9];
    let gx_sid = "e2e-gx-session-1";
    let rx_sid = "e2e-rx-session-1";

    // ------------------------------------------------------------------
    // 1. PCEF connects and opens the IP-CAN session (CCR-I -> CCA)
    // ------------------------------------------------------------------
    let mut pcef = connect_peer(addr, pcef_host).await;
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 1, 0, ue_ip))
        .await
        .expect("send CCR-I");
    let cca = next_message(&mut pcef).await;
    assert!(cca.header.is_answer());
    assert_eq!(cca.header.command_code, gx_cmd::CREDIT_CONTROL);
    assert_eq!(cca.header.hop_by_hop_id, 0x1000);
    assert_eq!(cca.result_code(), Some(2001));
    assert_eq!(cca.session_id(), Some(gx_sid));
    assert_eq!(
        cca.find_avp(gx_avp::CC_REQUEST_TYPE).and_then(|a| a.as_u32()),
        Some(1)
    );
    // Full provisioning present on the wire
    let install = cca
        .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, OGS_3GPP_VENDOR_ID)
        .expect("Charging-Rule-Install");
    assert!(install.is_mandatory());
    assert!(install.is_vendor_specific());
    let crd = find_avp(
        &install.parse_grouped().unwrap(),
        gx_avp::CHARGING_RULE_DEFINITION,
    )
    .expect("Charging-Rule-Definition")
    .parse_grouped()
    .unwrap();
    assert!(find_avp(&crd, gx_avp::CHARGING_RULE_NAME).is_some());
    assert!(find_avp(&crd, gx_avp::FLOW_INFORMATION).is_some());
    assert!(find_avp(&crd, gx_avp::QOS_INFORMATION).is_some());
    assert!(cca
        .find_vendor_avp(gx_avp::DEFAULT_EPS_BEARER_QOS, OGS_3GPP_VENDOR_ID)
        .is_some());
    assert!(!find_all_avps(&cca.avps, gx_avp::EVENT_TRIGGER).is_empty());

    // ------------------------------------------------------------------
    // 2. CCR-U on the same session
    // ------------------------------------------------------------------
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 2, 1, ue_ip))
        .await
        .expect("send CCR-U");
    let cca_u = next_message(&mut pcef).await;
    assert_eq!(cca_u.result_code(), Some(2001));
    assert_eq!(
        cca_u
            .find_avp(gx_avp::CC_REQUEST_NUMBER)
            .and_then(|a| a.as_u32()),
        Some(1)
    );

    // ------------------------------------------------------------------
    // 3. AF connects, AAR -> PCRF pushes RAR (install) to the PCEF -> AAA
    // ------------------------------------------------------------------
    let mut af = connect_peer(addr, af_host).await;

    // PCEF concurrently answers the incoming RAR
    let pcef_task = tokio::spawn(async move {
        let rar = next_message(&mut pcef).await;
        assert!(rar.header.is_request());
        assert_eq!(rar.header.command_code, gx_cmd::RE_AUTH);
        assert_eq!(rar.session_id(), Some(gx_sid));
        assert_eq!(rar.destination_host(), Some(pcef_host));
        // Hop-by-Hop must not be a fixed value like 0
        assert_ne!(rar.header.hop_by_hop_id, 0);
        let install = rar
            .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, OGS_3GPP_VENDOR_ID)
            .expect("RAR Charging-Rule-Install");
        let crd = find_avp(
            &install.parse_grouped().unwrap(),
            gx_avp::CHARGING_RULE_DEFINITION,
        )
        .expect("rule definition")
        .parse_grouped()
        .unwrap();
        let rule_name = find_avp(&crd, gx_avp::CHARGING_RULE_NAME)
            .and_then(|a| a.as_octet_string())
            .expect("rule name")
            .to_vec();
        // Audio media component -> QCI 1 GBR rule
        let qi = find_avp(&crd, gx_avp::QOS_INFORMATION)
            .expect("rule QoS")
            .parse_grouped()
            .unwrap();
        assert_eq!(
            find_avp(&qi, gx_avp::QOS_CLASS_IDENTIFIER).and_then(|a| a.as_u32()),
            Some(1)
        );
        pcef.send_message(&build_raa(&rar, pcef_host))
            .await
            .expect("send RAA");
        (pcef, rule_name)
    });

    af.send_message(&build_aar(rx_sid, af_host, ue_ip))
        .await
        .expect("send AAR");
    let aaa = next_message(&mut af).await;
    assert!(aaa.header.is_answer());
    assert_eq!(aaa.header.command_code, rx_cmd::AA);
    assert_eq!(aaa.result_code(), Some(2001));
    assert_eq!(aaa.session_id(), Some(rx_sid));

    let (mut pcef, installed_rule_name) = pcef_task.await.expect("pcef task");

    // ------------------------------------------------------------------
    // 4. STR -> PCRF pushes RAR (Charging-Rule-Remove) to the PCEF -> STA
    // ------------------------------------------------------------------
    let pcef_task = tokio::spawn(async move {
        let rar = next_message(&mut pcef).await;
        assert_eq!(rar.header.command_code, gx_cmd::RE_AUTH);
        assert_eq!(rar.session_id(), Some(gx_sid));
        let remove = rar
            .find_vendor_avp(gx_avp::CHARGING_RULE_REMOVE, OGS_3GPP_VENDOR_ID)
            .expect("RAR Charging-Rule-Remove");
        let names: Vec<Vec<u8>> =
            find_all_avps(&remove.parse_grouped().unwrap(), gx_avp::CHARGING_RULE_NAME)
                .iter()
                .map(|a| a.as_octet_string().unwrap().to_vec())
                .collect();
        assert_eq!(names, vec![installed_rule_name]);
        pcef.send_message(&build_raa(&rar, pcef_host))
            .await
            .expect("send RAA");
        pcef
    });

    af.send_message(&build_str_msg(rx_sid, af_host))
        .await
        .expect("send STR");
    let sta = next_message(&mut af).await;
    assert!(sta.header.is_answer());
    assert_eq!(sta.header.command_code, rx_cmd::SESSION_TERMINATION);
    assert_eq!(sta.result_code(), Some(2001));

    let mut pcef = pcef_task.await.expect("pcef task");

    // ------------------------------------------------------------------
    // 5. CCR-T closes the IP-CAN session
    // ------------------------------------------------------------------
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 3, 2, ue_ip))
        .await
        .expect("send CCR-T");
    let cca_t = next_message(&mut pcef).await;
    assert_eq!(cca_t.result_code(), Some(2001));
    // No provisioning AVPs on termination
    assert!(cca_t
        .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, OGS_3GPP_VENDOR_ID)
        .is_none());

    // A further CCR-U for the removed session must be rejected
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 2, 3, ue_ip))
        .await
        .expect("send stale CCR-U");
    let cca_stale = next_message(&mut pcef).await;
    assert_eq!(cca_stale.result_code(), Some(5002)); // DIAMETER_UNKNOWN_SESSION_ID
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ccr_t_aborts_bound_rx_session_with_asr() {
    pcrf_context_init(1024);
    let identity = LocalIdentity {
        host: "pcrf-asr.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        realm: REALM.to_string(),
    };
    let addr = pcrf_fd_listen(identity, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen");

    let pcef_host = "pgw-asr.epc.mnc001.mcc001.3gppnetwork.org";
    let af_host = "pcscf-asr.ims.mnc001.mcc001.3gppnetwork.org";
    let ue_ip = [10, 45, 0, 77];
    let gx_sid = "asr-gx-session-1";
    let rx_sid = "asr-rx-session-1";

    // Open IP-CAN session
    let mut pcef = connect_peer(addr, pcef_host).await;
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 1, 0, ue_ip))
        .await
        .expect("send CCR-I");
    assert_eq!(next_message(&mut pcef).await.result_code(), Some(2001));

    // AF binds an Rx session (PCEF answers the RAR install)
    let mut af = connect_peer(addr, af_host).await;
    let pcef_task = tokio::spawn(async move {
        let rar = next_message(&mut pcef).await;
        assert_eq!(rar.header.command_code, gx_cmd::RE_AUTH);
        pcef.send_message(&build_raa(&rar, pcef_host))
            .await
            .expect("send RAA");
        pcef
    });
    af.send_message(&build_aar(rx_sid, af_host, ue_ip))
        .await
        .expect("send AAR");
    assert_eq!(next_message(&mut af).await.result_code(), Some(2001));
    let mut pcef = pcef_task.await.expect("pcef task");

    // The AF concurrently answers the incoming ASR triggered by CCR-T
    let af_task = tokio::spawn(async move {
        let asr = next_message(&mut af).await;
        assert!(asr.header.is_request());
        assert_eq!(asr.header.command_code, rx_cmd::ABORT_SESSION);
        assert_eq!(asr.session_id(), Some(rx_sid));
        assert_eq!(asr.destination_host(), Some(af_host));
        let abort_cause = asr
            .find_vendor_avp(rx_avp::ABORT_CAUSE, OGS_3GPP_VENDOR_ID)
            .expect("Abort-Cause");
        assert_eq!(abort_cause.as_i32(), Some(0)); // BEARER_RELEASED
        let mut asa = DiameterMessage::new_answer(&asr);
        asa.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(rx_sid.to_string()),
        ));
        asa.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(2001),
        ));
        asa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(af_host.to_string()),
        ));
        asa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(REALM.to_string()),
        ));
        af.send_message(&asa).await.expect("send ASA");
    });

    // PCEF terminates the IP-CAN session
    pcef.send_message(&build_ccr(gx_sid, pcef_host, 3, 1, ue_ip))
        .await
        .expect("send CCR-T");
    let cca_t = next_message(&mut pcef).await;
    assert_eq!(cca_t.result_code(), Some(2001));

    tokio::time::timeout(std::time::Duration::from_secs(5), af_task)
        .await
        .expect("ASR not received in time")
        .expect("af task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_strict_peer_rejects_ccr_missing_mandatory_avps() {
    pcrf_context_init(1024);
    let identity = LocalIdentity {
        host: "pcrf-strict.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        realm: REALM.to_string(),
    };
    let addr = pcrf_fd_listen(identity, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen");

    let pcef_host = "pgw-strict.epc.mnc001.mcc001.3gppnetwork.org";
    let mut pcef = connect_peer(addr, pcef_host).await;

    // CCR without CC-Request-Type / CC-Request-Number
    let mut ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
    ccr.header.hop_by_hop_id = 0x77;
    ccr.header.end_to_end_id = 0x88;
    ccr.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String("strict-gx-1".to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(GX_APPLICATION_ID),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(pcef_host.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    ccr.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(REALM.to_string()),
    ));
    pcef.send_message(&ccr).await.expect("send strict CCR");

    let cca = next_message(&mut pcef).await;
    assert_eq!(cca.result_code(), Some(5005)); // DIAMETER_MISSING_AVP
    assert_eq!(cca.header.hop_by_hop_id, 0x77);
    let failed = cca.find_avp(279).expect("Failed-AVP"); // FAILED_AVP
    let members = failed.parse_grouped().unwrap();
    assert_eq!(members[0].code, gx_avp::CC_REQUEST_TYPE);

    // CCR with the wrong Auth-Application-Id is rejected with 3007
    let mut ccr = build_ccr("strict-gx-2", pcef_host, 1, 0, [10, 99, 0, 1]);
    ccr.avps.retain(|a| a.code != avp_code::AUTH_APPLICATION_ID);
    ccr.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));
    pcef.send_message(&ccr).await.expect("send wrong-app CCR");
    let cca = next_message(&mut pcef).await;
    assert_eq!(cca.result_code(), Some(3007)); // DIAMETER_APPLICATION_UNSUPPORTED
    assert!(cca.header.is_error()); // protocol error -> E-bit set
}
