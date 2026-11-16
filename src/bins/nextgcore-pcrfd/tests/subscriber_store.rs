//! #1459: the real pcrfd binary opens the subscriber store its config names,
//! answers a CCR-I with the policy the subscriber is provisioned with, and refuses
//! to start when that store is unreachable.
//!
//! Before #1459 nothing in pcrfd called `nextgcore_dbi_init*`: the shipped
//! pcrf.yaml set `db_uri` and nothing read it, so every subscription lookup failed
//! "Database not initialized" and every CCA-I carried the local default (QCI 9,
//! APN-AMBR UL 50 / DL 100 Mbps).
//!
//! The MongoDB test runs a throwaway `mongo:6.0` container published on loopback
//! only. Without docker it is skipped with a note, except where
//! `NEXTGCORE_DOCKER_REQUIRED` is set (CI's Test job), where a missing docker fails
//! it instead. Containers are labelled with the test process id, and one whose
//! process is gone is removed by the next run.
//!
//! REVERT-VERIFIED: with the `open_subscriber_store` call removed from `main`,
//! `pcrfd_answers_a_ccr_i_with_the_provisioned_policy` reads the default APN-AMBR,
//! `pcrfd_refuses_to_start_when_its_store_is_unreachable` times out with pcrfd
//! serving, and `a_sigterm_during_the_store_retry_exits_promptly` never sees the
//! retry.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nextgcore_dbi::mongodb::bson::doc;
use nextgcore_diameter::avp::{find_avp, Avp, AvpData};
use nextgcore_diameter::common::avp_code;
use nextgcore_diameter::config::DiameterConfig;
use nextgcore_diameter::gx::{avp as gx_avp, cmd as gx_cmd, GX_APPLICATION_ID};
use nextgcore_diameter::message::DiameterMessage;
use nextgcore_diameter::peer::{DiameterPeer, PeerEvent};
use nextgcore_diameter::transport::DiameterTransport;
use nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID;

const DOCKER_REQUIRED_ENV: &str = "NEXTGCORE_DOCKER_REQUIRED";
const PID_LABEL: &str = "nextgcore-test-pcrfd-1459-pid";
const REALM: &str = "epc.mnc001.mcc001.3gppnetwork.org";
const PCEF_HOST: &str = "pgw-1459.epc.mnc001.mcc001.3gppnetwork.org";

/// A per-test scratch directory, removed on drop.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("pcrfd-1459-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn name(&self) -> String {
        self.0
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("pcrf.yaml"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker").args(args).output().expect("docker")
}

/// A `mongo:6.0` container on a loopback-only ephemeral port, removed on drop.
struct Mongo {
    id: String,
    port: u16,
}

impl Drop for Mongo {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.id]);
    }
}

impl Mongo {
    /// `None` when docker is unavailable and not required.
    fn start() -> Option<Mongo> {
        let docker_ok = Command::new("docker")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !docker_ok {
            assert!(
                std::env::var_os(DOCKER_REQUIRED_ENV).is_none(),
                "{DOCKER_REQUIRED_ENV} is set but docker is not available"
            );
            eprintln!("skipped: docker is not available (set {DOCKER_REQUIRED_ENV} to require it)");
            return None;
        }
        Self::sweep_orphans();
        let label = format!("{PID_LABEL}={}", std::process::id());
        let out = docker(&[
            "run",
            "-d",
            "--rm",
            "--label",
            &label,
            "-p",
            "127.0.0.1::27017",
            "mongo:6.0",
        ]);
        assert!(
            out.status.success(),
            "docker run mongo:6.0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let mut mongo = Mongo { id, port: 0 };
        let out = docker(&["port", &mongo.id, "27017/tcp"]);
        let mapping = String::from_utf8(out.stdout).unwrap();
        mongo.port = mapping
            .lines()
            .find_map(|l| l.trim().strip_prefix("127.0.0.1:"))
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("a loopback port mapping: {mapping:?}"));
        Some(mongo)
    }

    fn sweep_orphans() {
        let out = docker(&[
            "ps",
            "-a",
            "--filter",
            &format!("label={PID_LABEL}"),
            "--format",
            &format!("{{{{.ID}}}} {{{{.Label \"{PID_LABEL}\"}}}}"),
        ]);
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut it = line.split_whitespace();
            let (Some(id), Some(pid)) = (it.next(), it.next()) else {
                continue;
            };
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                let _ = docker(&["rm", "-f", id]);
            }
        }
    }

    /// The URI with no timeout options, as the shipped pcrf.yaml writes it.
    fn uri(&self) -> String {
        format!("mongodb://127.0.0.1:{}/nextgcore", self.port)
    }

    fn provision(&self, document: nextgcore_dbi::mongodb::bson::Document) {
        let client = nextgcore_dbi::mongodb::sync::Client::with_uri_str(format!(
            "{}?serverSelectionTimeoutMS=1000",
            self.uri()
        ))
        .expect("mongo client");
        let db = client.database("nextgcore");
        let deadline = Instant::now() + Duration::from_secs(60);
        while db.run_command(doc! { "ping": 1 }, None).is_err() {
            assert!(Instant::now() < deadline, "mongo:6.0 never answered a ping");
            std::thread::sleep(Duration::from_millis(250));
        }
        db.collection("subscribers")
            .insert_one(document, None)
            .expect("provision the subscriber");
    }

    /// #1553: bring a killed store back, empty, on the same loopback port, so the
    /// URI pcrfd holds reaches it again.
    fn restart(&mut self) {
        let label = format!("{PID_LABEL}={}", std::process::id());
        let publish = format!("127.0.0.1:{}:27017", self.port);
        let out = docker(&[
            "run",
            "-d",
            "--rm",
            "--label",
            &label,
            "-p",
            &publish,
            "mongo:6.0",
        ]);
        assert!(
            out.status.success(),
            "docker run mongo:6.0 on {publish}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.id = String::from_utf8(out.stdout).unwrap().trim().to_string();
    }

    /// Take the store away under a running pcrfd.
    fn kill(&self) {
        let out = docker(&["kill", &self.id]);
        assert!(out.status.success(), "docker kill the store");
    }
}

use nextgcore_sbi::test_support::{free_port, NfProcess, NfSpawn};

/// Start pcrfd on `db_uri` and wait for its Diameter listener.
///
/// #1521: through the shared `NfSpawn`. pcrfd's Diameter bind is not fatal: on a
/// lost port it logs the error and runs on without a listener, so the probed
/// port taken by another process (the #1497 race) surfaced as the PCEF never
/// connecting. `NfSpawn` sees "Address already in use" and respawns on a fresh
/// port. The startup-failure tests below spawn directly: pcrfd opens its store
/// before the Diameter listener, so an unreachable store exits before any bind.
async fn start_pcrfd(dir: &Scratch, db_uri: &str) -> NfProcess {
    NfSpawn::new(
        env!("CARGO_BIN_EXE_nextgcore-pcrfd"),
        &format!("pcrfd-1459-{}", dir.name()),
    )
    .ready_when_logged("Diameter listener active on")
    .spawn_async(|cmd, diameter_port, _| {
        pcrfd_args(cmd, dir, db_uri, diameter_port);
    })
    .await
}

fn pcrfd_command(dir: &Scratch, db_uri: &str, diameter_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nextgcore-pcrfd"));
    pcrfd_args(&mut cmd, dir, db_uri, diameter_port);
    cmd.stdout(Stdio::null());
    cmd
}

fn pcrfd_args(cmd: &mut Command, dir: &Scratch, db_uri: &str, diameter_port: u16) {
    let config = dir.0.join("pcrf.yaml");
    std::fs::write(&config, format!("db_uri: {db_uri}\n")).unwrap();
    cmd.arg("-c")
        .arg(&config)
        .arg("--diameter-addr")
        .arg(format!("127.0.0.1:{diameter_port}"))
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1");
}

/// A subscriber whose APN "internet" differs from the local default in every
/// value (QCI 9, UL 50 / DL 100 Mbps), with uplink differing from downlink, so
/// neither the default nor a direction swap can pass.
fn subscriber(imsi: &str) -> nextgcore_dbi::mongodb::bson::Document {
    doc! {
        "imsi": imsi,
        "ambr": { "uplink": { "value": 1, "unit": 3 }, "downlink": { "value": 1, "unit": 3 } },
        "slice": [{
            "sst": 1,
            "default_indicator": true,
            "session": [{
                "name": "internet",
                "type": 3,
                "qos": {
                    "index": 7,
                    "arp": { "priority_level": 2, "pre_emption_capability": 1,
                             "pre_emption_vulnerability": 1 },
                },
                "ambr": { "uplink": { "value": 7, "unit": 2 },
                          "downlink": { "value": 13, "unit": 2 } },
            }],
        }],
    }
}

fn build_ccr_i(session_id: &str, imsi: &str) -> DiameterMessage {
    build_ccr(session_id, imsi, 1, 0, &[])
}

/// CC-Request-Type values (RFC 4006 §8.3).
const UPDATE_REQUEST: i32 = 2;
const TERMINATION_REQUEST: i32 = 3;
/// Event-Trigger RAT_CHANGE (TS 29.212 §5.3.7).
const RAT_CHANGE: i32 = 2;

fn build_ccr(
    session_id: &str,
    imsi: &str,
    cc_request_type: i32,
    cc_request_number: u32,
    triggers: &[i32],
) -> DiameterMessage {
    let mut ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
    ccr.header.hop_by_hop_id = 0x1459_0000 + cc_request_number;
    ccr.header.end_to_end_id = 0x1459_1000 + cc_request_number;
    for avp in [
        Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(session_id.to_string()),
        ),
        Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(GX_APPLICATION_ID),
        ),
        Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(PCEF_HOST.to_string()),
        ),
        Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(REALM.to_string()),
        ),
        Avp::mandatory(
            avp_code::DESTINATION_REALM,
            AvpData::DiameterIdentity(REALM.to_string()),
        ),
        Avp::mandatory(
            gx_avp::CC_REQUEST_TYPE,
            AvpData::Enumerated(cc_request_type),
        ),
        Avp::mandatory(
            gx_avp::CC_REQUEST_NUMBER,
            AvpData::Unsigned32(cc_request_number),
        ),
        Avp::mandatory(
            avp_code::SUBSCRIPTION_ID,
            AvpData::Grouped(vec![
                // END_USER_IMSI
                Avp::mandatory(avp_code::SUBSCRIPTION_ID_TYPE, AvpData::Enumerated(1)),
                Avp::mandatory(
                    avp_code::SUBSCRIPTION_ID_DATA,
                    AvpData::Utf8String(imsi.to_string()),
                ),
            ]),
        ),
        Avp::mandatory(
            gx_avp::CALLED_STATION_ID,
            AvpData::Utf8String("internet".to_string()),
        ),
        Avp::mandatory(
            gx_avp::FRAMED_IP_ADDRESS,
            AvpData::OctetString(Bytes::copy_from_slice(&[10, 45, 14, 59])),
        ),
    ] {
        ccr.add_avp(avp);
    }
    for trigger in triggers {
        ccr.add_avp(Avp::vendor_mandatory(
            gx_avp::EVENT_TRIGGER,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Enumerated(*trigger),
        ));
    }
    ccr
}

/// The session-level APN-AMBR (UL, DL) a CCA provisions, `None` when it carries no
/// session QoS-Information.
fn apn_ambr(cca: &DiameterMessage) -> Option<(Option<u32>, Option<u32>)> {
    let qos = cca
        .find_vendor_avp(gx_avp::QOS_INFORMATION, NEXTGCORE_3GPP_VENDOR_ID)?
        .parse_grouped()
        .unwrap();
    let ambr = |code| find_avp(&qos, code).and_then(|a| a.as_u32());
    Some((
        ambr(gx_avp::APN_AGGREGATE_MAX_BITRATE_UL),
        ambr(gx_avp::APN_AGGREGATE_MAX_BITRATE_DL),
    ))
}

/// The Experimental-Result-Code of an answer, if it carries one.
fn experimental_result(cca: &DiameterMessage) -> Option<u32> {
    let exp = cca
        .find_avp(avp_code::EXPERIMENTAL_RESULT)?
        .parse_grouped()
        .unwrap();
    assert_eq!(
        find_avp(&exp, avp_code::VENDOR_ID).and_then(|a| a.as_u32()),
        Some(NEXTGCORE_3GPP_VENDOR_ID),
        "a 3GPP experimental result"
    );
    find_avp(&exp, avp_code::EXPERIMENTAL_RESULT_CODE).and_then(|a| a.as_u32())
}

/// Send `ccr` and answer (the CCA, how long it took).
async fn exchange(peer: &mut DiameterPeer, ccr: &DiameterMessage) -> (DiameterMessage, Duration) {
    let started = Instant::now();
    peer.send_message(ccr).await.expect("send CCR");
    let cca = tokio::time::timeout(Duration::from_secs(40), next_message(peer))
        .await
        .expect("a CCA within 40 s");
    (cca, started.elapsed())
}

/// #1539 review: the store dies under a running pcrfd, with the shipped URI shape
/// (no timeout options; nextgcore-dbi bounds selection at 1 s, #1462).
///
/// - A live session's CCR-U(RAT_CHANGE) is answered 2001 with **no** QoS
///   provisioning, so the PCEF keeps enforcing the subscriber's real policy,
///   instead of being re-authorized onto the local default.
/// - A new CCR-I is rejected with DIAMETER_ERROR_INITIAL_PARAMETERS (5140), per
///   TS 29.212 §4.5.1, instead of being established on the default.
/// - Each is answered in about one server selection, inside a PCEF's Tx timer.
/// - A CCR-T does not need the store and is answered promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_outage_neither_downgrades_live_sessions_nor_invents_new_ones() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    let imsi = "001010000014591";
    mongo.provision(subscriber(imsi));
    let dir = Scratch::new("outage");
    let pcrfd = start_pcrfd(&dir, &mongo.uri()).await;
    let mut pcef = connect_pcef(pcrfd.port()).await;
    let sid = "pgw-1459;2;outage";

    // Store up: the session is established, and a RAT change re-authorizes it,
    // both from the subscription.
    let (cca, _) = exchange(&mut pcef, &build_ccr_i(sid, imsi)).await;
    assert_eq!(cca.result_code(), Some(2001));
    assert_eq!(apn_ambr(&cca), Some((Some(7_000_000), Some(13_000_000))));
    let (cca, _) = exchange(
        &mut pcef,
        &build_ccr(sid, imsi, UPDATE_REQUEST, 1, &[RAT_CHANGE]),
    )
    .await;
    assert_eq!(cca.result_code(), Some(2001));
    assert_eq!(
        apn_ambr(&cca),
        Some((Some(7_000_000), Some(13_000_000))),
        "with the store up, a RAT change re-authorizes from the subscription"
    );

    mongo.kill();

    let (cca, took) = exchange(
        &mut pcef,
        &build_ccr(sid, imsi, UPDATE_REQUEST, 2, &[RAT_CHANGE]),
    )
    .await;
    assert_eq!(cca.result_code(), Some(2001), "the live session is kept");
    assert_eq!(
        apn_ambr(&cca),
        None,
        "no re-authorization during the outage: the PCEF keeps 7/13 Mbps, not the default"
    );
    assert!(
        cca.find_vendor_avp(gx_avp::DEFAULT_EPS_BEARER_QOS, NEXTGCORE_3GPP_VENDOR_ID)
            .is_none(),
        "no default-bearer QoS either"
    );
    eprintln!("outage CCA-U answered in {took:?}");
    assert!(took < Duration::from_secs(3), "CCA-U took {took:?}");

    let (cca, took) = exchange(&mut pcef, &build_ccr_i("pgw-1459;3;outage", imsi)).await;
    assert_eq!(
        cca.result_code(),
        None,
        "an Experimental-Result, not a Result-Code"
    );
    assert_eq!(experimental_result(&cca), Some(5140));
    assert_eq!(apn_ambr(&cca), None, "and no invented policy");
    eprintln!("outage CCA-I answered in {took:?}");
    assert!(took < Duration::from_secs(3), "CCA-I took {took:?}");

    let (cca, took) = exchange(
        &mut pcef,
        &build_ccr(sid, imsi, TERMINATION_REQUEST, 3, &[]),
    )
    .await;
    assert_eq!(cca.result_code(), Some(2001));
    assert!(
        took < Duration::from_millis(500),
        "CCA-T took {took:?}: it read the store"
    );
}

/// #1553: during a store outage, CCRs on ONE PCEF connection (handled in order)
/// no longer each wait a server selection: after the first finds the store down,
/// the rest fail fast for `STORE_DOWN_LATCH` (3 s), so a burst drains in about one
/// selection rather than one per CCR. A store that comes back is read again once
/// the latch expires.
///
/// REVERT-VERIFIED: with the latch check removed from `lookup_subscriber_policy`,
/// the burst of 6 CCR-Is takes about 6 s and the burst assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_during_an_outage_costs_one_store_wait_1553() {
    let Some(mut mongo) = Mongo::start() else {
        return;
    };
    let imsi = "001010000015531";
    mongo.provision(subscriber(imsi));
    let dir = Scratch::new("latch");
    let pcrfd = start_pcrfd(&dir, &mongo.uri()).await;
    let mut pcef = connect_pcef(pcrfd.port()).await;

    let (cca, _) = exchange(&mut pcef, &build_ccr_i("pgw-1553;0;latch", imsi)).await;
    assert_eq!(cca.result_code(), Some(2001), "the store is up");

    mongo.kill();
    const BURST: u32 = 6;
    let started = Instant::now();
    for n in 1..=BURST {
        let (cca, _) = exchange(
            &mut pcef,
            &build_ccr_i(&format!("pgw-1553;{n};latch"), imsi),
        )
        .await;
        assert_eq!(
            experimental_result(&cca),
            Some(5140),
            "CCR-I {n} during the outage"
        );
    }
    let burst = started.elapsed();
    eprintln!("{BURST} outage CCR-Is answered in {burst:?}");
    assert!(
        burst < Duration::from_millis(2_500),
        "{BURST} CCR-Is on one connection took {burst:?}: each waited a server selection"
    );

    // The store comes back: once the latch expires a CCR-I reads it again and is
    // established from the subscription.
    mongo.restart();
    mongo.provision(subscriber(imsi));
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut n = 100;
    loop {
        n += 1;
        let (cca, _) = exchange(
            &mut pcef,
            &build_ccr_i(&format!("pgw-1553;{n};latch"), imsi),
        )
        .await;
        if cca.result_code() == Some(2001) {
            assert_eq!(
                apn_ambr(&cca),
                Some((Some(7_000_000), Some(13_000_000))),
                "recovered: the provisioned policy"
            );
            break;
        }
        assert_eq!(experimental_result(&cca), Some(5140));
        assert!(
            Instant::now() < deadline,
            "pcrfd never read the restored store"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Connect to pcrfd as a PCEF and complete CER/CEA, waiting on the listener
/// rather than a timer: a refused connection is pcrfd still starting.
async fn connect_pcef(port: u16) -> DiameterPeer {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let transport = loop {
        match DiameterTransport::connect(addr).await {
            Ok(t) => break t,
            Err(_) => {
                assert!(Instant::now() < deadline, "pcrfd never served Diameter");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    let config = DiameterConfig {
        diameter_id: PCEF_HOST.to_string(),
        diameter_realm: REALM.to_string(),
        timer_tc: 30,
        ..Default::default()
    };
    let mut peer = DiameterPeer::new_initiator(transport, &config);
    peer.start().await.expect("CER");
    match peer.next_event().await.expect("CEA") {
        PeerEvent::Established { .. } => peer,
        other => panic!("expected Established, got {other:?}"),
    }
}

async fn next_message(peer: &mut DiameterPeer) -> DiameterMessage {
    loop {
        match peer.next_event().await.expect("peer event") {
            PeerEvent::Message(msg) => return msg,
            PeerEvent::WatchdogAck => continue,
            other => panic!("unexpected peer event: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcrfd_answers_a_ccr_i_with_the_provisioned_policy() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    let imsi = "001010000001459";
    mongo.provision(subscriber(imsi));
    let dir = Scratch::new("store");
    let pcrfd = start_pcrfd(&dir, &mongo.uri()).await;
    let mut pcef = connect_pcef(pcrfd.port()).await;
    pcef.send_message(&build_ccr_i("pgw-1459;1;1459", imsi))
        .await
        .expect("send CCR-I");
    let cca = tokio::time::timeout(Duration::from_secs(10), next_message(&mut pcef))
        .await
        .expect("a CCA within 10 s");
    assert_eq!(cca.result_code(), Some(2001));

    // TS 29.212 clause 4.5.5.7: the session-level QoS-Information carries the
    // APN-AMBR the subscriber is provisioned with.
    let qos = cca
        .find_vendor_avp(gx_avp::QOS_INFORMATION, NEXTGCORE_3GPP_VENDOR_ID)
        .expect("session QoS-Information")
        .parse_grouped()
        .unwrap();
    let ambr = |code| find_avp(&qos, code).and_then(|a| a.as_u32());
    assert_eq!(
        (
            ambr(gx_avp::APN_AGGREGATE_MAX_BITRATE_UL),
            ambr(gx_avp::APN_AGGREGATE_MAX_BITRATE_DL)
        ),
        (Some(7_000_000), Some(13_000_000)),
        "the provisioned APN-AMBR, not the local default (50/100 Mbps)"
    );
    // Clause 4.5.5.9: the default bearer's QCI and ARP are the provisioned ones.
    let bearer = cca
        .find_vendor_avp(gx_avp::DEFAULT_EPS_BEARER_QOS, NEXTGCORE_3GPP_VENDOR_ID)
        .expect("Default-EPS-Bearer-QoS")
        .parse_grouped()
        .unwrap();
    assert_eq!(
        find_avp(&bearer, gx_avp::QOS_CLASS_IDENTIFIER).and_then(|a| a.as_u32()),
        Some(7)
    );
    let arp = find_avp(&bearer, gx_avp::ALLOCATION_RETENTION_PRIORITY)
        .expect("ARP")
        .parse_grouped()
        .unwrap();
    assert_eq!(
        find_avp(&arp, gx_avp::PRIORITY_LEVEL).and_then(|a| a.as_u32()),
        Some(2)
    );
}

/// A configured store that cannot be reached fails startup after the bounded
/// retry, instead of answering every CCR with the default. The URI bounds its own
/// server selection, so this test does not depend on nextgcore-dbi's default bound
/// (#1462).
#[test]
fn pcrfd_refuses_to_start_when_its_store_is_unreachable() {
    let dir = Scratch::new("down");
    let port = free_port();
    let mut child = pcrfd_command(
        &dir,
        "mongodb://127.0.0.1:1/nextgcore?serverSelectionTimeoutMS=500&connectTimeoutMS=500",
        port,
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn pcrfd");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = status.unwrap_or_else(|| {
        panic!("pcrfd still running after 30 s with its configured store unreachable: {stderr}")
    });
    assert!(!status.success(), "with a failure status, not 0");
    assert!(
        stderr.contains(
            "cannot open the subscriber store after 5 attempt(s): the server did not answer"
        ),
        "the failure names the store and the bounded retry: {stderr}"
    );
    // It never served Gx while the store was missing.
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
        "the Diameter listener is not up"
    );
}

/// A SIGTERM while startup waits for the store ends the process promptly and
/// cleanly, rather than at the end of a supervisor's grace period.
#[test]
fn a_sigterm_during_the_store_retry_exits_promptly() {
    let dir = Scratch::new("sigterm");
    let mut child = pcrfd_command(
        &dir,
        "mongodb://127.0.0.1:1/nextgcore?serverSelectionTimeoutMS=500&connectTimeoutMS=500",
        free_port(),
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn pcrfd");
    let child_stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(child_stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("Subscriber store not reachable") {
                let _ = tx.send(());
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("pcrfd reached the store retry");
    let term = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill -TERM");
    assert!(term.success());
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let status = status.expect("pcrfd exits within 2 s of a SIGTERM during the store retry");
    assert!(
        status.success(),
        "a requested shutdown is a clean exit: {status:?}"
    );
}
