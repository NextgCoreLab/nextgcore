//! #1457: the real pcfd binary opens the subscriber store its config names, and
//! authorises an SM policy from what the subscriber is provisioned with.
//!
//! Before #1457 pcfd never called `nextgcore_dbi_init*`: the shipped pcf.yaml set
//! `db_uri` and nothing read it, so every session-data read failed "Database not
//! initialized" and every session was authorised the local default (5QI 9,
//! 100/100 Mbps). The in-process unit tests could not see it, because they seed the
//! dbi test mirror rather than a store the binary has to open.
//!
//! The MongoDB test runs a throwaway `mongo:6.0` container published on loopback
//! only. Without docker it is skipped with a note, except where
//! `NEXTGCORE_DOCKER_REQUIRED` is set (CI's Test job), where a missing docker fails
//! it instead -- the same rule as `NEXTGCORE_HELM_REQUIRED`.
//!
//! REVERT-VERIFIED: with the `open_subscriber_store` call removed from `app::run`,
//! `pcfd_authorises_the_session_ambr_the_subscriber_is_provisioned_with` reads
//! "100 Mbps" for both directions, and `pcfd_refuses_to_start_when_its_store_is_unreachable`
//! times out with pcfd still running.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nextgcore_dbi::mongodb::bson::doc;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};

const DOCKER_REQUIRED_ENV: &str = "NEXTGCORE_DOCKER_REQUIRED";

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A `mongo:6.0` container on a loopback-only ephemeral port, removed on drop.
struct Mongo {
    id: String,
    port: u16,
}

impl Drop for Mongo {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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
        let out = Command::new("docker")
            .args(["run", "-d", "--rm", "-p", "127.0.0.1::27017", "mongo:6.0"])
            .output()
            .expect("docker run");
        assert!(
            out.status.success(),
            "docker run mongo:6.0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let mut mongo = Mongo { id, port: 0 };
        let out = Command::new("docker")
            .args(["port", &mongo.id, "27017/tcp"])
            .output()
            .expect("docker port");
        let mapping = String::from_utf8(out.stdout).unwrap();
        mongo.port = mapping
            .lines()
            .find_map(|l| l.trim().strip_prefix("127.0.0.1:"))
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("a loopback port mapping: {mapping:?}"));
        Some(mongo)
    }

    fn uri(&self) -> String {
        format!("mongodb://127.0.0.1:{}/nextgcore", self.port)
    }

    /// Wait until the server answers a ping, then insert `document` into
    /// `nextgcore.subscribers`, the collection pcfd reads.
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
}

fn spawn_pcfd(dir: &std::path::Path, db_uri: &str, sbi_port: u16, stderr: Stdio) -> Child {
    std::fs::create_dir_all(dir).unwrap();
    let config = dir.join("pcf.yaml");
    std::fs::write(
        &config,
        format!(
            "db_uri: {db_uri}\npcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        \
             port: {sbi_port}\n"
        ),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
        .arg("-c")
        .arg(&config)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env(
            "PCF_METRICS_PORT",
            nextgcore_sbi::test_support::free_port().to_string(),
        )
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn pcfd")
}

/// The provisioned subscriber: every value differs from the local default (5QI 9,
/// 100/100 Mbps), and uplink differs from downlink, so neither a default nor a
/// direction swap can pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcfd_authorises_the_session_ambr_the_subscriber_is_provisioned_with() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    let supi = "imsi-001010000001457";
    mongo.provision(doc! {
        "imsi": "001010000001457",
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
    });

    let sbi_port = nextgcore_sbi::test_support::free_port();
    let dir = std::env::temp_dir().join(format!("pcfd-1457-store-{}", std::process::id()));
    let _pcfd = Killed(spawn_pcfd(&dir, &mongo.uri(), sbi_port, Stdio::null()));

    let client = SbiClient::new(SbiClientConfig::new("127.0.0.1", sbi_port));
    let create = serde_json::json!({
        "supi": supi,
        "pduSessionId": 5,
        "pduSessionType": "IPV4",
        "dnn": "internet",
        "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/5",
        "ipv4Address": "10.45.14.57",
        "sliceInfo": { "sst": 1 },
        "servingNetwork": { "mcc": "001", "mnc": "01" },
        "suppFeat": "0"
    });
    // Waits on the listener, not a timer: a refused connection is pcfd still starting.
    let deadline = Instant::now() + Duration::from_secs(60);
    let resp = loop {
        match client
            .post_json("/npcf-smpolicycontrol/v1/sm-policies", &create)
            .await
        {
            Ok(r) => break r,
            Err(e) => {
                assert!(Instant::now() < deadline, "pcfd never served the SBI: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(
        resp.status, 201,
        "SM policy create: {:?}",
        resp.http.content
    );
    let decision: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().expect("a decision")).unwrap();
    let rules = decision["sessRules"]
        .as_object()
        .unwrap_or_else(|| panic!("sessRules: {decision}"));
    assert_eq!(rules.len(), 1, "one session rule: {decision}");
    let rule = rules.values().next().unwrap();
    assert_eq!(rule["authSessAmbr"]["uplink"], "7 Mbps", "{decision}");
    assert_eq!(rule["authSessAmbr"]["downlink"], "13 Mbps", "{decision}");
    assert_eq!(rule["authDefQos"]["5qi"], 7, "{decision}");
}

/// A configured store that cannot be reached fails startup, after the bounded
/// retry, instead of serving the default to every subscriber.
#[test]
fn pcfd_refuses_to_start_when_its_store_is_unreachable() {
    // Nothing listens on a free port; a short selection timeout keeps each of the
    // bounded attempts quick.
    let down = nextgcore_sbi::test_support::free_port();
    let db_uri = format!(
        "mongodb://127.0.0.1:{down}/nextgcore?serverSelectionTimeoutMS=200&connectTimeoutMS=200"
    );
    let dir = std::env::temp_dir().join(format!("pcfd-1457-down-{}", std::process::id()));
    let mut child = spawn_pcfd(
        &dir,
        &db_uri,
        nextgcore_sbi::test_support::free_port(),
        Stdio::piped(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
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
    let status = status.expect("pcfd exits when its configured store is unreachable");
    assert!(!status.success(), "with a failure status, not 0");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains(
            "cannot open the subscriber store after 5 attempt(s): the server did not answer"
        ),
        "the failure names the store and the bounded retry: {stderr}"
    );
}
