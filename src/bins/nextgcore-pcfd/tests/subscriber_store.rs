//! #1457: the real pcfd binary opens the subscriber store its config names,
//! authorises an SM policy from what the subscriber is provisioned with, and
//! fails fast when that store is unreachable, both at startup and at runtime.
//!
//! Before #1457 pcfd never called `nextgcore_dbi_init*`: the shipped pcf.yaml set
//! `db_uri` and nothing read it, so every session-data read failed "Database not
//! initialized" and every session was authorised the local default (5QI 9,
//! 100/100 Mbps). The in-process unit tests could not see it, because they seed the
//! dbi test mirror rather than a store the binary has to open.
//!
//! The MongoDB tests run a throwaway `mongo:6.0` container published on loopback
//! only. Without docker they are skipped with a note, except where
//! `NEXTGCORE_DOCKER_REQUIRED` is set (CI's Test job), where a missing docker fails
//! them instead -- the same rule as `NEXTGCORE_HELM_REQUIRED`. Each container is
//! labelled with the test process id, and a container whose process is gone (a test
//! binary killed before its Drop ran) is removed by the next run.
//!
//! REVERT-VERIFIED:
//! - with the `open_subscriber_store` call removed from `app::run`,
//!   `pcfd_authorises_the_session_ambr_the_subscriber_is_provisioned_with` reads
//!   "100 Mbps", and `pcfd_refuses_to_start_when_its_store_is_unreachable` times out
//!   with pcfd still running;
//! - with `bounded_db_uri` returning the URI unchanged, the refusal takes 158 s
//!   (past its 30 s deadline), and `a_store_that_goes_down_answers_a_create_in_time`
//!   waits 30 s for its create;
//! - with `off_runtime` running the read inline,
//!   `a_slow_store_read_does_not_stall_the_runtime` waits out the read for `/metrics`.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nextgcore_dbi::mongodb::bson::doc;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};

const DOCKER_REQUIRED_ENV: &str = "NEXTGCORE_DOCKER_REQUIRED";
/// The docker label carrying the owning test process id.
const PID_LABEL: &str = "nextgcore-test-pcfd-1457-pid";

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A per-test scratch directory, removed on drop.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("pcfd-1457-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("pcf.yaml"));
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

    /// Remove containers left by a test process that no longer exists.
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

    /// The URI with no timeout options, as every shipped config writes it.
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

    /// Take the store away under a running pcfd.
    fn kill(&self) {
        let out = docker(&["kill", &self.id]);
        assert!(out.status.success(), "docker kill the store");
    }
}

/// A subscriber whose every value differs from the local default (5QI 9,
/// 100/100 Mbps), with uplink differing from downlink, so neither a default nor a
/// direction swap can pass.
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

struct Pcfd {
    _child: Killed,
    sbi: SbiClient,
    metrics_port: u16,
}

/// Start pcfd on `db_uri` (one runtime worker when `one_worker`, so a blocked
/// worker is the whole runtime) and wait for its SBI listener.
async fn start_pcfd(dir: &Scratch, db_uri: &str, one_worker: bool) -> Pcfd {
    let sbi_port = nextgcore_sbi::test_support::free_port();
    let metrics_port = nextgcore_sbi::test_support::free_port();
    let mut cmd = pcfd_command(dir, db_uri, sbi_port, metrics_port);
    if one_worker {
        cmd.env("TOKIO_WORKER_THREADS", "1");
    }
    let child = Killed(cmd.stderr(Stdio::null()).spawn().expect("spawn pcfd"));
    let pcfd = Pcfd {
        _child: child,
        sbi: SbiClient::new(SbiClientConfig::new("127.0.0.1", sbi_port)),
        metrics_port,
    };
    // Waits on the listener, not a timer: a refused connection is pcfd still starting.
    let deadline = Instant::now() + Duration::from_secs(60);
    while tokio::net::TcpStream::connect(("127.0.0.1", sbi_port))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "pcfd never served the SBI");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    pcfd
}

fn pcfd_command(dir: &Scratch, db_uri: &str, sbi_port: u16, metrics_port: u16) -> Command {
    let config = dir.0.join("pcf.yaml");
    std::fs::write(
        &config,
        format!(
            "db_uri: {db_uri}\npcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        \
             port: {sbi_port}\n"
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"));
    cmd.arg("-c")
        .arg(&config)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env("PCF_METRICS_PORT", metrics_port.to_string())
        .stdout(Stdio::null());
    cmd
}

fn create_body(supi: &str, psi: u8, ipv4: &str) -> serde_json::Value {
    serde_json::json!({
        "supi": supi,
        "pduSessionId": psi,
        "pduSessionType": "IPV4",
        "dnn": "internet",
        "notificationUri": format!("http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/{psi}"),
        "ipv4Address": ipv4,
        "sliceInfo": { "sst": 1 },
        "servingNetwork": { "mcc": "001", "mnc": "01" },
        "suppFeat": "0"
    })
}

/// SM policy create; answers (status, single session rule's uplink, downlink, 5QI).
async fn create(pcfd: &Pcfd, body: &serde_json::Value) -> (u16, String, String, i64) {
    let resp = pcfd
        .sbi
        .post_json("/npcf-smpolicycontrol/v1/sm-policies", body)
        .await
        .expect("SM policy create over HTTP/2");
    let decision: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    let rule = decision["sessRules"]
        .as_object()
        .and_then(|r| r.values().next().cloned())
        .unwrap_or_default();
    (
        resp.status,
        rule["authSessAmbr"]["uplink"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        rule["authSessAmbr"]["downlink"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        rule["authDefQos"]["5qi"].as_i64().unwrap_or(-1),
    )
}

/// `GET /metrics` over plain HTTP/1.1; answers the time it took.
async fn scrape(port: u16) -> Duration {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let started = Instant::now();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect /metrics");
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: pcf\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    s.read_to_end(&mut body).await.unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("pcf_policy_associations"),
        "a PCF exposition"
    );
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcfd_authorises_the_session_ambr_the_subscriber_is_provisioned_with() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    mongo.provision(subscriber("001010000001457"));
    let dir = Scratch::new("store");
    let pcfd = start_pcfd(&dir, &mongo.uri(), false).await;
    let (status, ul, dl, qi) = create(
        &pcfd,
        &create_body("imsi-001010000001457", 5, "10.45.14.57"),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!((ul.as_str(), dl.as_str(), qi), ("7 Mbps", "13 Mbps", 7));
}

/// The store dies under a running pcfd. A create must still be answered inside the
/// SMF's 3 s Npcf budget (`nextgcore-smfd` policy.rs `with_request_timeout`), so
/// the association the PCF keeps is one the SMF holds too. The URI is the shipped
/// shape, with no timeout options.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_that_goes_down_answers_a_create_in_time() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    mongo.provision(subscriber("001010000014571"));
    let dir = Scratch::new("down-runtime");
    let pcfd = start_pcfd(&dir, &mongo.uri(), false).await;
    let (status, ul, ..) = create(
        &pcfd,
        &create_body("imsi-001010000014571", 5, "10.45.14.71"),
    )
    .await;
    assert_eq!((status, ul.as_str()), (201, "7 Mbps"), "the store is live");

    mongo.kill();
    let started = Instant::now();
    let (status, ul, ..) = create(
        &pcfd,
        &create_body("imsi-001010000014571", 6, "10.45.14.72"),
    )
    .await;
    let took = started.elapsed();
    assert_eq!(status, 201, "the documented fallback decision");
    assert_eq!(ul, "100 Mbps", "the store really was down");
    assert!(
        took < Duration::from_secs(3),
        "answered in {took:?}, past the SMF's 3 s: the SMF would have given up on an \
         association the PCF keeps"
    );
}

/// A slow store read must not hold the runtime. One worker, and a URI that sets its
/// own 6 s selection timeout (kept as written): while a create waits out that read
/// against a dead store, `/metrics` on the same process still answers promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_store_read_does_not_stall_the_runtime() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    mongo.provision(subscriber("001010000014572"));
    let dir = Scratch::new("stall");
    let uri = format!("{}?serverSelectionTimeoutMS=6000", mongo.uri());
    let pcfd = start_pcfd(&dir, &uri, true).await;
    assert!(scrape(pcfd.metrics_port).await < Duration::from_secs(1));

    mongo.kill();
    let body = create_body("imsi-001010000014572", 5, "10.45.14.73");
    let slow = async {
        let started = Instant::now();
        let _ = create(&pcfd, &body).await;
        started.elapsed()
    };
    let probe = async {
        // Let the create reach its read first.
        tokio::time::sleep(Duration::from_millis(500)).await;
        scrape(pcfd.metrics_port).await
    };
    let (create_took, scrape_took) = tokio::join!(slow, probe);
    assert!(
        create_took > Duration::from_secs(3),
        "the create really waited on the store ({create_took:?}), so the probe overlapped it"
    );
    assert!(
        scrape_took < Duration::from_secs(1),
        "/metrics took {scrape_took:?} while a store read was in flight: the read held the \
         runtime worker"
    );
}

/// A configured store that cannot be reached fails startup, after the bounded
/// retry, instead of serving the default to every subscriber. The URI is the shipped
/// shape, with no timeout options: each attempt must still be short, so the refusal
/// lands well before a k8s liveness probe (about 75 s) would kill the pod.
#[test]
fn pcfd_refuses_to_start_when_its_store_is_unreachable() {
    let down = nextgcore_sbi::test_support::free_port();
    let dir = Scratch::new("down-startup");
    let mut child = pcfd_command(
        &dir,
        &format!("mongodb://127.0.0.1:{down}/nextgcore"),
        nextgcore_sbi::test_support::free_port(),
        nextgcore_sbi::test_support::free_port(),
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn pcfd");
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
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
    let status = status.expect("pcfd exits within 30 s when its configured store is unreachable");
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

/// A SIGTERM while startup waits for the store ends the process promptly and
/// cleanly, rather than at the end of a supervisor's grace period.
#[test]
fn a_sigterm_during_the_store_retry_exits_promptly() {
    let down = nextgcore_sbi::test_support::free_port();
    let dir = Scratch::new("sigterm");
    let mut child = pcfd_command(
        &dir,
        &format!("mongodb://127.0.0.1:{down}/nextgcore"),
        nextgcore_sbi::test_support::free_port(),
        nextgcore_sbi::test_support::free_port(),
    )
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn pcfd");
    let child_stderr = child.stderr.take().unwrap();
    // Wait on the retry itself: the first "retrying" line means pcfd is in the
    // backoff, which is where a SIGTERM used to be ignored.
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
        .expect("pcfd reached the store retry");
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
    let status = status.expect("pcfd exits within 2 s of a SIGTERM during the store retry");
    assert!(
        status.success(),
        "a requested shutdown is a clean exit: {status:?}"
    );
}
