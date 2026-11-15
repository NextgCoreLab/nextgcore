//! #1462: a real udrd whose subscriber store goes away answers each Nudr read
//! within the consumer's budget, with the shipped URI shape (no timeout options).
//!
//! Before #1462 every read against a store that had gone down waited the MongoDB
//! driver's 30 s server-selection default. One registration makes several UDR
//! reads (authentication subscription, am-data, SMF selection, ...), and the UE
//! gives the whole registration T3510 = 15 s (TS 24.501 Table 10.2.1), so a single
//! 30 s read already loses the UE; pcfd's consumer, the SMF, gives up after 3 s.
//!
//! The test runs a throwaway `mongo:6.0` container published on loopback only.
//! Without docker it is skipped with a note, except where
//! `NEXTGCORE_DOCKER_REQUIRED` is set (CI's Test job), where a missing docker fails
//! it instead. Containers are labelled with the test process id, and one whose
//! process is gone is removed by the next run.
//!
//! REVERT-VERIFIED: with `bound_store_timeouts` not called from
//! `nextgcore_mongoc_init`, `a_store_that_goes_down_answers_a_read_in_time` waits
//! about 30 s for its read, and the test client gives up on it with no answer.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nextgcore_dbi::mongodb::bson::doc;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};

const DOCKER_REQUIRED_ENV: &str = "NEXTGCORE_DOCKER_REQUIRED";
const PID_LABEL: &str = "nextgcore-test-udrd-1462-pid";

/// A K no default could produce, so a 200 carrying it came from the store.
const K: &str = "14621462146214621462146214621462";

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

    /// The URI with no timeout options, as every shipped config writes it.
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

    fn kill(&self) {
        let out = docker(&["kill", &self.id]);
        assert!(out.status.success(), "docker kill the store");
    }
}

/// GET the authentication subscription; answers (status, encPermanentKey).
async fn get_auth(sbi: &SbiClient, supi: &str) -> (u16, String) {
    let resp = sbi
        .get(&format!(
            "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
        ))
        .await
        .unwrap_or_else(|e| {
            panic!("no Nudr answer (the client gives up after its own 30 s): {e:?}")
        });
    let body: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    (
        resp.status,
        body["encPermanentKey"].as_str().unwrap_or("").to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_that_goes_down_answers_a_read_in_time() {
    let Some(mongo) = Mongo::start() else {
        return;
    };
    let imsi = "001010000001462";
    mongo.provision(doc! {
        "imsi": imsi,
        "security": { "k": K, "opc": "e8ed289deba952e4283b54e88e6183ca", "amf": "8000", "sqn": 64_i64 },
    });

    let dir = std::env::temp_dir().join(format!("udrd-1462-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("udr.yaml");
    let port = nextgcore_sbi::test_support::free_port();
    std::fs::write(
        &config,
        format!(
            "db_uri: {}\nudr:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {port}\n",
            mongo.uri()
        ),
    )
    .unwrap();
    let _udrd = Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-udrd"))
            .arg("-c")
            .arg(&config)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env_remove("NEXTGCORE_SBI_ADVERTISE")
            .env_remove("DB_URI")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn udrd"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "udrd never served the SBI");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sbi = SbiClient::new(SbiClientConfig::new("127.0.0.1", port));
    let supi = format!("imsi-{imsi}");

    let (status, k) = get_auth(&sbi, &supi).await;
    assert_eq!(
        (status, k.as_str()),
        (200, K),
        "the store is live and was read"
    );

    mongo.kill();
    let started = Instant::now();
    let (status, _) = get_auth(&sbi, &supi).await;
    let took = started.elapsed();
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_dir(&dir);
    assert_ne!(status, 200, "the store really was down");
    assert!(
        took < Duration::from_secs(3),
        "answered in {took:?}: past the 3 s an SBI consumer here waits"
    );
}
