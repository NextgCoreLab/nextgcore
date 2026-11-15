//! #1402: `pcf.policy.session_ambr_cap` at pcfd start-up, through the real binary.
//! An unknown value fails start-up naming the setting; a known one is logged as in
//! force.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(tag: &str, policy: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pcfd-sessambrcap-{tag}-{}-{}.yaml",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        format!(
            "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {}\n{policy}",
            free_port()
        ),
    )
    .unwrap();
    path
}

fn spawn(config: &std::path::Path) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
            .arg("-c")
            .arg(config)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env("RUST_LOG", "info")
            .env("PCF_METRICS_PORT", free_port().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pcfd"),
    )
}

#[test]
fn an_unknown_session_ambr_cap_fails_startup() {
    let cfg = config("unknown", "  policy:\n    session_ambr_cap: ceiling\n");
    let mut child = spawn(&cfg);
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "pcfd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(!status.success(), "start-up must fail: {err}");
    assert!(
        err.contains("pcf.policy.session_ambr_cap") && err.contains("ceiling"),
        "the failure names the setting and the value: {err}"
    );
}

#[test]
fn a_known_session_ambr_cap_is_logged_in_force() {
    for (value, expect) in [
        ("none", "pcf.policy.session_ambr_cap = none"),
        ("subscribed", "pcf.policy.session_ambr_cap = subscribed"),
        ("", "pcf.policy.session_ambr_cap = subscribed"),
    ] {
        let policy = if value.is_empty() {
            String::new()
        } else {
            format!("  policy:\n    session_ambr_cap: {value}\n")
        };
        let cfg = config(if value.is_empty() { "absent" } else { value }, &policy);
        let mut child = spawn(&cfg);
        let stderr = child.0.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut seen = Vec::new();
        let found = loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    let hit = line.contains(expect);
                    seen.push(line);
                    if hit {
                        break true;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break false,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                break false;
            }
        };
        assert!(found, "{value:?}: expected {expect:?} in {seen:#?}");
        drop(child);
    }
}
