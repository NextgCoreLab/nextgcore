//! #1402: `pcf.policy.session_ambr_cap` at pcfd start-up, through the real binary.
//! An unknown value fails start-up naming the setting; a known one is logged as in
//! force.
//!
//! #1521: these spawn pcfd on probed ports without waiting for a listener, and
//! cannot lose to the #1497 bind race. Everything they assert is in stderr
//! BEFORE pcfd binds anything: `app::run` logs the setting in force, and fails
//! on an unknown one, before the boot restoration and long before the SBI and
//! metrics listeners start. A port lost afterwards ends the run after the
//! asserted lines are out.

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
    spawn_with(config, &[])
}

fn spawn_with(config: &std::path::Path, extra: &[&std::ffi::OsStr]) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
            .arg("-c")
            .arg(config)
            .args(extra)
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

/// #1402 review M1: the value logged is the one IN FORCE (read back from the global
/// the paths read), and it is in force BEFORE the durable-state restoration, whose
/// demo-cap restore re-authorises restored sessions.
///
/// REVERT-VERIFIED: with `session_ambr_cap::set(..)` deleted from `run()`, `none`
/// logs `subscribed`; with the set and its log moved after the boot restoration,
/// the line comes after "PCF durable state".
#[test]
fn a_known_session_ambr_cap_is_in_force_before_the_boot_restoration() {
    const DURABLE: &str = "PCF durable state";
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
        let tag = if value.is_empty() { "absent" } else { value };
        let cfg = config(tag, &policy);
        let state = std::env::temp_dir().join(format!(
            "pcfd-sessambrcap-{tag}-{}-{}.json",
            std::process::id(),
            free_port()
        ));
        let _ = std::fs::remove_file(&state);
        let mut child = spawn_with(
            &cfg,
            &[std::ffi::OsStr::new("--state-file"), state.as_os_str()],
        );
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
        let mut seen: Vec<String> = Vec::new();
        let (mut cap_at, mut durable_at) = (None, None);
        while cap_at.is_none() || durable_at.is_none() {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => {
                    if cap_at.is_none() && line.contains("pcf.policy.session_ambr_cap = ") {
                        cap_at = Some(seen.len());
                    }
                    if durable_at.is_none() && line.contains(DURABLE) {
                        durable_at = Some(seen.len());
                    }
                    seen.push(line);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        let (Some(cap_at), Some(durable_at)) = (cap_at, durable_at) else {
            panic!("{value:?}: both the cap line and {DURABLE:?} expected in {seen:#?}");
        };
        assert!(
            seen[cap_at].contains(expect),
            "{value:?}: the value in force is logged, expected {expect:?}: {}",
            seen[cap_at]
        );
        assert!(
            cap_at < durable_at,
            "{value:?}: the setting is in force before the boot restoration: {seen:#?}"
        );
        drop(child);
        let _ = std::fs::remove_file(&state);
    }
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
