//! #1848: the real `nextgcore-seppd` binary refuses to start under the
//! production SBI profile with a lab flag that weakens N32.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run seppd with `flag` under `profile`; `Some(stderr)` if it exited within
/// the deadline, `None` if it was still running (it started).
fn run(flag: &str, profile: &str) -> Option<(bool, String)> {
    let port = nextgcore_sbi::test_support::free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-seppd"))
        .args([
            "-c",
            "/nonexistent/sepp.yaml",
            "--sbi-addr",
            "127.0.0.1",
            "--sbi-port",
            &port.to_string(),
            flag,
        ])
        .env("NEXTGCORE_SBI_PROFILE", profile)
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn seppd");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait") {
            let out = child.wait_with_output().expect("output");
            return Some((
                status.success(),
                String::from_utf8_lossy(&out.stderr).into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// REVERT-VERIFIED: with `refuse_lab_flags_under_production` short-circuited,
/// seppd keeps running under production and this fails.
#[test]
fn production_seppd_refuses_to_start_with_a_lab_flag_1848() {
    for flag in ["--n32-allow-insecure-no-mtls", "--allow-insecure-no-tls"] {
        let (ok, stderr) = run(flag, "production")
            .unwrap_or_else(|| panic!("{flag}: seppd started under production"));
        assert!(!ok, "{flag}: a non-zero exit");
        assert!(
            stderr.contains("lab-only flags") && stderr.contains(flag),
            "{flag}: the refusal names the flag: {stderr}"
        );
    }
}

/// R26 on #1881: an `http` peer SEPP is a cleartext N32 too.
///
/// REVERT-VERIFIED: with the scheme check in `n32_peer_client_tls` removed,
/// seppd keeps running under production and this fails.
#[test]
fn production_seppd_refuses_to_start_with_a_cleartext_peer_1848() {
    let flag = "--peer-sepp=sepp.peer.example=http://127.0.0.1:1";
    let (ok, stderr) =
        run(flag, "production").unwrap_or_else(|| panic!("seppd started with an http peer"));
    assert!(!ok, "a non-zero exit");
    assert!(
        stderr.contains("is not https"),
        "the refusal names it: {stderr}"
    );
}
