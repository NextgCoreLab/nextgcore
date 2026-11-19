//! #1849: the real `nextgcore-pind` binary refuses to start under the
//! production SBI profile with --trust-caller-supi-header.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run pind with `flag` under `profile`; `Some(stderr)` if it exited within
/// the deadline, `None` if it was still running (it started).
fn run(flag: &str, profile: &str) -> Option<(bool, String)> {
    let port = nextgcore_sbi::test_support::free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-pind"))
        .args([
            "-c",
            "/nonexistent/pin.yaml",
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
        .expect("spawn pind");
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

/// REVERT-VERIFIED: with `refuse_trusted_supi_header_under_production`
/// short-circuited, pind keeps running under production and this fails.
#[test]
fn production_pind_refuses_to_start_with_the_trusted_supi_header_1849() {
    let flag = "--trust-caller-supi-header";
    let (ok, stderr) =
        run(flag, "production").unwrap_or_else(|| panic!("{flag}: pind started under production"));
    assert!(!ok, "a non-zero exit");
    assert!(
        stderr.contains("lab-only") && stderr.contains(flag),
        "the refusal names the flag: {stderr}"
    );
}
