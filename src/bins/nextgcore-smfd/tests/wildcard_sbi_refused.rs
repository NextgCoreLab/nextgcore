//! #1322: smfd refuses to start on a wildcard SBI bind with nothing reachable to
//! advertise (before any socket is bound), rather than hand peers 0.0.0.0 or a
//! loopback URI in its callback URIs and NFProfile.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn exits_with_failure(config_text: &str, envs: &[(&str, &str)], tag: &str) -> bool {
    let dir = std::env::temp_dir().join(format!("smfd-1322-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("smf.yaml");
    std::fs::write(&config, config_text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-smfd"))
        .arg("-c")
        .arg(&config)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env_remove("NEXTGCORE_SBI_ADVERTISE")
        .env_remove("SMF_SBI_ADVERTISE_URI")
        .envs(envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn smfd");
    let deadline = Instant::now() + Duration::from_secs(20);
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
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
    }
    status.is_some_and(|s| !s.success()) && stderr.contains("refusing to start")
}

#[test]
fn smfd_refuses_a_wildcard_sbi_bind_with_nothing_to_advertise() {
    // Port 1: were the check gone, the bind would fail (unprivileged), so no
    // wildcard is ever bound; the stderr says which check refused it.
    let wildcard = "smf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 1\n";
    assert!(exits_with_failure(wildcard, &[], "plain"));
    assert!(
        exits_with_failure(
            wildcard,
            &[("SMF_SBI_ADVERTISE_URI", "http://0.0.0.0:7777")],
            "uri"
        ),
        "nor a wildcard SMF_SBI_ADVERTISE_URI"
    );
}
