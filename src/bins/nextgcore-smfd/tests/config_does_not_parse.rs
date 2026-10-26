//! #1313 review: smfd refuses to start on a config file that does not parse,
//! rather than falling back to the defaults (its SBI bind among them).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn smfd_refuses_a_config_that_does_not_parse() {
    let dir = std::env::temp_dir().join(format!("smfd-badcfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("smf.yaml");
    std::fs::write(&config, "smf:\n  sbi: [\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-smfd"))
        .arg("-c")
        .arg(&config)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
    let status = status.expect("smfd exits on a config that does not parse");
    assert!(!status.success(), "with a failure status, not 0");
}
