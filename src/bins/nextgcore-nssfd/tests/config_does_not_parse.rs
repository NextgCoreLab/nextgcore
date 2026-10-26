//! #1313 review: nssfd refuses to start on a config file that does not parse,
//! rather than falling back to the defaults (its SBI bind among them).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn nssfd_refuses_a_config_that_does_not_parse() {
    let dir = std::env::temp_dir().join(format!("nssfd-badcfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("nssf.yaml");
    std::fs::write(&config, "nssf:\n  sbi: [\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-nssfd"))
        .arg("-c")
        .arg(&config)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nssfd");
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
    let status = status.expect("nssfd exits on a config that does not parse");
    assert!(!status.success(), "with a failure status, not 0");
}
