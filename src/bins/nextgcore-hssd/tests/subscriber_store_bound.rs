//! #1462: the real hssd binary refuses to start promptly when the subscriber store
//! its config names is unreachable, with the shipped URI shape (no timeout options).
//!
//! Before #1462 each of the five attempts waited the MongoDB driver's 30 s server
//! selection default, so hssd gave up after about 158 s, past a k8s liveness probe:
//! the operator saw probe restarts instead of the store error.
//!
//! REVERT-VERIFIED: with `bound_store_timeouts` not called from
//! `nextgcore_mongoc_init`, `hssd_refuses_an_unreachable_store_within_30_s` times out
//! with hssd still retrying.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn hssd_refuses_an_unreachable_store_within_30_s() {
    let dir = std::env::temp_dir().join(format!("hssd-1462-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("hss.yaml");
    // The shipped hss.yaml shape: a top-level db_uri with no options. Port 1 has
    // nothing listening on loopback, so every server selection fails.
    std::fs::write(
        &config,
        "db_uri: mongodb://127.0.0.1:1/nextgcore\nhss: {}\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-hssd"))
        .arg("-c")
        .arg(&config)
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hssd");
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
    let took = started.elapsed();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_dir(&dir);
    let status = status.unwrap_or_else(|| {
        panic!("hssd still running after 30 s against an unreachable store: {stderr}")
    });
    assert!(!status.success(), "with a failure status, not 0");
    assert!(
        stderr.contains("cannot open the subscriber store after 5 attempt(s)"),
        "the failure names the store and the bounded retry: {stderr}"
    );
    // Five bounded attempts and four 2 s backoffs: the retry really ran.
    assert!(took >= Duration::from_secs(8), "refused in {took:?}");
}
