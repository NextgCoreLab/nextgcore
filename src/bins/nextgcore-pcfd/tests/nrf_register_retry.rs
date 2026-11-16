//! #1482: the real pcfd binary retries a failed first NFRegister (TS 29.510
//! §5.2.2.2.2) and starts its heartbeat (§5.2.2.3.2) only after the NRF has
//! accepted the profile.
//!
//! The NRF is an in-process stub on a loopback listener. It records every
//! NFRegister PUT and heartbeat PATCH in arrival order.
//!
//! REVERT-VERIFIED:
//! - with `register_with_nrf` reading a non-2xx or a transport error as success
//!   again (the `Ok(())` it returned before), both tests fail. The 503 test saw
//!   `[("PUT", 503), ("PATCH", 204), ("PATCH", 204), ...]`: one attempt, then a
//!   heartbeat for a profile the NRF never accepted, the #1482 report. The
//!   down-NRF test fails at "the first NFRegister fails", because nothing
//!   reported the failure;
//! - with `register_or_retry` making only the first attempt, both tests fail
//!   at "a second NFRegister, a 201 and then a heartbeat".

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::SbiServer;

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the stub NRF saw, in order: `("PUT", status answered)` or `("PATCH", 204)`.
type Seen = Arc<Mutex<Vec<(&'static str, u16)>>>;

/// Serve a stub NRF on `listener`. The first `fail_puts` NFRegister PUTs are
/// answered 503; later ones 201.
async fn nrf_on(
    listener: std::net::TcpListener,
    addr: SocketAddr,
    fail_puts: usize,
) -> (SbiServer, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let server = SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let s = s.clone();
            async move {
                let uri = req.header.uri.clone();
                let method = req.header.method.clone();
                let mut seen = s.lock().unwrap();
                match method.as_str() {
                    "PUT" if uri.starts_with("/nnrf-nfm/v1/nf-instances/") => {
                        let puts = seen.iter().filter(|(m, _)| *m == "PUT").count();
                        let status = if puts < fail_puts { 503 } else { 201 };
                        seen.push(("PUT", status));
                        if status == 503 {
                            SbiResponse::with_status(503)
                        } else {
                            SbiResponse::with_status(201).with_body(
                                req.http.content.clone().unwrap_or_else(|| "{}".into()),
                                "application/json",
                            )
                        }
                    }
                    "PATCH" => {
                        seen.push(("PATCH", 204));
                        SbiResponse::with_status(204)
                    }
                    "GET" if uri.starts_with("/nnrf-disc/") => SbiResponse::with_status(200)
                        .with_body(r#"{"nfInstances":[]}"#, "application/json"),
                    _ => SbiResponse::with_status(204),
                }
            }
        })
        .await
        .expect("stub NRF");
    (server, seen)
}

/// A per-test scratch directory, removed on drop; pcfd's stderr is printed when
/// the test fails.
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn log(&self) -> std::path::PathBuf {
        self.0.join("pcfd.log")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "--- pcfd stderr ---\n{}",
                std::fs::read_to_string(self.log()).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_file(self.0.join("pcf.yaml"));
        let _ = std::fs::remove_file(self.log());
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// Spawn pcfd against the NRF on `nrf_port` and return once its SBI listener is
/// bound. On a lost SBI bind (#1497) it respawns on a fresh port; on any other
/// exit it fails with pcfd's stderr.
async fn spawn_pcfd(name: &str, nrf_port: u16) -> (Killed, Scratch) {
    let dir =
        Scratch(std::env::temp_dir().join(format!("pcfd-1482-{name}-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let config = dir.0.join("pcf.yaml");
    for _ in 0..5 {
        let sbi_port = nextgcore_sbi::test_support::free_port();
        std::fs::write(
            &config,
            format!(
                "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {sbi_port}\n    \
                 client:\n      nrf:\n        - uri: http://127.0.0.1:{nrf_port}\n"
            ),
        )
        .unwrap();
        let mut child = Killed(
            Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
                .arg("-c")
                .arg(&config)
                .env("NEXTGCORE_SBI_PROFILE", "dev")
                .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
                .env(
                    "PCF_METRICS_PORT",
                    nextgcore_sbi::test_support::free_port().to_string(),
                )
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(dir.log()).unwrap())
                .spawn()
                .expect("spawn pcfd"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            // Exit status first, then the log: once exited, stderr is complete.
            let exited = child.0.try_wait().unwrap();
            let log = std::fs::read_to_string(dir.log()).unwrap_or_default();
            match exited {
                None if log.contains("SBI HTTP/2 server listening on") => return (child, dir),
                None => {}
                Some(_) if log.contains("Failed to start SBI server") && log.contains("in use") => {
                    break;
                }
                Some(status) => panic!("pcfd exited at startup ({status})"),
            }
            assert!(Instant::now() < deadline, "pcfd listens within 30 s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    panic!("pcfd lost its SBI bind 5 times");
}

/// Wait until `seen` holds a successful PUT followed by a PATCH, then check that
/// no PATCH came before the success.
async fn assert_registered_then_heartbeat(seen: &Seen, min_puts: usize) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let snapshot = seen.lock().unwrap().clone();
        let ok_at = snapshot.iter().position(|e| *e == ("PUT", 201));
        let puts = snapshot.iter().filter(|(m, _)| *m == "PUT").count();
        if let Some(ok_at) = ok_at {
            if snapshot[ok_at..].iter().any(|(m, _)| *m == "PATCH") {
                assert!(
                    puts >= min_puts,
                    "a second NFRegister after the failure: {snapshot:?}"
                );
                assert!(
                    !snapshot[..ok_at].iter().any(|(m, _)| *m == "PATCH"),
                    "no heartbeat before the NRF accepted the profile: {snapshot:?}"
                );
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "a second NFRegister, a 201 and then a heartbeat within 30 s: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The NRF answers the first two NFRegisters 503 (a non-2xx, §5.2.2.2.2 2b).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_2xx_nfregister_is_retried_and_the_heartbeat_follows_the_success() {
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let (_nrf, seen) = nrf_on(listener, addr, 2).await;
    let (_pcfd, _dir) = spawn_pcfd("non2xx", addr.port()).await;
    assert_registered_then_heartbeat(&seen, 3).await;
}

/// The NRF is down when pcfd starts (connections refused) and comes up later on
/// the same address: an NRF restart, or its Service with no ready endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_nfregister_to_an_nrf_that_is_down_is_retried_once_it_is_up() {
    let down = nextgcore_sbi::test_support::down_port();
    let addr = down.addr();
    let (_pcfd, dir) = spawn_pcfd("down", addr.port()).await;
    // Premise: the first attempt has failed before the NRF comes up.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !std::fs::read_to_string(dir.log())
        .unwrap_or_default()
        .contains("NFRegister failed (attempt 1)")
    {
        assert!(Instant::now() < deadline, "the first NFRegister fails");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (_nrf, seen) = nrf_on(down.listen(), addr, 0).await;
    assert_registered_then_heartbeat(&seen, 1).await;
}
