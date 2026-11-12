//! nextgsim#458 / #464: the `demo:` block at amfd start-up, through the real
//! binary. An unknown key or mode fails start-up, with no fallback. An active
//! `d440c-nwdaf-paging` logs the banner and the effective paging strategy and
//! exports `nextg_demo_enabled`. The kill switch and an absent block leave the
//! process unchanged.

use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_tcp() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(tag: &str, demo: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "amfd-demo-{tag}-{}-{}.yaml",
        std::process::id(),
        free_tcp()
    ));
    std::fs::write(
        &path,
        format!(
            "amf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {}\n  \
             ngap:\n    server:\n      - address: 127.0.0.1\n        port: {}\n{demo}",
            free_tcp(),
            free_udp()
        ),
    )
    .unwrap();
    path
}

fn spawn(config: &std::path::Path, metrics_port: u16) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-amfd"))
            .arg("-c")
            .arg(config)
            .env_remove("AMF_SBI_ADDR")
            .env_remove("AMF_SBI_PORT")
            .env_remove("NEXTGCORE_SBI_ADVERTISE")
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env("RUST_LOG", "info")
            .env("AMF_METRICS_PORT", metrics_port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn amfd"),
    )
}

/// Run to exit (start-up failure), returning (success, stderr).
fn run_to_exit(config: &std::path::Path) -> (bool, String) {
    let mut child = spawn(config, free_tcp());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut err = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            return (status.success(), err);
        }
        assert!(Instant::now() < deadline, "amfd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `/metrics` body once it answers.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
fn scrape(port: u16, within: Duration) -> Option<String> {
    use std::io::Write;
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .ok()?;
            let mut body = String::new();
            s.read_to_string(&mut body).ok()?;
            return Some(body);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Kill a running amfd and return its stderr.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
fn stop(mut child: Killed) -> String {
    let _ = child.0.kill();
    let _ = child.0.wait();
    let mut err = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    err
}

fn block(mode: &str) -> String {
    format!("demo:\n  enabled: true\n  d440c-nwdaf-paging:\n    enabled: true\n    mode: {mode}\n")
}

#[test]
fn an_unknown_demo_key_fails_startup() {
    let cfg = config(
        "unknown-key",
        "demo:\n  enabled: true\n  d999-nope:\n    enabled: true\n    mode: on\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// Without the feature, the demo's own key is unknown too: a shipped default
/// image refuses the block rather than ignoring it.
#[cfg(not(feature = "demo-d440c-nwdaf-paging"))]
#[test]
fn the_demo_key_fails_startup_in_a_build_without_its_feature() {
    let (ok, err) = run_to_exit(&config("no-feature", &block("nwdaf-mobility")));
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// The ticket's invalid-mode arm, and `ran-recommendation` until #462's amfd
/// demo lands: no fallback.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
#[test]
fn an_unknown_mode_fails_startup_with_unknown_mode() {
    for mode in ["bogus", "ran-recommendation"] {
        let (ok, err) = run_to_exit(&config(mode, &block(mode)));
        assert!(!ok, "{mode}: start-up must fail");
        assert!(
            err.contains(&format!(
                r#"UnknownMode {{ demo: "d440c-nwdaf-paging", mode: "{mode}""#
            )),
            "{mode}: {err}"
        );
    }
}

/// Mode `nwdaf-mobility`: the banner, the forced strategy line and the metric.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
#[test]
fn mode_nwdaf_mobility_logs_the_banner_and_the_strategy_and_exports_the_metric() {
    let port = free_tcp();
    let child = spawn(&config("on", &block("nwdaf-mobility")), port);
    let body = scrape(port, Duration::from_secs(30)).expect("/metrics");
    assert!(
        body.contains(r#"nextg_demo_enabled{demo="d440c-nwdaf-paging",mode="nwdaf-mobility"} 1"#),
        "{body}"
    );
    assert!(
        body.contains("amf_paging_nwdaf_hints_total"),
        "the forced strategy's counter is rendered: {body}"
    );
    let err = stop(child);
    assert!(
        err.contains("DEMO MODE ACTIVE: d440c-nwdaf-paging=nwdaf-mobility"),
        "{err}"
    );
    assert!(
        err.contains(
            "[demo:d440c-nwdaf-paging] Paging strategy: nwdaf-mobility (mode nwdaf-mobility \
             supersedes amf.paging.strategy: registration-area)"
        ),
        "{err}"
    );
}

/// The demo-off arms: the kill switch off with the key enabled, and no block at
/// all. No banner, no `[demo:` line, no `nextg_demo_enabled`, and the default
/// strategy.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
#[test]
fn the_kill_switch_and_an_absent_block_are_demo_off() {
    for (tag, demo) in [
        (
            "killswitch",
            "demo:\n  enabled: false\n  d440c-nwdaf-paging:\n    enabled: true\n    mode: nwdaf-mobility\n",
        ),
        ("absent", ""),
    ] {
        let port = free_tcp();
        let child = spawn(&config(tag, demo), port);
        let body = scrape(port, Duration::from_secs(30)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(!body.contains("amf_paging_nwdaf_hints_total"), "{tag}: {body}");
        let err = stop(child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
        assert!(err.contains("Paging strategy: registration-area"), "{tag}: {err}");
    }
}
