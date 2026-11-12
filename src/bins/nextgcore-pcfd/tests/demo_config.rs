//! nextgsim#458 / #465: the `demo:` block at pcfd start-up, through the real
//! binary. An unknown key or mode fails start-up with no fallback; an active
//! `d441a-congestion-loop` needs its `pcf.congestion_loop` block, logs the banner
//! and exports `nextg_demo_enabled`; the demo-off shapes leave pcfd unchanged.

use std::io::Read;
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

#[allow(dead_code)]
const LOOP_BLOCK: &str = "  congestion_loop:\n    cells:\n      - {mcc: '999', mnc: '70', nr_cell_id: '000000010'}\n    best_effort_supis: [imsi-999700000000002]\n";

fn config(tag: &str, pcf_extra: &str, demo: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pcfd-demo-{tag}-{}-{}.yaml",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        format!(
            "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {}\n{pcf_extra}{demo}",
            free_port()
        ),
    )
    .unwrap();
    path
}

fn spawn(config: &std::path::Path, metrics_port: u16) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
            .arg("-c")
            .arg(config)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env("RUST_LOG", "info")
            .env("PCF_METRICS_PORT", metrics_port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pcfd"),
    )
}

/// Run to exit (start-up failure), returning (success, stderr).
fn run_to_exit(config: &std::path::Path) -> (bool, String) {
    let mut child = spawn(config, free_port());
    let deadline = Instant::now() + Duration::from_secs(20);
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
        assert!(Instant::now() < deadline, "pcfd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn stderr_of(child: &mut Killed) -> String {
    let _ = child.0.kill();
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

#[test]
fn an_unknown_demo_key_fails_startup() {
    let cfg = config(
        "unknown-key",
        "",
        "demo:\n  enabled: true\n  d999-nope:\n    enabled: true\n    mode: on\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

#[cfg(not(feature = "demo-d441a-congestion-loop"))]
#[test]
fn the_d441a_key_fails_startup_in_a_build_without_its_feature() {
    let cfg = config(
        "no-feature",
        "",
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: statistics\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// Invalid-mode criterion: `mode: bogus` fails pcfd start-up with
/// `UnknownMode { demo: "d441a-congestion-loop", mode: "bogus" }`.
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn mode_bogus_fails_startup_with_unknown_mode() {
    let cfg = config(
        "bogus",
        LOOP_BLOCK,
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: bogus\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "no fallback: start-up must fail");
    assert!(
        err.contains(r#"UnknownMode { demo: "d441a-congestion-loop", mode: "bogus""#),
        "{err}"
    );
}

/// An active demo with no `pcf.congestion_loop` block has no area or guardrails
/// to throttle with: start-up fails rather than guessing.
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn an_active_demo_without_its_block_fails_startup() {
    let cfg = config(
        "no-block",
        "",
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: statistics\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok);
    assert!(err.contains("pcf.congestion_loop is absent"), "{err}");
}

/// Each mode: the banner, the controller's start line, the metric.
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn each_mode_logs_the_banner_and_exports_the_metric() {
    for mode in ["statistics", "prediction", "no-loop"] {
        let cfg = config(
            &format!("on-{mode}"),
            LOOP_BLOCK,
            &format!(
                "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: {mode}\n"
            ),
        );
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(
            body.contains(&format!(
                r#"nextg_demo_enabled{{demo="d441a-congestion-loop",mode="{mode}"}} 1"#
            )),
            "{body}"
        );
        let err = stderr_of(&mut child);
        assert!(
            err.contains(&format!("DEMO MODE ACTIVE: d441a-congestion-loop={mode}")),
            "{err}"
        );
        assert!(
            err.contains(&format!(
                "[demo:d441a-congestion-loop] congestion-loop: on (mode={mode};"
            )),
            "{err}"
        );
    }
}

/// Demo-off criterion: no block, `demo.enabled: false`, and the kill switch off
/// with the key on. No banner, no `[demo:` line, no `nextg_demo_enabled`, no
/// controller (the block is ignored).
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn the_demo_off_shapes_run_no_controller() {
    for (tag, demo) in [
        ("absent", ""),
        ("off", "demo:\n  enabled: false\n"),
        (
            "killswitch",
            "demo:\n  enabled: false\n  d441a-congestion-loop:\n    enabled: true\n    mode: statistics\n",
        ),
    ] {
        let cfg = config(tag, LOOP_BLOCK, demo);
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        let err = stderr_of(&mut child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
        assert!(!err.contains("congestion-loop"), "{tag}: {err}");
    }
}
