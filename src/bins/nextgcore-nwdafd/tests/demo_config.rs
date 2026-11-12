//! nextgsim#458 / #466: the `demo:` block at nwdafd start-up, through the real
//! binary. An unknown key or mode fails start-up with no fallback; an active
//! `d441c-amf-mobility` logs the banner and exports `nextg_demo_enabled`; the kill
//! switch and an absent block leave the process unchanged.

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

fn config(tag: &str, demo: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nwdafd-demo-{tag}-{}-{}.yaml",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        format!(
            "nwdaf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {}\n{demo}",
            free_port()
        ),
    )
    .unwrap();
    path
}

fn spawn(config: &std::path::Path, metrics_port: u16) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-nwdafd"))
            .arg("-c")
            .arg(config)
            // No NRF: registration and the AMF subscription fail and retry, which
            // is all this test needs.
            .args(["--nrf-uri", "http://127.0.0.1:1"])
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env("RUST_LOG", "info")
            .env("NWDAF_METRICS_PORT", metrics_port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nwdafd"),
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
        assert!(Instant::now() < deadline, "nwdafd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(any(feature = "amf-mobility", feature = "demo-d441e-model-retrain"))]
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

/// Without the `amf-mobility` feature, the demo's own key is unknown too.
#[cfg(not(feature = "amf-mobility"))]
#[test]
fn the_demo_key_fails_startup_in_a_build_without_its_feature() {
    let cfg = config(
        "no-feature",
        "demo:\n  enabled: true\n  d441c-amf-mobility:\n    enabled: true\n    mode: on\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

#[cfg(feature = "amf-mobility")]
#[test]
fn mode_bogus_fails_startup_with_unknown_mode() {
    let cfg = config(
        "bogus",
        "demo:\n  enabled: true\n  d441c-amf-mobility:\n    enabled: true\n    mode: bogus\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "no fallback: start-up must fail");
    assert!(
        err.contains(r#"UnknownMode { demo: "d441c-amf-mobility", mode: "bogus""#),
        "{err}"
    );
}

/// Mode `on`: the banner, the prefixed mode line and the metric series.
#[cfg(feature = "amf-mobility")]
#[test]
fn mode_on_logs_the_banner_and_exports_the_metric() {
    let cfg = config(
        "on",
        "demo:\n  enabled: true\n  d441c-amf-mobility:\n    enabled: true\n    mode: on\n",
    );
    let port = free_port();
    let mut child = spawn(&cfg, port);
    let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
    assert!(
        body.contains(r#"nextg_demo_enabled{demo="d441c-amf-mobility",mode="on"} 1"#),
        "{body}"
    );
    assert!(body.contains("nwdaf_ue_mobility_serving 1"), "{body}");
    let _ = child.0.kill();
    let mut err = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        err.contains("DEMO MODE ACTIVE: d441c-amf-mobility=on"),
        "{err}"
    );
    assert!(
        err.contains("[demo:d441c-amf-mobility] ue-mobility: on"),
        "{err}"
    );
}

/// The demo-off arms: the kill switch off with the key enabled, and no block at
/// all. No banner, no `[demo:` line, no `nextg_demo_enabled`, nothing served.
#[cfg(feature = "amf-mobility")]
#[test]
fn the_kill_switch_and_an_absent_block_are_demo_off() {
    for (tag, demo) in [
        (
            "killswitch",
            "demo:\n  enabled: false\n  d441c-amf-mobility:\n    enabled: true\n    mode: on\n",
        ),
        ("absent", ""),
    ] {
        let cfg = config(tag, demo);
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(
            body.contains("nwdaf_ue_mobility_serving 0"),
            "{tag}: {body}"
        );
        let _ = child.0.kill();
        let mut err = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}

/// nextgsim#465: a build without `demo-d441a-congestion-loop` does not know the
/// key, so the block fails start-up.
#[cfg(not(feature = "demo-d441a-congestion-loop"))]
#[test]
fn the_d441a_key_fails_startup_in_a_build_without_its_feature() {
    let cfg = config(
        "d441a-no-feature",
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: statistics\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// nextgsim#465 invalid-mode criterion: `mode: bogus` fails nwdafd start-up with
/// `DemoConfigError::UnknownMode { key: "d441a-congestion-loop", mode: "bogus" }`.
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn d441a_mode_bogus_fails_startup_with_unknown_mode() {
    let cfg = config(
        "d441a-bogus",
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: bogus\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "no fallback: start-up must fail");
    assert!(
        err.contains(r#"UnknownMode { demo: "d441a-congestion-loop", mode: "bogus""#),
        "{err}"
    );
}

/// nextgsim#465: each mode logs the banner and its own prefixed line and exports
/// the metric; the three demo-off shapes export none and serve nothing.
#[cfg(feature = "demo-d441a-congestion-loop")]
#[test]
fn d441a_modes_and_demo_off_shapes() {
    let read_err = |child: &mut Killed| {
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
    };
    for mode in ["statistics", "prediction", "no-loop"] {
        let cfg = config(
            &format!("d441a-{mode}"),
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
        assert!(body.contains("nwdaf_udc_serving 1"), "{body}");
        let err = read_err(&mut child);
        assert!(
            err.contains(&format!("DEMO MODE ACTIVE: d441a-congestion-loop={mode}")),
            "{err}"
        );
        assert!(
            err.contains(&format!(
                "[demo:d441a-congestion-loop] user-data-congestion: on (mode={mode};"
            )),
            "{err}"
        );
    }
    for (tag, demo) in [
        ("d441a-absent", ""),
        ("d441a-off", "demo:\n  enabled: false\n"),
        (
            "d441a-killswitch",
            "demo:\n  enabled: false\n  d441a-congestion-loop:\n    enabled: true\n    mode: statistics\n",
        ),
    ] {
        let cfg = config(tag, demo);
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(body.contains("nwdaf_udc_serving 0"), "{tag}: {body}");
        let err = read_err(&mut child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}

// ── nextgsim#468: nwdaf.role and demo d441e-model-retrain ──────────────────

/// `nwdaf.role` is a deployment setting: anything but mtlf/anlf/both fails
/// start-up, in every build.
#[test]
fn an_unknown_nwdaf_role_fails_startup() {
    let path = std::env::temp_dir().join(format!(
        "nwdafd-role-bogus-{}-{}.yaml",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        format!(
            "nwdaf:\n  role: bogus\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {}\n",
            free_port()
        ),
    )
    .unwrap();
    let (ok, err) = run_to_exit(&path);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("nwdaf.role must be one of"), "{err}");
}

/// An AnLF-only NWDAF contains no MTLF: Nnwdaf_MLModelProvision is not served
/// (404), while the default role serves it (201).
#[test]
fn an_anlf_role_serves_no_mlmodelprovision() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (role, expected) in [("anlf", 404u16), ("both", 201)] {
        let sbi_port = free_port();
        let path = std::env::temp_dir().join(format!(
            "nwdafd-role-{role}-{}-{sbi_port}.yaml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            format!(
                "nwdaf:\n  role: {role}\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {sbi_port}\n"
            ),
        )
        .unwrap();
        let mut child = spawn(&path, free_port());
        let status = rt.block_on(async {
            let client = nextgcore_sbi::SbiClient::new(nextgcore_sbi::SbiClientConfig::new(
                "127.0.0.1",
                sbi_port,
            ));
            let body = serde_json::json!({
                "notifUri": "http://127.0.0.1:1/cb",
                "mLEventSubscs": [{ "mLEvent": "NF_LOAD", "mLEventFilter": {} }]
            });
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                match client
                    .post_json("/nnwdaf-mlmodelprovision/v1/subscriptions", &body)
                    .await
                {
                    Ok(resp) => return resp.status,
                    Err(_) if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(100)).await
                    }
                    Err(e) => panic!("nwdafd never answered: {e}"),
                }
            }
        });
        assert_eq!(status, expected, "role {role}");
        let _ = child.0.kill();
    }
}

/// Without `demo-d441e-model-retrain` the key is unknown.
#[cfg(not(feature = "demo-d441e-model-retrain"))]
#[test]
fn the_d441e_key_fails_startup_in_a_build_without_its_feature() {
    let cfg = config(
        "d441e-no-feature",
        "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: retrain\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// nextgsim#468 invalid-mode criterion: no fallback.
#[cfg(feature = "demo-d441e-model-retrain")]
#[test]
fn d441e_mode_bogus_fails_startup_with_unknown_mode() {
    let cfg = config(
        "d441e-bogus",
        "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: bogus\n",
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "no fallback: start-up must fail");
    assert!(
        err.contains(r#"UnknownMode { demo: "d441e-model-retrain", mode: "bogus""#),
        "{err}"
    );
}

/// Each mode on an AnLF: the banner, the prefixed line, the metric and the
/// client. The three demo-off shapes on the same AnLF: none of it, and the
/// client does not start.
#[cfg(feature = "demo-d441e-model-retrain")]
#[test]
fn d441e_modes_and_demo_off_shapes() {
    let anlf = "nwdaf:\n  role: anlf\n  anlf:\n    mtlf_uri: http://127.0.0.1:1\n";
    let read_err = |child: &mut Killed| {
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
    };
    let cfg_with = |tag: &str, demo: &str| {
        let path = config(tag, demo);
        let text = std::fs::read_to_string(&path).unwrap();
        // config() writes `nwdaf:\n  sbi: ...`; put role and anlf under it.
        std::fs::write(&path, text.replacen("nwdaf:\n", anlf, 1)).unwrap();
        path
    };
    for mode in ["retrain", "no-retrain"] {
        let cfg = cfg_with(
            &format!("d441e-{mode}"),
            &format!(
                "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: {mode}\n"
            ),
        );
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(
            body.contains(&format!(
                r#"nextg_demo_enabled{{demo="d441e-model-retrain",mode="{mode}"}} 1"#
            )),
            "{body}"
        );
        assert!(body.contains("nwdaf_anlf_client_active 1"), "{body}");
        let err = read_err(&mut child);
        assert!(
            err.contains(&format!("DEMO MODE ACTIVE: d441e-model-retrain={mode}")),
            "{err}"
        );
        assert!(
            err.contains(&format!(
                "[demo:d441e-model-retrain] model-retrain: on (mode={mode}, role=anlf; AnLF client to http://127.0.0.1:1"
            )),
            "{err}"
        );
    }
    for (tag, demo) in [
        ("d441e-absent", ""),
        ("d441e-off", "demo:\n  enabled: false\n"),
        (
            "d441e-killswitch",
            "demo:\n  enabled: false\n  d441e-model-retrain:\n    enabled: true\n    mode: retrain\n",
        ),
    ] {
        let cfg = cfg_with(tag, demo);
        let port = free_port();
        let mut child = spawn(&cfg, port);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(body.contains("nwdaf_anlf_client_active 0"), "{tag}: {body}");
        let err = read_err(&mut child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}
