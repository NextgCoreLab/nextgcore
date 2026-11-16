//! nextgsim#458 / #466: the `demo:` block at nwdafd start-up, through the real
//! binary. An unknown key or mode fails start-up with no fallback; an active
//! `d441c-amf-mobility` logs the banner and exports `nextg_demo_enabled`; the kill
//! switch and an absent block leave the process unchanged.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nextgcore_sbi::test_support::{free_port, NfProcess, NfSpawn};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The SBI port's place in a config template; [`running`] and [`run_to_exit`]
/// fill it in.
const SBI_PORT: &str = "__SBI_PORT__";

/// A config template: `nwdaf.sbi` on [`SBI_PORT`], then `demo`.
fn config(_tag: &str, demo: &str) -> String {
    format!(
        "nwdaf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {SBI_PORT}\n{demo}"
    )
}

fn nwdafd_args(cmd: &mut Command, config: &std::path::Path, metrics_port: u16) {
    cmd.arg("-c")
        .arg(config)
        // No NRF: registration and the AMF subscription fail and retry, which
        // is all this test needs.
        .args(["--nrf-uri", "http://127.0.0.1:1"])
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env("RUST_LOG", "info")
        .env("NWDAF_METRICS_PORT", metrics_port.to_string());
}

/// Start nwdafd on `template` and wait until its SBI port accepts (and, in a
/// build that serves `/metrics`, its metrics endpoint is up). Returns the
/// process and its metrics port; the SBI port is `nf.port()`.
///
/// #1521: through the shared `NfSpawn`, which respawns on fresh ports when
/// nwdafd loses a probed one to another process (the #1497 race). The SBI bind
/// is fatal; the metrics bind is not, and a lost one used to surface as
/// "/metrics" timing out. The start-up-failure tests use [`run_to_exit`]:
/// nwdafd validates its `demo:` block and `nwdaf.role` before it binds
/// anything, so they lose no bind.
fn running(template: &str) -> (NfProcess, u16) {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let spawn = NfSpawn::new(
        env!("CARGO_BIN_EXE_nextgcore-nwdafd"),
        &format!("nwdafd-demo-{n}"),
    )
    .ready_when_accepting(std::net::Ipv4Addr::LOCALHOST.into());
    #[cfg(any(feature = "amf-mobility", feature = "demo-d441e-model-retrain"))]
    let spawn = spawn.ready_when_logged("NWDAF metrics endpoint on http://");
    let mut metrics_port = 0;
    let nf = spawn.spawn(|cmd, sbi_port, dir| {
        metrics_port = free_port();
        let config = dir.join("nwdaf.yaml");
        std::fs::write(&config, template.replace(SBI_PORT, &sbi_port.to_string())).unwrap();
        nwdafd_args(cmd, &config, metrics_port);
    });
    (nf, metrics_port)
}

/// Run to exit (start-up failure), returning (success, stderr).
fn run_to_exit(template: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!(
        "nwdafd-demo-exit-{}-{}.yaml",
        std::process::id(),
        free_port()
    ));
    std::fs::write(&path, template.replace(SBI_PORT, &free_port().to_string())).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nextgcore-nwdafd"));
    nwdafd_args(&mut cmd, &path, free_port());
    let mut child = Killed(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nwdafd"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let out = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut err = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            break (status.success(), err);
        }
        assert!(Instant::now() < deadline, "nwdafd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_file(&path);
    out
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
    let (child, port) = running(&cfg);
    let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
    assert!(
        body.contains(r#"nextg_demo_enabled{demo="d441c-amf-mobility",mode="on"} 1"#),
        "{body}"
    );
    assert!(body.contains("nwdaf_ue_mobility_serving 1"), "{body}");
    let err = child.log();
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
        let (child, port) = running(&cfg);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(
            body.contains("nwdaf_ue_mobility_serving 0"),
            "{tag}: {body}"
        );
        let err = child.log();
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
    let read_err = |child: &NfProcess| child.log();
    for mode in ["statistics", "prediction", "no-loop"] {
        let cfg = config(
            &format!("d441a-{mode}"),
            &format!(
                "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: {mode}\n"
            ),
        );
        let (child, port) = running(&cfg);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(
            body.contains(&format!(
                r#"nextg_demo_enabled{{demo="d441a-congestion-loop",mode="{mode}"}} 1"#
            )),
            "{body}"
        );
        assert!(body.contains("nwdaf_udc_serving 1"), "{body}");
        let err = read_err(&child);
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
        let (child, port) = running(&cfg);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(body.contains("nwdaf_udc_serving 0"), "{tag}: {body}");
        let err = read_err(&child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}

// ── nextgsim#468: nwdaf.role and demo d441e-model-retrain ──────────────────

/// `nwdaf.role` is a deployment setting: anything but mtlf/anlf/both fails
/// start-up, in every build.
#[test]
fn an_unknown_nwdaf_role_fails_startup() {
    let path = format!(
        "nwdaf:\n  role: bogus\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {SBI_PORT}\n"
    );
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
        let path = format!(
            "nwdaf:\n  role: {role}\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {SBI_PORT}\n"
        );
        let (child, _) = running(&path);
        let sbi_port = child.port();
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
        drop(child);
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
    let read_err = |child: &NfProcess| child.log();
    // config() writes `nwdaf:\n  sbi: ...`; put role and anlf under it.
    let cfg_with = |tag: &str, demo: &str| config(tag, demo).replacen("nwdaf:\n", anlf, 1);
    for mode in ["retrain", "no-retrain"] {
        let cfg = cfg_with(
            &format!("d441e-{mode}"),
            &format!(
                "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: {mode}\n"
            ),
        );
        let (child, port) = running(&cfg);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(
            body.contains(&format!(
                r#"nextg_demo_enabled{{demo="d441e-model-retrain",mode="{mode}"}} 1"#
            )),
            "{body}"
        );
        assert!(body.contains("nwdaf_anlf_client_active 1"), "{body}");
        let err = read_err(&child);
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
        let (child, port) = running(&cfg);
        let body = scrape(port, Duration::from_secs(20)).expect("/metrics");
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(body.contains("nwdaf_anlf_client_active 0"), "{tag}: {body}");
        let err = read_err(&child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}

/// nextgsim#468 PR 3 criterion: with the feature built but the block off, the
/// MLModelMonitor routes return 404; with it on they are served (a malformed
/// registration is a 400, not a 404). A build without the feature: 404 always.
#[test]
fn mlmodelmonitor_routes_follow_the_demo_block() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let on =
        "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: retrain\n";
    let mut arms = vec![
        ("mm-absent", "", 404u16),
        ("mm-off", "demo:\n  enabled: false\n", 404),
    ];
    // A build without the feature refuses the key itself (UnknownKey).
    if cfg!(feature = "demo-d441e-model-retrain") {
        arms.push((
            "mm-killswitch",
            "demo:\n  enabled: false\n  d441e-model-retrain:\n    enabled: true\n    mode: retrain\n",
            404,
        ));
        arms.push(("mm-on", on, 400));
    }
    for (tag, demo, expected) in arms {
        let path = format!(
            "nwdaf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {SBI_PORT}\n{demo}"
        );
        let (child, _) = running(&path);
        let sbi_port = child.port();
        let status = rt.block_on(async {
            let client = nextgcore_sbi::SbiClient::new(nextgcore_sbi::SbiClientConfig::new(
                "127.0.0.1",
                sbi_port,
            ));
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                match client
                    .post_json(
                        "/nnwdaf-mlmodelmonitor/v1/registrations",
                        &serde_json::json!({}),
                    )
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
        assert_eq!(status, expected, "{tag}");
        drop(child);
    }
}

/// nextgsim#468 PR 4: with the demo on, the binary feeds the seeded series
/// (an NF_LOAD analytics target) and logs its disclosed regime change;
/// `retrain_series.enabled: false` feeds nothing; a malformed block fails
/// start-up.
#[cfg(feature = "demo-d441e-model-retrain")]
#[test]
fn the_seeded_series_follows_its_block() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let on =
        "demo:\n  enabled: true\n  d441e-model-retrain:\n    enabled: true\n    mode: retrain\n";
    let filter = "%7B%22nfInstanceIds%22%3A%5B%22d441e000-0468-4000-8000-000000000468%22%5D%7D";
    for (tag, series, expected) in [
        ("series-on", "", 200u16),
        ("series-off", "  retrain_series:\n    enabled: false\n", 204),
    ] {
        let path = format!(
            "nwdaf:\n  role: mtlf\n{series}  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {SBI_PORT}\n{on}"
        );
        let (child, _) = running(&path);
        let sbi_port = child.port();
        let status = rt.block_on(async {
            let client = nextgcore_sbi::SbiClient::new(nextgcore_sbi::SbiClientConfig::new(
                "127.0.0.1",
                sbi_port,
            ));
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                match client
                    .get(&format!(
                        "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter={filter}"
                    ))
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
        let err = child.log();
        assert_eq!(status, expected, "{tag}: {err}");
        assert_eq!(
            err.contains("[demo:d441e-model-retrain] seeded series nf=d441e000-0468-4000-8000-000000000468 seed=468"),
            expected == 200,
            "{tag}: {err}"
        );
    }
    let cfg = config("series-bad", on).replacen(
        "nwdaf:\n",
        "nwdaf:\n  retrain_series:\n    step_secs: 0\n",
        1,
    );
    let (ok, err) = run_to_exit(&cfg);
    assert!(!ok, "a malformed retrain_series fails start-up");
    assert!(err.contains("nwdaf.retrain_series.step_secs"), "{err}");
}
