//! nextgsim#458 / #464: the `demo:` block at amfd start-up, through the real
//! binary. An unknown key or mode fails start-up, with no fallback. An active
//! `d440c-nwdaf-paging` logs the banner and the effective paging strategy and
//! exports `nextg_demo_enabled`. The kill switch and an absent block leave the
//! process unchanged. nextgsim#462: an active `d440a-ai-paging` forces
//! `recommended-first` and exports `amf_paging_attempts_total`; it and
//! `d440c-nwdaf-paging` together fail start-up.

use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A spawned amfd, killed on drop, whose stderr is drained as it is written
/// (#1963): a test reads it while amfd runs, and amfd can never block on a full
/// pipe.
struct Killed {
    child: Child,
    err: std::sync::Arc<std::sync::Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Killed {
    /// What amfd has written to stderr so far.
    fn stderr_so_far(&self) -> String {
        self.err.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Wait for the stderr reader (the pipe closes when amfd exits) and return
    /// everything amfd wrote.
    fn collect(mut self) -> String {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.stderr_so_far()
    }
}

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// #1963: every port this test binary hands out, so two of its tests (which
/// run concurrently, each spawning an amfd) are never given the same one. The
/// kernel is free to return a just-released ephemeral port to the next bind(0),
/// and two amfds then fight over it: one fails to start, or a scrape reads the
/// other's listener.
static HANDED_OUT: std::sync::Mutex<std::collections::BTreeSet<u16>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

fn unique_port(probe: impl Fn() -> u16) -> u16 {
    loop {
        let port = probe();
        if HANDED_OUT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(port)
        {
            return port;
        }
    }
}

fn free_tcp() -> u16 {
    unique_port(|| {
        TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    })
}

fn free_udp() -> u16 {
    unique_port(|| {
        UdpSocket::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    })
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_nextgcore-amfd"))
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
        .expect("spawn amfd");
    let mut pipe = child.stderr.take().expect("stderr piped");
    let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = std::sync::Arc::clone(&err);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut chunk) {
            if n == 0 {
                break;
            }
            sink.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    });
    Killed {
        child,
        err,
        reader: Some(reader),
    }
}

/// Run to exit (start-up failure), returning (success, stderr).
fn run_to_exit(config: &std::path::Path) -> (bool, String) {
    let mut child = spawn(config, free_tcp());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.child.try_wait().unwrap() {
            return (status.success(), child.collect());
        }
        assert!(Instant::now() < deadline, "amfd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// amfd's log line for a listener it could not bind: it then runs on without
/// that listener (the metrics endpoint is best-effort), so it does not exit.
#[cfg(any(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
const IN_USE: &str = "Address already in use";

/// The `/metrics` body once `child` answers it with a 200, or `None` when it
/// will not: `within` passed, or `child` logged that a port it was given is
/// taken.
///
/// #1963: every failed attempt is retried until then. A listener that accepts
/// and then resets, or that answers something other than a 200 metrics page,
/// used to end the scrape at once with `None`, failing the test 0.1 s in.
#[cfg(any(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
fn scrape(child: &Killed, port: u16, within: Duration) -> Option<String> {
    use std::io::Write;
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if child.stderr_so_far().contains(IN_USE) {
            return None;
        }
        if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            // A listener that accepts and never answers (one that only holds the
            // port) must not hang the scrape: bounded reads and writes.
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
            let mut body = String::new();
            let answered = s
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .and_then(|()| s.read_to_string(&mut body));
            if answered.is_ok() && body.starts_with("HTTP/1.1 200") {
                return Some(body);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Start amfd with a fresh config for `tag` / `demo` and return it with its
/// `/metrics` body (#1963).
///
/// Root cause: a port probed free with bind(0) and released is free to be taken
/// before amfd binds it, by any socket on the machine (another test's amfd, or
/// its outbound connections, which draw from the same ephemeral range). The
/// ports are reserved within this binary ([`unique_port`]), which closes the
/// in-binary case; for the rest, when amfd logs that a port it was given is in
/// use (it runs on without its metrics endpoint, so it does not exit), it is
/// started again on new ports, up to five times. Any other failure panics with
/// amfd's stderr, so a failure says why rather than only "/metrics".
#[cfg(any(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
fn start_and_scrape(tag: &str, demo: &str) -> (Killed, String) {
    start_and_scrape_with(tag, demo, free_tcp)
}

/// [`start_and_scrape`] with the metrics port of each attempt from `next_port`.
#[cfg(any(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
fn start_and_scrape_with(
    tag: &str,
    demo: &str,
    mut next_port: impl FnMut() -> u16,
) -> (Killed, String) {
    let mut last = String::new();
    for _attempt in 0..5 {
        let port = next_port();
        let child = spawn(&config(tag, demo), port);
        if let Some(body) = scrape(&child, port, Duration::from_secs(30)) {
            return (child, body);
        }
        last = stop(child);
        if !last.contains(IN_USE) {
            break;
        }
    }
    panic!("{tag}: amfd never served /metrics; its stderr:\n{last}");
}

/// Kill a running amfd and return its stderr.
#[cfg(any(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
fn stop(mut child: Killed) -> String {
    let _ = child.child.kill();
    let _ = child.child.wait();
    child.collect()
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
    let (child, body) = start_and_scrape("on", &block("nwdaf-mobility"));
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

/// #1963: the flake, made deterministic. The metrics port amfd is given is
/// already taken when it binds (here by this test's own listener; in CI by
/// another socket that drew the same released ephemeral port). amfd logs it
/// and runs on without metrics, and the scrape used to wait out its 30 s and
/// fail with "/metrics". It is now started again on a fresh port and served.
#[cfg(feature = "demo-d440c-nwdaf-paging")]
#[test]
fn a_taken_metrics_port_is_retried_on_a_fresh_one_1963() {
    let taken = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let taken_port = taken.local_addr().unwrap().port();
    let mut first = true;
    let started = Instant::now();
    let (child, body) = start_and_scrape_with("taken", &block("nwdaf-mobility"), || {
        if std::mem::take(&mut first) {
            taken_port
        } else {
            free_tcp()
        }
    });
    assert!(
        body.contains(r#"nextg_demo_enabled{demo="d440c-nwdaf-paging",mode="nwdaf-mobility"} 1"#),
        "{body}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the taken port is noticed from amfd's log, not by waiting out the scrape"
    );
    drop(child);
    drop(taken);
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
        let (child, body) = start_and_scrape(tag, demo);
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(!body.contains("amf_paging_nwdaf_hints_total"), "{tag}: {body}");
        let err = stop(child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
        assert!(err.contains("Paging strategy: registration-area"), "{tag}: {err}");
    }
}

fn d440a_block(mode: &str) -> String {
    format!("demo:\n  enabled: true\n  d440a-ai-paging:\n    enabled: true\n    mode: {mode}\n")
}

/// Without the feature, `d440a-ai-paging` is an unknown key.
#[cfg(not(feature = "demo-d440a-ai-paging"))]
#[test]
fn the_d440a_key_fails_startup_in_a_build_without_its_feature() {
    let (ok, err) = run_to_exit(&config("d440a-no-feature", &d440a_block("ct")));
    assert!(!ok, "start-up must fail");
    assert!(err.contains("UnknownKey"), "{err}");
}

/// nextgsim#462's invalid-mode arm: no fallback, and amfd's own strategy names
/// are not demo modes.
#[cfg(feature = "demo-d440a-ai-paging")]
#[test]
fn a_d440a_mode_the_gnb_does_not_have_fails_startup_with_unknown_mode() {
    for mode in ["bogus", "recommended-first"] {
        let (ok, err) = run_to_exit(&config(&format!("d440a-{mode}"), &d440a_block(mode)));
        assert!(!ok, "{mode}: start-up must fail");
        assert!(
            err.contains(&format!(
                r#"UnknownMode {{ demo: "d440a-ai-paging", mode: "{mode}""#
            )),
            "{mode}: {err}"
        );
    }
}

/// Mode `ct` (and `page-all`, the baseline arm): the banner, the forced
/// `recommended-first` line, `nextg_demo_enabled` and the attempts counter.
#[cfg(feature = "demo-d440a-ai-paging")]
#[test]
fn a_d440a_mode_logs_the_banner_and_the_forced_strategy_and_exports_the_metrics() {
    for mode in ["ct", "page-all"] {
        let (child, body) = start_and_scrape(&format!("d440a-on-{mode}"), &d440a_block(mode));
        assert!(
            body.contains(&format!(
                r#"nextg_demo_enabled{{demo="d440a-ai-paging",mode="{mode}"}} 1"#
            )),
            "{mode}: {body}"
        );
        assert!(
            body.contains(r#"amf_paging_attempts_total{scope="recommended"} 0"#)
                && body.contains(r#"amf_paging_attempts_total{scope="registration-area"} 0"#),
            "{mode}: {body}"
        );
        let err = stop(child);
        assert!(
            err.contains(&format!("DEMO MODE ACTIVE: d440a-ai-paging={mode}")),
            "{mode}: {err}"
        );
        assert!(
            err.contains(&format!(
                "[demo:d440a-ai-paging] Paging strategy: recommended-first (mode {mode} \
                 supersedes amf.paging.strategy: registration-area)"
            )),
            "{mode}: {err}"
        );
    }
}

/// The demo-off arms in a d440a build: the kill switch off, and no block with
/// `paging.strategy: recommended-first` set (the base feature on its own). No
/// banner, no `[demo:` line, no `nextg_demo_enabled`, no attempts counter.
#[cfg(feature = "demo-d440a-ai-paging")]
#[test]
fn d440a_demo_off_exports_nothing_of_the_demo() {
    for (tag, demo) in [
        (
            "d440a-killswitch",
            "demo:\n  enabled: false\n  d440a-ai-paging:\n    enabled: true\n    mode: ct\n",
        ),
        (
            "d440a-base-feature",
            "  paging:\n    strategy: recommended-first\n",
        ),
    ] {
        let (child, body) = start_and_scrape(tag, demo);
        assert!(!body.contains("nextg_demo_enabled"), "{tag}: {body}");
        assert!(!body.contains("amf_paging_attempts_total"), "{tag}: {body}");
        let err = stop(child);
        assert!(!err.contains("DEMO MODE ACTIVE"), "{tag}: {err}");
        assert!(!err.contains("[demo:"), "{tag}: {err}");
    }
}

/// Both paging demos at once: each would supersede the other's strategy, so
/// start-up fails by name before either is installed.
#[cfg(all(feature = "demo-d440a-ai-paging", feature = "demo-d440c-nwdaf-paging"))]
#[test]
fn both_paging_demos_at_once_fail_startup() {
    let (ok, err) = run_to_exit(&config(
        "both",
        "demo:\n  enabled: true\n  d440a-ai-paging:\n    enabled: true\n    mode: ct\n  \
         d440c-nwdaf-paging:\n    enabled: true\n    mode: nwdaf-mobility\n",
    ));
    assert!(!ok, "start-up must fail");
    assert!(err.contains("PagingDemoConflict"), "{err}");
    assert!(
        !err.contains("DEMO MODE ACTIVE"),
        "nothing installed: {err}"
    );
}
