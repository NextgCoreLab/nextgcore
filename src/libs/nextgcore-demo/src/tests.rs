use super::*;
use std::sync::Mutex;

const LOOP: DemoSpec = DemoSpec {
    key: "d441a-congestion-loop",
    modes: &["baseline", "closed-loop"],
    requires: &[],
};
const AGENT: DemoSpec = DemoSpec {
    key: "d446c-oauth-agent",
    modes: &["observe", "act"],
    requires: &["d441a-congestion-loop"],
};

fn registry() -> DemoRegistry {
    DemoRegistry::new(&[LOOP, AGENT])
}

fn parse(yaml: &str) -> Result<ActiveDemos, DemoConfigError> {
    let root: Value = serde_yaml::from_str(yaml).unwrap();
    DemoConfig::from_root(&root)?.validate(&registry())
}

#[test]
fn no_block_null_block_and_empty_block_are_all_no_demo() {
    for yaml in [
        "nrf: {sbi: {}}",
        "demo: ~\nnrf: {}",
        "demo: {}",
        "demo:\n  enabled: false",
    ] {
        let a = parse(yaml).unwrap();
        assert!(a.is_empty(), "{yaml}");
        assert_eq!(a.banner(), None, "{yaml}");
    }
}

#[test]
fn an_enabled_demo_under_the_kill_switch_is_active_with_its_mode() {
    let a = parse(
        "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: closed-loop\n",
    )
    .unwrap();
    assert_eq!(a.mode("d441a-congestion-loop"), Some("closed-loop"));
    assert!(a.is_active("d441a-congestion-loop"));
    assert!(!a.is_active("d446c-oauth-agent"));
    assert_eq!(
        a.banner().as_deref(),
        Some("DEMO MODE ACTIVE: d441a-congestion-loop=closed-loop")
    );
}

#[test]
fn the_kill_switch_off_overrides_every_enabled_demo() {
    for top in ["false", "~"] {
        let yaml = format!(
            "demo:\n  enabled: {top}\n  d441a-congestion-loop:\n    enabled: true\n    mode: baseline\n\
             \x20 d446c-oauth-agent:\n    enabled: true\n    mode: act\n"
        );
        let a = parse(&yaml).unwrap();
        assert!(a.is_empty(), "kill switch {top}: {a:?}");
        let mut out = String::new();
        a.render_metrics(&mut out);
        assert!(out.is_empty(), "kill switch {top}: {out}");
    }
    // The kill switch defaults to off: a demo enabled without it is not active.
    let a =
        parse("demo:\n  d441a-congestion-loop:\n    enabled: true\n    mode: baseline\n").unwrap();
    assert!(a.is_empty());
}

#[test]
fn an_unknown_key_fails_even_with_the_kill_switch_off() {
    for top in ["true", "false"] {
        let err = parse(&format!(
            "demo:\n  enabled: {top}\n  d441a-congestion-lop:\n    enabled: false\n"
        ))
        .unwrap_err();
        assert_eq!(
            err,
            DemoConfigError::UnknownKey {
                key: "d441a-congestion-lop".into(),
                known: vec!["d441a-congestion-loop", "d446c-oauth-agent"],
            },
            "kill switch {top}"
        );
    }
    // A default build registers nothing, so any key is unknown there.
    let root: Value =
        serde_yaml::from_str("demo:\n  d441a-congestion-loop:\n    enabled: false\n").unwrap();
    let err = DemoConfig::from_root(&root)
        .unwrap()
        .validate(&DemoRegistry::default())
        .unwrap_err();
    assert!(matches!(err, DemoConfigError::UnknownKey { .. }), "{err}");
}

#[test]
fn an_unknown_mode_fails_even_on_a_disabled_demo() {
    for enabled in ["true", "false"] {
        let err = parse(&format!(
            "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: {enabled}\n    mode: open-loop\n"
        ))
        .unwrap_err();
        assert_eq!(
            err,
            DemoConfigError::UnknownMode {
                demo: "d441a-congestion-loop".into(),
                mode: "open-loop".into(),
                known: vec!["baseline", "closed-loop"],
            },
            "enabled {enabled}"
        );
    }
}

#[test]
fn an_active_demo_without_its_dependency_fails() {
    let err =
        parse("demo:\n  enabled: true\n  d446c-oauth-agent:\n    enabled: true\n    mode: act\n")
            .unwrap_err();
    assert_eq!(
        err,
        DemoConfigError::MissingDependency {
            demo: "d446c-oauth-agent".into(),
            requires: "d441a-congestion-loop".into(),
        }
    );
    // Present but disabled is still missing.
    let err = parse(
        "demo:\n  enabled: true\n  d446c-oauth-agent:\n    enabled: true\n    mode: act\n\
         \x20 d441a-congestion-loop:\n    enabled: false\n    mode: baseline\n",
    )
    .unwrap_err();
    assert!(
        matches!(err, DemoConfigError::MissingDependency { .. }),
        "{err}"
    );
    // With the dependency active, both are.
    let a = parse(
        "demo:\n  enabled: true\n  d446c-oauth-agent:\n    enabled: true\n    mode: act\n\
         \x20 d441a-congestion-loop:\n    enabled: true\n    mode: baseline\n",
    )
    .unwrap();
    assert_eq!(
        a.banner().as_deref(),
        Some("DEMO MODE ACTIVE: d441a-congestion-loop=baseline,d446c-oauth-agent=act")
    );
}

#[test]
fn malformed_blocks_are_named_errors_not_silent_defaults() {
    let cases = [
        ("demo: true", "demo must be a mapping"),
        (
            "demo:\n  enabled: yes-please",
            "demo.enabled must be a boolean",
        ),
        (
            "demo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n",
            "demo.d441a-congestion-loop.mode is required",
        ),
        (
            "demo:\n  d441a-congestion-loop:\n    enabled: false\n    mdoe: baseline\n",
            "unknown field \"mdoe\"",
        ),
        (
            "demo:\n  d441a-congestion-loop:\n    mode: 3\n",
            "demo.d441a-congestion-loop.mode must be a string",
        ),
        (
            "demo:\n  d441a-congestion-loop: on\n",
            "demo.d441a-congestion-loop must be a mapping",
        ),
    ];
    for (yaml, want) in cases {
        match parse(yaml) {
            Err(DemoConfigError::Malformed { detail }) => {
                assert!(detail.contains(want), "{yaml}: {detail}")
            }
            other => panic!("{yaml}: expected Malformed, got {other:?}"),
        }
    }
}

#[test]
fn the_metric_has_one_series_per_active_demo_and_none_when_off() {
    let mut out = String::new();
    ActiveDemos::default().render_metrics(&mut out);
    assert_eq!(out, "", "no demo: not even a HELP/TYPE header");

    let a = parse(
        "demo:\n  enabled: true\n  d446c-oauth-agent:\n    enabled: true\n    mode: observe\n\
         \x20 d441a-congestion-loop:\n    enabled: true\n    mode: baseline\n",
    )
    .unwrap();
    a.render_metrics(&mut out);
    assert_eq!(
        out,
        "# HELP nextg_demo_enabled 1 for each demo active in this process (nextgsim#458)\n\
         # TYPE nextg_demo_enabled gauge\n\
         nextg_demo_enabled{demo=\"d441a-congestion-loop\",mode=\"baseline\"} 1\n\
         nextg_demo_enabled{demo=\"d446c-oauth-agent\",mode=\"observe\"} 1\n"
    );
}

#[test]
#[should_panic(expected = "is not [a-z0-9-]+")]
fn a_registry_key_with_label_unsafe_characters_is_a_programming_error() {
    DemoRegistry::new(&[DemoSpec {
        key: "bad\"key",
        modes: &["a"],
        requires: &[],
    }]);
}

#[test]
#[should_panic(expected = "requires unregistered demo")]
fn a_registry_dependency_on_an_unregistered_demo_is_a_programming_error() {
    DemoRegistry::new(&[AGENT]);
}

// --- process-global state -------------------------------------------------
//
// `INSTALLED` and the logger are process-wide and write-once, so ONE test owns
// both: it is the only caller of `install` / `init_from_root` and of
// `log::set_logger` in this test binary.

struct Capture(Mutex<Vec<(log::Level, String)>>);

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        self.0
            .lock()
            .unwrap()
            .push((r.level(), r.args().to_string()));
    }
    fn flush(&self) {}
}

static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

#[test]
fn install_logs_the_banner_once_and_feeds_the_metric_and_the_log_prefix() {
    log::set_logger(&CAPTURE).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    // Before install: no state, no metric.
    assert!(installed().is_none());
    let mut out = String::new();
    render_installed_metrics(&mut out);
    assert_eq!(out, "");

    let root: Value = serde_yaml::from_str(
        "nrf: {}\ndemo:\n  enabled: true\n  d441a-congestion-loop:\n    enabled: true\n    mode: closed-loop\n",
    )
    .unwrap();
    let a = init_from_root(&root, &registry()).unwrap();
    assert_eq!(active_mode("d441a-congestion-loop"), Some("closed-loop"));
    assert_eq!(installed(), Some(a));

    render_installed_metrics(&mut out);
    assert!(
        out.contains("nextg_demo_enabled{demo=\"d441a-congestion-loop\",mode=\"closed-loop\"} 1"),
        "{out}"
    );

    demo_log!(info, "d441a-congestion-loop", "lowered the cap to {}", 3);
    assert_eq!(prefix("k"), "[demo:k]");

    // Write-once: no runtime switching.
    assert_eq!(install(ActiveDemos::default()), Err(AlreadyInstalled));
    assert_eq!(
        init_from_root(&root, &registry()),
        Err(DemoConfigError::AlreadyInstalled)
    );
    assert_eq!(active_mode("d441a-congestion-loop"), Some("closed-loop"));

    let logs = CAPTURE.0.lock().unwrap().clone();
    assert_eq!(
        logs,
        vec![
            (
                log::Level::Warn,
                "DEMO MODE ACTIVE: d441a-congestion-loop=closed-loop".to_string()
            ),
            (
                log::Level::Info,
                "[demo:d441a-congestion-loop] lowered the cap to 3".to_string()
            ),
        ],
        "one WARN banner at install, then the prefixed demo line"
    );
}
