//! #1521: the shared real-binary spawn (`nextgcore_sbi::test_support::NfSpawn`),
//! tested against the real pcfd. These are #1520's lost-bind harness tests,
//! moved here from `policy_data_subscription.rs` when the helper became shared.
//!
//! The race (#1497): a `free_port()` port is free when probed, and a sibling
//! process connecting out can be handed it as its ephemeral source port before
//! the spawned NF binds it. Here the first port is held by a `bound_listener()`
//! instead, which makes the bind loss deterministic. A held socket and a
//! sibling's outbound one both give the NF EADDRINUSE.
//!
//! REVERT-VERIFIED:
//! - with `Run::poll` not respawning on "Address already in use", the taken-SBI,
//!   taken-late and taken-metrics tests fail;
//! - with stderr read before `try_wait` (the pause between them), the taken-late test fails
//!   ("exited at startup" while the printed stderr shows the bind error);
//! - with an exit that is not a lost bind no longer failing at once, the
//!   bad-address test fails its `should_panic` (it panics "not ready within"
//!   30 s later instead).

use std::time::Duration;

use nextgcore_sbi::test_support::{bound_listener, free_port, NfProcess, NfSpawn};

const SBI_LISTENING: &str = "SBI HTTP/2 server listening on";
const METRICS_ON: &str = "PCF metrics endpoint on http://";

/// pcfd with no NRF, its SBI listener on the spawn's port and its metrics port
/// from `metrics_port` (called once per spawn).
fn pcfd(spawn: NfSpawn, address: &'static str, mut metrics_port: impl FnMut() -> u16) -> NfProcess {
    spawn.spawn(move |cmd, sbi_port, dir| {
        let config = dir.join("pcf.yaml");
        std::fs::write(
            &config,
            format!(
                "pcf:\n  sbi:\n    server:\n      - address: {address}\n        port: {sbi_port}\n"
            ),
        )
        .unwrap();
        cmd.arg("-c")
            .arg(&config)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env("PCF_METRICS_PORT", metrics_port().to_string());
    })
}

fn listening_on(nf: &NfProcess) -> String {
    nf.log()
        .lines()
        .find_map(|l| l.split(SBI_LISTENING).nth(1))
        .expect("the listening line")
        .trim()
        .to_string()
}

/// A lost SBI bind is fatal for pcfd. The spawn sees the exit, moves to another
/// port, and returns a pcfd that is listening there.
#[test]
fn an_nf_that_loses_its_sbi_port_is_spawned_on_another() {
    let taken = bound_listener();
    let nf = pcfd(
        NfSpawn::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"), "nfspawn-taken")
            .ready_when_logged(SBI_LISTENING)
            .first_port(taken.port()),
        "127.0.0.1",
        free_port,
    );
    assert_ne!(nf.port(), taken.port());
    assert_eq!(listening_on(&nf), format!("127.0.0.1:{}", nf.port()));
    drop(taken);
}

/// #1520 review: a lost bind is still retried when the NF prints the bind error
/// and exits after the spawn last looked at its stderr. The 300 ms pause between
/// `try_wait` and the stderr read always puts the exit in that window.
#[test]
fn a_lost_bind_seen_late_is_still_retried() {
    let taken = bound_listener();
    let nf = pcfd(
        NfSpawn::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"), "nfspawn-taken-late")
            .ready_when_logged(SBI_LISTENING)
            .first_port(taken.port())
            .pause_after_exit_check(Duration::from_millis(300)),
        "127.0.0.1",
        free_port,
    );
    assert_eq!(listening_on(&nf), format!("127.0.0.1:{}", nf.port()));
    drop(taken);
}

/// A lost bind that is NOT fatal: pcfd's metrics listener only logs a warning
/// and pcfd runs on without it, so a test scraping it would time out. The spawn
/// treats the warning like an exit and respawns, and `configure` draws a new
/// metrics port for the respawn.
#[test]
fn a_non_fatal_lost_bind_is_respawned_too() {
    let taken = bound_listener();
    let mut first = Some(taken.port());
    let nf = pcfd(
        NfSpawn::new(
            env!("CARGO_BIN_EXE_nextgcore-pcfd"),
            "nfspawn-taken-metrics",
        )
        .ready_when_logged(SBI_LISTENING)
        .ready_when_logged(METRICS_ON),
        "127.0.0.1",
        move || first.take().unwrap_or_else(free_port),
    );
    let log = nf.log();
    assert!(
        log.contains(METRICS_ON),
        "the respawn serves metrics: {log}"
    );
    assert!(
        !log.contains(&format!("127.0.0.1:{}", taken.port())),
        "not on the held port: {log}"
    );
    drop(taken);
}

/// #1520 review: a startup failure that is not a lost bind fails at once, as the
/// failure it is, instead of being respawned until the attempts run out. The SBI
/// address does not parse, so pcfd exits before it binds anything.
#[test]
#[should_panic(expected = "exited at startup")]
fn a_startup_failure_that_is_not_a_lost_bind_fails_at_once() {
    let _ = pcfd(
        NfSpawn::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"), "nfspawn-badaddr")
            .ready_when_logged(SBI_LISTENING),
        "not-an-address",
        free_port,
    );
}
