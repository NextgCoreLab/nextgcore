//! #1529: eesd's Nsmf_EventExposure Subscribe (demo d443a-edge-budget) against
//! the real `nextgcore-smfd` enforcing OAuth2 and the real `nextgcore-nrfd`
//! issuing the tokens, three binaries over HTTP/2 on loopback.
//!
//! - With `--nrf-uri`, eesd registers at nrfd as an AF (TS 23.558 §6.2),
//!   authenticates its token request with a CCA (TS 33.501 §13.3.8, nrfd's
//!   default policy), and presents the token for scope `nsmf-event-exposure`;
//!   smfd answers 201, so the subscription is held and the refused counter stays
//!   at 0.
//! - Without it, the same Subscribe carries no token and smfd refuses it: the
//!   refused counter rises and nothing is held.
//!
//! nrfd and smfd are siblings of this crate's binary in the target directory.
//! `cargo test --workspace` builds them; a `-p nextgcore-eesd` run that did not
//! skips with a message saying so.
#![cfg(feature = "demo-d443a-edge-budget")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nextgcore_sbi::test_support::{spawn_port, NfProcess, NfSpawn};

const EESD: &str = env!("CARGO_BIN_EXE_nextgcore-eesd");

fn sibling(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(EESD).with_file_name(name);
    p.exists().then_some(p)
}

/// Plain-HTTP SBI on loopback (the `dev` profile, issue #63); OAuth2 is turned
/// on separately where a test wants it.
fn child_env(cmd: &mut std::process::Command) {
    cmd.env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env("RUST_LOG", "info")
        .env_remove("NEXTGCORE_SBI_OAUTH2_REQUIRE")
        .env_remove("NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE")
        .env_remove("NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR")
        .env_remove("NEXTGCORE_METRICS_BIND")
        .env_remove("NEXTGCORE_SBI_ADVERTISE");
}

/// nrfd, trusting the CCA public keys NFs publish into `trust`.
async fn nrfd(bin: &Path, tag: &str, trust: &Path) -> NfProcess {
    let trust = trust.display().to_string();
    NfSpawn::new(bin, &format!("{tag}-nrfd"))
        .ready_when_logged("server listening on")
        .spawn_async(move |cmd, port, dir| {
            child_env(cmd);
            let config = dir.join("nrf.yaml");
            std::fs::write(
                &config,
                format!("nrf:\n  sbi:\n    oauth2:\n      cca_trusted_keys_dir: {trust}\n"),
            )
            .unwrap();
            cmd.arg("-c")
                .arg(&config)
                .args(["--sbi-addr", "127.0.0.1", "--sbi-port", &port.to_string()])
                .env("NRF_METRICS_PORT", "0");
        })
        .await
}

/// smfd enforcing OAuth2 on its service routes, JWKS and registration at `nrf`.
async fn smfd(bin: &Path, tag: &str, nrf: u16) -> NfProcess {
    NfSpawn::new(bin, &format!("{tag}-smfd"))
        .ready_when_logged("SBI HTTP/2 server listening on")
        .spawn_async(move |cmd, port, dir| {
            child_env(cmd);
            let config = dir.join("smf.yaml");
            std::fs::write(
                &config,
                format!(
                    "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {port}\n    \
                     client:\n      nrf:\n        - uri: http://127.0.0.1:{nrf}\n"
                ),
            )
            .unwrap();
            cmd.arg("-c")
                .arg(&config)
                .env("NEXTGCORE_SBI_OAUTH2_REQUIRE", "1")
                .env("SMF_PFCP_ADDR", "127.0.0.1")
                .env("SMF_PFCP_PORT", "0")
                .env("SMF_METRICS_PORT", "0");
        })
        .await
}

/// eesd with the demo on, subscribing at `smf`; with `nrf`, as an AF of it.
async fn eesd(tag: &str, smf: u16, nrf: Option<(u16, &Path)>) -> (NfProcess, SocketAddr) {
    let mut metrics = 0;
    let nrf = nrf.map(|(p, trust)| (p, trust.to_path_buf()));
    let nf = NfSpawn::new(EESD, &format!("{tag}-eesd"))
        .ready_when_logged("EES metrics endpoint on http://")
        .spawn_async(|cmd, port, dir| {
            child_env(cmd);
            metrics = spawn_port();
            let config = dir.join("ees.yaml");
            std::fs::write(
                &config,
                format!(
                    "ees:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {port}\n  \
                     edge_budget:\n    smf_uri: http://127.0.0.1:{smf}\n    rep_period_s: 1\n\
                     demo:\n  enabled: true\n  d443a-edge-budget:\n    enabled: true\n    mode: measured-budget\n"
                ),
            )
            .unwrap();
            cmd.arg("-c")
                .arg(&config)
                .env("EES_METRICS_PORT", metrics.to_string());
            if let Some((nrf, trust)) = &nrf {
                cmd.args(["--nrf-uri", &format!("http://127.0.0.1:{nrf}")])
                    .env("NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE", dir.join("cca.key"))
                    .env("NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR", trust);
            }
        })
        .await;
    (nf, SocketAddr::from(([127, 0, 0, 1], metrics)))
}

/// The value of the unlabelled sample `name`, or of `name{labels}`, if present.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

/// Scrape until `done` holds, or panic with the last body and eesd's log.
async fn scrape_until(addr: SocketAddr, nf: &NfProcess, done: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let body = nextgcore_metrics::nf::scrape_for_test(addr).await;
        if done(&body) {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "eesd metrics never reached the expected state:\n{body}\n--- eesd log ---\n{}",
            nf.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

const SUBSCRIBED: &str = "eees_d443a_qos_mon_subscribed";
const REFUSED: &str = "eees_d443a_qos_mon_subscribe_failures_total{reason=\"refused\"}";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_subscribe_carries_an_nrf_token_the_oauth2_smf_accepts() {
    let (Some(nrfd_bin), Some(smfd_bin)) = (sibling("nextgcore-nrfd"), sibling("nextgcore-smfd"))
    else {
        eprintln!(
            "SKIPPED: nextgcore-nrfd / nextgcore-smfd are not built next to nextgcore-eesd \
             (`cargo test --workspace` builds them)"
        );
        return;
    };
    let trust = std::env::temp_dir().join(format!("eesd-1529-trust-{}", std::process::id()));
    std::fs::create_dir_all(&trust).unwrap();

    let nrf = nrfd(&nrfd_bin, "eesd-1529-token", &trust).await;
    let smf = smfd(&smfd_bin, "eesd-1529-token", nrf.port()).await;

    // Token arm: held, never refused.
    let (ees, metrics) = eesd("eesd-1529-token", smf.port(), Some((nrf.port(), &trust))).await;
    let body = scrape_until(metrics, &ees, |b| sample(b, SUBSCRIBED) == Some(1.0)).await;
    assert_eq!(sample(&body, REFUSED).unwrap_or(0.0), 0.0, "{body}");
    assert!(
        ees.log().contains("registered at the NRF as AF"),
        "{}",
        ees.log()
    );
    drop(ees);

    // No token source: the same SMF refuses, nothing is held.
    let (bare, metrics) = eesd("eesd-1529-bare", smf.port(), None).await;
    let body = scrape_until(metrics, &bare, |b| sample(b, REFUSED).unwrap_or(0.0) >= 1.0).await;
    assert_eq!(sample(&body, SUBSCRIBED), Some(0.0), "{body}");

    let _ = std::fs::remove_dir_all(&trust);
}
