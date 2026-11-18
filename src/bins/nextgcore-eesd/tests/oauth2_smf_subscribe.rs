//! #1529: eesd's Nsmf_EventExposure Subscribe (demo d443a-edge-budget) against
//! the real `nextgcore-smfd` enforcing OAuth2 and the real `nextgcore-nrfd`
//! issuing the tokens, three binaries over HTTP/2 on loopback.
//!
//! - With `--nrf-uri`, eesd registers at nrfd as an AF (TS 23.558 §6.2),
//!   authenticates its token request with a CCA (TS 33.501 §13.3.8, nrfd's
//!   default policy), and presents the token for scope `nsmf-event-exposure`;
//!   smfd answers 201, so the subscription is held and the refused counter stays
//!   at 0.
//! - With `--nrf-uri` but no client authentication, nrfd issues no token: the
//!   Subscribe is not sent bare, it counts as `no-token`, nothing is held.
//! - Without it, the same Subscribe carries no token and smfd refuses it: the
//!   refused counter rises and nothing is held.
//!
//! Since #1617 step f nrfd refuses NF management from a caller with no verified
//! certificate identity, so nrfd serves TLS from the shipped dev PKI
//! (`DevPki`) and smfd and eesd register with their own certificates.
//!
//! nrfd and smfd are siblings of this crate's binary in the target directory.
//! The CI steps that run this test (feature `demo-d443a-edge-budget`) build
//! them first; outside CI a run without them skips with a message, and in CI
//! (`CI` set) it fails.
#![cfg(feature = "demo-d443a-edge-budget")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nextgcore_sbi::test_support::{spawn_port, DevPki, NfProcess, NfSpawn};

const EESD: &str = env!("CARGO_BIN_EXE_nextgcore-eesd");

/// The dev PKI rows: the NRF, smfd and the token arm's eesd (registered as AF
/// under its UUID eesId).
const NRF_ID: &str = "1529f000-0000-4000-8000-0000000000f0";
const SMF_ID: &str = "1529f000-0000-4000-8000-0000000005f0";
const EES_ID: &str = "1529f000-0000-4000-8000-0000000000e5";

fn dev_pki() -> DevPki {
    DevPki::generate(NRF_ID, &[("smf", "SMF", SMF_ID), ("ees", "AF", EES_ID)])
}

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

/// nrfd over TLS (`pki`), trusting the CCA public keys NFs publish into `trust`.
async fn nrfd(bin: &Path, tag: &str, trust: &Path, pki: &DevPki) -> NfProcess {
    let trust = trust.display().to_string();
    NfSpawn::new(bin, &format!("{tag}-nrfd"))
        .ready_when_logged("server listening on")
        .spawn_async(move |cmd, port, dir| {
            child_env(cmd);
            pki.nrf_server_env(cmd);
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
///
/// With OAuth2 on, smfd's own NRF calls carry an `nnrf-nfm` token too, which it
/// obtains before NFRegister (TS 29.510 §6.1.8, #1667). nrfd grants that token to
/// a not-yet-registered NF only on a proven identity (here a CCA, TS 33.501
/// §13.3.8), so smfd gets a CCA key whose public half is published into nrfd's
/// trust directory `trust`, as eesd's is. Without one its token request is
/// `invalid_client` and, failing closed, it never registers.
async fn smfd(bin: &Path, tag: &str, nrf: u16, trust: &Path, pki: &DevPki) -> NfProcess {
    let trust = trust.to_path_buf();
    NfSpawn::new(bin, &format!("{tag}-smfd"))
        .ready_when_logged("SBI HTTP/2 server listening on")
        .spawn_async(move |cmd, port, dir| {
            child_env(cmd);
            pki.nrf_client_env(cmd, "smf");
            let config = dir.join("smf.yaml");
            std::fs::write(
                &config,
                format!(
                    "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {port}\n    \
                     client:\n      nrf:\n        - uri: https://127.0.0.1:{nrf}\n"
                ),
            )
            .unwrap();
            cmd.arg("-c")
                .arg(&config)
                .env("NEXTGCORE_SBI_OAUTH2_REQUIRE", "1")
                .env("NEXTGCORE_SMF_INSTANCE_ID", SMF_ID)
                .env("NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE", dir.join("cca.key"))
                .env("NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR", &trust)
                .env("SMF_PFCP_ADDR", "127.0.0.1")
                .env("SMF_PFCP_PORT", "0")
                .env("SMF_METRICS_PORT", "0");
        })
        .await
}

/// How eesd reaches the NRF.
enum Arm<'a> {
    /// `--nrf-uri` at this nrfd, a CCA key whose public half is published into
    /// the nrfd's trust directory, the `ees` certificate, and the UUID eesId
    /// that certificate names (the AF id is then the eesId; the derivation from
    /// a non-UUID eesId is `nrf_af`'s unit test, since a certificate must name
    /// the ID it registers).
    Token(u16, &'a Path, &'a DevPki),
    /// `--nrf-uri` but no CCA key and no certificate (the CA only): nrfd's
    /// default policy refuses the token, and since #1617 step f the
    /// registration too.
    NoCca(u16, &'a DevPki),
    /// No `--nrf-uri`.
    Bare,
}

/// eesd with the demo on, subscribing at `smf`, reaching the NRF per `arm`.
async fn eesd(tag: &str, smf: u16, arm: Arm<'_>) -> (NfProcess, SocketAddr) {
    let mut metrics = 0;
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
            match &arm {
                Arm::Token(nrf, trust, pki) => {
                    pki.nrf_client_env(cmd, "ees");
                    cmd.args(["--nrf-uri", &format!("https://127.0.0.1:{nrf}")])
                        .args(["--ees-id", EES_ID])
                        .env("NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE", dir.join("cca.key"))
                        .env("NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR", trust);
                }
                Arm::NoCca(nrf, pki) => {
                    cmd.env("NEXTGCORE_NRF_TLS_CA", pki.file("ca.crt"))
                        .env("NEXTGCORE_NRF_TLS_SERVER_NAME", "nrf")
                        .args(["--nrf-uri", &format!("https://127.0.0.1:{nrf}")]);
                }
                Arm::Bare => {}
            }
        })
        .await;
    (nf, SocketAddr::from(([127, 0, 0, 1], metrics)))
}

/// Wait until smfd has registered at nrfd: until then nrfd has no producer to
/// grant `nsmf-event-exposure` for and answers a token request `invalid_scope`.
/// Read from smfd's log, since an SMF without a UPF registers UNDISCOVERABLE and
/// no discovery returns it.
async fn smf_registered(smf: &NfProcess) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !smf.log().contains("SMF registered with NRF") {
        assert!(
            Instant::now() < deadline,
            "smfd never registered at nrfd\n--- smfd log ---\n{}",
            smf.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
const NO_TOKEN: &str = "eees_d443a_qos_mon_subscribe_failures_total{reason=\"no-token\"}";

/// Removes the CCA trust directory however the test ends.
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_subscribe_carries_an_nrf_token_the_oauth2_smf_accepts() {
    let (Some(nrfd_bin), Some(smfd_bin)) = (sibling("nextgcore-nrfd"), sibling("nextgcore-smfd"))
    else {
        // #1581 review: in CI a missing sibling is a broken job, not a pass. The
        // CI steps that run this test build nrfd and smfd first.
        assert!(
            std::env::var_os("CI").is_none(),
            "nextgcore-nrfd / nextgcore-smfd are not built next to nextgcore-eesd ({EESD}); \
             build them first (`cargo build --bin nextgcore-nrfd --bin nextgcore-smfd`)"
        );
        eprintln!(
            "SKIPPED: nextgcore-nrfd / nextgcore-smfd are not built next to nextgcore-eesd \
             (`cargo test --workspace` builds them)"
        );
        return;
    };
    let trust =
        TempDir(std::env::temp_dir().join(format!("eesd-1529-trust-{}", std::process::id())));
    std::fs::create_dir_all(&trust.0).unwrap();
    let trust = &trust.0;

    let pki = dev_pki();
    let nrf = nrfd(&nrfd_bin, "eesd-1529-token", trust, &pki).await;
    let smf = smfd(&smfd_bin, "eesd-1529-token", nrf.port(), trust, &pki).await;
    smf_registered(&smf).await;

    // Token arm: held, never refused. The AF registers (and its CCA key is
    // trusted) under the eesId its certificate names.
    let (ees, metrics) = eesd(
        "eesd-1529-token",
        smf.port(),
        Arm::Token(nrf.port(), trust, &pki),
    )
    .await;
    let body = scrape_until(metrics, &ees, |b| sample(b, SUBSCRIBED) == Some(1.0)).await;
    assert_eq!(sample(&body, REFUSED).unwrap_or(0.0), 0.0, "{body}");
    assert_eq!(sample(&body, NO_TOKEN).unwrap_or(0.0), 0.0, "{body}");
    let log = ees.log();
    assert!(
        log.contains(&format!(
            "registered at the NRF as AF nfInstanceId {EES_ID}"
        )),
        "{log}"
    );
    drop(ees);

    // An NRF that issues no token (no client authentication): nothing is sent
    // bare, the failure is counted as no-token, nothing is held.
    let (no_cca, metrics) = eesd("eesd-1529-nocca", smf.port(), Arm::NoCca(nrf.port(), &pki)).await;
    let body = scrape_until(metrics, &no_cca, |b| {
        sample(b, NO_TOKEN).unwrap_or(0.0) >= 1.0
    })
    .await;
    assert_eq!(sample(&body, SUBSCRIBED), Some(0.0), "{body}");
    assert_eq!(
        sample(&body, REFUSED).unwrap_or(0.0),
        0.0,
        "never sent bare: {body}"
    );
    drop(no_cca);

    // No token source: the same SMF refuses, nothing is held.
    let (bare, metrics) = eesd("eesd-1529-bare", smf.port(), Arm::Bare).await;
    let body = scrape_until(metrics, &bare, |b| sample(b, REFUSED).unwrap_or(0.0) >= 1.0).await;
    assert_eq!(sample(&body, SUBSCRIBED), Some(0.0), "{body}");
}
