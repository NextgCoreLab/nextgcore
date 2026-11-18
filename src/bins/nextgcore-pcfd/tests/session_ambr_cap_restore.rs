//! #1402 review M1: `pcf.policy.session_ambr_cap` is in force for the boot
//! restoration. The real pcfd binary is started on a durable state file holding a
//! demo-capped session whose stored subscribed Session-AMBR (5/7 Mbps) is below its
//! policy (11/22 Mbps). The start-up demo-cap restore (`app::run` ->
//! `pcf_restore_demo_capped_sessions`) re-authorises it through
//! `build_sm_policy_notification`: 5/7 under `subscribed` (and with the setting
//! absent), 11/22 under `none`.
//!
//! Its own test binary: the snapshot is written through this process's
//! `pcf_self()`, which no other test here shares.
//!
//! REVERT-VERIFIED: with `session_ambr_cap::set(..)` deleted from `run()`, the
//! `none` run notifies 5/7.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nextgcore_pcfd::context::{pcf_self, Ambr, DemoAmbrCap, SNssai, SessCreateRequest};
use nextgcore_pcfd::nudr_handler::SessionData;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::test_support::NfSpawn;

type Seen = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

/// Run pcfd on a copy of `snapshot` with `policy` under `pcf:`, and answer the
/// `authSessAmbr` (uplink, downlink) of the restore notify the stub SMF receives.
async fn restored_ambr(
    dir: &std::path::Path,
    snapshot: &std::path::Path,
    tag: &str,
    policy: &str,
    seen: &Seen,
) -> (String, String) {
    seen.lock().unwrap().clear();
    let state = dir.join(format!("pcf-state-{tag}.json"));
    std::fs::copy(snapshot, &state).expect("copy the snapshot");
    // #1521: wait for the SBI listener, and respawn on fresh ports if pcfd loses
    // a probed one to another process (the #1497 race).
    let _pcfd = NfSpawn::new(
        env!("CARGO_BIN_EXE_nextgcore-pcfd"),
        &format!("pcfd-1402-restore-{tag}"),
    )
    .ready_when_logged("SBI HTTP/2 server listening on")
    .spawn_async(|cmd, sbi_port, scratch| {
        let config = scratch.join("pcf.yaml");
        std::fs::write(
            &config,
            format!(
                "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {sbi_port}\n{policy}"
            ),
        )
        .unwrap();
        cmd.arg("-c")
            .arg(&config)
            .arg("--state-file")
            .arg(&state)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            // An ephemeral metrics port: /metrics is not under test here.
            .env("PCF_METRICS_PORT", "0");
    })
    .await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let notify = loop {
        if let Some(n) = seen
            .lock()
            .unwrap()
            .iter()
            .find(|(uri, _)| uri.ends_with("/sm-policy-notify/6/update"))
            .cloned()
        {
            break n;
        }
        assert!(
            Instant::now() < deadline,
            "{tag}: the restarted pcfd sent no UpdateNotify for the capped session"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let rule = notify.1["smPolicyDecision"]["sessRules"]
        .as_object()
        .and_then(|r| r.values().next().cloned())
        .expect("a session rule");
    (
        rule["authSessAmbr"]["uplink"].as_str().unwrap().to_string(),
        rule["authSessAmbr"]["downlink"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_boot_restoration_authorises_under_the_configured_cap_1402() {
    let seen: Seen = Arc::default();
    let sink = seen.clone();
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let smf =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    smf.start(move |req: SbiRequest| {
        let sink = sink.clone();
        async move {
            let body = req
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or_default();
            sink.lock().unwrap().push((req.header.uri.clone(), body));
            SbiResponse::with_status(204)
        }
    })
    .await
    .expect("stub SMF");

    // The snapshot: one demo-capped session, policy 11/22 Mbps (no MongoDB here,
    // so the re-evaluation falls back to the stored session data), subscribed 5/7.
    let dir = std::env::temp_dir().join(format!("pcfd-1402-restore-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let snapshot = dir.join("pcf-state.json");
    let _ = std::fs::remove_file(&snapshot);
    nextgcore_pcfd::test_support::init_context();
    pcf_self()
        .write()
        .unwrap()
        .set_state_file(snapshot.clone())
        .expect("fresh state file");
    {
        let ctx = pcf_self();
        let ctx = ctx.read().unwrap();
        let mut sess = ctx
            .sess_create_for_supi(&SessCreateRequest {
                supi: "imsi-001010000140299",
                psi: 6,
                dnn: "internet",
                s_nssai: SNssai { sst: 1, sd: None },
                origination_ms: None,
            })
            .expect("session")
            .sess;
        sess.notification_uri = Some(format!(
            "http://127.0.0.1:{}/nsmf-callback/v1/sm-policy-notify/6",
            addr.port()
        ));
        sess.authorised_session_data = Some(SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 11_000_000,
            ambr_downlink: 22_000_000,
            pcc_rules: vec![],
        });
        sess.subscribed_sess_ambr = Some(Ambr {
            uplink: "5 Mbps".into(),
            downlink: "7 Mbps".into(),
        });
        sess.demo_ambr_cap = Some(DemoAmbrCap {
            writer: "d441a-congestion-loop".into(),
            uplink_bps: 1_000_000,
            downlink_bps: 1_000_000,
            generation: 1,
        });
        assert!(ctx.sess_update(&sess));
    }
    assert!(snapshot.exists(), "the snapshot was written");

    let capped = ("5 Mbps".to_string(), "7 Mbps".to_string());
    let uncapped = ("11 Mbps".to_string(), "22 Mbps".to_string());
    assert_eq!(
        restored_ambr(
            &dir,
            &snapshot,
            "none",
            "  policy:\n    session_ambr_cap: none\n",
            &seen
        )
        .await,
        uncapped,
        "under none the restore authorises the policy value"
    );
    assert_eq!(
        restored_ambr(
            &dir,
            &snapshot,
            "subscribed",
            "  policy:\n    session_ambr_cap: subscribed\n",
            &seen
        )
        .await,
        capped,
        "under subscribed the restore is capped by the stored subscribed value"
    );
    assert_eq!(
        restored_ambr(&dir, &snapshot, "absent", "", &seen).await,
        capped,
        "the default is subscribed"
    );
    smf.stop().await.ok();
}
