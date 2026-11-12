//! nextgsim#465 review round 2, MINOR 3: the real pcfd binary, started on a
//! durable state file that holds a demo-capped session, tells the SMF the
//! subscribed Session-AMBR again at start-up (`app::run` calls
//! `pcf_restore_demo_capped_sessions`). Runs in every build: a default build may
//! restore a snapshot a demo build wrote.
//!
//! REVERT-VERIFIED: removing the `pcf_restore_demo_capped_sessions()` call from
//! `app::run` times the wait for the notify out.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nextgcore_pcfd::context::{pcf_context_init, pcf_self, DemoAmbrCap, SNssai, SessCreateRequest};
use nextgcore_pcfd::nudr_handler::SessionData;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_pcfd_restores_a_demo_capped_session() {
    // The stub SMF: records every POST.
    let seen: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::default();
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

    // The snapshot a demo build left behind: one session, capped at 1 Mbps.
    let dir = std::env::temp_dir().join(format!("pcfd-465-restore-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("pcf-state.json");
    let _ = std::fs::remove_file(&state);
    pcf_context_init(64, 64);
    pcf_self()
        .write()
        .unwrap()
        .set_state_file(state.clone())
        .expect("fresh state file");
    {
        let ctx = pcf_self();
        let ctx = ctx.read().unwrap();
        let mut sess = ctx
            .sess_create_for_supi(&SessCreateRequest {
                supi: "imsi-001010000465099",
                psi: 5,
                dnn: "internet",
                s_nssai: SNssai { sst: 1, sd: None },
                origination_ms: None,
            })
            .expect("session")
            .sess;
        sess.notification_uri = Some(format!(
            "http://127.0.0.1:{}/nsmf-callback/v1/sm-policy-notify/5",
            addr.port()
        ));
        // No MongoDB in this test: the re-evaluation falls back to the stored
        // session data, the subscribed 11/22 Mbps.
        sess.authorised_session_data = Some(SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 11_000_000,
            ambr_downlink: 22_000_000,
            pcc_rules: vec![],
        });
        sess.demo_ambr_cap = Some(DemoAmbrCap {
            writer: "d441a-congestion-loop".into(),
            uplink_bps: 1_000_000,
            downlink_bps: 1_000_000,
        });
        assert!(ctx.sess_update(&sess));
    }
    assert!(state.exists(), "the snapshot was written");

    let sbi_port = nextgcore_sbi::test_support::free_port();
    let config = dir.join("pcf.yaml");
    std::fs::write(
        &config,
        format!(
            "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {sbi_port}\n"
        ),
    )
    .unwrap();
    let _pcfd = Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"))
            .arg("-c")
            .arg(&config)
            .arg("--state-file")
            .arg(&state)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env(
                "PCF_METRICS_PORT",
                nextgcore_sbi::test_support::free_port().to_string(),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pcfd"),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let notify = loop {
        if let Some(n) = seen
            .lock()
            .unwrap()
            .iter()
            .find(|(uri, _)| uri.ends_with("/sm-policy-notify/5/update"))
            .cloned()
        {
            break n;
        }
        assert!(
            Instant::now() < deadline,
            "the restarted pcfd sent no UpdateNotify for the capped session"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let rule = notify.1["smPolicyDecision"]["sessRules"]
        .as_object()
        .and_then(|r| r.values().next().cloned())
        .expect("a session rule");
    assert_eq!(rule["authSessAmbr"]["uplink"], "11 Mbps");
    assert_eq!(rule["authSessAmbr"]["downlink"], "22 Mbps");
    smf.stop().await.ok();
}
