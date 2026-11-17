//! #1534: a real udrd whose subscriber store is unreachable answers every Nudr
//! read that needs it with `500 SYSTEM_FAILURE` (TS 29.500 Table 5.2.7.2-1), not
//! the `404` that tells a UDM the user does not exist (TS 29.504 Table 6.1.7.3-1
//! `USER_NOT_FOUND`).
//!
//! The store here is a held loopback port nothing listens on: udrd soft-fails
//! its startup open and serves with the store never opened (`NotInitialized`).
//! The live-store-goes-down case (`MongoDb` server-selection errors) is
//! `subscriber_store_bound.rs`, which needs docker.
//!
//! REVERT-VERIFIED: with `store_read_failure` answering 404 for every error again,
//! each read answers 404; without the `store_outage` arm in `ue-policy-set`, that
//! read answers 200 `{}`.

use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::test_support::{down_port, NfSpawn};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_read_of_an_unreachable_store_is_a_system_failure_1534() {
    let store = down_port();
    let db_uri = format!("mongodb://127.0.0.1:{}/nextgcore", store.port());
    let udrd = NfSpawn::new(env!("CARGO_BIN_EXE_nextgcore-udrd"), "udrd-1534")
        .ready_when_logged("SBI HTTP/2 server listening on")
        .within(Duration::from_secs(60))
        .spawn_async(|cmd, port, dir| {
            let config = dir.join("udr.yaml");
            std::fs::write(
                &config,
                format!(
                    "db_uri: {db_uri}\nudr:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {port}\n"
                ),
            )
            .unwrap();
            cmd.arg("-c")
                .arg(&config)
                .env("NEXTGCORE_SBI_PROFILE", "dev")
                .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
                .env_remove("NEXTGCORE_SBI_ADVERTISE")
                .env_remove("DB_URI")
                .env("UDR_METRICS_PORT", "0");
        })
        .await;
    let sbi = SbiClient::new(SbiClientConfig::new("127.0.0.1", udrd.port()));
    let supi = "imsi-001010000001534";
    for path in [
        format!(
            "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
        ),
        format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        ),
        format!("/nudr-dr/v2/subscription-data/{supi}/00101/provisioned-data/am-data"),
        format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/sm-data"),
        format!("/nudr-dr/v2/subscription-data/{supi}/identity-data"),
        format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data"),
        format!("/nudr-dr/v2/policy-data/ues/{supi}/ue-policy-set"),
    ] {
        let resp = sbi
            .get(&path)
            .await
            .unwrap_or_else(|e| panic!("{path}: no answer: {e:?}"));
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(
            (resp.status, body["cause"].as_str()),
            (500, Some("SYSTEM_FAILURE")),
            "{path}: {body}"
        );
    }
    drop(store);
}
