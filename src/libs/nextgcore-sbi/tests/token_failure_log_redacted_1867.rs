//! #1867: when an OAuth2 token cannot be obtained, the client refuses the request
//! and logs it. The request URI can be a callback carrying the notified NF's
//! token (`.../dereg-notify/{token}`, #753), so that log line must show it
//! redacted, as every other client log path already does (#940).
//!
//! An integration test, so it runs in its own process and can install the one
//! global `log` logger.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::message::SbiRequest;
use nextgcore_sbi::oauth::OAuth2Client;
use nextgcore_sbi::security::{set_sbi_profile_override, SbiProfile};
use nextgcore_sbi::types::NfType;

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        LINES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(format!("{} {}", record.level(), record.args()));
    }
    fn flush(&self) {}
}

const TOKEN: &str = "1867deadbeef0123456789abcdef1867";

#[tokio::test]
async fn a_failed_token_fetch_logs_the_callback_uri_redacted_1867() {
    log::set_boxed_logger(Box::new(Capture)).expect("the only logger");
    log::set_max_level(log::LevelFilter::Trace);
    // Loopback cleartext peers: the dev profile.
    set_sbi_profile_override(SbiProfile::Dev);

    // An NRF that refuses connections, so the token fetch fails for certain.
    let nrf = nextgcore_sbi::test_support::refused_addr();
    let oauth2 = Arc::new(OAuth2Client::new(
        format!("http://{nrf}"),
        "6b1d7e3c-0000-4000-8000-000000001867",
        NfType::Udm,
    ));
    let amf = nextgcore_sbi::test_support::refused_addr();
    let client = SbiClient::new(
        SbiClientConfig::new(amf.ip().to_string(), amf.port())
            .with_connect_timeout(Duration::from_millis(500))
            .with_request_timeout(Duration::from_millis(500)),
    )
    .with_oauth2(oauth2, NfType::Amf);

    let uri = format!("/namf-callback/v1/imsi-001010000001867/dereg-notify/{TOKEN}");
    let sent = client.send_request(SbiRequest::post(&uri)).await;
    assert!(sent.is_err(), "no token, no request");

    let lines = LINES.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let refusal: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("OAuth2 token acquisition failed"))
        .collect();
    assert!(
        !refusal.is_empty(),
        "the refusal is still logged: {lines:#?}"
    );
    assert!(
        refusal
            .iter()
            .all(|l| l.contains("dereg-notify/<redacted>")),
        "the refusal names the request, redacted: {refusal:#?}"
    );
    let leaked: Vec<&String> = lines.iter().filter(|l| l.contains(TOKEN)).collect();
    assert!(
        leaked.is_empty(),
        "the callback token was logged:\n{leaked:#?}"
    );
}
