//! #940 review M1: the subscriber's `nfStatusNotificationUri` can carry a bearer
//! token (the AMF's does, `.../nf-status-notify/{token}`). nrfd must not write it
//! to its log: not when the notification is delivered, refused, or fails.
//!
//! An integration test, so it runs in its own process and can install the one
//! global `log` logger.

use std::sync::Mutex;

use nextgcore_nrfd::nnrf_build::NotificationEventType;
use nextgcore_nrfd::nnrf_handler::{NfProfile, SubscriptionData};
use nextgcore_nrfd::sbi_path::{nrf_nnrf_nfm_send_nf_status_notify_async, NotifySendResult};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};

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

const TOKEN: &str = "940deadbeef0123456789abcdef0940";

fn subscription(uri: String) -> SubscriptionData {
    SubscriptionData {
        id: "sub-940".to_string(),
        req_nf_type: Some("AMF".to_string()),
        req_nf_instance_id: None,
        notification_uri: uri,
        subscr_cond: None,
        validity_duration: 3600,
        req_notif_events: None,
        notif_condition: None,
    }
}

#[tokio::test]
async fn the_callback_token_never_reaches_the_log() {
    log::set_boxed_logger(Box::new(Capture)).expect("the only logger");
    log::set_max_level(log::LevelFilter::Trace);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let profile = NfProfile::from_json(&serde_json::json!({
        "nfInstanceId": "6680a6c8-0000-4000-8000-000000000940",
        "nfType": "SMF",
        "nfStatus": "REGISTERED",
    }))
    .expect("profile");

    // Delivered (204), refused (403), and failed (nothing listening).
    for status in [204u16, 403] {
        let (_server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: SbiRequest| async move { SbiResponse::with_status(status) },
        )
        .await;
        let sub = subscription(format!(
            "http://{addr}/namf-callback/v1/nf-status-notify/{TOKEN}"
        ));
        let sent = nrf_nnrf_nfm_send_nf_status_notify_async(
            &sub,
            NotificationEventType::NfDeregistered,
            &profile,
            "http://127.0.0.1:7777",
        )
        .await;
        assert_eq!(matches!(sent, NotifySendResult::Success), status == 204);
    }
    // A port that refuses for certain: a dropped probe listener's port could be handed
    // to another listener meanwhile, which would then answer the notify.
    let closed = nextgcore_sbi::test_support::refused_addr();
    let sub = subscription(format!(
        "http://{closed}/namf-callback/v1/nf-status-notify/{TOKEN}"
    ));
    let sent = nrf_nnrf_nfm_send_nf_status_notify_async(
        &sub,
        NotificationEventType::NfDeregistered,
        &profile,
        "http://127.0.0.1:7777",
    )
    .await;
    assert!(!matches!(sent, NotifySendResult::Success));

    let lines = LINES.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let leaked: Vec<&String> = lines.iter().filter(|l| l.contains(TOKEN)).collect();
    assert!(leaked.is_empty(), "the token was logged:\n{leaked:#?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("nf-status-notify/<redacted>")),
        "the notifications are still logged, redacted: {lines:#?}"
    );
}
