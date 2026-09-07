//! Nudm_SDM Data Change Notification and Nudm_EE Event Occurrence producers
//! (TS 29.503 §5.2.2.5.2, §5.5.2.5).
//!
//! Before this module the UDM's event-exposure surfaces were facades: a consumer
//! could `POST` an `SdmSubscription` or an `EeSubscription`, receive `201`, and
//! then hear nothing ever again, because no code path in the crate produced a
//! notification. `lib.rs` and `context.rs` both carried comments admitting it.
//!
//! # What triggers a notification
//!
//! The UDM is mostly a read-through to the UDR, so it observes few writes of its
//! own. The ones it does observe are the UECM lifecycle transitions — an AMF or
//! SMF registering, updating or deregistering a UE — and those *are* changes to a
//! monitored SDM resource (the UE's context data set) as well as EE-reportable
//! events. Both producers therefore hook the same sites in `uecm.rs`, which is
//! coherent rather than coincidental: one transition, two audiences.
//!
//! [`notify_ue_context_change`] is the entry point, and is deliberately shaped so
//! any future data-set write can call it without knowing about subscriptions.

use serde_json::{json, Value};

/// Env switch to silence both producers.
///
/// Default **on**. An off-by-default producer would leave the gap open for every
/// deployment that did not know to flip it, and the usual argument for gating new
/// outbound traffic does not apply here: a notification is only ever sent to a
/// `callbackReference` a consumer explicitly subscribed with, so a deployment that
/// subscribes to nothing sees no new traffic at all. The switch exists for the
/// case where a consumer subscribes and then cannot cope with being notified.
const NOTIFY_DISABLE_ENV: &str = "UDM_NOTIFY_DISABLE";

/// Are the notification producers enabled?
pub fn notifications_enabled() -> bool {
    !matches!(
        std::env::var(NOTIFY_DISABLE_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// The UECM transition that occurred, as both an SDM changed-resource and an EE
/// event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UeContextEvent {
    /// An AMF registered for 3GPP access (TS 29.503 §5.3.2.2.2).
    AmfRegistered,
    /// A registered AMF context was updated.
    AmfContextUpdated,
    /// The AMF deregistered (§5.3.2.3.2).
    AmfDeregistered,
    /// An SMF registered a PDU session (§5.3.2.2.4).
    SmfRegistered,
    /// An SMF deregistered its PDU session(s).
    SmfDeregistered,
}

impl UeContextEvent {
    /// The SDM data set this transition changes, as the resource-URI suffix a
    /// subscriber's `monitoredResourceUris` would name.
    ///
    /// AMF transitions change the UE's AMF context data set; SMF transitions
    /// change the SMF one. Reporting a single catch-all resource instead would
    /// wake every subscriber on every transition.
    pub fn changed_data_set(&self) -> &'static str {
        match self {
            Self::AmfRegistered | Self::AmfContextUpdated | Self::AmfDeregistered => {
                "ue-context-in-amf-data"
            }
            Self::SmfRegistered | Self::SmfDeregistered => "ue-context-in-smf-data",
        }
    }

    /// The Nudm_EE event type (TS 29.503 `EventType`) this transition reports as.
    pub fn ee_event_type(&self) -> &'static str {
        match self {
            // A UE whose AMF context appears or is refreshed is reachable; one
            // whose AMF context is gone is not (TS 29.503 EventType
            // UE_REACHABILITY_FOR_DATA / LOSS_OF_CONNECTIVITY).
            Self::AmfRegistered | Self::AmfContextUpdated => "UE_REACHABILITY_FOR_DATA",
            Self::AmfDeregistered => "LOSS_OF_CONNECTIVITY",
            Self::SmfRegistered | Self::SmfDeregistered => "PDN_CONNECTIVITY_STATUS",
        }
    }

    /// Is this transition a deregistration? Used only for the report's own
    /// human-readable framing, never for routing.
    fn is_removal(&self) -> bool {
        matches!(self, Self::AmfDeregistered | Self::SmfDeregistered)
    }
}

/// Build the `ModificationNotification` body (TS 29.503 §6.1.6.2.x).
///
/// `notifyItems` carries one `NotifyItem` per changed resource, each with the
/// resource's identifier and a `changes` list of RFC 7396-shaped `ChangeItem`s.
pub fn build_modification_notification(supi: &str, event: UeContextEvent) -> Value {
    let resource_id = format!("/nudm-sdm/v2/{supi}/{}", event.changed_data_set());
    json!({
        "notifyItems": [{
            "resourceId": resource_id,
            "changes": [{
                // RFC 7396 op names, as ChangeItem uses (TS 29.571).
                "op": if event.is_removal() { "REMOVE" } else { "REPLACE" },
                "path": format!("/{}", event.changed_data_set()),
            }],
        }],
    })
}

/// Build the `MonitoringReport` body (TS 29.503 §6.4.6.2.x).
pub fn build_monitoring_report(
    supi: &str,
    subscription_id: &str,
    event: UeContextEvent,
    timestamp: &str,
) -> Value {
    json!({
        "reportList": [{
            "referenceId": subscription_id,
            "eventType": event.ee_event_type(),
            "report": {
                "supi": supi,
                "timeStamp": timestamp,
            },
        }],
    })
}

/// Format `secs` since the Unix epoch as an RFC 3339 UTC timestamp.
///
/// Hand-rolled rather than pulling in a date/time crate, matching what nrfd
/// already does for the same reason (`epoch_to_rfc3339`).
pub fn epoch_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Deliver SDM and EE notifications for a UECM transition.
///
/// Best-effort by design: a subscriber that is down must not fail the UECM
/// operation that triggered the notification, so every delivery failure is logged
/// and the next subscriber is still attempted. Returns
/// `(sdm_delivered, ee_delivered)` so a caller — and a test — can see what
/// actually went out rather than assuming.
pub async fn notify_ue_context_change(supi: &str, event: UeContextEvent) -> (usize, usize) {
    if !notifications_enabled() {
        log::debug!("{NOTIFY_DISABLE_ENV} is set; not notifying for {supi} ({event:?})");
        return (0, 0);
    }

    let ctx = crate::context::udm_self();
    let (sdm_subs, ee_subs) = match ctx.read() {
        Ok(context) => (
            context.sdm_subscriptions_for_supi(supi),
            context.ee_subscriptions_for_supi(supi),
        ),
        Err(_) => {
            log::error!("UDM context lock poisoned; cannot notify for {supi}");
            return (0, 0);
        }
    };
    // The guard is dropped here, before any `.await`: holding the context lock
    // across an outbound HTTP call would deadlock the subscribe path.
    drop(ctx);

    let mut sdm_delivered = 0usize;
    let changed = event.changed_data_set();
    for sub in &sdm_subs {
        // TS 29.503 §5.2.2.5.2: notify only the resources the subscriber asked
        // to monitor. An empty list is treated as "everything for this UE" —
        // subscribing to a UE with no resource list is a whole-UE subscription,
        // not a subscription to nothing.
        if !sub.monitored_resource_uris.is_empty()
            && !sub
                .monitored_resource_uris
                .iter()
                .any(|uri| uri.contains(changed))
        {
            log::debug!(
                "SDM subscription {} does not monitor {changed}; not notified",
                sub.id
            );
            continue;
        }
        let Some(callback) = sub.callback_reference.as_deref() else {
            log::warn!("SDM subscription {} has no callbackReference", sub.id);
            continue;
        };
        let body = build_modification_notification(supi, event);
        match crate::sbi_path::udm_sbi_send_callback_notification(callback, &body).await {
            Ok(resp) => {
                log::info!(
                    "SDM ModificationNotification for {supi} ({changed}) -> {callback}: status={}",
                    resp.status
                );
                sdm_delivered += 1;
            }
            Err(e) => log::warn!("SDM ModificationNotification to {callback} failed: {e}"),
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = epoch_to_rfc3339(now);
    let mut ee_delivered = 0usize;
    for sub in &ee_subs {
        let body = build_monitoring_report(supi, &sub.id, event, &timestamp);
        match crate::sbi_path::udm_sbi_send_callback_notification(&sub.callback_reference, &body)
            .await
        {
            Ok(resp) => {
                log::info!(
                    "EE MonitoringReport ({}) for {supi} -> {}: status={}",
                    event.ee_event_type(),
                    sub.callback_reference,
                    resp.status
                );
                ee_delivered += 1;
            }
            Err(e) => log::warn!(
                "EE MonitoringReport to {} failed: {e}",
                sub.callback_reference
            ),
        }
    }

    (sdm_delivered, ee_delivered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{udm_context_init, udm_self, UdmEeSubscription, UdmSdmSubscription};
    use nextgcore_sbi::message::{SbiRequest, SbiResponse};
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::sync::{Arc, Mutex};

    /// The crate-wide serializer, not a lock of our own.
    ///
    /// Three separate pieces of process-global state are in play: the UDM context
    /// these tests insert subscriptions into, the `UDM_NOTIFY_DISABLE` env var, and
    /// the SBI profile override — which `app.rs`'s
    /// `test_http_generate_auth_data_flows` also sets. A private lock only
    /// serialized these tests against EACH OTHER, so that sibling could still flip
    /// the profile to production between our stub starting and our POST going out;
    /// the failure showed up roughly one run in four as an "HTTP/2 connection
    /// error" that reads as the producer sending nothing. `CONTEXT_GUARD` is the
    /// lock that sibling already takes.
    fn notify_env_lock() -> &'static Mutex<()> {
        &crate::test_support::CONTEXT_GUARD
    }

    /// A stub consumer that records every notification body it is POSTed.
    ///
    /// The returned `SbiServer` must be held: dropping it closes the listener and
    /// every delivery then fails with connection-refused, which looks exactly
    /// like the producer not sending anything.
    async fn stub_callback() -> (SbiServer, String, Arc<Mutex<Vec<serde_json::Value>>>) {
        // Declared, not inherited: these tests drive the production peer-call path
        // against a loopback PLAINTEXT stub, i.e. a dev-profile deployment (issue
        // #63). The override is process-global and `test_http_generate_auth_data_flows`
        // in app.rs sets it without resetting, so before declaring it here these
        // tests passed or failed on TEST ORDER — inheriting TLS when they ran
        // first and plaintext when they ran after it. The symptom was an
        // "HTTP/2 connection error" that reads as the producer sending nothing.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let addr = nextgcore_sbi::test_support::ephemeral_addr();
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(body) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                            sink.lock().expect("sink").push(v);
                        }
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("stub callback starts");
        // `start` spawns the accept loop, so wait for the port to accept before
        // returning: otherwise the first POST races the listener and the test
        // reads as "nothing was sent".
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let uri = format!("http://127.0.0.1:{}/callback", addr.port());
        (server, uri, seen)
    }

    /// Drop every subscription that could reach `supi`, so each test starts from
    /// a known state.
    ///
    /// `udm_context_init` does not reset the process-global context, and these
    /// tests share it. Without this the `anyUE` EE subscription one of them
    /// inserts would leak into the others' delivery counts — they would pass or
    /// fail on test ORDER, which is the recorded process-global hazard in this
    /// repo. Cleaning up front rather than at the end also survives a test that
    /// panics part-way.
    fn clear_subscriptions_for(supi: &str) {
        let ctx = udm_self();
        let Ok(guard) = ctx.read() else { return };
        for sub in guard.sdm_subscriptions_for_supi(supi) {
            guard.sdm_subscription_remove(&sub.id);
        }
        for sub in guard.ee_subscriptions_for_supi(supi) {
            guard.ee_subscription_remove(&sub.id);
        }
    }

    async fn wait_for(
        seen: &Arc<Mutex<Vec<serde_json::Value>>>,
        want: usize,
    ) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            {
                let got = seen.lock().expect("sink");
                if got.len() >= want {
                    return got.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        seen.lock().expect("sink").clone()
    }

    #[test]
    fn ue_context_events_map_to_their_data_set_and_ee_event_type() {
        // AMF transitions change the AMF context data set, SMF ones the SMF data
        // set. A single catch-all resource would wake every subscriber on every
        // transition.
        assert_eq!(
            UeContextEvent::AmfRegistered.changed_data_set(),
            "ue-context-in-amf-data"
        );
        assert_eq!(
            UeContextEvent::AmfDeregistered.changed_data_set(),
            "ue-context-in-amf-data"
        );
        assert_eq!(
            UeContextEvent::SmfRegistered.changed_data_set(),
            "ue-context-in-smf-data"
        );
        assert_ne!(
            UeContextEvent::AmfRegistered.changed_data_set(),
            UeContextEvent::SmfRegistered.changed_data_set()
        );

        // Reachability appearing and being lost are different EE events; the same
        // value for both would make the report useless.
        assert_eq!(
            UeContextEvent::AmfRegistered.ee_event_type(),
            "UE_REACHABILITY_FOR_DATA"
        );
        assert_eq!(
            UeContextEvent::AmfDeregistered.ee_event_type(),
            "LOSS_OF_CONNECTIVITY"
        );
        assert_ne!(
            UeContextEvent::AmfRegistered.ee_event_type(),
            UeContextEvent::AmfDeregistered.ee_event_type()
        );
    }

    #[test]
    fn notification_bodies_carry_the_spec_shapes() {
        let m =
            build_modification_notification("imsi-001010000000001", UeContextEvent::AmfRegistered);
        let item = &m["notifyItems"][0];
        assert_eq!(
            item["resourceId"], "/nudm-sdm/v2/imsi-001010000000001/ue-context-in-amf-data",
            "the resourceId must be the v2 SDM path the subscriber monitors: {m}"
        );
        assert_eq!(item["changes"][0]["op"], "REPLACE");
        // A deregistration is a removal, not a replacement.
        let d = build_modification_notification("imsi-1", UeContextEvent::AmfDeregistered);
        assert_eq!(d["notifyItems"][0]["changes"][0]["op"], "REMOVE");

        let r = build_monitoring_report(
            "imsi-001010000000001",
            "sub-9",
            UeContextEvent::AmfDeregistered,
            "2026-09-07T12:00:00Z",
        );
        let report = &r["reportList"][0];
        assert_eq!(report["referenceId"], "sub-9");
        assert_eq!(report["eventType"], "LOSS_OF_CONNECTIVITY");
        assert_eq!(report["report"]["supi"], "imsi-001010000000001");
        assert_eq!(report["report"]["timeStamp"], "2026-09-07T12:00:00Z");
    }

    #[test]
    fn epoch_to_rfc3339_formats_utc() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day, which an off-by-one in the civil-date conversion gets wrong.
        assert_eq!(epoch_to_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    /// Criteria 2 and 5 together: a real monitored-resource change delivers a
    /// ModificationNotification to an SDM subscriber and a MonitoringReport to an
    /// EE subscriber, at their actual callback URIs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn a_ue_context_change_notifies_sdm_and_ee_subscribers() {
        let _serial = notify_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        udm_context_init(64, 64);
        let supi = "imsi-001010000000083";
        clear_subscriptions_for(supi);

        let (_sdm_server, sdm_uri, sdm_seen) = stub_callback().await;
        let (_ee_server, ee_uri, ee_seen) = stub_callback().await;

        {
            let ctx = udm_self();
            let guard = ctx.read().expect("context");
            guard.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                supi,
                Some("nf-1".to_string()),
                Some(sdm_uri.clone()),
                vec![format!("/nudm-sdm/v2/{supi}/ue-context-in-amf-data")],
            ));
            guard.ee_subscription_insert(UdmEeSubscription::for_ue(
                supi,
                ee_uri.clone(),
                r#"{"callbackReference":"x","monitoringConfigurations":{}}"#,
            ));
        }

        let (sdm, ee) = notify_ue_context_change(supi, UeContextEvent::AmfRegistered).await;
        assert_eq!(sdm, 1, "the SDM subscriber must be notified");
        assert_eq!(ee, 1, "the EE subscriber must be notified");

        let sdm_bodies = wait_for(&sdm_seen, 1).await;
        assert_eq!(sdm_bodies.len(), 1, "got {sdm_bodies:?}");
        assert_eq!(
            sdm_bodies[0]["notifyItems"][0]["resourceId"],
            format!("/nudm-sdm/v2/{supi}/ue-context-in-amf-data")
        );

        let ee_bodies = wait_for(&ee_seen, 1).await;
        assert_eq!(ee_bodies.len(), 1, "got {ee_bodies:?}");
        assert_eq!(
            ee_bodies[0]["reportList"][0]["eventType"],
            "UE_REACHABILITY_FOR_DATA"
        );
        assert_eq!(ee_bodies[0]["reportList"][0]["report"]["supi"], supi);
    }

    /// A subscription monitoring a DIFFERENT data set is not notified — otherwise
    /// `monitoredResourceUris` would be decoration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn monitored_resource_uris_narrow_the_sdm_notification() {
        let _serial = notify_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        udm_context_init(64, 64);
        let supi = "imsi-001010000000084";
        clear_subscriptions_for(supi);
        let (_server, uri, seen) = stub_callback().await;

        {
            let ctx = udm_self();
            let guard = ctx.read().expect("context");
            guard.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                supi,
                Some("nf-1".to_string()),
                Some(uri.clone()),
                // Monitors the SMF data set only.
                vec![format!("/nudm-sdm/v2/{supi}/ue-context-in-smf-data")],
            ));
        }

        // An AMF transition must not reach it...
        let (sdm, _) = notify_ue_context_change(supi, UeContextEvent::AmfRegistered).await;
        assert_eq!(
            sdm, 0,
            "a subscriber monitoring smf-data must not be woken by an AMF change"
        );
        assert!(seen.lock().expect("sink").is_empty());

        // ...but an SMF transition must.
        let (sdm, _) = notify_ue_context_change(supi, UeContextEvent::SmfRegistered).await;
        assert_eq!(sdm, 1);
        assert_eq!(wait_for(&seen, 1).await.len(), 1);
    }

    /// A subscription for a different SUPI is never notified, and `anyUE` EE
    /// subscriptions are.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn notifications_are_scoped_to_the_right_subscriber() {
        let _serial = notify_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        udm_context_init(64, 64);
        clear_subscriptions_for("imsi-001010000000085");
        clear_subscriptions_for("imsi-001010000000999");
        let (_server, uri, seen) = stub_callback().await;

        {
            let ctx = udm_self();
            let guard = ctx.read().expect("context");
            // SDM subscription for a DIFFERENT UE.
            guard.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                "imsi-001010000000999",
                Some("nf-1".to_string()),
                Some(uri.clone()),
                Vec::new(),
            ));
            // EE subscription scoped to every UE.
            guard.ee_subscription_insert(UdmEeSubscription::for_ue("anyUE", uri.clone(), "{}"));
        }

        let (sdm, ee) =
            notify_ue_context_change("imsi-001010000000085", UeContextEvent::AmfRegistered).await;
        assert_eq!(sdm, 0, "another UE's SDM subscription must not be notified");
        assert_eq!(ee, 1, "an anyUE EE subscription covers every UE");
        assert_eq!(wait_for(&seen, 1).await.len(), 1);

        // An anyUE subscription reaches every SUPI, so it must not outlive this
        // test regardless of what runs next.
        clear_subscriptions_for("imsi-001010000000085");
        clear_subscriptions_for("imsi-001010000000999");
    }

    /// An SDM subscription with an EMPTY monitoredResourceUris is a whole-UE
    /// subscription, not a subscription to nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn an_empty_monitored_list_is_a_whole_ue_subscription() {
        let _serial = notify_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        udm_context_init(64, 64);
        let supi = "imsi-001010000000086";
        clear_subscriptions_for(supi);
        let (_server, uri, seen) = stub_callback().await;
        {
            let ctx = udm_self();
            let guard = ctx.read().expect("context");
            guard.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                supi,
                Some("nf-1".to_string()),
                Some(uri.clone()),
                Vec::new(),
            ));
        }
        let (sdm, _) = notify_ue_context_change(supi, UeContextEvent::SmfRegistered).await;
        assert_eq!(sdm, 1);
        assert_eq!(wait_for(&seen, 1).await.len(), 1);
    }

    /// The off switch silences both producers, and is off-by-default.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn the_disable_switch_silences_both_producers() {
        let _serial = notify_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-001010000000087";
        clear_subscriptions_for(supi);
        let (_server, uri, seen) = stub_callback().await;
        {
            let ctx = udm_self();
            let guard = ctx.read().expect("context");
            guard.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                supi,
                Some("nf-1".to_string()),
                Some(uri.clone()),
                Vec::new(),
            ));
            guard.ee_subscription_insert(UdmEeSubscription::for_ue(supi, uri.clone(), "{}"));
        }

        std::env::remove_var("UDM_NOTIFY_DISABLE");
        assert!(
            notifications_enabled(),
            "the producers are on by default: an off-by-default producer leaves \
             the gap open for anyone who does not know to flip it"
        );

        std::env::set_var("UDM_NOTIFY_DISABLE", "1");
        assert!(!notifications_enabled());
        let (sdm, ee) = notify_ue_context_change(supi, UeContextEvent::AmfRegistered).await;
        assert_eq!((sdm, ee), (0, 0));
        assert!(
            seen.lock().expect("sink").is_empty(),
            "nothing may go out while the switch is set"
        );
        std::env::remove_var("UDM_NOTIFY_DISABLE");
    }
}
