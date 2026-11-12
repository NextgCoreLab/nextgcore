//! AMF-detected Nudm_EE events, subscribed at the serving AMF (#1440).
//!
//! TS 23.502 §4.15.3.2.3 step 3a (`23502-k20.txt:29103-29108`): *"If the
//! requested event (e.g. monitoring of Loss of Connectivity) requires AMF
//! assistance, then the UDM sends the Namf_EventExposure_Subscribe to the AMF
//! serving the requested user."* The AMF then notifies the NEF directly (steps
//! 4-6), so the report carries what only the AMF knows, such as the TS 29.518
//! `lossOfConnectReason`, and fires on every trigger the AMF detects (the
//! mobile-reachable timer as well as deregistration), not only the UECM purge.
//!
//! The UDM *"shall additionally provide the notification endpoint of itself"*
//! (`:29115-29119`) so it hears about subscription changes: on an AMF change the
//! new AMF takes the subscription over and reports its new id there
//! (`SUBSCRIPTION_ID_CHANGE`, TS 29.518 §5.2.2.2.3.1).
//!
//! # What this module owns
//!
//! One [`AmfEeLeg`] per Nudm_EE subscription, reconciled against what the
//! subscription asks for (events, callback) and where the UE is served
//! ([`reconcile`]). Reconciles run **after** the triggering operation answered
//! ([`spawn_reconcile`]): at subscribe, at PATCH and at every UECM AMF
//! registration. A consumer's own timeout (nefd's is 3 s) must never be spent
//! waiting on an AMF, and the UECM-derived report covers the gap. Reconciles of
//! one subscription are serialised, so two of them cannot both create a leg.
//!
//! The UDM stops raising an AMF-assisted event itself only while the leg is
//! **confirmed** for the subscription as it is now ([`amf_reports`]): made for
//! its current callback, at the serving AMF. Any other state (none yet, a stale
//! AMF, a changed callback, a refused or unreachable AMF) keeps the
//! UECM-derived fallback, so a consumer may hear a loss twice but never not at
//! all.
//!
//! # Scope
//!
//! Only SUPI-addressed subscriptions are forwarded. `anyUE` and group
//! subscriptions would go to every AMF in the PLMN, and a GPSI one needs the
//! identifier translation this UDM does not do (#85); they keep the fallback.

use crate::context::{udm_self, AmfEeLeg, UdmEeSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::types::NfType;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Nudm_EE event types the AMF detects, with the Namf_EventExposure
/// `AmfEventType` each is subscribed as (TS 29.518 §6.2.6.3.3).
pub const AMF_ASSISTED_EVENTS: &[(&str, &str)] =
    &[("LOSS_OF_CONNECTIVITY", "LOSS_OF_CONNECTIVITY")];

/// The base (`scheme://host:port`) of this UDM's own SBI endpoint, for the
/// `subsChangeNotifyUri` it hands the AMF. Set once at startup from the
/// advertised address ([`set_notify_base`]); `None` when nothing reachable is
/// advertised, in which case no change endpoint is offered.
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`, which every test that makes a
/// UECM registration already holds.
static NOTIFY_BASE: RwLock<Option<String>> = RwLock::new(None);

/// One async lock per EE subscription id, so its reconciles, its subscription
/// changes and its release run one at a time (#1449 review: two concurrent
/// reconciles both saw no leg, both subscribed, and one AMF subscription leaked).
/// Entries are dropped on [`release`].
static LEG_LOCKS: Mutex<Option<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

/// The bound on one AMF call (subscribe or delete), in milliseconds, so a
/// blackholed AMF cannot hold a subscription's reconciles for the client's
/// 30 s default. A subscribe that times out is treated as refused (fallback).
/// Test lock: `CONTEXT_GUARD`.
pub(crate) static AMF_CALL_TIMEOUT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(5_000);

fn amf_call_timeout() -> std::time::Duration {
    std::time::Duration::from_millis(AMF_CALL_TIMEOUT_MS.load(Ordering::Relaxed))
}

/// Spawned reconciles not yet finished. Tests wait for it to reach zero
/// ([`wait_idle`]) instead of sleeping. Test lock: `CONTEXT_GUARD`.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Record this UDM's callback base (`None` to clear).
pub fn set_notify_base(base: Option<String>) {
    if let Ok(mut slot) = NOTIFY_BASE.write() {
        *slot = base;
    }
}

fn notify_base() -> Option<String> {
    NOTIFY_BASE.read().ok().and_then(|b| b.clone())
}

fn leg_lock(id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = LEG_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.get_or_insert_with(HashMap::new)
        .entry(id.to_string())
        .or_default()
        .clone()
}

fn drop_leg_lock(id: &str) {
    let mut map = LEG_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = map.as_mut() {
        map.remove(id);
    }
}

/// How many per-subscription locks exist (tests: the map must not grow from
/// wire input, #1449 review 10).
#[cfg(test)]
fn leg_lock_count() -> usize {
    LEG_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or(0, HashMap::len)
}

/// The stored subscription `id`, if any.
fn find_subscription(id: &str) -> Option<UdmEeSubscription> {
    let ctx = udm_self();
    let guard = ctx.read().ok()?;
    guard.ee_subscription_find_by_id(id)
}

/// Whether `token` is the change token of `id`'s stored leg.
fn token_matches(id: &str, token: &str) -> bool {
    find_subscription(id)
        .and_then(|s| s.amf_leg)
        .is_some_and(|l| tokens_equal(&l.change_token, token))
}

/// The path segment of the UDM's subscription-change callback; the capability
/// token follows it, so the shared log redaction hides it.
pub const SUBS_CHANGE_SEGMENT: &str = "ee-amf-subs-change";

/// `/nudm-callback/v1/{eeSubscriptionId}/ee-amf-subs-change/{token}`.
pub fn subs_change_path(ee_subscription_id: &str, token: &str) -> String {
    format!("/nudm-callback/v1/{ee_subscription_id}/{SUBS_CHANGE_SEGMENT}/{token}")
}

/// The Namf event types `sub` needs the AMF for.
fn amf_event_types(sub: &UdmEeSubscription) -> Vec<String> {
    AMF_ASSISTED_EVENTS
        .iter()
        .filter(|(ee, _)| !sub.configurations_for(ee).is_empty())
        .map(|(_, amf)| amf.to_string())
        .collect()
}

/// Whether `sub` is addressed to one UE by SUPI (TS 23.003 §2.2A: `imsi-` or
/// `nai-`), the only form forwarded.
fn is_supi(ue_identity: &str) -> bool {
    ue_identity.starts_with("imsi-") || ue_identity.starts_with("nai-")
}

/// Whether the serving AMF, not the UDM, reports `ee_event_type` to `sub` now.
///
/// True only while the leg is confirmed for the subscription as it is: made for
/// its current callback and events, at `serving_amf` (the UE's serving AMF, or
/// `None` once the UE is deregistered, when the leg's own confirmed AMF stands).
pub fn amf_reports(
    sub: &UdmEeSubscription,
    ee_event_type: &str,
    serving_amf: Option<&str>,
) -> bool {
    let Some(leg) = &sub.amf_leg else {
        return false;
    };
    let Some(amf_event) = AMF_ASSISTED_EVENTS
        .iter()
        .find(|(ee, _)| *ee == ee_event_type)
        .map(|(_, amf)| *amf)
    else {
        return false;
    };
    let confirmed_at = match (serving_amf, leg.amf_instance_id.as_deref()) {
        (Some(serving), Some(leg_amf)) => serving == leg_amf,
        (None, Some(_)) => true,
        (_, None) => false,
    };
    confirmed_at
        && leg.notify_uri == sub.callback_reference
        && leg.events.iter().any(|e| e == amf_event)
}

/// `scheme://host:port` of a URI, for comparing which AMF two URIs name.
fn authority(uri: &str) -> Option<&str> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    let end = rest.find('/').unwrap_or(rest.len());
    Some(&uri[..uri.len() - rest.len() + end])
}

/// Split an absolute `http(s)://host[:port]/path` into `(host, port, path)`.
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else {
        (80u16, uri.strip_prefix("http://")?)
    };
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if auth.is_empty() {
        return None;
    }
    // `[v6]:port`, `[v6]`, `host:port` or `host`.
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (h.to_string(), p.parse().ok()?),
            None if tail.is_empty() => (h.to_string(), default_port),
            None => return None,
        }
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (auth.to_string(), default_port),
        }
    };
    Some((host, port, path))
}

/// The client for an AMF: carries the NRF-issued OAuth2 bearer whenever
/// enforcement is on (TS 33.501 §13.4.1), as every other udmd peer call does
/// (#1449 review: without it the production profile answered 401).
async fn amf_client(host: &str, port: u16) -> Arc<nextgcore_sbi::client::SbiClient> {
    crate::app::peer_client(host, port, NfType::Amf).await
}

/// `scheme://host:port` of the AMF instance `amf_instance_id`'s Namf_EventExposure
/// endpoint: from the NF-instance cache, else by NRF discovery of that instance
/// (TS 29.510 `target-nf-instance-id`). Never "any AMF": a subscription at an AMF
/// that does not serve the UE would never fire.
async fn resolve_amf(amf_instance_id: &str) -> Option<String> {
    let ctx = nextgcore_sbi::context::global_context();
    if ctx.get_nf_instance(amf_instance_id).await.is_none() {
        // Under the same cap as the AMF calls: it runs holding the leg lock
        // (#1449 review 11).
        let discovered = tokio::time::timeout(
            amf_call_timeout(),
            crate::sbi_path::udm_nrf_discover_instance(NfType::Amf, amf_instance_id),
        )
        .await
        .unwrap_or_else(|_| Err("NRF discovery timed out".to_string()));
        if let Err(e) = discovered {
            log::warn!("AMF {amf_instance_id} is not known and could not be discovered: {e}");
            return None;
        }
    }
    let instance = ctx.get_nf_instance(amf_instance_id).await?;
    let service = instance
        .find_service(nextgcore_sbi::types::SbiServiceType::NamfEvts)
        .or_else(|| instance.services.first());
    let host = service
        .and_then(|s| s.ip_addresses.first().or(s.fqdn.as_ref()))
        .or_else(|| instance.host())?
        .clone();
    let port = service.map(|s| s.port).filter(|p| *p != 0).unwrap_or(80);
    let scheme = match service.map(|s| s.scheme) {
        Some(nextgcore_sbi::types::UriScheme::Https) => "https",
        _ => "http",
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    Some(format!("{scheme}://{host}:{port}"))
}

/// The Namf_EventExposure_Subscribe body for `sub` (TS 29.518 §6.2.6.2.3
/// `AmfEventSubscription`): the consumer's own callback as `eventNotifyUri`, so
/// the AMF notifies it directly (step 4), and this UDM's change endpoint.
pub(crate) fn subscribe_body(
    sub: &UdmEeSubscription,
    events: &[String],
    change_token: &str,
) -> Value {
    let event_list: Vec<Value> = events.iter().map(|t| json!({ "type": t })).collect();
    let mut subscription = json!({
        "eventList": event_list,
        "eventNotifyUri": sub.callback_reference,
        "notifyCorrelationId": sub.id,
        "nfId": nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Udm).to_string(),
        "supi": sub.ue_identity,
    });
    if let Some(base) = notify_base() {
        subscription["subsChangeNotifyUri"] =
            json!(format!("{base}{}", subs_change_path(&sub.id, change_token)));
        subscription["subsChangeNotifyCorrelationId"] = json!(sub.id);
    }
    json!({ "subscription": subscription })
}

/// POST the subscription to the AMF at `amf_base`; the created resource's
/// absolute URI on 201.
async fn amf_subscribe(amf_base: &str, body: &Value) -> Result<String, String> {
    let (host, port, _) = split_uri(amf_base).ok_or("bad AMF URI")?;
    let client = amf_client(&host, port).await;
    let resp = tokio::time::timeout(
        amf_call_timeout(),
        client.post_json("/namf-evts/v1/subscriptions", body),
    )
    .await
    .map_err(|_| format!("Namf_EventExposure_Subscribe to {amf_base} timed out"))?
    .map_err(|e| format!("Namf_EventExposure_Subscribe to {amf_base} failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "Namf_EventExposure_Subscribe to {amf_base} returned {}",
            resp.status
        ));
    }
    let location = resp
        .http
        .headers
        .get("location")
        .cloned()
        .or_else(|| {
            resp.http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
                .and_then(|v| v["subscriptionId"].as_str().map(String::from))
                .map(|id| format!("/namf-evts/v1/subscriptions/{id}"))
        })
        .ok_or("201 without a Location or subscriptionId")?;
    Ok(
        if location.starts_with("http://") || location.starts_with("https://") {
            location
        } else {
            format!("{amf_base}{location}")
        },
    )
}

/// DELETE an AMF subscription (TS 29.518 §5.3.2.3). Best-effort: a gone AMF or an
/// already-deleted subscription leaves nothing to clean up.
async fn amf_unsubscribe(subscription_uri: &str) {
    let Some((host, port, path)) = split_uri(subscription_uri) else {
        return;
    };
    let client = amf_client(&host, port).await;
    match tokio::time::timeout(
        amf_call_timeout(),
        client.send_request(SbiRequest::delete(&path)),
    )
    .await
    {
        Ok(Ok(resp)) => log::info!(
            "Namf_EventExposure_Unsubscribe {subscription_uri}: status={}",
            resp.status
        ),
        Ok(Err(e)) => log::warn!("Namf_EventExposure_Unsubscribe {subscription_uri} failed: {e}"),
        Err(_) => log::warn!("Namf_EventExposure_Unsubscribe {subscription_uri} timed out"),
    }
}

/// Store `leg` on subscription `id` if it still exists; `false` when it is gone.
/// Only the leg is written, never the rest of the subscription.
fn store_leg(id: &str, leg: Option<AmfEeLeg>) -> bool {
    let ctx = udm_self();
    let Ok(context) = ctx.read() else {
        return false;
    };
    context.ee_subscription_set_amf_leg(id, leg)
}

/// Drop `sub`'s leg at the AMF and here: the fallback resumes.
async fn drop_leg(id: &str, sub: &UdmEeSubscription, why: &str) {
    if let Some(leg) = &sub.amf_leg {
        log::info!(
            "EE subscription {id}: dropping AMF subscription {} ({why}); the UDM reports \
             AMF-assisted events from UECM again",
            leg.subscription_uri
        );
        amf_unsubscribe(&leg.subscription_uri).await;
        store_leg(id, None);
    }
}

/// Run [`reconcile`] for `id` after the caller has answered. The fallback
/// covers the time until the leg is confirmed.
pub fn spawn_reconcile(id: &str) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        }
    }
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    let done = Done;
    let id = id.to_string();
    handle.spawn(async move {
        let _done = done;
        reconcile(&id).await;
    });
}

/// Wait until no spawned reconcile is running (tests).
pub async fn wait_idle() {
    for _ in 0..2000 {
        if IN_FLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Bring subscription `id`'s AMF leg in line with what it asks for and where its
/// UE is served now (see the module docs). Never fails the caller: a refused or
/// unreachable AMF drops any stale leg so the UECM-derived fallback applies, and
/// is logged.
pub async fn reconcile(id: &str) {
    if find_subscription(id).is_none() {
        return;
    }
    let lock = leg_lock(id);
    let _held = lock.lock().await;
    let (sub, serving_amf) = {
        let ctx = udm_self();
        let Ok(context) = ctx.read() else {
            return;
        };
        let Some(sub) = context.ee_subscription_find_by_id(id) else {
            // Removed meanwhile; `release` may already have dropped the entry.
            drop(context);
            drop_leg_lock(id);
            return;
        };
        let serving = context
            .ue_find_by_supi(&sub.ue_identity)
            .and_then(|ue| ue.amf_instance_id);
        (sub, serving)
    };
    let events = amf_event_types(&sub);
    if events.is_empty() || !is_supi(&sub.ue_identity) {
        drop_leg(id, &sub, "no AMF-assisted event is subscribed").await;
        return;
    }
    // A deregistered UE keeps its leg: the AMF subscription outlives the UE
    // context, and the UE most often returns to the same AMF.
    let Some(serving_amf) = serving_amf else {
        return;
    };
    let fits = |leg: &AmfEeLeg| leg.notify_uri == sub.callback_reference && leg.events == events;
    if let Some(leg) = &sub.amf_leg {
        if fits(leg) && leg.amf_instance_id.as_deref() == Some(serving_amf.as_str()) {
            return;
        }
    }
    let Some(amf_base) = resolve_amf(&serving_amf).await else {
        drop_leg(id, &sub, "the serving AMF cannot be resolved").await;
        return;
    };
    if let Some(leg) = &sub.amf_leg {
        if fits(leg) && authority(&leg.subscription_uri) == Some(amf_base.as_str()) {
            // A taken-over leg (SUBSCRIPTION_ID_CHANGE) at the AMF that now
            // serves the UE: confirm it rather than subscribe a second time.
            store_leg(
                id,
                Some(AmfEeLeg {
                    amf_instance_id: Some(serving_amf),
                    ..leg.clone()
                }),
            );
            return;
        }
    }
    let change_token = uuid::Uuid::new_v4().simple().to_string();
    match amf_subscribe(&amf_base, &subscribe_body(&sub, &events, &change_token)).await {
        Ok(subscription_uri) => {
            log::info!(
                "EE subscription {id} ({events:?}) forwarded to AMF {serving_amf}: {subscription_uri}"
            );
            let leg = AmfEeLeg {
                subscription_uri: subscription_uri.clone(),
                change_token,
                amf_instance_id: Some(serving_amf),
                notify_uri: sub.callback_reference.clone(),
                events,
            };
            if !store_leg(id, Some(leg)) {
                // Unsubscribed while the AMF answered: do not leave it behind.
                amf_unsubscribe(&subscription_uri).await;
                return;
            }
            // The previous leg (another AMF, or another callback) is replaced.
            if let Some(old) = sub.amf_leg {
                amf_unsubscribe(&old.subscription_uri).await;
            }
        }
        Err(e) => {
            log::warn!("EE subscription {id}: {e}");
            drop_leg(id, &sub, "the serving AMF refused or is unreachable").await;
        }
    }
}

/// Reconcile, after this returns, every EE subscription for `supi` whose serving
/// AMF changed or was confirmed (UECM AMF registration).
pub fn on_amf_registered(supi: &str) {
    let ids: Vec<String> = {
        let ctx = udm_self();
        let Ok(context) = ctx.read() else {
            return;
        };
        context
            .ee_subscriptions_for_supi(supi)
            .into_iter()
            .filter(|s| s.ue_identity == supi)
            .map(|s| s.id)
            .collect()
    };
    for id in ids {
        spawn_reconcile(&id);
    }
}

/// Delete `sub`'s AMF leg, for a subscription that has been removed. Waits for
/// a reconcile in flight; one that finishes later finds the subscription gone and
/// deletes what it made.
pub async fn release(sub: &UdmEeSubscription) {
    let lock = leg_lock(&sub.id);
    {
        let _held = lock.lock().await;
        // `sub` is the copy removed from the store, so it carries any leg a
        // reconcile stored before the removal.
        if let Some(leg) = &sub.amf_leg {
            amf_unsubscribe(&leg.subscription_uri).await;
        }
    }
    drop_leg_lock(&sub.id);
}

/// Compare two tokens without an early exit on the first differing byte.
fn tokens_equal(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// `POST /nudm-callback/v1/{eeSubscriptionId}/ee-amf-subs-change/{token}`: an
/// AMF reports the new id of a subscription it took over on an AMF change
/// (TS 29.518 §5.2.2.2.3.1, `SUBSCRIPTION_ID_CHANGE`).
///
/// The token must be this leg's: the body names a URI the UDM will later DELETE,
/// so only the AMF this UDM gave the endpoint to may move it. The new URI must be
/// an absolute Namf_EventExposure subscription resource (§6.2.6.2.5).
pub async fn handle_subs_change(
    ee_subscription_id: &str,
    token: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let not_found = || {
        nextgcore_sbi::server::send_not_found(
            "No such subscription-change endpoint",
            Some("RESOURCE_URI_NOT_FOUND"),
        )
    };
    // Refuse an unknown id or a wrong token BEFORE a lock entry exists for it:
    // the id is wire input, and an entry per forged id grew the map without
    // bound (#1449 review 10).
    if !token_matches(ee_subscription_id, token) {
        return not_found();
    }
    let lock = leg_lock(ee_subscription_id);
    let _held = lock.lock().await;
    // Re-read under the lock: a reconcile or release may have run meanwhile.
    let Some(leg) = find_subscription(ee_subscription_id)
        .and_then(|s| s.amf_leg)
        .filter(|l| tokens_equal(&l.change_token, token))
    else {
        if find_subscription(ee_subscription_id).is_none() {
            drop_leg_lock(ee_subscription_id);
        }
        return not_found();
    };
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<Value>(b).ok())
    else {
        return nextgcore_sbi::server::send_bad_request("Invalid JSON", Some("INVALID_MSG_FORMAT"));
    };
    let new_uri = body["reportList"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["type"] == "SUBSCRIPTION_ID_CHANGE")
        .find_map(|r| r["subscriptionId"].as_str());
    let Some(new_uri) = new_uri else {
        return nextgcore_sbi::server::send_bad_request(
            "no SUBSCRIPTION_ID_CHANGE report with a subscriptionId",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    let is_namf_subscription = split_uri(new_uri)
        .is_some_and(|(_, _, path)| path.starts_with("/namf-evts/v1/subscriptions/"));
    if !is_namf_subscription {
        return nextgcore_sbi::server::send_bad_request(
            "subscriptionId is not an absolute Namf_EventExposure subscription URI",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    if new_uri == leg.subscription_uri {
        return SbiResponse::no_content();
    }
    if authority(new_uri) == authority(&leg.subscription_uri) {
        // The UDM already re-subscribed at this AMF (the UECM registration
        // overtook this notification): keep one, drop the transferred copy.
        log::info!(
            "EE subscription {ee_subscription_id}: AMF reports transferred {new_uri}, \
             but {} is already held there; deleting the duplicate",
            leg.subscription_uri
        );
        amf_unsubscribe(new_uri).await;
        return SbiResponse::no_content();
    }
    log::info!(
        "EE subscription {ee_subscription_id}: AMF subscription moved {} -> {new_uri}",
        leg.subscription_uri
    );
    // Not yet confirmed at a serving AMF: the next UECM registration matches it
    // (by authority) and confirms it, and until then the fallback stays on.
    store_leg(
        ee_subscription_id,
        Some(AmfEeLeg {
            subscription_uri: new_uri.to_string(),
            amf_instance_id: None,
            ..leg.clone()
        }),
    );
    // The source AMF's copy, if it kept one (best-effort; 404 if it did not).
    amf_unsubscribe(&leg.subscription_uri).await;
    SbiResponse::no_content()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uecm::{
        process_amf_deregistration, process_amf_registration, UdrClient, UecmAccess,
    };
    use nextgcore_sbi::context::{global_context, NfInstance, NfService};
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::SbiServiceType;
    use std::time::Duration;

    type Seen = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

    /// A loopback server recording `(path, authorization, body)` of every request
    /// and answering with `answer(path)`.
    async fn recorder<F>(answer: F) -> (SbiServer, std::net::SocketAddr, Seen)
    where
        F: Fn(&str) -> SbiResponse + Send + Sync + 'static,
    {
        let seen: Seen = Arc::default();
        let sink = Arc::clone(&seen);
        let answer = Arc::new(answer);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                let answer = Arc::clone(&answer);
                async move {
                    let path = req.header.uri.clone();
                    let auth = req.http.headers.get("authorization").cloned();
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str::<Value>(b).ok())
                        .unwrap_or(Value::Null);
                    sink.lock().expect("sink").push((path.clone(), auth, body));
                    answer(&path)
                }
            })
            .await
            .expect("stub starts");
        wait_listening(addr).await;
        (server, addr, seen)
    }

    /// A NEF: records every notification body.
    async fn nef_stub(name: &str) -> (SbiServer, String, Seen) {
        let (server, addr, seen) = recorder(|_| SbiResponse::with_status(204)).await;
        (
            server,
            format!(
                "http://127.0.0.1:{}/nnef-eventexposure/v1/notify/{name}",
                addr.port()
            ),
            seen,
        )
    }

    fn bodies(seen: &Seen) -> Vec<Value> {
        seen.lock()
            .expect("sink")
            .iter()
            .map(|(_, _, b)| b.clone())
            .collect()
    }

    /// Notifications the UDM raised itself (Nudm_EE, `eventType`), as opposed to
    /// the AMF's (Namf, `type`).
    fn udm_raised(seen: &Seen) -> usize {
        bodies(seen)
            .iter()
            .filter(|b| b["reportList"][0].get("eventType").is_some())
            .count()
    }

    async fn wait_listening(addr: std::net::SocketAddr) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn register_amf_instance(amf_instance_id: &str, port: u16) {
        let mut instance = NfInstance::new(amf_instance_id, NfType::Amf);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("namf-evts", SbiServiceType::NamfEvts);
        svc.versions = vec!["v1".to_string()];
        svc.ip_addresses.push("127.0.0.1".to_string());
        svc.port = port;
        instance.add_service(svc);
        global_context().add_nf_instance(instance).await;
    }

    /// amfd's REAL Namf handler on loopback, registered in the NF-instance cache as
    /// `amf_instance_id`. Returns the server (hold it) and its base URI.
    async fn real_amf(amf_instance_id: &str) -> (SbiServer, String) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd Namf server starts");
        wait_listening(addr).await;
        register_amf_instance(amf_instance_id, addr.port()).await;
        (server, format!("http://127.0.0.1:{}", addr.port()))
    }

    fn amf_registration(amf_instance_id: &str) -> Value {
        json!({
            "amfInstanceId": amf_instance_id,
            "deregCallbackUri": "http://amf.example.org:7777/namf-callback/v1/imsi-x/dereg-notify",
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        })
    }

    fn mock_udr() -> UdrClient {
        UdrClient::Mock(Arc::new(crate::uecm::MockUdr::new()))
    }

    /// A UECM AMF registration, then the reconciles it spawned.
    async fn register(supi: &str, amf_instance_id: &str, client: &UdrClient) -> u16 {
        let resp = process_amf_registration(
            supi,
            &amf_registration(amf_instance_id),
            client,
            UecmAccess::ThreeGpp,
        )
        .await;
        wait_idle().await;
        resp.status
    }

    fn loc() -> Value {
        json!({ "loc": { "eventType": "LOSS_OF_CONNECTIVITY" } })
    }

    /// A real Nudm_EE subscribe; returns the id once its reconcile is done.
    async fn ee_subscribe(supi: &str, callback: &str, configs: Value) -> String {
        let mut req = SbiRequest::post(format!("/nudm-ee/v1/{supi}/ee-subscriptions"));
        req.http.content = Some(
            json!({ "callbackReference": callback, "monitoringConfigurations": configs })
                .to_string(),
        );
        let resp = crate::app::handle_ee_subscribe(supi, &req).await;
        assert_eq!(resp.status, 201);
        wait_idle().await;
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        body["eeSubscription"]["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string()
    }

    async fn ee_patch(supi: &str, id: &str, ops: Value) -> u16 {
        let mut patch = SbiRequest::patch(format!("/nudm-ee/v1/{supi}/ee-subscriptions/{id}"));
        patch.http.content = Some(ops.to_string());
        let status = crate::app::handle_ee_modify(supi, id, &patch).await.status;
        wait_idle().await;
        status
    }

    fn stored(id: &str) -> Option<UdmEeSubscription> {
        let ctx = udm_self();
        let context = ctx.read().expect("context");
        context.ee_subscription_find_by_id(id)
    }

    fn leg_of(id: &str) -> Option<AmfEeLeg> {
        stored(id).and_then(|s| s.amf_leg)
    }

    fn amf_subscription(uri: &str) -> Option<nextgcore_amfd::context::EventSubscription> {
        let id = uri.rsplit('/').next()?;
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().ok()?;
        guard.event_subscription_find(id)
    }

    /// amfd's subscriptions for `supi` that notify `notify_uri`.
    fn amf_subscriptions_to(supi: &str, notify_uri: &str) -> usize {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx");
        guard
            .event_subscriptions_matching("LOSS_OF_CONNECTIVITY", Some(supi))
            .iter()
            .filter(|s| s.notify_uri == notify_uri)
            .count()
    }

    async fn wait_for(seen: &Seen, n: usize) -> Vec<Value> {
        for _ in 0..300 {
            let got = bodies(seen);
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        bodies(seen)
    }

    fn clear(supi: &str) {
        let ctx = udm_self();
        let context = ctx.read().expect("context");
        for sub in context.ee_subscriptions_for_supi(supi) {
            context.ee_subscription_remove(&sub.id);
        }
    }

    /// The common preamble: the guard, a plaintext dev profile, a fresh context,
    /// an AMF context, and no OAuth2 override.
    fn setup(supi: &str) -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(1024, 4096);
        nextgcore_amfd::test_support::init_context();
        set_notify_base(Some("http://udm.example.org:7777".to_string()));
        *crate::app::OAUTH2_CLIENT_TEST_OVERRIDE
            .write()
            .expect("override") = None;
        AMF_CALL_TIMEOUT_MS.store(5_000, Ordering::Relaxed);
        clear(supi);
        guard
    }

    /// **#1440, TS 23.502 §4.15.3.2.3 steps 3a-6, end to end against amfd's real
    /// Namf_EventExposure handler.**
    ///
    /// 1. The UE is registered at AMF `amf-1440`; a NEF subscribes to LoC.
    /// 2. Step 3a: the UDM subscribes at that AMF, for that SUPI, with the NEF's
    ///    callback as `eventNotifyUri` and its own `subsChangeNotifyUri`.
    /// 3. Steps 4-6: the AMF's LoC reaches the NEF directly, with its reason.
    /// 4. On deregistration the UDM does NOT also raise LoC (the AMF does).
    /// 5. Unsubscribing deletes the AMF subscription.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn loss_of_connectivity_is_subscribed_at_the_serving_amf() {
        let supi = "imsi-001010000001440";
        let _guard = setup(supi);
        let (_amf, amf_base) = real_amf("amf-1440").await;
        let (_nef, nef_uri, nef_seen) = nef_stub("n1").await;
        let client = mock_udr();

        assert_eq!(register(supi, "amf-1440", &client).await, 201);
        let id = ee_subscribe(supi, &nef_uri, loc()).await;

        let leg = leg_of(&id).expect("the UDM holds an AMF subscription");
        assert!(
            leg.subscription_uri
                .starts_with(&format!("{amf_base}/namf-evts/v1/subscriptions/")),
            "{leg:?}"
        );
        assert_eq!(leg.amf_instance_id.as_deref(), Some("amf-1440"));
        let at_amf = amf_subscription(&leg.subscription_uri).expect("amfd stored it");
        assert_eq!(at_amf.event_types, vec!["LOSS_OF_CONNECTIVITY".to_string()]);
        assert_eq!(at_amf.supi.as_deref(), Some(supi));
        assert_eq!(
            at_amf.notify_uri, nef_uri,
            "the AMF notifies the NEF directly"
        );
        assert_eq!(
            at_amf.subs_change_notify_uri,
            Some(format!(
                "http://udm.example.org:7777/nudm-callback/v1/{id}/ee-amf-subs-change/{}",
                leg.change_token
            )),
            "the UDM provides its own endpoint too (step 3a)"
        );

        nextgcore_amfd::namf_server::fire_amf_event_for(
            "LOSS_OF_CONNECTIVITY",
            Some(supi),
            None,
            None,
            json!({ "lossOfConnectReason": "MAX_DETECTION_TIME_EXPIRED" }),
        );
        let got = wait_for(&nef_seen, 1).await;
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0]["reportList"][0]["type"], "LOSS_OF_CONNECTIVITY");
        assert_eq!(
            got[0]["reportList"][0]["lossOfConnectReason"],
            "MAX_DETECTION_TIME_EXPIRED"
        );

        // Awaited notifications: whatever the UDM sent is recorded on return.
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        assert_eq!(
            udm_raised(&nef_seen),
            0,
            "the AMF reports LoC; not the UDM as well"
        );
        assert!(leg_of(&id).is_some(), "the leg outlives the UE context");

        let resp = crate::app::handle_ee_unsubscribe(supi, &id).await;
        assert_eq!(resp.status, 204);
        assert!(
            amf_subscription(&leg.subscription_uri).is_none(),
            "deleted at the AMF"
        );
    }

    /// **#1449 review 5.** The subscribe answers at once even when the serving AMF
    /// never answers: the leg is made after the 201, and until then (here: never)
    /// the UDM reports LoC itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn a_silent_amf_does_not_delay_the_subscribe() {
        let supi = "imsi-001010000005449";
        let _guard = setup(supi);
        AMF_CALL_TIMEOUT_MS.store(300, Ordering::Relaxed);
        // Accepts TCP connections and never answers.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        register_amf_instance("amf-silent-5449", silent.local_addr().expect("addr").port()).await;
        let (_nef, nef_uri, nef_seen) = nef_stub("n5").await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-silent-5449", &client).await, 201);

        let mut req = SbiRequest::post(format!("/nudm-ee/v1/{supi}/ee-subscriptions"));
        req.http.content = Some(
            json!({ "callbackReference": nef_uri, "monitoringConfigurations": loc() }).to_string(),
        );
        let started = std::time::Instant::now();
        let resp = crate::app::handle_ee_subscribe(supi, &req).await;
        let took = started.elapsed();
        assert_eq!(resp.status, 201);
        assert!(
            took < Duration::from_millis(250),
            "the 201 must not wait for the AMF (nefd gives up after 3 s): took {took:?}"
        );
        wait_idle().await;
        let id: Value = serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let id = id["eeSubscription"]["subscriptionId"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(leg_of(&id).is_none(), "a timed-out AMF holds no leg");

        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        assert_eq!(udm_raised(&nef_seen), 1, "the fallback reports the loss");
        drop(silent);
        clear(supi);
    }

    /// **#1440.** A subscription made before the UE registers is forwarded when it
    /// does; re-registration at the same AMF keeps one leg; a PATCH that drops LoC
    /// releases it at the AMF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn registration_forwards_and_patch_releases() {
        let supi = "imsi-001010000002440";
        let _guard = setup(supi);
        let (_amf, _amf_base) = real_amf("amf-2440").await;
        let client = mock_udr();

        let id = ee_subscribe(supi, "http://nef.example.org/notify", loc()).await;
        assert!(leg_of(&id).is_none(), "no serving AMF yet");

        assert_eq!(register(supi, "amf-2440", &client).await, 201);
        let leg = leg_of(&id).expect("forwarded on registration");
        assert!(amf_subscription(&leg.subscription_uri).is_some());

        assert_eq!(register(supi, "amf-2440", &client).await, 200);
        assert_eq!(
            leg_of(&id),
            Some(leg.clone()),
            "one leg, not a second subscribe"
        );

        let ops = json!([{
            "op": "replace",
            "path": "/monitoringConfigurations",
            "value": { "r": { "eventType": "UE_REACHABILITY_FOR_DATA" } },
        }]);
        assert_eq!(ee_patch(supi, &id, ops).await, 204);
        assert!(leg_of(&id).is_none());
        assert!(
            amf_subscription(&leg.subscription_uri).is_none(),
            "released at the AMF"
        );
        clear(supi);
    }

    /// **#1449 review 2.** A PATCH of `callbackReference` re-subscribes at the AMF
    /// for the new callback and deletes the old subscription: the AMF must not keep
    /// notifying the old NEF while the UDM stays silent toward the new one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn a_callback_patch_moves_the_amf_subscription() {
        let supi = "imsi-001010000002449";
        let _guard = setup(supi);
        let (_amf, _amf_base) = real_amf("amf-2449").await;
        let (_nef1, nef1, _seen1) = nef_stub("nef1").await;
        let (_nef2, nef2, seen2) = nef_stub("nef2").await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-2449", &client).await, 201);
        let id = ee_subscribe(supi, &nef1, loc()).await;
        let old = leg_of(&id).expect("leg for nef1");

        let ops = json!([{ "op": "replace", "path": "/callbackReference", "value": nef2 }]);
        assert_eq!(ee_patch(supi, &id, ops).await, 204);
        let new = leg_of(&id).expect("leg for nef2");
        assert_eq!(new.notify_uri, nef2);
        assert_ne!(new.subscription_uri, old.subscription_uri);
        assert_eq!(
            amf_subscription(&new.subscription_uri).map(|s| s.notify_uri),
            Some(nef2.clone()),
            "the AMF notifies the new callback"
        );
        assert!(
            amf_subscription(&old.subscription_uri).is_none(),
            "the old one is deleted"
        );
        assert_eq!(amf_subscriptions_to(supi, &nef1), 0);

        nextgcore_amfd::namf_server::fire_amf_event_for(
            "LOSS_OF_CONNECTIVITY",
            Some(supi),
            None,
            None,
            json!({ "lossOfConnectReason": "DEREGISTERED" }),
        );
        assert_eq!(
            wait_for(&seen2, 1).await.len(),
            1,
            "nef2 hears the AMF's LoC"
        );
        clear(supi);
    }

    /// **#1449 review 3.** A leg that is no longer at the serving AMF does not
    /// silence the fallback: the UE moves to an AMF this UDM cannot resolve, the
    /// old leg is dropped (and deleted), and the NEF hears the UDM's LoC. The same
    /// holds when the new AMF refuses the subscription.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn a_stale_leg_does_not_silence_the_fallback() {
        let supi = "imsi-001010000003449";
        let _guard = setup(supi);
        let (_amf, _amf_base) = real_amf("amf-9449").await;
        let (_nef, nef_uri, nef_seen) = nef_stub("n3").await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-9449", &client).await, 201);
        let id = ee_subscribe(supi, &nef_uri, loc()).await;
        let old = leg_of(&id).expect("leg at amf-9449");

        // Unresolvable new AMF.
        assert_eq!(register(supi, "amf-unknown-3449", &client).await, 200);
        assert!(leg_of(&id).is_none(), "the stale leg is dropped");
        assert!(
            amf_subscription(&old.subscription_uri).is_none(),
            "and deleted at the old AMF"
        );
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        assert_eq!(udm_raised(&nef_seen), 1, "the fallback reports the loss");

        // A new AMF that refuses: back at amf-9449 first, then to the refuser.
        assert_eq!(register(supi, "amf-9449", &client).await, 201);
        assert!(leg_of(&id).is_some());
        let (_refuser, refuser_addr, _) = recorder(|_| SbiResponse::with_status(403)).await;
        register_amf_instance("amf-refuses-3449", refuser_addr.port()).await;
        assert_eq!(register(supi, "amf-refuses-3449", &client).await, 200);
        assert!(
            leg_of(&id).is_none(),
            "a refused subscribe drops the stale leg"
        );
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        assert_eq!(udm_raised(&nef_seen), 2);
        clear(supi);
    }

    /// **#1449 review 3, the window.** While a reconcile has not yet run after an
    /// AMF change, the leg at the previous AMF does not suppress the UDM's report.
    #[test]
    fn suppression_needs_the_leg_at_the_serving_amf() {
        let mut sub = UdmEeSubscription::for_ue(
            "imsi-001010000006449",
            "http://nef/cb",
            json!({ "callbackReference": "http://nef/cb", "monitoringConfigurations": loc() })
                .to_string(),
        );
        assert!(
            !amf_reports(&sub, "LOSS_OF_CONNECTIVITY", Some("amf-a")),
            "no leg"
        );
        let leg = AmfEeLeg {
            subscription_uri: "http://amf-a/namf-evts/v1/subscriptions/s".to_string(),
            change_token: "t".to_string(),
            amf_instance_id: Some("amf-a".to_string()),
            notify_uri: "http://nef/cb".to_string(),
            events: vec!["LOSS_OF_CONNECTIVITY".to_string()],
        };
        sub.amf_leg = Some(leg.clone());
        assert!(amf_reports(&sub, "LOSS_OF_CONNECTIVITY", Some("amf-a")));
        assert!(
            amf_reports(&sub, "LOSS_OF_CONNECTIVITY", None),
            "deregistered: the leg stands"
        );
        assert!(
            !amf_reports(&sub, "LOSS_OF_CONNECTIVITY", Some("amf-b")),
            "another AMF serves"
        );
        assert!(!amf_reports(
            &sub,
            "UE_REACHABILITY_FOR_DATA",
            Some("amf-a")
        ));
        sub.callback_reference = "http://nef2/cb".to_string();
        assert!(
            !amf_reports(&sub, "LOSS_OF_CONNECTIVITY", Some("amf-a")),
            "callback moved"
        );
        sub.callback_reference = "http://nef/cb".to_string();
        sub.amf_leg = Some(AmfEeLeg {
            amf_instance_id: None,
            ..leg
        });
        assert!(
            !amf_reports(&sub, "LOSS_OF_CONNECTIVITY", None),
            "unconfirmed take-over"
        );
    }

    /// **#1449 review 6.** Reconciles racing on one subscription (its subscribe,
    /// UECM registrations, a second explicit one) leave exactly one AMF
    /// subscription, and a PATCH write-back of a clone read earlier does not
    /// restore an older leg.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn concurrent_reconciles_leave_one_amf_subscription() {
        let supi = "imsi-001010000004449";
        let _guard = setup(supi);
        let (_amf, _amf_base) = real_amf("amf-4449").await;
        let (_nef, nef_uri, _seen) = nef_stub("n4").await;
        let client = mock_udr();
        // Serving AMF known, but no subscription yet.
        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-4449"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
        let mut req = SbiRequest::post(format!("/nudm-ee/v1/{supi}/ee-subscriptions"));
        req.http.content = Some(
            json!({ "callbackReference": nef_uri, "monitoringConfigurations": loc() }).to_string(),
        );
        let resp = crate::app::handle_ee_subscribe(supi, &req).await;
        let id: Value = serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let id = id["eeSubscription"]["subscriptionId"]
            .as_str()
            .unwrap()
            .to_string();
        let stale_clone = stored(&id).expect("stored");
        for _ in 0..4 {
            spawn_reconcile(&id);
            on_amf_registered(supi);
        }
        wait_idle().await;
        assert_eq!(
            amf_subscriptions_to(supi, &nef_uri),
            1,
            "exactly one AMF subscription"
        );
        let leg = leg_of(&id).expect("leg");

        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            assert!(context.ee_subscription_update(stale_clone));
        }
        assert_eq!(
            leg_of(&id),
            Some(leg),
            "the write-back keeps the stored leg"
        );
        crate::app::handle_ee_unsubscribe(supi, &id).await;
        assert_eq!(amf_subscriptions_to(supi, &nef_uri), 0);
    }

    /// **#1449 review 1.** Under OAuth2 enforcement the AMF calls carry the
    /// NRF-issued bearer, as every other udmd peer call does. The stub serves the
    /// NRF token endpoint and records the AMF requests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn amf_calls_carry_the_oauth2_bearer() {
        let supi = "imsi-001010000001449";
        let _guard = setup(supi);
        let (_stub, addr, seen) = recorder(|path| {
            if path.contains("access-token") || path.contains("oauth2/token") {
                SbiResponse::with_status(200)
                    .with_json_body(&json!({
                        "access_token": "tok-1449",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                    .expect("json")
            } else if path.starts_with("/namf-evts/v1/subscriptions/") {
                SbiResponse::with_status(204)
            } else {
                SbiResponse::with_status(201)
                    .with_header("location", "/namf-evts/v1/subscriptions/sub-1449")
            }
        })
        .await;
        *crate::app::OAUTH2_CLIENT_TEST_OVERRIDE
            .write()
            .expect("override") = Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            format!("http://127.0.0.1:{}", addr.port()),
            "udm-1449",
            NfType::Udm,
        )));
        register_amf_instance("amf-oauth-1449", addr.port()).await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-oauth-1449", &client).await, 201);
        let id = ee_subscribe(supi, "http://nef.example.org/notify", loc()).await;
        assert!(leg_of(&id).is_some());
        crate::app::handle_ee_unsubscribe(supi, &id).await;
        *crate::app::OAUTH2_CLIENT_TEST_OVERRIDE
            .write()
            .expect("override") = None;

        let calls = seen.lock().expect("sink").clone();
        let amf_calls: Vec<_> = calls
            .iter()
            .filter(|(p, _, _)| p.starts_with("/namf-evts/"))
            .collect();
        assert_eq!(amf_calls.len(), 2, "subscribe and delete: {calls:?}");
        for (path, auth, _) in amf_calls {
            assert_eq!(
                auth.as_deref(),
                Some("Bearer tok-1449"),
                "{path} without the bearer"
            );
        }
    }

    /// **#1440, the fallback and #1444.** With no reachable serving AMF the UDM
    /// raises LoC itself on deregistration, as a TS 29.503 §6.4.6.2.17
    /// LossConnectivityReport with a top-level timeStamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn without_an_amf_leg_the_udm_reports_loc_with_its_reason() {
        let supi = "imsi-001010000003440";
        let _guard = setup(supi);
        let (_nef, nef_uri, nef_seen) = nef_stub("n6").await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-unknown-3440", &client).await, 201);
        let id = ee_subscribe(supi, &nef_uri, loc()).await;
        assert!(leg_of(&id).is_none());

        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        let got = bodies(&nef_seen);
        assert_eq!(got.len(), 1, "{got:?}");
        let report = &got[0]["reportList"][0];
        assert_eq!(report["eventType"], "LOSS_OF_CONNECTIVITY");
        assert_eq!(report["referenceId"], "loc");
        assert!(report["timeStamp"].is_string(), "{report}");
        assert_eq!(
            report["report"],
            json!({ "lossOfConnectReason": "DEREGISTERED" })
        );
        clear(supi);
    }

    /// **#1449 review 4, with amfd's REAL take-over.** The UE's context is
    /// transferred to a target AMF (amfd's real CreateUEContext, carrying the
    /// subscription the UDM made); amfd posts SUBSCRIPTION_ID_CHANGE to the UDM's
    /// real SBI handler; the leg moves to the absolute URI amfd reports, and the
    /// source AMF's copy is deleted (review 7). The next UECM registration at the
    /// target confirms it without a second subscribe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn amfd_take_over_moves_the_leg() {
        let supi = "imsi-001010000007449";
        let _guard = setup(supi);
        // The UDM's own SBI listener, so amfd's notification reaches the router.
        let (udm_listener, udm_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udm = SbiServer::on_listener(SbiServerConfig::new(udm_addr), udm_listener);
        udm.start(crate::app::udm_sbi_request_handler)
            .await
            .expect("udm starts");
        wait_listening(udm_addr).await;
        set_notify_base(Some(format!("http://127.0.0.1:{}", udm_addr.port())));
        let (_source, _source_base) = real_amf("amf-src-7449").await;
        let (_nef, nef_uri, _seen) = nef_stub("n7").await;
        let client = mock_udr();
        assert_eq!(register(supi, "amf-src-7449", &client).await, 201);
        let id = ee_subscribe(supi, &nef_uri, loc()).await;
        let old = leg_of(&id).expect("leg at the source AMF");

        // The target AMF receives the context with the subscription in it, as the
        // source AMF holds it.
        let transferred = subscribe_body(
            &stored(&id).expect("stored"),
            &["LOSS_OF_CONNECTIVITY".to_string()],
            &old.change_token,
        )["subscription"]
            .clone();
        let body = json!({
            "ueContext": {
                "supi": supi,
                "pei": "imeisv-0000000000007449",
                "mmContextList": [{ "accessType": "3GPP_ACCESS" }],
                "eventSubscriptionList": [transferred],
            },
            "targetId": {
                "ranNodeId": { "gNbId": { "bitLength": 24, "gNBValue": "007449" } },
                "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "7449" },
            },
            "sourceToTargetData": { "ngapIeType": "SRC_TO_TAR_CONTAINER",
                                    "ngapData": { "contentId": "n2SrcToTar" } },
            "pduSessionList": [{ "pduSessionId": 5,
                                 "n2InfoContent": { "ngapData": { "contentId": "n2Sm5" } } }],
        });
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{supi}"))
                .with_json_body(&body)
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201, "CreateUEContext");

        let mut moved = None;
        for _ in 0..300 {
            if let Some(leg) = leg_of(&id).filter(|l| l.subscription_uri != old.subscription_uri) {
                moved = Some(leg);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let moved = moved.expect("amfd's SUBSCRIPTION_ID_CHANGE was accepted");
        let target_base = nextgcore_amfd::sbi_path::advertised_sbi_base();
        assert!(
            moved
                .subscription_uri
                .starts_with(&format!("{target_base}/namf-evts/v1/subscriptions/")),
            "amfd reports the absolute URI: {moved:?}"
        );
        assert_eq!(
            moved.amf_instance_id, None,
            "not yet confirmed at a serving AMF"
        );
        assert!(
            amf_subscription(&moved.subscription_uri).is_some(),
            "the URI names the subscription amfd took over"
        );
        for _ in 0..300 {
            if amf_subscription(&old.subscription_uri).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            amf_subscription(&old.subscription_uri).is_none(),
            "the source copy is deleted"
        );
        drop(udm);
        clear(supi);
    }

    /// **#1440, the UDM's change endpoint.** Only the token this UDM handed the AMF
    /// moves a leg, only to a Namf_EventExposure subscription URI; a transferred
    /// copy at an AMF the UDM already subscribed at is not adopted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn subscription_change_moves_the_leg_only_with_its_token() {
        let supi = "imsi-001010000004440";
        let _guard = setup(supi);
        let mut sub = UdmEeSubscription::for_ue(
            supi,
            "http://nef.example.org/notify",
            json!({
                "callbackReference": "http://nef.example.org/notify",
                "monitoringConfigurations": loc(),
            })
            .to_string(),
        );
        // Ports nothing listens on: a best-effort DELETE to them fails at once.
        let (old_port, new_port) = (
            nextgcore_sbi::test_support::down_port(),
            nextgcore_sbi::test_support::down_port(),
        );
        let old = format!(
            "http://127.0.0.1:{}/namf-evts/v1/subscriptions/sub-old",
            old_port.addr().port()
        );
        sub.amf_leg = Some(AmfEeLeg {
            subscription_uri: old.clone(),
            change_token: "tok-4440".to_string(),
            amf_instance_id: Some("amf-old".to_string()),
            notify_uri: "http://nef.example.org/notify".to_string(),
            events: vec!["LOSS_OF_CONNECTIVITY".to_string()],
        });
        let id = sub.id.clone();
        {
            let ctx = udm_self();
            ctx.read().expect("context").ee_subscription_insert(sub);
        }
        let change = |token: &str, uri: &str| {
            let mut req = SbiRequest::post(subs_change_path(&id, token));
            req.http.content = Some(
                json!({
                    "subsChangeNotifyCorrelationId": id,
                    "reportList": [{
                        "type": "SUBSCRIPTION_ID_CHANGE",
                        "state": { "active": true },
                        "timeStamp": "2026-11-12T00:00:00Z",
                        "subscriptionId": uri,
                    }],
                })
                .to_string(),
            );
            req
        };
        let new = format!(
            "http://127.0.0.1:{}/namf-evts/v1/subscriptions/sub-new",
            new_port.addr().port()
        );
        let resp = crate::app::udm_sbi_request_handler(change("forged", &new)).await;
        assert_eq!(resp.status, 404, "a wrong token is refused");
        let resp =
            crate::app::udm_sbi_request_handler(change("tok-4440", "http://evil.example/x")).await;
        assert_eq!(
            resp.status, 400,
            "only a Namf_EventExposure subscription URI"
        );
        let resp = crate::app::udm_sbi_request_handler(change(
            "tok-4440",
            "/namf-evts/v1/subscriptions/sub-relative",
        ))
        .await;
        assert_eq!(resp.status, 400, "only an absolute one (§6.2.6.2.5)");
        assert_eq!(leg_of(&id).map(|l| l.subscription_uri), Some(old));

        let resp = crate::app::udm_sbi_request_handler(change("tok-4440", &new)).await;
        assert_eq!(resp.status, 204);
        assert_eq!(
            leg_of(&id).map(|l| l.subscription_uri),
            Some(new.clone()),
            "the leg follows the subscription to the new AMF"
        );

        // A second id at the SAME AMF is a duplicate of the one held: kept as is.
        let dup = format!(
            "http://127.0.0.1:{}/namf-evts/v1/subscriptions/sub-dup",
            new_port.addr().port()
        );
        let resp = crate::app::udm_sbi_request_handler(change("tok-4440", &dup)).await;
        assert_eq!(resp.status, 204);
        assert_eq!(leg_of(&id).map(|l| l.subscription_uri), Some(new));
        clear(supi);
    }

    /// **#1449 review 10.** Forged subscription-change calls (unknown ids, and a
    /// real id with a wrong token) are refused without creating a lock entry, so
    /// wire input cannot grow the lock map.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn forged_subscription_changes_leave_the_lock_map_unchanged() {
        let supi = "imsi-001010000010449";
        let _guard = setup(supi);
        let mut sub = UdmEeSubscription::for_ue(
            supi,
            "http://nef.example.org/notify",
            json!({ "callbackReference": "http://nef.example.org/notify", "monitoringConfigurations": loc() })
                .to_string(),
        );
        sub.amf_leg = Some(AmfEeLeg {
            subscription_uri: "http://127.0.0.1:9/namf-evts/v1/subscriptions/s".to_string(),
            change_token: "tok-10449".to_string(),
            amf_instance_id: Some("amf-10449".to_string()),
            notify_uri: "http://nef.example.org/notify".to_string(),
            events: vec!["LOSS_OF_CONNECTIVITY".to_string()],
        });
        let id = sub.id.clone();
        udm_self()
            .read()
            .expect("context")
            .ee_subscription_insert(sub);
        let before = leg_lock_count();
        let post = |path: String| {
            let mut req = SbiRequest::post(path);
            req.http.content = Some(json!({ "reportList": [] }).to_string());
            req
        };
        for n in 0..1000 {
            let resp = crate::app::udm_sbi_request_handler(post(subs_change_path(
                &format!("forged-{n}"),
                "x",
            )))
            .await;
            assert_eq!(resp.status, 404);
        }
        let resp = crate::app::udm_sbi_request_handler(post(subs_change_path(&id, "wrong"))).await;
        assert_eq!(resp.status, 404);
        assert_eq!(
            leg_lock_count(),
            before,
            "forged calls must not add lock entries"
        );
        clear(supi);
    }

    /// **#1449 review 11.** NRF discovery of an unknown serving AMF runs under the
    /// same cap as the AMF calls: an NRF that never answers does not hold the
    /// subscription's lock for the client's 30 s default.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_silent_nrf_is_bounded_by_the_amf_call_cap() {
        let supi = "imsi-001010000011449";
        let _guard = setup(supi);
        AMF_CALL_TIMEOUT_MS.store(300, Ordering::Relaxed);
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let ctx = global_context();
        ctx.set_nrf_uri(format!("http://{}", silent.local_addr().expect("addr")))
            .await;
        let client = mock_udr();
        let id = ee_subscribe(supi, "http://nef.example.org/notify", loc()).await;
        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-undiscovered-11449"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
        let started = std::time::Instant::now();
        wait_idle().await;
        let took = started.elapsed();
        // The process-wide NRF URI cannot be unset: leave it at a refused port, which
        // fails at once exactly as "no NRF" does for every later test.
        ctx.set_nrf_uri(format!(
            "http://127.0.0.1:{}",
            nextgcore_sbi::test_support::refused_port()
        ))
        .await;
        assert!(
            took < Duration::from_secs(2),
            "the discovery must give up at the cap: took {took:?}"
        );
        assert!(leg_of(&id).is_none());
        drop(silent);
        clear(supi);
    }

    #[test]
    fn uri_helpers() {
        assert_eq!(
            authority("http://10.0.0.1:7777/namf-evts/v1/subscriptions/x"),
            Some("http://10.0.0.1:7777")
        );
        assert_eq!(
            authority("https://amf.example:443"),
            Some("https://amf.example:443")
        );
        assert_eq!(authority("ftp://x"), None);
        assert_eq!(
            split_uri("http://10.0.0.1:7777/namf-evts/v1/subscriptions/x"),
            Some((
                "10.0.0.1".to_string(),
                7777,
                "/namf-evts/v1/subscriptions/x".to_string()
            ))
        );
        assert_eq!(
            split_uri("http://amf/p"),
            Some(("amf".to_string(), 80, "/p".to_string()))
        );
        assert_eq!(split_uri("x://amf/p"), None);
        assert_eq!(
            split_uri("http://[::1]:8080/p"),
            Some(("::1".to_string(), 8080, "/p".to_string()))
        );
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        assert!(!tokens_equal("abc", "ab"));
        assert!(is_supi("imsi-001010000000001"));
        assert!(!is_supi("anyUE"));
        assert!(!is_supi("msisdn-491700000001"));
    }
}
