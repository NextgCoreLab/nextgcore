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
//! subscription asks for and where the UE is served ([`reconcile`]):
//! - created when a subscription with an AMF-assisted event exists for a SUPI
//!   whose serving AMF is known: at subscribe, at PATCH, and at every UECM AMF
//!   registration (which is also how a UE that registers after the subscription
//!   was made, or at a new AMF, gets one);
//! - deleted when the subscription goes or stops asking for such an event.
//!
//! While a leg is held, the UDM does not also raise that event itself from the
//! UECM purge ([`amf_reports`]): the consumer would hear the same loss twice.
//! Without one (no serving AMF yet, or the AMF refused), the UECM-derived report
//! remains the fallback.
//!
//! # Scope
//!
//! Only SUPI-addressed subscriptions are forwarded. `anyUE` and group
//! subscriptions would go to every AMF in the PLMN, and a GPSI one needs the
//! identifier translation this UDM does not do (#85); they keep the fallback.

use crate::context::{udm_self, AmfEeLeg, UdmEeSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};
use std::sync::RwLock;

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

/// Record this UDM's callback base (`None` to clear).
pub fn set_notify_base(base: Option<String>) {
    if let Ok(mut slot) = NOTIFY_BASE.write() {
        *slot = base;
    }
}

fn notify_base() -> Option<String> {
    NOTIFY_BASE.read().ok().and_then(|b| b.clone())
}

/// The path segment of the UDM's subscription-change callback; the capability
/// token follows it, so the shared log redaction hides it.
pub const SUBS_CHANGE_SEGMENT: &str = "ee-amf-subs-change";

/// `/nudm-callback/v1/{eeSubscriptionId}/ee-amf-subs-change/{token}`.
pub fn subs_change_path(ee_subscription_id: &str, token: &str) -> String {
    format!("/nudm-callback/v1/{ee_subscription_id}/{SUBS_CHANGE_SEGMENT}/{token}")
}

/// The Namf event types `sub` needs the AMF for.
fn amf_event_types(sub: &UdmEeSubscription) -> Vec<&'static str> {
    AMF_ASSISTED_EVENTS
        .iter()
        .filter(|(ee, _)| !sub.configurations_for(ee).is_empty())
        .map(|(_, amf)| *amf)
        .collect()
}

/// Whether `sub` is addressed to one UE by SUPI (TS 23.003 §2.2A: `imsi-` or
/// `nai-`), the only form forwarded.
fn is_supi(ue_identity: &str) -> bool {
    ue_identity.starts_with("imsi-") || ue_identity.starts_with("nai-")
}

/// Whether the serving AMF, not the UDM, reports `ee_event_type` to `sub`:
/// a leg is held and the event is AMF-assisted.
pub fn amf_reports(sub: &UdmEeSubscription, ee_event_type: &str) -> bool {
    sub.amf_leg.is_some()
        && AMF_ASSISTED_EVENTS
            .iter()
            .any(|(ee, _)| *ee == ee_event_type)
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

/// `scheme://host:port` of the AMF instance `amf_instance_id`'s Namf_EventExposure
/// endpoint: from the NF-instance cache, else by NRF discovery of that instance
/// (TS 29.510 `target-nf-instance-id`). Never "any AMF": a subscription at an AMF
/// that does not serve the UE would never fire.
async fn resolve_amf(amf_instance_id: &str) -> Option<String> {
    let ctx = nextgcore_sbi::context::global_context();
    if ctx.get_nf_instance(amf_instance_id).await.is_none() {
        if let Err(e) = crate::sbi_path::udm_nrf_discover_instance(
            nextgcore_sbi::types::NfType::Amf,
            amf_instance_id,
        )
        .await
        {
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
fn subscribe_body(sub: &UdmEeSubscription, events: &[&str], change_token: &str) -> Value {
    let event_list: Vec<Value> = events.iter().map(|t| json!({ "type": t })).collect();
    let mut subscription = json!({
        "eventList": event_list,
        "eventNotifyUri": sub.callback_reference,
        "notifyCorrelationId": sub.id,
        "nfId": nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Udm)
            .to_string(),
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
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    let resp = client
        .post_json("/namf-evts/v1/subscriptions", body)
        .await
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
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    match client.send_request(SbiRequest::delete(&path)).await {
        Ok(resp) => log::info!(
            "Namf_EventExposure_Unsubscribe {subscription_uri}: status={}",
            resp.status
        ),
        Err(e) => log::warn!("Namf_EventExposure_Unsubscribe {subscription_uri} failed: {e}"),
    }
}

/// Store `leg` on subscription `id` if it still exists; `false` when it is gone.
fn store_leg(id: &str, leg: Option<AmfEeLeg>) -> bool {
    let ctx = udm_self();
    let Ok(context) = ctx.read() else {
        return false;
    };
    context.ee_subscription_set_amf_leg(id, leg)
}

/// Bring subscription `id`'s AMF leg in line with what it asks for and where its
/// UE is served now (see the module docs). Never fails the caller: a refused or
/// unreachable AMF leaves the UECM-derived fallback in place, and is logged.
pub async fn reconcile(id: &str) {
    let (sub, serving_amf) = {
        let ctx = udm_self();
        let Ok(context) = ctx.read() else {
            return;
        };
        let Some(sub) = context.ee_subscription_find_by_id(id) else {
            return;
        };
        let serving = context
            .ue_find_by_supi(&sub.ue_identity)
            .and_then(|ue| ue.amf_instance_id);
        (sub, serving)
    };
    let events = amf_event_types(&sub);
    if events.is_empty() || !is_supi(&sub.ue_identity) {
        if let Some(leg) = &sub.amf_leg {
            amf_unsubscribe(&leg.subscription_uri).await;
            store_leg(id, None);
        }
        return;
    }
    // A deregistered UE keeps its leg: the AMF subscription outlives the UE
    // context, and the UE most often returns to the same AMF.
    let Some(serving_amf) = serving_amf else {
        return;
    };
    let Some(amf_base) = resolve_amf(&serving_amf).await else {
        return;
    };
    if let Some(leg) = &sub.amf_leg {
        if authority(&leg.subscription_uri) == Some(amf_base.as_str()) {
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
            };
            if !store_leg(id, Some(leg)) {
                // Unsubscribed while the AMF answered: do not leave it behind.
                amf_unsubscribe(&subscription_uri).await;
                return;
            }
            if let Some(old) = sub.amf_leg {
                amf_unsubscribe(&old.subscription_uri).await;
            }
        }
        Err(e) => log::warn!(
            "EE subscription {id}: {e}; the UDM keeps reporting {events:?} from UECM itself"
        ),
    }
}

/// Reconcile every EE subscription covering `supi` after its serving AMF
/// changed or was confirmed (UECM AMF registration).
pub async fn on_amf_registered(supi: &str) {
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
        reconcile(&id).await;
    }
}

/// Delete `sub`'s AMF leg, for a subscription that is being removed.
pub async fn release(sub: &UdmEeSubscription) {
    if let Some(leg) = &sub.amf_leg {
        amf_unsubscribe(&leg.subscription_uri).await;
    }
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
/// a Namf_EventExposure subscription resource.
pub async fn handle_subs_change(
    ee_subscription_id: &str,
    token: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let sub = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .as_ref()
            .and_then(|c| c.ee_subscription_find_by_id(ee_subscription_id))
    };
    let leg = sub.as_ref().and_then(|s| s.amf_leg.clone());
    let authorised = leg
        .as_ref()
        .is_some_and(|l| tokens_equal(&l.change_token, token));
    let (Some(_), Some(leg), true) = (sub, leg, authorised) else {
        return nextgcore_sbi::server::send_not_found(
            "No such subscription-change endpoint",
            Some("RESOURCE_URI_NOT_FOUND"),
        );
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
    store_leg(
        ee_subscription_id,
        Some(AmfEeLeg {
            subscription_uri: new_uri.to_string(),
            change_token: leg.change_token,
        }),
    );
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
    use nextgcore_sbi::types::{NfType, SbiServiceType};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A loopback consumer (the NEF) recording every body POSTed to it.
    async fn nef_stub() -> (SbiServer, String, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let sink = Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(v) = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str::<Value>(b).ok())
                    {
                        sink.lock().expect("sink").push(v);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("NEF stub starts");
        wait_listening(addr).await;
        (
            server,
            format!(
                "http://127.0.0.1:{}/nnef-eventexposure/v1/notify/n1",
                addr.port()
            ),
            seen,
        )
    }

    async fn wait_listening(addr: std::net::SocketAddr) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// amfd's REAL Namf handler on loopback, registered in the NF-instance cache as
    /// `amf_instance_id` with its `namf-evts` service. Returns the server (hold it)
    /// and its base URI.
    async fn real_amf(amf_instance_id: &str) -> (SbiServer, String) {
        nextgcore_amfd::test_support::init_context();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd Namf server starts");
        wait_listening(addr).await;
        let mut instance = NfInstance::new(amf_instance_id, NfType::Amf);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("namf-evts", SbiServiceType::NamfEvts);
        svc.versions = vec!["v1".to_string()];
        svc.ip_addresses.push("127.0.0.1".to_string());
        svc.port = addr.port();
        instance.add_service(svc);
        global_context().add_nf_instance(instance).await;
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

    async fn ee_subscribe(supi: &str, callback: &str, configs: Value) -> String {
        let mut req = SbiRequest::post(format!("/nudm-ee/v1/{supi}/ee-subscriptions"));
        req.http.content = Some(
            json!({ "callbackReference": callback, "monitoringConfigurations": configs })
                .to_string(),
        );
        let resp = crate::app::handle_ee_subscribe(supi, &req).await;
        assert_eq!(resp.status, 201);
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        body["eeSubscription"]["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string()
    }

    fn stored(id: &str) -> Option<UdmEeSubscription> {
        let ctx = udm_self();
        let context = ctx.read().expect("context");
        context.ee_subscription_find_by_id(id)
    }

    fn amf_subscription(leg: &AmfEeLeg) -> Option<nextgcore_amfd::context::EventSubscription> {
        let id = leg.subscription_uri.rsplit('/').next()?;
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().ok()?;
        guard.event_subscription_find(id)
    }

    async fn wait_for(seen: &Mutex<Vec<Value>>, n: usize) -> Vec<Value> {
        for _ in 0..300 {
            let got = seen.lock().expect("sink").clone();
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        seen.lock().expect("sink").clone()
    }

    fn clear(supi: &str) {
        let ctx = udm_self();
        let context = ctx.read().expect("context");
        for sub in context.ee_subscriptions_for_supi(supi) {
            context.ee_subscription_remove(&sub.id);
        }
    }

    /// **#1440, TS 23.502 §4.15.3.2.3 steps 3a-6, end to end against amfd's real
    /// Namf_EventExposure handler.**
    ///
    /// 1. The UE is registered at AMF `amf-1440` (UECM). A NEF subscribes to
    ///    LOSS_OF_CONNECTIVITY through the real `handle_ee_subscribe`.
    /// 2. Step 3a: the UDM subscribes at that AMF, for that SUPI, with the NEF's
    ///    callback as `eventNotifyUri` and its own `subsChangeNotifyUri`.
    /// 3. Steps 4-6: the AMF's mobile-reachable expiry reaches the NEF directly,
    ///    as an AmfEventNotification carrying `lossOfConnectReason`.
    /// 4. On deregistration the UDM does NOT also raise LoC itself (the AMF does).
    /// 5. Unsubscribing deletes the AMF subscription.
    ///
    /// Revert-verified: dropping the `reconcile` call in `handle_ee_subscribe`
    /// fails step 2; dropping the `amf_reports` skip in `notify` fails step 4.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn loss_of_connectivity_is_subscribed_at_the_serving_amf() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(1024, 4096);
        set_notify_base(Some("http://udm.example.org:7777".to_string()));
        let supi = "imsi-001010000001440";
        clear(supi);
        let (_amf, amf_base) = real_amf("amf-1440").await;
        let (_nef, nef_uri, nef_seen) = nef_stub().await;
        let client = UdrClient::Mock(Arc::new(crate::uecm::MockUdr::new()));

        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-1440"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
        let id = ee_subscribe(
            supi,
            &nef_uri,
            json!({ "loc": { "eventType": "LOSS_OF_CONNECTIVITY" } }),
        )
        .await;

        // Step 3a, read back from the AMF's own store.
        let leg = stored(&id)
            .and_then(|s| s.amf_leg)
            .expect("the UDM holds an AMF subscription");
        assert!(
            leg.subscription_uri
                .starts_with(&format!("{amf_base}/namf-evts/v1/subscriptions/")),
            "{leg:?}"
        );
        let at_amf = amf_subscription(&leg).expect("amfd stored the subscription");
        assert_eq!(at_amf.event_types, vec!["LOSS_OF_CONNECTIVITY".to_string()]);
        assert_eq!(at_amf.supi.as_deref(), Some(supi));
        assert_eq!(
            at_amf.notify_uri, nef_uri,
            "the AMF notifies the NEF directly (step 4)"
        );
        assert_eq!(
            at_amf.subs_change_notify_uri.as_deref(),
            Some(
                format!(
                    "http://udm.example.org:7777/nudm-callback/v1/{id}/ee-amf-subs-change/{}",
                    leg.change_token
                )
                .as_str()
            ),
            "the UDM provides its own endpoint too (step 3a)"
        );

        // Steps 4-6: an AMF-detected loss reaches the NEF with the AMF's reason.
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

        // Deregistration: the UDM's own UECM-derived LoC is not sent as well.
        // `process_amf_deregistration` awaits its notifications, so anything the
        // UDM sent is already recorded when it returns.
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        let from_udm = nef_seen
            .lock()
            .expect("sink")
            .iter()
            .filter(|b| b["reportList"][0].get("eventType").is_some())
            .count();
        assert_eq!(
            from_udm, 0,
            "the AMF reports LoC; the UDM must not report it twice"
        );
        assert!(
            stored(&id).and_then(|s| s.amf_leg).is_some(),
            "the leg outlives the UE context"
        );

        // Unsubscribe removes the AMF subscription too.
        let resp = crate::app::handle_ee_unsubscribe(supi, &id).await;
        assert_eq!(resp.status, 204);
        assert!(
            amf_subscription(&leg).is_none(),
            "the AMF subscription is deleted"
        );
        set_notify_base(None);
    }

    /// **#1440.** A subscription made before the UE registers is forwarded when
    /// it does; a PATCH that drops the AMF-detected event deletes it at the AMF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM/AMF state
    async fn registration_forwards_and_patch_releases() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000002440";
        clear(supi);
        let (_amf, _amf_base) = real_amf("amf-2440").await;
        let client = UdrClient::Mock(Arc::new(crate::uecm::MockUdr::new()));

        let id = ee_subscribe(
            supi,
            "http://nef.example.org/notify",
            json!({ "loc": { "eventType": "LOSS_OF_CONNECTIVITY" } }),
        )
        .await;
        assert!(
            stored(&id).and_then(|s| s.amf_leg).is_none(),
            "no serving AMF yet"
        );

        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-2440"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
        let leg = stored(&id)
            .and_then(|s| s.amf_leg)
            .expect("forwarded on registration");
        assert!(amf_subscription(&leg).is_some());

        // A re-registration at the same AMF keeps the one subscription.
        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-2440"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 200);
        assert_eq!(stored(&id).and_then(|s| s.amf_leg), Some(leg.clone()));

        let mut patch = SbiRequest::patch(format!("/nudm-ee/v1/{supi}/ee-subscriptions/{id}"));
        patch.http.content = Some(
            json!([{
                "op": "replace",
                "path": "/monitoringConfigurations",
                "value": { "r": { "eventType": "UE_REACHABILITY_FOR_DATA" } },
            }])
            .to_string(),
        );
        assert_eq!(
            crate::app::handle_ee_modify(supi, &id, &patch).await.status,
            204
        );
        assert!(stored(&id).and_then(|s| s.amf_leg).is_none());
        assert!(amf_subscription(&leg).is_none(), "released at the AMF");
        clear(supi);
    }

    /// **#1440, the fallback and #1444.** With no reachable serving AMF the UDM
    /// keeps raising LoC itself on deregistration, now as a TS 29.503 §6.4.6.2.17
    /// LossConnectivityReport with a top-level timeStamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn without_an_amf_leg_the_udm_reports_loc_with_its_reason() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000003440";
        clear(supi);
        let (_nef, nef_uri, nef_seen) = nef_stub().await;
        let client = UdrClient::Mock(Arc::new(crate::uecm::MockUdr::new()));
        // An AMF this UDM cannot resolve: not cached, and no NRF to ask.
        let resp = process_amf_registration(
            supi,
            &amf_registration("amf-unknown-3440"),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
        let id = ee_subscribe(
            supi,
            &nef_uri,
            json!({ "loc": { "eventType": "LOSS_OF_CONNECTIVITY" } }),
        )
        .await;
        assert!(stored(&id).and_then(|s| s.amf_leg).is_none());

        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        let got = nef_seen.lock().expect("sink").clone();
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

    /// **#1440, the UDM's change endpoint.** Only the token this UDM handed the AMF
    /// moves a leg, only to a Namf_EventExposure subscription URI; a transferred
    /// copy at an AMF the UDM already subscribed at is not adopted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn subscription_change_moves_the_leg_only_with_its_token() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000004440";
        clear(supi);
        let mut sub = UdmEeSubscription::for_ue(
            supi,
            "http://nef.example.org/notify",
            json!({
                "callbackReference": "http://nef.example.org/notify",
                "monitoringConfigurations": { "loc": { "eventType": "LOSS_OF_CONNECTIVITY" } },
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
        let new = &format!(
            "http://127.0.0.1:{}/namf-evts/v1/subscriptions/sub-new",
            new_port.addr().port()
        );
        // Through the real router, as the AMF would reach it.
        let resp = crate::app::udm_sbi_request_handler(change("forged", new)).await;
        assert_eq!(resp.status, 404, "a wrong token is refused");
        let resp =
            crate::app::udm_sbi_request_handler(change("tok-4440", "http://evil.example/x")).await;
        assert_eq!(
            resp.status, 400,
            "only a Namf_EventExposure subscription URI"
        );
        assert_eq!(
            stored(&id)
                .and_then(|s| s.amf_leg)
                .map(|l| l.subscription_uri),
            Some(old)
        );

        let resp = crate::app::udm_sbi_request_handler(change("tok-4440", new)).await;
        assert_eq!(resp.status, 204);
        assert_eq!(
            stored(&id)
                .and_then(|s| s.amf_leg)
                .map(|l| l.subscription_uri)
                .as_deref(),
            Some(new.as_str()),
            "the leg follows the subscription to the new AMF"
        );

        // A second id at the SAME AMF is a duplicate of the one held: kept as is.
        let dup = &format!(
            "http://127.0.0.1:{}/namf-evts/v1/subscriptions/sub-dup",
            new_port.addr().port()
        );
        let resp = crate::app::udm_sbi_request_handler(change("tok-4440", dup)).await;
        assert_eq!(resp.status, 204);
        assert_eq!(
            stored(&id)
                .and_then(|s| s.amf_leg)
                .map(|l| l.subscription_uri)
                .as_deref(),
            Some(new.as_str())
        );
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
