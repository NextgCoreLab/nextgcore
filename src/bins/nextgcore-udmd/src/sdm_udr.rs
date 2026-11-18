//! am-data change notification: from the UDR's Nudr_DM_Notify to the AMF's
//! Nudm_SDM_Notification (#1775).
//!
//! TS 23.502 §4.5.1: "Whenever the user profile is changed for a user in the
//! UDM/UDR and the changes affect the user profile in the AMF, the UDM shall notify
//! these changes to the affected AMF by the means of invoking
//! Nudm_SDM_Notification". The AMF subscribes to the UE's `am-data` at registration
//! (`POST /nudm-sdm/v2/{supi}/sdm-subscriptions`, #1748). The change itself is
//! provisioned in the UDR, so this UDM learns of it from the UDR.
//!
//! # The UDR leg
//!
//! While at least one SDM subscription of a SUPI monitors its `am-data`, this UDM
//! holds one subscription for that SUPI at the UDR
//! (`POST /nudr-dr/v2/subscription-data/subs-to-notify`, TS 29.505 §5.2.20 /
//! §5.4.2.6), monitoring `/subscription-data/{supi}/provisioned-data/am-data`. Its
//! `callbackReference` is `/nudm-callback/v1/{supi}/udr-data-change/{token}`, with a
//! token minted per leg: the UDR sends no access token with a notification
//! (TS 33.501 §13.4.1), so the token is what admits it (#1421). No `ueId` is
//! given, so the UDR tells this leg of am-data changes only, not of every change of
//! the UE's data.
//!
//! Legs are reconciled after the SDM subscribe or unsubscribe answered
//! ([`spawn_reconcile`]): an AMF's registration must not wait on the UDR. The
//! reconciles of one SUPI run one at a time, so two of them cannot both create a
//! leg. A leg whose SUPI has no am-data subscription any more is deleted at the
//! UDR (a 404 there means it is gone already).
//!
//! # The notification
//!
//! [`handle_udr_data_change`]: the UDR's `DataChangeNotify` carries `ChangeItem`s
//! per changed am-data member (`op`, `path`, `newValue`, `origValue`; arrays
//! replaced whole, TS 29.503 §5.2.2.5.2). This UDM sends them on, unchanged, in a
//! `ModificationNotification` (TS 29.503 §6.1.6.2.21) to the `callbackReference` of
//! each SDM subscription of the SUPI that monitors am-data, naming
//! `/nudm-sdm/v2/{supi}/am-data` and the subscription's id. The answers
//! (TS 29.503 Table 6.1.5.2-3):
//! - 204: delivered;
//! - 404: the subscription is gone at the consumer; it is removed here, and the leg
//!   reconciled;
//! - any other status, or no answer: logged and not resent. In particular a 400 is
//!   the consumer refusing the change (amfd answers it for a change it cannot apply,
//!   DECISIONS 2026-11-18-030000), and resending it would only be refused again.
//!
//! The notifications of one SUPI are delivered one at a time, in the order the UDR
//! sent them, so an earlier change cannot overtake a later one; the UDR sends each
//! subscription's changes one at a time too. The UDR is answered 204 once the
//! consumers were tried.
//!
//! # Restart
//!
//! Legs are held in memory, like the SDM subscriptions they serve. After a restart
//! the UDR's notifications on an old leg name a token this UDM does not hold, and
//! are answered 404, on which the UDR removes that subscription.

use crate::context::{udm_self, UdmSdmSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The path segment of the UDR data-change callback; the leg's token follows it,
/// so the shared log redaction hides it.
pub const UDR_DATA_CHANGE_SEGMENT: &str = "udr-data-change";

/// The bound on one UDR or consumer call.
const CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// This UDM's subscription at the UDR for one SUPI's am-data.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UdrLeg {
    /// The created resource's path at the UDR, for the DELETE.
    subscription_path: String,
    /// The token in the leg's `callbackReference`.
    token: String,
}

/// SUPI -> its UDR leg. Bounded by the SUPIs with an SDM subscription, which the
/// context caps (`max_num_of_sdm_subscriptions`).
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static LEGS: Mutex<Option<HashMap<String, UdrLeg>>> = Mutex::new(None);

/// SUPI -> the lock its reconciles and deliveries take. An entry is dropped when no
/// one else holds it, so the map does not outgrow [`LEGS`]'s SUPIs.
static SUPI_LOCKS: Mutex<Option<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

/// Spawned reconciles not yet finished; tests wait for none ([`wait_idle`]).
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

fn leg(supi: &str) -> Option<UdrLeg> {
    LEGS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(supi).cloned())
}

fn set_leg(supi: &str, leg: Option<UdrLeg>) {
    let mut map = LEGS.lock().unwrap_or_else(|e| e.into_inner());
    let map = map.get_or_insert_with(HashMap::new);
    match leg {
        Some(l) => map.insert(supi.to_string(), l),
        None => map.remove(supi),
    };
}

fn supi_lock(supi: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = SUPI_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.get_or_insert_with(HashMap::new)
        .entry(supi.to_string())
        .or_default()
        .clone()
}

/// Drop `supi`'s lock entry when `held` (the caller's clone) and the map's are its
/// only holders and the SUPI has no leg.
fn release_supi_lock(supi: &str, held: Arc<tokio::sync::Mutex<()>>) {
    let mut map = SUPI_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = map.as_mut() {
        if Arc::strong_count(&held) == 2 && leg(supi).is_none() {
            map.remove(supi);
        }
    }
}

/// Whether `token` is `supi`'s leg token: the check both the handler and the
/// server's OAuth2 callback exemption (#1421) apply.
pub(crate) fn token_matches(supi: &str, token: &str) -> bool {
    leg(supi).is_some_and(|l| crate::ee_amf::tokens_equal(&l.token, token))
}

/// `/nudm-callback/v1/{supi}/udr-data-change/{token}`.
pub fn data_change_path(supi: &str, token: &str) -> String {
    format!("/nudm-callback/v1/{supi}/{UDR_DATA_CHANGE_SEGMENT}/{token}")
}

/// Whether `sub` monitors its UE's am-data.
fn monitors_am_data(sub: &UdmSdmSubscription) -> bool {
    sub.monitored_resource_uris
        .iter()
        .any(|u| u.trim_end_matches('/').ends_with("/am-data"))
}

/// The SDM subscriptions of `supi` that monitor its am-data.
fn am_data_subscriptions(supi: &str) -> Vec<UdmSdmSubscription> {
    let ctx = udm_self();
    let Ok(context) = ctx.read() else {
        return Vec::new();
    };
    context
        .sdm_subscriptions_for_supi(supi)
        .into_iter()
        .filter(monitors_am_data)
        .collect()
}

/// The UDR resource this UDM's leg monitors (TS 29.505).
pub fn udr_am_data_path(supi: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data")
}

/// The `SubscriptionDataSubscriptions` body of `supi`'s leg (TS 29.505).
pub(crate) fn leg_body(base: &str, supi: &str, token: &str) -> Value {
    json!({
        "callbackReference": format!("{base}{}", data_change_path(supi, token)),
        "monitoredResourceUris": [udr_am_data_path(supi)],
    })
}

/// Send `request` to the UDR, bounded by [`CALL_TIMEOUT`].
async fn udr_call(request: SbiRequest) -> Result<SbiResponse, String> {
    tokio::time::timeout(
        CALL_TIMEOUT,
        crate::sbi_path::udm_sbi_discover_and_send_nudr_dr(0, 0, request),
    )
    .await
    .map_err(|_| "UDR call timed out".to_string())?
}

/// Create `supi`'s leg at the UDR.
async fn udr_subscribe(base: &str, supi: &str) -> Result<UdrLeg, String> {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let request = SbiRequest::post("/nudr-dr/v2/subscription-data/subs-to-notify")
        .with_json_body(&leg_body(base, supi, &token))
        .map_err(|e| format!("body: {e}"))?;
    let resp = udr_call(request).await?;
    if resp.status != 201 {
        return Err(format!("UDR answered {}", resp.status));
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
                .map(|id| format!("/nudr-dr/v2/subscription-data/subs-to-notify/{id}"))
        })
        .ok_or("201 without a Location or subscriptionId")?;
    // An absolute Location keeps only its path: the call goes to the UDR again.
    let subscription_path = match location.split_once("://") {
        Some((_, rest)) => rest
            .find('/')
            .map_or("/".to_string(), |i| rest[i..].to_string()),
        None => location,
    };
    Ok(UdrLeg {
        subscription_path,
        token,
    })
}

/// Delete a leg at the UDR. Best-effort: a 404 means it is gone already.
async fn udr_unsubscribe(supi: &str, leg: &UdrLeg) {
    match udr_call(SbiRequest::delete(&leg.subscription_path)).await {
        Ok(resp) => log::info!(
            "[{supi}] UDR am-data subscription {} deleted: status={}",
            leg.subscription_path,
            resp.status
        ),
        Err(e) => log::warn!(
            "[{supi}] UDR am-data subscription {} not deleted: {e}",
            leg.subscription_path
        ),
    }
}

/// Reconcile `supi`'s leg after the answer to the operation that changed what it
/// needs.
pub fn spawn_reconcile(supi: &str) {
    let supi = supi.to_string();
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        reconcile(&supi).await;
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Wait until no spawned reconcile is running (tests).
pub async fn wait_idle() {
    for _ in 0..500 {
        if IN_FLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Make `supi`'s leg exist exactly while an SDM subscription of `supi` monitors its
/// am-data and this UDM has a callback address to give.
pub async fn reconcile(supi: &str) {
    let lock = supi_lock(supi);
    {
        let _serial = lock.lock().await;
        let want = !am_data_subscriptions(supi).is_empty();
        match (want, leg(supi), crate::ee_amf::notify_base()) {
            (true, None, Some(base)) => match udr_subscribe(&base, supi).await {
                Ok(new_leg) => {
                    log::info!(
                        "[{supi}] subscribed at the UDR for am-data changes: {}",
                        new_leg.subscription_path
                    );
                    set_leg(supi, Some(new_leg));
                }
                // The SDM subscription stands; the next subscribe retries.
                Err(e) => log::warn!("[{supi}] UDR am-data subscription not made: {e}"),
            },
            (true, None, None) => log::warn!(
                "[{supi}] no advertised SBI address: am-data changes are not subscribed at the UDR"
            ),
            (false, Some(old), _) => {
                set_leg(supi, None);
                udr_unsubscribe(supi, &old).await;
            }
            _ => {}
        }
    }
    release_supi_lock(supi, lock);
}

/// The am-data `ChangeItem`s of a `DataChangeNotify` (TS 29.505 §5.4.2.6) for
/// `supi`, or why it is malformed. Items naming another resource are skipped: the
/// leg monitors am-data only.
pub(crate) fn am_data_changes(supi: &str, notify: &Value) -> Result<Vec<Value>, String> {
    let items = notify
        .get("notifyItems")
        .and_then(Value::as_array)
        .ok_or("DataChangeNotify needs notifyItems")?;
    let ours = udr_am_data_path(supi);
    let mut changes = Vec::new();
    for item in items {
        let resource = item
            .get("resourceId")
            .and_then(Value::as_str)
            .ok_or("NotifyItem needs resourceId")?;
        let path = resource.split_once("://").map_or(resource, |(_, rest)| {
            rest.find('/').map_or("/", |i| &rest[i..])
        });
        if path.trim_end_matches('/') != ours {
            continue;
        }
        let item_changes = item
            .get("changes")
            .and_then(Value::as_array)
            .ok_or("NotifyItem needs changes")?;
        changes.extend(item_changes.iter().cloned());
    }
    Ok(changes)
}

/// The `ModificationNotification` (TS 29.503 §6.1.6.2.21) telling SDM subscription
/// `subscription_id` of `changes` to `supi`'s am-data.
pub fn modification_notification(supi: &str, subscription_id: &str, changes: &[Value]) -> Value {
    json!({
        "notifyItems": [{
            "resourceId": format!("/nudm-sdm/v2/{supi}/am-data"),
            "changes": changes,
        }],
        "subscriptionId": subscription_id,
    })
}

/// Tell `sub` of `changes`; whether it answered 2xx.
async fn deliver(supi: &str, sub: &UdmSdmSubscription, changes: &[Value]) -> bool {
    let Some(callback) = sub.callback_reference.as_deref() else {
        return false;
    };
    let target = nextgcore_sbi::log_redact::redact_last_segment(callback);
    let body = modification_notification(supi, &sub.id, changes);
    let sent = tokio::time::timeout(
        CALL_TIMEOUT,
        crate::sbi_path::udm_sbi_send_callback_notification(callback, &body),
    )
    .await;
    match sent {
        Ok(Ok(resp)) if (200..300).contains(&resp.status) => {
            log::info!(
                "[{supi}] am-data change notified to {target}: {}",
                resp.status
            );
            true
        }
        Ok(Ok(resp)) if resp.status == 404 => {
            log::info!(
                "[{supi}] {target} answered 404: SDM subscription {} is gone, removed",
                sub.id
            );
            let ctx = udm_self();
            if let Ok(context) = ctx.read() {
                context.sdm_subscription_remove(&sub.id);
            }
            spawn_reconcile(supi);
            false
        }
        Ok(Ok(resp)) => {
            log::warn!(
                "[{supi}] {target} answered {} to the am-data change; not resent",
                resp.status
            );
            false
        }
        Ok(Err(e)) => {
            log::warn!("[{supi}] am-data change not delivered: {e}; not resent");
            false
        }
        Err(_) => {
            log::warn!("[{supi}] am-data change to {target} timed out; not resent");
            false
        }
    }
}

/// `POST /nudm-callback/v1/{supi}/udr-data-change/{token}`: the UDR's
/// `DataChangeNotify` for `supi`'s am-data.
pub async fn handle_udr_data_change(supi: &str, token: &str, request: &SbiRequest) -> SbiResponse {
    if !token_matches(supi, token) {
        // Not a leg this UDM holds (one from before a restart): 404, on which the
        // UDR removes it.
        return nextgcore_sbi::server::send_not_found(
            "No such UDR data-change subscription",
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }
    let notify: Value = match request
        .http
        .content
        .as_deref()
        .map(serde_json::from_str::<Value>)
    {
        Some(Ok(v)) => v,
        _ => {
            return nextgcore_sbi::server::send_bad_request(
                "DataChangeNotify body is not JSON",
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let changes = match am_data_changes(supi, &notify) {
        Ok(c) => c,
        Err(e) => return nextgcore_sbi::server::send_bad_request(&e, Some("INVALID_MSG_FORMAT")),
    };
    if changes.is_empty() {
        return SbiResponse::with_status(204);
    }
    let lock = supi_lock(supi);
    {
        let _in_order = lock.lock().await;
        let subs = am_data_subscriptions(supi);
        if subs.is_empty() {
            // Its subscriptions went without an unsubscribe (the UE was removed).
            spawn_reconcile(supi);
        }
        if crate::notify::notifications_enabled() {
            for sub in &subs {
                Box::pin(deliver(supi, sub, &changes)).await;
            }
        }
    }
    release_supi_lock(supi, lock);
    SbiResponse::with_status(204)
}

/// Forget every leg (tests).
#[cfg(test)]
pub(crate) fn clear_legs() {
    *LEGS.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// `supi`'s leg's token, if any (tests).
#[cfg(test)]
pub(crate) fn leg_token(supi: &str) -> Option<String> {
    leg(supi).map(|l| l.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ee_amf::set_notify_base;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::sync::Arc;

    type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

    async fn wait_listening(addr: std::net::SocketAddr) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A peer answering `status` to every request (201 with a Location to a POST
    /// when `status` is 201), recording (method, path, body). Its base URI.
    async fn stub(status: u16) -> (SbiServer, String, Seen) {
        let seen: Seen = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let log = seen.clone();
        server
            .start(move |req: SbiRequest| {
                let log = log.clone();
                async move {
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    let path = req.header.uri.clone();
                    log.lock()
                        .expect("seen")
                        .push((req.header.method.clone(), path, body));
                    match (req.header.method.as_str(), status) {
                        ("POST", 201) => SbiResponse::with_status(201).with_header(
                            "Location",
                            "/nudr-dr/v2/subscription-data/subs-to-notify/77",
                        ),
                        ("DELETE", _) => SbiResponse::with_status(204),
                        _ => SbiResponse::with_status(status),
                    }
                }
            })
            .await
            .expect("stub starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    fn requests(seen: &Seen, method: &str) -> Vec<(String, Value)> {
        seen.lock()
            .expect("seen")
            .iter()
            .filter(|(m, _, _)| m == method)
            .map(|(_, p, b)| (p.clone(), b.clone()))
            .collect()
    }

    /// The UDM's own SBI listener (its real router); its base URI.
    async fn udm_server() -> (SbiServer, String) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udm = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        udm.start(crate::app::udm_sbi_request_handler)
            .await
            .expect("udm starts");
        wait_listening(addr).await;
        (udm, format!("http://127.0.0.1:{}", addr.port()))
    }

    /// An AMF's SDM subscribe of `supi`'s am-data with `callback`; the reconcile it
    /// spawned has finished on return.
    async fn sdm_subscribe(supi: &str, callback: &str) -> String {
        let mut req = SbiRequest::post(format!("/nudm-sdm/v2/{supi}/sdm-subscriptions"));
        req.http.content = Some(
            json!({
                "nfInstanceId": "amf-1775",
                "callbackReference": callback,
                "monitoredResourceUris": [format!("/nudm-sdm/v2/{supi}/am-data")],
            })
            .to_string(),
        );
        let resp = crate::app::handle_sdm_subscribe(supi, &req).await;
        assert_eq!(resp.status, 201);
        wait_idle().await;
        serde_json::from_str::<Value>(resp.http.content.as_deref().expect("body")).expect("json")
            ["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string()
    }

    /// The UDR's DataChangeNotify for `supi`'s am-data going from `old` to `new`,
    /// built by udrd's REAL builders.
    fn udr_notify(supi: &str, callback: &str, old: &Value, new: &Value) -> Value {
        use nextgcore_udrd::data_store as udr;
        let sub = udr::StoredSub {
            id: "77".to_string(),
            kind: udr::SubKind::SubscriptionData,
            notify_uri: callback.to_string(),
            body: json!({ "callbackReference": callback }),
        };
        udr::data_change_notify(
            &sub,
            supi,
            &udr::am_data_path(supi),
            udr::am_data_changes(old, new),
        )
    }

    async fn post(uri: &str, body: &Value) -> u16 {
        crate::sbi_path::udm_sbi_send_callback_notification(uri, body)
            .await
            .expect("answered")
            .status
    }

    /// The locks, a dev profile, fresh UDM and AMF contexts, the UDR env pointed at
    /// `udr_base`. Hold the returned guards.
    async fn setup(
        udr_base: &str,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let udr_env = crate::sbi_path::UDR_ENV_TEST_LOCK.lock().await;
        let guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(64, 64);
        clear_legs();
        let port = udr_base.rsplit(':').next().expect("port");
        std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDR_SBI_PORT", port);
        (udr_env, guard)
    }

    /// **#1775 acceptance, TS 23.502 §4.5.1, both peers.** The AMF's SDM
    /// subscription to am-data makes this UDM subscribe at the UDR for that am-data
    /// (TS 29.505), with its own tokened callback. A provisioning change of the
    /// subscribed UE-AMBR and GPSI, as udrd's real builders put it in a
    /// DataChangeNotify, posted to that callback on the UDM's real router, reaches
    /// amfd's REAL `sdmsubscription-notify/{token}` handler, which applies it: the
    /// UE's UE-AMBR and GPSI are the new ones. The AMF unsubscribing takes the UDR
    /// subscription with it.
    ///
    /// REVERT-VERIFIED: with `spawn_reconcile` not called at SDM subscribe, no UDR
    /// subscription is made; with the deliveries skipped in
    /// `handle_udr_data_change`, the UDR is answered 204 and the AMF keeps the old
    /// UE-AMBR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_provisioned_am_data_change_reaches_amfd_through_the_udm_1775() {
        let (_udr, udr_base, udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let supi = "imsi-001010000017751";
        let amf_token = "0123456789abcdef0123456789a17751";
        let old = json!({
            "subscribedUeAmbr": {"uplink": "1 Mbps", "downlink": "2 Mbps"},
            "gpsis": ["msisdn-4917751"],
        });

        // amfd's REAL Namf router, holding the UE (CM-IDLE) with its am-data.
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let amf = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        amf.start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd starts");
        wait_listening(addr).await;
        nextgcore_amfd::test_support::init_context();
        {
            let ctx = nextgcore_amfd::context::amf_self();
            let guard = ctx.read().expect("amf ctx");
            let ran = guard.ran_ue_add(901_775, 61_775).expect("ran_ue_add");
            let mut ue = guard.amf_ue_add(ran.id).expect("amf_ue_add");
            ue.supi = Some(supi.to_string());
            ue.sdm_notify_token = Some(amf_token.to_string());
            ue.am_data = Some(old.clone());
            ue.gpsi = Some("msisdn-4917751".to_string());
            ue.ue_ambr.uplink = 1_000_000;
            ue.ue_ambr.downlink = 2_000_000;
            ue.ran_ue_id = nextgcore_amfd::context::NEXTGCORE_INVALID_POOL_ID;
            guard.amf_ue_publish(&ue, 61_775, 901_775);
            guard.amf_ue_update(&ue);
        }
        let built = nextgcore_amfd::sbi_path::sdm_callback_reference(supi, Some(amf_token));
        let amf_callback = format!(
            "http://127.0.0.1:{}{}",
            addr.port(),
            &built[built.find("/namf-callback").expect("path")..]
        );

        let sdm_id = sdm_subscribe(supi, &amf_callback).await;
        let made = requests(&udr_seen, "POST");
        assert_eq!(made.len(), 1, "one UDR subscription: {made:?}");
        let (path, body) = &made[0];
        assert_eq!(path, "/nudr-dr/v2/subscription-data/subs-to-notify");
        assert_eq!(
            body["monitoredResourceUris"],
            json!([format!(
                "/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"
            )])
        );
        assert!(
            body.get("ueId").is_none(),
            "am-data only, not every change of the UE"
        );
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        assert_eq!(body["callbackReference"], udm_callback);

        let new = json!({
            "subscribedUeAmbr": {"uplink": "5 Mbps", "downlink": "10 Mbps"},
            "gpsis": ["msisdn-4917759"],
        });
        let notify = udr_notify(supi, &udm_callback, &old, &new);
        assert_eq!(post(&udm_callback, &notify).await, 204);
        let ue = nextgcore_amfd::context::amf_self()
            .read()
            .expect("amf ctx")
            .amf_ue_find_by_supi(supi)
            .expect("ue");
        assert_eq!(
            (ue.ue_ambr.uplink, ue.ue_ambr.downlink),
            (5_000_000, 10_000_000),
            "the new UE-AMBR"
        );
        assert_eq!(ue.gpsi.as_deref(), Some("msisdn-4917759"), "the new GPSI");

        assert_eq!(
            crate::app::handle_sdm_unsubscribe(supi, &sdm_id)
                .await
                .status,
            204
        );
        wait_idle().await;
        assert_eq!(
            requests(&udr_seen, "DELETE"),
            vec![(
                "/nudr-dr/v2/subscription-data/subs-to-notify/77".to_string(),
                Value::Null
            )],
            "the last am-data subscription takes the UDR leg with it"
        );
        assert!(leg_token(supi).is_none());
        amf.stop().await.expect("stop");
    }

    /// **#1775, TS 29.503 Table 6.1.5.2-3 at the consumer.** A notification on a
    /// token this UDM does not hold is 404 (the UDR then removes it) and is sent to
    /// no one. A consumer's 400 is a refusal: the change is sent once and not again,
    /// and the subscription stays. A consumer's 404 says its subscription is gone:
    /// it is removed here, and with it the UDR leg.
    ///
    /// REVERT-VERIFIED: with `token_matches` not checked, the forged notification is
    /// delivered (the 400 consumer sees 2 posts); with the 404 arm not removing the
    /// subscription, it is still stored and no DELETE reaches the UDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn refusals_are_not_resent_and_a_gone_consumer_is_removed_1775() {
        let (_udr, udr_base, udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_refusing, refusing_base, refused) = stub(400).await;
        let (_gone, gone_base, gone) = stub(404).await;
        let supi = "imsi-001010000017752";
        let refusing_id = sdm_subscribe(supi, &format!("{refusing_base}/cb/sdm-notify/a")).await;
        let gone_id = sdm_subscribe(supi, &format!("{gone_base}/cb/sdm-notify/b")).await;
        assert_eq!(requests(&udr_seen, "POST").len(), 1, "one leg per SUPI");
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let notify = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );

        let forged = format!("{udm_base}{}", data_change_path(supi, "0000forged0000"));
        assert_eq!(
            post(&forged, &notify).await,
            404,
            "not a leg this UDM holds"
        );
        assert!(requests(&refused, "POST").is_empty() && requests(&gone, "POST").is_empty());

        assert_eq!(post(&udm_callback, &notify).await, 204);
        wait_idle().await;
        let sent = requests(&refused, "POST");
        assert_eq!(sent.len(), 1, "a refusal is not resent: {sent:?}");
        assert_eq!(
            sent[0].1,
            modification_notification(
                supi,
                &refusing_id,
                &[json!({"op": "REPLACE", "path": "/gpsis",
                         "newValue": ["msisdn-2"], "origValue": ["msisdn-1"]})]
            )
        );
        assert_eq!(requests(&gone, "POST").len(), 1);
        let held: Vec<String> = udm_self()
            .read()
            .expect("ctx")
            .sdm_subscriptions_for_supi(supi)
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(held, vec![refusing_id.clone()], "the gone one is removed");
        assert!(!held.contains(&gone_id));
        assert!(
            requests(&udr_seen, "DELETE").is_empty(),
            "one still needs the leg"
        );

        assert_eq!(
            crate::app::handle_sdm_unsubscribe(supi, &refusing_id)
                .await
                .status,
            204
        );
        wait_idle().await;
        assert_eq!(requests(&udr_seen, "DELETE").len(), 1);
    }

    /// #1775: only the am-data items of a DataChangeNotify are passed on, with their
    /// ChangeItems unchanged; a malformed one is refused.
    #[test]
    fn only_am_data_changes_are_passed_on_1775() {
        let supi = "imsi-001010000017753";
        let ambr = json!({"op": "REPLACE", "path": "/subscribedUeAmbr", "newValue": {}});
        let notify = json!({
            "ueId": supi,
            "notifyItems": [
                {"resourceId": format!("/nudr-dr/v2/subscription-data/{supi}/pp-data"),
                 "changes": [{"op": "REPLACE", "path": ""}]},
                {"resourceId": format!(
                    "http://udr:7777/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"),
                 "changes": [ambr]},
            ],
        });
        assert_eq!(am_data_changes(supi, &notify), Ok(vec![ambr]));
        assert!(am_data_changes(supi, &json!({})).is_err());
        assert!(am_data_changes(supi, &json!({"notifyItems": [{"changes": []}]})).is_err());
    }
}
