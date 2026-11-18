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
//! # Accepted, then delivered (#1775 review MAJOR-1)
//!
//! The UDR is answered 204 as soon as the notification is validated (token, body)
//! and queued, before any consumer is tried. The UDR bounds its wait for the answer
//! (3 s) and resends a change it saw no 2xx for, so an answer that waited for the
//! consumers (each also bounded to 3 s) let one slow AMF, or two subscriptions,
//! make the UDR resend, and every consumer that had taken the change got it twice.
//! Acknowledging on acceptance is the option taken over making delivery idempotent:
//! a `ModificationNotification` carries no sequence number or change id the AMF
//! could deduplicate on (TS 29.503 §6.1.6.2.21), and a REPLACE applied twice is
//! harmless but an ADD/REMOVE pair resent out of order is not.
//!
//! Each SUPI has one queue and at most one worker draining it
//! ([`enqueue_changes`]), so the notifications of one SUPI are delivered one at a
//! time, in the order the UDR sent them: a later change cannot overtake an earlier
//! one. The UDR sends each subscription's changes one at a time too (it sends the
//! next only after this 204). The consumers of one notification are tried
//! concurrently, and the next notification waits for all of them. A queue holds at
//! most [`MAX_QUEUED_PER_SUPI`] notifications; one more is answered 503, which the
//! UDR resends at its next pass, so nothing is lost and nothing is told twice.
//!
//! # Restart
//!
//! Legs are held in memory, like the SDM subscriptions they serve. After a restart
//! the UDR's notifications on an old leg name a token this UDM does not hold, and
//! are answered 404, on which the UDR removes that subscription.

use crate::context::{udm_self, UdmSdmSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
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

/// SUPI -> the lock its reconciles take (deliveries are ordered by the SUPI's
/// single worker instead, [`QUEUES`]). An entry is dropped when no
/// one else holds it, so the map does not outgrow [`LEGS`]'s SUPIs.
static SUPI_LOCKS: Mutex<Option<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

/// Spawned reconciles and delivery workers not yet finished; tests wait for none
/// ([`wait_idle`]).
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// The most accepted notifications of one SUPI waiting for delivery. One more is
/// answered 503, and the UDR resends it at its next pass.
pub const MAX_QUEUED_PER_SUPI: usize = 32;

/// SUPI -> the accepted am-data changes waiting for delivery, oldest first. An entry
/// exists exactly while that SUPI's worker runs ([`enqueue_changes`]), so the map is
/// bounded by the SUPIs with a leg ([`LEGS`]: only a leg's token is accepted), and
/// each queue by [`MAX_QUEUED_PER_SUPI`].
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static QUEUES: Mutex<Option<HashMap<String, VecDeque<Vec<Value>>>>> = Mutex::new(None);

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
    spawn_reconcile_attempt(supi.to_string(), 0);
}

/// The most reconciles of one SUPI in a row whose UDR subscribe failed; after them
/// the leg is left unmade until the SUPI's next SDM subscribe.
const MAX_RECONCILE_ATTEMPTS: u32 = 8;

/// The wait before reconcile attempt `attempt` (1-based retry): 1 s doubling, at
/// most 60 s, so the eight attempts span about three minutes.
fn reconcile_backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.min(6).saturating_sub(1)).min(60))
}

/// Run reconcile `attempt` of `supi` now. A failed UDR subscribe is retried with
/// backoff (#1775 review minor): the AMF subscribes once per registration, so
/// without the retry a UDR that was down at that moment left the UE without am-data
/// notifications until it registered again.
fn spawn_reconcile_attempt(supi: String, attempt: u32) {
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let retry = reconcile(&supi).await;
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        if !retry {
            return;
        }
        let next = attempt + 1;
        if next >= MAX_RECONCILE_ATTEMPTS {
            log::error!(
                "[{supi}] UDR am-data subscription not made after {next} attempts; am-data \
                 changes are not notified until the next SDM subscribe"
            );
            return;
        }
        tokio::time::sleep(reconcile_backoff(next)).await;
        spawn_reconcile_attempt(supi, next);
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
/// am-data and this UDM has a callback address to give. `true` when the leg is
/// wanted and the UDR subscribe failed, so it is worth retrying.
pub async fn reconcile(supi: &str) -> bool {
    let lock = supi_lock(supi);
    let mut retry = false;
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
                // The SDM subscription stands; the leg is retried with backoff.
                Err(e) => {
                    log::warn!("[{supi}] UDR am-data subscription not made: {e}; retried");
                    retry = true;
                }
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
    retry
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
    match enqueue_changes(supi, changes) {
        Ok(()) => SbiResponse::with_status(204),
        Err(()) => {
            log::warn!(
                "[{supi}] {MAX_QUEUED_PER_SUPI} am-data changes already wait for delivery: \
                 503, the UDR resends this one"
            );
            nextgcore_sbi::server::send_error(
                503,
                "Service Unavailable",
                "too many am-data changes waiting for delivery",
                None,
            )
        }
    }
}

/// Accept `changes` for delivery to `supi`'s consumers. They join the SUPI's
/// queue, behind every change accepted before them, and the SUPI's worker is
/// started when none runs. `Err` when the queue is full ([`MAX_QUEUED_PER_SUPI`]).
fn enqueue_changes(supi: &str, changes: Vec<Value>) -> Result<(), ()> {
    {
        let mut map = QUEUES.lock().unwrap_or_else(|e| e.into_inner());
        let map = map.get_or_insert_with(HashMap::new);
        if let Some(queue) = map.get_mut(supi) {
            // A worker runs for the SUPI and takes this one after the others.
            if queue.len() >= MAX_QUEUED_PER_SUPI {
                return Err(());
            }
            queue.push_back(changes);
            return Ok(());
        }
        map.insert(supi.to_string(), VecDeque::from([changes]));
    }
    let supi = supi.to_string();
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        while let Some(changes) = next_queued(&supi) {
            Box::pin(deliver_to_consumers(&supi, &changes)).await;
        }
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    });
    Ok(())
}

/// The oldest change waiting for `supi`'s worker. When none waits the queue is
/// removed, under the same lock, so the worker ends and the next accepted change
/// starts a new one.
fn next_queued(supi: &str) -> Option<Vec<Value>> {
    let mut map = QUEUES.lock().unwrap_or_else(|e| e.into_inner());
    let map = map.as_mut()?;
    let queue = map.get_mut(supi)?;
    match queue.pop_front() {
        Some(changes) => Some(changes),
        None => {
            map.remove(supi);
            None
        }
    }
}

/// Tell every SDM subscription of `supi` that monitors am-data of `changes`,
/// concurrently; returns once each has answered or timed out.
async fn deliver_to_consumers(supi: &str, changes: &[Value]) {
    let subs = am_data_subscriptions(supi);
    if subs.is_empty() {
        // Its subscriptions went without an unsubscribe (the UE was removed).
        spawn_reconcile(supi);
    }
    if crate::notify::notifications_enabled() {
        let mut each = tokio::task::JoinSet::new();
        for sub in subs {
            let (supi, changes) = (supi.to_string(), changes.to_vec());
            each.spawn(async move { deliver(&supi, &sub, &changes).await });
        }
        while each.join_next().await.is_some() {}
    }
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
        // Accepted, then delivered (#1775 review MAJOR-1).
        wait_idle().await;
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

    /// A consumer that answers 204 to each notification after `delay(body)`. It
    /// records the body when the answer is made (so the record is in answer order),
    /// or on arrival when `on_arrival`. Its base URI.
    async fn slow_consumer(
        delay: fn(&Value) -> Duration,
        on_arrival: bool,
    ) -> (SbiServer, String, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let log = seen.clone();
        server
            .start(move |req: SbiRequest| {
                let log = log.clone();
                async move {
                    let body: Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    if on_arrival {
                        log.lock().expect("seen").push(body.clone());
                    }
                    tokio::time::sleep(delay(&body)).await;
                    if !on_arrival {
                        log.lock().expect("seen").push(body);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("consumer starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// The `newValue` of the first change of each recorded ModificationNotification.
    fn told_values(seen: &Arc<Mutex<Vec<Value>>>) -> Vec<Value> {
        seen.lock()
            .expect("seen")
            .iter()
            .map(|n| n["notifyItems"][0]["changes"][0]["newValue"].clone())
            .collect()
    }

    /// **#1775 review MAJOR-1** (failure-path check 2, both peers): the UDR's real
    /// delivery (`deliver_notification`, which waits 3 s) is answered 204 as soon as
    /// the UDM has accepted the notification, although its two consumers each take
    /// longer to answer than the UDM waits for them (3 s), so trying them first
    /// would take 6 s, longer than the UDR waits. So the UDR advances and does not
    /// resend, and each consumer gets exactly one POST.
    ///
    /// REVERT-VERIFIED: with the consumers tried one after another before the UDR is
    /// answered (the code under review), the UDR's delivery times out ("answered
    /// before the consumer").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn the_udr_is_answered_before_a_slow_consumer_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_slow, slow_base, seen) = slow_consumer(|_| Duration::from_secs(4), true).await;
        let (_slower, slower_base, seen_too) =
            slow_consumer(|_| Duration::from_secs(4), true).await;
        let supi = "imsi-001010000017754";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/slow")).await;
        sdm_subscribe(supi, &format!("{slower_base}/cb/sdm-notify/slower")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let notify = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );
        let answered =
            nextgcore_udrd::data_store::deliver_notification(&udm_callback, &notify).await;
        assert_eq!(answered, Ok(204), "answered before the consumer");
        // The UDM gives up on each after 3 s, and resends nothing.
        tokio::time::sleep(Duration::from_millis(3500)).await;
        wait_idle().await;
        for seen in [&seen, &seen_too] {
            assert_eq!(
                told_values(seen),
                vec![json!(["msisdn-2"])],
                "exactly one POST"
            );
        }
        clear_legs();
    }

    /// **#1775 review MAJOR-3**: two DataChangeNotify of one SUPI that overlap reach
    /// the consumer in the order the UDR sent them, although the first is the slow
    /// one: the consumer takes 800 ms over the first and none over the second. Both
    /// are accepted (204) at once.
    ///
    /// REVERT-VERIFIED: with a second worker started for the SUPI while one runs
    /// (`enqueue_changes` not joining the running worker's queue), the second
    /// change is told first ("in the order the UDR sent them").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn overlapping_changes_of_one_supi_arrive_in_order_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_slow, slow_base, seen) = slow_consumer(
            |body| {
                if body["notifyItems"][0]["changes"][0]["newValue"] == json!(["msisdn-2"]) {
                    Duration::from_millis(800)
                } else {
                    Duration::ZERO
                }
            },
            false,
        )
        .await;
        let supi = "imsi-001010000017755";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/order")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let first = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );
        let second = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-2"]}),
            &json!({"gpsis": ["msisdn-3"]}),
        );
        assert_eq!(post(&udm_callback, &first).await, 204);
        assert_eq!(post(&udm_callback, &second).await, 204);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        wait_idle().await;
        assert_eq!(
            told_values(&seen),
            vec![json!(["msisdn-2"]), json!(["msisdn-3"])],
            "in the order the UDR sent them"
        );
        clear_legs();
    }

    /// **#1775 review MAJOR-1**: a SUPI's queue is bounded. While its consumer is
    /// slow, the notification after `MAX_QUEUED_PER_SUPI` waiting ones is answered
    /// 503 (the UDR resends it at its next pass); every accepted one is delivered.
    ///
    /// REVERT-VERIFIED: with the bound not checked, that notification is answered
    /// 204 ("bounded").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_full_queue_is_answered_503_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_slow, slow_base, seen) = slow_consumer(
            |body| {
                if body["notifyItems"][0]["changes"][0]["newValue"] == json!(0) {
                    Duration::from_millis(1500)
                } else {
                    Duration::ZERO
                }
            },
            false,
        )
        .await;
        let supi = "imsi-001010000017756";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/full")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let change =
            |n: usize| udr_notify(supi, &udm_callback, &json!({"n": n + 1}), &json!({"n": n}));
        // The first is taken by the worker and held by the slow consumer; the
        // next MAX_QUEUED_PER_SUPI wait.
        for n in 0..=MAX_QUEUED_PER_SUPI {
            assert_eq!(post(&udm_callback, &change(n)).await, 204, "{n}");
        }
        assert_eq!(
            post(&udm_callback, &change(MAX_QUEUED_PER_SUPI + 1)).await,
            503,
            "bounded"
        );
        tokio::time::sleep(Duration::from_millis(2000)).await;
        wait_idle().await;
        assert_eq!(seen.lock().expect("seen").len(), MAX_QUEUED_PER_SUPI + 1);
        clear_legs();
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
