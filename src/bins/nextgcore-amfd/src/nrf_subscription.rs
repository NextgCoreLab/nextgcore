//! #668: NF status subscriptions at the NRF (TS 29.510 §5.2.2.5, §5.2.2.6).
//!
//! The AMF caches the SMF, AUSF, UDM, PCF, NSSF, NSACF and UCMF profiles it
//! discovers. Before #668 nothing told it when one of them went away or moved:
//! a deregistered or changed peer was noticed only when a request to it failed
//! (#664 made that failure recoverable). This module subscribes, once per cached
//! NF type, to `NF_DEREGISTERED` and `NF_PROFILE_CHANGED`, keeps every
//! subscription alive by renewing it before its `validityTime`, and handles the
//! NRF's `NotificationData` callback.
//!
//! # The callback only evicts
//!
//! A notification names an NF instance (`nfInstanceUri`). The AMF drops that
//! instance from its discovery cache and nothing else. It never takes an
//! endpoint, a status or a whole profile from the notification body: the next
//! request for that NF type misses the cache and re-discovers through the NRF
//! (`resolve_nf_endpoint_async`), so every endpoint the AMF dials still comes
//! from a discovery answer. A forged or stale notification can therefore cost
//! one extra discovery and cannot redirect traffic.
//!
//! # Off every procedure task
//!
//! Subscribing, renewing and unsubscribing run on the maintainer task this
//! module spawns, each request bounded by [`NRF_REQUEST_TIMEOUT`], with the
//! NF types handled concurrently. A blackholed NRF delays only that task.
//! The callback handler does no I/O.

use std::collections::HashMap;
use std::time::Duration;

use nextgcore_sbi::context::global_context;
use nextgcore_sbi::datetime::{epoch_to_rfc3339, now_epoch_secs, rfc3339_to_epoch};
use nextgcore_sbi::message::SbiRequest;
use serde_json::{json, Value};

use crate::sbi_path::{advertised_sbi_base, parse_host_port, CACHED_PEER_NF_TYPES};

/// The events subscribed to (`reqNotifEvents`). `NF_REGISTERED` is left out:
/// a new instance is found by discovery when the cache misses, and the
/// callback has nothing to evict for it.
pub const REQ_NOTIF_EVENTS: [&str; 2] = ["NF_DEREGISTERED", "NF_PROFILE_CHANGED"];

/// The NFProfile attributes the discovery cache is built from
/// (`amf_nrf_discover`): a change to any other attribute (the `load` every
/// peer PATCHes on each heartbeat, `priority`, `capacity`, ...) leaves the
/// cached profile correct and is not worth a notification. Sent as
/// `notifCondition.monitoredAttributes`, and applied again by the callback
/// to an NRF that ignores the condition.
pub const MONITORED_ATTRIBUTES: [&str; 6] = [
    "nfStatus",
    "fqdn",
    "ipv4Addresses",
    "ipv6Addresses",
    "nfServices",
    "nfServiceList",
];

/// The resource the NRF POSTs `NotificationData` to (routed by `namf_server`).
pub const NOTIFY_PATH: &str = "/namf-callback/v1/nf-status-notify";

/// Upper bound on one subscribe, renew or unsubscribe exchange with the NRF.
pub const NRF_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the maintainer looks for a missing or nearly expired subscription.
pub const MAINTAIN_INTERVAL: Duration = Duration::from_secs(30);

/// The shortest renewal lead: a subscription is renewed at least this long
/// before it expires, even when a quarter of its lifetime is less.
const MIN_RENEW_LEAD_SECS: u64 = 60;

const SUBSCRIPTIONS_PATH: &str = "/nnrf-nfm/v1/subscriptions";

/// One NRF subscription this AMF holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrfSubscription {
    /// `subscriptionId` the NRF assigned.
    pub id: String,
    /// When it was granted or last renewed (epoch seconds).
    pub granted_at: u64,
    /// The NRF's `validityTime` (epoch seconds), or `None` when the NRF gave
    /// none and the subscription does not expire.
    pub expires_at: Option<u64>,
}

impl NrfSubscription {
    /// Whether the subscription should be renewed at `now`: within a quarter
    /// of its lifetime of expiring, and never later than
    /// [`MIN_RENEW_LEAD_SECS`] before it.
    pub fn renew_due(&self, now: u64) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let lifetime = expires_at.saturating_sub(self.granted_at);
        let lead = (lifetime / 4).max(MIN_RENEW_LEAD_SECS);
        now.saturating_add(lead) >= expires_at
    }

    /// The lifetime to ask for on renewal: the one the NRF last granted.
    fn lifetime(&self) -> Option<u64> {
        self.expires_at
            .map(|e| e.saturating_sub(self.granted_at).max(MIN_RENEW_LEAD_SECS))
    }
}

/// The subscriptions one AMF holds, by subscribed NF type.
#[derive(Debug, Default)]
pub struct NrfSubscriptions {
    /// Keyed by NF type (`"SMF"`, ...).
    pub by_nf_type: HashMap<String, NrfSubscription>,
}

/// The `SubscriptionData` for NF status changes of `nf_type` (TS 29.510
/// §5.2.2.5.2, `TS29510_Nnrf_NFManagement.yaml` `SubscriptionData`).
pub fn subscription_body(amf_instance_id: &str, nf_type: &str, notify_uri: &str) -> Value {
    json!({
        "nfStatusNotificationUri": notify_uri,
        "reqNfInstanceId": amf_instance_id,
        "reqNfType": "AMF",
        "subscrCond": { "nfType": nf_type },
        "reqNotifEvents": REQ_NOTIF_EVENTS,
        "notifCondition": { "monitoredAttributes": MONITORED_ATTRIBUTES },
    })
}

/// The absolute notification URI this AMF subscribes with.
pub fn notification_uri() -> String {
    format!("{}{NOTIFY_PATH}", advertised_sbi_base())
}

/// Read the 201 answer: `subscriptionId` from the body, else from the
/// `Location` header's last segment; `validityTime` from the body.
fn parse_created(body: Option<&str>, location: Option<&str>, now: u64) -> Option<NrfSubscription> {
    let doc: Option<Value> = body.and_then(|b| serde_json::from_str(b).ok());
    let id = doc
        .as_ref()
        .and_then(|d| d.get("subscriptionId"))
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| {
            location
                .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
                .filter(|s| !s.is_empty())
                .map(String::from)
        })?;
    Some(NrfSubscription {
        id,
        granted_at: now,
        expires_at: validity_of(doc.as_ref()),
    })
}

fn validity_of(doc: Option<&Value>) -> Option<u64> {
    doc.and_then(|d| d.get("validityTime"))
        .and_then(Value::as_str)
        .and_then(rfc3339_to_epoch)
}

/// What one maintenance pass did for one NF type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaintainOutcome {
    /// A new subscription was created.
    Subscribed,
    /// The existing subscription was renewed.
    Renewed,
    /// The NRF no longer knew the subscription; a new one was created.
    Resubscribed,
    /// Nothing was due.
    Unchanged,
    /// The exchange failed; the next pass retries.
    Failed(String),
}

async fn send(
    nrf_uri: &str,
    request: SbiRequest,
) -> Result<nextgcore_sbi::message::SbiResponse, String> {
    let (host, port) =
        parse_host_port(nrf_uri).ok_or_else(|| format!("NRF URI {nrf_uri:?} is unusable"))?;
    let client = global_context().get_client(&host, port).await;
    match tokio::time::timeout(NRF_REQUEST_TIMEOUT, client.send_request(request)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "no answer within {}s",
            NRF_REQUEST_TIMEOUT.as_secs()
        )),
    }
}

/// NFStatusSubscribe (TS 29.510 §5.2.2.5.2) for `nf_type`.
pub async fn subscribe(
    nrf_uri: &str,
    amf_instance_id: &str,
    nf_type: &str,
    notify_uri: &str,
) -> Result<NrfSubscription, String> {
    let body = subscription_body(amf_instance_id, nf_type, notify_uri);
    let request = SbiRequest::post(SUBSCRIPTIONS_PATH)
        .with_json_body(&body)
        .map_err(|e| e.to_string())?;
    let resp = send(nrf_uri, request).await?;
    if resp.status != 201 {
        return Err(format!(
            "NFStatusSubscribe for {nf_type} answered {}",
            resp.status
        ));
    }
    parse_created(
        resp.http.content.as_deref(),
        resp.http.get_header("Location").map(String::as_str),
        now_epoch_secs(),
    )
    .ok_or_else(|| format!("NFStatusSubscribe for {nf_type}: 201 without a subscriptionId"))
}

/// Why a renewal did not succeed.
#[derive(Debug)]
enum RenewError {
    /// 404: the NRF does not hold the subscription (it restarted, or let it
    /// lapse). A fresh subscribe replaces it.
    Gone,
    Other(String),
}

/// Update (TS 29.510 §5.2.2.5.6): replace `validityTime` with now plus the
/// lifetime last granted.
async fn renew(nrf_uri: &str, sub: &NrfSubscription) -> Result<NrfSubscription, RenewError> {
    let now = now_epoch_secs();
    let lifetime = sub.lifetime().unwrap_or(MIN_RENEW_LEAD_SECS);
    let wanted = epoch_to_rfc3339(now + lifetime);
    let patch = json!([{ "op": "replace", "path": "/validityTime", "value": wanted }]);
    let request = SbiRequest::patch(format!("{SUBSCRIPTIONS_PATH}/{}", sub.id))
        .with_body(patch.to_string(), "application/json-patch+json");
    let resp = send(nrf_uri, request).await.map_err(RenewError::Other)?;
    match resp.status {
        200 => {
            let doc: Option<Value> = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str(b).ok());
            Ok(NrfSubscription {
                id: sub.id.clone(),
                granted_at: now,
                // The NRF answers with the validity it will enforce; one that
                // echoes nothing has accepted what was asked for.
                expires_at: validity_of(doc.as_ref()).or(Some(now + lifetime)),
            })
        }
        // 204: accepted, nothing echoed (TS 29.510 permits it).
        204 => Ok(NrfSubscription {
            id: sub.id.clone(),
            granted_at: now,
            expires_at: Some(now + lifetime),
        }),
        404 => Err(RenewError::Gone),
        s => Err(RenewError::Other(format!("answered {s}"))),
    }
}

/// One maintenance step for `nf_type`: subscribe when there is no
/// subscription, renew when one is due, re-subscribe when the NRF has
/// forgotten it.
pub async fn maintain_one(
    nrf_uri: &str,
    amf_instance_id: &str,
    nf_type: &str,
    notify_uri: &str,
    current: Option<NrfSubscription>,
) -> (Option<NrfSubscription>, MaintainOutcome) {
    let Some(sub) = current else {
        return match subscribe(nrf_uri, amf_instance_id, nf_type, notify_uri).await {
            Ok(s) => (Some(s), MaintainOutcome::Subscribed),
            Err(e) => (None, MaintainOutcome::Failed(e)),
        };
    };
    if !sub.renew_due(now_epoch_secs()) {
        return (Some(sub), MaintainOutcome::Unchanged);
    }
    match renew(nrf_uri, &sub).await {
        Ok(s) => (Some(s), MaintainOutcome::Renewed),
        Err(RenewError::Gone) => {
            match subscribe(nrf_uri, amf_instance_id, nf_type, notify_uri).await {
                Ok(s) => (Some(s), MaintainOutcome::Resubscribed),
                Err(e) => (None, MaintainOutcome::Failed(e)),
            }
        }
        // Keep the subscription: it is still valid until `expires_at`, and the
        // next pass tries again. Past expiry it is dropped, so the pass after
        // subscribes afresh instead of renewing a dead id forever.
        Err(RenewError::Other(e)) => {
            let expired = sub.expires_at.is_some_and(|e| e <= now_epoch_secs());
            (
                if expired { None } else { Some(sub) },
                MaintainOutcome::Failed(e),
            )
        }
    }
}

/// One maintenance pass over every cached NF type, concurrently.
pub async fn maintain_all(
    subs: &mut NrfSubscriptions,
    nrf_uri: &str,
    amf_instance_id: &str,
    notify_uri: &str,
) -> HashMap<String, MaintainOutcome> {
    let mut set = tokio::task::JoinSet::new();
    for nf_type in CACHED_PEER_NF_TYPES {
        let current = subs.by_nf_type.get(nf_type).cloned();
        let (nrf, amf, uri) = (
            nrf_uri.to_string(),
            amf_instance_id.to_string(),
            notify_uri.to_string(),
        );
        set.spawn(async move {
            let (next, outcome) = maintain_one(&nrf, &amf, nf_type, &uri, current).await;
            (nf_type, next, outcome)
        });
    }
    let mut outcomes = HashMap::new();
    while let Some(joined) = set.join_next().await {
        let Ok((nf_type, next, outcome)) = joined else {
            continue;
        };
        match next {
            Some(s) => {
                subs.by_nf_type.insert(nf_type.to_string(), s);
            }
            None => {
                subs.by_nf_type.remove(nf_type);
            }
        }
        match &outcome {
            MaintainOutcome::Subscribed | MaintainOutcome::Resubscribed => {
                log::info!("Subscribed at the NRF to {nf_type} status changes")
            }
            MaintainOutcome::Renewed => {
                log::debug!("Renewed the NRF {nf_type} status subscription")
            }
            MaintainOutcome::Failed(e) => {
                log::warn!("NRF {nf_type} status subscription: {e} (retrying)")
            }
            MaintainOutcome::Unchanged => {}
        }
        outcomes.insert(nf_type.to_string(), outcome);
    }
    outcomes
}

/// NFStatusUnsubscribe (TS 29.510 §5.2.2.5.4) for every held subscription,
/// concurrently and each bounded by [`NRF_REQUEST_TIMEOUT`].
pub async fn unsubscribe_all(subs: &mut NrfSubscriptions, nrf_uri: &str) -> usize {
    let mut set = tokio::task::JoinSet::new();
    for (_, sub) in subs.by_nf_type.drain() {
        let nrf = nrf_uri.to_string();
        set.spawn(async move {
            let request = SbiRequest::delete(format!("{SUBSCRIPTIONS_PATH}/{}", sub.id));
            matches!(send(&nrf, request).await, Ok(r) if r.status == 204 || r.status == 404)
        });
    }
    let mut removed = 0;
    while let Some(joined) = set.join_next().await {
        if joined.unwrap_or(false) {
            removed += 1;
        }
    }
    removed
}

/// The process's subscriptions. Written only by the maintainer task and by
/// [`shutdown`]; tests build their own [`NrfSubscriptions`].
fn held() -> &'static tokio::sync::Mutex<NrfSubscriptions> {
    static HELD: std::sync::OnceLock<tokio::sync::Mutex<NrfSubscriptions>> =
        std::sync::OnceLock::new();
    HELD.get_or_init(|| tokio::sync::Mutex::new(NrfSubscriptions::default()))
}

/// Spawn the maintainer: subscribe now, then renew and retry every
/// [`MAINTAIN_INTERVAL`]. Does nothing without an NRF or an NF instance id.
pub fn spawn_maintainer(amf_instance_id: String) -> Option<tokio::task::JoinHandle<()>> {
    if amf_instance_id.is_empty() {
        return None;
    }
    Some(tokio::spawn(async move {
        let notify_uri = notification_uri();
        let mut tick = tokio::time::interval(MAINTAIN_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(nrf_uri) = global_context().get_nrf_uri().await else {
                continue;
            };
            let mut subs = held().lock().await;
            maintain_all(&mut subs, &nrf_uri, &amf_instance_id, &notify_uri).await;
        }
    }))
}

/// Unsubscribe at shutdown, bounded so a dead NRF cannot hold it open.
pub async fn shutdown() {
    let Some(nrf_uri) = global_context().get_nrf_uri().await else {
        return;
    };
    let work = async {
        let mut subs = held().lock().await;
        unsubscribe_all(&mut subs, &nrf_uri).await
    };
    match tokio::time::timeout(NRF_REQUEST_TIMEOUT + Duration::from_secs(1), work).await {
        Ok(n) if n > 0 => log::info!("Removed {n} NRF status subscription(s)"),
        Ok(_) => {}
        Err(_) => log::warn!("NRF status unsubscribe did not finish; the NRF lets them expire"),
    }
}

/// What a `NotificationData` asks of the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyAction {
    /// Drop this NF instance id from the discovery cache.
    Evict(String),
    /// Nothing: an event or a change the cache does not depend on.
    Ignore,
}

/// Why a `NotificationData` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// A mandatory attribute is absent.
    Missing(&'static str),
    /// A mandatory attribute is present but unusable.
    Incorrect(&'static str, String),
}

/// Decide what a `NotificationData` (TS 29.510 §6.1.6.2.17) asks for.
///
/// Reads `event`, `nfInstanceUri` and, for `NF_PROFILE_CHANGED`, the
/// attribute names in `profileChanges`. Never reads `nfProfile`.
pub fn classify_notification(body: &Value) -> Result<NotifyAction, NotifyError> {
    let event = body
        .get("event")
        .and_then(Value::as_str)
        .ok_or(NotifyError::Missing("event"))?;
    let uri = body
        .get("nfInstanceUri")
        .and_then(Value::as_str)
        .ok_or(NotifyError::Missing("nfInstanceUri"))?;
    // `{apiRoot}/nnrf-nfm/v1/nf-instances/{nfInstanceID}` (TS 29.510 §6.1.3.3.2).
    let id = uri
        .trim_end_matches('/')
        .rsplit_once("/nf-instances/")
        .map(|(_, id)| id)
        .filter(|id| !id.is_empty() && !id.contains('/'))
        .ok_or_else(|| NotifyError::Incorrect("nfInstanceUri", uri.to_string()))?
        .to_string();
    match event {
        "NF_DEREGISTERED" => Ok(NotifyAction::Evict(id)),
        "NF_PROFILE_CHANGED" => {
            // A change list names the attributes; one that touches only
            // attributes the cache does not use leaves the cached profile
            // right. Without a list (a complete replacement) it cannot be
            // known, so the profile goes.
            let changes = body.get("profileChanges").and_then(Value::as_array);
            let relevant = match changes {
                Some(list) if !list.is_empty() => list.iter().any(|c| {
                    c.get("path")
                        .and_then(Value::as_str)
                        .and_then(|p| p.trim_start_matches('/').split('/').next())
                        .is_none_or(|attr| MONITORED_ATTRIBUTES.contains(&attr))
                }),
                _ => true,
            };
            Ok(if relevant {
                NotifyAction::Evict(id)
            } else {
                NotifyAction::Ignore
            })
        }
        _ => Ok(NotifyAction::Ignore),
    }
}

/// Apply a notification to the process discovery cache. Returns whether an
/// instance was removed.
pub async fn apply_notification(action: &NotifyAction) -> bool {
    match action {
        NotifyAction::Evict(id) => {
            let removed = global_context().remove_nf_instance(id).await.is_some();
            if removed {
                log::info!("NRF notified a change of NF instance {id}; dropped it from the discovery cache");
            }
            removed
        }
        NotifyAction::Ignore => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subscription_names_the_type_events_and_attributes() {
        let b = subscription_body(
            "amf-1",
            "SMF",
            "http://10.0.0.1:7777/namf-callback/v1/nf-status-notify",
        );
        assert_eq!(b["subscrCond"], json!({ "nfType": "SMF" }));
        assert_eq!(
            b["reqNotifEvents"],
            json!(["NF_DEREGISTERED", "NF_PROFILE_CHANGED"])
        );
        assert_eq!(b["reqNfInstanceId"], "amf-1");
        assert_eq!(b["reqNfType"], "AMF");
        assert_eq!(
            b["nfStatusNotificationUri"],
            "http://10.0.0.1:7777/namf-callback/v1/nf-status-notify"
        );
        let monitored = b["notifCondition"]["monitoredAttributes"]
            .as_array()
            .unwrap();
        assert!(monitored.contains(&json!("nfServices")));
        assert!(!monitored.contains(&json!("load")));
        // The NRF chooses the validity; the AMF proposes none.
        assert!(b.get("validityTime").is_none());
    }

    #[test]
    fn every_cached_type_is_subscribed_and_nothing_else_is_cached() {
        for t in CACHED_PEER_NF_TYPES {
            assert!(
                crate::sbi_path::cached_peer_nf_type(t).is_some(),
                "{t} is not cached"
            );
        }
        for t in ["AMF", "UDR", "LMF", "NEF", "CHF", "BSF", "SCP", "NWDAF"] {
            assert!(
                crate::sbi_path::cached_peer_nf_type(t).is_none(),
                "{t} is cached but not subscribed to"
            );
        }
    }

    #[test]
    fn renewal_is_due_a_quarter_of_the_lifetime_before_expiry() {
        let sub = NrfSubscription {
            id: "s".into(),
            granted_at: 1_000,
            expires_at: Some(1_000 + 86_400),
        };
        assert!(!sub.renew_due(1_000));
        assert!(!sub.renew_due(1_000 + 64_799));
        assert!(sub.renew_due(1_000 + 64_800));
        assert!(sub.renew_due(1_000 + 90_000));
        // Short lifetimes still get the minimum lead.
        let short = NrfSubscription {
            id: "s".into(),
            granted_at: 0,
            expires_at: Some(100),
        };
        assert!(!short.renew_due(39));
        assert!(short.renew_due(40));
        let forever = NrfSubscription {
            id: "s".into(),
            granted_at: 0,
            expires_at: None,
        };
        assert!(!forever.renew_due(u64::MAX / 2));
    }

    #[test]
    fn the_created_answer_gives_id_and_validity() {
        let body =
            json!({ "subscriptionId": "abc", "validityTime": "2026-10-24T00:00:00Z" }).to_string();
        let s = parse_created(Some(&body), None, 5).unwrap();
        assert_eq!(s.id, "abc");
        assert_eq!(s.granted_at, 5);
        assert_eq!(s.expires_at, rfc3339_to_epoch("2026-10-24T00:00:00Z"));
        let s = parse_created(Some("{}"), Some("/nnrf-nfm/v1/subscriptions/xyz"), 5).unwrap();
        assert_eq!(s.id, "xyz");
        assert_eq!(s.expires_at, None);
        assert!(parse_created(Some("{}"), None, 5).is_none());
    }

    fn uri(id: &str) -> String {
        format!("http://nrf:7777/nnrf-nfm/v1/nf-instances/{id}")
    }

    #[test]
    fn deregistration_evicts_the_named_instance() {
        let b = json!({ "event": "NF_DEREGISTERED", "nfInstanceUri": uri("smf-1") });
        assert_eq!(
            classify_notification(&b),
            Ok(NotifyAction::Evict("smf-1".into()))
        );
    }

    #[test]
    fn a_load_only_change_keeps_the_profile() {
        let b = json!({
            "event": "NF_PROFILE_CHANGED", "nfInstanceUri": uri("smf-1"),
            "profileChanges": [{ "op": "replace", "path": "/load", "newValue": 40 }]
        });
        assert_eq!(classify_notification(&b), Ok(NotifyAction::Ignore));
    }

    #[test]
    fn an_endpoint_or_status_change_evicts() {
        for path in [
            "/nfServices/0/ipEndPoints/0/port",
            "/nfStatus",
            "/ipv4Addresses/0",
        ] {
            let b = json!({
                "event": "NF_PROFILE_CHANGED", "nfInstanceUri": uri("smf-1"),
                "profileChanges": [
                    { "op": "replace", "path": "/load" },
                    { "op": "replace", "path": path }
                ]
            });
            assert_eq!(
                classify_notification(&b),
                Ok(NotifyAction::Evict("smf-1".into())),
                "{path}"
            );
        }
        // A complete replacement (a profile, no change list) evicts too.
        let b = json!({
            "event": "NF_PROFILE_CHANGED", "nfInstanceUri": uri("smf-1"),
            "nfProfile": { "nfInstanceId": "smf-1" }
        });
        assert_eq!(
            classify_notification(&b),
            Ok(NotifyAction::Evict("smf-1".into()))
        );
    }

    #[test]
    fn a_registration_is_ignored() {
        let b = json!({ "event": "NF_REGISTERED", "nfInstanceUri": uri("smf-2") });
        assert_eq!(classify_notification(&b), Ok(NotifyAction::Ignore));
    }

    #[test]
    fn missing_or_unusable_members_are_refused() {
        assert_eq!(
            classify_notification(&json!({ "nfInstanceUri": uri("x") })),
            Err(NotifyError::Missing("event"))
        );
        assert_eq!(
            classify_notification(&json!({ "event": "NF_DEREGISTERED" })),
            Err(NotifyError::Missing("nfInstanceUri"))
        );
        for bad in [
            "http://nrf:7777",
            "http://nrf:7777/nnrf-nfm/v1/nf-instances/",
            "http://nrf:7777/nnrf-nfm/v1/nf-instances/a/b",
        ] {
            assert!(
                matches!(
                    classify_notification(
                        &json!({ "event": "NF_DEREGISTERED", "nfInstanceUri": bad })
                    ),
                    Err(NotifyError::Incorrect("nfInstanceUri", _))
                ),
                "{bad}"
            );
        }
    }

    fn cached(id: &str, port: u16) -> nextgcore_sbi::context::NfInstance {
        use nextgcore_sbi::context::{NfInstance, NfService};
        use nextgcore_sbi::types::{NfType, SbiServiceType};
        let mut i = NfInstance::new(id, NfType::Smf);
        let mut svc = NfService::new("nsmf-pdusession", SbiServiceType::NsmfPdusession);
        svc.ip_addresses = vec!["127.0.0.1".into()];
        svc.port = port;
        i.add_service(svc);
        i
    }

    fn notify(body: Value) -> SbiRequest {
        SbiRequest::post(NOTIFY_PATH).with_body(body.to_string(), "application/json")
    }

    /// Through the router: a deregistration drops exactly the named
    /// instance, and the endpoint in the body's `nfProfile` is not taken.
    #[tokio::test]
    async fn the_callback_evicts_the_named_instance_and_takes_nothing_from_the_body() {
        let _cache = crate::sbi_path::nf_cache_test_lock().lock().await;
        let ctx = global_context();
        ctx.add_nf_instance(cached("smf-668-gone", 40001)).await;
        ctx.add_nf_instance(cached("smf-668-kept", 40002)).await;

        let resp = crate::namf_server::namf_request_handler(notify(json!({
            "event": "NF_DEREGISTERED",
            "nfInstanceUri": uri("smf-668-gone"),
            "nfProfile": {
                "nfInstanceId": "smf-668-planted", "nfType": "SMF", "nfStatus": "REGISTERED",
                "nfServices": [{ "serviceInstanceId": "1", "serviceName": "nsmf-pdusession",
                    "ipEndPoints": [{ "ipv4Address": "192.0.2.66", "port": 6668 }] }]
            }
        })))
        .await;
        assert_eq!(resp.status, 204);
        assert!(ctx.get_nf_instance("smf-668-gone").await.is_none());
        assert!(ctx.get_nf_instance("smf-668-kept").await.is_some());
        assert!(ctx.get_nf_instance("smf-668-planted").await.is_none());
        let planted = ctx
            .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NsmfPdusession)
            .await
            .into_iter()
            .filter_map(|i| i.endpoint_for(nextgcore_sbi::types::SbiServiceType::NsmfPdusession))
            .any(|(h, _)| h == "192.0.2.66");
        assert!(!planted, "an endpoint was taken from the notification body");

        // A load-only change leaves the remaining profile cached.
        let resp = crate::namf_server::namf_request_handler(notify(json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": uri("smf-668-kept"),
            "profileChanges": [{ "op": "replace", "path": "/load", "newValue": 70 }]
        })))
        .await;
        assert_eq!(resp.status, 204);
        assert!(ctx.get_nf_instance("smf-668-kept").await.is_some());

        // A moved service endpoint drops it.
        let resp = crate::namf_server::namf_request_handler(notify(json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": uri("smf-668-kept"),
            "profileChanges": [{ "op": "replace", "path": "/nfServices/0/ipEndPoints/0/port", "newValue": 9 }]
        })))
        .await;
        assert_eq!(resp.status, 204);
        assert!(ctx.get_nf_instance("smf-668-kept").await.is_none());
    }

    #[tokio::test]
    async fn the_callback_refuses_a_body_without_its_mandatory_members() {
        let resp =
            crate::namf_server::namf_request_handler(notify(json!({ "nfInstanceUri": uri("x") })))
                .await;
        assert_eq!(resp.status, 400);
        let resp =
            crate::namf_server::namf_request_handler(notify(json!({ "event": "NF_DEREGISTERED" })))
                .await;
        assert_eq!(resp.status, 400);
        let resp = crate::namf_server::namf_request_handler(
            SbiRequest::post(NOTIFY_PATH).with_body("not json", "application/json"),
        )
        .await;
        assert_eq!(resp.status, 400);
    }
}
