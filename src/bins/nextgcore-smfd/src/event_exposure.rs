//! `Nsmf_EventExposure` (TS 29.508), issue #79.
//!
//! # What this replaces
//!
//! A facade. `POST /nsmf-event-exposure/v1/subscriptions` ignored the request body,
//! returned `{"subscriptionId": <uuid>}` — which is not a schema in TS 29.508 —
//! persisted nothing, and never notified; `DELETE` answered `204` for any id
//! including one that never existed; there was no `GET` or `PUT` at all. So a
//! consumer (NEF/AF, NWDAF, CHF) received an id that referenced nothing and then
//! waited for notifications that could not arrive.
//!
//! # The resource model
//!
//! TS 29.508 §4.2.2: an event subscription is a **persisted resource**. `POST
//! /subscriptions` creates it and answers `201` + `Location` + the created
//! `NsmfEventExposure` document; `/subscriptions/{subId}` supports `GET` (200),
//! `PUT` (200) and `DELETE` (204), each `404` for an unknown id.
//!
//! # Notification
//!
//! §4.2.3.2: on a matching occurrence the SMF sends an
//! `NsmfEventExposureNotification` to `notifUri`, carrying the subscription's own
//! `notifId` so the consumer can correlate it with the subscription it made.
//!
//! Which events are emitted, and why only these two: `PDU_SES_EST` and
//! `PDU_SES_REL` are the two occurrences the live establishment and release paths
//! actually reach. The other twenty values in `SmfEvent` name occurrences this SMF
//! does not detect (`UP_PATH_CH`, `QOS_MON`, `DISPERSION`, …); subscribing to one
//! is accepted and stored — refusing it would reject a conformant request — and it
//! simply never fires. That is stated here rather than left for a consumer to infer
//! from silence.

use std::collections::HashMap;
use std::sync::RwLock;

use serde_json::Value;

/// The `SmfEvent` values this SMF actually detects and reports (TS 29.508).
///
/// Named constants rather than string literals at the call sites: a typo in one
/// place would produce a subscription that matches and a notification that does
/// not, and the two are twenty lines apart in different files.
pub mod event {
    /// PDU session establishment.
    pub const PDU_SES_EST: &str = "PDU_SES_EST";
    /// PDU session release.
    pub const PDU_SES_REL: &str = "PDU_SES_REL";
}

/// A stored subscription: the parsed document plus the id this SMF assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSubscription {
    /// The SMF-assigned resource id (the `{subId}` path segment).
    pub id: String,
    /// Consumer-assigned notification correlation id (`notifId`, **required**).
    pub notif_id: String,
    /// Where notifications go (`notifUri`, **required**).
    pub notif_uri: String,
    /// The subscribed event names, from `eventSubs[].event` (**required**, minItems 1).
    pub events: Vec<String>,
    /// SUPI filter, when the subscription is scoped to one UE.
    pub supi: Option<String>,
    /// PDU session id filter, when scoped to one session.
    pub pdu_session_id: Option<u8>,
    /// The document as received, so `GET` returns what was stored rather than a
    /// re-serialisation of the subset this SMF models. A consumer that sent
    /// `sampRatio` or `partitionCriteria` gets them back.
    pub document: Value,
}

impl EventSubscription {
    /// Does an occurrence of `event` for `supi`/`psi` match this subscription?
    ///
    /// An absent filter matches anything — `anyUeInd` semantics — while a present
    /// one must match exactly. Getting this backwards would notify every consumer
    /// about every UE, which is a subscriber-data leak rather than a bug in
    /// reporting.
    pub fn matches(&self, event: &str, supi: &str, psi: u8) -> bool {
        if !self.events.iter().any(|e| e == event) {
            return false;
        }
        if let Some(ref want) = self.supi {
            if want != supi {
                return false;
            }
        }
        if let Some(want) = self.pdu_session_id {
            if want != psi {
                return false;
            }
        }
        true
    }
}

/// The subscription store.
///
/// Process-global and memory-only, like the other subscription stores in this tree.
/// A restart loses the subscriptions, which is the honest behaviour for a resource
/// whose consumer holds a `Location` it will re-create on a `404` — the alternative
/// (persisting them) would have the SMF notifying against `notifUri`s that may have
/// moved while it was down.
static SUBSCRIPTIONS: RwLock<Option<HashMap<String, EventSubscription>>> = RwLock::new(None);

fn with_store<T>(f: impl FnOnce(&mut HashMap<String, EventSubscription>) -> T) -> Option<T> {
    let mut guard = SUBSCRIPTIONS.write().ok()?;
    Some(f(guard.get_or_insert_with(HashMap::new)))
}

/// Why a subscription document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A `required` member is absent. Carries its name for the ProblemDetails.
    Missing(&'static str),
    /// `eventSubs` is present but no entry names an event.
    NoEvent,
    /// The body was not a JSON object.
    NotAnObject,
}

impl ParseError {
    pub fn detail(&self) -> String {
        match self {
            Self::Missing(m) => format!("Mandatory attribute '{m}' is missing"),
            Self::NoEvent => {
                "eventSubs is present but no entry names an 'event' (TS 29.508 EventSubscription \
                 requires it)"
                    .to_string()
            }
            Self::NotAnObject => "Request body is not an NsmfEventExposure object".to_string(),
        }
    }

    pub fn cause(&self) -> &'static str {
        match self {
            Self::Missing(_) | Self::NoEvent => "MANDATORY_IE_MISSING",
            Self::NotAnObject => "INVALID_MSG_FORMAT",
        }
    }
}

/// Parse an `NsmfEventExposure` document.
///
/// Enforces the three `required` members TS 29.508 declares — `notifId`, `notifUri`
/// and `eventSubs` — and nothing else. `eventSubs` items require `event`, so an
/// `eventSubs` naming none is refused too: it would create a subscription that can
/// never fire, which is the shape of resource this repo has decided repeatedly not
/// to accept.
///
/// `id` is assigned by the caller, so the same parse serves `POST` and `PUT`.
pub fn parse_subscription(body: &Value, id: String) -> Result<EventSubscription, ParseError> {
    let obj = body.as_object().ok_or(ParseError::NotAnObject)?;
    let notif_id = obj
        .get("notifId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::Missing("notifId"))?
        .to_string();
    let notif_uri = obj
        .get("notifUri")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::Missing("notifUri"))?
        .to_string();
    let event_subs = obj
        .get("eventSubs")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(ParseError::Missing("eventSubs"))?;
    let events: Vec<String> = event_subs
        .iter()
        .filter_map(|e| e.get("event").and_then(Value::as_str).map(str::to_string))
        .collect();
    if events.is_empty() {
        return Err(ParseError::NoEvent);
    }

    Ok(EventSubscription {
        id,
        notif_id,
        notif_uri,
        events,
        supi: obj.get("supi").and_then(Value::as_str).map(str::to_string),
        pdu_session_id: obj
            .get("pduSeId")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok()),
        document: body.clone(),
    })
}

/// Store a subscription under its id, returning the document to echo.
///
/// The echoed document is the stored one with `subId` and `self` filled in, which
/// is what makes the `201` body an `NsmfEventExposure` rather than the bare
/// `{"subscriptionId": ...}` the facade returned.
pub fn insert(sub: EventSubscription) -> Value {
    let mut document = sub.document.clone();
    if let Some(obj) = document.as_object_mut() {
        obj.insert("subId".to_string(), Value::String(sub.id.clone()));
        obj.insert("self".to_string(), Value::String(resource_path(&sub.id)));
    }
    let id = sub.id.clone();
    with_store(|store| store.insert(id, sub));
    document
}

/// Replace an existing subscription. `false` when the id is unknown — a `PUT` to a
/// resource that does not exist must not create one at a consumer-chosen id.
pub fn replace(id: &str, sub: EventSubscription) -> bool {
    with_store(|store| {
        if !store.contains_key(id) {
            return false;
        }
        store.insert(id.to_string(), sub);
        true
    })
    .unwrap_or(false)
}

pub fn find(id: &str) -> Option<EventSubscription> {
    SUBSCRIPTIONS.read().ok()?.as_ref()?.get(id).cloned()
}

pub fn remove(id: &str) -> Option<EventSubscription> {
    with_store(|store| store.remove(id)).flatten()
}

pub fn count() -> usize {
    SUBSCRIPTIONS
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(HashMap::len))
        .unwrap_or(0)
}

/// The ONE agreement about [`SUBSCRIPTIONS`], for tests.
///
/// It lives here, beside the store it protects, so `main.rs`'s router tests and this
/// module's own tests take the SAME lock. They must: `clear_for_test` empties the
/// store for the whole process, so a sibling clearing it between another test's
/// POST and the release that should notify makes the notification simply not
/// happen — which is how `a_released_session_notifies_its_event_subscriber` failed
/// on its first full-suite run while passing alone.
///
/// A `std::sync::Mutex` even though the async holders keep it across awaits (they
/// carry `#[allow(clippy::await_holding_lock)]`): every holder is a test in this
/// crate, none blocks on another, and a second `tokio` lock for the async half
/// would recreate the split this comment exists to prevent.
#[cfg(test)]
pub static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`STORE_LOCK`], recovering a poisoned guard so one failure does not cascade.
#[cfg(test)]
pub fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Test-only: empty the store so tests do not inherit each other's subscriptions.
#[cfg(test)]
pub fn clear_for_test() {
    with_store(|store| store.clear());
}

/// The canonical resource path for a subscription id.
pub fn resource_path(id: &str) -> String {
    format!("/nsmf-event-exposure/v1/subscriptions/{id}")
}

/// Every subscription that matches an occurrence.
fn matching(event: &str, supi: &str, psi: u8) -> Vec<EventSubscription> {
    SUBSCRIPTIONS
        .read()
        .ok()
        .and_then(|g| {
            g.as_ref().map(|store| {
                store
                    .values()
                    .filter(|s| s.matches(event, supi, psi))
                    .cloned()
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default()
}

/// Build the `NsmfEventExposureNotification` for one occurrence.
///
/// Both members TS 29.508 declares `required` are present: `notifId` (the
/// subscription's, not the SMF's — it is the consumer's correlator) and
/// `eventNotifs`, which is `minItems: 1` and therefore always carries exactly the
/// one occurrence being reported.
pub fn build_notification(sub: &EventSubscription, event: &str, supi: &str, psi: u8) -> Value {
    serde_json::json!({
        "notifId": sub.notif_id,
        "eventNotifs": [{
            "event": event,
            "timeStamp": nextgcore_sbi::datetime::epoch_to_rfc3339(
                nextgcore_sbi::datetime::now_epoch_secs(),
            ),
            "supi": supi,
            "pduSeId": psi,
        }],
    })
}

/// Emit `Nsmf_EventExposure_Notify` to every subscription matching an occurrence
/// (TS 29.508 §4.2.3.2).
///
/// Failures are logged and swallowed: an event is a report about something that
/// already happened, so a consumer being unreachable must not fail the procedure
/// that generated it. There is no retry queue, which is stated rather than implied.
pub async fn notify(event: &str, supi: &str, psi: u8) {
    let subs = matching(event, supi, psi);
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        let body = build_notification(&sub, event, supi, psi);
        let Some((host, port)) = crate::policy::split_host_port(&sub.notif_uri) else {
            log::warn!(
                "subscription {} has an unusable notifUri '{}': the {event} \
                 notification for {supi} cannot be delivered",
                sub.id,
                sub.notif_uri
            );
            continue;
        };
        let path = notify_path(&sub.notif_uri);
        let request = nextgcore_sbi::message::SbiRequest::post(path).with_body(
            body.to_string(),
            nextgcore_sbi::constants::content_type::APPLICATION_JSON,
        );
        let client = nextgcore_sbi::client::SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&host, port)
                .with_connect_timeout(std::time::Duration::from_secs(2))
                .with_request_timeout(std::time::Duration::from_secs(3)),
        );
        match client.send_request(request).await {
            Ok(resp) => log::info!(
                "Nsmf_EventExposure_Notify {event} (SUPI {supi}, PSI {psi}) → \
                 subscription {}: status={}",
                sub.id,
                resp.status
            ),
            Err(e) => log::warn!(
                "Nsmf_EventExposure_Notify {event} to subscription {} failed: {e}",
                sub.id
            ),
        }
    }
}

/// The path component of a `notifUri`, defaulting to `/` when it names only an
/// authority.
///
/// Split out because the consumer chooses this URI and a bare `http://host:port`
/// is a legal `Uri` — POSTing to an empty path would produce a malformed request
/// line rather than a failed delivery, which is much harder to diagnose.
fn notify_path(uri: &str) -> String {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    match without_scheme.find('/') {
        Some(at) => without_scheme[at..].to_string(),
        None => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Value {
        serde_json::json!({
            "notifId": "corr-1",
            "notifUri": "http://127.0.0.1:9/nsmf-events",
            "eventSubs": [{ "event": event::PDU_SES_REL }, { "event": event::PDU_SES_EST }],
            "supi": "imsi-001010000000079",
            "pduSeId": 5,
            // A member this SMF does not model, to prove the document round-trips.
            "sampRatio": 50,
        })
    }

    #[test]
    fn the_three_required_members_are_enforced_and_nothing_else_is() {
        let sub = parse_subscription(&document(), "sub-1".into()).expect("parses");
        assert_eq!(sub.notif_id, "corr-1");
        assert_eq!(sub.events, vec!["PDU_SES_REL", "PDU_SES_EST"]);
        assert_eq!(sub.supi.as_deref(), Some("imsi-001010000000079"));
        assert_eq!(sub.pdu_session_id, Some(5));

        for missing in ["notifId", "notifUri", "eventSubs"] {
            let mut doc = document();
            doc.as_object_mut().expect("obj").remove(missing);
            assert_eq!(
                parse_subscription(&doc, "x".into()),
                Err(ParseError::Missing(missing)),
                "{missing} is required by TS 29.508"
            );
        }

        // An eventSubs entry with no `event` cannot ever match, so the subscription
        // is refused rather than stored inert.
        let mut doc = document();
        doc["eventSubs"] = serde_json::json!([{ "referenceId": 7 }]);
        assert_eq!(
            parse_subscription(&doc, "x".into()),
            Err(ParseError::NoEvent)
        );

        // An empty eventSubs violates minItems: 1.
        let mut doc = document();
        doc["eventSubs"] = serde_json::json!([]);
        assert_eq!(
            parse_subscription(&doc, "x".into()),
            Err(ParseError::Missing("eventSubs"))
        );

        assert_eq!(
            parse_subscription(&serde_json::json!("not an object"), "x".into()),
            Err(ParseError::NotAnObject)
        );
    }

    /// An absent filter matches anything; a present one must match exactly.
    ///
    /// The negative direction is the one that matters: a subscription scoped to one
    /// SUPI that matched every UE would leak one subscriber's session events to a
    /// consumer authorised for another.
    #[test]
    fn filters_scope_a_subscription_and_an_absent_filter_matches_anything() {
        let scoped = parse_subscription(&document(), "s".into()).expect("parses");
        assert!(scoped.matches("PDU_SES_REL", "imsi-001010000000079", 5));
        assert!(
            !scoped.matches("PDU_SES_REL", "imsi-999990000000000", 5),
            "a SUPI-scoped subscription must not match another subscriber"
        );
        assert!(
            !scoped.matches("PDU_SES_REL", "imsi-001010000000079", 6),
            "a session-scoped subscription must not match another session"
        );
        assert!(
            !scoped.matches("UP_PATH_CH", "imsi-001010000000079", 5),
            "an event this subscription did not name must not match"
        );

        let mut doc = document();
        doc.as_object_mut().expect("obj").remove("supi");
        doc.as_object_mut().expect("obj").remove("pduSeId");
        let any = parse_subscription(&doc, "s".into()).expect("parses");
        assert!(any.matches("PDU_SES_REL", "imsi-whoever", 99));
    }

    #[test]
    fn the_stored_document_is_echoed_with_sub_id_and_self() {
        let _g = lock_store();
        clear_for_test();
        let sub = parse_subscription(&document(), "sub-echo".into()).expect("parses");
        let echoed = insert(sub);
        assert_eq!(echoed["subId"], serde_json::json!("sub-echo"));
        assert_eq!(
            echoed["self"],
            serde_json::json!("/nsmf-event-exposure/v1/subscriptions/sub-echo")
        );
        // Required members survive, and so does one this SMF does not model.
        assert_eq!(echoed["notifId"], serde_json::json!("corr-1"));
        assert_eq!(
            echoed["eventSubs"][0]["event"],
            serde_json::json!("PDU_SES_REL")
        );
        assert_eq!(
            echoed["sampRatio"],
            serde_json::json!(50),
            "a member the SMF does not model must round-trip, not be dropped"
        );

        assert!(find("sub-echo").is_some());
        assert!(remove("sub-echo").is_some());
        assert!(find("sub-echo").is_none());
        assert!(
            remove("sub-echo").is_none(),
            "removal is not idempotent-silent"
        );
    }

    #[test]
    fn a_put_to_an_unknown_id_does_not_create_one() {
        let _g = lock_store();
        clear_for_test();
        let sub = parse_subscription(&document(), "never-created".into()).expect("parses");
        assert!(!replace("never-created", sub));
        assert!(
            find("never-created").is_none(),
            "a PUT must not create a resource at a consumer-chosen id"
        );
    }

    #[test]
    fn the_notification_carries_both_required_members() {
        let sub = parse_subscription(&document(), "s".into()).expect("parses");
        let notif = build_notification(&sub, "PDU_SES_REL", "imsi-001010000000079", 5);
        assert_eq!(
            notif["notifId"],
            serde_json::json!("corr-1"),
            "notifId is the CONSUMER's correlator, not an SMF-side id"
        );
        let notifs = notif["eventNotifs"]
            .as_array()
            .expect("eventNotifs required");
        assert_eq!(notifs.len(), 1, "minItems: 1");
        assert_eq!(notifs[0]["event"], serde_json::json!("PDU_SES_REL"));
        assert_eq!(notifs[0]["pduSeId"], serde_json::json!(5));
        assert!(
            notifs[0]["timeStamp"]
                .as_str()
                .is_some_and(|t| t.contains('T')),
            "the timestamp must be an RFC 3339 DateTime, got {}",
            notifs[0]["timeStamp"]
        );
    }

    #[test]
    fn a_notif_uri_naming_only_an_authority_still_yields_a_usable_path() {
        assert_eq!(
            notify_path("http://127.0.0.1:8080/callbacks/smf"),
            "/callbacks/smf"
        );
        assert_eq!(notify_path("https://nef.example.com/x"), "/x");
        assert_eq!(
            notify_path("http://127.0.0.1:8080"),
            "/",
            "a bare authority is a legal Uri, and POSTing to an empty path would be \
             malformed rather than merely undelivered"
        );
    }
}
