//! MBS subscription management: StatusSubscribe / ContextStatusSubscribe / Notify
//! (TS 29.532 §5.3.2.6–11, §6.2.6.2.14). [mbsmfd-05]
//!
//! Two subscription families share this module:
//!   - **Status** subscriptions (NEF/MBSF/AF-facing): resource path
//!     `/mbs-sessions/subscriptions`.
//!   - **ContextStatus** subscriptions (SMF-facing): resource path
//!     `/mbs-sessions/contexts/subscriptions`.
//!
//! Both carry the same `SubEntry` shape (notifyUri, notifyCorrelationId,
//! optional eventList, optional nfInstanceId). The MB-SMF fires an outbound
//! POST to `notifyUri` on subscribed events (session release, QoS change …).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event types (TS 29.532 §6.2.6.2.14)
// ---------------------------------------------------------------------------

/// MBS event type for subscription filtering / notification bodies.
///
/// The spec lists six event types in §6.2.6.2.14; `#[serde(other)]` absorbs
/// future additions without rejecting the subscription.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MbsEvent {
    #[serde(rename = "QOS_INFO")]
    QosInfo,
    #[serde(rename = "STATUS_INFO")]
    StatusInfo,
    #[serde(rename = "SERVICE_AREA_INFO")]
    ServiceAreaInfo,
    #[serde(rename = "SECURITY_INFO")]
    SecurityInfo,
    #[serde(rename = "SESSION_RELEASE")]
    SessionRelease,
    #[serde(rename = "MULT_TRANS_ADD_CHANGE")]
    MultTransAddChange,
}

// ---------------------------------------------------------------------------
// Subscribe request / response bodies
// ---------------------------------------------------------------------------

/// Body for POST to `/mbs-sessions/subscriptions` (TS 29.532 §5.3.2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusSubscribeReqData {
    pub notify_uri: String,
    pub notify_correlation_id: String,
    /// Absent means subscribe to all events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_list: Option<Vec<MbsEvent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nf_instance_id: Option<String>,
}

/// Body for POST to `/mbs-sessions/contexts/subscriptions` (TS 29.532 §5.3.2.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusSubscribeReqData {
    pub notify_uri: String,
    pub notify_correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_list: Option<Vec<MbsEvent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nf_instance_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Notify callback bodies (POSTed to notifyUri)
// ---------------------------------------------------------------------------

/// Body POSTed to the subscriber's notifyUri for a Status event
/// (TS 29.532 §5.3.2.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusNotifyReqData {
    pub notify_correlation_id: String,
    pub mbs_event: MbsEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail: Option<serde_json::Value>,
}

/// Body POSTed to the subscriber's notifyUri for a ContextStatus event
/// (TS 29.532 §5.3.2.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusNotifyReqData {
    pub notify_correlation_id: String,
    pub mbs_event: MbsEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_detail: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// In-memory subscription store
// ---------------------------------------------------------------------------

/// A single subscription document held in the store.
#[derive(Debug, Clone)]
pub struct SubEntry {
    pub notify_uri: String,
    pub notify_correlation_id: String,
    /// `None` means "all events".
    pub event_list: Option<Vec<MbsEvent>>,
    pub nf_instance_id: Option<String>,
}

impl SubEntry {
    /// Returns true when this subscription should receive `event`.
    pub fn matches(&self, event: &MbsEvent) -> bool {
        match &self.event_list {
            None => true,
            Some(list) => list.contains(event),
        }
    }
}

/// In-memory subscription store keyed by UUID subscription ID.
///
/// Wrapping in a [`std::sync::Mutex`] at the [`crate::context::MbSmfContext`]
/// level gives interior mutability consistent with the `TmgiPool` pattern.
#[derive(Debug, Default)]
pub struct SubscriptionStore {
    entries: HashMap<String, SubEntry>,
}

impl SubscriptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new subscription; returns the generated subscription ID.
    pub fn add(&mut self, entry: SubEntry) -> String {
        let id = Uuid::new_v4().to_string();
        self.entries.insert(id.clone(), entry);
        id
    }

    /// Replace an existing subscription (PUT). Returns false if not found.
    pub fn update(&mut self, id: &str, entry: SubEntry) -> bool {
        if self.entries.contains_key(id) {
            self.entries.insert(id.to_string(), entry);
            true
        } else {
            false
        }
    }

    /// Remove a subscription (DELETE). Returns false if not found.
    pub fn remove(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Retrieve a subscription by ID (for response echo in PUT).
    pub fn get(&self, id: &str) -> Option<&SubEntry> {
        self.entries.get(id)
    }

    /// Collect all entries that match `event` (for fanning out notifications).
    pub fn matching(&self, event: &MbsEvent) -> Vec<SubEntry> {
        self.entries
            .values()
            .filter(|e| e.matches(event))
            .cloned()
            .collect()
    }

    /// Number of active subscriptions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Outbound notification (fire-and-forget)
// ---------------------------------------------------------------------------

/// POST a serializable `body` to `notify_uri` via the shared SBI client pool.
///
/// Failures are logged as warnings; the caller must not depend on delivery
/// confirmation (spec allows best-effort for outbound notify). [mbsmfd-05]
pub async fn send_notify_post(notify_uri: &str, body: &impl Serialize) {
    let body_val = match serde_json::to_value(body) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("[sub] serialize notification failed: {e}");
            return;
        }
    };

    let (host, port) = match crate::parse_host_port(notify_uri) {
        Some(hp) => hp,
        None => {
            log::warn!("[sub] invalid notifyUri (cannot parse host:port): {notify_uri}");
            return;
        }
    };

    let path = extract_path(notify_uri);
    let sbi_ctx = nextgcore_sbi::context::global_context();
    let client = sbi_ctx.get_client(&host, port).await;

    match client.post_json(&path, &body_val).await {
        Ok(rsp) if rsp.status / 100 == 2 => {
            log::debug!("[sub] notification delivered to {notify_uri} ({})", rsp.status);
        }
        Ok(rsp) => {
            log::warn!("[sub] notification to {notify_uri} returned {}", rsp.status);
        }
        Err(e) => {
            log::warn!("[sub] notification to {notify_uri} failed: {e}");
        }
    }
}

/// Extract the path (and query) from a URI, defaulting to `/`.
fn extract_path(uri: &str) -> String {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let start = without_scheme.find('/').unwrap_or(without_scheme.len());
    let path = &without_scheme[start..];
    if path.is_empty() { "/" } else { path }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- MbsEvent serde ----

    #[test]
    fn test_mbs_event_roundtrip() {
        for (ev, name) in [
            (MbsEvent::QosInfo, "QOS_INFO"),
            (MbsEvent::StatusInfo, "STATUS_INFO"),
            (MbsEvent::ServiceAreaInfo, "SERVICE_AREA_INFO"),
            (MbsEvent::SecurityInfo, "SECURITY_INFO"),
            (MbsEvent::SessionRelease, "SESSION_RELEASE"),
            (MbsEvent::MultTransAddChange, "MULT_TRANS_ADD_CHANGE"),
        ] {
            let json = serde_json::to_string(&ev).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            let back: MbsEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ev);
        }
    }

    // ---- StatusSubscribeReqData serde ----

    #[test]
    fn test_status_subscribe_req_roundtrip() {
        let json = r#"{
            "notifyUri":"http://smf:8080/notify",
            "notifyCorrelationId":"corr-001",
            "eventList":["SESSION_RELEASE","QOS_INFO"]
        }"#;
        let req: StatusSubscribeReqData = serde_json::from_str(json).unwrap();
        assert_eq!(req.notify_uri, "http://smf:8080/notify");
        assert_eq!(req.notify_correlation_id, "corr-001");
        assert_eq!(
            req.event_list.as_deref(),
            Some([MbsEvent::SessionRelease, MbsEvent::QosInfo].as_slice())
        );
        // Round-trip.
        let back: StatusSubscribeReqData =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.notify_uri, "http://smf:8080/notify");
    }

    #[test]
    fn test_status_subscribe_req_no_event_list() {
        let json = r#"{"notifyUri":"http://nef/cb","notifyCorrelationId":"x"}"#;
        let req: StatusSubscribeReqData = serde_json::from_str(json).unwrap();
        assert!(req.event_list.is_none());
    }

    // ---- ContextStatusSubscribeReqData serde ----

    #[test]
    fn test_context_status_subscribe_req_roundtrip() {
        let req = ContextStatusSubscribeReqData {
            notify_uri: "http://smf:9000/ctx-notify".to_string(),
            notify_correlation_id: "ctx-corr-002".to_string(),
            event_list: Some(vec![MbsEvent::MultTransAddChange]),
            nf_instance_id: Some("smf-inst-1".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"notifyUri\""));
        assert!(json.contains("\"MULT_TRANS_ADD_CHANGE\""));
        let back: ContextStatusSubscribeReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.notify_correlation_id, "ctx-corr-002");
    }

    // ---- StatusNotifyReqData serde ----

    #[test]
    fn test_status_notify_req_roundtrip() {
        let n = StatusNotifyReqData {
            notify_correlation_id: "corr-001".to_string(),
            mbs_event: MbsEvent::SessionRelease,
            event_detail: Some(serde_json::json!({"reason":"ADMIN"})),
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"SESSION_RELEASE\""));
        assert!(json.contains("\"notifyCorrelationId\":\"corr-001\""));
        let back: StatusNotifyReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mbs_event, MbsEvent::SessionRelease);
    }

    // ---- ContextStatusNotifyReqData serde ----

    #[test]
    fn test_context_status_notify_req_roundtrip() {
        let n = ContextStatusNotifyReqData {
            notify_correlation_id: "ctx-002".to_string(),
            mbs_event: MbsEvent::QosInfo,
            event_detail: None,
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"QOS_INFO\""));
        assert!(!json.contains("eventDetail"), "absent optional omitted");
        let back: ContextStatusNotifyReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mbs_event, MbsEvent::QosInfo);
    }

    // ---- SubscriptionStore CRUD ----

    fn entry(uri: &str, corr: &str) -> SubEntry {
        SubEntry {
            notify_uri: uri.to_string(),
            notify_correlation_id: corr.to_string(),
            event_list: None,
            nf_instance_id: None,
        }
    }

    #[test]
    fn test_store_add_remove() {
        let mut store = SubscriptionStore::new();
        let id = store.add(entry("http://a/cb", "c1"));
        assert_eq!(store.len(), 1);
        assert!(store.get(&id).is_some());

        assert!(store.remove(&id));
        assert_eq!(store.len(), 0);
        // Removing a non-existent id returns false.
        assert!(!store.remove(&id));
    }

    #[test]
    fn test_store_update() {
        let mut store = SubscriptionStore::new();
        let id = store.add(entry("http://a/cb", "c1"));

        // Update replaces the entry.
        let updated = store.update(&id, entry("http://b/cb", "c2"));
        assert!(updated);
        assert_eq!(store.get(&id).unwrap().notify_correlation_id, "c2");

        // Update on unknown id returns false.
        assert!(!store.update("nonexistent", entry("http://c/cb", "c3")));
    }

    #[test]
    fn test_store_matching_event_filter() {
        let mut store = SubscriptionStore::new();
        // Sub A: all events (no filter).
        store.add(entry("http://a/cb", "ca"));
        // Sub B: only SESSION_RELEASE.
        store.add(SubEntry {
            notify_uri: "http://b/cb".to_string(),
            notify_correlation_id: "cb".to_string(),
            event_list: Some(vec![MbsEvent::SessionRelease]),
            nf_instance_id: None,
        });

        // Both A and B match SESSION_RELEASE.
        let release = store.matching(&MbsEvent::SessionRelease);
        assert_eq!(release.len(), 2);

        // Only A (all-events) matches QOS_INFO.
        let qos = store.matching(&MbsEvent::QosInfo);
        assert_eq!(qos.len(), 1);
        assert_eq!(qos[0].notify_uri, "http://a/cb");
    }

    // ---- extract_path ----

    #[test]
    fn test_extract_path() {
        assert_eq!(extract_path("http://host:80/foo/bar"), "/foo/bar");
        assert_eq!(extract_path("https://host:443/notify"), "/notify");
        assert_eq!(extract_path("http://host:8080"), "/");
        assert_eq!(extract_path("/direct/path"), "/direct/path");
    }

    // ---- SubEntry.matches ----

    #[test]
    fn test_sub_entry_matches() {
        let all_events = SubEntry {
            notify_uri: "u".to_string(),
            notify_correlation_id: "c".to_string(),
            event_list: None,
            nf_instance_id: None,
        };
        assert!(all_events.matches(&MbsEvent::SessionRelease));
        assert!(all_events.matches(&MbsEvent::QosInfo));

        let release_only = SubEntry {
            event_list: Some(vec![MbsEvent::SessionRelease]),
            ..all_events
        };
        assert!(release_only.matches(&MbsEvent::SessionRelease));
        assert!(!release_only.matches(&MbsEvent::QosInfo));
    }
}
