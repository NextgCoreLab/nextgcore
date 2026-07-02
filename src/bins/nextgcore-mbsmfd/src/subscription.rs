//! MBS subscription management: StatusSubscribe / ContextStatusSubscribe / Notify
//! (TS 29.532 §5.3.2.6–11, §6.2.6.2.14). [mbsmfd-05]
//!
//! Two subscription families share this module:
//!   - **Status** subscriptions (NEF/MBSF/AF-facing): resource path
//!     `/mbs-sessions/subscriptions`.
//!   - **ContextStatus** subscriptions (SMF-facing): resource path
//!     `/mbs-sessions/contexts/subscriptions`.
//!
//! Both are stored as bare subscription documents (serde_json::Value) together
//! with derived fast-path fields (notifyUri, event_types, mbsSessionId key).
//! RFC 6902 PATCH (PATCH /subscriptions/{id}) mutates the document in-place and
//! re-derives the fast-path fields, returning the modified document as the 200 body.

use crate::types::{MbsSessionId, PatchItem};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Spec-conformant data models (TS 29.532 MBSSession.yaml + CommonData.yaml)
// ---------------------------------------------------------------------------

/// Individual MBS session event in a Status subscription's eventList.
/// (TS 29.532 MbsSessionEvent; eventType is anyOf[enum, string])
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbsSessionEvent {
    pub event_type: String,
}

/// Individual context-status event in a ContextStatus subscription's eventList.
/// (TS 29.532 ContextStatusEvent)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusEvent {
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immediate_report_ind: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporting_mode: Option<String>,
}

/// MbsSessionSubscription document (TS 29.532 MBSSession.yaml).
/// Required: eventList (minItems 1) + notifyUri.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbsSessionSubscription {
    pub event_list: Vec<MbsSessionEvent>,
    pub notify_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbs_session_id: Option<MbsSessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nfc_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
}

/// ContextStatusSubscription document (TS 29.532 MBSSession.yaml).
/// Required: nfcInstanceId + mbsSessionId + eventList (minItems 1) + notifyUri.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusSubscription {
    pub nfc_instance_id: String,
    pub mbs_session_id: MbsSessionId,
    pub event_list: Vec<ContextStatusEvent>,
    pub notify_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
}

// ---------------------------------------------------------------------------
// Subscribe request / response wrappers
// ---------------------------------------------------------------------------

/// POST /mbs-sessions/subscriptions body (TS 29.532 §5.3.2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusSubscribeReqData {
    pub subscription: MbsSessionSubscription,
}

/// 201 response body for POST /mbs-sessions/subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusSubscribeRspData {
    pub subscription: MbsSessionSubscription,
}

/// POST /mbs-sessions/contexts/subscriptions body (TS 29.532 §5.3.2.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusSubscribeReqData {
    pub subscription: ContextStatusSubscription,
}

/// 201 response body for POST /mbs-sessions/contexts/subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusSubscribeRspData {
    pub subscription: ContextStatusSubscription,
}

// ---------------------------------------------------------------------------
// Notify callback bodies (POSTed to notifyUri)
// ---------------------------------------------------------------------------

/// Individual event report in a Status notification.
/// (TS 29.532 MBSSession.yaml MbsSessionEventReport)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbsSessionEventReport {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_stamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_del_status: Option<String>,
}

/// List of event reports + optional correlation Id.
/// (TS 29.532 MbsSessionEventReportList)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbsSessionEventReportList {
    pub event_report_list: Vec<MbsSessionEventReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_correlation_id: Option<String>,
}

/// Body POSTed to the subscriber's notifyUri for a Status event
/// (TS 29.532 §5.3.2.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusNotifyReqData {
    pub event_list: MbsSessionEventReportList,
}

/// Individual context-status event report.
/// (TS 29.532 ContextStatusEventReport — required: eventType + timeStamp)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusEventReport {
    pub event_type: String,
    pub time_stamp: String,
}

/// Body POSTed to the subscriber's notifyUri for a ContextStatus event
/// (TS 29.532 §5.3.2.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStatusNotifyReqData {
    pub report_list: Vec<ContextStatusEventReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_correlation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// In-memory subscription store
// ---------------------------------------------------------------------------

/// A single subscription document held in the store.
#[derive(Debug, Clone)]
pub struct SubEntry {
    pub notify_uri: String,
    pub notify_correlation_id: Option<String>,
    /// Empty means "all events".
    pub event_types: Vec<String>,
    /// Normalized mbsSessionId for ContextStatus keying; None = match all sessions.
    pub mbs_session_id: Option<serde_json::Value>,
    /// Bare subscription document (MbsSessionSubscription or ContextStatusSubscription
    /// serialized to JSON) — the source of truth for PATCH echo.
    pub document: serde_json::Value,
}

impl SubEntry {
    /// Returns true when this subscription should receive `event_type`.
    pub fn matches(&self, event_type: &str) -> bool {
        self.event_types.is_empty() || self.event_types.iter().any(|e| e == event_type)
    }

    /// Returns true when this subscription's session key matches `key`.
    /// A subscription with no session key matches any session.
    pub fn matches_session(&self, key: &Option<serde_json::Value>) -> bool {
        match (&self.mbs_session_id, key) {
            (Some(a), Some(b)) => a == b,
            (Some(_), None) => true,
            (None, _) => true,
        }
    }

    /// Re-sync derived fast-path fields from the stored document after a PATCH.
    pub fn refresh_from_document(&mut self) {
        let d = &self.document;
        self.notify_uri = d
            .get("notifyUri")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.notify_uri)
            .to_string();
        self.notify_correlation_id = d
            .get("notifyCorrelationId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        self.event_types = d
            .get("eventList")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        e.get("eventType")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.mbs_session_id = d.get("mbsSessionId").cloned();
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

    /// Remove a subscription (DELETE). Returns false if not found.
    pub fn remove(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Retrieve a subscription by ID.
    pub fn get(&self, id: &str) -> Option<&SubEntry> {
        self.entries.get(id)
    }

    /// Apply a JSON Patch (RFC 6902 subset) to the subscription document;
    /// re-syncs derived fields and returns the modified bare document.
    /// Returns None if the subscription does not exist.
    pub fn patch(&mut self, id: &str, ops: &[PatchItem]) -> Option<serde_json::Value> {
        let e = self.entries.get_mut(id)?;
        json_patch_apply(&mut e.document, ops);
        e.refresh_from_document();
        Some(e.document.clone())
    }

    /// Collect all entries that match `event_type` and `session` key.
    pub fn matching(&self, event_type: &str, session: &Option<serde_json::Value>) -> Vec<SubEntry> {
        self.entries
            .values()
            .filter(|e| e.matches(event_type) && e.matches_session(session))
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
// Minimal RFC 6902 JSON Patch applier (top-level + one-level object paths)
// ---------------------------------------------------------------------------

fn json_patch_apply(doc: &mut serde_json::Value, ops: &[PatchItem]) {
    for op in ops {
        match op.op.as_str() {
            "remove" => {
                let (parent_opt, key_opt) = split_pointer(doc, &op.path);
                if let (Some(parent), Some(key)) = (parent_opt, key_opt) {
                    if let Some(m) = parent.as_object_mut() {
                        m.remove(&key);
                    }
                }
            }
            "add" | "replace" => {
                if let Some(val) = &op.value {
                    let val = val.clone();
                    let (parent_opt, key_opt) = split_pointer(doc, &op.path);
                    if let (Some(parent), Some(key)) = (parent_opt, key_opt) {
                        if let Some(m) = parent.as_object_mut() {
                            m.insert(key, val);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Split a JSON Pointer path (RFC 6901) into the mutable parent Value and
/// the final key string. Handles top-level (`/key`) and one-level (`/a/b`).
/// Returns `(None, None)` for empty or unparseable paths.
fn split_pointer<'a>(
    doc: &'a mut serde_json::Value,
    path: &str,
) -> (Option<&'a mut serde_json::Value>, Option<String>) {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return (None, None);
    }
    if let Some(slash) = path.find('/') {
        let parent_ptr = format!("/{}", &path[..slash]);
        let key = path[slash + 1..].to_string();
        if key.is_empty() {
            return (None, None);
        }
        (doc.pointer_mut(&parent_ptr), Some(key))
    } else {
        (Some(doc), Some(path.to_string()))
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
            log::debug!(
                "[sub] notification delivered to {notify_uri} ({})",
                rsp.status
            );
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
    use crate::types;

    // ---- SubscriptionStore helpers ----

    fn entry(uri: &str, corr: &str) -> SubEntry {
        SubEntry {
            notify_uri: uri.to_string(),
            notify_correlation_id: Some(corr.to_string()),
            event_types: vec![],
            mbs_session_id: None,
            document: serde_json::json!({}),
        }
    }

    // ---- SubscriptionStore CRUD ----

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
        // Build an entry with a real document so patch can update it.
        let doc = serde_json::json!({
            "notifyUri": "http://a/cb",
            "notifyCorrelationId": "c1",
            "eventList": []
        });
        let id = store.add(SubEntry {
            notify_uri: "http://a/cb".to_string(),
            notify_correlation_id: Some("c1".to_string()),
            event_types: vec![],
            mbs_session_id: None,
            document: doc,
        });

        // Patch replaces notifyCorrelationId.
        let ops = vec![PatchItem {
            op: "replace".to_string(),
            path: "/notifyCorrelationId".to_string(),
            from: None,
            value: Some(serde_json::json!("c2")),
        }];
        let result = store.patch(&id, &ops);
        assert!(result.is_some());
        assert_eq!(
            store.get(&id).unwrap().notify_correlation_id.as_deref(),
            Some("c2")
        );

        // Patch on unknown id returns None.
        assert!(store.patch("nonexistent", &ops).is_none());
    }

    #[test]
    fn test_store_matching_event_filter() {
        let mut store = SubscriptionStore::new();
        // Sub A: all events (empty event_types).
        store.add(entry("http://a/cb", "ca"));
        // Sub B: only SESSION_RELEASE.
        store.add(SubEntry {
            notify_uri: "http://b/cb".to_string(),
            notify_correlation_id: Some("cb".to_string()),
            event_types: vec!["SESSION_RELEASE".to_string()],
            mbs_session_id: None,
            document: serde_json::json!({}),
        });

        // Both A and B match SESSION_RELEASE.
        let release = store.matching("SESSION_RELEASE", &None);
        assert_eq!(release.len(), 2);

        // Only A (all-events) matches QOS_INFO.
        let qos = store.matching("QOS_INFO", &None);
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
            notify_correlation_id: None,
            event_types: vec![],
            mbs_session_id: None,
            document: serde_json::json!({}),
        };
        assert!(all_events.matches("SESSION_RELEASE"));
        assert!(all_events.matches("QOS_INFO"));

        let release_only = SubEntry {
            event_types: vec!["SESSION_RELEASE".to_string()],
            notify_uri: all_events.notify_uri.clone(),
            notify_correlation_id: None,
            mbs_session_id: None,
            document: serde_json::json!({}),
        };
        assert!(release_only.matches("SESSION_RELEASE"));
        assert!(!release_only.matches("QOS_INFO"));
    }

    // ---- StatusSubscribeReqData serde ----

    #[test]
    fn test_status_subscribe_req_roundtrip() {
        let json = r#"{"subscription":{"eventList":[{"eventType":"BROADCAST_DELIVERY_STATUS"}],"notifyUri":"http://smf:8080/notify","notifyCorrelationId":"corr-001"}}"#;
        let req: StatusSubscribeReqData = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.subscription.event_list[0].event_type,
            "BROADCAST_DELIVERY_STATUS"
        );
        assert_eq!(req.subscription.notify_uri, "http://smf:8080/notify");
        // Round-trip.
        let back: StatusSubscribeReqData =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.subscription.notify_uri, "http://smf:8080/notify");
    }

    // ---- ContextStatusSubscribeReqData serde ----

    #[test]
    fn test_context_status_subscribe_req_roundtrip() {
        let req = ContextStatusSubscribeReqData {
            subscription: ContextStatusSubscription {
                nfc_instance_id: "smf-1".to_string(),
                mbs_session_id: types::MbsSessionId {
                    tmgi: Some(types::Tmgi {
                        mbs_service_id: "010203".to_string(),
                        plmn_id: types::PlmnId {
                            mcc: "001".to_string(),
                            mnc: "01".to_string(),
                        },
                    }),
                    ssm: None,
                },
                event_list: vec![ContextStatusEvent {
                    event_type: "SESSION_RELEASE".to_string(),
                    immediate_report_ind: None,
                    reporting_mode: None,
                }],
                notify_uri: "http://smf:9000/ctx-notify".to_string(),
                notify_correlation_id: None,
                expiry_time: None,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"nfcInstanceId\""));
        assert!(json.contains("\"SESSION_RELEASE\""));
        let back: ContextStatusSubscribeReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.subscription.nfc_instance_id, "smf-1");
    }

    // ---- StatusNotifyReqData serde ----

    #[test]
    fn test_status_notify_req_roundtrip() {
        let n = StatusNotifyReqData {
            event_list: MbsSessionEventReportList {
                event_report_list: vec![MbsSessionEventReport {
                    event_type: "BROADCAST_DELIVERY_STATUS".to_string(),
                    time_stamp: Some("2026-06-28T00:00:00Z".to_string()),
                    broadcast_del_status: Some("TERMINATED".to_string()),
                }],
                notify_correlation_id: Some("corr-001".to_string()),
            },
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"eventList\""));
        assert!(json.contains("\"eventReportList\""));
        assert!(json.contains("\"BROADCAST_DELIVERY_STATUS\""));
        assert!(
            !json.contains("mbsEvent"),
            "old bespoke field must be absent"
        );
        let back: StatusNotifyReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.event_list.event_report_list[0].event_type,
            "BROADCAST_DELIVERY_STATUS"
        );
    }

    // ---- ContextStatusNotifyReqData serde ----

    #[test]
    fn test_context_status_notify_req_roundtrip() {
        let n = ContextStatusNotifyReqData {
            report_list: vec![ContextStatusEventReport {
                event_type: "SESSION_RELEASE".to_string(),
                time_stamp: "2026-06-28T00:00:00Z".to_string(),
            }],
            notify_correlation_id: None,
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"reportList\""));
        assert!(json.contains("\"SESSION_RELEASE\""));
        assert!(json.contains("\"timeStamp\""));
        assert!(
            !json.contains("\"mbsEvent\""),
            "old bespoke field must be absent"
        );
        let back: ContextStatusNotifyReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.report_list[0].event_type, "SESSION_RELEASE");
    }
}
