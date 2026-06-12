//! UDR resource trees and change-notification subscriptions (W4.2)
//!
//! Implements the storage backing for the TS 29.504 resource trees that are
//! not subscriber-database backed:
//!
//! - `context-data/amf-3gpp-access` (full Amf3GppAccessRegistration, TS 29.505)
//! - `exposure-data/*` (TS 29.519 AccessAndMobilityData / PduSessionManagementData)
//! - `application-data/*` (TS 29.519 PfdDataForAppExt / TrafficInfluData)
//! - `*/subs-to-notify` subscriptions with real HTTP POST change notifications
//!   to the registered notification URI (bounded timeouts, fire-and-forget).
//!
//! Locking: every accessor copies data out and drops the guard before any
//! other lock or any `.await` (no guard is ever held across an await or a
//! second map lock — see Wave 2/3 ABBA lock-order rule).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use ogs_sbi::client::{SbiClient, SbiClientConfig};
use serde_json::Value;

/// Kind of change subscription (which resource tree it watches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubKind {
    /// TS 29.505 `/subscription-data/subs-to-notify` (DataChangeNotify)
    SubscriptionData,
    /// TS 29.519 `/exposure-data/subs-to-notify` (ExposureDataChangeNotification)
    ExposureData,
    /// TS 29.519 `/application-data/influenceData/subs-to-notify` (TrafficInfluDataNotif)
    AppInfluence,
    /// TS 29.519 `/application-data/subs-to-notify` (ApplicationDataChangeNotif)
    AppData,
}

/// A stored change subscription.
#[derive(Debug, Clone)]
pub struct StoredSub {
    /// Allocated subscription id (used in the resource URI)
    pub id: String,
    /// Resource tree this subscription watches
    pub kind: SubKind,
    /// Where notifications are POSTed
    pub notify_uri: String,
    /// Full subscription document as received
    pub body: Value,
}

/// In-memory UDR data store for non-subscriber-DB resource trees.
#[derive(Default)]
pub struct UdrDataStore {
    /// supi -> full Amf3GppAccessRegistration
    amf_3gpp: RwLock<HashMap<String, Value>>,
    /// ueId -> AccessAndMobilityData
    exposure_am: RwLock<HashMap<String, Value>>,
    /// (ueId, pduSessionId) -> PduSessionManagementData
    exposure_sm: RwLock<HashMap<(String, String), Value>>,
    /// appId -> PfdDataForAppExt
    pfds: RwLock<HashMap<String, Value>>,
    /// influenceId -> TrafficInfluData
    influence: RwLock<HashMap<String, Value>>,
    /// subId -> subscription
    subs: RwLock<HashMap<String, StoredSub>>,
    /// Subscription id allocator
    next_sub_id: AtomicU64,
}

impl UdrDataStore {
    // -- amf-3gpp-access ---------------------------------------------------

    /// Store a registration; returns true when newly created.
    pub fn amf_3gpp_put(&self, supi: &str, doc: Value) -> bool {
        let mut map = self.amf_3gpp.write().expect("lock");
        map.insert(supi.to_string(), doc).is_none()
    }

    pub fn amf_3gpp_get(&self, supi: &str) -> Option<Value> {
        self.amf_3gpp.read().expect("lock").get(supi).cloned()
    }

    pub fn amf_3gpp_remove(&self, supi: &str) -> Option<Value> {
        self.amf_3gpp.write().expect("lock").remove(supi)
    }

    // -- exposure-data -----------------------------------------------------

    pub fn exposure_am_put(&self, ue_id: &str, doc: Value) -> bool {
        let mut map = self.exposure_am.write().expect("lock");
        map.insert(ue_id.to_string(), doc).is_none()
    }

    pub fn exposure_am_get(&self, ue_id: &str) -> Option<Value> {
        self.exposure_am.read().expect("lock").get(ue_id).cloned()
    }

    pub fn exposure_am_remove(&self, ue_id: &str) -> Option<Value> {
        self.exposure_am.write().expect("lock").remove(ue_id)
    }

    pub fn exposure_sm_put(&self, ue_id: &str, psi: &str, doc: Value) -> bool {
        let mut map = self.exposure_sm.write().expect("lock");
        map.insert((ue_id.to_string(), psi.to_string()), doc)
            .is_none()
    }

    pub fn exposure_sm_get(&self, ue_id: &str, psi: &str) -> Option<Value> {
        self.exposure_sm
            .read()
            .expect("lock")
            .get(&(ue_id.to_string(), psi.to_string()))
            .cloned()
    }

    pub fn exposure_sm_remove(&self, ue_id: &str, psi: &str) -> Option<Value> {
        self.exposure_sm
            .write()
            .expect("lock")
            .remove(&(ue_id.to_string(), psi.to_string()))
    }

    // -- application-data --------------------------------------------------

    pub fn pfd_put(&self, app_id: &str, doc: Value) -> bool {
        let mut map = self.pfds.write().expect("lock");
        map.insert(app_id.to_string(), doc).is_none()
    }

    pub fn pfd_get(&self, app_id: &str) -> Option<Value> {
        self.pfds.read().expect("lock").get(app_id).cloned()
    }

    pub fn pfd_remove(&self, app_id: &str) -> Option<Value> {
        self.pfds.write().expect("lock").remove(app_id)
    }

    /// List PFD data, optionally filtered by a set of application ids.
    pub fn pfd_list(&self, app_ids: Option<&[String]>) -> Vec<Value> {
        let map = self.pfds.read().expect("lock");
        map.iter()
            .filter(|(k, _)| app_ids.is_none_or(|ids| ids.iter().any(|id| id == *k)))
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn influence_put(&self, influence_id: &str, doc: Value) -> bool {
        let mut map = self.influence.write().expect("lock");
        map.insert(influence_id.to_string(), doc).is_none()
    }

    pub fn influence_get(&self, influence_id: &str) -> Option<Value> {
        self.influence
            .read()
            .expect("lock")
            .get(influence_id)
            .cloned()
    }

    pub fn influence_remove(&self, influence_id: &str) -> Option<Value> {
        self.influence.write().expect("lock").remove(influence_id)
    }

    /// List influence data filtered by the TS 29.519 ReadInfluenceData query
    /// parameters (each filter, when present, must match).
    pub fn influence_list(
        &self,
        influence_ids: Option<&[String]>,
        dnns: Option<&[String]>,
        supis: Option<&[String]>,
    ) -> Vec<Value> {
        let map = self.influence.read().expect("lock");
        map.iter()
            .filter(|(id, v)| {
                influence_ids.is_none_or(|ids| ids.iter().any(|i| i == *id))
                    && dnns.is_none_or(|d| {
                        v.get("dnn")
                            .and_then(Value::as_str)
                            .is_some_and(|dnn| d.iter().any(|x| x == dnn))
                    })
                    && supis.is_none_or(|s| {
                        v.get("supi")
                            .and_then(Value::as_str)
                            .is_some_and(|supi| s.iter().any(|x| x == supi))
                    })
            })
            .map(|(_, v)| v.clone())
            .collect()
    }

    // -- subscriptions -----------------------------------------------------

    /// Create a subscription; returns the stored record with allocated id.
    pub fn sub_create(&self, kind: SubKind, notify_uri: &str, body: Value) -> StoredSub {
        let id = format!("{}", self.next_sub_id.fetch_add(1, Ordering::SeqCst) + 1);
        let sub = StoredSub {
            id: id.clone(),
            kind,
            notify_uri: notify_uri.to_string(),
            body,
        };
        self.subs.write().expect("lock").insert(id, sub.clone());
        sub
    }

    pub fn sub_get(&self, sub_id: &str) -> Option<StoredSub> {
        self.subs.read().expect("lock").get(sub_id).cloned()
    }

    /// Replace an existing subscription's notify URI/body. Returns false when
    /// the subscription does not exist or is of a different kind.
    pub fn sub_replace(&self, sub_id: &str, kind: SubKind, notify_uri: &str, body: Value) -> bool {
        let mut map = self.subs.write().expect("lock");
        match map.get_mut(sub_id) {
            Some(sub) if sub.kind == kind => {
                sub.notify_uri = notify_uri.to_string();
                sub.body = body;
                true
            }
            _ => false,
        }
    }

    /// Patch an existing subscription's body in place (already-merged body).
    pub fn sub_set_body(&self, sub_id: &str, body: Value, notify_uri: Option<String>) -> bool {
        let mut map = self.subs.write().expect("lock");
        match map.get_mut(sub_id) {
            Some(sub) => {
                if let Some(uri) = notify_uri {
                    sub.notify_uri = uri;
                }
                sub.body = body;
                true
            }
            None => false,
        }
    }

    pub fn sub_remove(&self, sub_id: &str) -> Option<StoredSub> {
        self.subs.write().expect("lock").remove(sub_id)
    }

    /// List subscriptions of a kind matching a predicate (copies out).
    pub fn subs_matching<F: Fn(&StoredSub) -> bool>(&self, kind: SubKind, pred: F) -> Vec<StoredSub> {
        self.subs
            .read()
            .expect("lock")
            .values()
            .filter(|s| s.kind == kind && pred(s))
            .cloned()
            .collect()
    }

    /// Remove all SubscriptionData subscriptions for a ue-id; returns count.
    pub fn subs_remove_by_ue(&self, ue_id: &str) -> usize {
        let mut map = self.subs.write().expect("lock");
        let before = map.len();
        map.retain(|_, s| {
            !(s.kind == SubKind::SubscriptionData
                && s.body.get("ueId").and_then(Value::as_str) == Some(ue_id))
        });
        before - map.len()
    }
}

/// Global UDR data store singleton.
pub fn store() -> &'static UdrDataStore {
    static STORE: OnceLock<UdrDataStore> = OnceLock::new();
    STORE.get_or_init(UdrDataStore::default)
}

// ---------------------------------------------------------------------------
// Helpers: URI handling, RFC 7396 merge-patch, notification dispatch
// ---------------------------------------------------------------------------

/// RFC 7396 JSON merge-patch applied in place.
pub fn merge_patch(target: &mut Value, patch: &Value) {
    if let Value::Object(patch_obj) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let target_obj = target.as_object_mut().expect("object");
        for (k, v) in patch_obj {
            if v.is_null() {
                target_obj.remove(k);
            } else {
                merge_patch(target_obj.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
    } else {
        *target = patch.clone();
    }
}

/// Parse `http(s)://host[:port]/path` into (host, port, path).
pub fn parse_notify_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(rest) = uri.strip_prefix("https://") {
        (443u16, rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        (80u16, rest)
    } else {
        return None;
    };
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port, path))
    } else {
        Some((host_port.to_string(), default_port, path))
    }
}

/// Path of a URI (strips scheme and authority when present).
fn uri_path(uri: &str) -> &str {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"));
    match rest {
        Some(r) => match r.find('/') {
            Some(idx) => &r[idx..],
            None => "/",
        },
        None => uri,
    }
}

/// True when a monitored resource URI covers a changed resource path:
/// exact match, monitored-is-ancestor, or suffix match (apiRoot-agnostic).
pub fn uri_covers(monitored: &str, changed_path: &str) -> bool {
    let mp = uri_path(monitored).trim_end_matches('/');
    let cp = changed_path.trim_end_matches('/');
    if mp.is_empty() {
        return false;
    }
    mp == cp || cp.starts_with(&format!("{mp}/")) || mp.ends_with(cp) || cp.ends_with(mp)
}

/// POST a JSON notification to a notify URI as a detached task with bounded
/// connect/request timeouts. Failures are logged, never propagated.
pub fn post_notification(notify_uri: String, payload: Value) {
    let Some((host, port, path)) = parse_notify_uri(&notify_uri) else {
        log::warn!("Invalid notification URI, dropping notification: {notify_uri}");
        return;
    };
    tokio::spawn(async move {
        let client = SbiClient::new(
            SbiClientConfig::new(host, port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        );
        match client.post_json(&path, &payload).await {
            Ok(resp) if (200..300).contains(&resp.status) => {
                log::debug!("Notification delivered to {notify_uri} ({})", resp.status);
            }
            Ok(resp) => {
                log::warn!("Notification to {notify_uri} rejected: {}", resp.status);
            }
            Err(e) => {
                log::warn!("Notification to {notify_uri} failed: {e}");
            }
        }
        client.close().await;
    });
}

// ---------------------------------------------------------------------------
// Change-notification builders/dispatchers (spec payload shapes)
// ---------------------------------------------------------------------------

/// TS 29.505 DataChangeNotify to subscription-data subscribers whose
/// monitoredResourceUris cover the changed resource (or whose ueId matches).
pub fn notify_subscription_data_change(ue_id: &str, changed_path: &str, new_value: Option<&Value>) {
    let subs = store().subs_matching(SubKind::SubscriptionData, |s| {
        let ue_match = s.body.get("ueId").and_then(Value::as_str) == Some(ue_id);
        let uri_match = s
            .body
            .get("monitoredResourceUris")
            .and_then(Value::as_array)
            .is_some_and(|uris| {
                uris.iter()
                    .filter_map(Value::as_str)
                    .any(|u| uri_covers(u, changed_path))
            });
        ue_match || uri_match
    });
    for sub in subs {
        let change = match new_value {
            Some(v) => serde_json::json!({"op": "REPLACE", "path": "", "newValue": v}),
            None => serde_json::json!({"op": "REMOVE", "path": ""}),
        };
        let payload = serde_json::json!({
            "ueId": ue_id,
            "originalCallbackReference": [sub.notify_uri],
            "notifyItems": [{
                "resourceId": changed_path,
                "changes": [change]
            }],
            "subscriptionDataSubscriptions": [sub.body]
        });
        post_notification(sub.notify_uri.clone(), payload);
    }
}

/// TS 29.519 ExposureDataChangeNotification (array) to exposure-data
/// subscribers whose monitoredResourceUris cover the changed resource.
pub fn notify_exposure_data_change(ue_id: &str, changed_path: &str, notification: Value) {
    let subs = store().subs_matching(SubKind::ExposureData, |s| {
        s.body
            .get("monitoredResourceUris")
            .and_then(Value::as_array)
            .is_some_and(|uris| {
                uris.iter()
                    .filter_map(Value::as_str)
                    .any(|u| uri_covers(u, changed_path))
            })
    });
    for sub in subs {
        let mut item = notification.clone();
        if let Some(obj) = item.as_object_mut() {
            obj.insert("ueId".to_string(), Value::String(ue_id.to_string()));
        }
        post_notification(sub.notify_uri.clone(), Value::Array(vec![item]));
    }
}

/// TS 29.519 TrafficInfluDataNotif (array) to influenceData subscribers whose
/// TrafficInfluSub filters (dnns/snssais/supis/internalGroupIds) match.
pub fn notify_influence_data_change(res_uri: &str, data: Option<&Value>) {
    let subs = store().subs_matching(SubKind::AppInfluence, |s| {
        // Deleted data matches every subscription (subscribers must learn of
        // removals); otherwise at least one provided filter array must match.
        let Some(d) = data else { return true };
        let arr_match = |filter: &str, field: &str| {
            s.body
                .get(filter)
                .and_then(Value::as_array)
                .is_some_and(|list| {
                    d.get(field)
                        .is_some_and(|v| list.iter().any(|f| f == v))
                })
        };
        arr_match("dnns", "dnn")
            || arr_match("snssais", "snssai")
            || arr_match("supis", "supi")
            || arr_match("internalGroupIds", "interGroupId")
    });
    for sub in subs {
        let mut item = serde_json::Map::new();
        item.insert("resUri".to_string(), Value::String(res_uri.to_string()));
        if let Some(d) = data {
            item.insert("trafficInfluData".to_string(), d.clone());
        }
        post_notification(
            sub.notify_uri.clone(),
            Value::Array(vec![Value::Object(item)]),
        );
    }
}

/// TS 29.519 ApplicationDataChangeNotif (array) to application-data
/// subscribers (PFD changes).
pub fn notify_application_data_change(res_uri: &str, app_id: &str, removed: bool) {
    let subs = store().subs_matching(SubKind::AppData, |_| true);
    for sub in subs {
        let mut pfd_change = serde_json::Map::new();
        pfd_change.insert(
            "applicationId".to_string(),
            Value::String(app_id.to_string()),
        );
        if removed {
            pfd_change.insert("removalFlag".to_string(), Value::Bool(true));
        }
        let payload = serde_json::json!([{
            "resUri": res_uri,
            "pfdData": Value::Object(pfd_change)
        }]);
        post_notification(sub.notify_uri.clone(), payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_merge_patch_rfc7396() {
        let mut target = json!({"a": "b", "c": {"d": "e", "f": "g"}});
        let patch = json!({"a": "z", "c": {"f": null}});
        merge_patch(&mut target, &patch);
        assert_eq!(target, json!({"a": "z", "c": {"d": "e"}}));

        // Non-object patch replaces wholesale
        let mut target = json!({"a": 1});
        merge_patch(&mut target, &json!([1, 2]));
        assert_eq!(target, json!([1, 2]));
    }

    #[test]
    fn test_parse_notify_uri() {
        assert_eq!(
            parse_notify_uri("http://127.0.0.1:8080/cb/notify"),
            Some(("127.0.0.1".to_string(), 8080, "/cb/notify".to_string()))
        );
        assert_eq!(
            parse_notify_uri("https://nf.example.com/cb"),
            Some(("nf.example.com".to_string(), 443, "/cb".to_string()))
        );
        assert_eq!(
            parse_notify_uri("http://host:7777"),
            Some(("host".to_string(), 7777, "/".to_string()))
        );
        assert_eq!(parse_notify_uri("ftp://host/x"), None);
    }

    #[test]
    fn test_uri_covers() {
        let changed = "/nudr-dr/v1/subscription-data/imsi-1/context-data/amf-3gpp-access";
        // Exact full-URI match
        assert!(uri_covers(
            "http://udr:7777/nudr-dr/v1/subscription-data/imsi-1/context-data/amf-3gpp-access",
            changed
        ));
        // Ancestor match (monitored subtree)
        assert!(uri_covers(
            "http://udr:7777/nudr-dr/v1/subscription-data/imsi-1/context-data",
            changed
        ));
        // Different UE does not match
        assert!(!uri_covers(
            "http://udr:7777/nudr-dr/v1/subscription-data/imsi-2/context-data",
            changed
        ));
    }

    #[test]
    fn test_store_amf_3gpp_roundtrip() {
        let s = UdrDataStore::default();
        let doc = json!({"amfInstanceId": "x", "guami": {}});
        assert!(s.amf_3gpp_put("imsi-1", doc.clone()));
        assert!(!s.amf_3gpp_put("imsi-1", doc.clone())); // replace, not create
        assert_eq!(s.amf_3gpp_get("imsi-1"), Some(doc));
        assert!(s.amf_3gpp_remove("imsi-1").is_some());
        assert!(s.amf_3gpp_get("imsi-1").is_none());
    }

    #[test]
    fn test_store_exposure_roundtrip() {
        let s = UdrDataStore::default();
        assert!(s.exposure_am_put("imsi-1", json!({"roamingStatus": false})));
        assert!(s.exposure_sm_put("imsi-1", "5", json!({"dnn": "internet"})));
        assert!(s.exposure_am_get("imsi-1").is_some());
        assert!(s.exposure_sm_get("imsi-1", "5").is_some());
        assert!(s.exposure_sm_get("imsi-1", "6").is_none());
        assert!(s.exposure_am_remove("imsi-1").is_some());
        assert!(s.exposure_sm_remove("imsi-1", "5").is_some());
    }

    #[test]
    fn test_store_subscriptions() {
        let s = UdrDataStore::default();
        let sub = s.sub_create(
            SubKind::SubscriptionData,
            "http://x:1/cb",
            json!({"ueId": "imsi-1", "callbackReference": "http://x:1/cb",
                   "monitoredResourceUris": ["/nudr-dr/v1/subscription-data/imsi-1"]}),
        );
        assert!(s.sub_get(&sub.id).is_some());
        // kind mismatch on replace
        assert!(!s.sub_replace(&sub.id, SubKind::ExposureData, "http://y:1/cb", json!({})));
        assert!(s.sub_replace(
            &sub.id,
            SubKind::SubscriptionData,
            "http://y:1/cb",
            json!({"ueId": "imsi-1"})
        ));
        assert_eq!(s.subs_remove_by_ue("imsi-1"), 1);
        assert!(s.sub_get(&sub.id).is_none());
    }

    #[test]
    fn test_influence_list_filters() {
        let s = UdrDataStore::default();
        s.influence_put(
            "inf-1",
            json!({"afAppId": "app1", "dnn": "internet", "supi": "imsi-1"}),
        );
        s.influence_put(
            "inf-2",
            json!({"afAppId": "app2", "dnn": "ims", "supi": "imsi-2"}),
        );
        assert_eq!(s.influence_list(None, None, None).len(), 2);
        assert_eq!(
            s.influence_list(None, Some(&["internet".to_string()]), None)
                .len(),
            1
        );
        assert_eq!(
            s.influence_list(None, None, Some(&["imsi-2".to_string()]))
                .len(),
            1
        );
        assert_eq!(
            s.influence_list(Some(&["inf-1".to_string()]), None, None).len(),
            1
        );
    }
}
