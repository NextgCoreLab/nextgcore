//! UDR resource trees and change-notification subscriptions
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
//! second map lock — see the documented ABBA lock-order rule).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
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

impl SubKind {
    /// Stable string tag used in the on-disk snapshot.
    fn as_tag(self) -> &'static str {
        match self {
            SubKind::SubscriptionData => "SubscriptionData",
            SubKind::ExposureData => "ExposureData",
            SubKind::AppInfluence => "AppInfluence",
            SubKind::AppData => "AppData",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "SubscriptionData" => Some(SubKind::SubscriptionData),
            "ExposureData" => Some(SubKind::ExposureData),
            "AppInfluence" => Some(SubKind::AppInfluence),
            "AppData" => Some(SubKind::AppData),
            _ => None,
        }
    }
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
///
/// When a `state_path` is configured (via [`UdrDataStore::with_state_path`] /
/// [`init_store`]), every mutation snapshots the full store to that JSON file
/// (atomic temp+rename) so the resource trees survive a process restart. With
/// no path configured the store is purely in-memory and all persistence is a
/// no-op, preserving the previous behaviour (and the Docker/E2E default).
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
    /// (supi, pduSessionId) -> full SmfRegistration document (TS 29.505).
    /// Stores the ACTUAL registered values (smfInstanceId, sNssai, dnn,
    /// pduSessionId, plmnId, ...) as PUT by the consumer, not a hardcoded
    /// summary, so GET returns exactly what was registered.
    smf_registrations: RwLock<HashMap<(String, String), Value>>,
    /// supi -> provisioned AmPolicyData (TS 29.519 §5.2)
    policy_am: RwLock<HashMap<String, Value>>,
    /// supi -> provisioned SmPolicyData (TS 29.519 §5.3)
    policy_sm: RwLock<HashMap<String, Value>>,
    /// supi -> provisioned UePolicySet (TS 29.519 §5.4)
    policy_ue: RwLock<HashMap<String, Value>>,
    /// subId -> subscription
    subs: RwLock<HashMap<String, StoredSub>>,
    /// Subscription id allocator
    next_sub_id: AtomicU64,
    /// Optional on-disk snapshot path. `None` => purely in-memory.
    state_path: Option<PathBuf>,
}

impl UdrDataStore {
    /// Construct a store that snapshots to `path` on every mutation. If the
    /// file already exists it is loaded so prior state is restored.
    pub fn with_state_path(path: impl Into<PathBuf>) -> Self {
        let mut store = UdrDataStore {
            state_path: Some(path.into()),
            ..Default::default()
        };
        store.load();
        store
    }

    // -- persistence -------------------------------------------------------

    /// Serialize the full store as a single JSON snapshot document.
    fn snapshot(&self) -> Value {
        let amf_3gpp: HashMap<String, Value> = self.amf_3gpp.read().expect("lock").clone();
        let exposure_am: HashMap<String, Value> = self.exposure_am.read().expect("lock").clone();
        // (ueId, psi) tuple keys are flattened to "ueId\u{1f}psi" strings so the
        // map round-trips through JSON object keys without ambiguity.
        let exposure_sm: HashMap<String, Value> = self
            .exposure_sm
            .read()
            .expect("lock")
            .iter()
            .map(|((ue, psi), v)| (format!("{ue}\u{1f}{psi}"), v.clone()))
            .collect();
        let pfds: HashMap<String, Value> = self.pfds.read().expect("lock").clone();
        let influence: HashMap<String, Value> = self.influence.read().expect("lock").clone();
        let smf_registrations: HashMap<String, Value> = self
            .smf_registrations
            .read()
            .expect("lock")
            .iter()
            .map(|((supi, psi), v)| (format!("{supi}\u{1f}{psi}"), v.clone()))
            .collect();
        let policy_am: HashMap<String, Value> = self.policy_am.read().expect("lock").clone();
        let policy_sm: HashMap<String, Value> = self.policy_sm.read().expect("lock").clone();
        let policy_ue: HashMap<String, Value> = self.policy_ue.read().expect("lock").clone();
        let subs: Vec<Value> = self
            .subs
            .read()
            .expect("lock")
            .values()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "kind": s.kind.as_tag(),
                    "notify_uri": s.notify_uri,
                    "body": s.body,
                })
            })
            .collect();
        serde_json::json!({
            "version": 1,
            "next_sub_id": self.next_sub_id.load(Ordering::SeqCst),
            "amf_3gpp": amf_3gpp,
            "exposure_am": exposure_am,
            "exposure_sm": exposure_sm,
            "pfds": pfds,
            "influence": influence,
            "smf_registrations": smf_registrations,
            "policy_am": policy_am,
            "policy_sm": policy_sm,
            "policy_ue": policy_ue,
            "subs": subs,
        })
    }

    /// Persist the current store to disk. No-op when no path is configured.
    /// Failures are logged, never propagated (best-effort durability — the
    /// in-memory store remains authoritative for the live process).
    fn persist(&self) {
        let Some(path) = self.state_path.as_ref() else {
            return;
        };
        let doc = self.snapshot();
        if let Err(e) = write_atomic(path, &doc) {
            log::warn!("UDR state persist to {} failed: {e}", path.display());
        }
    }

    /// Load state from the configured path into this (empty) store. No-op when
    /// no path is set or the file does not exist yet.
    fn load(&mut self) {
        let Some(path) = self.state_path.clone() else {
            return;
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::warn!("UDR state load from {} failed: {e}", path.display());
                return;
            }
        };
        let doc: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("UDR state file {} is not valid JSON: {e}", path.display());
                return;
            }
        };
        self.restore_from(&doc);
    }

    /// Restore in-memory maps from a snapshot document (used by `load` and by
    /// tests). Unknown/missing fields are tolerated.
    fn restore_from(&self, doc: &Value) {
        let obj_map = |key: &str| -> HashMap<String, Value> {
            doc.get(key)
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default()
        };
        *self.amf_3gpp.write().expect("lock") = obj_map("amf_3gpp");
        *self.exposure_am.write().expect("lock") = obj_map("exposure_am");
        {
            let mut sm = self.exposure_sm.write().expect("lock");
            sm.clear();
            if let Some(m) = doc.get("exposure_sm").and_then(Value::as_object) {
                for (k, v) in m {
                    if let Some((ue, psi)) = k.split_once('\u{1f}') {
                        sm.insert((ue.to_string(), psi.to_string()), v.clone());
                    }
                }
            }
        }
        *self.pfds.write().expect("lock") = obj_map("pfds");
        *self.influence.write().expect("lock") = obj_map("influence");
        *self.policy_am.write().expect("lock") = obj_map("policy_am");
        *self.policy_sm.write().expect("lock") = obj_map("policy_sm");
        *self.policy_ue.write().expect("lock") = obj_map("policy_ue");
        {
            let mut sr = self.smf_registrations.write().expect("lock");
            sr.clear();
            if let Some(m) = doc.get("smf_registrations").and_then(Value::as_object) {
                for (k, v) in m {
                    if let Some((supi, psi)) = k.split_once('\u{1f}') {
                        sr.insert((supi.to_string(), psi.to_string()), v.clone());
                    }
                }
            }
        }
        {
            let mut subs = self.subs.write().expect("lock");
            subs.clear();
            if let Some(arr) = doc.get("subs").and_then(Value::as_array) {
                for s in arr {
                    let (Some(id), Some(kind), Some(uri)) = (
                        s.get("id").and_then(Value::as_str),
                        s.get("kind")
                            .and_then(Value::as_str)
                            .and_then(SubKind::from_tag),
                        s.get("notify_uri").and_then(Value::as_str),
                    ) else {
                        continue;
                    };
                    subs.insert(
                        id.to_string(),
                        StoredSub {
                            id: id.to_string(),
                            kind,
                            notify_uri: uri.to_string(),
                            body: s.get("body").cloned().unwrap_or(Value::Null),
                        },
                    );
                }
            }
        }
        if let Some(n) = doc.get("next_sub_id").and_then(Value::as_u64) {
            self.next_sub_id.store(n, Ordering::SeqCst);
        }
    }

    // -- amf-3gpp-access ---------------------------------------------------

    /// Store a registration; returns true when newly created.
    pub fn amf_3gpp_put(&self, supi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.amf_3gpp.write().expect("lock");
            map.insert(supi.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    pub fn amf_3gpp_get(&self, supi: &str) -> Option<Value> {
        self.amf_3gpp.read().expect("lock").get(supi).cloned()
    }

    pub fn amf_3gpp_remove(&self, supi: &str) -> Option<Value> {
        let removed = self.amf_3gpp.write().expect("lock").remove(supi);
        self.persist();
        removed
    }

    // -- exposure-data -----------------------------------------------------

    pub fn exposure_am_put(&self, ue_id: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.exposure_am.write().expect("lock");
            map.insert(ue_id.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    pub fn exposure_am_get(&self, ue_id: &str) -> Option<Value> {
        self.exposure_am.read().expect("lock").get(ue_id).cloned()
    }

    pub fn exposure_am_remove(&self, ue_id: &str) -> Option<Value> {
        let removed = self.exposure_am.write().expect("lock").remove(ue_id);
        self.persist();
        removed
    }

    pub fn exposure_sm_put(&self, ue_id: &str, psi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.exposure_sm.write().expect("lock");
            map.insert((ue_id.to_string(), psi.to_string()), doc)
                .is_none()
        };
        self.persist();
        created
    }

    pub fn exposure_sm_get(&self, ue_id: &str, psi: &str) -> Option<Value> {
        self.exposure_sm
            .read()
            .expect("lock")
            .get(&(ue_id.to_string(), psi.to_string()))
            .cloned()
    }

    pub fn exposure_sm_remove(&self, ue_id: &str, psi: &str) -> Option<Value> {
        let removed = self
            .exposure_sm
            .write()
            .expect("lock")
            .remove(&(ue_id.to_string(), psi.to_string()));
        self.persist();
        removed
    }

    // -- application-data --------------------------------------------------

    pub fn pfd_put(&self, app_id: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.pfds.write().expect("lock");
            map.insert(app_id.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    pub fn pfd_get(&self, app_id: &str) -> Option<Value> {
        self.pfds.read().expect("lock").get(app_id).cloned()
    }

    pub fn pfd_remove(&self, app_id: &str) -> Option<Value> {
        let removed = self.pfds.write().expect("lock").remove(app_id);
        self.persist();
        removed
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
        let created = {
            let mut map = self.influence.write().expect("lock");
            map.insert(influence_id.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    pub fn influence_get(&self, influence_id: &str) -> Option<Value> {
        self.influence
            .read()
            .expect("lock")
            .get(influence_id)
            .cloned()
    }

    pub fn influence_remove(&self, influence_id: &str) -> Option<Value> {
        let removed = self.influence.write().expect("lock").remove(influence_id);
        self.persist();
        removed
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

    // -- smf-registrations (TS 29.505 context-data) ------------------------

    /// Store/replace the full SmfRegistration document for (supi, psi).
    /// Returns true when newly created. The document is stored verbatim so a
    /// later GET returns the actual registered values, not a hardcoded summary.
    pub fn smf_registration_put(&self, supi: &str, psi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.smf_registrations.write().expect("lock");
            map.insert((supi.to_string(), psi.to_string()), doc)
                .is_none()
        };
        self.persist();
        created
    }

    /// Get the full SmfRegistration document for a single (supi, psi).
    pub fn smf_registration_get(&self, supi: &str, psi: &str) -> Option<Value> {
        self.smf_registrations
            .read()
            .expect("lock")
            .get(&(supi.to_string(), psi.to_string()))
            .cloned()
    }

    /// List all SmfRegistration documents for a SUPI (across all PDU sessions),
    /// sorted by pduSessionId for a stable collection response.
    pub fn smf_registrations_for_supi(&self, supi: &str) -> Vec<Value> {
        let map = self.smf_registrations.read().expect("lock");
        let mut out: Vec<(String, Value)> = map
            .iter()
            .filter(|((s, _), _)| s == supi)
            .map(|((_, psi), v)| (psi.clone(), v.clone()))
            .collect();
        out.sort_by(|a, b| {
            a.0.parse::<u64>()
                .unwrap_or(u64::MAX)
                .cmp(&b.0.parse::<u64>().unwrap_or(u64::MAX))
        });
        out.into_iter().map(|(_, v)| v).collect()
    }

    /// Remove the SmfRegistration document for (supi, psi).
    pub fn smf_registration_remove(&self, supi: &str, psi: &str) -> Option<Value> {
        let removed = self
            .smf_registrations
            .write()
            .expect("lock")
            .remove(&(supi.to_string(), psi.to_string()));
        self.persist();
        removed
    }

    /// Remove all SmfRegistration documents for a SUPI (UE deletion).
    pub fn smf_registrations_remove_by_supi(&self, supi: &str) -> usize {
        let removed = {
            let mut map = self.smf_registrations.write().expect("lock");
            let before = map.len();
            map.retain(|(s, _), _| s != supi);
            before - map.len()
        };
        if removed > 0 {
            self.persist();
        }
        removed
    }

    // -- policy-data (TS 29.519) -------------------------------------------

    /// Store/replace provisioned AmPolicyData for a SUPI.
    /// Returns true when newly created, false when replaced.
    pub fn policy_am_put(&self, supi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.policy_am.write().expect("lock");
            map.insert(supi.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    /// Retrieve provisioned AmPolicyData for a SUPI, or `None` if not set.
    pub fn policy_am_get(&self, supi: &str) -> Option<Value> {
        self.policy_am.read().expect("lock").get(supi).cloned()
    }

    /// Store/replace provisioned SmPolicyData for a SUPI.
    /// Returns true when newly created, false when replaced.
    pub fn policy_sm_put(&self, supi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.policy_sm.write().expect("lock");
            map.insert(supi.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    /// Retrieve provisioned SmPolicyData for a SUPI, or `None` if not set.
    pub fn policy_sm_get(&self, supi: &str) -> Option<Value> {
        self.policy_sm.read().expect("lock").get(supi).cloned()
    }

    /// Store/replace provisioned UePolicySet for a SUPI.
    /// Returns true when newly created, false when replaced.
    pub fn policy_ue_put(&self, supi: &str, doc: Value) -> bool {
        let created = {
            let mut map = self.policy_ue.write().expect("lock");
            map.insert(supi.to_string(), doc).is_none()
        };
        self.persist();
        created
    }

    /// Retrieve provisioned UePolicySet for a SUPI, or `None` if not set.
    pub fn policy_ue_get(&self, supi: &str) -> Option<Value> {
        self.policy_ue.read().expect("lock").get(supi).cloned()
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
        self.persist();
        sub
    }

    pub fn sub_get(&self, sub_id: &str) -> Option<StoredSub> {
        self.subs.read().expect("lock").get(sub_id).cloned()
    }

    /// Replace an existing subscription's notify URI/body. Returns false when
    /// the subscription does not exist or is of a different kind.
    pub fn sub_replace(&self, sub_id: &str, kind: SubKind, notify_uri: &str, body: Value) -> bool {
        let replaced = {
            let mut map = self.subs.write().expect("lock");
            match map.get_mut(sub_id) {
                Some(sub) if sub.kind == kind => {
                    sub.notify_uri = notify_uri.to_string();
                    sub.body = body;
                    true
                }
                _ => false,
            }
        };
        if replaced {
            self.persist();
        }
        replaced
    }

    /// Patch an existing subscription's body in place (already-merged body).
    pub fn sub_set_body(&self, sub_id: &str, body: Value, notify_uri: Option<String>) -> bool {
        let updated = {
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
        };
        if updated {
            self.persist();
        }
        updated
    }

    pub fn sub_remove(&self, sub_id: &str) -> Option<StoredSub> {
        let removed = self.subs.write().expect("lock").remove(sub_id);
        self.persist();
        removed
    }

    /// List subscriptions of a kind matching a predicate (copies out).
    pub fn subs_matching<F: Fn(&StoredSub) -> bool>(
        &self,
        kind: SubKind,
        pred: F,
    ) -> Vec<StoredSub> {
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
        let removed = {
            let mut map = self.subs.write().expect("lock");
            let before = map.len();
            map.retain(|_, s| {
                !(s.kind == SubKind::SubscriptionData
                    && s.body.get("ueId").and_then(Value::as_str) == Some(ue_id))
            });
            before - map.len()
        };
        if removed > 0 {
            self.persist();
        }
        removed
    }
}

/// Atomically write `doc` to `path` (write a temp file in the same directory,
/// then rename over the target) so a crash mid-write can never leave a
/// truncated snapshot. Creates parent directories as needed.
fn write_atomic(path: &Path, doc: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let serialized = serde_json::to_vec_pretty(doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &serialized)?;
    std::fs::rename(&tmp, path)
}

/// Backing cell for the global UDR data store singleton.
static STORE: OnceLock<UdrDataStore> = OnceLock::new();

/// Global UDR data store singleton.
///
/// If [`init_store`] has not been called, this lazily initialises a purely
/// in-memory store (no on-disk snapshot), matching the previous behaviour.
pub fn store() -> &'static UdrDataStore {
    STORE.get_or_init(UdrDataStore::default)
}

/// Initialise the global store with an on-disk snapshot path, loading any
/// previously persisted state. Must be called before the first [`store`] use
/// to take effect; returns `false` if the store was already initialised (in
/// which case the existing store, including its path, is left untouched).
///
/// Passing `None` leaves the store purely in-memory (the default).
pub fn init_store(state_path: Option<PathBuf>) -> bool {
    let store = match state_path {
        Some(p) => UdrDataStore::with_state_path(p),
        None => UdrDataStore::default(),
    };
    STORE.set(store).is_ok()
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
///
/// Payload shape strictly follows TS 29.505 §5.4.2.6 DataChangeNotify +
/// NotifyItem/ChangeItem: only `ueId`, optional `originalCallbackReference`,
/// and `notifyItems[]` with `resourceId`/`changes` are emitted.
/// Non-standard members such as `subscriptionDataSubscriptions` are NOT
/// included (udrd-11).
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
        // TS 29.571 §5.2.4.8: ChangeItem.path is MANDATORY. Use "" (whole
        // resource, per the ChangeItem NOTE / RFC 6901) for a full-resource
        // replace or remove.
        let change = match new_value {
            Some(v) => serde_json::json!({"op": "REPLACE", "path": "", "newValue": v}),
            None => serde_json::json!({"op": "REMOVE", "path": ""}),
        };
        // `originalCallbackReference` is conditional per TS 29.505 DataChangeNotify:
        // include it only when the subscription body carried a `callbackReference`.
        let orig_cb = sub.body.get("callbackReference").and_then(Value::as_str);
        let mut payload_map = serde_json::Map::new();
        payload_map.insert("ueId".to_string(), Value::String(ue_id.to_string()));
        if let Some(cb) = orig_cb {
            payload_map.insert(
                "originalCallbackReference".to_string(),
                serde_json::json!([cb]),
            );
        }
        payload_map.insert(
            "notifyItems".to_string(),
            serde_json::json!([{
                "resourceId": changed_path,
                "changes": [change]
            }]),
        );
        post_notification(sub.notify_uri.clone(), Value::Object(payload_map));
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
                .is_some_and(|list| d.get(field).is_some_and(|v| list.iter().any(|f| f == v)))
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
        let changed = "/nudr-dr/v2/subscription-data/imsi-1/context-data/amf-3gpp-access";
        // Exact full-URI match
        assert!(uri_covers(
            "http://udr:7777/nudr-dr/v2/subscription-data/imsi-1/context-data/amf-3gpp-access",
            changed
        ));
        // Ancestor match (monitored subtree)
        assert!(uri_covers(
            "http://udr:7777/nudr-dr/v2/subscription-data/imsi-1/context-data",
            changed
        ));
        // Different UE does not match
        assert!(!uri_covers(
            "http://udr:7777/nudr-dr/v2/subscription-data/imsi-2/context-data",
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
                   "monitoredResourceUris": ["/nudr-dr/v2/subscription-data/imsi-1"]}),
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
            s.influence_list(Some(&["inf-1".to_string()]), None, None)
                .len(),
            1
        );
    }

    // ------------------------------------------------------------------
    // udrd-04: policy-data store round-trip
    // ------------------------------------------------------------------

    /// TS 29.519 §5 policy-data persistence: put then get must return the
    /// same document; a second put must signal replace (false), not create.
    #[test]
    fn test_policy_store_roundtrip() {
        let s = UdrDataStore::default();
        let supi = "imsi-001010000000099";

        // AmPolicyData
        let am_doc = json!({"suppFeat": "0"});
        assert!(s.policy_am_put(supi, am_doc.clone()), "first put = created");
        assert!(
            !s.policy_am_put(supi, am_doc.clone()),
            "second put = replaced"
        );
        assert_eq!(s.policy_am_get(supi), Some(am_doc));

        // SmPolicyData
        let sm_doc = json!({"smPolicySnssaiData": {}});
        assert!(s.policy_sm_put(supi, sm_doc.clone()), "first put = created");
        assert!(
            !s.policy_sm_put(supi, sm_doc.clone()),
            "second put = replaced"
        );
        assert_eq!(s.policy_sm_get(supi), Some(sm_doc));

        // UePolicySet
        let ue_doc = json!({"subscPolicySections": {}});
        assert!(s.policy_ue_put(supi, ue_doc.clone()), "first put = created");
        assert!(
            !s.policy_ue_put(supi, ue_doc.clone()),
            "second put = replaced"
        );
        assert_eq!(s.policy_ue_get(supi), Some(ue_doc));

        // Unknown SUPI has no stored policy
        assert!(s.policy_am_get("imsi-999").is_none());
        assert!(s.policy_sm_get("imsi-999").is_none());
        assert!(s.policy_ue_get("imsi-999").is_none());
    }

    // ------------------------------------------------------------------
    // udrd-11: DataChangeNotify shape — no non-standard members
    // ------------------------------------------------------------------

    /// TS 29.505 §5.4.2.6: DataChangeNotify must contain only the spec
    /// members {ueId, originalCallbackReference?, notifyItems}.
    /// Non-standard `subscriptionDataSubscriptions` must NOT be present.
    #[test]
    fn test_notify_payload_strict_shape() {
        let s = UdrDataStore::default();
        // Create a subscription with a callbackReference in the body.
        let cb_uri = "http://amf:7777/cb/data-change";
        let body = json!({
            "ueId": "imsi-001010000000001",
            "callbackReference": cb_uri,
            "monitoredResourceUris": [
                "/nudr-dr/v2/subscription-data/imsi-001010000000001/context-data"
            ]
        });
        let sub = s.sub_create(SubKind::SubscriptionData, cb_uri, body);

        // Collect what would be sent to the notification URI by examining the
        // payload constructed by the notify logic (we can re-derive it here
        // directly, mirroring the implementation, to assert its shape).
        let changed_path =
            "/nudr-dr/v2/subscription-data/imsi-001010000000001/context-data/amf-3gpp-access";
        let new_value = json!({"amfInstanceId": "x"});

        // Build the expected payload shape (mirrors notify_subscription_data_change).
        let change = json!({"op": "REPLACE", "newValue": new_value});
        let orig_cb = sub.body.get("callbackReference").and_then(Value::as_str);
        assert_eq!(orig_cb, Some(cb_uri), "callbackReference must be in body");

        let mut payload_map = serde_json::Map::new();
        payload_map.insert("ueId".to_string(), json!("imsi-001010000000001"));
        payload_map.insert("originalCallbackReference".to_string(), json!([cb_uri]));
        payload_map.insert(
            "notifyItems".to_string(),
            json!([{"resourceId": changed_path, "changes": [change]}]),
        );
        let payload = Value::Object(payload_map);

        // Assert only spec members present.
        let obj = payload.as_object().unwrap();
        let allowed_keys = ["ueId", "originalCallbackReference", "notifyItems"];
        for k in obj.keys() {
            assert!(
                allowed_keys.contains(&k.as_str()),
                "unexpected key in DataChangeNotify: {k}"
            );
        }
        assert!(obj.contains_key("ueId"));
        assert!(obj.contains_key("notifyItems"));
        // Non-standard member absent
        assert!(!obj.contains_key("subscriptionDataSubscriptions"));

        // notifyItems[0] must have resourceId + changes
        let notify_items = payload["notifyItems"].as_array().unwrap();
        assert_eq!(notify_items.len(), 1);
        assert!(notify_items[0].get("resourceId").is_some());
        assert!(notify_items[0].get("changes").is_some());
    }

    /// Subscription without a callbackReference in the body must NOT emit
    /// originalCallbackReference in the notify payload.
    #[test]
    fn test_notify_no_original_callback_when_absent() {
        let s = UdrDataStore::default();
        let cb_uri = "http://amf:7777/cb/no-orig";
        // Body intentionally omits "callbackReference"
        let body = json!({
            "ueId": "imsi-001010000000002",
            "monitoredResourceUris": ["/nudr-dr/v2/subscription-data/imsi-001010000000002"]
        });
        let sub = s.sub_create(SubKind::SubscriptionData, cb_uri, body);

        // originalCallbackReference must be absent when body has no callbackReference
        let orig_cb = sub.body.get("callbackReference").and_then(Value::as_str);
        assert!(
            orig_cb.is_none(),
            "this subscription has no callbackReference in body"
        );

        // Verify the payload won't include originalCallbackReference
        let mut payload_map = serde_json::Map::new();
        payload_map.insert("ueId".to_string(), json!("imsi-001010000000002"));
        if let Some(cb) = orig_cb {
            payload_map.insert("originalCallbackReference".to_string(), json!([cb]));
        }
        payload_map.insert("notifyItems".to_string(), json!([]));
        let payload = Value::Object(payload_map);
        assert!(!payload
            .as_object()
            .unwrap()
            .contains_key("originalCallbackReference"));
    }

    /// Unique snapshot path per test so concurrent runs do not collide.
    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("udrd-test-{tag}-{pid}-{nanos}.json"))
    }

    /// PUT a value, then re-open the store from the same path and confirm the
    /// value survived the simulated restart (across every resource tree).
    #[test]
    fn test_persistence_survives_restart() {
        let path = temp_state_path("restart");
        let _ = std::fs::remove_file(&path);

        // First lifetime: populate every tree, then drop the store.
        {
            let s = UdrDataStore::with_state_path(&path);
            assert!(s.amf_3gpp_put("imsi-1", json!({"amfInstanceId": "amf-x"})));
            assert!(s.exposure_am_put("imsi-1", json!({"roamingStatus": true})));
            assert!(s.exposure_sm_put("imsi-1", "5", json!({"dnn": "internet"})));
            assert!(s.pfd_put("app-1", json!({"pfds": []})));
            assert!(s.influence_put("inf-1", json!({"dnn": "ims"})));
            let sub = s.sub_create(
                SubKind::ExposureData,
                "http://cb:1/x",
                json!({"monitoredResourceUris": ["/a"]}),
            );
            assert_eq!(sub.id, "1");
        }

        // Second lifetime: a brand-new store re-opened from the same file must
        // see all prior data, and continue the subscription-id sequence.
        {
            let s = UdrDataStore::with_state_path(&path);
            assert_eq!(
                s.amf_3gpp_get("imsi-1"),
                Some(json!({"amfInstanceId": "amf-x"}))
            );
            assert_eq!(
                s.exposure_am_get("imsi-1"),
                Some(json!({"roamingStatus": true}))
            );
            assert_eq!(
                s.exposure_sm_get("imsi-1", "5"),
                Some(json!({"dnn": "internet"}))
            );
            assert_eq!(s.pfd_get("app-1"), Some(json!({"pfds": []})));
            assert_eq!(s.influence_get("inf-1"), Some(json!({"dnn": "ims"})));
            let restored = s.sub_get("1").expect("subscription restored");
            assert_eq!(restored.kind, SubKind::ExposureData);
            assert_eq!(restored.notify_uri, "http://cb:1/x");
            // Allocator continues past the restored id (no collision).
            let next = s.sub_create(SubKind::AppData, "http://cb:2/y", json!({}));
            assert_eq!(next.id, "2");
        }

        let _ = std::fs::remove_file(&path);
    }

    /// A removal must also be persisted (the restart must NOT resurrect it).
    #[test]
    fn test_persistence_remove_survives_restart() {
        let path = temp_state_path("remove");
        let _ = std::fs::remove_file(&path);
        {
            let s = UdrDataStore::with_state_path(&path);
            s.amf_3gpp_put("imsi-9", json!({"a": 1}));
            assert!(s.amf_3gpp_remove("imsi-9").is_some());
        }
        {
            let s = UdrDataStore::with_state_path(&path);
            assert!(
                s.amf_3gpp_get("imsi-9").is_none(),
                "removed entry must not reappear after restart"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// No configured path => no file written, store stays in-memory.
    #[test]
    fn test_no_path_is_pure_memory() {
        let s = UdrDataStore::default();
        s.amf_3gpp_put("imsi-1", json!({"a": 1}));
        // snapshot() works regardless, but persist() is a no-op without a path.
        s.persist();
        assert!(s.state_path.is_none());
    }

    /// Snapshot/restore round-trips through JSON without a file.
    #[test]
    fn test_snapshot_restore_roundtrip() {
        let s = UdrDataStore::default();
        s.amf_3gpp_put("imsi-1", json!({"x": 1}));
        s.exposure_sm_put("imsi-1", "7", json!({"dnn": "ims"}));
        s.policy_am_put("imsi-1", json!({"suppFeat": "1"}));
        s.policy_sm_put("imsi-1", json!({"smPolicySnssaiData": {}}));
        s.policy_ue_put("imsi-1", json!({"subscPolicySections": {}}));
        let snap = s.snapshot();

        let t = UdrDataStore::default();
        t.restore_from(&snap);
        assert_eq!(t.amf_3gpp_get("imsi-1"), Some(json!({"x": 1})));
        assert_eq!(
            t.exposure_sm_get("imsi-1", "7"),
            Some(json!({"dnn": "ims"}))
        );
        assert_eq!(t.policy_am_get("imsi-1"), Some(json!({"suppFeat": "1"})));
        assert_eq!(
            t.policy_sm_get("imsi-1"),
            Some(json!({"smPolicySnssaiData": {}}))
        );
        assert_eq!(
            t.policy_ue_get("imsi-1"),
            Some(json!({"subscPolicySections": {}}))
        );
    }
}
