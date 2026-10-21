//! UCMF dictionary, subscriptions and provisionings (TS 23.501 §5.4.4.1a,
//! TS 29.673, TS 29.675).
//!
//! Pure state and rules, no HTTP: the SBI layer in `main.rs` maps requests onto
//! these calls and these results onto responses. A `Ucmf` is an ordinary value,
//! so every test builds its own and none shares process-wide state.

use crate::racs_id::{RacsId, MAX_RCI};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use nextgcore_core::state_store::{Loaded, StateStore};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// TS 29.673 §6.1.6.3.4 `RacFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RacFormat {
    /// TS 38.331 format.
    FiveGs,
    /// TS 36.331 format.
    Eps,
}

impl RacFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "5GS" => Some(Self::FiveGs),
            "EPS" => Some(Self::Eps),
            _ => None,
        }
    }
}

/// TS 23.501 §5.4.4.1a NG-RAN / UCMF mode of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeOfOperation {
    /// RAN provides both formats; the UCMF need not transcode.
    A,
    /// RAN provides the TS 38.331 format only.
    B,
}

/// UE radio capability information in each format the UCMF may hold
/// (TS 23.501 §5.4.4.1a: capability and capability-for-paging, NR and E-UTRA).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub cap_5gs: Option<Vec<u8>>,
    pub cap_eps: Option<Vec<u8>>,
    pub paging_5gs: Option<Vec<u8>>,
    pub paging_eps: Option<Vec<u8>>,
}

impl Capabilities {
    fn has_any(&self) -> bool {
        self.cap_5gs.is_some() || self.cap_eps.is_some()
    }

    /// The provided formats agree with `stored`, and at least one was provided.
    fn matches(&self, stored: &Capabilities) -> bool {
        let agrees = |p: &Option<Vec<u8>>, s: &Option<Vec<u8>>| p.is_none() || p == s;
        self.has_any()
            && agrees(&self.cap_5gs, &stored.cap_5gs)
            && agrees(&self.cap_eps, &stored.cap_eps)
    }

    /// Fill formats `stored` lacks from `self` (never overwrite stored bytes).
    fn fill_missing_into(&self, stored: &mut Capabilities) {
        for (p, s) in [
            (&self.cap_5gs, &mut stored.cap_5gs),
            (&self.cap_eps, &mut stored.cap_eps),
            (&self.paging_5gs, &mut stored.paging_5gs),
            (&self.paging_eps, &mut stored.paging_eps),
        ] {
            if s.is_none() {
                s.clone_from(p);
            }
        }
    }
}

/// One dictionary entry (TS 29.673 `DicEntryData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DicEntry {
    pub id: u32,
    /// TS 29.571 `TypeAllocationCode`s associated to the entry. The first is the
    /// one `DicEntryData.typeAllocationCode` reports.
    pub tacs: Vec<String>,
    pub plmn_id: Option<RacsId>,
    pub man_id: Option<RacsId>,
    pub caps: Capabilities,
    /// The Nucmf_Provisioning resource that created this entry, if any.
    pub provisioning_id: Option<String>,
}

/// A Nucmf_UECapabilityManagement subscription (TS 29.673 §5.2.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub nf_id: Option<String>,
    pub notification_uri: String,
    pub expires: Option<DateTime<Utc>>,
}

/// An "Individual UE radio capability provisioning" (TS 29.675 §5.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioning {
    pub id: String,
    /// Successfully provisioned RACS configurations, keyed by RACS ID, exactly
    /// as the consumer sent them (TS 29.122 `RacsConfiguration`).
    pub configs: Map<String, Value>,
    pub supp_feat: Option<String>,
}

/// TS 29.122 Table 5.16.2.2.3-1 `RacsFailureCode`.
pub const RACS_ID_DUPLICATED: &str = "RACS_ID_DUPLICATED";
pub const RACS_OTHER_REASON: &str = "OTHER_REASON";

/// Resolve failures (TS 29.673 Table 6.1.7.3-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `NO_DICTIONARY_ENTRY_FOUND`.
    NotFound,
    /// `OUT_DATED_VERSION_ID_IN_RAC_ID` (TS 23.501 §5.4.4.1a).
    OutdatedVersionId,
    /// The entry exists but not in the requested format, and this UCMF does not
    /// transcode between TS 36.331 and TS 38.331 (see the module gaps note in
    /// `main.rs`).
    FormatNotStored,
}

/// Assign failures (TS 29.673 §5.2.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignError {
    BadTac,
    NoCapability,
    /// Mode A: both formats are required unless the input matches an entry.
    ModeARequiresBothFormats,
    /// The 11-digit RCI space for the current Version ID is used up.
    IdSpaceExhausted,
}

/// A notification to deliver to every active subscriber (TS 29.673 §5.2.2.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub uris: Vec<String>,
    pub body: Value,
}

/// The default and maximum subscription lifetime this UCMF grants.
pub const MAX_SUBSCRIPTION_LIFETIME_SECS: i64 = 24 * 3600;
/// Up to this much is taken off each granted expiry, varying per subscription,
/// so many subscriptions never expire together (TS 29.673 §5.2.2.4.1).
const EXPIRY_SPREAD_SECS: i64 = 600;

pub struct Ucmf {
    version_id: u8,
    mode: ModeOfOperation,
    next_entry_id: u32,
    next_rci: u64,
    entries: BTreeMap<u32, DicEntry>,
    subscriptions: BTreeMap<String, Subscription>,
    next_sub_seq: u64,
    provisionings: BTreeMap<String, Provisioning>,
    next_prov_seq: u64,
    store: StateStore,
}

impl Ucmf {
    pub fn new(version_id: u8, mode: ModeOfOperation) -> Self {
        Self {
            version_id,
            mode,
            next_entry_id: 1,
            next_rci: 0,
            entries: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            next_sub_seq: 1,
            provisionings: BTreeMap::new(),
            next_prov_seq: 1,
            store: StateStore::disabled(),
        }
    }

    pub fn version_id(&self) -> u8 {
        self.version_id
    }

    pub fn mode(&self) -> ModeOfOperation {
        self.mode
    }

    /// The highest Dictionary Entry ID allocated so far, 0 when none. IDs are
    /// allocated in increasing order (TS 29.673 §5.2.2.4.1 NOTE).
    pub fn highest_entry_id(&self) -> u32 {
        self.next_entry_id.saturating_sub(1)
    }

    pub fn entry(&self, id: u32) -> Option<&DicEntry> {
        self.entries.get(&id)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    // ---------------------------------------------------------------- Resolve

    /// TS 29.673 §5.2.2.2.1: find the entry for a UE radio capability ID.
    pub fn resolve(
        &self,
        id: &RacsId,
        format: Option<RacFormat>,
    ) -> Result<&DicEntry, ResolveError> {
        if let RacsId::PlmnAssigned { version_id, .. } = id {
            // TS 23.501 §5.4.4.1a: an old Version ID is an error even if an
            // entry with that ID still exists.
            if *version_id != self.version_id {
                return Err(ResolveError::OutdatedVersionId);
            }
        }
        let entry = self
            .entries
            .values()
            .find(|e| e.plmn_id.as_ref() == Some(id) || e.man_id.as_ref() == Some(id))
            .ok_or(ResolveError::NotFound)?;
        Self::check_format(entry, format)?;
        Ok(entry)
    }

    /// TS 29.673 §5.2.2.2.2: an entry by its Dictionary Entry ID.
    pub fn get_entry(&self, id: u32, format: Option<RacFormat>) -> Result<&DicEntry, ResolveError> {
        let entry = self.entries.get(&id).ok_or(ResolveError::NotFound)?;
        Self::check_format(entry, format)?;
        Ok(entry)
    }

    fn check_format(entry: &DicEntry, format: Option<RacFormat>) -> Result<(), ResolveError> {
        let stored = match format {
            Some(RacFormat::FiveGs) => entry.caps.cap_5gs.is_some(),
            Some(RacFormat::Eps) => entry.caps.cap_eps.is_some(),
            None => true,
        };
        if stored {
            Ok(())
        } else {
            Err(ResolveError::FormatNotStored)
        }
    }

    // ----------------------------------------------------------------- Assign

    /// TS 29.673 §5.2.2.3 / TS 23.502 §5.2.18.3.2: obtain a PLMN-assigned ID for
    /// a UE's capability. Returns the entry ID, the ID, and the notification to
    /// send when a new entry was created.
    pub fn assign(
        &mut self,
        tac: &str,
        caps: Capabilities,
        now: DateTime<Utc>,
    ) -> Result<(u32, RacsId, Option<Notification>), AssignError> {
        if !is_tac(tac) {
            return Err(AssignError::BadTac);
        }
        if !caps.has_any() {
            return Err(AssignError::NoCapability);
        }
        let matched = self
            .entries
            .values()
            .find(|e| e.tacs.iter().any(|t| t == tac) && caps.matches(&e.caps))
            .map(|e| e.id);

        if let Some(entry_id) = matched {
            let current = self.version_id;
            let existing = self.entries[&entry_id].plmn_id;
            let id = match existing {
                Some(id @ RacsId::PlmnAssigned { version_id, .. }) if version_id == current => id,
                // No PLMN-assigned ID yet (a provisioned manufacturer entry), or
                // one under an old Version ID: assign a current one.
                _ => self.allocate_plmn_id()?,
            };
            if let Some(e) = self.entries.get_mut(&entry_id) {
                e.plmn_id = Some(id);
                caps.fill_missing_into(&mut e.caps);
            }
            self.persist();
            return Ok((entry_id, id, None));
        }

        if self.mode == ModeOfOperation::A && !(caps.cap_5gs.is_some() && caps.cap_eps.is_some()) {
            return Err(AssignError::ModeARequiresBothFormats);
        }
        let id = self.allocate_plmn_id()?;
        let entry_id = self.allocate_entry_id();
        self.entries.insert(
            entry_id,
            DicEntry {
                id: entry_id,
                tacs: vec![tac.to_string()],
                plmn_id: Some(id),
                man_id: None,
                caps,
                provisioning_id: None,
            },
        );
        self.persist();
        Ok((entry_id, id, self.creation_notification(now)))
    }

    fn allocate_plmn_id(&mut self) -> Result<RacsId, AssignError> {
        if self.next_rci > MAX_RCI {
            return Err(AssignError::IdSpaceExhausted);
        }
        let id = RacsId::plmn_assigned(self.version_id, self.next_rci)
            .map_err(|_| AssignError::IdSpaceExhausted)?;
        self.next_rci += 1;
        Ok(id)
    }

    fn allocate_entry_id(&mut self) -> u32 {
        let id = self.next_entry_id;
        self.next_entry_id = self.next_entry_id.saturating_add(1);
        id
    }

    fn creation_notification(&mut self, now: DateTime<Utc>) -> Option<Notification> {
        self.notification(
            now,
            json!({
                "dicEntryId": self.highest_entry_id(),
                "eventType": "CREATION_OF_DICTIONARY_ENTRY",
            }),
        )
    }

    fn notification(&mut self, now: DateTime<Utc>, body: Value) -> Option<Notification> {
        let uris = self.active_notification_uris(now);
        (!uris.is_empty()).then_some(Notification { uris, body })
    }

    // ------------------------------------------------------------- Version ID

    /// Install a new Version ID (operator configuration). PLMN-assigned IDs
    /// under the old Version ID stop resolving (TS 23.501 §5.4.4.1a). Returns
    /// the `NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs` notification when it changed.
    pub fn set_version_id(&mut self, version_id: u8, now: DateTime<Utc>) -> Option<Notification> {
        if version_id == self.version_id {
            return None;
        }
        self.version_id = version_id;
        self.persist();
        self.notification(
            now,
            json!({
                "dicEntryId": self.highest_entry_id(),
                "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
                "versionId": version_id,
            }),
        )
    }

    /// Delete every PLMN-assigned ID that is not under the current Version ID,
    /// notifying `DELETION_OF_PLMN_ASSIGNED_IDS` with the complete list.
    /// Entries left with neither ID are removed.
    pub fn purge_outdated_plmn_ids(&mut self, now: DateTime<Utc>) -> Option<Notification> {
        let current = self.version_id;
        let mut deleted = Vec::new();
        for e in self.entries.values_mut() {
            if let Some(id @ RacsId::PlmnAssigned { version_id, .. }) = e.plmn_id {
                if version_id != current {
                    deleted.push(id.to_nucmf());
                    e.plmn_id = None;
                }
            }
        }
        if deleted.is_empty() {
            return None;
        }
        self.entries
            .retain(|_, e| e.plmn_id.is_some() || e.man_id.is_some());
        self.persist();
        self.notification(
            now,
            json!({
                "dicEntryId": self.highest_entry_id(),
                "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
                "manAssOpRequestlist": { "plmnAssiUeRadioCapId": deleted },
            }),
        )
    }

    // ---------------------------------------------------------- Subscriptions

    /// TS 29.673 §5.2.2.4: create a subscription, granting an expiry no later
    /// than both the consumer's hint and this UCMF's maximum lifetime.
    pub fn subscribe(
        &mut self,
        nf_id: Option<String>,
        notification_uri: String,
        suggested: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Subscription {
        self.purge_expired(now);
        let seq = self.next_sub_seq;
        self.next_sub_seq += 1;
        // Deterministic per-subscription spread, so consecutive subscriptions
        // never share an expiry.
        let spread = ChronoDuration::seconds(((seq as i64) * 37) % EXPIRY_SPREAD_SECS);
        let ceiling = now + ChronoDuration::seconds(MAX_SUBSCRIPTION_LIFETIME_SECS) - spread;
        let expires = match suggested {
            Some(s) if s < ceiling => s,
            _ => ceiling,
        };
        let sub = Subscription {
            id: seq.to_string(),
            nf_id,
            notification_uri,
            expires: Some(expires),
        };
        self.subscriptions.insert(sub.id.clone(), sub.clone());
        self.persist();
        sub
    }

    /// TS 29.673 §5.2.2.5. `false` when no such subscription exists.
    pub fn unsubscribe(&mut self, id: &str) -> bool {
        let removed = self.subscriptions.remove(id).is_some();
        if removed {
            self.persist();
        }
        removed
    }

    pub fn subscription(&self, id: &str) -> Option<&Subscription> {
        self.subscriptions.get(id)
    }

    fn purge_expired(&mut self, now: DateTime<Utc>) {
        let before = self.subscriptions.len();
        self.subscriptions
            .retain(|_, s| s.expires.is_none_or(|e| e > now));
        if self.subscriptions.len() != before {
            self.persist();
        }
    }

    fn active_notification_uris(&mut self, now: DateTime<Utc>) -> Vec<String> {
        self.purge_expired(now);
        self.subscriptions
            .values()
            .map(|s| s.notification_uri.clone())
            .collect()
    }

    // ----------------------------------------------------------- Provisioning

    /// TS 29.675 §5.2.2.2: provision manufacturer-assigned dictionary entries.
    /// Returns the new resource (when at least one RACS ID was provisioned),
    /// the per-RACS-ID failure reports, and the creation notification.
    pub fn create_provisioning(
        &mut self,
        racs_configs: &Map<String, Value>,
        supp_feat: Option<String>,
        now: DateTime<Utc>,
    ) -> (
        Option<Provisioning>,
        Vec<(String, &'static str)>,
        Option<Notification>,
    ) {
        let prov_id = self.next_prov_seq.to_string();
        let (ok, failed) = self.provision_entries(&prov_id, racs_configs, None);
        if ok.is_empty() {
            return (None, failed, None);
        }
        self.next_prov_seq += 1;
        let prov = Provisioning {
            id: prov_id,
            configs: ok,
            supp_feat,
        };
        self.provisionings.insert(prov.id.clone(), prov.clone());
        self.persist();
        let note = self.creation_notification(now);
        (Some(prov), failed, note)
    }

    pub fn provisioning(&self, id: &str) -> Option<&Provisioning> {
        self.provisionings.get(id)
    }

    /// TS 29.675 §5.2.2.3 (PUT): replace a provisioning's RACS configurations.
    /// `None` when no such resource; `Err(reports)` when nothing in the new
    /// set could be provisioned, in which case the resource is left unchanged.
    #[allow(clippy::type_complexity)]
    pub fn replace_provisioning(
        &mut self,
        id: &str,
        racs_configs: &Map<String, Value>,
        supp_feat: Option<String>,
        now: DateTime<Utc>,
    ) -> Option<
        Result<
            (
                Provisioning,
                Vec<(String, &'static str)>,
                Option<Notification>,
            ),
            Vec<(String, &'static str)>,
        >,
    > {
        self.provisionings.get(id)?;
        let removed: Vec<DicEntry> = self.take_entries_of(id);
        let (ok, failed) = self.provision_entries(id, racs_configs, Some(id));
        if ok.is_empty() {
            // Put the previous entries back: a failed replace changes nothing.
            for e in removed {
                self.entries.insert(e.id, e);
            }
            return Some(Err(failed));
        }
        let prov = Provisioning {
            id: id.to_string(),
            configs: ok,
            supp_feat,
        };
        self.provisionings.insert(prov.id.clone(), prov.clone());
        self.persist();
        let note = self.creation_notification(now);
        Some(Ok((prov, failed, note)))
    }

    /// TS 29.675 §5.2.2.3 (PATCH, RFC 7396): merge `RacsDataPatch.racsConfigs`
    /// into the stored configurations — `null` removes a RACS ID, an object is
    /// merged into (or adds) it — then re-provision.
    #[allow(clippy::type_complexity)]
    pub fn patch_provisioning(
        &mut self,
        id: &str,
        patch: &Map<String, Value>,
        now: DateTime<Utc>,
    ) -> Option<
        Result<
            (
                Provisioning,
                Vec<(String, &'static str)>,
                Option<Notification>,
            ),
            Vec<(String, &'static str)>,
        >,
    > {
        let current = self.provisionings.get(id)?.clone();
        let mut merged = current.configs.clone();
        for (racs_id, change) in patch {
            match change {
                Value::Null => {
                    merged.remove(racs_id);
                }
                Value::Object(_) => {
                    let mut base = merged.get(racs_id).cloned().unwrap_or_else(|| json!({}));
                    merge_patch(&mut base, change);
                    merged.insert(racs_id.clone(), base);
                }
                _ => {
                    return Some(Err(vec![(racs_id.clone(), RACS_OTHER_REASON)]));
                }
            }
        }
        self.replace_provisioning(id, &merged, current.supp_feat, now)
    }

    /// TS 29.675 §5.2.2.4. `false` when no such resource.
    pub fn delete_provisioning(&mut self, id: &str) -> bool {
        if self.provisionings.remove(id).is_none() {
            return false;
        }
        let _ = self.take_entries_of(id);
        self.persist();
        true
    }

    fn take_entries_of(&mut self, prov_id: &str) -> Vec<DicEntry> {
        let ids: Vec<u32> = self
            .entries
            .values()
            .filter(|e| e.provisioning_id.as_deref() == Some(prov_id))
            .map(|e| e.id)
            .collect();
        ids.into_iter()
            .filter_map(|i| self.entries.remove(&i))
            .collect()
    }

    /// Create one entry per valid RACS configuration. A RACS ID already in the
    /// dictionary is `RACS_ID_DUPLICATED` (TS 29.675 §5.2.2.2.2); an unusable
    /// key or configuration is `OTHER_REASON`.
    fn provision_entries(
        &mut self,
        prov_id: &str,
        racs_configs: &Map<String, Value>,
        _replacing: Option<&str>,
    ) -> (Map<String, Value>, Vec<(String, &'static str)>) {
        let mut ok = Map::new();
        let mut failed = Vec::new();
        for (racs_key, config) in racs_configs {
            let Ok(man_id @ RacsId::ManufacturerAssigned { .. }) = RacsId::from_digit_str(racs_key)
            else {
                failed.push((racs_key.clone(), RACS_OTHER_REASON));
                continue;
            };
            let Some((tacs, caps)) = parse_racs_configuration(config) else {
                failed.push((racs_key.clone(), RACS_OTHER_REASON));
                continue;
            };
            if self.entries.values().any(|e| e.man_id == Some(man_id)) {
                failed.push((racs_key.clone(), RACS_ID_DUPLICATED));
                continue;
            }
            let entry_id = self.allocate_entry_id();
            self.entries.insert(
                entry_id,
                DicEntry {
                    id: entry_id,
                    tacs,
                    plmn_id: None,
                    man_id: Some(man_id),
                    caps,
                    provisioning_id: Some(prov_id.to_string()),
                },
            );
            ok.insert(racs_key.clone(), config.clone());
        }
        (ok, failed)
    }

    // ------------------------------------------------------------ Persistence

    /// Back this UCMF with a snapshot file and load it. A configured Version ID
    /// that differs from the stored one is applied by the caller afterwards
    /// with [`Ucmf::set_version_id`], so subscribers are told.
    pub fn attach_store(&mut self, path: Option<PathBuf>) -> Result<bool, String> {
        self.store = StateStore::new(path);
        match self.store.load() {
            Ok(Loaded::Absent) => Ok(false),
            Ok(Loaded::Snapshot(doc)) => {
                self.restore(&doc);
                Ok(true)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn persist(&self) {
        if let Err(e) = self.store.persist(&self.snapshot()) {
            log::error!("UCMF state not persisted: {e}");
        }
    }

    pub fn snapshot(&self) -> Value {
        let opt_b64 = |b: &Option<Vec<u8>>| b.as_ref().map(|v| B64.encode(v));
        json!({
            "versionId": self.version_id,
            "nextEntryId": self.next_entry_id,
            "nextRci": self.next_rci,
            "nextSubSeq": self.next_sub_seq,
            "nextProvSeq": self.next_prov_seq,
            "entries": self.entries.values().map(|e| json!({
                "id": e.id,
                "tacs": e.tacs,
                "plmnId": e.plmn_id.map(|i| i.to_nucmf()),
                "manId": e.man_id.map(|i| i.to_nucmf()),
                "cap5gs": opt_b64(&e.caps.cap_5gs),
                "capEps": opt_b64(&e.caps.cap_eps),
                "paging5gs": opt_b64(&e.caps.paging_5gs),
                "pagingEps": opt_b64(&e.caps.paging_eps),
                "provisioningId": e.provisioning_id,
            })).collect::<Vec<_>>(),
            "subscriptions": self.subscriptions.values().map(|s| json!({
                "id": s.id,
                "nfId": s.nf_id,
                "uri": s.notification_uri,
                "expires": s.expires.map(|t| t.to_rfc3339()),
            })).collect::<Vec<_>>(),
            "provisionings": self.provisionings.values().map(|p| json!({
                "id": p.id,
                "configs": p.configs,
                "suppFeat": p.supp_feat,
            })).collect::<Vec<_>>(),
        })
    }

    fn restore(&mut self, doc: &Value) {
        let u64_of = |k: &str| doc.get(k).and_then(Value::as_u64);
        if let Some(v) = u64_of("versionId") {
            self.version_id = v as u8;
        }
        if let Some(v) = u64_of("nextEntryId") {
            self.next_entry_id = v as u32;
        }
        if let Some(v) = u64_of("nextRci") {
            self.next_rci = v;
        }
        if let Some(v) = u64_of("nextSubSeq") {
            self.next_sub_seq = v;
        }
        if let Some(v) = u64_of("nextProvSeq") {
            self.next_prov_seq = v;
        }
        let b64 = |v: &Value, k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .and_then(|s| B64.decode(s).ok())
        };
        let id = |v: &Value, k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .and_then(|s| RacsId::from_nucmf(s).ok())
        };
        for e in doc
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(entry_id) = e.get("id").and_then(Value::as_u64) else {
                continue;
            };
            let tacs = e
                .get("tacs")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            self.entries.insert(
                entry_id as u32,
                DicEntry {
                    id: entry_id as u32,
                    tacs,
                    plmn_id: id(e, "plmnId"),
                    man_id: id(e, "manId"),
                    caps: Capabilities {
                        cap_5gs: b64(e, "cap5gs"),
                        cap_eps: b64(e, "capEps"),
                        paging_5gs: b64(e, "paging5gs"),
                        paging_eps: b64(e, "pagingEps"),
                    },
                    provisioning_id: e
                        .get("provisioningId")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                },
            );
        }
        for s in doc
            .get("subscriptions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(sid), Some(uri)) = (
                s.get("id").and_then(Value::as_str),
                s.get("uri").and_then(Value::as_str),
            ) else {
                continue;
            };
            self.subscriptions.insert(
                sid.to_string(),
                Subscription {
                    id: sid.to_string(),
                    nf_id: s.get("nfId").and_then(Value::as_str).map(str::to_string),
                    notification_uri: uri.to_string(),
                    expires: s
                        .get("expires")
                        .and_then(Value::as_str)
                        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.with_timezone(&Utc)),
                },
            );
        }
        for p in doc
            .get("provisionings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(pid) = p.get("id").and_then(Value::as_str) else {
                continue;
            };
            self.provisionings.insert(
                pid.to_string(),
                Provisioning {
                    id: pid.to_string(),
                    configs: p
                        .get("configs")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                    supp_feat: p
                        .get("suppFeat")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                },
            );
        }
    }
}

/// TS 29.571 `TypeAllocationCode`: `^[0-9]{8}$`.
pub fn is_tac(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())
}

/// TS 29.122 `RacsConfiguration`: `imeiTacs` (at least one TAC) and the
/// capability in `racsParamEps` and/or `racsParam5Gs`. The parameters are
/// taken as hexadecimal octet strings (see the module gaps note in `main.rs`).
fn parse_racs_configuration(config: &Value) -> Option<(Vec<String>, Capabilities)> {
    let tacs: Vec<String> = config
        .get("imeiTacs")?
        .as_array()?
        .iter()
        .map(|t| t.as_str().filter(|s| is_tac(s)).map(str::to_string))
        .collect::<Option<Vec<_>>>()?;
    if tacs.is_empty() {
        return None;
    }
    let param = |k: &str| -> Option<Option<Vec<u8>>> {
        match config.get(k) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(s)) => decode_hex(s).map(Some),
            Some(_) => None,
        }
    };
    let caps = Capabilities {
        cap_eps: param("racsParamEps")?,
        cap_5gs: param("racsParam5Gs")?,
        paging_5gs: None,
        paging_eps: None,
    };
    caps.has_any().then_some((tacs, caps))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// RFC 7396 JSON merge patch.
fn merge_patch(target: &mut Value, patch: &Value) {
    if let Value::Object(p) = patch {
        if !target.is_object() {
            *target = json!({});
        }
        if let Value::Object(t) = target {
            for (k, v) in p {
                if v.is_null() {
                    t.remove(k);
                } else {
                    merge_patch(t.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
    } else {
        *target = patch.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-21T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn caps(nr: &[u8]) -> Capabilities {
        Capabilities {
            cap_5gs: Some(nr.to_vec()),
            ..Default::default()
        }
    }

    #[test]
    fn assign_gives_a_current_version_id_and_the_same_id_for_the_same_input() {
        let mut u = Ucmf::new(0x05, ModeOfOperation::B);
        let (e1, id1, _) = u.assign("35123456", caps(&[1, 2, 3]), now()).unwrap();
        assert_eq!(
            id1,
            RacsId::PlmnAssigned {
                version_id: 0x05,
                rci: 0
            }
        );
        // Same TAC + same capability → the already assigned ID (TS 29.673 §5.2.2.3 2a).
        let (e2, id2, note) = u.assign("35123456", caps(&[1, 2, 3]), now()).unwrap();
        assert_eq!((e2, id2), (e1, id1));
        assert!(note.is_none());
        // A different capability → a new entry and ID.
        let (e3, id3, _) = u.assign("35123456", caps(&[9]), now()).unwrap();
        assert_ne!(e3, e1);
        assert_eq!(
            id3,
            RacsId::PlmnAssigned {
                version_id: 0x05,
                rci: 1
            }
        );
        // The same capability under another TAC is another device model.
        let (e4, _, _) = u.assign("35999999", caps(&[1, 2, 3]), now()).unwrap();
        assert_ne!(e4, e1);
    }

    #[test]
    fn resolve_finds_by_either_id_and_refuses_an_outdated_version_id() {
        let mut u = Ucmf::new(0x05, ModeOfOperation::B);
        let (_, id, _) = u.assign("35123456", caps(&[1, 2, 3]), now()).unwrap();
        assert_eq!(
            u.resolve(&id, Some(RacFormat::FiveGs))
                .unwrap()
                .caps
                .cap_5gs,
            Some(vec![1, 2, 3])
        );
        // Not stored in EPS format, and this UCMF does not transcode.
        assert_eq!(
            u.resolve(&id, Some(RacFormat::Eps)),
            Err(ResolveError::FormatNotStored)
        );
        let unknown = RacsId::plmn_assigned(0x05, 77).unwrap();
        assert_eq!(u.resolve(&unknown, None), Err(ResolveError::NotFound));
        // TS 23.501 §5.4.4.1a: after a Version ID change the old ID is outdated
        // even though its entry still exists, and Assign hands out a new one.
        u.set_version_id(0x06, now());
        assert_eq!(u.resolve(&id, None), Err(ResolveError::OutdatedVersionId));
        let (_, fresh, _) = u.assign("35123456", caps(&[1, 2, 3]), now()).unwrap();
        assert!(matches!(
            fresh,
            RacsId::PlmnAssigned {
                version_id: 0x06,
                ..
            }
        ));
        assert!(u.resolve(&fresh, None).is_ok());
    }

    #[test]
    fn mode_a_requires_both_formats_unless_the_input_matches() {
        let mut u = Ucmf::new(1, ModeOfOperation::A);
        assert_eq!(
            u.assign("35123456", caps(&[1]), now()),
            Err(AssignError::ModeARequiresBothFormats)
        );
        let both = Capabilities {
            cap_5gs: Some(vec![1]),
            cap_eps: Some(vec![2]),
            ..Default::default()
        };
        let (_, id, _) = u.assign("35123456", both, now()).unwrap();
        // One format that matches the stored entry is accepted (§5.2.2.3 2b).
        let (_, again, _) = u.assign("35123456", caps(&[1]), now()).unwrap();
        assert_eq!(again, id);
    }

    #[test]
    fn assign_refuses_a_bad_tac_and_no_capability() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        assert_eq!(
            u.assign("3512345", caps(&[1]), now()),
            Err(AssignError::BadTac)
        );
        assert_eq!(
            u.assign("35123456", Capabilities::default(), now()),
            Err(AssignError::NoCapability)
        );
    }

    #[test]
    fn creation_is_notified_to_active_subscribers_with_the_highest_entry_id() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let sub = u.subscribe(None, "http://amf/notify".into(), None, now());
        assert!(
            sub.expires.unwrap() <= now() + ChronoDuration::seconds(MAX_SUBSCRIPTION_LIFETIME_SECS)
        );
        let (eid, _, note) = u.assign("35123456", caps(&[1]), now()).unwrap();
        let note = note.unwrap();
        assert_eq!(note.uris, ["http://amf/notify"]);
        assert_eq!(note.body["eventType"], "CREATION_OF_DICTIONARY_ENTRY");
        assert_eq!(note.body["dicEntryId"], eid);
        assert!(u.unsubscribe(&sub.id));
        assert!(!u.unsubscribe(&sub.id));
        let (_, _, none) = u.assign("35123456", caps(&[2]), now()).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn subscription_expiry_honours_the_hint_the_ceiling_and_lapses() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let hint = now() + ChronoDuration::seconds(60);
        assert_eq!(
            u.subscribe(None, "http://a/n".into(), Some(hint), now())
                .expires,
            Some(hint)
        );
        let far = now() + ChronoDuration::days(30);
        let a = u
            .subscribe(None, "http://b/n".into(), Some(far), now())
            .expires
            .unwrap();
        let b = u
            .subscribe(None, "http://c/n".into(), Some(far), now())
            .expires
            .unwrap();
        assert!(a < far && b < far);
        assert_ne!(a, b, "two subscriptions must not share an expiry");
        // After the hinted expiry the first subscriber is no longer notified.
        let later = now() + ChronoDuration::seconds(120);
        let (_, _, note) = u.assign("35123456", caps(&[1]), later).unwrap();
        assert_eq!(note.unwrap().uris.len(), 2);
    }

    #[test]
    fn version_change_and_purge_are_notified() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let (_, old, _) = u.assign("35123456", caps(&[1]), now()).unwrap();
        u.subscribe(None, "http://amf/n".into(), None, now());
        let v = u.set_version_id(2, now()).unwrap();
        assert_eq!(v.body["eventType"], "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs");
        assert_eq!(v.body["versionId"], 2);
        assert!(u.set_version_id(2, now()).is_none());
        let d = u.purge_outdated_plmn_ids(now()).unwrap();
        assert_eq!(d.body["eventType"], "DELETION_OF_PLMN_ASSIGNED_IDS");
        assert_eq!(
            d.body["manAssOpRequestlist"]["plmnAssiUeRadioCapId"],
            json!([old.to_nucmf()])
        );
        assert_eq!(
            u.entry_count(),
            0,
            "an entry with neither ID left is removed"
        );
    }

    fn racs(key: &str, nr_hex: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert(
            key.into(),
            json!({"imeiTacs": ["35123456"], "racsParam5Gs": nr_hex}),
        );
        m
    }

    const MAN: &str = "000007ed900000000abc";

    #[test]
    fn provisioning_creates_manufacturer_entries_and_reports_duplicates() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let (prov, failed, _) = u.create_provisioning(&racs(MAN, "0a0b"), None, now());
        let prov = prov.unwrap();
        assert!(failed.is_empty());
        let man = RacsId::from_digit_str(MAN).unwrap();
        assert_eq!(
            u.resolve(&man, Some(RacFormat::FiveGs))
                .unwrap()
                .caps
                .cap_5gs,
            Some(vec![0x0a, 0x0b])
        );
        // The same RACS ID again → RACS_ID_DUPLICATED, and no resource.
        let (none, failed, _) = u.create_provisioning(&racs(MAN, "0c"), None, now());
        assert!(none.is_none());
        assert_eq!(failed, [(MAN.to_string(), RACS_ID_DUPLICATED)]);
        // A key that is not a manufacturer-assigned ID → OTHER_REASON.
        let (_, failed, _) = u.create_provisioning(&racs("10500000000001", "0c"), None, now());
        assert_eq!(failed, [("10500000000001".to_string(), RACS_OTHER_REASON)]);
        // Assign over the provisioned entry adds a PLMN-assigned ID to it.
        let (eid, plmn, _) = u.assign("35123456", caps(&[0x0a, 0x0b]), now()).unwrap();
        assert_eq!(u.entry(eid).unwrap().man_id, Some(man));
        assert_eq!(u.entry(eid).unwrap().plmn_id, Some(plmn));
        assert!(u.delete_provisioning(&prov.id));
        assert!(u.resolve(&man, None).is_err());
        assert!(!u.delete_provisioning(&prov.id));
    }

    #[test]
    fn provisioning_patch_merges_and_null_removes() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let (prov, _, _) = u.create_provisioning(&racs(MAN, "0a"), None, now());
        let pid = prov.unwrap().id;
        let mut patch = Map::new();
        patch.insert(MAN.into(), json!({"racsParam5Gs": "ff"}));
        let (p, _, _) = u.patch_provisioning(&pid, &patch, now()).unwrap().unwrap();
        assert_eq!(p.configs[MAN]["racsParam5Gs"], "ff");
        assert_eq!(p.configs[MAN]["imeiTacs"], json!(["35123456"]));
        let man = RacsId::from_digit_str(MAN).unwrap();
        assert_eq!(
            u.resolve(&man, None).unwrap().caps.cap_5gs,
            Some(vec![0xff])
        );
        // Removing the only RACS ID leaves nothing to provision: refused, unchanged.
        let mut remove = Map::new();
        remove.insert(MAN.into(), Value::Null);
        assert!(u.patch_provisioning(&pid, &remove, now()).unwrap().is_err());
        assert!(u.resolve(&man, None).is_ok());
        assert!(u.patch_provisioning("nope", &remove, now()).is_none());
    }

    #[test]
    fn state_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("ucmf-state-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ucmf.json");
        let _ = std::fs::remove_file(&path);
        let (id, sub_id) = {
            let mut u = Ucmf::new(3, ModeOfOperation::B);
            assert_eq!(u.attach_store(Some(path.clone())), Ok(false));
            let (_, id, _) = u.assign("35123456", caps(&[7, 7]), now()).unwrap();
            let sub = u.subscribe(Some("nf-1".into()), "http://amf/n".into(), None, now());
            u.create_provisioning(&racs(MAN, "0a"), None, now());
            (id, sub.id)
        };
        let mut u = Ucmf::new(0, ModeOfOperation::B);
        assert_eq!(u.attach_store(Some(path.clone())), Ok(true));
        assert_eq!(u.version_id(), 3);
        assert_eq!(u.resolve(&id, None).unwrap().caps.cap_5gs, Some(vec![7, 7]));
        assert_eq!(
            u.subscription(&sub_id).unwrap().nf_id.as_deref(),
            Some("nf-1")
        );
        assert!(u
            .resolve(&RacsId::from_digit_str(MAN).unwrap(), None)
            .is_ok());
        // A new ID after restart does not reuse an RCI.
        let (_, next, _) = u.assign("35123456", caps(&[8]), now()).unwrap();
        assert_eq!(
            next,
            RacsId::PlmnAssigned {
                version_id: 3,
                rci: 1
            }
        );
        // A corrupt file is refused and not overwritten.
        std::fs::write(&path, "{not json").unwrap();
        let mut bad = Ucmf::new(3, ModeOfOperation::B);
        assert!(bad.attach_store(Some(path.clone())).is_err());
        let _ = bad.assign("35123456", caps(&[1]), now());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
