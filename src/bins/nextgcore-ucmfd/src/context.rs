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
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

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

    /// Fill what this capability lacks from what it has (TS 23.501 §5.4.4.1a, #585):
    /// the other format by transcoding between TS 38.331 and TS 36.331, then each
    /// format's UE radio capability for paging by deriving it from the full
    /// capability. Never overwrites bytes that were provided, and leaves a part
    /// absent when the bytes cannot be read as the format they claim to be (the
    /// failure is logged; Resolve then reports the format as not stored).
    pub fn complete(&mut self) {
        let log_err = |what: &str, e: crate::rac::RacError| {
            log::warn!("UE radio capability: {what} not derived: {e}");
        };
        if self.cap_eps.is_none() {
            if let Some(nr) = &self.cap_5gs {
                match crate::rac::transcode_5gs_to_eps(nr) {
                    Ok(eps) => self.cap_eps = Some(eps),
                    Err(e) => log_err("EPS format (TS 36.331)", e),
                }
            }
        }
        if self.cap_5gs.is_none() {
            if let Some(eps) = &self.cap_eps {
                match crate::rac::transcode_eps_to_5gs(eps) {
                    Ok(nr) => self.cap_5gs = Some(nr),
                    Err(e) => log_err("5GS format (TS 38.331)", e),
                }
            }
        }
        if self.paging_5gs.is_none() {
            if let Some(nr) = &self.cap_5gs {
                match crate::rac::derive_paging_5gs(nr) {
                    Ok(p) => self.paging_5gs = Some(p),
                    Err(e) => log_err("5GS capability for paging", e),
                }
            }
        }
        if self.paging_eps.is_none() {
            if let Some(eps) = &self.cap_eps {
                match crate::rac::derive_paging_eps(eps) {
                    Ok(p) => self.paging_eps = Some(p),
                    Err(e) => log_err("EPS capability for paging", e),
                }
            }
        }
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
    /// The entry exists but not in the requested format, and the format it has
    /// could not be transcoded to it (#585: the stored bytes are not a valid
    /// TS 36.331 / TS 38.331 capability, or carry no RAT the other format holds).
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
    /// The dictionary holds [`Limits::max_dic_entries`] entries (#786).
    DictionaryFull,
    /// The ID reservation could not be written to the state file, so no ID is
    /// handed out (#843 review): one handed out above what is on disk could be
    /// issued again after a restart.
    StateNotPersisted,
}

/// Subscribe failures (#786).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeError {
    /// [`Limits::max_subscriptions`] subscriptions are active.
    TooManySubscriptions,
    /// This consumer holds [`Limits::max_subscriptions_per_consumer`].
    TooManyForConsumer,
    /// The subscription ID counter is at the top of its range.
    IdSpaceExhausted,
    /// The ID reservation could not be written (#843 review).
    StateNotPersisted,
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

/// The dictionary entries with the indexes every lookup uses (#786): by UE radio
/// capability ID (Resolve, the provisioning duplicate check) and by TAC (Assign).
/// Before #786 each of those scanned every entry while holding the state write
/// lock, so the cost of a request grew with the dictionary.
///
/// Every change goes through [`Dictionary::insert`], [`Dictionary::remove`] or
/// [`Dictionary::set_plmn_id`], which keep the indexes in step with the entries.
#[derive(Default)]
struct Dictionary {
    entries: BTreeMap<u32, DicEntry>,
    by_racs_id: HashMap<RacsId, u32>,
    by_tac: HashMap<String, Vec<u32>>,
}

impl Dictionary {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, id: u32) -> Option<&DicEntry> {
        self.entries.get(&id)
    }

    fn values(&self) -> impl Iterator<Item = &DicEntry> {
        self.entries.values()
    }

    fn by_racs_id(&self, id: &RacsId) -> Option<&DicEntry> {
        self.by_racs_id.get(id).and_then(|e| self.entries.get(e))
    }

    fn with_tac<'a>(&'a self, tac: &str) -> impl Iterator<Item = &'a DicEntry> + 'a {
        self.by_tac
            .get(tac)
            .into_iter()
            .flatten()
            .filter_map(|e| self.entries.get(e))
    }

    fn insert(&mut self, entry: DicEntry) {
        if let Some(old) = self.remove(entry.id) {
            log::warn!("dictionary entry {} replaced", old.id);
        }
        for id in entry.plmn_id.iter().chain(entry.man_id.iter()) {
            self.by_racs_id.insert(*id, entry.id);
        }
        for tac in &entry.tacs {
            let ids = self.by_tac.entry(tac.clone()).or_default();
            if !ids.contains(&entry.id) {
                ids.push(entry.id);
            }
        }
        self.entries.insert(entry.id, entry);
    }

    fn remove(&mut self, id: u32) -> Option<DicEntry> {
        let entry = self.entries.remove(&id)?;
        for racs in entry.plmn_id.iter().chain(entry.man_id.iter()) {
            if self.by_racs_id.get(racs) == Some(&id) {
                self.by_racs_id.remove(racs);
            }
        }
        for tac in &entry.tacs {
            if let Some(ids) = self.by_tac.get_mut(tac) {
                ids.retain(|e| *e != id);
                if ids.is_empty() {
                    self.by_tac.remove(tac);
                }
            }
        }
        Some(entry)
    }

    /// Replace (or clear) an entry's PLMN-assigned ID, and its index.
    fn set_plmn_id(&mut self, id: u32, plmn_id: Option<RacsId>) {
        let Some(e) = self.entries.get_mut(&id) else {
            return;
        };
        if let Some(old) = e.plmn_id.take() {
            if self.by_racs_id.get(&old) == Some(&id) {
                self.by_racs_id.remove(&old);
            }
        }
        if let Some(new) = plmn_id {
            self.by_racs_id.insert(new, id);
        }
        e.plmn_id = plmn_id;
    }

    /// Every index entry points at an entry that has that key, and every key
    /// of every entry is indexed.
    #[cfg(test)]
    fn assert_consistent(&self) {
        let mut ids = 0;
        let mut tacs = 0;
        for e in self.entries.values() {
            for id in e.plmn_id.iter().chain(e.man_id.iter()) {
                assert_eq!(self.by_racs_id.get(id), Some(&e.id), "{id:?}");
                ids += 1;
            }
            for t in &e.tacs {
                assert!(self.by_tac[t].contains(&e.id), "{t}");
                tacs += 1;
            }
        }
        assert_eq!(self.by_racs_id.len(), ids, "stale ID index entries");
        assert_eq!(
            self.by_tac.values().map(Vec::len).sum::<usize>(),
            tacs,
            "stale TAC index entries"
        );
    }

    /// The entry's capabilities, for changes that touch no indexed field.
    fn caps_mut(&mut self, id: u32) -> Option<&mut Capabilities> {
        self.entries.get_mut(&id).map(|e| &mut e.caps)
    }
}

/// Capacity limits (#786). Assign, Subscribe and Provisioning are open to any
/// SBI peer that the OAuth2 policy admits, and that policy is off by default. So
/// the dictionary and the subscriptions are bounded, and the bound is reached
/// with an error rather than with memory exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Dictionary entries in total, assigned and provisioned.
    pub max_dic_entries: usize,
    /// Subscriptions in total.
    pub max_subscriptions: usize,
    /// Subscriptions per consumer, identified by `nfId` or else by the
    /// notification URI's authority.
    pub max_subscriptions_per_consumer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Each entry holds the full capability in both formats and both
            // paging forms. A UE-NR-Capability with band combinations runs to
            // tens of kB, so 10 000 entries can be a few hundred MB. That is
            // still well above the number of distinct (TAC, capability) pairs,
            // i.e. device models and software versions, a PLMN sees.
            max_dic_entries: 10_000,
            max_subscriptions: 10_000,
            max_subscriptions_per_consumer: 16,
        }
    }
}

pub struct Ucmf {
    version_id: u8,
    mode: ModeOfOperation,
    next_entry_id: u32,
    next_rci: u64,
    entries: Dictionary,
    limits: Limits,
    subscriptions: BTreeMap<String, Subscription>,
    next_sub_seq: u64,
    provisionings: BTreeMap<String, Provisioning>,
    next_prov_seq: u64,
    persister: Arc<Persister>,
    /// Bumped by every change; orders snapshot writes (#786).
    generation: u64,
    /// Write-behind (#786): changes mark the state dirty and a flusher writes
    /// it, instead of every change rewriting the whole snapshot under the lock.
    write_behind: bool,
    dirty: bool,
    /// In write-behind mode, the counter values the last written snapshot
    /// claims. IDs are handed out only below them, so a crash that loses the
    /// unflushed tail never makes a restarted UCMF hand out an ID again.
    reserved: Counters,
}

/// The four ID counters, as a snapshot stores them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counters {
    entry_id: u32,
    rci: u64,
    sub_seq: u64,
    prov_seq: u64,
}

/// How many IDs of each kind one synchronous reservation write covers (#786).
const ID_RESERVATION: u64 = 1024;

/// A snapshot's contents copied out of the state (#843 review), serialised by
/// [`SnapshotSource::to_json`] outside the state lock.
#[derive(Debug, Clone)]
pub struct SnapshotSource {
    version_id: u8,
    counters: Counters,
    entries: Vec<DicEntry>,
    subscriptions: Vec<Subscription>,
    provisionings: Vec<Provisioning>,
}

impl SnapshotSource {
    pub fn to_json(&self) -> Value {
        let opt_b64 = |b: &Option<Vec<u8>>| b.as_ref().map(|v| B64.encode(v));
        json!({
            "versionId": self.version_id,
            "nextEntryId": self.counters.entry_id,
            "nextRci": self.counters.rci,
            "nextSubSeq": self.counters.sub_seq,
            "nextProvSeq": self.counters.prov_seq,
            "entries": self.entries.iter().map(|e| json!({
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
            "subscriptions": self.subscriptions.iter().map(|s| json!({
                "id": s.id,
                "nfId": s.nf_id,
                "uri": s.notification_uri,
                "expires": s.expires.map(|t| t.to_rfc3339()),
            })).collect::<Vec<_>>(),
            "provisionings": self.provisionings.iter().map(|p| json!({
                "id": p.id,
                "configs": p.configs,
                "suppFeat": p.supp_feat,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Writes snapshots in generation order (#786).
///
/// Snapshots are taken under the state lock but may be written after it is
/// released, so two writes could land out of order. This writes a snapshot only
/// when it is newer than the last one written.
#[derive(Debug, Default)]
pub struct Persister {
    store: StateStore,
    written: std::sync::Mutex<u64>,
}

impl Persister {
    /// Write `doc` unless a newer generation is already on disk. `Err` when the
    /// write failed (#843 review): a caller that needs the write to have happened
    /// (an ID reservation) must not proceed.
    pub fn write(&self, generation: u64, doc: &Value) -> Result<(), String> {
        let mut written = self
            .written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if generation <= *written {
            return Ok(());
        }
        match self.store.persist(doc) {
            Ok(()) => {
                *written = generation;
                Ok(())
            }
            Err(e) => {
                log::error!("UCMF state not persisted: {e}");
                Err(e.to_string())
            }
        }
    }
}

impl Ucmf {
    pub fn new(version_id: u8, mode: ModeOfOperation) -> Self {
        Self {
            version_id,
            mode,
            next_entry_id: 1,
            next_rci: 0,
            entries: Dictionary::default(),
            limits: Limits::default(),
            subscriptions: BTreeMap::new(),
            next_sub_seq: 1,
            provisionings: BTreeMap::new(),
            next_prov_seq: 1,
            persister: Arc::new(Persister::default()),
            generation: 0,
            write_behind: false,
            dirty: false,
            reserved: Counters::default(),
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
        self.entries.get(id)
    }

    /// Set the capacity limits (configuration, #786).
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
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
        let entry = self.entries.by_racs_id(id).ok_or(ResolveError::NotFound)?;
        Self::check_format(entry, format)?;
        Ok(entry)
    }

    /// TS 29.673 §5.2.2.2.2: an entry by its Dictionary Entry ID.
    pub fn get_entry(&self, id: u32, format: Option<RacFormat>) -> Result<&DicEntry, ResolveError> {
        let entry = self.entries.get(id).ok_or(ResolveError::NotFound)?;
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
            .with_tac(tac)
            .find(|e| caps.matches(&e.caps))
            .map(|e| (e.id, e.plmn_id));

        if let Some((entry_id, existing)) = matched {
            let current = self.version_id;
            let id = match existing {
                Some(id @ RacsId::PlmnAssigned { version_id, .. }) if version_id == current => id,
                // No PLMN-assigned ID yet (a provisioned manufacturer entry), or
                // one under an old Version ID: assign a current one.
                _ => self.allocate_plmn_id()?,
            };
            self.entries.set_plmn_id(entry_id, Some(id));
            if let Some(stored) = self.entries.caps_mut(entry_id) {
                caps.fill_missing_into(stored);
                stored.complete();
            }
            self.persist();
            return Ok((entry_id, id, None));
        }

        if self.mode == ModeOfOperation::A && !(caps.cap_5gs.is_some() && caps.cap_eps.is_some()) {
            return Err(AssignError::ModeARequiresBothFormats);
        }
        if self.entries.len() >= self.limits.max_dic_entries {
            log::warn!(
                "Assign refused: the dictionary holds the configured maximum of {} entries",
                self.limits.max_dic_entries
            );
            return Err(AssignError::DictionaryFull);
        }
        let entry_id = self.allocate_entry_id()?;
        let id = self.allocate_plmn_id()?;
        let mut caps = caps;
        caps.complete();
        self.entries.insert(DicEntry {
            id: entry_id,
            tacs: vec![tac.to_string()],
            plmn_id: Some(id),
            man_id: None,
            caps,
            provisioning_id: None,
        });
        self.persist();
        Ok((entry_id, id, self.creation_notification(now)))
    }

    fn allocate_plmn_id(&mut self) -> Result<RacsId, AssignError> {
        self.reserve_ids()
            .map_err(|_| AssignError::StateNotPersisted)?;
        if self.next_rci > MAX_RCI {
            return Err(AssignError::IdSpaceExhausted);
        }
        let id = RacsId::plmn_assigned(self.version_id, self.next_rci)
            .map_err(|_| AssignError::IdSpaceExhausted)?;
        self.next_rci += 1;
        Ok(id)
    }

    /// The next Dictionary Entry ID. `StateNotPersisted` when the reservation could
    /// not be written (#843 review), `IdSpaceExhausted` when the counter cannot
    /// advance: handing out its last value again would give two entries one ID.
    fn allocate_entry_id(&mut self) -> Result<u32, AssignError> {
        self.reserve_ids()
            .map_err(|_| AssignError::StateNotPersisted)?;
        let id = self.next_entry_id;
        self.next_entry_id = id.checked_add(1).ok_or(AssignError::IdSpaceExhausted)?;
        Ok(id)
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
        let outdated: Vec<(u32, RacsId, bool)> = self
            .entries
            .values()
            .filter_map(|e| match e.plmn_id {
                Some(id @ RacsId::PlmnAssigned { version_id, .. }) if version_id != current => {
                    Some((e.id, id, e.man_id.is_some()))
                }
                _ => None,
            })
            .collect();
        if outdated.is_empty() {
            return None;
        }
        let mut deleted = Vec::with_capacity(outdated.len());
        for (entry_id, id, has_man_id) in outdated {
            deleted.push(id.to_nucmf());
            // An entry left with neither ID is removed.
            if has_man_id {
                self.entries.set_plmn_id(entry_id, None);
            } else {
                self.entries.remove(entry_id);
            }
        }
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
    ) -> Result<Subscription, SubscribeError> {
        self.purge_expired(now);
        if self.subscriptions.len() >= self.limits.max_subscriptions {
            log::warn!(
                "Subscribe refused: {} subscriptions are active, the configured maximum",
                self.limits.max_subscriptions
            );
            return Err(SubscribeError::TooManySubscriptions);
        }
        // #843 review: the consumer is self-declared by `nfId`, so a cap keyed on it
        // alone is sidestepped by varying it. A subscription counts against both
        // its nfId and its notification URI's authority, and either reaching the
        // cap refuses.
        let by_nf = nf_id.as_deref().map(|id| {
            self.subscriptions
                .values()
                .filter(|s| s.nf_id.as_deref() == Some(id))
                .count()
        });
        let authority = uri_authority(&notification_uri);
        let by_uri = self
            .subscriptions
            .values()
            .filter(|s| uri_authority(&s.notification_uri) == authority)
            .count();
        let consumer = consumer_of(nf_id.as_deref(), &notification_uri);
        let held = by_nf.unwrap_or(0).max(by_uri);
        if held >= self.limits.max_subscriptions_per_consumer {
            log::warn!(
                "Subscribe refused: consumer {consumer} (callback {authority}) holds {held} \
                 subscriptions, the configured maximum"
            );
            return Err(SubscribeError::TooManyForConsumer);
        }
        self.reserve_ids()
            .map_err(|_| SubscribeError::StateNotPersisted)?;
        let seq = self.next_sub_seq;
        // The counter is restored from the state file, so it is not trusted not
        // to be near the top of its range. At the top it refuses rather than
        // hand out an ID again.
        self.next_sub_seq = seq.checked_add(1).ok_or(SubscribeError::IdSpaceExhausted)?;
        // Deterministic per-subscription spread, so consecutive subscriptions
        // never share an expiry. `(seq mod m)·37 mod m` is `seq·37 mod m`
        // without the multiplication overflowing.
        let m = EXPIRY_SPREAD_SECS as u64;
        let spread = ChronoDuration::seconds((((seq % m) * 37) % m) as i64);
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
        Ok(sub)
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
        if self.reserve_ids().is_err() {
            // TS 29.122 RacsFailureCode: nothing is provisioned without an ID that
            // is safe to hand out (#843 review).
            let failed = racs_configs
                .keys()
                .map(|k| (k.clone(), RACS_OTHER_REASON))
                .collect();
            return (None, failed, None);
        }
        let Some(next_prov_seq) = self.next_prov_seq.checked_add(1) else {
            // The counter cannot advance: refuse rather than reuse an ID.
            log::error!("Provisioning refused: the provisioning ID space is used up");
            let failed = racs_configs
                .keys()
                .map(|k| (k.clone(), RACS_OTHER_REASON))
                .collect();
            return (None, failed, None);
        };
        let prov_id = self.next_prov_seq.to_string();
        let (ok, failed) = self.provision_entries(&prov_id, racs_configs, None);
        if ok.is_empty() {
            return (None, failed, None);
        }
        self.next_prov_seq = next_prov_seq;
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
            (Provisioning, Vec<(String, &'static str)>, Vec<Notification>),
            Vec<(String, &'static str)>,
        >,
    > {
        self.provisionings.get(id)?;
        let removed: Vec<DicEntry> = self.take_entries_of(id);
        let (ok, failed) = self.provision_entries(id, racs_configs, Some(id));
        if ok.is_empty() {
            // Put the previous entries back: a failed replace changes nothing.
            for e in removed {
                self.entries.insert(e);
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
        // The replaced entries are gone, and with them any PLMN-assigned ID an Assign
        // had added to one: those IDs no longer resolve, so subscribers are told
        // before they are told about the new entries (#585).
        let notes = self
            .plmn_id_deletion_notification(&removed, now)
            .into_iter()
            .chain(self.creation_notification(now))
            .collect();
        Some(Ok((prov, failed, notes)))
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
            (Provisioning, Vec<(String, &'static str)>, Vec<Notification>),
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

    /// TS 29.675 §4.2.4: remove the resource and its dictionary entries. `None`
    /// when no such resource; otherwise the notification to send, if any (#585).
    ///
    /// TS 29.673 can only notify the deletion of PLMN-assigned IDs
    /// (`DELETION_OF_PLMN_ASSIGNED_IDS`, Table 6.1.6.3.3-1). A provisioned entry
    /// has one whenever an Assign matched it, and that ID stops resolving with the
    /// entry, so it is notified. For the manufacturer-assigned IDs themselves
    /// TS 29.673 V20.0.0 defines no event type. TS 23.502 §5.2.18.3.5 lists a
    /// "deletion" notification, but the stage 3 has no way to carry one. Inventing
    /// an `eventType` no AMF understands would tell nobody anything, so none is
    /// sent; a subscriber that resolves such an ID gets `404`.
    pub fn delete_provisioning(
        &mut self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Option<Option<Notification>> {
        self.provisionings.remove(id)?;
        let removed = self.take_entries_of(id);
        self.persist();
        Some(self.plmn_id_deletion_notification(&removed, now))
    }

    /// `DELETION_OF_PLMN_ASSIGNED_IDS` for the PLMN-assigned IDs of `removed`, or
    /// `None` when they had none.
    fn plmn_id_deletion_notification(
        &mut self,
        removed: &[DicEntry],
        now: DateTime<Utc>,
    ) -> Option<Notification> {
        let deleted: Vec<String> = removed
            .iter()
            .filter_map(|e| e.plmn_id.map(|i| i.to_nucmf()))
            .collect();
        if deleted.is_empty() {
            return None;
        }
        self.notification(
            now,
            json!({
                "dicEntryId": self.highest_entry_id(),
                "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
                "manAssOpRequestlist": { "plmnAssiUeRadioCapId": deleted },
            }),
        )
    }

    fn take_entries_of(&mut self, prov_id: &str) -> Vec<DicEntry> {
        let ids: Vec<u32> = self
            .entries
            .values()
            .filter(|e| e.provisioning_id.as_deref() == Some(prov_id))
            .map(|e| e.id)
            .collect();
        ids.into_iter()
            .filter_map(|i| self.entries.remove(i))
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
            let Some((tacs, mut caps)) = parse_racs_configuration(config) else {
                failed.push((racs_key.clone(), RACS_OTHER_REASON));
                continue;
            };
            if self.entries.by_racs_id(&man_id).is_some() {
                failed.push((racs_key.clone(), RACS_ID_DUPLICATED));
                continue;
            }
            if self.entries.len() >= self.limits.max_dic_entries {
                log::warn!(
                    "Provisioning of {racs_key} refused: the dictionary holds the configured \
                     maximum of {} entries",
                    self.limits.max_dic_entries
                );
                failed.push((racs_key.clone(), RACS_OTHER_REASON));
                continue;
            }
            let Ok(entry_id) = self.allocate_entry_id() else {
                failed.push((racs_key.clone(), RACS_OTHER_REASON));
                continue;
            };
            caps.complete();
            self.entries.insert(DicEntry {
                id: entry_id,
                tacs,
                plmn_id: None,
                man_id: Some(man_id),
                caps,
                provisioning_id: Some(prov_id.to_string()),
            });
            ok.insert(racs_key.clone(), config.clone());
        }
        (ok, failed)
    }

    // ------------------------------------------------------------ Persistence

    /// Back this UCMF with a snapshot file and load it. A configured Version ID
    /// that differs from the stored one is applied by the caller afterwards
    /// with [`Ucmf::set_version_id`], so subscribers are told.
    pub fn attach_store(&mut self, path: Option<PathBuf>) -> Result<bool, String> {
        let mut store = StateStore::new(path);
        let loaded = store.load();
        self.persister = Arc::new(Persister {
            store,
            written: std::sync::Mutex::new(0),
        });
        match loaded {
            Ok(Loaded::Absent) => Ok(false),
            Ok(Loaded::Snapshot(doc)) => {
                self.restore(&doc);
                Ok(true)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Switch to write-behind persistence (#786): changes are written by
    /// [`Ucmf::take_pending_write`]'s caller, not by the change itself.
    pub fn set_write_behind(&mut self, on: bool) {
        self.write_behind = on;
        self.reserved = self.counters();
    }

    fn counters(&self) -> Counters {
        Counters {
            entry_id: self.next_entry_id,
            rci: self.next_rci,
            sub_seq: self.next_sub_seq,
            prov_seq: self.next_prov_seq,
        }
    }

    /// Record a change: written now, or marked for the flusher.
    fn persist(&mut self) {
        self.generation += 1;
        if self.write_behind {
            self.dirty = true;
        } else {
            self.write_now();
        }
    }

    /// Write the snapshot now, under the caller's lock.
    fn write_now(&mut self) {
        self.generation += 1;
        self.dirty = false;
        let doc = self.snapshot();
        // Outside write-behind mode a failed write is logged by the persister and
        // the change stays in memory, as before #786; the reservation path below
        // is the one that must not proceed on failure.
        let _ = self.persister.write(self.generation, &doc);
    }

    /// In write-behind mode, make sure every counter is below what the written
    /// snapshot claims before an ID is handed out: when one reaches its
    /// reservation, reserve [`ID_RESERVATION`] more of each and write that
    /// synchronously. One write per 1024 IDs, and a crash leaves gaps, never
    /// reuse.
    ///
    /// Fail-closed (#843 review): the reservation counts only once it is on disk.
    /// When the write fails, `reserved` stays where it was and the caller refuses
    /// the allocation, so no ID is ever handed out above what a restart resumes
    /// from.
    fn reserve_ids(&mut self) -> Result<(), String> {
        if !self.write_behind {
            return Ok(());
        }
        let c = self.counters();
        let r = self.reserved;
        if c.entry_id < r.entry_id
            && c.rci < r.rci
            && c.sub_seq < r.sub_seq
            && c.prov_seq < r.prov_seq
        {
            return Ok(());
        }
        let step = ID_RESERVATION;
        let previous = self.reserved;
        self.reserved = Counters {
            entry_id: c.entry_id.saturating_add(step as u32),
            rci: c.rci.saturating_add(step),
            sub_seq: c.sub_seq.saturating_add(step),
            prov_seq: c.prov_seq.saturating_add(step),
        };
        self.generation += 1;
        let doc = self.snapshot();
        match self.persister.write(self.generation, &doc) {
            Ok(()) => {
                self.dirty = false;
                Ok(())
            }
            Err(e) => {
                self.reserved = previous;
                // The in-memory changes still need writing.
                self.dirty = true;
                log::error!(
                    "UCMF ID reservation not written ({e}); no ID is handed out until the \
                     state file can be written"
                );
                Err(e)
            }
        }
    }

    /// In write-behind mode, the snapshot to write if anything changed since the
    /// last one, with its generation and the writer to hand it to. Taken under
    /// the state lock; the caller writes it after releasing the lock.
    pub fn take_pending_write(&mut self) -> Option<(Arc<Persister>, u64, SnapshotSource)> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some((
            self.persister.clone(),
            self.generation,
            self.snapshot_source(),
        ))
    }

    pub fn snapshot(&self) -> Value {
        self.snapshot_source().to_json()
    }

    /// What a snapshot is made of, copied out of the state (#843 review). The
    /// copy is taken under the state lock; the JSON and base64 serialisation of
    /// every capability is done from it after the lock is released.
    fn snapshot_source(&self) -> SnapshotSource {
        SnapshotSource {
            version_id: self.version_id,
            // In write-behind mode the reservations, so a restart after a crash
            // continues above every ID handed out (#786).
            counters: if self.write_behind {
                self.reserved
            } else {
                self.counters()
            },
            entries: self.entries.values().cloned().collect(),
            subscriptions: self.subscriptions.values().cloned().collect(),
            provisionings: self.provisionings.values().cloned().collect(),
        }
    }

    fn restore(&mut self, doc: &Value) {
        let u64_of = |k: &str| doc.get(k).and_then(Value::as_u64);
        if let Some(v) = u64_of("versionId") {
            self.version_id = v as u8;
        }
        if let Some(v) = u64_of("nextEntryId") {
            self.next_entry_id = u32::try_from(v).unwrap_or(u32::MAX);
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
            self.entries.insert(DicEntry {
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
            });
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

/// The authority (`host[:port]`) of a notification URI.
fn uri_authority(notification_uri: &str) -> &str {
    let rest = notification_uri
        .split_once("://")
        .map_or(notification_uri, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

/// Who a subscription belongs to, for logging the per-consumer cap (#786): its
/// `nfId` when given, else the authority (`host[:port]`) of its notification URI.
fn consumer_of(nf_id: Option<&str>, notification_uri: &str) -> String {
    match nf_id {
        Some(id) => format!("nf:{id}"),
        None => {
            let rest = notification_uri
                .split_once("://")
                .map_or(notification_uri, |(_, r)| r);
            format!("uri:{}", rest.split('/').next().unwrap_or(rest))
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

/// A non-empty, even-length string of ASCII hexadecimal digits as octets, or
/// `None`.
///
/// Works on the bytes, never on `&str` slices: `racsParamEps` / `racsParam5Gs`
/// arrive from any SBI peer, and slicing a `&str` at a byte offset that is not
/// a char boundary panics (#725). Any byte outside `[0-9A-Fa-f]`, which
/// includes every byte of a multi-byte UTF-8 character, is refused.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    b.chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
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
        let sub = u
            .subscribe(None, "http://amf/notify".into(), None, now())
            .unwrap();
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
                .unwrap()
                .expires,
            Some(hint)
        );
        let far = now() + ChronoDuration::days(30);
        let a = u
            .subscribe(None, "http://b/n".into(), Some(far), now())
            .unwrap()
            .expires
            .unwrap();
        let b = u
            .subscribe(None, "http://c/n".into(), Some(far), now())
            .unwrap()
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
        u.subscribe(None, "http://amf/n".into(), None, now())
            .unwrap();
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
        assert!(u.delete_provisioning(&prov.id, now()).is_some());
        assert!(u.resolve(&man, None).is_err());
        assert!(u.delete_provisioning(&prov.id, now()).is_none());
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

    // ----------------------------------------------------------------- #585

    use crate::rac::tests::{cap_5gs, cap_eps};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// TS 23.501 §5.4.4.1a, Mode of operation B: the AMF sends the TS 38.331 format
    /// only, and the UCMF holds the TS 36.331 format and both paging capabilities.
    #[test]
    fn a_5gs_assign_is_transcoded_to_eps_and_both_paging_capabilities_derived() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let nr = cap_5gs();
        let (_, id, _) = u.assign("35123456", caps(&nr), now()).unwrap();
        let e = u
            .resolve(&id, Some(RacFormat::Eps))
            .expect("an EPS resolve of a 5GS-only assign must succeed: the UCMF transcodes");
        assert_eq!(
            e.caps.cap_5gs.as_deref(),
            Some(&nr[..]),
            "the provided bytes are kept"
        );
        assert_eq!(
            e.caps.cap_eps,
            Some(crate::rac::transcode_5gs_to_eps(&nr).unwrap())
        );
        assert_eq!(
            e.caps.paging_5gs,
            Some(crate::rac::derive_paging_5gs(&nr).unwrap())
        );
        assert!(e.caps.paging_eps.is_some());

        // The same capability again matches the entry (the comparison is on the
        // provided format), so no second ID.
        let (_, again, _) = u.assign("35123456", caps(&nr), now()).unwrap();
        assert_eq!(again, id);
    }

    #[test]
    fn a_paging_capability_the_amf_provided_is_not_replaced() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let mut c = caps(&cap_5gs());
        c.paging_5gs = Some(vec![0x42]);
        let (_, id, _) = u.assign("35123456", c, now()).unwrap();
        assert_eq!(
            u.resolve(&id, None).unwrap().caps.paging_5gs,
            Some(vec![0x42])
        );
    }

    #[test]
    fn an_eps_only_provisioning_resolves_in_5gs_format() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        let eps = cap_eps(false);
        let mut m = Map::new();
        m.insert(
            MAN.into(),
            json!({"imeiTacs": ["35123456"], "racsParamEps": hex(&eps)}),
        );
        let (prov, failed, _) = u.create_provisioning(&m, None, now());
        assert!(prov.is_some() && failed.is_empty());
        let man = RacsId::from_digit_str(MAN).unwrap();
        let e = u.resolve(&man, Some(RacFormat::FiveGs)).unwrap();
        assert_eq!(
            e.caps.cap_5gs,
            Some(crate::rac::transcode_eps_to_5gs(&eps).unwrap())
        );
        assert_eq!(
            e.caps.paging_eps,
            Some(crate::rac::derive_paging_eps(&eps).unwrap())
        );
    }

    /// TS 29.675 §4.2.4 removes the entries; TS 29.673 notifies what it can express of
    /// that, the PLMN-assigned IDs that went with them.
    #[test]
    fn deleting_a_provisioning_notifies_the_plmn_assigned_ids_it_removed() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.subscribe(None, "http://amf/n".into(), None, now())
            .unwrap();
        let (prov, _, _) = u.create_provisioning(&racs(MAN, "0a0b"), None, now());
        let pid = prov.unwrap().id;
        // An AMF assigns over the provisioned entry: it now also has a PLMN ID.
        let (_, plmn, _) = u.assign("35123456", caps(&[0x0a, 0x0b]), now()).unwrap();

        let note = u
            .delete_provisioning(&pid, now())
            .expect("the provisioning exists")
            .expect("the PLMN-assigned ID went with the entry, so it is notified");
        assert_eq!(note.uris, ["http://amf/n"]);
        assert_eq!(note.body["eventType"], "DELETION_OF_PLMN_ASSIGNED_IDS");
        assert_eq!(
            note.body["manAssOpRequestlist"]["plmnAssiUeRadioCapId"],
            json!([plmn.to_nucmf()])
        );
        assert_eq!(u.resolve(&plmn, None), Err(ResolveError::NotFound));
    }

    #[test]
    fn deleting_a_provisioning_no_one_assigned_over_notifies_nothing() {
        // TS 29.673 has no event for manufacturer-assigned IDs (see
        // `delete_provisioning`), so a subscriber is not sent an invented one.
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.subscribe(None, "http://amf/n".into(), None, now())
            .unwrap();
        let (prov, _, _) = u.create_provisioning(&racs(MAN, "0a0b"), None, now());
        assert_eq!(u.delete_provisioning(&prov.unwrap().id, now()), Some(None));
    }

    #[test]
    fn replacing_a_provisioning_notifies_the_deleted_plmn_id_before_the_creation() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.subscribe(None, "http://amf/n".into(), None, now())
            .unwrap();
        let (prov, _, _) = u.create_provisioning(&racs(MAN, "0a0b"), None, now());
        let pid = prov.unwrap().id;
        let (_, plmn, _) = u.assign("35123456", caps(&[0x0a, 0x0b]), now()).unwrap();
        let (_, _, notes) = u
            .replace_provisioning(&pid, &racs(MAN, "0c"), None, now())
            .unwrap()
            .unwrap();
        let events: Vec<&str> = notes
            .iter()
            .map(|n| n.body["eventType"].as_str().unwrap())
            .collect();
        assert_eq!(
            events,
            [
                "DELETION_OF_PLMN_ASSIGNED_IDS",
                "CREATION_OF_DICTIONARY_ENTRY"
            ]
        );
        assert_eq!(
            notes[0].body["manAssOpRequestlist"]["plmnAssiUeRadioCapId"],
            json!([plmn.to_nucmf()])
        );
    }

    // ----------------------------------------------------------------- #725

    /// `"aéa"` is four bytes, so it passed the even-length check and then
    /// panicked slicing `s[0..2]` across the `é`. Each of these lands a
    /// multi-byte character on an even byte offset, or is otherwise not hex.
    #[test]
    fn a_racs_param_that_is_not_ascii_hex_is_other_reason_not_a_panic() {
        for bad in [
            "aéa", "éé", "0é0", "€0", "0g", " 0a", "0a ", "+1", "0x0a", "a", "",
        ] {
            for member in ["racsParam5Gs", "racsParamEps"] {
                let mut u = Ucmf::new(1, ModeOfOperation::B);
                let mut m = Map::new();
                m.insert(MAN.into(), json!({"imeiTacs": ["35123456"], member: bad}));
                let (prov, failed, _) = u.create_provisioning(&m, None, now());
                assert!(prov.is_none(), "{member}={bad:?} must not provision");
                assert_eq!(
                    failed,
                    [(MAN.to_string(), RACS_OTHER_REASON)],
                    "{member}={bad:?}"
                );
                assert_eq!(u.entry_count(), 0);
            }
        }
    }

    #[test]
    fn decode_hex_takes_either_case_and_refuses_odd_or_empty() {
        assert_eq!(decode_hex("00aAfF19"), Some(vec![0x00, 0xAA, 0xFF, 0x19]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex(""), None);
    }

    /// The provisioning and subscription counters are restored from the state
    /// file. At the top of their range they used to overflow (`+= 1`, and
    /// `seq * 37` in the expiry spread), which panics under the state lock.
    #[test]
    fn counters_at_the_top_of_their_range_do_not_overflow() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.restore(&json!({"nextSubSeq": u64::MAX - 1, "nextProvSeq": u64::MAX - 1}));
        let a = u
            .subscribe(None, "http://amf/n".into(), None, now())
            .unwrap();
        assert_eq!(a.id, (u64::MAX - 1).to_string());
        let ceiling = now() + ChronoDuration::seconds(MAX_SUBSCRIPTION_LIFETIME_SECS);
        assert!(a.expires.unwrap() <= ceiling);
        // At the top the counter refuses rather than hand out an ID again.
        assert_eq!(
            u.subscribe(None, "http://amf/m".into(), None, now()),
            Err(SubscribeError::IdSpaceExhausted)
        );
        let (prov, _, _) = u.create_provisioning(&racs(MAN, "0a"), None, now());
        assert_eq!(prov.unwrap().id, (u64::MAX - 1).to_string());
        let other = "000007ed900000000abd";
        let (prov, failed, _) = u.create_provisioning(&racs(other, "0b"), None, now());
        assert!(prov.is_none());
        assert_eq!(failed, [(other.to_string(), RACS_OTHER_REASON)]);
    }

    /// The Dictionary Entry ID counter refuses at u32::MAX instead of
    /// saturating into a reused ID (#725 review).
    #[test]
    fn the_entry_id_counter_refuses_at_its_top() {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.restore(&json!({"nextEntryId": u64::from(u32::MAX) - 1}));
        let (e, _, _) = u.assign("35123456", caps(&[1]), now()).unwrap();
        assert_eq!(e, u32::MAX - 1);
        assert_eq!(
            u.assign("35123456", caps(&[2]), now()),
            Err(AssignError::IdSpaceExhausted)
        );
        let (prov, failed, _) = u.create_provisioning(&racs(MAN, "0a"), None, now());
        assert!(prov.is_none());
        assert_eq!(failed, [(MAN.to_string(), RACS_OTHER_REASON)]);
        // An out-of-range stored value is clamped, not truncated to a low ID.
        let mut v = Ucmf::new(1, ModeOfOperation::B);
        v.restore(&json!({"nextEntryId": u64::from(u32::MAX) + 5}));
        assert_eq!(
            v.assign("35123456", caps(&[1]), now()),
            Err(AssignError::IdSpaceExhausted)
        );
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        /// The reference: what a hex octet string is, written the obvious way.
        fn reference(s: &str) -> Option<Vec<u8>> {
            let ok = !s.is_empty()
                && s.len().is_multiple_of(2)
                && s.chars().all(|c| c.is_ascii_hexdigit());
            ok.then(|| {
                (0..s.len() / 2)
                    .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                    .collect()
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2000))]

            /// Any string at all, multi-byte characters included.
            #[test]
            fn decode_hex_never_panics_and_agrees_with_the_reference(s in any::<String>()) {
                prop_assert_eq!(decode_hex(&s), reference(&s));
            }

            /// Strings drawn mostly from hex digits, with the odd non-ASCII
            /// character, so the even-length, mostly-valid cases are reached.
            #[test]
            fn near_hex_strings_agree_with_the_reference(s in "[0-9a-fA-Fé€ g]{0,24}") {
                prop_assert_eq!(decode_hex(&s), reference(&s));
            }

            #[test]
            fn hex_of_any_octets_round_trips(b in proptest::collection::vec(any::<u8>(), 1..64)) {
                prop_assert_eq!(decode_hex(&hex(&b)), Some(b.clone()));
                prop_assert_eq!(decode_hex(&hex(&b).to_uppercase()), Some(b));
            }

            /// Whole `RacsConfiguration`s from arbitrary JSON-ish members.
            #[test]
            fn any_racs_configuration_is_provisioned_or_refused(
                key in "[0-9a-f]{0,22}|.{0,22}",
                tac in "[0-9]{8}|.{0,10}",
                p5 in proptest::option::of(any::<String>()),
                peps in proptest::option::of("[0-9a-f]{0,40}|.{0,40}"),
            ) {
                let mut u = Ucmf::new(1, ModeOfOperation::B);
                let mut cfg = json!({"imeiTacs": [tac]});
                if let Some(p) = p5 { cfg["racsParam5Gs"] = json!(p); }
                if let Some(p) = peps { cfg["racsParamEps"] = json!(p); }
                let mut m = Map::new();
                m.insert(key.clone(), cfg);
                let (prov, failed, _) = u.create_provisioning(&m, None, now());
                prop_assert!(prov.is_some() == failed.is_empty());
                prop_assert_eq!(u.entry_count(), usize::from(prov.is_some()));
            }
        }
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
            let sub = u
                .subscribe(Some("nf-1".into()), "http://amf/n".into(), None, now())
                .unwrap();
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

    // ----------------------------------------------------------------- #786

    fn limited(max_dic_entries: usize, max_subscriptions: usize, per_consumer: usize) -> Ucmf {
        let mut u = Ucmf::new(1, ModeOfOperation::B);
        u.set_limits(Limits {
            max_dic_entries,
            max_subscriptions,
            max_subscriptions_per_consumer: per_consumer,
        });
        u
    }

    /// #843 review MINOR 4: the nfId is self-declared, so varying it must not
    /// sidestep the per-consumer cap: one callback authority is one consumer.
    #[test]
    fn varying_the_nf_id_does_not_sidestep_the_per_consumer_cap() {
        let mut u = limited(10, 10, 2);
        for i in 0..2 {
            u.subscribe(Some(format!("nf-{i}")), "http://a:80/n".into(), None, now())
                .unwrap();
        }
        assert_eq!(
            u.subscribe(
                Some("nf-new".into()),
                "http://a:80/other".into(),
                None,
                now()
            )
            .map(|s| s.id),
            Err(SubscribeError::TooManyForConsumer)
        );
        // One nfId across callback hosts is still one consumer.
        let mut u = limited(10, 10, 2);
        for host in ["b", "c"] {
            u.subscribe(Some("nf-x".into()), format!("http://{host}/n"), None, now())
                .unwrap();
        }
        assert_eq!(
            u.subscribe(Some("nf-x".into()), "http://d/n".into(), None, now())
                .map(|s| s.id),
            Err(SubscribeError::TooManyForConsumer)
        );
        // Another consumer is unaffected.
        assert!(u
            .subscribe(Some("nf-y".into()), "http://e/n".into(), None, now())
            .is_ok());
    }

    #[test]
    fn the_dictionary_is_capped_and_a_matching_assign_still_works() {
        let mut u = limited(2, 10, 10);
        let (_, first, _) = u.assign("35123456", caps(&[1]), now()).unwrap();
        u.assign("35123456", caps(&[2]), now()).unwrap();
        assert_eq!(
            u.assign("35123456", caps(&[3]), now()),
            Err(AssignError::DictionaryFull)
        );
        // An Assign that matches an entry creates nothing, so it is not refused.
        assert_eq!(u.assign("35123456", caps(&[1]), now()).unwrap().1, first);
        // Provisioning counts against the same cap.
        let (prov, failed, _) = u.create_provisioning(&racs(MAN, "0a"), None, now());
        assert!(prov.is_none());
        assert_eq!(failed, [(MAN.to_string(), RACS_OTHER_REASON)]);
        assert_eq!(u.entry_count(), 2);
    }

    #[test]
    fn subscriptions_are_capped_in_total_and_per_consumer() {
        let mut u = limited(10, 3, 2);
        u.subscribe(Some("amf-1".into()), "http://a/1".into(), None, now())
            .unwrap();
        u.subscribe(Some("amf-1".into()), "http://b/1".into(), None, now())
            .unwrap();
        assert_eq!(
            u.subscribe(Some("amf-1".into()), "http://c/1".into(), None, now()),
            Err(SubscribeError::TooManyForConsumer),
            "the nfId is the consumer"
        );
        // Without an nfId the consumer is the notification URI's authority.
        u.subscribe(None, "http://amf2:80/x".into(), None, now())
            .unwrap();
        assert_eq!(
            u.subscribe(None, "http://amf3/x".into(), None, now()),
            Err(SubscribeError::TooManySubscriptions)
        );
        let mut v = limited(10, 10, 1);
        v.subscribe(None, "http://amf2:80/x".into(), None, now())
            .unwrap();
        assert_eq!(
            v.subscribe(None, "http://amf2:80/y".into(), None, now()),
            Err(SubscribeError::TooManyForConsumer)
        );
        // An expired subscription no longer counts.
        let mut w = limited(10, 1, 1);
        let soon = now() + ChronoDuration::seconds(1);
        w.subscribe(None, "http://a/n".into(), Some(soon), now())
            .unwrap();
        let later = now() + ChronoDuration::seconds(5);
        assert!(w.subscribe(None, "http://a/n".into(), None, later).is_ok());
    }

    /// Write-behind (#786): a change marks the state dirty instead of rewriting
    /// the snapshot, and the flusher's write carries it.
    #[test]
    fn write_behind_defers_the_snapshot_to_the_flusher() {
        let dir = std::env::temp_dir().join(format!("ucmf-wb-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ucmf.json");
        let _ = std::fs::remove_file(&path);
        let mut u = Ucmf::new(3, ModeOfOperation::B);
        u.attach_store(Some(path.clone())).unwrap();
        u.set_write_behind(true);
        // The first ID reserves, so that one write is synchronous.
        let (_, id, _) = u.assign("35123456", caps(&[7]), now()).unwrap();
        let reserved = std::fs::read_to_string(&path).unwrap();
        u.assign("35123456", caps(&[8]), now()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            reserved,
            "the second Assign did not rewrite the snapshot"
        );
        let (persister, generation, doc) = u.take_pending_write().expect("dirty");
        assert!(u.take_pending_write().is_none(), "taken once");
        persister.write(generation, &doc.to_json()).unwrap();
        let mut back = Ucmf::new(0, ModeOfOperation::B);
        assert_eq!(back.attach_store(Some(path.clone())), Ok(true));
        assert_eq!(back.entry_count(), 2);
        assert!(back.resolve(&id, None).is_ok());
        // An older snapshot written late does not overwrite a newer one.
        persister
            .write(generation - 1, &json!({"versionId": 9}))
            .unwrap();
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["versionId"], 3, "the newer snapshot stays");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crash loses the unflushed tail, but a restarted UCMF never hands out an
    /// ID it handed out before: the written snapshot claims the reservation.
    #[test]
    fn a_crash_before_the_flush_never_reissues_an_id() {
        let dir = std::env::temp_dir().join(format!("ucmf-crash-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ucmf.json");
        let _ = std::fs::remove_file(&path);
        let mut handed_out = Vec::new();
        {
            let mut u = Ucmf::new(3, ModeOfOperation::B);
            u.attach_store(Some(path.clone())).unwrap();
            u.set_write_behind(true);
            for i in 0..5u8 {
                handed_out.push(u.assign("35123456", caps(&[i]), now()).unwrap().1);
            }
            u.subscribe(None, "http://a/n".into(), None, now()).unwrap();
            // Dropped without a flush: the crash.
        }
        let mut u = Ucmf::new(3, ModeOfOperation::B);
        u.attach_store(Some(path.clone())).unwrap();
        u.set_write_behind(true);
        let (entry, next, _) = u.assign("35123456", caps(&[99]), now()).unwrap();
        assert!(
            !handed_out.contains(&next),
            "{next:?} was handed out before the crash"
        );
        assert!(entry > 5);
        let sub = u.subscribe(None, "http://a/n".into(), None, now()).unwrap();
        assert_ne!(sub.id, "1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #843 review MAJOR: when the reservation cannot be written, no ID is handed
    /// out. Before, `reserved` advanced anyway, IDs were issued above what was on
    /// disk, and after a crash RCI 0 was issued again. The store is made
    /// unwritable by putting a FILE where its directory was (ENOTDIR), which
    /// fails for root too, unlike a read-only mode.
    #[test]
    fn an_unwritable_reservation_hands_out_no_id() {
        let dir = std::env::temp_dir().join(format!("ucmf-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ucmf.json");
        let mut handed_out = Vec::new();
        {
            let mut u = Ucmf::new(3, ModeOfOperation::B);
            u.attach_store(Some(path.clone())).unwrap();
            u.set_write_behind(true);
            // Sabotage: the state directory becomes a file.
            std::fs::remove_dir_all(&dir).unwrap();
            std::fs::write(&dir, b"not a directory").unwrap();
            for i in 0..3u8 {
                assert_eq!(
                    u.assign("35123456", caps(&[i]), now()).map(|r| r.1),
                    Err(AssignError::StateNotPersisted),
                    "no RCI without a reservation on disk"
                );
            }
            assert_eq!(
                u.subscribe(None, "http://a/n".into(), None, now())
                    .map(|s| s.id),
                Err(SubscribeError::StateNotPersisted)
            );
            let mut configs = Map::new();
            configs.insert(
                "01ABCDEF".into(),
                json!({ "imeiTacs": ["35123456"], "racsParam5Gs": "0102" }),
            );
            let (prov, failed, _) = u.create_provisioning(&configs, None, now());
            assert!(prov.is_none());
            assert_eq!(failed, vec![("01ABCDEF".to_string(), RACS_OTHER_REASON)]);
            // The store heals: allocation resumes.
            std::fs::remove_file(&dir).unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            for i in 0..3u8 {
                handed_out.push(u.assign("35123456", caps(&[i]), now()).unwrap().1);
            }
            // Dropped without a flush: the crash.
        }
        let mut u = Ucmf::new(3, ModeOfOperation::B);
        u.attach_store(Some(path.clone())).unwrap();
        u.set_write_behind(true);
        let next = u.assign("35123456", caps(&[99]), now()).unwrap().1;
        assert!(
            !handed_out.contains(&next),
            "{next:?} was handed out before the crash"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    mod index {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone)]
        enum Op {
            Assign(u8, u8),
            Provision(u8, u8),
            Replace(u8, u8),
            Delete,
            NewVersion,
            Purge,
        }

        fn op() -> impl Strategy<Value = Op> {
            prop_oneof![
                (0..3u8, 0..4u8).prop_map(|(t, c)| Op::Assign(t, c)),
                (0..3u8, 0..4u8).prop_map(|(m, c)| Op::Provision(m, c)),
                (0..3u8, 0..4u8).prop_map(|(m, c)| Op::Replace(m, c)),
                Just(Op::Delete),
                Just(Op::NewVersion),
                Just(Op::Purge),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(300))]

            /// Any sequence of dictionary changes keeps the indexes exact, and
            /// Resolve by index agrees with a scan of every entry.
            #[test]
            fn the_indexes_follow_every_change(ops in proptest::collection::vec(op(), 1..30)) {
                let mut u = Ucmf::new(1, ModeOfOperation::B);
                let tac = |t: u8| format!("3512345{t}");
                let man = |m: u8| format!("000007ed90000000000{m}");
                let mut version = 1u8;
                for op in ops {
                    match op {
                        Op::Assign(t, c) => { let _ = u.assign(&tac(t), caps(&[c]), now()); }
                        Op::Provision(m, c) => {
                            let mut cfg = Map::new();
                            cfg.insert(man(m), json!({"imeiTacs": [tac(m)], "racsParam5Gs": format!("0{c}")}));
                            u.create_provisioning(&cfg, None, now());
                        }
                        Op::Replace(m, c) => {
                            let mut cfg = Map::new();
                            cfg.insert(man(m), json!({"imeiTacs": [tac(c % 3)], "racsParam5Gs": format!("1{c}")}));
                            u.replace_provisioning("1", &cfg, None, now());
                        }
                        Op::Delete => { u.delete_provisioning("1", now()); }
                        Op::NewVersion => { version = version.wrapping_add(1); u.set_version_id(version, now()); }
                        Op::Purge => { u.purge_outdated_plmn_ids(now()); }
                    }
                    u.entries.assert_consistent();
                    for e in u.entries.values() {
                        for id in e.plmn_id.iter().chain(e.man_id.iter()) {
                            let scanned = u.entries.values().find(|x| x.plmn_id.as_ref() == Some(id) || x.man_id.as_ref() == Some(id)).map(|x| x.id);
                            prop_assert_eq!(u.entries.by_racs_id(id).map(|x| x.id), scanned);
                        }
                    }
                }
            }
        }
    }
}
