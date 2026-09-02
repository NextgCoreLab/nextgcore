//! NSSF Context Management
//!
//! Port of src/nssf/context.c - NSSF context with NSI list and Home list

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

impl SNssai {
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        Self { sst, sd }
    }

    /// Create S-NSSAI from SST and SD values
    pub fn from_sst_sd(sst: u8, sd: u32) -> Self {
        let sd_opt = if sd == 0xFFFFFF { None } else { Some(sd) };
        Self { sst, sd: sd_opt }
    }
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

impl PlmnId {
    pub fn new(mcc: &str, mnc: &str) -> Self {
        Self {
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
        }
    }

    /// Create from raw bytes (3 bytes)
    pub fn from_bytes(bytes: &[u8; 3]) -> Self {
        let mcc = format!(
            "{}{}{}",
            bytes[0] & 0x0F,
            (bytes[0] >> 4) & 0x0F,
            bytes[1] & 0x0F
        );
        let mnc2 = (bytes[1] >> 4) & 0x0F;
        let mnc = if mnc2 == 0x0F {
            format!("{}{}", bytes[2] & 0x0F, (bytes[2] >> 4) & 0x0F)
        } else {
            format!("{}{}{}", bytes[2] & 0x0F, (bytes[2] >> 4) & 0x0F, mnc2)
        };
        Self { mcc, mnc }
    }
}

/// 5GS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default)]
pub struct Tai {
    pub plmn_id: PlmnId,
    pub tac: u32,
}

/// Roaming indication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoamingIndication {
    #[default]
    NonRoaming,
    LocalBreakout,
    HomeRouted,
}

impl RoamingIndication {
    pub fn from_openapi(value: i32) -> Self {
        match value {
            1 => RoamingIndication::NonRoaming,
            2 => RoamingIndication::LocalBreakout,
            3 => RoamingIndication::HomeRouted,
            _ => RoamingIndication::NonRoaming,
        }
    }

    pub fn to_openapi(&self) -> i32 {
        match self {
            RoamingIndication::NonRoaming => 1,
            RoamingIndication::LocalBreakout => 2,
            RoamingIndication::HomeRouted => 3,
        }
    }
}

/// NSSF NSI (Network Slice Instance) context
/// Port of nssf_nsi_t from context.h
#[derive(Debug, Clone)]
pub struct NssfNsi {
    pub id: u64,
    pub nrf_id: String,
    pub nsi_id: String,
    pub s_nssai: SNssai,
    pub roaming_indication: RoamingIndication,
    pub tai_presence: bool,
    pub tai: Option<Tai>,
}

impl NssfNsi {
    pub fn new(id: u64, nrf_id: &str, sst: u8, sd: Option<u32>) -> Self {
        Self {
            id,
            nrf_id: nrf_id.to_string(),
            // TS 29.531: nsiId is an opaque slice-instance identifier, not a
            // pool index. Use a UUID so identifiers are not guessable/sequential.
            nsi_id: uuid::Uuid::new_v4().to_string(),
            s_nssai: SNssai::new(sst, sd),
            roaming_indication: RoamingIndication::default(),
            tai_presence: false,
            tai: None,
        }
    }

    pub fn set_tai(&mut self, tai: Tai) {
        self.tai_presence = true;
        self.tai = Some(tai);
    }
}

/// NSSF Home network context
/// Port of nssf_home_t from context.h
#[derive(Debug, Clone)]
pub struct NssfHome {
    pub id: u64,
    pub plmn_id: PlmnId,
    pub s_nssai: SNssai,
    pub nrf_id: Option<String>,
    pub nsi_id: Option<String>,
    /// Associated stream ID for SBI operations
    pub stream_id: Option<u64>,
}

impl NssfHome {
    pub fn new(id: u64, plmn_id: PlmnId, s_nssai: SNssai) -> Self {
        Self {
            id,
            plmn_id,
            s_nssai,
            nrf_id: None,
            nsi_id: None,
            stream_id: None,
        }
    }

    pub fn set_nrf_info(&mut self, nrf_id: &str, nsi_id: &str) {
        self.nrf_id = Some(nrf_id.to_string());
        self.nsi_id = Some(nsi_id.to_string());
    }

    pub fn has_nrf_info(&self) -> bool {
        self.nrf_id.is_some() && self.nsi_id.is_some()
    }
}

/// NSSAI Availability info stored per NF
///
/// `doc` is the canonical TS 29.531 `NssaiAvailabilityInfo` JSON document as
/// last PUT/PATCHed by the consumer (AMF); the flattened lists are derived
/// from it for fast lookup.
#[derive(Debug, Clone)]
pub struct NssaiAvailabilityInfo {
    pub nf_id: String,
    pub supported_snssai_list: Vec<SNssai>,
    pub tai_list: Vec<Tai>,
    pub doc: serde_json::Value,
}

/// NSSAI availability change subscription (TS 29.531 NssfEventSubscriptionCreateData)
#[derive(Debug, Clone)]
pub struct NssfSubscription {
    pub subscription_id: String,
    /// Callback URI for NssfEventNotification POSTs (mandatory)
    pub nf_nssai_availability_uri: String,
    /// TAIs of interest (mandatory, may be empty array per schema)
    pub tai_list: Vec<Tai>,
    /// Subscribed event (mandatory), e.g. SNSSAI_STATUS_CHANGE_REPORT
    pub event: String,
    pub expiry: Option<String>,
    pub amf_id: Option<String>,
    pub amf_set_id: Option<String>,
}

impl NssfSubscription {
    /// Serialize as NssfEventSubscriptionCreatedData-compatible JSON (without
    /// authorizedNssaiAvailabilityData, which the caller appends).
    pub fn to_created_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "subscriptionId": self.subscription_id });
        if let Some(ref e) = self.expiry {
            v["expiry"] = serde_json::json!(e);
        }
        v
    }

    /// Serialize the full subscription for the on-disk snapshot (lossless),
    /// using the canonical TS 29.571 Tai JSON encoding for the TAI list.
    fn to_persist_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "subscriptionId": self.subscription_id,
            "nfNssaiAvailabilityUri": self.nf_nssai_availability_uri,
            "taiList": self.tai_list.iter().map(tai_to_json).collect::<Vec<_>>(),
            "event": self.event,
        });
        let obj = v.as_object_mut().expect("object");
        if let Some(ref e) = self.expiry {
            obj.insert("expiry".into(), serde_json::json!(e));
        }
        if let Some(ref a) = self.amf_id {
            obj.insert("amfId".into(), serde_json::json!(a));
        }
        if let Some(ref a) = self.amf_set_id {
            obj.insert("amfSetId".into(), serde_json::json!(a));
        }
        v
    }

    /// Reconstruct a subscription from its persisted JSON form.
    fn from_persist_json(v: &serde_json::Value) -> Option<NssfSubscription> {
        let subscription_id = v.get("subscriptionId")?.as_str()?.to_string();
        let nf_nssai_availability_uri = v.get("nfNssaiAvailabilityUri")?.as_str()?.to_string();
        let event = v.get("event")?.as_str()?.to_string();
        let tai_list = v
            .get("taiList")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(tai_from_json).collect())
            .unwrap_or_default();
        let str_at = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
        Some(NssfSubscription {
            subscription_id,
            nf_nssai_availability_uri,
            tai_list,
            event,
            expiry: str_at("expiry"),
            amf_id: str_at("amfId"),
            amf_set_id: str_at("amfSetId"),
        })
    }
}

/// Parse an S-NSSAI from TS 29.571 Snssai JSON (`{"sst": 1, "sd": "010203"}`)
pub fn snssai_from_json(v: &serde_json::Value) -> Option<SNssai> {
    let sst = v.get("sst")?.as_u64()?;
    if sst > 255 {
        return None;
    }
    let sd = match v.get("sd") {
        Some(serde_json::Value::String(s)) => Some(u32::from_str_radix(s, 16).ok()?),
        Some(serde_json::Value::Null) | None => None,
        _ => return None,
    };
    Some(SNssai::new(sst as u8, sd))
}

/// Serialize an S-NSSAI as TS 29.571 Snssai JSON
pub fn snssai_to_json(s: &SNssai) -> serde_json::Value {
    let mut v = serde_json::json!({ "sst": s.sst });
    if let Some(sd) = s.sd {
        v["sd"] = serde_json::json!(format!("{sd:06x}"));
    }
    v
}

/// Parse a TAI from TS 29.571 Tai JSON
pub fn tai_from_json(v: &serde_json::Value) -> Option<Tai> {
    let plmn = v.get("plmnId")?;
    let mcc = plmn.get("mcc")?.as_str()?;
    let mnc = plmn.get("mnc")?.as_str()?;
    let tac = u32::from_str_radix(v.get("tac")?.as_str()?, 16).ok()?;
    Some(Tai {
        plmn_id: PlmnId::new(mcc, mnc),
        tac,
    })
}

/// Serialize a TAI as TS 29.571 Tai JSON
pub fn tai_to_json(t: &Tai) -> serde_json::Value {
    serde_json::json!({
        "plmnId": { "mcc": t.plmn_id.mcc, "mnc": t.plmn_id.mnc },
        "tac": format!("{:06x}", t.tac),
    })
}

fn tai_eq(a: &Tai, b: &Tai) -> bool {
    a.plmn_id.mcc == b.plmn_id.mcc && a.plmn_id.mnc == b.plmn_id.mnc && a.tac == b.tac
}

/// Decompose a TS 29.531 NssaiAvailabilityInfo doc into per-entry
/// (TAIs, supported S-NSSAIs) tuples. Each `supportedNssaiAvailabilityData`
/// entry contributes its mandatory `tai` plus any optional `taiList` members.
pub fn availability_entries(doc: &serde_json::Value) -> Vec<(Vec<Tai>, Vec<SNssai>)> {
    let mut result = Vec::new();
    let Some(entries) = doc
        .get("supportedNssaiAvailabilityData")
        .and_then(|v| v.as_array())
    else {
        return result;
    };
    for entry in entries {
        let mut tais = Vec::new();
        if let Some(tai) = entry.get("tai").and_then(tai_from_json) {
            tais.push(tai);
        }
        if let Some(extra) = entry.get("taiList").and_then(|v| v.as_array()) {
            tais.extend(extra.iter().filter_map(tai_from_json));
        }
        let snssais: Vec<SNssai> = entry
            .get("supportedSnssaiList")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(snssai_from_json).collect())
            .unwrap_or_default();
        result.push((tais, snssais));
    }
    result
}

/// Build a derived NssaiAvailabilityInfo (flattened lists) from a stored doc.
pub fn availability_info_from_doc(nf_id: &str, doc: serde_json::Value) -> NssaiAvailabilityInfo {
    let mut supported = Vec::new();
    let mut tais = Vec::new();
    for (entry_tais, entry_snssais) in availability_entries(&doc) {
        for t in entry_tais {
            if !tais.iter().any(|x| tai_eq(x, &t)) {
                tais.push(t);
            }
        }
        for s in entry_snssais {
            if !supported.contains(&s) {
                supported.push(s);
            }
        }
    }
    NssaiAvailabilityInfo {
        nf_id: nf_id.to_string(),
        supported_snssai_list: supported,
        tai_list: tais,
        doc,
    }
}

/// NSSF Context - main context structure for NSSF
/// Port of nssf_context_t from context.h
pub struct NssfContext {
    /// NSI list (by pool ID)
    nsi_list: RwLock<HashMap<u64, NssfNsi>>,
    /// Home list (by pool ID)
    home_list: RwLock<HashMap<u64, NssfHome>>,
    /// S-NSSAI -> NSI ID hash for quick lookup
    snssai_hash: RwLock<HashMap<(u8, Option<u32>), u64>>,
    /// (PLMN ID, S-NSSAI) -> Home ID hash for quick lookup
    home_hash: RwLock<HashMap<(String, String, u8, Option<u32>), u64>>,
    /// NSSAI availability per NF instance ID (B24.4)
    pub(crate) nssai_availability: RwLock<HashMap<String, NssaiAvailabilityInfo>>,
    /// Availability-change subscriptions by subscriptionId (TS 29.531 §5.2.2.5)
    subscriptions: RwLock<HashMap<String, NssfSubscription>>,
    /// Configured target AMF Set ID for AMF re-selection (TS 29.531 targetAmfSet)
    target_amf_set: RwLock<Option<String>>,
    /// Explicitly configured set of S-NSSAIs supported in this PLMN
    /// (TS 29.531 §6.2.3.2.3.1). `None` => NO restriction configured =>
    /// allow-all (matched-sim back-compat); `Some(set)` => only these
    /// S-NSSAIs may be reported in an NSSAIAvailability PUT/PATCH.
    plmn_supported_snssai_restriction: RwLock<Option<Vec<SNssai>>>,
    /// Per-home-PLMN S-NSSAI restrictions included in
    /// `AuthorizedNssaiAvailabilityData.restrictedSnssaiList` responses
    /// (TS 29.531 §5.3.2.2 / §6.2.6.2.4 RestrictedSnssai). Key:
    /// (home_mcc, home_mnc). Value: S-NSSAIs restricted for subscribers of
    /// that home PLMN. Default empty = no restrictions (matched-sim
    /// back-compat; `restrictedSnssaiList` is absent when this map is empty).
    per_plmn_snssai_restrictions: RwLock<HashMap<(String, String), Vec<SNssai>>>,
    /// Next NSI ID
    next_nsi_id: AtomicUsize,
    /// Next Home ID
    next_home_id: AtomicUsize,
    /// Maximum number of NF instances (pool size)
    max_num_of_nf: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Optional on-disk snapshot path for NSSAI-availability subscriptions and
    /// availability data. `None` => purely in-memory (previous behaviour).
    state_path: Option<PathBuf>,
    /// Issue #66: set when `load` could not read the snapshot. While set,
    /// `persist` REFUSES to write, so an unreadable file is never replaced by the
    /// empty state that failing to read it produced. `AtomicBool` because
    /// `persist` takes `&self`.
    state_unreadable: std::sync::atomic::AtomicBool,
}

impl NssfContext {
    pub fn new() -> Self {
        Self {
            nsi_list: RwLock::new(HashMap::new()),
            home_list: RwLock::new(HashMap::new()),
            snssai_hash: RwLock::new(HashMap::new()),
            home_hash: RwLock::new(HashMap::new()),
            nssai_availability: RwLock::new(HashMap::new()),
            subscriptions: RwLock::new(HashMap::new()),
            target_amf_set: RwLock::new(None),
            plmn_supported_snssai_restriction: RwLock::new(None),
            per_plmn_snssai_restrictions: RwLock::new(HashMap::new()),
            next_nsi_id: AtomicUsize::new(1),
            next_home_id: AtomicUsize::new(1),
            max_num_of_nf: 0,
            initialized: AtomicBool::new(false),
            state_path: None,
            state_unreadable: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a context that snapshots availability subscriptions / data to
    /// `path`, restoring any prior state on construction.
    pub fn with_state_path(path: impl Into<PathBuf>) -> Self {
        let mut ctx = Self::new();
        ctx.state_path = Some(path.into());
        ctx.load();
        ctx
    }

    // -- persistence (NSSAI-availability subscriptions + availability data) --

    /// Serialize availability subscriptions and per-NF availability docs to a
    /// single snapshot document.
    fn snapshot(&self) -> serde_json::Value {
        let subscriptions: Vec<serde_json::Value> = self
            .subscriptions
            .read()
            .map(|s| s.values().map(|sub| sub.to_persist_json()).collect())
            .unwrap_or_default();
        // Availability is fully reconstructible from (nfId, canonical doc).
        let availability: Vec<serde_json::Value> = self
            .nssai_availability
            .read()
            .map(|m| {
                m.values()
                    .map(|i| serde_json::json!({ "nfId": i.nf_id, "doc": i.doc }))
                    .collect()
            })
            .unwrap_or_default();
        serde_json::json!({
            "version": 1,
            "subscriptions": subscriptions,
            "availability": availability,
        })
    }

    /// Persist the current context. No-op without a configured path.
    fn persist(&self) {
        let Some(path) = self.state_path.as_ref() else {
            return;
        };
        // Issue #66: a failed load left this context EMPTY, so writing now would
        // replace the unreadable file with nothing and make the loss permanent --
        // here, every slice-availability subscription and per-NF availability document. Refuse, and keep saying so.
        if self
            .state_unreadable
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            log::error!(
                "NSSF refusing to persist to {}: its previous contents could not be read, \
                 and overwriting them with the current (empty) state would make the loss \
                 permanent. Move the file aside to start fresh.",
                path.display()
            );
            return;
        }
        let doc = self.snapshot();
        if let Err(e) = nextgcore_core::state_store::write_snapshot(path, &doc) {
            log::warn!("NSSF state persist failed: {e}");
        }
    }

    /// Load state from the configured path (no-op when unset/not-yet-created).
    fn load(&mut self) {
        let Some(path) = self.state_path.clone() else {
            return;
        };
        match nextgcore_core::state_store::read_snapshot(&path) {
            Ok(Some(doc)) => self.restore_from(&doc),
            // No file yet: a first boot, not a problem.
            Ok(None) => {}
            // Issue #66: unreadable or malformed. This USED to be a `warn!` and a
            // silent empty start, after which the first mutation rewrote the file
            // from that empty state and made the loss permanent. Now the context
            // is marked unreadable so `persist` refuses and the file survives.
            Err(e) => {
                log::error!(
                    "NSSF state load failed, starting EMPTY and refusing to overwrite the \
                     file: {e}"
                );
                self.state_unreadable
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Restore subscriptions and availability data from a snapshot document.
    fn restore_from(&self, doc: &serde_json::Value) {
        if let Some(arr) = doc.get("subscriptions").and_then(|v| v.as_array()) {
            if let Ok(mut subs) = self.subscriptions.write() {
                for sd in arr {
                    if let Some(sub) = NssfSubscription::from_persist_json(sd) {
                        subs.insert(sub.subscription_id.clone(), sub);
                    }
                }
            }
        }
        if let Some(arr) = doc.get("availability").and_then(|v| v.as_array()) {
            if let Ok(mut avail) = self.nssai_availability.write() {
                for ad in arr {
                    let (Some(nf_id), Some(av_doc)) =
                        (ad.get("nfId").and_then(|v| v.as_str()), ad.get("doc"))
                    else {
                        continue;
                    };
                    let info = availability_info_from_doc(nf_id, av_doc.clone());
                    avail.insert(nf_id.to_string(), info);
                }
            }
        }
    }

    pub fn init(&mut self, max_nf: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_nf = max_nf;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("NSSF context initialized with max {max_nf} NF instances");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.nsi_remove_all();
        self.home_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NSSF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // NSI management

    pub fn nsi_add(&self, nrf_id: &str, sst: u8, sd: Option<u32>) -> Option<NssfNsi> {
        let mut nsi_list = self.nsi_list.write().ok()?;
        let mut snssai_hash = self.snssai_hash.write().ok()?;

        if nsi_list.len() >= self.max_num_of_nf {
            log::error!("Maximum number of NSIs [{}] reached", self.max_num_of_nf);
            return None;
        }

        let id = self.next_nsi_id.fetch_add(1, Ordering::SeqCst) as u64;
        let nsi = NssfNsi::new(id, nrf_id, sst, sd);

        snssai_hash.insert((sst, sd), id);
        nsi_list.insert(id, nsi.clone());

        log::debug!("NSSF NSI added (id={id}, sst={sst}, sd={sd:?})");
        Some(nsi)
    }

    pub fn nsi_remove(&self, id: u64) -> Option<NssfNsi> {
        let mut nsi_list = self.nsi_list.write().ok()?;
        let mut snssai_hash = self.snssai_hash.write().ok()?;

        if let Some(nsi) = nsi_list.remove(&id) {
            snssai_hash.remove(&(nsi.s_nssai.sst, nsi.s_nssai.sd));
            log::debug!("NSSF NSI removed (id={id})");
            return Some(nsi);
        }
        None
    }

    pub fn nsi_remove_all(&self) {
        if let (Ok(mut nsi_list), Ok(mut snssai_hash)) =
            (self.nsi_list.write(), self.snssai_hash.write())
        {
            nsi_list.clear();
            snssai_hash.clear();
        }
    }

    pub fn nsi_find_by_s_nssai(&self, s_nssai: &SNssai) -> Option<NssfNsi> {
        // Lock order nsi_list < snssai_hash (matches nsi_add/nsi_remove); taking
        // snssai_hash first would be an AB-BA deadlock vs nsi_add.
        let nsi_list = self.nsi_list.read().ok()?;
        let snssai_hash = self.snssai_hash.read().ok()?;
        snssai_hash
            .get(&(s_nssai.sst, s_nssai.sd))
            .and_then(|&id| nsi_list.get(&id).cloned())
    }

    pub fn nsi_find_by_id(&self, id: u64) -> Option<NssfNsi> {
        let nsi_list = self.nsi_list.read().ok()?;
        nsi_list.get(&id).cloned()
    }

    pub fn nsi_update(&self, nsi: &NssfNsi) -> bool {
        if let Ok(mut nsi_list) = self.nsi_list.write() {
            if let Some(existing) = nsi_list.get_mut(&nsi.id) {
                *existing = nsi.clone();
                return true;
            }
        }
        false
    }

    // Home management

    pub fn home_add(&self, plmn_id: &PlmnId, s_nssai: &SNssai) -> Option<NssfHome> {
        let mut home_list = self.home_list.write().ok()?;
        let mut home_hash = self.home_hash.write().ok()?;

        if home_list.len() >= self.max_num_of_nf {
            log::error!(
                "Maximum number of Home contexts [{}] reached",
                self.max_num_of_nf
            );
            return None;
        }

        let id = self.next_home_id.fetch_add(1, Ordering::SeqCst) as u64;
        let home = NssfHome::new(id, plmn_id.clone(), s_nssai.clone());

        let key = (
            plmn_id.mcc.clone(),
            plmn_id.mnc.clone(),
            s_nssai.sst,
            s_nssai.sd,
        );
        home_hash.insert(key, id);
        home_list.insert(id, home.clone());

        log::debug!(
            "NSSF Home added (id={}, plmn={}{}, sst={}, sd={:?})",
            id,
            plmn_id.mcc,
            plmn_id.mnc,
            s_nssai.sst,
            s_nssai.sd
        );
        Some(home)
    }

    pub fn home_remove(&self, id: u64) -> Option<NssfHome> {
        let mut home_list = self.home_list.write().ok()?;
        let mut home_hash = self.home_hash.write().ok()?;

        if let Some(home) = home_list.remove(&id) {
            let key = (
                home.plmn_id.mcc.clone(),
                home.plmn_id.mnc.clone(),
                home.s_nssai.sst,
                home.s_nssai.sd,
            );
            home_hash.remove(&key);
            log::debug!("NSSF Home removed (id={id})");
            return Some(home);
        }
        None
    }

    pub fn home_remove_all(&self) {
        if let (Ok(mut home_list), Ok(mut home_hash)) =
            (self.home_list.write(), self.home_hash.write())
        {
            home_list.clear();
            home_hash.clear();
        }
    }

    pub fn home_find(&self, plmn_id: &PlmnId, s_nssai: &SNssai) -> Option<NssfHome> {
        // Lock order home_list < home_hash (matches home_add/home_remove); taking
        // home_hash first would be an AB-BA deadlock vs home_add (live under
        // concurrent SBI reads in nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf).
        let home_list = self.home_list.read().ok()?;
        let home_hash = self.home_hash.read().ok()?;
        let key = (
            plmn_id.mcc.clone(),
            plmn_id.mnc.clone(),
            s_nssai.sst,
            s_nssai.sd,
        );
        home_hash
            .get(&key)
            .and_then(|&id| home_list.get(&id).cloned())
    }

    pub fn home_find_by_id(&self, id: u64) -> Option<NssfHome> {
        let home_list = self.home_list.read().ok()?;
        home_list.get(&id).cloned()
    }

    pub fn home_update(&self, home: &NssfHome) -> bool {
        if let Ok(mut home_list) = self.home_list.write() {
            if let Some(existing) = home_list.get_mut(&home.id) {
                *existing = home.clone();
                return true;
            }
        }
        false
    }

    // NSSAI Availability management (B24.4)

    pub fn set_nssai_availability(&self, nf_id: &str, info: NssaiAvailabilityInfo) {
        {
            if let Ok(mut avail) = self.nssai_availability.write() {
                avail.insert(nf_id.to_string(), info);
            }
        }
        self.persist();
    }

    pub fn get_nssai_availability(&self, nf_id: &str) -> Option<NssaiAvailabilityInfo> {
        let avail = self.nssai_availability.read().ok()?;
        avail.get(nf_id).cloned()
    }

    pub fn remove_nssai_availability(&self, nf_id: &str) -> bool {
        let removed = {
            if let Ok(mut avail) = self.nssai_availability.write() {
                avail.remove(nf_id).is_some()
            } else {
                false
            }
        };
        if removed {
            self.persist();
        }
        removed
    }

    /// Snapshot all stored availability docs (nfId, doc)
    pub fn all_nssai_availability(&self) -> Vec<NssaiAvailabilityInfo> {
        self.nssai_availability
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// True if any availability data has been provided by any NF
    pub fn has_availability_data(&self) -> bool {
        self.nssai_availability
            .read()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
    }

    /// Per-AMF supported S-NSSAIs snapshot: (nfId, supported list)
    pub fn per_nf_supported_snssais(&self) -> Vec<(String, Vec<SNssai>)> {
        self.nssai_availability
            .read()
            .map(|m| {
                m.values()
                    .map(|i| (i.nf_id.clone(), i.supported_snssai_list.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    // Availability-change subscription management (TS 29.531 §5.2.2.5)

    pub fn subscription_add(&self, sub: NssfSubscription) {
        {
            if let Ok(mut subs) = self.subscriptions.write() {
                subs.insert(sub.subscription_id.clone(), sub);
            }
        }
        self.persist();
    }

    pub fn subscription_get(&self, id: &str) -> Option<NssfSubscription> {
        self.subscriptions.read().ok()?.get(id).cloned()
    }

    pub fn subscription_remove(&self, id: &str) -> bool {
        let removed = self
            .subscriptions
            .write()
            .map(|mut subs| subs.remove(id).is_some())
            .unwrap_or(false);
        if removed {
            self.persist();
        }
        removed
    }

    pub fn subscription_update(&self, sub: NssfSubscription) -> bool {
        let updated = {
            if let Ok(mut subs) = self.subscriptions.write() {
                if subs.contains_key(&sub.subscription_id) {
                    subs.insert(sub.subscription_id.clone(), sub);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if updated {
            self.persist();
        }
        updated
    }

    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Subscriptions whose TAI list intersects `affected_tais`
    /// (a subscription with an empty TAI list matches everything).
    pub fn subscriptions_matching(&self, affected_tais: &[Tai]) -> Vec<NssfSubscription> {
        self.subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| {
                        s.tai_list.is_empty()
                            || s.tai_list
                                .iter()
                                .any(|st| affected_tais.iter().any(|at| tai_eq(st, at)))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // Target AMF set configuration

    pub fn set_target_amf_set(&self, set_id: &str) {
        if let Ok(mut t) = self.target_amf_set.write() {
            *t = Some(set_id.to_string());
        }
    }

    /// Clear the configured target AMF set (reverts to `None`).
    pub fn clear_target_amf_set(&self) {
        if let Ok(mut t) = self.target_amf_set.write() {
            *t = None;
        }
    }

    pub fn get_target_amf_set(&self) -> Option<String> {
        self.target_amf_set.read().ok()?.clone()
    }

    // -- NSSAI-availability authorization & PLMN S-NSSAI support (nssfd-01) --

    /// Configure (or clear) the set of S-NSSAIs supported in this PLMN.
    ///
    /// `Some(list)` installs an explicit restriction; `None` clears it,
    /// restoring the default allow-all behaviour (matched-sim back-compat).
    pub fn set_plmn_supported_snssais(&self, list: Option<Vec<SNssai>>) {
        if let Ok(mut g) = self.plmn_supported_snssai_restriction.write() {
            *g = list;
        }
    }

    /// The PLMN-supported S-NSSAI set sourced from NSSF configuration
    /// (TS 29.531 §6.2.3.2.3.1). Returns an empty vector when NO restriction
    /// is configured; callers MUST consult [`Self::has_plmn_snssai_restriction`]
    /// to distinguish "no restriction (allow all)" from "restricted to {}".
    pub fn plmn_supported_snssais(&self) -> Vec<SNssai> {
        self.plmn_supported_snssai_restriction
            .read()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_default()
    }

    /// Whether an explicit PLMN-supported-S-NSSAI restriction is configured.
    ///
    /// Default-allow stance (TS 29.531 §6.2.3.2.3.1 + matched-sim back-compat):
    /// when this is `false` the NSSF accepts ANY reported S-NSSAI; only an
    /// explicitly configured restriction can trigger 403 SNSSAI_NOT_SUPPORTED.
    pub fn has_plmn_snssai_restriction(&self) -> bool {
        self.plmn_supported_snssai_restriction
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Whether the NF service consumer identified by `nf_id` is authorized to
    /// update the NSSAI-availability information for `_tai` (TS 33.521).
    ///
    /// Default-allow stance (matched-sim back-compat): authorize any non-empty
    /// NF Id and reject only a missing/empty NF Id, rather than requiring an
    /// NRF round-trip that would break the matched simulator's AMF. `_tai` is
    /// accepted for spec fidelity and future per-TA authorization (TS 33.521)
    /// but is not consulted under the default-allow policy.
    pub fn nf_authorized_for_availability(&self, nf_id: &str, _tai: &Tai) -> bool {
        !nf_id.trim().is_empty()
    }

    // -- nssfd-02: per-home-PLMN S-NSSAI restrictions (restrictedSnssaiList) --

    /// Configure S-NSSAI restrictions for a specific home PLMN
    /// (TS 29.531 §5.3.2.2 / §6.2.6.2.4 `restrictedSnssaiList`).
    ///
    /// When configured, `authorized_availability_response` includes these in
    /// the `restrictedSnssaiList` of the `AuthorizedNssaiAvailabilityData`
    /// response. Default: empty map (no restrictions).
    pub fn set_plmn_snssai_restrictions(&self, home_plmn: &PlmnId, restricted: Vec<SNssai>) {
        if let Ok(mut m) = self.per_plmn_snssai_restrictions.write() {
            m.insert((home_plmn.mcc.clone(), home_plmn.mnc.clone()), restricted);
        }
    }

    /// Clear all per-PLMN S-NSSAI restrictions (restores matched-sim
    /// back-compat / default-allow state).
    pub fn clear_plmn_snssai_restrictions(&self) {
        if let Ok(mut m) = self.per_plmn_snssai_restrictions.write() {
            m.clear();
        }
    }

    /// Per-PLMN S-NSSAI restrictions for a given TAI
    /// (TS 29.531 §5.3.2.2 / §6.2.6.2.4). Returns an empty `Vec` when no
    /// restrictions are configured. The `_tai` parameter is accepted for
    /// future per-TA scoping; the current implementation uses the global
    /// per-PLMN map (TAI-scoped restrictions are not yet config-driven).
    pub fn restricted_snssais_for_tai(&self, _tai: &Tai) -> Vec<(PlmnId, Vec<SNssai>)> {
        self.per_plmn_snssai_restrictions
            .read()
            .map(|m| {
                m.iter()
                    .map(|((mcc, mnc), snssais)| (PlmnId::new(mcc, mnc), snssais.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get supported S-NSSAIs for a specific TAI from NSSAI availability data.
    ///
    /// Walks the per-TA `supportedNssaiAvailabilityData` entries of each
    /// stored doc so the TAI -> S-NSSAI association is preserved (an AMF may
    /// support different slices in different TAs).
    pub fn get_supported_snssai_for_tai(&self, tai: &Tai) -> Vec<SNssai> {
        let mut result: Vec<SNssai> = Vec::new();
        if let Ok(avail) = self.nssai_availability.read() {
            for info in avail.values() {
                for (entry_tais, entry_snssais) in availability_entries(&info.doc) {
                    if entry_tais.iter().any(|t| tai_eq(t, tai)) {
                        for snssai in entry_snssais {
                            if !result.contains(&snssai) {
                                result.push(snssai);
                            }
                        }
                    }
                }
            }
        }
        result
    }

    /// Get all NSI entries
    pub fn nsi_get_all(&self) -> Vec<NssfNsi> {
        self.nsi_list
            .read()
            .map(|l| l.values().cloned().collect())
            .expect("value expected")
    }

    /// Get NSI load percentage
    pub fn get_nsi_load(&self) -> i32 {
        let nsi_count = self.nsi_list.read().map(|l| l.len()).unwrap_or(0);
        if self.max_num_of_nf == 0 {
            return 0;
        }
        ((nsi_count * 100) / self.max_num_of_nf) as i32
    }

    pub fn nsi_count(&self) -> usize {
        self.nsi_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn home_count(&self) -> usize {
        self.home_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for NssfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NSSF context (thread-safe singleton)
static GLOBAL_NSSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NssfContext>>> =
    std::sync::OnceLock::new();

/// Get the global NSSF context
pub fn nssf_self() -> Arc<RwLock<NssfContext>> {
    GLOBAL_NSSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NssfContext::new())))
        .clone()
}

/// Initialise the global NSSF context with an on-disk snapshot path for
/// NSSAI-availability subscriptions and availability data, restoring any
/// previously persisted state. Must be called before the first [`nssf_self`]
/// use to take effect; returns `false` if the context was already initialised.
///
/// Passing `None` leaves the context purely in-memory (the default).
pub fn nssf_context_init_with_state(state_path: Option<PathBuf>) -> bool {
    let ctx = match state_path {
        Some(p) => NssfContext::with_state_path(p),
        None => NssfContext::new(),
    };
    GLOBAL_NSSF_CONTEXT.set(Arc::new(RwLock::new(ctx))).is_ok()
}

/// Initialize the global NSSF context
pub fn nssf_context_init(max_nf: usize) {
    let ctx = nssf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_nf);
    };
}

/// Finalize the global NSSF context
pub fn nssf_context_final() {
    let ctx = nssf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get NSI load (for NF instance load reporting)
pub fn get_nsi_load() -> i32 {
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        return context.get_nsi_load();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nssf_context_new() {
        let ctx = NssfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.nsi_count(), 0);
        assert_eq!(ctx.home_count(), 0);
    }

    #[test]
    fn test_nssf_context_init_fini() {
        let mut ctx = NssfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_nsi_add_remove() {
        let mut ctx = NssfContext::new();
        ctx.init(100);

        let nsi = ctx
            .nsi_add("http://nrf.example.com", 1, Some(0x010203))
            .unwrap();
        assert_eq!(nsi.s_nssai.sst, 1);
        assert_eq!(nsi.s_nssai.sd, Some(0x010203));
        assert_eq!(ctx.nsi_count(), 1);

        let found = ctx.nsi_find_by_s_nssai(&SNssai::new(1, Some(0x010203)));
        assert!(found.is_some());

        ctx.nsi_remove(nsi.id);
        assert_eq!(ctx.nsi_count(), 0);
    }

    #[test]
    fn test_home_add_remove() {
        let mut ctx = NssfContext::new();
        ctx.init(100);

        let plmn_id = PlmnId::new("001", "01");
        let s_nssai = SNssai::new(1, Some(0x010203));
        let home = ctx.home_add(&plmn_id, &s_nssai).unwrap();
        assert_eq!(home.plmn_id.mcc, "001");
        assert_eq!(ctx.home_count(), 1);

        let found = ctx.home_find(&plmn_id, &s_nssai);
        assert!(found.is_some());

        ctx.home_remove(home.id);
        assert_eq!(ctx.home_count(), 0);
    }

    #[test]
    fn test_get_nsi_load() {
        let mut ctx = NssfContext::new();
        ctx.init(100);

        assert_eq!(ctx.get_nsi_load(), 0);

        // Add 10 NSIs
        for i in 0..10 {
            ctx.nsi_add(&format!("http://nrf{i}.example.com"), i as u8, None);
        }

        assert_eq!(ctx.get_nsi_load(), 10); // 10/100 = 10%
    }

    #[test]
    fn test_snssai() {
        let s1 = SNssai::new(1, Some(0x010203));
        let s2 = SNssai::from_sst_sd(1, 0x010203);
        assert_eq!(s1, s2);

        let s3 = SNssai::from_sst_sd(1, 0xFFFFFF);
        assert_eq!(s3.sd, None);
    }

    #[test]
    fn test_nsi_id_is_uuid_not_sequential() {
        let mut ctx = NssfContext::new();
        ctx.init(100);
        let a = ctx.nsi_add("http://nrf", 1, None).unwrap();
        let b = ctx.nsi_add("http://nrf", 2, None).unwrap();
        // UUID v4 string form: 36 chars with 4 hyphens
        assert_eq!(a.nsi_id.len(), 36);
        assert_eq!(a.nsi_id.matches('-').count(), 4);
        assert_ne!(a.nsi_id, b.nsi_id);
        assert!(
            a.nsi_id.parse::<u64>().is_err(),
            "nsiId must not be a pool index"
        );
    }

    #[test]
    fn test_subscription_store() {
        let mut ctx = NssfContext::new();
        ctx.init(100);

        let tai = Tai {
            plmn_id: PlmnId::new("999", "70"),
            tac: 200,
        };
        let sub = NssfSubscription {
            subscription_id: "sub-1".to_string(),
            nf_nssai_availability_uri: "http://127.0.0.1:9999/cb".to_string(),
            tai_list: vec![tai.clone()],
            event: "SNSSAI_STATUS_CHANGE_REPORT".to_string(),
            expiry: None,
            amf_id: None,
            amf_set_id: None,
        };
        ctx.subscription_add(sub);
        assert_eq!(ctx.subscription_count(), 1);
        assert!(ctx.subscription_get("sub-1").is_some());

        // Matching: same TAI matches, different TAC does not
        assert_eq!(
            ctx.subscriptions_matching(std::slice::from_ref(&tai)).len(),
            1
        );
        let other = Tai {
            plmn_id: PlmnId::new("999", "70"),
            tac: 999,
        };
        assert!(ctx.subscriptions_matching(&[other]).is_empty());

        assert!(ctx.subscription_remove("sub-1"));
        assert!(!ctx.subscription_remove("sub-1"));
    }

    fn temp_state_path(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("nssfd-test-{tag}-{pid}-{nanos}.json"))
    }

    /// Add an NSSAI-availability subscription (and availability data) on a
    /// persisting context, then re-open from the same file (simulated restart)
    /// and confirm both are retained, including the TAI list and matching.
    #[test]
    fn test_nssf_persistence_survives_restart() {
        let path = temp_state_path("restart");
        let _ = std::fs::remove_file(&path);

        let tai = Tai {
            plmn_id: PlmnId::new("999", "70"),
            tac: 200,
        };
        let avail_doc = serde_json::json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });

        // First lifetime: subscribe + set availability, then drop the context.
        {
            let ctx = NssfContext::with_state_path(&path);
            ctx.subscription_add(NssfSubscription {
                subscription_id: "sub-restart".to_string(),
                nf_nssai_availability_uri: "http://amf:9999/cb".to_string(),
                tai_list: vec![tai.clone()],
                event: "SNSSAI_STATUS_CHANGE_REPORT".to_string(),
                expiry: Some("2030-01-01T00:00:00Z".to_string()),
                amf_id: Some("amf-1".to_string()),
                amf_set_id: None,
            });
            ctx.set_nssai_availability(
                "amf-1",
                availability_info_from_doc("amf-1", avail_doc.clone()),
            );
        }

        // Second lifetime: a fresh context re-opened from the same file.
        {
            let ctx = NssfContext::with_state_path(&path);
            assert_eq!(ctx.subscription_count(), 1);
            let sub = ctx
                .subscription_get("sub-restart")
                .expect("subscription retained across restart");
            assert_eq!(sub.nf_nssai_availability_uri, "http://amf:9999/cb");
            assert_eq!(sub.event, "SNSSAI_STATUS_CHANGE_REPORT");
            assert_eq!(sub.expiry.as_deref(), Some("2030-01-01T00:00:00Z"));
            assert_eq!(sub.amf_id.as_deref(), Some("amf-1"));
            assert_eq!(sub.tai_list.len(), 1);
            assert_eq!(sub.tai_list[0].tac, 200);
            assert_eq!(sub.tai_list[0].plmn_id.mcc, "999");
            // TAI matching still works after restore.
            assert_eq!(
                ctx.subscriptions_matching(std::slice::from_ref(&tai)).len(),
                1
            );
            // Availability data was retained and is reconstructible.
            let info = ctx
                .get_nssai_availability("amf-1")
                .expect("availability retained across restart");
            assert_eq!(info.supported_snssai_list, vec![SNssai::new(1, None)]);
            assert_eq!(info.doc, avail_doc);
        }

        let _ = std::fs::remove_file(&path);
    }

    /// A subscription removal must also be persisted (no resurrection).
    #[test]
    fn test_nssf_persistence_remove_survives_restart() {
        let path = temp_state_path("remove");
        let _ = std::fs::remove_file(&path);
        {
            let ctx = NssfContext::with_state_path(&path);
            ctx.subscription_add(NssfSubscription {
                subscription_id: "sub-x".to_string(),
                nf_nssai_availability_uri: "http://amf:1/cb".to_string(),
                tai_list: vec![],
                event: "SNSSAI_STATUS_CHANGE_REPORT".to_string(),
                expiry: None,
                amf_id: None,
                amf_set_id: None,
            });
            assert!(ctx.subscription_remove("sub-x"));
        }
        {
            let ctx = NssfContext::with_state_path(&path);
            assert!(
                ctx.subscription_get("sub-x").is_none(),
                "removed subscription must not reappear after restart"
            );
            assert_eq!(ctx.subscription_count(), 0);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// No path configured => no file written, context stays in-memory.
    #[test]
    fn test_nssf_no_path_is_pure_memory() {
        let ctx = NssfContext::new();
        ctx.subscription_add(NssfSubscription {
            subscription_id: "s".to_string(),
            nf_nssai_availability_uri: "http://a/cb".to_string(),
            tai_list: vec![],
            event: "E".to_string(),
            expiry: None,
            amf_id: None,
            amf_set_id: None,
        });
        ctx.persist(); // no-op without a path
        assert!(ctx.state_path.is_none());
    }

    #[test]
    fn test_availability_entries_per_ta() {
        let doc = serde_json::json!({
            "supportedNssaiAvailabilityData": [
                {
                    "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                    "supportedSnssaiList": [{"sst": 1}]
                },
                {
                    "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000002"},
                    "supportedSnssaiList": [{"sst": 2, "sd": "0a0b0c"}]
                }
            ]
        });
        let entries = availability_entries(&doc);
        assert_eq!(entries.len(), 2);

        // get_supported_snssai_for_tai must NOT flatten across TAs
        let mut ctx = NssfContext::new();
        ctx.init(100);
        ctx.set_nssai_availability("amf-x", availability_info_from_doc("amf-x", doc));
        let tai1 = Tai {
            plmn_id: PlmnId::new("999", "70"),
            tac: 1,
        };
        let supported = ctx.get_supported_snssai_for_tai(&tai1);
        assert_eq!(supported, vec![SNssai::new(1, None)]);
    }

    #[test]
    fn test_snssai_tai_json_roundtrip() {
        let s = SNssai::new(7, Some(0x0A0B0C));
        let parsed = snssai_from_json(&snssai_to_json(&s)).unwrap();
        assert_eq!(parsed, s);

        let t = Tai {
            plmn_id: PlmnId::new("001", "01"),
            tac: 0xABC,
        };
        let parsed = tai_from_json(&tai_to_json(&t)).unwrap();
        assert_eq!(parsed.tac, 0xABC);
        assert_eq!(parsed.plmn_id.mcc, "001");

        // Invalid inputs are rejected, not defaulted
        assert!(snssai_from_json(&serde_json::json!({"sd": "010203"})).is_none());
        assert!(snssai_from_json(&serde_json::json!({"sst": 1, "sd": 42})).is_none());
        assert!(tai_from_json(&serde_json::json!({"tac": "000001"})).is_none());
    }

    #[test]
    fn test_roaming_indication() {
        assert_eq!(
            RoamingIndication::from_openapi(1),
            RoamingIndication::NonRoaming
        );
        assert_eq!(
            RoamingIndication::from_openapi(2),
            RoamingIndication::LocalBreakout
        );
        assert_eq!(
            RoamingIndication::from_openapi(3),
            RoamingIndication::HomeRouted
        );
        assert_eq!(RoamingIndication::NonRoaming.to_openapi(), 1);
    }
}
