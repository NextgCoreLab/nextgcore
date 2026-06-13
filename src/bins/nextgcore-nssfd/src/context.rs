//! NSSF Context Management
//!
//! Port of src/nssf/context.c - NSSF context with NSI list and Home list

use std::collections::HashMap;
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
    /// Next NSI ID
    next_nsi_id: AtomicUsize,
    /// Next Home ID
    next_home_id: AtomicUsize,
    /// Maximum number of NF instances (pool size)
    max_num_of_nf: usize,
    /// Context initialized flag
    initialized: AtomicBool,
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
            next_nsi_id: AtomicUsize::new(1),
            next_home_id: AtomicUsize::new(1),
            max_num_of_nf: 0,
            initialized: AtomicBool::new(false),
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
        let snssai_hash = self.snssai_hash.read().ok()?;
        let nsi_list = self.nsi_list.read().ok()?;
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
        let home_hash = self.home_hash.read().ok()?;
        let home_list = self.home_list.read().ok()?;
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
        if let Ok(mut avail) = self.nssai_availability.write() {
            avail.insert(nf_id.to_string(), info);
        }
    }

    pub fn get_nssai_availability(&self, nf_id: &str) -> Option<NssaiAvailabilityInfo> {
        let avail = self.nssai_availability.read().ok()?;
        avail.get(nf_id).cloned()
    }

    pub fn remove_nssai_availability(&self, nf_id: &str) -> bool {
        if let Ok(mut avail) = self.nssai_availability.write() {
            return avail.remove(nf_id).is_some();
        }
        false
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
        if let Ok(mut subs) = self.subscriptions.write() {
            subs.insert(sub.subscription_id.clone(), sub);
        }
    }

    pub fn subscription_get(&self, id: &str) -> Option<NssfSubscription> {
        self.subscriptions.read().ok()?.get(id).cloned()
    }

    pub fn subscription_remove(&self, id: &str) -> bool {
        self.subscriptions
            .write()
            .map(|mut subs| subs.remove(id).is_some())
            .unwrap_or(false)
    }

    pub fn subscription_update(&self, sub: NssfSubscription) -> bool {
        if let Ok(mut subs) = self.subscriptions.write() {
            if subs.contains_key(&sub.subscription_id) {
                subs.insert(sub.subscription_id.clone(), sub);
                return true;
            }
        }
        false
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

    pub fn get_target_amf_set(&self) -> Option<String> {
        self.target_amf_set.read().ok()?.clone()
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
