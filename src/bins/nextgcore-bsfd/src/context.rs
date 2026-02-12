//! BSF Context Management
//!
//! Port of src/bsf/context.c - BSF context with session management and IP address hashing

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use ogs_dbi::mongoc::{ogs_mongoc, DbiResult};

/// Maximum number of IP addresses for PCF
pub const MAX_NUM_OF_PCF_IP: usize = 8;

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

    /// Convert SD to string representation
    pub fn sd_to_string(&self) -> Option<String> {
        self.sd.map(|sd| format!("{sd:06X}"))
    }

    /// Parse SD from string
    pub fn sd_from_string(s: &str) -> Option<u32> {
        u32::from_str_radix(s, 16).ok()
    }
}

/// PCF IP endpoint information
#[derive(Debug, Clone, Default)]
pub struct PcfIpEndpoint {
    pub addr: Option<String>,
    pub addr6: Option<String>,
    pub is_port: bool,
    pub port: u16,
}

/// IPv6 prefix structure
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    pub len: u8,
    pub addr6: [u8; 16],
}

impl Ipv6Prefix {
    pub fn from_string(prefix_str: &str) -> Option<Self> {
        let parts: Vec<&str> = prefix_str.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let addr: Ipv6Addr = parts[0].parse().ok()?;
        let len: u8 = parts[1].parse().ok()?;
        
        Some(Self {
            len,
            addr6: addr.octets(),
        })
    }

    /// Get hash key bytes (prefix length / 8 + 1 bytes)
    pub fn hash_key(&self) -> Vec<u8> {
        let key_len = (self.len as usize >> 3) + 1;
        let mut key = vec![self.len];
        key.extend_from_slice(&self.addr6[..key_len.min(16)]);
        key
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = Ipv6Addr::from(self.addr6);
        write!(f, "{addr}/{}", self.len)
    }
}


/// BSF Session structure
/// Port of bsf_sess_t from context.h
#[derive(Debug, Clone)]
pub struct BsfSess {
    /// Session pool ID
    pub id: u64,
    /// Binding ID (string representation of pool index)
    pub binding_id: String,

    /// SUPI (Subscription Permanent Identifier)
    pub supi: Option<String>,
    /// GPSI (Generic Public Subscription Identifier)
    pub gpsi: Option<String>,

    /// IPv4 address string
    pub ipv4addr_string: Option<String>,
    /// IPv6 prefix string
    pub ipv6prefix_string: Option<String>,

    /// IPv4 frame route list
    pub ipv4_frame_route_list: Vec<String>,
    /// IPv6 frame route list
    pub ipv6_frame_route_list: Vec<String>,

    /// Parsed IPv4 address
    pub ipv4addr: Option<u32>,
    /// Parsed IPv6 prefix
    pub ipv6prefix: Option<Ipv6Prefix>,

    /// S-NSSAI
    pub s_nssai: SNssai,
    /// DNN (Data Network Name)
    pub dnn: Option<String>,

    /// PCF FQDN
    pub pcf_fqdn: Option<String>,
    /// PCF IP endpoints
    pub pcf_ip: Vec<PcfIpEndpoint>,

    /// SBI management features
    pub management_features: u64,
}

/// SBI feature flag for binding update
pub const SBI_NBSF_MANAGEMENT_BINDING_UPDATE: u64 = 1 << 0;

impl BsfSess {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            binding_id: id.to_string(),
            supi: None,
            gpsi: None,
            ipv4addr_string: None,
            ipv6prefix_string: None,
            ipv4_frame_route_list: Vec::new(),
            ipv6_frame_route_list: Vec::new(),
            ipv4addr: None,
            ipv6prefix: None,
            s_nssai: SNssai::default(),
            dnn: None,
            pcf_fqdn: None,
            pcf_ip: Vec::new(),
            management_features: SBI_NBSF_MANAGEMENT_BINDING_UPDATE,
        }
    }

    /// Set IPv4 address from string
    pub fn set_ipv4addr(&mut self, ipv4addr_string: &str) -> bool {
        match ipv4addr_string.parse::<Ipv4Addr>() {
            Ok(addr) => {
                self.ipv4addr = Some(u32::from(addr));
                self.ipv4addr_string = Some(ipv4addr_string.to_string());
                true
            }
            Err(_) => {
                log::error!("Failed to parse IPv4 address: {ipv4addr_string}");
                false
            }
        }
    }

    /// Set IPv6 prefix from string
    pub fn set_ipv6prefix(&mut self, ipv6prefix_string: &str) -> bool {
        match Ipv6Prefix::from_string(ipv6prefix_string) {
            Some(prefix) => {
                self.ipv6prefix = Some(prefix);
                self.ipv6prefix_string = Some(ipv6prefix_string.to_string());
                true
            }
            None => {
                log::error!("Failed to parse IPv6 prefix: {ipv6prefix_string}");
                false
            }
        }
    }

    /// Check if session has PCF IP information
    pub fn has_pcf_ip(&self) -> bool {
        !self.pcf_ip.is_empty()
    }

    /// Get number of PCF IP endpoints
    pub fn num_of_pcf_ip(&self) -> usize {
        self.pcf_ip.len()
    }
}


/// BSF Context - main context structure for BSF
/// Port of bsf_context_t from context.h
pub struct BsfContext {
    /// IPv4 address -> session ID hash
    ipv4addr_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 prefix -> session ID hash
    ipv6prefix_hash: RwLock<HashMap<Vec<u8>, u64>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, BsfSess>>,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Maximum number of sessions (pool size)
    max_num_of_sess: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl BsfContext {
    pub fn new() -> Self {
        Self {
            ipv4addr_hash: RwLock::new(HashMap::new()),
            ipv6prefix_hash: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            next_sess_id: AtomicUsize::new(1),
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("BSF context initialized with max {max_sess} sessions");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.sess_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("BSF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add session by IP address
    /// Port of bsf_sess_add_by_ip_address
    pub fn sess_add_by_ip_address(
        &self,
        ipv4addr_string: Option<&str>,
        ipv6prefix_string: Option<&str>,
    ) -> Option<BsfSess> {
        if ipv4addr_string.is_none() && ipv6prefix_string.is_none() {
            log::error!("Either IPv4 or IPv6 address must be provided");
            return None;
        }

        let mut sess_list = self.sess_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut sess = BsfSess::new(id);

        // Set IPv4 address
        if let Some(ipv4) = ipv4addr_string {
            if !sess.set_ipv4addr(ipv4) {
                return None;
            }
            // Add to IPv4 hash
            if let (Ok(mut hash), Some(addr)) = (self.ipv4addr_hash.write(), sess.ipv4addr) {
                hash.insert(addr, id);
            }
        }

        // Set IPv6 prefix
        if let Some(ipv6) = ipv6prefix_string {
            if !sess.set_ipv6prefix(ipv6) {
                return None;
            }
            // Add to IPv6 hash
            if let (Ok(mut hash), Some(ref prefix)) = (self.ipv6prefix_hash.write(), &sess.ipv6prefix) {
                hash.insert(prefix.hash_key(), id);
            }
        }

        sess_list.insert(id, sess.clone());
        log::debug!("BSF session added (id={id}, ipv4={ipv4addr_string:?}, ipv6={ipv6prefix_string:?})");
        
        Some(sess)
    }

    /// Remove session
    pub fn sess_remove(&self, id: u64) -> Option<BsfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        
        if let Some(sess) = sess_list.remove(&id) {
            // Remove from IPv4 hash
            if let (Ok(mut hash), Some(addr)) = (self.ipv4addr_hash.write(), sess.ipv4addr) {
                hash.remove(&addr);
            }
            // Remove from IPv6 hash
            if let (Ok(mut hash), Some(ref prefix)) = (self.ipv6prefix_hash.write(), &sess.ipv6prefix) {
                hash.remove(&prefix.hash_key());
            }
            log::debug!("BSF session removed (id={id})");
            return Some(sess);
        }
        None
    }

    /// Remove all sessions
    pub fn sess_remove_all(&self) {
        if let (Ok(mut sess_list), Ok(mut ipv4_hash), Ok(mut ipv6_hash)) = (
            self.sess_list.write(),
            self.ipv4addr_hash.write(),
            self.ipv6prefix_hash.write(),
        ) {
            sess_list.clear();
            ipv4_hash.clear();
            ipv6_hash.clear();
        }
    }

    /// Find session by pool index
    pub fn sess_find(&self, index: u64) -> Option<BsfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&index).cloned()
    }

    /// Find session by binding ID
    pub fn sess_find_by_binding_id(&self, binding_id: &str) -> Option<BsfSess> {
        let index: u64 = binding_id.parse().ok()?;
        self.sess_find(index)
    }

    /// Find session by IPv4 address string
    pub fn sess_find_by_ipv4addr(&self, ipv4addr_string: &str) -> Option<BsfSess> {
        let addr: Ipv4Addr = ipv4addr_string.parse().ok()?;
        let addr_u32 = u32::from(addr);
        
        let ipv4_hash = self.ipv4addr_hash.read().ok()?;
        let sess_id = ipv4_hash.get(&addr_u32)?;
        
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by IPv6 prefix string
    pub fn sess_find_by_ipv6prefix(&self, ipv6prefix_string: &str) -> Option<BsfSess> {
        let prefix = Ipv6Prefix::from_string(ipv6prefix_string)?;
        let key = prefix.hash_key();
        
        let ipv6_hash = self.ipv6prefix_hash.read().ok()?;
        let sess_id = ipv6_hash.get(&key)?;
        
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by S-NSSAI and DNN
    pub fn sess_find_by_snssai_and_dnn(&self, s_nssai: &SNssai, dnn: &str) -> Option<BsfSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess.s_nssai.sst == s_nssai.sst {
                if let Some(ref sess_dnn) = sess.dnn {
                    if sess_dnn.eq_ignore_ascii_case(dnn) {
                        return Some(sess.clone());
                    }
                }
            }
        }
        None
    }

    /// Update session in the context
    pub fn sess_update(&self, sess: &BsfSess) -> bool {
        if let Ok(mut sess_list) = self.sess_list.write() {
            if let Some(existing) = sess_list.get_mut(&sess.id) {
                *existing = sess.clone();
                return true;
            }
        }
        false
    }

    /// Get session load percentage
    pub fn get_sess_load(&self) -> i32 {
        let sess_count = self.sess_list.read().map(|l| l.len()).unwrap_or(0);
        if self.max_num_of_sess == 0 {
            return 0;
        }
        ((sess_count * 100) / self.max_num_of_sess) as i32
    }

    /// Get session count
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl BsfContext {
    /// Persist a session binding to the database (if available)
    pub fn sess_persist(&self, sess: &BsfSess) {
        if let Err(e) = bsf_db_upsert_binding(sess) {
            log::debug!("DB persistence unavailable, binding in-memory only: {e}");
        }
    }

    /// Remove a session binding from the database (if available)
    pub fn sess_unpersist(&self, binding_id: &str) {
        if let Err(e) = bsf_db_delete_binding(binding_id) {
            log::debug!("DB persistence unavailable for delete: {e}");
        }
    }

    /// Load persisted bindings from database on startup
    pub fn load_persisted_bindings(&self) {
        match bsf_db_load_all_bindings() {
            Ok(bindings) => {
                for sess in bindings {
                    if let Ok(mut sess_list) = self.sess_list.write() {
                        let id = sess.id;
                        // Update hashes
                        if let (Ok(mut ipv4_hash), Some(addr)) =
                            (self.ipv4addr_hash.write(), sess.ipv4addr)
                        {
                            ipv4_hash.insert(addr, id);
                        }
                        if let (Ok(mut ipv6_hash), Some(ref prefix)) =
                            (self.ipv6prefix_hash.write(), &sess.ipv6prefix)
                        {
                            ipv6_hash.insert(prefix.hash_key(), id);
                        }
                        sess_list.insert(id, sess);
                    }
                }
                log::info!("Loaded persisted BSF bindings from database");
            }
            Err(e) => {
                log::debug!("No persisted bindings loaded (DB unavailable): {e}");
            }
        }
    }
}

/// Get the BSF bindings collection from MongoDB
fn get_bsf_bindings_collection()
    -> DbiResult<ogs_dbi::mongodb::sync::Collection<ogs_dbi::mongodb::bson::Document>>
{
    let dbi = ogs_mongoc();
    let dbi_guard = dbi.lock().unwrap();
    let db = dbi_guard
        .mongoc
        .database
        .as_ref()
        .ok_or(ogs_dbi::DbiError::NotInitialized)?;
    Ok(db.collection("bsf_bindings"))
}

/// Upsert a BSF binding to MongoDB
fn bsf_db_upsert_binding(sess: &BsfSess) -> DbiResult<()> {
    let collection = get_bsf_bindings_collection()?;
    let filter = ogs_dbi::mongodb::bson::doc! { "binding_id": &sess.binding_id };

    let mut doc = ogs_dbi::mongodb::bson::doc! {
        "binding_id": &sess.binding_id,
        "id": sess.id as i64,
    };
    if let Some(ref supi) = sess.supi {
        doc.insert("supi", supi);
    }
    if let Some(ref gpsi) = sess.gpsi {
        doc.insert("gpsi", gpsi);
    }
    if let Some(ref ipv4) = sess.ipv4addr_string {
        doc.insert("ipv4Addr", ipv4);
    }
    if let Some(ref ipv6) = sess.ipv6prefix_string {
        doc.insert("ipv6Prefix", ipv6);
    }
    if let Some(ref dnn) = sess.dnn {
        doc.insert("dnn", dnn);
    }
    doc.insert("sst", sess.s_nssai.sst as i32);
    if let Some(sd) = sess.s_nssai.sd {
        doc.insert("sd", sd as i64);
    }
    if let Some(ref pcf_fqdn) = sess.pcf_fqdn {
        doc.insert("pcf_fqdn", pcf_fqdn);
    }

    let opts = ogs_dbi::mongodb::options::ReplaceOptions::builder()
        .upsert(true)
        .build();
    collection.replace_one(filter, doc, opts)?;

    log::debug!("BSF binding {} persisted to DB", sess.binding_id);
    Ok(())
}

/// Delete a BSF binding from MongoDB
fn bsf_db_delete_binding(binding_id: &str) -> DbiResult<()> {
    let collection = get_bsf_bindings_collection()?;
    let filter = ogs_dbi::mongodb::bson::doc! { "binding_id": binding_id };
    collection.delete_one(filter, None)?;
    log::debug!("BSF binding {binding_id} removed from DB");
    Ok(())
}

/// Load all BSF bindings from MongoDB
fn bsf_db_load_all_bindings() -> DbiResult<Vec<BsfSess>> {
    let collection = get_bsf_bindings_collection()?;
    let cursor = collection.find(ogs_dbi::mongodb::bson::doc! {}, None)?;

    let mut bindings = Vec::new();
    for result in cursor {
        let doc = result?;
        let id = doc.get_i64("id").unwrap_or(0) as u64;
        let mut sess = BsfSess::new(id);

        if let Ok(binding_id) = doc.get_str("binding_id") {
            sess.binding_id = binding_id.to_string();
        }
        if let Ok(supi) = doc.get_str("supi") {
            sess.supi = Some(supi.to_string());
        }
        if let Ok(gpsi) = doc.get_str("gpsi") {
            sess.gpsi = Some(gpsi.to_string());
        }
        if let Ok(ipv4) = doc.get_str("ipv4Addr") {
            sess.set_ipv4addr(ipv4);
        }
        if let Ok(ipv6) = doc.get_str("ipv6Prefix") {
            sess.set_ipv6prefix(ipv6);
        }
        if let Ok(dnn) = doc.get_str("dnn") {
            sess.dnn = Some(dnn.to_string());
        }
        if let Ok(sst) = doc.get_i32("sst") {
            sess.s_nssai.sst = sst as u8;
        }
        if let Ok(sd) = doc.get_i64("sd") {
            sess.s_nssai.sd = Some(sd as u32);
        }
        if let Ok(pcf_fqdn) = doc.get_str("pcf_fqdn") {
            sess.pcf_fqdn = Some(pcf_fqdn.to_string());
        }

        bindings.push(sess);
    }

    Ok(bindings)
}

impl Default for BsfContext {
    fn default() -> Self {
        Self::new()
    }
}


/// Global BSF context (thread-safe singleton)
static GLOBAL_BSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<BsfContext>>> = std::sync::OnceLock::new();

/// Get the global BSF context
pub fn bsf_self() -> Arc<RwLock<BsfContext>> {
    GLOBAL_BSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(BsfContext::new())))
        .clone()
}

/// Initialize the global BSF context
pub fn bsf_context_init(max_sess: usize) {
    let ctx = bsf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_sess);
    };
}

/// Finalize the global BSF context
pub fn bsf_context_final() {
    let ctx = bsf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get session load (for NF instance load reporting)
pub fn get_sess_load() -> i32 {
    let ctx = bsf_self();
    if let Ok(context) = ctx.read() {
        return context.get_sess_load();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsf_context_new() {
        let ctx = BsfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_bsf_context_init_fini() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_sess_add_by_ipv4() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_by_ip_address(Some("192.168.1.1"), None).unwrap();
        assert_eq!(sess.ipv4addr_string, Some("192.168.1.1".to_string()));
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_ipv4addr("192.168.1.1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, sess.id);
    }

    #[test]
    fn test_sess_add_by_ipv6() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_by_ip_address(None, Some("2001:db8::1/128")).unwrap();
        assert_eq!(sess.ipv6prefix_string, Some("2001:db8::1/128".to_string()));
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_ipv6prefix("2001:db8::1/128");
        assert!(found.is_some());
    }

    #[test]
    fn test_sess_add_by_both() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_by_ip_address(
            Some("10.0.0.1"), 
            Some("fd00::1/128")
        ).unwrap();
        
        assert!(sess.ipv4addr_string.is_some());
        assert!(sess.ipv6prefix_string.is_some());
    }

    #[test]
    fn test_sess_remove() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_by_ip_address(Some("192.168.1.1"), None).unwrap();
        assert_eq!(ctx.sess_count(), 1);

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);

        let found = ctx.sess_find_by_ipv4addr("192.168.1.1");
        assert!(found.is_none());
    }

    #[test]
    fn test_sess_find_by_binding_id() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_by_ip_address(Some("192.168.1.1"), None).unwrap();
        let binding_id = sess.binding_id.clone();

        let found = ctx.sess_find_by_binding_id(&binding_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, sess.id);
    }

    #[test]
    fn test_get_sess_load() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        assert_eq!(ctx.get_sess_load(), 0);

        // Add 10 sessions
        for i in 0..10 {
            ctx.sess_add_by_ip_address(Some(&format!("192.168.1.{i}")), None);
        }

        assert_eq!(ctx.get_sess_load(), 10); // 10/100 = 10%
    }

    #[test]
    fn test_snssai() {
        let s1 = SNssai::new(1, Some(0x010203));
        let s2 = SNssai::from_sst_sd(1, 0x010203);
        assert_eq!(s1, s2);

        let s3 = SNssai::from_sst_sd(1, 0xFFFFFF);
        assert_eq!(s3.sd, None);

        assert_eq!(s1.sd_to_string(), Some("010203".to_string()));
    }

    #[test]
    fn test_ipv6_prefix() {
        let prefix = Ipv6Prefix::from_string("2001:db8::1/64").unwrap();
        assert_eq!(prefix.len, 64);
        
        let prefix_str = prefix.to_string();
        assert!(prefix_str.contains("/64"));
    }

    #[test]
    fn test_bsf_sess_set_ipv4addr() {
        let mut sess = BsfSess::new(1);
        assert!(sess.set_ipv4addr("192.168.1.1"));
        assert_eq!(sess.ipv4addr_string, Some("192.168.1.1".to_string()));
        assert!(sess.ipv4addr.is_some());
    }

    #[test]
    fn test_bsf_sess_set_ipv6prefix() {
        let mut sess = BsfSess::new(1);
        assert!(sess.set_ipv6prefix("2001:db8::1/128"));
        assert_eq!(sess.ipv6prefix_string, Some("2001:db8::1/128".to_string()));
        assert!(sess.ipv6prefix.is_some());
    }
}
