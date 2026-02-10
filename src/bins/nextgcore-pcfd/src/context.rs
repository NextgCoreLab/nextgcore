//! PCF Context Management
//!
//! Port of src/pcf/context.c - PCF context with UE AM/SM lists, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Access type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessType {
    #[default]
    ThreeGppAccess,
    NonThreeGppAccess,
}

/// RAT type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RatType {
    #[default]
    Nr,
    Eutra,
    Wlan,
    Virtual,
}

/// PDU Session Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PduSessionType {
    #[default]
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

/// PLMN ID
#[derive(Debug, Clone, Default)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// AMF ID
#[derive(Debug, Clone, Default)]
pub struct AmfId {
    pub region: u8,
    pub set: u16,
    pub pointer: u8,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Default)]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

/// Subscribed Default QoS
#[derive(Debug, Clone, Default)]
pub struct SubscribedDefaultQos {
    pub five_qi: u8,
    pub priority_level: u8,
    pub arp_priority_level: u8,
    pub arp_preempt_cap: bool,
    pub arp_preempt_vuln: bool,
}

/// PCF UE AM (Access Management) context
/// Port of pcf_ue_am_t from context.h
#[derive(Debug, Clone)]
pub struct PcfUeAm {
    pub id: u64,
    pub association_id: String,
    pub supi: String,
    pub notification_uri: Option<String>,
    pub gpsi: Option<String>,
    pub access_type: AccessType,
    pub pei: Option<String>,
    pub guami: Guami,
    pub rat_type: RatType,
    /// SBI Features - AM Policy Control features
    pub am_policy_control_features: u64,
    /// Subscribed UE AMBR
    pub subscribed_ue_ambr: Option<Ambr>,
    /// Associated stream ID
    pub stream_id: Option<u64>,
    /// URSP rules for this UE (Rel-17, TS 24.526)
    pub ursp_rules: Vec<UrspRule>,
    /// RedCap UE flag (Rel-17)
    pub is_redcap: bool,
    /// SNPN NID (Rel-17)
    pub snpn_nid: Option<String>,
}

/// UE Route Selection Policy rule (TS 24.526)
#[derive(Debug, Clone)]
pub struct UrspRule {
    /// Rule precedence (lower = higher priority)
    pub precedence: u8,
    /// Traffic descriptor (app ID or domain)
    pub traffic_descriptor: String,
    /// Preferred S-NSSAI SST
    pub preferred_sst: Option<u8>,
    /// Preferred DNN
    pub preferred_dnn: Option<String>,
    /// SSC mode (1, 2, or 3)
    pub ssc_mode: Option<u8>,
}

impl PcfUeAm {
    pub fn new(id: u64, supi: &str) -> Self {
        Self {
            id,
            association_id: Uuid::new_v4().to_string(),
            supi: supi.to_string(),
            notification_uri: None,
            gpsi: None,
            access_type: AccessType::default(),
            pei: None,
            guami: Guami::default(),
            rat_type: RatType::default(),
            am_policy_control_features: 0,
            subscribed_ue_ambr: None,
            stream_id: None,
            ursp_rules: Vec::new(),
            is_redcap: false,
            snpn_nid: None,
        }
    }

    /// Generate default URSP rules based on UE subscription.
    ///
    /// In production, rules would come from UDR subscription data.
    /// This creates sensible defaults for standard slice types.
    pub fn generate_default_ursp_rules(&mut self) {
        self.ursp_rules = vec![
            UrspRule {
                precedence: 1,
                traffic_descriptor: "internet".to_string(),
                preferred_sst: Some(1), // eMBB
                preferred_dnn: Some("internet".to_string()),
                ssc_mode: Some(1),
            },
            UrspRule {
                precedence: 2,
                traffic_descriptor: "ims".to_string(),
                preferred_sst: Some(1),
                preferred_dnn: Some("ims".to_string()),
                ssc_mode: Some(1),
            },
            UrspRule {
                precedence: 3,
                traffic_descriptor: "v2x".to_string(),
                preferred_sst: Some(4), // V2X
                preferred_dnn: Some("v2x".to_string()),
                ssc_mode: Some(2),
            },
        ];
        log::info!("PCF: Generated {} URSP rules for SUPI={}", self.ursp_rules.len(), self.supi);
    }
}


/// PCF UE SM (Session Management) context
/// Port of pcf_ue_sm_t from context.h
#[derive(Debug, Clone)]
pub struct PcfUeSm {
    pub id: u64,
    pub supi: String,
    pub gpsi: Option<String>,
    /// List of session IDs belonging to this UE
    pub sess_ids: Vec<u64>,
}

impl PcfUeSm {
    pub fn new(id: u64, supi: &str) -> Self {
        Self {
            id,
            supi: supi.to_string(),
            gpsi: None,
            sess_ids: Vec::new(),
        }
    }

    pub fn is_last_session(&self) -> bool {
        self.sess_ids.len() == 1
    }
}

/// BSF Binding information
#[derive(Debug, Clone, Default)]
pub struct PcfBinding {
    pub resource_uri: Option<String>,
    pub id: Option<String>,
}

impl PcfBinding {
    pub fn is_associated(&self) -> bool {
        self.id.is_some()
    }

    pub fn clear(&mut self) {
        self.resource_uri = None;
        self.id = None;
    }

    pub fn store(&mut self, resource_uri: &str, id: &str) {
        self.resource_uri = Some(resource_uri.to_string());
        self.id = Some(id.to_string());
    }
}

/// Serving/Home PLMN presence
#[derive(Debug, Clone, Default)]
pub struct PlmnPresence {
    pub presence: bool,
    pub plmn_id: PlmnId,
}

/// PCF Session context
/// Port of pcf_sess_t from context.h
#[derive(Debug, Clone)]
pub struct PcfSess {
    pub id: u64,
    pub sm_policy_id: String,
    pub binding: PcfBinding,
    /// PDU Session Identity
    pub psi: u8,
    pub pdu_session_type: PduSessionType,
    /// DNN
    pub dnn: Option<String>,
    pub full_dnn: Option<String>,
    /// Serving PLMN
    pub serving: PlmnPresence,
    /// Home PLMN
    pub home: PlmnPresence,
    pub notification_uri: Option<String>,
    /// IPv4 address string
    pub ipv4addr_string: Option<String>,
    /// IPv6 prefix string
    pub ipv6prefix_string: Option<String>,
    /// IPv4 address (network byte order)
    pub ipv4addr: u32,
    /// IPv6 prefix
    pub ipv6prefix: Option<(u8, [u8; 16])>,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// SBI Features
    pub smpolicycontrol_features: u64,
    pub management_features: u64,
    pub policyauthorization_features: u64,
    /// Subscribed session AMBR
    pub subscribed_sess_ambr: Option<Ambr>,
    /// Subscribed default QoS
    pub subscribed_default_qos: Option<SubscribedDefaultQos>,
    /// App session IDs
    pub app_ids: Vec<u64>,
    /// Parent UE SM ID
    pub pcf_ue_sm_id: u64,
    /// Associated stream ID
    pub stream_id: Option<u64>,
}

impl PcfSess {
    pub fn new(id: u64, pcf_ue_sm_id: u64, psi: u8) -> Self {
        Self {
            id,
            sm_policy_id: Uuid::new_v4().to_string(),
            binding: PcfBinding::default(),
            psi,
            pdu_session_type: PduSessionType::default(),
            dnn: None,
            full_dnn: None,
            serving: PlmnPresence::default(),
            home: PlmnPresence::default(),
            notification_uri: None,
            ipv4addr_string: None,
            ipv6prefix_string: None,
            ipv4addr: 0,
            ipv6prefix: None,
            s_nssai: SNssai::default(),
            smpolicycontrol_features: 0,
            management_features: 0,
            policyauthorization_features: 0,
            subscribed_sess_ambr: None,
            subscribed_default_qos: None,
            app_ids: Vec::new(),
            pcf_ue_sm_id,
            stream_id: None,
        }
    }

    /// Set IPv4 address from string
    pub fn set_ipv4addr(&mut self, ipv4addr: &str) -> bool {
        if let Ok(addr) = ipv4addr.parse::<std::net::Ipv4Addr>() {
            self.ipv4addr_string = Some(ipv4addr.to_string());
            self.ipv4addr = u32::from(addr);
            true
        } else {
            false
        }
    }

    /// Set IPv6 prefix from string
    pub fn set_ipv6prefix(&mut self, ipv6prefix: &str) -> bool {
        // Parse format like "2001:db8::/64"
        let parts: Vec<&str> = ipv6prefix.split('/').collect();
        if parts.len() != 2 {
            return false;
        }
        if let (Ok(addr), Ok(len)) = (parts[0].parse::<std::net::Ipv6Addr>(), parts[1].parse::<u8>()) {
            self.ipv6prefix_string = Some(ipv6prefix.to_string());
            self.ipv6prefix = Some((len, addr.octets()));
            true
        } else {
            false
        }
    }
}


/// PCF App Session context
/// Port of pcf_app_t from context.h
#[derive(Debug, Clone)]
pub struct PcfApp {
    pub id: u64,
    pub app_session_id: String,
    pub notif_uri: Option<String>,
    /// Parent session ID
    pub sess_id: u64,
}

impl PcfApp {
    pub fn new(id: u64, sess_id: u64) -> Self {
        Self {
            id,
            app_session_id: Uuid::new_v4().to_string(),
            notif_uri: None,
            sess_id,
        }
    }
}

/// PCF Context - main context structure for PCF
/// Port of pcf_context_t from context.h
pub struct PcfContext {
    /// UE AM list (by pool ID)
    ue_am_list: RwLock<HashMap<u64, PcfUeAm>>,
    /// UE SM list (by pool ID)
    ue_sm_list: RwLock<HashMap<u64, PcfUeSm>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, PcfSess>>,
    /// App session list (by pool ID)
    app_list: RwLock<HashMap<u64, PcfApp>>,
    /// SUPI -> UE AM ID hash
    supi_am_hash: RwLock<HashMap<String, u64>>,
    /// SUPI -> UE SM ID hash
    supi_sm_hash: RwLock<HashMap<String, u64>>,
    /// IPv4 address -> Session ID hash
    ipv4addr_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 prefix -> Session ID hash
    ipv6prefix_hash: RwLock<HashMap<String, u64>>,
    /// Association ID -> UE AM ID hash
    association_id_hash: RwLock<HashMap<String, u64>>,
    /// SM Policy ID -> Session ID hash
    sm_policy_id_hash: RwLock<HashMap<String, u64>>,
    /// App Session ID -> App ID hash
    app_session_id_hash: RwLock<HashMap<String, u64>>,
    /// Next UE AM ID
    next_ue_am_id: AtomicUsize,
    /// Next UE SM ID
    next_ue_sm_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Next app ID
    next_app_id: AtomicUsize,
    /// Maximum number of UE AMs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl PcfContext {
    pub fn new() -> Self {
        Self {
            ue_am_list: RwLock::new(HashMap::new()),
            ue_sm_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            app_list: RwLock::new(HashMap::new()),
            supi_am_hash: RwLock::new(HashMap::new()),
            supi_sm_hash: RwLock::new(HashMap::new()),
            ipv4addr_hash: RwLock::new(HashMap::new()),
            ipv6prefix_hash: RwLock::new(HashMap::new()),
            association_id_hash: RwLock::new(HashMap::new()),
            sm_policy_id_hash: RwLock::new(HashMap::new()),
            app_session_id_hash: RwLock::new(HashMap::new()),
            next_ue_am_id: AtomicUsize::new(1),
            next_ue_sm_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            next_app_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_ue: usize, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_ue = max_ue;
        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("PCF context initialized with max {} UEs, {} sessions", max_ue, max_sess);
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.ue_am_remove_all();
        self.ue_sm_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PCF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // UE AM management

    pub fn ue_am_add(&self, supi: &str) -> Option<PcfUeAm> {
        let mut ue_am_list = self.ue_am_list.write().ok()?;
        let mut supi_am_hash = self.supi_am_hash.write().ok()?;
        let mut association_id_hash = self.association_id_hash.write().ok()?;

        if ue_am_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UE AMs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_am_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue_am = PcfUeAm::new(id, supi);

        supi_am_hash.insert(supi.to_string(), id);
        association_id_hash.insert(ue_am.association_id.clone(), id);
        ue_am_list.insert(id, ue_am.clone());

        log::debug!("[{}] PCF UE AM added (id={})", supi, id);
        Some(ue_am)
    }

    pub fn ue_am_remove(&self, id: u64) -> Option<PcfUeAm> {
        let mut ue_am_list = self.ue_am_list.write().ok()?;
        let mut supi_am_hash = self.supi_am_hash.write().ok()?;
        let mut association_id_hash = self.association_id_hash.write().ok()?;

        if let Some(ue_am) = ue_am_list.remove(&id) {
            supi_am_hash.remove(&ue_am.supi);
            association_id_hash.remove(&ue_am.association_id);
            log::debug!("[{}] PCF UE AM removed (id={})", ue_am.supi, id);
            return Some(ue_am);
        }
        None
    }

    pub fn ue_am_remove_all(&self) {
        if let (Ok(mut ue_am_list), Ok(mut supi_am_hash), Ok(mut association_id_hash)) = (
            self.ue_am_list.write(),
            self.supi_am_hash.write(),
            self.association_id_hash.write(),
        ) {
            ue_am_list.clear();
            supi_am_hash.clear();
            association_id_hash.clear();
        }
    }

    pub fn ue_am_find_by_supi(&self, supi: &str) -> Option<PcfUeAm> {
        let supi_am_hash = self.supi_am_hash.read().ok()?;
        let ue_am_list = self.ue_am_list.read().ok()?;
        supi_am_hash.get(supi).and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_association_id(&self, association_id: &str) -> Option<PcfUeAm> {
        let association_id_hash = self.association_id_hash.read().ok()?;
        let ue_am_list = self.ue_am_list.read().ok()?;
        association_id_hash.get(association_id).and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_id(&self, id: u64) -> Option<PcfUeAm> {
        let ue_am_list = self.ue_am_list.read().ok()?;
        ue_am_list.get(&id).cloned()
    }

    pub fn ue_am_update(&self, ue_am: &PcfUeAm) -> bool {
        if let Ok(mut ue_am_list) = self.ue_am_list.write() {
            if let Some(existing) = ue_am_list.get_mut(&ue_am.id) {
                *existing = ue_am.clone();
                return true;
            }
        }
        false
    }


    // UE SM management

    pub fn ue_sm_add(&self, supi: &str) -> Option<PcfUeSm> {
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;
        let mut supi_sm_hash = self.supi_sm_hash.write().ok()?;

        if ue_sm_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UE SMs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_sm_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue_sm = PcfUeSm::new(id, supi);

        supi_sm_hash.insert(supi.to_string(), id);
        ue_sm_list.insert(id, ue_sm.clone());

        log::debug!("[{}] PCF UE SM added (id={})", supi, id);
        Some(ue_sm)
    }

    pub fn ue_sm_remove(&self, id: u64) -> Option<PcfUeSm> {
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;
        let mut supi_sm_hash = self.supi_sm_hash.write().ok()?;

        if let Some(ue_sm) = ue_sm_list.remove(&id) {
            supi_sm_hash.remove(&ue_sm.supi);
            // Remove all sessions for this UE
            self.sess_remove_all_for_ue(id);
            log::debug!("[{}] PCF UE SM removed (id={})", ue_sm.supi, id);
            return Some(ue_sm);
        }
        None
    }

    pub fn ue_sm_remove_all(&self) {
        if let (Ok(mut ue_sm_list), Ok(mut supi_sm_hash)) = (
            self.ue_sm_list.write(),
            self.supi_sm_hash.write(),
        ) {
            ue_sm_list.clear();
            supi_sm_hash.clear();
        }
        // Clear sessions and apps
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.clear();
        }
        if let Ok(mut app_list) = self.app_list.write() {
            app_list.clear();
        }
    }

    pub fn ue_sm_find_by_supi(&self, supi: &str) -> Option<PcfUeSm> {
        let supi_sm_hash = self.supi_sm_hash.read().ok()?;
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        supi_sm_hash.get(supi).and_then(|&id| ue_sm_list.get(&id).cloned())
    }

    pub fn ue_sm_find_by_id(&self, id: u64) -> Option<PcfUeSm> {
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        ue_sm_list.get(&id).cloned()
    }

    pub fn ue_sm_update(&self, ue_sm: &PcfUeSm) -> bool {
        if let Ok(mut ue_sm_list) = self.ue_sm_list.write() {
            if let Some(existing) = ue_sm_list.get_mut(&ue_sm.id) {
                *existing = ue_sm.clone();
                return true;
            }
        }
        false
    }

    // Session management

    pub fn sess_add(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sess = PcfSess::new(id, pcf_ue_sm_id, psi);

        sm_policy_id_hash.insert(sess.sm_policy_id.clone(), id);
        sess_list.insert(id, sess.clone());

        // Add session ID to UE SM
        if let Some(ue_sm) = ue_sm_list.get_mut(&pcf_ue_sm_id) {
            ue_sm.sess_ids.push(id);
        }

        log::debug!("[ue_sm_id={}, psi={}] PCF session added (id={})", pcf_ue_sm_id, psi, id);
        Some(sess)
    }

    pub fn sess_remove(&self, id: u64) -> Option<PcfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
        let mut ipv4addr_hash = self.ipv4addr_hash.write().ok()?;
        let mut ipv6prefix_hash = self.ipv6prefix_hash.write().ok()?;
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            sm_policy_id_hash.remove(&sess.sm_policy_id);
            if sess.ipv4addr != 0 {
                ipv4addr_hash.remove(&sess.ipv4addr);
            }
            if let Some(ref prefix_str) = sess.ipv6prefix_string {
                ipv6prefix_hash.remove(prefix_str);
            }
            // Remove session ID from UE SM
            if let Some(ue_sm) = ue_sm_list.get_mut(&sess.pcf_ue_sm_id) {
                ue_sm.sess_ids.retain(|&sid| sid != id);
            }
            // Remove all apps for this session
            self.app_remove_all_for_sess(id);
            log::debug!("[psi={}] PCF session removed (id={})", sess.psi, id);
            return Some(sess);
        }
        None
    }

    fn sess_remove_all_for_ue(&self, pcf_ue_sm_id: u64) {
        if let Ok(mut sess_list) = self.sess_list.write() {
            let sess_ids: Vec<u64> = sess_list.values()
                .filter(|s| s.pcf_ue_sm_id == pcf_ue_sm_id)
                .map(|s| s.id)
                .collect();
            for id in sess_ids {
                sess_list.remove(&id);
            }
        }
    }

    pub fn sess_find_by_id(&self, id: u64) -> Option<PcfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    pub fn sess_find_by_sm_policy_id(&self, sm_policy_id: &str) -> Option<PcfSess> {
        let sm_policy_id_hash = self.sm_policy_id_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        sm_policy_id_hash.get(sm_policy_id).and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_find_by_psi(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values().find(|s| s.pcf_ue_sm_id == pcf_ue_sm_id && s.psi == psi).cloned()
    }

    pub fn sess_find_by_ipv4addr(&self, ipv4addr_string: &str) -> Option<PcfSess> {
        if let Ok(addr) = ipv4addr_string.parse::<std::net::Ipv4Addr>() {
            let ipv4addr = u32::from(addr);
            let ipv4addr_hash = self.ipv4addr_hash.read().ok()?;
            let sess_list = self.sess_list.read().ok()?;
            return ipv4addr_hash.get(&ipv4addr).and_then(|&id| sess_list.get(&id).cloned());
        }
        None
    }

    pub fn sess_find_by_ipv6addr(&self, ipv6prefix_string: &str) -> Option<PcfSess> {
        let ipv6prefix_hash = self.ipv6prefix_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        ipv6prefix_hash.get(ipv6prefix_string).and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_update(&self, sess: &PcfSess) -> bool {
        if let (Ok(mut sess_list), Ok(mut ipv4addr_hash), Ok(mut ipv6prefix_hash)) = (
            self.sess_list.write(),
            self.ipv4addr_hash.write(),
            self.ipv6prefix_hash.write(),
        ) {
            if let Some(existing) = sess_list.get_mut(&sess.id) {
                // Update IPv4 hash if changed
                if existing.ipv4addr != sess.ipv4addr {
                    if existing.ipv4addr != 0 {
                        ipv4addr_hash.remove(&existing.ipv4addr);
                    }
                    if sess.ipv4addr != 0 {
                        ipv4addr_hash.insert(sess.ipv4addr, sess.id);
                    }
                }
                // Update IPv6 hash if changed
                if existing.ipv6prefix_string != sess.ipv6prefix_string {
                    if let Some(ref old_prefix) = existing.ipv6prefix_string {
                        ipv6prefix_hash.remove(old_prefix);
                    }
                    if let Some(ref new_prefix) = sess.ipv6prefix_string {
                        ipv6prefix_hash.insert(new_prefix.clone(), sess.id);
                    }
                }
                *existing = sess.clone();
                return true;
            }
        }
        false
    }

    pub fn sessions_number_by_snssai_and_dnn(&self, pcf_ue_sm_id: u64, s_nssai: &SNssai, dnn: &str) -> usize {
        if let Ok(sess_list) = self.sess_list.read() {
            return sess_list.values()
                .filter(|s| s.pcf_ue_sm_id == pcf_ue_sm_id && &s.s_nssai == s_nssai && s.dnn.as_deref() == Some(dnn))
                .count();
        }
        0
    }


    // App session management

    pub fn app_add(&self, sess_id: u64) -> Option<PcfApp> {
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        let id = self.next_app_id.fetch_add(1, Ordering::SeqCst) as u64;
        let app = PcfApp::new(id, sess_id);

        app_session_id_hash.insert(app.app_session_id.clone(), id);
        app_list.insert(id, app.clone());

        // Add app ID to session
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            sess.app_ids.push(id);
        }

        log::debug!("[sess_id={}] PCF app added (id={})", sess_id, id);
        Some(app)
    }

    pub fn app_remove(&self, id: u64) -> Option<PcfApp> {
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(app) = app_list.remove(&id) {
            app_session_id_hash.remove(&app.app_session_id);
            // Remove app ID from session
            if let Some(sess) = sess_list.get_mut(&app.sess_id) {
                sess.app_ids.retain(|&aid| aid != id);
            }
            log::debug!("PCF app removed (id={})", id);
            return Some(app);
        }
        None
    }

    fn app_remove_all_for_sess(&self, sess_id: u64) {
        if let Ok(mut app_list) = self.app_list.write() {
            let app_ids: Vec<u64> = app_list.values()
                .filter(|a| a.sess_id == sess_id)
                .map(|a| a.id)
                .collect();
            for id in app_ids {
                app_list.remove(&id);
            }
        }
    }

    pub fn app_find_by_id(&self, id: u64) -> Option<PcfApp> {
        let app_list = self.app_list.read().ok()?;
        app_list.get(&id).cloned()
    }

    pub fn app_find_by_app_session_id(&self, app_session_id: &str) -> Option<PcfApp> {
        let app_session_id_hash = self.app_session_id_hash.read().ok()?;
        let app_list = self.app_list.read().ok()?;
        app_session_id_hash.get(app_session_id).and_then(|&id| app_list.get(&id).cloned())
    }

    pub fn app_update(&self, app: &PcfApp) -> bool {
        if let Ok(mut app_list) = self.app_list.write() {
            if let Some(existing) = app_list.get_mut(&app.id) {
                *existing = app.clone();
                return true;
            }
        }
        false
    }

    /// Get instance load percentage
    pub fn get_load(&self) -> i32 {
        let ue_am_count = self.ue_am_list.read().map(|l| l.len()).unwrap_or(0);
        let ue_sm_count = self.ue_sm_list.read().map(|l| l.len()).unwrap_or(0);
        let total = ue_am_count + ue_sm_count;
        let max = self.max_num_of_ue * 2;
        if max == 0 {
            return 0;
        }
        ((total * 100) / max) as i32
    }

    pub fn ue_am_count(&self) -> usize {
        self.ue_am_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn ue_sm_count(&self) -> usize {
        self.ue_sm_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn app_count(&self) -> usize {
        self.app_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for PcfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PCF context (thread-safe singleton)
static GLOBAL_PCF_CONTEXT: std::sync::OnceLock<Arc<RwLock<PcfContext>>> = std::sync::OnceLock::new();

/// Get the global PCF context
pub fn pcf_self() -> Arc<RwLock<PcfContext>> {
    GLOBAL_PCF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PcfContext::new())))
        .clone()
}

/// Initialize the global PCF context
pub fn pcf_context_init(max_ue: usize, max_sess: usize) {
    let ctx = pcf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue, max_sess);
    };
}

/// Finalize the global PCF context
pub fn pcf_context_final() {
    let ctx = pcf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get instance load (for NF instance load reporting)
pub fn pcf_instance_get_load() -> i32 {
    let ctx = pcf_self();
    if let Ok(context) = ctx.read() {
        return context.get_load();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcf_context_new() {
        let ctx = PcfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_am_count(), 0);
        assert_eq!(ctx.ue_sm_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_pcf_context_init_fini() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_am_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_am = ctx.ue_am_add("imsi-001010000000001").unwrap();
        assert_eq!(ue_am.supi, "imsi-001010000000001");
        assert_eq!(ctx.ue_am_count(), 1);

        let found = ctx.ue_am_find_by_supi("imsi-001010000000001");
        assert!(found.is_some());

        ctx.ue_am_remove(ue_am.id);
        assert_eq!(ctx.ue_am_count(), 0);
    }

    #[test]
    fn test_ue_sm_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        assert_eq!(ue_sm.supi, "imsi-001010000000001");
        assert_eq!(ctx.ue_sm_count(), 1);

        ctx.ue_sm_remove(ue_sm.id);
        assert_eq!(ctx.ue_sm_count(), 0);
    }

    #[test]
    fn test_sess_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        assert_eq!(sess.psi, 1);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_psi(ue_sm.id, 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_app_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        let app = ctx.app_add(sess.id).unwrap();
        assert_eq!(ctx.app_count(), 1);

        ctx.app_remove(app.id);
        assert_eq!(ctx.app_count(), 0);
    }

    #[test]
    fn test_sess_ipv4_lookup() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let mut sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        sess.set_ipv4addr("10.45.0.1");
        ctx.sess_update(&sess);

        let found = ctx.sess_find_by_ipv4addr("10.45.0.1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().psi, 1);
    }
}
