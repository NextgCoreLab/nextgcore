//! UDM Context Management
//!
//! Port of src/udm/context.c - UDM context with UE list, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Authentication type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    /// 5G AKA authentication
    FiveGAka,
    /// EAP-AKA' authentication
    EapAkaPrime,
    /// EAP-TLS authentication
    EapTls,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::FiveGAka
    }
}

/// RAT type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatType {
    /// NR (New Radio)
    Nr,
    /// EUTRA (LTE)
    Eutra,
    /// WLAN
    Wlan,
    /// Virtual
    Virtual,
}

impl Default for RatType {
    fn default() -> Self {
        RatType::Nr
    }
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// AMF ID
    pub amf_id: AmfId,
}

/// PLMN ID
#[derive(Debug, Clone, Default)]
pub struct PlmnId {
    /// Mobile Country Code
    pub mcc: String,
    /// Mobile Network Code
    pub mnc: String,
}

/// AMF ID
#[derive(Debug, Clone, Default)]
pub struct AmfId {
    /// AMF Region ID
    pub region: u8,
    /// AMF Set ID
    pub set: u16,
    /// AMF Pointer
    pub pointer: u8,
}

/// Authentication event data
#[derive(Debug, Clone, Default)]
pub struct AuthEvent {
    /// NF instance ID
    pub nf_instance_id: Option<String>,
    /// Success indicator
    pub success: bool,
    /// Time stamp
    pub time_stamp: Option<String>,
    /// Authentication type
    pub auth_type: Option<AuthType>,
    /// Serving network name
    pub serving_network_name: Option<String>,
}

/// AMF 3GPP Access Registration
#[derive(Debug, Clone, Default)]
pub struct Amf3GppAccessRegistration {
    /// AMF instance ID
    pub amf_instance_id: Option<String>,
    /// Dereg callback URI
    pub dereg_callback_uri: Option<String>,
    /// GUAMI
    pub guami: Option<Guami>,
    /// RAT type
    pub rat_type: Option<RatType>,
}

/// SMF Registration
#[derive(Debug, Clone, Default)]
pub struct SmfRegistration {
    /// SMF instance ID
    pub smf_instance_id: Option<String>,
    /// PDU session ID
    pub pdu_session_id: u8,
    /// Single NSSAI
    pub single_nssai: Option<String>,
    /// DNN
    pub dnn: Option<String>,
    /// PLMN ID
    pub plmn_id: Option<PlmnId>,
}


/// Key length constant
pub const OGS_KEY_LEN: usize = 16;
/// AMF length constant
pub const OGS_AMF_LEN: usize = 2;
/// RAND length constant
pub const OGS_RAND_LEN: usize = 16;
/// SQN length constant
pub const OGS_SQN_LEN: usize = 6;

/// UDM UE context
#[derive(Debug, Clone)]
pub struct UdmUe {
    /// Unique pool ID
    pub id: u64,
    /// Context ID (string representation of pool index)
    pub ctx_id: String,
    /// SUCI (Subscription Concealed Identifier)
    pub suci: String,
    /// SUPI (Subscription Permanent Identifier)
    pub supi: Option<String>,
    /// Serving network name
    pub serving_network_name: Option<String>,
    /// AUSF instance ID
    pub ausf_instance_id: Option<String>,
    /// AMF instance ID
    pub amf_instance_id: Option<String>,
    /// Deregistration callback URI
    pub dereg_callback_uri: Option<String>,
    /// K key (16 bytes)
    pub k: [u8; OGS_KEY_LEN],
    /// OPc key (16 bytes)
    pub opc: [u8; OGS_KEY_LEN],
    /// AMF value (2 bytes)
    pub amf: [u8; OGS_AMF_LEN],
    /// RAND value (16 bytes)
    pub rand: [u8; OGS_RAND_LEN],
    /// SQN value (6 bytes)
    pub sqn: [u8; OGS_SQN_LEN],
    /// GUAMI
    pub guami: Guami,
    /// Authentication type
    pub auth_type: AuthType,
    /// RAT type
    pub rat_type: RatType,
    /// Authentication event
    pub auth_event: Option<AuthEvent>,
    /// AMF 3GPP access registration
    pub amf_3gpp_access_registration: Option<Amf3GppAccessRegistration>,
    /// Associated stream ID
    pub stream_id: Option<u64>,
}

impl UdmUe {
    /// Create a new UDM UE
    pub fn new(id: u64, suci: &str) -> Self {
        // Extract SUPI from SUCI if possible
        let supi = supi_from_suci(suci);

        Self {
            id,
            ctx_id: id.to_string(),
            suci: suci.to_string(),
            supi,
            serving_network_name: None,
            ausf_instance_id: None,
            amf_instance_id: None,
            dereg_callback_uri: None,
            k: [0u8; OGS_KEY_LEN],
            opc: [0u8; OGS_KEY_LEN],
            amf: [0u8; OGS_AMF_LEN],
            rand: [0u8; OGS_RAND_LEN],
            sqn: [0u8; OGS_SQN_LEN],
            guami: Guami::default(),
            auth_type: AuthType::default(),
            rat_type: RatType::default(),
            auth_event: None,
            amf_3gpp_access_registration: None,
            stream_id: None,
        }
    }

    /// Set authentication event
    pub fn set_auth_event(&mut self, auth_event: AuthEvent) {
        self.auth_event = Some(auth_event);
    }

    /// Clear authentication event
    pub fn clear_auth_event(&mut self) {
        self.auth_event = None;
    }

    /// Set AMF 3GPP access registration
    pub fn set_amf_3gpp_access_registration(&mut self, registration: Amf3GppAccessRegistration) {
        self.amf_3gpp_access_registration = Some(registration);
    }

    /// Clear AMF 3GPP access registration
    pub fn clear_amf_3gpp_access_registration(&mut self) {
        self.amf_3gpp_access_registration = None;
    }
}

/// UDM Session context
#[derive(Debug, Clone)]
pub struct UdmSess {
    /// Unique pool ID
    pub id: u64,
    /// PDU Session Identity
    pub psi: u8,
    /// SMF registration
    pub smf_registration: Option<SmfRegistration>,
    /// SMF instance ID
    pub smf_instance_id: Option<String>,
    /// Parent UDM UE ID
    pub udm_ue_id: u64,
    /// Associated stream ID
    pub stream_id: Option<u64>,
}

impl UdmSess {
    /// Create a new UDM session
    pub fn new(id: u64, udm_ue_id: u64, psi: u8) -> Self {
        Self {
            id,
            psi,
            smf_registration: None,
            smf_instance_id: None,
            udm_ue_id,
            stream_id: None,
        }
    }

    /// Set SMF registration
    pub fn set_smf_registration(&mut self, registration: SmfRegistration) {
        self.smf_registration = Some(registration);
    }

    /// Clear SMF registration
    pub fn clear_smf_registration(&mut self) {
        self.smf_registration = None;
    }
}

/// UDM SDM Subscription
#[derive(Debug, Clone)]
pub struct UdmSdmSubscription {
    /// Unique subscription ID (UUID)
    pub id: String,
    /// Data change callback URI
    pub data_change_callback_uri: Option<String>,
    /// Parent UDM UE ID
    pub udm_ue_id: u64,
}

impl UdmSdmSubscription {
    /// Create a new SDM subscription
    pub fn new(udm_ue_id: u64) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            data_change_callback_uri: None,
            udm_ue_id,
        }
    }
}


/// Extract SUPI from SUCI or SUPI string
fn supi_from_suci(suci_or_supi: &str) -> Option<String> {
    if suci_or_supi.starts_with("suci-") {
        // Parse SUCI format: suci-0-MCC-MNC-MSIN...
        // For now, return None - actual implementation would decode SUCI
        None
    } else if suci_or_supi.starts_with("imsi-") {
        Some(suci_or_supi.to_string())
    } else {
        None
    }
}

/// UDM Context - main context structure for UDM
pub struct UdmContext {
    /// UE list (by pool ID)
    ue_list: RwLock<HashMap<u64, UdmUe>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, UdmSess>>,
    /// SDM subscription list (by subscription ID)
    sdm_subscription_list: RwLock<HashMap<String, UdmSdmSubscription>>,
    /// SUCI hash (SUCI -> pool ID)
    suci_hash: RwLock<HashMap<String, u64>>,
    /// SUPI hash (SUPI -> pool ID)
    supi_hash: RwLock<HashMap<String, u64>>,
    /// Next UE ID
    next_ue_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Maximum number of SDM subscriptions
    max_num_of_sdm_subscriptions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl UdmContext {
    /// Create a new UDM context
    pub fn new() -> Self {
        Self {
            ue_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            sdm_subscription_list: RwLock::new(HashMap::new()),
            suci_hash: RwLock::new(HashMap::new()),
            supi_hash: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            max_num_of_sdm_subscriptions: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the UDM context
    pub fn init(&mut self, max_ue: usize, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_ue = max_ue;
        self.max_num_of_sess = max_sess;
        // 4 SDM subscriptions per UE
        self.max_num_of_sdm_subscriptions = max_ue * 4;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "UDM context initialized with max {} UEs, {} sessions",
            self.max_num_of_ue,
            self.max_num_of_sess
        );
    }

    /// Finalize the UDM context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Remove all UEs (which also removes sessions and subscriptions)
        self.ue_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("UDM context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add a new UE by SUCI
    pub fn ue_add(&self, suci: &str) -> Option<UdmUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;

        if ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue = UdmUe::new(id, suci);

        suci_hash.insert(suci.to_string(), id);
        if let Some(ref supi) = ue.supi {
            supi_hash.insert(supi.clone(), id);
        }
        ue_list.insert(id, ue.clone());

        log::debug!("[{}] UDM UE added (id={})", suci, id);
        Some(ue)
    }

    /// Remove a UE by ID
    pub fn ue_remove(&self, id: u64) -> Option<UdmUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;

        if let Some(ue) = ue_list.remove(&id) {
            suci_hash.remove(&ue.suci);
            if let Some(ref supi) = ue.supi {
                supi_hash.remove(supi);
            }

            // Remove all sessions for this UE
            self.sess_remove_all_for_ue(id);
            // Remove all SDM subscriptions for this UE
            self.sdm_subscription_remove_all_for_ue(id);

            log::debug!("[{}] UDM UE removed (id={})", ue.suci, id);
            return Some(ue);
        }
        None
    }

    /// Remove all UEs
    pub fn ue_remove_all(&self) {
        if let (Ok(mut ue_list), Ok(mut suci_hash), Ok(mut supi_hash)) = (
            self.ue_list.write(),
            self.suci_hash.write(),
            self.supi_hash.write(),
        ) {
            ue_list.clear();
            suci_hash.clear();
            supi_hash.clear();
        }

        // Clear sessions and subscriptions
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.clear();
        }
        if let Ok(mut sdm_list) = self.sdm_subscription_list.write() {
            sdm_list.clear();
        }
    }

    /// Find UE by SUCI
    pub fn ue_find_by_suci(&self, suci: &str) -> Option<UdmUe> {
        let suci_hash = self.suci_hash.read().ok()?;
        let ue_list = self.ue_list.read().ok()?;

        if let Some(&id) = suci_hash.get(suci) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by SUPI
    pub fn ue_find_by_supi(&self, supi: &str) -> Option<UdmUe> {
        let supi_hash = self.supi_hash.read().ok()?;
        let ue_list = self.ue_list.read().ok()?;

        if let Some(&id) = supi_hash.get(supi) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by context ID
    pub fn ue_find_by_ctx_id(&self, ctx_id: &str) -> Option<UdmUe> {
        let id: u64 = ctx_id.parse().ok()?;
        self.ue_find_by_id(id)
    }

    /// Find UE by pool ID
    pub fn ue_find_by_id(&self, id: u64) -> Option<UdmUe> {
        let ue_list = self.ue_list.read().ok()?;
        ue_list.get(&id).cloned()
    }

    /// Update UE in the context
    pub fn ue_update(&self, ue: &UdmUe) -> bool {
        let mut ue_list = self.ue_list.write().ok().unwrap();
        let mut supi_hash = self.supi_hash.write().ok().unwrap();

        if let Some(existing) = ue_list.get_mut(&ue.id) {
            // Update SUPI hash if SUPI changed
            if existing.supi != ue.supi {
                if let Some(ref old_supi) = existing.supi {
                    supi_hash.remove(old_supi);
                }
                if let Some(ref new_supi) = ue.supi {
                    supi_hash.insert(new_supi.clone(), ue.id);
                }
            }
            *existing = ue.clone();
            return true;
        }
        false
    }

    /// Set SUPI for a UE
    pub fn ue_set_supi(&self, id: u64, supi: &str) -> bool {
        let mut ue_list = self.ue_list.write().ok().unwrap();
        let mut supi_hash = self.supi_hash.write().ok().unwrap();

        if let Some(ue) = ue_list.get_mut(&id) {
            // Remove old SUPI from hash
            if let Some(ref old_supi) = ue.supi {
                supi_hash.remove(old_supi);
            }
            // Set new SUPI
            ue.supi = Some(supi.to_string());
            supi_hash.insert(supi.to_string(), id);
            return true;
        }
        false
    }


    // Session management methods

    /// Add a new session for a UE
    pub fn sess_add(&self, udm_ue_id: u64, psi: u8) -> Option<UdmSess> {
        let mut sess_list = self.sess_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sess = UdmSess::new(id, udm_ue_id, psi);

        sess_list.insert(id, sess.clone());

        log::debug!("[ue_id={}, psi={}] UDM session added (id={})", udm_ue_id, psi, id);
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<UdmSess> {
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            log::debug!(
                "[ue_id={}, psi={}] UDM session removed (id={})",
                sess.udm_ue_id,
                sess.psi,
                id
            );
            return Some(sess);
        }
        None
    }

    /// Remove all sessions for a UE
    fn sess_remove_all_for_ue(&self, udm_ue_id: u64) {
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.retain(|_, sess| sess.udm_ue_id != udm_ue_id);
        }
    }

    /// Find session by ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<UdmSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    /// Find session by PSI for a UE
    pub fn sess_find_by_psi(&self, udm_ue_id: u64, psi: u8) -> Option<UdmSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess.udm_ue_id == udm_ue_id && sess.psi == psi {
                return Some(sess.clone());
            }
        }
        None
    }

    /// Update session in the context
    pub fn sess_update(&self, sess: &UdmSess) -> bool {
        let mut sess_list = self.sess_list.write().ok().unwrap();
        if let Some(existing) = sess_list.get_mut(&sess.id) {
            *existing = sess.clone();
            return true;
        }
        false
    }

    // SDM Subscription management methods

    /// Add a new SDM subscription for a UE
    pub fn sdm_subscription_add(&self, udm_ue_id: u64) -> Option<UdmSdmSubscription> {
        let mut sdm_list = self.sdm_subscription_list.write().ok()?;

        if sdm_list.len() >= self.max_num_of_sdm_subscriptions {
            log::error!(
                "Maximum number of SDM subscriptions [{}] reached",
                self.max_num_of_sdm_subscriptions
            );
            return None;
        }

        let subscription = UdmSdmSubscription::new(udm_ue_id);
        let id = subscription.id.clone();

        sdm_list.insert(id.clone(), subscription.clone());

        log::debug!(
            "[ue_id={}] SDM subscription added (id={})",
            udm_ue_id,
            id
        );
        Some(subscription)
    }

    /// Remove an SDM subscription by ID
    pub fn sdm_subscription_remove(&self, id: &str) -> Option<UdmSdmSubscription> {
        let mut sdm_list = self.sdm_subscription_list.write().ok()?;

        if let Some(subscription) = sdm_list.remove(id) {
            log::debug!(
                "[ue_id={}] SDM subscription removed (id={})",
                subscription.udm_ue_id,
                id
            );
            return Some(subscription);
        }
        None
    }

    /// Remove all SDM subscriptions for a UE
    fn sdm_subscription_remove_all_for_ue(&self, udm_ue_id: u64) {
        if let Ok(mut sdm_list) = self.sdm_subscription_list.write() {
            sdm_list.retain(|_, sub| sub.udm_ue_id != udm_ue_id);
        }
    }

    /// Find SDM subscription by ID
    pub fn sdm_subscription_find_by_id(&self, id: &str) -> Option<UdmSdmSubscription> {
        let sdm_list = self.sdm_subscription_list.read().ok()?;
        sdm_list.get(id).cloned()
    }

    /// Update SDM subscription in the context
    pub fn sdm_subscription_update(&self, subscription: &UdmSdmSubscription) -> bool {
        let mut sdm_list = self.sdm_subscription_list.write().ok().unwrap();
        if let Some(existing) = sdm_list.get_mut(&subscription.id) {
            *existing = subscription.clone();
            return true;
        }
        false
    }

    /// Get UE load percentage
    pub fn get_ue_load(&self) -> i32 {
        let ue_list = self.ue_list.read().ok().unwrap();
        let used = ue_list.len();
        let total = self.max_num_of_ue;
        if total == 0 {
            return 0;
        }
        ((used * 100) / total) as i32
    }

    /// Get number of UEs
    pub fn ue_count(&self) -> usize {
        self.ue_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get number of sessions
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get number of SDM subscriptions
    pub fn sdm_subscription_count(&self) -> usize {
        self.sdm_subscription_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for UdmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global UDM context (thread-safe singleton)
static GLOBAL_UDM_CONTEXT: std::sync::OnceLock<Arc<RwLock<UdmContext>>> = std::sync::OnceLock::new();

/// Get the global UDM context
pub fn udm_self() -> Arc<RwLock<UdmContext>> {
    GLOBAL_UDM_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(UdmContext::new())))
        .clone()
}

/// Initialize the global UDM context
pub fn udm_context_init(max_ue: usize, max_sess: usize) {
    let ctx = udm_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue, max_sess);
    };
}

/// Finalize the global UDM context
pub fn udm_context_final() {
    let ctx = udm_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get UE load (for NF instance load reporting)
pub fn get_ue_load() -> i32 {
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        return context.get_ue_load();
    }
    0
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udm_context_new() {
        let ctx = UdmContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_udm_context_init_fini() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);
        assert!(ctx.is_initialized());
        assert_eq!(ctx.max_num_of_ue, 100);
        assert_eq!(ctx.max_num_of_sess, 200);

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_add_remove() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        assert_eq!(ue.suci, "suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.ue_count(), 1);

        let found = ctx.ue_find_by_suci("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ue_find_by_ctx_id() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        let found = ctx.ue_find_by_ctx_id(&ue.ctx_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().suci, ue.suci);
    }

    #[test]
    fn test_sess_add_remove() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        let sess = ctx.sess_add(ue.id, 1).unwrap();
        assert_eq!(sess.psi, 1);
        assert_eq!(sess.udm_ue_id, ue.id);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_psi(ue.id, 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_sdm_subscription_add_remove() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        let sub = ctx.sdm_subscription_add(ue.id).unwrap();
        assert_eq!(sub.udm_ue_id, ue.id);
        assert_eq!(ctx.sdm_subscription_count(), 1);

        let found = ctx.sdm_subscription_find_by_id(&sub.id);
        assert!(found.is_some());

        ctx.sdm_subscription_remove(&sub.id);
        assert_eq!(ctx.sdm_subscription_count(), 0);
    }

    #[test]
    fn test_ue_remove_cascades() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        ctx.sess_add(ue.id, 1);
        ctx.sess_add(ue.id, 2);
        ctx.sdm_subscription_add(ue.id);

        assert_eq!(ctx.sess_count(), 2);
        assert_eq!(ctx.sdm_subscription_count(), 1);

        // Removing UE should cascade to sessions and subscriptions
        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
        assert_eq!(ctx.sdm_subscription_count(), 0);
    }

    #[test]
    fn test_get_ue_load() {
        let mut ctx = UdmContext::new();
        ctx.init(100, 200);

        assert_eq!(ctx.get_ue_load(), 0);

        ctx.ue_add("suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.get_ue_load(), 1);

        for i in 2..=50 {
            ctx.ue_add(&format!("suci-0-001-01-0000-0-0-{:010}", i));
        }
        assert_eq!(ctx.get_ue_load(), 50);
    }
}
