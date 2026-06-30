//! AMF Context Management
//!
//! Port of src/amf/context.c, src/amf/context.h - AMF context with gNB list, UE list, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of served GUAMI
pub const NEXTGCORE_MAX_NUM_OF_SERVED_GUAMI: usize = 8;
/// Maximum number of supported TA
pub const NEXTGCORE_MAX_NUM_OF_SUPPORTED_TA: usize = 16;
/// Maximum number of PLMN
pub const NEXTGCORE_MAX_NUM_OF_PLMN: usize = 6;
/// Maximum number of slice support
pub const NEXTGCORE_MAX_NUM_OF_SLICE_SUPPORT: usize = 8;
/// Maximum number of BPLMN
pub const NEXTGCORE_MAX_NUM_OF_BPLMN: usize = 12;
/// Maximum number of algorithms
pub const NEXTGCORE_MAX_NUM_OF_ALGORITHM: usize = 8;
/// Maximum number of slices
pub const NEXTGCORE_MAX_NUM_OF_SLICE: usize = 8;
/// Maximum number of MSISDN
pub const NEXTGCORE_MAX_NUM_OF_MSISDN: usize = 2;

/// Key length
pub const NEXTGCORE_KEY_LEN: usize = 16;
/// RAND length
pub const NEXTGCORE_RAND_LEN: usize = 16;
/// AUTN length
pub const NEXTGCORE_AUTN_LEN: usize = 16;
/// MAX RES length
pub const NEXTGCORE_MAX_RES_LEN: usize = 16;
/// SHA256 digest size
pub const NEXTGCORE_SHA256_DIGEST_SIZE: usize = 32;
/// NAS MAX ABBA length
pub const NEXTGCORE_NAS_MAX_ABBA_LEN: usize = 2;
/// MAX IMEISV length
pub const NEXTGCORE_MAX_IMEISV_LEN: usize = 8;
/// MAX IMEISV BCD length
pub const NEXTGCORE_MAX_IMEISV_BCD_LEN: usize = 16;

/// Invalid UE NGAP ID
pub const INVALID_UE_NGAP_ID: u64 = 0xffffffffffffffff;
/// Invalid pool ID
pub const NEXTGCORE_INVALID_POOL_ID: u64 = 0;
/// Minimum pool ID
pub const NEXTGCORE_MIN_POOL_ID: u64 = 1;
/// Maximum pool ID
pub const NEXTGCORE_MAX_POOL_ID: u64 = u64::MAX - 1;

/// NAS KSI no key available
pub const NEXTGCORE_NAS_KSI_NO_KEY_IS_AVAILABLE: u8 = 7;

// ============================================================================
// Basic Types
// ============================================================================

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    /// MCC digit 1
    pub mcc1: u8,
    /// MCC digit 2
    pub mcc2: u8,
    /// MCC digit 3
    pub mcc3: u8,
    /// MNC digit 1
    pub mnc1: u8,
    /// MNC digit 2
    pub mnc2: u8,
    /// MNC digit 3 (0xf if 2-digit MNC)
    pub mnc3: u8,
}

impl PlmnId {
    /// Create a new PLMN ID
    pub fn new(mcc: &str, mnc: &str) -> Self {
        let mcc_bytes: Vec<u8> = mcc
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        let mnc_bytes: Vec<u8> = mnc
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();

        Self {
            mcc1: mcc_bytes.first().copied().unwrap_or(0),
            mcc2: mcc_bytes.get(1).copied().unwrap_or(0),
            mcc3: mcc_bytes.get(2).copied().unwrap_or(0),
            mnc1: mnc_bytes.first().copied().unwrap_or(0),
            mnc2: mnc_bytes.get(1).copied().unwrap_or(0),
            mnc3: mnc_bytes.get(2).copied().unwrap_or(0xf),
        }
    }
}

/// AMF ID (Region + Set + Pointer)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmfId {
    /// AMF Region ID (8 bits)
    pub region: u8,
    /// AMF Set ID (10 bits)
    pub set: u16,
    /// AMF Pointer (6 bits)
    pub pointer: u8,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// AMF ID
    pub amf_id: AmfId,
}

/// 5GS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default)]
pub struct Tai5gs {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC (24 bits)
    pub tac: u32,
}

/// NR CGI (NR Cell Global Identity)
#[derive(Debug, Clone, Default)]
pub struct NrCgi {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// NR Cell ID (36 bits)
    pub cell_id: u64,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default)]
pub struct SNssai {
    /// SST (Slice/Service Type)
    pub sst: u8,
    /// SD (Slice Differentiator) - optional
    pub sd: Option<u32>,
}

/// Bitrate
#[derive(Debug, Clone, Default)]
pub struct Bitrate {
    /// Downlink bitrate (bps)
    pub downlink: u64,
    /// Uplink bitrate (bps)
    pub uplink: u64,
}

/// Slice data
#[derive(Debug, Clone, Default)]
pub struct SliceData {
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// Default indicator
    pub default_indicator: bool,
}

/// Network name
#[derive(Debug, Clone, Default)]
pub struct NetworkName {
    /// Name string
    pub name: String,
}

/// UE security capability
#[derive(Debug, Clone, Default)]
pub struct UeSecurityCapability {
    /// 5G-EA algorithms (bitmap)
    pub ea: u8,
    /// 5G-IA algorithms (bitmap)
    pub ia: u8,
    /// EEA algorithms (bitmap)
    pub eea: u8,
    /// EIA algorithms (bitmap)
    pub eia: u8,
}

/// UE network capability
#[derive(Debug, Clone, Default)]
pub struct UeNetworkCapability {
    /// EEA algorithms (bitmap)
    pub eea: u8,
    /// EIA algorithms (bitmap)
    pub eia: u8,
}

/// 5GS GUTI
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Guti5gs {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// AMF Region ID
    pub amf_region_id: u8,
    /// AMF Set ID
    pub amf_set_id: u16,
    /// AMF Pointer
    pub amf_pointer: u8,
    /// 5G-TMSI
    pub tmsi: u32,
}

/// RAT type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RatType {
    #[default]
    Nr,
    Eutra,
    Wlan,
    Virtual,
}

/// Auth result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthResult {
    #[default]
    Success,
    Failure,
    Synch,
}

/// UE context transfer state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UeContextTransferState {
    #[default]
    Initial,
    TransferOldAmf,
    TransferNewAmf,
    RegistrationStatusUpdateOldAmf,
    RegistrationStatusUpdateNewAmf,
}

/// NGAP UE context release action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NgapUeCtxRelAction {
    #[default]
    Invalid,
    NgContextRemove,
    NgRemoveAndUnlink,
    UeContextRemove,
    NgHandoverComplete,
    NgHandoverCancel,
    NgHandoverFailure,
}

/// NGAP Cause
#[derive(Debug, Clone, Default)]
pub struct NgapCause {
    /// Cause group
    pub group: u8,
    /// Cause value
    pub cause: i64,
}

// ============================================================================
// TAI List Types (for served TAI)
// ============================================================================

/// TAI0 list (type 0 - list of TACs with same PLMN)
#[derive(Debug, Clone, Default)]
pub struct Tai0List {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC list
    pub tac: Vec<u32>,
}

/// TAI1 list (type 1 - contiguous TACs)
#[derive(Debug, Clone, Default)]
pub struct Tai1List {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// Start TAC
    pub start_tac: u32,
    /// Number of TACs
    pub num_of_tac: u8,
}

/// TAI2 list (type 2 - list of TAIs)
#[derive(Debug, Clone, Default)]
pub struct Tai2List {
    /// List of TAIs
    pub tai: Vec<Tai5gs>,
}

/// Served TAI configuration
#[derive(Debug, Clone, Default)]
pub struct ServedTai {
    /// TAI0 list
    pub list0: Tai0List,
    /// TAI1 list
    pub list1: Tai1List,
    /// TAI2 list
    pub list2: Tai2List,
}

/// PLMN support configuration
#[derive(Debug, Clone, Default)]
pub struct PlmnSupport {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// Number of S-NSSAIs
    pub num_of_s_nssai: usize,
    /// S-NSSAI list
    pub s_nssai: Vec<SNssai>,
}

/// Access control entry
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    /// Reject cause
    pub reject_cause: i32,
    /// PLMN ID
    pub plmn_id: PlmnId,
}

// ============================================================================
// gNB Supported TA
// ============================================================================

/// BPLMN (Broadcast PLMN) entry
#[derive(Debug, Clone, Default)]
pub struct BplmnEntry {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// Number of S-NSSAIs
    pub num_of_s_nssai: usize,
    /// S-NSSAI list
    pub s_nssai: Vec<SNssai>,
}

/// Supported TA entry for gNB
#[derive(Debug, Clone, Default)]
pub struct SupportedTa {
    /// TAC (24 bits)
    pub tac: u32,
    /// Number of BPLMN entries
    pub num_of_bplmn_list: usize,
    /// BPLMN list
    pub bplmn_list: Vec<BplmnEntry>,
}

// ============================================================================
// AMF Context (Main)
// ============================================================================

/// AMF Context - main context structure for AMF
pub struct AmfContext {
    // Served GUAMI
    /// Number of served GUAMI
    pub num_of_served_guami: usize,
    /// Served GUAMI list
    pub served_guami: Vec<Guami>,

    // Served TAI
    /// Number of served TAI
    pub num_of_served_tai: usize,
    /// Served TAI list
    pub served_tai: Vec<ServedTai>,

    // PLMN Support
    /// Number of PLMN support entries
    pub num_of_plmn_support: usize,
    /// PLMN support list
    pub plmn_support: Vec<PlmnSupport>,

    // Access Control
    /// Default reject cause
    pub default_reject_cause: i32,
    /// Number of access control entries
    pub num_of_access_control: usize,
    /// Access control list
    pub access_control: Vec<AccessControl>,

    // Security algorithms
    /// Number of ciphering algorithms
    pub num_of_ciphering_order: usize,
    /// Ciphering algorithm order
    pub ciphering_order: Vec<u8>,
    /// Number of integrity algorithms
    pub num_of_integrity_order: usize,
    /// Integrity algorithm order
    pub integrity_order: Vec<u8>,

    // Network Name
    /// Short network name
    pub short_name: NetworkName,
    /// Full network name
    pub full_name: NetworkName,

    // AMF Name
    /// AMF name
    pub amf_name: Option<String>,

    // NGSetupResponse
    /// Relative capacity
    pub relative_capacity: u8,

    // Generator for unique identification
    /// AMF UE NGAP ID generator
    amf_ue_ngap_id_generator: AtomicU64,

    // Lists
    /// gNB list (by pool ID)
    gnb_list: RwLock<HashMap<u64, AmfGnb>>,
    /// AMF UE list (by pool ID)
    amf_ue_list: RwLock<HashMap<u64, AmfUe>>,
    /// RAN UE list (by pool ID)
    ran_ue_list: RwLock<HashMap<u64, RanUe>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, AmfSess>>,

    // Hash tables
    /// gNB address hash (addr string -> pool ID)
    gnb_addr_hash: RwLock<HashMap<String, u64>>,
    /// gNB ID hash (gnb_id -> pool ID)
    gnb_id_hash: RwLock<HashMap<u32, u64>>,
    /// GUTI UE hash (GUTI -> pool ID)
    guti_ue_hash: RwLock<HashMap<Guti5gs, u64>>,
    /// SUCI hash (SUCI -> pool ID)
    suci_hash: RwLock<HashMap<String, u64>>,
    /// SUPI hash (SUPI -> pool ID)
    supi_hash: RwLock<HashMap<String, u64>>,

    // NGAP port
    /// Default NGAP port
    pub ngap_port: u16,

    // Timers
    /// T3502 timer value
    pub t3502_value: u64,
    /// T3512 timer value
    pub t3512_value: u64,

    // ID generators
    /// Next gNB ID
    next_gnb_id: AtomicUsize,
    /// Next RAN UE ID
    next_ran_ue_id: AtomicUsize,
    /// Next AMF UE ID
    next_amf_ue_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// RAN UE index counter
    ran_ue_index: AtomicU64,

    // Pool limits
    /// Maximum number of gNBs
    max_num_of_gnb: usize,
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Maximum number of RAN UEs
    max_num_of_ran_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,

    /// Context initialized flag
    initialized: AtomicBool,

    /// Paging context map: AMF-UE-NGAP-ID -> PagingContext (TS 23.502 4.2.3.3)
    paging_map: RwLock<HashMap<u64, PagingContext>>,

    /// Namf_EventExposure subscriptions: subscriptionId -> EventSubscription
    /// (TS 29.518 §5.3). Persisted across requests; expiry-aware.
    event_subscriptions: RwLock<HashMap<String, EventSubscription>>,

    /// LCS positioning downlink queue (TS 23.273): positioning payloads the LMF
    /// asked the AMF to relay (NRPPa→gNB / LPP→UE), enqueued by the Namf SBI
    /// handler and drained + delivered by the NGAP server task. Empty on the
    /// reg/PDU/ping path — only populated by positioning N1N2 transfers.
    positioning_dl_queue: RwLock<Vec<PendingPositioningDl>>,
}

/// A positioning payload the LMF asked the AMF to relay downlink (TS 23.273),
/// enqueued by the Namf SBI handler task and delivered by the NGAP server task.
#[derive(Debug, Clone)]
pub struct PendingPositioningDl {
    /// Target UE (AMF-UE-NGAP-ID). The NGAP task resolves the serving SCTP
    /// association + RAN-UE-NGAP-ID from its per-UE state at delivery time.
    pub amf_ue_ngap_id: u64,
    /// What to deliver and over which interface.
    pub kind: PositioningDlKind,
}

/// Downlink positioning payload variants (TS 23.273).
#[derive(Debug, Clone)]
pub enum PositioningDlKind {
    /// NRPPa PDU → serving gNB (N2, UE-associated NRPPa transport). `routing_id`
    /// is the LMF's opaque RoutingID, echoed so the gNB's uplink reply routes
    /// back to the originating LMF.
    NrppaToGnb {
        routing_id: Vec<u8>,
        nrppa_pdu: Vec<u8>,
    },
    /// LPP message → UE (N1, DL NAS Transport with payload container type LPP).
    LppToUe { lpp_pdu: Vec<u8> },
}

/// Namf_EventExposure subscription stored in the AMF context
/// (TS 29.518 §6.2.6.2.2 AmfEventSubscription)
#[derive(Debug, Clone)]
pub struct EventSubscription {
    /// Subscription ID (assigned by AMF, returned in Location header)
    pub subscription_id: String,
    /// Event notification URI (mandatory `eventNotifyUri`)
    pub notify_uri: String,
    /// Notify correlation ID (mandatory `notifyCorrelationId`)
    pub notify_correlation_id: String,
    /// Subscribing NF instance ID (mandatory `nfId`)
    pub nf_id: String,
    /// Subscribed event types (mandatory `eventList`, at least one entry)
    pub event_types: Vec<String>,
    /// Single-UE subscription filter (`supi`)
    pub supi: Option<String>,
    /// Any-UE subscription (`anyUE`)
    pub any_ue: bool,
    /// Optional subscription expiry (`expiry`, DateTime)
    pub expiry: Option<std::time::SystemTime>,
}

impl AmfContext {
    /// Create a new AMF context
    pub fn new() -> Self {
        Self {
            num_of_served_guami: 0,
            served_guami: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SERVED_GUAMI),
            num_of_served_tai: 0,
            served_tai: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SUPPORTED_TA),
            num_of_plmn_support: 0,
            plmn_support: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_PLMN),
            default_reject_cause: 0,
            num_of_access_control: 0,
            access_control: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_PLMN),
            num_of_ciphering_order: 0,
            ciphering_order: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_ALGORITHM),
            num_of_integrity_order: 0,
            integrity_order: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_ALGORITHM),
            short_name: NetworkName::default(),
            full_name: NetworkName::default(),
            amf_name: None,
            relative_capacity: 255,
            amf_ue_ngap_id_generator: AtomicU64::new(1),
            gnb_list: RwLock::new(HashMap::new()),
            amf_ue_list: RwLock::new(HashMap::new()),
            ran_ue_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            gnb_addr_hash: RwLock::new(HashMap::new()),
            gnb_id_hash: RwLock::new(HashMap::new()),
            guti_ue_hash: RwLock::new(HashMap::new()),
            suci_hash: RwLock::new(HashMap::new()),
            supi_hash: RwLock::new(HashMap::new()),
            ngap_port: 38412,
            t3502_value: 720,
            t3512_value: 3240,
            next_gnb_id: AtomicUsize::new(1),
            next_ran_ue_id: AtomicUsize::new(1),
            next_amf_ue_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            ran_ue_index: AtomicU64::new(1),
            max_num_of_gnb: 0,
            max_num_of_ue: 0,
            max_num_of_ran_ue: 0,
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
            paging_map: RwLock::new(HashMap::new()),
            event_subscriptions: RwLock::new(HashMap::new()),
            positioning_dl_queue: RwLock::new(Vec::new()),
        }
    }

    /// Initialize the AMF context
    pub fn init(&mut self, max_gnb: usize, max_ue: usize, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_gnb = max_gnb;
        self.max_num_of_ue = max_ue;
        self.max_num_of_ran_ue = max_ue * 2; // Allow for handover scenarios
        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "AMF context initialized with max {} gNBs, {} UEs, {} sessions",
            self.max_num_of_gnb,
            self.max_num_of_ue,
            self.max_num_of_sess
        );
    }

    /// Finalize the AMF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.gnb_remove_all();
        self.amf_ue_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("AMF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate next AMF UE NGAP ID
    pub fn next_amf_ue_ngap_id(&self) -> u64 {
        self.amf_ue_ngap_id_generator.fetch_add(1, Ordering::SeqCst)
    }

    // ========================================================================
    // gNB Management
    // ========================================================================

    /// Add a new gNB
    pub fn gnb_add(&self, addr: &str) -> Option<AmfGnb> {
        let mut gnb_list = self.gnb_list.write().ok()?;
        let mut gnb_addr_hash = self.gnb_addr_hash.write().ok()?;

        if gnb_list.len() >= self.max_num_of_gnb {
            log::error!("Maximum number of gNBs [{}] reached", self.max_num_of_gnb);
            return None;
        }

        let id = self.next_gnb_id.fetch_add(1, Ordering::SeqCst) as u64;
        let gnb = AmfGnb::new(id, addr);

        gnb_addr_hash.insert(addr.to_string(), id);
        gnb_list.insert(id, gnb.clone());

        log::debug!("[{addr}] gNB added (id={id})");
        Some(gnb)
    }

    /// Remove a gNB by ID
    pub fn gnb_remove(&self, id: u64) -> Option<AmfGnb> {
        let mut gnb_list = self.gnb_list.write().ok()?;
        let mut gnb_addr_hash = self.gnb_addr_hash.write().ok()?;
        let mut gnb_id_hash = self.gnb_id_hash.write().ok()?;

        if let Some(gnb) = gnb_list.remove(&id) {
            gnb_addr_hash.remove(&gnb.addr);
            if gnb.gnb_id_presence {
                gnb_id_hash.remove(&gnb.gnb_id);
            }

            // Remove all RAN UEs for this gNB
            self.ran_ue_remove_all_for_gnb(id);

            log::debug!("[{}] gNB removed (id={})", gnb.addr, id);
            return Some(gnb);
        }
        None
    }

    /// Remove all gNBs
    pub fn gnb_remove_all(&self) {
        if let (Ok(mut gnb_list), Ok(mut gnb_addr_hash), Ok(mut gnb_id_hash)) = (
            self.gnb_list.write(),
            self.gnb_addr_hash.write(),
            self.gnb_id_hash.write(),
        ) {
            gnb_list.clear();
            gnb_addr_hash.clear();
            gnb_id_hash.clear();
        }

        // Clear RAN UEs
        if let Ok(mut ran_ue_list) = self.ran_ue_list.write() {
            ran_ue_list.clear();
        }
    }

    // Lock-order note: gnb_set_gnb_id acquires gnb_list BEFORE gnb_id_hash;
    // finders must not hold a hash guard while locking gnb_list (ABBA).
    // Copy the id, drop the hash guard, then lock the list.

    /// Find gNB by address
    pub fn gnb_find_by_addr(&self, addr: &str) -> Option<AmfGnb> {
        let id = {
            let gnb_addr_hash = self.gnb_addr_hash.read().ok()?;
            gnb_addr_hash.get(addr).copied()
        }?;
        let gnb_list = self.gnb_list.read().ok()?;
        gnb_list.get(&id).cloned()
    }

    /// Find gNB by gNB ID
    pub fn gnb_find_by_gnb_id(&self, gnb_id: u32) -> Option<AmfGnb> {
        let id = {
            let gnb_id_hash = self.gnb_id_hash.read().ok()?;
            gnb_id_hash.get(&gnb_id).copied()
        }?;
        let gnb_list = self.gnb_list.read().ok()?;
        gnb_list.get(&id).cloned()
    }

    /// Find gNB by pool ID
    pub fn gnb_find_by_id(&self, id: u64) -> Option<AmfGnb> {
        let gnb_list = self.gnb_list.read().ok()?;
        gnb_list.get(&id).cloned()
    }

    /// Set gNB ID for a gNB
    pub fn gnb_set_gnb_id(&self, id: u64, gnb_id: u32) -> bool {
        let mut gnb_list = self.gnb_list.write().unwrap();
        let mut gnb_id_hash = self.gnb_id_hash.write().unwrap();

        if let Some(gnb) = gnb_list.get_mut(&id) {
            // Remove old gNB ID from hash if present
            if gnb.gnb_id_presence {
                gnb_id_hash.remove(&gnb.gnb_id);
            }
            // Set new gNB ID
            gnb.gnb_id = gnb_id;
            gnb.gnb_id_presence = true;
            gnb_id_hash.insert(gnb_id, id);
            return true;
        }
        false
    }

    /// Update gNB in the context
    pub fn gnb_update(&self, gnb: &AmfGnb) -> bool {
        let mut gnb_list = self.gnb_list.write().unwrap();
        if let Some(existing) = gnb_list.get_mut(&gnb.id) {
            *existing = gnb.clone();
            return true;
        }
        false
    }

    /// Get number of gNBs
    pub fn gnb_count(&self) -> usize {
        self.gnb_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // RAN UE Management
    // ========================================================================

    /// Add a new RAN UE
    pub fn ran_ue_add(&self, gnb_id: u64, ran_ue_ngap_id: u64) -> Option<RanUe> {
        let mut ran_ue_list = self.ran_ue_list.write().ok()?;

        if ran_ue_list.len() >= self.max_num_of_ran_ue {
            log::error!(
                "Maximum number of RAN UEs [{}] reached",
                self.max_num_of_ran_ue
            );
            return None;
        }

        let id = self.next_ran_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let index = self.ran_ue_index.fetch_add(1, Ordering::SeqCst) as u32;
        let amf_ue_ngap_id = self.next_amf_ue_ngap_id();

        let ran_ue = RanUe::new(id, index, gnb_id, ran_ue_ngap_id, amf_ue_ngap_id);
        ran_ue_list.insert(id, ran_ue.clone());

        log::debug!(
            "RAN UE added (id={id}, ran_ue_ngap_id={ran_ue_ngap_id}, amf_ue_ngap_id={amf_ue_ngap_id})"
        );
        Some(ran_ue)
    }

    /// Remove a RAN UE by ID
    pub fn ran_ue_remove(&self, id: u64) -> Option<RanUe> {
        let mut ran_ue_list = self.ran_ue_list.write().ok()?;

        if let Some(ran_ue) = ran_ue_list.remove(&id) {
            log::debug!(
                "RAN UE removed (id={}, ran_ue_ngap_id={}, amf_ue_ngap_id={})",
                id,
                ran_ue.ran_ue_ngap_id,
                ran_ue.amf_ue_ngap_id
            );
            return Some(ran_ue);
        }
        None
    }

    /// Remove all RAN UEs for a gNB
    pub fn ran_ue_remove_all_for_gnb(&self, gnb_id: u64) {
        if let Ok(mut ran_ue_list) = self.ran_ue_list.write() {
            ran_ue_list.retain(|_, ran_ue| ran_ue.gnb_id != gnb_id);
        }
    }

    /// List all RAN UEs attached to a gNB
    pub fn ran_ue_list_for_gnb(&self, gnb_id: u64) -> Vec<RanUe> {
        self.ran_ue_list
            .read()
            .map(|list| {
                list.values()
                    .filter(|ran_ue| ran_ue.gnb_id == gnb_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find RAN UE by pool ID
    pub fn ran_ue_find_by_id(&self, id: u64) -> Option<RanUe> {
        let ran_ue_list = self.ran_ue_list.read().ok()?;
        ran_ue_list.get(&id).cloned()
    }

    /// Find RAN UE by RAN UE NGAP ID within a gNB
    pub fn ran_ue_find_by_ran_ue_ngap_id(&self, gnb_id: u64, ran_ue_ngap_id: u64) -> Option<RanUe> {
        let ran_ue_list = self.ran_ue_list.read().ok()?;
        for ran_ue in ran_ue_list.values() {
            if ran_ue.gnb_id == gnb_id && ran_ue.ran_ue_ngap_id == ran_ue_ngap_id {
                return Some(ran_ue.clone());
            }
        }
        None
    }

    /// Find RAN UE by AMF UE NGAP ID
    pub fn ran_ue_find_by_amf_ue_ngap_id(&self, amf_ue_ngap_id: u64) -> Option<RanUe> {
        let ran_ue_list = self.ran_ue_list.read().ok()?;
        for ran_ue in ran_ue_list.values() {
            if ran_ue.amf_ue_ngap_id == amf_ue_ngap_id {
                return Some(ran_ue.clone());
            }
        }
        None
    }

    /// Find RAN UE by index
    pub fn ran_ue_find_by_index(&self, index: u32) -> Option<RanUe> {
        let ran_ue_list = self.ran_ue_list.read().ok()?;
        for ran_ue in ran_ue_list.values() {
            if ran_ue.index == index {
                return Some(ran_ue.clone());
            }
        }
        None
    }

    /// Update RAN UE in the context
    pub fn ran_ue_update(&self, ran_ue: &RanUe) -> bool {
        let mut ran_ue_list = self.ran_ue_list.write().unwrap();
        if let Some(existing) = ran_ue_list.get_mut(&ran_ue.id) {
            *existing = ran_ue.clone();
            return true;
        }
        false
    }

    /// Switch RAN UE to a new gNB (for handover)
    pub fn ran_ue_switch_to_gnb(&self, ran_ue_id: u64, new_gnb_id: u64) -> bool {
        let mut ran_ue_list = self.ran_ue_list.write().unwrap();
        if let Some(ran_ue) = ran_ue_list.get_mut(&ran_ue_id) {
            ran_ue.gnb_id = new_gnb_id;
            return true;
        }
        false
    }

    /// Get number of RAN UEs
    pub fn ran_ue_count(&self) -> usize {
        self.ran_ue_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // AMF UE Management
    // ========================================================================

    /// Add a new AMF UE
    pub fn amf_ue_add(&self, ran_ue_id: u64) -> Option<AmfUe> {
        let mut amf_ue_list = self.amf_ue_list.write().ok()?;

        if amf_ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_amf_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let amf_ue = AmfUe::new(id, ran_ue_id);
        amf_ue_list.insert(id, amf_ue.clone());

        log::debug!("AMF UE added (id={id})");
        Some(amf_ue)
    }

    /// Remove an AMF UE by ID
    pub fn amf_ue_remove(&self, id: u64) -> Option<AmfUe> {
        let mut amf_ue_list = self.amf_ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;
        let mut guti_ue_hash = self.guti_ue_hash.write().ok()?;

        if let Some(amf_ue) = amf_ue_list.remove(&id) {
            if let Some(ref suci) = amf_ue.suci {
                suci_hash.remove(suci);
            }
            if let Some(ref supi) = amf_ue.supi {
                supi_hash.remove(supi);
            }
            guti_ue_hash.remove(&amf_ue.current_guti);

            // Remove all sessions for this UE
            self.sess_remove_all_for_ue(id);

            log::debug!("AMF UE removed (id={id})");
            return Some(amf_ue);
        }
        None
    }

    /// Remove all AMF UEs
    pub fn amf_ue_remove_all(&self) {
        if let (Ok(mut amf_ue_list), Ok(mut suci_hash), Ok(mut supi_hash), Ok(mut guti_ue_hash)) = (
            self.amf_ue_list.write(),
            self.suci_hash.write(),
            self.supi_hash.write(),
            self.guti_ue_hash.write(),
        ) {
            amf_ue_list.clear();
            suci_hash.clear();
            supi_hash.clear();
            guti_ue_hash.clear();
        }

        // Clear sessions
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.clear();
        }
    }

    /// Find AMF UE by pool ID
    pub fn amf_ue_find_by_id(&self, id: u64) -> Option<AmfUe> {
        let amf_ue_list = self.amf_ue_list.read().ok()?;
        amf_ue_list.get(&id).cloned()
    }

    // Lock-order note: the setters (amf_ue_set_suci/set_supi/update_guti)
    // acquire amf_ue_list BEFORE the hash map. The finders below must never
    // hold the hash lock while acquiring amf_ue_list (ABBA deadlock observed
    // under concurrent SBI handlers): copy the id out, drop the hash guard,
    // then lock the list.

    /// Find AMF UE by SUCI
    pub fn amf_ue_find_by_suci(&self, suci: &str) -> Option<AmfUe> {
        let id = {
            let suci_hash = self.suci_hash.read().ok()?;
            suci_hash.get(suci).copied()
        }?;
        let amf_ue_list = self.amf_ue_list.read().ok()?;
        amf_ue_list.get(&id).cloned()
    }

    /// Find AMF UE by SUPI
    pub fn amf_ue_find_by_supi(&self, supi: &str) -> Option<AmfUe> {
        let id = {
            let supi_hash = self.supi_hash.read().ok()?;
            supi_hash.get(supi).copied()
        }?;
        let amf_ue_list = self.amf_ue_list.read().ok()?;
        amf_ue_list.get(&id).cloned()
    }

    /// Find AMF UE by GUTI
    pub fn amf_ue_find_by_guti(&self, guti: &Guti5gs) -> Option<AmfUe> {
        let id = {
            let guti_ue_hash = self.guti_ue_hash.read().ok()?;
            guti_ue_hash.get(guti).copied()
        }?;
        let amf_ue_list = self.amf_ue_list.read().ok()?;
        amf_ue_list.get(&id).cloned()
    }

    /// Set SUCI for an AMF UE
    pub fn amf_ue_set_suci(&self, id: u64, suci: &str) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        let mut suci_hash = self.suci_hash.write().unwrap();

        if let Some(amf_ue) = amf_ue_list.get_mut(&id) {
            // Remove old SUCI from hash
            if let Some(ref old_suci) = amf_ue.suci {
                suci_hash.remove(old_suci);
            }
            // Set new SUCI
            amf_ue.suci = Some(suci.to_string());
            suci_hash.insert(suci.to_string(), id);
            return true;
        }
        false
    }

    /// Set SUPI for an AMF UE
    pub fn amf_ue_set_supi(&self, id: u64, supi: &str) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        let mut supi_hash = self.supi_hash.write().unwrap();

        if let Some(amf_ue) = amf_ue_list.get_mut(&id) {
            // Remove old SUPI from hash
            if let Some(ref old_supi) = amf_ue.supi {
                supi_hash.remove(old_supi);
            }
            // Set new SUPI
            amf_ue.supi = Some(supi.to_string());
            supi_hash.insert(supi.to_string(), id);
            return true;
        }
        false
    }

    /// Update GUTI for an AMF UE
    pub fn amf_ue_update_guti(&self, id: u64, guti: &Guti5gs) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        let mut guti_ue_hash = self.guti_ue_hash.write().unwrap();

        if let Some(amf_ue) = amf_ue_list.get_mut(&id) {
            // Remove old GUTI from hash
            guti_ue_hash.remove(&amf_ue.current_guti);
            // Set new GUTI
            amf_ue.current_guti = guti.clone();
            guti_ue_hash.insert(guti.clone(), id);
            return true;
        }
        false
    }

    /// Update AMF UE in the context
    pub fn amf_ue_update(&self, amf_ue: &AmfUe) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        if let Some(existing) = amf_ue_list.get_mut(&amf_ue.id) {
            *existing = amf_ue.clone();
            return true;
        }
        false
    }

    /// Associate AMF UE with RAN UE
    pub fn amf_ue_associate_ran_ue(&self, amf_ue_id: u64, ran_ue_id: u64) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        let mut ran_ue_list = self.ran_ue_list.write().unwrap();

        if let (Some(amf_ue), Some(ran_ue)) = (
            amf_ue_list.get_mut(&amf_ue_id),
            ran_ue_list.get_mut(&ran_ue_id),
        ) {
            amf_ue.ran_ue_id = ran_ue_id;
            ran_ue.amf_ue_id = amf_ue_id;
            return true;
        }
        false
    }

    /// Deassociate AMF UE from RAN UE
    pub fn amf_ue_deassociate_ran_ue(&self, amf_ue_id: u64, ran_ue_id: u64) -> bool {
        let mut amf_ue_list = self.amf_ue_list.write().unwrap();
        let mut ran_ue_list = self.ran_ue_list.write().unwrap();

        if let Some(amf_ue) = amf_ue_list.get_mut(&amf_ue_id) {
            amf_ue.ran_ue_id = NEXTGCORE_INVALID_POOL_ID;
        }
        if let Some(ran_ue) = ran_ue_list.get_mut(&ran_ue_id) {
            ran_ue.amf_ue_id = NEXTGCORE_INVALID_POOL_ID;
        }
        true
    }

    /// Get number of AMF UEs
    pub fn amf_ue_count(&self) -> usize {
        self.amf_ue_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Add a new session for an AMF UE
    pub fn sess_add(&self, amf_ue_id: u64, psi: u8) -> Option<AmfSess> {
        let mut sess_list = self.sess_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sess = AmfSess::new(id, amf_ue_id, psi);
        sess_list.insert(id, sess.clone());

        log::debug!("[ue_id={amf_ue_id}, psi={psi}] AMF session added (id={id})");
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<AmfSess> {
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            log::debug!(
                "[ue_id={}, psi={}] AMF session removed (id={})",
                sess.amf_ue_id,
                sess.psi,
                id
            );
            return Some(sess);
        }
        None
    }

    /// Remove all sessions for an AMF UE
    fn sess_remove_all_for_ue(&self, amf_ue_id: u64) {
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.retain(|_, sess| sess.amf_ue_id != amf_ue_id);
        }
    }

    /// Find session by ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<AmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    /// Find session by PSI for an AMF UE
    pub fn sess_find_by_psi(&self, amf_ue_id: u64, psi: u8) -> Option<AmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess.amf_ue_id == amf_ue_id && sess.psi == psi {
                return Some(sess.clone());
            }
        }
        None
    }

    /// Find session by DNN for an AMF UE
    pub fn sess_find_by_dnn(&self, amf_ue_id: u64, dnn: &str) -> Option<AmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess.amf_ue_id == amf_ue_id && sess.dnn.as_deref() == Some(dnn) {
                return Some(sess.clone());
            }
        }
        None
    }

    /// Update session in the context
    pub fn sess_update(&self, sess: &AmfSess) -> bool {
        let mut sess_list = self.sess_list.write().unwrap();
        if let Some(existing) = sess_list.get_mut(&sess.id) {
            *existing = sess.clone();
            return true;
        }
        false
    }

    /// Get number of sessions
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get sessions for an AMF UE
    pub fn sess_list_for_ue(&self, amf_ue_id: u64) -> Vec<AmfSess> {
        let sess_list = self.sess_list.read().unwrap();
        sess_list
            .values()
            .filter(|sess| sess.amf_ue_id == amf_ue_id)
            .cloned()
            .collect()
    }

    // ========================================================================
    // Paging Management (TS 23.502 4.2.3.3)
    // ========================================================================

    /// Initiate paging for a UE in CM-IDLE state
    pub fn paging_add(&self, ctx: PagingContext) -> bool {
        if let Ok(mut paging_map) = self.paging_map.write() {
            let id = ctx.amf_ue_ngap_id;
            log::info!(
                "[UE NGAP ID: {}] Paging initiated (TMSI: 0x{:08x}, TAC: {})",
                id,
                ctx.tmsi,
                ctx.tac
            );
            paging_map.insert(id, ctx);
            return true;
        }
        false
    }

    /// Cancel paging for a UE (e.g., Service Request received)
    pub fn paging_remove(&self, amf_ue_ngap_id: u64) -> Option<PagingContext> {
        if let Ok(mut paging_map) = self.paging_map.write() {
            if let Some(ctx) = paging_map.remove(&amf_ue_ngap_id) {
                log::info!(
                    "[UE NGAP ID: {}] Paging cancelled (retransmit_count: {})",
                    amf_ue_ngap_id,
                    ctx.retransmit_count
                );
                return Some(ctx);
            }
        }
        None
    }

    /// Get paging context for a UE
    pub fn paging_find(&self, amf_ue_ngap_id: u64) -> Option<PagingContext> {
        if let Ok(paging_map) = self.paging_map.read() {
            return paging_map.get(&amf_ue_ngap_id).cloned();
        }
        None
    }

    /// Enqueue a positioning downlink for NGAP-task egress (TS 23.273).
    pub fn positioning_dl_add(&self, item: PendingPositioningDl) {
        if let Ok(mut q) = self.positioning_dl_queue.write() {
            q.push(item);
        }
    }

    /// Drain all pending positioning downlinks (called by the NGAP server pump).
    pub fn positioning_dl_drain(&self) -> Vec<PendingPositioningDl> {
        match self.positioning_dl_queue.write() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => Vec::new(),
        }
    }

    /// Increment retransmit count, returns false if max reached
    pub fn paging_retransmit(&self, amf_ue_ngap_id: u64) -> bool {
        if let Ok(mut paging_map) = self.paging_map.write() {
            if let Some(ctx) = paging_map.get_mut(&amf_ue_ngap_id) {
                if ctx.retransmit_count >= ctx.max_retransmit {
                    log::warn!(
                        "[UE NGAP ID: {}] Paging max retransmissions ({}) reached",
                        amf_ue_ngap_id,
                        ctx.max_retransmit
                    );
                    return false;
                }
                ctx.retransmit_count += 1;
                log::debug!(
                    "[UE NGAP ID: {}] Paging retransmit {}/{}",
                    amf_ue_ngap_id,
                    ctx.retransmit_count,
                    ctx.max_retransmit
                );
                return true;
            }
        }
        false
    }

    /// Process paging timeout - remove expired entries (> 10s default)
    pub fn paging_expire(&self, timeout_secs: u64) -> Vec<PagingContext> {
        let mut expired = Vec::new();
        if let Ok(mut paging_map) = self.paging_map.write() {
            let now = std::time::Instant::now();
            paging_map.retain(|id, ctx| {
                if now.duration_since(ctx.initiated_at).as_secs() > timeout_secs {
                    log::warn!("[UE NGAP ID: {id}] Paging expired after {timeout_secs}s");
                    expired.push(ctx.clone());
                    false
                } else {
                    true
                }
            });
        }
        expired
    }

    /// Get number of active paging entries
    pub fn paging_count(&self) -> usize {
        self.paging_map.read().map(|m| m.len()).unwrap_or(0)
    }

    // ========================================================================
    // Namf_EventExposure Subscription Management (TS 29.518 §5.3)
    //
    // Subscriptions are persisted in the AMF context so they survive across
    // requests. Lock-order rule: these methods only ever take the
    // `event_subscriptions` lock and never call into other lock-taking
    // methods while holding it.
    // ========================================================================

    /// Store an event-exposure subscription. Returns false if the
    /// subscription ID already exists.
    pub fn event_subscription_add(&self, sub: EventSubscription) -> bool {
        if let Ok(mut subs) = self.event_subscriptions.write() {
            if subs.contains_key(&sub.subscription_id) {
                return false;
            }
            subs.insert(sub.subscription_id.clone(), sub);
            true
        } else {
            false
        }
    }

    /// Remove an event-exposure subscription by ID
    pub fn event_subscription_remove(&self, subscription_id: &str) -> Option<EventSubscription> {
        self.event_subscriptions
            .write()
            .ok()
            .and_then(|mut subs| subs.remove(subscription_id))
    }

    /// Find an event-exposure subscription by ID (clone-out, lock dropped)
    pub fn event_subscription_find(&self, subscription_id: &str) -> Option<EventSubscription> {
        self.event_subscriptions
            .read()
            .ok()
            .and_then(|subs| subs.get(subscription_id).cloned())
    }

    /// Replace an existing subscription (modify). Returns false when the
    /// subscription does not exist.
    pub fn event_subscription_update(&self, sub: EventSubscription) -> bool {
        if let Ok(mut subs) = self.event_subscriptions.write() {
            if let std::collections::hash_map::Entry::Occupied(mut e) =
                subs.entry(sub.subscription_id.clone())
            {
                e.insert(sub);
                return true;
            }
        }
        false
    }

    /// Collect subscriptions matching an event type and (optionally) a SUPI.
    /// Expired subscriptions are skipped. Results are cloned out so no lock
    /// is held by the caller.
    pub fn event_subscriptions_matching(
        &self,
        event_type: &str,
        supi: Option<&str>,
    ) -> Vec<EventSubscription> {
        let now = std::time::SystemTime::now();
        self.event_subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| {
                        if let Some(expiry) = s.expiry {
                            if expiry <= now {
                                return false;
                            }
                        }
                        if !s.event_types.iter().any(|t| t == event_type) {
                            return false;
                        }
                        // UE filter: any-UE subscriptions match everything;
                        // single-UE subscriptions must match the SUPI.
                        s.any_ue || (s.supi.is_some() && s.supi.as_deref() == supi)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove expired subscriptions; returns how many were removed.
    pub fn event_subscriptions_remove_expired(&self) -> usize {
        let now = std::time::SystemTime::now();
        if let Ok(mut subs) = self.event_subscriptions.write() {
            let before = subs.len();
            subs.retain(|_, s| s.expiry.map(|e| e > now).unwrap_or(true));
            before - subs.len()
        } else {
            0
        }
    }

    /// Number of stored event-exposure subscriptions
    pub fn event_subscription_count(&self) -> usize {
        self.event_subscriptions
            .read()
            .map(|m| m.len())
            .unwrap_or(0)
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// Get UE load percentage
    pub fn get_ue_load(&self) -> i32 {
        let amf_ue_list = self.amf_ue_list.read().unwrap();
        let used = amf_ue_list.len();
        let total = self.max_num_of_ue;
        if total == 0 {
            return 0;
        }
        ((used * 100) / total) as i32
    }

    /// Find served TAI
    pub fn find_served_tai(&self, tai: &Tai5gs) -> Option<usize> {
        for (i, served_tai) in self.served_tai.iter().enumerate() {
            // Check TAI0 list
            if served_tai.list0.plmn_id == tai.plmn_id {
                for tac in &served_tai.list0.tac {
                    if *tac == tai.tac {
                        return Some(i);
                    }
                }
            }
            // Check TAI2 list
            for t in &served_tai.list2.tai {
                if t.plmn_id == tai.plmn_id && t.tac == tai.tac {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find S-NSSAI for a served PLMN
    pub fn find_s_nssai(&self, plmn_id: &PlmnId, s_nssai: &SNssai) -> Option<SNssai> {
        for plmn_support in &self.plmn_support {
            if plmn_support.plmn_id == *plmn_id {
                for supported_nssai in &plmn_support.s_nssai {
                    if supported_nssai.sst == s_nssai.sst && supported_nssai.sd == s_nssai.sd {
                        return Some(supported_nssai.clone());
                    }
                }
            }
        }
        None
    }
}

impl Default for AmfContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AmfGnb - gNB Context
// ============================================================================

/// gNB state
#[derive(Debug, Clone, Default)]
pub struct GnbState {
    /// NG Setup success flag
    pub ng_setup_success: bool,
}

/// AMF gNB context
#[derive(Debug, Clone)]
pub struct AmfGnb {
    /// Unique pool ID
    pub id: u64,
    /// gNB address string
    pub addr: String,
    /// gNB ID presence flag
    pub gnb_id_presence: bool,
    /// gNB ID (received from gNB)
    pub gnb_id: u32,
    /// PLMN ID (received from gNB)
    pub plmn_id: PlmnId,
    /// gNB state
    pub state: GnbState,
    /// Maximum number of outbound streams
    pub max_num_of_ostreams: i32,
    /// Output stream ID generator
    pub ostream_id: u16,
    /// Number of supported TA entries
    pub num_of_supported_ta_list: usize,
    /// Supported TA list
    pub supported_ta_list: Vec<SupportedTa>,
    /// RAT type
    pub rat_type: RatType,
}

impl AmfGnb {
    /// Create a new gNB context
    pub fn new(id: u64, addr: &str) -> Self {
        Self {
            id,
            addr: addr.to_string(),
            gnb_id_presence: false,
            gnb_id: 0,
            plmn_id: PlmnId::default(),
            state: GnbState::default(),
            max_num_of_ostreams: 0,
            ostream_id: 0,
            num_of_supported_ta_list: 0,
            supported_ta_list: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SUPPORTED_TA),
            rat_type: RatType::Nr,
        }
    }

    /// Get next output stream ID
    pub fn next_ostream_id(&mut self) -> u16 {
        if self.max_num_of_ostreams <= 1 {
            return 0;
        }
        let id = self.ostream_id;
        self.ostream_id = (self.ostream_id + 1) % (self.max_num_of_ostreams as u16);
        id
    }
}

// ============================================================================
// RanUe - RAN UE Context
// ============================================================================

/// RAN UE context
#[derive(Debug, Clone)]
pub struct RanUe {
    /// Unique pool ID
    pub id: u64,
    /// Index (for finding by index)
    pub index: u32,
    /// RAN UE NGAP ID (received from RAN)
    pub ran_ue_ngap_id: u64,
    /// AMF UE NGAP ID (assigned by AMF)
    pub amf_ue_ngap_id: u64,
    /// gNB output stream ID
    pub gnb_ostream_id: u16,
    /// UE context requested flag
    pub ue_context_requested: bool,
    /// Initial context setup request sent flag
    pub initial_context_setup_request_sent: bool,
    /// Initial context setup response received flag
    pub initial_context_setup_response_received: bool,
    /// UE AMBR sent flag
    pub ue_ambr_sent: bool,
    /// Source UE ID (for handover)
    pub source_ue_id: u64,
    /// Target UE ID (for handover)
    pub target_ue_id: u64,
    /// Saved TAI
    pub saved_nr_tai: Tai5gs,
    /// Saved NR CGI
    pub saved_nr_cgi: NrCgi,
    /// UE context release action
    pub ue_ctx_rel_action: NgapUeCtxRelAction,
    /// Part of NG reset requested flag
    pub part_of_ng_reset_requested: bool,
    /// Activated PSI mask
    pub psimask_activated: u16,
    /// Deactivation cause
    pub deactivation: NgapCause,
    /// Associated gNB ID
    pub gnb_id: u64,
    /// Associated AMF UE ID
    pub amf_ue_id: u64,
}

impl RanUe {
    /// Create a new RAN UE context
    pub fn new(id: u64, index: u32, gnb_id: u64, ran_ue_ngap_id: u64, amf_ue_ngap_id: u64) -> Self {
        Self {
            id,
            index,
            ran_ue_ngap_id,
            amf_ue_ngap_id,
            gnb_ostream_id: 0,
            ue_context_requested: false,
            initial_context_setup_request_sent: false,
            initial_context_setup_response_received: false,
            ue_ambr_sent: false,
            source_ue_id: NEXTGCORE_INVALID_POOL_ID,
            target_ue_id: NEXTGCORE_INVALID_POOL_ID,
            saved_nr_tai: Tai5gs::default(),
            saved_nr_cgi: NrCgi::default(),
            ue_ctx_rel_action: NgapUeCtxRelAction::Invalid,
            part_of_ng_reset_requested: false,
            psimask_activated: 0,
            deactivation: NgapCause::default(),
            gnb_id,
            amf_ue_id: NEXTGCORE_INVALID_POOL_ID,
        }
    }
}

impl Default for RanUe {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

// ============================================================================
// AmfUeMemento - Backup of UE Security Context
// ============================================================================

/// AMF UE memento (backup of security context)
#[derive(Debug, Clone, Default)]
pub struct AmfUeMemento {
    /// UE security capability
    pub ue_security_capability: UeSecurityCapability,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// Random challenge value
    pub rand: [u8; NEXTGCORE_RAND_LEN],
    /// Authentication token
    pub autn: [u8; NEXTGCORE_AUTN_LEN],
    /// Expected auth response
    pub xres_star: [u8; NEXTGCORE_MAX_RES_LEN],
    /// ABBA value
    pub abba: [u8; NEXTGCORE_NAS_MAX_ABBA_LEN],
    /// ABBA length
    pub abba_len: u8,
    /// Hash of XRES*
    pub hxres_star: [u8; NEXTGCORE_MAX_RES_LEN],
    /// Key for AMF derived from NAS key
    pub kamf: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Integrity key
    pub knas_int: [u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
    /// Ciphering key
    pub knas_enc: [u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
    /// Downlink counter
    pub dl_count: u32,
    /// Uplink counter
    pub ul_count: u32,
    /// nas-06 Phase-6 strict-path replay baseline (persisted with ul_count).
    pub ul_count_established: bool,
    /// gNB key
    pub kgnb: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Next hop key
    pub nh: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Selected encryption algorithm
    pub selected_enc_algorithm: u8,
    /// Selected integrity algorithm
    pub selected_int_algorithm: u8,
}

// ============================================================================
// NAS State
// ============================================================================

/// NAS state for AMF UE
#[derive(Debug, Clone, Default)]
pub struct NasState {
    /// Type of last specific NAS message received
    pub message_type: u8,
    /// Access type (3GPP or Non-3GPP)
    pub access_type: i32,
    /// AMF TSC and KSI
    pub amf_tsc: u8,
    pub amf_ksi: u8,
    /// UE TSC and KSI
    pub ue_tsc: u8,
    pub ue_ksi: u8,
    /// Registration type
    pub registration_type: u8,
    /// De-registration type
    pub de_registration_type: u8,
    /// Present flags
    pub uplink_data_status: bool,
    pub pdu_session_status: bool,
    pub allowed_pdu_session_status: bool,
}

/// GMM capability
#[derive(Debug, Clone, Default)]
pub struct GmmCapability {
    /// LTE positioning protocol capability
    pub lte_positioning_protocol_capability: bool,
    /// Handover attach
    pub ho_attach: bool,
    /// S1 mode
    pub s1_mode: bool,
}

/// Policy association
#[derive(Debug, Clone, Default)]
pub struct PolicyAssociation {
    /// Resource URI
    pub resource_uri: Option<String>,
    /// ID
    pub id: Option<String>,
}

/// 5G AKA confirmation
#[derive(Debug, Clone, Default)]
pub struct Confirmation5gAka {
    /// Resource URI
    pub resource_uri: Option<String>,
}

/// Data change subscription
#[derive(Debug, Clone, Default)]
pub struct DataChangeSubscription {
    /// Resource URI
    pub resource_uri: Option<String>,
    /// ID
    pub id: Option<String>,
}

/// Handover info
#[derive(Debug, Clone, Default)]
pub struct HandoverInfo {
    /// Handover type
    pub handover_type: i32,
    /// Container
    pub container: Vec<u8>,
    /// Cause group
    pub cause_group: u8,
    /// Cause
    pub cause: i64,
}

/// Explicit de-registration state
#[derive(Debug, Clone, Default)]
pub struct ExplicitDeRegistered {
    /// N1 done flag
    pub n1_done: bool,
    /// SBI done flag
    pub sbi_done: bool,
}

// ============================================================================
// AmfUe - AMF UE Context
// ============================================================================

/// AMF UE context
#[derive(Debug, Clone)]
pub struct AmfUe {
    /// Unique pool ID
    pub id: u64,
    /// NAS state
    pub nas: NasState,
    /// SUCI (Subscription Concealed Identifier)
    pub suci: Option<String>,
    /// SUPI (Subscription Permanent Identifier)
    pub supi: Option<String>,
    /// Home PLMN ID
    pub home_plmn_id: PlmnId,
    /// PEI (Permanent Equipment Identifier)
    pub pei: Option<String>,
    /// Masked IMEISV
    pub masked_imeisv: [u8; NEXTGCORE_MAX_IMEISV_LEN],
    /// Masked IMEISV length
    pub masked_imeisv_len: usize,
    /// IMEISV BCD
    pub imeisv_bcd: String,
    /// Number of MSISDNs
    pub num_of_msisdn: usize,
    /// MSISDN list
    pub msisdn: Vec<String>,
    /// Current M-TMSI
    pub current_m_tmsi: Option<u32>,
    /// Current GUTI
    pub current_guti: Guti5gs,
    /// Next M-TMSI
    pub next_m_tmsi: Option<u32>,
    /// Next GUTI
    pub next_guti: Guti5gs,
    /// Old GUTI (for context transfer)
    pub old_guti: Guti5gs,
    /// UE context transfer state
    pub amf_ue_context_transfer_state: UeContextTransferState,
    /// GUAMI pointer index
    pub guami_index: Option<usize>,
    /// gNB output stream ID
    pub gnb_ostream_id: u16,
    /// NR TAI
    pub nr_tai: Tai5gs,
    /// NR CGI
    pub nr_cgi: NrCgi,
    /// UE location timestamp
    pub ue_location_timestamp: u64,
    /// Last visited PLMN ID
    pub last_visited_plmn_id: PlmnId,
    /// Requested NSSAI
    pub requested_nssai: Vec<SNssai>,
    /// Allowed NSSAI
    pub allowed_nssai: Vec<SNssai>,
    /// Rejected NSSAI
    pub rejected_nssai: Vec<SNssai>,
    /// Policy association
    pub policy_association: PolicyAssociation,
    /// GMM capability
    pub gmm_capability: GmmCapability,
    /// Security context available flag
    pub security_context_available: bool,
    /// MAC failed flag
    pub mac_failed: bool,
    /// Can restore context flag
    pub can_restore_context: bool,
    /// Memento (backup of security context)
    pub memento: AmfUeMemento,
    /// UE security capability
    pub ue_security_capability: UeSecurityCapability,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// 5G AKA confirmation
    pub confirmation_for_5g_aka: Confirmation5gAka,
    /// Random challenge value
    pub rand: [u8; NEXTGCORE_RAND_LEN],
    /// Expected auth response
    pub xres_star: [u8; NEXTGCORE_MAX_RES_LEN],
    /// ABBA value
    pub abba: [u8; NEXTGCORE_NAS_MAX_ABBA_LEN],
    /// ABBA length
    pub abba_len: u8,
    /// Hash of XRES*
    pub hxres_star: [u8; NEXTGCORE_MAX_RES_LEN],
    /// Key for AMF
    pub kamf: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Auth result
    pub auth_result: AuthResult,
    /// Integrity key
    pub knas_int: [u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
    /// Ciphering key
    pub knas_enc: [u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
    /// Downlink counter
    pub dl_count: u32,
    /// Uplink counter
    pub ul_count: u32,
    /// nas-06 Phase-6 CANARY (default false): when true, the NAS security
    /// ENCODE/DECODE path delegates to the conformant nextgcore-nas
    /// protect/unprotect adapter (strict MAC + replay) instead of the
    /// hand-rolled lenient path. Default-OFF keeps production behavior
    /// byte-for-byte unchanged. Flipping the default + removing the
    /// hand-rolled path is DEFERRED pending matched-sim + Open5GS E2E
    /// (reg + PDU + ping). See `nas_security.rs`.
    pub use_ogs_nas_security: bool,
    /// nas-06 Phase-6 strict-path state: true once an uplink NAS message has
    /// been successfully integrity-verified. Gates replay rejection so the
    /// first (COUNT 0) message is not self-rejected. Only consulted on the
    /// `use_ogs_nas_security` path; persisted via the memento.
    pub ul_count_established: bool,
    /// gNB key
    pub kgnb: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Next hop chaining counter
    pub nhcc: u8,
    /// Next hop key
    pub nh: [u8; NEXTGCORE_SHA256_DIGEST_SIZE],
    /// Selected encryption algorithm
    pub selected_enc_algorithm: u8,
    /// Selected integrity algorithm
    pub selected_int_algorithm: u8,
    /// UE AMBR
    pub ue_ambr: Bitrate,
    /// Number of slices
    pub num_of_slice: usize,
    /// Slice data
    pub slice: Vec<SliceData>,
    /// AM policy control features
    pub am_policy_control_features: u64,
    /// Associated RAN UE ID
    pub ran_ue_id: u64,
    /// Holding RAN UE ID
    pub ran_ue_holding_id: u64,
    /// UE Radio Capability
    pub ue_radio_capability: Vec<u8>,
    /// Handover info
    pub handover: HandoverInfo,
    /// Data change subscription
    pub data_change_subscription: DataChangeSubscription,
    /// Explicit de-registration state
    pub explicit_de_registered: ExplicitDeRegistered,

    // ========================================================================
    // GMM Handler Fields (added for gmm_build.rs and gmm_handler.rs)
    // ========================================================================
    /// Access type (1 = 3GPP, 2 = Non-3GPP)
    pub access_type: u8,
    /// Registration type
    pub registration_type: u8,
    /// NAS message type
    pub nas_message_type: u8,
    /// NAS TSC (Type of Security Context)
    pub nas_tsc: u8,
    /// NAS KSI (Key Set Identifier)
    pub nas_ksi: u8,
    /// NAS UE TSC
    pub nas_ue_tsc: u8,
    /// NAS UE KSI
    pub nas_ue_ksi: u8,
    /// PDU session status present flag
    pub pdu_session_status_present: bool,
    /// PDU session status
    pub pdu_session_status: u16,
    /// Uplink data status present flag
    pub uplink_data_status_present: bool,
    /// Uplink data status
    pub uplink_data_status: u16,
    /// Switch off flag (for deregistration)
    pub switch_off: bool,
    /// T3560 timer running flag
    pub t3560_running: bool,
    /// IMEISV
    pub imeisv: Option<String>,
    /// Pending N1 SM message
    pub pending_n1_sm_msg: Option<Vec<u8>>,
    /// Pending PSI
    pub pending_psi: Option<u8>,
    /// Sessions list (for PDU session status calculation)
    pub sessions: Vec<AmfSessRef>,
    /// AUTN as Vec for variable length
    pub autn: Vec<u8>,

    // ========================================================================
    // Rel-17 Feature Fields
    // ========================================================================
    /// RedCap (Reduced Capability) UE indication (TS 38.101)
    pub redcap_indication: bool,
    /// SNPN NID if UE is registering via SNPN
    pub snpn_nid: Option<String>,
    /// CAG (Closed Access Group) ID for SNPN
    pub cag_id: Option<u32>,
    /// Slice admission control result (from NSACF)
    pub slice_admission_granted: bool,
    /// UE Route Selection Policy rules (from PCF)
    pub ursp_rules: Vec<UrspPolicyRule>,
    /// ProSe capability
    pub prose_capable: bool,
    /// PIN (Personal IoT Network) role
    pub pin_role: Option<String>,
    /// UAV (aerial UE) flight authorization context (Rel-18, TS 23.256). Set
    /// when the UE registers as an aerial UE (UAV indication IE); drives the
    /// geofence on UAV tracking reports.
    pub uav_auth: Option<UavAuthorizationContext>,
}

/// URSP policy rule for UE policy delivery (TS 24.526)
#[derive(Debug, Clone, Default)]
pub struct UrspPolicyRule {
    /// Rule precedence (lower = higher priority)
    pub precedence: u8,
    /// Traffic descriptor (app ID or IP descriptor)
    pub traffic_descriptor: String,
    /// Preferred S-NSSAI SST
    pub preferred_sst: Option<u8>,
    /// Preferred DNN
    pub preferred_dnn: Option<String>,
}

// ============================================================================
// Rel-17 SNPN Authentication (TS 23.501, TS 33.501)
// ============================================================================

/// SNPN Authentication Context
#[derive(Debug, Clone, Default)]
pub struct SnpnAuthContext {
    /// NID (Network Identifier) - identifies the SNPN
    pub nid: String,
    /// Subscription credentials for SNPN authentication
    pub subscription_credentials: Option<SnpnSubscriptionCredentials>,
    /// Onboarding state
    pub onboarding_state: SnpnOnboardingState,
    /// Timestamp of last authentication
    pub last_auth_time: u64,
}

/// SNPN subscription credentials
#[derive(Debug, Clone, Default)]
pub struct SnpnSubscriptionCredentials {
    /// K (128-bit authentication key)
    pub k: [u8; 16],
    /// OPc (128-bit operator variant key)
    pub opc: [u8; 16],
    /// AMF value (2 bytes)
    pub amf: [u8; 2],
    /// SQN (6 bytes)
    pub sqn: [u8; 6],
}

/// SNPN onboarding state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnpnOnboardingState {
    /// Not onboarded
    #[default]
    NotOnboarded,
    /// Onboarding in progress
    OnboardingInProgress,
    /// Onboarded (credentials provisioned)
    Onboarded,
    /// Onboarding failed
    OnboardingFailed,
}

impl AmfUe {
    /// Start SNPN-specific authentication
    /// Returns true if SNPN authentication should proceed
    pub fn start_snpn_auth(&mut self, nid: &str) -> bool {
        if self.snpn_nid.is_none() {
            self.snpn_nid = Some(nid.to_string());
            log::info!("[SNPN Auth] Starting SNPN authentication for UE with NID={nid}");
            return true;
        }
        false
    }

    /// Handle SNPN onboarding process
    /// This provisions initial credentials for a new SNPN UE
    pub fn handle_snpn_onboarding(
        &mut self,
        nid: &str,
        _credentials: SnpnSubscriptionCredentials,
    ) -> bool {
        self.snpn_nid = Some(nid.to_string());
        log::info!("[SNPN Onboarding] Provisioning credentials for UE in SNPN NID={nid}");
        // In production, this would contact DCS (Default Credential Server)
        // and provision initial K/OPc for the UE
        true
    }

    /// Validate NID (Network Identifier) against allowed SNPN list
    pub fn validate_nid(&self, nid: &str, allowed_nids: &[String]) -> bool {
        if allowed_nids.is_empty() {
            // If no NID restriction, accept all
            return true;
        }
        allowed_nids.iter().any(|allowed| allowed == nid)
    }
}

// ============================================================================
// Rel-18 UAV Support (TS 23.256)
// ============================================================================

/// UAV Authorization Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UavAuthorizationStatus {
    /// Not authorized
    #[default]
    NotAuthorized,
    /// Authorized for flight
    Authorized,
    /// Authorization revoked
    Revoked,
    /// Authorization pending
    Pending,
}

/// UAV Flight Path Point
#[derive(Debug, Clone, Default)]
pub struct UavFlightPathPoint {
    /// Latitude (decimal degrees)
    pub latitude: f64,
    /// Longitude (decimal degrees)
    pub longitude: f64,
    /// Altitude (meters)
    pub altitude: f64,
    /// Timestamp when this point should be reached
    pub timestamp: u64,
}

/// UAV Geofence Violation Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UavGeofenceViolation {
    /// Altitude exceeded
    AltitudeExceeded,
    /// Outside permitted area
    OutsidePermittedArea,
    /// Flight path deviation
    FlightPathDeviation,
    /// Time constraint violation
    TimeConstraintViolation,
}

/// UAV Authorization Context (per TS 23.256)
#[derive(Debug, Clone, Default)]
pub struct UavAuthorizationContext {
    /// UAV ID (UAVID from CAA - Civil Aviation Authority)
    pub uav_id: Option<String>,
    /// CAA-level UAV identifier
    pub caa_level_id: Option<String>,
    /// UAV serial number
    pub serial_number: Option<String>,
    /// Authorization status
    pub authorization_status: UavAuthorizationStatus,
    /// Authorized flight path (sequence of waypoints)
    pub flight_path: Vec<UavFlightPathPoint>,
    /// Geofence constraints (min/max altitude, permitted area)
    pub min_altitude: f64,
    pub max_altitude: f64,
    /// Permitted latitude range
    pub min_latitude: f64,
    pub max_latitude: f64,
    /// Permitted longitude range
    pub min_longitude: f64,
    pub max_longitude: f64,
    /// Flight authorization start time
    pub auth_start_time: u64,
    /// Flight authorization end time
    pub auth_end_time: u64,
    /// Last reported position
    pub last_latitude: f64,
    pub last_longitude: f64,
    pub last_altitude: f64,
    pub last_position_time: u64,
    /// Geofence violations detected
    pub violations: Vec<UavGeofenceViolation>,
}

impl UavAuthorizationContext {
    /// Create a new UAV authorization context
    pub fn new(uav_id: &str, serial_number: &str) -> Self {
        Self {
            uav_id: Some(uav_id.to_string()),
            serial_number: Some(serial_number.to_string()),
            authorization_status: UavAuthorizationStatus::NotAuthorized,
            flight_path: Vec::new(),
            min_altitude: 0.0,
            max_altitude: 120.0, // Default 120m per regulations
            min_latitude: -90.0,
            max_latitude: 90.0,
            min_longitude: -180.0,
            max_longitude: 180.0,
            auth_start_time: 0,
            auth_end_time: 0,
            last_latitude: 0.0,
            last_longitude: 0.0,
            last_altitude: 0.0,
            last_position_time: 0,
            violations: Vec::new(),
            caa_level_id: None,
        }
    }

    /// Grant UAV authorization
    pub fn grant_authorization(&mut self, start_time: u64, end_time: u64) {
        self.authorization_status = UavAuthorizationStatus::Authorized;
        self.auth_start_time = start_time;
        self.auth_end_time = end_time;
        log::info!(
            "[UAV Auth] Authorization granted for UAV ID {:?} from {} to {}",
            self.uav_id,
            start_time,
            end_time
        );
    }

    /// Revoke UAV authorization
    pub fn revoke_authorization(&mut self, reason: &str) {
        self.authorization_status = UavAuthorizationStatus::Revoked;
        log::warn!(
            "[UAV Auth] Authorization revoked for UAV ID {:?}: {}",
            self.uav_id,
            reason
        );
    }

    /// Update UAV position and check geofence violations
    pub fn update_position(
        &mut self,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        timestamp: u64,
    ) -> bool {
        self.last_latitude = latitude;
        self.last_longitude = longitude;
        self.last_altitude = altitude;
        self.last_position_time = timestamp;

        let mut violation_detected = false;

        // Check altitude constraints
        if altitude > self.max_altitude {
            log::warn!(
                "[UAV Tracking] Altitude violation: {:.1}m > {:.1}m for UAV {:?}",
                altitude,
                self.max_altitude,
                self.uav_id
            );
            self.violations.push(UavGeofenceViolation::AltitudeExceeded);
            violation_detected = true;
        }

        // Check geographic constraints
        if latitude < self.min_latitude
            || latitude > self.max_latitude
            || longitude < self.min_longitude
            || longitude > self.max_longitude
        {
            log::warn!(
                "[UAV Tracking] Geofence violation: ({:.6}, {:.6}) outside permitted area for UAV {:?}",
                latitude,
                longitude,
                self.uav_id
            );
            self.violations
                .push(UavGeofenceViolation::OutsidePermittedArea);
            violation_detected = true;
        }

        !violation_detected
    }

    /// Set geofence boundaries
    pub fn set_geofence(
        &mut self,
        min_lat: f64,
        max_lat: f64,
        min_lon: f64,
        max_lon: f64,
        min_alt: f64,
        max_alt: f64,
    ) {
        self.min_latitude = min_lat;
        self.max_latitude = max_lat;
        self.min_longitude = min_lon;
        self.max_longitude = max_lon;
        self.min_altitude = min_alt;
        self.max_altitude = max_alt;
    }

    /// Add waypoint to flight path
    pub fn add_flight_waypoint(
        &mut self,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        timestamp: u64,
    ) {
        self.flight_path.push(UavFlightPathPoint {
            latitude,
            longitude,
            altitude,
            timestamp,
        });
    }

    /// Check if currently authorized
    pub fn is_authorized(&self, current_time: u64) -> bool {
        self.authorization_status == UavAuthorizationStatus::Authorized
            && current_time >= self.auth_start_time
            && current_time <= self.auth_end_time
    }
}

/// Reference to an AMF session (for PDU session status)
#[derive(Debug, Clone, Default)]
pub struct AmfSessRef {
    /// PSI
    pub psi: u8,
    /// SM context in SMF flag
    pub sm_context_in_smf: bool,
}

impl AmfUe {
    /// Create a new AMF UE context
    pub fn new(id: u64, ran_ue_id: u64) -> Self {
        Self {
            id,
            nas: NasState::default(),
            suci: None,
            supi: None,
            home_plmn_id: PlmnId::default(),
            pei: None,
            masked_imeisv: [0u8; NEXTGCORE_MAX_IMEISV_LEN],
            masked_imeisv_len: 0,
            imeisv_bcd: String::new(),
            num_of_msisdn: 0,
            msisdn: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_MSISDN),
            current_m_tmsi: None,
            current_guti: Guti5gs::default(),
            next_m_tmsi: None,
            next_guti: Guti5gs::default(),
            old_guti: Guti5gs::default(),
            amf_ue_context_transfer_state: UeContextTransferState::Initial,
            guami_index: None,
            gnb_ostream_id: 0,
            nr_tai: Tai5gs::default(),
            nr_cgi: NrCgi::default(),
            ue_location_timestamp: 0,
            last_visited_plmn_id: PlmnId::default(),
            requested_nssai: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SLICE),
            allowed_nssai: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SLICE),
            rejected_nssai: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SLICE),
            policy_association: PolicyAssociation::default(),
            gmm_capability: GmmCapability::default(),
            security_context_available: false,
            mac_failed: false,
            can_restore_context: false,
            memento: AmfUeMemento::default(),
            ue_security_capability: UeSecurityCapability::default(),
            ue_network_capability: UeNetworkCapability::default(),
            confirmation_for_5g_aka: Confirmation5gAka::default(),
            rand: [0u8; NEXTGCORE_RAND_LEN],
            xres_star: [0u8; NEXTGCORE_MAX_RES_LEN],
            abba: [0u8; NEXTGCORE_NAS_MAX_ABBA_LEN],
            abba_len: 0,
            hxres_star: [0u8; NEXTGCORE_MAX_RES_LEN],
            kamf: [0u8; NEXTGCORE_SHA256_DIGEST_SIZE],
            auth_result: AuthResult::default(),
            knas_int: [0u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
            knas_enc: [0u8; NEXTGCORE_SHA256_DIGEST_SIZE / 2],
            dl_count: 0,
            ul_count: 0,
            use_ogs_nas_security: false,
            ul_count_established: false,
            kgnb: [0u8; NEXTGCORE_SHA256_DIGEST_SIZE],
            nhcc: 0,
            nh: [0u8; NEXTGCORE_SHA256_DIGEST_SIZE],
            selected_enc_algorithm: 0,
            selected_int_algorithm: 0,
            ue_ambr: Bitrate::default(),
            num_of_slice: 0,
            slice: Vec::with_capacity(NEXTGCORE_MAX_NUM_OF_SLICE),
            am_policy_control_features: 0,
            ran_ue_id,
            ran_ue_holding_id: NEXTGCORE_INVALID_POOL_ID,
            ue_radio_capability: Vec::new(),
            handover: HandoverInfo::default(),
            data_change_subscription: DataChangeSubscription::default(),
            explicit_de_registered: ExplicitDeRegistered::default(),
            // GMM Handler fields
            access_type: 1, // Default to 3GPP
            registration_type: 0,
            nas_message_type: 0,
            nas_tsc: 0,
            nas_ksi: NEXTGCORE_NAS_KSI_NO_KEY_IS_AVAILABLE,
            nas_ue_tsc: 0,
            nas_ue_ksi: NEXTGCORE_NAS_KSI_NO_KEY_IS_AVAILABLE,
            pdu_session_status_present: false,
            pdu_session_status: 0,
            uplink_data_status_present: false,
            uplink_data_status: 0,
            switch_off: false,
            t3560_running: false,
            imeisv: None,
            pending_n1_sm_msg: None,
            pending_psi: None,
            sessions: Vec::new(),
            autn: vec![0u8; NEXTGCORE_AUTN_LEN],
            redcap_indication: false,
            snpn_nid: None,
            cag_id: None,
            // Default deny: slice admission is granted only by an explicit
            // Nnsacf_NSAC admittedFlag=true response (TS 29.536), never assumed.
            slice_admission_granted: false,
            ursp_rules: Vec::new(),
            prose_capable: false,
            pin_role: None,
            uav_auth: None,
        }
    }

    /// Check if security context is valid
    pub fn security_context_is_valid(&self) -> bool {
        self.security_context_available
            && !self.mac_failed
            && self.nas.ue_ksi != NEXTGCORE_NAS_KSI_NO_KEY_IS_AVAILABLE
    }

    /// Clear security context
    pub fn clear_security_context(&mut self) {
        self.security_context_available = false;
        self.mac_failed = false;
    }

    /// Check if UE has SUCI
    pub fn has_suci(&self) -> bool {
        self.suci.is_some()
    }

    /// Check if UE has SUPI
    pub fn has_supi(&self) -> bool {
        self.supi.is_some()
    }

    /// Check if PCF AM policy is associated
    pub fn pcf_am_policy_associated(&self) -> bool {
        self.policy_association.id.is_some()
    }

    /// Clear PCF AM policy
    pub fn pcf_am_policy_clear(&mut self) {
        self.policy_association.resource_uri = None;
        self.policy_association.id = None;
    }

    /// Check if 5G AKA confirmation exists
    pub fn check_5g_aka_confirmation(&self) -> bool {
        self.confirmation_for_5g_aka.resource_uri.is_some()
    }

    /// Clear 5G AKA confirmation
    pub fn clear_5g_aka_confirmation(&mut self) {
        self.confirmation_for_5g_aka.resource_uri = None;
    }

    /// Check if UDM SDM is subscribed
    pub fn udm_sdm_subscribed(&self) -> bool {
        self.data_change_subscription.id.is_some()
    }

    /// Clear UDM SDM subscription
    pub fn udm_sdm_clear(&mut self) {
        self.data_change_subscription.resource_uri = None;
        self.data_change_subscription.id = None;
    }

    /// Save memento (backup security context)
    pub fn save_memento(&mut self) {
        self.memento.ue_security_capability = self.ue_security_capability.clone();
        self.memento.ue_network_capability = self.ue_network_capability.clone();
        self.memento.rand = self.rand;
        // Copy from Vec to fixed-size array
        let len = self.autn.len().min(NEXTGCORE_AUTN_LEN);
        self.memento.autn[..len].copy_from_slice(&self.autn[..len]);
        self.memento.xres_star = self.xres_star;
        self.memento.abba = self.abba;
        self.memento.abba_len = self.abba_len;
        self.memento.hxres_star = self.hxres_star;
        self.memento.kamf = self.kamf;
        self.memento.knas_int = self.knas_int;
        self.memento.knas_enc = self.knas_enc;
        self.memento.dl_count = self.dl_count;
        self.memento.ul_count = self.ul_count;
        self.memento.ul_count_established = self.ul_count_established;
        self.memento.kgnb = self.kgnb;
        self.memento.nh = self.nh;
        self.memento.selected_enc_algorithm = self.selected_enc_algorithm;
        self.memento.selected_int_algorithm = self.selected_int_algorithm;
    }

    /// Restore memento (restore security context)
    pub fn restore_memento(&mut self) {
        self.ue_security_capability = self.memento.ue_security_capability.clone();
        self.ue_network_capability = self.memento.ue_network_capability.clone();
        self.rand = self.memento.rand;
        self.autn = self.memento.autn.to_vec();
        self.xres_star = self.memento.xres_star;
        self.abba = self.memento.abba;
        self.abba_len = self.memento.abba_len;
        self.hxres_star = self.memento.hxres_star;
        self.kamf = self.memento.kamf;
        self.knas_int = self.memento.knas_int;
        self.knas_enc = self.memento.knas_enc;
        self.dl_count = self.memento.dl_count;
        self.ul_count = self.memento.ul_count;
        self.ul_count_established = self.memento.ul_count_established;
        self.kgnb = self.memento.kgnb;
        self.nh = self.memento.nh;
        self.selected_enc_algorithm = self.memento.selected_enc_algorithm;
        self.selected_int_algorithm = self.memento.selected_int_algorithm;
    }

    // ========================================================================
    // GMM Handler Helper Methods
    // ========================================================================

    /// Clear paging info
    pub fn clear_paging_info(&mut self) {
        // Clear paging-related state
    }

    /// Clear all timers
    pub fn clear_timers(&mut self) {
        self.t3560_running = false;
        // Clear other timers as needed
    }

    /// Generate new GUTI with a cryptographically random 5G-TMSI
    /// (TS 23.003 Section 2.10.1: the M-TMSI must not be predictable —
    /// never an NGAP-ID cast or a timestamp).
    pub fn generate_new_guti(&mut self) {
        self.next_guti.tmsi = generate_random_tmsi();
        self.next_m_tmsi = Some(self.next_guti.tmsi);
    }
}

/// Generate a cryptographically random 5G-TMSI (CSPRNG via the OS RNG).
///
/// Avoids the reserved all-zeros / all-ones values (TS 23.003).
pub fn generate_random_tmsi() -> u32 {
    loop {
        // uuid::Uuid::new_v4 sources its bytes from the OS CSPRNG (getrandom)
        let bytes = uuid::Uuid::new_v4();
        let b = bytes.as_bytes();
        let tmsi = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if tmsi != 0 && tmsi != u32::MAX {
            return tmsi;
        }
    }
}

impl Default for AmfUe {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// AmfSess - PDU Session Context
// ============================================================================

/// Paging context for tracking UEs awaiting paging response (TS 23.502 4.2.3.3)
#[derive(Debug, Clone)]
pub struct PagingContext {
    /// UE NGAP ID (AMF-side)
    pub amf_ue_ngap_id: u64,
    /// 5G-S-TMSI for paging
    pub tmsi: u32,
    /// AMF Set ID for paging identity
    pub amf_set_id: u16,
    /// AMF Pointer for paging identity
    pub amf_pointer: u8,
    /// PLMN for paging area
    pub plmn_id: PlmnId,
    /// TAC for paging area
    pub tac: u32,
    /// Timestamp when paging was initiated
    pub initiated_at: std::time::Instant,
    /// Number of paging retransmissions
    pub retransmit_count: u8,
    /// Maximum retransmissions before giving up
    pub max_retransmit: u8,
    /// Pending N1 message to deliver after paging response
    pub pending_n1: Option<Vec<u8>>,
    /// Pending N2 info to deliver after paging response
    pub pending_n2: Option<Vec<u8>>,
    /// PDU session ID that triggered paging
    pub pdu_session_id: Option<u8>,
}

impl Default for PagingContext {
    fn default() -> Self {
        Self {
            amf_ue_ngap_id: 0,
            tmsi: 0,
            amf_set_id: 0,
            amf_pointer: 0,
            plmn_id: PlmnId::default(),
            tac: 0,
            initiated_at: std::time::Instant::now(),
            retransmit_count: 0,
            max_retransmit: 4,
            pending_n1: None,
            pending_n2: None,
            pdu_session_id: None,
        }
    }
}

/// Session paging info
#[derive(Debug, Clone, Default)]
pub struct SessionPaging {
    /// Paging ongoing flag
    pub ongoing: bool,
    /// Location in N1N2MessageTransferRspData
    pub location: Option<String>,
    /// N1N2 failure transfer notification URI
    pub n1n2_failure_txf_notif_uri: Option<String>,
}

/// GSM message info
#[derive(Debug, Clone, Default)]
pub struct GsmMessage {
    /// Message type
    pub message_type: u8,
    /// N1 buffer
    pub n1buf: Option<Vec<u8>>,
    /// N2 buffer
    pub n2buf: Option<Vec<u8>>,
}

/// NSSF info
#[derive(Debug, Clone, Default)]
pub struct NssfInfo {
    /// NSI ID
    pub nsi_id: Option<String>,
    /// NRF URI
    pub nrf_uri: Option<String>,
    /// HNRF URI
    pub hnrf_uri: Option<String>,
}

/// N2 transfer buffers
#[derive(Debug, Clone, Default)]
pub struct N2Transfer {
    /// PDU session resource setup request
    pub pdu_session_resource_setup_request: Option<Vec<u8>>,
    /// PDU session resource modification command
    pub pdu_session_resource_modification_command: Option<Vec<u8>>,
    /// Path switch request ack
    pub path_switch_request_ack: Option<Vec<u8>>,
    /// Handover request
    pub handover_request: Option<Vec<u8>>,
    /// Handover command
    pub handover_command: Option<Vec<u8>>,
}

/// Resource status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceStatus {
    #[default]
    Null,
    Released,
    Unchanged,
}

/// AMF Session context
#[derive(Debug, Clone)]
pub struct AmfSess {
    /// Unique pool ID
    pub id: u64,
    /// PDU Session Identity
    pub psi: u8,
    /// Procedure Transaction Identity
    pub pti: u8,
    /// Request type
    pub request_type: u8,
    /// SM context resource URI
    pub sm_context_resource_uri: Option<String>,
    /// SM context ref
    pub sm_context_ref: Option<String>,
    /// PDU session release complete received flag
    pub pdu_session_release_complete_received: bool,
    /// PDU session resource release response received flag
    pub pdu_session_resource_release_response_received: bool,
    /// PDU session establishment accept
    pub pdu_session_establishment_accept: Option<Vec<u8>>,
    /// Resource status
    pub resource_status: ResourceStatus,
    /// N1 released flag
    pub n1_released: bool,
    /// N2 released flag
    pub n2_released: bool,
    /// Old GSM type
    pub old_gsm_type: u8,
    /// Current GSM type
    pub current_gsm_type: u8,
    /// N2 transfer buffers
    pub transfer: N2Transfer,
    /// Paging info
    pub paging: SessionPaging,
    /// GSM message
    pub gsm_message: GsmMessage,
    /// NSSF info
    pub nssf: NssfInfo,
    /// Payload container type
    pub payload_container_type: u8,
    /// Payload container
    pub payload_container: Option<Vec<u8>>,
    /// Associated AMF UE ID
    pub amf_ue_id: u64,
    /// Associated RAN UE ID
    pub ran_ue_id: u64,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// Mapped HPLMN
    pub mapped_hplmn: SNssai,
    /// Mapped HPLMN presence flag
    pub mapped_hplmn_presence: bool,
    /// DNN
    pub dnn: Option<String>,
    /// LBO roaming allowed flag
    pub lbo_roaming_allowed: bool,
    /// SM context in SMF flag (for gmm_build compatibility)
    pub sm_context_in_smf: bool,
}

impl AmfSess {
    /// Create a new AMF session
    pub fn new(id: u64, amf_ue_id: u64, psi: u8) -> Self {
        Self {
            id,
            psi,
            pti: 0,
            request_type: 0,
            sm_context_resource_uri: None,
            sm_context_ref: None,
            pdu_session_release_complete_received: false,
            pdu_session_resource_release_response_received: false,
            pdu_session_establishment_accept: None,
            resource_status: ResourceStatus::Null,
            n1_released: false,
            n2_released: false,
            old_gsm_type: 0,
            current_gsm_type: 0,
            transfer: N2Transfer::default(),
            paging: SessionPaging::default(),
            gsm_message: GsmMessage::default(),
            nssf: NssfInfo::default(),
            payload_container_type: 0,
            payload_container: None,
            amf_ue_id,
            ran_ue_id: NEXTGCORE_INVALID_POOL_ID,
            s_nssai: SNssai::default(),
            mapped_hplmn: SNssai::default(),
            mapped_hplmn_presence: false,
            dnn: None,
            lbo_roaming_allowed: false,
            sm_context_in_smf: false,
        }
    }

    /// Check if session context is in SMF
    pub fn session_context_in_smf(&self) -> bool {
        self.sm_context_ref.is_some()
    }

    /// Store session context
    pub fn store_session_context(&mut self, resource_uri: &str, context_ref: &str) {
        self.clear_session_context();
        self.sm_context_resource_uri = Some(resource_uri.to_string());
        self.sm_context_ref = Some(context_ref.to_string());
    }

    /// Clear session context
    pub fn clear_session_context(&mut self) {
        self.sm_context_ref = None;
        self.sm_context_resource_uri = None;
    }

    /// Store paging info
    pub fn store_paging_info(&mut self, location: &str, uri: Option<&str>) {
        self.clear_paging_info();
        self.paging.ongoing = true;
        self.paging.location = Some(location.to_string());
        if let Some(u) = uri {
            self.paging.n1n2_failure_txf_notif_uri = Some(u.to_string());
        }
    }

    /// Clear paging info
    pub fn clear_paging_info(&mut self) {
        if self.paging.ongoing {
            self.paging.location = None;
            self.paging.n1n2_failure_txf_notif_uri = None;
            self.paging.ongoing = false;
        }
    }

    /// Store 5GSM message
    pub fn store_5gsm_message(
        &mut self,
        msg_type: u8,
        n1buf: Option<Vec<u8>>,
        n2buf: Option<Vec<u8>>,
    ) {
        self.gsm_message.n1buf = n1buf;
        self.gsm_message.n2buf = n2buf;
        self.gsm_message.message_type = msg_type;
    }

    /// Clear 5GSM message
    pub fn clear_5gsm_message(&mut self) {
        self.gsm_message.n1buf = None;
        self.gsm_message.n2buf = None;
        self.gsm_message.message_type = 0;
    }

    /// Store N2 transfer
    pub fn store_n2_transfer_setup_request(&mut self, buf: Vec<u8>) {
        self.transfer.pdu_session_resource_setup_request = Some(buf);
    }

    /// Clear N2 transfer setup request
    pub fn clear_n2_transfer_setup_request(&mut self) {
        self.transfer.pdu_session_resource_setup_request = None;
    }
}

impl Default for AmfSess {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ============================================================================
// Global Context Singleton
// ============================================================================

/// Global AMF context (thread-safe singleton)
static GLOBAL_AMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<AmfContext>>> =
    std::sync::OnceLock::new();

/// Get the global AMF context
pub fn amf_self() -> Arc<RwLock<AmfContext>> {
    GLOBAL_AMF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(AmfContext::new())))
        .clone()
}

/// Initialize the global AMF context
pub fn amf_context_init(max_gnb: usize, max_ue: usize, max_sess: usize) {
    let ctx = amf_self();
    // Fast path: already initialized. Never queue a writer in that case —
    // the std queued RwLock gives writers priority, so a steady stream of
    // (no-op) writers blocks every new reader and can wedge concurrent
    // callers (observed as a deadlock under parallel tests).
    if ctx
        .read()
        .map(|context| context.is_initialized())
        .unwrap_or(false)
    {
        return;
    }
    if let Ok(mut context) = ctx.write() {
        context.init(max_gnb, max_ue, max_sess);
    };
}

/// Finalize the global AMF context
pub fn amf_context_final() {
    let ctx = amf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get UE load (for NF instance load reporting)
pub fn amf_instance_get_load() -> i32 {
    let ctx = amf_self();
    if let Ok(context) = ctx.read() {
        return context.get_ue_load();
    }
    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amf_context_new() {
        let ctx = AmfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.gnb_count(), 0);
        assert_eq!(ctx.amf_ue_count(), 0);
    }

    #[test]
    fn test_amf_context_init_fini() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);
        assert!(ctx.is_initialized());
        assert_eq!(ctx.max_num_of_gnb, 64);
        assert_eq!(ctx.max_num_of_ue, 1024);

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_gnb_add_remove() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        assert_eq!(gnb.addr, "192.168.0.1:38412");
        assert_eq!(ctx.gnb_count(), 1);

        let found = ctx.gnb_find_by_addr("192.168.0.1:38412");
        assert!(found.is_some());

        ctx.gnb_remove(gnb.id);
        assert_eq!(ctx.gnb_count(), 0);
    }

    #[test]
    fn test_gnb_set_gnb_id() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        ctx.gnb_set_gnb_id(gnb.id, 12345);

        let found = ctx.gnb_find_by_gnb_id(12345);
        assert!(found.is_some());
        assert_eq!(found.unwrap().gnb_id, 12345);
    }

    #[test]
    fn test_ran_ue_add_remove() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        let ran_ue = ctx.ran_ue_add(gnb.id, 1001).unwrap();
        assert_eq!(ran_ue.ran_ue_ngap_id, 1001);
        assert_eq!(ctx.ran_ue_count(), 1);

        let found = ctx.ran_ue_find_by_ran_ue_ngap_id(gnb.id, 1001);
        assert!(found.is_some());

        ctx.ran_ue_remove(ran_ue.id);
        assert_eq!(ctx.ran_ue_count(), 0);
    }

    #[test]
    fn test_amf_ue_add_remove() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        let ran_ue = ctx.ran_ue_add(gnb.id, 1001).unwrap();
        let amf_ue = ctx.amf_ue_add(ran_ue.id).unwrap();
        assert_eq!(ctx.amf_ue_count(), 1);

        ctx.amf_ue_set_suci(amf_ue.id, "suci-0-001-01-0000-0-0-0000000001");
        let found = ctx.amf_ue_find_by_suci("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        ctx.amf_ue_remove(amf_ue.id);
        assert_eq!(ctx.amf_ue_count(), 0);
    }

    #[test]
    fn test_sess_add_remove() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        let ran_ue = ctx.ran_ue_add(gnb.id, 1001).unwrap();
        let amf_ue = ctx.amf_ue_add(ran_ue.id).unwrap();
        let sess = ctx.sess_add(amf_ue.id, 1).unwrap();
        assert_eq!(sess.psi, 1);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_psi(amf_ue.id, 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_amf_ue_remove_cascades() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        let ran_ue = ctx.ran_ue_add(gnb.id, 1001).unwrap();
        let amf_ue = ctx.amf_ue_add(ran_ue.id).unwrap();
        ctx.sess_add(amf_ue.id, 1);
        ctx.sess_add(amf_ue.id, 2);

        assert_eq!(ctx.sess_count(), 2);

        // Removing AMF UE should cascade to sessions
        ctx.amf_ue_remove(amf_ue.id);
        assert_eq!(ctx.amf_ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_get_ue_load() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 100, 4096);

        assert_eq!(ctx.get_ue_load(), 0);

        let gnb = ctx.gnb_add("192.168.0.1:38412").unwrap();
        let ran_ue = ctx.ran_ue_add(gnb.id, 1001).unwrap();
        ctx.amf_ue_add(ran_ue.id);
        assert_eq!(ctx.get_ue_load(), 1);
    }

    #[test]
    fn test_plmn_id() {
        let plmn = PlmnId::new("001", "01");
        assert_eq!(plmn.mcc1, 0);
        assert_eq!(plmn.mcc2, 0);
        assert_eq!(plmn.mcc3, 1);
        assert_eq!(plmn.mnc1, 0);
        assert_eq!(plmn.mnc2, 1);
        assert_eq!(plmn.mnc3, 0xf);
    }

    #[test]
    fn test_amf_ue_security_context() {
        let mut amf_ue = AmfUe::new(1, 1);
        assert!(!amf_ue.security_context_is_valid());

        amf_ue.security_context_available = true;
        amf_ue.nas.ue_ksi = 0;
        assert!(amf_ue.security_context_is_valid());

        amf_ue.mac_failed = true;
        assert!(!amf_ue.security_context_is_valid());

        amf_ue.clear_security_context();
        assert!(!amf_ue.security_context_available);
        assert!(!amf_ue.mac_failed);
    }

    #[test]
    fn test_amf_sess_session_context() {
        let mut sess = AmfSess::new(1, 1, 1);
        assert!(!sess.session_context_in_smf());

        sess.store_session_context("http://smf/context/1", "ref-1");
        assert!(sess.session_context_in_smf());
        assert_eq!(sess.sm_context_ref, Some("ref-1".to_string()));

        sess.clear_session_context();
        assert!(!sess.session_context_in_smf());
    }

    #[test]
    fn test_paging_add_find_remove() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let paging = PagingContext {
            amf_ue_ngap_id: 42,
            tmsi: 0xDEADBEEF,
            amf_set_id: 1,
            amf_pointer: 0,
            plmn_id: PlmnId::new("001", "01"),
            tac: 7,
            ..Default::default()
        };

        assert!(ctx.paging_add(paging));
        assert_eq!(ctx.paging_count(), 1);

        let found = ctx.paging_find(42);
        assert!(found.is_some());
        assert_eq!(found.unwrap().tmsi, 0xDEADBEEF);

        let removed = ctx.paging_remove(42);
        assert!(removed.is_some());
        assert_eq!(ctx.paging_count(), 0);
    }

    #[test]
    fn test_positioning_dl_queue_add_drain() {
        let ctx = AmfContext::new();

        // Empty queue drains to nothing.
        assert!(ctx.positioning_dl_drain().is_empty());

        ctx.positioning_dl_add(PendingPositioningDl {
            amf_ue_ngap_id: 7,
            kind: PositioningDlKind::NrppaToGnb {
                routing_id: vec![0x00, 0x01],
                nrppa_pdu: vec![0xAA, 0xBB],
            },
        });
        ctx.positioning_dl_add(PendingPositioningDl {
            amf_ue_ngap_id: 9,
            kind: PositioningDlKind::LppToUe {
                lpp_pdu: vec![0x90, 0x01],
            },
        });

        // Drain returns all items in FIFO order and leaves the queue empty.
        let drained = ctx.positioning_dl_drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].amf_ue_ngap_id, 7);
        assert!(matches!(
            drained[0].kind,
            PositioningDlKind::NrppaToGnb { .. }
        ));
        assert_eq!(drained[1].amf_ue_ngap_id, 9);
        assert!(matches!(drained[1].kind, PositioningDlKind::LppToUe { .. }));
        assert!(ctx.positioning_dl_drain().is_empty());
    }

    #[test]
    fn test_paging_retransmit_limit() {
        let mut ctx = AmfContext::new();
        ctx.init(64, 1024, 4096);

        let paging = PagingContext {
            amf_ue_ngap_id: 10,
            tmsi: 0x1234,
            max_retransmit: 2,
            ..Default::default()
        };
        ctx.paging_add(paging);

        assert!(ctx.paging_retransmit(10)); // 1/2
        assert!(ctx.paging_retransmit(10)); // 2/2
        assert!(!ctx.paging_retransmit(10)); // exceeded
    }
}
