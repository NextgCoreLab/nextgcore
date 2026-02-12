//! SEPP Context Management
//!
//! Port of src/sepp/context.c - SEPP context with peer node and association management

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::handshake_sm::HandshakeState;

/// Maximum number of PLMN IDs per SEPP node
pub const MAX_NUM_OF_PLMN: usize = 16;

/// Security capability enumeration (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityCapability {
    #[default]
    Null,
    Tls,
    Prins,
    None,
}

impl SecurityCapability {
    pub fn to_string(&self) -> &'static str {
        match self {
            SecurityCapability::Null => "NULL",
            SecurityCapability::Tls => "TLS",
            SecurityCapability::Prins => "PRINS",
            SecurityCapability::None => "NONE",
        }
    }

    pub fn from_string(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TLS" => SecurityCapability::Tls,
            "PRINS" => SecurityCapability::Prins,
            "NONE" => SecurityCapability::None,
            _ => SecurityCapability::Null,
        }
    }
}

/// NF Type enumeration (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NfType {
    #[default]
    Null,
    Nrf,
    Udm,
    Amf,
    Smf,
    Ausf,
    Nef,
    Pcf,
    Smsf,
    Nssf,
    Udr,
    Sepp,
    Scp,
    Bsf,
}

impl NfType {
    pub fn to_string(&self) -> &'static str {
        match self {
            NfType::Null => "NULL",
            NfType::Nrf => "NRF",
            NfType::Udm => "UDM",
            NfType::Amf => "AMF",
            NfType::Smf => "SMF",
            NfType::Ausf => "AUSF",
            NfType::Nef => "NEF",
            NfType::Pcf => "PCF",
            NfType::Smsf => "SMSF",
            NfType::Nssf => "NSSF",
            NfType::Udr => "UDR",
            NfType::Sepp => "SEPP",
            NfType::Scp => "SCP",
            NfType::Bsf => "BSF",
        }
    }

    pub fn from_string(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "NRF" => NfType::Nrf,
            "UDM" => NfType::Udm,
            "AMF" => NfType::Amf,
            "SMF" => NfType::Smf,
            "AUSF" => NfType::Ausf,
            "NEF" => NfType::Nef,
            "PCF" => NfType::Pcf,
            "SMSF" => NfType::Smsf,
            "NSSF" => NfType::Nssf,
            "UDR" => NfType::Udr,
            "SEPP" => NfType::Sepp,
            "SCP" => NfType::Scp,
            "BSF" => NfType::Bsf,
            _ => NfType::Null,
        }
    }
}

/// SBI Service Type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SbiServiceType {
    #[default]
    Null,
    NnrfNfm,
    NnrfDisc,
    N32cHandshake,
}

impl SbiServiceType {
    pub fn from_name(name: &str) -> Self {
        match name {
            "nnrf-nfm" => SbiServiceType::NnrfNfm,
            "nnrf-disc" => SbiServiceType::NnrfDisc,
            "n32c-handshake" => SbiServiceType::N32cHandshake,
            _ => SbiServiceType::Null,
        }
    }

    pub fn to_name(&self) -> &'static str {
        match self {
            SbiServiceType::Null => "",
            SbiServiceType::NnrfNfm => "nnrf-nfm",
            SbiServiceType::NnrfDisc => "nnrf-disc",
            SbiServiceType::N32cHandshake => "n32c-handshake",
        }
    }
}

/// PLMN ID structure
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: u16,
    pub mnc: u16,
    pub mnc_len: u8,
}

impl PlmnId {
    pub fn new(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        Self { mcc, mnc, mnc_len }
    }

    pub fn build(mcc: i32, mnc: i32, mnc_len: usize) -> Self {
        Self {
            mcc: mcc as u16,
            mnc: mnc as u16,
            mnc_len: mnc_len as u8,
        }
    }

    pub fn mcc(&self) -> u16 {
        self.mcc
    }

    pub fn mnc(&self) -> u16 {
        self.mnc
    }
}

/// SEPP Node structure - represents a peer SEPP
/// Port of sepp_node_t from context.h
#[derive(Debug, Clone)]
pub struct SeppNode {
    /// Node ID (pool ID)
    pub id: u64,
    /// Receiver FQDN (peer SEPP identifier)
    pub receiver: String,
    /// Negotiated security scheme
    pub negotiated_security_scheme: SecurityCapability,
    /// Whether target API root is supported
    pub target_apiroot_supported: bool,
    /// PLMN IDs served by this peer SEPP
    pub plmn_ids: Vec<PlmnId>,
    /// Target PLMN ID (for outbound routing)
    pub target_plmn_id: Option<PlmnId>,
    /// Supported features bitmap
    pub supported_features: u64,
    /// Handshake state machine state
    pub handshake_state: HandshakeState,
    /// Timer for peer establishment retry
    pub establish_timer_active: bool,
    /// Client ID for N32c interface
    pub client_id: Option<u64>,
    /// Client ID for N32f interface
    pub n32f_client_id: Option<u64>,
}

impl SeppNode {
    pub fn new(id: u64, receiver: &str) -> Self {
        Self {
            id,
            receiver: receiver.to_string(),
            negotiated_security_scheme: SecurityCapability::Null,
            target_apiroot_supported: false,
            plmn_ids: Vec::new(),
            target_plmn_id: None,
            supported_features: 0,
            handshake_state: HandshakeState::Initial,
            establish_timer_active: false,
            client_id: None,
            n32f_client_id: None,
        }
    }

    pub fn add_plmn_id(&mut self, plmn_id: PlmnId) {
        if self.plmn_ids.len() < MAX_NUM_OF_PLMN {
            self.plmn_ids.push(plmn_id);
        }
    }

    pub fn set_target_plmn_id(&mut self, plmn_id: PlmnId) {
        self.target_plmn_id = Some(plmn_id);
    }

    pub fn has_plmn_id(&self, mcc: u16, mnc: u16) -> bool {
        self.plmn_ids.iter().any(|p| p.mcc == mcc && p.mnc == mnc)
    }
}

/// SEPP Association structure - tracks forwarded requests
/// Port of sepp_assoc_t from context.h
#[derive(Debug, Clone)]
pub struct SeppAssoc {
    /// Association pool ID
    pub id: u64,
    /// Stream ID for the associated HTTP/2 stream
    pub stream_id: u64,
    /// Client ID (for response routing)
    pub client_id: Option<u64>,
    /// Original request (stored for forwarding)
    pub request: Option<SbiRequest>,
    /// Service type
    pub service_type: SbiServiceType,
    /// Requester NF type
    pub requester_nf_type: NfType,
    /// NF service producer instance ID
    pub nf_service_producer_id: Option<String>,
}

/// Simplified SBI request for storage
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl SeppAssoc {
    pub fn new(id: u64, stream_id: u64) -> Self {
        Self {
            id,
            stream_id,
            client_id: None,
            request: None,
            service_type: SbiServiceType::Null,
            requester_nf_type: NfType::Null,
            nf_service_producer_id: None,
        }
    }
}

/// SEPP security capability configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityCapabilityConfig {
    pub tls: bool,
    pub prins: bool,
}

/// SEPP Context - main context structure for SEPP
/// Port of sepp_context_t from context.h
pub struct SeppContext {
    /// Sender FQDN (this SEPP's identifier)
    pub sender: Option<String>,
    /// Security capability configuration
    pub security_capability: SecurityCapabilityConfig,
    /// Whether target API root is supported
    pub target_apiroot_supported: bool,
    /// Peer SEPP node list (by ID)
    peer_list: RwLock<HashMap<u64, SeppNode>>,
    /// Association list (by ID)
    assoc_list: RwLock<HashMap<u64, SeppAssoc>>,
    /// Next node ID
    next_node_id: AtomicUsize,
    /// Next association ID
    next_assoc_id: AtomicUsize,
    /// Maximum number of nodes
    max_num_of_node: usize,
    /// Maximum number of associations
    max_num_of_assoc: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl SeppContext {
    pub fn new() -> Self {
        Self {
            sender: None,
            security_capability: SecurityCapabilityConfig {
                tls: true,
                prins: false,
            },
            target_apiroot_supported: true,
            peer_list: RwLock::new(HashMap::new()),
            assoc_list: RwLock::new(HashMap::new()),
            next_node_id: AtomicUsize::new(1),
            next_assoc_id: AtomicUsize::new(1),
            max_num_of_node: 0,
            max_num_of_assoc: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_node: usize, max_assoc: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_node = max_node;
        self.max_num_of_assoc = max_assoc;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("SEPP context initialized (max_node={max_node}, max_assoc={max_assoc})");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.node_remove_all();
        self.assoc_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SEPP context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn set_sender(&mut self, sender: &str) {
        self.sender = Some(sender.to_string());
    }

    // Node management functions

    /// Add a new SEPP peer node
    /// Port of sepp_node_add
    pub fn node_add(&self, receiver: &str) -> Option<SeppNode> {
        let mut peer_list = self.peer_list.write().ok()?;

        if peer_list.len() >= self.max_num_of_node {
            log::error!("Maximum number of nodes [{}] reached", self.max_num_of_node);
            return None;
        }

        let id = self.next_node_id.fetch_add(1, Ordering::SeqCst) as u64;
        let node = SeppNode::new(id, receiver);

        peer_list.insert(id, node.clone());
        log::debug!("SEPP node added (id={id}, receiver={receiver})");

        Some(node)
    }

    /// Remove a SEPP peer node
    /// Port of sepp_node_remove
    pub fn node_remove(&self, id: u64) -> Option<SeppNode> {
        let mut peer_list = self.peer_list.write().ok()?;

        if let Some(node) = peer_list.remove(&id) {
            log::debug!("SEPP node removed (id={}, receiver={})", id, node.receiver);
            return Some(node);
        }
        None
    }

    /// Remove all SEPP peer nodes
    /// Port of sepp_node_remove_all
    pub fn node_remove_all(&self) {
        if let Ok(mut peer_list) = self.peer_list.write() {
            peer_list.clear();
        }
    }

    /// Find node by receiver FQDN
    /// Port of sepp_node_find_by_receiver
    pub fn node_find_by_receiver(&self, receiver: &str) -> Option<SeppNode> {
        let peer_list = self.peer_list.read().ok()?;
        for node in peer_list.values() {
            if node.receiver == receiver {
                return Some(node.clone());
            }
        }
        None
    }

    /// Find node by PLMN ID
    /// Port of sepp_node_find_by_plmn_id
    pub fn node_find_by_plmn_id(&self, mcc: u16, mnc: u16) -> Option<SeppNode> {
        let peer_list = self.peer_list.read().ok()?;
        for node in peer_list.values() {
            if node.has_plmn_id(mcc, mnc) {
                return Some(node.clone());
            }
        }
        None
    }

    /// Find node by ID
    pub fn node_find(&self, id: u64) -> Option<SeppNode> {
        let peer_list = self.peer_list.read().ok()?;
        peer_list.get(&id).cloned()
    }

    /// Update node in the context
    pub fn node_update(&self, node: &SeppNode) -> bool {
        if let Ok(mut peer_list) = self.peer_list.write() {
            if let Some(existing) = peer_list.get_mut(&node.id) {
                *existing = node.clone();
                return true;
            }
        }
        false
    }

    /// Get all nodes
    pub fn node_list(&self) -> Vec<SeppNode> {
        self.peer_list.read().map(|l| l.values().cloned().collect()).unwrap_or_default()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.peer_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // Association management functions

    /// Add a new association
    /// Port of sepp_assoc_add
    pub fn assoc_add(&self, stream_id: u64) -> Option<SeppAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;

        if assoc_list.len() >= self.max_num_of_assoc {
            log::error!("Maximum number of associations [{}] reached", self.max_num_of_assoc);
            return None;
        }

        let id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst) as u64;
        let assoc = SeppAssoc::new(id, stream_id);

        assoc_list.insert(id, assoc.clone());
        log::debug!("SEPP association added (id={id}, stream_id={stream_id})");

        Some(assoc)
    }

    /// Remove an association
    /// Port of sepp_assoc_remove
    pub fn assoc_remove(&self, id: u64) -> Option<SeppAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;

        if let Some(assoc) = assoc_list.remove(&id) {
            log::debug!("SEPP association removed (id={id})");
            return Some(assoc);
        }
        None
    }

    /// Remove all associations
    /// Port of sepp_assoc_remove_all
    pub fn assoc_remove_all(&self) {
        if let Ok(mut assoc_list) = self.assoc_list.write() {
            assoc_list.clear();
        }
    }

    /// Find association by ID
    pub fn assoc_find(&self, id: u64) -> Option<SeppAssoc> {
        let assoc_list = self.assoc_list.read().ok()?;
        assoc_list.get(&id).cloned()
    }

    /// Find association by stream ID
    pub fn assoc_find_by_stream_id(&self, stream_id: u64) -> Option<SeppAssoc> {
        let assoc_list = self.assoc_list.read().ok()?;
        for assoc in assoc_list.values() {
            if assoc.stream_id == stream_id {
                return Some(assoc.clone());
            }
        }
        None
    }

    /// Update association in the context
    pub fn assoc_update(&self, assoc: &SeppAssoc) -> bool {
        if let Ok(mut assoc_list) = self.assoc_list.write() {
            if let Some(existing) = assoc_list.get_mut(&assoc.id) {
                *existing = assoc.clone();
                return true;
            }
        }
        false
    }

    /// Get association count
    pub fn assoc_count(&self) -> usize {
        self.assoc_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for SeppContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global SEPP context (thread-safe singleton)
static GLOBAL_SEPP_CONTEXT: std::sync::OnceLock<Arc<RwLock<SeppContext>>> = std::sync::OnceLock::new();

/// Get the global SEPP context
pub fn sepp_self() -> Arc<RwLock<SeppContext>> {
    GLOBAL_SEPP_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(SeppContext::new())))
        .clone()
}

/// Initialize the global SEPP context
pub fn sepp_context_init(max_node: usize, max_assoc: usize) {
    let ctx = sepp_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_node, max_assoc);
    };
}

/// Finalize the global SEPP context
pub fn sepp_context_final() {
    let ctx = sepp_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}
