//! AUSF Context Management
//!
//! Port of src/ausf/context.c - AUSF context with UE list and hash tables

use nextgcore_crypt::kdf::{nextgcore_kdf_hxres_star, nextgcore_kdf_kseaf};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Authentication type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthType {
    /// 5G AKA authentication
    #[default]
    FiveGAka,
    /// EAP-AKA' authentication
    EapAkaPrime,
    /// EAP-TLS authentication
    EapTls,
}

/// Authentication result (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthResult {
    /// Authentication success
    AuthenticationSuccess,
    /// Authentication failure
    AuthenticationFailure,
    /// Authentication ongoing
    #[default]
    AuthenticationOngoing,
}

/// Authentication event data
#[derive(Debug, Clone, Default)]
pub struct AuthEvent {
    /// Resource URI for auth event
    pub resource_uri: Option<String>,
    /// Client for auth event
    pub client_id: Option<u64>,
}

impl AuthEvent {
    /// Create a new auth event
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the auth event
    pub fn clear(&mut self) {
        self.resource_uri = None;
    }

    /// Store a resource URI
    pub fn store(&mut self, resource_uri: &str) {
        self.resource_uri = Some(resource_uri.to_string());
    }
}

/// AUSF UE context
#[derive(Debug, Clone)]
pub struct AusfUe {
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
    /// Authentication type
    pub auth_type: AuthType,
    /// Authentication event
    pub auth_event: AuthEvent,
    /// Authentication result
    pub auth_result: AuthResult,
    /// RAND value (16 bytes)
    pub rand: [u8; 16],
    /// XRES* value (16 bytes)
    pub xres_star: [u8; 16],
    /// HXRES* value (16 bytes)
    pub hxres_star: [u8; 16],
    /// KAUSF value (32 bytes)
    pub kausf: [u8; 32],
    /// KSEAF value (32 bytes)
    pub kseaf: [u8; 32],
    /// AUTN value (16 bytes)
    pub autn: [u8; 16],
    /// RES* hex string from confirmation data
    pub res_star_hex: Option<String>,
    /// EAP-AKA' session state (TS 33.501 §6.1.3.1); None for 5G-AKA
    pub eap_session: Option<crate::eap_aka_prime::EapAkaSession>,
    /// Associated stream ID
    pub stream_id: Option<u64>,
    /// SNPN NID (Network Identifier) - Rel-17
    pub snpn_nid: Option<String>,
}

impl AusfUe {
    /// Create a new AUSF UE
    pub fn new(id: u64, suci: &str) -> Self {
        Self {
            id,
            ctx_id: id.to_string(),
            suci: suci.to_string(),
            supi: None,
            serving_network_name: None,
            auth_type: AuthType::default(),
            auth_event: AuthEvent::new(),
            auth_result: AuthResult::default(),
            rand: [0u8; 16],
            xres_star: [0u8; 16],
            hxres_star: [0u8; 16],
            kausf: [0u8; 32],
            kseaf: [0u8; 32],
            autn: [0u8; 16],
            res_star_hex: None,
            eap_session: None,
            stream_id: None,
            snpn_nid: None,
        }
    }

    /// Clear auth event
    pub fn auth_event_clear(&mut self) {
        self.auth_event.clear();
    }

    /// Store auth event resource URI
    pub fn auth_event_store(&mut self, resource_uri: &str) {
        self.auth_event.store(resource_uri);
    }

    /// Calculate HXRES* from RAND and XRES*
    pub fn calculate_hxres_star(&mut self) {
        self.hxres_star = nextgcore_kdf_hxres_star(&self.rand, &self.xres_star);
    }

    /// Calculate KSEAF from serving network name and KAUSF
    pub fn calculate_kseaf(&mut self) {
        if let Some(ref serving_network_name) = self.serving_network_name {
            self.kseaf = nextgcore_kdf_kseaf(serving_network_name, &self.kausf);
        }
    }

    /// Zeroize all sensitive key material held in this UE context (ausfd-08).
    ///
    /// TS 33.501 §6.1.4.1a: when the authentication context is deleted the AUSF
    /// does not retain the per-auth-flow keys (KAUSF/KSEAF) or the expected
    /// response (XRES*/HXRES*) in *this* context. Invoked when the UE context
    /// is removed on `DELETE .../ue-authentications/{authCtxId}`.
    ///
    /// Reconciliation with TS 33.501 §6.14.1: an AUSF supporting the control
    /// plane solution for Steering of Roaming "shall store the latest K_AUSF
    /// after the completion of the latest primary authentication" (likewise
    /// §6.15 for UPU). That retained copy lives in the separate per-SUPI
    /// SoR/UPU anchor store ([`AusfContext`] `anchor_*` methods) together with
    /// Counter_SoR/Counter_UPU, and is deliberately NOT touched by this
    /// zeroize — the §6.1.4.1a teardown is scoped to the authentication
    /// context, not to the SoR/UPU anchor.
    pub fn zeroize(&mut self) {
        self.kausf = [0u8; 32];
        self.kseaf = [0u8; 32];
        self.xres_star = [0u8; 16];
        self.hxres_star = [0u8; 16];
        self.rand = [0u8; 16];
        self.autn = [0u8; 16];
        self.res_star_hex = None;
        if let Some(session) = self.eap_session.as_mut() {
            session.kausf = [0u8; 32];
            session.k_aut = [0u8; 32];
            session.ck_prime = [0u8; 16];
            session.ik_prime = [0u8; 16];
        }
        self.eap_session = None;
    }

    // ========================================================================
    // SNPN Authentication Support (Rel-17 TS 33.501)
    // ========================================================================

    /// Accept NID (Network Identifier) in SNPN authentication request
    pub fn set_snpn_nid(&mut self, nid: &str) {
        self.snpn_nid = Some(nid.to_string());
        log::info!("[AUSF SNPN] NID set for UE context: nid={nid}");
    }

    /// Use NID for KAUSF key derivation (TS 33.501 Annex A.2)
    /// In SNPN, KAUSF derivation includes NID as input parameter
    pub fn derive_kausf_with_nid(&mut self, _ck: &[u8; 16], _ik: &[u8; 16]) {
        // Standard KAUSF derivation: KAUSF = KDF(CK, IK, serving_network_name, SQN ⊕ AK)
        // SNPN enhancement: serving_network_name includes NID
        if let Some(ref nid) = self.snpn_nid {
            let serving_network_with_nid = format!(
                "5G:{}:NID-{}",
                self.serving_network_name.as_deref().unwrap_or(""),
                nid
            );
            log::debug!(
                "[AUSF SNPN] KAUSF derivation with NID: serving_network={serving_network_with_nid}"
            );
            // In production, this would use nextgcore_kdf_kausf with NID-augmented serving network name
            // For now, we log the intent
        }
    }

    /// Support Default Credential Server (DCS) for SNPN onboarding
    /// DCS provisions initial credentials for new SNPN UEs (TS 23.501 5.30.14)
    pub fn request_dcs_credentials(&self) -> bool {
        if let Some(ref nid) = self.snpn_nid {
            log::info!(
                "[AUSF SNPN] Requesting DCS credentials for onboarding: nid={} suci={}",
                nid,
                self.suci
            );
            // In production, this would send Nudm_SDM_Get to DCS
            return true;
        }
        false
    }
}

/// Error returned by the SoR/UPU anchor-store counter allocators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorCounterError {
    /// No SoR/UPU anchor exists for this SUPI (no completed primary
    /// authentication since process start) — fail closed, never MAC with a
    /// zero key.
    NoAnchor,
    /// The counter is about to wrap around (0xFFFF): TS 33.501 §6.14.2.3 /
    /// §6.15.2.2 — the AUSF shall suspend the protection service for the UE
    /// until a fresh KAUSF is generated. The counter is NOT consumed.
    CounterWrap,
}

impl std::fmt::Display for AnchorCounterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAnchor => write!(f, "no SoR/UPU anchor (no completed primary authentication)"),
            Self::CounterWrap => write!(
                f,
                "counter about to wrap (0xFFFF): protection service suspended until fresh KAUSF"
            ),
        }
    }
}

impl std::error::Error for AnchorCounterError {}

/// Per-SUPI SoR/UPU anchor (TS 33.501 §6.14.1, §6.14.2.3, §6.15.2.2).
///
/// Holds the latest KAUSF after the completion of the latest primary
/// authentication, plus the 16-bit Counter_SoR / Counter_UPU associated with
/// that key. Lifetime: in-memory for the process lifetime, which is
/// spec-consistent — the counters live for the lifetime of the KAUSF and an
/// AUSF restart forces re-authentication (a fresh KAUSF resets them anyway).
///
/// Counter invariants enforced here:
/// - initialised to 0x0001 when a newly derived KAUSF is stored;
/// - the value returned for a MAC computation is the CURRENT counter, which is
///   then incremented (first MAC uses 0x0001, stored counter becomes 0x0002);
/// - 0x0000 is never handed out;
/// - at 0xFFFF the allocator refuses with [`AnchorCounterError::CounterWrap`]
///   (service suspended) and the counter is not consumed;
/// - counters reset only when a genuinely NEW KAUSF is stored (a retransmitted
///   confirmation carrying the same KAUSF must not reset them).
pub struct SorUpuAnchor {
    /// Latest KAUSF (TS 33.501 §6.14.1); zeroized on drop.
    kausf: [u8; 32],
    /// Counter_SoR (TS 33.501 §6.14.2.3).
    counter_sor: u16,
    /// Counter_UPU (TS 33.501 §6.15.2.2).
    counter_upu: u16,
    /// When the anchor was last stored/refreshed.
    updated_at: std::time::SystemTime,
}

impl SorUpuAnchor {
    /// Store a newly derived KAUSF: counters initialised to 0x0001
    /// (TS 33.501 §6.14.2.3 / §6.15.2.2).
    pub fn new(kausf: [u8; 32]) -> Self {
        Self {
            kausf,
            counter_sor: 0x0001,
            counter_upu: 0x0001,
            updated_at: std::time::SystemTime::now(),
        }
    }

    /// Refresh with the KAUSF from the latest completed primary
    /// authentication. Counters reset to 0x0001 ONLY when the KAUSF is
    /// genuinely new; a retransmitted confirmation carrying the same KAUSF
    /// leaves the counters untouched (UE-side monotonicity, §6.14.2.3).
    pub fn refresh(&mut self, kausf: [u8; 32]) {
        if self.kausf != kausf {
            self.kausf = kausf;
            self.counter_sor = 0x0001;
            self.counter_upu = 0x0001;
        }
        self.updated_at = std::time::SystemTime::now();
    }

    /// The stored latest KAUSF.
    pub fn kausf(&self) -> &[u8; 32] {
        &self.kausf
    }

    /// When the anchor was last stored/refreshed.
    pub fn updated_at(&self) -> std::time::SystemTime {
        self.updated_at
    }

    /// Allocate the Counter_SoR value to use for ONE SoR-MAC-I_AUSF
    /// computation: returns the current counter and increments the stored
    /// value (first MAC uses 0x0001, stored counter becomes 0x0002 —
    /// TS 33.501 §6.14.2.3). Refuses with [`AnchorCounterError::CounterWrap`]
    /// at 0xFFFF (suspension until fresh KAUSF); the counter is not consumed.
    pub fn next_sor_counter(&mut self) -> Result<u16, AnchorCounterError> {
        Self::next_counter(&mut self.counter_sor)
    }

    /// Allocate the Counter_UPU value for ONE UPU-MAC-I_AUSF computation
    /// (TS 33.501 §6.15.2.2); same rules as [`Self::next_sor_counter`].
    pub fn next_upu_counter(&mut self) -> Result<u16, AnchorCounterError> {
        Self::next_counter(&mut self.counter_upu)
    }

    fn next_counter(counter: &mut u16) -> Result<u16, AnchorCounterError> {
        // 0x0000 shall never be used to calculate a MAC (§6.14.2.3/§6.15.2.2);
        // with init at 0x0001 and wrap refusal below it can never be reached.
        debug_assert!(*counter != 0, "SoR/UPU counter must never be 0x0000");
        if *counter == 0xFFFF {
            // About to wrap: suspend the protection service (§6.14.2.3
            // "The AUSF shall suspend the SoR protection service for the UE,
            // if the Counter_SoR ... is about to wrap around").
            return Err(AnchorCounterError::CounterWrap);
        }
        let value = *counter;
        *counter += 1;
        Ok(value)
    }

    /// Zeroize the stored KAUSF.
    fn zeroize(&mut self) {
        self.kausf = [0u8; 32];
    }
}

impl Drop for SorUpuAnchor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// AUSF Context - main context structure for AUSF
pub struct AusfContext {
    /// UE list (by pool ID)
    ue_list: RwLock<HashMap<u64, AusfUe>>,
    /// SUCI hash (SUCI -> pool ID)
    suci_hash: RwLock<HashMap<String, u64>>,
    /// SUPI hash (SUPI -> pool ID)
    supi_hash: RwLock<HashMap<String, u64>>,
    /// Per-SUPI SoR/UPU anchor store (TS 33.501 §6.14.1): latest KAUSF +
    /// Counter_SoR/Counter_UPU. Separate from `ue_list` on purpose — it
    /// SURVIVES `DELETE .../ue-authentications/{authCtxId}` (§6.1.4.1a tears
    /// down the auth context only, while §6.14.1 requires the latest KAUSF to
    /// be retained for SoR/UPU protection).
    ///
    /// LOCK ORDER: leaf-level. This lock is only ever taken alone — never
    /// while holding `ue_list`/`suci_hash`/`supi_hash` guards and never
    /// calling back into methods that take them (nf-context-lock-deadlocks).
    anchor_store: RwLock<HashMap<String, SorUpuAnchor>>,
    /// Next UE ID
    next_ue_id: AtomicUsize,
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl AusfContext {
    /// Create a new AUSF context
    pub fn new() -> Self {
        Self {
            ue_list: RwLock::new(HashMap::new()),
            suci_hash: RwLock::new(HashMap::new()),
            supi_hash: RwLock::new(HashMap::new()),
            anchor_store: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the AUSF context
    pub fn init(&mut self, max_ue: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_ue = max_ue;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "AUSF context initialized with max {} UEs",
            self.max_num_of_ue
        );
    }

    /// Finalize the AUSF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Remove all UEs
        self.ue_remove_all();

        // Drop all SoR/UPU anchors (KAUSF zeroized by SorUpuAnchor::drop).
        self.anchor_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("AUSF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add a new UE by SUCI
    pub fn ue_add(&self, suci: &str) -> Option<AusfUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;

        if ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue = AusfUe::new(id, suci);

        suci_hash.insert(suci.to_string(), id);
        ue_list.insert(id, ue.clone());

        log::debug!("[{suci}] AUSF UE added (id={id})");
        Some(ue)
    }

    /// Remove a UE by ID
    pub fn ue_remove(&self, id: u64) -> Option<AusfUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;

        if let Some(ue) = ue_list.remove(&id) {
            suci_hash.remove(&ue.suci);
            if let Some(ref supi) = ue.supi {
                supi_hash.remove(supi);
            }
            log::debug!("[{}] AUSF UE removed (id={})", ue.suci, id);
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
    }

    /// Find UE by SUCI
    pub fn ue_find_by_suci(&self, suci: &str) -> Option<AusfUe> {
        // Lock order ue_list < suci_hash (matches ue_add/ue_remove). Acquiring
        // suci_hash before ue_list would be an AB-BA deadlock vs ue_add (which
        // holds ue_list while taking suci_hash).
        let ue_list = self.ue_list.read().ok()?;
        let suci_hash = self.suci_hash.read().ok()?;

        if let Some(&id) = suci_hash.get(suci) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by SUPI
    pub fn ue_find_by_supi(&self, supi: &str) -> Option<AusfUe> {
        // Lock order ue_list < supi_hash (matches ue_remove / the SUPI setters).
        let ue_list = self.ue_list.read().ok()?;
        let supi_hash = self.supi_hash.read().ok()?;

        if let Some(&id) = supi_hash.get(supi) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by SUCI or SUPI
    pub fn ue_find_by_suci_or_supi(&self, suci_or_supi: &str) -> Option<AusfUe> {
        if suci_or_supi.starts_with("suci-") {
            self.ue_find_by_suci(suci_or_supi)
        } else {
            self.ue_find_by_supi(suci_or_supi)
        }
    }

    /// Find UE by context ID
    pub fn ue_find_by_ctx_id(&self, ctx_id: &str) -> Option<AusfUe> {
        let id: u64 = ctx_id.parse().ok()?;
        self.ue_find_by_id(id)
    }

    /// Find UE by pool ID
    pub fn ue_find_by_id(&self, id: u64) -> Option<AusfUe> {
        let ue_list = self.ue_list.read().ok()?;
        ue_list.get(&id).cloned()
    }

    /// Update UE in the context
    pub fn ue_update(&self, ue: &AusfUe) -> bool {
        let mut ue_list = self.ue_list.write().unwrap();
        let mut supi_hash = self.supi_hash.write().unwrap();

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
        let mut ue_list = self.ue_list.write().unwrap();
        let mut supi_hash = self.supi_hash.write().unwrap();

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

    // ========================================================================
    // SoR/UPU anchor store (TS 33.501 §6.14.1, §6.14.2.3, §6.15.2.2)
    //
    // All methods below take ONLY the leaf-level `anchor_store` lock; they
    // never touch `ue_list`/`suci_hash`/`supi_hash` (nf-context-lock-deadlocks
    // discipline). `anchor_next_*_counter` is the ONLY way to obtain a counter
    // value for a MAC computation — there is no raw counter read.
    // ========================================================================

    /// Store/refresh the SoR/UPU anchor for `supi` with the KAUSF from the
    /// latest completed primary authentication (TS 33.501 §6.14.1 "the AUSF
    /// shall store the latest K_AUSF after the completion of the latest
    /// primary authentication"). Counters reset to 0x0001 only when the KAUSF
    /// is genuinely new (see [`SorUpuAnchor::refresh`]).
    pub fn anchor_refresh(&self, supi: &str, kausf: &[u8; 32]) {
        let Ok(mut store) = self.anchor_store.write() else {
            log::error!("[{supi}] anchor_refresh: anchor store lock poisoned");
            return;
        };
        match store.get_mut(supi) {
            Some(anchor) => anchor.refresh(*kausf),
            None => {
                store.insert(supi.to_string(), SorUpuAnchor::new(*kausf));
            }
        }
        log::debug!("[{supi}] SoR/UPU anchor stored/refreshed (latest KAUSF)");
    }

    /// Latest KAUSF for `supi`, if a primary authentication has completed.
    pub fn anchor_lookup_kausf(&self, supi: &str) -> Option<[u8; 32]> {
        let store = self.anchor_store.read().ok()?;
        store.get(supi).map(|anchor| *anchor.kausf())
    }

    /// Allocate the Counter_SoR value for ONE SoR-MAC-I_AUSF computation
    /// (returns the current value, then increments — TS 33.501 §6.14.2.3).
    ///
    /// Errors: [`AnchorCounterError::NoAnchor`] when no primary authentication
    /// has completed for `supi`; [`AnchorCounterError::CounterWrap`] when the
    /// counter is about to wrap (service suspended, counter NOT consumed).
    pub fn anchor_next_sor_counter(&self, supi: &str) -> Result<u16, AnchorCounterError> {
        let mut store = self
            .anchor_store
            .write()
            .map_err(|_| AnchorCounterError::NoAnchor)?;
        store
            .get_mut(supi)
            .ok_or(AnchorCounterError::NoAnchor)?
            .next_sor_counter()
    }

    /// Allocate the Counter_UPU value for ONE UPU-MAC-I_AUSF computation
    /// (TS 33.501 §6.15.2.2); same rules as [`Self::anchor_next_sor_counter`].
    pub fn anchor_next_upu_counter(&self, supi: &str) -> Result<u16, AnchorCounterError> {
        let mut store = self
            .anchor_store
            .write()
            .map_err(|_| AnchorCounterError::NoAnchor)?;
        store
            .get_mut(supi)
            .ok_or(AnchorCounterError::NoAnchor)?
            .next_upu_counter()
    }

    /// Remove the anchor for `supi` (future purge policy hook; NOT called on
    /// auth-context deletion). The KAUSF is zeroized on drop. Returns whether
    /// an anchor existed. Config-driven retention is out of scope: in-memory
    /// lifetime = process lifetime, which is spec-consistent (§6.14.2.3 —
    /// counters live for the KAUSF lifetime; a restart forces re-auth).
    pub fn anchor_remove(&self, supi: &str) -> bool {
        match self.anchor_store.write() {
            Ok(mut store) => store.remove(supi).is_some(),
            Err(_) => false,
        }
    }

    /// Drop all anchors (process shutdown; KAUSFs zeroized on drop).
    pub fn anchor_remove_all(&self) {
        if let Ok(mut store) = self.anchor_store.write() {
            store.clear();
        }
    }

    /// Number of stored anchors.
    pub fn anchor_count(&self) -> usize {
        self.anchor_store.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Overwrite the stored counters for `supi` (returns false if no anchor).
    ///
    /// Validation/ops support ONLY — used by tests (and the F-07 strict-peer
    /// suite) to force the wrap-suspension state (e.g. counter = 0xFFFF). It
    /// writes counters; it can never be used to READ a counter for a MAC —
    /// [`Self::anchor_next_sor_counter`]/[`Self::anchor_next_upu_counter`]
    /// remain the only read path. 0x0000 is rejected (§6.14.2.3/§6.15.2.2).
    pub fn anchor_force_counters(&self, supi: &str, counter_sor: u16, counter_upu: u16) -> bool {
        if counter_sor == 0 || counter_upu == 0 {
            log::error!("[{supi}] anchor_force_counters: 0x0000 is forbidden");
            return false;
        }
        match self.anchor_store.write() {
            Ok(mut store) => match store.get_mut(supi) {
                Some(anchor) => {
                    anchor.counter_sor = counter_sor;
                    anchor.counter_upu = counter_upu;
                    true
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Get UE load percentage
    pub fn get_ue_load(&self) -> i32 {
        let ue_list = self.ue_list.read().unwrap();
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
}

impl Default for AusfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global AUSF context (thread-safe singleton)
static GLOBAL_AUSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<AusfContext>>> =
    std::sync::OnceLock::new();

/// Get the global AUSF context
pub fn ausf_self() -> Arc<RwLock<AusfContext>> {
    GLOBAL_AUSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(AusfContext::new())))
        .clone()
}

/// Initialize the global AUSF context
pub fn ausf_context_init(max_ue: usize) {
    let ctx = ausf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue);
    };
}

/// Finalize the global AUSF context
pub fn ausf_context_final() {
    let ctx = ausf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ausf_context_new() {
        let ctx = AusfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ausf_context_init_fini() {
        let mut ctx = AusfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        assert_eq!(ctx.max_num_of_ue, 100);

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_add_remove() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        assert_eq!(ue.suci, "suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.ue_count(), 1);

        let found = ctx.ue_find_by_suci("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ue_find_by_suci_or_supi() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        ctx.ue_set_supi(ue.id, "imsi-001010000000001");

        // Find by SUCI
        let found = ctx.ue_find_by_suci_or_supi("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        // Find by SUPI
        let found = ctx.ue_find_by_suci_or_supi("imsi-001010000000001");
        assert!(found.is_some());
    }

    #[test]
    fn test_ue_find_by_ctx_id() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        let found = ctx.ue_find_by_ctx_id(&ue.ctx_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().suci, ue.suci);
    }

    #[test]
    fn test_get_ue_load() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        assert_eq!(ctx.get_ue_load(), 0);

        ctx.ue_add("suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.get_ue_load(), 1);

        for i in 2..=50 {
            ctx.ue_add(&format!("suci-0-001-01-0000-0-0-{i:010}"));
        }
        assert_eq!(ctx.get_ue_load(), 50);
    }

    #[test]
    fn test_ausf_ue_zeroize() {
        // ausfd-08: zeroize() must clear all sensitive key material.
        let mut ue = AusfUe::new(1, "suci-test");
        ue.kausf = [0x11u8; 32];
        ue.kseaf = [0x22u8; 32];
        ue.xres_star = [0x33u8; 16];
        ue.hxres_star = [0x44u8; 16];
        ue.rand = [0x55u8; 16];
        ue.autn = [0x66u8; 16];
        ue.res_star_hex = Some("deadbeef".to_string());
        ue.eap_session = Some(crate::eap_aka_prime::EapAkaSession::new(
            "5G:mnc001.mcc001.3gppnetwork.org",
        ));

        ue.zeroize();

        assert_eq!(ue.kausf, [0u8; 32], "kausf must be zeroized");
        assert_eq!(ue.kseaf, [0u8; 32], "kseaf must be zeroized");
        assert_eq!(ue.xres_star, [0u8; 16], "xres_star must be zeroized");
        assert_eq!(ue.hxres_star, [0u8; 16], "hxres_star must be zeroized");
        assert_eq!(ue.rand, [0u8; 16], "rand must be zeroized");
        assert_eq!(ue.autn, [0u8; 16], "autn must be zeroized");
        assert!(ue.res_star_hex.is_none(), "res_star_hex must be cleared");
        assert!(ue.eap_session.is_none(), "eap_session must be cleared");
    }

    // ========================================================================
    // F-02: SoR/UPU anchor store (TS 33.501 §6.14.1, §6.14.2.3, §6.15.2.2)
    // ========================================================================

    /// §6.14.1: the anchor (latest KAUSF) survives removal of the
    /// authentication context — auth → remove UE ctx → anchor still there.
    #[test]
    fn test_anchor_survives_ue_removal() {
        let mut ctx = AusfContext::new();
        ctx.init(16);

        let supi = "imsi-001010000000042";
        let kausf = [0x5au8; 32];

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000042").unwrap();
        ctx.ue_set_supi(ue.id, supi);
        ctx.anchor_refresh(supi, &kausf);

        // Auth-context teardown (§6.1.4.1a) — the UE context goes away...
        ctx.ue_remove(ue.id);
        assert!(ctx.ue_find_by_supi(supi).is_none(), "UE ctx must be gone");

        // ...but the SoR/UPU anchor is retained (§6.14.1).
        assert_eq!(
            ctx.anchor_lookup_kausf(supi),
            Some(kausf),
            "anchor must survive auth-context removal"
        );
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));
    }

    /// §6.14.2.3/§6.15.2.2: counters start at 0x0001, hand out
    /// 0x0001, 0x0002, 0x0003…, refuse at 0xFFFF without consuming, and reset
    /// to 0x0001 on a fresh KAUSF (service resumes).
    #[test]
    fn test_anchor_counter_sequence_wrap_and_refresh() {
        let mut ctx = AusfContext::new();
        ctx.init(16);
        let supi = "imsi-001010000000043";

        // No anchor yet → NoAnchor (fail-closed).
        assert_eq!(
            ctx.anchor_next_sor_counter(supi),
            Err(AnchorCounterError::NoAnchor)
        );

        ctx.anchor_refresh(supi, &[0x01u8; 32]);

        // First MAC uses 0x0001, then 0x0002, 0x0003 (monotonic, never 0x0000).
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0002));
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0003));

        // UPU counter is independent of the SoR counter.
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0x0001));
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0x0002));

        // Force the about-to-wrap state: 0xFFFE is still usable...
        assert!(ctx.anchor_force_counters(supi, 0xFFFE, 0xFFFE));
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0xFFFE));
        // ...0xFFFF refuses (suspension) and is NOT consumed: repeated calls
        // keep failing identically instead of wrapping through 0x0000.
        assert_eq!(
            ctx.anchor_next_sor_counter(supi),
            Err(AnchorCounterError::CounterWrap)
        );
        assert_eq!(
            ctx.anchor_next_sor_counter(supi),
            Err(AnchorCounterError::CounterWrap)
        );
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0xFFFE));
        assert_eq!(
            ctx.anchor_next_upu_counter(supi),
            Err(AnchorCounterError::CounterWrap)
        );

        // Fresh KAUSF → counters reset to 0x0001, service resumes.
        ctx.anchor_refresh(supi, &[0x02u8; 32]);
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0x0001));

        // 0x0000 can never be forced in.
        assert!(!ctx.anchor_force_counters(supi, 0x0000, 0x0001));
    }

    /// Two successive successful primary authentications: the latest KAUSF
    /// wins and BOTH counters reset to 0x0001.
    #[test]
    fn test_anchor_latest_kausf_wins_and_resets_counters() {
        let mut ctx = AusfContext::new();
        ctx.init(16);
        let supi = "imsi-001010000000044";

        let kausf_a = [0xaau8; 32];
        let kausf_b = [0xbbu8; 32];

        ctx.anchor_refresh(supi, &kausf_a);
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0002));
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0x0001));

        // Second successful primary auth with a NEW KAUSF.
        ctx.anchor_refresh(supi, &kausf_b);
        assert_eq!(ctx.anchor_lookup_kausf(supi), Some(kausf_b), "latest wins");
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));
        assert_eq!(ctx.anchor_next_upu_counter(supi), Ok(0x0001));
    }

    /// Retransmit guard (§6.14.2.3 risk note): re-storing the SAME KAUSF
    /// (e.g. a retransmitted confirmation) must NOT reset the counters —
    /// that would break UE-side monotonicity.
    #[test]
    fn test_anchor_same_kausf_retransmit_does_not_reset() {
        let mut ctx = AusfContext::new();
        ctx.init(16);
        let supi = "imsi-001010000000045";
        let kausf = [0xccu8; 32];

        ctx.anchor_refresh(supi, &kausf);
        assert_eq!(ctx.anchor_next_sor_counter(supi), Ok(0x0001));

        // Same KAUSF again (retransmitted confirm) — counters keep advancing.
        ctx.anchor_refresh(supi, &kausf);
        assert_eq!(
            ctx.anchor_next_sor_counter(supi),
            Ok(0x0002),
            "same-KAUSF refresh must not reset Counter_SoR"
        );
    }

    /// anchor_remove purges the anchor; lookups and counter allocation then
    /// fail closed.
    #[test]
    fn test_anchor_remove() {
        let mut ctx = AusfContext::new();
        ctx.init(16);
        let supi = "imsi-001010000000046";

        ctx.anchor_refresh(supi, &[0x77u8; 32]);
        assert_eq!(ctx.anchor_count(), 1);
        assert!(ctx.anchor_remove(supi));
        assert!(!ctx.anchor_remove(supi), "second remove finds nothing");
        assert_eq!(ctx.anchor_count(), 0);
        assert!(ctx.anchor_lookup_kausf(supi).is_none());
        assert_eq!(
            ctx.anchor_next_sor_counter(supi),
            Err(AnchorCounterError::NoAnchor)
        );
    }

    /// Concurrency smoke: parallel anchor_next_sor_counter calls hand out
    /// UNIQUE monotonic values — no two MACs can ever share a counter.
    #[test]
    fn test_anchor_counter_concurrency_unique_monotonic() {
        use std::collections::HashSet;

        let mut ctx = AusfContext::new();
        ctx.init(16);
        let ctx = Arc::new(ctx);
        let supi = "imsi-001010000000047";
        ctx.anchor_refresh(supi, &[0x11u8; 32]);

        const THREADS: usize = 8;
        const PER_THREAD: usize = 50;

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || {
                    (0..PER_THREAD)
                        .map(|_| ctx.anchor_next_sor_counter(supi).expect("counter"))
                        .collect::<Vec<u16>>()
                })
            })
            .collect();

        let mut all = Vec::new();
        for handle in handles {
            all.extend(handle.join().expect("thread"));
        }

        let unique: HashSet<u16> = all.iter().copied().collect();
        assert_eq!(
            unique.len(),
            THREADS * PER_THREAD,
            "no duplicate counter may ever be handed out"
        );
        let expected: HashSet<u16> = (1..=(THREADS * PER_THREAD) as u16).collect();
        assert_eq!(unique, expected, "counters must be gapless 0x0001..=N");
        assert!(!unique.contains(&0), "0x0000 must never be handed out");
    }

    #[test]
    fn test_auth_event() {
        let mut ue = AusfUe::new(1, "suci-test");
        assert!(ue.auth_event.resource_uri.is_none());

        ue.auth_event_store("http://example.com/auth-events/1");
        assert_eq!(
            ue.auth_event.resource_uri,
            Some("http://example.com/auth-events/1".to_string())
        );

        ue.auth_event_clear();
        assert!(ue.auth_event.resource_uri.is_none());
    }
}
