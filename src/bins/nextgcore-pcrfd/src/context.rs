//! PCRF Context Management
//!
//! Port of src/pcrf/pcrf-context.c - PCRF context with IP hash tables for
//! Gx session lookup, DB operations, and session management

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Maximum number of PCC rules per session
pub const NEXTGCORE_MAX_NUM_OF_PCC_RULE: usize = 8;

/// IPv6 address length in bytes
pub const NEXTGCORE_IPV6_LEN: usize = 16;

/// PCRF Rx Session State - represents an Rx session linked to a Gx session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default = "PcrfRxSession::snapshot_default")]
pub struct PcrfRxSession {
    /// Rx Session-Id
    pub sid: String,
    /// Associated Gx Session index
    pub gx_session_idx: usize,
    /// Peer host (AF / P-CSCF Origin-Host) for PCRF-initiated ASR
    pub peer_host: Option<String>,
    /// PCC rules installed on behalf of this Rx session
    pub pcc_rules: Vec<PccRule>,
}

impl PcrfRxSession {
    /// Create a new Rx session
    pub fn new(sid: &str, gx_session_idx: usize) -> Self {
        Self {
            sid: sid.to_string(),
            gx_session_idx,
            peer_host: None,
            pcc_rules: Vec::new(),
        }
    }

    /// Per-field fallback for deserialising a snapshot written before a member
    /// existed (#57). Not a `Default` impl: an empty `sid` names no session.
    fn snapshot_default() -> Self {
        Self::new("", 0)
    }
}

/// PCC Rule structure
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct PccRule {
    /// Rule name
    pub name: String,
    /// QoS index
    pub qos_index: u8,
    /// Flow status
    pub flow_status: i32,
    /// Precedence
    pub precedence: u32,
    /// Number of flows
    pub num_of_flow: usize,
}

/// PCRF Gx Session State - represents a Gx session with P-GW
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default = "PcrfGxSession::snapshot_default")]
pub struct PcrfGxSession {
    /// Gx Session-Id
    pub sid: String,
    /// Peer host (P-GW)
    pub peer_host: Option<String>,
    /// IMSI BCD string
    pub imsi_bcd: Option<String>,
    /// APN
    pub apn: Option<String>,
    /// Has IPv4 address
    pub has_ipv4: bool,
    /// Framed IPv4 address
    pub ipv4_addr: Option<Ipv4Addr>,
    /// Has IPv6 address
    pub has_ipv6: bool,
    /// Framed IPv6 prefix
    pub ipv6_addr: Option<[u8; NEXTGCORE_IPV6_LEN]>,
    /// RAT type the PCEF reported (TS 29.212 §5.3.31). `0` = WLAN is a real
    /// value, so `reported_rat` distinguishes "never reported" from "reported 0".
    pub rat_type: u32,
    /// Whether `rat_type` came from a CCR rather than being the initial zero
    /// (#57). Before #57 this field was hardcoded `0` and never populated, so a
    /// reader could not tell an unreported RAT from a WLAN one.
    pub reported_rat: bool,
    /// Names of the PCC rules the PCRF believes are installed at the PCEF for the
    /// session as a whole (#57).
    ///
    /// Maintained so a Charging-Rule-Report saying a rule went INACTIVE has
    /// something to remove it from. Without it the PCRF has no record of what it
    /// provisioned and so cannot act on a failure report at all
    /// (TS 29.212 §4.5.12).
    pub installed_rules: Vec<String>,
    /// List of Rx session indices
    pub rx_sessions: Vec<usize>,
}

impl PcrfGxSession {
    /// Create a new Gx session
    pub fn new(sid: &str) -> Self {
        Self {
            sid: sid.to_string(),
            peer_host: None,
            imsi_bcd: None,
            apn: None,
            has_ipv4: false,
            ipv4_addr: None,
            has_ipv6: false,
            ipv6_addr: None,
            rat_type: 0,
            reported_rat: false,
            installed_rules: Vec::new(),
            rx_sessions: Vec::new(),
        }
    }

    /// Record the RAT-Type the PCEF reported (#57).
    ///
    /// Returns `true` when this is a *change* from a previously reported value —
    /// the first report is not a change, so a session whose initial CCR carried a
    /// RAT is not treated as having handed over.
    pub fn set_rat_type(&mut self, rat_type: u32) -> bool {
        let changed = self.reported_rat && self.rat_type != rat_type;
        self.rat_type = rat_type;
        self.reported_rat = true;
        changed
    }

    /// Record the rule names the PCRF has provisioned to the PCEF (#57).
    pub fn set_installed_rules(&mut self, names: Vec<String>) {
        self.installed_rules = names;
    }

    /// Drop `name` from the installed set. `true` when it was there.
    pub fn remove_installed_rule(&mut self, name: &str) -> bool {
        let before = self.installed_rules.len();
        self.installed_rules.retain(|n| n != name);
        self.installed_rules.len() != before
    }

    /// Set peer host
    pub fn set_peer_host(&mut self, host: &str) {
        self.peer_host = Some(host.to_string());
    }

    /// Set IMSI
    pub fn set_imsi(&mut self, imsi: &str) {
        self.imsi_bcd = Some(imsi.to_string());
    }

    /// Set APN
    pub fn set_apn(&mut self, apn: &str) {
        self.apn = Some(apn.to_string());
    }

    /// Set IPv4 address
    pub fn set_ipv4(&mut self, addr: Ipv4Addr) {
        self.ipv4_addr = Some(addr);
        self.has_ipv4 = true;
    }

    /// Set IPv6 prefix
    pub fn set_ipv6(&mut self, addr: [u8; NEXTGCORE_IPV6_LEN]) {
        self.ipv6_addr = Some(addr);
        self.has_ipv6 = true;
    }

    /// Add Rx session
    pub fn add_rx_session(&mut self, rx_idx: usize) {
        if !self.rx_sessions.contains(&rx_idx) {
            self.rx_sessions.push(rx_idx);
        }
    }

    /// Remove Rx session
    pub fn remove_rx_session(&mut self, rx_idx: usize) {
        self.rx_sessions.retain(|&idx| idx != rx_idx);
    }

    /// Per-field fallback for deserialising a snapshot written before a member
    /// existed (#57). Not a `Default` impl: an empty `sid` names no session.
    fn snapshot_default() -> Self {
        Self::new("")
    }
}

/// Diameter configuration
#[derive(Debug, Clone, Default)]
pub struct DiamConfig {
    /// Diameter identity
    pub cnf_diamid: Option<String>,
    /// Diameter realm
    pub cnf_diamrlm: Option<String>,
    /// Listen address
    pub cnf_addr: Option<String>,
    /// Port
    pub cnf_port: u16,
    /// TLS port
    pub cnf_port_tls: u16,
}

/// PCRF Context - main context structure for PCRF
pub struct PcrfContext {
    /// Diameter configuration file path
    pub diam_conf_path: Option<String>,
    /// Diameter configuration
    pub diam_config: DiamConfig,

    /// Database lock for thread-safe DB operations
    db_lock: Mutex<()>,

    /// Gx session list
    gx_sessions: RwLock<Vec<PcrfGxSession>>,
    /// Gx session hash by Session-Id
    gx_sid_hash: RwLock<HashMap<String, usize>>,
    /// IPv4 to Gx Session-Id mapping
    ipv4_hash: RwLock<HashMap<u32, String>>,
    /// IPv6 to Gx Session-Id mapping
    ipv6_hash: RwLock<HashMap<[u8; NEXTGCORE_IPV6_LEN], String>>,

    /// Rx session list
    rx_sessions: RwLock<Vec<PcrfRxSession>>,
    /// Rx session hash by Session-Id
    rx_sid_hash: RwLock<HashMap<String, usize>>,

    /// Context initialized flag
    initialized: AtomicBool,
    /// Maximum sessions
    max_sess: AtomicUsize,

    /// Durable snapshot of the Gx/Rx session tables and the IP maps (#57).
    ///
    /// Disabled unless a state file is configured, in which case behaviour is
    /// byte-identical to before. `StateStore` rather than the
    /// `read_snapshot`/`write_snapshot` free functions: it enforces "never
    /// overwrite a snapshot you could not read" internally.
    state: nextgcore_core::state_store::StateStore,
}

/// Why pcrfd durable state could not be loaded (#57).
#[derive(Debug, thiserror::Error)]
pub enum PcrfStateError {
    /// The snapshot file itself could not be read or parsed.
    #[error(transparent)]
    Store(#[from] nextgcore_core::state_store::StateStoreError),
    /// The snapshot was written by a newer build. Refused rather than partially
    /// restored: restoring only what this build recognises and then persisting
    /// would rewrite a newer-format file in the older format, discarding the rest.
    #[error(
        "state file {path} was written by a newer pcrfd (snapshot version {found}; this build \
         understands {supported}). Refusing to restore or overwrite it. Run the newer build, or \
         move the file aside to start fresh."
    )]
    UnsupportedVersion {
        path: std::path::PathBuf,
        found: u64,
        supported: u64,
    },
}

impl PcrfContext {
    /// Create a new PCRF context
    pub fn new() -> Self {
        Self {
            diam_conf_path: None,
            diam_config: DiamConfig {
                cnf_port: 3868,
                cnf_port_tls: 5868,
                ..Default::default()
            },
            db_lock: Mutex::new(()),
            gx_sessions: RwLock::new(Vec::new()),
            gx_sid_hash: RwLock::new(HashMap::new()),
            ipv4_hash: RwLock::new(HashMap::new()),
            ipv6_hash: RwLock::new(HashMap::new()),
            rx_sessions: RwLock::new(Vec::new()),
            rx_sid_hash: RwLock::new(HashMap::new()),
            initialized: AtomicBool::new(false),
            max_sess: AtomicUsize::new(1024),
            state: nextgcore_core::state_store::StateStore::disabled(),
        }
    }

    /// Initialize the PCRF context
    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_sess.store(max_sess, Ordering::SeqCst);
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("PCRF context initialized (max_sess={max_sess})");
    }

    /// Finalize the PCRF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // #57: DISABLE the store before clearing anything. The two removals below
        // empty every table, and pcrfd has a Diameter listener that can still reach
        // a mutation during shutdown -- so a persist reached afterwards would write
        // an empty snapshot over a good one and lose every live session, which is
        // the 5002-forever state this snapshot exists to prevent.
        self.state = nextgcore_core::state_store::StateStore::disabled();
        // Clear all sessions
        self.gx_session_remove_all();
        self.rx_session_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PCRF context finalized");
    }

    // ── durable state (#57) ──────────────────────────────────────────────────

    /// Snapshot document version. Bump ONLY for a change no `#[serde(default)]`
    /// can absorb; a bump makes every older snapshot unreadable.
    pub const SNAPSHOT_VERSION: u64 = 1;

    /// Point this context at a snapshot file and restore any prior state,
    /// returning how many sessions were installed.
    ///
    /// Call once at startup, **after** [`init`](Self::init) and **before** the
    /// Diameter listener can accept a CCR, so a restored session is never shadowed
    /// by a fresh one.
    ///
    /// An unreadable snapshot is an **error**: the caller should refuse to start
    /// rather than answer `DIAMETER_UNKNOWN_SESSION_ID` for sessions that exist.
    pub fn set_state_file(&mut self, path: std::path::PathBuf) -> Result<usize, PcrfStateError> {
        use nextgcore_core::state_store::{Loaded, StateStore};
        self.state = StateStore::new(Some(path.clone()));
        match self.state.load()? {
            Loaded::Snapshot(doc) => {
                let restored = self.restore_from(&doc, &path);
                if restored.is_err() {
                    // The load itself succeeded, so the store is not poisoned; a
                    // caller that logged and carried on could overwrite a snapshot
                    // this build cannot fully read. Disable instead.
                    self.state = StateStore::disabled();
                }
                restored
            }
            Loaded::Absent => Ok(0),
        }
    }

    /// Whether durable state is armed. `false` is the shipped default.
    pub fn state_is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    /// Serialize the session tables to one snapshot document.
    ///
    /// **Takes one lock at a time.** `gx_session_remove` documents the canonical
    /// order (primary list before the index and IP hashes); a function holding four
    /// guards at once would be an inversion waiting to happen, so each table is
    /// cloned out and its guard dropped before the next is taken.
    ///
    /// The **index hashes ARE persisted**, which is the opposite of what the other
    /// NFs in this tree do, for a reason specific to pcrfd: `gx_session_remove` and
    /// `rx_session_remove` drop only the hash entry and leave a **tombstone** in
    /// the vector, because a Gx session's `rx_sessions` and an Rx session's
    /// `gx_session_idx` are positional indexes that compacting would re-point. So
    /// the hash — not the vector — is the record of which sessions are live, and it
    /// is not derivable from the list. Rebuilding it from every vector entry would
    /// resurrect every session ever removed. Only the sid→index key set is kept;
    /// the indexes themselves are re-derived from position, so a persisted index
    /// cannot disagree with the list it points into.
    fn snapshot(&self) -> serde_json::Value {
        let gx: Vec<PcrfGxSession> = self
            .gx_sessions
            .read()
            .map(|v| v.clone())
            .unwrap_or_default();
        let live_gx: std::collections::BTreeSet<String> = self
            .gx_sid_hash
            .read()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default();
        let rx: Vec<PcrfRxSession> = self
            .rx_sessions
            .read()
            .map(|v| v.clone())
            .unwrap_or_default();
        let live_rx: std::collections::BTreeSet<String> = self
            .rx_sid_hash
            .read()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default();
        serde_json::json!({
            "version": Self::SNAPSHOT_VERSION,
            // Positional: a Gx session's `rx_sessions` and an Rx session's
            // `gx_session_idx` are INDEXES into these vectors, so the order is part
            // of the data. Sorting or de-duplicating here would silently re-point
            // every binding.
            "gxSessions": gx,
            "rxSessions": rx,
            // BTreeSet so the file does not churn on hash iteration order.
            "liveGxSids": live_gx,
            "liveRxSids": live_rx,
        })
    }

    /// Restore the session tables, re-index the **live** sessions, and rebuild both
    /// IP maps.
    ///
    /// Liveness comes from the persisted sid sets (see [`snapshot`](Self::snapshot)
    /// for why); the indexes themselves are re-derived from vector position, so
    /// they cannot disagree with the list. The IP maps are rebuilt under the same
    /// conditions the live path uses (`has_ipv4`/`has_ipv6` with an address
    /// present) and only for live sessions, so the restored map has exactly the
    /// entries the live one would — a tombstone's old address does not come back
    /// pointing at a session that no longer answers.
    fn restore_from(
        &self,
        doc: &serde_json::Value,
        path: &std::path::Path,
    ) -> Result<usize, PcrfStateError> {
        let found = doc
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(Self::SNAPSHOT_VERSION);
        if found > Self::SNAPSHOT_VERSION {
            return Err(PcrfStateError::UnsupportedVersion {
                path: path.to_path_buf(),
                found,
                supported: Self::SNAPSHOT_VERSION,
            });
        }

        // Whole-vector deserialise, NOT per-record: the vectors are positional and
        // skipping one malformed record would shift every later index, re-pointing
        // `gx_session_idx` and `rx_sessions` at the wrong sessions. An unreadable
        // table restores as empty, which is the pre-#57 behaviour, rather than as a
        // silently re-indexed one.
        let gx: Vec<PcrfGxSession> = doc
            .get("gxSessions")
            .and_then(
                |v| match serde_json::from_value::<Vec<PcrfGxSession>>(v.clone()) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        log::error!("PCRF gxSessions table unreadable, restoring none: {e}");
                        None
                    }
                },
            )
            .unwrap_or_default();
        let rx: Vec<PcrfRxSession> = doc
            .get("rxSessions")
            .and_then(
                |v| match serde_json::from_value::<Vec<PcrfRxSession>>(v.clone()) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        log::error!("PCRF rxSessions table unreadable, restoring none: {e}");
                        None
                    }
                },
            )
            .unwrap_or_default();
        let live_gx: std::collections::HashSet<String> = doc
            .get("liveGxSids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let live_rx: std::collections::HashSet<String> = doc
            .get("liveRxSids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        if let (Ok(mut list), Ok(mut hash), Ok(mut v4), Ok(mut v6)) = (
            self.gx_sessions.write(),
            self.gx_sid_hash.write(),
            self.ipv4_hash.write(),
            self.ipv6_hash.write(),
        ) {
            for (idx, session) in gx.iter().enumerate() {
                if !live_gx.contains(&session.sid) {
                    // A tombstone left by `gx_session_remove`. Kept in the vector so
                    // later indexes still resolve, but NOT re-indexed: doing so would
                    // resurrect a terminated session and answer CCR-Us for it.
                    continue;
                }
                hash.insert(session.sid.clone(), idx);
                if session.has_ipv4 {
                    if let Some(addr) = session.ipv4_addr {
                        v4.insert(u32::from(addr), session.sid.clone());
                    }
                }
                if session.has_ipv6 {
                    if let Some(addr) = session.ipv6_addr {
                        v6.insert(addr, session.sid.clone());
                    }
                }
            }
            *list = gx;
        }
        if let (Ok(mut list), Ok(mut hash)) = (self.rx_sessions.write(), self.rx_sid_hash.write()) {
            for (idx, session) in rx.iter().enumerate() {
                if !live_rx.contains(&session.sid) {
                    continue;
                }
                hash.insert(session.sid.clone(), idx);
            }
            *list = rx;
        }
        let restored = self.gx_session_count() + self.rx_session_count();

        log::info!(
            "PCRF durable state restored: {} Gx session(s), {} Rx session(s); a CCR-U or CCR-T for \
             any of them is answered instead of DIAMETER_UNKNOWN_SESSION_ID",
            self.gx_session_count(),
            self.rx_session_count(),
        );
        Ok(restored)
    }

    /// Write the snapshot after a mutation. A no-op with no state file, and
    /// refused (loudly) when the previous load failed.
    ///
    /// **Every caller must have dropped its write guards first.** `persist` ->
    /// `snapshot` takes read locks on the same tables and `std::sync::RwLock` is
    /// not reentrant, so calling this while holding `gx_sessions.write()`
    /// deadlocks the calling thread.
    pub fn persist(&self) {
        if !self.state.is_enabled() {
            return;
        }
        let doc = self.snapshot();
        if let Err(e) = self.state.persist(&doc) {
            // The session exists in memory but not on disk: the CCR was answered
            // and a restart will reject its updates with 5002.
            log::error!("PCRF state was NOT persisted: {e}");
        }
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // ========== Gx Session Management ==========

    /// Add a new Gx session
    pub fn gx_session_add(&self, sid: &str) -> Option<usize> {
        // #57: scoped so both guards drop before `persist` re-reads them.
        let (idx, added) = {
            let mut sessions = self.gx_sessions.write().ok()?;
            let mut hash = self.gx_sid_hash.write().ok()?;

            if let Some(&existing) = hash.get(sid) {
                (existing, false)
            } else {
                let session = PcrfGxSession::new(sid);
                let idx = sessions.len();
                sessions.push(session);
                hash.insert(sid.to_string(), idx);
                log::debug!("Gx session added: {sid}");
                (idx, true)
            }
        };
        if added {
            self.persist();
        }
        Some(idx)
    }

    /// Find Gx session by Session-Id
    pub fn gx_session_find_by_sid(&self, sid: &str) -> Option<PcrfGxSession> {
        let sessions = self.gx_sessions.read().ok()?;
        let hash = self.gx_sid_hash.read().ok()?;

        hash.get(sid).and_then(|&idx| sessions.get(idx).cloned())
    }

    /// Get Gx session index by Session-Id
    pub fn gx_session_get_idx(&self, sid: &str) -> Option<usize> {
        let hash = self.gx_sid_hash.read().ok()?;
        hash.get(sid).copied()
    }

    /// Update Gx session
    pub fn gx_session_update<F>(&self, sid: &str, f: F) -> bool
    where
        F: FnOnce(&mut PcrfGxSession),
    {
        let updated = {
            if let (Ok(mut sessions), Ok(hash)) =
                (self.gx_sessions.write(), self.gx_sid_hash.read())
            {
                match hash.get(sid).and_then(|&idx| sessions.get_mut(idx)) {
                    Some(session) => {
                        f(session);
                        true
                    }
                    None => false,
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

    /// Remove Gx session
    pub fn gx_session_remove(&self, sid: &str) -> bool {
        // #57: scoped so every guard drops before `persist` re-reads them.
        let removed = {
            // AB-BA: primary list (gx_sessions) before index/IP hashes — canonical order
            let sessions = self.gx_sessions.read();
            let mut hash = self.gx_sid_hash.write().unwrap();
            let mut ipv4_hash = self.ipv4_hash.write().unwrap();
            let mut ipv6_hash = self.ipv6_hash.write().unwrap();

            match hash.get(sid).copied() {
                Some(idx) => {
                    // Remove IP mappings
                    if let Ok(ref sessions) = sessions {
                        if let Some(session) = sessions.get(idx) {
                            if let Some(addr) = session.ipv4_addr {
                                ipv4_hash.remove(&u32::from(addr));
                            }
                            if let Some(addr) = session.ipv6_addr {
                                ipv6_hash.remove(&addr);
                            }
                        }
                    }
                    hash.remove(sid);
                    log::debug!("Gx session removed: {sid}");
                    true
                }
                None => false,
            }
        };
        if removed {
            self.persist();
        }
        removed
    }

    /// Remove all Gx sessions
    pub fn gx_session_remove_all(&self) {
        if let (Ok(mut sessions), Ok(mut hash), Ok(mut ipv4), Ok(mut ipv6)) = (
            self.gx_sessions.write(),
            self.gx_sid_hash.write(),
            self.ipv4_hash.write(),
            self.ipv6_hash.write(),
        ) {
            sessions.clear();
            hash.clear();
            ipv4.clear();
            ipv6.clear();
        }
    }

    /// Get Gx session count
    pub fn gx_session_count(&self) -> usize {
        self.gx_sid_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== IP Address Mapping ==========

    /// Set IPv4 to Session-Id mapping
    pub fn set_ipv4_mapping(&self, addr: &[u8; 4], sid: Option<&str>) {
        // Not persisted here: the IPv4 map is DERIVED from the session table on
        // restore (see `restore_from`), so snapshotting on a map-only change would
        // write a document whose map half is regenerated anyway. Every caller also
        // updates the session's own address, and that path persists.
        let mut hash = self.ipv4_hash.write().unwrap();
        let key = u32::from_be_bytes(*addr);

        if let Some(sid) = sid {
            hash.insert(key, sid.to_string());
            log::debug!("IPv4 mapping set: {addr:?} -> {sid}");
        } else {
            hash.remove(&key);
            log::debug!("IPv4 mapping removed: {addr:?}");
        }
    }

    /// Set IPv6 to Session-Id mapping
    pub fn set_ipv6_mapping(&self, addr: &[u8; NEXTGCORE_IPV6_LEN], sid: Option<&str>) {
        let mut hash = self.ipv6_hash.write().unwrap();

        if let Some(sid) = sid {
            hash.insert(*addr, sid.to_string());
            log::debug!("IPv6 mapping set: {addr:?} -> {sid}");
        } else {
            hash.remove(addr);
            log::debug!("IPv6 mapping removed: {addr:?}");
        }
    }

    /// Find Session-Id by IPv4 address
    pub fn find_sid_by_ipv4(&self, addr: &[u8; 4]) -> Option<String> {
        let hash = self.ipv4_hash.read().ok()?;
        let key = u32::from_be_bytes(*addr);
        hash.get(&key).cloned()
    }

    /// Find Session-Id by IPv6 address
    pub fn find_sid_by_ipv6(&self, addr: &[u8; NEXTGCORE_IPV6_LEN]) -> Option<String> {
        let hash = self.ipv6_hash.read().ok()?;
        hash.get(addr).cloned()
    }

    // ========== Rx Session Management ==========

    /// Add a new Rx session
    pub fn rx_session_add(&self, sid: &str, gx_session_idx: usize) -> Option<usize> {
        // #57: scoped so every guard drops before `persist` re-reads them.
        let (idx, added) = {
            let mut sessions = self.rx_sessions.write().ok()?;
            let mut hash = self.rx_sid_hash.write().ok()?;

            match hash.get(sid).copied() {
                Some(existing) => (existing, false),
                None => {
                    let session = PcrfRxSession::new(sid, gx_session_idx);
                    let idx = sessions.len();
                    sessions.push(session);
                    hash.insert(sid.to_string(), idx);

                    // Add to Gx session's rx_sessions list
                    if let Ok(mut gx_sessions) = self.gx_sessions.write() {
                        if let Some(gx_session) = gx_sessions.get_mut(gx_session_idx) {
                            gx_session.add_rx_session(idx);
                        }
                    }

                    log::debug!("Rx session added: {sid} (gx_idx={gx_session_idx})");
                    (idx, true)
                }
            }
        };
        if added {
            self.persist();
        }
        Some(idx)
    }

    /// Find Rx session by Session-Id
    pub fn rx_session_find_by_sid(&self, sid: &str) -> Option<PcrfRxSession> {
        let sessions = self.rx_sessions.read().ok()?;
        let hash = self.rx_sid_hash.read().ok()?;

        hash.get(sid).and_then(|&idx| sessions.get(idx).cloned())
    }

    /// Find Rx session by index (as referenced from a Gx session binding)
    pub fn rx_session_find_by_idx(&self, idx: usize) -> Option<PcrfRxSession> {
        let sessions = self.rx_sessions.read().ok()?;
        let hash = self.rx_sid_hash.read().ok()?;
        let session = sessions.get(idx)?;
        // Only return the session if it is still registered (not removed)
        if hash.get(&session.sid) == Some(&idx) {
            Some(session.clone())
        } else {
            None
        }
    }

    /// Update Rx session
    pub fn rx_session_update<F>(&self, sid: &str, f: F) -> bool
    where
        F: FnOnce(&mut PcrfRxSession),
    {
        let updated = {
            if let (Ok(mut sessions), Ok(hash)) =
                (self.rx_sessions.write(), self.rx_sid_hash.read())
            {
                match hash.get(sid).and_then(|&idx| sessions.get_mut(idx)) {
                    Some(session) => {
                        f(session);
                        true
                    }
                    None => false,
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

    /// Find Gx session by index (as referenced from an Rx session binding)
    pub fn gx_session_find_by_idx(&self, idx: usize) -> Option<PcrfGxSession> {
        let sessions = self.gx_sessions.read().ok()?;
        let hash = self.gx_sid_hash.read().ok()?;
        let session = sessions.get(idx)?;
        // Only return the session if it is still registered (not removed)
        if hash.get(&session.sid) == Some(&idx) {
            Some(session.clone())
        } else {
            None
        }
    }

    /// Remove Rx session
    pub fn rx_session_remove(&self, sid: &str) -> bool {
        // #57: scoped so every guard drops before `persist` re-reads them.
        let removed = {
            // AB-BA: primary list (rx_sessions) before index (rx_sid_hash) — canonical order
            let rx_sessions = self.rx_sessions.read();
            let mut hash = self.rx_sid_hash.write().unwrap();

            match hash.get(sid).copied() {
                Some(idx) => {
                    // Remove from Gx session's rx_sessions list
                    if let Ok(ref rx_sessions) = rx_sessions {
                        if let Some(rx_session) = rx_sessions.get(idx) {
                            let gx_idx = rx_session.gx_session_idx;
                            if let Ok(mut gx_sessions) = self.gx_sessions.write() {
                                if let Some(gx_session) = gx_sessions.get_mut(gx_idx) {
                                    gx_session.remove_rx_session(idx);
                                }
                            }
                        }
                    }
                    hash.remove(sid);
                    log::debug!("Rx session removed: {sid}");
                    true
                }
                None => false,
            }
        };
        if removed {
            self.persist();
        }
        removed
    }

    /// Remove all Rx sessions
    pub fn rx_session_remove_all(&self) {
        if let (Ok(mut sessions), Ok(mut hash)) =
            (self.rx_sessions.write(), self.rx_sid_hash.write())
        {
            sessions.clear();
            hash.clear();
        }
    }

    /// Get Rx session count
    pub fn rx_session_count(&self) -> usize {
        self.rx_sid_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== Database Operations ==========

    /// Lock database for thread-safe operations
    pub fn db_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.db_lock.lock().unwrap()
    }
}

impl Default for PcrfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PCRF context (thread-safe singleton)
static GLOBAL_PCRF_CONTEXT: std::sync::OnceLock<Arc<RwLock<PcrfContext>>> =
    std::sync::OnceLock::new();

/// Get the global PCRF context
pub fn pcrf_self() -> Arc<RwLock<PcrfContext>> {
    GLOBAL_PCRF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PcrfContext::new())))
        .clone()
}

/// Initialize the global PCRF context
pub fn pcrf_context_init(max_sess: usize) {
    let ctx = pcrf_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.init(max_sess);
    }
}

/// Finalize the global PCRF context
pub fn pcrf_context_final() {
    let ctx = pcrf_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.fini();
    }
}

// ---------------------------------------------------------------------------
// YAML configuration (`pcrf:` section)
// ---------------------------------------------------------------------------

/// The `pcrf.diameter` block: this node's Diameter identity and listener.
///
/// Only the keys `PcrfContext`'s [`DiamConfig`] can hold are declared. It is a
/// smaller struct than the HSS's -- no Tc timer, no forwarding flag, no peer
/// connections -- so those keys are deliberately absent here rather than parsed
/// and dropped, which would be the same silently-ignored-config defect this
/// change removes.
#[derive(Debug, Default, Deserialize)]
pub struct DiameterYaml {
    /// Origin-Host (RFC 6733 §6.3) — this node's Diameter identity.
    pub identity: Option<String>,
    /// Origin-Realm (RFC 6733 §6.4).
    pub realm: Option<String>,
    /// Listen address for the shared Gx + Rx listener.
    pub addr: Option<String>,
    pub port: Option<u16>,
    pub port_tls: Option<u16>,
}

/// The `pcrf:` section. Unknown keys are ignored: the shipped configs carry
/// `freeDiameter:` and `metrics:` keys owned by other subsystems.
#[derive(Debug, Default, Deserialize)]
pub struct PcrfSectionYaml {
    pub diameter: Option<DiameterYaml>,
    /// Path to a freeDiameter-style config, recorded for diagnosis only; this
    /// daemon does not parse that format.
    #[serde(rename = "freeDiameter")]
    pub free_diameter: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PcrfYaml {
    pub pcrf: Option<PcrfSectionYaml>,
}

/// Parse PCRF configuration from YAML and apply it to the global context.
///
/// # Why this exists
///
/// This function used to `return Ok(())` without reading the file, while
/// `main()` logged "Loading configuration from <file>". The only source of the
/// Diameter identity was therefore the CLI, whose defaults are
/// `pcrf.localdomain` / `localdomain` -- well-formed but matching no real
/// deployment, so Gx/Rx peers fail realm-based routing (RFC 6733 §6.1) until
/// flags are supplied, and the config file could not fix it.
///
/// Unlike the HSS, pcrfd does expose `--diameter-id`/`--diameter-realm`/
/// `--diameter-addr`, so those flags remain a valid workaround. `main()` applies
/// YAML first and lets an EXPLICITLY-passed flag win; see its
/// `resolve_diameter_identity`.
///
/// # Errors
///
/// Returns `Err` when the file cannot be read or is not valid YAML — a fatal
/// condition for `main()`, deliberately not a warn-and-continue, because
/// silently falling back to `localdomain` is much harder to diagnose than a
/// refusal to start. A file with no `pcrf.diameter` block is not an error: the
/// shipped `docker/rust/configs/epc/pcrf.yaml` is exactly that.
pub fn pcrf_context_parse_config(config_path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read {config_path}: {e}"))?;

    let parsed: PcrfYaml = serde_yaml::from_str(&content)
        .map_err(|e| format!("invalid YAML in {config_path}: {e}"))?;

    let Some(section) = parsed.pcrf else {
        log::debug!("{config_path}: no 'pcrf' section; keeping defaults");
        return Ok(());
    };

    let ctx = pcrf_self();
    let mut ctx = ctx
        .write()
        .map_err(|_| "PCRF context lock poisoned".to_string())?;

    // The freeDiameter file is the LOWER-precedence source, applied before the
    // YAML block so `pcrf.diameter` wins wherever both speak. Until this landed
    // the path was only recorded, so the identity came from the built-in
    // `pcrf.localdomain` default rather than the mounted file.
    if let Some(path) = section.free_diameter {
        match nextgcore_diameter::fd_conf::FreeDiameterConf::load(&path) {
            Ok(conf) => {
                if !conf.ignored.is_empty() {
                    log::info!(
                        "{path}: directives not interpreted: {}",
                        conf.ignored
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                apply_fd_conf(&mut ctx.diam_config, &conf);
            }
            Err(e) => log::warn!("Could not read freeDiameter config '{path}': {e}"),
        }
        ctx.diam_conf_path = Some(path);
    }

    if let Some(diam) = section.diameter {
        apply_diameter_yaml(&mut ctx.diam_config, diam);
    } else {
        log::debug!("{config_path}: no 'pcrf.diameter' block");
    }
    Ok(())
}

/// Copy a parsed freeDiameter `.conf` onto a [`DiamConfig`].
///
/// Only what the file states is copied. `pcrf.conf` declares no peers this
/// daemon dials — the PCRF is the Gx server — so `ConnectPeer` entries are
/// ignored here rather than invented into a client list.
pub fn apply_fd_conf(cfg: &mut DiamConfig, conf: &nextgcore_diameter::fd_conf::FreeDiameterConf) {
    if let Some(identity) = conf.identity.clone() {
        cfg.cnf_diamid = Some(identity);
    }
    if let Some(realm) = conf.realm.clone() {
        cfg.cnf_diamrlm = Some(realm);
    }
    if let Some(addr) = conf.listen_address() {
        cfg.cnf_addr = Some(addr.to_string());
    }
    if let Some(port) = conf.port {
        cfg.cnf_port = port;
    }
    if let Some(port) = conf.sec_port {
        cfg.cnf_port_tls = port;
    }
}

/// Copy the parsed `diameter` block onto a [`DiamConfig`].
///
/// Absent keys leave the existing value untouched, so a partial config cannot
/// zero `cnf_port`. Shared with the unit tests so the mapping is verified
/// directly rather than only through `main()`.
pub fn apply_diameter_yaml(cfg: &mut DiamConfig, diam: DiameterYaml) {
    if let Some(v) = diam.identity {
        cfg.cnf_diamid = Some(v);
    }
    if let Some(v) = diam.realm {
        cfg.cnf_diamrlm = Some(v);
    }
    if let Some(v) = diam.addr {
        cfg.cnf_addr = Some(v);
    }
    if let Some(v) = diam.port {
        cfg.cnf_port = v;
    }
    if let Some(v) = diam.port_tls {
        cfg.cnf_port_tls = v;
    }
}

/// Set IPv4 to Session-Id mapping (global function)
pub fn pcrf_sess_set_ipv4(addr: &[u8; 4], sid: Option<&str>) {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        context.set_ipv4_mapping(addr, sid);
    }
}

/// Set IPv6 to Session-Id mapping (global function)
pub fn pcrf_sess_set_ipv6(addr: &[u8; NEXTGCORE_IPV6_LEN], sid: Option<&str>) {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        context.set_ipv6_mapping(addr, sid);
    }
}

/// Find Session-Id by IPv4 address (global function)
pub fn pcrf_sess_find_by_ipv4(addr: &[u8; 4]) -> Option<String> {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        return context.find_sid_by_ipv4(addr);
    }
    None
}

/// Find Session-Id by IPv6 address (global function)
pub fn pcrf_sess_find_by_ipv6(addr: &[u8; NEXTGCORE_IPV6_LEN]) -> Option<String> {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        return context.find_sid_by_ipv6(addr);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcrf_context_new() {
        let ctx = PcrfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.gx_session_count(), 0);
        assert_eq!(ctx.rx_session_count(), 0);
    }

    #[test]
    fn test_pcrf_context_init_fini() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_gx_session_add_remove() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        let _idx = ctx.gx_session_add("gx-session-1").unwrap();
        assert_eq!(ctx.gx_session_count(), 1);

        let session = ctx.gx_session_find_by_sid("gx-session-1");
        assert!(session.is_some());
        assert_eq!(session.unwrap().sid, "gx-session-1");

        ctx.gx_session_remove("gx-session-1");
        assert_eq!(ctx.gx_session_count(), 0);
    }

    #[test]
    fn test_gx_session_update() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        ctx.gx_session_update("gx-session-1", |session| {
            session.set_imsi("123456789012345");
            session.set_apn("internet");
        });

        let session = ctx.gx_session_find_by_sid("gx-session-1").unwrap();
        assert_eq!(session.imsi_bcd, Some("123456789012345".to_string()));
        assert_eq!(session.apn, Some("internet".to_string()));
    }

    #[test]
    fn test_ipv4_mapping() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        let addr: [u8; 4] = [192, 168, 1, 1];
        ctx.set_ipv4_mapping(&addr, Some("gx-session-1"));

        let sid = ctx.find_sid_by_ipv4(&addr);
        assert_eq!(sid, Some("gx-session-1".to_string()));

        ctx.set_ipv4_mapping(&addr, None);
        let sid = ctx.find_sid_by_ipv4(&addr);
        assert!(sid.is_none());
    }

    #[test]
    fn test_ipv6_mapping() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        let addr: [u8; NEXTGCORE_IPV6_LEN] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        ctx.set_ipv6_mapping(&addr, Some("gx-session-1"));

        let sid = ctx.find_sid_by_ipv6(&addr);
        assert_eq!(sid, Some("gx-session-1".to_string()));
    }

    #[test]
    fn test_rx_session_add_remove() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        let gx_idx = ctx.gx_session_add("gx-session-1").unwrap();
        let rx_idx = ctx.rx_session_add("rx-session-1", gx_idx).unwrap();

        assert_eq!(ctx.rx_session_count(), 1);

        let rx_session = ctx.rx_session_find_by_sid("rx-session-1");
        assert!(rx_session.is_some());
        assert_eq!(rx_session.unwrap().gx_session_idx, gx_idx);

        // Check Gx session has Rx session reference
        let gx_session = ctx.gx_session_find_by_sid("gx-session-1").unwrap();
        assert!(gx_session.rx_sessions.contains(&rx_idx));

        ctx.rx_session_remove("rx-session-1");
        assert_eq!(ctx.rx_session_count(), 0);
    }

    #[test]
    fn test_pcrf_gx_session() {
        let mut session = PcrfGxSession::new("test-session");
        assert_eq!(session.sid, "test-session");
        assert!(session.peer_host.is_none());

        session.set_peer_host("pgw.example.com");
        assert_eq!(session.peer_host, Some("pgw.example.com".to_string()));

        session.set_imsi("123456789012345");
        assert_eq!(session.imsi_bcd, Some("123456789012345".to_string()));

        session.set_apn("internet");
        assert_eq!(session.apn, Some("internet".to_string()));

        session.set_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(session.has_ipv4);
        assert_eq!(session.ipv4_addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_pcrf_rx_session() {
        let session = PcrfRxSession::new("rx-session-1", 0);
        assert_eq!(session.sid, "rx-session-1");
        assert_eq!(session.gx_session_idx, 0);
        assert!(session.pcc_rules.is_empty());
    }

    #[test]
    fn freediameter_conf_supplies_the_identity_the_deployment_mounts() {
        let path = "../../../docker/rust/configs/epc/freeDiameter/pcrf.conf";
        let conf = nextgcore_diameter::fd_conf::FreeDiameterConf::load(path)
            .unwrap_or_else(|e| panic!("cannot read shipped {path}: {e}"));

        let mut cfg = DiamConfig::default();
        apply_fd_conf(&mut cfg, &conf);

        assert_eq!(cfg.cnf_diamid.as_deref(), Some("pcrf.localdomain"));
        assert_eq!(cfg.cnf_diamrlm.as_deref(), Some("localdomain"));
        // The listen address the deployment mounts, which was previously ignored.
        assert_eq!(cfg.cnf_addr.as_deref(), Some("172.24.0.9"));
    }

    #[test]
    fn yaml_wins_over_the_freediameter_conf() {
        let mut cfg = DiamConfig::default();
        apply_fd_conf(
            &mut cfg,
            &nextgcore_diameter::fd_conf::FreeDiameterConf::parse(
                "Identity = \"from.conf\";\nRealm = \"conf.realm\";\n",
            ),
        );

        let parsed: PcrfYaml =
            serde_yaml::from_str("pcrf:\n  diameter:\n    identity: from.yaml\n")
                .expect("must parse");
        apply_diameter_yaml(&mut cfg, parsed.pcrf.unwrap().diameter.unwrap());

        assert_eq!(cfg.cnf_diamid.as_deref(), Some("from.yaml"));
        assert_eq!(
            cfg.cnf_diamrlm.as_deref(),
            Some("conf.realm"),
            "what the YAML omits still comes from the .conf"
        );
    }

    // ── durable state (#57) ──────────────────────────────────────────────────
    //
    // Every test here builds its own `PcrfContext`, never `pcrf_self()`: arming a
    // state file on the process-global context would make one test's snapshot the
    // next test's restored state.

    /// Unique snapshot path per test so parallel runs cannot collide.
    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nextgcore-pcrf-state-{}-{tag}-{nanos}.json",
            std::process::id()
        ))
    }

    fn ctx_with_state(path: &std::path::Path) -> PcrfContext {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);
        ctx.set_state_file(path.to_path_buf())
            .expect("arming a fresh state file must succeed");
        ctx
    }

    /// #57 criterion 5, the persistence path: after a simulated restart a CCR-U or
    /// CCR-T for a pre-restart session resolves, so it is no longer answered
    /// DIAMETER_UNKNOWN_SESSION_ID (5002) forever.
    #[test]
    fn a_pre_restart_session_still_resolves_after_a_simulated_restart() {
        let path = temp_state_path("restart");
        let sid = "gx-restart-1";
        let rx_sid = "rx-restart-1";
        {
            let ctx = ctx_with_state(&path);
            let gx_idx = ctx.gx_session_add(sid).expect("gx session");
            ctx.gx_session_update(sid, |s| {
                s.set_peer_host("pgw.example.com");
                s.set_imsi("001010123456789");
                s.set_apn("internet");
                s.set_ipv4(Ipv4Addr::new(10, 45, 0, 2));
                s.set_rat_type(1004);
                s.set_installed_rules(vec!["pcrf-internet-default".to_string()]);
            });
            ctx.set_ipv4_mapping(&[10, 45, 0, 2], Some(sid));
            ctx.rx_session_add(rx_sid, gx_idx).expect("rx session");
            ctx.rx_session_update(rx_sid, |rx| {
                rx.peer_host = Some("pcscf.example.com".to_string());
                rx.pcc_rules.push(PccRule {
                    name: "rx-voice-1".to_string(),
                    qos_index: 1,
                    flow_status: 2,
                    precedence: 50,
                    num_of_flow: 1,
                });
            });
        }

        // A cold rebuild from the same file: a different process would do exactly
        // this, and nothing carries over except the snapshot.
        let restored = ctx_with_state(&path);

        let session = restored
            .gx_session_find_by_sid(sid)
            .expect("the CCR-U/CCR-T lookup that used to answer 5002 must resolve");
        assert_eq!(session.peer_host.as_deref(), Some("pgw.example.com"));
        assert_eq!(session.imsi_bcd.as_deref(), Some("001010123456789"));
        assert_eq!(session.apn.as_deref(), Some("internet"));
        assert_eq!(session.ipv4_addr, Some(Ipv4Addr::new(10, 45, 0, 2)));
        assert_eq!(session.rat_type, 1004);
        assert!(session.reported_rat);
        assert_eq!(
            session.installed_rules,
            vec!["pcrf-internet-default".to_string()],
            "without the installed set a post-restart rule report has nothing to act on"
        );
        // The IPv4 map is DERIVED on restore, so this also proves the derivation.
        assert_eq!(
            restored.find_sid_by_ipv4(&[10, 45, 0, 2]).as_deref(),
            Some(sid)
        );

        // The Rx binding survives in both directions, or the PCRF could not abort
        // the AF for a restored session.
        let rx = restored
            .rx_session_find_by_sid(rx_sid)
            .expect("Rx session restored");
        assert_eq!(rx.peer_host.as_deref(), Some("pcscf.example.com"));
        assert_eq!(rx.pcc_rules.len(), 1);
        assert_eq!(
            session.rx_sessions,
            vec![0],
            "the Gx -> Rx index binding survives"
        );
        assert_eq!(
            restored.rx_session_find_by_idx(0).map(|r| r.sid),
            Some(rx_sid.to_string()),
            "and resolves by index, which is how handle_ccr walks it"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Each mutator must persist on its own, not rely on a later one doing it.
    ///
    /// Written after noticing that
    /// `a_pre_restart_session_still_resolves_after_a_simulated_restart` still
    /// passed with `gx_session_update`'s persist removed: the snapshot is a
    /// full-store document, so the `rx_session_add` that followed captured the
    /// update's changes too. That test therefore proves "something persisted", not
    /// "this mutator persisted". Here the update is the LAST thing that happens
    /// before the restore, which is the crash-right-after-a-CCR case, so nothing
    /// else can cover for it.
    #[test]
    fn the_last_mutation_before_a_crash_is_durable() {
        let path = temp_state_path("last-write");
        let sid = "gx-lastwrite-1";
        {
            let ctx = ctx_with_state(&path);
            ctx.gx_session_add(sid).expect("gx session");
            // The final mutation, with no later persist to cover for it.
            ctx.gx_session_update(sid, |s| {
                s.set_apn("ims");
                s.set_rat_type(1001);
            });
        }

        let restored = ctx_with_state(&path);
        let session = restored
            .gx_session_find_by_sid(sid)
            .expect("session restored");
        assert_eq!(
            session.apn.as_deref(),
            Some("ims"),
            "the update itself must have reached the file"
        );
        assert_eq!(session.rat_type, 1001);

        let _ = std::fs::remove_file(&path);
    }

    /// Same shape for the Rx side, and it found a real gap: `rx_session_add` was
    /// the one mutator with no persist, and
    /// `a_pre_restart_session_still_resolves_after_a_simulated_restart` did not
    /// catch it because the `rx_session_update` that followed persisted the whole
    /// store anyway.
    #[test]
    fn an_rx_binding_added_and_nothing_else_is_durable() {
        let path = temp_state_path("rx-last-write");
        let sid = "gx-rxlast-1";
        let rx_sid = "rx-rxlast-1";
        {
            let ctx = ctx_with_state(&path);
            let gx_idx = ctx.gx_session_add(sid).expect("gx session");
            // The final mutation. No rx_session_update follows.
            ctx.rx_session_add(rx_sid, gx_idx).expect("rx session");
        }

        let restored = ctx_with_state(&path);
        assert!(
            restored.rx_session_find_by_sid(rx_sid).is_some(),
            "the Rx binding must have reached the file on its own"
        );
        assert_eq!(
            restored
                .gx_session_find_by_sid(sid)
                .expect("gx session")
                .rx_sessions,
            vec![0],
            "and so must the Gx -> Rx back-reference the add installed"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// An Rx session aborted by a rule report must stay gone across a restart.
    ///
    /// `withdraw_rule_from_rx_sessions` removes the Rx session it just told the AF
    /// to abort; if that removal were not durable the restart would resurrect an Rx
    /// session whose AF has already torn its own side down, and the next rule report
    /// would try to abort it a second time.
    #[test]
    fn an_aborted_rx_session_stays_gone_across_a_restart() {
        let path = temp_state_path("rx-abort");
        let sid = "gx-rxabort-1";
        let rx_sid = "rx-rxabort-1";
        {
            let ctx = ctx_with_state(&path);
            let gx_idx = ctx.gx_session_add(sid).expect("gx session");
            ctx.rx_session_add(rx_sid, gx_idx).expect("rx session");
            // The final mutation.
            assert!(ctx.rx_session_remove(rx_sid));
        }

        let restored = ctx_with_state(&path);
        assert!(
            restored.rx_session_find_by_sid(rx_sid).is_none(),
            "an aborted Rx session must not come back"
        );
        assert_eq!(restored.rx_session_count(), 0);
        assert!(
            restored
                .gx_session_find_by_sid(sid)
                .expect("gx session")
                .rx_sessions
                .is_empty(),
            "and the Gx side must not still point at it"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The tombstone hazard: `gx_session_remove` drops only the hash entry and
    /// leaves the vector entry in place, so a restore that re-indexed every vector
    /// entry would RESURRECT terminated sessions and answer CCR-Us for them.
    #[test]
    fn a_terminated_session_is_not_resurrected_by_a_restore() {
        let path = temp_state_path("tombstone");
        {
            let ctx = ctx_with_state(&path);
            ctx.gx_session_add("gx-tomb-live").expect("live");
            ctx.gx_session_add("gx-tomb-dead").expect("dead");
            ctx.gx_session_update("gx-tomb-dead", |s| {
                s.set_ipv4(Ipv4Addr::new(10, 45, 9, 9));
            });
            ctx.set_ipv4_mapping(&[10, 45, 9, 9], Some("gx-tomb-dead"));
            assert!(ctx.gx_session_remove("gx-tomb-dead"));
        }

        let restored = ctx_with_state(&path);
        assert!(
            restored.gx_session_find_by_sid("gx-tomb-live").is_some(),
            "the live session must come back"
        );
        assert!(
            restored.gx_session_find_by_sid("gx-tomb-dead").is_none(),
            "a terminated session must NOT come back; answering its CCR-U would be worse \
             than 5002"
        );
        assert_eq!(restored.gx_session_count(), 1);
        assert_eq!(
            restored.find_sid_by_ipv4(&[10, 45, 9, 9]),
            None,
            "and its address must not resolve to it either"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The shipped default: no state file means no file operations at all.
    #[test]
    fn without_a_state_file_nothing_is_persisted() {
        let dir = std::env::temp_dir().join(format!(
            "nextgcore-pcrf-nostate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // Positive control FIRST, so the absence assertion below is known to be
        // capable of failing: an armed context writing into this same directory
        // must be visible to the scan.
        {
            let armed = ctx_with_state(&dir.join("armed.json"));
            armed.gx_session_add("gx-control").expect("session");
        }
        assert!(
            dir.join("armed.json").exists(),
            "positive control: an armed store must write into the watched directory"
        );
        std::fs::remove_file(dir.join("armed.json")).expect("clear the control");

        let mut ctx = PcrfContext::new();
        ctx.init(1024);
        assert!(!ctx.state_is_enabled());
        let idx = ctx.gx_session_add("gx-nostate").expect("session");
        ctx.gx_session_update("gx-nostate", |s| s.set_apn("internet"));
        ctx.rx_session_add("rx-nostate", idx).expect("rx");
        ctx.rx_session_update("rx-nostate", |r| r.peer_host = Some("af".to_string()));
        ctx.set_ipv4_mapping(&[10, 45, 0, 3], Some("gx-nostate"));
        ctx.rx_session_remove("rx-nostate");
        ctx.gx_session_remove("gx-nostate");
        ctx.fini();

        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("read temp dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "a memory-only PCRF must touch no files, found {entries:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot from a newer build must be refused AND left alone, not partially
    /// restored and then rewritten in the older format.
    #[test]
    fn a_newer_snapshot_is_refused_and_not_overwritten() {
        let path = temp_state_path("newer");
        let doc = serde_json::json!({
            "version": PcrfContext::SNAPSHOT_VERSION + 1,
            "gxSessions": [],
            "rxSessions": [],
            "liveGxSids": [],
            "liveRxSids": [],
        });
        let before = serde_json::to_vec_pretty(&doc).expect("serialise");
        std::fs::write(&path, &before).expect("write snapshot");

        let mut ctx = PcrfContext::new();
        ctx.init(1024);
        let err = ctx
            .set_state_file(path.clone())
            .expect_err("a newer snapshot must be refused");
        assert!(
            matches!(err, PcrfStateError::UnsupportedVersion { .. }),
            "got {err:?}"
        );
        assert!(
            !ctx.state_is_enabled(),
            "the store must be disabled so a later mutation cannot rewrite the file"
        );

        // Prove the refusal protects the file.
        ctx.gx_session_add("gx-after-refusal");
        assert_eq!(
            std::fs::read(&path).expect("file still there"),
            before,
            "the newer-format file must be byte-identical after a refused load"
        );

        let _ = std::fs::remove_file(&path);
    }
}
