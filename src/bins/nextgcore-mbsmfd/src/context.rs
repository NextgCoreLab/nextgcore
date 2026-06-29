//! MB-SMF Context Management
//!
//! Multicast/Broadcast Session Management Function context (TS 23.247)
//! Includes N4mb PFCP session management for multicast transport

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::subscription::{MbsEvent, SubEntry, SubscriptionStore};

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// MBS Session ID (TMGI - Temporary Mobile Group Identity)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tmgi {
    /// MBS Service ID (3 bytes)
    pub mbs_service_id: [u8; 3],
    /// PLMN ID (MCC + MNC)
    pub plmn_id: PlmnId,
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// MBS Session Type (TS 23.247 5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MbsSessionType {
    #[default]
    Multicast,
    Broadcast,
}

/// MBS Session State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MbsSessionState {
    #[default]
    Created,
    Active,
    Suspended,
    Released,
}

/// N4mb PFCP session state for multicast transport (TS 23.247 7.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum N4mbSessionState {
    #[default]
    Idle,
    EstablishmentPending,
    Established,
    ModificationPending,
    ReleasePending,
}

/// N4mb PFCP session context for UPF multicast transport
#[derive(Debug, Clone)]
pub struct N4mbSession {
    /// PFCP session endpoint ID (local)
    pub local_seid: u64,
    /// PFCP session endpoint ID (UPF)
    pub remote_seid: u64,
    /// UPF address for N4mb
    pub upf_addr: Ipv4Addr,
    /// Session state
    pub state: N4mbSessionState,
    /// Multicast PDR ID (downlink, 1-to-many)
    pub mcast_pdr_id: u16,
    /// Multicast FAR ID (forwarding to gNBs)
    pub mcast_far_id: u32,
    /// GTP-U TEID for multicast DL tunnel (the GTP-U common TEID / `cTeid`
    /// returned to the SMF in ContextUpdate).
    pub dl_teid: u32,
    /// Multicast transport address (UPF endpoint)
    pub transport_addr: Option<Ipv4Addr>,
    /// Lower-layer SSM source address (`llSsm.sourceIpAddr`) advertised to the
    /// SMF for multicast reception (TS 29.532 ContextUpdate). [mbsmfd-03/09]
    pub ll_ssm_src: Option<Ipv4Addr>,
    /// Lower-layer SSM destination (the IP multicast group `llSsm.destIpAddr`),
    /// also the OuterHeaderCreation transport address in the N4mb Create FAR.
    pub ll_ssm_dst: Option<Ipv4Addr>,
    /// Target gNB TEIDs for multicast forwarding
    pub gnb_teids: Vec<GnbMcastEndpoint>,
}

/// gNB endpoint for multicast GTP-U delivery
#[derive(Debug, Clone)]
pub struct GnbMcastEndpoint {
    pub gnb_addr: Ipv4Addr,
    pub teid: u32,
}

impl N4mbSession {
    pub fn new(local_seid: u64, upf_addr: Ipv4Addr) -> Self {
        Self {
            local_seid,
            remote_seid: 0,
            upf_addr,
            state: N4mbSessionState::Idle,
            mcast_pdr_id: 0,
            mcast_far_id: 0,
            dl_teid: 0,
            transport_addr: None,
            ll_ssm_src: None,
            ll_ssm_dst: None,
            gnb_teids: Vec::new(),
        }
    }
}

/// MBS group membership entry
#[derive(Debug, Clone)]
pub struct MbsGroupMember {
    pub supi: String,
    pub pdu_session_id: Option<u8>,
    pub joined_at: u64,
}

/// MBS Session Context (TS 23.247 5.3)
#[derive(Debug, Clone)]
pub struct MbsSession {
    /// Unique pool ID
    pub id: u64,
    /// MBS Session ID (TMGI)
    pub tmgi: Tmgi,
    /// MBS session type
    pub session_type: MbsSessionType,
    /// Session state
    pub state: MbsSessionState,
    /// S-NSSAI for the session
    pub s_nssai: SNssai,
    /// DNN
    pub dnn: Option<String>,
    /// MBS service area (list of TAIs)
    pub service_area_tacs: Vec<u32>,
    /// QoS flow ID
    pub qfi: u8,
    /// 5QI for the MBS QoS flow
    pub fiveqi: u8,
    /// Maximum bitrate (bps)
    pub max_bitrate: u64,
    /// Multicast transport address (for NGAP)
    pub transport_address: Option<String>,
    /// GTP-U TEID for multicast data
    pub gtp_teid: u32,
    /// Number of joined UEs
    pub joined_ue_count: u32,
    /// SM context reference at SMF
    pub sm_context_ref: Option<String>,
    /// N4mb PFCP session to UPF
    pub n4mb_session: Option<N4mbSession>,
    /// Group membership tracking (SUPI set)
    pub group_members: HashSet<String>,
}

impl MbsSession {
    pub fn new(id: u64, tmgi: Tmgi, session_type: MbsSessionType) -> Self {
        Self {
            id,
            tmgi,
            session_type,
            state: MbsSessionState::Created,
            s_nssai: SNssai::default(),
            dnn: None,
            service_area_tacs: Vec::new(),
            qfi: 1,
            fiveqi: 9,
            max_bitrate: 10_000_000, // 10 Mbps default
            transport_address: None,
            gtp_teid: 0,
            joined_ue_count: 0,
            sm_context_ref: None,
            n4mb_session: None,
            group_members: HashSet::new(),
        }
    }

    /// Add a UE to the multicast group
    pub fn member_join(&mut self, supi: &str) -> bool {
        if self.group_members.insert(supi.to_string()) {
            self.joined_ue_count = self.group_members.len() as u32;
            log::info!("UE {supi} joined MBS session {}", self.id);
            true
        } else {
            false
        }
    }

    /// Remove a UE from the multicast group
    pub fn member_leave(&mut self, supi: &str) -> bool {
        if self.group_members.remove(supi) {
            self.joined_ue_count = self.group_members.len() as u32;
            log::info!("UE {supi} left MBS session {}", self.id);
            true
        } else {
            false
        }
    }

    /// Check if a UE is a member of this session
    pub fn is_member(&self, supi: &str) -> bool {
        self.group_members.contains(supi)
    }
}

/// N4mb PFCP message types for multicast transport (TS 29.244 extension)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N4mbMessageType {
    SessionEstablishmentRequest,
    SessionEstablishmentResponse,
    SessionModificationRequest,
    SessionModificationResponse,
    SessionReleaseRequest,
    SessionReleaseResponse,
}

/// Build N4mb PFCP Session Establishment for multicast (TS 23.247 7.3.2)
pub fn build_n4mb_session_establishment(
    session: &MbsSession,
    local_seid: u64,
    upf_addr: Ipv4Addr,
) -> N4mbSession {
    let mut n4mb = N4mbSession::new(local_seid, upf_addr);
    n4mb.state = N4mbSessionState::EstablishmentPending;
    // Assign multicast PDR/FAR IDs based on session
    n4mb.mcast_pdr_id = (session.id as u16).wrapping_mul(2).wrapping_add(1000);
    n4mb.mcast_far_id = (session.id as u32).wrapping_mul(2).wrapping_add(2000);
    n4mb.dl_teid = session.gtp_teid;
    // Lower-layer SSM for multicast reception (TS 29.532 §6.2.6.2.6): the source
    // is the (MB-)UPF transport address and the destination is an admin-scoped
    // (239.0.0.0/8) IP multicast group derived deterministically from the
    // session id. This same destination is the OuterHeaderCreation transport
    // address in the N4mb Create FAR (mbsmfd-09).
    n4mb.ll_ssm_src = Some(upf_addr);
    n4mb.ll_ssm_dst = Some(mcast_group_for(session.id));
    n4mb
}

/// Deterministic admin-scoped IPv4 multicast group (239.1.x.y) for an MBS
/// session id — used as the lower-layer SSM destination / N4mb transport address.
pub fn mcast_group_for(session_id: u64) -> Ipv4Addr {
    Ipv4Addr::new(239, 1, (session_id >> 8) as u8, session_id as u8)
}

/// Process N4mb Session Establishment Response
pub fn process_n4mb_establishment_response(
    n4mb: &mut N4mbSession,
    remote_seid: u64,
    dl_teid: u32,
    transport_addr: Ipv4Addr,
) {
    n4mb.remote_seid = remote_seid;
    n4mb.dl_teid = dl_teid;
    n4mb.transport_addr = Some(transport_addr);
    n4mb.state = N4mbSessionState::Established;
    log::info!(
        "N4mb session established: local_seid={} remote_seid={} dl_teid={:#x} transport={}",
        n4mb.local_seid,
        remote_seid,
        dl_teid,
        transport_addr
    );
}

// ---------------------------------------------------------------------------
// mbsmfd-04: TMGI allocation pool (Nmbsmf_TMGI, TS 29.532 §5.2)
// ---------------------------------------------------------------------------

/// Current wall-clock time as whole seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as an RFC 3339 / ISO-8601 UTC string (the
/// `DateTime` shape TS 29.571 expects for `expirationTime`). Dependency-free
/// civil-date conversion (Howard Hinnant's algorithm).
pub fn unix_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Default TMGI lifetime (seconds) before expiry. Refreshed on re-allocation.
pub const TMGI_DEFAULT_TTL_SECS: u64 = 3600;

/// Per-PLMN TMGI allocation pool with per-allocation expiry (TS 29.532 §5.2.2).
///
/// `mbsServiceId` is a 3-octet value allocated monotonically per PLMN; each
/// allocated TMGI tracks an absolute expiry (Unix seconds) that refresh extends.
#[derive(Debug, Default)]
pub struct TmgiPool {
    /// Next free 3-octet service id per PLMN.
    next_id: HashMap<PlmnId, u32>,
    /// Allocated TMGI -> absolute expiry (Unix seconds).
    allocated: HashMap<Tmgi, u64>,
}

impl TmgiPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate `count` fresh TMGIs in `plmn`, expiring `ttl_secs` from `now`.
    /// Returns the allocated TMGIs and the common absolute expiry.
    pub fn allocate(
        &mut self,
        plmn: &PlmnId,
        count: u32,
        ttl_secs: u64,
        now: u64,
    ) -> (Vec<Tmgi>, u64) {
        let expiry = now.saturating_add(ttl_secs);
        let mut out = Vec::with_capacity(count as usize);
        let next = self.next_id.entry(plmn.clone()).or_insert(1);
        for _ in 0..count {
            let id = *next;
            *next = next.wrapping_add(1);
            let tmgi = Tmgi {
                mbs_service_id: [(id >> 16) as u8, (id >> 8) as u8, id as u8],
                plmn_id: plmn.clone(),
            };
            self.allocated.insert(tmgi.clone(), expiry);
            out.push(tmgi);
        }
        (out, expiry)
    }

    /// Refresh the expiry of the supplied TMGIs (inserting any not yet known),
    /// returning the new common absolute expiry.
    pub fn refresh(&mut self, tmgis: &[Tmgi], ttl_secs: u64, now: u64) -> u64 {
        let expiry = now.saturating_add(ttl_secs);
        for t in tmgis {
            self.allocated.insert(t.clone(), expiry);
        }
        expiry
    }

    /// Deallocate the supplied TMGIs; returns how many were present.
    pub fn deallocate(&mut self, tmgis: &[Tmgi]) -> usize {
        tmgis
            .iter()
            .filter(|t| self.allocated.remove(t).is_some())
            .count()
    }

    /// Deallocate every TMGI; returns how many were freed.
    pub fn deallocate_all(&mut self) -> usize {
        let n = self.allocated.len();
        self.allocated.clear();
        n
    }

    /// Drop TMGIs whose expiry is at or before `now`.
    pub fn purge_expired(&mut self, now: u64) {
        self.allocated.retain(|_, &mut expiry| expiry > now);
    }

    /// Number of currently-allocated TMGIs.
    pub fn len(&self) -> usize {
        self.allocated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocated.is_empty()
    }

    /// Expiry (Unix seconds) of a specific TMGI, if allocated.
    pub fn expiry_of(&self, tmgi: &Tmgi) -> Option<u64> {
        self.allocated.get(tmgi).copied()
    }
}

/// MB-SMF Context - main context structure
pub struct MbSmfContext {
    /// MBS session list
    session_list: RwLock<HashMap<u64, MbsSession>>,
    /// TMGI -> session ID hash
    tmgi_hash: RwLock<HashMap<Tmgi, u64>>,
    /// Next session ID generator
    next_session_id: AtomicUsize,
    /// Maximum number of sessions
    max_sessions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Next N4mb SEID generator
    next_n4mb_seid: AtomicUsize,
    /// Next GTP-U TEID generator for multicast
    next_mcast_teid: AtomicU32,
    /// Nmbsmf_TMGI allocation pool (per-PLMN, with expiry). [mbsmfd-04]
    tmgi_pool: Mutex<TmgiPool>,
    /// Status subscription store (NEF/MBSF/AF-facing). [mbsmfd-05]
    status_subs: Mutex<SubscriptionStore>,
    /// ContextStatus subscription store (SMF-facing). [mbsmfd-05]
    context_status_subs: Mutex<SubscriptionStore>,
}

impl MbSmfContext {
    pub fn new() -> Self {
        Self {
            session_list: RwLock::new(HashMap::new()),
            tmgi_hash: RwLock::new(HashMap::new()),
            next_session_id: AtomicUsize::new(1),
            max_sessions: 0,
            initialized: AtomicBool::new(false),
            next_n4mb_seid: AtomicUsize::new(0x100),
            next_mcast_teid: AtomicU32::new(0x0BCA_0001),
            tmgi_pool: Mutex::new(TmgiPool::new()),
            status_subs: Mutex::new(SubscriptionStore::new()),
            context_status_subs: Mutex::new(SubscriptionStore::new()),
        }
    }

    pub fn init(&mut self, max_sessions: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_sessions = max_sessions;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("MB-SMF context initialized with max {max_sessions} sessions");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.session_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("MB-SMF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Allocate a new N4mb SEID
    pub fn alloc_n4mb_seid(&self) -> u64 {
        self.next_n4mb_seid.fetch_add(1, Ordering::SeqCst) as u64
    }

    /// Allocate a new multicast GTP-U TEID
    pub fn alloc_mcast_teid(&self) -> u32 {
        self.next_mcast_teid.fetch_add(1, Ordering::SeqCst)
    }

    // Session management

    pub fn session_add(&self, tmgi: Tmgi, session_type: MbsSessionType) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if session_list.len() >= self.max_sessions {
            log::error!(
                "Maximum number of MBS sessions [{}] reached",
                self.max_sessions
            );
            return None;
        }

        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut session = MbsSession::new(id, tmgi.clone(), session_type);
        // Allocate a multicast TEID for this session
        session.gtp_teid = self.alloc_mcast_teid();

        tmgi_hash.insert(tmgi, id);
        session_list.insert(id, session.clone());

        log::info!(
            "MBS session added (id={id}, type={session_type:?}, teid={:#x})",
            session.gtp_teid
        );
        Some(session)
    }

    pub fn session_remove(&self, id: u64) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if let Some(session) = session_list.remove(&id) {
            tmgi_hash.remove(&session.tmgi);
            if let Some(ref n4mb) = session.n4mb_session {
                log::info!(
                    "MBS session removed (id={id}) - releasing N4mb SEID {}",
                    n4mb.local_seid
                );
            } else {
                log::info!("MBS session removed (id={id})");
            }
            return Some(session);
        }
        None
    }

    pub fn session_remove_all(&self) {
        if let (Ok(mut session_list), Ok(mut tmgi_hash)) =
            (self.session_list.write(), self.tmgi_hash.write())
        {
            session_list.clear();
            tmgi_hash.clear();
        }
    }

    pub fn session_find_by_tmgi(&self, tmgi: &Tmgi) -> Option<MbsSession> {
        // Lock order session_list < tmgi_hash (matches session_add/session_remove).
        // Taking tmgi_hash before session_list would be an AB-BA deadlock vs
        // session_add (which holds session_list while acquiring tmgi_hash).
        let session_list = self.session_list.read().ok()?;
        let tmgi_hash = self.tmgi_hash.read().ok()?;
        tmgi_hash
            .get(tmgi)
            .and_then(|&id| session_list.get(&id).cloned())
    }

    pub fn session_find_by_id(&self, id: u64) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list.get(&id).cloned()
    }

    pub fn session_update(&self, session: &MbsSession) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(existing) = session_list.get_mut(&session.id) {
                *existing = session.clone();
                return true;
            }
        }
        false
    }

    pub fn session_count(&self) -> usize {
        self.session_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Activate a session with N4mb PFCP establishment to UPF
    pub fn session_activate_n4mb(&self, session_id: u64, upf_addr: Ipv4Addr) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let session = session_list.get_mut(&session_id)?;

        let local_seid = self.alloc_n4mb_seid();
        let n4mb = build_n4mb_session_establishment(session, local_seid, upf_addr);

        session.n4mb_session = Some(n4mb);
        session.state = MbsSessionState::Active;
        session.transport_address = Some(upf_addr.to_string());

        log::info!(
            "MBS session {session_id} activated with N4mb to UPF {upf_addr} (seid={local_seid})"
        );
        Some(session.clone())
    }

    /// Join a UE to an MBS session group
    pub fn session_member_join(&self, session_id: u64, supi: &str) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(session) = session_list.get_mut(&session_id) {
                return session.member_join(supi);
            }
        }
        false
    }

    /// Remove a UE from an MBS session group
    pub fn session_member_leave(&self, session_id: u64, supi: &str) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(session) = session_list.get_mut(&session_id) {
                return session.member_leave(supi);
            }
        }
        false
    }

    /// Get all sessions (for listing)
    pub fn all_sessions(&self) -> Vec<MbsSession> {
        self.session_list
            .read()
            .map(|l| l.values().cloned().collect())
            .expect("value expected")
    }

    /// Get active multicast sessions
    pub fn active_multicast_sessions(&self) -> Vec<MbsSession> {
        self.session_list
            .read()
            .map(|l| {
                l.values()
                    .filter(|s| {
                        s.state == MbsSessionState::Active
                            && s.session_type == MbsSessionType::Multicast
                    })
                    .cloned()
                    .collect()
            })
            .expect("value expected")
    }

    // ---- mbsmfd-04: Nmbsmf_TMGI operations ----

    /// Allocate `count` fresh TMGIs in `plmn` (TS 29.532 §5.2.2.2). Returns the
    /// allocated TMGIs and the common expiry (Unix seconds).
    pub fn tmgi_allocate(&self, plmn: &PlmnId, count: u32, ttl_secs: u64) -> (Vec<Tmgi>, u64) {
        let now = now_unix();
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.purge_expired(now);
        pool.allocate(plmn, count, ttl_secs, now)
    }

    /// Refresh the supplied TMGIs' expiry (TS 29.532 §5.2.2.2). Returns the new
    /// common expiry (Unix seconds).
    pub fn tmgi_refresh(&self, tmgis: &[Tmgi], ttl_secs: u64) -> u64 {
        let now = now_unix();
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.purge_expired(now);
        pool.refresh(tmgis, ttl_secs, now)
    }

    /// Deallocate specific TMGIs (TS 29.532 §5.2.2.3); returns how many existed.
    pub fn tmgi_deallocate(&self, tmgis: &[Tmgi]) -> usize {
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.deallocate(tmgis)
    }

    /// Deallocate all TMGIs (TS 29.532 §5.2.2.3); returns how many were freed.
    pub fn tmgi_deallocate_all(&self) -> usize {
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.deallocate_all()
    }

    /// Number of currently-allocated TMGIs.
    pub fn tmgi_count(&self) -> usize {
        self.tmgi_pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Expiry (Unix seconds) of a specific allocated TMGI, if present.
    pub fn tmgi_expiry_of(&self, tmgi: &Tmgi) -> Option<u64> {
        self.tmgi_pool.lock().ok().and_then(|p| p.expiry_of(tmgi))
    }

    // ---- mbsmfd-05: Status / ContextStatus subscription CRUD ----

    /// Add a Status subscription (NEF/MBSF/AF-facing). Returns the new ID.
    pub fn status_sub_add(&self, entry: SubEntry) -> Option<String> {
        self.status_subs.lock().ok().map(|mut s| s.add(entry))
    }

    /// Update a Status subscription (PUT). Returns false if not found.
    pub fn status_sub_update(&self, id: &str, entry: SubEntry) -> bool {
        self.status_subs
            .lock()
            .ok()
            .map(|mut s| s.update(id, entry))
            .unwrap_or(false)
    }

    /// Remove a Status subscription (DELETE). Returns false if not found.
    pub fn status_sub_remove(&self, id: &str) -> bool {
        self.status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect Status subscriptions that match `event` (for notify fan-out).
    pub fn status_subs_matching(&self, event: &MbsEvent) -> Vec<SubEntry> {
        self.status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event))
            .unwrap_or_default()
    }

    /// Number of active Status subscriptions.
    pub fn status_sub_count(&self) -> usize {
        self.status_subs.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Add a ContextStatus subscription (SMF-facing). Returns the new ID.
    pub fn ctx_sub_add(&self, entry: SubEntry) -> Option<String> {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.add(entry))
    }

    /// Update a ContextStatus subscription (PUT). Returns false if not found.
    pub fn ctx_sub_update(&self, id: &str, entry: SubEntry) -> bool {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.update(id, entry))
            .unwrap_or(false)
    }

    /// Remove a ContextStatus subscription (DELETE). Returns false if not found.
    pub fn ctx_sub_remove(&self, id: &str) -> bool {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect ContextStatus subscriptions that match `event`.
    pub fn ctx_subs_matching(&self, event: &MbsEvent) -> Vec<SubEntry> {
        self.context_status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event))
            .unwrap_or_default()
    }

    /// Number of active ContextStatus subscriptions.
    pub fn ctx_sub_count(&self) -> usize {
        self.context_status_subs.lock().map(|s| s.len()).unwrap_or(0)
    }

    // ---- mbsmfd-03: ContextUpdate Start / Terminate ----

    /// ContextUpdate **Start** (SMF, multicast): resolve the MBS session by TMGI,
    /// ensure an N4mb session is allocated (cTeid + llSsm + PDR/FAR), mark it
    /// establishment-pending and the MBS session Active. Returns the resolved
    /// session snapshot (carrying the freshly allocated N4mb context), or `None`
    /// when no session matches the TMGI.
    pub fn session_context_start(&self, tmgi: &Tmgi, upf_addr: Ipv4Addr) -> Option<MbsSession> {
        let id = {
            let tmgi_hash = self.tmgi_hash.read().ok()?;
            *tmgi_hash.get(tmgi)?
        };
        self.session_activate_n4mb(id, upf_addr)
    }

    /// ContextUpdate **Terminate** (SMF) / leave: resolve the MBS session by
    /// TMGI and release its N4mb multicast transport (drives the N4mb release
    /// path). Returns whether a session matched.
    pub fn session_context_terminate(&self, tmgi: &Tmgi) -> bool {
        let id = {
            match self.tmgi_hash.read() {
                Ok(h) => match h.get(tmgi) {
                    Some(&id) => id,
                    None => return false,
                },
                Err(_) => return false,
            }
        };
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&id) {
                if let Some(n4mb) = session.n4mb_session.as_mut() {
                    n4mb.state = N4mbSessionState::ReleasePending;
                }
                session.n4mb_session = None;
                session.state = MbsSessionState::Suspended;
                return true;
            }
        }
        false
    }

    /// Apply a successful N4mb Session Establishment Response to the stored
    /// session, transitioning its N4mb context to `Established`. [mbsmfd-02]
    pub fn apply_n4mb_response(
        &self,
        session_id: u64,
        remote_seid: u64,
        dl_teid: u32,
        transport_addr: Ipv4Addr,
    ) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&session_id) {
                if let Some(n4mb) = session.n4mb_session.as_mut() {
                    process_n4mb_establishment_response(n4mb, remote_seid, dl_teid, transport_addr);
                    return true;
                }
            }
        }
        false
    }
}

impl Default for MbSmfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global MB-SMF context (thread-safe singleton)
static GLOBAL_MBSMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<MbSmfContext>>> =
    std::sync::OnceLock::new();

/// Get the global MB-SMF context
pub fn mbsmf_self() -> Arc<RwLock<MbSmfContext>> {
    GLOBAL_MBSMF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(MbSmfContext::new())))
        .clone()
}

/// Initialize the global MB-SMF context
pub fn mbsmf_context_init(max_sessions: usize) {
    let ctx = mbsmf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_sessions);
    };
}

/// Finalize the global MB-SMF context
pub fn mbsmf_context_final() {
    let ctx = mbsmf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tmgi(id: u8) -> Tmgi {
        Tmgi {
            mbs_service_id: [id, 0x00, 0x00],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        }
    }

    #[test]
    fn test_mbsmf_context_new() {
        let ctx = MbSmfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_mbsmf_context_init_fini() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_session_add_remove() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let tmgi = Tmgi {
            mbs_service_id: [0x01, 0x02, 0x03],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };

        let session = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        assert_eq!(session.session_type, MbsSessionType::Multicast);
        assert_eq!(session.state, MbsSessionState::Created);
        assert_ne!(session.gtp_teid, 0); // TEID should be allocated
        assert_eq!(ctx.session_count(), 1);

        let found = ctx.session_find_by_tmgi(&tmgi);
        assert!(found.is_some());

        ctx.session_remove(session.id);
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_session_update_state() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let tmgi = Tmgi {
            mbs_service_id: [0x0A, 0x0B, 0x0C],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };

        let mut session = ctx.session_add(tmgi, MbsSessionType::Broadcast).unwrap();
        session.state = MbsSessionState::Active;
        session.joined_ue_count = 5;
        ctx.session_update(&session);

        let found = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(found.state, MbsSessionState::Active);
        assert_eq!(found.joined_ue_count, 5);
    }

    #[test]
    fn test_active_multicast_sessions() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let mut s1 = ctx
            .session_add(make_tmgi(0x01), MbsSessionType::Multicast)
            .unwrap();
        s1.state = MbsSessionState::Active;
        ctx.session_update(&s1);

        let s2 = ctx
            .session_add(make_tmgi(0x02), MbsSessionType::Broadcast)
            .unwrap();

        let active = ctx.active_multicast_sessions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, s1.id);
        let _ = s2;
    }

    #[test]
    fn test_n4mb_session_activation() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let session = ctx
            .session_add(make_tmgi(0x10), MbsSessionType::Multicast)
            .unwrap();
        assert!(session.n4mb_session.is_none());

        let activated = ctx
            .session_activate_n4mb(session.id, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();
        assert_eq!(activated.state, MbsSessionState::Active);
        let n4mb = activated.n4mb_session.unwrap();
        assert_eq!(n4mb.upf_addr, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(n4mb.state, N4mbSessionState::EstablishmentPending);
        assert_ne!(n4mb.mcast_pdr_id, 0);
        assert_ne!(n4mb.mcast_far_id, 0);
    }

    #[test]
    fn test_n4mb_establishment_response() {
        let session = MbsSession::new(1, make_tmgi(0x20), MbsSessionType::Multicast);
        let mut n4mb = N4mbSession::new(0x100, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(n4mb.state, N4mbSessionState::Idle);

        process_n4mb_establishment_response(
            &mut n4mb,
            0x200,
            0xABCD_0001,
            Ipv4Addr::new(10, 0, 0, 7),
        );

        assert_eq!(n4mb.state, N4mbSessionState::Established);
        assert_eq!(n4mb.remote_seid, 0x200);
        assert_eq!(n4mb.dl_teid, 0xABCD_0001);
        assert_eq!(n4mb.transport_addr, Some(Ipv4Addr::new(10, 0, 0, 7)));
        let _ = session;
    }

    #[test]
    fn test_group_membership_join_leave() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let session = ctx
            .session_add(make_tmgi(0x30), MbsSessionType::Multicast)
            .unwrap();

        // Join
        assert!(ctx.session_member_join(session.id, "imsi-001010000000001"));
        assert!(ctx.session_member_join(session.id, "imsi-001010000000002"));
        // Duplicate join returns false
        assert!(!ctx.session_member_join(session.id, "imsi-001010000000001"));

        let s = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(s.joined_ue_count, 2);
        assert!(s.is_member("imsi-001010000000001"));

        // Leave
        assert!(ctx.session_member_leave(session.id, "imsi-001010000000001"));
        let s = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(s.joined_ue_count, 1);
        assert!(!s.is_member("imsi-001010000000001"));

        // Leave non-member returns false
        assert!(!ctx.session_member_leave(session.id, "imsi-001010000000099"));
    }

    #[test]
    fn test_all_sessions() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        ctx.session_add(make_tmgi(0x01), MbsSessionType::Multicast);
        ctx.session_add(make_tmgi(0x02), MbsSessionType::Broadcast);

        let all = ctx.all_sessions();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_teid_allocation_unique() {
        let ctx = MbSmfContext::new();
        let t1 = ctx.alloc_mcast_teid();
        let t2 = ctx.alloc_mcast_teid();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_n4mb_seid_allocation_unique() {
        let ctx = MbSmfContext::new();
        let s1 = ctx.alloc_n4mb_seid();
        let s2 = ctx.alloc_n4mb_seid();
        assert_ne!(s1, s2);
    }

    // ---- mbsmfd-04: TMGI pool ----

    fn plmn() -> PlmnId {
        PlmnId {
            mcc: "001".to_string(),
            mnc: "01".to_string(),
        }
    }

    #[test]
    fn test_tmgi_allocate_distinct_and_expiry() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, expiry) = ctx.tmgi_allocate(&plmn(), 3, TMGI_DEFAULT_TTL_SECS);
        assert_eq!(tmgis.len(), 3);
        // All three are distinct service ids.
        let mut ids: Vec<[u8; 3]> = tmgis.iter().map(|t| t.mbs_service_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3);
        assert!(expiry > now_unix());
        assert_eq!(ctx.tmgi_count(), 3);
    }

    #[test]
    fn test_tmgi_refresh_extends_expiry() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, first) = ctx.tmgi_allocate(&plmn(), 1, 1);
        let before = ctx.tmgi_expiry_of(&tmgis[0]).unwrap();
        assert_eq!(before, first);
        // Refresh with a longer TTL extends the recorded expiry.
        let extended = ctx.tmgi_refresh(&tmgis, TMGI_DEFAULT_TTL_SECS);
        assert!(extended >= before);
        assert_eq!(ctx.tmgi_expiry_of(&tmgis[0]), Some(extended));
        assert_eq!(ctx.tmgi_count(), 1);
    }

    #[test]
    fn test_tmgi_deallocate_one_and_all() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, _) = ctx.tmgi_allocate(&plmn(), 3, TMGI_DEFAULT_TTL_SECS);
        // Deallocate exactly one leaves the rest.
        assert_eq!(ctx.tmgi_deallocate(std::slice::from_ref(&tmgis[0])), 1);
        assert_eq!(ctx.tmgi_count(), 2);
        // Deallocate-all empties the pool.
        assert_eq!(ctx.tmgi_deallocate_all(), 2);
        assert_eq!(ctx.tmgi_count(), 0);
    }

    // ---- mbsmfd-03: ContextUpdate Start / Terminate ----

    #[test]
    fn test_context_start_allocates_cteid_and_llssm() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x42);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();

        let upf = Ipv4Addr::new(10, 0, 0, 7);
        let started = ctx.session_context_start(&tmgi, upf).expect("started");
        assert_eq!(started.id, created.id);
        assert_eq!(started.state, MbsSessionState::Active);
        let n4mb = started.n4mb_session.expect("n4mb allocated");
        assert_eq!(n4mb.state, N4mbSessionState::EstablishmentPending);
        // cTeid is the allocated DL multicast TEID; llSsm carries src+dst.
        assert_ne!(n4mb.dl_teid, 0);
        assert_eq!(n4mb.ll_ssm_src, Some(upf));
        assert_eq!(n4mb.ll_ssm_dst, Some(mcast_group_for(created.id)));
    }

    #[test]
    fn test_context_start_unknown_tmgi_is_none() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        assert!(ctx
            .session_context_start(&make_tmgi(0x99), Ipv4Addr::new(10, 0, 0, 7))
            .is_none());
    }

    #[test]
    fn test_context_terminate_releases_n4mb() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x43);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        ctx.session_context_start(&tmgi, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();

        assert!(ctx.session_context_terminate(&tmgi));
        let after = ctx.session_find_by_id(created.id).unwrap();
        assert!(after.n4mb_session.is_none());
        assert_eq!(after.state, MbsSessionState::Suspended);

        // Terminating an unknown TMGI is a no-op.
        assert!(!ctx.session_context_terminate(&make_tmgi(0x77)));
    }

    #[test]
    fn test_apply_n4mb_response_marks_established() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x44);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        ctx.session_context_start(&tmgi, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();

        assert!(ctx.apply_n4mb_response(
            created.id,
            0x9999,
            0xABCD_0001,
            Ipv4Addr::new(10, 0, 0, 7)
        ));
        let n4mb = ctx
            .session_find_by_id(created.id)
            .unwrap()
            .n4mb_session
            .unwrap();
        assert_eq!(n4mb.state, N4mbSessionState::Established);
        assert_eq!(n4mb.remote_seid, 0x9999);
    }

    #[test]
    fn test_unix_to_rfc3339_known_epoch() {
        // 1970-01-01T00:00:00Z and a known later instant.
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z == 1609459200.
        assert_eq!(unix_to_rfc3339(1_609_459_200), "2021-01-01T00:00:00Z");
    }
}
