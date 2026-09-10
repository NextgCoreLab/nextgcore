//! MB-SMF Context Management
//!
//! Multicast/Broadcast Session Management Function context (TS 23.247)
//! Includes N4mb PFCP session management for multicast transport

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::subscription::{SubEntry, SubscriptionStore};
use crate::types::PatchItem;

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
    /// The SSM the consumer identified this session with, when it used one (#76).
    ///
    /// Distinct from `n4mb_session.ll_ssm_src`/`ll_ssm_dst`, which are the
    /// lower-layer SSM the MB-SMF *allocates* toward NG-RAN. This is the
    /// `MbsSessionId.ssm` the consumer supplied, and it is what an SSM-identified
    /// ContextUpdate has to be resolved by.
    ///
    /// Held as the wire type (`crate::types::Ssm`) rather than parsed into
    /// `std::net::IpAddr`: TS 29.571's `IpAddr` is a choice of two OPTIONAL textual
    /// members, so "the address the consumer sent" and "an address" are not the same
    /// thing, and matching on the received form is what makes a lookup agree with
    /// what was stored.
    pub ssm: Option<crate::types::Ssm>,
    /// The NF consumers (`ContextUpdateReqData.nfcInstanceId`) currently receiving on
    /// this session's shared N4mb transport (#295, TS 23.247 §7.2.1.3/§7.2.1.4).
    ///
    /// Distinct from [`Self::group_members`], which tracks UE SUPIs: a multicast MBS
    /// session is a SHARED distribution session established once and reused across
    /// joins, so the transport underneath it must outlive any single consumer's
    /// departure. Before this set existed, the first consumer to send a ContextUpdate
    /// TERMINATE released the MB-UPF session for every other consumer still receiving
    /// on it — and the remaining consumers' sessions looked fine (state, SBI surface
    /// and TMGI all unchanged) and simply stopped carrying data.
    ///
    /// Keyed on `nfcInstanceId` rather than counted, so a consumer that restarts and
    /// re-STARTs is not counted twice and a repeated TERMINATE cannot decrement twice.
    pub consumers: HashSet<String>,
}

/// What a consumer's ContextUpdate TERMINATE means for the shared transport (#295).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumerTerminate {
    /// No MBS session matched the TMGI.
    NotFound,
    /// Other consumers are still receiving: the transport stays up. Carries who they
    /// are, because nothing else in the system can name them.
    ConsumerRemains { remaining: Vec<String> },
    /// The set is now empty: this was the last consumer, so the transport is released.
    LastConsumer,
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
            ssm: None,
            consumers: HashSet::new(),
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

        // #76: a duplicate TMGI used to overwrite `tmgi_hash` silently, so the
        // earlier session stayed in `session_list` reachable by NOTHING — its TMGI
        // resolved to the new session, and its N4mb session on the MB-UPF could
        // never be released. Refusing is the honest answer: a TMGI identifies one
        // MBS session, so a second create for the same one is the consumer's error,
        // and the existing session is still there to be found or deleted.
        if tmgi_hash.contains_key(&tmgi) {
            log::warn!(
                "MBS session create refused: TMGI {tmgi:?} already identifies session {:?}",
                tmgi_hash.get(&tmgi)
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

    /// Remove a session's LOCAL state.
    ///
    /// #76: this used to be the whole of DELETE, and its log line said "releasing
    /// N4mb SEID" while releasing nothing — no PFCP Session Deletion Request was
    /// ever sent, so every released MBS session leaked an N4mb session on the
    /// MB-UPF. The wire release is the caller's job (it needs an `await`), which is
    /// why the removed session — carrying its `n4mb_session` — is returned. Callers
    /// must use [`Self::session_mark_release_pending`] first and remove only after
    /// the Session Deletion Response.
    pub fn session_remove(&self, id: u64) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if let Some(session) = session_list.remove(&id) {
            tmgi_hash.remove(&session.tmgi);
            log::info!("MBS session local state removed (id={id})");
            return Some(session);
        }
        None
    }

    /// Mark a session's N4mb context `ReleasePending` and return the remote SEID to
    /// address the Session Deletion Request to (#76).
    ///
    /// Two steps rather than one because the deletion is an `await` and the context
    /// is behind a `std` lock: the state transition happens under the lock, the wire
    /// exchange outside it, and the local removal only after the response. The
    /// remote SEID is what the request must be addressed to (TS 29.244 §7.5.4) —
    /// the LOCAL seid would address a session the UP does not know.
    pub fn session_mark_release_pending(&self, id: u64) -> Option<u64> {
        let mut session_list = self.session_list.write().ok()?;
        let session = session_list.get_mut(&id)?;
        let n4mb = session.n4mb_session.as_mut()?;
        n4mb.state = N4mbSessionState::ReleasePending;
        // A session whose establishment never completed has no UP-allocated SEID,
        // so there is nothing on the UP to delete. `None` says so, distinctly from
        // "no N4mb context at all".
        (n4mb.remote_seid != 0).then_some(n4mb.remote_seid)
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

    /// Activate a session with N4mb PFCP establishment to UPF.
    ///
    /// **Idempotent (#76).** An N4mb session that is already `Established` is
    /// returned unchanged rather than replaced. It used to allocate a fresh
    /// `local_seid` and overwrite `n4mb_session` on every call, so N repeated
    /// joins/STARTs created N PFCP sessions on the MB-UPF and orphaned every
    /// previous one — contrary to the shared-distribution-session model of TS 23.247
    /// §7.2.1.3/§7.2.1.4, where one MB-UPF session is established once and reused
    /// across joins. Under multicast churn that leaked a UPF session per join.
    ///
    /// An `EstablishmentPending` session is NOT short-circuited: its establishment
    /// may have failed, and re-driving it is how a retry works. Only a session the
    /// UP has confirmed is reused.
    pub fn session_activate_n4mb(&self, session_id: u64, upf_addr: Ipv4Addr) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let session = session_list.get_mut(&session_id)?;

        if let Some(existing) = session.n4mb_session.as_ref() {
            if existing.state == N4mbSessionState::Established {
                log::debug!(
                    "MBS session {session_id} already has an established N4mb session \
                     (seid={}); reusing it rather than allocating a second",
                    existing.local_seid
                );
                return Some(session.clone());
            }
        }

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

    /// Find a session by the SSM the consumer identified it with (#76).
    ///
    /// A linear scan rather than a second index. Sessions are capped at
    /// `max_sessions` and ContextUpdate is not a per-packet path, so the cost is
    /// irrelevant — while a second index over the same sessions would be a second
    /// set of invariants to keep in step with `session_add`/`session_remove`, which
    /// is exactly the class of bug the duplicate-TMGI overwrite was.
    pub fn session_find_by_ssm(&self, ssm: &crate::types::Ssm) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list
            .values()
            .find(|s| s.ssm.as_ref() == Some(ssm))
            .cloned()
    }

    /// Find a session by the LOCAL N4mb SEID (#76).
    ///
    /// The MB-UPF addresses a Session Report to the CP F-SEID it was given at
    /// establishment, i.e. to our `local_seid` — not to the SEID it allocated
    /// itself. Looking up by `remote_seid` would find nothing for every report.
    pub fn session_find_by_local_seid(&self, seid: u64) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list
            .values()
            .find(|s| {
                s.n4mb_session
                    .as_ref()
                    .is_some_and(|n| n.local_seid == seid)
            })
            .cloned()
    }

    /// Activate a session on downlink data arrival (TS 23.247 §7.2.5.2), #76.
    ///
    /// Returns whether the state actually CHANGED. A session already `Active` is
    /// left alone and reports `false`, so the caller can distinguish "traffic
    /// reactivated a deactivated session" — the event that matters — from a report
    /// about a session that was never deactivated. Answering `true` unconditionally
    /// would make the log say a session was reactivated every time a packet arrived.
    pub fn session_activate_on_downlink_data(&self, session_id: u64) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&session_id) {
                if session.state != MbsSessionState::Active {
                    session.state = MbsSessionState::Active;
                    return true;
                }
            }
        }
        false
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

    /// Apply a JSON Patch (RFC 6902 subset) to a Status subscription.
    /// Returns the modified bare document, or None if not found.
    pub fn status_sub_patch(&self, id: &str, ops: &[PatchItem]) -> Option<serde_json::Value> {
        self.status_subs
            .lock()
            .ok()
            .and_then(|mut s| s.patch(id, ops))
    }

    /// Remove a Status subscription (DELETE). Returns false if not found.
    pub fn status_sub_remove(&self, id: &str) -> bool {
        self.status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect Status subscriptions that match `event_type` and `session` key
    /// (for notify fan-out).
    pub fn status_subs_matching(
        &self,
        event_type: &str,
        session: &Option<serde_json::Value>,
    ) -> Vec<SubEntry> {
        self.status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event_type, session))
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

    /// Apply a JSON Patch (RFC 6902 subset) to a ContextStatus subscription.
    /// Returns the modified bare document, or None if not found.
    pub fn ctx_sub_patch(&self, id: &str, ops: &[PatchItem]) -> Option<serde_json::Value> {
        self.context_status_subs
            .lock()
            .ok()
            .and_then(|mut s| s.patch(id, ops))
    }

    /// Remove a ContextStatus subscription (DELETE). Returns false if not found.
    pub fn ctx_sub_remove(&self, id: &str) -> bool {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect ContextStatus subscriptions that match `event_type` and `session` key.
    pub fn ctx_subs_matching(
        &self,
        event_type: &str,
        session: &Option<serde_json::Value>,
    ) -> Vec<SubEntry> {
        self.context_status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event_type, session))
            .unwrap_or_default()
    }

    /// Number of active ContextStatus subscriptions.
    pub fn ctx_sub_count(&self) -> usize {
        self.context_status_subs
            .lock()
            .map(|s| s.len())
            .unwrap_or(0)
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

    /// Register a consumer NF on a session's shared transport (#295).
    ///
    /// Returns the consumer count after the insert, or `None` when no session matches
    /// the TMGI. Idempotent: a consumer that restarts and re-STARTs the same session is
    /// the same entry, which is what keying the set on `nfcInstanceId` buys.
    ///
    /// **Where the count starts, and why this leg.** #295 asks whether a ContextUpdate
    /// START implicitly registers `nfcInstanceId` as a consumer. It does: nothing else
    /// in the tree registers one, TS 23.247 §7.2.1.3 models the START as the establish
    /// side of a shared session, and this makes the count derivable from traffic the
    /// MB-SMF already sees rather than from a member the schema does not have. The
    /// alternative — counting only an explicit `leaveInd` join/leave — would leave the
    /// shared-transport hazard on exactly the `leaveInd == false` path that carries
    /// most of the traffic.
    pub fn session_consumer_register(&self, tmgi: &Tmgi, nfc_instance_id: &str) -> Option<usize> {
        if nfc_instance_id.is_empty() {
            return None;
        }
        let id = {
            let tmgi_hash = self.tmgi_hash.read().ok()?;
            *tmgi_hash.get(tmgi)?
        };
        let mut list = self.session_list.write().ok()?;
        let session = list.get_mut(&id)?;
        let fresh = session.consumers.insert(nfc_instance_id.to_string());
        let count = session.consumers.len();
        if fresh {
            log::info!(
                "[MBS] consumer {nfc_instance_id} registered on session {id} \
                 (TMGI {:02x?}); {count} consumer(s) now hold its shared transport",
                tmgi.mbs_service_id
            );
        }
        Some(count)
    }

    /// ContextUpdate **Terminate** from one consumer (#295): deregister it and say
    /// whether the shared transport may now be released.
    ///
    /// The transport is released only when the set becomes EMPTY. A consumer this
    /// session does not hold does not decrement anything, so a repeated TERMINATE
    /// cannot release a transport another consumer still holds.
    ///
    /// A session with no registered consumers at all yields [`ConsumerTerminate::
    /// LastConsumer`], which is deliberately the pre-#295 behaviour: sessions created
    /// before any START, and every existing single-consumer flow, must keep releasing
    /// on the first TERMINATE.
    pub fn session_context_terminate_for(
        &self,
        tmgi: &Tmgi,
        nfc_instance_id: &str,
    ) -> ConsumerTerminate {
        let id = {
            match self.tmgi_hash.read() {
                Ok(h) => match h.get(tmgi) {
                    Some(&id) => id,
                    None => return ConsumerTerminate::NotFound,
                },
                Err(_) => return ConsumerTerminate::NotFound,
            }
        };
        let remaining = {
            let Ok(mut list) = self.session_list.write() else {
                return ConsumerTerminate::NotFound;
            };
            let Some(session) = list.get_mut(&id) else {
                return ConsumerTerminate::NotFound;
            };
            if !nfc_instance_id.is_empty() {
                session.consumers.remove(nfc_instance_id);
            }
            let mut remaining: Vec<String> = session.consumers.iter().cloned().collect();
            // Sorted so a log line and a test assertion are both deterministic over a
            // HashSet.
            remaining.sort();
            remaining
        };
        if !remaining.is_empty() {
            return ConsumerTerminate::ConsumerRemains { remaining };
        }
        // Last consumer: mark the transport for release exactly as the unconditional
        // path does, so the two agree about what "terminating" means locally.
        if self.session_context_terminate(tmgi) {
            ConsumerTerminate::LastConsumer
        } else {
            ConsumerTerminate::NotFound
        }
    }

    /// ContextUpdate **Terminate** (SMF) / leave: resolve the MBS session by
    /// TMGI and release its N4mb multicast transport (drives the N4mb release
    /// path). Returns whether a session matched.
    ///
    /// Unconditional — it does not consult the consumer set (#295). Kept for the N2
    /// (AMF) release leg, whose `nfcInstanceId` is the AMF's and therefore not a member
    /// of the consumer set the SMF STARTs populate; see the spec's ceiling on the
    /// per-RAN-node dimension.
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
                // #76: this used to set ReleasePending and then IMMEDIATELY zero
                // `n4mb_session`, so the SEID needed to delete the session on the
                // MB-UPF was discarded before anything could send the deletion. The
                // context is now left in place for the caller to release on the
                // wire and clear afterwards (`session_clear_n4mb`).
                if let Some(n4mb) = session.n4mb_session.as_mut() {
                    n4mb.state = N4mbSessionState::ReleasePending;
                }
                session.state = MbsSessionState::Suspended;
                return true;
            }
        }
        false
    }

    /// Clear a session's N4mb context after its Session Deletion completed (#76).
    ///
    /// Separate from [`Self::session_context_terminate`] so the SEID survives long
    /// enough to be used. Returns whether a context was cleared, so a caller can
    /// tell "released and cleared" from "there was nothing to release".
    pub fn session_clear_n4mb(&self, id: u64) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&id) {
                let had = session.n4mb_session.is_some();
                session.n4mb_session = None;
                return had;
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

    /// **Assertion inverted by #76, and why.** This used to assert that
    /// `session_context_terminate` leaves `n4mb_session` as `None`. That was pinning
    /// the defect as the requirement: zeroing the context discards the remote SEID a
    /// PFCP Session Deletion Request has to be addressed to, so nothing could delete
    /// the session on the MB-UPF even in principle, and every terminate leaked one.
    ///
    /// The governing clause is not a "may": TS 29.244 §7.5.4 has the CP function
    /// **send** a Session Deletion Request to release a PFCP session, and TS 23.247
    /// §7.1.1.4 has releasing an MBS session tear down the associated MB-UPF
    /// resources. So the old assertion was asserting a shortcut past a mandatory
    /// message, and inverting it is legitimate.
    ///
    /// Terminate now marks the context `ReleasePending` and LEAVES it; the wire
    /// release plus the clear is `release_n4mb_transport` in `main.rs`, and the two
    /// handler-level tests that assert the post-handler state
    /// (`test_router_context_update_amf_release_golden_204`,
    /// `mbs_context_update_strict_peer_release_204`) still pass unchanged — which is
    /// what shows the observable behaviour of the SERVICE is preserved and only this
    /// function's own contract narrowed.
    #[test]
    fn test_context_terminate_marks_release_pending_without_discarding_the_seid() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x43);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        ctx.session_context_start(&tmgi, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();
        // Pretend the UP answered, so there is a remote SEID to delete.
        assert!(ctx.apply_n4mb_response(
            created.id,
            0xdead_beef,
            0x1234,
            Ipv4Addr::new(10, 0, 0, 7)
        ));

        assert!(ctx.session_context_terminate(&tmgi));
        let after = ctx.session_find_by_id(created.id).unwrap();
        let n4mb = after.n4mb_session.as_ref().expect(
            "the N4mb context must SURVIVE terminate: its remote SEID is what the \
                     Session Deletion Request is addressed to",
        );
        assert_eq!(n4mb.state, N4mbSessionState::ReleasePending);
        assert_eq!(n4mb.remote_seid, 0xdead_beef);
        assert_eq!(after.state, MbsSessionState::Suspended);

        // The two-step is what the release driver uses: mark, then delete, then clear.
        assert_eq!(
            ctx.session_mark_release_pending(created.id),
            Some(0xdead_beef),
            "the remote SEID must be recoverable for the deletion request"
        );
        assert!(ctx.session_clear_n4mb(created.id));
        assert!(ctx
            .session_find_by_id(created.id)
            .unwrap()
            .n4mb_session
            .is_none());
        assert!(
            !ctx.session_clear_n4mb(created.id),
            "clearing twice must report that there was nothing left to clear"
        );

        // Terminating an unknown TMGI is a no-op.
        assert!(!ctx.session_context_terminate(&make_tmgi(0x77)));
    }

    /// #76 criterion 5: a repeated START must not allocate a second N4mb session.
    ///
    /// N repeated joins used to create N PFCP sessions on the MB-UPF and orphan
    /// every previous one, contrary to the shared-distribution-session model of TS
    /// 23.247 §7.2.1.3/§7.2.1.4. An `EstablishmentPending` session is deliberately
    /// NOT short-circuited: its establishment may have failed, and re-driving it is
    /// how a retry works.
    #[test]
    fn a_repeated_start_reuses_an_established_n4mb_session() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x51);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        let upf = Ipv4Addr::new(10, 0, 0, 7);

        let first = ctx.session_context_start(&tmgi, upf).unwrap();
        let first_seid = first.n4mb_session.as_ref().unwrap().local_seid;
        // Not yet established: a second START re-drives it, which is the retry path.
        let retry = ctx.session_context_start(&tmgi, upf).unwrap();
        assert_ne!(
            retry.n4mb_session.as_ref().unwrap().local_seid,
            first_seid,
            "an establishment that never completed must be re-drivable"
        );
        let retry_seid = retry.n4mb_session.as_ref().unwrap().local_seid;

        // Now the UP confirms it. Every later START must reuse this one.
        assert!(ctx.apply_n4mb_response(created.id, 0x99, 0x1234, upf));
        for _ in 0..3 {
            let again = ctx.session_context_start(&tmgi, upf).unwrap();
            let n4mb = again.n4mb_session.as_ref().unwrap();
            assert_eq!(
                n4mb.local_seid, retry_seid,
                "a repeated START must not allocate a new SEID for an established session"
            );
            assert_eq!(n4mb.remote_seid, 0x99, "nor discard the UP-allocated one");
            assert_eq!(n4mb.state, N4mbSessionState::Established);
        }
    }

    /// #76 criterion 7: a second create for a TMGI already in use is refused rather
    /// than silently orphaning the first session.
    ///
    /// The overwrite used to leave the earlier session in `session_list` reachable
    /// by NOTHING — its TMGI resolved to the new session, so it could never be found
    /// or deleted, and its MB-UPF session could never be released.
    #[test]
    fn a_duplicate_tmgi_create_is_refused_and_the_first_session_survives() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x61);
        let first = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .expect("the first create succeeds");
        assert!(
            ctx.session_add(tmgi.clone(), MbsSessionType::Multicast)
                .is_none(),
            "a TMGI identifies one MBS session; a second create for it must be refused"
        );
        assert_eq!(
            ctx.session_find_by_tmgi(&tmgi).map(|s| s.id),
            Some(first.id),
            "the TMGI must still resolve to the FIRST session"
        );
        assert_eq!(ctx.session_count(), 1, "and no orphan is left behind");
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
