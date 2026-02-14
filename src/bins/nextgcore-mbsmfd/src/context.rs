//! MB-SMF Context Management
//!
//! Multicast/Broadcast Session Management Function context (TS 23.247)
//! Includes N4mb PFCP session management for multicast transport

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

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
    /// GTP-U TEID for multicast DL tunnel
    pub dl_teid: u32,
    /// Multicast transport address (UPF endpoint)
    pub transport_addr: Option<Ipv4Addr>,
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
    n4mb
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
        n4mb.local_seid, remote_seid, dl_teid, transport_addr
    );
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
            log::error!("Maximum number of MBS sessions [{}] reached", self.max_sessions);
            return None;
        }

        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut session = MbsSession::new(id, tmgi.clone(), session_type);
        // Allocate a multicast TEID for this session
        session.gtp_teid = self.alloc_mcast_teid();

        tmgi_hash.insert(tmgi, id);
        session_list.insert(id, session.clone());

        log::info!("MBS session added (id={id}, type={session_type:?}, teid={:#x})", session.gtp_teid);
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
        if let (Ok(mut session_list), Ok(mut tmgi_hash)) = (
            self.session_list.write(),
            self.tmgi_hash.write(),
        ) {
            session_list.clear();
            tmgi_hash.clear();
        }
    }

    pub fn session_find_by_tmgi(&self, tmgi: &Tmgi) -> Option<MbsSession> {
        let tmgi_hash = self.tmgi_hash.read().ok()?;
        let session_list = self.session_list.read().ok()?;
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
    pub fn session_activate_n4mb(
        &self,
        session_id: u64,
        upf_addr: Ipv4Addr,
    ) -> Option<MbsSession> {
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
            .unwrap_or_default()
    }

    /// Get active multicast sessions
    pub fn active_multicast_sessions(&self) -> Vec<MbsSession> {
        self.session_list
            .read()
            .map(|l| {
                l.values()
                    .filter(|s| s.state == MbsSessionState::Active && s.session_type == MbsSessionType::Multicast)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for MbSmfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global MB-SMF context (thread-safe singleton)
static GLOBAL_MBSMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<MbSmfContext>>> = std::sync::OnceLock::new();

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
            plmn_id: PlmnId { mcc: "001".to_string(), mnc: "01".to_string() },
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
            plmn_id: PlmnId { mcc: "001".to_string(), mnc: "01".to_string() },
        };

        let session = ctx.session_add(tmgi.clone(), MbsSessionType::Multicast).unwrap();
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
            plmn_id: PlmnId { mcc: "001".to_string(), mnc: "01".to_string() },
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

        let mut s1 = ctx.session_add(make_tmgi(0x01), MbsSessionType::Multicast).unwrap();
        s1.state = MbsSessionState::Active;
        ctx.session_update(&s1);

        let s2 = ctx.session_add(make_tmgi(0x02), MbsSessionType::Broadcast).unwrap();

        let active = ctx.active_multicast_sessions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, s1.id);
        let _ = s2;
    }

    #[test]
    fn test_n4mb_session_activation() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let session = ctx.session_add(make_tmgi(0x10), MbsSessionType::Multicast).unwrap();
        assert!(session.n4mb_session.is_none());

        let activated = ctx.session_activate_n4mb(session.id, Ipv4Addr::new(10, 0, 0, 7)).unwrap();
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

        let session = ctx.session_add(make_tmgi(0x30), MbsSessionType::Multicast).unwrap();

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
}
