//! MB-SMF Context Management
//!
//! Multicast/Broadcast Session Management Function context (TS 23.247)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        }
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
}

impl MbSmfContext {
    pub fn new() -> Self {
        Self {
            session_list: RwLock::new(HashMap::new()),
            tmgi_hash: RwLock::new(HashMap::new()),
            next_session_id: AtomicUsize::new(1),
            max_sessions: 0,
            initialized: AtomicBool::new(false),
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

    // Session management

    pub fn session_add(&self, tmgi: Tmgi, session_type: MbsSessionType) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if session_list.len() >= self.max_sessions {
            log::error!("Maximum number of MBS sessions [{}] reached", self.max_sessions);
            return None;
        }

        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst) as u64;
        let session = MbsSession::new(id, tmgi.clone(), session_type);

        tmgi_hash.insert(tmgi, id);
        session_list.insert(id, session.clone());

        log::info!("MBS session added (id={id}, type={session_type:?})");
        Some(session)
    }

    pub fn session_remove(&self, id: u64) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if let Some(session) = session_list.remove(&id) {
            tmgi_hash.remove(&session.tmgi);
            log::info!("MBS session removed (id={id})");
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

        let tmgi1 = Tmgi {
            mbs_service_id: [0x01, 0x00, 0x00],
            plmn_id: PlmnId { mcc: "001".to_string(), mnc: "01".to_string() },
        };
        let tmgi2 = Tmgi {
            mbs_service_id: [0x02, 0x00, 0x00],
            plmn_id: PlmnId { mcc: "001".to_string(), mnc: "01".to_string() },
        };

        let mut s1 = ctx.session_add(tmgi1, MbsSessionType::Multicast).unwrap();
        s1.state = MbsSessionState::Active;
        ctx.session_update(&s1);

        let s2 = ctx.session_add(tmgi2, MbsSessionType::Broadcast).unwrap();
        // s2 stays Created

        let active = ctx.active_multicast_sessions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, s1.id);
        let _ = s2; // suppress unused warning
    }
}
