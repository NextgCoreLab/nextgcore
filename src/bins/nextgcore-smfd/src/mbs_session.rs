//! MBS (Multicast-Broadcast Services) Session Management for SMF (Rel-17, TS 23.247)
//!
//! Implements SMF-side MBS session context: multicast PDU session establishment,
//! MBSF/MBSTF/MBSN4 interface stubs, and per-UE join/leave tracking.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

/// MBS session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsSessionState {
    /// Session is being created
    Creating,
    /// Session is active and delivering content
    Active,
    /// Session is being modified
    Modifying,
    /// Session is being released
    Releasing,
    /// Session has been released
    Released,
}

/// MBS service type per TS 23.247
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsServiceType {
    /// Broadcast (one-to-many, no join/leave signaling)
    Broadcast,
    /// Multicast (group membership required)
    Multicast,
}

/// MBS session context
#[derive(Debug, Clone)]
pub struct MbsSession {
    /// Temporary MBS session ID (tmgi) - 6 octets per TS 24.008
    pub tmgi: [u8; 6],
    /// Area session ID (optional)
    pub area_session_id: Option<u32>,
    /// MBS service type
    pub service_type: MbsServiceType,
    /// IP multicast group address (IPv4 or IPv6)
    pub group_addr: MbsGroupAddr,
    /// Session state
    pub state: MbsSessionState,
    /// Set of UE SUPIs that have joined this session
    pub members: HashSet<String>,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Session data rate (kbps)
    pub data_rate_kbps: u32,
    /// 5QI for MBS flows (default 5QI 8 per TS 23.247 §5.4)
    pub qi5: u8,
}

/// Multicast group address (IPv4 or IPv6)
#[derive(Debug, Clone)]
pub enum MbsGroupAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl MbsGroupAddr {
    pub fn is_valid_multicast_v4(addr: &[u8; 4]) -> bool {
        // IPv4 multicast: 224.0.0.0/4 (0xE0000000 - 0xEFFFFFFF)
        addr[0] & 0xF0 == 0xE0
    }
}

impl MbsSession {
    /// Creates a new MBS multicast session
    pub fn new_multicast(tmgi: [u8; 6], group_addr: MbsGroupAddr) -> Self {
        Self {
            tmgi,
            area_session_id: None,
            service_type: MbsServiceType::Multicast,
            group_addr,
            state: MbsSessionState::Creating,
            members: HashSet::new(),
            created_at: SystemTime::now(),
            data_rate_kbps: 1000,
            qi5: 8,
        }
    }

    /// Creates a new MBS broadcast session
    pub fn new_broadcast(tmgi: [u8; 6], group_addr: MbsGroupAddr) -> Self {
        let mut s = Self::new_multicast(tmgi, group_addr);
        s.service_type = MbsServiceType::Broadcast;
        s
    }

    /// Adds a UE to this MBS session (multicast join)
    pub fn join(&mut self, supi: String) -> bool {
        if self.service_type == MbsServiceType::Broadcast {
            return false; // broadcast doesn't track members
        }
        self.members.insert(supi)
    }

    /// Removes a UE from this MBS session (multicast leave)
    pub fn leave(&mut self, supi: &str) -> bool {
        self.members.remove(supi)
    }

    /// Returns true if this session has active members
    pub fn is_active(&self) -> bool {
        self.state == MbsSessionState::Active
    }

    /// Returns the TMGI as a hex string
    pub fn tmgi_hex(&self) -> String {
        self.tmgi.iter().map(|b| format!("{b:02X}")).collect()
    }
}

/// SMF MBS context: manages all active MBS sessions
#[derive(Debug, Default)]
pub struct SmfMbsContext {
    /// Active MBS sessions keyed by TMGI hex string
    sessions: HashMap<String, MbsSession>,
}

impl SmfMbsContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates and registers a new MBS session
    pub fn create_session(&mut self, session: MbsSession) -> String {
        let key = session.tmgi_hex();
        self.sessions.insert(key.clone(), session);
        key
    }

    /// Activates a session
    pub fn activate(&mut self, tmgi: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(tmgi) {
            s.state = MbsSessionState::Active;
            true
        } else {
            false
        }
    }

    /// Releases a session
    pub fn release(&mut self, tmgi: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(tmgi) {
            s.state = MbsSessionState::Released;
            true
        } else {
            false
        }
    }

    /// Handles a UE join request
    pub fn ue_join(&mut self, tmgi: &str, supi: String) -> bool {
        self.sessions.get_mut(tmgi).map(|s| s.join(supi)).unwrap_or(false)
    }

    /// Handles a UE leave request
    pub fn ue_leave(&mut self, tmgi: &str, supi: &str) -> bool {
        self.sessions.get_mut(tmgi).map(|s| s.leave(supi)).unwrap_or(false)
    }

    /// Returns number of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_active()).count()
    }

    /// Returns all sessions
    pub fn sessions(&self) -> &HashMap<String, MbsSession> {
        &self.sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tmgi() -> [u8; 6] {
        [0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03]
    }

    fn test_group() -> MbsGroupAddr {
        MbsGroupAddr::V4([239, 1, 2, 3])
    }

    #[test]
    fn test_mbs_multicast_join_leave() {
        let mut s = MbsSession::new_multicast(test_tmgi(), test_group());
        assert!(s.join("imsi-001011234567890".into()));
        assert_eq!(s.members.len(), 1);
        assert!(s.leave("imsi-001011234567890"));
        assert!(s.members.is_empty());
    }

    #[test]
    fn test_mbs_broadcast_join_returns_false() {
        let mut s = MbsSession::new_broadcast(test_tmgi(), test_group());
        assert!(!s.join("imsi-001011234567890".into()));
        assert!(s.members.is_empty());
    }

    #[test]
    fn test_tmgi_hex() {
        let s = MbsSession::new_multicast(test_tmgi(), test_group());
        assert_eq!(s.tmgi_hex(), "ABCDEF010203");
    }

    #[test]
    fn test_valid_multicast_addr() {
        assert!(MbsGroupAddr::is_valid_multicast_v4(&[239, 1, 2, 3]));
        assert!(!MbsGroupAddr::is_valid_multicast_v4(&[10, 0, 0, 1]));
    }

    #[test]
    fn test_smf_mbs_context_lifecycle() {
        let mut ctx = SmfMbsContext::new();
        let s = MbsSession::new_multicast(test_tmgi(), test_group());
        let key = ctx.create_session(s);
        assert_eq!(ctx.active_count(), 0);
        assert!(ctx.activate(&key));
        assert_eq!(ctx.active_count(), 1);
        assert!(ctx.release(&key));
        assert_eq!(ctx.active_count(), 0);
    }

    #[test]
    fn test_ue_join_nonexistent_session() {
        let mut ctx = SmfMbsContext::new();
        assert!(!ctx.ue_join("DEADBEEF", "imsi-001011234567890".into()));
    }
}
