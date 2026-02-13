//! NGAP Multicast Session Procedures (TS 38.413 / TS 23.247)
//!
//! MBS (Multicast/Broadcast Service) NGAP procedures in the AMF:
//! - Multicast Session Activation: AMF -> gNB (activate MBS session)
//! - Multicast Session Deactivation: AMF -> gNB (deactivate MBS session)
//! - Multicast Session Update: AMF -> gNB (modify MBS session parameters)
//! - Multicast Group Paging: AMF -> gNB (page UEs for MBS join)
//!
//! The AMF acts as the NGAP anchor for MBS, relaying MB-SMF instructions
//! to gNBs over the N2 interface.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::ngap_build::NgapMessageBuilder;

/// NGAP procedure codes for MBS (TS 38.413 Section 9.2.9)
pub mod mbs_procedure_code {
    pub const MULTICAST_SESSION_ACTIVATION: u16 = 68;
    pub const MULTICAST_SESSION_DEACTIVATION: u16 = 69;
    pub const MULTICAST_SESSION_UPDATE: u16 = 70;
    pub const MULTICAST_GROUP_PAGING: u16 = 71;
}

/// TMGI (Temporary Mobile Group Identity) for MBS sessions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tmgi {
    /// MBS Service ID (3 bytes)
    pub mbs_service_id: [u8; 3],
    /// PLMN ID (MCC + MNC encoded as 3 bytes)
    pub plmn_id: [u8; 3],
}

impl Tmgi {
    pub fn new(service_id: u32, plmn: [u8; 3]) -> Self {
        Self {
            mbs_service_id: [
                (service_id >> 16) as u8,
                (service_id >> 8) as u8,
                service_id as u8,
            ],
            plmn_id: plmn,
        }
    }

    pub fn service_id_u32(&self) -> u32 {
        (self.mbs_service_id[0] as u32) << 16
            | (self.mbs_service_id[1] as u32) << 8
            | (self.mbs_service_id[2] as u32)
    }
}

/// MBS session state in NGAP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsSessionState {
    Inactive,
    Activating,
    Active,
    Deactivating,
}

/// Multicast transport information (DL tunnel endpoint for gNB)
#[derive(Debug, Clone)]
pub struct McastTransportInfo {
    /// GTP-U TEID for multicast DL
    pub dl_teid: u32,
    /// UPF transport layer address
    pub transport_addr: Ipv4Addr,
}

/// gNB multicast session context (per-gNB state for an MBS session)
#[derive(Debug, Clone)]
pub struct GnbMbsSessionCtx {
    /// gNB ID
    pub gnb_id: u32,
    /// Session state at this gNB
    pub state: MbsSessionState,
    /// gNB-allocated UL TEID (from activation response)
    pub gnb_ul_teid: Option<u32>,
}

/// MBS Session in AMF NGAP context
#[derive(Debug, Clone)]
pub struct NgapMbsSession {
    /// TMGI identifying the MBS session
    pub tmgi: Tmgi,
    /// MBS Session ID (AMF-allocated)
    pub mbs_session_id: u64,
    /// Overall session state
    pub state: MbsSessionState,
    /// Multicast transport info (from MB-SMF via N2)
    pub transport: Option<McastTransportInfo>,
    /// Per-gNB session contexts
    pub gnb_sessions: Vec<GnbMbsSessionCtx>,
    /// S-NSSAI SST for this MBS session
    pub sst: u8,
    /// S-NSSAI SD (optional)
    pub sd: Option<u32>,
    /// MBS Area of Interest (list of TAC values)
    pub area_tacs: Vec<u32>,
}

/// AMF NGAP Multicast Context
pub struct NgapMcastContext {
    /// MBS sessions (session_id -> session)
    sessions: RwLock<HashMap<u64, NgapMbsSession>>,
    /// TMGI -> session_id index
    tmgi_index: RwLock<HashMap<Tmgi, u64>>,
    /// Next MBS session ID allocator
    next_session_id: AtomicU64,
}

impl NgapMcastContext {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            tmgi_index: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
        }
    }

    /// Create a new MBS session (triggered by MB-SMF via Namf)
    pub fn session_create(
        &self,
        tmgi: Tmgi,
        sst: u8,
        sd: Option<u32>,
        area_tacs: Vec<u32>,
    ) -> Option<NgapMbsSession> {
        let mut sessions = self.sessions.write().ok()?;
        let mut tmgi_index = self.tmgi_index.write().ok()?;

        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);

        let session = NgapMbsSession {
            tmgi: tmgi.clone(),
            mbs_session_id: session_id,
            state: MbsSessionState::Inactive,
            transport: None,
            gnb_sessions: Vec::new(),
            sst,
            sd,
            area_tacs,
        };

        tmgi_index.insert(tmgi, session_id);
        sessions.insert(session_id, session.clone());

        log::info!(
            "NGAP MBS session created: id={} tmgi_svc={:#x} sst={}",
            session_id,
            session.tmgi.service_id_u32(),
            sst,
        );

        Some(session)
    }

    /// Activate MBS session on target gNBs
    /// Returns (session_id, list of NGAP activation messages to send per gNB)
    pub fn session_activate(
        &self,
        session_id: u64,
        transport: McastTransportInfo,
        target_gnb_ids: &[u32],
    ) -> Vec<(u32, Vec<u8>)> {
        let mut sessions = match self.sessions.write().ok() {
            Some(s) => s,
            None => return vec![],
        };

        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return vec![],
        };

        session.transport = Some(transport.clone());
        session.state = MbsSessionState::Activating;

        let mut messages = Vec::new();

        for &gnb_id in target_gnb_ids {
            // Add gNB session context
            session.gnb_sessions.push(GnbMbsSessionCtx {
                gnb_id,
                state: MbsSessionState::Activating,
                gnb_ul_teid: None,
            });

            // Build NGAP Multicast Session Activation Request
            let msg = build_mcast_session_activation_request(
                &session.tmgi,
                session_id,
                &transport,
                session.sst,
                session.sd,
            );
            messages.push((gnb_id, msg));
        }

        log::info!(
            "NGAP MBS session activation: id={} transport={}:{:#x} gnbs={}",
            session_id,
            transport.transport_addr,
            transport.dl_teid,
            target_gnb_ids.len(),
        );

        messages
    }

    /// Process gNB activation response
    pub fn session_activation_response(
        &self,
        session_id: u64,
        gnb_id: u32,
        gnb_ul_teid: Option<u32>,
        success: bool,
    ) -> bool {
        let mut sessions = match self.sessions.write().ok() {
            Some(s) => s,
            None => return false,
        };

        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return false,
        };

        if let Some(gnb_ctx) = session.gnb_sessions.iter_mut().find(|g| g.gnb_id == gnb_id) {
            if success {
                gnb_ctx.state = MbsSessionState::Active;
                gnb_ctx.gnb_ul_teid = gnb_ul_teid;
                log::info!(
                    "NGAP MBS gNB activated: session={session_id} gnb={gnb_id} ul_teid={gnb_ul_teid:#x?}"
                );
            } else {
                gnb_ctx.state = MbsSessionState::Inactive;
                log::warn!(
                    "NGAP MBS gNB activation failed: session={session_id} gnb={gnb_id}"
                );
            }
        }

        // Check if all gNBs have responded
        let all_responded = session
            .gnb_sessions
            .iter()
            .all(|g| g.state != MbsSessionState::Activating);

        if all_responded {
            let any_active = session
                .gnb_sessions
                .iter()
                .any(|g| g.state == MbsSessionState::Active);
            session.state = if any_active {
                MbsSessionState::Active
            } else {
                MbsSessionState::Inactive
            };
        }

        all_responded
    }

    /// Deactivate MBS session on all gNBs
    /// Returns list of (gnb_id, deactivation_message)
    pub fn session_deactivate(&self, session_id: u64) -> Vec<(u32, Vec<u8>)> {
        let mut sessions = match self.sessions.write().ok() {
            Some(s) => s,
            None => return vec![],
        };

        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return vec![],
        };

        session.state = MbsSessionState::Deactivating;

        let mut messages = Vec::new();

        for gnb_ctx in &mut session.gnb_sessions {
            if gnb_ctx.state == MbsSessionState::Active {
                gnb_ctx.state = MbsSessionState::Deactivating;
                let msg = build_mcast_session_deactivation_request(
                    &session.tmgi,
                    session_id,
                );
                messages.push((gnb_ctx.gnb_id, msg));
            }
        }

        log::info!(
            "NGAP MBS session deactivation: id={} gnbs={}",
            session_id,
            messages.len(),
        );

        messages
    }

    /// Process gNB deactivation response
    pub fn session_deactivation_response(
        &self,
        session_id: u64,
        gnb_id: u32,
    ) -> bool {
        let mut sessions = match self.sessions.write().ok() {
            Some(s) => s,
            None => return false,
        };

        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return false,
        };

        if let Some(gnb_ctx) = session.gnb_sessions.iter_mut().find(|g| g.gnb_id == gnb_id) {
            gnb_ctx.state = MbsSessionState::Inactive;
        }

        let all_inactive = session
            .gnb_sessions
            .iter()
            .all(|g| g.state == MbsSessionState::Inactive);

        if all_inactive {
            session.state = MbsSessionState::Inactive;
        }

        all_inactive
    }

    /// Remove an MBS session entirely
    pub fn session_remove(&self, session_id: u64) -> Option<NgapMbsSession> {
        let mut sessions = self.sessions.write().ok()?;
        let mut tmgi_index = self.tmgi_index.write().ok()?;

        if let Some(session) = sessions.remove(&session_id) {
            tmgi_index.remove(&session.tmgi);
            log::info!("NGAP MBS session removed: id={session_id}");
            return Some(session);
        }
        None
    }

    /// Find MBS session by ID
    pub fn session_find(&self, session_id: u64) -> Option<NgapMbsSession> {
        self.sessions.read().ok()?.get(&session_id).cloned()
    }

    /// Find MBS session by TMGI
    pub fn session_find_by_tmgi(&self, tmgi: &Tmgi) -> Option<NgapMbsSession> {
        let tmgi_index = self.tmgi_index.read().ok()?;
        let session_id = tmgi_index.get(tmgi)?;
        self.sessions.read().ok()?.get(session_id).cloned()
    }

    /// Build multicast group paging message for a set of TACs
    pub fn build_group_paging(
        &self,
        session_id: u64,
    ) -> Option<Vec<u8>> {
        let sessions = self.sessions.read().ok()?;
        let session = sessions.get(&session_id)?;

        Some(build_mcast_group_paging(&session.tmgi, session_id, &session.area_tacs))
    }

    /// Get all active MBS sessions
    pub fn active_sessions(&self) -> Vec<NgapMbsSession> {
        self.sessions
            .read()
            .map(|s| {
                s.values()
                    .filter(|s| s.state == MbsSessionState::Active)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for NgapMcastContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// NGAP Message Building for MBS
// ============================================================================

/// Build Multicast Session Activation Request (AMF -> gNB)
/// TS 38.413 Section 9.2.9.1
fn build_mcast_session_activation_request(
    tmgi: &Tmgi,
    session_id: u64,
    transport: &McastTransportInfo,
    sst: u8,
    sd: Option<u32>,
) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(mbs_procedure_code::MULTICAST_SESSION_ACTIVATION);
    builder.write_u8(0); // criticality: reject

    // MBS Session ID
    builder.write_u64(session_id);

    // TMGI
    builder.write_bytes(&tmgi.mbs_service_id);
    builder.write_bytes(&tmgi.plmn_id);

    // S-NSSAI
    builder.write_u8(sst);
    if let Some(sd_val) = sd {
        builder.write_u8(1); // SD present
        builder.write_u8((sd_val >> 16) as u8);
        builder.write_u8((sd_val >> 8) as u8);
        builder.write_u8(sd_val as u8);
    } else {
        builder.write_u8(0); // SD not present
    }

    // Multicast Transport Layer Information
    builder.write_u32(transport.dl_teid);
    let addr_octets = transport.transport_addr.octets();
    builder.write_u8(4); // IPv4 address length
    builder.write_bytes(&addr_octets);

    builder.build()
}

/// Build Multicast Session Deactivation Request (AMF -> gNB)
/// TS 38.413 Section 9.2.9.3
fn build_mcast_session_deactivation_request(
    tmgi: &Tmgi,
    session_id: u64,
) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    builder.write_u16(mbs_procedure_code::MULTICAST_SESSION_DEACTIVATION);
    builder.write_u8(0); // criticality: reject

    // MBS Session ID
    builder.write_u64(session_id);

    // TMGI
    builder.write_bytes(&tmgi.mbs_service_id);
    builder.write_bytes(&tmgi.plmn_id);

    builder.build()
}

/// Build Multicast Group Paging (AMF -> gNBs in MBS area)
/// TS 38.413 Section 9.2.9.5
fn build_mcast_group_paging(
    tmgi: &Tmgi,
    session_id: u64,
    area_tacs: &[u32],
) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    builder.write_u16(mbs_procedure_code::MULTICAST_GROUP_PAGING);
    builder.write_u8(1); // criticality: ignore

    // MBS Session ID
    builder.write_u64(session_id);

    // TMGI
    builder.write_bytes(&tmgi.mbs_service_id);
    builder.write_bytes(&tmgi.plmn_id);

    // MBS Service Area TAC list
    builder.write_u8(area_tacs.len() as u8);
    for &tac in area_tacs {
        builder.write_u8((tac >> 16) as u8);
        builder.write_u8((tac >> 8) as u8);
        builder.write_u8(tac as u8);
    }

    builder.build()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tmgi() -> Tmgi {
        Tmgi::new(0x000101, [0x00, 0xF1, 0x10])
    }

    #[test]
    fn test_tmgi_creation() {
        let tmgi = test_tmgi();
        assert_eq!(tmgi.service_id_u32(), 0x000101);
        assert_eq!(tmgi.plmn_id, [0x00, 0xF1, 0x10]);
    }

    #[test]
    fn test_context_new() {
        let ctx = NgapMcastContext::new();
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_session_create() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, None, vec![1, 2])
            .unwrap();
        assert_eq!(session.state, MbsSessionState::Inactive);
        assert_eq!(session.sst, 1);
        assert_eq!(session.area_tacs, vec![1, 2]);
        assert_eq!(ctx.session_count(), 1);
    }

    #[test]
    fn test_session_find_by_tmgi() {
        let ctx = NgapMcastContext::new();
        let tmgi = test_tmgi();
        ctx.session_create(tmgi.clone(), 1, None, vec![1]);

        let found = ctx.session_find_by_tmgi(&tmgi).unwrap();
        assert_eq!(found.tmgi, tmgi);

        let bad_tmgi = Tmgi::new(0x999999, [0x00, 0x00, 0x00]);
        assert!(ctx.session_find_by_tmgi(&bad_tmgi).is_none());
    }

    #[test]
    fn test_session_activate_deactivate() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, Some(0x010203), vec![1])
            .unwrap();
        let sid = session.mbs_session_id;

        let transport = McastTransportInfo {
            dl_teid: 0x1234,
            transport_addr: Ipv4Addr::new(10, 0, 0, 1),
        };

        // Activate on 2 gNBs
        let msgs = ctx.session_activate(sid, transport, &[100, 200]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].0, 100);
        assert_eq!(msgs[1].0, 200);

        // Verify activating state
        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Activating);
        assert_eq!(s.gnb_sessions.len(), 2);

        // gNB 100 responds success
        let all = ctx.session_activation_response(sid, 100, Some(0x5001), true);
        assert!(!all); // not all responded yet

        // gNB 200 responds success
        let all = ctx.session_activation_response(sid, 200, Some(0x5002), true);
        assert!(all); // all responded

        // Session should be active
        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Active);

        // Deactivate
        let deact_msgs = ctx.session_deactivate(sid);
        assert_eq!(deact_msgs.len(), 2);

        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Deactivating);

        // Both gNBs respond
        ctx.session_deactivation_response(sid, 100);
        let all = ctx.session_deactivation_response(sid, 200);
        assert!(all);

        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Inactive);
    }

    #[test]
    fn test_session_activation_partial_failure() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, None, vec![1])
            .unwrap();
        let sid = session.mbs_session_id;

        let transport = McastTransportInfo {
            dl_teid: 0xABCD,
            transport_addr: Ipv4Addr::new(10, 0, 0, 2),
        };

        ctx.session_activate(sid, transport, &[100, 200]);

        // gNB 100 success, gNB 200 failure
        ctx.session_activation_response(sid, 100, Some(0x6001), true);
        ctx.session_activation_response(sid, 200, None, false);

        // Should still be active (at least one gNB succeeded)
        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Active);
    }

    #[test]
    fn test_session_activation_all_fail() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, None, vec![1])
            .unwrap();
        let sid = session.mbs_session_id;

        let transport = McastTransportInfo {
            dl_teid: 0xDEAD,
            transport_addr: Ipv4Addr::new(10, 0, 0, 3),
        };

        ctx.session_activate(sid, transport, &[100]);
        ctx.session_activation_response(sid, 100, None, false);

        // Should be inactive (all failed)
        let s = ctx.session_find(sid).unwrap();
        assert_eq!(s.state, MbsSessionState::Inactive);
    }

    #[test]
    fn test_session_remove() {
        let ctx = NgapMcastContext::new();
        let tmgi = test_tmgi();
        let session = ctx.session_create(tmgi.clone(), 1, None, vec![1]).unwrap();
        let sid = session.mbs_session_id;

        assert_eq!(ctx.session_count(), 1);
        let removed = ctx.session_remove(sid).unwrap();
        assert_eq!(removed.tmgi, tmgi);
        assert_eq!(ctx.session_count(), 0);
        assert!(ctx.session_find_by_tmgi(&tmgi).is_none());
    }

    #[test]
    fn test_active_sessions() {
        let ctx = NgapMcastContext::new();
        let s1 = ctx
            .session_create(Tmgi::new(1, [0x00, 0xF1, 0x10]), 1, None, vec![1])
            .unwrap();
        let s2 = ctx
            .session_create(Tmgi::new(2, [0x00, 0xF1, 0x10]), 1, None, vec![1])
            .unwrap();

        let transport = McastTransportInfo {
            dl_teid: 0x1111,
            transport_addr: Ipv4Addr::new(10, 0, 0, 1),
        };

        // Activate only s1
        ctx.session_activate(s1.mbs_session_id, transport, &[100]);
        ctx.session_activation_response(s1.mbs_session_id, 100, Some(0x7001), true);

        let active = ctx.active_sessions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].mbs_session_id, s1.mbs_session_id);

        // s2 is still inactive
        let s2_found = ctx.session_find(s2.mbs_session_id).unwrap();
        assert_eq!(s2_found.state, MbsSessionState::Inactive);
    }

    #[test]
    fn test_group_paging() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, None, vec![1, 2, 3])
            .unwrap();

        let paging_msg = ctx.build_group_paging(session.mbs_session_id).unwrap();
        assert!(!paging_msg.is_empty());

        // Verify procedure code
        let proc_code = (paging_msg[0] as u16) << 8 | paging_msg[1] as u16;
        assert_eq!(proc_code, mbs_procedure_code::MULTICAST_GROUP_PAGING);
    }

    #[test]
    fn test_build_activation_message() {
        let tmgi = test_tmgi();
        let transport = McastTransportInfo {
            dl_teid: 0x1234,
            transport_addr: Ipv4Addr::new(10, 0, 0, 1),
        };

        let msg = build_mcast_session_activation_request(&tmgi, 1, &transport, 1, Some(0x010203));
        assert!(!msg.is_empty());

        let proc_code = (msg[0] as u16) << 8 | msg[1] as u16;
        assert_eq!(
            proc_code,
            mbs_procedure_code::MULTICAST_SESSION_ACTIVATION
        );
    }

    #[test]
    fn test_build_deactivation_message() {
        let tmgi = test_tmgi();
        let msg = build_mcast_session_deactivation_request(&tmgi, 1);
        assert!(!msg.is_empty());

        let proc_code = (msg[0] as u16) << 8 | msg[1] as u16;
        assert_eq!(
            proc_code,
            mbs_procedure_code::MULTICAST_SESSION_DEACTIVATION
        );
    }
}
