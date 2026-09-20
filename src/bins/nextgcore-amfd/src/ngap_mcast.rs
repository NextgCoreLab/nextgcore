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
//!
//! # Not yet dispatched
//!
//! Nothing calls into this module: `lib.rs` declares it and the NGAP dispatch in
//! `ngap_path.rs` has no arm for procedures 71-74. Its procedure codes were
//! nevertheless wrong (see [`mbs_procedure_code`]) and are now correct, because a
//! latent builder that emits the wrong procedure code is a trap for whoever wires
//! it up.
//!
//! It is deliberately **not deleted**, unlike the unreachable duplicate handlers
//! removed from `ngap_handler.rs`: those had live reimplementations elsewhere, so
//! deleting them lost nothing, whereas this is the only MBS N2 code in the AMF and
//! `nextgcore-mbsmfd` exists as its peer. Whether the AMF should carry MBS N2 at
//! all is a product decision, not a cleanup.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use nextgcore_ngap::ie::MulticastGroupPagingArea;
use nextgcore_ngap::mbs_transfer::MbsSessionId;
use nextgcore_ngap::types::TaiListItem;

/// `maxnoofTAIforPaging` (38413-j30.txt:59347), the ASN.1 upper bound on
/// `MBS-AreaTAIList`.
const MAX_TAI_FOR_PAGING: usize = 16;

/// NGAP procedure codes for MBS.
///
/// The values are from the TS 38.413 `ProcedureCode` assignments:
/// `id-MulticastSessionActivation ::= 71`, `...Deactivation ::= 72`,
/// `...Update ::= 73`, `id-MulticastGroupPaging ::= 74`.
///
/// These were previously 68/69/70/71 — off by three, which is not a harmless
/// numbering slip: **68 is `id-BroadcastSessionSetup`**, so every builder in this
/// module labelled its PDU as a different elementary procedure than the one it
/// carried, and the value used for Group Paging (71) is in fact Multicast Session
/// Activation. A gNB decoding any of them would have dispatched the wrong
/// procedure or rejected the PDU outright.
pub mod mbs_procedure_code {
    /// `id-MulticastSessionActivation` (TS 38.413)
    pub const MULTICAST_SESSION_ACTIVATION: u16 = 71;
    /// `id-MulticastSessionDeactivation`
    pub const MULTICAST_SESSION_DEACTIVATION: u16 = 72;
    /// `id-MulticastSessionUpdate`
    pub const MULTICAST_SESSION_UPDATE: u16 = 73;
    /// `id-MulticastGroupPaging`
    pub const MULTICAST_GROUP_PAGING: u16 = 74;
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
            if let Some(msg) = build_mcast_session_activation_request(&session.tmgi) {
                messages.push((gnb_id, msg));
            }
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
                log::warn!("NGAP MBS gNB activation failed: session={session_id} gnb={gnb_id}");
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
                if let Some(msg) = build_mcast_session_deactivation_request(&session.tmgi) {
                    messages.push((gnb_ctx.gnb_id, msg));
                }
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
    pub fn session_deactivation_response(&self, session_id: u64, gnb_id: u32) -> bool {
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
    pub fn build_group_paging(&self, session_id: u64) -> Option<Vec<u8>> {
        let sessions = self.sessions.read().ok()?;
        let session = sessions.get(&session_id)?;

        build_mcast_group_paging(&session.tmgi, &session.area_tacs)
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
            .expect("value expected")
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

/// The TMGI as the shared NGAP codec spells it.
///
/// `MBS-SessionID` carries the TMGI as PLMN identity then MBS service id
/// (TS 38.413 §9.3.1.176). Converting here rather than storing an
/// `MbsSessionId` directly keeps [`Tmgi`]'s `Hash`/`Eq` index usable.
fn mbs_session_id_of(tmgi: &Tmgi) -> MbsSessionId {
    MbsSessionId::new(tmgi.plmn_id, tmgi.mbs_service_id)
}

/// Build Multicast Session Activation Request (AMF -> gNB), TS 38.413 §9.2.9.1.
///
/// Delegates to `nextgcore_ngap::builder`, so the PDU is real APER with the
/// outer CHOICE index in byte 0 and the procedure code in byte 1.
///
/// The `transport`, `sst` and `sd` the AMF holds are deliberately NOT sent:
/// `MulticastSessionActivationRequest` carries only `MBS-SessionID` and the
/// activation transfer (38413-j30.txt:42786). Multicast transport is set up by
/// the Distribution Setup procedures (69/70) against the MB-UPF; S-NSSAI is not
/// an IE of this message at all.
fn build_mcast_session_activation_request(tmgi: &Tmgi) -> Option<Vec<u8>> {
    nextgcore_ngap::builder::build_multicast_session_activation_request(&mbs_session_id_of(tmgi))
        .map_err(|e| log::error!("failed to encode MulticastSessionActivationRequest: {e}"))
        .ok()
}

/// Build Multicast Session Deactivation Request (AMF -> gNB), TS 38.413 §9.2.9.3.
fn build_mcast_session_deactivation_request(tmgi: &Tmgi) -> Option<Vec<u8>> {
    nextgcore_ngap::builder::build_multicast_session_deactivation_request(&mbs_session_id_of(tmgi))
        .map_err(|e| log::error!("failed to encode MulticastSessionDeactivationRequest: {e}"))
        .ok()
}

/// Build Multicast Group Paging (AMF -> gNBs in the MBS area), TS 38.413 §9.2.9.5.
///
/// The stored `area_tacs` become one `MulticastGroupPagingArea` whose
/// `MBS-AreaTAIList` is those TACs under the AMF's own PLMN. `MBS-AreaTAIList`
/// is `SEQUENCE (SIZE(1..16)) OF TAI`, so an empty area list cannot be encoded
/// and yields `None` rather than a PDU asserting an empty area.
fn build_mcast_group_paging(tmgi: &Tmgi, area_tacs: &[u32]) -> Option<Vec<u8>> {
    // The APER encoder ALSO refuses a zero length against `SIZE(1..16)` with a
    // ConstraintViolation, so this early return is not what makes an empty area
    // safe -- it is what makes the REASON legible. An operator reading
    // "ConstraintViolation { value: 0, min: 1 }" cannot tell that the session
    // simply has no service area configured.
    //
    // Deliberately NOT claimed as a revert-verified guard: removing it leaves
    // behaviour identical (verified -- the test still passes with it gone),
    // which is precisely why the test pins the populated/empty CONTRAST rather
    // than the empty case alone.
    if area_tacs.is_empty() {
        log::warn!(
            "MulticastGroupPaging not built: MBS-AreaTAIList has ASN.1 lower bound 1 and the \
             session carries no service-area TAC"
        );
        return None;
    }

    let area_tai_list = area_tacs
        .iter()
        .take(MAX_TAI_FOR_PAGING)
        .map(|&tac| TaiListItem {
            tai_plmn: tmgi.plmn_id,
            tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
        })
        .collect();

    if area_tacs.len() > MAX_TAI_FOR_PAGING {
        log::warn!(
            "MulticastGroupPaging area truncated to maxnoofTAIforPaging={MAX_TAI_FOR_PAGING} \
             (session carries {} TACs)",
            area_tacs.len()
        );
    }

    nextgcore_ngap::builder::build_multicast_group_paging(
        &mbs_session_id_of(tmgi),
        &[MulticastGroupPagingArea { area_tai_list }],
    )
    .map_err(|e| log::error!("failed to encode MulticastGroupPaging: {e}"))
    .ok()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_asn1c::ngap::types::ProcedureCode;

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
        let session = ctx.session_create(test_tmgi(), 1, None, vec![1]).unwrap();
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
        let session = ctx.session_create(test_tmgi(), 1, None, vec![1]).unwrap();
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

    /// Decode an MBS PDU the way a real peer does: byte 0 is the outer NGAP
    /// CHOICE index and byte 1 is the procedure code (TS 38.413 §9.1).
    ///
    /// The tests this replaces read `(msg[0] << 8) | msg[1]` as a u16 procedure
    /// code, which is what the deleted byte-writer emitted -- so they agreed
    /// with a format no gNB could parse, and compared a built PDU against the
    /// same constant it was built from. Decoding through the real codec is what
    /// makes these assertions mean something.
    fn decode_initiating(msg: &[u8]) -> (u8, Vec<u16>) {
        use nextgcore_asn1c::ngap::pdu::{InitiatingMessageValue, NgapPdu};
        use nextgcore_asn1c::per::{AperDecode, AperDecoder};

        let mut decoder = AperDecoder::new(msg);
        let pdu = NgapPdu::decode_aper(&mut decoder).expect("MBS PDU must decode as APER");
        let NgapPdu::InitiatingMessage(im) = pdu else {
            panic!("expected an InitiatingMessage");
        };
        // MBS procedures are not in the generated InitiatingMessageValue enum,
        // so the decoder routes them to `Other` -- which is the variant the
        // builders encode through. Asserting on it proves the round trip took
        // the same path a peer's decoder would.
        let InitiatingMessageValue::Other(ies) = im.value else {
            panic!("MBS procedures decode through InitiatingMessageValue::Other");
        };
        assert_eq!(msg[0], 0x00, "InitiatingMessage is outer CHOICE index 0");
        (
            im.procedure_code.0,
            ies.ies.iter().map(|ie| ie.id.0).collect(),
        )
    }

    #[test]
    fn a_group_paging_pdu_decodes_as_procedure_74_with_its_area_list() {
        let ctx = NgapMcastContext::new();
        let session = ctx
            .session_create(test_tmgi(), 1, None, vec![1, 2, 3])
            .unwrap();

        let msg = ctx.build_group_paging(session.mbs_session_id).unwrap();
        let (proc_code, ies) = decode_initiating(&msg);
        assert_eq!(proc_code, ProcedureCode::MULTICAST_GROUP_PAGING.0);
        assert_eq!(proc_code, 74, "38413-j30.txt:59161");

        // The IEs are the ones TS 38.413 lists, and the area list is present
        // rather than merely the session id.
        assert!(ies.contains(&299), "id-MBS-SessionID");
        assert!(ies.contains(&307), "id-MulticastGroupPagingAreaList");
    }

    /// A session with no service-area TAC yields NO paging PDU, while an
    /// otherwise identical session WITH a TAC does -- `MBS-AreaTAIList` is
    /// `SEQUENCE (SIZE(1..16)) OF TAI`, so there is no such thing as a paging
    /// PDU for an empty area, and inventing a TAC would page the wrong cells.
    ///
    /// Asserted as a CONTRAST pair on purpose. The empty half alone would be a
    /// false guard: `None` is also what a constraint violation, a lookup miss or
    /// any other early return produces, so it is satisfied by paths that never
    /// reach the area list. Only the populated half proves the builder works,
    /// and only together do they show the empty case is a decision rather than a
    /// failure. (Measured: removing the explicit `is_empty` check leaves the
    /// empty half passing, because the encoder refuses length 0 anyway.)
    #[test]
    fn a_session_with_no_service_area_builds_no_group_paging() {
        let ctx = NgapMcastContext::new();

        let empty = ctx.session_create(test_tmgi(), 1, None, vec![]).unwrap();
        assert!(
            ctx.build_group_paging(empty.mbs_session_id).is_none(),
            "no service area means no paging PDU"
        );

        let populated = ctx
            .session_create(Tmgi::new(0x00AAAA, [0x00, 0xF1, 0x10]), 1, None, vec![7])
            .unwrap();
        let msg = ctx
            .build_group_paging(populated.mbs_session_id)
            .expect("one TAC is enough to page");
        let (proc_code, ies) = decode_initiating(&msg);
        assert_eq!(proc_code, ProcedureCode::MULTICAST_GROUP_PAGING.0);
        assert!(ies.contains(&307), "the area list must be on the wire");
    }

    #[test]
    fn an_activation_pdu_decodes_as_procedure_71_carrying_session_id_and_transfer() {
        let msg = build_mcast_session_activation_request(&test_tmgi()).unwrap();
        let (proc_code, ies) = decode_initiating(&msg);
        assert_eq!(proc_code, ProcedureCode::MULTICAST_SESSION_ACTIVATION.0);
        assert_eq!(proc_code, 71, "38413-j30.txt:59155");
        assert_eq!(
            ies,
            vec![299, 304],
            "TS 38.413 lists exactly id-MBS-SessionID and \
             id-MulticastSessionActivationRequestTransfer (38413-j30.txt:42786)"
        );
    }

    #[test]
    fn a_deactivation_pdu_decodes_as_procedure_72_with_its_own_transfer_ie() {
        let msg = build_mcast_session_deactivation_request(&test_tmgi()).unwrap();
        let (proc_code, ies) = decode_initiating(&msg);
        assert_eq!(proc_code, ProcedureCode::MULTICAST_SESSION_DEACTIVATION.0);
        assert_eq!(proc_code, 72, "38413-j30.txt:59157");
        assert_eq!(
            ies,
            vec![299, 305],
            "deactivation transfer is IE 305, not 304"
        );
    }

    /// The four MBS procedure codes are pairwise distinct AND distinct from the
    /// live neighbours they were once confused with. The pre-fix module used
    /// 68/69/70/71, so activation was labelled `id-BroadcastSessionSetup`.
    #[test]
    fn mbs_procedure_codes_are_distinct_from_the_broadcast_procedures() {
        let codes = [
            ProcedureCode::MULTICAST_SESSION_ACTIVATION.0,
            ProcedureCode::MULTICAST_SESSION_DEACTIVATION.0,
            ProcedureCode::MULTICAST_SESSION_UPDATE.0,
            ProcedureCode::MULTICAST_GROUP_PAGING.0,
        ];
        assert_eq!(codes, [71, 72, 73, 74]);

        // Controls: the codes an off-by-three lands on (38413-j30.txt:59145-59153).
        assert_eq!(ProcedureCode::BROADCAST_SESSION_MODIFICATION.0, 66);
        assert_eq!(ProcedureCode::BROADCAST_SESSION_RELEASE.0, 67);
        assert_eq!(ProcedureCode::BROADCAST_SESSION_SETUP.0, 68);
        assert_eq!(ProcedureCode::DISTRIBUTION_SETUP.0, 69);
        assert_eq!(ProcedureCode::DISTRIBUTION_RELEASE.0, 70);
        for code in codes {
            assert!(
                !(66..=70).contains(&code),
                "procedure {code} collides with a broadcast/distribution procedure"
            );
        }
    }
}
