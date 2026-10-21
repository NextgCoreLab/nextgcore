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
//! # Wiring
//!
//! `namf_server.rs` drives activation, deactivation and group paging for the
//! MB-SMF, and the NGAP dispatch in `ngap_path.rs` routes the gNB's outcomes of
//! procedures 68/71-74 to `handle_mbs_outcome`, which finds the session by the
//! `MBS-SessionID` [`crate::ngap_asn1::extract_mbs_session_id`] reads. The PDUs
//! are built and decoded by the generated codec (#417).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use nextgcore_ngap_gen::generated as ngap_gen;

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

/// The TMGI's six octets as `MBS-SessionID` carries them: "Encoded as defined in
/// TS 23.003" (TS 38.413 §9.3.1.206), which puts the MBS Service ID first and
/// the MCC/MNC after it (TS 23.003 §30.2; the same octet order as the NAS TMGI
/// IE, TS 24.008 §10.5.6.13).
fn tmgi_octets(tmgi: &Tmgi) -> Vec<u8> {
    let mut octets = tmgi.mbs_service_id.to_vec();
    octets.extend_from_slice(&tmgi.plmn_id);
    octets
}

/// `tmgi` as the generated `MBS-SessionID`. No NID: the AMF keeps no SNPN MBS
/// sessions.
pub(crate) fn generated_mbs_session_id(tmgi: &Tmgi) -> ngap_gen::MBS_SessionID {
    ngap_gen::MBS_SessionID {
        tmgi: ngap_gen::TMGI(tmgi_octets(tmgi)),
        nid: None,
        ie_extensions: None,
    }
}

/// The [`Tmgi`] of a received `MBS-SessionID`, the inverse of
/// [`generated_mbs_session_id`]. `None` unless the TMGI is six octets, which the
/// codec's SIZE(6) already enforces. A NID is not part of the AMF's session key.
pub(crate) fn tmgi_from_generated(id: &ngap_gen::MBS_SessionID) -> Option<Tmgi> {
    let octets: &[u8; 6] = id.tmgi.0.as_slice().try_into().ok()?;
    let mut mbs_service_id = [0u8; 3];
    let mut plmn_id = [0u8; 3];
    mbs_service_id.copy_from_slice(&octets[..3]);
    plmn_id.copy_from_slice(&octets[3..]);
    Some(Tmgi {
        mbs_service_id,
        plmn_id,
    })
}

/// Encode an AMF-initiated MBS message, logging what failed.
fn encode_initiating(
    procedure_code: u8,
    criticality: u8,
    value: ngap_gen::InitiatingMessageValue,
    message: &str,
) -> Option<Vec<u8>> {
    let pdu = ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(procedure_code),
        criticality: ngap_gen::Criticality(criticality),
        value,
    });
    nextgcore_ngap_gen::encode(&pdu)
        .map_err(|e| log::error!("failed to encode {message}: {e:?}"))
        .ok()
}

/// Build Multicast Session Activation Request (AMF -> gNB), TS 38.413 §9.2.9.1,
/// with the GENERATED codec (#417). Both IEs and the procedure are criticality
/// reject.
///
/// The `transport`, `sst` and `sd` the AMF holds are deliberately NOT sent:
/// `MulticastSessionActivationRequest` carries only `MBS-SessionID` and the
/// activation transfer (38413-j30.txt:42786). Multicast transport is set up by
/// the Distribution Setup procedures (69/70) against the MB-UPF; S-NSSAI is not
/// an IE of this message at all.
fn build_mcast_session_activation_request(tmgi: &Tmgi) -> Option<Vec<u8>> {
    use ngap_gen::{
        MulticastSessionActivationRequestProtocolIEs_Entry as Entry,
        MulticastSessionActivationRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };

    // `SEQUENCE { mBS-SessionID, iE-Extensions OPTIONAL, ... }` (:51642), as
    // `OCTET STRING (CONTAINING ...)`: the session id is both the outer IE and
    // inside the transfer -- the spec's shape, not a duplication to collapse.
    let transfer = nextgcore_ngap_gen::encode_contained(
        &ngap_gen::MulticastSessionActivationRequestTransfer {
            mbs_session_id: generated_mbs_session_id(tmgi),
            ie_extensions: None,
        },
    )
    .map_err(|e| log::error!("failed to encode MulticastSessionActivationRequestTransfer: {e:?}"))
    .ok()?;
    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    encode_initiating(
        ngap_gen::ID_MULTICAST_SESSION_ACTIVATION,
        ngap_gen::Criticality::REJECT,
        ngap_gen::InitiatingMessageValue::Id_MulticastSessionActivation(
            ngap_gen::MulticastSessionActivationRequest {
                protocol_i_es: ngap_gen::MulticastSessionActivationRequestProtocolIEs(vec![
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                        criticality: reject.clone(),
                        value: Ie::Id_MBS_SessionID(generated_mbs_session_id(tmgi)),
                    },
                    Entry {
                        id: ProtocolIE_ID(
                            ngap_gen::ID_MULTICAST_SESSION_ACTIVATION_REQUEST_TRANSFER,
                        ),
                        criticality: reject,
                        value: Ie::Id_MulticastSessionActivationRequestTransfer(
                            ngap_gen::Id_MulticastSessionActivationRequestTransfer(transfer),
                        ),
                    },
                ]),
            },
        ),
        "MulticastSessionActivationRequest",
    )
}

/// Build Multicast Session Deactivation Request (AMF -> gNB), TS 38.413 §9.2.9.3,
/// with the GENERATED codec (#417): the activation request's shape
/// (38413-j30.txt:42892) with the deactivation transfer, IE 305.
fn build_mcast_session_deactivation_request(tmgi: &Tmgi) -> Option<Vec<u8>> {
    use ngap_gen::{
        MulticastSessionDeactivationRequestProtocolIEs_Entry as Entry,
        MulticastSessionDeactivationRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };

    let transfer = nextgcore_ngap_gen::encode_contained(
        &ngap_gen::MulticastSessionDeactivationRequestTransfer {
            mbs_session_id: generated_mbs_session_id(tmgi),
            ie_extensions: None,
        },
    )
    .map_err(|e| log::error!("failed to encode MulticastSessionDeactivationRequestTransfer: {e:?}"))
    .ok()?;
    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    encode_initiating(
        ngap_gen::ID_MULTICAST_SESSION_DEACTIVATION,
        ngap_gen::Criticality::REJECT,
        ngap_gen::InitiatingMessageValue::Id_MulticastSessionDeactivation(
            ngap_gen::MulticastSessionDeactivationRequest {
                protocol_i_es: ngap_gen::MulticastSessionDeactivationRequestProtocolIEs(vec![
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                        criticality: reject.clone(),
                        value: Ie::Id_MBS_SessionID(generated_mbs_session_id(tmgi)),
                    },
                    Entry {
                        id: ProtocolIE_ID(
                            ngap_gen::ID_MULTICAST_SESSION_DEACTIVATION_REQUEST_TRANSFER,
                        ),
                        criticality: reject,
                        value: Ie::Id_MulticastSessionDeactivationRequestTransfer(
                            ngap_gen::Id_MulticastSessionDeactivationRequestTransfer(transfer),
                        ),
                    },
                ]),
            },
        ),
        "MulticastSessionDeactivationRequest",
    )
}

/// Build Multicast Group Paging (AMF -> gNBs in the MBS area), TS 38.413 §9.2.9.5,
/// with the GENERATED codec (#417). The procedure and both IEs are criticality
/// ignore (38413-j30.txt:43085): a peer that cannot parse the area list still
/// pages.
///
/// The stored `area_tacs` become one `MulticastGroupPagingArea` whose
/// `MBS-AreaTAIList` is those TACs under the TMGI's PLMN. `MBS-AreaTAIList`
/// is `SEQUENCE (SIZE(1..16)) OF TAI`, so an empty area list cannot be encoded
/// and yields `None` rather than a PDU asserting an empty area.
fn build_mcast_group_paging(tmgi: &Tmgi, area_tacs: &[u32]) -> Option<Vec<u8>> {
    use ngap_gen::{
        MulticastGroupPagingProtocolIEs_Entry as Entry,
        MulticastGroupPagingProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };

    // The encoder ALSO refuses a zero length against `SIZE(1..16)`, so this
    // early return is not what makes an empty area safe -- it is what makes the
    // REASON legible: an operator reading a constraint violation cannot tell
    // that the session simply has no service area configured.
    //
    // Deliberately NOT claimed as a revert-verified guard: removing it leaves
    // behaviour identical, which is precisely why the test pins the
    // populated/empty CONTRAST rather than the empty case alone.
    if area_tacs.is_empty() {
        log::warn!(
            "MulticastGroupPaging not built: MBS-AreaTAIList has ASN.1 lower bound 1 and the \
             session carries no service-area TAC"
        );
        return None;
    }

    if area_tacs.len() > MAX_TAI_FOR_PAGING {
        log::warn!(
            "MulticastGroupPaging area truncated to maxnoofTAIforPaging={MAX_TAI_FOR_PAGING} \
             (session carries {} TACs)",
            area_tacs.len()
        );
    }
    let area_tai_list = area_tacs
        .iter()
        .take(MAX_TAI_FOR_PAGING)
        .map(|&tac| ngap_gen::TAI {
            plmn_identity: ngap_gen::PLMNIdentity(tmgi.plmn_id.to_vec()),
            tac: ngap_gen::TAC(vec![(tac >> 16) as u8, (tac >> 8) as u8, tac as u8]),
            ie_extensions: None,
        })
        .collect();

    let ignore = ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    encode_initiating(
        ngap_gen::ID_MULTICAST_GROUP_PAGING,
        ngap_gen::Criticality::IGNORE,
        ngap_gen::InitiatingMessageValue::Id_MulticastGroupPaging(ngap_gen::MulticastGroupPaging {
            protocol_i_es: ngap_gen::MulticastGroupPagingProtocolIEs(vec![
                Entry {
                    id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                    criticality: ignore.clone(),
                    value: Ie::Id_MBS_SessionID(generated_mbs_session_id(tmgi)),
                },
                Entry {
                    id: ProtocolIE_ID(ngap_gen::ID_MULTICAST_GROUP_PAGING_AREA_LIST),
                    criticality: ignore,
                    value: Ie::Id_MulticastGroupPagingAreaList(
                        ngap_gen::MulticastGroupPagingAreaList(vec![
                            ngap_gen::MulticastGroupPagingAreaItem {
                                multicast_group_paging_area: ngap_gen::MulticastGroupPagingArea {
                                    mbs_area_tai_list: ngap_gen::MBS_AreaTAIList(area_tai_list),
                                    ie_extensions: None,
                                },
                                ue_paging_list: None,
                                ie_extensions: None,
                            },
                        ]),
                    ),
                },
            ]),
        }),
        "MulticastGroupPaging",
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nextgcore_asn1c::ngap::types::ProcedureCode;
    use nextgcore_ngap::ie::MulticastGroupPagingArea;
    use nextgcore_ngap::mbs_transfer::MbsSessionId;
    use nextgcore_ngap::types::TaiListItem;

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

    /// Decode an MBS PDU the way a real peer does, with the generated codec:
    /// its procedure code and IE ids, in order.
    ///
    /// The tests this replaces read `(msg[0] << 8) | msg[1]` as a u16 procedure
    /// code, which is what the deleted byte-writer emitted -- so they agreed
    /// with a format no gNB could parse, and compared a built PDU against the
    /// same constant it was built from. Decoding through the real codec is what
    /// makes these assertions mean something.
    fn decode_initiating(msg: &[u8]) -> (u8, Vec<u16>) {
        let ngap_gen::NGAP_PDU::InitiatingMessage(im) =
            nextgcore_ngap_gen::decode(msg).expect("MBS PDU must decode as APER")
        else {
            panic!("expected an InitiatingMessage");
        };
        assert_eq!(msg[0], 0x00, "InitiatingMessage is outer CHOICE index 0");
        let ies = match im.value {
            ngap_gen::InitiatingMessageValue::Id_MulticastSessionActivation(r) => {
                r.protocol_i_es.0.iter().map(|e| e.id.0).collect()
            }
            ngap_gen::InitiatingMessageValue::Id_MulticastSessionDeactivation(r) => {
                r.protocol_i_es.0.iter().map(|e| e.id.0).collect()
            }
            ngap_gen::InitiatingMessageValue::Id_MulticastGroupPaging(r) => {
                r.protocol_i_es.0.iter().map(|e| e.id.0).collect()
            }
            other => panic!("not an MBS message: {other:?}"),
        };
        (im.procedure_code.0, ies)
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

    /// The hand-written codec's `MBS-SessionID` for `tmgi` with its halves
    /// SWAPPED: it writes its `plmn_identity` field first, so feeding it the
    /// service id there yields the TS 23.003 octet order, and every remaining
    /// byte can be compared as-is.
    fn spec_ordered_hand_written_id(tmgi: &Tmgi) -> MbsSessionId {
        MbsSessionId::new(tmgi.mbs_service_id, tmgi.plmn_id)
    }

    fn tmgis() -> Vec<Tmgi> {
        vec![
            test_tmgi(),
            Tmgi::new(0, [0x00, 0x00, 0x00]),
            Tmgi::new(0xFF_FFFF, [0x99, 0xF9, 0x07]),
            Tmgi::new(0x12_3456, [0x21, 0x43, 0x65]),
        ]
    }

    /// Oracle: the generated activation and deactivation requests are the
    /// hand-written ones byte for byte, but for the TMGI octet order the
    /// hand-written codec had backwards (see `tmgi_octets`).
    #[test]
    fn activation_and_deactivation_generated_match_hand_written() {
        for tmgi in tmgis() {
            let id = spec_ordered_hand_written_id(&tmgi);
            assert_eq!(
                build_mcast_session_activation_request(&tmgi).expect("generated"),
                nextgcore_ngap::builder::build_multicast_session_activation_request(&id)
                    .expect("hand-written"),
                "{tmgi:?}"
            );
            assert_eq!(
                build_mcast_session_deactivation_request(&tmgi).expect("generated"),
                nextgcore_ngap::builder::build_multicast_session_deactivation_request(&id)
                    .expect("hand-written"),
                "{tmgi:?}"
            );
        }
    }

    /// Oracle: group paging, for every area size up to maxnoofTAIforPaging and
    /// one past it (truncated), with TACs at every octet.
    #[test]
    fn group_paging_generated_matches_hand_written() {
        for tmgi in tmgis() {
            for n in 1..=MAX_TAI_FOR_PAGING + 1 {
                let tacs: Vec<u32> = (0..n as u32)
                    .map(|i| (0x01_0203 * (i + 1)) & 0xFF_FFFF)
                    .collect();
                let area_tai_list = tacs
                    .iter()
                    .take(MAX_TAI_FOR_PAGING)
                    .map(|&tac| TaiListItem {
                        tai_plmn: tmgi.plmn_id,
                        tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
                    })
                    .collect();
                assert_eq!(
                    build_mcast_group_paging(&tmgi, &tacs).expect("generated"),
                    nextgcore_ngap::builder::build_multicast_group_paging(
                        &spec_ordered_hand_written_id(&tmgi),
                        &[MulticastGroupPagingArea { area_tai_list }],
                    )
                    .expect("hand-written"),
                    "{tmgi:?} with {n} TACs"
                );
            }
        }
    }

    /// TS 38.413 §9.2.9.1, derived by hand (X.691 ALIGNED), for MBS Service ID
    /// 000101 under PLMN 00F110: initiatingMessage `00`, procedure 71 `47`,
    /// reject `00`, length 26; extension bit + 2 IEs `00 00 02`.
    /// MBS-SessionID 299 `01 2B`, reject, length 7: three preamble bits
    /// (extension, NID, iE-Extensions) padded `00`, then the fixed six-octet
    /// TMGI with no length -- service id FIRST (TS 23.003 §30.2):
    /// `00 01 01 00 F1 10`. Transfer 304 `01 30`, reject, length 8: an
    /// unconstrained OCTET STRING, length `07`, holding the transfer's two
    /// preamble bits and the session id's three, padded `00`, then the TMGI.
    const ACTIVATION_REQUEST: [u8; 30] = [
        0x00, 0x47, 0x00, 0x1A, 0x00, 0x00, 0x02, 0x01, 0x2B, 0x00, 0x07, 0x00, 0x00, 0x01, 0x01,
        0x00, 0xF1, 0x10, 0x01, 0x30, 0x00, 0x08, 0x07, 0x00, 0x00, 0x01, 0x01, 0x00, 0xF1, 0x10,
    ];

    /// TS 38.413 §9.2.9.5, by hand: procedure 74 `4A`, ignore `40`, length 27.
    /// MBS-SessionID as above but ignore. Area list 307 `01 33`, ignore, length
    /// 9: list count-1 in 6 bits, the item's 3 preamble bits, the area's 2, the
    /// TAI list count-1 in 4 bits, the TAI's 2 -- 17 bits, padded to `00 00
    /// 00` -- then PLMN `00 F1 10` and TAC 7 `00 00 07`.
    const GROUP_PAGING: [u8; 31] = [
        0x00, 0x4A, 0x40, 0x1B, 0x00, 0x00, 0x02, 0x01, 0x2B, 0x40, 0x07, 0x00, 0x00, 0x01, 0x01,
        0x00, 0xF1, 0x10, 0x01, 0x33, 0x40, 0x09, 0x00, 0x00, 0x00, 0x00, 0xF1, 0x10, 0x00, 0x00,
        0x07,
    ];

    #[test]
    fn mbs_golden_bytes() {
        assert_eq!(
            build_mcast_session_activation_request(&test_tmgi()).expect("build"),
            ACTIVATION_REQUEST
        );
        assert_eq!(
            build_mcast_group_paging(&test_tmgi(), &[7]).expect("build"),
            GROUP_PAGING
        );
    }

    /// An outcome carrying `tmgi`, built with the generated codec.
    pub(crate) fn activation_response(tmgi: &Tmgi) -> Vec<u8> {
        use ngap_gen::MulticastSessionActivationResponseProtocolIEs_Entry as Entry;
        use ngap_gen::MulticastSessionActivationResponseProtocolIEs_EntryValue as Ie;
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::SuccessfulOutcome(
            ngap_gen::SuccessfulOutcome {
                procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_MULTICAST_SESSION_ACTIVATION),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                value: ngap_gen::SuccessfulOutcomeValue::Id_MulticastSessionActivation(
                    ngap_gen::MulticastSessionActivationResponse {
                        protocol_i_es: ngap_gen::MulticastSessionActivationResponseProtocolIEs(
                            vec![Entry {
                                id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                                criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                                value: Ie::Id_MBS_SessionID(generated_mbs_session_id(tmgi)),
                            }],
                        ),
                    },
                ),
            },
        ))
        .expect("encode")
    }

    /// The outcome's session id reads back as the TMGI it was built from --
    /// the round trip `handle_mbs_outcome` depends on to find the session --
    /// and, by hand, the six octets follow the response's header and preamble
    /// service id first.
    #[test]
    fn an_outcome_yields_the_session_tmgi() {
        let response = activation_response(&test_tmgi());
        assert_eq!(
            response,
            [
                0x20, 0x47, 0x00, 0x0E, 0x00, 0x00, 0x01, 0x01, 0x2B, 0x40, 0x07, 0x00, 0x00, 0x01,
                0x01, 0x00, 0xF1, 0x10
            ]
        );
        for tmgi in tmgis() {
            assert_eq!(
                crate::ngap_asn1::extract_mbs_session_id(&activation_response(&tmgi)),
                Some(tmgi)
            );
        }
        // A request is not an outcome; truncations do not decode.
        let request = build_mcast_session_activation_request(&test_tmgi()).expect("build");
        assert_eq!(crate::ngap_asn1::extract_mbs_session_id(&request), None);
        for len in 0..response.len() {
            assert_eq!(
                crate::ngap_asn1::extract_mbs_session_id(&response[..len]),
                None,
                "prefix of {len}"
            );
        }
        // Not-comprehended IEs in a response are skipped (§10.3.4.2).
        for criticality in [0x00, 0x40, 0x80] {
            let spliced = crate::ngap_asn1::tests::with_unknown_ie(&response, 4_000, criticality);
            assert_eq!(
                crate::ngap_asn1::extract_mbs_session_id(&spliced),
                Some(test_tmgi())
            );
        }
    }

    /// Oracle for the extraction: on every outcome, the hand-written reader
    /// (kept verbatim below) yields the same six octets, split the other way
    /// round -- the octet order it shared with the hand-written builder.
    #[test]
    fn extraction_matches_the_hand_written_reader_but_for_the_octet_order() {
        for tmgi in tmgis() {
            let old = hand_written_extract(&activation_response(&tmgi)).expect("oracle");
            assert_eq!(
                (old.plmn_id, old.mbs_service_id),
                (tmgi.mbs_service_id, tmgi.plmn_id),
                "{tmgi:?}"
            );
        }
    }

    /// The pre-#417 `ngap_asn1::extract_mbs_session_id`, verbatim but for its
    /// doc comment, as the oracle above.
    fn hand_written_extract(data: &[u8]) -> Option<Tmgi> {
        use nextgcore_asn1c::ngap::pdu::{
            InitiatingMessageValue, NgapPdu, SuccessfulOutcomeValue, UnsuccessfulOutcomeValue,
        };
        use nextgcore_asn1c::per::{AperDecode, AperDecoder};

        let mut decoder = AperDecoder::new(data);
        let pdu = NgapPdu::decode_aper(&mut decoder).ok()?;
        let ies = match pdu {
            NgapPdu::InitiatingMessage(m) => match m.value {
                InitiatingMessageValue::Other(ies) => ies,
                _ => return None,
            },
            NgapPdu::SuccessfulOutcome(m) => match m.value {
                SuccessfulOutcomeValue::Other(ies) => ies,
                _ => return None,
            },
            NgapPdu::UnsuccessfulOutcome(m) => match m.value {
                UnsuccessfulOutcomeValue::Other(ies) => ies,
                _ => return None,
            },
        };
        let field = ies
            .ies
            .iter()
            .find(|ie| ie.id.0 == nextgcore_ngap::ie::IE_ID_MBS_SESSION_ID)?;
        let mut ie_decoder = AperDecoder::new(&field.value);
        let _ext = ie_decoder.read_bit().ok()?;
        let _nid_present = ie_decoder.read_bit().ok()?;
        let plmn = ie_decoder.decode_octet_string(Some(3), Some(3)).ok()?;
        let service = ie_decoder.decode_octet_string(Some(3), Some(3)).ok()?;
        Some(Tmgi {
            plmn_id: plmn.try_into().ok()?,
            mbs_service_id: service.try_into().ok()?,
        })
    }
}
