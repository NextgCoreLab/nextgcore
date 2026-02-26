//! Xn-based and N2-based Handover for AMF (Rel-15, TS 23.502 §4.9)
//!
//! Implements the AMF side of:
//! - Xn-based handover: PathSwitchRequest / PathSwitchRequestAcknowledge
//! - N2-based handover: HandoverRequired → HandoverCommand → HandoverNotify
//! - UE context transfer between gNBs

use std::collections::HashMap;

/// Handover type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverType {
    /// Intra-system 5GS to 5GS (Xn-based, within same AMF)
    IntraSystem5gs,
    /// N2-based handover (different AMF or no Xn)
    N2Based,
    /// Inter-system LTE → 5GS
    LteTo5gs,
    /// Inter-system 5GS → LTE
    FiveGsToLte,
}

/// Handover state machine phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverState {
    /// No handover in progress
    Idle,
    /// HandoverRequired received from source gNB
    Preparation,
    /// HandoverCommand sent to source gNB; waiting for completion
    Execution,
    /// HandoverNotify received; updating paths
    Completion,
    /// Handover complete; UE at target gNB
    Complete,
    /// Handover failed
    Failed,
}

/// PDU session resource to be transferred during handover
#[derive(Debug, Clone)]
pub struct PduSessionHandoverResource {
    pub pdu_session_id: u8,
    /// Source gNB tunnel endpoint (GTP-U TEID + IP)
    pub source_teid: u32,
    pub source_ip: [u8; 4],
    /// Target gNB tunnel endpoint (populated after PathSwitch)
    pub target_teid: Option<u32>,
    pub target_ip: Option<[u8; 4]>,
}

/// AMF Xn-based path switch context
///
/// Created when AMF receives PathSwitchRequest (NGAP ID 58)
#[derive(Debug, Clone)]
pub struct XnPathSwitchContext {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// Source RAN UE NGAP ID (at source gNB)
    pub source_ran_ue_ngap_id: u32,
    /// Target RAN UE NGAP ID (at target gNB)
    pub target_ran_ue_ngap_id: u32,
    /// Source gNB Global ID
    pub source_gnb_id: u32,
    /// Target gNB Global ID
    pub target_gnb_id: u32,
    /// SUPI of the UE
    pub supi: String,
    /// PDU session resources being transferred
    pub pdu_sessions: Vec<PduSessionHandoverResource>,
    /// Current handover state
    pub state: HandoverState,
    /// Handover type
    pub handover_type: HandoverType,
}

impl XnPathSwitchContext {
    pub fn new(
        amf_ue_ngap_id: u64,
        source_gnb_id: u32,
        target_gnb_id: u32,
        supi: String,
    ) -> Self {
        Self {
            amf_ue_ngap_id,
            source_ran_ue_ngap_id: 0,
            target_ran_ue_ngap_id: 0,
            source_gnb_id,
            target_gnb_id,
            supi,
            pdu_sessions: Vec::new(),
            state: HandoverState::Preparation,
            handover_type: HandoverType::IntraSystem5gs,
        }
    }

    /// Returns true if all PDU sessions have target tunnel info
    pub fn all_sessions_switched(&self) -> bool {
        self.pdu_sessions.iter().all(|s| s.target_teid.is_some())
    }

    /// Updates target tunnel info for a PDU session
    pub fn update_target_tunnel(
        &mut self,
        pdu_session_id: u8,
        teid: u32,
        ip: [u8; 4],
    ) -> bool {
        if let Some(s) = self.pdu_sessions.iter_mut().find(|s| s.pdu_session_id == pdu_session_id) {
            s.target_teid = Some(teid);
            s.target_ip = Some(ip);
            true
        } else {
            false
        }
    }
}

/// N2-based handover context (HandoverRequired → HandoverCommand → HandoverNotify)
#[derive(Debug, Clone)]
pub struct N2HandoverContext {
    pub amf_ue_ngap_id: u64,
    pub supi: String,
    pub source_gnb_id: u32,
    pub target_gnb_id: u32,
    pub cause: HandoverCause,
    pub state: HandoverState,
    pub pdu_sessions: Vec<PduSessionHandoverResource>,
}

/// Handover cause (subset of NGAP Cause IE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverCause {
    /// Radio network layer causes
    HandoverDesirable,
    TimeToTrigger,
    ResourceOptimisation,
    ReduceLoadInServingCell,
    /// Transport network layer
    TransportResourceUnavailable,
    /// NAS reason
    NasBecauseOfDl,
}

/// AMF handover manager: tracks active Xn and N2 handover contexts
#[derive(Debug, Default)]
pub struct AmfHandoverManager {
    /// Xn path switch contexts keyed by AMF UE NGAP ID
    xn_contexts: HashMap<u64, XnPathSwitchContext>,
    /// N2 handover contexts keyed by AMF UE NGAP ID
    n2_contexts: HashMap<u64, N2HandoverContext>,
}

impl AmfHandoverManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an Xn path switch context (on PathSwitchRequest)
    pub fn create_xn_context(&mut self, ctx: XnPathSwitchContext) {
        self.xn_contexts.insert(ctx.amf_ue_ngap_id, ctx);
    }

    /// Retrieves an Xn context mutably
    pub fn get_xn_context_mut(&mut self, amf_ue_ngap_id: u64) -> Option<&mut XnPathSwitchContext> {
        self.xn_contexts.get_mut(&amf_ue_ngap_id)
    }

    /// Completes an Xn handover: sets state to Complete and removes context
    pub fn complete_xn_handover(&mut self, amf_ue_ngap_id: u64) -> Option<XnPathSwitchContext> {
        if let Some(ctx) = self.xn_contexts.get_mut(&amf_ue_ngap_id) {
            ctx.state = HandoverState::Complete;
        }
        self.xn_contexts.remove(&amf_ue_ngap_id)
    }

    /// Creates an N2 handover context (on HandoverRequired)
    pub fn create_n2_context(&mut self, ctx: N2HandoverContext) {
        self.n2_contexts.insert(ctx.amf_ue_ngap_id, ctx);
    }

    /// Transitions N2 handover to execution phase (HandoverCommand sent)
    pub fn n2_start_execution(&mut self, amf_ue_ngap_id: u64) -> bool {
        if let Some(ctx) = self.n2_contexts.get_mut(&amf_ue_ngap_id) {
            ctx.state = HandoverState::Execution;
            true
        } else {
            false
        }
    }

    /// Completes N2 handover (HandoverNotify received)
    pub fn complete_n2_handover(&mut self, amf_ue_ngap_id: u64) -> Option<N2HandoverContext> {
        if let Some(ctx) = self.n2_contexts.get_mut(&amf_ue_ngap_id) {
            ctx.state = HandoverState::Complete;
        }
        self.n2_contexts.remove(&amf_ue_ngap_id)
    }

    /// Returns the count of active handovers
    pub fn active_count(&self) -> usize {
        self.xn_contexts.len() + self.n2_contexts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xn_path_switch_creation() {
        let ctx = XnPathSwitchContext::new(1001, 1, 2, "imsi-001011234567890".into());
        assert_eq!(ctx.state, HandoverState::Preparation);
        assert_eq!(ctx.handover_type, HandoverType::IntraSystem5gs);
    }

    #[test]
    fn test_xn_all_sessions_switched_empty() {
        let ctx = XnPathSwitchContext::new(1001, 1, 2, "supi".into());
        // no sessions → trivially all switched
        assert!(ctx.all_sessions_switched());
    }

    #[test]
    fn test_xn_update_target_tunnel() {
        let mut ctx = XnPathSwitchContext::new(1001, 1, 2, "supi".into());
        ctx.pdu_sessions.push(PduSessionHandoverResource {
            pdu_session_id: 5,
            source_teid: 100,
            source_ip: [10, 0, 0, 1],
            target_teid: None,
            target_ip: None,
        });
        assert!(!ctx.all_sessions_switched());
        assert!(ctx.update_target_tunnel(5, 200, [10, 0, 0, 2]));
        assert!(ctx.all_sessions_switched());
    }

    #[test]
    fn test_handover_manager_xn_lifecycle() {
        let mut mgr = AmfHandoverManager::new();
        let ctx = XnPathSwitchContext::new(42, 1, 2, "supi".into());
        mgr.create_xn_context(ctx);
        assert_eq!(mgr.active_count(), 1);
        let completed = mgr.complete_xn_handover(42).unwrap();
        assert_eq!(completed.state, HandoverState::Complete);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_handover_manager_n2_lifecycle() {
        let mut mgr = AmfHandoverManager::new();
        let ctx = N2HandoverContext {
            amf_ue_ngap_id: 99,
            supi: "supi".into(),
            source_gnb_id: 1,
            target_gnb_id: 3,
            cause: HandoverCause::HandoverDesirable,
            state: HandoverState::Preparation,
            pdu_sessions: vec![],
        };
        mgr.create_n2_context(ctx);
        assert!(mgr.n2_start_execution(99));
        let completed = mgr.complete_n2_handover(99).unwrap();
        assert_eq!(completed.state, HandoverState::Complete);
    }
}
