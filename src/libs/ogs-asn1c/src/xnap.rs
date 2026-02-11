//! XnAP Protocol Codec (3GPP TS 38.423)
//!
//! Inter-gNB signalling protocol for Xn interface. Supports handover
//! preparation, data forwarding, and dual connectivity procedures.

use crate::per::{AperEncoder, AperDecoder, Constraint, PerError, PerResult};

// ============================================================================
// XnAP Procedure Codes
// ============================================================================

/// XnAP procedure codes (TS 38.423 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XnApProcedure {
    /// Xn Setup procedure.
    XnSetup = 0,
    /// NG-RAN node configuration update.
    NgRanNodeConfigUpdate = 1,
    /// Handover Preparation.
    HandoverPreparation = 2,
    /// SN Status Transfer.
    SnStatusTransfer = 3,
    /// UE Context Release.
    UeContextRelease = 4,
    /// Handover Cancel.
    HandoverCancel = 5,
    /// Retrieve UE Context.
    RetrieveUeContext = 6,
    /// Data Forwarding Address Indication.
    DataForwardingAddressIndication = 7,
    /// Secondary RAT Data Usage Report.
    SecondaryRatDataUsageReport = 8,
    /// SNode Addition.
    SNodeAddition = 10,
    /// SNode Reconfiguration.
    SNodeReconfiguration = 11,
    /// SNode Modification.
    SNodeModification = 12,
    /// SNode Release.
    SNodeRelease = 13,
    /// SNode Change.
    SNodeChange = 14,
    /// Activity Notification.
    ActivityNotification = 15,
}

// ============================================================================
// XnAP Message Types
// ============================================================================

/// XnAP Handover Request.
#[derive(Debug, Clone)]
pub struct XnHandoverRequest {
    /// Source NG-RAN node UE XnAP ID.
    pub source_ue_xnap_id: u32,
    /// Target cell global ID.
    pub target_cell_id: u64,
    /// Cause.
    pub cause: XnCause,
    /// UE context info transfer (encoded).
    pub ue_context_info: Vec<u8>,
    /// UE security capabilities.
    pub ue_security_capabilities: UeSecurityCapabilities,
}

/// XnAP Handover Request Acknowledge.
#[derive(Debug, Clone)]
pub struct XnHandoverRequestAcknowledge {
    /// Source NG-RAN node UE XnAP ID.
    pub source_ue_xnap_id: u32,
    /// Target NG-RAN node UE XnAP ID.
    pub target_ue_xnap_id: u32,
    /// Target to source transparent container (encoded).
    pub target_to_source_container: Vec<u8>,
    /// PDU session resources admitted.
    pub admitted_resources: Vec<PduSessionResourceAdmitted>,
}

/// XnAP SN Addition Request (for Dual Connectivity).
#[derive(Debug, Clone)]
pub struct SnAdditionRequest {
    /// Master NG-RAN node UE XnAP ID.
    pub mn_ue_xnap_id: u32,
    /// SN UE Aggregate Maximum Bit Rate.
    pub sn_ue_ambr_ul: u64,
    pub sn_ue_ambr_dl: u64,
    /// PDU session resources to add.
    pub pdu_session_resources: Vec<PduSessionResourceToAdd>,
}

/// XnAP Xn Setup Request.
#[derive(Debug, Clone)]
pub struct XnSetupRequest {
    /// Global NG-RAN node ID.
    pub global_ng_ran_node_id: Vec<u8>,
    /// Tracking area identity list support.
    pub tai_support_list: Vec<TaiSupportItem>,
    /// Supported PLMN list.
    pub plmn_list: Vec<[u8; 3]>,
}

/// XnAP Xn Setup Response.
#[derive(Debug, Clone)]
pub struct XnSetupResponse {
    /// Global NG-RAN node ID.
    pub global_ng_ran_node_id: Vec<u8>,
    /// Tracking area identity list support.
    pub tai_support_list: Vec<TaiSupportItem>,
}

// ============================================================================
// XnAP Supporting Types
// ============================================================================

/// XnAP cause values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XnCause {
    RadioNetwork(XnCauseRadioNetwork),
    Transport(u8),
    Protocol(u8),
    Misc(u8),
}

/// XnAP radio network cause values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XnCauseRadioNetwork {
    Unspecified = 0,
    HandoverDesirable = 1,
    TimeCriticalHandover = 2,
    ResourceOptimization = 3,
    ReduceLoad = 4,
    PartialHandover = 5,
    UnknownNewEnbUeXnapId = 6,
    UnknownOldEnbUeXnapId = 7,
    CellNotAvailable = 8,
}

/// UE security capabilities.
#[derive(Debug, Clone, Copy)]
pub struct UeSecurityCapabilities {
    /// NR encryption algorithms (bitmap).
    pub nr_encryption: u16,
    /// NR integrity algorithms (bitmap).
    pub nr_integrity: u16,
    /// E-UTRA encryption algorithms (bitmap).
    pub eutra_encryption: u16,
    /// E-UTRA integrity algorithms (bitmap).
    pub eutra_integrity: u16,
}

/// PDU session resource admitted in handover.
#[derive(Debug, Clone)]
pub struct PduSessionResourceAdmitted {
    /// PDU session ID.
    pub pdu_session_id: u8,
    /// DL data forwarding GTP tunnel endpoint.
    pub dl_forwarding_teid: Option<u32>,
    /// DL data forwarding GTP transport address.
    pub dl_forwarding_addr: Option<[u8; 4]>,
}

/// PDU session resource to add for SN.
#[derive(Debug, Clone)]
pub struct PduSessionResourceToAdd {
    /// PDU session ID.
    pub pdu_session_id: u8,
    /// S-NSSAI SST.
    pub sst: u8,
    /// S-NSSAI SD.
    pub sd: Option<u32>,
    /// QoS flow QFI.
    pub qfi: u8,
}

/// Tracking Area Identity support item.
#[derive(Debug, Clone)]
pub struct TaiSupportItem {
    /// TAC (24-bit).
    pub tac: u32,
    /// PLMN identity.
    pub plmn_id: [u8; 3],
}

// ============================================================================
// XnAP Codec Functions
// ============================================================================

/// Encode an XnAP Handover Request.
pub fn encode_xn_handover_request(msg: &XnHandoverRequest) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    // Procedure code
    encoder.encode_constrained_whole_number(XnApProcedure::HandoverPreparation as i64, &Constraint::new(0, 255))?;
    // Criticality: reject
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?;
    // Source UE XnAP ID
    encoder.encode_unconstrained_whole_number(msg.source_ue_xnap_id as i64)?;
    // Target cell ID (36-bit NR Cell ID)
    encoder.encode_unconstrained_whole_number(msg.target_cell_id as i64)?;
    // UE context info (octet string)
    encoder.encode_octet_string(&msg.ue_context_info, None, None)?;
    Ok(encoder.into_bytes().to_vec())
}

/// Encode an XnAP Xn Setup Request.
pub fn encode_xn_setup_request(msg: &XnSetupRequest) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_whole_number(XnApProcedure::XnSetup as i64, &Constraint::new(0, 255))?;
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?; // Criticality
    encoder.encode_octet_string(&msg.global_ng_ran_node_id, None, None)?;
    encoder.encode_constrained_whole_number(msg.plmn_list.len() as i64, &Constraint::new(1, 12))?;
    for plmn in &msg.plmn_list {
        encoder.encode_octet_string(plmn, Some(3), Some(3))?;
    }
    Ok(encoder.into_bytes().to_vec())
}

/// Decode an XnAP message procedure code.
pub fn decode_xnap_procedure(data: &[u8]) -> PerResult<XnApProcedure> {
    let mut decoder = AperDecoder::new(data);
    let code = decoder.decode_constrained_whole_number(&Constraint::new(0, 255))? as u8;
    match code {
        0 => Ok(XnApProcedure::XnSetup),
        2 => Ok(XnApProcedure::HandoverPreparation),
        3 => Ok(XnApProcedure::SnStatusTransfer),
        4 => Ok(XnApProcedure::UeContextRelease),
        5 => Ok(XnApProcedure::HandoverCancel),
        10 => Ok(XnApProcedure::SNodeAddition),
        _ => Err(PerError::DecodeError(format!("Unknown XnAP procedure: {}", code))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xnap_procedure_codes() {
        assert_eq!(XnApProcedure::XnSetup as u8, 0);
        assert_eq!(XnApProcedure::HandoverPreparation as u8, 2);
        assert_eq!(XnApProcedure::SNodeAddition as u8, 10);
    }

    #[test]
    fn test_xn_setup_request_encode() {
        let msg = XnSetupRequest {
            global_ng_ran_node_id: vec![0x01, 0x02, 0x03],
            tai_support_list: vec![],
            plmn_list: vec![[0x99, 0xF9, 0x07]],
        };
        let bytes = encode_xn_setup_request(&msg).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_xn_handover_request_encode() {
        let msg = XnHandoverRequest {
            source_ue_xnap_id: 42,
            target_cell_id: 0x123456789,
            cause: XnCause::RadioNetwork(XnCauseRadioNetwork::HandoverDesirable),
            ue_context_info: vec![0xAA, 0xBB],
            ue_security_capabilities: UeSecurityCapabilities {
                nr_encryption: 0xE000,
                nr_integrity: 0xE000,
                eutra_encryption: 0xE000,
                eutra_integrity: 0xE000,
            },
        };
        let bytes = encode_xn_handover_request(&msg).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_decode_xnap_procedure() {
        let msg = XnSetupRequest {
            global_ng_ran_node_id: vec![0x01],
            tai_support_list: vec![],
            plmn_list: vec![[0x00, 0xF1, 0x10]],
        };
        let bytes = encode_xn_setup_request(&msg).unwrap();
        let proc = decode_xnap_procedure(&bytes).unwrap();
        assert_eq!(proc, XnApProcedure::XnSetup);
    }

    #[test]
    fn test_xn_cause() {
        let cause = XnCause::RadioNetwork(XnCauseRadioNetwork::ReduceLoad);
        assert!(matches!(cause, XnCause::RadioNetwork(XnCauseRadioNetwork::ReduceLoad)));
    }
}
