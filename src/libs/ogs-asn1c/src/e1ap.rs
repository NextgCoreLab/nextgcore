//! E1AP Protocol Codec (3GPP TS 38.463)
//!
//! E1 Application Protocol for the CU-CP to CU-UP interface within a
//! disaggregated gNB. Manages bearer context lifecycle and QoS flows.

use crate::per::{AperEncoder, AperDecoder, Constraint, PerError, PerResult};

// ============================================================================
// E1AP Procedure Codes
// ============================================================================

/// E1AP procedure codes (TS 38.463 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum E1ApProcedure {
    /// GNB-CU-CP E1 Setup.
    GnbCuCpE1Setup = 1,
    /// GNB-CU-UP E1 Setup.
    GnbCuUpE1Setup = 2,
    /// GNB-CU-UP Configuration Update.
    GnbCuUpConfigUpdate = 3,
    /// GNB-CU-CP Configuration Update.
    GnbCuCpConfigUpdate = 4,
    /// Bearer Context Setup.
    BearerContextSetup = 5,
    /// Bearer Context Modification.
    BearerContextModification = 6,
    /// Bearer Context Release.
    BearerContextRelease = 7,
    /// Bearer Context Release Request.
    BearerContextReleaseRequest = 8,
    /// Bearer Context Inactivity Notification.
    BearerContextInactivityNotification = 9,
    /// DL Data Notification.
    DlDataNotification = 10,
    /// UL Data Notification.
    UlDataNotification = 11,
    /// Data Usage Report.
    DataUsageReport = 12,
}

// ============================================================================
// E1AP Message Types
// ============================================================================

/// GNB-CU-UP E1 Setup Request.
#[derive(Debug, Clone)]
pub struct GnbCuUpE1SetupRequest {
    /// gNB-CU-UP ID.
    pub gnb_cu_up_id: u64,
    /// gNB-CU-UP name.
    pub gnb_cu_up_name: Option<String>,
    /// CN support (EPC, 5GC, or both).
    pub cn_support: CnSupport,
    /// Supported PLMNs.
    pub supported_plmns: Vec<SupportedPlmnItem>,
}

/// GNB-CU-UP E1 Setup Response.
#[derive(Debug, Clone)]
pub struct GnbCuUpE1SetupResponse {
    /// gNB-CU-CP name.
    pub gnb_cu_cp_name: Option<String>,
}

/// Bearer Context Setup Request.
#[derive(Debug, Clone)]
pub struct BearerContextSetupRequest {
    /// gNB-CU-CP UE E1AP ID.
    pub gnb_cu_cp_ue_e1ap_id: u32,
    /// Security information.
    pub security_info: SecurityInfo,
    /// UE DL Aggregate Maximum Bit Rate.
    pub ue_dl_aggregate_mbr: u64,
    /// Serving PLMN.
    pub serving_plmn: [u8; 3],
    /// PDU session resource to setup list.
    pub pdu_session_resources: Vec<PduSessionResourceToSetup>,
}

/// Bearer Context Setup Response.
#[derive(Debug, Clone)]
pub struct BearerContextSetupResponse {
    /// gNB-CU-CP UE E1AP ID.
    pub gnb_cu_cp_ue_e1ap_id: u32,
    /// gNB-CU-UP UE E1AP ID.
    pub gnb_cu_up_ue_e1ap_id: u32,
    /// PDU session resource setup list.
    pub pdu_session_resources_setup: Vec<PduSessionResourceSetup>,
}

/// Bearer Context Modification Request.
#[derive(Debug, Clone)]
pub struct BearerContextModificationRequest {
    /// gNB-CU-CP UE E1AP ID.
    pub gnb_cu_cp_ue_e1ap_id: u32,
    /// gNB-CU-UP UE E1AP ID.
    pub gnb_cu_up_ue_e1ap_id: u32,
    /// PDU session resources to modify.
    pub pdu_session_resources_to_modify: Vec<PduSessionResourceToModify>,
}

/// Bearer Context Release Command.
#[derive(Debug, Clone)]
pub struct BearerContextReleaseCommand {
    /// gNB-CU-CP UE E1AP ID.
    pub gnb_cu_cp_ue_e1ap_id: u32,
    /// gNB-CU-UP UE E1AP ID.
    pub gnb_cu_up_ue_e1ap_id: u32,
    /// Cause.
    pub cause: E1Cause,
}

// ============================================================================
// E1AP Supporting Types
// ============================================================================

/// CN Support type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnSupport {
    Epc,
    FiveGc,
    EpcAnd5Gc,
}

/// Supported PLMN item.
#[derive(Debug, Clone)]
pub struct SupportedPlmnItem {
    /// PLMN identity.
    pub plmn_id: [u8; 3],
    /// Slice support list.
    pub slice_support: Vec<SliceSupportItem>,
}

/// Slice support item.
#[derive(Debug, Clone, Copy)]
pub struct SliceSupportItem {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// Security information for bearer context.
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Security algorithm (ciphering).
    pub ciphering_algorithm: u8,
    /// Security algorithm (integrity).
    pub integrity_algorithm: u8,
    /// UP security key.
    pub up_security_key: Vec<u8>,
}

/// PDU session resource to setup.
#[derive(Debug, Clone)]
pub struct PduSessionResourceToSetup {
    /// PDU session ID.
    pub pdu_session_id: u8,
    /// PDU session type (IPv4, IPv6, etc.).
    pub pdu_session_type: u8,
    /// S-NSSAI.
    pub sst: u8,
    pub sd: Option<u32>,
    /// NG-U UP transport layer info (GTP tunnel).
    pub ng_ul_up_tnl_info: GtpTunnelInfo,
    /// DRB to setup list.
    pub drb_to_setup: Vec<DrbToSetup>,
}

/// PDU session resource setup result.
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetup {
    /// PDU session ID.
    pub pdu_session_id: u8,
    /// NG-DL UP transport layer info.
    pub ng_dl_up_tnl_info: GtpTunnelInfo,
    /// DRB setup list.
    pub drb_setup: Vec<DrbSetup>,
}

/// PDU session resource to modify.
#[derive(Debug, Clone)]
pub struct PduSessionResourceToModify {
    /// PDU session ID.
    pub pdu_session_id: u8,
    /// DRB to modify.
    pub drb_to_modify: Vec<DrbToModify>,
}

/// DRB to setup (in bearer context setup).
#[derive(Debug, Clone)]
pub struct DrbToSetup {
    /// DRB ID.
    pub drb_id: u8,
    /// PDCP configuration.
    pub pdcp_sn_size_ul: u8,
    pub pdcp_sn_size_dl: u8,
    /// QoS flows.
    pub qos_flows: Vec<QosFlowInfo>,
}

/// DRB setup result.
#[derive(Debug, Clone)]
pub struct DrbSetup {
    /// DRB ID.
    pub drb_id: u8,
    /// UL UP transport layer info.
    pub ul_up_tnl_info: GtpTunnelInfo,
}

/// DRB to modify.
#[derive(Debug, Clone)]
pub struct DrbToModify {
    /// DRB ID.
    pub drb_id: u8,
    /// New DL UP transport layer info.
    pub dl_up_tnl_info: Option<GtpTunnelInfo>,
}

/// GTP tunnel endpoint info.
#[derive(Debug, Clone)]
pub struct GtpTunnelInfo {
    /// Transport layer address (IPv4).
    pub transport_address: [u8; 4],
    /// GTP TEID.
    pub gtp_teid: u32,
}

/// QoS flow info.
#[derive(Debug, Clone, Copy)]
pub struct QosFlowInfo {
    /// QoS Flow Identifier.
    pub qfi: u8,
    /// 5QI.
    pub five_qi: u16,
    /// Priority level.
    pub priority: u8,
}

/// E1AP cause values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E1Cause {
    RadioNetwork(u8),
    Transport(u8),
    Protocol(u8),
    Misc(u8),
}

// ============================================================================
// E1AP Codec Functions
// ============================================================================

/// Encode a GNB-CU-UP E1 Setup Request.
pub fn encode_gnb_cu_up_e1_setup_request(msg: &GnbCuUpE1SetupRequest) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_whole_number(E1ApProcedure::GnbCuUpE1Setup as i64, &Constraint::new(0, 255))?;
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?; // Criticality
    encoder.encode_unconstrained_whole_number(msg.gnb_cu_up_id as i64)?;
    let cn = match msg.cn_support {
        CnSupport::Epc => 0,
        CnSupport::FiveGc => 1,
        CnSupport::EpcAnd5Gc => 2,
    };
    encoder.encode_constrained_whole_number(cn, &Constraint::new(0, 2))?;
    encoder.encode_constrained_whole_number(msg.supported_plmns.len() as i64, &Constraint::new(1, 12))?;
    for plmn in &msg.supported_plmns {
        encoder.encode_octet_string(&plmn.plmn_id, Some(3), Some(3))?;
    }
    Ok(encoder.into_bytes().to_vec())
}

/// Encode a Bearer Context Setup Request.
pub fn encode_bearer_context_setup_request(msg: &BearerContextSetupRequest) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_whole_number(E1ApProcedure::BearerContextSetup as i64, &Constraint::new(0, 255))?;
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?;
    encoder.encode_unconstrained_whole_number(msg.gnb_cu_cp_ue_e1ap_id as i64)?;
    encoder.encode_unconstrained_whole_number(msg.ue_dl_aggregate_mbr as i64)?;
    encoder.encode_octet_string(&msg.serving_plmn, Some(3), Some(3))?;
    encoder.encode_constrained_whole_number(msg.pdu_session_resources.len() as i64, &Constraint::new(1, 256))?;
    Ok(encoder.into_bytes().to_vec())
}

/// Decode E1AP procedure code.
pub fn decode_e1ap_procedure(data: &[u8]) -> PerResult<E1ApProcedure> {
    let mut decoder = AperDecoder::new(data);
    let code = decoder.decode_constrained_whole_number(&Constraint::new(0, 255))? as u8;
    match code {
        1 => Ok(E1ApProcedure::GnbCuCpE1Setup),
        2 => Ok(E1ApProcedure::GnbCuUpE1Setup),
        5 => Ok(E1ApProcedure::BearerContextSetup),
        6 => Ok(E1ApProcedure::BearerContextModification),
        7 => Ok(E1ApProcedure::BearerContextRelease),
        _ => Err(PerError::DecodeError(format!("Unknown E1AP procedure: {}", code))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e1ap_procedure_codes() {
        assert_eq!(E1ApProcedure::BearerContextSetup as u8, 5);
        assert_eq!(E1ApProcedure::BearerContextRelease as u8, 7);
    }

    #[test]
    fn test_gnb_cu_up_e1_setup_encode() {
        let msg = GnbCuUpE1SetupRequest {
            gnb_cu_up_id: 1,
            gnb_cu_up_name: Some("CU-UP-1".to_string()),
            cn_support: CnSupport::FiveGc,
            supported_plmns: vec![SupportedPlmnItem {
                plmn_id: [0x99, 0xF9, 0x07],
                slice_support: vec![SliceSupportItem { sst: 1, sd: None }],
            }],
        };
        let bytes = encode_gnb_cu_up_e1_setup_request(&msg).unwrap();
        assert!(!bytes.is_empty());

        let proc = decode_e1ap_procedure(&bytes).unwrap();
        assert_eq!(proc, E1ApProcedure::GnbCuUpE1Setup);
    }

    #[test]
    fn test_bearer_context_setup_encode() {
        let msg = BearerContextSetupRequest {
            gnb_cu_cp_ue_e1ap_id: 42,
            security_info: SecurityInfo {
                ciphering_algorithm: 0,
                integrity_algorithm: 2,
                up_security_key: vec![0; 32],
            },
            ue_dl_aggregate_mbr: 1_000_000_000,
            serving_plmn: [0x99, 0xF9, 0x07],
            pdu_session_resources: vec![PduSessionResourceToSetup {
                pdu_session_id: 1,
                pdu_session_type: 1,
                sst: 1,
                sd: None,
                ng_ul_up_tnl_info: GtpTunnelInfo {
                    transport_address: [10, 11, 0, 1],
                    gtp_teid: 0x00000001,
                },
                drb_to_setup: vec![DrbToSetup {
                    drb_id: 1,
                    pdcp_sn_size_ul: 18,
                    pdcp_sn_size_dl: 18,
                    qos_flows: vec![QosFlowInfo { qfi: 1, five_qi: 9, priority: 1 }],
                }],
            }],
        };
        let bytes = encode_bearer_context_setup_request(&msg).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_cn_support_values() {
        assert_ne!(CnSupport::Epc, CnSupport::FiveGc);
        assert_ne!(CnSupport::FiveGc, CnSupport::EpcAnd5Gc);
    }

    #[test]
    fn test_e1_cause() {
        let cause = E1Cause::RadioNetwork(0);
        assert_eq!(cause, E1Cause::RadioNetwork(0));
    }
}
