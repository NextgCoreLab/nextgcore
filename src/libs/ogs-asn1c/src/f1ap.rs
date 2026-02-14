//! F1AP Protocol Codec (3GPP TS 38.473)
//!
//! F1 Application Protocol for the CU-DU interface within a disaggregated
//! gNB (O-RAN / RAN disaggregation). Supports UE context management,
//! RRC message transfer, and DU resource coordination.

use crate::per::{AperEncoder, AperDecoder, Constraint, PerError, PerResult};

// ============================================================================
// F1AP Procedure Codes
// ============================================================================

/// F1AP procedure codes (TS 38.473 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum F1ApProcedure {
    /// F1 Setup procedure.
    F1Setup = 1,
    /// gNB-DU Configuration Update.
    GnbDuConfigUpdate = 2,
    /// gNB-CU Configuration Update.
    GnbCuConfigUpdate = 3,
    /// UE Context Setup.
    UeContextSetup = 4,
    /// UE Context Release.
    UeContextRelease = 5,
    /// UE Context Modification.
    UeContextModification = 6,
    /// UE Context Release Request.
    UeContextReleaseRequest = 7,
    /// Initial UL RRC Message Transfer.
    InitialUlRrcMessageTransfer = 10,
    /// DL RRC Message Transfer.
    DlRrcMessageTransfer = 11,
    /// UL RRC Message Transfer.
    UlRrcMessageTransfer = 12,
    /// UE Inactivity Notification.
    UeInactivityNotification = 13,
    /// GNB-DU Resource Coordination.
    GnbDuResourceCoordination = 14,
    /// Paging.
    Paging = 20,
}

// ============================================================================
// F1AP Message Types
// ============================================================================

/// F1 Setup Request.
#[derive(Debug, Clone)]
pub struct F1SetupRequest {
    /// gNB-DU ID.
    pub gnb_du_id: u64,
    /// gNB-DU name.
    pub gnb_du_name: Option<String>,
    /// Served cells to add.
    pub served_cells: Vec<ServedCellInfo>,
    /// RRC version.
    pub rrc_version: RrcVersion,
}

/// F1 Setup Response.
#[derive(Debug, Clone)]
pub struct F1SetupResponse {
    /// gNB-CU name.
    pub gnb_cu_name: Option<String>,
    /// Cells to activate.
    pub cells_to_activate: Vec<CellToActivate>,
    /// RRC version.
    pub rrc_version: RrcVersion,
}

/// UE Context Setup Request.
#[derive(Debug, Clone)]
pub struct UeContextSetupRequest {
    /// gNB-CU UE F1AP ID.
    pub gnb_cu_ue_f1ap_id: u32,
    /// gNB-DU UE F1AP ID (if already allocated).
    pub gnb_du_ue_f1ap_id: Option<u32>,
    /// Serving cell ID (NR CGI).
    pub serving_cell_id: u64,
    /// CU to DU RRC Information.
    pub cu_to_du_rrc_info: Vec<u8>,
    /// SRB to setup list.
    pub srb_to_setup: Vec<SrbInfo>,
    /// DRB to setup list.
    pub drb_to_setup: Vec<DrbInfo>,
    /// RRC container (encoded RRC message).
    pub rrc_container: Option<Vec<u8>>,
}

/// UE Context Setup Response.
#[derive(Debug, Clone)]
pub struct UeContextSetupResponse {
    /// gNB-CU UE F1AP ID.
    pub gnb_cu_ue_f1ap_id: u32,
    /// gNB-DU UE F1AP ID.
    pub gnb_du_ue_f1ap_id: u32,
    /// DU to CU RRC Information.
    pub du_to_cu_rrc_info: Vec<u8>,
    /// DRBs setup list.
    pub drbs_setup: Vec<DrbSetupResult>,
    /// SRBs failed to setup.
    pub srbs_failed: Vec<u8>,
}

/// DL RRC Message Transfer.
#[derive(Debug, Clone)]
pub struct DlRrcMessageTransfer {
    /// gNB-CU UE F1AP ID.
    pub gnb_cu_ue_f1ap_id: u32,
    /// gNB-DU UE F1AP ID.
    pub gnb_du_ue_f1ap_id: u32,
    /// SRB ID (1 or 2).
    pub srb_id: u8,
    /// RRC container (encoded RRC message).
    pub rrc_container: Vec<u8>,
}

/// UL RRC Message Transfer.
#[derive(Debug, Clone)]
pub struct UlRrcMessageTransfer {
    /// gNB-CU UE F1AP ID.
    pub gnb_cu_ue_f1ap_id: u32,
    /// gNB-DU UE F1AP ID.
    pub gnb_du_ue_f1ap_id: u32,
    /// SRB ID.
    pub srb_id: u8,
    /// RRC container.
    pub rrc_container: Vec<u8>,
}

// ============================================================================
// F1AP Supporting Types
// ============================================================================

/// Served cell information from DU.
#[derive(Debug, Clone)]
pub struct ServedCellInfo {
    /// NR CGI.
    pub nr_cgi: u64,
    /// NR PCI.
    pub nr_pci: u16,
    /// 5GS TAC (24-bit).
    pub five_gs_tac: Option<u32>,
    /// NR ARFCN.
    pub nr_arfcn: u32,
    /// Served PLMN list.
    pub served_plmns: Vec<[u8; 3]>,
}

/// Cell to activate from CU.
#[derive(Debug, Clone)]
pub struct CellToActivate {
    /// NR CGI.
    pub nr_cgi: u64,
    /// NR PCI.
    pub nr_pci: Option<u16>,
}

/// RRC version.
#[derive(Debug, Clone, Copy)]
pub struct RrcVersion {
    pub latest_rrc_version: u8,
}

impl Default for RrcVersion {
    fn default() -> Self {
        Self { latest_rrc_version: 16 } // NR Rel-16
    }
}

/// Signalling Radio Bearer info.
#[derive(Debug, Clone)]
pub struct SrbInfo {
    pub srb_id: u8,
}

/// Data Radio Bearer info.
#[derive(Debug, Clone)]
pub struct DrbInfo {
    pub drb_id: u8,
    pub qfi: u8,
    pub five_qi: u16,
    pub priority: u8,
}

/// DRB setup result.
#[derive(Debug, Clone)]
pub struct DrbSetupResult {
    pub drb_id: u8,
    pub dl_up_tnl_info: Option<GtpTunnelInfo>,
}

/// GTP tunnel endpoint info.
#[derive(Debug, Clone)]
pub struct GtpTunnelInfo {
    pub transport_address: [u8; 4],
    pub gtp_teid: u32,
}

// ============================================================================
// F1AP Codec Functions
// ============================================================================

/// Encode an F1 Setup Request.
pub fn encode_f1_setup_request(msg: &F1SetupRequest) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    // Procedure code
    encoder.encode_constrained_whole_number(F1ApProcedure::F1Setup as i64, &Constraint::new(0, 255))?;
    // Criticality: reject
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?;
    // gNB-DU ID
    encoder.encode_unconstrained_whole_number(msg.gnb_du_id as i64)?;
    // Served cells count
    encoder.encode_constrained_whole_number(msg.served_cells.len() as i64, &Constraint::new(1, 512))?;
    for cell in &msg.served_cells {
        encoder.encode_unconstrained_whole_number(cell.nr_cgi as i64)?;
        encoder.encode_constrained_whole_number(cell.nr_pci as i64, &Constraint::new(0, 1007))?;
        encoder.encode_constrained_whole_number(cell.nr_arfcn as i64, &Constraint::new(0, 3279165))?;
    }
    Ok(encoder.into_bytes().to_vec())
}

/// Encode a DL RRC Message Transfer.
pub fn encode_dl_rrc_message_transfer(msg: &DlRrcMessageTransfer) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_whole_number(F1ApProcedure::DlRrcMessageTransfer as i64, &Constraint::new(0, 255))?;
    encoder.encode_constrained_whole_number(0, &Constraint::new(0, 2))?;
    encoder.encode_unconstrained_whole_number(msg.gnb_cu_ue_f1ap_id as i64)?;
    encoder.encode_unconstrained_whole_number(msg.gnb_du_ue_f1ap_id as i64)?;
    encoder.encode_constrained_whole_number(msg.srb_id as i64, &Constraint::new(0, 3))?;
    encoder.encode_octet_string(&msg.rrc_container, None, None)?;
    Ok(encoder.into_bytes().to_vec())
}

/// Decode F1AP procedure code from a message.
pub fn decode_f1ap_procedure(data: &[u8]) -> PerResult<F1ApProcedure> {
    let mut decoder = AperDecoder::new(data);
    let code = decoder.decode_constrained_whole_number(&Constraint::new(0, 255))? as u8;
    match code {
        1 => Ok(F1ApProcedure::F1Setup),
        4 => Ok(F1ApProcedure::UeContextSetup),
        5 => Ok(F1ApProcedure::UeContextRelease),
        6 => Ok(F1ApProcedure::UeContextModification),
        10 => Ok(F1ApProcedure::InitialUlRrcMessageTransfer),
        11 => Ok(F1ApProcedure::DlRrcMessageTransfer),
        12 => Ok(F1ApProcedure::UlRrcMessageTransfer),
        20 => Ok(F1ApProcedure::Paging),
        _ => Err(PerError::DecodeError(format!("Unknown F1AP procedure: {code}"))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f1ap_procedure_codes() {
        assert_eq!(F1ApProcedure::F1Setup as u8, 1);
        assert_eq!(F1ApProcedure::UeContextSetup as u8, 4);
        assert_eq!(F1ApProcedure::DlRrcMessageTransfer as u8, 11);
    }

    #[test]
    fn test_f1_setup_request_encode() {
        let msg = F1SetupRequest {
            gnb_du_id: 1,
            gnb_du_name: Some("DU-1".to_string()),
            served_cells: vec![ServedCellInfo {
                nr_cgi: 0x123456789,
                nr_pci: 100,
                five_gs_tac: Some(1),
                nr_arfcn: 632628,
                served_plmns: vec![[0x99, 0xF9, 0x07]],
            }],
            rrc_version: RrcVersion::default(),
        };
        let bytes = encode_f1_setup_request(&msg).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_dl_rrc_message_transfer_encode() {
        let msg = DlRrcMessageTransfer {
            gnb_cu_ue_f1ap_id: 1,
            gnb_du_ue_f1ap_id: 1,
            srb_id: 1,
            rrc_container: vec![0x7e, 0x00, 0x56],
        };
        let bytes = encode_dl_rrc_message_transfer(&msg).unwrap();
        assert!(!bytes.is_empty());

        let proc = decode_f1ap_procedure(&bytes).unwrap();
        assert_eq!(proc, F1ApProcedure::DlRrcMessageTransfer);
    }

    #[test]
    fn test_rrc_version_default() {
        let ver = RrcVersion::default();
        assert_eq!(ver.latest_rrc_version, 16);
    }
}
