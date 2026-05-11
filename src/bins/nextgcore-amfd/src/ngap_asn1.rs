//! NGAP ASN.1 Encoding for AMF
//!
//! This module provides ASN.1 APER encoding for NGAP messages
//! using the ogs-ngap crate. This ensures wire compatibility with
//! the gNB (nextgsim-gnb) which also uses proper ASN.1 encoding.

use ogs_asn1c::ngap::cause::{
    Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport,
};
use ogs_ngap::{builder, parser, types::*, NgapMessage};

use crate::context::AmfContext;

/// Build an NG Setup Response PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB in response to a successful NG Setup Request.
/// The message follows 3GPP TS 38.413 Section 9.2.6.2.
pub fn build_ng_setup_response_asn1(ctx: &AmfContext) -> Option<Vec<u8>> {
    let amf_name = ctx.amf_name.as_deref().unwrap_or("AMF").to_string();

    let served_guami_list = ctx
        .served_guami
        .iter()
        .take(ctx.num_of_served_guami)
        .map(|guami| {
            let plmn_bytes = encode_plmn_id(&guami.plmn_id);
            ServedGuamiItem {
                guami: Guami {
                    plmn_identity: plmn_bytes,
                    amf_region_id: guami.amf_id.region,
                    amf_set_id: guami.amf_id.set,
                    amf_pointer: guami.amf_id.pointer,
                },
                backup_amf_name: None,
            }
        })
        .collect();

    let plmn_support_list = ctx
        .plmn_support
        .iter()
        .take(ctx.num_of_plmn_support)
        .map(|plmn_support| {
            let plmn_bytes = encode_plmn_id(&plmn_support.plmn_id);
            let slice_support_list = plmn_support
                .s_nssai
                .iter()
                .take(plmn_support.num_of_s_nssai)
                .map(|s_nssai| {
                    let sd = s_nssai.sd.map(|sd_val| {
                        [
                            ((sd_val >> 16) & 0xFF) as u8,
                            ((sd_val >> 8) & 0xFF) as u8,
                            (sd_val & 0xFF) as u8,
                        ]
                    });
                    SNssai {
                        sst: s_nssai.sst,
                        sd,
                    }
                })
                .collect();
            PlmnSupportItem {
                plmn_identity: plmn_bytes,
                slice_support_list,
            }
        })
        .collect();

    let msg = NgSetupResponse {
        amf_name,
        served_guami_list,
        relative_amf_capacity: ctx.relative_capacity,
        plmn_support_list,
    };

    match builder::build_ng_setup_response(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built NG Setup Response: {} bytes, hex: {:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(32)]
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Response: {e:?}");
            None
        }
    }
}

/// Build an NG Setup Failure PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB when NG Setup fails.
/// The message follows 3GPP TS 38.413 Section 9.2.6.3.
pub fn build_ng_setup_failure_asn1(
    cause_group: u8,
    cause_value: i64,
    time_to_wait: Option<u8>,
) -> Vec<u8> {
    let cause = build_cause(cause_group, cause_value);

    let ttw = time_to_wait.map(|ttw| match ttw {
        0 => TimeToWait::V1s,
        1 => TimeToWait::V2s,
        2 => TimeToWait::V5s,
        3 => TimeToWait::V10s,
        4 => TimeToWait::V20s,
        _ => TimeToWait::V60s,
    });

    let msg = NgSetupFailure {
        cause,
        time_to_wait: ttw,
        criticality_diagnostics: None,
    };

    match builder::build_ng_setup_failure(&msg) {
        Ok(bytes) => {
            log::debug!("Built NG Setup Failure: {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Failure: {e:?}");
            Vec::new()
        }
    }
}

/// Build Cause from group and value
fn build_cause(group: u8, value: i64) -> Cause {
    match group {
        0 => Cause::RadioNetwork(radio_network_cause(value as u8)),
        1 => Cause::Transport(transport_cause(value as u8)),
        2 => Cause::Nas(nas_cause(value as u8)),
        3 => Cause::Protocol(protocol_cause(value as u8)),
        4 => Cause::Misc(misc_cause(value as u8)),
        _ => Cause::Misc(CauseMisc::Unspecified),
    }
}

fn radio_network_cause(v: u8) -> CauseRadioNetwork {
    // SAFETY: CauseRadioNetwork is #[repr(u8)] with values 0..=46
    if v <= 46 {
        unsafe { std::mem::transmute(v) }
    } else {
        CauseRadioNetwork::Unspecified
    }
}

fn transport_cause(v: u8) -> CauseTransport {
    match v {
        0 => CauseTransport::TransportResourceUnavailable,
        _ => CauseTransport::Unspecified,
    }
}

fn nas_cause(v: u8) -> CauseNas {
    match v {
        0 => CauseNas::NormalRelease,
        1 => CauseNas::AuthenticationFailure,
        2 => CauseNas::Deregister,
        _ => CauseNas::Unspecified,
    }
}

fn protocol_cause(v: u8) -> CauseProtocol {
    // SAFETY: CauseProtocol is #[repr(u8)] with values 0..=6
    if v <= 6 {
        unsafe { std::mem::transmute(v) }
    } else {
        CauseProtocol::Unspecified
    }
}

fn misc_cause(v: u8) -> CauseMisc {
    // SAFETY: CauseMisc is #[repr(u8)] with values 0..=5
    if v <= 5 {
        unsafe { std::mem::transmute(v) }
    } else {
        CauseMisc::Unspecified
    }
}

/// Encode PLMN ID to 3-byte format per 3GPP TS 24.501
fn encode_plmn_id(plmn_id: &crate::context::PlmnId) -> [u8; 3] {
    let mut bytes = [0u8; 3];

    // Byte 0: MCC digit 2 (high nibble) | MCC digit 1 (low nibble)
    bytes[0] = (plmn_id.mcc2 << 4) | plmn_id.mcc1;

    // Byte 1: MNC digit 3 (high nibble) | MCC digit 3 (low nibble)
    // For 2-digit MNC, MNC digit 3 is 0xF
    bytes[1] = (plmn_id.mnc3 << 4) | plmn_id.mcc3;

    // Byte 2: MNC digit 2 (high nibble) | MNC digit 1 (low nibble)
    bytes[2] = (plmn_id.mnc2 << 4) | plmn_id.mnc1;

    bytes
}

/// Decode PLMN ID from 3 bytes
fn decode_plmn_id(bytes: &[u8]) -> crate::context::PlmnId {
    if bytes.len() < 3 {
        return crate::context::PlmnId::default();
    }

    crate::context::PlmnId {
        mcc1: bytes[0] & 0x0F,
        mcc2: (bytes[0] >> 4) & 0x0F,
        mcc3: bytes[1] & 0x0F,
        mnc1: bytes[2] & 0x0F,
        mnc2: (bytes[2] >> 4) & 0x0F,
        mnc3: (bytes[1] >> 4) & 0x0F,
    }
}

/// Decode an NG Setup Request from ASN.1 APER bytes
pub fn parse_ng_setup_request_asn1(data: &[u8]) -> Option<crate::ngap_handler::NgSetupRequest> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let req = match decoded {
        NgapMessage::NgSetupRequest(r) => r,
        _ => {
            log::error!("Expected NgSetupRequest");
            return None;
        }
    };

    let mut result = crate::ngap_handler::NgSetupRequest::default();
    result.global_ran_node_id_present = true;

    match &req.global_ran_node_id {
        GlobalRanNodeId::GlobalGnbId {
            plmn_identity,
            gnb_id,
            gnb_id_len,
        } => {
            result.plmn_id = decode_plmn_id(plmn_identity);
            result.gnb_id = *gnb_id;
            result.gnb_id_len = *gnb_id_len;
        }
        GlobalRanNodeId::GlobalNgEnbId { plmn_identity, .. } => {
            result.plmn_id = decode_plmn_id(plmn_identity);
        }
    }

    if let Some(name) = req.ran_node_name {
        result.ran_node_name = Some(name);
    }

    result.supported_ta_list = req
        .supported_ta_list
        .iter()
        .map(|ta_item| {
            let tac = ((ta_item.tac[0] as u32) << 16)
                | ((ta_item.tac[1] as u32) << 8)
                | (ta_item.tac[2] as u32);

            let bplmn_list: Vec<crate::context::BplmnEntry> = ta_item
                .broadcast_plmn_list
                .iter()
                .map(|bp| {
                    let plmn_id = decode_plmn_id(&bp.plmn_identity);
                    let s_nssai: Vec<crate::context::SNssai> = bp
                        .tai_slice_support_list
                        .iter()
                        .map(|slice| crate::context::SNssai {
                            sst: slice.sst,
                            sd: slice.sd.map(|sd| {
                                ((sd[0] as u32) << 16) | ((sd[1] as u32) << 8) | (sd[2] as u32)
                            }),
                        })
                        .collect();
                    crate::context::BplmnEntry {
                        plmn_id,
                        num_of_s_nssai: s_nssai.len(),
                        s_nssai,
                    }
                })
                .collect();

            crate::context::SupportedTa {
                tac,
                num_of_bplmn_list: bplmn_list.len(),
                bplmn_list,
            }
        })
        .collect();

    result.default_paging_drx = req.default_paging_drx as u8;

    Some(result)
}

/// Parsed Initial UE Message data
#[derive(Debug, Clone)]
pub struct InitialUeMessageData {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// PLMN ID from NR-CGI
    pub plmn_id: crate::context::PlmnId,
    /// NR Cell Identity (36 bits)
    pub nr_cell_identity: u64,
    /// TAC from TAI
    pub tac: u32,
    /// RRC Establishment Cause
    pub rrc_establishment_cause: u8,
    /// UE Context Request flag
    pub ue_context_request: bool,
}

/// Parse an Initial UE Message from ASN.1 APER bytes
pub fn parse_initial_ue_message_asn1(data: &[u8]) -> Option<InitialUeMessageData> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let msg = match decoded {
        NgapMessage::InitialUeMessage(m) => m,
        _ => {
            log::error!("Expected InitialUEMessage");
            return None;
        }
    };

    let (plmn_id, nr_cell_identity, tac) = match &msg.user_location_info {
        UserLocationInformation::Nr {
            nr_cgi_plmn,
            nr_cell_identity,
            tai_tac,
            ..
        } => {
            let plmn_id = decode_plmn_id(nr_cgi_plmn);
            let tac =
                ((tai_tac[0] as u32) << 16) | ((tai_tac[1] as u32) << 8) | (tai_tac[2] as u32);
            (plmn_id, *nr_cell_identity, tac)
        }
    };

    let rrc_establishment_cause = msg.rrc_establishment_cause as u8;
    let ue_context_request = msg.ue_context_request.unwrap_or(false);

    log::info!(
        "Parsed Initial UE Message: ran_ue_ngap_id={}, nas_pdu_len={}, plmn={}{}{}-{}{}{}, nci=0x{:x}, tac={}, cause={}",
        msg.ran_ue_ngap_id,
        msg.nas_pdu.len(),
        plmn_id.mcc1, plmn_id.mcc2, plmn_id.mcc3,
        plmn_id.mnc1, plmn_id.mnc2, if plmn_id.mnc3 == 0xF { "".to_string() } else { format!("{}", plmn_id.mnc3) },
        nr_cell_identity,
        tac,
        rrc_establishment_cause
    );

    Some(InitialUeMessageData {
        ran_ue_ngap_id: msg.ran_ue_ngap_id,
        nas_pdu: msg.nas_pdu,
        plmn_id,
        nr_cell_identity,
        tac,
        rrc_establishment_cause,
        ue_context_request,
    })
}

/// Build a Downlink NAS Transport PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB to deliver NAS messages to the UE.
/// The message follows 3GPP TS 38.413 Section 8.6.2.
pub fn build_downlink_nas_transport_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    nas_pdu: &[u8],
) -> Option<Vec<u8>> {
    let msg = DownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: nas_pdu.to_vec(),
    };

    match builder::build_downlink_nas_transport(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built Downlink NAS Transport: {} bytes, amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
                bytes.len(),
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                nas_pdu.len()
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode Downlink NAS Transport: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Setup Request with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB to establish PDU session resources.
/// The message follows 3GPP TS 38.413 Section 8.2.1.
pub fn build_pdu_session_resource_setup_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    s_nssai_sst: u8,
    s_nssai_sd: Option<u32>,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    let sd = s_nssai_sd.map(|sd_val| {
        [
            ((sd_val >> 16) & 0xFF) as u8,
            ((sd_val >> 8) & 0xFF) as u8,
            (sd_val & 0xFF) as u8,
        ]
    });

    let item = PduSessionResourceSetupItem {
        pdu_session_id,
        nas_pdu: None,
        s_nssai: SNssai {
            sst: s_nssai_sst,
            sd,
        },
        transfer: n2_sm_transfer.to_vec(),
    };

    let msg = PduSessionResourceSetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        pdu_session_list: vec![item],
        nas_pdu: nas_pdu.map(|p| p.to_vec()),
    };

    match builder::build_pdu_session_resource_setup_request(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Setup Request: {} bytes, amf_ue_ngap_id={}, psi={}",
                bytes.len(),
                amf_ue_ngap_id,
                pdu_session_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Setup Request: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Release Command with proper ASN.1 APER encoding
///
/// Sent by AMF to gNB to release PDU session resources.
pub fn build_pdu_session_resource_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_ids: &[u8],
) -> Option<Vec<u8>> {
    let pdu_session_list = pdu_session_ids
        .iter()
        .map(|&psi| PduSessionResourceReleaseItem {
            pdu_session_id: psi,
            transfer: vec![],
        })
        .collect();

    let msg = PduSessionResourceReleaseCommand {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: None,
        pdu_session_list,
    };

    match builder::build_pdu_session_resource_release_command(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Release Command: {} bytes, amf_ue_ngap_id={}, psi_count={}",
                bytes.len(), amf_ue_ngap_id, pdu_session_ids.len()
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Release Command: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Modify Request with proper ASN.1 APER encoding
///
/// Sent by AMF to gNB to modify PDU session resources (e.g., QoS changes).
/// The message follows 3GPP TS 38.413 Section 8.2.3.
pub fn build_pdu_session_resource_modify_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    let item = PduSessionResourceModifyItem {
        pdu_session_id,
        nas_pdu: nas_pdu.map(|p| p.to_vec()),
        transfer: n2_sm_transfer.to_vec(),
    };

    let msg = PduSessionResourceModifyRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        pdu_session_list: vec![item],
    };

    match builder::build_pdu_session_resource_modify_request(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Modify Request: {} bytes, amf_ue_ngap_id={}, psi={}",
                bytes.len(),
                amf_ue_ngap_id,
                pdu_session_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Modify Request: {e:?}");
            None
        }
    }
}

/// Parsed Uplink NAS Transport data
#[derive(Debug, Clone)]
pub struct UplinkNasTransportData {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
}

/// Parse an Uplink NAS Transport message from ASN.1 APER bytes
pub fn parse_uplink_nas_transport_asn1(data: &[u8]) -> Option<UplinkNasTransportData> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let msg = match decoded {
        NgapMessage::UplinkNasTransport(m) => m,
        _ => {
            log::error!("Expected UplinkNASTransport");
            return None;
        }
    };

    log::info!(
        "Parsed Uplink NAS Transport: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
        msg.amf_ue_ngap_id,
        msg.ran_ue_ngap_id,
        msg.nas_pdu.len()
    );

    Some(UplinkNasTransportData {
        amf_ue_ngap_id: msg.amf_ue_ngap_id,
        ran_ue_ngap_id: msg.ran_ue_ngap_id,
        nas_pdu: msg.nas_pdu,
    })
}

/// Build a Paging message with proper ASN.1 APER encoding
///
/// Sent by AMF to gNBs to page a UE in CM-IDLE state.
/// The message follows 3GPP TS 38.413 Section 8.7.2.
pub fn build_paging_asn1(
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
    plmn_id: &crate::context::PlmnId,
    tac: u32,
) -> Option<Vec<u8>> {
    let plmn_bytes = encode_plmn_id(plmn_id);

    let msg = Paging {
        ue_paging_identity: UePagingIdentity::FiveGSTmsi {
            amf_set_id,
            amf_pointer,
            tmsi,
        },
        tai_list: vec![TaiListItem {
            tai_plmn: plmn_bytes,
            tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
        }],
        paging_drx: None,
        paging_priority: None,
        ue_radio_capability: None,
        paging_origin: None,
        assistance_data: None,
    };

    match builder::build_paging(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built Paging: {} bytes, amf_set_id={}, tmsi=0x{:08x}, tac={}",
                bytes.len(),
                amf_set_id,
                tmsi,
                tac
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode Paging: {e:?}");
            None
        }
    }
}

/// Extract AMF UE NGAP ID from a UE Context Release Request
pub fn extract_amf_ue_ngap_id(data: &[u8]) -> Option<u64> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.amf_ue_ngap_id),
        Ok(_) => {
            log::warn!("Expected UeContextReleaseRequest");
            None
        }
        Err(e) => {
            log::warn!("Failed to extract AMF UE NGAP ID: {e}");
            None
        }
    }
}

/// Extract RAN UE NGAP ID from a UE Context Release Request
pub fn extract_ran_ue_ngap_id(data: &[u8]) -> Option<u32> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.ran_ue_ngap_id),
        Ok(_) => {
            log::warn!("Expected UeContextReleaseRequest");
            None
        }
        Err(e) => {
            log::warn!("Failed to extract RAN UE NGAP ID: {e}");
            None
        }
    }
}

/// Build a UE Context Release Command with proper ASN.1 APER encoding
pub fn build_ue_context_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
) -> Option<Vec<u8>> {
    let msg = UeContextReleaseCommand {
        ue_ngap_ids: UeNgapIds::Pair {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
        },
        cause: Cause::Nas(CauseNas::NormalRelease),
    };

    match builder::build_ue_context_release_command(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built UE Context Release Command: {} bytes, AMF UE NGAP ID={}, RAN UE NGAP ID={}",
                bytes.len(),
                amf_ue_ngap_id,
                ran_ue_ngap_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode UE Context Release Command: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AmfId, Guami, PlmnId, PlmnSupport, SNssai};

    fn create_test_context() -> AmfContext {
        let mut ctx = AmfContext::new();
        ctx.amf_name = Some("AMF-Test".to_string());
        ctx.relative_capacity = 255;
        ctx.num_of_served_guami = 1;
        ctx.served_guami.push(Guami {
            plmn_id: PlmnId::new("999", "70"),
            amf_id: AmfId {
                region: 2,
                set: 1,
                pointer: 0,
            },
        });
        ctx.num_of_plmn_support = 1;
        ctx.plmn_support.push(PlmnSupport {
            plmn_id: PlmnId::new("999", "70"),
            num_of_s_nssai: 1,
            s_nssai: vec![SNssai { sst: 1, sd: None }],
        });
        ctx
    }

    #[test]
    fn test_build_ng_setup_response_asn1() {
        let ctx = create_test_context();
        let response = build_ng_setup_response_asn1(&ctx);

        assert!(response.is_some());
        let bytes = response.unwrap();
        assert!(!bytes.is_empty());

        // Verify we can decode it back
        let decoded = parser::decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match decoded {
            NgapMessage::NgSetupResponse(resp) => {
                assert_eq!(resp.amf_name, "AMF-Test");
                assert_eq!(resp.relative_amf_capacity, 255);
            }
            _ => panic!("Expected NgSetupResponse"),
        }
    }

    #[test]
    fn test_build_ng_setup_failure_asn1() {
        let bytes = build_ng_setup_failure_asn1(4, 0, Some(2)); // Misc, Unspecified, 5s wait

        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match decoded {
            NgapMessage::NgSetupFailure(failure) => {
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V5s));
            }
            _ => panic!("Expected NgSetupFailure"),
        }
    }

    #[test]
    fn test_encode_plmn_id() {
        let plmn = PlmnId::new("999", "70");
        let bytes = encode_plmn_id(&plmn);

        // PLMN 999-70 should encode as:
        // Byte 0: MCC2 (9) << 4 | MCC1 (9) = 0x99
        // Byte 1: MNC3 (F) << 4 | MCC3 (9) = 0xF9
        // Byte 2: MNC2 (0) << 4 | MNC1 (7) = 0x07
        assert_eq!(bytes[0], 0x99);
        assert_eq!(bytes[1], 0xF9);
        assert_eq!(bytes[2], 0x07);
    }

    #[test]
    fn test_decode_plmn_id() {
        let bytes = [0x99, 0xF9, 0x70]; // PLMN 999-70
        let plmn = decode_plmn_id(&bytes);

        assert_eq!(plmn.mcc1, 9);
        assert_eq!(plmn.mcc2, 9);
        assert_eq!(plmn.mcc3, 9);
        assert_eq!(plmn.mnc1, 0);
        assert_eq!(plmn.mnc2, 7);
        assert_eq!(plmn.mnc3, 0xF); // 2-digit MNC indicator
    }
}
