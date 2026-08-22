//! MME SGsAP Message Handling
//!
//! Port of src/mme/sgsap-handler.c - SGsAP message handling functions

use crate::sgsap_build::{ie_type, message_type, ServiceIndicator, SgsapCause};

/// Result type for SGsAP operations
pub type SgsapResult<T> = Result<T, SgsapError>;

/// Error type for SGsAP operations
#[derive(Debug, Clone)]
pub enum SgsapError {
    /// Invalid message format
    InvalidMessageFormat,
    /// Unknown message type
    UnknownMessageType(u8),
    /// Mandatory IE missing
    MandatoryIeMissing(String),
    /// Invalid IE value
    InvalidIeValue(String),
    /// Parse error
    ParseError(String),
}

impl std::fmt::Display for SgsapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessageFormat => write!(f, "Invalid message format"),
            Self::UnknownMessageType(t) => write!(f, "Unknown message type: {t}"),
            Self::MandatoryIeMissing(ie) => write!(f, "Mandatory IE missing: {ie}"),
            Self::InvalidIeValue(ie) => write!(f, "Invalid IE value: {ie}"),
            Self::ParseError(msg) => write!(f, "Parse error: {msg}"),
        }
    }
}

impl std::error::Error for SgsapError {}

// ============================================================================
// Parsed Data Structures
// ============================================================================

/// Location Update Accept data
#[derive(Debug, Clone, Default)]
pub struct LocationUpdateAcceptData {
    pub imsi: Vec<u8>,
    pub lai: Option<LaiData>,
    pub mobile_identity: Option<Vec<u8>>,
}

/// Location Update Reject data
#[derive(Debug, Clone, Default)]
pub struct LocationUpdateRejectData {
    pub imsi: Vec<u8>,
    pub reject_cause: u8,
    pub lai: Option<LaiData>,
}

/// LAI data
#[derive(Debug, Clone, Default)]
pub struct LaiData {
    pub plmn: [u8; 3],
    pub lac: u16,
}

/// Paging Request data
#[derive(Debug, Clone, Default)]
pub struct PagingRequestData {
    pub imsi: Vec<u8>,
    pub vlr_name: Option<String>,
    pub service_indicator: Option<ServiceIndicator>,
    pub tmsi: Option<Vec<u8>>,
    pub cli: Option<Vec<u8>>,
    pub lai: Option<LaiData>,
    pub global_cn_id: Option<Vec<u8>>,
    pub ss_code: Option<u8>,
    pub lcs_indicator: Option<u8>,
    pub lcs_client_identity: Option<Vec<u8>>,
    pub channel_needed: Option<u8>,
    pub emlpp_priority: Option<u8>,
    pub additional_paging_indicators: Option<u8>,
}

/// Downlink Unitdata data
#[derive(Debug, Clone, Default)]
pub struct DownlinkUnitdataData {
    pub imsi: Vec<u8>,
    pub nas_message_container: Vec<u8>,
}

/// EPS Detach Ack data
#[derive(Debug, Clone, Default)]
pub struct EpsDetachAckData {
    pub imsi: Vec<u8>,
}

/// IMSI Detach Ack data
#[derive(Debug, Clone, Default)]
pub struct ImsiDetachAckData {
    pub imsi: Vec<u8>,
}

/// Reset Indication data
#[derive(Debug, Clone, Default)]
pub struct ResetIndicationData {
    pub vlr_name: Option<String>,
}

/// Alert Request data
#[derive(Debug, Clone, Default)]
pub struct AlertRequestData {
    pub imsi: Vec<u8>,
}

/// MM Information Request data
#[derive(Debug, Clone, Default)]
pub struct MmInformationRequestData {
    pub imsi: Vec<u8>,
    pub mm_information: Option<Vec<u8>>,
}

/// Release Request data
#[derive(Debug, Clone, Default)]
pub struct ReleaseRequestData {
    pub imsi: Vec<u8>,
    pub sgs_cause: Option<SgsapCause>,
}

/// Service Abort Request data
#[derive(Debug, Clone, Default)]
pub struct ServiceAbortRequestData {
    pub imsi: Vec<u8>,
}

// ============================================================================
// Parsing Helpers
// ============================================================================

/// Parse TLV IE header
fn parse_tlv_header(data: &[u8]) -> Option<(u8, u8, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let ie_type = data[0];
    let length = data[1] as usize;
    if data.len() < 2 + length {
        return None;
    }
    Some((ie_type, length as u8, &data[2..2 + length]))
}

/// Parse LAI from bytes
fn parse_lai(data: &[u8]) -> Option<LaiData> {
    if data.len() < 5 {
        return None;
    }
    let mut plmn = [0u8; 3];
    plmn.copy_from_slice(&data[0..3]);
    let lac = u16::from_be_bytes([data[3], data[4]]);
    Some(LaiData { plmn, lac })
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle Location Update Accept
pub fn handle_location_update_accept(data: &[u8]) -> SgsapResult<LocationUpdateAcceptData> {
    if data.is_empty() || data[0] != message_type::LOCATION_UPDATE_ACCEPT {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = LocationUpdateAcceptData::default();
    let mut offset = 1; // Skip message type

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::LAI => {
                    result.lai = parse_lai(value);
                }
                ie_type::MOBILE_IDENTITY => {
                    result.mobile_identity = Some(value.to_vec());
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle Location Update Reject
pub fn handle_location_update_reject(data: &[u8]) -> SgsapResult<LocationUpdateRejectData> {
    if data.is_empty() || data[0] != message_type::LOCATION_UPDATE_REJECT {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = LocationUpdateRejectData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::REJECT_CAUSE => {
                    if !value.is_empty() {
                        result.reject_cause = value[0];
                    }
                }
                ie_type::LAI => {
                    result.lai = parse_lai(value);
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Act on an SGs Paging Request: page the UE for the CS domain (issue #47).
///
/// TS 29.118 §5.1.2 / TS 23.272: the VLR wants the UE for a terminating call or an
/// SMS. The parser below has existed all along with no action attached, so the
/// request was decoded and the call dropped.
///
/// Returns the number of eNBs paged; `None` when the IMSI names no UE this MME
/// holds, which the caller answers with an SGsAP-PAGING-REJECT.
pub fn process_paging_request(
    ctx: &crate::context::MmeContext,
    data: &[u8],
) -> SgsapResult<Option<usize>> {
    let request = handle_paging_request(data)?;

    // The IMSI arrives TBCD-encoded with a leading type octet, the same shape the
    // S6a path decodes.
    let imsi_bcd = tbcd_to_bcd(&request.imsi);
    let Some(mme_ue_id) = ctx.mme_ue_find_by_imsi(&imsi_bcd) else {
        log::warn!("SGs Paging Request for IMSI[{imsi_bcd}], which this MME does not hold");
        return Ok(None);
    };

    // The service indicator distinguishes a call from an SMS (TS 29.118 §9.4.17):
    // 0x01 = CS call, 0x02 = SMS.
    let paging_type =
        if request.service_indicator == Some(crate::sgsap_build::ServiceIndicator::Sms) {
            crate::context::PagingType::SmsService
        } else {
            crate::context::PagingType::CsCallService
        };
    log::info!("SGs paging IMSI[{imsi_bcd}] for {paging_type:?}");
    Ok(Some(crate::paging::page_ue(ctx, mme_ue_id, paging_type)))
}

/// Decode a TBCD-encoded IMSI, skipping the leading type octet if present.
fn tbcd_to_bcd(imsi: &[u8]) -> String {
    let mut out = String::with_capacity(imsi.len() * 2);
    for byte in imsi {
        let low = byte & 0x0f;
        let high = (byte >> 4) & 0x0f;
        if low < 10 {
            out.push((b'0' + low) as char);
        }
        if high < 10 {
            out.push((b'0' + high) as char);
        }
    }
    out
}

/// Handle Paging Request
pub fn handle_paging_request(data: &[u8]) -> SgsapResult<PagingRequestData> {
    if data.is_empty() || data[0] != message_type::PAGING_REQUEST {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = PagingRequestData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::VLR_NAME => {
                    result.vlr_name = String::from_utf8(value.to_vec()).ok();
                }
                ie_type::SERVICE_INDICATOR => {
                    if !value.is_empty() {
                        result.service_indicator = Some(match value[0] {
                            0x01 => ServiceIndicator::CsCall,
                            0x02 => ServiceIndicator::Sms,
                            _ => ServiceIndicator::CsCall,
                        });
                    }
                }
                ie_type::TMSI => {
                    result.tmsi = Some(value.to_vec());
                }
                ie_type::CLI => {
                    result.cli = Some(value.to_vec());
                }
                ie_type::LAI => {
                    result.lai = parse_lai(value);
                }
                ie_type::GLOBAL_CN_ID => {
                    result.global_cn_id = Some(value.to_vec());
                }
                ie_type::SS_CODE => {
                    if !value.is_empty() {
                        result.ss_code = Some(value[0]);
                    }
                }
                ie_type::LCS_INDICATOR => {
                    if !value.is_empty() {
                        result.lcs_indicator = Some(value[0]);
                    }
                }
                ie_type::LCS_CLIENT_IDENTITY => {
                    result.lcs_client_identity = Some(value.to_vec());
                }
                ie_type::CHANNEL_NEEDED => {
                    if !value.is_empty() {
                        result.channel_needed = Some(value[0]);
                    }
                }
                ie_type::EMLPP_PRIORITY => {
                    if !value.is_empty() {
                        result.emlpp_priority = Some(value[0]);
                    }
                }
                ie_type::ADDITIONAL_PAGING_INDICATORS => {
                    if !value.is_empty() {
                        result.additional_paging_indicators = Some(value[0]);
                    }
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle Downlink Unitdata
pub fn handle_downlink_unitdata(data: &[u8]) -> SgsapResult<DownlinkUnitdataData> {
    if data.is_empty() || data[0] != message_type::DOWNLINK_UNITDATA {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = DownlinkUnitdataData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::NAS_MESSAGE_CONTAINER => {
                    result.nas_message_container = value.to_vec();
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }
    if result.nas_message_container.is_empty() {
        return Err(SgsapError::MandatoryIeMissing(
            "NAS Message Container".to_string(),
        ));
    }

    Ok(result)
}

/// Handle EPS Detach Ack
pub fn handle_eps_detach_ack(data: &[u8]) -> SgsapResult<EpsDetachAckData> {
    if data.is_empty() || data[0] != message_type::EPS_DETACH_ACK {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = EpsDetachAckData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            if ie_type == ie_type::IMSI {
                result.imsi = value.to_vec();
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle IMSI Detach Ack
pub fn handle_imsi_detach_ack(data: &[u8]) -> SgsapResult<ImsiDetachAckData> {
    if data.is_empty() || data[0] != message_type::IMSI_DETACH_ACK {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = ImsiDetachAckData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            if ie_type == ie_type::IMSI {
                result.imsi = value.to_vec();
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle Reset Indication
pub fn handle_reset_indication(data: &[u8]) -> SgsapResult<ResetIndicationData> {
    if data.is_empty() || data[0] != message_type::RESET_INDICATION {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = ResetIndicationData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            if ie_type == ie_type::VLR_NAME {
                result.vlr_name = String::from_utf8(value.to_vec()).ok();
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    Ok(result)
}

/// Handle Alert Request
pub fn handle_alert_request(data: &[u8]) -> SgsapResult<AlertRequestData> {
    if data.is_empty() || data[0] != message_type::ALERT_REQUEST {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = AlertRequestData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            if ie_type == ie_type::IMSI {
                result.imsi = value.to_vec();
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle MM Information Request
pub fn handle_mm_information_request(data: &[u8]) -> SgsapResult<MmInformationRequestData> {
    if data.is_empty() || data[0] != message_type::MM_INFORMATION_REQUEST {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = MmInformationRequestData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::MM_INFORMATION => {
                    result.mm_information = Some(value.to_vec());
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle Release Request
pub fn handle_release_request(data: &[u8]) -> SgsapResult<ReleaseRequestData> {
    if data.is_empty() || data[0] != message_type::RELEASE_REQUEST {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = ReleaseRequestData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            match ie_type {
                ie_type::IMSI => {
                    result.imsi = value.to_vec();
                }
                ie_type::SGS_CAUSE => {
                    if !value.is_empty() {
                        result.sgs_cause = Some(SgsapCause::from(value[0]));
                    }
                }
                _ => {}
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

/// Handle Service Abort Request
pub fn handle_service_abort_request(data: &[u8]) -> SgsapResult<ServiceAbortRequestData> {
    if data.is_empty() || data[0] != message_type::SERVICE_ABORT_REQUEST {
        return Err(SgsapError::InvalidMessageFormat);
    }

    let mut result = ServiceAbortRequestData::default();
    let mut offset = 1;

    while offset < data.len() {
        if let Some((ie_type, length, value)) = parse_tlv_header(&data[offset..]) {
            if ie_type == ie_type::IMSI {
                result.imsi = value.to_vec();
            }
            offset += 2 + length as usize;
        } else {
            break;
        }
    }

    if result.imsi.is_empty() {
        return Err(SgsapError::MandatoryIeMissing("IMSI".to_string()));
    }

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_message(msg_type: u8, ies: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = vec![msg_type];
        for (ie_type, value) in ies {
            data.push(*ie_type);
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
        data
    }

    #[test]
    fn test_handle_location_update_accept() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let lai = [0x00, 0xf1, 0x10, 0x12, 0x34];
        let msg = build_test_message(
            message_type::LOCATION_UPDATE_ACCEPT,
            &[(ie_type::IMSI, &imsi), (ie_type::LAI, &lai)],
        );
        let result = handle_location_update_accept(&msg).unwrap();
        assert_eq!(result.imsi, imsi);
        assert!(result.lai.is_some());
        let lai_data = result.lai.unwrap();
        assert_eq!(lai_data.lac, 0x1234);
    }

    #[test]
    fn test_handle_location_update_reject() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_test_message(
            message_type::LOCATION_UPDATE_REJECT,
            &[(ie_type::IMSI, &imsi), (ie_type::REJECT_CAUSE, &[0x04])],
        );
        let result = handle_location_update_reject(&msg).unwrap();
        assert_eq!(result.imsi, imsi);
        assert_eq!(result.reject_cause, 0x04);
    }

    #[test]
    fn test_handle_paging_request() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_test_message(
            message_type::PAGING_REQUEST,
            &[
                (ie_type::IMSI, &imsi),
                (ie_type::SERVICE_INDICATOR, &[0x01]),
            ],
        );
        let result = handle_paging_request(&msg).unwrap();
        assert_eq!(result.imsi, imsi);
        assert_eq!(result.service_indicator, Some(ServiceIndicator::CsCall));
    }

    #[test]
    fn test_handle_downlink_unitdata() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let nas_msg = [0x07, 0x41, 0x01];
        let msg = build_test_message(
            message_type::DOWNLINK_UNITDATA,
            &[
                (ie_type::IMSI, &imsi),
                (ie_type::NAS_MESSAGE_CONTAINER, &nas_msg),
            ],
        );
        let result = handle_downlink_unitdata(&msg).unwrap();
        assert_eq!(result.imsi, imsi);
        assert_eq!(result.nas_message_container, nas_msg);
    }

    #[test]
    fn test_handle_reset_indication() {
        let vlr_name = b"vlr.example.com";
        let msg = build_test_message(
            message_type::RESET_INDICATION,
            &[(ie_type::VLR_NAME, vlr_name)],
        );
        let result = handle_reset_indication(&msg).unwrap();
        assert_eq!(result.vlr_name, Some("vlr.example.com".to_string()));
    }

    #[test]
    fn test_sgsap_error_display() {
        let err = SgsapError::MandatoryIeMissing("IMSI".to_string());
        assert!(err.to_string().contains("IMSI"));
    }

    #[test]
    fn test_sgs_paging_request_pages_the_ue_it_names() {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
            enb.supported_ta_list = vec![crate::context::EpsTai {
                plmn_id: crate::context::PlmnId::new("310", "410"),
                tac: 1,
            }];
        }
        let mme_ue_id = ctx.mme_ue_add(crate::context::NEXTGCORE_INVALID_POOL_ID);
        // IMSI 310410123456789 in TBCD.
        ctx.mme_ue_set_imsi(mme_ue_id, "310410123456789");
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.tai = crate::context::EpsTai {
                plmn_id: crate::context::PlmnId::new("310", "410"),
                tac: 1,
            };
        }

        // SGsAP-PAGING-REQUEST: message type, IMSI TLV, service indicator TLV.
        let imsi_tbcd = [0x13, 0x40, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9];
        let mut msg = vec![message_type::PAGING_REQUEST];
        msg.push(ie_type::IMSI);
        msg.push(imsi_tbcd.len() as u8);
        msg.extend_from_slice(&imsi_tbcd);
        msg.push(ie_type::SERVICE_INDICATOR);
        msg.push(1);
        msg.push(0x01); // CS call

        let paged = process_paging_request(&ctx, &msg).expect("a valid request");

        assert_eq!(paged, Some(1), "the serving eNB must be paged");
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            mme_ue.paging.type_,
            crate::context::PagingType::CsCallService
        );
        assert!(mme_ue.t3413.is_running());
    }

    #[test]
    fn test_sgs_paging_request_for_an_unknown_imsi_is_reported() {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let imsi_tbcd = [0x13, 0x40, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9];
        let mut msg = vec![message_type::PAGING_REQUEST];
        msg.push(ie_type::IMSI);
        msg.push(imsi_tbcd.len() as u8);
        msg.extend_from_slice(&imsi_tbcd);

        // None, not an error: the caller answers SGsAP-PAGING-REJECT.
        assert_eq!(process_paging_request(&ctx, &msg).unwrap(), None);
    }

    #[test]
    fn test_tbcd_to_bcd_decodes_an_imsi() {
        assert_eq!(
            tbcd_to_bcd(&[0x13, 0x40, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9]),
            "310410123456789"
        );
    }
}
