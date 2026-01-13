//! MME SGsAP Message Building
//!
//! Port of src/mme/sgsap-build.c - SGsAP message building functions


// ============================================================================
// SGsAP Message Types
// ============================================================================

/// SGsAP message types
pub mod message_type {
    pub const PAGING_REQUEST: u8 = 0x01;
    pub const PAGING_REJECT: u8 = 0x02;
    pub const SERVICE_REQUEST: u8 = 0x06;
    pub const DOWNLINK_UNITDATA: u8 = 0x07;
    pub const UPLINK_UNITDATA: u8 = 0x08;
    pub const LOCATION_UPDATE_REQUEST: u8 = 0x09;
    pub const LOCATION_UPDATE_ACCEPT: u8 = 0x0a;
    pub const LOCATION_UPDATE_REJECT: u8 = 0x0b;
    pub const TMSI_REALLOCATION_COMPLETE: u8 = 0x0c;
    pub const ALERT_REQUEST: u8 = 0x0d;
    pub const ALERT_ACK: u8 = 0x0e;
    pub const ALERT_REJECT: u8 = 0x0f;
    pub const UE_ACTIVITY_INDICATION: u8 = 0x10;
    pub const EPS_DETACH_INDICATION: u8 = 0x11;
    pub const EPS_DETACH_ACK: u8 = 0x12;
    pub const IMSI_DETACH_INDICATION: u8 = 0x13;
    pub const IMSI_DETACH_ACK: u8 = 0x14;
    pub const RESET_INDICATION: u8 = 0x15;
    pub const RESET_ACK: u8 = 0x16;
    pub const SERVICE_ABORT_REQUEST: u8 = 0x17;
    pub const MO_CSFB_INDICATION: u8 = 0x18;
    pub const MM_INFORMATION_REQUEST: u8 = 0x1a;
    pub const RELEASE_REQUEST: u8 = 0x1b;
    pub const STATUS: u8 = 0x1d;
    pub const UE_UNREACHABLE: u8 = 0x1f;
}

// ============================================================================
// SGsAP IE Types
// ============================================================================

/// SGsAP IE types
pub mod ie_type {
    pub const IMSI: u8 = 0x01;
    pub const VLR_NAME: u8 = 0x02;
    pub const TMSI: u8 = 0x03;
    pub const LAI: u8 = 0x04;
    pub const CHANNEL_NEEDED: u8 = 0x05;
    pub const EMLPP_PRIORITY: u8 = 0x06;
    pub const TMSI_STATUS: u8 = 0x07;
    pub const SGS_CAUSE: u8 = 0x08;
    pub const MME_NAME: u8 = 0x09;
    pub const EPS_LOCATION_UPDATE_TYPE: u8 = 0x0a;
    pub const GLOBAL_CN_ID: u8 = 0x0b;
    pub const MOBILE_IDENTITY: u8 = 0x0e;
    pub const REJECT_CAUSE: u8 = 0x0f;
    pub const IMSI_DETACH_FROM_EPS_SERVICE_TYPE: u8 = 0x10;
    pub const IMSI_DETACH_FROM_NON_EPS_SERVICE_TYPE: u8 = 0x11;
    pub const IMEISV: u8 = 0x15;
    pub const NAS_MESSAGE_CONTAINER: u8 = 0x16;
    pub const MM_INFORMATION: u8 = 0x17;
    pub const ERRONEOUS_MESSAGE: u8 = 0x1b;
    pub const CLI: u8 = 0x1c;
    pub const LCS_CLIENT_IDENTITY: u8 = 0x1d;
    pub const LCS_INDICATOR: u8 = 0x1e;
    pub const SS_CODE: u8 = 0x1f;
    pub const SERVICE_INDICATOR: u8 = 0x20;
    pub const UE_TIME_ZONE: u8 = 0x21;
    pub const MOBILE_STATION_CLASSMARK_2: u8 = 0x22;
    pub const TAI: u8 = 0x23;
    pub const E_CGI: u8 = 0x24;
    pub const UE_EMM_MODE: u8 = 0x25;
    pub const ADDITIONAL_PAGING_INDICATORS: u8 = 0x26;
    pub const TMSI_BASED_NRI_CONTAINER: u8 = 0x27;
    pub const SELECTED_CS_DOMAIN_OPERATOR: u8 = 0x28;
}

// ============================================================================
// SGsAP Cause Values
// ============================================================================

/// SGsAP cause values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SgsapCause {
    #[default]
    ImsiDetachedForEpsServices = 0x02,
    ImsiDetachedForEpsAndNonEpsServices = 0x03,
    ImsiUnknown = 0x04,
    ImsiDetachedForNonEpsServices = 0x05,
    ImsiImplicitlyDetachedForNonEpsServices = 0x06,
    UeUnreachable = 0x07,
    MessageNotCompatibleWithProtocolState = 0x08,
    MissingMandatoryIe = 0x09,
    InvalidMandatoryInformation = 0x0a,
    ConditionalIeError = 0x0b,
    SemanticallyIncorrectMessage = 0x0c,
    MessageUnknown = 0x0d,
    MtCsfbCallRejectedByUser = 0x0e,
    UeTemporarilyUnreachable = 0x0f,
}

impl From<u8> for SgsapCause {
    fn from(value: u8) -> Self {
        match value {
            0x02 => SgsapCause::ImsiDetachedForEpsServices,
            0x03 => SgsapCause::ImsiDetachedForEpsAndNonEpsServices,
            0x04 => SgsapCause::ImsiUnknown,
            0x05 => SgsapCause::ImsiDetachedForNonEpsServices,
            0x06 => SgsapCause::ImsiImplicitlyDetachedForNonEpsServices,
            0x07 => SgsapCause::UeUnreachable,
            0x08 => SgsapCause::MessageNotCompatibleWithProtocolState,
            0x09 => SgsapCause::MissingMandatoryIe,
            0x0a => SgsapCause::InvalidMandatoryInformation,
            0x0b => SgsapCause::ConditionalIeError,
            0x0c => SgsapCause::SemanticallyIncorrectMessage,
            0x0d => SgsapCause::MessageUnknown,
            0x0e => SgsapCause::MtCsfbCallRejectedByUser,
            0x0f => SgsapCause::UeTemporarilyUnreachable,
            _ => SgsapCause::ImsiDetachedForEpsServices,
        }
    }
}


// ============================================================================
// EPS Location Update Type
// ============================================================================

/// EPS location update type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EpsLocationUpdateType {
    #[default]
    ImsiAttach = 0x01,
    NormalLocationUpdate = 0x02,
}

// ============================================================================
// Service Indicator
// ============================================================================

/// Service indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ServiceIndicator {
    #[default]
    CsCall = 0x01,
    Sms = 0x02,
}

// ============================================================================
// UE EMM Mode
// ============================================================================

/// UE EMM mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum UeEmmMode {
    #[default]
    EmmIdle = 0x00,
    EmmConnected = 0x01,
}

// ============================================================================
// SGsAP Buffer Helper
// ============================================================================

/// Buffer for building SGsAP messages
#[derive(Debug, Clone)]
pub struct SgsapBuffer {
    data: Vec<u8>,
}

impl SgsapBuffer {
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(512) }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn write_u16_be(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u32_be(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Write TLV IE
    pub fn write_tlv(&mut self, ie_type: u8, value: &[u8]) {
        self.write_u8(ie_type);
        self.write_u8(value.len() as u8);
        self.write_bytes(value);
    }

    /// Write IMSI IE
    pub fn write_imsi(&mut self, imsi: &[u8]) {
        self.write_tlv(ie_type::IMSI, imsi);
    }

    /// Write MME Name IE
    pub fn write_mme_name(&mut self, mme_name: &str) {
        self.write_tlv(ie_type::MME_NAME, mme_name.as_bytes());
    }

    /// Write EPS Location Update Type IE
    pub fn write_eps_location_update_type(&mut self, update_type: EpsLocationUpdateType) {
        self.write_tlv(ie_type::EPS_LOCATION_UPDATE_TYPE, &[update_type as u8]);
    }


    /// Write LAI IE
    pub fn write_lai(&mut self, plmn: &[u8; 3], lac: u16) {
        let mut lai = [0u8; 5];
        lai[0..3].copy_from_slice(plmn);
        lai[3..5].copy_from_slice(&lac.to_be_bytes());
        self.write_tlv(ie_type::LAI, &lai);
    }

    /// Write TAI IE
    pub fn write_tai(&mut self, plmn: &[u8; 3], tac: u16) {
        let mut tai = [0u8; 5];
        tai[0..3].copy_from_slice(plmn);
        tai[3..5].copy_from_slice(&tac.to_be_bytes());
        self.write_tlv(ie_type::TAI, &tai);
    }

    /// Write E-CGI IE
    pub fn write_ecgi(&mut self, plmn: &[u8; 3], cell_id: u32) {
        let mut ecgi = [0u8; 7];
        ecgi[0..3].copy_from_slice(plmn);
        ecgi[3..7].copy_from_slice(&cell_id.to_be_bytes());
        self.write_tlv(ie_type::E_CGI, &ecgi);
    }

    /// Write SGS Cause IE
    pub fn write_sgs_cause(&mut self, cause: SgsapCause) {
        self.write_tlv(ie_type::SGS_CAUSE, &[cause as u8]);
    }

    /// Write Service Indicator IE
    pub fn write_service_indicator(&mut self, indicator: ServiceIndicator) {
        self.write_tlv(ie_type::SERVICE_INDICATOR, &[indicator as u8]);
    }

    /// Write UE EMM Mode IE
    pub fn write_ue_emm_mode(&mut self, mode: UeEmmMode) {
        self.write_tlv(ie_type::UE_EMM_MODE, &[mode as u8]);
    }

    /// Write NAS Message Container IE
    pub fn write_nas_message_container(&mut self, nas_msg: &[u8]) {
        self.write_tlv(ie_type::NAS_MESSAGE_CONTAINER, nas_msg);
    }

    /// Write Mobile Identity IE
    pub fn write_mobile_identity(&mut self, identity: &[u8]) {
        self.write_tlv(ie_type::MOBILE_IDENTITY, identity);
    }

    /// Write Reject Cause IE
    pub fn write_reject_cause(&mut self, cause: u8) {
        self.write_tlv(ie_type::REJECT_CAUSE, &[cause]);
    }
}

impl Default for SgsapBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Build Functions
// ============================================================================

/// Build Location Update Request
pub fn build_location_update_request(
    imsi: &[u8],
    mme_name: &str,
    update_type: EpsLocationUpdateType,
    plmn: &[u8; 3],
    lac: u16,
    tac: u16,
    cell_id: u32,
) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::LOCATION_UPDATE_REQUEST);
    buf.write_imsi(imsi);
    buf.write_mme_name(mme_name);
    buf.write_eps_location_update_type(update_type);
    buf.write_lai(plmn, lac);
    buf.write_tai(plmn, tac);
    buf.write_ecgi(plmn, cell_id);
    buf.data().to_vec()
}

/// Build TMSI Reallocation Complete
pub fn build_tmsi_reallocation_complete(imsi: &[u8]) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::TMSI_REALLOCATION_COMPLETE);
    buf.write_imsi(imsi);
    buf.data().to_vec()
}


/// Build UE Activity Indication
pub fn build_ue_activity_indication(imsi: &[u8]) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::UE_ACTIVITY_INDICATION);
    buf.write_imsi(imsi);
    buf.data().to_vec()
}

/// Build EPS Detach Indication
pub fn build_eps_detach_indication(
    imsi: &[u8],
    mme_name: &str,
    detach_type: u8,
) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::EPS_DETACH_INDICATION);
    buf.write_imsi(imsi);
    buf.write_mme_name(mme_name);
    buf.write_tlv(ie_type::IMSI_DETACH_FROM_EPS_SERVICE_TYPE, &[detach_type]);
    buf.data().to_vec()
}

/// Build IMSI Detach Indication
pub fn build_imsi_detach_indication(
    imsi: &[u8],
    mme_name: &str,
    detach_type: u8,
) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::IMSI_DETACH_INDICATION);
    buf.write_imsi(imsi);
    buf.write_mme_name(mme_name);
    buf.write_tlv(ie_type::IMSI_DETACH_FROM_NON_EPS_SERVICE_TYPE, &[detach_type]);
    buf.data().to_vec()
}

/// Build Paging Reject
pub fn build_paging_reject(imsi: &[u8], cause: SgsapCause) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::PAGING_REJECT);
    buf.write_imsi(imsi);
    buf.write_sgs_cause(cause);
    buf.data().to_vec()
}

/// Build Service Request
pub fn build_service_request(
    imsi: &[u8],
    service_indicator: ServiceIndicator,
    ue_emm_mode: UeEmmMode,
) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::SERVICE_REQUEST);
    buf.write_imsi(imsi);
    buf.write_service_indicator(service_indicator);
    buf.write_ue_emm_mode(ue_emm_mode);
    buf.data().to_vec()
}

/// Build Uplink Unitdata
pub fn build_uplink_unitdata(imsi: &[u8], nas_msg: &[u8]) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::UPLINK_UNITDATA);
    buf.write_imsi(imsi);
    buf.write_nas_message_container(nas_msg);
    buf.data().to_vec()
}

/// Build MO CSFB Indication
pub fn build_mo_csfb_indication(imsi: &[u8]) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::MO_CSFB_INDICATION);
    buf.write_imsi(imsi);
    buf.data().to_vec()
}

/// Build Alert Ack
pub fn build_alert_ack(imsi: &[u8]) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::ALERT_ACK);
    buf.write_imsi(imsi);
    buf.data().to_vec()
}

/// Build Alert Reject
pub fn build_alert_reject(imsi: &[u8], cause: SgsapCause) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::ALERT_REJECT);
    buf.write_imsi(imsi);
    buf.write_sgs_cause(cause);
    buf.data().to_vec()
}

/// Build Reset Ack
pub fn build_reset_ack(mme_name: &str) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::RESET_ACK);
    buf.write_mme_name(mme_name);
    buf.data().to_vec()
}

/// Build UE Unreachable
pub fn build_ue_unreachable(imsi: &[u8], cause: SgsapCause) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::UE_UNREACHABLE);
    buf.write_imsi(imsi);
    buf.write_sgs_cause(cause);
    buf.data().to_vec()
}

/// Build Release Request
pub fn build_release_request(imsi: &[u8], cause: SgsapCause) -> Vec<u8> {
    let mut buf = SgsapBuffer::new();
    buf.write_u8(message_type::RELEASE_REQUEST);
    buf.write_imsi(imsi);
    buf.write_sgs_cause(cause);
    buf.data().to_vec()
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgsap_buffer() {
        let mut buf = SgsapBuffer::new();
        buf.write_u8(0x01);
        buf.write_u16_be(0x0203);
        assert_eq!(buf.data(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_build_location_update_request() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let plmn = [0x00, 0xf1, 0x10];
        let msg = build_location_update_request(
            &imsi,
            "mme.example.com",
            EpsLocationUpdateType::ImsiAttach,
            &plmn,
            0x1234,
            0x5678,
            0x12345678,
        );
        assert_eq!(msg[0], message_type::LOCATION_UPDATE_REQUEST);
        assert_eq!(msg[1], ie_type::IMSI);
    }

    #[test]
    fn test_build_tmsi_reallocation_complete() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_tmsi_reallocation_complete(&imsi);
        assert_eq!(msg[0], message_type::TMSI_REALLOCATION_COMPLETE);
        assert_eq!(msg[1], ie_type::IMSI);
    }

    #[test]
    fn test_build_ue_activity_indication() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_ue_activity_indication(&imsi);
        assert_eq!(msg[0], message_type::UE_ACTIVITY_INDICATION);
    }

    #[test]
    fn test_build_paging_reject() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_paging_reject(&imsi, SgsapCause::ImsiUnknown);
        assert_eq!(msg[0], message_type::PAGING_REJECT);
    }

    #[test]
    fn test_build_service_request() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let msg = build_service_request(&imsi, ServiceIndicator::CsCall, UeEmmMode::EmmIdle);
        assert_eq!(msg[0], message_type::SERVICE_REQUEST);
    }

    #[test]
    fn test_build_uplink_unitdata() {
        let imsi = [0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let nas_msg = [0x07, 0x41, 0x01];
        let msg = build_uplink_unitdata(&imsi, &nas_msg);
        assert_eq!(msg[0], message_type::UPLINK_UNITDATA);
    }

    #[test]
    fn test_sgsap_cause_from_u8() {
        assert_eq!(SgsapCause::from(0x04), SgsapCause::ImsiUnknown);
        assert_eq!(SgsapCause::from(0x07), SgsapCause::UeUnreachable);
        assert_eq!(SgsapCause::from(0xff), SgsapCause::ImsiDetachedForEpsServices);
    }

    #[test]
    fn test_build_reset_ack() {
        let msg = build_reset_ack("mme.example.com");
        assert_eq!(msg[0], message_type::RESET_ACK);
        assert_eq!(msg[1], ie_type::MME_NAME);
    }
}
