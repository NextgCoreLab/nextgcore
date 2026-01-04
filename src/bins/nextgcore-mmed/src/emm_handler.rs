//! EMM Message Handling
//!
//! Port of src/mme/emm-handler.c - EMM message handling functions

use crate::context::{MmeUe, EnbUe, EpsTai, ECgi, PlmnId};
use crate::emm_build::{EmmCause, IdentityType2};

// ============================================================================
// EMM Handler Result
// ============================================================================

/// Result type for EMM handlers
pub type EmmResult<T> = Result<T, EmmError>;

/// EMM error types
#[derive(Debug, Clone)]
pub enum EmmError {
    /// Invalid message format
    InvalidMessage(String),
    /// Security failure
    SecurityFailure(String),
    /// Protocol error
    ProtocolError(EmmCause),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for EmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmmError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            EmmError::SecurityFailure(msg) => write!(f, "Security failure: {}", msg),
            EmmError::ProtocolError(cause) => write!(f, "Protocol error: {:?}", cause),
            EmmError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for EmmError {}

// ============================================================================
// Attach Request Handling
// ============================================================================

/// Parsed attach request data
#[derive(Debug, Clone, Default)]
pub struct AttachRequestData {
    /// EPS attach type
    pub attach_type: u8,
    /// NAS key set identifier
    pub nas_ksi: u8,
    /// TSC (Type of Security Context)
    pub tsc: u8,
    /// Mobile identity type
    pub identity_type: u8,
    /// IMSI (if provided)
    pub imsi: Option<String>,
    /// GUTI (if provided)
    pub guti: Option<ParsedGuti>,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// MS network capability (optional)
    pub ms_network_capability: Option<MsNetworkCapability>,
    /// ESM message container
    pub esm_message: Vec<u8>,
    /// Last visited TAI (optional)
    pub last_visited_tai: Option<EpsTai>,
    /// Additional security capability (optional)
    pub additional_security_capability: Option<UeAdditionalSecurityCapability>,
}

/// Parsed GUTI
#[derive(Debug, Clone, Default)]
pub struct ParsedGuti {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// MME Group ID
    pub mme_gid: u16,
    /// MME Code
    pub mme_code: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

/// UE network capability
#[derive(Debug, Clone, Default)]
pub struct UeNetworkCapability {
    /// EEA algorithms
    pub eea: u8,
    /// EIA algorithms
    pub eia: u8,
    /// UEA algorithms
    pub uea: u8,
    /// UIA algorithms
    pub uia: u8,
}

/// MS network capability
#[derive(Debug, Clone, Default)]
pub struct MsNetworkCapability {
    /// GEA1 support
    pub gea1: bool,
    /// Extended GEA
    pub extended_gea: u8,
}

/// UE additional security capability
#[derive(Debug, Clone, Default)]
pub struct UeAdditionalSecurityCapability {
    /// 5G-EA algorithms
    pub nea: u8,
    /// 5G-IA algorithms
    pub nia: u8,
}

/// Handle attach request
pub fn handle_attach_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<AttachRequestData> {
    if data.len() < 10 {
        return Err(EmmError::InvalidMessage("Attach request too short".into()));
    }
    
    let mut offset = 0;
    
    // Skip protocol discriminator and message type (already parsed)
    // Parse EPS attach type and NAS key set identifier
    let attach_type_byte = data[offset];
    offset += 1;
    
    let attach_type = attach_type_byte & 0x07;
    let nas_ksi = (attach_type_byte >> 4) & 0x07;
    let tsc = (attach_type_byte >> 7) & 0x01;
    
    // Parse EPS mobile identity
    let identity_len = data[offset] as usize;
    offset += 1;
    
    if offset + identity_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid identity length".into()));
    }
    
    let identity_data = &data[offset..offset + identity_len];
    offset += identity_len;
    
    let identity_type = identity_data[0] & 0x07;
    let (imsi, guti) = parse_mobile_identity(identity_data)?;
    
    // Parse UE network capability
    if offset >= data.len() {
        return Err(EmmError::InvalidMessage("Missing UE network capability".into()));
    }
    
    let ue_cap_len = data[offset] as usize;
    offset += 1;
    
    if offset + ue_cap_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid UE capability length".into()));
    }
    
    let ue_network_capability = parse_ue_network_capability(&data[offset..offset + ue_cap_len]);
    offset += ue_cap_len;
    
    // Parse ESM message container
    if offset + 2 > data.len() {
        return Err(EmmError::InvalidMessage("Missing ESM message container".into()));
    }
    
    let esm_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;
    
    if offset + esm_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid ESM message length".into()));
    }
    
    let esm_message = data[offset..offset + esm_len].to_vec();
    offset += esm_len;
    
    // Parse optional IEs
    let mut last_visited_tai = None;
    let mut ms_network_capability = None;
    let mut additional_security_capability = None;
    
    while offset < data.len() {
        let iei = data[offset];
        offset += 1;
        
        match iei {
            0x52 => {
                // Last visited registered TAI
                if offset + 5 <= data.len() {
                    last_visited_tai = Some(parse_tai(&data[offset..offset + 5]));
                    offset += 5;
                }
            }
            0x31 => {
                // MS network capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        ms_network_capability = Some(parse_ms_network_capability(&data[offset..offset + len]));
                        offset += len;
                    }
                }
            }
            0x6f => {
                // UE additional security capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        additional_security_capability = Some(parse_additional_security_capability(&data[offset..offset + len]));
                        offset += len;
                    }
                }
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE (1 byte)
                } else {
                    // Type 4 IE (TLV)
                    if offset < data.len() {
                        let len = data[offset] as usize;
                        offset += 1 + len;
                    }
                }
            }
        }
    }
    
    // Update MME UE context
    mme_ue.nas_eps.attach_type = attach_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.nas_eps.mme_ksi.tsc = tsc;
    mme_ue.ue_network_capability.eea = ue_network_capability.eea;
    mme_ue.ue_network_capability.eia = ue_network_capability.eia;
    mme_ue.ue_network_capability.uea = ue_network_capability.uea;
    mme_ue.ue_network_capability.uia = ue_network_capability.uia;
    
    if let Some(ref imsi_str) = imsi {
        mme_ue.imsi_bcd = imsi_str.clone();
    }
    
    // Copy TAI and E-CGI from eNB UE
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();
    
    Ok(AttachRequestData {
        attach_type,
        nas_ksi,
        tsc,
        identity_type,
        imsi,
        guti,
        ue_network_capability,
        ms_network_capability,
        esm_message,
        last_visited_tai,
        additional_security_capability,
    })
}

// ============================================================================
// Attach Complete Handling
// ============================================================================

/// Handle attach complete
pub fn handle_attach_complete(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Vec<u8>> {
    // Parse ESM message container
    if data.len() < 2 {
        return Err(EmmError::InvalidMessage("Attach complete too short".into()));
    }
    
    let esm_len = ((data[0] as usize) << 8) | (data[1] as usize);
    
    if data.len() < 2 + esm_len {
        return Err(EmmError::InvalidMessage("Invalid ESM message length".into()));
    }
    
    let esm_message = data[2..2 + esm_len].to_vec();
    
    log::info!("Attach complete received for IMSI[{}]", mme_ue.imsi_bcd);
    
    Ok(esm_message)
}

// ============================================================================
// Authentication Response Handling
// ============================================================================

/// Handle authentication response
pub fn handle_authentication_response(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<bool> {
    // Parse authentication response parameter
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Authentication response empty".into()));
    }
    
    let res_len = data[0] as usize;
    
    if data.len() < 1 + res_len {
        return Err(EmmError::InvalidMessage("Invalid RES length".into()));
    }
    
    let res = &data[1..1 + res_len];
    
    // Compare with expected response (XRES)
    if res_len == 0 || res_len > mme_ue.xres_len as usize {
        log::warn!("Authentication response length mismatch");
        return Ok(false);
    }
    
    let xres = &mme_ue.xres[..res_len];
    
    if res != xres {
        log::warn!("Authentication response mismatch");
        log::debug!("  RES: {:02x?}", res);
        log::debug!("  XRES: {:02x?}", xres);
        return Ok(false);
    }
    
    log::info!("Authentication successful for IMSI[{}]", mme_ue.imsi_bcd);
    
    Ok(true)
}

// ============================================================================
// Identity Response Handling
// ============================================================================

/// Handle identity response
pub fn handle_identity_response(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Option<String>> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Identity response empty".into()));
    }
    
    let identity_len = data[0] as usize;
    
    if data.len() < 1 + identity_len {
        return Err(EmmError::InvalidMessage("Invalid identity length".into()));
    }
    
    let identity_data = &data[1..1 + identity_len];
    let identity_type = identity_data[0] & 0x07;
    
    match identity_type {
        1 => {
            // IMSI
            let imsi = decode_imsi(identity_data)?;
            mme_ue.imsi_bcd = imsi.clone();
            log::info!("Identity response: IMSI[{}]", imsi);
            Ok(Some(imsi))
        }
        2 => {
            // IMEI
            let imei = decode_imei(identity_data)?;
            log::info!("Identity response: IMEI[{}]", imei);
            Ok(Some(imei))
        }
        3 => {
            // IMEISV
            let imeisv = decode_imeisv(identity_data)?;
            mme_ue.imeisv_bcd = imeisv.clone();
            log::info!("Identity response: IMEISV[{}]", imeisv);
            Ok(Some(imeisv))
        }
        _ => {
            log::warn!("Unknown identity type: {}", identity_type);
            Ok(None)
        }
    }
}

// ============================================================================
// Security Mode Complete Handling
// ============================================================================

/// Handle security mode complete
pub fn handle_security_mode_complete(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Option<String>> {
    let mut offset = 0;
    let mut imeisv = None;
    
    // Parse optional IEs
    while offset < data.len() {
        let iei = data[offset];
        offset += 1;
        
        match iei {
            0x23 => {
                // IMEISV
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        let imeisv_data = &data[offset..offset + len];
                        if let Ok(decoded) = decode_imeisv(imeisv_data) {
                            mme_ue.imeisv_bcd = decoded.clone();
                            imeisv = Some(decoded);
                        }
                        offset += len;
                    }
                }
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE
                } else if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1 + len;
                }
            }
        }
    }
    
    mme_ue.security_context_available = true;
    log::info!("Security mode complete for IMSI[{}]", mme_ue.imsi_bcd);
    
    Ok(imeisv)
}

// ============================================================================
// TAU Request Handling
// ============================================================================

/// Parsed TAU request data
#[derive(Debug, Clone, Default)]
pub struct TauRequestData {
    /// EPS update type
    pub update_type: u8,
    /// Active flag
    pub active_flag: bool,
    /// NAS key set identifier
    pub nas_ksi: u8,
    /// TSC
    pub tsc: u8,
    /// Old GUTI
    pub old_guti: Option<ParsedGuti>,
    /// UE network capability (optional)
    pub ue_network_capability: Option<UeNetworkCapability>,
    /// Last visited TAI (optional)
    pub last_visited_tai: Option<EpsTai>,
}

/// Handle TAU request
pub fn handle_tau_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<TauRequestData> {
    if data.len() < 12 {
        return Err(EmmError::InvalidMessage("TAU request too short".into()));
    }
    
    let mut offset = 0;
    
    // Parse EPS update type and NAS key set identifier
    let update_type_byte = data[offset];
    offset += 1;
    
    let update_type = update_type_byte & 0x07;
    let active_flag = (update_type_byte & 0x08) != 0;
    let nas_ksi = (update_type_byte >> 4) & 0x07;
    let tsc = (update_type_byte >> 7) & 0x01;
    
    // Parse old GUTI
    let guti_len = data[offset] as usize;
    offset += 1;
    
    if offset + guti_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid GUTI length".into()));
    }
    
    let guti_data = &data[offset..offset + guti_len];
    let (_, old_guti) = parse_mobile_identity(guti_data)?;
    offset += guti_len;
    
    // Parse optional IEs
    let mut ue_network_capability = None;
    let mut last_visited_tai = None;
    
    while offset < data.len() {
        let iei = data[offset];
        offset += 1;
        
        match iei {
            0x31 => {
                // UE network capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        ue_network_capability = Some(parse_ue_network_capability(&data[offset..offset + len]));
                        offset += len;
                    }
                }
            }
            0x52 => {
                // Last visited registered TAI
                if offset + 5 <= data.len() {
                    last_visited_tai = Some(parse_tai(&data[offset..offset + 5]));
                    offset += 5;
                }
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE
                } else if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1 + len;
                }
            }
        }
    }
    
    // Update MME UE context
    mme_ue.nas_eps.update_type = update_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.nas_eps.mme_ksi.tsc = tsc;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();
    
    Ok(TauRequestData {
        update_type,
        active_flag,
        nas_ksi,
        tsc,
        old_guti,
        ue_network_capability,
        last_visited_tai,
    })
}

// ============================================================================
// Service Request Handling
// ============================================================================

/// Handle service request
pub fn handle_service_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<(u8, u8)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Service request empty".into()));
    }
    
    // Parse KSI and sequence number
    let ksi_seq = data[0];
    let ksi = (ksi_seq >> 5) & 0x07;
    let sequence_number = ksi_seq & 0x1f;
    
    // Update context
    mme_ue.nas_eps.mme_ksi.ksi = ksi;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();
    
    log::info!("Service request from IMSI[{}] KSI[{}] SEQ[{}]",
               mme_ue.imsi_bcd, ksi, sequence_number);
    
    Ok((ksi, sequence_number))
}

// ============================================================================
// Extended Service Request Handling
// ============================================================================

/// Handle extended service request
pub fn handle_extended_service_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<u8> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Extended service request empty".into()));
    }
    
    // Parse service type and NAS key set identifier
    let service_type_byte = data[0];
    let service_type = service_type_byte & 0x0f;
    let nas_ksi = (service_type_byte >> 4) & 0x07;
    
    // Update context
    mme_ue.nas_eps.service_type = service_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();
    
    log::info!("Extended service request from IMSI[{}] type[{}]",
               mme_ue.imsi_bcd, service_type);
    
    Ok(service_type)
}

// ============================================================================
// Detach Request Handling
// ============================================================================

/// Handle detach request (from UE)
pub fn handle_detach_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<(u8, bool)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Detach request empty".into()));
    }
    
    // Parse detach type
    let detach_type_byte = data[0];
    let detach_type = detach_type_byte & 0x07;
    let switch_off = (detach_type_byte & 0x08) != 0;
    let nas_ksi = (detach_type_byte >> 4) & 0x07;
    
    // Update context
    mme_ue.nas_eps.detach_type = detach_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    
    log::info!("Detach request from IMSI[{}] type[{}] switch_off[{}]",
               mme_ue.imsi_bcd, detach_type, switch_off);
    
    Ok((detach_type, switch_off))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse mobile identity
fn parse_mobile_identity(data: &[u8]) -> EmmResult<(Option<String>, Option<ParsedGuti>)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Empty mobile identity".into()));
    }
    
    let identity_type = data[0] & 0x07;
    
    match identity_type {
        1 => {
            // IMSI
            let imsi = decode_imsi(data)?;
            Ok((Some(imsi), None))
        }
        6 => {
            // GUTI
            if data.len() < 11 {
                return Err(EmmError::InvalidMessage("GUTI too short".into()));
            }
            
            let guti = ParsedGuti {
                plmn_id: decode_plmn_id(&data[1..4]),
                mme_gid: ((data[4] as u16) << 8) | (data[5] as u16),
                mme_code: data[6],
                m_tmsi: ((data[7] as u32) << 24) | ((data[8] as u32) << 16) 
                      | ((data[9] as u32) << 8) | (data[10] as u32),
            };
            Ok((None, Some(guti)))
        }
        _ => {
            log::warn!("Unknown mobile identity type: {}", identity_type);
            Ok((None, None))
        }
    }
}

/// Decode IMSI from BCD format
fn decode_imsi(data: &[u8]) -> EmmResult<String> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Empty IMSI data".into()));
    }
    
    let mut imsi = String::with_capacity(15);
    
    // First digit is in the high nibble of first byte (after type)
    let first_digit = (data[0] >> 4) & 0x0f;
    if first_digit < 10 {
        imsi.push((b'0' + first_digit) as char);
    }
    
    // Remaining digits
    for &byte in &data[1..] {
        let low = byte & 0x0f;
        let high = (byte >> 4) & 0x0f;
        
        if low < 10 {
            imsi.push((b'0' + low) as char);
        }
        if high < 10 && high != 0x0f {
            imsi.push((b'0' + high) as char);
        }
    }
    
    Ok(imsi)
}

/// Decode IMEI from BCD format
fn decode_imei(data: &[u8]) -> EmmResult<String> {
    decode_imsi(data) // Same format as IMSI
}

/// Decode IMEISV from BCD format
fn decode_imeisv(data: &[u8]) -> EmmResult<String> {
    decode_imsi(data) // Same format as IMSI
}

/// Decode PLMN ID from 3 bytes
fn decode_plmn_id(data: &[u8]) -> PlmnId {
    if data.len() < 3 {
        return PlmnId::default();
    }
    
    PlmnId {
        mcc1: data[0] & 0x0f,
        mcc2: (data[0] >> 4) & 0x0f,
        mcc3: data[1] & 0x0f,
        mnc1: data[2] & 0x0f,
        mnc2: (data[2] >> 4) & 0x0f,
        mnc3: (data[1] >> 4) & 0x0f,
    }
}

/// Parse TAI from 5 bytes
fn parse_tai(data: &[u8]) -> EpsTai {
    if data.len() < 5 {
        return EpsTai::default();
    }
    
    EpsTai {
        plmn_id: decode_plmn_id(&data[0..3]),
        tac: ((data[3] as u16) << 8) | (data[4] as u16),
    }
}

/// Parse UE network capability
fn parse_ue_network_capability(data: &[u8]) -> UeNetworkCapability {
    let mut cap = UeNetworkCapability::default();
    
    if !data.is_empty() {
        cap.eea = data[0];
    }
    if data.len() > 1 {
        cap.eia = data[1];
    }
    if data.len() > 2 {
        cap.uea = data[2];
    }
    if data.len() > 3 {
        cap.uia = data[3] & 0x7f;
    }
    
    cap
}

/// Parse MS network capability
fn parse_ms_network_capability(data: &[u8]) -> MsNetworkCapability {
    let mut cap = MsNetworkCapability::default();
    
    if !data.is_empty() {
        cap.gea1 = (data[0] & 0x80) != 0;
        cap.extended_gea = data[0] & 0x7f;
    }
    
    cap
}

/// Parse UE additional security capability
fn parse_additional_security_capability(data: &[u8]) -> UeAdditionalSecurityCapability {
    let mut cap = UeAdditionalSecurityCapability::default();
    
    if !data.is_empty() {
        cap.nea = data[0];
    }
    if data.len() > 1 {
        cap.nia = data[1];
    }
    
    cap
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_imsi() {
        // Test with a simple IMSI pattern
        // First byte: odd indicator (1) + type (1) + first digit in high nibble
        // For IMSI "123456789012345":
        // byte 0: 0x19 = odd(1) + type(1) + digit 1
        // byte 1: 0x32 = digit 2 (low) + digit 3 (high)
        // etc.
        let data = [0x19, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54];
        let imsi = decode_imsi(&data).unwrap();
        // The decoder extracts: 1 (from high nibble of byte 0)
        // then pairs: 2,3 4,5 6,7 8,9 0,1 2,3 4,5
        assert_eq!(imsi, "123456789012345");
    }

    #[test]
    fn test_decode_plmn_id() {
        // PLMN: MCC=310, MNC=410
        // Encoded: 0x13 0xf0 0x14
        let data = [0x13, 0xf0, 0x14];
        let plmn = decode_plmn_id(&data);
        assert_eq!(plmn.mcc1, 3);
        assert_eq!(plmn.mcc2, 1);
        assert_eq!(plmn.mcc3, 0);
        assert_eq!(plmn.mnc1, 4);
        assert_eq!(plmn.mnc2, 1);
        assert_eq!(plmn.mnc3, 0x0f); // 2-digit MNC
    }

    #[test]
    fn test_parse_tai() {
        // TAI: PLMN=310/410, TAC=0x1234
        let data = [0x13, 0xf0, 0x14, 0x12, 0x34];
        let tai = parse_tai(&data);
        assert_eq!(tai.tac, 0x1234);
    }

    #[test]
    fn test_parse_ue_network_capability() {
        let data = [0xff, 0x7f, 0x00, 0x00];
        let cap = parse_ue_network_capability(&data);
        assert_eq!(cap.eea, 0xff);
        assert_eq!(cap.eia, 0x7f);
        assert_eq!(cap.uea, 0x00);
        assert_eq!(cap.uia, 0x00);
    }

    #[test]
    fn test_parse_mobile_identity_imsi() {
        // IMSI type (1) with odd indicator
        let data = [0x19, 0x01, 0x14, 0x21, 0x43, 0x65, 0x87, 0xf9];
        let (imsi, guti) = parse_mobile_identity(&data).unwrap();
        assert!(imsi.is_some());
        assert!(guti.is_none());
    }

    #[test]
    fn test_parse_mobile_identity_guti() {
        // GUTI type (6)
        let data = [
            0xf6, // Type = GUTI
            0x13, 0xf0, 0x14, // PLMN
            0x00, 0x01, // MME GID
            0x02, // MME Code
            0x12, 0x34, 0x56, 0x78, // M-TMSI
        ];
        let (imsi, guti) = parse_mobile_identity(&data).unwrap();
        assert!(imsi.is_none());
        assert!(guti.is_some());
        
        let guti = guti.unwrap();
        assert_eq!(guti.mme_gid, 1);
        assert_eq!(guti.mme_code, 2);
        assert_eq!(guti.m_tmsi, 0x12345678);
    }

    #[test]
    fn test_emm_error_display() {
        let err = EmmError::InvalidMessage("test".into());
        assert!(err.to_string().contains("Invalid message"));
        
        let err = EmmError::ProtocolError(EmmCause::PlmnNotAllowed);
        assert!(err.to_string().contains("Protocol error"));
    }
}
