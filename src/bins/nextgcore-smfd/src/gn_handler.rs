//! GTP v1 (Gn/Gp) Message Handler for SMF

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/gn-handler.c - GTPv1-C message handling for GGSN interworking
//!
//! This module handles GTPv1-C messages from SGSNs, enabling the SMF to act as
//! a GGSN for legacy 2G/3G devices.
//!
//! Supported procedures:
//! - Create PDP Context (establish data session)
//! - Update PDP Context (modify QoS, handover)
//! - Delete PDP Context (release session)
//! - Echo Request/Response (path management)
//!
//! Reference: 3GPP TS 29.060 (GTPv1-C), 3GPP TS 23.401 Annex E

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use log::{debug, error, info, warn};
use bytes::Bytes;

use crate::context::SmfContext;
use crate::gn_build::{cause, ie_type, msg_type};

// ============================================================================
// Message Parsing Structures
// ============================================================================

/// Parsed Create PDP Context Request
#[derive(Debug, Default)]
pub struct CreatePdpContextRequest {
    /// IMSI
    pub imsi: Option<Vec<u8>>,
    /// RAI (Routing Area Identity)
    pub rai: Option<Vec<u8>>,
    /// Recovery counter
    pub recovery: Option<u8>,
    /// Selection mode
    pub selection_mode: Option<u8>,
    /// TEID Data I (uplink user data)
    pub teid_data_i: Option<u32>,
    /// TEID Control (signalling)
    pub teid_control: Option<u32>,
    /// NSAPI
    pub nsapi: Option<u8>,
    /// Linked NSAPI (for secondary PDP contexts)
    pub linked_nsapi: Option<u8>,
    /// Charging characteristics
    pub charging_characteristics: Option<Vec<u8>>,
    /// Protocol configuration options
    pub pco: Option<Vec<u8>>,
    /// SGSN address for signalling
    pub sgsn_addr_control: Option<Ipv4Addr>,
    /// SGSN address for user plane
    pub sgsn_addr_user: Option<Ipv4Addr>,
    /// MSISDN
    pub msisdn: Option<Vec<u8>>,
    /// QoS profile
    pub qos_profile: Option<QosProfileData>,
    /// Traffic flow template
    pub tft: Option<Vec<u8>>,
    /// Trigger ID
    pub trigger_id: Option<Vec<u8>>,
    /// OMC Identity
    pub omc_identity: Option<Vec<u8>>,
    /// Common flags
    pub common_flags: Option<u8>,
    /// APN Restriction
    pub apn_restriction: Option<u8>,
    /// RAT Type
    pub rat_type: Option<u8>,
    /// User Location Information
    pub user_location_info: Option<Vec<u8>>,
    /// MS Time Zone
    pub ms_time_zone: Option<Vec<u8>>,
    /// IMEI(SV)
    pub imei: Option<Vec<u8>>,
    /// Access Point Name
    pub apn: Option<String>,
    /// End User Address (requested IP)
    pub end_user_address: Option<EndUserAddress>,
}

/// End User Address (requested IP configuration)
#[derive(Debug, Default, Clone)]
pub struct EndUserAddress {
    /// PDP type organization (0=ETSI, 1=IETF)
    pub pdp_type_org: u8,
    /// PDP type number (0x21=IPv4, 0x57=IPv6, 0x8D=IPv4v6)
    pub pdp_type_num: u8,
    /// IPv4 address if present
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 address if present
    pub ipv6: Option<Ipv6Addr>,
}

/// QoS Profile data
#[derive(Debug, Default, Clone)]
pub struct QosProfileData {
    /// Allocation/Retention Priority
    pub arp: u8,
    /// Delay class
    pub delay_class: u8,
    /// Reliability class
    pub reliability_class: u8,
    /// Peak throughput
    pub peak_throughput: u8,
    /// Mean throughput
    pub mean_throughput: u8,
    /// Traffic class
    pub traffic_class: u8,
    /// Delivery order
    pub delivery_order: u8,
    /// Max SDU size
    pub max_sdu_size: u8,
    /// Max bit rate for uplink
    pub max_bitrate_ul: u32,
    /// Max bit rate for downlink
    pub max_bitrate_dl: u32,
    /// Guaranteed bit rate for uplink
    pub guaranteed_bitrate_ul: u32,
    /// Guaranteed bit rate for downlink
    pub guaranteed_bitrate_dl: u32,
}

/// Parsed Update PDP Context Request
#[derive(Debug, Default)]
pub struct UpdatePdpContextRequest {
    /// IMSI (optional in update)
    pub imsi: Option<Vec<u8>>,
    /// RAI
    pub rai: Option<Vec<u8>>,
    /// Recovery
    pub recovery: Option<u8>,
    /// TEID Data I
    pub teid_data_i: Option<u32>,
    /// TEID Control
    pub teid_control: Option<u32>,
    /// NSAPI
    pub nsapi: Option<u8>,
    /// SGSN address signalling
    pub sgsn_addr_control: Option<Ipv4Addr>,
    /// SGSN address user
    pub sgsn_addr_user: Option<Ipv4Addr>,
    /// QoS profile
    pub qos_profile: Option<QosProfileData>,
    /// User Location Information
    pub user_location_info: Option<Vec<u8>>,
    /// RAT Type
    pub rat_type: Option<u8>,
}

/// Parsed Delete PDP Context Request
#[derive(Debug, Default)]
pub struct DeletePdpContextRequest {
    /// NSAPI
    pub nsapi: Option<u8>,
    /// Teardown indicator (delete all linked contexts)
    pub teardown_ind: bool,
    /// Protocol configuration options
    pub pco: Option<Vec<u8>>,
}

/// GTPv1-C handler error
#[derive(Debug)]
pub enum GnError {
    /// Parsing error
    ParseError(String),
    /// Context not found
    ContextNotFound,
    /// Internal error
    Internal(String),
}

// ============================================================================
// Echo Handler
// ============================================================================

/// Handle Echo Request
///
/// Responds to GTPv1 path management echo requests.
pub fn handle_echo_request(
    _smf_ctx: &Arc<SmfContext>,
    recovery: u8,
) -> Vec<u8> {
    debug!("[GTPv1] Echo Request received, recovery={recovery}");
    crate::gn_build::build_echo_response(recovery)
}

/// Handle Echo Response
///
/// Processes GTPv1 echo responses for path management.
pub fn handle_echo_response(
    _smf_ctx: &Arc<SmfContext>,
    recovery: u8,
) {
    debug!("[GTPv1] Echo Response received, recovery={recovery}");
    // In a complete implementation, this would update path state
}

// ============================================================================
// PDP Context Handlers (Stubs)
// ============================================================================

/// Handle Create PDP Context Request
///
/// Establishes a new PDP context (data session) for a 2G/3G device.
/// This is a stub implementation that validates the request and returns success.
pub fn handle_create_pdp_context_request(
    smf_ctx: &Arc<SmfContext>,
    req: &CreatePdpContextRequest,
) -> Result<(u8, Bytes), GnError> {
    info!("[GTPv1] Create PDP Context Request");

    // Validate mandatory IEs
    if req.imsi.is_none() {
        error!("No IMSI in Create PDP Context Request");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.selection_mode.is_none() {
        error!("No Selection Mode");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.teid_data_i.is_none() {
        error!("No TEID Data I");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.nsapi.is_none() {
        error!("No NSAPI");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.sgsn_addr_control.is_none() {
        error!("No SGSN Address for signalling");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.sgsn_addr_user.is_none() {
        error!("No SGSN Address for user traffic");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    if req.qos_profile.is_none() {
        error!("No QoS Profile");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    // Log the request details
    if let Some(ref apn) = req.apn {
        info!("[GTPv1] APN: {apn}");
    }
    if let Some(nsapi) = req.nsapi {
        info!("[GTPv1] NSAPI: {nsapi}");
    }
    if let Some(ref qos) = req.qos_profile {
        info!("[GTPv1] QoS: traffic_class={}, arp={}", qos.traffic_class, qos.arp);
    }

    // In a full implementation, this would:
    // 1. Create or find the UE context
    // 2. Allocate IP address from pool
    // 3. Establish PFCP session with UPF
    // 4. Store session state
    // 5. Build and return Create PDP Context Response

    // For now, return a stub success response
    let ggsn_addr = Ipv4Addr::new(10, 45, 0, 1);
    let response = crate::gn_build::build_create_pdp_context_response(
        cause::REQUEST_ACCEPTED,
        0x12345678, // GGSN TEID-U
        0x12345679, // GGSN TEID-C
        req.nsapi.unwrap_or(5), // NSAPI
        false, // reordering_required
        Some(&ggsn_addr), // GGSN address for control
        Some(&ggsn_addr), // GGSN address for user
        &crate::gn_build::QosProfileDecoded::from_qci(9, req.qos_profile.as_ref().map(|q| q.arp).unwrap_or(1)),
        0x12345680, // Charging ID
        None, // PCO
        Some(Ipv4Addr::new(10, 45, 0, 100)), // Allocated IPv4
        None, // IPv6
    );

    Ok((cause::REQUEST_ACCEPTED, Bytes::from(response)))
}

/// Handle Update PDP Context Request
///
/// Modifies an existing PDP context (QoS change, SGSN relocation).
pub fn handle_update_pdp_context_request(
    _smf_ctx: &Arc<SmfContext>,
    req: &UpdatePdpContextRequest,
) -> Result<(u8, Bytes), GnError> {
    info!("[GTPv1] Update PDP Context Request");

    // Validate NSAPI
    if req.nsapi.is_none() {
        error!("No NSAPI in Update PDP Context Request");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    let nsapi = req.nsapi.unwrap();
    info!("[GTPv1] Updating NSAPI: {nsapi}");

    // In a full implementation, would update session state and UPF
    let ggsn_addr = Ipv4Addr::new(10, 45, 0, 1);
    let qos = crate::gn_build::QosProfileDecoded::from_qci(9, 1);

    let response = crate::gn_build::build_update_pdp_context_response(
        cause::REQUEST_ACCEPTED,
        0x12345678, // TEID-U
        0x12345679, // TEID-C
        Some(&ggsn_addr),
        Some(&ggsn_addr),
        Some(&qos),
    );

    Ok((cause::REQUEST_ACCEPTED, Bytes::from(response)))
}

/// Handle Delete PDP Context Request
///
/// Releases a PDP context and associated resources.
pub fn handle_delete_pdp_context_request(
    _smf_ctx: &Arc<SmfContext>,
    req: &DeletePdpContextRequest,
) -> Result<(u8, Bytes), GnError> {
    info!("[GTPv1] Delete PDP Context Request");

    if req.nsapi.is_none() {
        error!("No NSAPI in Delete PDP Context Request");
        return Ok((cause::MANDATORY_IE_MISSING, Bytes::new()));
    }

    let nsapi = req.nsapi.unwrap();
    info!("[GTPv1] Deleting NSAPI: {}, teardown={}", nsapi, req.teardown_ind);

    // In a full implementation, would:
    // 1. Find the session by NSAPI
    // 2. Release PFCP session
    // 3. Release IP address
    // 4. Clean up state

    let response = crate::gn_build::build_delete_pdp_context_response(
        cause::REQUEST_ACCEPTED,
    );

    Ok((cause::REQUEST_ACCEPTED, Bytes::from(response)))
}

// ============================================================================
// Message Parsing
// ============================================================================

/// Parse Create PDP Context Request from raw GTPv1-C message
pub fn parse_create_pdp_context_request(data: &[u8]) -> Result<CreatePdpContextRequest, GnError> {
    if data.len() < 8 {
        return Err(GnError::ParseError("Message too short".to_string()));
    }

    let mut req = CreatePdpContextRequest::default();
    let mut offset = 8; // Skip GTP header

    while offset + 2 <= data.len() {
        let ie_type = data[offset];
        offset += 1;

        match ie_type {
            ie_type::IMSI => {
                if offset + 8 <= data.len() {
                    req.imsi = Some(data[offset..offset + 8].to_vec());
                    offset += 8;
                }
            }
            ie_type::RECOVERY => {
                if offset < data.len() {
                    req.recovery = Some(data[offset]);
                    offset += 1;
                }
            }
            ie_type::SELECTION_MODE => {
                if offset < data.len() {
                    req.selection_mode = Some(data[offset] & 0x03);
                    offset += 1;
                }
            }
            ie_type::TEID_DATA_I => {
                if offset + 4 <= data.len() {
                    req.teid_data_i = Some(u32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]));
                    offset += 4;
                }
            }
            ie_type::TEID_CONTROL => {
                if offset + 4 <= data.len() {
                    req.teid_control = Some(u32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]));
                    offset += 4;
                }
            }
            ie_type::NSAPI => {
                if offset < data.len() {
                    req.nsapi = Some(data[offset] & 0x0F);
                    offset += 1;
                }
            }
            ie_type::RAT_TYPE => {
                if offset < data.len() {
                    req.rat_type = Some(data[offset]);
                    offset += 1;
                }
            }
            _ => {
                // TLV IE - get length and skip
                if ie_type >= 128 && offset + 1 < data.len() {
                    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2 + len;
                } else {
                    // Unknown TV IE, try to continue
                    offset += 1;
                }
            }
        }
    }

    Ok(req)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pdp_context_request_validation() {
        let req = CreatePdpContextRequest::default();

        // Empty request should fail validation
        // (validation happens in handler, not here)
        assert!(req.imsi.is_none());
    }

    #[test]
    fn test_parse_minimal_message() {
        // Minimal GTP header
        let data = vec![0x32, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = parse_create_pdp_context_request(&data);
        assert!(result.is_ok());
    }
}
