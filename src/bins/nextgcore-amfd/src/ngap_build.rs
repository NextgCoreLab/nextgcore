//! NGAP Message Building
//!
//! Port of src/amf/ngap-build.c - NGAP message building functions

use crate::context::{
    AmfContext, AmfUe, AmfSess, RanUe, Tai5gs,
    NgapCause,
};
use bytes::{BufMut, BytesMut};

// ============================================================================
// Constants
// ============================================================================

/// NGAP procedure codes
pub mod procedure_code {
    pub const NG_SETUP: u16 = 21;
    pub const INITIAL_CONTEXT_SETUP: u16 = 14;
    pub const UE_CONTEXT_RELEASE: u16 = 41;
    pub const UE_CONTEXT_MODIFICATION: u16 = 40;
    pub const HANDOVER_PREPARATION: u16 = 12;
    pub const HANDOVER_RESOURCE_ALLOCATION: u16 = 13;
    pub const HANDOVER_NOTIFICATION: u16 = 11;
    pub const HANDOVER_CANCEL: u16 = 10;
    pub const PATH_SWITCH_REQUEST: u16 = 25;
    pub const PAGING: u16 = 24;
    pub const DOWNLINK_NAS_TRANSPORT: u16 = 4;
    pub const UPLINK_NAS_TRANSPORT: u16 = 46;
    pub const PDU_SESSION_RESOURCE_SETUP: u16 = 29;
    pub const PDU_SESSION_RESOURCE_RELEASE: u16 = 28;
    pub const PDU_SESSION_RESOURCE_MODIFY: u16 = 26;
    pub const AMF_CONFIGURATION_UPDATE: u16 = 0;
    pub const RAN_CONFIGURATION_UPDATE: u16 = 35;
    pub const NG_RESET: u16 = 20;
    pub const ERROR_INDICATION: u16 = 5;
}

/// NGAP criticality
pub mod criticality {
    pub const REJECT: u8 = 0;
    pub const IGNORE: u8 = 1;
    pub const NOTIFY: u8 = 2;
}

/// NGAP cause groups
pub mod cause_group {
    pub const RADIO_NETWORK: u8 = 0;
    pub const TRANSPORT: u8 = 1;
    pub const NAS: u8 = 2;
    pub const PROTOCOL: u8 = 3;
    pub const MISC: u8 = 4;
}

/// NGAP radio network cause values
pub mod radio_network_cause {
    pub const UNSPECIFIED: i64 = 0;
    pub const TXNRELOCOVERALL_EXPIRY: i64 = 1;
    pub const SUCCESSFUL_HANDOVER: i64 = 2;
    pub const RELEASE_DUE_TO_NGRAN_GENERATED_REASON: i64 = 3;
    pub const RELEASE_DUE_TO_5GC_GENERATED_REASON: i64 = 4;
    pub const HANDOVER_CANCELLED: i64 = 5;
    pub const PARTIAL_HANDOVER: i64 = 6;
    pub const HO_FAILURE_IN_TARGET_5GC_NGRAN_NODE_OR_TARGET_SYSTEM: i64 = 7;
    pub const HO_TARGET_NOT_ALLOWED: i64 = 8;
    pub const TNGRELOCOVERALL_EXPIRY: i64 = 9;
    pub const TNGRELOCPREP_EXPIRY: i64 = 10;
    pub const CELL_NOT_AVAILABLE: i64 = 11;
    pub const UNKNOWN_TARGET_ID: i64 = 12;
    pub const NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL: i64 = 13;
    pub const UNKNOWN_LOCAL_UE_NGAP_ID: i64 = 14;
    pub const INCONSISTENT_REMOTE_UE_NGAP_ID: i64 = 15;
    pub const HANDOVER_DESIRABLE_FOR_RADIO_REASON: i64 = 16;
    pub const TIME_CRITICAL_HANDOVER: i64 = 17;
    pub const RESOURCE_OPTIMISATION_HANDOVER: i64 = 18;
    pub const REDUCE_LOAD_IN_SERVING_CELL: i64 = 19;
    pub const USER_INACTIVITY: i64 = 20;
    pub const RADIO_CONNECTION_WITH_UE_LOST: i64 = 21;
    pub const RADIO_RESOURCES_NOT_AVAILABLE: i64 = 22;
    pub const INVALID_QOS_COMBINATION: i64 = 23;
    pub const FAILURE_IN_RADIO_INTERFACE_PROCEDURE: i64 = 24;
    pub const INTERACTION_WITH_OTHER_PROCEDURE: i64 = 25;
    pub const UNKNOWN_PDU_SESSION_ID: i64 = 26;
    pub const UNKNOWN_QOS_FLOW_ID: i64 = 27;
    pub const MULTIPLE_PDU_SESSION_ID_INSTANCES: i64 = 28;
    pub const MULTIPLE_QOS_FLOW_ID_INSTANCES: i64 = 29;
    pub const ENCRYPTION_AND_OR_INTEGRITY_PROTECTION_ALGORITHMS_NOT_SUPPORTED: i64 = 30;
    pub const NG_INTRA_SYSTEM_HANDOVER_TRIGGERED: i64 = 31;
    pub const NG_INTER_SYSTEM_HANDOVER_TRIGGERED: i64 = 32;
    pub const XN_HANDOVER_TRIGGERED: i64 = 33;
    pub const NOT_SUPPORTED_5QI_VALUE: i64 = 34;
    pub const UE_CONTEXT_TRANSFER: i64 = 35;
    pub const IMS_VOICE_EPS_FALLBACK_OR_RAT_FALLBACK_TRIGGERED: i64 = 36;
    pub const UP_INTEGRITY_PROTECTION_NOT_POSSIBLE: i64 = 37;
    pub const UP_CONFIDENTIALITY_PROTECTION_NOT_POSSIBLE: i64 = 38;
    pub const SLICE_NOT_SUPPORTED: i64 = 39;
    pub const UE_IN_RRC_INACTIVE_STATE_NOT_REACHABLE: i64 = 40;
    pub const REDIRECTION: i64 = 41;
    pub const RESOURCES_NOT_AVAILABLE_FOR_THE_SLICE: i64 = 42;
    pub const UE_MAX_INTEGRITY_PROTECTED_DATA_RATE_REASON: i64 = 43;
    pub const RELEASE_DUE_TO_CN_DETECTED_MOBILITY: i64 = 44;
}

// ============================================================================
// NGAP Message Builder
// ============================================================================

/// NGAP message builder
#[derive(Debug)]
pub struct NgapMessageBuilder {
    buffer: BytesMut,
}

impl NgapMessageBuilder {
    /// Create a new NGAP message builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Write a single byte
    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.put_u8(value);
        self
    }

    /// Write two bytes (big endian)
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buffer.put_u16(value);
        self
    }

    /// Write four bytes (big endian)
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.put_u32(value);
        self
    }

    /// Write eight bytes (big endian)
    pub fn write_u64(&mut self, value: u64) -> &mut Self {
        self.buffer.put_u64(value);
        self
    }

    /// Write bytes
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_slice(data);
        self
    }

    /// Build the message and return the buffer
    pub fn build(self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    /// Get current buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for NgapMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// NGAP Message Building Functions
// ============================================================================

/// Build NG Setup Response message
/// 
/// This is sent by AMF to gNB in response to NG Setup Request
pub fn build_ng_setup_response(ctx: &AmfContext) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // In a real implementation, this would use ASN.1 encoding
    // For now, we create a simplified representation

    // Procedure code
    builder.write_u16(procedure_code::NG_SETUP);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF Name (if present)
    if let Some(ref name) = ctx.amf_name {
        builder.write_u8(name.len() as u8);
        builder.write_bytes(name.as_bytes());
    } else {
        builder.write_u8(0);
    }

    // Served GUAMI List
    builder.write_u8(ctx.num_of_served_guami as u8);
    for guami in ctx.served_guami.iter().take(ctx.num_of_served_guami) {
        // PLMN ID (3 bytes)
        builder.write_u8((guami.plmn_id.mcc2 << 4) | guami.plmn_id.mcc1);
        builder.write_u8((guami.plmn_id.mnc3 << 4) | guami.plmn_id.mcc3);
        builder.write_u8((guami.plmn_id.mnc2 << 4) | guami.plmn_id.mnc1);
        // AMF Region ID
        builder.write_u8(guami.amf_id.region);
        // AMF Set ID + Pointer
        builder.write_u16(guami.amf_id.set);
        builder.write_u8(guami.amf_id.pointer);
    }

    // Relative AMF Capacity
    builder.write_u8(ctx.relative_capacity);

    // PLMN Support List
    builder.write_u8(ctx.num_of_plmn_support as u8);
    for plmn_support in ctx.plmn_support.iter().take(ctx.num_of_plmn_support) {
        // PLMN ID
        builder.write_u8((plmn_support.plmn_id.mcc2 << 4) | plmn_support.plmn_id.mcc1);
        builder.write_u8((plmn_support.plmn_id.mnc3 << 4) | plmn_support.plmn_id.mcc3);
        builder.write_u8((plmn_support.plmn_id.mnc2 << 4) | plmn_support.plmn_id.mnc1);
        // S-NSSAI count
        builder.write_u8(plmn_support.num_of_s_nssai as u8);
        for s_nssai in plmn_support.s_nssai.iter().take(plmn_support.num_of_s_nssai) {
            builder.write_u8(s_nssai.sst);
            if let Some(sd) = s_nssai.sd {
                builder.write_u8(1); // SD present
                builder.write_u8((sd >> 16) as u8);
                builder.write_u8((sd >> 8) as u8);
                builder.write_u8(sd as u8);
            } else {
                builder.write_u8(0); // SD not present
            }
        }
    }

    Some(builder.build())
}

/// Build NG Setup Failure message
pub fn build_ng_setup_failure(cause: &NgapCause, time_to_wait: Option<u8>) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::NG_SETUP);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    // Time to wait (optional)
    if let Some(ttw) = time_to_wait {
        builder.write_u8(1); // present
        builder.write_u8(ttw);
    } else {
        builder.write_u8(0); // not present
    }

    builder.build()
}

/// Build Downlink NAS Transport message
pub fn build_downlink_nas_transport(
    ran_ue: &RanUe,
    nas_pdu: &[u8],
    mobility_restriction: bool,
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::DOWNLINK_NAS_TRANSPORT);
    // Criticality
    builder.write_u8(criticality::IGNORE);

    // AMF UE NGAP ID
    builder.write_u64(ran_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(ran_ue.ran_ue_ngap_id);

    // NAS PDU
    builder.write_u16(nas_pdu.len() as u16);
    builder.write_bytes(nas_pdu);

    // Mobility restriction (optional)
    builder.write_u8(if mobility_restriction { 1 } else { 0 });

    Some(builder.build())
}

/// Build UE Context Release Command message
pub fn build_ue_context_release_command(
    ran_ue: &RanUe,
    cause: &NgapCause,
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::UE_CONTEXT_RELEASE);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // UE NGAP IDs
    builder.write_u64(ran_ue.amf_ue_ngap_id);
    builder.write_u64(ran_ue.ran_ue_ngap_id);

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    Some(builder.build())
}

/// Build UE Context Modification Request message
pub fn build_ue_context_modification_request(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::UE_CONTEXT_MODIFICATION);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID (from associated RAN UE)
    builder.write_u64(amf_ue.ran_ue_id);

    // UE AMBR (if present)
    if amf_ue.ue_ambr.downlink > 0 || amf_ue.ue_ambr.uplink > 0 {
        builder.write_u8(1); // present
        builder.write_u64(amf_ue.ue_ambr.downlink);
        builder.write_u64(amf_ue.ue_ambr.uplink);
    } else {
        builder.write_u8(0); // not present
    }

    Some(builder.build())
}

/// Build PDU Session Resource Setup Request message
pub fn build_pdu_session_resource_setup_request(
    ran_ue: &RanUe,
    sess: &AmfSess,
    nas_pdu: Option<&[u8]>,
    n2_sm_info: &[u8],
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::PDU_SESSION_RESOURCE_SETUP);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(ran_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(ran_ue.ran_ue_ngap_id);

    // PDU Session ID
    builder.write_u8(sess.psi);

    // S-NSSAI
    builder.write_u8(sess.s_nssai.sst);
    if let Some(sd) = sess.s_nssai.sd {
        builder.write_u8(1);
        builder.write_u8((sd >> 16) as u8);
        builder.write_u8((sd >> 8) as u8);
        builder.write_u8(sd as u8);
    } else {
        builder.write_u8(0);
    }

    // NAS PDU (optional)
    if let Some(pdu) = nas_pdu {
        builder.write_u8(1);
        builder.write_u16(pdu.len() as u16);
        builder.write_bytes(pdu);
    } else {
        builder.write_u8(0);
    }

    // N2 SM Information
    builder.write_u16(n2_sm_info.len() as u16);
    builder.write_bytes(n2_sm_info);

    Some(builder.build())
}

/// Build PDU Session Resource Release Command message
pub fn build_pdu_session_resource_release_command(
    ran_ue: &RanUe,
    sess: &AmfSess,
    nas_pdu: Option<&[u8]>,
    n2_sm_info: &[u8],
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::PDU_SESSION_RESOURCE_RELEASE);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(ran_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(ran_ue.ran_ue_ngap_id);

    // PDU Session ID
    builder.write_u8(sess.psi);

    // NAS PDU (optional)
    if let Some(pdu) = nas_pdu {
        builder.write_u8(1);
        builder.write_u16(pdu.len() as u16);
        builder.write_bytes(pdu);
    } else {
        builder.write_u8(0);
    }

    // N2 SM Information
    builder.write_u16(n2_sm_info.len() as u16);
    builder.write_bytes(n2_sm_info);

    Some(builder.build())
}

/// Build Paging message
pub fn build_paging(amf_ue: &AmfUe, tai: &Tai5gs) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::PAGING);
    // Criticality
    builder.write_u8(criticality::IGNORE);

    // UE Paging Identity (5G-S-TMSI)
    builder.write_u16(amf_ue.current_guti.amf_set_id);
    builder.write_u8(amf_ue.current_guti.amf_pointer);
    builder.write_u32(amf_ue.current_guti.tmsi);

    // TAI List for Paging
    // PLMN ID
    builder.write_u8((tai.plmn_id.mcc2 << 4) | tai.plmn_id.mcc1);
    builder.write_u8((tai.plmn_id.mnc3 << 4) | tai.plmn_id.mcc3);
    builder.write_u8((tai.plmn_id.mnc2 << 4) | tai.plmn_id.mnc1);
    // TAC (3 bytes)
    builder.write_u8((tai.tac >> 16) as u8);
    builder.write_u8((tai.tac >> 8) as u8);
    builder.write_u8(tai.tac as u8);

    Some(builder.build())
}

/// Build Handover Request message
pub fn build_handover_request(
    target_ue: &RanUe,
    _source_ue: &RanUe,
    amf_ue: &AmfUe,
    cause: &NgapCause,
    source_to_target_container: &[u8],
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::HANDOVER_RESOURCE_ALLOCATION);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(target_ue.amf_ue_ngap_id);

    // Handover Type (intra-5GS = 0)
    builder.write_u8(0);

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    // UE AMBR
    builder.write_u64(amf_ue.ue_ambr.downlink);
    builder.write_u64(amf_ue.ue_ambr.uplink);

    // Source to Target Transparent Container
    builder.write_u16(source_to_target_container.len() as u16);
    builder.write_bytes(source_to_target_container);

    // Security context
    builder.write_u8(amf_ue.nhcc);
    builder.write_bytes(&amf_ue.nh);

    Some(builder.build())
}

/// Build Handover Command message
pub fn build_handover_command(
    source_ue: &RanUe,
    target_to_source_container: &[u8],
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::HANDOVER_PREPARATION);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(source_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(source_ue.ran_ue_ngap_id);

    // Handover Type (intra-5GS = 0)
    builder.write_u8(0);

    // Target to Source Transparent Container
    builder.write_u16(target_to_source_container.len() as u16);
    builder.write_bytes(target_to_source_container);

    Some(builder.build())
}

/// Build Handover Preparation Failure message
pub fn build_handover_preparation_failure(
    source_ue: &RanUe,
    cause: &NgapCause,
) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::HANDOVER_PREPARATION);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(source_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(source_ue.ran_ue_ngap_id);

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    Some(builder.build())
}

/// Build Handover Cancel Acknowledge message
pub fn build_handover_cancel_ack(source_ue: &RanUe) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::HANDOVER_CANCEL);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(source_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(source_ue.ran_ue_ngap_id);

    Some(builder.build())
}

/// Build Path Switch Request Acknowledge message
pub fn build_path_switch_ack(amf_ue: &AmfUe, ran_ue: &RanUe) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::PATH_SWITCH_REQUEST);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF UE NGAP ID
    builder.write_u64(ran_ue.amf_ue_ngap_id);
    // RAN UE NGAP ID
    builder.write_u64(ran_ue.ran_ue_ngap_id);

    // Security context
    builder.write_u8(amf_ue.nhcc);
    builder.write_bytes(&amf_ue.nh);

    Some(builder.build())
}

/// Build AMF Configuration Update message
pub fn build_amf_configuration_update(ctx: &AmfContext) -> Option<Vec<u8>> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::AMF_CONFIGURATION_UPDATE);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // AMF Name (if present)
    if let Some(ref name) = ctx.amf_name {
        builder.write_u8(name.len() as u8);
        builder.write_bytes(name.as_bytes());
    } else {
        builder.write_u8(0);
    }

    // Served GUAMI List
    builder.write_u8(ctx.num_of_served_guami as u8);
    for guami in ctx.served_guami.iter().take(ctx.num_of_served_guami) {
        builder.write_u8((guami.plmn_id.mcc2 << 4) | guami.plmn_id.mcc1);
        builder.write_u8((guami.plmn_id.mnc3 << 4) | guami.plmn_id.mcc3);
        builder.write_u8((guami.plmn_id.mnc2 << 4) | guami.plmn_id.mnc1);
        builder.write_u8(guami.amf_id.region);
        builder.write_u16(guami.amf_id.set);
        builder.write_u8(guami.amf_id.pointer);
    }

    // Relative AMF Capacity
    builder.write_u8(ctx.relative_capacity);

    Some(builder.build())
}

/// Build RAN Configuration Update Acknowledge message
pub fn build_ran_configuration_update_ack() -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::RAN_CONFIGURATION_UPDATE);
    // Criticality
    builder.write_u8(criticality::REJECT);

    builder.build()
}

/// Build RAN Configuration Update Failure message
pub fn build_ran_configuration_update_failure(
    cause: &NgapCause,
    time_to_wait: Option<u8>,
) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::RAN_CONFIGURATION_UPDATE);
    // Criticality
    builder.write_u8(criticality::REJECT);

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    // Time to wait (optional)
    if let Some(ttw) = time_to_wait {
        builder.write_u8(1);
        builder.write_u8(ttw);
    } else {
        builder.write_u8(0);
    }

    builder.build()
}

/// Build Error Indication message
pub fn build_error_indication(
    amf_ue_ngap_id: Option<u64>,
    ran_ue_ngap_id: Option<u64>,
    cause: &NgapCause,
) -> Vec<u8> {
    let mut builder = NgapMessageBuilder::new();

    // Procedure code
    builder.write_u16(procedure_code::ERROR_INDICATION);
    // Criticality
    builder.write_u8(criticality::IGNORE);

    // AMF UE NGAP ID (optional)
    if let Some(id) = amf_ue_ngap_id {
        builder.write_u8(1);
        builder.write_u64(id);
    } else {
        builder.write_u8(0);
    }

    // RAN UE NGAP ID (optional)
    if let Some(id) = ran_ue_ngap_id {
        builder.write_u8(1);
        builder.write_u64(id);
    } else {
        builder.write_u8(0);
    }

    // Cause
    builder.write_u8(cause.group);
    builder.write_u64(cause.cause as u64);

    builder.build()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AmfId, Guami, PlmnId, SNssai, OGS_SHA256_DIGEST_SIZE};

    fn create_test_context() -> AmfContext {
        let mut ctx = AmfContext::new();
        ctx.amf_name = Some("AMF-Test".to_string());
        ctx.relative_capacity = 255;
        ctx.num_of_served_guami = 1;
        ctx.served_guami.push(Guami {
            plmn_id: PlmnId::new("001", "01"),
            amf_id: AmfId {
                region: 1,
                set: 1,
                pointer: 1,
            },
        });
        ctx.num_of_plmn_support = 1;
        ctx.plmn_support.push(crate::context::PlmnSupport {
            plmn_id: PlmnId::new("001", "01"),
            num_of_s_nssai: 1,
            s_nssai: vec![SNssai { sst: 1, sd: None }],
        });
        ctx
    }

    fn create_test_ran_ue() -> RanUe {
        RanUe {
            id: 1,
            index: 1,
            gnb_id: 1,
            ran_ue_ngap_id: 1001,
            amf_ue_ngap_id: 2001,
            ..Default::default()
        }
    }

    fn create_test_amf_ue() -> AmfUe {
        AmfUe {
            id: 1,
            ran_ue_id: 1,
            current_guti: crate::context::Guti5gs {
                plmn_id: PlmnId::new("001", "01"),
                amf_region_id: 1,
                amf_set_id: 1,
                amf_pointer: 1,
                tmsi: 0x12345678,
            },
            nh: [0u8; OGS_SHA256_DIGEST_SIZE],
            nhcc: 1,
            ..Default::default()
        }
    }

    fn create_test_sess() -> AmfSess {
        AmfSess {
            id: 1,
            amf_ue_id: 1,
            psi: 5,
            s_nssai: SNssai { sst: 1, sd: Some(0x010203) },
            ..Default::default()
        }
    }

    #[test]
    fn test_ngap_message_builder() {
        let mut builder = NgapMessageBuilder::new();
        builder.write_u8(0x01);
        builder.write_u16(0x0203);
        builder.write_u32(0x04050607);

        let msg = builder.build();
        assert_eq!(msg.len(), 7);
        assert_eq!(msg[0], 0x01);
        assert_eq!(msg[1], 0x02);
        assert_eq!(msg[2], 0x03);
    }

    #[test]
    fn test_build_ng_setup_response() {
        let ctx = create_test_context();
        let msg = build_ng_setup_response(&ctx);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        // Check procedure code
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::NG_SETUP);
    }

    #[test]
    fn test_build_ng_setup_failure() {
        let cause = NgapCause {
            group: cause_group::MISC,
            cause: 0,
        };
        let msg = build_ng_setup_failure(&cause, Some(5));

        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::NG_SETUP);
    }

    #[test]
    fn test_build_downlink_nas_transport() {
        let ran_ue = create_test_ran_ue();
        let nas_pdu = vec![0x7e, 0x00, 0x42];
        let msg = build_downlink_nas_transport(&ran_ue, &nas_pdu, false);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::DOWNLINK_NAS_TRANSPORT);
    }

    #[test]
    fn test_build_ue_context_release_command() {
        let ran_ue = create_test_ran_ue();
        let cause = NgapCause {
            group: cause_group::NAS,
            cause: 0,
        };
        let msg = build_ue_context_release_command(&ran_ue, &cause);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::UE_CONTEXT_RELEASE);
    }

    #[test]
    fn test_build_pdu_session_resource_setup_request() {
        let ran_ue = create_test_ran_ue();
        let sess = create_test_sess();
        let n2_sm_info = vec![0x01, 0x02, 0x03];
        let msg = build_pdu_session_resource_setup_request(&ran_ue, &sess, None, &n2_sm_info);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::PDU_SESSION_RESOURCE_SETUP);
    }

    #[test]
    fn test_build_paging() {
        let amf_ue = create_test_amf_ue();
        let tai = Tai5gs {
            plmn_id: PlmnId::new("001", "01"),
            tac: 1,
        };
        let msg = build_paging(&amf_ue, &tai);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::PAGING);
    }

    #[test]
    fn test_build_handover_cancel_ack() {
        let ran_ue = create_test_ran_ue();
        let msg = build_handover_cancel_ack(&ran_ue);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::HANDOVER_CANCEL);
    }

    #[test]
    fn test_build_error_indication() {
        let cause = NgapCause {
            group: cause_group::PROTOCOL,
            cause: 0,
        };
        let msg = build_error_indication(Some(1001), Some(2001), &cause);

        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::ERROR_INDICATION);
    }

    #[test]
    fn test_build_ran_configuration_update_ack() {
        let msg = build_ran_configuration_update_ack();

        assert!(!msg.is_empty());
        assert_eq!((msg[0] as u16) << 8 | msg[1] as u16, procedure_code::RAN_CONFIGURATION_UPDATE);
    }
}
