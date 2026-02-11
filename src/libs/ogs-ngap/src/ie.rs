//! NGAP IE Encoding/Decoding Helpers
//!
//! Functions for encoding individual Information Elements into raw APER bytes
//! suitable for ProtocolIeField values, and decoding them back.

use ogs_asn1c::ngap::cause::Cause;
use ogs_asn1c::ngap::ies::{
    AmfUeNgapId, NasPdu, ProtocolIeContainer, ProtocolIeField, RanUeNgapId, RelativeAmfCapacity,
};
use ogs_asn1c::ngap::types::{Criticality, ProtocolIeId};
use ogs_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};

use crate::error::NgapResult;
use crate::types::*;

// ============================================================================
// IE Encoding Helpers
// ============================================================================

/// Encode a value to raw APER bytes for use in ProtocolIeField.value
fn encode_ie_value<T: AperEncode>(value: &T) -> NgapResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    value.encode_aper(&mut encoder)?;
    encoder.align();
    Ok(encoder.into_bytes().to_vec())
}

/// Create a ProtocolIeField with the given ID, criticality, and encoded value
fn make_ie_field<T: AperEncode>(
    id: ProtocolIeId,
    criticality: Criticality,
    value: &T,
) -> NgapResult<ProtocolIeField> {
    Ok(ProtocolIeField {
        id,
        criticality,
        value: encode_ie_value(value)?,
    })
}

/// Decode a value from raw APER bytes in a ProtocolIeField.value
fn decode_ie_value<T: AperDecode>(raw: &[u8]) -> NgapResult<T> {
    let mut decoder = AperDecoder::new(raw);
    Ok(T::decode_aper(&mut decoder)?)
}

// ============================================================================
// AMF-UE-NGAP-ID IE
// ============================================================================

pub fn encode_amf_ue_ngap_id(container: &mut ProtocolIeContainer, id: u64) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::AMF_UE_NGAP_ID,
        Criticality::Reject,
        &AmfUeNgapId(id),
    )?);
    Ok(())
}

pub fn decode_amf_ue_ngap_id(field: &ProtocolIeField) -> NgapResult<u64> {
    let id: AmfUeNgapId = decode_ie_value(&field.value)?;
    Ok(id.0)
}

// ============================================================================
// RAN-UE-NGAP-ID IE
// ============================================================================

pub fn encode_ran_ue_ngap_id(container: &mut ProtocolIeContainer, id: u32) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::RAN_UE_NGAP_ID,
        Criticality::Reject,
        &RanUeNgapId(id),
    )?);
    Ok(())
}

pub fn decode_ran_ue_ngap_id(field: &ProtocolIeField) -> NgapResult<u32> {
    let id: RanUeNgapId = decode_ie_value(&field.value)?;
    Ok(id.0)
}

// ============================================================================
// NAS-PDU IE
// ============================================================================

pub fn encode_nas_pdu(container: &mut ProtocolIeContainer, pdu: &[u8]) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::NAS_PDU,
        Criticality::Reject,
        &NasPdu(pdu.to_vec()),
    )?);
    Ok(())
}

pub fn decode_nas_pdu(field: &ProtocolIeField) -> NgapResult<Vec<u8>> {
    let pdu: NasPdu = decode_ie_value(&field.value)?;
    Ok(pdu.0)
}

// ============================================================================
// Cause IE
// ============================================================================

pub fn encode_cause(container: &mut ProtocolIeContainer, cause: &Cause) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::CAUSE,
        Criticality::Ignore,
        cause,
    )?);
    Ok(())
}

pub fn decode_cause(field: &ProtocolIeField) -> NgapResult<Cause> {
    decode_ie_value(&field.value)
}

// ============================================================================
// RelativeAMFCapacity IE
// ============================================================================

pub fn encode_relative_amf_capacity(
    container: &mut ProtocolIeContainer,
    capacity: u8,
) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::RELATIVE_AMF_CAPACITY,
        Criticality::Ignore,
        &RelativeAmfCapacity(capacity),
    )?);
    Ok(())
}

pub fn decode_relative_amf_capacity(field: &ProtocolIeField) -> NgapResult<u8> {
    let cap: RelativeAmfCapacity = decode_ie_value(&field.value)?;
    Ok(cap.0)
}

// ============================================================================
// TimeToWait IE
// ============================================================================

pub fn encode_time_to_wait(
    container: &mut ProtocolIeContainer,
    ttw: TimeToWait,
) -> NgapResult<()> {
    let asn_ttw = match ttw {
        TimeToWait::V1s => ogs_asn1c::ngap::ies::TimeToWait::V1s,
        TimeToWait::V2s => ogs_asn1c::ngap::ies::TimeToWait::V2s,
        TimeToWait::V5s => ogs_asn1c::ngap::ies::TimeToWait::V5s,
        TimeToWait::V10s => ogs_asn1c::ngap::ies::TimeToWait::V10s,
        TimeToWait::V20s => ogs_asn1c::ngap::ies::TimeToWait::V20s,
        TimeToWait::V60s => ogs_asn1c::ngap::ies::TimeToWait::V60s,
    };
    container.push(make_ie_field(
        ProtocolIeId::TIME_TO_WAIT,
        Criticality::Ignore,
        &asn_ttw,
    )?);
    Ok(())
}

pub fn decode_time_to_wait(field: &ProtocolIeField) -> NgapResult<TimeToWait> {
    let asn_ttw: ogs_asn1c::ngap::ies::TimeToWait = decode_ie_value(&field.value)?;
    Ok(match asn_ttw {
        ogs_asn1c::ngap::ies::TimeToWait::V1s => TimeToWait::V1s,
        ogs_asn1c::ngap::ies::TimeToWait::V2s => TimeToWait::V2s,
        ogs_asn1c::ngap::ies::TimeToWait::V5s => TimeToWait::V5s,
        ogs_asn1c::ngap::ies::TimeToWait::V10s => TimeToWait::V10s,
        ogs_asn1c::ngap::ies::TimeToWait::V20s => TimeToWait::V20s,
        ogs_asn1c::ngap::ies::TimeToWait::V60s => TimeToWait::V60s,
    })
}

// ============================================================================
// AMFName IE (PrintableString, encoded as unconstrained OCTET STRING)
// ============================================================================

/// IE ID for additional IDs not in the base types module
pub const IE_ID_AMF_NAME: u16 = 1;
pub const IE_ID_SERVED_GUAMI_LIST: u16 = 96;
pub const IE_ID_PLMN_SUPPORT_LIST: u16 = 80;
pub const IE_ID_GLOBAL_RAN_NODE_ID: u16 = 27;
pub const IE_ID_RAN_NODE_NAME: u16 = 82;
pub const IE_ID_SUPPORTED_TA_LIST: u16 = 102;
pub const IE_ID_DEFAULT_PAGING_DRX: u16 = 18;
pub const IE_ID_UE_SECURITY_CAPABILITIES: u16 = 119;
pub const IE_ID_SECURITY_KEY: u16 = 94;
pub const IE_ID_UE_AGGREGATE_MAXIMUM_BIT_RATE: u16 = 110;
pub const IE_ID_GUAMI: u16 = 28;
pub const IE_ID_ALLOWED_NSSAI: u16 = 0;
pub const IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ: u16 = 74;
pub const IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES: u16 = 75;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES: u16 = 58;
pub const IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ: u16 = 64;
pub const IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES: u16 = 65;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_RES: u16 = 54;
pub const IE_ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD: u16 = 79;
pub const IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES: u16 = 70;
pub const IE_ID_UE_NGAP_IDS: u16 = 114;
pub const IE_ID_USER_LOCATION_INFORMATION: u16 = 121;
pub const IE_ID_RRC_ESTABLISHMENT_CAUSE: u16 = 90;
pub const IE_ID_UE_CONTEXT_REQUEST: u16 = 112;

/// Encode AMF Name as a PrintableString IE
pub fn encode_amf_name(container: &mut ProtocolIeContainer, name: &str) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // PrintableString (1..150, ...) - encode as unconstrained for simplicity
    encoder.encode_octet_string(name.as_bytes(), None, None)?;
    encoder.align();
    let value = encoder.into_bytes().to_vec();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_AMF_NAME),
        criticality: Criticality::Reject,
        value,
    });
    Ok(())
}

/// Decode AMF Name from a raw IE field
pub fn decode_amf_name(field: &ProtocolIeField) -> NgapResult<String> {
    let mut decoder = AperDecoder::new(&field.value);
    let bytes = decoder.decode_octet_string(None, None)?;
    String::from_utf8(bytes).map_err(|e| {
        crate::error::NgapError::InvalidIeValue {
            ie_name: "AMFName",
            reason: e.to_string(),
        }
    })
}

// ============================================================================
// Opaque/Composite IE encoding helpers
// ============================================================================

/// Encode a raw octet string IE (for opaque values)
pub fn encode_raw_octet_ie(
    container: &mut ProtocolIeContainer,
    ie_id: u16,
    criticality: Criticality,
    data: &[u8],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_octet_string(data, None, None)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(ie_id),
        criticality,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode a raw octet string from an IE field
pub fn decode_raw_octet_ie(field: &ProtocolIeField) -> NgapResult<Vec<u8>> {
    let mut decoder = AperDecoder::new(&field.value);
    Ok(decoder.decode_octet_string(None, None)?)
}

/// Encode a GUAMI to raw bytes for an IE
pub fn encode_guami_ie(container: &mut ProtocolIeContainer, guami: &Guami) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // GUAMI is a SEQUENCE: plmnIdentity, amfRegionID, amfSetID, amfPointer
    // Extension bit (not present)
    encoder.write_bit(false);
    // PLMN Identity (3 bytes, fixed)
    encoder.encode_octet_string(&guami.plmn_identity, Some(3), Some(3))?;
    // AMF Region ID (8 bits, fixed BIT STRING)
    encoder.write_bits(guami.amf_region_id as u64, 8);
    // AMF Set ID (10 bits, fixed BIT STRING)
    encoder.write_bits(guami.amf_set_id as u64, 10);
    // AMF Pointer (6 bits, fixed BIT STRING)
    encoder.write_bits(guami.amf_pointer as u64, 6);
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_GUAMI),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode GUAMI from an IE field
pub fn decode_guami_ie(field: &ProtocolIeField) -> NgapResult<Guami> {
    let mut decoder = AperDecoder::new(&field.value);
    // Extension bit
    let _ext = decoder.read_bit()?;
    // PLMN Identity (3 bytes)
    let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
    let mut plmn_identity = [0u8; 3];
    plmn_identity.copy_from_slice(&plmn_bytes);
    // AMF Region ID (8 bits)
    let amf_region_id = decoder.read_bits(8)? as u8;
    // AMF Set ID (10 bits)
    let amf_set_id = decoder.read_bits(10)? as u16;
    // AMF Pointer (6 bits)
    let amf_pointer = decoder.read_bits(6)? as u8;

    Ok(Guami {
        plmn_identity,
        amf_region_id,
        amf_set_id,
        amf_pointer,
    })
}

/// Encode Served GUAMI List IE
pub fn encode_served_guami_list(
    container: &mut ProtocolIeContainer,
    list: &[ServedGuamiItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SEQUENCE (SIZE (1..maxnoofServedGUAMIs=256)) OF ServedGUAMIItem
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        // ServedGUAMIItem is SEQUENCE { guami, backupAMFName OPTIONAL, iE-Extensions OPTIONAL }
        // Extension bit
        encoder.write_bit(false);
        // Optional bitmap: backupAMFName, iE-Extensions
        encoder.write_bit(item.backup_amf_name.is_some());
        encoder.write_bit(false); // no extensions

        // GUAMI SEQUENCE
        encode_guami_inline(&mut encoder, &item.guami)?;

        if let Some(ref name) = item.backup_amf_name {
            encoder.encode_octet_string(name.as_bytes(), None, None)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_SERVED_GUAMI_LIST),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PLMN Support List IE
pub fn encode_plmn_support_list(
    container: &mut ProtocolIeContainer,
    list: &[PlmnSupportItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SEQUENCE (SIZE (1..maxnoofPLMNs=12)) OF PLMNSupportItem
    encoder.encode_constrained_length(list.len(), 1, 12)?;
    for item in list {
        // PLMNSupportItem SEQUENCE { plmnIdentity, sliceSupportList, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension bit
        encoder.write_bit(false); // iE-Extensions not present

        // PLMN Identity
        encoder.encode_octet_string(&item.plmn_identity, Some(3), Some(3))?;

        // SliceSupportList: SEQUENCE (SIZE (1..maxnoofSliceItems=1024)) OF SliceSupportItem
        encoder.encode_constrained_length(item.slice_support_list.len(), 1, 1024)?;
        for snssai in &item.slice_support_list {
            encode_snssai_inline(&mut encoder, snssai)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PLMN_SUPPORT_LIST),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode Allowed NSSAI IE
pub fn encode_allowed_nssai(
    container: &mut ProtocolIeContainer,
    nssai_list: &[SNssai],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // AllowedNSSAI: SEQUENCE (SIZE (1..maxnoofAllowedS-NSSAIs=8)) OF AllowedNSSAI-Item
    encoder.encode_constrained_length(nssai_list.len(), 1, 8)?;
    for snssai in nssai_list {
        // AllowedNSSAI-Item SEQUENCE { s-NSSAI, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encode_snssai_inline(&mut encoder, snssai)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_ALLOWED_NSSAI),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode UE Security Capabilities IE
pub fn encode_ue_security_capabilities(
    container: &mut ProtocolIeContainer,
    caps: &UeSecurityCapabilities,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UESecurityCapabilities SEQUENCE { nRencryptionAlgorithms, nRintegrityProtectionAlgorithms,
    //   eUTRAencryptionAlgorithms, eUTRAintegrityProtectionAlgorithms, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
    // Each is BIT STRING (SIZE (16))
    encoder.write_bits(caps.nr_encryption_algorithms as u64, 16);
    encoder.write_bits(caps.nr_integrity_algorithms as u64, 16);
    encoder.write_bits(caps.eutra_encryption_algorithms as u64, 16);
    encoder.write_bits(caps.eutra_integrity_algorithms as u64, 16);
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_SECURITY_CAPABILITIES),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode UE Security Capabilities from IE field
pub fn decode_ue_security_capabilities(
    field: &ProtocolIeField,
) -> NgapResult<UeSecurityCapabilities> {
    let mut decoder = AperDecoder::new(&field.value);
    let _ext = decoder.read_bit()?;
    let _ie_ext_present = decoder.read_bit()?;
    let nr_enc = decoder.read_bits(16)? as u16;
    let nr_int = decoder.read_bits(16)? as u16;
    let eutra_enc = decoder.read_bits(16)? as u16;
    let eutra_int = decoder.read_bits(16)? as u16;
    Ok(UeSecurityCapabilities {
        nr_encryption_algorithms: nr_enc,
        nr_integrity_algorithms: nr_int,
        eutra_encryption_algorithms: eutra_enc,
        eutra_integrity_algorithms: eutra_int,
    })
}

/// Encode Security Key IE (BIT STRING SIZE (256))
pub fn encode_security_key(
    container: &mut ProtocolIeContainer,
    key: &[u8; 32],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SecurityKey ::= BIT STRING (SIZE(256))
    // Fixed size = 256 bits = 32 bytes, no length determinant needed
    // For fixed size > 16 bits, align first
    encoder.align();
    encoder.write_bytes(key);
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_SECURITY_KEY),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode Security Key from IE field
pub fn decode_security_key(field: &ProtocolIeField) -> NgapResult<[u8; 32]> {
    let mut decoder = AperDecoder::new(&field.value);
    decoder.align();
    let bytes = decoder.read_bytes(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Encode UE Aggregate Maximum Bit Rate IE
pub fn encode_ue_ambr(
    container: &mut ProtocolIeContainer,
    ambr: &UeAmbrInfo,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UEAggregateMaximumBitRate SEQUENCE { uEAggregateMaximumBitRateDL, uEAggregateMaximumBitRateUL, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
    // BitRate ::= INTEGER (0..4000000000000, ...) - encoded as unconstrained
    encoder.encode_unconstrained_whole_number(ambr.dl as i64)?;
    encoder.encode_unconstrained_whole_number(ambr.ul as i64)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_AGGREGATE_MAXIMUM_BIT_RATE),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode UE AMBR from IE field
pub fn decode_ue_ambr(field: &ProtocolIeField) -> NgapResult<UeAmbrInfo> {
    let mut decoder = AperDecoder::new(&field.value);
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    let dl = decoder.decode_unconstrained_whole_number()? as u64;
    let ul = decoder.decode_unconstrained_whole_number()? as u64;
    Ok(UeAmbrInfo { dl, ul })
}

/// Encode Global RAN Node ID IE
pub fn encode_global_ran_node_id(
    container: &mut ProtocolIeContainer,
    id: &GlobalRanNodeId,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    match id {
        GlobalRanNodeId::GlobalGnbId {
            plmn_identity,
            gnb_id,
            gnb_id_len,
        } => {
            // GlobalRANNodeID CHOICE: globalGNB-ID is index 0 out of 4 alternatives, extensible
            encoder.encode_choice_index(0, 4, true)?;
            // GlobalGNB-ID SEQUENCE { plmnIdentity, gNB-ID, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            // PLMN Identity
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // GNB-ID CHOICE: gNB-ID (BIT STRING (22..32)) is index 0 out of 1, extensible
            encoder.encode_choice_index(0, 1, true)?;
            let len = *gnb_id_len as usize;
            // BIT STRING (SIZE (22..32)) - constrained length
            encoder.encode_constrained_length(len, 22, 32)?;
            encoder.write_bits(*gnb_id as u64, len);
        }
        GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
        } => {
            // globalNgENB-ID is index 1
            encoder.encode_choice_index(1, 4, true)?;
            encoder.write_bit(false);
            encoder.write_bit(false);
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // NgENB-ID CHOICE: macroNgENB-ID (BIT STRING (20)) is index 0
            encoder.encode_choice_index(0, 2, true)?;
            encoder.write_bits(*ng_enb_id as u64, 20);
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_GLOBAL_RAN_NODE_ID),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode Global RAN Node ID from IE field
pub fn decode_global_ran_node_id(field: &ProtocolIeField) -> NgapResult<GlobalRanNodeId> {
    let mut decoder = AperDecoder::new(&field.value);
    let choice = decoder.decode_choice_index(4, true)?;
    match choice {
        0 => {
            // GlobalGNB-ID
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut plmn_identity = [0u8; 3];
            plmn_identity.copy_from_slice(&plmn_bytes);
            // GNB-ID CHOICE
            let _gnb_choice = decoder.decode_choice_index(1, true)?;
            let gnb_id_len = decoder.decode_constrained_length(22, 32)?;
            let gnb_id = decoder.read_bits(gnb_id_len)? as u32;
            Ok(GlobalRanNodeId::GlobalGnbId {
                plmn_identity,
                gnb_id,
                gnb_id_len: gnb_id_len as u8,
            })
        }
        1 => {
            // GlobalNgENB-ID
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut plmn_identity = [0u8; 3];
            plmn_identity.copy_from_slice(&plmn_bytes);
            let _enb_choice = decoder.decode_choice_index(2, true)?;
            let ng_enb_id = decoder.read_bits(20)? as u32;
            Ok(GlobalRanNodeId::GlobalNgEnbId {
                plmn_identity,
                ng_enb_id,
            })
        }
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "GlobalRANNodeID",
            reason: format!("Unknown choice index: {}", choice),
        }),
    }
}

/// Encode RAN Node Name IE
pub fn encode_ran_node_name(
    container: &mut ProtocolIeContainer,
    name: &str,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_octet_string(name.as_bytes(), None, None)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_RAN_NODE_NAME),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode RAN Node Name from IE field
pub fn decode_ran_node_name(field: &ProtocolIeField) -> NgapResult<String> {
    let mut decoder = AperDecoder::new(&field.value);
    let bytes = decoder.decode_octet_string(None, None)?;
    String::from_utf8(bytes).map_err(|e| crate::error::NgapError::InvalidIeValue {
        ie_name: "RANNodeName",
        reason: e.to_string(),
    })
}

/// Encode Supported TA List IE
pub fn encode_supported_ta_list(
    container: &mut ProtocolIeContainer,
    list: &[SupportedTaItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SupportedTAList: SEQUENCE (SIZE (1..maxnoofTACs=256)) OF SupportedTAItem
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        // SupportedTAItem SEQUENCE { tAC, broadcastPLMNList, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        // TAC (3 bytes, fixed)
        encoder.encode_octet_string(&item.tac, Some(3), Some(3))?;
        // BroadcastPLMNList: SEQUENCE (SIZE (1..maxnoofBPLMNs=12)) OF BroadcastPLMNItem
        encoder.encode_constrained_length(item.broadcast_plmn_list.len(), 1, 12)?;
        for bp in &item.broadcast_plmn_list {
            // BroadcastPLMNItem SEQUENCE { plmnIdentity, tAISliceSupportList, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            encoder.encode_octet_string(&bp.plmn_identity, Some(3), Some(3))?;
            // SliceSupportList: SEQUENCE (SIZE (1..maxnoofSliceItems=1024))
            encoder.encode_constrained_length(bp.tai_slice_support_list.len(), 1, 1024)?;
            for snssai in &bp.tai_slice_support_list {
                encode_snssai_inline(&mut encoder, snssai)?;
            }
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_SUPPORTED_TA_LIST),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode Supported TA List from IE field
pub fn decode_supported_ta_list(field: &ProtocolIeField) -> NgapResult<Vec<SupportedTaItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let ta_count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(ta_count);
    for _ in 0..ta_count {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let tac_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut tac = [0u8; 3];
        tac.copy_from_slice(&tac_bytes);
        let bp_count = decoder.decode_constrained_length(1, 12)?;
        let mut broadcast_plmn_list = Vec::with_capacity(bp_count);
        for _ in 0..bp_count {
            let _bp_ext = decoder.read_bit()?;
            let _bp_ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut plmn_identity = [0u8; 3];
            plmn_identity.copy_from_slice(&plmn_bytes);
            let slice_count = decoder.decode_constrained_length(1, 1024)?;
            let mut tai_slice_support_list = Vec::with_capacity(slice_count);
            for _ in 0..slice_count {
                tai_slice_support_list.push(decode_snssai_inline(&mut decoder)?);
            }
            broadcast_plmn_list.push(BroadcastPlmnItem {
                plmn_identity,
                tai_slice_support_list,
            });
        }
        result.push(SupportedTaItem {
            tac,
            broadcast_plmn_list,
        });
    }
    Ok(result)
}

/// Encode Default Paging DRX IE
pub fn encode_default_paging_drx(
    container: &mut ProtocolIeContainer,
    drx: PagingDrx,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // PagingDRX ::= ENUMERATED { v32, v64, v128, v256, ... }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 3);
    encoder.encode_enumerated(drx as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_DEFAULT_PAGING_DRX),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode Default Paging DRX from IE field
pub fn decode_default_paging_drx(field: &ProtocolIeField) -> NgapResult<PagingDrx> {
    let mut decoder = AperDecoder::new(&field.value);
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 3);
    let val = decoder.decode_enumerated(&constraint)?;
    match val {
        0 => Ok(PagingDrx::V32),
        1 => Ok(PagingDrx::V64),
        2 => Ok(PagingDrx::V128),
        3 => Ok(PagingDrx::V256),
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "PagingDRX",
            reason: format!("Unknown value: {}", val),
        }),
    }
}

/// Encode User Location Information IE
pub fn encode_user_location_info(
    container: &mut ProtocolIeContainer,
    info: &UserLocationInformation,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    match info {
        UserLocationInformation::Nr {
            nr_cgi_plmn,
            nr_cell_identity,
            tai_plmn,
            tai_tac,
        } => {
            // UserLocationInformation CHOICE: userLocationInformationNR is index 1 out of 2, extensible
            encoder.encode_choice_index(1, 2, true)?;
            // UserLocationInformationNR SEQUENCE { nR-CGI, tAI, timeStamp OPTIONAL, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // timeStamp not present
            encoder.write_bit(false); // no iE-Extensions
            // NR-CGI SEQUENCE { pLMNIdentity, nRCellIdentity, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            encoder.encode_octet_string(nr_cgi_plmn, Some(3), Some(3))?;
            // NRCellIdentity BIT STRING (SIZE (36))
            encoder.write_bits(*nr_cell_identity, 36);
            // TAI SEQUENCE { pLMNIdentity, tAC, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            encoder.encode_octet_string(tai_plmn, Some(3), Some(3))?;
            encoder.encode_octet_string(tai_tac, Some(3), Some(3))?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_USER_LOCATION_INFORMATION),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode User Location Information from IE field
pub fn decode_user_location_info(
    field: &ProtocolIeField,
) -> NgapResult<UserLocationInformation> {
    let mut decoder = AperDecoder::new(&field.value);
    let choice = decoder.decode_choice_index(2, true)?;
    match choice {
        1 => {
            // UserLocationInformationNR
            let _ext = decoder.read_bit()?;
            let _ts_present = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            // NR-CGI
            let _cgi_ext = decoder.read_bit()?;
            let _cgi_ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut nr_cgi_plmn = [0u8; 3];
            nr_cgi_plmn.copy_from_slice(&plmn_bytes);
            let nr_cell_identity = decoder.read_bits(36)?;
            // TAI
            let _tai_ext = decoder.read_bit()?;
            let _tai_ie_ext = decoder.read_bit()?;
            let tai_plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut tai_plmn = [0u8; 3];
            tai_plmn.copy_from_slice(&tai_plmn_bytes);
            let tac_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut tai_tac = [0u8; 3];
            tai_tac.copy_from_slice(&tac_bytes);
            Ok(UserLocationInformation::Nr {
                nr_cgi_plmn,
                nr_cell_identity,
                tai_plmn,
                tai_tac,
            })
        }
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "UserLocationInformation",
            reason: format!("Unsupported choice index: {}", choice),
        }),
    }
}

/// Encode RRC Establishment Cause IE
pub fn encode_rrc_establishment_cause(
    container: &mut ProtocolIeContainer,
    cause: RrcEstablishmentCause,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // RRCEstablishmentCause ::= ENUMERATED { emergency, ..., notAvailable }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 9);
    encoder.encode_enumerated(cause as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_RRC_ESTABLISHMENT_CAUSE),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode RRC Establishment Cause from IE field
pub fn decode_rrc_establishment_cause(field: &ProtocolIeField) -> NgapResult<RrcEstablishmentCause> {
    let mut decoder = AperDecoder::new(&field.value);
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 9);
    let val = decoder.decode_enumerated(&constraint)?;
    Ok(match val {
        0 => RrcEstablishmentCause::Emergency,
        1 => RrcEstablishmentCause::HighPriorityAccess,
        2 => RrcEstablishmentCause::MtAccess,
        3 => RrcEstablishmentCause::MoSignalling,
        4 => RrcEstablishmentCause::MoData,
        5 => RrcEstablishmentCause::MoVoiceCall,
        6 => RrcEstablishmentCause::MoVideoCall,
        7 => RrcEstablishmentCause::MoSms,
        8 => RrcEstablishmentCause::MpsPriorityAccess,
        9 => RrcEstablishmentCause::McsPriorityAccess,
        10 => RrcEstablishmentCause::NotAvailable,
        _ => RrcEstablishmentCause::NotAvailable,
    })
}

/// Encode UE Context Request IE
pub fn encode_ue_context_request(
    container: &mut ProtocolIeContainer,
    requested: bool,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UEContextRequest ::= ENUMERATED { requested, ... }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 0);
    encoder.encode_enumerated(if requested { 0 } else { 0 }, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_CONTEXT_REQUEST),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode UE-NGAP-IDs IE (for UE Context Release Command)
pub fn encode_ue_ngap_ids(
    container: &mut ProtocolIeContainer,
    ids: &UeNgapIds,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UE-NGAP-IDs CHOICE { uE-NGAP-ID-pair, aMF-UE-NGAP-ID, choice-Extensions }
    match ids {
        UeNgapIds::Pair {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
        } => {
            encoder.encode_choice_index(0, 2, true)?;
            // UE-NGAP-ID-pair SEQUENCE { aMF-UE-NGAP-ID, rAN-UE-NGAP-ID, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            AmfUeNgapId(*amf_ue_ngap_id).encode_aper(&mut encoder)?;
            RanUeNgapId(*ran_ue_ngap_id).encode_aper(&mut encoder)?;
        }
        UeNgapIds::AmfOnly { amf_ue_ngap_id } => {
            encoder.encode_choice_index(1, 2, true)?;
            AmfUeNgapId(*amf_ue_ngap_id).encode_aper(&mut encoder)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_NGAP_IDS),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode UE-NGAP-IDs from IE field
pub fn decode_ue_ngap_ids(field: &ProtocolIeField) -> NgapResult<UeNgapIds> {
    let mut decoder = AperDecoder::new(&field.value);
    let choice = decoder.decode_choice_index(2, true)?;
    match choice {
        0 => {
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            let amf_id = AmfUeNgapId::decode_aper(&mut decoder)?;
            let ran_id = RanUeNgapId::decode_aper(&mut decoder)?;
            Ok(UeNgapIds::Pair {
                amf_ue_ngap_id: amf_id.0,
                ran_ue_ngap_id: ran_id.0,
            })
        }
        1 => {
            let amf_id = AmfUeNgapId::decode_aper(&mut decoder)?;
            Ok(UeNgapIds::AmfOnly {
                amf_ue_ngap_id: amf_id.0,
            })
        }
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "UE-NGAP-IDs",
            reason: format!("Unknown choice index: {}", choice),
        }),
    }
}

// ============================================================================
// Inline encoding helpers (encode directly into an existing encoder)
// ============================================================================

/// Encode GUAMI inline (into an existing encoder, not as separate IE)
fn encode_guami_inline(encoder: &mut AperEncoder, guami: &Guami) -> NgapResult<()> {
    // GUAMI SEQUENCE { plmnIdentity, amfRegionID, amfSetID, amfPointer, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
    encoder.encode_octet_string(&guami.plmn_identity, Some(3), Some(3))?;
    encoder.write_bits(guami.amf_region_id as u64, 8);
    encoder.write_bits(guami.amf_set_id as u64, 10);
    encoder.write_bits(guami.amf_pointer as u64, 6);
    Ok(())
}

/// Encode S-NSSAI inline
fn encode_snssai_inline(encoder: &mut AperEncoder, snssai: &SNssai) -> NgapResult<()> {
    // SliceSupportItem SEQUENCE { s-NSSAI, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension for SliceSupportItem
    encoder.write_bit(false); // no iE-Extensions for SliceSupportItem
    // S-NSSAI SEQUENCE { sST, sD OPTIONAL, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(snssai.sd.is_some()); // SD present
    encoder.write_bit(false); // no iE-Extensions
    // SST: OCTET STRING (SIZE (1))
    encoder.encode_octet_string(&[snssai.sst], Some(1), Some(1))?;
    // SD: OCTET STRING (SIZE (3)), optional
    if let Some(ref sd) = snssai.sd {
        encoder.encode_octet_string(sd, Some(3), Some(3))?;
    }
    Ok(())
}

/// Decode S-NSSAI inline (from within a SliceSupportItem)
fn decode_snssai_inline(decoder: &mut AperDecoder) -> NgapResult<SNssai> {
    // SliceSupportItem
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    // S-NSSAI
    let _snssai_ext = decoder.read_bit()?;
    let sd_present = decoder.read_bit()?;
    let _snssai_ie_ext = decoder.read_bit()?;
    let sst_bytes = decoder.decode_octet_string(Some(1), Some(1))?;
    let sst = sst_bytes[0];
    let sd = if sd_present {
        let sd_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut sd = [0u8; 3];
        sd.copy_from_slice(&sd_bytes);
        Some(sd)
    } else {
        None
    };
    Ok(SNssai { sst, sd })
}

// ============================================================================
// PDU Session Resource List encoding helpers
// ============================================================================

/// Encode PDU Session Resource Setup List for Setup Request
pub fn encode_pdu_session_setup_list_su_req(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceSetupItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SEQUENCE (SIZE (1..maxnoofPDUSessions=256))
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        // PDUSessionResourceSetupItemSUReq SEQUENCE {
        //   pDUSessionID, pDUSessionNAS-PDU OPTIONAL, s-NSSAI,
        //   pDUSessionResourceSetupRequestTransfer, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(item.nas_pdu.is_some()); // NAS-PDU optional
        encoder.write_bit(false); // no iE-Extensions
        // PDUSessionID ::= INTEGER (0..255)
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        if let Some(ref nas_pdu) = item.nas_pdu {
            encoder.encode_octet_string(nas_pdu, None, None)?;
        }
        // S-NSSAI inline (without SliceSupportItem wrapper)
        encoder.write_bit(false); // extension
        encoder.write_bit(item.s_nssai.sd.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encoder.encode_octet_string(&[item.s_nssai.sst], Some(1), Some(1))?;
        if let Some(ref sd) = item.s_nssai.sd {
            encoder.encode_octet_string(sd, Some(3), Some(3))?;
        }
        // Transfer (OCTET STRING, unconstrained)
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode PDU Session Resource Setup List from Setup Request
pub fn decode_pdu_session_setup_list_su_req(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceSetupItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let nas_pdu_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        let pdu_session_id = decoder.decode_constrained_whole_number(&pdu_constraint)? as u8;
        let nas_pdu = if nas_pdu_present {
            Some(decoder.decode_octet_string(None, None)?)
        } else {
            None
        };
        // S-NSSAI
        let _snssai_ext = decoder.read_bit()?;
        let sd_present = decoder.read_bit()?;
        let _snssai_ie_ext = decoder.read_bit()?;
        let sst_bytes = decoder.decode_octet_string(Some(1), Some(1))?;
        let sd = if sd_present {
            let sd_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut sd = [0u8; 3];
            sd.copy_from_slice(&sd_bytes);
            Some(sd)
        } else {
            None
        };
        let transfer = decoder.decode_octet_string(None, None)?;
        result.push(PduSessionResourceSetupItem {
            pdu_session_id,
            nas_pdu,
            s_nssai: SNssai { sst: sst_bytes[0], sd },
            transfer,
        });
    }
    Ok(result)
}

/// Encode PDU Session Resource Setup Response List
pub fn encode_pdu_session_setup_list_su_res(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceSetupResponseItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Failed List
pub fn encode_pdu_session_failed_list(
    container: &mut ProtocolIeContainer,
    ie_id: u16,
    list: &[PduSessionResourceFailedItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false);
        encoder.write_bit(false);
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(ie_id),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource to Release List
pub fn encode_pdu_session_release_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceReleaseItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false);
        encoder.write_bit(false);
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Released List (for response)
pub fn encode_pdu_session_released_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceReleasedItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false);
        encoder.write_bit(false);
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Modify List for Modify Request
pub fn encode_pdu_session_modify_list_req(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceModifyItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false); // extension
        encoder.write_bit(item.nas_pdu.is_some()); // NAS-PDU optional
        encoder.write_bit(false); // no iE-Extensions
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        if let Some(ref nas_pdu) = item.nas_pdu {
            encoder.encode_octet_string(nas_pdu, None, None)?;
        }
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Modify Response List
pub fn encode_pdu_session_modify_list_res(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceModifyResponseItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false);
        encoder.write_bit(false);
        let pdu_constraint = ogs_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

// ============================================================================
// Handover-related IE encoding
// ============================================================================

/// Encode HandoverType IE
pub fn encode_handover_type(
    container: &mut ProtocolIeContainer,
    handover_type: HandoverType,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // HandoverType ::= ENUMERATED { intra5gs, fivegstoeps, epsto5gs, ... }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 2);
    encoder.encode_enumerated(handover_type as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_HANDOVER_TYPE),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

pub const IE_ID_HANDOVER_TYPE: u16 = 28;
pub const IE_ID_TARGET_ID: u16 = 39;
pub const IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY: u16 = 27;
pub const IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: u16 = 104;
pub const IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER: u16 = 105;
pub const IE_ID_SECURITY_CONTEXT: u16 = 99;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK: u16 = 82;
pub const IE_ID_UE_PAGING_IDENTITY: u16 = 112;
pub const IE_ID_PAGING_DRX: u16 = 70;
pub const IE_ID_TAI_LIST_FOR_PAGING: u16 = 106;
pub const IE_ID_PAGING_PRIORITY: u16 = 69;
pub const IE_ID_UE_RADIO_CAPABILITY_FOR_PAGING: u16 = 119;
pub const IE_ID_PAGING_ORIGIN: u16 = 64;
pub const IE_ID_ASSISTANCE_DATA_FOR_PAGING: u16 = 2;

/// Encode TargetID IE
pub fn encode_target_id(
    container: &mut ProtocolIeContainer,
    target_id: &TargetId,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // TargetID ::= CHOICE { targetRANNodeID, targetHomeENB-ID, ... }
    match target_id {
        TargetId::TargetRanNodeId { global_ran_node_id, selected_tai } => {
            encoder.encode_choice_index(0, 2, true)?;
            // TargetRANNodeID SEQUENCE { globalRANNodeID, selectedTAI, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            encode_global_ran_node_id_inline(&mut encoder, global_ran_node_id)?;
            encode_tai_inline(&mut encoder, selected_tai)?;
        }
        TargetId::TargetGlobalNgEnbId { plmn_identity, ng_enb_id, selected_tai } => {
            encoder.encode_choice_index(1, 2, true)?;
            encoder.write_bit(false);
            encoder.write_bit(false);
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // ng-eNB-ID is a BIT STRING (SIZE(20..32))
            encoder.write_bits(*ng_enb_id as u64, 32);
            encode_tai_inline(&mut encoder, selected_tai)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_TARGET_ID),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode GlobalRANNodeID inline
fn encode_global_ran_node_id_inline(
    encoder: &mut AperEncoder,
    ran_id: &GlobalRanNodeId,
) -> NgapResult<()> {
    match ran_id {
        GlobalRanNodeId::GlobalGnbId { plmn_identity, gnb_id, gnb_id_len } => {
            encoder.encode_choice_index(0, 2, true)?;
            encoder.write_bit(false);
            encoder.write_bit(false);
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // gNB-ID is a BIT STRING (SIZE(22..32))
            encoder.write_bits(*gnb_id as u64, *gnb_id_len as usize);
        }
        GlobalRanNodeId::GlobalNgEnbId { plmn_identity, ng_enb_id } => {
            encoder.encode_choice_index(1, 2, true)?;
            encoder.write_bit(false);
            encoder.write_bit(false);
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            encoder.write_bits(*ng_enb_id as u64, 32);
        }
    }
    Ok(())
}

/// Encode TAI inline
fn encode_tai_inline(encoder: &mut AperEncoder, tai: &TaiListItem) -> NgapResult<()> {
    // TAI SEQUENCE { pLMNIdentity, tAC, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
    encoder.encode_octet_string(&tai.tai_plmn, Some(3), Some(3))?;
    encoder.encode_octet_string(&tai.tai_tac, Some(3), Some(3))?;
    Ok(())
}

/// Encode SourceToTarget-TransparentContainer IE
pub fn encode_source_to_target_container(
    container: &mut ProtocolIeContainer,
    data: &[u8],
) -> NgapResult<()> {
    encode_raw_octet_ie(
        container,
        IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
        Criticality::Reject,
        data,
    )
}

/// Encode TargetToSource-TransparentContainer IE
pub fn encode_target_to_source_container(
    container: &mut ProtocolIeContainer,
    data: &[u8],
) -> NgapResult<()> {
    encode_raw_octet_ie(
        container,
        IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
        Criticality::Reject,
        data,
    )
}

/// Encode SecurityContext IE
pub fn encode_security_context(
    container: &mut ProtocolIeContainer,
    ctx: &SecurityContext,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SecurityContext SEQUENCE { nextHopChainingCount, nextHopNH, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
    // nextHopChainingCount INTEGER (0..7)
    let constraint = ogs_asn1c::per::Constraint::new(0, 7);
    encoder.encode_constrained_whole_number(ctx.next_hop_chaining_count as i64, &constraint)?;
    // nextHopNH BIT STRING (SIZE(256))
    for byte in &ctx.next_hop {
        encoder.write_bits(*byte as u64, 8);
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_SECURITY_CONTEXT),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource list for Handover Required
pub fn encode_pdu_session_ho_required_list(
    container: &mut ProtocolIeContainer,
    _list: &[PduSessionResourceSetupItem],
) -> NgapResult<()> {
    // Stub: reuse setup list encoding for now
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(0, 1, 256)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(75), // PDUSessionResourceListHORqd
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource list for Handover Request
pub fn encode_pdu_session_ho_request_list(
    container: &mut ProtocolIeContainer,
    _list: &[PduSessionResourceSetupItemHoReq],
) -> NgapResult<()> {
    // Stub: similar structure
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(0, 1, 256)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(74), // PDUSessionResourceSetupListHOReq
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Admitted List
pub fn encode_pdu_session_admitted_list(
    container: &mut ProtocolIeContainer,
    _list: &[PduSessionResourceAdmittedItemHoAck],
) -> NgapResult<()> {
    // Stub
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(0, 1, 256)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(81), // PDUSessionResourceAdmittedList
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PDU Session Resource Handover List
pub fn encode_pdu_session_handover_list(
    container: &mut ProtocolIeContainer,
    _list: &[PduSessionResourceHandoverItem],
) -> NgapResult<()> {
    // Stub
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(0, 1, 256)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(83), // PDUSessionResourceHandoverList
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode CriticalityDiagnostics IE
pub fn encode_criticality_diagnostics(
    container: &mut ProtocolIeContainer,
    _diag: &CriticalityDiagnostics,
) -> NgapResult<()> {
    // Stub: empty CriticalityDiagnostics
    let mut encoder = AperEncoder::new();
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no optionals
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(7), // CriticalityDiagnostics
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

// ============================================================================
// Paging-related IE encoding
// ============================================================================

/// Encode UEPagingIdentity IE
pub fn encode_ue_paging_identity(
    container: &mut ProtocolIeContainer,
    ue_paging_id: &UePagingIdentity,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UEPagingIdentity ::= CHOICE { fiveG-S-TMSI, ... }
    match ue_paging_id {
        UePagingIdentity::FiveGSTmsi { amf_set_id, amf_pointer, tmsi } => {
            encoder.encode_choice_index(0, 1, true)?;
            // FiveG-S-TMSI SEQUENCE { aMFSetID, aMFPointer, fiveG-TMSI, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            // AMFSetID BIT STRING (SIZE(10))
            encoder.write_bits(*amf_set_id as u64, 10);
            // AMFPointer BIT STRING (SIZE(6))
            encoder.write_bits(*amf_pointer as u64, 6);
            // FiveG-TMSI BIT STRING (SIZE(32))
            encoder.write_bits(*tmsi as u64, 32);
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_PAGING_IDENTITY),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PagingDRX IE (same as default paging DRX)
pub fn encode_paging_drx(
    container: &mut ProtocolIeContainer,
    drx: PagingDrx,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 3);
    encoder.encode_enumerated(drx as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PAGING_DRX),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode TAIListForPaging IE
pub fn encode_tai_list_for_paging(
    container: &mut ProtocolIeContainer,
    list: &[TaiListItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // TAIListForPaging SEQUENCE (SIZE (1..maxnoofTAIforPaging=16)) OF TAI
    encoder.encode_constrained_length(list.len(), 1, 16)?;
    for tai in list {
        encode_tai_inline(&mut encoder, tai)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_TAI_LIST_FOR_PAGING),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode PagingPriority IE
pub fn encode_paging_priority(
    container: &mut ProtocolIeContainer,
    priority: PagingPriority,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // PagingPriority ::= ENUMERATED { priolevel1, ..., priolevel8, ... }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 7);
    encoder.encode_enumerated(priority as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PAGING_PRIORITY),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode UERadioCapabilityForPaging IE
pub fn encode_ue_radio_capability_for_paging(
    container: &mut ProtocolIeContainer,
    radio_cap: &[u8],
) -> NgapResult<()> {
    encode_raw_octet_ie(
        container,
        IE_ID_UE_RADIO_CAPABILITY_FOR_PAGING,
        Criticality::Ignore,
        radio_cap,
    )
}

/// Encode PagingOrigin IE
pub fn encode_paging_origin(
    container: &mut ProtocolIeContainer,
    origin: PagingOrigin,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // PagingOrigin ::= ENUMERATED { non-3gpp, ... }
    let constraint = ogs_asn1c::per::Constraint::extensible(0, 0);
    encoder.encode_enumerated(origin as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PAGING_ORIGIN),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode AssistanceDataForPaging IE
pub fn encode_assistance_data_for_paging(
    container: &mut ProtocolIeContainer,
    assistance: &[u8],
) -> NgapResult<()> {
    encode_raw_octet_ie(
        container,
        IE_ID_ASSISTANCE_DATA_FOR_PAGING,
        Criticality::Ignore,
        assistance,
    )
}
