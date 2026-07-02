//! NGAP IE Encoding/Decoding Helpers
//!
//! Functions for encoding individual Information Elements into raw APER bytes
//! suitable for ProtocolIeField values, and decoding them back.

use nextgcore_asn1c::ngap::cause::Cause;
use nextgcore_asn1c::ngap::ies::{
    AmfUeNgapId, NasPdu, ProtocolIeContainer, ProtocolIeField, RanUeNgapId, RelativeAmfCapacity,
};
use nextgcore_asn1c::ngap::types::{Criticality, ProtocolIeId};
use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};

use crate::error::NgapResult;
use crate::types::*;

// ============================================================================
// IE Encoding Helpers
// ============================================================================
//
// AUTHOR GUIDANCE (NGAP-08): a CHOICE without an ASN.1 `...` marker is
// NON-extensible — encode its alternative with
// `AperEncoder::encode_choice_index(idx, num_alts, /*extensible=*/false)` so the
// index is a bare constrained whole number with NO leading extension bit. A BIT
// STRING whose upper bound exceeds 16 bits must be octet-aligned before its
// content (X.691 §16); prefer `AperEncoder::encode_bit_string(..)`, which aligns
// for you, over hand-rolled `align()` + `write_bits`. The `property_tests` module
// fences both invariants for the encoders below.

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

/// Criticality-driven handling of a not-comprehended IE on receive
/// (TS 38.413 §10.3.4/§10.3.5). This is the conservative NGAP-05 default
/// applied at every `parse_*` / transfer-decode catch-all arm:
///
/// - `reject`  -> surface a typed [`crate::error::NgapError::IeNotComprehended`]
///   carrying [`CriticalityDiagnostics`] with `typeOfError = not-understood`,
///   so the caller can answer with an Error Indication / unsuccessful outcome.
/// - `ignore`  -> drop silently.
/// - `notify`  -> drop (ignore-and-notify is modeled conservatively as a drop;
///   there is no notify side-channel yet).
///
/// Genuinely-handled IEs never reach this helper (their match arm fires first),
/// so it cannot regress decoding of any currently-modeled IE.
pub(crate) fn handle_unknown_ie(field: &ProtocolIeField) -> NgapResult<()> {
    match field.criticality {
        Criticality::Reject => Err(crate::error::NgapError::IeNotComprehended {
            ie_id: field.id.0,
            criticality_diagnostics: CriticalityDiagnostics {
                ies: vec![IeCriticalityDiagnostics {
                    ie_criticality: field.criticality,
                    ie_id: field.id.0,
                    type_of_error: TypeOfError::NotUnderstood,
                }],
                ..Default::default()
            },
        }),
        Criticality::Ignore | Criticality::Notify => Ok(()),
    }
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

pub fn encode_time_to_wait(container: &mut ProtocolIeContainer, ttw: TimeToWait) -> NgapResult<()> {
    let asn_ttw = match ttw {
        TimeToWait::V1s => nextgcore_asn1c::ngap::ies::TimeToWait::V1s,
        TimeToWait::V2s => nextgcore_asn1c::ngap::ies::TimeToWait::V2s,
        TimeToWait::V5s => nextgcore_asn1c::ngap::ies::TimeToWait::V5s,
        TimeToWait::V10s => nextgcore_asn1c::ngap::ies::TimeToWait::V10s,
        TimeToWait::V20s => nextgcore_asn1c::ngap::ies::TimeToWait::V20s,
        TimeToWait::V60s => nextgcore_asn1c::ngap::ies::TimeToWait::V60s,
    };
    container.push(make_ie_field(
        ProtocolIeId::TIME_TO_WAIT,
        Criticality::Ignore,
        &asn_ttw,
    )?);
    Ok(())
}

pub fn decode_time_to_wait(field: &ProtocolIeField) -> NgapResult<TimeToWait> {
    let asn_ttw: nextgcore_asn1c::ngap::ies::TimeToWait = decode_ie_value(&field.value)?;
    Ok(match asn_ttw {
        nextgcore_asn1c::ngap::ies::TimeToWait::V1s => TimeToWait::V1s,
        nextgcore_asn1c::ngap::ies::TimeToWait::V2s => TimeToWait::V2s,
        nextgcore_asn1c::ngap::ies::TimeToWait::V5s => TimeToWait::V5s,
        nextgcore_asn1c::ngap::ies::TimeToWait::V10s => TimeToWait::V10s,
        nextgcore_asn1c::ngap::ies::TimeToWait::V20s => TimeToWait::V20s,
        nextgcore_asn1c::ngap::ies::TimeToWait::V60s => TimeToWait::V60s,
    })
}

// ============================================================================
// AMFName IE (PrintableString SIZE(1..150, ...))
// ============================================================================

/// IE ID for additional IDs not in the base types module
pub const IE_ID_AMF_NAME: u16 = 1;
pub const IE_ID_SERVED_GUAMI_LIST: u16 = 96;
pub const IE_ID_PLMN_SUPPORT_LIST: u16 = 80;
pub const IE_ID_GLOBAL_RAN_NODE_ID: u16 = 27;
pub const IE_ID_RAN_NODE_NAME: u16 = 82;
pub const IE_ID_SUPPORTED_TA_LIST: u16 = 102;
pub const IE_ID_DEFAULT_PAGING_DRX: u16 = 21;
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
pub const IE_ID_CRITICALITY_DIAGNOSTICS: u16 = 19;
pub const IE_ID_RESET_TYPE: u16 = 88;
pub const IE_ID_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST: u16 = 111;
pub const IE_ID_UNAVAILABLE_GUAMI_LIST: u16 = 120;
pub const IE_ID_PDU_SESSION_RESOURCE_NOTIFY_LIST: u16 = 66;
pub const IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_NOT: u16 = 67;
pub const IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_IND: u16 = 63;
pub const IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_CFM: u16 = 62;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_CFM: u16 = 131;
pub const IE_ID_SOURCE_AMF_UE_NGAP_ID: u16 = 100;
pub const IE_ID_PDU_SESSION_RESOURCE_TO_BE_SWITCHED_DL_LIST: u16 = 76;
pub const IE_ID_PDU_SESSION_RESOURCE_SWITCHED_LIST: u16 = 77;
pub const IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_ACK: u16 = 68;
pub const IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_FAIL: u16 = 69;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_PS_REQ: u16 = 57;
pub const IE_ID_PDU_SESSION_RESOURCE_LIST_HO_RQD: u16 = 61;
pub const IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ: u16 = 73;
pub const IE_ID_PDU_SESSION_RESOURCE_ADMITTED_LIST: u16 = 53;
pub const IE_ID_PDU_SESSION_RESOURCE_HANDOVER_LIST: u16 = 59;
/// TrafficLoadReductionIndication (TS 38.413 §9.3.1.99), carried in OverloadStart.
pub const IE_ID_TRAFFIC_LOAD_REDUCTION_INDICATION: u16 = 281;

// AMFName / RANNodeName ::= PrintableString (SIZE(1..150, ...)) — TS 38.413 §9.3.3
const NAME_SIZE_MIN: usize = 1;
const NAME_SIZE_MAX: usize = 150;

/// Encode an extensible constrained-size PrintableString (SIZE(1..150, ...))
/// per X.691: size-extension bit, constrained length determinant over the
/// root size range, octet alignment, then one octet per character.
fn encode_printable_string_1_150(
    encoder: &mut AperEncoder,
    s: &str,
    ie_name: &'static str,
) -> NgapResult<()> {
    let bytes = s.as_bytes();
    if bytes.len() < NAME_SIZE_MIN || bytes.len() > NAME_SIZE_MAX {
        return Err(crate::error::NgapError::InvalidIeValue {
            ie_name,
            reason: format!("length {} outside 1..150", bytes.len()),
        });
    }
    // Size is extensible: write the extension bit (0 = within the root range)
    encoder.write_bit(false);
    // Constrained length determinant over the root size range [1..150]
    encoder.encode_constrained_length(bytes.len(), NAME_SIZE_MIN, NAME_SIZE_MAX)?;
    // Known-multiplier character string with ub > 2 octets: octet-aligned content
    encoder.align();
    encoder.write_bytes(bytes);
    Ok(())
}

/// Decode an extensible constrained-size PrintableString (SIZE(1..150, ...)).
fn decode_printable_string_1_150(
    decoder: &mut AperDecoder,
    ie_name: &'static str,
) -> NgapResult<String> {
    let extended = decoder.read_bit()?;
    if extended {
        return Err(crate::error::NgapError::InvalidIeValue {
            ie_name,
            reason: "size extension beyond 150 not supported".to_string(),
        });
    }
    let len = decoder.decode_constrained_length(NAME_SIZE_MIN, NAME_SIZE_MAX)?;
    decoder.align();
    let bytes = decoder.read_bytes(len)?;
    String::from_utf8(bytes).map_err(|e| crate::error::NgapError::InvalidIeValue {
        ie_name,
        reason: e.to_string(),
    })
}

/// Encode AMF Name as a PrintableString IE
pub fn encode_amf_name(container: &mut ProtocolIeContainer, name: &str) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encode_printable_string_1_150(&mut encoder, name, "AMFName")?;
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
    decode_printable_string_1_150(&mut decoder, "AMFName")
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
            // BackupAMFName ::= AMFName (PrintableString SIZE(1..150, ...))
            encode_printable_string_1_150(&mut encoder, name, "BackupAMFName")?;
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
                                  // The only field is the bare S-NSSAI (no SliceSupportItem wrapper)
        encode_snssai_only(&mut encoder, snssai)?;
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
                              // Each field is BIT STRING (SIZE(16, ...)) — extensible.
                              // X.691 §16: a size-extensible BIT STRING prepends a
                              // 1-bit extension marker (0 = within root size). The
                              // root size range is fixed (16) so no length follows.
    for value in [
        caps.nr_encryption_algorithms,
        caps.nr_integrity_algorithms,
        caps.eutra_encryption_algorithms,
        caps.eutra_integrity_algorithms,
    ] {
        encoder.write_bit(false); // BIT STRING size-extension marker
        encoder.write_bits(value as u64, 16);
    }
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
    // Each field: BIT STRING (SIZE(16, ...)) extension marker, then 16 bits.
    let mut read_algs = || -> NgapResult<u16> {
        let _size_ext = decoder.read_bit()?;
        Ok(decoder.read_bits(16)? as u16)
    };
    let nr_enc = read_algs()?;
    let nr_int = read_algs()?;
    let eutra_enc = read_algs()?;
    let eutra_int = read_algs()?;
    Ok(UeSecurityCapabilities {
        nr_encryption_algorithms: nr_enc,
        nr_integrity_algorithms: nr_int,
        eutra_encryption_algorithms: eutra_enc,
        eutra_integrity_algorithms: eutra_int,
    })
}

/// Encode Security Key IE (BIT STRING SIZE (256))
pub fn encode_security_key(container: &mut ProtocolIeContainer, key: &[u8; 32]) -> NgapResult<()> {
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

// BitRate ::= INTEGER (0..4000000000000, ...) — TS 38.413 §9.3.1.4
const BIT_RATE_MAX: i64 = 4_000_000_000_000;

/// Encode an extensible constrained INTEGER (X.691 §12): the extension marker
/// bit (0 = value within the root range) followed by the constrained encoding.
fn encode_ext_constrained_int(
    encoder: &mut AperEncoder,
    value: i64,
    min: i64,
    max: i64,
) -> NgapResult<()> {
    encoder.write_bit(false);
    let constraint = nextgcore_asn1c::per::Constraint::new(min, max);
    encoder.encode_constrained_whole_number(value, &constraint)?;
    Ok(())
}

/// Decode an extensible constrained INTEGER.
fn decode_ext_constrained_int(decoder: &mut AperDecoder, min: i64, max: i64) -> NgapResult<i64> {
    let extended = decoder.read_bit()?;
    if extended {
        Ok(decoder.decode_unconstrained_whole_number()?)
    } else {
        let constraint = nextgcore_asn1c::per::Constraint::new(min, max);
        Ok(decoder.decode_constrained_whole_number(&constraint)?)
    }
}

/// Encode UE Aggregate Maximum Bit Rate IE
pub fn encode_ue_ambr(container: &mut ProtocolIeContainer, ambr: &UeAmbrInfo) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // UEAggregateMaximumBitRate SEQUENCE { uEAggregateMaximumBitRateDL, uEAggregateMaximumBitRateUL, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension
    encoder.write_bit(false); // no iE-Extensions
                              // BitRate ::= INTEGER (0..4000000000000, ...) — extensible constrained
    encode_ext_constrained_int(&mut encoder, ambr.dl as i64, 0, BIT_RATE_MAX)?;
    encode_ext_constrained_int(&mut encoder, ambr.ul as i64, 0, BIT_RATE_MAX)?;
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
    let dl = decode_ext_constrained_int(&mut decoder, 0, BIT_RATE_MAX)? as u64;
    let ul = decode_ext_constrained_int(&mut decoder, 0, BIT_RATE_MAX)? as u64;
    Ok(UeAmbrInfo { dl, ul })
}

/// Encode TrafficLoadReductionIndication IE (TS 38.413 §9.3.1.99).
/// `TrafficLoadReductionIndication ::= INTEGER (1..99)` (not extensible).
pub fn encode_traffic_load_reduction(
    container: &mut ProtocolIeContainer,
    percent: u8,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    let constraint = nextgcore_asn1c::per::Constraint::new(1, 99);
    encoder.encode_constrained_whole_number(percent.clamp(1, 99) as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_TRAFFIC_LOAD_REDUCTION_INDICATION),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode TrafficLoadReductionIndication IE (TS 38.413 §9.3.1.99).
pub fn decode_traffic_load_reduction(field: &ProtocolIeField) -> NgapResult<u8> {
    let mut decoder = AperDecoder::new(&field.value);
    let constraint = nextgcore_asn1c::per::Constraint::new(1, 99);
    Ok(decoder.decode_constrained_whole_number(&constraint)? as u8)
}

/// Encode Global RAN Node ID IE
pub fn encode_global_ran_node_id(
    container: &mut ProtocolIeContainer,
    id: &GlobalRanNodeId,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encode_global_ran_node_id_into(&mut encoder, id)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_GLOBAL_RAN_NODE_ID),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Encode the GlobalRANNodeID CHOICE directly into an existing encoder.
///
/// Single source of truth for the NGAP-02/03-conformant (non-extensible,
/// octet-aligned) GlobalRANNodeID encoding, shared by the standalone IE
/// (`encode_global_ran_node_id`) and the inline handover TargetID path
/// (`encode_target_id`) so the two can never drift again (NGAP-02b).
fn encode_global_ran_node_id_into(
    encoder: &mut AperEncoder,
    id: &GlobalRanNodeId,
) -> NgapResult<()> {
    match id {
        GlobalRanNodeId::GlobalGnbId {
            plmn_identity,
            gnb_id,
            gnb_id_len,
        } => {
            // GlobalRANNodeID CHOICE: globalGNB-ID = index 0 of 4, NON-extensible
            // (TS 38.413 §9.3.1.5 has no `...`) -> 2-bit index, no extension bit.
            encoder.encode_choice_index(0, 4, false)?;
            // GlobalGNB-ID SEQUENCE { plmnIdentity, gNB-ID, iE-Extensions OPTIONAL, ... }
            encoder.write_bit(false); // extension marker
            encoder.write_bit(false); // no iE-Extensions
                                      // PLMN Identity
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // GNB-ID CHOICE { gNB-ID BIT STRING(22..32), choice-Extensions }:
            // 2 alternatives, NON-extensible -> 1-bit index.
            encoder.encode_choice_index(0, 2, false)?;
            let len = *gnb_id_len as usize;
            // BIT STRING (SIZE (22..32)): constrained length, then octet-align
            // before the content (upper bound 32 > 16, X.691 §16).
            encoder.encode_constrained_length(len, 22, 32)?;
            encoder.align();
            encoder.write_bits(*gnb_id as u64, len);
        }
        GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
        } => {
            // globalNgENB-ID = index 1 of 4, NON-extensible.
            encoder.encode_choice_index(1, 4, false)?;
            encoder.write_bit(false); // extension marker
            encoder.write_bit(false); // no iE-Extensions
            encoder.encode_octet_string(plmn_identity, Some(3), Some(3))?;
            // NgENB-ID CHOICE { macroNgENB-ID(20), shortMacroNgENB-ID(18),
            // longMacroNgENB-ID(21), choice-Extensions }: 4 alts, NON-extensible
            // -> 2-bit index. macroNgENB-ID = index 0.
            encoder.encode_choice_index(0, 4, false)?;
            // macroNgENB-ID BIT STRING(20): octet-align before content (>16).
            encoder.align();
            encoder.write_bits(*ng_enb_id as u64, 20);
        }
    }
    Ok(())
}

/// Decode Global RAN Node ID from IE field
pub fn decode_global_ran_node_id(field: &ProtocolIeField) -> NgapResult<GlobalRanNodeId> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_global_ran_node_id_into(&mut decoder)
}

/// Decode the GlobalRANNodeID CHOICE from an existing decoder (mirror of
/// `encode_global_ran_node_id_into`); shared by the standalone IE and the
/// inline handover TargetID path so decode can never drift either (NGAP-02b).
fn decode_global_ran_node_id_into(decoder: &mut AperDecoder) -> NgapResult<GlobalRanNodeId> {
    let choice = decoder.decode_choice_index(4, false)?;
    match choice {
        0 => {
            // GlobalGNB-ID
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut plmn_identity = [0u8; 3];
            plmn_identity.copy_from_slice(&plmn_bytes);
            // GNB-ID CHOICE: 2 alternatives, non-extensible (1-bit index)
            let _gnb_choice = decoder.decode_choice_index(2, false)?;
            let gnb_id_len = decoder.decode_constrained_length(22, 32)?;
            decoder.align();
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
            // NgENB-ID CHOICE: 4 alternatives, non-extensible (2-bit index)
            let _enb_choice = decoder.decode_choice_index(4, false)?;
            decoder.align();
            let ng_enb_id = decoder.read_bits(20)? as u32;
            Ok(GlobalRanNodeId::GlobalNgEnbId {
                plmn_identity,
                ng_enb_id,
            })
        }
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "GlobalRANNodeID",
            reason: format!("Unknown choice index: {choice}"),
        }),
    }
}

/// Encode RAN Node Name IE
pub fn encode_ran_node_name(container: &mut ProtocolIeContainer, name: &str) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encode_printable_string_1_150(&mut encoder, name, "RANNodeName")?;
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
    decode_printable_string_1_150(&mut decoder, "RANNodeName")
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 3);
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 3);
    let val = decoder.decode_enumerated(&constraint)?;
    match val {
        0 => Ok(PagingDrx::V32),
        1 => Ok(PagingDrx::V64),
        2 => Ok(PagingDrx::V128),
        3 => Ok(PagingDrx::V256),
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "PagingDRX",
            reason: format!("Unknown value: {val}"),
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
            // NRCellIdentity BIT STRING (SIZE (36)): octet-align before content
            // (size 36 > 16, X.691 §16). No-op here as it follows a 3-octet PLMN.
            encoder.align();
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
pub fn decode_user_location_info(field: &ProtocolIeField) -> NgapResult<UserLocationInformation> {
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
            decoder.align();
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
            reason: format!("Unsupported choice index: {choice}"),
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 9);
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
pub fn decode_rrc_establishment_cause(
    field: &ProtocolIeField,
) -> NgapResult<RrcEstablishmentCause> {
    let mut decoder = AperDecoder::new(&field.value);
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 9);
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
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
pub fn encode_ue_ngap_ids(container: &mut ProtocolIeContainer, ids: &UeNgapIds) -> NgapResult<()> {
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
            reason: format!("Unknown choice index: {choice}"),
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

/// Encode a bare S-NSSAI SEQUENCE { sST, sD OPTIONAL, iE-Extensions OPTIONAL }.
///
/// This is the S-NSSAI itself, WITHOUT any enclosing list-item preamble. Used
/// directly by AllowedNSSAI-Item (whose only field is the s-NSSAI) and via
/// `encode_snssai_inline` for SliceSupportItem (which adds its own preamble).
fn encode_snssai_only(encoder: &mut AperEncoder, snssai: &SNssai) -> NgapResult<()> {
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

/// Decode a bare S-NSSAI SEQUENCE (no enclosing list-item preamble).
fn decode_snssai_only(decoder: &mut AperDecoder) -> NgapResult<SNssai> {
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

/// Encode S-NSSAI inside a SliceSupportItem (SEQUENCE { s-NSSAI, iE-Ext OPT }).
fn encode_snssai_inline(encoder: &mut AperEncoder, snssai: &SNssai) -> NgapResult<()> {
    // SliceSupportItem SEQUENCE { s-NSSAI, iE-Extensions OPTIONAL }
    encoder.write_bit(false); // extension for SliceSupportItem
    encoder.write_bit(false); // no iE-Extensions for SliceSupportItem
    encode_snssai_only(encoder, snssai)
}

/// Decode S-NSSAI from within a SliceSupportItem.
fn decode_snssai_inline(decoder: &mut AperDecoder) -> NgapResult<SNssai> {
    // SliceSupportItem
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    decode_snssai_only(decoder)
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
            s_nssai: SNssai {
                sst: sst_bytes[0],
                sd,
            },
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 2);
    encoder.encode_enumerated(handover_type as i64, &constraint)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_HANDOVER_TYPE),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

pub const IE_ID_HANDOVER_TYPE: u16 = 29;
pub const IE_ID_TARGET_ID: u16 = 105;
pub const IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY: u16 = 22;
pub const IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: u16 = 101;
pub const IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER: u16 = 106;
pub const IE_ID_SECURITY_CONTEXT: u16 = 93;
pub const IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK: u16 = 56;
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
        TargetId::TargetRanNodeId {
            global_ran_node_id,
            selected_tai,
        } => {
            encoder.encode_choice_index(0, 2, true)?;
            // TargetRANNodeID SEQUENCE { globalRANNodeID, selectedTAI, iE-Extensions OPTIONAL }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
                                      // NGAP-02b: reuse the single shared (conformant) GlobalRANNodeID
                                      // encoder instead of a now-deleted misaligned/extensible inline copy.
            encode_global_ran_node_id_into(&mut encoder, global_ran_node_id)?;
            encode_tai_inline(&mut encoder, selected_tai)?;
        }
        TargetId::TargetGlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
            selected_tai,
        } => {
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
    let constraint = nextgcore_asn1c::per::Constraint::new(0, 7);
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

// ============================================================================
// Generic { pDUSessionID, <transfer> OCTET STRING } list helpers
//
// Many TS 38.413 list IEs share the item shape
//   SEQUENCE { pDUSessionID, <something>Transfer OCTET STRING, iE-Extensions OPTIONAL }
// inside SEQUENCE (SIZE (1..maxnoofPDUSessions=256)) OF <item>.
// ============================================================================

/// Encode a list of (pdu_session_id, transfer) pairs as a single IE
pub fn encode_id_transfer_list_ie<'a>(
    container: &mut ProtocolIeContainer,
    ie_id: u16,
    criticality: Criticality,
    items: impl ExactSizeIterator<Item = (u8, &'a [u8])>,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(items.len(), 1, 256)?;
    for (pdu_session_id, transfer) in items {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(pdu_session_id as i64, &pdu_constraint)?;
        encoder.encode_octet_string(transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(ie_id),
        criticality,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode a list of (pdu_session_id, transfer) pairs from an IE field
pub fn decode_id_transfer_list(field: &ProtocolIeField) -> NgapResult<Vec<(u8, Vec<u8>)>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        let pdu_session_id = decoder.decode_constrained_whole_number(&pdu_constraint)? as u8;
        let transfer = decoder.decode_octet_string(None, None)?;
        result.push((pdu_session_id, transfer));
    }
    Ok(result)
}

/// Encode PDU Session Resource List HO Rqd (TS 38.413 Section 9.2.3.1)
pub fn encode_pdu_session_ho_required_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceItemHoRqd],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_LIST_HO_RQD,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource List HO Rqd
pub fn decode_pdu_session_ho_required_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceItemHoRqd>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(|(pdu_session_id, transfer)| PduSessionResourceItemHoRqd {
            pdu_session_id,
            transfer,
        })
        .collect())
}

/// Encode PDU Session Resource Setup List HO Req (TS 38.413 Section 9.2.3.4)
///
/// Items carry an S-NSSAI in addition to the transfer:
/// SEQUENCE { pDUSessionID, s-NSSAI, handoverRequestTransfer, iE-Extensions OPTIONAL }
pub fn encode_pdu_session_ho_request_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceSetupItemHoReq],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(item.pdu_session_id as i64, &pdu_constraint)?;
        // S-NSSAI SEQUENCE { sST, sD OPTIONAL, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(item.s_nssai.sd.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encoder.encode_octet_string(&[item.s_nssai.sst], Some(1), Some(1))?;
        if let Some(ref sd) = item.s_nssai.sd {
            encoder.encode_octet_string(sd, Some(3), Some(3))?;
        }
        encoder.encode_octet_string(&item.transfer, None, None)?;
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode PDU Session Resource Setup List HO Req
pub fn decode_pdu_session_ho_request_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceSetupItemHoReq>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        let pdu_session_id = decoder.decode_constrained_whole_number(&pdu_constraint)? as u8;
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
        result.push(PduSessionResourceSetupItemHoReq {
            pdu_session_id,
            s_nssai: SNssai {
                sst: sst_bytes[0],
                sd,
            },
            transfer,
        });
    }
    Ok(result)
}

/// Encode PDU Session Resource Admitted List (TS 38.413 Section 9.2.3.5)
pub fn encode_pdu_session_admitted_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceAdmittedItemHoAck],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_ADMITTED_LIST,
        Criticality::Ignore,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource Admitted List
pub fn decode_pdu_session_admitted_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceAdmittedItemHoAck>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceAdmittedItemHoAck {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Encode PDU Session Resource Handover List (TS 38.413 Section 9.2.3.10)
pub fn encode_pdu_session_handover_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceHandoverItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_HANDOVER_LIST,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Map TypeOfError to its ASN.1 enumeration index (TS 38.413 §9.3.1.3:
/// `not-understood(0)`, `missing(1)`).
fn type_of_error_to_index(t: TypeOfError) -> i64 {
    match t {
        TypeOfError::NotUnderstood => 0,
        TypeOfError::Missing => 1,
    }
}

/// Encode CriticalityDiagnostics IE (TS 38.413 Section 9.3.1.3)
pub fn encode_criticality_diagnostics(
    container: &mut ProtocolIeContainer,
    diag: &CriticalityDiagnostics,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // CriticalityDiagnostics ::= SEQUENCE { procedureCode OPTIONAL,
    //   triggeringMessage OPTIONAL, procedureCriticality OPTIONAL,
    //   iEsCriticalityDiagnostics OPTIONAL, iE-Extensions OPTIONAL, ... }
    let ies_present = !diag.ies.is_empty();
    encoder.write_bit(false); // extension
    encoder.write_bit(diag.procedure_code.is_some());
    encoder.write_bit(diag.triggering_message.is_some());
    encoder.write_bit(diag.procedure_criticality.is_some());
    encoder.write_bit(ies_present); // iEsCriticalityDiagnostics present
    encoder.write_bit(false); // no iE-Extensions
    if let Some(code) = diag.procedure_code {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(code as i64, &constraint)?;
    }
    if let Some(tm) = diag.triggering_message {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 2);
        encoder.encode_enumerated(tm as i64, &constraint)?;
    }
    if let Some(crit) = diag.procedure_criticality {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 2);
        encoder.encode_enumerated(crit as i64, &constraint)?;
    }
    if ies_present {
        // CriticalityDiagnostics-IE-List ::= SEQUENCE (SIZE(1..maxnoofErrors))
        //   OF CriticalityDiagnostics-IE-Item, where maxnoofErrors = 256.
        encoder.encode_constrained_length(diag.ies.len(), 1, 256)?;
        for item in &diag.ies {
            // CriticalityDiagnostics-IE-Item ::= SEQUENCE { iECriticality,
            //   iE-ID, typeOfError, iE-Extensions OPTIONAL, ... }
            encoder.write_bit(false); // extension marker
            encoder.write_bit(false); // no iE-Extensions
            item.ie_criticality.encode_aper(&mut encoder)?;
            let id_constraint = nextgcore_asn1c::per::Constraint::new(0, 65535);
            encoder.encode_constrained_whole_number(item.ie_id as i64, &id_constraint)?;
            let err_constraint = nextgcore_asn1c::per::Constraint::extensible(0, 1);
            encoder
                .encode_enumerated(type_of_error_to_index(item.type_of_error), &err_constraint)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_CRITICALITY_DIAGNOSTICS),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode CriticalityDiagnostics from IE field
pub fn decode_criticality_diagnostics(
    field: &ProtocolIeField,
) -> NgapResult<CriticalityDiagnostics> {
    let mut decoder = AperDecoder::new(&field.value);
    let _ext = decoder.read_bit()?;
    let pc_present = decoder.read_bit()?;
    let tm_present = decoder.read_bit()?;
    let crit_present = decoder.read_bit()?;
    let ies_present = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    let procedure_code = if pc_present {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        Some(decoder.decode_constrained_whole_number(&constraint)? as u8)
    } else {
        None
    };
    let triggering_message = if tm_present {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 2);
        Some(decoder.decode_enumerated(&constraint)? as u8)
    } else {
        None
    };
    let procedure_criticality = if crit_present {
        let constraint = nextgcore_asn1c::per::Constraint::new(0, 2);
        Some(decoder.decode_enumerated(&constraint)? as u8)
    } else {
        None
    };
    let mut ies = Vec::new();
    if ies_present {
        // CriticalityDiagnostics-IE-List ::= SEQUENCE (SIZE (1..maxnoofErrors))
        //   OF CriticalityDiagnostics-IE-Item, where maxnoofErrors = 256.
        let count = decoder.decode_constrained_length(1, 256)?;
        for _ in 0..count {
            let _item_ext = decoder.read_bit()?;
            let _item_ie_ext = decoder.read_bit()?;
            let ie_criticality = Criticality::decode_aper(&mut decoder)?;
            let id_constraint = nextgcore_asn1c::per::Constraint::new(0, 65535);
            let ie_id = decoder.decode_constrained_whole_number(&id_constraint)? as u16;
            let err_constraint = nextgcore_asn1c::per::Constraint::extensible(0, 1);
            // not-understood(0), missing(1); future extension values map to
            // not-understood so an extended peer does not fail the decode.
            let type_of_error = match decoder.decode_enumerated(&err_constraint)? {
                1 => TypeOfError::Missing,
                _ => TypeOfError::NotUnderstood,
            };
            ies.push(IeCriticalityDiagnostics {
                ie_criticality,
                ie_id,
                type_of_error,
            });
        }
    }
    Ok(CriticalityDiagnostics {
        procedure_code,
        triggering_message,
        procedure_criticality,
        ies,
    })
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
        UePagingIdentity::FiveGSTmsi {
            amf_set_id,
            amf_pointer,
            tmsi,
        } => {
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
pub fn encode_paging_drx(container: &mut ProtocolIeContainer, drx: PagingDrx) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 3);
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 7);
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
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
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

// ============================================================================
// Handover / Path Switch decode helpers
// ============================================================================

/// Decode HandoverType from IE field
pub fn decode_handover_type(field: &ProtocolIeField) -> NgapResult<HandoverType> {
    let mut decoder = AperDecoder::new(&field.value);
    let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 2);
    let val = decoder.decode_enumerated(&constraint)?;
    match val {
        0 => Ok(HandoverType::Intra5gs),
        1 => Ok(HandoverType::FivegsToEps),
        2 => Ok(HandoverType::EpsTo5gs),
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "HandoverType",
            reason: format!("Unknown value: {val}"),
        }),
    }
}

/// Decode TAI inline (mirrors `encode_tai_inline`)
fn decode_tai_inline(decoder: &mut AperDecoder) -> NgapResult<TaiListItem> {
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
    let mut tai_plmn = [0u8; 3];
    tai_plmn.copy_from_slice(&plmn_bytes);
    let tac_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
    let mut tai_tac = [0u8; 3];
    tai_tac.copy_from_slice(&tac_bytes);
    Ok(TaiListItem { tai_plmn, tai_tac })
}

/// Decode TargetID from IE field
pub fn decode_target_id(field: &ProtocolIeField) -> NgapResult<TargetId> {
    let mut decoder = AperDecoder::new(&field.value);
    let choice = decoder.decode_choice_index(2, true)?;
    match choice {
        0 => {
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            // NGAP-02b: shared decoder (mirror of the shared encoder).
            let global_ran_node_id = decode_global_ran_node_id_into(&mut decoder)?;
            let selected_tai = decode_tai_inline(&mut decoder)?;
            Ok(TargetId::TargetRanNodeId {
                global_ran_node_id,
                selected_tai,
            })
        }
        1 => {
            let _ext = decoder.read_bit()?;
            let _ie_ext = decoder.read_bit()?;
            let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
            let mut plmn_identity = [0u8; 3];
            plmn_identity.copy_from_slice(&plmn_bytes);
            let ng_enb_id = decoder.read_bits(32)? as u32;
            let selected_tai = decode_tai_inline(&mut decoder)?;
            Ok(TargetId::TargetGlobalNgEnbId {
                plmn_identity,
                ng_enb_id,
                selected_tai,
            })
        }
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "TargetID",
            reason: format!("Unknown choice index: {choice}"),
        }),
    }
}

/// Decode SecurityContext from IE field
pub fn decode_security_context(field: &ProtocolIeField) -> NgapResult<SecurityContext> {
    let mut decoder = AperDecoder::new(&field.value);
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    let constraint = nextgcore_asn1c::per::Constraint::new(0, 7);
    let next_hop_chaining_count = decoder.decode_constrained_whole_number(&constraint)? as u8;
    let mut next_hop = [0u8; 32];
    for byte in next_hop.iter_mut() {
        *byte = decoder.read_bits(8)? as u8;
    }
    Ok(SecurityContext {
        next_hop_chaining_count,
        next_hop,
    })
}

/// Encode SourceAMF-UE-NGAP-ID IE (used in Path Switch Request)
pub fn encode_source_amf_ue_ngap_id(
    container: &mut ProtocolIeContainer,
    id: u64,
) -> NgapResult<()> {
    container.push(make_ie_field(
        ProtocolIeId(IE_ID_SOURCE_AMF_UE_NGAP_ID),
        Criticality::Reject,
        &AmfUeNgapId(id),
    )?);
    Ok(())
}

// ============================================================================
// NG Reset IEs
// ============================================================================

/// Encode ResetType IE (TS 38.413 Section 9.3.1.95)
pub fn encode_reset_type(
    container: &mut ProtocolIeContainer,
    reset_type: &ResetType,
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // ResetType ::= CHOICE { nG-Interface ResetAll,
    //   partOfNG-Interface UE-associatedLogicalNG-connectionList, choice-Extensions }
    match reset_type {
        ResetType::NgInterface => {
            encoder.encode_choice_index(0, 3, false)?;
            // ResetAll ::= ENUMERATED { reset-all, ... }
            let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
            encoder.encode_enumerated(0, &constraint)?;
        }
        ResetType::PartOfNgInterface(connections) => {
            encoder.encode_choice_index(1, 3, false)?;
            encode_ng_connection_list_inline(&mut encoder, connections)?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_RESET_TYPE),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode ResetType from IE field
pub fn decode_reset_type(field: &ProtocolIeField) -> NgapResult<ResetType> {
    let mut decoder = AperDecoder::new(&field.value);
    let choice = decoder.decode_choice_index(3, false)?;
    match choice {
        0 => {
            let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
            let _reset_all = decoder.decode_enumerated(&constraint)?;
            Ok(ResetType::NgInterface)
        }
        1 => Ok(ResetType::PartOfNgInterface(
            decode_ng_connection_list_inline(&mut decoder)?,
        )),
        _ => Err(crate::error::NgapError::InvalidIeValue {
            ie_name: "ResetType",
            reason: format!("Unsupported choice index: {choice}"),
        }),
    }
}

/// Encode UE-associatedLogicalNG-connectionList inline
fn encode_ng_connection_list_inline(
    encoder: &mut AperEncoder,
    connections: &[UeAssociatedLogicalNgConnectionItem],
) -> NgapResult<()> {
    // SEQUENCE (SIZE (1..maxnoofNGConnectionsToReset=65536)) OF item
    encoder.encode_constrained_length(connections.len(), 1, 65536)?;
    for item in connections {
        // SEQUENCE { aMF-UE-NGAP-ID OPTIONAL, rAN-UE-NGAP-ID OPTIONAL, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(item.amf_ue_ngap_id.is_some());
        encoder.write_bit(item.ran_ue_ngap_id.is_some());
        encoder.write_bit(false); // no iE-Extensions
        if let Some(amf_id) = item.amf_ue_ngap_id {
            AmfUeNgapId(amf_id).encode_aper(encoder)?;
        }
        if let Some(ran_id) = item.ran_ue_ngap_id {
            RanUeNgapId(ran_id).encode_aper(encoder)?;
        }
    }
    Ok(())
}

/// Decode UE-associatedLogicalNG-connectionList inline
fn decode_ng_connection_list_inline(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<UeAssociatedLogicalNgConnectionItem>> {
    let count = decoder.decode_constrained_length(1, 65536)?;
    let mut result = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let amf_present = decoder.read_bit()?;
        let ran_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let amf_ue_ngap_id = if amf_present {
            Some(AmfUeNgapId::decode_aper(decoder)?.0)
        } else {
            None
        };
        let ran_ue_ngap_id = if ran_present {
            Some(RanUeNgapId::decode_aper(decoder)?.0)
        } else {
            None
        };
        result.push(UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
        });
    }
    Ok(result)
}

/// Encode UE-associatedLogicalNG-connectionList IE (NG Reset Acknowledge)
pub fn encode_ng_connection_list(
    container: &mut ProtocolIeContainer,
    connections: &[UeAssociatedLogicalNgConnectionItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    encode_ng_connection_list_inline(&mut encoder, connections)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST),
        criticality: Criticality::Ignore,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode UE-associatedLogicalNG-connectionList from IE field
pub fn decode_ng_connection_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<UeAssociatedLogicalNgConnectionItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_ng_connection_list_inline(&mut decoder)
}

// ============================================================================
// AMF Status Indication IEs
// ============================================================================

/// Encode UnavailableGUAMIList IE (TS 38.413 Section 9.3.3.18)
pub fn encode_unavailable_guami_list(
    container: &mut ProtocolIeContainer,
    list: &[UnavailableGuamiItem],
) -> NgapResult<()> {
    let mut encoder = AperEncoder::new();
    // SEQUENCE (SIZE (1..maxnoofServedGUAMIs=256)) OF UnavailableGUAMIItem
    encoder.encode_constrained_length(list.len(), 1, 256)?;
    for item in list {
        // SEQUENCE { gUAMI, timerApproachForGUAMIRemoval OPTIONAL,
        //   backupAMFName OPTIONAL, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(item.timer_approach_for_guami_removal);
        encoder.write_bit(item.backup_amf_name.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_guami_inline(&mut encoder, &item.guami)?;
        if item.timer_approach_for_guami_removal {
            // TimerApproachForGuamiRemoval ::= ENUMERATED { apply-timer, ... }
            let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
            encoder.encode_enumerated(0, &constraint)?;
        }
        if let Some(ref name) = item.backup_amf_name {
            // BackupAMFName ::= AMFName (PrintableString SIZE(1..150, ...))
            encode_printable_string_1_150(&mut encoder, name, "BackupAMFName")?;
        }
    }
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(IE_ID_UNAVAILABLE_GUAMI_LIST),
        criticality: Criticality::Reject,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

/// Decode UnavailableGUAMIList from IE field
pub fn decode_unavailable_guami_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<UnavailableGuamiItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let timer_present = decoder.read_bit()?;
        let backup_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let guami = decode_guami_inline(&mut decoder)?;
        if timer_present {
            let constraint = nextgcore_asn1c::per::Constraint::extensible(0, 0);
            let _timer = decoder.decode_enumerated(&constraint)?;
        }
        let backup_amf_name = if backup_present {
            Some(decode_printable_string_1_150(
                &mut decoder,
                "BackupAMFName",
            )?)
        } else {
            None
        };
        result.push(UnavailableGuamiItem {
            guami,
            timer_approach_for_guami_removal: timer_present,
            backup_amf_name,
        });
    }
    Ok(result)
}

// ============================================================================
// List decode helpers for setup/configuration responses
// ============================================================================

/// Decode GUAMI inline (mirrors `encode_guami_inline`)
fn decode_guami_inline(decoder: &mut AperDecoder) -> NgapResult<Guami> {
    let _ext = decoder.read_bit()?;
    let _ie_ext = decoder.read_bit()?;
    let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
    let mut plmn_identity = [0u8; 3];
    plmn_identity.copy_from_slice(&plmn_bytes);
    let amf_region_id = decoder.read_bits(8)? as u8;
    let amf_set_id = decoder.read_bits(10)? as u16;
    let amf_pointer = decoder.read_bits(6)? as u8;
    Ok(Guami {
        plmn_identity,
        amf_region_id,
        amf_set_id,
        amf_pointer,
    })
}

/// Decode Served GUAMI List from IE field
pub fn decode_served_guami_list(field: &ProtocolIeField) -> NgapResult<Vec<ServedGuamiItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let backup_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let guami = decode_guami_inline(&mut decoder)?;
        let backup_amf_name = if backup_present {
            Some(decode_printable_string_1_150(
                &mut decoder,
                "BackupAMFName",
            )?)
        } else {
            None
        };
        result.push(ServedGuamiItem {
            guami,
            backup_amf_name,
        });
    }
    Ok(result)
}

/// Decode PLMN Support List from IE field
pub fn decode_plmn_support_list(field: &ProtocolIeField) -> NgapResult<Vec<PlmnSupportItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 12)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut plmn_identity = [0u8; 3];
        plmn_identity.copy_from_slice(&plmn_bytes);
        let slice_count = decoder.decode_constrained_length(1, 1024)?;
        let mut slice_support_list = Vec::with_capacity(slice_count);
        for _ in 0..slice_count {
            slice_support_list.push(decode_snssai_inline(&mut decoder)?);
        }
        result.push(PlmnSupportItem {
            plmn_identity,
            slice_support_list,
        });
    }
    Ok(result)
}

/// Decode Allowed NSSAI from IE field (mirrors `encode_allowed_nssai`)
pub fn decode_allowed_nssai(field: &ProtocolIeField) -> NgapResult<Vec<SNssai>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 8)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        // AllowedNSSAI-Item SEQUENCE { s-NSSAI, iE-Extensions OPTIONAL }
        let _item_ext = decoder.read_bit()?;
        let _item_ie_ext = decoder.read_bit()?;
        // The only field is the bare S-NSSAI (no SliceSupportItem wrapper)
        result.push(decode_snssai_only(&mut decoder)?);
    }
    Ok(result)
}

/// Decode PDU Session Resource Setup Response List from IE field
pub fn decode_pdu_session_setup_list_su_res(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceSetupResponseItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceSetupResponseItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Decode a PDU Session Resource Failed List from IE field
pub fn decode_pdu_session_failed_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceFailedItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(|(pdu_session_id, transfer)| PduSessionResourceFailedItem {
            pdu_session_id,
            transfer,
        })
        .collect())
}

/// Decode PDU Session Resource to Release List from IE field
pub fn decode_pdu_session_release_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceReleaseItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(|(pdu_session_id, transfer)| PduSessionResourceReleaseItem {
            pdu_session_id,
            transfer,
        })
        .collect())
}

/// Decode PDU Session Resource Released List from IE field
pub fn decode_pdu_session_released_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceReleasedItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceReleasedItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Decode PDU Session Resource Modify Response List from IE field
pub fn decode_pdu_session_modify_list_res(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceModifyResponseItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceModifyResponseItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Decode PDU Session Resource Modify List from Modify Request IE field
pub fn decode_pdu_session_modify_list_req(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceModifyItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, 256)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let _ext = decoder.read_bit()?;
        let nas_pdu_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let pdu_constraint = nextgcore_asn1c::per::Constraint::new(0, 255);
        let pdu_session_id = decoder.decode_constrained_whole_number(&pdu_constraint)? as u8;
        let nas_pdu = if nas_pdu_present {
            Some(decoder.decode_octet_string(None, None)?)
        } else {
            None
        };
        let transfer = decoder.decode_octet_string(None, None)?;
        result.push(PduSessionResourceModifyItem {
            pdu_session_id,
            nas_pdu,
            transfer,
        });
    }
    Ok(result)
}

// ============================================================================
// PDU Session Resource Notify / Modify Indication / Path Switch list IEs
// ============================================================================

/// Encode PDU Session Resource Notify List IE
pub fn encode_pdu_session_notify_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceNotifyItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_NOTIFY_LIST,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource Notify List from IE field
pub fn decode_pdu_session_notify_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceNotifyItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(|(pdu_session_id, transfer)| PduSessionResourceNotifyItem {
            pdu_session_id,
            transfer,
        })
        .collect())
}

/// Encode a PDU Session Resource Released List under the given IE ID
pub fn encode_pdu_session_released_list_with_id(
    container: &mut ProtocolIeContainer,
    ie_id: u16,
    list: &[PduSessionResourceReleasedItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        ie_id,
        Criticality::Ignore,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Encode PDU Session Resource Modify List Mod Ind IE
pub fn encode_pdu_session_modify_list_mod_ind(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceModifyIndicationItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_IND,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource Modify List Mod Ind from IE field
pub fn decode_pdu_session_modify_list_mod_ind(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceModifyIndicationItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceModifyIndicationItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Encode PDU Session Resource Modify List Mod Cfm IE
pub fn encode_pdu_session_modify_list_mod_cfm(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceModifyConfirmItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_CFM,
        Criticality::Ignore,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource Modify List Mod Cfm from IE field
pub fn decode_pdu_session_modify_list_mod_cfm(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceModifyConfirmItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceModifyConfirmItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

/// Encode PDU Session Resource To Be Switched DL List IE
pub fn encode_pdu_session_to_be_switched_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceSwitchItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_TO_BE_SWITCHED_DL_LIST,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource To Be Switched DL List from IE field
pub fn decode_pdu_session_to_be_switched_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceSwitchItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(|(pdu_session_id, transfer)| PduSessionResourceSwitchItem {
            pdu_session_id,
            transfer,
        })
        .collect())
}

/// Encode PDU Session Resource Switched List IE
pub fn encode_pdu_session_switched_list(
    container: &mut ProtocolIeContainer,
    list: &[PduSessionResourceSwitchedItem],
) -> NgapResult<()> {
    encode_id_transfer_list_ie(
        container,
        IE_ID_PDU_SESSION_RESOURCE_SWITCHED_LIST,
        Criticality::Reject,
        list.iter()
            .map(|item| (item.pdu_session_id, item.transfer.as_slice())),
    )
}

/// Decode PDU Session Resource Switched List from IE field
pub fn decode_pdu_session_switched_list(
    field: &ProtocolIeField,
) -> NgapResult<Vec<PduSessionResourceSwitchedItem>> {
    Ok(decode_id_transfer_list(field)?
        .into_iter()
        .map(
            |(pdu_session_id, transfer)| PduSessionResourceSwitchedItem {
                pdu_session_id,
                transfer,
            },
        )
        .collect())
}

#[cfg(test)]
mod global_ran_node_id_tests {
    use super::*;

    #[test]
    fn test_global_gnb_id_non_extensible_and_octet_aligned() {
        // gNB-ID 0x000ABC over 24 bits -> octet-aligned content [0x00,0x0A,0xBC].
        let id = GlobalRanNodeId::GlobalGnbId {
            plmn_identity: [0x00, 0xf1, 0x10],
            gnb_id: 0x000ABC,
            gnb_id_len: 24,
        };
        let mut container = ProtocolIeContainer::new();
        encode_global_ran_node_id(&mut container, &id).unwrap();
        let bytes = &container.ies[0].value;

        // GlobalRANNodeID CHOICE: globalGNB-ID = index 0 over 4 non-extensible
        // alternatives -> 2-bit "00" at the top of octet 0, no leading ext bit.
        assert_eq!(bytes[0] >> 6, 0, "globalGNB-ID index must be 2-bit 00");
        // BIT STRING content is octet-aligned (X.691 §16): the 24-bit gNB-ID
        // occupies the final three octets verbatim.
        assert_eq!(
            &bytes[bytes.len() - 3..],
            &[0x00, 0x0A, 0xBC],
            "gNB-ID content must be octet-aligned"
        );
        match decode_global_ran_node_id(&container.ies[0]).unwrap() {
            GlobalRanNodeId::GlobalGnbId {
                plmn_identity,
                gnb_id,
                gnb_id_len,
            } => {
                assert_eq!(plmn_identity, [0x00, 0xf1, 0x10]);
                assert_eq!(gnb_id, 0x000ABC);
                assert_eq!(gnb_id_len, 24);
            }
            other => panic!("expected GlobalGnbId, got {other:?}"),
        }
    }

    #[test]
    fn test_global_ng_enb_id_choice_index_no_extension_bit() {
        let id = GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity: [0x00, 0xf1, 0x10],
            ng_enb_id: 0x0ABCD, // 20-bit macroNgENB-ID
        };
        let mut container = ProtocolIeContainer::new();
        encode_global_ran_node_id(&mut container, &id).unwrap();
        let bytes = &container.ies[0].value;
        // globalNgENB-ID = index 1: top 2 bits "01" (== 1). With a spurious
        // leading extension bit this would read 0, so this proves it is gone.
        assert_eq!(bytes[0] >> 6, 1, "globalNgENB-ID index must be 2-bit 01");
        match decode_global_ran_node_id(&container.ies[0]).unwrap() {
            GlobalRanNodeId::GlobalNgEnbId {
                plmn_identity,
                ng_enb_id,
            } => {
                assert_eq!(plmn_identity, [0x00, 0xf1, 0x10]);
                assert_eq!(ng_enb_id, 0x0ABCD);
            }
            other => panic!("expected GlobalNgEnbId, got {other:?}"),
        }
    }

    /// NGAP-02b: the handover TargetID path must encode its inner
    /// GlobalRANNodeID with the SAME conformant (non-extensible, octet-aligned)
    /// form as the NG-Setup path — it previously used a duplicate, broken
    /// (extensible + misaligned) inline encoder. Byte-vector pins the new bytes.
    #[test]
    fn test_handover_target_id_global_ran_node_id_byte_vector() {
        let target = TargetId::TargetRanNodeId {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x00, 0xf1, 0x10],
                gnb_id: 0x000ABC,
                gnb_id_len: 24,
            },
            selected_tai: TaiListItem {
                tai_plmn: [0x00, 0xf1, 0x10],
                tai_tac: [0x00, 0x00, 0x01],
            },
        };
        let mut container = ProtocolIeContainer::new();
        encode_target_id(&mut container, &target).unwrap();
        let value = &container.ies[0].value;

        // Reference vector (hand-derived from X.691 Aligned PER):
        //   octet0 = 0x00: TargetID choice "00" + SEQ ext 0 + ie-ext 0 +
        //                  GlobalRANNodeID choice "00" (no ext bit) + SEQ ext 0 + ie-ext 0
        //   octet1..3      = PLMN 00 f1 10
        //   octet4 = 0x10: GNB-ID choice bit 0 + len-determinant (24-22=2 over 4 bits) + pad
        //   octet5..7      = gNB-ID 00 0A BC  (octet-aligned, X.691 §16)
        //   octet8 = 0x00: TAI ext 0 + ie-ext 0 + pad
        //   octet9..11     = selected-TAI PLMN 00 f1 10
        //   octet12..14    = selected-TAI TAC 00 00 01
        assert_eq!(
            value,
            &vec![
                0x00, 0x00, 0xf1, 0x10, 0x10, 0x00, 0x0A, 0xBC, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00,
                0x01
            ]
        );
        // No spurious leading extension bit on the GlobalRANNodeID choice and the
        // gNB-ID content sits octet-aligned in octets 5..8.
        assert_eq!(value[0], 0x00);
        assert_eq!(&value[5..8], &[0x00, 0x0A, 0xBC]);

        // Roundtrips through the shared decoder.
        match decode_target_id(&container.ies[0]).unwrap() {
            TargetId::TargetRanNodeId {
                global_ran_node_id:
                    GlobalRanNodeId::GlobalGnbId {
                        plmn_identity,
                        gnb_id,
                        gnb_id_len,
                    },
                selected_tai,
            } => {
                assert_eq!(plmn_identity, [0x00, 0xf1, 0x10]);
                assert_eq!(gnb_id, 0x000ABC);
                assert_eq!(gnb_id_len, 24);
                assert_eq!(selected_tai.tai_tac, [0x00, 0x00, 0x01]);
            }
            other => panic!("expected TargetRanNodeId/GlobalGnbId, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod unknown_ie_tests {
    use super::*;

    /// NGAP-05: a not-comprehended IE with reject criticality is surfaced as a
    /// typed error carrying CriticalityDiagnostics (typeOfError=not-understood);
    /// ignore/notify criticality drop silently.
    #[test]
    fn test_handle_unknown_ie_criticality_behavior() {
        let reject = ProtocolIeField {
            id: ProtocolIeId(9999),
            criticality: Criticality::Reject,
            value: vec![],
        };
        match handle_unknown_ie(&reject).unwrap_err() {
            crate::error::NgapError::IeNotComprehended {
                ie_id,
                criticality_diagnostics,
            } => {
                assert_eq!(ie_id, 9999);
                assert_eq!(criticality_diagnostics.ies.len(), 1);
                assert_eq!(criticality_diagnostics.ies[0].ie_id, 9999);
                assert_eq!(
                    criticality_diagnostics.ies[0].type_of_error,
                    TypeOfError::NotUnderstood
                );
                assert_eq!(
                    criticality_diagnostics.ies[0].ie_criticality,
                    Criticality::Reject
                );
            }
            other => panic!("expected IeNotComprehended, got {other:?}"),
        }

        for crit in [Criticality::Ignore, Criticality::Notify] {
            let field = ProtocolIeField {
                id: ProtocolIeId(9999),
                criticality: crit,
                value: vec![],
            };
            assert!(handle_unknown_ie(&field).is_ok());
        }
    }
}

#[cfg(test)]
mod criticality_diagnostics_tests {
    use super::*;

    // NGAP-06: CriticalityDiagnostics (TS 38.413 §9.3.1.3) is fully retained,
    // including the IEsCriticalityDiagnostics list. These are byte-vector tests:
    // the expected APER octets are derived by hand from X.691 (Aligned PER) and
    // pin the encoder against regressions.

    #[test]
    fn test_criticality_diagnostics_procedure_code_byte_vector() {
        // Only procedureCode = 21 (NG-SETUP) present, no list.
        //   preamble: ext=0, pc=1, tm=0, crit=0, ies=0, ext2=0  -> 0b010000xx
        //   align before the 0..255 octet -> octet0 = 0x40
        //   procedureCode 21 -> octet1 = 0x15
        let diag = CriticalityDiagnostics {
            procedure_code: Some(21),
            triggering_message: None,
            procedure_criticality: None,
            ies: vec![],
        };
        let mut container = ProtocolIeContainer::new();
        encode_criticality_diagnostics(&mut container, &diag).unwrap();
        let field = &container.ies[0];
        assert_eq!(field.id.0, IE_ID_CRITICALITY_DIAGNOSTICS);
        assert_eq!(field.criticality, Criticality::Ignore);
        assert_eq!(field.value, vec![0x40, 0x15]);
        assert_eq!(decode_criticality_diagnostics(field).unwrap(), diag);
    }

    #[test]
    fn test_criticality_diagnostics_ie_list_byte_vector() {
        // No scalar optionals, one IE item: { Reject(0), iE-ID=27, NotUnderstood(0) }.
        //   preamble: ext=0,pc=0,tm=0,crit=0,ies=1,ext2=0          octet0 hi = 000010
        //   list length SIZE(1..256): align + (1-1) over 8 bits -> octet0=0x08, octet1=0x00
        //   item: ext=0, ie-ext=0, iECriticality Reject=2bit 00,
        //         iE-ID 27 -> align + 16 bits -> octet2=0x00, octet3=0x00, octet4=0x1B
        //         typeOfError not-understood -> ext=0 + 1bit 0, final align -> octet5=0x00
        let diag = CriticalityDiagnostics {
            procedure_code: None,
            triggering_message: None,
            procedure_criticality: None,
            ies: vec![IeCriticalityDiagnostics {
                ie_criticality: Criticality::Reject,
                ie_id: 27,
                type_of_error: TypeOfError::NotUnderstood,
            }],
        };
        let mut container = ProtocolIeContainer::new();
        encode_criticality_diagnostics(&mut container, &diag).unwrap();
        let field = &container.ies[0];
        assert_eq!(field.value, vec![0x08, 0x00, 0x00, 0x00, 0x1B, 0x00]);
        assert_eq!(decode_criticality_diagnostics(field).unwrap(), diag);
    }

    #[test]
    fn test_criticality_diagnostics_full_roundtrip() {
        let diag = CriticalityDiagnostics {
            procedure_code: Some(21),
            triggering_message: Some(2),
            procedure_criticality: Some(0),
            ies: vec![
                IeCriticalityDiagnostics {
                    ie_criticality: Criticality::Reject,
                    ie_id: 27,
                    type_of_error: TypeOfError::NotUnderstood,
                },
                IeCriticalityDiagnostics {
                    ie_criticality: Criticality::Ignore,
                    ie_id: 0,
                    type_of_error: TypeOfError::Missing,
                },
            ],
        };
        let mut container = ProtocolIeContainer::new();
        encode_criticality_diagnostics(&mut container, &diag).unwrap();
        let decoded = decode_criticality_diagnostics(&container.ies[0]).unwrap();
        assert_eq!(decoded, diag);
    }

    #[test]
    fn test_criticality_diagnostics_empty_list_bytes_unchanged() {
        // Additive-safety guard: with an empty list the encoder must emit the
        // exact same bytes as before NGAP-06 (iEsCriticalityDiagnostics bit = 0).
        let diag = CriticalityDiagnostics {
            procedure_code: Some(21),
            triggering_message: Some(0),
            procedure_criticality: Some(1),
            ies: vec![],
        };
        let mut container = ProtocolIeContainer::new();
        encode_criticality_diagnostics(&mut container, &diag).unwrap();
        // preamble byte has the iEs bit (5th) clear.
        assert_eq!(container.ies[0].value[0] & 0b0000_1000, 0);
        assert_eq!(
            decode_criticality_diagnostics(&container.ies[0]).unwrap(),
            diag
        );
    }
}
