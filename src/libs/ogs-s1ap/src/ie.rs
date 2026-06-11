//! S1AP IE Encoding/Decoding Helpers
//!
//! Functions for encoding individual Information Elements into raw APER bytes
//! suitable for ProtocolIeField values, and decoding them back, per
//! 3GPP TS 36.413 §9.2.

use ogs_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint};
use ogs_asn1c::s1ap::cause::Cause;
use ogs_asn1c::s1ap::ies::{
    EnbUeS1apId as AsnEnbUeS1apId, MmeUeS1apId as AsnMmeUeS1apId, NasPdu, ProtocolIeContainer,
    ProtocolIeField, RelativeMmeCapacity,
};
use ogs_asn1c::s1ap::types::{Criticality, ProtocolIeId};

use crate::error::{S1apError, S1apResult};
use crate::types::*;

// ============================================================================
// Constraints (TS 36.413 §9.2 / §9.4 ASN.1)
// ============================================================================

const ERAB_ID_CONSTRAINT: Constraint = Constraint::new(0, 15);
const BIT_RATE_CONSTRAINT: Constraint = Constraint::new(0, 10_000_000_000);
const PRIORITY_LEVEL_CONSTRAINT: Constraint = Constraint::new(0, 15);
const QCI_CONSTRAINT: Constraint = Constraint::new(0, 255);
const BOOL_ENUM_CONSTRAINT: Constraint = Constraint::new(0, 1);
const PAGING_DRX_CONSTRAINT: Constraint = Constraint::extensible(0, 3);
const RRC_CAUSE_CONSTRAINT: Constraint = Constraint::extensible(0, 4);
const HANDOVER_TYPE_CONSTRAINT: Constraint = Constraint::extensible(0, 4);
const CN_DOMAIN_CONSTRAINT: Constraint = Constraint::new(0, 1);
const RESET_ALL_CONSTRAINT: Constraint = Constraint::extensible(0, 0);
const NEXT_HOP_CHAINING_COUNT_CONSTRAINT: Constraint = Constraint::new(0, 7);
const RNC_ID_CONSTRAINT: Constraint = Constraint::new(0, 4095);
const EXTENDED_RNC_ID_CONSTRAINT: Constraint = Constraint::new(4096, 65535);

const MAX_NO_OF_ERABS: usize = 256;
const MAX_NO_OF_TAIS: usize = 256;
const MAX_NO_OF_TACS: usize = 256;
const MAX_NO_OF_BPLMNS: usize = 6;
const MAX_NO_OF_RATS: usize = 8;
const MAX_NO_OF_PLMNS_PER_MME: usize = 32;
const MAX_NO_OF_GROUP_IDS: usize = 65535;
const MAX_NO_OF_MMECS: usize = 256;
const MAX_NO_OF_INDIVIDUAL_S1_CONNECTIONS_TO_RESET: usize = 256;

// ============================================================================
// Generic helpers
// ============================================================================

/// Encode a value to raw APER bytes for use in ProtocolIeField.value
fn encode_ie_value<T: AperEncode>(value: &T) -> S1apResult<Vec<u8>> {
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
) -> S1apResult<ProtocolIeField> {
    Ok(ProtocolIeField {
        id,
        criticality,
        value: encode_ie_value(value)?,
    })
}

/// Decode a value from raw APER bytes in a ProtocolIeField.value
fn decode_ie_value<T: AperDecode>(raw: &[u8]) -> S1apResult<T> {
    let mut decoder = AperDecoder::new(raw);
    Ok(T::decode_aper(&mut decoder)?)
}

/// Finish an encoder and produce an aligned byte buffer
fn finish_value(mut encoder: AperEncoder) -> Vec<u8> {
    encoder.align();
    encoder.into_bytes().to_vec()
}

/// Push a field built from a closure that writes the IE value
fn push_ie<F>(
    container: &mut ProtocolIeContainer,
    id: ProtocolIeId,
    criticality: Criticality,
    write: F,
) -> S1apResult<()>
where
    F: FnOnce(&mut AperEncoder) -> S1apResult<()>,
{
    let mut encoder = AperEncoder::new();
    write(&mut encoder)?;
    container.push(ProtocolIeField {
        id,
        criticality,
        value: finish_value(encoder),
    });
    Ok(())
}

/// Write the SEQUENCE preamble: extension bit (always false on encode) plus
/// the optional-field presence bitmap.
fn encode_seq_preamble(encoder: &mut AperEncoder, optionals: &[bool]) {
    encoder.write_bit(false);
    for &present in optionals {
        encoder.write_bit(present);
    }
}

/// Read the SEQUENCE preamble: extension bit plus optional-field bitmap.
fn decode_seq_preamble(decoder: &mut AperDecoder, num_optionals: usize) -> S1apResult<(bool, Vec<bool>)> {
    let ext = decoder.read_bit()?;
    let mut opts = Vec::with_capacity(num_optionals);
    for _ in 0..num_optionals {
        opts.push(decoder.read_bit()?);
    }
    Ok((ext, opts))
}

/// Skip a ProtocolExtensionContainer (SEQUENCE SIZE(1..65535) OF
/// ProtocolExtensionField) without interpreting it.
fn skip_extension_container(decoder: &mut AperDecoder) -> S1apResult<()> {
    let count = decoder.decode_constrained_length(1, 65535)?;
    for _ in 0..count {
        let _id = ProtocolIeId::decode_aper(decoder)?;
        let _criticality = Criticality::decode_aper(decoder)?;
        skip_open_type(decoder)?;
    }
    Ok(())
}

/// Skip an open type value (length determinant + content, possibly fragmented)
fn skip_open_type(decoder: &mut AperDecoder) -> S1apResult<()> {
    loop {
        let (len, fragmented) = decoder.decode_length_fragment()?;
        let _ = decoder.read_bytes(len)?;
        if !fragmented {
            return Ok(());
        }
    }
}

/// Skip SEQUENCE extension additions (X.691 §18.8-18.9) when the extension
/// bit was set by the sender.
fn skip_sequence_extensions(decoder: &mut AperDecoder) -> S1apResult<()> {
    // Normally-small length: count of extension-addition presence bits
    let count = decoder.decode_normally_small_non_negative()? as usize + 1;
    let mut present = Vec::with_capacity(count);
    for _ in 0..count {
        present.push(decoder.read_bit()?);
    }
    for p in present {
        if p {
            skip_open_type(decoder)?;
        }
    }
    Ok(())
}

/// Finish decoding a SEQUENCE: consume an iE-Extensions container and/or
/// extension additions if the sender included them.
fn decode_seq_trailer(decoder: &mut AperDecoder, ext: bool, ie_extensions: bool) -> S1apResult<()> {
    if ie_extensions {
        skip_extension_container(decoder)?;
    }
    if ext {
        skip_sequence_extensions(decoder)?;
    }
    Ok(())
}

/// Encode a SEQUENCE OF ProtocolIE-SingleContainer list into an IE
fn push_single_container_list<T, F>(
    container: &mut ProtocolIeContainer,
    list_id: ProtocolIeId,
    list_criticality: Criticality,
    item_id: ProtocolIeId,
    item_criticality: Criticality,
    items: &[T],
    mut encode_item: F,
) -> S1apResult<()>
where
    F: FnMut(&mut AperEncoder, &T) -> S1apResult<()>,
{
    push_ie(container, list_id, list_criticality, |encoder| {
        encoder.encode_constrained_length(items.len(), 1, MAX_NO_OF_ERABS)?;
        for item in items {
            let mut item_encoder = AperEncoder::new();
            encode_item(&mut item_encoder, item)?;
            let field = ProtocolIeField {
                id: item_id,
                criticality: item_criticality,
                value: finish_value(item_encoder),
            };
            field.encode_aper(encoder)?;
        }
        Ok(())
    })
}

/// Decode a SEQUENCE OF ProtocolIE-SingleContainer list from an IE field
fn decode_single_container_list<T, F>(
    field: &ProtocolIeField,
    expected_item_id: ProtocolIeId,
    mut decode_item: F,
) -> S1apResult<Vec<T>>
where
    F: FnMut(&mut AperDecoder) -> S1apResult<T>,
{
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, MAX_NO_OF_ERABS)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let item_field = ProtocolIeField::decode_aper(&mut decoder)?;
        if item_field.id != expected_item_id {
            return Err(S1apError::ProtocolError(format!(
                "unexpected item IE id {} (expected {})",
                item_field.id.0, expected_item_id.0
            )));
        }
        let mut item_decoder = AperDecoder::new(&item_field.value);
        items.push(decode_item(&mut item_decoder)?);
    }
    Ok(items)
}

// ============================================================================
// Inline field codecs (not full IEs)
// ============================================================================

fn encode_plmn(encoder: &mut AperEncoder, plmn: &[u8; 3]) -> S1apResult<()> {
    encoder.encode_octet_string(plmn, Some(3), Some(3))?;
    Ok(())
}

fn decode_plmn(decoder: &mut AperDecoder) -> S1apResult<[u8; 3]> {
    let bytes = decoder.decode_octet_string(Some(3), Some(3))?;
    let mut plmn = [0u8; 3];
    plmn.copy_from_slice(&bytes);
    Ok(plmn)
}

fn encode_fixed_u16(encoder: &mut AperEncoder, value: u16) -> S1apResult<()> {
    // OCTET STRING (SIZE(2))
    encoder.encode_octet_string(&value.to_be_bytes(), Some(2), Some(2))?;
    Ok(())
}

fn decode_fixed_u16(decoder: &mut AperDecoder) -> S1apResult<u16> {
    let bytes = decoder.decode_octet_string(Some(2), Some(2))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn encode_gtp_teid(encoder: &mut AperEncoder, teid: u32) -> S1apResult<()> {
    // GTP-TEID ::= OCTET STRING (SIZE(4))
    encoder.encode_octet_string(&teid.to_be_bytes(), Some(4), Some(4))?;
    Ok(())
}

fn decode_gtp_teid(decoder: &mut AperDecoder) -> S1apResult<u32> {
    let bytes = decoder.decode_octet_string(Some(4), Some(4))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn encode_erab_id(encoder: &mut AperEncoder, erab_id: u8) -> S1apResult<()> {
    // E-RAB-ID ::= INTEGER (0..15, ...)
    encoder.write_bit(false);
    encoder.encode_constrained_whole_number(erab_id as i64, &ERAB_ID_CONSTRAINT)?;
    Ok(())
}

fn decode_erab_id(decoder: &mut AperDecoder) -> S1apResult<u8> {
    let extended = decoder.read_bit()?;
    if extended {
        return Err(S1apError::InvalidIeValue {
            ie_name: "E-RAB-ID",
            reason: "extension values not supported".to_string(),
        });
    }
    let value = decoder.decode_constrained_whole_number(&ERAB_ID_CONSTRAINT)?;
    Ok(value as u8)
}

fn encode_transport_address(encoder: &mut AperEncoder, address: &[u8]) -> S1apResult<()> {
    // TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))
    encoder.write_bit(false);
    encoder.encode_constrained_length(address.len() * 8, 1, 160)?;
    encoder.align();
    encoder.write_bytes(address);
    Ok(())
}

fn decode_transport_address(decoder: &mut AperDecoder) -> S1apResult<Vec<u8>> {
    let extended = decoder.read_bit()?;
    let num_bits = if extended {
        decoder.decode_length_determinant()?
    } else {
        decoder.decode_constrained_length(1, 160)?
    };
    if num_bits % 8 != 0 {
        return Err(S1apError::InvalidIeValue {
            ie_name: "TransportLayerAddress",
            reason: format!("bit length {num_bits} is not byte-aligned"),
        });
    }
    decoder.align();
    Ok(decoder.read_bytes(num_bits / 8)?)
}

fn encode_tai_inline(encoder: &mut AperEncoder, tai: &Tai) -> S1apResult<()> {
    // TAI ::= SEQUENCE { pLMNidentity, tAC, iE-Extensions OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encode_plmn(encoder, &tai.plmn_identity)?;
    encode_fixed_u16(encoder, tai.tac)?;
    Ok(())
}

fn decode_tai_inline(decoder: &mut AperDecoder) -> S1apResult<Tai> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let plmn_identity = decode_plmn(decoder)?;
    let tac = decode_fixed_u16(decoder)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(Tai { plmn_identity, tac })
}

fn encode_eutran_cgi_inline(encoder: &mut AperEncoder, cgi: &EutranCgi) -> S1apResult<()> {
    // EUTRAN-CGI ::= SEQUENCE { pLMNidentity, cell-ID BIT STRING(28), iE-Ext OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encode_plmn(encoder, &cgi.plmn_identity)?;
    encoder.align();
    encoder.write_bits((cgi.cell_identity & 0x0FFF_FFFF) as u64, 28);
    Ok(())
}

fn decode_eutran_cgi_inline(decoder: &mut AperDecoder) -> S1apResult<EutranCgi> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let plmn_identity = decode_plmn(decoder)?;
    decoder.align();
    let cell_identity = decoder.read_bits(28)? as u32;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(EutranCgi {
        plmn_identity,
        cell_identity,
    })
}

fn encode_global_enb_id_inline(encoder: &mut AperEncoder, id: &GlobalEnbId) -> S1apResult<()> {
    // Global-ENB-ID ::= SEQUENCE { pLMNidentity, eNB-ID CHOICE, iE-Ext OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encode_plmn(encoder, &id.plmn_identity)?;
    // ENB-ID ::= CHOICE { macroENB-ID BIT STRING(20), homeENB-ID BIT STRING(28), ... }
    match id.enb_id {
        EnbId::Macro(value) => {
            encoder.encode_choice_index(0, 2, true)?;
            encoder.align();
            encoder.write_bits((value & 0x000F_FFFF) as u64, 20);
        }
        EnbId::Home(value) => {
            encoder.encode_choice_index(1, 2, true)?;
            encoder.align();
            encoder.write_bits((value & 0x0FFF_FFFF) as u64, 28);
        }
    }
    Ok(())
}

fn decode_global_enb_id_inline(decoder: &mut AperDecoder) -> S1apResult<GlobalEnbId> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let plmn_identity = decode_plmn(decoder)?;
    let index = decoder.decode_choice_index(2, true)?;
    let enb_id = match index {
        0 => {
            decoder.align();
            EnbId::Macro(decoder.read_bits(20)? as u32)
        }
        1 => {
            decoder.align();
            EnbId::Home(decoder.read_bits(28)? as u32)
        }
        _ => {
            return Err(S1apError::InvalidIeValue {
                ie_name: "ENB-ID",
                reason: format!("unsupported choice index {index}"),
            })
        }
    };
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(GlobalEnbId {
        plmn_identity,
        enb_id,
    })
}

fn encode_arp_inline(
    encoder: &mut AperEncoder,
    arp: &AllocationRetentionPriority,
) -> S1apResult<()> {
    // AllocationAndRetentionPriority ::= SEQUENCE { priorityLevel, pre-emptionCapability,
    //   pre-emptionVulnerability, iE-Extensions OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encoder.encode_constrained_whole_number(arp.priority_level as i64, &PRIORITY_LEVEL_CONSTRAINT)?;
    encoder.encode_enumerated(arp.pre_emption_capability as i64, &BOOL_ENUM_CONSTRAINT)?;
    encoder.encode_enumerated(arp.pre_emption_vulnerability as i64, &BOOL_ENUM_CONSTRAINT)?;
    Ok(())
}

fn decode_arp_inline(decoder: &mut AperDecoder) -> S1apResult<AllocationRetentionPriority> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let priority_level = decoder.decode_constrained_whole_number(&PRIORITY_LEVEL_CONSTRAINT)? as u8;
    let pre_emption_capability = decoder.decode_enumerated(&BOOL_ENUM_CONSTRAINT)? != 0;
    let pre_emption_vulnerability = decoder.decode_enumerated(&BOOL_ENUM_CONSTRAINT)? != 0;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(AllocationRetentionPriority {
        priority_level,
        pre_emption_capability,
        pre_emption_vulnerability,
    })
}

fn encode_erab_qos_inline(
    encoder: &mut AperEncoder,
    qos: &ErabLevelQosParameters,
) -> S1apResult<()> {
    // E-RABLevelQoSParameters ::= SEQUENCE { qCI, allocationRetentionPriority,
    //   gbrQosInformation OPTIONAL, iE-Extensions OPTIONAL, ... }
    encode_seq_preamble(encoder, &[qos.gbr_qos_info.is_some(), false]);
    encoder.encode_constrained_whole_number(qos.qci as i64, &QCI_CONSTRAINT)?;
    encode_arp_inline(encoder, &qos.arp)?;
    if let Some(ref gbr) = qos.gbr_qos_info {
        // GBR-QosInformation ::= SEQUENCE { 4x BitRate, iE-Extensions OPTIONAL, ... }
        encode_seq_preamble(encoder, &[false]);
        encoder.encode_constrained_whole_number(gbr.erab_max_bitrate_dl as i64, &BIT_RATE_CONSTRAINT)?;
        encoder.encode_constrained_whole_number(gbr.erab_max_bitrate_ul as i64, &BIT_RATE_CONSTRAINT)?;
        encoder.encode_constrained_whole_number(
            gbr.erab_guaranteed_bitrate_dl as i64,
            &BIT_RATE_CONSTRAINT,
        )?;
        encoder.encode_constrained_whole_number(
            gbr.erab_guaranteed_bitrate_ul as i64,
            &BIT_RATE_CONSTRAINT,
        )?;
    }
    Ok(())
}

fn decode_erab_qos_inline(decoder: &mut AperDecoder) -> S1apResult<ErabLevelQosParameters> {
    let (ext, opts) = decode_seq_preamble(decoder, 2)?;
    let qci = decoder.decode_constrained_whole_number(&QCI_CONSTRAINT)? as u8;
    let arp = decode_arp_inline(decoder)?;
    let gbr_qos_info = if opts[0] {
        let (gbr_ext, gbr_opts) = decode_seq_preamble(decoder, 1)?;
        let erab_max_bitrate_dl =
            decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
        let erab_max_bitrate_ul =
            decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
        let erab_guaranteed_bitrate_dl =
            decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
        let erab_guaranteed_bitrate_ul =
            decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
        decode_seq_trailer(decoder, gbr_ext, gbr_opts[0])?;
        Some(GbrQosInformation {
            erab_max_bitrate_dl,
            erab_max_bitrate_ul,
            erab_guaranteed_bitrate_dl,
            erab_guaranteed_bitrate_ul,
        })
    } else {
        None
    };
    decode_seq_trailer(decoder, ext, opts[1])?;
    Ok(ErabLevelQosParameters {
        qci,
        arp,
        gbr_qos_info,
    })
}

fn encode_security_key_inline(encoder: &mut AperEncoder, key: &[u8; 32]) {
    // SecurityKey ::= BIT STRING (SIZE(256))
    encoder.align();
    encoder.write_bytes(key);
}

fn decode_security_key_inline(decoder: &mut AperDecoder) -> S1apResult<[u8; 32]> {
    decoder.align();
    let bytes = decoder.read_bytes(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encode_s_tmsi_inline(encoder: &mut AperEncoder, s_tmsi: &STmsi) -> S1apResult<()> {
    // S-TMSI ::= SEQUENCE { mMEC OCTET STRING(1), m-TMSI OCTET STRING(4), iE-Ext OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encoder.encode_octet_string(&[s_tmsi.mmec], Some(1), Some(1))?;
    encoder.encode_octet_string(&s_tmsi.m_tmsi.to_be_bytes(), Some(4), Some(4))?;
    Ok(())
}

fn decode_s_tmsi_inline(decoder: &mut AperDecoder) -> S1apResult<STmsi> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let mmec_bytes = decoder.decode_octet_string(Some(1), Some(1))?;
    let m_tmsi_bytes = decoder.decode_octet_string(Some(4), Some(4))?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(STmsi {
        mmec: mmec_bytes[0],
        m_tmsi: u32::from_be_bytes([
            m_tmsi_bytes[0],
            m_tmsi_bytes[1],
            m_tmsi_bytes[2],
            m_tmsi_bytes[3],
        ]),
    })
}

fn encode_printable_string(encoder: &mut AperEncoder, value: &str) -> S1apResult<()> {
    // PrintableString (SIZE(1..150, ...))
    encoder.write_bit(false);
    encoder.encode_constrained_length(value.len(), 1, 150)?;
    encoder.align();
    encoder.write_bytes(value.as_bytes());
    Ok(())
}

fn decode_printable_string(decoder: &mut AperDecoder, ie_name: &'static str) -> S1apResult<String> {
    let extended = decoder.read_bit()?;
    let len = if extended {
        decoder.decode_length_determinant()?
    } else {
        decoder.decode_constrained_length(1, 150)?
    };
    decoder.align();
    let bytes = decoder.read_bytes(len)?;
    String::from_utf8(bytes).map_err(|e| S1apError::InvalidIeValue {
        ie_name,
        reason: e.to_string(),
    })
}

fn encode_ue_connection_item(
    encoder: &mut AperEncoder,
    item: &UeAssociatedLogicalS1Connection,
) -> S1apResult<()> {
    // UE-associatedLogicalS1-ConnectionItem ::= SEQUENCE {
    //   mME-UE-S1AP-ID OPTIONAL, eNB-UE-S1AP-ID OPTIONAL, iE-Extensions OPTIONAL, ... }
    encode_seq_preamble(
        encoder,
        &[
            item.mme_ue_s1ap_id.is_some(),
            item.enb_ue_s1ap_id.is_some(),
            false,
        ],
    );
    if let Some(id) = item.mme_ue_s1ap_id {
        AsnMmeUeS1apId(id).encode_aper(encoder)?;
    }
    if let Some(id) = item.enb_ue_s1ap_id {
        AsnEnbUeS1apId(id).encode_aper(encoder)?;
    }
    Ok(())
}

fn decode_ue_connection_item(
    decoder: &mut AperDecoder,
) -> S1apResult<UeAssociatedLogicalS1Connection> {
    let (ext, opts) = decode_seq_preamble(decoder, 3)?;
    let mme_ue_s1ap_id = if opts[0] {
        Some(AsnMmeUeS1apId::decode_aper(decoder)?.0)
    } else {
        None
    };
    let enb_ue_s1ap_id = if opts[1] {
        Some(AsnEnbUeS1apId::decode_aper(decoder)?.0)
    } else {
        None
    };
    decode_seq_trailer(decoder, ext, opts[2])?;
    Ok(UeAssociatedLogicalS1Connection {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
    })
}

fn encode_ue_security_capabilities_inline(
    encoder: &mut AperEncoder,
    caps: &UeSecurityCapabilities,
) -> S1apResult<()> {
    // UESecurityCapabilities ::= SEQUENCE { encryptionAlgorithms BIT STRING(16, ...),
    //   integrityProtectionAlgorithms BIT STRING(16, ...), iE-Extensions OPTIONAL, ... }
    encode_seq_preamble(encoder, &[false]);
    encoder.write_bit(false);
    encoder.write_bits(caps.encryption_algorithms as u64, 16);
    encoder.write_bit(false);
    encoder.write_bits(caps.integrity_algorithms as u64, 16);
    Ok(())
}

fn decode_extensible_bit_string_16(
    decoder: &mut AperDecoder,
    ie_name: &'static str,
) -> S1apResult<u16> {
    let extended = decoder.read_bit()?;
    if extended {
        return Err(S1apError::InvalidIeValue {
            ie_name,
            reason: "extended bit string size not supported".to_string(),
        });
    }
    Ok(decoder.read_bits(16)? as u16)
}

fn decode_ue_security_capabilities_inline(
    decoder: &mut AperDecoder,
) -> S1apResult<UeSecurityCapabilities> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let encryption_algorithms = decode_extensible_bit_string_16(decoder, "EncryptionAlgorithms")?;
    let integrity_algorithms =
        decode_extensible_bit_string_16(decoder, "IntegrityProtectionAlgorithms")?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(UeSecurityCapabilities {
        encryption_algorithms,
        integrity_algorithms,
    })
}

// ============================================================================
// E-RAB item codecs
// ============================================================================

/// E-RABToBeSetupItemCtxtSUReq: nAS-PDU is OPTIONAL
fn encode_erab_to_be_setup_item_ctxt(
    encoder: &mut AperEncoder,
    item: &ErabToBeSetupItem,
) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[item.nas_pdu.is_some(), false]);
    encode_erab_id(encoder, item.erab_id)?;
    encode_erab_qos_inline(encoder, &item.erab_qos)?;
    encode_transport_address(encoder, &item.transport_layer_address)?;
    encode_gtp_teid(encoder, item.gtp_teid)?;
    if let Some(ref nas_pdu) = item.nas_pdu {
        encoder.encode_octet_string(nas_pdu, None, None)?;
    }
    Ok(())
}

fn decode_erab_to_be_setup_item_ctxt(decoder: &mut AperDecoder) -> S1apResult<ErabToBeSetupItem> {
    let (ext, opts) = decode_seq_preamble(decoder, 2)?;
    let erab_id = decode_erab_id(decoder)?;
    let erab_qos = decode_erab_qos_inline(decoder)?;
    let transport_layer_address = decode_transport_address(decoder)?;
    let gtp_teid = decode_gtp_teid(decoder)?;
    let nas_pdu = if opts[0] {
        Some(decoder.decode_octet_string(None, None)?)
    } else {
        None
    };
    decode_seq_trailer(decoder, ext, opts[1])?;
    Ok(ErabToBeSetupItem {
        erab_id,
        erab_qos,
        transport_layer_address,
        gtp_teid,
        nas_pdu,
    })
}

/// E-RABToBeSetupItemBearerSUReq: nAS-PDU is MANDATORY
fn encode_erab_to_be_setup_item_bearer(
    encoder: &mut AperEncoder,
    item: &ErabToBeSetupItem,
) -> S1apResult<()> {
    let nas_pdu = item
        .nas_pdu
        .as_ref()
        .ok_or(S1apError::MissingMandatoryIe("NAS-PDU (E-RABToBeSetupItemBearerSUReq)"))?;
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, item.erab_id)?;
    encode_erab_qos_inline(encoder, &item.erab_qos)?;
    encode_transport_address(encoder, &item.transport_layer_address)?;
    encode_gtp_teid(encoder, item.gtp_teid)?;
    encoder.encode_octet_string(nas_pdu, None, None)?;
    Ok(())
}

fn decode_erab_to_be_setup_item_bearer(decoder: &mut AperDecoder) -> S1apResult<ErabToBeSetupItem> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    let erab_qos = decode_erab_qos_inline(decoder)?;
    let transport_layer_address = decode_transport_address(decoder)?;
    let gtp_teid = decode_gtp_teid(decoder)?;
    let nas_pdu = Some(decoder.decode_octet_string(None, None)?);
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(ErabToBeSetupItem {
        erab_id,
        erab_qos,
        transport_layer_address,
        gtp_teid,
        nas_pdu,
    })
}

/// Shared shape: SEQUENCE { e-RAB-ID, transportLayerAddress, gTP-TEID, iE-Ext OPTIONAL, ... }
/// Used by E-RABSetupItem (CtxtSURes / BearerSURes) and E-RABToBeSwitched DL/UL items.
fn encode_erab_setup_shape_item(
    encoder: &mut AperEncoder,
    erab_id: u8,
    transport_layer_address: &[u8],
    gtp_teid: u32,
) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, erab_id)?;
    encode_transport_address(encoder, transport_layer_address)?;
    encode_gtp_teid(encoder, gtp_teid)?;
    Ok(())
}

fn decode_erab_setup_shape_item(decoder: &mut AperDecoder) -> S1apResult<(u8, Vec<u8>, u32)> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    let transport_layer_address = decode_transport_address(decoder)?;
    let gtp_teid = decode_gtp_teid(decoder)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok((erab_id, transport_layer_address, gtp_teid))
}

/// E-RABItem ::= SEQUENCE { e-RAB-ID, cause, iE-Extensions OPTIONAL, ... }
fn encode_erab_item(encoder: &mut AperEncoder, erab_id: u8, cause: &Cause) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, erab_id)?;
    cause.encode_aper(encoder)?;
    Ok(())
}

fn decode_erab_item(decoder: &mut AperDecoder) -> S1apResult<(u8, Cause)> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    let cause = Cause::decode_aper(decoder)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok((erab_id, cause))
}

/// Shared shape: SEQUENCE { e-RAB-ID, iE-Extensions OPTIONAL, ... }
/// Used by E-RABModifyItemBearerModRes and E-RABReleaseItemBearerRelComp.
fn encode_erab_id_only_item(encoder: &mut AperEncoder, erab_id: u8) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, erab_id)?;
    Ok(())
}

fn decode_erab_id_only_item(decoder: &mut AperDecoder) -> S1apResult<u8> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(erab_id)
}

/// E-RABToBeModifiedItemBearerModReq ::= SEQUENCE { e-RAB-ID, e-RABLevelQoSParameters,
///   nAS-PDU, iE-Extensions OPTIONAL, ... }
fn encode_erab_to_be_modified_item(
    encoder: &mut AperEncoder,
    item: &ErabToBeModifiedItem,
) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, item.erab_id)?;
    encode_erab_qos_inline(encoder, &item.erab_qos)?;
    encoder.encode_octet_string(&item.nas_pdu, None, None)?;
    Ok(())
}

fn decode_erab_to_be_modified_item(decoder: &mut AperDecoder) -> S1apResult<ErabToBeModifiedItem> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    let erab_qos = decode_erab_qos_inline(decoder)?;
    let nas_pdu = decoder.decode_octet_string(None, None)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(ErabToBeModifiedItem {
        erab_id,
        erab_qos,
        nas_pdu,
    })
}

/// E-RABToBeSetupItemHOReq ::= SEQUENCE { e-RAB-ID, transportLayerAddress, gTP-TEID,
///   e-RABlevelQosParameters, iE-Extensions OPTIONAL, ... }
fn encode_erab_to_be_setup_item_ho_req(
    encoder: &mut AperEncoder,
    item: &ErabToBeSetupItemHoReq,
) -> S1apResult<()> {
    encode_seq_preamble(encoder, &[false]);
    encode_erab_id(encoder, item.erab_id)?;
    encode_transport_address(encoder, &item.transport_layer_address)?;
    encode_gtp_teid(encoder, item.gtp_teid)?;
    encode_erab_qos_inline(encoder, &item.erab_qos)?;
    Ok(())
}

fn decode_erab_to_be_setup_item_ho_req(
    decoder: &mut AperDecoder,
) -> S1apResult<ErabToBeSetupItemHoReq> {
    let (ext, opts) = decode_seq_preamble(decoder, 1)?;
    let erab_id = decode_erab_id(decoder)?;
    let transport_layer_address = decode_transport_address(decoder)?;
    let gtp_teid = decode_gtp_teid(decoder)?;
    let erab_qos = decode_erab_qos_inline(decoder)?;
    decode_seq_trailer(decoder, ext, opts[0])?;
    Ok(ErabToBeSetupItemHoReq {
        erab_id,
        transport_layer_address,
        gtp_teid,
        erab_qos,
    })
}

/// E-RABAdmittedItem ::= SEQUENCE { e-RAB-ID, transportLayerAddress, gTP-TEID,
///   dL-transportLayerAddress OPTIONAL, dL-gTP-TEID OPTIONAL,
///   uL-TransportLayerAddress OPTIONAL, uL-GTP-TEID OPTIONAL, iE-Ext OPTIONAL, ... }
fn encode_erab_admitted_item(
    encoder: &mut AperEncoder,
    item: &ErabAdmittedItem,
) -> S1apResult<()> {
    encode_seq_preamble(
        encoder,
        &[
            item.dl_transport_layer_address.is_some(),
            item.dl_gtp_teid.is_some(),
            item.ul_transport_layer_address.is_some(),
            item.ul_gtp_teid.is_some(),
            false,
        ],
    );
    encode_erab_id(encoder, item.erab_id)?;
    encode_transport_address(encoder, &item.transport_layer_address)?;
    encode_gtp_teid(encoder, item.gtp_teid)?;
    if let Some(ref addr) = item.dl_transport_layer_address {
        encode_transport_address(encoder, addr)?;
    }
    if let Some(teid) = item.dl_gtp_teid {
        encode_gtp_teid(encoder, teid)?;
    }
    if let Some(ref addr) = item.ul_transport_layer_address {
        encode_transport_address(encoder, addr)?;
    }
    if let Some(teid) = item.ul_gtp_teid {
        encode_gtp_teid(encoder, teid)?;
    }
    Ok(())
}

fn decode_erab_admitted_item(decoder: &mut AperDecoder) -> S1apResult<ErabAdmittedItem> {
    let (ext, opts) = decode_seq_preamble(decoder, 5)?;
    let erab_id = decode_erab_id(decoder)?;
    let transport_layer_address = decode_transport_address(decoder)?;
    let gtp_teid = decode_gtp_teid(decoder)?;
    let dl_transport_layer_address = if opts[0] {
        Some(decode_transport_address(decoder)?)
    } else {
        None
    };
    let dl_gtp_teid = if opts[1] {
        Some(decode_gtp_teid(decoder)?)
    } else {
        None
    };
    let ul_transport_layer_address = if opts[2] {
        Some(decode_transport_address(decoder)?)
    } else {
        None
    };
    let ul_gtp_teid = if opts[3] {
        Some(decode_gtp_teid(decoder)?)
    } else {
        None
    };
    decode_seq_trailer(decoder, ext, opts[4])?;
    Ok(ErabAdmittedItem {
        erab_id,
        transport_layer_address,
        gtp_teid,
        dl_transport_layer_address,
        dl_gtp_teid,
        ul_transport_layer_address,
        ul_gtp_teid,
    })
}

/// E-RABDataForwardingItem ::= SEQUENCE { e-RAB-ID,
///   dL-transportLayerAddress OPTIONAL, dL-gTP-TEID OPTIONAL,
///   uL-TransportLayerAddress OPTIONAL, uL-GTP-TEID OPTIONAL, iE-Ext OPTIONAL, ... }
fn encode_erab_data_forwarding_item(
    encoder: &mut AperEncoder,
    item: &ErabDataForwardingItem,
) -> S1apResult<()> {
    encode_seq_preamble(
        encoder,
        &[
            item.dl_transport_layer_address.is_some(),
            item.dl_gtp_teid.is_some(),
            item.ul_transport_layer_address.is_some(),
            item.ul_gtp_teid.is_some(),
            false,
        ],
    );
    encode_erab_id(encoder, item.erab_id)?;
    if let Some(ref addr) = item.dl_transport_layer_address {
        encode_transport_address(encoder, addr)?;
    }
    if let Some(teid) = item.dl_gtp_teid {
        encode_gtp_teid(encoder, teid)?;
    }
    if let Some(ref addr) = item.ul_transport_layer_address {
        encode_transport_address(encoder, addr)?;
    }
    if let Some(teid) = item.ul_gtp_teid {
        encode_gtp_teid(encoder, teid)?;
    }
    Ok(())
}

fn decode_erab_data_forwarding_item(
    decoder: &mut AperDecoder,
) -> S1apResult<ErabDataForwardingItem> {
    let (ext, opts) = decode_seq_preamble(decoder, 5)?;
    let erab_id = decode_erab_id(decoder)?;
    let dl_transport_layer_address = if opts[0] {
        Some(decode_transport_address(decoder)?)
    } else {
        None
    };
    let dl_gtp_teid = if opts[1] {
        Some(decode_gtp_teid(decoder)?)
    } else {
        None
    };
    let ul_transport_layer_address = if opts[2] {
        Some(decode_transport_address(decoder)?)
    } else {
        None
    };
    let ul_gtp_teid = if opts[3] {
        Some(decode_gtp_teid(decoder)?)
    } else {
        None
    };
    decode_seq_trailer(decoder, ext, opts[4])?;
    Ok(ErabDataForwardingItem {
        erab_id,
        dl_transport_layer_address,
        dl_gtp_teid,
        ul_transport_layer_address,
        ul_gtp_teid,
    })
}

// ============================================================================
// Simple IE encode/decode (UE IDs, NAS-PDU, Cause, ...)
// ============================================================================

pub fn encode_mme_ue_s1ap_id(
    container: &mut ProtocolIeContainer,
    id: u32,
    criticality: Criticality,
) -> S1apResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::MME_UE_S1AP_ID,
        criticality,
        &AsnMmeUeS1apId(id),
    )?);
    Ok(())
}

pub fn decode_mme_ue_s1ap_id(field: &ProtocolIeField) -> S1apResult<u32> {
    let id: AsnMmeUeS1apId = decode_ie_value(&field.value)?;
    Ok(id.0)
}

pub fn encode_enb_ue_s1ap_id(
    container: &mut ProtocolIeContainer,
    id: u32,
    criticality: Criticality,
) -> S1apResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::ENB_UE_S1AP_ID,
        criticality,
        &AsnEnbUeS1apId(id),
    )?);
    Ok(())
}

pub fn decode_enb_ue_s1ap_id(field: &ProtocolIeField) -> S1apResult<u32> {
    let id: AsnEnbUeS1apId = decode_ie_value(&field.value)?;
    Ok(id.0)
}

pub fn encode_source_mme_ue_s1ap_id(container: &mut ProtocolIeContainer, id: u32) -> S1apResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::SOURCE_MME_UE_S1AP_ID,
        Criticality::Reject,
        &AsnMmeUeS1apId(id),
    )?);
    Ok(())
}

pub fn decode_source_mme_ue_s1ap_id(field: &ProtocolIeField) -> S1apResult<u32> {
    let id: AsnMmeUeS1apId = decode_ie_value(&field.value)?;
    Ok(id.0)
}

pub fn encode_nas_pdu(
    container: &mut ProtocolIeContainer,
    pdu: &[u8],
    criticality: Criticality,
) -> S1apResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::NAS_PDU,
        criticality,
        &NasPdu(pdu.to_vec()),
    )?);
    Ok(())
}

pub fn decode_nas_pdu(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    let pdu: NasPdu = decode_ie_value(&field.value)?;
    Ok(pdu.0)
}

pub fn encode_cause(container: &mut ProtocolIeContainer, cause: &Cause) -> S1apResult<()> {
    container.push(make_ie_field(ProtocolIeId::CAUSE, Criticality::Ignore, cause)?);
    Ok(())
}

pub fn decode_cause(field: &ProtocolIeField) -> S1apResult<Cause> {
    decode_ie_value(&field.value)
}

pub fn encode_time_to_wait(container: &mut ProtocolIeContainer, ttw: TimeToWait) -> S1apResult<()> {
    let asn_ttw = match ttw {
        TimeToWait::V1s => ogs_asn1c::s1ap::ies::TimeToWait::V1s,
        TimeToWait::V2s => ogs_asn1c::s1ap::ies::TimeToWait::V2s,
        TimeToWait::V5s => ogs_asn1c::s1ap::ies::TimeToWait::V5s,
        TimeToWait::V10s => ogs_asn1c::s1ap::ies::TimeToWait::V10s,
        TimeToWait::V20s => ogs_asn1c::s1ap::ies::TimeToWait::V20s,
        TimeToWait::V60s => ogs_asn1c::s1ap::ies::TimeToWait::V60s,
    };
    container.push(make_ie_field(
        ProtocolIeId::TIME_TO_WAIT,
        Criticality::Ignore,
        &asn_ttw,
    )?);
    Ok(())
}

pub fn decode_time_to_wait(field: &ProtocolIeField) -> S1apResult<TimeToWait> {
    let asn_ttw: ogs_asn1c::s1ap::ies::TimeToWait = decode_ie_value(&field.value)?;
    Ok(match asn_ttw {
        ogs_asn1c::s1ap::ies::TimeToWait::V1s => TimeToWait::V1s,
        ogs_asn1c::s1ap::ies::TimeToWait::V2s => TimeToWait::V2s,
        ogs_asn1c::s1ap::ies::TimeToWait::V5s => TimeToWait::V5s,
        ogs_asn1c::s1ap::ies::TimeToWait::V10s => TimeToWait::V10s,
        ogs_asn1c::s1ap::ies::TimeToWait::V20s => TimeToWait::V20s,
        ogs_asn1c::s1ap::ies::TimeToWait::V60s => TimeToWait::V60s,
    })
}

pub fn encode_relative_mme_capacity(
    container: &mut ProtocolIeContainer,
    capacity: u8,
) -> S1apResult<()> {
    container.push(make_ie_field(
        ProtocolIeId::RELATIVE_MME_CAPACITY,
        Criticality::Reject,
        &RelativeMmeCapacity(capacity),
    )?);
    Ok(())
}

pub fn decode_relative_mme_capacity(field: &ProtocolIeField) -> S1apResult<u8> {
    let cap: RelativeMmeCapacity = decode_ie_value(&field.value)?;
    Ok(cap.0)
}

// ============================================================================
// S1 Setup IEs
// ============================================================================

pub fn encode_global_enb_id(
    container: &mut ProtocolIeContainer,
    id: &GlobalEnbId,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::GLOBAL_ENB_ID,
        Criticality::Reject,
        |encoder| encode_global_enb_id_inline(encoder, id),
    )
}

pub fn decode_global_enb_id(field: &ProtocolIeField) -> S1apResult<GlobalEnbId> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_global_enb_id_inline(&mut decoder)
}

pub fn encode_enb_name(container: &mut ProtocolIeContainer, name: &str) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::ENB_NAME,
        Criticality::Ignore,
        |encoder| encode_printable_string(encoder, name),
    )
}

pub fn decode_enb_name(field: &ProtocolIeField) -> S1apResult<String> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_printable_string(&mut decoder, "ENBname")
}

pub fn encode_mme_name(container: &mut ProtocolIeContainer, name: &str) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::MME_NAME,
        Criticality::Ignore,
        |encoder| encode_printable_string(encoder, name),
    )
}

pub fn decode_mme_name(field: &ProtocolIeField) -> S1apResult<String> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_printable_string(&mut decoder, "MMEname")
}

pub fn encode_supported_tas(
    container: &mut ProtocolIeContainer,
    tas: &[SupportedTaItem],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::SUPPORTED_TAS,
        Criticality::Reject,
        |encoder| {
            // SupportedTAs ::= SEQUENCE (SIZE(1..256)) OF SupportedTAs-Item
            encoder.encode_constrained_length(tas.len(), 1, MAX_NO_OF_TACS)?;
            for ta in tas {
                // SupportedTAs-Item ::= SEQUENCE { tAC, broadcastPLMNs, iE-Ext OPTIONAL, ... }
                encode_seq_preamble(encoder, &[false]);
                encode_fixed_u16(encoder, ta.tac)?;
                encoder.encode_constrained_length(ta.broadcast_plmns.len(), 1, MAX_NO_OF_BPLMNS)?;
                for plmn in &ta.broadcast_plmns {
                    encode_plmn(encoder, plmn)?;
                }
            }
            Ok(())
        },
    )
}

pub fn decode_supported_tas(field: &ProtocolIeField) -> S1apResult<Vec<SupportedTaItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, MAX_NO_OF_TACS)?;
    let mut tas = Vec::with_capacity(count);
    for _ in 0..count {
        let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
        let tac = decode_fixed_u16(&mut decoder)?;
        let plmn_count = decoder.decode_constrained_length(1, MAX_NO_OF_BPLMNS)?;
        let mut broadcast_plmns = Vec::with_capacity(plmn_count);
        for _ in 0..plmn_count {
            broadcast_plmns.push(decode_plmn(&mut decoder)?);
        }
        decode_seq_trailer(&mut decoder, ext, opts[0])?;
        tas.push(SupportedTaItem {
            tac,
            broadcast_plmns,
        });
    }
    Ok(tas)
}

pub fn encode_default_paging_drx(
    container: &mut ProtocolIeContainer,
    drx: PagingDrx,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::DEFAULT_PAGING_DRX,
        Criticality::Ignore,
        |encoder| {
            encoder.encode_enumerated(drx as i64, &PAGING_DRX_CONSTRAINT)?;
            Ok(())
        },
    )
}

fn paging_drx_from_value(value: i64) -> S1apResult<PagingDrx> {
    match value {
        0 => Ok(PagingDrx::V32),
        1 => Ok(PagingDrx::V64),
        2 => Ok(PagingDrx::V128),
        3 => Ok(PagingDrx::V256),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "PagingDRX",
            reason: format!("unknown value {value}"),
        }),
    }
}

pub fn decode_default_paging_drx(field: &ProtocolIeField) -> S1apResult<PagingDrx> {
    let mut decoder = AperDecoder::new(&field.value);
    paging_drx_from_value(decoder.decode_enumerated(&PAGING_DRX_CONSTRAINT)?)
}

pub fn encode_paging_drx(container: &mut ProtocolIeContainer, drx: PagingDrx) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::PAGING_DRX,
        Criticality::Ignore,
        |encoder| {
            encoder.encode_enumerated(drx as i64, &PAGING_DRX_CONSTRAINT)?;
            Ok(())
        },
    )
}

pub fn decode_paging_drx(field: &ProtocolIeField) -> S1apResult<PagingDrx> {
    let mut decoder = AperDecoder::new(&field.value);
    paging_drx_from_value(decoder.decode_enumerated(&PAGING_DRX_CONSTRAINT)?)
}

pub fn encode_served_gummeis(
    container: &mut ProtocolIeContainer,
    gummeis: &[ServedGummeiItem],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::SERVED_GUMMEIS,
        Criticality::Reject,
        |encoder| {
            // ServedGUMMEIs ::= SEQUENCE (SIZE(1..8)) OF ServedGUMMEIsItem
            encoder.encode_constrained_length(gummeis.len(), 1, MAX_NO_OF_RATS)?;
            for item in gummeis {
                // ServedGUMMEIsItem ::= SEQUENCE { servedPLMNs, servedGroupIDs, servedMMECs,
                //   iE-Extensions OPTIONAL, ... }
                encode_seq_preamble(encoder, &[false]);
                encoder
                    .encode_constrained_length(item.served_plmns.len(), 1, MAX_NO_OF_PLMNS_PER_MME)?;
                for plmn in &item.served_plmns {
                    encode_plmn(encoder, plmn)?;
                }
                encoder.encode_constrained_length(
                    item.served_group_ids.len(),
                    1,
                    MAX_NO_OF_GROUP_IDS,
                )?;
                for group_id in &item.served_group_ids {
                    encode_fixed_u16(encoder, *group_id)?;
                }
                encoder.encode_constrained_length(item.served_mmec_codes.len(), 1, MAX_NO_OF_MMECS)?;
                for mmec in &item.served_mmec_codes {
                    encoder.encode_octet_string(&[*mmec], Some(1), Some(1))?;
                }
            }
            Ok(())
        },
    )
}

pub fn decode_served_gummeis(field: &ProtocolIeField) -> S1apResult<Vec<ServedGummeiItem>> {
    let mut decoder = AperDecoder::new(&field.value);
    let count = decoder.decode_constrained_length(1, MAX_NO_OF_RATS)?;
    let mut gummeis = Vec::with_capacity(count);
    for _ in 0..count {
        let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
        let plmn_count = decoder.decode_constrained_length(1, MAX_NO_OF_PLMNS_PER_MME)?;
        let mut served_plmns = Vec::with_capacity(plmn_count);
        for _ in 0..plmn_count {
            served_plmns.push(decode_plmn(&mut decoder)?);
        }
        let group_count = decoder.decode_constrained_length(1, MAX_NO_OF_GROUP_IDS)?;
        let mut served_group_ids = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            served_group_ids.push(decode_fixed_u16(&mut decoder)?);
        }
        let mmec_count = decoder.decode_constrained_length(1, MAX_NO_OF_MMECS)?;
        let mut served_mmec_codes = Vec::with_capacity(mmec_count);
        for _ in 0..mmec_count {
            let bytes = decoder.decode_octet_string(Some(1), Some(1))?;
            served_mmec_codes.push(bytes[0]);
        }
        decode_seq_trailer(&mut decoder, ext, opts[0])?;
        gummeis.push(ServedGummeiItem {
            served_plmns,
            served_group_ids,
            served_mmec_codes,
        });
    }
    Ok(gummeis)
}

// ============================================================================
// Location / NAS transport IEs
// ============================================================================

pub fn encode_tai(
    container: &mut ProtocolIeContainer,
    tai: &Tai,
    criticality: Criticality,
) -> S1apResult<()> {
    push_ie(container, ProtocolIeId::TAI, criticality, |encoder| {
        encode_tai_inline(encoder, tai)
    })
}

pub fn decode_tai(field: &ProtocolIeField) -> S1apResult<Tai> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_tai_inline(&mut decoder)
}

pub fn encode_eutran_cgi(container: &mut ProtocolIeContainer, cgi: &EutranCgi) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::EUTRAN_CGI,
        Criticality::Ignore,
        |encoder| encode_eutran_cgi_inline(encoder, cgi),
    )
}

pub fn decode_eutran_cgi(field: &ProtocolIeField) -> S1apResult<EutranCgi> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_eutran_cgi_inline(&mut decoder)
}

pub fn encode_rrc_establishment_cause(
    container: &mut ProtocolIeContainer,
    cause: RrcEstablishmentCause,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::RRC_ESTABLISHMENT_CAUSE,
        Criticality::Ignore,
        |encoder| {
            encoder.encode_enumerated(cause as i64, &RRC_CAUSE_CONSTRAINT)?;
            Ok(())
        },
    )
}

pub fn decode_rrc_establishment_cause(
    field: &ProtocolIeField,
) -> S1apResult<RrcEstablishmentCause> {
    let mut decoder = AperDecoder::new(&field.value);
    let value = decoder.decode_enumerated(&RRC_CAUSE_CONSTRAINT)?;
    match value {
        0 => Ok(RrcEstablishmentCause::Emergency),
        1 => Ok(RrcEstablishmentCause::HighPriorityAccess),
        2 => Ok(RrcEstablishmentCause::MtAccess),
        3 => Ok(RrcEstablishmentCause::MoSignalling),
        4 => Ok(RrcEstablishmentCause::MoData),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "RRC-Establishment-Cause",
            reason: format!("unknown value {value}"),
        }),
    }
}

pub fn encode_s_tmsi(container: &mut ProtocolIeContainer, s_tmsi: &STmsi) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::S_TMSI,
        Criticality::Reject,
        |encoder| encode_s_tmsi_inline(encoder, s_tmsi),
    )
}

pub fn decode_s_tmsi(field: &ProtocolIeField) -> S1apResult<STmsi> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_s_tmsi_inline(&mut decoder)
}

// ============================================================================
// Context setup / security IEs
// ============================================================================

pub fn encode_ue_ambr(container: &mut ProtocolIeContainer, ambr: &UeAmbr) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE,
        Criticality::Reject,
        |encoder| {
            // UEAggregateMaximumBitrate ::= SEQUENCE { dL, uL, iE-Ext OPTIONAL, ... }
            encode_seq_preamble(encoder, &[false]);
            encoder.encode_constrained_whole_number(ambr.dl as i64, &BIT_RATE_CONSTRAINT)?;
            encoder.encode_constrained_whole_number(ambr.ul as i64, &BIT_RATE_CONSTRAINT)?;
            Ok(())
        },
    )
}

pub fn decode_ue_ambr(field: &ProtocolIeField) -> S1apResult<UeAmbr> {
    let mut decoder = AperDecoder::new(&field.value);
    let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
    let dl = decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
    let ul = decoder.decode_constrained_whole_number(&BIT_RATE_CONSTRAINT)? as u64;
    decode_seq_trailer(&mut decoder, ext, opts[0])?;
    Ok(UeAmbr { dl, ul })
}

pub fn encode_ue_security_capabilities(
    container: &mut ProtocolIeContainer,
    caps: &UeSecurityCapabilities,
    criticality: Criticality,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_SECURITY_CAPABILITIES,
        criticality,
        |encoder| encode_ue_security_capabilities_inline(encoder, caps),
    )
}

pub fn decode_ue_security_capabilities(
    field: &ProtocolIeField,
) -> S1apResult<UeSecurityCapabilities> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_ue_security_capabilities_inline(&mut decoder)
}

pub fn encode_security_key(container: &mut ProtocolIeContainer, key: &[u8; 32]) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::SECURITY_KEY,
        Criticality::Reject,
        |encoder| {
            encode_security_key_inline(encoder, key);
            Ok(())
        },
    )
}

pub fn decode_security_key(field: &ProtocolIeField) -> S1apResult<[u8; 32]> {
    let mut decoder = AperDecoder::new(&field.value);
    decode_security_key_inline(&mut decoder)
}

pub fn encode_security_context(
    container: &mut ProtocolIeContainer,
    context: &SecurityContext,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::SECURITY_CONTEXT,
        Criticality::Reject,
        |encoder| {
            // SecurityContext ::= SEQUENCE { nextHopChainingCount INTEGER(0..7),
            //   nextHopParameter SecurityKey, iE-Extensions OPTIONAL, ... }
            encode_seq_preamble(encoder, &[false]);
            encoder.encode_constrained_whole_number(
                context.next_hop_chaining_count as i64,
                &NEXT_HOP_CHAINING_COUNT_CONSTRAINT,
            )?;
            encode_security_key_inline(encoder, &context.next_hop_parameter);
            Ok(())
        },
    )
}

pub fn decode_security_context(field: &ProtocolIeField) -> S1apResult<SecurityContext> {
    let mut decoder = AperDecoder::new(&field.value);
    let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
    let next_hop_chaining_count =
        decoder.decode_constrained_whole_number(&NEXT_HOP_CHAINING_COUNT_CONSTRAINT)? as u8;
    let next_hop_parameter = decode_security_key_inline(&mut decoder)?;
    decode_seq_trailer(&mut decoder, ext, opts[0])?;
    Ok(SecurityContext {
        next_hop_chaining_count,
        next_hop_parameter,
    })
}

pub fn encode_ue_s1ap_ids(container: &mut ProtocolIeContainer, ids: &UeS1apIds) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_S1AP_IDS,
        Criticality::Reject,
        |encoder| {
            // UE-S1AP-IDs ::= CHOICE { uE-S1AP-ID-pair, mME-UE-S1AP-ID, ... }
            match ids {
                UeS1apIds::Pair {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                } => {
                    encoder.encode_choice_index(0, 2, true)?;
                    // UE-S1AP-ID-pair ::= SEQUENCE { mME, eNB, iE-Ext OPTIONAL, ... }
                    encode_seq_preamble(encoder, &[false]);
                    AsnMmeUeS1apId(*mme_ue_s1ap_id).encode_aper(encoder)?;
                    AsnEnbUeS1apId(*enb_ue_s1ap_id).encode_aper(encoder)?;
                }
                UeS1apIds::MmeOnly { mme_ue_s1ap_id } => {
                    encoder.encode_choice_index(1, 2, true)?;
                    AsnMmeUeS1apId(*mme_ue_s1ap_id).encode_aper(encoder)?;
                }
            }
            Ok(())
        },
    )
}

pub fn decode_ue_s1ap_ids(field: &ProtocolIeField) -> S1apResult<UeS1apIds> {
    let mut decoder = AperDecoder::new(&field.value);
    let index = decoder.decode_choice_index(2, true)?;
    match index {
        0 => {
            let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
            let mme_ue_s1ap_id = AsnMmeUeS1apId::decode_aper(&mut decoder)?.0;
            let enb_ue_s1ap_id = AsnEnbUeS1apId::decode_aper(&mut decoder)?.0;
            decode_seq_trailer(&mut decoder, ext, opts[0])?;
            Ok(UeS1apIds::Pair {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
            })
        }
        1 => Ok(UeS1apIds::MmeOnly {
            mme_ue_s1ap_id: AsnMmeUeS1apId::decode_aper(&mut decoder)?.0,
        }),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "UE-S1AP-IDs",
            reason: format!("unsupported choice index {index}"),
        }),
    }
}

pub fn encode_ue_radio_capability(
    container: &mut ProtocolIeContainer,
    capability: &[u8],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_RADIO_CAPABILITY,
        Criticality::Ignore,
        |encoder| {
            encoder.encode_octet_string(capability, None, None)?;
            Ok(())
        },
    )
}

pub fn decode_ue_radio_capability(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    let mut decoder = AperDecoder::new(&field.value);
    Ok(decoder.decode_octet_string(None, None)?)
}

// ============================================================================
// Paging IEs
// ============================================================================

pub fn encode_ue_identity_index(
    container: &mut ProtocolIeContainer,
    index: u16,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_IDENTITY_INDEX_VALUE,
        Criticality::Ignore,
        |encoder| {
            // UEIdentityIndexValue ::= BIT STRING (SIZE(10))
            encoder.write_bits((index & 0x03FF) as u64, 10);
            Ok(())
        },
    )
}

pub fn decode_ue_identity_index(field: &ProtocolIeField) -> S1apResult<u16> {
    let mut decoder = AperDecoder::new(&field.value);
    Ok(decoder.read_bits(10)? as u16)
}

pub fn encode_ue_paging_id(
    container: &mut ProtocolIeContainer,
    id: &UePagingId,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_PAGING_ID,
        Criticality::Ignore,
        |encoder| {
            // UEPagingID ::= CHOICE { s-TMSI, iMSI, ... }
            match id {
                UePagingId::STmsi(s_tmsi) => {
                    encoder.encode_choice_index(0, 2, true)?;
                    encode_s_tmsi_inline(encoder, s_tmsi)?;
                }
                UePagingId::Imsi(imsi) => {
                    encoder.encode_choice_index(1, 2, true)?;
                    // IMSI ::= OCTET STRING (SIZE(3..8))
                    encoder.encode_octet_string(imsi, Some(3), Some(8))?;
                }
            }
            Ok(())
        },
    )
}

pub fn decode_ue_paging_id(field: &ProtocolIeField) -> S1apResult<UePagingId> {
    let mut decoder = AperDecoder::new(&field.value);
    let index = decoder.decode_choice_index(2, true)?;
    match index {
        0 => Ok(UePagingId::STmsi(decode_s_tmsi_inline(&mut decoder)?)),
        1 => Ok(UePagingId::Imsi(
            decoder.decode_octet_string(Some(3), Some(8))?,
        )),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "UEPagingID",
            reason: format!("unsupported choice index {index}"),
        }),
    }
}

pub fn encode_cn_domain(container: &mut ProtocolIeContainer, domain: CnDomain) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::CN_DOMAIN,
        Criticality::Ignore,
        |encoder| {
            // CNDomain ::= ENUMERATED { ps, cs }
            encoder.encode_enumerated(domain as i64, &CN_DOMAIN_CONSTRAINT)?;
            Ok(())
        },
    )
}

pub fn decode_cn_domain(field: &ProtocolIeField) -> S1apResult<CnDomain> {
    let mut decoder = AperDecoder::new(&field.value);
    let value = decoder.decode_enumerated(&CN_DOMAIN_CONSTRAINT)?;
    match value {
        0 => Ok(CnDomain::Ps),
        1 => Ok(CnDomain::Cs),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "CNDomain",
            reason: format!("unknown value {value}"),
        }),
    }
}

pub fn encode_tai_list(container: &mut ProtocolIeContainer, tais: &[Tai]) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::TAI_LIST,
        Criticality::Ignore,
        |encoder| {
            // TAIList ::= SEQUENCE (SIZE(1..256)) OF ProtocolIE-SingleContainer { TAIItem }
            encoder.encode_constrained_length(tais.len(), 1, MAX_NO_OF_TAIS)?;
            for tai in tais {
                let mut item_encoder = AperEncoder::new();
                // TAIItem ::= SEQUENCE { tAI, iE-Extensions OPTIONAL, ... }
                encode_seq_preamble(&mut item_encoder, &[false]);
                encode_tai_inline(&mut item_encoder, tai)?;
                let field = ProtocolIeField {
                    id: ProtocolIeId::TAI_ITEM,
                    criticality: Criticality::Ignore,
                    value: finish_value(item_encoder),
                };
                field.encode_aper(encoder)?;
            }
            Ok(())
        },
    )
}

pub fn decode_tai_list(field: &ProtocolIeField) -> S1apResult<Vec<Tai>> {
    decode_single_container_list(field, ProtocolIeId::TAI_ITEM, |decoder| {
        let (ext, opts) = decode_seq_preamble(decoder, 1)?;
        let tai = decode_tai_inline(decoder)?;
        decode_seq_trailer(decoder, ext, opts[0])?;
        Ok(tai)
    })
}

// ============================================================================
// Reset IEs
// ============================================================================

pub fn encode_reset_type(
    container: &mut ProtocolIeContainer,
    reset_type: &ResetType,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::RESET_TYPE,
        Criticality::Reject,
        |encoder| {
            // ResetType ::= CHOICE { s1-Interface ResetAll, partOfS1-Interface, ... }
            match reset_type {
                ResetType::S1Interface => {
                    encoder.encode_choice_index(0, 2, true)?;
                    // ResetAll ::= ENUMERATED { reset-all, ... }
                    encoder.encode_enumerated(0, &RESET_ALL_CONSTRAINT)?;
                }
                ResetType::PartOfS1Interface(connections) => {
                    encoder.encode_choice_index(1, 2, true)?;
                    encoder.encode_constrained_length(
                        connections.len(),
                        1,
                        MAX_NO_OF_INDIVIDUAL_S1_CONNECTIONS_TO_RESET,
                    )?;
                    for connection in connections {
                        let mut item_encoder = AperEncoder::new();
                        encode_ue_connection_item(&mut item_encoder, connection)?;
                        let field = ProtocolIeField {
                            id: ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM,
                            criticality: Criticality::Reject,
                            value: finish_value(item_encoder),
                        };
                        field.encode_aper(encoder)?;
                    }
                }
            }
            Ok(())
        },
    )
}

pub fn decode_reset_type(field: &ProtocolIeField) -> S1apResult<ResetType> {
    let mut decoder = AperDecoder::new(&field.value);
    let index = decoder.decode_choice_index(2, true)?;
    match index {
        0 => {
            let _ = decoder.decode_enumerated(&RESET_ALL_CONSTRAINT)?;
            Ok(ResetType::S1Interface)
        }
        1 => {
            let count = decoder
                .decode_constrained_length(1, MAX_NO_OF_INDIVIDUAL_S1_CONNECTIONS_TO_RESET)?;
            let mut connections = Vec::with_capacity(count);
            for _ in 0..count {
                let item_field = ProtocolIeField::decode_aper(&mut decoder)?;
                if item_field.id != ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM {
                    return Err(S1apError::ProtocolError(format!(
                        "unexpected item IE id {} in ResetType",
                        item_field.id.0
                    )));
                }
                let mut item_decoder = AperDecoder::new(&item_field.value);
                connections.push(decode_ue_connection_item(&mut item_decoder)?);
            }
            Ok(ResetType::PartOfS1Interface(connections))
        }
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "ResetType",
            reason: format!("unsupported choice index {index}"),
        }),
    }
}

pub fn encode_ue_associated_connection_list_ack(
    container: &mut ProtocolIeContainer,
    connections: &[UeAssociatedLogicalS1Connection],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_LIST_RES_ACK,
        Criticality::Ignore,
        |encoder| {
            encoder.encode_constrained_length(
                connections.len(),
                1,
                MAX_NO_OF_INDIVIDUAL_S1_CONNECTIONS_TO_RESET,
            )?;
            for connection in connections {
                let mut item_encoder = AperEncoder::new();
                encode_ue_connection_item(&mut item_encoder, connection)?;
                let field = ProtocolIeField {
                    id: ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM,
                    criticality: Criticality::Ignore,
                    value: finish_value(item_encoder),
                };
                field.encode_aper(encoder)?;
            }
            Ok(())
        },
    )
}

pub fn decode_ue_associated_connection_list_ack(
    field: &ProtocolIeField,
) -> S1apResult<Vec<UeAssociatedLogicalS1Connection>> {
    decode_single_container_list(
        field,
        ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM,
        decode_ue_connection_item,
    )
}

// ============================================================================
// Handover IEs
// ============================================================================

pub fn encode_handover_type(
    container: &mut ProtocolIeContainer,
    handover_type: HandoverType,
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::HANDOVER_TYPE,
        Criticality::Reject,
        |encoder| {
            encoder.encode_enumerated(handover_type as i64, &HANDOVER_TYPE_CONSTRAINT)?;
            Ok(())
        },
    )
}

pub fn decode_handover_type(field: &ProtocolIeField) -> S1apResult<HandoverType> {
    let mut decoder = AperDecoder::new(&field.value);
    let value = decoder.decode_enumerated(&HANDOVER_TYPE_CONSTRAINT)?;
    match value {
        0 => Ok(HandoverType::IntraLte),
        1 => Ok(HandoverType::LteToUtran),
        2 => Ok(HandoverType::LteToGeran),
        3 => Ok(HandoverType::UtranToLte),
        4 => Ok(HandoverType::GeranToLte),
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "HandoverType",
            reason: format!("unknown value {value}"),
        }),
    }
}

pub fn encode_target_id(container: &mut ProtocolIeContainer, target: &TargetId) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::TARGET_ID,
        Criticality::Reject,
        |encoder| {
            // TargetID ::= CHOICE { targeteNB-ID, targetRNC-ID, cGI, ... }
            match target {
                TargetId::TargetEnbId {
                    global_enb_id,
                    selected_tai,
                } => {
                    encoder.encode_choice_index(0, 3, true)?;
                    // TargeteNB-ID ::= SEQUENCE { global-ENB-ID, selected-TAI, iE-Ext OPT, ... }
                    encode_seq_preamble(encoder, &[false]);
                    encode_global_enb_id_inline(encoder, global_enb_id)?;
                    encode_tai_inline(encoder, selected_tai)?;
                }
                TargetId::TargetRncId {
                    plmn_identity,
                    lac,
                    rac,
                    rnc_id,
                } => {
                    encoder.encode_choice_index(1, 3, true)?;
                    // TargetRNC-ID ::= SEQUENCE { lAI, rAC OPTIONAL, rNC-ID,
                    //   extendedRNC-ID OPTIONAL, iE-Extensions OPTIONAL, ... }
                    let extended = *rnc_id > 4095;
                    encode_seq_preamble(encoder, &[rac.is_some(), extended, false]);
                    // LAI ::= SEQUENCE { pLMNidentity, lAC, iE-Extensions OPTIONAL, ... }
                    encode_seq_preamble(encoder, &[false]);
                    encode_plmn(encoder, plmn_identity)?;
                    encode_fixed_u16(encoder, *lac)?;
                    if let Some(rac) = rac {
                        encoder.encode_octet_string(&[*rac], Some(1), Some(1))?;
                    }
                    let root_rnc_id = if extended { 4095 } else { *rnc_id };
                    encoder
                        .encode_constrained_whole_number(root_rnc_id as i64, &RNC_ID_CONSTRAINT)?;
                    if extended {
                        encoder.encode_constrained_whole_number(
                            *rnc_id as i64,
                            &EXTENDED_RNC_ID_CONSTRAINT,
                        )?;
                    }
                }
                TargetId::Cgi {
                    plmn_identity,
                    lac,
                    ci,
                    rac,
                } => {
                    encoder.encode_choice_index(2, 3, true)?;
                    // CGI ::= SEQUENCE { pLMNidentity, lAC, cI, rAC OPTIONAL, iE-Ext OPT, ... }
                    encode_seq_preamble(encoder, &[rac.is_some(), false]);
                    encode_plmn(encoder, plmn_identity)?;
                    encode_fixed_u16(encoder, *lac)?;
                    encode_fixed_u16(encoder, *ci)?;
                    if let Some(rac) = rac {
                        encoder.encode_octet_string(&[*rac], Some(1), Some(1))?;
                    }
                }
            }
            Ok(())
        },
    )
}

pub fn decode_target_id(field: &ProtocolIeField) -> S1apResult<TargetId> {
    let mut decoder = AperDecoder::new(&field.value);
    let index = decoder.decode_choice_index(3, true)?;
    match index {
        0 => {
            let (ext, opts) = decode_seq_preamble(&mut decoder, 1)?;
            let global_enb_id = decode_global_enb_id_inline(&mut decoder)?;
            let selected_tai = decode_tai_inline(&mut decoder)?;
            decode_seq_trailer(&mut decoder, ext, opts[0])?;
            Ok(TargetId::TargetEnbId {
                global_enb_id,
                selected_tai,
            })
        }
        1 => {
            let (ext, opts) = decode_seq_preamble(&mut decoder, 3)?;
            let (lai_ext, lai_opts) = decode_seq_preamble(&mut decoder, 1)?;
            let plmn_identity = decode_plmn(&mut decoder)?;
            let lac = decode_fixed_u16(&mut decoder)?;
            decode_seq_trailer(&mut decoder, lai_ext, lai_opts[0])?;
            let rac = if opts[0] {
                let bytes = decoder.decode_octet_string(Some(1), Some(1))?;
                Some(bytes[0])
            } else {
                None
            };
            let mut rnc_id = decoder.decode_constrained_whole_number(&RNC_ID_CONSTRAINT)? as u16;
            if opts[1] {
                rnc_id =
                    decoder.decode_constrained_whole_number(&EXTENDED_RNC_ID_CONSTRAINT)? as u16;
            }
            decode_seq_trailer(&mut decoder, ext, opts[2])?;
            Ok(TargetId::TargetRncId {
                plmn_identity,
                lac,
                rac,
                rnc_id,
            })
        }
        2 => {
            let (ext, opts) = decode_seq_preamble(&mut decoder, 2)?;
            let plmn_identity = decode_plmn(&mut decoder)?;
            let lac = decode_fixed_u16(&mut decoder)?;
            let ci = decode_fixed_u16(&mut decoder)?;
            let rac = if opts[0] {
                let bytes = decoder.decode_octet_string(Some(1), Some(1))?;
                Some(bytes[0])
            } else {
                None
            };
            decode_seq_trailer(&mut decoder, ext, opts[1])?;
            Ok(TargetId::Cgi {
                plmn_identity,
                lac,
                ci,
                rac,
            })
        }
        _ => Err(S1apError::InvalidIeValue {
            ie_name: "TargetID",
            reason: format!("unsupported choice index {index}"),
        }),
    }
}

pub fn encode_source_to_target_container(
    container: &mut ProtocolIeContainer,
    data: &[u8],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
        Criticality::Reject,
        |encoder| {
            encoder.encode_octet_string(data, None, None)?;
            Ok(())
        },
    )
}

pub fn decode_source_to_target_container(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    let mut decoder = AperDecoder::new(&field.value);
    Ok(decoder.decode_octet_string(None, None)?)
}

pub fn encode_target_to_source_container(
    container: &mut ProtocolIeContainer,
    data: &[u8],
) -> S1apResult<()> {
    push_ie(
        container,
        ProtocolIeId::TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
        Criticality::Reject,
        |encoder| {
            encoder.encode_octet_string(data, None, None)?;
            Ok(())
        },
    )
}

pub fn decode_target_to_source_container(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    let mut decoder = AperDecoder::new(&field.value);
    Ok(decoder.decode_octet_string(None, None)?)
}

// ============================================================================
// E-RAB list IEs
// ============================================================================

pub fn encode_erab_to_be_setup_list_ctxt(
    container: &mut ProtocolIeContainer,
    items: &[ErabToBeSetupItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ,
        Criticality::Reject,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ,
        Criticality::Reject,
        items,
        encode_erab_to_be_setup_item_ctxt,
    )
}

pub fn decode_erab_to_be_setup_list_ctxt(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabToBeSetupItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ,
        decode_erab_to_be_setup_item_ctxt,
    )
}

pub fn encode_erab_setup_list_ctxt_res(
    container: &mut ProtocolIeContainer,
    items: &[ErabSetupItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_SETUP_LIST_CTXT_SU_RES,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_SETUP_ITEM_CTXT_SU_RES,
        Criticality::Ignore,
        items,
        |encoder, item| {
            encode_erab_setup_shape_item(
                encoder,
                item.erab_id,
                &item.transport_layer_address,
                item.gtp_teid,
            )
        },
    )
}

pub fn decode_erab_setup_list_ctxt_res(field: &ProtocolIeField) -> S1apResult<Vec<ErabSetupItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_SETUP_ITEM_CTXT_SU_RES,
        |decoder| {
            let (erab_id, transport_layer_address, gtp_teid) =
                decode_erab_setup_shape_item(decoder)?;
            Ok(ErabSetupItem {
                erab_id,
                transport_layer_address,
                gtp_teid,
            })
        },
    )
}

pub fn encode_erab_to_be_setup_list_bearer(
    container: &mut ProtocolIeContainer,
    items: &[ErabToBeSetupItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ,
        Criticality::Reject,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ,
        Criticality::Reject,
        items,
        encode_erab_to_be_setup_item_bearer,
    )
}

pub fn decode_erab_to_be_setup_list_bearer(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabToBeSetupItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ,
        decode_erab_to_be_setup_item_bearer,
    )
}

pub fn encode_erab_setup_list_bearer_res(
    container: &mut ProtocolIeContainer,
    items: &[ErabSetupItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_SETUP_LIST_BEARER_SU_RES,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_SETUP_ITEM_BEARER_SU_RES,
        Criticality::Ignore,
        items,
        |encoder, item| {
            encode_erab_setup_shape_item(
                encoder,
                item.erab_id,
                &item.transport_layer_address,
                item.gtp_teid,
            )
        },
    )
}

pub fn decode_erab_setup_list_bearer_res(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabSetupItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_SETUP_ITEM_BEARER_SU_RES,
        |decoder| {
            let (erab_id, transport_layer_address, gtp_teid) =
                decode_erab_setup_shape_item(decoder)?;
            Ok(ErabSetupItem {
                erab_id,
                transport_layer_address,
                gtp_teid,
            })
        },
    )
}

pub fn encode_erab_to_be_modified_list(
    container: &mut ProtocolIeContainer,
    items: &[ErabToBeModifiedItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ,
        Criticality::Reject,
        ProtocolIeId::E_RAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ,
        Criticality::Reject,
        items,
        encode_erab_to_be_modified_item,
    )
}

pub fn decode_erab_to_be_modified_list(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabToBeModifiedItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ,
        decode_erab_to_be_modified_item,
    )
}

pub fn encode_erab_modify_list_res(
    container: &mut ProtocolIeContainer,
    erab_ids: &[u8],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_MODIFY_LIST_BEARER_MOD_RES,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_MODIFY_ITEM_BEARER_MOD_RES,
        Criticality::Ignore,
        erab_ids,
        |encoder, erab_id| encode_erab_id_only_item(encoder, *erab_id),
    )
}

pub fn decode_erab_modify_list_res(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_MODIFY_ITEM_BEARER_MOD_RES,
        decode_erab_id_only_item,
    )
}

pub fn encode_erab_release_list_rel_comp(
    container: &mut ProtocolIeContainer,
    erab_ids: &[u8],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_RELEASE_LIST_BEARER_REL_COMP,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_RELEASE_ITEM_BEARER_REL_COMP,
        Criticality::Ignore,
        erab_ids,
        |encoder, erab_id| encode_erab_id_only_item(encoder, *erab_id),
    )
}

pub fn decode_erab_release_list_rel_comp(field: &ProtocolIeField) -> S1apResult<Vec<u8>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_RELEASE_ITEM_BEARER_REL_COMP,
        decode_erab_id_only_item,
    )
}

/// Encode a generic E-RAB-List (items are E-RABItem { e-RAB-ID, cause }) under
/// the given list IE id. Used by failed-to-setup/modify/release lists and the
/// E-RABToBeReleasedList / E-RABtoReleaseListHOCmd.
pub fn encode_erab_item_list(
    container: &mut ProtocolIeContainer,
    list_id: ProtocolIeId,
    list_criticality: Criticality,
    items: &[(u8, Cause)],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        list_id,
        list_criticality,
        ProtocolIeId::E_RAB_ITEM,
        Criticality::Ignore,
        items,
        |encoder, (erab_id, cause)| encode_erab_item(encoder, *erab_id, cause),
    )
}

pub fn decode_erab_item_list(field: &ProtocolIeField) -> S1apResult<Vec<(u8, Cause)>> {
    decode_single_container_list(field, ProtocolIeId::E_RAB_ITEM, decode_erab_item)
}

pub fn encode_erab_to_be_setup_list_ho_req(
    container: &mut ProtocolIeContainer,
    items: &[ErabToBeSetupItemHoReq],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_HO_REQ,
        Criticality::Reject,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_HO_REQ,
        Criticality::Reject,
        items,
        encode_erab_to_be_setup_item_ho_req,
    )
}

pub fn decode_erab_to_be_setup_list_ho_req(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabToBeSetupItemHoReq>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_SETUP_ITEM_HO_REQ,
        decode_erab_to_be_setup_item_ho_req,
    )
}

pub fn encode_erab_admitted_list(
    container: &mut ProtocolIeContainer,
    items: &[ErabAdmittedItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_ADMITTED_LIST,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_ADMITTED_ITEM,
        Criticality::Ignore,
        items,
        encode_erab_admitted_item,
    )
}

pub fn decode_erab_admitted_list(field: &ProtocolIeField) -> S1apResult<Vec<ErabAdmittedItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_ADMITTED_ITEM,
        decode_erab_admitted_item,
    )
}

pub fn encode_erab_failed_to_setup_list_ho_req_ack(
    container: &mut ProtocolIeContainer,
    items: &[(u8, Cause)],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK,
        Criticality::Ignore,
        items,
        |encoder, (erab_id, cause)| encode_erab_item(encoder, *erab_id, cause),
    )
}

pub fn decode_erab_failed_to_setup_list_ho_req_ack(
    field: &ProtocolIeField,
) -> S1apResult<Vec<(u8, Cause)>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK,
        decode_erab_item,
    )
}

pub fn encode_erab_switched_dl_list(
    container: &mut ProtocolIeContainer,
    items: &[ErabSwitchedItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_DL_LIST,
        Criticality::Reject,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_DL_ITEM,
        Criticality::Reject,
        items,
        |encoder, item| {
            encode_erab_setup_shape_item(
                encoder,
                item.erab_id,
                &item.transport_layer_address,
                item.gtp_teid,
            )
        },
    )
}

pub fn decode_erab_switched_dl_list(field: &ProtocolIeField) -> S1apResult<Vec<ErabSwitchedItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_DL_ITEM,
        |decoder| {
            let (erab_id, transport_layer_address, gtp_teid) =
                decode_erab_setup_shape_item(decoder)?;
            Ok(ErabSwitchedItem {
                erab_id,
                transport_layer_address,
                gtp_teid,
            })
        },
    )
}

pub fn encode_erab_switched_ul_list(
    container: &mut ProtocolIeContainer,
    items: &[ErabSwitchedItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_UL_LIST,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_UL_ITEM,
        Criticality::Ignore,
        items,
        |encoder, item| {
            encode_erab_setup_shape_item(
                encoder,
                item.erab_id,
                &item.transport_layer_address,
                item.gtp_teid,
            )
        },
    )
}

pub fn decode_erab_switched_ul_list(field: &ProtocolIeField) -> S1apResult<Vec<ErabSwitchedItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_TO_BE_SWITCHED_UL_ITEM,
        |decoder| {
            let (erab_id, transport_layer_address, gtp_teid) =
                decode_erab_setup_shape_item(decoder)?;
            Ok(ErabSwitchedItem {
                erab_id,
                transport_layer_address,
                gtp_teid,
            })
        },
    )
}

pub fn encode_erab_data_forwarding_list(
    container: &mut ProtocolIeContainer,
    items: &[ErabDataForwardingItem],
) -> S1apResult<()> {
    push_single_container_list(
        container,
        ProtocolIeId::E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST,
        Criticality::Ignore,
        ProtocolIeId::E_RAB_DATA_FORWARDING_ITEM,
        Criticality::Ignore,
        items,
        encode_erab_data_forwarding_item,
    )
}

pub fn decode_erab_data_forwarding_list(
    field: &ProtocolIeField,
) -> S1apResult<Vec<ErabDataForwardingItem>> {
    decode_single_container_list(
        field,
        ProtocolIeId::E_RAB_DATA_FORWARDING_ITEM,
        decode_erab_data_forwarding_item,
    )
}
