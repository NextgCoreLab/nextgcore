//! N2 SM Information Transfer IEs (TS 38.413 Section 9.3.4)
//!
//! APER encode/decode for the transfer containers carried opaquely inside
//! PDU Session Resource procedures and exchanged with the SMF as N2 SM
//! information (`n2SmInfo` in Nsmf_PDUSession). The AMF forwards these as
//! OCTET STRING payloads; this module gives producers/consumers (amfd,
//! smfd, gNB simulators) a real codec instead of bespoke byte layouts.
//!
//! Implemented (Rel-15 shapes):
//! - `PduSessionResourceSetupRequestTransfer` / `...SetupResponseTransfer`
//! - `PduSessionResourceModifyRequestTransfer` / `...ModifyResponseTransfer`
//! - `PduSessionResourceReleaseCommandTransfer` / `...ReleaseResponseTransfer`

use nextgcore_asn1c::ngap::cause::Cause;
use nextgcore_asn1c::ngap::ies::{ProtocolIeContainer, ProtocolIeField};
use nextgcore_asn1c::ngap::types::{Criticality, ProtocolIeId};
use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint};

use crate::error::{NgapError, NgapResult};

// Transfer-container ProtocolIE IDs (TS 38.413 Section 9.4)
const IE_ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE: u16 = 130;
const IE_ID_UL_NGU_UP_TNL_INFORMATION: u16 = 139;
/// AdditionalUL-NGU-UP-TNLInformation (TS 38.413 §9.3.4.1, Rel-15 multi-
/// connectivity, criticality reject). NGAP-07.
const IE_ID_ADDITIONAL_UL_NGU_UP_TNL_INFORMATION: u16 = 126;
const IE_ID_DATA_FORWARDING_NOT_POSSIBLE: u16 = 127;
const IE_ID_PDU_SESSION_TYPE: u16 = 134;
const IE_ID_SECURITY_INDICATION: u16 = 138;
const IE_ID_NETWORK_INSTANCE: u16 = 129;
const IE_ID_QOS_FLOW_SETUP_REQUEST_LIST: u16 = 136;
/// id-DirectForwardingPathAvailability (TS 38.413 §9.4); criticality `ignore` in
/// `PDUSessionResourceSetupRequestTransferIEs`.
const IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY: u16 = 22;
const IE_ID_UL_NGU_UP_TNL_MODIFY_LIST: u16 = 140;
const IE_ID_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST: u16 = 135;
const IE_ID_QOS_FLOW_TO_RELEASE_LIST: u16 = 137;

// BitRate ::= INTEGER (0..4000000000000, ...)
const BIT_RATE_MAX: i64 = 4_000_000_000_000;

// ============================================================================
// Shared primitive helpers
// ============================================================================

/// Encode an extensible constrained INTEGER (extension bit + root encoding)
pub(crate) fn encode_ext_constrained(
    encoder: &mut AperEncoder,
    value: i64,
    min: i64,
    max: i64,
) -> NgapResult<()> {
    encoder.write_bit(false);
    let constraint = Constraint::new(min, max);
    encoder.encode_constrained_whole_number(value, &constraint)?;
    Ok(())
}

/// Decode an extensible constrained INTEGER
pub(crate) fn decode_ext_constrained(
    decoder: &mut AperDecoder,
    min: i64,
    max: i64,
) -> NgapResult<i64> {
    let extended = decoder.read_bit()?;
    if extended {
        // Extension values are encoded as an unconstrained whole number
        Ok(decoder.decode_unconstrained_whole_number()?)
    } else {
        let constraint = Constraint::new(min, max);
        Ok(decoder.decode_constrained_whole_number(&constraint)?)
    }
}

fn encode_bit_rate(encoder: &mut AperEncoder, value: u64) -> NgapResult<()> {
    encode_ext_constrained(encoder, value as i64, 0, BIT_RATE_MAX)
}

fn decode_bit_rate(decoder: &mut AperDecoder) -> NgapResult<u64> {
    Ok(decode_ext_constrained(decoder, 0, BIT_RATE_MAX)? as u64)
}

pub(crate) fn invalid(ie_name: &'static str, reason: String) -> NgapError {
    NgapError::InvalidIeValue { ie_name, reason }
}

// ============================================================================
// Extension handling, shared with mbs_transfer.rs
// ============================================================================

/// maxProtocolExtensions INTEGER ::= 65535 (NGAP-Containers)
pub(crate) const MAX_PROTOCOL_EXTENSIONS: usize = 65535;

/// Skip the extension additions of an extensible SEQUENCE whose extension bit
/// was set (X.691 §18.8/§18.9): a normally-small length holding the number of
/// additions minus 1, an n-bit presence bitmap, then each present addition
/// wrapped as an open type. Truncation anywhere inside is an error
/// (fail-closed); the addition *content* is version-bracket data and is
/// skippable by definition.
pub(crate) fn skip_extension_additions(decoder: &mut AperDecoder) -> NgapResult<()> {
    let count = decoder.decode_normally_small_non_negative()? as usize + 1;
    let mut present = Vec::with_capacity(count);
    for _ in 0..count {
        present.push(decoder.read_bit()?);
    }
    for is_present in present {
        if is_present {
            loop {
                let (len, fragmented) = decoder.decode_length_fragment()?;
                let _skipped = decoder.read_bytes(len)?;
                if !fragmented {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Encode a `ProtocolExtensionContainer {{...}}`:
/// `SEQUENCE (SIZE(1..maxProtocolExtensions)) OF ProtocolExtensionField`
/// where `ProtocolExtensionField ::= SEQUENCE { id, criticality,
/// extensionValue }` shares its wire shape with ProtocolIE-Field.
pub(crate) fn encode_extension_container(
    encoder: &mut AperEncoder,
    fields: &[ProtocolIeField],
) -> NgapResult<()> {
    encoder.encode_constrained_length(fields.len(), 1, MAX_PROTOCOL_EXTENSIONS)?;
    for field in fields {
        field.encode_aper(encoder)?;
    }
    Ok(())
}

/// Decode a `ProtocolExtensionContainer` into its raw fields.
pub(crate) fn decode_extension_container(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<ProtocolIeField>> {
    let count = decoder.decode_constrained_length(1, MAX_PROTOCOL_EXTENSIONS)?;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(ProtocolIeField::decode_aper(decoder)?);
    }
    Ok(fields)
}

/// Decode an iE-Extensions container in which no extension IE is
/// comprehended: unknown ignore/notify extensions are skipped, unknown
/// reject extensions fail the decode (TS 38.413 §10.3.4).
pub(crate) fn decode_unknown_extensions_only(decoder: &mut AperDecoder) -> NgapResult<()> {
    for field in decode_extension_container(decoder)? {
        crate::ie::handle_unknown_ie(&field)?;
    }
    Ok(())
}

/// Finish decoding an extensible SEQUENCE once its root members are read
/// (X.691 §19.6, §19.7): the optional `iE-Extensions` container is the last
/// root member, and extension additions follow the root when the extension
/// bit was set. Neither may be left unread, or every member after this
/// SEQUENCE is decoded from the wrong bits (#469).
pub(crate) fn finish_extensible_sequence(
    decoder: &mut AperDecoder,
    extended: bool,
    ie_extensions_present: bool,
) -> NgapResult<()> {
    if ie_extensions_present {
        decode_unknown_extensions_only(decoder)?;
    }
    if extended {
        skip_extension_additions(decoder)?;
    }
    Ok(())
}

// ============================================================================
// Transport layer types
// ============================================================================

/// TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportLayerAddress {
    /// Address bits, MSB-aligned in `octets`
    pub octets: Vec<u8>,
    /// Number of significant bits (32 for IPv4, 128 for IPv6)
    pub bit_len: usize,
}

impl TransportLayerAddress {
    pub fn from_ipv4(addr: [u8; 4]) -> Self {
        Self {
            octets: addr.to_vec(),
            bit_len: 32,
        }
    }

    pub fn from_ipv6(addr: [u8; 16]) -> Self {
        Self {
            octets: addr.to_vec(),
            bit_len: 128,
        }
    }

    pub(crate) fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        if self.bit_len == 0 || self.bit_len > 160 || self.octets.len() != self.bit_len.div_ceil(8)
        {
            return Err(invalid(
                "TransportLayerAddress",
                format!(
                    "Invalid bit length {} for {} octets",
                    self.bit_len,
                    self.octets.len()
                ),
            ));
        }
        encoder.write_bit(false); // extension bit
        encoder.encode_constrained_length(self.bit_len, 1, 160)?;
        encoder.align(); // BIT STRING with max > 16 is octet-aligned
        let full_bytes = self.bit_len / 8;
        for byte in &self.octets[..full_bytes] {
            encoder.write_bits(*byte as u64, 8);
        }
        let rem = self.bit_len % 8;
        if rem != 0 {
            encoder.write_bits((self.octets[full_bytes] >> (8 - rem)) as u64, rem);
        }
        Ok(())
    }

    pub(crate) fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let extended = decoder.read_bit()?;
        if extended {
            return Err(invalid(
                "TransportLayerAddress",
                "Extension values beyond 160 bits are not supported".to_string(),
            ));
        }
        let bit_len = decoder.decode_constrained_length(1, 160)?;
        decoder.align();
        let full_bytes = bit_len / 8;
        let mut octets = Vec::with_capacity(bit_len.div_ceil(8));
        for _ in 0..full_bytes {
            octets.push(decoder.read_bits(8)? as u8);
        }
        let rem = bit_len % 8;
        if rem != 0 {
            octets.push((decoder.read_bits(rem)? as u8) << (8 - rem));
        }
        Ok(Self { octets, bit_len })
    }
}

/// GTPTunnel ::= SEQUENCE { transportLayerAddress, gTP-TEID, iE-Extensions OPTIONAL }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpTunnel {
    pub transport_layer_address: TransportLayerAddress,
    pub gtp_teid: [u8; 4],
}

/// UPTransportLayerInformation ::= CHOICE { gTPTunnel, choice-Extensions }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpTransportLayerInformation {
    GtpTunnel(GtpTunnel),
}

impl UpTransportLayerInformation {
    pub(crate) fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        match self {
            UpTransportLayerInformation::GtpTunnel(tunnel) => {
                encoder.encode_choice_index(0, 2, false)?;
                encoder.write_bit(false); // extension
                encoder.write_bit(false); // no iE-Extensions
                tunnel.transport_layer_address.encode(encoder)?;
                encoder.encode_octet_string(&tunnel.gtp_teid, Some(4), Some(4))?;
                Ok(())
            }
        }
    }

    pub(crate) fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let choice = decoder.decode_choice_index(2, false)?;
        if choice != 0 {
            return Err(invalid(
                "UPTransportLayerInformation",
                format!("Unsupported choice index: {choice}"),
            ));
        }
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let transport_layer_address = TransportLayerAddress::decode(decoder)?;
        let teid_bytes = decoder.decode_octet_string(Some(4), Some(4))?;
        let mut gtp_teid = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_bytes);
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address,
            gtp_teid,
        }))
    }
}

/// Decode an `AdditionalUL-NGU-UP-TNLInformation` (NGAP-07).
///
/// `AdditionalUL-NGU-UP-TNLInformation ::= UPTransportLayerInformationList`,
/// `UPTransportLayerInformationList ::= SEQUENCE (SIZE(1..maxnoofMultiConnectivityMinusOne=3))
/// OF UPTransportLayerInformationItem`, where each item is the extensible
/// `SEQUENCE { nGU-UP-TNLInformation UPTransportLayerInformation, iE-Extensions OPTIONAL, ... }`
/// (TS 38.413 §9.3.4.1, Rel-15 multi-connectivity). Returning the endpoints lets
/// a caller validate a conformant peer's transfer instead of treating this known
/// optional reject-criticality IE as not-comprehended.
fn decode_additional_ul_ngu_up_tnl_information(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<UpTransportLayerInformation>> {
    let count = decoder.decode_constrained_length(1, 3)?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        list.push(UpTransportLayerInformation::decode(decoder)?);
        finish_extensible_sequence(decoder, ext, ie_ext)?;
    }
    Ok(list)
}

// ============================================================================
// QoS types
// ============================================================================

/// MaximumDataBurstVolume ::= INTEGER (0..4095, ..., 4096..2000000)
/// (TS 38.413 §9.3.1.83). The extension range is not PER-visible, so a value
/// past the root is the extension bit followed by an unconstrained whole
/// number (X.691 §12.1, §12.2.6).
const MAX_DATA_BURST_VOLUME_ROOT: u32 = 4095;
const MAX_DATA_BURST_VOLUME: u32 = 2_000_000;

fn encode_maximum_data_burst_volume(encoder: &mut AperEncoder, value: u32) -> NgapResult<()> {
    if value <= MAX_DATA_BURST_VOLUME_ROOT {
        return encode_ext_constrained(encoder, i64::from(value), 0, 4095);
    }
    if value > MAX_DATA_BURST_VOLUME {
        return Err(invalid(
            "MaximumDataBurstVolume",
            format!("Value {value} outside 0..{MAX_DATA_BURST_VOLUME}"),
        ));
    }
    encoder.write_bit(true);
    encoder.encode_unconstrained_whole_number(i64::from(value))?;
    Ok(())
}

fn decode_maximum_data_burst_volume(decoder: &mut AperDecoder) -> NgapResult<u32> {
    let value = decode_ext_constrained(decoder, 0, 4095)?;
    u32::try_from(value)
        .ok()
        .filter(|v| *v <= MAX_DATA_BURST_VOLUME)
        .ok_or_else(|| {
            invalid(
                "MaximumDataBurstVolume",
                format!("Value {value} outside 0..{MAX_DATA_BURST_VOLUME}"),
            )
        })
}

/// NonDynamic5QIDescriptor (TS 38.413 Section 9.3.1.28)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonDynamic5qiDescriptor {
    /// 5QI value (0..255)
    pub five_qi: u16,
    /// Priority Level QoS (1..127, optional)
    pub priority_level_qos: Option<u8>,
    /// Averaging Window in ms (0..4095, optional)
    pub averaging_window: Option<u16>,
    /// Maximum Data Burst Volume in bytes (0..4095, extension 4096..2000000, optional)
    pub maximum_data_burst_volume: Option<u32>,
}

impl NonDynamic5qiDescriptor {
    pub fn new(five_qi: u16) -> Self {
        Self {
            five_qi,
            priority_level_qos: None,
            averaging_window: None,
            maximum_data_burst_volume: None,
        }
    }

    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.priority_level_qos.is_some());
        encoder.write_bit(self.averaging_window.is_some());
        encoder.write_bit(self.maximum_data_burst_volume.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_ext_constrained(encoder, self.five_qi as i64, 0, 255)?;
        if let Some(p) = self.priority_level_qos {
            encode_ext_constrained(encoder, p as i64, 1, 127)?;
        }
        if let Some(w) = self.averaging_window {
            encode_ext_constrained(encoder, w as i64, 0, 4095)?;
        }
        if let Some(v) = self.maximum_data_burst_volume {
            encode_maximum_data_burst_volume(encoder, v)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let prio_present = decoder.read_bit()?;
        let avg_present = decoder.read_bit()?;
        let burst_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let five_qi = decode_ext_constrained(decoder, 0, 255)? as u16;
        let priority_level_qos = if prio_present {
            Some(decode_ext_constrained(decoder, 1, 127)? as u8)
        } else {
            None
        };
        let averaging_window = if avg_present {
            Some(decode_ext_constrained(decoder, 0, 4095)? as u16)
        } else {
            None
        };
        let maximum_data_burst_volume = if burst_present {
            Some(decode_maximum_data_burst_volume(decoder)?)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            five_qi,
            priority_level_qos,
            averaging_window,
            maximum_data_burst_volume,
        })
    }
}

/// DelayCritical ::= ENUMERATED { delay-critical, non-delay-critical, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DelayCritical {
    DelayCritical = 0,
    NonDelayCritical = 1,
}

/// Dynamic5QIDescriptor (TS 38.413 Section 9.3.1.18)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamic5qiDescriptor {
    /// Priority Level QoS (1..127)
    pub priority_level_qos: u8,
    /// Packet Delay Budget in 0.5ms units (0..1023)
    pub packet_delay_budget: u16,
    /// Packet Error Rate scalar (0..9)
    pub per_scalar: u8,
    /// Packet Error Rate exponent (0..9)
    pub per_exponent: u8,
    /// 5QI (optional)
    pub five_qi: Option<u16>,
    /// Delay Critical (conditional, present for GBR flows)
    pub delay_critical: Option<DelayCritical>,
    /// Averaging Window (conditional)
    pub averaging_window: Option<u16>,
    /// Maximum Data Burst Volume in bytes (0..4095, extension 4096..2000000, conditional)
    pub maximum_data_burst_volume: Option<u32>,
}

impl Dynamic5qiDescriptor {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.five_qi.is_some());
        encoder.write_bit(self.delay_critical.is_some());
        encoder.write_bit(self.averaging_window.is_some());
        encoder.write_bit(self.maximum_data_burst_volume.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_ext_constrained(encoder, self.priority_level_qos as i64, 1, 127)?;
        encode_ext_constrained(encoder, self.packet_delay_budget as i64, 0, 1023)?;
        // PacketErrorRate ::= SEQUENCE { pERScalar, pERExponent, iE-Extensions OPTIONAL }
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encode_ext_constrained(encoder, self.per_scalar as i64, 0, 9)?;
        encode_ext_constrained(encoder, self.per_exponent as i64, 0, 9)?;
        if let Some(q) = self.five_qi {
            encode_ext_constrained(encoder, q as i64, 0, 255)?;
        }
        if let Some(dc) = self.delay_critical {
            let constraint = Constraint::extensible(0, 1);
            encoder.encode_enumerated(dc as i64, &constraint)?;
        }
        if let Some(w) = self.averaging_window {
            encode_ext_constrained(encoder, w as i64, 0, 4095)?;
        }
        if let Some(v) = self.maximum_data_burst_volume {
            encode_maximum_data_burst_volume(encoder, v)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let five_qi_present = decoder.read_bit()?;
        let dc_present = decoder.read_bit()?;
        let avg_present = decoder.read_bit()?;
        let burst_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let priority_level_qos = decode_ext_constrained(decoder, 1, 127)? as u8;
        let packet_delay_budget = decode_ext_constrained(decoder, 0, 1023)? as u16;
        let per_ext = decoder.read_bit()?;
        let per_ie_ext = decoder.read_bit()?;
        let per_scalar = decode_ext_constrained(decoder, 0, 9)? as u8;
        let per_exponent = decode_ext_constrained(decoder, 0, 9)? as u8;
        finish_extensible_sequence(decoder, per_ext, per_ie_ext)?;
        let five_qi = if five_qi_present {
            Some(decode_ext_constrained(decoder, 0, 255)? as u16)
        } else {
            None
        };
        let delay_critical = if dc_present {
            let constraint = Constraint::extensible(0, 1);
            match decoder.decode_enumerated(&constraint)? {
                0 => Some(DelayCritical::DelayCritical),
                1 => Some(DelayCritical::NonDelayCritical),
                v => return Err(invalid("DelayCritical", format!("Unknown value: {v}"))),
            }
        } else {
            None
        };
        let averaging_window = if avg_present {
            Some(decode_ext_constrained(decoder, 0, 4095)? as u16)
        } else {
            None
        };
        let maximum_data_burst_volume = if burst_present {
            Some(decode_maximum_data_burst_volume(decoder)?)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            priority_level_qos,
            packet_delay_budget,
            per_scalar,
            per_exponent,
            five_qi,
            delay_critical,
            averaging_window,
            maximum_data_burst_volume,
        })
    }
}

/// QosCharacteristics ::= CHOICE { nonDynamic5QI, dynamic5QI, choice-Extensions }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QosCharacteristics {
    NonDynamic5qi(NonDynamic5qiDescriptor),
    Dynamic5qi(Dynamic5qiDescriptor),
}

impl QosCharacteristics {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        match self {
            QosCharacteristics::NonDynamic5qi(desc) => {
                encoder.encode_choice_index(0, 3, false)?;
                desc.encode(encoder)
            }
            QosCharacteristics::Dynamic5qi(desc) => {
                encoder.encode_choice_index(1, 3, false)?;
                desc.encode(encoder)
            }
        }
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let choice = decoder.decode_choice_index(3, false)?;
        match choice {
            0 => Ok(QosCharacteristics::NonDynamic5qi(
                NonDynamic5qiDescriptor::decode(decoder)?,
            )),
            1 => Ok(QosCharacteristics::Dynamic5qi(
                Dynamic5qiDescriptor::decode(decoder)?,
            )),
            _ => Err(invalid(
                "QosCharacteristics",
                format!("Unsupported choice index: {choice}"),
            )),
        }
    }
}

/// Pre-emptionCapability ::= ENUMERATED (non-extensible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PreEmptionCapability {
    ShallNotTriggerPreEmption = 0,
    MayTriggerPreEmption = 1,
}

/// Pre-emptionVulnerability ::= ENUMERATED (non-extensible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PreEmptionVulnerability {
    NotPreEmptable = 0,
    PreEmptable = 1,
}

/// AllocationAndRetentionPriority (TS 38.413 Section 9.3.1.19)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationAndRetentionPriority {
    /// Priority Level ARP (1..15)
    pub priority_level_arp: u8,
    pub pre_emption_capability: PreEmptionCapability,
    pub pre_emption_vulnerability: PreEmptionVulnerability,
}

impl AllocationAndRetentionPriority {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        let constraint = Constraint::new(1, 15);
        encoder.encode_constrained_whole_number(self.priority_level_arp as i64, &constraint)?;
        // Pre-emptionCapability / Pre-emptionVulnerability ::= ENUMERATED { ..., ... }
        // are extensible (TS 38.413 §9.3.1.19): each carries an extension marker.
        let two = Constraint::extensible(0, 1);
        encoder.encode_enumerated(self.pre_emption_capability as i64, &two)?;
        encoder.encode_enumerated(self.pre_emption_vulnerability as i64, &two)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let constraint = Constraint::new(1, 15);
        let priority_level_arp = decoder.decode_constrained_whole_number(&constraint)? as u8;
        let two = Constraint::extensible(0, 1);
        let pre_emption_capability = match decoder.decode_enumerated(&two)? {
            0 => PreEmptionCapability::ShallNotTriggerPreEmption,
            _ => PreEmptionCapability::MayTriggerPreEmption,
        };
        let pre_emption_vulnerability = match decoder.decode_enumerated(&two)? {
            0 => PreEmptionVulnerability::NotPreEmptable,
            _ => PreEmptionVulnerability::PreEmptable,
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            priority_level_arp,
            pre_emption_capability,
            pre_emption_vulnerability,
        })
    }
}

/// GBR-QosInformation (TS 38.413 Section 9.3.1.20)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbrQosInformation {
    pub maximum_flow_bit_rate_dl: u64,
    pub maximum_flow_bit_rate_ul: u64,
    pub guaranteed_flow_bit_rate_dl: u64,
    pub guaranteed_flow_bit_rate_ul: u64,
    /// notificationControl ::= ENUMERATED { notification-requested, ... } (present if true)
    pub notification_control: bool,
    /// Maximum Packet Loss Rate DL in 0.1% units (0..1000, optional)
    pub maximum_packet_loss_rate_dl: Option<u16>,
    /// Maximum Packet Loss Rate UL in 0.1% units (0..1000, optional)
    pub maximum_packet_loss_rate_ul: Option<u16>,
}

impl GbrQosInformation {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.notification_control);
        encoder.write_bit(self.maximum_packet_loss_rate_dl.is_some());
        encoder.write_bit(self.maximum_packet_loss_rate_ul.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_bit_rate(encoder, self.maximum_flow_bit_rate_dl)?;
        encode_bit_rate(encoder, self.maximum_flow_bit_rate_ul)?;
        encode_bit_rate(encoder, self.guaranteed_flow_bit_rate_dl)?;
        encode_bit_rate(encoder, self.guaranteed_flow_bit_rate_ul)?;
        if self.notification_control {
            let constraint = Constraint::extensible(0, 0);
            encoder.encode_enumerated(0, &constraint)?;
        }
        // PacketLossRate ::= INTEGER (0..1000, ...) -- extensible (§9.3.1.83), so
        // each value starts with its extension bit.
        if let Some(dl) = self.maximum_packet_loss_rate_dl {
            encode_ext_constrained(encoder, dl as i64, 0, 1000)?;
        }
        if let Some(ul) = self.maximum_packet_loss_rate_ul {
            encode_ext_constrained(encoder, ul as i64, 0, 1000)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let notif_present = decoder.read_bit()?;
        let dl_present = decoder.read_bit()?;
        let ul_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let maximum_flow_bit_rate_dl = decode_bit_rate(decoder)?;
        let maximum_flow_bit_rate_ul = decode_bit_rate(decoder)?;
        let guaranteed_flow_bit_rate_dl = decode_bit_rate(decoder)?;
        let guaranteed_flow_bit_rate_ul = decode_bit_rate(decoder)?;
        if notif_present {
            let constraint = Constraint::extensible(0, 0);
            let _notif = decoder.decode_enumerated(&constraint)?;
        }
        let maximum_packet_loss_rate_dl = if dl_present {
            Some(decode_packet_loss_rate(decoder)?)
        } else {
            None
        };
        let maximum_packet_loss_rate_ul = if ul_present {
            Some(decode_packet_loss_rate(decoder)?)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            maximum_flow_bit_rate_dl,
            maximum_flow_bit_rate_ul,
            guaranteed_flow_bit_rate_dl,
            guaranteed_flow_bit_rate_ul,
            notification_control: notif_present,
            maximum_packet_loss_rate_dl,
            maximum_packet_loss_rate_ul,
        })
    }
}

/// PacketLossRate ::= INTEGER (0..1000, ...). The extension range is empty in
/// TS 38.413, so a value past the root has no meaning here and is refused
/// rather than truncated into the `u16`.
fn decode_packet_loss_rate(decoder: &mut AperDecoder) -> NgapResult<u16> {
    let value = decode_ext_constrained(decoder, 0, 1000)?;
    u16::try_from(value)
        .ok()
        .filter(|v| *v <= 1000)
        .ok_or_else(|| invalid("PacketLossRate", format!("Value {value} outside 0..1000")))
}

/// QosFlowLevelQosParameters (TS 38.413 Section 9.3.1.12)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowLevelQosParameters {
    pub qos_characteristics: QosCharacteristics,
    pub allocation_and_retention_priority: AllocationAndRetentionPriority,
    pub gbr_qos_information: Option<GbrQosInformation>,
    /// reflectiveQosAttribute ::= ENUMERATED { subject-to, ... } (present if true)
    pub reflective_qos_attribute: bool,
    /// additionalQosFlowInformation ::= ENUMERATED { more-likely, ... } (present if true)
    pub additional_qos_flow_information: bool,
}

impl QosFlowLevelQosParameters {
    pub(crate) fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.gbr_qos_information.is_some());
        encoder.write_bit(self.reflective_qos_attribute);
        encoder.write_bit(self.additional_qos_flow_information);
        encoder.write_bit(false); // no iE-Extensions
        self.qos_characteristics.encode(encoder)?;
        self.allocation_and_retention_priority.encode(encoder)?;
        if let Some(ref gbr) = self.gbr_qos_information {
            gbr.encode(encoder)?;
        }
        let single = Constraint::extensible(0, 0);
        if self.reflective_qos_attribute {
            encoder.encode_enumerated(0, &single)?;
        }
        if self.additional_qos_flow_information {
            encoder.encode_enumerated(0, &single)?;
        }
        Ok(())
    }

    pub(crate) fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let gbr_present = decoder.read_bit()?;
        let reflective_present = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_characteristics = QosCharacteristics::decode(decoder)?;
        let allocation_and_retention_priority = AllocationAndRetentionPriority::decode(decoder)?;
        let gbr_qos_information = if gbr_present {
            Some(GbrQosInformation::decode(decoder)?)
        } else {
            None
        };
        let single = Constraint::extensible(0, 0);
        if reflective_present {
            let _val = decoder.decode_enumerated(&single)?;
        }
        if additional_present {
            let _val = decoder.decode_enumerated(&single)?;
        }
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_characteristics,
            allocation_and_retention_priority,
            gbr_qos_information,
            reflective_qos_attribute: reflective_present,
            additional_qos_flow_information: additional_present,
        })
    }
}

pub(crate) fn encode_qfi(encoder: &mut AperEncoder, qfi: u8) -> NgapResult<()> {
    encode_ext_constrained(encoder, qfi as i64, 0, 63)
}

pub(crate) fn decode_qfi(decoder: &mut AperDecoder) -> NgapResult<u8> {
    Ok(decode_ext_constrained(decoder, 0, 63)? as u8)
}

/// QosFlowSetupRequestItem (TS 38.413 Section 9.3.4.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowSetupRequestItem {
    /// QoS Flow Identifier (0..63)
    pub qos_flow_identifier: u8,
    pub qos_flow_level_qos_parameters: QosFlowLevelQosParameters,
    /// E-RAB ID (0..15, optional, for EPS interworking)
    pub e_rab_id: Option<u8>,
}

impl QosFlowSetupRequestItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.e_rab_id.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        self.qos_flow_level_qos_parameters.encode(encoder)?;
        if let Some(erab) = self.e_rab_id {
            encode_ext_constrained(encoder, erab as i64, 0, 15)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let erab_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let qos_flow_level_qos_parameters = QosFlowLevelQosParameters::decode(decoder)?;
        let e_rab_id = if erab_present {
            Some(decode_ext_constrained(decoder, 0, 15)? as u8)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
            qos_flow_level_qos_parameters,
            e_rab_id,
        })
    }
}

/// QosFlowMappingIndication ::= ENUMERATED { ul, dl, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QosFlowMappingIndication {
    Ul = 0,
    Dl = 1,
}

/// AssociatedQosFlowItem (TS 38.413 Section 9.3.1.13)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociatedQosFlowItem {
    pub qos_flow_identifier: u8,
    pub qos_flow_mapping_indication: Option<QosFlowMappingIndication>,
}

impl AssociatedQosFlowItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.qos_flow_mapping_indication.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        if let Some(ind) = self.qos_flow_mapping_indication {
            let constraint = Constraint::extensible(0, 1);
            encoder.encode_enumerated(ind as i64, &constraint)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let mapping_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let qos_flow_mapping_indication = if mapping_present {
            let constraint = Constraint::extensible(0, 1);
            match decoder.decode_enumerated(&constraint)? {
                0 => Some(QosFlowMappingIndication::Ul),
                1 => Some(QosFlowMappingIndication::Dl),
                v => {
                    return Err(invalid(
                        "QosFlowMappingIndication",
                        format!("Unknown value: {v}"),
                    ))
                }
            }
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
            qos_flow_mapping_indication,
        })
    }
}

/// QosFlowPerTNLInformation (TS 38.413 Section 9.3.2.8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowPerTnlInformation {
    pub up_transport_layer_information: UpTransportLayerInformation,
    pub associated_qos_flow_list: Vec<AssociatedQosFlowItem>,
}

impl QosFlowPerTnlInformation {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        self.up_transport_layer_information.encode(encoder)?;
        encoder.encode_constrained_length(self.associated_qos_flow_list.len(), 1, 64)?;
        for item in &self.associated_qos_flow_list {
            item.encode(encoder)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let up_transport_layer_information = UpTransportLayerInformation::decode(decoder)?;
        let count = decoder.decode_constrained_length(1, 64)?;
        let mut associated_qos_flow_list = Vec::with_capacity(count);
        for _ in 0..count {
            associated_qos_flow_list.push(AssociatedQosFlowItem::decode(decoder)?);
        }
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            up_transport_layer_information,
            associated_qos_flow_list,
        })
    }
}

/// maxnoofMultiConnectivityMinusOne (TS 38.413 §9.4)
const MAX_MULTI_CONNECTIVITY_MINUS_ONE: usize = 3;

/// Encode a `QosFlowPerTNLInformationList ::= SEQUENCE (SIZE(1..maxnoofMultiConnectivityMinusOne))
/// OF QosFlowPerTNLInformationItem`, each item the extensible
/// `SEQUENCE { qosFlowPerTNLInformation, iE-Extensions OPTIONAL, ... }` (§9.3.2.8). It
/// carries the additional DL tunnels of a dual- or multi-connectivity NG-RAN node.
fn encode_qos_flow_per_tnl_information_list(
    encoder: &mut AperEncoder,
    list: &[QosFlowPerTnlInformation],
) -> NgapResult<()> {
    if list.is_empty() || list.len() > MAX_MULTI_CONNECTIVITY_MINUS_ONE {
        return Err(invalid(
            "QosFlowPerTNLInformationList",
            format!(
                "{} items, outside 1..{MAX_MULTI_CONNECTIVITY_MINUS_ONE}",
                list.len()
            ),
        ));
    }
    encoder.encode_constrained_length(list.len(), 1, MAX_MULTI_CONNECTIVITY_MINUS_ONE)?;
    for item in list {
        encoder.write_bit(false); // item extension marker
        encoder.write_bit(false); // no iE-Extensions
        item.encode(encoder)?;
    }
    Ok(())
}

fn decode_qos_flow_per_tnl_information_list(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<QosFlowPerTnlInformation>> {
    let count = decoder.decode_constrained_length(1, MAX_MULTI_CONNECTIVITY_MINUS_ONE)?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        list.push(QosFlowPerTnlInformation::decode(decoder)?);
        finish_extensible_sequence(decoder, ext, ie_ext)?;
    }
    Ok(list)
}

/// QosFlowItem with cause - entry of QosFlowList (failed/to-release lists)
#[derive(Debug, Clone, PartialEq)]
pub struct QosFlowWithCauseItem {
    pub qos_flow_identifier: u8,
    pub cause: Cause,
}

impl QosFlowWithCauseItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        self.cause.encode_aper(encoder)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let cause = Cause::decode_aper(decoder)?;
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
            cause,
        })
    }
}

fn encode_qos_flow_with_cause_list(
    encoder: &mut AperEncoder,
    list: &[QosFlowWithCauseItem],
) -> NgapResult<()> {
    encoder.encode_constrained_length(list.len(), 1, 64)?;
    for item in list {
        item.encode(encoder)?;
    }
    Ok(())
}

fn decode_qos_flow_with_cause_list(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<QosFlowWithCauseItem>> {
    let count = decoder.decode_constrained_length(1, 64)?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        list.push(QosFlowWithCauseItem::decode(decoder)?);
    }
    Ok(list)
}

// ============================================================================
// Security types (transfer-level)
// ============================================================================

/// IntegrityProtectionIndication / ConfidentialityProtectionIndication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectionIndication {
    Required = 0,
    Preferred = 1,
    NotNeeded = 2,
}

/// MaximumIntegrityProtectedDataRate ::= ENUMERATED { bitrate64kbs, maximum-UE-rate, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MaximumIntegrityProtectedDataRate {
    Bitrate64kbs = 0,
    MaximumUeRate = 1,
}

/// SecurityIndication (TS 38.413 Section 9.3.1.27)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityIndication {
    pub integrity_protection_indication: ProtectionIndication,
    pub confidentiality_protection_indication: ProtectionIndication,
    /// Conditional: present when integrity protection is required or preferred
    pub maximum_integrity_protected_data_rate_ul: Option<MaximumIntegrityProtectedDataRate>,
}

impl SecurityIndication {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.maximum_integrity_protected_data_rate_ul.is_some());
        encoder.write_bit(false); // no iE-Extensions
        let constraint = Constraint::extensible(0, 2);
        encoder.encode_enumerated(self.integrity_protection_indication as i64, &constraint)?;
        encoder.encode_enumerated(
            self.confidentiality_protection_indication as i64,
            &constraint,
        )?;
        if let Some(rate) = self.maximum_integrity_protected_data_rate_ul {
            let rate_constraint = Constraint::extensible(0, 1);
            encoder.encode_enumerated(rate as i64, &rate_constraint)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let rate_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let constraint = Constraint::extensible(0, 2);
        let decode_indication = |v: i64| -> NgapResult<ProtectionIndication> {
            match v {
                0 => Ok(ProtectionIndication::Required),
                1 => Ok(ProtectionIndication::Preferred),
                2 => Ok(ProtectionIndication::NotNeeded),
                _ => Err(invalid(
                    "SecurityIndication",
                    format!("Unknown protection indication: {v}"),
                )),
            }
        };
        let integrity = decode_indication(decoder.decode_enumerated(&constraint)?)?;
        let confidentiality = decode_indication(decoder.decode_enumerated(&constraint)?)?;
        let maximum_integrity_protected_data_rate_ul = if rate_present {
            let rate_constraint = Constraint::extensible(0, 1);
            match decoder.decode_enumerated(&rate_constraint)? {
                0 => Some(MaximumIntegrityProtectedDataRate::Bitrate64kbs),
                1 => Some(MaximumIntegrityProtectedDataRate::MaximumUeRate),
                v => {
                    return Err(invalid(
                        "MaximumIntegrityProtectedDataRate",
                        format!("Unknown value: {v}"),
                    ))
                }
            }
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            integrity_protection_indication: integrity,
            confidentiality_protection_indication: confidentiality,
            maximum_integrity_protected_data_rate_ul,
        })
    }
}

/// IntegrityProtectionResult / ConfidentialityProtectionResult
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectionResult {
    Performed = 0,
    NotPerformed = 1,
}

/// SecurityResult (TS 38.413 Section 9.3.1.61)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityResult {
    pub integrity_protection_result: ProtectionResult,
    pub confidentiality_protection_result: ProtectionResult,
}

impl SecurityResult {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        let constraint = Constraint::extensible(0, 1);
        encoder.encode_enumerated(self.integrity_protection_result as i64, &constraint)?;
        encoder.encode_enumerated(self.confidentiality_protection_result as i64, &constraint)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let constraint = Constraint::extensible(0, 1);
        let decode_result = |v: i64| -> NgapResult<ProtectionResult> {
            match v {
                0 => Ok(ProtectionResult::Performed),
                1 => Ok(ProtectionResult::NotPerformed),
                _ => Err(invalid(
                    "SecurityResult",
                    format!("Unknown protection result: {v}"),
                )),
            }
        };
        let integrity = decode_result(decoder.decode_enumerated(&constraint)?)?;
        let confidentiality = decode_result(decoder.decode_enumerated(&constraint)?)?;
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            integrity_protection_result: integrity,
            confidentiality_protection_result: confidentiality,
        })
    }
}

// ============================================================================
// PDU Session type / AMBR
// ============================================================================

/// PDUSessionType ::= ENUMERATED { ipv4, ipv6, ipv4v6, ethernet, unstructured, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduSessionType {
    Ipv4 = 0,
    Ipv6 = 1,
    Ipv4v6 = 2,
    Ethernet = 3,
    Unstructured = 4,
}

impl PduSessionType {
    const CONSTRAINT: Constraint = Constraint::extensible(0, 4);

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        match decoder.decode_enumerated(&Self::CONSTRAINT)? {
            0 => Ok(PduSessionType::Ipv4),
            1 => Ok(PduSessionType::Ipv6),
            2 => Ok(PduSessionType::Ipv4v6),
            3 => Ok(PduSessionType::Ethernet),
            4 => Ok(PduSessionType::Unstructured),
            v => Err(invalid("PDUSessionType", format!("Unknown value: {v}"))),
        }
    }
}

/// PDUSessionAggregateMaximumBitRate (TS 38.413 Section 9.3.1.58)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduSessionAggregateMaximumBitRate {
    /// Downlink AMBR in bits/s
    pub dl: u64,
    /// Uplink AMBR in bits/s
    pub ul: u64,
}

impl PduSessionAggregateMaximumBitRate {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encode_bit_rate(encoder, self.dl)?;
        encode_bit_rate(encoder, self.ul)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let dl = decode_bit_rate(decoder)?;
        let ul = decode_bit_rate(decoder)?;
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self { dl, ul })
    }
}

// ============================================================================
// IE-container helpers for transfer containers
// ============================================================================

fn push_transfer_ie<F>(
    container: &mut ProtocolIeContainer,
    ie_id: u16,
    criticality: Criticality,
    encode_value: F,
) -> NgapResult<()>
where
    F: FnOnce(&mut AperEncoder) -> NgapResult<()>,
{
    let mut encoder = AperEncoder::new();
    encode_value(&mut encoder)?;
    encoder.align();
    container.push(ProtocolIeField {
        id: ProtocolIeId(ie_id),
        criticality,
        value: encoder.into_bytes().to_vec(),
    });
    Ok(())
}

fn encode_container(container: &ProtocolIeContainer) -> NgapResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    // The outer *RequestTransfer SEQUENCE (TS 38.413 §9.3.4.x) is extensible
    // (`...`); APER (Aligned, §9.5) requires a leading extension-presence bit.
    // The single root field is mandatory, so the preamble is exactly this one
    // bit; the container's own length determinant then self-aligns.
    encoder.write_bit(false);
    container.encode_aper(&mut encoder)?;
    encoder.align();
    Ok(encoder.into_bytes().to_vec())
}

fn decode_container(data: &[u8]) -> NgapResult<ProtocolIeContainer> {
    let mut decoder = AperDecoder::new(data);
    // The outer SEQUENCE extension-presence bit (see encode_container). Its
    // only root member is the mandatory container, so there is no iE-Extensions
    // bit; extension additions, if flagged, follow the container.
    let ext = decoder.read_bit()?;
    let container = ProtocolIeContainer::decode_aper(&mut decoder)?;
    finish_extensible_sequence(&mut decoder, ext, false)?;
    Ok(container)
}

// ============================================================================
// PDU Session Resource Setup Request Transfer (TS 38.413 Section 9.3.4.1)
// ============================================================================

/// PDUSessionResourceSetupRequestTransfer - built by SMF, consumed by gNB
#[derive(Debug, Clone, PartialEq)]
pub struct PduSessionResourceSetupRequestTransfer {
    /// PDU Session Aggregate Maximum Bit Rate (conditional, for non-GBR flows)
    pub pdu_session_aggregate_maximum_bit_rate: Option<PduSessionAggregateMaximumBitRate>,
    /// UL NG-U UP TNL Information (mandatory) - UPF N3 endpoint
    pub ul_ngu_up_tnl_information: UpTransportLayerInformation,
    /// Data Forwarding Not Possible (optional flag)
    pub data_forwarding_not_possible: bool,
    /// PDU Session Type (mandatory)
    pub pdu_session_type: PduSessionType,
    /// Security Indication (optional)
    pub security_indication: Option<SecurityIndication>,
    /// Network Instance (optional, 1..256)
    pub network_instance: Option<u16>,
    /// QoS Flow Setup Request List (mandatory)
    pub qos_flow_setup_request_list: Vec<QosFlowSetupRequestItem>,
    /// Direct Forwarding Path Availability (optional flag, IE 22, criticality `ignore`).
    ///
    /// TS 29.502 §5.2.2.2.3 step 2a: in an EPS→5GS handover over N26, *"if the SMF was
    /// indicated in step 1 that direct data forwarding is applicable, the SMF shall include
    /// an indication that a direct forwarding path is available in the N2 SM information"*.
    pub direct_forwarding_path_availability: bool,
}

impl PduSessionResourceSetupRequestTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut container = ProtocolIeContainer::new();
        if let Some(ambr) = self.pdu_session_aggregate_maximum_bit_rate {
            push_transfer_ie(
                &mut container,
                IE_ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE,
                Criticality::Reject,
                |enc| ambr.encode(enc),
            )?;
        }
        push_transfer_ie(
            &mut container,
            IE_ID_UL_NGU_UP_TNL_INFORMATION,
            Criticality::Reject,
            |enc| self.ul_ngu_up_tnl_information.encode(enc),
        )?;
        if self.data_forwarding_not_possible {
            push_transfer_ie(
                &mut container,
                IE_ID_DATA_FORWARDING_NOT_POSSIBLE,
                Criticality::Reject,
                |enc| {
                    // DataForwardingNotPossible ::= ENUMERATED { data-forwarding-not-possible, ... }
                    let constraint = Constraint::extensible(0, 0);
                    enc.encode_enumerated(0, &constraint)?;
                    Ok(())
                },
            )?;
        }
        push_transfer_ie(
            &mut container,
            IE_ID_PDU_SESSION_TYPE,
            Criticality::Reject,
            |enc| {
                enc.encode_enumerated(self.pdu_session_type as i64, &PduSessionType::CONSTRAINT)?;
                Ok(())
            },
        )?;
        if let Some(ref sec) = self.security_indication {
            push_transfer_ie(
                &mut container,
                IE_ID_SECURITY_INDICATION,
                Criticality::Reject,
                |enc| sec.encode(enc),
            )?;
        }
        if let Some(instance) = self.network_instance {
            push_transfer_ie(
                &mut container,
                IE_ID_NETWORK_INSTANCE,
                Criticality::Reject,
                |enc| encode_ext_constrained(enc, instance as i64, 1, 256),
            )?;
        }
        push_transfer_ie(
            &mut container,
            IE_ID_QOS_FLOW_SETUP_REQUEST_LIST,
            Criticality::Reject,
            |enc| {
                enc.encode_constrained_length(self.qos_flow_setup_request_list.len(), 1, 64)?;
                for item in &self.qos_flow_setup_request_list {
                    item.encode(enc)?;
                }
                Ok(())
            },
        )?;
        // Object-set order (§9.4.1): after QosFlowSetupRequestList.
        if self.direct_forwarding_path_availability {
            push_transfer_ie(
                &mut container,
                IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY,
                Criticality::Ignore,
                |enc| {
                    // DirectForwardingPathAvailability ::= ENUMERATED { direct-path-available, ... }
                    let constraint = Constraint::extensible(0, 0);
                    enc.encode_enumerated(0, &constraint)?;
                    Ok(())
                },
            )?;
        }
        encode_container(&container)
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let container = decode_container(data)?;
        let mut ambr = None;
        let mut ul_tnl = None;
        let mut data_forwarding_not_possible = false;
        let mut pdu_session_type = None;
        let mut security_indication = None;
        let mut network_instance = None;
        let mut qos_flow_list = None;
        let mut direct_forwarding_path_availability = false;
        for field in &container.ies {
            let mut decoder = AperDecoder::new(&field.value);
            match field.id.0 {
                IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY => {
                    let constraint = Constraint::extensible(0, 0);
                    let _val = decoder.decode_enumerated(&constraint)?;
                    direct_forwarding_path_availability = true;
                }
                IE_ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE => {
                    ambr = Some(PduSessionAggregateMaximumBitRate::decode(&mut decoder)?);
                }
                IE_ID_UL_NGU_UP_TNL_INFORMATION => {
                    ul_tnl = Some(UpTransportLayerInformation::decode(&mut decoder)?);
                }
                IE_ID_ADDITIONAL_UL_NGU_UP_TNL_INFORMATION => {
                    // NGAP-07: known Rel-15 multi-connectivity optional IE that
                    // was previously silently skipped. Decode + validate so a
                    // conformant peer's transfer is accepted (not rejected as
                    // not-comprehended). The additional UL endpoints are not
                    // retained on the public struct — adding a field would force
                    // amfd/smfd construction-site churn outside this crate, and a
                    // single-connectivity SMF ignores additional UL tunnels.
                    let _additional = decode_additional_ul_ngu_up_tnl_information(&mut decoder)?;
                }
                IE_ID_DATA_FORWARDING_NOT_POSSIBLE => {
                    let constraint = Constraint::extensible(0, 0);
                    let _val = decoder.decode_enumerated(&constraint)?;
                    data_forwarding_not_possible = true;
                }
                IE_ID_PDU_SESSION_TYPE => {
                    pdu_session_type = Some(PduSessionType::decode(&mut decoder)?);
                }
                IE_ID_SECURITY_INDICATION => {
                    security_indication = Some(SecurityIndication::decode(&mut decoder)?);
                }
                IE_ID_NETWORK_INSTANCE => {
                    network_instance = Some(decode_ext_constrained(&mut decoder, 1, 256)? as u16);
                }
                IE_ID_QOS_FLOW_SETUP_REQUEST_LIST => {
                    let count = decoder.decode_constrained_length(1, 64)?;
                    let mut list = Vec::with_capacity(count);
                    for _ in 0..count {
                        list.push(QosFlowSetupRequestItem::decode(&mut decoder)?);
                    }
                    qos_flow_list = Some(list);
                }
                _ => crate::ie::handle_unknown_ie(field)?,
            }
        }
        Ok(Self {
            pdu_session_aggregate_maximum_bit_rate: ambr,
            ul_ngu_up_tnl_information: ul_tnl.ok_or(NgapError::MissingMandatoryIe {
                ie_name: "UL-NGU-UP-TNLInformation",
                ie_id: IE_ID_UL_NGU_UP_TNL_INFORMATION,
            })?,
            data_forwarding_not_possible,
            pdu_session_type: pdu_session_type.ok_or(NgapError::MissingMandatoryIe {
                ie_name: "PDUSessionType",
                ie_id: IE_ID_PDU_SESSION_TYPE,
            })?,
            security_indication,
            network_instance,
            qos_flow_setup_request_list: qos_flow_list.ok_or(NgapError::MissingMandatoryIe {
                ie_name: "QosFlowSetupRequestList",
                ie_id: IE_ID_QOS_FLOW_SETUP_REQUEST_LIST,
            })?,
            direct_forwarding_path_availability,
        })
    }
}

// ============================================================================
// PDU Session Resource Setup Response Transfer (TS 38.413 Section 9.3.4.2)
// ============================================================================

/// PDUSessionResourceSetupResponseTransfer - built by gNB, consumed by SMF
#[derive(Debug, Clone, PartialEq)]
pub struct PduSessionResourceSetupResponseTransfer {
    /// DL QoS Flow per TNL Information (mandatory) - gNB N3 endpoint
    pub dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation,
    /// Additional DL QoS Flow per TNL Information (optional, empty = absent): a
    /// `QosFlowPerTNLInformationList` of 1..3 additional tunnels (§9.3.4.2)
    pub additional_dl_qos_flow_per_tnl_information: Vec<QosFlowPerTnlInformation>,
    /// Security Result (optional)
    pub security_result: Option<SecurityResult>,
    /// QoS Flow Failed To Setup List (optional, empty = absent)
    pub qos_flow_failed_to_setup_list: Vec<QosFlowWithCauseItem>,
}

impl PduSessionResourceSetupResponseTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(!self.additional_dl_qos_flow_per_tnl_information.is_empty());
        encoder.write_bit(self.security_result.is_some());
        encoder.write_bit(!self.qos_flow_failed_to_setup_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        self.dl_qos_flow_per_tnl_information.encode(&mut encoder)?;
        if !self.additional_dl_qos_flow_per_tnl_information.is_empty() {
            encode_qos_flow_per_tnl_information_list(
                &mut encoder,
                &self.additional_dl_qos_flow_per_tnl_information,
            )?;
        }
        if let Some(ref result) = self.security_result {
            result.encode(&mut encoder)?;
        }
        if !self.qos_flow_failed_to_setup_list.is_empty() {
            encode_qos_flow_with_cause_list(&mut encoder, &self.qos_flow_failed_to_setup_list)?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let security_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let dl_qos_flow_per_tnl_information = QosFlowPerTnlInformation::decode(&mut decoder)?;
        let additional_dl_qos_flow_per_tnl_information = if additional_present {
            decode_qos_flow_per_tnl_information_list(&mut decoder)?
        } else {
            Vec::new()
        };
        let security_result = if security_present {
            Some(SecurityResult::decode(&mut decoder)?)
        } else {
            None
        };
        let qos_flow_failed_to_setup_list = if failed_present {
            decode_qos_flow_with_cause_list(&mut decoder)?
        } else {
            Vec::new()
        };
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            dl_qos_flow_per_tnl_information,
            additional_dl_qos_flow_per_tnl_information,
            security_result,
            qos_flow_failed_to_setup_list,
        })
    }
}

// ============================================================================
// Handover Request Acknowledge Transfer (TS 38.413 Section 9.3.4.11)
// ============================================================================

/// `QosFlowItemWithDataForwarding` (§9.3.4.11): a QoS flow the target NG-RAN set up, and
/// whether it accepted data forwarding for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosFlowItemWithDataForwarding {
    /// QoS Flow Identifier (0..63)
    pub qos_flow_identifier: u8,
    /// `dataForwardingAccepted ENUMERATED { data-forwarding-accepted, ... } OPTIONAL`
    pub data_forwarding_accepted: bool,
}

impl QosFlowItemWithDataForwarding {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.data_forwarding_accepted);
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        if self.data_forwarding_accepted {
            encoder.encode_enumerated(0, &Constraint::extensible(0, 0))?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let accepted_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        if accepted_present {
            let _ = decoder.decode_enumerated(&Constraint::extensible(0, 0))?;
        }
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
            data_forwarding_accepted: accepted_present,
        })
    }
}

/// `DataForwardingResponseDRBItem` (§9.3.4.11): per-DRB forwarding tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataForwardingResponseDrbItem {
    /// `DRB-ID ::= INTEGER (1..32, ...)`
    pub drb_id: u8,
    pub dl_forwarding_up_tnl_information: Option<UpTransportLayerInformation>,
    pub ul_forwarding_up_tnl_information: Option<UpTransportLayerInformation>,
}

impl DataForwardingResponseDrbItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.dl_forwarding_up_tnl_information.is_some());
        encoder.write_bit(self.ul_forwarding_up_tnl_information.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_ext_constrained(encoder, i64::from(self.drb_id), 1, 32)?;
        if let Some(ref t) = self.dl_forwarding_up_tnl_information {
            t.encode(encoder)?;
        }
        if let Some(ref t) = self.ul_forwarding_up_tnl_information {
            t.encode(encoder)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let dl_present = decoder.read_bit()?;
        let ul_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let drb_id = decode_ext_constrained(decoder, 1, 32)? as u8;
        let dl_forwarding_up_tnl_information = if dl_present {
            Some(UpTransportLayerInformation::decode(decoder)?)
        } else {
            None
        };
        let ul_forwarding_up_tnl_information = if ul_present {
            Some(UpTransportLayerInformation::decode(decoder)?)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            drb_id,
            dl_forwarding_up_tnl_information,
            ul_forwarding_up_tnl_information,
        })
    }
}

/// maxnoofDRBs (TS 38.413 §9.4)
const MAX_NO_OF_DRBS: usize = 32;

/// `HandoverRequestAcknowledgeTransfer` (TS 38.413 §9.3.4.11) — built by the target NG-RAN,
/// relayed by the AMF in the PREPARED `UpdateSMContext` (TS 29.502 §5.2.2.3.4.2 step 3),
/// consumed by the SMF.
///
/// The SMF reads it for the target's **downlink** N3 endpoint, which the UPF is switched to
/// at handover execution, and for which QoS flows the target accepted (TS 23.502
/// §4.11.1.2.2.2 step 12: *"The EPS Bearer Setup list ... is generated based on the list of
/// accepted QFI(s)"*).
#[derive(Debug, Clone, PartialEq)]
pub struct HandoverRequestAcknowledgeTransfer {
    /// `dL-NGU-UP-TNLInformation` (mandatory) — the target's DL N3 endpoint.
    pub dl_ngu_up_tnl_information: UpTransportLayerInformation,
    /// `dLForwardingUP-TNLInformation` (optional).
    pub dl_forwarding_up_tnl_information: Option<UpTransportLayerInformation>,
    /// `securityResult` (optional).
    pub security_result: Option<SecurityResult>,
    /// `qosFlowSetupResponseList` (mandatory, 1..64).
    pub qos_flow_setup_response_list: Vec<QosFlowItemWithDataForwarding>,
    /// `qosFlowFailedToSetupList` (optional, empty = absent).
    pub qos_flow_failed_to_setup_list: Vec<QosFlowWithCauseItem>,
    /// `dataForwardingResponseDRBList` (optional, empty = absent).
    pub data_forwarding_response_drb_list: Vec<DataForwardingResponseDrbItem>,
}

impl HandoverRequestAcknowledgeTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        if self.qos_flow_setup_response_list.is_empty() {
            return Err(invalid(
                "HandoverRequestAcknowledgeTransfer",
                "qosFlowSetupResponseList is SIZE(1..maxnoofQosFlows)".to_string(),
            ));
        }
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(self.dl_forwarding_up_tnl_information.is_some());
        encoder.write_bit(self.security_result.is_some());
        encoder.write_bit(!self.qos_flow_failed_to_setup_list.is_empty());
        encoder.write_bit(!self.data_forwarding_response_drb_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        self.dl_ngu_up_tnl_information.encode(&mut encoder)?;
        if let Some(ref t) = self.dl_forwarding_up_tnl_information {
            t.encode(&mut encoder)?;
        }
        if let Some(ref r) = self.security_result {
            r.encode(&mut encoder)?;
        }
        encoder.encode_constrained_length(self.qos_flow_setup_response_list.len(), 1, 64)?;
        for item in &self.qos_flow_setup_response_list {
            item.encode(&mut encoder)?;
        }
        if !self.qos_flow_failed_to_setup_list.is_empty() {
            encode_qos_flow_with_cause_list(&mut encoder, &self.qos_flow_failed_to_setup_list)?;
        }
        if !self.data_forwarding_response_drb_list.is_empty() {
            encoder.encode_constrained_length(
                self.data_forwarding_response_drb_list.len(),
                1,
                MAX_NO_OF_DRBS,
            )?;
            for item in &self.data_forwarding_response_drb_list {
                item.encode(&mut encoder)?;
            }
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let dl_forwarding_present = decoder.read_bit()?;
        let security_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let drb_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let dl_ngu_up_tnl_information = UpTransportLayerInformation::decode(&mut decoder)?;
        let dl_forwarding_up_tnl_information = if dl_forwarding_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let security_result = if security_present {
            Some(SecurityResult::decode(&mut decoder)?)
        } else {
            None
        };
        let count = decoder.decode_constrained_length(1, 64)?;
        let mut qos_flow_setup_response_list = Vec::with_capacity(count);
        for _ in 0..count {
            qos_flow_setup_response_list.push(QosFlowItemWithDataForwarding::decode(&mut decoder)?);
        }
        let qos_flow_failed_to_setup_list = if failed_present {
            decode_qos_flow_with_cause_list(&mut decoder)?
        } else {
            Vec::new()
        };
        let data_forwarding_response_drb_list = if drb_present {
            let count = decoder.decode_constrained_length(1, MAX_NO_OF_DRBS)?;
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(DataForwardingResponseDrbItem::decode(&mut decoder)?);
            }
            list
        } else {
            Vec::new()
        };
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            dl_ngu_up_tnl_information,
            dl_forwarding_up_tnl_information,
            security_result,
            qos_flow_setup_response_list,
            qos_flow_failed_to_setup_list,
            data_forwarding_response_drb_list,
        })
    }
}

// ============================================================================
// PDU Session Resource Modify Request/Response Transfer (Section 9.3.4.3/4)
// ============================================================================

/// UL-NGU-UP-TNLModifyItem (TS 38.413 Section 9.3.4.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlNguUpTnlModifyItem {
    pub ul_ngu_up_tnl_information: UpTransportLayerInformation,
    pub dl_ngu_up_tnl_information: UpTransportLayerInformation,
}

impl UlNguUpTnlModifyItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        self.ul_ngu_up_tnl_information.encode(encoder)?;
        self.dl_ngu_up_tnl_information.encode(encoder)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let ul_ngu_up_tnl_information = UpTransportLayerInformation::decode(decoder)?;
        let dl_ngu_up_tnl_information = UpTransportLayerInformation::decode(decoder)?;
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            ul_ngu_up_tnl_information,
            dl_ngu_up_tnl_information,
        })
    }
}

/// QosFlowAddOrModifyRequestItem (TS 38.413 Section 9.3.4.3)
#[derive(Debug, Clone, PartialEq)]
pub struct QosFlowAddOrModifyRequestItem {
    pub qos_flow_identifier: u8,
    pub qos_flow_level_qos_parameters: Option<QosFlowLevelQosParameters>,
    pub e_rab_id: Option<u8>,
}

impl QosFlowAddOrModifyRequestItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(self.qos_flow_level_qos_parameters.is_some());
        encoder.write_bit(self.e_rab_id.is_some());
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        if let Some(ref params) = self.qos_flow_level_qos_parameters {
            params.encode(encoder)?;
        }
        if let Some(erab) = self.e_rab_id {
            encode_ext_constrained(encoder, erab as i64, 0, 15)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let params_present = decoder.read_bit()?;
        let erab_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let qos_flow_level_qos_parameters = if params_present {
            Some(QosFlowLevelQosParameters::decode(decoder)?)
        } else {
            None
        };
        let e_rab_id = if erab_present {
            Some(decode_ext_constrained(decoder, 0, 15)? as u8)
        } else {
            None
        };
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
            qos_flow_level_qos_parameters,
            e_rab_id,
        })
    }
}

/// PDUSessionResourceModifyRequestTransfer - built by SMF, consumed by gNB
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionResourceModifyRequestTransfer {
    /// PDU Session Aggregate Maximum Bit Rate (optional)
    pub pdu_session_aggregate_maximum_bit_rate: Option<PduSessionAggregateMaximumBitRate>,
    /// UL NG-U UP TNL Modify List (optional, empty = absent)
    pub ul_ngu_up_tnl_modify_list: Vec<UlNguUpTnlModifyItem>,
    /// Network Instance (optional)
    pub network_instance: Option<u16>,
    /// QoS Flow Add Or Modify Request List (optional, empty = absent)
    pub qos_flow_add_or_modify_request_list: Vec<QosFlowAddOrModifyRequestItem>,
    /// QoS Flow To Release List (optional, empty = absent)
    pub qos_flow_to_release_list: Vec<QosFlowWithCauseItem>,
}

impl PduSessionResourceModifyRequestTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut container = ProtocolIeContainer::new();
        if let Some(ambr) = self.pdu_session_aggregate_maximum_bit_rate {
            push_transfer_ie(
                &mut container,
                IE_ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE,
                Criticality::Reject,
                |enc| ambr.encode(enc),
            )?;
        }
        if !self.ul_ngu_up_tnl_modify_list.is_empty() {
            push_transfer_ie(
                &mut container,
                IE_ID_UL_NGU_UP_TNL_MODIFY_LIST,
                Criticality::Reject,
                |enc| {
                    enc.encode_constrained_length(self.ul_ngu_up_tnl_modify_list.len(), 1, 3)?;
                    for item in &self.ul_ngu_up_tnl_modify_list {
                        item.encode(enc)?;
                    }
                    Ok(())
                },
            )?;
        }
        if let Some(instance) = self.network_instance {
            push_transfer_ie(
                &mut container,
                IE_ID_NETWORK_INSTANCE,
                Criticality::Reject,
                |enc| encode_ext_constrained(enc, instance as i64, 1, 256),
            )?;
        }
        if !self.qos_flow_add_or_modify_request_list.is_empty() {
            push_transfer_ie(
                &mut container,
                IE_ID_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST,
                Criticality::Reject,
                |enc| {
                    enc.encode_constrained_length(
                        self.qos_flow_add_or_modify_request_list.len(),
                        1,
                        64,
                    )?;
                    for item in &self.qos_flow_add_or_modify_request_list {
                        item.encode(enc)?;
                    }
                    Ok(())
                },
            )?;
        }
        if !self.qos_flow_to_release_list.is_empty() {
            push_transfer_ie(
                &mut container,
                IE_ID_QOS_FLOW_TO_RELEASE_LIST,
                Criticality::Reject,
                |enc| encode_qos_flow_with_cause_list(enc, &self.qos_flow_to_release_list),
            )?;
        }
        encode_container(&container)
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let container = decode_container(data)?;
        let mut transfer = Self::default();
        for field in &container.ies {
            let mut decoder = AperDecoder::new(&field.value);
            match field.id.0 {
                IE_ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE => {
                    transfer.pdu_session_aggregate_maximum_bit_rate =
                        Some(PduSessionAggregateMaximumBitRate::decode(&mut decoder)?);
                }
                IE_ID_UL_NGU_UP_TNL_MODIFY_LIST => {
                    let count = decoder.decode_constrained_length(1, 3)?;
                    let mut list = Vec::with_capacity(count);
                    for _ in 0..count {
                        list.push(UlNguUpTnlModifyItem::decode(&mut decoder)?);
                    }
                    transfer.ul_ngu_up_tnl_modify_list = list;
                }
                IE_ID_NETWORK_INSTANCE => {
                    transfer.network_instance =
                        Some(decode_ext_constrained(&mut decoder, 1, 256)? as u16);
                }
                IE_ID_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST => {
                    let count = decoder.decode_constrained_length(1, 64)?;
                    let mut list = Vec::with_capacity(count);
                    for _ in 0..count {
                        list.push(QosFlowAddOrModifyRequestItem::decode(&mut decoder)?);
                    }
                    transfer.qos_flow_add_or_modify_request_list = list;
                }
                IE_ID_QOS_FLOW_TO_RELEASE_LIST => {
                    transfer.qos_flow_to_release_list =
                        decode_qos_flow_with_cause_list(&mut decoder)?;
                }
                _ => crate::ie::handle_unknown_ie(field)?,
            }
        }
        Ok(transfer)
    }
}

/// QosFlowAddOrModifyResponseItem (TS 38.413 Section 9.3.4.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosFlowAddOrModifyResponseItem {
    pub qos_flow_identifier: u8,
}

impl QosFlowAddOrModifyResponseItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.qos_flow_identifier)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        finish_extensible_sequence(decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_identifier,
        })
    }
}

/// PDUSessionResourceModifyResponseTransfer - built by gNB, consumed by SMF
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionResourceModifyResponseTransfer {
    /// DL NG-U UP TNL Information (optional)
    pub dl_ngu_up_tnl_information: Option<UpTransportLayerInformation>,
    /// UL NG-U UP TNL Information (optional)
    pub ul_ngu_up_tnl_information: Option<UpTransportLayerInformation>,
    /// QoS Flow Add Or Modify Response List (optional, empty = absent)
    pub qos_flow_add_or_modify_response_list: Vec<QosFlowAddOrModifyResponseItem>,
    /// Additional DL QoS Flow per TNL Information (optional, empty = absent): a
    /// `QosFlowPerTNLInformationList` of 1..3 additional tunnels (§9.3.4.4)
    pub additional_dl_qos_flow_per_tnl_information: Vec<QosFlowPerTnlInformation>,
    /// QoS Flow Failed To Add Or Modify List (optional, empty = absent)
    pub qos_flow_failed_to_add_or_modify_list: Vec<QosFlowWithCauseItem>,
}

impl PduSessionResourceModifyResponseTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(self.dl_ngu_up_tnl_information.is_some());
        encoder.write_bit(self.ul_ngu_up_tnl_information.is_some());
        encoder.write_bit(!self.qos_flow_add_or_modify_response_list.is_empty());
        encoder.write_bit(!self.additional_dl_qos_flow_per_tnl_information.is_empty());
        encoder.write_bit(!self.qos_flow_failed_to_add_or_modify_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        if let Some(ref dl) = self.dl_ngu_up_tnl_information {
            dl.encode(&mut encoder)?;
        }
        if let Some(ref ul) = self.ul_ngu_up_tnl_information {
            ul.encode(&mut encoder)?;
        }
        if !self.qos_flow_add_or_modify_response_list.is_empty() {
            encoder.encode_constrained_length(
                self.qos_flow_add_or_modify_response_list.len(),
                1,
                64,
            )?;
            for item in &self.qos_flow_add_or_modify_response_list {
                item.encode(&mut encoder)?;
            }
        }
        if !self.additional_dl_qos_flow_per_tnl_information.is_empty() {
            encode_qos_flow_per_tnl_information_list(
                &mut encoder,
                &self.additional_dl_qos_flow_per_tnl_information,
            )?;
        }
        if !self.qos_flow_failed_to_add_or_modify_list.is_empty() {
            encode_qos_flow_with_cause_list(
                &mut encoder,
                &self.qos_flow_failed_to_add_or_modify_list,
            )?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let dl_present = decoder.read_bit()?;
        let ul_present = decoder.read_bit()?;
        let response_present = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let dl_ngu_up_tnl_information = if dl_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let ul_ngu_up_tnl_information = if ul_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let qos_flow_add_or_modify_response_list = if response_present {
            let count = decoder.decode_constrained_length(1, 64)?;
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(QosFlowAddOrModifyResponseItem::decode(&mut decoder)?);
            }
            list
        } else {
            Vec::new()
        };
        let additional_dl_qos_flow_per_tnl_information = if additional_present {
            decode_qos_flow_per_tnl_information_list(&mut decoder)?
        } else {
            Vec::new()
        };
        let qos_flow_failed_to_add_or_modify_list = if failed_present {
            decode_qos_flow_with_cause_list(&mut decoder)?
        } else {
            Vec::new()
        };
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            dl_ngu_up_tnl_information,
            ul_ngu_up_tnl_information,
            qos_flow_add_or_modify_response_list,
            additional_dl_qos_flow_per_tnl_information,
            qos_flow_failed_to_add_or_modify_list,
        })
    }
}

// ============================================================================
// PDU Session Resource Release Command/Response Transfer (Section 9.3.4.11/12)
// ============================================================================

/// PDUSessionResourceReleaseCommandTransfer - built by SMF, consumed by gNB
#[derive(Debug, Clone, PartialEq)]
pub struct PduSessionResourceReleaseCommandTransfer {
    /// Cause (mandatory)
    pub cause: Cause,
}

impl PduSessionResourceReleaseCommandTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        self.cause.encode_aper(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let cause = Cause::decode_aper(&mut decoder)?;
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self { cause })
    }
}

// ============================================================================
// AN-initiated PDU session modification (TS 38.413 §8.2.4; #525)
// ============================================================================

/// maxnoofQosFlows (TS 38.413 §9.4)
const MAX_NOOF_QOS_FLOWS: usize = 64;

/// PDUSessionResourceModifyIndicationTransfer (TS 38.413 §9.3.4.20) - built by
/// the gNB, consumed by the SMF: the NG-RAN's (new) DL N3 endpoint and the QoS
/// flows it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionResourceModifyIndicationTransfer {
    /// DL QoS Flow per TNL Information (mandatory)
    pub dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation,
    /// Additional DL QoS Flow per TNL Information (optional, empty = absent),
    /// 1..maxnoofMultiConnectivityMinusOne.
    pub additional_dl_qos_flow_per_tnl_information: Vec<QosFlowPerTnlInformation>,
}

impl PduSessionResourceModifyIndicationTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(!self.additional_dl_qos_flow_per_tnl_information.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        self.dl_qos_flow_per_tnl_information.encode(&mut encoder)?;
        if !self.additional_dl_qos_flow_per_tnl_information.is_empty() {
            encode_qos_flow_per_tnl_information_list(
                &mut encoder,
                &self.additional_dl_qos_flow_per_tnl_information,
            )?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let dl_qos_flow_per_tnl_information = QosFlowPerTnlInformation::decode(&mut decoder)?;
        let additional_dl_qos_flow_per_tnl_information = if additional_present {
            decode_qos_flow_per_tnl_information_list(&mut decoder)?
        } else {
            Vec::new()
        };
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            dl_qos_flow_per_tnl_information,
            additional_dl_qos_flow_per_tnl_information,
        })
    }
}

/// PDUSessionResourceModifyConfirmTransfer (TS 38.413 §9.3.4.19) - built by the
/// SMF, consumed by the gNB: the QoS flows the core confirms, the UPF's UL N3
/// endpoint, and the flows it could not modify. `additionalNG-UUPTNLInformation`
/// is never sent (this SMF allocates no additional UL tunnels).
#[derive(Debug, Clone, PartialEq)]
pub struct PduSessionResourceModifyConfirmTransfer {
    /// QoS Flow Modify Confirm List (mandatory, 1..maxnoofQosFlows): QFIs.
    pub qos_flow_modify_confirm_list: Vec<u8>,
    /// UL NG-U UP TNL Information (mandatory)
    pub ul_ngu_up_tnl_information: UpTransportLayerInformation,
    /// QoS Flow Failed To Modify List (optional, empty = absent)
    pub qos_flow_failed_to_modify_list: Vec<QosFlowWithCauseItem>,
}

impl PduSessionResourceModifyConfirmTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let flows = &self.qos_flow_modify_confirm_list;
        if flows.is_empty() || flows.len() > MAX_NOOF_QOS_FLOWS {
            return Err(invalid(
                "QosFlowModifyConfirmList",
                format!("{} items, outside 1..{MAX_NOOF_QOS_FLOWS}", flows.len()),
            ));
        }
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // additionalNG-UUPTNLInformation absent
        encoder.write_bit(!self.qos_flow_failed_to_modify_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        encoder.encode_constrained_length(flows.len(), 1, MAX_NOOF_QOS_FLOWS)?;
        for &qfi in flows {
            // QosFlowModifyConfirmItem ::= SEQUENCE { qosFlowIdentifier,
            // iE-Extensions OPTIONAL, ... }
            encoder.write_bit(false); // extension
            encoder.write_bit(false); // no iE-Extensions
            encode_qfi(&mut encoder, qfi)?;
        }
        self.ul_ngu_up_tnl_information.encode(&mut encoder)?;
        if !self.qos_flow_failed_to_modify_list.is_empty() {
            encode_qos_flow_with_cause_list(&mut encoder, &self.qos_flow_failed_to_modify_list)?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let count = decoder.decode_constrained_length(1, MAX_NOOF_QOS_FLOWS)?;
        let mut qos_flow_modify_confirm_list = Vec::with_capacity(count);
        for _ in 0..count {
            let item_ext = decoder.read_bit()?;
            let item_ie_ext = decoder.read_bit()?;
            qos_flow_modify_confirm_list.push(decode_qfi(&mut decoder)?);
            finish_extensible_sequence(&mut decoder, item_ext, item_ie_ext)?;
        }
        let ul_ngu_up_tnl_information = UpTransportLayerInformation::decode(&mut decoder)?;
        if additional_present {
            return Err(invalid(
                "PDUSessionResourceModifyConfirmTransfer",
                "additionalNG-UUPTNLInformation is not supported".to_string(),
            ));
        }
        let qos_flow_failed_to_modify_list = if failed_present {
            decode_qos_flow_with_cause_list(&mut decoder)?
        } else {
            Vec::new()
        };
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            qos_flow_modify_confirm_list,
            ul_ngu_up_tnl_information,
            qos_flow_failed_to_modify_list,
        })
    }
}

/// PDUSessionResourceModifyIndicationUnsuccessfulTransfer (TS 38.413
/// §9.3.4.21) - built by the SMF when it cannot carry out an AN-initiated
/// modification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionResourceModifyIndicationUnsuccessfulTransfer {
    /// Cause (mandatory)
    pub cause: Cause,
}

impl PduSessionResourceModifyIndicationUnsuccessfulTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        self.cause.encode_aper(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let cause = Cause::decode_aper(&mut decoder)?;
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self { cause })
    }
}

/// PDUSessionResourceReleaseResponseTransfer - built by gNB, consumed by SMF
///
/// The Rel-15 type carries only optional iE-Extensions, so the structure is
/// empty; the encoding is a single SEQUENCE preamble octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PduSessionResourceReleaseResponseTransfer;

impl PduSessionResourceReleaseResponseTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(false); // no iE-Extensions
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self)
    }
}

// ============================================================================
// Path Switch Request Transfer (TS 38.413 Section 9.3.4.8)
// ============================================================================

/// PathSwitchRequestTransfer - built by the target gNB, consumed by SMF.
///
/// Carries the new DL NG-U F-TEID the UPF must forward to after an Xn handover,
/// plus the accepted QoS flows. Only the fields the SMF needs (DL tunnel +
/// accepted QFIs) are modelled; the optional reused-TNL and user-plane-security
/// fields are skipped on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSwitchRequestTransfer {
    /// DL NG-U UP TNL information (mandatory) - the target gNB N3 endpoint
    pub dl_ngu_up_tnl_information: UpTransportLayerInformation,
    /// QoS Flow Accepted List (mandatory, at least one) - accepted QFIs
    pub qos_flow_accepted_list: Vec<u8>,
}

impl PathSwitchRequestTransfer {
    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        // SEQUENCE preamble: extension marker + 3 optional-field present bits
        // (dL-NGU-TNLInformationReused, userPlaneSecurityInformation,
        // iE-Extensions). The DL tunnel and accepted list are mandatory.
        let ext = decoder.read_bit()?;
        let reused_present = decoder.read_bit()?;
        let security_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;

        let dl_ngu_up_tnl_information = UpTransportLayerInformation::decode(&mut decoder)?;

        // The reused-TNL and user-plane-security fields are not consumed by the
        // SMF DL-path activation; reject transfers that carry them rather than
        // silently mis-parse the following QoS list.
        if reused_present || security_present {
            return Err(invalid(
                "PathSwitchRequestTransfer",
                "dL-NGU-TNLInformationReused / userPlaneSecurityInformation not supported"
                    .to_string(),
            ));
        }

        // QosFlowAcceptedList ::= SEQUENCE (SIZE(1..64)) OF QosFlowAcceptedItem
        let count = decoder.decode_constrained_length(1, 64)?;
        let mut qos_flow_accepted_list = Vec::with_capacity(count);
        for _ in 0..count {
            // QosFlowAcceptedItem ::= SEQUENCE { qosFlowIdentifier, iE-Ext OPT }
            let item_ext = decoder.read_bit()?;
            let item_ie_ext = decoder.read_bit()?;
            qos_flow_accepted_list.push(decode_qfi(&mut decoder)?);
            finish_extensible_sequence(&mut decoder, item_ext, item_ie_ext)?;
        }

        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            dl_ngu_up_tnl_information,
            qos_flow_accepted_list,
        })
    }
}

// ============================================================================
// Path Switch Request Acknowledge Transfer (TS 38.413 Section 9.3.4.9)
// ============================================================================

/// PathSwitchRequestAcknowledgeTransfer - built by the SMF, consumed by the target gNB.
///
/// The SMF's answer to a [`PathSwitchRequestTransfer`]: it tells the target gNB the UL
/// NG-U endpoint to send on, and optionally re-states the user-plane security policy and
/// its result.
///
/// # Why this exists (#70)
///
/// Before #70 the AMF echoed the gNB's own `PathSwitchRequestTransfer` back to it as the
/// acknowledge transfer, because there was nothing else to send: this type did not exist,
/// the AMF never asked the SMF, and the SMF's `PATH_SWITCH_REQ` branch answered with no
/// `n2SmInfo` at all. TS 38.413 §9.3.4.9 makes these two different transfers with
/// different contents and opposite directions — the request carries the target's DL
/// tunnel, the acknowledge carries the core's UL tunnel — so echoing one for the other
/// tells the target gNB to send uplink traffic to itself.
///
/// # Optionality
///
/// Every member is OPTIONAL in the ASN.1, so an empty acknowledge is legal and means "no
/// change". That is deliberately representable: `Default` gives exactly that, and it is
/// the honest encoding for a path switch where the UL tunnel did not move.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PathSwitchRequestAcknowledgeTransfer {
    /// UL NG-U UP TNL information - the UPF N3 endpoint the target gNB sends uplink to.
    pub ul_ngu_up_tnl_information: Option<UpTransportLayerInformation>,
    /// User-plane security policy for the switched session.
    pub security_indication: Option<SecurityIndication>,
    /// The security result actually applied.
    pub new_security_result: Option<SecurityResult>,
    /// QoS flows the core is releasing as part of the switch.
    pub qos_flow_to_release_list: Vec<QosFlowWithCauseItem>,
}

impl PathSwitchRequestAcknowledgeTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        // SEQUENCE preamble: extension marker, then one present-bit per OPTIONAL member
        // in declaration order (uL-NGU-UP-TNLInformation, securityIndication,
        // newSecurityResult, qosFlowToReleaseList, iE-Extensions).
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.ul_ngu_up_tnl_information.is_some());
        encoder.write_bit(self.security_indication.is_some());
        encoder.write_bit(self.new_security_result.is_some());
        encoder.write_bit(!self.qos_flow_to_release_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions

        if let Some(tnl) = &self.ul_ngu_up_tnl_information {
            tnl.encode(&mut encoder)?;
        }
        if let Some(si) = &self.security_indication {
            si.encode(&mut encoder)?;
        }
        if let Some(sr) = &self.new_security_result {
            sr.encode(&mut encoder)?;
        }
        if !self.qos_flow_to_release_list.is_empty() {
            // QosFlowListWithCause ::= SEQUENCE (SIZE(1..64)) OF QosFlowWithCauseItem
            encoder.encode_constrained_length(self.qos_flow_to_release_list.len(), 1, 64)?;
            for item in &self.qos_flow_to_release_list {
                item.encode(&mut encoder)?;
            }
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let tnl_present = decoder.read_bit()?;
        let si_present = decoder.read_bit()?;
        let sr_present = decoder.read_bit()?;
        let release_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;

        let ul_ngu_up_tnl_information = if tnl_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let security_indication = if si_present {
            Some(SecurityIndication::decode(&mut decoder)?)
        } else {
            None
        };
        let new_security_result = if sr_present {
            Some(SecurityResult::decode(&mut decoder)?)
        } else {
            None
        };
        let qos_flow_to_release_list = if release_present {
            let count = decoder.decode_constrained_length(1, 64)?;
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(QosFlowWithCauseItem::decode(&mut decoder)?);
            }
            list
        } else {
            Vec::new()
        };

        finish_extensible_sequence(&mut decoder, ext, ie_ext)?;
        Ok(Self {
            ul_ngu_up_tnl_information,
            security_indication,
            new_security_result,
            qos_flow_to_release_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_asn1c::ngap::cause::{CauseNas, CauseRadioNetwork};
    use proptest::prelude::*;

    fn sample_tunnel() -> UpTransportLayerInformation {
        UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4([10, 45, 0, 1]),
            gtp_teid: [0x00, 0x00, 0x12, 0x34],
        })
    }

    fn sample_qos_params() -> QosFlowLevelQosParameters {
        QosFlowLevelQosParameters {
            qos_characteristics: QosCharacteristics::NonDynamic5qi(NonDynamic5qiDescriptor::new(9)),
            allocation_and_retention_priority: AllocationAndRetentionPriority {
                priority_level_arp: 8,
                pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
            },
            gbr_qos_information: None,
            reflective_qos_attribute: false,
            additional_qos_flow_information: false,
        }
    }

    /// Build a minimal valid SetupRequestTransfer container (mandatory IEs only)
    /// and let the caller inject extra IEs, then return the encoded bytes.
    fn build_setup_request_container(
        extra: impl FnOnce(&mut ProtocolIeContainer) -> NgapResult<()>,
    ) -> NgapResult<Vec<u8>> {
        let mut container = ProtocolIeContainer::new();
        push_transfer_ie(
            &mut container,
            IE_ID_UL_NGU_UP_TNL_INFORMATION,
            Criticality::Reject,
            |enc| sample_tunnel().encode(enc),
        )?;
        extra(&mut container)?;
        push_transfer_ie(
            &mut container,
            IE_ID_PDU_SESSION_TYPE,
            Criticality::Reject,
            |enc| {
                enc.encode_enumerated(PduSessionType::Ipv4 as i64, &PduSessionType::CONSTRAINT)?;
                Ok(())
            },
        )?;
        push_transfer_ie(
            &mut container,
            IE_ID_QOS_FLOW_SETUP_REQUEST_LIST,
            Criticality::Reject,
            |enc| {
                enc.encode_constrained_length(1, 1, 64)?;
                QosFlowSetupRequestItem {
                    qos_flow_identifier: 1,
                    qos_flow_level_qos_parameters: sample_qos_params(),
                    e_rab_id: None,
                }
                .encode(enc)
            },
        )?;
        encode_container(&container)
    }

    /// NGAP-07: a SetupRequestTransfer carrying the Rel-15 multi-connectivity
    /// AdditionalUL-NGU-UP-TNLInformation (id 126, criticality reject) — formerly
    /// silently skipped — now decodes successfully (the IE is comprehended and
    /// validated, not treated as not-comprehended).
    #[test]
    fn test_setup_request_transfer_with_additional_ul_ngu() {
        let bytes = build_setup_request_container(|c| {
            push_transfer_ie(
                c,
                IE_ID_ADDITIONAL_UL_NGU_UP_TNL_INFORMATION,
                Criticality::Reject,
                |enc| {
                    // UPTransportLayerInformationList: 1 item, extensible item
                    // SEQUENCE preamble (ext=0, ie-ext=0), then a GTP tunnel.
                    enc.encode_constrained_length(1, 1, 3)?;
                    enc.write_bit(false);
                    enc.write_bit(false);
                    sample_tunnel().encode(enc)
                },
            )
        })
        .unwrap();
        let decoded = PduSessionResourceSetupRequestTransfer::decode(&bytes).unwrap();
        // Mandatory fields still parse; additional UL endpoints are validated then dropped.
        assert_eq!(decoded.pdu_session_type, PduSessionType::Ipv4);
        assert_eq!(decoded.qos_flow_setup_request_list.len(), 1);
    }

    /// NGAP-05: a not-comprehended IE drives decode by its criticality —
    /// reject is surfaced as IeNotComprehended, ignore is dropped and the rest
    /// of the (valid) transfer still decodes.
    #[test]
    fn test_setup_request_transfer_unknown_ie_criticality() {
        const UNKNOWN_IE_ID: u16 = 60000;

        let reject_bytes = build_setup_request_container(|c| {
            push_transfer_ie(c, UNKNOWN_IE_ID, Criticality::Reject, |enc| {
                enc.encode_octet_string(&[0xAB, 0xCD], None, None)?;
                Ok(())
            })
        })
        .unwrap();
        match PduSessionResourceSetupRequestTransfer::decode(&reject_bytes) {
            Err(NgapError::IeNotComprehended { ie_id, .. }) => assert_eq!(ie_id, UNKNOWN_IE_ID),
            other => panic!("expected IeNotComprehended, got {other:?}"),
        }

        let ignore_bytes = build_setup_request_container(|c| {
            push_transfer_ie(c, UNKNOWN_IE_ID, Criticality::Ignore, |enc| {
                enc.encode_octet_string(&[0xAB, 0xCD], None, None)?;
                Ok(())
            })
        })
        .unwrap();
        let decoded = PduSessionResourceSetupRequestTransfer::decode(&ignore_bytes).unwrap();
        assert_eq!(decoded.pdu_session_type, PduSessionType::Ipv4);
        assert_eq!(decoded.qos_flow_setup_request_list.len(), 1);
    }

    #[test]
    fn test_setup_request_transfer_roundtrip() {
        let transfer = PduSessionResourceSetupRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                dl: 1_000_000_000,
                ul: 500_000_000,
            }),
            ul_ngu_up_tnl_information: sample_tunnel(),
            data_forwarding_not_possible: false,
            direct_forwarding_path_availability: false,
            pdu_session_type: PduSessionType::Ipv4,
            security_indication: Some(SecurityIndication {
                integrity_protection_indication: ProtectionIndication::NotNeeded,
                confidentiality_protection_indication: ProtectionIndication::Required,
                maximum_integrity_protected_data_rate_ul: None,
            }),
            network_instance: None,
            qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
                qos_flow_identifier: 1,
                qos_flow_level_qos_parameters: sample_qos_params(),
                e_rab_id: None,
            }],
        };
        let bytes = transfer.encode().unwrap();
        assert!(!bytes.is_empty());
        let decoded = PduSessionResourceSetupRequestTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_setup_request_transfer_with_gbr_and_dynamic_5qi() {
        let transfer = PduSessionResourceSetupRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: None,
            ul_ngu_up_tnl_information: sample_tunnel(),
            data_forwarding_not_possible: true,
            direct_forwarding_path_availability: false,
            pdu_session_type: PduSessionType::Ipv4v6,
            security_indication: None,
            network_instance: Some(7),
            qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
                qos_flow_identifier: 63,
                qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                    qos_characteristics: QosCharacteristics::Dynamic5qi(Dynamic5qiDescriptor {
                        priority_level_qos: 42,
                        packet_delay_budget: 200,
                        per_scalar: 1,
                        per_exponent: 6,
                        five_qi: Some(82),
                        delay_critical: Some(DelayCritical::DelayCritical),
                        averaging_window: Some(2000),
                        maximum_data_burst_volume: Some(255),
                    }),
                    allocation_and_retention_priority: AllocationAndRetentionPriority {
                        priority_level_arp: 1,
                        pre_emption_capability: PreEmptionCapability::MayTriggerPreEmption,
                        pre_emption_vulnerability: PreEmptionVulnerability::PreEmptable,
                    },
                    gbr_qos_information: Some(GbrQosInformation {
                        maximum_flow_bit_rate_dl: 4_000_000_000_000,
                        maximum_flow_bit_rate_ul: 100_000,
                        guaranteed_flow_bit_rate_dl: 50_000_000,
                        guaranteed_flow_bit_rate_ul: 25_000_000,
                        notification_control: true,
                        maximum_packet_loss_rate_dl: Some(10),
                        maximum_packet_loss_rate_ul: None,
                    }),
                    reflective_qos_attribute: true,
                    additional_qos_flow_information: false,
                },
                e_rab_id: Some(5),
            }],
        };
        let bytes = transfer.encode().unwrap();
        let decoded = PduSessionResourceSetupRequestTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_setup_request_transfer_missing_mandatory_rejected() {
        // Encode a container holding only the PDU session type; the decoder
        // must reject it because UL TNL info and QoS flow list are mandatory
        let mut container = ProtocolIeContainer::new();
        push_transfer_ie(
            &mut container,
            IE_ID_PDU_SESSION_TYPE,
            Criticality::Reject,
            |enc| {
                enc.encode_enumerated(0, &PduSessionType::CONSTRAINT)?;
                Ok(())
            },
        )
        .unwrap();
        let bytes = encode_container(&container).unwrap();
        let result = PduSessionResourceSetupRequestTransfer::decode(&bytes);
        assert!(matches!(
            result,
            Err(NgapError::MissingMandatoryIe {
                ie_name: "UL-NGU-UP-TNLInformation",
                ..
            })
        ));
    }

    #[test]
    fn test_setup_response_transfer_roundtrip() {
        let transfer = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation {
                up_transport_layer_information: sample_tunnel(),
                associated_qos_flow_list: vec![AssociatedQosFlowItem {
                    qos_flow_identifier: 1,
                    qos_flow_mapping_indication: None,
                }],
            },
            additional_dl_qos_flow_per_tnl_information: Vec::new(),
            security_result: Some(SecurityResult {
                integrity_protection_result: ProtectionResult::Performed,
                confidentiality_protection_result: ProtectionResult::NotPerformed,
            }),
            qos_flow_failed_to_setup_list: vec![QosFlowWithCauseItem {
                qos_flow_identifier: 5,
                cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownQosFlowId),
            }],
        };
        let bytes = transfer.encode().unwrap();
        let decoded = PduSessionResourceSetupResponseTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_modify_request_transfer_roundtrip() {
        let transfer = PduSessionResourceModifyRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                dl: 200_000_000,
                ul: 100_000_000,
            }),
            ul_ngu_up_tnl_modify_list: vec![UlNguUpTnlModifyItem {
                ul_ngu_up_tnl_information: sample_tunnel(),
                dl_ngu_up_tnl_information: sample_tunnel(),
            }],
            network_instance: Some(1),
            qos_flow_add_or_modify_request_list: vec![QosFlowAddOrModifyRequestItem {
                qos_flow_identifier: 2,
                qos_flow_level_qos_parameters: Some(sample_qos_params()),
                e_rab_id: None,
            }],
            qos_flow_to_release_list: vec![QosFlowWithCauseItem {
                qos_flow_identifier: 3,
                cause: Cause::Nas(CauseNas::NormalRelease),
            }],
        };
        let bytes = transfer.encode().unwrap();
        let decoded = PduSessionResourceModifyRequestTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_modify_response_transfer_roundtrip() {
        let transfer = PduSessionResourceModifyResponseTransfer {
            dl_ngu_up_tnl_information: Some(sample_tunnel()),
            ul_ngu_up_tnl_information: None,
            qos_flow_add_or_modify_response_list: vec![QosFlowAddOrModifyResponseItem {
                qos_flow_identifier: 2,
            }],
            additional_dl_qos_flow_per_tnl_information: Vec::new(),
            qos_flow_failed_to_add_or_modify_list: Vec::new(),
        };
        let bytes = transfer.encode().unwrap();
        let decoded = PduSessionResourceModifyResponseTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_release_command_transfer_roundtrip() {
        let transfer = PduSessionResourceReleaseCommandTransfer {
            cause: Cause::Nas(CauseNas::NormalRelease),
        };
        let bytes = transfer.encode().unwrap();
        let decoded = PduSessionResourceReleaseCommandTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_release_response_transfer_roundtrip() {
        let transfer = PduSessionResourceReleaseResponseTransfer;
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes.len(), 1);
        let decoded = PduSessionResourceReleaseResponseTransfer::decode(&bytes).unwrap();
        assert_eq!(transfer, decoded);
    }

    #[test]
    fn test_ipv6_transport_layer_address_roundtrip() {
        let addr = TransportLayerAddress::from_ipv6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let tunnel = UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: addr,
            gtp_teid: [0xde, 0xad, 0xbe, 0xef],
        });
        let transfer = PduSessionResourceReleaseCommandTransfer {
            cause: Cause::Nas(CauseNas::NormalRelease),
        };
        // Tunnel round-trip via a modify response container
        let modify = PduSessionResourceModifyResponseTransfer {
            dl_ngu_up_tnl_information: Some(tunnel.clone()),
            ..Default::default()
        };
        let bytes = modify.encode().unwrap();
        let decoded = PduSessionResourceModifyResponseTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded.dl_ngu_up_tnl_information, Some(tunnel));
        // Sanity: command transfer still decodes
        let bytes = transfer.encode().unwrap();
        assert!(PduSessionResourceReleaseCommandTransfer::decode(&bytes).is_ok());
    }

    #[test]
    fn test_truncated_transfer_rejected() {
        let transfer = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation {
                up_transport_layer_information: sample_tunnel(),
                associated_qos_flow_list: vec![AssociatedQosFlowItem {
                    qos_flow_identifier: 1,
                    qos_flow_mapping_indication: None,
                }],
            },
            additional_dl_qos_flow_per_tnl_information: Vec::new(),
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        };
        let bytes = transfer.encode().unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(PduSessionResourceSetupResponseTransfer::decode(truncated).is_err());
        assert!(PduSessionResourceSetupRequestTransfer::decode(&[0xFF]).is_err());
    }

    /// Cross-codec: the target gNB (nextgsim-ngap) emits this
    /// PathSwitchRequestTransfer (DL F-TEID 0x00020002 / 10.46.0.1 / QFI 1);
    /// the SMF must decode it to re-point the UPF DL FAR after an Xn handover.
    #[test]
    fn test_path_switch_request_transfer_decodes_gnb_vector() {
        const GNB_PATH_SWITCH_TRANSFER: [u8; 12] = [
            0x00, 0x1f, 0x0a, 0x2e, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
        ];
        let t = PathSwitchRequestTransfer::decode(&GNB_PATH_SWITCH_TRANSFER).unwrap();
        let UpTransportLayerInformation::GtpTunnel(tun) = &t.dl_ngu_up_tnl_information;
        assert_eq!(u32::from_be_bytes(tun.gtp_teid), 0x0002_0002);
        assert_eq!(tun.transport_layer_address.octets, vec![10, 46, 0, 1]);
        assert_eq!(t.qos_flow_accepted_list, vec![1]);
    }

    #[test]
    fn test_path_switch_request_transfer_rejects_truncated() {
        assert!(PathSwitchRequestTransfer::decode(&[0x00]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        // NGAP-08: the outer *RequestTransfer SEQUENCE is extensible (`...`), so
        // APER must emit a leading extension-marker bit (0) and then octet-align
        // before the ProtocolIE-Container length determinant. With the ext bit
        // present, octet 0 is exactly 0x00 (the 0 bit + 7 alignment pad); if the
        // bit regressed away, the IE count would land in octet 0 instead. This
        // fences `encode_container`/`decode_container` against that regression.
        #[test]
        fn prop_setup_request_transfer_leading_ext_marker(
            dl in 1u64..=4_000_000_000_000,
            ul in 1u64..=4_000_000_000_000,
        ) {
            let transfer = PduSessionResourceSetupRequestTransfer {
                pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                    dl,
                    ul,
                }),
                ul_ngu_up_tnl_information: sample_tunnel(),
                data_forwarding_not_possible: false,
                direct_forwarding_path_availability: false,
                pdu_session_type: PduSessionType::Ipv4,
                security_indication: None,
                network_instance: None,
                qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
                    qos_flow_identifier: 1,
                    qos_flow_level_qos_parameters: sample_qos_params(),
                    e_rab_id: None,
                }],
            };
            let bytes = transfer.encode().unwrap();
            prop_assert_eq!(bytes[0], 0x00);
            let decoded = PduSessionResourceSetupRequestTransfer::decode(&bytes).unwrap();
            prop_assert_eq!(decoded, transfer);
        }
    }
    // ------------------------------------------------------------------
    // PathSwitchRequestAcknowledgeTransfer (#70, TS 38.413 §9.3.4.9)
    // ------------------------------------------------------------------

    /// Every member is OPTIONAL, so the empty transfer must round-trip — it is the honest
    /// encoding for a path switch where the UL tunnel did not move.
    #[test]
    fn path_switch_ack_transfer_round_trips_empty() {
        let empty = PathSwitchRequestAcknowledgeTransfer::default();
        let bytes = empty.encode().expect("encode");
        let decoded = PathSwitchRequestAcknowledgeTransfer::decode(&bytes).expect("decode");
        assert_eq!(decoded, empty);
        assert!(decoded.ul_ngu_up_tnl_information.is_none());
        assert!(decoded.qos_flow_to_release_list.is_empty());
    }

    /// The member that matters: the UL tunnel the target gNB must send uplink to.
    #[test]
    fn path_switch_ack_transfer_round_trips_the_ul_tunnel() {
        let transfer = PathSwitchRequestAcknowledgeTransfer {
            ul_ngu_up_tnl_information: Some(sample_tunnel()),
            ..Default::default()
        };
        let bytes = transfer.encode().expect("encode");
        let decoded = PathSwitchRequestAcknowledgeTransfer::decode(&bytes).expect("decode");
        assert_eq!(decoded, transfer);
        assert_eq!(
            decoded.ul_ngu_up_tnl_information,
            Some(sample_tunnel()),
            "the UPF endpoint must survive: it is the whole point of the acknowledge"
        );
    }

    /// All members together, so the present-bit order in the preamble is exercised.
    ///
    /// Order matters and a wrong one is silent: with only one member set, any preamble
    /// ordering decodes back to the same value, so a permutation would pass. Setting all
    /// of them is what pins the sequence.
    #[test]
    fn path_switch_ack_transfer_round_trips_every_member() {
        let transfer = PathSwitchRequestAcknowledgeTransfer {
            ul_ngu_up_tnl_information: Some(sample_tunnel()),
            security_indication: Some(SecurityIndication {
                integrity_protection_indication: ProtectionIndication::Required,
                confidentiality_protection_indication: ProtectionIndication::Preferred,
                maximum_integrity_protected_data_rate_ul: Some(
                    MaximumIntegrityProtectedDataRate::Bitrate64kbs,
                ),
            }),
            new_security_result: Some(SecurityResult {
                integrity_protection_result: ProtectionResult::Performed,
                confidentiality_protection_result: ProtectionResult::NotPerformed,
            }),
            qos_flow_to_release_list: vec![QosFlowWithCauseItem {
                qos_flow_identifier: 5,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            }],
        };
        let bytes = transfer.encode().expect("encode");
        let decoded = PathSwitchRequestAcknowledgeTransfer::decode(&bytes).expect("decode");
        assert_eq!(decoded, transfer);
    }

    /// The acknowledge and the request are DIFFERENT transfers, which is the defect #70
    /// names: the AMF echoed the request back as the acknowledge.
    ///
    /// Decoding an acknowledge's bytes as a request (or the reverse) must not quietly
    /// succeed with plausible contents — that is what made the echo invisible.
    #[test]
    fn an_acknowledge_transfer_is_not_a_request_transfer() {
        let ack = PathSwitchRequestAcknowledgeTransfer {
            ul_ngu_up_tnl_information: Some(sample_tunnel()),
            ..Default::default()
        };
        let ack_bytes = ack.encode().expect("encode");

        // The request has a 4-bit preamble and two MANDATORY members; the acknowledge has
        // a 6-bit preamble and none. They cannot be the same bytes for the same tunnel.
        match PathSwitchRequestTransfer::decode(&ack_bytes) {
            Err(_) => {}
            Ok(req) => assert_ne!(
                req.dl_ngu_up_tnl_information,
                sample_tunnel(),
                "an acknowledge must not decode as a request naming the same tunnel — if it \
                 did, echoing one for the other would be undetectable on the wire"
            ),
        }
    }

    /// GBR-QosInformation with every bit rate 0, no Notification Control, and
    /// both loss rates present (DL 1000, UL 0), derived by hand from X.691:
    ///
    /// - preamble: extension 0, notificationControl 0, maximumPacketLossRateDL 1,
    ///   maximumPacketLossRateUL 1, iE-Extensions 0 -- `00110`;
    /// - each BitRate ::= INTEGER (0..4000000000000, ...): extension bit 0, then
    ///   the range (> 64K) takes the length-prefixed form -- the octet count of a
    ///   value of up to 6 octets as a 3-bit field (1 octet -> `000`), octet
    ///   alignment, then the value octet `00`. The first rate completes octet 0
    ///   as `00110 0 00` = 0x30 with its last length bit in octet 1, so it is
    ///   `30 00 00`; the next three are `00 00` each;
    /// - PacketLossRate ::= INTEGER (0..1000, ...) is EXTENSIBLE (§9.3.1.83): an
    ///   extension bit 0, then the 1001-value range takes two aligned octets --
    ///   `00 03 e8` for 1000 and `00 00 00` for 0.
    ///
    /// The non-extensible reading drops each loss rate's extension bit and so
    /// its padding octet: `03 e8 00 00`, two octets shorter.
    #[test]
    fn packet_loss_rate_carries_its_extension_bit() {
        const GOLDEN: [u8; 15] = [
            0x30, 0x00, 0x00, // preamble + maximumFlowBitRateDL 0
            0x00, 0x00, // maximumFlowBitRateUL 0
            0x00, 0x00, // guaranteedFlowBitRateDL 0
            0x00, 0x00, // guaranteedFlowBitRateUL 0
            0x00, 0x03, 0xe8, // maximumPacketLossRateDL: ext 0, pad, 1000
            0x00, 0x00, 0x00, // maximumPacketLossRateUL: ext 0, pad, 0
        ];
        let gbr = GbrQosInformation {
            maximum_flow_bit_rate_dl: 0,
            maximum_flow_bit_rate_ul: 0,
            guaranteed_flow_bit_rate_dl: 0,
            guaranteed_flow_bit_rate_ul: 0,
            notification_control: false,
            maximum_packet_loss_rate_dl: Some(1000),
            maximum_packet_loss_rate_ul: Some(0),
        };
        let mut encoder = AperEncoder::new();
        gbr.encode(&mut encoder).expect("encode");
        encoder.align();
        assert_eq!(encoder.into_bytes().to_vec(), GOLDEN.to_vec());
        let mut decoder = AperDecoder::new(&GOLDEN);
        assert_eq!(
            GbrQosInformation::decode(&mut decoder).expect("decode"),
            gbr
        );
    }

    fn per_tnl(address: [u8; 4], teid: u32, qfi: u8) -> QosFlowPerTnlInformation {
        QosFlowPerTnlInformation {
            up_transport_layer_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                transport_layer_address: TransportLayerAddress::from_ipv4(address),
                gtp_teid: teid.to_be_bytes(),
            }),
            associated_qos_flow_list: vec![AssociatedQosFlowItem {
                qos_flow_identifier: qfi,
                qos_flow_mapping_indication: None,
            }],
        }
    }

    /// A dual-connectivity Setup Response Transfer -- DL tunnel 10.45.0.3 /
    /// 0xdeadbeef and one additional DL tunnel 10.45.0.4 / 2, both carrying QFI 9
    /// -- derived by hand from X.691:
    ///
    /// - octet 0 `40`: transfer preamble (extension 0, additionalDL 1, security 0,
    ///   failed 0, iE-Extensions 0) `01000`, QosFlowPerTNLInformation preamble
    ///   `00`, UPTransportLayerInformation CHOICE index 0 of 2 `0`;
    /// - `03 e0`: GTPTunnel preamble `00`, TransportLayerAddress extension bit `0`,
    ///   SIZE(1..160) length 32 as the 8-bit field 31 `00011111`, then octet
    ///   alignment (the string's ub exceeds 16 bits); `0a 2d 00 03`, TEID
    ///   `de ad be ef` (fixed 4 octets, aligned);
    /// - `00 09`: AssociatedQosFlowList SIZE(1..64) count 1 as `000000`, item
    ///   preamble `000`, QFI extension bit `0` and 9 as `001001`;
    /// - the additional list: SIZE(1..maxnoofMultiConnectivityMinusOne=3) count 1
    ///   as `00`, QosFlowPerTNLInformationItem preamble `00`, then the same
    ///   QosFlowPerTNLInformation shape -- `00 07 c0`, `0a 2d 00 04`,
    ///   `00 00 00 02`, `00 09`.
    ///
    /// Reading the list as a single QosFlowPerTNLInformation drops its count and
    /// the item preamble, which is how the old decoder came to a 2-bit address.
    const DUAL_CONNECTIVITY_SETUP_RESPONSE: [u8; 26] = [
        // DL QoS Flow per TNL Information
        0x40, 0x03, 0xe0, 0x0a, 0x2d, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x09,
        // Additional DL QoS Flow per TNL Information, a list of one
        0x00, 0x07, 0xc0, 0x0a, 0x2d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09,
    ];

    #[test]
    fn additional_dl_qos_flow_per_tnl_information_is_a_list() {
        let transfer = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: per_tnl([10, 45, 0, 3], 0xdead_beef, 9),
            additional_dl_qos_flow_per_tnl_information: vec![per_tnl([10, 45, 0, 4], 2, 9)],
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        };
        assert_eq!(
            transfer.encode().expect("encode"),
            DUAL_CONNECTIVITY_SETUP_RESPONSE.to_vec()
        );
        assert_eq!(
            PduSessionResourceSetupResponseTransfer::decode(&DUAL_CONNECTIVITY_SETUP_RESPONSE)
                .expect("decode"),
            transfer
        );
    }

    /// 1..3 additional tunnels round-trip on both response transfers; 0 is
    /// "absent" and 4 exceeds maxnoofMultiConnectivityMinusOne.
    #[test]
    fn additional_dl_tunnel_lists_round_trip_and_are_bounded() {
        for n in 1..=3u8 {
            let additional: Vec<_> = (0..n)
                .map(|i| per_tnl([10, 45, 1, i], 0x100 + u32::from(i), 1 + i))
                .collect();
            let setup = PduSessionResourceSetupResponseTransfer {
                dl_qos_flow_per_tnl_information: per_tnl([10, 45, 0, 3], 1, 9),
                additional_dl_qos_flow_per_tnl_information: additional.clone(),
                security_result: None,
                qos_flow_failed_to_setup_list: Vec::new(),
            };
            let bytes = setup.encode().expect("encode");
            assert_eq!(
                PduSessionResourceSetupResponseTransfer::decode(&bytes).expect("decode"),
                setup,
                "{n} additional"
            );
            let modify = PduSessionResourceModifyResponseTransfer {
                additional_dl_qos_flow_per_tnl_information: additional,
                ..Default::default()
            };
            let bytes = modify.encode().expect("encode");
            assert_eq!(
                PduSessionResourceModifyResponseTransfer::decode(&bytes).expect("decode"),
                modify,
                "{n} additional"
            );
        }
        let too_many = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: per_tnl([10, 45, 0, 3], 1, 9),
            additional_dl_qos_flow_per_tnl_information: vec![per_tnl([10, 45, 1, 0], 1, 1); 4],
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        };
        assert!(too_many.encode().is_err());
    }

    /// Every PacketLossRate in the root, DL and UL, round-trips; the boundary
    /// values sit on both sides of an octet boundary in the encoding.
    #[test]
    fn packet_loss_rates_round_trip_across_the_root() {
        for dl in [
            None,
            Some(0u16),
            Some(1),
            Some(255),
            Some(256),
            Some(999),
            Some(1000),
        ] {
            for ul in [None, Some(0u16), Some(500), Some(1000)] {
                for notification_control in [false, true] {
                    let gbr = GbrQosInformation {
                        maximum_flow_bit_rate_dl: 64_000,
                        maximum_flow_bit_rate_ul: 4_000_000_000_000,
                        guaranteed_flow_bit_rate_dl: 0,
                        guaranteed_flow_bit_rate_ul: 1,
                        notification_control,
                        maximum_packet_loss_rate_dl: dl,
                        maximum_packet_loss_rate_ul: ul,
                    };
                    let mut encoder = AperEncoder::new();
                    gbr.encode(&mut encoder).expect("encode");
                    encoder.align();
                    let bytes = encoder.into_bytes().to_vec();
                    let mut decoder = AperDecoder::new(&bytes);
                    assert_eq!(
                        GbrQosInformation::decode(&mut decoder).expect("decode"),
                        gbr
                    );
                }
            }
        }
        let out_of_root = GbrQosInformation {
            maximum_flow_bit_rate_dl: 0,
            maximum_flow_bit_rate_ul: 0,
            guaranteed_flow_bit_rate_dl: 0,
            guaranteed_flow_bit_rate_ul: 0,
            notification_control: false,
            maximum_packet_loss_rate_dl: Some(1001),
            maximum_packet_loss_rate_ul: None,
        };
        assert!(out_of_root.encode(&mut AperEncoder::new()).is_err());
    }

    // ------------------------------------------------------------------------
    // #469: iE-Extensions and extension additions are consumed, not skipped
    // past. Every octet below is derived by hand from X.691, not from an
    // encoder, and each case ends with a 0x2A sentinel octet: a decoder that
    // leaves the extension unread lands on the wrong bits and does not find it.
    // ------------------------------------------------------------------------

    /// Decode an ARP from `bytes`, then require the sentinel octet and nothing else.
    fn decode_arp_then_sentinel(bytes: &[u8]) -> NgapResult<AllocationAndRetentionPriority> {
        let mut decoder = AperDecoder::new(bytes);
        let arp = AllocationAndRetentionPriority::decode(&mut decoder)?;
        decoder.align();
        assert_eq!(decoder.read_bits(8).expect("sentinel"), 0x2A, "sentinel");
        assert_eq!(decoder.remaining_bits(), 0, "trailing bits");
        Ok(arp)
    }

    fn arp_level_1() -> AllocationAndRetentionPriority {
        AllocationAndRetentionPriority {
            priority_level_arp: 1,
            pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
            pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
        }
    }

    // ARP with an iE-Extensions container holding one unknown extension
    // (id 999, one-octet value 0x00):
    //   ext 0, iE-Extensions present 1                       01
    //   priorityLevelARP 1 -> 0 in 4 bits (range 15)          0000
    //   pre-emptionCapability: ext 0, index 0                 00
    //   pre-emptionVulnerability: ext 0, index 0              00   -> 10 bits, pad -> 40 00
    //   container count-1 = 0, two-octet aligned (ub 65535)   00 00
    //   id 999, two-octet aligned (range 65536)               03 E7
    //   criticality, 2 bits, then pad: ignore=01 -> 40, reject=00 -> 00
    //   open type: length 1, value 00                         01 00
    const ARP_WITH_IGNORE_EXTENSION: [u8; 10] =
        [0x40, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x40, 0x01, 0x00, 0x2A];
    const ARP_WITH_NOTIFY_EXTENSION: [u8; 10] =
        [0x40, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x80, 0x01, 0x00, 0x2A];
    const ARP_WITH_REJECT_EXTENSION: [u8; 10] =
        [0x40, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x00, 0x2A];

    #[test]
    fn an_ignorable_ie_extension_is_consumed() {
        assert_eq!(
            decode_arp_then_sentinel(&ARP_WITH_IGNORE_EXTENSION).expect("decode"),
            arp_level_1()
        );
        assert_eq!(
            decode_arp_then_sentinel(&ARP_WITH_NOTIFY_EXTENSION).expect("decode"),
            arp_level_1()
        );
    }

    #[test]
    fn a_reject_ie_extension_that_is_not_comprehended_fails_the_decode() {
        let mut decoder = AperDecoder::new(&ARP_WITH_REJECT_EXTENSION);
        match AllocationAndRetentionPriority::decode(&mut decoder) {
            Err(NgapError::IeNotComprehended { ie_id, .. }) => assert_eq!(ie_id, 999),
            other => panic!("expected IeNotComprehended(999), got {other:?}"),
        }
    }

    // ARP with the SEQUENCE extension bit set and one extension addition:
    //   ext 1, iE-Extensions 0, then the same 8 root bits     10 00000000
    //   normally-small count-1 = 0: 0 + 000000                0000000
    //   presence bitmap: 1                                    1    -> 18 bits, pad -> 80 00 40
    //   open type: length 1, value 00                         01 00
    const ARP_WITH_EXTENSION_ADDITION: [u8; 6] = [0x80, 0x00, 0x40, 0x01, 0x00, 0x2A];

    #[test]
    fn extension_additions_are_consumed() {
        assert_eq!(
            decode_arp_then_sentinel(&ARP_WITH_EXTENSION_ADDITION).expect("decode"),
            arp_level_1()
        );
    }

    #[test]
    fn a_sequence_without_extensions_still_decodes_exactly() {
        // ext 0, iE-Ext 0, then the 8 root bits: 10 bits, pad -> 00 00
        assert_eq!(
            decode_arp_then_sentinel(&[0x00, 0x00, 0x2A]).expect("decode"),
            arp_level_1()
        );
    }

    // NonDynamic5QIDescriptor { fiveQI 9, maximumDataBurstVolume v }:
    //   ext 0, priority 0, averaging 0, MDBV 1, iE-Ext 0      00010
    //   fiveQI ext 0, then one-octet aligned (range 256)      0 -> pad -> 10, 09
    //   MDBV root (0..4095): ext 0, two-octet aligned         00, 0F FF
    //   MDBV extension: ext 1, then an unconstrained whole
    //   number: aligned length octet + minimal 2's complement 80, 02 10 00 / 80, 03 1E 84 80
    fn mdbv_descriptor(v: u32) -> NonDynamic5qiDescriptor {
        NonDynamic5qiDescriptor {
            five_qi: 9,
            priority_level_qos: None,
            averaging_window: None,
            maximum_data_burst_volume: Some(v),
        }
    }

    fn encode_descriptor(d: &NonDynamic5qiDescriptor) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        d.encode(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    #[test]
    fn maximum_data_burst_volume_encodes_its_extension_range() {
        for (v, golden) in [
            (0u32, vec![0x10, 0x09, 0x00, 0x00, 0x00]),
            (4095, vec![0x10, 0x09, 0x00, 0x0F, 0xFF]),
            (4096, vec![0x10, 0x09, 0x80, 0x02, 0x10, 0x00]),
            (2_000_000, vec![0x10, 0x09, 0x80, 0x03, 0x1E, 0x84, 0x80]),
        ] {
            let d = mdbv_descriptor(v);
            assert_eq!(encode_descriptor(&d).expect("encode"), golden, "MDBV {v}");
            let mut decoder = AperDecoder::new(&golden);
            assert_eq!(
                NonDynamic5qiDescriptor::decode(&mut decoder).expect("decode"),
                d
            );
        }
    }

    #[test]
    fn maximum_data_burst_volume_past_the_extension_range_is_refused() {
        assert!(encode_descriptor(&mdbv_descriptor(2_000_001)).is_err());
        // 3000000 = 0x2DC6C0 as an extension value
        let bytes = [0x10, 0x09, 0x80, 0x03, 0x2D, 0xC6, 0xC0];
        let mut decoder = AperDecoder::new(&bytes);
        assert!(NonDynamic5qiDescriptor::decode(&mut decoder).is_err());
    }

    // ---- #475: HandoverRequestAcknowledgeTransfer, DirectForwardingPathAvailability ----

    fn ipv4_tunnel(addr: [u8; 4], teid: u32) -> UpTransportLayerInformation {
        UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4(addr),
            gtp_teid: teid.to_be_bytes(),
        })
    }

    /// The smallest HandoverRequestAcknowledgeTransfer, derived bit by bit from X.691
    /// (APER) and TS 38.413 §9.3.4.11, not captured from the encoder:
    ///
    /// ```text
    /// SEQUENCE ext 0 | 5 OPTIONAL bits 00000            -> 0 00000
    /// dL-NGU: CHOICE (2 alts, not extensible) idx 0      -> 0
    ///   GTPTunnel ext 0 | iE-Extensions 0                -> 0 0
    ///   TransportLayerAddress ext 0 | len-1 in 8 bits 31 -> 0 00011111 | pad to octet
    ///   address 0A 01 02 03 | GTP-TEID SIZE(4) 0000ABCD
    /// qosFlowSetupResponseList: count-1 in 6 bits        -> 000000
    ///   item ext 0 | dataForwardingAccepted 0 | ext 0    -> 0 0 0
    ///   QFI ext 0 | 6 bits = 5                           -> 0 000101
    /// ```
    ///
    /// Octets 1-3: `00000000 00000111 11000000` = `00 07 C0`.
    #[test]
    fn handover_request_acknowledge_transfer_golden_bytes() {
        let transfer = HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: ipv4_tunnel([10, 1, 2, 3], 0xABCD),
            dl_forwarding_up_tnl_information: None,
            security_result: None,
            qos_flow_setup_response_list: vec![QosFlowItemWithDataForwarding {
                qos_flow_identifier: 5,
                data_forwarding_accepted: false,
            }],
            qos_flow_failed_to_setup_list: Vec::new(),
            data_forwarding_response_drb_list: Vec::new(),
        };
        let golden = [
            0x00, 0x07, 0xC0, 0x0A, 0x01, 0x02, 0x03, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x05,
        ];
        assert_eq!(transfer.encode().unwrap(), golden);
        assert_eq!(
            HandoverRequestAcknowledgeTransfer::decode(&golden).unwrap(),
            transfer
        );
    }

    /// Every optional member present round-trips, and a decoder that left one unread would
    /// fail on the trailing members.
    #[test]
    fn handover_request_acknowledge_transfer_round_trips_every_member() {
        let transfer = HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: ipv4_tunnel([10, 1, 2, 3], 0xABCD),
            dl_forwarding_up_tnl_information: Some(ipv4_tunnel([10, 9, 9, 9], 7)),
            security_result: Some(SecurityResult {
                integrity_protection_result: ProtectionResult::Performed,
                confidentiality_protection_result: ProtectionResult::NotPerformed,
            }),
            qos_flow_setup_response_list: vec![
                QosFlowItemWithDataForwarding {
                    qos_flow_identifier: 5,
                    data_forwarding_accepted: true,
                },
                QosFlowItemWithDataForwarding {
                    qos_flow_identifier: 63,
                    data_forwarding_accepted: false,
                },
            ],
            qos_flow_failed_to_setup_list: vec![QosFlowWithCauseItem {
                qos_flow_identifier: 6,
                cause: Cause::RadioNetwork(
                    nextgcore_asn1c::ngap::cause::CauseRadioNetwork::Unspecified,
                ),
            }],
            data_forwarding_response_drb_list: vec![DataForwardingResponseDrbItem {
                drb_id: 32,
                dl_forwarding_up_tnl_information: Some(ipv4_tunnel([10, 8, 8, 8], 9)),
                ul_forwarding_up_tnl_information: None,
            }],
        };
        let bytes = transfer.encode().unwrap();
        assert_eq!(
            HandoverRequestAcknowledgeTransfer::decode(&bytes).unwrap(),
            transfer
        );
    }

    /// DirectForwardingPathAvailability rides IE 22 with criticality ignore, after the QoS
    /// flow list (object-set order), and round-trips.
    #[test]
    fn setup_request_transfer_carries_direct_forwarding_path_availability() {
        let mut transfer = PduSessionResourceSetupRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: None,
            ul_ngu_up_tnl_information: ipv4_tunnel([10, 45, 0, 1], 0x1289),
            data_forwarding_not_possible: false,
            pdu_session_type: PduSessionType::Ipv4,
            security_indication: None,
            network_instance: None,
            qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
                qos_flow_identifier: 5,
                qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                    qos_characteristics: QosCharacteristics::NonDynamic5qi(
                        NonDynamic5qiDescriptor::new(9),
                    ),
                    allocation_and_retention_priority: AllocationAndRetentionPriority {
                        priority_level_arp: 8,
                        pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                        pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                    },
                    gbr_qos_information: None,
                    reflective_qos_attribute: false,
                    additional_qos_flow_information: false,
                },
                e_rab_id: Some(5),
            }],
            direct_forwarding_path_availability: false,
        };
        let without = transfer.encode().unwrap();
        transfer.direct_forwarding_path_availability = true;
        let with = transfer.encode().unwrap();
        // The container count goes from 3 to 4, and the last field is `00 16 40 01 00`:
        // id 22, criticality ignore (01 -> 0x40), open-type length 1, the one-bit ENUMERATED
        // (ext 0, no root bits) padded to an octet.
        assert_eq!(&with[with.len() - 5..], &[0x00, 0x16, 0x40, 0x01, 0x00]);
        assert_eq!(with.len(), without.len() + 5);
        let decoded = PduSessionResourceSetupRequestTransfer::decode(&with).unwrap();
        assert!(decoded.direct_forwarding_path_availability);
        assert_eq!(decoded, transfer);
    }
}
