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
const IE_ID_UL_NGU_UP_TNL_MODIFY_LIST: u16 = 140;
const IE_ID_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST: u16 = 135;
const IE_ID_QOS_FLOW_TO_RELEASE_LIST: u16 = 137;

// BitRate ::= INTEGER (0..4000000000000, ...)
const BIT_RATE_MAX: i64 = 4_000_000_000_000;

// ============================================================================
// Shared primitive helpers
// ============================================================================

/// Encode an extensible constrained INTEGER (extension bit + root encoding)
fn encode_ext_constrained(
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
fn decode_ext_constrained(decoder: &mut AperDecoder, min: i64, max: i64) -> NgapResult<i64> {
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

fn invalid(ie_name: &'static str, reason: String) -> NgapError {
    NgapError::InvalidIeValue { ie_name, reason }
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

    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
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

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
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
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
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

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let choice = decoder.decode_choice_index(2, false)?;
        if choice != 0 {
            return Err(invalid(
                "UPTransportLayerInformation",
                format!("Unsupported choice index: {choice}"),
            ));
        }
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let transport_layer_address = TransportLayerAddress::decode(decoder)?;
        let teid_bytes = decoder.decode_octet_string(Some(4), Some(4))?;
        let mut gtp_teid = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_bytes);
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
        let _ext = decoder.read_bit()?; // item extension marker
        let _ie_ext = decoder.read_bit()?; // no iE-Extensions
        list.push(UpTransportLayerInformation::decode(decoder)?);
    }
    Ok(list)
}

// ============================================================================
// QoS types
// ============================================================================

/// NonDynamic5QIDescriptor (TS 38.413 Section 9.3.1.28)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonDynamic5qiDescriptor {
    /// 5QI value (0..255)
    pub five_qi: u16,
    /// Priority Level QoS (1..127, optional)
    pub priority_level_qos: Option<u8>,
    /// Averaging Window in ms (0..4095, optional)
    pub averaging_window: Option<u16>,
    /// Maximum Data Burst Volume in bytes (0..4095, optional)
    pub maximum_data_burst_volume: Option<u16>,
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
            encode_ext_constrained(encoder, v as i64, 0, 4095)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let _ext = decoder.read_bit()?;
        let prio_present = decoder.read_bit()?;
        let avg_present = decoder.read_bit()?;
        let burst_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
            Some(decode_ext_constrained(decoder, 0, 4095)? as u16)
        } else {
            None
        };
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
    /// Maximum Data Burst Volume (conditional)
    pub maximum_data_burst_volume: Option<u16>,
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
            encode_ext_constrained(encoder, v as i64, 0, 4095)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let _ext = decoder.read_bit()?;
        let five_qi_present = decoder.read_bit()?;
        let dc_present = decoder.read_bit()?;
        let avg_present = decoder.read_bit()?;
        let burst_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let priority_level_qos = decode_ext_constrained(decoder, 1, 127)? as u8;
        let packet_delay_budget = decode_ext_constrained(decoder, 0, 1023)? as u16;
        let _per_ext = decoder.read_bit()?;
        let _per_ie_ext = decoder.read_bit()?;
        let per_scalar = decode_ext_constrained(decoder, 0, 9)? as u8;
        let per_exponent = decode_ext_constrained(decoder, 0, 9)? as u8;
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
            Some(decode_ext_constrained(decoder, 0, 4095)? as u16)
        } else {
            None
        };
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let loss_constraint = Constraint::new(0, 1000);
        if let Some(dl) = self.maximum_packet_loss_rate_dl {
            encoder.encode_constrained_whole_number(dl as i64, &loss_constraint)?;
        }
        if let Some(ul) = self.maximum_packet_loss_rate_ul {
            encoder.encode_constrained_whole_number(ul as i64, &loss_constraint)?;
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let _ext = decoder.read_bit()?;
        let notif_present = decoder.read_bit()?;
        let dl_present = decoder.read_bit()?;
        let ul_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let maximum_flow_bit_rate_dl = decode_bit_rate(decoder)?;
        let maximum_flow_bit_rate_ul = decode_bit_rate(decoder)?;
        let guaranteed_flow_bit_rate_dl = decode_bit_rate(decoder)?;
        let guaranteed_flow_bit_rate_ul = decode_bit_rate(decoder)?;
        if notif_present {
            let constraint = Constraint::extensible(0, 0);
            let _notif = decoder.decode_enumerated(&constraint)?;
        }
        let loss_constraint = Constraint::new(0, 1000);
        let maximum_packet_loss_rate_dl = if dl_present {
            Some(decoder.decode_constrained_whole_number(&loss_constraint)? as u16)
        } else {
            None
        };
        let maximum_packet_loss_rate_ul = if ul_present {
            Some(decoder.decode_constrained_whole_number(&loss_constraint)? as u16)
        } else {
            None
        };
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
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
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

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let _ext = decoder.read_bit()?;
        let gbr_present = decoder.read_bit()?;
        let reflective_present = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        Ok(Self {
            qos_characteristics,
            allocation_and_retention_priority,
            gbr_qos_information,
            reflective_qos_attribute: reflective_present,
            additional_qos_flow_information: additional_present,
        })
    }
}

fn encode_qfi(encoder: &mut AperEncoder, qfi: u8) -> NgapResult<()> {
    encode_ext_constrained(encoder, qfi as i64, 0, 63)
}

fn decode_qfi(decoder: &mut AperDecoder) -> NgapResult<u8> {
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
        let _ext = decoder.read_bit()?;
        let erab_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let qos_flow_level_qos_parameters = QosFlowLevelQosParameters::decode(decoder)?;
        let e_rab_id = if erab_present {
            Some(decode_ext_constrained(decoder, 0, 15)? as u8)
        } else {
            None
        };
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
        let _ext = decoder.read_bit()?;
        let mapping_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let up_transport_layer_information = UpTransportLayerInformation::decode(decoder)?;
        let count = decoder.decode_constrained_length(1, 64)?;
        let mut associated_qos_flow_list = Vec::with_capacity(count);
        for _ in 0..count {
            associated_qos_flow_list.push(AssociatedQosFlowItem::decode(decoder)?);
        }
        Ok(Self {
            up_transport_layer_information,
            associated_qos_flow_list,
        })
    }
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
        let cause = Cause::decode_aper(decoder)?;
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
        let _ext = decoder.read_bit()?;
        let rate_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let dl = decode_bit_rate(decoder)?;
        let ul = decode_bit_rate(decoder)?;
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
    // Consume the outer SEQUENCE extension-presence bit (see encode_container).
    let _ext = decoder.read_bit()?;
    Ok(ProtocolIeContainer::decode_aper(&mut decoder)?)
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
        for field in &container.ies {
            let mut decoder = AperDecoder::new(&field.value);
            match field.id.0 {
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
                    let _additional =
                        decode_additional_ul_ngu_up_tnl_information(&mut decoder)?;
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
    /// Additional DL QoS Flow per TNL Information (optional)
    pub additional_dl_qos_flow_per_tnl_information: Option<QosFlowPerTnlInformation>,
    /// Security Result (optional)
    pub security_result: Option<SecurityResult>,
    /// QoS Flow Failed To Setup List (optional, empty = absent)
    pub qos_flow_failed_to_setup_list: Vec<QosFlowWithCauseItem>,
}

impl PduSessionResourceSetupResponseTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension
        encoder.write_bit(self.additional_dl_qos_flow_per_tnl_information.is_some());
        encoder.write_bit(self.security_result.is_some());
        encoder.write_bit(!self.qos_flow_failed_to_setup_list.is_empty());
        encoder.write_bit(false); // no iE-Extensions
        self.dl_qos_flow_per_tnl_information.encode(&mut encoder)?;
        if let Some(ref additional) = self.additional_dl_qos_flow_per_tnl_information {
            additional.encode(&mut encoder)?;
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
        let _ext = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let security_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let dl_qos_flow_per_tnl_information = QosFlowPerTnlInformation::decode(&mut decoder)?;
        let additional_dl_qos_flow_per_tnl_information = if additional_present {
            Some(QosFlowPerTnlInformation::decode(&mut decoder)?)
        } else {
            None
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
        Ok(Self {
            dl_qos_flow_per_tnl_information,
            additional_dl_qos_flow_per_tnl_information,
            security_result,
            qos_flow_failed_to_setup_list,
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let ul_ngu_up_tnl_information = UpTransportLayerInformation::decode(decoder)?;
        let dl_ngu_up_tnl_information = UpTransportLayerInformation::decode(decoder)?;
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
        let _ext = decoder.read_bit()?;
        let params_present = decoder.read_bit()?;
        let erab_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let qos_flow_identifier = decode_qfi(decoder)?;
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
    /// Additional DL QoS Flow per TNL Information (optional)
    pub additional_dl_qos_flow_per_tnl_information: Option<QosFlowPerTnlInformation>,
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
        encoder.write_bit(self.additional_dl_qos_flow_per_tnl_information.is_some());
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
        if let Some(ref additional) = self.additional_dl_qos_flow_per_tnl_information {
            additional.encode(&mut encoder)?;
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
        let _ext = decoder.read_bit()?;
        let dl_present = decoder.read_bit()?;
        let ul_present = decoder.read_bit()?;
        let response_present = decoder.read_bit()?;
        let additional_present = decoder.read_bit()?;
        let failed_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
            Some(QosFlowPerTnlInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let qos_flow_failed_to_add_or_modify_list = if failed_present {
            decode_qos_flow_with_cause_list(&mut decoder)?
        } else {
            Vec::new()
        };
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let cause = Cause::decode_aper(&mut decoder)?;
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
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
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
        let _ext = decoder.read_bit()?;
        let reused_present = decoder.read_bit()?;
        let security_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;

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
            let _item_ext = decoder.read_bit()?;
            let _item_ie_ext = decoder.read_bit()?;
            qos_flow_accepted_list.push(decode_qfi(&mut decoder)?);
        }

        Ok(Self {
            dl_ngu_up_tnl_information,
            qos_flow_accepted_list,
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
            additional_dl_qos_flow_per_tnl_information: None,
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
            additional_dl_qos_flow_per_tnl_information: None,
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
            additional_dl_qos_flow_per_tnl_information: None,
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
}
