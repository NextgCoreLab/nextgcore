//! MBS N2 transfer containers (TS 38.413 §9.3.5.7 - §9.3.5.10)
//!
//! APER encode/decode for the four MBS Distribution transfer containers that
//! the MB-SMF and AMF exchange opaquely (OCTET STRING) over
//! Nmbsmf_MBSSession ContextUpdate (TS 29.532 §5.3.2.5, `n2MbsSmInfo`):
//!
//! - `MbsDistributionSetupRequestTransfer`      (§9.3.5.7, `MBS_DIS_SETUP_REQ`)
//! - `MbsDistributionSetupResponseTransfer`     (§9.3.5.8, `MBS_DIS_SETUP_RSP`)
//! - `MbsDistributionSetupUnsuccessfulTransfer` (§9.3.5.9, `MBS_DIS_SETUP_FAIL`)
//! - `MbsDistributionReleaseRequestTransfer`    (§9.3.5.10, `MBS_DIS_REL_REQ`)
//!
//! Unlike the PDU-session transfer containers (which are ProtocolIE
//! containers), the MBS Distribution containers are defined in the TS 38.413
//! ASN.1 module as plain extensible SEQUENCEs (38413-j30.txt:51163-51266):
//! extension bit + OPTIONAL-presence bitmap + fields in declaration order.
//! Field order and extension markers below are transcribed verbatim from the
//! ASN.1 module; the only IE-id used is `id-TAIMBSSupportList (441)`, which
//! travels inside the SetupRequestTransfer's `iE-Extensions`
//! (MBS-DistributionSetupRequestTransfer-ExtIEs, criticality ignore).
//!
//! Supporting IEs implemented here per their ASN.1:
//! - `MBS-SessionID ::= SEQUENCE { tMGI TMGI, nID NID OPTIONAL, iE-Extensions
//!   OPTIONAL, ... }` with `TMGI ::= OCTET STRING (SIZE(6))` (§9.3.1.206) and
//!   `NID ::= BIT STRING (SIZE(44))`
//! - `MBS-AreaSessionID ::= INTEGER (0..65535, ...)` (§9.3.1.207)
//! - `SharedNGU-MulticastTNLInformation ::= SEQUENCE { iP-MulticastAddress,
//!   iP-SourceAddress, gTP-TEID, iE-Extensions OPTIONAL, ... }` (§9.3.2.16)
//! - `MBS-QoSFlowsToBeSetupList ::= SEQUENCE (SIZE(1..maxnoofMBSQoSFlows=64))
//!   OF MBS-QoSFlowsToBeSetupItem` (§9.3.1.236)
//! - `MBSSessionStatus ::= ENUMERATED { activated, deactivated, ... }`
//!   (§9.3.1.217)
//! - `TAIMBSSupportList ::= SEQUENCE (SIZE(1..maxnoofSupportedTAIforMBS=256))
//!   OF TAIMBSSupportItem { tAI TAI, iE-Extensions OPTIONAL, ... }`
//!
//! Honest scope limits (documented defers, both OPTIONAL on the wire so the
//! emitted containers remain conformant):
//! - `mBS-ServiceArea` (§9.3.1.208) in the SetupResponseTransfer is never
//!   emitted and its presence on decode is rejected (fail-closed) rather than
//!   misparsed.
//!
//! Decode is fail-closed: truncated buffers, out-of-range values, unsupported
//! deferred IEs and reject-criticality unknown extensions all return
//! [`NgapError`]; version extension additions (the `...` bracket) and
//! ignore/notify-criticality unknown protocol extensions are skipped per
//! X.691 §18.8 / TS 38.413 §10.

use nextgcore_asn1c::ngap::cause::Cause;
use nextgcore_asn1c::ngap::ies::ProtocolIeField;
use nextgcore_asn1c::ngap::types::{Criticality, ProtocolIeId};
use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint};

use crate::error::NgapResult;
use crate::transfer::{
    decode_ext_constrained, decode_qfi, encode_ext_constrained, encode_qfi, invalid,
    QosFlowLevelQosParameters, TransportLayerAddress, UpTransportLayerInformation,
};
use crate::types::{CriticalityDiagnostics, IeCriticalityDiagnostics, TypeOfError};

/// id-TAIMBSSupportList ProtocolIE-ID ::= 441 (38413-j30.txt:60306); carried
/// in MBS-DistributionSetupRequestTransfer-ExtIEs with criticality ignore
pub const IE_ID_TAI_MBS_SUPPORT_LIST: u16 = 441;

/// maxnoofMBSQoSFlows INTEGER ::= 64 (38413-j30.txt:59273)
pub const MAX_MBS_QOS_FLOWS: usize = 64;

/// maxnoofSupportedTAIforMBS INTEGER ::= 256 (38413-j30.txt:59343)
pub const MAX_TAI_MBS_SUPPORT: usize = 256;

/// maxProtocolExtensions INTEGER ::= 65535 (NGAP-Containers)
const MAX_PROTOCOL_EXTENSIONS: usize = 65535;

// ============================================================================
// Shared helpers
// ============================================================================

/// Skip the extension additions of an extensible SEQUENCE whose extension bit
/// was set (X.691 §18.8/§18.9): a normally-small length holding the number of
/// additions minus 1, an n-bit presence bitmap, then each present addition
/// wrapped as an open type. Truncation anywhere inside is an error
/// (fail-closed); the addition *content* is version-bracket data and is
/// skippable by definition.
fn skip_extension_additions(decoder: &mut AperDecoder) -> NgapResult<()> {
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
fn encode_extension_container(
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
fn decode_extension_container(decoder: &mut AperDecoder) -> NgapResult<Vec<ProtocolIeField>> {
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
fn decode_unknown_extensions_only(decoder: &mut AperDecoder) -> NgapResult<()> {
    for field in decode_extension_container(decoder)? {
        crate::ie::handle_unknown_ie(&field)?;
    }
    Ok(())
}

/// Encode `MBS-AreaSessionID ::= INTEGER (0..65535, ...)` (§9.3.1.207)
fn encode_mbs_area_session_id(encoder: &mut AperEncoder, value: u16) -> NgapResult<()> {
    encode_ext_constrained(encoder, value as i64, 0, 65535)
}

/// Decode `MBS-AreaSessionID`, fail-closed on extension values outside u16
fn decode_mbs_area_session_id(decoder: &mut AperDecoder) -> NgapResult<u16> {
    let value = decode_ext_constrained(decoder, 0, 65535)?;
    u16::try_from(value).map_err(|_| {
        invalid(
            "MBS-AreaSessionID",
            format!("Value {value} outside 0..65535"),
        )
    })
}

// ============================================================================
// MBS-SessionID (TS 38.413 §9.3.1.206)
// ============================================================================

/// `MBS-SessionID ::= SEQUENCE { tMGI TMGI, nID NID OPTIONAL, iE-Extensions
/// OPTIONAL, ... }` with `TMGI ::= OCTET STRING (SIZE(6))` = PLMN identity
/// (3 octets, TS 24.008 BCD) + MBS Service ID (3 octets), and
/// `NID ::= BIT STRING (SIZE(44))` (SNPN network identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbsSessionId {
    /// TMGI octets 0-2: PLMN identity (BCD-coded per TS 24.008)
    pub plmn_identity: [u8; 3],
    /// TMGI octets 3-5: MBS Service ID
    pub mbs_service_id: [u8; 3],
    /// SNPN NID, 44 significant bits (values >= 2^44 are rejected)
    pub nid: Option<u64>,
}

impl MbsSessionId {
    pub fn new(plmn_identity: [u8; 3], mbs_service_id: [u8; 3]) -> Self {
        Self {
            plmn_identity,
            mbs_service_id,
            nid: None,
        }
    }

    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        if let Some(nid) = self.nid {
            if nid >= (1u64 << 44) {
                return Err(invalid(
                    "MBS-SessionID",
                    format!("NID {nid:#x} exceeds 44 bits"),
                ));
            }
        }
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.nid.is_some());
        encoder.write_bit(false); // no iE-Extensions
        let mut tmgi = [0u8; 6];
        tmgi[..3].copy_from_slice(&self.plmn_identity);
        tmgi[3..].copy_from_slice(&self.mbs_service_id);
        encoder.encode_octet_string(&tmgi, Some(6), Some(6))?;
        if let Some(nid) = self.nid {
            // BIT STRING fixed SIZE(44) > 16 bits is octet-aligned (X.691 §16)
            encoder.align();
            encoder.write_bits(nid, 44);
        }
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let nid_present = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let tmgi = decoder.decode_octet_string(Some(6), Some(6))?;
        let mut plmn_identity = [0u8; 3];
        let mut mbs_service_id = [0u8; 3];
        plmn_identity.copy_from_slice(&tmgi[..3]);
        mbs_service_id.copy_from_slice(&tmgi[3..]);
        let nid = if nid_present {
            decoder.align();
            Some(decoder.read_bits(44)?)
        } else {
            None
        };
        if ie_ext_present {
            decode_unknown_extensions_only(decoder)?;
        }
        if ext {
            skip_extension_additions(decoder)?;
        }
        Ok(Self {
            plmn_identity,
            mbs_service_id,
            nid,
        })
    }
}

// ============================================================================
// Shared NG-U Multicast TNL Information (TS 38.413 §9.3.2.16)
// ============================================================================

/// `SharedNGU-MulticastTNLInformation ::= SEQUENCE { iP-MulticastAddress
/// TransportLayerAddress, iP-SourceAddress TransportLayerAddress, gTP-TEID
/// GTP-TEID, iE-Extensions OPTIONAL, ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNguMulticastTnlInformation {
    /// LL SSM destination: IP multicast address of the shared NG-U tunnel
    pub ip_multicast_address: TransportLayerAddress,
    /// LL SSM source: source IP address (source-specific multicast)
    pub ip_source_address: TransportLayerAddress,
    /// Common GTP-TEID (C-TEID) of the shared downlink tunnel
    pub gtp_teid: [u8; 4],
}

impl SharedNguMulticastTnlInformation {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // no iE-Extensions
        self.ip_multicast_address.encode(encoder)?;
        self.ip_source_address.encode(encoder)?;
        encoder.encode_octet_string(&self.gtp_teid, Some(4), Some(4))?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let ip_multicast_address = TransportLayerAddress::decode(decoder)?;
        let ip_source_address = TransportLayerAddress::decode(decoder)?;
        let teid_bytes = decoder.decode_octet_string(Some(4), Some(4))?;
        let mut gtp_teid = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_bytes);
        if ie_ext_present {
            decode_unknown_extensions_only(decoder)?;
        }
        if ext {
            skip_extension_additions(decoder)?;
        }
        Ok(Self {
            ip_multicast_address,
            ip_source_address,
            gtp_teid,
        })
    }
}

// ============================================================================
// MBS QoS Flows To Be Setup List (TS 38.413 §9.3.1.236)
// ============================================================================

/// `MBS-QoSFlowsToBeSetupItem ::= SEQUENCE { mBSqosFlowIdentifier
/// QosFlowIdentifier, mBSqosFlowLevelQosParameters QosFlowLevelQosParameters,
/// iE-Extensions OPTIONAL, ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsQosFlowsToBeSetupItem {
    /// QoS Flow Identifier (0..63)
    pub mbs_qos_flow_identifier: u8,
    /// QoS parameters (reused §9.3.1.12 codec)
    pub mbs_qos_flow_level_qos_parameters: QosFlowLevelQosParameters,
}

impl MbsQosFlowsToBeSetupItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // no iE-Extensions
        encode_qfi(encoder, self.mbs_qos_flow_identifier)?;
        self.mbs_qos_flow_level_qos_parameters.encode(encoder)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let ext = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let mbs_qos_flow_identifier = decode_qfi(decoder)?;
        let mbs_qos_flow_level_qos_parameters = QosFlowLevelQosParameters::decode(decoder)?;
        if ie_ext_present {
            decode_unknown_extensions_only(decoder)?;
        }
        if ext {
            skip_extension_additions(decoder)?;
        }
        Ok(Self {
            mbs_qos_flow_identifier,
            mbs_qos_flow_level_qos_parameters,
        })
    }
}

fn encode_mbs_qos_flows_to_be_setup_list(
    encoder: &mut AperEncoder,
    list: &[MbsQosFlowsToBeSetupItem],
) -> NgapResult<()> {
    encoder.encode_constrained_length(list.len(), 1, MAX_MBS_QOS_FLOWS)?;
    for item in list {
        item.encode(encoder)?;
    }
    Ok(())
}

fn decode_mbs_qos_flows_to_be_setup_list(
    decoder: &mut AperDecoder,
) -> NgapResult<Vec<MbsQosFlowsToBeSetupItem>> {
    let count = decoder.decode_constrained_length(1, MAX_MBS_QOS_FLOWS)?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        list.push(MbsQosFlowsToBeSetupItem::decode(decoder)?);
    }
    Ok(list)
}

// ============================================================================
// MBS Session Status (TS 38.413 §9.3.1.217)
// ============================================================================

/// `MBSSessionStatus ::= ENUMERATED { activated, deactivated, ... }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MbsSessionStatus {
    Activated = 0,
    Deactivated = 1,
}

impl MbsSessionStatus {
    const CONSTRAINT: Constraint = Constraint::extensible(0, 1);

    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        match decoder.decode_enumerated(&Self::CONSTRAINT)? {
            0 => Ok(MbsSessionStatus::Activated),
            1 => Ok(MbsSessionStatus::Deactivated),
            v => Err(invalid("MBSSessionStatus", format!("Unknown value: {v}"))),
        }
    }
}

// ============================================================================
// TAI MBS Support List (SetupRequestTransfer extension, id 441)
// ============================================================================

/// One `TAIMBSSupportItem ::= SEQUENCE { tAI TAI, iE-Extensions OPTIONAL,
/// ... }` where `TAI ::= SEQUENCE { pLMNIdentity OCTET STRING (SIZE(3)),
/// tAC OCTET STRING (SIZE(3)), iE-Extensions OPTIONAL, ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaiMbsSupportItem {
    /// PLMN identity (BCD-coded per TS 24.008)
    pub plmn_identity: [u8; 3],
    /// Tracking Area Code
    pub tac: [u8; 3],
}

impl TaiMbsSupportItem {
    fn encode(&self, encoder: &mut AperEncoder) -> NgapResult<()> {
        encoder.write_bit(false); // TAIMBSSupportItem extension marker
        encoder.write_bit(false); // no iE-Extensions
        encoder.write_bit(false); // TAI extension marker
        encoder.write_bit(false); // no TAI iE-Extensions
        encoder.encode_octet_string(&self.plmn_identity, Some(3), Some(3))?;
        encoder.encode_octet_string(&self.tac, Some(3), Some(3))?;
        Ok(())
    }

    fn decode(decoder: &mut AperDecoder) -> NgapResult<Self> {
        let item_ext = decoder.read_bit()?;
        let item_ie_ext_present = decoder.read_bit()?;
        let tai_ext = decoder.read_bit()?;
        let tai_ie_ext_present = decoder.read_bit()?;
        let plmn_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
        let tac_bytes = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut plmn_identity = [0u8; 3];
        let mut tac = [0u8; 3];
        plmn_identity.copy_from_slice(&plmn_bytes);
        tac.copy_from_slice(&tac_bytes);
        // TAI's own trailing optionals/extensions come before the item's
        if tai_ie_ext_present {
            decode_unknown_extensions_only(decoder)?;
        }
        if tai_ext {
            skip_extension_additions(decoder)?;
        }
        if item_ie_ext_present {
            decode_unknown_extensions_only(decoder)?;
        }
        if item_ext {
            skip_extension_additions(decoder)?;
        }
        Ok(Self { plmn_identity, tac })
    }
}

fn encode_tai_mbs_support_list(
    encoder: &mut AperEncoder,
    list: &[TaiMbsSupportItem],
) -> NgapResult<()> {
    encoder.encode_constrained_length(list.len(), 1, MAX_TAI_MBS_SUPPORT)?;
    for item in list {
        item.encode(encoder)?;
    }
    Ok(())
}

fn decode_tai_mbs_support_list(data: &[u8]) -> NgapResult<Vec<TaiMbsSupportItem>> {
    let mut decoder = AperDecoder::new(data);
    let count = decoder.decode_constrained_length(1, MAX_TAI_MBS_SUPPORT)?;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        list.push(TaiMbsSupportItem::decode(&mut decoder)?);
    }
    Ok(list)
}

// ============================================================================
// Inline CriticalityDiagnostics codec (TS 38.413 §9.3.1.3)
//
// Same SEQUENCE logic as ie.rs's IE-level functions, but inline because the
// UnsuccessfulTransfer carries criticalityDiagnostics as a plain SEQUENCE
// field, not as a ProtocolIE.
// ============================================================================

fn encode_criticality_diagnostics_inline(
    encoder: &mut AperEncoder,
    diag: &CriticalityDiagnostics,
) -> NgapResult<()> {
    let ies_present = !diag.ies.is_empty();
    encoder.write_bit(false); // extension marker
    encoder.write_bit(diag.procedure_code.is_some());
    encoder.write_bit(diag.triggering_message.is_some());
    encoder.write_bit(diag.procedure_criticality.is_some());
    encoder.write_bit(ies_present);
    encoder.write_bit(false); // no iE-Extensions
    if let Some(code) = diag.procedure_code {
        let constraint = Constraint::new(0, 255);
        encoder.encode_constrained_whole_number(code as i64, &constraint)?;
    }
    if let Some(tm) = diag.triggering_message {
        let constraint = Constraint::new(0, 2);
        encoder.encode_enumerated(tm as i64, &constraint)?;
    }
    if let Some(crit) = diag.procedure_criticality {
        let constraint = Constraint::new(0, 2);
        encoder.encode_enumerated(crit as i64, &constraint)?;
    }
    if ies_present {
        encoder.encode_constrained_length(diag.ies.len(), 1, 256)?;
        for item in &diag.ies {
            encoder.write_bit(false); // item extension marker
            encoder.write_bit(false); // no iE-Extensions
            item.ie_criticality.encode_aper(encoder)?;
            let id_constraint = Constraint::new(0, 65535);
            encoder.encode_constrained_whole_number(item.ie_id as i64, &id_constraint)?;
            let err_constraint = Constraint::extensible(0, 1);
            let err_index = match item.type_of_error {
                TypeOfError::NotUnderstood => 0,
                TypeOfError::Missing => 1,
            };
            encoder.encode_enumerated(err_index, &err_constraint)?;
        }
    }
    Ok(())
}

fn decode_criticality_diagnostics_inline(
    decoder: &mut AperDecoder,
) -> NgapResult<CriticalityDiagnostics> {
    let ext = decoder.read_bit()?;
    let pc_present = decoder.read_bit()?;
    let tm_present = decoder.read_bit()?;
    let crit_present = decoder.read_bit()?;
    let ies_present = decoder.read_bit()?;
    let ie_ext_present = decoder.read_bit()?;
    let procedure_code = if pc_present {
        let constraint = Constraint::new(0, 255);
        Some(decoder.decode_constrained_whole_number(&constraint)? as u8)
    } else {
        None
    };
    let triggering_message = if tm_present {
        let constraint = Constraint::new(0, 2);
        Some(decoder.decode_enumerated(&constraint)? as u8)
    } else {
        None
    };
    let procedure_criticality = if crit_present {
        let constraint = Constraint::new(0, 2);
        Some(decoder.decode_enumerated(&constraint)? as u8)
    } else {
        None
    };
    let mut ies = Vec::new();
    if ies_present {
        let count = decoder.decode_constrained_length(1, 256)?;
        for _ in 0..count {
            let item_ext = decoder.read_bit()?;
            let item_ie_ext_present = decoder.read_bit()?;
            let ie_criticality = Criticality::decode_aper(decoder)?;
            let id_constraint = Constraint::new(0, 65535);
            let ie_id = decoder.decode_constrained_whole_number(&id_constraint)? as u16;
            let err_constraint = Constraint::extensible(0, 1);
            let type_of_error = match decoder.decode_enumerated(&err_constraint)? {
                1 => TypeOfError::Missing,
                _ => TypeOfError::NotUnderstood,
            };
            if item_ie_ext_present {
                decode_unknown_extensions_only(decoder)?;
            }
            if item_ext {
                skip_extension_additions(decoder)?;
            }
            ies.push(IeCriticalityDiagnostics {
                ie_criticality,
                ie_id,
                type_of_error,
            });
        }
    }
    if ie_ext_present {
        decode_unknown_extensions_only(decoder)?;
    }
    if ext {
        skip_extension_additions(decoder)?;
    }
    Ok(CriticalityDiagnostics {
        procedure_code,
        triggering_message,
        procedure_criticality,
        ies,
    })
}

// ============================================================================
// MBS Distribution Setup Request Transfer (TS 38.413 §9.3.5.7)
// ============================================================================

/// `MBS-DistributionSetupRequestTransfer ::= SEQUENCE { mBS-SessionID,
/// mBS-AreaSessionID OPTIONAL, sharedNGU-UnicastTNLInformation
/// UPTransportLayerInformation OPTIONAL, iE-Extensions OPTIONAL, ... }`
/// (38413-j30.txt:51187). Built by the AMF (relaying the NG-RAN request),
/// consumed by the MB-SMF over Nmbsmf ContextUpdate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsDistributionSetupRequestTransfer {
    pub mbs_session_id: MbsSessionId,
    pub mbs_area_session_id: Option<u16>,
    /// Downlink NG-U unicast fallback endpoint offered by the NG-RAN node
    pub shared_ngu_unicast_tnl_information: Option<UpTransportLayerInformation>,
    /// TAIMBSSupportList (id-TAIMBSSupportList=441, criticality ignore),
    /// carried inside iE-Extensions per
    /// MBS-DistributionSetupRequestTransfer-ExtIEs
    pub tai_mbs_support_list: Option<Vec<TaiMbsSupportItem>>,
}

impl MbsDistributionSetupRequestTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.mbs_area_session_id.is_some());
        encoder.write_bit(self.shared_ngu_unicast_tnl_information.is_some());
        encoder.write_bit(self.tai_mbs_support_list.is_some()); // iE-Extensions
        self.mbs_session_id.encode(&mut encoder)?;
        if let Some(area) = self.mbs_area_session_id {
            encode_mbs_area_session_id(&mut encoder, area)?;
        }
        if let Some(ref tnl) = self.shared_ngu_unicast_tnl_information {
            tnl.encode(&mut encoder)?;
        }
        if let Some(ref list) = self.tai_mbs_support_list {
            let mut value = AperEncoder::new();
            encode_tai_mbs_support_list(&mut value, list)?;
            value.align();
            let field = ProtocolIeField {
                id: ProtocolIeId(IE_ID_TAI_MBS_SUPPORT_LIST),
                criticality: Criticality::Ignore,
                value: value.into_bytes().to_vec(),
            };
            encode_extension_container(&mut encoder, &[field])?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let area_present = decoder.read_bit()?;
        let tnl_present = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let mbs_session_id = MbsSessionId::decode(&mut decoder)?;
        let mbs_area_session_id = if area_present {
            Some(decode_mbs_area_session_id(&mut decoder)?)
        } else {
            None
        };
        let shared_ngu_unicast_tnl_information = if tnl_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let mut tai_mbs_support_list = None;
        if ie_ext_present {
            for field in decode_extension_container(&mut decoder)? {
                match field.id.0 {
                    IE_ID_TAI_MBS_SUPPORT_LIST => {
                        tai_mbs_support_list = Some(decode_tai_mbs_support_list(&field.value)?);
                    }
                    _ => crate::ie::handle_unknown_ie(&field)?,
                }
            }
        }
        if ext {
            skip_extension_additions(&mut decoder)?;
        }
        Ok(Self {
            mbs_session_id,
            mbs_area_session_id,
            shared_ngu_unicast_tnl_information,
            tai_mbs_support_list,
        })
    }
}

// ============================================================================
// MBS Distribution Setup Response Transfer (TS 38.413 §9.3.5.8)
// ============================================================================

/// `MBS-DistributionSetupResponseTransfer ::= SEQUENCE { mBS-SessionID,
/// mBS-AreaSessionID OPTIONAL, sharedNGU-MulticastTNLInformation OPTIONAL,
/// mBS-QoSFlowsToBeSetupList, mBSSessionStatus, mBS-ServiceArea OPTIONAL,
/// iE-Extensions OPTIONAL, ... }` (38413-j30.txt:51212). Built by the MB-SMF,
/// relayed by the AMF to the NG-RAN node.
///
/// `mBS-ServiceArea` (§9.3.1.208) is a documented defer: never emitted, and
/// rejected fail-closed if a peer sends it (it cannot be skipped inside a
/// plain PER SEQUENCE without a codec for it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsDistributionSetupResponseTransfer {
    pub mbs_session_id: MbsSessionId,
    pub mbs_area_session_id: Option<u16>,
    /// Shared NG-U multicast distribution endpoint (LL SSM + C-TEID)
    pub shared_ngu_multicast_tnl_information: Option<SharedNguMulticastTnlInformation>,
    /// SIZE(1..64), mandatory
    pub mbs_qos_flows_to_be_setup_list: Vec<MbsQosFlowsToBeSetupItem>,
    pub mbs_session_status: MbsSessionStatus,
}

impl MbsDistributionSetupResponseTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.mbs_area_session_id.is_some());
        encoder.write_bit(self.shared_ngu_multicast_tnl_information.is_some());
        encoder.write_bit(false); // mBS-ServiceArea deliberately absent (defer)
        encoder.write_bit(false); // no iE-Extensions
        self.mbs_session_id.encode(&mut encoder)?;
        if let Some(area) = self.mbs_area_session_id {
            encode_mbs_area_session_id(&mut encoder, area)?;
        }
        if let Some(ref tnl) = self.shared_ngu_multicast_tnl_information {
            tnl.encode(&mut encoder)?;
        }
        encode_mbs_qos_flows_to_be_setup_list(&mut encoder, &self.mbs_qos_flows_to_be_setup_list)?;
        self.mbs_session_status.encode(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let area_present = decoder.read_bit()?;
        let tnl_present = decoder.read_bit()?;
        let service_area_present = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let mbs_session_id = MbsSessionId::decode(&mut decoder)?;
        let mbs_area_session_id = if area_present {
            Some(decode_mbs_area_session_id(&mut decoder)?)
        } else {
            None
        };
        let shared_ngu_multicast_tnl_information = if tnl_present {
            Some(SharedNguMulticastTnlInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let mbs_qos_flows_to_be_setup_list = decode_mbs_qos_flows_to_be_setup_list(&mut decoder)?;
        let mbs_session_status = MbsSessionStatus::decode(&mut decoder)?;
        if service_area_present {
            // Fail-closed: no codec for MBS-ServiceArea (§9.3.1.208) — a plain
            // SEQUENCE field cannot be skipped without one (no length wrapper)
            return Err(invalid(
                "MBS-ServiceArea",
                "MBS-ServiceArea decoding is not supported (deferred IE)".to_string(),
            ));
        }
        if ie_ext_present {
            decode_unknown_extensions_only(&mut decoder)?;
        }
        if ext {
            skip_extension_additions(&mut decoder)?;
        }
        Ok(Self {
            mbs_session_id,
            mbs_area_session_id,
            shared_ngu_multicast_tnl_information,
            mbs_qos_flows_to_be_setup_list,
            mbs_session_status,
        })
    }
}

// ============================================================================
// MBS Distribution Setup Unsuccessful Transfer (TS 38.413 §9.3.5.9)
// ============================================================================

/// `MBS-DistributionSetupUnsuccessfulTransfer ::= SEQUENCE { mBS-SessionID,
/// mBS-AreaSessionID OPTIONAL, cause Cause, criticalityDiagnostics OPTIONAL,
/// iE-Extensions OPTIONAL, ... }` (38413-j30.txt:51241)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsDistributionSetupUnsuccessfulTransfer {
    pub mbs_session_id: MbsSessionId,
    pub mbs_area_session_id: Option<u16>,
    pub cause: Cause,
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

impl MbsDistributionSetupUnsuccessfulTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.mbs_area_session_id.is_some());
        encoder.write_bit(self.criticality_diagnostics.is_some());
        encoder.write_bit(false); // no iE-Extensions
        self.mbs_session_id.encode(&mut encoder)?;
        if let Some(area) = self.mbs_area_session_id {
            encode_mbs_area_session_id(&mut encoder, area)?;
        }
        self.cause.encode_aper(&mut encoder)?;
        if let Some(ref diag) = self.criticality_diagnostics {
            encode_criticality_diagnostics_inline(&mut encoder, diag)?;
        }
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let area_present = decoder.read_bit()?;
        let diag_present = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let mbs_session_id = MbsSessionId::decode(&mut decoder)?;
        let mbs_area_session_id = if area_present {
            Some(decode_mbs_area_session_id(&mut decoder)?)
        } else {
            None
        };
        let cause = Cause::decode_aper(&mut decoder)?;
        let criticality_diagnostics = if diag_present {
            Some(decode_criticality_diagnostics_inline(&mut decoder)?)
        } else {
            None
        };
        if ie_ext_present {
            decode_unknown_extensions_only(&mut decoder)?;
        }
        if ext {
            skip_extension_additions(&mut decoder)?;
        }
        Ok(Self {
            mbs_session_id,
            mbs_area_session_id,
            cause,
            criticality_diagnostics,
        })
    }
}

// ============================================================================
// MBS Distribution Release Request Transfer (TS 38.413 §9.3.5.10)
// ============================================================================

/// `MBS-DistributionReleaseRequestTransfer ::= SEQUENCE { mBS-SessionID,
/// mBS-AreaSessionID OPTIONAL, sharedNGU-UnicastTNLInformation
/// UPTransportLayerInformation OPTIONAL, cause Cause, iE-Extensions OPTIONAL,
/// ... }` (38413-j30.txt:51163)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsDistributionReleaseRequestTransfer {
    pub mbs_session_id: MbsSessionId,
    pub mbs_area_session_id: Option<u16>,
    pub shared_ngu_unicast_tnl_information: Option<UpTransportLayerInformation>,
    pub cause: Cause,
}

impl MbsDistributionReleaseRequestTransfer {
    pub fn encode(&self) -> NgapResult<Vec<u8>> {
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.mbs_area_session_id.is_some());
        encoder.write_bit(self.shared_ngu_unicast_tnl_information.is_some());
        encoder.write_bit(false); // no iE-Extensions
        self.mbs_session_id.encode(&mut encoder)?;
        if let Some(area) = self.mbs_area_session_id {
            encode_mbs_area_session_id(&mut encoder, area)?;
        }
        if let Some(ref tnl) = self.shared_ngu_unicast_tnl_information {
            tnl.encode(&mut encoder)?;
        }
        self.cause.encode_aper(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes().to_vec())
    }

    pub fn decode(data: &[u8]) -> NgapResult<Self> {
        let mut decoder = AperDecoder::new(data);
        let ext = decoder.read_bit()?;
        let area_present = decoder.read_bit()?;
        let tnl_present = decoder.read_bit()?;
        let ie_ext_present = decoder.read_bit()?;
        let mbs_session_id = MbsSessionId::decode(&mut decoder)?;
        let mbs_area_session_id = if area_present {
            Some(decode_mbs_area_session_id(&mut decoder)?)
        } else {
            None
        };
        let shared_ngu_unicast_tnl_information = if tnl_present {
            Some(UpTransportLayerInformation::decode(&mut decoder)?)
        } else {
            None
        };
        let cause = Cause::decode_aper(&mut decoder)?;
        if ie_ext_present {
            decode_unknown_extensions_only(&mut decoder)?;
        }
        if ext {
            skip_extension_additions(&mut decoder)?;
        }
        Ok(Self {
            mbs_session_id,
            mbs_area_session_id,
            shared_ngu_unicast_tnl_information,
            cause,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NgapError;
    use crate::transfer::{
        AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor, PreEmptionCapability,
        PreEmptionVulnerability, QosCharacteristics,
    };
    use nextgcore_asn1c::ngap::cause::{CauseNas, CauseRadioNetwork};
    use proptest::prelude::*;

    /// TMGI used across all golden vectors: PLMN 208/93 (BCD `02 F8 39`),
    /// MBS Service ID `00 00 01`
    fn sample_session_id() -> MbsSessionId {
        MbsSessionId::new([0x02, 0xF8, 0x39], [0x00, 0x00, 0x01])
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

    fn sample_unicast_tnl() -> UpTransportLayerInformation {
        UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4([10, 1, 2, 3]),
            gtp_teid: [0x00, 0x00, 0x30, 0x39],
        })
    }

    // ------------------------------------------------------------------
    // Golden vectors — every byte hand-derived per X.691 (aligned PER).
    // Shared prefix derivation for MbsSessionId (nid absent):
    //   ext=0, nid-present=0, iE-ext=0 (3 bits), then TMGI = fixed OCTET
    //   STRING (SIZE(6)) > 2 octets => octet-aligned => pad to byte
    //   boundary, then the 6 TMGI octets 02 F8 39 00 00 01.
    // ------------------------------------------------------------------

    /// §9.3.5.7 SetupRequestTransfer golden vector.
    ///
    /// Fields: TMGI 02F839/000001 (nid absent), areaSessionId=1,
    /// sharedNGU-UnicastTNLInformation = GTP tunnel IPv4 10.1.2.3 /
    /// TEID 0x00003039, no iE-Extensions.
    ///
    /// Bit derivation:
    ///   bit0    seq ext            = 0
    ///   bit1    area present       = 1
    ///   bit2    unicast-TNL present= 1
    ///   bit3    iE-Ext present     = 0
    ///   bits4-6 MBS-SessionID preamble (ext,nid,iE-ext) = 000
    ///   bit7    align pad for TMGI = 0            => byte0 = 0110 0000 = 0x60
    ///   bytes1-6  TMGI             = 02 F8 39 00 00 01
    ///   bit56   area INTEGER ext   = 0; range 65536 => align (7 pad bits)
    ///                                             => byte7  = 0x00
    ///   bytes8-9  area offset 1    = 00 01
    ///   bit80   UPTransportLayerInformation choice (2 alts, 1 bit) = 0
    ///   bit81   GTPTunnel ext = 0; bit82 GTPTunnel iE-ext = 0
    ///   bit83   TransportLayerAddress ext = 0
    ///   bits84-91 length 32 in (1..160): offset 31 = 0001 1111 (8 bits)
    ///                                             => byte10 = 0x01
    ///   bits92-95 align pad for BIT STRING > 16   => byte11 = 0xF0
    ///   bytes12-15 address          = 0A 01 02 03
    ///   bytes16-19 TEID fixed OCTET STRING(4), aligned = 00 00 30 39
    const GOLDEN_SETUP_REQ: [u8; 20] = [
        0x60, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0xF0, 0x0A, 0x01, 0x02,
        0x03, 0x00, 0x00, 0x30, 0x39,
    ];

    #[test]
    fn test_mbs_setup_request_transfer_golden_vector() {
        let transfer = MbsDistributionSetupRequestTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: Some(1),
            shared_ngu_unicast_tnl_information: Some(sample_unicast_tnl()),
            tai_mbs_support_list: None,
        };
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes, GOLDEN_SETUP_REQ, "encode() != hand-derived APER");
        let decoded = MbsDistributionSetupRequestTransfer::decode(&GOLDEN_SETUP_REQ).unwrap();
        assert_eq!(decoded, transfer);
        // Byte-identity both ways
        assert_eq!(decoded.encode().unwrap(), GOLDEN_SETUP_REQ);
    }

    /// §9.3.5.7 SetupRequestTransfer with the TAIMBSSupportList protocol
    /// extension (id-TAIMBSSupportList = 441, criticality ignore).
    ///
    /// Fields: TMGI 02F839/000001, no area, no TNL, TAI list = [
    /// {PLMN 02 F8 39, TAC 00 00 01} ].
    ///
    /// Bit derivation:
    ///   bit0-3  ext=0, area=0, tnl=0, iE-Ext=1
    ///   bits4-6 MBS-SessionID preamble = 000; bit7 TMGI align pad
    ///                                             => byte0 = 0x10
    ///   bytes1-6 TMGI                             = 02 F8 39 00 00 01
    ///   ProtocolExtensionContainer SIZE(1..65535): range 65535 <= 65536
    ///     => aligned 2-octet offset = count-1 = 0 => bytes7-8 = 00 00
    ///   ProtocolIE-ID 441 (0..65535 => aligned 2 octets) => bytes9-10 = 01 B9
    ///   Criticality ignore = enum 1 of 3 => 2 bits 01 (bits88-89)
    ///   open type => length determinant aligns (6 pad bits) => byte11 = 0x40
    ///   open-type length = 8                      => byte12 = 0x08
    ///   content (TAIMBSSupportList):
    ///     list length (1..256): range 256 => aligned 1 octet offset 0 = 0x00
    ///     item ext=0, item iE-ext=0, TAI ext=0, TAI iE-ext=0 (4 bits) then
    ///       PLMN fixed OCTET STRING(3) aligns (4 pad bits)   => 0x00
    ///     PLMN = 02 F8 39, TAC (aligned) = 00 00 01
    ///     content = 00 00 02 F8 39 00 00 01 (bytes13-20)
    const GOLDEN_SETUP_REQ_TAI: [u8; 21] = [
        0x10, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xB9, 0x40, 0x08, 0x00, 0x00,
        0x02, 0xF8, 0x39, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_mbs_setup_request_transfer_tai_extension_golden_vector() {
        let transfer = MbsDistributionSetupRequestTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: None,
            shared_ngu_unicast_tnl_information: None,
            tai_mbs_support_list: Some(vec![TaiMbsSupportItem {
                plmn_identity: [0x02, 0xF8, 0x39],
                tac: [0x00, 0x00, 0x01],
            }]),
        };
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes, GOLDEN_SETUP_REQ_TAI, "encode() != hand-derived APER");
        let decoded = MbsDistributionSetupRequestTransfer::decode(&GOLDEN_SETUP_REQ_TAI).unwrap();
        assert_eq!(decoded, transfer);
    }

    /// §9.3.5.8 SetupResponseTransfer golden vector.
    ///
    /// Fields: TMGI 02F839/000001 (nid absent), no area,
    /// sharedNGU-MulticastTNLInformation = { multicast 232.1.1.1,
    /// source 10.1.2.3, C-TEID 0x00003039 }, one QoS flow { QFI 1,
    /// non-dynamic 5QI 9, ARP prio 8/shall-not/not-preemptable }, status
    /// activated, serviceArea absent, no iE-Extensions.
    ///
    /// Bit derivation:
    ///   bit0-4  ext=0, area=0, tnl=1, svcArea=0, iE-Ext=0
    ///   bits5-7 MBS-SessionID preamble = 000      => byte0 = 0x20
    ///   bytes1-6 TMGI (already aligned)           = 02 F8 39 00 00 01
    ///   SharedNGU-MulticastTNLInformation:
    ///     bit56 ext=0, bit57 iE-ext=0
    ///     iP-MulticastAddress: bit58 ext=0, bits59-66 length offset 31
    ///       (0001 1111)                           => byte7 = 0x03
    ///     bits67-71 align pad                     => byte8 = 0xE0
    ///     bytes9-12 multicast addr                = E8 01 01 01
    ///     iP-SourceAddress: bit104 ext=0, bits105-112 offset 31
    ///                                             => byte13 = 0x0F
    ///     bits113-119 align pad                   => byte14 = 0x80
    ///     bytes15-18 source addr                  = 0A 01 02 03
    ///     bytes19-22 C-TEID (aligned)             = 00 00 30 39
    ///   QoS list: bits184-189 length (1..64) offset 0 = 000000
    ///   item: bit190 ext=0, bit191 iE-ext=0       => byte23 = 0x00
    ///   QFI: bit192 ext=0, bits193-198 value 1 = 000001
    ///   params: bit199 ext=0                      => byte24 = 0x02
    ///   params presence gbr=0,refl=0,addl=0,iE-ext=0 (bits200-203)
    ///   QosCharacteristics choice 0 of 3 (2 bits) = 00 (bits204-205)
    ///   NonDynamic5QI: bit206 ext=0, bit207 prio-present=0 => byte25 = 0x00
    ///   bits208-210 avg=0,burst=0,iE-ext=0; bit211 fiveQI ext=0;
    ///     fiveQI range 256 => align (bits212-215) => byte26 = 0x00
    ///   byte27 fiveQI offset                       = 0x09
    ///   ARP: bit224 ext=0, bit225 iE-ext=0; priority (1..15) offset 7 =
    ///     0111 (bits226-229); preemption-capability ext=0,val=0 (bits230-231)
    ///                                             => byte28 = 0x1C
    ///   vulnerability ext=0,val=0 (bits232-233)
    ///   MBSSessionStatus ext=0, val=0 (bits234-235); final align pad
    ///                                             => byte29 = 0x00
    const GOLDEN_SETUP_RSP: [u8; 30] = [
        0x20, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x03, 0xE0, 0xE8, 0x01, 0x01, 0x01, 0x0F, 0x80,
        0x0A, 0x01, 0x02, 0x03, 0x00, 0x00, 0x30, 0x39, 0x00, 0x02, 0x00, 0x00, 0x09, 0x1C, 0x00,
    ];

    fn golden_rsp_struct() -> MbsDistributionSetupResponseTransfer {
        MbsDistributionSetupResponseTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: None,
            shared_ngu_multicast_tnl_information: Some(SharedNguMulticastTnlInformation {
                ip_multicast_address: TransportLayerAddress::from_ipv4([232, 1, 1, 1]),
                ip_source_address: TransportLayerAddress::from_ipv4([10, 1, 2, 3]),
                gtp_teid: [0x00, 0x00, 0x30, 0x39],
            }),
            mbs_qos_flows_to_be_setup_list: vec![MbsQosFlowsToBeSetupItem {
                mbs_qos_flow_identifier: 1,
                mbs_qos_flow_level_qos_parameters: sample_qos_params(),
            }],
            mbs_session_status: MbsSessionStatus::Activated,
        }
    }

    #[test]
    fn test_mbs_setup_response_transfer_golden_vector() {
        let transfer = golden_rsp_struct();
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes, GOLDEN_SETUP_RSP, "encode() != hand-derived APER");

        // decode(golden) yields exactly the documented field values...
        let decoded = MbsDistributionSetupResponseTransfer::decode(&GOLDEN_SETUP_RSP).unwrap();
        let tnl = decoded
            .shared_ngu_multicast_tnl_information
            .as_ref()
            .unwrap();
        assert_eq!(tnl.ip_multicast_address.octets, vec![232, 1, 1, 1]);
        assert_eq!(tnl.ip_source_address.octets, vec![10, 1, 2, 3]);
        assert_eq!(u32::from_be_bytes(tnl.gtp_teid), 0x0000_3039);
        assert_eq!(decoded.mbs_qos_flows_to_be_setup_list.len(), 1);
        assert_eq!(
            decoded.mbs_qos_flows_to_be_setup_list[0].mbs_qos_flow_identifier,
            1
        );
        assert_eq!(decoded.mbs_session_status, MbsSessionStatus::Activated);
        assert_eq!(decoded.mbs_session_id, sample_session_id());
        assert_eq!(decoded, transfer);

        // ...and re-encodes to the identical bytes
        assert_eq!(decoded.encode().unwrap(), GOLDEN_SETUP_RSP);
    }

    /// §9.3.5.9 SetupUnsuccessfulTransfer golden vector.
    ///
    /// Fields: TMGI 02F839/000001, areaSessionId=0xABCD, cause =
    /// radioNetwork:cell-not-available(11), no criticalityDiagnostics.
    ///
    /// Bit derivation:
    ///   bit0-3  ext=0, area=1, critDiag=0, iE-Ext=0
    ///   bits4-6 MBS-SessionID preamble = 000; bit7 TMGI align pad
    ///                                             => byte0 = 0x40
    ///   bytes1-6 TMGI                             = 02 F8 39 00 00 01
    ///   area: bit56 INTEGER ext=0; align (7 pad)  => byte7 = 0x00
    ///   bytes8-9 area offset 0xABCD               = AB CD
    ///   Cause CHOICE (6 alts, non-ext, 3 bits) index 0 = 000 (bits80-82)
    ///   CauseRadioNetwork ENUM ext=0 (bit83); value 11 in 6 bits =
    ///     001011 (bits84-89) => byte10 = 0000 0010 = 0x02,
    ///     byte11 = 11xx xxxx with final align pad  = 0xC0
    const GOLDEN_SETUP_FAIL: [u8; 12] = [
        0x40, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x00, 0xAB, 0xCD, 0x02, 0xC0,
    ];

    #[test]
    fn test_mbs_setup_unsuccessful_transfer_golden_vector() {
        let transfer = MbsDistributionSetupUnsuccessfulTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: Some(0xABCD),
            cause: Cause::RadioNetwork(CauseRadioNetwork::CellNotAvailable),
            criticality_diagnostics: None,
        };
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes, GOLDEN_SETUP_FAIL, "encode() != hand-derived APER");
        let decoded = MbsDistributionSetupUnsuccessfulTransfer::decode(&GOLDEN_SETUP_FAIL).unwrap();
        assert_eq!(decoded, transfer);
        assert_eq!(decoded.encode().unwrap(), GOLDEN_SETUP_FAIL);
    }

    /// §9.3.5.10 ReleaseRequestTransfer golden vector.
    ///
    /// Fields: TMGI 02F839/000001, no area, no TNL, cause =
    /// nas:normal-release(0).
    ///
    /// Bit derivation:
    ///   bit0-3  ext=0, area=0, tnl=0, iE-Ext=0
    ///   bits4-6 MBS-SessionID preamble = 000; bit7 TMGI align pad
    ///                                             => byte0 = 0x00
    ///   bytes1-6 TMGI                             = 02 F8 39 00 00 01
    ///   Cause CHOICE index 2 (nas) in 3 bits = 010 (bits56-58)
    ///   CauseNas ENUM ext=0 (bit59); value 0 in 2 bits (root 0..3) = 00
    ///     (bits60-61); final align pad (bits62-63) => byte7 = 0x40
    const GOLDEN_REL_REQ: [u8; 8] = [0x00, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01, 0x40];

    #[test]
    fn test_mbs_release_request_transfer_golden_vector() {
        let transfer = MbsDistributionReleaseRequestTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: None,
            shared_ngu_unicast_tnl_information: None,
            cause: Cause::Nas(CauseNas::NormalRelease),
        };
        let bytes = transfer.encode().unwrap();
        assert_eq!(bytes, GOLDEN_REL_REQ, "encode() != hand-derived APER");
        let decoded = MbsDistributionReleaseRequestTransfer::decode(&GOLDEN_REL_REQ).unwrap();
        assert_eq!(decoded, transfer);
        assert_eq!(decoded.encode().unwrap(), GOLDEN_REL_REQ);
    }

    // ------------------------------------------------------------------
    // Fail-closed decode tests
    // ------------------------------------------------------------------

    #[test]
    fn test_truncated_golden_vectors_rejected() {
        // Every proper prefix that drops payload must fail, never yield a
        // default struct
        assert!(MbsDistributionSetupRequestTransfer::decode(
            &GOLDEN_SETUP_REQ[..GOLDEN_SETUP_REQ.len() - 1]
        )
        .is_err());
        assert!(MbsDistributionSetupResponseTransfer::decode(
            &GOLDEN_SETUP_RSP[..GOLDEN_SETUP_RSP.len() / 2]
        )
        .is_err());
        assert!(MbsDistributionSetupUnsuccessfulTransfer::decode(
            &GOLDEN_SETUP_FAIL[..GOLDEN_SETUP_FAIL.len() - 3]
        )
        .is_err());
        assert!(MbsDistributionReleaseRequestTransfer::decode(&GOLDEN_REL_REQ[..3]).is_err());
        assert!(MbsDistributionSetupRequestTransfer::decode(&[]).is_err());
        assert!(MbsDistributionSetupResponseTransfer::decode(&[0xFF]).is_err());
    }

    #[test]
    fn test_out_of_range_mbs_area_session_id_rejected() {
        // Craft a ReleaseRequestTransfer whose MBS-AreaSessionID uses the
        // INTEGER extension bracket with value 70000 (> 65535): a decoder
        // that wrapped with `as u16` would silently accept 4464 instead.
        let mut encoder = AperEncoder::new();
        encoder.write_bit(false); // seq ext
        encoder.write_bit(true); // area present
        encoder.write_bit(false); // tnl absent
        encoder.write_bit(false); // no iE-Extensions
        sample_session_id().encode(&mut encoder).unwrap();
        encoder.write_bit(true); // INTEGER extension bit
        encoder.encode_unconstrained_whole_number(70_000).unwrap();
        Cause::Nas(CauseNas::NormalRelease)
            .encode_aper(&mut encoder)
            .unwrap();
        encoder.align();
        let bytes = encoder.into_bytes().to_vec();
        let result = MbsDistributionReleaseRequestTransfer::decode(&bytes);
        assert!(
            matches!(
                result,
                Err(NgapError::InvalidIeValue {
                    ie_name: "MBS-AreaSessionID",
                    ..
                })
            ),
            "expected out-of-range MBS-AreaSessionID rejection, got {result:?}"
        );
    }

    #[test]
    fn test_deferred_mbs_service_area_rejected_not_skipped() {
        // Flip the mBS-ServiceArea presence bit (bit3) of the golden
        // response: 0x20 -> 0x30. The decoder has no MBS-ServiceArea codec
        // and must fail closed instead of misparsing the remaining stream.
        let mut bytes = GOLDEN_SETUP_RSP.to_vec();
        bytes[0] |= 0x10;
        let result = MbsDistributionSetupResponseTransfer::decode(&bytes);
        assert!(
            matches!(
                result,
                Err(NgapError::InvalidIeValue {
                    ie_name: "MBS-ServiceArea",
                    ..
                })
            ),
            "expected deferred MBS-ServiceArea rejection, got {result:?}"
        );
    }

    #[test]
    fn test_unknown_extension_criticality_drives_decode() {
        // A reject-criticality unknown protocol extension must fail the
        // decode; an ignore-criticality one must be skipped.
        let build = |criticality: Criticality| -> Vec<u8> {
            let mut encoder = AperEncoder::new();
            encoder.write_bit(false); // seq ext
            encoder.write_bit(false); // area absent
            encoder.write_bit(false); // tnl absent
            encoder.write_bit(true); // iE-Extensions present
            sample_session_id().encode(&mut encoder).unwrap();
            let field = ProtocolIeField {
                id: ProtocolIeId(60_000),
                criticality,
                value: vec![0xAB, 0xCD],
            };
            encode_extension_container(&mut encoder, &[field]).unwrap();
            encoder.align();
            encoder.into_bytes().to_vec()
        };

        match MbsDistributionSetupRequestTransfer::decode(&build(Criticality::Reject)) {
            Err(NgapError::IeNotComprehended { ie_id, .. }) => assert_eq!(ie_id, 60_000),
            other => panic!("expected IeNotComprehended, got {other:?}"),
        }

        let decoded =
            MbsDistributionSetupRequestTransfer::decode(&build(Criticality::Ignore)).unwrap();
        assert_eq!(decoded.mbs_session_id, sample_session_id());
        assert_eq!(decoded.tai_mbs_support_list, None);
    }

    #[test]
    fn test_list_bounds_enforced() {
        // SIZE(1..64): empty and oversized lists must fail on encode
        let mut transfer = golden_rsp_struct();
        transfer.mbs_qos_flows_to_be_setup_list = Vec::new();
        assert!(transfer.encode().is_err(), "empty QoS flow list accepted");
        transfer.mbs_qos_flows_to_be_setup_list = (0..65)
            .map(|i| MbsQosFlowsToBeSetupItem {
                mbs_qos_flow_identifier: (i % 64) as u8,
                mbs_qos_flow_level_qos_parameters: sample_qos_params(),
            })
            .collect();
        assert!(transfer.encode().is_err(), "65-item QoS flow list accepted");

        // TAIMBSSupportList SIZE(1..256)
        let tai = TaiMbsSupportItem {
            plmn_identity: [0x02, 0xF8, 0x39],
            tac: [0, 0, 1],
        };
        let request = MbsDistributionSetupRequestTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: None,
            shared_ngu_unicast_tnl_information: None,
            tai_mbs_support_list: Some(vec![tai; 257]),
        };
        assert!(request.encode().is_err(), "257-item TAI list accepted");
        let request = MbsDistributionSetupRequestTransfer {
            tai_mbs_support_list: Some(Vec::new()),
            ..request
        };
        assert!(request.encode().is_err(), "empty TAI list accepted");
    }

    #[test]
    fn test_nid_out_of_range_rejected_on_encode() {
        let transfer = MbsDistributionReleaseRequestTransfer {
            mbs_session_id: MbsSessionId {
                nid: Some(1u64 << 44),
                ..sample_session_id()
            },
            mbs_area_session_id: None,
            shared_ngu_unicast_tnl_information: None,
            cause: Cause::Nas(CauseNas::NormalRelease),
        };
        assert!(transfer.encode().is_err());
    }

    #[test]
    fn test_sequence_extension_additions_skipped() {
        // A future-release peer sets the SEQUENCE extension bit and appends
        // one open-type-wrapped addition after the root fields (X.691 §18.8).
        // The decoder must skip it and still return the root values; a
        // truncated addition must fail.
        let mut encoder = AperEncoder::new();
        encoder.write_bit(true); // seq ext SET
        encoder.write_bit(false); // area absent
        encoder.write_bit(false); // tnl absent
        encoder.write_bit(false); // no iE-Extensions
        sample_session_id().encode(&mut encoder).unwrap();
        Cause::Nas(CauseNas::NormalRelease)
            .encode_aper(&mut encoder)
            .unwrap();
        // extension additions: count-1=0 as normally-small (1+6 bits), 1-bit
        // presence map (present), open type len 2 + payload
        encoder.encode_normally_small_non_negative(0).unwrap();
        encoder.write_bit(true);
        encoder.encode_length_determinant(2).unwrap();
        encoder.write_bytes(&[0xDE, 0xAD]);
        encoder.align();
        let bytes = encoder.into_bytes().to_vec();

        let decoded = MbsDistributionReleaseRequestTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded.mbs_session_id, sample_session_id());
        assert_eq!(decoded.cause, Cause::Nas(CauseNas::NormalRelease));

        // Truncate inside the addition payload -> Err
        assert!(MbsDistributionReleaseRequestTransfer::decode(&bytes[..bytes.len() - 2]).is_err());
    }

    // ------------------------------------------------------------------
    // Round-trips with all optionals populated / max sizes
    // ------------------------------------------------------------------

    #[test]
    fn test_setup_request_transfer_all_optionals_roundtrip() {
        let transfer = MbsDistributionSetupRequestTransfer {
            mbs_session_id: MbsSessionId {
                nid: Some(0x0AB_CDEF_0123),
                ..sample_session_id()
            },
            mbs_area_session_id: Some(65_535),
            shared_ngu_unicast_tnl_information: Some(sample_unicast_tnl()),
            tai_mbs_support_list: Some(vec![
                TaiMbsSupportItem {
                    plmn_identity: [0x02, 0xF8, 0x39],
                    tac: [0, 0, 1],
                };
                MAX_TAI_MBS_SUPPORT
            ]),
        };
        let bytes = transfer.encode().unwrap();
        let decoded = MbsDistributionSetupRequestTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded, transfer);
        assert_eq!(
            decoded.tai_mbs_support_list.as_ref().unwrap().len(),
            MAX_TAI_MBS_SUPPORT
        );
    }

    #[test]
    fn test_setup_response_transfer_max_qos_flows_roundtrip() {
        let transfer = MbsDistributionSetupResponseTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: Some(7),
            shared_ngu_multicast_tnl_information: Some(SharedNguMulticastTnlInformation {
                ip_multicast_address: TransportLayerAddress::from_ipv6([
                    0xFF, 0x3E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                ip_source_address: TransportLayerAddress::from_ipv6([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ]),
                gtp_teid: [0xDE, 0xAD, 0xBE, 0xEF],
            }),
            mbs_qos_flows_to_be_setup_list: (0..MAX_MBS_QOS_FLOWS)
                .map(|i| MbsQosFlowsToBeSetupItem {
                    mbs_qos_flow_identifier: i as u8,
                    mbs_qos_flow_level_qos_parameters: sample_qos_params(),
                })
                .collect(),
            mbs_session_status: MbsSessionStatus::Deactivated,
        };
        let bytes = transfer.encode().unwrap();
        let decoded = MbsDistributionSetupResponseTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded, transfer);
        assert_eq!(
            decoded.mbs_qos_flows_to_be_setup_list.len(),
            MAX_MBS_QOS_FLOWS
        );
    }

    #[test]
    fn test_unsuccessful_transfer_with_criticality_diagnostics_roundtrip() {
        let transfer = MbsDistributionSetupUnsuccessfulTransfer {
            mbs_session_id: sample_session_id(),
            mbs_area_session_id: None,
            cause: Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable),
            criticality_diagnostics: Some(CriticalityDiagnostics {
                procedure_code: Some(29),
                triggering_message: Some(0),
                procedure_criticality: Some(0),
                ies: vec![IeCriticalityDiagnostics {
                    ie_criticality: Criticality::Reject,
                    ie_id: IE_ID_TAI_MBS_SUPPORT_LIST,
                    type_of_error: TypeOfError::NotUnderstood,
                }],
            }),
        };
        let bytes = transfer.encode().unwrap();
        let decoded = MbsDistributionSetupUnsuccessfulTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded, transfer);
    }

    // ------------------------------------------------------------------
    // Property tests: encode(decode(x)) == x over optional-presence
    // combinations, list sizes up to the ASN.1 maxima, and value ranges
    // ------------------------------------------------------------------

    fn arb_session_id() -> impl Strategy<Value = MbsSessionId> {
        (
            any::<[u8; 3]>(),
            any::<[u8; 3]>(),
            prop::option::of(0u64..(1u64 << 44)),
        )
            .prop_map(|(plmn_identity, mbs_service_id, nid)| MbsSessionId {
                plmn_identity,
                mbs_service_id,
                nid,
            })
    }

    fn arb_unicast_tnl() -> impl Strategy<Value = UpTransportLayerInformation> {
        (any::<[u8; 4]>(), any::<[u8; 4]>()).prop_map(|(addr, teid)| {
            UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                transport_layer_address: TransportLayerAddress::from_ipv4(addr),
                gtp_teid: teid,
            })
        })
    }

    fn arb_multicast_tnl() -> impl Strategy<Value = SharedNguMulticastTnlInformation> {
        (any::<[u8; 4]>(), any::<[u8; 16]>(), any::<[u8; 4]>()).prop_map(|(mc4, src6, gtp_teid)| {
            SharedNguMulticastTnlInformation {
                ip_multicast_address: TransportLayerAddress::from_ipv4(mc4),
                ip_source_address: TransportLayerAddress::from_ipv6(src6),
                gtp_teid,
            }
        })
    }

    fn arb_tai_list() -> impl Strategy<Value = Vec<TaiMbsSupportItem>> {
        prop::collection::vec(
            (any::<[u8; 3]>(), any::<[u8; 3]>())
                .prop_map(|(plmn_identity, tac)| TaiMbsSupportItem { plmn_identity, tac }),
            1..=MAX_TAI_MBS_SUPPORT,
        )
    }

    fn arb_qos_flow_list() -> impl Strategy<Value = Vec<MbsQosFlowsToBeSetupItem>> {
        prop::collection::vec(
            (0u8..=63, 0u16..=255).prop_map(|(qfi, five_qi)| MbsQosFlowsToBeSetupItem {
                mbs_qos_flow_identifier: qfi,
                mbs_qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                    qos_characteristics: QosCharacteristics::NonDynamic5qi(
                        NonDynamic5qiDescriptor::new(five_qi),
                    ),
                    ..sample_qos_params()
                },
            }),
            1..=MAX_MBS_QOS_FLOWS,
        )
    }

    fn arb_cause() -> impl Strategy<Value = Cause> {
        prop_oneof![
            Just(Cause::RadioNetwork(CauseRadioNetwork::Unspecified)),
            Just(Cause::RadioNetwork(CauseRadioNetwork::CellNotAvailable)),
            Just(Cause::Nas(CauseNas::NormalRelease)),
            Just(Cause::Nas(CauseNas::Unspecified)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_setup_request_roundtrip(
            session_id in arb_session_id(),
            area in prop::option::of(any::<u16>()),
            tnl in prop::option::of(arb_unicast_tnl()),
            tai in prop::option::of(arb_tai_list()),
        ) {
            let transfer = MbsDistributionSetupRequestTransfer {
                mbs_session_id: session_id,
                mbs_area_session_id: area,
                shared_ngu_unicast_tnl_information: tnl,
                tai_mbs_support_list: tai,
            };
            let bytes = transfer.encode().unwrap();
            let decoded = MbsDistributionSetupRequestTransfer::decode(&bytes).unwrap();
            prop_assert_eq!(&decoded, &transfer);
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }

        #[test]
        fn prop_setup_response_roundtrip(
            session_id in arb_session_id(),
            area in prop::option::of(any::<u16>()),
            tnl in prop::option::of(arb_multicast_tnl()),
            flows in arb_qos_flow_list(),
            deactivated in any::<bool>(),
        ) {
            let transfer = MbsDistributionSetupResponseTransfer {
                mbs_session_id: session_id,
                mbs_area_session_id: area,
                shared_ngu_multicast_tnl_information: tnl,
                mbs_qos_flows_to_be_setup_list: flows,
                mbs_session_status: if deactivated {
                    MbsSessionStatus::Deactivated
                } else {
                    MbsSessionStatus::Activated
                },
            };
            let bytes = transfer.encode().unwrap();
            let decoded = MbsDistributionSetupResponseTransfer::decode(&bytes).unwrap();
            prop_assert_eq!(&decoded, &transfer);
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }

        #[test]
        fn prop_setup_unsuccessful_roundtrip(
            session_id in arb_session_id(),
            area in prop::option::of(any::<u16>()),
            cause in arb_cause(),
            with_diag in any::<bool>(),
        ) {
            let transfer = MbsDistributionSetupUnsuccessfulTransfer {
                mbs_session_id: session_id,
                mbs_area_session_id: area,
                cause,
                criticality_diagnostics: with_diag.then(|| CriticalityDiagnostics {
                    procedure_code: Some(29),
                    triggering_message: None,
                    procedure_criticality: None,
                    ies: Vec::new(),
                }),
            };
            let bytes = transfer.encode().unwrap();
            let decoded = MbsDistributionSetupUnsuccessfulTransfer::decode(&bytes).unwrap();
            prop_assert_eq!(&decoded, &transfer);
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }

        #[test]
        fn prop_release_request_roundtrip(
            session_id in arb_session_id(),
            area in prop::option::of(any::<u16>()),
            tnl in prop::option::of(arb_unicast_tnl()),
            cause in arb_cause(),
        ) {
            let transfer = MbsDistributionReleaseRequestTransfer {
                mbs_session_id: session_id,
                mbs_area_session_id: area,
                shared_ngu_unicast_tnl_information: tnl,
                cause,
            };
            let bytes = transfer.encode().unwrap();
            let decoded = MbsDistributionReleaseRequestTransfer::decode(&bytes).unwrap();
            prop_assert_eq!(&decoded, &transfer);
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }
}
