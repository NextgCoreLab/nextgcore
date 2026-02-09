//! NGAP Information Elements
//!
//! Protocol IE containers and common IEs from NGAP-IEs (3GPP TS 38.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerResult};
use super::types::{Criticality, ProtocolIeId};

/// ProtocolIE-Field - Single IE with ID, criticality, and value
/// ASN.1: ProtocolIE-Field ::= SEQUENCE { id, criticality, value }
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolIeField {
    pub id: ProtocolIeId,
    pub criticality: Criticality,
    pub value: Vec<u8>, // Raw APER-encoded value
}

impl AperEncode for ProtocolIeField {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.id.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        
        // Value is encoded as OPEN TYPE
        encoder.encode_length_determinant(self.value.len())?;
        encoder.write_bytes(&self.value);
        
        Ok(())
    }
}

impl AperDecode for ProtocolIeField {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let id = ProtocolIeId::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        
        let value_len = decoder.decode_length_determinant()?;
        let value = decoder.read_bytes(value_len)?;
        
        Ok(ProtocolIeField {
            id,
            criticality,
            value,
        })
    }
}


/// ProtocolIE-Container - Sequence of IEs
/// ASN.1: ProtocolIE-Container ::= SEQUENCE (SIZE (0..maxProtocolIEs)) OF ProtocolIE-Field
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProtocolIeContainer {
    pub ies: Vec<ProtocolIeField>,
}

impl ProtocolIeContainer {
    // maxProtocolIEs = 65535
    pub const MAX_PROTOCOL_IES: usize = 65535;
    pub const SIZE_CONSTRAINT: Constraint = Constraint::new(0, 65535);

    pub fn new() -> Self {
        Self { ies: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { ies: Vec::with_capacity(capacity) }
    }

    pub fn push(&mut self, ie: ProtocolIeField) {
        self.ies.push(ie);
    }

    pub fn len(&self) -> usize {
        self.ies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ies.is_empty()
    }

    /// Find an IE by ID
    pub fn find(&self, id: ProtocolIeId) -> Option<&ProtocolIeField> {
        self.ies.iter().find(|ie| ie.id == id)
    }

    /// Find an IE by ID (mutable)
    pub fn find_mut(&mut self, id: ProtocolIeId) -> Option<&mut ProtocolIeField> {
        self.ies.iter_mut().find(|ie| ie.id == id)
    }
}

impl AperEncode for ProtocolIeContainer {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Encode length (constrained to 0..65535)
        encoder.encode_constrained_length(self.ies.len(), 0, Self::MAX_PROTOCOL_IES)?;
        
        // Encode each IE
        for ie in &self.ies {
            ie.encode_aper(encoder)?;
        }
        
        Ok(())
    }
}

impl AperDecode for ProtocolIeContainer {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(0, Self::MAX_PROTOCOL_IES)?;
        
        let mut ies = Vec::with_capacity(count);
        for _ in 0..count {
            ies.push(ProtocolIeField::decode_aper(decoder)?);
        }
        
        Ok(ProtocolIeContainer { ies })
    }
}


/// AMF-UE-NGAP-ID - Unique identifier for UE in AMF
/// ASN.1: AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AmfUeNgapId(pub u64);

impl AmfUeNgapId {
    // 40-bit value (0 to 2^40 - 1)
    pub const CONSTRAINT: Constraint = Constraint::new(0, 1099511627775);
}

impl AperEncode for AmfUeNgapId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for AmfUeNgapId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(AmfUeNgapId(value as u64))
    }
}

/// RAN-UE-NGAP-ID - Unique identifier for UE in RAN
/// ASN.1: RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RanUeNgapId(pub u32);

impl RanUeNgapId {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 4294967295);
}

impl AperEncode for RanUeNgapId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for RanUeNgapId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(RanUeNgapId(value as u32))
    }
}

/// TimeToWait - Time to wait before retrying
/// ASN.1: TimeToWait ::= ENUMERATED { v1s, v2s, v5s, v10s, v20s, v60s, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimeToWait {
    V1s = 0,
    V2s = 1,
    V5s = 2,
    V10s = 3,
    V20s = 4,
    V60s = 5,
}

impl TimeToWait {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 5);

    /// Get the wait time in seconds
    pub fn seconds(&self) -> u32 {
        match self {
            TimeToWait::V1s => 1,
            TimeToWait::V2s => 2,
            TimeToWait::V5s => 5,
            TimeToWait::V10s => 10,
            TimeToWait::V20s => 20,
            TimeToWait::V60s => 60,
        }
    }
}

impl AperEncode for TimeToWait {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for TimeToWait {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(TimeToWait::V1s),
            1 => Ok(TimeToWait::V2s),
            2 => Ok(TimeToWait::V5s),
            3 => Ok(TimeToWait::V10s),
            4 => Ok(TimeToWait::V20s),
            5 => Ok(TimeToWait::V60s),
            _ => Err(crate::per::PerError::DecodeError(
                format!("Unknown TimeToWait value: {value}")
            )),
        }
    }
}


/// RelativeAMFCapacity - Relative capacity of AMF
/// ASN.1: RelativeAMFCapacity ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelativeAmfCapacity(pub u8);

impl RelativeAmfCapacity {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);
}

impl AperEncode for RelativeAmfCapacity {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for RelativeAmfCapacity {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(RelativeAmfCapacity(value as u8))
    }
}

/// NAS-PDU - NAS Protocol Data Unit (opaque octet string)
/// ASN.1: NAS-PDU ::= OCTET STRING
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NasPdu(pub Vec<u8>);

impl NasPdu {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AperEncode for NasPdu {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_octet_string(&self.0, None, None)
    }
}

impl AperDecode for NasPdu {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let data = decoder.decode_octet_string(None, None)?;
        Ok(NasPdu(data))
    }
}

//
// Additional typed NGAP IEs (B16.1)
//

/// GlobalRANNodeID - Global RAN Node Identifier (CHOICE)
/// ASN.1: GlobalRANNodeID ::= CHOICE { globalGNB-ID, globalNgENB-ID, ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRanNodeId {
    GlobalGnbId { plmn_id: [u8; 3], gnb_id: u32 },
    GlobalNgEnbId { plmn_id: [u8; 3], enb_id: u32 },
}

/// PLMN-Identity - PLMN Identifier (3 octets)
/// ASN.1: PLMNIdentity ::= OCTET STRING (SIZE (3))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlmnIdentity(pub [u8; 3]);

impl PlmnIdentity {
    pub fn new(plmn: [u8; 3]) -> Self {
        Self(plmn)
    }

    pub fn from_mcc_mnc(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        let mut plmn = [0u8; 3];

        let mcc1 = (mcc / 100) % 10;
        let mcc2 = (mcc / 10) % 10;
        let mcc3 = mcc % 10;

        let mnc1 = (mnc / 100) % 10;
        let mnc2 = (mnc / 10) % 10;
        let mnc3 = mnc % 10;

        plmn[0] = ((mcc2 as u8) << 4) | (mcc1 as u8);
        plmn[1] = if mnc_len == 2 {
            0xF0 | (mcc3 as u8)
        } else {
            ((mnc3 as u8) << 4) | (mcc3 as u8)
        };
        plmn[2] = ((mnc2 as u8) << 4) | (mnc1 as u8);

        Self(plmn)
    }
}

impl AperEncode for PlmnIdentity {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_octet_string(&self.0, Some(3), Some(3))
    }
}

impl AperDecode for PlmnIdentity {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let data = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut arr = [0u8; 3];
        arr.copy_from_slice(&data);
        Ok(PlmnIdentity(arr))
    }
}

/// S-NSSAI - Single Network Slice Selection Assistance Information
/// ASN.1: S-NSSAI ::= SEQUENCE { sST, sD OPTIONAL, ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<[u8; 3]>,
}

impl SNssai {
    pub fn new(sst: u8) -> Self {
        Self { sst, sd: None }
    }

    pub fn with_sd(sst: u8, sd: [u8; 3]) -> Self {
        Self { sst, sd: Some(sd) }
    }
}

/// UE-NGAP-IDs - Choice of UE identifiers
/// ASN.1: UE-NGAP-IDs ::= CHOICE { uE-NGAP-ID-pair, aMF-UE-NGAP-ID, ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeNgapIds {
    UeNgapIdPair { amf_ue_ngap_id: AmfUeNgapId, ran_ue_ngap_id: RanUeNgapId },
    AmfUeNgapId(AmfUeNgapId),
}

impl AperEncode for UeNgapIds {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            UeNgapIds::UeNgapIdPair { amf_ue_ngap_id, ran_ue_ngap_id } => {
                encoder.encode_choice_index(0, 2, true)?;
                amf_ue_ngap_id.encode_aper(encoder)?;
                ran_ue_ngap_id.encode_aper(encoder)?;
            }
            UeNgapIds::AmfUeNgapId(id) => {
                encoder.encode_choice_index(1, 2, true)?;
                id.encode_aper(encoder)?;
            }
        }
        Ok(())
    }
}

impl AperDecode for UeNgapIds {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(2, true)?;
        match index {
            0 => {
                let amf_ue_ngap_id = AmfUeNgapId::decode_aper(decoder)?;
                let ran_ue_ngap_id = RanUeNgapId::decode_aper(decoder)?;
                Ok(UeNgapIds::UeNgapIdPair { amf_ue_ngap_id, ran_ue_ngap_id })
            }
            1 => {
                let id = AmfUeNgapId::decode_aper(decoder)?;
                Ok(UeNgapIds::AmfUeNgapId(id))
            }
            _ => Err(crate::per::PerError::InvalidChoiceIndex { index, max: 1 }),
        }
    }
}

/// PagingDRX - Paging DRX cycle
/// ASN.1: PagingDRX ::= ENUMERATED { v32, v64, v128, v256, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingDrx {
    V32 = 0,
    V64 = 1,
    V128 = 2,
    V256 = 3,
}

impl PagingDrx {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 3);

    pub fn value(&self) -> u32 {
        match self {
            PagingDrx::V32 => 32,
            PagingDrx::V64 => 64,
            PagingDrx::V128 => 128,
            PagingDrx::V256 => 256,
        }
    }
}

impl AperEncode for PagingDrx {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for PagingDrx {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(PagingDrx::V32),
            1 => Ok(PagingDrx::V64),
            2 => Ok(PagingDrx::V128),
            3 => Ok(PagingDrx::V256),
            _ => Err(crate::per::PerError::DecodeError(
                format!("Unknown PagingDrx value: {value}")
            )),
        }
    }
}

/// TAC - Tracking Area Code (3 octets)
/// ASN.1: TAC ::= OCTET STRING (SIZE (3))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tac(pub [u8; 3]);

impl Tac {
    pub fn new(tac: [u8; 3]) -> Self {
        Self(tac)
    }

    pub fn from_u24(value: u32) -> Self {
        let bytes = value.to_be_bytes();
        Self([bytes[1], bytes[2], bytes[3]])
    }

    pub fn to_u24(&self) -> u32 {
        ((self.0[0] as u32) << 16) | ((self.0[1] as u32) << 8) | (self.0[2] as u32)
    }
}

impl AperEncode for Tac {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_octet_string(&self.0, Some(3), Some(3))
    }
}

impl AperDecode for Tac {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let data = decoder.decode_octet_string(Some(3), Some(3))?;
        let mut arr = [0u8; 3];
        arr.copy_from_slice(&data);
        Ok(Tac(arr))
    }
}

/// UserLocationInformation - UE location information (CHOICE)
/// ASN.1: UserLocationInformation ::= CHOICE { userLocationInformationEUTRA, userLocationInformationNR, ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserLocationInformation {
    Eutra {
        plmn_id: PlmnIdentity,
        eutran_cell_id: u32,
        tac: Tac,
    },
    Nr {
        plmn_id: PlmnIdentity,
        nr_cell_id: u64,
        tac: Tac,
    },
}

/// RRC-Establishment-Cause
/// ASN.1: RRCEstablishmentCause ::= ENUMERATED { emergency, highPriorityAccess, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RrcEstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    MoVideoCall = 6,
    MoSms = 7,
    MpsCall = 8,
    McsCall = 9,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per::{AperEncoder, AperDecoder};

    #[test]
    fn test_amf_ue_ngap_id_roundtrip() {
        let id = AmfUeNgapId(12345678);
        
        let mut encoder = AperEncoder::new();
        id.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = AmfUeNgapId::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_ran_ue_ngap_id_roundtrip() {
        let id = RanUeNgapId(0xDEADBEEF);
        
        let mut encoder = AperEncoder::new();
        id.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = RanUeNgapId::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_protocol_ie_container_roundtrip() {
        let mut container = ProtocolIeContainer::new();
        container.push(ProtocolIeField {
            id: ProtocolIeId::AMF_UE_NGAP_ID,
            criticality: Criticality::Reject,
            value: vec![0x00, 0x01, 0x02, 0x03],
        });
        container.push(ProtocolIeField {
            id: ProtocolIeId::RAN_UE_NGAP_ID,
            criticality: Criticality::Reject,
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
        
        let mut encoder = AperEncoder::new();
        container.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = ProtocolIeContainer::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(container.len(), decoded.len());
        assert_eq!(container.ies[0].id, decoded.ies[0].id);
        assert_eq!(container.ies[1].id, decoded.ies[1].id);
    }
}
