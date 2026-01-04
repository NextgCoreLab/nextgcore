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
                format!("Unknown TimeToWait value: {}", value)
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
