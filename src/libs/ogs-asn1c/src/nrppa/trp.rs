//! NRPPa TRP Information Exchange IEs (3GPP TS 38.455 §9.3.4, ASN.1 L18625+).
//!
//! Typed codecs for the TRP Information Exchange procedure: the request-side
//! `TRPList` / `TRPInformationTypeListTRPReq` and the response-side
//! `TRPInformationListTRPResp` → `TRPInformation` → `TRPInformationTypeResponseList`.
//!
//! BOUNDED v1: the response-item CHOICE types only the cheap, position-relevant
//! alternatives — `pCI-NR`, `cGI-NR`, `aRFCN` and `geographicalCoordinates`
//! (the TRP position, down to the reusable `NG-RANAccessPointPosition` leaf).
//! The heavy PRS/SSB/spatial/relative-time alternatives, `TRPPositionReferenced`,
//! `NGRANHighAccuracyAccessPointPosition`, `dLPRSResourceCoordinates`, and every
//! `choice-extension` / `iE-Extensions` are modeled UNSUPPORTED — never emitted,
//! and rejected on decode if a peer selects/sets them (each deferral documented
//! inline), mirroring the discipline used elsewhere in this crate.

use super::ies::{CgiNr, NgRanAccessPointPosition};
use super::types::{Criticality, ProtocolIeId, MAX_NO_TRPS, MAX_NO_TRP_INFO_TYPES};
use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerError, PerResult};

// ---------------------------------------------------------------------------
// TRP-ID / TRPItem / TRPList
// ---------------------------------------------------------------------------

/// TRP-ID ::= INTEGER (1..maxnoTRPs, ...)   -- EXTENSIBLE
///
/// An extensible constrained INTEGER: a leading extension bit (0 = the value is
/// in the root range) precedes the constrained whole number. Because the root
/// `1..65535` already spans the full practical `u16` range, an extension
/// addition could only carry a value that cannot fit a `u16`, so a set
/// extension bit is rejected in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrpId(pub u16);

impl TrpId {
    pub const CONSTRAINT: Constraint = Constraint::new(1, MAX_NO_TRPS as i64);
}

impl AperEncode for TrpId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Root value: extension bit 0, then the constrained whole number
        // (range 65535 <= 65536 -> two octet-aligned octets).
        encoder.write_bit(false);
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for TrpId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let extended = decoder.read_bit()?;
        if extended {
            return Err(PerError::DecodeError(
                "TRP-ID extension value not supported in NRPPa v1".to_string(),
            ));
        }
        let v = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(TrpId(v as u16))
    }
}

/// TRPItem ::= SEQUENCE { tRP-ID TRP-ID, iE-Extensions OPTIONAL, ... }
/// EXTENSIBLE SEQUENCE; the single optional (`iE-Extensions`) is UNSUPPORTED in
/// v1 (always absent on encode; rejected on decode if its presence bit is set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrpItem {
    pub trp_id: TrpId,
}

impl AperEncode for TrpItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // iE-Extensions absent
        self.trp_id.encode_aper(encoder)
    }
}

impl AperDecode for TrpItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let trp_id = TrpId::decode_aper(decoder)?;
        if ie_ext {
            return Err(PerError::DecodeError(
                "TRPItem iE-Extensions not supported in NRPPa v1".to_string(),
            ));
        }
        Ok(TrpItem { trp_id })
    }
}

/// TRPList ::= SEQUENCE (SIZE(1..maxnoTRPs)) OF TRPItem
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrpList {
    pub items: Vec<TrpItem>,
}

impl AperEncode for TrpList {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.items.len(), 1, MAX_NO_TRPS)?;
        for item in &self.items {
            item.encode_aper(encoder)?;
        }
        Ok(())
    }
}

impl AperDecode for TrpList {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(1, MAX_NO_TRPS)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            items.push(TrpItem::decode_aper(decoder)?);
        }
        Ok(TrpList { items })
    }
}

// ---------------------------------------------------------------------------
// TRPInformationTypeItem / TRPInformationTypeListTRPReq
// ---------------------------------------------------------------------------

/// TRPInformationTypeItem ::= ENUMERATED {
///     nrPCI, nG-RAN-CGI, arfcn, pRSConfig, sSBInfo, sFNInitTime,
///     spatialDirectInfo, geoCoord, ..., trp-type, ondemandPRSInfo, trpTxTeg,
///     beam-antenna-info, mobile-trp-location-info, commonTA }
/// EXTENSIBLE ENUMERATED, root values 0..7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TrpInformationTypeItem {
    NrPci = 0,
    NgRanCgi = 1,
    Arfcn = 2,
    PrsConfig = 3,
    SsbInfo = 4,
    SfnInitTime = 5,
    SpatialDirectInfo = 6,
    GeoCoord = 7,
    // Extension additions (root ends at index 7).
    TrpType = 8,
    OndemandPrsInfo = 9,
    TrpTxTeg = 10,
    BeamAntennaInfo = 11,
    MobileTrpLocationInfo = 12,
    CommonTa = 13,
}

impl TrpInformationTypeItem {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 7);
}

impl TryFrom<i64> for TrpInformationTypeItem {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NrPci),
            1 => Ok(Self::NgRanCgi),
            2 => Ok(Self::Arfcn),
            3 => Ok(Self::PrsConfig),
            4 => Ok(Self::SsbInfo),
            5 => Ok(Self::SfnInitTime),
            6 => Ok(Self::SpatialDirectInfo),
            7 => Ok(Self::GeoCoord),
            8 => Ok(Self::TrpType),
            9 => Ok(Self::OndemandPrsInfo),
            10 => Ok(Self::TrpTxTeg),
            11 => Ok(Self::BeamAntennaInfo),
            12 => Ok(Self::MobileTrpLocationInfo),
            13 => Ok(Self::CommonTa),
            _ => Err(PerError::DecodeError(format!(
                "Unknown TRPInformationTypeItem value: {value}"
            ))),
        }
    }
}

impl AperEncode for TrpInformationTypeItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for TrpInformationTypeItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        Self::try_from(decoder.decode_enumerated(&Self::CONSTRAINT)?)
    }
}

/// TRPInformationTypeListTRPReq ::= SEQUENCE (SIZE(1..maxnoTRPInfoTypes)) OF
///        ProtocolIE-Single-Container {{ TRPInformationTypeItemTRPReq }}
///
/// Each list member is a single-container `ProtocolIE-Field` carrying
/// id-TRPInformationTypeItem (57), criticality reject, and a
/// `TRPInformationTypeItem` as its open-type value (same shape as
/// `MeasurementQuantities`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrpInformationTypeListTrpReq {
    pub items: Vec<TrpInformationTypeItem>,
}

impl AperEncode for TrpInformationTypeListTrpReq {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.items.len(), 1, MAX_NO_TRP_INFO_TYPES)?;
        for item in &self.items {
            ProtocolIeId::TRP_INFORMATION_TYPE_ITEM.encode_aper(encoder)?;
            Criticality::Reject.encode_aper(encoder)?;
            let mut inner = AperEncoder::new();
            item.encode_aper(&mut inner)?;
            inner.align();
            encoder.encode_fragmented_octets(&inner.into_bytes())?;
        }
        Ok(())
    }
}

impl AperDecode for TrpInformationTypeListTrpReq {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(1, MAX_NO_TRP_INFO_TYPES)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let _id = ProtocolIeId::decode_aper(decoder)?;
            let _crit = Criticality::decode_aper(decoder)?;
            let mut value = Vec::new();
            loop {
                let (len, fragmented) = decoder.decode_length_fragment()?;
                value.extend_from_slice(&decoder.read_bytes(len)?);
                if !fragmented {
                    break;
                }
            }
            let mut inner = AperDecoder::new(&value);
            items.push(TrpInformationTypeItem::decode_aper(&mut inner)?);
        }
        Ok(TrpInformationTypeListTrpReq { items })
    }
}

// ---------------------------------------------------------------------------
// TRP position (geographical coordinates -> direct -> NG-RANAccessPointPosition)
// ---------------------------------------------------------------------------

/// TRPPositionDirectAccuracy ::= CHOICE {
///     tRPPosition NG-RANAccessPointPosition,
///     tRPHAposition NGRANHighAccuracyAccessPointPosition,
///     choice-extension ProtocolIE-Single-Container {{...}} }
/// Non-extensible CHOICE, 3 alternatives -> 2-bit index. v1 types only the
/// `tRPPosition` (GAD ellipsoid-point) leaf; the high-accuracy and
/// choice-extension alternatives are DEFERRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrpPositionDirectAccuracy {
    TrpPosition(NgRanAccessPointPosition),
}

impl TrpPositionDirectAccuracy {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = false;
}

impl AperEncode for TrpPositionDirectAccuracy {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            TrpPositionDirectAccuracy::TrpPosition(pos) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                pos.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for TrpPositionDirectAccuracy {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(TrpPositionDirectAccuracy::TrpPosition(
                NgRanAccessPointPosition::decode_aper(decoder)?,
            )),
            1 => Err(PerError::DecodeError(
                "TRPPositionDirectAccuracy tRPHAposition (NGRANHighAccuracyAccessPointPosition) \
                 not supported in NRPPa v1"
                    .to_string(),
            )),
            2 => Err(PerError::DecodeError(
                "TRPPositionDirectAccuracy choice-extension not supported in NRPPa v1".to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// TRPPositionDirect ::= SEQUENCE { accuracy TRPPositionDirectAccuracy,
///        iE-extensions OPTIONAL, ... }
/// EXTENSIBLE; the single optional (`iE-extensions`) is UNSUPPORTED in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrpPositionDirect {
    pub accuracy: TrpPositionDirectAccuracy,
}

impl AperEncode for TrpPositionDirect {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // iE-extensions absent
        self.accuracy.encode_aper(encoder)
    }
}

impl AperDecode for TrpPositionDirect {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let accuracy = TrpPositionDirectAccuracy::decode_aper(decoder)?;
        if ie_ext {
            return Err(PerError::DecodeError(
                "TRPPositionDirect iE-extensions not supported in NRPPa v1".to_string(),
            ));
        }
        Ok(TrpPositionDirect { accuracy })
    }
}

/// TRPPositionDefinitionType ::= CHOICE { direct TRPPositionDirect,
///        referenced TRPPositionReferenced, choice-extension ... }
/// Non-extensible CHOICE, 3 alternatives -> 2-bit index. v1 types only the
/// `direct` alternative; `referenced` and `choice-extension` are DEFERRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrpPositionDefinitionType {
    Direct(TrpPositionDirect),
}

impl TrpPositionDefinitionType {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = false;
}

impl AperEncode for TrpPositionDefinitionType {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            TrpPositionDefinitionType::Direct(direct) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                direct.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for TrpPositionDefinitionType {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(TrpPositionDefinitionType::Direct(
                TrpPositionDirect::decode_aper(decoder)?,
            )),
            1 => Err(PerError::DecodeError(
                "TRPPositionDefinitionType referenced (TRPPositionReferenced) not supported in \
                 NRPPa v1"
                    .to_string(),
            )),
            2 => Err(PerError::DecodeError(
                "TRPPositionDefinitionType choice-extension not supported in NRPPa v1".to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// GeographicalCoordinates ::= SEQUENCE { tRPPositionDefinitionType,
///        dLPRSResourceCoordinates OPTIONAL, iE-Extensions OPTIONAL, ... }
/// EXTENSIBLE; both optionals (`dLPRSResourceCoordinates`, `iE-Extensions`) are
/// UNSUPPORTED in v1 (absent on encode; rejected on decode if their bit is set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeographicalCoordinates {
    pub position_definition_type: TrpPositionDefinitionType,
}

impl AperEncode for GeographicalCoordinates {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // dLPRSResourceCoordinates absent
        encoder.write_bit(false); // iE-Extensions absent
        self.position_definition_type.encode_aper(encoder)
    }
}

impl AperDecode for GeographicalCoordinates {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let dlprs_present = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        if dlprs_present {
            return Err(PerError::DecodeError(
                "GeographicalCoordinates dLPRSResourceCoordinates not supported in NRPPa v1"
                    .to_string(),
            ));
        }
        let position_definition_type = TrpPositionDefinitionType::decode_aper(decoder)?;
        if ie_ext {
            return Err(PerError::DecodeError(
                "GeographicalCoordinates iE-Extensions not supported in NRPPa v1".to_string(),
            ));
        }
        Ok(GeographicalCoordinates {
            position_definition_type,
        })
    }
}

// ---------------------------------------------------------------------------
// TRPInformationTypeResponseItem / List / TRPInformation
// ---------------------------------------------------------------------------

/// TRPInformationTypeResponseItem ::= CHOICE {
///     pCI-NR INTEGER (0..1007), cGI-NR CGI-NR, aRFCN INTEGER (0..3279165),
///     pRSConfiguration, sSBinformation, sFNInitialisationTime,
///     spatialDirectionInformation, geographicalCoordinates,
///     choice-extension ProtocolIE-Single-Container {{...}} }
/// Non-extensible CHOICE, 9 alternatives -> 4-bit index. v1 types indices 0/1/2
/// (pCI-NR / cGI-NR / aRFCN) and 7 (geographicalCoordinates — the TRP position).
/// Indices 3/4/5/6 (PRS/SSB/SFN-init/spatial) and 8 (choice-extension) are
/// DEFERRED: never encoded, rejected on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrpInformationTypeResponseItem {
    PciNr(u16),
    CgiNr(CgiNr),
    Arfcn(u32),
    GeographicalCoordinates(GeographicalCoordinates),
}

impl TrpInformationTypeResponseItem {
    pub const NUM_ALTERNATIVES: usize = 9;
    pub const EXTENSIBLE: bool = false;
    const PCI_NR: Constraint = Constraint::new(0, 1007);
    const ARFCN: Constraint = Constraint::new(0, 3279165);
}

impl AperEncode for TrpInformationTypeResponseItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            TrpInformationTypeResponseItem::PciNr(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::PCI_NR)
            }
            TrpInformationTypeResponseItem::CgiNr(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            TrpInformationTypeResponseItem::Arfcn(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::ARFCN)
            }
            TrpInformationTypeResponseItem::GeographicalCoordinates(v) => {
                encoder.encode_choice_index(7, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for TrpInformationTypeResponseItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(TrpInformationTypeResponseItem::PciNr(
                decoder.decode_constrained_whole_number(&Self::PCI_NR)? as u16,
            )),
            1 => Ok(TrpInformationTypeResponseItem::CgiNr(CgiNr::decode_aper(
                decoder,
            )?)),
            2 => Ok(TrpInformationTypeResponseItem::Arfcn(
                decoder.decode_constrained_whole_number(&Self::ARFCN)? as u32,
            )),
            3 => Err(PerError::DecodeError(
                "TRPInformationTypeResponseItem pRSConfiguration not supported in NRPPa v1"
                    .to_string(),
            )),
            4 => Err(PerError::DecodeError(
                "TRPInformationTypeResponseItem sSBinformation not supported in NRPPa v1"
                    .to_string(),
            )),
            5 => Err(PerError::DecodeError(
                "TRPInformationTypeResponseItem sFNInitialisationTime not supported in NRPPa v1"
                    .to_string(),
            )),
            6 => Err(PerError::DecodeError(
                "TRPInformationTypeResponseItem spatialDirectionInformation not supported in \
                 NRPPa v1"
                    .to_string(),
            )),
            7 => Ok(TrpInformationTypeResponseItem::GeographicalCoordinates(
                GeographicalCoordinates::decode_aper(decoder)?,
            )),
            8 => Err(PerError::DecodeError(
                "TRPInformationTypeResponseItem choice-extension not supported in NRPPa v1"
                    .to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// TRPInformationTypeResponseList ::= SEQUENCE (SIZE(1..maxnoTRPInfoTypes)) OF
///        TRPInformationTypeResponseItem
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrpInformationTypeResponseList {
    pub items: Vec<TrpInformationTypeResponseItem>,
}

impl AperEncode for TrpInformationTypeResponseList {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.items.len(), 1, MAX_NO_TRP_INFO_TYPES)?;
        for item in &self.items {
            item.encode_aper(encoder)?;
        }
        Ok(())
    }
}

impl AperDecode for TrpInformationTypeResponseList {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(1, MAX_NO_TRP_INFO_TYPES)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            items.push(TrpInformationTypeResponseItem::decode_aper(decoder)?);
        }
        Ok(TrpInformationTypeResponseList { items })
    }
}

/// TRPInformation ::= SEQUENCE { tRP-ID TRP-ID,
///        tRPInformationTypeResponseList TRPInformationTypeResponseList,
///        iE-Extensions OPTIONAL, ... }
/// EXTENSIBLE; the single optional (`iE-Extensions`) is UNSUPPORTED in v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrpInformation {
    pub trp_id: TrpId,
    pub response_list: TrpInformationTypeResponseList,
}

impl AperEncode for TrpInformation {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false); // extension marker
        encoder.write_bit(false); // iE-Extensions absent
        self.trp_id.encode_aper(encoder)?;
        self.response_list.encode_aper(encoder)
    }
}

impl AperDecode for TrpInformation {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let ie_ext = decoder.read_bit()?;
        let trp_id = TrpId::decode_aper(decoder)?;
        let response_list = TrpInformationTypeResponseList::decode_aper(decoder)?;
        if ie_ext {
            return Err(PerError::DecodeError(
                "TRPInformation iE-Extensions not supported in NRPPa v1".to_string(),
            ));
        }
        Ok(TrpInformation {
            trp_id,
            response_list,
        })
    }
}

/// TRPInformationListTRPResp ::= SEQUENCE (SIZE(1..maxnoTRPs)) OF
///        SEQUENCE { tRPInformation TRPInformation, iE-Extensions OPTIONAL, ... }
///
/// The anonymous inner SEQUENCE is EXTENSIBLE with a single optional
/// (`iE-Extensions`) that is UNSUPPORTED in v1; its preamble (extension marker +
/// presence bit) is encoded around each `TRPInformation`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrpInformationListTrpResp {
    pub items: Vec<TrpInformation>,
}

impl AperEncode for TrpInformationListTrpResp {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.items.len(), 1, MAX_NO_TRPS)?;
        for info in &self.items {
            // Anonymous inner SEQUENCE: extension marker + 1 optional bit
            // (iE-Extensions, absent in v1).
            encoder.write_bit(false);
            encoder.write_bit(false);
            info.encode_aper(encoder)?;
        }
        Ok(())
    }
}

impl AperDecode for TrpInformationListTrpResp {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(1, MAX_NO_TRPS)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let _ext = decoder.read_bit()?;
            let ie_ext = decoder.read_bit()?;
            let info = TrpInformation::decode_aper(decoder)?;
            if ie_ext {
                return Err(PerError::DecodeError(
                    "TRPInformationListTRPResp item iE-Extensions not supported in NRPPa v1"
                        .to_string(),
                ));
            }
            items.push(info);
        }
        Ok(TrpInformationListTrpResp { items })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nrppa::ies::PlmnIdentity;

    fn roundtrip<T: AperEncode + AperDecode + PartialEq + std::fmt::Debug>(value: T) {
        let mut encoder = AperEncoder::new();
        value.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = T::decode_aper(&mut decoder).unwrap();
        assert_eq!(decoded, value);
    }

    fn sample_position() -> NgRanAccessPointPosition {
        NgRanAccessPointPosition {
            latitude_sign_south: false,
            latitude: 1_234_567,
            longitude: -1_000_000,
            direction_of_altitude_depth: false,
            altitude: 12_345,
            uncertainty_semi_major: 10,
            uncertainty_semi_minor: 20,
            orientation_of_major_axis: 90,
            uncertainty_altitude: 30,
            confidence: 95,
        }
    }

    fn sample_geo() -> GeographicalCoordinates {
        GeographicalCoordinates {
            position_definition_type: TrpPositionDefinitionType::Direct(TrpPositionDirect {
                accuracy: TrpPositionDirectAccuracy::TrpPosition(sample_position()),
            }),
        }
    }

    #[test]
    fn test_trp_id_roundtrip() {
        roundtrip(TrpId(1));
        roundtrip(TrpId(100));
        roundtrip(TrpId(65535));
    }

    #[test]
    fn test_trp_information_type_item_roundtrip() {
        // Each root value plus a couple of extension additions.
        for v in [
            TrpInformationTypeItem::NrPci,
            TrpInformationTypeItem::NgRanCgi,
            TrpInformationTypeItem::Arfcn,
            TrpInformationTypeItem::PrsConfig,
            TrpInformationTypeItem::SsbInfo,
            TrpInformationTypeItem::SfnInitTime,
            TrpInformationTypeItem::SpatialDirectInfo,
            TrpInformationTypeItem::GeoCoord,
            TrpInformationTypeItem::TrpType,
            TrpInformationTypeItem::CommonTa,
        ] {
            roundtrip(v);
        }
    }

    #[test]
    fn test_trp_information_type_list_req_roundtrip() {
        roundtrip(TrpInformationTypeListTrpReq {
            items: vec![
                TrpInformationTypeItem::NrPci,
                TrpInformationTypeItem::NgRanCgi,
                TrpInformationTypeItem::GeoCoord,
            ],
        });
    }

    #[test]
    fn test_trp_response_item_roundtrip() {
        roundtrip(TrpInformationTypeResponseItem::PciNr(0));
        roundtrip(TrpInformationTypeResponseItem::PciNr(1007));
        roundtrip(TrpInformationTypeResponseItem::Arfcn(0));
        roundtrip(TrpInformationTypeResponseItem::Arfcn(3_279_165));
        roundtrip(TrpInformationTypeResponseItem::CgiNr(CgiNr {
            plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
            nr_cell_identifier: 0xF_FFFF_FFFF,
        }));
        roundtrip(TrpInformationTypeResponseItem::GeographicalCoordinates(
            sample_geo(),
        ));
    }

    #[test]
    fn test_trp_information_roundtrip() {
        roundtrip(TrpInformation {
            trp_id: TrpId(7),
            response_list: TrpInformationTypeResponseList {
                items: vec![
                    TrpInformationTypeResponseItem::PciNr(500),
                    TrpInformationTypeResponseItem::GeographicalCoordinates(sample_geo()),
                ],
            },
        });
    }

    #[test]
    fn test_trp_list_and_resp_list_roundtrip() {
        roundtrip(TrpList {
            items: vec![TrpItem { trp_id: TrpId(1) }, TrpItem { trp_id: TrpId(65535) }],
        });
        roundtrip(TrpInformationListTrpResp {
            items: vec![
                TrpInformation {
                    trp_id: TrpId(1),
                    response_list: TrpInformationTypeResponseList {
                        items: vec![TrpInformationTypeResponseItem::Arfcn(640_000)],
                    },
                },
                TrpInformation {
                    trp_id: TrpId(2),
                    response_list: TrpInformationTypeResponseList {
                        items: vec![TrpInformationTypeResponseItem::GeographicalCoordinates(
                            sample_geo(),
                        )],
                    },
                },
            ],
        });
    }

    #[test]
    fn test_trp_response_item_deferred_alternative_errors() {
        // CHOICE index 3 (pRSConfiguration) is DEFERRED -> clean decode error.
        // 9 alternatives, non-extensible -> 4-bit index; `0011` selects index 3.
        let mut decoder = AperDecoder::new(&[0x30]);
        assert!(TrpInformationTypeResponseItem::decode_aper(&mut decoder).is_err());
    }

    #[test]
    fn test_trp_id_extension_bit_rejected() {
        // Extension bit set (high bit) -> out-of-root TRP-ID, rejected in v1.
        let mut decoder = AperDecoder::new(&[0x80, 0x00, 0x00]);
        assert!(TrpId::decode_aper(&mut decoder).is_err());
    }
}
