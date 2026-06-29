//! NRPPa Information Elements
//!
//! Protocol IE containers and the typed E-CID Information Elements from
//! NRPPA-IEs (3GPP TS 38.455 §9.3.4, ASN.1 L12830+).
//!
//! Like the NGAP sibling, the generic `ProtocolIE-Field` keeps its value as an
//! opaque `Vec<u8>` (the open-type content) so only the IEs we explicitly build
//! or parse get typed codecs; every other IE rides through as raw bytes.

use super::types::{Criticality, ProtocolIeId};
use crate::per::{
    AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerError, PerResult,
};

// ---------------------------------------------------------------------------
// Extensible constrained INTEGER helper
// ---------------------------------------------------------------------------
//
// NRPPa uses many `INTEGER (lb..ub, ...)` types (UE-Measurement-ID,
// Cell-Portion-ID, PCI-EUTRA, EARFCN, ValueRSRP/RSRQ-EUTRA). Per X.691 §12.2.6
// these prepend a single extension bit: 0 -> the value lies in the root range
// and is encoded as a constrained whole number; 1 -> the value is an extension
// addition encoded as an unconstrained whole number (length determinant +
// minimum-octet two's complement). This mirrors how asn1c emits these types.

fn encode_ext_constrained_int(
    encoder: &mut AperEncoder,
    value: i64,
    min: i64,
    max: i64,
) -> PerResult<()> {
    let in_root = value >= min && value <= max;
    encoder.write_bit(!in_root);
    if in_root {
        encoder.encode_constrained_whole_number(value, &Constraint::new(min, max))
    } else {
        encoder.encode_unconstrained_whole_number(value)
    }
}

fn decode_ext_constrained_int(
    decoder: &mut AperDecoder,
    min: i64,
    max: i64,
) -> PerResult<i64> {
    let extended = decoder.read_bit()?;
    if !extended {
        decoder.decode_constrained_whole_number(&Constraint::new(min, max))
    } else {
        decoder.decode_unconstrained_whole_number()
    }
}

// Fixed-size BIT STRING <-> integer helper (matches `encode_bit_string`'s
// fixed-size path: octet-align when the length exceeds 16 bits).
fn encode_fixed_bit_string(encoder: &mut AperEncoder, value: u64, num_bits: usize) {
    if num_bits > 16 {
        encoder.align();
    }
    encoder.write_bits(value, num_bits);
}

fn decode_fixed_bit_string(decoder: &mut AperDecoder, num_bits: usize) -> PerResult<u64> {
    if num_bits > 16 {
        decoder.align();
    }
    decoder.read_bits(num_bits)
}

// ---------------------------------------------------------------------------
// Generic Protocol IE container (opaque value)
// ---------------------------------------------------------------------------

/// ProtocolIE-Field - a single IE with ID, criticality and an open-type value.
/// ASN.1: ProtocolIE-Field ::= SEQUENCE { id, criticality, value }
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolIeField {
    pub id: ProtocolIeId,
    pub criticality: Criticality,
    pub value: Vec<u8>, // Raw APER-encoded open-type value
}

impl AperEncode for ProtocolIeField {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.id.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        // Open-type framing: length determinant (fragmenting per X.691 §11.9.3
        // when content exceeds 16383 octets) followed by the content octets.
        encoder.encode_fragmented_octets(&self.value)?;
        Ok(())
    }
}

impl AperDecode for ProtocolIeField {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let id = ProtocolIeId::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;

        let mut value = Vec::new();
        loop {
            let (len, fragmented) = decoder.decode_length_fragment()?;
            value.extend_from_slice(&decoder.read_bytes(len)?);
            if !fragmented {
                break;
            }
        }

        Ok(ProtocolIeField {
            id,
            criticality,
            value,
        })
    }
}

/// ProtocolIE-Container - SEQUENCE (SIZE(0..maxProtocolIEs)) OF ProtocolIE-Field
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProtocolIeContainer {
    pub ies: Vec<ProtocolIeField>,
}

impl ProtocolIeContainer {
    // maxProtocolIEs = 65535 (TS 38.455 §9.3.6 / NRPPA-CommonDataTypes)
    pub const MAX_PROTOCOL_IES: usize = 65535;

    pub fn new() -> Self {
        Self { ies: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ies: Vec::with_capacity(capacity),
        }
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

    /// Find an IE by ID.
    pub fn find(&self, id: ProtocolIeId) -> Option<&ProtocolIeField> {
        self.ies.iter().find(|ie| ie.id == id)
    }

    /// Find an IE by ID (mutable).
    pub fn find_mut(&mut self, id: ProtocolIeId) -> Option<&mut ProtocolIeField> {
        self.ies.iter_mut().find(|ie| ie.id == id)
    }
}

impl AperEncode for ProtocolIeContainer {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.ies.len(), 0, Self::MAX_PROTOCOL_IES)?;
        for ie in &self.ies {
            ie.encode_aper(encoder)?;
        }
        Ok(())
    }
}

impl AperDecode for ProtocolIeContainer {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(0, Self::MAX_PROTOCOL_IES)?;
        let mut ies = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            ies.push(ProtocolIeField::decode_aper(decoder)?);
        }
        Ok(ProtocolIeContainer { ies })
    }
}

// ---------------------------------------------------------------------------
// Scalar / enumerated E-CID IEs
// ---------------------------------------------------------------------------

/// UE-Measurement-ID
/// ASN.1: UE-Measurement-ID ::= INTEGER (1..15, ..., 16..256)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UeMeasurementId(pub u16);

impl UeMeasurementId {
    pub const ROOT_MIN: i64 = 1;
    pub const ROOT_MAX: i64 = 15;
}

impl AperEncode for UeMeasurementId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encode_ext_constrained_int(encoder, self.0 as i64, Self::ROOT_MIN, Self::ROOT_MAX)
    }
}

impl AperDecode for UeMeasurementId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let v = decode_ext_constrained_int(decoder, Self::ROOT_MIN, Self::ROOT_MAX)?;
        Ok(UeMeasurementId(v as u16))
    }
}

/// ReportCharacteristics
/// ASN.1: ReportCharacteristics ::= ENUMERATED { onDemand, periodic, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReportCharacteristics {
    OnDemand = 0,
    Periodic = 1,
}

impl ReportCharacteristics {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 1);
}

impl AperEncode for ReportCharacteristics {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for ReportCharacteristics {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        match decoder.decode_enumerated(&Self::CONSTRAINT)? {
            0 => Ok(ReportCharacteristics::OnDemand),
            1 => Ok(ReportCharacteristics::Periodic),
            v => Err(PerError::DecodeError(format!(
                "Unknown ReportCharacteristics value: {v}"
            ))),
        }
    }
}

/// MeasurementPeriodicity
/// ASN.1: ENUMERATED { ms120, ms240, ms480, ms640, ms1024, ms2048, ms5120,
///        ms10240, min1, min6, min12, min30, min60, ..., ms20480, ms40960, extended }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MeasurementPeriodicity {
    Ms120 = 0,
    Ms240 = 1,
    Ms480 = 2,
    Ms640 = 3,
    Ms1024 = 4,
    Ms2048 = 5,
    Ms5120 = 6,
    Ms10240 = 7,
    Min1 = 8,
    Min6 = 9,
    Min12 = 10,
    Min30 = 11,
    Min60 = 12,
    // Extension additions (root ends at index 12)
    Ms20480 = 13,
    Ms40960 = 14,
    Extended = 15,
}

impl MeasurementPeriodicity {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 12);
}

impl TryFrom<i64> for MeasurementPeriodicity {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ms120),
            1 => Ok(Self::Ms240),
            2 => Ok(Self::Ms480),
            3 => Ok(Self::Ms640),
            4 => Ok(Self::Ms1024),
            5 => Ok(Self::Ms2048),
            6 => Ok(Self::Ms5120),
            7 => Ok(Self::Ms10240),
            8 => Ok(Self::Min1),
            9 => Ok(Self::Min6),
            10 => Ok(Self::Min12),
            11 => Ok(Self::Min30),
            12 => Ok(Self::Min60),
            13 => Ok(Self::Ms20480),
            14 => Ok(Self::Ms40960),
            15 => Ok(Self::Extended),
            _ => Err(PerError::DecodeError(format!(
                "Unknown MeasurementPeriodicity value: {value}"
            ))),
        }
    }
}

impl AperEncode for MeasurementPeriodicity {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for MeasurementPeriodicity {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        Self::try_from(decoder.decode_enumerated(&Self::CONSTRAINT)?)
    }
}

/// MeasurementQuantitiesValue
/// ASN.1: ENUMERATED { cell-ID, angleOfArrival, timingAdvanceType1,
///        timingAdvanceType2, rSRP, rSRQ, ..., sS-RSRP, sS-RSRQ, cSI-RSRP,
///        cSI-RSRQ, angleOfArrivalNR, timingAdvanceNR, uE-Rx-Tx-Time-Diff,
///        angleOfArrivalNR-per-TRP }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MeasurementQuantitiesValue {
    CellId = 0,
    AngleOfArrival = 1,
    TimingAdvanceType1 = 2,
    TimingAdvanceType2 = 3,
    Rsrp = 4,
    Rsrq = 5,
    // Extension additions (root ends at index 5)
    SsRsrp = 6,
    SsRsrq = 7,
    CsiRsrp = 8,
    CsiRsrq = 9,
    AngleOfArrivalNr = 10,
    TimingAdvanceNr = 11,
    UeRxTxTimeDiff = 12,
    AngleOfArrivalNrPerTrp = 13,
}

impl MeasurementQuantitiesValue {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 5);
}

impl TryFrom<i64> for MeasurementQuantitiesValue {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CellId),
            1 => Ok(Self::AngleOfArrival),
            2 => Ok(Self::TimingAdvanceType1),
            3 => Ok(Self::TimingAdvanceType2),
            4 => Ok(Self::Rsrp),
            5 => Ok(Self::Rsrq),
            6 => Ok(Self::SsRsrp),
            7 => Ok(Self::SsRsrq),
            8 => Ok(Self::CsiRsrp),
            9 => Ok(Self::CsiRsrq),
            10 => Ok(Self::AngleOfArrivalNr),
            11 => Ok(Self::TimingAdvanceNr),
            12 => Ok(Self::UeRxTxTimeDiff),
            13 => Ok(Self::AngleOfArrivalNrPerTrp),
            _ => Err(PerError::DecodeError(format!(
                "Unknown MeasurementQuantitiesValue value: {value}"
            ))),
        }
    }
}

impl AperEncode for MeasurementQuantitiesValue {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for MeasurementQuantitiesValue {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        Self::try_from(decoder.decode_enumerated(&Self::CONSTRAINT)?)
    }
}

/// MeasurementQuantities-Item
/// ASN.1: SEQUENCE { measurementQuantitiesValue, iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurementQuantitiesItem {
    pub measurement_quantities_value: MeasurementQuantitiesValue,
}

impl AperEncode for MeasurementQuantitiesItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE: extension marker + 1 optional bit (iE-Extensions,
        // always absent in this v1).
        encoder.write_bit(false);
        encoder.write_bit(false);
        self.measurement_quantities_value.encode_aper(encoder)
    }
}

impl AperDecode for MeasurementQuantitiesItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let measurement_quantities_value = MeasurementQuantitiesValue::decode_aper(decoder)?;
        Ok(MeasurementQuantitiesItem {
            measurement_quantities_value,
        })
    }
}

/// MeasurementQuantities
/// ASN.1: SEQUENCE (SIZE (1..maxNoMeas=64)) OF
///        ProtocolIE-Single-Container {{ MeasurementQuantities-ItemIEs }}
///
/// Each list member is a single-container `ProtocolIE-Field` carrying
/// id-MeasurementQuantities-Item (11), criticality reject, and the
/// `MeasurementQuantities-Item` as its open-type value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeasurementQuantities {
    pub items: Vec<MeasurementQuantitiesItem>,
}

impl MeasurementQuantities {
    pub const MAX_NO_MEAS: usize = 64;
}

impl AperEncode for MeasurementQuantities {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_length(self.items.len(), 1, Self::MAX_NO_MEAS)?;
        for item in &self.items {
            // ProtocolIE-Single-Container == ProtocolIE-Field { id, crit, value }
            ProtocolIeId::MEASUREMENT_QUANTITIES_ITEM.encode_aper(encoder)?;
            Criticality::Reject.encode_aper(encoder)?;

            let mut inner = AperEncoder::new();
            item.encode_aper(&mut inner)?;
            inner.align();
            encoder.encode_fragmented_octets(&inner.into_bytes())?;
        }
        Ok(())
    }
}

impl AperDecode for MeasurementQuantities {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_length(1, Self::MAX_NO_MEAS)?;
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
            items.push(MeasurementQuantitiesItem::decode_aper(&mut inner)?);
        }
        Ok(MeasurementQuantities { items })
    }
}

/// Cell-Portion-ID
/// ASN.1: Cell-Portion-ID ::= INTEGER (0..4095, ...)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellPortionId(pub u16);

impl CellPortionId {
    pub const ROOT_MIN: i64 = 0;
    pub const ROOT_MAX: i64 = 4095;
}

impl AperEncode for CellPortionId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encode_ext_constrained_int(encoder, self.0 as i64, Self::ROOT_MIN, Self::ROOT_MAX)
    }
}

impl AperDecode for CellPortionId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let v = decode_ext_constrained_int(decoder, Self::ROOT_MIN, Self::ROOT_MAX)?;
        Ok(CellPortionId(v as u16))
    }
}

/// NR-PCI
/// ASN.1: NR-PCI ::= INTEGER (0..1007)   -- non-extensible
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NrPci(pub u16);

impl NrPci {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 1007);
}

impl AperEncode for NrPci {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for NrPci {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let v = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(NrPci(v as u16))
    }
}

// ---------------------------------------------------------------------------
// OCTET STRING / fixed types
// ---------------------------------------------------------------------------

/// PLMN-Identity ::= OCTET STRING (SIZE(3))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlmnIdentity(pub [u8; 3]);

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

/// TAC ::= OCTET STRING (SIZE(3))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tac(pub [u8; 3]);

impl Tac {
    pub fn from_u24(value: u32) -> Self {
        let b = value.to_be_bytes();
        Self([b[1], b[2], b[3]])
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

// ---------------------------------------------------------------------------
// Cell global identities
// ---------------------------------------------------------------------------

/// NG-RANCell ::= CHOICE { eUTRA-CellID EUTRACellIdentifier (BIT STRING 28),
///        nR-CellID NRCellIdentifier (BIT STRING 36), choice-Extension }
/// Non-extensible CHOICE, 3 alternatives -> 2-bit index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgRanCell {
    /// EUTRACellIdentifier ::= BIT STRING (SIZE (28))
    EutraCellId(u32),
    /// NRCellIdentifier ::= BIT STRING (SIZE (36))
    NrCellId(u64),
}

impl NgRanCell {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = false;
}

impl AperEncode for NgRanCell {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            NgRanCell::EutraCellId(id) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encode_fixed_bit_string(encoder, *id as u64, 28);
                Ok(())
            }
            NgRanCell::NrCellId(id) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encode_fixed_bit_string(encoder, *id, 36);
                Ok(())
            }
        }
    }
}

impl AperDecode for NgRanCell {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(NgRanCell::EutraCellId(
                decode_fixed_bit_string(decoder, 28)? as u32,
            )),
            1 => Ok(NgRanCell::NrCellId(decode_fixed_bit_string(decoder, 36)?)),
            2 => Err(PerError::DecodeError(
                "NG-RANCell choice-Extension selected but NG-RANCell-ExtensionIE is empty"
                    .to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// NG-RAN-CGI ::= SEQUENCE { pLMN-Identity, nG-RANcell NG-RANCell,
///        iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NgRanCgi {
    pub plmn_identity: PlmnIdentity,
    pub ng_ran_cell: NgRanCell,
}

impl AperEncode for NgRanCgi {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE + 1 optional bit (iE-Extensions, absent).
        encoder.write_bit(false);
        encoder.write_bit(false);
        self.plmn_identity.encode_aper(encoder)?;
        self.ng_ran_cell.encode_aper(encoder)
    }
}

impl AperDecode for NgRanCgi {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let plmn_identity = PlmnIdentity::decode_aper(decoder)?;
        let ng_ran_cell = NgRanCell::decode_aper(decoder)?;
        Ok(NgRanCgi {
            plmn_identity,
            ng_ran_cell,
        })
    }
}

/// CGI-NR ::= SEQUENCE { pLMN-Identity, nRcellIdentifier NRCellIdentifier
///        (BIT STRING 36), iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgiNr {
    pub plmn_identity: PlmnIdentity,
    pub nr_cell_identifier: u64,
}

impl AperEncode for CgiNr {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false);
        encoder.write_bit(false);
        self.plmn_identity.encode_aper(encoder)?;
        encode_fixed_bit_string(encoder, self.nr_cell_identifier, 36);
        Ok(())
    }
}

impl AperDecode for CgiNr {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let plmn_identity = PlmnIdentity::decode_aper(decoder)?;
        let nr_cell_identifier = decode_fixed_bit_string(decoder, 36)?;
        Ok(CgiNr {
            plmn_identity,
            nr_cell_identifier,
        })
    }
}

// ---------------------------------------------------------------------------
// NG-RANAccessPointPosition
// ---------------------------------------------------------------------------

/// NG-RANAccessPointPosition ::= SEQUENCE { latitudeSign ENUMERATED{north,south},
///   latitude INTEGER(0..8388607), longitude INTEGER(-8388608..8388607),
///   directionOfAltitude ENUMERATED{height,depth}, altitude INTEGER(0..32767),
///   uncertaintySemi-major INTEGER(0..127), uncertaintySemi-minor INTEGER(0..127),
///   orientationOfMajorAxis INTEGER(0..179), uncertaintyAltitude INTEGER(0..127),
///   confidence INTEGER(0..100), iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NgRanAccessPointPosition {
    pub latitude_sign_south: bool, // false = north, true = south
    pub latitude: u32,             // 0..8388607
    pub longitude: i32,            // -8388608..8388607
    pub direction_of_altitude_depth: bool, // false = height, true = depth
    pub altitude: u16,             // 0..32767
    pub uncertainty_semi_major: u8, // 0..127
    pub uncertainty_semi_minor: u8, // 0..127
    pub orientation_of_major_axis: u8, // 0..179
    pub uncertainty_altitude: u8,  // 0..127
    pub confidence: u8,            // 0..100
}

impl NgRanAccessPointPosition {
    const LATITUDE: Constraint = Constraint::new(0, 8388607);
    const LONGITUDE: Constraint = Constraint::new(-8388608, 8388607);
    const ALTITUDE: Constraint = Constraint::new(0, 32767);
    const UNCERTAINTY7: Constraint = Constraint::new(0, 127);
    const ORIENTATION: Constraint = Constraint::new(0, 179);
    const CONFIDENCE: Constraint = Constraint::new(0, 100);
    const SIGN: Constraint = Constraint::new(0, 1);
}

impl AperEncode for NgRanAccessPointPosition {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE + 1 optional bit (iE-Extensions, absent).
        encoder.write_bit(false);
        encoder.write_bit(false);
        encoder.encode_enumerated(self.latitude_sign_south as i64, &Self::SIGN)?;
        encoder.encode_constrained_whole_number(self.latitude as i64, &Self::LATITUDE)?;
        encoder.encode_constrained_whole_number(self.longitude as i64, &Self::LONGITUDE)?;
        encoder.encode_enumerated(self.direction_of_altitude_depth as i64, &Self::SIGN)?;
        encoder.encode_constrained_whole_number(self.altitude as i64, &Self::ALTITUDE)?;
        encoder
            .encode_constrained_whole_number(self.uncertainty_semi_major as i64, &Self::UNCERTAINTY7)?;
        encoder
            .encode_constrained_whole_number(self.uncertainty_semi_minor as i64, &Self::UNCERTAINTY7)?;
        encoder
            .encode_constrained_whole_number(self.orientation_of_major_axis as i64, &Self::ORIENTATION)?;
        encoder
            .encode_constrained_whole_number(self.uncertainty_altitude as i64, &Self::UNCERTAINTY7)?;
        encoder.encode_constrained_whole_number(self.confidence as i64, &Self::CONFIDENCE)?;
        Ok(())
    }
}

impl AperDecode for NgRanAccessPointPosition {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        let latitude_sign_south = decoder.decode_enumerated(&Self::SIGN)? != 0;
        let latitude = decoder.decode_constrained_whole_number(&Self::LATITUDE)? as u32;
        let longitude = decoder.decode_constrained_whole_number(&Self::LONGITUDE)? as i32;
        let direction_of_altitude_depth = decoder.decode_enumerated(&Self::SIGN)? != 0;
        let altitude = decoder.decode_constrained_whole_number(&Self::ALTITUDE)? as u16;
        let uncertainty_semi_major =
            decoder.decode_constrained_whole_number(&Self::UNCERTAINTY7)? as u8;
        let uncertainty_semi_minor =
            decoder.decode_constrained_whole_number(&Self::UNCERTAINTY7)? as u8;
        let orientation_of_major_axis =
            decoder.decode_constrained_whole_number(&Self::ORIENTATION)? as u8;
        let uncertainty_altitude =
            decoder.decode_constrained_whole_number(&Self::UNCERTAINTY7)? as u8;
        let confidence = decoder.decode_constrained_whole_number(&Self::CONFIDENCE)? as u8;
        Ok(NgRanAccessPointPosition {
            latitude_sign_south,
            latitude,
            longitude,
            direction_of_altitude_depth,
            altitude,
            uncertainty_semi_major,
            uncertainty_semi_minor,
            orientation_of_major_axis,
            uncertainty_altitude,
            confidence,
        })
    }
}

// ---------------------------------------------------------------------------
// MeasuredResults (SEQUENCE OF MeasuredResultsValue CHOICE)
// ---------------------------------------------------------------------------

/// PCI-EUTRA ::= INTEGER (0..503, ...)
fn encode_pci_eutra(encoder: &mut AperEncoder, v: u16) -> PerResult<()> {
    encode_ext_constrained_int(encoder, v as i64, 0, 503)
}
fn decode_pci_eutra(decoder: &mut AperDecoder) -> PerResult<u16> {
    Ok(decode_ext_constrained_int(decoder, 0, 503)? as u16)
}

/// EARFCN ::= INTEGER (0..262143, ...)
fn encode_earfcn(encoder: &mut AperEncoder, v: u32) -> PerResult<()> {
    encode_ext_constrained_int(encoder, v as i64, 0, 262143)
}
fn decode_earfcn(decoder: &mut AperDecoder) -> PerResult<u32> {
    Ok(decode_ext_constrained_int(decoder, 0, 262143)? as u32)
}

/// ResultRSRP-EUTRA-Item ::= SEQUENCE { pCI-EUTRA, eARFCN, cGI-EUTRA OPTIONAL,
///        valueRSRP-EUTRA INTEGER(0..97,...), iE-Extensions OPTIONAL, ... }
///
/// The optional `cGI-EUTRA` is not modelled in this v1 (always absent on encode;
/// a set present-bit is rejected on decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultRsrpEutraItem {
    pub pci_eutra: u16,
    pub earfcn: u32,
    pub value_rsrp_eutra: u8, // 0..97
}

impl AperEncode for ResultRsrpEutraItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE + 2 optional bits (cGI-EUTRA, iE-Extensions),
        // both absent in this v1.
        encoder.write_bit(false);
        encoder.write_bit(false);
        encoder.write_bit(false);
        encode_pci_eutra(encoder, self.pci_eutra)?;
        encode_earfcn(encoder, self.earfcn)?;
        encode_ext_constrained_int(encoder, self.value_rsrp_eutra as i64, 0, 97)
    }
}

impl AperDecode for ResultRsrpEutraItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let cgi_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        if cgi_present {
            return Err(PerError::DecodeError(
                "ResultRSRP-EUTRA-Item optional cGI-EUTRA not supported in NRPPa v1".to_string(),
            ));
        }
        let pci_eutra = decode_pci_eutra(decoder)?;
        let earfcn = decode_earfcn(decoder)?;
        let value_rsrp_eutra = decode_ext_constrained_int(decoder, 0, 97)? as u8;
        Ok(ResultRsrpEutraItem {
            pci_eutra,
            earfcn,
            value_rsrp_eutra,
        })
    }
}

/// ResultRSRQ-EUTRA-Item ::= SEQUENCE { pCI-EUTRA, eARFCN, cGI-UTRA OPTIONAL,
///        valueRSRQ-EUTRA INTEGER(0..34,...), iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultRsrqEutraItem {
    pub pci_eutra: u16,
    pub earfcn: u32,
    pub value_rsrq_eutra: u8, // 0..34
}

impl AperEncode for ResultRsrqEutraItem {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.write_bit(false);
        encoder.write_bit(false);
        encoder.write_bit(false);
        encode_pci_eutra(encoder, self.pci_eutra)?;
        encode_earfcn(encoder, self.earfcn)?;
        encode_ext_constrained_int(encoder, self.value_rsrq_eutra as i64, 0, 34)
    }
}

impl AperDecode for ResultRsrqEutraItem {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let cgi_present = decoder.read_bit()?;
        let _ie_ext = decoder.read_bit()?;
        if cgi_present {
            return Err(PerError::DecodeError(
                "ResultRSRQ-EUTRA-Item optional cGI-EUTRA not supported in NRPPa v1".to_string(),
            ));
        }
        let pci_eutra = decode_pci_eutra(decoder)?;
        let earfcn = decode_earfcn(decoder)?;
        let value_rsrq_eutra = decode_ext_constrained_int(decoder, 0, 34)? as u8;
        Ok(ResultRsrqEutraItem {
            pci_eutra,
            earfcn,
            value_rsrq_eutra,
        })
    }
}

// SEQUENCE OF helpers for the EUTRA result lists (SIZE (1..maxCellReport=9)).
const MAX_CELL_REPORT: usize = 9;

fn encode_seq_of<T: AperEncode>(
    encoder: &mut AperEncoder,
    items: &[T],
    min: usize,
    max: usize,
) -> PerResult<()> {
    encoder.encode_constrained_length(items.len(), min, max)?;
    for item in items {
        item.encode_aper(encoder)?;
    }
    Ok(())
}

fn decode_seq_of<T: AperDecode>(
    decoder: &mut AperDecoder,
    min: usize,
    max: usize,
) -> PerResult<Vec<T>> {
    let count = decoder.decode_constrained_length(min, max)?;
    let mut out = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        out.push(T::decode_aper(decoder)?);
    }
    Ok(out)
}

/// MeasuredResultsValue ::= CHOICE {
///   valueAngleOfArrival-EUTRA INTEGER (0..719),
///   valueTimingAdvanceType1-EUTRA INTEGER (0..7690),
///   valueTimingAdvanceType2-EUTRA INTEGER (0..7690),
///   resultRSRP-EUTRA ResultRSRP-EUTRA,
///   resultRSRQ-EUTRA ResultRSRQ-EUTRA,
///   choice-Extension }
/// Non-extensible CHOICE, 6 alternatives -> 3-bit index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasuredResultsValue {
    ValueAngleOfArrival(u16),     // 0..719
    ValueTimingAdvanceType1(u16), // 0..7690
    ValueTimingAdvanceType2(u16), // 0..7690
    ResultRsrp(Vec<ResultRsrpEutraItem>),
    ResultRsrq(Vec<ResultRsrqEutraItem>),
}

impl MeasuredResultsValue {
    pub const NUM_ALTERNATIVES: usize = 6;
    pub const EXTENSIBLE: bool = false;
    const ANGLE: Constraint = Constraint::new(0, 719);
    const TA: Constraint = Constraint::new(0, 7690);
}

impl AperEncode for MeasuredResultsValue {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            MeasuredResultsValue::ValueAngleOfArrival(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::ANGLE)
            }
            MeasuredResultsValue::ValueTimingAdvanceType1(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::TA)
            }
            MeasuredResultsValue::ValueTimingAdvanceType2(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::TA)
            }
            MeasuredResultsValue::ResultRsrp(items) => {
                encoder.encode_choice_index(3, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encode_seq_of(encoder, items, 1, MAX_CELL_REPORT)
            }
            MeasuredResultsValue::ResultRsrq(items) => {
                encoder.encode_choice_index(4, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encode_seq_of(encoder, items, 1, MAX_CELL_REPORT)
            }
        }
    }
}

impl AperDecode for MeasuredResultsValue {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(MeasuredResultsValue::ValueAngleOfArrival(
                decoder.decode_constrained_whole_number(&Self::ANGLE)? as u16,
            )),
            1 => Ok(MeasuredResultsValue::ValueTimingAdvanceType1(
                decoder.decode_constrained_whole_number(&Self::TA)? as u16,
            )),
            2 => Ok(MeasuredResultsValue::ValueTimingAdvanceType2(
                decoder.decode_constrained_whole_number(&Self::TA)? as u16,
            )),
            3 => Ok(MeasuredResultsValue::ResultRsrp(decode_seq_of(
                decoder,
                1,
                MAX_CELL_REPORT,
            )?)),
            4 => Ok(MeasuredResultsValue::ResultRsrq(decode_seq_of(
                decoder,
                1,
                MAX_CELL_REPORT,
            )?)),
            5 => Err(PerError::DecodeError(
                "MeasuredResultsValue choice-Extension not supported in NRPPa v1".to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// MeasuredResults ::= SEQUENCE (SIZE (1..maxNoMeas=64)) OF MeasuredResultsValue
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeasuredResults {
    pub values: Vec<MeasuredResultsValue>,
}

impl MeasuredResults {
    pub const MAX_NO_MEAS: usize = 64;
}

impl AperEncode for MeasuredResults {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encode_seq_of(encoder, &self.values, 1, Self::MAX_NO_MEAS)
    }
}

impl AperDecode for MeasuredResults {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        Ok(MeasuredResults {
            values: decode_seq_of(decoder, 1, Self::MAX_NO_MEAS)?,
        })
    }
}

// ---------------------------------------------------------------------------
// E-CID-MeasurementResult
// ---------------------------------------------------------------------------

/// E-CID-MeasurementResult ::= SEQUENCE { servingCell-ID NG-RAN-CGI,
///   servingCellTAC TAC, nG-RANAccessPointPosition OPTIONAL,
///   measuredResults OPTIONAL, iE-Extensions OPTIONAL, ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECidMeasurementResult {
    pub serving_cell_id: NgRanCgi,
    pub serving_cell_tac: Tac,
    pub ng_ran_access_point_position: Option<NgRanAccessPointPosition>,
    pub measured_results: Option<MeasuredResults>,
}

impl AperEncode for ECidMeasurementResult {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE; optional bitmap covers the 3 optional root fields
        // (nG-RANAccessPointPosition, measuredResults, iE-Extensions). The last
        // is never present in this v1.
        encoder.write_bit(false); // extension marker
        encoder.write_bit(self.ng_ran_access_point_position.is_some());
        encoder.write_bit(self.measured_results.is_some());
        encoder.write_bit(false); // iE-Extensions absent

        self.serving_cell_id.encode_aper(encoder)?;
        self.serving_cell_tac.encode_aper(encoder)?;
        if let Some(pos) = &self.ng_ran_access_point_position {
            pos.encode_aper(encoder)?;
        }
        if let Some(mr) = &self.measured_results {
            mr.encode_aper(encoder)?;
        }
        Ok(())
    }
}

impl AperDecode for ECidMeasurementResult {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let _ext = decoder.read_bit()?;
        let has_position = decoder.read_bit()?;
        let has_measured = decoder.read_bit()?;
        let has_ie_ext = decoder.read_bit()?;

        let serving_cell_id = NgRanCgi::decode_aper(decoder)?;
        let serving_cell_tac = Tac::decode_aper(decoder)?;
        let ng_ran_access_point_position = if has_position {
            Some(NgRanAccessPointPosition::decode_aper(decoder)?)
        } else {
            None
        };
        let measured_results = if has_measured {
            Some(MeasuredResults::decode_aper(decoder)?)
        } else {
            None
        };
        if has_ie_ext {
            return Err(PerError::DecodeError(
                "E-CID-MeasurementResult iE-Extensions not supported in NRPPa v1".to_string(),
            ));
        }
        Ok(ECidMeasurementResult {
            serving_cell_id,
            serving_cell_tac,
            ng_ran_access_point_position,
            measured_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: AperEncode + AperDecode + PartialEq + std::fmt::Debug>(value: T) {
        let mut encoder = AperEncoder::new();
        value.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = T::decode_aper(&mut decoder).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_ue_measurement_id_roundtrip() {
        roundtrip(UeMeasurementId(1));
        roundtrip(UeMeasurementId(15));
        roundtrip(UeMeasurementId(200)); // extension range
    }

    #[test]
    fn test_enumerated_ies_roundtrip() {
        roundtrip(ReportCharacteristics::OnDemand);
        roundtrip(ReportCharacteristics::Periodic);
        roundtrip(MeasurementPeriodicity::Ms120);
        roundtrip(MeasurementPeriodicity::Extended);
        roundtrip(MeasurementQuantitiesValue::Rsrp);
        roundtrip(MeasurementQuantitiesValue::AngleOfArrivalNr);
    }

    #[test]
    fn test_measurement_quantities_roundtrip() {
        roundtrip(MeasurementQuantities {
            items: vec![
                MeasurementQuantitiesItem {
                    measurement_quantities_value: MeasurementQuantitiesValue::CellId,
                },
                MeasurementQuantitiesItem {
                    measurement_quantities_value: MeasurementQuantitiesValue::Rsrp,
                },
            ],
        });
    }

    #[test]
    fn test_cell_portion_and_pci_roundtrip() {
        roundtrip(CellPortionId(0));
        roundtrip(CellPortionId(4095));
        roundtrip(CellPortionId(5000)); // extension range
        roundtrip(NrPci(0));
        roundtrip(NrPci(1007));
    }

    #[test]
    fn test_ng_ran_cgi_roundtrip() {
        roundtrip(NgRanCgi {
            plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
            ng_ran_cell: NgRanCell::NrCellId(0x0_1234_5678),
        });
        roundtrip(NgRanCgi {
            plmn_identity: PlmnIdentity([0x13, 0x00, 0xF0]),
            ng_ran_cell: NgRanCell::EutraCellId(0x0123_4567),
        });
        roundtrip(CgiNr {
            plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
            nr_cell_identifier: 0xF_FFFF_FFFF,
        });
    }

    #[test]
    fn test_ng_ran_access_point_position_roundtrip() {
        roundtrip(NgRanAccessPointPosition {
            latitude_sign_south: true,
            latitude: 1_234_567,
            longitude: -1_000_000,
            direction_of_altitude_depth: false,
            altitude: 12_345,
            uncertainty_semi_major: 10,
            uncertainty_semi_minor: 20,
            orientation_of_major_axis: 90,
            uncertainty_altitude: 30,
            confidence: 95,
        });
    }

    #[test]
    fn test_measured_results_roundtrip() {
        roundtrip(MeasuredResults {
            values: vec![
                MeasuredResultsValue::ValueAngleOfArrival(360),
                MeasuredResultsValue::ValueTimingAdvanceType1(7690),
                MeasuredResultsValue::ResultRsrp(vec![ResultRsrpEutraItem {
                    pci_eutra: 100,
                    earfcn: 1800,
                    value_rsrp_eutra: 50,
                }]),
                MeasuredResultsValue::ResultRsrq(vec![ResultRsrqEutraItem {
                    pci_eutra: 200,
                    earfcn: 2600,
                    value_rsrq_eutra: 20,
                }]),
            ],
        });
    }

    #[test]
    fn test_e_cid_measurement_result_roundtrip() {
        roundtrip(ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
                ng_ran_cell: NgRanCell::NrCellId(1),
            },
            serving_cell_tac: Tac::from_u24(1),
            ng_ran_access_point_position: None,
            measured_results: None,
        });

        roundtrip(ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x13, 0x00, 0xF0]),
                ng_ran_cell: NgRanCell::NrCellId(0xABCDEF12),
            },
            serving_cell_tac: Tac::from_u24(0x010203),
            ng_ran_access_point_position: Some(NgRanAccessPointPosition {
                latitude_sign_south: false,
                latitude: 100,
                longitude: 200,
                direction_of_altitude_depth: true,
                altitude: 50,
                uncertainty_semi_major: 1,
                uncertainty_semi_minor: 2,
                orientation_of_major_axis: 3,
                uncertainty_altitude: 4,
                confidence: 5,
            }),
            measured_results: Some(MeasuredResults {
                values: vec![MeasuredResultsValue::ValueAngleOfArrival(180)],
            }),
        });
    }
}
