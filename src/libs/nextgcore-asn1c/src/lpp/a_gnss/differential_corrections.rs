//! GNSS-DifferentialCorrections (3GPP TS 37.355, LPP-PDU-Definitions, A-GNSS
//! assistance data — clause 6.5.2), UNALIGNED PER, LMF -> UE.
//!
//! ASN.1 (TS 37.355 v16/v17):
//!
//! ```asn1
//! GNSS-DifferentialCorrections ::= SEQUENCE {
//!     dgnss-RefTime       INTEGER (0..3599),
//!     dgnss-SgnTypeList   DGNSS-SgnTypeList,
//!     ...
//! }
//!
//! DGNSS-SgnTypeList ::= SEQUENCE (SIZE (1..3)) OF DGNSS-SgnTypeElement
//!
//! DGNSS-SgnTypeElement ::= SEQUENCE {
//!     gnss-SignalID       GNSS-SignalID,
//!     gnss-StatusHealth   INTEGER (0..7),
//!     dgnss-SatList       DGNSS-SatList,
//!     ...
//! }
//!
//! DGNSS-SatList ::= SEQUENCE (SIZE (1..64)) OF DGNSS-CorrectionsElement
//!
//! DGNSS-CorrectionsElement ::= SEQUENCE {
//!     svID                SV-ID,
//!     iod                 BIT STRING (SIZE (11)),
//!     udre                INTEGER (0..3),
//!     pseudoRangeCor      INTEGER (-2047..2047),
//!     rangeRateCor        INTEGER (-127..127),
//!     ...,
//!     [[  udreGrowthRate      INTEGER (0..7)  OPTIONAL,   -- Cond noZero
//!         udreValidityTime    INTEGER (0..7)  OPTIONAL    -- Cond noZero
//!     ]]
//! }
//! ```
//!
//! Deferrals (each raises a decode-error if present on the wire, never emitted):
//!  * The `...` extension additions of `GNSS-DifferentialCorrections`,
//!    `DGNSS-SgnTypeElement`, and `DGNSS-CorrectionsElement` (the r10
//!    `udreGrowthRate` / `udreValidityTime` growth-rate group) are UNSUPPORTED.

use super::common::{GnssSignalId, SvId};
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};
use bitvec::prelude::*;

/// `GNSS-DifferentialCorrections ::= SEQUENCE { dgnss-RefTime INTEGER (0..3599),
/// dgnss-SgnTypeList DGNSS-SgnTypeList, ... }` (TS 37.355 6.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssDifferentialCorrections {
    /// `dgnss-RefTime` — INTEGER(0..3599), seconds within the hour.
    pub dgnss_ref_time: u16,
    /// `dgnss-SgnTypeList` — SEQUENCE(SIZE(1..3)) OF DGNSS-SgnTypeElement.
    pub dgnss_sgn_type_list: DgnssSgnTypeList,
}

impl GnssDifferentialCorrections {
    const DGNSS_REF_TIME: Constraint = Constraint::new(0, 3599);
}

impl UperEncode for GnssDifferentialCorrections {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONALs; no extension additions emitted.
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.dgnss_ref_time as i64, &Self::DGNSS_REF_TIME)?;
        self.dgnss_sgn_type_list.encode_uper(e)
    }
}

impl UperDecode for GnssDifferentialCorrections {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-DifferentialCorrections extension additions not supported".into(),
            ));
        }
        let dgnss_ref_time = d.decode_constrained_whole_number(&Self::DGNSS_REF_TIME)? as u16;
        let dgnss_sgn_type_list = DgnssSgnTypeList::decode_uper(d)?;
        Ok(GnssDifferentialCorrections {
            dgnss_ref_time,
            dgnss_sgn_type_list,
        })
    }
}

/// `DGNSS-SgnTypeList ::= SEQUENCE (SIZE (1..3)) OF DGNSS-SgnTypeElement`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DgnssSgnTypeList {
    pub elements: Vec<DgnssSgnTypeElement>,
}

impl DgnssSgnTypeList {
    const SIZE: Constraint = Constraint::new(1, 3);
}

impl UperEncode for DgnssSgnTypeList {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_constrained_whole_number(self.elements.len() as i64, &Self::SIZE)?;
        for elem in &self.elements {
            elem.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for DgnssSgnTypeList {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let count = d.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count.min(3));
        for _ in 0..count {
            elements.push(DgnssSgnTypeElement::decode_uper(d)?);
        }
        Ok(DgnssSgnTypeList { elements })
    }
}

/// `DGNSS-SgnTypeElement ::= SEQUENCE { gnss-SignalID GNSS-SignalID,
/// gnss-StatusHealth INTEGER (0..7), dgnss-SatList DGNSS-SatList, ... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DgnssSgnTypeElement {
    /// `gnss-SignalID` — GNSS-SignalID (shared type, INTEGER(0..7) in ext. SEQ).
    pub gnss_signal_id: GnssSignalId,
    /// `gnss-StatusHealth` — INTEGER(0..7).
    pub gnss_status_health: u8,
    /// `dgnss-SatList` — SEQUENCE(SIZE(1..64)) OF DGNSS-CorrectionsElement.
    pub dgnss_sat_list: DgnssSatList,
}

impl DgnssSgnTypeElement {
    const GNSS_STATUS_HEALTH: Constraint = Constraint::new(0, 7);
}

impl UperEncode for DgnssSgnTypeElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONALs.
        e.encode_sequence_preamble(Some(false), &[]);
        self.gnss_signal_id.encode_uper(e)?;
        e.encode_constrained_whole_number(
            self.gnss_status_health as i64,
            &Self::GNSS_STATUS_HEALTH,
        )?;
        self.dgnss_sat_list.encode_uper(e)
    }
}

impl UperDecode for DgnssSgnTypeElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "DGNSS-SgnTypeElement extension additions not supported".into(),
            ));
        }
        let gnss_signal_id = GnssSignalId::decode_uper(d)?;
        let gnss_status_health =
            d.decode_constrained_whole_number(&Self::GNSS_STATUS_HEALTH)? as u8;
        let dgnss_sat_list = DgnssSatList::decode_uper(d)?;
        Ok(DgnssSgnTypeElement {
            gnss_signal_id,
            gnss_status_health,
            dgnss_sat_list,
        })
    }
}

/// `DGNSS-SatList ::= SEQUENCE (SIZE (1..64)) OF DGNSS-CorrectionsElement`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DgnssSatList {
    pub elements: Vec<DgnssCorrectionsElement>,
}

impl DgnssSatList {
    const SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for DgnssSatList {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_constrained_whole_number(self.elements.len() as i64, &Self::SIZE)?;
        for elem in &self.elements {
            elem.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for DgnssSatList {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let count = d.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            elements.push(DgnssCorrectionsElement::decode_uper(d)?);
        }
        Ok(DgnssSatList { elements })
    }
}

/// `DGNSS-CorrectionsElement ::= SEQUENCE { svID SV-ID,
/// iod BIT STRING (SIZE (11)), udre INTEGER (0..3),
/// pseudoRangeCor INTEGER (-2047..2047), rangeRateCor INTEGER (-127..127),
/// ..., [[ udreGrowthRate / udreValidityTime ]] }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DgnssCorrectionsElement {
    /// `svID` — SV-ID (shared type, INTEGER(0..63) in ext. SEQUENCE).
    pub sv_id: SvId,
    /// `iod` — BIT STRING(SIZE(11)); issue-of-data, opaque 11-bit field.
    pub iod: BitVec<u8, Msb0>,
    /// `udre` — INTEGER(0..3), user differential range error.
    pub udre: u8,
    /// `pseudoRangeCor` — INTEGER(-2047..2047).
    pub pseudo_range_cor: i16,
    /// `rangeRateCor` — INTEGER(-127..127).
    pub range_rate_cor: i8,
    // Extension additions udreGrowthRate/udreValidityTime (r10) DEFERRED.
}

impl DgnssCorrectionsElement {
    const IOD_BITS: usize = 11;
    const UDRE: Constraint = Constraint::new(0, 3);
    const PSEUDO_RANGE_COR: Constraint = Constraint::new(-2047, 2047);
    const RANGE_RATE_COR: Constraint = Constraint::new(-127, 127);
}

impl UperEncode for DgnssCorrectionsElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONALs; r10 additions never emitted.
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_bit_string(&self.iod, Some(Self::IOD_BITS), Some(Self::IOD_BITS))?;
        e.encode_constrained_whole_number(self.udre as i64, &Self::UDRE)?;
        e.encode_constrained_whole_number(self.pseudo_range_cor as i64, &Self::PSEUDO_RANGE_COR)?;
        e.encode_constrained_whole_number(self.range_rate_cor as i64, &Self::RANGE_RATE_COR)
    }
}

impl UperDecode for DgnssCorrectionsElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "DGNSS-CorrectionsElement r10 udreGrowthRate/udreValidityTime not supported".into(),
            ));
        }
        let sv_id = SvId::decode_uper(d)?;
        let iod = d.decode_bit_string(Some(Self::IOD_BITS), Some(Self::IOD_BITS))?;
        let udre = d.decode_constrained_whole_number(&Self::UDRE)? as u8;
        let pseudo_range_cor = d.decode_constrained_whole_number(&Self::PSEUDO_RANGE_COR)? as i16;
        let range_rate_cor = d.decode_constrained_whole_number(&Self::RANGE_RATE_COR)? as i8;
        Ok(DgnssCorrectionsElement {
            sv_id,
            iod,
            udre,
            pseudo_range_cor,
            range_rate_cor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iod_bits(value: u16) -> BitVec<u8, Msb0> {
        // 11-bit MSB-first bit string from an 11-bit value.
        let mut bv: BitVec<u8, Msb0> = BitVec::new();
        for i in (0..11).rev() {
            bv.push((value >> i) & 1 == 1);
        }
        bv
    }

    fn sample() -> GnssDifferentialCorrections {
        GnssDifferentialCorrections {
            dgnss_ref_time: 1800,
            dgnss_sgn_type_list: DgnssSgnTypeList {
                elements: vec![
                    DgnssSgnTypeElement {
                        gnss_signal_id: GnssSignalId { gnss_signal_id: 0 },
                        gnss_status_health: 3,
                        dgnss_sat_list: DgnssSatList {
                            elements: vec![
                                DgnssCorrectionsElement {
                                    sv_id: SvId { satellite_id: 5 },
                                    iod: iod_bits(0b101_0101_0101),
                                    udre: 2,
                                    pseudo_range_cor: -2047,
                                    range_rate_cor: 127,
                                },
                                DgnssCorrectionsElement {
                                    sv_id: SvId { satellite_id: 63 },
                                    iod: iod_bits(0),
                                    udre: 0,
                                    pseudo_range_cor: 2047,
                                    range_rate_cor: -127,
                                },
                            ],
                        },
                    },
                    DgnssSgnTypeElement {
                        gnss_signal_id: GnssSignalId { gnss_signal_id: 7 },
                        gnss_status_health: 0,
                        dgnss_sat_list: DgnssSatList {
                            elements: vec![DgnssCorrectionsElement {
                                sv_id: SvId { satellite_id: 0 },
                                iod: iod_bits(0b111_1111_1111),
                                udre: 3,
                                pseudo_range_cor: 0,
                                range_rate_cor: 0,
                            }],
                        },
                    },
                ],
            },
        }
    }

    #[test]
    fn round_trip_gnss_differential_corrections() {
        let original = sample();
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();

        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssDifferentialCorrections::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }
}
