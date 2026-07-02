//! GNSS-DataBitAssistance — 3GPP TS 37.355 clause 6.5.2.7, UNALIGNED PER.
//!
//! Navigation-message data-bit assistance: for each satellite and each of its
//! signals the LMF hands the UE the actual broadcast navigation data bits over
//! a reference time window, so the UE can perform data-bit wipe-off (removing
//! the unknown navigation modulation) and thereby integrate longer for weak
//! signals.
//!
//! ASN.1 (TS 37.355):
//! ```text
//! GNSS-DataBitAssistance ::= SEQUENCE {
//!     gnss-TOD-msec           INTEGER (0..3599999),
//!     gnss-TOD-frac           INTEGER (0..999)            OPTIONAL,   -- Need ON
//!     gnss-DataBitsSatList    GNSS-DataBitsSatList,
//!     ...
//! }
//!
//! GNSS-DataBitsSatList ::= SEQUENCE (SIZE(1..64)) OF GNSS-DataBitsSatElement
//!
//! GNSS-DataBitsSatElement ::= SEQUENCE {
//!     svID                    SV-ID,
//!     gnss-DataBitsSgnList    GNSS-DataBitsSgnList,
//!     ...
//! }
//!
//! GNSS-DataBitsSgnList ::= SEQUENCE (SIZE(1..8)) OF GNSS-DataBitsSgnElement
//!
//! GNSS-DataBitsSgnElement ::= SEQUENCE {
//!     gnss-SignalType         GNSS-SignalID,
//!     gnss-DataBits           BIT STRING (SIZE (1..1024)),
//!     ...
//! }
//! ```

use bitvec::prelude::*;

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

use super::common::{GnssSignalId, SvId};

/// GNSS-DataBitAssistance ::= SEQUENCE { ... } — extensible, one root OPTIONAL.
///
/// `gnss-TOD-msec` is the reference GNSS TOD in milliseconds; the data bits in
/// every sub-element are referenced to this instant. `gnss-TOD-frac` refines it
/// to sub-millisecond resolution when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssDataBitAssistance {
    /// gnss-TOD-msec INTEGER (0..3599999) — reference TOD, milliseconds.
    pub gnss_tod_msec: u32,
    /// gnss-TOD-frac INTEGER (0..999) OPTIONAL — fractional-ms refinement.
    pub gnss_tod_frac: Option<u16>,
    /// gnss-DataBitsSatList SEQUENCE (SIZE(1..64)) OF GNSS-DataBitsSatElement.
    pub gnss_data_bits_sat_list: Vec<GnssDataBitsSatElement>,
}

impl GnssDataBitAssistance {
    const TOD_MSEC: Constraint = Constraint::new(0, 3_599_999);
    const TOD_FRAC: Constraint = Constraint::new(0, 999);
    const SAT_LIST_SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for GnssDataBitAssistance {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE (no extension additions emitted); 1 root OPTIONAL.
        e.encode_sequence_preamble(Some(false), &[self.gnss_tod_frac.is_some()]);
        e.encode_constrained_whole_number(self.gnss_tod_msec as i64, &Self::TOD_MSEC)?;
        if let Some(frac) = self.gnss_tod_frac {
            e.encode_constrained_whole_number(frac as i64, &Self::TOD_FRAC)?;
        }
        // SEQUENCE (SIZE(1..64)) OF: constrained count, then each element.
        e.encode_constrained_whole_number(
            self.gnss_data_bits_sat_list.len() as i64,
            &Self::SAT_LIST_SIZE,
        )?;
        for el in &self.gnss_data_bits_sat_list {
            el.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssDataBitAssistance {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 1)?;
        let gnss_tod_msec = d.decode_constrained_whole_number(&Self::TOD_MSEC)? as u32;
        let gnss_tod_frac = if opts[0] {
            Some(d.decode_constrained_whole_number(&Self::TOD_FRAC)? as u16)
        } else {
            None
        };
        let count = d.decode_constrained_whole_number(&Self::SAT_LIST_SIZE)? as usize;
        let mut gnss_data_bits_sat_list = Vec::with_capacity(count);
        for _ in 0..count {
            gnss_data_bits_sat_list.push(GnssDataBitsSatElement::decode_uper(d)?);
        }
        // Extension additions are deferred (never emitted); reject if present.
        if ext {
            return Err(PerError::DecodeError(
                "GnssDataBitAssistance extension additions not supported".into(),
            ));
        }
        Ok(GnssDataBitAssistance {
            gnss_tod_msec,
            gnss_tod_frac,
            gnss_data_bits_sat_list,
        })
    }
}

/// GNSS-DataBitsSatElement ::= SEQUENCE { ... } — extensible, no root optionals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssDataBitsSatElement {
    /// svID SV-ID — satellite identity (INTEGER(0..63) in an extensible SEQUENCE).
    pub sv_id: SvId,
    /// gnss-DataBitsSgnList SEQUENCE (SIZE(1..8)) OF GNSS-DataBitsSgnElement.
    pub gnss_data_bits_sgn_list: Vec<GnssDataBitsSgnElement>,
}

impl GnssDataBitsSatElement {
    const SGN_LIST_SIZE: Constraint = Constraint::new(1, 8);
}

impl UperEncode for GnssDataBitsSatElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL/DEFAULT fields.
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_constrained_whole_number(
            self.gnss_data_bits_sgn_list.len() as i64,
            &Self::SGN_LIST_SIZE,
        )?;
        for el in &self.gnss_data_bits_sgn_list {
            el.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssDataBitsSatElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        let sv_id = SvId::decode_uper(d)?;
        let count = d.decode_constrained_whole_number(&Self::SGN_LIST_SIZE)? as usize;
        let mut gnss_data_bits_sgn_list = Vec::with_capacity(count);
        for _ in 0..count {
            gnss_data_bits_sgn_list.push(GnssDataBitsSgnElement::decode_uper(d)?);
        }
        if ext {
            return Err(PerError::DecodeError(
                "GnssDataBitsSatElement extension additions not supported".into(),
            ));
        }
        Ok(GnssDataBitsSatElement {
            sv_id,
            gnss_data_bits_sgn_list,
        })
    }
}

/// GNSS-DataBitsSgnElement ::= SEQUENCE { ... } — extensible, no root optionals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssDataBitsSgnElement {
    /// gnss-SignalType GNSS-SignalID (INTEGER(0..7) in an extensible SEQUENCE).
    pub gnss_signal_type: GnssSignalId,
    /// gnss-DataBits BIT STRING (SIZE (1..1024)) — the broadcast nav-message bits.
    pub gnss_data_bits: BitVec<u8, Msb0>,
}

impl GnssDataBitsSgnElement {
    const DATA_BITS_MIN: usize = 1;
    const DATA_BITS_MAX: usize = 1024;
}

impl UperEncode for GnssDataBitsSgnElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        if self.gnss_data_bits.is_empty() || self.gnss_data_bits.len() > Self::DATA_BITS_MAX {
            return Err(PerError::InvalidLength {
                length: self.gnss_data_bits.len(),
            });
        }
        // Extensible SEQUENCE, no root OPTIONAL/DEFAULT fields.
        e.encode_sequence_preamble(Some(false), &[]);
        self.gnss_signal_type.encode_uper(e)?;
        e.encode_bit_string(
            &self.gnss_data_bits,
            Some(Self::DATA_BITS_MIN),
            Some(Self::DATA_BITS_MAX),
        )?;
        Ok(())
    }
}

impl UperDecode for GnssDataBitsSgnElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        let gnss_signal_type = GnssSignalId::decode_uper(d)?;
        let gnss_data_bits =
            d.decode_bit_string(Some(Self::DATA_BITS_MIN), Some(Self::DATA_BITS_MAX))?;
        if ext {
            return Err(PerError::DecodeError(
                "GnssDataBitsSgnElement extension additions not supported".into(),
            ));
        }
        Ok(GnssDataBitsSgnElement {
            gnss_signal_type,
            gnss_data_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(vals: &[bool]) -> BitVec<u8, Msb0> {
        let mut b: BitVec<u8, Msb0> = BitVec::new();
        for &v in vals {
            b.push(v);
        }
        b
    }

    #[test]
    fn round_trip_data_bit_assistance() {
        let original = GnssDataBitAssistance {
            gnss_tod_msec: 1_234_567,
            gnss_tod_frac: Some(750),
            gnss_data_bits_sat_list: vec![
                GnssDataBitsSatElement {
                    sv_id: SvId { satellite_id: 12 },
                    gnss_data_bits_sgn_list: vec![
                        GnssDataBitsSgnElement {
                            gnss_signal_type: GnssSignalId { gnss_signal_id: 0 },
                            gnss_data_bits: bits(&[true, false, true, true, false, false, true]),
                        },
                        GnssDataBitsSgnElement {
                            gnss_signal_type: GnssSignalId { gnss_signal_id: 5 },
                            gnss_data_bits: bits(&[false; 300]),
                        },
                    ],
                },
                GnssDataBitsSatElement {
                    sv_id: SvId { satellite_id: 63 },
                    gnss_data_bits_sgn_list: vec![GnssDataBitsSgnElement {
                        gnss_signal_type: GnssSignalId { gnss_signal_id: 7 },
                        gnss_data_bits: bits(&[true]),
                    }],
                },
            ],
        };

        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();

        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssDataBitAssistance::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_no_frac_max_databits() {
        let original = GnssDataBitAssistance {
            gnss_tod_msec: 0,
            gnss_tod_frac: None,
            gnss_data_bits_sat_list: vec![GnssDataBitsSatElement {
                sv_id: SvId { satellite_id: 0 },
                gnss_data_bits_sgn_list: vec![GnssDataBitsSgnElement {
                    gnss_signal_type: GnssSignalId { gnss_signal_id: 3 },
                    gnss_data_bits: bits(&[true; 1024]),
                }],
            }],
        };

        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();

        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssDataBitAssistance::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_empty_databits() {
        let bad = GnssDataBitsSgnElement {
            gnss_signal_type: GnssSignalId { gnss_signal_id: 1 },
            gnss_data_bits: BitVec::new(),
        };
        let mut enc = UperEncoder::new();
        assert!(bad.encode_uper(&mut enc).is_err());
    }
}
