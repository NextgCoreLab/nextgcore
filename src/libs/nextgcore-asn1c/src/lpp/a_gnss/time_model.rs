//! GNSS Time Model assistance data (3GPP TS 37.355 §6.5.2.4), UNALIGNED PER.
//!
//! The GNSS-TimeModel assistance data element provides the parameters needed
//! to relate the system time of one GNSS to a reference GNSS system time
//! (GNSS-to-GNSS time offset). One [`GnssTimeModelElement`] is provided per
//! satellite-system time-offset relation; a [`GnssTimeModelList`] carries
//! `SIZE(1..15)` of them and is referenced by the generic assistance-data
//! container as `super::common::...`'s `gnss_time_models` field.
//!
//! ASN.1 (TS 37.355 LPP-PDU-Definitions):
//! ```asn1
//! GNSS-TimeModelList ::= SEQUENCE (SIZE(1..15)) OF GNSS-TimeModelElement
//!
//! GNSS-TimeModelElement ::= SEQUENCE {
//!     gnss-TimeModelRefTime   INTEGER(0..65535),
//!     tA0                     INTEGER(-2147483648..2147483647),
//!     tA1                     INTEGER(-8388608..8388607)   OPTIONAL,  -- Need ON
//!     tA2                     INTEGER(-64..63)             OPTIONAL,  -- Need ON
//!     gnss-TO-ID              INTEGER(1..15),
//!     weekNumber              INTEGER(0..8191)             OPTIONAL,  -- Need ON
//!     deltaT                  INTEGER(-128..127)           OPTIONAL,  -- Need ON
//!     ...
//! }
//! ```
//!
//! All root fields (including the four OPTIONALs, which are plain INTEGERs) are
//! implemented at full bit-fidelity. The SEQUENCE is extensible (`...`); no
//! root extension additions are defined, so on decode any additions a newer
//! peer appended are read and discarded (forward-compatible).

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// GNSS-TimeModelElement ::= SEQUENCE { ... } -- EXTENSIBLE (TS 37.355 §6.5.2.4)
///
/// Parameters relating a satellite-system time to a reference GNSS system time:
/// * `gnss_time_model_ref_time` — reference time, scale 16 s, `INTEGER(0..65535)`.
/// * `ta0` — bias, scale 2^-35 s, `INTEGER(-2147483648..2147483647)` (full i32).
/// * `ta1` — drift, scale 2^-51 s/s, `INTEGER(-8388608..8388607)` OPTIONAL.
/// * `ta2` — drift rate, scale 2^-68 s/s², `INTEGER(-64..63)` OPTIONAL.
/// * `gnss_to_id` — time-offset system identifier, `INTEGER(1..15)`.
/// * `week_number` — reference week, scale 1 week, `INTEGER(0..8191)` OPTIONAL.
/// * `delta_t` — integer leap seconds, `INTEGER(-128..127)` OPTIONAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GnssTimeModelElement {
    pub gnss_time_model_ref_time: u16,
    pub ta0: i32,
    pub ta1: Option<i32>,
    pub ta2: Option<i8>,
    pub gnss_to_id: u8,
    pub week_number: Option<u16>,
    pub delta_t: Option<i8>,
}

impl GnssTimeModelElement {
    const REF_TIME: Constraint = Constraint::new(0, 65535);
    const TA0: Constraint = Constraint::new(-2_147_483_648, 2_147_483_647);
    const TA1: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const TA2: Constraint = Constraint::new(-64, 63);
    const TO_ID: Constraint = Constraint::new(1, 15);
    const WEEK_NUMBER: Constraint = Constraint::new(0, 8191);
    const DELTA_T: Constraint = Constraint::new(-128, 127);
}

impl UperEncode for GnssTimeModelElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE: ext-bit 0, then presence bits for the four
        // OPTIONALs in declaration order (tA1, tA2, weekNumber, deltaT).
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.ta1.is_some(),
                self.ta2.is_some(),
                self.week_number.is_some(),
                self.delta_t.is_some(),
            ],
        );
        encoder.encode_constrained_whole_number(
            self.gnss_time_model_ref_time as i64,
            &Self::REF_TIME,
        )?;
        encoder.encode_constrained_whole_number(self.ta0 as i64, &Self::TA0)?;
        if let Some(ta1) = self.ta1 {
            encoder.encode_constrained_whole_number(ta1 as i64, &Self::TA1)?;
        }
        if let Some(ta2) = self.ta2 {
            encoder.encode_constrained_whole_number(ta2 as i64, &Self::TA2)?;
        }
        encoder.encode_constrained_whole_number(self.gnss_to_id as i64, &Self::TO_ID)?;
        if let Some(week_number) = self.week_number {
            encoder.encode_constrained_whole_number(week_number as i64, &Self::WEEK_NUMBER)?;
        }
        if let Some(delta_t) = self.delta_t {
            encoder.encode_constrained_whole_number(delta_t as i64, &Self::DELTA_T)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssTimeModelElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 4)?;
        let gnss_time_model_ref_time =
            decoder.decode_constrained_whole_number(&Self::REF_TIME)? as u16;
        let ta0 = decoder.decode_constrained_whole_number(&Self::TA0)? as i32;
        let ta1 = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::TA1)? as i32)
        } else {
            None
        };
        let ta2 = if opts[1] {
            Some(decoder.decode_constrained_whole_number(&Self::TA2)? as i8)
        } else {
            None
        };
        let gnss_to_id = decoder.decode_constrained_whole_number(&Self::TO_ID)? as u8;
        let week_number = if opts[2] {
            Some(decoder.decode_constrained_whole_number(&Self::WEEK_NUMBER)? as u16)
        } else {
            None
        };
        let delta_t = if opts[3] {
            Some(decoder.decode_constrained_whole_number(&Self::DELTA_T)? as i8)
        } else {
            None
        };
        if ext {
            // Forward-compat: discard any root extension additions a newer peer added.
            decoder.decode_extension_additions()?;
        }
        Ok(GnssTimeModelElement {
            gnss_time_model_ref_time,
            ta0,
            ta1,
            ta2,
            gnss_to_id,
            week_number,
            delta_t,
        })
    }
}

/// GNSS-TimeModelList ::= SEQUENCE (SIZE(1..15)) OF GNSS-TimeModelElement
///
/// (TS 37.355 §6.5.2.4). At least one and at most 15 elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssTimeModelList {
    pub elements: Vec<GnssTimeModelElement>,
}

impl GnssTimeModelList {
    const SIZE: Constraint = Constraint::new(1, 15);
}

impl UperEncode for GnssTimeModelList {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        let count = self.elements.len();
        if !(1..=15).contains(&count) {
            // SIZE(1..15) violated; no dedicated encode-error variant exists.
            return Err(PerError::InvalidLength { length: count });
        }
        encoder.encode_constrained_whole_number(count as i64, &Self::SIZE)?;
        for element in &self.elements {
            element.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssTimeModelList {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(GnssTimeModelElement::decode_uper(decoder)?);
        }
        Ok(GnssTimeModelList { elements })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: UperEncode + UperDecode + PartialEq + std::fmt::Debug,
    {
        let mut enc = UperEncoder::new();
        value.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = T::decode_uper(&mut dec).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn rt_time_model_element_all_present() {
        roundtrip(&GnssTimeModelElement {
            gnss_time_model_ref_time: 12345,
            ta0: -2_147_483_648,
            ta1: Some(-8_388_608),
            ta2: Some(-64),
            gnss_to_id: 1,
            week_number: Some(8191),
            delta_t: Some(-128),
        });
        roundtrip(&GnssTimeModelElement {
            gnss_time_model_ref_time: 65535,
            ta0: 2_147_483_647,
            ta1: Some(8_388_607),
            ta2: Some(63),
            gnss_to_id: 15,
            week_number: Some(0),
            delta_t: Some(127),
        });
    }

    #[test]
    fn rt_time_model_element_optionals_absent() {
        roundtrip(&GnssTimeModelElement {
            gnss_time_model_ref_time: 0,
            ta0: 0,
            ta1: None,
            ta2: None,
            gnss_to_id: 8,
            week_number: None,
            delta_t: None,
        });
    }

    #[test]
    fn rt_time_model_element_partial_optionals() {
        roundtrip(&GnssTimeModelElement {
            gnss_time_model_ref_time: 100,
            ta0: 42,
            ta1: Some(7),
            ta2: None,
            gnss_to_id: 3,
            week_number: Some(2048),
            delta_t: None,
        });
    }

    #[test]
    fn rt_time_model_list() {
        roundtrip(&GnssTimeModelList {
            elements: vec![GnssTimeModelElement {
                gnss_time_model_ref_time: 500,
                ta0: -1,
                ta1: None,
                ta2: None,
                gnss_to_id: 2,
                week_number: None,
                delta_t: None,
            }],
        });
        roundtrip(&GnssTimeModelList {
            elements: vec![
                GnssTimeModelElement {
                    gnss_time_model_ref_time: 1,
                    ta0: 10,
                    ta1: Some(-5),
                    ta2: Some(1),
                    gnss_to_id: 1,
                    week_number: Some(1),
                    delta_t: Some(-1),
                },
                GnssTimeModelElement {
                    gnss_time_model_ref_time: 65000,
                    ta0: -100000,
                    ta1: None,
                    ta2: Some(-2),
                    gnss_to_id: 15,
                    week_number: None,
                    delta_t: Some(18),
                },
            ],
        });
    }

    #[test]
    fn list_length_out_of_range_errors() {
        let empty = GnssTimeModelList { elements: vec![] };
        let mut enc = UperEncoder::new();
        assert!(empty.encode_uper(&mut enc).is_err());
    }
}
