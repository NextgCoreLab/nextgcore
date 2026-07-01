//! LPP GNSS Ionospheric Model assistance data (3GPP TS 37.355 §6.5.2.2), UPER.
//!
//! Encodes/decodes `GNSS-IonosphericModel`, delivered inside
//! [`super::common::GnssCommonAssistData`], and its two model parameter sets:
//!
//!   GNSS-IonosphericModel ::= SEQUENCE {
//!       klobucharModel   KlobucharModelParameter   OPTIONAL,  -- Need ON
//!       neQuickModel     NeQuickModelParameter     OPTIONAL,  -- Need ON
//!       ...
//!   }
//!
//! Both parameter sets are typed at full bit fidelity (they are the entire
//! payload of this IE). The Klobuchar model carries the ionospheric-delay
//! coefficients broadcast in GPS/QZSS/BDS navigation messages; the NeQuick
//! model carries the Galileo effective-ionisation-level coefficients plus the
//! optional per-region disturbance (storm) flags.
//!
//! The only deferrals are the SEQUENCE extension additions ("..."): none are
//! defined for the primary path, so a set extension bit yields a decode error
//! (documented per field below).

use bitvec::prelude::*;

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// `KlobucharModelParameter ::= SEQUENCE {
///     dataID  BIT STRING (SIZE (2)),
///     alfa0   INTEGER (-128..127),
///     alfa1   INTEGER (-128..127),
///     alfa2   INTEGER (-128..127),
///     alfa3   INTEGER (-128..127),
///     beta0   INTEGER (-128..127),
///     beta1   INTEGER (-128..127),
///     beta2   INTEGER (-128..127),
///     beta3   INTEGER (-128..127),
///     ... }`  (TS 37.355 §6.5.2.2)
///
/// `data_id` holds the 2 broadcast BIT STRING bits as a value in 0..=3
/// (bit 0 = MSB), matching the house convention used for other short fixed
/// BIT STRINGs (e.g. `GnssSystemTime::notification_of_leap_second`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KlobucharModelParameter {
    pub data_id: u8,
    pub alfa0: i8,
    pub alfa1: i8,
    pub alfa2: i8,
    pub alfa3: i8,
    pub beta0: i8,
    pub beta1: i8,
    pub beta2: i8,
    pub beta3: i8,
}

impl KlobucharModelParameter {
    const DATA_ID_BITS: usize = 2;
    /// alfa0..3 / beta0..3: INTEGER (-128..127).
    const COEFF: Constraint = Constraint::new(-128, 127);
}

impl UperEncode for KlobucharModelParameter {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL fields.
        encoder.encode_sequence_preamble(Some(false), &[]);
        // dataID BIT STRING (SIZE (2)) — fixed length, no length determinant.
        let mut data_id_bits: BitVec<u8, Msb0> = BitVec::with_capacity(Self::DATA_ID_BITS);
        data_id_bits.push(self.data_id & 0b10 != 0);
        data_id_bits.push(self.data_id & 0b01 != 0);
        encoder.encode_bit_string(
            &data_id_bits,
            Some(Self::DATA_ID_BITS),
            Some(Self::DATA_ID_BITS),
        )?;
        encoder.encode_constrained_whole_number(self.alfa0 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.alfa1 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.alfa2 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.alfa3 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.beta0 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.beta1 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.beta2 as i64, &Self::COEFF)?;
        encoder.encode_constrained_whole_number(self.beta3 as i64, &Self::COEFF)?;
        Ok(())
    }
}

impl UperDecode for KlobucharModelParameter {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            // "..." — no extension additions defined for the primary path.
            return Err(PerError::DecodeError(
                "LPP KlobucharModelParameter extension additions not supported".to_string(),
            ));
        }
        let data_id_bits =
            decoder.decode_bit_string(Some(Self::DATA_ID_BITS), Some(Self::DATA_ID_BITS))?;
        let data_id = ((data_id_bits[0] as u8) << 1) | (data_id_bits[1] as u8);
        Ok(KlobucharModelParameter {
            data_id,
            alfa0: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            alfa1: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            alfa2: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            alfa3: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            beta0: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            beta1: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            beta2: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
            beta3: decoder.decode_constrained_whole_number(&Self::COEFF)? as i8,
        })
    }
}

/// `NeQuickModelParameter ::= SEQUENCE {
///     ai0             INTEGER (0..2047),
///     ai1             INTEGER (0..2047),
///     ai2             INTEGER (0..2047),
///     ionoStormFlag1  INTEGER (0..1)  OPTIONAL,  -- Need ON
///     ionoStormFlag2  INTEGER (0..1)  OPTIONAL,  -- Need ON
///     ionoStormFlag3  INTEGER (0..1)  OPTIONAL,  -- Need ON
///     ionoStormFlag4  INTEGER (0..1)  OPTIONAL,  -- Need ON
///     ionoStormFlag5  INTEGER (0..1)  OPTIONAL,  -- Need ON
///     ... }`  (TS 37.355 §6.5.2.2)
///
/// The five `ionoStormFlag*` fields are the per-region disturbance flags, each
/// an `INTEGER (0..1)` carried as `Option<u8>` (0 or 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeQuickModelParameter {
    pub ai0: u16,
    pub ai1: u16,
    pub ai2: u16,
    pub iono_storm_flag1: Option<u8>,
    pub iono_storm_flag2: Option<u8>,
    pub iono_storm_flag3: Option<u8>,
    pub iono_storm_flag4: Option<u8>,
    pub iono_storm_flag5: Option<u8>,
}

impl NeQuickModelParameter {
    /// ai0/ai1/ai2: INTEGER (0..2047).
    const AI: Constraint = Constraint::new(0, 2047);
    /// ionoStormFlag1..5: INTEGER (0..1).
    const STORM_FLAG: Constraint = Constraint::new(0, 1);
}

impl UperEncode for NeQuickModelParameter {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.iono_storm_flag1.is_some(),
                self.iono_storm_flag2.is_some(),
                self.iono_storm_flag3.is_some(),
                self.iono_storm_flag4.is_some(),
                self.iono_storm_flag5.is_some(),
            ],
        );
        encoder.encode_constrained_whole_number(self.ai0 as i64, &Self::AI)?;
        encoder.encode_constrained_whole_number(self.ai1 as i64, &Self::AI)?;
        encoder.encode_constrained_whole_number(self.ai2 as i64, &Self::AI)?;
        for v in [
            self.iono_storm_flag1,
            self.iono_storm_flag2,
            self.iono_storm_flag3,
            self.iono_storm_flag4,
            self.iono_storm_flag5,
        ]
        .into_iter()
        .flatten()
        {
            encoder.encode_constrained_whole_number(v as i64, &Self::STORM_FLAG)?;
        }
        Ok(())
    }
}

impl UperDecode for NeQuickModelParameter {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        if ext {
            return Err(PerError::DecodeError(
                "LPP NeQuickModelParameter extension additions not supported".to_string(),
            ));
        }
        let ai0 = decoder.decode_constrained_whole_number(&Self::AI)? as u16;
        let ai1 = decoder.decode_constrained_whole_number(&Self::AI)? as u16;
        let ai2 = decoder.decode_constrained_whole_number(&Self::AI)? as u16;
        let mut read_flag = |present: bool| -> PerResult<Option<u8>> {
            if present {
                Ok(Some(
                    decoder.decode_constrained_whole_number(&Self::STORM_FLAG)? as u8,
                ))
            } else {
                Ok(None)
            }
        };
        Ok(NeQuickModelParameter {
            ai0,
            ai1,
            ai2,
            iono_storm_flag1: read_flag(opts[0])?,
            iono_storm_flag2: read_flag(opts[1])?,
            iono_storm_flag3: read_flag(opts[2])?,
            iono_storm_flag4: read_flag(opts[3])?,
            iono_storm_flag5: read_flag(opts[4])?,
        })
    }
}

/// `GNSS-IonosphericModel ::= SEQUENCE {
///     klobucharModel  KlobucharModelParameter  OPTIONAL,  -- Need ON
///     neQuickModel    NeQuickModelParameter    OPTIONAL,  -- Need ON
///     ... }`  (TS 37.355 §6.5.2.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GnssIonosphericModel {
    pub klobuchar_model: Option<KlobucharModelParameter>,
    pub nequick_model: Option<NeQuickModelParameter>,
}

impl UperEncode for GnssIonosphericModel {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[self.klobuchar_model.is_some(), self.nequick_model.is_some()],
        );
        if let Some(k) = &self.klobuchar_model {
            k.encode_uper(encoder)?;
        }
        if let Some(n) = &self.nequick_model {
            n.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssIonosphericModel {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 2)?;
        if ext {
            return Err(PerError::DecodeError(
                "LPP GNSS-IonosphericModel extension additions not supported".to_string(),
            ));
        }
        let klobuchar_model = if opts[0] {
            Some(KlobucharModelParameter::decode_uper(decoder)?)
        } else {
            None
        };
        let nequick_model = if opts[1] {
            Some(NeQuickModelParameter::decode_uper(decoder)?)
        } else {
            None
        };
        Ok(GnssIonosphericModel {
            klobuchar_model,
            nequick_model,
        })
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
    fn rt_klobuchar() {
        roundtrip(&KlobucharModelParameter {
            data_id: 0b01,
            alfa0: 12,
            alfa1: -128,
            alfa2: 127,
            alfa3: -1,
            beta0: 0,
            beta1: 64,
            beta2: -64,
            beta3: 100,
        });
    }

    #[test]
    fn rt_nequick_all_flags() {
        roundtrip(&NeQuickModelParameter {
            ai0: 2047,
            ai1: 0,
            ai2: 1234,
            iono_storm_flag1: Some(1),
            iono_storm_flag2: Some(0),
            iono_storm_flag3: Some(1),
            iono_storm_flag4: Some(0),
            iono_storm_flag5: Some(1),
        });
    }

    #[test]
    fn rt_nequick_no_flags() {
        roundtrip(&NeQuickModelParameter {
            ai0: 100,
            ai1: 200,
            ai2: 300,
            iono_storm_flag1: None,
            iono_storm_flag2: None,
            iono_storm_flag3: None,
            iono_storm_flag4: None,
            iono_storm_flag5: None,
        });
    }

    #[test]
    fn rt_ionospheric_model() {
        roundtrip(&GnssIonosphericModel {
            klobuchar_model: Some(KlobucharModelParameter {
                data_id: 0b11,
                alfa0: 1,
                alfa1: 2,
                alfa2: 3,
                alfa3: 4,
                beta0: -5,
                beta1: -6,
                beta2: -7,
                beta3: -8,
            }),
            nequick_model: Some(NeQuickModelParameter {
                ai0: 1,
                ai1: 2,
                ai2: 3,
                iono_storm_flag1: Some(1),
                iono_storm_flag2: None,
                iono_storm_flag3: Some(0),
                iono_storm_flag4: None,
                iono_storm_flag5: Some(1),
            }),
        });
    }

    #[test]
    fn rt_ionospheric_model_empty() {
        roundtrip(&GnssIonosphericModel {
            klobuchar_model: None,
            nequick_model: None,
        });
    }
}
