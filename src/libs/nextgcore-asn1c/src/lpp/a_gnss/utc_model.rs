//! LPP A-GNSS GNSS-UTC-Model assistance data (3GPP TS 37.355 §6.5.2), UPER.
//!
//! `GNSS-UTC-Model` lets the location server relate a GNSS system time to
//! Universal Time Coordinated (UTC). It is a CHOICE over five parameter sets,
//! each tailored to a constellation / signal:
//!
//!   * `utcModel1` (UTC-ModelSet1) — GPS / QZSS / SBAS (IS-GPS-200 style).
//!   * `utcModel2` (UTC-ModelSet2) — Modernized GPS CNAV, BDS B1C / B2a.
//!   * `utcModel3` (UTC-ModelSet3) — GLONASS.
//!   * `utcModel4` (UTC-ModelSet4) — Galileo / NavIC (with UTC-Standard-ID).
//!   * `utcModel5-r12` (UTC-ModelSet5-r12) — BDS B1I. **DEFERRED**: this is the
//!     lone CHOICE extension addition (past the `...`); never emitted, and a
//!     peer that selects it is rejected on decode.
//!
//! Every model-set SEQUENCE is itself extensible; no extension additions are
//! defined for the root sets, so a set-that-carries-extensions is rejected on
//! decode (documented per type). Primary fields are full bit-fidelity.
//!
//! ASN.1 (TS 37.355):
//! ```text
//! GNSS-UTC-Model ::= CHOICE {
//!     utcModel1        UTC-ModelSet1,
//!     utcModel2        UTC-ModelSet2,
//!     utcModel3        UTC-ModelSet3,
//!     utcModel4        UTC-ModelSet4,
//!     ...,
//!     utcModel5-r12    UTC-ModelSet5-r12
//! }
//! ```

use bitvec::prelude::*;

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// Fixed-size BIT STRING helpers (value carried as an integer, bit0 = MSB).
// ---------------------------------------------------------------------------

/// Encode the low `n` bits of `value` as a fixed-length BIT STRING(SIZE(n)),
/// MSB first (X.691 16; no length determinant for a fixed size).
fn encode_fixed_bits(e: &mut UperEncoder, value: u8, n: usize) -> PerResult<()> {
    let mut bits: BitVec<u8, Msb0> = BitVec::with_capacity(n);
    for i in (0..n).rev() {
        bits.push((value >> i) & 1 == 1);
    }
    e.encode_bit_string(&bits, Some(n), Some(n))
}

/// Decode a fixed-length BIT STRING(SIZE(n)) back into an integer (bit0 = MSB).
fn decode_fixed_bits(d: &mut UperDecoder, n: usize) -> PerResult<u8> {
    let bits = d.decode_bit_string(Some(n), Some(n))?;
    let mut v = 0u8;
    for b in bits.iter() {
        v = (v << 1) | (*b as u8);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// UTC-ModelSet1  (GPS / QZSS / SBAS)
// ---------------------------------------------------------------------------

/// UTC-ModelSet1 ::= SEQUENCE {   -- extensible
///     gnss-Utc-A1        INTEGER (-8388608..8388607),
///     gnss-Utc-A0        INTEGER (-2147483648..2147483647),
///     gnss-Utc-Tot       INTEGER (0..255),
///     gnss-Utc-WNt       INTEGER (0..255),
///     gnss-Utc-DeltaTls  INTEGER (-128..127),
///     gnss-Utc-WNlsf     INTEGER (0..255),
///     gnss-Utc-DN        INTEGER (-128..127),
///     gnss-Utc-DeltaTlsf INTEGER (-128..127),
///     ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcModelSet1 {
    pub gnss_utc_a1: i32,
    pub gnss_utc_a0: i32,
    pub gnss_utc_tot: u8,
    pub gnss_utc_wnt: u8,
    pub gnss_utc_delta_tls: i8,
    pub gnss_utc_wnlsf: u8,
    pub gnss_utc_dn: i8,
    pub gnss_utc_delta_tlsf: i8,
}

impl UtcModelSet1 {
    const A1: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const A0: Constraint = Constraint::new(-2_147_483_648, 2_147_483_647);
    const TOT: Constraint = Constraint::new(0, 255);
    const WNT: Constraint = Constraint::new(0, 255);
    const DELTA_TLS: Constraint = Constraint::new(-128, 127);
    const WNLSF: Constraint = Constraint::new(0, 255);
    const DN: Constraint = Constraint::new(-128, 127);
    const DELTA_TLSF: Constraint = Constraint::new(-128, 127);
}

impl UperEncode for UtcModelSet1 {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root optionals, no extensions emitted.
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.gnss_utc_a1 as i64, &Self::A1)?;
        e.encode_constrained_whole_number(self.gnss_utc_a0 as i64, &Self::A0)?;
        e.encode_constrained_whole_number(self.gnss_utc_tot as i64, &Self::TOT)?;
        e.encode_constrained_whole_number(self.gnss_utc_wnt as i64, &Self::WNT)?;
        e.encode_constrained_whole_number(self.gnss_utc_delta_tls as i64, &Self::DELTA_TLS)?;
        e.encode_constrained_whole_number(self.gnss_utc_wnlsf as i64, &Self::WNLSF)?;
        e.encode_constrained_whole_number(self.gnss_utc_dn as i64, &Self::DN)?;
        e.encode_constrained_whole_number(self.gnss_utc_delta_tlsf as i64, &Self::DELTA_TLSF)
    }
}

impl UperDecode for UtcModelSet1 {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "UTC-ModelSet1 extension additions not supported".to_string(),
            ));
        }
        Ok(UtcModelSet1 {
            gnss_utc_a1: d.decode_constrained_whole_number(&Self::A1)? as i32,
            gnss_utc_a0: d.decode_constrained_whole_number(&Self::A0)? as i32,
            gnss_utc_tot: d.decode_constrained_whole_number(&Self::TOT)? as u8,
            gnss_utc_wnt: d.decode_constrained_whole_number(&Self::WNT)? as u8,
            gnss_utc_delta_tls: d.decode_constrained_whole_number(&Self::DELTA_TLS)? as i8,
            gnss_utc_wnlsf: d.decode_constrained_whole_number(&Self::WNLSF)? as u8,
            gnss_utc_dn: d.decode_constrained_whole_number(&Self::DN)? as i8,
            gnss_utc_delta_tlsf: d.decode_constrained_whole_number(&Self::DELTA_TLSF)? as i8,
        })
    }
}

// ---------------------------------------------------------------------------
// UTC-ModelSet2  (Modernized GPS CNAV / BDS B1C, B2a)
// ---------------------------------------------------------------------------

/// UTC-ModelSet2 ::= SEQUENCE {   -- extensible
///     utcA0         INTEGER (-32768..32767),
///     utcA1         INTEGER (-4096..4095),
///     utcA2         INTEGER (-64..63),
///     utcDeltaTls   INTEGER (-128..127),
///     utcTot        INTEGER (0..65535),
///     utcWNot       INTEGER (0..8191),
///     utcWNlsf      INTEGER (0..255),
///     utcDN         BIT STRING (SIZE(4)),
///     utcDeltaTlsf  INTEGER (-128..127),
///     ... }
///
/// `utc_dn` carries the 4-bit BIT STRING as an integer (bit0 = MSB, 0..15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcModelSet2 {
    pub utc_a0: i16,
    pub utc_a1: i16,
    pub utc_a2: i8,
    pub utc_delta_tls: i8,
    pub utc_tot: u16,
    pub utc_wnot: u16,
    pub utc_wnlsf: u8,
    pub utc_dn: u8,
    pub utc_delta_tlsf: i8,
}

impl UtcModelSet2 {
    const A0: Constraint = Constraint::new(-32_768, 32_767);
    const A1: Constraint = Constraint::new(-4_096, 4_095);
    const A2: Constraint = Constraint::new(-64, 63);
    const DELTA_TLS: Constraint = Constraint::new(-128, 127);
    const TOT: Constraint = Constraint::new(0, 65_535);
    const WNOT: Constraint = Constraint::new(0, 8_191);
    const WNLSF: Constraint = Constraint::new(0, 255);
    const DELTA_TLSF: Constraint = Constraint::new(-128, 127);
    const DN_BITS: usize = 4;
}

impl UperEncode for UtcModelSet2 {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.utc_a0 as i64, &Self::A0)?;
        e.encode_constrained_whole_number(self.utc_a1 as i64, &Self::A1)?;
        e.encode_constrained_whole_number(self.utc_a2 as i64, &Self::A2)?;
        e.encode_constrained_whole_number(self.utc_delta_tls as i64, &Self::DELTA_TLS)?;
        e.encode_constrained_whole_number(self.utc_tot as i64, &Self::TOT)?;
        e.encode_constrained_whole_number(self.utc_wnot as i64, &Self::WNOT)?;
        e.encode_constrained_whole_number(self.utc_wnlsf as i64, &Self::WNLSF)?;
        encode_fixed_bits(e, self.utc_dn, Self::DN_BITS)?;
        e.encode_constrained_whole_number(self.utc_delta_tlsf as i64, &Self::DELTA_TLSF)
    }
}

impl UperDecode for UtcModelSet2 {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "UTC-ModelSet2 extension additions not supported".to_string(),
            ));
        }
        Ok(UtcModelSet2 {
            utc_a0: d.decode_constrained_whole_number(&Self::A0)? as i16,
            utc_a1: d.decode_constrained_whole_number(&Self::A1)? as i16,
            utc_a2: d.decode_constrained_whole_number(&Self::A2)? as i8,
            utc_delta_tls: d.decode_constrained_whole_number(&Self::DELTA_TLS)? as i8,
            utc_tot: d.decode_constrained_whole_number(&Self::TOT)? as u16,
            utc_wnot: d.decode_constrained_whole_number(&Self::WNOT)? as u16,
            utc_wnlsf: d.decode_constrained_whole_number(&Self::WNLSF)? as u8,
            utc_dn: decode_fixed_bits(d, Self::DN_BITS)?,
            utc_delta_tlsf: d.decode_constrained_whole_number(&Self::DELTA_TLSF)? as i8,
        })
    }
}

// ---------------------------------------------------------------------------
// UTC-ModelSet3  (GLONASS)
// ---------------------------------------------------------------------------

/// UTC-ModelSet3 ::= SEQUENCE {   -- extensible
///     nA    INTEGER (1..1461),
///     tauC  INTEGER (-2147483648..2147483647),
///     b1    INTEGER (-1024..1023)   OPTIONAL,   -- Cond GLONASS-M
///     b2    INTEGER (-512..511)     OPTIONAL,   -- Cond GLONASS-M
///     kp    BIT STRING (SIZE(2))    OPTIONAL,   -- Cond GLONASS-M
///     ... }
///
/// The three GLONASS-M conditional optionals are FULLY supported (present or
/// absent). `kp` carries the 2-bit BIT STRING as an integer (bit0 = MSB, 0..3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcModelSet3 {
    pub na: u16,
    pub tau_c: i32,
    pub b1: Option<i16>,
    pub b2: Option<i16>,
    pub kp: Option<u8>,
}

impl UtcModelSet3 {
    const NA: Constraint = Constraint::new(1, 1_461);
    const TAU_C: Constraint = Constraint::new(-2_147_483_648, 2_147_483_647);
    const B1: Constraint = Constraint::new(-1_024, 1_023);
    const B2: Constraint = Constraint::new(-512, 511);
    const KP_BITS: usize = 2;
}

impl UperEncode for UtcModelSet3 {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(
            Some(false),
            &[self.b1.is_some(), self.b2.is_some(), self.kp.is_some()],
        );
        e.encode_constrained_whole_number(self.na as i64, &Self::NA)?;
        e.encode_constrained_whole_number(self.tau_c as i64, &Self::TAU_C)?;
        if let Some(b1) = self.b1 {
            e.encode_constrained_whole_number(b1 as i64, &Self::B1)?;
        }
        if let Some(b2) = self.b2 {
            e.encode_constrained_whole_number(b2 as i64, &Self::B2)?;
        }
        if let Some(kp) = self.kp {
            encode_fixed_bits(e, kp, Self::KP_BITS)?;
        }
        Ok(())
    }
}

impl UperDecode for UtcModelSet3 {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 3)?;
        if ext {
            return Err(PerError::DecodeError(
                "UTC-ModelSet3 extension additions not supported".to_string(),
            ));
        }
        let na = d.decode_constrained_whole_number(&Self::NA)? as u16;
        let tau_c = d.decode_constrained_whole_number(&Self::TAU_C)? as i32;
        let b1 = if opts[0] {
            Some(d.decode_constrained_whole_number(&Self::B1)? as i16)
        } else {
            None
        };
        let b2 = if opts[1] {
            Some(d.decode_constrained_whole_number(&Self::B2)? as i16)
        } else {
            None
        };
        let kp = if opts[2] {
            Some(decode_fixed_bits(d, Self::KP_BITS)?)
        } else {
            None
        };
        Ok(UtcModelSet3 {
            na,
            tau_c,
            b1,
            b2,
            kp,
        })
    }
}

// ---------------------------------------------------------------------------
// UTC-ModelSet4  (Galileo / NavIC)
// ---------------------------------------------------------------------------

/// UTC-ModelSet4 ::= SEQUENCE {   -- extensible
///     utcA1wnt      INTEGER (-8388608..8388607),
///     utcA0wnt      INTEGER (-2147483648..2147483647),
///     utcTot        INTEGER (0..255),
///     utcWNt        INTEGER (0..255),
///     utcDeltaTls   INTEGER (-128..127),
///     utcWNlsf      INTEGER (0..255),
///     utcDN         INTEGER (-128..127),
///     utcDeltaTlsf  INTEGER (-128..127),
///     utcStandardID INTEGER (0..7),
///     ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcModelSet4 {
    pub utc_a1wnt: i32,
    pub utc_a0wnt: i32,
    pub utc_tot: u8,
    pub utc_wnt: u8,
    pub utc_delta_tls: i8,
    pub utc_wnlsf: u8,
    pub utc_dn: i8,
    pub utc_delta_tlsf: i8,
    pub utc_standard_id: u8,
}

impl UtcModelSet4 {
    const A1WNT: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const A0WNT: Constraint = Constraint::new(-2_147_483_648, 2_147_483_647);
    const TOT: Constraint = Constraint::new(0, 255);
    const WNT: Constraint = Constraint::new(0, 255);
    const DELTA_TLS: Constraint = Constraint::new(-128, 127);
    const WNLSF: Constraint = Constraint::new(0, 255);
    const DN: Constraint = Constraint::new(-128, 127);
    const DELTA_TLSF: Constraint = Constraint::new(-128, 127);
    const STANDARD_ID: Constraint = Constraint::new(0, 7);
}

impl UperEncode for UtcModelSet4 {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.utc_a1wnt as i64, &Self::A1WNT)?;
        e.encode_constrained_whole_number(self.utc_a0wnt as i64, &Self::A0WNT)?;
        e.encode_constrained_whole_number(self.utc_tot as i64, &Self::TOT)?;
        e.encode_constrained_whole_number(self.utc_wnt as i64, &Self::WNT)?;
        e.encode_constrained_whole_number(self.utc_delta_tls as i64, &Self::DELTA_TLS)?;
        e.encode_constrained_whole_number(self.utc_wnlsf as i64, &Self::WNLSF)?;
        e.encode_constrained_whole_number(self.utc_dn as i64, &Self::DN)?;
        e.encode_constrained_whole_number(self.utc_delta_tlsf as i64, &Self::DELTA_TLSF)?;
        e.encode_constrained_whole_number(self.utc_standard_id as i64, &Self::STANDARD_ID)
    }
}

impl UperDecode for UtcModelSet4 {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "UTC-ModelSet4 extension additions not supported".to_string(),
            ));
        }
        Ok(UtcModelSet4 {
            utc_a1wnt: d.decode_constrained_whole_number(&Self::A1WNT)? as i32,
            utc_a0wnt: d.decode_constrained_whole_number(&Self::A0WNT)? as i32,
            utc_tot: d.decode_constrained_whole_number(&Self::TOT)? as u8,
            utc_wnt: d.decode_constrained_whole_number(&Self::WNT)? as u8,
            utc_delta_tls: d.decode_constrained_whole_number(&Self::DELTA_TLS)? as i8,
            utc_wnlsf: d.decode_constrained_whole_number(&Self::WNLSF)? as u8,
            utc_dn: d.decode_constrained_whole_number(&Self::DN)? as i8,
            utc_delta_tlsf: d.decode_constrained_whole_number(&Self::DELTA_TLSF)? as i8,
            utc_standard_id: d.decode_constrained_whole_number(&Self::STANDARD_ID)? as u8,
        })
    }
}

// ---------------------------------------------------------------------------
// GNSS-UTC-Model  (CHOICE)
// ---------------------------------------------------------------------------

/// GNSS-UTC-Model ::= CHOICE {   -- extensible, 4 root alternatives
///     utcModel1      UTC-ModelSet1,
///     utcModel2      UTC-ModelSet2,
///     utcModel3      UTC-ModelSet3,
///     utcModel4      UTC-ModelSet4,
///     ...,
///     utcModel5-r12  UTC-ModelSet5-r12 }   -- DEFERRED extension addition
///
/// The `utcModel5-r12` extension addition (BDS B1I) is UNSUPPORTED: it is never
/// selected on encode, and a decode whose CHOICE index falls past the root
/// (extension bit set) is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnssUtcModel {
    UtcModel1(UtcModelSet1),
    UtcModel2(UtcModelSet2),
    UtcModel3(UtcModelSet3),
    UtcModel4(UtcModelSet4),
}

impl GnssUtcModel {
    const NUM_ALTERNATIVES: usize = 4;
    const EXTENSIBLE: bool = true;
}

impl UperEncode for GnssUtcModel {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        match self {
            GnssUtcModel::UtcModel1(v) => {
                e.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_uper(e)
            }
            GnssUtcModel::UtcModel2(v) => {
                e.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_uper(e)
            }
            GnssUtcModel::UtcModel3(v) => {
                e.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_uper(e)
            }
            GnssUtcModel::UtcModel4(v) => {
                e.encode_choice_index(3, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_uper(e)
            }
        }
    }
}

impl UperDecode for GnssUtcModel {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let index = d.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(GnssUtcModel::UtcModel1(UtcModelSet1::decode_uper(d)?)),
            1 => Ok(GnssUtcModel::UtcModel2(UtcModelSet2::decode_uper(d)?)),
            2 => Ok(GnssUtcModel::UtcModel3(UtcModelSet3::decode_uper(d)?)),
            3 => Ok(GnssUtcModel::UtcModel4(UtcModelSet4::decode_uper(d)?)),
            // index >= 4 => extension addition (utcModel5-r12): DEFERRED.
            _ => Err(PerError::DecodeError(
                "GNSS-UTC-Model utcModel5-r12 extension addition not supported".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(model: &GnssUtcModel) -> GnssUtcModel {
        let mut enc = UperEncoder::new();
        model.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        GnssUtcModel::decode_uper(&mut dec).unwrap()
    }

    #[test]
    fn round_trip_utc_model1() {
        let original = GnssUtcModel::UtcModel1(UtcModelSet1 {
            gnss_utc_a1: -8_388_608,
            gnss_utc_a0: 2_147_483_647,
            gnss_utc_tot: 200,
            gnss_utc_wnt: 15,
            gnss_utc_delta_tls: -18,
            gnss_utc_wnlsf: 137,
            gnss_utc_dn: 7,
            gnss_utc_delta_tlsf: -18,
        });
        assert_eq!(round_trip(&original), original);
    }

    #[test]
    fn round_trip_utc_model2() {
        let original = GnssUtcModel::UtcModel2(UtcModelSet2 {
            utc_a0: -32_768,
            utc_a1: 4_095,
            utc_a2: -64,
            utc_delta_tls: -18,
            utc_tot: 65_535,
            utc_wnot: 8_191,
            utc_wnlsf: 255,
            utc_dn: 0b1010,
            utc_delta_tlsf: 127,
        });
        assert_eq!(round_trip(&original), original);
    }

    #[test]
    fn round_trip_utc_model3_all_optionals() {
        let original = GnssUtcModel::UtcModel3(UtcModelSet3 {
            na: 1_461,
            tau_c: -2_147_483_648,
            b1: Some(-1_024),
            b2: Some(511),
            kp: Some(0b11),
        });
        assert_eq!(round_trip(&original), original);
    }

    #[test]
    fn round_trip_utc_model3_no_optionals() {
        let original = GnssUtcModel::UtcModel3(UtcModelSet3 {
            na: 1,
            tau_c: 0,
            b1: None,
            b2: None,
            kp: None,
        });
        assert_eq!(round_trip(&original), original);
    }

    #[test]
    fn round_trip_utc_model4() {
        let original = GnssUtcModel::UtcModel4(UtcModelSet4 {
            utc_a1wnt: 8_388_607,
            utc_a0wnt: -2_147_483_648,
            utc_tot: 128,
            utc_wnt: 250,
            utc_delta_tls: -18,
            utc_wnlsf: 255,
            utc_dn: -1,
            utc_delta_tlsf: -18,
            utc_standard_id: 7,
        });
        assert_eq!(round_trip(&original), original);
    }

    /// A CHOICE encoded with the extension bit set (utcModel5-r12) must be
    /// rejected — the extension addition is deferred/unsupported.
    #[test]
    fn decode_extension_choice_is_rejected() {
        // extension bit = 1, normally-small index 0 (00000000...) -> selects
        // the first extension alternative (utcModel5-r12).
        let mut enc = UperEncoder::new();
        enc.write_bit(true); // CHOICE extension present
        enc.write_bit(false); // normally-small: not-large form
        enc.write_bits(0, 6); // extension index 0
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(GnssUtcModel::decode_uper(&mut dec).is_err());
    }
}
