//! LPP A-GNSS **GNSS-Almanac** assistance data (3GPP TS 37.355 §6.5.2, ASN.1
//! module `LPP-PDU-Definitions`), X.691 UNALIGNED PER (UPER).
//!
//! The IE `GNSS-Almanac` carries the coarse, long-term model of the satellite
//! positions of a GNSS constellation. It is a size-constrained list of
//! per-satellite almanac elements, each selecting one of six root almanac
//! model variants (Model-1..Model-6):
//!
//!   GNSS-Almanac
//!     → GNSS-AlmanacList  SEQUENCE (SIZE(1..64)) OF
//!       → GNSS-AlmanacElement  CHOICE {
//!            keplerianAlmanacSet      AlmanacKeplerianSet,       -- Model-1
//!            keplerianNAV-Almanac     AlmanacNAV-KeplerianSet,   -- Model-2
//!            keplerianReducedAlmanac  AlmanacReducedKeplerianSet,-- Model-3
//!            keplerianMidiAlmanac     AlmanacMidiAlmanacSet,     -- Model-4
//!            keplerianGLONASS         AlmanacGLONASS-AlmanacSet, -- Model-5
//!            ecef-SBAS-Almanac        AlmanacECEF-SBAS-AlmanacSet,-- Model-6
//!            ... }
//!
//! Full bit-fidelity for all six root variants and every primary field.
//! DEFERRALS (each `false` in the preamble / decode-error, documented inline):
//!   * every SEQUENCE `...` extension-addition block (none defined in the root
//!     release; later releases add e.g. new fields) is emitted absent and, if a
//!     peer sets the extension-present bit, rejected on decode;
//!   * the `GNSS-AlmanacElement` CHOICE extension additions (e.g.
//!     `keplerianBDS-Almanac-r12` added in later releases) are never selected
//!     and rejected on decode.
//!
//! Ranges/field names cited from TS 37.355 (aligned with TS 36.355 v10.5.0
//! §6.5.2 which shares the identical A-GNSS ASN.1).

use super::common::SvId;
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ===========================================================================
// AlmanacKeplerianSet  -- Model-1 (Galileo / QZSS / GPS Keplerian)
// ===========================================================================

/// AlmanacKeplerianSet ::= SEQUENCE {   -- extensible
///     svID                 SV-ID,
///     kepAlmanacE          INTEGER (0..2047),
///     kepAlmanacDeltaI     INTEGER (-1024..1023),
///     kepAlmanacOmegaDot   INTEGER (-1024..1023),
///     kepSVHealth          INTEGER (0..15),
///     kepAlmanacAPowerHalf INTEGER (-65536..65535),
///     kepAlmanacOmega0     INTEGER (-32768..32767),
///     kepAlmanacW          INTEGER (-32768..32767),
///     kepAlmanacM0         INTEGER (-32768..32767),
///     kepAlmanacAF0        INTEGER (-8192..8191),
///     kepAlmanacAF1        INTEGER (-1024..1023),
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct AlmanacKeplerianSet {
    pub sv_id: SvId,
    pub kep_almanac_e: u16,
    pub kep_almanac_delta_i: i16,
    pub kep_almanac_omega_dot: i16,
    pub kep_sv_health: u8,
    pub kep_almanac_a_power_half: i32,
    pub kep_almanac_omega0: i16,
    pub kep_almanac_w: i16,
    pub kep_almanac_m0: i16,
    pub kep_almanac_af0: i16,
    pub kep_almanac_af1: i16,
}

impl AlmanacKeplerianSet {
    const E: Constraint = Constraint::new(0, 2047);
    const DELTA_I: Constraint = Constraint::new(-1024, 1023);
    const OMEGA_DOT: Constraint = Constraint::new(-1024, 1023);
    const SV_HEALTH: Constraint = Constraint::new(0, 15);
    const A_POWER_HALF: Constraint = Constraint::new(-65536, 65535);
    const OMEGA0: Constraint = Constraint::new(-32768, 32767);
    const W: Constraint = Constraint::new(-32768, 32767);
    const M0: Constraint = Constraint::new(-32768, 32767);
    const AF0: Constraint = Constraint::new(-8192, 8191);
    const AF1: Constraint = Constraint::new(-1024, 1023);
}

impl UperEncode for AlmanacKeplerianSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no OPTIONAL root fields, no extension additions.
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_constrained_whole_number(self.kep_almanac_e as i64, &Self::E)?;
        e.encode_constrained_whole_number(self.kep_almanac_delta_i as i64, &Self::DELTA_I)?;
        e.encode_constrained_whole_number(self.kep_almanac_omega_dot as i64, &Self::OMEGA_DOT)?;
        e.encode_constrained_whole_number(self.kep_sv_health as i64, &Self::SV_HEALTH)?;
        e.encode_constrained_whole_number(
            self.kep_almanac_a_power_half as i64,
            &Self::A_POWER_HALF,
        )?;
        e.encode_constrained_whole_number(self.kep_almanac_omega0 as i64, &Self::OMEGA0)?;
        e.encode_constrained_whole_number(self.kep_almanac_w as i64, &Self::W)?;
        e.encode_constrained_whole_number(self.kep_almanac_m0 as i64, &Self::M0)?;
        e.encode_constrained_whole_number(self.kep_almanac_af0 as i64, &Self::AF0)?;
        e.encode_constrained_whole_number(self.kep_almanac_af1 as i64, &Self::AF1)?;
        Ok(())
    }
}

impl UperDecode for AlmanacKeplerianSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacKeplerianSet extension additions not supported".into(),
            ));
        }
        Ok(AlmanacKeplerianSet {
            sv_id: SvId::decode_uper(d)?,
            kep_almanac_e: d.decode_constrained_whole_number(&Self::E)? as u16,
            kep_almanac_delta_i: d.decode_constrained_whole_number(&Self::DELTA_I)? as i16,
            kep_almanac_omega_dot: d.decode_constrained_whole_number(&Self::OMEGA_DOT)? as i16,
            kep_sv_health: d.decode_constrained_whole_number(&Self::SV_HEALTH)? as u8,
            kep_almanac_a_power_half: d.decode_constrained_whole_number(&Self::A_POWER_HALF)?
                as i32,
            kep_almanac_omega0: d.decode_constrained_whole_number(&Self::OMEGA0)? as i16,
            kep_almanac_w: d.decode_constrained_whole_number(&Self::W)? as i16,
            kep_almanac_m0: d.decode_constrained_whole_number(&Self::M0)? as i16,
            kep_almanac_af0: d.decode_constrained_whole_number(&Self::AF0)? as i16,
            kep_almanac_af1: d.decode_constrained_whole_number(&Self::AF1)? as i16,
        })
    }
}

// ===========================================================================
// AlmanacNAV-KeplerianSet  -- Model-2 (GPS/QZSS NAV Keplerian)
// ===========================================================================

/// AlmanacNAV-KeplerianSet ::= SEQUENCE {   -- extensible
///     svID           SV-ID,
///     navAlmE        INTEGER (0..65535),
///     navAlmDeltaI   INTEGER (-32768..32767),
///     navAlmOMEGADOT INTEGER (-32768..32767),
///     navAlmSVHealth INTEGER (0..255),
///     navAlmSqrtA    INTEGER (0..16777215),
///     navAlmOMEGAo   INTEGER (-8388608..8388607),
///     navAlmOmega    INTEGER (-8388608..8388607),
///     navAlmMo       INTEGER (-8388608..8388607),
///     navAlmaf0      INTEGER (-1024..1023),
///     navAlmaf1      INTEGER (-1024..1023),
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct AlmanacNavKeplerianSet {
    pub sv_id: SvId,
    pub nav_alm_e: u16,
    pub nav_alm_delta_i: i16,
    pub nav_alm_omega_dot: i16,
    pub nav_alm_sv_health: u8,
    pub nav_alm_sqrt_a: u32,
    pub nav_alm_omega_o: i32,
    pub nav_alm_omega: i32,
    pub nav_alm_mo: i32,
    pub nav_alm_af0: i16,
    pub nav_alm_af1: i16,
}

impl AlmanacNavKeplerianSet {
    const E: Constraint = Constraint::new(0, 65535);
    const DELTA_I: Constraint = Constraint::new(-32768, 32767);
    const OMEGA_DOT: Constraint = Constraint::new(-32768, 32767);
    const SV_HEALTH: Constraint = Constraint::new(0, 255);
    const SQRT_A: Constraint = Constraint::new(0, 16_777_215);
    const OMEGA_O: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const OMEGA: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const MO: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const AF0: Constraint = Constraint::new(-1024, 1023);
    const AF1: Constraint = Constraint::new(-1024, 1023);
}

impl UperEncode for AlmanacNavKeplerianSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_constrained_whole_number(self.nav_alm_e as i64, &Self::E)?;
        e.encode_constrained_whole_number(self.nav_alm_delta_i as i64, &Self::DELTA_I)?;
        e.encode_constrained_whole_number(self.nav_alm_omega_dot as i64, &Self::OMEGA_DOT)?;
        e.encode_constrained_whole_number(self.nav_alm_sv_health as i64, &Self::SV_HEALTH)?;
        e.encode_constrained_whole_number(self.nav_alm_sqrt_a as i64, &Self::SQRT_A)?;
        e.encode_constrained_whole_number(self.nav_alm_omega_o as i64, &Self::OMEGA_O)?;
        e.encode_constrained_whole_number(self.nav_alm_omega as i64, &Self::OMEGA)?;
        e.encode_constrained_whole_number(self.nav_alm_mo as i64, &Self::MO)?;
        e.encode_constrained_whole_number(self.nav_alm_af0 as i64, &Self::AF0)?;
        e.encode_constrained_whole_number(self.nav_alm_af1 as i64, &Self::AF1)?;
        Ok(())
    }
}

impl UperDecode for AlmanacNavKeplerianSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacNAV-KeplerianSet extension additions not supported".into(),
            ));
        }
        Ok(AlmanacNavKeplerianSet {
            sv_id: SvId::decode_uper(d)?,
            nav_alm_e: d.decode_constrained_whole_number(&Self::E)? as u16,
            nav_alm_delta_i: d.decode_constrained_whole_number(&Self::DELTA_I)? as i16,
            nav_alm_omega_dot: d.decode_constrained_whole_number(&Self::OMEGA_DOT)? as i16,
            nav_alm_sv_health: d.decode_constrained_whole_number(&Self::SV_HEALTH)? as u8,
            nav_alm_sqrt_a: d.decode_constrained_whole_number(&Self::SQRT_A)? as u32,
            nav_alm_omega_o: d.decode_constrained_whole_number(&Self::OMEGA_O)? as i32,
            nav_alm_omega: d.decode_constrained_whole_number(&Self::OMEGA)? as i32,
            nav_alm_mo: d.decode_constrained_whole_number(&Self::MO)? as i32,
            nav_alm_af0: d.decode_constrained_whole_number(&Self::AF0)? as i16,
            nav_alm_af1: d.decode_constrained_whole_number(&Self::AF1)? as i16,
        })
    }
}

// ===========================================================================
// AlmanacReducedKeplerianSet  -- Model-3 (reduced Keplerian)
// ===========================================================================

/// AlmanacReducedKeplerianSet ::= SEQUENCE {   -- extensible
///     svID           SV-ID,
///     redAlmDeltaA   INTEGER (-128..127),
///     redAlmOmega0   INTEGER (-64..63),
///     redAlmPhi0     INTEGER (-64..63),
///     redAlmL1Health BOOLEAN,
///     redAlmL2Health BOOLEAN,
///     redAlmL5Health BOOLEAN,
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct AlmanacReducedKeplerianSet {
    pub sv_id: SvId,
    pub red_alm_delta_a: i8,
    pub red_alm_omega0: i8,
    pub red_alm_phi0: i8,
    pub red_alm_l1_health: bool,
    pub red_alm_l2_health: bool,
    pub red_alm_l5_health: bool,
}

impl AlmanacReducedKeplerianSet {
    const DELTA_A: Constraint = Constraint::new(-128, 127);
    const OMEGA0: Constraint = Constraint::new(-64, 63);
    const PHI0: Constraint = Constraint::new(-64, 63);
}

impl UperEncode for AlmanacReducedKeplerianSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_constrained_whole_number(self.red_alm_delta_a as i64, &Self::DELTA_A)?;
        e.encode_constrained_whole_number(self.red_alm_omega0 as i64, &Self::OMEGA0)?;
        e.encode_constrained_whole_number(self.red_alm_phi0 as i64, &Self::PHI0)?;
        // Three BOOLEAN fields: one bit each (X.691 12).
        e.write_bit(self.red_alm_l1_health);
        e.write_bit(self.red_alm_l2_health);
        e.write_bit(self.red_alm_l5_health);
        Ok(())
    }
}

impl UperDecode for AlmanacReducedKeplerianSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacReducedKeplerianSet extension additions not supported".into(),
            ));
        }
        Ok(AlmanacReducedKeplerianSet {
            sv_id: SvId::decode_uper(d)?,
            red_alm_delta_a: d.decode_constrained_whole_number(&Self::DELTA_A)? as i8,
            red_alm_omega0: d.decode_constrained_whole_number(&Self::OMEGA0)? as i8,
            red_alm_phi0: d.decode_constrained_whole_number(&Self::PHI0)? as i8,
            red_alm_l1_health: d.read_bit()?,
            red_alm_l2_health: d.read_bit()?,
            red_alm_l5_health: d.read_bit()?,
        })
    }
}

// ===========================================================================
// AlmanacMidiAlmanacSet  -- Model-4 (Midi almanac)
// ===========================================================================

/// AlmanacMidiAlmanacSet ::= SEQUENCE {   -- extensible
///     svID            SV-ID,
///     midiAlmE        INTEGER (0..2047),
///     midiAlmDeltaI   INTEGER (-1024..1023),
///     midiAlmOmegaDot INTEGER (-1024..1023),
///     midiAlmSqrtA    INTEGER (0..131071),
///     midiAlmOmega0   INTEGER (-32768..32767),
///     midiAlmOmega    INTEGER (-32768..32767),
///     midiAlmMo       INTEGER (-32768..32767),
///     midiAlmaf0      INTEGER (-1024..1023),
///     midiAlmaf1      INTEGER (-512..511),
///     midiAlmL1Health BOOLEAN,
///     midiAlmL2Health BOOLEAN,
///     midiAlmL5Health BOOLEAN,
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct AlmanacMidiAlmanacSet {
    pub sv_id: SvId,
    pub midi_alm_e: u16,
    pub midi_alm_delta_i: i16,
    pub midi_alm_omega_dot: i16,
    pub midi_alm_sqrt_a: u32,
    pub midi_alm_omega0: i16,
    pub midi_alm_omega: i16,
    pub midi_alm_mo: i16,
    pub midi_alm_af0: i16,
    pub midi_alm_af1: i16,
    pub midi_alm_l1_health: bool,
    pub midi_alm_l2_health: bool,
    pub midi_alm_l5_health: bool,
}

impl AlmanacMidiAlmanacSet {
    const E: Constraint = Constraint::new(0, 2047);
    const DELTA_I: Constraint = Constraint::new(-1024, 1023);
    const OMEGA_DOT: Constraint = Constraint::new(-1024, 1023);
    const SQRT_A: Constraint = Constraint::new(0, 131_071);
    const OMEGA0: Constraint = Constraint::new(-32768, 32767);
    const OMEGA: Constraint = Constraint::new(-32768, 32767);
    const MO: Constraint = Constraint::new(-32768, 32767);
    const AF0: Constraint = Constraint::new(-1024, 1023);
    const AF1: Constraint = Constraint::new(-512, 511);
}

impl UperEncode for AlmanacMidiAlmanacSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        e.encode_constrained_whole_number(self.midi_alm_e as i64, &Self::E)?;
        e.encode_constrained_whole_number(self.midi_alm_delta_i as i64, &Self::DELTA_I)?;
        e.encode_constrained_whole_number(self.midi_alm_omega_dot as i64, &Self::OMEGA_DOT)?;
        e.encode_constrained_whole_number(self.midi_alm_sqrt_a as i64, &Self::SQRT_A)?;
        e.encode_constrained_whole_number(self.midi_alm_omega0 as i64, &Self::OMEGA0)?;
        e.encode_constrained_whole_number(self.midi_alm_omega as i64, &Self::OMEGA)?;
        e.encode_constrained_whole_number(self.midi_alm_mo as i64, &Self::MO)?;
        e.encode_constrained_whole_number(self.midi_alm_af0 as i64, &Self::AF0)?;
        e.encode_constrained_whole_number(self.midi_alm_af1 as i64, &Self::AF1)?;
        e.write_bit(self.midi_alm_l1_health);
        e.write_bit(self.midi_alm_l2_health);
        e.write_bit(self.midi_alm_l5_health);
        Ok(())
    }
}

impl UperDecode for AlmanacMidiAlmanacSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacMidiAlmanacSet extension additions not supported".into(),
            ));
        }
        Ok(AlmanacMidiAlmanacSet {
            sv_id: SvId::decode_uper(d)?,
            midi_alm_e: d.decode_constrained_whole_number(&Self::E)? as u16,
            midi_alm_delta_i: d.decode_constrained_whole_number(&Self::DELTA_I)? as i16,
            midi_alm_omega_dot: d.decode_constrained_whole_number(&Self::OMEGA_DOT)? as i16,
            midi_alm_sqrt_a: d.decode_constrained_whole_number(&Self::SQRT_A)? as u32,
            midi_alm_omega0: d.decode_constrained_whole_number(&Self::OMEGA0)? as i16,
            midi_alm_omega: d.decode_constrained_whole_number(&Self::OMEGA)? as i16,
            midi_alm_mo: d.decode_constrained_whole_number(&Self::MO)? as i16,
            midi_alm_af0: d.decode_constrained_whole_number(&Self::AF0)? as i16,
            midi_alm_af1: d.decode_constrained_whole_number(&Self::AF1)? as i16,
            midi_alm_l1_health: d.read_bit()?,
            midi_alm_l2_health: d.read_bit()?,
            midi_alm_l5_health: d.read_bit()?,
        })
    }
}

// ===========================================================================
// AlmanacGLONASS-AlmanacSet  -- Model-5 (GLONASS)
// ===========================================================================

/// AlmanacGLONASS-AlmanacSet ::= SEQUENCE {   -- extensible
///     gloAlm-NA        INTEGER (1..1461),
///     gloAlmnA         INTEGER (1..24),
///     gloAlmHA         INTEGER (0..31),
///     gloAlmLambdaA    INTEGER (-1048576..1048575),
///     gloAlmtlambdaA   INTEGER (0..2097151),
///     gloAlmDeltaIa    INTEGER (-131072..131071),
///     gloAlmDeltaTA    INTEGER (-2097152..2097151),
///     gloAlmDeltaTdotA INTEGER (-64..63),
///     gloAlmEpsilonA   INTEGER (0..32767),
///     gloAlmOmegaA     INTEGER (-32768..32767),
///     gloAlmTauA       INTEGER (-512..511),
///     gloAlmCA         INTEGER (0..1),
///     gloAlmMA         BIT STRING (SIZE(2))  OPTIONAL,  -- Need ON
///     ... }
///
/// `gloAlmMA` is a fixed 2-bit BIT STRING held as its 0..3 value (bit0 = MSB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlmanacGlonassAlmanacSet {
    pub glo_alm_na: u16,
    pub glo_alm_n_a: u8,
    pub glo_alm_h_a: u8,
    pub glo_alm_lambda_a: i32,
    pub glo_alm_tlambda_a: u32,
    pub glo_alm_delta_ia: i32,
    pub glo_alm_delta_ta: i32,
    pub glo_alm_delta_tdot_a: i8,
    pub glo_alm_epsilon_a: u16,
    pub glo_alm_omega_a: i16,
    pub glo_alm_tau_a: i16,
    pub glo_alm_c_a: u8,
    pub glo_alm_m_a: Option<u8>,
}

impl AlmanacGlonassAlmanacSet {
    const NA: Constraint = Constraint::new(1, 1461);
    const N_A: Constraint = Constraint::new(1, 24);
    const H_A: Constraint = Constraint::new(0, 31);
    const LAMBDA_A: Constraint = Constraint::new(-1_048_576, 1_048_575);
    const TLAMBDA_A: Constraint = Constraint::new(0, 2_097_151);
    const DELTA_IA: Constraint = Constraint::new(-131_072, 131_071);
    const DELTA_TA: Constraint = Constraint::new(-2_097_152, 2_097_151);
    const DELTA_TDOT_A: Constraint = Constraint::new(-64, 63);
    const EPSILON_A: Constraint = Constraint::new(0, 32767);
    const OMEGA_A: Constraint = Constraint::new(-32768, 32767);
    const TAU_A: Constraint = Constraint::new(-512, 511);
    const C_A: Constraint = Constraint::new(0, 1);
}

impl UperEncode for AlmanacGlonassAlmanacSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, one OPTIONAL root field (gloAlmMA).
        e.encode_sequence_preamble(Some(false), &[self.glo_alm_m_a.is_some()]);
        e.encode_constrained_whole_number(self.glo_alm_na as i64, &Self::NA)?;
        e.encode_constrained_whole_number(self.glo_alm_n_a as i64, &Self::N_A)?;
        e.encode_constrained_whole_number(self.glo_alm_h_a as i64, &Self::H_A)?;
        e.encode_constrained_whole_number(self.glo_alm_lambda_a as i64, &Self::LAMBDA_A)?;
        e.encode_constrained_whole_number(self.glo_alm_tlambda_a as i64, &Self::TLAMBDA_A)?;
        e.encode_constrained_whole_number(self.glo_alm_delta_ia as i64, &Self::DELTA_IA)?;
        e.encode_constrained_whole_number(self.glo_alm_delta_ta as i64, &Self::DELTA_TA)?;
        e.encode_constrained_whole_number(self.glo_alm_delta_tdot_a as i64, &Self::DELTA_TDOT_A)?;
        e.encode_constrained_whole_number(self.glo_alm_epsilon_a as i64, &Self::EPSILON_A)?;
        e.encode_constrained_whole_number(self.glo_alm_omega_a as i64, &Self::OMEGA_A)?;
        e.encode_constrained_whole_number(self.glo_alm_tau_a as i64, &Self::TAU_A)?;
        e.encode_constrained_whole_number(self.glo_alm_c_a as i64, &Self::C_A)?;
        if let Some(m) = self.glo_alm_m_a {
            // Fixed BIT STRING(SIZE(2)): exactly 2 bits, no length prefix.
            e.write_bits((m & 0x3) as u64, 2);
        }
        Ok(())
    }
}

impl UperDecode for AlmanacGlonassAlmanacSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 1)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacGLONASS-AlmanacSet extension additions not supported".into(),
            ));
        }
        let glo_alm_na = d.decode_constrained_whole_number(&Self::NA)? as u16;
        let glo_alm_n_a = d.decode_constrained_whole_number(&Self::N_A)? as u8;
        let glo_alm_h_a = d.decode_constrained_whole_number(&Self::H_A)? as u8;
        let glo_alm_lambda_a = d.decode_constrained_whole_number(&Self::LAMBDA_A)? as i32;
        let glo_alm_tlambda_a = d.decode_constrained_whole_number(&Self::TLAMBDA_A)? as u32;
        let glo_alm_delta_ia = d.decode_constrained_whole_number(&Self::DELTA_IA)? as i32;
        let glo_alm_delta_ta = d.decode_constrained_whole_number(&Self::DELTA_TA)? as i32;
        let glo_alm_delta_tdot_a = d.decode_constrained_whole_number(&Self::DELTA_TDOT_A)? as i8;
        let glo_alm_epsilon_a = d.decode_constrained_whole_number(&Self::EPSILON_A)? as u16;
        let glo_alm_omega_a = d.decode_constrained_whole_number(&Self::OMEGA_A)? as i16;
        let glo_alm_tau_a = d.decode_constrained_whole_number(&Self::TAU_A)? as i16;
        let glo_alm_c_a = d.decode_constrained_whole_number(&Self::C_A)? as u8;
        let glo_alm_m_a = if opts[0] {
            Some(d.read_bits(2)? as u8)
        } else {
            None
        };
        Ok(AlmanacGlonassAlmanacSet {
            glo_alm_na,
            glo_alm_n_a,
            glo_alm_h_a,
            glo_alm_lambda_a,
            glo_alm_tlambda_a,
            glo_alm_delta_ia,
            glo_alm_delta_ta,
            glo_alm_delta_tdot_a,
            glo_alm_epsilon_a,
            glo_alm_omega_a,
            glo_alm_tau_a,
            glo_alm_c_a,
            glo_alm_m_a,
        })
    }
}

// ===========================================================================
// AlmanacECEF-SBAS-AlmanacSet  -- Model-6 (SBAS ECEF)
// ===========================================================================

/// AlmanacECEF-SBAS-AlmanacSet ::= SEQUENCE {   -- extensible
///     sbasAlmDataID INTEGER (0..3),
///     svID          SV-ID,
///     sbasAlmHealth BIT STRING (SIZE(8)),
///     sbasAlmXg     INTEGER (-16384..16383),
///     sbasAlmYg     INTEGER (-16384..16383),
///     sbasAlmZg     INTEGER (-256..255),
///     sbasAlmXgdot  INTEGER (-4..3),
///     sbasAlmYgDot  INTEGER (-4..3),
///     sbasAlmZgDot  INTEGER (-8..7),
///     sbasAlmTo     INTEGER (0..2047),
///     ... }
///
/// `sbasAlmHealth` is a fixed 8-bit BIT STRING held as a byte (bit0 = 0x80 MSB).
#[derive(Debug, Clone, PartialEq)]
pub struct AlmanacEcefSbasAlmanacSet {
    pub sbas_alm_data_id: u8,
    pub sv_id: SvId,
    pub sbas_alm_health: u8,
    pub sbas_alm_xg: i16,
    pub sbas_alm_yg: i16,
    pub sbas_alm_zg: i16,
    pub sbas_alm_xg_dot: i8,
    pub sbas_alm_yg_dot: i8,
    pub sbas_alm_zg_dot: i8,
    pub sbas_alm_to: u16,
}

impl AlmanacEcefSbasAlmanacSet {
    const DATA_ID: Constraint = Constraint::new(0, 3);
    const XG: Constraint = Constraint::new(-16384, 16383);
    const YG: Constraint = Constraint::new(-16384, 16383);
    const ZG: Constraint = Constraint::new(-256, 255);
    const XG_DOT: Constraint = Constraint::new(-4, 3);
    const YG_DOT: Constraint = Constraint::new(-4, 3);
    const ZG_DOT: Constraint = Constraint::new(-8, 7);
    const TO: Constraint = Constraint::new(0, 2047);
}

impl UperEncode for AlmanacEcefSbasAlmanacSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.sbas_alm_data_id as i64, &Self::DATA_ID)?;
        self.sv_id.encode_uper(e)?;
        // Fixed BIT STRING(SIZE(8)): 8 bits, no length prefix.
        e.write_bits(self.sbas_alm_health as u64, 8);
        e.encode_constrained_whole_number(self.sbas_alm_xg as i64, &Self::XG)?;
        e.encode_constrained_whole_number(self.sbas_alm_yg as i64, &Self::YG)?;
        e.encode_constrained_whole_number(self.sbas_alm_zg as i64, &Self::ZG)?;
        e.encode_constrained_whole_number(self.sbas_alm_xg_dot as i64, &Self::XG_DOT)?;
        e.encode_constrained_whole_number(self.sbas_alm_yg_dot as i64, &Self::YG_DOT)?;
        e.encode_constrained_whole_number(self.sbas_alm_zg_dot as i64, &Self::ZG_DOT)?;
        e.encode_constrained_whole_number(self.sbas_alm_to as i64, &Self::TO)?;
        Ok(())
    }
}

impl UperDecode for AlmanacEcefSbasAlmanacSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "AlmanacECEF-SBAS-AlmanacSet extension additions not supported".into(),
            ));
        }
        let sbas_alm_data_id = d.decode_constrained_whole_number(&Self::DATA_ID)? as u8;
        let sv_id = SvId::decode_uper(d)?;
        let sbas_alm_health = d.read_bits(8)? as u8;
        Ok(AlmanacEcefSbasAlmanacSet {
            sbas_alm_data_id,
            sv_id,
            sbas_alm_health,
            sbas_alm_xg: d.decode_constrained_whole_number(&Self::XG)? as i16,
            sbas_alm_yg: d.decode_constrained_whole_number(&Self::YG)? as i16,
            sbas_alm_zg: d.decode_constrained_whole_number(&Self::ZG)? as i16,
            sbas_alm_xg_dot: d.decode_constrained_whole_number(&Self::XG_DOT)? as i8,
            sbas_alm_yg_dot: d.decode_constrained_whole_number(&Self::YG_DOT)? as i8,
            sbas_alm_zg_dot: d.decode_constrained_whole_number(&Self::ZG_DOT)? as i8,
            sbas_alm_to: d.decode_constrained_whole_number(&Self::TO)? as u16,
        })
    }
}

// ===========================================================================
// GNSS-AlmanacElement  -- CHOICE over the six almanac models (extensible)
// ===========================================================================

/// GNSS-AlmanacElement ::= CHOICE {   -- 6 root alternatives, extensible
///     keplerianAlmanacSet      AlmanacKeplerianSet,        -- idx 0, Model-1
///     keplerianNAV-Almanac     AlmanacNAV-KeplerianSet,    -- idx 1, Model-2
///     keplerianReducedAlmanac  AlmanacReducedKeplerianSet, -- idx 2, Model-3
///     keplerianMidiAlmanac     AlmanacMidiAlmanacSet,      -- idx 3, Model-4
///     keplerianGLONASS         AlmanacGLONASS-AlmanacSet,  -- idx 4, Model-5
///     ecef-SBAS-Almanac        AlmanacECEF-SBAS-AlmanacSet,-- idx 5, Model-6
///     ...,
///     [[ keplerianBDS-Almanac-r12 ... ]]  -- DEFERRED (never selected;
///                                         --  rejected on decode) }
#[derive(Debug, Clone, PartialEq)]
pub enum GnssAlmanacElement {
    KeplerianAlmanacSet(AlmanacKeplerianSet),
    KeplerianNavAlmanac(AlmanacNavKeplerianSet),
    KeplerianReducedAlmanac(AlmanacReducedKeplerianSet),
    KeplerianMidiAlmanac(AlmanacMidiAlmanacSet),
    KeplerianGlonass(AlmanacGlonassAlmanacSet),
    EcefSbasAlmanac(AlmanacEcefSbasAlmanacSet),
}

impl GnssAlmanacElement {
    const NUM_ROOT: usize = 6;
}

impl UperEncode for GnssAlmanacElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        match self {
            GnssAlmanacElement::KeplerianAlmanacSet(v) => {
                e.encode_choice_index(0, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
            GnssAlmanacElement::KeplerianNavAlmanac(v) => {
                e.encode_choice_index(1, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
            GnssAlmanacElement::KeplerianReducedAlmanac(v) => {
                e.encode_choice_index(2, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
            GnssAlmanacElement::KeplerianMidiAlmanac(v) => {
                e.encode_choice_index(3, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
            GnssAlmanacElement::KeplerianGlonass(v) => {
                e.encode_choice_index(4, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
            GnssAlmanacElement::EcefSbasAlmanac(v) => {
                e.encode_choice_index(5, Self::NUM_ROOT, true)?;
                v.encode_uper(e)
            }
        }
    }
}

impl UperDecode for GnssAlmanacElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let idx = d.decode_choice_index(Self::NUM_ROOT, true)?;
        match idx {
            0 => Ok(GnssAlmanacElement::KeplerianAlmanacSet(
                AlmanacKeplerianSet::decode_uper(d)?,
            )),
            1 => Ok(GnssAlmanacElement::KeplerianNavAlmanac(
                AlmanacNavKeplerianSet::decode_uper(d)?,
            )),
            2 => Ok(GnssAlmanacElement::KeplerianReducedAlmanac(
                AlmanacReducedKeplerianSet::decode_uper(d)?,
            )),
            3 => Ok(GnssAlmanacElement::KeplerianMidiAlmanac(
                AlmanacMidiAlmanacSet::decode_uper(d)?,
            )),
            4 => Ok(GnssAlmanacElement::KeplerianGlonass(
                AlmanacGlonassAlmanacSet::decode_uper(d)?,
            )),
            5 => Ok(GnssAlmanacElement::EcefSbasAlmanac(
                AlmanacEcefSbasAlmanacSet::decode_uper(d)?,
            )),
            _ => Err(PerError::DecodeError(
                "GNSS-AlmanacElement extension alternative (e.g. keplerianBDS-Almanac-r12) not supported"
                    .into(),
            )),
        }
    }
}

// ===========================================================================
// GNSS-Almanac  -- top-level IE
// ===========================================================================

/// GNSS-Almanac ::= SEQUENCE {   -- extensible
///     weekNumber              INTEGER (0..255) OPTIONAL,  -- Need ON
///     toa                     INTEGER (0..255) OPTIONAL,  -- Need ON
///     ioda                    INTEGER (0..3)   OPTIONAL,  -- Need ON
///     completeAlmanacProvided BOOLEAN,
///     gnss-AlmanacList        GNSS-AlmanacList,           -- SEQUENCE(SIZE(1..64)) OF
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct GnssAlmanac {
    pub week_number: Option<u8>,
    pub toa: Option<u8>,
    pub ioda: Option<u8>,
    pub complete_almanac_provided: bool,
    pub gnss_almanac_list: Vec<GnssAlmanacElement>,
}

impl GnssAlmanac {
    const WEEK_NUMBER: Constraint = Constraint::new(0, 255);
    const TOA: Constraint = Constraint::new(0, 255);
    const IODA: Constraint = Constraint::new(0, 3);
    /// GNSS-AlmanacList ::= SEQUENCE (SIZE(1..64)) OF GNSS-AlmanacElement.
    const LIST_SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for GnssAlmanac {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(
            Some(false),
            &[
                self.week_number.is_some(),
                self.toa.is_some(),
                self.ioda.is_some(),
            ],
        );
        if let Some(w) = self.week_number {
            e.encode_constrained_whole_number(w as i64, &Self::WEEK_NUMBER)?;
        }
        if let Some(t) = self.toa {
            e.encode_constrained_whole_number(t as i64, &Self::TOA)?;
        }
        if let Some(i) = self.ioda {
            e.encode_constrained_whole_number(i as i64, &Self::IODA)?;
        }
        e.write_bit(self.complete_almanac_provided);
        // GNSS-AlmanacList: constrained SIZE(1..64) count, then each element.
        let count = self.gnss_almanac_list.len();
        if !(1..=64).contains(&count) {
            return Err(PerError::InvalidLength { length: count });
        }
        e.encode_constrained_whole_number(count as i64, &Self::LIST_SIZE)?;
        for elem in &self.gnss_almanac_list {
            elem.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssAlmanac {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 3)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-Almanac extension additions not supported".into(),
            ));
        }
        let week_number = if opts[0] {
            Some(d.decode_constrained_whole_number(&Self::WEEK_NUMBER)? as u8)
        } else {
            None
        };
        let toa = if opts[1] {
            Some(d.decode_constrained_whole_number(&Self::TOA)? as u8)
        } else {
            None
        };
        let ioda = if opts[2] {
            Some(d.decode_constrained_whole_number(&Self::IODA)? as u8)
        } else {
            None
        };
        let complete_almanac_provided = d.read_bit()?;
        let count = d.decode_constrained_whole_number(&Self::LIST_SIZE)? as usize;
        let mut gnss_almanac_list = Vec::with_capacity(count);
        for _ in 0..count {
            gnss_almanac_list.push(GnssAlmanacElement::decode_uper(d)?);
        }
        Ok(GnssAlmanac {
            week_number,
            toa,
            ioda,
            complete_almanac_provided,
            gnss_almanac_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uper::{UperDecoder, UperEncoder};

    fn sv(id: u8) -> SvId {
        SvId { satellite_id: id }
    }

    fn kep() -> AlmanacKeplerianSet {
        AlmanacKeplerianSet {
            sv_id: sv(1),
            kep_almanac_e: 2047,
            kep_almanac_delta_i: -1024,
            kep_almanac_omega_dot: 1023,
            kep_sv_health: 15,
            kep_almanac_a_power_half: -65536,
            kep_almanac_omega0: -32768,
            kep_almanac_w: 32767,
            kep_almanac_m0: -1,
            kep_almanac_af0: -8192,
            kep_almanac_af1: 1023,
        }
    }

    fn nav() -> AlmanacNavKeplerianSet {
        AlmanacNavKeplerianSet {
            sv_id: sv(2),
            nav_alm_e: 65535,
            nav_alm_delta_i: -32768,
            nav_alm_omega_dot: 32767,
            nav_alm_sv_health: 255,
            nav_alm_sqrt_a: 16_777_215,
            nav_alm_omega_o: -8_388_608,
            nav_alm_omega: 8_388_607,
            nav_alm_mo: 0,
            nav_alm_af0: -1024,
            nav_alm_af1: 1023,
        }
    }

    fn reduced() -> AlmanacReducedKeplerianSet {
        AlmanacReducedKeplerianSet {
            sv_id: sv(3),
            red_alm_delta_a: -128,
            red_alm_omega0: 63,
            red_alm_phi0: -64,
            red_alm_l1_health: true,
            red_alm_l2_health: false,
            red_alm_l5_health: true,
        }
    }

    fn midi() -> AlmanacMidiAlmanacSet {
        AlmanacMidiAlmanacSet {
            sv_id: sv(4),
            midi_alm_e: 2047,
            midi_alm_delta_i: -1024,
            midi_alm_omega_dot: 1023,
            midi_alm_sqrt_a: 131_071,
            midi_alm_omega0: -32768,
            midi_alm_omega: 32767,
            midi_alm_mo: 5,
            midi_alm_af0: -1024,
            midi_alm_af1: -512,
            midi_alm_l1_health: false,
            midi_alm_l2_health: true,
            midi_alm_l5_health: false,
        }
    }

    fn glonass(with_m: bool) -> AlmanacGlonassAlmanacSet {
        AlmanacGlonassAlmanacSet {
            glo_alm_na: 1461,
            glo_alm_n_a: 24,
            glo_alm_h_a: 31,
            glo_alm_lambda_a: -1_048_576,
            glo_alm_tlambda_a: 2_097_151,
            glo_alm_delta_ia: -131_072,
            glo_alm_delta_ta: 2_097_151,
            glo_alm_delta_tdot_a: -64,
            glo_alm_epsilon_a: 32767,
            glo_alm_omega_a: -32768,
            glo_alm_tau_a: 511,
            glo_alm_c_a: 1,
            glo_alm_m_a: if with_m { Some(3) } else { None },
        }
    }

    fn sbas() -> AlmanacEcefSbasAlmanacSet {
        AlmanacEcefSbasAlmanacSet {
            sbas_alm_data_id: 3,
            sv_id: sv(5),
            sbas_alm_health: 0xA5,
            sbas_alm_xg: -16384,
            sbas_alm_yg: 16383,
            sbas_alm_zg: -256,
            sbas_alm_xg_dot: -4,
            sbas_alm_yg_dot: 3,
            sbas_alm_zg_dot: -8,
            sbas_alm_to: 2047,
        }
    }

    fn rt_element(elem: &GnssAlmanacElement) {
        let mut enc = UperEncoder::new();
        elem.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let got = GnssAlmanacElement::decode_uper(&mut dec).unwrap();
        assert_eq!(&got, elem);
    }

    #[test]
    fn round_trip_each_element_variant() {
        rt_element(&GnssAlmanacElement::KeplerianAlmanacSet(kep()));
        rt_element(&GnssAlmanacElement::KeplerianNavAlmanac(nav()));
        rt_element(&GnssAlmanacElement::KeplerianReducedAlmanac(reduced()));
        rt_element(&GnssAlmanacElement::KeplerianMidiAlmanac(midi()));
        rt_element(&GnssAlmanacElement::KeplerianGlonass(glonass(true)));
        rt_element(&GnssAlmanacElement::KeplerianGlonass(glonass(false)));
        rt_element(&GnssAlmanacElement::EcefSbasAlmanac(sbas()));
    }

    #[test]
    fn round_trip_gnss_almanac_full() {
        let original = GnssAlmanac {
            week_number: Some(200),
            toa: Some(255),
            ioda: Some(3),
            complete_almanac_provided: true,
            gnss_almanac_list: vec![
                GnssAlmanacElement::KeplerianAlmanacSet(kep()),
                GnssAlmanacElement::KeplerianNavAlmanac(nav()),
                GnssAlmanacElement::KeplerianReducedAlmanac(reduced()),
                GnssAlmanacElement::KeplerianMidiAlmanac(midi()),
                GnssAlmanacElement::KeplerianGlonass(glonass(true)),
                GnssAlmanacElement::EcefSbasAlmanac(sbas()),
            ],
        };
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssAlmanac::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_gnss_almanac_optionals_absent() {
        let original = GnssAlmanac {
            week_number: None,
            toa: None,
            ioda: None,
            complete_almanac_provided: false,
            gnss_almanac_list: vec![GnssAlmanacElement::KeplerianGlonass(glonass(false))],
        };
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssAlmanac::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }
}
