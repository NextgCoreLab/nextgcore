//! LPP A-GNSS Earth Orientation Parameters (3GPP TS 37.355 §6.5.2), UPER.
//!
//! `GNSS-EarthOrientationParameters` carries the Earth Orientation Parameters
//! (EOP) the location server provides so the target can construct the ECEF
//! (Earth-Centered-Earth-Fixed) <-> ECI (Earth-Centered-Inertial) coordinate
//! transformation. It describes the relationship between the Earth's rotational
//! axis and the WGS-84 reference system (polar motion + UT1-UTC offset & drift).
//!
//! This IE is one of the `GNSS-CommonAssistData` members
//! ([`super::common::GnssCommonAssistData::gnss_earth_orientation_parameters`]).
//!
//! Encoding is X.691 UNALIGNED PER (LPP is specified with the UNALIGNED
//! variant), riding the shared [`crate::uper`] codepath in NRPPa/LPP house
//! style: a per-field `Constraint` const plus a hand-written
//! `UperEncode`/`UperDecode`.

use crate::per::{Constraint, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// GNSS-EarthOrientationParameters ::= SEQUENCE {   -- EXTENSIBLE
///     teop        INTEGER (0..65535),
///     pmX         INTEGER (-1048576..1048575),
///     pmXdot      INTEGER (-16384..16383),
///     pmY         INTEGER (-1048576..1048575),
///     pmYdot      INTEGER (-16384..16383),
///     deltaUT1    INTEGER (-1073741824..1073741823),
///     deltaUT1dot INTEGER (-262144..262143),
///     ...
/// }
///
/// (TS 37.355 §6.5.2.7, verbatim ranges from the LPP-PDU-Definitions module.)
///
/// Field semantics (informative): `teop` is the EOP data reference time
/// (scale 2^4 s); `pmX`/`pmY` are polar-motion values (scale 2^-20 arc-sec) and
/// `pmXdot`/`pmYdot` their drifts (scale 2^-21 arc-sec/day); `deltaUT1` is the
/// UT1-UTC difference (scale 2^-24 s) and `deltaUT1dot` its rate (scale
/// 2^-25 s/day).
///
/// All seven root fields are mandatory (no OPTIONAL members). The SEQUENCE is
/// extensible ("..."); no extension additions are defined at the primary
/// release captured here — none are emitted, and any a newer peer appends are
/// discarded on decode for forward-compatibility (documented at the `ext` gate
/// below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GnssEarthOrientationParameters {
    /// teop INTEGER (0..65535)
    pub teop: u16,
    /// pmX INTEGER (-1048576..1048575)
    pub pm_x: i32,
    /// pmXdot INTEGER (-16384..16383)
    pub pm_x_dot: i16,
    /// pmY INTEGER (-1048576..1048575)
    pub pm_y: i32,
    /// pmYdot INTEGER (-16384..16383)
    pub pm_y_dot: i16,
    /// deltaUT1 INTEGER (-1073741824..1073741823)
    pub delta_ut1: i32,
    /// deltaUT1dot INTEGER (-262144..262143)
    pub delta_ut1_dot: i32,
}

impl GnssEarthOrientationParameters {
    const TEOP: Constraint = Constraint::new(0, 65535);
    const PM_X: Constraint = Constraint::new(-1_048_576, 1_048_575);
    const PM_X_DOT: Constraint = Constraint::new(-16_384, 16_383);
    const PM_Y: Constraint = Constraint::new(-1_048_576, 1_048_575);
    const PM_Y_DOT: Constraint = Constraint::new(-16_384, 16_383);
    const DELTA_UT1: Constraint = Constraint::new(-1_073_741_824, 1_073_741_823);
    const DELTA_UT1_DOT: Constraint = Constraint::new(-262_144, 262_143);
}

impl UperEncode for GnssEarthOrientationParameters {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no OPTIONAL root fields, no extension additions
        // emitted (primary-release fidelity).
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(self.teop as i64, &Self::TEOP)?;
        encoder.encode_constrained_whole_number(self.pm_x as i64, &Self::PM_X)?;
        encoder.encode_constrained_whole_number(self.pm_x_dot as i64, &Self::PM_X_DOT)?;
        encoder.encode_constrained_whole_number(self.pm_y as i64, &Self::PM_Y)?;
        encoder.encode_constrained_whole_number(self.pm_y_dot as i64, &Self::PM_Y_DOT)?;
        encoder.encode_constrained_whole_number(self.delta_ut1 as i64, &Self::DELTA_UT1)?;
        encoder.encode_constrained_whole_number(self.delta_ut1_dot as i64, &Self::DELTA_UT1_DOT)?;
        Ok(())
    }
}

impl UperDecode for GnssEarthOrientationParameters {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let teop = decoder.decode_constrained_whole_number(&Self::TEOP)? as u16;
        let pm_x = decoder.decode_constrained_whole_number(&Self::PM_X)? as i32;
        let pm_x_dot = decoder.decode_constrained_whole_number(&Self::PM_X_DOT)? as i16;
        let pm_y = decoder.decode_constrained_whole_number(&Self::PM_Y)? as i32;
        let pm_y_dot = decoder.decode_constrained_whole_number(&Self::PM_Y_DOT)? as i16;
        let delta_ut1 = decoder.decode_constrained_whole_number(&Self::DELTA_UT1)? as i32;
        let delta_ut1_dot = decoder.decode_constrained_whole_number(&Self::DELTA_UT1_DOT)? as i32;
        if ext {
            // Forward-compat: a newer peer added extension additions past the
            // "..." marker. None are defined in this primary release, so discard
            // them rather than fail (mirrors the LPP envelope house pattern).
            decoder.decode_extension_additions()?;
        }
        Ok(GnssEarthOrientationParameters {
            teop,
            pm_x,
            pm_x_dot,
            pm_y,
            pm_y_dot,
            delta_ut1,
            delta_ut1_dot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: &GnssEarthOrientationParameters) {
        let mut enc = UperEncoder::new();
        value.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssEarthOrientationParameters::decode_uper(&mut dec).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn rt_gnss_earth_orientation_parameters() {
        // Nominal mid-range value.
        roundtrip(&GnssEarthOrientationParameters {
            teop: 12345,
            pm_x: 100_000,
            pm_x_dot: -200,
            pm_y: -100_000,
            pm_y_dot: 200,
            delta_ut1: 500_000,
            delta_ut1_dot: -1000,
        });

        // All-zero.
        roundtrip(&GnssEarthOrientationParameters {
            teop: 0,
            pm_x: 0,
            pm_x_dot: 0,
            pm_y: 0,
            pm_y_dot: 0,
            delta_ut1: 0,
            delta_ut1_dot: 0,
        });

        // Lower bounds of every constrained range.
        roundtrip(&GnssEarthOrientationParameters {
            teop: 0,
            pm_x: -1_048_576,
            pm_x_dot: -16_384,
            pm_y: -1_048_576,
            pm_y_dot: -16_384,
            delta_ut1: -1_073_741_824,
            delta_ut1_dot: -262_144,
        });

        // Upper bounds of every constrained range.
        roundtrip(&GnssEarthOrientationParameters {
            teop: 65_535,
            pm_x: 1_048_575,
            pm_x_dot: 16_383,
            pm_y: 1_048_575,
            pm_y_dot: 16_383,
            delta_ut1: 1_073_741_823,
            delta_ut1_dot: 262_143,
        });
    }
}
