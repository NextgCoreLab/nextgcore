//! LPP A-GNSS `GNSS-ReferenceLocation` assistance-data IE (3GPP TS 37.355
//! §6.5.2), UNALIGNED PER, LMF -> UE.
//!
//! `GNSS-ReferenceLocation` gives the a-priori 3-D reference position used to
//! seed the target's GNSS acquisition search. It is a single-field extensible
//! SEQUENCE wrapping an `EllipsoidPointWithAltitudeAndUncertaintyEllipsoid`
//! (TS 37.355 §6.5.2 / the LPP common location shapes, aligned with
//! TS 36.355 §7 and 3GPP TS 23.032):
//!
//! ```text
//! GNSS-ReferenceLocation ::= SEQUENCE {
//!     threeDlocation   EllipsoidPointWithAltitudeAndUncertaintyEllipsoid,
//!     ...
//! }
//!
//! EllipsoidPointWithAltitudeAndUncertaintyEllipsoid ::= SEQUENCE {
//!     latitudeSign          ENUMERATED { north, south },
//!     degreesLatitude       INTEGER (0..8388607),          -- 23-bit field
//!     degreesLongitude      INTEGER (-8388608..8388607),   -- 24-bit field
//!     altitudeDirection     ENUMERATED { height, depth },
//!     altitude              INTEGER (0..32767),            -- 15-bit field
//!     uncertaintySemiMajor  INTEGER (0..127),
//!     uncertaintySemiMinor  INTEGER (0..127),
//!     orientationMajorAxis  INTEGER (0..179),
//!     uncertaintyAltitude   INTEGER (0..127),
//!     confidence            INTEGER (0..100)
//! }
//! ```
//!
//! Every field is a primary field and is encoded at full bit-fidelity; there
//! are no OPTIONAL or extension sub-options to defer inside
//! `EllipsoidPointWithAltitudeAndUncertaintyEllipsoid` (it is a NON-extensible
//! SEQUENCE with all-mandatory fields). The only deferral is the outer
//! `GNSS-ReferenceLocation` extension marker (`...`): additions beyond the root
//! are rejected on decode.

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// latitudeSign / altitudeDirection ENUMERATEDs (2 values, NON-extensible)
// ---------------------------------------------------------------------------

/// `latitudeSign ::= ENUMERATED { north, south }` (TS 37.355 §6.5.2).
///
/// Two-value, non-extensible ENUMERATED encoded as a constrained index over
/// `0..1` (a single bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatitudeSign {
    North = 0,
    South = 1,
}

/// `altitudeDirection ::= ENUMERATED { height, depth }` (TS 37.355 §6.5.2).
///
/// Two-value, non-extensible ENUMERATED encoded as a constrained index over
/// `0..1` (a single bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltitudeDirection {
    Height = 0,
    Depth = 1,
}

// ---------------------------------------------------------------------------
// EllipsoidPointWithAltitudeAndUncertaintyEllipsoid
// ---------------------------------------------------------------------------

/// `EllipsoidPointWithAltitudeAndUncertaintyEllipsoid ::= SEQUENCE { ... }`
/// (TS 37.355 §6.5.2, mirroring TS 23.032 §6). NON-extensible SEQUENCE with
/// ten mandatory fields and no OPTIONALs, so it contributes no preamble bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
    pub latitude_sign: LatitudeSign,
    /// INTEGER (0..8388607) — 23-bit degreesLatitude.
    pub degrees_latitude: u32,
    /// INTEGER (-8388608..8388607) — 24-bit signed degreesLongitude.
    pub degrees_longitude: i32,
    pub altitude_direction: AltitudeDirection,
    /// INTEGER (0..32767) — 15-bit altitude.
    pub altitude: u16,
    /// INTEGER (0..127) — encoded uncertainty semi-major axis.
    pub uncertainty_semi_major: u8,
    /// INTEGER (0..127) — encoded uncertainty semi-minor axis.
    pub uncertainty_semi_minor: u8,
    /// INTEGER (0..179) — orientation of the semi-major axis.
    pub orientation_major_axis: u8,
    /// INTEGER (0..127) — encoded altitude uncertainty.
    pub uncertainty_altitude: u8,
    /// INTEGER (0..100) — confidence level (percent).
    pub confidence: u8,
}

impl EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
    const SIGN: Constraint = Constraint::new(0, 1);
    const DEGREES_LATITUDE: Constraint = Constraint::new(0, 8_388_607);
    const DEGREES_LONGITUDE: Constraint = Constraint::new(-8_388_608, 8_388_607);
    const ALTITUDE: Constraint = Constraint::new(0, 32_767);
    const UNCERTAINTY: Constraint = Constraint::new(0, 127);
    const ORIENTATION: Constraint = Constraint::new(0, 179);
    const CONFIDENCE: Constraint = Constraint::new(0, 100);
}

impl UperEncode for EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // NON-extensible SEQUENCE, no OPTIONAL root fields -> no preamble bits.
        e.encode_sequence_preamble(None, &[]);
        e.encode_enumerated(self.latitude_sign as i64, &Self::SIGN)?;
        e.encode_constrained_whole_number(self.degrees_latitude as i64, &Self::DEGREES_LATITUDE)?;
        e.encode_constrained_whole_number(self.degrees_longitude as i64, &Self::DEGREES_LONGITUDE)?;
        e.encode_enumerated(self.altitude_direction as i64, &Self::SIGN)?;
        e.encode_constrained_whole_number(self.altitude as i64, &Self::ALTITUDE)?;
        e.encode_constrained_whole_number(self.uncertainty_semi_major as i64, &Self::UNCERTAINTY)?;
        e.encode_constrained_whole_number(self.uncertainty_semi_minor as i64, &Self::UNCERTAINTY)?;
        e.encode_constrained_whole_number(self.orientation_major_axis as i64, &Self::ORIENTATION)?;
        e.encode_constrained_whole_number(self.uncertainty_altitude as i64, &Self::UNCERTAINTY)?;
        e.encode_constrained_whole_number(self.confidence as i64, &Self::CONFIDENCE)?;
        Ok(())
    }
}

impl UperDecode for EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, _opts) = d.decode_sequence_preamble(false, 0)?;
        let latitude_sign = match d.decode_enumerated(&Self::SIGN)? {
            0 => LatitudeSign::North,
            _ => LatitudeSign::South,
        };
        let degrees_latitude = d.decode_constrained_whole_number(&Self::DEGREES_LATITUDE)? as u32;
        let degrees_longitude = d.decode_constrained_whole_number(&Self::DEGREES_LONGITUDE)? as i32;
        let altitude_direction = match d.decode_enumerated(&Self::SIGN)? {
            0 => AltitudeDirection::Height,
            _ => AltitudeDirection::Depth,
        };
        let altitude = d.decode_constrained_whole_number(&Self::ALTITUDE)? as u16;
        let uncertainty_semi_major = d.decode_constrained_whole_number(&Self::UNCERTAINTY)? as u8;
        let uncertainty_semi_minor = d.decode_constrained_whole_number(&Self::UNCERTAINTY)? as u8;
        let orientation_major_axis = d.decode_constrained_whole_number(&Self::ORIENTATION)? as u8;
        let uncertainty_altitude = d.decode_constrained_whole_number(&Self::UNCERTAINTY)? as u8;
        let confidence = d.decode_constrained_whole_number(&Self::CONFIDENCE)? as u8;
        Ok(EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
            latitude_sign,
            degrees_latitude,
            degrees_longitude,
            altitude_direction,
            altitude,
            uncertainty_semi_major,
            uncertainty_semi_minor,
            orientation_major_axis,
            uncertainty_altitude,
            confidence,
        })
    }
}

// ---------------------------------------------------------------------------
// GNSS-ReferenceLocation
// ---------------------------------------------------------------------------

/// `GNSS-ReferenceLocation ::= SEQUENCE { threeDlocation ..., ... }`
/// (TS 37.355 §6.5.2). EXTENSIBLE SEQUENCE with a single mandatory field, so it
/// contributes only the extension-marker bit (no OPTIONAL presence bits).
///
/// DEFERRED: any extension addition beyond the root (the trailing `...`) is
/// UNSUPPORTED — never emitted, and rejected on decode if a peer sets the
/// extension bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GnssReferenceLocation {
    pub three_d_location: EllipsoidPointWithAltitudeAndUncertaintyEllipsoid,
}

impl UperEncode for GnssReferenceLocation {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // EXTENSIBLE SEQUENCE, no OPTIONAL root fields: extension bit = 0.
        e.encode_sequence_preamble(Some(false), &[]);
        self.three_d_location.encode_uper(e)
    }
}

impl UperDecode for GnssReferenceLocation {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-ReferenceLocation extension additions not supported".into(),
            ));
        }
        let three_d_location = EllipsoidPointWithAltitudeAndUncertaintyEllipsoid::decode_uper(d)?;
        Ok(GnssReferenceLocation { three_d_location })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnss_reference_location_round_trip() {
        let original = GnssReferenceLocation {
            three_d_location: EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
                latitude_sign: LatitudeSign::North,
                degrees_latitude: 4_194_303,
                degrees_longitude: -12_345,
                altitude_direction: AltitudeDirection::Height,
                altitude: 20_000,
                uncertainty_semi_major: 42,
                uncertainty_semi_minor: 17,
                orientation_major_axis: 179,
                uncertainty_altitude: 63,
                confidence: 95,
            },
        };

        let mut encoder = UperEncoder::new();
        original.encode_uper(&mut encoder).unwrap();
        let bytes = encoder.into_bytes();

        let mut decoder = UperDecoder::new(&bytes);
        let decoded = GnssReferenceLocation::decode_uper(&mut decoder).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn ellipsoid_point_extremes_round_trip() {
        let original = EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
            latitude_sign: LatitudeSign::South,
            degrees_latitude: 8_388_607,
            degrees_longitude: -8_388_608,
            altitude_direction: AltitudeDirection::Depth,
            altitude: 32_767,
            uncertainty_semi_major: 127,
            uncertainty_semi_minor: 0,
            orientation_major_axis: 0,
            uncertainty_altitude: 127,
            confidence: 100,
        };

        let mut encoder = UperEncoder::new();
        original.encode_uper(&mut encoder).unwrap();
        let bytes = encoder.into_bytes();

        let mut decoder = UperDecoder::new(&bytes);
        let decoded =
            EllipsoidPointWithAltitudeAndUncertaintyEllipsoid::decode_uper(&mut decoder).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_unsupported_extension() {
        // Extension bit set -> additions present -> must be rejected.
        let mut encoder = UperEncoder::new();
        encoder.write_bit(true);
        let bytes = encoder.into_bytes();
        let mut decoder = UperDecoder::new(&bytes);
        assert!(GnssReferenceLocation::decode_uper(&mut decoder).is_err());
    }
}
