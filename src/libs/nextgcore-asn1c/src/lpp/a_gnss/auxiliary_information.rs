//! GNSS-AuxiliaryInformation assistance-data IE (3GPP TS 37.355 §6.5.2.10), UPER.
//!
//! The IE carries GNSS-system-specific satellite auxiliary information (which
//! signals are available per SV, and — for GLONASS FDMA — the frequency channel
//! number). It is a CHOICE selecting one GNSS system's per-satellite list.
//!
//! ASN.1 (TS 37.355):
//! ```text
//! GNSS-AuxiliaryInformation ::= CHOICE {
//!     gnss-ID-GPS         GNSS-ID-GPS,
//!     gnss-ID-GLONASS     GNSS-ID-GLONASS,
//!     ...,
//!     [[ gnss-ID-BDS-r16  GNSS-ID-BDS-r16 ]]
//! }
//!
//! GNSS-ID-GPS ::= SEQUENCE (SIZE(1..64)) OF GNSS-ID-GPS-SatElement
//! GNSS-ID-GPS-SatElement ::= SEQUENCE {
//!     svID                SV-ID,
//!     signalsAvailable    GNSS-SignalIDs,
//!     ...
//! }
//!
//! GNSS-ID-GLONASS ::= SEQUENCE (SIZE(1..64)) OF GNSS-ID-GLONASS-SatElement
//! GNSS-ID-GLONASS-SatElement ::= SEQUENCE {
//!     svID                SV-ID,
//!     signalsAvailable    GNSS-SignalIDs,
//!     channelNumber       INTEGER (-7..13) OPTIONAL,  -- Cond FDMA
//!     ...
//! }
//!
//! GNSS-ID-BDS-r16 ::= SEQUENCE (SIZE(1..64)) OF GNSS-ID-BDS-SatElement-r16
//! ```
//!
//! Scope: both root alternatives (`gnss-ID-GPS`, `gnss-ID-GLONASS`) are modeled
//! at full bit fidelity. The `gnss-ID-BDS-r16` extension alternative is DEFERRED
//! (never emitted; a peer selecting it is rejected on decode).

use super::common::{GnssSignalIds, SvId};
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// SIZE(1..64) constraint shared by the per-system `SEQUENCE OF` satellite lists.
const SAT_LIST_SIZE: Constraint = Constraint::new(1, 64);

/// GNSS-ID-GPS-SatElement ::= SEQUENCE {
///     svID             SV-ID,
///     signalsAvailable GNSS-SignalIDs,
///     ... }
///
/// Extensible SEQUENCE with no root OPTIONAL fields (1 preamble bit: the
/// extension marker, always 0 on encode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssIdGpsSatElement {
    pub sv_id: SvId,
    pub signals_available: GnssSignalIds,
}

impl UperEncode for GnssIdGpsSatElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        self.signals_available.encode_uper(e)
    }
}

impl UperDecode for GnssIdGpsSatElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-ID-GPS-SatElement extension additions not supported".into(),
            ));
        }
        let sv_id = SvId::decode_uper(d)?;
        let signals_available = GnssSignalIds::decode_uper(d)?;
        Ok(GnssIdGpsSatElement {
            sv_id,
            signals_available,
        })
    }
}

/// GNSS-ID-GLONASS-SatElement ::= SEQUENCE {
///     svID             SV-ID,
///     signalsAvailable GNSS-SignalIDs,
///     channelNumber    INTEGER (-7..13) OPTIONAL,  -- Cond FDMA
///     ... }
///
/// Extensible SEQUENCE with one root OPTIONAL (`channelNumber`): 1 extension bit
/// + 1 optional-presence bit of preamble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssIdGlonassSatElement {
    pub sv_id: SvId,
    pub signals_available: GnssSignalIds,
    /// GLONASS FDMA frequency channel number, INTEGER(-7..13). Present only for
    /// FDMA signals (spec: "Cond FDMA").
    pub channel_number: Option<i8>,
}

impl GnssIdGlonassSatElement {
    const CHANNEL_NUMBER: Constraint = Constraint::new(-7, 13);
}

impl UperEncode for GnssIdGlonassSatElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[self.channel_number.is_some()]);
        self.sv_id.encode_uper(e)?;
        self.signals_available.encode_uper(e)?;
        if let Some(ch) = self.channel_number {
            e.encode_constrained_whole_number(ch as i64, &Self::CHANNEL_NUMBER)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssIdGlonassSatElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 1)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-ID-GLONASS-SatElement extension additions not supported".into(),
            ));
        }
        let sv_id = SvId::decode_uper(d)?;
        let signals_available = GnssSignalIds::decode_uper(d)?;
        let channel_number = if opts[0] {
            Some(d.decode_constrained_whole_number(&Self::CHANNEL_NUMBER)? as i8)
        } else {
            None
        };
        Ok(GnssIdGlonassSatElement {
            sv_id,
            signals_available,
            channel_number,
        })
    }
}

/// GNSS-AuxiliaryInformation ::= CHOICE {
///     gnss-ID-GPS      GNSS-ID-GPS,       -- SEQUENCE (SIZE(1..64)) OF GNSS-ID-GPS-SatElement
///     gnss-ID-GLONASS  GNSS-ID-GLONASS,   -- SEQUENCE (SIZE(1..64)) OF GNSS-ID-GLONASS-SatElement
///     ...,
///     [[ gnss-ID-BDS-r16 GNSS-ID-BDS-r16 ]] }
///
/// Extensible CHOICE with 2 root alternatives. The `gnss-ID-BDS-r16` extension
/// alternative is DEFERRED: never emitted, and rejected on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GnssAuxiliaryInformation {
    /// gnss-ID-GPS: SEQUENCE (SIZE(1..64)) OF GNSS-ID-GPS-SatElement.
    GnssIdGps(Vec<GnssIdGpsSatElement>),
    /// gnss-ID-GLONASS: SEQUENCE (SIZE(1..64)) OF GNSS-ID-GLONASS-SatElement.
    GnssIdGlonass(Vec<GnssIdGlonassSatElement>),
}

impl UperEncode for GnssAuxiliaryInformation {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        match self {
            GnssAuxiliaryInformation::GnssIdGps(list) => {
                e.encode_choice_index(0, 2, true)?;
                e.encode_constrained_whole_number(list.len() as i64, &SAT_LIST_SIZE)?;
                for el in list {
                    el.encode_uper(e)?;
                }
            }
            GnssAuxiliaryInformation::GnssIdGlonass(list) => {
                e.encode_choice_index(1, 2, true)?;
                e.encode_constrained_whole_number(list.len() as i64, &SAT_LIST_SIZE)?;
                for el in list {
                    el.encode_uper(e)?;
                }
            }
        }
        Ok(())
    }
}

impl UperDecode for GnssAuxiliaryInformation {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let idx = d.decode_choice_index(2, true)?;
        match idx {
            0 => {
                let count = d.decode_constrained_whole_number(&SAT_LIST_SIZE)? as usize;
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    list.push(GnssIdGpsSatElement::decode_uper(d)?);
                }
                Ok(GnssAuxiliaryInformation::GnssIdGps(list))
            }
            1 => {
                let count = d.decode_constrained_whole_number(&SAT_LIST_SIZE)? as usize;
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    list.push(GnssIdGlonassSatElement::decode_uper(d)?);
                }
                Ok(GnssAuxiliaryInformation::GnssIdGlonass(list))
            }
            // Extension alternative gnss-ID-BDS-r16 (and any future additions).
            _ => Err(PerError::DecodeError(
                "GNSS-AuxiliaryInformation extension alternative (gnss-ID-BDS-r16) not supported"
                    .into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_gps() {
        let original = GnssAuxiliaryInformation::GnssIdGps(vec![
            GnssIdGpsSatElement {
                sv_id: SvId { satellite_id: 0 },
                signals_available: GnssSignalIds { signals: 0x80 },
            },
            GnssIdGpsSatElement {
                sv_id: SvId { satellite_id: 63 },
                signals_available: GnssSignalIds { signals: 0xC1 },
            },
        ]);

        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssAuxiliaryInformation::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_glonass() {
        let original = GnssAuxiliaryInformation::GnssIdGlonass(vec![
            GnssIdGlonassSatElement {
                sv_id: SvId { satellite_id: 12 },
                signals_available: GnssSignalIds { signals: 0x40 },
                channel_number: Some(-7),
            },
            GnssIdGlonassSatElement {
                sv_id: SvId { satellite_id: 5 },
                signals_available: GnssSignalIds { signals: 0x20 },
                channel_number: Some(13),
            },
            GnssIdGlonassSatElement {
                sv_id: SvId { satellite_id: 30 },
                signals_available: GnssSignalIds { signals: 0x10 },
                channel_number: None,
            },
        ]);

        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssAuxiliaryInformation::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }
}
