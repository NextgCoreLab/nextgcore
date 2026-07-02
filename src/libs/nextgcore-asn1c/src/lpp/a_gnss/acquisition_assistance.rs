//! LPP A-GNSS acquisition-assistance body (3GPP TS 37.355 §6.5.2), UPER.
//!
//! The location-server-provided `GNSS-AcquisitionAssistance` IE and its list of
//! per-satellite `GNSS-AcquisitionAssistElement` entries. These parameters let
//! the target device predict Doppler / code-phase / azimuth-elevation search
//! windows for fast GNSS-signal acquisition at the reference time.
//!
//! Verbatim ASN.1 (TS 37.355 v16.1.0, §6.5.2):
//!
//! ```text
//! GNSS-AcquisitionAssistance ::= SEQUENCE {
//!     gnss-SignalID               GNSS-SignalID,
//!     gnss-AcquisitionAssistList  GNSS-AcquisitionAssistList,
//!     ...,
//!     confidence-r10              INTEGER (0..100)   OPTIONAL   -- Need ON
//! }
//!
//! GNSS-AcquisitionAssistList ::= SEQUENCE (SIZE(1..64)) OF GNSS-AcquisitionAssistElement
//!
//! GNSS-AcquisitionAssistElement ::= SEQUENCE {
//!     svID                        SV-ID,
//!     doppler0                    INTEGER (-2048..2047),
//!     doppler1                    INTEGER (0..63),
//!     dopplerUncertainty          INTEGER (0..4),
//!     codePhase                   INTEGER (0..1022),
//!     intCodePhase                INTEGER (0..127),
//!     codePhaseSearchWindow       INTEGER (0..31),
//!     azimuth                     INTEGER (0..511),
//!     elevation                   INTEGER (0..127),
//!     ...,
//!     codePhase1023               BOOLEAN   OPTIONAL,   -- Need OP
//!     dopplerUncertaintyExt-r10   ENUMERATED { d60, d80, d100, d120, noInformation, ... } OPTIONAL
//! }
//! ```
//!
//! BOUNDED v1: every ROOT field is modeled at full bit-fidelity. The r10
//! extension additions are DEFERRED (never emitted; decode-error if a peer
//! sets the SEQUENCE extension bit):
//!   * `GNSS-AcquisitionAssistance`  → `confidence-r10`
//!   * `GNSS-AcquisitionAssistElement` → `codePhase1023`, `dopplerUncertaintyExt-r10`
//!
//! Each deferral is documented inline at its encode/decode site.

use super::common::{GnssSignalId, SvId};
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// GNSS-AcquisitionAssistElement
// ---------------------------------------------------------------------------

/// GNSS-AcquisitionAssistElement ::= SEQUENCE {     -- extensible
///     svID                  SV-ID,
///     doppler0              INTEGER (-2048..2047),
///     doppler1              INTEGER (0..63),
///     dopplerUncertainty    INTEGER (0..4),
///     codePhase             INTEGER (0..1022),
///     intCodePhase          INTEGER (0..127),
///     codePhaseSearchWindow INTEGER (0..31),
///     azimuth               INTEGER (0..511),
///     elevation             INTEGER (0..127),
///     ...,
///     codePhase1023             BOOLEAN OPTIONAL,        -- DEFERRED
///     dopplerUncertaintyExt-r10 ENUMERATED{..} OPTIONAL  -- DEFERRED
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssAcquisitionAssistElement {
    pub sv_id: SvId,
    /// doppler0 INTEGER (-2048..2047): 0.5 m/s scale.
    pub doppler0: i16,
    /// doppler1 INTEGER (0..63): (-42 + doppler1)/210 m/s^2.
    pub doppler1: u8,
    /// dopplerUncertainty INTEGER (0..4): 2^-n * 40 m/s.
    pub doppler_uncertainty: u8,
    /// codePhase INTEGER (0..1022): 1/1023 ms scale.
    pub code_phase: u16,
    /// intCodePhase INTEGER (0..127): integer ms.
    pub int_code_phase: u8,
    /// codePhaseSearchWindow INTEGER (0..31).
    pub code_phase_search_window: u8,
    /// azimuth INTEGER (0..511): 0.703125 degrees.
    pub azimuth: u16,
    /// elevation INTEGER (0..127): 0.703125 degrees.
    pub elevation: u8,
}

impl GnssAcquisitionAssistElement {
    const DOPPLER0: Constraint = Constraint::new(-2048, 2047);
    const DOPPLER1: Constraint = Constraint::new(0, 63);
    const DOPPLER_UNCERTAINTY: Constraint = Constraint::new(0, 4);
    const CODE_PHASE: Constraint = Constraint::new(0, 1022);
    const INT_CODE_PHASE: Constraint = Constraint::new(0, 127);
    const CODE_PHASE_SEARCH_WINDOW: Constraint = Constraint::new(0, 31);
    const AZIMUTH: Constraint = Constraint::new(0, 511);
    const ELEVATION: Constraint = Constraint::new(0, 127);
}

impl UperEncode for GnssAcquisitionAssistElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no ROOT optionals. Extension bit = false:
        // codePhase1023 / dopplerUncertaintyExt-r10 are DEFERRED (never emitted).
        encoder.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(encoder)?;
        encoder.encode_constrained_whole_number(self.doppler0 as i64, &Self::DOPPLER0)?;
        encoder.encode_constrained_whole_number(self.doppler1 as i64, &Self::DOPPLER1)?;
        encoder.encode_constrained_whole_number(
            self.doppler_uncertainty as i64,
            &Self::DOPPLER_UNCERTAINTY,
        )?;
        encoder.encode_constrained_whole_number(self.code_phase as i64, &Self::CODE_PHASE)?;
        encoder
            .encode_constrained_whole_number(self.int_code_phase as i64, &Self::INT_CODE_PHASE)?;
        encoder.encode_constrained_whole_number(
            self.code_phase_search_window as i64,
            &Self::CODE_PHASE_SEARCH_WINDOW,
        )?;
        encoder.encode_constrained_whole_number(self.azimuth as i64, &Self::AZIMUTH)?;
        encoder.encode_constrained_whole_number(self.elevation as i64, &Self::ELEVATION)
    }
}

impl UperDecode for GnssAcquisitionAssistElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            // codePhase1023 / dopplerUncertaintyExt-r10 additions are DEFERRED.
            return Err(PerError::DecodeError(
                "GNSS-AcquisitionAssistElement extension additions (codePhase1023 / \
                 dopplerUncertaintyExt-r10) not supported"
                    .to_string(),
            ));
        }
        let sv_id = SvId::decode_uper(decoder)?;
        let doppler0 = decoder.decode_constrained_whole_number(&Self::DOPPLER0)? as i16;
        let doppler1 = decoder.decode_constrained_whole_number(&Self::DOPPLER1)? as u8;
        let doppler_uncertainty =
            decoder.decode_constrained_whole_number(&Self::DOPPLER_UNCERTAINTY)? as u8;
        let code_phase = decoder.decode_constrained_whole_number(&Self::CODE_PHASE)? as u16;
        let int_code_phase = decoder.decode_constrained_whole_number(&Self::INT_CODE_PHASE)? as u8;
        let code_phase_search_window =
            decoder.decode_constrained_whole_number(&Self::CODE_PHASE_SEARCH_WINDOW)? as u8;
        let azimuth = decoder.decode_constrained_whole_number(&Self::AZIMUTH)? as u16;
        let elevation = decoder.decode_constrained_whole_number(&Self::ELEVATION)? as u8;
        Ok(GnssAcquisitionAssistElement {
            sv_id,
            doppler0,
            doppler1,
            doppler_uncertainty,
            code_phase,
            int_code_phase,
            code_phase_search_window,
            azimuth,
            elevation,
        })
    }
}

// ---------------------------------------------------------------------------
// GNSS-AcquisitionAssistList
// ---------------------------------------------------------------------------

/// GNSS-AcquisitionAssistList ::= SEQUENCE (SIZE(1..64)) OF GNSS-AcquisitionAssistElement
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssAcquisitionAssistList {
    pub elements: Vec<GnssAcquisitionAssistElement>,
}

impl GnssAcquisitionAssistList {
    const SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for GnssAcquisitionAssistList {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        let count = self.elements.len();
        if !(1..=64).contains(&count) {
            return Err(PerError::InvalidLength { length: count });
        }
        encoder.encode_constrained_whole_number(count as i64, &Self::SIZE)?;
        for element in &self.elements {
            element.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssAcquisitionAssistList {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(GnssAcquisitionAssistElement::decode_uper(decoder)?);
        }
        Ok(GnssAcquisitionAssistList { elements })
    }
}

// ---------------------------------------------------------------------------
// GNSS-AcquisitionAssistance
// ---------------------------------------------------------------------------

/// GNSS-AcquisitionAssistance ::= SEQUENCE {     -- extensible
///     gnss-SignalID              GNSS-SignalID,
///     gnss-AcquisitionAssistList GNSS-AcquisitionAssistList,
///     ...,
///     confidence-r10             INTEGER (0..100) OPTIONAL  -- DEFERRED
/// }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssAcquisitionAssistance {
    pub gnss_signal_id: GnssSignalId,
    pub gnss_acquisition_assist_list: GnssAcquisitionAssistList,
}

impl UperEncode for GnssAcquisitionAssistance {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no ROOT optionals. Extension bit = false:
        // confidence-r10 is DEFERRED (never emitted).
        encoder.encode_sequence_preamble(Some(false), &[]);
        self.gnss_signal_id.encode_uper(encoder)?;
        self.gnss_acquisition_assist_list.encode_uper(encoder)
    }
}

impl UperDecode for GnssAcquisitionAssistance {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            // confidence-r10 extension addition is DEFERRED.
            return Err(PerError::DecodeError(
                "GNSS-AcquisitionAssistance extension addition (confidence-r10) not supported"
                    .to_string(),
            ));
        }
        let gnss_signal_id = GnssSignalId::decode_uper(decoder)?;
        let gnss_acquisition_assist_list = GnssAcquisitionAssistList::decode_uper(decoder)?;
        Ok(GnssAcquisitionAssistance {
            gnss_signal_id,
            gnss_acquisition_assist_list,
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

    fn sample_element() -> GnssAcquisitionAssistElement {
        GnssAcquisitionAssistElement {
            sv_id: SvId { satellite_id: 17 },
            doppler0: -1500,
            doppler1: 42,
            doppler_uncertainty: 3,
            code_phase: 900,
            int_code_phase: 100,
            code_phase_search_window: 20,
            azimuth: 400,
            elevation: 90,
        }
    }

    #[test]
    fn round_trip_element_boundaries() {
        // Minimum-value element (all constraint lows).
        roundtrip(&GnssAcquisitionAssistElement {
            sv_id: SvId { satellite_id: 0 },
            doppler0: -2048,
            doppler1: 0,
            doppler_uncertainty: 0,
            code_phase: 0,
            int_code_phase: 0,
            code_phase_search_window: 0,
            azimuth: 0,
            elevation: 0,
        });
        // Maximum-value element (all constraint highs).
        roundtrip(&GnssAcquisitionAssistElement {
            sv_id: SvId { satellite_id: 63 },
            doppler0: 2047,
            doppler1: 63,
            doppler_uncertainty: 4,
            code_phase: 1022,
            int_code_phase: 127,
            code_phase_search_window: 31,
            azimuth: 511,
            elevation: 127,
        });
        roundtrip(&sample_element());
    }

    #[test]
    fn round_trip_list() {
        roundtrip(&GnssAcquisitionAssistList {
            elements: vec![sample_element()],
        });
        roundtrip(&GnssAcquisitionAssistList {
            elements: vec![sample_element(), sample_element(), sample_element()],
        });
    }

    #[test]
    fn round_trip_acquisition_assistance() {
        roundtrip(&GnssAcquisitionAssistance {
            gnss_signal_id: GnssSignalId { gnss_signal_id: 0 },
            gnss_acquisition_assist_list: GnssAcquisitionAssistList {
                elements: vec![sample_element()],
            },
        });
        roundtrip(&GnssAcquisitionAssistance {
            gnss_signal_id: GnssSignalId { gnss_signal_id: 7 },
            gnss_acquisition_assist_list: GnssAcquisitionAssistList {
                elements: vec![sample_element(), sample_element()],
            },
        });
    }

    #[test]
    fn list_size_zero_rejected_on_encode() {
        let empty = GnssAcquisitionAssistList { elements: vec![] };
        let mut enc = UperEncoder::new();
        assert!(empty.encode_uper(&mut enc).is_err());
    }

    #[test]
    fn element_extension_bit_rejected_on_decode() {
        // Encode a valid element, then flip the leading extension bit (MSB of
        // byte 0) so decode sees an unsupported extension addition.
        let mut enc = UperEncoder::new();
        sample_element().encode_uper(&mut enc).unwrap();
        let mut bytes = enc.into_bytes().to_vec();
        bytes[0] |= 0x80;
        let mut dec = UperDecoder::new(&bytes);
        assert!(GnssAcquisitionAssistElement::decode_uper(&mut dec).is_err());
    }

    // =====================================================================
    // GOLDEN VECTOR — GNSS-AcquisitionAssistance (H7, TS 37.355 §6.5.2, UPER)
    //
    // Method: `.context/GOLDEN-VECTOR-METHOD.md` (H5 dual derivation).
    //   Derivation A: the hand X.691-UNALIGNED bit table below.
    //   Derivation B: `tests/lpp_agnss_golden_derivation_b.py` (`vector4()`),
    //     an independent from-scratch recompute agreeing byte-for-byte.
    //   Tier-1 encoder golden + tier-2 decode-from-frozen asserted below.
    //
    // Value: gnss-SignalID=5; one element{ svID=17, doppler0=-1500, doppler1=42,
    //        dopplerUncertainty=3, codePhase=900, intCodePhase=100,
    //        codePhaseSearchWindow=20, azimuth=400, elevation=90 }.
    //
    //   bits   value          X.691 clause / ASN.1 production
    //   -----  -------------  ------------------------------------------------
    //   0      0              §19 ext-marker of GNSS-AcquisitionAssistance (none)
    //   -- gnss-SignalID = SEQUENCE{ INTEGER(0..7) } (extensible SEQ) --
    //   1      0              §19 ext-marker (none)
    //   2-4    101            §11.5 gnss-SignalID, range 8 -> 3 bits, off 5
    //   5-10   000000         §20 SEQUENCE(SIZE(1..64)) OF length, range 64 -> 6 bits, off 0
    //   -- element (extensible SEQ, no root OPTIONAL) --
    //   11     0              §19 ext-marker (none)
    //   -- svID = SV-ID SEQUENCE{ INTEGER(0..63) } (extensible SEQ) --
    //   12     0              §19 ext-marker (none)
    //   13-18  010001         §11.5 satellite-id, range 64 -> 6 bits, off 17
    //   19-30  001000100100   §11.5 doppler0, range 4096 -> 12 bits, off 548 (=-1500+2048)
    //   31-36  101010         §11.5 doppler1, range 64 -> 6 bits, off 42
    //   37-39  011            §11.5 dopplerUncertainty, range 5 -> 3 bits, off 3
    //   40-49  1110000100     §11.5 codePhase, range 1023 -> 10 bits, off 900
    //   50-56  1100100        §11.5 intCodePhase, range 128 -> 7 bits, off 100
    //   57-61  10100          §11.5 codePhaseSearchWindow, range 32 -> 5 bits, off 20
    //   62-70  110010000      §11.5 azimuth, range 512 -> 9 bits, off 400
    //   71-77  1011010        §11.5 elevation, range 128 -> 7 bits, off 90
    //   pad    00             §11.1 final octet alignment (78 -> 80 bits)
    //   regroup: 00101000 00000010 00100100 01001001 01010011 11100001
    //            00110010 01010011 00100001 01101000
    //          = 28 02 24 49 53 E1 32 53 21 68
    // =====================================================================
    const GOLDEN_GNSS_ACQUISITION_ASSISTANCE: [u8; 10] = [
        0x28, 0x02, 0x24, 0x49, 0x53, 0xE1, 0x32, 0x53, 0x21, 0x68,
    ];

    fn golden_acquisition_assistance_value() -> GnssAcquisitionAssistance {
        GnssAcquisitionAssistance {
            gnss_signal_id: GnssSignalId { gnss_signal_id: 5 },
            gnss_acquisition_assist_list: GnssAcquisitionAssistList {
                elements: vec![GnssAcquisitionAssistElement {
                    sv_id: SvId { satellite_id: 17 },
                    doppler0: -1500,
                    doppler1: 42,
                    doppler_uncertainty: 3,
                    code_phase: 900,
                    int_code_phase: 100,
                    code_phase_search_window: 20,
                    azimuth: 400,
                    elevation: 90,
                }],
            },
        }
    }

    #[test]
    fn golden_gnss_acquisition_assistance_encode() {
        let mut enc = UperEncoder::new();
        golden_acquisition_assistance_value()
            .encode_uper(&mut enc)
            .unwrap();
        assert_eq!(enc.bit_length(), 78, "hand derivation A = 78 bits");
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &GOLDEN_GNSS_ACQUISITION_ASSISTANCE);
    }

    #[test]
    fn golden_gnss_acquisition_assistance_decode() {
        let mut dec = UperDecoder::new(&GOLDEN_GNSS_ACQUISITION_ASSISTANCE);
        let decoded = GnssAcquisitionAssistance::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, golden_acquisition_assistance_value());
    }
}
