//! LPP A-GNSS shared common types + top-level assistance-data containers
//! (3GPP TS 37.355 §6.5.2, `LPP-PDU-Definitions` A-GNSS IEs), UNALIGNED PER.
//!
//! This is the A-GNSS *spine*: the small, widely-reused primitives
//! (`GnssId`, `SbasId`, `GnssSignalId`, `GnssSignalIds`, `SvId`,
//! `GnssSystemTime`, `NetworkTime`) plus the four container SEQUENCEs that
//! frame every assistance-data transfer:
//!
//!   * [`GnssCommonAssistData`]  — GNSS-independent assistance (reference time /
//!     location / ionosphere / EOP),
//!   * [`GnssGenericAssistDataElement`] / [`GnssGenericAssistData`] — the
//!     per-GNSS assistance list,
//!   * [`AGnssProvideAssistanceData`] — the provide-side body (LMF -> UE),
//!   * [`AGnssRequestAssistanceData`] — the request-side body (UE -> LMF).
//!
//! The leaf assistance-data IEs referenced by the containers live in their own
//! sibling modules (`super::reference_time::GnssReferenceTime`, …); this file
//! only wires them in by `Option<>` of the sibling type. The exact sibling
//! paths are the contract the 13 leaf modules implement.
//!
//! BOUNDED v1: `gnss-Error` (provide), the whole `A-GNSS-RequestAssistanceData`
//! request sub-bodies, `GNSS-SystemTime.gps-TOW-Assist`, and the non-eUTRA
//! `NetworkTime.cellID` CHOICE alternatives are modeled UNSUPPORTED — never
//! emitted, rejected on decode (each deferral documented inline). Ranges are
//! cited from TS 37.355 (v16/v17) above each type.

use bitvec::prelude::*;

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ===========================================================================
// GNSS-ID
// ===========================================================================

/// gnss-id ENUMERATED { gps, sbas, qzss, galileo, glonass, bds, ... } — the
/// inner extensible ENUMERATED of `GNSS-ID` (TS 37.355 §6.5.2). Six root
/// values (indices 0..5); newer releases add navic/… as extensions (rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GnssIdValue {
    Gps = 0,
    Sbas = 1,
    Qzss = 2,
    Galileo = 3,
    Glonass = 4,
    Bds = 5,
}

/// GNSS-ID ::= SEQUENCE {          -- EXTENSIBLE
///     gnss-id  ENUMERATED { gps, sbas, qzss, galileo, glonass, bds, ... } }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GnssId {
    pub gnss_id: GnssIdValue,
}

impl GnssId {
    /// Extensible ENUMERATED, 6 root values -> index range 0..5.
    const GNSS_ID: Constraint = Constraint::extensible(0, 5);
}

impl UperEncode for GnssId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root optionals.
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_enumerated(self.gnss_id as i64, &Self::GNSS_ID)
    }
}

impl UperDecode for GnssId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let value = decoder.decode_enumerated(&Self::GNSS_ID)?;
        let gnss_id = match value {
            0 => GnssIdValue::Gps,
            1 => GnssIdValue::Sbas,
            2 => GnssIdValue::Qzss,
            3 => GnssIdValue::Galileo,
            4 => GnssIdValue::Glonass,
            5 => GnssIdValue::Bds,
            other => {
                return Err(PerError::DecodeError(format!(
                    "GNSS-ID gnss-id extension value {other} not supported in v1"
                )));
            }
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(GnssId { gnss_id })
    }
}

// ===========================================================================
// SBAS-ID
// ===========================================================================

/// sbas-id ENUMERATED { waas, egnos, msas, gagan, ... } — the inner extensible
/// ENUMERATED of `SBAS-ID` (TS 37.355 §6.5.2). Four root values (0..3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SbasIdValue {
    Waas = 0,
    Egnos = 1,
    Msas = 2,
    Gagan = 3,
}

/// SBAS-ID ::= SEQUENCE {          -- EXTENSIBLE
///     sbas-id  ENUMERATED { waas, egnos, msas, gagan, ... } }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SbasId {
    pub sbas_id: SbasIdValue,
}

impl SbasId {
    /// Extensible ENUMERATED, 4 root values -> index range 0..3.
    const SBAS_ID: Constraint = Constraint::extensible(0, 3);
}

impl UperEncode for SbasId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_enumerated(self.sbas_id as i64, &Self::SBAS_ID)
    }
}

impl UperDecode for SbasId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let value = decoder.decode_enumerated(&Self::SBAS_ID)?;
        let sbas_id = match value {
            0 => SbasIdValue::Waas,
            1 => SbasIdValue::Egnos,
            2 => SbasIdValue::Msas,
            3 => SbasIdValue::Gagan,
            other => {
                return Err(PerError::DecodeError(format!(
                    "SBAS-ID sbas-id extension value {other} not supported in v1"
                )));
            }
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(SbasId { sbas_id })
    }
}

// ===========================================================================
// GNSS-SignalID
// ===========================================================================

/// GNSS-SignalID ::= SEQUENCE {    -- EXTENSIBLE
///     gnss-SignalID  INTEGER (0..7),
///     ...,
///     [[ gnss-SignalID-Ext-r15 ... ]] }
///
/// The r15 extension group is UNSUPPORTED (skipped on decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GnssSignalId {
    pub gnss_signal_id: u8,
}

impl GnssSignalId {
    const SIGNAL_ID: Constraint = Constraint::new(0, 7);
}

impl UperEncode for GnssSignalId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(self.gnss_signal_id as i64, &Self::SIGNAL_ID)
    }
}

impl UperDecode for GnssSignalId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let gnss_signal_id = decoder.decode_constrained_whole_number(&Self::SIGNAL_ID)? as u8;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(GnssSignalId { gnss_signal_id })
    }
}

// ===========================================================================
// GNSS-SignalIDs
// ===========================================================================

/// GNSS-SignalIDs ::= BIT STRING (SIZE (8))
///
/// A fixed 8-bit signal-mask (one bit per `gnss-SignalID` value). Stored as a
/// `u8`; bit 0 (MSB, `0x80`) is signal 0, matching X.691 BIT STRING ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GnssSignalIds {
    pub signals: u8,
}

impl GnssSignalIds {
    fn to_bits(self) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::with_capacity(8);
        for i in 0..8 {
            bv.push((self.signals >> (7 - i)) & 1 == 1);
        }
        bv
    }
}

impl UperEncode for GnssSignalIds {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_bit_string(&self.to_bits(), Some(8), Some(8))
    }
}

impl UperDecode for GnssSignalIds {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let bits = decoder.decode_bit_string(Some(8), Some(8))?;
        let mut signals = 0u8;
        for (i, b) in bits.iter().enumerate().take(8) {
            if *b {
                signals |= 1 << (7 - i);
            }
        }
        Ok(GnssSignalIds { signals })
    }
}

// ===========================================================================
// SV-ID
// ===========================================================================

/// SV-ID ::= SEQUENCE {            -- EXTENSIBLE
///     satellite-id  INTEGER (0..63) }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SvId {
    pub satellite_id: u8,
}

impl SvId {
    const SATELLITE_ID: Constraint = Constraint::new(0, 63);
}

impl UperEncode for SvId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(self.satellite_id as i64, &Self::SATELLITE_ID)
    }
}

impl UperDecode for SvId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let satellite_id = decoder.decode_constrained_whole_number(&Self::SATELLITE_ID)? as u8;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(SvId { satellite_id })
    }
}

// ===========================================================================
// GNSS-SystemTime
// ===========================================================================

/// GNSS-SystemTime ::= SEQUENCE {  -- EXTENSIBLE
///     gnss-TimeID                 GNSS-ID,
///     gnss-DayNumber              INTEGER (0..32767),
///     gnss-TimeOfDay              INTEGER (0..86399),
///     gnss-TimeOfDayFrac-msec     INTEGER (0..999)     OPTIONAL,   -- opt0 Need ON
///     notificationOfLeapSecond    BIT STRING (SIZE(2)) OPTIONAL,   -- opt1 Cond GLONASS
///     gps-TOW-Assist              GPS-TOW-Assist       OPTIONAL,   -- opt2 UNSUPPORTED
///     ... }
///
/// Three root optionals `[timeOfDayFrac, notificationOfLeapSecond,
/// gps-TOW-Assist]`; `gps-TOW-Assist` (opt2) is UNSUPPORTED in v1.
/// `notificationOfLeapSecond` is a 2-bit field stored as a 0..3 value (bit 0 in
/// the MSB position).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GnssSystemTime {
    pub gnss_time_id: GnssId,
    pub gnss_day_number: u16,
    pub gnss_time_of_day: u32,
    pub gnss_time_of_day_frac_msec: Option<u16>,
    pub notification_of_leap_second: Option<u8>,
}

impl GnssSystemTime {
    const DAY_NUMBER: Constraint = Constraint::new(0, 32767);
    const TIME_OF_DAY: Constraint = Constraint::new(0, 86399);
    const TIME_OF_DAY_FRAC: Constraint = Constraint::new(0, 999);
}

impl UperEncode for GnssSystemTime {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.gnss_time_of_day_frac_msec.is_some(), // opt0
                self.notification_of_leap_second.is_some(), // opt1
                false,                                     // opt2 gps-TOW-Assist UNSUPPORTED
            ],
        );
        self.gnss_time_id.encode_uper(encoder)?;
        encoder.encode_constrained_whole_number(self.gnss_day_number as i64, &Self::DAY_NUMBER)?;
        encoder.encode_constrained_whole_number(self.gnss_time_of_day as i64, &Self::TIME_OF_DAY)?;
        if let Some(frac) = self.gnss_time_of_day_frac_msec {
            encoder.encode_constrained_whole_number(frac as i64, &Self::TIME_OF_DAY_FRAC)?;
        }
        if let Some(notif) = self.notification_of_leap_second {
            let mut bv: BitVec<u8, Msb0> = BitVec::with_capacity(2);
            bv.push((notif >> 1) & 1 == 1);
            bv.push(notif & 1 == 1);
            encoder.encode_bit_string(&bv, Some(2), Some(2))?;
        }
        // gps-TOW-Assist absent.
        Ok(())
    }
}

impl UperDecode for GnssSystemTime {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        // opts = [timeOfDayFrac, notificationOfLeapSecond, gps-TOW-Assist]
        if opts[2] {
            return Err(PerError::DecodeError(
                "GNSS-SystemTime gps-TOW-Assist not supported in v1".to_string(),
            ));
        }
        let gnss_time_id = GnssId::decode_uper(decoder)?;
        let gnss_day_number = decoder.decode_constrained_whole_number(&Self::DAY_NUMBER)? as u16;
        let gnss_time_of_day = decoder.decode_constrained_whole_number(&Self::TIME_OF_DAY)? as u32;
        let gnss_time_of_day_frac_msec = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::TIME_OF_DAY_FRAC)? as u16)
        } else {
            None
        };
        let notification_of_leap_second = if opts[1] {
            let bits = decoder.decode_bit_string(Some(2), Some(2))?;
            let b0 = *bits.first().as_deref().unwrap_or(&false);
            let b1 = *bits.get(1).as_deref().unwrap_or(&false);
            Some(((b0 as u8) << 1) | b1 as u8)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(GnssSystemTime {
            gnss_time_id,
            gnss_day_number,
            gnss_time_of_day,
            gnss_time_of_day_frac_msec,
            notification_of_leap_second,
        })
    }
}

// ===========================================================================
// NetworkTime
// ===========================================================================

/// The `eUTRA` alternative of `NetworkTime.cellID` (TS 37.355 §6.5.2):
///
///     eUTRA SEQUENCE {                 -- EXTENSIBLE
///         physCellId          INTEGER (0..503),
///         cellGlobalIdEUTRA-AndUTRA  CellGlobalIdEUTRA-AndUTRA OPTIONAL, -- opt0 UNSUPPORTED
///         earfcn              INTEGER (0..maxEARFCN),   -- maxEARFCN = 65535
///         ...,
///         [[ earfcn-v9a0 ... ]] }
///
/// The `cellGlobalIdEUTRA-AndUTRA` optional and the `earfcn-v9a0` extension are
/// UNSUPPORTED in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkTimeEUtra {
    pub phys_cell_id: u16,
    pub earfcn: u32,
}

impl NetworkTimeEUtra {
    const PHYS_CELL_ID: Constraint = Constraint::new(0, 503);
    const EARFCN: Constraint = Constraint::new(0, 65535);
}

impl UperEncode for NetworkTimeEUtra {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // One root optional (cellGlobalIdEUTRA-AndUTRA), UNSUPPORTED -> absent.
        encoder.encode_sequence_preamble(Some(false), &[false]);
        encoder.encode_constrained_whole_number(self.phys_cell_id as i64, &Self::PHYS_CELL_ID)?;
        encoder.encode_constrained_whole_number(self.earfcn as i64, &Self::EARFCN)
    }
}

impl UperDecode for NetworkTimeEUtra {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 1)?;
        if opts[0] {
            return Err(PerError::DecodeError(
                "NetworkTime eUTRA cellGlobalIdEUTRA-AndUTRA not supported in v1".to_string(),
            ));
        }
        let phys_cell_id = decoder.decode_constrained_whole_number(&Self::PHYS_CELL_ID)? as u16;
        let earfcn = decoder.decode_constrained_whole_number(&Self::EARFCN)? as u32;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NetworkTimeEUtra { phys_cell_id, earfcn })
    }
}

/// cellID ::= CHOICE { eUTRA, uTRA, gSM, ..., nR-r15 } (TS 37.355 §6.5.2).
///
/// Three root alternatives (extensible). v1 types only `eUTRA` (index 0); the
/// `uTRA`/`gSM` root alternatives and the `nR-r15` extension are UNSUPPORTED
/// (rejected on decode; only `EUtra` is representable on encode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCellId {
    EUtra(NetworkTimeEUtra),
}

impl NetworkCellId {
    const NUM_ALTERNATIVES: usize = 3;
    const EXTENSIBLE: bool = true;
}

impl UperEncode for NetworkCellId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            NetworkCellId::EUtra(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_uper(encoder)
            }
        }
    }
}

impl UperDecode for NetworkCellId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(NetworkCellId::EUtra(NetworkTimeEUtra::decode_uper(decoder)?)),
            other => Err(PerError::DecodeError(format!(
                "NetworkTime cellID alternative {other} (uTRA/gSM/nR-r15) not supported in v1"
            ))),
        }
    }
}

/// NetworkTime ::= SEQUENCE {      -- EXTENSIBLE
///     secondsFromFrameStructureStart            INTEGER (0..12533),
///     fractionalSecondsFromFrameStructureStart  INTEGER (0..3999999),
///     frameDrift                                INTEGER (-64..63) OPTIONAL,  -- opt0
///     cellID                                    CHOICE { eUTRA, uTRA, gSM, ..., nR-r15 },
///     ... }
///
/// One root optional `[frameDrift]`; `cellID` is mandatory (see
/// [`NetworkCellId`], eUTRA-only in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkTime {
    pub seconds_from_frame_structure_start: u16,
    pub fractional_seconds_from_frame_structure_start: u32,
    pub frame_drift: Option<i8>,
    pub cell_id: NetworkCellId,
}

impl NetworkTime {
    const SECONDS: Constraint = Constraint::new(0, 12533);
    const FRACTIONAL_SECONDS: Constraint = Constraint::new(0, 3_999_999);
    const FRAME_DRIFT: Constraint = Constraint::new(-64, 63);
}

impl UperEncode for NetworkTime {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[self.frame_drift.is_some()]);
        encoder.encode_constrained_whole_number(
            self.seconds_from_frame_structure_start as i64,
            &Self::SECONDS,
        )?;
        encoder.encode_constrained_whole_number(
            self.fractional_seconds_from_frame_structure_start as i64,
            &Self::FRACTIONAL_SECONDS,
        )?;
        if let Some(drift) = self.frame_drift {
            encoder.encode_constrained_whole_number(drift as i64, &Self::FRAME_DRIFT)?;
        }
        self.cell_id.encode_uper(encoder)
    }
}

impl UperDecode for NetworkTime {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 1)?;
        let seconds_from_frame_structure_start =
            decoder.decode_constrained_whole_number(&Self::SECONDS)? as u16;
        let fractional_seconds_from_frame_structure_start =
            decoder.decode_constrained_whole_number(&Self::FRACTIONAL_SECONDS)? as u32;
        let frame_drift = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::FRAME_DRIFT)? as i8)
        } else {
            None
        };
        let cell_id = NetworkCellId::decode_uper(decoder)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NetworkTime {
            seconds_from_frame_structure_start,
            fractional_seconds_from_frame_structure_start,
            frame_drift,
            cell_id,
        })
    }
}

// ===========================================================================
// GNSS-CommonAssistData
// ===========================================================================

/// GNSS-CommonAssistData ::= SEQUENCE {   -- EXTENSIBLE
///     gnss-ReferenceTime               GNSS-ReferenceTime               OPTIONAL, -- opt0 Need ON
///     gnss-ReferenceLocation           GNSS-ReferenceLocation           OPTIONAL, -- opt1 Need ON
///     gnss-IonosphericModel            GNSS-IonosphericModel            OPTIONAL, -- opt2 Need ON
///     gnss-EarthOrientationParameters  GNSS-EarthOrientationParameters  OPTIONAL, -- opt3 Need ON
///     ...,
///     [[ gnss-RTK-* -r15 extensions ]] }
///
/// The four leaf IEs live in sibling modules; the r15 RTK extension group is
/// skipped on decode.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssCommonAssistData {
    pub gnss_reference_time: Option<super::reference_time::GnssReferenceTime>,
    pub gnss_reference_location: Option<super::reference_location::GnssReferenceLocation>,
    pub gnss_ionospheric_model: Option<super::ionospheric_model::GnssIonosphericModel>,
    pub gnss_earth_orientation_parameters:
        Option<super::earth_orientation::GnssEarthOrientationParameters>,
}

impl UperEncode for GnssCommonAssistData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.gnss_reference_time.is_some(),
                self.gnss_reference_location.is_some(),
                self.gnss_ionospheric_model.is_some(),
                self.gnss_earth_orientation_parameters.is_some(),
            ],
        );
        if let Some(v) = &self.gnss_reference_time {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_reference_location {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_ionospheric_model {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_earth_orientation_parameters {
            v.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssCommonAssistData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 4)?;
        let gnss_reference_time = if opts[0] {
            Some(super::reference_time::GnssReferenceTime::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_reference_location = if opts[1] {
            Some(super::reference_location::GnssReferenceLocation::decode_uper(
                decoder,
            )?)
        } else {
            None
        };
        let gnss_ionospheric_model = if opts[2] {
            Some(super::ionospheric_model::GnssIonosphericModel::decode_uper(
                decoder,
            )?)
        } else {
            None
        };
        let gnss_earth_orientation_parameters = if opts[3] {
            Some(
                super::earth_orientation::GnssEarthOrientationParameters::decode_uper(
                    decoder,
                )?,
            )
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(GnssCommonAssistData {
            gnss_reference_time,
            gnss_reference_location,
            gnss_ionospheric_model,
            gnss_earth_orientation_parameters,
        })
    }
}

// ===========================================================================
// GNSS-GenericAssistDataElement / GNSS-GenericAssistData
// ===========================================================================

/// GNSS-GenericAssistDataElement ::= SEQUENCE {   -- EXTENSIBLE
///     gnss-ID                        GNSS-ID,
///     sbas-ID                        SBAS-ID                       OPTIONAL, -- opt0 Cond GNSS-ID-SBAS
///     gnss-TimeModels                GNSS-TimeModelList            OPTIONAL, -- opt1 Need ON
///     gnss-DifferentialCorrections   GNSS-DifferentialCorrections OPTIONAL, -- opt2 Need ON
///     gnss-NavigationModel           GNSS-NavigationModel         OPTIONAL, -- opt3 Need ON
///     gnss-RealTimeIntegrity         GNSS-RealTimeIntegrity       OPTIONAL, -- opt4 Need ON
///     gnss-DataBitAssistance         GNSS-DataBitAssistance       OPTIONAL, -- opt5 Need ON
///     gnss-AcquisitionAssistance     GNSS-AcquisitionAssistance   OPTIONAL, -- opt6 Need ON
///     gnss-Almanac                   GNSS-Almanac                 OPTIONAL, -- opt7 Need ON
///     gnss-UTC-Model                 GNSS-UTC-Model               OPTIONAL, -- opt8 Need ON
///     gnss-AuxiliaryInformation      GNSS-AuxiliaryInformation    OPTIONAL, -- opt9 Need ON
///     ...,
///     [[ ... r15 extensions ]] }
///
/// `gnss-ID` is mandatory; the ten optionals are wired to their sibling leaf
/// modules (`sbas-ID` is [`SbasId`], defined here). The r15 extension group is
/// skipped on decode.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssGenericAssistDataElement {
    pub gnss_id: GnssId,
    pub sbas_id: Option<SbasId>,
    pub gnss_time_models: Option<super::time_model::GnssTimeModelList>,
    pub gnss_differential_corrections:
        Option<super::differential_corrections::GnssDifferentialCorrections>,
    pub gnss_navigation_model: Option<super::navigation_model::GnssNavigationModel>,
    pub gnss_real_time_integrity: Option<super::real_time_integrity::GnssRealTimeIntegrity>,
    pub gnss_data_bit_assistance: Option<super::data_bit_assistance::GnssDataBitAssistance>,
    pub gnss_acquisition_assistance:
        Option<super::acquisition_assistance::GnssAcquisitionAssistance>,
    pub gnss_almanac: Option<super::almanac::GnssAlmanac>,
    pub gnss_utc_model: Option<super::utc_model::GnssUtcModel>,
    pub gnss_auxiliary_information:
        Option<super::auxiliary_information::GnssAuxiliaryInformation>,
}

impl UperEncode for GnssGenericAssistDataElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.sbas_id.is_some(),
                self.gnss_time_models.is_some(),
                self.gnss_differential_corrections.is_some(),
                self.gnss_navigation_model.is_some(),
                self.gnss_real_time_integrity.is_some(),
                self.gnss_data_bit_assistance.is_some(),
                self.gnss_acquisition_assistance.is_some(),
                self.gnss_almanac.is_some(),
                self.gnss_utc_model.is_some(),
                self.gnss_auxiliary_information.is_some(),
            ],
        );
        self.gnss_id.encode_uper(encoder)?;
        if let Some(v) = &self.sbas_id {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_time_models {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_differential_corrections {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_navigation_model {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_real_time_integrity {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_data_bit_assistance {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_acquisition_assistance {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_almanac {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_utc_model {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_auxiliary_information {
            v.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssGenericAssistDataElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 10)?;
        let gnss_id = GnssId::decode_uper(decoder)?;
        let sbas_id = if opts[0] {
            Some(SbasId::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_time_models = if opts[1] {
            Some(super::time_model::GnssTimeModelList::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_differential_corrections = if opts[2] {
            Some(
                super::differential_corrections::GnssDifferentialCorrections::decode_uper(decoder)?,
            )
        } else {
            None
        };
        let gnss_navigation_model = if opts[3] {
            Some(super::navigation_model::GnssNavigationModel::decode_uper(
                decoder,
            )?)
        } else {
            None
        };
        let gnss_real_time_integrity = if opts[4] {
            Some(super::real_time_integrity::GnssRealTimeIntegrity::decode_uper(
                decoder,
            )?)
        } else {
            None
        };
        let gnss_data_bit_assistance = if opts[5] {
            Some(super::data_bit_assistance::GnssDataBitAssistance::decode_uper(
                decoder,
            )?)
        } else {
            None
        };
        let gnss_acquisition_assistance = if opts[6] {
            Some(
                super::acquisition_assistance::GnssAcquisitionAssistance::decode_uper(decoder)?,
            )
        } else {
            None
        };
        let gnss_almanac = if opts[7] {
            Some(super::almanac::GnssAlmanac::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_utc_model = if opts[8] {
            Some(super::utc_model::GnssUtcModel::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_auxiliary_information = if opts[9] {
            Some(super::auxiliary_information::GnssAuxiliaryInformation::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(GnssGenericAssistDataElement {
            gnss_id,
            sbas_id,
            gnss_time_models,
            gnss_differential_corrections,
            gnss_navigation_model,
            gnss_real_time_integrity,
            gnss_data_bit_assistance,
            gnss_acquisition_assistance,
            gnss_almanac,
            gnss_utc_model,
            gnss_auxiliary_information,
        })
    }
}

/// GNSS-GenericAssistData ::= SEQUENCE (SIZE (1..16)) OF
///        GNSS-GenericAssistDataElement
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GnssGenericAssistData {
    pub elements: Vec<GnssGenericAssistDataElement>,
}

impl GnssGenericAssistData {
    const SIZE: Constraint = Constraint::new(1, 16);
}

impl UperEncode for GnssGenericAssistData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.elements.len() as i64, &Self::SIZE)?;
        for element in &self.elements {
            element.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssGenericAssistData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            elements.push(GnssGenericAssistDataElement::decode_uper(decoder)?);
        }
        Ok(GnssGenericAssistData { elements })
    }
}

// ===========================================================================
// A-GNSS-ProvideAssistanceData
// ===========================================================================

/// A-GNSS-ProvideAssistanceData ::= SEQUENCE {   -- EXTENSIBLE
///     gnss-CommonAssistData    GNSS-CommonAssistData   OPTIONAL, -- opt0 Need ON
///     gnss-GenericAssistData   GNSS-GenericAssistData  OPTIONAL, -- opt1 Need ON
///     gnss-Error               A-GNSS-Error            OPTIONAL, -- opt2 UNSUPPORTED
///     ... }
///
/// `gnss-Error` (opt2) is UNSUPPORTED in v1 — never emitted, rejected on decode.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AGnssProvideAssistanceData {
    pub gnss_common_assist_data: Option<GnssCommonAssistData>,
    pub gnss_generic_assist_data: Option<GnssGenericAssistData>,
}

impl UperEncode for AGnssProvideAssistanceData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.gnss_common_assist_data.is_some(),
                self.gnss_generic_assist_data.is_some(),
                false, // gnss-Error UNSUPPORTED
            ],
        );
        if let Some(v) = &self.gnss_common_assist_data {
            v.encode_uper(encoder)?;
        }
        if let Some(v) = &self.gnss_generic_assist_data {
            v.encode_uper(encoder)?;
        }
        // gnss-Error absent.
        Ok(())
    }
}

impl UperDecode for AGnssProvideAssistanceData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        // opts = [commonAssistData, genericAssistData, gnss-Error]
        if opts[2] {
            return Err(PerError::DecodeError(
                "A-GNSS-ProvideAssistanceData gnss-Error not supported in v1".to_string(),
            ));
        }
        let gnss_common_assist_data = if opts[0] {
            Some(GnssCommonAssistData::decode_uper(decoder)?)
        } else {
            None
        };
        let gnss_generic_assist_data = if opts[1] {
            Some(GnssGenericAssistData::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(AGnssProvideAssistanceData {
            gnss_common_assist_data,
            gnss_generic_assist_data,
        })
    }
}

// ===========================================================================
// A-GNSS-RequestAssistanceData
// ===========================================================================

/// A-GNSS-RequestAssistanceData ::= SEQUENCE {   -- EXTENSIBLE
///     gnss-CommonAssistDataReq   GNSS-CommonAssistDataReq   OPTIONAL, -- opt0 UNSUPPORTED
///     gnss-GenericAssistDataReq  GNSS-GenericAssistDataReq  OPTIONAL, -- opt1 UNSUPPORTED
///     ... }
///
/// BOUNDED v1: both request sub-bodies are UNSUPPORTED (the request-side
/// assistance selectors are a large tree not yet typed). Encodes as the empty
/// request (both absent); a decode that sets either presence bit is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AGnssRequestAssistanceData;

impl UperEncode for AGnssRequestAssistanceData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Two root optionals, both UNSUPPORTED -> absent.
        encoder.encode_sequence_preamble(Some(false), &[false, false]);
        Ok(())
    }
}

impl UperDecode for AGnssRequestAssistanceData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 2)?;
        if opts[0] || opts[1] {
            return Err(PerError::DecodeError(
                "A-GNSS-RequestAssistanceData request sub-bodies (common/generic) not supported \
                 in v1"
                    .to_string(),
            ));
        }
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(AGnssRequestAssistanceData)
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
    fn rt_gnss_id_each_value() {
        for v in [
            GnssIdValue::Gps,
            GnssIdValue::Sbas,
            GnssIdValue::Qzss,
            GnssIdValue::Galileo,
            GnssIdValue::Glonass,
            GnssIdValue::Bds,
        ] {
            roundtrip(&GnssId { gnss_id: v });
        }
    }

    #[test]
    fn rt_sbas_id_each_value() {
        for v in [
            SbasIdValue::Waas,
            SbasIdValue::Egnos,
            SbasIdValue::Msas,
            SbasIdValue::Gagan,
        ] {
            roundtrip(&SbasId { sbas_id: v });
        }
    }

    #[test]
    fn rt_gnss_signal_id() {
        for v in 0..=7u8 {
            roundtrip(&GnssSignalId { gnss_signal_id: v });
        }
    }

    #[test]
    fn rt_gnss_signal_ids() {
        for v in [0x00u8, 0x01, 0x80, 0xA5, 0xFF] {
            roundtrip(&GnssSignalIds { signals: v });
        }
    }

    #[test]
    fn rt_sv_id() {
        for v in [0u8, 1, 31, 63] {
            roundtrip(&SvId { satellite_id: v });
        }
    }

    #[test]
    fn rt_gnss_system_time() {
        roundtrip(&GnssSystemTime {
            gnss_time_id: GnssId {
                gnss_id: GnssIdValue::Galileo,
            },
            gnss_day_number: 1234,
            gnss_time_of_day: 54321,
            gnss_time_of_day_frac_msec: Some(500),
            notification_of_leap_second: Some(2),
        });
        // Minimal: all optionals absent.
        roundtrip(&GnssSystemTime {
            gnss_time_id: GnssId {
                gnss_id: GnssIdValue::Gps,
            },
            gnss_day_number: 0,
            gnss_time_of_day: 0,
            gnss_time_of_day_frac_msec: None,
            notification_of_leap_second: None,
        });
        // Max values.
        roundtrip(&GnssSystemTime {
            gnss_time_id: GnssId {
                gnss_id: GnssIdValue::Glonass,
            },
            gnss_day_number: 32767,
            gnss_time_of_day: 86399,
            gnss_time_of_day_frac_msec: Some(999),
            notification_of_leap_second: Some(3),
        });
    }

    #[test]
    fn rt_network_time() {
        roundtrip(&NetworkTime {
            seconds_from_frame_structure_start: 12000,
            fractional_seconds_from_frame_structure_start: 3_000_000,
            frame_drift: Some(-64),
            cell_id: NetworkCellId::EUtra(NetworkTimeEUtra {
                phys_cell_id: 503,
                earfcn: 65535,
            }),
        });
        roundtrip(&NetworkTime {
            seconds_from_frame_structure_start: 0,
            fractional_seconds_from_frame_structure_start: 0,
            frame_drift: None,
            cell_id: NetworkCellId::EUtra(NetworkTimeEUtra {
                phys_cell_id: 0,
                earfcn: 0,
            }),
        });
    }

    #[test]
    fn err_network_time_non_eutra_cell_id_rejected() {
        // Encode a cellID CHOICE with root index 1 (uTRA) -> must be rejected.
        let mut enc = UperEncoder::new();
        // extensible CHOICE: ext bit 0 (root) + 2-bit index 1.
        enc.encode_choice_index(1, 3, true).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(NetworkCellId::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn rt_generic_assist_data_element_minimal() {
        // gnss-ID mandatory; all ten optionals absent (no leaf types needed).
        roundtrip(&GnssGenericAssistDataElement {
            gnss_id: GnssId {
                gnss_id: GnssIdValue::Bds,
            },
            sbas_id: None,
            gnss_time_models: None,
            gnss_differential_corrections: None,
            gnss_navigation_model: None,
            gnss_real_time_integrity: None,
            gnss_data_bit_assistance: None,
            gnss_acquisition_assistance: None,
            gnss_almanac: None,
            gnss_utc_model: None,
            gnss_auxiliary_information: None,
        });
    }

    #[test]
    fn rt_generic_assist_data_element_with_sbas() {
        // sbas-ID is defined locally, so it can be exercised without leaf types.
        roundtrip(&GnssGenericAssistDataElement {
            gnss_id: GnssId {
                gnss_id: GnssIdValue::Sbas,
            },
            sbas_id: Some(SbasId {
                sbas_id: SbasIdValue::Egnos,
            }),
            gnss_time_models: None,
            gnss_differential_corrections: None,
            gnss_navigation_model: None,
            gnss_real_time_integrity: None,
            gnss_data_bit_assistance: None,
            gnss_acquisition_assistance: None,
            gnss_almanac: None,
            gnss_utc_model: None,
            gnss_auxiliary_information: None,
        });
    }

    fn sample_element() -> GnssGenericAssistDataElement {
        GnssGenericAssistDataElement {
            gnss_id: GnssId {
                gnss_id: GnssIdValue::Gps,
            },
            sbas_id: None,
            gnss_time_models: None,
            gnss_differential_corrections: None,
            gnss_navigation_model: None,
            gnss_real_time_integrity: None,
            gnss_data_bit_assistance: None,
            gnss_acquisition_assistance: None,
            gnss_almanac: None,
            gnss_utc_model: None,
            gnss_auxiliary_information: None,
        }
    }

    #[test]
    fn rt_generic_assist_data_list() {
        roundtrip(&GnssGenericAssistData {
            elements: vec![sample_element()],
        });
        roundtrip(&GnssGenericAssistData {
            elements: vec![
                sample_element(),
                GnssGenericAssistDataElement {
                    gnss_id: GnssId {
                        gnss_id: GnssIdValue::Galileo,
                    },
                    ..sample_element()
                },
            ],
        });
    }

    #[test]
    fn rt_common_assist_data_empty() {
        // All four leaf optionals absent (no leaf types needed to exercise).
        roundtrip(&GnssCommonAssistData {
            gnss_reference_time: None,
            gnss_reference_location: None,
            gnss_ionospheric_model: None,
            gnss_earth_orientation_parameters: None,
        });
    }

    #[test]
    fn rt_provide_assistance_data() {
        roundtrip(&AGnssProvideAssistanceData {
            gnss_common_assist_data: Some(GnssCommonAssistData {
                gnss_reference_time: None,
                gnss_reference_location: None,
                gnss_ionospheric_model: None,
                gnss_earth_orientation_parameters: None,
            }),
            gnss_generic_assist_data: Some(GnssGenericAssistData {
                elements: vec![sample_element()],
            }),
        });
        roundtrip(&AGnssProvideAssistanceData::default());
    }

    #[test]
    fn err_provide_assistance_data_error_body_rejected() {
        // Preamble ext 0 + [common=0, generic=0, error=1].
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(Some(false), &[false, false, true]);
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(AGnssProvideAssistanceData::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn rt_request_assistance_data() {
        roundtrip(&AGnssRequestAssistanceData);
    }

    #[test]
    fn err_request_assistance_data_subbody_rejected() {
        // Preamble ext 0 + [commonReq=1, genericReq=0].
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(Some(false), &[true, false]);
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(AGnssRequestAssistanceData::decode_uper(&mut dec).is_err());
    }
}
