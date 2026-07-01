//! LPP A-GNSS GNSS-NavigationModel assistance data (3GPP TS 37.355 §6.5.2), UPER.
//!
//! Models `GNSS-NavigationModel` and its satellite list of Keplerian ephemeris
//! sets, as delivered from the LMF to the UE inside a
//! `GNSS-GenericAssistDataElement`.
//!
//! ```text
//! GNSS-NavigationModel ::= SEQUENCE {
//!     nonBroadcastIndFlag     INTEGER(0..1),
//!     gnss-SatelliteList      GNSS-NavModelSatelliteList,
//!     ...
//! }
//!
//! GNSS-NavModelSatelliteList ::= SEQUENCE (SIZE(1..64)) OF GNSS-NavModelSatelliteElement
//!
//! GNSS-NavModelSatelliteElement ::= SEQUENCE {
//!     svID                    SV-ID,
//!     svHealth                BIT STRING(SIZE(8)),
//!     iod                     BIT STRING(SIZE(11)),
//!     gnss-ClockModel         GNSS-ClockModel,
//!     gnss-OrbitModel         GNSS-OrbitModel,
//!     ...
//! }
//! ```
//!
//! SCOPE / DEFERRALS: the two model CHOICEs each carry five root alternatives.
//! At full bit-fidelity this module types the primary GPS/Galileo-style
//! broadcast set:
//!   * `GNSS-ClockModel` -> `nav-ClockModel` (alternative index 1), and
//!   * `GNSS-OrbitModel` -> `keplerianSet`   (alternative index 0).
//! The remaining alternatives (standardClockModelList / cnav / glonass / sbas
//! clock models; nav-/cnav-KeplerianSet, GLONASS-ECEF, SBAS-ECEF orbit models)
//! plus every SEQUENCE extension addition are DEFERRED: never emitted on encode
//! and rejected with a `DecodeError` if a peer selects/sets them. Each site is
//! documented inline.

use bitvec::prelude::*;

use super::common::SvId;
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// NavModelKeplerianSet  (GNSS-OrbitModel Model-1)
// ---------------------------------------------------------------------------

/// ```text
/// NavModelKeplerianSet ::= SEQUENCE {
///     keplerToe           INTEGER (0..16383),
///     keplerW             INTEGER (-2147483648..2147483647),
///     keplerDeltaN        INTEGER (-32768..32767),
///     keplerM0            INTEGER (-2147483648..2147483647),
///     keplerOmegaDot      INTEGER (-8388608..8388607),
///     keplerE             INTEGER (0..4294967295),
///     keplerIDot          INTEGER (-8192..8191),
///     keplerAPowerHalf    INTEGER (0..4294967295),
///     keplerI0            INTEGER (-2147483648..2147483647),
///     keplerOmega0        INTEGER (-2147483648..2147483647),
///     keplerCrs           INTEGER (-32768..32767),
///     keplerCis           INTEGER (-32768..32767),
///     keplerCus           INTEGER (-32768..32767),
///     keplerCrc           INTEGER (-32768..32767),
///     keplerCic           INTEGER (-32768..32767),
///     keplerCuc           INTEGER (-32768..32767),
///     ...
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavModelKeplerianSet {
    pub kepler_toe: u16,
    pub kepler_w: i32,
    pub kepler_delta_n: i16,
    pub kepler_m0: i32,
    pub kepler_omega_dot: i32,
    pub kepler_e: u32,
    pub kepler_i_dot: i16,
    pub kepler_a_power_half: u32,
    pub kepler_i0: i32,
    pub kepler_omega0: i32,
    pub kepler_crs: i16,
    pub kepler_cis: i16,
    pub kepler_cus: i16,
    pub kepler_crc: i16,
    pub kepler_cic: i16,
    pub kepler_cuc: i16,
}

impl NavModelKeplerianSet {
    const TOE: Constraint = Constraint::new(0, 16383);
    const I32_FULL: Constraint = Constraint::new(-2147483648, 2147483647);
    const I16_FULL: Constraint = Constraint::new(-32768, 32767);
    const OMEGA_DOT: Constraint = Constraint::new(-8388608, 8388607);
    const U32_FULL: Constraint = Constraint::new(0, 4294967295);
    const I_DOT: Constraint = Constraint::new(-8192, 8191);
}

impl UperEncode for NavModelKeplerianSet {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL fields; no extension additions.
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.kepler_toe as i64, &Self::TOE)?;
        e.encode_constrained_whole_number(self.kepler_w as i64, &Self::I32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_delta_n as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_m0 as i64, &Self::I32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_omega_dot as i64, &Self::OMEGA_DOT)?;
        e.encode_constrained_whole_number(self.kepler_e as i64, &Self::U32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_i_dot as i64, &Self::I_DOT)?;
        e.encode_constrained_whole_number(self.kepler_a_power_half as i64, &Self::U32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_i0 as i64, &Self::I32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_omega0 as i64, &Self::I32_FULL)?;
        e.encode_constrained_whole_number(self.kepler_crs as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_cis as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_cus as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_crc as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_cic as i64, &Self::I16_FULL)?;
        e.encode_constrained_whole_number(self.kepler_cuc as i64, &Self::I16_FULL)?;
        Ok(())
    }
}

impl UperDecode for NavModelKeplerianSet {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            // DEFERRED: NavModelKeplerianSet extension additions not supported.
            return Err(PerError::DecodeError(
                "NavModelKeplerianSet extension additions not supported".into(),
            ));
        }
        Ok(NavModelKeplerianSet {
            kepler_toe: d.decode_constrained_whole_number(&Self::TOE)? as u16,
            kepler_w: d.decode_constrained_whole_number(&Self::I32_FULL)? as i32,
            kepler_delta_n: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_m0: d.decode_constrained_whole_number(&Self::I32_FULL)? as i32,
            kepler_omega_dot: d.decode_constrained_whole_number(&Self::OMEGA_DOT)? as i32,
            kepler_e: d.decode_constrained_whole_number(&Self::U32_FULL)? as u32,
            kepler_i_dot: d.decode_constrained_whole_number(&Self::I_DOT)? as i16,
            kepler_a_power_half: d.decode_constrained_whole_number(&Self::U32_FULL)? as u32,
            kepler_i0: d.decode_constrained_whole_number(&Self::I32_FULL)? as i32,
            kepler_omega0: d.decode_constrained_whole_number(&Self::I32_FULL)? as i32,
            kepler_crs: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_cis: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_cus: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_crc: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_cic: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
            kepler_cuc: d.decode_constrained_whole_number(&Self::I16_FULL)? as i16,
        })
    }
}

// ---------------------------------------------------------------------------
// NAV-ClockModel  (GNSS-ClockModel Model-2)
// ---------------------------------------------------------------------------

/// ```text
/// NAV-ClockModel ::= SEQUENCE {
///     navToc      INTEGER(0..37799),
///     navaf2      INTEGER(-128..127),
///     navaf1      INTEGER(-32768..32767),
///     navaf0      INTEGER(-2097152..2097151),
///     navTgd      INTEGER(-128..127),
///     ...
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavClockModel {
    pub nav_toc: u16,
    pub navaf2: i8,
    pub navaf1: i16,
    pub navaf0: i32,
    pub nav_tgd: i8,
}

impl NavClockModel {
    const TOC: Constraint = Constraint::new(0, 37799);
    const AF2: Constraint = Constraint::new(-128, 127);
    const AF1: Constraint = Constraint::new(-32768, 32767);
    const AF0: Constraint = Constraint::new(-2097152, 2097151);
    const TGD: Constraint = Constraint::new(-128, 127);
}

impl UperEncode for NavClockModel {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL fields; no extension additions.
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(self.nav_toc as i64, &Self::TOC)?;
        e.encode_constrained_whole_number(self.navaf2 as i64, &Self::AF2)?;
        e.encode_constrained_whole_number(self.navaf1 as i64, &Self::AF1)?;
        e.encode_constrained_whole_number(self.navaf0 as i64, &Self::AF0)?;
        e.encode_constrained_whole_number(self.nav_tgd as i64, &Self::TGD)?;
        Ok(())
    }
}

impl UperDecode for NavClockModel {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            // DEFERRED: NAV-ClockModel extension additions not supported.
            return Err(PerError::DecodeError(
                "NAV-ClockModel extension additions not supported".into(),
            ));
        }
        Ok(NavClockModel {
            nav_toc: d.decode_constrained_whole_number(&Self::TOC)? as u16,
            navaf2: d.decode_constrained_whole_number(&Self::AF2)? as i8,
            navaf1: d.decode_constrained_whole_number(&Self::AF1)? as i16,
            navaf0: d.decode_constrained_whole_number(&Self::AF0)? as i32,
            nav_tgd: d.decode_constrained_whole_number(&Self::TGD)? as i8,
        })
    }
}

// ---------------------------------------------------------------------------
// GNSS-ClockModel  (CHOICE)
// ---------------------------------------------------------------------------

/// ```text
/// GNSS-ClockModel ::= CHOICE {
///     standardClockModelList  StandardClockModelList,     -- Model-1
///     nav-ClockModel          NAV-ClockModel,             -- Model-2
///     cnav-ClockModel         CNAV-ClockModel,            -- Model-3
///     glonass-ClockModel      GLONASS-ClockModel,         -- Model-4
///     sbas-ClockModel         SBAS-ClockModel,            -- Model-5
///     ...
/// }
/// ```
///
/// Only `nav-ClockModel` (root alternative index 1) is typed. The other four
/// root alternatives plus any extension alternative are DEFERRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnssClockModel {
    /// nav-ClockModel — root CHOICE alternative index 1.
    Nav(NavClockModel),
}

impl GnssClockModel {
    /// Number of root CHOICE alternatives (Models 1..5).
    const NUM_ROOT: usize = 5;
    /// Root index of the typed `nav-ClockModel` alternative.
    const NAV_INDEX: usize = 1;
}

impl UperEncode for GnssClockModel {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        match self {
            GnssClockModel::Nav(m) => {
                e.encode_choice_index(Self::NAV_INDEX, Self::NUM_ROOT, true)?;
                m.encode_uper(e)
            }
        }
    }
}

impl UperDecode for GnssClockModel {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let idx = d.decode_choice_index(Self::NUM_ROOT, true)?;
        if idx == Self::NAV_INDEX {
            Ok(GnssClockModel::Nav(NavClockModel::decode_uper(d)?))
        } else {
            // DEFERRED: standardClockModelList / cnav / glonass / sbas clock
            // models and any extension alternative are not supported.
            Err(PerError::DecodeError(format!(
                "GNSS-ClockModel alternative {idx} not supported (only nav-ClockModel)"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// GNSS-OrbitModel  (CHOICE)
// ---------------------------------------------------------------------------

/// ```text
/// GNSS-OrbitModel ::= CHOICE {
///     keplerianSet        NavModelKeplerianSet,       -- Model-1
///     nav-KeplerianSet    NavModelNAV-KeplerianSet,   -- Model-2
///     cnav-KeplerianSet   NavModelCNAV-KeplerianSet,  -- Model-3
///     glonass-ECEF        NavModel-GLONASS-ECEF,      -- Model-4
///     sbas-ECEF           NavModel-SBAS-ECEF,         -- Model-5
///     ...
/// }
/// ```
///
/// Only `keplerianSet` (root alternative index 0) is typed. The other four
/// root alternatives plus any extension alternative are DEFERRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnssOrbitModel {
    /// keplerianSet — root CHOICE alternative index 0.
    Keplerian(NavModelKeplerianSet),
}

impl GnssOrbitModel {
    /// Number of root CHOICE alternatives (Models 1..5).
    const NUM_ROOT: usize = 5;
    /// Root index of the typed `keplerianSet` alternative.
    const KEPLERIAN_INDEX: usize = 0;
}

impl UperEncode for GnssOrbitModel {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        match self {
            GnssOrbitModel::Keplerian(m) => {
                e.encode_choice_index(Self::KEPLERIAN_INDEX, Self::NUM_ROOT, true)?;
                m.encode_uper(e)
            }
        }
    }
}

impl UperDecode for GnssOrbitModel {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let idx = d.decode_choice_index(Self::NUM_ROOT, true)?;
        if idx == Self::KEPLERIAN_INDEX {
            Ok(GnssOrbitModel::Keplerian(
                NavModelKeplerianSet::decode_uper(d)?,
            ))
        } else {
            // DEFERRED: nav-/cnav-KeplerianSet, GLONASS-ECEF, SBAS-ECEF and any
            // extension alternative are not supported.
            Err(PerError::DecodeError(format!(
                "GNSS-OrbitModel alternative {idx} not supported (only keplerianSet)"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// GNSS-NavModelSatelliteElement
// ---------------------------------------------------------------------------

/// ```text
/// GNSS-NavModelSatelliteElement ::= SEQUENCE {
///     svID                SV-ID,
///     svHealth            BIT STRING(SIZE(8)),
///     iod                 BIT STRING(SIZE(11)),
///     gnss-ClockModel     GNSS-ClockModel,
///     gnss-OrbitModel     GNSS-OrbitModel,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssNavModelSatelliteElement {
    pub sv_id: SvId,
    /// BIT STRING(SIZE(8)).
    pub sv_health: BitVec<u8, Msb0>,
    /// BIT STRING(SIZE(11)).
    pub iod: BitVec<u8, Msb0>,
    pub gnss_clock_model: GnssClockModel,
    pub gnss_orbit_model: GnssOrbitModel,
}

impl GnssNavModelSatelliteElement {
    const SV_HEALTH_LEN: usize = 8;
    const IOD_LEN: usize = 11;
}

impl UperEncode for GnssNavModelSatelliteElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL fields; no extension additions.
        e.encode_sequence_preamble(Some(false), &[]);
        self.sv_id.encode_uper(e)?;
        if self.sv_health.len() != Self::SV_HEALTH_LEN {
            return Err(PerError::InvalidLength {
                length: self.sv_health.len(),
            });
        }
        e.encode_bit_string(
            &self.sv_health,
            Some(Self::SV_HEALTH_LEN),
            Some(Self::SV_HEALTH_LEN),
        )?;
        if self.iod.len() != Self::IOD_LEN {
            return Err(PerError::InvalidLength {
                length: self.iod.len(),
            });
        }
        e.encode_bit_string(&self.iod, Some(Self::IOD_LEN), Some(Self::IOD_LEN))?;
        self.gnss_clock_model.encode_uper(e)?;
        self.gnss_orbit_model.encode_uper(e)?;
        Ok(())
    }
}

impl UperDecode for GnssNavModelSatelliteElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            // DEFERRED: satellite-element extension additions not supported.
            return Err(PerError::DecodeError(
                "GNSS-NavModelSatelliteElement extension additions not supported".into(),
            ));
        }
        let sv_id = SvId::decode_uper(d)?;
        let sv_health =
            d.decode_bit_string(Some(Self::SV_HEALTH_LEN), Some(Self::SV_HEALTH_LEN))?;
        let iod = d.decode_bit_string(Some(Self::IOD_LEN), Some(Self::IOD_LEN))?;
        let gnss_clock_model = GnssClockModel::decode_uper(d)?;
        let gnss_orbit_model = GnssOrbitModel::decode_uper(d)?;
        Ok(GnssNavModelSatelliteElement {
            sv_id,
            sv_health,
            iod,
            gnss_clock_model,
            gnss_orbit_model,
        })
    }
}

// ---------------------------------------------------------------------------
// GNSS-NavModelSatelliteList  (SEQUENCE (SIZE(1..64)) OF ...)
// ---------------------------------------------------------------------------

/// ```text
/// GNSS-NavModelSatelliteList ::= SEQUENCE (SIZE(1..64)) OF GNSS-NavModelSatelliteElement
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssNavModelSatelliteList {
    pub elements: Vec<GnssNavModelSatelliteElement>,
}

impl GnssNavModelSatelliteList {
    const SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for GnssNavModelSatelliteList {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        let count = self.elements.len();
        if !(1..=64).contains(&count) {
            return Err(PerError::InvalidLength { length: count });
        }
        e.encode_constrained_whole_number(count as i64, &Self::SIZE)?;
        for el in &self.elements {
            el.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssNavModelSatelliteList {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let count = d.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(GnssNavModelSatelliteElement::decode_uper(d)?);
        }
        Ok(GnssNavModelSatelliteList { elements })
    }
}

// ---------------------------------------------------------------------------
// GNSS-NavigationModel  (top-level assistance-data IE)
// ---------------------------------------------------------------------------

/// ```text
/// GNSS-NavigationModel ::= SEQUENCE {
///     nonBroadcastIndFlag     INTEGER(0..1),
///     gnss-SatelliteList      GNSS-NavModelSatelliteList,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssNavigationModel {
    /// nonBroadcastIndFlag INTEGER(0..1).
    pub non_broadcast_ind_flag: u8,
    pub gnss_satellite_list: GnssNavModelSatelliteList,
}

impl GnssNavigationModel {
    const NON_BROADCAST: Constraint = Constraint::new(0, 1);
}

impl UperEncode for GnssNavigationModel {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no root OPTIONAL fields; no extension additions.
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(
            self.non_broadcast_ind_flag as i64,
            &Self::NON_BROADCAST,
        )?;
        self.gnss_satellite_list.encode_uper(e)?;
        Ok(())
    }
}

impl UperDecode for GnssNavigationModel {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            // DEFERRED: GNSS-NavigationModel extension additions not supported.
            return Err(PerError::DecodeError(
                "GNSS-NavigationModel extension additions not supported".into(),
            ));
        }
        let non_broadcast_ind_flag = d.decode_constrained_whole_number(&Self::NON_BROADCAST)? as u8;
        let gnss_satellite_list = GnssNavModelSatelliteList::decode_uper(d)?;
        Ok(GnssNavigationModel {
            non_broadcast_ind_flag,
            gnss_satellite_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bits(source: &[bool]) -> BitVec<u8, Msb0> {
        source.iter().copied().collect()
    }

    fn sample_keplerian() -> NavModelKeplerianSet {
        NavModelKeplerianSet {
            kepler_toe: 12345,
            kepler_w: -1_000_000_000,
            kepler_delta_n: -12345,
            kepler_m0: 2_000_000_000,
            kepler_omega_dot: -8_388_608,
            kepler_e: 4_000_000_000,
            kepler_i_dot: 8191,
            kepler_a_power_half: 4_294_967_295,
            kepler_i0: -2_147_483_648,
            kepler_omega0: 2_147_483_647,
            kepler_crs: -32768,
            kepler_cis: 32767,
            kepler_cus: -1,
            kepler_crc: 100,
            kepler_cic: -100,
            kepler_cuc: 0,
        }
    }

    fn sample_nav_clock() -> NavClockModel {
        NavClockModel {
            nav_toc: 37799,
            navaf2: -128,
            navaf1: 12345,
            navaf0: -2_097_152,
            nav_tgd: 127,
        }
    }

    fn sample_element() -> GnssNavModelSatelliteElement {
        GnssNavModelSatelliteElement {
            sv_id: SvId { satellite_id: 42 },
            sv_health: make_bits(&[true, false, true, false, false, true, true, false]),
            iod: make_bits(&[
                true, true, false, false, true, false, true, false, false, true, true,
            ]),
            gnss_clock_model: GnssClockModel::Nav(sample_nav_clock()),
            gnss_orbit_model: GnssOrbitModel::Keplerian(sample_keplerian()),
        }
    }

    fn round_trip<T: UperEncode + UperDecode + PartialEq + core::fmt::Debug>(value: &T) {
        let mut enc = UperEncoder::new();
        value.encode_uper(&mut enc).expect("encode");
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = T::decode_uper(&mut dec).expect("decode");
        assert_eq!(&decoded, value);
    }

    #[test]
    fn round_trip_keplerian_set() {
        round_trip(&sample_keplerian());
    }

    #[test]
    fn round_trip_nav_clock_model() {
        round_trip(&sample_nav_clock());
    }

    #[test]
    fn round_trip_clock_model_choice() {
        round_trip(&GnssClockModel::Nav(sample_nav_clock()));
    }

    #[test]
    fn round_trip_orbit_model_choice() {
        round_trip(&GnssOrbitModel::Keplerian(sample_keplerian()));
    }

    #[test]
    fn round_trip_satellite_element() {
        round_trip(&sample_element());
    }

    #[test]
    fn round_trip_navigation_model() {
        let value = GnssNavigationModel {
            non_broadcast_ind_flag: 1,
            gnss_satellite_list: GnssNavModelSatelliteList {
                elements: vec![
                    sample_element(),
                    GnssNavModelSatelliteElement {
                        sv_id: SvId { satellite_id: 0 },
                        sv_health: make_bits(&[false; 8]),
                        iod: make_bits(&[true; 11]),
                        gnss_clock_model: GnssClockModel::Nav(NavClockModel {
                            nav_toc: 0,
                            navaf2: 0,
                            navaf1: 0,
                            navaf0: 0,
                            nav_tgd: 0,
                        }),
                        gnss_orbit_model: GnssOrbitModel::Keplerian(NavModelKeplerianSet {
                            kepler_toe: 0,
                            kepler_w: 0,
                            kepler_delta_n: 0,
                            kepler_m0: 0,
                            kepler_omega_dot: 0,
                            kepler_e: 0,
                            kepler_i_dot: 0,
                            kepler_a_power_half: 0,
                            kepler_i0: 0,
                            kepler_omega0: 0,
                            kepler_crs: 0,
                            kepler_cis: 0,
                            kepler_cus: 0,
                            kepler_crc: 0,
                            kepler_cic: 0,
                            kepler_cuc: 0,
                        }),
                    },
                ],
            },
        };
        round_trip(&value);
    }
}
