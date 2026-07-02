//! LPP A-GNSS assistance-data codec (3GPP TS 37.355 §6.5.2), UNALIGNED PER.
//!
//! Full-breadth A-GNSS assistance data: the shared [`common`] spine (GNSS-ID,
//! SBAS-ID, signal ids, system time, and the `A-GNSS-Provide/RequestAssistanceData`
//! + `GNSS-CommonAssistData` + `GNSS-GenericAssistData(Element)` containers) plus
//! the 13 per-GNSS assistance-data IEs, each in its own sibling module.
//!
//! Like the rest of `lpp`, this is hand-derived bit-by-bit from X.691 + the
//! TS 37.355 ASN.1. Rarely-used sub-options are modeled UNSUPPORTED (never
//! emitted, rejected on decode) and documented inline.
//!
//! # Golden wire vectors (Wave-6 H7)
//!
//! Four productions are now pinned by **hand-derived golden byte vectors**
//! (H5 TUAK-style dual derivation — see `.context/GOLDEN-VECTOR-METHOD.md`;
//! derivation B is `tests/lpp_agnss_golden_derivation_b.py`), catching the
//! symmetric bit-order / length-determinant errors that round-trip tests
//! cannot. Each has a tier-1 `encode == FROZEN` and a tier-2
//! `decode(FROZEN) == struct` test (`golden_*`):
//!
//!   * [`common::AGnssProvideAssistanceData`] — the spine/envelope: SEQUENCE
//!     preamble, `GNSS-GenericAssistData` SIZE(1..16) length determinant, the
//!     10-bit element OPTIONAL bitmap, nested `GNSS-ID`/`SBAS-ID` ENUMERATEDs,
//!   * [`reference_time::GnssReferenceTime`],
//!   * [`navigation_model::GnssNavigationModel`] (one satellite, one Keplerian
//!     set — exercises the CHOICE index + fixed BIT STRING machinery),
//!   * [`acquisition_assistance::GnssAcquisitionAssistance`] (one satellite).
//!
//! These four were chosen because they drive the spine's list / choice /
//! extension machinery that all 13 IEs share. The remaining 9 leaf IEs
//! (`almanac`, `auxiliary_information`, `data_bit_assistance`,
//! `differential_corrections`, `earth_orientation`, `ionospheric_model`,
//! `real_time_integrity`, `time_model`, `utc_model`) remain **round-trip-only**
//! (honest deferral) and should be golden-pinned opportunistically.

// The per-IE ASN.1 is quoted verbatim in doc comments (machine-generated from
// TS 37.355); allow the cosmetic markdown list-continuation lint on it.
#![allow(clippy::doc_lazy_continuation)]

pub mod acquisition_assistance;
pub mod almanac;
pub mod auxiliary_information;
pub mod body;
pub mod common;
pub mod data_bit_assistance;
pub mod differential_corrections;
pub mod earth_orientation;
pub mod ionospheric_model;
pub mod navigation_model;
pub mod real_time_integrity;
pub mod reference_location;
pub mod reference_time;
pub mod time_model;
pub mod utc_model;

// The shared spine (containers + GNSS-ID/SBAS-ID/system-time primitives) is the
// public face of the A-GNSS codec; leaf IE types are reached via their modules.
pub use common::*;
