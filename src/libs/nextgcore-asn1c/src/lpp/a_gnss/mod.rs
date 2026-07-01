//! LPP A-GNSS assistance-data codec (3GPP TS 37.355 §6.5.2), UNALIGNED PER.
//!
//! Full-breadth A-GNSS assistance data: the shared [`common`] spine (GNSS-ID,
//! SBAS-ID, signal ids, system time, and the `A-GNSS-Provide/RequestAssistanceData`
//! + `GNSS-CommonAssistData` + `GNSS-GenericAssistData(Element)` containers) plus
//! the 13 per-GNSS assistance-data IEs, each in its own sibling module.
//!
//! Like the rest of `lpp`, this is hand-derived bit-by-bit from X.691 + the
//! TS 37.355 ASN.1; there is no golden wire vector in-repo and no reference
//! encoder, so the round-trip tests attest structural self-consistency (they
//! cannot catch a symmetric bit-field error). Rarely-used sub-options are
//! modeled UNSUPPORTED (never emitted, rejected on decode) and documented inline.

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
