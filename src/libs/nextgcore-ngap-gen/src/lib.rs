//! NextGCore NGAP codec generated from the TS 38.413 ASN.1 (#417, stage 1)
//!
//! Every type here is produced at build time from `asn/ngap-17.9.asn` by the
//! same forked `asn1-compiler` nextgsim uses, with the APER codec. The root
//! CHOICE therefore carries its key structurally:
//!
//! ```text
//! pub enum NGAP_PDU {
//!     #[asn(key = 0, ...)] InitiatingMessage(..),
//!     #[asn(key = 1, ...)] SuccessfulOutcome(..),
//!     #[asn(key = 2, ...)] UnsuccessfulOutcome(..),
//! }
//! ```
//!
//! So a PDU whose byte 0 is not the CHOICE index cannot be produced at all. With
//! a hand-written codec that is only true while someone keeps asserting it.
//!
//! Stage 1 added this crate with no call sites. Stage 2 moved the first family:
//! amfd's NG Setup Response and NG Setup Failure encoders. Everything else still
//! goes through `nextgcore-ngap` and `nextgcore-asn1c`'s `ngap` module.
//!
//! Two limits of the generated codec that every later family must handle,
//! found by stage 2's byte-equivalence tests: it does not enforce the SIZE
//! bounds of a SEQUENCE OF (an empty or over-long list encodes without error),
//! and it cannot encode an ENUMERATED value past the root (so Cause extension
//! values such as radioNetwork 45/46 fail to encode). Its decoder also fails
//! the whole PDU on an IE id outside the schema, where TS 38.413 §10.3.4 says
//! to ignore a not-comprehended IE marked "ignore".

/// The generated NGAP types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`NGAP-PDU` is [`generated::NGAP_PDU`]), so the usual naming
/// lints do not apply.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused,
    non_camel_case_types,
    non_snake_case
)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ngap.rs"));
}

pub use generated::NGAP_PDU;

/// Decode one APER-encoded NGAP PDU.
pub fn decode(bytes: &[u8]) -> Result<NGAP_PDU, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    NGAP_PDU::aper_decode(&mut data)
}

/// Encode one NGAP PDU as APER.
pub fn encode(pdu: &NGAP_PDU) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::new_aper();
    pdu.aper_encode(&mut data)?;
    Ok(data.into_bytes())
}

#[cfg(test)]
mod tests;
