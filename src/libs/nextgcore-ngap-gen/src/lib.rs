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
//! **Stage 1 moves no call sites.** `nextgcore-ngap` and `nextgcore-asn1c`'s
//! `ngap` module remain the codecs the daemons use. This crate exists so that
//! later stages can migrate one procedure family at a time against a codec that
//! is already built and tested in the workspace.

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
