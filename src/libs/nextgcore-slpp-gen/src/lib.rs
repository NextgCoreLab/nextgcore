//! NextGCore SLPP codec generated from the TS 38.355 ASN.1 (#557)
//!
//! Every type here is produced at build time from `asn/slpp-19.2.0.asn` by the
//! same forked `asn1-compiler` that generates `nextgcore-lpp-gen`, with the
//! UPER codec (TS 38.355 §6.1: BASIC-PER, unaligned variant, for messages and
//! for IEs encoded as a basic production). It covers all eight modules of the
//! specification: `SLPP-PDU-Definitions`, the common, common SL-PRS methods,
//! SL-AoA, SL-RTT, SL-TDOA and SL-TOA contents, and
//! `NR-DiscoveryMessageMetaDataContents`.
//!
//! The method-specific contents travel as OCTET STRINGs inside the message
//! IEs (`-- Containing SL-RTT-ProvideLocationInformation` and so on), so a
//! receiver decodes twice: [`decode`] for the `SLPP-Message`, then
//! [`decode_ie`] for each container. [`encode_ie`] is the inverse.

/// The generated SLPP types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`SLPP-Message` is [`generated::SLPP_Message`]).
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
    include!(concat!(env!("OUT_DIR"), "/slpp.rs"));
}

pub use generated::SLPP_Message;

/// Decode one UPER-encoded SLPP-Message.
pub fn decode(bytes: &[u8]) -> Result<SLPP_Message, asn1_codecs::PerCodecError> {
    decode_ie(bytes)
}

/// Encode one SLPP-Message with UPER.
pub fn encode(msg: &SLPP_Message) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    encode_ie(msg)
}

/// Decode one SLPP IE encoded as a basic production (TS 38.355 §6.1), such
/// as the contents of an `sl-RTT-ProvideLocationInformation` OCTET STRING.
pub fn decode_ie<T: asn1_codecs::uper::UperCodec<Output = T>>(
    bytes: &[u8],
) -> Result<T, asn1_codecs::PerCodecError> {
    let mut data = asn1_codecs::PerCodecData::from_slice_uper(bytes);
    T::uper_decode(&mut data)
}

/// Encode one SLPP IE as a basic production. The result is a whole number of
/// octets, as TS 38.355 §6.1 requires, and an empty encoding (a SEQUENCE with
/// every OPTIONAL member absent and no extension marker) becomes the single
/// zero octet X.691 §10.1.3 prescribes for an outermost value.
pub fn encode_ie<T: asn1_codecs::uper::UperCodec>(
    ie: &T,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    let mut data = asn1_codecs::PerCodecData::new_uper();
    ie.uper_encode(&mut data)?;
    let bytes = data.into_bytes();
    Ok(if bytes.is_empty() { vec![0] } else { bytes })
}

#[cfg(test)]
mod tests;
