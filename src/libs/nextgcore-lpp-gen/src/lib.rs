//! NextGCore LPP codec generated from the TS 37.355 ASN.1 (#515)
//!
//! Every type here is produced at build time from `asn/lpp-19.3.0.asn` by the
//! same forked `asn1-compiler` that generates `nextgcore-ngap-gen`, with the
//! UPER codec (TS 37.355 §6.1). It covers both modules of the specification:
//! `LPP-PDU-Definitions` and `LPP-Broadcast-Definitions` (posSIB contents).

/// The generated LPP types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`LPP-Message` is [`generated::LPP_Message`]).
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
    include!(concat!(env!("OUT_DIR"), "/lpp.rs"));
}

pub use generated::LPP_Message;

/// Decode one UPER-encoded LPP-Message.
pub fn decode(bytes: &[u8]) -> Result<LPP_Message, asn1_codecs::PerCodecError> {
    use asn1_codecs::uper::UperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_uper(bytes);
    LPP_Message::uper_decode(&mut data)
}

/// Encode one LPP-Message with UPER.
pub fn encode(msg: &LPP_Message) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use asn1_codecs::uper::UperCodec;
    let mut data = asn1_codecs::PerCodecData::new_uper();
    msg.uper_encode(&mut data)?;
    Ok(data.into_bytes())
}

#[cfg(test)]
mod tests;
