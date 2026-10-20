//! NextGCore NRPPa codec generated from the TS 38.455 ASN.1 (#515)
//!
//! Every type here is produced at build time from `asn/nrppa-19.2.0.asn` by the
//! same forked `asn1-compiler` that generates `nextgcore-ngap-gen`, with the
//! APER codec (TS 38.455 §9.4: NRPPa uses Aligned PER).

/// The generated NRPPa types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`NRPPA-PDU` is [`generated::NRPPA_PDU`]).
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
    include!(concat!(env!("OUT_DIR"), "/nrppa.rs"));
}

pub use generated::NRPPA_PDU;

/// Decode one APER-encoded NRPPa PDU.
pub fn decode(bytes: &[u8]) -> Result<NRPPA_PDU, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    NRPPA_PDU::aper_decode(&mut data)
}

/// Encode one NRPPa PDU with APER.
pub fn encode(pdu: &NRPPA_PDU) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::new_aper();
    pdu.aper_encode(&mut data)?;
    Ok(data.into_bytes())
}

#[cfg(test)]
mod tests;
