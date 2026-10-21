//! NextGCore E-UTRA RRC codec generated from the TS 36.331 V19.4.0 ASN.1 (#585).
//!
//! Every type is produced at build time from `asn/` by the same pinned
//! asn1-compiler that generates `nextgcore-ngap-gen`, with the UPER codec. The
//! schema is the one nextgsim generates its RRC codec from (see
//! `asn/PROVENANCE.md`), so both ends of the air interface and the core agree
//! on the transfer syntax. It exists for the UCMF, which transcodes UE radio
//! capability between TS 36.331 and TS 38.331 and derives the UE radio
//! capability for paging (TS 23.501 §5.4.4.1a).

/// The generated types. Names follow the ASN.1 with hyphens mapped to
/// underscores.
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
    include!(concat!(env!("OUT_DIR"), "/lte_rrc.rs"));
}

/// Decode one UPER-encoded value of `T`.
pub fn decode<T: asn1_codecs::uper::UperCodec<Output = T>>(
    bytes: &[u8],
) -> Result<T, asn1_codecs::PerCodecError> {
    let mut data = asn1_codecs::PerCodecData::from_slice_uper(bytes);
    T::uper_decode(&mut data)
}

/// Encode one value of `T` with UPER.
pub fn encode<T: asn1_codecs::uper::UperCodec>(
    value: &T,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    let mut data = asn1_codecs::PerCodecData::new_uper();
    value.uper_encode(&mut data)?;
    Ok(data.into_bytes())
}
