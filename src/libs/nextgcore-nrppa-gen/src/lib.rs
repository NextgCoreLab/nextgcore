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

/// A protocol IE (or protocol extension) whose id the schema has no entry for,
/// skipped by [`decode_with_unknown_ies`] instead of failing the decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownIe {
    /// The ProtocolIE-ID (or ProtocolExtensionID) as received.
    pub id: i128,
    /// Its `Criticality` index as sent -- 0 = reject, 1 = ignore, 2 = notify --
    /// or `None` if the container carries none. Every NRPPa IE container does.
    pub criticality: Option<u8>,
    /// The IE value's octets, exactly as framed on the wire.
    pub value: Vec<u8>,
}

/// Decode one APER-encoded NRPPa PDU, skipping protocol IEs whose id the schema
/// does not know and returning them alongside the PDU (TS 38.455 §10.3.4).
///
/// The rest of the message decodes as if the unknown IEs were absent. The caller
/// MUST inspect their criticality: an unknown IE marked `reject` still means the
/// procedure is to be rejected. An unknown id is only skippable as an entry of a
/// protocol-IE or extension container; anywhere else -- an unknown procedure
/// code, for one -- the decode still fails.
pub fn decode_with_unknown_ies(
    bytes: &[u8],
) -> Result<(NRPPA_PDU, Vec<UnknownIe>), asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    data.set_skip_unknown_open_types(true);
    let pdu = NRPPA_PDU::aper_decode(&mut data)?;
    let unknown = data
        .take_unknown_open_types()
        .into_iter()
        .map(|u| UnknownIe {
            id: u.key,
            criticality: u.criticality.and_then(|c| u8::try_from(c).ok()),
            value: u.value,
        })
        .collect();
    Ok((pdu, unknown))
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
