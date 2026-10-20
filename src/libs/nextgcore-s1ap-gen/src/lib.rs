//! NextGCore S1AP codec generated from the TS 36.413 ASN.1 (#514, stage 1)
//!
//! Every type here is produced at build time from `asn/s1ap-19.2.0.asn` by the
//! same forked `asn1-compiler` that generates `nextgcore-ngap-gen`, with the
//! APER codec. The root CHOICE therefore carries its key structurally, so a PDU
//! whose first bits are not the CHOICE index cannot be produced at all.
//!
//! #455 is why this exists: the hand-written S1AP codec omitted the X.691 §19.1
//! extension bit before every message's IE container on BOTH encode and decode.
//! Encoder and decoder agreed, every round trip passed, and no conformant eNB
//! could complete S1 Setup. A generated codec cannot make that mistake
//! symmetrically, because the bit comes from the schema's `...`, not from code.
//!
//! Stage 1 adds this crate with no call sites; mmed still goes through
//! `nextgcore-s1ap` and `nextgcore-asn1c`'s `s1ap` module. The following stages
//! move mmed's S1AP one message family at a time.

/// The generated S1AP types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`S1AP-PDU` is [`generated::S1AP_PDU`]), so the usual naming
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
    include!(concat!(env!("OUT_DIR"), "/s1ap.rs"));
}

pub use generated::S1AP_PDU;

/// Decode one APER-encoded S1AP PDU.
pub fn decode(bytes: &[u8]) -> Result<S1AP_PDU, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    S1AP_PDU::aper_decode(&mut data)
}

/// A protocol IE (or protocol extension) whose id the schema has no entry for,
/// skipped by [`decode_with_unknown_ies`] instead of failing the decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownIe {
    /// The ProtocolIE-ID (or ProtocolExtensionID) as received.
    pub id: i128,
    /// Its `Criticality` index as sent -- 0 = reject, 1 = ignore, 2 = notify --
    /// or `None` if the container carries none. Every S1AP IE container does.
    pub criticality: Option<u8>,
    /// The IE value's octets, exactly as framed on the wire.
    pub value: Vec<u8>,
}

/// Decode one APER-encoded S1AP PDU, skipping protocol IEs whose id the schema
/// does not know and returning them alongside the PDU (TS 36.413 §10.3.4).
///
/// The caller MUST inspect their criticality: an unknown IE marked `reject`
/// still means the procedure is to be rejected. Only a ProtocolIE or
/// extension-container entry is skippable; an unknown value anywhere else still
/// fails the decode.
pub fn decode_with_unknown_ies(
    bytes: &[u8],
) -> Result<(S1AP_PDU, Vec<UnknownIe>), asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    data.set_skip_unknown_open_types(true);
    let pdu = S1AP_PDU::aper_decode(&mut data)?;
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

/// Encode one S1AP PDU as APER.
pub fn encode(pdu: &S1AP_PDU) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::new_aper();
    pdu.aper_encode(&mut data)?;
    Ok(data.into_bytes())
}

#[cfg(test)]
mod tests;
