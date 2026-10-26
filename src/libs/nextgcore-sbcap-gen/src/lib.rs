//! NextGCore SBc-AP codec generated from the TS 29.168 ASN.1 (#1071, stage 1).
//!
//! Every type here is produced at build time from `asn/sbcap-19.0.0.asn` (the
//! six SBC-AP modules of TS 29.168 V19.0.0 §4.4.3-§4.4.8, see
//! `asn/PROVENANCE.md`) by the forked `asn1-compiler` that generates
//! `nextgcore-s1ap-gen`, with the APER codec: SBc-AP's transfer syntax is
//! BASIC-PER Aligned (TS 29.168 §4.4.9).
//!
//! Stage 1 adds the crate with no call sites. Stage 2 gives mmed the SBc-AP
//! association with the CBC (the CBC establishes it, TS 29.168 §3) and its
//! procedures, among them the PWS Restart Indication relay (TS 23.007
//! §15A.1.2).

/// The generated SBc-AP types. Names follow the ASN.1 with hyphens mapped to
/// underscores (`SBC-AP-PDU` is [`generated::SBC_AP_PDU`]).
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
    include!(concat!(env!("OUT_DIR"), "/sbcap.rs"));
}

pub use generated::SBC_AP_PDU;

/// The SCTP port registered for SBc-AP (TS 29.168 §3).
pub const SBCAP_PORT: u16 = 29168;
/// The SCTP payload protocol identifier registered for SBc-AP (TS 29.168 §3).
pub const SBCAP_PPID: u32 = 24;

/// Decode one APER-encoded SBc-AP PDU.
pub fn decode(bytes: &[u8]) -> Result<SBC_AP_PDU, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes);
    SBC_AP_PDU::aper_decode(&mut data)
}

/// Encode one SBc-AP PDU with APER.
pub fn encode(pdu: &SBC_AP_PDU) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::new_aper();
    pdu.aper_encode(&mut data)?;
    Ok(data.into_bytes())
}

#[cfg(test)]
mod tests;
