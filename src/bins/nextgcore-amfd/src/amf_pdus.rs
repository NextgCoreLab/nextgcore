//! #417 stage B3.2: the NGAP PDUs and N2 SM transfers amfd SENDS (AMF->gNB),
//! derived by hand from the TS 38.413 ASN.1 and X.691 ALIGNED through
//! [`crate::aper_golden::Bits`], with the derivation written beside each
//! function. They replace the hand-written `nextgcore-ngap` builders the
//! `ngap_asn1.rs` tests used to compare the generated codec with. The gNB->AMF
//! direction lives in [`crate::gnb_pdus`].
//!
//! Which release: the ASN.1 is V17.9.0, the module vendored at
//! `libs/nextgcore-ngap-gen/asn/ngap-17.9.asn` (see its `PROVENANCE.md`), which
//! is what the generated codec is compiled from. The § numbers cite the prose
//! of TS 38.413 V19.3.0 (`38413-j30`).

pub(crate) mod handover;
pub(crate) mod ng_setup;
pub(crate) mod session;
pub(crate) mod transfer;
pub(crate) mod ue;
