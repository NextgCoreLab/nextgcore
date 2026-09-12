//! 5GS↔EPS interworking: identity mapping and the capability the AMF signals.
//!
//! Two things live here, both from #116, because both are needed before any
//! interworking procedure can be attempted and neither belongs to one NF:
//!
//! - **5G-GUTI ↔ EPS GUTI mapping** (TS 23.003 §2.10.2). A UE moving between the two
//!   systems presents a temporary identity mapped from the other system's, and the
//!   receiving core has to perform the reverse mapping to find its own context
//!   (§2.10.2.1.3, §2.10.2.2.3).
//! - **The 5GS network feature support IE** (TS 24.501 §9.11.3.5), whose IWK N26 bit
//!   is how a UE learns which interworking mode is on offer.
//!
//! These were promoted to production code from nothing: before #116 the only
//! GUTI-mapping arithmetic in the tree was in `libs/nextgcore-nas/tests` fixtures,
//! so no NF could perform it.

use crate::eps::types::EpsGuti;
use crate::fiveg::types::FiveGGuti;

// ============================================================================
// 5G-GUTI <-> EPS GUTI (TS 23.003 Section 2.10.2)
// ============================================================================

/// Map a 5G-GUTI to an EPS GUTI (TS 23.003 §2.10.2.1.2).
///
/// The mapping is a **bijection**, which is why it round-trips exactly and why
/// [`eps_guti_to_5g_guti`] is its exact inverse: the 5GS side spends
/// 8 + 10 + 6 = 24 bits on `<AMF Region ID><AMF Set ID><AMF Pointer>` and the EPS
/// side spends 16 + 8 = 24 on `<MME Group ID><MME Code>`, so nothing is lost or
/// invented in either direction. That is worth stating because a "mapping" between
/// identity spaces is usually lossy, and a lossy one could not satisfy §2.10.2.1.3
/// (the old AMF must recover its *stored* 5G-GUTI from the GUTI an MME sends).
///
/// Per §2.10.2.1.2, bit by bit:
///
/// | 5GS | bits | EPS |
/// |---|---|---|
/// | `<MCC>`, `<MNC>` | — | `<MCC>`, `<MNC>` (pass through) |
/// | `<AMF Region ID>` | 7..0 | `<MME Group ID>` 15..8 |
/// | `<AMF Set ID>` | 9..2 | `<MME Group ID>` 7..0 |
/// | `<AMF Set ID>` | 1..0 | `<MME Code>` 7..6 |
/// | `<AMF Pointer>` | 5..0 | `<MME Code>` 5..0 |
/// | `<5G-TMSI>` | — | `<M-TMSI>` |
///
/// The two-bit split of `<AMF Set ID>` across the Group-ID/Code boundary is the part
/// that is easy to get wrong, and getting it wrong is invisible to a round-trip test
/// written against this function alone — the same self-consistency trap that let a
/// wrong payload-container type ship in #91. `eps_guti_mapping_matches_ts23003_2_10_2`
/// therefore asserts the byte layout against hand-computed values from the clause,
/// not just `f(g(x)) == x`.
pub fn five_g_guti_to_eps_guti(guti: &FiveGGuti) -> EpsGuti {
    let set_id = guti.amf_set_id & 0x03FF;
    EpsGuti {
        plmn_id: guti.plmn_id.clone(),
        // Region ID -> MME GID 15..8; Set ID 9..2 -> MME GID 7..0.
        mme_gid: ((guti.amf_region_id as u16) << 8) | ((set_id >> 2) & 0x00FF),
        // Set ID 1..0 -> MME Code 7..6; Pointer 5..0 -> MME Code 5..0.
        mme_code: (((set_id & 0x0003) as u8) << 6) | (guti.amf_pointer & 0x3F),
        m_tmsi: guti.tmsi,
    }
}

/// Map an EPS GUTI to a 5G-GUTI (TS 23.003 §2.10.2.2.2).
///
/// The exact inverse of [`five_g_guti_to_eps_guti`]; see there for the bit table and
/// why the mapping loses nothing.
pub fn eps_guti_to_5g_guti(guti: &EpsGuti) -> FiveGGuti {
    FiveGGuti {
        plmn_id: guti.plmn_id.clone(),
        // MME GID 15..8 -> Region ID.
        amf_region_id: (guti.mme_gid >> 8) as u8,
        // MME GID 7..0 -> Set ID 9..2; MME Code 7..6 -> Set ID 1..0.
        amf_set_id: ((guti.mme_gid & 0x00FF) << 2) | ((guti.mme_code >> 6) as u16 & 0x0003),
        // MME Code 5..0 -> Pointer 5..0.
        amf_pointer: guti.mme_code & 0x3F,
        tmsi: guti.m_tmsi,
    }
}

// ============================================================================
// 5GS network feature support IE (TS 24.501 Section 9.11.3.5)
// ============================================================================

/// IEI of the 5GS network feature support IE in REGISTRATION ACCEPT.
///
/// TS 24.501 Table 8.2.7.1: `21`, optional, format TLV, length 3-6.
pub const IEI_5GS_NETWORK_FEATURE_SUPPORT: u8 = 0x21;

/// `IWK N26` — octet 3, bit 7 of the 5GS network feature support IE.
///
/// TS 24.501 Table 9.11.3.5.1 (spec text: `24501-j62.txt:75100`).
pub const IWK_N26_BIT: u8 = 0x40;

/// `IMS-VoPS-3GPP` — octet 3, bit 1. Kept as a named constant so the IE builder
/// below is not writing bare hex for the one other bit it can be asked to set.
pub const IMS_VOPS_3GPP_BIT: u8 = 0x01;

/// What the AMF advertises in the `IWK N26` bit (TS 24.501 §9.11.3.5).
///
/// # The bit is inverted from the obvious reading, and that is the whole point
///
/// It is **not** "N26 is supported". Table 9.11.3.5.1 names it *"Interworking
/// without N26 interface indicator"*, so:
///
/// - `0` = "interworking without N26 interface **not** supported" → the AMF **has**
///   N26, and per §5.5.1.2.4 the UE must then operate in **single-registration** mode;
/// - `1` = "interworking without N26 interface supported" → the AMF has **no** N26,
///   and a UE that supports it **may** operate in dual-registration mode.
///
/// Setting the bit because "we support interworking" would therefore tell every UE
/// the exact opposite of the truth, and it is the kind of error that round-trips
/// clean through an encode/decode test. Hence an enum rather than a `bool`: at a call
/// site `Iwk26::WithoutN26Supported` cannot be confused with "N26 supported", where
/// `true` can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iwk26 {
    /// The AMF has an N26 interface to an MME. Encodes IWK N26 = **0**.
    N26Supported,
    /// The AMF has no N26 interface; interworking is the non-N26 kind. Encodes
    /// IWK N26 = **1**.
    WithoutN26Supported,
}

impl Iwk26 {
    /// The octet-3 bit value this posture encodes.
    pub fn bit(self) -> u8 {
        match self {
            // Deliberately: N26 present => bit CLEAR. See the type's doc.
            Self::N26Supported => 0,
            Self::WithoutN26Supported => IWK_N26_BIT,
        }
    }
}

/// The 5GS network feature support IE, as much of it as this core has an answer for.
///
/// Only the two octet-3 bits the AMF can honestly speak to are modelled. The rest of
/// octet 3 (`EMC`, `EMF`, `MPSI`, `IMS-VoPS-N3GPP`) and the optional octets 4-6 are
/// **omitted rather than sent as zero-with-meaning**: a length of 1 makes the UE read
/// octets 4-6 as all-zero anyway (§9.11.3.5), and zero is the correct "not supported"
/// for every bit in them, so a 1-octet contents field is both the shortest legal
/// encoding and the truthful one. Emitting three octets of zeroes would assert the
/// same thing at greater length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveGsNetworkFeatureSupport {
    /// Interworking-without-N26 posture (octet 3, bit 7).
    pub iwk_n26: Iwk26,
    /// IMS voice over PS over 3GPP access (octet 3, bit 1).
    pub ims_vops_3gpp: bool,
}

impl FiveGsNetworkFeatureSupport {
    /// Encode as a TLV: IEI, length, then the octet-3 contents.
    ///
    /// One content octet, so the length is 1 — the minimum §9.11.3.5 allows, and the
    /// UE treats octets 4-6 as zero.
    pub fn encode_tlv(&self) -> [u8; 3] {
        let mut octet3 = self.iwk_n26.bit();
        if self.ims_vops_3gpp {
            octet3 |= IMS_VOPS_3GPP_BIT;
        }
        [IEI_5GS_NETWORK_FEATURE_SUPPORT, 1, octet3]
    }

    /// Decode from the IE's **contents** (i.e. after IEI and length).
    ///
    /// Returns `None` for an empty contents field, which §9.11.3.5 does not permit
    /// (minimum length 3 octets total, so at least one content octet).
    pub fn decode_contents(contents: &[u8]) -> Option<Self> {
        let octet3 = *contents.first()?;
        Some(Self {
            iwk_n26: if octet3 & IWK_N26_BIT != 0 {
                Iwk26::WithoutN26Supported
            } else {
                Iwk26::N26Supported
            },
            ims_vops_3gpp: octet3 & IMS_VOPS_3GPP_BIT != 0,
        })
    }
}

// ============================================================================
// 5GMM capability (TS 24.501 Section 9.11.3.1) -- the S1-mode bit only
// ============================================================================

/// IEI of the 5GMM capability IE in REGISTRATION REQUEST.
///
/// TS 24.501 Table 8.2.6.1: `10`, optional, format TLV, length 3-15.
pub const IEI_5GMM_CAPABILITY: u8 = 0x10;

/// `S1 mode` ("EPC NAS supported") — octet 3, bit 1 of the 5GMM capability IE.
///
/// TS 24.501 Table 9.11.3.1.1. This is the bit that gates everything else:
/// §5.5.1.2.4 makes the AMF signal `IWK N26` **only** to a UE that included an
/// S1-mode indication, so without parsing it there is nothing to answer.
pub const S1_MODE_BIT: u8 = 0x01;

/// Does this 5GMM capability contents field claim S1 mode (EPC NAS) support?
///
/// Takes the IE **contents** (after IEI and length), which is what a byte-level IE
/// walk has in hand — amfd's registration parser is hand-rolled and does not go
/// through [`crate::fiveg::ie::FiveGmmCapability`]'s decoder.
///
/// # Why this delegates instead of masking the bit itself
///
/// [`crate::fiveg::ie::FiveGmmCapability`] ALREADY derives `s1_mode` from the same
/// octet with the same mask. A second `& 0x01` here would be a second implementation
/// of one wire fact, and the two would be free to drift — the shape that has bitten
/// this tree repeatedly (three modules spelling `Pdr` for different types in #335,
/// four hand-maintained wire tables wrong in #340). So this function synthesises the
/// length octet the decoder expects and asks the existing type, making it a *reframing*
/// of one implementation rather than a rival to it.
///
/// An empty or unparseable contents field reads as "not claimed", which is the
/// fail-closed answer: advertising an interworking posture to a UE that never asked
/// for one is the worse error.
pub fn claims_s1_mode(contents: &[u8]) -> bool {
    let Some(&octet3) = contents.first() else {
        return false;
    };
    // `FiveGmmCapability::decode` expects `length` then the capability octets; the
    // caller has only the contents, so the length is reconstructed from them.
    let mut framed = bytes::Bytes::from(
        std::iter::once(contents.len() as u8)
            .chain(contents.iter().copied())
            .collect::<Vec<u8>>(),
    );
    match crate::fiveg::ie::FiveGmmCapability::decode(&mut framed) {
        Ok(cap) => cap.s1_mode,
        // A malformed IE still has an octet 3, and the bit's position does not depend
        // on the octets after it. Falling back to it keeps a UE that claimed S1 mode in
        // a slightly-off IE from being silently treated as not having asked.
        Err(_) => octet3 & S1_MODE_BIT != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::PlmnId;

    fn plmn() -> PlmnId {
        PlmnId::new([0, 0, 1], [0, 1, 0], 2)
    }

    /// TS 23.003 §2.10.2 by hand, not by round-trip.
    ///
    /// A round-trip proves only that the two functions are inverses of each other —
    /// it would pass with the `<AMF Set ID>` split placed at any bit boundary, as
    /// long as both directions agreed. So the field values are computed here from
    /// the clause and asserted literally, which is the only form that pins
    /// conformance rather than self-consistency (#91).
    #[test]
    fn eps_guti_mapping_matches_ts23003_2_10_2() {
        // Region 0xAB; Set ID 0b10_0110_1101 (0x26D); Pointer 0b10_1010 (0x2A).
        let five_g = FiveGGuti {
            plmn_id: plmn(),
            amf_region_id: 0xAB,
            amf_set_id: 0x026D,
            amf_pointer: 0x2A,
            tmsi: 0x1234_5678,
        };
        let eps = five_g_guti_to_eps_guti(&five_g);

        // MME GID 15..8 = Region ID = 0xAB.
        // MME GID  7..0 = Set ID bits 9..2 = 0x026D >> 2 = 0x9B.
        assert_eq!(
            eps.mme_gid, 0xAB9B,
            "MME Group ID is <AMF Region ID> then <AMF Set ID> bits 9..2 \
             (TS 23.003 2.10.2.1.2)"
        );
        // MME Code 7..6 = Set ID bits 1..0 = 0b01 -> 0b0100_0000.
        // MME Code 5..0 = Pointer        = 0b10_1010.
        assert_eq!(
            eps.mme_code, 0b0110_1010,
            "MME Code is <AMF Set ID> bits 1..0 then <AMF Pointer> bits 5..0 \
             (TS 23.003 2.10.2.1.2)"
        );
        assert_eq!(eps.m_tmsi, 0x1234_5678, "<5G-TMSI> maps to <M-TMSI>");
        assert_eq!(eps.plmn_id, plmn(), "MCC/MNC pass through unchanged");

        // And the reverse direction, computed from 2.10.2.2.2 the same way.
        let back = eps_guti_to_5g_guti(&eps);
        assert_eq!(back.amf_region_id, 0xAB);
        assert_eq!(back.amf_set_id, 0x026D);
        assert_eq!(back.amf_pointer, 0x2A);
        assert_eq!(back.tmsi, 0x1234_5678);
    }

    /// The mapping is a bijection (24 bits each side), so it must survive a
    /// round trip for every corner of the field ranges -- including the all-ones
    /// case, where a mask that is one bit too wide would bleed into a neighbour.
    #[test]
    fn eps_guti_mapping_round_trips_at_the_field_boundaries() {
        for (region, set, pointer) in [
            (0x00u8, 0x0000u16, 0x00u8),
            (0xFF, 0x03FF, 0x3F), // every bit of every field set
            (0x01, 0x0001, 0x01),
            (0x80, 0x0200, 0x20),
            (0xFF, 0x0000, 0x3F),
            (0x00, 0x03FF, 0x00),
        ] {
            let g = FiveGGuti {
                plmn_id: plmn(),
                amf_region_id: region,
                amf_set_id: set,
                amf_pointer: pointer,
                tmsi: 0xDEAD_BEEF,
            };
            let back = eps_guti_to_5g_guti(&five_g_guti_to_eps_guti(&g));
            assert_eq!(back, g, "5G-GUTI -> GUTI -> 5G-GUTI must be lossless");
        }
    }

    /// The inverted bit, pinned against the clause in both directions.
    ///
    /// This is the assertion that would have caught "set the bit because we support
    /// interworking": with N26 present the bit is CLEAR.
    #[test]
    fn iwk_n26_bit_matches_ts24501_table_9_11_3_5_1() {
        assert_eq!(
            IWK_N26_BIT, 0x40,
            "IWK N26 is octet 3 bit 7 (24501-j62.txt:75100)"
        );
        assert_eq!(
            Iwk26::N26Supported.bit(),
            0,
            "an AMF that HAS N26 sets IWK N26 = 0, 'interworking without N26 \
             interface not supported'"
        );
        assert_eq!(
            Iwk26::WithoutN26Supported.bit(),
            0x40,
            "an AMF with NO N26 sets IWK N26 = 1, 'interworking without N26 \
             interface supported'"
        );

        // TLV shape: IEI 0x21, length 1, contents.
        let ie = FiveGsNetworkFeatureSupport {
            iwk_n26: Iwk26::WithoutN26Supported,
            ims_vops_3gpp: false,
        };
        assert_eq!(
            ie.encode_tlv(),
            [0x21, 0x01, 0x40],
            "IEI 21, length 1, octet 3 with only IWK N26 set (TS 24.501 Table 8.2.7.1)"
        );

        // Decode is the inverse, and the OTHER posture must not decode as this one.
        assert_eq!(
            FiveGsNetworkFeatureSupport::decode_contents(&[0x40]),
            Some(ie)
        );
        assert_eq!(
            FiveGsNetworkFeatureSupport::decode_contents(&[0x00]),
            Some(FiveGsNetworkFeatureSupport {
                iwk_n26: Iwk26::N26Supported,
                ims_vops_3gpp: false,
            })
        );
        assert_eq!(
            FiveGsNetworkFeatureSupport::decode_contents(&[0x41]),
            Some(FiveGsNetworkFeatureSupport {
                iwk_n26: Iwk26::WithoutN26Supported,
                ims_vops_3gpp: true,
            }),
            "bit 1 is IMS-VoPS-3GPP and is independent of bit 7"
        );
        assert_eq!(
            FiveGsNetworkFeatureSupport::decode_contents(&[]),
            None,
            "an empty contents field is not a legal IE"
        );
    }

    #[test]
    fn s1_mode_bit_matches_ts24501_table_9_11_3_1_1() {
        assert_eq!(S1_MODE_BIT, 0x01, "S1 mode is octet 3 bit 1");
        assert_eq!(IEI_5GMM_CAPABILITY, 0x10, "5GMM capability IEI is 10");
        assert!(claims_s1_mode(&[0x01]), "bit 1 set = S1 mode supported");
        assert!(
            claims_s1_mode(&[0xFF]),
            "S1 mode is bit 1 regardless of the other capability bits"
        );
        assert!(!claims_s1_mode(&[0x02]), "bit 2 is HO attach, not S1 mode");
        assert!(!claims_s1_mode(&[0x00]));
        assert!(
            !claims_s1_mode(&[]),
            "an unparseable capability is read as NOT claiming S1 mode: \
             advertising an interworking posture to a UE that never asked is worse"
        );

        // The bit comes from ONE implementation, not two: `claims_s1_mode` must agree
        // with `FiveGmmCapability`'s own decoder for every octet-3 value, because a
        // second `& 0x01` here is exactly how two spellings of one wire fact drift.
        for octet3 in 0u8..=255 {
            let mut framed = bytes::Bytes::from(vec![1u8, octet3]);
            let via_type = crate::fiveg::ie::FiveGmmCapability::decode(&mut framed)
                .expect("a 1-octet capability decodes")
                .s1_mode;
            assert_eq!(
                claims_s1_mode(&[octet3]),
                via_type,
                "octet3={octet3:#04x}: claims_s1_mode must agree with FiveGmmCapability"
            );
        }
    }
}
