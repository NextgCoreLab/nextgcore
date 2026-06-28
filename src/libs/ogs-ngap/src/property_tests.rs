//! Property tests fencing the APER wire invariants the hand-rolled NGAP IE
//! encoders depend on (NGAP-08).
//!
//! These guard the *already-fixed* encoders against silent regressions:
//!
//! * **Non-extensible CHOICE index width** — a CHOICE without an ASN.1 `...`
//!   marker encodes its alternative as a bare constrained whole number with NO
//!   leading extension-presence bit. A spurious extension bit shifts the index
//!   by one bit position and misaligns the whole APER stream against a
//!   conformant peer. Affected IEs: `Cause` (6 alts -> 3-bit index),
//!   `GlobalRANNodeID`/`GNB-ID`/`NgENB-ID` (`ie::encode_global_ran_node_id`).
//! * **BIT-STRING octet alignment** — a BIT STRING whose upper bound exceeds
//!   16 bits is octet-aligned before its content (X.691 §16), e.g. the
//!   `gNB-ID(22..32)` and `macroNgENB-ID(20)` strings.
//!
//! AUTHOR GUIDANCE: when writing a *new* IE encoder, prefer the generic
//! `AperEncoder::encode_choice_index(idx, num_alts, /*extensible=*/false)` and
//! `AperEncoder::encode_bit_string(..)` helpers (in `ogs_asn1c::per`) rather
//! than hand-rolling `write_bit`/`write_bits`: those helpers already apply the
//! correct non-extensible index width and the >16-bit octet alignment that
//! these properties assert. (The primitive layer lives in `ogs-asn1c/src/per.rs`,
//! which is outside this crate; this guidance is colocated with the consumers.)

use ogs_asn1c::ngap::cause::{
    Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport,
};
use ogs_asn1c::ngap::ies::ProtocolIeContainer;
use ogs_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};
use proptest::prelude::*;

use crate::ie::{decode_global_ran_node_id, encode_global_ran_node_id};
use crate::types::GlobalRanNodeId;

const SAMPLE_PLMN: [u8; 3] = [0x00, 0xf1, 0x10];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// `Cause` is a non-extensible 6-alternative CHOICE: the index is a 3-bit
    /// constrained whole number in the top bits with NO leading extension bit.
    #[test]
    fn prop_cause_choice_index_no_extension_bit(sel in 0u8..5) {
        let (cause, idx) = match sel {
            0 => (Cause::RadioNetwork(CauseRadioNetwork::Unspecified), 0u8),
            1 => (Cause::Transport(CauseTransport::Unspecified), 1),
            2 => (Cause::Nas(CauseNas::Unspecified), 2),
            3 => (Cause::Protocol(CauseProtocol::Unspecified), 3),
            _ => (Cause::Misc(CauseMisc::Unspecified), 4),
        };
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        // 3-bit index occupies the top of octet 0; a spurious extension bit
        // would push it down and change this value.
        prop_assert_eq!(bytes[0] >> 5, idx);
        let mut decoder = AperDecoder::new(&bytes);
        prop_assert_eq!(Cause::decode_aper(&mut decoder).unwrap(), cause);
    }

    /// `GlobalRANNodeID`/`globalGNB-ID` is index 0 of a 4-alternative
    /// non-extensible CHOICE (2-bit `00`, no ext bit) and the 24-bit gNB-ID
    /// BIT STRING content is octet-aligned (occupies the final three octets).
    #[test]
    fn prop_global_gnb_id_index_width_and_octet_alignment(gnb_id in 0u32..(1u32 << 24)) {
        let id = GlobalRanNodeId::GlobalGnbId {
            plmn_identity: SAMPLE_PLMN,
            gnb_id,
            gnb_id_len: 24,
        };
        let mut container = ProtocolIeContainer::new();
        encode_global_ran_node_id(&mut container, &id).unwrap();
        let bytes = &container.ies[0].value;
        // 2-bit choice index `00` at the top of octet 0, no extension bit.
        prop_assert_eq!(bytes[0] >> 6, 0u8);
        // 24-bit (> 16) BIT STRING is octet-aligned: value sits big-endian in
        // the trailing three octets.
        prop_assert_eq!(&bytes[bytes.len() - 3..], &gnb_id.to_be_bytes()[1..4]);
        match decode_global_ran_node_id(&container.ies[0]).unwrap() {
            GlobalRanNodeId::GlobalGnbId { gnb_id: decoded, gnb_id_len, .. } => {
                prop_assert_eq!(decoded, gnb_id);
                prop_assert_eq!(gnb_id_len, 24);
            }
            other => prop_assert!(false, "expected GlobalGnbId, got {:?}", other),
        }
    }

    /// gNB-ID roundtrips at every length 22..=32 and never regrows a leading
    /// extension bit (index stays 2-bit `00`).
    #[test]
    fn prop_global_gnb_id_roundtrip_all_lengths(len in 22u8..=32, raw in any::<u32>()) {
        let mask = if len >= 32 { u32::MAX } else { (1u32 << len) - 1 };
        let gnb_id = raw & mask;
        let id = GlobalRanNodeId::GlobalGnbId {
            plmn_identity: SAMPLE_PLMN,
            gnb_id,
            gnb_id_len: len,
        };
        let mut container = ProtocolIeContainer::new();
        encode_global_ran_node_id(&mut container, &id).unwrap();
        prop_assert_eq!(container.ies[0].value[0] >> 6, 0u8);
        match decode_global_ran_node_id(&container.ies[0]).unwrap() {
            GlobalRanNodeId::GlobalGnbId { gnb_id: decoded, gnb_id_len, .. } => {
                prop_assert_eq!(decoded, gnb_id);
                prop_assert_eq!(gnb_id_len, len);
            }
            other => prop_assert!(false, "expected GlobalGnbId, got {:?}", other),
        }
    }

    /// `GlobalRANNodeID`/`globalNgENB-ID` is index 1 (2-bit `01`, no ext bit)
    /// and the 20-bit macroNgENB-ID BIT STRING roundtrips through alignment.
    #[test]
    fn prop_global_ng_enb_id_index_width(ng_enb_id in 0u32..(1u32 << 20)) {
        let id = GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity: SAMPLE_PLMN,
            ng_enb_id,
        };
        let mut container = ProtocolIeContainer::new();
        encode_global_ran_node_id(&mut container, &id).unwrap();
        prop_assert_eq!(container.ies[0].value[0] >> 6, 1u8);
        match decode_global_ran_node_id(&container.ies[0]).unwrap() {
            GlobalRanNodeId::GlobalNgEnbId { ng_enb_id: decoded, .. } => {
                prop_assert_eq!(decoded, ng_enb_id);
            }
            other => prop_assert!(false, "expected GlobalNgEnbId, got {:?}", other),
        }
    }
}
