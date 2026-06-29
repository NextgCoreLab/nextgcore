//! LMF positioning relay support (TS 23.273 §6 / §7).
//!
//! In 5GC location services the AMF is a **transparent relay** for two
//! positioning protocols, neither of which it interprets:
//!
//!   * **NRPPa** (TS 38.455) — LMF ↔ NG-RAN. Carried on N2 inside the NGAP
//!     `*NRPPaTransport` messages. UE-associated (procedures 8 / 50) when a
//!     specific UE is being positioned; non-UE-associated (procedures 5 / 47)
//!     for TRP / assistance information.
//!   * **LPP** (TS 37.355) — LMF ↔ UE. Carried on N1 inside DL/UL NAS
//!     Transport messages whose *payload container type* is `LPP` (0x03).
//!
//! This module owns the **downlink wire construction** (LMF→AMF→gNB/UE): given
//! the opaque positioning payloads the LMF supplies over
//! `Namf_Communication_N1N2MessageTransfer`, it produces the APER-encoded NGAP
//! PDU (NRPPa→gNB) or the DL NAS Transport (LPP→UE) ready for the existing N2 /
//! N1 send primitives.
//!
//! ## Strictly additive
//! Every entry point here is reached **only** on a positioning-specific trigger
//! (`ngapIeType == NRPPA_PDU`, an `nrppaInfo` N2 container, or NAS payload
//! container type `LPP`). None of those occur on the registration /
//! PDU-session / user-plane data path, so this code is dormant in the
//! reg+PDU+ping flow and cannot perturb it.
//!
//! ## Cross-task egress (deferred)
//! The actual SCTP egress to the gNB and the `Nlmf` uplink callback to the LMF
//! are owned by the NGAP server task / a future LMF consumer, not by the SBI
//! handler task that invokes these builders. The same SBI→NGAP hand-off gap
//! affects the existing paging N1/N2 path (its `pending_n1`/`pending_n2` are
//! likewise not yet drained to SCTP). Wiring that shared egress + the `Nlmf`
//! consumer is tracked as `lmfd-07`; conformance of the bytes built here is
//! proven by the round-trip / framing unit tests below, independent of egress.

use ogs_asn1c::ngap::ies::{AmfUeNgapId, NrppaPdu, RanUeNgapId, RoutingId};
use ogs_asn1c::ngap::pdu::{
    build_downlink_non_ue_associated_nrppa_transport,
    build_downlink_ue_associated_nrppa_transport, NgapPdu,
};
use ogs_asn1c::per::{AperEncode, AperEncoder};

/// NAS payload container type "LPP" (TS 24.501 Table 9.11.3.40.1).
pub const PAYLOAD_CONTAINER_TYPE_LPP: u8 = 0x03;

/// APER-encode a built NGAP PDU into the byte string carried over N2 SCTP.
fn encode_ngap(pdu: &NgapPdu) -> Option<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    pdu.encode_aper(&mut encoder).ok()?;
    Some(encoder.into_bytes().to_vec())
}

/// Build a `DownlinkUEAssociatedNRPPaTransport` (NGAP procedure 8, TS 38.413
/// §9.2.9.3) relaying an LMF-provided NRPPa PDU toward the UE's serving gNB.
///
/// `routing_id` is the LMF's opaque `RoutingID` (echoed unchanged so the gNB's
/// uplink reply can be routed back); `nrppa_pdu` is the opaque NRPPa message.
/// Returns the APER-encoded NGAP PDU ready for the N2 send primitive.
pub fn build_nrppa_dl_ue_associated(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    routing_id: &[u8],
    nrppa_pdu: &[u8],
) -> Option<Vec<u8>> {
    let pdu = build_downlink_ue_associated_nrppa_transport(
        AmfUeNgapId(amf_ue_ngap_id),
        RanUeNgapId(ran_ue_ngap_id),
        RoutingId::new(routing_id.to_vec()),
        NrppaPdu::new(nrppa_pdu.to_vec()),
    )
    .ok()?;
    encode_ngap(&pdu)
}

/// Build a `DownlinkNonUEAssociatedNRPPaTransport` (NGAP procedure 5, TS 38.413
/// §9.2.9.5) relaying an LMF-provided NRPPa PDU not tied to a specific UE
/// (e.g. TRP information / assistance). Returns the APER-encoded NGAP PDU.
pub fn build_nrppa_dl_non_ue_associated(routing_id: &[u8], nrppa_pdu: &[u8]) -> Option<Vec<u8>> {
    let pdu = build_downlink_non_ue_associated_nrppa_transport(
        RoutingId::new(routing_id.to_vec()),
        NrppaPdu::new(nrppa_pdu.to_vec()),
    )
    .ok()?;
    encode_ngap(&pdu)
}

/// Build a DL NAS Transport (TS 24.501 §8.2.10) carrying an LMF-provided LPP
/// message toward the UE. Thin, positioning-typed wrapper over the generic
/// 5GMM DL NAS Transport builder with payload container type `LPP`; no PDU
/// session ID and no 5GMM cause (the container is being *forwarded*, not
/// rejected). The returned NAS PDU still needs NAS security protection by the
/// caller before it goes on the wire.
pub fn build_lpp_dl_nas(lpp_pdu: &[u8]) -> Option<Vec<u8>> {
    crate::gmm_build::build_dl_nas_transport(None, PAYLOAD_CONTAINER_TYPE_LPP, lpp_pdu, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_asn1c::ngap::pdu::{
        parse_non_ue_associated_nrppa_transport, parse_ue_associated_nrppa_transport,
    };
    use ogs_asn1c::per::{AperDecode, AperDecoder};

    fn decode(bytes: &[u8]) -> NgapPdu {
        let mut decoder = AperDecoder::new(bytes);
        NgapPdu::decode_aper(&mut decoder).expect("NGAP PDU decode")
    }

    #[test]
    fn nrppa_dl_ue_associated_round_trips() {
        let routing = [0x00u8, 0x01];
        let nrppa = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let bytes = build_nrppa_dl_ue_associated(42, 7, &routing, &nrppa)
            .expect("build UE-associated NRPPa transport");
        assert!(!bytes.is_empty());

        let parsed = parse_ue_associated_nrppa_transport(&decode(&bytes))
            .expect("parse UE-associated NRPPa transport");
        assert_eq!(parsed.amf_ue_ngap_id.0, 42);
        assert_eq!(parsed.ran_ue_ngap_id.0, 7);
        assert_eq!(parsed.routing_id.0, routing.to_vec());
        assert_eq!(parsed.nrppa_pdu.0, nrppa.to_vec());
    }

    #[test]
    fn nrppa_dl_non_ue_associated_round_trips() {
        let routing = [0x05u8, 0x06, 0x07];
        let nrppa = [0x01u8, 0x02];
        let bytes = build_nrppa_dl_non_ue_associated(&routing, &nrppa)
            .expect("build non-UE-associated NRPPa transport");
        assert!(!bytes.is_empty());

        let parsed = parse_non_ue_associated_nrppa_transport(&decode(&bytes))
            .expect("parse non-UE-associated NRPPa transport");
        assert_eq!(parsed.routing_id.0, routing.to_vec());
        assert_eq!(parsed.nrppa_pdu.0, nrppa.to_vec());
    }

    #[test]
    fn lpp_dl_nas_frames_lpp_container() {
        // A small opaque LPP body (envelope bytes are irrelevant to framing).
        let lpp = [0x90u8, 0x01, 0x20];
        let nas = build_lpp_dl_nas(&lpp).expect("build LPP DL NAS Transport");
        // 5GMM EPD, plain header, then DL NAS Transport framing.
        assert_eq!(nas[0], 0x7E, "extended protocol discriminator = 5GMM");
        // Payload container type octet must select LPP ...
        assert_eq!(nas[3], PAYLOAD_CONTAINER_TYPE_LPP);
        // ... followed by the LV-E length and the verbatim LPP payload.
        assert_eq!(nas[4], 0x00);
        assert_eq!(nas[5], 0x03);
        assert_eq!(&nas[6..9], &lpp);
    }
}
