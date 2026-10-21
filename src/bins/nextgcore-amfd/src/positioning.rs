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
//! ## Cross-task egress (wired)
//! Downlink egress is live: the Namf SBI handler enqueues the payloads built
//! here on `positioning_dl_queue` (`context.rs`) and the NGAP server task
//! drains it every pump loop in `process_positioning_downlinks`
//! (`ngap_path.rs`), delivering NRPPa to the serving gNB over the live SCTP
//! association and LPP to the UE as a security-protected DL NAS Transport.
//! The **uplink** leg is wired too (Wave-6 WS-A item A1): NGAP procedures 50
//! (`UplinkUEAssociatedNRPPaTransport`) and 47 (`UplinkNonUEAssociatedNRPPa-
//! Transport`) are dispatched in `ngap_path.rs` and relayed verbatim to the
//! LMF's registered `n2NotifyCallbackUri` as a multipart Namf N2InfoNotify
//! (`namf_server::send_n2_info_notify`, TS 29.518 §5.2.2.3.3), keyed off the
//! N1N2MessageSubscribe registry (fail-closed: no subscription → WARN + drop,
//! never an ErrorIndication toward the gNB).

/// NAS payload container type "LPP" (TS 24.501 Table 9.11.3.40.1).
pub const PAYLOAD_CONTAINER_TYPE_LPP: u8 = 0x03;

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
    crate::ngap_asn1::build_downlink_ue_nrppa_transport_asn1(
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        routing_id,
        nrppa_pdu,
    )
}

/// Build a `DownlinkNonUEAssociatedNRPPaTransport` (NGAP procedure 5, TS 38.413
/// §9.2.9.5) relaying an LMF-provided NRPPa PDU not tied to a specific UE
/// (e.g. TRP information / assistance). Returns the APER-encoded NGAP PDU.
pub fn build_nrppa_dl_non_ue_associated(routing_id: &[u8], nrppa_pdu: &[u8]) -> Option<Vec<u8>> {
    crate::ngap_asn1::build_downlink_non_ue_nrppa_transport_asn1(routing_id, nrppa_pdu)
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

    /// A DOWNLINK UE-ASSOCIATED NRPPA TRANSPORT derived by hand from X.691
    /// APER and TS 38.413 §9.2.9.1 / §9.4:
    /// `00` initiatingMessage, `08` procedure 8, `40` criticality ignore,
    /// `1F` open-type length 31; `00` SEQUENCE extension bit, `00 04` four IEs;
    /// IE 10 AMF-UE-NGAP-ID 42 (`00 2A`: 3-bit length 1, padded, one octet);
    /// IE 85 RAN-UE-NGAP-ID 7 (`00 07`: 2-bit length 1); IE 89 RoutingID
    /// `02 00 01`; IE 46 NRPPa-PDU `04 AA BB CC DD` -- each IE `id`, `00`
    /// criticality reject, open-type length, value.
    const DL_UE_GOLDEN: [u8; 35] = [
        0x00, 0x08, 0x40, 0x1F, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x2A, 0x00, 0x55,
        0x00, 0x02, 0x00, 0x07, 0x00, 0x59, 0x00, 0x03, 0x02, 0x00, 0x01, 0x00, 0x2E, 0x00, 0x05,
        0x04, 0xAA, 0xBB, 0xCC, 0xDD,
    ];

    /// A DOWNLINK NON UE-ASSOCIATED NRPPA TRANSPORT (procedure 5, §9.2.9.3):
    /// RoutingID `03 05 06 07`, NRPPa-PDU `02 01 02`, value length 18.
    const DL_NON_UE_GOLDEN: [u8; 22] = [
        0x00, 0x05, 0x40, 0x12, 0x00, 0x00, 0x02, 0x00, 0x59, 0x00, 0x04, 0x03, 0x05, 0x06, 0x07,
        0x00, 0x2E, 0x00, 0x03, 0x02, 0x01, 0x02,
    ];

    #[test]
    fn nrppa_dl_ue_associated_matches_hand_derived_bytes() {
        let bytes = build_nrppa_dl_ue_associated(42, 7, &[0x00, 0x01], &[0xAA, 0xBB, 0xCC, 0xDD])
            .expect("build UE-associated NRPPa transport");
        assert_eq!(bytes, DL_UE_GOLDEN.to_vec());
        assert_eq!(crate::ngap_asn1::extract_amf_ue_ngap_id(&bytes), Some(42));
        assert_eq!(crate::ngap_asn1::extract_ran_ue_ngap_id(&bytes), Some(7));
    }

    #[test]
    fn nrppa_dl_non_ue_associated_matches_hand_derived_bytes() {
        let bytes = build_nrppa_dl_non_ue_associated(&[0x05, 0x06, 0x07], &[0x01, 0x02])
            .expect("build non-UE-associated NRPPa transport");
        assert_eq!(bytes, DL_NON_UE_GOLDEN.to_vec());
        assert_eq!(crate::ngap_asn1::extract_amf_ue_ngap_id(&bytes), None);
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
