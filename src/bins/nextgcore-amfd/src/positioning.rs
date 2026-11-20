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

/// Additional information IEI (TS 24.501 §9.11.2.1, a type 4 TLV): IEI 0x24 in
/// both DL NAS TRANSPORT (Table 8.2.11.1.1) and UL NAS TRANSPORT (Table
/// 8.2.10.1.1). For LPP and SLPP it carries the routing information (#2256).
pub const ADDITIONAL_INFORMATION_IEI: u8 = 0x24;

/// Append an Additional information IE carrying `lcs_correlation_id` to a DL
/// NAS TRANSPORT (TS 24.501 §5.4.5.3.2 case c: "set the Additional information
/// IE to an LCS correlation identifier received from the LMF from which the LPP
/// message was received"). The value is the identifier's octets, which is what
/// the UE hands back in the UL NAS TRANSPORT's Additional information (§5.4.5.2.2
/// case c) and [`routing_correlation`] reads.
///
/// Every IE ahead of it in Table 8.2.11.1.1 is absent from a positioning
/// downlink, so it goes right after the payload container. An identifier that
/// does not fit the one-octet length (TS 29.572 allows 255 characters, the IE
/// 255 octets) or is empty is left out and logged, never truncated: a cut
/// identifier would route the UE's answer to no LMF at all.
pub fn append_additional_information(nas: &mut Vec<u8>, lcs_correlation_id: &str) {
    match u8::try_from(lcs_correlation_id.len()) {
        Ok(0) => {}
        Ok(len) => {
            nas.push(ADDITIONAL_INFORMATION_IEI);
            nas.push(len);
            nas.extend_from_slice(lcs_correlation_id.as_bytes());
        }
        Err(_) => log::warn!(
            "DL NAS Transport: LCS correlation id of {} octets does not fit the Additional \
             information IE (max 255); sent without it",
            lcs_correlation_id.len()
        ),
    }
}

/// The LCS correlation identifier a UL NAS TRANSPORT's Additional information
/// value names (TS 24.501 §5.4.5.2.5 cases c and c1: the AMF sends the
/// container "to the LMF associated with the routing information included in
/// the Additional information IE"). The inverse of
/// [`append_additional_information`]. `None` for an empty value or one that is
/// not UTF-8: no downlink of this AMF put it there, and TS 29.572 CorrelationID
/// is a string.
pub fn routing_correlation(value: &[u8]) -> Option<String> {
    std::str::from_utf8(value)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Build a DL NAS Transport (TS 24.501 §8.2.10) carrying an LMF-provided LPP
/// message toward the UE. Thin, positioning-typed wrapper over the generic
/// 5GMM DL NAS Transport builder with payload container type `LPP`; no PDU
/// session ID and no 5GMM cause (the container is being *forwarded*, not
/// rejected). `lcs_correlation_id`, the LMF's, goes in Additional information
/// (§5.4.5.3.2 case c, #2256). The returned NAS PDU still needs NAS security
/// protection by the caller before it goes on the wire.
pub fn build_lpp_dl_nas(lpp_pdu: &[u8], lcs_correlation_id: Option<&str>) -> Option<Vec<u8>> {
    let mut nas = crate::gmm_build::build_dl_nas_transport(
        None,
        PAYLOAD_CONTAINER_TYPE_LPP,
        lpp_pdu,
        None,
        None,
    )?;
    if let Some(corr) = lcs_correlation_id {
        append_additional_information(&mut nas, corr);
    }
    Some(nas)
}

/// NAS payload container type "SLPP message container" (TS 24.501 k00
/// §9.11.3.40, value `1100`, #557).
pub const PAYLOAD_CONTAINER_TYPE_SLPP: u8 = 0x0C;

/// Additional information IEI in DL NAS TRANSPORT (TS 24.501 §8.2.11.1,
/// §9.11.2.1, a type 4 TLV).
pub const IEI_ADDITIONAL_INFORMATION: u8 = 0x24;

/// Build a DL NAS Transport carrying an LMF-provided SLPP message (TS 24.501
/// k00 §5.4.5.3.2 case c1, #557). The AMF:
/// a) sets the Payload container type IE to "SLPP message container";
/// b) sets the Payload container IE to the SLPP message payload received from
///    the LMF;
/// c) sets the Additional information IE to the LCS correlation identifier
///    received from that LMF.
///
/// Additional information is the only optional IE present, so it comes right
/// after the payload container, which is where TS 24.501 Table 8.2.11.1.1
/// orders it. A correlation identifier that does not fit the IE's one-octet
/// length is left out and logged rather than truncated: a cut identifier
/// would route the UE's answer to no LMF at all.
pub fn build_slpp_dl_nas(slpp_pdu: &[u8], lcs_correlation_id: Option<&str>) -> Option<Vec<u8>> {
    let mut nas = crate::gmm_build::build_dl_nas_transport(
        None,
        PAYLOAD_CONTAINER_TYPE_SLPP,
        slpp_pdu,
        None,
        None,
    )?;
    if let Some(corr) = lcs_correlation_id.filter(|c| !c.is_empty()) {
        match u8::try_from(corr.len()) {
            Ok(len) => {
                nas.push(IEI_ADDITIONAL_INFORMATION);
                nas.push(len);
                nas.extend_from_slice(corr.as_bytes());
            }
            Err(_) => log::warn!(
                "SLPP DL NAS Transport: LCS correlation id of {} octets does not fit the \
                 Additional information IE (max 255); sent without it",
                corr.len()
            ),
        }
    }
    Some(nas)
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
    fn slpp_dl_nas_frames_the_slpp_container_and_the_correlation_id() {
        // TS 24.501 k00: type 12 "SLPP message container" (§9.11.3.40) and
        // the LCS correlation id in Additional information (§5.4.5.3.2 c1).
        assert_eq!(PAYLOAD_CONTAINER_TYPE_SLPP, 0b1100);
        assert_eq!(IEI_ADDITIONAL_INFORMATION, 0x24);
        assert_ne!(PAYLOAD_CONTAINER_TYPE_SLPP, PAYLOAD_CONTAINER_TYPE_LPP);
        let slpp = [0x44u8, 0x02, 0x00, 0x40, 0x04, 0x00];
        let nas = build_slpp_dl_nas(&slpp, Some("corr-1")).expect("builds");
        // 7E 00 68 | type 0C | LV-E 00 06 + payload | 24 06 "corr-1"
        let mut want = vec![0x7E, 0x00, 0x68, 0x0C, 0x00, 0x06];
        want.extend_from_slice(&slpp);
        want.extend_from_slice(&[0x24, 0x06]);
        want.extend_from_slice(b"corr-1");
        assert_eq!(nas, want);
        // No correlation id, so no Additional information.
        assert_eq!(
            build_slpp_dl_nas(&slpp, None).expect("builds").len(),
            6 + slpp.len()
        );
        // One that cannot fit is left out, not truncated.
        let long = "x".repeat(256);
        assert_eq!(
            build_slpp_dl_nas(&slpp, Some(&long)).expect("builds").len(),
            6 + slpp.len()
        );
    }

    #[test]
    fn lpp_dl_nas_frames_lpp_container() {
        // A small opaque LPP body (envelope bytes are irrelevant to framing).
        let lpp = [0x90u8, 0x01, 0x20];
        let nas = build_lpp_dl_nas(&lpp, None).expect("build LPP DL NAS Transport");
        // 5GMM EPD, plain header, then DL NAS Transport framing.
        assert_eq!(nas[0], 0x7E, "extended protocol discriminator = 5GMM");
        // Payload container type octet must select LPP ...
        assert_eq!(nas[3], PAYLOAD_CONTAINER_TYPE_LPP);
        // ... followed by the LV-E length and the verbatim LPP payload.
        assert_eq!(nas[4], 0x00);
        assert_eq!(nas[5], 0x03);
        assert_eq!(&nas[6..9], &lpp);
        assert_eq!(nas.len(), 9, "no correlation, so no Additional information");
    }

    /// #2256, TS 24.501 §5.4.5.3.2 case c: the LMF's LCS correlation id rides in
    /// Additional information (IEI 0x24), and the UL reader gets it back. One that
    /// cannot fit the one-octet length is left out, not truncated.
    #[test]
    fn lpp_dl_nas_carries_the_lcs_correlation_id_in_additional_information() {
        let lpp = [0x90u8, 0x01, 0x20];
        let nas = build_lpp_dl_nas(&lpp, Some("corr-A")).expect("builds");
        let mut want = vec![0x7E, 0x00, 0x68, PAYLOAD_CONTAINER_TYPE_LPP, 0x00, 0x03];
        want.extend_from_slice(&lpp);
        want.extend_from_slice(&[0x24, 0x06]);
        want.extend_from_slice(b"corr-A");
        assert_eq!(nas, want);
        assert_eq!(routing_correlation(&nas[11..]).as_deref(), Some("corr-A"));

        let long = "x".repeat(256);
        assert_eq!(
            build_lpp_dl_nas(&lpp, Some(&long)).expect("builds").len(),
            9
        );
        assert_eq!(build_lpp_dl_nas(&lpp, Some("")).expect("builds").len(), 9);
        let max = "y".repeat(255);
        let nas = build_lpp_dl_nas(&lpp, Some(&max)).expect("builds");
        assert_eq!(&nas[9..11], &[0x24, 0xFF]);
        assert_eq!(routing_correlation(&nas[11..]), Some(max));
        assert_eq!(routing_correlation(&[]), None);
        assert_eq!(routing_correlation(&[0xFF, 0xFE]), None);
    }
}
