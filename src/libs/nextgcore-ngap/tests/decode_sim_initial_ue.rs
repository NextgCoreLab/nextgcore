//! Cross-implementation regression: decode the exact APER bytes the nextgsim
//! gNB puts on the wire for InitialUEMessage.
//!
//! Both captures below were produced by `nextgsim-ngap`'s own encoder
//! (`nextgsim-ngap/tests/dump_initial_ue.rs`) with the deployed gNB's
//! parameters: PLMN 999-70, TAC 1, cell-id bits 0, ran_ue_ngap_id 1, and a
//! 23-byte Registration Request.
//!
//! The 76-byte case is the regression. It carries AllowedNSSAI (IE id 0), which
//! the TS 38.413 ASN.1 permits in InitialUEMessage and which the gNB sends with
//! criticality "reject" whenever the UE requested a slice. The parser had no arm
//! for IE 0, so the field fell through to `handle_unknown_ie`, which honours the
//! reject criticality and fails the entire PDU. Live symptom: every registration
//! logged "Failed to parse Initial UE Message" and the UE retransmitted on
//! T3510 indefinitely, so no UE could attach.

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Without AllowedNSSAI. This always worked; it guards against a fix that
/// accidentally makes the IE mandatory.
const CAPTURE_WITHOUT_ALLOWED_NSSAI: &str = "000f404200000500550002000100260018177e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e0079000f4099f907000000010099f907000001005a4001180070400100";

/// With AllowedNSSAI (IE id 0, criticality reject, sst=1). Byte-for-byte the
/// 76-byte PDU observed on the cluster.
const CAPTURE_WITH_ALLOWED_NSSAI: &str = "000f404800000600550002000100260018177e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e0079000f4099f907000000010099f907000001005a4001180070400100000000020001";

fn decode_initial_ue(hex: &str) -> nextgcore_ngap::types::InitialUeMessage {
    let bytes = unhex(hex);
    let msg = nextgcore_ngap::parser::decode_ngap_pdu(&bytes)
        .unwrap_or_else(|e| panic!("decode failed for a gNB-generated PDU: {e:?}"));
    match msg {
        nextgcore_ngap::NgapMessage::InitialUeMessage(m) => m,
        other => panic!("expected InitialUeMessage, got {other:?}"),
    }
}

#[test]
fn decodes_gnb_initial_ue_message_with_allowed_nssai() {
    let bytes = unhex(CAPTURE_WITH_ALLOWED_NSSAI);
    assert_eq!(
        bytes.len(),
        76,
        "capture must match the observed wire length"
    );

    let msg = decode_initial_ue(CAPTURE_WITH_ALLOWED_NSSAI);

    assert_eq!(msg.ran_ue_ngap_id, 1);
    assert_eq!(
        msg.nas_pdu.len(),
        23,
        "the Registration Request must survive"
    );
    assert_eq!(msg.ue_context_request, Some(true));
    assert_eq!(
        msg.allowed_nssai.len(),
        1,
        "AllowedNSSAI must be decoded, not merely tolerated"
    );
    assert_eq!(msg.allowed_nssai[0].sst, 1);
}

#[test]
fn decodes_gnb_initial_ue_message_without_allowed_nssai() {
    let msg = decode_initial_ue(CAPTURE_WITHOUT_ALLOWED_NSSAI);

    assert_eq!(msg.ran_ue_ngap_id, 1);
    assert_eq!(msg.nas_pdu.len(), 23);
    assert!(
        msg.allowed_nssai.is_empty(),
        "the IE is optional: absent must decode to empty, not fail"
    );
}

/// The mandatory IEs must decode identically whether or not the optional
/// AllowedNSSAI is present, so adding it cannot shift the rest of the decode.
#[test]
fn allowed_nssai_does_not_disturb_mandatory_ies() {
    let with = decode_initial_ue(CAPTURE_WITH_ALLOWED_NSSAI);
    let without = decode_initial_ue(CAPTURE_WITHOUT_ALLOWED_NSSAI);

    assert_eq!(with.ran_ue_ngap_id, without.ran_ue_ngap_id);
    assert_eq!(with.nas_pdu, without.nas_pdu);

    match (&with.user_location_info, &without.user_location_info) {
        (
            nextgcore_ngap::types::UserLocationInformation::Nr {
                nr_cgi_plmn: a_plmn,
                nr_cell_identity: a_nci,
                tai_tac: a_tac,
                ..
            },
            nextgcore_ngap::types::UserLocationInformation::Nr {
                nr_cgi_plmn: b_plmn,
                nr_cell_identity: b_nci,
                tai_tac: b_tac,
                ..
            },
        ) => {
            assert_eq!(a_plmn, b_plmn);
            assert_eq!(a_nci, b_nci);
            assert_eq!(a_tac, b_tac);
        }
    }
}

/// #445 sweep: `build_initial_ue_message` silently dropped `allowed_nssai`, so a
/// message decoded from the gNB and rebuilt lost IE 0. Rebuilding each capture
/// from its decoded form must reproduce the gNB's bytes -- the nextgsim encoder
/// is the independent oracle -- except for ONE known, separate divergence: the
/// shared `ie::encode_user_location_info` always writes criticality `ignore`,
/// which is right in every message but InitialUEMessage, where TS 38.413's
/// `InitialUEMessage-IEs` gives UserLocationInformation (IE 121) criticality
/// `reject`. That octet is pinned here so the test fails, and must be updated,
/// when it is fixed.
#[test]
fn rebuilding_a_gnb_initial_ue_message_reproduces_its_bytes() {
    for capture in [CAPTURE_WITHOUT_ALLOWED_NSSAI, CAPTURE_WITH_ALLOWED_NSSAI] {
        let expected = unhex(capture);
        let msg = decode_initial_ue(capture);
        let rebuilt = nextgcore_ngap::builder::build_initial_ue_message(&msg)
            .unwrap_or_else(|e| panic!("rebuild failed: {e:?}"));
        assert_eq!(
            rebuilt.len(),
            expected.len(),
            "rebuilt InitialUEMessage must have the capture's length (IE 0 dropped?)"
        );
        let diffs: Vec<(usize, u8, u8)> = expected
            .iter()
            .zip(&rebuilt)
            .enumerate()
            .filter(|(_, (e, r))| e != r)
            .map(|(i, (e, r))| (i, *e, *r))
            .collect();
        // The ULI field header: id 0x0079 then the criticality octet.
        let uli = expected
            .windows(2)
            .position(|w| w == [0x00, 0x79])
            .expect("capture carries UserLocationInformation")
            + 2;
        assert_eq!(
            diffs,
            vec![(uli, 0x00, 0x40)],
            "only the known ULI criticality octet may differ (reject on the wire, ignore rebuilt)"
        );
        assert_eq!(
            decode_initial_ue(
                &rebuilt
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
            .allowed_nssai,
            msg.allowed_nssai,
            "AllowedNSSAI must survive the rebuild"
        );
    }
}
