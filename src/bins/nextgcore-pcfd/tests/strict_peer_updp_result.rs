//! Wave-6 E6 strict-peer test: the UE-policy delivery-RESULT loop, exercising
//! amfd's REAL `N1MessageNotify` producer against pcfd's REAL notify-callback
//! consumer + delivery-state correlation — no lenient mock, both real code
//! driven in-process (Wave-6 H1 lib-targetization).
//!
//! The un-driveable middle (the NGAP UL NAS path needs live SCTP) is elided:
//! we build the exact `N1MessageNotify` amfd's `forward_ul_updp_to_pcf` emits
//! (amfd's real `build_n1_message_notify_request`, class "UPDP") and feed it to
//! pcfd's REAL SBI router (`pcf_sbi_request_handler`) — the same producer→
//! consumer cross-decode the wire would carry.
//!
//! Specs: TS 29.518 §5.2.2.4 (N1MessageNotify), TS 24.501 D.2.1.3 (COMPLETE
//! stops the procedure), D.2.1.4/D.6.3 (REJECT carries per-instruction result),
//! D.2.1.6 (drop a stale/duplicate command's answer), TS 29.525 §4.2.2.2.
//!
//! Falsifiable acceptance (E6): the association reaches `Delivered` ONLY via a
//! decoded MANAGE UE POLICY COMPLETE with the matching PTI; a REJECT yields
//! `Failed` with the D.6.3 cause; a wrong-PTI answer leaves it `Pending`.

use nextgcore_amfd::namf_server::build_n1_message_notify_request;
use nextgcore_nas::fiveg::ue_policy as nas_updp;
use nextgcore_pcfd::pcf_sbi_request_handler;
use nextgcore_pcfd::ue_policy::{
    ue_policy_add, ue_policy_find, ue_policy_set_delivery, DeliveryState,
};

/// Seed a Pending pcfd UE-policy association carrying `pti`, return its id.
fn seed_pending_association(pti: u8) -> String {
    let assoc = ue_policy_add("imsi-001010000006e60", "http://127.0.0.1:9/ue-policy-notify", "");
    ue_policy_set_delivery(
        &assoc.pol_asso_id,
        pti,
        1, // UPSC 1
        Some(("001".into(), "01".into())),
        nextgcore_pcfd::ue_policy::default_wire_rules(),
    );
    assoc.pol_asso_id
}

/// The N1MessageNotify amfd would POST to the PCF's registered callback for a
/// UE-policy uplink message: amfd's REAL multipart builder (class "UPDP"),
/// targeting pcfd's callback path for `pol_asso_id`.
fn amfd_notify_request(
    pol_asso_id: &str,
    n1_payload: &[u8],
) -> nextgcore_sbi::message::SbiRequest {
    let path =
        format!("/npcf-ue-policy-control/v1/notify/{pol_asso_id}/n1-message-notify");
    build_n1_message_notify_request(
        &path,
        Some("n1n2sub-test"),
        "UPDP",
        None,
        Some("imsi-001010000006e60"),
        n1_payload,
    )
    .expect("amfd builds the N1MessageNotify")
}

/// COMPLETE with the matching PTI → real amfd notify → real pcfd callback flips
/// the association Pending→Delivered (records the UPSC as installed UPSI).
#[tokio::test]
async fn complete_via_real_amfd_notify_delivers() {
    let id = seed_pending_association(0x91);
    let complete = nas_updp::ManageUePolicyComplete { pti: 0x91 }
        .encode()
        .expect("COMPLETE encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &complete)).await;
    assert_eq!(resp.status, 204, "notify callback acks 204");

    let a = ue_policy_find(&id).expect("association still present");
    assert_eq!(
        a.delivery_state,
        DeliveryState::Delivered,
        "Delivered ONLY via a matching-PTI COMPLETE"
    );
    assert_eq!(a.installed_upsc, Some(1), "UPSC recorded as installed UPSI");
}

/// REJECT with the matching PTI → association Failed, carrying the decoded
/// D.6.3 per-instruction cause.
#[tokio::test]
async fn reject_via_real_amfd_notify_fails_with_cause() {
    let id = seed_pending_association(0x92);
    let reject = nas_updp::ManageUePolicyCommandReject {
        pti: 0x92,
        result: nas_updp::UePolicySectionManagementResult {
            subresults: vec![nas_updp::UePolicySectionManagementSubresult {
                plmn_id: nextgcore_nas::common::types::PlmnId::new([0, 0, 1], [0, 1, 0xf], 2),
                results: vec![nas_updp::UePolicyResult {
                    upsc: 0x0001,
                    failed_instruction_order: 1,
                    cause: nas_updp::UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                }],
            }],
        },
    }
    .encode()
    .expect("REJECT encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &reject)).await;
    assert_eq!(resp.status, 204);

    match ue_policy_find(&id).expect("association").delivery_state {
        DeliveryState::Failed(cause) => {
            assert!(cause.contains("REJECT"), "cause names the REJECT: {cause}");
            assert!(cause.contains("UPSC"), "cause names the failed UPSC: {cause}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A COMPLETE with a NON-matching PTI (stale/duplicate command, D.2.1.6) is
/// dropped: the callback still acks 204 (no crash) but the association stays
/// Pending — Delivered is reached ONLY via a matching PTI.
#[tokio::test]
async fn wrong_pti_complete_is_dropped() {
    let id = seed_pending_association(0x93);
    let stale = nas_updp::ManageUePolicyComplete { pti: 0x9F }
        .encode()
        .expect("COMPLETE encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &stale)).await;
    assert_eq!(resp.status, 204, "stale answer is still consumed (no crash)");
    assert_eq!(
        ue_policy_find(&id).expect("association").delivery_state,
        DeliveryState::Pending,
        "a wrong-PTI COMPLETE must NOT deliver"
    );
}
