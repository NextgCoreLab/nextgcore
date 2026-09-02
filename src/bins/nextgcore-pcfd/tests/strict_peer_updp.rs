//! Wave-6 E4 strict-peer test: pcfd's REAL URSP delivery pipeline against
//! amfd's REAL `Namf_Communication_N1N2MessageTransfer` handler (item E5's
//! UPDP branch) — no lenient mock, both handlers driven in-process (Wave-6 H1
//! lib-targetization).
//!
//! Specs: TS 29.525 §4.2.2.2 (PCF delivers UE policies via N1N2MessageTransfer),
//! TS 29.518 §5.2.2.3.1 (N1N2MessageTransfer, n1MessageClass UPDP,
//! `specs/TS29518_Namf_Communication.yaml:4453`), TS 24.501 Table D.5.1.1.1
//! (MANAGE UE POLICY COMMAND), TS 24.526 §5.2 (URSP contents).
//!
//! Falsifiable acceptance (E4): the exact bytes pcfd hands to the multipart
//! binary part equal the E1 golden command vector (f), and amfd's REAL handler
//! 200-accepts them and enqueues the SAME bytes for N1 egress; a CM-IDLE UE is
//! 504-rejected (never a fake 200), which pcfd's delivery path records Failed.

use nextgcore_amfd::context as amf;
use nextgcore_amfd::handle_n1_n2_message_transfer_request;
use nextgcore_amfd::test_support::CONTEXT_GUARD;
use nextgcore_pcfd::sbi_path::build_ue_policy_n1n2_request;
use nextgcore_pcfd::ue_policy::{build_manage_ue_policy_command, default_wire_rules};

/// E1 golden vector (f), re-cited verbatim (see the pcfd unit-test copy and
/// `nextgcore-nas/tests/ue_policy_golden_vectors/data.rs`). PTI 0x80, PLMN
/// 001-01, UPSC 1, one URSP part = catch-all rule.
const VEC_F: &[u8] = &[
    0x80, 0x01, 0x00, 0x2B, 0x00, 0x29, 0x00, 0xF1, 0x10, 0x00, 0x24, 0x00, 0x01, 0x00, 0x20, 0x01,
    0x00, 0x1D, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x17, 0x00, 0x15, 0xFF, 0x00, 0x12, 0x01, 0x01, 0x02,
    0x01, 0x01, 0x04, 0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x08, 0x03,
];

/// The catch-all MANAGE UE POLICY COMMAND pcfd would build for a default
/// association (PTI 0x80, UPSC 1, PLMN 001-01).
fn pcfd_updp_pdu() -> Vec<u8> {
    std::env::remove_var("PCF_URSP_RULES");
    build_manage_ue_policy_command(0x80, 1, "001", "01", &default_wire_rules())
        .expect("pcfd builds the catch-all MANAGE UE POLICY COMMAND")
}

/// Seed a UE in amfd's process-global context; `connected` => CM-CONNECTED
/// (a live RAN UE context, required for an N1 downlink). Returns the AMF-UE id.
fn seed_ue(supi: &str, connected: bool) -> u64 {
    amf::amf_context_init(64, 1024, 4096);
    let ctx = amf::amf_self();
    let guard = ctx.read().expect("amf ctx lock");
    // Unique RAN-UE-NGAP-ID per SUPI hash so tests never collide.
    let ngap_id = 70_000 + (supi.bytes().map(u64::from).sum::<u64>() % 20_000);
    let ran_ue = guard.ran_ue_add(900_200, ngap_id).expect("ran_ue_add");
    let mut ue = guard.amf_ue_add(ran_ue.id).expect("amf_ue_add");
    guard.amf_ue_set_supi(ue.id, supi);
    ue.supi = Some(supi.to_string());
    ue.security_context_available = true;
    if connected {
        guard.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
        ue.ran_ue_id = ran_ue.id;
    } else {
        ue.ran_ue_id = amf::NEXTGCORE_INVALID_POOL_ID;
    }
    guard.amf_ue_update(&ue);
    ue.id
}

/// Drain amfd's downlink queue keeping only this UE's items (the queue is
/// process-global and shared with other seeded UEs).
fn drain_for(ue_id: u64) -> Vec<amf::PendingPositioningDl> {
    let ctx = amf::amf_self();
    let guard = ctx.read().expect("amf ctx lock");
    let (mine, others): (Vec<_>, Vec<_>) = guard
        .positioning_dl_drain()
        .into_iter()
        .partition(|d| d.amf_ue_ngap_id == ue_id);
    for o in others {
        guard.positioning_dl_add(o);
    }
    mine
}

fn body_cause(resp: &nextgcore_sbi::message::SbiResponse) -> String {
    let v: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    // 200 body: {"cause": ...}; 504 error body: {"error": {"cause": ...}}
    v.get("cause")
        .and_then(|c| c.as_str())
        .or_else(|| v.pointer("/error/cause").and_then(|c| c.as_str()))
        .unwrap_or_default()
        .to_string()
}

/// E4 primary acceptance: pcfd's production multipart request → amfd's REAL
/// handler → 200 N1_N2_TRANSFER_INITIATED, and the bytes amfd enqueues for N1
/// egress are byte-identical to pcfd's E1(f) command (no re-encoding, no drop).
#[test]
fn pcfd_updp_accepted_by_real_amfd_and_enqueued_verbatim() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _serial = CONTEXT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let supi = "imsi-001010000004001";
    let ue_id = seed_ue(supi, true);

    let pdu = pcfd_updp_pdu();
    // Sanity: pcfd's builder equals the E1 golden command vector.
    assert_eq!(pdu, VEC_F, "pcfd UPDP command must equal E1(f)");

    // pcfd's PRODUCTION multipart request, fed to amfd's REAL handler.
    let req = build_ue_policy_n1n2_request(supi, &pdu);
    let resp = handle_n1_n2_message_transfer_request(supi, &req);

    assert_eq!(
        resp.status, 200,
        "real amfd must 200-accept pcfd's UPDP transfer, got {} ({:?})",
        resp.status, resp.http.content
    );
    assert_eq!(body_cause(&resp), "N1_N2_TRANSFER_INITIATED");

    let drained = drain_for(ue_id);
    assert_eq!(drained.len(), 1, "exactly one UPDP downlink enqueued");
    match &drained[0].kind {
        amf::PositioningDlKind::UePolicyToUe { updp_pdu } => {
            assert_eq!(
                updp_pdu.as_slice(),
                VEC_F,
                "amfd relays pcfd's UPDP bytes verbatim (== E1(f))"
            );
        }
        other => panic!("expected UePolicyToUe downlink, got {other:?}"),
    }
}

/// E4 fail-closed leg: the same pcfd request against a CM-IDLE UE gets 504
/// UE_NOT_REACHABLE from amfd's REAL handler (never a fake 200-and-drop) — the
/// non-2xx that pcfd's delivery path records as `DeliveryState::Failed`.
#[test]
fn pcfd_updp_to_idle_ue_rejected_504_by_real_amfd() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _serial = CONTEXT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let supi = "imsi-001010000004002";
    let ue_id = seed_ue(supi, false);

    let pdu = pcfd_updp_pdu();
    let req = build_ue_policy_n1n2_request(supi, &pdu);
    let resp = handle_n1_n2_message_transfer_request(supi, &req);

    assert_eq!(
        resp.status, 504,
        "CM-IDLE UPDP must be 504 UE_NOT_REACHABLE, never a fake 200"
    );
    assert_eq!(body_cause(&resp), "UE_NOT_REACHABLE");

    // Fail-closed: nothing enqueued for an unreachable UE.
    assert_eq!(drain_for(ue_id).len(), 0, "no downlink for an idle UE");
}
