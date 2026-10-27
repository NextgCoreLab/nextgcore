//! #774: an initial registration of a genuine UE supersedes the subscriber's
//! earlier registration at this AMF (TS 24.501 §5.5.1.2.8 f), TS 23.502
//! §4.2.2.2.2 step 14d).
//!
//! Each test drives the real `handle_authentication_response_nas` with a RES*
//! that matches the stored HXRES*, against a stand-in AUSF that confirms the
//! SUPI, and a stand-in SMF that records the releases.

use super::handler_tests::{
    activating_smf, decode_sent, establishment_request, hanging_smf, hold_session,
    secured_registered_ue, Sent, SmfCall, ASSOC,
};
use super::*;

/// The RES* every UE here answers with.
const RES_STAR: [u8; 16] = [0x5A; 16];

/// A stand-in AUSF that answers every 5G-AKA confirmation with `auth_result`
/// for `supi`. Keep the server alive.
async fn confirming_ausf(auth_result: &str, supi: &str) -> (nextgcore_sbi::server::SbiServer, u16) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let answer = serde_json::json!({
        "authResult": auth_result,
        "supi": supi,
        "kseaf": hex::encode([0x77u8; 32]),
    })
    .to_string();
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |req: SReq| {
            let answer = answer.clone();
            async move {
                if req.header.uri.ends_with("/5g-aka-confirmation") {
                    SResp::with_status(200).with_body(answer, "application/json")
                } else {
                    SResp::with_status(404)
                }
            }
        })
        .await
        .expect("stand-in AUSF starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (server, addr.port())
}

/// Points the AMF's AUSF calls at `port` while held.
struct AusfEnvGuard(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

impl AusfEnvGuard {
    /// Async: the lock is a tokio mutex (#643), held across the test's awaits.
    async fn acquire(port: u16) -> Self {
        let guard = crate::test_support::AUSF_ENV_LOCK.lock().await;
        std::env::set_var("AUSF_SBI_ADDR", "127.0.0.1");
        std::env::set_var("AUSF_SBI_PORT", port.to_string());
        Self(guard)
    }
}

impl Drop for AusfEnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("AUSF_SBI_ADDR");
        std::env::remove_var("AUSF_SBI_PORT");
    }
}

/// A UE on `ran_ue_ngap_id` that has sent a Registration Request of
/// `registration_type` and been sent an Authentication Request whose expected
/// answer is [`RES_STAR`].
fn authenticating_ue(
    server: &mut NgapServer,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    registration_type: u8,
) {
    crate::context::amf_context_init(64, 1024, 4096);
    let mut ue = UeNasContext::new(amf_ue_ngap_id, ran_ue_ngap_id, ASSOC, false);
    ue.auth_ctx_id = format!("auth-{amf_ue_ngap_id}");
    ue.amf_ue.registration_type = registration_type;
    ue.amf_ue.access_type = ACCESS_TYPE_3GPP;
    ue.amf_ue.rand = [0x3C; 16];
    // TS 33.501 Annex A.5: HXRES* = SHA-256(RAND || XRES*), the 128 low-order bits.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(ue.amf_ue.rand);
    hasher.update(RES_STAR);
    let digest = hasher.finalize();
    ue.amf_ue.hxres_star[..16].copy_from_slice(&digest[16..32]);
    // 5G-EA0..3 and 5G-IA0..3: NIA2 is common with the AMF's default order.
    ue.amf_ue.ue_security_capability = UeSecurityCapability {
        ea: 0xF0,
        ia: 0xF0,
        eea: 0,
        eia: 0,
    };
    server.ue_auth_state.insert(amf_ue_ngap_id, ue);
}

/// The registered UE `amf_ue_ngap_id` with `supi`, holding a session per
/// `(psi, ref)` at the stand-in SMF, CM-IDLE when `idle`.
fn earlier_registration(
    server: &mut NgapServer,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    supi: &str,
    idle: bool,
    sessions: &[(u8, &str)],
    smf_port: u16,
) {
    secured_registered_ue(server, amf_ue_ngap_id, ran_ue_ngap_id);
    server.ue_auth_state.with_mut(amf_ue_ngap_id, |s| {
        s.amf_ue.supi = Some(supi.to_string());
        s.cm_idle = idle;
    });
    for (psi, sm_ref) in sessions {
        hold_session(server, amf_ue_ngap_id, *psi, sm_ref, smf_port);
    }
}

/// The AUTHENTICATION RESPONSE carrying [`RES_STAR`] (IEI 0x2D, TLV).
fn authentication_response() -> Vec<u8> {
    let mut nas = vec![0x7E, 0x00, message_type::AUTHENTICATION_RESPONSE, 0x2D, 16];
    nas.extend_from_slice(&RES_STAR);
    nas
}

/// The SM context refs the stand-in SMF was asked to release.
fn released_refs(seen: &std::sync::Mutex<Vec<SmfCall>>) -> Vec<String> {
    let mut refs: Vec<String> = seen
        .lock()
        .expect("smf calls")
        .iter()
        .filter_map(|(uri, _)| {
            let rest = uri.split("/sm-contexts/").nth(1)?;
            let (sm_ref, op) = rest.split_once('/')?;
            (op == "release").then(|| sm_ref.to_string())
        })
        .collect();
    refs.sort();
    refs
}

/// `amf_ue_ngap_id`'s per-session state: (`sm_context_refs`, `sess_list`) sizes.
fn session_state(server: &NgapServer, amf_ue_ngap_id: u64) -> (usize, usize) {
    let refs = server
        .sm_context_refs
        .keys()
        .filter(|(ue, _)| *ue == amf_ue_ngap_id)
        .count();
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
    (refs, guard.sess_list_for_ue(amf_ue_ngap_id).len())
}

/// The UE Context Release Commands sent, as `(amf_ue_ngap_id, ran_ue_ngap_id)`.
fn release_commands(server: &mut NgapServer) -> Vec<(u64, Option<u32>)> {
    take_sent_ngap(server)
        .iter()
        .filter_map(|(_, pdu)| decoded_release_command(pdu))
        .map(|(amf, ran, _)| (amf, ran))
        .collect()
}

/// The issue's case: the UE power-cycled without de-registering, so its earlier
/// context is CM-IDLE with two sessions, and it comes back by SUCI. Once 5G-AKA
/// proves it genuine both sessions are released at the SMF and the earlier
/// context is gone; the new registration goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initial_registration_releases_the_sessions_of_the_earlier_registration() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774001";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_001u64, 7_774_002u64);
    let successes = super::metrics_tests::scraped("amf_auth_success_total");
    earlier_registration(
        &mut server,
        old,
        41,
        supi,
        true,
        &[(1, "774-a1"), (2, "774-a2")],
        smf_port,
    );
    authenticating_ue(
        &mut server,
        new,
        42,
        crate::gmm_build::registration_type::INITIAL,
    );

    server
        .handle_authentication_response_nas(ASSOC, new, 42, &authentication_response())
        .await
        .expect("authentication response handled");
    // #774 review M1: the releases run off the NGAP task.
    server.sbi_offload.settle().await;

    assert_eq!(
        released_refs(&seen),
        vec!["774-a1".to_string(), "774-a2".to_string()],
        "both sessions of the earlier registration are released at the SMF"
    );
    assert!(
        !server.ue_auth_state.contains(old),
        "the earlier 5GMM context is deleted (TS 24.501 §5.5.1.2.8 f))"
    );
    assert_eq!(session_state(&server, old), (0, 0));
    assert_eq!(
        release_commands(&mut server),
        vec![],
        "a CM-IDLE context has no N2 connection to release"
    );
    let kept = server
        .ue_auth_state
        .get(new)
        .expect("the new registration goes on");
    assert_eq!(kept.amf_ue.supi.as_deref(), Some(supi));
    assert_eq!(
        server.ue_auth_state.find_all_by_supi(supi).len(),
        1,
        "the subscriber resolves to one context"
    );
    // #1334: the confirmed 5G-AKA is counted (REVERT-VERIFIED: without
    // `observe_authentication_success` this fails).
    assert!(super::metrics_tests::scraped("amf_auth_success_total") >= successes + 1.0);
}

/// An earlier context still CM-CONNECTED on another RAN UE NGAP ID: its N2
/// connection is released too (TS 38.413 §8.3.3.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_earlier_registration_also_gets_its_n2_connection_released() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774002";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_011u64, 7_774_012u64);
    earlier_registration(
        &mut server,
        old,
        51,
        supi,
        false,
        &[(5, "774-c5")],
        smf_port,
    );
    authenticating_ue(
        &mut server,
        new,
        52,
        crate::gmm_build::registration_type::INITIAL,
    );

    server
        .handle_authentication_response_nas(ASSOC, new, 52, &authentication_response())
        .await
        .expect("authentication response handled");
    // #774 review M1: the releases run off the NGAP task.
    server.sbi_offload.settle().await;

    assert_eq!(released_refs(&seen), vec!["774-c5".to_string()]);
    assert!(!server.ue_auth_state.contains(old));
    assert_eq!(session_state(&server, old), (0, 0));
    assert_eq!(
        release_commands(&mut server),
        vec![(old, Some(51))],
        "the old UE-associated NG connection is released, and only it"
    );
    assert!(server.ue_auth_state.contains(new));
}

/// The gNB has already reused the old RAN UE NGAP ID for the new connection: the
/// old context is deleted without a Release Command, which the gNB would match
/// against the NEW connection (TS 38.413 §10.6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reused_ran_ue_ngap_id_is_not_released() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774003";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_021u64, 7_774_022u64);
    earlier_registration(
        &mut server,
        old,
        61,
        supi,
        false,
        &[(1, "774-r1")],
        smf_port,
    );
    authenticating_ue(
        &mut server,
        new,
        61,
        crate::gmm_build::registration_type::INITIAL,
    );

    server
        .handle_authentication_response_nas(ASSOC, new, 61, &authentication_response())
        .await
        .expect("authentication response handled");
    // #774 review M1: the releases run off the NGAP task.
    server.sbi_offload.settle().await;

    assert_eq!(released_refs(&seen), vec!["774-r1".to_string()]);
    assert!(!server.ue_auth_state.contains(old));
    assert_eq!(release_commands(&mut server), vec![]);
    assert!(server.ue_auth_state.contains(new));
}

/// A UE that is not proven genuine leaves the subscriber's context unchanged
/// (TS 24.501 §5.5.1.2.8 f), second half).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_authentication_keeps_the_earlier_registration() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774004";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_FAILURE", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_031u64, 7_774_032u64);
    let rejects = super::metrics_tests::scraped(r#"amf_auth_failure_total{source="network"}"#);
    earlier_registration(&mut server, old, 71, supi, true, &[(1, "774-f1")], smf_port);
    authenticating_ue(
        &mut server,
        new,
        72,
        crate::gmm_build::registration_type::INITIAL,
    );

    let _ = server
        .handle_authentication_response_nas(ASSOC, new, 72, &authentication_response())
        .await;
    server.sbi_offload.settle().await;

    assert_eq!(released_refs(&seen), Vec::<String>::new());
    assert!(server.ue_auth_state.contains(old));
    assert_eq!(session_state(&server, old), (1, 1));
    // #1334: the Authentication Reject sent is a network-side authentication failure
    // (REVERT-VERIFIED: without `observe_downlink_nas` in `send_nas_pdu` this fails).
    assert!(
        super::metrics_tests::scraped(r#"amf_auth_failure_total{source="network"}"#)
            >= rejects + 1.0
    );
}

/// Only an INITIAL registration supersedes: a mobility registration update that
/// re-authenticates keeps the sessions (TS 24.501 §5.5.1.3.4 reconciles them by
/// the PDU session status instead).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mobility_registration_does_not_release_the_earlier_sessions() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774005";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_041u64, 7_774_042u64);
    earlier_registration(&mut server, old, 81, supi, true, &[(1, "774-m1")], smf_port);
    authenticating_ue(
        &mut server,
        new,
        82,
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
    );

    server
        .handle_authentication_response_nas(ASSOC, new, 82, &authentication_response())
        .await
        .expect("authentication response handled");
    // #774 review M1: the releases run off the NGAP task.
    server.sbi_offload.settle().await;

    assert_eq!(released_refs(&seen), Vec::<String>::new());
    assert!(server.ue_auth_state.contains(old));
    assert_eq!(session_state(&server, old), (1, 1));
}

/// An integrity-verified initial registration from 5GMM-IDLE moves the stored
/// context, sessions included, onto the new AMF UE NGAP ID. Those sessions are
/// released and forgotten, and the registration goes on under that context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_carried_into_the_initial_registration_are_released() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774006";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let ue = 7_774_051u64;
    authenticating_ue(
        &mut server,
        ue,
        91,
        crate::gmm_build::registration_type::INITIAL,
    );
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.supi = Some(supi.to_string());
    });
    hold_session(&mut server, ue, 3, "774-s3", smf_port);

    server
        .handle_authentication_response_nas(ASSOC, ue, 91, &authentication_response())
        .await
        .expect("authentication response handled");
    // #774 review M1: the releases run off the NGAP task.
    server.sbi_offload.settle().await;

    assert_eq!(released_refs(&seen), vec!["774-s3".to_string()]);
    assert_eq!(session_state(&server, ue), (0, 0));
    assert!(
        server.ue_auth_state.contains(ue),
        "the registration goes on"
    );
    assert_eq!(release_commands(&mut server), vec![]);
}

/// The CreateSMContext requests the stand-in SMF has seen, as their PSIs.
fn created_psis(seen: &std::sync::Mutex<Vec<SmfCall>>) -> Vec<u64> {
    seen.lock()
        .expect("smf calls")
        .iter()
        .filter(|(uri, _)| uri.ends_with("/nsmf-pdusession/v1/sm-contexts"))
        .map(|(_, body)| body["pduSessionId"].as_u64().unwrap_or_default())
        .collect()
}

/// Whether the AMF sent a DOWNLINK NAS TRANSPORT (here: the Security Mode
/// Command that follows a successful authentication).
fn sent_downlink_nas(server: &mut NgapServer) -> bool {
    take_sent_ngap(server)
        .iter()
        .any(|(_, pdu)| matches!(decode_sent(pdu), Sent::DownlinkNas { .. }))
}

/// #774 review M1. The earlier registration's SMF is blackholed (it never
/// answers). The authentication response is still handled at once and the
/// Security Mode Command goes out, because the releases run off the NGAP task.
/// The new UE's PDU Session Establishment waits for them, but only up to the
/// barrier's bound; then it goes to the SMF anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// The SMF and AUSF environment guards are held across the awaits on purpose:
// both addresses are process environment variables.
#[allow(clippy::await_holding_lock)]
async fn a_blackholed_smf_holds_neither_the_registration_nor_the_new_sessions_for_long() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let _smf_env = super::SmfEnvGuard::acquire(smf_port).await;
    let (_blackhole, blackhole_port) = hanging_smf();
    let supi = "imsi-001010000774007";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    server.supersede_barrier_max = Duration::from_millis(400);
    let (old, new) = (7_774_061u64, 7_774_062u64);
    earlier_registration(
        &mut server,
        old,
        93,
        supi,
        true,
        &[(1, "774-b1"), (2, "774-b2")],
        blackhole_port,
    );
    authenticating_ue(
        &mut server,
        new,
        94,
        crate::gmm_build::registration_type::INITIAL,
    );

    let started = std::time::Instant::now();
    server
        .handle_authentication_response_nas(ASSOC, new, 94, &authentication_response())
        .await
        .expect("authentication response handled");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the NGAP task did not wait for the blackholed SMF: {:?}",
        started.elapsed()
    );
    assert!(
        sent_downlink_nas(&mut server),
        "the Security Mode Command goes out without waiting for the releases"
    );
    assert!(
        !server.ue_auth_state.contains(old),
        "the earlier context is gone"
    );
    assert_eq!(
        server.supersede_barriers.get(&new).map(|b| b.outstanding),
        Some(2),
        "both releases are still out"
    );

    server
        .handle_5gsm_message(ASSOC, new, 94, &establishment_request(1), None)
        .await
        .expect("establishment handled");
    server.process_sbi_outcomes().await;
    server.process_supersede_barriers().await;
    assert_eq!(
        created_psis(&seen),
        Vec::<u64>::new(),
        "the establishment waits while the earlier sessions are being released"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    server.process_sbi_outcomes().await;
    server.process_supersede_barriers().await;
    // #922: the released establishment's CreateSMContext runs off the NGAP task.
    for _ in 0..200 {
        if !created_psis(&seen).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        created_psis(&seen),
        vec![1],
        "past the bound the establishment goes to the SMF anyway"
    );
    assert!(server.supersede_barriers.is_empty());
    server.forget_ue(new);
}

/// #774 review M1. The barrier keeps the order the inline release gave: the
/// new UE's establishment reaches the SMF only after every ReleaseSMContext of
/// the registration it superseded has reported back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn the_new_establishments_reach_the_smf_after_the_earlier_releases() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let _smf_env = super::SmfEnvGuard::acquire(smf_port).await;
    let supi = "imsi-001010000774008";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::acquire(ausf_port).await;
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_071u64, 7_774_072u64);
    earlier_registration(
        &mut server,
        old,
        95,
        supi,
        true,
        &[(1, "774-o1"), (2, "774-o2")],
        smf_port,
    );
    authenticating_ue(
        &mut server,
        new,
        96,
        crate::gmm_build::registration_type::INITIAL,
    );

    server
        .handle_authentication_response_nas(ASSOC, new, 96, &authentication_response())
        .await
        .expect("authentication response handled");
    // Before the releases' outcomes are back on the NGAP task.
    server
        .handle_5gsm_message(ASSOC, new, 96, &establishment_request(1), None)
        .await
        .expect("establishment handled");
    assert_eq!(created_psis(&seen), Vec::<u64>::new(), "it waits");

    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
    server.process_supersede_barriers().await;
    // #922: the released establishment's CreateSMContext runs off the NGAP task.
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;

    let calls: Vec<String> = seen
        .lock()
        .expect("smf calls")
        .iter()
        .map(|(uri, _)| uri.clone())
        .collect();
    let create = calls
        .iter()
        .position(|u| u.ends_with("/nsmf-pdusession/v1/sm-contexts"))
        .expect("the establishment went to the SMF once the releases were done");
    let last_release = calls
        .iter()
        .rposition(|u| u.ends_with("/release"))
        .expect("released");
    assert!(last_release < create, "release before create: {calls:?}");
    assert_eq!(
        released_refs(&seen),
        vec!["774-o1".to_string(), "774-o2".to_string()]
    );
    assert!(server.supersede_barriers.is_empty());
    server.forget_ue(new);
}
