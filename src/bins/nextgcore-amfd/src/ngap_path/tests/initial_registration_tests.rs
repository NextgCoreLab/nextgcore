//! #774: an initial registration of a genuine UE supersedes the subscriber's
//! earlier registration at this AMF (TS 24.501 §5.5.1.2.8 f), TS 23.502
//! §4.2.2.2.2 step 14d).
//!
//! Each test drives the real `handle_authentication_response_nas` with a RES*
//! that matches the stored HXRES*, against a stand-in AUSF that confirms the
//! SUPI, and a stand-in SMF that records the releases.

use super::handler_tests::{activating_smf, hold_session, secured_registered_ue, SmfCall, ASSOC};
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
struct AusfEnvGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl AusfEnvGuard {
    fn set(port: u16) -> Self {
        let guard = crate::test_support::AUSF_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
    let _env = AusfEnvGuard::set(ausf_port);
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_001u64, 7_774_002u64);
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
}

/// An earlier context still CM-CONNECTED on another RAN UE NGAP ID: its N2
/// connection is released too (TS 38.413 §8.3.3.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_earlier_registration_also_gets_its_n2_connection_released() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774002";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::set(ausf_port);
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
    let _env = AusfEnvGuard::set(ausf_port);
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
    let _env = AusfEnvGuard::set(ausf_port);
    let mut server = capturing_ngap_server().await;
    let (old, new) = (7_774_031u64, 7_774_032u64);
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

    assert_eq!(released_refs(&seen), Vec::<String>::new());
    assert!(server.ue_auth_state.contains(old));
    assert_eq!(session_state(&server, old), (1, 1));
}

/// Only an INITIAL registration supersedes: a mobility registration update that
/// re-authenticates keeps the sessions (TS 24.501 §5.5.1.3.4 reconciles them by
/// the PDU session status instead).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mobility_registration_does_not_release_the_earlier_sessions() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let supi = "imsi-001010000774005";
    let (_ausf, ausf_port) = confirming_ausf("AUTHENTICATION_SUCCESS", supi).await;
    let _env = AusfEnvGuard::set(ausf_port);
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
    let _env = AusfEnvGuard::set(ausf_port);
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

    assert_eq!(released_refs(&seen), vec!["774-s3".to_string()]);
    assert_eq!(session_state(&server, ue), (0, 0));
    assert!(
        server.ue_auth_state.contains(ue),
        "the registration goes on"
    );
    assert_eq!(release_commands(&mut server), vec![]);
}
