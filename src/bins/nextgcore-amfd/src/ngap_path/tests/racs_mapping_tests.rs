//! #747: UE RADIO CAPABILITY ID MAPPING never waits on the UCMF on the NGAP task,
//! never re-asks for an ID the UCMF deleted, and caps the lookups in flight.

// The RACS cache and the UCMF env vars are process-global; their std locks are
// held across the awaits on purpose, to serialise these tests with the racs::
// tests, as `a_mapping_request_is_answered_only_when_the_id_resolves` does.
#![allow(clippy::await_holding_lock)]

use super::handler_tests::ASSOC;
use super::*;

/// PLMN-assigned, Version ID 05 (TS 23.003 §29.2).
const ID: [u8; 7] = [0x01, 0x05, 0x00, 0x00, 0x00, 0x07, 0x47];

/// A UE RADIO CAPABILITY ID MAPPING REQUEST for [`ID`] (APER, as
/// `racs/tests.rs::mapping_request_octets_decode_to_the_id` derives it).
fn mapping_request() -> Vec<u8> {
    let mut pdu = vec![
        0x00, 0x3C, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x08, 0x00, 0x08, 0x07,
    ];
    pdu.extend_from_slice(&ID);
    pdu
}

/// The RACS cache is process-global: hold its lock, from a clean cache.
fn racs_guard() -> std::sync::MutexGuard<'static, ()> {
    let g = crate::racs::RACS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::racs::reset_for_tests();
    g
}

fn in_flight(server: &NgapServer) -> usize {
    server
        .mapping_resolves_in_flight
        .load(std::sync::atomic::Ordering::Acquire)
}

/// A cached ID is answered at once, on the asking association.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cached_id_is_answered_at_once() {
    let _g = racs_guard();
    crate::racs::cache_put(&ID, &[0xAA, 0xBB]);
    let mut server = capturing_ngap_server().await;

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request())
        .await
        .expect("handled");

    let sent = take_sent_ngap(&mut server);
    assert_eq!(
        sent,
        vec![(
            ASSOC,
            crate::racs::build_mapping_response(&ID, &[0xAA, 0xBB]).unwrap()
        )]
    );
    assert_eq!(in_flight(&server), 0);
}

/// An ID the UCMF has no entry for is not asked about again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_id_is_not_resolved_again() {
    let _g = racs_guard();
    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "manAssOpRequestlist": { "plmnAssiUeRadioCapId": [crate::racs::to_nucmf(&ID).unwrap()] },
    }));
    let mut server = capturing_ngap_server().await;

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request())
        .await
        .expect("handled");

    assert_eq!(in_flight(&server), 0, "no UCMF lookup is started");
    assert!(take_sent_ngap(&mut server).is_empty());
}

/// At the cap, a further request starts no lookup and gets no answer
/// (TS 38.413 §8.14.3.3 has no unsuccessful outcome).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_cap_no_lookup_is_started() {
    let _g = racs_guard();
    let mut server = capturing_ngap_server().await;
    server.mapping_resolves_in_flight.store(
        MAX_MAPPING_RESOLVES_IN_FLIGHT,
        std::sync::atomic::Ordering::Release,
    );

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request())
        .await
        .expect("handled");

    assert_eq!(in_flight(&server), MAX_MAPPING_RESOLVES_IN_FLIGHT);
    assert!(take_sent_ngap(&mut server).is_empty());
}

/// An answer an off-task lookup produced is sent by the NGAP pump, on the
/// association that asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pump_sends_an_off_task_answer() {
    let mut server = capturing_ngap_server().await;
    let pdu = crate::racs::build_mapping_response(&ID, &[0xCC]).unwrap();
    let queued = pdu.clone();
    server.sbi_offload.spawn(async move {
        Some(crate::sbi_offload::SbiOutcome::MappingResponse {
            association_id: ASSOC + 6,
            pdu: queued,
        })
    });
    server.sbi_offload.settle().await;

    server.process_sbi_outcomes().await;

    assert_eq!(take_sent_ngap(&mut server), vec![(ASSOC + 6, pdu)]);
}

/// The lookup runs off the NGAP task: the handler returns while the UCMF has not
/// answered, and a 404 then records the ID as deleted, with no answer sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_id_is_resolved_off_the_ngap_task() {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    let _g = racs_guard();
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::clone(&release);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let ucmf = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    ucmf.start(move |_req: SReq| {
        let gate = Arc::clone(&gate);
        async move {
            // The UCMF answers only when the test lets it.
            gate.notified().await;
            SResp::with_status(404)
        }
    })
    .await
    .expect("stand-in UCMF starts");
    let _env = UcmfEnvGuard::set(addr.port());
    let mut server = capturing_ngap_server().await;

    tokio::time::timeout(
        Duration::from_secs(2),
        server.handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request()),
    )
    .await
    .expect("the handler does not wait for the UCMF")
    .expect("handled");
    assert_eq!(in_flight(&server), 1);

    release.notify_one();
    for _ in 0..500 {
        if in_flight(&server) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(in_flight(&server), 0, "the lookup finished");
    assert!(crate::racs::is_known_deleted(&ID));
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
    assert!(take_sent_ngap(&mut server).is_empty());
}

/// Points the AMF's UCMF calls at `port` while held.
struct UcmfEnvGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl UcmfEnvGuard {
    fn set(port: u16) -> Self {
        let guard = crate::test_support::UCMF_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UCMF_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UCMF_SBI_PORT", port.to_string());
        Self(guard)
    }
}

impl Drop for UcmfEnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("UCMF_SBI_ADDR");
        std::env::remove_var("UCMF_SBI_PORT");
    }
}
