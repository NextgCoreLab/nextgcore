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
    server.mapping_resolves.len()
}

/// A manufacturer-assigned ID (Type Field digit != 1, TS 23.003 §29.2).
const MAN_ID: [u8; 7] = [0x02, 0x05, 0x00, 0x00, 0x00, 0x07, 0x48];

/// A UE RADIO CAPABILITY ID MAPPING REQUEST for `id`.
fn mapping_request_for(id: &[u8]) -> Vec<u8> {
    let mut pdu = vec![
        0x00, 0x3C, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x08, 0x00, 0x08, 0x07,
    ];
    pdu.extend_from_slice(id);
    pdu
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
    // Fill every slot with other IDs' lookups.
    for n in 0..MAX_MAPPING_RESOLVES_IN_FLIGHT {
        server.mapping_resolves.insert(
            vec![0x01, 0x05, 0x00, 0x00, 0x00, 0x09, n as u8],
            crate::ngap_path::MappingResolve {
                waiting: vec![ASSOC],
                started: std::time::Instant::now(),
            },
        );
    }

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request())
        .await
        .expect("handled");

    assert_eq!(in_flight(&server), MAX_MAPPING_RESOLVES_IN_FLIGHT);
    assert!(!server.mapping_resolves.contains_key(ID.as_slice()));
    assert!(take_sent_ngap(&mut server).is_empty());
}

/// An answer an off-task lookup produced is sent by the NGAP pump, on the
/// association that asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pump_sends_an_off_task_answer() {
    let mut server = capturing_ngap_server().await;
    let pdu = crate::racs::build_mapping_response(&ID, &[0xCC]).unwrap();
    server.mapping_resolves.insert(
        ID.to_vec(),
        crate::ngap_path::MappingResolve {
            waiting: vec![ASSOC + 6],
            started: std::time::Instant::now(),
        },
    );
    server.sbi_offload.spawn(async move {
        Some(crate::sbi_offload::SbiOutcome::MappingResponse {
            id: ID.to_vec(),
            capability: Some(vec![0xCC]),
        })
    });
    server.sbi_offload.settle().await;

    server.process_sbi_outcomes().await;

    assert_eq!(take_sent_ngap(&mut server), vec![(ASSOC + 6, pdu)]);
}

/// The lookup runs off the NGAP task: the handler returns while the UCMF has not
/// answered, and a 404 for a PLMN-assigned ID then retires it, with no answer
/// sent.
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
    // The slot is released by the pump, not by the job (#925 review MINOR 2).
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
    assert_eq!(
        in_flight(&server),
        0,
        "the lookup finished and freed its slot"
    );
    // A PLMN-assigned ID's 404 is authoritative: it retires the ID.
    assert!(crate::racs::is_known_deleted(&ID));
    assert!(crate::racs::is_retired(&ID));
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

/// #925 review MAJOR 1: a manufacturer-assigned ID that 404s before the UCMF has
/// it is looked up again once a `CREATION_OF_DICTIONARY_ENTRY` notification says
/// it exists. Before this, the 404 was permanent and RACS stayed dead for that
/// model.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_creation_notification_makes_a_404ed_id_resolvable_again() {
    let _g = racs_guard();
    let mut server = capturing_ngap_server().await;
    // The 404 the UCMF gave for it.
    crate::racs::note_unresolved_for_tests(&MAN_ID);
    assert!(crate::racs::is_known_deleted(&MAN_ID));
    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request_for(&MAN_ID))
        .await
        .expect("handled");
    assert_eq!(
        in_flight(&server),
        0,
        "within the TTL, no lookup is started"
    );

    // Nucmf_Provisioning added the entry, and the UCMF notified it.
    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "CREATION_OF_DICTIONARY_ENTRY",
        "newDicEntries": [{ "manAssiUeRadioCapId": crate::racs::to_nucmf(&MAN_ID).unwrap() }],
    }));
    assert!(!crate::racs::is_known_deleted(&MAN_ID));

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request_for(&MAN_ID))
        .await
        .expect("handled");
    assert_eq!(in_flight(&server), 1, "the ID is looked up again");
    assert_eq!(
        server.mapping_resolves[&MAN_ID.to_vec()].waiting,
        vec![ASSOC]
    );
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
}

/// The negative a 404 leaves for a manufacturer-assigned ID expires, so the ID is
/// looked up again even without a notification (#925 review MAJOR 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_404_negative_for_a_manufacturer_id_expires() {
    let _g = racs_guard();
    let mut server = capturing_ngap_server().await;
    crate::racs::note_unresolved_for_tests(&MAN_ID);
    assert!(crate::racs::is_known_deleted(&MAN_ID));

    crate::racs::expire_unresolved_for_tests();

    assert!(!crate::racs::is_known_deleted(&MAN_ID));
    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request_for(&MAN_ID))
        .await
        .expect("handled");
    assert_eq!(in_flight(&server), 1);
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
}

/// #925 review MINOR 3: several associations asking for ONE id start one Resolve,
/// and every one of them gets its answer. Driven through the real handler, a real
/// 200 Resolve at a stand-in UCMF, the offload and the pump (MINOR 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_resolve_answers_every_association_that_asked() {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    let _g = racs_guard();
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let capability = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let answered = capability.clone();
    let resolves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&resolves);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let ucmf = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    ucmf.start(move |_req: SReq| {
        let (counted, answered) = (Arc::clone(&counted), answered.clone());
        async move {
            counted.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            // A 200 Resolve: the capability in its `ueRadioCapability5GS` part.
            SResp::with_status(200)
                .with_json_body(&serde_json::json!({
                    "ueRadioCapability5GS": { "contentId": "ueRadioCapability5GS" },
                }))
                .expect("json")
                .with_part(nextgcore_sbi::message::SbiPart::with_content(
                    "ueRadioCapability5GS",
                    "application/vnd.3gpp.ngap",
                    bytes::Bytes::from(answered),
                ))
        }
    })
    .await
    .expect("stand-in UCMF starts");
    let _env = UcmfEnvGuard::set(addr.port());
    let mut server = capturing_ngap_server().await;

    // Three gNBs ask for the same ID.
    for assoc in [ASSOC, ASSOC + 1, ASSOC + 2] {
        server
            .handle_ue_radio_capability_id_mapping(assoc, &mapping_request())
            .await
            .expect("handled");
    }
    assert_eq!(in_flight(&server), 1, "one Resolve for the three requests");
    assert_eq!(
        server.mapping_resolves[&ID.to_vec()].waiting,
        vec![ASSOC, ASSOC + 1, ASSOC + 2]
    );

    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;

    assert_eq!(
        resolves.load(std::sync::atomic::Ordering::Acquire),
        1,
        "the UCMF saw exactly one Resolve"
    );
    let pdu = crate::racs::build_mapping_response(&ID, &capability).expect("response");
    assert_eq!(
        take_sent_ngap(&mut server),
        vec![
            (ASSOC, pdu.clone()),
            (ASSOC + 1, pdu.clone()),
            (ASSOC + 2, pdu)
        ],
        "every association that asked is answered"
    );
    assert_eq!(in_flight(&server), 0, "the slot is released");
    assert_eq!(
        crate::racs::cache_get(&ID).as_deref(),
        Some(&capability[..])
    );
}

/// #925 review MINOR 2: a lookup whose job never reports does not hold its slot
/// for ever — the next request past `STALE_MAPPING_RESOLVE` releases it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lookup_that_never_reports_does_not_hold_its_slot() {
    let _g = racs_guard();
    let mut server = capturing_ngap_server().await;
    for n in 0..MAX_MAPPING_RESOLVES_IN_FLIGHT {
        server.mapping_resolves.insert(
            vec![0x01, 0x05, 0x00, 0x00, 0x00, 0x0A, n as u8],
            crate::ngap_path::MappingResolve {
                waiting: vec![ASSOC],
                // Started longer ago than any SBI exchange can take.
                started: std::time::Instant::now() - STALE_MAPPING_RESOLVE - Duration::from_secs(1),
            },
        );
    }

    server
        .handle_ue_radio_capability_id_mapping(ASSOC, &mapping_request())
        .await
        .expect("handled");

    assert_eq!(in_flight(&server), 1, "the stale slots were released");
    assert!(server.mapping_resolves.contains_key(ID.as_slice()));
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
}
