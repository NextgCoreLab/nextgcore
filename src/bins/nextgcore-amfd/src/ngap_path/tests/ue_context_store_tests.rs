//! #686: UE contexts survive an AMF restart.
//!
//! Each test drives one AMF ("before"): it registers a UE and stores it through the
//! production sweep, into a backend the test holds. The "crash" drops every trace of
//! the UE from the process. A fresh `NgapServer` ("after") then restores from the same
//! backend, as `amf_ngap_open` does, and gets real NAS and NGAP bytes.
//!
//! The UE store and the AMF session list are process-global, so every test uses its own
//! SUPI, 5G-TMSI and AMF UE NGAP IDs.

use super::super::ue_context_store::{
    guti_served, open_with, MemoryBackend, ServedGuami, StoredUeContext, UeContextBackend,
    UeContextWriter, DL_COUNT_RESTORE_MARGIN, RECORD_VERSION,
};
use super::*;
use std::sync::Arc;

const SLICE_SD: u32 = 0x00_0686;

/// A registered UE under `id` with a real NAS security context (NIA2/NEA2, keys,
/// COUNTs), the 5G-GUTI of `tmsi`, and PDU session 5 at the SMF on `smf_port`.
fn seed_registered_ue(
    server: &mut NgapServer,
    id: u64,
    tmsi: u32,
    supi: &str,
    sm_ref: &str,
    smf_port: u16,
    connected: bool,
) {
    let mut ue = idle_ue_with_security(id, tmsi);
    ue.amf_ue.supi = Some(supi.to_string());
    ue.amf_ue.kamf = [0x33; 32];
    ue.amf_ue.dl_count = 0x0102;
    ue.amf_ue.nas_ksi = 1;
    ue.amf_ue.ue_ambr = crate::context::Bitrate {
        downlink: 2_000_000,
        uplink: 1_000_000,
    };
    ue.amf_ue.ue_security_capability = crate::context::UeSecurityCapability {
        ea: 0xE0,
        ia: 0x60,
        eea: 0,
        eia: 0,
    };
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: 1,
        sd: Some(SLICE_SD),
    }];
    ue.amf_ue.uecm_dereg_token = Some(format!("tok-{id}"));
    ue.sdm_subscription_id = Some(format!("sdm-{id}"));
    if connected {
        ue.cm_idle = false;
        ue.reachability = None;
        ue.association_id = 1;
    }
    server.ue_auth_state.insert(id, ue);
    server.sm_context_refs.insert((id, 5), sm_ref.to_string());
    server
        .sm_context_smfs
        .insert((id, 5), ("127.0.0.1".to_string(), smf_port));
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
    let mut sess = guard.sess_add(id, 5).expect("PSI 5");
    sess.sm_context_ref = Some(sm_ref.to_string());
    sess.s_nssai = crate::context::SNssai {
        sst: 1,
        sd: Some(SLICE_SD),
    };
    sess.dnn = Some("internet".to_string());
    guard.sess_update(&sess);
}

/// The AMF "crashes": nothing of UE `id` is left in the process.
fn crash(server: &mut NgapServer, id: u64) {
    server.forget_ue(id);
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
    while let Some(sess) = guard.sess_find_by_psi(id, 5) {
        guard.sess_remove(sess.id);
    }
}

/// The AMF Region / Set / Pointer of `idle_ue_with_security`'s 5G-GUTI (PLMN 001/01).
fn fixture_guami() -> ServedGuami {
    (crate::context::PlmnId::new("001", "01"), 0x02, 0x155, 0x2A)
}

/// An AMF serving the fixture's GUAMI.
async fn restoring_server() -> NgapServer {
    let mut server = test_ngap_server().await;
    server.served_guami_override = Some(vec![fixture_guami()]);
    server
}

/// An AMF storing into `backend`, as `amf_ngap_open` arms it.
async fn storing_server(backend: &Arc<MemoryBackend>) -> NgapServer {
    let mut server = restoring_server().await;
    server.attach_ue_context_store(UeContextWriter::spawn(
        Arc::clone(backend) as Arc<dyn UeContextBackend>
    ));
    server
}

/// A backend holding only `supi`'s record from `backend`. The "before" AMF's sweep also
/// stored the UEs other tests hold in the process-global UE store; restoring those
/// would put ghosts into it.
fn only(backend: &MemoryBackend, supi: &str) -> Arc<MemoryBackend> {
    let alone = Arc::new(MemoryBackend::default());
    alone.put(&backend.get(supi).expect("stored")).expect("put");
    alone
}

/// Store everything `server` holds, and wait until it reached the backend.
async fn store_now(server: &mut NgapServer) {
    server.flush_ue_contexts(Duration::from_secs(2)).await;
}

/// A SERVICE REQUEST from 5GMM-IDLE (TS 24.501 §8.2.16, §4.4.6) for the UE `ue`
/// describes: integrity protected under its keys at uplink NAS COUNT `count`, with its
/// NAS message container (Uplink data status and PDU session status: PSI 5) ciphered.
fn protected_idle_service_request(ue: &AmfUe, tmsi: u32, count: u32) -> Vec<u8> {
    let mut cleartext = vec![0x7E, 0x00, 0x4C, 0x11, 0x00, 0x07, 0xF4, 0x55, 0x6A];
    cleartext.extend_from_slice(&tmsi.to_be_bytes());
    let mut inner = cleartext.clone();
    inner.extend_from_slice(&[0x40, 0x02, 0x20, 0x00, 0x50, 0x02, 0x20, 0x00]);
    let mut container = inner;
    nas_security::nas_encrypt(
        ue.selected_enc_algorithm,
        &ue.knas_enc,
        count,
        ue.access_type,
        nas_security::direction::UPLINK,
        &mut container,
    );
    let mut outer = cleartext;
    outer.push(0x71);
    outer.extend_from_slice(&(container.len() as u16).to_be_bytes());
    outer.extend_from_slice(&container);
    let sqn = (count & 0xFF) as u8;
    let mut mac_input = vec![sqn];
    mac_input.extend_from_slice(&outer);
    let mac = nas_security::nas_mac_calculate(
        ue.selected_int_algorithm,
        &ue.knas_int,
        count,
        ue.access_type,
        nas_security::direction::UPLINK,
        &mac_input,
    );
    let mut nas = vec![0x7E, 0x01];
    nas.extend_from_slice(&mac);
    nas.push(sqn);
    nas.extend_from_slice(&outer);
    nas
}

/// **#686.** A registered CM-IDLE UE is stored and, after the AMF restarts, restored
/// with its identity, 5G-GUTI, NAS security context and PDU session. Its next
/// SERVICE REQUEST, protected under the keys it already had, is verified, and the
/// stored session's user plane is re-activated at the stored SMF and SM context
/// (`upCnxState: ACTIVATING`, TS 29.502 §5.2.2.3.2.2). No re-registration and no new
/// PDU session.
///
/// The downlink NAS COUNT moves on by 255 (TS 24.501 §4.4.3.1). The uplink one is the
/// stored one, so the UE's next COUNT verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_ue_s_service_request_reactivates_its_stored_session() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let (old_id, sr_id, tmsi) = (6_860_101u64, 6_860_103u64, 0x0686_0101u32);
    let supi = "imsi-001010000686101";

    let mut before = storing_server(&backend).await;
    seed_registered_ue(&mut before, old_id, tmsi, supi, "ref-686-a", port, false);
    let original = before.ue_auth_state.get(old_id).expect("seeded");
    store_now(&mut before).await;
    let stored = backend.get(supi).expect("the registered UE is stored");
    assert_eq!(stored.version, RECORD_VERSION);
    assert_eq!(stored.sessions.len(), 1);
    assert_eq!(stored.sessions[0].sm_context_ref, "ref-686-a");
    assert_eq!(
        stored.sessions[0].smf,
        Some(("127.0.0.1".to_string(), port))
    );
    assert_eq!(stored.security.dl_count, 0x0102);
    crash(&mut before, old_id);
    drop(before);

    let backend = only(&backend, supi);
    let mut after = storing_server(&backend).await;
    open_with(
        &mut after,
        Arc::clone(&backend) as Arc<dyn UeContextBackend>,
    )
    .await;
    let (new_id, restored) = after
        .ue_auth_state
        .find_by_supi(supi)
        .expect("the UE is restored");
    assert!(restored.registered && restored.cm_idle && restored.restored);
    assert!(
        restored.reachability.is_some(),
        "mobile reachable timer runs"
    );
    assert!(restored.has_registration_area(), "it can be paged");
    let (a, b) = (&restored.amf_ue, &original.amf_ue);
    assert_eq!(a.current_guti, b.current_guti, "the same 5G-GUTI");
    assert_eq!(
        (a.kamf, a.knas_int, a.knas_enc),
        (b.kamf, b.knas_int, b.knas_enc)
    );
    assert_eq!((a.selected_int_algorithm, a.selected_enc_algorithm), (2, 2));
    assert_eq!(a.ul_count, b.ul_count, "the uplink COUNT as stored");
    assert_eq!(
        a.dl_count,
        b.dl_count + DL_COUNT_RESTORE_MARGIN,
        "the downlink COUNT moves on by 255"
    );
    assert_eq!(a.allowed_nssai, b.allowed_nssai);
    assert_eq!(a.ue_ambr, b.ue_ambr);
    assert_eq!(a.uecm_dereg_token, b.uecm_dereg_token);
    assert_eq!(
        after.sm_context_refs.get(&(new_id, 5)).map(String::as_str),
        Some("ref-686-a")
    );
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let sess = guard.sess_find_by_psi(new_id, 5).expect("PSI 5 restored");
        assert_eq!(sess.s_nssai.sd, Some(SLICE_SD));
        assert_eq!(sess.dnn.as_deref(), Some("internet"));
    }

    // The UE comes back with the next uplink COUNT.
    after.forced_amf_ue_ngap_id = Some(sr_id);
    let nas = protected_idle_service_request(&restored.amf_ue, tmsi, b.ul_count + 1);
    let _ = after
        .handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await;
    settle_offloaded_sbi(&mut after).await;
    let calls = seen.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|(uri, body)| uri.contains("/sm-contexts/ref-686-a/modify")
                && body.contains("ACTIVATING")),
        "the stored session is re-activated at the stored SMF: {calls:?}"
    );
    assert!(
        !calls.iter().any(|(uri, _)| uri.contains("/release")),
        "nothing is released: {calls:?}"
    );
    let resumed = after.ue_auth_state.get(sr_id).expect("resumed");
    assert_eq!(resumed.amf_ue.supi.as_deref(), Some(supi));
    assert!(!resumed.cm_idle, "CM-CONNECTED again");
    assert_eq!(resumed.amf_ue.ul_count, b.ul_count + 1, "verified");
    crash(&mut after, sr_id);
}

/// **#686.** A UE CM-CONNECTED when stored has no NG connection after the restart: it is
/// released as an NG Reset would release it (TS 23.502 §4.2.6). Its session's user plane
/// is DEACTIVATED at the stored SMF, so downlink data is buffered and pages the UE, and
/// the UE is CM-IDLE, supervised and pageable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_connected_when_stored_is_restored_idle_with_its_user_plane_deactivated() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let (old_id, tmsi) = (6_860_201u64, 0x0686_0201u32);
    let supi = "imsi-001010000686201";

    let mut before = storing_server(&backend).await;
    seed_registered_ue(&mut before, old_id, tmsi, supi, "ref-686-b", port, true);
    store_now(&mut before).await;
    assert!(backend.get(supi).expect("stored").cm_connected);
    crash(&mut before, old_id);
    drop(before);

    let backend = only(&backend, supi);
    let mut after = storing_server(&backend).await;
    open_with(
        &mut after,
        Arc::clone(&backend) as Arc<dyn UeContextBackend>,
    )
    .await;
    settle_offloaded_sbi(&mut after).await;
    let (new_id, restored) = after.ue_auth_state.find_by_supi(supi).expect("restored");
    assert!(restored.cm_idle, "CM-IDLE: no NG connection survived");
    assert!(
        restored.reachability.is_some(),
        "mobile reachable timer runs"
    );
    assert!(
        crate::namf_server::ue_pageable(&restored.amf_ue),
        "an N1N2MessageTransfer for it pages it"
    );
    let calls = seen.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|(uri, body)| uri.contains("/sm-contexts/ref-686-b/modify")
                && body.contains("DEACTIVATED")),
        "the user plane is deactivated at the stored SMF: {calls:?}"
    );
    crash(&mut after, new_id);
}

/// A backend recording each write and delete, by SUPI, over a [`MemoryBackend`].
///
/// The UE store is process-global, so a sweep also sees UEs other tests hold; the
/// assertions below only look at this test's SUPI.
#[derive(Default)]
struct RecordingBackend {
    inner: MemoryBackend,
    ops: std::sync::Mutex<Vec<(&'static str, String)>>,
}

impl RecordingBackend {
    fn ops_for(&self, supi: &str) -> Vec<&'static str> {
        self.ops
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s == supi)
            .map(|(op, _)| *op)
            .collect()
    }
}

impl UeContextBackend for RecordingBackend {
    fn put(&self, rec: &StoredUeContext) -> Result<(), String> {
        self.ops.lock().unwrap().push(("put", rec.supi.clone()));
        self.inner.put(rec)
    }
    fn delete(&self, supi: &str) -> Result<(), String> {
        self.ops.lock().unwrap().push(("delete", supi.to_string()));
        self.inner.delete(supi)
    }
    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String> {
        self.inner.load(amf_instance_id)
    }
}

/// **#686.** What the sweep writes for a UE:
/// - once when stable;
/// - nothing more while it is unchanged, and nothing before the sweep interval;
/// - again when it changes;
/// - nothing while a NAS procedure is in flight (its last stable record stays);
/// - a delete once the UE is no longer held.
#[tokio::test]
async fn the_sweep_writes_changes_only_and_deletes_ues_no_longer_held() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(RecordingBackend::default());
    let (id, tmsi) = (6_860_301u64, 0x0686_0301u32);
    let supi = "imsi-001010000686301";
    let mut server = test_ngap_server().await;
    server.attach_ue_context_store(UeContextWriter::spawn(
        Arc::clone(&backend) as Arc<dyn UeContextBackend>
    ));
    seed_registered_ue(&mut server, id, tmsi, supi, "ref-686-c", 7777, false);

    server.persist_ue_contexts(true);
    server.persist_ue_contexts(true);
    server.persist_ue_contexts(false);
    store_now(&mut server).await;
    assert_eq!(
        backend.ops_for(supi),
        vec!["put"],
        "one write: then unchanged, then not due"
    );
    server
        .ue_auth_state
        .with_mut(id, |s| s.amf_ue.dl_count += 1);
    store_now(&mut server).await;
    assert_eq!(backend.ops_for(supi), vec!["put", "put"], "changed");

    server.ue_auth_state.with_mut(id, |s| {
        s.amf_ue.dl_count += 1;
        s.retx = Some(NasRetx {
            timer: NasProcTimer::T3550,
            deadline: Instant::now() + Duration::from_secs(6),
            retries: 0,
            ngap_pdu: Vec::new(),
        });
    });
    store_now(&mut server).await;
    assert_eq!(
        backend.ops_for(supi),
        vec!["put", "put"],
        "mid-procedure: kept as last stored"
    );
    assert_eq!(
        backend.inner.get(supi).expect("stored").security.dl_count,
        0x0103
    );

    crash(&mut server, id);
    store_now(&mut server).await;
    assert_eq!(backend.ops_for(supi), vec!["put", "put", "delete"]);
    assert!(backend.inner.get(supi).is_none(), "deleted");
}

/// **#686.** Only this AMF instance's records of the current format are restored. A record
/// written by another AMF instance waits for the AMF Set takeover (TS 23.501 §5.21.2.3),
/// which updates the UDM first. Skipped records stay in the store.
#[tokio::test]
async fn records_of_another_amf_instance_or_version_are_not_restored() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let mut before = storing_server(&backend).await;
    seed_registered_ue(
        &mut before,
        6_860_401,
        0x0686_0401,
        "imsi-001010000686401",
        "ref-686-d",
        7777,
        false,
    );
    store_now(&mut before).await;
    crash(&mut before, 6_860_401);
    let mut rec: StoredUeContext = backend.get("imsi-001010000686401").expect("stored");
    let mut other = rec.clone();
    other.supi = "imsi-001010000686402".to_string();
    other.amf_instance_id = "00000000-0000-4000-8000-000000000686".to_string();
    let mut old = rec.clone();
    old.supi = "imsi-001010000686403".to_string();
    old.version = RECORD_VERSION + 1;
    rec.supi = "imsi-001010000686404".to_string();
    rec.guti.tmsi = 0x0686_0404;

    let mut after = restoring_server().await;
    let summary = after
        .restore_ue_contexts(vec![other, old, rec.clone()])
        .await;
    assert_eq!(summary.restored.len(), 1, "{summary:?}");
    assert_eq!(summary.skipped, 2);
    assert!(after
        .ue_auth_state
        .find_by_supi("imsi-001010000686402")
        .is_none());
    assert!(after
        .ue_auth_state
        .find_by_supi("imsi-001010000686403")
        .is_none());
    let (id, _) = after
        .ue_auth_state
        .find_by_supi("imsi-001010000686404")
        .expect("this instance's record");
    crash(&mut after, id);
}

/// The record survives the BSON encoding the MongoDB backend stores, and its `Debug`
/// carries no key material (#861).
#[tokio::test]
async fn a_record_round_trips_through_bson_and_debug_shows_no_keys() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let mut server = storing_server(&backend).await;
    seed_registered_ue(
        &mut server,
        6_860_501,
        0x0686_0501,
        "imsi-001010000686501",
        "ref-686-e",
        7777,
        false,
    );
    store_now(&mut server).await;
    crash(&mut server, 6_860_501);
    let rec = backend.get("imsi-001010000686501").expect("stored");
    let bson = mongodb::bson::to_bson(&rec).expect("encodes");
    let back: StoredUeContext = mongodb::bson::from_bson(bson).expect("decodes");
    assert!(back == rec, "BSON round trip");
    let shown = format!("{rec:?}");
    assert!(
        !shown.contains("17, 17") && !shown.contains("51, 51") && !shown.contains("kamf"),
        "{shown}"
    );
}

/// **#686 across a real MongoDB.** Put, load (by instance) and delete through
/// [`super::super::ue_context_store::MongoBackend`]. Ignored: needs `NEXTG_TEST_MONGO_URI`,
/// for example a `mongo:6.0` container on a private bridge.
#[test]
#[ignore = "needs a MongoDB at NEXTG_TEST_MONGO_URI"]
fn the_mongodb_backend_stores_loads_and_deletes() {
    use super::super::ue_context_store::MongoBackend;
    let uri = std::env::var("NEXTG_TEST_MONGO_URI").expect("NEXTG_TEST_MONGO_URI");
    let backend = MongoBackend::connect(&uri).expect("connects");
    let rec = StoredUeContext {
        version: RECORD_VERSION,
        amf_instance_id: "00000000-0000-4000-8000-0000006860aa".to_string(),
        supi: "imsi-001010000686601".to_string(),
        suci: String::new(),
        gpsi: None,
        pei: None,
        imeisv: None,
        msisdn: Vec::new(),
        home_plmn_id: Default::default(),
        guti: crate::context::Guti5gs {
            tmsi: 0x0686_0601,
            ..Default::default()
        },
        tai: Default::default(),
        cgi: Default::default(),
        access_type: 1,
        registration_type: 1,
        requested_nssai: Vec::new(),
        allowed_nssai: vec![crate::context::SNssai {
            sst: 1,
            sd: Some(SLICE_SD),
        }],
        rejected_nssai: Vec::new(),
        ue_ambr: Default::default(),
        gmm_capability: Default::default(),
        ue_security_capability: Default::default(),
        ue_network_capability: Default::default(),
        redcap_indication: false,
        slice_admission_granted: false,
        racs_supported: false,
        ue_radio_capability_id: None,
        ue_radio_capability_id_known_to_ue: false,
        assigned_ebis: Vec::new(),
        uecm_dereg_token: Some("tok".to_string()),
        sdm_subscription_id: None,
        policy_association: Default::default(),
        ue_policy_association: Default::default(),
        security: super::super::ue_context_store::StoredSecurity {
            nas_ksi: 1,
            nas_tsc: 0,
            nas_ue_ksi: 1,
            nas_ue_tsc: 0,
            kamf: vec![0x33; 32],
            knas_int: vec![0x11; 16],
            knas_enc: vec![0x22; 16],
            kgnb: vec![0; 32],
            nh: vec![0; 32],
            nhcc: 0,
            selected_int_algorithm: 2,
            selected_enc_algorithm: 2,
            ul_count: 4,
            ul_count_established: true,
            dl_count: 0x0102,
        },
        sessions: Vec::new(),
        cm_connected: false,
    };
    backend.put(&rec).expect("put");
    let mut changed = rec.clone();
    changed.security.dl_count = 0x0103;
    backend.put(&changed).expect("replace");
    let loaded = backend.load(&rec.amf_instance_id).expect("load");
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0] == changed, "the replaced record");
    assert!(backend
        .load("00000000-0000-4000-8000-0000006860bb")
        .expect("load other")
        .is_empty());
    backend.delete(&rec.supi).expect("delete");
    assert!(backend.load(&rec.amf_instance_id).expect("load").is_empty());
}

/// Only a 5G-GUTI of a served GUAMI can bring its UE back to this AMF: a record whose
/// GUTI names another AMF (the GUAMI configuration changed) is not restored.
#[test]
fn a_guti_is_served_only_under_a_served_guami() {
    let served = vec![fixture_guami()];
    let mut guti = crate::context::Guti5gs {
        plmn_id: crate::context::PlmnId::new("001", "01"),
        amf_region_id: 0x02,
        amf_set_id: 0x155,
        amf_pointer: 0x2A,
        tmsi: 1,
    };
    assert!(guti_served(&served, &guti));
    assert!(guti_served(&[], &guti), "no GUAMI configured: any");
    guti.amf_pointer = 0x2B;
    assert!(!guti_served(&served, &guti), "another AMF Pointer");
    guti.amf_pointer = 0x2A;
    guti.amf_set_id = 0x156;
    assert!(!guti_served(&served, &guti), "another AMF Set");
    guti.amf_set_id = 0x155;
    guti.plmn_id = crate::context::PlmnId::new("001", "02");
    assert!(!guti_served(&served, &guti), "another PLMN");
}
