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
    guti_served, open_with, MemoryBackend, ServedGuami, StoredUeContext, UeContextBackend, Written,
    DL_COUNT_RESTORE_MARGIN, RECORD_VERSION,
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
    server.attach_ue_context_store(Arc::clone(backend) as Arc<dyn UeContextBackend>);
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
/// The downlink NAS COUNT moves on by 127 (TS 24.501 §4.4.3.1). The uplink one is the
/// stored one, so the UE's next COUNT verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_ue_s_service_request_reactivates_its_stored_session() {
    // The SMF holding the SM context, and another one SMF selection would find: the
    // stored owner (#669) is what the re-activation must use.
    let (_smf, port, seen) = fake_activating_smf().await;
    let (_selected, selected_port, selected_seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(selected_port).await;
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
    assert_eq!(
        backend.get(supi).expect("stored").security.dl_count,
        0x0102 + DL_COUNT_RESTORE_MARGIN,
        "#1176 review m2: the moved-on downlink COUNT is stored before any association"
    );
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
        "the downlink COUNT moves on by 127"
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
    assert!(
        selected_seen.lock().unwrap().is_empty(),
        "nothing goes to another SMF"
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
    fn put(&self, rec: &StoredUeContext) -> Result<Written, String> {
        self.ops.lock().unwrap().push(("put", rec.supi.clone()));
        self.inner.put(rec)
    }
    fn delete(&self, supi: &str, amf_instance_id: &str) -> Result<(), String> {
        self.ops.lock().unwrap().push(("delete", supi.to_string()));
        self.inner.delete(supi, amf_instance_id)
    }
    fn owner(&self, supi: &str) -> Result<Option<String>, String> {
        self.inner.owner(supi)
    }
    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String> {
        self.inner.load(amf_instance_id)
    }
    fn take_over(
        &self,
        s_tmsi: super::super::ue_context_store::STmsi,
        to_instance: &str,
    ) -> Result<Option<StoredUeContext>, String> {
        self.inner.take_over(s_tmsi, to_instance)
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
    server.attach_ue_context_store(Arc::clone(&backend) as Arc<dyn UeContextBackend>);
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

/// **#686.** Only this AMF instance's records of the current format, whose 5G-GUTI this
/// AMF serves and whose SUPI it does not already hold, are restored. A record
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
    let mut unserved = rec.clone();
    unserved.supi = "imsi-001010000686405".to_string();
    unserved.guti.amf_pointer = 0x2B;
    let mut held = rec.clone();
    held.supi = "imsi-001010000686406".to_string();
    rec.supi = "imsi-001010000686404".to_string();
    rec.guti.tmsi = 0x0686_0404;

    let mut after = restoring_server().await;
    // A UE this AMF already holds (it registered again before the record was read).
    let mut live = idle_ue_with_security(6_860_406, 0x0686_0406);
    live.amf_ue.supi = Some(held.supi.clone());
    after.ue_auth_state.insert(6_860_406, live);
    let summary = after
        .restore_ue_contexts(vec![other, old, unserved, held, rec.clone()])
        .await;
    assert_eq!(summary.restored.len(), 1, "{summary:?}");
    assert_eq!(summary.skipped, 4);
    assert!(
        after
            .ue_auth_state
            .find_by_supi("imsi-001010000686405")
            .is_none(),
        "a GUTI of an AMF this one is not"
    );
    assert_eq!(
        after
            .ue_auth_state
            .snapshot()
            .iter()
            .filter(|(_, s)| s.amf_ue.supi.as_deref() == Some("imsi-001010000686406"))
            .count(),
        1,
        "a SUPI already held is not restored a second time"
    );
    after.ue_auth_state.remove(6_860_406);
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
        priority_subscription: false,
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
    // #686 PR 2: another AMF of the set claims it by 5G-S-TMSI, once.
    const PEER: &str = "00000000-0000-4000-8000-0000006860cc";
    let s_tmsi = (
        changed.guti.amf_set_id,
        changed.guti.amf_pointer,
        changed.guti.tmsi,
    );
    assert!(backend
        .take_over((s_tmsi.0, s_tmsi.1, s_tmsi.2 + 1), PEER)
        .expect("lookup")
        .is_none());
    let claimed = backend
        .take_over(s_tmsi, PEER)
        .expect("lookup")
        .expect("claimed");
    assert_eq!(claimed.amf_instance_id, PEER);
    assert!(claimed.security == changed.security, "the stored context");
    assert!(
        backend.take_over(s_tmsi, PEER).expect("lookup").is_none(),
        "once"
    );
    assert_eq!(
        backend.load(PEER).expect("load").len(),
        1,
        "it names the claimer"
    );
    assert!(backend.load(&rec.amf_instance_id).expect("load").is_empty());
    backend
        .delete(&rec.supi, &rec.amf_instance_id)
        .expect("delete");
    assert_eq!(
        backend.load(PEER).expect("load").len(),
        1,
        "#1185 review M1: the old owner's delete leaves the new owner's record"
    );
    assert_eq!(
        backend.put(&changed).expect("put"),
        Written::Lost,
        "and its write is refused as lost"
    );
    assert_eq!(
        backend.owner(&rec.supi).expect("owner").as_deref(),
        Some(PEER)
    );
    backend.delete(&rec.supi, PEER).expect("delete");
    assert!(backend.load(PEER).expect("load").is_empty());
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

/// A backend refusing the first `fail` writes and deletes, then storing.
struct FlakyBackend {
    inner: MemoryBackend,
    fail: std::sync::atomic::AtomicUsize,
}

impl FlakyBackend {
    fn refusing(fail: usize) -> Self {
        Self {
            inner: MemoryBackend::default(),
            fail: std::sync::atomic::AtomicUsize::new(fail),
        }
    }

    fn refuse(&self) -> Result<(), String> {
        let left = self.fail.load(std::sync::atomic::Ordering::SeqCst);
        if left > 0 {
            self.fail
                .store(left - 1, std::sync::atomic::Ordering::SeqCst);
            return Err("store unavailable".to_string());
        }
        Ok(())
    }
}

impl UeContextBackend for FlakyBackend {
    fn put(&self, rec: &StoredUeContext) -> Result<Written, String> {
        if rec.supi == FLAKY_SUPI {
            self.refuse()?;
        }
        self.inner.put(rec)
    }
    fn delete(&self, supi: &str, amf_instance_id: &str) -> Result<(), String> {
        if supi == FLAKY_SUPI {
            self.refuse()?;
        }
        self.inner.delete(supi, amf_instance_id)
    }
    fn owner(&self, supi: &str) -> Result<Option<String>, String> {
        self.inner.owner(supi)
    }
    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String> {
        self.inner.load(amf_instance_id)
    }
    fn take_over(
        &self,
        s_tmsi: super::super::ue_context_store::STmsi,
        to_instance: &str,
    ) -> Result<Option<StoredUeContext>, String> {
        self.inner.take_over(s_tmsi, to_instance)
    }
}

const FLAKY_SUPI: &str = "imsi-001010000686701";

/// **#1176 review m1.** A write or delete the store refused is retried by the next sweep.
/// Without that, an unchanged UE would stay unstored after a store blip, and a refused
/// delete would leave a record that a restart restores as a registered UE.
#[tokio::test]
async fn a_refused_write_or_delete_is_retried_by_the_next_sweep() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(FlakyBackend::refusing(1));
    let id = 6_860_701u64;
    let mut server = restoring_server().await;
    server.attach_ue_context_store(Arc::clone(&backend) as Arc<dyn UeContextBackend>);
    seed_registered_ue(
        &mut server,
        id,
        0x0686_0701,
        FLAKY_SUPI,
        "ref-686-g",
        7777,
        false,
    );

    store_now(&mut server).await;
    assert!(
        backend.inner.get(FLAKY_SUPI).is_none(),
        "the first write was refused"
    );
    store_now(&mut server).await;
    assert!(
        backend.inner.get(FLAKY_SUPI).is_some(),
        "the unchanged UE is written by the next sweep"
    );

    backend.fail.store(1, std::sync::atomic::Ordering::SeqCst);
    crash(&mut server, id);
    store_now(&mut server).await;
    assert!(
        backend.inner.get(FLAKY_SUPI).is_some(),
        "the delete was refused"
    );
    store_now(&mut server).await;
    assert!(
        backend.inner.get(FLAKY_SUPI).is_none(),
        "the delete is sent again by the next sweep"
    );
}

/// **#1176 review m3.** A registered UE is stored only in a state worth restoring. These
/// are not:
/// - an unauthenticated emergency registration, which has no key hierarchy (TS 33.501
///   §10.2.2);
/// - a registration update being answered;
/// - a UE without a NAS security context.
///
/// A restore marks the security context available, so storing either of those would
/// restore one that does not exist.
#[tokio::test]
async fn ues_in_a_state_not_worth_restoring_are_not_written() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(RecordingBackend::default());
    let mut server = restoring_server().await;
    server.attach_ue_context_store(Arc::clone(&backend) as Arc<dyn UeContextBackend>);
    let cases: [(u64, &str, fn(&mut UeNasContext)); 3] = [
        (6_860_801, "imsi-001010000686801", |s| {
            s.amf_ue.unauthenticated_emergency = true
        }),
        (6_860_802, "imsi-001010000686802", |s| {
            s.registration_session_ies = Some(ServiceRequestSessionIes::default())
        }),
        (6_860_803, "imsi-001010000686803", |s| {
            s.amf_ue.security_context_available = false
        }),
    ];
    for (id, supi, unworthy) in cases {
        seed_registered_ue(&mut server, id, id as u32, supi, "ref-686-h", 7777, false);
        server.ue_auth_state.with_mut(id, unworthy);
    }
    store_now(&mut server).await;
    for (id, supi, _) in cases {
        assert!(backend.ops_for(supi).is_empty(), "{supi} is not stored");
        crash(&mut server, id);
    }
}

/// A server of the fixture's AMF Set under another AMF Pointer (0x2B): another AMF of
/// the set, the one a UE of the failed 0x2A AMF is sent to (TS 23.501 §5.21.2.3).
async fn set_peer_server(backend: &Arc<MemoryBackend>) -> NgapServer {
    let mut server = test_ngap_server().await;
    server.served_guami_override = Some(vec![(
        crate::context::PlmnId::new("001", "01"),
        0x02,
        0x155,
        0x2B,
    )]);
    server.attach_ue_context_store(Arc::clone(backend) as Arc<dyn UeContextBackend>);
    server
}

/// What `amf_ue` stored, as the failed AMF instance `dead` wrote it.
fn stored_by(backend: &MemoryBackend, supi: &str, dead: &str) -> StoredUeContext {
    let mut rec = backend.get(supi).expect("stored");
    rec.amf_instance_id = dead.to_string();
    backend.force(rec.clone());
    rec
}

const DEAD_AMF: &str = "00000000-0000-4000-8000-00000000dead";

/// **#686 PR 2, TS 23.501 §5.21.2.3.** The UE of an AMF that failed comes back with a
/// SERVICE REQUEST to another AMF of its AMF Set. That AMF:
/// - claims the UE's stored context (the record now names it);
/// - verifies the request under the stored keys;
/// - registers with the UDM as the serving AMF, under its own nfInstanceId
///   (TS 29.503 §5.3.2.2.2), and keeps the new `deregCallbackUri` token;
/// - tells the SMF holding the session that it serves it (`servingNfId`,
///   `smContextStatusUri`, TS 29.502 Table 6.1.6.2.2-1), BEFORE the session's
///   ACTIVATING;
/// - owes, and starts, a 5G-GUTI reallocation to its own GUAMI ("shall not use old GUAMI
///   to allocate 5G-GUTI").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_of_a_failed_amf_is_taken_over_by_its_service_request() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let (_selected, selected_port, selected_seen) = fake_activating_smf().await;
    let (_udm, udm_port, udm_seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(selected_port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let (old_id, tmsi) = (6_860_901u64, 0x0686_0901u32);
    let supi = "imsi-001010000686901";

    // The failed AMF (pointer 0x2A) stored the UE, then went away.
    let mut failed = storing_server(&backend).await;
    seed_registered_ue(&mut failed, old_id, tmsi, supi, "ref-686-t", port, false);
    let original = failed.ue_auth_state.get(old_id).expect("seeded");
    store_now(&mut failed).await;
    crash(&mut failed, old_id);
    drop(failed);
    let backend = only(&backend, supi);
    stored_by(&backend, supi, DEAD_AMF);

    let mut peer = set_peer_server(&backend).await;
    peer.udm_override = Some(("127.0.0.1".to_string(), udm_port));
    peer.sent_ngap = Some(Vec::new());
    let nas = protected_idle_service_request(&original.amf_ue, tmsi, original.amf_ue.ul_count + 1);
    peer.handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }

    let instance = nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Amf);
    assert_eq!(
        backend.get(supi).expect("record").amf_instance_id,
        instance,
        "the stored context is claimed"
    );
    let (id, ue) = peer.ue_auth_state.find_by_supi(supi).expect("taken over");
    assert!(
        !ue.cm_idle,
        "the Service Request was verified and the UE is connected"
    );
    assert!(!ue.taken_over, "the peer updates went out once");

    let udm = udm_seen.lock().unwrap().clone();
    let put = udm
        .iter()
        .find(|(uri, _)| {
            uri.contains(&format!(
                "/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access"
            ))
        })
        .unwrap_or_else(|| panic!("UECM registration at the UDM: {udm:?}"));
    let body: serde_json::Value = serde_json::from_str(&put.1).expect("json");
    assert_eq!(body["amfInstanceId"], instance, "as the serving AMF");
    assert!(
        ue.amf_ue.uecm_dereg_token.as_deref() != original.amf_ue.uecm_dereg_token.as_deref()
            && ue.amf_ue.uecm_dereg_token.is_some(),
        "the accepted registration's token is the UE's"
    );

    let calls = seen.lock().unwrap().clone();
    let serving = calls
        .iter()
        .position(|(uri, body)| {
            uri.contains("/sm-contexts/ref-686-t/modify") && body.contains("servingNfId")
        })
        .unwrap_or_else(|| panic!("the SMF is told of the new AMF: {calls:?}"));
    let serving_body: serde_json::Value = serde_json::from_str(&calls[serving].1).expect("json");
    assert_eq!(serving_body["servingNfId"], instance);
    assert_eq!(
        serving_body["smContextStatusUri"],
        crate::sbi_path::sm_context_status_uri(supi, 5)
    );
    assert_eq!(
        serving_body["guami"]["amfId"], "02556b",
        "this AMF's GUAMI (pointer 0x2B)"
    );
    let activating = calls
        .iter()
        .position(|(uri, body)| {
            uri.contains("/sm-contexts/ref-686-t/modify") && body.contains("ACTIVATING")
        })
        .unwrap_or_else(|| panic!("the session is re-activated: {calls:?}"));
    assert!(
        serving < activating,
        "the SMF learns of the new AMF first: {calls:?}"
    );
    assert!(selected_seen.lock().unwrap().is_empty(), "no other SMF");
    assert!(ue.guti_reallocation_owed, "a new 5G-GUTI is owed");
    // The gNB set the UE context up: the new 5G-GUTI goes out.
    peer.handle_initial_context_setup_response(1, &ics_response_pdu(id, 512, &[], &[]))
        .await
        .expect("ICS Response");
    let ue = peer.ue_auth_state.get(id).expect("UE");
    assert!(
        !ue.guti_reallocation_owed
            && ue.amf_ue.next_guti.amf_pointer == 0x2B
            && ue.amf_ue.next_guti.tmsi != tmsi,
        "a UE Configuration Update gives it a 5G-GUTI of this AMF's GUAMI"
    );
    assert!(
        matches!(ue.retx.as_ref().map(|r| r.timer), Some(NasProcTimer::T3555)),
        "supervised by T3555"
    );
    crash(&mut peer, id);
}

/// **#686 PR 2.** A takeover claims a record written by ANOTHER AMF instance, and only
/// one whose 5G-S-TMSI matches. Once claimed, the record names the claimer, so the same
/// AMF does not take it over again. A UE with no stored context is processed as before:
/// its SERVICE REQUEST gets SERVICE REJECT #9.
#[tokio::test]
async fn a_takeover_claims_another_instance_s_record_and_without_one_nothing_changes() {
    use super::super::ue_context_store::UeContextBackend as _;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let mut failed = storing_server(&backend).await;
    let (old_id, tmsi, supi) = (6_861_001u64, 0x0686_1001u32, "imsi-001010000686100");
    seed_registered_ue(&mut failed, old_id, tmsi, supi, "ref-686-u", 7777, false);
    store_now(&mut failed).await;
    crash(&mut failed, old_id);
    let backend = only(&backend, supi);
    stored_by(&backend, supi, DEAD_AMF);
    const ME: &str = "00000000-0000-4000-8000-0000000000a1";
    assert!(
        backend
            .take_over((0x155, 0x2A, tmsi + 1), ME)
            .expect("lookup")
            .is_none(),
        "another 5G-S-TMSI"
    );
    assert!(
        backend
            .take_over((0x155, 0x2B, tmsi), ME)
            .expect("lookup")
            .is_none(),
        "another AMF Pointer"
    );
    let claimed = backend
        .take_over((0x155, 0x2A, tmsi), ME)
        .expect("lookup")
        .expect("the failed AMF's record");
    assert_eq!(claimed.amf_instance_id, ME);
    assert_eq!(backend.get(supi).expect("stored").amf_instance_id, ME);
    assert!(
        backend
            .take_over((0x155, 0x2A, tmsi), ME)
            .expect("lookup")
            .is_none(),
        "its own record is not taken over again"
    );

    let mut peer = set_peer_server(&Arc::new(MemoryBackend::default())).await;
    peer.sent_ngap = Some(Vec::new());
    let nas = protected_service_request([0; 4], 0x0686_1099);
    peer.handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    assert!(
        peer.sent_ngap.as_ref().unwrap().is_empty(),
        "held for the lookup"
    );
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }
    assert!(
        !peer.sent_ngap.as_ref().unwrap().is_empty(),
        "processed as before once nothing was found (SERVICE REJECT #9)"
    );
}

/// **#686 PR 2, TS 23.502 §4.2.2.2.2 step 4.** The UE of a failed AMF comes back with an
/// integrity-protected periodic REGISTRATION REQUEST (TS 24.501 §4.4.6) to another AMF of
/// its set. Its context is taken over, the request is verified, the UDM and the SMF learn
/// of the new AMF, and the Registration Accept's 5G-GUTI is one of this AMF's GUAMI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_of_a_failed_amf_is_taken_over_by_its_registration_request() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let (_udm, udm_port, udm_seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let (old_id, tmsi) = (6_861_101u64, 0x0686_1101u32);
    let supi = "imsi-001010000686111";
    let mut failed = storing_server(&backend).await;
    seed_registered_ue(&mut failed, old_id, tmsi, supi, "ref-686-r", port, false);
    let original = failed.ue_auth_state.get(old_id).expect("seeded");
    store_now(&mut failed).await;
    crash(&mut failed, old_id);
    drop(failed);
    let backend = only(&backend, supi);
    stored_by(&backend, supi, DEAD_AMF);

    let mut peer = set_peer_server(&backend).await;
    peer.udm_override = Some(("127.0.0.1".to_string(), udm_port));
    peer.sent_ngap = Some(Vec::new());
    let rr =
        guti_registration_request(crate::gmm_build::registration_type::PERIODIC_UPDATING, tmsi);
    let nas =
        protected_initial_registration(&original.amf_ue, &rr, &rr, original.amf_ue.ul_count + 1);
    peer.handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }
    let (id, ue) = peer.ue_auth_state.find_by_supi(supi).expect("taken over");
    assert!(!ue.cm_idle && !ue.taken_over, "verified, peer updates sent");
    assert_eq!(ue.amf_ue.next_guti.amf_pointer, 0x2B, "this AMF's GUAMI");
    assert_ne!(ue.amf_ue.next_guti.tmsi, tmsi, "a new 5G-TMSI");
    assert!(
        udm_seen
            .lock()
            .unwrap()
            .iter()
            .any(|(uri, _)| uri.contains("registrations/amf-3gpp-access")),
        "UECM registration"
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(uri, body)| uri.contains("/sm-contexts/ref-686-r/modify")
                && body.contains("servingNfId")),
        "the SMF learns of the new AMF"
    );
    crash(&mut peer, id);
}

/// **#686 PR 2.** No store lookup for a UE this AMF holds, or for an identity of another
/// AMF Set: those take the existing paths at once.
#[tokio::test]
async fn no_takeover_for_a_ue_held_here_or_of_another_amf_set() {
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let mut peer = set_peer_server(&backend).await;
    let tmsi = 0x0686_1201u32;
    let held = protected_service_request([0; 4], tmsi);
    assert_eq!(
        peer.takeover_candidate(&held),
        Some((0x155, 0x2A, tmsi)),
        "a 5G-S-TMSI of this set held by no UE here is looked up"
    );
    let mut ue = idle_registered_ue(6_861_201);
    ue.amf_ue.current_guti.plmn_id = crate::context::PlmnId::new("001", "01");
    ue.amf_ue.current_guti.amf_region_id = 0x02;
    ue.amf_ue.current_guti.tmsi = tmsi;
    peer.ue_auth_state.insert(6_861_201, ue);
    assert_eq!(peer.takeover_candidate(&held), None, "held here");
    peer.ue_auth_state.remove(6_861_201);
    peer.served_guami_override = Some(vec![(
        crate::context::PlmnId::new("001", "01"),
        0x02,
        0x156,
        0x2B,
    )]);
    assert_eq!(peer.takeover_candidate(&held), None, "another AMF Set");
    let off = test_ngap_server().await;
    assert_eq!(off.takeover_candidate(&held), None, "storage off");
}

/// A stand-in NF refusing every request with 500, recording them as (path, body).
async fn refusing_nf() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    use nextgcore_sbi::server::{SbiServer as NSbiServer, SbiServerConfig as NSbiCfg};
    let seen: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = NSbiServer::on_listener(NSbiCfg::new(addr), listener);
    server
        .start(move |req: SReq| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push((
                    req.header.uri.clone(),
                    req.http.content.clone().unwrap_or_default(),
                ));
                SResp::with_status(500)
            }
        })
        .await
        .expect("stand-in starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (server, addr.port(), seen)
}

/// The UE of the "failed" AMF, stored under `dead`, and a peer of the set about to take
/// it over. Returns (backend, the UE as stored, peer).
async fn ue_of_a_failed_amf(
    id: u64,
    tmsi: u32,
    supi: &str,
    sm_ref: &str,
    smf_port: u16,
    connected: bool,
) -> (Arc<MemoryBackend>, UeNasContext, NgapServer) {
    let backend = Arc::new(MemoryBackend::default());
    let mut failed = storing_server(&backend).await;
    seed_registered_ue(&mut failed, id, tmsi, supi, sm_ref, smf_port, connected);
    let original = failed.ue_auth_state.get(id).expect("seeded");
    store_now(&mut failed).await;
    crash(&mut failed, id);
    drop(failed);
    let backend = only(&backend, supi);
    stored_by(&backend, supi, DEAD_AMF);
    let peer = set_peer_server(&backend).await;
    (backend, original, peer)
}

/// **#1185 review m1.** A taken-over UE whose message does not verify is restored idle
/// (it was CM-CONNECTED at the AMF that failed) and supervised, and is owed its peer
/// updates still: no UDM registration and no SMF update went out for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_over_ue_whose_message_fails_integrity_is_idle_and_owed_its_updates() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let (_udm, udm_port, udm_seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let (tmsi, supi) = (0x0686_1301u32, "imsi-001010000686131");
    let (_backend, original, mut peer) =
        ue_of_a_failed_amf(6_861_301, tmsi, supi, "ref-686-v", port, true).await;
    peer.udm_override = Some(("127.0.0.1".to_string(), udm_port));
    peer.sent_ngap = Some(Vec::new());
    let mut nas =
        protected_idle_service_request(&original.amf_ue, tmsi, original.amf_ue.ul_count + 1);
    nas[2] ^= 0xFF; // the MAC fails
    peer.handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }
    let (id, ue) = peer.ue_auth_state.find_by_supi(supi).expect("taken over");
    assert!(
        ue.cm_idle,
        "idle here, whatever it was at the AMF that failed"
    );
    assert!(ue.reachability.is_some(), "its mobile reachable timer runs");
    assert!(ue.taken_over, "the peer updates are still owed");
    assert!(
        udm_seen.lock().unwrap().is_empty(),
        "no UECM registration yet"
    );
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|(_, b)| b.contains("servingNfId")),
        "no SMF update yet"
    );
    crash(&mut peer, id);
}

/// **#1185 review m1.** The UDM refuses the takeover's UECM registration: the UE keeps
/// the token it had (the UDM's registration is still the old one, #753).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_takeover_registration_keeps_the_old_token() {
    let (_smf, port, _seen) = fake_activating_smf().await;
    let (_udm, udm_port, udm_seen) = refusing_nf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let (tmsi, supi) = (0x0686_1401u32, "imsi-001010000686141");
    let (_backend, original, mut peer) =
        ue_of_a_failed_amf(6_861_401, tmsi, supi, "ref-686-w", port, false).await;
    peer.udm_override = Some(("127.0.0.1".to_string(), udm_port));
    peer.sent_ngap = Some(Vec::new());
    let nas = protected_idle_service_request(&original.amf_ue, tmsi, original.amf_ue.ul_count + 1);
    peer.handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }
    assert!(
        !udm_seen.lock().unwrap().is_empty(),
        "the registration was tried"
    );
    let (id, ue) = peer.ue_auth_state.find_by_supi(supi).expect("taken over");
    assert_eq!(
        ue.amf_ue.uecm_dereg_token, original.amf_ue.uecm_dereg_token,
        "the refused registration's token is not the UE's"
    );
    crash(&mut peer, id);
}

/// **#1185 review m1, m2.**
/// - A UE that registered here while its context was being fetched keeps that
///   registration: the fetched one is not installed beside it.
/// - A second Initial UE Message for the identity, arriving during the lookup, waits
///   for the same lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lookup_waits_for_duplicates_and_yields_to_a_ue_registered_meanwhile() {
    let (_smf, port, _seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let (tmsi, supi) = (0x0686_1501u32, "imsi-001010000686151");
    let (_backend, original, mut peer) =
        ue_of_a_failed_amf(6_861_501, tmsi, supi, "ref-686-x", port, false).await;
    peer.sent_ngap = Some(Vec::new());
    let nas = protected_idle_service_request(&original.amf_ue, tmsi, original.amf_ue.ul_count + 1);
    for _ in 0..2 {
        peer.handle_initial_ue_message(1, &service_request_initial_ue(nas.clone()))
            .await
            .expect("handled");
    }
    assert_eq!(
        peer.pending_takeovers.values().map(Vec::len).sum::<usize>(),
        2,
        "both wait for one lookup"
    );
    // Meanwhile the UE registers here afresh.
    let mut fresh = idle_registered_ue(6_861_502);
    fresh.amf_ue.supi = Some(supi.to_string());
    fresh.amf_ue.current_guti.tmsi = 0x0686_1502;
    peer.ue_auth_state.insert(6_861_502, fresh);
    for _ in 0..3 {
        settle_offloaded_sbi(&mut peer).await;
    }
    assert!(peer.pending_takeovers.is_empty(), "both were processed");
    // Both were processed: no UE here holds their 5G-S-TMSI (the fetched context was not
    // installed beside the fresh registration), so each is answered SERVICE REJECT #9.
    let sent: Vec<super::handler_tests::Sent> = peer
        .sent_ngap
        .take()
        .unwrap_or_default()
        .iter()
        .map(|(_, _, pdu)| super::handler_tests::decode_sent(pdu))
        .collect();
    let rejects = sent
        .iter()
        .filter(|s| {
            matches!(s, super::handler_tests::Sent::DownlinkNas { nas_pdu, .. }
                if nas_pdu[..] == [0x7E, 0x00, 0x4D, 0x09])
        })
        .count();
    assert_eq!(rejects, 2, "each held message is answered: {sent:?}");
    let held: Vec<u64> = peer
        .ue_auth_state
        .snapshot()
        .into_iter()
        .filter(|(_, s)| s.amf_ue.supi.as_deref() == Some(supi))
        .map(|(id, _)| id)
        .collect();
    assert_eq!(held, vec![6_861_502], "only the registration made here");
    peer.ue_auth_state.remove(6_861_502);
}

/// **#1185 review m1.** A REGISTRATION REQUEST's 5G-GUTI must name this AMF Set's region
/// and PLMN as well: a GUTI of another region is not looked up.
#[tokio::test]
async fn a_registration_guti_of_another_region_is_not_looked_up() {
    crate::context::amf_context_init(64, 1024, 4096);
    let peer = set_peer_server(&Arc::new(MemoryBackend::default())).await;
    let ue = idle_ue_with_security(6_861_601, 0x0686_1601);
    let rr = guti_registration_request(
        crate::gmm_build::registration_type::PERIODIC_UPDATING,
        0x0686_1601,
    );
    let nas = protected_initial_registration(&ue.amf_ue, &rr, &rr, 5);
    assert_eq!(
        peer.takeover_candidate(&nas),
        Some((0x155, 0x2A, 0x0686_1601)),
        "region 2 of this set"
    );
    let mut other = rr.clone();
    other[10] = 0x03; // AMF Region ID 3
    let nas = protected_initial_registration(&ue.amf_ue, &other, &other, 5);
    assert_eq!(peer.takeover_candidate(&nas), None, "another region");
}

/// **#1185 review M1.** The old AMF is alive after all: its UEs were taken over by a
/// peer of the set (its gNB could not reach it, a partition). It must not tear down what
/// the peer took over:
/// - told by the UDM to deregister a UE locally, it finds the record names the peer and
///   only forgets the UE, with no SM context release;
/// - writing a UE again (it changed) is refused as lost, and the UE is forgotten;
/// - the peer's records survive either way.
///
/// The peer is its claim in the store: two AMFs in one process would share the
/// process-global UE store, which two real AMFs do not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_old_amf_forgets_a_taken_over_ue_without_releasing_it() {
    use super::super::ue_context_store::UeContextBackend as _;
    let _serial = crate::namf_server::dereg_queue_test_lock().lock().await;
    let (_smf, port, seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    const OLD: &str = "00000000-0000-4000-8000-0000000001d0";
    const PEER: &str = "00000000-0000-4000-8000-0000000001d1";
    let backend = Arc::new(MemoryBackend::default());
    let (tmsi, supi) = (0x0686_1701u32, "imsi-001010000686171");
    let (tmsi2, supi2) = (0x0686_1702u32, "imsi-001010000686172");

    let mut old = restoring_server().await;
    old.instance_override = Some(OLD.to_string());
    old.attach_ue_context_store(Arc::clone(&backend) as Arc<dyn UeContextBackend>);
    seed_registered_ue(&mut old, 6_861_701, tmsi, supi, "ref-686-y1", port, false);
    seed_registered_ue(&mut old, 6_861_702, tmsi2, supi2, "ref-686-y2", port, false);
    store_now(&mut old).await;
    assert_eq!(backend.get(supi).expect("stored").amf_instance_id, OLD);
    // A peer of the set claims both.
    for t in [tmsi, tmsi2] {
        backend
            .take_over((0x155, 0x2A, t), PEER)
            .expect("lookup")
            .expect("claimed");
    }

    // 1. The UDM's notification makes the old AMF deregister the first UE locally.
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().expect("ctx");
        guard.network_dereg_add(crate::context::PendingNetworkDereg {
            amf_ue_ngap_id: 6_861_701,
            reregistration_required: false,
            gmm_cause: None,
            local: true,
        });
    }
    old.process_network_deregs().await;
    for _ in 0..3 {
        settle_offloaded_sbi(&mut old).await;
    }
    assert!(!old.ue_auth_state.contains(6_861_701), "forgotten");

    // 2. The old AMF writes the second UE again: refused as lost, and forgotten.
    old.ue_auth_state
        .with_mut(6_861_702, |s| s.amf_ue.dl_count += 1);
    store_now(&mut old).await;
    for supi in old.persist_ue_contexts(true).lost {
        old.forget_moved_ue(&supi).await;
    }
    assert!(!old.ue_auth_state.contains(6_861_702), "forgotten");

    // Its sweep would delete the records of the UEs it no longer holds: only its own.
    store_now(&mut old).await;
    let calls = seen.lock().unwrap().clone();
    assert!(
        !calls.iter().any(|(uri, _)| uri.contains("/release")),
        "no SM context was released: {calls:?}"
    );
    assert_eq!(backend.get(supi).expect("record").amf_instance_id, PEER);
    assert_eq!(backend.get(supi2).expect("record").amf_instance_id, PEER);
    for id in [6_861_701, 6_861_702] {
        crash(&mut old, id);
    }
}

/// **#1185 review m1.** The implicit deregistration timer is the third path that releases
/// a UE's sessions and policies. At a live old AMF that missed the UDM's notification, a
/// taken-over UE's timer expires all the same: the store says the UE moved, so it is only
/// forgotten. A UE whose record is still this AMF's is implicitly deregistered as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_implicit_deregistration_of_a_taken_over_ue_releases_nothing() {
    use super::super::ue_context_store::UeContextBackend as _;
    let (_smf, port, seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    const OLD: &str = "00000000-0000-4000-8000-0000000001e0";
    const PEER: &str = "00000000-0000-4000-8000-0000000001e1";
    let backend = Arc::new(MemoryBackend::default());
    let mut old = restoring_server().await;
    old.instance_override = Some(OLD.to_string());
    old.attach_ue_context_store(Arc::clone(&backend) as Arc<dyn UeContextBackend>);
    let (moved, kept) = (
        (6_861_801u64, 0x0686_1801u32),
        (6_861_802u64, 0x0686_1802u32),
    );
    seed_registered_ue(
        &mut old,
        moved.0,
        moved.1,
        "imsi-001010000686181",
        "ref-686-z1",
        port,
        false,
    );
    seed_registered_ue(
        &mut old,
        kept.0,
        kept.1,
        "imsi-001010000686182",
        "ref-686-z2",
        port,
        false,
    );
    store_now(&mut old).await;
    backend
        .take_over((0x155, 0x2A, moved.1), PEER)
        .expect("lookup")
        .expect("claimed");
    for id in [moved.0, kept.0] {
        old.ue_auth_state.with_mut(id, |s| {
            s.reachability = Some(Reachability {
                phase: ReachabilityPhase::ImplicitDeregistration,
                deadline: Instant::now() - Duration::from_millis(1),
            })
        });
    }
    old.process_reachability_timers().await.expect("timers");
    for _ in 0..3 {
        settle_offloaded_sbi(&mut old).await;
    }
    assert!(
        !old.ue_auth_state.contains(moved.0),
        "the moved UE is forgotten"
    );
    assert!(
        !old.ue_auth_state.contains(kept.0),
        "the other is deregistered"
    );
    let calls = seen.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|(uri, _)| uri.contains("ref-686-z1/release")),
        "the moved UE's session is not released: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|(uri, _)| uri.contains("ref-686-z2/release")),
        "the UE still this AMF's is released as before: {calls:?}"
    );
    for id in [moved.0, kept.0] {
        crash(&mut old, id);
    }
}

/// **#1185 review m1 (round 3).** The owner check before an implicit deregistration is a
/// store round trip. A UE that comes back in it (a new N1 connection, so CM-CONNECTED,
/// or idle again with its supervision restarted) is not deregistered when the answer
/// arrives. A returning UE normally moves to a new AMF UE NGAP ID, which leaves nothing
/// under the old one; here its context comes back under the same id, the case that
/// would otherwise release its sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_back_during_the_owner_check_is_not_implicitly_deregistered() {
    let (_smf, port, seen) = fake_activating_smf().await;
    let _env = SmfEnvGuard::acquire(port).await;
    crate::context::amf_context_init(64, 1024, 4096);
    let backend = Arc::new(MemoryBackend::default());
    let mut amf = storing_server(&backend).await;
    let (back, again) = (
        (6_861_901u64, 0x0686_1901u32),
        (6_861_902u64, 0x0686_1902u32),
    );
    seed_registered_ue(
        &mut amf,
        back.0,
        back.1,
        "imsi-001010000686191",
        "ref-686-q1",
        port,
        false,
    );
    seed_registered_ue(
        &mut amf,
        again.0,
        again.1,
        "imsi-001010000686192",
        "ref-686-q2",
        port,
        false,
    );
    store_now(&mut amf).await;
    for id in [back.0, again.0] {
        amf.ue_auth_state.with_mut(id, |s| {
            s.reachability = Some(Reachability {
                phase: ReachabilityPhase::ImplicitDeregistration,
                deadline: Instant::now() - Duration::from_millis(1),
            })
        });
    }
    amf.process_reachability_timers().await.expect("timers");
    // In the round trip: one is connected again, the other supervised again.
    amf.ue_auth_state.with_mut(back.0, |s| s.cm_idle = false);
    amf.ue_auth_state.with_mut(again.0, |s| {
        s.reachability = Some(Reachability {
            phase: ReachabilityPhase::MobileReachable,
            deadline: Instant::now() + Duration::from_secs(3600),
        })
    });
    for _ in 0..3 {
        settle_offloaded_sbi(&mut amf).await;
    }
    assert!(amf.ue_auth_state.contains(back.0) && amf.ue_auth_state.contains(again.0));
    let calls = seen.lock().unwrap().clone();
    assert!(
        !calls.iter().any(|(uri, _)| uri.contains("/release")),
        "nothing released: {calls:?}"
    );
    for id in [back.0, again.0] {
        crash(&mut amf, id);
    }
}

/// The downlink COUNT a UE estimates from a received SN (TS 24.501 §4.4.3.1), given
/// `last`, the largest COUNT it verified, as a conformant UE does it: the smallest COUNT
/// above `last` with that SN.
fn estimate_conformant(last: u32, sn: u32) -> u32 {
    let candidate = (last & !0xFF) | sn;
    if candidate > last {
        candidate
    } else {
        candidate + 0x100
    }
}

/// The same, as a UE with a replay window: an SN step forward of at most half the SN
/// space (128) is the next COUNT, wrapping the overflow if the SN is lower; anything
/// else is a replay (`None`). nextgsim's UE does this.
fn estimate_windowed(last: u32, sn: u32) -> Option<u32> {
    let step = sn.wrapping_sub(last & 0xFF) & 0xFF;
    if step == 0 || step > 128 {
        return None;
    }
    Some(last + step)
}

/// **#686.** The restored downlink COUNT, the stored next COUNT plus the margin:
/// - is above every COUNT used before the restart, for up to 127 unrecorded downlink
///   messages;
/// - is estimated exactly by a conformant UE and by one with a half-space replay window,
///   whatever the stored COUNT and however many of those messages it received.
///
/// A margin of 254 is a replay to the windowed UE, which is what the real-binary restart
/// proof found.
#[test]
fn the_restored_downlink_count_is_estimated_right_by_any_ue() {
    for stored_next in [1u32, 0x0102, 0x01FF, 0x0200, 0x1234, 0xFFFF00] {
        let restored = (stored_next + DL_COUNT_RESTORE_MARGIN) & 0x00FF_FFFF;
        for unrecorded in 0..=DL_COUNT_RESTORE_MARGIN {
            let last = stored_next - 1 + unrecorded; // the largest COUNT the UE verified
            assert!(
                restored > last,
                "never reused ({stored_next:#x}, +{unrecorded})"
            );
            let sn = restored & 0xFF;
            assert_eq!(estimate_conformant(last, sn), restored);
            assert_eq!(
                estimate_windowed(last, sn),
                Some(restored),
                "{stored_next:#x} +{unrecorded}"
            );
        }
    }
    let stored_next = 0x0102u32;
    assert_eq!(
        estimate_windowed(stored_next - 1, (stored_next + 254) & 0xFF),
        None,
        "254 is a replay to a windowed UE"
    );
}
