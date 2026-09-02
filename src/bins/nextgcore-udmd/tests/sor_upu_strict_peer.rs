//! Wave-6 F-07 — TRUE strict-peer SoR/UPU integration test: real udmd
//! am-data injection ↔ real ausfd Nausf_SoRProtection / Nausf_UPUProtection
//! producers, end-to-end over a loopback SBI HTTP/2 server, with an
//! INDEPENDENT MAC recompute and counter/replay/wrap adversarial cases.
//!
//! Specs emulated NF-side:
//! - TS 33.501 §6.14.2.1 (SoR message sequence) / §6.15.2.1 (UPU)
//! - TS 33.501 §6.14.2.3 / §6.15.2.2 (Counter_SoR / Counter_UPU invariants)
//! - TS 33.501 Annex A.17-A.20 (SoR/UPU-MAC-I_AUSF / -I_UE, FC 0x77/0x78/0x7B/0x7C)
//! - specs/TS29509_Nausf_SoRProtection.yaml, TS29509_Nausf_UPUProtection.yaml
//! - specs/TS29503_Nudm_SDM.yaml (SorInfo / UpuInfo / AcknowledgeInfo)
//!
//! Why this is a STRICT peer (not the pcfd lenient-mock trap): the positive
//! path drives udmd's REAL am-data SoR/UPU injectors
//! ([`nextgcore_udmd::maybe_inject_sor_info`] / `maybe_inject_upu_info`),
//! whose internal AUSF client makes a REAL SBI HTTP request to a REAL ausfd
//! dispatcher ([`nextgcore_ausfd::ausf_sbi_request_handler`]) running on a
//! loopback port — no canned peer, no shortcut. The returned MAC is then
//! reproduced from the seeded KAUSF with a raw `Hmac<Sha256>` S-string
//! assembly (this file's [`independent_mac`]), which does NOT reuse the
//! nextgcore-crypt KDF the ausfd producer computes with — so equality is a
//! genuine two-implementation cross-check, and corrupting the ausfd
//! steering/UPU wire encoder makes Scenario 1 / 6 FAIL (wire-byte sensitivity).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::Duration;

use nextgcore_ausfd::{ausf_sbi_request_handler, ausf_self};
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::SbiRequest;
use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
use nextgcore_sbi::types::{NfType, SbiServiceType};
use nextgcore_udmd::context::{SorSteeringConfig, UpuConfig};
use nextgcore_udmd::{
    handle_sor_ack, handle_upu_ack, maybe_inject_sor_info, maybe_inject_upu_info, udm_self,
};

// ---------------------------------------------------------------------------
// Independent MAC oracle (raw HMAC-SHA-256, NOT the production KDF)
// ---------------------------------------------------------------------------

/// TS 33.220 clause B.2.0 generic KDF, assembled BY HAND from raw
/// `Hmac<Sha256>`: `S = FC || P0 || L0 || P1 || L1 || ...` where each `Li` is
/// the 2-octet big-endian length of the preceding `Pi`. The SoR/UPU MAC is the
/// 128 **least** significant bits — the LAST 16 bytes — of the 256-bit output
/// (TS 33.501 Annex A.17-A.20). Deliberately independent of
/// `nextgcore_crypt::kdf` (which the ausfd producer uses) so this test is a
/// cross-implementation oracle, not a self-confirmation.
fn independent_mac(key: &[u8], fc: u8, params: &[&[u8]]) -> [u8; 16] {
    let mut s = vec![fc];
    for p in params {
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&s);
    let out = mac.finalize().into_bytes();
    let mut m = [0u8; 16];
    m.copy_from_slice(&out[16..]); // last 16 bytes = 128 LSBs
    m
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Golden wire vectors (hand-derived — identical derivation to the ausfd F-03
// and udmd F-04/F-05 unit vectors, re-stated here as this test's independent
// P2 / P0 input; NOT taken from any handler intermediate).
// ---------------------------------------------------------------------------

/// TS 29.509 `SteeringContainer` (SteeringInfo[]) exactly as configured on the
/// UDM. The AUSF performs the TS 24.501 §9.11.3.51 wire encoding.
fn golden_container() -> serde_json::Value {
    serde_json::json!([
        {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": ["NR"]},
        {"plmnId": {"mcc": "310", "mnc": "410"},
         "accessTechList": ["NR", "EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE"]}
    ])
}

/// Hand-derived TS 24.501 §9.11.3.51 fig. 9.11.3.51.3 "PLMN ID and access
/// technology list" bytes for `golden_container()` (TS 31.102 §4.2.5):
/// entry 1: mcc=001 mnc=01 → BCD 00 F1 10 (MNC digit 3 = 0xF for a 2-digit
///          MNC); AcT NR → NG-RAN bit b4 of octet 1 = 08 00.
/// entry 2: mcc=310 mnc=410 → BCD 13 00 14; AcT NR|E-UTRAN → 48 00.
const GOLDEN_LIST: [u8; 10] = [0x00, 0xF1, 0x10, 0x08, 0x00, 0x13, 0x00, 0x14, 0x48, 0x00];

/// The SOR header (TS 24.501 fig. 9.11.3.51.5 octet 4) the AUSF constructs for
/// `{ackInd:true, steeringContainer:[PLMN list]}`: b2 list indication | b3 list
/// type (PLMN list) | b4 ACK = 0x02|0x04|0x08 = 0x0E.
const SOR_HEADER_ACK_PLMN_LIST: u8 = 0x0E;

/// TS 29.509 `UpuData[]` exactly as configured on the UDM.
fn golden_upu_data_list() -> serde_json::Value {
    serde_json::json!([
        {"routingId": "1234"},
        {"defaultConfNssai": [{"sst": 1}, {"sst": 2, "sd": "00007B"}]}
    ])
}

/// Hand-derived TS 24.501 §9.11.3.53A "UE parameters update list" bytes for
/// `golden_upu_data_list()` (fig. 9.11.3.53A.2):
/// set 1: ME routing indicator (type 0100), len 0x0002, "1234" → BCD 21 43.
/// set 2: default configured NSSAI (type 0010), len 0x0007, NSSAI value part
///        {sst:1} → 01 01, {sst:2, sd:00007B} → 04 02 00 00 7B.
const GOLDEN_UPU_LIST: [u8; 15] = [
    0x04, 0x00, 0x02, 0x21, 0x43, // ME routing indicator data set
    0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x7B, // NSSAI data set
];

// FC values (TS 33.501 Annex A.17-A.20), verified against specs/33501-k20.txt.
const FC_SOR_MAC_IAUSF: u8 = 0x77; // A.17
const FC_SOR_MAC_IUE: u8 = 0x78; // A.18
const FC_UPU_MAC_IAUSF: u8 = 0x7B; // A.19
const FC_UPU_MAC_IUE: u8 = 0x7C; // A.20

const PROVISIONING_TIME: &str = "2026-07-01T00:00:00Z";
const AUSF_INSTANCE_ID: &str = "ausf-f07-strict-peer";

/// A representative UDR am-data body the injectors operate on. It carries no
/// pre-provisioned sorInfo/upuInfo, so the steering/UPU source is the udmd
/// config (F-04/F-05 precedence branch (b)).
const RAW_AM_DATA: &str =
    r#"{"gpsis":["msisdn-777"],"subscribedUeAmbr":{"uplink":"1 Gbps","downlink":"2 Gbps"}}"#;

fn test_kausf(tag: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = tag ^ (i as u8);
    }
    k
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// Seed the ausfd per-SUPI anchor store (F-02) with a known KAUSF, exactly as
/// a completed primary authentication would (TS 33.501 §6.14.1). `anchor_refresh`
/// resets both counters to 0x0001 (§6.14.2.3 / §6.15.2.2).
fn seed_anchor(supi: &str, kausf: &[u8; 32]) {
    ausf_self()
        .read()
        .expect("AUSF context")
        .anchor_refresh(supi, kausf);
}

/// Register the real ausfd server (listening on `port`) as an AUSF NF instance
/// so udmd's AUSF client resolves it (TS 33.501 §6.14.2.1 step 8 — "the AUSF
/// that holds the latest K_AUSF").
async fn register_ausf(port: u16) {
    let mut instance = NfInstance::new(AUSF_INSTANCE_ID, NfType::Ausf);
    instance.ipv4_addresses.push("127.0.0.1".to_string());
    let mut svc = NfService::new("nausf-sorprotection", SbiServiceType::NausfAuth);
    svc.versions = vec!["v1".to_string()];
    svc.port = port;
    instance.add_service(svc);
    global_context().add_nf_instance(instance).await;
}

/// Create a udmd UE context for `supi` whose `ausf_instance_id` points at the
/// authenticating AUSF (exercises the §6.14.2.1 step-8 "prefer the stored AUSF"
/// selection branch of `udm_ausf_send_sor_protect`).
fn seed_udm_ue_with_ausf(supi: &str) {
    let ctx = udm_self();
    let guard = ctx.read().expect("UDM context");
    let mut ue = guard.ue_add(supi).expect("ue_add");
    ue.ausf_instance_id = Some(AUSF_INSTANCE_ID.to_string());
    assert!(guard.ue_update(&ue), "ue_update");
}

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("am-data body is JSON")
}

// ---------------------------------------------------------------------------
// The strict-peer suite. One test function: it owns the process-global UDM +
// AUSF contexts and the shared SBI context, so the six scenarios run
// sequentially (no intra-binary parallelism to race the singletons).
// ---------------------------------------------------------------------------

// The two `CONTEXT_GUARD`s (std `Mutex`) are deliberately held across the
// `.await` points: this is a single-threaded `#[tokio::test]` (current-thread
// runtime), so no other task can run while the guards are held — there is no
// lock held across a genuine yield to a concurrent task, and the guards
// serialize the process-global UDM/AUSF contexts against any future in-process
// consumer per the H1 `test_support` contract. `await_holding_lock` therefore
// does not apply here.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn sor_upu_strict_peer_end_to_end() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _ = env_logger::try_init();

    // Serialize against any other in-process consumer of the two NF contexts
    // (per the H1 test_support contract). Poison-tolerant.
    let _udm_guard = nextgcore_udmd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _ausf_guard = nextgcore_ausfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    nextgcore_udmd::test_support::init_context();
    nextgcore_ausfd::test_support::init_context();

    tokio::time::timeout(Duration::from_secs(60), async {
        // Stand up the REAL ausfd SBI HTTP/2 server + dispatcher.
        let ausf_port = free_port();
        let ausf_server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            ausf_port,
        ))));
        ausf_server
            .start(ausf_sbi_request_handler)
            .await
            .expect("real ausfd SBI server starts");
        register_ausf(ausf_port).await;

        // Provision the operator SoR + UPU sources on the UDM (F-04/F-05
        // config branch). Their PRESENCE is what turns the byte-identical
        // passthrough into an injection — matched-sim configs carry neither.
        {
            let ctx = udm_self();
            let guard = ctx.read().expect("UDM context");
            guard.set_sor_steering(SorSteeringConfig {
                steering_container: golden_container(),
                ack_ind: true,
            });
            guard.set_upu_config(UpuConfig {
                upu_data_list: golden_upu_data_list(),
                ack_ind: true,
            });
        }

        // Distinct SUPIs per scenario so the process-global anchor + UE state
        // never bleeds across cases.
        let supi_sor = "imsi-001010000000701";
        let supi_fresh = "imsi-001010000000702";
        let supi_wrap = "imsi-001010000000703";
        let supi_noanchor = "imsi-001010000000704";
        let supi_upu = "imsi-001010000000705";

        // =================================================================
        // Scenario 1 — SoR happy path: real injection ↔ real producer, MAC
        // reproduced independently from KAUSF + returned counter + wire bytes.
        // =================================================================
        let kausf_sor = test_kausf(0x11);
        seed_anchor(supi_sor, &kausf_sor);
        seed_udm_ue_with_ausf(supi_sor); // exercise step-8 AUSF preference

        let out = maybe_inject_sor_info(supi_sor, RAW_AM_DATA.to_string()).await;
        let am = parse(&out);
        let sor = am.get("sorInfo").expect("Scenario 1: sorInfo injected");

        // TS 29.503 SorInfo shape (note the lowercase-`countersor` spec quirk).
        assert_eq!(sor["ackInd"], serde_json::Value::Bool(true));
        assert!(
            sor["provisioningTime"].as_str().is_some(),
            "SorInfo.provisioningTime is mandatory"
        );
        assert!(sor.get("steeringContainer").is_some());
        let counter = u16::from_str_radix(sor["countersor"].as_str().unwrap(), 16).unwrap();
        assert_eq!(
            counter, 0x0001,
            "first MAC after a fresh KAUSF uses Counter_SoR 0x0001"
        );

        // INDEPENDENT Annex A.17 recompute (header 0x0E, counter, P2 = the
        // hand-derived steering wire bytes). Equality proves the ausfd producer
        // MACed exactly these bytes with the seeded KAUSF.
        let expected = independent_mac(
            &kausf_sor,
            FC_SOR_MAC_IAUSF,
            &[
                &[SOR_HEADER_ACK_PLMN_LIST],
                &counter.to_be_bytes(),
                &GOLDEN_LIST,
            ],
        );
        assert_eq!(
            sor["sorMacIausf"].as_str().unwrap(),
            to_hex(&expected),
            "Scenario 1: sorMacIausf must equal the independent Annex A.17 recompute"
        );
        // Wire-byte sensitivity: a one-byte steering corruption ⇒ different MAC.
        let mut tampered = GOLDEN_LIST;
        tampered[0] ^= 0x01;
        let mac_tampered = independent_mac(
            &kausf_sor,
            FC_SOR_MAC_IAUSF,
            &[
                &[SOR_HEADER_ACK_PLMN_LIST],
                &counter.to_be_bytes(),
                &tampered,
            ],
        );
        assert_ne!(
            expected, mac_tampered,
            "MAC must depend on the steering-list bytes"
        );

        // =================================================================
        // Scenario 2 — SoR ack (F-06): verified SoR-MAC-I_UE ⇒ 204; wrong MAC
        // ⇒ 400 (state unchanged); replayed valid ack ⇒ 400 (single-use).
        // The XMAC was pinned by the Scenario-1 injection with counter 0x0001.
        // =================================================================
        let mac_iue = independent_mac(&kausf_sor, FC_SOR_MAC_IUE, &[&[0x01], &1u16.to_be_bytes()]);

        // Wrong MAC first — one bit flipped — must NOT consume the pin.
        let mut bad = mac_iue;
        bad[0] ^= 0x01;
        let resp = handle_sor_ack(supi_sor, &sor_ack_req("sorMacIue", &to_hex(&bad))).await;
        assert_eq!(
            resp.status, 400,
            "Scenario 2: mismatched SoR-MAC-I_UE ⇒ 400"
        );

        // Correct MAC — verifies constant-time against the pinned XMAC ⇒ 204,
        // and clears the pin (single-use).
        let resp = handle_sor_ack(supi_sor, &sor_ack_req("sorMacIue", &to_hex(&mac_iue))).await;
        assert_eq!(resp.status, 204, "Scenario 2: verified SoR-MAC-I_UE ⇒ 204");

        // Replay the same valid ack — pin already consumed ⇒ unexpected ack.
        let resp = handle_sor_ack(supi_sor, &sor_ack_req("sorMacIue", &to_hex(&mac_iue))).await;
        assert_eq!(
            resp.status, 400,
            "Scenario 2: replayed ack ⇒ 400 (single-use)"
        );

        // =================================================================
        // Scenario 3 — freshness: two GETs ⇒ Counter_SoR 0x0001 then 0x0002,
        // DIFFERENT MACs over identical input, each independently reproducible.
        // =================================================================
        let kausf_fresh = test_kausf(0x22);
        seed_anchor(supi_fresh, &kausf_fresh);

        let first = parse(&maybe_inject_sor_info(supi_fresh, RAW_AM_DATA.to_string()).await);
        let second = parse(&maybe_inject_sor_info(supi_fresh, RAW_AM_DATA.to_string()).await);
        let (m1, c1) = (
            &first["sorInfo"]["sorMacIausf"],
            &first["sorInfo"]["countersor"],
        );
        let (m2, c2) = (
            &second["sorInfo"]["sorMacIausf"],
            &second["sorInfo"]["countersor"],
        );
        assert_eq!(c1, "0001");
        assert_eq!(c2, "0002");
        assert_ne!(
            m1, m2,
            "Scenario 3: identical input, fresh counter ⇒ different MAC"
        );
        let expected_2 = independent_mac(
            &kausf_fresh,
            FC_SOR_MAC_IAUSF,
            &[
                &[SOR_HEADER_ACK_PLMN_LIST],
                &0x0002u16.to_be_bytes(),
                &GOLDEN_LIST,
            ],
        );
        assert_eq!(m2.as_str().unwrap(), to_hex(&expected_2));

        // =================================================================
        // Scenario 4 — counter wrap: force the anchor to 0xFFFF; the real ausfd
        // returns 503 COUNTER_WRAP and the real udmd FAIL-CLOSES — am-data comes
        // back WITHOUT sorInfo (never an unprotected steering list).
        // =================================================================
        let kausf_wrap = test_kausf(0x33);
        seed_anchor(supi_wrap, &kausf_wrap);
        assert!(ausf_self()
            .read()
            .unwrap()
            .anchor_force_counters(supi_wrap, 0xFFFF, 0xFFFF));

        let out = maybe_inject_sor_info(supi_wrap, RAW_AM_DATA.to_string()).await;
        assert!(
            !out.contains("sorInfo"),
            "Scenario 4: counter_wrap ⇒ withhold sorInfo: {out}"
        );
        assert!(
            !out.contains("steeringContainer"),
            "Scenario 4: no unprotected steering list may leak"
        );
        assert_eq!(
            parse(&out)["gpsis"][0],
            "msisdn-777",
            "rest of am-data survives"
        );

        // =================================================================
        // Scenario 5 — no anchor (UE never primary-authenticated through this
        // AUSF): the real ausfd returns 404 CONTEXT_NOT_FOUND (never a MAC over
        // a zero key), the real udmd fail-closes ⇒ no sorInfo.
        // =================================================================
        let out = maybe_inject_sor_info(supi_noanchor, RAW_AM_DATA.to_string()).await;
        assert!(
            !out.contains("sorInfo"),
            "Scenario 5: no anchor ⇒ withhold sorInfo: {out}"
        );
        assert!(!out.contains("steeringContainer"));
        assert_eq!(parse(&out)["gpsis"][0], "msisdn-777");

        // =================================================================
        // Scenario 6 — UPU mirror of 1-2: real injection ↔ real producer,
        // independent Annex A.19 recompute, then the ack verify (A.20).
        // =================================================================
        let kausf_upu = test_kausf(0x44);
        seed_anchor(supi_upu, &kausf_upu);

        let out = maybe_inject_upu_info(supi_upu, RAW_AM_DATA.to_string()).await;
        let am = parse(&out);
        let upu = am.get("upuInfo").expect("Scenario 6: upuInfo injected");
        assert_eq!(upu["upuAckInd"], serde_json::Value::Bool(true));
        assert!(upu.get("upuDataList").is_some());
        // TS 29.503 UpuInfo uses camelCase `counterUpu` (unlike SoR's quirk).
        let counter_upu = u16::from_str_radix(upu["counterUpu"].as_str().unwrap(), 16).unwrap();
        assert_eq!(counter_upu, 0x0001);

        let expected_upu = independent_mac(
            &kausf_upu,
            FC_UPU_MAC_IAUSF,
            &[&GOLDEN_UPU_LIST, &counter_upu.to_be_bytes()],
        );
        assert_eq!(
            upu["upuMacIausf"].as_str().unwrap(),
            to_hex(&expected_upu),
            "Scenario 6: upuMacIausf must equal the independent Annex A.19 recompute"
        );
        // Wire-byte sensitivity for the UPU list too.
        let mut tampered_upu = GOLDEN_UPU_LIST;
        tampered_upu[3] ^= 0x01;
        let mac_upu_tampered = independent_mac(
            &kausf_upu,
            FC_UPU_MAC_IAUSF,
            &[&tampered_upu, &counter_upu.to_be_bytes()],
        );
        assert_ne!(
            expected_upu, mac_upu_tampered,
            "UPU MAC must depend on the UpuData bytes"
        );

        // UPU ack (A.20): wrong ⇒ 400, correct ⇒ 204, replay ⇒ 400.
        let upu_mac_iue =
            independent_mac(&kausf_upu, FC_UPU_MAC_IUE, &[&[0x01], &1u16.to_be_bytes()]);
        let mut bad_upu = upu_mac_iue;
        bad_upu[0] ^= 0x01;
        let resp = handle_upu_ack(supi_upu, &upu_ack_req("upuMacIue", &to_hex(&bad_upu))).await;
        assert_eq!(
            resp.status, 400,
            "Scenario 6: mismatched UPU-MAC-I_UE ⇒ 400"
        );
        let resp = handle_upu_ack(supi_upu, &upu_ack_req("upuMacIue", &to_hex(&upu_mac_iue))).await;
        assert_eq!(resp.status, 204, "Scenario 6: verified UPU-MAC-I_UE ⇒ 204");
        let resp = handle_upu_ack(supi_upu, &upu_ack_req("upuMacIue", &to_hex(&upu_mac_iue))).await;
        assert_eq!(
            resp.status, 400,
            "Scenario 6: replayed UPU ack ⇒ 400 (single-use)"
        );

        let _ = ausf_server.stop().await;
    })
    .await
    .expect("F-07 strict-peer suite completes within the timeout");
}

/// Build a TS 29.503 `AcknowledgeInfo` SoR-ack PUT carrying `mac_field=hex`.
fn sor_ack_req(mac_field: &str, mac_hex: &str) -> SbiRequest {
    ack_req(
        "/nudm-sdm/v2/imsi-001010000000701/am-data/sor-ack",
        mac_field,
        mac_hex,
    )
}

/// Build a TS 29.503 `AcknowledgeInfo` UPU-ack PUT carrying `mac_field=hex`.
fn upu_ack_req(mac_field: &str, mac_hex: &str) -> SbiRequest {
    ack_req(
        "/nudm-sdm/v2/imsi-001010000000705/am-data/upu-ack",
        mac_field,
        mac_hex,
    )
}

fn ack_req(path: &str, mac_field: &str, mac_hex: &str) -> SbiRequest {
    SbiRequest::put(path)
        .with_json_body(&serde_json::json!({
            "provisioningTime": PROVISIONING_TIME,
            mac_field: mac_hex,
        }))
        .expect("serialize AcknowledgeInfo")
}
