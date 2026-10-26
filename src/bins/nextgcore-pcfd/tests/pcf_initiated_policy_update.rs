//! #1261: a change of the UE's policy data at the UDR is pushed to the AMF and
//! the UE, end to end against amfd's REAL Namf router.
//!
//! - AM policy: the PCF re-evaluates the AM policy association and sends
//!   Npcf_AMPolicyControl_UpdateNotify, `POST {notificationUri}/update`, with a
//!   PolicyUpdate that carries only the changed members (TS 29.513 §5.1.2.2,
//!   TS 29.507 §4.2.4.2 and §4.2.3.3). amfd's `am-policy-notify` route answers 204.
//! - UE policy: the PCF re-evaluates the UE policy association and delivers the
//!   changed URSP to the UE in a MANAGE UE POLICY COMMAND over
//!   Namf_Communication_N1N2MessageTransfer (TS 29.513 §5.6.2.2.2 step 7). amfd's
//!   N1N2 handler accepts it. No Npcf_UEPolicyControl_UpdateNotify is sent: the
//!   request triggers did not change (step 5, TS 29.525 §4.2.4.2).
//! - Nothing is sent when nothing changed.
//!
//! One stub peer plays the NRF and the UDR, and relays every `namf-*` request to
//! `nextgcore_amfd::namf_request_handler`, so the AMF side is amfd's real code.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_amfd::context as amf;
use nextgcore_pcfd::pcf_sbi_request_handler;
use nextgcore_pcfd::sbi_path::POLICY_DATA_NOTIFY_PATH;
use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};

const SUPI: &str = "imsi-001010000012610";

/// What the stub's UDR answers, changed by the test between notifications.
struct Udr {
    am_data: Mutex<serde_json::Value>,
    ue_policy_set: Mutex<serde_json::Value>,
}

/// One request the stub relayed to amfd, and amfd's answer.
#[derive(Clone, Debug)]
struct Relayed {
    path: String,
    body: Option<String>,
    status: u16,
}

type Log = Arc<Mutex<Vec<Relayed>>>;

fn ursp(dnn: &str) -> serde_json::Value {
    serde_json::json!({
        "urspRules": [{
            "precedence": 10,
            "trafficDescriptor": { "dnn": dnn },
            "routeSelectionDescriptors": [{
                "precedence": 10, "sscMode": 1, "snssai": {"sst": 1},
                "dnn": dnn, "pduSessionType": "ipv4v6", "preferredAccess": "3gpp"
            }]
        }]
    })
}

fn am_data(rfsp: u64) -> serde_json::Value {
    serde_json::json!({
        "subscribedUeAmbr": { "uplink": "100 Mbps", "downlink": "200 Mbps" },
        "rfspIndex": rfsp,
        "serviceAreaRestriction": {
            "restrictionType": "ALLOWED_AREAS",
            "areas": [{ "tacs": ["000001"] }]
        }
    })
}

async fn start_peer(udr: Arc<Udr>, log: Log) -> (nextgcore_sbi::server::SbiServer, u16) {
    let port_cell = Arc::new(Mutex::new(0u16));
    let port_for_handler = Arc::clone(&port_cell);
    let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let udr = Arc::clone(&udr);
        let log = Arc::clone(&log);
        let port = *port_for_handler.lock().unwrap();
        async move {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            if path == "/nnrf-disc/v1/nf-instances" {
                let nf_type = req
                    .http
                    .params
                    .get("target-nf-type")
                    .cloned()
                    .unwrap_or_default();
                let service = if nf_type == "UDR" {
                    "nudr-dr"
                } else {
                    "namf-comm"
                };
                return Resp::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "nfInstances": [{
                            "nfInstanceId": format!("{nf_type}-1261"),
                            "nfType": nf_type,
                            "ipv4Addresses": ["127.0.0.1"],
                            "nfServices": [{
                                "serviceName": service,
                                "scheme": "http",
                                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
                            }]
                        }]
                    }))
                    .unwrap_or_else(|_| Resp::with_status(500));
            }
            if path.ends_with("/provisioned-data/am-data") {
                let body = udr.am_data.lock().unwrap().clone();
                return Resp::with_status(200)
                    .with_json_body(&body)
                    .unwrap_or_else(|_| Resp::with_status(500));
            }
            if path.ends_with("/ue-policy-set") {
                let body = udr.ue_policy_set.lock().unwrap().clone();
                return Resp::with_status(200)
                    .with_json_body(&body)
                    .unwrap_or_else(|_| Resp::with_status(500));
            }
            if path.starts_with("/namf-") {
                // The JSON root, then each binary part (the N1N2 multipart carries
                // the MANAGE UE POLICY COMMAND as one), so two commands differ here.
                let mut body = req.http.content.clone().unwrap_or_default();
                for part in &req.http.parts {
                    body.push_str(&format!("|{:?}:{:02x?}", part.content_type, &part.data[..]));
                }
                let body = Some(body);
                let resp = nextgcore_amfd::namf_request_handler(req).await;
                log.lock().unwrap().push(Relayed {
                    path,
                    body,
                    status: resp.status,
                });
                return resp;
            }
            Resp::with_status(404)
        }
    })
    .await;
    *port_cell.lock().unwrap() = addr.port();
    (server, addr.port())
}

/// Seed a CM-CONNECTED UE in amfd's process-global context, as
/// `strict_peer_updp.rs` does.
fn seed_amf_ue(supi: &str) {
    amf::amf_context_init(64, 1024, 4096);
    let ctx = amf::amf_self();
    let guard = ctx.read().expect("amf ctx lock");
    let ngap_id = 71_261;
    let ran_ue = guard.ran_ue_add(901_261, ngap_id).expect("ran_ue_add");
    let mut ue = guard.amf_ue_add(ran_ue.id).expect("amf_ue_add");
    ue.supi = Some(supi.to_string());
    ue.security_context_available = true;
    guard.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
    ue.ran_ue_id = ran_ue.id;
    guard.amf_ue_update(&ue);
    guard.amf_ue_publish(&ue, ngap_id as u32, 901_261);
}

fn relayed(log: &Log, pred: impl Fn(&Relayed) -> bool) -> Vec<Relayed> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|r| pred(r))
        .cloned()
        .collect()
}

fn is_am_update(r: &Relayed) -> bool {
    r.path == format!("/namf-callback/v1/{SUPI}/am-policy-notify/update")
}

fn is_n1n2(r: &Relayed) -> bool {
    r.path == format!("/namf-comm/v1/ue-contexts/{SUPI}/n1-n2-messages")
}

/// The distinct N1N2 transfer bodies: a T3501 retransmission repeats a command
/// byte for byte, so only a new command adds one.
fn distinct_n1n2(log: &Log) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in relayed(log, is_n1n2) {
        let b = r.body.unwrap_or_default();
        if !out.contains(&b) {
            out.push(b);
        }
    }
    out
}

/// Wait for `cond` (event-bounded; the ceiling only stops a broken build hanging).
async fn wait_for(cond: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cond()
}

fn post(path: &str, body: serde_json::Value) -> Req {
    Req::post(path).with_json_body(&body).expect("json body")
}

async fn notify_policy_data_change() {
    let resp = pcf_sbi_request_handler(post(
        POLICY_DATA_NOTIFY_PATH,
        serde_json::json!({
            "ueId": SUPI,
            "reportId": format!("/nudr-dr/v2/policy-data/ues/{SUPI}/ue-policy-set"),
        }),
    ))
    .await;
    assert_eq!(resp.status, 204);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guards serialise the process-global PCF context and delivery env
async fn a_policy_data_change_is_pushed_to_the_amf_and_the_ue() {
    let _pcf = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _amf = nextgcore_amfd::test_support::CONTEXT_GUARD.lock().await;
    let _delivery = nextgcore_pcfd::test_support::ue_policy_delivery(true);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("PCF_URSP_RULES");
    nextgcore_pcfd::test_support::init_context();
    seed_amf_ue(SUPI);

    let udr = Arc::new(Udr {
        am_data: Mutex::new(am_data(3)),
        ue_policy_set: Mutex::new(ursp("internet")),
    });
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let (_peer, port) = start_peer(Arc::clone(&udr), Arc::clone(&log)).await;
    nextgcore_pcfd::test_support::point_nrf_at(format!("http://127.0.0.1:{port}")).await;

    // The AMF's associations, as amfd creates them.
    let am = pcf_sbi_request_handler(post(
        "/npcf-am-policy-control/v1/policies",
        serde_json::json!({
            "notificationUri": format!("http://127.0.0.1:{port}/namf-callback/v1/{SUPI}/am-policy-notify"),
            "supi": SUPI,
            "suppFeat": "",
        }),
    ))
    .await;
    assert_eq!(am.status, 201);
    let am: serde_json::Value = serde_json::from_str(am.http.content.as_deref().unwrap()).unwrap();
    assert_eq!(am["rfsp"], 3, "created with the provisioned RFSP");
    let am_id = am["polAssoId"].as_str().unwrap().to_string();

    let ue = pcf_sbi_request_handler(post(
        "/npcf-ue-policy-control/v1/policies",
        serde_json::json!({
            "notificationUri": format!("http://127.0.0.1:{port}/namf-callback/v1/{SUPI}/ue-policy-notify"),
            "supi": SUPI,
            "suppFeat": "",
            "servingPlmn": { "mcc": "001", "mnc": "01" },
        }),
    ))
    .await;
    assert_eq!(ue.status, 201);
    assert!(
        wait_for(|| distinct_n1n2(&log).len() == 1).await,
        "the create delivers the UE policy once: {:?}",
        relayed(&log, |_| true)
    );

    // Nothing changed: nothing is pushed.
    notify_policy_data_change().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        relayed(&log, is_am_update).is_empty(),
        "an unchanged AM policy is not notified"
    );
    assert_eq!(
        distinct_n1n2(&log).len(),
        1,
        "an unchanged URSP is not re-delivered"
    );

    // The operator changes the UE's policy data; the RFSP and the URSP differ now.
    *udr.am_data.lock().unwrap() = am_data(7);
    *udr.ue_policy_set.lock().unwrap() = ursp("ims");
    notify_policy_data_change().await;

    assert!(
        wait_for(|| !relayed(&log, is_am_update).is_empty()).await,
        "Npcf_AMPolicyControl_UpdateNotify reached the AMF"
    );
    let update = &relayed(&log, is_am_update)[0];
    let body: serde_json::Value = serde_json::from_str(update.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "resourceUri": format!("/npcf-am-policy-control/v1/policies/{am_id}"),
            "rfsp": 7,
        }),
        "only the changed member (TS 29.507 §4.2.3.3.1): the SAR and the triggers did not change"
    );
    assert_eq!(
        update.status, 204,
        "amfd's am-policy-notify route acknowledges it"
    );

    assert!(
        wait_for(|| distinct_n1n2(&log).len() == 2).await,
        "the changed URSP is delivered to the UE"
    );
    let transfers = relayed(&log, is_n1n2);
    let second = transfers
        .iter()
        .find(|r| r.body.as_deref() == Some(distinct_n1n2(&log)[1].as_str()))
        .unwrap();
    assert_eq!(
        second.status, 200,
        "amfd's N1N2 handler accepts the command"
    );
    assert!(
        second.body.as_deref().unwrap().contains("UPDP")
            && second.body.as_deref().unwrap().contains("vnd.3gpp.5gnas"),
        "it is a UE policy container carried as a NAS part: {second:?}"
    );
    assert!(
        relayed(&log, |r| r.path.contains("/ue-policy-notify/")).is_empty(),
        "no Npcf_UEPolicyControl_UpdateNotify: the triggers did not change"
    );

    // And again unchanged: nothing more.
    notify_policy_data_change().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(relayed(&log, is_am_update).len(), 1);
    assert_eq!(distinct_n1n2(&log).len(), 2);
}
