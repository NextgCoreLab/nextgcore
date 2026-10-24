//! #1087: Namf transfers and answers for a UE as the live NGAP path holds it.
//!
//! The UEs here are NGAP-store records only (`UeNasContext`), as a real
//! registration leaves them, with no RAN UE in the context pool. Before #1087
//! such a CM-CONNECTED UE looked unreachable to every Namf reader that gated on
//! `AmfUe.ran_ue_id`. LPP, UE-associated NRPPa and UPDP were answered 504
//! UE_NOT_REACHABLE, which a real-binary LMF run showed (nextgsim #347).

use super::handler_tests::*;
use super::*;
use nextgcore_sbi::message::SbiPart;

/// A registered, CM-CONNECTED UE as the NGAP path records it, resolvable by `supi`.
fn live_ue(server: &mut NgapServer, ue: u64, ran: u32, supi: &str) {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.supi = Some(supi.to_string());
    });
}

/// The same UE, CM-IDLE after its AN release.
fn idle_ue(server: &mut NgapServer, ue: u64, ran: u32, supi: &str) {
    live_ue(server, ue, ran, supi);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
}

/// An LMF's N1N2MessageTransfer with an LPP message and a UE-associated NRPPa PDU.
fn positioning_transfer(supi: &str) -> nextgcore_sbi::SbiRequest {
    let body = serde_json::json!({
        "n1MessageContainer": {
            "n1MessageClass": "LPP",
            "n1MessageContent": { "contentId": "lpp-pdu" }
        },
        "n2InfoContainer": {
            "n2InformationClass": "NRPPa",
            "nrppaInfo": {
                "nfId": "lmf-1087",
                "nrppaPdu": {
                    "ngapIeType": "NRPPA_PDU",
                    "ngapData": { "contentId": "nrppa-pdu" }
                }
            }
        }
    });
    nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
        .with_json_body(&body)
        .expect("json")
        .with_part(SbiPart::with_content(
            "lpp-pdu",
            "application/vnd.3gpp.lpp",
            bytes::Bytes::from_static(&[0x90, 0x10, 0x87]),
        ))
        .with_part(SbiPart::with_content(
            "nrppa-pdu",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::from_static(&[0x00, 0x10, 0x87, 0x00]),
        ))
}

fn cause_of(resp: &nextgcore_sbi::SbiResponse) -> String {
    let body: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    body["cause"].as_str().unwrap_or_default().to_string()
}

/// What the pump sent that concerns `ue`: its DL NAS Transports, and the
/// UE-associated NRPPa transports (procedure code 8) on its association.
fn positioning_sent(server: &mut NgapServer, ue: u64) -> (usize, usize) {
    let mut nas = 0;
    let mut nrppa = 0;
    for (_, pdu) in take_sent_ngap(server) {
        match decode_sent(&pdu) {
            Sent::DownlinkNas { amf_ue_ngap_id, .. } if amf_ue_ngap_id == ue => nas += 1,
            Sent::Other(Some(8)) => {
                if pdu.windows(4).any(|w| w == [0x00, 0x10, 0x87, 0x00]) {
                    nrppa += 1;
                }
            }
            _ => {}
        }
    }
    (nas, nrppa)
}

/// TS 29.518 §5.2.2.3.1, TS 23.273: a CM-CONNECTED UE's positioning transfer is
/// accepted (200 N1_N2_TRANSFER_INITIATED), and the NGAP task delivers both legs:
/// the LPP in a DL NAS Transport, the NRPPa in a UE-associated NRPPa transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_ues_lpp_and_nrppa_are_relayed() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_701u64, 87, "imsi-001010010870001");
    live_ue(&mut server, ue, ran, supi);

    let resp = crate::namf_request_handler(positioning_transfer(supi)).await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    assert_eq!(cause_of(&resp), "N1_N2_TRANSFER_INITIATED");
    server.process_positioning_downlinks().await;
    assert_eq!(positioning_sent(&mut server, ue), (1, 1));
    server.forget_ue(ue);
}

/// The other readers of the UE's CM state agree: Namf_MT EnableUEReachability
/// answers REACHABLE for a CM-CONNECTED UE (TS 29.518 §5.4.2.2), not 504.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_ue_is_reachable_for_namf_mt() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_702u64, 88, "imsi-001010010870002");
    live_ue(&mut server, ue, ran, supi);
    let req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-mt/v1/ue-contexts/{supi}/ue-reachind"))
            .with_json_body(&serde_json::json!({ "reachability": "REACHABLE" }))
            .expect("json");
    let resp = crate::namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    server.forget_ue(ue);
}

/// TS 29.518 §5.2.2.3.1 / TS 23.502 §4.2.3.3: a CM-IDLE UE is not "not
/// reachable". It is paged (202 ATTEMPTING_TO_REACH_UE), and its positioning
/// downlinks wait for the Service Request instead of going to the released
/// connection. Once the UE is connected, they are delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cm_idle_ues_positioning_transfer_pages_it_and_waits() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_703u64, 89, "imsi-001010010870003");
    idle_ue(&mut server, ue, ran, supi);

    let resp = crate::namf_request_handler(positioning_transfer(supi)).await;
    assert_eq!(resp.status, 202, "{}", cause_of(&resp));
    assert_eq!(cause_of(&resp), "ATTEMPTING_TO_REACH_UE");
    let paged = crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_find(ue)
        .is_some();
    assert!(paged, "the UE is paged");

    server.process_positioning_downlinks().await;
    assert_eq!(
        positioning_sent(&mut server, ue),
        (0, 0),
        "nothing goes to the released connection"
    );

    // The Service Request brings the UE back on this connection.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
    crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_remove(ue);
    server.process_positioning_downlinks().await;
    assert_eq!(
        positioning_sent(&mut server, ue),
        (1, 1),
        "delivered once connected"
    );
    server.forget_ue(ue);
}

/// 504 UE_NOT_REACHABLE only for a UE that cannot be paged: CM-IDLE with no
/// registration to page it by.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpageable_idle_ue_is_not_reachable() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_704u64, 90, "imsi-001010010870004");
    idle_ue(&mut server, ue, ran, supi);
    server.ue_auth_state.with_mut(ue, |s| s.registered = false);
    let resp = crate::namf_request_handler(positioning_transfer(supi)).await;
    // An unregistered UE may not be resolvable by SUPI at all (404); either way it
    // is never relayed to.
    assert!(
        resp.status == 504 || resp.status == 404,
        "{} {}",
        resp.status,
        cause_of(&resp)
    );
    server.forget_ue(ue);
}

/// A positioning downlink queued for a UE that went CM-IDLE before the NGAP task
/// sent it, and that is not being paged, is dropped. It is not sent on the
/// released connection's stale association and RAN UE NGAP ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downlink_for_a_ue_that_went_idle_is_not_sent_to_its_old_connection() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_705u64, 91, "imsi-001010010870005");
    live_ue(&mut server, ue, ran, supi);
    let resp = crate::namf_request_handler(positioning_transfer(supi)).await;
    assert_eq!(resp.status, 200);
    // The AN release lands before the pump runs.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    server.process_positioning_downlinks().await;
    assert_eq!(positioning_sent(&mut server, ue), (0, 0));
    assert!(
        server.held_positioning.is_empty(),
        "not paged: dropped, not held"
    );
    server.forget_ue(ue);
}

fn json_of(resp: &nextgcore_sbi::SbiResponse) -> serde_json::Value {
    serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default()
}

/// #1087: the immediate REACHABILITY_REPORT and CONNECTIVITY_STATE_REPORT of a
/// CM-CONNECTED UE say REACHABLE and CONNECTED (TS 29.518 §5.3.2.2.2: delivered
/// in the subscribe response's `reportList`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_ues_immediate_reports_say_reachable_and_connected() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_706u64, 92, "imsi-001010010870006");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let req = nextgcore_sbi::SbiRequest::post("/namf-evts/v1/subscriptions")
        .with_json_body(&serde_json::json!({
            "subscription": {
                "eventList": [
                    { "type": "REACHABILITY_REPORT", "immediateFlag": true },
                    { "type": "CONNECTIVITY_STATE_REPORT", "immediateFlag": true }
                ],
                "eventNotifyUri": "http://127.0.0.1:9/notify/1087",
                "notifyCorrelationId": "corr-1087",
                "nfId": "3fa85f64-5717-4562-b3fc-2c963f661087",
                "supi": supi,
            }
        }))
        .expect("json");
    let resp = crate::namf_request_handler(req).await;
    assert_eq!(resp.status, 201, "{}", json_of(&resp));
    let body = json_of(&resp);
    let reports = body["reportList"].as_array().cloned().unwrap_or_default();
    let of = |t: &str| reports.iter().find(|r| r["type"] == t).cloned();
    assert_eq!(
        of("REACHABILITY_REPORT").expect("reachability report")["reachability"],
        "REACHABLE"
    );
    assert_eq!(
        of("CONNECTIVITY_STATE_REPORT").expect("connectivity report")["cmInfoList"][0]["cmState"],
        "CONNECTED"
    );
    server.forget_ue(ue);
}

/// #1087: Namf_Location ProvideLocationInfo reports `ratType` NR for a UE that is
/// attached now, and Namf_MT ProvideDomainSelectionInfo its `lastActTime`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_ues_location_and_domain_selection_info_say_it_is_attached() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_707u64, 93, "imsi-001010010870007");
    live_ue(&mut server, ue, ran, supi);
    server
        .ue_auth_state
        .with_mut(ue, |s| s.amf_ue.ue_location_timestamp = 1_700_000_000);

    let req = nextgcore_sbi::SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-loc-info"));
    let resp = crate::namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    assert_eq!(json_of(&resp)["ratType"], "NR");

    let req = nextgcore_sbi::SbiRequest::get(format!("/namf-mt/v1/ue-contexts/{supi}"))
        .with_param("info-class", "TADS");
    let resp = crate::namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    assert!(
        json_of(&resp).get("lastActTime").is_some(),
        "{}",
        json_of(&resp)
    );
    server.forget_ue(ue);
}

/// #1087: a pure-N1 transfer of a class the AMF has no relay for is acknowledged
/// for a CM-CONNECTED UE (logged as not forwarded), not refused 504.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unhandled_n1_class_for_a_connected_ue_is_not_refused_unreachable() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_708u64, 94, "imsi-001010010870008");
    live_ue(&mut server, ue, ran, supi);
    let req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&serde_json::json!({
                "n1MessageContainer": {
                    "n1MessageClass": "SMS",
                    "n1MessageContent": { "contentId": "sms" }
                }
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "sms",
                "application/vnd.3gpp.sms",
                bytes::Bytes::from_static(&[0x01]),
            ));
    let resp = crate::namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    server.forget_ue(ue);
}

/// #1089 review: a UE context created over Namf for a UE no gNB has signalled for
/// yet (CreateUEContext publishes it with association 0) has no NG connection. It
/// is neither CM-CONNECTED nor pageable, so a positioning transfer gets 504, and
/// nothing is ever sent "on association 0".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_ue_context_is_not_connected() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, supi) = (7_108_709u64, "imsi-001010010870009");
    let mut amf_ue = AmfUe::default();
    amf_ue.id = ue;
    amf_ue.supi = Some(supi.to_string());
    amf_ue.security_context_available = true;
    // As CreateUEContext leaves it: a pool RAN UE, no NG association.
    amf_ue.ran_ue_id = 1;
    server
        .ue_auth_state
        .insert(ue, UeNasContext::published(amf_ue, 0, 0));

    let resp = crate::namf_request_handler(positioning_transfer(supi)).await;
    assert_eq!(resp.status, 504, "{}", cause_of(&resp));
    server.process_positioning_downlinks().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "nothing is sent for an unbound UE"
    );
    server.forget_ue(ue);
}
