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
    positioning_transfer_notifying(supi, None)
}

/// [`positioning_transfer`], with `failure_uri` as its n1n2FailureTxfNotifURI.
fn positioning_transfer_notifying(
    supi: &str,
    failure_uri: Option<&str>,
) -> nextgcore_sbi::SbiRequest {
    positioning_transfer_tagged(supi, failure_uri, None)
}

/// [`positioning_transfer_notifying`], with `correlation` as its lcsCorrelationId:
/// another transfer from the same LMF.
fn positioning_transfer_tagged(
    supi: &str,
    failure_uri: Option<&str>,
    correlation: Option<&str>,
) -> nextgcore_sbi::SbiRequest {
    let mut body = serde_json::json!({
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
    if let Some(uri) = failure_uri {
        body["n1n2FailureTxfNotifURI"] = serde_json::json!(uri);
    }
    if let Some(c) = correlation {
        body["lcsCorrelationId"] = serde_json::json!(c);
    }
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

    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer(supi)).await;
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
    let resp = crate::namf_server::test_namf_request_handler(req).await;
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
    // #1588: this page reads the paging strategy.
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_108_703u64, 89, "imsi-001010010870003");
    idle_ue(&mut server, ue, ran, supi);

    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer(supi)).await;
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
    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer(supi)).await;
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
    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer(supi)).await;
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
    let resp = crate::namf_server::test_namf_request_handler(req).await;
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
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    assert_eq!(json_of(&resp)["ratType"], "NR");

    let req = nextgcore_sbi::SbiRequest::get(format!("/namf-mt/v1/ue-contexts/{supi}"))
        .with_param("info-class", "TADS");
    let resp = crate::namf_server::test_namf_request_handler(req).await;
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
    let resp = crate::namf_server::test_namf_request_handler(req).await;
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

    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer(supi)).await;
    assert_eq!(resp.status, 504, "{}", cause_of(&resp));
    server.process_positioning_downlinks().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "nothing is sent for an unbound UE"
    );
    server.forget_ue(ue);
}

/// Seconds since the Unix epoch, now.
fn epoch_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// An RFC 3339 DateTime as seconds since the Unix epoch.
fn rfc3339_secs(v: &serde_json::Value) -> u64 {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("a DateTime string, got {v}"));
    crate::namf_server::rfc3339_to_system_time(s)
        .unwrap_or_else(|| panic!("{s} is RFC 3339"))
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// nextgsim#488: an Uplink NAS Transport's User Location Information is stamped with
/// the time the AMF learnt it, and every Namf reader of that stamp now answers from it
/// on the default path, with no test write of `ue_location_timestamp`:
/// - Namf_Location ProvideLocationInfo `location.nrLocation.ueLocationTimestamp`
///   (TS 29.571 §5.4.4.9, "the UTC time when the UeLocation information was acquired")
///   and its `locationAge` (seconds, `ngap_location_age_secs`);
/// - Namf_MT ProvideDomainSelectionInfo `lastActTime`;
/// - an immediate LOCATION_REPORT's `reportList` (TS 29.518, "Last Known Location (if
///   the immediateFlag is set)").
///
/// REVERT-VERIFIED: dropping `amf_ue.stamp_location_now()` from `apply_user_location`
/// fails the first assertion (the stamp stays 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uplink_nas_transports_location_reaches_namf_with_the_time_it_was_acquired() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_488_001u64, 95, "imsi-001010004880001");
    live_ue(&mut server, ue, ran, supi);
    assert_eq!(
        server
            .ue_auth_state
            .get(ue)
            .expect("live")
            .amf_ue
            .ue_location_timestamp,
        0,
        "the precondition: no location has been reported yet"
    );

    let before = epoch_secs_now();
    let ul_pdu = crate::gnb_pdus::uplink_nas_transport(&crate::ngap_types::UplinkNasTransport {
        amf_ue_ngap_id: ue,
        ran_ue_ngap_id: ran,
        nas_pdu: vec![
            0x7E,
            security_header::PLAIN_NAS_MESSAGE,
            message_type::CONFIGURATION_UPDATE_COMPLETE,
        ],
        user_location_info: super::test_user_location(0x04_88_01, 0x0004_8801),
    });
    server
        .handle_uplink_nas_transport(1, &ul_pdu)
        .await
        .expect("handled");
    let after = epoch_secs_now();

    let stamp = server
        .ue_auth_state
        .get(ue)
        .expect("live")
        .amf_ue
        .ue_location_timestamp;
    assert!(
        (before..=after).contains(&stamp),
        "the ULI is stamped when it is stored, in seconds: {before} <= {stamp} <= {after}"
    );

    let req = nextgcore_sbi::SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-loc-info"));
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    let body = json_of(&resp);
    assert_eq!(
        body["location"]["nrLocation"]["ncgi"]["nrCellId"], "000048801",
        "{body}"
    );
    assert_eq!(
        rfc3339_secs(&body["location"]["nrLocation"]["ueLocationTimestamp"]),
        stamp,
        "{body}"
    );
    let age = body["locationAge"].as_u64().expect("locationAge");
    assert!(
        age <= epoch_secs_now() - stamp,
        "the age is in seconds since the stamp, not since the epoch: {age}"
    );

    let req = nextgcore_sbi::SbiRequest::get(format!("/namf-mt/v1/ue-contexts/{supi}"))
        .with_param("info-class", "TADS");
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    assert_eq!(rfc3339_secs(&json_of(&resp)["lastActTime"]), stamp);

    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let req = nextgcore_sbi::SbiRequest::post("/namf-evts/v1/subscriptions".to_string())
        .with_json_body(&serde_json::json!({
            "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT", "immediateFlag": true }],
                "eventNotifyUri": "http://127.0.0.1:9/notify",
                "notifyCorrelationId": "corr-488",
                "nfId": "3fa85f64-5717-4562-b3fc-2c9630004880",
                "supi": supi,
            }
        }))
        .expect("json");
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 201, "{}", json_of(&resp));
    let body = json_of(&resp);
    let report = body["reportList"]
        .as_array()
        .and_then(|r| r.iter().find(|r| r["type"] == "LOCATION_REPORT"))
        .cloned()
        .unwrap_or_else(|| panic!("an immediate LOCATION_REPORT: {body}"));
    assert_eq!(
        rfc3339_secs(&report["location"]["nrLocation"]["ueLocationTimestamp"]),
        stamp,
        "{report}"
    );
    delete_subscription(&body).await;
    server.forget_ue(ue);
}

/// nextgsim#488: a location the AMF never learnt carries no `ueLocationTimestamp`
/// (the IE is optional, TS 29.571 §5.4.4.9) rather than the epoch, and no
/// `lastActTime`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unstamped_location_omits_its_timestamp() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_488_002u64, 96, "imsi-001010004880002");
    live_ue(&mut server, ue, ran, supi);

    let req = nextgcore_sbi::SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-loc-info"));
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 200, "{}", json_of(&resp));
    let body = json_of(&resp);
    assert!(body["location"]["nrLocation"].is_object(), "{body}");
    assert!(
        body["location"]["nrLocation"]
            .get("ueLocationTimestamp")
            .is_none(),
        "{body}"
    );
    assert!(body.get("locationAge").is_none(), "{body}");

    let req = nextgcore_sbi::SbiRequest::get(format!("/namf-mt/v1/ue-contexts/{supi}"))
        .with_param("info-class", "TADS");
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert!(
        json_of(&resp).get("lastActTime").is_none(),
        "{}",
        json_of(&resp)
    );
    server.forget_ue(ue);
}

/// nextgsim#488 review: a stamp that is no plausible time (a corrupt store record,
/// `u64::MAX` or the BSON maximum) is "no timestamp". Every Namf reader still
/// answers 200 and omits the field, rather than panicking in the `SystemTime`
/// arithmetic.
///
/// REVERT-VERIFIED: `UNIX_EPOCH + Duration::from_secs(..)` in place of
/// `location_acquired_at` panics here ("overflow when adding duration").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_location_stamp_is_omitted_and_never_panics() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_488_003u64, 97, "imsi-001010004880003");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    for corrupt in [u64::MAX, i64::MAX as u64, epoch_secs_now() + 10 * 86_400] {
        server
            .ue_auth_state
            .with_mut(ue, |s| s.amf_ue.ue_location_timestamp = corrupt);

        let req = nextgcore_sbi::SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-loc-info"));
        let resp = crate::namf_server::test_namf_request_handler(req).await;
        assert_eq!(resp.status, 200, "{corrupt}: {}", json_of(&resp));
        let body = json_of(&resp);
        assert!(
            body["location"]["nrLocation"]
                .get("ueLocationTimestamp")
                .is_none()
                && body.get("locationAge").is_none(),
            "{corrupt}: {body}"
        );

        let req = nextgcore_sbi::SbiRequest::get(format!("/namf-mt/v1/ue-contexts/{supi}"))
            .with_param("info-class", "TADS");
        let resp = crate::namf_server::test_namf_request_handler(req).await;
        assert_eq!(resp.status, 200, "{corrupt}");
        assert!(json_of(&resp).get("lastActTime").is_none(), "{corrupt}");

        let req = nextgcore_sbi::SbiRequest::post("/namf-evts/v1/subscriptions".to_string())
            .with_json_body(&serde_json::json!({
                "subscription": {
                    "eventList": [{ "type": "LOCATION_REPORT", "immediateFlag": true }],
                    "eventNotifyUri": "http://127.0.0.1:9/notify",
                    "notifyCorrelationId": "corr-488-corrupt",
                    "nfId": "3fa85f64-5717-4562-b3fc-2c9630004883",
                    "supi": supi,
                }
            }))
            .expect("json");
        let resp = crate::namf_server::test_namf_request_handler(req).await;
        assert_eq!(resp.status, 201, "{corrupt}: {}", json_of(&resp));
        let body = json_of(&resp);
        let report = body["reportList"]
            .as_array()
            .and_then(|r| r.iter().find(|r| r["type"] == "LOCATION_REPORT"))
            .cloned()
            .unwrap_or_else(|| panic!("an immediate LOCATION_REPORT: {body}"));
        assert!(
            report["location"]["nrLocation"]
                .get("ueLocationTimestamp")
                .is_none(),
            "{corrupt}: {report}"
        );
        delete_subscription(&body).await;
    }
    server.forget_ue(ue);
}

/// DELETE the subscription a subscribe answer created.
async fn delete_subscription(answer: &serde_json::Value) {
    let id = answer["subscriptionId"].as_str().expect("subscriptionId");
    let req = nextgcore_sbi::SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{id}"));
    let resp = crate::namf_server::test_namf_request_handler(req).await;
    assert_eq!(resp.status, 204, "{}", json_of(&resp));
}

/// Pump the paging map until `ue`'s page (`max_retransmit` 0) is abandoned.
async fn run_page_out(server: &mut NgapServer, ue: u64) {
    for _ in 0..3 {
        server.process_paging_with(Duration::ZERO).await;
        if crate::context::amf_self()
            .read()
            .expect("ctx")
            .paging_find(ue)
            .is_none()
        {
            return;
        }
    }
    panic!("the page for UE {ue} was not abandoned");
}

/// The next failure notification at `rx`: (cause, n1n2MsgDataUri).
async fn next_failure(rx: &mut mpsc::Receiver<String>) -> (String, String) {
    let body = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("a failure notification")
        .expect("channel open");
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    (
        v["cause"].as_str().unwrap_or_default().to_string(),
        v["n1n2MsgDataUri"].as_str().unwrap_or_default().to_string(),
    )
}

/// **#1837 (b)**, TS 29.518 §5.2.2.3.1 / TS 23.502 §4.2.3.3 step 4c: an LMF's
/// positioning transfer for a CM-IDLE UE that a LOCATION_REPORT subscription is
/// already paging (a location-only page, #1760) joins that page, and when the UE
/// never answers the LMF gets its N1N2MsgTxfrFailureNotification. Before #1837 the
/// join kept no failure URI, and the location-only page carries none of its own,
/// so the LMF was never told. A retry of the same transfer is told once.
///
/// REVERT-VERIFIED: with `paging_join_or_add_transfer` joining without recording
/// the URI, no notification arrives ("a failure notification").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_positioning_transfer_joining_a_location_page_is_told_it_failed_1837() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink, port, mut rx) = notify_sink().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (18_370_001u64, 92, "imsi-001010018370001");
    idle_ue(&mut server, ue, ran, supi);
    let amf_ue = server.ue_auth_state.get(ue).expect("UE").amf_ue;
    let mut location_page = crate::namf_handler::idle_ue_paging_context(
        &amf_ue,
        None,
        None,
        crate::namf_handler::PagedN2::Setup,
        None,
        None,
    );
    location_page.max_retransmit = 0;
    assert!(!crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_join_or_add_location(location_page, "sub-1837-b"));

    let lmf = format!("http://127.0.0.1:{port}/lmf-fail-1837");
    let mut locations = Vec::new();
    for _ in 0..2 {
        let resp = crate::namf_server::test_namf_request_handler(positioning_transfer_notifying(
            supi,
            Some(&lmf),
        ))
        .await;
        assert_eq!(resp.status, 202, "{}", cause_of(&resp));
        assert_eq!(cause_of(&resp), "ATTEMPTING_TO_REACH_UE");
        locations.push(
            resp.http
                .get_header("location")
                .expect("Location")
                .to_string(),
        );
    }
    assert_eq!(locations[0], locations[1], "a retry is the same transfer");
    let page = crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_find(ue)
        .expect("paged");
    assert!(
        page.location_only,
        "the location page is joined, not replaced"
    );

    run_page_out(&mut server, ue).await;
    let (cause, uri) = next_failure(&mut rx).await;
    assert_eq!(cause, "UE_NOT_RESPONDING");
    assert_eq!(
        uri, locations[0],
        "the notification names the transfer's Location"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "the retried transfer is told once"
    );
    server.process_positioning_downlinks().await;
    assert_eq!(
        positioning_sent(&mut server, ue),
        (0, 0),
        "the held downlinks are dropped with the page"
    );
    server.forget_ue(ue);
    sink.stop().await.expect("sink stop");
}

/// **#1837 (a)+(b)**, TS 29.518 §5.2.2.3.1: a page that holds an SMF's transfer and
/// that an LMF's positioning transfer joined notifies each of them, at its own URI
/// and naming its own resource, when the UE never answers. The LMF's join leaves
/// the SMF's N2 and URI as they were. Before #1837 the LMF was not told, and a
/// positioning page started meanwhile replaced the SMF's.
///
/// REVERT-VERIFIED: with `paging_ended` notifying only `failure_notify_uri`, the
/// LMF is not told ("the LMF is told").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_page_notifies_every_transfer_it_holds_at_its_own_uri_1837() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (smf_sink, smf_port, mut smf_rx) = notify_sink().await;
    let (lmf_sink, lmf_port, mut lmf_rx) = notify_sink().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (18_370_002u64, 93, "imsi-001010018370002");
    idle_ue(&mut server, ue, ran, supi);
    let amf_ue = server.ue_auth_state.get(ue).expect("UE").amf_ue;
    let smf_data_uri = format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/5");
    let mut sm_page = crate::namf_handler::idle_ue_paging_context(
        &amf_ue,
        None,
        Some(vec![0x00, 0x18, 0x37]),
        crate::namf_handler::PagedN2::Setup,
        Some(5),
        Some(&format!("http://127.0.0.1:{smf_port}/smf-fail-1837")),
    );
    sm_page.n1n2_msg_data_uri = smf_data_uri.clone();
    sm_page.max_retransmit = 0;
    assert!(crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_add(sm_page));

    let lmf = format!("http://127.0.0.1:{lmf_port}/lmf-fail-1837");
    let resp = crate::namf_server::test_namf_request_handler(positioning_transfer_notifying(
        supi,
        Some(&lmf),
    ))
    .await;
    assert_eq!(resp.status, 202, "{}", cause_of(&resp));
    let lmf_location = resp
        .http
        .get_header("location")
        .expect("Location")
        .to_string();
    let page = crate::context::amf_self()
        .read()
        .expect("ctx")
        .paging_find(ue)
        .expect("paged");
    assert_eq!(
        page.pending_n2,
        Some(vec![0x00, 0x18, 0x37]),
        "the SMF's N2 is kept"
    );
    assert_eq!(
        page.failure_notify_uri,
        Some(format!("http://127.0.0.1:{smf_port}/smf-fail-1837"))
    );

    run_page_out(&mut server, ue).await;
    assert_eq!(
        next_failure(&mut smf_rx).await,
        ("UE_NOT_RESPONDING".to_string(), smf_data_uri),
        "the SMF is told"
    );
    let lmf_got = tokio::time::timeout(Duration::from_secs(3), lmf_rx.recv())
        .await
        .ok()
        .flatten();
    let lmf_got = lmf_got.expect("the LMF is told");
    let v: serde_json::Value = serde_json::from_str(&lmf_got).expect("JSON");
    assert_eq!(v["cause"], "UE_NOT_RESPONDING");
    assert_eq!(v["n1n2MsgDataUri"], lmf_location.as_str());
    server.forget_ue(ue);
    smf_sink.stop().await.expect("sink stop");
    lmf_sink.stop().await.expect("sink stop");
}

/// An SMF's PDU_RES_SETUP_REQ N1N2MessageTransfer for `psi`, notifying `failure_uri`.
fn sm_setup_transfer(supi: &str, psi: u8, failure_uri: &str) -> nextgcore_sbi::SbiRequest {
    nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
        .with_json_body(&serde_json::json!({
            "pduSessionId": psi,
            "n1n2FailureTxfNotifURI": failure_uri,
            "n2InfoContainer": {
                "n2InformationClass": "SM",
                "smInfo": {
                    "pduSessionId": psi,
                    "n2InfoContent": {
                        "ngapIeType": "PDU_RES_SETUP_REQ",
                        "ngapData": { "contentId": "ngap-sm" },
                    },
                },
            },
        }))
        .expect("json")
        .with_part(SbiPart::with_content(
            "ngap-sm",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::from_static(&[0x00, 0x18, 0x58]),
        ))
}

/// **#1858 (1)**, TS 23.502 §4.2.3.3 step 3b (`23502-k20.txt:7177-7183`): a page an
/// LMF's positioning transfer started is not a page for a request of the same or a
/// higher priority than an SMF's downlink data, so the SMF's N1N2MessageTransfer is
/// not refused 409 HIGHER_PRIORITY_REQUEST_ONGOING: it is answered 202
/// ATTEMPTING_TO_REACH_UE and takes the page over. Before #1858 it got 409.
/// - Answered: the page then holds the SMF's N2, and the LMF's held LPP and NRPPa
///   still go out once the UE is connected.
/// - Unanswered: both the SMF and the LMF that started the page are told, each at
///   its own URI.
///
/// REVERT-VERIFIED: with `PagingContext::holds_transfer` ignoring
/// `positioning_only`, the SMF gets 409 ("not refused for a positioning page");
/// with the started page keeping the LMF's URI as its own rather than as a joined
/// transfer, the takeover drops it ("the LMF that started the page is told").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_smf_transfer_takes_over_a_positioning_page_1858() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (smf_sink, smf_port, mut smf_rx) = notify_sink().await;
    let (lmf_sink, lmf_port, mut lmf_rx) = notify_sink().await;
    let mut server = capturing_ngap_server().await;
    let smf = format!("http://127.0.0.1:{smf_port}/smf-fail-1858");
    let lmf = format!("http://127.0.0.1:{lmf_port}/lmf-fail-1858");
    let page_of = |ue: u64| {
        crate::context::amf_self()
            .read()
            .expect("ctx")
            .paging_find(ue)
    };

    for (answered, ue, ran, supi) in [
        (true, 18_580_001u64, 94u32, "imsi-001010018580001"),
        (false, 18_580_002, 95, "imsi-001010018580002"),
    ] {
        idle_ue(&mut server, ue, ran, supi);
        {
            let ctx = crate::context::amf_self();
            let guard = ctx.read().expect("ctx");
            let mut sess = guard.sess_add(ue, 5).expect("session");
            sess.sm_context_ref = Some(format!("smctx-1858-{ue}"));
            sess.s_nssai.sst = 1;
            guard.sess_update(&sess);
        }
        let resp =
            crate::namf_request_handler(positioning_transfer_notifying(supi, Some(&lmf))).await;
        assert_eq!(resp.status, 202, "{}", cause_of(&resp));
        let lmf_location = resp
            .http
            .get_header("location")
            .expect("Location")
            .to_string();
        let page = page_of(ue).expect("the LMF's transfer pages the UE");
        assert!(page.positioning_only);

        let resp = crate::namf_request_handler(sm_setup_transfer(supi, 5, &smf)).await;
        assert_eq!(
            resp.status, 202,
            "not refused for a positioning page: {:?}",
            resp.http.content
        );
        assert_eq!(cause_of(&resp), "ATTEMPTING_TO_REACH_UE");
        let mut page = page_of(ue).expect("still paged");
        assert!(
            !page.positioning_only,
            "the page now holds the SMF's transfer"
        );
        assert_eq!(page.pdu_session_id, Some(5));
        assert_eq!(page.pending_n2.as_deref(), Some(&[0x00, 0x18, 0x58][..]));
        assert!(
            crate::namf_request_handler(sm_setup_transfer(supi, 5, &smf))
                .await
                .status
                == 409,
            "a second SM transfer is refused: the page holds one now"
        );

        if answered {
            server.process_positioning_downlinks().await;
            assert_eq!(
                positioning_sent(&mut server, ue),
                (0, 0),
                "held while paged"
            );
            // The UE answers: the page is consumed and the UE is connected.
            crate::context::amf_self()
                .read()
                .expect("ctx")
                .paging_remove(ue);
            server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
            server.process_positioning_downlinks().await;
            assert_eq!(
                positioning_sent(&mut server, ue),
                (1, 1),
                "the LMF's held downlinks go out once the UE is connected"
            );
        } else {
            page.max_retransmit = 0;
            {
                let ctx = crate::context::amf_self();
                let guard = ctx.read().expect("ctx");
                // The same page, on its last attempt.
                guard.paging_remove(ue);
                assert!(guard.paging_add(page));
            }
            run_page_out(&mut server, ue).await;
            let (cause, _) = next_failure(&mut smf_rx).await;
            assert_eq!(cause, "UE_NOT_RESPONDING", "the SMF is told");
            let got = tokio::time::timeout(Duration::from_secs(3), lmf_rx.recv())
                .await
                .ok()
                .flatten()
                .expect("the LMF that started the page is told");
            let v: serde_json::Value = serde_json::from_str(&got).expect("JSON");
            assert_eq!(v["cause"], "UE_NOT_RESPONDING");
            assert_eq!(v["n1n2MsgDataUri"], lmf_location.as_str());
        }
        server.forget_ue(ue);
    }
    smf_sink.stop().await.expect("sink stop");
    lmf_sink.stop().await.expect("sink stop");
}

/// **#1858 (2)**, TS 29.518 §5.2.2.3.1: two LMF positioning transfers that share
/// one n1n2FailureTxfNotifURI are two transfers. Each is answered with its own
/// Location, and when the page fails each is told, naming its own resource. A
/// retry of one of them is still told once. Before #1858 both had one resource,
/// the join keyed on the URI, and they collapsed into a single notification.
///
/// REVERT-VERIFIED: with `join_transfer` keyed by the callback URI again, the
/// second transfer is not recorded ("each transfer is told"); with
/// `positioning_transfer_id` ignoring the request (one id for every transfer), the
/// two get one Location ("two transfers, two resources").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lmf_transfers_sharing_one_callback_uri_are_each_told_1858() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink, port, mut rx) = notify_sink().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (18_580_011u64, 96, "imsi-001010018580011");
    idle_ue(&mut server, ue, ran, supi);
    let lmf = format!("http://127.0.0.1:{port}/lmf-fail-1858-shared");

    let mut locations = Vec::new();
    for corr in ["corr-a", "corr-b", "corr-b"] {
        let resp =
            crate::namf_request_handler(positioning_transfer_tagged(supi, Some(&lmf), Some(corr)))
                .await;
        assert_eq!(resp.status, 202, "{}", cause_of(&resp));
        locations.push(
            resp.http
                .get_header("location")
                .expect("Location")
                .to_string(),
        );
    }
    assert_ne!(locations[0], locations[1], "two transfers, two resources");
    assert_eq!(locations[1], locations[2], "a retry is the same transfer");
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().expect("ctx");
        let mut page = guard.paging_remove(ue).expect("paged");
        // The same page, on its last attempt.
        page.max_retransmit = 0;
        assert!(guard.paging_add(page));
    }

    run_page_out(&mut server, ue).await;
    let mut told = Vec::new();
    for _ in 0..2 {
        let got = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .ok()
            .flatten()
            .expect("each transfer is told");
        let v: serde_json::Value = serde_json::from_str(&got).expect("JSON");
        told.push(v["n1n2MsgDataUri"].as_str().unwrap_or_default().to_string());
    }
    told.sort();
    let mut want = vec![locations[0].clone(), locations[1].clone()];
    want.sort();
    assert_eq!(told, want, "each names its own resource");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "the retried transfer is told once"
    );
    server.forget_ue(ue);
    sink.stop().await.expect("sink stop");
}

/// #2256: the verified NF instance IDs of two LMFs serving one UE at once.
const LMF_A_2256: &str = "6f1d0a52-2256-4a00-8000-00000000000a";
const LMF_B_2256: &str = "6f1d0a52-2256-4b00-8000-00000000000b";

/// An LMF's N1N2MessageSubscribe for the UE's uplink LPP, as LMF `lmf`, with
/// its notify callback on `port`.
fn lpp_subscription_as(supi: &str, lmf: &str, port: u16) -> nextgcore_sbi::SbiRequest {
    let mut req = nextgcore_sbi::SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions"
    ))
    .with_json_body(&serde_json::json!({
        "n1MessageClass": "LPP",
        "n1NotifyCallbackUri": format!("http://127.0.0.1:{port}/nlmf-loc/v1/n1-notify"),
    }))
    .expect("json");
    req.oauth2_subject = Some(lmf.to_string());
    req
}

/// An LMF's LPP-only N1N2MessageTransfer as LMF `lmf`, for LCS correlation
/// `correlation`.
fn lpp_transfer_as(supi: &str, lmf: &str, correlation: &str) -> nextgcore_sbi::SbiRequest {
    lpp_transfer_with(supi, Some(lmf), None, None, correlation)
}

/// An LPP-only N1N2MessageTransfer for LCS correlation `correlation`, from a
/// caller verified as `verified` (if any), declaring `nf_id` and
/// `service_instance` in its n1MessageContainer (if any).
fn lpp_transfer_with(
    supi: &str,
    verified: Option<&str>,
    nf_id: Option<&str>,
    service_instance: Option<&str>,
    correlation: &str,
) -> nextgcore_sbi::SbiRequest {
    let mut body = serde_json::json!({
        "n1MessageContainer": {
            "n1MessageClass": "LPP",
            "n1MessageContent": { "contentId": "lpp-pdu" }
        },
        "lcsCorrelationId": correlation,
    });
    if let Some(id) = nf_id {
        body["n1MessageContainer"]["nfId"] = serde_json::json!(id);
    }
    if let Some(sid) = service_instance {
        body["n1MessageContainer"]["serviceInstanceId"] = serde_json::json!(sid);
    }
    let mut req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "lpp-pdu",
                "application/vnd.3gpp.lpp",
                bytes::Bytes::from_static(&[0x92, 0x22, 0x56]),
            ));
    req.oauth2_subject = verified.map(str::to_string);
    req
}

/// A protected UL NAS TRANSPORT (TS 24.501 §8.2.10) with an LPP container
/// `lpp`, and `routing` in Additional information (IEI 0x24) when given.
fn ul_lpp(lpp: &[u8], routing: Option<&[u8]>, count: u8) -> Vec<u8> {
    let mut inner = vec![0x7E, 0x00, 0x67, 0x03];
    inner.extend_from_slice(&(lpp.len() as u16).to_be_bytes());
    inner.extend_from_slice(lpp);
    if let Some(r) = routing {
        inner.push(0x24);
        inner.push(r.len() as u8);
        inner.extend_from_slice(r);
    }
    ue_protect(&inner, count)
}

/// The next N1MessageNotify a sink received: its JSON root and its N1 part.
async fn next_notify(
    rx: &mut mpsc::Receiver<(String, String, Vec<nextgcore_sbi::message::SbiPart>)>,
) -> (serde_json::Value, Vec<u8>) {
    let (_uri, json, parts) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("an N1MessageNotify arrives")
        .expect("sink open");
    let n1 = parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(crate::namf_server::N1_MESSAGE_NOTIFY_CONTENT_ID))
        .map(|p| p.data.to_vec())
        .unwrap_or_default();
    (serde_json::from_str(&json).expect("json root"), n1)
}

/// #2256, TS 24.501 §5.4.5.3.2 case c and §5.4.5.2.5 case c. Two LMFs run a
/// location session each for one UE. Each LPP downlink carries its LMF's LCS
/// correlation in Additional information, and the UE's answer, naming it
/// again, reaches that LMF, tagged with that correlation, whichever LMF spoke
/// last. An answer with no Additional information keeps the single-session
/// fallback: the most recent LPP subscription and correlation.
///
/// Revert-verified: with the uplink routed as before #2256 (the most recent
/// subscription, the last correlation), LMF A's answer reaches LMF B and the
/// first wait on A's sink times out, as it does with IEI 0x24 left unparsed;
/// with the downlink built without Additional information, the downlink
/// assertion fails; with the notification tagged with the last correlation
/// rather than the one the UE named, A's `lcsCorrelationId` assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lmfs_sessions_for_one_ue_each_get_their_own_uplink() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_601u64, 96, "imsi-001010022560001");
    live_ue(&mut server, ue, ran, supi);
    // The sinks are plain-HTTP peers, which only the dev SBI profile calls.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink_a, port_a, mut rx_a) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;

    for (lmf, port) in [(LMF_A_2256, port_a), (LMF_B_2256, port_b)] {
        let resp =
            crate::namf_server::test_namf_request_handler(lpp_subscription_as(supi, lmf, port))
                .await;
        assert_eq!(resp.status, 201, "{}", json_of(&resp));
    }
    // B's transfer comes last, so B is what the last-writer fallback names.
    for (lmf, corr) in [
        (LMF_A_2256, "corr-2256-a"),
        (LMF_B_2256, "corr-2256-b-longer"),
    ] {
        let resp =
            crate::namf_server::test_namf_request_handler(lpp_transfer_as(supi, lmf, corr)).await;
        assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    }

    // Each downlink carries its own LMF's correlation in Additional information.
    server.process_positioning_downlinks().await;
    let downlinks: Vec<Vec<u8>> = take_sent_ngap(&mut server)
        .into_iter()
        .filter_map(|(_, pdu)| match decode_sent(&pdu) {
            Sent::DownlinkNas {
                amf_ue_ngap_id,
                nas_pdu,
            } if amf_ue_ngap_id == ue => Some(nas_pdu),
            _ => None,
        })
        .collect();
    assert_eq!(downlinks.len(), 2, "one LPP downlink per transfer");
    for (protected, corr) in downlinks
        .iter()
        .zip([&b"corr-2256-a"[..], &b"corr-2256-b-longer"[..]])
    {
        // NEA0: the plain DL NAS TRANSPORT follows the 7-octet security header.
        let plain = &protected[7..];
        let mut want = vec![0x7E, 0x00, 0x68, 0x03, 0x00, 0x03, 0x92, 0x22, 0x56];
        want.extend_from_slice(&[0x24, corr.len() as u8]);
        want.extend_from_slice(corr);
        assert_eq!(
            plain,
            want.as_slice(),
            "LPP downlink with Additional information"
        );
    }

    // The UE answers A's session, then B's, each naming its correlation.
    let answers = [
        (&b"corr-2256-a"[..], [0xA1u8, 0x01], &mut rx_a, "A"),
        (&b"corr-2256-b-longer"[..], [0xB2u8, 0x02], &mut rx_b, "B"),
    ];
    for (count, (corr, lpp, rx, lmf)) in (0u8..).zip(answers) {
        let ul = ul_lpp(&lpp, Some(corr), count);
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
            .await
            .expect("handled");
        let (json, n1) = next_notify(rx).await;
        assert_eq!(n1, lpp, "LMF {lmf} gets its own session's answer, verbatim");
        assert_eq!(
            json["lcsCorrelationId"].as_str().map(str::as_bytes),
            Some(corr),
            "LMF {lmf}: {json}"
        );
        assert_eq!(json["n1MessageContainer"]["n1MessageClass"], "LPP");
        assert_eq!(json["supi"], supi);
    }

    // No Additional information: the single-session fallback, the most recent
    // LPP subscription (B's) with the most recent correlation (B's).
    let ul = ul_lpp(&[0xC3, 0x03], None, 2);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
        .await
        .expect("handled");
    let (json, n1) = next_notify(&mut rx_b).await;
    assert_eq!(n1, [0xC3, 0x03]);
    assert_eq!(json["lcsCorrelationId"], "corr-2256-b-longer", "{json}");

    // Each uplink made exactly one notification, so nothing else is in flight.
    assert!(rx_a.try_recv().is_err(), "LMF A got only its own answer");
    assert!(rx_b.try_recv().is_err(), "LMF B got only its own answers");
    sink_a.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// An LMF's N1N2MessageSubscribe for the UE's uplink NRPPa, as LMF `lmf`, with
/// its notify callback on `port`.
fn nrppa_subscription_as(supi: &str, lmf: &str, port: u16) -> nextgcore_sbi::SbiRequest {
    let mut req = nextgcore_sbi::SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions"
    ))
    .with_json_body(&serde_json::json!({
        "n2InformationClass": "NRPPa",
        "n2NotifyCallbackUri": format!("http://127.0.0.1:{port}/nlmf-loc/v1/n2-notify"),
    }))
    .expect("json");
    req.oauth2_subject = Some(lmf.to_string());
    req
}

/// An LMF's NRPPa-only N1N2MessageTransfer as LMF `lmf`, declaring `nf_id` as
/// its nrppaInfo.nfId, for LCS correlation `correlation`.
fn nrppa_transfer_as(
    supi: &str,
    lmf: &str,
    nf_id: &str,
    correlation: &str,
) -> nextgcore_sbi::SbiRequest {
    let mut req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&serde_json::json!({
                "n2InfoContainer": {
                    "n2InformationClass": "NRPPa",
                    "nrppaInfo": {
                        "nfId": nf_id,
                        "nrppaPdu": {
                            "ngapIeType": "NRPPA_PDU",
                            "ngapData": { "contentId": "nrppa-pdu" }
                        }
                    }
                },
                "lcsCorrelationId": correlation,
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "nrppa-pdu",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(&[0x00, 0x22, 0x56, 0x00]),
            ));
    req.oauth2_subject = Some(lmf.to_string());
    req
}

/// #2256, TS 38.413 §8.15.3 / §9.3.3.13 and TS 29.518 §5.2.2.3.3: two LMFs run
/// an NRPPa session each for one UE. Each UE-associated NRPPa downlink's Routing
/// ID names its LMF by verified identity, even when that LMF declares another
/// LMF's nfId. The gNB's answer, echoing the Routing ID, reaches that LMF,
/// tagged with that LMF's correlation and nfId, whichever LMF spoke last. An
/// empty Routing ID (an LMF with no identity) reaches neither. (A Routing ID naming an
/// LMF with no subscription is never handed to another LMF: see
/// `an_lmf_without_a_subscription_gets_its_uplink_at_its_nrf_default`.)
///
/// Revert-verified: with the uplink routed as before (the most recent NRPPa
/// subscription), A's answer reaches B and the wait on A's sink times out; with
/// the Routing ID seeded from the declared nfId, A's downlink names B and its
/// assertion fails; with the notification tagged with the UE's last correlation,
/// A's `lcsCorrelationId` assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lmfs_nrppa_sessions_for_one_ue_each_get_their_own_uplink() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_602u64, 97, "imsi-001010022560002");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink_a, port_a, mut rx_a) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;

    for (lmf, port) in [(LMF_A_2256, port_a), (LMF_B_2256, port_b)] {
        let resp =
            crate::namf_server::test_namf_request_handler(nrppa_subscription_as(supi, lmf, port))
                .await;
        assert_eq!(resp.status, 201, "{}", json_of(&resp));
    }
    // A declares B's nfId; B's transfer comes last, so B is the last writer.
    for (lmf, nf_id, corr) in [
        (LMF_A_2256, LMF_B_2256, "corr-nrppa-a"),
        (LMF_B_2256, LMF_B_2256, "corr-nrppa-b"),
    ] {
        let resp = crate::namf_server::test_namf_request_handler(nrppa_transfer_as(
            supi, lmf, nf_id, corr,
        ))
        .await;
        assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    }

    // Each downlink's Routing ID names the LMF that sent it.
    server.process_positioning_downlinks().await;
    let downlinks: Vec<Vec<u8>> = take_sent_ngap(&mut server)
        .into_iter()
        .filter_map(|(_, pdu)| matches!(decode_sent(&pdu), Sent::Other(Some(8))).then_some(pdu))
        .collect();
    assert_eq!(downlinks.len(), 2, "one NRPPa downlink per transfer");
    let names = |pdu: &[u8], lmf: &str| pdu.windows(lmf.len()).any(|w| w == lmf.as_bytes());
    assert!(
        names(&downlinks[0], LMF_A_2256) && !names(&downlinks[0], LMF_B_2256),
        "A's Routing ID is A's verified identity, not the nfId it declared"
    );
    assert!(names(&downlinks[1], LMF_B_2256));

    // The gNB answers A's request, then B's, each echoing its Routing ID.
    let answers = [
        (LMF_A_2256, [0xA1u8, 0x01], &mut rx_a, "corr-nrppa-a"),
        (LMF_B_2256, [0xB2u8, 0x02], &mut rx_b, "corr-nrppa-b"),
    ];
    for (lmf, nrppa, rx, corr) in answers {
        let ul =
            crate::gnb_pdus::uplink_ue_associated_nrppa_transport(ue, ran, lmf.as_bytes(), &nrppa);
        server
            .process_ngap_message(ASSOC, &ul)
            .await
            .expect("handled");
        let (_uri, json, parts) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("an N2InfoNotify arrives")
            .expect("sink open");
        let json: serde_json::Value = serde_json::from_str(&json).expect("json root");
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].data.as_ref(),
            nrppa,
            "LMF {lmf} gets its own answer"
        );
        assert_eq!(json["lcsCorrelationId"], corr, "LMF {lmf}: {json}");
        assert_eq!(json["n2InfoContainer"]["nrppaInfo"]["nfId"], lmf);
        assert_eq!(json["n2InfoContainer"]["n2InformationClass"], "NRPPa");
    }

    // An empty Routing ID is our downlink's for an LMF that gave no identity:
    // it goes to no subscription another LMF owns, so here to none.
    let dropped = || UL_NRPPA_DROPPED_NO_CONSUMER.load(std::sync::atomic::Ordering::Relaxed);
    let before = dropped();
    let ul = crate::gnb_pdus::uplink_ue_associated_nrppa_transport(ue, ran, b"", &[0xC3, 0x03]);
    server
        .process_ngap_message(ASSOC, &ul)
        .await
        .expect("handled");
    assert!(dropped() > before, "dropped, not handed to B");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(rx_a.try_recv().is_err(), "LMF A got only its own answer");
    assert!(rx_b.try_recv().is_err(), "LMF B got only its own answers");
    sink_a.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// #2256: a third LMF, with no subscription of its own, and a fourth, unknown
/// to the NRF.
const LMF_C_2256: &str = "6f1d0a52-2256-4c00-8000-00000000000c";
const LMF_D_2256: &str = "6f1d0a52-2256-4d00-8000-00000000000d";

/// #2256, TS 29.518 §5.2.2.3.5.3 and §5.2.2.3.6.3 step 1: an LMF that never
/// subscribed gets the UE's LPP answer and the gNB's NRPPa answer at the default
/// notification subscriptions in its NRF profile, with `"implicit"` as the
/// subscription id (Tables 6.1.6.2.14-1, 6.1.6.2.16-1) and its own correlation;
/// the other LMF's subscription is not used. For an LMF with no default, the
/// UE's LPP comes back with 5GMM #90 and the NRPPa is dropped and counted.
///
/// The default is the service instance's the transfer named, when it names
/// one (§5.2.2.3.5.3 step 1), else the NF's; and an LMF the NRF does not know
/// is not asked about again on the next uplink.
///
/// Revert-verified: with the default lookup answering nothing, the first wait
/// on the default sink times out; with the queued #90 not sent by the pump, the
/// #90 wait times out; with the subscription id not "implicit", that assertion
/// fails; with the service instance ignored, the URI is /default-n1; with no
/// negative cache, the NRF is asked about D twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lmf_without_a_subscription_gets_its_uplink_at_its_nrf_default() {
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let _cache = crate::sbi_path::nf_cache_test_lock().lock().await;
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_603u64, 98, "imsi-001010022560003");
    live_ue(&mut server, ue, ran, supi);
    let (sink_c, port_c, mut rx_c) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;

    // A stand-in NRF that knows LMF C, with both default subscriptions, only.
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let nrf_port = addr.port();
    let nrf = SbiServer::on_listener(
        SbiServerConfig::new(format!("127.0.0.1:{nrf_port}").parse().expect("addr")),
        listener,
    );
    let asked_for: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let asked_sink = std::sync::Arc::clone(&asked_for);
    crate::sbi_path::forget_lmfs_unknown_to_nrf_for_test();
    nrf.start(move |req: nextgcore_sbi::SbiRequest| {
        let asked_sink = std::sync::Arc::clone(&asked_sink);
        async move {
            let asked = req.http.get_param("target-nf-instance-id").cloned();
            asked_sink
                .lock()
                .expect("asked")
                .push(asked.clone().unwrap_or_default());
            let instances = if asked.as_deref() == Some(LMF_C_2256) {
                serde_json::json!([{
                    "nfInstanceId": LMF_C_2256,
                    "nfType": "LMF",
                    "nfStatus": "REGISTERED",
                    "defaultNotificationSubscriptions": [
                        { "notificationType": "N1_MESSAGES", "n1MessageClass": "SM",
                          "callbackUri": format!("http://127.0.0.1:{port_c}/wrong-class") },
                        { "notificationType": "N1_MESSAGES", "n1MessageClass": "LPP",
                          "callbackUri": format!("http://127.0.0.1:{port_c}/default-n1") },
                        { "notificationType": "N2_INFORMATION", "n2InformationClass": "NRPPa",
                          "callbackUri": format!("http://127.0.0.1:{port_c}/default-n2") },
                    ],
                    "nfServices": [{
                        "serviceInstanceId": "nlmf-loc-c1",
                        "serviceName": "nlmf-loc",
                        "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.0.0" }],
                        "scheme": "http",
                        "nfServiceStatus": "REGISTERED",
                        "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port_c }],
                        "defaultNotificationSubscriptions": [
                            { "notificationType": "N1_MESSAGES", "n1MessageClass": "LPP",
                              "callbackUri": format!("http://127.0.0.1:{port_c}/c1-n1") },
                        ],
                    }, {
                        "serviceInstanceId": "nlmf-loc-c2",
                        "serviceName": "nlmf-loc",
                        "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.0.0" }],
                        "scheme": "http",
                        "nfServiceStatus": "REGISTERED",
                        "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port_c }],
                        "defaultNotificationSubscriptions": [
                            { "notificationType": "N1_MESSAGES", "n1MessageClass": "LPP",
                              "callbackUri": format!("http://127.0.0.1:{port_c}/c2-n1") },
                        ],
                    }],
                }])
            } else {
                serde_json::json!([])
            };
            nextgcore_sbi::SbiResponse::with_status(200)
                .with_json_body(
                    &serde_json::json!({ "validityPeriod": 60, "nfInstances": instances }),
                )
                .expect("json")
        }
    })
    .await
    .expect("stand-in NRF start");
    crate::sbi_path::set_lmf_instance_discovery_nrf_for_test(Some(format!(
        "http://127.0.0.1:{nrf_port}"
    )));

    // Only LMF B subscribes; C and D only transfer, C last.
    let resp = crate::namf_server::test_namf_request_handler(lpp_subscription_as(
        supi, LMF_B_2256, port_b,
    ))
    .await;
    assert_eq!(resp.status, 201, "{}", json_of(&resp));
    let resp = crate::namf_server::test_namf_request_handler(nrppa_subscription_as(
        supi, LMF_B_2256, port_b,
    ))
    .await;
    assert_eq!(resp.status, 201, "{}", json_of(&resp));
    // C names its service instance nlmf-loc-c2 (TS 29.518 §6.1.6.2.17).
    for (lmf, corr, sid) in [
        (LMF_D_2256, "corr-d", None),
        (LMF_C_2256, "corr-c", Some("nlmf-loc-c2")),
    ] {
        let resp = crate::namf_server::test_namf_request_handler(lpp_transfer_with(
            supi,
            Some(lmf),
            None,
            sid,
            corr,
        ))
        .await;
        assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    }
    server.process_positioning_downlinks().await;
    let _ = take_sent_ngap(&mut server);

    // C's LPP session: the UE's answer goes to the default N1 subscription of
    // the service instance C named, not its NF's or its other instance's.
    let ul = ul_lpp(&[0xC1, 0x01], Some(b"corr-c"), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
        .await
        .expect("handled");
    let (uri, json, parts) = tokio::time::timeout(Duration::from_secs(10), rx_c.recv())
        .await
        .expect("an N1MessageNotify at C's default")
        .expect("sink open");
    let json: serde_json::Value = serde_json::from_str(&json).expect("json root");
    assert_eq!(uri, "/c2-n1", "the named service instance's default first");
    assert_eq!(json["n1NotifySubscriptionId"], "implicit", "{json}");
    assert_eq!(json["lcsCorrelationId"], "corr-c");
    assert!(parts.iter().any(|p| p.data.as_ref() == [0xC1, 0x01]));

    // C's NRPPa: the gNB's answer, Routing ID C, goes to C's NF-level default N2
    // one (its service instance has none), with the correlation C last used.
    let ul = crate::gnb_pdus::uplink_ue_associated_nrppa_transport(
        ue,
        ran,
        LMF_C_2256.as_bytes(),
        &[0xC2, 0x02],
    );
    server
        .process_ngap_message(ASSOC, &ul)
        .await
        .expect("handled");
    let (uri, json, parts) = tokio::time::timeout(Duration::from_secs(10), rx_c.recv())
        .await
        .expect("an N2InfoNotify at C's default")
        .expect("sink open");
    let json: serde_json::Value = serde_json::from_str(&json).expect("json root");
    assert_eq!(uri, "/default-n2");
    assert_eq!(json["n2NotifySubscriptionId"], "implicit", "{json}");
    assert_eq!(json["n2InfoContainer"]["nrppaInfo"]["nfId"], LMF_C_2256);
    assert_eq!(json["lcsCorrelationId"], "corr-c");
    assert_eq!(parts[0].data.as_ref(), [0xC2, 0x02]);

    // D has no default: its NRPPa answer is dropped and counted ...
    let dropped = || UL_NRPPA_DROPPED_NO_CONSUMER.load(std::sync::atomic::Ordering::Relaxed);
    let before = dropped();
    let ul = crate::gnb_pdus::uplink_ue_associated_nrppa_transport(
        ue,
        ran,
        LMF_D_2256.as_bytes(),
        &[0xD2],
    );
    server
        .process_ngap_message(ASSOC, &ul)
        .await
        .expect("handled");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while dropped() == before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "D's NRPPa is counted"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // ... again, without the NRF being asked again (the negative cache) ...
    let before = dropped();
    let ul = crate::gnb_pdus::uplink_ue_associated_nrppa_transport(
        ue,
        ran,
        LMF_D_2256.as_bytes(),
        &[0xD3],
    );
    server
        .process_ngap_message(ASSOC, &ul)
        .await
        .expect("handled");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while dropped() == before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "D's NRPPa is counted"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let asked_d = asked_for
        .lock()
        .expect("asked")
        .iter()
        .filter(|id| *id == LMF_D_2256)
        .count();
    assert_eq!(
        asked_d, 1,
        "the NRF is asked once for an LMF it does not know"
    );

    // ... and the UE's LPP answer to D comes back with 5GMM #90.
    let ul = ul_lpp(&[0xD1, 0x01], Some(b"corr-d"), 1);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
        .await
        .expect("handled");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let echoed = loop {
        server.process_positioning_downlinks().await;
        let nas = take_sent_ngap(&mut server)
            .into_iter()
            .find_map(|(_, pdu)| match decode_sent(&pdu) {
                Sent::DownlinkNas {
                    amf_ue_ngap_id,
                    nas_pdu,
                } if amf_ue_ngap_id == ue => Some(nas_pdu),
                _ => None,
            });
        if let Some(nas) = nas {
            break nas;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a #90 DL NAS Transport"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // NEA0: the plain DL NAS TRANSPORT follows the 7-octet security header.
    let plain = &echoed[7..];
    assert_eq!(&plain[..3], [0x7E, 0x00, 0x68]);
    assert!(
        plain.windows(2).any(|w| w == [0x58, 90]),
        "5GMM cause #90: {plain:02x?}"
    );
    assert!(
        plain.windows(2).any(|w| w == [0xD1, 0x01]),
        "the payload echoed"
    );

    assert!(
        rx_b.try_recv().is_err(),
        "LMF B's subscriptions are not used"
    );
    assert!(rx_c.try_recv().is_err());
    crate::sbi_path::set_lmf_instance_discovery_nrf_for_test(None);
    let sbi_ctx = nextgcore_sbi::context::global_context();
    sbi_ctx.remove_nf_instance(LMF_C_2256).await;
    sbi_ctx.remove_nf_instance(LMF_D_2256).await;
    nrf.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    sink_c.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// An LMF's SLPP N1N2MessageTransfer as LMF `lmf`, for LCS correlation
/// `correlation` (#557).
fn slpp_transfer_as(supi: &str, lmf: &str, correlation: &str) -> nextgcore_sbi::SbiRequest {
    let mut req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&serde_json::json!({
                "n1MessageContainer": {
                    "n1MessageClass": "SLPP",
                    "n1MessageContent": { "contentId": "slpp-pdu" }
                },
                "lcsCorrelationId": correlation,
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "slpp-pdu",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x44, 0x22, 0x56]),
            ));
    req.oauth2_subject = Some(lmf.to_string());
    req
}

/// #2256 on #557, TS 24.501 §5.4.5.2.5 case c1: the UE's uplink SLPP is routed
/// by its Additional information exactly as LPP is. Two LMFs, each with only
/// an LPP subscription (which SLPP falls back to), run an SLPP session each;
/// each answer reaches the LMF whose correlation it names, still as "SLPP".
///
/// Revert-verified: with the SLPP arm passing no Additional information, A's
/// answer reaches B (the most recent subscription) and A's wait times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lmfs_slpp_sessions_for_one_ue_each_get_their_own_uplink() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_604u64, 99, "imsi-001010022560004");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink_a, port_a, mut rx_a) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;
    for (lmf, port) in [(LMF_A_2256, port_a), (LMF_B_2256, port_b)] {
        let resp =
            crate::namf_server::test_namf_request_handler(lpp_subscription_as(supi, lmf, port))
                .await;
        assert_eq!(resp.status, 201, "{}", json_of(&resp));
    }
    for (lmf, corr) in [(LMF_A_2256, "slpp-corr-a"), (LMF_B_2256, "slpp-corr-b")] {
        let resp =
            crate::namf_server::test_namf_request_handler(slpp_transfer_as(supi, lmf, corr)).await;
        assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    }
    server.process_positioning_downlinks().await;
    let _ = take_sent_ngap(&mut server);

    let answers = [
        (&b"slpp-corr-a"[..], [0xA5u8, 0x05], &mut rx_a, "A"),
        (&b"slpp-corr-b"[..], [0xB6u8, 0x06], &mut rx_b, "B"),
    ];
    for (count, (corr, slpp, rx, lmf)) in (0u8..).zip(answers) {
        // UL NAS TRANSPORT, payload container type 12 (SLPP), with Additional
        // information.
        let mut inner = vec![0x7E, 0x00, 0x67, 0x0C];
        inner.extend_from_slice(&(slpp.len() as u16).to_be_bytes());
        inner.extend_from_slice(&slpp);
        inner.extend_from_slice(&[0x24, corr.len() as u8]);
        inner.extend_from_slice(corr);
        let ul = ue_protect(&inner, count);
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
            .await
            .expect("handled");
        let (json, n1) = next_notify(rx).await;
        assert_eq!(n1, slpp, "LMF {lmf} gets its own session's answer");
        assert_eq!(
            json["lcsCorrelationId"].as_str().map(str::as_bytes),
            Some(corr),
            "LMF {lmf}: {json}"
        );
        assert_eq!(json["n1MessageContainer"]["n1MessageClass"], "SLPP");
    }
    assert!(rx_a.try_recv().is_err());
    assert!(rx_b.try_recv().is_err());
    sink_a.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// #2256, R47 MAJOR 1 on #2261: an LMF cannot take over another LMF's location
/// session by using its LCS correlation first. A second LMF's transfer naming a
/// correlation that is already another LMF's is refused with 403 and sends no
/// downlink, so the UE is never asked a question whose answer would go
/// elsewhere. A verified identity does take over a correlation that was bound
/// only by a declared nfId, which anyone could have sent.
///
/// Revert-verified: with the refusal removed (the binding refused, the transfer
/// still accepted), A's transfer gets 200 and two downlinks go out; with a
/// declared binding outranking a verified one, B's verified transfer is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_correlation_another_lmf_holds_is_refused_not_hijacked() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_605u64, 100, "imsi-001010022560005");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink_a, port_a, mut rx_a) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;
    for (lmf, port) in [(LMF_A_2256, port_a), (LMF_B_2256, port_b)] {
        let resp =
            crate::namf_server::test_namf_request_handler(lpp_subscription_as(supi, lmf, port))
                .await;
        assert_eq!(resp.status, 201, "{}", json_of(&resp));
    }
    let lpp_downlinks = |server: &mut NgapServer| {
        take_sent_ngap(server)
            .into_iter()
            .filter(|(_, pdu)| {
                matches!(decode_sent(pdu), Sent::DownlinkNas { amf_ue_ngap_id, .. } if amf_ue_ngap_id == ue)
            })
            .count()
    };

    // B uses the correlation first; A's transfer naming it is refused.
    let resp = crate::namf_server::test_namf_request_handler(lpp_transfer_as(
        supi,
        LMF_B_2256,
        "corr-victim",
    ))
    .await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    let resp = crate::namf_server::test_namf_request_handler(lpp_transfer_as(
        supi,
        LMF_A_2256,
        "corr-victim",
    ))
    .await;
    assert_eq!(resp.status, 403, "{}", cause_of(&resp));
    assert_eq!(cause_of(&resp), "UNSPECIFIED");
    server.process_positioning_downlinks().await;
    assert_eq!(lpp_downlinks(&mut server), 1, "only B's downlink goes out");

    // A declaration binds a correlation, but a verified LMF outranks it: a
    // caller declaring A's nfId claims corr-declared, verified B takes it over,
    // and the UE's answer naming it reaches B.
    // (Not the test handler, which would make the caller a verified consumer.)
    let resp = crate::namf_request_handler(lpp_transfer_with(
        supi,
        None,
        Some(LMF_A_2256),
        None,
        "corr-declared",
    ))
    .await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    let resp = crate::namf_server::test_namf_request_handler(lpp_transfer_as(
        supi,
        LMF_B_2256,
        "corr-declared",
    ))
    .await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    // ... and a declaration never takes back a verified binding.
    // (Not the test handler, which would make the caller a verified consumer.)
    let resp = crate::namf_request_handler(lpp_transfer_with(
        supi,
        None,
        Some(LMF_A_2256),
        None,
        "corr-declared",
    ))
    .await;
    assert_eq!(resp.status, 403, "{}", cause_of(&resp));
    server.process_positioning_downlinks().await;
    let _ = take_sent_ngap(&mut server);

    let ul = ul_lpp(&[0xBD, 0x01], Some(b"corr-declared"), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
        .await
        .expect("handled");
    let (json, n1) = next_notify(&mut rx_b).await;
    assert_eq!(n1, [0xBD, 0x01]);
    assert_eq!(json["lcsCorrelationId"], "corr-declared");
    assert!(rx_a.try_recv().is_err(), "A gets nothing of B's sessions");
    sink_a.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// #2256, R47 MAJOR 2 on #2261, TS 24.501 §5.4.5.2.5 case c) 2): another LMF's
/// fresh correlations never push out an LMF's binding (eviction is per LMF), and
/// Additional information naming a correlation the AMF does not hold aborts the
/// uplink: it reaches no LMF and the UE gets no #90, rather than going to the
/// most recent subscription.
///
/// Revert-verified: with a per-UE least-recently-used eviction, A's answer after
/// B's flood is aborted (A's wait times out); with an unknown correlation sent
/// to the fallback, B receives the `corr-never` answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_lmfs_correlations_never_evict_a_session_and_unknown_ones_abort() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_606u64, 101, "imsi-001010022560006");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (sink_a, port_a, mut rx_a) = super::start_lmf_callback_sink().await;
    let (sink_b, port_b, mut rx_b) = super::start_lmf_callback_sink().await;
    for (lmf, port) in [(LMF_A_2256, port_a), (LMF_B_2256, port_b)] {
        let resp =
            crate::namf_server::test_namf_request_handler(lpp_subscription_as(supi, lmf, port))
                .await;
        assert_eq!(resp.status, 201, "{}", json_of(&resp));
    }
    let resp =
        crate::namf_server::test_namf_request_handler(lpp_transfer_as(supi, LMF_A_2256, "corr-a"))
            .await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    for n in 0..=crate::context::MAX_LCS_UPLINK_ROUTES_PER_LMF {
        let resp = crate::namf_server::test_namf_request_handler(lpp_transfer_as(
            supi,
            LMF_B_2256,
            &format!("corr-b{n}"),
        ))
        .await;
        assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    }
    server.process_positioning_downlinks().await;
    let _ = take_sent_ngap(&mut server);

    // A's session survives B's flood.
    let ul = ul_lpp(&[0xA7, 0x07], Some(b"corr-a"), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
        .await
        .expect("handled");
    let (json, n1) = next_notify(&mut rx_a).await;
    assert_eq!(n1, [0xA7, 0x07]);
    assert_eq!(json["lcsCorrelationId"], "corr-a");

    // Correlations the AMF does not hold (B's evicted oldest, and one it never
    // sent): aborted, to no LMF and with no #90 to the UE.
    for (count, corr) in [(1u8, &b"corr-b0"[..]), (2, &b"corr-never"[..])] {
        let ul = ul_lpp(&[0xEE, count], Some(corr), count);
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &ul))
            .await
            .expect("handled");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    server.process_positioning_downlinks().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "aborted: no #90 to the UE"
    );
    assert!(rx_a.try_recv().is_err(), "aborted: not to A");
    assert!(
        rx_b.try_recv().is_err(),
        "aborted: not to B, the most recent"
    );
    sink_a.stop().await.expect("stop");
    sink_b.stop().await.expect("stop");
    server.forget_ue(ue);
}

/// #2256 follow-up: under a profile that admits unverified callers, a caller
/// declaring an nfId cannot take over a correlation bound with no identity, so
/// it cannot capture that session's answers. (lmfd names its nfId in its LPP
/// container, TS 29.518 Table 6.1.6.2.17-1, so its own correlations are never
/// anonymous.)
///
/// Revert-verified: with "a declared nfId fills an anonymous binding" restored,
/// the declared transfer gets 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_nfid_cannot_take_over_an_anonymous_correlation() {
    let _q = crate::test_support::POSITIONING_DL_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_225_607u64, 102, "imsi-001010022560007");
    live_ue(&mut server, ue, ran, supi);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    // (Not the test handler, which would make each caller a verified consumer.)
    let resp =
        crate::namf_request_handler(lpp_transfer_with(supi, None, None, None, "corr-anon")).await;
    assert_eq!(resp.status, 200, "{}", cause_of(&resp));
    let resp = crate::namf_request_handler(lpp_transfer_with(
        supi,
        None,
        Some(LMF_B_2256),
        None,
        "corr-anon",
    ))
    .await;
    assert_eq!(resp.status, 403, "{}", cause_of(&resp));
    assert_eq!(cause_of(&resp), "UNSPECIFIED");
    let bound = crate::context::amf_self()
        .read()
        .ok()
        .and_then(|g| g.lcs_uplink_route_find(supi, "corr-anon"));
    assert_eq!(bound.and_then(|r| r.lmf_id), None, "still nobody's");
    server.process_positioning_downlinks().await;
    let _ = take_sent_ngap(&mut server);
    server.forget_ue(ue);
}
