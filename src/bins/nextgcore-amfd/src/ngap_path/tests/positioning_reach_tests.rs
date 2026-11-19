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
    // #1588: this page reads the paging strategy.
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
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
    let ul_pdu = nextgcore_ngap::builder::build_uplink_nas_transport(
        &nextgcore_ngap::types::UplinkNasTransport {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            nas_pdu: vec![
                0x7E,
                security_header::PLAIN_NAS_MESSAGE,
                message_type::CONFIGURATION_UPDATE_COMPLETE,
            ],
            user_location_info: super::test_user_location(0x04_88_01, 0x0004_8801),
        },
    )
    .expect("encode an Uplink NAS Transport");
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
    let resp = crate::namf_request_handler(req).await;
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
    let resp = crate::namf_request_handler(req).await;
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
    let resp = crate::namf_request_handler(req).await;
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
    let resp = crate::namf_request_handler(req).await;
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
    let resp = crate::namf_request_handler(req).await;
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
        let resp = crate::namf_request_handler(req).await;
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
        let resp = crate::namf_request_handler(req).await;
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
        let resp = crate::namf_request_handler(req).await;
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
    let resp = crate::namf_request_handler(req).await;
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
        let resp =
            crate::namf_request_handler(positioning_transfer_notifying(supi, Some(&lmf))).await;
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
    let resp = crate::namf_request_handler(positioning_transfer_notifying(supi, Some(&lmf))).await;
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
