//! #1776: a Nudm_SDM change of a CM-CONNECTED UE's subscribed UE-AMBR reaches its
//! NG-RAN node in a UE CONTEXT MODIFICATION REQUEST (TS 23.502 §4.5.1, TS 38.413
//! §8.3.4), and the node's Response and Failure are handled.
//!
//! Both peers: the AMF side drives the real Namf notify handler and the NGAP pump;
//! the gNB side is the capture seam (`sent_ngap`), whose PDUs are decoded with the
//! generated codec as a gNB would, and the gNB's answers are fed back through the
//! NGAP dispatch.

use super::handler_tests::*;
use super::*;
use nextgcore_ngap_gen::generated as g;

/// A registered, CM-CONNECTED UE on [`ASSOC`] holding an SDM subscription (token
/// `sdm-{supi}`) and am-data with a 1 / 2 Mbps UE-AMBR.
fn subscribed_ue(server: &mut NgapServer, ue: u64, ran: u32, supi: &str) {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.supi = Some(supi.to_string());
        s.amf_ue.sdm_notify_token = Some(format!("sdm-{supi}"));
        crate::sdm_notify::adopt_am_data(
            supi,
            &mut s.amf_ue,
            serde_json::json!({"subscribedUeAmbr": {"uplink": "1 Mbps", "downlink": "2 Mbps"}}),
        );
    });
}

/// The UDM's ModificationNotification setting the UE-AMBR to `ul` / `dl`.
async fn notify_ue_ambr(supi: &str, ul: &str, dl: &str) -> u16 {
    let body = serde_json::json!({
        "notifyItems": [{
            "resourceId": format!("/nudm-sdm/v2/{supi}/am-data"),
            "changes": [{"op": "REPLACE", "path": "/subscribedUeAmbr",
                         "newValue": {"uplink": ul, "downlink": dl}}],
        }],
    });
    let req = nextgcore_sbi::SbiRequest::post(format!(
        "/namf-callback/v1/{supi}/sdmsubscription-notify/sdm-{supi}"
    ))
    .with_json_body(&body)
    .expect("json");
    crate::namf_request_handler(req).await.status
}

/// A UE CONTEXT MODIFICATION REQUEST as the gNB decodes it: `(AMF UE NGAP ID, RAN
/// UE NGAP ID, (UE-AMBR DL, UL))`, `None` for any other PDU.
fn decoded_modification_request(pdu: &[u8]) -> Option<(u64, u32, Option<(u64, u64)>)> {
    let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let g::InitiatingMessageValue::Id_UEContextModification(req) = m.value else {
        return None;
    };
    let (mut amf, mut ran, mut ambr) = (None, None, None);
    for ie in req.protocol_i_es.0 {
        use g::UEContextModificationRequestProtocolIEs_EntryValue as Ie;
        match ie.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran = Some(v.0),
            Ie::Id_UEAggregateMaximumBitRate(v) => {
                ambr = Some((
                    v.ue_aggregate_maximum_bit_rate_dl.0,
                    v.ue_aggregate_maximum_bit_rate_ul.0,
                ))
            }
            _ => {}
        }
    }
    Some((amf?, ran?, ambr))
}

/// The UE Context Modification Requests sent for `ue`, decoded, and how many PDUs
/// of any kind were sent for it in all (by AMF UE NGAP ID).
fn modifications_sent(server: &mut NgapServer, ue: u64) -> (Vec<(u32, Option<(u64, u64)>)>, usize) {
    let mut requests = Vec::new();
    let mut for_ue = 0;
    for (assoc, pdu) in take_sent_ngap(server) {
        if crate::ngap_asn1::extract_amf_ue_ngap_id(&pdu) != Some(ue) {
            continue;
        }
        for_ue += 1;
        if let Some((_, ran, ambr)) = decoded_modification_request(&pdu) {
            assert_eq!(assoc, ASSOC, "sent on the UE's association");
            requests.push((ran, ambr));
        }
    }
    (requests, for_ue)
}

fn queued(ue: u64) -> bool {
    crate::context::amf_self()
        .read()
        .expect("ctx")
        .ue_ambr_modification_queued(ue)
}

/// The gNB's answer to the request: a Response, or a Failure with radio-network
/// `cause`.
fn gnb_answer(ue: u64, ran: u32, failure_cause: Option<u8>) -> Vec<u8> {
    let ignore = || g::Criticality(g::Criticality::IGNORE);
    let pdu = match failure_cause {
        None => {
            use g::UEContextModificationResponseProtocolIEs_EntryValue as Ie;
            let entry = |id: u16, value| g::UEContextModificationResponseProtocolIEs_Entry {
                id: g::ProtocolIE_ID(id),
                criticality: ignore(),
                value,
            };
            g::NGAP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                procedure_code: g::ProcedureCode(g::ID_UE_CONTEXT_MODIFICATION),
                criticality: g::Criticality(g::Criticality::REJECT),
                value: g::SuccessfulOutcomeValue::Id_UEContextModification(
                    g::UEContextModificationResponse {
                        protocol_i_es: g::UEContextModificationResponseProtocolIEs(vec![
                            entry(
                                g::ID_AMF_UE_NGAP_ID,
                                Ie::Id_AMF_UE_NGAP_ID(g::AMF_UE_NGAP_ID(ue)),
                            ),
                            entry(
                                g::ID_RAN_UE_NGAP_ID,
                                Ie::Id_RAN_UE_NGAP_ID(g::RAN_UE_NGAP_ID(ran)),
                            ),
                        ]),
                    },
                ),
            })
        }
        Some(cause) => {
            use g::UEContextModificationFailureProtocolIEs_EntryValue as Ie;
            let entry = |id: u16, value| g::UEContextModificationFailureProtocolIEs_Entry {
                id: g::ProtocolIE_ID(id),
                criticality: ignore(),
                value,
            };
            g::NGAP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
                procedure_code: g::ProcedureCode(g::ID_UE_CONTEXT_MODIFICATION),
                criticality: g::Criticality(g::Criticality::REJECT),
                value: g::UnsuccessfulOutcomeValue::Id_UEContextModification(
                    g::UEContextModificationFailure {
                        protocol_i_es: g::UEContextModificationFailureProtocolIEs(vec![
                            entry(
                                g::ID_AMF_UE_NGAP_ID,
                                Ie::Id_AMF_UE_NGAP_ID(g::AMF_UE_NGAP_ID(ue)),
                            ),
                            entry(
                                g::ID_RAN_UE_NGAP_ID,
                                Ie::Id_RAN_UE_NGAP_ID(g::RAN_UE_NGAP_ID(ran)),
                            ),
                            entry(
                                g::ID_CAUSE,
                                Ie::Id_Cause(g::Cause::RadioNetwork(g::CauseRadioNetwork(cause))),
                            ),
                        ]),
                    },
                ),
            })
        }
    };
    nextgcore_ngap_gen::encode(&pdu).expect("encode the gNB's answer")
}

fn held_ue_ambr(server: &NgapServer, ue: u64) -> (u64, u64) {
    let s = server.ue_auth_state.get(ue).expect("UE held");
    (s.amf_ue.ue_ambr.downlink, s.amf_ue.ue_ambr.uplink)
}

/// TS 38.413 §9.2.2.7: the request carries the AMF and RAN UE NGAP IDs (reject) and
/// the UE Aggregate Maximum Bit Rate (ignore), on procedure 40 with criticality
/// reject; a rate past the BitRate root (§9.3.1.4) is not encoded.
///
/// REVERT-VERIFIED: with the builder's DL and UL swapped, the "UE-AMBR" assertion
/// fails.
#[test]
fn the_request_carries_both_ids_and_the_ue_ambr_1776() {
    let pdu = crate::ngap_asn1::build_ue_context_modification_request_asn1(
        (1u64 << 40) - 1,
        u32::MAX,
        (10_000_000, 5_000_000),
    )
    .expect("encodes");
    let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(&pdu).expect("decodes")
    else {
        panic!("an InitiatingMessage");
    };
    assert_eq!(m.procedure_code.0, g::ID_UE_CONTEXT_MODIFICATION);
    assert_eq!(m.criticality.0, g::Criticality::REJECT);
    let g::InitiatingMessageValue::Id_UEContextModification(req) = &m.value else {
        panic!("a UEContextModificationRequest");
    };
    let criticalities: Vec<(u16, u8)> = req
        .protocol_i_es
        .0
        .iter()
        .map(|ie| (ie.id.0, ie.criticality.0))
        .collect();
    assert_eq!(
        criticalities,
        vec![
            (g::ID_AMF_UE_NGAP_ID, g::Criticality::REJECT),
            (g::ID_RAN_UE_NGAP_ID, g::Criticality::REJECT),
            (g::ID_UE_AGGREGATE_MAXIMUM_BIT_RATE, g::Criticality::IGNORE),
        ],
        "IEs and criticalities as §9.2.2.7"
    );
    assert_eq!(
        decoded_modification_request(&pdu),
        Some(((1u64 << 40) - 1, u32::MAX, Some((10_000_000, 5_000_000)))),
        "UE-AMBR"
    );
    assert!(
        crate::ngap_asn1::build_ue_context_modification_request_asn1(
            1,
            1,
            (crate::ngap_asn1::MAX_BIT_RATE + 1, 1)
        )
        .is_none(),
        "a rate past the root"
    );
}

/// #1776 acceptance: a UE-AMBR change for a CM-CONNECTED UE is answered 204, and its
/// gNB receives one UE CONTEXT MODIFICATION REQUEST naming the UE with the new
/// UE-AMBR.
///
/// REVERT-VERIFIED: with the `send_to_association` call in
/// `send_ue_ambr_modification` removed, the "one request" assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_ues_ue_ambr_change_reaches_its_gnb_1776() {
    let _q = crate::test_support::UE_AMBR_MODIFICATION_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (1_776_001u64, 76, "imsi-001010017760001");
    subscribed_ue(&mut server, ue, ran, supi);

    assert_eq!(notify_ue_ambr(supi, "5 Mbps", "10 Mbps").await, 204);
    assert_eq!(held_ue_ambr(&server, ue), (10_000_000, 5_000_000), "held");
    server.process_ue_ambr_modifications().await;
    let (requests, _) = modifications_sent(&mut server, ue);
    assert_eq!(
        requests,
        vec![(ran, Some((10_000_000, 5_000_000)))],
        "one request, with the new UE-AMBR"
    );
    assert!(!queued(ue), "nothing left queued");
    server.forget_ue(ue);
}

/// #1776 (failure-path check 2): changes queued before the drain go out as ONE
/// request with the latest UE-AMBR, and the UDM's retry of a notification already
/// applied sends nothing more.
///
/// REVERT-VERIFIED: with the queue a Vec (one entry per notification, not one per
/// UE), the "one request" count fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_changes_send_one_request_with_the_latest_ue_ambr_1776() {
    let _q = crate::test_support::UE_AMBR_MODIFICATION_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (1_776_002u64, 77, "imsi-001010017760002");
    subscribed_ue(&mut server, ue, ran, supi);

    assert_eq!(notify_ue_ambr(supi, "5 Mbps", "10 Mbps").await, 204);
    assert_eq!(notify_ue_ambr(supi, "7 Mbps", "20 Mbps").await, 204);
    server.process_ue_ambr_modifications().await;
    let (requests, _) = modifications_sent(&mut server, ue);
    assert_eq!(requests.len(), 1, "one request");
    assert_eq!(requests[0].1, Some((20_000_000, 7_000_000)), "the latest");

    assert_eq!(
        notify_ue_ambr(supi, "7 Mbps", "20 Mbps").await,
        204,
        "a retry"
    );
    server.process_ue_ambr_modifications().await;
    assert_eq!(
        modifications_sent(&mut server, ue).1,
        0,
        "a retry changes nothing and sends nothing"
    );
    server.forget_ue(ue);
}

/// #1776 (failure-path check 3): a UE that goes CM-IDLE, or whose context is gone,
/// while its modification is queued is sent nothing, and nothing stays queued; the
/// idle UE keeps the new UE-AMBR for its next Initial Context Setup. A UE
/// deregistered while queued has the entry dropped at once.
///
/// REVERT-VERIFIED: with the CM-IDLE check in `send_ue_ambr_modification` removed,
/// the "idle: nothing sent" assertion fails; with the `ue_ambr_modification_remove_for`
/// call in `stop_paging_on_deregistration` removed, the "deregistered" assertion
/// fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_idle_or_gone_before_the_drain_is_sent_nothing_1776() {
    let _q = crate::test_support::UE_AMBR_MODIFICATION_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (1_776_003u64, 78, "imsi-001010017760003");
    subscribed_ue(&mut server, ue, ran, supi);

    assert_eq!(notify_ue_ambr(supi, "5 Mbps", "10 Mbps").await, 204);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    server.process_ue_ambr_modifications().await;
    assert_eq!(
        modifications_sent(&mut server, ue).1,
        0,
        "idle: nothing sent"
    );
    assert!(!queued(ue), "idle: nothing left queued");
    assert_eq!(held_ue_ambr(&server, ue), (10_000_000, 5_000_000), "kept");

    // Connected again, queued, then deregistered (the context forgotten).
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
    assert_eq!(notify_ue_ambr(supi, "6 Mbps", "12 Mbps").await, 204);
    assert!(queued(ue));
    server.forget_ue(ue);
    assert!(!queued(ue), "deregistered: the entry is dropped");

    // A UE whose context is gone by the drain.
    crate::context::amf_self()
        .read()
        .expect("ctx")
        .ue_ambr_modification_add(ue);
    server.process_ue_ambr_modifications().await;
    assert_eq!(
        modifications_sent(&mut server, ue).1,
        0,
        "gone: nothing sent"
    );
    assert!(!queued(ue), "gone: nothing left queued");
}

/// #1776, TS 38.413 §8.3.4.2 / §8.3.4.3 (the gNB peer): the node's Response and
/// Failure are handled, not answered with an Error Indication as a procedure the AMF
/// does not implement (as before), and neither changes the UE-AMBR the AMF holds:
/// on a Failure it keeps the subscribed one for the next Initial Context Setup
/// (DECISIONS, #1776). The decoder reads the Failure's cause.
///
/// REVERT-VERIFIED: with procedure 40 routed to the `_` arm again, the "no Error
/// Indication" assertion fails for the Response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gnbs_response_and_failure_are_handled_1776() {
    let _q = crate::test_support::UE_AMBR_MODIFICATION_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (1_776_004u64, 79, "imsi-001010017760004");
    subscribed_ue(&mut server, ue, ran, supi);
    assert_eq!(notify_ue_ambr(supi, "5 Mbps", "10 Mbps").await, 204);
    server.process_ue_ambr_modifications().await;
    assert_eq!(modifications_sent(&mut server, ue).0.len(), 1);

    let failure = gnb_answer(ue, ran, Some(g::CauseRadioNetwork::UNSPECIFIED));
    assert!(matches!(
        crate::ngap_asn1::decode_ue_context_modification_outcome_asn1(&failure),
        crate::ngap_asn1::UeContextModificationOutcomeDecode::Decoded {
            amf_ue_ngap_id: Some(id),
            ran_ue_ngap_id: Some(r),
            cause: Some((0, _)),
            error_indication: None,
        } if id == ue && r == ran
    ));
    for (what, pdu) in [
        ("Response", gnb_answer(ue, ran, None)),
        ("Failure", failure),
    ] {
        server.process_ngap_message(ASSOC, &pdu).await.expect(what);
        assert!(
            take_sent_ngap(&mut server).is_empty(),
            "{what}: no Error Indication, nothing sent"
        );
        assert_eq!(
            held_ue_ambr(&server, ue),
            (10_000_000, 5_000_000),
            "{what}: the subscribed UE-AMBR is kept"
        );
    }
    server.forget_ue(ue);
}
