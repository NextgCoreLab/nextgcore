//! #922 part 2: the N11 calls an NGAP handler makes run off the NGAP task.
//!
//! Each test points one UE's session at a blackholed SMF (192.0.2.1, TEST-NET-1:
//! a connection attempt gets no answer at all, so the SBI client waits out its
//! connect timeout). It then checks two things:
//! - the handler returns at once, and another UE is served meanwhile;
//! - what the procedure sends after the SMF's answer still waits for that answer
//!   (the 3GPP order).
//!
//! Before #922 part 2 each of these calls was awaited on the NGAP task, so every
//! gNB's N2 stalled for the connect timeout.

use super::handler_tests::*;
use super::*;

/// TEST-NET-1 (RFC 5737): nothing answers there.
const BLACKHOLE: (&str, u16) = ("192.0.2.1", 7777);

/// What a handler may take at most when it does not wait for the SMF.
const AT_ONCE: Duration = Duration::from_millis(500);

/// Give `ue` an SM context for `psi` held at the blackholed SMF.
fn hold_blackholed(server: &mut NgapServer, ue: u64, psi: u8, sm_ref: &str) {
    record_amf_session(ue, psi, sm_ref, SLICE.0, SLICE.1);
    server.sm_context_refs.insert((ue, psi), sm_ref.to_string());
    server
        .sm_context_smfs
        .insert((ue, psi), (BLACKHOLE.0.to_string(), BLACKHOLE.1));
}

/// Apply off-task outcomes, collecting what is sent, until `done` holds for the
/// collected PDUs (up to 3 s). Returns them.
async fn apply_until(
    server: &mut NgapServer,
    mut done: impl FnMut(&[(u64, Sent)]) -> bool,
) -> Vec<(u64, Sent)> {
    let mut sent = Vec::new();
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        sent.extend(
            take_sent_ngap(server)
                .into_iter()
                .map(|(a, p)| (a, decode_sent(&p))),
        );
        if done(&sent) {
            return sent;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not done after 3 s; sent: {sent:?}");
}

/// Wait until the stand-in SMF has seen a request whose URI ends with `suffix`.
async fn until_called(calls: &Arc<std::sync::Mutex<Vec<SmfCall>>>, suffix: &str) -> SmfCall {
    for _ in 0..300 {
        if let Some(c) = calls
            .lock()
            .expect("calls")
            .iter()
            .find(|(u, _)| u.ends_with(suffix))
        {
            return c.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the SMF never saw {suffix}");
}

fn concerns(sent: &[(u64, Sent)], ue: u64) -> Vec<&Sent> {
    sent.iter()
        .map(|(_, s)| s)
        .filter(|s| match s {
            Sent::SetupRequest { amf_ue_ngap_id, .. }
            | Sent::ModifyRequest { amf_ue_ngap_id, .. }
            | Sent::ReleaseCommand { amf_ue_ngap_id, .. }
            | Sent::DownlinkNas { amf_ue_ngap_id, .. } => *amf_ue_ngap_id == ue,
            _ => false,
        })
        .collect()
}

/// Make every SMF join due now.
fn joins_due(server: &mut NgapServer) {
    for j in server.smf_joins.values_mut() {
        j.deadline = Instant::now();
    }
}

/// TS 23.502 §4.3.3.2: a UE-requested PDU Session Modification (0xC9) whose SMF is
/// blackholed does not hold the NGAP task. Another UE's modification is answered
/// meanwhile. The first UE's Modification Command waits for its SMF's answer
/// (step 3b, then step 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modification_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_101u64, 121u32), (7_922_102u64, 122u32));
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    hold_blackholed(&mut server, dead.0, 5, "mod-922-dead");
    hold_session(&mut server, live.0, 5, "mod-922-live", port);
    let request = [0x2E, 0x05, 0x07, 0xC9];

    let started = Instant::now();
    for (ue, ran) in [dead, live] {
        server
            .handle_5gsm_message(ASSOC, ue, ran, &request, None)
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    until_called(&calls, "/sm-contexts/mod-922-live/modify").await;
    assert!(
        matches!(concerns(&sent, live.0)[..], [Sent::DownlinkNas { .. }]),
        "the answered UE gets its Modification Command: {sent:?}"
    );
    assert!(
        concerns(&sent, dead.0).is_empty(),
        "nothing goes to the UE before its SMF answers: {sent:?}"
    );
    assert!(server.sbi_offload.key_busy((dead.0, 5)));
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// #1546, TS 24.501 §6.4.2.4.1: a UE-requested PDU Session Modification (0xC9)
/// whose SMF update fails is answered PDU SESSION MODIFICATION REJECT (§8.3.8,
/// message type 0xCA, Table 9.7.2) with 5GSM cause #26, echoing the PSI and PTI.
/// Before, it went out as 0xCC (PDU SESSION MODIFICATION COMPLETE), a UE-to-network
/// message the UE answers with 5GSM STATUS #97 (§7.4).
///
/// REVERT-VERIFIED: with the message type back at 0xCC, the reject is not found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_modification_is_answered_with_a_modification_reject_1546() {
    let down = nextgcore_sbi::test_support::down_port();
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (15_460_101u64, 146u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "mod-1546", down.port());
    let request = [0x2E, 0x05, 0x07, 0xC9];

    server
        .handle_5gsm_message(ASSOC, ue, ran, &request, None)
        .await
        .expect("handled");
    let sent = apply_until(&mut server, |s| !concerns(s, ue).is_empty()).await;
    let [Sent::DownlinkNas { nas_pdu, .. }] = concerns(&sent, ue)[..] else {
        panic!("one DL NAS TRANSPORT to the UE: {sent:?}");
    };
    let reject = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
    assert!(
        nas_pdu.windows(reject.len()).any(|w| w == reject),
        "the DL NAS Transport carries PDU SESSION MODIFICATION REJECT #26: {nas_pdu:02x?}"
    );
    server.forget_ue(ue);
}

/// A stand-in SMF that refuses every UpdateSMContext with `status`, carrying `n1` as
/// its SmContextUpdateError's `n1SmMsg` part when given (TS 29.502 §5.2.2.3.1 step
/// 2b, Table 6.1.6.2.36-1).
async fn refusing_smf(status: u16, n1: Option<Vec<u8>>) -> (nextgcore_sbi::server::SbiServer, u16) {
    use nextgcore_sbi::message::{SbiPart, SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |_req: SReq| {
            let n1 = n1.clone();
            async move {
                let mut body = serde_json::json!({
                    "error": { "status": status, "cause": "SUBSCRIPTION_DENIED" },
                });
                let Some(n1) = n1 else {
                    return SResp::with_status(status)
                        .with_body(body.to_string(), "application/json");
                };
                body["n1SmMsg"] = serde_json::json!({ "contentId": "n1SmMsg" });
                SResp::with_status(status)
                    .with_body(body.to_string(), "application/json")
                    .with_part(SbiPart::with_content(
                        "n1SmMsg",
                        nextgcore_sbi::constants::content_type::APPLICATION_5GNAS,
                        bytes::Bytes::from(n1),
                    ))
            }
        })
        .await
        .expect("stand-in SMF starts");
    (server, addr.port())
}

/// The one DL NAS TRANSPORT a UE-requested modification of `ue` (PSI 5, PTI 7) at
/// an SMF on `port` is answered with.
async fn modification_answer(ue: u64, ran: u32, sm_ref: &str, port: u16) -> Vec<u8> {
    let mut server = capturing_ngap_server().await;
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, sm_ref, port);
    server
        .handle_5gsm_message(ASSOC, ue, ran, &[0x2E, 0x05, 0x07, 0xC9], None)
        .await
        .expect("handled");
    let sent = apply_until(&mut server, |s| !concerns(s, ue).is_empty()).await;
    let [Sent::DownlinkNas { nas_pdu, .. }] = concerns(&sent, ue)[..] else {
        panic!("one DL NAS TRANSPORT to the UE: {sent:?}");
    };
    let nas_pdu = nas_pdu.clone();
    server.forget_ue(ue);
    nas_pdu
}

/// #1590, TS 29.502 §5.2.2.3.1 step 2b / TS 24.501 §6.4.2.4.1: an SMF that refuses a
/// UE-requested modification with its own PDU SESSION MODIFICATION REJECT (#29 here,
/// as smfd answers a PCF refusal) has that reject relayed to the UE, not the AMF's
/// own #26. A refusal with no N1 still gets the AMF's #26.
///
/// REVERT-VERIFIED: with the SMF's `n1SmMsg` dropped on a non-2xx again, the UE gets
/// `CA 1A` (#26) instead of `CA 1D`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_smf_modification_reject_is_relayed_to_the_ue_1590() {
    let smf_reject = vec![0x2E, 0x05, 0x07, 0xCA, 0x1D];
    let (relaying, port) = refusing_smf(403, Some(smf_reject.clone())).await;
    let nas = modification_answer(15_900_101, 159, "mod-1590-n1", port).await;
    assert!(
        nas.windows(smf_reject.len()).any(|w| w == smf_reject),
        "the DL NAS TRANSPORT carries the SMF's MODIFICATION REJECT #29: {nas:02x?}"
    );
    assert!(
        !nas.windows(5).any(|w| w == [0x2E, 0x05, 0x07, 0xCA, 0x1A]),
        "and not the AMF's #26: {nas:02x?}"
    );
    relaying.stop().await.expect("stop");

    let (bare, port) = refusing_smf(403, None).await;
    let nas = modification_answer(15_900_102, 160, "mod-1590-bare", port).await;
    let own = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
    assert!(
        nas.windows(own.len()).any(|w| w == own),
        "a refusal with no N1 gets the AMF's own #26: {nas:02x?}"
    );
    bare.stop().await.expect("stop");
}

/// What a release-answering stand-in SMF saw: the URI, the JSON body, and the
/// `n1SmMsg` part.
type ReleaseCall = (String, serde_json::Value, Vec<u8>);

/// A stand-in SMF for a UE-requested PDU Session Release (#1637), answering each
/// N1 by its SM context ref's prefix:
/// - `rel-n2-*`: 200 with the PDU SESSION RELEASE COMMAND (`D3`, the request's PSI
///   and PTI, #36) and N2 `transfer_for(ref)` as `PDU_RES_REL_CMD` (an active UP);
/// - `rel-n1-*`: 200 with the command alone (no user plane to release);
/// - `rel-rej-*`: 403 with a PDU SESSION RELEASE REJECT (`D2`, #43);
/// - `rel-foreign-*`: 403 with a 5GSM message for another PSI.
async fn release_answering_smf() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<std::sync::Mutex<Vec<ReleaseCall>>>,
) {
    use base64::Engine as _;
    use nextgcore_sbi::message::{SbiPart, SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let seen: Arc<std::sync::Mutex<Vec<ReleaseCall>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |req: SReq| {
            let sink = Arc::clone(&sink);
            async move {
                let uri = req.header.uri.clone();
                let body: serde_json::Value = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str(c).ok())
                    .unwrap_or_default();
                let n1 = req
                    .http
                    .parts
                    .iter()
                    .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
                    .map(|p| p.data.to_vec())
                    .unwrap_or_default();
                sink.lock()
                    .expect("sink")
                    .push((uri.clone(), body, n1.clone()));
                let sm_ref = uri
                    .split("/sm-contexts/")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .unwrap_or_default()
                    .to_string();
                let (psi, pti) = (
                    n1.get(1).copied().unwrap_or(0),
                    n1.get(2).copied().unwrap_or(0),
                );
                let part = |bytes: Vec<u8>| {
                    SbiPart::with_content(
                        "n1SmMsg",
                        nextgcore_sbi::constants::content_type::APPLICATION_5GNAS,
                        bytes::Bytes::from(bytes),
                    )
                };
                let command = vec![0x2E, psi, pti, 0xD3, 0x24];
                if sm_ref.starts_with("rel-n2-") {
                    let answer = serde_json::json!({
                        "n1SmMsg": { "contentId": "n1SmMsg" },
                        "n2SmInfoType": "PDU_RES_REL_CMD",
                        "n2SmInfo": base64::engine::general_purpose::STANDARD
                            .encode(transfer_for(&sm_ref)),
                    });
                    return SResp::with_status(200)
                        .with_body(answer.to_string(), "application/json")
                        .with_part(part(command));
                }
                if sm_ref.starts_with("rel-n1-") {
                    let answer = serde_json::json!({ "n1SmMsg": { "contentId": "n1SmMsg" } });
                    return SResp::with_status(200)
                        .with_body(answer.to_string(), "application/json")
                        .with_part(part(command));
                }
                let reject = if sm_ref.starts_with("rel-foreign-") {
                    vec![0x2E, psi.wrapping_add(1), pti, 0xD2, 0x2B]
                } else {
                    vec![0x2E, psi, pti, 0xD2, 0x2B]
                };
                let answer = serde_json::json!({
                    "error": { "status": 403, "cause": "INVALID_PDU_SESSION_ID" },
                    "n1SmMsg": { "contentId": "n1SmMsg" },
                });
                SResp::with_status(403)
                    .with_body(answer.to_string(), "application/json")
                    .with_part(part(reject))
            }
        })
        .await
        .expect("stand-in SMF starts");
    (server, addr.port(), seen)
}

/// The NAS-PDU and the `(psi, transfer)` items of a PDU SESSION RESOURCE RELEASE
/// COMMAND, decoded with the generated codec.
#[allow(clippy::type_complexity)]
fn decoded_release_command_relayed(pdu: &[u8]) -> Option<(Option<Vec<u8>>, Vec<(u8, Vec<u8>)>)> {
    use nextgcore_ngap_gen::generated as g;
    let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let g::InitiatingMessageValue::Id_PDUSessionResourceRelease(cmd) = m.value else {
        return None;
    };
    let (mut nas, mut items) = (None, Vec::new());
    for ie in cmd.protocol_i_es.0 {
        use g::PDUSessionResourceReleaseCommandProtocolIEs_EntryValue as Ie;
        match ie.value {
            Ie::Id_NAS_PDU(n) => nas = Some(n.0),
            Ie::Id_PDUSessionResourceToReleaseListRelCmd(list) => {
                items = list
                    .0
                    .into_iter()
                    .map(|i| {
                        (
                            i.pdu_session_id.0,
                            i.pdu_session_resource_release_command_transfer.0,
                        )
                    })
                    .collect()
            }
            _ => {}
        }
    }
    Some((nas, items))
}

/// Send `ue` a UE-requested release of PSI 5 (PTI 7) held at `sm_ref` on `port`;
/// return the raw NGAP the AMF sends the UE's gNB once the SMF has answered.
async fn release_and_collect(
    server: &mut NgapServer,
    ue: u64,
    ran: u32,
    sm_ref: &str,
    port: u16,
) -> Vec<Vec<u8>> {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.nr_tai.plmn_id = PlmnId::new("001", "01");
        s.amf_ue.nr_tai.tac = 0x1637;
        s.amf_ue.nr_cgi.plmn_id = PlmnId::new("001", "01");
        s.amf_ue.nr_cgi.cell_id = 0x0016_3701;
    });
    hold_session(server, ue, 5, sm_ref, port);
    server.mark_up_active(ue, 5);
    server
        .handle_5gsm_message(ASSOC, ue, ran, &[0x2E, 0x05, 0x07, 0xD1], None)
        .await
        .expect("handled");
    let mut raw = Vec::new();
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        raw.extend(take_sent_ngap(server).into_iter().map(|(_, p)| p));
        if !raw.is_empty() {
            return raw;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing sent for UE {ue} after 3 s");
}

/// #1637, TS 23.502 §4.3.4.2 steps 1a-3 / TS 24.501 §6.4.3.3: a UE's PDU SESSION
/// RELEASE REQUEST goes to the SMF in an UpdateSMContext (the N1 as received, with
/// the User Location Information). With an active user plane, the SMF's PDU SESSION
/// RELEASE COMMAND rides a PDU SESSION RESOURCE RELEASE COMMAND as its NAS-PDU,
/// with the SMF's N2 transfer as received (TS 38.413 §9.2.1.3). The session is kept
/// until the SMF reports it RELEASED, so the UE's RELEASE COMPLETE still finds it.
///
/// REVERT-VERIFIED: with main's 0xD1 arm (the AMF's own release) back, the SMF
/// gets no UpdateSMContext with the N1 (`left: 0`), and the UE gets the AMF's own
/// RELEASE COMMAND #36 at once. All four #1637 tests fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_requested_release_is_the_smfs_to_answer_1637() {
    let (_smf, port, calls) = release_answering_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (16_370_101u64, 163u32);
    let raw = release_and_collect(&mut server, ue, ran, "rel-n2-1637", port).await;

    let seen = calls.lock().expect("calls").clone();
    assert_eq!(seen.len(), 1, "one SMF request: {seen:?}");
    let (uri, body, n1) = &seen[0];
    assert!(uri.ends_with("/sm-contexts/rel-n2-1637/modify"), "{uri}");
    assert_eq!(
        n1,
        &vec![0x2E, 0x05, 0x07, 0xD1],
        "the UE's request, as received"
    );
    assert_eq!(body["n1SmMsg"]["contentId"], "n1SmMsg");
    assert_eq!(
        body["ueLocation"]["nrLocation"]["tai"]["tac"], "001637",
        "with the ULI: {body}"
    );

    let [pdu] = &raw[..] else {
        panic!("one NGAP message: {raw:02x?}");
    };
    let (nas, items) = decoded_release_command_relayed(pdu).expect("a RELEASE COMMAND");
    assert_eq!(
        items,
        vec![(5, transfer_for("rel-n2-1637"))],
        "the SMF's transfer"
    );
    let nas = nas.expect("the NAS-PDU");
    let command = [0x2E, 0x05, 0x07, 0xD3, 0x24];
    assert!(
        nas.windows(command.len()).any(|w| w == command),
        "the SMF's RELEASE COMMAND, with the UE's PTI: {nas:02x?}"
    );
    assert!(!server.up_active.contains(&(ue, 5)));
    assert!(
        server.sm_context_refs.contains_key(&(ue, 5)),
        "kept until the SMF reports RELEASED"
    );
    server.forget_ue(ue);
}

/// #1637: with no user plane to release (the SMF answers no N2, TS 23.502 §4.3.4.2
/// step 3a), the SMF's RELEASE COMMAND goes in a DL NAS TRANSPORT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_with_no_user_plane_relays_the_command_alone_1637() {
    let (_smf, port, _calls) = release_answering_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (16_370_102u64, 164u32);
    let raw = release_and_collect(&mut server, ue, ran, "rel-n1-1637", port).await;
    let sent: Vec<Sent> = raw.iter().map(|p| decode_sent(p)).collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = &sent[..] else {
        panic!("one DL NAS TRANSPORT: {sent:?}");
    };
    let command = [0x2E, 0x05, 0x07, 0xD3, 0x24];
    assert!(
        nas_pdu.windows(command.len()).any(|w| w == command),
        "{nas_pdu:02x?}"
    );
    server.forget_ue(ue);
}

/// #1637, TS 24.501 §6.4.3.4 and §5.4.5.3.1 case e): the SMF's PDU SESSION RELEASE
/// REJECT is relayed. An SMF that cannot be reached, or that refuses with an N1 that
/// is not a 5GSM message for this session (the #1590 review guard), has the request
/// sent back with 5GMM #90 "payload was not forwarded", after which the UE releases
/// locally (§6.4.3.5 d)).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_or_unreachable_release_is_answered_as_the_spec_says_1637() {
    let (_smf, port, _calls) = release_answering_smf().await;
    let down = nextgcore_sbi::test_support::down_port();
    let request = [0x2E, 0x05, 0x07, 0xD1];
    for (i, (sm_ref, port, want_reject)) in [
        ("rel-rej-1637", port, true),
        ("rel-foreign-1637", port, false),
        ("rel-down-1637", down.port(), false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut server = capturing_ngap_server().await;
        let (ue, ran) = (16_370_110u64 + i as u64, 170 + i as u32);
        let raw = release_and_collect(&mut server, ue, ran, sm_ref, port).await;
        let sent: Vec<Sent> = raw.iter().map(|p| decode_sent(p)).collect();
        let [Sent::DownlinkNas { nas_pdu, .. }] = &sent[..] else {
            panic!("{sm_ref}: one DL NAS TRANSPORT: {sent:?}");
        };
        if want_reject {
            let reject = [0x2E, 0x05, 0x07, 0xD2, 0x2B];
            assert!(
                nas_pdu.windows(reject.len()).any(|w| w == reject),
                "{sm_ref}: the SMF's RELEASE REJECT #43: {nas_pdu:02x?}"
            );
        } else {
            use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
            let Ok(FiveGmmMessage::DlNasTransport(dl)) =
                parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&nas_pdu[7..]))
            else {
                panic!("{sm_ref}: a DL NAS TRANSPORT: {nas_pdu:02x?}");
            };
            assert_eq!(dl.gmm_cause, Some(90), "{sm_ref}: #90");
            assert_eq!(dl.payload_container.data.to_vec(), request.to_vec());
        }
        server.forget_ue(ue);
    }
}

/// Handle `request` (PSI 5) for `ue`, make the UE CM-IDLE before the SMF's answer
/// is applied, and return the page the answer queued (removed from the context).
async fn page_after_idle_answer(
    server: &mut NgapServer,
    ue: u64,
    ran: u32,
    request: &[u8],
) -> crate::context::PagingContext {
    server
        .handle_5gsm_message(ASSOC, ue, ran, request, None)
        .await
        .expect("handled");
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        let paged = crate::context::amf_self().read().unwrap().paging_find(ue);
        if let Some(paged) = paged {
            crate::context::amf_self().read().unwrap().paging_remove(ue);
            return paged;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("UE {ue} was not paged within 3 s");
}

/// #1643 review, TS 23.502 §4.3.4.2 step 4 and §4.2.3.3: when the UE went CM-IDLE
/// before the SMF's answer arrived, the AMF pages it. The SMF's RELEASE COMMAND or its
/// MODIFICATION REJECT is kept in the page, N1 only, and delivered after the Service
/// Request, through the N1N2 transfer's paging path.
///
/// REVERT-VERIFIED: with the answer dropped for an idle UE again (no page), both
/// cases panic "was not paged".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_smf_answer_for_a_ue_gone_idle_is_paged_for_and_delivered_1643() {
    // The page reads the paging strategy (#1588).
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;

    // The release: N1 RELEASE COMMAND and the N2 release.
    let (_smf, port, _calls) = release_answering_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (16_430_101u64, 191u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "rel-n2-1643-idle", port);
    server.mark_up_active(ue, 5);
    let paged = page_after_idle_answer(&mut server, ue, ran, &[0x2E, 0x05, 0x07, 0xD1]).await;
    let command = vec![0x2E, 0x05, 0x07, 0xD3, 0x24];
    assert_eq!(
        paged.pending_n1.as_deref(),
        Some(&command[..]),
        "the SMF's command is kept"
    );
    assert!(
        paged.pending_n1_only && !paged.pending_n2_release && paged.pending_n2.is_none(),
        "N1 only: a CM-IDLE UE has no AN resources to release (round 2)"
    );
    assert_eq!(paged.pdu_session_id, Some(5));
    // The UE answers the page: the Service Request brings it back.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
    take_sent_ngap(&mut server);
    server
        .deliver_paged_after_service_request(ASSOC, ue, ran, &paged)
        .await
        .expect("delivered");
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    assert!(
        !sent
            .iter()
            .any(|s| matches!(s, Sent::ReleaseCommand { .. })),
        "no Release Command at the gNB: {sent:?}"
    );
    assert!(
        sent.iter()
            .any(|s| matches!(s, Sent::DownlinkNas { nas_pdu, .. }
            if nas_pdu.windows(command.len()).any(|w| w == command))),
        "the SMF's RELEASE COMMAND reaches the UE after the Service Request: {sent:?}"
    );
    server.forget_ue(ue);

    // The modification: the SMF's own MODIFICATION REJECT.
    let reject = vec![0x2E, 0x05, 0x07, 0xCA, 0x1D];
    let (refusing, port) = refusing_smf(403, Some(reject.clone())).await;
    let (ue, ran) = (16_430_102u64, 192u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "mod-1643-idle", port);
    let paged = page_after_idle_answer(&mut server, ue, ran, &[0x2E, 0x05, 0x07, 0xC9]).await;
    assert_eq!(paged.pending_n1.as_deref(), Some(&reject[..]));
    assert!(paged.pending_n1_only && !paged.pending_n2_release && !paged.pending_n2_modify);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
    take_sent_ngap(&mut server);
    server
        .deliver_paged_after_service_request(ASSOC, ue, ran, &paged)
        .await
        .expect("delivered");
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    assert!(
        sent.iter()
            .any(|s| matches!(s, Sent::DownlinkNas { nas_pdu, .. }
            if nas_pdu.windows(reject.len()).any(|w| w == reject))),
        "the SMF's MODIFICATION REJECT reaches the UE after the Service Request: {sent:?}"
    );
    server.forget_ue(ue);
    refusing.stop().await.expect("stop");
}

/// The PSIs an INITIAL CONTEXT SETUP REQUEST sets up; `None` for any other PDU.
fn ics_psis(pdu: &[u8]) -> Option<Vec<u8>> {
    use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
    use nextgcore_ngap_gen::generated as g;
    let Ok(g::NGAP_PDU::InitiatingMessage(m)) = nextgcore_ngap_gen::decode(pdu) else {
        return None;
    };
    let g::InitiatingMessageValue::Id_InitialContextSetup(req) = m.value else {
        return None;
    };
    Some(
        req.protocol_i_es
            .0
            .into_iter()
            .filter_map(|ie| match ie.value {
                V::Id_PDUSessionResourceSetupListCxtReq(l) => Some(l.0),
                _ => None,
            })
            .flatten()
            .map(|it| it.pdu_session_id.0)
            .collect(),
    )
}

/// How the paged UE comes back in [`release_then_idle_answer`].
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// A Service Request from CM-IDLE, with its PDU session status IE if given.
    ServiceRequest(Option<[u8; 2]>),
    /// A protected periodic registration update from CM-IDLE (TS 24.501 §4.4.6).
    PeriodicUpdate,
}

/// Whether the process-global connected-downlink queue holds an item for `ue`
/// (peeked by draining and re-adding; the caller holds CONNECTED_DOWNLINK_LOCK).
fn connected_downlink_queued_for(ue: u64) -> bool {
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap();
    let items = guard.connected_downlink_drain();
    let found = items.iter().any(|i| i.amf_ue_ngap_id == ue);
    for item in items {
        guard.connected_downlink_add(item);
    }
    found
}

/// The UE's release is answered by the SMF while the UE went CM-IDLE; then the UE
/// answers the page (`answer`). With `ongoing_page`, another page for the UE was
/// already running: the SMF's N1 waits as a queued downlink, that page is exhausted,
/// and the downlink pump pages for the queued N1 itself. Returns the SMF calls and
/// the NGAP sent from the UE's answer on.
async fn release_then_idle_answer(
    old_id: u64,
    new_id: u64,
    sm_ref: &str,
    answer: Answer,
    ongoing_page: bool,
) -> (Vec<ReleaseCall>, Vec<Vec<u8>>) {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = release_answering_smf().await;
    let mut server = capturing_ngap_server().await;
    let tmsi = old_id as u32;
    let mut ue = match answer {
        Answer::ServiceRequest(_) => idle_registered_ue(old_id),
        Answer::PeriodicUpdate => {
            let mut ue = idle_ue_with_security(old_id, tmsi);
            // NEA0, so the delivered N1 can be found in the DL NAS TRANSPORT's octets.
            ue.amf_ue.selected_enc_algorithm = 0;
            ue
        }
    };
    ue.cm_idle = false;
    ue.amf_ue.supi = Some(format!("imsi-00101000164{:05}", old_id % 100_000));
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai { sst: 1, sd: None }];
    ue.amf_ue.nr_tai.plmn_id = PlmnId::new("001", "01");
    ue.amf_ue.nr_tai.tac = 0x74;
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().expect("ctx lock");
        guard.amf_ue_publish(&ue.amf_ue, 51, 1);
    }
    server.ue_auth_state.insert(old_id, ue);
    hold_session(&mut server, old_id, 5, sm_ref, port);
    server.mark_up_active(old_id, 5);
    server
        .handle_5gsm_message(ASSOC, old_id, 51, &[0x2E, 0x05, 0x07, 0xD1], None)
        .await
        .expect("handled");
    server.ue_auth_state.with_mut(old_id, |s| s.cm_idle = true);
    if ongoing_page {
        // Another transfer's page is already running for the UE.
        let mut other = paged_ue(old_id, 4);
        other.tmsi = tmsi;
        crate::context::amf_self().read().unwrap().paging_add(other);
        for _ in 0..300 {
            server.process_sbi_outcomes().await;
            if connected_downlink_queued_for(old_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            connected_downlink_queued_for(old_id),
            "behind the ongoing page, the SMF's N1 waits queued"
        );
        // The ongoing page is exhausted (T3513); the pump pages for the queued N1.
        crate::context::amf_self()
            .read()
            .unwrap()
            .paging_remove(old_id);
        server.process_connected_downlinks().await;
    }
    let paged = {
        let mut found = None;
        for _ in 0..300 {
            server.process_sbi_outcomes().await;
            found = crate::context::amf_self()
                .read()
                .unwrap()
                .paging_find(old_id);
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        found.expect("the UE is paged")
    };
    assert!(paged.pending_n1_only, "an N1-only page");
    assert!(
        paged.pending_n2.is_none() && !paged.pending_n2_release,
        "no N2"
    );
    take_sent_ngap(&mut server);
    let calls_before = calls.lock().expect("calls").len();

    server.forced_amf_ue_ngap_id = Some(new_id);
    let nas = match answer {
        Answer::ServiceRequest(pss) => {
            let mut nas = protected_service_request([0; 4], tmsi);
            if let Some(bitmap) = pss {
                nas.extend_from_slice(&[0x50, 0x02, bitmap[0], bitmap[1]]);
            }
            nas
        }
        Answer::PeriodicUpdate => {
            let state = server.ue_auth_state.get(old_id).expect("the UE");
            let rr = guti_registration_request(
                crate::gmm_build::registration_type::PERIODIC_UPDATING,
                tmsi,
            );
            protected_initial_registration(&state.amf_ue, &rr, &rr, 5)
        }
    };
    let _ = server
        .handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await;
    assert!(
        server.ue_auth_state.get(new_id).is_some(),
        "the UE answered the page"
    );
    let mut sent = Vec::new();
    for _ in 0..50 {
        server.process_sbi_outcomes().await;
        sent.extend(take_sent_ngap(&mut server).into_iter().map(|(_, p)| p));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let after = calls.lock().expect("calls")[calls_before..].to_vec();
    server.forget_ue(new_id);
    crate::context::amf_self()
        .read()
        .unwrap()
        .paging_remove(old_id);
    (after, sent)
}

/// #1643 round 3: an ordinary page (not N1-only) for a session with no setup
/// transfer, answered by a Service Request whose PDU session status shows that
/// session inactive. A session the plan releases is not re-activated by the #540
/// rule: the release goes to the SMF, and no ACTIVATING. The activation would go to
/// the default SMF (the release drops the session's SMF), so the stand-in is also
/// the environment's SMF.
///
/// REVERT-VERIFIED: without the `!plan.release.contains(&psi)` check, the stand-in
/// sees the release and then an ACTIVATING for PSI 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_page_for_a_session_the_ue_releases_activates_nothing_1643() {
    let _ctx = crate::test_support::CONTEXT_GUARD.lock().await;
    let (_smf, port, calls) = release_answering_smf().await;
    // An activation that loses the session's SMF goes to the environment's SMF.
    let _env = super::SmfEnvGuard::acquire(port).await;
    // Paging reads the strategy (#1588). Taken last.
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    let _guamis = serve_only_local_guami();
    crate::context::amf_context_init(64, 1024, 4096);
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id) = (16_430_241u64, 16_430_242u64);
    let mut ue = idle_registered_ue(old_id);
    ue.amf_ue.supi = Some(format!("imsi-00101000164{:05}", old_id % 100_000));
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai { sst: 1, sd: None }];
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().expect("ctx lock");
        guard.amf_ue_publish(&ue.amf_ue, 51, 1);
    }
    server.ue_auth_state.insert(old_id, ue);
    hold_session(&mut server, old_id, 5, "rel-n2-1643-plan", port);
    // smfd's Downlink Data Report page: names PSI 5, no transfer.
    let mut page = paged_ue(old_id, 4);
    page.pdu_session_id = Some(5);
    crate::context::amf_self().read().unwrap().paging_add(page);

    let mut nas = protected_service_request([0; 4], old_id as u32);
    nas.extend_from_slice(&[0x50, 0x02, 0x00, 0x00]);
    server.forced_amf_ue_ngap_id = Some(new_id);
    let _ = server
        .handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await;
    for _ in 0..50 {
        server.process_sbi_outcomes().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = calls.lock().expect("calls").clone();
    assert!(
        seen.iter()
            .any(|(u, _, _)| u.ends_with("/sm-contexts/rel-n2-1643-plan/release")),
        "the session the UE dropped is released at the SMF: {seen:?}"
    );
    assert!(
        !seen.iter().any(|(_, b, _)| b["upCnxState"] == "ACTIVATING"),
        "and not re-activated: {seen:?}"
    );
    server.forget_ue(new_id);
    crate::context::amf_self()
        .read()
        .unwrap()
        .paging_remove(old_id);
}

/// #1643 review round 2, TS 23.502 §4.3.4.2 step 4 (the NAS message only): a page for
/// the SMF's answer to the UE's own release is N1-only. The real Service Request from
/// CM-IDLE that answers it re-activates no user plane for that session (no
/// ACTIVATING at the SMF, no ICS item for the PSI), and the SMF's RELEASE COMMAND goes
/// to the UE in a DL NAS TRANSPORT, with no Release Command at the gNB. If the UE's
/// PDU session status already shows the session inactive, it is released toward the
/// SMF there and the command is not sent.
///
/// REVERT-VERIFIED: with the page queued as before (PagedN2::Release / Setup, no
/// N1-only mark), the #540 rule sends ACTIVATING for PSI 5 and the first case fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_n1_only_page_reactivates_nothing_and_delivers_the_command_1643() {
    let _ctx = crate::test_support::CONTEXT_GUARD.lock().await;
    // The re-page case drains the process-global connected-downlink queue.
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    // #1933: the Registration Accept resolves the PCF for the UE policy create.
    let _pcf = crate::test_support::SMF_ENV_LOCK.lock().await;
    // #1974: this test resolves the AUSF (process-global endpoint).
    let _ausf = crate::test_support::AUSF_ENV_LOCK.lock().await;
    // Paging reads the strategy (#1588).
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    let _guamis = serve_only_local_guami();
    let command = [0x2E, 0x05, 0x07, 0xD3, 0x24];
    let has_command = |sent: &[Vec<u8>]| {
        sent.iter().any(|p| {
            matches!(decode_sent(p), Sent::DownlinkNas { nas_pdu, .. }
                if nas_pdu.windows(command.len()).any(|w| w == command))
        })
    };

    // The Service Request reports no PDU session status.
    let (calls, sent) = release_then_idle_answer(
        16_430_201,
        16_430_202,
        "rel-n2-1643-sr",
        Answer::ServiceRequest(None),
        false,
    )
    .await;
    assert!(
        !calls
            .iter()
            .any(|(_, b, _)| b["upCnxState"] == "ACTIVATING"),
        "no user-plane activation for the released session: {calls:?}"
    );
    assert!(
        sent.iter()
            .filter_map(|p| ics_psis(p))
            .all(|psis| !psis.contains(&5)),
        "the Initial Context Setup sets no PSI 5 up"
    );
    assert!(
        !sent
            .iter()
            .any(|p| matches!(decode_sent(p), Sent::ReleaseCommand { .. })),
        "no Release Command at the gNB: the UE had no AN resources"
    );
    assert!(
        has_command(&sent),
        "the SMF's RELEASE COMMAND reaches the UE"
    );

    // Its PDU session status shows PSI 5 inactive (all bits clear).
    let (calls, sent) = release_then_idle_answer(
        16_430_211,
        16_430_212,
        "rel-n2-1643-pss",
        Answer::ServiceRequest(Some([0x00, 0x00])),
        false,
    )
    .await;
    assert!(
        calls
            .iter()
            .any(|(u, _, _)| u.ends_with("/sm-contexts/rel-n2-1643-pss/release")),
        "the session is released toward the SMF: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|(_, b, _)| b["upCnxState"] == "ACTIVATING"),
        "and not activated: {calls:?}"
    );
    assert!(
        !has_command(&sent),
        "no RELEASE COMMAND for a session the UE dropped"
    );

    // #1643 round 3: a periodic registration update from CM-IDLE answers the page.
    let (calls, sent) = release_then_idle_answer(
        16_430_221,
        16_430_222,
        "rel-n2-1643-rr",
        Answer::PeriodicUpdate,
        false,
    )
    .await;
    assert!(
        !calls
            .iter()
            .any(|(_, b, _)| b["upCnxState"] == "ACTIVATING"),
        "the registration update re-activates nothing for it: {calls:?}"
    );
    assert!(
        has_command(&sent),
        "the update's page delivers the SMF's RELEASE COMMAND"
    );

    // #1643 round 3: the answer came behind another page, which was exhausted; the
    // re-page for the queued N1 is N1-only too.
    let (calls, sent) = release_then_idle_answer(
        16_430_231,
        16_430_232,
        "rel-n2-1643-requeue",
        Answer::ServiceRequest(None),
        true,
    )
    .await;
    assert!(
        !calls
            .iter()
            .any(|(_, b, _)| b["upCnxState"] == "ACTIVATING"),
        "the re-page re-activates nothing: {calls:?}"
    );
    assert!(
        has_command(&sent),
        "the re-page delivers the SMF's RELEASE COMMAND"
    );
}

/// #1643 review, TS 24.501 §7.3.2 c) 2): a PDU SESSION RELEASE REQUEST for a PSI that
/// matches no existing PDU session is answered with a DL NAS TRANSPORT carrying the
/// message back and 5GMM #90 "payload was not forwarded". Before, it was dropped.
///
/// REVERT-VERIFIED: with the drop back, nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_request_for_no_session_gets_payload_not_forwarded_1643() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (16_430_111u64, 193u32);
    secured_registered_ue(&mut server, ue, ran);
    let request = [0x2E, 0x09, 0x07, 0xD1];
    server
        .handle_5gsm_message(ASSOC, ue, ran, &request, None)
        .await
        .expect("handled");
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = &sent[..] else {
        panic!("one DL NAS TRANSPORT: {sent:?}");
    };
    use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
    let Ok(FiveGmmMessage::DlNasTransport(dl)) =
        parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&nas_pdu[7..]))
    else {
        panic!("a DL NAS TRANSPORT: {nas_pdu:02x?}");
    };
    assert_eq!(dl.gmm_cause, Some(90));
    assert_eq!(dl.payload_container.data.to_vec(), request.to_vec());
    server.forget_ue(ue);
}

/// #1590 review guard: an SMF that refuses a UE-requested modification with an N1
/// that is not a 5GSM message for this session does not have it relayed. The UE
/// gets the AMF's own MODIFICATION REJECT #26.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modification_refusal_for_another_session_is_not_relayed_1637() {
    let (foreign, port) = refusing_smf(403, Some(vec![0x2E, 0x06, 0x07, 0xCA, 0x1D])).await;
    let nas = modification_answer(16_370_120, 180, "mod-1637-foreign", port).await;
    let own = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
    assert!(
        nas.windows(own.len()).any(|w| w == own),
        "the AMF's own #26: {nas:02x?}"
    );
    foreign.stop().await.expect("stop");
}

/// #1636: an SMF refusal whose N1 is longer than a payload container can carry
/// (TS 24.501 §9.11.3.39) is not relayed, truncated or sent bare. The UE gets the
/// AMF's own MODIFICATION REJECT #26.
///
/// REVERT-VERIFIED: without the length bound in `smf_n1_for_session`, nothing is
/// sent to the UE at all (the builder refuses the N1), and the test times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_long_smf_n1_gets_the_amfs_own_reject_1636() {
    let mut n1 = vec![0x2E, 0x05, 0x07, 0xCA, 0x1D];
    n1.resize(crate::gmm_build::MAX_PAYLOAD_CONTAINER_LEN + 1, 0);
    let (smf, port) = refusing_smf(403, Some(n1)).await;
    let nas = modification_answer(16_360_101, 201, "mod-1636-long", port).await;
    let own = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
    assert!(
        nas.windows(own.len()).any(|w| w == own),
        "the AMF's own #26: {:02x?}",
        &nas[..nas.len().min(32)]
    );
    assert!(nas.len() < 100, "and not the SMF's oversized N1");
    smf.stop().await.expect("stop");
}

/// A stand-in SMF that accepts every UpdateSMContext (200) with `n1` as its
/// `n1SmMsg` and an N2 SM transfer as its `n2SmInfo` (PDU_RES_MOD_REQ), both as
/// binary parts (TS 29.502 §6.1.6.2.4).
async fn accepting_smf(n1: Vec<u8>) -> (nextgcore_sbi::server::SbiServer, u16) {
    use nextgcore_sbi::message::{SbiPart, SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |_req: SReq| {
            let n1 = n1.clone();
            async move {
                let body = serde_json::json!({
                    "n1SmMsg": { "contentId": "n1SmMsg" },
                    "n2SmInfo": { "contentId": "n2SmInfo" },
                    "n2SmInfoType": "PDU_RES_MOD_REQ",
                });
                SResp::with_status(200)
                    .with_body(body.to_string(), "application/json")
                    .with_part(SbiPart::with_content(
                        "n1SmMsg",
                        nextgcore_sbi::constants::content_type::APPLICATION_5GNAS,
                        bytes::Bytes::from(n1),
                    ))
                    .with_part(SbiPart::with_content(
                        "n2SmInfo",
                        "application/vnd.3gpp.ngap",
                        bytes::Bytes::from_static(&[0x00, 0x00, 0x00]),
                    ))
            }
        })
        .await
        .expect("stand-in SMF starts");
    (server, addr.port())
}

/// What a UE-requested modification of `ue` (PSI 5, PTI 7) at an SMF on `port`
/// sends for that UE in the pass that sends anything: the number of PDUs, whether
/// one is an N2 Modify Request, and the DL NAS TRANSPORTs' NAS PDUs.
async fn modification_sends(
    ue: u64,
    ran: u32,
    sm_ref: &str,
    port: u16,
) -> (usize, bool, Vec<Vec<u8>>) {
    let mut server = capturing_ngap_server().await;
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, sm_ref, port);
    server
        .handle_5gsm_message(ASSOC, ue, ran, &[0x2E, 0x05, 0x07, 0xC9], None)
        .await
        .expect("handled");
    let sent = apply_until(&mut server, |s| !concerns(s, ue).is_empty()).await;
    let mine = concerns(&sent, ue);
    let modify = mine.iter().any(|s| matches!(s, Sent::ModifyRequest { .. }));
    let nas = mine
        .iter()
        .filter_map(|s| match s {
            Sent::DownlinkNas { nas_pdu, .. } => Some(nas_pdu.clone()),
            _ => None,
        })
        .collect();
    let out = (mine.len(), modify, nas);
    server.forget_ue(ue);
    out
}

/// #1674 (the #1670 review), TS 24.501 §9.11.3.39 / §6.4.2.4.1: an accepted
/// modification whose N1 the AMF cannot relay (over-long, or for another session)
/// sends no N2 Modify Request, so the gNB does not apply a QoS change the UE is
/// never told of. The UE gets the AMF's own #26. A relayable N1 still goes with
/// its N2 (the positive control).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_modification_with_an_unrelayable_n1_sends_no_n2_1674() {
    let command = vec![0x2E, 0x05, 0x07, 0xCB, 0x00];
    let (smf, port) = accepting_smf(command.clone()).await;
    let (_, modify, nas) = modification_sends(16_740_101, 211, "mod-1674-ok", port).await;
    assert!(modify, "a relayable command goes with its N2");
    assert!(
        nas.iter()
            .any(|p| p.windows(command.len()).any(|w| w == command)),
        "and the UE gets the SMF's command: {nas:02x?}"
    );
    smf.stop().await.expect("stop");

    let mut long = command.clone();
    long.resize(crate::gmm_build::MAX_PAYLOAD_CONTAINER_LEN + 1, 0);
    let foreign = vec![0x2E, 0x06, 0x07, 0xCB, 0x00];
    for (i, n1) in [long, foreign].into_iter().enumerate() {
        let (smf, port) = accepting_smf(n1).await;
        let ue = 16_740_110 + i as u64;
        let (count, modify, nas) =
            modification_sends(ue, 212 + i as u32, &format!("mod-1674-{i}"), port).await;
        assert!(!modify, "case {i}: no N2 Modify Request");
        let [nas_pdu] = &nas[..] else {
            panic!("case {i}: one DL NAS TRANSPORT ({count} PDUs)");
        };
        assert_eq!(count, 1, "case {i}: and nothing else");
        let own = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
        assert!(
            nas_pdu.windows(own.len()).any(|w| w == own),
            "case {i}: the AMF's own #26: {:02x?}",
            &nas_pdu[..nas_pdu.len().min(32)]
        );
        smf.stop().await.expect("stop");
    }
}

/// #1674 (the #1670 review, its mutation Q4): `protect_nas` refuses an empty plain
/// message, which is a builder's refusal passed on as `unwrap_or_default()`, so
/// nothing is sent for it. A real message is protected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protect_nas_refuses_an_empty_plain_message_1674() {
    let mut server = capturing_ngap_server().await;
    let ue = 16_740_201;
    secured_registered_ue(&mut server, ue, 221);
    assert!(
        server.protect_nas(ue, &[0x7E, 0x00, 0x68]).is_some(),
        "a real message is protected"
    );
    assert_eq!(server.protect_nas(ue, &[]), None, "an empty one is not");
    server.forget_ue(ue);
}

/// #1636: an SMF answer body larger than `MAX_SMF_RESPONSE_BODY` is refused while
/// it is read. The UE-requested modification is then an SMF failure with no N1, and
/// the UE gets the AMF's own #26.
///
/// REVERT-VERIFIED: with the SMF client uncapped (`SbiClient::for_peer`), the call
/// returns the 200 and the UE gets a MODIFICATION COMMAND.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_smf_answer_over_the_body_cap_is_refused_1636() {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let smf = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    smf.start(|_req: SReq| async move {
        let pad = "x".repeat(crate::sbi_path::MAX_SMF_RESPONSE_BODY + 1);
        let body = serde_json::json!({ "pad": pad }).to_string();
        SResp::with_status(200).with_body(body, "application/json")
    })
    .await
    .expect("stand-in SMF starts");
    let nas = modification_answer(16_360_111, 202, "mod-1636-big", addr.port()).await;
    let own = [0x2E, 0x05, 0x07, 0xCA, 0x1A];
    assert!(
        nas.windows(own.len()).any(|w| w == own),
        "the AMF's own #26: {nas:02x?}"
    );
    smf.stop().await.expect("stop");
}

/// TS 23.502 §4.2.3.2, CM-CONNECTED: a Service Request re-activating a session at a
/// blackholed SMF does not hold the NGAP task, and another UE's Service Request is
/// served meanwhile. The Service Accept waits for the ACTIVATING's answer, since it
/// rides the step-12 setup request. At the deadline the UE gets it on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_request_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_201u64, 123u32), (7_922_202u64, 124u32));
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    hold_blackholed(&mut server, dead.0, 1, "sr-922-dead");
    hold_session(&mut server, live.0, 1, "sr-922-live", port);

    let started = Instant::now();
    async fn handle(server: &mut NgapServer, (ue, ran): (u64, u32)) -> Vec<(u64, Vec<u8>)> {
        let sr = ue_protect(&service_request(Some(1 << 1)), 0);
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &sr))
            .await
            .expect("handled");
        take_sent_ngap(server)
    }
    let first = handle(&mut server, dead).await;
    let second = handle(&mut server, live).await;
    assert!(
        started.elapsed() < AT_ONCE,
        "the handlers waited {:?} for the SMF",
        started.elapsed()
    );
    assert!(
        first.is_empty() && second.is_empty(),
        "no Service Accept before the ACTIVATING is answered: {first:?} {second:?}"
    );

    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    let Sent::SetupRequest { items, nas_pdu, .. } = concerns(&sent, live.0)[0] else {
        panic!("the answered UE's setup request: {sent:?}");
    };
    assert_eq!(items, &vec![setup_item(1, transfer_for("sr-922-live"))]);
    assert_protected_service_accept(nas_pdu.as_deref().expect("the Accept rides the setup"));
    assert_eq!(
        until_called(&calls, "/sm-contexts/sr-922-live/modify")
            .await
            .1["upCnxState"],
        "ACTIVATING"
    );
    assert!(concerns(&sent, dead.0).is_empty(), "{sent:?}");

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<(u64, Sent)> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(a, p)| (a, decode_sent(&p)))
        .collect();
    let Sent::DownlinkNas { nas_pdu, .. } = concerns(&sent, dead.0)[0] else {
        panic!("a standalone Service Accept at the deadline: {sent:?}");
    };
    assert_protected_service_accept(nas_pdu);
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// TS 23.502 §4.2.3.2, CM-IDLE: a Service Request whose session to re-activate is
/// at a blackholed SMF does not hold the NGAP task. Its Initial Context Setup (step
/// 12) waits for the ACTIVATING's answer (step 4). At the deadline it goes without
/// that session, and the Service Accept reports the re-activation failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_service_request_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_301u64, 7_922_391u64);
    let mut ue = idle_registered_ue(old);
    // The ICS carries the Allowed NSSAI (TS 38.413 §9.2.2.1: one to eight).
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    server.ue_auth_state.insert(old, ue);
    hold_blackholed(&mut server, old, 5, "isr-922-dead");
    server.forced_amf_ue_ngap_id = Some(new);
    let tmsi = old as u32;
    // Data (1), uplink data status PSI 5, PDU session status PSI 5.
    let mut inner = vec![0x7E, 0x00, 0x4C, 0x10, 0x00, 0x07, 0xF4, 0x55, 0x6A];
    inner.extend_from_slice(&tmsi.to_be_bytes());
    inner.extend_from_slice(&[0x40, 0x02, 0x20, 0x00, 0x50, 0x02, 0x20, 0x00]);
    let mut nas = protected_service_request([0; 4], tmsi);
    nas.extend_from_slice(&[0x71, 0x00, inner.len() as u8]);
    nas.extend_from_slice(&inner);

    let started = Instant::now();
    server
        .handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    // nextgsim#488: the ULI is stamped as acquired now (seconds since the epoch).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    assert!(
        (now.saturating_sub(5)..=now).contains(
            &server
                .ue_auth_state
                .get(new)
                .expect("resumed")
                .amf_ue
                .ue_location_timestamp
        ),
        "ue_location_timestamp {} is not this message's arrival",
        server
            .ue_auth_state
            .get(new)
            .expect("resumed")
            .amf_ue
            .ue_location_timestamp
    );
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Initial Context Setup before the ACTIVATING is answered"
    );
    assert!(
        server.sbi_offload.key_busy((new, 5)),
        "the ACTIVATING is in flight"
    );
    assert_eq!(server.smf_joins.len(), 1);

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    let ics: Vec<_> = sent
        .iter()
        .filter(|(_, p)| decode_sent(p) == Sent::Other(Some(14)))
        .collect();
    assert_eq!(
        ics.len(),
        1,
        "one Initial Context Setup at the deadline: {sent:?}"
    );
    assert!(
        !server.up_active.contains(&(new, 5)),
        "the unanswered session is not in it"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

/// #778, TS 23.502 §4.2.3.3 step 4: a queued downlink setup whose ACTIVATING goes to
/// a blackholed SMF does not hold the NGAP task, and another UE's is delivered
/// meanwhile. The setup request waits for the SMF's transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downlink_setup_activated_at_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    // #1693: this test adds pages to, or pumps, the process-global paging map.
    let _paging_map = crate::context::PAGING_MAP_TEST_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_401u64, 125u32), (7_922_402u64, 126u32));
    let (dead_supi, live_supi) = ("imsi-001010009224010", "imsi-001010009224020");
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    with_supi(&mut server, dead.0, dead_supi);
    with_supi(&mut server, live.0, live_supi);
    hold_blackholed(&mut server, dead.0, 2, "dl-922-dead");
    hold_session(&mut server, live.0, 2, "dl-922-live", port);
    for supi in [dead_supi, live_supi] {
        let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
        assert_eq!(resp.status, 200);
    }

    let started = Instant::now();
    server.process_connected_downlinks().await;
    assert!(
        started.elapsed() < AT_ONCE,
        "the delivery waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    assert_eq!(
        concerns(&sent, live.0),
        vec![&Sent::SetupRequest {
            amf_ue_ngap_id: live.0,
            ran_ue_ngap_id: live.1,
            nas_pdu: None,
            items: vec![setup_item(2, transfer_for("dl-922-live"))],
        }]
    );
    until_called(&calls, "/sm-contexts/dl-922-live/modify").await;
    assert!(concerns(&sent, dead.0).is_empty(), "{sent:?}");
    assert!(server.sbi_offload.key_busy((dead.0, 2)));
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// TS 23.502 §4.2.6 step 5: the DEACTIVATED after an AN release goes to a blackholed
/// SMF without holding the NGAP task. The other session's DEACTIVATED still reaches
/// its SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_an_release_deactivation_at_a_blackholed_smf_does_not_hold_the_ngap_task() {
    // #1588: this test reads the paging strategy.
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_501u64, 127u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "an-922-dead");
    hold_session(&mut server, ue, 2, "an-922-live", port);

    let started = Instant::now();
    server
        .handle_ue_context_release_complete(ASSOC, &release_complete_pdu(ue, Some(ran)))
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let (_, body) = until_called(&calls, "/sm-contexts/an-922-live/modify").await;
    assert_eq!(body["upCnxState"], "DEACTIVATED");
    assert!(
        server.sbi_offload.key_busy((ue, 1)),
        "the other is still on its way"
    );
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.6: an AN release of a UE that is not registered releases its
/// sessions at the SMF, and a blackholed one does not hold the UE CONTEXT RELEASE
/// COMMAND.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_of_an_unregistered_ue_does_not_wait_for_a_blackholed_smf() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_601u64, 128u32);
    secured_registered_ue(&mut server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| s.registered = false);
    hold_blackholed(&mut server, ue, 1, "rel-922-dead");
    hold_session(&mut server, ue, 2, "rel-922-live", port);
    let request = crate::gnb_pdus::ue_context_release_request(
        &nextgcore_ngap::types::UeContextReleaseRequest {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            cause: nextgcore_ngap::types::Cause::RadioNetwork(
                nextgcore_ngap::types::CauseRadioNetwork::UserInactivity,
            ),
        },
    );

    let started = Instant::now();
    server
        .handle_ue_context_release(ASSOC, &request)
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = take_sent_ngap(&mut server);
    assert!(
        sent.iter()
            .any(|(_, p)| decode_sent(p) == Sent::Other(Some(41))),
        "the UE Context Release Command went at once: {sent:?}"
    );
    until_called(&calls, "/sm-contexts/rel-922-live/release").await;
    server.forget_ue(ue);
}

/// A de-registration's ReleaseSMContexts (`release_all_pdu_sessions`) go off the
/// NGAP task, so a blackholed SMF does not hold it. The other session is released at
/// its SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deregistration_does_not_wait_for_a_blackholed_smf() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_701u64, 129u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "dereg-922-dead");
    hold_session(&mut server, ue, 2, "dereg-922-live", port);

    let dereg = ue_protect(&switch_off_deregistration_request(), 0);
    let started = Instant::now();
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &dereg))
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    until_called(&calls, "/sm-contexts/dereg-922-live/release").await;
    assert!(
        server.sbi_offload.key_busy((ue, 1)),
        "the blackholed release still runs: it is durable"
    );
}

// ---- #1086 review: the join deadline and the connection-ended guard ----

/// The upCnxStates the slow stand-in SMF saw for `sm_ref`, waiting (up to 5 s)
/// until there are `n` of them. Off-task outcomes are applied meanwhile, as `poll`
/// does: that is what starts the next job queued for a key.
async fn up_cnx_states_of(
    server: &mut NgapServer,
    seen: &Arc<std::sync::Mutex<Vec<(String, String, Instant)>>>,
    sm_ref: &str,
    n: usize,
) -> Vec<String> {
    let states = || -> Vec<String> {
        seen.lock()
            .expect("seen")
            .iter()
            .filter(|(r, _, _)| r == sm_ref)
            .map(|(_, s, _)| s.clone())
            .collect()
    };
    for _ in 0..500 {
        if states().len() >= n {
            break;
        }
        server.process_sbi_outcomes().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    states()
}

/// Apply outcomes until the only join left waits for just `psi` (up to 3 s).
async fn until_join_waits_only_for(server: &mut NgapServer, psi: u8) {
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        if server
            .smf_joins
            .values()
            .all(|j| j.waiting.len() == 1 && j.waiting.contains(&psi))
            && !server.smf_joins.is_empty()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the join never narrowed to PSI {psi}");
}

/// A CM-IDLE UE holding PSI 5 at `fast` and PSI 6 at `slow`, and the protected
/// Service Request (Initial UE Message) that re-activates both.
fn idle_ue_with_two_sessions(
    server: &mut NgapServer,
    old: u64,
    new: u64,
    fast: u16,
    slow: u16,
    refs: (&str, &str),
) -> Vec<u8> {
    let mut ue = idle_registered_ue(old);
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    server.ue_auth_state.insert(old, ue);
    hold_session(server, old, 5, refs.0, fast);
    hold_session(server, old, 6, refs.1, slow);
    server.forced_amf_ue_ngap_id = Some(new);
    let tmsi = old as u32;
    // Data (1); uplink data status and PDU session status: PSI 5 and 6.
    let mut inner = vec![0x7E, 0x00, 0x4C, 0x10, 0x00, 0x07, 0xF4, 0x55, 0x6A];
    inner.extend_from_slice(&tmsi.to_be_bytes());
    inner.extend_from_slice(&[0x40, 0x02, 0x60, 0x00, 0x50, 0x02, 0x60, 0x00]);
    let mut nas = protected_service_request([0; 4], tmsi);
    nas.extend_from_slice(&[0x71, 0x00, inner.len() as u8]);
    nas.extend_from_slice(&inner);
    service_request_initial_ue(nas)
}

/// TS 23.502 §4.2.3.2, CM-IDLE, at the join deadline: PSI 5's SMF answered and
/// PSI 6's had not. The ICS carries PSI 5 only, and PSI 6's ACTIVATING, which then
/// succeeds late, is rolled back (DEACTIVATED, after it on its key). Otherwise the
/// SMF would wait in ACTIVATING for a setup that never comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_service_requests_unanswered_activation_is_rolled_back_at_the_deadline() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(800)).await;
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_311u64, 7_922_312u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-dl-fast", "isr-dl-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    until_join_waits_only_for(&mut server, 6).await;

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let ics: Vec<_> = take_sent_ngap(&mut server)
        .into_iter()
        .filter(|(_, p)| decode_sent(p) == Sent::Other(Some(14)))
        .collect();
    assert_eq!(ics.len(), 1, "the ICS goes at the deadline");
    assert!(server.up_active.contains(&(new, 5)), "with PSI 5");
    assert!(!server.up_active.contains(&(new, 6)), "without PSI 6");
    assert_eq!(
        up_cnx_states_of(&mut server, &seen, "isr-dl-slow", 2).await,
        vec!["ACTIVATING", "DEACTIVATED"],
        "the late ACTIVATING is rolled back"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

/// TS 23.502 §4.2.3.2, CM-CONNECTED, at the join deadline: the setup with the
/// Service Accept carries the answered PSI 5, and PSI 6's late ACTIVATING is
/// rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_requests_unanswered_activation_is_rolled_back_at_the_deadline() {
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(800)).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_211u64, 131u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "csr-dl-fast", fast_port);
    hold_session(&mut server, ue, 6, "csr-dl-slow", slow_port);
    let sr = ue_protect(&service_request(Some((1 << 5) | (1 << 6))), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &sr))
        .await
        .expect("handled");
    until_join_waits_only_for(&mut server, 6).await;

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<(u64, Sent)> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(a, p)| (a, decode_sent(&p)))
        .collect();
    let setups: Vec<&Sent> = concerns(&sent, ue)
        .into_iter()
        .filter(|s| matches!(s, Sent::SetupRequest { .. }))
        .collect();
    let [Sent::SetupRequest { items, nas_pdu, .. }] = setups[..] else {
        panic!("one setup request at the deadline: {sent:?}");
    };
    assert_eq!(items, &vec![setup_item(5, transfer_for("csr-dl-fast"))]);
    assert_protected_service_accept(nas_pdu.as_deref().expect("the Accept rides it"));
    assert_eq!(
        up_cnx_states_of(&mut server, &seen, "csr-dl-slow", 2).await,
        vec!["ACTIVATING", "DEACTIVATED"],
        "the late ACTIVATING is rolled back"
    );
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.6 during a CM-IDLE Service Request's join: the gNB releases the
/// UE's new connection before the SMF answers. When the ACTIVATING's answer
/// arrives, no Initial Context Setup goes to the released connection, and the
/// activation is rolled back. The SMF ends DEACTIVATED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_an_release_during_the_join_sends_no_initial_context_setup() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    // #1588: this test reads the paging strategy.
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(400)).await;
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_321u64, 7_922_322u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-an-fast", "isr-an-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    // The AN release lands while the join waits.
    server
        .handle_ue_context_release_complete(1, &release_complete_pdu(new, Some(512)))
        .await
        .expect("handled");
    assert!(server.ue_auth_state.get(new).expect("ue").is_cm_idle());
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        if server.smf_joins.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(server.smf_joins.is_empty(), "both answers came in");
    assert!(
        !take_sent_ngap(&mut server)
            .iter()
            .any(|(_, p)| decode_sent(p) == Sent::Other(Some(14))),
        "no ICS to the released connection"
    );
    assert!(server.up_active.is_empty() || !server.up_active.contains(&(new, 5)));
    let states = up_cnx_states_of(&mut server, &seen, "isr-an-slow", 3).await;
    assert_eq!(
        states.last().map(String::as_str),
        Some("DEACTIVATED"),
        "the SMF ends DEACTIVATED: {states:?}"
    );
    assert!(
        states.len() >= 3,
        "the AN release's DEACTIVATED and the roll-back both follow the ACTIVATING: \
         {states:?}"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

// ---------------------------------------------------------------------------
// #922 part 3: the N2 SM relays, the Path Switch, the Modify Indication and the
// registration update's sessions
// ---------------------------------------------------------------------------

/// The PDU sessions a PDU SESSION RESOURCE MODIFY CONFIRM reports failed, or `None`
/// when `pdu` is not a Modify Confirm.
fn modify_confirm_failed_psis(pdu: &[u8]) -> Option<Vec<u8>> {
    use g::PDUSessionResourceModifyConfirmProtocolIEs_EntryValue as Ie;
    use nextgcore_ngap_gen::generated as g;
    let Ok(g::NGAP_PDU::SuccessfulOutcome(out)) = nextgcore_ngap_gen::decode(pdu) else {
        return None;
    };
    let g::SuccessfulOutcomeValue::Id_PDUSessionResourceModifyIndication(confirm) = out.value
    else {
        return None;
    };
    let mut failed = Vec::new();
    for e in confirm.protocol_i_es.0 {
        if let Ie::Id_PDUSessionResourceFailedToModifyListModCfm(l) = e.value {
            failed.extend(l.0.into_iter().map(|i| i.pdu_session_id.0));
        }
    }
    Some(failed)
}

/// TS 23.502 §4.9.1.2.2 steps 2-7: a PATH SWITCH REQUEST whose session is held at a
/// blackholed SMF does not hold the NGAP task. Another UE's Path Switch is acknowledged
/// meanwhile. The first is answered only when the AMF stops waiting: nothing was
/// switched, so a PATH SWITCH REQUEST FAILURE (TS 38.413 §8.4.4.3), and the UE stays on
/// its source.
///
/// REVERT-VERIFIED: with the Update SM Context awaited on the NGAP task, the handler
/// takes the connect timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_switch_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, _calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_923_001u64, 97_923_002u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let (dead, live) = (7_923_011u64, 7_923_012u64);
    for (ue, ran) in [(dead, 31u32), (live, 32)] {
        let mut state = UeNasContext::new(ue, ran, source, false);
        state.registered = true;
        server.ue_auth_state.insert(ue, state);
    }
    hold_blackholed(&mut server, dead, 5, "ps922-dead-5");
    hold_session(&mut server, live, 5, "ps922-live-5", port);

    let started = Instant::now();
    for (ue, ran) in [(dead, 41u32), (live, 42)] {
        server
            .handle_path_switch_request(target, &path_switch_request_pdu(ue, ran, &[5]))
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    // The answered UE is acknowledged and moved to the target.
    let mut acks = Vec::new();
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        acks.extend(take_sent_ngap(&mut server));
        if !acks.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(acks.len(), 1, "{acks:?}");
    let (switched, _) = decoded_path_switch_ack(&acks[0].1).expect("an Acknowledge");
    assert_eq!(switched, vec![(5, transfer_for("ps922-live-5"))]);
    assert_eq!(
        server.ue_auth_state.get(live).expect("UE").association_id,
        target
    );
    // The blackholed one: nothing yet, and still on its source.
    assert_eq!(
        server.ue_auth_state.get(dead).expect("UE").association_id,
        source
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (amf, ran, released) =
        decoded_path_switch_failure(&sent[0].1).expect("a PATH SWITCH REQUEST FAILURE");
    assert_eq!((amf, ran, released.len()), (dead, 41, 1));
    assert_eq!(
        server.ue_auth_state.get(dead).expect("UE").association_id,
        source
    );
    forget_amf_sessions(dead);
    forget_amf_sessions(live);
    server.forget_ue(dead);
    server.forget_ue(live);
}

/// TS 38.413 §8.2.4: a PDU SESSION RESOURCE MODIFY INDICATION for a session at a
/// blackholed SMF does not hold the NGAP task, and its Modify Confirm waits for the
/// SMF. When the AMF stops waiting, the session is reported failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modify_indication_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_021u64, 51u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 5, "mi922-dead-5");
    let indication = crate::ngap_asn1::tests::modify_indication_bytes(ue, ran, &[(5, vec![0x51])]);

    let started = Instant::now();
    server
        .handle_pdu_session_resource_modify_indication(ASSOC, &indication)
        .await
        .expect("handled");
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    server.process_sbi_outcomes().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Confirm before the SMF answers"
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, ASSOC);
    assert_eq!(modify_confirm_failed_psis(&sent[0].1), Some(vec![5]));
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.2.2.2 step 21: a connected UE's registration update re-activating a
/// session at a blackholed SMF does not hold the NGAP task, and the Accept waits for
/// the SMF. When the AMF stops waiting, the Accept goes on its own, reporting the
/// re-activation failed (TS 24.501 §8.2.7.15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_update_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    // #1974: this test resolves the AUSF (process-global endpoint).
    let _ausf = crate::test_support::AUSF_ENV_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_031u64, 61u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "ru922-dead-1");
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            Some(1 << 1),
            None,
        ),
        0,
    );

    let started = Instant::now();
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    server.process_sbi_outcomes().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Accept before the SMF answers"
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = sent.as_slice() else {
        panic!("a standalone Accept: {sent:?}");
    };
    let accept = registration_accept_of(nas_pdu);
    assert_eq!(accept.pdu_session_reactivation_result, Some(1 << 1));
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// The N2 SM containers nothing waits for -- a Setup Response's failed session, a
/// Notify's notified and released sessions -- are relayed off the NGAP task: against
/// a blackholed SMF the handlers return at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n2_sm_relays_to_a_blackholed_smf_do_not_hold_the_ngap_task() {
    use nextgcore_ngap::types as t;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_041u64, 71u32);
    secured_registered_ue(&mut server, ue, ran);
    for psi in [1u8, 2, 3] {
        hold_blackholed(&mut server, ue, psi, &format!("relay922-{psi}"));
    }
    let setup =
        crate::gnb_pdus::pdu_session_resource_setup_response(&t::PduSessionResourceSetupResponse {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            setup_list: vec![],
            failed_list: vec![t::PduSessionResourceFailedItem {
                pdu_session_id: 1,
                transfer: vec![0x11],
            }],
        });
    let notify = crate::gnb_pdus::pdu_session_resource_notify(&t::PduSessionResourceNotify {
        amf_ue_ngap_id: ue,
        ran_ue_ngap_id: ran,
        notify_list: vec![t::PduSessionResourceNotifyItem {
            pdu_session_id: 2,
            transfer: vec![0x21],
        }],
        released_list: vec![t::PduSessionResourceReleasedItem {
            pdu_session_id: 3,
            transfer: vec![0x31],
        }],
    });

    let started = Instant::now();
    server
        .handle_pdu_session_resource_setup_response(ASSOC, &setup)
        .await
        .expect("handled");
    server
        .handle_pdu_session_resource_notify(ASSOC, &notify)
        .await
        .expect("handled");
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    assert!(
        (1..=3).all(|psi| server.sbi_offload.key_busy((ue, psi))),
        "each relay is queued on its session"
    );
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review M1/M2: a UE whose NG connection is released (CM-IDLE) while its
/// registration update waits for the SMFs gets no Accept on the released connection
/// at the deadline, and the session its SMF did activate is rolled back (DEACTIVATED).
///
/// REVERT-VERIFIED: without the CM-IDLE check in `finish_registration_update`, the
/// Accept goes out in a setup request on the released connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_update_released_during_its_join_sends_no_accept() {
    // #1974: this test resolves the AUSF (process-global endpoint).
    let _ausf = crate::test_support::AUSF_ENV_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_051u64, 81u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "ru922-live-1", port);
    hold_blackholed(&mut server, ue, 2, "ru922-dead-2");
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            Some((1 << 1) | (1 << 2)),
            None,
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    until_called(&calls, "/sm-contexts/ru922-live-1/modify").await;
    until_join_waits_only_for(&mut server, 2).await;

    // AN release: the UE is CM-IDLE, on the same association and RAN UE NGAP ID.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Accept on the released connection"
    );
    // PSI 2's calls hang at the blackhole, so wait for PSI 1's roll-back itself.
    let states = || -> Vec<String> {
        calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|(u, _)| u.ends_with("/sm-contexts/ru922-live-1/modify"))
            .map(|(_, b)| b["upCnxState"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    for _ in 0..300 {
        if states().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(states(), vec!["ACTIVATING", "DEACTIVATED"], "rolled back");
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review M2: a UE that goes CM-IDLE while its PATH SWITCH REQUEST waits for the
/// SMFs is not moved to the target: at the deadline the target gets a PATH SWITCH
/// REQUEST FAILURE, even though one session was switched.
///
/// REVERT-VERIFIED: without the CM-IDLE filter in `finish_path_switch`, an Acknowledge
/// goes out and the UE is relocated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_switch_whose_ue_goes_idle_during_its_join_is_failed() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_923_011u64, 97_923_012u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let ue = 7_923_061u64;
    let mut state = UeNasContext::new(ue, 33, source, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "ps922-idle-5", port);
    hold_blackholed(&mut server, ue, 6, "ps922-idle-6");
    server
        .handle_path_switch_request(target, &path_switch_request_pdu(ue, 43, &[5, 6]))
        .await
        .expect("handled");
    for _ in 0..300 {
        if !calls.lock().expect("calls").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until_join_waits_only_for(&mut server, 6).await;

    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(
        decoded_path_switch_failure(&sent[0].1).is_some(),
        "a PATH SWITCH REQUEST FAILURE, not an Acknowledge"
    );
    assert_eq!(
        server.ue_auth_state.get(ue).expect("UE").association_id,
        source
    );
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review m1, TS 24.501 §5.5.1.3.8 e): a REGISTRATION REQUEST repeated with the
/// same IEs while the first one's Accept waits for the SMF is not treated further (the
/// first procedure goes on, one join); one with different IEs aborts the first and is
/// progressed (a new join, the old one gone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_registration_request_during_the_join_follows_5_5_1_3_8_e() {
    // #1974: this test resolves the AUSF (process-global endpoint).
    let _ausf = crate::test_support::AUSF_ENV_LOCK.lock().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_071u64, 91u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "ru922-rep-1");
    hold_blackholed(&mut server, ue, 2, "ru922-rep-2");
    let request = |uds: u16, pss: Option<u16>, count: u8| {
        ue_protect(
            &update_registration_request(
                crate::gmm_build::registration_type::PERIODIC_UPDATING,
                Some(uds),
                pss,
            ),
            count,
        )
    };
    let joins = |server: &NgapServer| -> Vec<u64> {
        let mut ids: Vec<u64> = server
            .smf_joins
            .iter()
            .filter(|(_, j)| j.amf_ue_ngap_id == ue)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    };

    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request(1 << 1, None, 0)),
        )
        .await;
    let first = joins(&server);
    assert_eq!(first.len(), 1, "the first request waits for its SMF");

    // The same IEs again: the first procedure goes on.
    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request(1 << 1, None, 1)),
        )
        .await;
    assert_eq!(joins(&server), first, "not treated further");

    // Different IEs: the first is aborted, this one progressed.
    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request((1 << 1) | (1 << 2), None, 2)),
        )
        .await;
    let second = joins(&server);
    assert_eq!(second.len(), 1, "{second:?}");
    assert_ne!(second, first, "the first join is gone, a new one waits");
    assert!(take_sent_ngap(&mut server).is_empty(), "no Accept yet");
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1674 (the #1670 review): the N1N2 delivery backstop refuses an over-long N1 at
/// the builder and says so, rather than reaching `protect_nas` with an empty
/// message and logging a missing security context. Nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_long_n1n2_delivery_is_refused_with_an_accurate_log_1674() {
    nextgcore_core::test_log::init();
    let mut server = capturing_ngap_server().await;
    let ue = 16_740_301;
    secured_registered_ue(&mut server, ue, 231);
    let said = nextgcore_core::test_log::watch(format!(
        "UE {ue}: N1 message for PSI Some(5) of 65536 bytes not sent: longer than a payload"
    ));
    let n1 = vec![0x2E; crate::gmm_build::MAX_PAYLOAD_CONTAINER_LEN + 1];
    server
        .deliver_n1_n2(
            ASSOC,
            ue,
            231,
            Some(5),
            false,
            Some(&n1),
            payload_container_type::N1_SM_INFORMATION,
        )
        .await
        .expect("delivered");
    assert_eq!(said.records().len(), 1, "the refusal says why");
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "and nothing is sent"
    );
    server.forget_ue(ue);
}

/// **#1645** (the R5 #1624 round-3 MINOR, and the #1695 review's MINOR c): a release
/// that ends an idle Service Request's connection before its SMF answers came back
/// (so before the CONNECTED report), by a UE Context Release Complete or by an NG
/// Reset, tells a subscriber that last heard IDLE nothing: never IDLE with no
/// CONNECTED before it. A subscriber created during that connection, whose immediate
/// report said CONNECTED, hears IDLE, so it does not stay at CONNECTED. Positive
/// control: the next Service Request, with no session to wait for, reports CONNECTED
/// to both, and its release IDLE to both. Counted as deliveries past the
/// per-subscription change gate on the test's own thread, and read at real sinks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_before_the_connected_report_reports_no_idle_1645() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _guami = ServeOneGuami::install();
    let delivered = crate::namf_server::connectivity_deliveries_on_this_thread;
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, _seen) = slow_up_cnx_smf(Duration::from_millis(400)).await;
    /// Subscribe with the immediateFlag; the guard and the immediate report's CM state.
    async fn subscribe(
        supi: &str,
        port: u16,
    ) -> (crate::namf_server::EventSubscriptionGuard, String) {
        let resp = crate::namf_server::test_namf_request_handler(
            nextgcore_sbi::SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&serde_json::json!({ "subscription": {
                    "eventList": [{ "type": "CONNECTIVITY_STATE_REPORT", "immediateFlag": true }],
                    "eventNotifyUri": format!("http://127.0.0.1:{port}/notify/1645"),
                    "notifyCorrelationId": "corr-1645",
                    "nfId": "3fa85f64-5717-4562-b3fc-2c963f661645",
                    "supi": supi,
                }}))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).expect("JSON");
        let state = v["reportList"][0]["cmInfoList"][0]["cmState"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (crate::namf_server::EventSubscriptionGuard::of(&resp), state)
    }
    async fn next_cm_state(rx: &mut tokio::sync::mpsc::Receiver<String>) -> String {
        let body = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a CONNECTIVITY_STATE_REPORT")
            .expect("channel open");
        let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        v["reportList"][0]["cmInfoList"][0]["cmState"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
    for (i, by_reset) in [false, true].into_iter().enumerate() {
        let mut server = capturing_ngap_server().await;
        seed_gnb_session(&server, 1).await;
        let base = 16_450_001u64 + 10 * i as u64;
        let (old, new, next) = (base, base + 1, base + 2);
        let supi = format!("imsi-00101001645{:04}", base % 10_000);
        let pdu = idle_ue_with_two_sessions(
            &mut server,
            old,
            new,
            fast_port,
            slow_port,
            (&format!("isr-1645-fast-{i}"), &format!("isr-1645-slow-{i}")),
        );
        server
            .ue_auth_state
            .with_mut(old, |s| s.amf_ue.supi = Some(supi.clone()));
        // A: subscribed while the UE is idle; its immediate report says IDLE.
        let (sink_a, port_a, mut rx_a) = super::notify_sink().await;
        let (sub_a, first_a) = subscribe(&supi, port_a).await;
        assert_eq!(first_a, "IDLE", "A's immediate report");

        server
            .handle_initial_ue_message(1, &pdu)
            .await
            .expect("handled");
        // B: subscribed while the Service Request waits for its SMFs; its immediate
        // report says CONNECTED.
        let (sink_b, port_b, mut rx_b) = super::notify_sink().await;
        let (sub_b, first_b) = subscribe(&supi, port_b).await;
        assert_eq!(first_b, "CONNECTED", "B's immediate report");

        // The connection ends while the join waits.
        let d0 = delivered();
        if by_reset {
            // A partial reset naming this UE alone: the UE store is process-global,
            // and a whole-interface reset of association 1 would idle every sibling
            // test's UE on it too.
            let item = nextgcore_ngap::types::UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: Some(new),
                ran_ue_ngap_id: None,
            };
            server
                .handle_ng_reset(
                    1,
                    &ng_reset_pdu(nextgcore_ngap::types::ResetType::PartOfNgInterface(vec![
                        item,
                    ])),
                )
                .await
                .expect("handled");
        } else {
            server
                .handle_ue_context_release_complete(1, &release_complete_pdu(new, Some(512)))
                .await
                .expect("handled");
        }
        // Review M1: waited on the joins' state against a generous deadline, not a
        // fixed number of short sleeps, so a loaded host does not fail it.
        let deadline = Instant::now() + Duration::from_secs(15);
        while !server.smf_joins.is_empty() && Instant::now() < deadline {
            server.process_sbi_outcomes().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            server.smf_joins.is_empty(),
            "reset={by_reset}: both answers came in"
        );
        assert!(server.ue_auth_state.get(new).expect("ue").is_cm_idle());
        assert_eq!(
            delivered() - d0,
            1,
            "reset={by_reset}: IDLE to B only; A last heard IDLE"
        );
        assert_eq!(
            next_cm_state(&mut rx_b).await,
            "IDLE",
            "reset={by_reset}: B hears IDLE"
        );

        // Positive control: back with a Service Request that waits for no session.
        server.forget_ue_sessions(new);
        server.forced_amf_ue_ngap_id = Some(next);
        let d0 = delivered();
        server
            .handle_initial_ue_message(
                1,
                &service_request_initial_ue(protected_service_request([0; 4], old as u32)),
            )
            .await
            .expect("handled");
        assert_eq!(delivered() - d0, 2, "reset={by_reset}: CONNECTED to both");
        // Each notification is its own spawned POST: read before the next is fired,
        // so the order at the sink is the order fired.
        assert_eq!(next_cm_state(&mut rx_a).await, "CONNECTED");
        let d0 = delivered();
        server
            .handle_ue_context_release_complete(1, &release_complete_pdu(next, Some(512)))
            .await
            .expect("handled");
        assert_eq!(delivered() - d0, 2, "reset={by_reset}: and IDLE to both");
        assert_eq!(next_cm_state(&mut rx_a).await, "IDLE");
        server.forced_amf_ue_ngap_id = None;
        server.forget_ue(next);
        drop((sub_a, sub_b));
        sink_a.stop().await.expect("sink stop");
        sink_b.stop().await.expect("sink stop");
    }
}

/// **#1924.** An NG Reset that supersedes a Service Request's SMF activations
/// before they started (they were still waiting for a permit) resolves the join
/// that waited on them at once. Their outcomes never arrive, so before, the join
/// lingered until its deadline: the flake of
/// `a_release_before_the_connected_report_reports_no_idle_1645` under load, made
/// deterministic here with an offload that has no permits to give.
///
/// REVERT-VERIFIED: with `resolve_superseded_join_parts` not called from the NG
/// Reset handler, the join is still open and the assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_reset_that_supersedes_waiting_activations_closes_their_join_1924() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, _seen) = slow_up_cnx_smf(Duration::from_millis(400)).await;
    let mut server = capturing_ngap_server().await;
    // No permits: every offloaded exchange waits, as under heavy load.
    server.sbi_offload = crate::sbi_offload::SbiOffload::new(0);
    seed_gnb_session(&server, 1).await;
    let (old, new) = (19_240_001u64, 19_240_002u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-1924-fast", "isr-1924-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    assert_eq!(
        server.smf_joins.len(),
        1,
        "the join waits for both activations"
    );

    let item = nextgcore_ngap::types::UeAssociatedLogicalNgConnectionItem {
        amf_ue_ngap_id: Some(new),
        ran_ue_ngap_id: None,
    };
    server
        .handle_ng_reset(
            1,
            &ng_reset_pdu(nextgcore_ngap::types::ResetType::PartOfNgInterface(vec![
                item,
            ])),
        )
        .await
        .expect("handled");
    assert!(
        server.smf_joins.is_empty(),
        "the superseded activations will never answer: their join is closed now"
    );
    assert!(server.ue_auth_state.get(new).expect("ue").is_cm_idle());
    server.forget_ue(new);
}

/// **#1924 (R31 M1).** The other NG-release caller: an SCTP association lost
/// (restart, closure, or NG Setup without retention, TS 38.413 §8.7.1.1)
/// during an idle Service Request releases the UE's NG connection as an NG
/// Reset does, superseding the activations still waiting for a permit. Their
/// join is closed straight away, not after `SMF_JOIN_MAX_WAIT`.
///
/// REVERT-VERIFIED: with `resolve_superseded_join_parts` dropped from
/// `reset_ue_associations_of`, the join is still open and this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_association_loss_that_supersedes_waiting_activations_closes_their_join_1924() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    let _strategy = crate::test_support::PAGING_STRATEGY_LOCK.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, _seen) = slow_up_cnx_smf(Duration::from_millis(400)).await;
    let mut server = capturing_ngap_server().await;
    // No permits: every offloaded exchange waits, as under heavy load.
    server.sbi_offload = crate::sbi_offload::SbiOffload::new(0);
    seed_gnb_session(&server, 1).await;
    let (old, new) = (19_240_011u64, 19_240_012u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-1924-assoc-fast", "isr-1924-assoc-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    assert_eq!(
        server.smf_joins.len(),
        1,
        "the join waits for both activations"
    );

    server
        .reset_ue_associations_of(1, "SCTP association lost (test)")
        .await;
    assert!(
        server.smf_joins.is_empty(),
        "the superseded activations will never answer: their join is closed now"
    );
    assert!(server.ue_auth_state.get(new).expect("ue").is_cm_idle());
    server.forget_ue(new);
}
