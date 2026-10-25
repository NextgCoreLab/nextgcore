//! Handler-level tests that assert what amfd SENDS (#760).
//!
//! A child of `ngap_path::tests`, so it reaches `NgapServer`'s private state and
//! handlers, and the shared capture helpers (`capturing_ngap_server`,
//! `take_sent_ngap`). Each test drives a real handler entry point (for example
//! the Uplink NAS Transport dispatch), with the NGAP egress captured by the
//! `sent_ngap` seam and N11 answered by a stand-in SMF on loopback. It then
//! decodes the captured PDUs with the generated NGAP codec.

use super::*;
use base64::Engine as _;
use nextgcore_ngap_gen::generated as g;

/// The association every UE in this module is served on.
pub(super) const ASSOC: u64 = 1;

/// The NAS keys every UE here shares with "its" UE side: NIA2 integrity, NEA0.
const KNAS_INT: [u8; 16] = [0x11; 16];

/// A registered UE with an established NAS security context, CM-CONNECTED on
/// [`ASSOC`] as `ran_ue_ngap_id`.
pub(super) fn secured_registered_ue(
    server: &mut NgapServer,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
) {
    // The global context holds the UE's sessions (`sess_list`).
    crate::context::amf_context_init(64, 1024, 4096);
    let mut ue = UeNasContext::new(amf_ue_ngap_id, ran_ue_ngap_id, ASSOC, false);
    ue.registered = true;
    ue.amf_ue.security_context_available = true;
    ue.amf_ue.selected_int_algorithm = 2;
    ue.amf_ue.selected_enc_algorithm = 0;
    ue.amf_ue.knas_int = KNAS_INT;
    ue.amf_ue.access_type = ACCESS_TYPE_3GPP;
    server.ue_auth_state.insert(amf_ue_ngap_id, ue);
}

/// Integrity-protect `inner` as the UE would, with uplink NAS COUNT `count`
/// (TS 24.501 §9.1: EPD, security header, MAC, SQN, plain message).
pub(super) fn ue_protect(inner: &[u8], count: u8) -> Vec<u8> {
    let mut mac_data = vec![count];
    mac_data.extend_from_slice(inner);
    let mac = nas_security::nas_mac_calculate(
        2,
        &KNAS_INT,
        u32::from(count),
        ACCESS_TYPE_3GPP,
        nas_security::direction::UPLINK,
        &mac_data,
    );
    let mut out = vec![0x7E, security_header::INTEGRITY_PROTECTED];
    out.extend_from_slice(&mac);
    out.push(count);
    out.extend_from_slice(inner);
    out
}

/// An APER Uplink NAS Transport carrying `nas`.
pub(super) fn uplink_nas_transport(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    nas: &[u8],
) -> Vec<u8> {
    nextgcore_ngap::builder::build_uplink_nas_transport(
        &nextgcore_ngap::types::UplinkNasTransport {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            nas_pdu: nas.to_vec(),
            user_location_info: nextgcore_ngap::types::UserLocationInformation::Nr {
                nr_cgi_plmn: [0x00, 0xF1, 0x10],
                nr_cell_identity: 1,
                tai_plmn: [0x00, 0xF1, 0x10],
                tai_tac: [0x00, 0x00, 0x01],
            },
        },
    )
    .expect("encode an Uplink NAS Transport")
}

/// A plain SERVICE REQUEST (TS 24.501 §8.2.16), service type "data", with an
/// Uplink data status (IEI 0x40) naming the PSIs in `uplink_psis` when given.
pub(super) fn service_request(uplink_psis: Option<u16>) -> Vec<u8> {
    let mut sr = vec![
        0x7E,
        security_header::PLAIN_NAS_MESSAGE,
        message_type::SERVICE_REQUEST,
        0x10, // service type 1 (data) high nibble, ngKSI 0 low nibble
        0x00,
        0x07,
        0xF4, // 5G-S-TMSI
        0x01,
        0x01,
        0x11,
        0x22,
        0x33,
        0x44,
    ];
    if let Some(bitmap) = uplink_psis {
        // §9.11.3.57: octet 3 carries PSI 7..0, octet 4 PSI 15..8.
        sr.extend_from_slice(&[0x40, 0x02, bitmap as u8, (bitmap >> 8) as u8]);
    }
    sr
}

/// One request a stand-in SMF saw: `(uri, json body)`.
pub(super) type SmfCall = (String, serde_json::Value);

/// A stand-in SMF: records every request, and answers an `upCnxState: ACTIVATING`
/// update for any ref except `fail-*` with 200 and `n2SmInfo` = `transfer_for(ref)`.
/// A `fail-*` ref gets 500. A CreateSMContext gets 201 with SM context `est-<psi>`.
/// Everything else gets 204. Keep the server alive.
pub(super) async fn activating_smf() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<std::sync::Mutex<Vec<SmfCall>>>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    // Plain h2c loopback: the client must dial it under the dev profile (#586).
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let seen: Arc<std::sync::Mutex<Vec<SmfCall>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
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
                sink.lock().expect("sink").push((uri.clone(), body.clone()));
                let sm_ref = uri
                    .split("/sm-contexts/")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .unwrap_or_default()
                    .to_string();
                // #756: a CreateSMContext (POST .../sm-contexts) is answered 201 with
                // SM context `est-<psi>`, a recognisable N1 and an N2 transfer.
                if uri.ends_with("/nsmf-pdusession/v1/sm-contexts") {
                    let psi = body["pduSessionId"].as_u64().unwrap_or_default();
                    let created = serde_json::json!({
                        "smContextRef": format!("est-{psi}"),
                        "n1SmMsg": base64::engine::general_purpose::STANDARD
                            .encode([0x2E, psi as u8, 0x01, 0xC2]),
                        "n2SmInfo": base64::engine::general_purpose::STANDARD
                            .encode(transfer_for(&format!("est-{psi}"))),
                    });
                    return SResp::with_status(201)
                        .with_body(created.to_string(), "application/json");
                }
                if body["upCnxState"] != "ACTIVATING" {
                    return SResp::no_content();
                }
                if sm_ref.starts_with("fail-") {
                    return SResp::with_status(500);
                }
                let answer = serde_json::json!({
                    "upCnxState": "ACTIVATING",
                    "n2SmInfoType": "PDU_RES_SETUP_REQ",
                    "n2SmInfo": base64::engine::general_purpose::STANDARD
                        .encode(transfer_for(&sm_ref)),
                });
                SResp::with_status(200).with_body(answer.to_string(), "application/json")
            }
        })
        .await
        .expect("stand-in SMF starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (server, addr.port(), seen)
}

/// The N2 SM information the stand-in SMF answers for `sm_ref`: recognisable
/// octets, so a test can find exactly that session's transfer on the wire.
pub(super) fn transfer_for(sm_ref: &str) -> Vec<u8> {
    let mut t = vec![0x00, 0x03];
    t.extend_from_slice(sm_ref.as_bytes());
    t
}

/// The S-NSSAI every held session here is on, as (SST, SD).
pub(super) const SLICE: (u8, Option<u32>) = (1, Some(0x0A_0B_0C));

/// Give `amf_ue_ngap_id` an SM context for `psi` held at the stand-in SMF.
pub(super) fn hold_session(
    server: &mut NgapServer,
    amf_ue_ngap_id: u64,
    psi: u8,
    sm_ref: &str,
    smf_port: u16,
) {
    record_amf_session(amf_ue_ngap_id, psi, sm_ref, SLICE.0, SLICE.1);
    server
        .sm_context_refs
        .insert((amf_ue_ngap_id, psi), sm_ref.to_string());
    server
        .sm_context_smfs
        .insert((amf_ue_ngap_id, psi), ("127.0.0.1".to_string(), smf_port));
}

/// One PDU SESSION RESOURCE SETUP REQUEST item: PSI, S-NSSAI (SST, SD), transfer.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SetupItem {
    pub psi: u8,
    pub sst: u8,
    pub sd: Option<u32>,
    pub transfer: Vec<u8>,
}

/// A decoded outbound NGAP PDU, reduced to what the tests here assert on.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Sent {
    /// PDU SESSION RESOURCE SETUP REQUEST: message-level NAS-PDU, and per item
    /// `(psi, transfer)`.
    SetupRequest {
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas_pdu: Option<Vec<u8>>,
        items: Vec<SetupItem>,
    },
    /// PDU SESSION RESOURCE MODIFY REQUEST: per item `(psi, nas, transfer)`.
    ModifyRequest {
        amf_ue_ngap_id: u64,
        items: Vec<(u8, Option<Vec<u8>>, Vec<u8>)>,
    },
    /// PDU SESSION RESOURCE RELEASE COMMAND: the PSIs.
    ReleaseCommand { amf_ue_ngap_id: u64, psis: Vec<u8> },
    /// DOWNLINK NAS TRANSPORT: the NAS-PDU.
    DownlinkNas {
        amf_ue_ngap_id: u64,
        nas_pdu: Vec<u8>,
    },
    /// ERROR INDICATION, with its cause when it has a radio-network one.
    ErrorIndication { radio_network_cause: Option<u8> },
    /// Anything else: the initiating procedure code, or `None` if not initiating.
    Other(Option<u16>),
}

/// Decode one captured PDU.
pub(super) fn decode_sent(pdu: &[u8]) -> Sent {
    let Ok(g::NGAP_PDU::InitiatingMessage(m)) = nextgcore_ngap_gen::decode(pdu) else {
        return Sent::Other(None);
    };
    let code = m.procedure_code.0 as u16;
    match m.value {
        g::InitiatingMessageValue::Id_PDUSessionResourceSetup(req) => {
            let (mut amf, mut ran, mut nas, mut items) = (0, 0, None, Vec::new());
            for ie in req.protocol_i_es.0 {
                match ie.value {
                    g::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                        id,
                    ) => amf = id.0,
                    g::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(
                        id,
                    ) => ran = id.0,
                    g::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_NAS_PDU(n) => {
                        nas = Some(n.0)
                    }
                    g::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSUReq(l) => {
                        for it in l.0 {
                            items.push(SetupItem {
                                psi: it.pdu_session_id.0,
                                sst: it.s_nssai.sst.0.first().copied().unwrap_or_default(),
                                sd: it.s_nssai.sd.map(|sd| {
                                    sd.0.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
                                }),
                                transfer: it.pdu_session_resource_setup_request_transfer.0,
                            });
                        }
                    }
                    _ => {}
                }
            }
            Sent::SetupRequest {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                nas_pdu: nas,
                items,
            }
        }
        g::InitiatingMessageValue::Id_PDUSessionResourceModify(req) => {
            let (mut amf, mut items) = (0, Vec::new());
            for ie in req.protocol_i_es.0 {
                match ie.value {
                    g::PDUSessionResourceModifyRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                        id,
                    ) => amf = id.0,
                    g::PDUSessionResourceModifyRequestProtocolIEs_EntryValue::Id_PDUSessionResourceModifyListModReq(l) => {
                        for it in l.0 {
                            items.push((
                                it.pdu_session_id.0,
                                it.nas_pdu.map(|n| n.0),
                                it.pdu_session_resource_modify_request_transfer.0,
                            ));
                        }
                    }
                    _ => {}
                }
            }
            Sent::ModifyRequest {
                amf_ue_ngap_id: amf,
                items,
            }
        }
        g::InitiatingMessageValue::Id_PDUSessionResourceRelease(cmd) => {
            let (mut amf, mut psis) = (0, Vec::new());
            for ie in cmd.protocol_i_es.0 {
                match ie.value {
                    g::PDUSessionResourceReleaseCommandProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                        id,
                    ) => amf = id.0,
                    g::PDUSessionResourceReleaseCommandProtocolIEs_EntryValue::Id_PDUSessionResourceToReleaseListRelCmd(l) => {
                        psis.extend(l.0.into_iter().map(|it| it.pdu_session_id.0))
                    }
                    _ => {}
                }
            }
            Sent::ReleaseCommand {
                amf_ue_ngap_id: amf,
                psis,
            }
        }
        g::InitiatingMessageValue::Id_DownlinkNASTransport(dl) => {
            let (mut amf, mut nas) = (0, Vec::new());
            for ie in dl.protocol_i_es.0 {
                match ie.value {
                    g::DownlinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                        amf = id.0
                    }
                    g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(n) => nas = n.0,
                    _ => {}
                }
            }
            Sent::DownlinkNas {
                amf_ue_ngap_id: amf,
                nas_pdu: nas,
            }
        }
        g::InitiatingMessageValue::Id_ErrorIndication(ei) => {
            let mut cause = None;
            for ie in ei.protocol_i_es.0 {
                if let g::ErrorIndicationProtocolIEs_EntryValue::Id_Cause(g::Cause::RadioNetwork(
                    c,
                )) = ie.value
                {
                    cause = Some(c.0);
                }
            }
            Sent::ErrorIndication {
                radio_network_cause: cause,
            }
        }
        _ => Sent::Other(Some(code)),
    }
}

/// A setup item for `psi` on [`SLICE`] carrying `transfer`.
pub(super) fn setup_item(psi: u8, transfer: Vec<u8>) -> SetupItem {
    SetupItem {
        psi,
        sst: SLICE.0,
        sd: SLICE.1,
        transfer,
    }
}

/// Assert `nas` is a SERVICE ACCEPT, integrity-protected and ciphered under the
/// UE's context (TS 24.501 §4.4.4: the UE discards an unprotected one), with a
/// MAC that verifies under [`KNAS_INT`] for its sequence number (NIA2, NEA0).
pub(super) fn assert_protected_service_accept(nas: &[u8]) {
    assert_eq!(
        nas.get(1),
        Some(&security_header::INTEGRITY_PROTECTED_AND_CIPHERED),
        "the Service Accept is protected: {nas:02x?}"
    );
    assert!(nas.len() > 9, "{nas:02x?}");
    let mac = nas_security::nas_mac_calculate(
        2,
        &KNAS_INT,
        u32::from(nas[6]),
        ACCESS_TYPE_3GPP,
        nas_security::direction::DOWNLINK,
        &nas[6..],
    );
    assert_eq!(&nas[2..6], &mac, "the downlink MAC verifies: {nas:02x?}");
    assert_eq!(
        dl_nas_message_type(nas),
        Some(message_type::SERVICE_ACCEPT),
        "{nas:02x?}"
    );
}

/// The plain 5GMM message type inside a downlink protected NAS PDU (NEA0, so
/// the plain message follows the 7-octet security header).
pub(super) fn dl_nas_message_type(protected: &[u8]) -> Option<u8> {
    match protected.get(1) {
        Some(&security_header::PLAIN_NAS_MESSAGE) => protected.get(2).copied(),
        Some(_) => protected.get(7 + 2).copied(),
        None => None,
    }
}

// ---------------------------------------------------------------------------
// #760: connected-mode Service Request (#683 user plane, #685 Accept-in-Setup)
// ---------------------------------------------------------------------------

/// The Service Request bytes this module builds are what the AMF's own parser
/// reads: Uplink data status PSI 1 and PSI 2.
#[test]
fn the_built_service_request_carries_the_uplink_data_status_it_names() {
    let ies = service_request_session_ies(&service_request(Some(0b110)), &|_| {});
    assert_eq!(ies.uplink_data_status, Some(0b110));
    let ies = service_request_session_ies(&service_request(None), &|_| {});
    assert_eq!(ies.uplink_data_status, None);
}

/// Drive a connected UE's protected Service Request through the Uplink NAS
/// Transport dispatch, and return the decoded NGAP it caused.
pub(super) async fn connected_service_request(
    server: &mut NgapServer,
    ue: u64,
    ran: u32,
    uplink_psis: Option<u16>,
) -> Vec<(u64, Sent)> {
    let sr = ue_protect(&service_request(uplink_psis), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &sr))
        .await
        .expect("the Service Request is handled");
    // #922: the re-activations run off the NGAP task; their answers are applied here.
    settle_offloaded_sbi(server).await;
    take_sent_ngap(server)
        .into_iter()
        .map(|(a, p)| (a, decode_sent(&p)))
        .collect()
}

/// The single standalone Accept in `sent`: exactly one PDU, a DL NAS Transport
/// to `ue` on [`ASSOC`] carrying a protected SERVICE ACCEPT.
fn assert_only_a_standalone_accept(sent: &[(u64, Sent)], ue: u64) {
    assert_eq!(
        sent.len(),
        1,
        "one NGAP PDU, the DL NAS Transport: {sent:?}"
    );
    assert_eq!(sent[0].0, ASSOC);
    let Sent::DownlinkNas {
        amf_ue_ngap_id,
        nas_pdu,
    } = &sent[0].1
    else {
        panic!("a DOWNLINK NAS TRANSPORT, got {:?}", sent[0].1);
    };
    assert_eq!(*amf_ue_ngap_id, ue);
    assert_protected_service_accept(nas_pdu);
}

/// #683 + #685, TS 23.502 §4.2.3.2 steps 4-12. A CM-CONNECTED UE sends a
/// protected Service Request with Uplink data status for a held PSI. It gets:
/// - exactly one UpdateSMContext ACTIVATING, for that session;
/// - then exactly one PDU SESSION RESOURCE SETUP REQUEST. That request carries
///   the SMF's transfer on the session's S-NSSAI, and, as its message-level
///   NAS-PDU, the protected Service Accept.
///
/// No separate Downlink NAS Transport is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_request_activates_the_user_plane_and_carries_the_accept_in_the_setup()
{
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_001u64, 76);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "sr760-ok-1", port);
    // A second held session the Uplink data status does NOT name stays as it is.
    hold_session(&mut server, ue, 2, "sr760-ok-2", port);

    let sent = connected_service_request(&mut server, ue, ran, Some(1 << 1)).await;

    let calls = calls.lock().expect("calls").clone();
    assert_eq!(calls.len(), 1, "one N11 call, for PSI 1 only: {calls:?}");
    assert!(
        calls[0].0.ends_with("/sm-contexts/sr760-ok-1/modify"),
        "UpdateSMContext on PSI 1's SM context: {}",
        calls[0].0
    );
    assert_eq!(calls[0].1["upCnxState"], "ACTIVATING");

    assert_eq!(sent.len(), 1, "one NGAP PDU, the setup request: {sent:?}");
    assert_eq!(sent[0].0, ASSOC);
    let Sent::SetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu,
        items,
    } = &sent[0].1
    else {
        panic!("a PDU SESSION RESOURCE SETUP REQUEST, got {:?}", sent[0].1);
    };
    assert_eq!((*amf_ue_ngap_id, *ran_ue_ngap_id), (ue, ran));
    assert_eq!(items, &vec![setup_item(1, transfer_for("sr760-ok-1"))]);
    assert_protected_service_accept(
        nas_pdu
            .as_deref()
            .expect("the Service Accept rides in the setup (#685)"),
    );
}

/// The other half of #685: when the SMF cannot activate the session there is no
/// setup request to carry the Accept, so it goes on its own in a Downlink NAS
/// Transport, and nothing else is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_request_whose_activation_fails_gets_a_standalone_accept() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_002u64, 77);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "fail-sr760-1", port);

    let sent = connected_service_request(&mut server, ue, ran, Some(1 << 1)).await;
    assert_eq!(
        calls.lock().expect("calls").len(),
        1,
        "the activation was attempted"
    );
    assert_only_a_standalone_accept(&sent, ue);
}

/// With two sessions to activate, the Accept rides in the FIRST setup request
/// only: the UE must see exactly one Service Accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_activated_sessions_carry_the_accept_exactly_once() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_003u64, 78);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "sr760-two-1", port);
    hold_session(&mut server, ue, 2, "sr760-two-2", port);

    let sent = connected_service_request(&mut server, ue, ran, Some((1 << 1) | (1 << 2))).await;

    assert_eq!(calls.lock().expect("calls").len(), 2);
    let mut psis = Vec::new();
    let mut accepts = 0;
    for (_, s) in &sent {
        match s {
            Sent::SetupRequest { items, nas_pdu, .. } => {
                psis.extend(items.iter().map(|i| i.psi));
                if let Some(nas) = nas_pdu {
                    assert_protected_service_accept(nas);
                    accepts += 1;
                }
            }
            other => panic!("only setup requests expected, got {other:?}"),
        }
    }
    psis.sort_unstable();
    assert_eq!(psis, vec![1, 2]);
    assert_eq!(accepts, 1, "exactly one Service Accept: {sent:?}");
}

/// Review of #768, MAJOR-1. The SMF refuses PSI 1 and accepts PSI 2. The Accept
/// must ride the first setup request that actually goes out, which is PSI 2's.
/// If it were tied to the first PLANNED PSI, PSI 2's setup would go out bare,
/// no standalone Accept would follow, and the UE would never be answered
/// (T3517 expires).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_accept_rides_the_first_setup_sent_when_an_earlier_session_is_refused() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_004u64, 79);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "fail-sr760-mixed-1", port);
    hold_session(&mut server, ue, 2, "sr760-mixed-2", port);

    let sent = connected_service_request(&mut server, ue, ran, Some((1 << 1) | (1 << 2))).await;

    assert_eq!(calls.lock().expect("calls").len(), 2, "both were attempted");
    assert_eq!(
        sent.len(),
        1,
        "one setup request and no DL NAS Transport: {sent:?}"
    );
    let Sent::SetupRequest { items, nas_pdu, .. } = &sent[0].1 else {
        panic!("a PDU SESSION RESOURCE SETUP REQUEST, got {:?}", sent[0].1);
    };
    assert_eq!(items, &vec![setup_item(2, transfer_for("sr760-mixed-2"))]);
    assert_protected_service_accept(nas_pdu.as_deref().expect("PSI 2's setup carries it"));
}

/// Review of #768, MAJOR-2 (TS 24.501 §5.6.1.2, TS 23.502 §4.2.3.2). A
/// connected Service Request with no Uplink data status activates nothing: no
/// N11 call, and one standalone Accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_request_without_uplink_data_status_activates_nothing() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_005u64, 80);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "sr760-none-1", port);
    hold_session(&mut server, ue, 2, "sr760-none-2", port);

    let sent = connected_service_request(&mut server, ue, ran, None).await;
    assert!(
        calls.lock().expect("calls").is_empty(),
        "no session activated"
    );
    assert_only_a_standalone_accept(&sent, ue);
}

/// An Uplink data status naming a PSI the AMF holds no SM context for causes no
/// N11 call, and the Accept goes standalone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uplink_data_status_for_an_unknown_session_gets_a_standalone_accept() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_006u64, 81);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "sr760-known-1", port);

    let sent = connected_service_request(&mut server, ue, ran, Some(1 << 3)).await;
    assert!(
        calls.lock().expect("calls").is_empty(),
        "PSI 3 has no SM context"
    );
    assert_only_a_standalone_accept(&sent, ue);
}

/// The send-failure branch: PSI 1's setup request is encoded but its SCTP send
/// fails. The Accept is not lost: it rides PSI 2's setup, which is the next one
/// to go out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_whose_send_fails_hands_the_accept_to_the_next_setup() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_760_007u64, 82);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "sr760-sendfail-1", port);
    hold_session(&mut server, ue, 2, "sr760-sendfail-2", port);
    server.fail_next_sends = 1;

    let sent = connected_service_request(&mut server, ue, ran, Some((1 << 1) | (1 << 2))).await;
    assert_eq!(calls.lock().expect("calls").len(), 2);
    assert_eq!(
        sent.len(),
        1,
        "PSI 1's setup was lost on the wire: {sent:?}"
    );
    let Sent::SetupRequest { items, nas_pdu, .. } = &sent[0].1 else {
        panic!("a PDU SESSION RESOURCE SETUP REQUEST, got {:?}", sent[0].1);
    };
    assert_eq!(
        items,
        &vec![setup_item(2, transfer_for("sr760-sendfail-2"))]
    );
    assert_protected_service_accept(nas_pdu.as_deref().expect("PSI 2's setup carries it"));
}

// ---- #745 follow-ups (review of #830): Path Switch with SM contexts held at an SMF ----

/// A stand-in SMF for Path Switch: records `(ref, n2SmInfoType)` of every update and
/// answers `PATH_SWITCH_REQ` with 200 and `n2SmInfo` = `transfer_for(ref)` (the
/// acknowledge transfer the AMF relays), except a `fail-*` ref, which gets 500.
pub(super) async fn path_switch_smf() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let seen: Arc<std::sync::Mutex<Vec<(String, String)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
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
                let sm_ref = req
                    .header
                    .uri
                    .split("/sm-contexts/")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .unwrap_or_default()
                    .to_string();
                let body: serde_json::Value = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str(c).ok())
                    .unwrap_or_default();
                let n2_type = body["n2SmInfoType"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                sink.lock()
                    .expect("sink")
                    .push((sm_ref.clone(), n2_type.clone()));
                if n2_type != "PATH_SWITCH_REQ" {
                    return SResp::no_content();
                }
                if sm_ref.starts_with("fail-") {
                    return SResp::with_status(500);
                }
                let answer = serde_json::json!({
                    "n2SmInfoType": "PATH_SWITCH_REQ_ACK",
                    "n2SmInfo": base64::engine::general_purpose::STANDARD
                        .encode(transfer_for(&sm_ref)),
                });
                SResp::with_status(200).with_body(answer.to_string(), "application/json")
            }
        })
        .await
        .expect("stand-in SMF starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (server, addr.port(), seen)
}

/// A PATH SWITCH REQUEST ACKNOWLEDGE's switched `[(psi, transfer)]` and released
/// `[(psi, unsuccessful transfer)]` lists, decoded with the generated codec.
#[allow(clippy::type_complexity)]
fn decoded_path_switch_ack(pdu: &[u8]) -> Option<(Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>)> {
    let g::NGAP_PDU::SuccessfulOutcome(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let g::SuccessfulOutcomeValue::Id_PathSwitchRequest(ack) = m.value else {
        return None;
    };
    let (mut switched, mut released) = (Vec::new(), Vec::new());
    for ie in ack.protocol_i_es.0 {
        use g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue as Ie;
        match ie.value {
            Ie::Id_PDUSessionResourceSwitchedList(list) => {
                switched = list
                    .0
                    .into_iter()
                    .map(|i| {
                        (
                            i.pdu_session_id.0,
                            i.path_switch_request_acknowledge_transfer.0,
                        )
                    })
                    .collect()
            }
            Ie::Id_PDUSessionResourceReleasedListPSAck(list) => {
                released = list
                    .0
                    .into_iter()
                    .map(|i| {
                        (
                            i.pdu_session_id.0,
                            i.path_switch_request_unsuccessful_transfer.0,
                        )
                    })
                    .collect()
            }
            _ => {}
        }
    }
    Some((switched, released))
}

fn forget_amf_sessions(ue: u64) {
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap();
    for sess in guard.sess_list_for_ue(ue) {
        guard.sess_remove(sess.id);
    }
}

/// #745 follow-up (review of #830, MINOR 2): the duplicate check runs before ANY SMF
/// call. The UE's sessions 5 and 6 are held at a recording SMF that would switch them;
/// a request naming PSI 5 twice is failed, the SMF sees no request at all, and the UE
/// stays on the source.
///
/// REVERT-VERIFIED: without the duplicate check the SMF receives three
/// PATH_SWITCH_REQ updates (PSIs 5, 6, 5) and the gNB gets an Acknowledge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicated_psi_reaches_no_smf() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_461u64, 97_462u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let ue = 7_745_011u64;
    let mut state = UeNasContext::new(ue, 11, source, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "ps745-dup-5", port);
    hold_session(&mut server, ue, 6, "ps745-dup-6", port);

    server
        .handle_path_switch_request(target, &path_switch_request_pdu(ue, 67, &[5, 6, 5]))
        .await
        .expect("handled");

    let sent = take_sent_ngap(&mut server);
    forget_amf_sessions(ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, _, released) =
        decoded_path_switch_failure(&sent[0].1).expect("a PATH SWITCH REQUEST FAILURE");
    assert_eq!(
        released.iter().map(|(psi, _)| *psi).collect::<Vec<_>>(),
        vec![5, 6]
    );
    assert!(
        calls.lock().expect("calls").is_empty(),
        "no SMF is called for a failed request: {:?}",
        calls.lock().expect("calls")
    );
    let after = server.ue_auth_state.get(ue).expect("UE");
    assert_eq!((after.association_id, after.ran_ue_ngap_id), (source, 11));
}

/// #745 follow-up (review of #830, MINOR 3), TS 38.413 §8.4.4.2: a session the SMF does
/// not switch is listed in the Acknowledge's PDU Session Resource Released List, with an
/// AMF-generated Path Switch Request Unsuccessful Transfer, while the switched one
/// carries the SMF's own acknowledge transfer. When no session switches, §8.4.4.3: a
/// PATH SWITCH REQUEST FAILURE releasing every requested session.
///
/// REVERT-VERIFIED: with `released_list: Vec::new()` in the Acknowledge, PSI 6 is
/// missing from the Released List.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_the_smf_does_not_switch_is_released_in_the_acknowledge() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_463u64, 97_464u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let unswitched = crate::ngap_asn1::path_switch_unsuccessful_transfer(
        nextgcore_ngap::types::Cause::Misc(nextgcore_ngap::types::CauseMisc::Unspecified),
    )
    .expect("encode");

    // One switched, one not.
    let ue = 7_745_012u64;
    let mut state = UeNasContext::new(ue, 12, source, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "ps745-ok-5", port);
    hold_session(&mut server, ue, 6, "fail-ps745-6", port);
    server.mark_up_active(ue, 5);
    server.mark_up_active(ue, 6);
    server
        .handle_path_switch_request(target, &path_switch_request_pdu(ue, 68, &[5, 6]))
        .await
        .expect("handled");
    let sent = take_sent_ngap(&mut server);
    forget_amf_sessions(ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, target);
    let (switched, released) =
        decoded_path_switch_ack(&sent[0].1).expect("a PATH SWITCH REQUEST ACKNOWLEDGE");
    assert_eq!(switched, vec![(5, transfer_for("ps745-ok-5"))]);
    assert_eq!(released, vec![(6, unswitched.clone())]);
    assert_eq!(
        calls.lock().expect("calls").clone(),
        vec![
            ("ps745-ok-5".to_string(), "PATH_SWITCH_REQ".to_string()),
            ("fail-ps745-6".to_string(), "PATH_SWITCH_REQ".to_string())
        ]
    );
    // #778 follow-up: the session the Acknowledge releases has no user plane on the
    // target; the switched one keeps its flag.
    assert!(server.up_active.contains(&(ue, 5)));
    assert!(!server.up_active.contains(&(ue, 6)), "the released session");
    let after = server.ue_auth_state.get(ue).expect("UE");
    assert_eq!(
        (after.association_id, after.ran_ue_ngap_id),
        (target, 68),
        "an acknowledged switch relocates the UE"
    );

    // Nothing switched: the Failure releases both.
    let ue = 7_745_013u64;
    let mut state = UeNasContext::new(ue, 13, source, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "fail-ps745-n5", port);
    hold_session(&mut server, ue, 6, "fail-ps745-n6", port);
    server
        .handle_path_switch_request(target, &path_switch_request_pdu(ue, 69, &[5, 6]))
        .await
        .expect("handled");
    let sent = take_sent_ngap(&mut server);
    forget_amf_sessions(ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (amf, ran, released) =
        decoded_path_switch_failure(&sent[0].1).expect("a PATH SWITCH REQUEST FAILURE");
    assert_eq!((amf, ran), (ue, 69));
    assert_eq!(released, vec![(5, unswitched.clone()), (6, unswitched)]);
}

// ---------------------------------------------------------------------------
// #796: a PDU session establishment while no SMF is reachable (SMF restart)
// ---------------------------------------------------------------------------

/// A stand-in SMF that answers CreateSMContext 201 (`smContextRef` "est-796",
/// an N1 and an N2 transfer), started on `listener`, recording each URI.
async fn creating_smf_on(
    listener: std::net::TcpListener,
) -> (
    nextgcore_sbi::server::SbiServer,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let addr = listener.local_addr().expect("addr");
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |req: SReq| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().expect("sink").push(req.header.uri.clone());
                let body = serde_json::json!({
                    "smContextRef": "est-796",
                    "n1SmMsg": base64::engine::general_purpose::STANDARD
                        .encode([0x2E, 0x05, 0x01, 0xC2]),
                    "n2SmInfo": base64::engine::general_purpose::STANDARD
                        .encode(transfer_for("est-796")),
                });
                SResp::with_status(201).with_body(body.to_string(), "application/json")
            }
        })
        .await
        .expect("stand-in SMF starts");
    (server, seen)
}

/// A connected, registered UE whose UE context is up at the gNB, so a session
/// setup is sent as soon as the SMF answers.
fn ue_ready_for_sessions(server: &mut NgapServer, ue: u64, ran: u32) {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.initial_context_setup_response_received = true;
    });
}

/// Run the establishment supervision until no attempt is in flight and every
/// outcome has been applied (the attempts run off the NGAP task, #796 M1).
async fn settle_establishments(server: &mut NgapServer) {
    for _ in 0..500 {
        server.process_pending_establishments().await;
        server.process_sbi_outcomes().await;
        let attempting = server.pending_establishments.values().any(|p| p.in_flight);
        if !attempting && server.sbi_offload.in_flight() == 0 {
            server.process_sbi_outcomes().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the establishment attempts did not settle");
}

/// Make every waiting establishment due now.
fn make_establishments_due(server: &mut NgapServer) {
    let now = std::time::Instant::now();
    for p in server.pending_establishments.values_mut() {
        p.next_attempt = now;
    }
}

/// #796, TS 23.502 §4.3.2.2.1. The UE asks for a PDU session while its only
/// SMF is restarting (nothing listens). The AMF does not reject at once. It
/// waits, sending nothing to the UE, then retries; the restarted SMF answers;
/// the session is established: a PDU SESSION RESOURCE SETUP REQUEST reaches
/// the gNB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_establishment_while_the_smf_restarts_is_retried_and_succeeds() {
    // The SMF is down: its port is held but not listening (#1050).
    let down = nextgcore_sbi::test_support::down_port();
    let port = down.port();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_001u64, 96);
    ue_ready_for_sessions(&mut server, ue, ran);

    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "nothing to the UE yet: no 5GSM reject, no DL NAS Transport"
    );
    assert!(server.pending_establishments.contains_key(&(ue, 5)));

    // The SMF comes back on the same address: the reserved socket starts listening.
    let listener = down.listen();
    let (_smf, seen) = creating_smf_on(listener).await;
    make_establishments_due(&mut server);
    settle_establishments(&mut server).await;

    assert_eq!(
        seen.lock().expect("seen").len(),
        1,
        "the retry reached the restarted SMF"
    );
    assert!(server.pending_establishments.is_empty());
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    assert!(
        sent.iter()
            .any(|s| matches!(s, Sent::SetupRequest { items, .. }
            if items.first().map(|i| i.psi) == Some(5))),
        "the session is set up at the gNB: {sent:?}"
    );
    server.forget_ue(ue);
}

/// #980 review: an establishment's `3gpp-Sbi-Origination-Timestamp` is taken
/// once, when its first CreateSMContext goes out. It is kept with the waiting
/// request (a UE retransmission does not change it) and sent unchanged on the
/// retry, so the PCF sees the retried create as the same request
/// (TS 29.512 §4.2.7) and does not replace the association.
///
/// Revert-verified: stamping each attempt afresh fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_retried_establishment_carries_its_first_origination_timestamp() {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    // The SMF is down: its port is held but not listening (#1050).
    let down = nextgcore_sbi::test_support::down_port();
    let port = down.port();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_980_001u64, 98);
    ue_ready_for_sessions(&mut server, ue, ran);

    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    // #922: the first attempt runs off the NGAP task; let it fail.
    settle_establishments(&mut server).await;
    let first = server
        .pending_establishments
        .get(&(ue, 5))
        .expect("waiting")
        .origination_timestamp
        .clone();
    assert!(
        nextgcore_sbi::datetime::origination_timestamp_to_epoch_ms(&first).is_some(),
        "{first}"
    );
    // The UE retransmits (T3580) a little later: the same establishment.
    tokio::time::sleep(Duration::from_millis(5)).await;
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    assert_eq!(
        server.pending_establishments[&(ue, 5)].origination_timestamp,
        first
    );

    // The SMF comes back and records the header of what it receives.
    let stamps: Arc<std::sync::Mutex<Vec<Option<String>>>> = Arc::default();
    let sink = Arc::clone(&stamps);
    let rebound = down.listen();
    let addr = rebound.local_addr().expect("addr");
    let smf = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        rebound,
    );
    smf.start(move |req: SReq| {
        let sink = Arc::clone(&sink);
        async move {
            sink.lock().expect("sink").push(
                req.http
                    .get_header(crate::sbi_path::ORIGINATION_TIMESTAMP_HEADER)
                    .cloned(),
            );
            let body = serde_json::json!({
                "smContextRef": "est-980",
                "n1SmMsg": base64::engine::general_purpose::STANDARD
                    .encode([0x2E, 0x05, 0x01, 0xC2]),
                "n2SmInfo": base64::engine::general_purpose::STANDARD
                    .encode(transfer_for("est-980")),
            });
            SResp::with_status(201).with_body(body.to_string(), "application/json")
        }
    })
    .await
    .expect("stand-in SMF starts");
    make_establishments_due(&mut server);
    settle_establishments(&mut server).await;

    assert_eq!(
        *stamps.lock().expect("stamps"),
        vec![Some(first)],
        "the retry carries the establishment's first stamp"
    );
    server.forget_ue(ue);
}

/// A protected UL NAS TRANSPORT carrying `sm` (N1 SM information) for PSI
/// `sm[1]`, with Request type "initial request" (TS 24.501 §8.2.10).
fn ul_nas_transport_initial_request(sm: &[u8], count: u8) -> Vec<u8> {
    let mut inner = vec![0x7E, 0x00, 0x67, 0x01];
    inner.extend_from_slice(&(sm.len() as u16).to_be_bytes());
    inner.extend_from_slice(sm);
    inner.extend_from_slice(&[0x12, sm[1], 0x81]);
    ue_protect(&inner, count)
}

/// #1036, TS 24.501 §5.4.5.2.5 a) 12). The UE retransmits its PDU SESSION
/// ESTABLISHMENT REQUEST (Request type "initial request") after the AMF's
/// CreateSMContext for it succeeded, e.g. because the Accept was lost on the
/// radio. The AMF holds a routing context for the PSI, so it releases that
/// session first: at the SMF (ReleaseSMContext, before the new create), and at
/// the gNB (PDU SESSION RESOURCE RELEASE COMMAND), whose resources for the PSI
/// would refuse the new setup. Then the request is a new establishment. Before,
/// a second create overwrote the AMF's ref and orphaned the first SM context.
///
/// Revert-verified: without the release, the SMF sees create, create.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_initial_request_for_a_held_psi_releases_the_session_first() {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let smf = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(listener.local_addr().expect("addr")),
        listener,
    );
    smf.start(move |req: SReq| {
        let sink = Arc::clone(&sink);
        async move {
            let uri = req.header.uri.clone();
            sink.lock().expect("sink").push(uri.clone());
            if uri.ends_with("/release") {
                return SResp::with_status(204);
            }
            let n = sink.lock().expect("sink").len();
            let sm_ref = format!("est-1036-{n}");
            let body = serde_json::json!({
                "smContextRef": sm_ref,
                "n1SmMsg": base64::engine::general_purpose::STANDARD
                    .encode([0x2E, 0x05, 0x01, 0xC2]),
                "n2SmInfo": base64::engine::general_purpose::STANDARD
                    .encode(transfer_for(&sm_ref)),
            });
            SResp::with_status(201).with_body(body.to_string(), "application/json")
        }
    })
    .await
    .expect("stand-in SMF starts");
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_103_601u64, 99);
    ue_ready_for_sessions(&mut server, ue, ran);

    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &ul_nas_transport_initial_request(&request, 0)),
        )
        .await
        .expect("handled");
    settle_establishments(&mut server).await;
    assert_eq!(
        server.sm_context_refs.get(&(ue, 5)).map(String::as_str),
        Some("est-1036-1"),
        "the first create succeeded"
    );
    let _ = take_sent_ngap(&mut server);

    // T3580 expires at the UE: the same request again.
    server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &ul_nas_transport_initial_request(&request, 1)),
        )
        .await
        .expect("handled");
    settle_establishments(&mut server).await;
    server.sbi_offload.settle().await;

    let uris = seen.lock().expect("seen").clone();
    assert_eq!(uris.len(), 3, "{uris:?}");
    assert!(
        uris[1].ends_with("/sm-contexts/est-1036-1/release"),
        "the held SM context is released before the new create: {uris:?}"
    );
    assert!(uris[2].ends_with("/sm-contexts"), "{uris:?}");
    assert_eq!(
        server.sm_context_refs.get(&(ue, 5)).map(String::as_str),
        Some("est-1036-3"),
        "the new establishment holds the PSI"
    );
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let release = sent
        .iter()
        .position(|s| matches!(s, Sent::ReleaseCommand { psis, .. } if psis == &[5]));
    let setup = sent.iter().position(|s| {
        matches!(s, Sent::SetupRequest { items, .. }
            if items.first().map(|i| i.psi) == Some(5))
    });
    assert!(
        matches!((release, setup), (Some(r), Some(s)) if r < s),
        "the gNB releases PSI 5 before its new setup: {sent:?}"
    );
    server.forget_ue(ue);
}

/// When no SMF comes back within the window, the UE is answered as TS 24.501
/// prescribes for a routing failure (§5.4.5.2.5 a) 1), §5.4.5.3.1 e)): a DL NAS
/// TRANSPORT carrying its own 5GSM message back, with 5GMM #90. The AMF does
/// not fabricate a 5GSM reject. A UE retransmission does not extend the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_establishment_with_no_smf_back_in_the_window_gets_payload_not_forwarded() {
    // The SMF is down, and stays down: its port is held but never listens (#1050).
    let down = nextgcore_sbi::test_support::down_port();
    let _env = super::SmfEnvGuard::acquire(down.port()).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_002u64, 97);
    ue_ready_for_sessions(&mut server, ue, ran);

    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    // The window started a while ago (the first failure is what counts).
    let started = server.pending_establishments[&(ue, 5)].first_failure;
    server
        .pending_establishments
        .get_mut(&(ue, 5))
        .expect("waiting")
        .first_failure = started - ESTABLISHMENT_RETRY_WINDOW;
    // A UE retransmission meanwhile keeps that original start.
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");

    assert!(server.pending_establishments.is_empty());
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = sent.as_slice() else {
        panic!("one DL NAS Transport: {sent:?}");
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

// ---------------------------------------------------------------------------
// #1101: an SMF that answers NF_FAILOVER or 503 is re-selected, and a refusal
// carries a back-off timer
// ---------------------------------------------------------------------------

/// A stand-in SMF whose CreateSMContext answers follow `script`: the n-th create
/// gets `script[n]` as `(status, ProblemDetails cause)`, and every create past the
/// script is created (201, `smContextRef` "est-1101"). The error bodies are
/// SmContextCreateErrors. Returns the server, its port
/// and the number of creates it saw. Keep the server alive.
async fn scripted_create_smf(
    script: Vec<(u16, Option<&'static str>)>,
) -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&creates);
    let script = Arc::new(script);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |req: SReq| {
            let counter = Arc::clone(&counter);
            let script = Arc::clone(&script);
            async move {
                if !req.header.uri.ends_with("/nsmf-pdusession/v1/sm-contexts") {
                    return SResp::no_content();
                }
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some((status, cause)) = script.get(n) {
                    // An SmContextCreateError, as smfd sends (TS 29.502 Table
                    // 6.1.3.2.3.1-3); `problem_cause` also reads the flat form.
                    let error = serde_json::json!({
                        "error": { "status": status, "cause": cause },
                    });
                    return SResp::with_status(*status)
                        .with_body(error.to_string(), "application/json");
                }
                let body = serde_json::json!({
                    "smContextRef": "est-1101",
                    "n1SmMsg": base64::engine::general_purpose::STANDARD
                        .encode([0x2E, 0x05, 0x01, 0xC2]),
                    "n2SmInfo": base64::engine::general_purpose::STANDARD
                        .encode(transfer_for("est-1101")),
                });
                SResp::with_status(201).with_body(body.to_string(), "application/json")
            }
        })
        .await
        .expect("stand-in SMF starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    (server, addr.port(), creates)
}

/// Whether a PDU SESSION RESOURCE SETUP REQUEST for `psi` is among `sent`.
fn sets_up(sent: &[(u64, Vec<u8>)], psi: u8) -> bool {
    sent.iter().any(|(_, p)| {
        matches!(decode_sent(p), Sent::SetupRequest { items, .. }
            if items.first().map(|i| i.psi) == Some(psi))
    })
}

/// Ask for PSI 5 and let the first CreateSMContext come back.
async fn request_psi_5(server: &mut NgapServer, ue: u64, ran: u32) {
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    settle_establishments(server).await;
}

/// **#1101** (TS 29.500 Table 5.2.7.2-1). The SMF answers the first CreateSMContext
/// with 500 NF_FAILOVER, as a shutting-down smfd does (#718 review M3), and then, as
/// the replacement behind the same Service does, creates. The AMF does not reject:
/// the establishment waits, nothing goes to the UE, the retry is created and the
/// session reaches the gNB.
///
/// REVERT-VERIFIED: without `smf_failing_over` the UE gets 5GSM #26 at once and no
/// second CreateSMContext is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_nf_failover_answer_is_retried_not_rejected() {
    let (_smf, port, creates) = scripted_create_smf(vec![(500, Some("NF_FAILOVER"))]).await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let _seeded = SeededSmfs {
        ids: &[],
        held_down: ("127.0.0.1", port),
    };
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_110_101u64, 101);
    ue_ready_for_sessions(&mut server, ue, ran);

    request_psi_5(&mut server, ue, ran).await;
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no 5GSM reject, no DL NAS Transport"
    );
    assert!(server.pending_establishments.contains_key(&(ue, 5)));

    make_establishments_due(&mut server);
    settle_establishments(&mut server).await;
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(server.pending_establishments.is_empty());
    assert!(sets_up(&take_sent_ngap(&mut server), 5));
    server.forget_ue(ue);
}

/// **#1101**, the 503 row (TS 29.500 §5.2.7.2: NF_SERVICE_FAILOVER, or the
/// service unavailable for now): retried the same way.
///
/// REVERT-VERIFIED: without the 503 arm of `smf_failing_over` it is rejected #26.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_503_answer_is_retried_not_rejected() {
    let (_smf, port, creates) =
        scripted_create_smf(vec![(503, Some("NF_SERVICE_FAILOVER")), (503, None)]).await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let _seeded = SeededSmfs {
        ids: &[],
        held_down: ("127.0.0.1", port),
    };
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_110_102u64, 102);
    ue_ready_for_sessions(&mut server, ue, ran);

    request_psi_5(&mut server, ue, ran).await;
    for _ in 0..2 {
        make_establishments_due(&mut server);
        settle_establishments(&mut server).await;
    }
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert!(server.pending_establishments.is_empty());
    assert!(sets_up(&take_sent_ngap(&mut server), 5));
    server.forget_ue(ue);
}

/// SMF instances a test put in the process-global discovery cache, and the endpoint
/// its NF_FAILOVER held down. Drop removes both (#1107 review m1), so neither a
/// cached profile nor a hold-down outlives the test: the port is freed and may be
/// another test's SMF next. The cache removal is async, so
/// it runs on a fresh runtime of its own on a scoped thread: a panicking test drops
/// this while its own runtime is unwinding.
struct SeededSmfs {
    ids: &'static [&'static str],
    held_down: (&'static str, u16),
}

impl Drop for SeededSmfs {
    fn drop(&mut self) {
        let ctx = nextgcore_sbi::context::global_context();
        ctx.clear_endpoint_failure(self.held_down.0, self.held_down.1);
        let ids = self.ids;
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("cleanup runtime");
                rt.block_on(async {
                    for id in ids {
                        ctx.remove_nf_instance(id).await;
                    }
                });
            });
        });
    }
}

/// **#1101**, re-selection. The discovery cache holds two SMF instances, one failing
/// over. The establishment goes to it first, and its NF_FAILOVER evicts its profile
/// and holds its endpoint down. So the retry goes to the other instance and is
/// created there; the failing one sees no second create.
///
/// REVERT-VERIFIED: without the eviction and the hold-down, the failing instance is
/// still cached and not held down, and the retry may go back to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_nf_failover_answer_re_selects_another_smf_instance() {
    use nextgcore_sbi::context::{NfInstance, NfService};
    use nextgcore_sbi::types::{NfType, SbiServiceType as S};
    let (_failing, failing_port, failing_creates) =
        scripted_create_smf(vec![(500, Some("NF_FAILOVER")); 4]).await;
    let (_healthy, healthy_port, healthy_creates) = scripted_create_smf(Vec::new()).await;
    let _env = super::SmfEnvGuard::acquire(failing_port).await;
    let ctx = nextgcore_sbi::context::global_context();
    let instance = |id: &str, port: u16| {
        let mut i = NfInstance::new(id, NfType::Smf);
        i.ipv4_addresses = vec!["127.0.0.1".to_string()];
        let mut svc = NfService::new("nsmf-pdusession", S::NsmfPdusession);
        svc.port = port;
        i.add_service(svc);
        i
    };
    // #1107 review m1: dropped whether the test passes or panics, so a failure here
    // leaves no cached SMF or hold-down behind for the next SmfEnvGuard test.
    let _seeded = SeededSmfs {
        ids: &["smf-1101-failing", "smf-1101-healthy"],
        held_down: ("127.0.0.1", failing_port),
    };
    ctx.add_nf_instance(instance("smf-1101-failing", failing_port))
        .await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_110_103u64, 103);
    ue_ready_for_sessions(&mut server, ue, ran);

    request_psi_5(&mut server, ue, ran).await;
    assert_eq!(failing_creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cached: Vec<String> = ctx
        .find_nf_instances_by_service(S::NsmfPdusession)
        .await
        .into_iter()
        .map(|i| i.id)
        .collect();
    let held_down = ctx.endpoint_held_down("127.0.0.1", failing_port);
    assert!(
        !cached.iter().any(|id| id == "smf-1101-failing") && held_down,
        "the failing SMF is evicted ({cached:?}) and held down ({held_down})"
    );
    // The replacement registers at the NRF meanwhile; the AMF's cache learns of it.
    ctx.add_nf_instance(instance("smf-1101-healthy", healthy_port))
        .await;
    make_establishments_due(&mut server);
    settle_establishments(&mut server).await;

    let failing = failing_creates.load(std::sync::atomic::Ordering::SeqCst);
    let healthy = healthy_creates.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        (failing, healthy),
        (1, 1),
        "the retry went to the other SMF"
    );
    assert!(server.pending_establishments.is_empty());
    assert!(sets_up(&take_sent_ngap(&mut server), 5));
    server.forget_ue(ue);
}

/// The 5GSM message a DL NAS TRANSPORT in `sent` carries (NEA0: the plain message
/// follows the 7-octet security header).
fn delivered_n1(sent: &[(u64, Vec<u8>)]) -> Vec<u8> {
    use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
    let decoded: Vec<Sent> = sent.iter().map(|(_, p)| decode_sent(p)).collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = decoded.as_slice() else {
        panic!("one DL NAS Transport: {decoded:?}");
    };
    let Ok(FiveGmmMessage::DlNasTransport(dl)) =
        parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&nas_pdu[7..]))
    else {
        panic!("a DL NAS TRANSPORT: {nas_pdu:02x?}");
    };
    dl.payload_container.data.to_vec()
}

/// **#1101**, a refusal (TS 24.501 §6.4.1.4.3). An SMF that answers 500
/// SYSTEM_FAILURE refused; that is not a failover. The UE gets PDU SESSION
/// ESTABLISHMENT REJECT #26 at once, now with a Back-off timer value of 10 s (GPRS
/// timer 3: unit 2 s, value 5), so it asks again after T3396 rather than at T3512.
///
/// REVERT-VERIFIED: the reject without the back-off timer fails the byte compare.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_create_is_rejected_26_with_a_back_off_timer() {
    let (_smf, port, creates) = scripted_create_smf(vec![(500, Some("SYSTEM_FAILURE"))]).await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_110_104u64, 104);
    ue_ready_for_sessions(&mut server, ue, ran);

    request_psi_5(&mut server, ue, ran).await;
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(server.pending_establishments.is_empty());
    assert_eq!(
        delivered_n1(&take_sent_ngap(&mut server)),
        vec![0x2E, 0x05, 0x01, 0xC3, 0x1A, 0x37, 0x01, 0x65]
    );
    server.forget_ue(ue);
}

/// **#1101.** The classification, row by row: which SMF answers are re-selected for,
/// and the ProblemDetails `cause` read from either body shape.
#[test]
fn which_smf_answers_are_re_selected_for() {
    use crate::sbi_path::SbiError::{RequestFailed, SmfRefused};
    let refused = |status, cause: Option<&str>| SmfRefused {
        status,
        cause: cause.map(str::to_string),
    };
    assert!(smf_failing_over(&refused(500, Some("NF_FAILOVER"))));
    assert!(smf_failing_over(&refused(503, Some("NF_SERVICE_FAILOVER"))));
    assert!(smf_failing_over(&refused(503, None)));
    assert!(!smf_failing_over(&refused(500, Some("SYSTEM_FAILURE"))));
    assert!(!smf_failing_over(&refused(500, None)));
    assert!(!smf_failing_over(&refused(403, Some("NF_FAILOVER"))));
    assert!(!smf_failing_over(&RequestFailed(
        "SMF request failed: refused".into()
    )));
    assert!(smf_unreachable(&RequestFailed(
        "SMF request failed: refused".into()
    )));
    assert!(!smf_unreachable(&refused(500, Some("NF_FAILOVER"))));
    assert_eq!(
        refused(500, Some("NF_FAILOVER")).to_string(),
        "Request failed: SMF returned status 500 (NF_FAILOVER)"
    );
    assert_eq!(
        crate::sbi_path::problem_cause(Some(r#"{"status":500,"cause":"NF_FAILOVER"}"#)),
        Some("NF_FAILOVER".to_string())
    );
    assert_eq!(
        crate::sbi_path::problem_cause(Some(r#"{"error":{"status":503,"cause":"X"}}"#)),
        Some("X".to_string())
    );
    assert_eq!(crate::sbi_path::problem_cause(Some("not json")), None);
    assert_eq!(crate::sbi_path::problem_cause(None), None);
}

/// An SMF that never answers: a listener nobody accepts on, so the connection
/// sits in the backlog and the request waits for the client's timeout. Locally
/// deterministic stand-in for a blackholed address (a stale pod IP, a lost node).
/// Keep the listener alive.
pub(super) fn hanging_smf() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

/// #796 review M1. With the SMF not answering, a due re-selection
/// attempt does not hold the NGAP task: the supervision returns at once while the
/// attempt waits for its connect timeout off the task, and NGAP keeps being
/// handled (here: a second UE's establishment, answered by being queued, and a
/// retransmission absorbed without a new attempt).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_unanswering_smf_does_not_hold_the_ngap_task() {
    let (_hang, port) = hanging_smf();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_011u64, 98);
    ue_ready_for_sessions(&mut server, ue, ran);
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    // As left by a first attempt that found no SMF.
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            &request,
            None,
            std::time::Instant::now(),
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
    make_establishments_due(&mut server);

    let started = std::time::Instant::now();
    server.process_pending_establishments().await;
    server.process_sbi_outcomes().await;
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the supervision spawned the attempt and returned: {:?}",
        started.elapsed()
    );
    assert!(server.pending_establishments[&(ue, 5)].in_flight);
    until_in_flight(&server, 1).await;

    // N2 is still served while the attempt hangs: the UE's retransmission is
    // handled at once and starts no second attempt.
    let started = std::time::Instant::now();
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(server.sbi_offload.in_flight(), 1);
    assert!(take_sent_ngap(&mut server).is_empty());
    server.forget_ue(ue);
}

/// #796 review M1: the window is wall clock. When it ends while an attempt is
/// still waiting on an unreachable SMF, the UE gets #90 then, not when the
/// attempt gives up. The late outcome is then ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn the_window_ends_on_time_while_an_attempt_hangs() {
    let (_hang, port) = hanging_smf();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_012u64, 99);
    ue_ready_for_sessions(&mut server, ue, ran);
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            &request,
            None,
            std::time::Instant::now(),
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
    {
        let p = server
            .pending_establishments
            .get_mut(&(ue, 5))
            .expect("waiting");
        // 300 ms of the window left, and the attempt is due now.
        p.first_failure =
            std::time::Instant::now() - ESTABLISHMENT_RETRY_WINDOW + Duration::from_millis(300);
        p.next_attempt = std::time::Instant::now();
    }
    server.process_pending_establishments().await;
    assert!(server.pending_establishments[&(ue, 5)].in_flight);
    assert!(take_sent_ngap(&mut server).is_empty());

    tokio::time::sleep(Duration::from_millis(400)).await;
    let started = std::time::Instant::now();
    server.process_pending_establishments().await;
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(server.pending_establishments.is_empty());
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    assert!(
        matches!(sent.as_slice(), [Sent::DownlinkNas { .. }]),
        "the #90 DL NAS Transport at the end of the window: {sent:?}"
    );
    // The attempt is still waiting on the SMF (its own SBI timeout bounds it);
    // whatever it returns later is matched against a request that no longer
    // waits (`a_late_success_for_an_earlier_request_is_released_not_applied`).
    server.process_sbi_outcomes().await;
    assert!(take_sent_ngap(&mut server).is_empty());
    server.forget_ue(ue);
    until_in_flight(&server, 0).await;
}

/// #796 review m1: a UE that goes CM-IDLE during the window is dropped without
/// an answer on the released connection, and no attempt is made for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_that_went_idle_is_dropped_from_the_window() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_013u64, 100);
    ue_ready_for_sessions(&mut server, ue, ran);
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            &request,
            None,
            std::time::Instant::now(),
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    make_establishments_due(&mut server);

    server.process_pending_establishments().await;

    assert!(server.pending_establishments.is_empty());
    assert_eq!(server.sbi_offload.in_flight(), 0);
    assert!(take_sent_ngap(&mut server).is_empty());
    server.forget_ue(ue);
}

/// #877 m1: the window runs from the request's arrival, not from the first
/// failure, which an unanswering SMF reports only after the connect timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_window_runs_from_the_request_arrival() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_014u64, 101);
    ue_ready_for_sessions(&mut server, ue, ran);
    let arrived = std::time::Instant::now() - Duration::from_secs(5);
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            &[0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF],
            None,
            arrived,
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
    assert_eq!(
        server.pending_establishments[&(ue, 5)].first_failure,
        arrived
    );
    server.forget_ue(ue);
}

/// #877 m2: an attempt's late success for an EARLIER request of the same PSI
/// (that one was answered #90 and the UE asked again) is not applied to the new
/// request: nothing is set up, the new request keeps waiting, and the context
/// the late success created is released at its SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_success_for_an_earlier_request_is_released_not_applied() {
    let (_smf, smf_port, seen) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_015u64, 102);
    ue_ready_for_sessions(&mut server, ue, ran);
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    defer_request(&mut server, ue, ran, &request).await;
    let earlier = server.pending_establishments[&(ue, 5)].generation;
    // That request was answered #90; the UE asked again.
    server.pending_establishments.remove(&(ue, 5));
    defer_request(&mut server, ue, ran, &request).await;
    assert_ne!(server.pending_establishments[&(ue, 5)].generation, earlier);

    server
        .apply_establishment_attempt(EstablishmentAttempt {
            amf_ue_ngap_id: ue,
            psi: 5,
            generation: earlier,
            sst: 1,
            sd: None,
            dnn: None,
            smf: ("127.0.0.1".to_string(), smf_port),
            result: Ok(crate::sbi_path::SmContextCreateResponse {
                n1_sm_msg: vec![0x2E, 0x05, 0x01, 0xC2],
                n2_sm_info: transfer_for("late-796"),
                sm_context_ref: "late-796".to_string(),
                smf_authority: Some(format!("127.0.0.1:{smf_port}")),
            }),
        })
        .await
        .expect("applied");
    // #877 re-review m1/M1: the release is DURABLE keyed work. The window
    // ending for this PSI supersedes its attempts, and the UE then leaves;
    // neither may drop the release, or the context leaks at the SMF.
    server.sbi_offload.supersede_key((ue, 5));
    server.sbi_offload.cancel_ue(ue);
    server.sbi_offload.settle().await;

    assert!(take_sent_ngap(&mut server).is_empty(), "nothing set up");
    assert!(!server.sm_context_refs.contains_key(&(ue, 5)));
    assert!(
        seen.lock()
            .expect("seen")
            .iter()
            .any(|(uri, _)| uri.ends_with("/sm-contexts/late-796/release")),
        "the late context is released: {:?}",
        seen.lock().expect("seen")
    );
    server.forget_ue(ue);
}

/// #877 re-review M1: a departed UE's attempt stops holding a permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn forgetting_a_ue_frees_its_attempt_permit() {
    let (_hang, port) = hanging_smf();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_016u64, 103);
    ue_ready_for_sessions(&mut server, ue, ran);
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            &[0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF],
            None,
            std::time::Instant::now(),
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
    make_establishments_due(&mut server);
    server.process_pending_establishments().await;
    until_in_flight(&server, 1).await;

    server.forget_ue(ue);

    until_in_flight(&server, 0).await;
    assert!(!server.sbi_offload.key_busy((ue, 5)));
}

async fn defer_request(server: &mut NgapServer, ue: u64, ran: u32, request: &[u8]) {
    server
        .defer_establishment(
            ASSOC,
            ue,
            ran,
            request,
            None,
            std::time::Instant::now(),
            "Fri, 23 Oct 2026 10:00:00.000 GMT",
            &crate::sbi_path::SbiError::Timeout,
        )
        .await
        .expect("deferred");
}

/// A stand-in that accepts the TCP connection, holds it for `hold`, then drops
/// it: a transport failure the AMF classifies as "no SMF reachable", but one
/// that takes measurable time, so a test can tell the request's arrival from
/// the moment its first attempt failed. Returns its port and a stop flag.
async fn slow_to_fail_smf(hold: Duration) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    tokio::spawn(async move {
        while !flag.load(std::sync::atomic::Ordering::Acquire) {
            let Ok(Ok((sock, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                continue;
            };
            tokio::spawn(async move {
                tokio::time::sleep(hold).await;
                drop(sock);
            });
        }
    });
    (port, stop)
}

/// #877 re-review m2: the re-selection window runs from the request's ARRIVAL,
/// pinned through `handle_uplink_nas_transport` rather than at `defer_establishment`.
///
/// The first attempt takes `HOLD` to fail (off the NGAP task since #922), so a
/// window started at the failure would be `HOLD` shorter.
/// The assertion is on the recorded start, which must be within a few ms of the
/// instant before the handler was called.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn the_window_runs_from_arrival_through_the_uplink_nas_handler() {
    const HOLD: Duration = Duration::from_millis(400);
    let (port, stop) = slow_to_fail_smf(HOLD).await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_020u64, 105);
    ue_ready_for_sessions(&mut server, ue, ran);

    let before = std::time::Instant::now();
    server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &[0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF]),
        )
        .await
        .expect("handled");
    let after = std::time::Instant::now();
    let inline = after.duration_since(before);
    // #922: the first attempt runs off the NGAP task, so the handler does not
    // wait out the slow SMF.
    assert!(
        inline < HOLD,
        "the handler waited for the first attempt: {inline:?}"
    );
    // Let the slow attempt fail, so the window's start is read after it.
    settle_establishments(&mut server).await;
    let started = server.pending_establishments[&(ue, 5)].first_failure;
    assert!(
        started.duration_since(before) < Duration::from_millis(100),
        "the window must start at arrival ({:?} after it), not when the first \
         attempt failed (at least {HOLD:?} after it)",
        started.duration_since(before)
    );

    server.forget_ue(ue);
    stop.store(true, std::sync::atomic::Ordering::Release);
}

/// #877 re-review m1: a UE that goes CM-IDLE while an attempt is still waiting
/// for a concurrency permit frees the PSI's key at once, so a later request for
/// that session is not queued behind an attempt nobody waits for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn going_cm_idle_cancels_an_attempt_that_never_started() {
    // The SMF is down, and stays down: its port is held but never listens (#1050).
    let down = nextgcore_sbi::test_support::down_port();
    let _env = super::SmfEnvGuard::acquire(down.port()).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_796_021u64, 106);
    ue_ready_for_sessions(&mut server, ue, ran);
    defer_request(&mut server, ue, ran, &[0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF]).await;

    // Every permit is taken by other UEs' hanging exchanges, so this UE's next
    // attempt is spawned and waits.
    for other in 0..MAX_OFFLOADED_SBI as u64 {
        server
            .sbi_offload
            .spawn_keyed((7_796_900 + other, 1), || async {
                std::future::pending::<()>().await;
                None
            });
    }
    until_in_flight(&server, MAX_OFFLOADED_SBI).await;
    make_establishments_due(&mut server);
    server.process_pending_establishments().await;
    assert!(
        server.sbi_offload.key_busy((ue, 5)),
        "the attempt is waiting"
    );

    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    server.process_pending_establishments().await;

    assert!(!server.pending_establishments.contains_key(&(ue, 5)));
    assert!(
        !server.sbi_offload.key_busy((ue, 5)),
        "an attempt that never started must not keep the session's key"
    );
    for other in 0..MAX_OFFLOADED_SBI as u64 {
        server.forget_ue(7_796_900 + other);
    }
    server.forget_ue(ue);
}

// ---------------------------------------------------------------------------
// #757: N1N2MessageTransfer PDU_RES_SETUP_REQ / PDU_RES_MOD_REQ to a UE
// ---------------------------------------------------------------------------

/// Give the UE a SUPI, so the Namf surface resolves it.
pub(super) fn with_supi(server: &mut NgapServer, amf_ue_ngap_id: u64, supi: &str) {
    server.ue_auth_state.with_mut(amf_ue_ngap_id, |s| {
        s.amf_ue.supi = Some(supi.to_string());
    });
}

/// An N1N2MessageTransfer through the live Namf request handler. `n2` is the
/// `ngapIeType` and the transfer octets (absent: no `ngapData`, as smfd's
/// downlink-data request sends it). `n1` is the N1 SM message.
pub(super) async fn n1n2_transfer(
    supi: &str,
    psi: u8,
    n2: Option<(&str, Option<&[u8]>)>,
    n1: Option<&[u8]>,
) -> nextgcore_sbi::SbiResponse {
    use nextgcore_sbi::message::SbiPart;
    let mut body = serde_json::json!({ "pduSessionId": psi });
    if let Some((ie_type, data)) = n2 {
        body["n2InfoContainer"] = serde_json::json!({
            "n2InformationClass": "SM",
            "smInfo": {
                "pduSessionId": psi,
                "n2InfoContent": { "ngapIeType": ie_type },
            },
        });
        if data.is_some() {
            body["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"] =
                serde_json::json!({ "contentId": "ngap-sm" });
        }
    }
    if n1.is_some() {
        body["n1MessageContainer"] = serde_json::json!({
            "n1MessageClass": "SM",
            "n1MessageContent": { "contentId": "5gnas-sm" },
        });
    }
    let mut req =
        nextgcore_sbi::SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json");
    if let Some((_, Some(data))) = n2 {
        req = req.with_part(SbiPart::with_content(
            "ngap-sm",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::copy_from_slice(data),
        ));
    }
    if let Some(n1) = n1 {
        req = req.with_part(SbiPart::with_content(
            "5gnas-sm",
            "application/vnd.3gpp.5gnas",
            bytes::Bytes::copy_from_slice(n1),
        ));
    }
    crate::namf_request_handler(req).await
}

fn cause_of(resp: &nextgcore_sbi::SbiResponse) -> String {
    let body: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    body["cause"].as_str().unwrap_or_default().to_string()
}

/// The captured PDUs that concern `ue`, decoded. Other tests may enqueue
/// transfers for their own UEs on the shared queue, and the pump delivers those too.
pub(super) fn sent_to(server: &mut NgapServer, ue: u64) -> Vec<Sent> {
    take_sent_ngap(server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .filter(|s| match s {
            Sent::SetupRequest { amf_ue_ngap_id, .. }
            | Sent::ModifyRequest { amf_ue_ngap_id, .. }
            | Sent::ReleaseCommand { amf_ue_ngap_id, .. }
            | Sent::DownlinkNas { amf_ue_ngap_id, .. } => *amf_ue_ngap_id == ue,
            _ => false,
        })
        .collect()
}

const MOD_CMD: [u8; 5] = [0x2E, 0x02, 0x01, 0xCB, 0x59]; // PDU SESSION MODIFICATION COMMAND
const MOD_TRANSFER: [u8; 4] = [0x00, 0x00, 0x01, 0x7E];

/// #757 scenario 1: a CM-CONNECTED UE whose PSI 2 user plane is deactivated gets
/// smfd's downlink-data N1N2 (`PDU_RES_SETUP_REQ`, no N1, no transfer). The AMF
/// answers 200 N1_N2_TRANSFER_INITIATED and DELIVERS it: UpdateSMContext
/// ACTIVATING for PSI 2, then a PDU SESSION RESOURCE SETUP REQUEST with the
/// SMF's transfer (TS 23.502 §4.2.3.3 steps 4-5, TS 38.413 §8.2.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downlink_data_setup_request_for_a_connected_ue_activates_and_reaches_the_gnb() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_001u64, 57, "imsi-001010007570001");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 2, "n1n2-757-setup", port);

    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(cause_of(&resp), "N1_N2_TRANSFER_INITIATED");

    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    let calls = calls.lock().expect("calls").clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].0.ends_with("/sm-contexts/n1n2-757-setup/modify"));
    assert_eq!(calls[0].1["upCnxState"], "ACTIVATING");
    assert_eq!(
        sent_to(&mut server, ue),
        vec![Sent::SetupRequest {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            nas_pdu: None,
            items: vec![setup_item(2, transfer_for("n1n2-757-setup"))],
        }]
    );
}

/// A `PDU_RES_SETUP_REQ` that carries its transfer goes to the gNB as is, with no
/// N11 round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_request_with_a_transfer_is_sent_without_asking_the_smf() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_002u64, 58, "imsi-001010007570002");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 3, "n1n2-757-setup-t", port);

    let transfer = [0x00, 0x04, 0xAB, 0xCD];
    let resp = n1n2_transfer(supi, 3, Some(("PDU_RES_SETUP_REQ", Some(&transfer))), None).await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    assert!(calls.lock().expect("calls").is_empty());
    assert_eq!(
        sent_to(&mut server, ue),
        vec![Sent::SetupRequest {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            nas_pdu: None,
            items: vec![setup_item(3, transfer.to_vec())],
        }]
    );
}

/// #757 scenario 2, TS 23.502 §4.3.3.2 step 4: a network-requested PDU Session
/// Modification (`PDU_RES_MOD_REQ` + N1 PDU SESSION MODIFICATION COMMAND) to a
/// connected UE is ONE PDU SESSION RESOURCE MODIFY REQUEST. Its item carries the
/// transfer, and the N1 as a protected DL NAS Transport NAS-PDU.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_requested_modification_reaches_a_connected_ue_as_a_modify_request() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_003u64, 59, "imsi-001010007570003");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "n1n2-757-mod", port);

    let resp = n1n2_transfer(
        supi,
        1,
        Some(("PDU_RES_MOD_REQ", Some(&MOD_TRANSFER))),
        Some(&MOD_CMD),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(cause_of(&resp), "N1_N2_TRANSFER_INITIATED");
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;

    let sent = sent_to(&mut server, ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let Sent::ModifyRequest { items, .. } = &sent[0] else {
        panic!("a PDU SESSION RESOURCE MODIFY REQUEST, got {:?}", sent[0]);
    };
    assert_eq!(items.len(), 1);
    let (psi, nas, transfer) = &items[0];
    assert_eq!(*psi, 1);
    assert_eq!(transfer, &MOD_TRANSFER.to_vec());
    let nas = nas.as_deref().expect("the N1 rides the item's NAS-PDU");
    assert_eq!(
        dl_nas_message_type(nas),
        Some(message_type::DL_NAS_TRANSPORT)
    );
    assert!(
        nas.windows(MOD_CMD.len()).any(|w| w == MOD_CMD),
        "the DL NAS Transport carries the Modification Command: {nas:02x?}"
    );
}

/// A `PDU_RES_MOD_REQ` without an N1 or without its transfer is refused (400),
/// not acknowledged and dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modify_request_missing_its_n1_or_transfer_is_refused() {
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_004u64, 60, "imsi-001010007570004");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "n1n2-757-mod-bad", port);
    let no_n1 = n1n2_transfer(
        supi,
        1,
        Some(("PDU_RES_MOD_REQ", Some(&MOD_TRANSFER))),
        None,
    )
    .await;
    assert_eq!(no_n1.status, 400);
    let no_transfer = n1n2_transfer(supi, 1, Some(("PDU_RES_MOD_REQ", None)), Some(&MOD_CMD)).await;
    assert_eq!(no_transfer.status, 400);
}

/// #757 for a CM-IDLE UE: a modification is paged for (202 ATTEMPTING_TO_REACH_UE)
/// and kept as a MODIFY in the paging context, not answered 200 and dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modification_for_an_idle_ue_pages_it() {
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_005u64, 61, "imsi-001010007570005");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    hold_session(&mut server, ue, 1, "n1n2-757-mod-idle", port);

    let resp = n1n2_transfer(
        supi,
        1,
        Some(("PDU_RES_MOD_REQ", Some(&MOD_TRANSFER))),
        Some(&MOD_CMD),
    )
    .await;
    assert_eq!(resp.status, 202);
    assert_eq!(cause_of(&resp), "ATTEMPTING_TO_REACH_UE");
    let paged = crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(ue)
        .expect("paging queued");
    crate::context::amf_self().read().unwrap().paging_remove(ue);
    assert!(paged.pending_n2_modify && !paged.pending_n2_release);
    assert_eq!(paged.pending_n2.as_deref(), Some(&MOD_TRANSFER[..]));
    assert_eq!(paged.pending_n1.as_deref(), Some(&MOD_CMD[..]));
    assert_eq!(paged.pdu_session_id, Some(1));
}

/// #757's drain-time race: a transfer queued while the UE was connected, for a UE
/// that went CM-IDLE before the pump ran, is paged for. It is NOT sent to the
/// released NG connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transfer_queued_before_the_ue_went_idle_pages_it_instead_of_sending() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_757_006u64, 62, "imsi-001010007570006");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "n1n2-757-race", port);

    let resp = n1n2_transfer(
        supi,
        1,
        Some(("PDU_RES_MOD_REQ", Some(&MOD_TRANSFER))),
        Some(&MOD_CMD),
    )
    .await;
    assert_eq!(resp.status, 200);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;

    assert!(
        sent_to(&mut server, ue).is_empty(),
        "nothing on the released connection"
    );
    let paged = crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(ue)
        .expect("the UE is paged instead");
    crate::context::amf_self().read().unwrap().paging_remove(ue);
    assert!(paged.pending_n2_modify);
    assert_eq!(paged.pending_n2.as_deref(), Some(&MOD_TRANSFER[..]));
    assert_eq!(paged.pending_n1.as_deref(), Some(&MOD_CMD[..]));
}

/// #749: the same drain-time race while the UE is ALREADY being paged for
/// another transfer. The queued one does not overwrite that paging context
/// (that would lose the other transfer); it stays queued, and once the UE
/// answers the page it goes to the CM-CONNECTED UE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_transfer_waits_for_a_paging_already_ongoing() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_749_011u64, 64, "imsi-001010007490011");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "n1n2-749-queued", port);

    let resp = n1n2_transfer(
        supi,
        1,
        Some(("PDU_RES_MOD_REQ", Some(&MOD_TRANSFER))),
        Some(&MOD_CMD),
    )
    .await;
    assert_eq!(resp.status, 200);
    // The UE went idle and is already paged for PSI 2's downlink data.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    crate::context::amf_self()
        .read()
        .unwrap()
        .paging_add(crate::context::PagingContext {
            amf_ue_ngap_id: ue,
            pdu_session_id: Some(2),
            pending_n2: Some(vec![0x02]),
            ..Default::default()
        });
    server.process_connected_downlinks().await;

    let paged = crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(ue)
        .expect("still paged");
    assert_eq!(
        paged.pdu_session_id,
        Some(2),
        "PSI 2's paging is not overwritten"
    );
    assert!(sent_to(&mut server, ue).is_empty());

    // The UE answers: it is CM-CONNECTED, and the waiting transfer goes out.
    crate::context::amf_self().read().unwrap().paging_remove(ue);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = false);
    server.process_connected_downlinks().await;
    let sent = sent_to(&mut server, ue);
    assert!(
        sent.iter().any(
            |s| matches!(s, Sent::ModifyRequest { amf_ue_ngap_id, .. } if *amf_ue_ngap_id == ue)
        ),
        "the waiting modification reaches the connected UE: {sent:?}"
    );
    server.forget_ue(ue);
}

/// A paged modification is delivered after the Service Request as its own
/// MODIFY REQUEST. Delivering it as a bare DL NAS Transport would lose the N2 half.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paged_modification_is_delivered_as_a_modify_request_after_the_service_request() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_757_007u64, 63);
    secured_registered_ue(&mut server, ue, ran);
    let paging = crate::context::PagingContext {
        amf_ue_ngap_id: ue,
        pending_n1: Some(MOD_CMD.to_vec()),
        pending_n2: Some(MOD_TRANSFER.to_vec()),
        pending_n2_modify: true,
        pdu_session_id: Some(4),
        ..Default::default()
    };
    // The Service Request's Initial Context Setup set PSI 4 up.
    server.mark_up_active(ue, 4);
    server
        .deliver_paged_after_service_request(ASSOC, ue, ran, &paging)
        .await
        .expect("delivered");
    let sent = sent_to(&mut server, ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let Sent::ModifyRequest { items, .. } = &sent[0] else {
        panic!("a MODIFY REQUEST, got {:?}", sent[0]);
    };
    assert_eq!(items[0].0, 4);
    assert_eq!(items[0].2, MOD_TRANSFER.to_vec());
    assert!(items[0].1.is_some());
}

// ---------------------------------------------------------------------------
// #778 review: duplicate setups, failure paths, item NAS-PDU, paged modify e2e
// ---------------------------------------------------------------------------

/// Per item of a captured PDU SESSION RESOURCE SETUP REQUEST: `(psi, the item's
/// PDU Session NAS-PDU)`. Empty for any other PDU.
fn setup_item_nas_pdus(pdu: &[u8]) -> Vec<(u8, Option<Vec<u8>>)> {
    use g::PDUSessionResourceSetupRequestProtocolIEs_EntryValue as V;
    let Ok(g::NGAP_PDU::InitiatingMessage(m)) = nextgcore_ngap_gen::decode(pdu) else {
        return Vec::new();
    };
    let g::InitiatingMessageValue::Id_PDUSessionResourceSetup(req) = m.value else {
        return Vec::new();
    };
    req.protocol_i_es
        .0
        .into_iter()
        .filter_map(|ie| match ie.value {
            V::Id_PDUSessionResourceSetupListSUReq(l) => Some(l.0),
            _ => None,
        })
        .flatten()
        .map(|it| (it.pdu_session_id.0, it.pdu_session_nas_pdu.map(|n| n.0)))
        .collect()
}

/// The `upCnxState`s the stand-in SMF saw for `sm_ref`, in order.
fn up_cnx_states(calls: &[SmfCall], sm_ref: &str) -> Vec<String> {
    calls
        .iter()
        .filter(|(u, _)| u.ends_with(&format!("/sm-contexts/{sm_ref}/modify")))
        .filter_map(|(_, b)| b["upCnxState"].as_str().map(str::to_string))
        .collect()
}

/// #778 review M1. A connected Service Request re-activates PSI 2 while smfd's
/// downlink-data N1N2 for PSI 2 is queued; smfd checked DEACTIVATED before the
/// Service Request's ACTIVATING. The drained transfer must NOT cause a second
/// ACTIVATING and a second setup: the gNB would refuse the duplicate of an
/// active session (TS 38.413 §8.2.1.4), and the relayed failure would have smfd
/// deactivate the working downlink. Exactly one ACTIVATING and one setup.
/// A third, retransmitted transfer is coalesced the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_downlink_setup_for_a_session_the_service_request_activated_is_not_sent_again() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_778_001u64, 71, "imsi-001010007780001");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 2, "dup-778-2", port);

    // smfd's request is accepted and queued first ...
    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    let retx = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(retx.status, 200);
    // ... then the UE's Service Request re-activates PSI 2 before the pump runs.
    let sr = connected_service_request(&mut server, ue, ran, Some(1 << 2)).await;
    assert!(
        matches!(&sr[..], [(_, Sent::SetupRequest { .. })]),
        "the Service Request's own setup: {sr:?}"
    );
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;

    let calls = calls.lock().expect("calls").clone();
    assert_eq!(
        up_cnx_states(&calls, "dup-778-2"),
        vec!["ACTIVATING".to_string()],
        "one activation, the Service Request's: {calls:?}"
    );
    assert!(
        sent_to(&mut server, ue).is_empty(),
        "no second PDU SESSION RESOURCE SETUP REQUEST for the active PSI"
    );
}

/// The flag is per NG connection: after an AN release has ended PSI 2's user
/// plane, a new downlink-data request for it is set up again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_an_an_release_a_downlink_setup_is_sent_again() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_778_002u64, 72, "imsi-001010007780002");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 2, "dup-778-again", port);
    server.mark_up_active(ue, 2);
    // The AN release ends the user plane (and deactivates it at the SMF).
    server.deactivate_up_connections(ue).await;
    // #922: the DEACTIVATED runs off the NGAP task.
    settle_offloaded_sbi(&mut server).await;
    calls.lock().expect("calls").clear();

    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    assert_eq!(
        up_cnx_states(&calls.lock().expect("calls"), "dup-778-again"),
        vec!["ACTIVATING".to_string()]
    );
    assert!(matches!(
        &sent_to(&mut server, ue)[..],
        [Sent::SetupRequest { .. }]
    ));
}

/// #778 review m1. An N1 that cannot be protected (the UE has no NAS security
/// context) is found BEFORE ACTIVATING: the SMF is left alone, not stranded in
/// ACTIVATING, and nothing goes to the gNB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unprotectable_n1_does_not_activate_the_user_plane() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_778_003u64, 73, "imsi-001010007780003");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.security_context_available = false;
    });
    hold_session(&mut server, ue, 2, "noprot-778", port);

    let n1 = [0x2E, 0x02, 0x01, 0xC2];
    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), Some(&n1)).await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    assert!(
        calls.lock().expect("calls").is_empty(),
        "no ACTIVATING for a setup that cannot carry its N1"
    );
    assert!(sent_to(&mut server, ue).is_empty());
}

/// #778 review m1. ACTIVATING succeeded but the setup does not go out (here the
/// SCTP send fails): the activation is rolled back with upCnxState DEACTIVATED,
/// so the SMF buffers and reports downlink data again rather than waiting in
/// ACTIVATING.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_that_does_not_go_out_rolls_the_activation_back() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_778_004u64, 74, "imsi-001010007780004");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 2, "rollback-778", port);

    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    server.fail_next_sends = 1;
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    assert_eq!(
        up_cnx_states(&calls.lock().expect("calls"), "rollback-778"),
        vec!["ACTIVATING".to_string(), "DEACTIVATED".to_string()]
    );
    assert!(
        !server.up_active.contains(&(ue, 2)),
        "a setup that did not go out does not mark the PSI active"
    );
}

/// #778 review m3. A `PDU_RES_SETUP_REQ` with an N1 5GSM message for the
/// session: the N1 is the ITEM's PDU Session NAS-PDU (TS 38.413 §9.2.1.1, TS
/// 23.502 §4.3.2.2.1 step 12), tied to that session's outcome, and there is no
/// message-level NAS-PDU.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_requests_n1_rides_the_items_pdu_session_nas_pdu() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_778_005u64, 75, "imsi-001010007780005");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 3, "itemnas-778", port);

    let n1 = [0x2E, 0x03, 0x01, 0xC2, 0x77];
    let transfer = [0x00, 0x04, 0xAB, 0xCD];
    let resp = n1n2_transfer(
        supi,
        3,
        Some(("PDU_RES_SETUP_REQ", Some(&transfer))),
        Some(&n1),
    )
    .await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;
    settle_offloaded_sbi(&mut server).await;
    let mine: Vec<Vec<u8>> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| p)
        .filter(|p| matches!(decode_sent(p), Sent::SetupRequest { amf_ue_ngap_id, .. } if amf_ue_ngap_id == ue))
        .collect();
    assert_eq!(mine.len(), 1);
    let Sent::SetupRequest { nas_pdu, .. } = decode_sent(&mine[0]) else {
        unreachable!()
    };
    assert_eq!(nas_pdu, None, "no message-level NAS-PDU");
    let items = setup_item_nas_pdus(&mine[0]);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].0, 3);
    let nas = items[0]
        .1
        .as_deref()
        .expect("the item's PDU Session NAS-PDU");
    assert_eq!(
        dl_nas_message_type(nas),
        Some(message_type::DL_NAS_TRANSPORT)
    );
    assert!(nas.windows(n1.len()).any(|w| w == n1), "{nas:02x?}");
}

/// Serve one GUAMI for the paged-modification tests' Initial Context Setup,
/// restoring the previous list on drop.
pub(super) struct ServeOneGuami(Vec<crate::context::Guami>);

impl ServeOneGuami {
    pub(super) fn install() -> Self {
        let ctx = crate::context::amf_self();
        let mut guard = ctx.write().unwrap_or_else(|e| e.into_inner());
        let previous = std::mem::replace(
            &mut guard.served_guami,
            vec![crate::context::Guami {
                plmn_id: PlmnId::new("001", "01"),
                amf_id: crate::context::AmfId {
                    region: 0x02,
                    set: 0x155,
                    pointer: 0x2A,
                },
            }],
        );
        Self(previous)
    }
}

impl Drop for ServeOneGuami {
    fn drop(&mut self) {
        let ctx = crate::context::amf_self();
        ctx.write().unwrap_or_else(|e| e.into_inner()).served_guami = std::mem::take(&mut self.0);
    }
}

/// Page the CM-IDLE UE `old_id` for a modification of PSI 1 (held as `sm_ref`),
/// answer the page with a Service Request in an Initial UE Message, and return
/// the decoded NGAP and the SMF calls.
async fn paged_modification_answered(
    old_id: u64,
    new_id: u64,
    sm_ref: &str,
) -> (Vec<(Vec<u8>, Sent)>, Vec<SmfCall>) {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let mut ue = super::idle_registered_ue(old_id);
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    server.ue_auth_state.insert(old_id, ue);
    hold_session(&mut server, old_id, 1, sm_ref, port);
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let mut paging = super::paged_ue(old_id, 4);
        paging.pdu_session_id = Some(1);
        paging.pending_n1 = Some(MOD_CMD.to_vec());
        paging.pending_n2 = Some(MOD_TRANSFER.to_vec());
        paging.pending_n2_modify = true;
        guard.paging_add(paging);
    }
    server.forced_amf_ue_ngap_id = Some(new_id);
    let pdu =
        super::service_request_initial_ue(super::protected_service_request([0; 4], old_id as u32));
    let _ = server.handle_initial_ue_message(ASSOC, &pdu).await;
    settle_offloaded_sbi(&mut server).await;
    let sent = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| {
            let d = decode_sent(&p);
            (p, d)
        })
        .collect();
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        guard.paging_remove(old_id);
        guard.paging_remove(new_id);
    }
    server.forget_ue(new_id);
    let calls = calls.lock().expect("calls").clone();
    (sent, calls)
}

/// #778 review m4, end to end. A CM-IDLE UE is paged for a modification of
/// PSI 1 and answers with a Service Request. The AMF re-activates PSI 1
/// (ACTIVATING) and sends it in the Initial Context Setup, then sends the
/// modification as a PDU SESSION RESOURCE MODIFY REQUEST, in that order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// CONTEXT_GUARD is held across the awaits on purpose: `served_guami` is
// process-global and this exchange needs its own.
#[allow(clippy::await_holding_lock)]
async fn a_paged_modification_rides_after_an_ics_that_set_its_session_up() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (sent, calls) = paged_modification_answered(7_778_011, 7_778_012, "pmod-778-ok").await;
    assert_eq!(
        up_cnx_states(&calls, "pmod-778-ok"),
        vec!["ACTIVATING".to_string()]
    );
    let codes: Vec<&Sent> = sent.iter().map(|(_, d)| d).collect();
    assert_eq!(codes.len(), 2, "{codes:?}");
    assert_eq!(
        codes[0],
        &Sent::Other(Some(14)),
        "the Initial Context Setup first: {codes:?}"
    );
    let Sent::ModifyRequest { items, .. } = codes[1] else {
        panic!("then a MODIFY REQUEST: {codes:?}");
    };
    assert_eq!(items[0].0, 1);
    assert_eq!(items[0].2, MOD_TRANSFER.to_vec());
}

/// The other half: the SMF refuses to activate PSI 1, so the Initial Context
/// Setup does not carry it and the gNB has no such session. No Modify Request
/// goes to it. The Modification Command still reaches the UE, alone in a DL
/// NAS Transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_paged_modification_of_a_session_not_set_up_sends_only_the_n1() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (sent, _calls) = paged_modification_answered(7_778_021, 7_778_022, "fail-pmod-778").await;
    let codes: Vec<&Sent> = sent.iter().map(|(_, d)| d).collect();
    assert_eq!(codes.len(), 2, "{codes:?}");
    assert_eq!(codes[0], &Sent::Other(Some(14)));
    let Sent::DownlinkNas { nas_pdu, .. } = codes[1] else {
        panic!("then the N1 alone: {codes:?}");
    };
    assert!(
        nas_pdu.windows(MOD_CMD.len()).any(|w| w == MOD_CMD),
        "{nas_pdu:02x?}"
    );
}

// ---------------------------------------------------------------------------
// #756: per-session state is pruned when the UE or the session goes away
// ---------------------------------------------------------------------------

/// What the AMF still holds for `ue`: `(sm_context_refs, sm_context_smfs, sess_list)`.
fn session_state_of(server: &NgapServer, ue: u64) -> (usize, usize, usize) {
    let refs = server
        .sm_context_refs
        .keys()
        .filter(|(u, _)| *u == ue)
        .count();
    let smfs = server
        .sm_context_smfs
        .keys()
        .filter(|(u, _)| *u == ue)
        .count();
    let sess = crate::context::amf_self()
        .read()
        .unwrap()
        .sess_list_for_ue(ue)
        .len();
    (refs, smfs, sess)
}

/// A UE-initiated (switch-off) DEREGISTRATION REQUEST, TS 24.501 §8.2.12.
pub(super) fn switch_off_deregistration_request() -> Vec<u8> {
    vec![
        0x7E,
        security_header::PLAIN_NAS_MESSAGE,
        message_type::DEREGISTRATION_REQUEST_FROM_UE,
        0x09, // switch off, 3GPP access; ngKSI 0
        0x00,
        0x0B,
        0xF2, // 5G-GUTI
        0x00,
        0xF1,
        0x10,
        0x02,
        0x00,
        0x40,
        0x11,
        0x22,
        0x33,
        0x44,
    ]
}

/// #756: register, open two sessions, deregister. All three stores are empty for
/// the UE afterwards, and both sessions were released at the SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deregistered_ue_leaves_no_session_state_behind() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_756_001u64, 56);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "prune-756-1", port);
    hold_session(&mut server, ue, 2, "prune-756-2", port);
    assert_eq!(session_state_of(&server, ue), (2, 2, 2));

    let dereg = ue_protect(&switch_off_deregistration_request(), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &dereg))
        .await
        .expect("handled");
    // #922: the releases run off the NGAP task.
    settle_offloaded_sbi(&mut server).await;

    let released: Vec<String> = calls
        .lock()
        .expect("calls")
        .iter()
        .map(|(u, _)| u.clone())
        .filter(|u| u.ends_with("/release"))
        .collect();
    assert_eq!(
        released.len(),
        2,
        "both sessions released at the SMF: {released:?}"
    );
    assert_eq!(
        session_state_of(&server, ue),
        (0, 0, 0),
        "no sm_context_refs, sm_context_smfs or sess_list entry survives the UE"
    );
    assert!(!server.ue_auth_state.contains(ue));
}

/// The UE-requested PDU Session Release (0xD1) forgets that PSI and only that PSI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_pdu_session_is_forgotten_and_its_sibling_kept() {
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_756_002u64, 57);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "prune-756-rel-1", port);
    hold_session(&mut server, ue, 2, "prune-756-rel-2", port);

    // A raw 5GSM PDU SESSION RELEASE REQUEST for PSI 1 (the legacy 0x2E path).
    let release_request = [0x2E, 0x01, 0x07, 0xD1];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &release_request))
        .await
        .expect("handled");
    assert_eq!(session_state_of(&server, ue), (1, 1, 1));
    assert!(
        server.sm_context_refs.contains_key(&(ue, 2)),
        "PSI 2 is untouched"
    );
    assert!(!server.sm_context_refs.contains_key(&(ue, 1)));
}

/// The orphan sweep drops refs whose session the SBI task removed (the SMF's
/// RELEASED notify) or whose UE is gone, and keeps live ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_drops_orphaned_session_state_and_keeps_live_state() {
    let mut server = capturing_ngap_server().await;
    let (live, gone) = (7_756_003u64, 7_756_004u64);
    secured_registered_ue(&mut server, live, 58);
    hold_session(&mut server, live, 1, "sweep-756-live", 7777);
    hold_session(&mut server, live, 2, "sweep-756-released", 7777);
    secured_registered_ue(&mut server, gone, 59);
    hold_session(&mut server, gone, 1, "sweep-756-gone", 7777);

    // RELEASED for live/PSI 2 arrives on the SBI task: only sess_list loses it.
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap();
        let s = guard.sess_find_by_psi(live, 2).expect("held");
        guard.sess_remove(s.id);
    }
    // The other UE's NAS context disappears without forget_ue.
    server.ue_auth_state.remove(gone);

    server.sweep_orphaned_session_state();
    assert!(server.sm_context_refs.contains_key(&(live, 1)));
    assert!(server.sm_context_smfs.contains_key(&(live, 1)));
    assert!(!server.sm_context_refs.contains_key(&(live, 2)));
    assert!(!server.sm_context_smfs.contains_key(&(live, 2)));
    assert!(!server.sm_context_refs.contains_key(&(gone, 1)));
    assert!(!server.sm_context_smfs.contains_key(&(gone, 1)));
    // Tidy the global table for the UE whose NAS context the test removed.
    server.forget_ue_sessions(gone);
}

/// A raw 5GSM PDU SESSION ESTABLISHMENT REQUEST for `psi` (the legacy 0x2E
/// path): PTI 1, integrity protection maximum data rate full.
pub(super) fn establishment_request(psi: u8) -> Vec<u8> {
    vec![0x2E, psi, 0x01, 0xC1, 0xFF, 0xFF]
}

/// Establish PSI 5 for a connected `ue` through the Uplink NAS Transport dispatch,
/// with `fail_record` forcing the session record to fail as a full table would.
/// Returns the SMF calls and the decoded NGAP.
// `SmfEnvGuard` is held across the awaits on purpose: the SMF address is a
// process environment variable, read during the establishment.
#[allow(clippy::await_holding_lock)]
async fn establish_psi_5(
    fail_record: bool,
    ue: u64,
    ran: u32,
) -> (Vec<SmfCall>, Vec<Sent>, (usize, usize, usize)) {
    let (_smf, port, calls) = activating_smf().await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    secured_registered_ue(&mut server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.initial_context_setup_response_received = true;
    });
    server.fail_next_session_record = fail_record;
    server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &establishment_request(5)),
        )
        .await
        .expect("handled");
    // #922: the CreateSMContext runs off the NGAP task, and so does the
    // unrecorded session's SMF release.
    settle_establishments(&mut server).await;
    server.sbi_offload.settle().await;
    let sent = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let state = session_state_of(&server, ue);
    server.forget_ue_sessions(ue);
    server.ue_auth_state.remove(ue);
    let calls = calls.lock().expect("calls").clone();
    (calls, sent, state)
}

/// #756 review m1. A session the AMF cannot record (its session table is full)
/// is not established. Otherwise the AMF could never page, modify, re-activate
/// or release it, and the sweep would drop its refs within 10 s, leaking it at
/// the SMF and UPF. The AMF releases it at the SMF, does not relay the SMF's
/// Accept, and sends the 5GSM message back to the UE in a DL NAS Transport with
/// 5GMM #90 "payload was not forwarded" (TS 24.501 §5.4.5.2.5, §5.4.5.3.1 e)).
/// Nothing is left for the UE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_the_amf_cannot_record_is_released_and_refused() {
    let (calls, sent, state) = establish_psi_5(true, 7_756_011, 61).await;
    let uris: Vec<&str> = calls.iter().map(|(u, _)| u.as_str()).collect();
    assert_eq!(
        uris.iter()
            .filter(|u| u.ends_with("/nsmf-pdusession/v1/sm-contexts"))
            .count(),
        1,
        "{uris:?}"
    );
    assert!(
        uris.iter()
            .any(|u| u.ends_with("/sm-contexts/est-5/release")),
        "the unrecorded session is released at the SMF: {uris:?}"
    );
    let [Sent::DownlinkNas { nas_pdu, .. }] = sent.as_slice() else {
        panic!("one DL NAS Transport and no setup request: {sent:?}");
    };
    use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
    let Ok(FiveGmmMessage::DlNasTransport(dl)) =
        parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&nas_pdu[7..]))
    else {
        panic!("a DL NAS TRANSPORT: {nas_pdu:02x?}");
    };
    assert_eq!(dl.gmm_cause, Some(90), "5GMM #90 payload was not forwarded");
    assert_eq!(
        dl.payload_container.data.first(),
        Some(&0x2E),
        "the UE's own 5GSM message comes back, not the SMF's Accept"
    );
    assert_eq!(dl.payload_container.data.get(3), Some(&0xC1));
    assert_eq!(state, (0, 0, 0), "nothing is left for the UE");
}

/// The positive control for the test above: with the record succeeding, the
/// same establishment is recorded in all three stores and nothing is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recorded_session_is_established() {
    let (calls, _sent, state) = establish_psi_5(false, 7_756_012, 62).await;
    assert!(
        !calls.iter().any(|(u, _)| u.ends_with("/release")),
        "{calls:?}"
    );
    assert_eq!(state, (1, 1, 1));
}

/// #756 review m4. Implicit deregistration (TS 24.501 §5.3.7) releases every
/// session at its SMF BEFORE the UE's per-session state is pruned: two
/// `/release` calls, then nothing left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// The reachability sweep lock is held across the awaits on purpose: the sweep
// walks the shared store, and no sibling sweep may run in between.
#[allow(clippy::await_holding_lock)]
async fn an_implicit_deregistration_releases_at_the_smf_then_prunes() {
    let _sweep = crate::context::REACHABILITY_SWEEP_TEST_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_756_021u64, 63);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "implicit-756-1", port);
    hold_session(&mut server, ue, 2, "implicit-756-2", port);
    server.ue_auth_state.with_mut(ue, |s| {
        s.cm_idle = true;
        s.reachability = Some(Reachability {
            phase: ReachabilityPhase::ImplicitDeregistration,
            deadline: Instant::now() - Duration::from_secs(1),
        });
    });

    server
        .process_reachability_timers()
        .await
        .expect("implicit deregistration");
    // #922: the releases run off the NGAP task.
    settle_offloaded_sbi(&mut server).await;

    let mut released: Vec<String> = calls
        .lock()
        .expect("calls")
        .iter()
        .map(|(u, _)| u.clone())
        .filter(|u| u.ends_with("/release"))
        .collect();
    released.sort();
    assert_eq!(
        released
            .iter()
            .map(|u| u.rsplit("/sm-contexts/").next().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["implicit-756-1/release", "implicit-756-2/release"],
        "each session is released at the SMF holding it"
    );
    assert_eq!(session_state_of(&server, ue), (0, 0, 0));
    assert!(!server.ue_auth_state.contains(ue));
}

// ---------------------------------------------------------------------------
// #758: an Uplink NAS Transport for an AMF UE NGAP ID never allocated here
// ---------------------------------------------------------------------------

/// The radio-network causes of the Error Indications in `sent`.
fn error_indication_causes(sent: Vec<(u64, Vec<u8>)>) -> Vec<Option<u8>> {
    sent.into_iter()
        .filter_map(|(_, p)| match decode_sent(&p) {
            Sent::ErrorIndication {
                radio_network_cause,
            } => Some(radio_network_cause),
            _ => None,
        })
        .collect()
}

fn plain_initial_registration(amf_ue_ngap_id: u64, ran: u32) -> Vec<u8> {
    uplink_nas_transport(amf_ue_ngap_id, ran, &super::sample_registration_request())
}

/// #758: a gNB names an AMF UE NGAP ID this AMF never allocated, with a plain
/// initial Registration Request. No NAS context is created (the ID could later be
/// allocated to another UE). The AMF answers an Error Indication "Unknown local UE
/// NGAP ID" (TS 38.413 §10.6), and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initial_registration_under_an_unallocated_id_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    let invented = 7_758_001u64;
    server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(invented, 58))
        .await
        .expect("handled");
    assert!(
        !server.ue_auth_state.contains(invented),
        "no context for an invented ID"
    );
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, ASSOC);
    assert_eq!(
        error_indication_causes(sent),
        vec![Some(g::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID)]
    );
}

/// The ID IS allocated with no context (a Service Request rejected #9), but the
/// Uplink NAS Transport names another RAN UE NGAP ID on the same association. That
/// is "Inconsistent remote UE NGAP ID"; on another association it is "Unknown
/// local UE NGAP ID". No context is created either way. The genuine connection keeps its
/// allocation and is taken up afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initial_registration_on_another_connection_than_the_allocation_is_refused() {
    let mut server = capturing_ngap_server().await;
    let id = 7_758_002u64;
    server.forced_amf_ue_ngap_id = Some(id);
    server
        .handle_initial_ue_message(
            ASSOC,
            &super::service_request_initial_ue(service_request(None)),
        )
        .await
        .expect("rejected #9");
    take_sent_ngap(&mut server);
    assert!(!server.ue_auth_state.contains(id));

    // Wrong RAN UE NGAP ID (the allocation is for 512).
    server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(id, 513))
        .await
        .expect("handled");
    assert!(!server.ue_auth_state.contains(id));
    assert_eq!(
        error_indication_causes(take_sent_ngap(&mut server)),
        vec![Some(g::CauseRadioNetwork::INCONSISTENT_REMOTE_UE_NGAP_ID)]
    );
    // Wrong association: there the ID names no logical connection at all, so it
    // is an unknown LOCAL ID (TS 38.413 §10.6), and the answer does not tell that
    // gNB the ID is live elsewhere.
    server
        .handle_uplink_nas_transport(ASSOC + 1, &plain_initial_registration(id, 512))
        .await
        .expect("handled");
    assert!(!server.ue_auth_state.contains(id));
    assert_eq!(
        error_indication_causes(take_sent_ngap(&mut server)),
        vec![Some(g::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID)]
    );

    // The genuine connection's registration is taken up, once.
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(id, 512))
        .await;
    assert!(
        server.ue_auth_state.contains(id),
        "the allocated connection registers"
    );
    server.ue_auth_state.remove(id);
    take_sent_ngap(&mut server);
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(id, 512))
        .await;
    assert!(
        !server.ue_auth_state.contains(id),
        "the allocation is consumed: a second context is not minted under it"
    );
}

/// A gNB inventing IDs cannot grow the allocation record without bound: it is
/// capped, oldest first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_contextless_allocation_record_is_bounded() {
    let mut server = capturing_ngap_server().await;
    for i in 0..(MAX_CONTEXTLESS_UE_IDS as u64 + 10) {
        server.remember_contextless_ue_id(ASSOC, 9_000_000 + i, 1);
    }
    assert_eq!(server.contextless_ue_ids.len(), MAX_CONTEXTLESS_UE_IDS);
    assert_eq!(
        server.take_contextless_ue_id(ASSOC, 9_000_000, 1),
        ContextlessLookup::Unknown,
        "the oldest went first"
    );
}

/// The plain-dispatch SERVICE REQUEST arm of the Initial UE Message: a message
/// whose third octet is 0x4C but which is neither a plain nor a type-1 Service
/// Request (here security header type 3, so octet 3 is a MAC octet). It is
/// answered SERVICE REJECT #9 like the others, and the ID it allocated is
/// recorded, so the UE's re-registration on that connection is taken up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_plain_dispatch_service_request_arm_records_its_allocation() {
    let mut server = capturing_ngap_server().await;
    let id = 7_758_011u64;
    server.forced_amf_ue_ngap_id = Some(id);
    let odd = vec![
        0x7E,
        0x03,
        message_type::SERVICE_REQUEST,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(odd))
        .await
        .expect("rejected #9");
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = sent.as_slice() else {
        panic!("one DL NAS Transport, the Service Reject: {sent:?}");
    };
    assert_eq!(nas_pdu.get(2), Some(&message_type::SERVICE_REJECT));
    assert!(!server.ue_auth_state.contains(id));

    let _ = server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(id, 512))
        .await;
    assert!(
        server.ue_auth_state.contains(id),
        "the re-registration on the allocated connection is taken up"
    );
    server.ue_auth_state.remove(id);
}

/// A released NG connection loses its contextless allocation: after the UE
/// Context Release Complete for the ID, the same gNB cannot mint a context under
/// it. It gets an Error Indication "Unknown local UE NGAP ID".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_connection_loses_its_contextless_allocation() {
    let mut server = capturing_ngap_server().await;
    let id = 7_758_021u64;
    server.forced_amf_ue_ngap_id = Some(id);
    server
        .handle_initial_ue_message(
            ASSOC,
            &super::service_request_initial_ue(service_request(None)),
        )
        .await
        .expect("rejected #9");
    take_sent_ngap(&mut server);

    let complete = nextgcore_ngap::builder::build_ue_context_release_complete(
        &nextgcore_ngap::types::UeContextReleaseComplete {
            amf_ue_ngap_id: id,
            ran_ue_ngap_id: 512,
        },
    )
    .expect("encode a UE Context Release Complete");
    server
        .handle_ue_context_release_complete(ASSOC, &complete)
        .await
        .expect("handled");
    take_sent_ngap(&mut server);

    server
        .handle_uplink_nas_transport(ASSOC, &plain_initial_registration(id, 512))
        .await
        .expect("handled");
    assert!(!server.ue_auth_state.contains(id));
    assert_eq!(
        error_indication_causes(take_sent_ngap(&mut server)),
        vec![Some(g::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID)]
    );
}

/// An NG Reset drops the contextless allocations of the connections it resets:
/// a partial reset only those its items name (by either ID) on the resetting
/// association, a whole reset every one on that association. Another
/// association's allocation is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_reset_drops_the_contextless_allocations_it_resets() {
    use nextgcore_ngap::types::{
        Cause, CauseTransport, NgReset, ResetType, UeAssociatedLogicalNgConnectionItem,
    };
    let mut server = capturing_ngap_server().await;
    // Its own association (and so gNB pool id): an NG Reset also resets the
    // process-global RAN UE bookkeeping of that gNB, which the other tests here
    // share on [`ASSOC`].
    let assoc = 758_041u64;
    super::seed_gnb_session(&server, assoc).await;
    let other = assoc + 7;
    server.remember_contextless_ue_id(assoc, 7_758_031, 31);
    server.remember_contextless_ue_id(assoc, 7_758_032, 32);
    server.remember_contextless_ue_id(assoc, 7_758_033, 33);
    server.remember_contextless_ue_id(other, 7_758_034, 31);
    let reset = |reset_type| {
        nextgcore_ngap::builder::build_ng_reset(&NgReset {
            cause: Cause::Transport(CauseTransport::TransportResourceUnavailable),
            reset_type,
        })
        .expect("encode an NG Reset")
    };

    let partial = reset(ResetType::PartOfNgInterface(vec![
        UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id: Some(7_758_031),
            ran_ue_ngap_id: None,
        },
        UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id: None,
            ran_ue_ngap_id: Some(32),
        },
    ]));
    let _ = server.handle_ng_reset(assoc, &partial).await;
    let held: Vec<u64> = server
        .contextless_ue_ids
        .iter()
        .map(|c| c.amf_ue_ngap_id)
        .collect();
    assert_eq!(
        held,
        vec![7_758_033, 7_758_034],
        "the two named connections are dropped, by AMF and by RAN UE NGAP ID"
    );

    let _ = server
        .handle_ng_reset(assoc, &reset(ResetType::NgInterface))
        .await;
    let held: Vec<u64> = server
        .contextless_ue_ids
        .iter()
        .map(|c| c.amf_ue_ngap_id)
        .collect();
    assert_eq!(
        held,
        vec![7_758_034],
        "only the other association's is left"
    );
    take_sent_ngap(&mut server);
}

// ---- #739: the UE-association gate (TS 38.413 §10.6) ----

/// An ERROR INDICATION's `(amf id, ran id, radio-network cause)`, decoded with the
/// generated codec; `None` for any other PDU.
fn decoded_error_indication(pdu: &[u8]) -> Option<(Option<u64>, Option<u32>, Option<u8>)> {
    let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let g::InitiatingMessageValue::Id_ErrorIndication(e) = m.value else {
        return None;
    };
    let (mut amf, mut ran, mut cause) = (None, None, None);
    for ie in e.protocol_i_es.0 {
        use g::ErrorIndicationProtocolIEs_EntryValue as Ie;
        match ie.value {
            Ie::Id_AMF_UE_NGAP_ID(id) => amf = Some(id.0),
            Ie::Id_RAN_UE_NGAP_ID(id) => ran = Some(id.0),
            Ie::Id_Cause(g::Cause::RadioNetwork(c)) => cause = Some(c.0),
            _ => {}
        }
    }
    Some((amf, ran, cause))
}

/// Every gNB->AMF UE-associated message of the #739 table and of the #787 / #805
/// follow-ups, naming `(amf, ran)`.
fn ue_associated_uplinks(amf: u64, ran: u32) -> Vec<(&'static str, Vec<u8>)> {
    use nextgcore_ngap::builder as b;
    use nextgcore_ngap::types as t;
    let uli = super::test_user_location(1, 0x10);
    let radio_cap = nextgcore_ngap_gen::encode(&g::NGAP_PDU::InitiatingMessage(
        g::InitiatingMessage {
            procedure_code: g::ProcedureCode(g::ID_UE_RADIO_CAPABILITY_INFO_INDICATION),
            criticality: g::Criticality(g::Criticality::IGNORE),
            value: g::InitiatingMessageValue::Id_UERadioCapabilityInfoIndication(
                g::UERadioCapabilityInfoIndication {
                    protocol_i_es: g::UERadioCapabilityInfoIndicationProtocolIEs(vec![
                        g::UERadioCapabilityInfoIndicationProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(g::ID_AMF_UE_NGAP_ID),
                            criticality: g::Criticality(g::Criticality::REJECT),
                            value: g::UERadioCapabilityInfoIndicationProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                                g::AMF_UE_NGAP_ID(amf),
                            ),
                        },
                        g::UERadioCapabilityInfoIndicationProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(g::ID_RAN_UE_NGAP_ID),
                            criticality: g::Criticality(g::Criticality::REJECT),
                            value: g::UERadioCapabilityInfoIndicationProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(
                                g::RAN_UE_NGAP_ID(ran),
                            ),
                        },
                        g::UERadioCapabilityInfoIndicationProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(g::ID_UE_RADIO_CAPABILITY),
                            criticality: g::Criticality(g::Criticality::IGNORE),
                            value: g::UERadioCapabilityInfoIndicationProtocolIEs_EntryValue::Id_UERadioCapability(
                                g::UERadioCapability(vec![0x07, 0x39]),
                            ),
                        },
                    ]),
                },
            ),
        },
    ))
    .expect("encode UERadioCapabilityInfoIndication");
    let nrppa = {
        use nextgcore_asn1c::ngap::ies::{AmfUeNgapId, NrppaPdu, RanUeNgapId, RoutingId};
        use nextgcore_asn1c::ngap::pdu::build_uplink_ue_associated_nrppa_transport;
        super::encode_ngap_pdu(
            &build_uplink_ue_associated_nrppa_transport(
                AmfUeNgapId(amf),
                RanUeNgapId(ran),
                RoutingId::new(b"lmf-739".to_vec()),
                NrppaPdu::new(vec![0x20, 0x0B, 0x00]),
            )
            .expect("build NRPPa"),
        )
    };
    vec![
        (
            "InitialContextSetupResponse",
            b::build_initial_context_setup_response(&t::InitialContextSetupResponse {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
            })
            .unwrap(),
        ),
        ("UplinkUEAssociatedNRPPaTransport", nrppa),
        (
            "PDUSessionResourceNotify",
            b::build_pdu_session_resource_notify(&t::PduSessionResourceNotify {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                notify_list: vec![t::PduSessionResourceNotifyItem {
                    pdu_session_id: 5,
                    transfer: vec![0x00],
                }],
                released_list: Vec::new(),
            })
            .unwrap(),
        ),
        ("UERadioCapabilityInfoIndication", radio_cap),
        (
            "UplinkNASTransport",
            b::build_uplink_nas_transport(&t::UplinkNasTransport {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                nas_pdu: vec![0x7E, 0x00, 0x67],
                user_location_info: uli,
            })
            .unwrap(),
        ),
        (
            "UplinkRANStatusTransfer",
            super::uplink_status_pdu(amf, ran),
        ),
        (
            "UEContextReleaseRequest",
            b::build_ue_context_release_request(&t::UeContextReleaseRequest {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::RadioConnectionWithUeLost),
            })
            .unwrap(),
        ),
        (
            "HandoverCancel",
            b::build_handover_cancel(&t::HandoverCancel {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                cause: t::Cause::RadioNetwork(t::CauseRadioNetwork::HandoverCancelled),
            })
            .unwrap(),
        ),
    ]
}

/// **#739.** A UE-associated message that names a UE the sending association does not
/// serve is dropped and answered with an Error Indication (TS 38.413 §10.6), before any
/// handler acts on it:
/// - from ANOTHER gNB: unknown-local-UE-NGAP-ID (AP IDs are local to their interface);
/// - from the serving gNB with another RAN UE NGAP ID: inconsistent-remote-UE-NGAP-ID;
/// - for a CM-IDLE UE (no logical connection): unknown-local-UE-NGAP-ID.
///
/// For every message of the issue's table (ICS Response, UL UE-associated NRPPa, PDU
/// Session Resource Notify, UE Radio Capability Info Indication) and of the #787
/// (UL RAN Status Transfer) and #805 (UE Context Release Request) follow-ups, plus
/// Uplink NAS Transport and Handover Cancel. The UE is left exactly as it was.
///
/// REVERT-VERIFIED: with the gate disabled the handlers run, and the intruder's messages
/// get no Error Indication (or a different answer).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ue_associated_messages_for_a_ue_the_sender_does_not_serve_are_refused() {
    crate::context::amf_context_init(64, 1024, 4096);
    let mut server = capturing_ngap_server().await;
    let (serving, intruder) = (97_391u64, 97_392u64);
    seed_gnb_session(&server, serving).await;
    seed_gnb_session(&server, intruder).await;
    let (ue, ran) = (7_739_001u64, 7u32);
    let mut state = UeNasContext::new(ue, ran, serving, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    let (idle, idle_ran) = (7_739_002u64, 8u32);
    let mut state = UeNasContext::new(idle, idle_ran, serving, false);
    state.registered = true;
    state.cm_idle = true;
    server.ue_auth_state.insert(idle, state);
    let unknown = ngap_gen::CauseRadioNetwork::UNKNOWN_LOCAL_UE_NGAP_ID;
    let inconsistent = ngap_gen::CauseRadioNetwork::INCONSISTENT_REMOTE_UE_NGAP_ID;
    let refused_before =
        crate::metrics::global().get(crate::metrics::GlobalMetric::UeAssociatedRefused);
    let mut refused = 0u64;

    let cases = [
        (intruder, ue, ran, unknown, "another gNB"),
        (
            serving,
            ue,
            ran + 100,
            inconsistent,
            "another RAN UE NGAP ID",
        ),
        (serving, idle, idle_ran, unknown, "a CM-IDLE UE"),
    ];
    for (from, amf, r, cause, what) in cases {
        for (name, pdu) in ue_associated_uplinks(amf, r) {
            server
                .process_ngap_message(from, &pdu)
                .await
                .expect("handled");
            let sent = take_sent_ngap(&mut server);
            assert_eq!(sent.len(), 1, "{name} from {what}: {sent:?}");
            assert_eq!(sent[0].0, from, "{name}: answered to the sender");
            assert_eq!(
                decoded_error_indication(&sent[0].1),
                Some((Some(amf), Some(r), Some(cause))),
                "{name} from {what}: Error Indication naming the received ids"
            );
            refused += 1;
        }
    }
    // #1009 review: each refusal is counted in the exported metric (process-wide, so at
    // least this test's own).
    assert!(
        crate::metrics::global().get(crate::metrics::GlobalMetric::UeAssociatedRefused)
            >= refused_before + refused,
        "amf_ngap_ue_associated_refused counts the {refused} refusals"
    );
    // #1009 review, M1: a HANDOVER NOTIFY is exempt from the gate (the target allocates
    // its own RAN UE NGAP ID) and its handler checks it against the recorded target
    // (#803): with no handover in progress, a gNB naming a connected UE is refused with
    // an Error Indication and takes nothing over -- no relocation, no release of the
    // serving gNB.
    for (from, r) in [(intruder, 99u32), (intruder, ran), (serving, ran + 1)] {
        server
            .process_ngap_message(from, &super::handover_notify_pdu(ue, r))
            .await
            .expect("handled");
        let sent = take_sent_ngap(&mut server);
        assert_eq!(sent.len(), 1, "stray Notify from {from}: {sent:?}");
        assert_eq!(sent[0].0, from, "only the sender hears of it");
        assert_eq!(
            decoded_error_indication(&sent[0].1),
            Some((Some(ue), Some(r), Some(unknown))),
            "stray Notify from {from}"
        );
    }
    for (id, ran, idle_now) in [(ue, ran, false), (idle, idle_ran, true)] {
        let state = server.ue_auth_state.get(id).expect("untouched");
        assert_eq!(
            (
                state.association_id,
                state.ran_ue_ngap_id,
                state.is_cm_idle()
            ),
            (serving, ran, idle_now),
            "UE {id} left as it was"
        );
        assert!(state.reachability.is_none());
    }
    assert_eq!(
        server.check_ue_association(
            serving,
            Some(42),
            &ue_associated_uplinks(ue, ran)
                .into_iter()
                .find(|(n, _)| *n == "UEContextReleaseRequest")
                .unwrap()
                .1
        ),
        UeAssociation::Serving,
        "positive control: the serving pair passes"
    );
    server.ue_auth_state.remove(ue);
    server.ue_auth_state.remove(idle);
}

/// **#1009 review, M2.** A PATH SWITCH REQUEST is exempt from the gate (it comes from the
/// new gNB), so its handler refuses a UE that is not CM-CONNECTED -- an Xn handover
/// presupposes one -- with PATH SWITCH REQUEST FAILURE, unknown-local-UE-NGAP-ID, before
/// any SMF call; and only an Acknowledge moves the UE and advances its NH chain. Here a
/// CM-IDLE UE is named by a stray gNB; it used to have its serving pair moved to that gNB
/// and its NH advanced even though the request failed.
///
/// REVERT-VERIFIED: without the CM-CONNECTED check the SMF is asked to switch the
/// session; without commit-on-Acknowledge the failed request still moves the UE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_switch_for_a_ue_that_is_not_connected_changes_nothing() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (serving, stray) = (97_393u64, 97_394u64);
    seed_gnb_session(&server, serving).await;
    seed_gnb_session(&server, stray).await;
    let ue = 7_739_201u64;
    let mut state = UeNasContext::new(ue, 21, serving, false);
    state.registered = true;
    state.cm_idle = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "ps1009-idle-5", port);
    let before = server.ue_auth_state.get(ue).expect("UE").amf_ue.clone();

    server
        .process_ngap_message(stray, &super::path_switch_request_pdu(ue, 77, &[5]))
        .await
        .expect("handled");

    let sent = take_sent_ngap(&mut server);
    forget_amf_sessions(ue);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, stray);
    let (amf, ran, released) =
        super::decoded_path_switch_failure(&sent[0].1).expect("a PATH SWITCH REQUEST FAILURE");
    assert_eq!((amf, ran), (ue, 77));
    assert_eq!(
        released.iter().map(|(psi, _)| *psi).collect::<Vec<_>>(),
        vec![5]
    );
    assert!(
        calls.lock().expect("calls").is_empty(),
        "no SMF is asked to switch a CM-IDLE UE's session"
    );
    let after = server.ue_auth_state.get(ue).expect("UE");
    assert_eq!(
        (
            after.association_id,
            after.ran_ue_ngap_id,
            after.is_cm_idle()
        ),
        (serving, 21, true),
        "the UE keeps its stored pair"
    );
    assert_eq!(
        (after.amf_ue.nhcc, after.amf_ue.nh),
        (before.nhcc, before.nh),
        "and its NH chain"
    );
    server.ue_auth_state.remove(ue);
}

/// An INITIAL CONTEXT SETUP RESPONSE for `(amf, ran)` reporting `sessions` as set up,
/// each with the one-octet transfer `[psi]`.
fn ics_response_with_sessions(amf: u64, ran: u32, sessions: &[u8]) -> Vec<u8> {
    use g::InitialContextSetupResponseProtocolIEs_EntryValue as Ie;
    let entry = |id: u16, value| g::InitialContextSetupResponseProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(g::Criticality::IGNORE),
        value,
    };
    let list = g::PDUSessionResourceSetupListCxtRes(
        sessions
            .iter()
            .map(|&psi| g::PDUSessionResourceSetupItemCxtRes {
                pdu_session_id: g::PDUSessionID(psi),
                pdu_session_resource_setup_response_transfer:
                    g::PDUSessionResourceSetupItemCxtResPDUSessionResourceSetupResponseTransfer(
                        vec![psi],
                    ),
                ie_extensions: None,
            })
            .collect(),
    );
    nextgcore_ngap_gen::encode(&g::NGAP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(g::ID_INITIAL_CONTEXT_SETUP),
        criticality: g::Criticality(g::Criticality::REJECT),
        value: g::SuccessfulOutcomeValue::Id_InitialContextSetup(g::InitialContextSetupResponse {
            protocol_i_es: g::InitialContextSetupResponseProtocolIEs(vec![
                entry(
                    g::ID_AMF_UE_NGAP_ID,
                    Ie::Id_AMF_UE_NGAP_ID(g::AMF_UE_NGAP_ID(amf)),
                ),
                entry(
                    g::ID_RAN_UE_NGAP_ID,
                    Ie::Id_RAN_UE_NGAP_ID(g::RAN_UE_NGAP_ID(ran)),
                ),
                entry(
                    g::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES,
                    Ie::Id_PDUSessionResourceSetupListCxtRes(list),
                ),
            ]),
        }),
    }))
    .expect("encode InitialContextSetupResponse")
}

/// **#739 (the #550 row).** An INITIAL CONTEXT SETUP RESPONSE relays to the SMF only the
/// sessions its Request asked the gNB to set up. The serving gNB reports PSI 1, which
/// the Service Request's ICS carried, and PSI 2, which it did not: only PSI 1's Setup
/// Response Transfer reaches the SMF, so a gNB cannot re-point another session's
/// downlink at itself.
///
/// REVERT-VERIFIED: relaying every reported session sends PSI 2's transfer too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ics_response_relays_only_the_sessions_the_request_set_up() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_739_101u64, 91);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "ics739-asked-1", port);
    hold_session(&mut server, ue, 2, "ics739-not-asked-2", port);
    server
        .ue_auth_state
        .with_mut(ue, |s| s.ics_requested_psis = vec![1]);

    server
        .process_ngap_message(ASSOC, &ics_response_with_sessions(ue, ran, &[1, 2]))
        .await
        .expect("handled");

    let calls = calls.lock().expect("calls").clone();
    let refs: Vec<&str> = calls
        .iter()
        .filter(|(_, body)| body["n2SmInfoType"] == "PDU_RES_SETUP_RSP")
        .map(|(uri, _)| uri.as_str())
        .collect();
    assert_eq!(refs.len(), 1, "{calls:?}");
    assert!(refs[0].contains("/sm-contexts/ics739-asked-1/"), "{refs:?}");
    assert!(
        server
            .ue_auth_state
            .get(ue)
            .expect("UE")
            .ics_requested_psis
            .is_empty(),
        "the Request is answered"
    );
    server.ue_auth_state.remove(ue);
}

// ---------------------------------------------------------------------------
// #922: the first CreateSMContext runs off the NGAP task
// ---------------------------------------------------------------------------

/// #922: a PDU Session Establishment Request whose SMF never answers does not
/// hold the NGAP task. The handler returns at once, with the attempt in flight
/// off the task, and a second UE's establishment is handled meanwhile. Before
/// #922 the first attempt was awaited inline, so N2 for every gNB stalled for
/// the SBI client's timeout per establishment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_create_sm_context_to_an_unanswering_smf_does_not_hold_the_ngap_task() {
    let (_hang, port) = hanging_smf();
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (a, b) = (7_922_001u64, 7_922_002u64);
    ue_ready_for_sessions(&mut server, a, 110);
    ue_ready_for_sessions(&mut server, b, 111);
    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];

    let started = std::time::Instant::now();
    for (ue, ran) in [(a, 110), (b, 111)] {
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "both establishments were handled at once: {:?}",
        started.elapsed()
    );
    for ue in [a, b] {
        assert!(
            server.pending_establishments[&(ue, 5)].in_flight,
            "UE {ue}: its CreateSMContext is in flight off the task"
        );
    }
    until_in_flight(&server, 2).await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "nothing answered yet"
    );
    server.forget_ue(a);
    server.forget_ue(b);
}

/// #922: the off-task first attempt still sets the session up: the SMF's
/// answer is applied on the NGAP task (the session recorded, the Accept relayed
/// and the PDU SESSION RESOURCE SETUP REQUEST sent), exactly as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_create_sm_context_answered_off_the_task_sets_the_session_up() {
    let (_smf, port, calls) = activating_smf().await;
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_011u64, 112);
    ue_ready_for_sessions(&mut server, ue, ran);
    server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &[0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF]),
        )
        .await
        .expect("handled");
    settle_establishments(&mut server).await;

    assert_eq!(
        calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|(u, _)| u.ends_with("/nsmf-pdusession/v1/sm-contexts"))
            .count(),
        1
    );
    assert!(server.sm_context_refs.contains_key(&(ue, 5)));
    assert!(server.pending_establishments.is_empty());
    let sent = sent_to(&mut server, ue);
    assert!(
        sent.iter().any(|s| matches!(s, Sent::SetupRequest { .. })),
        "the session is set up at the gNB: {sent:?}"
    );
    server.forget_ue(ue);
}

/// #922: a UE-requested PDU Session Release does not wait for the SMF. The
/// release command goes to the UE and the gNB at once, and the ReleaseSMContext
/// reaches the SMF off the NGAP task. With an SMF that never answers, the
/// handler still returns at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_requested_release_does_not_wait_for_the_smf() {
    let (_hang, hang_port) = hanging_smf();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_021u64, 113);
    ue_ready_for_sessions(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "rel-922-hang", hang_port);
    hold_session(&mut server, ue, 6, "rel-922-ok", port);
    let release_request = |psi: u8| vec![0x2E, psi, 0x01, 0xD1];

    let started = std::time::Instant::now();
    for psi in [5, 6] {
        server
            .handle_5gsm_message(ASSOC, ue, ran, &release_request(psi), None)
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the handler did not wait for the SMF: {:?}",
        started.elapsed()
    );
    let releases = sent_to(&mut server, ue)
        .into_iter()
        .filter(|s| matches!(s, Sent::ReleaseCommand { .. }))
        .count();
    assert_eq!(releases, 2, "both sessions released at the gNB at once");
    // The answering SMF gets its release off the task.
    for _ in 0..200 {
        if calls
            .lock()
            .expect("calls")
            .iter()
            .any(|(u, _)| u.ends_with("/sm-contexts/rel-922-ok/release"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(calls
        .lock()
        .expect("calls")
        .iter()
        .any(|(u, _)| u.ends_with("/sm-contexts/rel-922-ok/release")));
    server.forget_ue(ue);
}

// ---------------------------------------------------------------------------
// #759: mobility / periodic Registration with PDU session status and Uplink
// data status (TS 24.501 §5.5.1.3.4)
// ---------------------------------------------------------------------------

/// A plain mobility (or periodic) REGISTRATION REQUEST under the UE's 5G-GUTI,
/// with Uplink data status (0x40) and PDU session status (0x50) when given.
fn update_registration_request(reg_type: u8, uds: Option<u16>, pss: Option<u16>) -> Vec<u8> {
    let mut rr = super::guti_registration_request(reg_type, 0x0759_0001);
    if let Some(b) = uds {
        rr.extend_from_slice(&[0x40, 0x02, b as u8, (b >> 8) as u8]);
    }
    if let Some(b) = pss {
        rr.extend_from_slice(&[0x50, 0x02, b as u8, (b >> 8) as u8]);
    }
    rr
}

/// A registered, connected UE whose current 5G-GUTI is the one
/// [`update_registration_request`] names.
fn registered_ue_with_guti(server: &mut NgapServer, ue: u64, ran: u32) {
    secured_registered_ue(server, ue, ran);
    let guti = parse_registration_request_pdu(&update_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        None,
        None,
    ))
    .and_then(|r| r.guti)
    .expect("GUTI");
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.current_guti = guti;
        s.initial_context_setup_request_sent = true;
    });
}

/// The decoded REGISTRATION ACCEPT inside a protected DL NAS PDU (NEA0).
fn registration_accept_of(nas: &[u8]) -> nextgcore_nas::fiveg::message::RegistrationAccept {
    registration_accept_of_plain(&nas[7..])
}

/// #759: a connected UE's mobility update says PSI 1 is active and has uplink
/// data, and PSI 2 is inactive. The AMF does the following:
/// - releases PSI 2 at the SMF;
/// - activates PSI 1 (ACTIVATING), then sends a PDU SESSION RESOURCE SETUP
///   REQUEST whose NAS-PDU is the REGISTRATION ACCEPT;
/// - in the Accept, reports PDU session status {1} and reactivation result
///   "no failure".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mobility_update_releases_inactive_and_reactivates_uplink_sessions() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_001u64, 59);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "reg759-1", port);
    hold_session(&mut server, ue, 2, "reg759-2", port);

    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::MOBILITY_UPDATING,
            Some(1 << 1),
            Some(1 << 1),
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;

    let calls = calls.lock().expect("calls").clone();
    assert!(
        calls
            .iter()
            .any(|(u, _)| u.ends_with("/sm-contexts/reg759-2/release")),
        "PSI 2, inactive at the UE, is released at the SMF: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|(u, b)| u.ends_with("/sm-contexts/reg759-1/modify")
                && b["upCnxState"] == "ACTIVATING"),
        "PSI 1's user plane is re-activated: {calls:?}"
    );
    assert!(crate::context::amf_self()
        .read()
        .unwrap()
        .sess_find_by_psi(ue, 2)
        .is_none());

    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let Some(Sent::SetupRequest { items, nas_pdu, .. }) = sent.first() else {
        panic!("a PDU SESSION RESOURCE SETUP REQUEST first, got {sent:?}");
    };
    assert_eq!(items, &vec![setup_item(1, transfer_for("reg759-1"))]);
    let accept = registration_accept_of(nas_pdu.as_deref().expect("the Accept rides it"));
    assert_eq!(accept.pdu_session_status.map(|p| p.psi), Some(1 << 1));
    assert_eq!(accept.pdu_session_reactivation_result, Some(0));
    assert!(
        !sent.iter().any(|s| matches!(s, Sent::DownlinkNas { .. })),
        "the Accept goes once, in the setup: {sent:?}"
    );
}

/// A failed re-activation is reported in the Accept (bit n = PSI n failed), and
/// the Accept then goes on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_reactivation_is_reported_in_a_standalone_accept() {
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_002u64, 60);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "fail-reg759-1", port);

    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            Some(1 << 1),
            None,
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let Some(Sent::DownlinkNas { nas_pdu, .. }) = sent.first() else {
        panic!("a standalone DL NAS Transport, got {sent:?}");
    };
    let accept = registration_accept_of(nas_pdu);
    assert_eq!(accept.pdu_session_reactivation_result, Some(1 << 1));
    assert_eq!(accept.pdu_session_status, None, "the UE sent none");
}

/// An update without either IE behaves as before: no N11 call, and a standalone
/// Accept without the session IEs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_without_session_ies_touches_no_session() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_003u64, 61);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "reg759-none-1", port);
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            None,
            None,
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    assert!(calls.lock().expect("calls").is_empty());
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let Some(Sent::DownlinkNas { nas_pdu, .. }) = sent.first() else {
        panic!("a DL NAS Transport, got {sent:?}");
    };
    let accept = registration_accept_of(nas_pdu);
    assert_eq!(accept.pdu_session_status, None);
    assert_eq!(accept.pdu_session_reactivation_result, None);
}

// ---------------------------------------------------------------------------
// #759 from CM-IDLE: the update arrives in an Initial UE Message (#609 resume),
// so the gNB holds no UE context and the Accept rides an Initial Context Setup
// ---------------------------------------------------------------------------

/// An INITIAL CONTEXT SETUP REQUEST, reduced to what the CM-IDLE update asserts.
#[derive(Debug)]
struct SentIcs {
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    nas_pdu: Option<Vec<u8>>,
    items: Vec<SetupItem>,
    security_key: Vec<u8>,
}

/// Decode `pdu` as an INITIAL CONTEXT SETUP REQUEST, or `None` for anything else.
fn decode_ics(pdu: &[u8]) -> Option<SentIcs> {
    use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
    let Ok(g::NGAP_PDU::InitiatingMessage(m)) = nextgcore_ngap_gen::decode(pdu) else {
        return None;
    };
    let g::InitiatingMessageValue::Id_InitialContextSetup(req) = m.value else {
        return None;
    };
    let mut out = SentIcs {
        amf_ue_ngap_id: 0,
        ran_ue_ngap_id: 0,
        nas_pdu: None,
        items: Vec::new(),
        security_key: Vec::new(),
    };
    for ie in req.protocol_i_es.0 {
        match ie.value {
            V::Id_AMF_UE_NGAP_ID(id) => out.amf_ue_ngap_id = id.0,
            V::Id_RAN_UE_NGAP_ID(id) => out.ran_ue_ngap_id = id.0,
            V::Id_NAS_PDU(n) => out.nas_pdu = Some(n.0),
            V::Id_SecurityKey(k) => out.security_key = k.0.into_vec(),
            V::Id_PDUSessionResourceSetupListCxtReq(l) => {
                for it in l.0 {
                    out.items.push(SetupItem {
                        psi: it.pdu_session_id.0,
                        sst: it.s_nssai.sst.0.first().copied().unwrap_or_default(),
                        sd: it
                            .s_nssai
                            .sd
                            .map(|sd| sd.0.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b))),
                        transfer: it.pdu_session_resource_setup_request_transfer.0,
                    });
                }
            }
            _ => {}
        }
    }
    Some(out)
}

/// The GUAMI the #609 fixtures' 5G-GUTI names (PLMN 001/01, region 0x02, set
/// 0x155, pointer 0x2A), installed as the only served one so the Initial Context
/// Setup encodes and the GUTI is this AMF's own. Restores the previous list on drop.
struct ServeFixtureGuami(Vec<crate::context::Guami>);

impl ServeFixtureGuami {
    fn install() -> Self {
        let ctx = crate::context::amf_self();
        let mut guard = ctx.write().unwrap_or_else(|e| e.into_inner());
        let previous = std::mem::replace(
            &mut guard.served_guami,
            vec![crate::context::Guami {
                plmn_id: PlmnId::new("001", "01"),
                amf_id: crate::context::AmfId {
                    region: 0x02,
                    set: 0x155,
                    pointer: 0x2A,
                },
            }],
        );
        Self(previous)
    }
}

impl Drop for ServeFixtureGuami {
    fn drop(&mut self) {
        let ctx = crate::context::amf_self();
        ctx.write().unwrap_or_else(|e| e.into_inner()).served_guami = std::mem::take(&mut self.0);
    }
}

/// The CM-IDLE UE the two tests below resume: the #609 fixture with a K_AMF, an
/// Allowed NSSAI and security capabilities, so an Initial Context Setup encodes,
/// and the previous connection's UE context recorded as established.
fn idle_ue_for_update(old_id: u64, tmsi: u32) -> UeNasContext {
    let mut ue = super::idle_ue_with_security(old_id, tmsi);
    // As its registration left it: the previous connection's Initial Context
    // Setup was sent and answered. The resume must not inherit that.
    ue.initial_context_setup_request_sent = true;
    ue.initial_context_setup_response_received = true;
    ue.amf_ue.kamf = [0x33; 32];
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    ue.amf_ue.ue_security_capability = crate::context::UeSecurityCapability {
        ea: 0xE0,
        ia: 0xE0,
        eea: 0,
        eia: 0,
    };
    ue
}

/// The REGISTRATION ACCEPT inside a downlink NAS PDU protected under `ue`'s
/// context (integrity and NEA2 ciphering, downlink COUNT = the PDU's SQN).
fn deciphered_registration_accept(
    ue: &crate::context::AmfUe,
    nas: &[u8],
) -> nextgcore_nas::fiveg::message::RegistrationAccept {
    assert_eq!(
        nas.get(1),
        Some(&security_header::INTEGRITY_PROTECTED_AND_CIPHERED),
        "{nas:02x?}"
    );
    let mut plain = nas[7..].to_vec();
    nas_security::nas_encrypt(
        ue.selected_enc_algorithm,
        &ue.knas_enc,
        u32::from(nas[6]),
        ue.access_type,
        nas_security::direction::DOWNLINK,
        &mut plain,
    );
    registration_accept_of_plain(&plain)
}

/// The decoded REGISTRATION ACCEPT of a plain 5GMM message.
fn registration_accept_of_plain(plain: &[u8]) -> nextgcore_nas::fiveg::message::RegistrationAccept {
    use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
    match parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(plain)) {
        Ok(FiveGmmMessage::RegistrationAccept(a)) => a,
        other => panic!("a REGISTRATION ACCEPT, got {other:?}"),
    }
}

/// #759 from CM-IDLE (TS 24.501 §5.5.1.3.4, TS 23.502 §4.2.2.2.2 steps 17-21).
/// A CM-IDLE UE sends a protected mobility update in an Initial UE Message. The
/// cleartext part holds only the cleartext IEs, and the full request in the
/// NAS message container holds Uplink data status {1} and PDU session status
/// {1}. PSI 2, which the AMF holds, is inactive at the UE. The AMF:
/// - releases PSI 2 at its SMF and activates PSI 1 (ACTIVATING), both under the
///   UE's new AMF UE NGAP ID;
/// - sends ONE Initial Context Setup Request on the new connection. It carries
///   PSI 1's transfer, a K_gNB derived from this request's uplink NAS COUNT
///   (5), and as its NAS-PDU the REGISTRATION ACCEPT, which reports PDU
///   session status {1} and reactivation result "no failure";
/// - sends no Downlink NAS Transport and no PDU Session Resource Setup Request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// CONTEXT_GUARD is held across the awaits on purpose: `served_guami` is
// process-global and this test needs its own for the whole exchange.
#[allow(clippy::await_holding_lock)]
async fn a_mobility_update_from_cm_idle_rides_an_initial_context_setup_with_its_sessions() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_759_101u64, 7_759_102u64, 0x0759_0101u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    let kamf = stored.amf_ue.kamf;
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg759-idle-1", port);
    hold_session(&mut server, old_id, 2, "reg759-idle-2", port);
    server.forced_amf_ue_ngap_id = Some(new_id);

    let cleartext = super::guti_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        tmsi,
    );
    let mut full = cleartext.clone();
    full.extend_from_slice(&[0x40, 0x02, 1 << 1, 0x00]); // Uplink data status: PSI 1
    full.extend_from_slice(&[0x50, 0x02, 1 << 1, 0x00]); // PDU session status: PSI 1
    let nas = super::protected_initial_registration(&ue_keys, &cleartext, &full, 5);
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(nas))
        .await
        .expect("the update is handled");

    let calls = calls.lock().expect("calls").clone();
    assert_eq!(calls.len(), 2, "one release and one activation: {calls:?}");
    assert!(
        calls
            .iter()
            .any(|(u, _)| u.ends_with("/sm-contexts/reg759-idle-2/release")),
        "PSI 2, inactive at the UE, is released at its SMF: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|(u, b)| u.ends_with("/sm-contexts/reg759-idle-1/modify")
                && b["upCnxState"] == "ACTIVATING"),
        "PSI 1's user plane is re-activated: {calls:?}"
    );

    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "exactly one NGAP PDU: {sent:?}");
    assert_eq!(sent[0].0, ASSOC);
    let ics = decode_ics(&sent[0].1).unwrap_or_else(|| {
        panic!(
            "an INITIAL CONTEXT SETUP REQUEST, got {:?}",
            decode_sent(&sent[0].1)
        )
    });
    assert_eq!((ics.amf_ue_ngap_id, ics.ran_ue_ngap_id), (new_id, 512));
    assert_eq!(
        ics.items,
        vec![setup_item(1, transfer_for("reg759-idle-1"))]
    );
    let kgnb = nextgcore_crypt::kdf::nextgcore_kdf_kgnb_and_kn3iwf(&kamf, 5, ACCESS_TYPE_3GPP);
    assert_eq!(
        ics.security_key,
        kgnb.to_vec(),
        "K_gNB from the REGISTRATION REQUEST's uplink NAS COUNT (TS 33.501 Annex A.9)"
    );
    let accept = deciphered_registration_accept(
        &ue_keys,
        ics.nas_pdu.as_deref().expect("the Accept rides the ICS"),
    );
    assert_eq!(accept.pdu_session_status.map(|p| p.psi), Some(1 << 1));
    assert_eq!(accept.pdu_session_reactivation_result, Some(0));

    // #826 review M2 (#778): PSI 1's user plane is recorded as set up on the
    // new connection, so a downlink-data setup for it is not sent again.
    assert!(server.up_active.contains(&(new_id, 1)));
    assert!(!server.up_active.contains(&(new_id, 2)));
    let resumed = server.ue_auth_state.get(new_id).expect("the resumed UE");
    assert!(resumed.initial_context_setup_request_sent);
    assert!(
        !resumed.initial_context_setup_response_received,
        "the UE context is up only once the gNB answers"
    );
    assert_eq!(resumed.amf_ue.kgnb, kgnb);
    drop(resumed);
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        assert!(guard.sess_find_by_psi(new_id, 2).is_none(), "PSI 2 is gone");
        if let Some(sess) = guard.sess_find_by_psi(new_id, 1) {
            guard.sess_remove(sess.id);
        }
    }
    server.ue_auth_state.remove(new_id);
}

// ---------------------------------------------------------------------------
// #1102: a registration update's Initial Context Setup records its sessions, and
// the registration answers the UE's page
// ---------------------------------------------------------------------------

/// The protected mobility update `tmsi`'s UE sends from CM-IDLE, its full request
/// carrying `extra` (session IEs) in the NAS message container.
fn idle_mobility_update(ue_keys: &crate::context::AmfUe, tmsi: u32, extra: &[u8]) -> Vec<u8> {
    let cleartext = super::guti_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        tmsi,
    );
    let mut full = cleartext.clone();
    full.extend_from_slice(extra);
    super::service_request_initial_ue(super::protected_initial_registration(
        ue_keys, &cleartext, &full, 5,
    ))
}

/// A page for `old_id`'s UE, identified by the fixture GUTI's 5G-S-TMSI with `tmsi`.
fn page_for(old_id: u64, tmsi: u32, psi: u8) -> crate::context::PagingContext {
    crate::context::PagingContext {
        amf_ue_ngap_id: old_id,
        tmsi,
        amf_set_id: 0x155,
        amf_pointer: 0x2A,
        plmn_id: PlmnId::new("001", "01"),
        tac: 0x74,
        max_retransmit: 4,
        pdu_session_id: Some(psi),
        ..Default::default()
    }
}

/// Drop what a #1102 test left in the process-global context.
fn forget_update_test(server: &mut NgapServer, old_id: u64, new_id: u64) {
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
    guard.paging_remove(old_id);
    guard.paging_remove(new_id);
    for id in [old_id, new_id] {
        for sess in guard.sess_list_for_ue(id) {
            guard.sess_remove(sess.id);
        }
    }
    drop(guard);
    server.forget_ue(new_id);
    server.ue_auth_state.remove(old_id);
}

/// The n2SmInfoType=PDU_RES_SETUP_RSP calls the SMF received.
fn setup_response_uris(calls: &[SmfCall]) -> Vec<String> {
    calls
        .iter()
        .filter(|(_, body)| body["n2SmInfoType"] == "PDU_RES_SETUP_RSP")
        .map(|(uri, _)| uri.clone())
        .collect()
}

/// **#1102** (TS 23.502 §4.2.2.2.2 step 21, §4.2.3.2 steps 12-14). A CM-IDLE UE
/// comes back on a new gNB with a mobility update whose Uplink data status
/// re-activates PSI 1. The Accept rides an Initial Context Setup with PSI 1, and
/// the gNB's Response reports PSI 1 set up: its Setup Response Transfer, the new
/// downlink tunnel, reaches PSI 1's SMF. Before the fix the update's ICS left
/// `ics_requested_psis` as the initial registration's ICS had (empty), so the #739
/// gate dropped the transfer and the downlink stayed on the old gNB for minutes.
///
/// REVERT-VERIFIED: without `record_ics_request(sessions)` in
/// `send_update_accept_in_initial_context_setup`, no PDU_RES_SETUP_RSP reaches the SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// CONTEXT_GUARD is held across the awaits on purpose: `served_guami` is
// process-global and this test needs its own for the whole exchange.
#[allow(clippy::await_holding_lock)]
async fn a_cm_idle_updates_ics_response_reaches_the_smf_for_the_reactivated_session() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_201u64, 7_110_202u64, 0x1102_0201u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-1", port);
    server.forced_amf_ue_ngap_id = Some(new_id);

    let pdu = idle_mobility_update(
        &ue_keys,
        tmsi,
        &[0x40, 0x02, 1 << 1, 0x00, 0x50, 0x02, 1 << 1, 0x00],
    );
    server
        .handle_initial_ue_message(ASSOC, &pdu)
        .await
        .expect("the update is handled");
    let sent = take_sent_ngap(&mut server);
    let ics = sent
        .iter()
        .find_map(|(_, p)| decode_ics(p))
        .unwrap_or_else(|| panic!("an Initial Context Setup Request: {sent:?}"));
    assert_eq!(ics.items, vec![setup_item(1, transfer_for("reg1102-1"))]);
    assert_eq!(
        server
            .ue_auth_state
            .get(new_id)
            .expect("the resumed UE")
            .ics_requested_psis,
        vec![1],
        "the Request's sessions are recorded"
    );

    server
        .process_ngap_message(ASSOC, &ics_response_with_sessions(new_id, 512, &[1]))
        .await
        .expect("handled");

    let calls = calls.lock().expect("calls").clone();
    let uris = setup_response_uris(&calls);
    assert_eq!(uris.len(), 1, "{calls:?}");
    assert!(uris[0].contains("/sm-contexts/reg1102-1/"), "{uris:?}");
    forget_update_test(&mut server, old_id, new_id);
}

/// **#1102, the page** (TS 24.501 §5.6.2.2.1, TS 23.502 §4.2.3.3 step 6). The SMF's
/// downlink data paged the CM-IDLE UE for PSI 1, and the UE answers with a mobility
/// update instead of a Service Request, reporting PSI 1 active but sending no Uplink
/// data status. The verified REGISTRATION REQUEST answers the page, and the update
/// Accept takes it out of the paging map, so it is not retransmitted for the old
/// connection and its requester is not told UE_NOT_RESPONDING. And PSI 1, which the page was for, is re-activated
/// at its SMF and rides the Initial Context Setup, so the buffered downlink is
/// delivered.
///
/// REVERT-VERIFIED: without taking the page in `open_idle_registration_request`, the
/// page stays in the map and PSI 1 is not activated (no ICS item).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_registration_update_from_cm_idle_answers_the_page_and_sets_its_session_up() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_301u64, 7_110_302u64, 0x1102_0301u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-paged-1", port);
    assert!(crate::context::amf_self()
        .read()
        .unwrap()
        .paging_add(page_for(old_id, tmsi, 1)));
    server.forced_amf_ue_ngap_id = Some(new_id);

    let pdu = idle_mobility_update(&ue_keys, tmsi, &[0x50, 0x02, 1 << 1, 0x00]);
    server
        .handle_initial_ue_message(ASSOC, &pdu)
        .await
        .expect("the update is handled");

    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        assert!(
            guard.paging_find(old_id).is_none() && guard.paging_find(new_id).is_none(),
            "the registration answers the page and its Accept takes it"
        );
    }
    let calls = calls.lock().expect("calls").clone();
    assert!(
        calls
            .iter()
            .any(|(u, b)| u.ends_with("/sm-contexts/reg1102-paged-1/modify")
                && b["upCnxState"] == "ACTIVATING"),
        "the paged session is re-activated: {calls:?}"
    );
    let sent = take_sent_ngap(&mut server);
    let ics = sent
        .iter()
        .find_map(|(_, p)| decode_ics(p))
        .unwrap_or_else(|| panic!("an Initial Context Setup Request: {sent:?}"));
    assert_eq!(
        ics.items,
        vec![setup_item(1, transfer_for("reg1102-paged-1"))]
    );
    let resumed = server.ue_auth_state.get(new_id).expect("the resumed UE");
    assert_eq!(resumed.ics_requested_psis, vec![1]);
    drop(resumed);
    forget_update_test(&mut server, old_id, new_id);
}

/// **#1102, a page with its own setup transfer.** A page whose N1N2 transfer brought
/// PSI 1's PDU Session Resource Setup Request Transfer is answered by a mobility
/// update. That transfer rides the Initial Context Setup as it is, as it would ride a
/// Service Request's: the SMF is not asked to activate PSI 1 a second time.
///
/// REVERT-VERIFIED: without the page in `reconcile_update_sessions`, the ICS carries
/// no session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_pages_setup_transfer_rides_the_registration_updates_initial_context_setup() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_401u64, 7_110_402u64, 0x1102_0401u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-paged-n2-1", port);
    let transfer = transfer_for("paged-n2-transfer");
    let mut page = page_for(old_id, tmsi, 1);
    page.pending_n2 = Some(transfer.clone());
    assert!(crate::context::amf_self().read().unwrap().paging_add(page));
    server.forced_amf_ue_ngap_id = Some(new_id);

    let pdu = idle_mobility_update(&ue_keys, tmsi, &[0x50, 0x02, 1 << 1, 0x00]);
    server
        .handle_initial_ue_message(ASSOC, &pdu)
        .await
        .expect("the update is handled");

    let calls = calls.lock().expect("calls").clone();
    assert!(
        !calls.iter().any(|(u, _)| u.contains("reg1102-paged-n2-1")),
        "no second activation and no release: {calls:?}"
    );
    let sent = take_sent_ngap(&mut server);
    let ics = sent
        .iter()
        .find_map(|(_, p)| decode_ics(p))
        .unwrap_or_else(|| panic!("an Initial Context Setup Request: {sent:?}"));
    assert_eq!(ics.items, vec![setup_item(1, transfer)]);
    assert!(crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(old_id)
        .is_none());
    forget_update_test(&mut server, old_id, new_id);
}

/// **#1102 (#1105 review m2): a page answered by an update with no session IE.** The
/// CM-IDLE UE sends a periodic update with neither PDU session status nor Uplink data
/// status, so the request has nothing to reconcile on its own. The page it answered
/// still is: its session (PSI 1, a DDN page) is re-activated and rides the ICS.
///
/// REVERT-VERIFIED: without the `(None, Some(_))` arm in `send_registration_accept`,
/// the ICS carries no session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_page_answered_by_an_update_without_session_ies_still_sets_its_session_up() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_601u64, 7_110_602u64, 0x1102_0601u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-noies-1", port);
    assert!(crate::context::amf_self()
        .read()
        .unwrap()
        .paging_add(page_for(old_id, tmsi, 1)));
    server.forced_amf_ue_ngap_id = Some(new_id);

    let cleartext = super::guti_registration_request(
        crate::gmm_build::registration_type::PERIODIC_UPDATING,
        tmsi,
    );
    let pdu = super::service_request_initial_ue(super::protected_initial_registration(
        &ue_keys, &cleartext, &cleartext, 5,
    ));
    server
        .handle_initial_ue_message(ASSOC, &pdu)
        .await
        .expect("the update is handled");

    let calls = calls.lock().expect("calls").clone();
    assert!(
        calls
            .iter()
            .any(|(u, b)| u.ends_with("/sm-contexts/reg1102-noies-1/modify")
                && b["upCnxState"] == "ACTIVATING"),
        "{calls:?}"
    );
    let sent = take_sent_ngap(&mut server);
    let ics = sent
        .iter()
        .find_map(|(_, p)| decode_ics(p))
        .unwrap_or_else(|| panic!("an Initial Context Setup Request: {sent:?}"));
    assert_eq!(
        ics.items,
        vec![setup_item(1, transfer_for("reg1102-noies-1"))]
    );
    assert!(crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(old_id)
        .is_none());
    forget_update_test(&mut server, old_id, new_id);
}

/// **#1102 (#1105 review m1): an answered page no update Accept takes.** A paged
/// CM-IDLE UE answers with a verified INITIAL registration, which is not an update
/// and takes no page. The page is marked answered by the new connection, so it is
/// not sent again, but it stays in the paging map. There it runs out on T3513's
/// schedule and is abandoned, and its requester is told UE_NOT_RESPONDING as
/// before. It is not silently dropped. The expiry of an answered page is pinned in
/// `context::tests::an_answered_page_is_not_sent_but_still_expires`.
///
/// REVERT-VERIFIED: removing the page when the registration answers it (the first
/// cut of this fix) fails the "still in the map" assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_page_answered_by_an_initial_registration_is_kept_for_abandonment() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_701u64, 7_110_702u64, 0x1102_0701u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-initial-1", port);
    let mut page = page_for(old_id, tmsi, 1);
    page.failure_notify_uri = Some(format!("http://127.0.0.1:{port}/n1n2-fail-1102"));
    assert!(crate::context::amf_self().read().unwrap().paging_add(page));
    server.forced_amf_ue_ngap_id = Some(new_id);

    let cleartext =
        super::guti_registration_request(crate::gmm_build::registration_type::INITIAL, tmsi);
    let pdu = super::service_request_initial_ue(super::protected_initial_registration(
        &ue_keys, &cleartext, &cleartext, 5,
    ));
    let _ = server.handle_initial_ue_message(ASSOC, &pdu).await;

    let kept = crate::context::amf_self()
        .read()
        .unwrap()
        .paging_find(old_id)
        .expect("the answered page is still in the map");
    assert_eq!(kept.answered_by, Some(new_id));
    assert!(
        kept.failure_notify_uri.is_some(),
        "its requester can still be told"
    );
    forget_update_test(&mut server, old_id, new_id);
}

/// **#1102, a paged release.** A page that carries PSI 1's release (an N2 Release
/// Command transfer and the N1 PDU SESSION RELEASE COMMAND) is answered by a mobility
/// update. The Accept's Initial Context Setup does not set PSI 1 up, and the release
/// follows it, as after a Service Accept (#518): a PDU SESSION RESOURCE RELEASE
/// COMMAND for PSI 1, then the N1 in a DOWNLINK NAS TRANSPORT, both on the new
/// connection.
///
/// REVERT-VERIFIED: without the delivery in `send_registration_accept`, only the
/// Initial Context Setup goes out and the release is lost with the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_paged_release_follows_the_registration_updates_initial_context_setup() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_110_501u64, 7_110_502u64, 0x1102_0501u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg1102-paged-rel-1", port);
    let mut page = page_for(old_id, tmsi, 1);
    page.pending_n2 = Some(vec![0x00]);
    page.pending_n2_release = true;
    page.pending_n1 = Some(vec![0x2E, 0x01, 0x00, 0xD3, 0x24]);
    page.pending_n1_container_type = 0x01;
    assert!(crate::context::amf_self().read().unwrap().paging_add(page));
    server.forced_amf_ue_ngap_id = Some(new_id);

    let pdu = idle_mobility_update(&ue_keys, tmsi, &[0x50, 0x02, 1 << 1, 0x00]);
    server
        .handle_initial_ue_message(ASSOC, &pdu)
        .await
        .expect("the update is handled");

    let calls = calls.lock().expect("calls").clone();
    assert!(
        !calls.iter().any(|(u, _)| u.contains("reg1102-paged-rel-1")),
        "a paged release is not activated: {calls:?}"
    );
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 3, "ICS, Release Command, DL NAS: {sent:?}");
    let ics = decode_ics(&sent[0].1).expect("the Initial Context Setup goes first");
    assert!(ics.items.is_empty(), "{:?}", ics.items);
    assert!(
        matches!(
            decode_sent(&sent[1].1),
            Sent::ReleaseCommand { amf_ue_ngap_id, ref psis } if amf_ue_ngap_id == new_id && psis == &[1]
        ),
        "{:?}",
        decode_sent(&sent[1].1)
    );
    assert!(
        matches!(
            decode_sent(&sent[2].1),
            Sent::DownlinkNas { amf_ue_ngap_id, .. } if amf_ue_ngap_id == new_id
        ),
        "{:?}",
        decode_sent(&sent[2].1)
    );
    forget_update_test(&mut server, old_id, new_id);
}

/// A periodic update from CM-IDLE with no session IE still sets up the UE's
/// context on the new connection: an Initial Context Setup with no session and
/// the Accept, no N11 call. Otherwise a PDU session the UE establishes next on
/// this connection would wait for an Initial Context Setup Response that never
/// comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_periodic_update_from_cm_idle_without_session_ies_still_sets_up_the_ue_context() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_759_201u64, 7_759_202u64, 0x0759_0201u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "reg759-idle-none-1", port);
    server.forced_amf_ue_ngap_id = Some(new_id);

    let rr = super::guti_registration_request(
        crate::gmm_build::registration_type::PERIODIC_UPDATING,
        tmsi,
    );
    let nas = super::protected_initial_registration(&ue_keys, &rr, &rr, 5);
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(nas))
        .await
        .expect("the update is handled");

    assert!(
        calls.lock().expect("calls").is_empty(),
        "no session touched"
    );
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "exactly one NGAP PDU: {sent:?}");
    let ics = decode_ics(&sent[0].1).unwrap_or_else(|| {
        panic!(
            "an INITIAL CONTEXT SETUP REQUEST, got {:?}",
            decode_sent(&sent[0].1)
        )
    });
    assert_eq!(ics.amf_ue_ngap_id, new_id);
    assert!(ics.items.is_empty(), "no session re-activated");
    let accept = deciphered_registration_accept(
        &ue_keys,
        ics.nas_pdu.as_deref().expect("the Accept rides the ICS"),
    );
    assert_eq!(accept.pdu_session_status, None);
    assert_eq!(accept.pdu_session_reactivation_result, None);
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        if let Some(sess) = guard.sess_find_by_psi(new_id, 1) {
            guard.sess_remove(sess.id);
        }
    }
    server.ue_auth_state.remove(new_id);
}

/// The fallback: when the Initial Context Setup cannot be encoded (here: an
/// empty Allowed NSSAI, which the SIZE(1..8) list refuses), the Accept is not
/// lost. It goes on its own in a Downlink NAS Transport, and the UE context is
/// not recorded as being set up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_update_from_cm_idle_whose_initial_context_setup_cannot_encode_still_gets_its_accept() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_759_301u64, 7_759_302u64, 0x0759_0301u32);
    let mut stored = idle_ue_for_update(old_id, tmsi);
    stored.amf_ue.allowed_nssai.clear();
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    server.forced_amf_ue_ngap_id = Some(new_id);

    let rr = super::guti_registration_request(
        crate::gmm_build::registration_type::PERIODIC_UPDATING,
        tmsi,
    );
    let nas = super::protected_initial_registration(&ue_keys, &rr, &rr, 5);
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(nas))
        .await
        .expect("the update is handled");

    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas {
        amf_ue_ngap_id,
        nas_pdu,
    }] = sent.as_slice()
    else {
        panic!("one DL NAS Transport, got {sent:?}");
    };
    assert_eq!(*amf_ue_ngap_id, new_id);
    let _ = deciphered_registration_accept(&ue_keys, nas_pdu);
    let resumed = server.ue_auth_state.get(new_id).expect("the resumed UE");
    assert!(!resumed.initial_context_setup_request_sent);
    drop(resumed);
    server.ue_auth_state.remove(new_id);
}

// ---------------------------------------------------------------------------
// #826 review: ICS Failure for a registered UE; the §4.4.6 gate for the session
// IEs; the IEs are always overwritten
// ---------------------------------------------------------------------------

/// #826 review M1, TS 38.413 §8.3.1.3. The gNB refuses the Initial Context Setup
/// that carried a CM-IDLE mobility update's Accept and re-activated PSI 1. The
/// UE was registered before this ICS, so only the NG connection ends:
/// - the UE stays in the store, registered and CM-IDLE;
/// - the Accept is not counted as delivered;
/// - PSI 1, re-activated by this ICS, is DEACTIVATED at its SMF, so it is not
///   left in ACTIVATING;
/// - a UE Context Release Command (normal release) goes to the gNB.
///
/// The Release Complete that follows does not deactivate a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_ics_failure_after_an_idle_update_keeps_the_ue_registered_and_idle() {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = (7_759_401u64, 7_759_402u64, 0x0759_0401u32);
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    hold_session(&mut server, old_id, 1, "icsfail-759-1", port);
    server.forced_amf_ue_ngap_id = Some(new_id);
    let cleartext = super::guti_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        tmsi,
    );
    let mut full = cleartext.clone();
    full.extend_from_slice(&[0x40, 0x02, 1 << 1, 0x00]);
    let nas = super::protected_initial_registration(&ue_keys, &cleartext, &full, 5);
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(nas))
        .await
        .expect("the update is handled");
    let sent = take_sent_ngap(&mut server);
    assert!(decode_ics(&sent[0].1).is_some(), "the ICS went out");

    let failure = nextgcore_ngap::builder::build_initial_context_setup_failure(
        &nextgcore_ngap::types::InitialContextSetupFailure {
            amf_ue_ngap_id: new_id,
            ran_ue_ngap_id: 512,
            cause: nextgcore_ngap::types::Cause::RadioNetwork(
                nextgcore_ngap::types::CauseRadioNetwork::Unspecified,
            ),
        },
    )
    .expect("encode an Initial Context Setup Failure");
    server
        .handle_initial_context_setup_failure(ASSOC, &failure)
        .await
        .expect("handled");
    // #922: the DEACTIVATED runs off the NGAP task; its answer is applied here.
    settle_offloaded_sbi(&mut server).await;

    let ue = server
        .ue_auth_state
        .get(new_id)
        .expect("the NAS context is kept: the UE stays registered");
    assert!(ue.registered && ue.cm_idle, "registered and CM-IDLE");
    assert!(!ue.registration_accept_sent, "the Accept was not delivered");
    assert!(!ue.initial_context_setup_request_sent);
    drop(ue);
    let states = |calls: &[SmfCall]| -> Vec<String> {
        calls
            .iter()
            .filter(|(u, _)| u.ends_with("/sm-contexts/icsfail-759-1/modify"))
            .filter_map(|(_, b)| b["upCnxState"].as_str().map(str::to_string))
            .collect()
    };
    assert_eq!(
        states(&calls.lock().expect("calls")),
        vec!["ACTIVATING".to_string(), "DEACTIVATED".to_string()],
        "the re-activated user plane is rolled back at the SMF"
    );
    let released: Vec<_> = take_sent_ngap(&mut server)
        .into_iter()
        .filter_map(|(_, p)| super::decoded_release_command(&p))
        .collect();
    assert_eq!(released.len(), 1, "one UE Context Release Command");
    assert_eq!(released[0].0, new_id);

    let complete = nextgcore_ngap::builder::build_ue_context_release_complete(
        &nextgcore_ngap::types::UeContextReleaseComplete {
            amf_ue_ngap_id: new_id,
            ran_ue_ngap_id: 512,
        },
    )
    .expect("encode a UE Context Release Complete");
    server
        .handle_ue_context_release_complete(ASSOC, &complete)
        .await
        .expect("handled");
    assert_eq!(
        states(&calls.lock().expect("calls")).len(),
        2,
        "no second DEACTIVATED on the Release Complete"
    );
    assert!(server.ue_auth_state.contains(new_id));
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        if let Some(sess) = guard.sess_find_by_psi(new_id, 1) {
            guard.sess_remove(sess.id);
        }
    }
    server.forget_ue(new_id);
}

/// #826 review m1. Uplink data status (0x40) and PDU session status (0x50) are
/// non-cleartext (TS 24.501 §4.4.6). An unprotected initial Registration
/// Request carrying either is refused with 5GMM #95, the same as Requested NSSAI.
#[test]
fn the_session_ies_are_non_cleartext() {
    for iei in [0x40u8, 0x50] {
        let mut rr = super::guti_registration_request(
            crate::gmm_build::registration_type::MOBILITY_UPDATING,
            0x0759_0501,
        );
        rr.extend_from_slice(&[iei, 0x02, 0x02, 0x00]);
        let parsed = parse_registration_request_pdu(&rr).expect("parses");
        assert_eq!(
            validate_initial_registration_cleartext(&parsed, false),
            Some(GmmCause::SemanticallyIncorrectMessage),
            "IEI {iei:#04x} in the clear"
        );
        assert_eq!(validate_initial_registration_cleartext(&parsed, true), None);
    }
}

/// #826 review m1: the session IEs of a request that is not integrity-verified
/// are never recorded, whatever happens to the request afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_session_ies_are_not_recorded() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_601u64, 66);
    registered_ue_with_guti(&mut server, ue, ran);
    let rr = update_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        Some(1 << 1),
        Some(1 << 1),
    );
    let _ = server
        .handle_registration_request_nas(ASSOC, ue, ran, &rr, false)
        .await;
    assert_eq!(
        server
            .ue_auth_state
            .get(ue)
            .expect("ue")
            .registration_session_ies,
        None
    );
    server.ue_auth_state.remove(ue);
}

/// #826 review n1, TS 24.501 §4.4.4.3: a CM-CONNECTED UE's mobility update whose
/// MAC fails is not discarded but processed as unprotected, so its Uplink data
/// status and PDU session status are ignored: no session is released or
/// re-activated at the SMF, and none is recorded for the Accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_update_whose_mac_fails_has_its_session_ies_ignored() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_701u64, 67);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "reg759-mac-1", port);
    hold_session(&mut server, ue, 2, "reg759-mac-2", port);

    // The §4.4.4.3 exception path: the request decoded, its MAC failed.
    let plain = update_registration_request(
        crate::gmm_build::registration_type::MOBILITY_UPDATING,
        Some(1 << 1),
        Some(1 << 1),
    );
    let ul_nas = crate::ngap_asn1::UplinkNasTransportData {
        amf_ue_ngap_id: ue,
        ran_ue_ngap_id: ran,
        nas_pdu: ue_protect(&plain, 0),
        user_location_info: None,
    };
    let _ = server
        .handle_integrity_check_failure(
            ASSOC,
            &ul_nas,
            &plain,
            security_header::INTEGRITY_PROTECTED,
        )
        .await;

    assert!(
        calls.lock().expect("calls").is_empty(),
        "no session is released or re-activated: {:?}",
        calls.lock().expect("calls")
    );
    {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        assert!(guard.sess_find_by_psi(ue, 2).is_some(), "PSI 2 is kept");
    }
    assert_eq!(
        server
            .ue_auth_state
            .get(ue)
            .and_then(|s| s.registration_session_ies),
        None
    );
    server.forget_ue(ue);
}

/// #826 review m1, the always-overwritten rule. IEs left on the context by an
/// earlier request (one that never reached an Accept) must not be applied to
/// the Accept of a later request that carries none. The later request
/// overwrites them with nothing: no N11 call, and no session IEs in its Accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_update_without_session_ies_clears_earlier_ones() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_759_701u64, 67);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "stale-759-1", port);
    server.ue_auth_state.with_mut(ue, |s| {
        s.registration_session_ies = Some(ServiceRequestSessionIes {
            uplink_data_status: Some(1 << 1),
            pdu_session_status: Some(0),
        });
    });
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            None,
            None,
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    assert!(
        calls.lock().expect("calls").is_empty(),
        "the stale IEs neither released nor re-activated anything"
    );
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let Some(Sent::DownlinkNas { nas_pdu, .. }) = sent.first() else {
        panic!("a DL NAS Transport, got {sent:?}");
    };
    let accept = registration_accept_of(nas_pdu);
    assert_eq!(accept.pdu_session_status, None);
    assert_eq!(accept.pdu_session_reactivation_result, None);
    let ctx = crate::context::amf_self();
    let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
    if let Some(sess) = guard.sess_find_by_psi(ue, 1) {
        guard.sess_remove(sess.id);
    }
}

/// #826 review M2 (#778): a connected mobility update re-activates PSI 1 with
/// its own PDU SESSION RESOURCE SETUP REQUEST. smfd's downlink-data N1N2
/// (`PDU_RES_SETUP_REQ`) for the same PSI, queued meanwhile, must not produce
/// a second one. The gNB would refuse it as a duplicate of an active session
/// (TS 38.413 §8.2.1.4), and the relayed failure would have the SMF deactivate
/// the working downlink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_reactivated_by_a_registration_update_gets_no_second_setup() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_759_301u64, 63, "imsi-001010007590301");
    registered_ue_with_guti(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "reg759-nodup-1", port);

    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::MOBILITY_UPDATING,
            Some(1 << 1),
            Some(1 << 1),
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    let first: Vec<Sent> = sent_to(&mut server, ue)
        .into_iter()
        .filter(|s| matches!(s, Sent::SetupRequest { .. }))
        .collect();
    assert_eq!(first.len(), 1, "the update's own setup: {first:?}");
    calls.lock().expect("calls").clear();

    let resp = n1n2_transfer(supi, 1, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;

    assert!(
        !sent_to(&mut server, ue)
            .iter()
            .any(|s| matches!(s, Sent::SetupRequest { .. })),
        "no second PDU SESSION RESOURCE SETUP REQUEST for PSI 1"
    );
    assert!(
        calls.lock().expect("calls").is_empty(),
        "and no second ACTIVATING at the SMF"
    );
    server.forget_ue(ue);
}

// ---------------------------------------------------------------------------
// #845: an aborted procedure releases the UE's PDU sessions before forgetting it
// ---------------------------------------------------------------------------

/// The SM context refs the stand-in SMF was asked to release, sorted.
fn released_sm_refs(calls: &std::sync::Mutex<Vec<SmfCall>>) -> Vec<String> {
    let mut refs: Vec<String> = calls
        .lock()
        .expect("calls")
        .iter()
        .filter_map(|(uri, _)| {
            let rest = uri.split("/sm-contexts/").nth(1)?;
            let (sm_ref, op) = rest.split_once('/')?;
            (op == "release").then(|| sm_ref.to_string())
        })
        .collect();
    refs.sort();
    refs
}

/// The abort paths #845 names, each driven through its real handler.
#[derive(Clone, Copy, Debug)]
enum Abort {
    RegistrationReject,
    T3560Exhausted,
    T3570Exhausted,
    SecurityModeReject,
    InitialContextSetupFailure,
}

/// A registered UE holding PSIs 1 and 2 at the stand-in SMF, whose procedure
/// `abort` ends. Returns the refs released at the SMF, what is left of the
/// UE's session state, and whether the UE is still held.
async fn abort_with_sessions(
    abort: Abort,
    ue: u64,
    ran: u32,
) -> (Vec<String>, (usize, usize, usize), bool) {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, &format!("abort-845-{ue}-1"), port);
    hold_session(&mut server, ue, 2, &format!("abort-845-{ue}-2"), port);
    match abort {
        Abort::RegistrationReject => {
            let reject = gmm_build::build_registration_reject(GmmCause::IllegalUe);
            server
                .reject_and_release(ASSOC, ue, ran, &reject, 1)
                .await
                .expect("rejected");
        }
        Abort::T3560Exhausted => {
            server.ue_auth_state.with_mut(ue, |s| {
                s.retx = Some(NasRetx {
                    timer: NasProcTimer::T3560,
                    deadline: Instant::now() - Duration::from_secs(1),
                    retries: 100,
                    ngap_pdu: vec![0x00],
                });
            });
            server.process_nas_timers().await.expect("timers");
        }
        Abort::T3570Exhausted => {
            // A SUCI identification (not the PEI one) that went unanswered.
            server.ue_auth_state.with_mut(ue, |s| {
                s.pei_requested = false;
                s.retx = Some(NasRetx {
                    timer: NasProcTimer::T3570,
                    deadline: Instant::now() - Duration::from_secs(1),
                    retries: 100,
                    ngap_pdu: vec![0x00],
                });
            });
            server.process_nas_timers().await.expect("timers");
        }
        Abort::SecurityModeReject => {
            let reject = ue_protect(&[0x7E, 0x00, message_type::SECURITY_MODE_REJECT, 0x18], 0);
            server
                .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &reject))
                .await
                .expect("handled");
        }
        Abort::InitialContextSetupFailure => {
            // The abort case is the ICS of an INITIAL registration: the UE is not
            // registered yet. Since #826 (review M1) a registered UE whose ICS fails
            // stays registered and keeps its sessions, so nothing is aborted.
            server.ue_auth_state.with_mut(ue, |s| s.registered = false);
            let failure = crate::ngap_asn1::tests::ics_failure_pdu(
                ue,
                ran,
                nextgcore_ngap::types::Cause::RadioNetwork(
                    nextgcore_ngap::types::CauseRadioNetwork::Unspecified,
                ),
            );
            server
                .handle_initial_context_setup_failure(ASSOC, &failure)
                .await
                .expect("handled");
        }
    }
    // The releases run off the NGAP task.
    server.sbi_offload.settle().await;
    let held = server.ue_auth_state.contains(ue);
    let state = session_state_of(&server, ue);
    server.forget_ue(ue);
    (released_sm_refs(&calls), state, held)
}

/// #845: every abort path that ends a UE context releases each PDU session it
/// held at the SMF (TS 23.502 §4.2.2.3.2), and only then is nothing left: no
/// UE, no refs, no `sess_list` entry. Before the fix the refs went with
/// `forget_ue` and nothing released them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_procedure_releases_the_sessions_before_forgetting_the_ue() {
    for (n, abort) in [
        Abort::RegistrationReject,
        Abort::T3560Exhausted,
        Abort::T3570Exhausted,
        Abort::SecurityModeReject,
        Abort::InitialContextSetupFailure,
    ]
    .into_iter()
    .enumerate()
    {
        let ue = 7_845_001 + n as u64;
        let (released, state, held) = abort_with_sessions(abort, ue, 70 + n as u32).await;
        assert_eq!(
            released,
            vec![format!("abort-845-{ue}-1"), format!("abort-845-{ue}-2")],
            "{abort:?}: each session is released at the SMF holding it"
        );
        assert_eq!(state, (0, 0, 0), "{abort:?}: nothing is left");
        assert!(!held, "{abort:?}: the UE context is gone");
    }
}

// ---------------------------------------------------------------------------
// #653: an update from CM-IDLE with no follow-on request releases the connection
// ---------------------------------------------------------------------------

/// `inner` as the UE sends it under `ue`'s context: integrity protected and
/// ciphered (security header type 2), uplink NAS COUNT `count`.
fn ue_protect_ciphered(ue: &crate::context::AmfUe, inner: &[u8], count: u8) -> Vec<u8> {
    let mut ciphered = inner.to_vec();
    nas_security::nas_encrypt(
        ue.selected_enc_algorithm,
        &ue.knas_enc,
        u32::from(count),
        ue.access_type,
        nas_security::direction::UPLINK,
        &mut ciphered,
    );
    let mut mac_data = vec![count];
    mac_data.extend_from_slice(&ciphered);
    let mac = nas_security::nas_mac_calculate(
        ue.selected_int_algorithm,
        &ue.knas_int,
        u32::from(count),
        ue.access_type,
        nas_security::direction::UPLINK,
        &mac_data,
    );
    let mut out = vec![0x7E, security_header::INTEGRITY_PROTECTED_AND_CIPHERED];
    out.extend_from_slice(&mac);
    out.push(count);
    out.extend_from_slice(&ciphered);
    out
}

/// A periodic update from CM-IDLE (no session IEs), with the Follow-on request
/// bit as given, answered and completed: ICS, ICS Response, Registration
/// Complete. Returns the UE Context Release Commands sent after the Accept, as
/// `(AMF UE NGAP ID, RAN UE NGAP ID, NAS cause)`, and whether the UE is still
/// registered.
async fn complete_idle_update(
    follow_on: bool,
    uplink_data_for_psi_1: bool,
    ids: (u64, u64, u32),
) -> (Vec<(u64, Option<u32>, Option<u8>)>, bool) {
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeFixtureGuami::install();
    let mut server = capturing_ngap_server().await;
    let (old_id, new_id, tmsi) = ids;
    let stored = idle_ue_for_update(old_id, tmsi);
    let ue_keys = stored.amf_ue.clone();
    server.ue_auth_state.insert(old_id, stored);
    server.forced_amf_ue_ngap_id = Some(new_id);
    let (_smf, port, _calls) = activating_smf().await;
    hold_session(&mut server, old_id, 1, &format!("upd653-{old_id}"), port);

    let mut rr = super::guti_registration_request(
        crate::gmm_build::registration_type::PERIODIC_UPDATING,
        tmsi,
    );
    if follow_on {
        rr[3] |= 0x08; // Follow-on request pending (TS 24.501 §9.11.3.7)
    }
    let mut full = rr.clone();
    if uplink_data_for_psi_1 {
        full.extend_from_slice(&[0x40, 0x02, 1 << 1, 0x00]); // Uplink data status: PSI 1
    }
    let nas = super::protected_initial_registration(&ue_keys, &rr, &full, 5);
    server
        .handle_initial_ue_message(ASSOC, &super::service_request_initial_ue(nas))
        .await
        .expect("the update is handled");
    let ran = server
        .ue_auth_state
        .get(new_id)
        .expect("resumed")
        .ran_ue_ngap_id;
    take_sent_ngap(&mut server);
    server
        .handle_initial_context_setup_response(
            ASSOC,
            &crate::ngap_asn1::tests::ics_response_pdu(new_id, ran),
        )
        .await
        .expect("ICS Response handled");
    let complete = ue_protect_ciphered(
        &ue_keys,
        &[0x7E, 0x00, message_type::REGISTRATION_COMPLETE],
        6,
    );
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(new_id, ran, &complete))
        .await
        .expect("Registration Complete handled");
    let released: Vec<_> = take_sent_ngap(&mut server)
        .iter()
        .filter_map(|(_, pdu)| super::decoded_release_command(pdu))
        .collect();
    let registered = server
        .ue_auth_state
        .get(new_id)
        .is_some_and(|s| s.registered);
    server.forget_ue(new_id);
    server.forget_ue(old_id);
    (released, registered)
}

/// #653, TS 24.501 §5.3.1.3 b) / TS 23.502 §4.2.2.2.2 step 23: an update from
/// 5GMM-IDLE with "No follow-on request pending", no Uplink data status and no
/// user plane re-established has nothing left to use the connection for. Once
/// the registration completes, the AMF releases it with a normal UE Context
/// Release (CauseNas normal-release 0), and the UE stays registered. Its next
/// uplink data then starts a Service Request, which restores the user plane.
/// Before #653 the connection stayed up with no user plane, and the UE, which
/// was CM-CONNECTED, never sent a Service Request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_without_follow_on_releases_the_connection_once_complete() {
    let (released, registered) =
        complete_idle_update(false, false, (7_653_001, 7_653_002, 0x0653_0001)).await;
    // (`decoded_release_command` reads only a radioNetwork cause; the NAS
    // normal-release is the builder's `cause_group::NAS`, 0.)
    assert_eq!(
        released,
        vec![(7_653_002, Some(512), None)],
        "one release of the update's connection, and not a radio-network one"
    );
    assert!(registered, "the UE stays registered");
}

/// The control: with "Follow-on request pending" the UE has more to do on the
/// connection, so it is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_with_follow_on_keeps_the_connection() {
    let (released, registered) =
        complete_idle_update(true, false, (7_653_011, 7_653_012, 0x0653_0011)).await;
    assert_eq!(released, vec![], "no release");
    assert!(registered);
}

/// Nor is a connection whose update re-established a user plane (Uplink data
/// status {1}) released: the UE has data to send on it (TS 24.501 §5.3.1.3 b) 3)).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_that_reactivated_a_session_keeps_the_connection() {
    let (released, registered) =
        complete_idle_update(false, true, (7_653_021, 7_653_022, 0x0653_0021)).await;
    assert_eq!(released, vec![], "no release");
    assert!(registered);
}

/// #749 over the Namf surface: smfd's downlink-data N1N2 for PSI 2 pages the
/// idle UE (202). The one for PSI 1, while that paging is ongoing, is answered
/// 409 with `N1N2MessageTransferError` cause HIGHER_PRIORITY_REQUEST_ONGOING and
/// `errInfo.retryAfter` (TS 29.518 §5.2.2.3.1), and leaves PSI 2's paging as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_downlink_data_transfer_while_paging_gets_409_with_retry_after() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, _calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran, supi) = (7_749_021u64, 65, "imsi-001010007490021");
    secured_registered_ue(&mut server, ue, ran);
    with_supi(&mut server, ue, supi);
    hold_session(&mut server, ue, 1, "n1n2-749-a", port);
    hold_session(&mut server, ue, 2, "n1n2-749-b", port);
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);

    let first = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(first.status, 202, "the first one pages");
    let second = n1n2_transfer(supi, 1, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(second.status, 409);
    let body: serde_json::Value =
        serde_json::from_str(second.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    assert_eq!(body["error"]["cause"], "HIGHER_PRIORITY_REQUEST_ONGOING");
    assert_eq!(
        body["errInfo"]["retryAfter"].as_u64(),
        Some(crate::namf_handler::PAGING_ONGOING_RETRY_AFTER_S)
    );
    let paged = crate::context::amf_self()
        .read()
        .unwrap()
        .paging_remove(ue)
        .expect("paging for PSI 2");
    assert_eq!(paged.pdu_session_id, Some(2));
    server.forget_ue(ue);
}
