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
async fn connected_service_request(
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
async fn path_switch_smf() -> (
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener); // the SMF is down: connection refused
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

    // The SMF comes back on the same address.
    let (_smf, seen) =
        creating_smf_on(std::net::TcpListener::bind(("127.0.0.1", port)).expect("rebind")).await;
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener); // the SMF is down
    let _env = super::SmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_980_001u64, 98);
    ue_ready_for_sessions(&mut server, ue, ran);

    let request = [0x2E, 0x05, 0x01, 0xC1, 0xFF, 0xFF];
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &request))
        .await
        .expect("handled");
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
    let rebound = std::net::TcpListener::bind(("127.0.0.1", port)).expect("rebind");
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

/// When no SMF comes back within the window, the UE is answered as TS 24.501
/// prescribes for a routing failure (§5.4.5.2.5 a) 1), §5.4.5.3.1 e)): a DL NAS
/// TRANSPORT carrying its own 5GSM message back, with 5GMM #90. The AMF does
/// not fabricate a 5GSM reject. A UE retransmission does not extend the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn an_establishment_with_no_smf_back_in_the_window_gets_payload_not_forwarded() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let _env = super::SmfEnvGuard::acquire(port).await;
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

/// An SMF that never answers: a listener nobody accepts on, so the connection
/// sits in the backlog and the request waits for the client's timeout. Locally
/// deterministic stand-in for a blackholed address (a stale pod IP, a lost node).
/// Keep the listener alive.
fn hanging_smf() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

/// Wait until `n` off-task exchanges hold a permit.
async fn until_in_flight(server: &NgapServer, n: usize) {
    for _ in 0..200 {
        if server.sbi_offload.in_flight() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("in flight: {}, wanted {n}", server.sbi_offload.in_flight());
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
/// The first attempt is made inline and takes `HOLD` to fail, so a window
/// started at the deferral (`Instant::now()` there) would be `HOLD` shorter.
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
    assert!(
        inline >= HOLD,
        "the fixture must make the first attempt take time: {inline:?}"
    );
    let started = server.pending_establishments[&(ue, 5)].first_failure;
    assert!(
        started.duration_since(before) < Duration::from_millis(100),
        "the window must start at arrival ({:?} after it), not when the first \
         attempt failed ({inline:?} after it)",
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let _env = super::SmfEnvGuard::acquire(port).await;
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
fn switch_off_deregistration_request() -> Vec<u8> {
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
fn establishment_request(psi: u8) -> Vec<u8> {
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
    // The unrecorded session's SMF release runs off the NGAP task.
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
