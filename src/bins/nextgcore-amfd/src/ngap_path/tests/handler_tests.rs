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
/// A `fail-*` ref gets 500. Everything else gets 204. Keep the server alive.
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
    use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
    match parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&nas[7..])) {
        Ok(FiveGmmMessage::RegistrationAccept(a)) => a,
        other => panic!("a REGISTRATION ACCEPT, got {other:?}"),
    }
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
