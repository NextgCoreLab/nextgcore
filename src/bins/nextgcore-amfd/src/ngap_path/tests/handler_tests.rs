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
// #757: N1N2MessageTransfer PDU_RES_SETUP_REQ / PDU_RES_MOD_REQ to a UE
// ---------------------------------------------------------------------------

/// Give the UE a SUPI, so the Namf surface resolves it.
fn with_supi(server: &mut NgapServer, amf_ue_ngap_id: u64, supi: &str) {
    server.ue_auth_state.with_mut(amf_ue_ngap_id, |s| {
        s.amf_ue.supi = Some(supi.to_string());
    });
}

/// An N1N2MessageTransfer through the live Namf request handler. `n2` is the
/// `ngapIeType` and the transfer octets (absent: no `ngapData`, as smfd's
/// downlink-data request sends it). `n1` is the N1 SM message.
async fn n1n2_transfer(
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
fn sent_to(server: &mut NgapServer, ue: u64) -> Vec<Sent> {
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
    calls.lock().expect("calls").clear();

    let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
    assert_eq!(resp.status, 200);
    server.process_connected_downlinks().await;
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
struct ServeOneGuami(Vec<crate::context::Guami>);

impl ServeOneGuami {
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
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
