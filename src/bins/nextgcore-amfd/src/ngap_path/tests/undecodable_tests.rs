//! #999, TS 38.413 §10.2: *"If a Transfer Syntax Error occurs, the receiver should
//! initiate Error Indication procedure with appropriate cause value for the Transfer
//! Syntax protocol error."* Every gNB-to-AMF procedure the AMF handles is driven
//! through `process_ngap_message` with a PDU that names the procedure but does not
//! decode, and must be answered with exactly one Error Indication (protocol cause
//! transfer-syntax-error, no UE id, since none could be read) on the same
//! association. An undecodable Error Indication is the one exception: it is never
//! answered, or two peers could loop.
//!
//! Also #910's open MINOR: the non-UE-associated NRPPa transport's reject arm.

use super::*;
use nextgcore_ngap_gen::generated as g;

/// The association every gNB in this module is on.
const GNB_ASSOC: u64 = 9_990;

#[derive(Debug, PartialEq, Eq)]
struct Ei {
    protocol_cause: Option<u8>,
    ie_ids: Vec<u16>,
    amf_ue_ngap_id: Option<u64>,
}

fn as_error_indication(pdu: &[u8]) -> Option<Ei> {
    let ei = crate::ngap_asn1::decode_error_indication_asn1(pdu)?;
    Some(Ei {
        protocol_cause: match ei.cause {
            Some(g::Cause::Protocol(p)) => Some(p.0),
            _ => None,
        },
        ie_ids: ei
            .criticality_diagnostics
            .as_ref()
            .and_then(|d| d.i_es_criticality_diagnostics.as_ref())
            .map(|l| l.0.iter().map(|i| i.ie_id.0).collect())
            .unwrap_or_default(),
        amf_ue_ngap_id: ei.amf_ue_ngap_id,
    })
}

async fn server_with_gnb() -> NgapServer {
    let server = capturing_ngap_server().await;
    let session = GnbSession::new(
        GNB_ASSOC,
        GNB_ASSOC,
        "127.0.0.1:38412".parse().expect("addr"),
    );
    server.sessions.write().await.insert(GNB_ASSOC, session);
    server
}

/// A PDU of `kind` (0x00 initiating, 0x20 successful, 0x40 unsuccessful) for
/// `procedure` whose value claims five protocol IEs and carries none: the
/// procedure is recognisable, the message is not decodable.
fn undecodable(kind: u8, procedure: u8) -> Vec<u8> {
    vec![kind, procedure, 0x00, 0x03, 0x00, 0x00, 0x05]
}

/// Every handler with an undecodable arm, as (what, message kind, procedure code).
const PROCEDURES: &[(&str, u8, u8)] = &[
    ("NG Reset", 0x00, 20),
    ("Initial UE Message", 0x00, 15),
    ("Uplink NAS Transport", 0x00, 46),
    ("Initial Context Setup Response", 0x20, 14),
    ("Initial Context Setup Failure", 0x40, 14),
    ("PDU Session Resource Setup Response", 0x20, 29),
    ("PDU Session Resource Modify Response", 0x20, 26),
    ("PDU Session Resource Release Response", 0x20, 28),
    ("PDU Session Resource Modify Indication", 0x00, 27),
    ("PDU Session Resource Notify", 0x00, 30),
    ("UE Context Release Request", 0x00, 42),
    ("UE Context Release Complete", 0x20, 41),
    ("Handover Required", 0x00, 12),
    ("Handover Request Acknowledge", 0x20, 13),
    ("Handover Failure", 0x40, 13),
    ("Handover Notify", 0x00, 11),
    ("Path Switch Request", 0x00, 25),
    ("Handover Cancel", 0x00, 10),
    ("Uplink RAN Status Transfer", 0x00, 49),
    ("Uplink UE-associated NRPPa Transport", 0x00, 50),
    ("Uplink non-UE-associated NRPPa Transport", 0x00, 47),
    ("RAN Configuration Update", 0x00, 35),
    ("Write-Replace Warning Response", 0x20, 51),
    ("PWS Cancel Response", 0x20, 32),
    ("PWS Restart Indication", 0x00, 33),
    ("PWS Failure Indication", 0x00, 34),
    ("UE Radio Capability Info Indication", 0x00, 44),
    ("UE Radio Capability ID Mapping Request", 0x00, 60),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_undecodable_message_gets_a_transfer_syntax_error_indication() {
    let mut server = server_with_gnb().await;
    let mut wrong = Vec::new();
    for &(what, kind, procedure) in PROCEDURES {
        let _ = take_sent_ngap(&mut server);
        if let Err(e) = server
            .process_ngap_message(GNB_ASSOC, &undecodable(kind, procedure))
            .await
        {
            wrong.push(format!("{what}: handler failed: {e}"));
            continue;
        }
        let sent: Vec<(u64, Option<Ei>)> = take_sent_ngap(&mut server)
            .into_iter()
            .map(|(a, p)| (a, as_error_indication(&p)))
            .collect();
        let want = vec![(
            GNB_ASSOC,
            Some(Ei {
                protocol_cause: Some(g::CauseProtocol::TRANSFER_SYNTAX_ERROR),
                ie_ids: vec![],
                amf_ue_ngap_id: None,
            }),
        )];
        if sent != want {
            wrong.push(format!("{what}: sent {sent:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "not answered per §10.2:\n{}",
        wrong.join("\n")
    );
}

/// An Error Indication that does not decode is not answered with another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_error_indication_is_not_answered() {
    let mut server = server_with_gnb().await;
    server
        .process_ngap_message(
            GNB_ASSOC,
            &undecodable(0x00, proc_code::ERROR_INDICATION as u8),
        )
        .await
        .expect("handled");
    assert!(take_sent_ngap(&mut server).is_empty());
}

/// UPLINK NON UE ASSOCIATED NRPPA TRANSPORT (procedure 47) with only its NRPPa-PDU:
/// the Routing ID (mandatory, criticality reject) is missing.
const UL_NON_UE_NRPPA_NO_ROUTING: [u8; 16] = [
    0x00, 0x2F, 0x40, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x2E, 0x00, 0x05, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
];

/// #910 MINOR, TS 38.413 §10.3.5: the non-UE-associated NRPPa transport missing its
/// Routing ID is terminated with an Error Indication naming it, about no UE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_ue_associated_nrppa_transport_without_its_routing_id_gets_an_error_indication() {
    let mut server = server_with_gnb().await;
    server
        .process_ngap_message(GNB_ASSOC, &UL_NON_UE_NRPPA_NO_ROUTING)
        .await
        .expect("handled");
    let sent: Vec<(u64, Option<Ei>)> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(a, p)| (a, as_error_indication(&p)))
        .collect();
    let [(assoc, Some(ei))] = sent.as_slice() else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(*assoc, GNB_ASSOC);
    assert_eq!(ei.ie_ids, vec![g::ID_ROUTING_ID]);
    assert_eq!(ei.amf_ue_ngap_id, None);
}
