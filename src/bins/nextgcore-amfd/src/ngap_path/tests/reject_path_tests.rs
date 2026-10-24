//! #752: the reject paths of RAN CONFIGURATION UPDATE (#571), PWS RESTART /
//! FAILURE INDICATION, UPLINK (NON) UE ASSOCIATED NRPPA TRANSPORT (#575) and
//! PDU SESSION RESOURCE NOTIFY (#575), driven through `process_ngap_message`
//! with the NGAP egress captured. Each test asserts the exact answer: the
//! procedure, its cause, and the IEs its Criticality Diagnostics name.

use super::*;
use nextgcore_ngap_gen::generated as g;

/// The association every gNB in this module is on.
const GNB_ASSOC: u64 = 7_752;

/// One answer, reduced to what the tests assert.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// ERROR INDICATION: protocol cause, Criticality Diagnostics IE ids, UE ids.
    ErrorIndication {
        protocol_cause: Option<u8>,
        ie_ids: Vec<u16>,
        amf_ue_ngap_id: Option<u64>,
    },
    /// RAN CONFIGURATION UPDATE FAILURE: protocol cause, diagnostics IE ids.
    RcuFailure {
        protocol_cause: Option<u8>,
        ie_ids: Vec<u16>,
    },
    /// RAN CONFIGURATION UPDATE ACKNOWLEDGE.
    RcuAcknowledge,
    Other,
}

fn diagnostics_ids(d: &Option<g::CriticalityDiagnostics>) -> Vec<u16> {
    d.as_ref()
        .and_then(|d| d.i_es_criticality_diagnostics.as_ref())
        .map(|l| l.0.iter().map(|i| i.ie_id.0).collect())
        .unwrap_or_default()
}

fn protocol_cause(c: &Option<g::Cause>) -> Option<u8> {
    match c {
        Some(g::Cause::Protocol(p)) => Some(p.0),
        _ => None,
    }
}

fn answer(pdu: &[u8]) -> Answer {
    if let Some(ei) = crate::ngap_asn1::decode_error_indication_asn1(pdu) {
        return Answer::ErrorIndication {
            protocol_cause: protocol_cause(&ei.cause),
            ie_ids: diagnostics_ids(&ei.criticality_diagnostics),
            amf_ue_ngap_id: ei.amf_ue_ngap_id,
        };
    }
    match nextgcore_ngap_gen::decode(pdu) {
        Ok(g::NGAP_PDU::UnsuccessfulOutcome(u)) => match u.value {
            g::UnsuccessfulOutcomeValue::Id_RANConfigurationUpdate(f) => {
                use g::RANConfigurationUpdateFailureProtocolIEs_EntryValue as Ie;
                let (mut cause, mut diag) = (None, None);
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        Ie::Id_Cause(c) => cause = Some(c),
                        Ie::Id_CriticalityDiagnostics(d) => diag = Some(d),
                        _ => {}
                    }
                }
                Answer::RcuFailure {
                    protocol_cause: protocol_cause(&cause),
                    ie_ids: diagnostics_ids(&diag),
                }
            }
            _ => Answer::Other,
        },
        Ok(g::NGAP_PDU::SuccessfulOutcome(o))
            if matches!(
                o.value,
                g::SuccessfulOutcomeValue::Id_RANConfigurationUpdate(_)
            ) =>
        {
            Answer::RcuAcknowledge
        }
        _ => Answer::Other,
    }
}

/// Process `pdu` from [`GNB_ASSOC`] and return what was sent, decoded, with the
/// association each went to.
async fn answers_to(server: &mut NgapServer, pdu: &[u8]) -> Vec<(u64, Answer)> {
    server
        .process_ngap_message(GNB_ASSOC, pdu)
        .await
        .expect("handled");
    take_sent_ngap(server)
        .into_iter()
        .map(|(a, p)| (a, answer(&p)))
        .collect()
}

/// A gNB on [`GNB_ASSOC`] serving TAC 1 of 999-70.
async fn gnb(server: &mut NgapServer) {
    let mut session = GnbSession::new(
        GNB_ASSOC,
        GNB_ASSOC,
        "127.0.0.1:38412".parse().expect("addr"),
    );
    session.gnb.supported_ta_list = vec![crate::context::SupportedTa {
        tac: 1,
        num_of_bplmn_list: 1,
        bplmn_list: vec![crate::context::BplmnEntry {
            plmn_id: PlmnId::new("999", "70"),
            num_of_s_nssai: 0,
            s_nssai: Vec::new(),
        }],
    }];
    session.gnb.num_of_supported_ta_list = 1;
    server.sessions.write().await.insert(GNB_ASSOC, session);
}

async fn stored_tacs(server: &NgapServer) -> Vec<u32> {
    server.sessions.read().await[&GNB_ASSOC]
        .gnb
        .supported_ta_list
        .iter()
        .map(|t| t.tac)
        .collect()
}

/// A RAN CONFIGURATION UPDATE replacing the TA list with TAC 7.
fn rcu() -> Vec<u8> {
    nextgcore_ngap::builder::build_ran_configuration_update(
        &nextgcore_ngap::types::RanConfigurationUpdate {
            ran_node_name: Some("g752".to_string()),
            supported_ta_list: Some(vec![nextgcore_ngap::types::SupportedTaItem {
                tac: [0x00, 0x00, 0x07],
                broadcast_plmn_list: vec![nextgcore_ngap::types::BroadcastPlmnItem {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    tai_slice_support_list: vec![nextgcore_ngap::types::SNssai {
                        sst: 1,
                        sd: None,
                    }],
                }],
            }]),
            default_paging_drx: None,
            global_ran_node_id: None,
        },
    )
    .expect("build")
}

/// `pdu` with one more protocol IE appended (`id`, criticality octet, a
/// one-octet value), as `ngap_asn1`'s `with_unknown_ie` does.
fn with_unknown_ie(pdu: &[u8], id: u16, criticality: u8) -> Vec<u8> {
    crate::ngap_asn1::tests::with_unknown_ie(pdu, id, criticality)
}

/// The happy path, as the reference the reject cases are measured against: the
/// update is acknowledged and applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ran_configuration_update_is_acknowledged_and_applied() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    assert_eq!(
        answers_to(&mut server, &rcu()).await,
        vec![(GNB_ASSOC, Answer::RcuAcknowledge)]
    );
    assert_eq!(stored_tacs(&server).await, vec![7]);
}

/// #571, TS 38.413 §10.3.4.2: a not-comprehended IE marked reject fails the
/// update. RAN CONFIGURATION UPDATE FAILURE, abstract-syntax-error-reject,
/// the IE named in the diagnostics; the stored TA list is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ran_configuration_update_with_a_reject_ie_fails_and_applies_nothing() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let pdu = with_unknown_ie(&rcu(), 9_999, 0x00);
    assert_eq!(
        answers_to(&mut server, &pdu).await,
        vec![(
            GNB_ASSOC,
            Answer::RcuFailure {
                protocol_cause: Some(g::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT),
                ie_ids: vec![9_999],
            }
        )]
    );
    assert_eq!(stored_tacs(&server).await, vec![1]);
}

/// TS 38.413 §10.2: an update that does not decode is a Transfer Syntax Error,
/// reported by Error Indication (transfer-syntax-error), not by the
/// procedure's failure; nothing is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_ran_configuration_update_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let mut pdu = rcu();
    pdu.truncate(pdu.len() - 3);
    assert_eq!(
        answers_to(&mut server, &pdu).await,
        vec![(
            GNB_ASSOC,
            Answer::ErrorIndication {
                protocol_cause: Some(g::CauseProtocol::TRANSFER_SYNTAX_ERROR),
                ie_ids: vec![],
                amf_ue_ngap_id: None,
            }
        )]
    );
    assert_eq!(stored_tacs(&server).await, vec![1]);
}

/// PDU SESSION RESOURCE NOTIFY (procedure 30), UE IDs 42/7, one Notify item
/// (as `ngap_asn1`'s decoder test derives it).
const NOTIFY: [u8; 29] = [
    0x00, 0x1E, 0x40, 0x19, 0x00, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x2A, 0x00, 0x55, 0x00,
    0x02, 0x00, 0x07, 0x00, 0x42, 0x00, 0x06, 0x00, 0x00, 0x05, 0x02, 0xAB, 0xCD,
];

/// The same Notify without its AMF UE NGAP ID (mandatory, criticality reject).
const NOTIFY_NO_AMF_ID: [u8; 23] = [
    0x00, 0x1E, 0x40, 0x13, 0x00, 0x00, 0x02, 0x00, 0x55, 0x00, 0x02, 0x00, 0x07, 0x00, 0x42, 0x00,
    0x06, 0x00, 0x00, 0x05, 0x02, 0xAB, 0xCD,
];

/// #575, TS 38.413 §10.3.5: a Notify missing a mandatory reject IE is
/// terminated with an Error Indication naming it (abstract-syntax-error-
/// falsely-constructed-message per §10.3.5 / the codec's report); nothing is
/// relayed to an SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_missing_its_amf_ue_ngap_id_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &NOTIFY_NO_AMF_ID).await;
    let [(assoc, Answer::ErrorIndication { ie_ids, .. })] = sent.as_slice() else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(*assoc, GNB_ASSOC);
    assert_eq!(ie_ids, &vec![g::ID_AMF_UE_NGAP_ID]);
}

/// #575, §10.3.4.2: a not-comprehended IE marked reject terminates the Notify
/// with an Error Indication naming it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_with_a_reject_ie_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &with_unknown_ie(&NOTIFY, 9_998, 0x00)).await;
    let [(
        _,
        Answer::ErrorIndication {
            ie_ids,
            protocol_cause,
            ..
        },
    )] = sent.as_slice()
    else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(ie_ids, &vec![9_998]);
    assert_eq!(
        *protocol_cause,
        Some(g::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT)
    );
}

/// §10.3.4.2: an IE marked "ignore and notify" is reported in an Error
/// Indication and the Notify is processed (here: its UE is unknown, so nothing
/// else is sent).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_with_a_notify_ie_is_processed_and_reported() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &with_unknown_ie(&NOTIFY, 9_997, 0x80)).await;
    let [(
        _,
        Answer::ErrorIndication {
            ie_ids,
            protocol_cause,
            ..
        },
    )] = sent.as_slice()
    else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(ie_ids, &vec![9_997]);
    assert_eq!(
        *protocol_cause,
        Some(g::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY)
    );
}

/// #71: a well-formed Notify is accepted and answered with nothing (class 2;
/// its UE is unknown here, so nothing is relayed either).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_well_formed_notify_gets_no_answer() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    assert_eq!(answers_to(&mut server, &NOTIFY).await, vec![]);
}

/// §10.2 for the Notify too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_notify_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &NOTIFY[..NOTIFY.len() - 4]).await;
    assert_eq!(
        sent,
        vec![(
            GNB_ASSOC,
            Answer::ErrorIndication {
                protocol_cause: Some(g::CauseProtocol::TRANSFER_SYNTAX_ERROR),
                ie_ids: vec![],
                amf_ue_ngap_id: None,
            }
        )]
    );
}

/// UPLINK UE ASSOCIATED NRPPA TRANSPORT (procedure 50) without its Routing ID
/// (as `ngap_asn1`'s decoder test derives it): UE IDs 42/7, NRPPa PDU.
const UL_UE_NRPPA_NO_ROUTING: [u8; 28] = [
    0x00, 0x32, 0x40, 0x18, 0x00, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x2A, 0x00, 0x55, 0x00,
    0x02, 0x00, 0x07, 0x00, 0x2E, 0x00, 0x05, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
];

/// #575: an Uplink UE-associated NRPPa Transport missing its Routing ID gets an
/// Error Indication naming it, for the UE it was about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uplink_nrppa_transport_without_its_routing_id_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &UL_UE_NRPPA_NO_ROUTING).await;
    let [(
        assoc,
        Answer::ErrorIndication {
            ie_ids,
            amf_ue_ngap_id,
            ..
        },
    )] = sent.as_slice()
    else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(*assoc, GNB_ASSOC);
    assert_eq!(ie_ids, &vec![g::ID_ROUTING_ID]);
    assert_eq!(*amf_ue_ngap_id, Some(42));
}

/// PWS FAILURE INDICATION (procedure 48... per the generated constant), with or
/// without its mandatory PWS Failed Cell ID List.
fn pws_failure_indication(with_cells: bool) -> Vec<u8> {
    use bitvec::prelude::{BitVec, Msb0};
    use g::PWSFailureIndicationProtocolIEs_EntryValue as Ie;
    let entry = |id, value| g::PWSFailureIndicationProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(g::Criticality::REJECT),
        value,
    };
    let mut gnb_id = BitVec::<u8, Msb0>::new();
    for i in 0..22 {
        gnb_id.push(i == 21);
    }
    let mut ies = vec![entry(
        g::ID_GLOBAL_RAN_NODE_ID,
        Ie::Id_GlobalRANNodeID(g::GlobalRANNodeID::GlobalGNB_ID(g::GlobalGNB_ID {
            plmn_identity: g::PLMNIdentity(vec![0x99, 0xF9, 0x07]),
            gnb_id: g::GNB_ID::GNB_ID(g::GNB_ID_gNB_ID(gnb_id)),
            ie_extensions: None,
        })),
    )];
    if with_cells {
        let cell = BitVec::<u8, Msb0>::repeat(false, 36);
        ies.push(entry(
            g::ID_PWS_FAILED_CELL_ID_LIST,
            Ie::Id_PWSFailedCellIDList(g::PWSFailedCellIDList::NR_CGI_PWSFailedList(
                g::NR_CGIList(vec![g::NR_CGI {
                    plmn_identity: g::PLMNIdentity(vec![0x99, 0xF9, 0x07]),
                    nr_cell_identity: g::NRCellIdentity(cell),
                    ie_extensions: None,
                }]),
            )),
        ));
    }
    nextgcore_ngap_gen::encode(&g::NGAP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(g::ID_PWS_FAILURE_INDICATION),
        criticality: g::Criticality(g::Criticality::IGNORE),
        value: g::InitiatingMessageValue::Id_PWSFailureIndication(g::PWSFailureIndication {
            protocol_i_es: g::PWSFailureIndicationProtocolIEs(ies),
        }),
    }))
    .expect("encode")
}

/// #575: a PWS Failure Indication missing its PWS Failed Cell ID List gets an
/// Error Indication naming it; the complete one gets no answer (class 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pws_failure_indication_without_its_cell_list_gets_an_error_indication() {
    let mut server = capturing_ngap_server().await;
    gnb(&mut server).await;
    let sent = answers_to(&mut server, &pws_failure_indication(false)).await;
    let [(assoc, Answer::ErrorIndication { ie_ids, .. })] = sent.as_slice() else {
        panic!("one Error Indication: {sent:?}");
    };
    assert_eq!(*assoc, GNB_ASSOC);
    assert_eq!(ie_ids, &vec![g::ID_PWS_FAILED_CELL_ID_LIST]);

    assert_eq!(
        answers_to(&mut server, &pws_failure_indication(true)).await,
        vec![]
    );
}
