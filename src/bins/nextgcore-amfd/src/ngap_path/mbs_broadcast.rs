//! The NGAP task's half of the broadcast MBS sessions (#1796): it sends the
//! BROADCAST SESSION SETUP / RELEASE REQUESTs [`crate::mbs_broadcast`] plans to
//! the associations of the MBS service area, and feeds the gNBs' answers back.
//!
//! The SBI handler never sends on SCTP: it changes the shared state and this
//! task's per-iteration pump ([`NgapServer::process_mbs_broadcast`]) does the
//! sending, like every other SBI-originated N2 transfer.

use std::time::Instant;

use anyhow::Result;

use super::NgapServer;
use crate::mbs_broadcast::{BroadcastOutcome, LiveGnb, RanNode};

impl NgapServer {
    /// Every connected gNB that completed NG Setup, with its Supported TA List.
    /// ng-eNBs are left out: NR MBS broadcast is a gNB function.
    async fn mbs_live_gnbs(&self) -> Vec<LiveGnb> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.gnb.gnb_id_presence && s.gnb.ng_enb_id.is_none())
            .map(|s| LiveGnb {
                association_id: s.association_id,
                node: RanNode {
                    plmn: s.gnb.plmn_id.clone(),
                    gnb_id: s.gnb.gnb_id,
                    gnb_id_len: s.gnb.gnb_id_len,
                },
                tais: s
                    .gnb
                    .supported_ta_list
                    .iter()
                    .flat_map(|ta| {
                        ta.bplmn_list
                            .iter()
                            .map(move |b| (b.plmn_id.clone(), ta.tac))
                    })
                    .collect(),
            })
            .collect()
    }

    /// Send what the broadcast MBS contexts need on N2 now, and hand every
    /// resulting ContextStatusNotify to its sender. Dormant when no broadcast
    /// context is held.
    pub(crate) async fn process_mbs_broadcast(&mut self) {
        let mcast = crate::context::amf_mcast();
        if !mcast.broadcast_has_work(Instant::now()) {
            return;
        }
        let live = self.mbs_live_gnbs().await;
        let plan = mcast.broadcast_plan(&live, Instant::now());
        let mut notifies = plan.notifies;
        for send in plan.sends {
            for association_id in send.associations {
                match self.send_to_association(association_id, &send.pdu).await {
                    Ok(()) => log::info!(
                        "Broadcast MBS context {}: {:?} Request sent to association \
                         {association_id}",
                        send.id,
                        send.procedure
                    ),
                    Err(e) => {
                        log::warn!(
                            "Broadcast MBS context {}: {:?} Request to association \
                             {association_id} failed: {e}",
                            send.id,
                            send.procedure
                        );
                        notifies.extend(mcast.broadcast_send_failed(
                            send.id,
                            send.procedure,
                            association_id,
                        ));
                    }
                }
            }
        }
        crate::mbs_broadcast::dispatch_notifies(notifies);
    }

    /// A gNB's BROADCAST SESSION SETUP RESPONSE / FAILURE (procedure 68) or
    /// BROADCAST SESSION RELEASE RESPONSE (67), TS 38.413 §8.17.1 / §8.17.3.
    ///
    /// Like the other MBS outcomes, a malformed one is logged and changes nothing,
    /// and none is answered with an Error Indication: the AMF implements the
    /// procedure, so the §10.3 cause the fallthrough would send would be wrong.
    pub(super) async fn handle_broadcast_outcome(
        &mut self,
        association_id: u64,
        procedure_code: Option<u16>,
        data: &[u8],
    ) -> Result<()> {
        let Some(outcome) = crate::mbs_broadcast::decode_broadcast_outcome(data) else {
            log::warn!(
                "Broadcast Session procedure {procedure_code:?} message from association \
                 {association_id} is not a decodable Setup Response/Failure or Release \
                 Response; ignored"
            );
            return Ok(());
        };
        let mcast = crate::context::amf_mcast();
        let notifies = match outcome {
            BroadcastOutcome::SetupResponse { tmgi, transfer } => {
                mcast.broadcast_setup_outcome(&tmgi, association_id, true, transfer)
            }
            BroadcastOutcome::SetupFailure { tmgi, transfer } => {
                mcast.broadcast_setup_outcome(&tmgi, association_id, false, transfer)
            }
            BroadcastOutcome::ReleaseResponse { tmgi, transfer } => {
                mcast.broadcast_release_outcome(&tmgi, association_id, transfer)
            }
        };
        crate::mbs_broadcast::dispatch_notifies(notifies);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! #1796, both peers: what the MB-SMF sends and is told over Namf_MBSBroadcast,
    //! and the NGAP PDUs a stand-in gNB receives and answers.
    use super::super::tests::{capturing_ngap_server, insert_pws_test_gnb, take_sent_ngap};
    use super::*;
    use crate::context::RatType;
    use crate::mbs_broadcast::{BroadcastGnbState, CreateStart};
    use crate::ngap_mcast::Tmgi;
    use nextgcore_ngap_gen::generated as g;
    use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex as StdMutex};

    type Seen = Arc<StdMutex<Vec<(Value, Vec<(String, Vec<u8>)>)>>>;

    /// A stand-in MB-SMF `notifyUri` that records every ContextStatusNotify.
    async fn notify_sink() -> (nextgcore_sbi::server::SbiServer, String, Seen) {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen = Arc::default();
        let sink = Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    let body = serde_json::from_str(req.http.content.as_deref().unwrap_or("{}"))
                        .unwrap_or(Value::Null);
                    let parts = req
                        .http
                        .parts
                        .iter()
                        .map(|p| (p.content_id.clone().unwrap_or_default(), p.data.to_vec()))
                        .collect();
                    sink.lock().unwrap().push((body, parts));
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("notify sink starts");
        let uri = format!("http://127.0.0.1:{}/mbsmf/notify/tok-1796", addr.port());
        (server, uri, seen)
    }

    /// An MBS Session Setup or Modification Request Transfer (TS 38.413 §9.3.5.x)
    /// with one QoS flow, as the MB-SMF builds it.
    fn setup_transfer() -> Vec<u8> {
        nextgcore_ngap_gen::encode_contained(&g::MBSSessionSetupOrModRequestTransfer {
            protocol_i_es: g::MBSSessionSetupOrModRequestTransferProtocolIEs(vec![
                g::MBSSessionSetupOrModRequestTransferProtocolIEs_Entry {
                    id: g::ProtocolIE_ID(297),
                    criticality: g::Criticality(g::Criticality::REJECT),
                    value: g::MBSSessionSetupOrModRequestTransferProtocolIEs_EntryValue::Id_MBS_QoSFlowsToBeSetupModList(
                        g::MBS_QoSFlowsToBeSetupList(vec![g::MBS_QoSFlowsToBeSetupItem {
                            mb_sqos_flow_identifier: g::QosFlowIdentifier(1),
                            mb_sqos_flow_level_qos_parameters: g::QosFlowLevelQosParameters {
                                qos_characteristics: g::QosCharacteristics::NonDynamic5QI(
                                    g::NonDynamic5QIDescriptor {
                                        five_qi: g::FiveQI(9),
                                        priority_level_qos: None,
                                        averaging_window: None,
                                        maximum_data_burst_volume: None,
                                        ie_extensions: None,
                                    },
                                ),
                                allocation_and_retention_priority: g::AllocationAndRetentionPriority {
                                    priority_level_arp: g::PriorityLevelARP(8),
                                    pre_emption_capability: g::Pre_emptionCapability(0),
                                    pre_emption_vulnerability: g::Pre_emptionVulnerability(0),
                                    ie_extensions: None,
                                },
                                gbr_qos_information: None,
                                reflective_qos_attribute: None,
                                additional_qos_flow_information: None,
                                ie_extensions: None,
                            },
                            ie_extensions: None,
                        }]),
                    ),
                },
            ]),
        })
        .expect("transfer encodes")
    }

    /// A Setup Response Transfer the gNB returns (no NG-U info: N3mb multicast).
    fn response_transfer() -> Vec<u8> {
        nextgcore_ngap_gen::encode_contained(&g::MBSSessionSetupOrModResponseTransfer {
            mbs_session_tnl_info_ngran: None,
            ie_extensions: None,
        })
        .expect("encodes")
    }

    fn release_transfer() -> Vec<u8> {
        nextgcore_ngap_gen::encode_contained(&g::MBSSessionReleaseResponseTransfer {
            mbs_session_tnl_info_ngran: None,
            ie_extensions: None,
        })
        .expect("encodes")
    }

    const MCC: &str = "001";
    const MNC: &str = "01";
    const AREA_TAC: u32 = 0x00_1796;

    /// The ContextCreate the MB-SMF sends (`ContextCreateReqData`), with the
    /// Setup Request Transfer as a binary part.
    fn create_request(svc: &str, notify_uri: &str, extra: Value) -> SbiRequest {
        let mut body = json!({
            "mbsSessionId": { "tmgi": { "mbsServiceId": svc,
                                         "plmnId": { "mcc": MCC, "mnc": MNC } } },
            "mbsServiceArea": { "taiList": [ { "plmnId": { "mcc": MCC, "mnc": MNC },
                                               "tac": format!("{AREA_TAC:06x}") } ] },
            "n2MbsSmInfo": { "ngapIeType": "MBS_SES_REQ", "ngapData": { "contentId": "n2" } },
            "notifyUri": notify_uri,
            "snssai": { "sst": 1, "sd": "000001" },
        });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                if v.is_null() {
                    b.remove(k);
                } else {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
        SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "n2",
                nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
                bytes::Bytes::from(setup_transfer()),
            ))
    }

    fn tmgi(svc: u32) -> Tmgi {
        Tmgi::new(svc, [0x00, 0xF1, 0x10])
    }

    fn body_json(resp: &SbiResponse) -> Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).expect("json")
    }

    /// A server with gNBs 1 and 2 in the area and gNB 3 outside it.
    async fn server_with_area_gnbs() -> NgapServer {
        let server = capturing_ngap_server().await;
        insert_pws_test_gnb(&server, 1, 0x1, RatType::Nr, &[(MCC, MNC, AREA_TAC)]).await;
        insert_pws_test_gnb(&server, 2, 0x2, RatType::Nr, &[(MCC, MNC, AREA_TAC)]).await;
        insert_pws_test_gnb(&server, 3, 0x3, RatType::Nr, &[(MCC, MNC, 0x99)]).await;
        server
    }

    /// Run the ContextCreate on its own task, and wait until its context exists.
    async fn start_create(req: SbiRequest) -> tokio::task::JoinHandle<SbiResponse> {
        let before = crate::context::amf_mcast().broadcast_count();
        let task = tokio::spawn(crate::namf_request_handler(req));
        for _ in 0..200 {
            if crate::context::amf_mcast().broadcast_count() > before {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        task
    }

    /// The decoded BROADCAST SESSION SETUP REQUEST: (TMGI, S-NSSAI, TAIs, transfer).
    fn decoded_setup(pdu: &[u8]) -> Option<(Tmgi, g::S_NSSAI, Vec<g::TAI>, Vec<u8>)> {
        use g::BroadcastSessionSetupRequestProtocolIEs_EntryValue as Ie;
        let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
            return None;
        };
        assert_eq!(m.procedure_code.0, g::ID_BROADCAST_SESSION_SETUP);
        let g::InitiatingMessageValue::Id_BroadcastSessionSetup(r) = m.value else {
            return None;
        };
        let (mut id, mut nssai, mut tais, mut transfer) = (None, None, None, None);
        for e in r.protocol_i_es.0 {
            assert_eq!(
                e.criticality.0,
                g::Criticality::REJECT,
                "every IE is reject"
            );
            match e.value {
                Ie::Id_MBS_SessionID(v) => id = crate::ngap_mcast::tmgi_from_generated(&v),
                Ie::Id_S_NSSAI(v) => nssai = Some(v),
                Ie::Id_MBS_ServiceArea(g::MBS_ServiceArea::Locationindependent(a)) => {
                    tais = a.mbs_service_area_tai_list.map(|l| l.0)
                }
                Ie::Id_MBSSessionSetupRequestTransfer(t) => transfer = Some(t.0),
                _ => {}
            }
        }
        Some((id?, nssai?, tais?, transfer?))
    }

    /// The decoded BROADCAST SESSION RELEASE REQUEST's TMGI and cause.
    fn decoded_release(pdu: &[u8]) -> Option<(Tmgi, g::Cause)> {
        use g::BroadcastSessionReleaseRequestProtocolIEs_EntryValue as Ie;
        let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
            return None;
        };
        let g::InitiatingMessageValue::Id_BroadcastSessionRelease(r) = m.value else {
            return None;
        };
        let (mut id, mut cause) = (None, None);
        for e in r.protocol_i_es.0 {
            match e.value {
                Ie::Id_MBS_SessionID(v) => id = crate::ngap_mcast::tmgi_from_generated(&v),
                Ie::Id_Cause(c) => cause = Some(c),
            }
        }
        Some((id?, cause?))
    }

    /// The gNB's BROADCAST SESSION SETUP RESPONSE.
    fn setup_response(t: &Tmgi, transfer: Option<Vec<u8>>) -> Vec<u8> {
        use g::BroadcastSessionSetupResponseProtocolIEs_EntryValue as Ie;
        let mut ies = vec![g::BroadcastSessionSetupResponseProtocolIEs_Entry {
            id: g::ProtocolIE_ID(g::ID_MBS_SESSION_ID),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: Ie::Id_MBS_SessionID(crate::ngap_mcast::generated_mbs_session_id(t)),
        }];
        if let Some(t) = transfer {
            ies.push(g::BroadcastSessionSetupResponseProtocolIEs_Entry {
                id: g::ProtocolIE_ID(g::ID_MBS_SESSION_SETUP_RESPONSE_TRANSFER),
                criticality: g::Criticality(g::Criticality::REJECT),
                value: Ie::Id_MBSSessionSetupResponseTransfer(
                    g::Id_MBSSessionSetupResponseTransfer(t),
                ),
            });
        }
        nextgcore_ngap_gen::encode(&g::NGAP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
            procedure_code: g::ProcedureCode(g::ID_BROADCAST_SESSION_SETUP),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: g::SuccessfulOutcomeValue::Id_BroadcastSessionSetup(
                g::BroadcastSessionSetupResponse {
                    protocol_i_es: g::BroadcastSessionSetupResponseProtocolIEs(ies),
                },
            ),
        }))
        .expect("encodes")
    }

    /// The gNB's BROADCAST SESSION SETUP FAILURE (radio resources not available).
    fn setup_failure(t: &Tmgi) -> Vec<u8> {
        use g::BroadcastSessionSetupFailureProtocolIEs_EntryValue as Ie;
        nextgcore_ngap_gen::encode(&g::NGAP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
            procedure_code: g::ProcedureCode(g::ID_BROADCAST_SESSION_SETUP),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: g::UnsuccessfulOutcomeValue::Id_BroadcastSessionSetup(
                g::BroadcastSessionSetupFailure {
                    protocol_i_es: g::BroadcastSessionSetupFailureProtocolIEs(vec![
                        g::BroadcastSessionSetupFailureProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(g::ID_MBS_SESSION_ID),
                            criticality: g::Criticality(g::Criticality::REJECT),
                            value: Ie::Id_MBS_SessionID(
                                crate::ngap_mcast::generated_mbs_session_id(t),
                            ),
                        },
                        g::BroadcastSessionSetupFailureProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(g::ID_CAUSE),
                            criticality: g::Criticality(g::Criticality::IGNORE),
                            value: Ie::Id_Cause(g::Cause::RadioNetwork(g::CauseRadioNetwork(
                                g::CauseRadioNetwork::RADIO_RESOURCES_NOT_AVAILABLE,
                            ))),
                        },
                    ]),
                },
            ),
        }))
        .expect("encodes")
    }

    /// The gNB's BROADCAST SESSION RELEASE RESPONSE.
    fn release_response(t: &Tmgi, transfer: Option<Vec<u8>>) -> Vec<u8> {
        use g::BroadcastSessionReleaseResponseProtocolIEs_EntryValue as Ie;
        let mut ies = vec![g::BroadcastSessionReleaseResponseProtocolIEs_Entry {
            id: g::ProtocolIE_ID(g::ID_MBS_SESSION_ID),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: Ie::Id_MBS_SessionID(crate::ngap_mcast::generated_mbs_session_id(t)),
        }];
        if let Some(t) = transfer {
            ies.push(g::BroadcastSessionReleaseResponseProtocolIEs_Entry {
                id: g::ProtocolIE_ID(g::ID_MBS_SESSION_RELEASE_RESPONSE_TRANSFER),
                criticality: g::Criticality(g::Criticality::IGNORE),
                value: Ie::Id_MBSSessionReleaseResponseTransfer(
                    g::Id_MBSSessionReleaseResponseTransfer(t),
                ),
            });
        }
        nextgcore_ngap_gen::encode(&g::NGAP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
            procedure_code: g::ProcedureCode(g::ID_BROADCAST_SESSION_RELEASE),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: g::SuccessfulOutcomeValue::Id_BroadcastSessionRelease(
                g::BroadcastSessionReleaseResponse {
                    protocol_i_es: g::BroadcastSessionReleaseResponseProtocolIEs(ies),
                },
            ),
        }))
        .expect("encodes")
    }

    /// Run the pump until `n` notifications have arrived (or 2 s pass).
    async fn wait_notifies(seen: &Seen, n: usize) -> Vec<(Value, Vec<(String, Vec<u8>)>)> {
        for _ in 0..400 {
            if seen.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        seen.lock().unwrap().clone()
    }

    fn assocs(sent: &[(u64, Vec<u8>)]) -> Vec<u64> {
        let mut a: Vec<u64> = sent.iter().map(|(a, _)| *a).collect();
        a.sort_unstable();
        a
    }

    /// Run the ContextDelete on its own task, and wait until it removed the context.
    async fn delete(context_ref: &str) -> tokio::task::JoinHandle<SbiResponse> {
        let task = tokio::spawn(crate::namf_request_handler(SbiRequest::delete(format!(
            "/namf-mbs-bc/v1/mbs-contexts/{context_ref}"
        ))));
        if let Ok(id) = context_ref.parse::<u64>() {
            for _ in 0..200 {
                if crate::context::amf_mcast()
                    .broadcast_context_find(id)
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }
        task
    }

    /// ContextCreate sends one BROADCAST SESSION SETUP REQUEST to each gNB of the
    /// MBS service area and none outside it, carrying the TMGI (MBS Service ID
    /// first, TS 23.003 §30.2), the S-NSSAI, the area's TAI and the MB-SMF's
    /// transfer byte for byte. It answers 201 on the first Setup Response, with
    /// that gNB's Response Transfer and no completion; the second gNB's answer
    /// reaches the MB-SMF as a ContextStatusNotify carrying its container and
    /// MBS_SESSION_START_COMPLETE.
    ///
    /// REVERT-VERIFIED: with the pump not sending (process_mbs_broadcast
    /// returning at once) no gNB receives a Setup; with `served_by` true for every
    /// gNB, gNB 3 receives one; with the first-success answer removed from
    /// `settle`, the 201 only comes after CREATE_ANSWER_WAIT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_create_sets_up_broadcast_at_the_area_gnbs_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let (_sink, uri, seen) = notify_sink().await;
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7960);

        let create = start_create(create_request("017960", &uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1, 2], "the area's gNBs, once each");
        for (_, pdu) in &sent {
            let (id, nssai, tais, transfer) = decoded_setup(pdu).expect("a Setup Request");
            assert_eq!(id, t);
            assert_eq!(nssai.sst.0, vec![1]);
            assert_eq!(nssai.sd.map(|s| s.0), Some(vec![0, 0, 1]));
            assert_eq!(tais.len(), 1);
            assert_eq!(tais[0].plmn_identity.0, vec![0x00, 0xF1, 0x10]);
            assert_eq!(tais[0].tac.0, vec![0x00, 0x17, 0x96]);
            assert_eq!(
                transfer,
                setup_transfer(),
                "the MB-SMF's container, untouched"
            );
        }

        server
            .process_ngap_message(1, &setup_response(&t, Some(response_transfer())))
            .await
            .expect("an outcome is never answered");
        // Well inside CREATE_ANSWER_WAIT: the answer is the first success, not the wait.
        let created = tokio::time::timeout(std::time::Duration::from_millis(150), create)
            .await
            .expect("answered on the first Setup Response, not after the wait")
            .expect("create task");
        assert_eq!(created.status, 201);
        let body = body_json(&created);
        let context_ref = body["mbsContextRef"].as_str().expect("ref").to_string();
        assert!(created
            .http
            .get_header("Location")
            .is_some_and(|l| l.ends_with(&format!("/mbs-contexts/{context_ref}"))));
        assert_eq!(body["mbsSessionId"]["tmgi"]["mbsServiceId"], "017960");
        let list = body["n2MbsSmInfoList"]
            .as_array()
            .expect("the first response");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["ngapIeType"], "MBS_SES_RSP");
        assert_eq!(list[0]["ranId"]["gNbId"]["gNBValue"], "00000001");
        let cid = list[0]["ngapData"]["contentId"].as_str().unwrap();
        let part = created
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(cid))
            .expect("the container part");
        assert_eq!(part.data.to_vec(), response_transfer());
        assert!(
            body.get("operationStatus").is_none(),
            "gNB 2 has not answered"
        );

        server
            .process_ngap_message(2, &setup_response(&t, Some(response_transfer())))
            .await
            .expect("outcome");
        let notes = wait_notifies(&seen, 1).await;
        assert_eq!(notes.len(), 1);
        let (note, parts) = &notes[0];
        assert_eq!(note["operationStatus"], "MBS_SESSION_START_COMPLETE");
        assert_eq!(
            note["n2MbsSmInfoList"][0]["ranId"]["gNbId"]["gNBValue"],
            "00000002"
        );
        assert_eq!(parts[0].1, response_transfer());

        let deleted = delete(&context_ref).await;
        server.process_mbs_broadcast().await;
        for (a, _) in take_sent_ngap(&mut server) {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .expect("outcome");
        }
        assert_eq!(deleted.await.unwrap().status, 204);
    }

    /// Failure-path (1): a rejected ContextCreate stores nothing and sends
    /// nothing. Each body lacks or breaks one mandatory member.
    ///
    /// REVERT-VERIFIED: with the transfer decode check removed, the malformed
    /// transfer is accepted (201 after the wait) and a Setup goes out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejected_context_create_applies_and_sends_nothing_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let uri = "http://127.0.0.1:9/notify";
        let bad_transfer = SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
            .with_json_body(&json!({
                "mbsSessionId": { "tmgi": { "mbsServiceId": "017961",
                                             "plmnId": { "mcc": MCC, "mnc": MNC } } },
                "mbsServiceArea": { "taiList": [ { "plmnId": { "mcc": MCC, "mnc": MNC },
                                                   "tac": "001796" } ] },
                "n2MbsSmInfo": { "ngapIeType": "MBS_SES_REQ", "ngapData": { "contentId": "n2" } },
                "notifyUri": uri, "snssai": { "sst": 1 },
            }))
            .unwrap()
            .with_part(SbiPart::with_content(
                "n2",
                nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
                bytes::Bytes::from_static(&[0xFF, 0xFF, 0xFF]),
            ));
        let cases = vec![
            ("malformed transfer", bad_transfer, 400),
            (
                "no n2MbsSmInfo",
                create_request("017961", uri, json!({ "n2MbsSmInfo": null })),
                400,
            ),
            (
                "wrong ngapIeType",
                create_request(
                    "017961",
                    uri,
                    json!({ "n2MbsSmInfo": { "ngapIeType": "MBS_SES_RSP",
                                             "ngapData": { "contentId": "n2" } } }),
                ),
                400,
            ),
            (
                "no notifyUri",
                create_request("017961", uri, json!({ "notifyUri": null })),
                400,
            ),
            (
                "bad notifyUri",
                create_request("017961", "ftp://x", json!({})),
                400,
            ),
            (
                "no snssai",
                create_request("017961", uri, json!({ "snssai": null })),
                400,
            ),
            (
                "no area",
                create_request("017961", uri, json!({ "mbsServiceArea": null })),
                400,
            ),
            (
                "empty area",
                create_request("017961", uri, json!({ "mbsServiceArea": {} })),
                400,
            ),
            (
                "location dependent",
                create_request(
                    "017961",
                    uri,
                    json!({ "mbsServiceArea": null, "mbsServiceAreaInfoList": [ {} ] }),
                ),
                501,
            ),
        ];
        let mcast = crate::context::amf_mcast();
        let before = mcast.broadcast_count();
        for (what, req, status) in cases {
            let resp = crate::namf_request_handler(req).await;
            assert_eq!(resp.status, status, "{what}");
            assert_eq!(mcast.broadcast_count(), before, "{what}: nothing stored");
            server.process_mbs_broadcast().await;
            assert!(
                take_sent_ngap(&mut server).is_empty(),
                "{what}: nothing sent"
            );
        }
        assert!(mcast.session_find_by_tmgi(&tmgi(0x01_7961)).is_none());
    }

    /// Failure-path (2): a ContextCreate repeated while the first waits, and again
    /// after it was answered, is one context with one Setup per gNB, and every
    /// answer names the same context.
    ///
    /// REVERT-VERIFIED: with the TMGI lookup in `broadcast_create` removed, the
    /// repeat stores a second context and each gNB receives a second Setup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repeated_context_create_is_one_context_and_one_setup_per_gnb_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7962);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();
        let before = mcast.broadcast_count();

        let first = start_create(create_request("017962", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        let retry = tokio::spawn(crate::namf_request_handler(create_request(
            "017962",
            uri,
            json!({}),
        )));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1, 2], "one Setup per gNB");
        for a in [1, 2] {
            server
                .process_ngap_message(a, &setup_response(&t, None))
                .await
                .unwrap();
        }
        let (first, retry) = (first.await.unwrap(), retry.await.unwrap());
        let late = crate::namf_request_handler(create_request("017962", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        assert!(take_sent_ngap(&mut server).is_empty(), "no second Setup");
        assert_eq!(mcast.broadcast_count(), before + 1, "one context");
        let r = body_json(&first)["mbsContextRef"].clone();
        for resp in [&first, &retry, &late] {
            assert_eq!(resp.status, 201);
            assert_eq!(body_json(resp)["mbsContextRef"], r);
        }
        assert_eq!(
            body_json(&late)["operationStatus"],
            "MBS_SESSION_START_COMPLETE"
        );

        let deleted = delete(r.as_str().unwrap()).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1, 2]);
        for (a, pdu) in &sent {
            assert_eq!(decoded_release(pdu).expect("a Release Request").0, t);
            server
                .process_ngap_message(*a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(deleted.await.unwrap().status, 204);
        // Failure-path (2) for the delete: a repeat is 404 and sends nothing.
        let again = delete(r.as_str().unwrap()).await.await.unwrap();
        assert_eq!(again.status, 404);
        assert_eq!(body_json(&again)["cause"], "CONTEXT_NOT_FOUND");
        server.process_mbs_broadcast().await;
        assert!(take_sent_ngap(&mut server).is_empty());
    }

    /// TS 23.247 §7.3.1 step 7: when every gNB fails the setup, ContextCreate
    /// fails and the AMF keeps nothing; and when no gNB serves the area, it fails
    /// without sending anything.
    ///
    /// REVERT-VERIFIED: with the all-failed branch of `settle` keeping the context,
    /// the create answers 201 after the wait and the context stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_gnb_failing_the_setup_fails_the_create_and_keeps_nothing_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7963);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();
        let before = mcast.broadcast_count();

        let create = start_create(create_request("017963", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        assert_eq!(assocs(&take_sent_ngap(&mut server)), vec![1, 2]);
        for a in [1, 2] {
            server
                .process_ngap_message(a, &setup_failure(&t))
                .await
                .unwrap();
        }
        let resp = create.await.unwrap();
        assert_eq!(resp.status, 500);
        assert_eq!(body_json(&resp)["cause"], "UNSPECIFIED_NF_FAILURE");
        assert_eq!(mcast.broadcast_count(), before, "nothing kept");
        assert!(mcast.session_find_by_tmgi(&t).is_none());

        let outside = start_create(create_request(
            "017963",
            uri,
            json!({ "mbsServiceArea": { "taiList": [ { "plmnId": { "mcc": MCC, "mnc": MNC },
                                                       "tac": "00abcd" } ] } }),
        ))
        .await;
        server.process_mbs_broadcast().await;
        assert!(
            take_sent_ngap(&mut server).is_empty(),
            "no gNB serves 00abcd"
        );
        assert_eq!(outside.await.unwrap().status, 500);
        assert_eq!(mcast.broadcast_count(), before);
    }

    /// ContextDelete sends the BROADCAST SESSION RELEASE REQUEST (NAS
    /// normal-release) to the gNBs that set the session up and not to one that
    /// failed it; their Release Response Transfer reaches the MB-SMF before the 204.
    ///
    /// REVERT-VERIFIED: with Failed nodes counted as release targets, gNB 2 also
    /// receives a Release; with the delete answering at once, the 204 precedes
    /// the notification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_delete_releases_the_gnbs_that_were_set_up_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let (_sink, uri, seen) = notify_sink().await;
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7964);

        let create = start_create(create_request("017964", &uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        server
            .process_ngap_message(1, &setup_response(&t, None))
            .await
            .unwrap();
        server
            .process_ngap_message(2, &setup_failure(&t))
            .await
            .unwrap();
        let created = create.await.unwrap();
        assert_eq!(created.status, 201);
        let r = body_json(&created)["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        let id: u64 = r.parse().unwrap();
        let mut states = crate::context::amf_mcast()
            .broadcast_gnb_states(id)
            .expect("held");
        states.sort_unstable_by_key(|(a, _)| *a);
        assert_eq!(
            states,
            vec![
                (1, BroadcastGnbState::Established),
                (2, BroadcastGnbState::Failed)
            ]
        );

        // gNB 2's failure, after the 201, completed the setup.
        let notes = wait_notifies(&seen, 1).await;
        assert_eq!(notes[0].0["operationStatus"], "MBS_SESSION_START_COMPLETE");

        let deleted = delete(&r).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1], "only the gNB that set it up");
        let (id_t, cause) = decoded_release(&sent[0].1).expect("a Release Request");
        assert_eq!(id_t, t);
        assert_eq!(
            cause,
            g::Cause::Nas(g::CauseNas(g::CauseNas::NORMAL_RELEASE))
        );
        assert!(!deleted.is_finished(), "the 204 follows the gNB's response");
        server
            .process_ngap_message(1, &release_response(&t, Some(release_transfer())))
            .await
            .unwrap();
        let resp = deleted.await.unwrap();
        assert_eq!(resp.status, 204);
        let notes = seen.lock().unwrap().clone();
        assert_eq!(notes.len(), 2, "delivered before the 204");
        assert_eq!(
            notes[1].0["n2MbsSmInfoList"][0]["ngapIeType"],
            "MBS_SES_REL_RSP"
        );
        assert_eq!(
            notes[1].0["n2MbsSmInfoList"][0]["ranId"]["gNbId"]["gNBValue"],
            "00000001"
        );
        assert_eq!(notes[1].1[0].1, release_transfer());
        assert!(!crate::context::amf_mcast().broadcast_releasing(id));
    }

    /// Failure-path (3): a ContextDelete while the setup is in flight answers the
    /// waiting ContextCreate, releases the gNBs it was sent to, and a Setup
    /// Response arriving afterwards revives nothing.
    ///
    /// REVERT-VERIFIED: with SetupSent nodes left out of the release targets,
    /// no Release goes out and the gNBs keep the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_during_setup_leaves_nothing_stuck_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7965);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();
        let before = mcast.broadcast_count();

        let create = start_create(create_request("017965", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        assert_eq!(assocs(&take_sent_ngap(&mut server)), vec![1, 2]);
        let id = mcast.broadcast_refs_of(&t)[0];

        let deleted = delete(&id.to_string()).await;
        let created = create.await.unwrap();
        assert_eq!(created.status, 500, "the waiting create is answered");
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1, 2], "both were sent the Setup");
        server
            .process_ngap_message(1, &setup_response(&t, None))
            .await
            .unwrap();
        assert_eq!(
            mcast.broadcast_count(),
            before,
            "a late response revives nothing"
        );
        for a in [1, 2] {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(deleted.await.unwrap().status, 204);
        assert!(!mcast.broadcast_releasing(id));
        assert!(mcast.session_find_by_tmgi(&t).is_none());
    }

    /// Failure-path (3), gNB side: a gNB lost before answering counts as answered
    /// (the MB-SMF is told it is unreachable and the setup complete), and when the
    /// last gNB holding the session is lost the context is released and the
    /// MB-SMF told so (releasedInd).
    ///
    /// REVERT-VERIFIED: with the loss check in `broadcast_plan` removed, no
    /// completion is ever notified and the context stays after both gNBs are gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gnb_lost_during_setup_leaves_nothing_stuck_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let (_sink, uri, seen) = notify_sink().await;
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7966);
        let mcast = crate::context::amf_mcast();
        let before = mcast.broadcast_count();

        let create = start_create(create_request("017966", &uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        server
            .process_ngap_message(1, &setup_response(&t, None))
            .await
            .unwrap();
        assert_eq!(create.await.unwrap().status, 201);

        server.sessions.write().await.remove(&2);
        mcast.broadcast_rescan();
        server.process_mbs_broadcast().await;
        let notes = wait_notifies(&seen, 1).await;
        assert!(!notes.is_empty(), "the lost gNB completes the setup");
        assert_eq!(notes[0].0["operationStatus"], "MBS_SESSION_START_COMPLETE");
        let ev = &notes[0].0["operationEvents"][0];
        assert_eq!(ev["opEventType"], "NG_RAN_EVENT");
        assert_eq!(
            ev["ngranFailureEventList"][0]["ngranFailureIndication"],
            "NG_RAN_NOT_REACHABLE"
        );
        assert_eq!(
            ev["ngranFailureEventList"][0]["ngranId"]["gNbId"]["gNBValue"],
            "00000002"
        );
        assert!(
            notes[0].0.get("releasedInd").is_none(),
            "gNB 1 still holds it"
        );

        server.sessions.write().await.remove(&1);
        mcast.broadcast_rescan();
        server.process_mbs_broadcast().await;
        let notes = wait_notifies(&seen, 2).await;
        assert_eq!(notes.len(), 2, "the last gNB's loss releases the context");
        assert_eq!(notes[1].0["releasedInd"], true);
        assert_eq!(mcast.broadcast_count(), before, "released, not stuck");
        assert!(take_sent_ngap(&mut server).is_empty());
    }

    /// TS 29.518 §5.6.2.2: with `maxResponseTime` elapsed and a gNB still silent,
    /// one MBS_SESSION_START_INCOMPLETE notification -- and only one.
    ///
    /// REVERT-VERIFIED: with the `incomplete_reported` latch removed, every scan
    /// notifies again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_response_time_elapsing_is_notified_once_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let (_sink, uri, seen) = notify_sink().await;
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7967);

        let create = start_create(create_request(
            "017967",
            &uri,
            json!({ "maxResponseTime": 0 }),
        ))
        .await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        server
            .process_ngap_message(1, &setup_response(&t, None))
            .await
            .unwrap();
        let r = body_json(&create.await.unwrap())["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..3 {
            crate::context::amf_mcast().broadcast_rescan();
            server.process_mbs_broadcast().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let notes = seen.lock().unwrap().clone();
        assert_eq!(notes.len(), 1, "one incompletion notification");
        assert_eq!(
            notes[0].0["operationStatus"],
            "MBS_SESSION_START_INCOMPLETE"
        );

        let deleted = delete(&r).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.process_mbs_broadcast().await;
        for (a, _) in take_sent_ngap(&mut server) {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(deleted.await.unwrap().status, 204);
    }

    /// The (procedure, TMGI) of every Broadcast Session PDU sent on `assoc`, in order.
    fn sent_on(sent: &[(u64, Vec<u8>)], assoc: u64) -> Vec<(&'static str, Tmgi)> {
        sent.iter()
            .filter(|(a, _)| *a == assoc)
            .map(|(_, pdu)| {
                if let Some(r) = decoded_release(pdu) {
                    ("release", r.0)
                } else {
                    ("setup", decoded_setup(pdu).expect("a Setup or a Release").0)
                }
            })
            .collect()
    }

    /// R29: a ContextDelete and a ContextCreate re-creating the same TMGI that both
    /// land before one pump pass: each gNB receives the Release of the old session
    /// BEFORE the Setup of the new one, so the Release cannot tear the new one down.
    ///
    /// REVERT-VERIFIED: with the Setup loop of `broadcast_plan` run before the
    /// Release loop, gNB 1 receives [setup, release].
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_precedes_the_setup_of_a_recreated_tmgi_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7968);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();

        let create = start_create(create_request("017968", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        for a in [1, 2] {
            server
                .process_ngap_message(a, &setup_response(&t, None))
                .await
                .unwrap();
        }
        let old = body_json(&create.await.unwrap())["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();

        // Both before the next pass.
        let deleted = delete(&old).await;
        let recreated = start_create(create_request("017968", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        for a in [1, 2] {
            assert_eq!(
                sent_on(&sent, a),
                vec![("release", t.clone()), ("setup", t.clone())],
                "gNB {a}: the old session's Release goes before the new one's Setup"
            );
        }
        for a in [1, 2] {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
            server
                .process_ngap_message(a, &setup_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(deleted.await.unwrap().status, 204);
        let new = recreated.await.unwrap();
        assert_eq!(new.status, 201);
        let new_ref = body_json(&new)["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(new_ref, old);
        let mut states = mcast
            .broadcast_gnb_states(new_ref.parse().unwrap())
            .unwrap();
        states.sort_unstable_by_key(|(a, _)| *a);
        assert_eq!(
            states,
            vec![
                (1, BroadcastGnbState::Established),
                (2, BroadcastGnbState::Established)
            ],
            "the new session is up at both gNBs"
        );
        let last = delete(&new_ref).await;
        server.process_mbs_broadcast().await;
        for (a, _) in take_sent_ngap(&mut server) {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(last.await.unwrap().status, 204);
    }

    /// R29: with two releases of one TMGI outstanding at a gNB, its Release
    /// Response settles the OLDEST (the gNB answers in the order the association
    /// carried the Requests), every time.
    ///
    /// REVERT-VERIFIED: with the release map searched newest first, the first
    /// response settles the second release and "the older release is settled first"
    /// fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_release_response_settles_the_oldest_release_of_its_tmgi_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7969);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();

        let mut refs = Vec::new();
        let mut deletes = Vec::new();
        for _ in 0..2 {
            let create = start_create(create_request("017969", uri, json!({}))).await;
            server.process_mbs_broadcast().await;
            take_sent_ngap(&mut server);
            for a in [1, 2] {
                server
                    .process_ngap_message(a, &setup_response(&t, None))
                    .await
                    .unwrap();
            }
            let r: u64 = body_json(&create.await.unwrap())["mbsContextRef"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            deletes.push(delete(&r.to_string()).await);
            server.process_mbs_broadcast().await;
            take_sent_ngap(&mut server);
            refs.push(r);
        }
        assert!(mcast.broadcast_releasing(refs[0]) && mcast.broadcast_releasing(refs[1]));
        for a in [1, 2] {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert!(
            !mcast.broadcast_releasing(refs[0]) && mcast.broadcast_releasing(refs[1]),
            "the older release is settled first"
        );
        for a in [1, 2] {
            server
                .process_ngap_message(a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert!(!mcast.broadcast_releasing(refs[1]));
        for d in deletes {
            assert_eq!(d.await.unwrap().status, 204);
        }
    }

    /// R29: a release whose gNB stays connected and never answers ends after
    /// RELEASE_RESPONSE_TIMEOUT, and the MB-SMF is told which NG-RAN it could not
    /// reach (TS 29.518 §5.6.2.4) -- the entry is not left for the cap to evict.
    ///
    /// REVERT-VERIFIED: with the timeout check removed, the release is still
    /// tracked and no report is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_release_ends_and_is_reported_1796() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let (_sink, uri, seen) = notify_sink().await;
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x01_7970);
        let mcast = crate::context::amf_mcast();

        let create = start_create(create_request("017970", &uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        server
            .process_ngap_message(1, &setup_response(&t, None))
            .await
            .unwrap();
        server
            .process_ngap_message(2, &setup_failure(&t))
            .await
            .unwrap();
        let r = body_json(&create.await.unwrap())["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        let before = wait_notifies(&seen, 1).await.len();

        let deleted = delete(&r).await;
        server.process_mbs_broadcast().await;
        assert_eq!(assocs(&take_sent_ngap(&mut server)), vec![1]);
        assert_eq!(
            deleted.await.unwrap().status,
            204,
            "answered after its wait"
        );
        tokio::time::sleep(crate::mbs_broadcast::RELEASE_RESPONSE_TIMEOUT).await;
        mcast.broadcast_rescan();
        server.process_mbs_broadcast().await;
        assert!(
            !mcast.broadcast_releasing(r.parse().unwrap()),
            "the unanswered release is over"
        );
        let notes = wait_notifies(&seen, before + 1).await;
        assert_eq!(notes.len(), before + 1, "the MB-SMF is told");
        let ev = &notes[before].0["operationEvents"][0];
        assert_eq!(
            ev["ngranFailureEventList"][0]["ngranFailureIndication"],
            "NG_RAN_NOT_REACHABLE"
        );
        assert_eq!(
            ev["ngranFailureEventList"][0]["ngranId"]["gNbId"]["gNBValue"],
            "00000001"
        );
    }

    /// #1818 (ported, now with a gNB): a ContextDelete keeps an MBS session the
    /// multicast path holds under the same TMGI. The broadcast context joins it;
    /// its delete releases the broadcast session at the gNB and leaves the
    /// multicast session, with its gNB state, in place.
    ///
    /// REVERT-VERIFIED: with `drop_broadcast_session` removing a session the
    /// context did not create, "the multicast session survives" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_delete_keeps_a_multicast_session_sharing_the_tmgi_1818() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x18_1800);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();
        let multicast = mcast
            .session_create(t.clone(), 1, None, vec![1])
            .expect("multicast session");
        mcast.session_activate(
            multicast.mbs_session_id,
            crate::ngap_mcast::McastTransportInfo {
                dl_teid: 0x1818,
                transport_addr: std::net::Ipv4Addr::new(239, 0, 18, 18),
            },
            &[1818],
        );

        let create = start_create(create_request("181800", uri, json!({}))).await;
        server.process_mbs_broadcast().await;
        take_sent_ngap(&mut server);
        for a in [1, 2] {
            server
                .process_ngap_message(a, &setup_response(&t, None))
                .await
                .unwrap();
        }
        let r = body_json(&create.await.unwrap())["mbsContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            mcast
                .broadcast_context_find(r.parse().unwrap())
                .unwrap()
                .session_id,
            multicast.mbs_session_id,
            "the broadcast context joins the multicast session sharing its TMGI"
        );
        let deleted = delete(&r).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(
            assocs(&sent),
            vec![1, 2],
            "the broadcast session is released"
        );
        for (a, _) in &sent {
            server
                .process_ngap_message(*a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(deleted.await.unwrap().status, 204);
        let kept = mcast
            .session_find(multicast.mbs_session_id)
            .expect("the multicast session survives the broadcast ContextDelete");
        assert_eq!(kept.gnb_sessions.len(), 1, "with its gNB state");
        assert_eq!(delete(&r).await.await.unwrap().status, 404);
        mcast.session_remove(multicast.mbs_session_id);
    }

    /// #1818 (ported, now with a gNB): two MB-SMFs' contexts on one TMGI share the
    /// broadcast session -- one Setup per gNB. The first delete releases its
    /// context only (no Release on N2, the session kept for the other); the last
    /// delete releases it at the gNBs and removes it. A repeat from the same
    /// MB-SMF is a retry and gets its own context back.
    ///
    /// REVERT-VERIFIED: with the "other context rides on it" check removed from
    /// `broadcast_delete`, the first delete sends a Release and "no Release while
    /// the other context rides on it" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_last_broadcast_context_on_a_tmgi_releases_its_session_1818() {
        let _g = crate::test_support::MBS_CONTEXT_LOCK.lock().await;
        crate::test_support::init_context();
        let mut server = server_with_area_gnbs().await;
        let t = tmgi(0x18_1801);
        let uri = "http://127.0.0.1:9/notify";
        let mcast = crate::context::amf_mcast();
        let from = |id: &str| json!({ "mbsmfId": id });

        let create = start_create(create_request("181801", uri, from("mbsmf-a"))).await;
        server.process_mbs_broadcast().await;
        assert_eq!(assocs(&take_sent_ngap(&mut server)), vec![1, 2]);
        for a in [1, 2] {
            server
                .process_ngap_message(a, &setup_response(&t, None))
                .await
                .unwrap();
        }
        let a = body_json(&create.await.unwrap())["mbsContextRef"].clone();
        let a_again =
            crate::namf_request_handler(create_request("181801", uri, from("mbsmf-a"))).await;
        assert_eq!(
            body_json(&a_again)["mbsContextRef"],
            a,
            "a retry is the same context"
        );
        let b = crate::namf_request_handler(create_request("181801", uri, from("mbsmf-b"))).await;
        assert_eq!(b.status, 201, "answered with the session's state");
        let b = body_json(&b)["mbsContextRef"].clone();
        assert_ne!(a, b, "another MB-SMF gets a context of its own");
        server.process_mbs_broadcast().await;
        assert!(take_sent_ngap(&mut server).is_empty(), "no second Setup");

        let first = delete(a.as_str().unwrap()).await.await.unwrap();
        assert_eq!(first.status, 204);
        server.process_mbs_broadcast().await;
        assert!(
            take_sent_ngap(&mut server).is_empty(),
            "no Release while the other context rides on it"
        );
        assert!(
            mcast.session_find_by_tmgi(&t).is_some(),
            "kept for the other context"
        );

        let last = delete(b.as_str().unwrap()).await;
        server.process_mbs_broadcast().await;
        let sent = take_sent_ngap(&mut server);
        assert_eq!(assocs(&sent), vec![1, 2], "the last context releases it");
        for (a, _) in &sent {
            server
                .process_ngap_message(*a, &release_response(&t, None))
                .await
                .unwrap();
        }
        assert_eq!(last.await.unwrap().status, 204);
        assert!(
            mcast.session_find_by_tmgi(&t).is_none(),
            "the last context removes the session it created"
        );
    }

    /// The context map is capped: past the cap a ContextCreate stores nothing.
    ///
    /// REVERT-VERIFIED: with the capacity check removed, the second context is stored.
    #[test]
    fn the_broadcast_context_map_is_capped_1796() {
        let mcast = crate::ngap_mcast::NgapMcastContext::with_broadcast_capacity(1);
        let req = |svc| crate::mbs_broadcast::BroadcastCreate {
            tmgi: tmgi(svc),
            mbs_session_id: json!({}),
            sst: 1,
            sd: None,
            area: Default::default(),
            setup_transfer: setup_transfer(),
            notify_uri: "http://127.0.0.1:9/n".into(),
            max_response_time: None,
            mbsmf_id: None,
        };
        let now = std::time::Instant::now();
        assert!(matches!(
            mcast.broadcast_create(req(1), now),
            CreateStart::Wait { .. }
        ));
        assert!(
            matches!(mcast.broadcast_create(req(2), now), CreateStart::Full),
            "past the cap nothing is stored"
        );
        assert_eq!(mcast.broadcast_count(), 1);
        assert_eq!(
            mcast.session_count(),
            1,
            "no session for the refused create"
        );
        // The same TMGI again is not a new context, so the cap does not refuse it.
        assert!(matches!(
            mcast.broadcast_create(req(1), now),
            CreateStart::Wait { .. }
        ));
    }
}
