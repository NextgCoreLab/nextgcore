//! #570 RACS tests. Expected octets are derived by hand from TS 24.501 §9.11.3.68,
//! TS 29.571 and X.691 APER, not captured from the encoder.

use super::*;

/// The RACS cache is process-global: tests that touch it hold its lock.
pub(crate) fn guard() -> std::sync::MutexGuard<'static, ()> {
    let g = RACS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_for_tests();
    g
}

/// PLMN-assigned, Version ID 05, RCI 1: digits `1 05 00000000001` (14), packed low
/// nibble first (§9.11.3.68): 01 05 00 00 00 00 10.
const ID: [u8; 7] = [0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10];

#[test]
fn nucmf_form_is_base64_of_the_whole_ie() {
    // 67 07 01 05 00 00 00 00 10, base64 (TS 29.571 `Bytes`).
    assert_eq!(to_nucmf(&ID).as_deref(), Some("ZwcBBQAAAAAQ"));
    assert_eq!(from_nucmf("ZwcBBQAAAAAQ").as_deref(), Some(&ID[..]));
    // A wrong IEI, or a length octet that disagrees with the value, is refused.
    let wrong_iei = base64::engine::general_purpose::STANDARD.encode([0x66, 1, 0x01]);
    assert_eq!(from_nucmf(&wrong_iei), None);
    let wrong_len = base64::engine::general_purpose::STANDARD.encode([0x67, 2, 0x01]);
    assert_eq!(from_nucmf(&wrong_len), None);
    assert_eq!(to_nucmf(&[]), None);
}

#[test]
fn id_type_and_version_come_from_the_digits() {
    assert!(is_plmn_assigned(&ID));
    assert_eq!(version_id(&ID), Some(0x05));
    // Manufacturer-assigned (Type Field 0): no Version ID.
    let man = [0x00, 0x00, 0x70, 0xDE, 0x09, 0x00, 0x00, 0x00, 0xA0, 0xCB];
    assert!(!is_plmn_assigned(&man));
    assert_eq!(version_id(&man), None);
}

#[test]
fn tac_is_the_first_eight_pei_digits() {
    assert_eq!(
        tac_from_pei("imeisv-3512345678901234").as_deref(),
        Some("35123456")
    );
    assert_eq!(
        tac_from_pei("imei-351234567890123").as_deref(),
        Some("35123456")
    );
    assert_eq!(tac_from_pei("mac-00-11"), None);
    assert_eq!(tac_from_pei("imei-1234"), None);
}

#[test]
fn the_racs_bit_is_octet_4_bit_8() {
    // nextgsim's 5GMM capability `10 02 00 80`: contents 00 80.
    assert!(gmm_capability_supports_racs(&[0x00, 0x80]));
    assert!(!gmm_capability_supports_racs(&[0x80, 0x00]));
    assert!(!gmm_capability_supports_racs(&[0x01]));
}

#[test]
fn mapping_response_octets() {
    // SuccessfulOutcome (CHOICE index 1 of 3, extensible): 0x20; procedureCode 60:
    // 0x3C; criticality reject: 0x00; open type length 22 (0x16).
    // Value: ext bit 0 + padding 00, IE count 00 02;
    //   IE 264: 01 08, reject 00, open length 08, OCTET STRING length 07 + ID;
    //   IE 117: 00 75, ignore 40, open length 03, OCTET STRING length 02 AA BB.
    let expected = [
        0x20, 0x3C, 0x00, 0x16, 0x00, 0x00, 0x02, 0x01, 0x08, 0x00, 0x08, 0x07, 0x01, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x75, 0x40, 0x03, 0x02, 0xAA, 0xBB,
    ];
    assert_eq!(
        build_mapping_response(&ID, &[0xAA, 0xBB]).as_deref(),
        Some(&expected[..])
    );
}

#[test]
fn mapping_request_octets_decode_to_the_id() {
    // InitiatingMessage index 0: 0x00; procedureCode 60; criticality reject; open
    // length 15; value: ext 0 + count 1; IE 264 reject, length 08, 07 + ID.
    let request = [
        0x00, 0x3C, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x08, 0x00, 0x08, 0x07, 0x01, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x10,
    ];
    assert_eq!(decode_mapping_request(&request).as_deref(), Some(&ID[..]));
    // A response is not a request.
    let response = build_mapping_response(&ID, &[0xAA]).unwrap();
    assert_eq!(decode_mapping_request(&response), None);
}

#[test]
fn info_indication_carries_ids_and_capability() {
    use ngap_gen::UERadioCapabilityInfoIndicationProtocolIEs_Entry as Entry;
    use ngap_gen::UERadioCapabilityInfoIndicationProtocolIEs_EntryValue as Ie;
    let reject = || ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let entry = |id: u16, value: Ie| Entry {
        id: ngap_gen::ProtocolIE_ID(id),
        criticality: reject(),
        value,
    };
    let ies = |with_cap: bool| {
        let mut v = vec![
            entry(10, Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7))),
            entry(85, Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(3))),
        ];
        if with_cap {
            v.push(entry(
                117,
                Ie::Id_UERadioCapability(ngap_gen::UERadioCapability(vec![0xCA, 0xFE])),
            ));
        }
        v
    };
    let pdu = |with_cap| {
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::InitiatingMessage(
            ngap_gen::InitiatingMessage {
                procedure_code: ngap_gen::ProcedureCode(
                    ngap_gen::ID_UE_RADIO_CAPABILITY_INFO_INDICATION,
                ),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                value: ngap_gen::InitiatingMessageValue::Id_UERadioCapabilityInfoIndication(
                    ngap_gen::UERadioCapabilityInfoIndication {
                        protocol_i_es: ngap_gen::UERadioCapabilityInfoIndicationProtocolIEs(ies(
                            with_cap,
                        )),
                    },
                ),
            },
        ))
        .unwrap()
    };
    assert_eq!(
        decode_info_indication(&pdu(true)),
        Some(InfoIndication {
            amf_ue_ngap_id: 7,
            ran_ue_ngap_id: 3,
            capability: vec![0xCA, 0xFE],
        })
    );
    // The capability is mandatory (§9.2.13.1).
    assert_eq!(decode_info_indication(&pdu(false)), None);
}

fn ics(nas: bool) -> Vec<u8> {
    let mut ctx = crate::context::AmfContext::new();
    ctx.served_guami.push(crate::context::Guami {
        plmn_id: crate::context::PlmnId::new("999", "70"),
        amf_id: crate::context::AmfId {
            region: 2,
            set: 1,
            pointer: 0,
        },
    });
    crate::ngap_asn1::build_initial_context_setup_request_asn1(
        &ctx,
        1,
        2,
        &[crate::context::SNssai { sst: 1, sd: None }],
        &crate::context::UeSecurityCapability::default(),
        &[0u8; 32],
        nas.then_some(&[0x7E, 0x00][..]),
        None,
    )
    .unwrap()
}

fn ics_ids(pdu: &[u8]) -> Vec<u16> {
    match nextgcore_ngap_gen::decode(pdu).unwrap() {
        ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
            value: ngap_gen::InitiatingMessageValue::Id_InitialContextSetup(r),
            ..
        }) => r.protocol_i_es.0.iter().map(|e| e.id.0).collect(),
        other => panic!("not an ICS: {other:?}"),
    }
}

#[test]
fn ics_gets_the_id_last_and_no_capability() {
    let _g = guard();
    let out = add_capability_ies(ics(true), Some(&ID), Some(&[0xAA]));
    let ids = ics_ids(&out);
    assert_eq!(ids.last(), Some(&ngap_gen::ID_UE_RADIO_CAPABILITY_ID));
    // With an ID the NG-RAN maps it; the capability is not sent too.
    assert!(!ids.contains(&ngap_gen::ID_UE_RADIO_CAPABILITY));
    // Criticality reject (ICS IE set, TS 38.413 §9.2.2.1).
    let ngap_gen::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(&out).unwrap() else {
        unreachable!()
    };
    let ngap_gen::InitiatingMessageValue::Id_InitialContextSetup(r) = m.value else {
        unreachable!()
    };
    let last = r.protocol_i_es.0.last().unwrap();
    assert_eq!(last.criticality.0, ngap_gen::Criticality::REJECT);
}

#[test]
fn ics_without_an_id_carries_the_capability_before_the_nas_pdu() {
    let _g = guard();
    let out = add_capability_ies(ics(true), None, Some(&[0xAA, 0xBB]));
    let ids = ics_ids(&out);
    let cap = ids
        .iter()
        .position(|i| *i == ngap_gen::ID_UE_RADIO_CAPABILITY)
        .unwrap();
    let nas = ids.iter().position(|i| *i == ngap_gen::ID_NAS_PDU).unwrap();
    assert!(cap < nas, "117 precedes NAS-PDU in the object set: {ids:?}");
    assert!(!ids.contains(&ngap_gen::ID_UE_RADIO_CAPABILITY_ID));
}

#[test]
fn nothing_to_add_leaves_the_bytes_untouched() {
    let _g = guard();
    let plain = ics(false);
    assert_eq!(add_capability_ies(plain.clone(), None, None), plain);
    assert_eq!(add_capability_ies(plain.clone(), None, Some(&[])), plain);
    // A retired ID is not put in NGAP.
    apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "manAssOpRequestlist": { "plmnAssiUeRadioCapId": [to_nucmf(&ID).unwrap()] },
    }));
    assert_eq!(add_capability_ies(plain.clone(), Some(&ID), None), plain);
}

#[test]
fn handover_request_and_path_switch_ack_get_the_id() {
    let _g = guard();
    let ho = nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::InitiatingMessage(
        ngap_gen::InitiatingMessage {
            procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_HANDOVER_RESOURCE_ALLOCATION),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
            value: ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(
                ngap_gen::HandoverRequest {
                    protocol_i_es: ngap_gen::HandoverRequestProtocolIEs(vec![
                        ngap_gen::HandoverRequestProtocolIEs_Entry {
                            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
                            criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                            value:
                                ngap_gen::HandoverRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                                    ngap_gen::AMF_UE_NGAP_ID(1),
                                ),
                        },
                    ]),
                },
            ),
        },
    ))
    .unwrap();
    let out = add_capability_ies(ho, Some(&ID), Some(&[0xAA]));
    let ngap_gen::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(&out).unwrap() else {
        unreachable!()
    };
    let ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(r) = m.value else {
        unreachable!()
    };
    let ids: Vec<u16> = r.protocol_i_es.0.iter().map(|e| e.id.0).collect();
    assert_eq!(
        ids,
        vec![
            ngap_gen::ID_AMF_UE_NGAP_ID,
            ngap_gen::ID_UE_RADIO_CAPABILITY_ID
        ]
    );

    let psa = nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::SuccessfulOutcome(
        ngap_gen::SuccessfulOutcome {
            procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PATH_SWITCH_REQUEST),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
            value: ngap_gen::SuccessfulOutcomeValue::Id_PathSwitchRequest(
                ngap_gen::PathSwitchRequestAcknowledge {
                    protocol_i_es: ngap_gen::PathSwitchRequestAcknowledgeProtocolIEs(vec![
                        ngap_gen::PathSwitchRequestAcknowledgeProtocolIEs_Entry {
                            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
                            criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                            value: ngap_gen::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                                ngap_gen::AMF_UE_NGAP_ID(1),
                            ),
                        },
                    ]),
                },
            ),
        },
    ))
    .unwrap();
    let out = add_capability_ies(psa, Some(&ID), None);
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(m) = nextgcore_ngap_gen::decode(&out).unwrap() else {
        unreachable!()
    };
    let ngap_gen::SuccessfulOutcomeValue::Id_PathSwitchRequest(r) = m.value else {
        unreachable!()
    };
    let ids: Vec<u16> = r.protocol_i_es.0.iter().map(|e| e.id.0).collect();
    assert_eq!(
        ids,
        vec![
            ngap_gen::ID_AMF_UE_NGAP_ID,
            ngap_gen::ID_UE_RADIO_CAPABILITY_ID
        ]
    );
}

fn racs_ue() -> crate::context::AmfUe {
    let mut ue = crate::context::AmfUe::default();
    ue.racs_supported = true;
    ue
}

#[test]
fn nas_sends_an_assigned_id_once_and_only_to_a_racs_ue() {
    let _g = guard();
    let mut ue = racs_ue();
    ue.ue_radio_capability_id = Some(ID.to_vec());
    // §9.11.3.68: IEI 67, length 07, value.
    assert_eq!(
        nas_ies_for(&mut ue, NasMessage::RegistrationAccept),
        vec![0x67, 0x07, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10]
    );
    assert!(ue.ue_radio_capability_id_known_to_ue);
    assert!(
        nas_ies_for(&mut ue, NasMessage::RegistrationAccept).is_empty(),
        "sent once"
    );

    let mut no_racs = crate::context::AmfUe::default();
    no_racs.ue_radio_capability_id = Some(ID.to_vec());
    assert!(
        nas_ies_for(&mut no_racs, NasMessage::RegistrationAccept).is_empty(),
        "§5.5.1.2.4: RACS bit required"
    );
}

#[test]
fn a_deleted_id_becomes_the_deletion_indication() {
    let _g = guard();
    let mut ue = racs_ue();
    ue.ue_radio_capability_id = Some(ID.to_vec());
    ue.ue_radio_capability_id_known_to_ue = true;
    let retired = apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "dicEntryId": 1,
        "manAssOpRequestlist": { "plmnAssiUeRadioCapId": [to_nucmf(&ID).unwrap()] },
    }));
    assert_eq!(retired, vec![ID.to_vec()]);
    // §9.11.3.69: half-octet IEI E in REGISTRATION ACCEPT (table 8.2.7.1.1),
    // "deletion requested" 1.
    assert_eq!(
        nas_ies_for(&mut ue, NasMessage::RegistrationAccept),
        vec![0xE1]
    );
    assert_eq!(ue.ue_radio_capability_id, None);
    // Sent once: the ID is gone from the context.
    assert!(nas_ies_for(&mut ue, NasMessage::RegistrationAccept).is_empty());

    // In a CONFIGURATION UPDATE COMMAND the same IE has IEI A (table 8.2.19.1.1).
    let mut ue = racs_ue();
    ue.ue_radio_capability_id = Some(ID.to_vec());
    assert_eq!(
        nas_ies_for(&mut ue, NasMessage::ConfigurationUpdateCommand),
        vec![0xA1]
    );
}

#[test]
fn a_new_version_id_retires_the_old_ones_and_purges_the_cache() {
    let _g = guard();
    cache_put(&ID, &[0xAA]);
    let newer = [0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10];
    cache_put(&newer, &[0xBB]);
    let purged = apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    assert_eq!(purged, vec![ID.to_vec()]);
    assert_eq!(cache_get(&ID), None);
    assert_eq!(cache_get(&newer), Some(vec![0xBB]));
    assert!(is_retired(&ID));
    assert!(!is_retired(&newer));
}

/// A distinct PLMN-assigned ID under Version ID `version` for each `n`.
fn nth_id(version: u8, n: u32) -> Vec<u8> {
    let mut id = vec![0x01, version, 0x00];
    id.extend_from_slice(&n.to_be_bytes());
    id
}

/// #747: the retired-ID set is bounded however many unknown IDs are presented,
/// and evicts the oldest first.
#[test]
fn the_retired_set_is_bounded_and_evicts_the_oldest() {
    let _g = guard();
    let over = DELETED_CAPACITY_FOR_TESTS + 100;
    for n in 0..over as u32 {
        with_cache(|c| c.retire(&nth_id(0x05, n)));
    }
    assert_eq!(deleted_len(), DELETED_CAPACITY_FOR_TESTS);
    assert!(!is_known_deleted(&nth_id(0x05, 0)), "the oldest is evicted");
    assert!(!is_known_deleted(&nth_id(0x05, 99)));
    assert!(is_known_deleted(&nth_id(0x05, 100)));
    assert!(is_known_deleted(&nth_id(0x05, over as u32 - 1)));
    // Retiring an ID already held moves nothing.
    with_cache(|c| c.retire(&nth_id(0x05, over as u32 - 1)));
    assert!(is_known_deleted(&nth_id(0x05, 100)));
    // A notification's deletions go through the same bound.
    let ids: Vec<String> = (0..10u32)
        .map(|n| to_nucmf(&nth_id(0x07, n)).unwrap())
        .collect();
    apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "manAssOpRequestlist": { "plmnAssiUeRadioCapId": ids },
    }));
    assert_eq!(deleted_len(), DELETED_CAPACITY_FOR_TESTS);
    assert!(is_known_deleted(&nth_id(0x07, 9)));
}

/// #747: a new Version ID drops the retired entries under older ones, which
/// `is_retired` now covers by the Version ID alone.
#[test]
fn a_new_version_id_drops_the_retired_entries_it_covers() {
    let _g = guard();
    with_cache(|c| {
        c.retire(&nth_id(0x05, 1));
        c.retire(&nth_id(0x06, 2));
        // Manufacturer-assigned: no Version ID, so kept.
        c.retire(&[0x00, 0x00, 0x70, 0xDE, 0x09, 0x00, 0x00, 0x00, 0xA0, 0xCB]);
    });
    apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    assert_eq!(deleted_len(), 2);
    assert!(!is_known_deleted(&nth_id(0x05, 1)));
    assert!(
        is_retired(&nth_id(0x05, 1)),
        "still retired, by its Version ID"
    );
    assert!(is_known_deleted(&nth_id(0x06, 2)));
    // The FIFO order follows the set, so a later eviction cannot resurrect a
    // dropped entry or skip a live one.
    assert_eq!(with_cache(|c| c.deleted_order.len()), 2);
}
