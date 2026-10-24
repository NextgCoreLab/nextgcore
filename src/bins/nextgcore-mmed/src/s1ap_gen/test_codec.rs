//! Test-only S1AP codec over the generated `nextgcore-s1ap-gen` types (#514
//! stage 13b).
//!
//! The hand-written S1AP builder and parser are gone. mmed's tests still need
//! two things they used to provide: building the eNB -> MME messages a test
//! feeds to a handler, and reading back the MME -> eNB messages a handler
//! sends. This module does both with the generated codec, so every byte a test
//! builds or reads is conformant by construction (TS 36.413 V19.2.0 ASN.1),
//! and maps to and from mmed's domain types (`nextgcore_s1ap`).
//!
//! `builder::build_*` keep the old builders' names and `&Message ->
//! S1apResult<Vec<u8>>` shape, and `decode_s1ap_pdu` the old parser's, so a
//! test changes only its `use`. Builders for messages mmed itself sends wrap
//! the production encoders in `s1ap_gen`; the rest are written here. IE order
//! and criticality follow each message's ProtocolIEs table.

use super::*;
use nextgcore_s1ap::{S1apError, S1apMessage, S1apResult};

fn asn(e: impl std::fmt::Debug) -> S1apError {
    S1apError::AsnError(format!("{e:?}"))
}

fn missing_ie(name: &'static str) -> S1apError {
    S1apError::MissingMandatoryIe(name)
}

fn bad(name: &'static str) -> S1apError {
    S1apError::InvalidIeValue {
        ie_name: name,
        reason: "out of range".into(),
    }
}

// ----------------------------------------------------------------------------
// domain -> generated
// ----------------------------------------------------------------------------

fn tai_g(t: &Tai) -> g::TAI {
    g::TAI {
        plm_nidentity: g::TBCD_STRING(t.plmn_identity.to_vec()),
        tac: g::TAC(t.tac.to_be_bytes().to_vec()),
        ie_extensions: None,
    }
}

fn cgi_g(c: &EutranCgi) -> g::EUTRAN_CGI {
    g::EUTRAN_CGI {
        plm_nidentity: g::TBCD_STRING(c.plmn_identity.to_vec()),
        cell_id: g::CellIdentity(u32_to_bits(c.cell_identity, 28)),
        ie_extensions: None,
    }
}

fn enb_id_g(id: &GlobalEnbId) -> g::Global_ENB_ID {
    g::Global_ENB_ID {
        plm_nidentity: g::TBCD_STRING(id.plmn_identity.to_vec()),
        enb_id: match id.enb_id {
            EnbId::Macro(v) => g::ENB_ID::MacroENB_ID(g::ENB_ID_macroENB_ID(u32_to_bits(v, 20))),
            EnbId::Home(v) => g::ENB_ID::HomeENB_ID(g::ENB_ID_homeENB_ID(u32_to_bits(v, 28))),
            EnbId::ShortMacro(v) => {
                g::ENB_ID::Short_macroENB_ID(g::ENB_ID_short_macroENB_ID(u32_to_bits(v, 18)))
            }
            EnbId::LongMacro(v) => {
                g::ENB_ID::Long_macroENB_ID(g::ENB_ID_long_macroENB_ID(u32_to_bits(v, 21)))
            }
        },
        ie_extensions: None,
    }
}

fn caps_g(c: &nextgcore_s1ap::UeSecurityCapabilities) -> g::UESecurityCapabilities {
    g::UESecurityCapabilities {
        encryption_algorithms: g::EncryptionAlgorithms(bits16(c.encryption_algorithms)),
        integrity_protection_algorithms: g::IntegrityProtectionAlgorithms(bits16(
            c.integrity_algorithms,
        )),
        ie_extensions: None,
    }
}

fn failed_list_g(items: &[nextgcore_s1ap::ErabFailedItem]) -> g::E_RABList {
    g::E_RABList(
        items
            .iter()
            .map(|i| g::E_RABList_Entry {
                id: g::ProtocolIE_ID(35),
                criticality: g::Criticality(IGNORE),
                value: g::E_RABList_EntryValue::Id_E_RABItem(g::E_RABItem {
                    e_rab_id: g::E_RAB_ID(i.erab_id),
                    cause: generated_cause(i.cause),
                    ie_extensions: None,
                }),
            })
            .collect(),
    )
}

fn supported_tas_g(tas: &[SupportedTaItem]) -> g::SupportedTAs {
    g::SupportedTAs(
        tas.iter()
            .map(|ta| g::SupportedTAs_Item {
                tac: g::TAC(ta.tac.to_be_bytes().to_vec()),
                broadcast_plm_ns: g::BPLMNs(
                    ta.broadcast_plmns
                        .iter()
                        .map(|p| g::TBCD_STRING(p.to_vec()))
                        .collect(),
                ),
                ie_extensions: None,
            })
            .collect(),
    )
}

fn completed_area_g(
    a: &nextgcore_s1ap::BroadcastCompletedAreaList,
) -> g::BroadcastCompletedAreaList {
    use nextgcore_s1ap::BroadcastCompletedAreaList as B;
    match a {
        B::CellIdBroadcast(cells) => {
            g::BroadcastCompletedAreaList::CellID_Broadcast(g::CellID_Broadcast(
                cells
                    .iter()
                    .map(|c| g::CellID_Broadcast_Item {
                        ecgi: cgi_g(c),
                        ie_extensions: None,
                    })
                    .collect(),
            ))
        }
        B::TaiBroadcast(items) => g::BroadcastCompletedAreaList::TAI_Broadcast(g::TAI_Broadcast(
            items
                .iter()
                .map(|i| g::TAI_Broadcast_Item {
                    tai: tai_g(&i.tai),
                    completed_cellin_tai: g::CompletedCellinTAI(
                        i.completed_cells
                            .iter()
                            .map(|c| g::CompletedCellinTAI_Item {
                                ecgi: cgi_g(c),
                                ie_extensions: None,
                            })
                            .collect(),
                    ),
                    ie_extensions: None,
                })
                .collect(),
        )),
        B::EmergencyAreaIdBroadcast(items) => {
            g::BroadcastCompletedAreaList::EmergencyAreaID_Broadcast(g::EmergencyAreaID_Broadcast(
                items
                    .iter()
                    .map(|i| g::EmergencyAreaID_Broadcast_Item {
                        emergency_area_id: g::EmergencyAreaID(i.emergency_area_id.to_vec()),
                        completed_cellin_eai: g::CompletedCellinEAI(
                            i.completed_cells
                                .iter()
                                .map(|c| g::CompletedCellinEAI_Item {
                                    ecgi: cgi_g(c),
                                    ie_extensions: None,
                                })
                                .collect(),
                        ),
                        ie_extensions: None,
                    })
                    .collect(),
            ))
        }
    }
}

fn cancelled_cells_g<T>(
    cells: &[nextgcore_s1ap::CellIdCancelledItem],
    make: impl Fn(g::EUTRAN_CGI, g::NumberOfBroadcasts) -> T,
) -> Vec<T> {
    cells
        .iter()
        .map(|c| {
            make(
                cgi_g(&c.ecgi),
                g::NumberOfBroadcasts(c.number_of_broadcasts),
            )
        })
        .collect()
}

fn cancelled_area_g(
    a: &nextgcore_s1ap::BroadcastCancelledAreaList,
) -> g::BroadcastCancelledAreaList {
    use nextgcore_s1ap::BroadcastCancelledAreaList as B;
    match a {
        B::CellIdCancelled(cells) => g::BroadcastCancelledAreaList::CellID_Cancelled(
            g::CellID_Cancelled(cancelled_cells_g(cells, |ecgi, number_of_broadcasts| {
                g::CellID_Cancelled_Item {
                    ecgi,
                    number_of_broadcasts,
                    ie_extensions: None,
                }
            })),
        ),
        B::TaiCancelled(items) => g::BroadcastCancelledAreaList::TAI_Cancelled(g::TAI_Cancelled(
            items
                .iter()
                .map(|i| g::TAI_Cancelled_Item {
                    tai: tai_g(&i.tai),
                    cancelled_cellin_tai: g::CancelledCellinTAI(cancelled_cells_g(
                        &i.cancelled_cells,
                        |ecgi, number_of_broadcasts| g::CancelledCellinTAI_Item {
                            ecgi,
                            number_of_broadcasts,
                            ie_extensions: None,
                        },
                    )),
                    ie_extensions: None,
                })
                .collect(),
        )),
        B::EmergencyAreaIdCancelled(items) => {
            g::BroadcastCancelledAreaList::EmergencyAreaID_Cancelled(g::EmergencyAreaID_Cancelled(
                items
                    .iter()
                    .map(|i| g::EmergencyAreaID_Cancelled_Item {
                        emergency_area_id: g::EmergencyAreaID(i.emergency_area_id.to_vec()),
                        cancelled_cellin_eai: g::CancelledCellinEAI(cancelled_cells_g(
                            &i.cancelled_cells,
                            |ecgi, number_of_broadcasts| g::CancelledCellinEAI_Item {
                                ecgi,
                                number_of_broadcasts,
                                ie_extensions: None,
                            },
                        )),
                        ie_extensions: None,
                    })
                    .collect(),
            ))
        }
    }
}

fn target_id_g(t: &nextgcore_s1ap::TargetId) -> g::TargetID {
    use nextgcore_s1ap::TargetId as T;
    match t {
        T::TargetEnbId {
            global_enb_id,
            selected_tai,
        } => g::TargetID::TargeteNB_ID(g::TargeteNB_ID {
            global_enb_id: enb_id_g(global_enb_id),
            selected_tai: tai_g(selected_tai),
            ie_extensions: None,
        }),
        T::TargetRncId {
            plmn_identity,
            lac,
            rac,
            rnc_id,
        } => g::TargetID::TargetRNC_ID(g::TargetRNC_ID {
            lai: g::LAI {
                plm_nidentity: g::TBCD_STRING(plmn_identity.to_vec()),
                lac: g::LAC(lac.to_be_bytes().to_vec()),
                ie_extensions: None,
            },
            rac: rac.map(|r| g::RAC(vec![r])),
            rnc_id: g::RNC_ID(*rnc_id),
            extended_rnc_id: None,
            ie_extensions: None,
        }),
        T::Cgi {
            plmn_identity,
            lac,
            ci,
            rac,
        } => g::TargetID::CGI(g::CGI {
            plm_nidentity: g::TBCD_STRING(plmn_identity.to_vec()),
            lac: g::LAC(lac.to_be_bytes().to_vec()),
            ci: g::CI(ci.to_be_bytes().to_vec()),
            rac: rac.map(|r| g::RAC(vec![r])),
            ie_extensions: None,
        }),
    }
}

fn enc(pdu: g::S1AP_PDU) -> S1apResult<Vec<u8>> {
    nextgcore_s1ap_gen::encode(&pdu).map_err(asn)
}

fn initiating(code: u8, criticality: u8, value: g::InitiatingMessageValue) -> S1apResult<Vec<u8>> {
    enc(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(code),
        criticality: g::Criticality(criticality),
        value,
    }))
}

fn successful(code: u8, value: g::SuccessfulOutcomeValue) -> S1apResult<Vec<u8>> {
    enc(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(code),
        criticality: g::Criticality(REJECT),
        value,
    }))
}

fn unsuccessful(code: u8, value: g::UnsuccessfulOutcomeValue) -> S1apResult<Vec<u8>> {
    enc(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        procedure_code: g::ProcedureCode(code),
        criticality: g::Criticality(REJECT),
        value,
    }))
}

/// One ProtocolIE-Field of message `$m` (`$m ProtocolIEs_Entry`).
macro_rules! ie {
    ($entry:ident, $id:expr, $crit:expr, $value:expr) => {
        g::$entry {
            id: g::ProtocolIE_ID($id),
            criticality: g::Criticality($crit),
            value: $value,
        }
    };
}

/// Builders with the shape of the deleted hand-written `builder` module.
pub mod builder {
    use super::*;
    use nextgcore_s1ap::*;

    fn wrap(r: Result<Vec<u8>, asn1_codecs::PerCodecError>) -> S1apResult<Vec<u8>> {
        r.map_err(asn)
    }

    /// A production encode, checked: the bytes must decode, through this
    /// module's independently written generated -> domain mapping, back to
    /// the message that was encoded. This is what the byte-equivalence tests
    /// that used to compare against the hand-written encoder now rely on.
    fn checked(
        r: Result<Vec<u8>, asn1_codecs::PerCodecError>,
        expect: S1apMessage,
    ) -> S1apResult<Vec<u8>> {
        let bytes = wrap(r)?;
        let back = super::decode_s1ap_pdu(&bytes)
            .unwrap_or_else(|e| panic!("production encode does not decode: {e:?}"));
        assert_eq!(
            format!("{back:?}"),
            format!("{expect:?}"),
            "production encode does not decode back to its input"
        );
        Ok(bytes)
    }

    // ---- messages mmed sends: the production encoders -------------------

    pub fn build_s1_setup_response(msg: &S1SetupResponse) -> S1apResult<Vec<u8>> {
        let gummeis: Vec<ServedGummei> = msg
            .served_gummeis
            .iter()
            .map(|s| ServedGummei {
                plmns: s.served_plmns.clone(),
                group_ids: s.served_group_ids.clone(),
                codes: s.served_mmec_codes.clone(),
            })
            .collect();
        checked(
            super::super::build_s1_setup_response(
                msg.mme_name.as_deref(),
                &gummeis,
                msg.relative_mme_capacity,
                &[],
            ),
            S1apMessage::S1SetupResponse(msg.clone()),
        )
    }

    pub fn build_s1_setup_failure(msg: &S1SetupFailure) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_s1_setup_failure(msg.cause, msg.time_to_wait, &[]),
            S1apMessage::S1SetupFailure(msg.clone()),
        )
    }

    pub fn build_downlink_nas_transport(msg: &DlNasTransport) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_downlink_nas_transport(
                msg.enb_ue_s1ap_id,
                msg.mme_ue_s1ap_id,
                &msg.nas_pdu,
            ),
            S1apMessage::DownlinkNasTransport(msg.clone()),
        )
    }

    pub fn build_initial_context_setup_request(
        msg: &InitialContextSetupRequest,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_initial_context_setup_request(msg),
            S1apMessage::InitialContextSetupRequest(msg.clone()),
        )
    }

    pub fn build_ue_context_release_command(msg: &UeContextReleaseCommand) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_ue_context_release_command(&msg.ue_s1ap_ids, msg.cause),
            S1apMessage::UeContextReleaseCommand(msg.clone()),
        )
    }

    pub fn build_erab_setup_request(msg: &ErabSetupRequest) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_erab_setup_request(msg),
            S1apMessage::ErabSetupRequest(msg.clone()),
        )
    }

    pub fn build_erab_modify_request(msg: &ErabModifyRequest) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_erab_modify_request(msg),
            S1apMessage::ErabModifyRequest(msg.clone()),
        )
    }

    pub fn build_erab_release_command(msg: &ErabReleaseCommand) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_erab_release_command(msg),
            S1apMessage::ErabReleaseCommand(msg.clone()),
        )
    }

    pub fn build_paging(msg: &Paging) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_paging(msg),
            S1apMessage::Paging(msg.clone()),
        )
    }

    pub fn build_error_indication(msg: &ErrorIndication) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_error_indication(msg),
            S1apMessage::ErrorIndication(msg.clone()),
        )
    }

    pub fn build_reset_acknowledge(msg: &ResetAcknowledge) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_reset_acknowledge(msg, &[]),
            S1apMessage::ResetAcknowledge(msg.clone()),
        )
    }

    pub fn build_mme_status_transfer(msg: &MmeStatusTransfer) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_mme_status_transfer(msg),
            S1apMessage::MmeStatusTransfer(msg.clone()),
        )
    }

    pub fn build_handover_command(msg: &HandoverCommand) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_handover_command(msg, &[]),
            S1apMessage::HandoverCommand(msg.clone()),
        )
    }

    pub fn build_handover_preparation_failure(
        msg: &HandoverPreparationFailure,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_handover_preparation_failure(msg),
            S1apMessage::HandoverPreparationFailure(msg.clone()),
        )
    }

    pub fn build_handover_request(msg: &HandoverRequest) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_handover_request(msg),
            S1apMessage::HandoverRequest(msg.clone()),
        )
    }

    pub fn build_handover_cancel_acknowledge(
        msg: &HandoverCancelAcknowledge,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_handover_cancel_acknowledge(msg, &[]),
            S1apMessage::HandoverCancelAcknowledge(msg.clone()),
        )
    }

    pub fn build_path_switch_request_acknowledge(
        msg: &PathSwitchRequestAcknowledge,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_path_switch_request_acknowledge(msg, &[]),
            S1apMessage::PathSwitchRequestAcknowledge(msg.clone()),
        )
    }

    pub fn build_path_switch_request_failure(
        msg: &PathSwitchRequestFailure,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_path_switch_request_failure(msg, &[]),
            S1apMessage::PathSwitchRequestFailure(msg.clone()),
        )
    }

    pub fn build_enb_configuration_update_acknowledge(
        _msg: &EnbConfigurationUpdateAcknowledge,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_enb_configuration_update_acknowledge(&[]),
            S1apMessage::EnbConfigurationUpdateAcknowledge(_msg.clone()),
        )
    }

    pub fn build_enb_configuration_update_failure(
        msg: &EnbConfigurationUpdateFailure,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_enb_configuration_update_failure(msg.cause, msg.time_to_wait, &[]),
            S1apMessage::EnbConfigurationUpdateFailure(msg.clone()),
        )
    }

    pub fn build_ue_context_modification_request(
        msg: &UeContextModificationRequest,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_ue_context_modification_request(msg),
            S1apMessage::UeContextModificationRequest(msg.clone()),
        )
    }

    pub fn build_overload_start(msg: &OverloadStart) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_overload_start(msg.overload_action),
            S1apMessage::OverloadStart(msg.clone()),
        )
    }

    pub fn build_overload_stop(_msg: &OverloadStop) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_overload_stop(),
            S1apMessage::OverloadStop(OverloadStop),
        )
    }

    pub fn build_write_replace_warning_request(
        msg: &WriteReplaceWarningRequest,
    ) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_write_replace_warning_request(msg),
            S1apMessage::WriteReplaceWarningRequest(msg.clone()),
        )
    }

    pub fn build_kill_request(msg: &KillRequest) -> S1apResult<Vec<u8>> {
        checked(
            super::super::build_kill_request(msg),
            S1apMessage::KillRequest(msg.clone()),
        )
    }

    pub fn build_mme_configuration_update(msg: &MmeConfigurationUpdate) -> S1apResult<Vec<u8>> {
        use g::MMEConfigurationUpdateProtocolIEs_EntryValue as V;
        let mut ies = Vec::new();
        if let Some(name) = &msg.mme_name {
            ies.push(ie!(
                MMEConfigurationUpdateProtocolIEs_Entry,
                61,
                IGNORE,
                V::Id_MMEname(g::MMEname(name.clone()))
            ));
        }
        if let Some(gummeis) = &msg.served_gummeis {
            ies.push(ie!(
                MMEConfigurationUpdateProtocolIEs_Entry,
                105,
                REJECT,
                V::Id_ServedGUMMEIs(g::ServedGUMMEIs(
                    gummeis
                        .iter()
                        .map(|s| g::ServedGUMMEIsItem {
                            served_plm_ns: g::ServedPLMNs(
                                s.served_plmns
                                    .iter()
                                    .map(|p| g::TBCD_STRING(p.to_vec()))
                                    .collect(),
                            ),
                            served_group_i_ds: g::ServedGroupIDs(
                                s.served_group_ids
                                    .iter()
                                    .map(|i| g::MME_Group_ID(i.to_be_bytes().to_vec()))
                                    .collect(),
                            ),
                            served_mme_cs: g::ServedMMECs(
                                s.served_mmec_codes
                                    .iter()
                                    .map(|c| g::MME_Code(vec![*c]))
                                    .collect(),
                            ),
                            ie_extensions: None,
                        })
                        .collect(),
                ))
            ));
        }
        if let Some(cap) = msg.relative_mme_capacity {
            ies.push(ie!(
                MMEConfigurationUpdateProtocolIEs_Entry,
                87,
                REJECT,
                V::Id_RelativeMMECapacity(g::RelativeMMECapacity(cap))
            ));
        }
        initiating(
            30,
            REJECT,
            g::InitiatingMessageValue::Id_MMEConfigurationUpdate(g::MMEConfigurationUpdate {
                protocol_i_es: g::MMEConfigurationUpdateProtocolIEs(ies),
            }),
        )
    }

    // ---- messages an eNB sends: written here -----------------------------

    pub fn build_s1_setup_request(msg: &S1SetupRequest) -> S1apResult<Vec<u8>> {
        wrap(super::super::build_s1_setup_request(msg))
    }

    pub fn build_initial_ue_message(msg: &InitialUeMessage) -> S1apResult<Vec<u8>> {
        use g::InitialUEMessageProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                InitialUEMessageProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                InitialUEMessageProtocolIEs_Entry,
                26,
                REJECT,
                V::Id_NAS_PDU(g::NAS_PDU(msg.nas_pdu.clone()))
            ),
            ie!(
                InitialUEMessageProtocolIEs_Entry,
                67,
                REJECT,
                V::Id_TAI(tai_g(&msg.tai))
            ),
            ie!(
                InitialUEMessageProtocolIEs_Entry,
                100,
                IGNORE,
                V::Id_EUTRAN_CGI(cgi_g(&msg.eutran_cgi))
            ),
            ie!(
                InitialUEMessageProtocolIEs_Entry,
                134,
                IGNORE,
                V::Id_RRC_Establishment_Cause(g::RRC_Establishment_Cause(
                    msg.rrc_establishment_cause as u8
                ))
            ),
        ];
        if let Some(s) = &msg.s_tmsi {
            ies.push(ie!(
                InitialUEMessageProtocolIEs_Entry,
                96,
                REJECT,
                V::Id_S_TMSI(g::S_TMSI {
                    mmec: g::MME_Code(vec![s.mmec]),
                    m_tmsi: g::M_TMSI(s.m_tmsi.to_be_bytes().to_vec()),
                    ie_extensions: None,
                })
            ));
        }
        initiating(
            12,
            IGNORE,
            g::InitiatingMessageValue::Id_initialUEMessage(g::InitialUEMessage {
                protocol_i_es: g::InitialUEMessageProtocolIEs(ies),
            }),
        )
    }

    pub fn build_uplink_nas_transport(msg: &UlNasTransport) -> S1apResult<Vec<u8>> {
        use g::UplinkNASTransportProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                UplinkNASTransportProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UplinkNASTransportProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                UplinkNASTransportProtocolIEs_Entry,
                26,
                REJECT,
                V::Id_NAS_PDU(g::NAS_PDU(msg.nas_pdu.clone()))
            ),
            ie!(
                UplinkNASTransportProtocolIEs_Entry,
                100,
                IGNORE,
                V::Id_EUTRAN_CGI(cgi_g(&msg.eutran_cgi))
            ),
            ie!(
                UplinkNASTransportProtocolIEs_Entry,
                67,
                IGNORE,
                V::Id_TAI(tai_g(&msg.tai))
            ),
        ];
        initiating(
            13,
            IGNORE,
            g::InitiatingMessageValue::Id_uplinkNASTransport(g::UplinkNASTransport {
                protocol_i_es: g::UplinkNASTransportProtocolIEs(ies),
            }),
        )
    }

    pub fn build_nas_non_delivery_indication(
        msg: &NasNonDeliveryIndication,
    ) -> S1apResult<Vec<u8>> {
        use g::NASNonDeliveryIndicationProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                NASNonDeliveryIndicationProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                NASNonDeliveryIndicationProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                NASNonDeliveryIndicationProtocolIEs_Entry,
                26,
                IGNORE,
                V::Id_NAS_PDU(g::NAS_PDU(msg.nas_pdu.clone()))
            ),
            ie!(
                NASNonDeliveryIndicationProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        initiating(
            16,
            IGNORE,
            g::InitiatingMessageValue::Id_NASNonDeliveryIndication(g::NASNonDeliveryIndication {
                protocol_i_es: g::NASNonDeliveryIndicationProtocolIEs(ies),
            }),
        )
    }

    pub fn build_initial_context_setup_response(
        msg: &InitialContextSetupResponse,
    ) -> S1apResult<Vec<u8>> {
        use g::InitialContextSetupResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                InitialContextSetupResponseProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                InitialContextSetupResponseProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                InitialContextSetupResponseProtocolIEs_Entry,
                51,
                IGNORE,
                V::Id_E_RABSetupListCtxtSURes(g::E_RABSetupListCtxtSURes(
                    msg.erab_setup_list
                        .iter()
                        .map(|i| g::E_RABSetupListCtxtSURes_Entry {
                            id: g::ProtocolIE_ID(50),
                            criticality: g::Criticality(IGNORE),
                            value:
                                g::E_RABSetupListCtxtSURes_EntryValue::Id_E_RABSetupItemCtxtSURes(
                                    g::E_RABSetupItemCtxtSURes {
                                        e_rab_id: g::E_RAB_ID(i.erab_id),
                                        transport_layer_address: transport(
                                            &i.transport_layer_address
                                        ),
                                        gtp_teid: gtp_teid(i.gtp_teid),
                                        ie_extensions: None,
                                    },
                                ),
                        })
                        .collect(),
                ))
            ),
        ];
        if !msg.erab_failed_list.is_empty() {
            ies.push(ie!(
                InitialContextSetupResponseProtocolIEs_Entry,
                48,
                IGNORE,
                V::Id_E_RABFailedToSetupListCtxtSURes(failed_list_g(&msg.erab_failed_list))
            ));
        }
        successful(
            9,
            g::SuccessfulOutcomeValue::Id_InitialContextSetup(g::InitialContextSetupResponse {
                protocol_i_es: g::InitialContextSetupResponseProtocolIEs(ies),
            }),
        )
    }

    pub fn build_initial_context_setup_failure(
        msg: &InitialContextSetupFailure,
    ) -> S1apResult<Vec<u8>> {
        use g::InitialContextSetupFailureProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                InitialContextSetupFailureProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                InitialContextSetupFailureProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                InitialContextSetupFailureProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        unsuccessful(
            9,
            g::UnsuccessfulOutcomeValue::Id_InitialContextSetup(g::InitialContextSetupFailure {
                protocol_i_es: g::InitialContextSetupFailureProtocolIEs(ies),
            }),
        )
    }

    pub fn build_ue_context_release_request(msg: &UeContextReleaseRequest) -> S1apResult<Vec<u8>> {
        use g::UEContextReleaseRequestProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                UEContextReleaseRequestProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UEContextReleaseRequestProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                UEContextReleaseRequestProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        initiating(
            18,
            IGNORE,
            g::InitiatingMessageValue::Id_UEContextReleaseRequest(g::UEContextReleaseRequest {
                protocol_i_es: g::UEContextReleaseRequestProtocolIEs(ies),
            }),
        )
    }

    pub fn build_ue_context_release_complete(
        msg: &UeContextReleaseComplete,
    ) -> S1apResult<Vec<u8>> {
        use g::UEContextReleaseCompleteProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                UEContextReleaseCompleteProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UEContextReleaseCompleteProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
        ];
        successful(
            23,
            g::SuccessfulOutcomeValue::Id_UEContextRelease(g::UEContextReleaseComplete {
                protocol_i_es: g::UEContextReleaseCompleteProtocolIEs(ies),
            }),
        )
    }

    pub fn build_erab_setup_response(msg: &ErabSetupResponse) -> S1apResult<Vec<u8>> {
        use g::E_RABSetupResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                E_RABSetupResponseProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                E_RABSetupResponseProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
        ];
        if !msg.erab_setup_list.is_empty() {
            ies.push(ie!(
                E_RABSetupResponseProtocolIEs_Entry,
                28,
                IGNORE,
                V::Id_E_RABSetupListBearerSURes(g::E_RABSetupListBearerSURes(
                    msg.erab_setup_list
                        .iter()
                        .map(|i| g::E_RABSetupListBearerSURes_Entry {
                            id: g::ProtocolIE_ID(39),
                            criticality: g::Criticality(IGNORE),
                            value:
                                g::E_RABSetupListBearerSURes_EntryValue::Id_E_RABSetupItemBearerSURes(
                                    g::E_RABSetupItemBearerSURes {
                                        e_rab_id: g::E_RAB_ID(i.erab_id),
                                        transport_layer_address: transport(
                                            &i.transport_layer_address,
                                        ),
                                        gtp_teid: gtp_teid(i.gtp_teid),
                                        ie_extensions: None,
                                    },
                                ),
                        })
                        .collect(),
                ))
            ));
        }
        if !msg.erab_failed_list.is_empty() {
            ies.push(ie!(
                E_RABSetupResponseProtocolIEs_Entry,
                29,
                IGNORE,
                V::Id_E_RABFailedToSetupListBearerSURes(failed_list_g(&msg.erab_failed_list))
            ));
        }
        successful(
            5,
            g::SuccessfulOutcomeValue::Id_E_RABSetup(g::E_RABSetupResponse {
                protocol_i_es: g::E_RABSetupResponseProtocolIEs(ies),
            }),
        )
    }

    pub fn build_erab_modify_response(msg: &ErabModifyResponse) -> S1apResult<Vec<u8>> {
        use g::E_RABModifyResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                E_RABModifyResponseProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                E_RABModifyResponseProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
        ];
        if !msg.erab_modify_list.is_empty() {
            ies.push(ie!(
                E_RABModifyResponseProtocolIEs_Entry,
                31,
                IGNORE,
                V::Id_E_RABModifyListBearerModRes(g::E_RABModifyListBearerModRes(
                    msg.erab_modify_list
                        .iter()
                        .map(|id| g::E_RABModifyListBearerModRes_Entry {
                            id: g::ProtocolIE_ID(37),
                            criticality: g::Criticality(IGNORE),
                            value:
                                g::E_RABModifyListBearerModRes_EntryValue::Id_E_RABModifyItemBearerModRes(
                                    g::E_RABModifyItemBearerModRes {
                                        e_rab_id: g::E_RAB_ID(*id),
                                        ie_extensions: None,
                                    },
                                ),
                        })
                        .collect(),
                ))
            ));
        }
        if !msg.erab_failed_list.is_empty() {
            ies.push(ie!(
                E_RABModifyResponseProtocolIEs_Entry,
                32,
                IGNORE,
                V::Id_E_RABFailedToModifyList(failed_list_g(&msg.erab_failed_list))
            ));
        }
        successful(
            6,
            g::SuccessfulOutcomeValue::Id_E_RABModify(g::E_RABModifyResponse {
                protocol_i_es: g::E_RABModifyResponseProtocolIEs(ies),
            }),
        )
    }

    pub fn build_erab_release_response(msg: &ErabReleaseResponse) -> S1apResult<Vec<u8>> {
        use g::E_RABReleaseResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                E_RABReleaseResponseProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                E_RABReleaseResponseProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
        ];
        if !msg.erab_release_list.is_empty() {
            ies.push(ie!(
                E_RABReleaseResponseProtocolIEs_Entry,
                69,
                IGNORE,
                V::Id_E_RABReleaseListBearerRelComp(g::E_RABReleaseListBearerRelComp(
                    msg.erab_release_list
                        .iter()
                        .map(|id| g::E_RABReleaseListBearerRelComp_Entry {
                            id: g::ProtocolIE_ID(15),
                            criticality: g::Criticality(IGNORE),
                            value: g::E_RABReleaseListBearerRelComp_EntryValue::Id_E_RABReleaseItemBearerRelComp(
                                g::E_RABReleaseItemBearerRelComp {
                                    e_rab_id: g::E_RAB_ID(*id),
                                    ie_extensions: None,
                                },
                            ),
                        })
                        .collect(),
                ))
            ));
        }
        if !msg.erab_failed_list.is_empty() {
            ies.push(ie!(
                E_RABReleaseResponseProtocolIEs_Entry,
                34,
                IGNORE,
                V::Id_E_RABFailedToReleaseList(failed_list_g(&msg.erab_failed_list))
            ));
        }
        successful(
            7,
            g::SuccessfulOutcomeValue::Id_E_RABRelease(g::E_RABReleaseResponse {
                protocol_i_es: g::E_RABReleaseResponseProtocolIEs(ies),
            }),
        )
    }

    fn connection_items(
        items: &[UeAssociatedLogicalS1Connection],
    ) -> impl Iterator<Item = g::UE_associatedLogicalS1_ConnectionItem> + '_ {
        items
            .iter()
            .map(|c| g::UE_associatedLogicalS1_ConnectionItem {
                mme_ue_s1ap_id: c.mme_ue_s1ap_id.map(g::MME_UE_S1AP_ID),
                enb_ue_s1ap_id: c.enb_ue_s1ap_id.map(g::ENB_UE_S1AP_ID),
                ie_extensions: None,
            })
    }

    pub fn build_reset(msg: &Reset) -> S1apResult<Vec<u8>> {
        use g::ResetProtocolIEs_EntryValue as V;
        let reset_type = match &msg.reset_type {
            ResetType::S1Interface => g::ResetType::S1_Interface(g::ResetAll(0)),
            ResetType::PartOfS1Interface(items) => g::ResetType::PartOfS1_Interface(
                g::UE_associatedLogicalS1_ConnectionListRes(
                    connection_items(items)
                        .map(|item| g::UE_associatedLogicalS1_ConnectionListRes_Entry {
                            id: g::ProtocolIE_ID(91),
                            criticality: g::Criticality(REJECT),
                            value: g::UE_associatedLogicalS1_ConnectionListRes_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(item),
                        })
                        .collect(),
                ),
            ),
        };
        let ies = vec![
            ie!(
                ResetProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
            ie!(
                ResetProtocolIEs_Entry,
                92,
                REJECT,
                V::Id_ResetType(reset_type)
            ),
        ];
        initiating(
            14,
            REJECT,
            g::InitiatingMessageValue::Id_Reset(g::Reset {
                protocol_i_es: g::ResetProtocolIEs(ies),
            }),
        )
    }

    pub fn build_handover_required(msg: &HandoverRequired) -> S1apResult<Vec<u8>> {
        use g::HandoverRequiredProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                HandoverRequiredProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                HandoverRequiredProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                HandoverRequiredProtocolIEs_Entry,
                1,
                REJECT,
                V::Id_HandoverType(handover_type_to(msg.handover_type))
            ),
            ie!(
                HandoverRequiredProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
            ie!(
                HandoverRequiredProtocolIEs_Entry,
                4,
                REJECT,
                V::Id_TargetID(target_id_g(&msg.target_id))
            ),
        ];
        if msg.direct_forwarding_path_availability.is_some() {
            ies.push(ie!(
                HandoverRequiredProtocolIEs_Entry,
                79,
                IGNORE,
                V::Id_Direct_Forwarding_Path_Availability(g::Direct_Forwarding_Path_Availability(
                    0
                ))
            ));
        }
        ies.push(ie!(
            HandoverRequiredProtocolIEs_Entry,
            104,
            REJECT,
            V::Id_Source_ToTarget_TransparentContainer(g::Source_ToTarget_TransparentContainer(
                msg.source_to_target_container.clone()
            ))
        ));
        initiating(
            0,
            REJECT,
            g::InitiatingMessageValue::Id_HandoverPreparation(g::HandoverRequired {
                protocol_i_es: g::HandoverRequiredProtocolIEs(ies),
            }),
        )
    }

    pub fn build_handover_request_acknowledge(
        msg: &HandoverRequestAcknowledge,
    ) -> S1apResult<Vec<u8>> {
        use g::HandoverRequestAcknowledgeProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                HandoverRequestAcknowledgeProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                HandoverRequestAcknowledgeProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                HandoverRequestAcknowledgeProtocolIEs_Entry,
                18,
                IGNORE,
                V::Id_E_RABAdmittedList(g::E_RABAdmittedList(
                    msg.erab_admitted_list
                        .iter()
                        .map(|i| g::E_RABAdmittedList_Entry {
                            id: g::ProtocolIE_ID(20),
                            criticality: g::Criticality(IGNORE),
                            value: g::E_RABAdmittedList_EntryValue::Id_E_RABAdmittedItem(
                                g::E_RABAdmittedItem {
                                    e_rab_id: g::E_RAB_ID(i.erab_id),
                                    transport_layer_address: transport(&i.transport_layer_address),
                                    gtp_teid: gtp_teid(i.gtp_teid),
                                    dl_transport_layer_address: i
                                        .dl_transport_layer_address
                                        .as_deref()
                                        .map(transport),
                                    dl_g_tp_teid: i.dl_gtp_teid.map(gtp_teid),
                                    ul_transport_layer_address: i
                                        .ul_transport_layer_address
                                        .as_deref()
                                        .map(transport),
                                    ul_gtp_teid: i.ul_gtp_teid.map(gtp_teid),
                                    ie_extensions: None,
                                },
                            ),
                        })
                        .collect(),
                ))
            ),
        ];
        if !msg.erab_failed_list.is_empty() {
            ies.push(ie!(
                HandoverRequestAcknowledgeProtocolIEs_Entry,
                19,
                IGNORE,
                V::Id_E_RABFailedToSetupListHOReqAck(g::E_RABFailedtoSetupListHOReqAck(
                    msg.erab_failed_list
                        .iter()
                        .map(|i| g::E_RABFailedtoSetupListHOReqAck_Entry {
                            id: g::ProtocolIE_ID(21),
                            criticality: g::Criticality(IGNORE),
                            value: g::E_RABFailedtoSetupListHOReqAck_EntryValue::Id_E_RABFailedtoSetupItemHOReqAck(
                                g::E_RABFailedToSetupItemHOReqAck {
                                    e_rab_id: g::E_RAB_ID(i.erab_id),
                                    cause: generated_cause(i.cause),
                                    ie_extensions: None,
                                },
                            ),
                        })
                        .collect(),
                ))
            ));
        }
        ies.push(ie!(
            HandoverRequestAcknowledgeProtocolIEs_Entry,
            123,
            REJECT,
            V::Id_Target_ToSource_TransparentContainer(g::Target_ToSource_TransparentContainer(
                msg.target_to_source_container.clone()
            ))
        ));
        successful(
            1,
            g::SuccessfulOutcomeValue::Id_HandoverResourceAllocation(
                g::HandoverRequestAcknowledge {
                    protocol_i_es: g::HandoverRequestAcknowledgeProtocolIEs(ies),
                },
            ),
        )
    }

    pub fn build_handover_failure(msg: &HandoverFailure) -> S1apResult<Vec<u8>> {
        use g::HandoverFailureProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                HandoverFailureProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                HandoverFailureProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        unsuccessful(
            1,
            g::UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(g::HandoverFailure {
                protocol_i_es: g::HandoverFailureProtocolIEs(ies),
            }),
        )
    }

    pub fn build_handover_notify(msg: &HandoverNotify) -> S1apResult<Vec<u8>> {
        use g::HandoverNotifyProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                HandoverNotifyProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                HandoverNotifyProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                HandoverNotifyProtocolIEs_Entry,
                100,
                IGNORE,
                V::Id_EUTRAN_CGI(cgi_g(&msg.eutran_cgi))
            ),
            ie!(
                HandoverNotifyProtocolIEs_Entry,
                67,
                IGNORE,
                V::Id_TAI(tai_g(&msg.tai))
            ),
        ];
        initiating(
            2,
            IGNORE,
            g::InitiatingMessageValue::Id_HandoverNotification(g::HandoverNotify {
                protocol_i_es: g::HandoverNotifyProtocolIEs(ies),
            }),
        )
    }

    pub fn build_handover_cancel(msg: &HandoverCancel) -> S1apResult<Vec<u8>> {
        use g::HandoverCancelProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                HandoverCancelProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                HandoverCancelProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                HandoverCancelProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        initiating(
            4,
            REJECT,
            g::InitiatingMessageValue::Id_HandoverCancel(g::HandoverCancel {
                protocol_i_es: g::HandoverCancelProtocolIEs(ies),
            }),
        )
    }

    pub fn build_enb_status_transfer(msg: &EnbStatusTransfer) -> S1apResult<Vec<u8>> {
        use g::ENBStatusTransferProtocolIEs_EntryValue as V;
        let container = status_container_from(&msg.status_transfer_container).map_err(asn)?;
        let ies = vec![
            ie!(
                ENBStatusTransferProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                ENBStatusTransferProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                ENBStatusTransferProtocolIEs_Entry,
                90,
                REJECT,
                V::Id_eNB_StatusTransfer_TransparentContainer(container)
            ),
        ];
        initiating(
            24,
            IGNORE,
            g::InitiatingMessageValue::Id_eNBStatusTransfer(g::ENBStatusTransfer {
                protocol_i_es: g::ENBStatusTransferProtocolIEs(ies),
            }),
        )
    }

    pub fn build_path_switch_request(msg: &PathSwitchRequest) -> S1apResult<Vec<u8>> {
        use g::PathSwitchRequestProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                22,
                REJECT,
                V::Id_E_RABToBeSwitchedDLList(g::E_RABToBeSwitchedDLList(
                    msg.erab_switched_dl_list
                        .iter()
                        .map(|i| g::E_RABToBeSwitchedDLList_Entry {
                            id: g::ProtocolIE_ID(23),
                            criticality: g::Criticality(REJECT),
                            value:
                                g::E_RABToBeSwitchedDLList_EntryValue::Id_E_RABToBeSwitchedDLItem(
                                    g::E_RABToBeSwitchedDLItem {
                                        e_rab_id: g::E_RAB_ID(i.erab_id),
                                        transport_layer_address: transport(
                                            &i.transport_layer_address
                                        ),
                                        gtp_teid: gtp_teid(i.gtp_teid),
                                        ie_extensions: None,
                                    },
                                ),
                        })
                        .collect(),
                ))
            ),
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                88,
                REJECT,
                V::Id_SourceMME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.source_mme_ue_s1ap_id))
            ),
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                100,
                IGNORE,
                V::Id_EUTRAN_CGI(cgi_g(&msg.eutran_cgi))
            ),
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                67,
                IGNORE,
                V::Id_TAI(tai_g(&msg.tai))
            ),
            ie!(
                PathSwitchRequestProtocolIEs_Entry,
                107,
                IGNORE,
                V::Id_UESecurityCapabilities(caps_g(&msg.ue_security_capabilities))
            ),
        ];
        initiating(
            3,
            REJECT,
            g::InitiatingMessageValue::Id_PathSwitchRequest(g::PathSwitchRequest {
                protocol_i_es: g::PathSwitchRequestProtocolIEs(ies),
            }),
        )
    }

    pub fn build_enb_configuration_update(msg: &EnbConfigurationUpdate) -> S1apResult<Vec<u8>> {
        use g::ENBConfigurationUpdateProtocolIEs_EntryValue as V;
        let mut ies = Vec::new();
        if let Some(name) = &msg.enb_name {
            ies.push(ie!(
                ENBConfigurationUpdateProtocolIEs_Entry,
                60,
                IGNORE,
                V::Id_eNBname(g::ENBname(name.clone()))
            ));
        }
        if let Some(tas) = &msg.supported_tas {
            ies.push(ie!(
                ENBConfigurationUpdateProtocolIEs_Entry,
                64,
                REJECT,
                V::Id_SupportedTAs(supported_tas_g(tas))
            ));
        }
        if let Some(drx) = msg.default_paging_drx {
            ies.push(ie!(
                ENBConfigurationUpdateProtocolIEs_Entry,
                137,
                IGNORE,
                V::Id_DefaultPagingDRX(g::PagingDRX(drx as u8))
            ));
        }
        initiating(
            29,
            REJECT,
            g::InitiatingMessageValue::Id_ENBConfigurationUpdate(g::ENBConfigurationUpdate {
                protocol_i_es: g::ENBConfigurationUpdateProtocolIEs(ies),
            }),
        )
    }

    pub fn build_mme_configuration_update_acknowledge(
        msg: &MmeConfigurationUpdateAcknowledge,
    ) -> S1apResult<Vec<u8>> {
        use g::MMEConfigurationUpdateAcknowledgeProtocolIEs_EntryValue as V;
        let mut ies = Vec::new();
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                MMEConfigurationUpdateAcknowledgeProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        successful(
            30,
            g::SuccessfulOutcomeValue::Id_MMEConfigurationUpdate(
                g::MMEConfigurationUpdateAcknowledge {
                    protocol_i_es: g::MMEConfigurationUpdateAcknowledgeProtocolIEs(ies),
                },
            ),
        )
    }

    pub fn build_mme_configuration_update_failure(
        msg: &MmeConfigurationUpdateFailure,
    ) -> S1apResult<Vec<u8>> {
        use g::MMEConfigurationUpdateFailureProtocolIEs_EntryValue as V;
        let mut ies = vec![ie!(
            MMEConfigurationUpdateFailureProtocolIEs_Entry,
            2,
            IGNORE,
            V::Id_Cause(generated_cause(msg.cause))
        )];
        if let Some(t) = msg.time_to_wait {
            ies.push(ie!(
                MMEConfigurationUpdateFailureProtocolIEs_Entry,
                65,
                IGNORE,
                V::Id_TimeToWait(g::TimeToWait(t as u8))
            ));
        }
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                MMEConfigurationUpdateFailureProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        unsuccessful(
            30,
            g::UnsuccessfulOutcomeValue::Id_MMEConfigurationUpdate(
                g::MMEConfigurationUpdateFailure {
                    protocol_i_es: g::MMEConfigurationUpdateFailureProtocolIEs(ies),
                },
            ),
        )
    }

    pub fn build_ue_context_modification_response(
        msg: &UeContextModificationResponse,
    ) -> S1apResult<Vec<u8>> {
        use g::UEContextModificationResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                UEContextModificationResponseProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UEContextModificationResponseProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
        ];
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                UEContextModificationResponseProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        successful(
            21,
            g::SuccessfulOutcomeValue::Id_UEContextModification(g::UEContextModificationResponse {
                protocol_i_es: g::UEContextModificationResponseProtocolIEs(ies),
            }),
        )
    }

    pub fn build_ue_context_modification_failure(
        msg: &UeContextModificationFailure,
    ) -> S1apResult<Vec<u8>> {
        use g::UEContextModificationFailureProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                UEContextModificationFailureProtocolIEs_Entry,
                0,
                IGNORE,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UEContextModificationFailureProtocolIEs_Entry,
                8,
                IGNORE,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                UEContextModificationFailureProtocolIEs_Entry,
                2,
                IGNORE,
                V::Id_Cause(generated_cause(msg.cause))
            ),
        ];
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                UEContextModificationFailureProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        unsuccessful(
            21,
            g::UnsuccessfulOutcomeValue::Id_UEContextModification(
                g::UEContextModificationFailure {
                    protocol_i_es: g::UEContextModificationFailureProtocolIEs(ies),
                },
            ),
        )
    }

    pub fn build_ue_capability_info_indication(
        msg: &UeCapabilityInfoIndication,
    ) -> S1apResult<Vec<u8>> {
        use g::UECapabilityInfoIndicationProtocolIEs_EntryValue as V;
        let ies = vec![
            ie!(
                UECapabilityInfoIndicationProtocolIEs_Entry,
                0,
                REJECT,
                V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id))
            ),
            ie!(
                UECapabilityInfoIndicationProtocolIEs_Entry,
                8,
                REJECT,
                V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id))
            ),
            ie!(
                UECapabilityInfoIndicationProtocolIEs_Entry,
                74,
                IGNORE,
                V::Id_UERadioCapability(g::UERadioCapability(msg.ue_radio_capability.clone()))
            ),
        ];
        initiating(
            22,
            IGNORE,
            g::InitiatingMessageValue::Id_UECapabilityInfoIndication(
                g::UECapabilityInfoIndication {
                    protocol_i_es: g::UECapabilityInfoIndicationProtocolIEs(ies),
                },
            ),
        )
    }

    pub fn build_write_replace_warning_response(
        msg: &WriteReplaceWarningResponse,
    ) -> S1apResult<Vec<u8>> {
        use g::WriteReplaceWarningResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                WriteReplaceWarningResponseProtocolIEs_Entry,
                111,
                REJECT,
                V::Id_MessageIdentifier(g::MessageIdentifier(bits16(msg.message_identifier)))
            ),
            ie!(
                WriteReplaceWarningResponseProtocolIEs_Entry,
                112,
                REJECT,
                V::Id_SerialNumber(g::SerialNumber(bits16(msg.serial_number)))
            ),
        ];
        if let Some(a) = &msg.broadcast_completed_area {
            ies.push(ie!(
                WriteReplaceWarningResponseProtocolIEs_Entry,
                120,
                IGNORE,
                V::Id_BroadcastCompletedAreaList(completed_area_g(a))
            ));
        }
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                WriteReplaceWarningResponseProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        successful(
            36,
            g::SuccessfulOutcomeValue::Id_WriteReplaceWarning(g::WriteReplaceWarningResponse {
                protocol_i_es: g::WriteReplaceWarningResponseProtocolIEs(ies),
            }),
        )
    }

    pub fn build_kill_response(msg: &KillResponse) -> S1apResult<Vec<u8>> {
        use g::KillResponseProtocolIEs_EntryValue as V;
        let mut ies = vec![
            ie!(
                KillResponseProtocolIEs_Entry,
                111,
                REJECT,
                V::Id_MessageIdentifier(g::MessageIdentifier(bits16(msg.message_identifier)))
            ),
            ie!(
                KillResponseProtocolIEs_Entry,
                112,
                REJECT,
                V::Id_SerialNumber(g::SerialNumber(bits16(msg.serial_number)))
            ),
        ];
        if let Some(a) = &msg.broadcast_cancelled_area {
            ies.push(ie!(
                KillResponseProtocolIEs_Entry,
                141,
                IGNORE,
                V::Id_BroadcastCancelledAreaList(cancelled_area_g(a))
            ));
        }
        if let Some(d) = &msg.criticality_diagnostics {
            ies.push(ie!(
                KillResponseProtocolIEs_Entry,
                58,
                IGNORE,
                V::Id_CriticalityDiagnostics(diagnostics_from(d))
            ));
        }
        successful(
            43,
            g::SuccessfulOutcomeValue::Id_Kill(g::KillResponse {
                protocol_i_es: g::KillResponseProtocolIEs(ies),
            }),
        )
    }
}

// ----------------------------------------------------------------------------
// generated -> domain
// ----------------------------------------------------------------------------

use nextgcore_s1ap::{
    CnDomain, CsFallbackIndicator, DirectForwardingPathAvailability, ResetType, SecurityContext,
    ServedGummeiItem, UePagingId, UeS1apIds,
};

fn tai_d(v: &g::TAI) -> S1apResult<Tai> {
    tai_from(v).ok_or_else(|| bad("TAI"))
}

fn cgi_d(v: &g::EUTRAN_CGI) -> S1apResult<EutranCgi> {
    cgi_from(v).ok_or_else(|| bad("EUTRAN-CGI"))
}

fn cause_d(c: &g::Cause) -> S1apResult<Cause> {
    domain_cause(c).ok_or_else(|| bad("Cause"))
}

fn teid_d(t: &g::GTP_TEID) -> S1apResult<u32> {
    teid(&t.0).ok_or_else(|| bad("GTP-TEID"))
}

fn tla_d(t: &g::TransportLayerAddress) -> Vec<u8> {
    bits_to_bytes(&t.0)
}

fn caps_d(c: &g::UESecurityCapabilities) -> S1apResult<nextgcore_s1ap::UeSecurityCapabilities> {
    Ok(nextgcore_s1ap::UeSecurityCapabilities {
        encryption_algorithms: u16_bits(&c.encryption_algorithms.0)
            .ok_or_else(|| bad("EncryptionAlgorithms"))?,
        integrity_algorithms: u16_bits(&c.integrity_protection_algorithms.0)
            .ok_or_else(|| bad("IntegrityProtectionAlgorithms"))?,
    })
}

fn ambr_d(a: &g::UEAggregateMaximumBitrate) -> nextgcore_s1ap::UeAmbr {
    nextgcore_s1ap::UeAmbr {
        dl: a.u_eaggregate_maximum_bit_rate_dl.0,
        ul: a.u_eaggregate_maximum_bit_rate_ul.0,
    }
}

fn qos_d(q: &g::E_RABLevelQoSParameters) -> nextgcore_s1ap::ErabLevelQosParameters {
    nextgcore_s1ap::ErabLevelQosParameters {
        qci: q.qci.0,
        arp: nextgcore_s1ap::AllocationRetentionPriority {
            priority_level: q.allocation_retention_priority.priority_level.0,
            pre_emption_capability: q.allocation_retention_priority.pre_emption_capability.0 != 0,
            pre_emption_vulnerability: q.allocation_retention_priority.pre_emption_vulnerability.0
                != 0,
        },
        gbr_qos_info: q
            .gbr_qos_information
            .as_ref()
            .map(|gbr| nextgcore_s1ap::GbrQosInformation {
                erab_max_bitrate_dl: gbr.e_rab_maximum_bitrate_dl.0,
                erab_max_bitrate_ul: gbr.e_rab_maximum_bitrate_ul.0,
                erab_guaranteed_bitrate_dl: gbr.e_rab_guaranteed_bitrate_dl.0,
                erab_guaranteed_bitrate_ul: gbr.e_rab_guaranteed_bitrate_ul.0,
            }),
    }
}

fn key_d(k: &g::SecurityKey) -> S1apResult<[u8; 32]> {
    bits_to_bytes(&k.0)
        .try_into()
        .map_err(|_| bad("SecurityKey"))
}

fn erab_items_d(l: &g::E_RABList) -> S1apResult<Vec<nextgcore_s1ap::ErabItem>> {
    l.0.iter()
        .map(|e| {
            let g::E_RABList_EntryValue::Id_E_RABItem(i) = &e.value;
            Ok(nextgcore_s1ap::ErabItem {
                erab_id: i.e_rab_id.0,
                cause: cause_d(&i.cause)?,
            })
        })
        .collect()
}

fn failed_d(l: &g::E_RABList) -> S1apResult<Vec<nextgcore_s1ap::ErabFailedItem>> {
    Ok(erab_items_d(l)?
        .into_iter()
        .map(|i| nextgcore_s1ap::ErabFailedItem {
            erab_id: i.erab_id,
            cause: i.cause,
        })
        .collect())
}

fn connections_d(
    items: impl Iterator<Item = g::UE_associatedLogicalS1_ConnectionItem>,
) -> Vec<nextgcore_s1ap::UeAssociatedLogicalS1Connection> {
    items
        .map(|c| nextgcore_s1ap::UeAssociatedLogicalS1Connection {
            mme_ue_s1ap_id: c.mme_ue_s1ap_id.map(|v| v.0),
            enb_ue_s1ap_id: c.enb_ue_s1ap_id.map(|v| v.0),
        })
        .collect()
}

fn gummeis_d(v: &g::ServedGUMMEIs) -> Vec<ServedGummeiItem> {
    v.0.iter()
        .map(|s| ServedGummeiItem {
            served_plmns: s
                .served_plm_ns
                .0
                .iter()
                .filter_map(|p| plmn(&p.0))
                .collect(),
            served_group_ids: s
                .served_group_i_ds
                .0
                .iter()
                .filter_map(|g| u16_from(&g.0))
                .collect(),
            served_mmec_codes: s
                .served_mme_cs
                .0
                .iter()
                .filter_map(|c| c.0.first().copied())
                .collect(),
        })
        .collect()
}

fn warning_area_d(a: &g::WarningAreaList) -> S1apResult<nextgcore_s1ap::WarningAreaList> {
    use nextgcore_s1ap::WarningAreaList as W;
    Ok(match a {
        g::WarningAreaList::CellIDList(l) => {
            W::CellIdList(l.0.iter().map(cgi_d).collect::<S1apResult<_>>()?)
        }
        g::WarningAreaList::TrackingAreaListforWarning(l) => {
            W::TrackingAreaListForWarning(l.0.iter().map(tai_d).collect::<S1apResult<_>>()?)
        }
        g::WarningAreaList::EmergencyAreaIDList(l) => W::EmergencyAreaIdList(
            l.0.iter()
                .map(|e| eai(e).ok_or_else(|| bad("EmergencyAreaID")))
                .collect::<S1apResult<_>>()?,
        ),
    })
}

fn opt_diag(
    d: Option<g::CriticalityDiagnostics>,
) -> Option<nextgcore_s1ap::CriticalityDiagnostics> {
    d.as_ref().map(hand_written_diagnostics)
}

fn ttw_d(t: Option<g::TimeToWait>) -> Option<TimeToWait> {
    t.and_then(|t| time_to_wait_from(t.0))
}

fn handover_type_d(t: &g::HandoverType) -> S1apResult<nextgcore_s1ap::HandoverType> {
    handover_type_from(t.0).ok_or_else(|| bad("HandoverType"))
}

fn overload_action_d(v: u8) -> S1apResult<nextgcore_s1ap::OverloadAction> {
    use nextgcore_s1ap::OverloadAction as A;
    Ok(match v {
        0 => A::RejectNonEmergencyMoDt,
        1 => A::RejectRrcCrSignalling,
        2 => A::PermitEmergencySessionsAndMtOnly,
        3 => A::PermitHighPrioritySessionsAndMtOnly,
        4 => A::RejectDelayTolerantAccess,
        5 => A::PermitHighPrioritySessionsAndExceptionReportingAndMtOnly,
        6 => A::NotAcceptMoDataOrDelayTolerantAccessFromCpCiot,
        _ => return Err(bad("OverloadAction")),
    })
}

fn req<T>(v: Option<T>, name: &'static str) -> S1apResult<T> {
    v.ok_or_else(|| missing_ie(name))
}

/// Decode any S1AP PDU into mmed's domain `S1apMessage`, as the deleted
/// hand-written parser did, but through the generated codec.
pub fn decode_s1ap_pdu(bytes: &[u8]) -> S1apResult<S1apMessage> {
    let pdu = nextgcore_s1ap_gen::decode(bytes).map_err(asn)?;
    match pdu {
        g::S1AP_PDU::InitiatingMessage(m) => initiating_d(m.value),
        g::S1AP_PDU::SuccessfulOutcome(m) => successful_d(m.value),
        g::S1AP_PDU::UnsuccessfulOutcome(m) => unsuccessful_d(m.value),
    }
}

/// Collect the MME/eNB UE S1AP IDs, Cause, NAS-PDU and Criticality
/// Diagnostics of a message's IEs: the fields most messages share.
#[derive(Default)]
struct Common {
    mme: Option<u32>,
    enb: Option<u32>,
    cause: Option<Cause>,
    nas: Option<Vec<u8>>,
    diag: Option<g::CriticalityDiagnostics>,
    ttw: Option<g::TimeToWait>,
}

macro_rules! common_ie {
    ($c:ident, $v:expr, $V:ident, { $($arm:tt)* }) => {
        #[allow(unreachable_patterns)]
        match $v {
            $V::Id_MME_UE_S1AP_ID(x) => $c.mme = Some(x.0),
            $V::Id_eNB_UE_S1AP_ID(x) => $c.enb = Some(x.0),
            $($arm)*
            _ => {}
        }
    };
}

fn initiating_d(v: g::InitiatingMessageValue) -> S1apResult<S1apMessage> {
    use g::InitiatingMessageValue as I;
    use nextgcore_s1ap as d;
    Ok(match v {
        I::Id_S1Setup(m) => {
            use g::S1SetupRequestProtocolIEs_EntryValue as V;
            let (mut id, mut name, mut tas, mut drx) = (None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_Global_ENB_ID(g) => id = Some(g),
                    V::Id_eNBname(n) => name = Some(n.0),
                    V::Id_SupportedTAs(t) => tas = Some(supported_tas_from(t)),
                    V::Id_DefaultPagingDRX(p) => drx = Some(paging_drx_from(&p)),
                    _ => {}
                }
            }
            let id = req(id, "Global-ENB-ID")?;
            let enb_id = match &id.enb_id {
                g::ENB_ID::MacroENB_ID(b) => EnbId::Macro(bits_to_u32(&b.0)),
                g::ENB_ID::HomeENB_ID(b) => EnbId::Home(bits_to_u32(&b.0)),
                g::ENB_ID::Short_macroENB_ID(b) => EnbId::ShortMacro(bits_to_u32(&b.0)),
                g::ENB_ID::Long_macroENB_ID(b) => EnbId::LongMacro(bits_to_u32(&b.0)),
            };
            S1apMessage::S1SetupRequest(d::S1SetupRequest {
                global_enb_id: GlobalEnbId {
                    plmn_identity: plmn(&id.plm_nidentity.0).ok_or_else(|| bad("PLMN"))?,
                    enb_id,
                },
                enb_name: name,
                supported_tas: req(tas, "SupportedTAs")?,
                default_paging_drx: req(drx, "DefaultPagingDRX")?,
            })
        }
        I::Id_initialUEMessage(m) => {
            use g::InitialUEMessageProtocolIEs_EntryValue as V;
            let (mut enb, mut nas, mut tai, mut cgi, mut rrc, mut stmsi) =
                (None, None, None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_eNB_UE_S1AP_ID(x) => enb = Some(x.0),
                    V::Id_NAS_PDU(x) => nas = Some(x.0),
                    V::Id_TAI(x) => tai = Some(tai_d(&x)?),
                    V::Id_EUTRAN_CGI(x) => cgi = Some(cgi_d(&x)?),
                    V::Id_RRC_Establishment_Cause(x) => rrc = Some(rrc_cause_from(x.0)),
                    V::Id_S_TMSI(s) => {
                        stmsi = Some(STmsi {
                            mmec: s.mmec.0.first().copied().ok_or_else(|| bad("MMEC"))?,
                            m_tmsi: teid(&s.m_tmsi.0).ok_or_else(|| bad("M-TMSI"))?,
                        })
                    }
                    _ => {}
                }
            }
            S1apMessage::InitialUeMessage(d::InitialUeMessage {
                enb_ue_s1ap_id: req(enb, "eNB-UE-S1AP-ID")?,
                nas_pdu: req(nas, "NAS-PDU")?,
                tai: req(tai, "TAI")?,
                eutran_cgi: req(cgi, "EUTRAN-CGI")?,
                rrc_establishment_cause: req(rrc, "RRC-Establishment-Cause")?,
                s_tmsi: stmsi,
            })
        }
        I::Id_downlinkNASTransport(m) => {
            use g::DownlinkNASTransportProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_NAS_PDU(x) => c.nas = Some(x.0), });
            }
            S1apMessage::DownlinkNasTransport(d::DlNasTransport {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                nas_pdu: req(c.nas, "NAS-PDU")?,
            })
        }
        I::Id_uplinkNASTransport(m) => {
            use g::UplinkNASTransportProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut tai, mut cgi) = (None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_NAS_PDU(x) => c.nas = Some(x.0),
                    V::Id_TAI(x) => tai = Some(tai_d(&x)?),
                    V::Id_EUTRAN_CGI(x) => cgi = Some(cgi_d(&x)?),
                });
            }
            S1apMessage::UplinkNasTransport(d::UlNasTransport {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                nas_pdu: req(c.nas, "NAS-PDU")?,
                eutran_cgi: req(cgi, "EUTRAN-CGI")?,
                tai: req(tai, "TAI")?,
            })
        }
        I::Id_NASNonDeliveryIndication(m) => {
            use g::NASNonDeliveryIndicationProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_NAS_PDU(x) => c.nas = Some(x.0),
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                });
            }
            S1apMessage::NasNonDeliveryIndication(d::NasNonDeliveryIndication {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                nas_pdu: req(c.nas, "NAS-PDU")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        I::Id_InitialContextSetup(m) => {
            use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ambr, mut erabs, mut caps, mut key) = (None, None, None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_E_RABToBeSetupListCtxtSUReq(l) => {
                        let mut v = Vec::new();
                        for e in l.0 {
                            let g::E_RABToBeSetupListCtxtSUReq_EntryValue::Id_E_RABToBeSetupItemCtxtSUReq(i) = e.value;
                            v.push(d::ErabToBeSetupItem {
                                erab_id: i.e_rab_id.0,
                                erab_qos: qos_d(&i.e_ra_blevel_qo_s_parameters),
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                                nas_pdu: i.nas_pdu.map(|n| n.0),
                            });
                        }
                        erabs = Some(v);
                    }
                    V::Id_UESecurityCapabilities(x) => caps = Some(caps_d(&x)?),
                    V::Id_SecurityKey(k) => key = Some(key_d(&k)?),
                });
            }
            S1apMessage::InitialContextSetupRequest(d::InitialContextSetupRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                ue_ambr: req(ambr, "UEAggregateMaximumBitrate")?,
                erab_list: req(erabs, "E-RABToBeSetupListCtxtSUReq")?,
                ue_security_capabilities: req(caps, "UESecurityCapabilities")?,
                security_key: req(key, "SecurityKey")?,
            })
        }
        I::Id_UEContextReleaseRequest(m) => {
            use g::UEContextReleaseRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_Cause(x) => c.cause = Some(cause_d(&x)?), });
            }
            S1apMessage::UeContextReleaseRequest(d::UeContextReleaseRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        I::Id_UEContextRelease(m) => {
            use g::UEContextReleaseCommandProtocolIEs_EntryValue as V;
            let (mut ids, mut cause) = (None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_UE_S1AP_IDs(x) => {
                        ids = Some(match x {
                            g::UE_S1AP_IDs::UE_S1AP_ID_pair(p) => UeS1apIds::Pair {
                                mme_ue_s1ap_id: p.mme_ue_s1ap_id.0,
                                enb_ue_s1ap_id: p.enb_ue_s1ap_id.0,
                            },
                            g::UE_S1AP_IDs::MME_UE_S1AP_ID(m) => UeS1apIds::MmeOnly {
                                mme_ue_s1ap_id: m.0,
                            },
                        })
                    }
                    V::Id_Cause(x) => cause = Some(cause_d(&x)?),
                }
            }
            S1apMessage::UeContextReleaseCommand(d::UeContextReleaseCommand {
                ue_s1ap_ids: req(ids, "UE-S1AP-IDs")?,
                cause: req(cause, "Cause")?,
            })
        }
        I::Id_E_RABSetup(m) => {
            use g::E_RABSetupRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ambr, mut erabs) = (None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_E_RABToBeSetupListBearerSUReq(l) => {
                        let mut v = Vec::new();
                        for e in l.0 {
                            let g::E_RABToBeSetupListBearerSUReq_EntryValue::Id_E_RABToBeSetupItemBearerSUReq(i) = e.value;
                            v.push(d::ErabToBeSetupItem {
                                erab_id: i.e_rab_id.0,
                                erab_qos: qos_d(&i.e_ra_blevel_qo_s_parameters),
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                                nas_pdu: Some(i.nas_pdu.0),
                            });
                        }
                        erabs = Some(v);
                    }
                });
            }
            S1apMessage::ErabSetupRequest(d::ErabSetupRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                ue_ambr: ambr,
                erab_list: req(erabs, "E-RABToBeSetupListBearerSUReq")?,
            })
        }
        I::Id_E_RABModify(m) => {
            use g::E_RABModifyRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ambr, mut erabs) = (None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_E_RABToBeModifiedListBearerModReq(l) => {
                        erabs = Some(
                            l.0.into_iter()
                                .map(|e| {
                                    let g::E_RABToBeModifiedListBearerModReq_EntryValue::Id_E_RABToBeModifiedItemBearerModReq(i) = e.value;
                                    d::ErabToBeModifiedItem {
                                        erab_id: i.e_rab_id.0,
                                        erab_qos: qos_d(&i.e_rab_level_qo_s_parameters),
                                        nas_pdu: i.nas_pdu.0,
                                    }
                                })
                                .collect(),
                        )
                    }
                });
            }
            S1apMessage::ErabModifyRequest(d::ErabModifyRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                ue_ambr: ambr,
                erab_list: req(erabs, "E-RABToBeModifiedListBearerModReq")?,
            })
        }
        I::Id_E_RABRelease(m) => {
            use g::E_RABReleaseCommandProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ambr, mut erabs) = (None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_E_RABToBeReleasedList(l) => erabs = Some(erab_items_d(&l)?),
                    V::Id_NAS_PDU(x) => c.nas = Some(x.0),
                });
            }
            S1apMessage::ErabReleaseCommand(d::ErabReleaseCommand {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                ue_ambr: ambr,
                erab_list: req(erabs, "E-RABToBeReleasedList")?,
                nas_pdu: c.nas,
            })
        }
        I::Id_Paging(m) => {
            use g::PagingProtocolIEs_EntryValue as V;
            let (mut index, mut id, mut drx, mut domain, mut tais) = (None, None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_UEIdentityIndexValue(x) => index = Some(bits_to_u32(&x.0) as u16),
                    V::Id_UEPagingID(x) => {
                        id = Some(match x {
                            g::UEPagingID::S_TMSI(s) => UePagingId::STmsi(STmsi {
                                mmec: s.mmec.0.first().copied().ok_or_else(|| bad("MMEC"))?,
                                m_tmsi: teid(&s.m_tmsi.0).ok_or_else(|| bad("M-TMSI"))?,
                            }),
                            g::UEPagingID::IMSI(i) => UePagingId::Imsi(i.0),
                        })
                    }
                    V::Id_pagingDRX(x) => drx = Some(paging_drx_from(&x)),
                    V::Id_CNDomain(x) => {
                        domain = Some(if x.0 == 1 { CnDomain::Cs } else { CnDomain::Ps })
                    }
                    V::Id_TAIList(l) => {
                        tais = Some(
                            l.0.iter()
                                .map(|e| {
                                    let g::TAIList_EntryValue::Id_TAIItem(t) = &e.value;
                                    tai_d(&t.tai)
                                })
                                .collect::<S1apResult<Vec<_>>>()?,
                        )
                    }
                    _ => {}
                }
            }
            S1apMessage::Paging(d::Paging {
                ue_identity_index: req(index, "UEIdentityIndexValue")?,
                ue_paging_id: req(id, "UEPagingID")?,
                paging_drx: drx,
                cn_domain: req(domain, "CNDomain")?,
                tai_list: req(tais, "TAIList")?,
            })
        }
        I::Id_Reset(m) => {
            use g::ResetProtocolIEs_EntryValue as V;
            let (mut cause, mut rt) = (None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_Cause(x) => cause = Some(cause_d(&x)?),
                    V::Id_ResetType(x) => {
                        rt = Some(match x {
                            g::ResetType::S1_Interface(_) => ResetType::S1Interface,
                            g::ResetType::PartOfS1_Interface(l) => {
                                ResetType::PartOfS1Interface(connections_d(l.0.into_iter().map(
                                    |e| {
                                        let g::UE_associatedLogicalS1_ConnectionListRes_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(i) = e.value;
                                        i
                                    },
                                )))
                            }
                        })
                    }
                }
            }
            S1apMessage::Reset(d::Reset {
                cause: req(cause, "Cause")?,
                reset_type: req(rt, "ResetType")?,
            })
        }
        I::Id_ErrorIndication(m) => {
            use g::ErrorIndicationProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_CriticalityDiagnostics(x) => c.diag = Some(x),
                });
            }
            S1apMessage::ErrorIndication(d::ErrorIndication {
                mme_ue_s1ap_id: c.mme,
                enb_ue_s1ap_id: c.enb,
                cause: c.cause,
                criticality_diagnostics: opt_diag(c.diag),
            })
        }
        I::Id_HandoverPreparation(m) => {
            use g::HandoverRequiredProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ht, mut target, mut dfpa, mut cont) = (None, None, None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_HandoverType(x) => ht = Some(handover_type_d(&x)?),
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_TargetID(x) => target = target_id_from(&x).map_err(|_| bad("TargetID"))?,
                    V::Id_Direct_Forwarding_Path_Availability(_) => {
                        dfpa = Some(DirectForwardingPathAvailability::DirectPathAvailable)
                    }
                    V::Id_Source_ToTarget_TransparentContainer(x) => cont = Some(x.0),
                });
            }
            S1apMessage::HandoverRequired(d::HandoverRequired {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                handover_type: req(ht, "HandoverType")?,
                cause: req(c.cause, "Cause")?,
                target_id: req(target, "TargetID")?,
                direct_forwarding_path_availability: dfpa,
                source_to_target_container: req(cont, "Source-ToTarget-TransparentContainer")?,
            })
        }
        I::Id_HandoverResourceAllocation(m) => {
            use g::HandoverRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ht, mut ambr, mut erabs, mut cont, mut caps, mut sc) =
                (None, None, None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MME_UE_S1AP_ID(x) => c.mme = Some(x.0),
                    V::Id_HandoverType(x) => ht = Some(handover_type_d(&x)?),
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_E_RABToBeSetupListHOReq(l) => {
                        let mut v = Vec::new();
                        for e in l.0 {
                            let g::E_RABToBeSetupListHOReq_EntryValue::Id_E_RABToBeSetupItemHOReq(
                                i,
                            ) = e.value;
                            v.push(d::ErabToBeSetupItemHoReq {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                                erab_qos: qos_d(&i.e_ra_blevel_qos_parameters),
                            });
                        }
                        erabs = Some(v);
                    }
                    V::Id_Source_ToTarget_TransparentContainer(x) => cont = Some(x.0),
                    V::Id_UESecurityCapabilities(x) => caps = Some(caps_d(&x)?),
                    V::Id_SecurityContext(s) => {
                        sc = Some(SecurityContext {
                            next_hop_chaining_count: s.next_hop_chaining_count.0,
                            next_hop_parameter: key_d(&s.next_hop_parameter)?,
                        })
                    }
                    _ => {}
                }
            }
            S1apMessage::HandoverRequest(d::HandoverRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                handover_type: req(ht, "HandoverType")?,
                cause: req(c.cause, "Cause")?,
                ue_ambr: req(ambr, "UEAggregateMaximumBitrate")?,
                erab_list: req(erabs, "E-RABToBeSetupListHOReq")?,
                source_to_target_container: req(cont, "Source-ToTarget-TransparentContainer")?,
                ue_security_capabilities: req(caps, "UESecurityCapabilities")?,
                security_context: req(sc, "SecurityContext")?,
            })
        }
        I::Id_HandoverNotification(m) => {
            use g::HandoverNotifyProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut tai, mut cgi) = (None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_TAI(x) => tai = Some(tai_d(&x)?),
                    V::Id_EUTRAN_CGI(x) => cgi = Some(cgi_d(&x)?),
                });
            }
            S1apMessage::HandoverNotify(d::HandoverNotify {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                eutran_cgi: req(cgi, "EUTRAN-CGI")?,
                tai: req(tai, "TAI")?,
            })
        }
        I::Id_PathSwitchRequest(m) => {
            use g::PathSwitchRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut erabs, mut src, mut cgi, mut tai, mut caps) = (None, None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_eNB_UE_S1AP_ID(x) => c.enb = Some(x.0),
                    V::Id_E_RABToBeSwitchedDLList(l) => {
                        let mut v = Vec::new();
                        for e in l.0 {
                            let g::E_RABToBeSwitchedDLList_EntryValue::Id_E_RABToBeSwitchedDLItem(
                                i,
                            ) = e.value;
                            v.push(d::ErabSwitchedItem {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                            });
                        }
                        erabs = Some(v);
                    }
                    V::Id_SourceMME_UE_S1AP_ID(x) => src = Some(x.0),
                    V::Id_EUTRAN_CGI(x) => cgi = Some(cgi_d(&x)?),
                    V::Id_TAI(x) => tai = Some(tai_d(&x)?),
                    V::Id_UESecurityCapabilities(x) => caps = Some(caps_d(&x)?),
                    _ => {}
                }
            }
            S1apMessage::PathSwitchRequest(d::PathSwitchRequest {
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_switched_dl_list: req(erabs, "E-RABToBeSwitchedDLList")?,
                source_mme_ue_s1ap_id: req(src, "SourceMME-UE-S1AP-ID")?,
                eutran_cgi: req(cgi, "EUTRAN-CGI")?,
                tai: req(tai, "TAI")?,
                ue_security_capabilities: req(caps, "UESecurityCapabilities")?,
            })
        }
        I::Id_HandoverCancel(m) => {
            use g::HandoverCancelProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_Cause(x) => c.cause = Some(cause_d(&x)?), });
            }
            S1apMessage::HandoverCancel(d::HandoverCancel {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        I::Id_eNBStatusTransfer(m) => {
            use g::ENBStatusTransferProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let mut cont = None;
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_eNB_StatusTransfer_TransparentContainer(x) => {
                        cont = Some(status_container_raw(&x).ok_or_else(|| bad("container"))?)
                    }
                });
            }
            S1apMessage::EnbStatusTransfer(d::EnbStatusTransfer {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                status_transfer_container: req(cont, "eNB-StatusTransfer-TransparentContainer")?,
            })
        }
        I::Id_MMEStatusTransfer(m) => {
            use g::MMEStatusTransferProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let mut cont = None;
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_eNB_StatusTransfer_TransparentContainer(x) => {
                        cont = Some(status_container_raw(&x).ok_or_else(|| bad("container"))?)
                    }
                });
            }
            S1apMessage::MmeStatusTransfer(d::MmeStatusTransfer {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                status_transfer_container: req(cont, "eNB-StatusTransfer-TransparentContainer")?,
            })
        }
        I::Id_ENBConfigurationUpdate(m) => {
            use g::ENBConfigurationUpdateProtocolIEs_EntryValue as V;
            let (mut name, mut tas, mut drx) = (None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_eNBname(n) => name = Some(n.0),
                    V::Id_SupportedTAs(t) => tas = Some(supported_tas_from(t)),
                    V::Id_DefaultPagingDRX(p) => drx = Some(paging_drx_from(&p)),
                    _ => {}
                }
            }
            S1apMessage::EnbConfigurationUpdate(d::EnbConfigurationUpdate {
                enb_name: name,
                supported_tas: tas,
                default_paging_drx: drx,
            })
        }
        I::Id_MMEConfigurationUpdate(m) => {
            use g::MMEConfigurationUpdateProtocolIEs_EntryValue as V;
            let (mut name, mut gummeis, mut cap) = (None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MMEname(n) => name = Some(n.0),
                    V::Id_ServedGUMMEIs(s) => gummeis = Some(gummeis_d(&s)),
                    V::Id_RelativeMMECapacity(c) => cap = Some(c.0),
                    _ => {}
                }
            }
            S1apMessage::MmeConfigurationUpdate(d::MmeConfigurationUpdate {
                mme_name: name,
                served_gummeis: gummeis,
                relative_mme_capacity: cap,
            })
        }
        I::Id_UEContextModification(m) => {
            use g::UEContextModificationRequestProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut key, mut spid, mut ambr, mut csfb, mut caps) = (None, None, None, None, None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_SecurityKey(k) => key = Some(key_d(&k)?),
                    V::Id_SubscriberProfileIDforRFP(x) => spid = Some(x.0),
                    V::Id_uEaggregateMaximumBitrate(a) => ambr = Some(ambr_d(&a)),
                    V::Id_CSFallbackIndicator(x) => {
                        csfb = Some(if x.0 == 1 {
                            CsFallbackIndicator::CsFallbackHighPriority
                        } else {
                            CsFallbackIndicator::CsFallbackRequired
                        })
                    }
                    V::Id_UESecurityCapabilities(x) => caps = Some(caps_d(&x)?),
                });
            }
            S1apMessage::UeContextModificationRequest(d::UeContextModificationRequest {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                security_key: key,
                subscriber_profile_id_for_rfp: spid,
                ue_ambr: ambr,
                cs_fallback_indicator: csfb,
                ue_security_capabilities: caps,
            })
        }
        I::Id_OverloadStart(m) => {
            use g::OverloadStartProtocolIEs_EntryValue as V;
            let mut action = None;
            for ie in m.protocol_i_es.0 {
                if let V::Id_OverloadResponse(g::OverloadResponse::OverloadAction(a)) = ie.value {
                    action = Some(overload_action_d(a.0)?);
                }
            }
            S1apMessage::OverloadStart(d::OverloadStart {
                overload_action: req(action, "OverloadResponse")?,
            })
        }
        I::Id_OverloadStop(_) => S1apMessage::OverloadStop(d::OverloadStop),
        I::Id_WriteReplaceWarning(m) => {
            use g::WriteReplaceWarningRequestProtocolIEs_EntryValue as V;
            let mut r = d::WriteReplaceWarningRequest {
                message_identifier: 0,
                serial_number: 0,
                warning_area: None,
                repetition_period: 0,
                number_of_broadcast_request: 0,
                warning_type: None,
                warning_security_info: None,
                data_coding_scheme: None,
                warning_message_contents: None,
                concurrent_warning_message_indicator: false,
            };
            let (mut id, mut serial) = (None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MessageIdentifier(x) => id = u16_bits(&x.0),
                    V::Id_SerialNumber(x) => serial = u16_bits(&x.0),
                    V::Id_WarningAreaList(x) => r.warning_area = Some(warning_area_d(&x)?),
                    V::Id_RepetitionPeriod(x) => r.repetition_period = x.0,
                    V::Id_NumberofBroadcastRequest(x) => r.number_of_broadcast_request = x.0,
                    V::Id_WarningType(x) => {
                        r.warning_type = Some(x.0.try_into().map_err(|_| bad("WarningType"))?)
                    }
                    V::Id_WarningSecurityInfo(x) => {
                        r.warning_security_info =
                            Some(x.0.try_into().map_err(|_| bad("WarningSecurityInfo"))?)
                    }
                    V::Id_DataCodingScheme(x) => {
                        r.data_coding_scheme = bits_to_bytes(&x.0).first().copied()
                    }
                    V::Id_WarningMessageContents(x) => r.warning_message_contents = Some(x.0),
                    V::Id_ConcurrentWarningMessageIndicator(_) => {
                        r.concurrent_warning_message_indicator = true
                    }
                    _ => {}
                }
            }
            r.message_identifier = req(id, "MessageIdentifier")?;
            r.serial_number = req(serial, "SerialNumber")?;
            S1apMessage::WriteReplaceWarningRequest(r)
        }
        I::Id_Kill(m) => {
            use g::KillRequestProtocolIEs_EntryValue as V;
            let (mut id, mut serial, mut area, mut all) = (None, None, None, false);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MessageIdentifier(x) => id = u16_bits(&x.0),
                    V::Id_SerialNumber(x) => serial = u16_bits(&x.0),
                    V::Id_WarningAreaList(x) => area = Some(warning_area_d(&x)?),
                    V::Id_KillAllWarningMessages(_) => all = true,
                }
            }
            S1apMessage::KillRequest(d::KillRequest {
                message_identifier: req(id, "MessageIdentifier")?,
                serial_number: req(serial, "SerialNumber")?,
                warning_area: area,
                kill_all_warning_messages: all,
            })
        }
        I::Id_UECapabilityInfoIndication(m) => {
            use g::UECapabilityInfoIndicationProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let mut cap = None;
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_UERadioCapability(x) => cap = Some(x.0), });
            }
            S1apMessage::UeCapabilityInfoIndication(d::UeCapabilityInfoIndication {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                ue_radio_capability: req(cap, "UERadioCapability")?,
            })
        }
        _ => S1apMessage::Unknown {
            procedure_code: 255,
            message_type: "InitiatingMessage",
        },
    })
}

fn successful_d(v: g::SuccessfulOutcomeValue) -> S1apResult<S1apMessage> {
    use g::SuccessfulOutcomeValue as S;
    use nextgcore_s1ap as d;
    Ok(match v {
        S::Id_S1Setup(m) => {
            use g::S1SetupResponseProtocolIEs_EntryValue as V;
            let (mut name, mut gummeis, mut cap) = (None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MMEname(n) => name = Some(n.0),
                    V::Id_ServedGUMMEIs(s) => gummeis = Some(gummeis_d(&s)),
                    V::Id_RelativeMMECapacity(c) => cap = Some(c.0),
                    _ => {}
                }
            }
            S1apMessage::S1SetupResponse(d::S1SetupResponse {
                mme_name: name,
                served_gummeis: req(gummeis, "ServedGUMMEIs")?,
                relative_mme_capacity: req(cap, "RelativeMMECapacity")?,
            })
        }
        S::Id_InitialContextSetup(m) => {
            use g::InitialContextSetupResponseProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut setup, mut failed) = (Vec::new(), Vec::new());
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABSetupListCtxtSURes(l) => {
                        for e in l.0 {
                            let g::E_RABSetupListCtxtSURes_EntryValue::Id_E_RABSetupItemCtxtSURes(i) = e.value;
                            setup.push(d::ErabSetupItem {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                            });
                        }
                    }
                    V::Id_E_RABFailedToSetupListCtxtSURes(l) => failed = failed_d(&l)?,
                });
            }
            S1apMessage::InitialContextSetupResponse(d::InitialContextSetupResponse {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_setup_list: setup,
                erab_failed_list: failed,
            })
        }
        S::Id_UEContextRelease(m) => {
            use g::UEContextReleaseCompleteProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {});
            }
            S1apMessage::UeContextReleaseComplete(d::UeContextReleaseComplete {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
            })
        }
        S::Id_E_RABSetup(m) => {
            use g::E_RABSetupResponseProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut setup, mut failed) = (Vec::new(), Vec::new());
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABSetupListBearerSURes(l) => {
                        for e in l.0 {
                            let g::E_RABSetupListBearerSURes_EntryValue::Id_E_RABSetupItemBearerSURes(i) = e.value;
                            setup.push(d::ErabSetupItem {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                            });
                        }
                    }
                    V::Id_E_RABFailedToSetupListBearerSURes(l) => failed = failed_d(&l)?,
                });
            }
            S1apMessage::ErabSetupResponse(d::ErabSetupResponse {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_setup_list: setup,
                erab_failed_list: failed,
            })
        }
        S::Id_E_RABModify(m) => {
            use g::E_RABModifyResponseProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ok, mut failed) = (Vec::new(), Vec::new());
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABModifyListBearerModRes(l) => {
                        for e in l.0 {
                            let g::E_RABModifyListBearerModRes_EntryValue::Id_E_RABModifyItemBearerModRes(i) = e.value;
                            ok.push(i.e_rab_id.0);
                        }
                    }
                    V::Id_E_RABFailedToModifyList(l) => failed = failed_d(&l)?,
                });
            }
            S1apMessage::ErabModifyResponse(d::ErabModifyResponse {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_modify_list: ok,
                erab_failed_list: failed,
            })
        }
        S::Id_E_RABRelease(m) => {
            use g::E_RABReleaseResponseProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ok, mut failed) = (Vec::new(), Vec::new());
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABReleaseListBearerRelComp(l) => {
                        for e in l.0 {
                            let g::E_RABReleaseListBearerRelComp_EntryValue::Id_E_RABReleaseItemBearerRelComp(i) = e.value;
                            ok.push(i.e_rab_id.0);
                        }
                    }
                    V::Id_E_RABFailedToReleaseList(l) => failed = failed_d(&l)?,
                });
            }
            S1apMessage::ErabReleaseResponse(d::ErabReleaseResponse {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_release_list: ok,
                erab_failed_list: failed,
            })
        }
        S::Id_Reset(m) => {
            use g::ResetAcknowledgeProtocolIEs_EntryValue as V;
            let mut list = Vec::new();
            for ie in m.protocol_i_es.0 {
                if let V::Id_UE_associatedLogicalS1_ConnectionListResAck(l) = ie.value {
                    list = connections_d(l.0.into_iter().map(|e| {
                        let g::UE_associatedLogicalS1_ConnectionListResAck_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(i) = e.value;
                        i
                    }));
                }
            }
            S1apMessage::ResetAcknowledge(d::ResetAcknowledge {
                ue_associated_connections: list,
            })
        }
        S::Id_HandoverPreparation(m) => {
            use g::HandoverCommandProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ht, mut fwd, mut rel, mut cont) = (None, Vec::new(), Vec::new(), None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_HandoverType(x) => ht = Some(handover_type_d(&x)?),
                    V::Id_E_RABSubjecttoDataForwardingList(l) => {
                        for e in l.0 {
                            let g::E_RABSubjecttoDataForwardingList_EntryValue::Id_E_RABDataForwardingItem(i) = e.value;
                            fwd.push(d::ErabDataForwardingItem {
                                erab_id: i.e_rab_id.0,
                                dl_transport_layer_address: i.dl_transport_layer_address.as_ref().map(tla_d),
                                dl_gtp_teid: i.dl_g_tp_teid.as_ref().map(teid_d).transpose()?,
                                ul_transport_layer_address: i.ul_transport_layer_address.as_ref().map(tla_d),
                                ul_gtp_teid: i.ul_gtp_teid.as_ref().map(teid_d).transpose()?,
                            });
                        }
                    }
                    V::Id_E_RABtoReleaseListHOCmd(l) => rel = erab_items_d(&l)?,
                    V::Id_Target_ToSource_TransparentContainer(x) => cont = Some(x.0),
                });
            }
            S1apMessage::HandoverCommand(d::HandoverCommand {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                handover_type: req(ht, "HandoverType")?,
                erab_subject_to_forwarding_list: fwd,
                erab_to_release_list: rel,
                target_to_source_container: req(cont, "Target-ToSource-TransparentContainer")?,
            })
        }
        S::Id_HandoverResourceAllocation(m) => {
            use g::HandoverRequestAcknowledgeProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut admitted, mut failed, mut cont) = (Vec::new(), Vec::new(), None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABAdmittedList(l) => {
                        for e in l.0 {
                            let g::E_RABAdmittedList_EntryValue::Id_E_RABAdmittedItem(i) = e.value;
                            admitted.push(d::ErabAdmittedItem {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                                dl_transport_layer_address: i.dl_transport_layer_address.as_ref().map(tla_d),
                                dl_gtp_teid: i.dl_g_tp_teid.as_ref().map(teid_d).transpose()?,
                                ul_transport_layer_address: i.ul_transport_layer_address.as_ref().map(tla_d),
                                ul_gtp_teid: i.ul_gtp_teid.as_ref().map(teid_d).transpose()?,
                            });
                        }
                    }
                    V::Id_E_RABFailedToSetupListHOReqAck(l) => {
                        for e in l.0 {
                            let g::E_RABFailedtoSetupListHOReqAck_EntryValue::Id_E_RABFailedtoSetupItemHOReqAck(i) = e.value;
                            failed.push(d::ErabFailedItem {
                                erab_id: i.e_rab_id.0,
                                cause: cause_d(&i.cause)?,
                            });
                        }
                    }
                    V::Id_Target_ToSource_TransparentContainer(x) => cont = Some(x.0),
                });
            }
            S1apMessage::HandoverRequestAcknowledge(d::HandoverRequestAcknowledge {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_admitted_list: admitted,
                erab_failed_list: failed,
                target_to_source_container: req(cont, "Target-ToSource-TransparentContainer")?,
            })
        }
        S::Id_PathSwitchRequest(m) => {
            use g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            let (mut ul, mut sc) = (Vec::new(), None);
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_E_RABToBeSwitchedULList(l) => {
                        for e in l.0 {
                            let g::E_RABToBeSwitchedULList_EntryValue::Id_E_RABToBeSwitchedULItem(i) = e.value;
                            ul.push(d::ErabSwitchedItem {
                                erab_id: i.e_rab_id.0,
                                transport_layer_address: tla_d(&i.transport_layer_address),
                                gtp_teid: teid_d(&i.gtp_teid)?,
                            });
                        }
                    }
                    V::Id_SecurityContext(s) => {
                        sc = Some(SecurityContext {
                            next_hop_chaining_count: s.next_hop_chaining_count.0,
                            next_hop_parameter: key_d(&s.next_hop_parameter)?,
                        })
                    }
                });
            }
            S1apMessage::PathSwitchRequestAcknowledge(d::PathSwitchRequestAcknowledge {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                erab_switched_ul_list: ul,
                security_context: req(sc, "SecurityContext")?,
            })
        }
        S::Id_HandoverCancel(m) => {
            use g::HandoverCancelAcknowledgeProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {});
            }
            S1apMessage::HandoverCancelAcknowledge(d::HandoverCancelAcknowledge {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
            })
        }
        S::Id_ENBConfigurationUpdate(m) => {
            use g::ENBConfigurationUpdateAcknowledgeProtocolIEs_EntryValue as V;
            let mut diag = None;
            for ie in m.protocol_i_es.0 {
                let V::Id_CriticalityDiagnostics(x) = ie.value;
                diag = Some(x);
            }
            S1apMessage::EnbConfigurationUpdateAcknowledge(d::EnbConfigurationUpdateAcknowledge {
                criticality_diagnostics: opt_diag(diag),
            })
        }
        S::Id_MMEConfigurationUpdate(m) => {
            use g::MMEConfigurationUpdateAcknowledgeProtocolIEs_EntryValue as V;
            let mut diag = None;
            for ie in m.protocol_i_es.0 {
                let V::Id_CriticalityDiagnostics(x) = ie.value;
                diag = Some(x);
            }
            S1apMessage::MmeConfigurationUpdateAcknowledge(d::MmeConfigurationUpdateAcknowledge {
                criticality_diagnostics: opt_diag(diag),
            })
        }
        S::Id_UEContextModification(m) => {
            use g::UEContextModificationResponseProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_CriticalityDiagnostics(x) => c.diag = Some(x), });
            }
            S1apMessage::UeContextModificationResponse(d::UeContextModificationResponse {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                criticality_diagnostics: opt_diag(c.diag),
            })
        }
        S::Id_WriteReplaceWarning(m) => {
            use g::WriteReplaceWarningResponseProtocolIEs_EntryValue as V;
            let (mut id, mut serial, mut area, mut diag) = (None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MessageIdentifier(x) => id = u16_bits(&x.0),
                    V::Id_SerialNumber(x) => serial = u16_bits(&x.0),
                    V::Id_BroadcastCompletedAreaList(x) => area = completed_area(x),
                    V::Id_CriticalityDiagnostics(x) => diag = Some(x),
                }
            }
            S1apMessage::WriteReplaceWarningResponse(d::WriteReplaceWarningResponse {
                message_identifier: req(id, "MessageIdentifier")?,
                serial_number: req(serial, "SerialNumber")?,
                broadcast_completed_area: area,
                criticality_diagnostics: opt_diag(diag),
            })
        }
        S::Id_Kill(m) => {
            use g::KillResponseProtocolIEs_EntryValue as V;
            let (mut id, mut serial, mut area, mut diag) = (None, None, None, None);
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MessageIdentifier(x) => id = u16_bits(&x.0),
                    V::Id_SerialNumber(x) => serial = u16_bits(&x.0),
                    V::Id_BroadcastCancelledAreaList(x) => area = cancelled_area(x),
                    V::Id_CriticalityDiagnostics(x) => diag = Some(x),
                }
            }
            S1apMessage::KillResponse(d::KillResponse {
                message_identifier: req(id, "MessageIdentifier")?,
                serial_number: req(serial, "SerialNumber")?,
                broadcast_cancelled_area: area,
                criticality_diagnostics: opt_diag(diag),
            })
        }
        _ => S1apMessage::Unknown {
            procedure_code: 255,
            message_type: "SuccessfulOutcome",
        },
    })
}

fn unsuccessful_d(v: g::UnsuccessfulOutcomeValue) -> S1apResult<S1apMessage> {
    use g::UnsuccessfulOutcomeValue as U;
    use nextgcore_s1ap as d;
    Ok(match v {
        U::Id_S1Setup(m) => {
            use g::S1SetupFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_TimeToWait(x) => c.ttw = Some(x),
                    _ => {}
                }
            }
            S1apMessage::S1SetupFailure(d::S1SetupFailure {
                cause: req(c.cause, "Cause")?,
                time_to_wait: ttw_d(c.ttw),
            })
        }
        U::Id_InitialContextSetup(m) => {
            use g::InitialContextSetupFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_Cause(x) => c.cause = Some(cause_d(&x)?), });
            }
            S1apMessage::InitialContextSetupFailure(d::InitialContextSetupFailure {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        U::Id_HandoverPreparation(m) => {
            use g::HandoverPreparationFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_Cause(x) => c.cause = Some(cause_d(&x)?), });
            }
            S1apMessage::HandoverPreparationFailure(d::HandoverPreparationFailure {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        U::Id_HandoverResourceAllocation(m) => {
            use g::HandoverFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_MME_UE_S1AP_ID(x) => c.mme = Some(x.0),
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    _ => {}
                }
            }
            S1apMessage::HandoverFailure(d::HandoverFailure {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        U::Id_PathSwitchRequest(m) => {
            use g::PathSwitchRequestFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, { V::Id_Cause(x) => c.cause = Some(cause_d(&x)?), });
            }
            S1apMessage::PathSwitchRequestFailure(d::PathSwitchRequestFailure {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
            })
        }
        U::Id_ENBConfigurationUpdate(m) => {
            use g::ENBConfigurationUpdateFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_TimeToWait(x) => c.ttw = Some(x),
                    V::Id_CriticalityDiagnostics(x) => c.diag = Some(x),
                }
            }
            S1apMessage::EnbConfigurationUpdateFailure(d::EnbConfigurationUpdateFailure {
                cause: req(c.cause, "Cause")?,
                time_to_wait: ttw_d(c.ttw),
                criticality_diagnostics: opt_diag(c.diag),
            })
        }
        U::Id_MMEConfigurationUpdate(m) => {
            use g::MMEConfigurationUpdateFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                match ie.value {
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_TimeToWait(x) => c.ttw = Some(x),
                    V::Id_CriticalityDiagnostics(x) => c.diag = Some(x),
                }
            }
            S1apMessage::MmeConfigurationUpdateFailure(d::MmeConfigurationUpdateFailure {
                cause: req(c.cause, "Cause")?,
                time_to_wait: ttw_d(c.ttw),
                criticality_diagnostics: opt_diag(c.diag),
            })
        }
        U::Id_UEContextModification(m) => {
            use g::UEContextModificationFailureProtocolIEs_EntryValue as V;
            let mut c = Common::default();
            for ie in m.protocol_i_es.0 {
                common_ie!(c, ie.value, V, {
                    V::Id_Cause(x) => c.cause = Some(cause_d(&x)?),
                    V::Id_CriticalityDiagnostics(x) => c.diag = Some(x),
                });
            }
            S1apMessage::UeContextModificationFailure(d::UeContextModificationFailure {
                mme_ue_s1ap_id: req(c.mme, "MME-UE-S1AP-ID")?,
                enb_ue_s1ap_id: req(c.enb, "eNB-UE-S1AP-ID")?,
                cause: req(c.cause, "Cause")?,
                criticality_diagnostics: opt_diag(c.diag),
            })
        }
        _ => S1apMessage::Unknown {
            procedure_code: 255,
            message_type: "UnsuccessfulOutcome",
        },
    })
}

#[cfg(test)]
mod tests {
    //! The test codec against octets derived by hand from X.691 (APER), so
    //! the fixtures mmed's tests build are pinned to the wire, not only to
    //! the generated codec they come from.
    use super::builder::*;
    use super::*;

    fn tai() -> Tai {
        Tai {
            plmn_identity: [0x00, 0xf1, 0x10],
            tac: 1,
        }
    }

    fn cgi() -> EutranCgi {
        EutranCgi {
            plmn_identity: [0x00, 0xf1, 0x10],
            cell_identity: 0x0000_0010,
        }
    }

    /// UE CONTEXT RELEASE COMPLETE, MME-UE-S1AP-ID 1, eNB-UE-S1AP-ID 2.
    /// S1AP-PDU CHOICE successfulOutcome (index 1 of 3, root): `20`.
    /// procedureCode 23 `17`, criticality reject `00`, open-type length `0f`.
    /// Value: extension bit 0 + 16-bit IE count 2 -> `00 00 02`.
    /// IE id 0 `00 00`, ignore `40`, length 2, MME-UE-S1AP-ID 1 as
    /// INTEGER (0..2^32-1): length-1 octet count `00` then `01`.
    /// IE id 8 `00 08`, ignore `40`, length 2, eNB-UE-S1AP-ID 2 as
    /// INTEGER (0..2^24-1): `00 02`.
    #[test]
    fn release_complete_golden() {
        let bytes = build_ue_context_release_complete(&nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 2,
        })
        .unwrap();
        assert_eq!(
            bytes,
            [
                0x20, 0x17, 0x00, 0x0f, 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x02, 0x00, 0x01, 0x00,
                0x08, 0x40, 0x02, 0x00, 0x02
            ]
        );
    }

    /// UE CONTEXT RELEASE REQUEST, IDs 1 / 2, Cause radioNetwork
    /// user-inactivity (20). initiatingMessage `00`, procedureCode 18 `12`,
    /// criticality ignore `40`, open-type length `15`; three IEs `00 00 03`;
    /// IDs as above but criticality reject `00`; Cause id 2 `00 02`, ignore
    /// `40`, length 2: CHOICE radioNetwork (index 0 of 5, extensible: ext bit
    /// 0, 3-bit index 000) then CauseRadioNetwork 20 of an extensible
    /// 36-value root (ext bit 0, 6 bits 010100) = `00 50`... packed: bits
    /// 0 000 0 010100 0 -> `02 80`.
    #[test]
    fn release_request_round_trips_and_pins_its_cause() {
        let msg = nextgcore_s1ap::UeContextReleaseRequest {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 2,
            cause: Cause::RadioNetwork(nextgcore_s1ap::CauseRadioNetwork::UserInactivity),
        };
        let bytes = build_ue_context_release_request(&msg).unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x12, 0x40, 0x15]);
        assert_eq!(
            &bytes[bytes.len() - 6..],
            &[0x00, 0x02, 0x40, 0x02, 0x02, 0x80]
        );
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UeContextReleaseRequest(back) => {
                assert_eq!(format!("{back:?}"), format!("{msg:?}"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn uplink_nas_round_trips() {
        let msg = nextgcore_s1ap::UlNasTransport {
            mme_ue_s1ap_id: 7,
            enb_ue_s1ap_id: 9,
            nas_pdu: vec![0x07, 0x43],
            eutran_cgi: cgi(),
            tai: tai(),
        };
        let bytes = build_uplink_nas_transport(&msg).unwrap();
        match decode_s1ap_pdu(&bytes).unwrap() {
            S1apMessage::UplinkNasTransport(back) => {
                assert_eq!(format!("{back:?}"), format!("{msg:?}"))
            }
            other => panic!("{other:?}"),
        }
    }
}
