//! NextGCore NGAP Protocol Library
//!
//! This crate provides high-level NGAP (NG Application Protocol) message building
//! and parsing for the 5G Core Network, as defined in 3GPP TS 38.413.
//!
//! # Architecture
//!
//! The library is layered on top of `nextgcore-asn1c` which provides raw ASN.1 APER
//! encoding/decoding. This crate adds:
//!
//! - **Strongly-typed message types** (`types`) for each NGAP procedure
//! - **Builder functions** (`builder`) to construct APER-encoded NGAP PDUs
//! - **Parser functions** (`parser`) to decode APER bytes into typed messages
//! - **IE helpers** (`ie`) for encoding/decoding individual Information Elements
//!
//! # Supported Procedures
//!
//! Interface management (Section 8.7):
//! - **NG Setup**: Request, Response, Failure
//! - **NG Reset**: Reset, Reset Acknowledge
//! - **RAN Configuration Update**: Update, Acknowledge, Failure
//! - **AMF Configuration Update**: Update, Acknowledge, Failure
//! - **AMF Status Indication**, **Error Indication**
//!
//! NAS transport (Section 8.6):
//! - **Initial UE Message**, **Downlink/Uplink NAS Transport**
//! - **NAS Non Delivery Indication**
//!
//! UE context management (Sections 8.3, 8.5):
//! - **Initial Context Setup**: Request, Response, Failure
//! - **UE Context Release**: Command, Complete, Request
//! - **Paging**
//!
//! PDU session management (Section 8.2):
//! - **PDU Session Resource Setup/Modify/Release**: Request + Response
//! - **PDU Session Resource Notify**
//! - **PDU Session Resource Modify Indication**: Indication, Confirm
//! - N2 SM transfer IEs ([`transfer`]): Setup/Modify/Release Request +
//!   Response transfer containers with full QoS flow parameters
//!
//! UE mobility (Section 8.4):
//! - **Handover Preparation**: Required, Command, Preparation Failure
//! - **Handover Resource Allocation**: Request, Request Acknowledge, Failure
//! - **Handover Notify**, **Handover Cancel** (types only)
//! - **Path Switch Request**: Request, Acknowledge, Failure
//!
//! # Deliberately Deferred Procedure Classes
//!
//! The following TS 38.413 procedure classes are not yet implemented because
//! no NF in this stack drives them today; the PDU dispatcher surfaces them as
//! [`parser::NgapMessage::Unknown`] so callers can answer with Error Indication:
//!
//! - Warning message transmission (Write-Replace Warning, PWS Cancel/Restart/Failure)
//! - Trace procedures (Trace Start, Trace Failure, Deactivate Trace, Cell Traffic Trace)
//! - Location reporting (Location Reporting Control/Failure, Location Report)
//! - NRPPa transport (UE/non-UE associated)
//! - RAN/AMF CP relocation indications (UE Context Modification, RRC Inactive
//!   Transition Report, Reroute NAS, Overload Start/Stop, UE Radio Capability
//!   Check/Info Indication, UE TNLA Binding Release, RAN Configuration Transfer,
//!   RAN/Secondary RAT Status Transfer)
//! - AMF Configuration Update TNL association add/remove/update lists
//!   (all-optional IEs; the name/GUAMI/capacity/PLMN subset is implemented)
//!
//! # Example
//!
//! ```no_run
//! use nextgcore_ngap::builder;
//! use nextgcore_ngap::types::*;
//! use nextgcore_asn1c::ngap::cause::{Cause, CauseNas};
//!
//! // Build a Downlink NAS Transport message
//! let msg = DownlinkNasTransport {
//!     amf_ue_ngap_id: 1,
//!     ran_ue_ngap_id: 100,
//!     nas_pdu: vec![0x7e, 0x00, 0x56],
//! };
//! let bytes = builder::build_downlink_nas_transport(&msg).expect("value expected");
//!
//! // Parse any NGAP message
//! use nextgcore_ngap::parser;
//! let decoded = parser::decode_ngap_pdu(&bytes).expect("value expected");
//! ```

pub mod builder;
pub mod error;
pub mod ie;
pub mod mbs_transfer;
pub mod parser;
pub mod transfer;
pub mod types;

#[cfg(test)]
mod property_tests;

// Re-export key types for convenience
pub use error::{NgapError, NgapResult};
pub use parser::NgapMessage;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_asn1c::ngap::cause::{Cause, CauseMisc, CauseNas, CauseRadioNetwork};

    #[test]
    fn test_downlink_nas_transport_roundtrip() {
        let msg = DownlinkNasTransport {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 100,
            nas_pdu: vec![0x7e, 0x00, 0x56, 0x01, 0x02],
        };

        let bytes = builder::build_downlink_nas_transport(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::DownlinkNasTransport(dl) => {
                assert_eq!(dl.amf_ue_ngap_id, 42);
                assert_eq!(dl.ran_ue_ngap_id, 100);
                assert_eq!(dl.nas_pdu, vec![0x7e, 0x00, 0x56, 0x01, 0x02]);
            }
            other => panic!("Expected DownlinkNasTransport, got {other:?}"),
        }
    }

    #[test]
    fn test_ng_setup_failure_roundtrip() {
        let msg = types::NgSetupFailure {
            cause: Cause::Misc(CauseMisc::Unspecified),
            time_to_wait: Some(types::TimeToWait::V5s),
            criticality_diagnostics: None,
        };

        let bytes = builder::build_ng_setup_failure(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NgSetupFailure(failure) => {
                assert_eq!(failure.cause, Cause::Misc(CauseMisc::Unspecified));
                assert_eq!(failure.time_to_wait, Some(types::TimeToWait::V5s));
            }
            other => panic!("Expected NgSetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_ue_context_release_command_roundtrip() {
        let msg = types::UeContextReleaseCommand {
            ue_ngap_ids: types::UeNgapIds::Pair {
                amf_ue_ngap_id: 1000,
                ran_ue_ngap_id: 500,
            },
            cause: Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
        };

        let bytes = builder::build_ue_context_release_command(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::UeContextReleaseCommand(cmd) => {
                match cmd.ue_ngap_ids {
                    types::UeNgapIds::Pair {
                        amf_ue_ngap_id,
                        ran_ue_ngap_id,
                    } => {
                        assert_eq!(amf_ue_ngap_id, 1000);
                        assert_eq!(ran_ue_ngap_id, 500);
                    }
                    _ => panic!("Expected Pair"),
                }
                assert_eq!(
                    cmd.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UserInactivity)
                );
            }
            other => panic!("Expected UeContextReleaseCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_ue_context_release_complete_roundtrip() {
        let msg = types::UeContextReleaseComplete {
            amf_ue_ngap_id: 1000,
            ran_ue_ngap_id: 500,
        };

        let bytes = builder::build_ue_context_release_complete(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::UeContextReleaseComplete(complete) => {
                assert_eq!(complete.amf_ue_ngap_id, 1000);
                assert_eq!(complete.ran_ue_ngap_id, 500);
            }
            other => panic!("Expected UeContextReleaseComplete, got {other:?}"),
        }
    }

    #[test]
    fn test_ue_context_release_request_roundtrip() {
        let msg = types::UeContextReleaseRequest {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 7,
            cause: Cause::Nas(CauseNas::NormalRelease),
        };

        let bytes = builder::build_ue_context_release_request(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::UeContextReleaseRequest(req) => {
                assert_eq!(req.amf_ue_ngap_id, 42);
                assert_eq!(req.ran_ue_ngap_id, 7);
                assert_eq!(req.cause, Cause::Nas(CauseNas::NormalRelease));
            }
            other => panic!("Expected UeContextReleaseRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_initial_context_setup_response_roundtrip() {
        let msg = types::InitialContextSetupResponse {
            amf_ue_ngap_id: 55,
            ran_ue_ngap_id: 33,
        };

        let bytes = builder::build_initial_context_setup_response(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::InitialContextSetupResponse(resp) => {
                assert_eq!(resp.amf_ue_ngap_id, 55);
                assert_eq!(resp.ran_ue_ngap_id, 33);
            }
            other => panic!("Expected InitialContextSetupResponse, got {other:?}"),
        }
    }

    #[test]
    fn test_initial_context_setup_failure_roundtrip() {
        let msg = types::InitialContextSetupFailure {
            amf_ue_ngap_id: 55,
            ran_ue_ngap_id: 33,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        };

        let bytes = builder::build_initial_context_setup_failure(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::InitialContextSetupFailure(fail) => {
                assert_eq!(fail.amf_ue_ngap_id, 55);
                assert_eq!(fail.ran_ue_ngap_id, 33);
                assert_eq!(
                    fail.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
                );
            }
            other => panic!("Expected InitialContextSetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_ng_setup_response_builds() {
        let msg = types::NgSetupResponse {
            amf_name: "TestAMF".to_string(),
            served_guami_list: vec![types::ServedGuamiItem {
                guami: types::Guami {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    amf_region_id: 2,
                    amf_set_id: 1,
                    amf_pointer: 0,
                },
                backup_amf_name: None,
            }],
            relative_amf_capacity: 255,
            plmn_support_list: vec![types::PlmnSupportItem {
                plmn_identity: [0x99, 0xF9, 0x07],
                slice_support_list: vec![types::SNssai { sst: 1, sd: None }],
            }],
        };

        let bytes = builder::build_ng_setup_response(&msg).unwrap();
        assert!(!bytes.is_empty());

        // Verify it decodes
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NgSetupResponse(resp) => {
                assert_eq!(resp.amf_name, "TestAMF");
                assert_eq!(resp.relative_amf_capacity, 255);
            }
            other => panic!("Expected NgSetupResponse, got {other:?}"),
        }
    }

    #[test]
    fn test_pdu_session_resource_setup_response_roundtrip() {
        let msg = types::PduSessionResourceSetupResponse {
            amf_ue_ngap_id: 100,
            ran_ue_ngap_id: 200,
            setup_list: vec![types::PduSessionResourceSetupResponseItem {
                pdu_session_id: 1,
                transfer: vec![0x11, 0x22, 0x33],
            }],
            failed_list: vec![types::PduSessionResourceFailedItem {
                pdu_session_id: 2,
                transfer: vec![0x44],
            }],
        };

        let bytes = builder::build_pdu_session_resource_setup_response(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PduSessionResourceSetupResponse(resp) => {
                assert_eq!(resp.amf_ue_ngap_id, 100);
                assert_eq!(resp.ran_ue_ngap_id, 200);
                assert_eq!(resp.setup_list.len(), 1);
                assert_eq!(resp.setup_list[0].pdu_session_id, 1);
                assert_eq!(resp.setup_list[0].transfer, vec![0x11, 0x22, 0x33]);
                assert_eq!(resp.failed_list.len(), 1);
                assert_eq!(resp.failed_list[0].pdu_session_id, 2);
            }
            other => panic!("Expected PduSessionResourceSetupResponse, got {other:?}"),
        }
    }

    // ========================================================================
    // Helpers for hand-built PDUs (strict-reject tests)
    // ========================================================================

    fn encode_initiating_pdu(
        procedure_code: nextgcore_asn1c::ngap::types::ProcedureCode,
        container: nextgcore_asn1c::ngap::ies::ProtocolIeContainer,
    ) -> Vec<u8> {
        use nextgcore_asn1c::ngap::pdu::{InitiatingMessage, InitiatingMessageValue, NgapPdu};
        use nextgcore_asn1c::ngap::types::Criticality;
        use nextgcore_asn1c::per::{AperEncode, AperEncoder};

        let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
            procedure_code,
            criticality: Criticality::Reject,
            value: InitiatingMessageValue::Other(container),
        });
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    // ========================================================================
    // NG Reset / Error Indication
    // ========================================================================

    #[test]
    fn test_ng_reset_full_interface_roundtrip() {
        let msg = types::NgReset {
            cause: Cause::Misc(CauseMisc::HardwareFailure),
            reset_type: types::ResetType::NgInterface,
        };

        let bytes = builder::build_ng_reset(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NgReset(reset) => {
                assert_eq!(reset.cause, Cause::Misc(CauseMisc::HardwareFailure));
                assert_eq!(reset.reset_type, types::ResetType::NgInterface);
            }
            other => panic!("Expected NgReset, got {other:?}"),
        }
    }

    #[test]
    fn test_ng_reset_partial_roundtrip() {
        let connections = vec![
            types::UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: Some(0x80_0000_0001),
                ran_ue_ngap_id: Some(7),
            },
            types::UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: None,
                ran_ue_ngap_id: Some(9),
            },
        ];
        let msg = types::NgReset {
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            reset_type: types::ResetType::PartOfNgInterface(connections.clone()),
        };

        let bytes = builder::build_ng_reset(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NgReset(reset) => {
                assert_eq!(
                    reset.reset_type,
                    types::ResetType::PartOfNgInterface(connections)
                );
            }
            other => panic!("Expected NgReset, got {other:?}"),
        }
    }

    #[test]
    fn test_ng_reset_acknowledge_roundtrip() {
        let msg = types::NgResetAcknowledge {
            connections: Some(vec![types::UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: Some(12),
                ran_ue_ngap_id: None,
            }]),
            criticality_diagnostics: Some(types::CriticalityDiagnostics {
                procedure_code: Some(20),
                triggering_message: Some(0),
                procedure_criticality: Some(0),
                ies: vec![],
            }),
        };

        let bytes = builder::build_ng_reset_acknowledge(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NgResetAcknowledge(ack) => {
                let conns = ack.connections.expect("connections expected");
                assert_eq!(conns.len(), 1);
                assert_eq!(conns[0].amf_ue_ngap_id, Some(12));
                let diag = ack.criticality_diagnostics.expect("diagnostics expected");
                assert_eq!(diag.procedure_code, Some(20));
            }
            other => panic!("Expected NgResetAcknowledge, got {other:?}"),
        }
    }

    #[test]
    fn test_ng_reset_missing_cause_rejected() {
        use nextgcore_asn1c::ngap::ies::ProtocolIeContainer;
        use nextgcore_asn1c::ngap::types::ProcedureCode;

        // NG Reset with only ResetType - the mandatory Cause is absent
        let mut container = ProtocolIeContainer::new();
        ie::encode_reset_type(&mut container, &types::ResetType::NgInterface).unwrap();
        let bytes = encode_initiating_pdu(ProcedureCode::NG_RESET, container);

        let result = parser::decode_ngap_pdu(&bytes);
        assert!(matches!(
            result,
            Err(error::NgapError::MissingMandatoryIe {
                ie_name: "Cause",
                ..
            })
        ));
    }

    #[test]
    fn test_error_indication_roundtrip() {
        let msg = types::ErrorIndication {
            amf_ue_ngap_id: Some(77),
            ran_ue_ngap_id: Some(88),
            cause: Some(Cause::Protocol(
                nextgcore_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
            )),
            criticality_diagnostics: None,
        };

        let bytes = builder::build_error_indication(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::ErrorIndication(ind) => {
                assert_eq!(ind.amf_ue_ngap_id, Some(77));
                assert_eq!(ind.ran_ue_ngap_id, Some(88));
                assert!(ind.cause.is_some());
            }
            other => panic!("Expected ErrorIndication, got {other:?}"),
        }
    }

    // ========================================================================
    // RAN / AMF Configuration Update
    // ========================================================================

    #[test]
    fn test_ran_configuration_update_roundtrip() {
        let msg = types::RanConfigurationUpdate {
            ran_node_name: Some("gnb-001".to_string()),
            supported_ta_list: Some(vec![types::SupportedTaItem {
                tac: [0x00, 0x00, 0x01],
                broadcast_plmn_list: vec![types::BroadcastPlmnItem {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    tai_slice_support_list: vec![types::SNssai { sst: 1, sd: None }],
                }],
            }]),
            default_paging_drx: Some(types::PagingDrx::V64),
            global_ran_node_id: None,
        };

        let bytes = builder::build_ran_configuration_update(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::RanConfigurationUpdate(update) => {
                assert_eq!(update.ran_node_name.as_deref(), Some("gnb-001"));
                assert_eq!(update.default_paging_drx, Some(types::PagingDrx::V64));
                let ta_list = update.supported_ta_list.expect("TA list expected");
                assert_eq!(ta_list.len(), 1);
                assert_eq!(ta_list[0].tac, [0x00, 0x00, 0x01]);
            }
            other => panic!("Expected RanConfigurationUpdate, got {other:?}"),
        }
    }

    #[test]
    fn test_ran_configuration_update_ack_and_failure_roundtrip() {
        let ack = types::RanConfigurationUpdateAcknowledge {
            criticality_diagnostics: None,
        };
        let bytes = builder::build_ran_configuration_update_acknowledge(&ack).unwrap();
        assert!(matches!(
            parser::decode_ngap_pdu(&bytes).unwrap(),
            NgapMessage::RanConfigurationUpdateAcknowledge(_)
        ));

        let failure = types::RanConfigurationUpdateFailure {
            cause: Cause::Misc(CauseMisc::ControlProcessingOverload),
            time_to_wait: Some(types::TimeToWait::V10s),
            criticality_diagnostics: None,
        };
        let bytes = builder::build_ran_configuration_update_failure(&failure).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::RanConfigurationUpdateFailure(f) => {
                assert_eq!(f.cause, Cause::Misc(CauseMisc::ControlProcessingOverload));
                assert_eq!(f.time_to_wait, Some(types::TimeToWait::V10s));
            }
            other => panic!("Expected RanConfigurationUpdateFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_amf_configuration_update_roundtrip() {
        let msg = types::AmfConfigurationUpdate {
            amf_name: Some("amf.5gc.example".to_string()),
            served_guami_list: Some(vec![types::ServedGuamiItem {
                guami: types::Guami {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    amf_region_id: 2,
                    amf_set_id: 1,
                    amf_pointer: 0,
                },
                backup_amf_name: Some("backup-amf".to_string()),
            }]),
            relative_amf_capacity: Some(128),
            plmn_support_list: Some(vec![types::PlmnSupportItem {
                plmn_identity: [0x99, 0xF9, 0x07],
                slice_support_list: vec![types::SNssai {
                    sst: 1,
                    sd: Some([0x00, 0x00, 0x01]),
                }],
            }]),
        };

        let bytes = builder::build_amf_configuration_update(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::AmfConfigurationUpdate(update) => {
                assert_eq!(update.amf_name.as_deref(), Some("amf.5gc.example"));
                assert_eq!(update.relative_amf_capacity, Some(128));
                let guamis = update.served_guami_list.expect("GUAMI list expected");
                assert_eq!(guamis[0].backup_amf_name.as_deref(), Some("backup-amf"));
                let plmns = update.plmn_support_list.expect("PLMN list expected");
                assert_eq!(plmns[0].slice_support_list[0].sd, Some([0x00, 0x00, 0x01]));
            }
            other => panic!("Expected AmfConfigurationUpdate, got {other:?}"),
        }
    }

    #[test]
    fn test_amf_configuration_update_ack_and_failure_roundtrip() {
        let ack = types::AmfConfigurationUpdateAcknowledge {
            criticality_diagnostics: None,
        };
        let bytes = builder::build_amf_configuration_update_acknowledge(&ack).unwrap();
        assert!(matches!(
            parser::decode_ngap_pdu(&bytes).unwrap(),
            NgapMessage::AmfConfigurationUpdateAcknowledge(_)
        ));

        let failure = types::AmfConfigurationUpdateFailure {
            cause: Cause::Misc(CauseMisc::Unspecified),
            time_to_wait: None,
            criticality_diagnostics: None,
        };
        let bytes = builder::build_amf_configuration_update_failure(&failure).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::AmfConfigurationUpdateFailure(f) => {
                assert_eq!(f.cause, Cause::Misc(CauseMisc::Unspecified));
            }
            other => panic!("Expected AmfConfigurationUpdateFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_amf_status_indication_roundtrip() {
        let msg = types::AmfStatusIndication {
            unavailable_guami_list: vec![types::UnavailableGuamiItem {
                guami: types::Guami {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    amf_region_id: 1,
                    amf_set_id: 4,
                    amf_pointer: 2,
                },
                timer_approach_for_guami_removal: true,
                backup_amf_name: Some("backup".to_string()),
            }],
        };

        let bytes = builder::build_amf_status_indication(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::AmfStatusIndication(ind) => {
                assert_eq!(ind.unavailable_guami_list.len(), 1);
                let item = &ind.unavailable_guami_list[0];
                assert_eq!(item.guami.amf_set_id, 4);
                assert!(item.timer_approach_for_guami_removal);
                assert_eq!(item.backup_amf_name.as_deref(), Some("backup"));
            }
            other => panic!("Expected AmfStatusIndication, got {other:?}"),
        }
    }

    // ========================================================================
    // PDU Session Resource Notify / Modify Indication / Modify
    // ========================================================================

    #[test]
    fn test_pdu_session_resource_notify_roundtrip() {
        let msg = types::PduSessionResourceNotify {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            notify_list: vec![types::PduSessionResourceNotifyItem {
                pdu_session_id: 5,
                transfer: vec![0xAA, 0xBB],
            }],
            released_list: vec![types::PduSessionResourceReleasedItem {
                pdu_session_id: 6,
                transfer: vec![0xCC],
            }],
        };

        let bytes = builder::build_pdu_session_resource_notify(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PduSessionResourceNotify(notify) => {
                assert_eq!(notify.notify_list.len(), 1);
                assert_eq!(notify.notify_list[0].pdu_session_id, 5);
                assert_eq!(notify.released_list.len(), 1);
                assert_eq!(notify.released_list[0].transfer, vec![0xCC]);
            }
            other => panic!("Expected PduSessionResourceNotify, got {other:?}"),
        }
    }

    #[test]
    fn test_pdu_session_resource_notify_requires_a_list() {
        let msg = types::PduSessionResourceNotify {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            notify_list: vec![],
            released_list: vec![],
        };
        assert!(builder::build_pdu_session_resource_notify(&msg).is_err());
    }

    #[test]
    fn test_pdu_session_resource_modify_indication_roundtrip() {
        let msg = types::PduSessionResourceModifyIndication {
            amf_ue_ngap_id: 10,
            ran_ue_ngap_id: 20,
            modify_list: vec![types::PduSessionResourceModifyIndicationItem {
                pdu_session_id: 1,
                transfer: vec![0x01, 0x02],
            }],
        };

        let bytes = builder::build_pdu_session_resource_modify_indication(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PduSessionResourceModifyIndication(ind) => {
                assert_eq!(ind.modify_list.len(), 1);
                assert_eq!(ind.modify_list[0].transfer, vec![0x01, 0x02]);
            }
            other => panic!("Expected PduSessionResourceModifyIndication, got {other:?}"),
        }
    }

    #[test]
    fn test_pdu_session_resource_modify_indication_missing_list_rejected() {
        use nextgcore_asn1c::ngap::ies::ProtocolIeContainer;
        use nextgcore_asn1c::ngap::types::ProcedureCode;

        let mut container = ProtocolIeContainer::new();
        ie::encode_amf_ue_ngap_id(&mut container, 10).unwrap();
        ie::encode_ran_ue_ngap_id(&mut container, 20).unwrap();
        let bytes = encode_initiating_pdu(
            ProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION,
            container,
        );

        let result = parser::decode_ngap_pdu(&bytes);
        assert!(matches!(
            result,
            Err(error::NgapError::MissingMandatoryIe {
                ie_name: "PDUSessionResourceModifyListModInd",
                ..
            })
        ));
    }

    #[test]
    fn test_pdu_session_resource_modify_confirm_roundtrip() {
        let msg = types::PduSessionResourceModifyConfirm {
            amf_ue_ngap_id: 10,
            ran_ue_ngap_id: 20,
            confirm_list: vec![types::PduSessionResourceModifyConfirmItem {
                pdu_session_id: 1,
                transfer: vec![0x09],
            }],
            failed_list: vec![],
        };

        let bytes = builder::build_pdu_session_resource_modify_confirm(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PduSessionResourceModifyConfirm(cfm) => {
                assert_eq!(cfm.confirm_list.len(), 1);
                assert!(cfm.failed_list.is_empty());
            }
            other => panic!("Expected PduSessionResourceModifyConfirm, got {other:?}"),
        }
    }

    #[test]
    fn test_pdu_session_resource_modify_request_and_response_roundtrip() {
        let req = types::PduSessionResourceModifyRequest {
            amf_ue_ngap_id: 3,
            ran_ue_ngap_id: 4,
            pdu_session_list: vec![types::PduSessionResourceModifyItem {
                pdu_session_id: 1,
                nas_pdu: Some(vec![0x7e, 0x00, 0x68]),
                transfer: vec![0x10, 0x20],
            }],
        };
        let bytes = builder::build_pdu_session_resource_modify_request(&req).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::PduSessionResourceModifyRequest(decoded) => {
                assert_eq!(decoded.pdu_session_list.len(), 1);
                assert_eq!(
                    decoded.pdu_session_list[0].nas_pdu,
                    Some(vec![0x7e, 0x00, 0x68])
                );
                assert_eq!(decoded.pdu_session_list[0].transfer, vec![0x10, 0x20]);
            }
            other => panic!("Expected PduSessionResourceModifyRequest, got {other:?}"),
        }

        let resp = types::PduSessionResourceModifyResponse {
            amf_ue_ngap_id: 3,
            ran_ue_ngap_id: 4,
            modify_list: vec![types::PduSessionResourceModifyResponseItem {
                pdu_session_id: 1,
                transfer: vec![0x30],
            }],
            failed_list: vec![types::PduSessionResourceFailedItem {
                pdu_session_id: 2,
                transfer: vec![0x40],
            }],
        };
        let bytes = builder::build_pdu_session_resource_modify_response(&resp).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::PduSessionResourceModifyResponse(decoded) => {
                assert_eq!(decoded.modify_list.len(), 1);
                assert_eq!(decoded.modify_list[0].transfer, vec![0x30]);
                assert_eq!(decoded.failed_list.len(), 1);
                assert_eq!(decoded.failed_list[0].pdu_session_id, 2);
            }
            other => panic!("Expected PduSessionResourceModifyResponse, got {other:?}"),
        }
    }

    // ========================================================================
    // NAS Non Delivery Indication
    // ========================================================================

    #[test]
    fn test_nas_non_delivery_indication_roundtrip() {
        let msg = types::NasNonDeliveryIndication {
            amf_ue_ngap_id: 5,
            ran_ue_ngap_id: 6,
            nas_pdu: vec![0x7e, 0x00, 0x56, 0x01],
            cause: Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost),
        };

        let bytes = builder::build_nas_non_delivery_indication(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::NasNonDeliveryIndication(ind) => {
                assert_eq!(ind.nas_pdu, vec![0x7e, 0x00, 0x56, 0x01]);
                assert_eq!(
                    ind.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost)
                );
            }
            other => panic!("Expected NasNonDeliveryIndication, got {other:?}"),
        }
    }

    #[test]
    fn test_nas_non_delivery_indication_missing_nas_pdu_rejected() {
        use nextgcore_asn1c::ngap::ies::ProtocolIeContainer;
        use nextgcore_asn1c::ngap::types::ProcedureCode;

        let mut container = ProtocolIeContainer::new();
        ie::encode_amf_ue_ngap_id(&mut container, 5).unwrap();
        ie::encode_ran_ue_ngap_id(&mut container, 6).unwrap();
        ie::encode_cause(
            &mut container,
            &Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost),
        )
        .unwrap();
        let bytes = encode_initiating_pdu(ProcedureCode::NAS_NON_DELIVERY_INDICATION, container);

        let result = parser::decode_ngap_pdu(&bytes);
        assert!(matches!(
            result,
            Err(error::NgapError::MissingMandatoryIe {
                ie_name: "NAS-PDU",
                ..
            })
        ));
    }

    // ========================================================================
    // Handover Required / Path Switch (decode for encode-only family)
    // ========================================================================

    #[test]
    fn test_handover_required_roundtrip() {
        let msg = types::HandoverRequired {
            amf_ue_ngap_id: 0x123456789,
            ran_ue_ngap_id: 42,
            handover_type: types::HandoverType::Intra5gs,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id: types::TargetId::TargetRanNodeId {
                global_ran_node_id: types::GlobalRanNodeId::GlobalGnbId {
                    plmn_identity: [0x99, 0xF9, 0x07],
                    gnb_id: 0x000133,
                    gnb_id_len: 24,
                },
                selected_tai: types::TaiListItem {
                    tai_plmn: [0x99, 0xF9, 0x07],
                    tai_tac: [0x00, 0x00, 0x01],
                },
            },
            pdu_session_list: vec![types::PduSessionResourceItemHoRqd {
                pdu_session_id: 1,
                transfer: vec![0xDE, 0xAD],
            }],
            source_to_target_container: vec![0x01, 0x02, 0x03, 0x04],
        };

        let bytes = builder::build_handover_required(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::HandoverRequired(ho) => {
                assert_eq!(ho.amf_ue_ngap_id, 0x123456789);
                assert_eq!(ho.ran_ue_ngap_id, 42);
                assert_eq!(ho.handover_type, types::HandoverType::Intra5gs);
                match ho.target_id {
                    types::TargetId::TargetRanNodeId {
                        global_ran_node_id:
                            types::GlobalRanNodeId::GlobalGnbId {
                                gnb_id, gnb_id_len, ..
                            },
                        ..
                    } => {
                        assert_eq!(gnb_id, 0x000133);
                        assert_eq!(gnb_id_len, 24);
                    }
                    other => panic!("Expected TargetRanNodeId/GlobalGnbId, got {other:?}"),
                }
                assert_eq!(ho.pdu_session_list.len(), 1);
                assert_eq!(ho.pdu_session_list[0].transfer, vec![0xDE, 0xAD]);
                assert_eq!(ho.source_to_target_container, vec![0x01, 0x02, 0x03, 0x04]);
            }
            other => panic!("Expected HandoverRequired, got {other:?}"),
        }
    }

    #[test]
    fn test_handover_preparation_failure_roundtrip() {
        let msg = types::HandoverPreparationFailure {
            amf_ue_ngap_id: 9,
            ran_ue_ngap_id: 8,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HoTargetNotAllowed),
            criticality_diagnostics: None,
        };

        let bytes = builder::build_handover_preparation_failure(&msg).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::HandoverPreparationFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::HoTargetNotAllowed)
                );
            }
            other => panic!("Expected HandoverPreparationFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_path_switch_request_roundtrip() {
        let msg = types::PathSwitchRequest {
            ran_ue_ngap_id: 100,
            source_amf_ue_ngap_id: 200,
            user_location_info: types::UserLocationInformation::Nr {
                nr_cgi_plmn: [0x99, 0xF9, 0x07],
                nr_cell_identity: 0x123456789,
                tai_plmn: [0x99, 0xF9, 0x07],
                tai_tac: [0x00, 0x00, 0x01],
            },
            ue_security_capabilities: types::UeSecurityCapabilities {
                nr_encryption_algorithms: 0xE000,
                nr_integrity_algorithms: 0xE000,
                eutra_encryption_algorithms: 0,
                eutra_integrity_algorithms: 0,
            },
            pdu_session_list: vec![types::PduSessionResourceSwitchItem {
                pdu_session_id: 1,
                transfer: vec![0x55, 0x66],
            }],
            failed_list: None,
        };

        let bytes = builder::build_path_switch_request(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PathSwitchRequest(psr) => {
                assert_eq!(psr.ran_ue_ngap_id, 100);
                assert_eq!(psr.source_amf_ue_ngap_id, 200);
                assert_eq!(
                    psr.ue_security_capabilities.nr_encryption_algorithms,
                    0xE000
                );
                assert_eq!(psr.pdu_session_list.len(), 1);
                assert_eq!(psr.pdu_session_list[0].transfer, vec![0x55, 0x66]);
            }
            other => panic!("Expected PathSwitchRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_path_switch_request_acknowledge_roundtrip() {
        let msg = types::PathSwitchRequestAcknowledge {
            amf_ue_ngap_id: 11,
            ran_ue_ngap_id: 22,
            ue_security_capabilities: None,
            security_context: types::SecurityContext {
                next_hop_chaining_count: 3,
                next_hop: [0xAB; 32],
            },
            switched_list: vec![types::PduSessionResourceSwitchedItem {
                pdu_session_id: 1,
                transfer: vec![0x77],
            }],
            released_list: None,
            allowed_nssai: vec![types::SNssai { sst: 1, sd: None }],
        };

        let bytes = builder::build_path_switch_request_acknowledge(&msg).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::PathSwitchRequestAcknowledge(ack) => {
                assert_eq!(ack.security_context.next_hop_chaining_count, 3);
                assert_eq!(ack.security_context.next_hop, [0xAB; 32]);
                assert_eq!(ack.switched_list.len(), 1);
                assert_eq!(ack.allowed_nssai, vec![types::SNssai { sst: 1, sd: None }]);
            }
            other => panic!("Expected PathSwitchRequestAcknowledge, got {other:?}"),
        }
    }

    #[test]
    fn test_path_switch_request_failure_roundtrip() {
        let msg = types::PathSwitchRequestFailure {
            amf_ue_ngap_id: 11,
            ran_ue_ngap_id: 22,
            cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownPduSessionId),
            released_list: Some(vec![types::PduSessionResourceReleasedItem {
                pdu_session_id: 1,
                transfer: vec![0x88],
            }]),
            criticality_diagnostics: None,
        };

        let bytes = builder::build_path_switch_request_failure(&msg).unwrap();
        match parser::decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::PathSwitchRequestFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UnknownPduSessionId)
                );
                let released = failure.released_list.expect("released list expected");
                assert_eq!(released[0].transfer, vec![0x88]);
            }
            other => panic!("Expected PathSwitchRequestFailure, got {other:?}"),
        }
    }

    // ========================================================================
    // Fragmented open types (X.691 Section 11.9.3)
    // ========================================================================

    #[test]
    fn test_large_nas_pdu_fragmented_roundtrip() {
        // A NAS-PDU above 16383 octets forces fragmented length determinants
        // at the IE level, the open-type level, and the OCTET STRING level
        let nas_pdu: Vec<u8> = (0..40_000usize).map(|i| (i % 251) as u8).collect();
        let msg = DownlinkNasTransport {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            nas_pdu: nas_pdu.clone(),
        };

        let bytes = builder::build_downlink_nas_transport(&msg).unwrap();
        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::DownlinkNasTransport(dl) => {
                assert_eq!(dl.nas_pdu, nas_pdu);
            }
            other => panic!("Expected DownlinkNasTransport, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_pdu_rejected() {
        let msg = DownlinkNasTransport {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 100,
            nas_pdu: vec![0x7e, 0x00, 0x56, 0x01, 0x02],
        };
        let bytes = builder::build_downlink_nas_transport(&msg).unwrap();
        let truncated = &bytes[..bytes.len() - 3];
        assert!(parser::decode_ngap_pdu(truncated).is_err());
    }
}
