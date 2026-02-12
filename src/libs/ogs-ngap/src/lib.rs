//! NextGCore NGAP Protocol Library
//!
//! This crate provides high-level NGAP (NG Application Protocol) message building
//! and parsing for the 5G Core Network, as defined in 3GPP TS 38.413.
//!
//! # Architecture
//!
//! The library is layered on top of `ogs-asn1c` which provides raw ASN.1 APER
//! encoding/decoding. This crate adds:
//!
//! - **Strongly-typed message types** (`types`) for each NGAP procedure
//! - **Builder functions** (`builder`) to construct APER-encoded NGAP PDUs
//! - **Parser functions** (`parser`) to decode APER bytes into typed messages
//! - **IE helpers** (`ie`) for encoding/decoding individual Information Elements
//!
//! # Supported Procedures
//!
//! - **NG Setup**: Request, Response, Failure (Section 9.2.6)
//! - **NAS Transport**: Initial UE Message, Downlink/Uplink NAS Transport (Section 8.6)
//! - **Initial Context Setup**: Request, Response, Failure (Section 9.2.2)
//! - **PDU Session Resource**: Setup/Modify/Release Request/Response (Section 9.2.1)
//! - **UE Context Release**: Command, Complete, Request (Section 9.2.5)
//!
//! # Example
//!
//! ```no_run
//! use ogs_ngap::builder;
//! use ogs_ngap::types::*;
//! use ogs_asn1c::ngap::cause::{Cause, CauseNas};
//!
//! // Build a Downlink NAS Transport message
//! let msg = DownlinkNasTransport {
//!     amf_ue_ngap_id: 1,
//!     ran_ue_ngap_id: 100,
//!     nas_pdu: vec![0x7e, 0x00, 0x56],
//! };
//! let bytes = builder::build_downlink_nas_transport(&msg).unwrap();
//!
//! // Parse any NGAP message
//! use ogs_ngap::parser;
//! let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
//! ```

pub mod error;
pub mod types;
pub mod ie;
pub mod builder;
pub mod parser;

// Re-export key types for convenience
pub use error::{NgapError, NgapResult};
pub use types::*;
pub use parser::NgapMessage;

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_asn1c::ngap::cause::{Cause, CauseMisc, CauseNas, CauseRadioNetwork};

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
                slice_support_list: vec![types::SNssai {
                    sst: 1,
                    sd: None,
                }],
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
            setup_list: vec![],
            failed_list: vec![],
        };

        let bytes = builder::build_pdu_session_resource_setup_response(&msg).unwrap();
        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).unwrap();
        match decoded {
            NgapMessage::PduSessionResourceSetupResponse(resp) => {
                assert_eq!(resp.amf_ue_ngap_id, 100);
                assert_eq!(resp.ran_ue_ngap_id, 200);
            }
            other => panic!("Expected PduSessionResourceSetupResponse, got {other:?}"),
        }
    }
}
