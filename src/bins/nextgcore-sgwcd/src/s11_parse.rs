//! SGWC S11 Message Parsers (TS 29.274)
//!
//! Strict receive-side validation: every IE marked Mandatory in the TS 29.274
//! message tables is required and produces `MANDATORY_IE_MISSING` (cause 70)
//! with the offending IE type when absent; conditional IEs needed by the SGW
//! procedures produce `CONDITIONAL_IE_MISSING` (cause 71).

use ogs_gtp::v2::ie::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2EbiIe,
    Gtp2FTeidIe, Gtp2IeType, Gtp2IndicationIe, Gtp2PaaIe,
};
use ogs_gtp::v2::message::Gtp2Message;

use crate::s11_handler::gtp_cause;

/// Validation failure: cause value plus the offending IE for the Cause IE
/// "offending IE" fields (TS 29.274 Section 8.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeError {
    pub cause: u8,
    pub offending_ie_type: u8,
}

impl IeError {
    pub fn missing_mandatory(ie_type: Gtp2IeType) -> Self {
        Self {
            cause: gtp_cause::MANDATORY_IE_MISSING,
            offending_ie_type: ie_type as u8,
        }
    }

    pub fn missing_conditional(ie_type: Gtp2IeType) -> Self {
        Self {
            cause: gtp_cause::CONDITIONAL_IE_MISSING,
            offending_ie_type: ie_type as u8,
        }
    }

    pub fn incorrect_mandatory(ie_type: Gtp2IeType) -> Self {
        Self {
            cause: gtp_cause::MANDATORY_IE_INCORRECT,
            offending_ie_type: ie_type as u8,
        }
    }
}

fn require(
    msg: &Gtp2Message,
    ie_type: Gtp2IeType,
    instance: u8,
) -> Result<&ogs_gtp::v2::ie::Gtp2Ie, IeError> {
    msg.get_ie(ie_type as u8, instance)
        .ok_or_else(|| IeError::missing_mandatory(ie_type))
}

// ============================================================================
// Create Session Request (TS 29.274 Table 7.2.1-1)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ParsedBearerToCreate {
    pub ebi: u8,
    pub qos: Gtp2BearerQosIe,
}

#[derive(Debug, Clone)]
pub struct ParsedCreateSessionRequest {
    pub imsi: Vec<u8>,
    pub rat_type: u8,
    pub sender_fteid: Gtp2FTeidIe,
    pub apn: String,
    pub bearer: ParsedBearerToCreate,
    pub pdn_type: Option<u8>,
    pub paa: Option<Gtp2PaaIe>,
    pub ambr: Option<Gtp2AmbrIe>,
    pub indication: Option<Gtp2IndicationIe>,
}

pub fn parse_create_session_request(
    msg: &Gtp2Message,
) -> Result<ParsedCreateSessionRequest, IeError> {
    // IMSI: conditional in the spec, but mandatory for non-emergency attach;
    // this SGW does not support emergency sessions, so require it.
    let imsi = require(msg, Gtp2IeType::Imsi, 0)?.value.to_vec();
    if imsi.is_empty() {
        return Err(IeError::incorrect_mandatory(Gtp2IeType::Imsi));
    }

    // RAT Type (M)
    let rat_ie = require(msg, Gtp2IeType::RatType, 0)?;
    let rat_type = *rat_ie
        .value
        .first()
        .ok_or_else(|| IeError::incorrect_mandatory(Gtp2IeType::RatType))?;

    // Sender F-TEID for control plane (M)
    let fteid_ie = require(msg, Gtp2IeType::FTeid, 0)?;
    let sender_fteid = Gtp2FTeidIe::decode(&fteid_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::FTeid))?;

    // APN (M)
    let apn_ie = require(msg, Gtp2IeType::Apn, 0)?;
    let apn = Gtp2ApnIe::decode(&apn_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::Apn))?
        .to_string();
    if apn.is_empty() {
        return Err(IeError::incorrect_mandatory(Gtp2IeType::Apn));
    }

    // Bearer Contexts to be created (M) with EBI (M) and Bearer QoS (M)
    let bc_ie = require(msg, Gtp2IeType::BearerContext, 0)?;
    let bc = Gtp2BearerContextIe::decode(&bc_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::BearerContext))?;
    let ebi = bc
        .ebi()
        .map_err(|_| IeError::missing_mandatory(Gtp2IeType::Ebi))?;
    let qos = bc
        .bearer_qos()
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::BearerQos))?
        .ok_or_else(|| IeError::missing_mandatory(Gtp2IeType::BearerQos))?;

    // Conditional IEs
    let pdn_type = msg
        .get_ie(Gtp2IeType::PdnType as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .map(|v| v & 0x07);
    let paa = msg
        .get_ie(Gtp2IeType::Paa as u8, 0)
        .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok());
    let ambr = msg
        .get_ie(Gtp2IeType::Ambr as u8, 0)
        .and_then(|ie| Gtp2AmbrIe::decode(&ie.value).ok());
    let indication = msg
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .and_then(|ie| Gtp2IndicationIe::decode(&ie.value).ok());

    Ok(ParsedCreateSessionRequest {
        imsi,
        rat_type,
        sender_fteid,
        apn,
        bearer: ParsedBearerToCreate { ebi, qos },
        pdn_type,
        paa,
        ambr,
        indication,
    })
}

// ============================================================================
// Modify Bearer Request (TS 29.274 Table 7.2.7-1)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ParsedModifyBearerRequest {
    /// Bearer Context to be modified: (EBI, S1 eNodeB F-TEID)
    pub bearer: Option<(u8, Option<Gtp2FTeidIe>)>,
    pub indication: Option<Gtp2IndicationIe>,
}

pub fn parse_modify_bearer_request(
    msg: &Gtp2Message,
) -> Result<ParsedModifyBearerRequest, IeError> {
    let bearer = match msg.get_ie(Gtp2IeType::BearerContext as u8, 0) {
        Some(bc_ie) => {
            let bc = Gtp2BearerContextIe::decode(&bc_ie.value)
                .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::BearerContext))?;
            // EBI is mandatory inside a Bearer Context grouped IE
            let ebi = bc
                .ebi()
                .map_err(|_| IeError::missing_mandatory(Gtp2IeType::Ebi))?;
            let enb_fteid = bc
                .fteid(0)
                .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::FTeid))?;
            Some((ebi, enb_fteid))
        }
        None => None,
    };

    let indication = msg
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .and_then(|ie| Gtp2IndicationIe::decode(&ie.value).ok());

    Ok(ParsedModifyBearerRequest { bearer, indication })
}

// ============================================================================
// Delete Session Request (TS 29.274 Table 7.2.9.1-1)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ParsedDeleteSessionRequest {
    pub linked_ebi: u8,
    /// Scope Indication flag (SI) from the Indication IE
    pub scope_indication: bool,
}

pub fn parse_delete_session_request(
    msg: &Gtp2Message,
) -> Result<ParsedDeleteSessionRequest, IeError> {
    // Linked EPS Bearer ID: conditional in the spec but required on S11
    // (the MME shall include it)
    let ebi_ie = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .ok_or_else(|| IeError::missing_conditional(Gtp2IeType::Ebi))?;
    let linked_ebi = Gtp2EbiIe::decode(&ebi_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::Ebi))?
        .ebi;

    let scope_indication = msg
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .and_then(|ie| Gtp2IndicationIe::decode(&ie.value).ok())
        .map(|ind| ind.si)
        .unwrap_or(false);

    Ok(ParsedDeleteSessionRequest {
        linked_ebi,
        scope_indication,
    })
}

// ============================================================================
// Downlink Data Notification Acknowledge (TS 29.274 Table 7.2.11.2-1)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ParsedDdnAck {
    pub cause: u8,
    pub data_notification_delay: Option<u8>,
}

pub fn parse_downlink_data_notification_ack(msg: &Gtp2Message) -> Result<ParsedDdnAck, IeError> {
    // Cause (M)
    let cause_ie = require(msg, Gtp2IeType::Cause, 0)?;
    let cause = Gtp2CauseIe::decode(&cause_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::Cause))?
        .cause;

    let data_notification_delay = msg
        .get_ie(Gtp2IeType::DelayValue as u8, 0)
        .and_then(|ie| ie.value.first().copied());

    Ok(ParsedDdnAck {
        cause,
        data_notification_delay,
    })
}

/// Downlink Data Notification Failure Indication (TS 29.274 Section 7.2.12):
/// Cause is mandatory.
pub fn parse_downlink_data_notification_failure_indication(
    msg: &Gtp2Message,
) -> Result<u8, IeError> {
    let cause_ie = require(msg, Gtp2IeType::Cause, 0)?;
    Ok(Gtp2CauseIe::decode(&cause_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::Cause))?
        .cause)
}

// ============================================================================
// Generic triggered messages carrying Cause + Bearer Contexts
// (Create/Update/Delete Bearer Response from the MME)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ParsedBearerResponse {
    pub cause: u8,
    pub bearer_ebi: Option<u8>,
    pub bearer_cause: Option<u8>,
}

pub fn parse_bearer_response(msg: &Gtp2Message) -> Result<ParsedBearerResponse, IeError> {
    // Cause (M)
    let cause_ie = require(msg, Gtp2IeType::Cause, 0)?;
    let cause = Gtp2CauseIe::decode(&cause_ie.value)
        .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::Cause))?
        .cause;

    let (bearer_ebi, bearer_cause) = match msg.get_ie(Gtp2IeType::BearerContext as u8, 0) {
        Some(bc_ie) => {
            let bc = Gtp2BearerContextIe::decode(&bc_ie.value)
                .map_err(|_| IeError::incorrect_mandatory(Gtp2IeType::BearerContext))?;
            let ebi = bc.ebi().ok();
            let bearer_cause = bc.cause().ok().flatten().map(|c| c.cause);
            (ebi, bearer_cause)
        }
        None => (None, None),
    };

    Ok(ParsedBearerResponse {
        cause,
        bearer_ebi,
        bearer_cause,
    })
}

// ============================================================================
// Tests (strict-peer: missing mandatory IEs are rejected)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_gtp::v2::header::{Gtp2Header, Gtp2MessageType};
    use ogs_gtp::v2::ie::Gtp2Ie;

    fn csr_message() -> Gtp2Message {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            0,
            1,
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &[0x21, 0x43, 0x65],
        ));
        msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::RatType as u8, 0, &[6]));
        msg.add_ie(Gtp2FTeidIe::new_ipv4(10, 0x1111, [10, 0, 0, 1]).to_ie(0));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Apn as u8,
            0,
            &[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't'],
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        msg.add_bearer_context(0, &bc);
        msg
    }

    #[test]
    fn test_parse_create_session_request_complete() {
        let msg = csr_message();
        let parsed = parse_create_session_request(&msg).unwrap();
        assert_eq!(parsed.rat_type, 6);
        assert_eq!(parsed.apn, "internet");
        assert_eq!(parsed.bearer.ebi, 5);
        assert_eq!(parsed.bearer.qos.qci, 9);
        assert_eq!(parsed.sender_fteid.teid, 0x1111);
    }

    #[test]
    fn test_parse_create_session_request_rejects_each_missing_mandatory_ie() {
        // (IE type to remove, expected offending IE in the reject)
        let cases = [
            (Gtp2IeType::Imsi as u8, Gtp2IeType::Imsi as u8),
            (Gtp2IeType::RatType as u8, Gtp2IeType::RatType as u8),
            (Gtp2IeType::FTeid as u8, Gtp2IeType::FTeid as u8),
            (Gtp2IeType::Apn as u8, Gtp2IeType::Apn as u8),
            (
                Gtp2IeType::BearerContext as u8,
                Gtp2IeType::BearerContext as u8,
            ),
        ];
        for (remove, offending) in cases {
            let mut msg = csr_message();
            msg.ies.retain(|ie| ie.ie_type != remove);
            let err = parse_create_session_request(&msg).unwrap_err();
            assert_eq!(err.cause, gtp_cause::MANDATORY_IE_MISSING);
            assert_eq!(err.offending_ie_type, offending);
        }
    }

    #[test]
    fn test_parse_create_session_request_rejects_bearer_without_ebi() {
        let mut msg = csr_message();
        msg.ies
            .retain(|ie| ie.ie_type != Gtp2IeType::BearerContext as u8);
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        msg.add_bearer_context(0, &bc);

        let err = parse_create_session_request(&msg).unwrap_err();
        assert_eq!(err.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(err.offending_ie_type, Gtp2IeType::Ebi as u8);
    }

    #[test]
    fn test_parse_create_session_request_rejects_bearer_without_qos() {
        let mut msg = csr_message();
        msg.ies
            .retain(|ie| ie.ie_type != Gtp2IeType::BearerContext as u8);
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        msg.add_bearer_context(0, &bc);

        let err = parse_create_session_request(&msg).unwrap_err();
        assert_eq!(err.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(err.offending_ie_type, Gtp2IeType::BearerQos as u8);
    }

    #[test]
    fn test_parse_modify_bearer_request() {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            1,
            2,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(0, 0x2222, [10, 0, 0, 2]));
        msg.add_bearer_context(0, &bc);

        let parsed = parse_modify_bearer_request(&msg).unwrap();
        let (ebi, fteid) = parsed.bearer.unwrap();
        assert_eq!(ebi, 5);
        assert_eq!(fteid.unwrap().teid, 0x2222);

        // No bearer context at all is allowed (e.g. TAU without bearer change)
        let msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            1,
            3,
        ));
        assert!(parse_modify_bearer_request(&msg).unwrap().bearer.is_none());
    }

    #[test]
    fn test_parse_modify_bearer_request_rejects_bearer_without_ebi() {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            1,
            4,
        ));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_fteid(0, &Gtp2FTeidIe::new_ipv4(0, 0x2222, [10, 0, 0, 2]));
        msg.add_bearer_context(0, &bc);

        let err = parse_modify_bearer_request(&msg).unwrap_err();
        assert_eq!(err.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(err.offending_ie_type, Gtp2IeType::Ebi as u8);
    }

    #[test]
    fn test_parse_delete_session_request() {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            1,
            5,
        ));
        msg.add_ie(Gtp2EbiIe::new(5).to_ie(0));
        msg.add_ie(
            Gtp2IndicationIe {
                si: true,
                ..Default::default()
            }
            .to_ie(0),
        );

        let parsed = parse_delete_session_request(&msg).unwrap();
        assert_eq!(parsed.linked_ebi, 5);
        assert!(parsed.scope_indication);

        // Missing linked EBI is rejected
        let msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            1,
            6,
        ));
        let err = parse_delete_session_request(&msg).unwrap_err();
        assert_eq!(err.cause, gtp_cause::CONDITIONAL_IE_MISSING);
        assert_eq!(err.offending_ie_type, Gtp2IeType::Ebi as u8);
    }

    #[test]
    fn test_parse_ddn_ack_requires_cause() {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            1,
            7,
        ));
        let err = parse_downlink_data_notification_ack(&msg).unwrap_err();
        assert_eq!(err.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(err.offending_ie_type, Gtp2IeType::Cause as u8);

        msg.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        let parsed = parse_downlink_data_notification_ack(&msg).unwrap();
        assert_eq!(parsed.cause, gtp_cause::REQUEST_ACCEPTED);
    }

    #[test]
    fn test_parse_ddn_failure_indication_requires_cause() {
        let msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationFailureIndication as u8,
            1,
            8,
        ));
        assert!(parse_downlink_data_notification_failure_indication(&msg).is_err());
    }

    #[test]
    fn test_parse_bearer_response() {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            1,
            9,
        ));
        // Missing Cause is rejected
        assert_eq!(
            parse_bearer_response(&msg).unwrap_err().cause,
            gtp_cause::MANDATORY_IE_MISSING
        );

        msg.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(6);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));
        msg.add_bearer_context(0, &bc);

        let parsed = parse_bearer_response(&msg).unwrap();
        assert_eq!(parsed.cause, gtp_cause::REQUEST_ACCEPTED);
        assert_eq!(parsed.bearer_ebi, Some(6));
        assert_eq!(parsed.bearer_cause, Some(gtp_cause::REQUEST_ACCEPTED));
    }
}
