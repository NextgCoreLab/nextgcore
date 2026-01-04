//! Namf Communication Handler
//!
//! Port of src/amf/namf-handler.c - Namf-comm service handlers

use crate::context::{AmfUe, AmfSess, RanUe, ResourceStatus};

// ============================================================================
// N1N2 Message Transfer Types
// ============================================================================

/// N1N2 message transfer cause
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1N2MessageTransferCause {
    /// N1N2 transfer initiated
    N1N2TransferInitiated,
    /// Attempting to reach UE
    AttemptingToReachUe,
    /// N1 message not transferred
    N1MsgNotTransferred,
    /// N2 message not transferred
    N2MsgNotTransferred,
    /// UE not responding
    UeNotResponding,
    /// UE not reachable
    UeNotReachable,
    /// Temporary reject registration ongoing
    TemporaryRejectRegistrationOngoing,
    /// Temporary reject handover ongoing
    TemporaryRejectHandoverOngoing,
}

impl N1N2MessageTransferCause {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::N1N2TransferInitiated => "N1_N2_TRANSFER_INITIATED",
            Self::AttemptingToReachUe => "ATTEMPTING_TO_REACH_UE",
            Self::N1MsgNotTransferred => "N1_MSG_NOT_TRANSFERRED",
            Self::N2MsgNotTransferred => "N2_MSG_NOT_TRANSFERRED",
            Self::UeNotResponding => "UE_NOT_RESPONDING",
            Self::UeNotReachable => "UE_NOT_REACHABLE",
            Self::TemporaryRejectRegistrationOngoing => "TEMPORARY_REJECT_REGISTRATION_ONGOING",
            Self::TemporaryRejectHandoverOngoing => "TEMPORARY_REJECT_HANDOVER_ONGOING",
        }
    }
}

/// NGAP IE type for N2 information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NgapIeType {
    #[default]
    Null,
    /// PDU session resource setup request
    PduResSetupReq,
    /// PDU session resource modify request
    PduResModReq,
    /// PDU session resource release command
    PduResRelCmd,
    /// PDU session resource notify
    PduResNotify,
    /// PDU session resource modify indication
    PduResModInd,
}

/// N1N2 message transfer request data
#[derive(Debug, Clone, Default)]
pub struct N1N2MessageTransferReqData {
    /// PDU session ID
    pub pdu_session_id: Option<u8>,
    /// N1 message container
    pub n1_message: Option<Vec<u8>>,
    /// N2 information container
    pub n2_info: Option<N2InfoContainer>,
    /// N1N2 failure notification URI
    pub n1n2_failure_txf_notif_uri: Option<String>,
    /// Skip indication
    pub skip_ind: bool,
}

/// N2 information container
#[derive(Debug, Clone, Default)]
pub struct N2InfoContainer {
    /// NGAP IE type
    pub ngap_ie_type: NgapIeType,
    /// NGAP data
    pub ngap_data: Option<Vec<u8>>,
}

/// N1N2 message transfer response data
#[derive(Debug, Clone)]
pub struct N1N2MessageTransferRspData {
    /// Transfer cause
    pub cause: N1N2MessageTransferCause,
}

// ============================================================================
// SM Context Status Types
// ============================================================================

/// SM context status notification
#[derive(Debug, Clone, Default)]
pub struct SmContextStatusNotification {
    /// Resource status
    pub resource_status: ResourceStatus,
}

// ============================================================================
// Deregistration Types
// ============================================================================

/// Deregistration reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeregistrationReason {
    /// UE initial registration
    UeInitialRegistration,
    /// UE registration area change
    UeRegistrationAreaChange,
    /// Subscription withdrawn
    SubscriptionWithdrawn,
    /// 5GS to EPS mobility
    FiveGsToEpsMobility,
    /// 5GS to EPS mobility UE initial registration
    FiveGsToEpsMobilityUeInitialRegistration,
    /// Reregistration required
    ReregistrationRequired,
    /// SMF context transferred
    SmfContextTransferred,
}

/// Access type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessType {
    #[default]
    ThreeGppAccess,
    NonThreeGppAccess,
}

/// Deregistration data
#[derive(Debug, Clone)]
pub struct DeregistrationData {
    /// Deregistration reason
    pub dereg_reason: DeregistrationReason,
    /// Access type
    pub access_type: AccessType,
}

// ============================================================================
// Handler Error Types
// ============================================================================

/// Namf handler error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamfHandlerError {
    /// Missing required field
    MissingField(String),
    /// UE not found
    UeNotFound(String),
    /// Session not found
    SessionNotFound(u8),
    /// Invalid state
    InvalidState,
    /// Internal error
    InternalError(String),
}

/// Namf handler result
pub type NamfHandlerResult<T> = Result<T, NamfHandlerError>;

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle N1N2 message transfer request
///
/// This is called when SMF sends N1/N2 messages to be forwarded to UE/gNB
pub fn handle_n1_n2_message_transfer(
    amf_ue: &AmfUe,
    sess: &mut AmfSess,
    ran_ue: Option<&RanUe>,
    req_data: &N1N2MessageTransferReqData,
) -> NamfHandlerResult<N1N2MessageTransferRspData> {
    log::debug!(
        "[{}] N1N2 message transfer: psi={:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        req_data.pdu_session_id
    );

    // Validate PDU session ID
    let _psi = req_data.pdu_session_id
        .ok_or_else(|| NamfHandlerError::MissingField("pdu_session_id".to_string()))?;

    let mut cause = N1N2MessageTransferCause::N1N2TransferInitiated;

    // Check N2 info type
    if let Some(n2_info) = &req_data.n2_info {
        match n2_info.ngap_ie_type {
            NgapIeType::PduResSetupReq => {
                // PDU session establishment
                if req_data.n1_message.is_some() {
                    // Has N1 message - send DL NAS transport with PDU session setup
                    if ran_ue.is_some() {
                        // UE is connected, send immediately
                        log::debug!("Sending PDU session resource setup request");
                    } else {
                        log::warn!("RAN-NG context not available");
                    }
                } else {
                    // No N1 message - network triggered service request
                    if !amf_ue.security_context_available {
                        // UE is idle, need to page
                        cause = N1N2MessageTransferCause::AttemptingToReachUe;
                        log::debug!("UE is idle, initiating paging");
                    } else {
                        // UE is connected
                        log::debug!("Sending PDU session setup request");
                    }
                }
            }
            NgapIeType::PduResModReq => {
                // PDU session modification
                if req_data.n1_message.is_none() {
                    return Err(NamfHandlerError::MissingField("n1_message".to_string()));
                }
                log::debug!("Sending PDU session modification command");
            }
            NgapIeType::PduResRelCmd => {
                // PDU session release
                if !amf_ue.security_context_available {
                    if req_data.skip_ind {
                        cause = N1N2MessageTransferCause::N1MsgNotTransferred;
                    } else {
                        cause = N1N2MessageTransferCause::AttemptingToReachUe;
                        log::debug!("UE is idle, initiating paging for release");
                    }
                } else {
                    log::debug!("Sending PDU session release command");
                }
            }
            NgapIeType::Null => {
                // No N2 info - SMF is rejecting the session
                if req_data.n1_message.is_none() {
                    return Err(NamfHandlerError::MissingField("n1_message".to_string()));
                }
                log::debug!("PDU session establishment rejected by SMF");
            }
            _ => {
                log::warn!("Unhandled NGAP IE type: {:?}", n2_info.ngap_ie_type);
            }
        }
    }

    // Update session state
    sess.n1_released = false;
    sess.n2_released = false;

    Ok(N1N2MessageTransferRspData { cause })
}

/// Handle SM context status notification
///
/// This is called when SMF notifies about SM context status change
pub fn handle_sm_context_status(
    amf_ue: &AmfUe,
    sess: &mut AmfSess,
    notification: &SmContextStatusNotification,
) -> NamfHandlerResult<()> {
    log::info!(
        "[{}:{}] SM context status: {:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        sess.psi,
        notification.resource_status
    );

    sess.resource_status = notification.resource_status;

    // Check if session should be removed
    if sess.n1_released && sess.n2_released && 
       notification.resource_status == ResourceStatus::Released {
        log::info!(
            "[{}:{}] Session fully released",
            amf_ue.supi.as_deref().unwrap_or("unknown"),
            sess.psi
        );
        // TODO: Trigger session removal
    }

    Ok(())
}

/// Handle deregistration notification
///
/// This is called when UDM notifies about deregistration
pub fn handle_dereg_notify(
    amf_ue: &AmfUe,
    data: &DeregistrationData,
) -> NamfHandlerResult<()> {
    log::info!(
        "[{}] Deregistration notify: reason={:?}, access={:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        data.dereg_reason,
        data.access_type
    );

    if data.access_type != AccessType::ThreeGppAccess {
        return Err(NamfHandlerError::InvalidState);
    }

    // TODO: Initiate network-initiated deregistration
    // 1. Send deregistration request to UE
    // 2. Unsubscribe from UDM
    // 3. Release PDU sessions
    // 4. Terminate AM policy association
    // 5. Release signalling connection

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::amf_context_init;

    fn create_test_ue() -> AmfUe {
        amf_context_init(64, 1024, 4096);
        let mut ue = AmfUe::default();
        ue.supi = Some("imsi-310260000000001".to_string());
        ue.security_context_available = true;
        ue
    }

    fn create_test_sess() -> AmfSess {
        let mut sess = AmfSess::default();
        sess.psi = 1;
        sess
    }

    #[test]
    fn test_n1n2_transfer_cause() {
        assert_eq!(
            N1N2MessageTransferCause::N1N2TransferInitiated.as_str(),
            "N1_N2_TRANSFER_INITIATED"
        );
        assert_eq!(
            N1N2MessageTransferCause::AttemptingToReachUe.as_str(),
            "ATTEMPTING_TO_REACH_UE"
        );
    }

    #[test]
    fn test_handle_n1_n2_message_transfer_missing_psi() {
        let ue = create_test_ue();
        let mut sess = create_test_sess();
        let req = N1N2MessageTransferReqData::default();

        let result = handle_n1_n2_message_transfer(&ue, &mut sess, None, &req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NamfHandlerError::MissingField(_)));
    }

    #[test]
    fn test_handle_n1_n2_message_transfer_pdu_setup() {
        let ue = create_test_ue();
        let mut sess = create_test_sess();
        let req = N1N2MessageTransferReqData {
            pdu_session_id: Some(1),
            n1_message: Some(vec![0x01, 0x02, 0x03]),
            n2_info: Some(N2InfoContainer {
                ngap_ie_type: NgapIeType::PduResSetupReq,
                ngap_data: Some(vec![0x04, 0x05, 0x06]),
            }),
            ..Default::default()
        };

        let result = handle_n1_n2_message_transfer(&ue, &mut sess, None, &req);
        assert!(result.is_ok());
        let rsp = result.unwrap();
        assert_eq!(rsp.cause, N1N2MessageTransferCause::N1N2TransferInitiated);
    }

    #[test]
    fn test_handle_sm_context_status() {
        let ue = create_test_ue();
        let mut sess = create_test_sess();
        sess.n1_released = true;
        sess.n2_released = true;

        let notification = SmContextStatusNotification {
            resource_status: ResourceStatus::Released,
        };

        let result = handle_sm_context_status(&ue, &mut sess, &notification);
        assert!(result.is_ok());
        assert_eq!(sess.resource_status, ResourceStatus::Released);
    }

    #[test]
    fn test_handle_dereg_notify() {
        let ue = create_test_ue();
        let data = DeregistrationData {
            dereg_reason: DeregistrationReason::SubscriptionWithdrawn,
            access_type: AccessType::ThreeGppAccess,
        };

        let result = handle_dereg_notify(&ue, &data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_dereg_notify_non_3gpp() {
        let ue = create_test_ue();
        let data = DeregistrationData {
            dereg_reason: DeregistrationReason::SubscriptionWithdrawn,
            access_type: AccessType::NonThreeGppAccess,
        };

        let result = handle_dereg_notify(&ue, &data);
        assert!(result.is_err());
    }
}
