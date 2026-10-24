//! Namf Communication Handler
//!
//! Port of src/amf/namf-handler.c - Namf-comm service handlers

use crate::context::{amf_self, AmfSess, AmfUe, PagingContext, RanUe, ResourceStatus};

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
    /// NRPPa PDU (LCS positioning, TS 23.273) — relayed transparently to the
    /// NG-RAN over an NGAP `*NRPPaTransport` message, never a PDU-session IE.
    Nrppa,
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
    /// What the NGAP task must send to a CM-CONNECTED UE now (#666). The caller
    /// enqueues it; returned rather than enqueued here so the decision is
    /// testable without the process-wide queue.
    pub deliver_now: Option<crate::context::PendingConnectedDownlink>,
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
// Event Exposure Types (B18.12)
// ============================================================================

/// Event type for Namf-evts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmfEventType {
    /// Location report
    LocationReport,
    /// Presence in AOI report
    PresenceInAoiReport,
    /// Timezone report
    TimezoneReport,
    /// Access type report
    AccessTypeReport,
    /// Registration state report
    RegistrationStateReport,
    /// Connectivity state report
    ConnectivityStateReport,
    /// Reachability report
    ReachabilityReport,
    /// Communication failure report
    CommunicationFailureReport,
    /// UE mobility report
    UeMobilityReport,
    /// PDU session status report
    PduSessStatusReport,
}

impl AmfEventType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocationReport => "LOCATION_REPORT",
            Self::PresenceInAoiReport => "PRESENCE_IN_AOI_REPORT",
            Self::TimezoneReport => "TIMEZONE_REPORT",
            Self::AccessTypeReport => "ACCESS_TYPE_REPORT",
            Self::RegistrationStateReport => "REGISTRATION_STATE_REPORT",
            Self::ConnectivityStateReport => "CONNECTIVITY_STATE_REPORT",
            Self::ReachabilityReport => "REACHABILITY_REPORT",
            Self::CommunicationFailureReport => "COMMUNICATION_FAILURE_REPORT",
            Self::UeMobilityReport => "UE_MOBILITY_REPORT",
            Self::PduSessStatusReport => "PDU_SESS_STATUS_REPORT",
        }
    }
}

/// Event subscription
#[derive(Debug, Clone)]
pub struct AmfEventSubscription {
    /// Event type
    pub event_type: AmfEventType,
    /// Immediate flag (report immediately)
    pub immediate_flag: bool,
    /// Area of interest list
    pub area_list: Option<Vec<AreaOfInterest>>,
    /// Location filter list
    pub location_filter_list: Option<Vec<LocationFilter>>,
}

/// Area of interest
#[derive(Debug, Clone)]
pub struct AreaOfInterest {
    /// TAI list
    pub tai_list: Vec<TrackingAreaId>,
    /// NCGI list
    pub ncgi_list: Vec<NrCellGlobalId>,
    /// Global RAN node ID list
    pub global_ran_node_id_list: Vec<GlobalRanNodeId>,
}

/// Tracking area identity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackingAreaId {
    /// PLMN ID
    pub plmn_id: String,
    /// TAC
    pub tac: u32,
}

/// NR cell global identity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NrCellGlobalId {
    /// PLMN ID
    pub plmn_id: String,
    /// Cell ID
    pub cell_id: u64,
}

/// Global RAN node ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalRanNodeId {
    /// PLMN ID
    pub plmn_id: String,
    /// Node ID
    pub node_id: String,
}

/// Location filter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationFilter {
    /// TAI
    Tai,
    /// Cell ID
    CellId,
    /// RAN node ID
    RanNodeId,
}

/// Event notification
#[derive(Debug, Clone)]
pub struct AmfEventNotification {
    /// Event type
    pub event_type: AmfEventType,
    /// Event state
    pub state: AmfEventState,
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// SUPI
    pub supi: String,
    /// Additional info
    pub additional_info: Option<AmfEventAdditionalInfo>,
}

/// Event state
#[derive(Debug, Clone)]
pub enum AmfEventState {
    /// Active
    Active,
    /// Idle
    Idle,
    /// Connected
    Connected,
    /// Location info
    Location {
        tai: TrackingAreaId,
        ncgi: Option<NrCellGlobalId>,
    },
}

/// Additional event information
#[derive(Debug, Clone)]
pub struct AmfEventAdditionalInfo {
    /// Access type
    pub access_type: Option<AccessType>,
    /// Timezone
    pub timezone: Option<String>,
    /// PDU session ID
    pub pdu_session_id: Option<u8>,
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
    // Kept for the callers' signature; the CM state comes from `cm_idle`, and the
    // NGAP task resolves the UE's NG connection when it delivers (#757).
    _ran_ue: Option<&RanUe>,
    cm_idle: bool,
    req_data: &N1N2MessageTransferReqData,
) -> NamfHandlerResult<N1N2MessageTransferRspData> {
    log::debug!(
        "[{}] N1N2 message transfer: psi={:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        req_data.pdu_session_id
    );

    // Validate PDU session ID
    let _psi = req_data
        .pdu_session_id
        .ok_or_else(|| NamfHandlerError::MissingField("pdu_session_id".to_string()))?;

    let mut cause = N1N2MessageTransferCause::N1N2TransferInitiated;

    // Check N2 info type
    if let Some(n2_info) = &req_data.n2_info {
        match n2_info.ngap_ie_type {
            NgapIeType::PduResSetupReq => {
                // A CM-CONNECTED UE gets the PDU SESSION RESOURCE SETUP REQUEST now
                // (`connected_downlink_for`, #757). A CM-IDLE one is paged (TS 23.502
                // §4.2.3.3 step 3a) and the session rides the Service Request's Initial
                // Context Setup. CM-IDLE here is as the NGAP layer tracks it
                // (TS 23.501 §5.3.3.2.2), NOT the security flag, which a registered
                // idle UE still has.
                if cm_idle {
                    cause = N1N2MessageTransferCause::AttemptingToReachUe;
                    initiate_paging_for_idle_ue(
                        amf_ue,
                        Some(sess),
                        req_data.n1_message.clone(),
                        n2_info.ngap_data.clone(),
                        PagedN2::Setup,
                        req_data.pdu_session_id,
                        req_data.n1n2_failure_txf_notif_uri.as_deref(),
                    );
                }
            }
            NgapIeType::PduResModReq => {
                // Network-requested PDU Session Modification (TS 23.502 §4.3.3.2
                // step 3b): the N2 transfer and the N1 PDU SESSION MODIFICATION
                // COMMAND both go in one PDU SESSION RESOURCE MODIFY REQUEST
                // (TS 38.413 §8.2.3), so both are mandatory.
                if req_data.n1_message.is_none() {
                    return Err(NamfHandlerError::MissingField("n1_message".to_string()));
                }
                if n2_info.ngap_data.is_none() {
                    return Err(NamfHandlerError::MissingField(
                        "n2InfoContainer.smInfo.n2InfoContent.ngapData".to_string(),
                    ));
                }
                if cm_idle {
                    cause = N1N2MessageTransferCause::AttemptingToReachUe;
                    initiate_paging_for_idle_ue(
                        amf_ue,
                        Some(sess),
                        req_data.n1_message.clone(),
                        n2_info.ngap_data.clone(),
                        PagedN2::Modify,
                        req_data.pdu_session_id,
                        req_data.n1n2_failure_txf_notif_uri.as_deref(),
                    );
                }
            }
            NgapIeType::PduResRelCmd => {
                // PDU session release
                if cm_idle {
                    if req_data.skip_ind {
                        cause = N1N2MessageTransferCause::N1MsgNotTransferred;
                    } else {
                        cause = N1N2MessageTransferCause::AttemptingToReachUe;
                        initiate_paging_for_idle_ue(
                            amf_ue,
                            Some(sess),
                            req_data.n1_message.clone(),
                            n2_info.ngap_data.clone(),
                            PagedN2::Release,
                            req_data.pdu_session_id,
                            req_data.n1n2_failure_txf_notif_uri.as_deref(),
                        );
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

    // N1-only transfer to a CM-IDLE UE (TS 23.502 §4.2.3.3 step 3a, TS 29.518
    // §5.2.2.3.1): the AMF pages and answers ATTEMPTING_TO_REACH_UE, and the N1
    // is delivered once the UE's Service Request arrives (#518). Before #518 this
    // case fell through with N1_N2_TRANSFER_INITIATED and the message was lost.
    if req_data.n2_info.is_none() && req_data.n1_message.is_some() && cm_idle {
        if req_data.skip_ind {
            cause = N1N2MessageTransferCause::N1MsgNotTransferred;
        } else {
            cause = N1N2MessageTransferCause::AttemptingToReachUe;
            initiate_paging_for_idle_ue(
                amf_ue,
                Some(sess),
                req_data.n1_message.clone(),
                None,
                PagedN2::Setup,
                req_data.pdu_session_id,
                req_data.n1n2_failure_txf_notif_uri.as_deref(),
            );
        }
    }

    // #666: a CM-CONNECTED UE gets the transfer NOW. Before #666 these branches
    // logged "Sending ..." and answered N1_N2_TRANSFER_INITIATED while nothing
    // reached NGAP, so every network-initiated 5GSM message to a connected UE
    // (an SMF-initiated release, a T3591/T3592 retransmission) was lost.
    let deliver_now = if cause == N1N2MessageTransferCause::N1N2TransferInitiated {
        connected_downlink_for(amf_ue, cm_idle, req_data)
    } else {
        None
    };

    // Update session state
    sess.n1_released = false;
    sess.n2_released = false;

    Ok(N1N2MessageTransferRspData { cause, deliver_now })
}

/// What a N1N2MessageTransfer must deliver to a CM-CONNECTED UE now (#666), or
/// `None` when the transfer is not for a connected UE or carries nothing this
/// path delivers.
///
/// Delivered: an N1-only transfer (DOWNLINK NAS TRANSPORT) and a PDU Session
/// Resource Release (PDU SESSION RESOURCE RELEASE COMMAND, then the N1), the same
/// two shapes a paged transfer is delivered in after the Service Request.
/// PDU_RES_SETUP_REQ and PDU_RES_MOD_REQ for a connected UE are not covered here.
pub fn connected_downlink_for(
    amf_ue: &AmfUe,
    cm_idle: bool,
    req_data: &N1N2MessageTransferReqData,
) -> Option<crate::context::PendingConnectedDownlink> {
    use crate::context::ConnectedN2;
    if cm_idle {
        return None;
    }
    let psi = req_data.pdu_session_id?;
    let n2 = match req_data.n2_info.as_ref() {
        None => ConnectedN2::None,
        Some(n2) => match n2.ngap_ie_type {
            NgapIeType::PduResRelCmd => ConnectedN2::Release,
            NgapIeType::PduResSetupReq => ConnectedN2::Setup(n2.ngap_data.clone()),
            NgapIeType::PduResModReq => ConnectedN2::Modify(n2.ngap_data.clone()?),
            // Null (an N1-only rejection carried with an empty N2 container) is
            // the N1 alone.
            NgapIeType::Null => ConnectedN2::None,
            _ => {
                log::warn!(
                    "UE {}: N1N2 transfer with ngapIeType {:?} for PSI {psi} has no NGAP \
                     procedure toward the gNB; only its N1 (if any) is delivered",
                    amf_ue.id,
                    n2.ngap_ie_type
                );
                ConnectedN2::None
            }
        },
    };
    if req_data.n1_message.is_none() && n2 == ConnectedN2::None {
        return None;
    }
    Some(crate::context::PendingConnectedDownlink {
        amf_ue_ngap_id: amf_ue.id,
        pdu_session_id: psi,
        n1: req_data.n1_message.clone(),
        n2,
        failure_notify_uri: req_data.n1n2_failure_txf_notif_uri.clone(),
    })
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
    if sess.n1_released
        && sess.n2_released
        && notification.resource_status == ResourceStatus::Released
    {
        log::info!(
            "[{}:{}] Session fully released",
            amf_ue.supi.as_deref().unwrap_or("unknown"),
            sess.psi
        );
        // Note: Trigger session removal
        // Session cleanup handled by AmfContext::remove_session when both N1/N2 released
    }

    Ok(())
}

/// Whether a Nudm_UECM DeregistrationNotification reason makes the AMF send its
/// DEREGISTRATION REQUEST with de-registration type "re-registration required"
/// (TS 24.501 §9.11.3.20 bit 3).
///
/// - `REREGISTRATION_REQUIRED` (TS 29.503 Table 6.2.6.3.3-1): the UDM uses it when
///   a UDR data-change notification carries `purgeFlag` and
///   `reRegistrationRequired` both true on the stored `Amf3GppAccessRegistration`
///   (TS 29.503 §6.2.6.2.2), i.e. the UE has to register again.
///   The reason exists to say exactly that, so the UE is told to re-register
///   (#580: it used to be sent "re-registration not required", leaving the UE
///   deregistered instead of re-registered).
/// - `UE_INITIAL_REGISTRATION` is NOT here: it is a local deregistration with no
///   NAS message at all (#602, see [`dereg_reason_is_local`]).
///
/// No 5GMM cause is set for these: with "re-registration required" the UE
/// ignores the 5GMM cause IE (TS 24.501 §5.5.2.3.2).
pub fn dereg_reason_requires_reregistration(reason: DeregistrationReason) -> bool {
    matches!(reason, DeregistrationReason::ReregistrationRequired)
}

/// Whether a Nudm_UECM DeregistrationNotification reason makes this AMF deregister
/// the UE LOCALLY, sending it no NAS message (#602).
///
/// `UE_INITIAL_REGISTRATION` (TS 29.503 Table 6.2.6.3.3-1): "the deregistration in
/// the old AMF is due to a new AMF serving the UE during an initial registration".
/// TS 23.502 §4.2.2.2.2 step 14d has the old AMF remove the UE context and release
/// the SM contexts at the SMF(s) (and, per §4.16.3.2 / §4.16.13.1, its policy
/// associations). Neither clause has it signal the UE, which now belongs to the new
/// AMF. A DEREGISTRATION REQUEST that still reached the UE over a live N2 context
/// would make it deregister from the NEW AMF and register again, which can loop.
///
/// Operator decision (2026-10-21, on #602): local deregistration.
pub fn dereg_reason_is_local(reason: DeregistrationReason) -> bool {
    matches!(reason, DeregistrationReason::UeInitialRegistration)
}

/// Handle a Nudm_UECM DeregistrationNotification (TS 29.503 §5.3.2.3.2).
///
/// WSB-4: this now has a real effect. When the notification targets 3GPP
/// access it enqueues a deregistration onto the AMF context queue, which the
/// NGAP server task drains (`ngap_path::process_network_deregs`):
///
/// - a LOCAL one for `UE_INITIAL_REGISTRATION` (#602, [`dereg_reason_is_local`]):
///   no NAS; SM contexts, AM and UE policy associations and any live N2 context
///   are released and the UE context is removed
///   (`ngap_path::local_deregistration`);
/// - otherwise a network-initiated one: the protected DEREGISTRATION REQUEST
///   (TS 24.501 §5.5.2.3) + T3522
///   (`ngap_path::send_network_initiated_deregistration`), with the teardown on
///   the Deregistration Accept / T3522 exhaustion.
///
/// `reregistration_required` (TS 23.502 §4.2.2.3.3 step 2, TS 24.501 §5.5.2.3.1):
/// see [`dereg_reason_requires_reregistration`] for which reasons set it.
///
/// A non-3GPP-access notification is accepted (the SBI callback answers 204)
/// but not actioned here — this AMF models only the 3GPP-access context.
pub fn handle_dereg_notify(amf_ue: &AmfUe, data: &DeregistrationData) -> NamfHandlerResult<()> {
    log::info!(
        "[{}] Deregistration notify: reason={:?}, access={:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        data.dereg_reason,
        data.access_type
    );

    if data.access_type != AccessType::ThreeGppAccess {
        log::info!(
            "[{}] Non-3GPP-access dereg-notify accepted without 3GPP action",
            amf_ue.supi.as_deref().unwrap_or("unknown")
        );
        return Ok(());
    }

    let local = dereg_reason_is_local(data.dereg_reason);
    let reregistration_required = dereg_reason_requires_reregistration(data.dereg_reason);

    if let Ok(context) = crate::context::amf_self().read() {
        context.network_dereg_add(crate::context::PendingNetworkDereg {
            amf_ue_ngap_id: amf_ue.id,
            reregistration_required,
            gmm_cause: None,
            local,
        });
    }
    log::info!(
        "[{}] {} deregistration enqueued (reregistration_required={})",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        if local { "Local" } else { "Network-initiated" },
        reregistration_required
    );

    Ok(())
}

/// Handle event subscription (Namf_EventExposure_Subscribe)
///
/// Persists the subscription in the AMF context (survives across requests)
/// and returns the assigned subscription ID. HTTP-level subscriptions are
/// handled by `namf_server::handle_event_subscription_create`, which uses
/// the same context store.
pub fn handle_event_subscribe(
    subscription: &AmfEventSubscription,
    callback_uri: &str,
) -> NamfHandlerResult<String> {
    log::info!(
        "Event subscription request: event={:?}, callback={}",
        subscription.event_type,
        nextgcore_sbi::log_redact::redact_last_segment(callback_uri)
    );

    // Validate subscription
    if callback_uri.is_empty() {
        return Err(NamfHandlerError::MissingField("callback_uri".to_string()));
    }

    // Generate subscription ID and persist in the AMF context
    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let stored = crate::context::EventSubscription {
        subscription_id: subscription_id.clone(),
        notify_uri: callback_uri.to_string(),
        notify_correlation_id: subscription_id.clone(),
        nf_id: String::new(),
        event_types: vec![subscription.event_type.as_str().to_string()],
        supi: None,
        // This internal entry point takes no target identity at all and keys
        // `any_ue`, so the #74 targeting members are absent by construction.
        gpsi: None,
        pei: None,
        group_id: None,
        any_ue: true,
        expiry: None,
        // No subscription-change callback either (#397): this entry point takes a
        // single `callback_uri` and has no second endpoint to record.
        subs_change_notify_uri: None,
        subs_change_notify_correlation_id: None,
        // #400: this entry point's `AreaOfInterest` type (below) is NOT the stored
        // area model. `AmfEventSubscription::area_list` here is only ever `None` — the
        // struct is constructed in three places, all inside `mod tests` — so
        // translating it would build a converter for a shape no production caller
        // produces. The HTTP surface
        // (`namf_server::handle_event_subscription_create`) is where a real
        // `AmfEventArea` arrives and is parsed into `context::EventArea`.
        areas: Vec::new(),
        reported_presence: std::collections::HashMap::new(),
        reporting_threshold: None,
    };

    let ctx = amf_self();
    let added = ctx
        .read()
        .map(|context| context.event_subscription_add(stored))
        .unwrap_or(false);
    if !added {
        return Err(NamfHandlerError::InternalError(
            "failed to persist event subscription".to_string(),
        ));
    }

    log::debug!(
        "Created event subscription: id={}, type={:?}",
        subscription_id,
        subscription.event_type
    );

    Ok(subscription_id)
}

/// Handle event notification (send to subscriber)
///
/// Looks up the persisted subscription and delivers the notification via
/// HTTP POST to its notify URI on a background task (bounded timeouts).
/// Returns an error when the subscription does not exist.
pub fn send_event_notification(
    subscription_id: &str,
    notification: &AmfEventNotification,
) -> NamfHandlerResult<()> {
    log::info!(
        "[{}] Sending event notification: type={:?}, state={:?}",
        notification.supi,
        notification.event_type,
        notification.state
    );

    let ctx = amf_self();
    let sub = ctx
        .read()
        .ok()
        .and_then(|context| context.event_subscription_find(subscription_id));
    let Some(_sub) = sub else {
        return Err(NamfHandlerError::UeNotFound(format!(
            "subscription {subscription_id}"
        )));
    };

    // Delegate the actual HTTP delivery to the namf_server event path so
    // both the legacy and HTTP entry points share one delivery pipeline.
    // PLMN strings in the legacy types are combined MCC+MNC digits
    let split_plmn = |plmn: &str| {
        let mcc: String = plmn.chars().take(3).collect();
        let mnc: String = plmn.chars().skip(3).collect();
        serde_json::json!({ "mcc": mcc, "mnc": mnc })
    };
    let extra = match &notification.state {
        AmfEventState::Location { tai, ncgi } => {
            let mut location = serde_json::json!({
                "nrLocation": {
                    "tai": {
                        "plmnId": split_plmn(&tai.plmn_id),
                        "tac": format!("{:04X}", tai.tac),
                    },
                }
            });
            if let Some(ncgi) = ncgi {
                location["nrLocation"]["ncgi"] = serde_json::json!({
                    "plmnId": split_plmn(&ncgi.plmn_id),
                    "nrCellId": format!("{:09X}", ncgi.cell_id),
                });
            }
            serde_json::json!({ "location": location })
        }
        AmfEventState::Active | AmfEventState::Connected => {
            serde_json::json!({ "reachability": "REACHABLE" })
        }
        AmfEventState::Idle => serde_json::json!({ "reachability": "UNREACHABLE" }),
    };
    crate::namf_server::fire_amf_event(
        notification.event_type.as_str(),
        Some(notification.supi.as_str()),
        extra,
    );

    Ok(())
}

// ============================================================================
// Paging Trigger (TS 23.502 4.2.3.3)
// ============================================================================

/// What a paged N2 SM transfer is, for its delivery after the Service Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PagedN2 {
    /// A setup transfer (or none): rides the Initial Context Setup.
    Setup,
    /// A release transfer: its own Release Command after the ICS (#518).
    Release,
    /// A modify transfer: its own Modify Request after the ICS (#757).
    Modify,
}

/// Initiate paging for an idle UE when DL data arrives
///
/// Creates a PagingContext, stores it in the AMF context paging map,
/// and marks the session paging as ongoing. The NGAP Paging message
/// will be sent by the event loop timer when it processes paging entries.
#[allow(clippy::too_many_arguments)]
pub(crate) fn initiate_paging_for_idle_ue(
    amf_ue: &AmfUe,
    sess: Option<&mut AmfSess>,
    pending_n1: Option<Vec<u8>>,
    pending_n2: Option<Vec<u8>>,
    paged_n2: PagedN2,
    pdu_session_id: Option<u8>,
    failure_notify_uri: Option<&str>,
) {
    // Extract 5G-S-TMSI components from current GUTI
    let tmsi = amf_ue.current_guti.tmsi;
    let amf_set_id = amf_ue.current_guti.amf_set_id;
    let amf_pointer = amf_ue.current_guti.amf_pointer;
    let plmn_id = amf_ue.current_guti.plmn_id.clone();

    // Use the last known TAC from the UE's registration area
    let tac = amf_ue.nr_tai.tac;

    let paging_ctx = PagingContext {
        amf_ue_ngap_id: amf_ue.id,
        tmsi,
        amf_set_id,
        amf_pointer,
        plmn_id,
        tac,
        initiated_at: std::time::Instant::now(),
        retransmit_count: 0,
        max_retransmit: 4,
        pending_n1,
        pending_n1_container_type: crate::gmm_handler::payload_container_type::N1_SM_INFORMATION,
        pending_n2,
        pending_n2_release: paged_n2 == PagedN2::Release,
        pending_n2_modify: paged_n2 == PagedN2::Modify,
        pdu_session_id,
        // The registration area this AMF assigned: the single TAI the
        // Registration Accept's TAI list carries (`gmm_build`, list type 00).
        tai_list: vec![(amf_ue.nr_tai.plmn_id.clone(), amf_ue.nr_tai.tac)],
        last_sent: None,
        failure_notify_uri: failure_notify_uri.map(str::to_string),
        n1n2_msg_data_uri: format!(
            "/namf-comm/v1/ue-contexts/{}/n1-n2-messages",
            amf_ue.supi.as_deref().unwrap_or("unknown")
        ),
        supi: amf_ue.supi.clone(),
    };

    // Mark session as paging ongoing; keep the consumer's failure-notify
    // URI so a paging timeout can trigger N1N2MsgTxfrFailureNotification
    let location = paging_ctx.n1n2_msg_data_uri.clone();

    // Store paging context in AMF global context. The NGAP server's paging pump
    // (`NgapServer::process_paging`) sends the PAGING and runs T3513.
    let ctx = amf_self();
    if let Ok(context) = ctx.read() {
        context.paging_add(paging_ctx);
    }
    if let Some(sess) = sess {
        sess.store_paging_info(&location, failure_notify_uri);
    }

    log::info!(
        "[{}] Paging initiated: TMSI=0x{:08x}, TAC={}, PSI={:?}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        tmsi,
        tac,
        pdu_session_id
    );
}

/// Page a CM-IDLE UE for an LMF's positioning transfer (#1087, TS 23.273: LPP to
/// the UE, UE-associated NRPPa to its gNB). The page carries no N1 and no SM N2:
/// the NGAP task holds the positioning payloads and delivers them once the UE is
/// connected. Returns the transfer's `Location`, as [`page_idle_ue_for_n1`] does.
pub fn page_idle_ue_for_positioning(amf_ue: &AmfUe, failure_notify_uri: Option<&str>) -> String {
    initiate_paging_for_idle_ue(
        amf_ue,
        None,
        None,
        None,
        PagedN2::Setup,
        None,
        failure_notify_uri,
    );
    format!(
        "/namf-comm/v1/ue-contexts/{}/n1-n2-messages",
        amf_ue.supi.as_deref().unwrap_or("unknown")
    )
}

/// Page a CM-IDLE UE for an N1 message that belongs to no PDU session -- a
/// UE-policy (UPDP) delivery from the PCF (#540, TS 23.502 §4.2.3.3 step 3a) --
/// and keep it for delivery, in `container_type`, once the Service Request
/// arrives. Returns the N1N2 transfer resource the 202 Location names.
pub fn page_idle_ue_for_n1(
    amf_ue: &AmfUe,
    n1: Vec<u8>,
    container_type: u8,
    failure_notify_uri: Option<&str>,
) -> String {
    initiate_paging_for_idle_ue(
        amf_ue,
        None,
        Some(n1),
        None,
        PagedN2::Setup,
        None,
        failure_notify_uri,
    );
    // The context was just queued with the default container type; set the one
    // this N1 travels in.
    let ctx = amf_self();
    if let Ok(context) = ctx.read() {
        context.paging_set_n1_container_type(amf_ue.id, container_type);
    }
    format!(
        "/namf-comm/v1/ue-contexts/{}/n1-n2-messages",
        amf_ue.supi.as_deref().unwrap_or("unknown")
    )
}

/// Handle event unsubscribe (Namf_EventExposure_Unsubscribe)
///
/// Removes the persisted subscription; returns an error when the
/// subscription does not exist (mapped to 404 at the HTTP layer).
pub fn handle_event_unsubscribe(subscription_id: &str) -> NamfHandlerResult<()> {
    log::info!("Event unsubscribe request: subscription={subscription_id}");

    let ctx = amf_self();
    let removed = ctx
        .read()
        .ok()
        .and_then(|context| context.event_subscription_remove(subscription_id));
    if removed.is_none() {
        return Err(NamfHandlerError::UeNotFound(format!(
            "subscription {subscription_id}"
        )));
    }

    log::debug!("Removed event subscription: {subscription_id}");
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

        let result = handle_n1_n2_message_transfer(&ue, &mut sess, None, false, &req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NamfHandlerError::MissingField(_)
        ));
    }

    /// #518 / TS 23.502 §4.2.3.3 step 3a: an N1-only transfer to a CM-IDLE UE pages
    /// it and keeps the N1 for delivery after the Service Request. Before #518 the
    /// N1-only case fell through as N1_N2_TRANSFER_INITIATED and nothing was sent.
    #[test]
    fn an_n1_only_transfer_to_an_idle_ue_pages_and_keeps_the_n1() {
        let mut ue = create_test_ue();
        ue.id = 5_180_001;
        let mut sess = create_test_sess();
        let n1 = vec![0x2E, 0x01, 0x01, 0xCB];
        let req = N1N2MessageTransferReqData {
            pdu_session_id: Some(1),
            n1_message: Some(n1.clone()),
            n2_info: None,
            ..Default::default()
        };
        let rsp = handle_n1_n2_message_transfer(&ue, &mut sess, None, true, &req).expect("ok");
        assert_eq!(rsp.cause, N1N2MessageTransferCause::AttemptingToReachUe);
        let paged = crate::context::amf_self()
            .read()
            .unwrap()
            .paging_find(5_180_001)
            .expect("the UE is paged");
        assert_eq!(paged.pending_n1, Some(n1));
        assert!(paged.pending_n2.is_none() && !paged.pending_n2_release);

        // CM-CONNECTED: no page.
        ue.id = 5_180_002;
        let rsp = handle_n1_n2_message_transfer(&ue, &mut sess, None, false, &req).expect("ok");
        assert_eq!(rsp.cause, N1N2MessageTransferCause::N1N2TransferInitiated);
        assert!(crate::context::amf_self()
            .read()
            .unwrap()
            .paging_find(5_180_002)
            .is_none());
    }

    /// #666: a CM-CONNECTED UE's N1-only transfer and PDU Session Resource
    /// Release are handed to the NGAP task for delivery NOW. Before #666 both were
    /// answered N1_N2_TRANSFER_INITIATED and never sent.
    #[test]
    fn a_connected_ues_n1_and_release_are_delivered_now() {
        let mut ue = create_test_ue();
        ue.id = 6_660_001;
        let mut sess = create_test_sess();
        let release_cmd = vec![0x2E, 0x01, 0x00, 0xD3, 0x27];

        let n1_only = N1N2MessageTransferReqData {
            pdu_session_id: Some(1),
            n1_message: Some(release_cmd.clone()),
            n2_info: None,
            ..Default::default()
        };
        let rsp = handle_n1_n2_message_transfer(&ue, &mut sess, None, false, &n1_only).expect("ok");
        assert_eq!(rsp.cause, N1N2MessageTransferCause::N1N2TransferInitiated);
        assert_eq!(
            rsp.deliver_now,
            Some(crate::context::PendingConnectedDownlink {
                amf_ue_ngap_id: 6_660_001,
                pdu_session_id: 1,
                n1: Some(release_cmd.clone()),
                n2: crate::context::ConnectedN2::None,
                failure_notify_uri: None,
            })
        );

        let release = N1N2MessageTransferReqData {
            pdu_session_id: Some(1),
            n1_message: Some(release_cmd.clone()),
            n2_info: Some(N2InfoContainer {
                ngap_ie_type: NgapIeType::PduResRelCmd,
                ngap_data: Some(vec![0x10]),
            }),
            ..Default::default()
        };
        let rsp = handle_n1_n2_message_transfer(&ue, &mut sess, None, false, &release).expect("ok");
        let item = rsp.deliver_now.expect("the release is delivered");
        assert_eq!(item.n2, crate::context::ConnectedN2::Release);
        assert_eq!(item.n1, Some(release_cmd));

        // CM-IDLE is the paging path, not this one.
        ue.id = 6_660_002;
        let rsp = handle_n1_n2_message_transfer(&ue, &mut sess, None, true, &release).expect("ok");
        assert_eq!(rsp.cause, N1N2MessageTransferCause::AttemptingToReachUe);
        assert!(rsp.deliver_now.is_none());
        crate::context::amf_self()
            .read()
            .unwrap()
            .paging_remove(6_660_002);
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

        let result = handle_n1_n2_message_transfer(&ue, &mut sess, None, false, &req);
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

    // WSB-4: `handle_dereg_notify`'s enqueue side effect and the
    // reregistration_required distinction are verified over the wire in the
    // `namf_server` router-arm tests (they serialize the destructive
    // process-global-queue drain). These two only assert the accept/skip
    // contract, so they never touch the shared queue.

    #[test]
    fn test_handle_dereg_notify() {
        let ue = create_test_ue();
        let data = DeregistrationData {
            dereg_reason: DeregistrationReason::SubscriptionWithdrawn,
            access_type: AccessType::ThreeGppAccess,
        };

        // WSB-4: a 3GPP-access notify is accepted (and enqueues a
        // network-initiated deregistration — asserted in the namf_server tests).
        assert!(handle_dereg_notify(&ue, &data).is_ok());
    }

    #[test]
    fn test_handle_dereg_notify_non_3gpp() {
        let ue = create_test_ue();
        let data = DeregistrationData {
            dereg_reason: DeregistrationReason::SubscriptionWithdrawn,
            access_type: AccessType::NonThreeGppAccess,
        };

        // WSB-4: a non-3GPP-access notify is accepted (the SBI layer answers
        // 204) but triggers no 3GPP network-initiated deregistration.
        assert!(handle_dereg_notify(&ue, &data).is_ok());
    }

    #[test]
    fn test_event_subscribe() {
        let subscription = AmfEventSubscription {
            event_type: AmfEventType::LocationReport,
            immediate_flag: false,
            area_list: None,
            location_filter_list: None,
        };

        let result = handle_event_subscribe(&subscription, "http://nef.example.com/callback");
        assert!(result.is_ok());
        let sub_id = result.unwrap();
        assert!(sub_id.starts_with("sub-"));
    }

    #[test]
    fn test_event_subscribe_missing_callback() {
        let subscription = AmfEventSubscription {
            event_type: AmfEventType::ReachabilityReport,
            immediate_flag: true,
            area_list: None,
            location_filter_list: None,
        };

        let result = handle_event_subscribe(&subscription, "");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NamfHandlerError::MissingField(_)
        ));
    }

    #[test]
    fn test_send_event_notification() {
        // Subscription must exist for delivery to be attempted
        let subscription = AmfEventSubscription {
            event_type: AmfEventType::LocationReport,
            immediate_flag: false,
            area_list: None,
            location_filter_list: None,
        };
        let sub_id = handle_event_subscribe(&subscription, "http://127.0.0.1:9/notify")
            .expect("subscribe failed");

        let notification = AmfEventNotification {
            event_type: AmfEventType::LocationReport,
            state: AmfEventState::Location {
                tai: TrackingAreaId {
                    plmn_id: "310260".to_string(),
                    tac: 1,
                },
                ncgi: None,
            },
            timestamp: std::time::SystemTime::now(),
            supi: "imsi-310260000000001".to_string(),
            additional_info: None,
        };

        let result = send_event_notification(&sub_id, &notification);
        assert!(result.is_ok());

        // Unknown subscription is an error (maps to 404 at HTTP level)
        let result = send_event_notification("sub-does-not-exist", &notification);
        assert!(result.is_err());

        let _ = handle_event_unsubscribe(&sub_id);
    }

    #[test]
    fn test_event_unsubscribe() {
        // Removing a non-existent subscription is an error
        assert!(handle_event_unsubscribe("sub-12345-missing").is_err());

        // Subscribe then unsubscribe round-trips
        let subscription = AmfEventSubscription {
            event_type: AmfEventType::ReachabilityReport,
            immediate_flag: false,
            area_list: None,
            location_filter_list: None,
        };
        let sub_id = handle_event_subscribe(&subscription, "http://127.0.0.1:9/notify")
            .expect("subscribe failed");
        assert!(handle_event_unsubscribe(&sub_id).is_ok());
        assert!(handle_event_unsubscribe(&sub_id).is_err());
    }

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(AmfEventType::LocationReport.as_str(), "LOCATION_REPORT");
        assert_eq!(
            AmfEventType::ReachabilityReport.as_str(),
            "REACHABILITY_REPORT"
        );
        assert_eq!(
            AmfEventType::PduSessStatusReport.as_str(),
            "PDU_SESS_STATUS_REPORT"
        );
    }

    #[test]
    fn test_n1n2_transfer_idle_ue_triggers_paging() {
        amf_context_init(64, 1024, 4096);

        let mut ue = AmfUe::default();
        ue.supi = Some("imsi-310260000000001".to_string());
        ue.security_context_available = false; // UE is IDLE
        ue.current_guti.tmsi = 0xAABBCCDD;
        ue.current_guti.amf_set_id = 1;
        ue.current_guti.amf_pointer = 0;
        ue.nr_tai.tac = 7;

        let mut sess = create_test_sess();
        let req = N1N2MessageTransferReqData {
            pdu_session_id: Some(1),
            n1_message: None,
            n2_info: Some(N2InfoContainer {
                ngap_ie_type: NgapIeType::PduResSetupReq,
                ngap_data: Some(vec![0x04, 0x05]),
            }),
            ..Default::default()
        };

        let result = handle_n1_n2_message_transfer(&ue, &mut sess, None, true, &req);
        assert!(result.is_ok());
        let rsp = result.unwrap();
        assert_eq!(rsp.cause, N1N2MessageTransferCause::AttemptingToReachUe);
        assert!(sess.paging.ongoing);
    }
}
