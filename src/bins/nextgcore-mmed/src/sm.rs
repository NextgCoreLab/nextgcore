//! MME State Machines
//!
//! Port of src/mme/mme-sm.c, emm-sm.c, esm-sm.c, s1ap-sm.c, sgsap-sm.c
//! Implements state machines for MME, EMM, ESM, S1AP, and SGsAP

use std::fmt;

// ============================================================================
// Event Types
// ============================================================================

/// Base event offset for MME events
pub const MME_EVENT_BASE: u32 = 100;

/// MME Event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MmeEventId {
    /// S1AP message received
    S1apMessage = MME_EVENT_BASE + 1,
    /// S1AP timer expired
    S1apTimer,
    /// S1AP connection accepted
    S1apLoAccept,
    /// S1AP SCTP communication up
    S1apLoSctpCommUp,
    /// S1AP connection refused
    S1apLoConnRefused,

    /// EMM message received
    EmmMessage,
    /// EMM timer expired
    EmmTimer,
    /// ESM message received
    EsmMessage,
    /// ESM timer expired
    EsmTimer,
    /// S11 message received
    S11Message,
    /// S11 timer expired
    S11Timer,
    /// S6a message received
    S6aMessage,
    /// S6a timer expired
    S6aTimer,

    /// SGsAP message received
    SgsapMessage,
    /// SGsAP timer expired
    SgsapTimer,
    /// SGsAP SCTP communication up
    SgsapLoSctpCommUp,
    /// SGsAP connection refused
    SgsapLoConnRefused,

    /// Gn message received
    GnMessage,
    /// Gn timer expired
    GnTimer,
}

impl fmt::Display for MmeEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmeEventId::S1apMessage => write!(f, "S1AP_MESSAGE"),
            MmeEventId::S1apTimer => write!(f, "S1AP_TIMER"),
            MmeEventId::S1apLoAccept => write!(f, "S1AP_LO_ACCEPT"),
            MmeEventId::S1apLoSctpCommUp => write!(f, "S1AP_LO_SCTP_COMM_UP"),
            MmeEventId::S1apLoConnRefused => write!(f, "S1AP_LO_CONNREFUSED"),
            MmeEventId::EmmMessage => write!(f, "EMM_MESSAGE"),
            MmeEventId::EmmTimer => write!(f, "EMM_TIMER"),
            MmeEventId::EsmMessage => write!(f, "ESM_MESSAGE"),
            MmeEventId::EsmTimer => write!(f, "ESM_TIMER"),
            MmeEventId::S11Message => write!(f, "S11_MESSAGE"),
            MmeEventId::S11Timer => write!(f, "S11_TIMER"),
            MmeEventId::S6aMessage => write!(f, "S6A_MESSAGE"),
            MmeEventId::S6aTimer => write!(f, "S6A_TIMER"),
            MmeEventId::SgsapMessage => write!(f, "SGSAP_MESSAGE"),
            MmeEventId::SgsapTimer => write!(f, "SGSAP_TIMER"),
            MmeEventId::SgsapLoSctpCommUp => write!(f, "SGSAP_LO_SCTP_COMM_UP"),
            MmeEventId::SgsapLoConnRefused => write!(f, "SGSAP_LO_CONNREFUSED"),
            MmeEventId::GnMessage => write!(f, "GN_MESSAGE"),
            MmeEventId::GnTimer => write!(f, "GN_TIMER"),
        }
    }
}

/// MME Timer IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmeTimerId {
    /// S1 delayed send timer
    S1DelayedSend,
    /// S1 holding timer
    S1Holding,
    /// T3413 - Paging timer
    T3413,
    /// T3422 - Detach timer
    T3422,
    /// T3450 - Attach/TAU accept timer
    T3450,
    /// T3460 - Authentication timer
    T3460,
    /// T3470 - Identity request timer
    T3470,
    /// T3489 - ESM information timer
    T3489,
    /// Mobile reachable timer
    MobileReachable,
    /// Implicit detach timer
    ImplicitDetach,
    /// SGS CLI connection to server timer
    SgsCliConnToSrv,
}

impl fmt::Display for MmeTimerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmeTimerId::S1DelayedSend => write!(f, "S1_DELAYED_SEND"),
            MmeTimerId::S1Holding => write!(f, "S1_HOLDING"),
            MmeTimerId::T3413 => write!(f, "T3413"),
            MmeTimerId::T3422 => write!(f, "T3422"),
            MmeTimerId::T3450 => write!(f, "T3450"),
            MmeTimerId::T3460 => write!(f, "T3460"),
            MmeTimerId::T3470 => write!(f, "T3470"),
            MmeTimerId::T3489 => write!(f, "T3489"),
            MmeTimerId::MobileReachable => write!(f, "MOBILE_REACHABLE"),
            MmeTimerId::ImplicitDetach => write!(f, "IMPLICIT_DETACH"),
            MmeTimerId::SgsCliConnToSrv => write!(f, "SGS_CLI_CONN_TO_SRV"),
        }
    }
}

// ============================================================================
// FSM Signal Types
// ============================================================================

/// FSM signal types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmSignal {
    /// Entry signal - sent when entering a state
    Entry,
    /// Exit signal - sent when exiting a state
    Exit,
    /// Event signal - regular event
    Event(MmeEventId),
}

// ============================================================================
// MME Event Structure
// ============================================================================

/// MME Event
#[derive(Debug, Clone)]
pub struct MmeEvent {
    /// Event ID
    pub id: MmeEventId,
    /// Timer ID (for timer events)
    pub timer_id: Option<MmeTimerId>,
    /// S1AP procedure code
    pub s1ap_code: Option<u32>,
    /// NAS type
    pub nas_type: Option<u8>,
    /// Create action
    pub create_action: Option<i32>,
    /// eNB ID
    pub enb_id: Option<u64>,
    /// eNB UE ID
    pub enb_ue_id: Option<u64>,
    /// SGW UE ID
    pub sgw_ue_id: Option<u64>,
    /// MME UE ID
    pub mme_ue_id: Option<u64>,
    /// Bearer ID
    pub bearer_id: Option<u64>,
    /// GTP transaction ID
    pub gtp_xact_id: Option<u64>,
}

impl MmeEvent {
    /// Create a new MME event
    pub fn new(id: MmeEventId) -> Self {
        Self {
            id,
            timer_id: None,
            s1ap_code: None,
            nas_type: None,
            create_action: None,
            enb_id: None,
            enb_ue_id: None,
            sgw_ue_id: None,
            mme_ue_id: None,
            bearer_id: None,
            gtp_xact_id: None,
        }
    }

    /// Get event name
    pub fn name(&self) -> String {
        self.id.to_string()
    }
}

// ============================================================================
// State Machine Trait
// ============================================================================

/// Finite State Machine trait
pub trait Fsm {
    /// Event type
    type Event;
    
    /// Initialize the state machine
    fn init(&mut self);
    
    /// Finalize the state machine
    fn fini(&mut self);
    
    /// Dispatch an event to the state machine
    fn dispatch(&mut self, event: &Self::Event);
    
    /// Check if in a specific state
    fn check_state(&self, state_name: &str) -> bool;
}

// ============================================================================
// EMM State Machine
// ============================================================================

/// EMM common state enum (for internal use)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmmCommonState {
    /// De-registered state
    DeRegistered,
    /// Registered state
    Registered,
}

/// EMM State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmmState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// De-registered state
    DeRegistered,
    /// Registered state
    Registered,
    /// Authentication state
    Authentication,
    /// Security mode state
    SecurityMode,
    /// Initial context setup state
    InitialContextSetup,
    /// Exception state
    Exception,
}

impl fmt::Display for EmmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmmState::Initial => write!(f, "INITIAL"),
            EmmState::Final => write!(f, "FINAL"),
            EmmState::DeRegistered => write!(f, "DE_REGISTERED"),
            EmmState::Registered => write!(f, "REGISTERED"),
            EmmState::Authentication => write!(f, "AUTHENTICATION"),
            EmmState::SecurityMode => write!(f, "SECURITY_MODE"),
            EmmState::InitialContextSetup => write!(f, "INITIAL_CONTEXT_SETUP"),
            EmmState::Exception => write!(f, "EXCEPTION"),
        }
    }
}

/// EMM State Machine
pub struct EmmFsm {
    /// Current state
    state: EmmState,
    /// MME UE ID
    mme_ue_id: u64,
}

impl EmmFsm {
    /// Create a new EMM FSM
    pub fn new(mme_ue_id: u64) -> Self {
        Self {
            state: EmmState::Initial,
            mme_ue_id,
        }
    }

    /// Get current state
    pub fn state(&self) -> EmmState {
        self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: EmmState) {
        log::debug!("EMM FSM [{}]: {} -> {}", self.mme_ue_id, self.state, new_state);
        self.state = new_state;
    }

    /// Handle initial state
    fn state_initial(&mut self, _event: &MmeEvent) {
        self.transition(EmmState::DeRegistered);
    }

    /// Handle final state
    fn state_final(&mut self, _event: &MmeEvent) {
        // Nothing to do
    }

    /// Handle de-registered state
    fn state_de_registered(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                // Handle EMM message in de-registered state
                // This would call common_register_state with DeRegistered
                log::debug!("EMM de-registered: handling EMM message");
            }
            MmeEventId::EmmTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        MmeTimerId::T3470 => {
                            log::warn!("T3470 timeout in de-registered state");
                            // Handle identity request retransmission
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in de-registered state");
                        }
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in de-registered state", event.id);
            }
        }
    }

    /// Handle registered state
    fn state_registered(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                // Handle EMM message in registered state
                log::debug!("EMM registered: handling EMM message");
            }
            MmeEventId::EmmTimer => {
                if let Some(timer_id) = event.timer_id {
                    match timer_id {
                        MmeTimerId::T3413 => {
                            log::info!("T3413 (paging) timeout");
                            // Handle paging retransmission
                        }
                        MmeTimerId::T3470 => {
                            log::warn!("T3470 timeout in registered state");
                        }
                        MmeTimerId::T3422 => {
                            log::warn!("T3422 (detach) timeout");
                        }
                        MmeTimerId::MobileReachable => {
                            log::info!("Mobile reachable timer expired");
                            // Start implicit detach timer
                        }
                        MmeTimerId::ImplicitDetach => {
                            log::info!("Implicit detach timer expired");
                            self.transition(EmmState::DeRegistered);
                        }
                        _ => {
                            log::error!("Unknown timer {timer_id:?} in registered state");
                        }
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in registered state", event.id);
            }
        }
    }

    /// Handle authentication state
    fn state_authentication(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                log::debug!("EMM authentication: handling EMM message");
                // Handle authentication response/failure
            }
            MmeEventId::EmmTimer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == MmeTimerId::T3460 {
                        log::warn!("T3460 (authentication) timeout");
                        // Handle authentication retransmission
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in authentication state", event.id);
            }
        }
    }

    /// Handle security mode state
    fn state_security_mode(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                log::debug!("EMM security mode: handling EMM message");
                // Handle security mode complete/reject
            }
            MmeEventId::EmmTimer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == MmeTimerId::T3460 {
                        log::warn!("T3460 (security mode) timeout");
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in security mode state", event.id);
            }
        }
    }

    /// Handle initial context setup state
    fn state_initial_context_setup(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                log::debug!("EMM initial context setup: handling EMM message");
                // Handle attach complete, TAU complete
            }
            MmeEventId::EmmTimer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == MmeTimerId::T3450 {
                        log::warn!("T3450 timeout");
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in initial context setup state", event.id);
            }
        }
    }

    /// Handle exception state
    fn state_exception(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EmmMessage => {
                log::debug!("EMM exception: handling EMM message");
                // Only handle attach request to recover
            }
            _ => {
                log::error!("Unknown event {:?} in exception state", event.id);
            }
        }
    }
}

impl Fsm for EmmFsm {
    type Event = MmeEvent;

    fn init(&mut self) {
        self.state = EmmState::Initial;
        let event = MmeEvent::new(MmeEventId::EmmMessage);
        self.state_initial(&event);
    }

    fn fini(&mut self) {
        self.state = EmmState::Final;
    }

    fn dispatch(&mut self, event: &MmeEvent) {
        match self.state {
            EmmState::Initial => self.state_initial(event),
            EmmState::Final => self.state_final(event),
            EmmState::DeRegistered => self.state_de_registered(event),
            EmmState::Registered => self.state_registered(event),
            EmmState::Authentication => self.state_authentication(event),
            EmmState::SecurityMode => self.state_security_mode(event),
            EmmState::InitialContextSetup => self.state_initial_context_setup(event),
            EmmState::Exception => self.state_exception(event),
        }
    }

    fn check_state(&self, state_name: &str) -> bool {
        self.state.to_string() == state_name
    }
}


// ============================================================================
// ESM State Machine
// ============================================================================

/// ESM State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EsmState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Inactive state
    Inactive,
    /// Active state
    Active,
    /// PDN will disconnect state
    PdnWillDisconnect,
    /// PDN did disconnect state
    PdnDidDisconnect,
    /// Bearer deactivated state
    BearerDeactivated,
    /// Exception state
    Exception,
}

impl fmt::Display for EsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EsmState::Initial => write!(f, "INITIAL"),
            EsmState::Final => write!(f, "FINAL"),
            EsmState::Inactive => write!(f, "INACTIVE"),
            EsmState::Active => write!(f, "ACTIVE"),
            EsmState::PdnWillDisconnect => write!(f, "PDN_WILL_DISCONNECT"),
            EsmState::PdnDidDisconnect => write!(f, "PDN_DID_DISCONNECT"),
            EsmState::BearerDeactivated => write!(f, "BEARER_DEACTIVATED"),
            EsmState::Exception => write!(f, "EXCEPTION"),
        }
    }
}

/// ESM State Machine
pub struct EsmFsm {
    /// Current state
    state: EsmState,
    /// Bearer ID
    bearer_id: u64,
}

impl EsmFsm {
    /// Create a new ESM FSM
    pub fn new(bearer_id: u64) -> Self {
        Self {
            state: EsmState::Initial,
            bearer_id,
        }
    }

    /// Get current state
    pub fn state(&self) -> EsmState {
        self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: EsmState) {
        log::debug!("ESM FSM [{}]: {} -> {}", self.bearer_id, self.state, new_state);
        self.state = new_state;
    }

    /// Handle initial state
    fn state_initial(&mut self, _event: &MmeEvent) {
        self.transition(EsmState::Inactive);
    }

    /// Handle final state
    fn state_final(&mut self, _event: &MmeEvent) {
        // Nothing to do
    }

    /// Handle inactive state
    fn state_inactive(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EsmMessage => {
                log::debug!("ESM inactive: handling ESM message");
                // Handle PDN connectivity request, ESM information response, etc.
            }
            MmeEventId::EsmTimer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == MmeTimerId::T3489 {
                        log::warn!("T3489 (ESM information) timeout");
                    }
                }
            }
            _ => {
                log::error!("Unknown event {:?} in ESM inactive state", event.id);
            }
        }
    }

    /// Handle active state
    fn state_active(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EsmMessage => {
                log::debug!("ESM active: handling ESM message");
                // Handle PDN disconnect, modify bearer, deactivate bearer, etc.
            }
            _ => {
                log::error!("Unknown event {:?} in ESM active state", event.id);
            }
        }
    }

    /// Handle PDN will disconnect state
    fn state_pdn_will_disconnect(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::EsmMessage => {
                log::debug!("ESM PDN will disconnect: handling ESM message");
                // Handle deactivate bearer context accept
            }
            _ => {
                log::error!("Unknown event {:?} in ESM PDN will disconnect state", event.id);
            }
        }
    }

    /// Handle PDN did disconnect state
    fn state_pdn_did_disconnect(&mut self, _event: &MmeEvent) {
        // Terminal state - nothing to do
    }

    /// Handle bearer deactivated state
    fn state_bearer_deactivated(&mut self, _event: &MmeEvent) {
        // Terminal state - nothing to do
    }

    /// Handle exception state
    fn state_exception(&mut self, _event: &MmeEvent) {
        // Clear all timers on entry
    }
}

impl Fsm for EsmFsm {
    type Event = MmeEvent;

    fn init(&mut self) {
        self.state = EsmState::Initial;
        let event = MmeEvent::new(MmeEventId::EsmMessage);
        self.state_initial(&event);
    }

    fn fini(&mut self) {
        self.state = EsmState::Final;
    }

    fn dispatch(&mut self, event: &MmeEvent) {
        match self.state {
            EsmState::Initial => self.state_initial(event),
            EsmState::Final => self.state_final(event),
            EsmState::Inactive => self.state_inactive(event),
            EsmState::Active => self.state_active(event),
            EsmState::PdnWillDisconnect => self.state_pdn_will_disconnect(event),
            EsmState::PdnDidDisconnect => self.state_pdn_did_disconnect(event),
            EsmState::BearerDeactivated => self.state_bearer_deactivated(event),
            EsmState::Exception => self.state_exception(event),
        }
    }

    fn check_state(&self, state_name: &str) -> bool {
        self.state.to_string() == state_name
    }
}

// ============================================================================
// S1AP State Machine
// ============================================================================

/// S1AP State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1apState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Operational state
    Operational,
    /// Exception state
    Exception,
}

impl fmt::Display for S1apState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            S1apState::Initial => write!(f, "INITIAL"),
            S1apState::Final => write!(f, "FINAL"),
            S1apState::Operational => write!(f, "OPERATIONAL"),
            S1apState::Exception => write!(f, "EXCEPTION"),
        }
    }
}

/// S1AP PDU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1apPduType {
    /// Initiating message
    InitiatingMessage,
    /// Successful outcome
    SuccessfulOutcome,
    /// Unsuccessful outcome
    UnsuccessfulOutcome,
}

/// S1AP Procedure codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum S1apProcedureCode {
    /// S1 Setup
    S1Setup = 17,
    /// eNB Configuration Update
    EnbConfigurationUpdate = 29,
    /// Initial UE Message
    InitialUeMessage = 12,
    /// Uplink NAS Transport
    UplinkNasTransport = 13,
    /// Downlink NAS Transport
    DownlinkNasTransport = 11,
    /// UE Capability Info Indication
    UeCapabilityInfoIndication = 22,
    /// UE Context Release Request
    UeContextReleaseRequest = 18,
    /// UE Context Release (Command and Complete use same procedure code)
    UeContextRelease = 23,
    /// Initial Context Setup
    InitialContextSetup = 9,
    /// UE Context Modification
    UeContextModification = 21,
    /// Path Switch Request
    PathSwitchRequest = 3,
    /// Handover Preparation
    HandoverPreparation = 0,
    /// Handover Resource Allocation
    HandoverResourceAllocation = 1,
    /// Handover Notification
    HandoverNotification = 2,
    /// Handover Cancel
    HandoverCancel = 4,
    /// eNB Status Transfer
    EnbStatusTransfer = 24,
    /// E-RAB Setup
    ErabSetup = 5,
    /// E-RAB Modify
    ErabModify = 6,
    /// E-RAB Release
    ErabRelease = 7,
    /// E-RAB Modification Indication
    ErabModificationIndication = 50,
    /// Reset
    Reset = 14,
    /// Error Indication
    ErrorIndication = 15,
    /// Write Replace Warning
    WriteReplaceWarning = 36,
    /// Kill
    Kill = 43,
    /// eNB Configuration Transfer
    EnbConfigurationTransfer = 40,
    /// eNB Direct Information Transfer
    EnbDirectInformationTransfer = 37,
    /// NAS Non Delivery Indication
    NasNonDeliveryIndication = 16,
}

/// S1AP State Machine
pub struct S1apFsm {
    /// Current state
    state: S1apState,
    /// eNB ID
    enb_id: u64,
    /// S1 setup success flag
    s1_setup_success: bool,
}

impl S1apFsm {
    /// Create a new S1AP FSM
    pub fn new(enb_id: u64) -> Self {
        Self {
            state: S1apState::Initial,
            enb_id,
            s1_setup_success: false,
        }
    }

    /// Get current state
    pub fn state(&self) -> S1apState {
        self.state
    }

    /// Set S1 setup success
    pub fn set_s1_setup_success(&mut self, success: bool) {
        self.s1_setup_success = success;
    }

    /// Check if S1 setup is successful
    pub fn is_s1_setup_success(&self) -> bool {
        self.s1_setup_success
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: S1apState) {
        log::debug!("S1AP FSM [{}]: {} -> {}", self.enb_id, self.state, new_state);
        self.state = new_state;
    }

    /// Handle initial state
    fn state_initial(&mut self, _event: &MmeEvent) {
        self.transition(S1apState::Operational);
    }

    /// Handle final state
    fn state_final(&mut self, _event: &MmeEvent) {
        // Nothing to do
    }

    /// Handle operational state
    fn state_operational(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::S1apMessage => {
                log::debug!("S1AP operational: handling S1AP message");
                // Handle S1AP messages based on procedure code
                // - S1 Setup Request
                // - eNB Configuration Update
                // - Initial UE Message
                // - Uplink NAS Transport
                // - UE Capability Info Indication
                // - UE Context Release Request/Complete
                // - Initial Context Setup Response/Failure
                // - Path Switch Request
                // - Handover messages
                // - E-RAB messages
                // - Reset
                // - Error Indication
            }
            _ => {
                log::error!("Unknown event {:?} in S1AP operational state", event.id);
            }
        }
    }

    /// Handle exception state
    fn state_exception(&mut self, _event: &MmeEvent) {
        // Error state - log and ignore events
    }
}

impl Fsm for S1apFsm {
    type Event = MmeEvent;

    fn init(&mut self) {
        self.state = S1apState::Initial;
        let event = MmeEvent::new(MmeEventId::S1apMessage);
        self.state_initial(&event);
    }

    fn fini(&mut self) {
        self.state = S1apState::Final;
    }

    fn dispatch(&mut self, event: &MmeEvent) {
        match self.state {
            S1apState::Initial => self.state_initial(event),
            S1apState::Final => self.state_final(event),
            S1apState::Operational => self.state_operational(event),
            S1apState::Exception => self.state_exception(event),
        }
    }

    fn check_state(&self, state_name: &str) -> bool {
        self.state.to_string() == state_name
    }
}


// ============================================================================
// SGsAP State Machine
// ============================================================================

/// SGsAP State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgsapState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Will connect state
    WillConnect,
    /// Connected state
    Connected,
    /// Exception state
    Exception,
}

impl fmt::Display for SgsapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SgsapState::Initial => write!(f, "INITIAL"),
            SgsapState::Final => write!(f, "FINAL"),
            SgsapState::WillConnect => write!(f, "WILL_CONNECT"),
            SgsapState::Connected => write!(f, "CONNECTED"),
            SgsapState::Exception => write!(f, "EXCEPTION"),
        }
    }
}

/// SGsAP Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SgsapMessageType {
    /// Paging request
    PagingRequest = 0x01,
    /// Paging reject
    PagingReject = 0x02,
    /// Service request
    ServiceRequest = 0x06,
    /// Downlink unitdata
    DownlinkUnitdata = 0x07,
    /// Uplink unitdata
    UplinkUnitdata = 0x08,
    /// Location update request
    LocationUpdateRequest = 0x09,
    /// Location update accept
    LocationUpdateAccept = 0x0a,
    /// Location update reject
    LocationUpdateReject = 0x0b,
    /// TMSI reallocation complete
    TmsiReallocationComplete = 0x0c,
    /// Alert request
    AlertRequest = 0x0d,
    /// Alert ack
    AlertAck = 0x0e,
    /// Alert reject
    AlertReject = 0x0f,
    /// UE activity indication
    UeActivityIndication = 0x10,
    /// EPS detach indication
    EpsDetachIndication = 0x11,
    /// EPS detach ack
    EpsDetachAck = 0x12,
    /// IMSI detach indication
    ImsiDetachIndication = 0x13,
    /// IMSI detach ack
    ImsiDetachAck = 0x14,
    /// Reset indication
    ResetIndication = 0x15,
    /// Reset ack
    ResetAck = 0x16,
    /// Service abort request
    ServiceAbortRequest = 0x17,
    /// MO CSFB indication
    MoCsfbIndication = 0x18,
    /// MM information request
    MmInformationRequest = 0x1a,
    /// Release request
    ReleaseRequest = 0x1b,
    /// Status
    Status = 0x1d,
    /// UE unreachable
    UeUnreachable = 0x1f,
}

/// SGsAP State Machine
pub struct SgsapFsm {
    /// Current state
    state: SgsapState,
    /// VLR ID
    vlr_id: u64,
}

impl SgsapFsm {
    /// Create a new SGsAP FSM
    pub fn new(vlr_id: u64) -> Self {
        Self {
            state: SgsapState::Initial,
            vlr_id,
        }
    }

    /// Get current state
    pub fn state(&self) -> SgsapState {
        self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: SgsapState) {
        log::debug!("SGsAP FSM [{}]: {} -> {}", self.vlr_id, self.state, new_state);
        self.state = new_state;
    }

    /// Handle initial state
    fn state_initial(&mut self, _event: &MmeEvent) {
        // Create connection timer and transition to will_connect
        self.transition(SgsapState::WillConnect);
    }

    /// Handle final state
    fn state_final(&mut self, _event: &MmeEvent) {
        // Delete connection timer
    }

    /// Handle will connect state
    fn state_will_connect(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::SgsapTimer => {
                if let Some(timer_id) = event.timer_id {
                    if timer_id == MmeTimerId::SgsCliConnToSrv {
                        log::warn!("SGsAP connection to VLR failed, retrying...");
                        // Restart timer and retry connection
                    }
                }
            }
            MmeEventId::SgsapLoSctpCommUp => {
                log::info!("SGsAP SCTP connection established");
                self.transition(SgsapState::Connected);
            }
            _ => {
                log::error!("Unknown event {:?} in SGsAP will connect state", event.id);
            }
        }
    }

    /// Handle connected state
    fn state_connected(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::SgsapLoConnRefused => {
                log::warn!("SGsAP connection refused");
                self.transition(SgsapState::WillConnect);
            }
            MmeEventId::SgsapMessage => {
                log::debug!("SGsAP connected: handling SGsAP message");
                // Handle SGsAP messages:
                // - Location update accept/reject
                // - Alert request
                // - EPS/IMSI detach ack
                // - Paging request
                // - Downlink unitdata
                // - Reset indication
                // - Release request
                // - MM information request
            }
            _ => {
                log::error!("Unknown event {:?} in SGsAP connected state", event.id);
            }
        }
    }

    /// Handle exception state
    fn state_exception(&mut self, _event: &MmeEvent) {
        // Error state - log and ignore events
    }
}

impl Fsm for SgsapFsm {
    type Event = MmeEvent;

    fn init(&mut self) {
        self.state = SgsapState::Initial;
        let event = MmeEvent::new(MmeEventId::SgsapMessage);
        self.state_initial(&event);
    }

    fn fini(&mut self) {
        self.state = SgsapState::Final;
    }

    fn dispatch(&mut self, event: &MmeEvent) {
        match self.state {
            SgsapState::Initial => self.state_initial(event),
            SgsapState::Final => self.state_final(event),
            SgsapState::WillConnect => self.state_will_connect(event),
            SgsapState::Connected => self.state_connected(event),
            SgsapState::Exception => self.state_exception(event),
        }
    }

    fn check_state(&self, state_name: &str) -> bool {
        self.state.to_string() == state_name
    }
}

// ============================================================================
// MME Main State Machine
// ============================================================================

/// MME State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmeState {
    /// Initial state
    Initial,
    /// Final state
    Final,
    /// Operational state
    Operational,
}

impl fmt::Display for MmeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmeState::Initial => write!(f, "INITIAL"),
            MmeState::Final => write!(f, "FINAL"),
            MmeState::Operational => write!(f, "OPERATIONAL"),
        }
    }
}

/// MME Main State Machine
pub struct MmeFsm {
    /// Current state
    state: MmeState,
}

impl MmeFsm {
    /// Create a new MME FSM
    pub fn new() -> Self {
        Self {
            state: MmeState::Initial,
        }
    }

    /// Get current state
    pub fn state(&self) -> MmeState {
        self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: MmeState) {
        log::debug!("MME FSM: {} -> {}", self.state, new_state);
        self.state = new_state;
    }

    /// Handle initial state
    fn state_initial(&mut self, _event: &MmeEvent) {
        self.transition(MmeState::Operational);
    }

    /// Handle final state
    fn state_final(&mut self, _event: &MmeEvent) {
        // Nothing to do
    }

    /// Handle operational state
    fn state_operational(&mut self, event: &MmeEvent) {
        match event.id {
            MmeEventId::S1apLoAccept => {
                log::info!("S1AP connection accepted");
                // Handle new eNB connection
            }
            MmeEventId::S1apLoSctpCommUp => {
                log::info!("S1AP SCTP communication up");
                // Handle SCTP association establishment
            }
            MmeEventId::S1apLoConnRefused => {
                log::warn!("S1AP connection refused");
                // Handle eNB disconnection
            }
            MmeEventId::S1apMessage => {
                log::debug!("MME operational: handling S1AP message");
                // Dispatch to eNB's S1AP FSM
            }
            MmeEventId::S1apTimer => {
                log::debug!("MME operational: handling S1AP timer");
                // Handle S1AP timers (delayed send, holding)
            }
            MmeEventId::EmmMessage => {
                log::debug!("MME operational: handling EMM message");
                // Dispatch to UE's EMM FSM
            }
            MmeEventId::EmmTimer => {
                log::debug!("MME operational: handling EMM timer");
                // Dispatch to UE's EMM FSM
            }
            MmeEventId::EsmMessage => {
                log::debug!("MME operational: handling ESM message");
                // Dispatch to bearer's ESM FSM
            }
            MmeEventId::EsmTimer => {
                log::debug!("MME operational: handling ESM timer");
                // Dispatch to bearer's ESM FSM
            }
            MmeEventId::S11Message => {
                log::debug!("MME operational: handling S11 message");
                // Handle GTP-C messages from SGW
            }
            MmeEventId::S11Timer => {
                log::debug!("MME operational: handling S11 timer");
            }
            MmeEventId::S6aMessage => {
                log::debug!("MME operational: handling S6a message");
                // Handle Diameter messages from HSS
            }
            MmeEventId::S6aTimer => {
                log::debug!("MME operational: handling S6a timer");
            }
            MmeEventId::SgsapMessage => {
                log::debug!("MME operational: handling SGsAP message");
                // Dispatch to VLR's SGsAP FSM
            }
            MmeEventId::SgsapTimer => {
                log::debug!("MME operational: handling SGsAP timer");
            }
            MmeEventId::SgsapLoSctpCommUp => {
                log::info!("SGsAP SCTP communication up");
            }
            MmeEventId::SgsapLoConnRefused => {
                log::warn!("SGsAP connection refused");
            }
            MmeEventId::GnMessage => {
                log::debug!("MME operational: handling Gn message");
                // Handle GTPv1 messages from SGSN
            }
            MmeEventId::GnTimer => {
                log::debug!("MME operational: handling Gn timer");
            }
        }
    }
}

impl Default for MmeFsm {
    fn default() -> Self {
        Self::new()
    }
}

impl Fsm for MmeFsm {
    type Event = MmeEvent;

    fn init(&mut self) {
        self.state = MmeState::Initial;
        let event = MmeEvent::new(MmeEventId::S1apMessage);
        self.state_initial(&event);
    }

    fn fini(&mut self) {
        self.state = MmeState::Final;
    }

    fn dispatch(&mut self, event: &MmeEvent) {
        match self.state {
            MmeState::Initial => self.state_initial(event),
            MmeState::Final => self.state_final(event),
            MmeState::Operational => self.state_operational(event),
        }
    }

    fn check_state(&self, state_name: &str) -> bool {
        self.state.to_string() == state_name
    }
}

// ============================================================================
// Debug Helper
// ============================================================================

/// Debug helper for state machine events
pub fn mme_sm_debug(event: &MmeEvent) {
    log::trace!("MME SM Event: {}", event.name());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emm_fsm_init() {
        let mut fsm = EmmFsm::new(1);
        fsm.init();
        assert_eq!(fsm.state(), EmmState::DeRegistered);
    }

    #[test]
    fn test_emm_fsm_transition() {
        let mut fsm = EmmFsm::new(1);
        fsm.init();
        fsm.transition(EmmState::Authentication);
        assert_eq!(fsm.state(), EmmState::Authentication);
        fsm.transition(EmmState::SecurityMode);
        assert_eq!(fsm.state(), EmmState::SecurityMode);
        fsm.transition(EmmState::Registered);
        assert_eq!(fsm.state(), EmmState::Registered);
    }

    #[test]
    fn test_esm_fsm_init() {
        let mut fsm = EsmFsm::new(1);
        fsm.init();
        assert_eq!(fsm.state(), EsmState::Inactive);
    }

    #[test]
    fn test_esm_fsm_transition() {
        let mut fsm = EsmFsm::new(1);
        fsm.init();
        fsm.transition(EsmState::Active);
        assert_eq!(fsm.state(), EsmState::Active);
        fsm.transition(EsmState::PdnWillDisconnect);
        assert_eq!(fsm.state(), EsmState::PdnWillDisconnect);
    }

    #[test]
    fn test_s1ap_fsm_init() {
        let mut fsm = S1apFsm::new(1);
        fsm.init();
        assert_eq!(fsm.state(), S1apState::Operational);
    }

    #[test]
    fn test_sgsap_fsm_init() {
        let mut fsm = SgsapFsm::new(1);
        fsm.init();
        assert_eq!(fsm.state(), SgsapState::WillConnect);
    }

    #[test]
    fn test_mme_fsm_init() {
        let mut fsm = MmeFsm::new();
        fsm.init();
        assert_eq!(fsm.state(), MmeState::Operational);
    }

    #[test]
    fn test_event_creation() {
        let event = MmeEvent::new(MmeEventId::EmmMessage);
        assert_eq!(event.id, MmeEventId::EmmMessage);
        assert_eq!(event.name(), "EMM_MESSAGE");
    }

    #[test]
    fn test_timer_id_display() {
        assert_eq!(MmeTimerId::T3413.to_string(), "T3413");
        assert_eq!(MmeTimerId::MobileReachable.to_string(), "MOBILE_REACHABLE");
    }
}
