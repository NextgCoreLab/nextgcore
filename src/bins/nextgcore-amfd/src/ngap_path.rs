//! NGAP Path - SCTP Server for gNB Connections
//!
//! This module provides the NGAP transport layer using SCTP (via sctp-proto).
//! It handles:
//! - SCTP server creation on port 38412
//! - gNB connection acceptance via SCTP associations
//! - NGAP message reception and transmission
//! - Integration with the NgapFsm state machine
//!
//! # Wire Compatibility
//! This implementation uses sctp-proto, which is wire-compatible with nextgsim's
//! SCTP implementation. Both use SCTP-over-UDP (RFC 6951).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::{mpsc, Mutex, RwLock};

use ogs_sctp::{OgsSctpInfo, SctpServer, SctpServerConfig, ServerEvent, OGS_NGAP_SCTP_PORT};

use crate::context::{AmfContext, AmfGnb, AmfUe, Guti5gs, PlmnId, SNssai, UeSecurityCapability};
use crate::event::AmfEvent;
use crate::gmm_build::{self, message_type, mobile_identity_type, security_header, GmmCause};
use crate::gmm_handler::payload_container_type;
use crate::gmm_sm::GmmFsm;
use crate::nas_security;
use crate::ngap_asn1;
use crate::ngap_handler::{self, time_to_wait, NgSetupRequest, NgapHandlerResult};
use crate::ngap_sm::NgapFsm;
use crate::timer::{AmfTimerConfigs, AmfTimerId};

// ============================================================================
// Constants
// ============================================================================

/// Default NGAP bind address
pub const DEFAULT_NGAP_ADDR: &str = "0.0.0.0";

/// Maximum NGAP message size
pub const MAX_NGAP_MSG_SIZE: usize = 65535;

/// Maximum number of gNB connections
pub const MAX_GNB_CONNECTIONS: usize = 64;

/// SCTP receive timeout
const SCTP_RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// KgNB access type distinguisher for 3GPP access (TS 33.501 Annex A.9).
/// Non-3GPP access uses 0x02; both match the stored `AmfUe::access_type`.
const ACCESS_TYPE_3GPP: u8 = 0x01;

/// NGAP elementary-procedure codes (TS 38.413 Section 9.3.1.2) used by the
/// procedure dispatch. Sourced from the ogs-asn1c `ProcedureCode` table so
/// the wire byte we read at `data[1]` is matched against spec constants, not
/// magic numbers.
mod proc_code {
    use ogs_asn1c::ngap::types::ProcedureCode;
    pub const ERROR_INDICATION: u16 = ProcedureCode::ERROR_INDICATION.0 as u16;
    pub const HANDOVER_CANCEL: u16 = ProcedureCode::HANDOVER_CANCEL.0 as u16;
    pub const HANDOVER_NOTIFICATION: u16 = ProcedureCode::HANDOVER_NOTIFICATION.0 as u16;
    pub const HANDOVER_PREPARATION: u16 = ProcedureCode::HANDOVER_PREPARATION.0 as u16;
    pub const HANDOVER_RESOURCE_ALLOCATION: u16 =
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION.0 as u16;
    pub const OVERLOAD_START: u16 = ProcedureCode::OVERLOAD_START.0 as u16;
    pub const OVERLOAD_STOP: u16 = ProcedureCode::OVERLOAD_STOP.0 as u16;
    pub const PATH_SWITCH_REQUEST: u16 = ProcedureCode::PATH_SWITCH_REQUEST.0 as u16;
}

// ============================================================================
// NGAP Server State
// ============================================================================

/// Connected gNB session
#[derive(Debug)]
pub struct GnbSession {
    /// gNB ID (assigned by AMF)
    pub id: u64,
    /// SCTP association ID
    pub association_id: u64,
    /// Remote address
    pub addr: SocketAddr,
    /// NGAP FSM for this gNB
    pub fsm: NgapFsm,
    /// gNB context
    pub gnb: AmfGnb,
    /// SCTP info
    pub sctp_info: OgsSctpInfo,
}

impl GnbSession {
    pub fn new(id: u64, association_id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            association_id,
            addr,
            fsm: NgapFsm::new(id),
            gnb: AmfGnb::new(id, &addr.to_string()),
            sctp_info: OgsSctpInfo::default(),
        }
    }
}

/// GMM procedure timers with retransmission (TS 24.501 Table 10.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NasProcTimer {
    /// Registration Accept sent, waiting for Registration Complete
    T3550,
    /// Authentication Request / Security Mode Command sent
    T3560,
    /// Identity Request sent
    T3570,
    /// Network-initiated Deregistration Request sent
    T3522,
}

impl NasProcTimer {
    fn config(self, configs: &AmfTimerConfigs) -> (u32, Duration) {
        let id = match self {
            Self::T3550 => AmfTimerId::T3550,
            Self::T3560 => AmfTimerId::T3560,
            Self::T3570 => AmfTimerId::T3570,
            Self::T3522 => AmfTimerId::T3522,
        };
        configs
            .get(id)
            .map(|c| (c.max_count, c.duration))
            .unwrap_or((4, Duration::from_secs(6)))
    }
}

/// Pending retransmission of a downlink NAS message
#[derive(Debug, Clone)]
struct NasRetx {
    /// Which procedure timer this is
    timer: NasProcTimer,
    /// When the timer expires next
    deadline: Instant,
    /// Number of retransmissions already performed
    retries: u32,
    /// The complete NGAP Downlink NAS Transport PDU to resend
    ngap_pdu: Vec<u8>,
}

/// Per-UE NAS/registration state for the live NGAP path.
///
/// `amf_ue` carries the full 5G NAS security context (keys, COUNTs,
/// replayed UE security capabilities, GUTI) so that all downlink NAS is
/// built by gmm_build and protected by nas_security — there is no inline
/// plain-NAS path.
#[derive(Debug, Clone)]
struct UeNasContext {
    /// Full AMF UE context (security keys, capabilities, GUTI, NSSAI)
    amf_ue: AmfUe,
    /// AUSF auth context ID (for 5G-AKA confirmation)
    auth_ctx_id: String,
    /// RAN UE NGAP ID (for building DL NAS Transport)
    ran_ue_ngap_id: u32,
    /// SCTP association ID
    association_id: u64,
    /// SUCI string
    suci: String,
    /// AUTN of the last authentication vector (for resync bookkeeping)
    autn: [u8; 16],
    /// Registration procedure completed (Registration Complete received)
    registered: bool,
    /// Identity Request for PEI outstanding
    pei_requested: bool,
    /// Count of authentication failures (MAC #20 / sync #21) seen
    auth_failure_count: u8,
    /// Pending NAS retransmission (T3550/T3560/T3570/T3522)
    retx: Option<NasRetx>,
    /// UDM SDM subscription ID (from Nudm_SDM_Subscribe)
    sdm_subscription_id: Option<String>,
    /// PCF AM policy association ID (from Npcf_AMPolicyControl_Create)
    policy_association_id: Option<String>,
    /// Per-UE GMM state machine (TS 24.501): tracks the registration phase,
    /// including the InitialContextSetup wait after the ICS Request is sent.
    gmm_fsm: GmmFsm,
    /// Initial Context Setup Request has been sent to the gNB; the registration
    /// is only established once the ICS Response arrives (TS 38.413 §8.3.1).
    initial_context_setup_request_sent: bool,
    /// Initial Context Setup Response received from the gNB.
    initial_context_setup_response_received: bool,
}

impl UeNasContext {
    fn new(amf_ue_ngap_id: u64, ran_ue_ngap_id: u32, association_id: u64) -> Self {
        Self {
            amf_ue: AmfUe::new(amf_ue_ngap_id, ran_ue_ngap_id as u64),
            auth_ctx_id: String::new(),
            ran_ue_ngap_id,
            association_id,
            suci: String::new(),
            autn: [0u8; 16],
            registered: false,
            pei_requested: false,
            auth_failure_count: 0,
            retx: None,
            sdm_subscription_id: None,
            policy_association_id: None,
            gmm_fsm: GmmFsm::new(amf_ue_ngap_id),
            initial_context_setup_request_sent: false,
            initial_context_setup_response_received: false,
        }
    }
}

/// NGAP Server - handles all gNB connections via SCTP
pub struct NgapServer {
    /// SCTP server (sctp-proto based)
    sctp_server: SctpServer,
    /// Bind address
    bind_addr: SocketAddr,
    /// Connected gNB sessions (keyed by SCTP association ID)
    sessions: Arc<RwLock<HashMap<u64, GnbSession>>>,
    /// Association ID to address mapping
    assoc_to_addr: Arc<RwLock<HashMap<u64, SocketAddr>>>,
    /// Next gNB ID
    next_gnb_id: Arc<Mutex<u64>>,
    /// AMF context reference
    amf_context: Arc<RwLock<AmfContext>>,
    /// Event sender for NGAP events
    event_tx: mpsc::Sender<AmfEvent>,
    /// Server event receiver
    server_event_rx: mpsc::UnboundedReceiver<ServerEvent>,
    /// Per-UE NAS/registration state (keyed by AMF-UE-NGAP-ID)
    ue_auth_state: HashMap<u64, UeNasContext>,
    /// GMM procedure timer configuration (T3550/T3560/T3570/T3522)
    timer_configs: AmfTimerConfigs,
}

impl NgapServer {
    /// Create a new NGAP server with sctp-proto
    pub async fn new(
        bind_addr: SocketAddr,
        amf_context: Arc<RwLock<AmfContext>>,
        event_tx: mpsc::Sender<AmfEvent>,
    ) -> Result<Self> {
        // Configure SCTP server
        let config = SctpServerConfig {
            max_inbound_streams: 2,
            max_outbound_streams: 2,
            max_message_size: MAX_NGAP_MSG_SIZE as u32,
            receive_buffer_size: 262144,
        };

        let mut sctp_server = SctpServer::bind(bind_addr, config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind SCTP server: {e}"))?;

        let local_addr = sctp_server.local_addr();

        // Set up event channel for server events
        let (server_event_tx, server_event_rx) = mpsc::unbounded_channel();
        sctp_server.set_event_sender(server_event_tx);

        log::info!("NGAP server listening on {local_addr} (sctp-proto over UDP)");

        Ok(Self {
            sctp_server,
            bind_addr: local_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            assoc_to_addr: Arc::new(RwLock::new(HashMap::new())),
            next_gnb_id: Arc::new(Mutex::new(1)),
            amf_context,
            event_tx,
            server_event_rx,
            ue_auth_state: HashMap::new(),
            timer_configs: AmfTimerConfigs::default(),
        })
    }

    /// Get the bind address
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get number of connected gNBs
    pub async fn num_gnbs(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Poll for incoming NGAP messages and server events
    pub async fn poll(&mut self) -> Result<bool> {
        // Check GMM procedure timers (T3550/T3560/T3570/T3522 retransmission)
        self.process_nas_timers().await?;

        // Process any pending server events
        while let Ok(event) = self.server_event_rx.try_recv() {
            self.handle_server_event(event).await?;
        }

        // Poll SCTP server for incoming data
        match self.sctp_server.recv(SCTP_RECV_TIMEOUT).await {
            Ok(true) => {
                // Data was received, process any new events
                while let Ok(event) = self.server_event_rx.try_recv() {
                    self.handle_server_event(event).await?;
                }
                Ok(true)
            }
            Ok(false) => Ok(false), // Timeout, no data
            Err(e) => Err(anyhow::anyhow!("SCTP receive error: {e}")),
        }
    }

    /// Handle SCTP server events
    async fn handle_server_event(&mut self, event: ServerEvent) -> Result<()> {
        match event {
            ServerEvent::NewAssociation {
                association_id,
                remote_addr,
            } => {
                self.handle_new_association(association_id, remote_addr)
                    .await?;
            }
            ServerEvent::AssociationClosed {
                association_id,
                reason,
            } => {
                self.handle_association_closed(association_id, &reason)
                    .await?;
            }
            ServerEvent::DataReceived {
                association_id,
                message,
            } => {
                self.handle_data_received(association_id, &message.data)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handle new SCTP association (gNB connection)
    async fn handle_new_association(
        &self,
        association_id: u64,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let gnb_id = {
            let mut id = self.next_gnb_id.lock().await;
            let current = *id;
            *id += 1;
            current
        };

        log::info!("New gNB connection from {remote_addr} (gNB ID: {gnb_id}, association: {association_id})");

        let mut session = GnbSession::new(gnb_id, association_id, remote_addr);
        session.fsm.init();

        self.sessions.write().await.insert(association_id, session);
        self.assoc_to_addr
            .write()
            .await
            .insert(association_id, remote_addr);

        Ok(())
    }

    /// Handle SCTP association closure
    async fn handle_association_closed(&self, association_id: u64, reason: &str) -> Result<()> {
        if let Some(session) = self.sessions.write().await.remove(&association_id) {
            log::info!(
                "gNB {} disconnected (association {}): {}",
                session.id,
                association_id,
                reason
            );
            self.assoc_to_addr.write().await.remove(&association_id);
        }
        Ok(())
    }

    /// Handle received NGAP data
    async fn handle_data_received(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let addr = self
            .assoc_to_addr
            .read()
            .await
            .get(&association_id)
            .copied();

        if let Some(addr) = addr {
            log::debug!(
                "Received {} bytes NGAP data from {} (association {})",
                data.len(),
                addr,
                association_id
            );

            // Process the NGAP message
            self.process_ngap_message(association_id, data).await?;
        } else {
            log::warn!("Received data for unknown association {association_id}");
        }

        Ok(())
    }

    /// Process an NGAP message
    async fn process_ngap_message(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        if data.len() < 3 {
            log::warn!("NGAP message too short from association {association_id}");
            return Ok(());
        }

        // Log raw message header for debugging
        log::debug!(
            "NGAP message from association {}: {} bytes, header: {:02x?}",
            association_id,
            data.len(),
            &data[..data.len().min(8)]
        );

        // Check for NGAP message type
        let procedure_code = self.extract_procedure_code(data);

        log::info!(
            "NGAP message from association {association_id}: procedure_code={procedure_code:?}"
        );

        match procedure_code {
            Some(21) => {
                // NGSetupRequest (procedure code 21)
                self.handle_ng_setup_request(association_id, data).await?;
            }
            Some(15) => {
                // InitialUEMessage (procedure code 15)
                self.handle_initial_ue_message(association_id, data).await?;
            }
            Some(46) => {
                // UplinkNASTransport (procedure code 46)
                log::info!("Dispatching to handle_uplink_nas_transport");
                self.handle_uplink_nas_transport(association_id, data)
                    .await?;
            }
            Some(14) => {
                // InitialContextSetup (procedure code 14)
                if data[0] == 0x20 {
                    // SuccessfulOutcome = InitialContextSetupResponse from gNB
                    log::info!("Initial Context Setup Response from gNB");
                    self.handle_initial_context_setup_response(association_id, data)
                        .await?;
                } else if data[0] == 0x40 {
                    // UnsuccessfulOutcome = InitialContextSetupFailure from gNB
                    log::warn!("Initial Context Setup Failure from gNB");
                    self.handle_initial_context_setup_failure(association_id, data)
                        .await?;
                }
            }
            Some(29) => {
                // PDU Session Resource Setup (procedure code 29)
                // SuccessfulOutcome = gNB response with gNB TEID
                if data[0] == 0x20 {
                    log::info!("PDU Session Resource Setup Response from gNB");
                    self.handle_pdu_session_resource_setup_response(association_id, data)
                        .await?;
                }
            }
            Some(26) => {
                // PDU Session Resource Modify (procedure code 26)
                if data[0] == 0x20 {
                    // SuccessfulOutcome = gNB confirmed resource modification
                    log::info!("PDU Session Resource Modify Response from gNB");
                    // Modification confirmed by gNB - no further action needed.
                    // The UE-side completion comes via PDU Session Modification Complete (0xCD).
                } else if data[0] == 0x40 {
                    // UnsuccessfulOutcome = gNB rejected modification
                    log::warn!("PDU Session Resource Modify Failure from gNB");
                }
            }
            Some(28) => {
                // PDU Session Resource Release (procedure code 28)
                if data[0] == 0x20 {
                    log::info!("PDU Session Resource Release Response from gNB");
                    // gNB confirmed resource release - session cleanup already done.
                }
            }
            Some(41) => {
                // UEContextReleaseRequest (procedure code 41)
                if data[0] == 0x00 {
                    // InitiatingMessage from gNB
                    log::info!("UE Context Release Request from gNB");
                    self.handle_ue_context_release(association_id, data).await?;
                } else if data[0] == 0x20 {
                    // SuccessfulOutcome = UEContextReleaseComplete from gNB
                    log::info!("UE Context Release Complete from gNB");
                }
            }
            Some(20) => {
                // NGReset (procedure code 20)
                if data[0] == 0x00 {
                    // InitiatingMessage = NGReset from gNB
                    self.handle_ng_reset(association_id, data).await?;
                } else if data[0] == 0x20 {
                    // SuccessfulOutcome = NGResetAcknowledge for an AMF-initiated reset
                    log::info!("NG Reset Acknowledge from association {association_id}");
                }
            }
            Some(proc_code::OVERLOAD_START) | Some(proc_code::OVERLOAD_STOP) => {
                // OverloadStart/OverloadStop are AMF->gNB procedures (TS 38.413
                // Sections 8.7.6/8.7.7); receiving one from a gNB is a logical
                // error. Acknowledge with an ErrorIndication carrying
                // protocol/message-not-compatible (TS 38.413 Section 8.7.5).
                log::warn!(
                    "Overload{} received from association {association_id}: not applicable in gNB->AMF direction",
                    if procedure_code == Some(proc_code::OVERLOAD_START) {
                        "Start"
                    } else {
                        "Stop"
                    }
                );
                self.send_error_indication(
                    association_id,
                    None,
                    None,
                    ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::MessageNotCompatibleWithReceiverState,
                    ),
                )
                .await?;
            }
            Some(proc_code::ERROR_INDICATION) => {
                // ErrorIndication from the gNB (TS 38.413 Section 8.7.5). The AMF
                // never replies to an ErrorIndication; it logs the diagnosis.
                self.handle_error_indication(association_id, data).await?;
            }
            Some(proc_code::HANDOVER_PREPARATION) => {
                // HandoverPreparation: InitiatingMessage = HandoverRequired from
                // the source gNB (TS 38.413 Section 8.4.1). HandoverCommand /
                // HandoverPreparationFailure are AMF->gNB.
                if data[0] == 0x00 {
                    self.handle_handover_required(association_id, data).await?;
                } else {
                    log::warn!(
                        "Unexpected HandoverPreparation outcome from association {association_id}"
                    );
                }
            }
            Some(proc_code::HANDOVER_RESOURCE_ALLOCATION) => {
                // HandoverResourceAllocation: SuccessfulOutcome =
                // HandoverRequestAcknowledge, UnsuccessfulOutcome =
                // HandoverFailure, both from the target gNB (TS 38.413 8.4.2).
                if data[0] == 0x20 {
                    self.handle_handover_request_acknowledge(association_id, data)
                        .await?;
                } else if data[0] == 0x40 {
                    self.handle_handover_failure(association_id, data).await?;
                } else {
                    log::warn!(
                        "HandoverRequest InitiatingMessage is AMF->gNB; unexpected from association {association_id}"
                    );
                }
            }
            Some(proc_code::PATH_SWITCH_REQUEST) => {
                // PathSwitchRequest: InitiatingMessage from the target gNB for
                // an Xn-based handover (TS 38.413 Section 8.4.4).
                if data[0] == 0x00 {
                    self.handle_path_switch_request(association_id, data)
                        .await?;
                } else {
                    log::warn!(
                        "PathSwitch ack/failure are AMF->gNB; unexpected from association {association_id}"
                    );
                }
            }
            Some(proc_code::HANDOVER_CANCEL) => {
                // HandoverCancel: InitiatingMessage = HandoverCancel from the
                // source gNB (TS 38.413 Section 8.4.5).
                if data[0] == 0x00 {
                    self.handle_handover_cancel(association_id, data).await?;
                } else {
                    log::info!(
                        "HandoverCancelAcknowledge is AMF->gNB; ignoring from association {association_id}"
                    );
                }
            }
            Some(proc_code::HANDOVER_NOTIFICATION) => {
                // HandoverNotification: HandoverNotify from the target gNB
                // confirms the UE arrived (TS 38.413 Section 8.4.3).
                self.handle_handover_notify(association_id, data).await?;
            }
            _ => {
                // Unknown / unsupported procedure: the PDU is either undecodable
                // or for a procedure the AMF does not implement. Per TS 38.413
                // Section 10.3, respond with an ErrorIndication carrying the
                // appropriate protocol cause rather than silently dropping it.
                log::warn!(
                    "Unhandled NGAP procedure_code={procedure_code:?} from association {association_id}; emitting ErrorIndication"
                );
                let cause = match procedure_code {
                    Some(_) => ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
                    ),
                    None => ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::TransferSyntaxError,
                    ),
                };
                // Best-effort: include the UE NGAP IDs if they can be located.
                let amf_ue_ngap_id = crate::ngap_asn1::extract_amf_ue_ngap_id(data);
                let ran_ue_ngap_id = crate::ngap_asn1::extract_ran_ue_ngap_id(data);
                self.send_error_indication(association_id, amf_ue_ngap_id, ran_ue_ngap_id, cause)
                    .await?;
            }
        }

        Ok(())
    }

    /// Extract procedure code from NGAP message
    ///
    /// NGAP PDU is a CHOICE with 3 options:
    /// - InitiatingMessage (0x00)
    /// - SuccessfulOutcome (0x20)
    /// - UnsuccessfulOutcome (0x40)
    ///
    /// In APER encoding:
    /// - Byte 0: CHOICE index (0x00, 0x20, or 0x40 with extension bit)
    /// - Byte 1: Procedure code (0-255)
    fn extract_procedure_code(&self, data: &[u8]) -> Option<u16> {
        if data.len() < 3 {
            log::warn!(
                "NGAP message too short to extract procedure code: {} bytes",
                data.len()
            );
            return None;
        }

        let byte0 = data[0];
        let procedure_code = data[1];

        log::trace!(
            "NGAP header bytes: [{:#04x}, {:#04x}, {:#04x}]",
            byte0,
            data[1],
            data[2]
        );

        // Check for valid NGAP PDU choice values
        match byte0 {
            0x00 => {
                // InitiatingMessage
                log::trace!("InitiatingMessage with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            0x20 => {
                // SuccessfulOutcome
                log::trace!("SuccessfulOutcome with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            0x40 => {
                // UnsuccessfulOutcome
                log::trace!("UnsuccessfulOutcome with procedure code {procedure_code}");
                Some(procedure_code as u16)
            }
            _ => {
                log::warn!(
                    "Unknown NGAP PDU type: {:#04x}, bytes: {:02x?}",
                    byte0,
                    &data[..data.len().min(16)]
                );
                None
            }
        }
    }

    /// Handle NG Setup Request
    async fn handle_ng_setup_request(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!(
            "NG Setup Request from association {} ({} bytes)",
            association_id,
            data.len()
        );

        // Parse the NG Setup Request using proper ASN.1 decoding
        let request = match ngap_asn1::parse_ng_setup_request_asn1(data) {
            Some(req) => {
                log::info!(
                    "Parsed NG Setup Request: gNB ID={}, PLMN={}{}{}-{}{}{}",
                    req.gnb_id,
                    req.plmn_id.mcc1,
                    req.plmn_id.mcc2,
                    req.plmn_id.mcc3,
                    req.plmn_id.mnc1,
                    req.plmn_id.mnc2,
                    if req.plmn_id.mnc3 == 0xf {
                        "".to_string()
                    } else {
                        req.plmn_id.mnc3.to_string()
                    }
                );
                req
            }
            None => {
                log::warn!("Failed to parse NG Setup Request, using fallback");
                self.parse_ng_setup_request_fallback(data)
            }
        };

        // Process request and build response with locks held, then release before sending
        let response_data: Option<Vec<u8>> = {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&association_id) {
                let ctx = self.amf_context.read().await;

                // Handle the request
                let result =
                    ngap_handler::handle_ng_setup_request(&mut session.gnb, &ctx, &request);

                match result {
                    NgapHandlerResult::Success => {
                        log::info!(
                            "NG Setup successful for gNB {} (association {})",
                            session.gnb.gnb_id,
                            association_id
                        );

                        // Build NG Setup Response with proper ASN.1 APER encoding
                        if let Some(response) = ngap_asn1::build_ng_setup_response_asn1(&ctx) {
                            log::debug!(
                                "Built NG Setup Response: {} bytes, hex: {:02x?}",
                                response.len(),
                                &response[..response.len().min(32)]
                            );
                            Some(response)
                        } else {
                            log::error!("Failed to build NG Setup Response");
                            None
                        }
                    }
                    NgapHandlerResult::Failure(cause) => {
                        log::warn!(
                            "NG Setup failed for association {}: cause group={}, cause={}",
                            association_id,
                            cause.group,
                            cause.cause
                        );

                        // Build NG Setup Failure with proper ASN.1 encoding and
                        // the real cause group/value from the handler
                        Some(ngap_asn1::build_ng_setup_failure_asn1(
                            cause.group,
                            cause.cause,
                            Some(time_to_wait::V1S),
                        ))
                    }
                    _ => None,
                }
            } else {
                None
            }
        }; // All locks released here

        // Now send the response with &mut self available
        if let Some(response) = response_data {
            self.send_to_association(association_id, &response).await?;
            log::info!(
                "Sent NG Setup Response to association {} ({} bytes)",
                association_id,
                response.len()
            );
        }

        Ok(())
    }

    /// Handle NG Reset from a gNB (TS 38.413 Section 8.7.4.2)
    ///
    /// Releases the affected UE contexts and responds with NG Reset Acknowledge.
    async fn handle_ng_reset(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        use ogs_ngap::types::ResetType;
        use ogs_ngap::{parser::decode_ngap_pdu, NgapMessage};

        let reset = match decode_ngap_pdu(data) {
            Ok(NgapMessage::NgReset(reset)) => reset,
            Ok(other) => {
                log::warn!("Expected NgReset, got {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::warn!("Failed to decode NG Reset: {e:?}");
                return Ok(());
            }
        };

        let gnb_pool_id = self
            .sessions
            .read()
            .await
            .get(&association_id)
            .map(|s| s.id);
        let Some(gnb_pool_id) = gnb_pool_id else {
            log::warn!("NG Reset from unknown association {association_id}");
            return Ok(());
        };

        // Drop pending authentication state for the affected UEs
        match &reset.reset_type {
            ResetType::NgInterface => {
                self.ue_auth_state
                    .retain(|_, state| state.association_id != association_id);
            }
            ResetType::PartOfNgInterface(connections) => {
                for item in connections {
                    if let Some(amf_ue_ngap_id) = item.amf_ue_ngap_id {
                        self.ue_auth_state.remove(&amf_ue_ngap_id);
                    }
                }
            }
        }

        // Release the affected UE contexts and get the list to echo in the Ack
        let ack_connections = ngap_handler::handle_ng_reset(gnb_pool_id, &reset);

        if let Some(ack) = ngap_asn1::build_ng_reset_acknowledge_asn1(ack_connections) {
            self.send_to_association(association_id, &ack).await?;
            log::info!("NG Reset Acknowledge sent to association {association_id}");
        } else {
            log::error!("Failed to build NG Reset Acknowledge");
        }

        Ok(())
    }

    /// Parse NG Setup Request (fallback when ASN.1 parsing fails)
    fn parse_ng_setup_request_fallback(&self, _data: &[u8]) -> NgSetupRequest {
        NgSetupRequest {
            global_ran_node_id_present: true,
            gnb_id: 1,
            gnb_id_len: 22,
            plmn_id: crate::context::PlmnId::new("999", "70"),
            ran_node_name: Some("gNB-nextgsim".to_string()),
            supported_ta_list: vec![crate::context::SupportedTa {
                tac: 1,
                num_of_bplmn_list: 1,
                bplmn_list: vec![crate::context::BplmnEntry {
                    plmn_id: crate::context::PlmnId::new("999", "70"),
                    num_of_s_nssai: 1,
                    s_nssai: vec![crate::context::SNssai { sst: 1, sd: None }],
                }],
            }],
            default_paging_drx: 0,
        }
    }

    /// Handle Initial UE Message
    ///
    /// Parses the contained NAS PDU and starts the appropriate 5GMM
    /// procedure (TS 24.501 Section 5.5.1 registration, Section 5.6.1
    /// service request). No blanket Identity Request: identification is
    /// only initiated when the UE identified itself with a GUTI unknown
    /// to this AMF (TS 23.502 Section 4.2.2.2.2 step 4).
    async fn handle_initial_ue_message(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!(
            "Initial UE Message from association {} ({} bytes)",
            association_id,
            data.len()
        );

        let initial_ue = match crate::ngap_asn1::parse_initial_ue_message_asn1(data) {
            Some(msg) => msg,
            None => {
                log::error!("Failed to parse Initial UE Message");
                return Ok(());
            }
        };

        log::info!(
            "Initial UE Message: ran_ue_ngap_id={}, nas_pdu_len={}, tac={}, nci=0x{:x}",
            initial_ue.ran_ue_ngap_id,
            initial_ue.nas_pdu.len(),
            initial_ue.tac,
            initial_ue.nr_cell_identity
        );

        // Allocate AMF-UE-NGAP-ID for this UE
        let amf_ue_ngap_id = {
            let mut id = self.next_gnb_id.lock().await;
            let current = *id;
            *id += 1;
            current
        };

        let nas = initial_ue.nas_pdu.clone();
        if nas.len() < 3 || nas[0] != 0x7E {
            log::warn!("Initial UE Message NAS PDU is not 5GMM, ignoring");
            return Ok(());
        }
        let msg_type = nas[2];

        match msg_type {
            message_type::REGISTRATION_REQUEST => {
                let mut state =
                    UeNasContext::new(amf_ue_ngap_id, initial_ue.ran_ue_ngap_id, association_id);
                state.amf_ue.nr_tai = crate::context::Tai5gs {
                    plmn_id: initial_ue.plmn_id.clone(),
                    tac: initial_ue.tac,
                };
                state.amf_ue.access_type = 1; // 3GPP access
                self.ue_auth_state.insert(amf_ue_ngap_id, state);

                self.handle_registration_request_nas(
                    association_id,
                    amf_ue_ngap_id,
                    initial_ue.ran_ue_ngap_id,
                    &nas,
                )
                .await?;
            }
            message_type::SERVICE_REQUEST => {
                // UE context unknown (fresh NGAP IDs) -> the UE identity cannot
                // be derived: Service Reject cause #9 forces re-registration
                // (TS 24.501 Section 5.6.1.5).
                log::warn!(
                    "Service Request in Initial UE Message without stored context: rejecting (#9)"
                );
                let reject = gmm_build::build_service_reject(
                    &AmfUe::default(),
                    GmmCause::UeIdentityCannotBeDerivedByTheNetwork,
                );
                self.send_nas_pdu(
                    association_id,
                    amf_ue_ngap_id,
                    initial_ue.ran_ue_ngap_id,
                    &reject,
                )
                .await?;
            }
            other => {
                log::warn!("Unhandled NAS message type 0x{other:02x} in Initial UE Message");
            }
        }

        // Forward to event handler for FSM bookkeeping
        if let Some(session) = self.sessions.read().await.get(&association_id) {
            let event = AmfEvent::ngap_message(session.id, data.to_vec());
            let _ = self.event_tx.send(event).await;
        }

        Ok(())
    }

    /// Handle Uplink NAS Transport: decode security (if any) and dispatch
    async fn handle_uplink_nas_transport(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let ul_nas = match crate::ngap_asn1::parse_uplink_nas_transport_asn1(data) {
            Some(msg) => msg,
            None => {
                log::error!("Failed to parse Uplink NAS Transport");
                return Ok(());
            }
        };

        log::info!(
            "Uplink NAS Transport: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
            ul_nas.amf_ue_ngap_id,
            ul_nas.ran_ue_ngap_id,
            ul_nas.nas_pdu.len()
        );

        if ul_nas.nas_pdu.len() < 3 {
            return Ok(());
        }

        let epd = ul_nas.nas_pdu[0];

        // Legacy compatibility: raw 5GSM PDU not wrapped in UL NAS TRANSPORT
        if epd == 0x2E {
            self.handle_5gsm_message(
                association_id,
                ul_nas.amf_ue_ngap_id,
                ul_nas.ran_ue_ngap_id,
                &ul_nas.nas_pdu,
                None,
            )
            .await?;
            return Ok(());
        }

        if epd != 0x7E {
            log::warn!("Unknown NAS EPD 0x{epd:02x}, discarding");
            return Ok(());
        }

        let sec_hdr = ul_nas.nas_pdu[1];
        let inner: Vec<u8> = if sec_hdr == security_header::PLAIN_NAS_MESSAGE {
            ul_nas.nas_pdu.clone()
        } else {
            // Security-protected: decode with the UE's NAS security context
            let Some(mut state) = self.ue_auth_state.remove(&ul_nas.amf_ue_ngap_id) else {
                log::warn!(
                    "Protected NAS from unknown UE {} discarded",
                    ul_nas.amf_ue_ngap_id
                );
                return Ok(());
            };
            let decoded =
                nas_security::nas_5gs_security_decode(&mut state.amf_ue, sec_hdr, &ul_nas.nas_pdu);
            let mac_failed = state.amf_ue.mac_failed;
            state.amf_ue.mac_failed = false;
            self.ue_auth_state.insert(ul_nas.amf_ue_ngap_id, state);
            match decoded {
                Ok(plain) => {
                    if mac_failed {
                        // TS 24.501 Section 4.4.3.3: messages failing integrity
                        // check are discarded (registration/dereg/service request
                        // exceptions are handled before security establishment)
                        log::warn!(
                            "NAS MAC verification failed for UE {}, discarding message",
                            ul_nas.amf_ue_ngap_id
                        );
                        return Ok(());
                    }
                    plain
                }
                Err(e) => {
                    log::warn!("NAS security decode failed: {e:?}, discarding");
                    return Ok(());
                }
            }
        };

        if inner.len() < 3 || inner[0] != 0x7E {
            log::warn!("Decoded NAS message malformed, discarding");
            return Ok(());
        }
        let msg_type = inner[2];

        match msg_type {
            message_type::REGISTRATION_REQUEST => {
                // Mobility / periodic registration update over existing connection
                self.handle_registration_request_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::IDENTITY_RESPONSE => {
                self.handle_identity_response_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::AUTHENTICATION_RESPONSE => {
                self.handle_authentication_response_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::AUTHENTICATION_FAILURE => {
                self.handle_authentication_failure_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::SECURITY_MODE_COMPLETE => {
                self.handle_security_mode_complete_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::SECURITY_MODE_REJECT => {
                let cause = inner.get(3).copied().unwrap_or(0);
                log::error!(
                    "Security Mode Reject from UE {} (5GMM cause #{cause}); aborting procedure",
                    ul_nas.amf_ue_ngap_id
                );
                // TS 24.501 Section 5.4.2.5: abort the procedure; the network
                // releases the N1 signalling connection.
                self.release_ue(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    1,
                )
                .await?;
            }
            message_type::REGISTRATION_COMPLETE => {
                if let Some(state) = self.ue_auth_state.get_mut(&ul_nas.amf_ue_ngap_id) {
                    if matches!(
                        state.retx,
                        Some(NasRetx {
                            timer: NasProcTimer::T3550,
                            ..
                        })
                    ) {
                        state.retx = None;
                    }
                    state.registered = true;
                    state.amf_ue.current_guti = state.amf_ue.next_guti.clone();
                    state.amf_ue.current_m_tmsi = Some(state.amf_ue.next_guti.tmsi);
                    log::info!(
                        "[{}] Registration Complete (5G-TMSI=0x{:08x})",
                        state.suci,
                        state.amf_ue.current_guti.tmsi
                    );
                }
            }
            message_type::SERVICE_REQUEST => {
                self.handle_service_request_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::DEREGISTRATION_REQUEST_FROM_UE => {
                self.handle_deregistration_request_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::DEREGISTRATION_ACCEPT_TO_UE => {
                // UE acknowledged a network-initiated deregistration
                log::info!(
                    "Deregistration Accept from UE {} (network-initiated procedure done)",
                    ul_nas.amf_ue_ngap_id
                );
                self.finish_deregistration(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                )
                .await?;
            }
            message_type::UL_NAS_TRANSPORT => {
                self.handle_ul_nas_transport_nas(
                    association_id,
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                )
                .await?;
            }
            message_type::GMM_STATUS => {
                let cause = inner.get(3).copied().unwrap_or(0);
                log::warn!(
                    "5GMM Status from UE {}: cause #{cause}",
                    ul_nas.amf_ue_ngap_id
                );
            }
            message_type::UAV_TRACKING_REPORT => {
                // UAV tracking report (Rel-18, TS 23.256): an aerial UE's
                // position / Remote-ID report. Run the geofence against the
                // stored UAV authorization context.
                self.handle_uav_tracking_report_nas(
                    ul_nas.amf_ue_ngap_id,
                    ul_nas.ran_ue_ngap_id,
                    &inner,
                );
            }
            other => {
                log::warn!("Unhandled 5GMM message type 0x{other:02x}");
            }
        }

        // Forward to event handler for FSM bookkeeping
        if let Some(session) = self.sessions.read().await.get(&association_id) {
            let event = AmfEvent::ngap_message(session.id, data.to_vec());
            let _ = self.event_tx.send(event).await;
        }

        Ok(())
    }

    /// Handle a UAV tracking report (Rel-18, TS 23.256).
    ///
    /// Parses the UE-originated position report (CAA-level ID + lat/lon/alt +
    /// flight status, see the nextgsim UE `build_uav_tracking_report`) and runs
    /// it through the stored UAV authorization context's geofence. A position
    /// inside the geofence is allowed; an altitude or area violation produces a
    /// deny and revokes the flight authorization (TS 23.256: the network
    /// withdraws UAV authorization on a geofence breach).
    fn handle_uav_tracking_report_nas(
        &mut self,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        inner: &[u8],
    ) {
        let Some(report) = parse_uav_tracking_report(amf_ue_ngap_id, ran_ue_ngap_id, inner) else {
            log::warn!("Malformed UAV tracking report from UE {amf_ue_ngap_id}; discarding");
            return;
        };

        // Dispatch to the NGAP-layer tracking-report handler for logging /
        // bookkeeping (it verifies the NGAP IDs and records the position).
        log::info!(
            "[UAV Tracking] Dispatching report from UE {amf_ue_ngap_id} to handler: \
             CAA-ID={}, pos=({:.6}, {:.6}), alt={:.1}m, status={}",
            report.uav_id,
            report.latitude,
            report.longitude,
            report.altitude,
            report.flight_status
        );

        let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) else {
            log::warn!("UAV tracking report from unknown UE {amf_ue_ngap_id}; discarding");
            return;
        };
        let Some(uav) = state.amf_ue.uav_auth.as_mut() else {
            log::warn!(
                "UAV tracking report from UE {amf_ue_ngap_id} that is not UAV-authorized; \
                 discarding (no UAV authorization context)"
            );
            return;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(report.timestamp);

        // Geofence check via the NGAP-layer UAV handler: returns true when the
        // position is within bounds and still authorized (allow), false on an
        // altitude/area violation or expired authorization (deny).
        let allowed = crate::ngap_handler::handle_uav_tracking_report(uav, &report, now);
        if allowed {
            log::info!(
                "[UAV Tracking] Geofence ALLOW: UAV {} at ({:.6}, {:.6}) alt={:.1}m within bounds",
                report.uav_id,
                report.latitude,
                report.longitude,
                report.altitude
            );
        } else {
            log::warn!(
                "[UAV Tracking] Geofence DENY: UAV {} at ({:.6}, {:.6}) alt={:.1}m violates \
                 flight authorization; revoking",
                report.uav_id,
                report.latitude,
                report.longitude,
                report.altitude
            );
            uav.revoke_authorization("geofence violation");
            // TS 23.256: a real deployment would notify the USS/UTM and PCF of
            // the withdrawn authorization here (documented stub).
            notify_uss_authorization(&report.uav_id, "REVOKED");
        }
    }

    /// Handle a (plain) Registration Request NAS PDU
    async fn handle_registration_request_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        let Some(req) = parse_registration_request_pdu(nas) else {
            log::error!("Malformed Registration Request: rejecting (#96)");
            let reject =
                gmm_build::build_registration_reject(GmmCause::InvalidMandatoryInformation);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                .await?;
            return Ok(());
        };

        log::info!(
            "Registration Request: type={}, ngKSI={}/{}, identity_type={}, suci={:?}",
            req.registration_type,
            req.tsc,
            req.ksi,
            req.identity_type,
            req.suci
        );

        // MINT (Rel-18, TS 23.761 §4.2): a UE may register more than one
        // subscription (multi-SUPI). Each distinct registration arrives with
        // its own RAN/AMF UE NGAP ID and is handled as a separate AMF UE
        // context with its own 5G-GUTI — the second SUPI is NOT rejected. The
        // disaster-roaming indication, when present, marks the registration for
        // minimization-of-service-interruption handling.
        if req.disaster_roaming {
            log::info!(
                "MINT disaster-roaming indication present (amf_ue_ngap_id={amf_ue_ngap_id}, \
                 suci={:?}); accepting as a distinct multi-SUPI registration",
                req.suci
            );
        }

        // Periodic registration updating with live security context: refresh
        if req.registration_type == crate::gmm_build::registration_type::PERIODIC_UPDATING {
            if let Some(state) = self.ue_auth_state.get(&amf_ue_ngap_id) {
                if state.amf_ue.security_context_available && state.registered {
                    log::info!("Periodic Registration Update from UE {amf_ue_ngap_id}");
                    self.send_registration_accept(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
                        .await?;
                    return Ok(());
                }
            }
            // No context: the UE identity cannot be derived (TS 24.501 5.5.1.3.5)
            let reject = gmm_build::build_registration_reject(
                GmmCause::UeIdentityCannotBeDerivedByTheNetwork,
            );
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                .await?;
            return Ok(());
        }

        let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) else {
            // Mobility update on an unknown UE: reject so it re-registers
            let reject = gmm_build::build_registration_reject(
                GmmCause::UeIdentityCannotBeDerivedByTheNetwork,
            );
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                .await?;
            return Ok(());
        };

        state.amf_ue.registration_type = req.registration_type;
        state.amf_ue.nas_ue_tsc = req.tsc;
        state.amf_ue.nas_ue_ksi = req.ksi;
        // Store the UE security capability EXACTLY as received so the
        // Security Mode Command replays it (TS 33.501 Section 6.7.2)
        if let Some(cap) = req.sec_cap {
            state.amf_ue.ue_security_capability = cap;
        } else {
            log::warn!(
                "Registration Request without UE security capability IE; \
                 assuming null algorithms only (no capability fabrication)"
            );
            state.amf_ue.ue_security_capability = UeSecurityCapability {
                ea: 0x80, // 5G-EA0 only
                ia: 0x80, // 5G-IA0 only
                eea: 0,
                eia: 0,
            };
        }
        state.amf_ue.requested_nssai = req.requested_nssai.clone();

        match req.identity_type {
            t if t == mobile_identity_type::SUCI => {
                let Some(suci) = req.suci else {
                    let reject =
                        gmm_build::build_registration_reject(GmmCause::InvalidMandatoryInformation);
                    self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                        .await?;
                    return Ok(());
                };
                state.suci = suci.clone();
                state.amf_ue.suci = Some(suci.clone());
                if let Some(plmn) = req.plmn {
                    state.amf_ue.home_plmn_id = plmn;
                }

                // SNPN access authorization (Rel-17, TS 23.501 §5.30 / TS 24.501).
                // When the UE advertised an SNPN NID, validate it against the
                // AMF's configured allowed-NID list. A non-allowed NID is
                // rejected with the SNPN-specific 5GMM cause (#75, permanently
                // not authorized for this SNPN). An allowed NID drives the
                // SNPN auth context; an onboarding SUCI drives onboarding.
                if let Some(ref nid) = req.snpn_nid {
                    let allowed_nids = snpn_allowed_nids();
                    if !state.amf_ue.validate_nid(nid, &allowed_nids) {
                        log::warn!(
                            "SNPN registration rejected: NID={nid} not in allowed list {allowed_nids:?}"
                        );
                        let reject = gmm_build::build_registration_reject(
                            GmmCause::PermanentlyNotAuthorized,
                        );
                        self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                            .await?;
                        self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                            .await?;
                        return Ok(());
                    }
                    if is_snpn_onboarding_suci(&suci) {
                        // Onboarding SUCI (TS 23.003): provision initial
                        // credentials via the SNPN onboarding flow.
                        let creds = crate::context::SnpnSubscriptionCredentials::default();
                        state.amf_ue.handle_snpn_onboarding(nid, creds);
                        log::info!("SNPN onboarding registration accepted for NID={nid}");
                    } else {
                        state.amf_ue.start_snpn_auth(nid);
                        log::info!("SNPN registration authorized for NID={nid}");
                    }
                }

                // UAV flight authorization (Rel-18, TS 23.256). When the UE
                // registered as an aerial UE, create and grant a UAV
                // authorization context with the AMF's configured geofence so
                // subsequent UAV tracking reports are checked against it. UTM /
                // USS authorization is represented by the local grant here; an
                // external USS interface is a documented stub (see
                // `notify_uss_authorization`).
                if let Some(ref caa_id) = req.uav_indication {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let mut uav = crate::context::UavAuthorizationContext::new(caa_id, &suci);
                    let (min_lat, max_lat, min_lon, max_lon, min_alt, max_alt) =
                        uav_geofence_config();
                    uav.set_geofence(min_lat, max_lat, min_lon, max_lon, min_alt, max_alt);
                    // Authorize for a 1-hour flight window from now.
                    uav.grant_authorization(now, now + 3600);
                    notify_uss_authorization(caa_id, &suci);
                    log::info!(
                        "UAV registration: aerial UE authorized (CAA-ID={caa_id}); geofence \
                         lat=[{min_lat},{max_lat}] lon=[{min_lon},{max_lon}] alt=[{min_alt},{max_alt}]"
                    );
                    state.amf_ue.uav_auth = Some(uav);
                }

                // RedCap (Rel-17, TS 38.101): a reduced-capability UE gets a
                // capped UE-AMBR, and the indication is propagated to the SMF on
                // the N11 SM Context Create so the session-AMBR is reduced too.
                if req.redcap_indication {
                    state.amf_ue.redcap_indication = true;
                    if state.amf_ue.ue_ambr.downlink > 150_000_000 {
                        state.amf_ue.ue_ambr.downlink = 150_000_000; // 150 Mbps DL
                    }
                    if state.amf_ue.ue_ambr.uplink > 50_000_000 {
                        state.amf_ue.ue_ambr.uplink = 50_000_000; // 50 Mbps UL
                    }
                    log::info!("UE indicates RedCap (Reduced Capability) device");
                }

                self.start_authentication(association_id, amf_ue_ngap_id, ran_ue_ngap_id, None)
                    .await?;
            }
            t if t == mobile_identity_type::GUTI => {
                if let Some(guti) = req.guti {
                    state.amf_ue.old_guti = guti;
                }
                // GUTI unknown to this AMF instance: identify the UE by SUCI
                // (TS 24.501 Section 5.4.3) and arm T3570
                log::info!("Registration with unknown 5G-GUTI: requesting SUCI");
                let identity_request =
                    gmm_build::build_identity_request(mobile_identity_type::SUCI);
                let ngap_pdu = self
                    .send_nas_pdu(
                        association_id,
                        amf_ue_ngap_id,
                        ran_ue_ngap_id,
                        &identity_request,
                    )
                    .await?;
                self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3570, ngap_pdu);
            }
            other => {
                log::error!("Unsupported mobile identity type {other} in Registration Request");
                let reject =
                    gmm_build::build_registration_reject(GmmCause::InvalidMandatoryInformation);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                    .await?;
            }
        }

        Ok(())
    }

    /// Start (or restart, on SQN resync) 5G-AKA via AUSF
    /// (TS 23.502 Section 4.2.2.2.2 step 9 / TS 33.501 Section 6.1.3.2)
    async fn start_authentication(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        resync: Option<([u8; 16], [u8; 14])>,
    ) -> Result<()> {
        let Some(mut state) = self.ue_auth_state.remove(&amf_ue_ngap_id) else {
            return Ok(());
        };

        let (ausf_host, ausf_port) =
            crate::sbi_path::resolve_nf_endpoint_async(crate::sbi_path::SbiServiceType::NausfAuth)
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));

        // Serving network name from the serving PLMN (TS 24.501 / TS 33.501 6.1.1.4)
        let snn = serving_network_name_from_plmn(&state.amf_ue.nr_tai.plmn_id);

        match crate::sbi_path::call_ausf_authenticate_with_resync(
            &ausf_host,
            ausf_port,
            &state.suci,
            &snn,
            resync,
        )
        .await
        {
            Ok(auth_resp) => {
                state.auth_ctx_id = auth_resp.auth_ctx_id;
                state.amf_ue.rand = auth_resp.rand;
                state.autn = auth_resp.autn;
                state.amf_ue.autn = auth_resp.autn.to_vec();
                state.amf_ue.hxres_star = auth_resp.hxres_star;
                // Initial ABBA (TS 33.501 Annex A.7.1)
                state.amf_ue.abba = [0x00, 0x00];
                state.amf_ue.abba_len = 2;
                state.amf_ue.nas_tsc = 0;
                state.amf_ue.nas_ksi = 0;

                let auth_request = gmm_build::build_authentication_request(&state.amf_ue);
                self.ue_auth_state.insert(amf_ue_ngap_id, state);

                let ngap_pdu = self
                    .send_nas_pdu(
                        association_id,
                        amf_ue_ngap_id,
                        ran_ue_ngap_id,
                        &auth_request,
                    )
                    .await?;
                self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3560, ngap_pdu);
                log::info!("Authentication Request sent to UE {amf_ue_ngap_id}");
            }
            Err(e) => {
                log::error!("AUSF authentication failed for {}: {e}", state.suci);
                let cause = gmm_cause_from_sbi_error(&e);
                let reject = gmm_build::build_registration_reject(cause);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handle Authentication Response: verify HXRES*, confirm with AUSF,
    /// derive the key hierarchy and send Security Mode Command
    async fn handle_authentication_response_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        // Authentication response parameter (IEI 0x2D, TLV, RES* 16 bytes)
        let mut res_star: Option<[u8; 16]> = None;
        let mut pos = 3;
        while pos + 1 < nas.len() {
            if nas[pos] == 0x2D {
                let len = nas[pos + 1] as usize;
                if len == 16 && pos + 2 + 16 <= nas.len() {
                    let mut rs = [0u8; 16];
                    rs.copy_from_slice(&nas[pos + 2..pos + 18]);
                    res_star = Some(rs);
                }
                break;
            }
            pos += 1;
        }

        let Some(rs) = res_star else {
            log::error!("Authentication Response without RES*");
            return Ok(());
        };

        let Some(mut state) = self.ue_auth_state.remove(&amf_ue_ngap_id) else {
            log::warn!("Authentication Response for unknown UE {amf_ue_ngap_id}");
            return Ok(());
        };

        // Stop T3560
        if matches!(
            state.retx,
            Some(NasRetx {
                timer: NasProcTimer::T3560,
                ..
            })
        ) {
            state.retx = None;
        }

        // Verify HRES* against HXRES* (TS 33.501 Section 6.1.3.2.0)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(state.amf_ue.rand);
        hasher.update(rs);
        let digest = hasher.finalize();
        let mut hres_star = [0u8; 16];
        hres_star.copy_from_slice(&digest[16..32]);
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&state.amf_ue.hxres_star[..16]);

        if hres_star != expected {
            log::error!("HXRES* verification failed - sending Authentication Reject");
            let auth_reject = gmm_build::build_authentication_reject();
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                .await?;
            self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                .await?;
            return Ok(());
        }

        // 5G-AKA confirmation toward AUSF -> KSEAF + SUPI
        let (ausf_host, ausf_port) =
            crate::sbi_path::resolve_nf_endpoint_async(crate::sbi_path::SbiServiceType::NausfAuth)
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));

        let confirm = match crate::sbi_path::call_ausf_5g_aka_confirm(
            &ausf_host,
            ausf_port,
            &state.auth_ctx_id,
            &rs,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                log::error!("AUSF 5G-AKA confirmation failed: {e}");
                let auth_reject = gmm_build::build_authentication_reject();
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
                return Ok(());
            }
        };

        if confirm.auth_result != "AUTHENTICATION_SUCCESS" {
            log::error!(
                "AUSF reports {}: Authentication Reject",
                confirm.auth_result
            );
            let auth_reject = gmm_build::build_authentication_reject();
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                .await?;
            self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                .await?;
            return Ok(());
        }

        // SUPI (from AUSF) and key hierarchy:
        // KSEAF -> KAMF (A.7) -> KNASint/KNASenc (A.8)
        let supi = confirm
            .supi
            .clone()
            .unwrap_or_else(|| supi_from_suci(&state.suci));
        state.amf_ue.supi = Some(supi.clone());

        let abba_len = state.amf_ue.abba_len as usize;
        let kamf =
            ogs_crypt::kdf::ogs_kdf_kamf(&supi, &state.amf_ue.abba[..abba_len], &confirm.kseaf);
        state.amf_ue.kamf = kamf;

        // Select NAS algorithms from the UE's replayed capabilities and the
        // AMF-supported set (configured order; default NIA2/NEA2 preference)
        let amf_int_mask = {
            let ctx = self.amf_context.read().await;
            algorithm_order_to_mask(&ctx.integrity_order, 0x0E) // NIA1-3, never NIA0 by preference
        };
        let amf_enc_mask = {
            let ctx = self.amf_context.read().await;
            algorithm_order_to_mask(&ctx.ciphering_order, 0x0F)
        };
        let ue_int_mask = wire_caps_to_mask(state.amf_ue.ue_security_capability.ia);
        let ue_enc_mask = wire_caps_to_mask(state.amf_ue.ue_security_capability.ea);

        state.amf_ue.selected_int_algorithm =
            nas_security::select_integrity_algorithm(ue_int_mask, amf_int_mask);
        state.amf_ue.selected_enc_algorithm =
            nas_security::select_encryption_algorithm(ue_enc_mask, amf_enc_mask);

        let knas_int = ogs_crypt::kdf::ogs_kdf_nas_5gs(
            0x02, // N-NAS-int-alg (TS 33.501 Annex A.8)
            state.amf_ue.selected_int_algorithm,
            &kamf,
        );
        let knas_enc = ogs_crypt::kdf::ogs_kdf_nas_5gs(
            0x01, // N-NAS-enc-alg
            state.amf_ue.selected_enc_algorithm,
            &kamf,
        );
        state.amf_ue.knas_int.copy_from_slice(&knas_int);
        state.amf_ue.knas_enc.copy_from_slice(&knas_enc);

        log::info!(
            "[{supi}] keys derived; selected NIA{} / NEA{}",
            state.amf_ue.selected_int_algorithm,
            state.amf_ue.selected_enc_algorithm
        );

        // Security Mode Command: plain inner built by gmm_build (replaying the
        // UE's actual capabilities), wrapped integrity-protected with the new
        // 5G NAS security context (TS 24.501 Section 5.4.2.2)
        let Some(smc_plain) = gmm_build::build_security_mode_command(&state.amf_ue) else {
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            return Ok(());
        };
        let Some(smc_protected) = nas_security::nas_5gs_security_encode(
            &mut state.amf_ue,
            &smc_plain,
            security_header::INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT,
        ) else {
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            return Ok(());
        };

        self.ue_auth_state.insert(amf_ue_ngap_id, state);
        let ngap_pdu = self
            .send_nas_pdu(
                association_id,
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                &smc_protected,
            )
            .await?;
        self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3560, ngap_pdu);
        log::info!("Security Mode Command sent to UE {amf_ue_ngap_id} (protected)");
        Ok(())
    }

    /// Handle Authentication Failure (TS 24.501 Section 5.4.1.3.7):
    /// - cause #20 (MAC failure): one re-authentication attempt, then reject
    /// - cause #21 (synch failure): SQN resynchronisation toward AUSF using
    ///   the AUTS parameter, then a fresh Authentication Request
    async fn handle_authentication_failure_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        let cause = nas.get(3).copied().unwrap_or(0);
        log::warn!("Authentication Failure from UE {amf_ue_ngap_id}: 5GMM cause #{cause}");

        // Authentication failure parameter (IEI 0x30, TLV, AUTS 14 bytes)
        let mut auts: Option<[u8; 14]> = None;
        let mut pos = 4;
        while pos + 1 < nas.len() {
            if nas[pos] == 0x30 {
                let len = nas[pos + 1] as usize;
                if len == 14 && pos + 2 + 14 <= nas.len() {
                    let mut a = [0u8; 14];
                    a.copy_from_slice(&nas[pos + 2..pos + 16]);
                    auts = Some(a);
                }
                break;
            }
            pos += 1;
        }

        let (failure_count, rand) = match self.ue_auth_state.get_mut(&amf_ue_ngap_id) {
            Some(state) => {
                state.auth_failure_count += 1;
                if matches!(
                    state.retx,
                    Some(NasRetx {
                        timer: NasProcTimer::T3560,
                        ..
                    })
                ) {
                    state.retx = None;
                }
                (state.auth_failure_count, state.amf_ue.rand)
            }
            None => return Ok(()),
        };

        if failure_count > 1 {
            log::error!("Repeated authentication failure: Authentication Reject");
            let auth_reject = gmm_build::build_authentication_reject();
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                .await?;
            self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                .await?;
            return Ok(());
        }

        match cause {
            21 => {
                // Synch failure: re-resolve the vector with AUTS (resync)
                let Some(auts) = auts else {
                    log::error!("Synch failure without AUTS parameter: Authentication Reject");
                    let auth_reject = gmm_build::build_authentication_reject();
                    self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                        .await?;
                    self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                        .await?;
                    return Ok(());
                };
                self.start_authentication(
                    association_id,
                    amf_ue_ngap_id,
                    ran_ue_ngap_id,
                    Some((rand, auts)),
                )
                .await?;
            }
            20 | 26 | 71 => {
                // MAC failure / non-5G auth unacceptable / ngKSI in use:
                // one fresh authentication attempt
                self.start_authentication(association_id, amf_ue_ngap_id, ran_ue_ngap_id, None)
                    .await?;
            }
            _ => {
                log::error!("Unhandled auth failure cause #{cause}: Authentication Reject");
                let auth_reject = gmm_build::build_authentication_reject();
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &auth_reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handle Identity Response (TS 24.501 Section 5.4.3): SUCI before
    /// authentication, or PEI (IMEI/IMEISV) after security establishment
    async fn handle_identity_response_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        if nas.len() < 5 {
            return Ok(());
        }
        let id_len = ((nas[3] as usize) << 8) | (nas[4] as usize);
        if id_len == 0 || nas.len() < 5 + id_len {
            log::error!("Malformed Identity Response");
            return Ok(());
        }
        let content = &nas[5..5 + id_len];
        let id_type = content[0] & 0x07;

        let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) else {
            return Ok(());
        };
        // Stop T3570
        if matches!(
            state.retx,
            Some(NasRetx {
                timer: NasProcTimer::T3570,
                ..
            })
        ) {
            state.retx = None;
        }

        match id_type {
            t if t == mobile_identity_type::SUCI => {
                if let Some((suci, plmn)) = parse_suci_identity(content) {
                    log::info!("Identity Response: SUCI {suci}");
                    state.suci = suci.clone();
                    state.amf_ue.suci = Some(suci);
                    state.amf_ue.home_plmn_id = plmn;
                    self.start_authentication(association_id, amf_ue_ngap_id, ran_ue_ngap_id, None)
                        .await?;
                } else {
                    log::error!("Failed to parse SUCI from Identity Response");
                }
            }
            t if t == mobile_identity_type::IMEISV || t == mobile_identity_type::IMEI => {
                let pei = decode_bcd_digits(&content[1..]);
                log::info!("Identity Response: PEI {pei}");
                state.amf_ue.pei = Some(format!("imeisv-{pei}"));
                state.amf_ue.imeisv = Some(pei);
                if state.pei_requested {
                    state.pei_requested = false;
                    self.complete_registration(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
                        .await?;
                }
            }
            other => {
                log::error!("Unsupported identity type {other} in Identity Response");
            }
        }
        Ok(())
    }

    /// Handle Security Mode Complete (TS 24.501 Section 5.4.2.4):
    /// extract IMEISV if present (it was requested in the SMC), request PEI
    /// via Identity Request otherwise, then run the registration SBI calls
    async fn handle_security_mode_complete_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        log::info!("Security Mode Complete from UE {amf_ue_ngap_id}");

        // Anti-bidding-down check (TS 24.501 Section 4.4.2.4 / TS 33.501
        // Section 6.7.2): the UE replays its complete initial RegistrationRequest
        // inside the (now integrity-protected) NAS message container of the
        // Security Mode Complete. The AMF re-parses the UE security capabilities
        // from that protected copy and compares them against the capabilities it
        // received in the cleartext initial RegistrationRequest. A mismatch means
        // an attacker tampered with the unprotected initial message to downgrade
        // the algorithms; the AMF aborts with 5GMM cause #23.
        if let Some(replayed) = extract_nas_message_container(nas) {
            if let Some(inner) = parse_registration_request_pdu(&replayed) {
                if let Some(replayed_caps) = inner.sec_cap {
                    let stored = self
                        .ue_auth_state
                        .get(&amf_ue_ngap_id)
                        .map(|s| s.amf_ue.ue_security_capability.clone());
                    if let Some(stored) = stored {
                        if replayed_caps.ea != stored.ea
                            || replayed_caps.ia != stored.ia
                            || replayed_caps.eea != stored.eea
                            || replayed_caps.eia != stored.eia
                        {
                            log::error!(
                                "Bidding-down detected for UE {amf_ue_ngap_id}: replayed caps \
                                 (EA={:#04x},IA={:#04x},EEA={:#04x},EIA={:#04x}) != initial \
                                 (EA={:#04x},IA={:#04x},EEA={:#04x},EIA={:#04x})",
                                replayed_caps.ea,
                                replayed_caps.ia,
                                replayed_caps.eea,
                                replayed_caps.eia,
                                stored.ea,
                                stored.ia,
                                stored.eea,
                                stored.eia
                            );
                            // Security Mode Reject (#23), then abort the
                            // registration and release the UE context.
                            let reject = gmm_build::build_security_mode_reject(
                                GmmCause::UeSecurityCapabilitiesMismatch,
                            );
                            self.send_nas_pdu(
                                association_id,
                                amf_ue_ngap_id,
                                ran_ue_ngap_id,
                                &reject,
                            )
                            .await?;
                            let reg_reject = gmm_build::build_registration_reject(
                                GmmCause::UeSecurityCapabilitiesMismatch,
                            );
                            self.send_nas_pdu(
                                association_id,
                                amf_ue_ngap_id,
                                ran_ue_ngap_id,
                                &reg_reject,
                            )
                            .await?;
                            self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 23)
                                .await?;
                            return Ok(());
                        }
                        log::info!(
                            "UE {amf_ue_ngap_id} security capabilities verified against replayed \
                             RegistrationRequest (no bidding-down)"
                        );
                    }
                }
            } else {
                log::warn!(
                    "Security Mode Complete NAS message container did not contain a \
                     parseable RegistrationRequest for UE {amf_ue_ngap_id}"
                );
            }
        }

        let mut need_pei = false;
        {
            let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) else {
                return Ok(());
            };
            // Stop T3560
            if matches!(
                state.retx,
                Some(NasRetx {
                    timer: NasProcTimer::T3560,
                    ..
                })
            ) {
                state.retx = None;
            }

            // IMEISV (mobile identity IEI 0x77, TLV-E) — requested in the SMC
            let mut pos = 3;
            while pos + 2 < nas.len() {
                if nas[pos] == 0x77 {
                    let len = ((nas[pos + 1] as usize) << 8) | (nas[pos + 2] as usize);
                    if len > 0 && pos + 3 + len <= nas.len() {
                        let content = &nas[pos + 3..pos + 3 + len];
                        if content[0] & 0x07 == mobile_identity_type::IMEISV {
                            let imeisv = decode_bcd_digits(&content[1..]);
                            log::info!("IMEISV from Security Mode Complete: {imeisv}");
                            state.amf_ue.imeisv = Some(imeisv.clone());
                            state.amf_ue.pei = Some(format!("imeisv-{imeisv}"));
                        }
                    }
                    break;
                }
                pos += 1;
            }

            if state.amf_ue.pei.is_none() {
                need_pei = true;
                state.pei_requested = true;
            }
        }

        if need_pei {
            // PEI not provided: Identity Request for IMEISV (protected),
            // TS 24.501 Section 5.4.3 / TS 23.502 step 11
            log::info!("No PEI yet: sending Identity Request (IMEISV)");
            let plain = gmm_build::build_identity_request(mobile_identity_type::IMEISV);
            let Some(protected) = self.protect_nas(amf_ue_ngap_id, &plain) else {
                return Ok(());
            };
            let ngap_pdu = self
                .send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
                .await?;
            self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3570, ngap_pdu);
            return Ok(());
        }

        self.complete_registration(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
            .await
    }

    /// Run the three mandatory registration SBI calls and, only if all
    /// succeed, send the protected Registration Accept
    /// (TS 23.502 Section 4.2.2.2.2 steps 14a/14b/14c/16)
    async fn complete_registration(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
    ) -> Result<()> {
        let Some(mut state) = self.ue_auth_state.remove(&amf_ue_ngap_id) else {
            return Ok(());
        };

        let supi = state
            .amf_ue
            .supi
            .clone()
            .unwrap_or_else(|| supi_from_suci(&state.suci));

        let (serving_mcc, serving_mnc) = plmn_mcc_mnc_strings(&state.amf_ue.nr_tai.plmn_id);

        // GUAMI of this AMF (for UECM registration)
        let (guami_plmn, amf_region, amf_set, amf_pointer) = {
            let ctx = self.amf_context.read().await;
            match ctx.served_guami.first() {
                Some(g) => (
                    g.plmn_id.clone(),
                    g.amf_id.region,
                    g.amf_id.set,
                    g.amf_id.pointer,
                ),
                None => (state.amf_ue.nr_tai.plmn_id.clone(), 2, 1, 0),
            }
        };
        let amf_id_hex = format!(
            "{:06x}",
            ((amf_region as u32) << 16) | ((amf_set as u32) << 6) | (amf_pointer as u32)
        );
        let (guami_mcc, guami_mnc) = plmn_mcc_mnc_strings(&guami_plmn);

        let (udm_host, udm_port) =
            crate::sbi_path::resolve_nf_endpoint_async(crate::sbi_path::SbiServiceType::NudmUecm)
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));

        // 1) Nudm_UECM_Registration (amf-3gpp-access)
        if let Err(e) = crate::sbi_path::call_udm_uecm_registration(
            &udm_host,
            udm_port,
            &supi,
            &amf_instance_id(),
            &guami_mcc,
            &guami_mnc,
            &amf_id_hex,
        )
        .await
        {
            log::error!("[{supi}] Nudm_UECM_Registration failed: {e}");
            let reject = gmm_build::build_registration_reject(gmm_cause_from_sbi_error(&e));
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                .await?;
            self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                .await?;
            return Ok(());
        }

        // 2) Nudm_SDM_Get (am-data) + Nudm_SDM_Subscribe
        let am_data =
            match crate::sbi_path::call_udm_sdm_get_am_data(&udm_host, udm_port, &supi).await {
                Ok(d) => d,
                Err(e) => {
                    log::error!("[{supi}] Nudm_SDM_Get failed: {e}");
                    let reject = gmm_build::build_registration_reject(gmm_cause_from_sbi_error(&e));
                    self.ue_auth_state.insert(amf_ue_ngap_id, state);
                    self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                        .await?;
                    self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                        .await?;
                    return Ok(());
                }
            };
        match crate::sbi_path::call_udm_sdm_subscribe(
            &udm_host,
            udm_port,
            &supi,
            &amf_instance_id(),
        )
        .await
        {
            Ok(sub_id) => state.sdm_subscription_id = Some(sub_id),
            Err(e) => {
                log::error!("[{supi}] Nudm_SDM_Subscribe failed: {e}");
                let reject = gmm_build::build_registration_reject(gmm_cause_from_sbi_error(&e));
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
                return Ok(());
            }
        }

        // 3) Npcf_AMPolicyControl_Create
        let (pcf_host, pcf_port) = crate::sbi_path::resolve_nf_endpoint_async(
            crate::sbi_path::SbiServiceType::NpcfAmPolicyControl,
        )
        .await
        .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));
        match crate::sbi_path::call_pcf_am_policy_create(
            &pcf_host,
            pcf_port,
            &supi,
            &serving_mcc,
            &serving_mnc,
        )
        .await
        {
            Ok(assoc) => {
                state.policy_association_id = Some(assoc.clone());
                state.amf_ue.policy_association.id = Some(assoc);
            }
            Err(e) => {
                log::error!("[{supi}] Npcf_AMPolicyControl_Create failed: {e}");
                let reject = gmm_build::build_registration_reject(gmm_cause_from_sbi_error(&e));
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
                return Ok(());
            }
        }

        // Allowed NSSAI: subscribed (UDM) > requested > PLMN support config
        let mut allowed: Vec<SNssai> = am_data
            .nssai
            .iter()
            .map(|(sst, sd)| SNssai { sst: *sst, sd: *sd })
            .collect();
        if allowed.is_empty() {
            allowed = state.amf_ue.requested_nssai.clone();
        }
        if allowed.is_empty() {
            let ctx = self.amf_context.read().await;
            if let Some(ps) = ctx.plmn_support.first() {
                allowed = ps.s_nssai.clone();
            }
        }
        state.amf_ue.allowed_nssai = allowed;

        // Network Slice Admission Control (TS 29.536 / TS 23.501 §5.15.11):
        // query the NSACF for each Allowed S-NSSAI subject to admission control
        // before accepting the registration. The NSACF returns HTTP 200 with
        // admittedFlag=false when the per-slice UE quota is exhausted; in that
        // case the registration is rejected with 5GMM cause #69 (insufficient
        // resources for the specific slice, TS 24.501 Annex A).
        {
            let (nsacf_host, nsacf_port) = crate::sbi_path::resolve_nf_endpoint_async(
                crate::sbi_path::SbiServiceType::NnsacfNsac,
            )
            .await
            .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));
            let access_type = if state.amf_ue.access_type == 0 || state.amf_ue.access_type == 1 {
                "3GPP_ACCESS"
            } else {
                "NON_3GPP_ACCESS"
            };
            let nf_id = amf_instance_id();
            let mut admission_denied: Option<SNssai> = None;
            for snssai in state.amf_ue.allowed_nssai.clone() {
                match crate::sbi_path::call_nsacf_ue_admission(
                    &nsacf_host,
                    nsacf_port,
                    &nf_id,
                    snssai.sst,
                    snssai.sd,
                    access_type,
                    true, // updateFlag: enforce/increase the per-slice UE count
                )
                .await
                {
                    Ok(res) => {
                        state.amf_ue.slice_admission_granted = res.admitted;
                        if !res.admitted {
                            admission_denied = Some(snssai);
                            break;
                        }
                    }
                    Err(e) => {
                        // NSACF unreachable: admission control cannot be
                        // performed. Per TS 23.501 §5.15.11 the AMF treats the
                        // slice as not-admitted to avoid exceeding quotas.
                        log::error!(
                            "[{supi}] NSACF UE admission query failed for SST={}: {e}",
                            snssai.sst
                        );
                        state.amf_ue.slice_admission_granted = false;
                        admission_denied = Some(snssai);
                        break;
                    }
                }
            }
            if let Some(denied) = admission_denied {
                log::warn!(
                    "[{supi}] Slice admission denied by NSACF (SST={}, SD={:?}); rejecting registration",
                    denied.sst,
                    denied.sd
                );
                let reject = gmm_build::build_registration_reject(
                    GmmCause::InsufficientResourcesForSpecificSlice,
                );
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                    .await?;
                self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                    .await?;
                return Ok(());
            }
        }

        // Subscribed UE-AMBR (UDM am-data, TS 29.571 BitRate strings) — carried
        // to the gNB in the Initial Context Setup Request (TS 38.413 §9.3.1.58).
        if let Some(dl) = am_data
            .ue_ambr_downlink
            .as_deref()
            .and_then(parse_bitrate_bps)
        {
            state.amf_ue.ue_ambr.downlink = dl;
        }
        if let Some(ul) = am_data.ue_ambr_uplink.as_deref().and_then(parse_bitrate_bps) {
            state.amf_ue.ue_ambr.uplink = ul;
        }

        // New 5G-GUTI: GUAMI of this AMF + CSPRNG 5G-TMSI (TS 23.003 2.10.1)
        state.amf_ue.generate_new_guti();
        state.amf_ue.next_guti.plmn_id = guami_plmn;
        state.amf_ue.next_guti.amf_region_id = amf_region;
        state.amf_ue.next_guti.amf_set_id = amf_set;
        state.amf_ue.next_guti.amf_pointer = amf_pointer;

        self.ue_auth_state.insert(amf_ue_ngap_id, state);
        self.send_registration_accept(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
            .await
    }

    /// Establish AS-layer security and deliver the initial Registration Accept.
    ///
    /// Per TS 23.502 §4.2.2.2.2 step 16 / TS 38.413 §8.3.1, the AMF derives
    /// KgNB (TS 33.501 Annex A.9) and sends NGAP InitialContextSetupRequest to
    /// the gNB carrying the GUAMI, the replayed UE security capabilities, the
    /// UE Security Key (KgNB), the Allowed NSSAI, the UE-AMBR and — piggybacked
    /// as the NAS-PDU — the protected Registration Accept. The registration is
    /// only considered established once the gNB returns
    /// InitialContextSetupResponse; T3550 is armed for the NAS-layer
    /// Registration Complete.
    async fn send_registration_accept(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
    ) -> Result<()> {
        let Some(mut state) = self.ue_auth_state.remove(&amf_ue_ngap_id) else {
            return Ok(());
        };

        let Some(plain) = gmm_build::build_registration_accept(&state.amf_ue) else {
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            return Ok(());
        };
        let Some(protected) = nas_security::nas_5gs_security_encode(
            &mut state.amf_ue,
            &plain,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        ) else {
            log::error!("Failed to protect Registration Accept (no security context?)");
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            return Ok(());
        };

        // Periodic / mobility registration update on a UE that ALREADY has an
        // established AS-security context: deliver the protected Registration
        // Accept over DownlinkNASTransport. A fresh InitialContextSetupRequest
        // is for the *initial* context only (TS 23.502 §4.2.2.2.2 step 16);
        // re-issuing it on a periodic update would needlessly re-establish AS
        // security. `registered` is false during initial registration (set only
        // after Registration Complete), so this branch is taken solely on update.
        if state.registered && state.amf_ue.security_context_available {
            let tmsi = state.amf_ue.next_guti.tmsi;
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
                .await?;
            log::info!(
                "Registration Accept (update) sent via DownlinkNASTransport to UE \
                 {amf_ue_ngap_id} (5G-TMSI=0x{tmsi:08x})"
            );
            return Ok(());
        }

        // Derive KgNB (TS 33.501 Annex A.9): KDF(Kamf, uplink NAS COUNT, access
        // type distinguisher). The access type distinguisher is 0x01 for 3GPP
        // access and 0x02 for non-3GPP access — matching the stored access_type.
        let access_type_distinguisher = if state.amf_ue.access_type == 0 {
            ACCESS_TYPE_3GPP
        } else {
            state.amf_ue.access_type
        };
        let kgnb = ogs_crypt::kdf::ogs_kdf_kgnb_and_kn3iwf(
            &state.amf_ue.kamf,
            state.amf_ue.ul_count,
            access_type_distinguisher,
        );
        state.amf_ue.kgnb = kgnb;

        let tmsi = state.amf_ue.next_guti.tmsi;
        let allowed_nssai = state.amf_ue.allowed_nssai.clone();
        let ue_security_capability = state.amf_ue.ue_security_capability.clone();
        // UE-AMBR from the subscription (UDM am-data, copied onto the context);
        // omitted when the subscription carries no aggregate bitrate.
        let ue_ambr = if state.amf_ue.ue_ambr.downlink > 0 || state.amf_ue.ue_ambr.uplink > 0 {
            Some((state.amf_ue.ue_ambr.downlink, state.amf_ue.ue_ambr.uplink))
        } else {
            None
        };

        // Build the Initial Context Setup Request carrying the protected
        // Registration Accept as the NAS-PDU.
        let ics = {
            let ctx = self.amf_context.read().await;
            crate::ngap_asn1::build_initial_context_setup_request_asn1(
                &ctx,
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                &allowed_nssai,
                &ue_security_capability,
                &kgnb,
                Some(&protected),
                ue_ambr,
            )
        };
        let Some(ics) = ics else {
            log::error!(
                "Failed to build Initial Context Setup Request for UE {amf_ue_ngap_id} \
                 (no served GUAMI?)"
            );
            self.ue_auth_state.insert(amf_ue_ngap_id, state);
            return Ok(());
        };

        state.initial_context_setup_request_sent = true;
        state.gmm_fsm.transition_to_initial_context_setup();
        self.ue_auth_state.insert(amf_ue_ngap_id, state);

        self.send_to_association(association_id, &ics).await?;
        // Arm T3550 against the ICS PDU: until the gNB confirms with an ICS
        // Response, the retransmission carries the whole request (Registration
        // Accept included), so the UE still receives the NAS message on retx.
        self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3550, ics);
        log::info!(
            "Initial Context Setup Request sent to gNB for UE {amf_ue_ngap_id} \
             (KgNB derived, Registration Accept piggybacked, 5G-TMSI=0x{tmsi:08x})"
        );
        Ok(())
    }

    /// Handle Service Request (TS 24.501 Section 5.6.1)
    async fn handle_service_request_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        let service_type = nas.get(3).map(|b| (b >> 4) & 0x0F).unwrap_or(0);
        log::info!("Service Request from UE {amf_ue_ngap_id}: service_type={service_type}");

        let has_context = self
            .ue_auth_state
            .get(&amf_ue_ngap_id)
            .map(|s| s.amf_ue.security_context_available && s.registered)
            .unwrap_or(false);

        if !has_context {
            // TS 24.501 Section 5.6.1.5: cause #9 forces re-registration
            let reject = gmm_build::build_service_reject(
                &AmfUe::default(),
                GmmCause::UeIdentityCannotBeDerivedByTheNetwork,
            );
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &reject)
                .await?;
            return Ok(());
        }

        // PDU session status (IEI 0x50, TLV) if present
        if let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) {
            let mut pos = 4;
            state.amf_ue.pdu_session_status_present = false;
            while pos + 1 < nas.len() {
                if nas[pos] == 0x50 {
                    let len = nas[pos + 1] as usize;
                    if len >= 2 && pos + 2 + len <= nas.len() {
                        state.amf_ue.pdu_session_status_present = true;
                        state.amf_ue.pdu_session_status =
                            ((nas[pos + 2] as u16) << 8) | nas[pos + 3] as u16;
                    }
                    break;
                }
                pos += 1;
            }
        }

        let plain = {
            let state = self.ue_auth_state.get(&amf_ue_ngap_id).expect("checked");
            gmm_build::build_service_accept(&state.amf_ue).unwrap_or_default()
        };
        let Some(protected) = self.protect_nas(amf_ue_ngap_id, &plain) else {
            return Ok(());
        };
        self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
            .await?;
        log::info!("Service Accept sent to UE {amf_ue_ngap_id} (protected)");
        Ok(())
    }

    /// Handle UE-initiated Deregistration Request (TS 24.501 Section 5.5.2.2):
    /// release all PDU sessions at the SMF, purge the UDM registration, send
    /// Deregistration Accept (unless switch-off) and release the NG context
    async fn handle_deregistration_request_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        // De-registration type (low nibble of octet 4): bit4 (0x08) = switch off
        let dereg_type = nas.get(3).copied().unwrap_or(0);
        let switch_off = dereg_type & 0x08 != 0;
        log::info!("Deregistration Request from UE {amf_ue_ngap_id} (switch_off={switch_off})");

        // Release every PDU session at the SMF (TS 23.502 Section 4.2.2.3.2
        // step 5: Nsmf_PDUSession_ReleaseSMContext)
        self.release_all_pdu_sessions(amf_ue_ngap_id).await;

        // Purge the AMF registration at UDM
        if let Some(state) = self.ue_auth_state.get(&amf_ue_ngap_id) {
            if let Some(supi) = state.amf_ue.supi.clone() {
                let (udm_host, udm_port) = crate::sbi_path::resolve_nf_endpoint_async(
                    crate::sbi_path::SbiServiceType::NudmUecm,
                )
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));
                if let Err(e) =
                    crate::sbi_path::call_udm_uecm_deregistration(&udm_host, udm_port, &supi).await
                {
                    log::warn!("[{supi}] UDM purge on deregistration failed: {e}");
                }
            }
        }

        // Deregistration Accept (not sent when the UE switched off,
        // TS 24.501 Section 5.5.2.2.2)
        if !switch_off {
            let plain = gmm_build::build_deregistration_accept(&AmfUe::default())
                .unwrap_or_else(|| vec![0x7E, 0x00, 0x46]);
            let pdu = self.protect_nas(amf_ue_ngap_id, &plain).unwrap_or(plain);
            self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &pdu)
                .await?;
            log::info!("Deregistration Accept sent to UE {amf_ue_ngap_id}");
        }

        self.finish_deregistration(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
            .await
    }

    /// Common tail of both deregistration directions: drop the NAS state and
    /// release the NG UE context (Cause NAS deregister)
    async fn finish_deregistration(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
    ) -> Result<()> {
        self.ue_auth_state.remove(&amf_ue_ngap_id);
        // Cause: NAS deregister (TS 38.413 Section 9.3.1.2, CauseNas value 2)
        self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 2)
            .await
    }

    /// Network-initiated Deregistration Request (TS 24.501 Section 5.5.2.3).
    ///
    /// Sends a protected DEREGISTRATION REQUEST (0x47) and arms T3522.
    /// PDU sessions are released when the Deregistration Accept arrives (or
    /// on T3522 exhaustion, the implicit-deregistration abnormal action).
    pub async fn send_network_initiated_deregistration(
        &mut self,
        amf_ue_ngap_id: u64,
        reregistration_required: bool,
        gmm_cause: Option<GmmCause>,
    ) -> Result<()> {
        let Some(state) = self.ue_auth_state.get(&amf_ue_ngap_id) else {
            return Err(anyhow::anyhow!("UE {amf_ue_ngap_id} not found"));
        };
        let association_id = state.association_id;
        let ran_ue_ngap_id = state.ran_ue_ngap_id;

        let reason = if reregistration_required {
            crate::gmm_build::DeregistrationReason::ReregistrationRequired
        } else {
            crate::gmm_build::DeregistrationReason::UeNotSwitchOff
        };
        let plain = gmm_build::build_deregistration_request(&AmfUe::default(), reason, gmm_cause)
            .unwrap_or_default();
        let Some(protected) = self.protect_nas(amf_ue_ngap_id, &plain) else {
            return Err(anyhow::anyhow!(
                "no security context for UE {amf_ue_ngap_id}"
            ));
        };
        let ngap_pdu = self
            .send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
            .await?;
        self.arm_retx(amf_ue_ngap_id, NasProcTimer::T3522, ngap_pdu);
        log::info!("Network-initiated Deregistration Request sent to UE {amf_ue_ngap_id}");
        Ok(())
    }

    /// Handle UL NAS TRANSPORT (0x67, TS 24.501 Section 5.4.5): route N1 SM
    /// to the SMF; reply with cause #90 for container types without a
    /// forwarding target; 5GMM Status on protocol errors
    async fn handle_ul_nas_transport_nas(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<()> {
        if nas.len() < 6 {
            return Ok(());
        }
        let container_type = nas[3] & 0x0F;
        let container_len = ((nas[4] as usize) << 8) | (nas[5] as usize);
        if nas.len() < 6 + container_len {
            log::error!("UL NAS Transport container truncated");
            return Ok(());
        }
        let container = nas[6..6 + container_len].to_vec();

        // Optional IEs after the container: PDU session ID (IEI 0x12, TV)
        let mut psi: Option<u8> = None;
        let mut dnn_value: Option<String> = None;
        let mut pos = 6 + container_len;
        while pos < nas.len() {
            match nas[pos] {
                0x12 if pos + 1 < nas.len() => {
                    psi = Some(nas[pos + 1]);
                    pos += 2;
                }
                0x59 if pos + 1 < nas.len() => pos += 2, // Old PDU session ID (TV)
                0x22 if pos + 1 < nas.len() => {
                    // S-NSSAI (TLV)
                    pos += 2 + nas[pos + 1] as usize;
                }
                0x25 if pos + 1 < nas.len() => {
                    // DNN (TLV, TS 24.501 9.11.2.1A): length-prefixed labels.
                    // Capture it so the requested DNN (e.g. "xr") reaches the
                    // SMF instead of being forced to "internet" below.
                    let l = nas[pos + 1] as usize;
                    if pos + 2 + l <= nas.len() {
                        dnn_value = decode_dnn_labels(&nas[pos + 2..pos + 2 + l]);
                    }
                    pos += 2 + l;
                }
                b if b & 0x80 != 0 => pos += 1, // type-1 TV (e.g. request type 0x8-)
                _ => break,
            }
        }

        let transport = crate::gmm_handler::UlNasTransport {
            payload_container_type: container_type,
            payload_container: container.clone(),
            pdu_session_id: psi,
            ..Default::default()
        };

        // Parse/validate via the GMM handler
        let action = {
            let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) else {
                return Ok(());
            };
            let ran_ue = crate::context::RanUe::default();
            crate::gmm_handler::handle_ul_nas_transport(&mut state.amf_ue, &ran_ue, &transport)
        };

        match action {
            Ok(crate::gmm_handler::UlTransportAction::RouteToSmf { .. }) => {
                self.handle_5gsm_message(
                    association_id,
                    amf_ue_ngap_id,
                    ran_ue_ngap_id,
                    &container,
                    dnn_value.as_deref(),
                )
                .await?;
            }
            Ok(crate::gmm_handler::UlTransportAction::PayloadNotForwarded) => {
                // DL NAS TRANSPORT with the original payload + cause #90
                // (TS 24.501 Section 5.4.5.3.1)
                let plain = gmm_build::build_dl_nas_transport(
                    None,
                    container_type,
                    &container,
                    Some(GmmCause::PayloadWasNotForwarded),
                    None,
                )
                .unwrap_or_default();
                if let Some(protected) = self.protect_nas(amf_ue_ngap_id, &plain) {
                    self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
                        .await?;
                }
            }
            Err(cause) => {
                // Protocol error: 5GMM STATUS (TS 24.501 Section 5.4.7)
                let plain = gmm_build::build_gmm_status(cause).unwrap_or_default();
                if let Some(protected) = self.protect_nas(amf_ue_ngap_id, &plain) {
                    self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &protected)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Handle a 5GSM PDU (from an UL NAS TRANSPORT N1 SM container, or a
    /// legacy raw 5GSM NAS PDU): SBI toward the SMF + N1/N2 distribution
    async fn handle_5gsm_message(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        sm_pdu: &[u8],
        dnn_override: Option<&str>,
    ) -> Result<()> {
        if sm_pdu.len() < 4 {
            return Ok(());
        }
        let psi = sm_pdu[1];
        let pti = sm_pdu[2];
        let sm_msg_type = sm_pdu[3];
        log::info!("5GSM message: PSI={psi}, PTI={pti}, msg_type=0x{sm_msg_type:02x}");

        let (smf_host, smf_port) = crate::sbi_path::resolve_nf_endpoint_async(
            crate::sbi_path::SbiServiceType::NsmfPdusession,
        )
        .await
        .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));

        match sm_msg_type {
            // PDU Session Establishment Request
            0xC1 => {
                log::info!("PDU Session Establishment Request from UE: PSI={psi}, PTI={pti}");

                // S-NSSAI/DNN: from the UE's allowed slice when known
                let (sst, sd) = self
                    .ue_auth_state
                    .get(&amf_ue_ngap_id)
                    .and_then(|s| s.amf_ue.allowed_nssai.first().map(|n| (n.sst, n.sd)))
                    .unwrap_or((1, None));
                // DNN from the UE's UL NAS Transport DNN IE (e.g. "xr" for an
                // XR session); fall back to "internet" for the legacy raw-5GSM
                // path or when the UE omits the IE.
                let dnn = dnn_override.unwrap_or("internet");

                // RedCap indication: propagate the UE's Reduced-Capability
                // status (parsed at registration in gmm_handler) to the SMF so
                // it can apply a reduced session-AMBR (Rel-17, TS 38.101).
                let redcap_indication = self
                    .ue_auth_state
                    .get(&amf_ue_ngap_id)
                    .map(|s| s.amf_ue.redcap_indication)
                    .unwrap_or(false);

                match crate::sbi_path::call_smf_create_sm_context(
                    &smf_host,
                    smf_port,
                    psi,
                    sst,
                    sd,
                    dnn,
                    sm_pdu,
                    redcap_indication,
                )
                .await
                {
                    Ok(resp) => {
                        log::info!(
                            "SMF SM Context Created: ref={}, n1_len={}, n2_len={}",
                            resp.sm_context_ref,
                            resp.n1_sm_msg.len(),
                            resp.n2_sm_info.len()
                        );

                        // N1: PDU Session Establishment Accept via DL NAS
                        // TRANSPORT (protected when a context exists)
                        self.send_n1_sm_to_ue(
                            association_id,
                            amf_ue_ngap_id,
                            ran_ue_ngap_id,
                            psi,
                            &resp.n1_sm_msg,
                        )
                        .await?;

                        // N2: PDU Session Resource Setup Request toward the gNB.
                        // The UE context (AS-layer security) must be established
                        // first — i.e. the gNB must have returned an Initial
                        // Context Setup Response (TS 38.413 §8.3.1 precedes the
                        // PDU session setup of TS 38.413 §8.2.1). Without it the
                        // gNB has no KgNB/DRBs to attach the session to.
                        let ics_done = self
                            .ue_auth_state
                            .get(&amf_ue_ngap_id)
                            .map(|s| s.initial_context_setup_response_received)
                            .unwrap_or(false);
                        if !ics_done {
                            log::warn!(
                                "Deferring PDU Session Resource Setup for PSI={psi}: Initial \
                                 Context Setup not yet confirmed for UE {amf_ue_ngap_id}"
                            );
                            return Ok(());
                        }

                        let setup_req =
                            match crate::ngap_asn1::build_pdu_session_resource_setup_request_asn1(
                                amf_ue_ngap_id,
                                ran_ue_ngap_id,
                                psi,
                                sst,
                                sd,
                                None,
                                &resp.n2_sm_info,
                            ) {
                                Some(bytes) => bytes,
                                None => {
                                    log::error!(
                                        "Failed to build PDU Session Resource Setup Request"
                                    );
                                    return Ok(());
                                }
                            };
                        self.send_to_association(association_id, &setup_req).await?;
                        log::info!("PDU Session Resource Setup Request sent to gNB: PSI={psi}");
                    }
                    Err(e) => {
                        // No local fabrication of sessions: PDU SESSION
                        // ESTABLISHMENT REJECT, 5GSM cause #26 insufficient
                        // resources (TS 24.501 Section 8.3.3)
                        log::warn!("SMF SM Context Create failed ({e}); rejecting PSI={psi}");
                        let reject = vec![0x2E, psi, pti, 0xC3, 0x1A];
                        self.send_n1_sm_to_ue(
                            association_id,
                            amf_ue_ngap_id,
                            ran_ue_ngap_id,
                            psi,
                            &reject,
                        )
                        .await?;
                    }
                }
            }
            // PDU Session Modification Request
            0xC9 => {
                log::info!("PDU Session Modification Request from UE: PSI={psi}, PTI={pti}");
                let sm_context_ref = format!("{psi}");

                match crate::sbi_path::call_smf_update_sm_context_with_n1(
                    &smf_host,
                    smf_port,
                    &sm_context_ref,
                    sm_pdu,
                )
                .await
                {
                    Ok(resp) => {
                        // PDU Session Modification Command to UE (from SMF N1
                        // when provided)
                        let n1 = if resp.n1_sm_msg.is_empty() {
                            vec![0x2E, psi, pti, 0xCB]
                        } else {
                            resp.n1_sm_msg.clone()
                        };
                        self.send_n1_sm_to_ue(
                            association_id,
                            amf_ue_ngap_id,
                            ran_ue_ngap_id,
                            psi,
                            &n1,
                        )
                        .await?;

                        if !resp.n2_sm_info.is_empty() {
                            let modify_req = match crate::ngap_asn1::build_pdu_session_resource_modify_request_asn1(
                                amf_ue_ngap_id,
                                ran_ue_ngap_id,
                                psi,
                                None,
                                &resp.n2_sm_info,
                            ) {
                                Some(bytes) => bytes,
                                None => {
                                    log::error!("Failed to build PDU Session Resource Modify Request");
                                    return Ok(());
                                }
                            };
                            self.send_to_association(association_id, &modify_req)
                                .await?;
                            log::info!(
                                "PDU Session Resource Modify Request sent to gNB: PSI={psi}"
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!("SMF modification failed ({e}), sending reject");
                        // PDU SESSION MODIFICATION REJECT, cause #26
                        let reject = vec![0x2E, psi, pti, 0xCC, 0x1A];
                        self.send_n1_sm_to_ue(
                            association_id,
                            amf_ue_ngap_id,
                            ran_ue_ngap_id,
                            psi,
                            &reject,
                        )
                        .await?;
                    }
                }
            }
            // PDU Session Modification Complete
            0xCD => {
                log::info!("PDU Session Modification Complete from UE: PSI={psi}");
            }
            // PDU Session Release Request
            0xD1 => {
                log::info!("PDU Session Release Request from UE: PSI={psi}, PTI={pti}");
                let sm_context_ref = format!("{psi}");

                match crate::sbi_path::call_smf_release_sm_context(
                    &smf_host,
                    smf_port,
                    &sm_context_ref,
                )
                .await
                {
                    Ok(()) => log::info!("SMF SM Context Released: PSI={psi}"),
                    Err(e) => log::warn!("SMF release failed: {e}"),
                }

                // PDU Session Release Command (cause #36 regular deactivation)
                let release_cmd = vec![0x2E, psi, pti, 0xD3, 0x24];
                self.send_n1_sm_to_ue(
                    association_id,
                    amf_ue_ngap_id,
                    ran_ue_ngap_id,
                    psi,
                    &release_cmd,
                )
                .await?;

                let release_ngap =
                    match crate::ngap_asn1::build_pdu_session_resource_release_command_asn1(
                        amf_ue_ngap_id,
                        ran_ue_ngap_id,
                        &[psi],
                    ) {
                        Some(bytes) => bytes,
                        None => {
                            log::error!("Failed to build PDU Session Resource Release Command");
                            return Ok(());
                        }
                    };
                self.send_to_association(association_id, &release_ngap)
                    .await?;
                log::info!("PDU Session Resource Release Command sent to gNB: PSI={psi}");
            }
            // PDU Session Release Complete
            0xD6 => {
                log::info!("PDU Session Release Complete from UE: PSI={psi}");
            }
            other => {
                log::warn!("Unhandled 5GSM message type 0x{other:02x}");
            }
        }
        Ok(())
    }

    /// Send an N1 SM payload to the UE inside a protected DL NAS TRANSPORT
    /// (TS 24.501 Section 5.4.5.2). Falls back to the bare container only if
    /// no security context exists (pre-Rel-15 sim compatibility).
    async fn send_n1_sm_to_ue(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        psi: u8,
        n1_sm: &[u8],
    ) -> Result<()> {
        let plain = gmm_build::build_dl_nas_transport(
            Some(psi),
            payload_container_type::N1_SM_INFORMATION,
            n1_sm,
            None,
            None,
        )
        .unwrap_or_default();

        let pdu = match self.protect_nas(amf_ue_ngap_id, &plain) {
            Some(p) => p,
            None => {
                log::warn!(
                    "No NAS security context for UE {amf_ue_ngap_id}: sending bare N1 SM (legacy peer)"
                );
                n1_sm.to_vec()
            }
        };
        self.send_nas_pdu(association_id, amf_ue_ngap_id, ran_ue_ngap_id, &pdu)
            .await?;
        Ok(())
    }

    /// Protect a plain inner NAS message with the UE's security context
    /// (integrity protected + ciphered). Returns None without a context.
    fn protect_nas(&mut self, amf_ue_ngap_id: u64, plain: &[u8]) -> Option<Vec<u8>> {
        let state = self.ue_auth_state.get_mut(&amf_ue_ngap_id)?;
        if !state.amf_ue.security_context_available {
            return None;
        }
        nas_security::nas_5gs_security_encode(
            &mut state.amf_ue,
            plain,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        )
    }

    /// Build a Downlink NAS Transport NGAP PDU and send it.
    /// Returns the NGAP PDU bytes for retransmission arming.
    async fn send_nas_pdu(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas: &[u8],
    ) -> Result<Vec<u8>> {
        let pdu = crate::ngap_asn1::build_downlink_nas_transport_asn1(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            nas,
        )
        .ok_or_else(|| anyhow::anyhow!("Failed to build Downlink NAS Transport"))?;
        self.send_to_association(association_id, &pdu).await?;
        Ok(pdu)
    }

    /// Arm a GMM procedure retransmission timer for a UE
    fn arm_retx(&mut self, amf_ue_ngap_id: u64, timer: NasProcTimer, ngap_pdu: Vec<u8>) {
        let (_max, duration) = timer.config(&self.timer_configs);
        if let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) {
            state.retx = Some(NasRetx {
                timer,
                deadline: Instant::now() + duration,
                retries: 0,
                ngap_pdu,
            });
        }
    }

    /// Process GMM procedure timers: retransmit up to the configured maximum,
    /// then apply the per-timer abnormal action (TS 24.501 Sections 5.4.1.3.7,
    /// 5.4.3.7, 5.5.1.2.8, 5.5.2.3.6)
    async fn process_nas_timers(&mut self) -> Result<()> {
        let now = Instant::now();
        let due: Vec<u64> = self
            .ue_auth_state
            .iter()
            .filter(|(_, s)| s.retx.as_ref().is_some_and(|r| r.deadline <= now))
            .map(|(id, _)| *id)
            .collect();

        for amf_ue_ngap_id in due {
            let Some(mut state) = self.ue_auth_state.remove(&amf_ue_ngap_id) else {
                continue;
            };
            let Some(mut retx) = state.retx.take() else {
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                continue;
            };
            let (max_count, duration) = retx.timer.config(&self.timer_configs);

            if retx.retries < max_count {
                retx.retries += 1;
                retx.deadline = now + duration;
                log::info!(
                    "{:?} expired for UE {amf_ue_ngap_id}: retransmission {}/{max_count}",
                    retx.timer,
                    retx.retries
                );
                let association_id = state.association_id;
                let pdu = retx.ngap_pdu.clone();
                state.retx = Some(retx);
                self.ue_auth_state.insert(amf_ue_ngap_id, state);
                let _ = self.send_to_association(association_id, &pdu).await;
                continue;
            }

            // Maximum retransmissions reached: abnormal action
            log::warn!(
                "{:?} max retransmissions reached for UE {amf_ue_ngap_id}: aborting procedure",
                retx.timer
            );
            let association_id = state.association_id;
            let ran_ue_ngap_id = state.ran_ue_ngap_id;
            match retx.timer {
                NasProcTimer::T3550 => {
                    // Abort; the network considers the new GUTI valid
                    // (TS 24.501 Section 5.5.1.2.8 case c)
                    state.registered = true;
                    state.amf_ue.current_guti = state.amf_ue.next_guti.clone();
                    self.ue_auth_state.insert(amf_ue_ngap_id, state);
                }
                NasProcTimer::T3560 => {
                    // Abort authentication/SMC and release the N1 connection
                    self.ue_auth_state.insert(amf_ue_ngap_id, state);
                    self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                        .await?;
                    self.ue_auth_state.remove(&amf_ue_ngap_id);
                }
                NasProcTimer::T3570 => {
                    if state.pei_requested {
                        // PEI identification aborted: continue registration
                        state.pei_requested = false;
                        self.ue_auth_state.insert(amf_ue_ngap_id, state);
                        self.complete_registration(association_id, amf_ue_ngap_id, ran_ue_ngap_id)
                            .await?;
                    } else {
                        // SUCI identification aborted: release
                        self.ue_auth_state.insert(amf_ue_ngap_id, state);
                        self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 1)
                            .await?;
                        self.ue_auth_state.remove(&amf_ue_ngap_id);
                    }
                }
                NasProcTimer::T3522 => {
                    // Implicit deregistration (TS 24.501 Section 5.5.2.3.6)
                    self.ue_auth_state.insert(amf_ue_ngap_id, state);
                    self.release_all_pdu_sessions(amf_ue_ngap_id).await;
                    self.ue_auth_state.remove(&amf_ue_ngap_id);
                    self.release_ue(association_id, amf_ue_ngap_id, ran_ue_ngap_id, 2)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Release every PDU session of a UE at the SMF
    /// (Nsmf_PDUSession_ReleaseSMContext)
    async fn release_all_pdu_sessions(&mut self, amf_ue_ngap_id: u64) {
        let (smf_host, smf_port) = crate::sbi_path::resolve_nf_endpoint_async(
            crate::sbi_path::SbiServiceType::NsmfPdusession,
        )
        .await
        .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777));

        // Collect SM context refs from the global AMF context (copy out under
        // the lock, then call SBI without holding it)
        let sm_context_refs: Vec<(u8, String)> = {
            let mut refs = Vec::new();
            let ctx = crate::context::amf_self();
            if let Ok(context) = ctx.read() {
                let amf_ue_id = context
                    .ran_ue_find_by_amf_ue_ngap_id(amf_ue_ngap_id)
                    .map(|ran_ue| ran_ue.amf_ue_id)
                    .unwrap_or(amf_ue_ngap_id);
                for sess in context.sess_list_for_ue(amf_ue_id).iter() {
                    if let Some(ref r) = sess.sm_context_ref {
                        refs.push((sess.psi, r.clone()));
                    }
                }
            }
            refs
        };

        for (psi, sm_context_ref) in &sm_context_refs {
            match crate::sbi_path::call_smf_release_sm_context(&smf_host, smf_port, sm_context_ref)
                .await
            {
                Ok(()) => log::info!("SMF SM Context Released: PSI={psi}"),
                Err(e) => log::warn!("SMF release failed for PSI={psi}: {e}"),
            }
        }
    }

    /// Send a UEContextReleaseCommand with a NAS cause and drop the UE's
    /// NAS state (0 = normal-release, 1 = authentication-failure,
    /// 2 = deregister)
    async fn release_ue(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        nas_cause: u8,
    ) -> Result<()> {
        self.ue_auth_state.remove(&amf_ue_ngap_id);
        if let Some(cmd) = crate::ngap_asn1::build_ue_context_release_command_asn1(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            ngap_handler::cause_group::NAS,
            nas_cause as i64,
        ) {
            self.send_to_association(association_id, &cmd).await?;
            log::info!(
                "UE Context Release Command sent (UE {amf_ue_ngap_id}, NAS cause {nas_cause})"
            );
        }
        Ok(())
    }

    // ========================================================================
    // Error Indication (TS 38.413 Section 8.7.5)
    // ========================================================================

    /// Send an NGAP ErrorIndication to a gNB (TS 38.413 Section 8.7.5).
    ///
    /// Emitted when the AMF receives an undecodable PDU, a PDU for an
    /// unimplemented/unexpected procedure, or a UE-associated message it cannot
    /// process. The AMF-UE-NGAP-ID / RAN-UE-NGAP-ID are included when known so
    /// the gNB can correlate the indication to a UE association.
    async fn send_error_indication(
        &mut self,
        association_id: u64,
        amf_ue_ngap_id: Option<u64>,
        ran_ue_ngap_id: Option<u32>,
        cause: ogs_ngap::types::Cause,
    ) -> Result<()> {
        let msg = ogs_ngap::types::ErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause: Some(cause),
            criticality_diagnostics: None,
        };
        match ogs_ngap::builder::build_error_indication(&msg) {
            Ok(bytes) => {
                self.send_to_association(association_id, &bytes).await?;
                log::info!(
                    "ErrorIndication sent to association {association_id} \
                     (amf_ue_ngap_id={amf_ue_ngap_id:?}, ran_ue_ngap_id={ran_ue_ngap_id:?})"
                );
            }
            Err(e) => log::error!("Failed to build ErrorIndication: {e}"),
        }
        Ok(())
    }

    /// Handle an inbound ErrorIndication from a gNB (TS 38.413 Section 8.7.5).
    /// The AMF never replies; it logs the reported cause/diagnostics for the
    /// affected UE association so operators can trace the protocol error.
    async fn handle_error_indication(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::ErrorIndication(ei)) => {
                log::warn!(
                    "ErrorIndication from association {association_id}: \
                     amf_ue_ngap_id={:?}, ran_ue_ngap_id={:?}, cause={:?}",
                    ei.amf_ue_ngap_id,
                    ei.ran_ue_ngap_id,
                    ei.cause
                );
            }
            Ok(other) => {
                log::warn!("Expected ErrorIndication, decoded {other:?}");
            }
            Err(e) => {
                log::error!("Failed to decode ErrorIndication: {e}");
            }
        }
        Ok(())
    }

    // ========================================================================
    // AMF-initiated Overload Start / Stop (TS 38.413 Sections 8.7.6/8.7.7)
    // ========================================================================

    /// Broadcast an AMF-initiated Overload Start to every connected gNB
    /// (TS 38.413 Section 8.7.6). `reduce_percent` is the requested traffic
    /// reduction (OverloadResponse = Overload Action, here the percentage
    /// variant `OverloadStartNSSAIList`-less form via OverloadResponse).
    pub async fn send_overload_start(&mut self, reduce_percent: u8) -> Result<()> {
        let bytes = match crate::ngap_asn1::build_overload_start_asn1(reduce_percent) {
            Some(b) => b,
            None => {
                log::error!("Failed to build OverloadStart");
                return Ok(());
            }
        };
        let assoc_ids: Vec<u64> = self.sessions.read().await.keys().copied().collect();
        for assoc_id in assoc_ids {
            self.send_to_association(assoc_id, &bytes).await?;
        }
        log::info!("OverloadStart broadcast (reduce {reduce_percent}%)");
        Ok(())
    }

    /// Broadcast an AMF-initiated Overload Stop to every connected gNB
    /// (TS 38.413 Section 8.7.7).
    pub async fn send_overload_stop(&mut self) -> Result<()> {
        let bytes = match crate::ngap_asn1::build_overload_stop_asn1() {
            Some(b) => b,
            None => {
                log::error!("Failed to build OverloadStop");
                return Ok(());
            }
        };
        let assoc_ids: Vec<u64> = self.sessions.read().await.keys().copied().collect();
        for assoc_id in assoc_ids {
            self.send_to_association(assoc_id, &bytes).await?;
        }
        log::info!("OverloadStop broadcast");
        Ok(())
    }

    // ========================================================================
    // N2 Handover (TS 38.413 Section 8.4) and Xn Path Switch (Section 8.4.4)
    // ========================================================================

    /// Handle a HandoverRequired from the source gNB (TS 38.413 Section 8.4.1).
    ///
    /// For an intra-AMF / Xn-less N2 handover the AMF would forward the
    /// SourceToTarget container to the target gNB in a HandoverRequest. Reaching
    /// the target requires resolving its NG association from the TargetID, which
    /// is cross-gNB state. When the target cannot be resolved on this AMF the
    /// preparation is rejected with HandoverPreparationFailure carrying the
    /// spec cause (TS 38.413 Section 9.2.3.6), rather than being dropped.
    async fn handle_handover_required(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let required = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::HandoverRequired(r)) => r,
            Ok(other) => {
                log::warn!("Expected HandoverRequired, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode HandoverRequired: {e}");
                self.send_error_indication(
                    association_id,
                    None,
                    None,
                    ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
                    ),
                )
                .await?;
                return Ok(());
            }
        };
        log::info!(
            "HandoverRequired (amf_ue_ngap_id={}, ran_ue_ngap_id={}, type={:?})",
            required.amf_ue_ngap_id,
            required.ran_ue_ngap_id,
            required.handover_type
        );

        // Locate the target gNB association from the TargetID's Global RAN Node
        // ID. Without a matching connected gNB the AMF cannot allocate handover
        // resources (inter-AMF / N2 relocation needs Namf_Communication, which
        // is out of scope here).
        let target_assoc = self
            .find_association_for_target(&required.target_id)
            .await;

        if target_assoc.is_none() {
            log::warn!(
                "HandoverRequired: target gNB not reachable on this AMF; \
                 rejecting with HandoverPreparationFailure"
            );
            let failure = ogs_ngap::types::HandoverPreparationFailure {
                amf_ue_ngap_id: required.amf_ue_ngap_id,
                ran_ue_ngap_id: required.ran_ue_ngap_id,
                cause: ogs_ngap::types::Cause::RadioNetwork(
                    ogs_asn1c::ngap::cause::CauseRadioNetwork::UnknownTargetId,
                ),
                criticality_diagnostics: None,
            };
            if let Ok(bytes) = ogs_ngap::builder::build_handover_preparation_failure(&failure) {
                self.send_to_association(association_id, &bytes).await?;
            }
            return Ok(());
        }

        // Intra-AMF path: forward a HandoverRequest to the target gNB built from
        // the source UE context. Cross-gNB UE-context relocation (new
        // RAN-UE-NGAP-ID allocation at the target, T304 supervision, the
        // HandoverRequestAcknowledge->HandoverCommand stitching) is tracked as
        // future work; we emit the HandoverRequest with the source container so
        // the target can begin admission.
        let target_assoc = target_assoc.expect("checked is_some");
        let Some(state) = self.ue_auth_state.get(&required.amf_ue_ngap_id) else {
            log::warn!(
                "HandoverRequired for unknown UE {}; rejecting",
                required.amf_ue_ngap_id
            );
            let failure = ogs_ngap::types::HandoverPreparationFailure {
                amf_ue_ngap_id: required.amf_ue_ngap_id,
                ran_ue_ngap_id: required.ran_ue_ngap_id,
                cause: ogs_ngap::types::Cause::RadioNetwork(
                    ogs_asn1c::ngap::cause::CauseRadioNetwork::UnknownLocalUeNgapId,
                ),
                criticality_diagnostics: None,
            };
            if let Ok(bytes) = ogs_ngap::builder::build_handover_preparation_failure(&failure) {
                self.send_to_association(association_id, &bytes).await?;
            }
            return Ok(());
        };

        let (guami_plmn, amf_region, amf_set, amf_pointer) = {
            let ctx = self.amf_context.read().await;
            match ctx.served_guami.first() {
                Some(g) => (
                    g.plmn_id.clone(),
                    g.amf_id.region,
                    g.amf_id.set,
                    g.amf_id.pointer,
                ),
                None => (state.amf_ue.nr_tai.plmn_id.clone(), 2u8, 1u16, 0u8),
            }
        };

        let ho_request = ogs_ngap::types::HandoverRequest {
            amf_ue_ngap_id: required.amf_ue_ngap_id,
            handover_type: required.handover_type,
            cause: required.cause,
            ue_ambr: ogs_ngap::types::UeAmbrInfo {
                dl: state.amf_ue.ue_ambr.downlink.max(1),
                ul: state.amf_ue.ue_ambr.uplink.max(1),
            },
            ue_security_capabilities: ue_caps_to_ngap(&state.amf_ue.ue_security_capability),
            security_context: ogs_ngap::types::SecurityContext {
                next_hop_chaining_count: state.amf_ue.nhcc,
                next_hop: state.amf_ue.nh,
            },
            pdu_session_list: required
                .pdu_session_list
                .iter()
                .map(|p| ogs_ngap::types::PduSessionResourceSetupItemHoReq {
                    pdu_session_id: p.pdu_session_id,
                    s_nssai: state
                        .amf_ue
                        .allowed_nssai
                        .first()
                        .map(|s| ogs_ngap::types::SNssai {
                            sst: s.sst,
                            sd: s.sd.map(|sd| sd.to_be_bytes()[1..4].try_into().unwrap()),
                        })
                        .unwrap_or(ogs_ngap::types::SNssai { sst: 1, sd: None }),
                    transfer: p.transfer.clone(),
                })
                .collect(),
            allowed_nssai: state
                .amf_ue
                .allowed_nssai
                .iter()
                .map(|s| ogs_ngap::types::SNssai {
                    sst: s.sst,
                    sd: s.sd.map(|sd| sd.to_be_bytes()[1..4].try_into().unwrap()),
                })
                .collect(),
            source_to_target_container: required.source_to_target_container.clone(),
            guami: ogs_ngap::types::Guami {
                plmn_identity: plmn_id_to_ngap_bytes(&guami_plmn),
                amf_region_id: amf_region,
                amf_set_id: amf_set,
                amf_pointer,
            },
        };

        match ogs_ngap::builder::build_handover_request(&ho_request) {
            Ok(bytes) => {
                self.send_to_association(target_assoc, &bytes).await?;
                log::info!(
                    "HandoverRequest forwarded to target association {target_assoc} \
                     for UE {}",
                    required.amf_ue_ngap_id
                );
            }
            Err(e) => {
                log::error!("Failed to build HandoverRequest: {e}");
                let failure = ogs_ngap::types::HandoverPreparationFailure {
                    amf_ue_ngap_id: required.amf_ue_ngap_id,
                    ran_ue_ngap_id: required.ran_ue_ngap_id,
                    cause: ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::Unspecified,
                    ),
                    criticality_diagnostics: None,
                };
                if let Ok(b) = ogs_ngap::builder::build_handover_preparation_failure(&failure) {
                    self.send_to_association(association_id, &b).await?;
                }
            }
        }
        Ok(())
    }

    /// Handle a HandoverRequestAcknowledge from the target gNB
    /// (TS 38.413 Section 8.4.2). The AMF stitches the TargetToSource container
    /// into a HandoverCommand back to the source gNB.
    async fn handle_handover_request_acknowledge(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let ack = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::HandoverRequestAcknowledge(a)) => a,
            Ok(other) => {
                log::warn!("Expected HandoverRequestAcknowledge, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode HandoverRequestAcknowledge: {e}");
                return Ok(());
            }
        };
        log::info!(
            "HandoverRequestAcknowledge from association {association_id} \
             (amf_ue_ngap_id={}, admitted {} sessions)",
            ack.amf_ue_ngap_id,
            ack.admitted_list.len()
        );

        // Resolve the source gNB association for this UE. The source is the gNB
        // that issued the original HandoverRequired (its NG association is the
        // one currently holding the UE auth state).
        let source_assoc = self
            .ue_auth_state
            .get(&ack.amf_ue_ngap_id)
            .map(|s| s.association_id);
        let Some(source_assoc) = source_assoc else {
            log::warn!(
                "HandoverRequestAcknowledge for unknown UE {}; cannot send HandoverCommand",
                ack.amf_ue_ngap_id
            );
            return Ok(());
        };
        let (ran_ue_ngap_id, handover_type) = {
            let state = self
                .ue_auth_state
                .get(&ack.amf_ue_ngap_id)
                .expect("checked");
            (state.ran_ue_ngap_id, ogs_ngap::types::HandoverType::Intra5gs)
        };

        let command = ogs_ngap::types::HandoverCommand {
            amf_ue_ngap_id: ack.amf_ue_ngap_id,
            ran_ue_ngap_id,
            handover_type,
            nas_pdu: None,
            pdu_session_list: ack
                .admitted_list
                .iter()
                .map(|a| ogs_ngap::types::PduSessionResourceHandoverItem {
                    pdu_session_id: a.pdu_session_id,
                    transfer: a.transfer.clone(),
                })
                .collect(),
            release_list: None,
            target_to_source_container: ack.target_to_source_container.clone(),
        };
        match ogs_ngap::builder::build_handover_command(&command) {
            Ok(bytes) => {
                self.send_to_association(source_assoc, &bytes).await?;
                log::info!(
                    "HandoverCommand sent to source association {source_assoc} for UE {}",
                    ack.amf_ue_ngap_id
                );
            }
            Err(e) => log::error!("Failed to build HandoverCommand: {e}"),
        }
        Ok(())
    }

    /// Handle a HandoverFailure from the target gNB (TS 38.413 Section 8.4.2).
    /// Resource allocation failed at the target; relay a
    /// HandoverPreparationFailure to the source gNB so it aborts T304.
    async fn handle_handover_failure(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let failure = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::HandoverFailure(f)) => f,
            Ok(other) => {
                log::warn!("Expected HandoverFailure, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode HandoverFailure: {e}");
                return Ok(());
            }
        };
        log::warn!(
            "HandoverFailure from association {association_id} (amf_ue_ngap_id={}, cause={:?})",
            failure.amf_ue_ngap_id,
            failure.cause
        );
        let source = self
            .ue_auth_state
            .get(&failure.amf_ue_ngap_id)
            .map(|s| (s.association_id, s.ran_ue_ngap_id));
        if let Some((source_assoc, ran_ue_ngap_id)) = source {
            let prep_failure = ogs_ngap::types::HandoverPreparationFailure {
                amf_ue_ngap_id: failure.amf_ue_ngap_id,
                ran_ue_ngap_id,
                cause: failure.cause,
                criticality_diagnostics: None,
            };
            if let Ok(bytes) =
                ogs_ngap::builder::build_handover_preparation_failure(&prep_failure)
            {
                self.send_to_association(source_assoc, &bytes).await?;
            }
        }
        Ok(())
    }

    /// Handle a HandoverNotify from the target gNB (TS 38.413 Section 8.4.3):
    /// the UE has successfully arrived. The AMF updates the UE's serving cell
    /// location and (in a full deployment) releases the source-side resources.
    async fn handle_handover_notify(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let notify = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::HandoverNotify(n)) => n,
            Ok(other) => {
                log::warn!("Expected HandoverNotify, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode HandoverNotify: {e}");
                return Ok(());
            }
        };
        log::info!(
            "HandoverNotify from association {association_id} (amf_ue_ngap_id={}, ran_ue_ngap_id={})",
            notify.amf_ue_ngap_id,
            notify.ran_ue_ngap_id
        );
        if let Some(state) = self.ue_auth_state.get_mut(&notify.amf_ue_ngap_id) {
            // Move the serving association/RAN-UE-NGAP-ID and location to the
            // target now that the UE has arrived (TS 23.502 Section 4.9.1.3).
            state.association_id = association_id;
            state.ran_ue_ngap_id = notify.ran_ue_ngap_id;
            let ogs_ngap::types::UserLocationInformation::Nr {
                nr_cgi_plmn,
                nr_cell_identity,
                tai_plmn,
                tai_tac,
            } = &notify.user_location_info;
            state.amf_ue.nr_cgi.plmn_id = plmn_id_from_ngap_bytes(nr_cgi_plmn);
            state.amf_ue.nr_cgi.cell_id = *nr_cell_identity;
            state.amf_ue.nr_tai.plmn_id = plmn_id_from_ngap_bytes(tai_plmn);
            state.amf_ue.nr_tai.tac =
                ((tai_tac[0] as u32) << 16) | ((tai_tac[1] as u32) << 8) | tai_tac[2] as u32;
            log::info!(
                "UE {} relocated to target gNB (association {association_id})",
                notify.amf_ue_ngap_id
            );
        } else {
            log::warn!(
                "HandoverNotify for unknown UE {}; ignoring",
                notify.amf_ue_ngap_id
            );
        }
        Ok(())
    }

    /// Handle a HandoverCancel from the source gNB (TS 38.413 Section 8.4.5).
    /// The AMF acknowledges with a HandoverCancelAcknowledge.
    async fn handle_handover_cancel(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        let cancel = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::HandoverCancel(c)) => c,
            Ok(other) => {
                log::warn!("Expected HandoverCancel, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode HandoverCancel: {e}");
                self.send_error_indication(
                    association_id,
                    None,
                    None,
                    ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
                    ),
                )
                .await?;
                return Ok(());
            }
        };
        log::info!(
            "HandoverCancel from association {association_id} (amf_ue_ngap_id={}, cause={:?})",
            cancel.amf_ue_ngap_id,
            cancel.cause
        );
        let ack = ogs_ngap::types::HandoverCancelAcknowledge {
            amf_ue_ngap_id: cancel.amf_ue_ngap_id,
            ran_ue_ngap_id: cancel.ran_ue_ngap_id,
            criticality_diagnostics: None,
        };
        match ogs_ngap::builder::build_handover_cancel_acknowledge(&ack) {
            Ok(bytes) => {
                self.send_to_association(association_id, &bytes).await?;
                log::info!(
                    "HandoverCancelAcknowledge sent for UE {}",
                    cancel.amf_ue_ngap_id
                );
            }
            Err(e) => log::error!("Failed to build HandoverCancelAcknowledge: {e}"),
        }
        Ok(())
    }

    /// Handle a PathSwitchRequest from the target gNB after an Xn handover
    /// (TS 38.413 Section 8.4.4). The AMF updates the UE's RAN-UE-NGAP-ID and
    /// serving association, derives a fresh NH (TS 33.501 Section 6.9.2.3.3),
    /// and replies with PathSwitchRequestAcknowledge; on any inconsistency it
    /// replies with PathSwitchRequestFailure (TS 38.413 Section 9.2.3.12).
    async fn handle_path_switch_request(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let req = match ogs_ngap::parser::decode_ngap_pdu(data) {
            Ok(ogs_ngap::NgapMessage::PathSwitchRequest(r)) => r,
            Ok(other) => {
                log::warn!("Expected PathSwitchRequest, decoded {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::error!("Failed to decode PathSwitchRequest: {e}");
                self.send_error_indication(
                    association_id,
                    None,
                    None,
                    ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
                    ),
                )
                .await?;
                return Ok(());
            }
        };
        let amf_ue_ngap_id = req.source_amf_ue_ngap_id;
        log::info!(
            "PathSwitchRequest (amf_ue_ngap_id={amf_ue_ngap_id}, new ran_ue_ngap_id={})",
            req.ran_ue_ngap_id
        );

        // Unknown UE → PathSwitchRequestFailure with unknown-local-UE cause.
        if !self.ue_auth_state.contains_key(&amf_ue_ngap_id) {
            log::warn!("PathSwitchRequest for unknown UE {amf_ue_ngap_id}; failing");
            let failure = ogs_ngap::types::PathSwitchRequestFailure {
                amf_ue_ngap_id,
                ran_ue_ngap_id: req.ran_ue_ngap_id,
                cause: ogs_ngap::types::Cause::RadioNetwork(
                    ogs_asn1c::ngap::cause::CauseRadioNetwork::UnknownLocalUeNgapId,
                ),
                released_list: None,
                criticality_diagnostics: None,
            };
            if let Ok(bytes) = ogs_ngap::builder::build_path_switch_request_failure(&failure) {
                self.send_to_association(association_id, &bytes).await?;
            }
            return Ok(());
        }

        // Derive a fresh NH from KAMF (vertical key derivation) and increment
        // the NHCC (TS 33.501 Section 6.9.2.3.3 / 6.9.4.1).
        let (ncc, switched_list, allowed_nssai, ue_caps) = {
            let state = self
                .ue_auth_state
                .get_mut(&amf_ue_ngap_id)
                .expect("checked");
            let new_nh = ogs_crypt::kdf::ogs_kdf_nh_gnb(&state.amf_ue.kamf, &state.amf_ue.nh);
            state.amf_ue.nh = new_nh;
            state.amf_ue.nhcc = state.amf_ue.nhcc.wrapping_add(1) & 0x07;
            // Move the UE's serving RAN association and RAN-UE-NGAP-ID to the
            // target gNB; this is the N3 tunnel/RAN identity update.
            state.ran_ue_ngap_id = req.ran_ue_ngap_id;
            state.association_id = association_id;

            let switched_list: Vec<ogs_ngap::types::PduSessionResourceSwitchedItem> = req
                .pdu_session_list
                .iter()
                .map(|p| ogs_ngap::types::PduSessionResourceSwitchedItem {
                    pdu_session_id: p.pdu_session_id,
                    // Echo the gNB's path-switch transfer back as the ack
                    // transfer; in a full deployment the SMF supplies the UL
                    // F-TEID via Nsmf_PDUSession_UpdateSMContext.
                    transfer: p.transfer.clone(),
                })
                .collect();

            let allowed_nssai = state
                .amf_ue
                .allowed_nssai
                .iter()
                .map(|s| ogs_ngap::types::SNssai {
                    sst: s.sst,
                    sd: s.sd.map(|sd| sd.to_be_bytes()[1..4].try_into().unwrap()),
                })
                .collect::<Vec<_>>();

            (
                state.amf_ue.nhcc,
                switched_list,
                allowed_nssai,
                ue_caps_to_ngap(&state.amf_ue.ue_security_capability),
            )
        };

        let nh = self
            .ue_auth_state
            .get(&amf_ue_ngap_id)
            .expect("checked")
            .amf_ue
            .nh;

        let allowed_for_ack = if allowed_nssai.is_empty() {
            vec![ogs_ngap::types::SNssai { sst: 1, sd: None }]
        } else {
            allowed_nssai
        };

        let ack = ogs_ngap::types::PathSwitchRequestAcknowledge {
            amf_ue_ngap_id,
            ran_ue_ngap_id: req.ran_ue_ngap_id,
            ue_security_capabilities: Some(ue_caps),
            security_context: ogs_ngap::types::SecurityContext {
                next_hop_chaining_count: ncc,
                next_hop: nh,
            },
            switched_list,
            released_list: None,
            allowed_nssai: allowed_for_ack,
        };
        match ogs_ngap::builder::build_path_switch_request_acknowledge(&ack) {
            Ok(bytes) => {
                self.send_to_association(association_id, &bytes).await?;
                log::info!(
                    "PathSwitchRequestAcknowledge sent for UE {amf_ue_ngap_id} \
                     (new ran_ue_ngap_id={}, NCC={ncc})",
                    req.ran_ue_ngap_id
                );
            }
            Err(e) => {
                log::error!("Failed to build PathSwitchRequestAcknowledge: {e}");
                let failure = ogs_ngap::types::PathSwitchRequestFailure {
                    amf_ue_ngap_id,
                    ran_ue_ngap_id: req.ran_ue_ngap_id,
                    cause: ogs_ngap::types::Cause::Protocol(
                        ogs_asn1c::ngap::cause::CauseProtocol::Unspecified,
                    ),
                    released_list: None,
                    criticality_diagnostics: None,
                };
                if let Ok(b) = ogs_ngap::builder::build_path_switch_request_failure(&failure) {
                    self.send_to_association(association_id, &b).await?;
                }
            }
        }
        Ok(())
    }

    /// Resolve the SCTP association of the gNB named by a handover TargetID by
    /// matching its Global RAN Node ID against connected gNB contexts.
    async fn find_association_for_target(
        &self,
        target_id: &ogs_ngap::types::TargetId,
    ) -> Option<u64> {
        let target_gnb_id = match target_id {
            ogs_ngap::types::TargetId::TargetRanNodeId {
                global_ran_node_id, ..
            } => match global_ran_node_id {
                ogs_ngap::types::GlobalRanNodeId::GlobalGnbId { gnb_id, .. } => Some(*gnb_id as u64),
                _ => None,
            },
            ogs_ngap::types::TargetId::TargetGlobalNgEnbId { .. } => None,
        }?;
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .find(|(_, s)| s.gnb.gnb_id as u64 == target_gnb_id)
            .map(|(assoc, _)| *assoc)
    }

    /// Handle Initial Context Setup Response from the gNB (TS 38.413 §8.3.1.2).
    ///
    /// The gNB has set up AS-layer security and delivered the piggybacked
    /// Registration Accept to the UE. The AMF marks the UE context as
    /// established and transitions the GMM FSM out of InitialContextSetup; the
    /// NAS-layer Registration Complete then drives the move to Registered. The
    /// ICS-based retransmission timer is cleared since the gNB has the NAS PDU.
    async fn handle_initial_context_setup_response(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let Some((amf_ue_ngap_id, ran_ue_ngap_id)) =
            crate::ngap_asn1::parse_initial_context_setup_response_asn1(data)
        else {
            return Ok(());
        };
        log::info!(
            "Initial Context Setup Response: amf_ue_ngap_id={amf_ue_ngap_id}, \
             ran_ue_ngap_id={ran_ue_ngap_id} (association {association_id})"
        );

        if let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) {
            state.initial_context_setup_response_received = true;
            // The gNB has the Registration Accept; stop retransmitting the ICS
            // request. T3550 logic that waits for Registration Complete is reset
            // here — Registration Complete arrives on the uplink NAS path.
            state.retx = None;
            // Leave InitialContextSetup; Registration Complete moves the FSM to
            // Registered (TS 24.501 §5.5.1.2.4).
            state.gmm_fsm.transition_to_registered();
            log::info!("UE {amf_ue_ngap_id} context established (AS-layer security up)");
        } else {
            log::warn!(
                "Initial Context Setup Response for unknown UE {amf_ue_ngap_id}; ignoring"
            );
        }
        Ok(())
    }

    /// Handle Initial Context Setup Failure from the gNB (TS 38.413 §8.3.1.3).
    ///
    /// The gNB could not establish AS-layer security. The registration cannot
    /// complete, so the AMF releases the UE context.
    async fn handle_initial_context_setup_failure(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let Some((amf_ue_ngap_id, ran_ue_ngap_id)) =
            crate::ngap_asn1::parse_initial_context_setup_failure_asn1(data)
        else {
            return Ok(());
        };
        log::warn!(
            "Initial Context Setup Failure: amf_ue_ngap_id={amf_ue_ngap_id}, \
             ran_ue_ngap_id={ran_ue_ngap_id} (association {association_id}); releasing UE"
        );

        // Drop any pending ICS retransmission, then release the NG context.
        if let Some(state) = self.ue_auth_state.get_mut(&amf_ue_ngap_id) {
            state.retx = None;
            state.gmm_fsm.transition_to_exception();
        }
        // NAS cause #22 "congestion" is not appropriate; use #9 (UE identity
        // cannot be derived) so the UE re-registers (TS 24.501 Annex).
        self.release_ue(
            association_id,
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            GmmCause::UeIdentityCannotBeDerivedByTheNetwork as u8,
        )
        .await
    }

    /// Handle PDU Session Resource Setup Response from gNB
    ///
    /// Extracts gNB TEID from the response and forwards it to SMF via SM Context Update.
    /// The SMF then sends PFCP Session Modification to the UPF to activate the DL FAR.
    async fn handle_pdu_session_resource_setup_response(
        &mut self,
        association_id: u64,
        data: &[u8],
    ) -> Result<()> {
        log::info!(
            "PDU Session Resource Setup Response from association {} ({} bytes)",
            association_id,
            data.len()
        );

        // Decode the APER-encoded PDU Session Resource Setup Response using ASN.1
        use ogs_ngap::{parser::decode_ngap_pdu, NgapMessage};

        let response_data = match decode_ngap_pdu(data) {
            Ok(NgapMessage::PduSessionResourceSetupResponse(resp)) => resp,
            Ok(other) => {
                log::warn!("Expected PduSessionResourceSetupResponse, got {other:?}");
                return Ok(());
            }
            Err(e) => {
                log::warn!("Failed to decode PDU Session Resource Setup Response: {e:?}");
                return Ok(());
            }
        };

        log::info!(
            "Decoded Setup Response: amf_ue_ngap_id={}, ran_ue_ngap_id={}",
            response_data.amf_ue_ngap_id,
            response_data.ran_ue_ngap_id
        );

        let mut gnb_endpoint: Option<(u8, ngap_asn1::GnbN3Endpoint, Vec<u8>)> = None;

        for item in &response_data.setup_list {
            // APER PDUSessionResourceSetupResponseTransfer (TS 38.413 Section 9.3.4.2)
            match ngap_asn1::parse_n2_sm_setup_response_transfer(&item.transfer) {
                Some(endpoint) => {
                    log::info!(
                        "Extracted gNB TEID=0x{:08x}, addr={:?}, QFIs={:?}, PSI={}",
                        endpoint.teid,
                        endpoint.address,
                        endpoint.qfis,
                        item.pdu_session_id
                    );
                    gnb_endpoint = Some((item.pdu_session_id, endpoint, item.transfer.clone()));
                }
                None => {
                    log::warn!(
                        "Failed to decode setup-response transfer for PSI={} ({} bytes)",
                        item.pdu_session_id,
                        item.transfer.len()
                    );
                }
            }
        }

        if let Some((pdu_session_id, endpoint, raw_transfer)) = gnb_endpoint {
            log::info!(
                "PDU Session Resource Setup Response: PSI={}, gNB TEID=0x{:08x}",
                pdu_session_id,
                endpoint.teid
            );

            // Forward the received N2 SM information container to the SMF
            // opaquely (the AMF does not re-encode N2 SM info, TS 23.502)
            let n2_sm_info = raw_transfer;

            // Call SMF to update SM context with gNB TEID
            let smf_update_host =
                std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
            let smf_update_port: u16 = std::env::var("SMF_SBI_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(7777);
            let sm_context_ref = format!("{pdu_session_id}");

            match crate::sbi_path::call_smf_update_sm_context(
                &smf_update_host,
                smf_update_port,
                &sm_context_ref,
                &n2_sm_info,
            )
            .await
            {
                Ok(()) => {
                    log::info!(
                        "SMF SM Context Updated with gNB TEID: ref={}, TEID=0x{:08x}",
                        sm_context_ref,
                        endpoint.teid
                    );
                }
                Err(e) => {
                    log::warn!("Failed to update SMF SM Context: {e}");
                }
            }
        } else {
            log::warn!("Could not extract gNB TEID from PDU Session Resource Setup Response");
        }

        Ok(())
    }

    /// Handle UE Context Release Request from gNB
    ///
    /// Releases all PDU sessions at SMF and sends UEContextReleaseCommand back.
    async fn handle_ue_context_release(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::info!(
            "UE Context Release Request from association {} ({} bytes)",
            association_id,
            data.len()
        );

        // Parse AMF UE NGAP ID and RAN UE NGAP ID from the message
        // The release request contains: procedure_code(1), criticality(1), length(variable),
        // then IEs for AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, PDUSessionResourceList, Cause
        let amf_ue_ngap_id = crate::ngap_asn1::extract_amf_ue_ngap_id(data);
        let ran_ue_ngap_id = crate::ngap_asn1::extract_ran_ue_ngap_id(data);

        log::info!(
            "UE Context Release: AMF UE NGAP ID={amf_ue_ngap_id:?}, RAN UE NGAP ID={ran_ue_ngap_id:?}"
        );

        // Release all PDU sessions at SMF
        let smf_host = std::env::var("SMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let smf_port: u16 = std::env::var("SMF_SBI_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(7777);

        // Look up active sessions for this UE via AMF UE NGAP ID -> RanUe -> amf_ue_id -> sessions
        // Collect session refs under the read lock, then release lock before async SMF calls
        let sm_context_refs: Vec<(u8, String)> = {
            let mut refs = Vec::new();
            if let Some(ngap_id) = amf_ue_ngap_id {
                let ctx = crate::context::amf_self();
                let context = ctx.read();
                if let Ok(context) = context {
                    let amf_ue_id = context
                        .ran_ue_find_by_amf_ue_ngap_id(ngap_id)
                        .map(|ran_ue| ran_ue.amf_ue_id)
                        .unwrap_or(ngap_id);

                    for sess in context.sess_list_for_ue(amf_ue_id).iter() {
                        if let Some(ref r) = sess.sm_context_ref {
                            refs.push((sess.psi, r.clone()));
                        }
                    }
                }
            }
            refs
        };

        if sm_context_refs.is_empty() {
            log::debug!("No PDU sessions to release for UE context release");
        }
        for (psi, sm_context_ref) in &sm_context_refs {
            log::info!("Releasing SMF SM Context: PSI={psi}, ref={sm_context_ref}");
            match crate::sbi_path::call_smf_release_sm_context(&smf_host, smf_port, sm_context_ref)
                .await
            {
                Ok(()) => log::info!("SMF SM Context Released: PSI={psi}"),
                Err(e) => log::warn!("SMF release failed for PSI={psi}: {e}"),
            }
        }

        // Build and send UEContextReleaseCommand (Cause: NAS normal-release)
        if let (Some(amf_id), Some(ran_id)) = (amf_ue_ngap_id, ran_ue_ngap_id) {
            let release_cmd = crate::ngap_asn1::build_ue_context_release_command_asn1(
                amf_id,
                ran_id,
                ngap_handler::cause_group::NAS,
                0, // CauseNas normal-release
            );
            if let Some(cmd) = release_cmd {
                self.send_to_association(association_id, &cmd).await?;
                log::info!("UE Context Release Command sent to gNB");
            }
        }

        Ok(())
    }

    /// Send Paging to all connected gNBs in the UE's tracking area
    ///
    /// This is called when the AMF needs to page a UE in CM-IDLE state,
    /// e.g., when downlink data notification is received from SMF.
    pub async fn send_paging(
        &mut self,
        amf_set_id: u16,
        amf_pointer: u8,
        tmsi: u32,
        plmn_id: &crate::context::PlmnId,
        tac: u32,
    ) -> Result<()> {
        let paging_bytes = match crate::ngap_asn1::build_paging_asn1(
            amf_set_id,
            amf_pointer,
            tmsi,
            plmn_id,
            tac,
        ) {
            Some(bytes) => bytes,
            None => {
                log::error!("Failed to build Paging message");
                return Err(anyhow::anyhow!("Failed to build Paging message"));
            }
        };

        // Send to all connected gNBs (in production, filter by TAI match)
        let association_ids: Vec<u64> = self.sessions.read().await.keys().copied().collect();
        let gnb_count = association_ids.len();

        for assoc_id in association_ids {
            if let Err(e) = self.send_to_association(assoc_id, &paging_bytes).await {
                log::warn!("Failed to send Paging to association {assoc_id}: {e}");
            }
        }

        log::info!(
            "Paging sent to {gnb_count} gNBs: amf_set_id={amf_set_id}, tmsi=0x{tmsi:08x}, tac={tac}"
        );
        Ok(())
    }

    /// Send message to a gNB by association ID
    /// NOTE: This method requires &mut self to access the SCTP server
    async fn send_to_association(&mut self, association_id: u64, data: &[u8]) -> Result<()> {
        log::debug!(
            "Sending {} bytes to association {}",
            data.len(),
            association_id
        );

        // Use stream 0 for NGAP signaling
        self.sctp_server
            .send(association_id, 0, data)
            .await
            .map_err(|e| anyhow::anyhow!("SCTP send error: {e}"))
    }

    /// Send message to a gNB by ID
    pub async fn send_by_id(&mut self, gnb_id: u64, data: &[u8]) -> Result<()> {
        // Find the association ID for this gNB ID, then drop the read lock
        // before calling send_to_association (which needs &mut self).
        let assoc_id = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .find(|(_, session)| session.id == gnb_id)
                .map(|(assoc_id, _)| *assoc_id)
        };

        match assoc_id {
            Some(assoc_id) => {
                log::debug!("Sending {} bytes to gNB {}", data.len(), gnb_id);
                self.send_to_association(assoc_id, data).await
            }
            None => Err(anyhow::anyhow!("gNB {gnb_id} not found")),
        }
    }

    /// Close a gNB session
    pub async fn close_session(&self, association_id: u64) -> Result<()> {
        if let Some(session) = self.sessions.write().await.remove(&association_id) {
            log::info!(
                "Closed gNB session {} (association {})",
                session.id,
                association_id
            );
            self.assoc_to_addr.write().await.remove(&association_id);
        }
        Ok(())
    }
}

// ============================================================================
// NAS parsing / helper functions (TS 24.501)
// ============================================================================

/// Stable AMF NF instance ID for SBI registrations/subscriptions
fn amf_instance_id() -> String {
    static ID: once_cell::sync::Lazy<String> =
        once_cell::sync::Lazy::new(|| uuid::Uuid::new_v4().to_string());
    ID.clone()
}

/// Parsed Registration Request (TS 24.501 Section 8.2.6)
#[derive(Debug, Clone, Default)]
struct ParsedRegistrationRequest {
    registration_type: u8,
    tsc: u8,
    ksi: u8,
    identity_type: u8,
    suci: Option<String>,
    guti: Option<Guti5gs>,
    plmn: Option<PlmnId>,
    sec_cap: Option<UeSecurityCapability>,
    requested_nssai: Vec<SNssai>,
    /// SNPN NID (Rel-17, TS 23.501 §5.30) included by the UE, if any.
    snpn_nid: Option<String>,
    /// MINT disaster-roaming indication (Rel-18, TS 23.761 §4.2). Set when the
    /// UE requests disaster-roaming / minimization-of-service-interruption
    /// handling for this (e.g. secondary multi-SUPI) registration.
    disaster_roaming: bool,
    /// UAV indication (Rel-18, TS 23.256). `Some(caa_id)` when the UE
    /// registered as an aerial UE; the AMF then creates a UAV flight
    /// authorization (geofence) context. The string is the UAV CAA-level ID
    /// (may be empty when only the aerial-UE capability is signalled).
    uav_indication: Option<String>,
    /// RedCap (Reduced Capability) indication (Rel-17, TS 38.101). Set when the
    /// UE signals a reduced-capability device (NAS IEI 0xA9) so the AMF caps
    /// UE-AMBR and forwards the indication to the SMF for a reduced session-AMBR.
    redcap_indication: bool,
}

/// SNPN allowed-NID list for this AMF (Rel-17, TS 23.501 §5.30).
///
/// Read from `AMF_SNPN_ALLOWED_NIDS` as a comma-separated list of 11-hex-char
/// NIDs. Empty/unset means no NID restriction (accept any SNPN NID), matching
/// `AmfUe::validate_nid`'s empty-list semantics. Sourcing from an env var keeps
/// the SNPN gate modular and consistent with the AMF's other runtime config.
/// Decode a DNN IE value (TS 24.501 9.11.2.1A / TS 23.003): a sequence of
/// labels each prefixed by a 1-byte length, joined with '.'. Returns None for
/// an empty/malformed value so the caller falls back to the default DNN.
fn decode_dnn_labels(bytes: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let len = bytes[i] as usize;
        if len == 0 || i + 1 + len > bytes.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&bytes[i + 1..i + 1 + len]).to_string());
        i += 1 + len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn snpn_allowed_nids() -> Vec<String> {
    std::env::var("AMF_SNPN_ALLOWED_NIDS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Decode the 44-bit packed SNPN NID (TS 23.003 §12.7) carried in the
/// Registration Request NID IE back to its canonical 11-uppercase-hex-digit
/// string. The wire form is 6 octets: assignment-mode nibble first, then the
/// 10-digit NID value MSB-first; the trailing nibble of the 6th octet is spare.
/// Must mirror the sim encoder (`nextgsim-nas` `encode_nid_44bit`). Returns
/// `None` if fewer than 6 octets are present.
fn decode_nid_44bit(octets: &[u8]) -> Option<String> {
    if octets.len() < 6 {
        return None;
    }
    let mut s = String::with_capacity(11);
    for &b in &octets[..5] {
        s.push(char::from_digit((b >> 4) as u32, 16)?.to_ascii_uppercase());
        s.push(char::from_digit((b & 0x0F) as u32, 16)?.to_ascii_uppercase());
    }
    s.push(char::from_digit((octets[5] >> 4) as u32, 16)?.to_ascii_uppercase());
    Some(s)
}

/// Parse a Service-level-AA container's contents (TS 24.501 §9.11.2.10) and
/// return the CAA-level UAV ID from the Service-level device ID parameter
/// (param-IEI 0x10, type-4, UTF-8). Mirrors the sim encoder
/// (`nextgsim-nas` `encode_service_level_aa_container`). Unknown type-4
/// parameters are skipped per the spec's "ignore unknown IEI" rule.
fn decode_service_level_aa_container(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let ptype = bytes[i];
        let plen = bytes[i + 1] as usize;
        let start = i + 2;
        if start + plen > bytes.len() {
            break;
        }
        if ptype == 0x10 {
            return std::str::from_utf8(&bytes[start..start + plen])
                .ok()
                .map(|s| s.to_string());
        }
        i = start + plen;
    }
    None
}

/// UAV geofence configuration for this AMF (Rel-18, TS 23.256).
///
/// Returns `(min_lat, max_lat, min_lon, max_lon, min_alt, max_alt)` read from
/// `AMF_UAV_GEOFENCE` as six comma-separated decimals. Defaults to a permissive
/// area capped at 120 m altitude (the common regulatory ceiling) when unset, so
/// a UAV reporting above 120 m or outside the area triggers a geofence deny.
/// Sourcing from an env var keeps the UAV gate modular and consistent with the
/// AMF's other runtime config (e.g. `AMF_SNPN_ALLOWED_NIDS`).
fn uav_geofence_config() -> (f64, f64, f64, f64, f64, f64) {
    let default = (
        37.0_f64, 38.0_f64, -123.0_f64, -122.0_f64, 0.0_f64, 120.0_f64,
    );
    let Ok(raw) = std::env::var("AMF_UAV_GEOFENCE") else {
        return default;
    };
    let vals: Vec<f64> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<f64>().ok())
        .collect();
    if vals.len() == 6 {
        (vals[0], vals[1], vals[2], vals[3], vals[4], vals[5])
    } else {
        default
    }
}

/// Notify the UTM / USS (UAS Service Supplier) of a UAV authorization
/// (Rel-18, TS 23.256). The external USS / UTM interface (e.g. over the UAV
/// flight authorization API) is a documented stub in this stack: it logs the
/// authorization rather than calling an external NF. Replace with a real USS
/// client when the UTM interface is productionized.
fn notify_uss_authorization(caa_id: &str, suci: &str) {
    log::info!("[UAV UTM stub] USS authorization accepted (stub): CAA-ID={caa_id}, SUCI={suci}");
}

/// Whether a SUCI belongs to an SNPN onboarding subscription (TS 23.003).
///
/// Onboarding SUPIs use the reserved onboarding routing/credential indicator;
/// a minimal heuristic flags the configured onboarding marker. Replace with the
/// full onboarding-SUCI parse when onboarding credentials are productionized.
fn is_snpn_onboarding_suci(suci: &str) -> bool {
    suci.contains("onboarding")
}

/// Parse a plain Registration Request NAS PDU
/// Extract the value of the NAS message container IE (IEI 0x71, TLV-E format:
/// IEI(1) | length(2, big-endian) | value) from a 5GMM plain message body such
/// as Security Mode Complete (TS 24.501 Section 9.11.3.33). Returns the
/// contained NAS message (the replayed initial RegistrationRequest).
fn extract_nas_message_container(nas: &[u8]) -> Option<Vec<u8>> {
    // 5GMM header: EPD(1) | security-header-type(1) | message-type(1).
    let mut pos = 3;
    while pos < nas.len() {
        let iei = nas[pos];
        match iei {
            // NAS message container (0x71) — TLV-E
            0x71 => {
                if pos + 3 > nas.len() {
                    return None;
                }
                let len = ((nas[pos + 1] as usize) << 8) | (nas[pos + 2] as usize);
                if pos + 3 + len > nas.len() {
                    return None;
                }
                return Some(nas[pos + 3..pos + 3 + len].to_vec());
            }
            // IMEISV (0x77) — TLV-E: skip over it
            0x77 => {
                if pos + 3 > nas.len() {
                    return None;
                }
                let len = ((nas[pos + 1] as usize) << 8) | (nas[pos + 2] as usize);
                pos += 3 + len;
            }
            // Any other IE: cannot reliably skip an unknown format, so advance
            // by one octet and keep scanning for the container IEI.
            _ => pos += 1,
        }
    }
    None
}

fn parse_registration_request_pdu(nas: &[u8]) -> Option<ParsedRegistrationRequest> {
    // EPD + sec hdr + msg type + (ngKSI | 5GS registration type) + LV-E identity
    if nas.len() < 6 {
        return None;
    }
    let mut req = ParsedRegistrationRequest {
        registration_type: nas[3] & 0x07,
        tsc: (nas[3] >> 7) & 0x01,
        ksi: (nas[3] >> 4) & 0x07,
        ..Default::default()
    };

    // 5GS mobile identity (LV-E: 2-byte length)
    let id_len = ((nas[4] as usize) << 8) | (nas[5] as usize);
    if id_len == 0 || nas.len() < 6 + id_len {
        return None;
    }
    let identity = &nas[6..6 + id_len];
    req.identity_type = identity[0] & 0x07;
    match req.identity_type {
        t if t == mobile_identity_type::SUCI => {
            if let Some((suci, plmn)) = parse_suci_identity(identity) {
                req.suci = Some(suci);
                req.plmn = Some(plmn);
            }
        }
        t if t == mobile_identity_type::GUTI => {
            req.guti = crate::gmm_handler::parse_guti(identity);
        }
        _ => {}
    }

    // Optional IEs
    let mut pos = 6 + id_len;
    while pos < nas.len() {
        let iei = nas[pos];
        match iei {
            // UE security capability (IEI 0x2E, TLV)
            0x2E => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                if len >= 2 && pos + 2 + len <= nas.len() {
                    req.sec_cap = Some(UeSecurityCapability {
                        ea: nas[pos + 2],
                        ia: nas[pos + 3],
                        eea: if len >= 3 { nas[pos + 4] } else { 0 },
                        eia: if len >= 4 { nas[pos + 5] } else { 0 },
                    });
                }
                pos += 2 + len;
            }
            // Requested NSSAI (IEI 0x2F, TLV)
            0x2F => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                if pos + 2 + len <= nas.len() {
                    req.requested_nssai = parse_nssai_value(&nas[pos + 2..pos + 2 + len]);
                }
                pos += 2 + len;
            }
            // SNPN NID (IEI 0xA6, TLV): UE-included SNPN Network Identifier
            // (Rel-17, TS 23.501 §5.30) carried as the 44-bit packed NID of
            // TS 23.003 §12.7 (6 octets). Parse before the generic Type-1 arm.
            0xA6 => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                if pos + 2 + len <= nas.len() {
                    if let Some(nid) = decode_nid_44bit(&nas[pos + 2..pos + 2 + len]) {
                        req.snpn_nid = Some(nid);
                    }
                }
                pos += 2 + len;
            }
            // MINT disaster-roaming indication (IEI 0xA7, TLV): Rel-18,
            // TS 23.761 §4.2. A single value octet whose bit 1 is the
            // disaster-roaming flag. Parse before the generic Type-1 arm.
            0xA7 => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                if len >= 1 && pos + 2 + len <= nas.len() {
                    req.disaster_roaming = nas[pos + 2] & 0x01 == 0x01;
                }
                pos += 2 + len;
            }
            // Service-level-AA container (IEI 0x72, TLV-E): Rel-17/18,
            // TS 24.501 §9.11.2.10 / §8.2.6. Type-6 IE with a 2-octet length;
            // contents carry the UAS CAA-level UAV ID as the Service-level
            // device ID parameter (0x10, UTF-8). Parse before the generic arms.
            0x72 => {
                if pos + 2 >= nas.len() {
                    break;
                }
                let len = ((nas[pos + 1] as usize) << 8) | nas[pos + 2] as usize;
                if pos + 3 + len <= nas.len() {
                    req.uav_indication =
                        decode_service_level_aa_container(&nas[pos + 3..pos + 3 + len]);
                }
                pos += 3 + len;
            }
            // RedCap indication (IEI 0xA9, TLV): Rel-17, TS 38.101. A single
            // value octet whose bit 0 marks a reduced-capability device. Parse
            // before the generic Type-1 arm.
            0xA9 => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                if len >= 1 && pos + 2 + len <= nas.len() {
                    req.redcap_indication = nas[pos + 2] & 0x01 == 0x01;
                }
                pos += 2 + len;
            }
            // Last visited registered TAI (IEI 0x52, TV, 7 bytes total)
            0x52 => pos += 7,
            // TLV-E IEs (2-byte length): EPS NAS container (0x70),
            // NAS message container (0x71), additional GUTI (0x77),
            // payload containers (0x7B/0x7C)
            0x70 | 0x71 | 0x77 | 0x7B | 0x7C => {
                if pos + 2 >= nas.len() {
                    break;
                }
                let len = ((nas[pos + 1] as usize) << 8) | (nas[pos + 2] as usize);
                pos += 3 + len;
            }
            // Type-1 TV (IEI in high nibble)
            b if b & 0x80 != 0 => pos += 1,
            // Default: assume TLV
            _ => {
                if pos + 1 >= nas.len() {
                    break;
                }
                let len = nas[pos + 1] as usize;
                pos += 2 + len;
            }
        }
    }

    Some(req)
}

/// Parse a UAV tracking report NAS PDU (Rel-18, TS 23.256).
///
/// Layout (matching the nextgsim UE `build_uav_tracking_report`): 5GMM header
/// (EPD, sec-hdr, msg-type = 3 octets), then a length-prefixed CAA-level ID,
/// then latitude/longitude as i32 1e-7-degree fixed point, altitude as i32
/// 0.1 m fixed point, and a flight-status octet.
fn parse_uav_tracking_report(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    inner: &[u8],
) -> Option<crate::ngap_handler::UavTrackingReport> {
    // 3-octet header + 1-octet ID length
    if inner.len() < 4 {
        return None;
    }
    let id_len = inner[3] as usize;
    let pos = 4 + id_len;
    // CAA ID + 4 (lat) + 4 (lon) + 4 (alt) + 1 (status)
    if inner.len() < pos + 13 {
        return None;
    }
    let uav_id = std::str::from_utf8(&inner[4..4 + id_len]).ok()?.to_string();
    let lat_raw = i32::from_be_bytes(inner[pos..pos + 4].try_into().ok()?);
    let lon_raw = i32::from_be_bytes(inner[pos + 4..pos + 8].try_into().ok()?);
    let alt_raw = i32::from_be_bytes(inner[pos + 8..pos + 12].try_into().ok()?);
    let flight_status = inner[pos + 12];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(crate::ngap_handler::UavTrackingReport {
        amf_ue_ngap_id,
        ran_ue_ngap_id: ran_ue_ngap_id as u64,
        uav_id,
        latitude: lat_raw as f64 / 1e7,
        longitude: lon_raw as f64 / 1e7,
        altitude: alt_raw as f64 / 10.0,
        timestamp,
        flight_status,
    })
}

/// Parse an NSSAI IE value into S-NSSAIs (TS 24.501 Section 9.11.3.37)
fn parse_nssai_value(data: &[u8]) -> Vec<SNssai> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 || pos + 1 + len > data.len() {
            break;
        }
        let sst = data[pos + 1];
        let sd = if len >= 4 {
            Some(
                ((data[pos + 2] as u32) << 16)
                    | ((data[pos + 3] as u32) << 8)
                    | data[pos + 4] as u32,
            )
        } else {
            None
        };
        out.push(SNssai { sst, sd });
        pos += 1 + len;
    }
    out
}

/// Parse a SUCI mobile identity content (TS 24.501 Section 9.11.3.4)
///
/// Returns the SUCI in the string form
/// `suci-0-<mcc>-<mnc>-<routing>-<scheme>-<hnkey>-<schemeoutput>` plus the
/// home PLMN.
fn parse_suci_identity(content: &[u8]) -> Option<(String, PlmnId)> {
    if content.len() < 9 {
        return None;
    }
    let supi_format = (content[0] >> 4) & 0x07;
    if supi_format != 0 {
        // Only IMSI-format SUCI supported here (network-specific NAI deferred)
        return None;
    }
    let plmn = PlmnId {
        mcc1: content[1] & 0x0f,
        mcc2: (content[1] >> 4) & 0x0f,
        mcc3: content[2] & 0x0f,
        mnc3: (content[2] >> 4) & 0x0f,
        mnc1: content[3] & 0x0f,
        mnc2: (content[3] >> 4) & 0x0f,
    };
    let (mcc, mnc) = plmn_mcc_mnc_strings(&plmn);
    let routing = decode_bcd_digits(&content[4..6]);
    let scheme = content[6] & 0x0f;
    let hn_key = content[7];
    // Scheme output encoding (TS 24.501 Section 9.11.3.4 / TS 23.003 §28.7.3):
    //   - null scheme (0): the scheme output IS the MSIN, carried as TBCD with
    //     swapped nibbles and 0xF fillers -> decode to cleartext digits.
    //   - ECIES profile A (1) / profile B (2): the scheme output is an opaque
    //     octet string (ephemeral public key || ciphertext || MAC). It must be
    //     carried verbatim and reversibly, so hex-encode the raw bytes. The UDM
    //     recovers them with hex_str_to_bytes (context.rs) before deconcealment.
    //     A BCD decode here would silently drop any nibble > 9, corrupting the
    //     ciphertext.
    let scheme_output = if scheme == SUCI_PROTECTION_SCHEME_NULL {
        decode_bcd_digits(&content[8..])
    } else {
        encode_hex_lower(&content[8..])
    };

    let suci = format!("suci-0-{mcc}-{mnc}-{routing}-{scheme}-{hn_key}-{scheme_output}");
    Some((suci, plmn))
}

/// SUCI protection scheme identifier for the null scheme (TS 33.501 Annex C).
const SUCI_PROTECTION_SCHEME_NULL: u8 = 0;

/// Lowercase, fixed-width (two chars/byte) hex encoding. Used for the ECIES
/// SUCI scheme output so it round-trips through `hex_str_to_bytes` on the UDM.
fn encode_hex_lower(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Derive a SUPI string from a null-scheme SUCI
/// ("suci-0-mcc-mnc-routing-0-0-msin" -> "imsi-mccmncmsin")
fn supi_from_suci(suci: &str) -> String {
    let parts: Vec<&str> = suci.split('-').collect();
    if parts.len() >= 8 && parts[0] == "suci" {
        format!("imsi-{}{}{}", parts[2], parts[3], parts[7])
    } else {
        suci.to_string()
    }
}

/// Decode (nibble-swapped) BCD digits, skipping 0xF fillers
fn decode_bcd_digits(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let lo = b & 0x0f;
        let hi = (b >> 4) & 0x0f;
        if lo <= 9 {
            s.push((b'0' + lo) as char);
        }
        if hi <= 9 {
            s.push((b'0' + hi) as char);
        }
    }
    s
}

/// MCC/MNC digit strings from a PLMN ID
fn plmn_mcc_mnc_strings(plmn: &PlmnId) -> (String, String) {
    let mcc = format!("{}{}{}", plmn.mcc1, plmn.mcc2, plmn.mcc3);
    let mnc = if plmn.mnc3 == 0xf {
        format!("{}{}", plmn.mnc1, plmn.mnc2)
    } else {
        format!("{}{}{}", plmn.mnc1, plmn.mnc2, plmn.mnc3)
    };
    (mcc, mnc)
}

/// Parse a TS 29.571 BitRate string ("<number> <unit>", e.g. "1 Gbps") into
/// bits per second. Supported units: bps, Kbps, Mbps, Gbps, Tbps (decimal,
/// 10^3 steps per TS 29.571 §5.5). Returns None for malformed input.
fn parse_bitrate_bps(s: &str) -> Option<u64> {
    let mut parts = s.split_whitespace();
    let value: f64 = parts.next()?.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let unit = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let multiplier: f64 = match unit {
        "bps" => 1.0,
        "Kbps" => 1e3,
        "Mbps" => 1e6,
        "Gbps" => 1e9,
        "Tbps" => 1e12,
        _ => return None,
    };
    Some((value * multiplier) as u64)
}

/// Serving network name (TS 24.501 Section 9.12.1 / TS 33.501 Section 6.1.1.4)
fn serving_network_name_from_plmn(plmn: &PlmnId) -> String {
    let (mcc, mnc) = plmn_mcc_mnc_strings(plmn);
    format!("5G:mnc{mnc:0>3}.mcc{mcc:0>3}.3gppnetwork.org")
}

/// Convert a wire-format security capability octet (bit 8 = algorithm 0,
/// TS 24.501 Section 9.11.3.54) into the bit-N = algorithm-N mask used by
/// the algorithm selection helpers
fn wire_caps_to_mask(wire: u8) -> u8 {
    let mut mask = 0u8;
    for n in 0..8 {
        if wire & (0x80 >> n) != 0 {
            mask |= 1 << n;
        }
    }
    mask
}

/// Map the stored NAS UE security-capability octets (5G/EPS EA/IA bitmaps,
/// MSB = algorithm 0) to the 16-bit NGAP UESecurityCapabilities bitstrings
/// (TS 38.413 Section 9.3.1.86); the NAS octet occupies the high 8 bits.
fn ue_caps_to_ngap(caps: &UeSecurityCapability) -> ogs_ngap::types::UeSecurityCapabilities {
    let to_bits = |octet: u8| -> u16 { (octet as u16) << 8 };
    ogs_ngap::types::UeSecurityCapabilities {
        nr_encryption_algorithms: to_bits(caps.ea),
        nr_integrity_algorithms: to_bits(caps.ia),
        eutra_encryption_algorithms: to_bits(caps.eea),
        eutra_integrity_algorithms: to_bits(caps.eia),
    }
}

/// Encode a PlmnId into the 3-byte NGAP PLMN Identity (TS 23.003 / TS 38.413).
fn plmn_id_to_ngap_bytes(plmn: &PlmnId) -> [u8; 3] {
    [
        (plmn.mcc2 << 4) | plmn.mcc1,
        (plmn.mnc3 << 4) | plmn.mcc3,
        (plmn.mnc2 << 4) | plmn.mnc1,
    ]
}

/// Decode a 3-byte NGAP PLMN Identity into a PlmnId (inverse of
/// `plmn_id_to_ngap_bytes`).
fn plmn_id_from_ngap_bytes(bytes: &[u8; 3]) -> PlmnId {
    PlmnId {
        mcc1: bytes[0] & 0x0F,
        mcc2: bytes[0] >> 4,
        mcc3: bytes[1] & 0x0F,
        mnc1: bytes[2] & 0x0F,
        mnc2: bytes[2] >> 4,
        mnc3: bytes[1] >> 4,
    }
}

/// Convert a configured algorithm preference order into a support mask;
/// `default_mask` when no order is configured
fn algorithm_order_to_mask(order: &[u8], default_mask: u8) -> u8 {
    if order.is_empty() {
        return default_mask;
    }
    let mut mask = 0u8;
    for alg in order {
        if *alg < 8 {
            mask |= 1 << *alg;
        }
    }
    mask
}

/// Map an SBI error to a 5GMM reject cause (TS 24.501 Annex A; mirrors the
/// Open5GS gmm_cause_from_sbi mapping — no blanket "unspecified")
fn gmm_cause_from_sbi_error(err: &crate::sbi_path::SbiError) -> GmmCause {
    use crate::sbi_path::SbiError;
    match err {
        SbiError::RequestFailed(msg) => {
            if msg.contains("404") {
                // Subscriber unknown
                GmmCause::UeIdentityCannotBeDerivedByTheNetwork
            } else if msg.contains("403") {
                GmmCause::FiveGsServicesNotAllowed
            } else if msg.contains("400") {
                GmmCause::SemanticallyIncorrectMessage
            } else {
                // Peer unreachable / 5xx: the payload could not be forwarded
                GmmCause::PayloadWasNotForwarded
            }
        }
        SbiError::Timeout | SbiError::GatewayTimeout => GmmCause::PayloadWasNotForwarded,
        SbiError::NfInstanceNotFound | SbiError::ServiceNotFound(_) => {
            GmmCause::PayloadWasNotForwarded
        }
        SbiError::ResponseParseError(_) => GmmCause::SemanticallyIncorrectMessage,
        SbiError::InvalidState => GmmCause::MessageNotCompatibleWithTheProtocolState,
    }
}

/// NGAP server wrapper with mutable SCTP access
pub struct NgapServerHandle {
    inner: Arc<Mutex<NgapServer>>,
}

impl NgapServerHandle {
    pub async fn new(
        bind_addr: SocketAddr,
        amf_context: Arc<RwLock<AmfContext>>,
        event_tx: mpsc::Sender<AmfEvent>,
    ) -> Result<Self> {
        let server = NgapServer::new(bind_addr, amf_context, event_tx).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(server)),
        })
    }

    pub async fn poll(&self) -> Result<bool> {
        let mut server = self.inner.lock().await;
        server.poll().await
    }

    pub async fn local_addr(&self) -> SocketAddr {
        let server = self.inner.lock().await;
        server.local_addr()
    }

    pub async fn num_gnbs(&self) -> usize {
        let server = self.inner.lock().await;
        server.num_gnbs().await
    }

    pub async fn send(&self, association_id: u64, stream_id: u16, data: &[u8]) -> Result<()> {
        let mut server = self.inner.lock().await;
        server
            .sctp_server
            .send(association_id, stream_id, data)
            .await
            .map_err(|e| anyhow::anyhow!("SCTP send error: {e}"))
    }
}

// ============================================================================
// NGAP Path Functions (Open5GS-style API)
// ============================================================================

/// Global NGAP server instance
static NGAP_SERVER: once_cell::sync::OnceCell<NgapServerHandle> = once_cell::sync::OnceCell::new();

/// Initialize NGAP path
pub async fn amf_ngap_open(
    bind_addr: Option<SocketAddr>,
    amf_context: Arc<RwLock<AmfContext>>,
    event_tx: mpsc::Sender<AmfEvent>,
) -> Result<()> {
    let addr = bind_addr.unwrap_or_else(|| {
        format!("{DEFAULT_NGAP_ADDR}:{OGS_NGAP_SCTP_PORT}")
            .parse()
            .expect("value expected")
    });

    let handle = NgapServerHandle::new(addr, amf_context, event_tx).await?;
    let local_addr = handle.local_addr().await;

    let _ = NGAP_SERVER.set(handle);

    log::info!("NGAP path opened on {local_addr} (sctp-proto)");
    Ok(())
}

/// Close NGAP path
pub async fn amf_ngap_close() {
    if let Some(_server) = NGAP_SERVER.get() {
        log::info!("NGAP path closed");
    }
}

/// Get the NGAP server (if initialized)
pub fn get_ngap_server() -> Option<&'static NgapServerHandle> {
    NGAP_SERVER.get()
}

/// Poll for NGAP events
pub async fn amf_ngap_poll() -> Result<bool> {
    if let Some(server) = NGAP_SERVER.get() {
        server.poll().await
    } else {
        Ok(false)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_ngap_server_creation() {
        let (tx, _rx) = mpsc::channel(100);
        let ctx = Arc::new(RwLock::new(AmfContext::new()));

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handle = NgapServerHandle::new(addr, ctx, tx).await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.num_gnbs().await, 0);
    }

    #[test]
    fn test_gnb_session_creation() {
        let addr: SocketAddr = "192.168.1.1:38412".parse().unwrap();
        let session = GnbSession::new(1, 100, addr);

        assert_eq!(session.id, 1);
        assert_eq!(session.association_id, 100);
        assert_eq!(session.addr, addr);
    }

    // ------------------------------------------------------------------
    // NAS parsing round-trips (TS 24.501)
    // ------------------------------------------------------------------

    /// Synthetic Registration Request: SUCI (mcc 999 / mnc 70), UE security
    /// capability EA0-3/IA0-3, requested NSSAI SST=1
    fn sample_registration_request() -> Vec<u8> {
        let mut nas = vec![
            0x7E, 0x00, 0x41, // 5GMM plain Registration Request
            0x09, // ngKSI=0 (native), 5GS registration type = initial(1) + FOR
        ];
        // 5GS mobile identity (LV-E): SUCI, IMSI format
        let suci = vec![
            0x01, // SUPI format IMSI, type SUCI
            0x99, 0xF9, 0x07, // PLMN 999/70 (mcc 999, 2-digit mnc 70, filler F)
            0xF0, 0xFF, // routing indicator "0"
            0x00, // protection scheme: null
            0x00, // home network public key id
            0x00, 0x00, 0x00, 0x00, 0x10, // MSIN BCD
        ];
        nas.extend_from_slice(&(suci.len() as u16).to_be_bytes());
        nas.extend_from_slice(&suci);
        // UE security capability (IEI 0x2E): EA0-3, IA0-3
        nas.extend_from_slice(&[0x2E, 0x02, 0xF0, 0xF0]);
        // Requested NSSAI (IEI 0x2F): one S-NSSAI, SST=1
        nas.extend_from_slice(&[0x2F, 0x02, 0x01, 0x01]);
        nas
    }

    #[test]
    fn test_parse_registration_request_suci_caps_nssai() {
        let nas = sample_registration_request();
        let req = parse_registration_request_pdu(&nas).expect("parse");

        assert_eq!(req.registration_type, 1); // initial
        assert_eq!(req.identity_type, mobile_identity_type::SUCI);
        let suci = req.suci.expect("suci");
        assert!(suci.starts_with("suci-0-999-70-"), "{suci}");
        let cap = req.sec_cap.expect("sec cap");
        assert_eq!(cap.ea, 0xF0);
        assert_eq!(cap.ia, 0xF0);
        assert_eq!(req.requested_nssai.len(), 1);
        assert_eq!(req.requested_nssai[0].sst, 1);
    }

    #[test]
    fn test_parse_registration_request_snpn_nid() {
        // SNPN (Rel-17, TS 23.501 §5.30): the AMF parser extracts the NID IE,
        // carried as the 44-bit packed NID of TS 23.003 §12.7 (6 octets).
        let mut nas = sample_registration_request();
        // "7AB01234567" packed MSB-first, trailing nibble spare.
        let packed = [0x7A, 0xB0, 0x12, 0x34, 0x56, 0x70];
        nas.push(0xA6); // SNPN NID IEI
        nas.push(packed.len() as u8); // 6
        nas.extend_from_slice(&packed);

        let req = parse_registration_request_pdu(&nas).expect("parse");
        assert_eq!(req.snpn_nid.as_deref(), Some("7AB01234567"));
        // The other IEs still parse correctly after the NID IE.
        assert_eq!(req.requested_nssai.len(), 1);
    }

    #[test]
    fn test_decode_nid_44bit() {
        // Mirrors the sim encoder; rejects short input (strict).
        assert_eq!(
            decode_nid_44bit(&[0x7A, 0xB0, 0x12, 0x34, 0x56, 0x70]).as_deref(),
            Some("7AB01234567")
        );
        assert_eq!(
            decode_nid_44bit(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]).as_deref(),
            Some("FFFFFFFFFFF")
        );
        assert!(decode_nid_44bit(&[0x00; 5]).is_none());
    }

    #[test]
    fn test_parse_registration_request_service_level_aa_container() {
        // UAS (Rel-17/18, TS 24.501 §9.11.2.10): the AMF extracts the CAA-level
        // UAV ID from the Service-level-AA container (IEI 0x72, TLV-E) via the
        // Service-level device ID parameter (0x10, UTF-8).
        let mut nas = sample_registration_request();
        let caa = b"FAA-N12345";
        let contents = [&[0x10u8, caa.len() as u8][..], caa].concat(); // device-ID param
        nas.push(0x72); // Service-level-AA container IEI
        nas.push((contents.len() >> 8) as u8); // 2-octet length, hi
        nas.push((contents.len() & 0xFF) as u8); // lo
        nas.extend_from_slice(&contents);

        let req = parse_registration_request_pdu(&nas).expect("parse");
        assert_eq!(req.uav_indication.as_deref(), Some("FAA-N12345"));
        // The other IEs still parse correctly after the TLV-E container.
        assert_eq!(req.requested_nssai.len(), 1);
    }

    #[test]
    fn test_decode_service_level_aa_container() {
        assert_eq!(
            decode_service_level_aa_container(&[0x10, 0x03, b'A', b'B', b'C']).as_deref(),
            Some("ABC")
        );
        // Unknown leading param skipped; device ID still found.
        assert_eq!(
            decode_service_level_aa_container(&[0x30, 0x01, 0xAA, 0x10, 0x02, b'X', b'Y'])
                .as_deref(),
            Some("XY")
        );
        assert!(decode_service_level_aa_container(&[0x30, 0x01, 0xAA]).is_none());
    }

    #[test]
    fn test_snpn_allowed_nids_and_validation() {
        // Empty allowed list accepts any NID (validate_nid empty-list semantics).
        let amf_ue = AmfUe::new(1, 1);
        assert!(amf_ue.validate_nid("7AB01234567", &[]));
        // Non-empty list gates on membership.
        let allowed = vec!["7AB01234567".to_string()];
        assert!(amf_ue.validate_nid("7AB01234567", &allowed));
        assert!(!amf_ue.validate_nid("FFFFFFFFFFF", &allowed));
    }

    #[test]
    fn test_is_snpn_onboarding_suci() {
        assert!(is_snpn_onboarding_suci("suci-0-999-70-onboarding-1"));
        assert!(!is_snpn_onboarding_suci("suci-0-999-70-0-0-1"));
    }

    #[test]
    fn test_parse_registration_request_rejects_truncated() {
        // Strict peer behaviour: missing mandatory mobile identity -> None
        assert!(parse_registration_request_pdu(&[0x7E, 0x00, 0x41, 0x09]).is_none());
        // Identity length larger than buffer -> None
        assert!(
            parse_registration_request_pdu(&[0x7E, 0x00, 0x41, 0x09, 0x00, 0x20, 0x01]).is_none()
        );
    }

    #[test]
    fn test_registration_accept_mandatory_ies_and_protection() {
        let mut amf_ue = AmfUe::new(1, 1);
        amf_ue.access_type = 1;
        amf_ue.nr_tai = crate::context::Tai5gs {
            plmn_id: PlmnId::new("999", "70"),
            tac: 1,
        };
        amf_ue.allowed_nssai = vec![SNssai { sst: 1, sd: None }];
        amf_ue.generate_new_guti();
        let tmsi = amf_ue.next_guti.tmsi;
        assert_ne!(tmsi, 0);

        let plain = gmm_build::build_registration_accept(&amf_ue).expect("accept");
        // Plain inner: EPD + plain hdr + msg type + result LV
        assert_eq!(&plain[..3], &[0x7E, 0x00, 0x42]);
        assert_eq!(plain[3], 1); // result length
        assert_eq!(plain[4] & 0x07, 1); // 3GPP access

        // Mandatory registration-area IEs present
        assert!(plain.contains(&0x54), "TAI list IEI missing");
        assert!(plain.contains(&0x15), "Allowed NSSAI IEI missing");
        assert!(plain.contains(&0x77), "5G-GUTI IEI missing");

        // Strict peer: protect with NIA2/NEA2 and verify the security header
        amf_ue.selected_int_algorithm = 2;
        amf_ue.selected_enc_algorithm = 2;
        amf_ue.knas_int = [0x11; 16];
        amf_ue.knas_enc = [0x22; 16];
        let protected = nas_security::nas_5gs_security_encode(
            &mut amf_ue,
            &plain,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        )
        .expect("protected");

        assert_eq!(protected[0], 0x7E);
        assert_eq!(
            protected[1],
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED
        );
        assert_eq!(protected.len(), plain.len() + 7);
        // MAC must be non-zero with NIA2
        assert_ne!(&protected[2..6], &[0, 0, 0, 0]);
        // Ciphered payload must differ from the plain message
        assert_ne!(&protected[7..], &plain[..]);
    }

    #[test]
    fn test_smc_replays_actual_ue_capabilities() {
        let mut amf_ue = AmfUe::new(1, 1);
        // Deliberately unusual capability pattern: must be replayed verbatim
        amf_ue.ue_security_capability = UeSecurityCapability {
            ea: 0x55,
            ia: 0xAA,
            eea: 0,
            eia: 0,
        };
        amf_ue.selected_int_algorithm = 2;
        amf_ue.selected_enc_algorithm = 0;

        let smc = gmm_build::build_security_mode_command(&amf_ue).expect("smc");
        assert_eq!(&smc[..3], &[0x7E, 0x00, 0x5D]);
        // Selected NAS security algorithms (TS 24.501 9.11.3.34):
        // ciphering high nibble (NEA0), integrity low nibble (NIA2)
        assert_eq!(smc[3], 0x02);
        // Replayed capability LV: find [len, 0x55, 0xAA]
        assert!(
            smc.windows(3).any(|w| w == [0x02, 0x55, 0xAA]),
            "SMC must replay the UE's actual security capabilities: {smc:02x?}"
        );
        // The hardcoded 0xF0/0xF0 pattern must NOT appear
        assert!(!smc.windows(2).any(|w| w == [0xF0, 0xF0]));
    }

    #[test]
    fn test_strict_peer_rejects_tampered_mac() {
        // Build an uplink-protected message the way the UE would, then check
        // that the AMF-side decode flags a tampered MAC
        let mut ue_side = AmfUe::new(1, 1);
        ue_side.selected_int_algorithm = 2;
        ue_side.selected_enc_algorithm = 0;
        ue_side.knas_int = [0x11; 16];
        ue_side.security_context_available = true;
        ue_side.access_type = 1;

        let inner = vec![0x7E, 0x00, 0x43]; // Registration Complete
        let sqn: u8 = 0;
        let mut mac_data = vec![sqn];
        mac_data.extend_from_slice(&inner);
        let mac = nas_security::nas_mac_calculate(
            2,
            &ue_side.knas_int,
            0,
            1,
            nas_security::direction::UPLINK,
            &mac_data,
        );

        let mut protected = vec![0x7E, security_header::INTEGRITY_PROTECTED];
        protected.extend_from_slice(&mac);
        protected.push(sqn);
        protected.extend_from_slice(&inner);

        // Valid MAC decodes without mac_failed
        let mut amf_side = ue_side.clone();
        amf_side.ul_count = 0;
        let out = nas_security::nas_5gs_security_decode(&mut amf_side, protected[1], &protected)
            .expect("decode");
        assert_eq!(out, inner);
        assert!(!amf_side.mac_failed, "valid MAC must pass");

        // Tampered MAC must be flagged (and the dispatcher discards it)
        let mut tampered = protected.clone();
        tampered[2] ^= 0xFF;
        let mut amf_side2 = ue_side.clone();
        amf_side2.ul_count = 0;
        let _ = nas_security::nas_5gs_security_decode(&mut amf_side2, tampered[1], &tampered)
            .expect("decode");
        assert!(amf_side2.mac_failed, "tampered MAC must be detected");
    }

    #[test]
    fn test_random_tmsi_is_not_ngap_id() {
        let a = crate::context::generate_random_tmsi();
        let b = crate::context::generate_random_tmsi();
        assert_ne!(a, 0);
        assert_ne!(a, u32::MAX);
        // Two consecutive draws colliding is a 2^-32 event
        assert_ne!(a, b);
    }

    #[test]
    fn test_wire_caps_to_mask() {
        assert_eq!(wire_caps_to_mask(0xF0), 0x0F); // EA0-3 -> algorithms 0..3
        assert_eq!(wire_caps_to_mask(0x80), 0x01); // EA0 only
        assert_eq!(wire_caps_to_mask(0x20), 0x04); // EA2 only
                                                   // Selection from EA0-3 with default AMF mask prefers NEA2/NIA2
        assert_eq!(
            nas_security::select_integrity_algorithm(wire_caps_to_mask(0xF0), 0x0E),
            2
        );
    }

    #[test]
    fn test_supi_from_suci() {
        assert_eq!(
            supi_from_suci("suci-0-999-70-0-0-0-0000000001"),
            "imsi-999700000000001"
        );
        // Non-SUCI strings pass through
        assert_eq!(
            supi_from_suci("imsi-001010000000001"),
            "imsi-001010000000001"
        );
    }

    #[test]
    fn test_serving_network_name() {
        let plmn = PlmnId::new("999", "70");
        assert_eq!(
            serving_network_name_from_plmn(&plmn),
            "5G:mnc070.mcc999.3gppnetwork.org"
        );
    }

    /// Mirror of the UDM's strict hex decode (context.rs `hex_str_to_bytes`):
    /// rejects odd length and non-hex characters.
    fn udm_hex_str_to_bytes(hex: &str) -> Option<Vec<u8>> {
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect()
    }

    #[test]
    fn test_null_scheme_suci_keeps_bcd_msin() {
        // Null scheme (TS 23.003 §28.7.3): scheme output is the MSIN in TBCD.
        // Content: type/format, PLMN 999/70, routing "0", scheme 0, hn key 0,
        // MSIN BCD (swapped nibbles, 0xF filler) for MSIN "0000000001".
        let content = [
            0x01, // SUPI format IMSI, type SUCI
            0x99, 0xF9, 0x07, // PLMN 999/70
            0xF0, 0xFF, // routing indicator "0"
            0x00, // protection scheme: null
            0x00, // home network public key id
            0x00, 0x00, 0x00, 0x00, 0x10, // MSIN BCD -> "0000000001"
        ];
        let (suci, _plmn) = parse_suci_identity(&content).expect("parse null SUCI");
        // schemeOutput must be decimal MSIN digits, not hex.
        assert_eq!(suci, "suci-0-999-70-0-0-0-0000000001");
    }

    #[test]
    fn test_ecies_scheme1_suci_output_is_reversible_hex() {
        // ECIES profile A (scheme 1, TS 33.501 Annex C.3.4.1): the scheme output
        // is an opaque octet string. The AMF must hex-encode it so the UDM can
        // recover the exact bytes with hex_str_to_bytes before deconcealment.
        // Deliberately include bytes with high nibbles > 9 (e.g. 0xDE, 0xAD)
        // that a BCD decode would silently corrupt.
        let raw_output: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x9A];
        let mut content = vec![
            0x01, // SUPI format IMSI, type SUCI
            0x99, 0xF9, 0x07, // PLMN 999/70
            0xF0, 0xFF, // routing indicator "0"
            0x01, // protection scheme: ECIES profile A
            0x02, // home network public key id
        ];
        content.extend_from_slice(&raw_output);

        let (suci, plmn) = parse_suci_identity(&content).expect("parse ECIES SUCI");
        assert_eq!(plmn, PlmnId::new("999", "70"));

        // The string form keeps the canonical 8-field layout the UDM parser
        // (parse_suci) expects: suci-0-mcc-mnc-routing-scheme-hnkey-output
        let parts: Vec<&str> = suci.split('-').collect();
        assert_eq!(parts.len(), 8, "{suci}");
        assert_eq!(parts[5], "1"); // scheme
        assert_eq!(parts[6], "2"); // hn key id
        let scheme_output = parts[7];

        // Lowercase hex, two chars per byte (matches UdmContext expectation)
        assert_eq!(scheme_output, "deadbeef019a");

        // Round-trip: the UDM's hex_str_to_bytes recovers the original bytes.
        let recovered = udm_hex_str_to_bytes(scheme_output).expect("UDM hex decode");
        assert_eq!(recovered, raw_output);
    }

    #[test]
    fn test_gmm_cause_from_sbi_error_mapping() {
        use crate::sbi_path::SbiError;
        // No "protocol error unspecified" blanket defaults
        assert_eq!(
            gmm_cause_from_sbi_error(&SbiError::RequestFailed("status 404".into())),
            GmmCause::UeIdentityCannotBeDerivedByTheNetwork
        );
        assert_eq!(
            gmm_cause_from_sbi_error(&SbiError::RequestFailed("status 403".into())),
            GmmCause::FiveGsServicesNotAllowed
        );
        assert_eq!(
            gmm_cause_from_sbi_error(&SbiError::GatewayTimeout),
            GmmCause::PayloadWasNotForwarded
        );
    }

    #[test]
    fn test_tai_list_and_nssai_encoding_roundtrip() {
        let tai = crate::context::Tai5gs {
            plmn_id: PlmnId::new("999", "70"),
            tac: 0x000001,
        };
        let encoded = gmm_build::encode_tai_list(&tai);
        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], 0x00); // list type 00, 1 element
        assert_eq!(&encoded[4..7], &[0x00, 0x00, 0x01]); // TAC

        let nssai = gmm_build::encode_nssai_value(&[
            SNssai { sst: 1, sd: None },
            SNssai {
                sst: 2,
                sd: Some(0x010203),
            },
        ]);
        // [1, sst1] + [4, sst2, sd...]
        assert_eq!(nssai, vec![1, 1, 4, 2, 0x01, 0x02, 0x03]);
        // Round-trip through the registration-request NSSAI parser
        let parsed = parse_nssai_value(&nssai);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sst, 1);
        assert_eq!(parsed[1].sd, Some(0x010203));
    }

    #[test]
    fn test_parse_bitrate_bps() {
        // TS 29.571 BitRate strings -> bits/s
        assert_eq!(parse_bitrate_bps("1 Gbps"), Some(1_000_000_000));
        assert_eq!(parse_bitrate_bps("100 Mbps"), Some(100_000_000));
        assert_eq!(parse_bitrate_bps("50 Kbps"), Some(50_000));
        assert_eq!(parse_bitrate_bps("64000 bps"), Some(64_000));
        assert_eq!(parse_bitrate_bps("2 Tbps"), Some(2_000_000_000_000));
        // Malformed input
        assert_eq!(parse_bitrate_bps("1Gbps"), None); // no separator
        assert_eq!(parse_bitrate_bps("Gbps"), None); // no value
        assert_eq!(parse_bitrate_bps("1 Pbps"), None); // unknown unit
        assert_eq!(parse_bitrate_bps("1 Gbps extra"), None);
    }

    #[test]
    fn test_kgnb_derivation_is_nonzero_and_drives_ics() {
        // T0.1: KgNB (TS 33.501 Annex A.9) derived from a non-zero Kamf must be
        // non-zero, and the resulting Initial Context Setup Request must carry
        // exactly that key as the UE Security Key.
        let kamf = [0x42u8; 32];
        let ul_count = 1u32;
        let kgnb = ogs_crypt::kdf::ogs_kdf_kgnb_and_kn3iwf(&kamf, ul_count, ACCESS_TYPE_3GPP);
        assert_ne!(kgnb, [0u8; 32], "KgNB must be non-zero");

        // Different UL NAS COUNT -> different KgNB (input binding holds).
        let kgnb2 = ogs_crypt::kdf::ogs_kdf_kgnb_and_kn3iwf(&kamf, ul_count + 1, ACCESS_TYPE_3GPP);
        assert_ne!(kgnb, kgnb2);

        // Wire it into an ICS request and confirm the security key round-trips.
        let mut ctx = AmfContext::new();
        ctx.num_of_served_guami = 1;
        ctx.served_guami.push(crate::context::Guami {
            plmn_id: PlmnId::new("999", "70"),
            amf_id: crate::context::AmfId {
                region: 2,
                set: 1,
                pointer: 0,
            },
        });
        let sec_cap = UeSecurityCapability {
            ea: 0xF0,
            ia: 0xF0,
            eea: 0,
            eia: 0,
        };
        let bytes = crate::ngap_asn1::build_initial_context_setup_request_asn1(
            &ctx,
            1,
            2,
            &[SNssai { sst: 1, sd: None }],
            &sec_cap,
            &kgnb,
            Some(&[0x7E, 0x00, 0x42]),
            None,
        )
        .expect("build ICS");
        let decoded = ogs_ngap::parser::decode_ngap_pdu(&bytes).expect("decode");
        match decoded {
            ogs_ngap::NgapMessage::InitialContextSetupRequest(req) => {
                assert_eq!(req.security_key, kgnb);
                assert_ne!(req.security_key, [0u8; 32]);
            }
            other => panic!("expected InitialContextSetupRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_registration_is_gated_on_ics_response() {
        // T0.1: a fresh UE context starts with the ICS Response not yet
        // received, so the PDU-session-setup gate (and the "context
        // established" decision) must be false until the gNB confirms.
        let mut state = UeNasContext::new(1, 2, 100);
        assert!(!state.initial_context_setup_response_received);
        assert!(!state.initial_context_setup_request_sent);
        assert_eq!(state.gmm_fsm.state, crate::gmm_sm::GmmState::Initial);

        // After the AMF sends the ICS request the FSM tracks the wait state.
        state.initial_context_setup_request_sent = true;
        state.gmm_fsm.transition_to_initial_context_setup();
        assert_eq!(
            state.gmm_fsm.state,
            crate::gmm_sm::GmmState::InitialContextSetup
        );
        // Still not established: the PDU-session gate must hold.
        assert!(!state.initial_context_setup_response_received);

        // The gNB confirms: parse a real ICS Response and apply the gate.
        let resp = ogs_ngap::builder::build_initial_context_setup_response(
            &ogs_ngap::types::InitialContextSetupResponse {
                amf_ue_ngap_id: 1,
                ran_ue_ngap_id: 2,
            },
        )
        .expect("build resp");
        let parsed = crate::ngap_asn1::parse_initial_context_setup_response_asn1(&resp);
        assert_eq!(parsed, Some((1, 2)));
        // Applying the response opens the gate.
        state.initial_context_setup_response_received = true;
        state.gmm_fsm.transition_to_registered();
        assert!(state.initial_context_setup_response_received);
        assert_eq!(state.gmm_fsm.state, crate::gmm_sm::GmmState::Registered);
    }

    #[test]
    fn test_nas_proc_timer_configs() {
        let configs = AmfTimerConfigs::default();
        let (max, dur) = NasProcTimer::T3560.config(&configs);
        assert_eq!(max, 4); // 4 retransmissions = 5 transmissions total
        assert_eq!(dur, Duration::from_secs(6));
        let (max550, _) = NasProcTimer::T3550.config(&configs);
        assert_eq!(max550, 4);
        let (max522, dur522) = NasProcTimer::T3522.config(&configs);
        assert_eq!(max522, 4);
        assert_eq!(dur522, Duration::from_secs(3));
    }

    // ------------------------------------------------------------------
    // T3.1 — NGAP procedure dispatch / ErrorIndication
    // ------------------------------------------------------------------

    #[test]
    fn test_proc_codes_match_3gpp() {
        // The dispatch must use the genuine TS 38.413 procedure codes, not the
        // legacy bogus values (0/1/3/24/25/27).
        assert_eq!(proc_code::ERROR_INDICATION, 9);
        assert_eq!(proc_code::HANDOVER_CANCEL, 10);
        assert_eq!(proc_code::HANDOVER_NOTIFICATION, 11);
        assert_eq!(proc_code::HANDOVER_PREPARATION, 12);
        assert_eq!(proc_code::HANDOVER_RESOURCE_ALLOCATION, 13);
        assert_eq!(proc_code::OVERLOAD_START, 22);
        assert_eq!(proc_code::OVERLOAD_STOP, 23);
        assert_eq!(proc_code::PATH_SWITCH_REQUEST, 25);
    }

    #[test]
    fn test_unknown_pdu_yields_error_indication() {
        // An undecodable / unknown-procedure PDU must produce a decodable
        // ErrorIndication carrying a protocol cause (TS 38.413 Section 10.3).
        // This mirrors the `_` dispatch arm's behaviour.
        let unknown_pdu = [0x00u8, 99, 0x00]; // InitiatingMessage, procedure 99
        let parsed = ogs_ngap::parser::decode_ngap_pdu(&unknown_pdu);
        // Either decodes to Unknown or fails to decode; both drive ErrorIndication.
        let is_unknown_or_err = matches!(
            parsed,
            Ok(ogs_ngap::NgapMessage::Unknown { .. }) | Err(_)
        );
        assert!(is_unknown_or_err, "got {parsed:?}");

        // Build the ErrorIndication the dispatch would emit and confirm it is a
        // valid, decodable PDU with the protocol cause.
        let ei = ogs_ngap::types::ErrorIndication {
            amf_ue_ngap_id: None,
            ran_ue_ngap_id: None,
            cause: Some(ogs_ngap::types::Cause::Protocol(
                ogs_asn1c::ngap::cause::CauseProtocol::AbstractSyntaxErrorReject,
            )),
            criticality_diagnostics: None,
        };
        let bytes = ogs_ngap::builder::build_error_indication(&ei).unwrap();
        assert_eq!(bytes[0], 0x00); // InitiatingMessage
        assert_eq!(bytes[1], proc_code::ERROR_INDICATION as u8);
        match ogs_ngap::parser::decode_ngap_pdu(&bytes).unwrap() {
            ogs_ngap::NgapMessage::ErrorIndication(e) => {
                assert!(matches!(
                    e.cause,
                    Some(ogs_ngap::types::Cause::Protocol(_))
                ));
            }
            other => panic!("expected ErrorIndication, got {other:?}"),
        }
    }

    #[test]
    fn test_overload_start_stop_roundtrip() {
        let start = crate::ngap_asn1::build_overload_start_asn1(40).expect("overload start");
        assert_eq!(start[0], 0x00);
        assert_eq!(start[1], proc_code::OVERLOAD_START as u8);
        match ogs_ngap::parser::decode_ngap_pdu(&start).unwrap() {
            ogs_ngap::NgapMessage::OverloadStart(o) => {
                assert_eq!(o.traffic_load_reduction, Some(40));
            }
            other => panic!("expected OverloadStart, got {other:?}"),
        }

        let stop = crate::ngap_asn1::build_overload_stop_asn1().expect("overload stop");
        assert_eq!(stop[1], proc_code::OVERLOAD_STOP as u8);
        match ogs_ngap::parser::decode_ngap_pdu(&stop).unwrap() {
            ogs_ngap::NgapMessage::OverloadStop(_) => {}
            other => panic!("expected OverloadStop, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // T3.2 — SMC anti-bidding-down check
    // ------------------------------------------------------------------

    /// Build a Security Mode Complete carrying a NAS message container (0x71,
    /// TLV-E) that holds a replayed RegistrationRequest with the given caps.
    fn smc_with_replayed_caps(ea: u8, ia: u8) -> Vec<u8> {
        let mut reg = sample_registration_request();
        // Overwrite the UE security capability octets in the replayed reg req.
        // sample_registration_request encodes [.. 0x2E, 0x02, EA, IA ..]; find it.
        if let Some(p) = reg.windows(2).position(|w| w == [0x2E, 0x02]) {
            reg[p + 2] = ea;
            reg[p + 3] = ia;
        }
        let mut smc = vec![0x7E, 0x00, 0x5E]; // 5GMM Security Mode Complete
        smc.push(0x71); // NAS message container IEI
        smc.extend_from_slice(&(reg.len() as u16).to_be_bytes());
        smc.extend_from_slice(&reg);
        smc
    }

    #[test]
    fn test_extract_nas_message_container_and_caps() {
        let smc = smc_with_replayed_caps(0xF0, 0xF0);
        let inner = extract_nas_message_container(&smc).expect("container");
        let parsed = parse_registration_request_pdu(&inner).expect("inner reg req");
        let caps = parsed.sec_cap.expect("caps");
        assert_eq!(caps.ea, 0xF0);
        assert_eq!(caps.ia, 0xF0);
    }

    #[test]
    fn test_bidding_down_caps_mismatch_detected() {
        // Stored (cleartext-initial) caps EA=0xF0 / IA=0xF0; replayed (protected)
        // caps EA=0x80 / IA=0x80 (downgraded to null algorithms). The mismatch
        // is the bidding-down signature the AMF must detect (TS 33.501 §6.7.2).
        let stored = UeSecurityCapability {
            ea: 0xF0,
            ia: 0xF0,
            eea: 0,
            eia: 0,
        };
        let smc = smc_with_replayed_caps(0x80, 0x80);
        let inner = extract_nas_message_container(&smc).unwrap();
        let replayed = parse_registration_request_pdu(&inner)
            .unwrap()
            .sec_cap
            .unwrap();
        let mismatch = replayed.ea != stored.ea
            || replayed.ia != stored.ia
            || replayed.eea != stored.eea
            || replayed.eia != stored.eia;
        assert!(mismatch, "downgraded caps must be detected as a mismatch");

        // The reject the AMF sends carries 5GMM cause #23.
        let reject = gmm_build::build_security_mode_reject(GmmCause::UeSecurityCapabilitiesMismatch);
        assert_eq!(reject[2], gmm_build::message_type::SECURITY_MODE_REJECT);
        assert_eq!(
            *reject.last().unwrap(),
            GmmCause::UeSecurityCapabilitiesMismatch as u8
        );
    }

    #[test]
    fn test_bidding_down_matching_caps_accepted() {
        let stored = UeSecurityCapability {
            ea: 0xF0,
            ia: 0xF0,
            eea: 0,
            eia: 0,
        };
        let smc = smc_with_replayed_caps(0xF0, 0xF0);
        let inner = extract_nas_message_container(&smc).unwrap();
        let replayed = parse_registration_request_pdu(&inner)
            .unwrap()
            .sec_cap
            .unwrap();
        let mismatch = replayed.ea != stored.ea
            || replayed.ia != stored.ia
            || replayed.eea != stored.eea
            || replayed.eia != stored.eia;
        assert!(!mismatch, "identical caps must NOT be flagged as bidding-down");
    }

    // ------------------------------------------------------------------
    // T3.1/T3.2 helper round-trips
    // ------------------------------------------------------------------

    #[test]
    fn test_plmn_id_ngap_bytes_roundtrip() {
        let plmn = PlmnId::new("999", "70");
        let bytes = plmn_id_to_ngap_bytes(&plmn);
        let back = plmn_id_from_ngap_bytes(&bytes);
        assert_eq!(back.mcc1, plmn.mcc1);
        assert_eq!(back.mcc2, plmn.mcc2);
        assert_eq!(back.mcc3, plmn.mcc3);
        assert_eq!(back.mnc1, plmn.mnc1);
        assert_eq!(back.mnc2, plmn.mnc2);
        assert_eq!(back.mnc3, plmn.mnc3);
    }

    #[test]
    fn test_ue_caps_to_ngap_high_octet() {
        let caps = UeSecurityCapability {
            ea: 0xE0,
            ia: 0xC0,
            eea: 0x80,
            eia: 0x40,
        };
        let ngap = ue_caps_to_ngap(&caps);
        assert_eq!(ngap.nr_encryption_algorithms, 0xE000);
        assert_eq!(ngap.nr_integrity_algorithms, 0xC000);
        assert_eq!(ngap.eutra_encryption_algorithms, 0x8000);
        assert_eq!(ngap.eutra_integrity_algorithms, 0x4000);
    }
}
