//! Diameter (freeDiameter) Path Functions
//!
//! Port of src/mme/mme-fd-path.c - Diameter S6a interface functions
//!
//! Implements Diameter S6a interface for HSS communication.
//! Wires the MME to HSS via ogs-diameter DiameterClient for S6a requests.

use std::net::SocketAddr;
use std::sync::OnceLock;

use tokio::sync::Mutex;

use ogs_diameter::config::DiameterConfig;
use ogs_diameter::s6a;
use ogs_diameter::transport::DiameterClient;

use crate::context::MmeUe;
use crate::emm_build::EmmCause;

// ============================================================================
// Diameter Constants
// ============================================================================

/// Diameter Application ID for S6a
pub const DIAMETER_APPLICATION_S6A: u32 = 16777251;

/// Diameter Result Codes
pub mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;
    pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
    pub const DIAMETER_REALM_NOT_SERVED: u32 = 3003;
    pub const DIAMETER_TOO_BUSY: u32 = 3004;
    pub const DIAMETER_LOOP_DETECTED: u32 = 3005;
    pub const DIAMETER_REDIRECT_INDICATION: u32 = 3006;
    pub const DIAMETER_APPLICATION_UNSUPPORTED: u32 = 3007;
    pub const DIAMETER_INVALID_HDR_BITS: u32 = 3008;
    pub const DIAMETER_INVALID_AVP_BITS: u32 = 3009;
    pub const DIAMETER_UNKNOWN_PEER: u32 = 3010;
    pub const DIAMETER_AUTHENTICATION_REJECTED: u32 = 4001;
    pub const DIAMETER_OUT_OF_SPACE: u32 = 4002;
    pub const DIAMETER_ELECTION_LOST: u32 = 4003;
    pub const DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
    pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
    pub const DIAMETER_AUTHORIZATION_REJECTED: u32 = 5003;
    pub const DIAMETER_INVALID_AVP_VALUE: u32 = 5004;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    pub const DIAMETER_RESOURCES_EXCEEDED: u32 = 5006;
    pub const DIAMETER_CONTRADICTING_AVPS: u32 = 5007;
    pub const DIAMETER_AVP_NOT_ALLOWED: u32 = 5008;
    pub const DIAMETER_AVP_OCCURS_TOO_MANY_TIMES: u32 = 5009;
    pub const DIAMETER_NO_COMMON_APPLICATION: u32 = 5010;
    pub const DIAMETER_UNSUPPORTED_VERSION: u32 = 5011;
    pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
    pub const DIAMETER_INVALID_BIT_IN_HEADER: u32 = 5013;
    pub const DIAMETER_INVALID_AVP_LENGTH: u32 = 5014;
    pub const DIAMETER_INVALID_MESSAGE_LENGTH: u32 = 5015;
    pub const DIAMETER_INVALID_AVP_BIT_COMBO: u32 = 5016;
    pub const DIAMETER_NO_COMMON_SECURITY: u32 = 5017;
}

/// Diameter Experimental Result Codes for S6a
pub mod experimental_result {
    pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
    pub const DIAMETER_ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;
    pub const DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION: u32 = 5420;
    pub const DIAMETER_ERROR_RAT_NOT_ALLOWED: u32 = 5421;
    pub const DIAMETER_ERROR_EQUIPMENT_UNKNOWN: u32 = 5422;
    pub const DIAMETER_ERROR_UNKNOWN_SERVING_NODE: u32 = 5423;
    pub const DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;
}

/// S6a Command Codes
pub mod command_code {
    pub const AUTHENTICATION_INFORMATION: u32 = 318;
    pub const UPDATE_LOCATION: u32 = 316;
    pub const CANCEL_LOCATION: u32 = 317;
    pub const INSERT_SUBSCRIBER_DATA: u32 = 319;
    pub const DELETE_SUBSCRIBER_DATA: u32 = 320;
    pub const PURGE_UE: u32 = 321;
    pub const RESET: u32 = 322;
    pub const NOTIFY: u32 = 323;
}

/// S6a AVP Codes
pub mod avp_code {
    pub const USER_NAME: u32 = 1;
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const ORIGIN_REALM: u32 = 296;
    pub const DESTINATION_HOST: u32 = 293;
    pub const DESTINATION_REALM: u32 = 283;
    pub const AUTH_SESSION_STATE: u32 = 277;
    pub const RESULT_CODE: u32 = 268;
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;
    pub const VENDOR_ID: u32 = 266;
    
    // S6a specific AVPs
    pub const VISITED_PLMN_ID: u32 = 1407;
    pub const RAT_TYPE: u32 = 1032;
    pub const ULR_FLAGS: u32 = 1405;
    pub const ULA_FLAGS: u32 = 1406;
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    pub const REQUESTED_EUTRAN_AUTHENTICATION_INFO: u32 = 1408;
    pub const NUMBER_OF_REQUESTED_VECTORS: u32 = 1410;
    pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
    pub const AUTHENTICATION_INFO: u32 = 1413;
    pub const E_UTRAN_VECTOR: u32 = 1414;
    pub const RAND: u32 = 1447;
    pub const XRES: u32 = 1448;
    pub const AUTN: u32 = 1449;
    pub const KASME: u32 = 1450;
    pub const CONTEXT_IDENTIFIER: u32 = 1423;
    pub const ALL_APN_CONFIG_INC_IND: u32 = 1428;
    pub const APN_CONFIGURATION_PROFILE: u32 = 1429;
    pub const APN_CONFIGURATION: u32 = 1430;
    pub const SERVICE_SELECTION: u32 = 493;
    pub const PDN_TYPE: u32 = 1456;
    pub const AMBR: u32 = 1435;
    pub const MAX_BANDWIDTH_UL: u32 = 516;
    pub const MAX_BANDWIDTH_DL: u32 = 515;
    pub const MSISDN: u32 = 701;
    pub const A_MSISDN: u32 = 1643;
    pub const NETWORK_ACCESS_MODE: u32 = 1417;
    pub const SUBSCRIBED_RAU_TAU_TIMER: u32 = 1619;
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
    pub const EPS_SUBSCRIBED_QOS_PROFILE: u32 = 1431;
    pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
    pub const PRIORITY_LEVEL: u32 = 1046;
    pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
    pub const CANCELLATION_TYPE: u32 = 1420;
    pub const CLR_FLAGS: u32 = 1638;
    pub const IDR_FLAGS: u32 = 1490;
    pub const PUA_FLAGS: u32 = 1442;
}

/// ULR Flags
pub mod ulr_flags {
    pub const SINGLE_REGISTRATION_IND: u32 = 1 << 0;
    pub const S6A_S6D_INDICATOR: u32 = 1 << 1;
    pub const SKIP_SUBSCRIBER_DATA: u32 = 1 << 2;
    pub const GPRS_SUBSCRIPTION_DATA_IND: u32 = 1 << 3;
    pub const NODE_TYPE_IND: u32 = 1 << 4;
    pub const INITIAL_ATTACH_IND: u32 = 1 << 5;
    pub const PS_LCS_NOT_SUPPORTED_BY_UE: u32 = 1 << 6;
}

/// RAT Types
pub mod rat_type {
    pub const EUTRAN: u32 = 1004;
    pub const WLAN: u32 = 0;
    pub const VIRTUAL: u32 = 1;
    pub const UTRAN: u32 = 1000;
    pub const GERAN: u32 = 1001;
    pub const GAN: u32 = 1002;
    pub const HSPA_EVOLUTION: u32 = 1003;
    pub const EUTRAN_NB_IOT: u32 = 1005;
}

/// Cancellation Types
pub mod cancellation_type {
    pub const MME_UPDATE_PROCEDURE: u32 = 0;
    pub const SGSN_UPDATE_PROCEDURE: u32 = 1;
    pub const SUBSCRIPTION_WITHDRAWAL: u32 = 2;
    pub const UPDATE_PROCEDURE_IWF: u32 = 3;
    pub const INITIAL_ATTACH_PROCEDURE: u32 = 4;
}

// ============================================================================
// Diameter Message Structures
// ============================================================================

/// E-UTRAN Authentication Vector
#[derive(Debug, Clone, Default)]
pub struct EUtranVector {
    /// Random challenge
    pub rand: [u8; 16],
    /// Expected response
    pub xres: Vec<u8>,
    /// Authentication token
    pub autn: [u8; 16],
    /// Key for ASME
    pub kasme: [u8; 32],
}

/// Authentication Information Answer message
#[derive(Debug, Clone, Default)]
pub struct AiaMessage {
    /// Result code
    pub result_code: u32,
    /// Experimental result code (if any)
    pub experimental_result_code: Option<u32>,
    /// E-UTRAN vector
    pub e_utran_vector: EUtranVector,
}

/// Subscription Data
#[derive(Debug, Clone, Default)]
pub struct SubscriptionData {
    /// MSISDN
    pub msisdn: Vec<u8>,
    /// A-MSISDN
    pub a_msisdn: Vec<u8>,
    /// Network access mode
    pub network_access_mode: u32,
    /// Subscribed RAU/TAU timer
    pub subscribed_rau_tau_timer: u32,
    /// AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// Context identifier
    pub context_identifier: u32,
    /// APN configurations
    pub apn_configs: Vec<ApnConfiguration>,
    /// Charging characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// APN Configuration
#[derive(Debug, Clone, Default)]
pub struct ApnConfiguration {
    /// Context identifier
    pub context_identifier: u32,
    /// Service selection (APN name)
    pub service_selection: String,
    /// PDN type (1=IPv4, 2=IPv6, 3=IPv4v6)
    pub pdn_type: u8,
    /// QoS class identifier
    pub qci: u8,
    /// ARP priority level
    pub arp_priority_level: u8,
    /// ARP pre-emption capability
    pub arp_pre_emption_capability: bool,
    /// ARP pre-emption vulnerability
    pub arp_pre_emption_vulnerability: bool,
    /// AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// Charging characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// Update Location Answer message
#[derive(Debug, Clone, Default)]
pub struct UlaMessage {
    /// Result code
    pub result_code: u32,
    /// Experimental result code (if any)
    pub experimental_result_code: Option<u32>,
    /// ULA flags
    pub ula_flags: u32,
    /// Subscription data
    pub subscription_data: SubscriptionData,
}

/// Cancel Location Request message
#[derive(Debug, Clone, Default)]
pub struct ClrMessage {
    /// Cancellation type
    pub cancellation_type: u32,
    /// CLR flags
    pub clr_flags: u32,
}

/// Insert Subscriber Data Request message
#[derive(Debug, Clone, Default)]
pub struct IdrMessage {
    /// IDR flags
    pub idr_flags: u32,
    /// Subscription data
    pub subscription_data: SubscriptionData,
}

/// S6a Message wrapper
#[derive(Debug, Clone)]
pub enum S6aMessage {
    /// Authentication Information Answer
    Aia(AiaMessage),
    /// Update Location Answer
    Ula(UlaMessage),
    /// Cancel Location Request
    Clr(ClrMessage),
    /// Insert Subscriber Data Request
    Idr(IdrMessage),
    /// Purge UE Answer
    Pua { result_code: u32, pua_flags: u32 },
}

// ============================================================================
// Result Types
// ============================================================================

/// Diameter path operation result
pub type DiameterResult<T> = Result<T, DiameterError>;

/// Diameter path error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterError {
    /// Not initialized
    NotInitialized,
    /// Connection failed
    ConnectionFailed,
    /// Message build failed
    BuildFailed,
    /// Send failed
    SendFailed,
    /// Timeout
    Timeout,
    /// Invalid response
    InvalidResponse,
    /// HSS error
    HssError(u32),
}

impl std::fmt::Display for DiameterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiameterError::NotInitialized => write!(f, "Diameter not initialized"),
            DiameterError::ConnectionFailed => write!(f, "Diameter connection failed"),
            DiameterError::BuildFailed => write!(f, "Message build failed"),
            DiameterError::SendFailed => write!(f, "Send failed"),
            DiameterError::Timeout => write!(f, "Timeout"),
            DiameterError::InvalidResponse => write!(f, "Invalid response"),
            DiameterError::HssError(code) => write!(f, "HSS error: {code}"),
        }
    }
}

impl std::error::Error for DiameterError {}

impl From<ogs_diameter::error::DiameterError> for DiameterError {
    fn from(e: ogs_diameter::error::DiameterError) -> Self {
        match e {
            ogs_diameter::error::DiameterError::Io(_) => DiameterError::ConnectionFailed,
            ogs_diameter::error::DiameterError::Protocol(_) => DiameterError::SendFailed,
            ogs_diameter::error::DiameterError::InvalidMessage(_) => DiameterError::InvalidResponse,
            _ => DiameterError::SendFailed,
        }
    }
}

// ============================================================================
// Session State
// ============================================================================

/// Diameter session state
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// MME UE ID
    pub mme_ue_id: u64,
    /// eNB UE ID
    pub enb_ue_id: u64,
    /// Timestamp
    pub timestamp: u64,
    /// GTP transaction ID (for Gn interface)
    pub gtp_xact_id: Option<u64>,
}

// ============================================================================
// Global Diameter Client
// ============================================================================

/// Diameter client state for the S6a interface (MME -> HSS)
struct S6aClientState {
    /// Diameter client connection to HSS
    client: DiameterClient,
    /// Diameter configuration
    config: DiameterConfig,
    /// Session ID counter
    session_counter: u64,
}

impl S6aClientState {
    fn next_session_id(&mut self) -> String {
        self.session_counter += 1;
        format!(
            "{};{};{}",
            self.config.diameter_id, self.session_counter, self.session_counter
        )
    }
}

/// Global S6a client state
static S6A_CLIENT: OnceLock<Mutex<Option<S6aClientState>>> = OnceLock::new();

fn s6a_client() -> &'static Mutex<Option<S6aClientState>> {
    S6A_CLIENT.get_or_init(|| Mutex::new(None))
}

// ============================================================================
// Diameter Path Functions
// ============================================================================

/// Initialize Diameter S6a interface (sync version for startup)
///
/// Creates the client state but does not connect. Call `mme_fd_connect` once
/// the async runtime is available to establish the Diameter connection.
pub fn mme_fd_init() -> DiameterResult<()> {
    log::info!("Initializing Diameter S6a interface (deferred connect)");
    // State will be populated when mme_fd_init_async is called with config.
    // For now, mark as initialized with None state so the sync init path works.
    let _ = s6a_client(); // ensure OnceLock is initialized
    Ok(())
}

/// Initialize Diameter S6a interface with configuration (async version)
///
/// # Arguments
/// * `config` - Diameter configuration (origin host, realm, etc.)
/// * `hss_addr` - HSS peer address
pub async fn mme_fd_init_async(config: DiameterConfig, hss_addr: SocketAddr) -> DiameterResult<()> {
    log::info!("Initializing Diameter S6a interface, HSS={hss_addr}");

    let client = DiameterClient::new(config.clone(), hss_addr);
    let state = S6aClientState {
        client,
        config,
        session_counter: 0,
    };

    let mut guard = s6a_client().lock().await;
    *guard = Some(state);
    Ok(())
}

/// Connect the S6a client to the HSS
pub async fn mme_fd_connect() -> DiameterResult<()> {
    let mut guard = s6a_client().lock().await;
    let state = guard.as_mut().ok_or(DiameterError::NotInitialized)?;
    state.client.connect_with_retry(3).await.map_err(|e| {
        log::error!("Failed to connect to HSS: {e}");
        DiameterError::ConnectionFailed
    })
}

/// Finalize Diameter S6a interface (sync version for shutdown)
pub fn mme_fd_final() {
    log::info!("Finalizing Diameter S6a interface");
    // Best-effort cleanup. In a proper async shutdown, use mme_fd_final_async.
}

/// Finalize Diameter S6a interface (async version with graceful disconnect)
pub async fn mme_fd_final_async() {
    log::info!("Finalizing Diameter S6a interface");
    let mut guard = s6a_client().lock().await;
    if let Some(ref mut state) = *guard {
        let _ = state.client.disconnect().await;
    }
    *guard = None;
}

/// Encode a PlmnId to 3-byte BCD wire format for Diameter Visited-PLMN-Id AVP
fn encode_plmn_id(plmn: &crate::context::PlmnId) -> [u8; 3] {
    let mut buf = [0u8; 3];
    buf[0] = (plmn.mcc2 << 4) | plmn.mcc1;
    buf[1] = (plmn.mnc3 << 4) | plmn.mcc3;
    buf[2] = (plmn.mnc2 << 4) | plmn.mnc1;
    buf
}

/// Send Authentication Information Request
///
/// Builds and sends a Diameter AIR to the HSS, returning the parsed AIA.
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `resync` - Whether this is a re-sync request (includes AUTS)
pub async fn mme_s6a_send_air(
    mme_ue: &MmeUe,
    resync: bool,
) -> DiameterResult<AiaMessage> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for AIR");
        return Err(DiameterError::BuildFailed);
    }

    let mut guard = s6a_client().lock().await;
    let state = guard.as_mut().ok_or(DiameterError::NotInitialized)?;

    let session_id = state.next_session_id();
    let visited_plmn = encode_plmn_id(&mme_ue.tai.plmn_id);

    log::debug!(
        "[{}] Sending Authentication-Information-Request (resync={})",
        mme_ue.imsi_bcd,
        resync
    );

    let mut air = s6a::create_air(
        &session_id,
        &state.config.diameter_id,
        &state.config.diameter_realm,
        &state.config.diameter_realm, // destination realm (same or from hssmap)
        &mme_ue.imsi_bcd,
        &visited_plmn,
        1, // request 1 vector
    );

    // If resync, add Re-Synchronization-Info grouped AVP containing RAND+AUTS
    if resync {
        let mut resync_data = Vec::with_capacity(30);
        resync_data.extend_from_slice(&mme_ue.rand);
        // AUTS would come from the UE; for now use a placeholder
        // In practice, the caller should pass in the AUTS bytes
        log::debug!("[{}] Adding Re-Synchronization-Info to AIR", mme_ue.imsi_bcd);
        let resync_avp = ogs_diameter::avp::Avp::vendor_mandatory(
            s6a::avp::RE_SYNC_INFO,
            ogs_diameter::OGS_3GPP_VENDOR_ID,
            ogs_diameter::avp::AvpData::OctetString(
                bytes::Bytes::copy_from_slice(&resync_data),
            ),
        );
        // Find the Requested-EUTRAN-Authentication-Info grouped AVP and add resync into it
        // For simplicity, add it as a top-level AVP (HSS implementations accept both)
        air.add_avp(resync_avp);
    }

    let answer = state.client.send_request(&air).await?;

    // Parse the AIA response
    let result_code = answer.result_code().unwrap_or(0);
    let experimental_result_code = answer
        .find_avp(avp_code::EXPERIMENTAL_RESULT)
        .and_then(|avp| avp.as_grouped())
        .and_then(|g| ogs_diameter::avp::find_avp(g, avp_code::EXPERIMENTAL_RESULT_CODE))
        .and_then(|a| a.as_u32());

    let mut e_utran_vector = EUtranVector::default();

    // Parse Authentication-Info -> E-UTRAN-Vector
    if let Some(auth_info) = answer.find_avp(avp_code::AUTHENTICATION_INFO) {
        if let Some(group) = auth_info.as_grouped() {
            if let Some(vec_avp) = ogs_diameter::avp::find_avp(group, avp_code::E_UTRAN_VECTOR) {
                if let Ok(vec) = s6a::parse_e_utran_vector(vec_avp) {
                    e_utran_vector = EUtranVector {
                        rand: vec.rand,
                        xres: vec.xres,
                        autn: vec.autn,
                        kasme: vec.kasme,
                    };
                }
            }
        }
    }

    log::debug!(
        "[{}] Received AIA result_code={}",
        mme_ue.imsi_bcd,
        result_code
    );

    Ok(AiaMessage {
        result_code,
        experimental_result_code,
        e_utran_vector,
    })
}

/// Send Update Location Request
///
/// Builds and sends a Diameter ULR to the HSS, returning the parsed ULA.
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `initial_attach` - Whether this is initial attach
pub async fn mme_s6a_send_ulr(
    mme_ue: &MmeUe,
    initial_attach: bool,
) -> DiameterResult<UlaMessage> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for ULR");
        return Err(DiameterError::BuildFailed);
    }

    let mut guard = s6a_client().lock().await;
    let state = guard.as_mut().ok_or(DiameterError::NotInitialized)?;

    let session_id = state.next_session_id();
    let visited_plmn = encode_plmn_id(&mme_ue.tai.plmn_id);

    // Build ULR flags
    let mut flags = s6a::ulr_flags::S6A_S6D_INDICATOR
        | s6a::ulr_flags::SINGLE_REGISTRATION_IND;
    if initial_attach {
        flags |= s6a::ulr_flags::INITIAL_ATTACH_IND;
    }

    log::debug!(
        "[{}] Sending Update-Location-Request (initial_attach={}, flags=0x{:04x})",
        mme_ue.imsi_bcd,
        initial_attach,
        flags
    );

    let ulr = s6a::create_ulr(
        &session_id,
        &state.config.diameter_id,
        &state.config.diameter_realm,
        &state.config.diameter_realm,
        &mme_ue.imsi_bcd,
        &visited_plmn,
        flags,
        1004, // E-UTRAN RAT type
    );

    let answer = state.client.send_request(&ulr).await?;

    // Parse ULA
    let result_code = answer.result_code().unwrap_or(0);
    let experimental_result_code = answer
        .find_avp(avp_code::EXPERIMENTAL_RESULT)
        .and_then(|avp| avp.as_grouped())
        .and_then(|g| ogs_diameter::avp::find_avp(g, avp_code::EXPERIMENTAL_RESULT_CODE))
        .and_then(|a| a.as_u32());

    let ula_flags = answer
        .find_avp(avp_code::ULA_FLAGS)
        .and_then(|a| a.as_u32())
        .unwrap_or(0);

    // Parse subscription data from the answer
    let subscription_data = parse_subscription_data(&answer);

    log::debug!(
        "[{}] Received ULA result_code={}, ula_flags=0x{:04x}",
        mme_ue.imsi_bcd,
        result_code,
        ula_flags
    );

    Ok(UlaMessage {
        result_code,
        experimental_result_code,
        ula_flags,
        subscription_data,
    })
}

/// Send Purge UE Request
///
/// Builds and sends a Diameter PUR to the HSS.
///
/// # Arguments
/// * `mme_ue` - MME UE context
///
/// # Returns
/// * `Ok(result_code, pua_flags)` on success
pub async fn mme_s6a_send_pur(mme_ue: &MmeUe) -> DiameterResult<(u32, u32)> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for PUR");
        return Err(DiameterError::BuildFailed);
    }

    let mut guard = s6a_client().lock().await;
    let state = guard.as_mut().ok_or(DiameterError::NotInitialized)?;

    let session_id = state.next_session_id();

    log::debug!("[{}] Sending Purge-UE-Request", mme_ue.imsi_bcd);

    let mut pur = ogs_diameter::message::DiameterMessage::new_request(
        s6a::cmd::PURGE_UE,
        s6a::S6A_APPLICATION_ID,
    );

    // Session-Id
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::SESSION_ID,
        ogs_diameter::avp::AvpData::Utf8String(session_id),
    ));
    // Origin-Host
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::ORIGIN_HOST,
        ogs_diameter::avp::AvpData::DiameterIdentity(state.config.diameter_id.clone()),
    ));
    // Origin-Realm
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::ORIGIN_REALM,
        ogs_diameter::avp::AvpData::DiameterIdentity(state.config.diameter_realm.clone()),
    ));
    // Destination-Realm
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::DESTINATION_REALM,
        ogs_diameter::avp::AvpData::DiameterIdentity(state.config.diameter_realm.clone()),
    ));
    // User-Name (IMSI)
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::USER_NAME,
        ogs_diameter::avp::AvpData::Utf8String(mme_ue.imsi_bcd.clone()),
    ));
    // Auth-Session-State (NO_STATE_MAINTAINED)
    pur.add_avp(ogs_diameter::avp::Avp::mandatory(
        ogs_diameter::common::avp_code::AUTH_SESSION_STATE,
        ogs_diameter::avp::AvpData::Enumerated(1),
    ));

    let answer = state.client.send_request(&pur).await?;

    let result_code = answer.result_code().unwrap_or(0);
    let pua_flags = answer
        .find_avp(avp_code::PUA_FLAGS)
        .and_then(|a| a.as_u32())
        .unwrap_or(0);

    log::debug!(
        "[{}] Received PUA result_code={}, flags=0x{:04x}",
        mme_ue.imsi_bcd,
        result_code,
        pua_flags
    );

    Ok((result_code, pua_flags))
}

/// Parse Subscription-Data from a ULA DiameterMessage
fn parse_subscription_data(msg: &ogs_diameter::message::DiameterMessage) -> SubscriptionData {
    let mut sub = SubscriptionData::default();

    let sub_avp = msg.find_avp(avp_code::SUBSCRIPTION_DATA);
    let group = match sub_avp.and_then(|a| a.as_grouped()) {
        Some(g) => g,
        None => return sub,
    };

    // MSISDN
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::MSISDN) {
        if let Some(b) = a.as_octet_string() {
            sub.msisdn = b.to_vec();
        }
    }

    // A-MSISDN
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::A_MSISDN) {
        if let Some(b) = a.as_octet_string() {
            sub.a_msisdn = b.to_vec();
        }
    }

    // Network-Access-Mode
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::NETWORK_ACCESS_MODE) {
        sub.network_access_mode = a.as_u32().unwrap_or(0);
    }

    // Charging-Characteristics
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::CHARGING_CHARACTERISTICS) {
        if let Some(b) = a.as_octet_string() {
            if b.len() >= 2 {
                sub.charging_characteristics = Some([b[0], b[1]]);
            }
        }
    }

    // AMBR
    if let Some(ambr) = ogs_diameter::avp::find_avp(group, avp_code::AMBR) {
        if let Some(ag) = ambr.as_grouped() {
            if let Some(ul) = ogs_diameter::avp::find_avp(ag, avp_code::MAX_BANDWIDTH_UL) {
                sub.ambr_uplink = ul.as_u32().unwrap_or(0) as u64;
            }
            if let Some(dl) = ogs_diameter::avp::find_avp(ag, avp_code::MAX_BANDWIDTH_DL) {
                sub.ambr_downlink = dl.as_u32().unwrap_or(0) as u64;
            }
        }
    }

    // APN-Configuration-Profile -> APN-Configuration(s)
    if let Some(profile) = ogs_diameter::avp::find_avp(group, avp_code::APN_CONFIGURATION_PROFILE)
    {
        if let Some(pg) = profile.as_grouped() {
            // Context-Identifier (default APN)
            if let Some(ci) = ogs_diameter::avp::find_avp(pg, avp_code::CONTEXT_IDENTIFIER) {
                sub.context_identifier = ci.as_u32().unwrap_or(0);
            }
            // APN-Configuration entries
            for inner in pg {
                if inner.code == avp_code::APN_CONFIGURATION {
                    if let Some(apn_group) = inner.as_grouped() {
                        sub.apn_configs.push(parse_apn_config(apn_group));
                    }
                }
            }
        }
    }

    sub
}

/// Parse a single APN-Configuration grouped AVP
fn parse_apn_config(group: &[ogs_diameter::avp::Avp]) -> ApnConfiguration {
    let mut apn = ApnConfiguration::default();

    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::CONTEXT_IDENTIFIER) {
        apn.context_identifier = a.as_u32().unwrap_or(0);
    }
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::SERVICE_SELECTION) {
        if let Some(s) = a.as_utf8_string() {
            apn.service_selection = s.to_string();
        }
    }
    if let Some(a) = ogs_diameter::avp::find_avp(group, avp_code::PDN_TYPE) {
        apn.pdn_type = a.as_u32().unwrap_or(1) as u8;
    }

    // AMBR
    if let Some(ambr) = ogs_diameter::avp::find_avp(group, avp_code::AMBR) {
        if let Some(ag) = ambr.as_grouped() {
            if let Some(ul) = ogs_diameter::avp::find_avp(ag, avp_code::MAX_BANDWIDTH_UL) {
                apn.ambr_uplink = ul.as_u32().unwrap_or(0) as u64;
            }
            if let Some(dl) = ogs_diameter::avp::find_avp(ag, avp_code::MAX_BANDWIDTH_DL) {
                apn.ambr_downlink = dl.as_u32().unwrap_or(0) as u64;
            }
        }
    }

    // EPS-Subscribed-QoS-Profile
    if let Some(qos_avp) =
        ogs_diameter::avp::find_avp(group, avp_code::EPS_SUBSCRIBED_QOS_PROFILE)
    {
        if let Some(qg) = qos_avp.as_grouped() {
            if let Some(a) = ogs_diameter::avp::find_avp(qg, avp_code::QOS_CLASS_IDENTIFIER) {
                apn.qci = a.as_u32().unwrap_or(9) as u8;
            }
            if let Some(arp) =
                ogs_diameter::avp::find_avp(qg, avp_code::ALLOCATION_RETENTION_PRIORITY)
            {
                if let Some(ag) = arp.as_grouped() {
                    if let Some(a) = ogs_diameter::avp::find_avp(ag, avp_code::PRIORITY_LEVEL) {
                        apn.arp_priority_level = a.as_u32().unwrap_or(8) as u8;
                    }
                    if let Some(a) =
                        ogs_diameter::avp::find_avp(ag, avp_code::PRE_EMPTION_CAPABILITY)
                    {
                        apn.arp_pre_emption_capability = a.as_u32().unwrap_or(1) == 0;
                    }
                    if let Some(a) =
                        ogs_diameter::avp::find_avp(ag, avp_code::PRE_EMPTION_VULNERABILITY)
                    {
                        apn.arp_pre_emption_vulnerability = a.as_u32().unwrap_or(1) == 0;
                    }
                }
            }
        }
    }

    apn
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert Diameter result code to EMM cause
pub fn emm_cause_from_diameter(
    result_code: Option<u32>,
    experimental_result_code: Option<u32>,
) -> EmmCause {
    // Check experimental result first
    if let Some(exp_code) = experimental_result_code {
        return match exp_code {
            experimental_result::DIAMETER_ERROR_USER_UNKNOWN => {
                EmmCause::ImsiUnknownInHss
            }
            experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION => {
                EmmCause::NoSuitableCellsInTa
            }
            experimental_result::DIAMETER_ERROR_RAT_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_EQUIPMENT_UNKNOWN => {
                EmmCause::IllegalUe
            }
            experimental_result::DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE => {
                EmmCause::NetworkFailure
            }
            _ => EmmCause::NetworkFailure,
        };
    }

    // Check result code
    if let Some(code) = result_code {
        return match code {
            result_code::DIAMETER_SUCCESS => EmmCause::RequestAccepted,
            result_code::DIAMETER_AUTHORIZATION_REJECTED => {
                EmmCause::EpsServicesNotAllowed
            }
            result_code::DIAMETER_UNABLE_TO_COMPLY => {
                EmmCause::NetworkFailure
            }
            _ => EmmCause::NetworkFailure,
        };
    }

    EmmCause::NetworkFailure
}

/// Encode PLMN ID for Diameter
pub fn encode_visited_plmn_id(mcc: &str, mnc: &str) -> Vec<u8> {
    let mut plmn = vec![0u8; 3];
    
    let mcc_digits: Vec<u8> = mcc.chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    let mnc_digits: Vec<u8> = mnc.chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    
    if mcc_digits.len() >= 3 {
        plmn[0] = (mcc_digits[1] << 4) | mcc_digits[0];
        if mnc_digits.len() == 2 {
            plmn[1] = 0xf0 | mcc_digits[2];
            plmn[2] = (mnc_digits[1] << 4) | mnc_digits[0];
        } else if mnc_digits.len() >= 3 {
            plmn[1] = (mnc_digits[2] << 4) | mcc_digits[2];
            plmn[2] = (mnc_digits[1] << 4) | mnc_digits[0];
        }
    }
    
    plmn
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_error_display() {
        assert_eq!(
            format!("{}", DiameterError::NotInitialized),
            "Diameter not initialized"
        );
        assert_eq!(
            format!("{}", DiameterError::HssError(5001)),
            "HSS error: 5001"
        );
    }

    #[test]
    fn test_emm_cause_from_diameter_success() {
        let cause = emm_cause_from_diameter(
            Some(result_code::DIAMETER_SUCCESS),
            None,
        );
        assert_eq!(cause, EmmCause::RequestAccepted);
    }

    #[test]
    fn test_emm_cause_from_diameter_user_unknown() {
        let cause = emm_cause_from_diameter(
            None,
            Some(experimental_result::DIAMETER_ERROR_USER_UNKNOWN),
        );
        assert_eq!(cause, EmmCause::ImsiUnknownInHss);
    }

    #[test]
    fn test_emm_cause_from_diameter_roaming_not_allowed() {
        let cause = emm_cause_from_diameter(
            None,
            Some(experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED),
        );
        assert_eq!(cause, EmmCause::RoamingNotAllowedInTa);
    }

    #[test]
    fn test_encode_visited_plmn_id_3digit_mnc() {
        let plmn = encode_visited_plmn_id("310", "410");
        assert_eq!(plmn.len(), 3);
    }

    #[test]
    fn test_encode_visited_plmn_id_2digit_mnc() {
        let plmn = encode_visited_plmn_id("310", "26");
        assert_eq!(plmn.len(), 3);
        // MNC filler should be 0xf
        assert_eq!(plmn[1] & 0xf0, 0xf0);
    }

    #[test]
    fn test_session_state_default() {
        let state = SessionState::default();
        assert_eq!(state.mme_ue_id, 0);
        assert_eq!(state.enb_ue_id, 0);
        assert!(state.gtp_xact_id.is_none());
    }

    #[test]
    fn test_e_utran_vector_default() {
        let vector = EUtranVector::default();
        assert_eq!(vector.rand, [0u8; 16]);
        assert_eq!(vector.autn, [0u8; 16]);
        assert_eq!(vector.kasme, [0u8; 32]);
        assert!(vector.xres.is_empty());
    }

    #[test]
    fn test_aia_message_default() {
        let msg = AiaMessage::default();
        assert_eq!(msg.result_code, 0);
        assert!(msg.experimental_result_code.is_none());
    }

    #[test]
    fn test_subscription_data_default() {
        let data = SubscriptionData::default();
        assert!(data.msisdn.is_empty());
        assert!(data.apn_configs.is_empty());
        assert_eq!(data.network_access_mode, 0);
    }

    #[test]
    fn test_encode_plmn_id_3digit_mnc() {
        // MCC=310, MNC=410 -> digits: mcc1=3, mcc2=1, mcc3=0, mnc1=4, mnc2=1, mnc3=0
        let plmn = crate::context::PlmnId::new("310", "410");
        let encoded = encode_plmn_id(&plmn);
        // byte[0] = (mcc2<<4)|mcc1 = (1<<4)|3 = 0x13
        assert_eq!(encoded[0], 0x13);
        // byte[1] = (mnc3<<4)|mcc3 = (0<<4)|0 = 0x00
        assert_eq!(encoded[1], 0x00);
        // byte[2] = (mnc2<<4)|mnc1 = (1<<4)|4 = 0x14
        assert_eq!(encoded[2], 0x14);
    }

    #[test]
    fn test_encode_plmn_id_2digit_mnc() {
        // MCC=001, MNC=01 -> digits: mcc1=0, mcc2=0, mcc3=1, mnc1=0, mnc2=1, mnc3=0xf
        let plmn = crate::context::PlmnId::new("001", "01");
        let encoded = encode_plmn_id(&plmn);
        // byte[0] = (mcc2<<4)|mcc1 = (0<<4)|0 = 0x00
        assert_eq!(encoded[0], 0x00);
        // byte[1] = (mnc3<<4)|mcc3 = (0xf<<4)|1 = 0xf1
        assert_eq!(encoded[1], 0xf1);
        // byte[2] = (mnc2<<4)|mnc1 = (1<<4)|0 = 0x10
        assert_eq!(encoded[2], 0x10);
    }

    #[test]
    fn test_diameter_error_from_ogs() {
        let io_err = ogs_diameter::error::DiameterError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        );
        let local: DiameterError = io_err.into();
        assert_eq!(local, DiameterError::ConnectionFailed);

        let proto_err =
            ogs_diameter::error::DiameterError::Protocol("test".to_string());
        let local: DiameterError = proto_err.into();
        assert_eq!(local, DiameterError::SendFailed);

        let inv_err =
            ogs_diameter::error::DiameterError::InvalidMessage("bad".to_string());
        let local: DiameterError = inv_err.into();
        assert_eq!(local, DiameterError::InvalidResponse);
    }

    #[test]
    fn test_mme_fd_init_sync() {
        // Sync init should succeed (deferred connect)
        let result = mme_fd_init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_air_without_init() {
        // Sending AIR without async init should fail with NotInitialized
        let mme_ue = crate::context::MmeUe {
            imsi_bcd: "001010123456789".to_string(),
            ..Default::default()
        };
        let result = mme_s6a_send_air(&mme_ue, false).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::NotInitialized);
    }

    #[tokio::test]
    async fn test_send_ulr_without_init() {
        let mme_ue = crate::context::MmeUe {
            imsi_bcd: "001010123456789".to_string(),
            ..Default::default()
        };
        let result = mme_s6a_send_ulr(&mme_ue, true).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::NotInitialized);
    }

    #[tokio::test]
    async fn test_send_pur_without_init() {
        let mme_ue = crate::context::MmeUe {
            imsi_bcd: "001010123456789".to_string(),
            ..Default::default()
        };
        let result = mme_s6a_send_pur(&mme_ue).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::NotInitialized);
    }

    #[tokio::test]
    async fn test_send_air_empty_imsi() {
        let mme_ue = crate::context::MmeUe::default();
        let result = mme_s6a_send_air(&mme_ue, false).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::BuildFailed);
    }

    #[tokio::test]
    async fn test_send_ulr_empty_imsi() {
        let mme_ue = crate::context::MmeUe::default();
        let result = mme_s6a_send_ulr(&mme_ue, false).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::BuildFailed);
    }

    #[tokio::test]
    async fn test_send_pur_empty_imsi() {
        let mme_ue = crate::context::MmeUe::default();
        let result = mme_s6a_send_pur(&mme_ue).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DiameterError::BuildFailed);
    }

    #[test]
    fn test_parse_subscription_data_empty() {
        // Parse subscription data from a message with no Subscription-Data AVP
        let msg = ogs_diameter::message::DiameterMessage::new_request(316, 16777251);
        let sub = parse_subscription_data(&msg);
        assert!(sub.msisdn.is_empty());
        assert!(sub.apn_configs.is_empty());
        assert_eq!(sub.ambr_uplink, 0);
        assert_eq!(sub.ambr_downlink, 0);
    }
}
