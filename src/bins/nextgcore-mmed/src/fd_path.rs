//! Diameter (freeDiameter) Path Functions
//!
//! Port of src/mme/mme-fd-path.c - Diameter S6a interface functions
//!
//! Implements Diameter S6a interface for HSS communication.
//! Wires the MME to HSS via nextgcore-diameter DiameterClient for S6a requests.

use std::net::SocketAddr;
use std::sync::OnceLock;

use tokio::sync::Mutex;

use nextgcore_diameter::config::DiameterConfig;
use nextgcore_diameter::s6a;
use nextgcore_diameter::session::DiameterSession;
use nextgcore_diameter::transport::DiameterClient;

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

// E-UTRAN authentication vector, Subscription-Data and APN-Configuration are
// shared with the HSS via the S6a library module so both sides encode/parse
// the same grouped-AVP wire format (TS 29.272 7.3.x).
pub use nextgcore_diameter::s6a::{ApnConfiguration, EUtranVector, SubscriptionData};

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

impl From<nextgcore_diameter::error::DiameterError> for DiameterError {
    fn from(e: nextgcore_diameter::error::DiameterError) -> Self {
        match e {
            nextgcore_diameter::error::DiameterError::Io(_) => DiameterError::ConnectionFailed,
            nextgcore_diameter::error::DiameterError::Protocol(_) => DiameterError::SendFailed,
            nextgcore_diameter::error::DiameterError::InvalidMessage(_) => {
                DiameterError::InvalidResponse
            }
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
///
/// # Why this no longer holds a `DiameterClient`
///
/// It used to, and every S6a operation took the global mutex below and then
/// called `client.send_request(..)` **while holding the guard**. Because
/// `send_request` awaits the HSS answer, one slow or unanswered exchange blocked
/// every other subscriber's AIR/ULR/PUR — the whole S6a plane, not just the UE
/// that stalled. A request timeout (added separately) bounded that to 30s of
/// total outage per stalled request, which is better than forever but still an
/// availability defect, and the lock was the cause.
///
/// The connection now lives in a [`DiameterSession`], which multiplexes requests
/// over it by Hop-by-Hop Identifier (RFC 6733 §3) and is `Clone` + `&self`. So
/// this struct keeps only what genuinely needs serialising: the session-id
/// counter. The lock is taken to build a request and released before the await.
struct S6aClientState {
    /// Multiplexing handle for the HSS connection. Cloned out under the lock and
    /// used without it, which is what allows concurrent exchanges.
    session: DiameterSession,
    /// Diameter configuration
    config: DiameterConfig,
    /// Session ID counter
    session_counter: u64,
    /// Reader task driving the session; aborted on shutdown.
    reader: Option<tokio::task::JoinHandle<()>>,
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

/// Configuration recorded by [`mme_fd_init_async`], consumed by
/// [`mme_fd_connect`].
///
/// Kept separate from `S6A_CLIENT` because the connection is now established in
/// one step (connect + session start), so `mme_fd_connect` needs the config
/// before any session exists — and it must not hold the state lock while dialling.
static S6A_CONFIG: OnceLock<Mutex<Option<(DiameterConfig, SocketAddr)>>> = OnceLock::new();

fn s6a_config() -> &'static Mutex<Option<(DiameterConfig, SocketAddr)>> {
    S6A_CONFIG.get_or_init(|| Mutex::new(None))
}

/// Take the session handle and a fresh session id, releasing the lock before the
/// caller awaits anything.
///
/// Every S6a request path goes through this rather than holding the guard across
/// its exchange. Returning owned values (a cloned handle, a `String`, the two
/// identity strings) is what makes that possible: nothing borrowed from the
/// guard outlives it.
async fn s6a_begin_request() -> DiameterResult<(DiameterSession, String, String, String)> {
    let mut guard = s6a_client().lock().await;
    let state = guard.as_mut().ok_or(DiameterError::NotInitialized)?;
    let session_id = state.next_session_id();
    Ok((
        state.session.clone(),
        session_id,
        state.config.diameter_id.clone(),
        state.config.diameter_realm.clone(),
    ))
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

/// Record the S6a configuration. The connection itself is established by
/// [`mme_fd_connect`].
///
/// The peer address is stashed rather than dialled here, preserving the previous
/// deferred-connect behaviour: `mme_fd_init` runs before the async runtime is
/// necessarily useful, and startup must not block on an HSS that is not up yet.
///
/// # Arguments
/// * `config` - Diameter configuration (origin host, realm, etc.)
/// * `hss_addr` - HSS peer address
pub async fn mme_fd_init_async(config: DiameterConfig, hss_addr: SocketAddr) -> DiameterResult<()> {
    log::info!("Initializing Diameter S6a interface, HSS={hss_addr}");
    let mut guard = s6a_config().lock().await;
    *guard = Some((config, hss_addr));
    Ok(())
}

/// Connect to the HSS and start multiplexing S6a requests over the connection.
///
/// `DiameterSession::start` consumes the connected client, so the CER/CEA
/// exchange has to complete first -- hence connect and session-start being one
/// step rather than the previous init-then-connect pair. Calling this again after
/// a connection loss replaces the session and aborts the old reader task.
pub async fn mme_fd_connect() -> DiameterResult<()> {
    let (config, hss_addr) = {
        let guard = s6a_config().lock().await;
        guard.clone().ok_or(DiameterError::NotInitialized)?
    };

    // Dialled OUTSIDE the state lock: connect_with_retry sleeps between
    // attempts, and holding the lock across that would reintroduce exactly the
    // stall this change removes.
    let mut client = DiameterClient::new(config.clone(), hss_addr);
    client.connect_with_retry(3).await.map_err(|e| {
        log::error!("Failed to connect to HSS: {e}");
        DiameterError::ConnectionFailed
    })?;

    let (session, reader) = DiameterSession::start(client)?;

    let mut guard = s6a_client().lock().await;
    // Replacing an existing session: stop its reader so two tasks never own
    // connections to the same peer.
    if let Some(old) = guard.take() {
        if let Some(handle) = old.reader {
            handle.abort();
        }
    }
    *guard = Some(S6aClientState {
        session,
        config,
        session_counter: 0,
        reader: Some(reader),
    });
    log::info!("S6a session established with HSS={hss_addr}");
    Ok(())
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
    if let Some(state) = guard.take() {
        // Aborting the reader drops the peer, which closes the socket. There is
        // no graceful DPR here: the session owns the peer, and adding a
        // disconnect path through the multiplexer is only worth it once
        // reconnection exists (tracked with the failover work).
        if let Some(handle) = state.reader {
            handle.abort();
        }
    }
}

/// True when the ULR did not set Skip-Subscriber-Data, i.e. the ULA is
/// expected to carry full subscription data.
fn ulr_flags_has_subscriber_data(flags: u32) -> bool {
    flags & s6a::ulr_flags::SKIP_SUBSCRIBER_DATA == 0
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
/// * `resync_auts` - AUTS from the UE's synchronisation-failure response
///   (TS 24.301 Authentication Failure, EMM cause #21). When present, a
///   Re-Synchronization-Info AVP (RAND of the failed challenge || AUTS) is
///   carried INSIDE Requested-EUTRAN-Authentication-Info per TS 29.272 7.3.11.
pub async fn mme_s6a_send_air(
    mme_ue: &MmeUe,
    resync_auts: Option<&[u8; 14]>,
) -> DiameterResult<AiaMessage> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for AIR");
        return Err(DiameterError::BuildFailed);
    }

    // The lock is released here, BEFORE the exchange below, so a slow answer
    // cannot block another subscriber's request.
    let (session, session_id, origin_host, origin_realm) = s6a_begin_request().await?;

    let visited_plmn = encode_plmn_id(&mme_ue.tai.plmn_id);

    log::debug!(
        "[{}] Sending Authentication-Information-Request (resync={})",
        mme_ue.imsi_bcd,
        resync_auts.is_some()
    );

    let mut air = s6a::create_air(
        &session_id,
        &origin_host,
        &origin_realm,
        &origin_realm, // destination realm (same or from hssmap)
        &mme_ue.imsi_bcd,
        &visited_plmn,
        1, // request 1 vector
    );

    if let Some(auts) = resync_auts {
        log::debug!(
            "[{}] Adding Re-Synchronization-Info inside Requested-EUTRAN-Authentication-Info",
            mme_ue.imsi_bcd
        );
        if !s6a::add_resync_info(&mut air, &mme_ue.rand, auts) {
            log::error!(
                "[{}] AIR has no Requested-EUTRAN-Authentication-Info",
                mme_ue.imsi_bcd
            );
            return Err(DiameterError::BuildFailed);
        }
    }

    let answer = session.send_request(&air).await?;

    // Parse the AIA response
    let result_code = answer.result_code().unwrap_or(0);
    let experimental_result_code = s6a::experimental_result_code(&answer);

    // Parse Authentication-Info -> E-UTRAN-Vector(s); we requested one vector
    let e_utran_vector = s6a::parse_authentication_info(&answer)
        .into_iter()
        .next()
        .unwrap_or_default();

    if result_code == result_code::DIAMETER_SUCCESS && e_utran_vector.xres.is_empty() {
        log::error!(
            "[{}] AIA claims success but carries no usable E-UTRAN vector",
            mme_ue.imsi_bcd
        );
        return Err(DiameterError::InvalidResponse);
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
pub async fn mme_s6a_send_ulr(mme_ue: &MmeUe, initial_attach: bool) -> DiameterResult<UlaMessage> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for ULR");
        return Err(DiameterError::BuildFailed);
    }

    // Lock released before the exchange; see `s6a_begin_request`.
    let (session, session_id, origin_host, origin_realm) = s6a_begin_request().await?;

    let visited_plmn = encode_plmn_id(&mme_ue.tai.plmn_id);

    // Build ULR flags
    let mut flags = s6a::ulr_flags::S6A_S6D_INDICATOR | s6a::ulr_flags::SINGLE_REGISTRATION_IND;
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
        &origin_host,
        &origin_realm,
        &origin_realm,
        &mme_ue.imsi_bcd,
        &visited_plmn,
        flags,
        1004, // E-UTRAN RAT type
    );

    let answer = session.send_request(&ulr).await?;

    // Parse ULA
    let result_code = answer.result_code().unwrap_or(0);
    let experimental_result_code = s6a::experimental_result_code(&answer);

    let ula_flags = answer
        .find_avp(avp_code::ULA_FLAGS)
        .and_then(|a| a.as_u32())
        .unwrap_or(0);

    // Parse the grouped Subscription-Data AVP (TS 29.272 7.3.2)
    let subscription_data = answer
        .find_avp(avp_code::SUBSCRIPTION_DATA)
        .map(s6a::parse_subscription_data_avp)
        .unwrap_or_default();

    if result_code == result_code::DIAMETER_SUCCESS
        && subscription_data.apn_configs.is_empty()
        && ulr_flags_has_subscriber_data(flags)
    {
        log::warn!(
            "[{}] ULA success without APN configuration in Subscription-Data",
            mme_ue.imsi_bcd
        );
    }

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

    // Lock released before the exchange; see `s6a_begin_request`.
    let (session, session_id, origin_host, origin_realm) = s6a_begin_request().await?;

    log::debug!("[{}] Sending Purge-UE-Request", mme_ue.imsi_bcd);

    let mut pur = nextgcore_diameter::message::DiameterMessage::new_request(
        s6a::cmd::PURGE_UE,
        s6a::S6A_APPLICATION_ID,
    );

    // Session-Id
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::SESSION_ID,
        nextgcore_diameter::avp::AvpData::Utf8String(session_id),
    ));
    // Origin-Host
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::ORIGIN_HOST,
        nextgcore_diameter::avp::AvpData::DiameterIdentity(origin_host.clone()),
    ));
    // Origin-Realm
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::ORIGIN_REALM,
        nextgcore_diameter::avp::AvpData::DiameterIdentity(origin_realm.clone()),
    ));
    // Destination-Realm
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::DESTINATION_REALM,
        nextgcore_diameter::avp::AvpData::DiameterIdentity(origin_realm.clone()),
    ));
    // User-Name (IMSI)
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::USER_NAME,
        nextgcore_diameter::avp::AvpData::Utf8String(mme_ue.imsi_bcd.clone()),
    ));
    // Auth-Session-State (NO_STATE_MAINTAINED)
    pur.add_avp(nextgcore_diameter::avp::Avp::mandatory(
        nextgcore_diameter::common::avp_code::AUTH_SESSION_STATE,
        nextgcore_diameter::avp::AvpData::Enumerated(1),
    ));
    // PUR-Flags: UE purged in the MME (TS 29.272 7.3.149)
    pur.add_avp(nextgcore_diameter::avp::Avp::vendor_mandatory(
        s6a::avp::PUR_FLAGS,
        nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID,
        nextgcore_diameter::avp::AvpData::Unsigned32(s6a::pur_flags::UE_PURGED_IN_MME),
    ));

    let answer = session.send_request(&pur).await?;

    let result_code = answer.result_code().unwrap_or(0);
    let pua_flags = answer
        .find_vendor_avp(
            avp_code::PUA_FLAGS,
            nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID,
        )
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

// ============================================================================
// Inbound HSS-initiated requests (CLR / IDR)
// ============================================================================

/// An HSS-initiated S6a request received on the MME's connection.
#[derive(Debug, Clone)]
pub struct InboundS6aRequest {
    /// IMSI from the User-Name AVP
    pub imsi_bcd: String,
    /// Parsed message
    pub message: S6aMessage,
}

/// Poll the S6a connection for HSS-initiated requests (CLR/IDR).
///
/// Parses the request, sends the corresponding answer (CLA/IDA) and returns
/// the parsed message so the caller can apply it to the UE context (e.g.
/// trigger a network-initiated detach on CLR). Returns `Ok(None)` if nothing
/// arrived within `timeout`.
pub async fn mme_fd_recv_inbound(
    timeout: std::time::Duration,
) -> DiameterResult<Option<InboundS6aRequest>> {
    // Clone the handle and identities, then RELEASE the lock: this function
    // waits up to `timeout` for a peer-initiated request, and holding the state
    // lock for that whole window would block every outbound AIR/ULR/PUR -- the
    // same defect as the request paths, just with a longer hold.
    let (session, origin_host, origin_realm) = {
        let guard = s6a_client().lock().await;
        let state = guard.as_ref().ok_or(DiameterError::NotInitialized)?;
        (
            state.session.clone(),
            state.config.diameter_id.clone(),
            state.config.diameter_realm.clone(),
        )
    };

    let Some(request) = session.recv_inbound_request(timeout).await? else {
        return Ok(None);
    };

    let build_answer =
        |req: &nextgcore_diameter::message::DiameterMessage, result: u32, protocol_error: bool| {
            let mut answer = nextgcore_diameter::message::DiameterMessage::new_answer(req);
            if let Some(sid) = req.session_id() {
                answer.add_avp(nextgcore_diameter::avp::Avp::mandatory(
                    nextgcore_diameter::common::avp_code::SESSION_ID,
                    nextgcore_diameter::avp::AvpData::Utf8String(sid.to_string()),
                ));
            }
            answer.add_avp(nextgcore_diameter::avp::Avp::mandatory(
                nextgcore_diameter::common::avp_code::RESULT_CODE,
                nextgcore_diameter::avp::AvpData::Unsigned32(result),
            ));
            answer.add_avp(nextgcore_diameter::avp::Avp::mandatory(
                nextgcore_diameter::common::avp_code::AUTH_SESSION_STATE,
                nextgcore_diameter::avp::AvpData::Enumerated(1),
            ));
            answer.add_avp(nextgcore_diameter::avp::Avp::mandatory(
                nextgcore_diameter::common::avp_code::ORIGIN_HOST,
                nextgcore_diameter::avp::AvpData::DiameterIdentity(origin_host.clone()),
            ));
            answer.add_avp(nextgcore_diameter::avp::Avp::mandatory(
                nextgcore_diameter::common::avp_code::ORIGIN_REALM,
                nextgcore_diameter::avp::AvpData::DiameterIdentity(origin_realm.clone()),
            ));
            if protocol_error {
                answer.header.set_error();
            }
            answer
        };

    // User-Name is mandatory in CLR/IDR (TS 29.272 7.2.7 / 7.2.9)
    let Some(imsi_bcd) = request.user_name().map(str::to_string) else {
        log::error!("Inbound S6a request missing User-Name");
        let answer = build_answer(&request, result_code::DIAMETER_MISSING_AVP, false);
        session.send_answer(&answer).await?;
        return Ok(None);
    };

    match request.header.command_code {
        command_code::CANCEL_LOCATION => {
            let cancellation_type = request
                .find_vendor_avp(
                    avp_code::CANCELLATION_TYPE,
                    nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID,
                )
                .and_then(|a| a.as_u32());
            // Cancellation-Type is mandatory in CLR (TS 29.272 Table 7.2.7/1)
            let Some(cancellation_type) = cancellation_type else {
                log::error!("[{imsi_bcd}] CLR missing Cancellation-Type");
                let answer = build_answer(&request, result_code::DIAMETER_MISSING_AVP, false);
                session.send_answer(&answer).await?;
                return Ok(None);
            };
            let clr_flags = request
                .find_vendor_avp(
                    avp_code::CLR_FLAGS,
                    nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID,
                )
                .and_then(|a| a.as_u32())
                .unwrap_or(0);

            log::info!(
                "[{imsi_bcd}] Received CLR (type={cancellation_type}, flags={clr_flags:#x})"
            );
            let answer = build_answer(&request, result_code::DIAMETER_SUCCESS, false);
            session.send_answer(&answer).await?;

            Ok(Some(InboundS6aRequest {
                imsi_bcd,
                message: S6aMessage::Clr(ClrMessage {
                    cancellation_type,
                    clr_flags,
                }),
            }))
        }
        command_code::INSERT_SUBSCRIBER_DATA => {
            // Subscription-Data is mandatory in IDR (TS 29.272 Table 7.2.9/1)
            let Some(sub_avp) = request.find_avp(avp_code::SUBSCRIPTION_DATA) else {
                log::error!("[{imsi_bcd}] IDR missing Subscription-Data");
                let answer = build_answer(&request, result_code::DIAMETER_MISSING_AVP, false);
                session.send_answer(&answer).await?;
                return Ok(None);
            };
            let subscription_data = s6a::parse_subscription_data_avp(sub_avp);
            let idr_flags = request
                .find_vendor_avp(
                    avp_code::IDR_FLAGS,
                    nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID,
                )
                .and_then(|a| a.as_u32())
                .unwrap_or(0);

            log::info!("[{imsi_bcd}] Received IDR (flags={idr_flags:#x})");
            let answer = build_answer(&request, result_code::DIAMETER_SUCCESS, false);
            session.send_answer(&answer).await?;

            Ok(Some(InboundS6aRequest {
                imsi_bcd,
                message: S6aMessage::Idr(IdrMessage {
                    idr_flags,
                    subscription_data,
                }),
            }))
        }
        other => {
            log::warn!("[{imsi_bcd}] Unsupported inbound S6a command: {other}");
            let answer = build_answer(
                &request,
                result_code::DIAMETER_COMMAND_UNSUPPORTED,
                true, // protocol error: E-bit (RFC 6733 7.2)
            );
            session.send_answer(&answer).await?;
            Ok(None)
        }
    }
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
            experimental_result::DIAMETER_ERROR_USER_UNKNOWN => EmmCause::ImsiUnknownInHss,
            experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION => {
                EmmCause::NoSuitableCellsInTa
            }
            experimental_result::DIAMETER_ERROR_RAT_NOT_ALLOWED => EmmCause::RoamingNotAllowedInTa,
            experimental_result::DIAMETER_ERROR_EQUIPMENT_UNKNOWN => EmmCause::IllegalUe,
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
            result_code::DIAMETER_AUTHORIZATION_REJECTED => EmmCause::EpsServicesNotAllowed,
            result_code::DIAMETER_UNABLE_TO_COMPLY => EmmCause::NetworkFailure,
            _ => EmmCause::NetworkFailure,
        };
    }

    EmmCause::NetworkFailure
}

/// Encode PLMN ID for Diameter
pub fn encode_visited_plmn_id(mcc: &str, mnc: &str) -> Vec<u8> {
    let mut plmn = vec![0u8; 3];

    let mcc_digits: Vec<u8> = mcc
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    let mnc_digits: Vec<u8> = mnc
        .chars()
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
// Pending Request Queue
// ============================================================================

/// An S6a exchange the synchronous NAS layer asked for.
///
/// The **UE id** is queued rather than a built message: the drain re-reads the
/// context when it runs, so a UE that detached — or a second Attach Request that
/// replaced the context — becomes a lookup miss instead of a request sent on
/// behalf of a UE that is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingS6aRequest {
    /// Fetch authentication vectors (AIR/AIA, TS 29.272 §5.2.3.1).
    AuthenticationInformation {
        /// MME UE pool id the vectors are for
        mme_ue_id: u64,
    },
}

/// Process-global sender for the pending-request queue.
///
/// A `OnceLock` for the same reason `s1ap_path::SEND_TX` is one: installed once
/// at startup and only cloned afterwards, so the synchronous side needs no lock.
static REQUEST_TX: OnceLock<tokio::sync::mpsc::UnboundedSender<PendingS6aRequest>> =
    OnceLock::new();

/// Install the queue, returning the receiving half for the main loop to drain.
///
/// Returns `None` when a queue is already installed, so a second call cannot
/// orphan the first.
pub fn install_request_queue() -> Option<tokio::sync::mpsc::UnboundedReceiver<PendingS6aRequest>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    match REQUEST_TX.set(tx) {
        Ok(()) => Some(rx),
        Err(_) => None,
    }
}

/// Ask for authentication vectors for `mme_ue_id`.
///
/// Callable from synchronous code: it never blocks and never fails the caller's
/// procedure. `false` means the request was dropped because no queue is
/// installed (a unit test, or a daemon whose init did not run) — which is logged,
/// and leaves the UE without a vector exactly as before.
pub fn queue_authentication_information(mme_ue_id: u64) -> bool {
    let Some(tx) = REQUEST_TX.get() else {
        log::warn!("S6a request dropped: no queue installed (mme_ue_id={mme_ue_id})");
        return false;
    };
    match tx.send(PendingS6aRequest::AuthenticationInformation { mme_ue_id }) {
        Ok(()) => {
            log::debug!("S6a AIR queued for UE {mme_ue_id}");
            true
        }
        Err(_) => {
            log::warn!("S6a request dropped: queue closed (mme_ue_id={mme_ue_id})");
            false
        }
    }
}

/// Run every queued S6a request that is ready, without waiting for more.
///
/// Called from the main loop beside the NAS timer sweep. Each request is a full
/// exchange with the HSS, so this awaits them one at a time: the S6a
/// multiplexer (#149) makes concurrent requests possible, but serialising here
/// keeps the ordering a UE observes intact and is not a bottleneck at the rate
/// attaches arrive.
pub async fn poll_pending(
    ctx: &'static crate::context::MmeContext,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<PendingS6aRequest>,
) {
    while let Ok(request) = rx.try_recv() {
        match request {
            PendingS6aRequest::AuthenticationInformation { mme_ue_id } => {
                run_authentication_information(ctx, mme_ue_id).await;
            }
        }
    }
}

/// AIR/AIA for one UE, then the AUTHENTICATION REQUEST it enables.
async fn run_authentication_information(ctx: &'static crate::context::MmeContext, mme_ue_id: u64) {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        log::debug!("S6a AIR skipped: UE {mme_ue_id} is gone");
        return;
    };
    if mme_ue.xres_len != 0 {
        // A retransmitted Attach Request queues a second AIR for a context that
        // already has a vector; a lookup is cheaper than a duplicate exchange.
        log::debug!("S6a AIR skipped: UE {mme_ue_id} already holds a vector");
        return;
    }
    if mme_ue.imsi_bcd.is_empty() {
        log::warn!("S6a AIR skipped: UE {mme_ue_id} has no IMSI to ask about");
        return;
    }

    // A synch failure (#45) stores the AUTS the HSS needs to resynchronise; it is
    // consumed by exactly one request (TS 33.401 §6.1.1).
    let resync_auts = mme_ue.resync_auts;
    let answer = mme_s6a_send_air(&mme_ue, resync_auts.as_ref()).await;

    let Some(enb_ue) = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|enb_ue| enb_ue.id != 0)
    else {
        log::warn!(
            "[{}] S6a answer arrived with no S1 connection to answer on",
            mme_ue.imsi_bcd
        );
        return;
    };

    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    mme_ue.resync_auts = None;

    let aia = match answer {
        Ok(aia) => aia,
        Err(e) => {
            log::error!("[{}] S6a AIR failed: {e}", mme_ue.imsi_bcd);
            // TS 24.301 §5.5.1.2.5: the network could not authenticate the UE,
            // so the attach is rejected rather than left outstanding.
            if let Err(e) = crate::nas_path::nas_eps_send_attach_reject(
                &enb_ue,
                mme_ue,
                EmmCause::NetworkFailure,
                None,
            ) {
                log::error!("Attach Reject send failed: {e}");
            }
            return;
        }
    };

    match crate::s6a_handler::mme_s6a_handle_aia(mme_ue, &aia) {
        Ok(EmmCause::RequestAccepted) => {
            log::info!("[{}] Authentication vector received", mme_ue.imsi_bcd);
            if let Err(e) = crate::nas_path::nas_eps_send_authentication_request(mme_ue, &enb_ue) {
                log::error!(
                    "[{}] Authentication Request send failed: {e}",
                    mme_ue.imsi_bcd
                );
            }
        }
        Ok(cause) => {
            // The HSS refused: an unknown subscriber, a barred UE, a roaming
            // restriction. The EMM cause it mapped to is what the UE is told.
            log::warn!(
                "[{}] HSS refused authentication: {cause:?}",
                mme_ue.imsi_bcd
            );
            if let Err(e) =
                crate::nas_path::nas_eps_send_attach_reject(&enb_ue, mme_ue, cause, None)
            {
                log::error!("Attach Reject send failed: {e}");
            }
        }
        Err(e) => log::error!("[{}] AIA rejected: {e:?}", mme_ue.imsi_bcd),
    }
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
        let cause = emm_cause_from_diameter(Some(result_code::DIAMETER_SUCCESS), None);
        assert_eq!(cause, EmmCause::RequestAccepted);
    }

    #[test]
    fn test_emm_cause_from_diameter_user_unknown() {
        let cause =
            emm_cause_from_diameter(None, Some(experimental_result::DIAMETER_ERROR_USER_UNKNOWN));
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
    fn test_diameter_error_from_nextgcore() {
        let io_err = nextgcore_diameter::error::DiameterError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        let local: DiameterError = io_err.into();
        assert_eq!(local, DiameterError::ConnectionFailed);

        let proto_err = nextgcore_diameter::error::DiameterError::Protocol("test".to_string());
        let local: DiameterError = proto_err.into();
        assert_eq!(local, DiameterError::SendFailed);

        let inv_err = nextgcore_diameter::error::DiameterError::InvalidMessage("bad".to_string());
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
        let result = mme_s6a_send_air(&mme_ue, None).await;
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
        let result = mme_s6a_send_air(&mme_ue, None).await;
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

    /// The MME must parse the grouped Subscription-Data exactly as the HSS
    /// encodes it, across a real wire encode/decode cycle.
    #[test]
    fn test_parse_subscription_data_grouped_wire_roundtrip() {
        let mut sub = SubscriptionData {
            network_access_mode: 2,
            subscribed_rau_tau_timer: 720,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            context_identifier: 1,
            all_apn_configs_included: true,
            charging_characteristics: Some([0x0A, 0x00]),
            ..Default::default()
        };
        sub.apn_configs.push(ApnConfiguration {
            context_identifier: 1,
            service_selection: "internet".to_string(),
            pdn_type: 2, // IPv4v6
            qci: 9,
            arp_priority_level: 8,
            arp_pre_emption_capability: false,
            arp_pre_emption_vulnerability: true,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            charging_characteristics: None,
        });

        // Simulate the HSS side: ULA with grouped Subscription-Data over the wire
        let mut ula = nextgcore_diameter::message::DiameterMessage::new_request(316, 16777251);
        ula.header.flags &= !nextgcore_diameter::message::cmd_flags::REQUEST;
        ula.add_avp(s6a::build_subscription_data_avp(&sub));
        let encoded = ula.encode();
        let mut bytes = encoded.freeze();
        let decoded = nextgcore_diameter::message::DiameterMessage::decode(&mut bytes).unwrap();

        // MME side parse: AMBR and APN config must NOT be lost
        let parsed = decoded
            .find_avp(avp_code::SUBSCRIPTION_DATA)
            .map(s6a::parse_subscription_data_avp)
            .unwrap_or_default();
        assert_eq!(parsed, sub);
        assert_eq!(parsed.ambr_uplink, 50_000_000);
        assert_eq!(parsed.apn_configs.len(), 1);
        assert_eq!(parsed.apn_configs[0].service_selection, "internet");
        assert_eq!(parsed.apn_configs[0].qci, 9);
    }

    /// Parsing a message without Subscription-Data yields empty defaults.
    #[test]
    fn test_parse_subscription_data_empty() {
        let msg = nextgcore_diameter::message::DiameterMessage::new_request(316, 16777251);
        let sub = msg
            .find_avp(avp_code::SUBSCRIPTION_DATA)
            .map(s6a::parse_subscription_data_avp)
            .unwrap_or_default();
        assert!(sub.msisdn.is_empty());
        assert!(sub.apn_configs.is_empty());
        assert_eq!(sub.ambr_uplink, 0);
        assert_eq!(sub.ambr_downlink, 0);
    }

    /// AIR re-sync must carry RAND||AUTS inside
    /// Requested-EUTRAN-Authentication-Info (TS 29.272 7.3.11), not top-level.
    #[test]
    fn test_air_resync_inside_requested_eutran_auth_info() {
        let mut air = s6a::create_air(
            "sess-1",
            "mme.example.org",
            "example.org",
            "example.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            1,
        );
        let rand = [0x5A; 16];
        let auts = [0xC3; 14];
        assert!(s6a::add_resync_info(&mut air, &rand, &auts));

        let encoded = air.encode();
        let mut bytes = encoded.freeze();
        let decoded = nextgcore_diameter::message::DiameterMessage::decode(&mut bytes).unwrap();

        assert!(decoded.find_avp(s6a::avp::RE_SYNC_INFO).is_none());
        let (r, a) = s6a::find_resync_info(&decoded).expect("resync info inside grouped AVP");
        assert_eq!(r, rand);
        assert_eq!(a, auts);
    }
}
