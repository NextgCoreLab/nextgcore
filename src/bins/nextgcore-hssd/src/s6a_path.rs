//! HSS S6a Diameter Path
//!
//! Port of src/hss/hss-s6a-path.c - S6a interface handlers for EPC (TS 29.272)
//! Handles AIR (Authentication-Information-Request), ULR (Update-Location-Request),
//! PUR (Purge-UE-Request) and transmits CLR (Cancel-Location-Request) and
//! IDR (Insert-Subscriber-Data-Request) towards the MME.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use ogs_diameter::s6a::{self, EUtranVector};
use ogs_diameter::{avp_code, Avp, AvpData, DiameterMessage, OGS_3GPP_VENDOR_ID};

use crate::fd_path::diam_stats;

/// S6a Application ID
pub const OGS_DIAM_S6A_APPLICATION_ID: u32 = 16777251;

/// 48-bit SQN mask (TS 33.102)
const SQN_MASK: u64 = 0xFFFF_FFFF_FFFF;

/// SQN increment per generated vector (matches ogs_dbi_increment_sqn step)
const SQN_STEP: u64 = 32;

/// Maximum number of E-UTRAN vectors generated per AIR
const MAX_VECTORS_PER_AIR: u32 = 4;

/// S6a Cancellation Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationType {
    /// MME Update Procedure
    MmeUpdateProcedure = 0,
    /// SGSN Update Procedure
    SgsnUpdateProcedure = 1,
    /// Subscription Withdrawal
    SubscriptionWithdrawal = 2,
    /// Update Procedure IWF
    UpdateProcedureIwf = 3,
    /// Initial Attach Procedure
    InitialAttachProcedure = 4,
}

impl From<u32> for CancellationType {
    fn from(value: u32) -> Self {
        match value {
            0 => CancellationType::MmeUpdateProcedure,
            1 => CancellationType::SgsnUpdateProcedure,
            2 => CancellationType::SubscriptionWithdrawal,
            3 => CancellationType::UpdateProcedureIwf,
            4 => CancellationType::InitialAttachProcedure,
            _ => CancellationType::SubscriptionWithdrawal,
        }
    }
}

/// S6a Subscription Data Mask flags
pub const OGS_DIAM_S6A_SUBDATA_MSISDN: u32 = 0x0001;
pub const OGS_DIAM_S6A_SUBDATA_ARD: u32 = 0x0002;
pub const OGS_DIAM_S6A_SUBDATA_SUB_STATUS: u32 = 0x0004;
pub const OGS_DIAM_S6A_SUBDATA_OP_DET_BARRING: u32 = 0x0008;
pub const OGS_DIAM_S6A_SUBDATA_NAM: u32 = 0x0010;
pub const OGS_DIAM_S6A_SUBDATA_UEAMBR: u32 = 0x0020;
pub const OGS_DIAM_S6A_SUBDATA_RAU_TAU_TIMER: u32 = 0x0040;
pub const OGS_DIAM_S6A_SUBDATA_APN_CONFIG: u32 = 0x0080;
pub const OGS_DIAM_S6A_SUBDATA_ALL: u32 = 0xFFFF;

/// S6a Result Codes
pub const OGS_DIAM_S6A_ERROR_USER_UNKNOWN: u32 = 5001;
pub const OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;

// ============================================================================
// Failure model (TS 29.272 7.4 + RFC 6733 7.1)
// ============================================================================

/// S6a procedure failure. Each variant maps to the spec-defined answer codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aFailure {
    /// DIAMETER_MISSING_AVP (5005)
    MissingAvp,
    /// DIAMETER_COMMAND_UNSUPPORTED (3001, protocol error: E-bit)
    UnsupportedCommand,
    /// DIAMETER_ERROR_USER_UNKNOWN (Experimental 5001)
    UserUnknown,
    /// DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE (Experimental 4181)
    AuthDataUnavailable,
    /// DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (Experimental 5420)
    UnknownEpsSubscription,
    /// DIAMETER_UNABLE_TO_COMPLY (5012)
    UnableToComply(String),
}

impl S6aFailure {
    /// Returns (Result-Code, Experimental-Result-Code) for the answer.
    pub fn codes(&self) -> (Option<u32>, Option<u32>) {
        match self {
            S6aFailure::MissingAvp => (Some(5005), None),
            S6aFailure::UnsupportedCommand => (Some(3001), None),
            S6aFailure::UserUnknown => (None, Some(s6a::exp_result::ERROR_USER_UNKNOWN)),
            S6aFailure::AuthDataUnavailable => (
                None,
                Some(s6a::exp_result::AUTHENTICATION_DATA_UNAVAILABLE),
            ),
            S6aFailure::UnknownEpsSubscription => (
                None,
                Some(s6a::exp_result::ERROR_UNKNOWN_EPS_SUBSCRIPTION),
            ),
            S6aFailure::UnableToComply(_) => (Some(5012), None),
        }
    }

    /// Protocol errors (3xxx) set the E-bit in the answer header (RFC 6733 7.2)
    pub fn is_protocol_error(&self) -> bool {
        matches!(self.codes().0, Some(code) if (3000..4000).contains(&code))
    }
}

fn map_dbi_error(e: &ogs_dbi::DbiError) -> S6aFailure {
    match e {
        ogs_dbi::DbiError::SubscriberNotFound(_) => S6aFailure::UserUnknown,
        other => S6aFailure::UnableToComply(other.to_string()),
    }
}

// ============================================================================
// Local Diameter identity (Origin-Host / Origin-Realm)
// ============================================================================

fn local_identity() -> &'static RwLock<(String, String)> {
    static IDENTITY: OnceLock<RwLock<(String, String)>> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        RwLock::new((
            "hss.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
            "epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        ))
    })
}

/// Set the HSS Diameter identity used in Origin-Host/Origin-Realm AVPs.
/// Must be called at startup from the loaded configuration.
pub fn hss_s6a_set_identity(origin_host: &str, origin_realm: &str) {
    let mut guard = local_identity().write().expect("identity lock poisoned");
    *guard = (origin_host.to_string(), origin_realm.to_string());
}

fn origin_host_realm() -> (String, String) {
    local_identity()
        .read()
        .expect("identity lock poisoned")
        .clone()
}

/// Generate a unique Session-Id (RFC 6733 8.8: <DiameterIdentity>;<high>;<low>)
fn next_session_id(suffix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let (host, _) = origin_host_realm();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{host};{now};{count};{suffix}")
}

/// Next Hop-by-Hop / End-to-End identifiers for HSS-initiated requests
/// (RFC 6733 Section 3: unique, seeded from time at startup).
fn next_request_ids() -> (u32, u32) {
    static IDS: OnceLock<AtomicU32> = OnceLock::new();
    let counter = IDS.get_or_init(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        AtomicU32::new((now.as_secs() as u32) << 20 | (now.subsec_nanos() & 0xFFFFF))
    });
    let id = counter.fetch_add(1, Ordering::Relaxed);
    (id, id)
}

// ============================================================================
// MME peer registry (for HSS-initiated CLR/IDR)
// ============================================================================

type PeerSenders = HashMap<String, tokio::sync::mpsc::UnboundedSender<DiameterMessage>>;

fn peer_registry() -> &'static RwLock<PeerSenders> {
    static REGISTRY: OnceLock<RwLock<PeerSenders>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a connected MME peer's outbound channel (keyed by Origin-Host).
pub fn register_mme_peer(
    origin_host: &str,
    sender: tokio::sync::mpsc::UnboundedSender<DiameterMessage>,
) {
    peer_registry()
        .write()
        .expect("peer registry lock poisoned")
        .insert(origin_host.to_string(), sender);
    log::info!("S6a peer registered: {origin_host}");
}

/// Unregister an MME peer on disconnect.
pub fn unregister_mme_peer(origin_host: &str) {
    peer_registry()
        .write()
        .expect("peer registry lock poisoned")
        .remove(origin_host);
    log::info!("S6a peer unregistered: {origin_host}");
}

/// Send an HSS-initiated request to a connected MME peer.
fn send_to_mme(dest_host: &str, msg: DiameterMessage) -> Result<(), String> {
    let registry = peer_registry()
        .read()
        .expect("peer registry lock poisoned");
    let sender = registry
        .get(dest_host)
        .ok_or_else(|| format!("no connected S6a peer for {dest_host}"))?;
    sender
        .send(msg)
        .map_err(|_| format!("S6a peer connection to {dest_host} is closed"))
}

/// Initialize S6a interface
pub fn hss_s6a_init() -> Result<(), String> {
    log::info!("Initializing HSS S6a interface");
    Ok(())
}

/// Finalize S6a interface
pub fn hss_s6a_final() {
    log::info!("Finalizing HSS S6a interface");
}

// ============================================================================
// Authentication vector generation (AIR -> AIA)
// ============================================================================

/// Generate a fresh, cryptographically random RAND for each vector
/// (TS 33.401: RAND must not be fixed or reused).
fn fresh_rand() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn sqn_to_bytes(sqn: u64) -> [u8; 6] {
    [
        ((sqn >> 40) & 0xFF) as u8,
        ((sqn >> 32) & 0xFF) as u8,
        ((sqn >> 24) & 0xFF) as u8,
        ((sqn >> 16) & 0xFF) as u8,
        ((sqn >> 8) & 0xFF) as u8,
        (sqn & 0xFF) as u8,
    ]
}

/// Verify an AUTS re-synchronisation token and extract SQN_MS
/// (TS 33.102 6.3.5: AUTS = SQN_MS xor AK* || MAC-S, MAC-S = f1*(SQN_MS, RAND, AMF=0)).
///
/// `rand` is the RAND of the challenge that failed synchronisation
/// (carried in Re-Synchronization-Info alongside AUTS).
pub fn process_resync(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
    auts: &[u8; 14],
) -> Result<u64, S6aFailure> {
    use ogs_crypt::milenage::milenage_auts;

    let sqn_ms = milenage_auts(opc, k, rand, auts).map_err(|_| {
        log::warn!("AUTS re-synchronisation failed: MAC-S mismatch");
        S6aFailure::AuthDataUnavailable
    })?;

    let mut sqn = 0u64;
    for b in sqn_ms {
        sqn = (sqn << 8) | b as u64;
    }
    Ok(sqn)
}

/// AIR Response: one or more E-UTRAN authentication vectors
#[derive(Debug, Default)]
pub struct AirResponse {
    /// Generated E-UTRAN vectors (ordered; Item-Number = index + 1)
    pub vectors: Vec<EUtranVector>,
}

/// Handle Authentication-Information-Request (AIR)
///
/// # Arguments
/// * `imsi_bcd` - IMSI in BCD format
/// * `visited_plmn_id` - 3-byte Visited-PLMN-Id from the AIR
/// * `resync` - (RAND, AUTS) from Re-Synchronization-Info, if present
/// * `num_vectors` - Number-Of-Requested-Vectors from the AIR
pub fn handle_air(
    imsi_bcd: &str,
    visited_plmn_id: &[u8],
    resync: Option<([u8; 16], [u8; 14])>,
    num_vectors: u32,
) -> Result<AirResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling AIR (vectors={num_vectors})");

    use ogs_crypt::kdf::ogs_auc_kasme;
    use ogs_crypt::milenage::{milenage_f1, milenage_f2345, milenage_opc};
    use ogs_dbi::{ogs_dbi_auth_info, ogs_dbi_update_sqn};

    // 1. Get auth info from DB (K, OPc, SQN, AMF)
    let supi = format!("imsi-{imsi_bcd}");
    let auth_info = ogs_dbi_auth_info(&supi).map_err(|e| map_dbi_error(&e))?;

    // 2. Compute OPc from OP if needed
    let opc = if auth_info.use_opc {
        auth_info.opc
    } else {
        milenage_opc(&auth_info.k, &auth_info.op)
            .map_err(|_| S6aFailure::UnableToComply("OPc computation failed".into()))?
    };

    // 3. Re-synchronise SQN from AUTS if requested (real f1*/f5* verification,
    //    not a blind SQN bump)
    let mut sqn = auth_info.sqn & SQN_MASK;
    if let Some((auts_rand, auts)) = resync {
        log::debug!("[{imsi_bcd}] Performing AUTS-based SQN re-synchronisation");
        let sqn_ms = process_resync(&opc, &auth_info.k, &auts_rand, &auts)?;
        log::debug!("[{imsi_bcd}] Re-sync OK: SQN_HE={sqn:#x} -> SQN_MS={sqn_ms:#x}");
        sqn = sqn_ms;
    }

    // 4. Generate the requested number of vectors, each with a fresh random
    //    RAND and a strictly increasing SQN
    let n = num_vectors.clamp(1, MAX_VECTORS_PER_AIR);
    let plmn_id: [u8; 3] = [
        visited_plmn_id.first().copied().unwrap_or(0),
        visited_plmn_id.get(1).copied().unwrap_or(0),
        visited_plmn_id.get(2).copied().unwrap_or(0),
    ];

    let mut vectors = Vec::with_capacity(n as usize);
    for _ in 0..n {
        sqn = sqn.wrapping_add(SQN_STEP) & SQN_MASK;
        let sqn_bytes = sqn_to_bytes(sqn);
        let rand = fresh_rand();

        let (mac_a, _mac_s) = milenage_f1(&opc, &auth_info.k, &rand, &sqn_bytes, &auth_info.amf)
            .map_err(|_| S6aFailure::UnableToComply("f1 computation failed".into()))?;
        let (res, ck, ik, ak, _ak_star) = milenage_f2345(&opc, &auth_info.k, &rand)
            .map_err(|_| S6aFailure::UnableToComply("f2-f5 computation failed".into()))?;

        // AUTN = SQN ^ AK || AMF || MAC-A
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn_bytes[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&auth_info.amf);
        autn[8..16].copy_from_slice(&mac_a);

        let kasme = ogs_auc_kasme(&ck, &ik, &plmn_id, &sqn_bytes, &ak);

        vectors.push(EUtranVector {
            rand,
            xres: res.to_vec(),
            autn,
            kasme,
        });
    }

    // 5. Persist the new SQN
    ogs_dbi_update_sqn(&supi, sqn).map_err(|e| map_dbi_error(&e))?;

    Ok(AirResponse { vectors })
}

// ============================================================================
// Update-Location (ULR -> ULA)
// ============================================================================

/// ULR Response: subscription data for the ULA
#[derive(Debug, Default)]
pub struct UlrResponse {
    /// EPS subscription data (encoded as a grouped Subscription-Data AVP)
    pub subscription_data: s6a::SubscriptionData,
}

/// Convert the database subscription record into the S6a typed model
/// (TS 29.272 7.3.2 Subscription-Data).
pub fn subscription_data_from_db(db: &ogs_dbi::OgsSubscriptionData) -> s6a::SubscriptionData {
    let mut sub = s6a::SubscriptionData {
        subscriber_status: db.subscriber_status as u32,
        operator_determined_barring: if db.subscriber_status == 1 {
            Some(db.operator_determined_barring as u32)
        } else {
            None
        },
        access_restriction_data: Some(db.access_restriction_data as u32),
        network_access_mode: db.network_access_mode as u32,
        subscribed_rau_tau_timer: (db.subscribed_rau_tau_timer.max(0) as u32) * 60, // minutes -> seconds
        ambr_uplink: db.ambr.uplink,
        ambr_downlink: db.ambr.downlink,
        context_identifier: 1,
        all_apn_configs_included: true,
        ..Default::default()
    };

    if let Some(m) = db.msisdn.first() {
        sub.msisdn = m.buf[..m.len.min(m.buf.len())].to_vec();
    }
    if let Some(m) = db.msisdn.get(1) {
        sub.a_msisdn = m.buf[..m.len.min(m.buf.len())].to_vec();
    }

    let mut context_id = 1u32;
    for slice in &db.slice {
        for session in &slice.session {
            let apn = s6a::ApnConfiguration {
                context_identifier: context_id,
                service_selection: session
                    .name
                    .clone()
                    .unwrap_or_else(|| "internet".to_string()),
                // DB session_type: 1=IPv4, 2=IPv6, 3=IPv4v6 -> Diameter PDN-Type
                pdn_type: match session.session_type {
                    1 => s6a::pdn_type::IPV4 as u8,
                    2 => s6a::pdn_type::IPV6 as u8,
                    _ => s6a::pdn_type::IPV4V6 as u8,
                },
                qci: session.qos.index,
                arp_priority_level: session.qos.arp.priority_level,
                arp_pre_emption_capability: session.qos.arp.pre_emption_capability != 0,
                arp_pre_emption_vulnerability: session.qos.arp.pre_emption_vulnerability != 0,
                ambr_uplink: session.ambr.uplink,
                ambr_downlink: session.ambr.downlink,
                charging_characteristics: None,
            };
            sub.apn_configs.push(apn);
            context_id += 1;
        }
    }

    sub
}

/// Handle Update-Location-Request (ULR)
pub fn handle_ulr(
    imsi_bcd: &str,
    _visited_plmn_id: &[u8],
    ulr_flags: u32,
    mme_host: &str,
    mme_realm: &str,
) -> Result<UlrResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling ULR from {mme_host}.{mme_realm} (flags={ulr_flags:#x})");

    use ogs_dbi::{ogs_dbi_subscription_data, ogs_dbi_update_mme};

    // 1. Update serving MME in DB
    let supi = format!("imsi-{imsi_bcd}");
    ogs_dbi_update_mme(&supi, mme_host, mme_realm, true).map_err(|e| map_dbi_error(&e))?;

    // 2. Get subscription data from DB
    let db_data = ogs_dbi_subscription_data(&supi).map_err(|e| map_dbi_error(&e))?;

    // 3. Convert to S6a Subscription-Data; a subscriber without any APN
    //    configuration has no EPS subscription (TS 29.272 5.2.1.1.3)
    let subscription_data = subscription_data_from_db(&db_data);
    let skip_subscriber_data = ulr_flags & s6a::ulr_flags::SKIP_SUBSCRIBER_DATA != 0;
    if subscription_data.apn_configs.is_empty() && !skip_subscriber_data {
        log::warn!("[{imsi_bcd}] No APN configuration: unknown EPS subscription");
        return Err(S6aFailure::UnknownEpsSubscription);
    }

    log::debug!("[{imsi_bcd}] ULR handled successfully");
    Ok(UlrResponse { subscription_data })
}

// ============================================================================
// Purge-UE (PUR -> PUA)
// ============================================================================

/// PUR Response
#[derive(Debug, Default)]
pub struct PurResponse {
    /// PUA-Flags to return (TS 29.272 7.3.49)
    pub pua_flags: u32,
}

/// Handle Purge-UE-Request (PUR)
pub fn handle_pur(imsi_bcd: &str, pur_flags: u32) -> Result<PurResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling PUR (flags={pur_flags:#x})");

    use ogs_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    let collection = get_subscriber_collection()
        .map_err(|e| S6aFailure::UnableToComply(format!("subscriber collection: {e}")))?;

    let query = doc! { "imsi": imsi_bcd };
    let update = doc! {
        "$set": {
            "purged": true,
            "purge_flags": pur_flags as i32,
        }
    };

    let result = collection
        .update_one(query, update, None)
        .map_err(|e| S6aFailure::UnableToComply(format!("purge update: {e}")))?;
    if result.matched_count == 0 {
        return Err(S6aFailure::UserUnknown);
    }

    // The UE was purged from the MME: tell the MME to freeze the M-TMSI
    // (TS 29.272 5.2.1.3.3)
    let mut pua_flags = 0;
    if pur_flags & s6a::pur_flags::UE_PURGED_IN_MME != 0 || pur_flags == 0 {
        pua_flags |= s6a::pua_flags::FREEZE_MTMSI;
    }
    if pur_flags & s6a::pur_flags::UE_PURGED_IN_SGSN != 0 {
        pua_flags |= s6a::pua_flags::FREEZE_PTMSI;
    }

    log::debug!("[{imsi_bcd}] PUR handled successfully (pua_flags={pua_flags:#x})");
    Ok(PurResponse { pua_flags })
}

// ============================================================================
// Answer builders
// ============================================================================

/// Add Origin-Host and Origin-Realm AVPs from the configured HSS identity
fn add_origin_avps(msg: &mut DiameterMessage) {
    let (host, realm) = origin_host_realm();
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(realm),
    ));
}

fn new_answer_with_common(request: &DiameterMessage) -> DiameterMessage {
    let mut answer = DiameterMessage::new_answer(request);
    if let Some(sid) = request.session_id() {
        answer.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    answer
}

/// Build a successful AIA from generated vectors
pub fn build_aia_answer(request: &DiameterMessage, resp: &AirResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);

    let many = resp.vectors.len() > 1;
    let vector_avps: Vec<Avp> = resp
        .vectors
        .iter()
        .enumerate()
        .map(|(i, v)| s6a::build_e_utran_vector_avp(many.then_some(i as u32 + 1), v))
        .collect();
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::AUTHENTICATION_INFO,
        OGS_3GPP_VENDOR_ID,
        AvpData::Grouped(vector_avps),
    ));
    answer
}

/// Build a successful ULA carrying grouped Subscription-Data
pub fn build_ula_answer(request: &DiameterMessage, resp: &UlrResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);

    // ULA-Flags: Separation Indication (TS 29.272 7.3.8)
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::ULA_FLAGS,
        OGS_3GPP_VENDOR_ID,
        AvpData::Unsigned32(1),
    ));
    answer.add_avp(s6a::build_subscription_data_avp(&resp.subscription_data));
    answer
}

/// Build a successful PUA carrying PUA-Flags
pub fn build_pua_answer(request: &DiameterMessage, resp: &PurResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::PUA_FLAGS,
        OGS_3GPP_VENDOR_ID,
        AvpData::Unsigned32(resp.pua_flags),
    ));
    answer
}

/// Build a Diameter error answer for the given failure.
///
/// 3GPP-specific failures use Experimental-Result (vendor 10415); base
/// protocol failures use Result-Code. The E-bit is set only for protocol
/// errors (RFC 6733 7.2).
pub fn build_failure_answer(request: &DiameterMessage, failure: &S6aFailure) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    let (result_code, exp_code) = failure.codes();
    if let Some(code) = result_code {
        answer.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(code),
        ));
    }
    if let Some(code) = exp_code {
        answer.add_avp(s6a::experimental_result_avp(code));
    }
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);
    if failure.is_protocol_error() {
        answer.header.set_error();
    }
    answer
}

// ============================================================================
// S6a Diameter Message Dispatch
// ============================================================================

/// Dispatch an incoming S6a Diameter request and produce an answer.
///
/// NOTE: this performs blocking MongoDB I/O. From async contexts use
/// [`dispatch_s6a_request_async`], which moves the work off the Diameter
/// dispatch thread.
pub fn dispatch_s6a_request(request: &DiameterMessage) -> Option<DiameterMessage> {
    use ogs_diameter::s6a::{avp as s6a_avp, cmd};

    let cmd_code = request.header.command_code;

    if request.header.application_id != s6a::S6A_APPLICATION_ID {
        log::warn!(
            "Non-S6a message received: app_id={}",
            request.header.application_id
        );
        return None;
    }
    if !request.header.is_request() {
        return None;
    }

    // User-Name (IMSI) is mandatory in AIR/ULR/PUR (TS 29.272 7.2.x)
    let imsi_bcd = match request.user_name() {
        Some(imsi) => imsi.to_string(),
        None => {
            log::error!("S6a request missing User-Name (IMSI)");
            return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
        }
    };

    match cmd_code {
        cmd::AUTHENTICATION_INFORMATION => {
            log::debug!("[{imsi_bcd}] Dispatching AIR");
            diam_stats().s6a.inc_rx_air();

            // Visited-PLMN-Id is mandatory in AIR (TS 29.272 Table 7.2.5/1)
            let Some(visited_plmn_id) = request
                .find_vendor_avp(s6a_avp::VISITED_PLMN_ID, OGS_3GPP_VENDOR_ID)
                .and_then(|a| a.as_octet_string())
                .map(|b| b.to_vec())
            else {
                diam_stats().s6a.inc_rx_air_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };

            // Requested-EUTRAN-Authentication-Info carries the vector count and
            // the AUTS re-synchronisation token (TS 29.272 7.3.11)
            if request.find_avp(s6a_avp::REQ_EUTRAN_AUTH_INFO).is_none() {
                diam_stats().s6a.inc_rx_air_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            }
            let num_vectors = s6a::find_num_requested_vectors(request).unwrap_or(1);
            let resync = s6a::find_resync_info(request);

            match handle_air(&imsi_bcd, &visited_plmn_id, resync, num_vectors) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_aia();
                    Some(build_aia_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] AIR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_air_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        cmd::UPDATE_LOCATION => {
            log::debug!("[{imsi_bcd}] Dispatching ULR");
            diam_stats().s6a.inc_rx_ulr();

            // Visited-PLMN-Id, RAT-Type and ULR-Flags are mandatory in ULR
            // (TS 29.272 Table 7.2.3/1)
            let Some(visited_plmn_id) = request
                .find_vendor_avp(s6a_avp::VISITED_PLMN_ID, OGS_3GPP_VENDOR_ID)
                .and_then(|a| a.as_octet_string())
                .map(|b| b.to_vec())
            else {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };
            if request
                .find_vendor_avp(ogs_diameter::common::avp_code::RAT_TYPE, OGS_3GPP_VENDOR_ID)
                .is_none()
            {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            }
            let Some(ulr_flags_val) = request
                .find_vendor_avp(s6a_avp::ULR_FLAGS, OGS_3GPP_VENDOR_ID)
                .and_then(|a| a.as_u32())
            else {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };

            let mme_host = request.origin_host().unwrap_or("unknown").to_string();
            let mme_realm = request.origin_realm().unwrap_or("unknown").to_string();

            match handle_ulr(
                &imsi_bcd,
                &visited_plmn_id,
                ulr_flags_val,
                &mme_host,
                &mme_realm,
            ) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_ula();
                    Some(build_ula_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] ULR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_ulr_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        cmd::PURGE_UE => {
            log::debug!("[{imsi_bcd}] Dispatching PUR");
            diam_stats().s6a.inc_rx_pur();

            // PUR-Flags is optional in PUR (TS 29.272 Table 7.2.13/1)
            let pur_flags = request
                .find_vendor_avp(s6a_avp::PUR_FLAGS, OGS_3GPP_VENDOR_ID)
                .and_then(|a| a.as_u32())
                .unwrap_or(0);

            match handle_pur(&imsi_bcd, pur_flags) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_pua();
                    Some(build_pua_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] PUR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_pur_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        _ => {
            log::warn!("[{imsi_bcd}] Unknown S6a command code: {cmd_code}");
            diam_stats().s6a.inc_rx_unknown();
            Some(build_failure_answer(
                request,
                &S6aFailure::UnsupportedCommand,
            ))
        }
    }
}

/// Async wrapper for [`dispatch_s6a_request`]: runs the blocking MongoDB work
/// on the tokio blocking pool so the Diameter dispatch task is never stalled.
pub async fn dispatch_s6a_request_async(request: DiameterMessage) -> Option<DiameterMessage> {
    match tokio::task::spawn_blocking(move || dispatch_s6a_request(&request)).await {
        Ok(answer) => answer,
        Err(e) => {
            log::error!("S6a dispatch task panicked: {e}");
            None
        }
    }
}

/// Handle an answer to an HSS-initiated request (CLA / IDA).
pub fn handle_s6a_answer(answer: &DiameterMessage) {
    use ogs_diameter::s6a::cmd;
    let result_code = answer.result_code();
    let exp_code = s6a::experimental_result_code(answer);
    let success = result_code == Some(2001);
    match answer.header.command_code {
        cmd::CANCEL_LOCATION => {
            diam_stats().s6a.inc_rx_cla();
            if !success {
                diam_stats().s6a.inc_rx_cla_error();
                log::warn!("CLA failure: result={result_code:?} experimental={exp_code:?}");
            }
        }
        cmd::INSERT_SUBSCRIBER_DATA => {
            diam_stats().s6a.inc_rx_ida();
            if !success {
                diam_stats().s6a.inc_rx_ida_error();
                log::warn!("IDA failure: result={result_code:?} experimental={exp_code:?}");
            }
        }
        other => {
            diam_stats().s6a.inc_rx_unknown();
            log::warn!("Unexpected S6a answer: cmd={other}");
        }
    }
}

// ============================================================================
// S6a server (Diameter responder + HSS-initiated requests)
// ============================================================================

/// Run the HSS S6a Diameter server.
///
/// Accepts MME connections, answers AIR/ULR/PUR (Mongo work on the blocking
/// pool) and forwards HSS-initiated CLR/IDR queued via
/// [`hss_s6a_send_clr`]/[`hss_s6a_send_idr`] over the peer's connection.
pub async fn hss_s6a_run_server(
    addr: std::net::SocketAddr,
    config: ogs_diameter::config::DiameterConfig,
) -> Result<(), String> {
    use ogs_diameter::transport::DiameterListener;

    let listener = DiameterListener::bind(addr)
        .await
        .map_err(|e| format!("S6a listener bind failed: {e}"))?;
    log::info!("HSS S6a Diameter server listening on {addr}");
    hss_s6a_serve(listener, config).await
}

/// Serve S6a on an already-bound listener (see [`hss_s6a_run_server`]).
pub async fn hss_s6a_serve(
    listener: ogs_diameter::transport::DiameterListener,
    config: ogs_diameter::config::DiameterConfig,
) -> Result<(), String> {
    hss_s6a_set_identity(&config.diameter_id, &config.diameter_realm);

    loop {
        match listener.accept().await {
            Ok(transport) => {
                let peer_addr = transport.peer_addr();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_s6a_peer(transport, config).await {
                        log::warn!("S6a peer {peer_addr} closed: {e}");
                    }
                });
            }
            Err(e) => log::warn!("S6a accept failed: {e}"),
        }
    }
}

async fn run_s6a_peer(
    transport: ogs_diameter::transport::DiameterTransport,
    config: ogs_diameter::config::DiameterConfig,
) -> Result<(), String> {
    use ogs_diameter::peer::{DiameterPeer, PeerEvent};

    let mut peer = DiameterPeer::new_responder(transport, &config);
    peer.start().await.map_err(|e| e.to_string())?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DiameterMessage>();
    let mut registered_host: Option<String> = None;

    let result = loop {
        tokio::select! {
            event = peer.next_event() => match event {
                Ok(PeerEvent::Established { origin_host, origin_realm }) => {
                    log::info!("S6a peer established: {origin_host} ({origin_realm})");
                    register_mme_peer(&origin_host, tx.clone());
                    registered_host = Some(origin_host);
                }
                Ok(PeerEvent::Message(msg)) if msg.header.is_request() => {
                    if let Some(answer) = dispatch_s6a_request_async(msg).await {
                        if let Err(e) = peer.send_message(&answer).await {
                            break Err(e.to_string());
                        }
                    }
                }
                Ok(PeerEvent::Message(msg)) => handle_s6a_answer(&msg),
                Ok(PeerEvent::WatchdogAck) => {}
                Ok(PeerEvent::Disconnected) => break Ok(()),
                Err(e) => break Err(e.to_string()),
            },
            Some(outbound) = rx.recv() => {
                if let Err(e) = peer.send_message(&outbound).await {
                    break Err(e.to_string());
                }
            }
        }
    };

    if let Some(host) = registered_host {
        unregister_mme_peer(&host);
    }
    result
}

// ============================================================================
// HSS-initiated requests: CLR / IDR
// ============================================================================

/// Look up the serving MME's Diameter host/realm for a subscriber.
///
/// NOTE: blocking MongoDB I/O; call from a blocking-safe context.
fn lookup_serving_mme(imsi_bcd: &str) -> Result<(String, String), String> {
    use ogs_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    let collection = get_subscriber_collection()
        .map_err(|e| format!("Failed to get subscriber collection: {e}"))?;

    let query = doc! { "imsi": imsi_bcd };
    let doc = collection
        .find_one(query, None)
        .map_err(|e| format!("Failed to query DB: {e}"))?
        .ok_or_else(|| format!("Subscriber not found: {imsi_bcd}"))?;

    let host = doc
        .get_str("mme_host")
        .map_err(|_| format!("No serving MME recorded for {imsi_bcd}"))?
        .to_string();
    let realm = doc
        .get_str("mme_realm")
        .map_err(|_| format!("No serving MME realm recorded for {imsi_bcd}"))?
        .to_string();

    Ok((host, realm))
}

/// Build a Cancel-Location-Request (TS 29.272 Table 7.2.7/1).
pub fn build_clr_request(
    imsi_bcd: &str,
    dest_host: &str,
    dest_realm: &str,
    cancellation_type: CancellationType,
    clr_flags: Option<u32>,
) -> DiameterMessage {
    use ogs_diameter::s6a::{avp, cmd};

    let mut msg = DiameterMessage::new_request(cmd::CANCEL_LOCATION, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(imsi_bcd)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(imsi_bcd.to_string()),
    ));
    msg.add_avp(Avp::vendor_mandatory(
        avp::CANCELLATION_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(cancellation_type as i32),
    ));
    if let Some(flags) = clr_flags {
        msg.add_avp(Avp::vendor_mandatory(
            avp::CLR_FLAGS,
            OGS_3GPP_VENDOR_ID,
            AvpData::Unsigned32(flags),
        ));
    }
    msg
}

/// Build an Insert-Subscriber-Data-Request (TS 29.272 Table 7.2.9/1).
///
/// Subscription-Data is mandatory in IDR; `subdata_mask` selects which parts
/// of the subscription record are included.
pub fn build_idr_request(
    imsi_bcd: &str,
    dest_host: &str,
    dest_realm: &str,
    idr_flags: u32,
    subscription_data: &s6a::SubscriptionData,
    subdata_mask: u32,
) -> DiameterMessage {
    use ogs_diameter::s6a::{avp, cmd};

    // Apply the subdata mask
    let mut sub = subscription_data.clone();
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_MSISDN == 0 {
        sub.msisdn.clear();
        sub.a_msisdn.clear();
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_ARD == 0 {
        sub.access_restriction_data = None;
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_OP_DET_BARRING == 0 {
        sub.operator_determined_barring = None;
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_RAU_TAU_TIMER == 0 {
        sub.subscribed_rau_tau_timer = 0;
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_UEAMBR == 0 {
        sub.ambr_uplink = 0;
        sub.ambr_downlink = 0;
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_APN_CONFIG == 0 {
        sub.apn_configs.clear();
    }

    let mut msg =
        DiameterMessage::new_request(cmd::INSERT_SUBSCRIBER_DATA, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(imsi_bcd)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(imsi_bcd.to_string()),
    ));
    // Subscription-Data is mandatory in IDR
    msg.add_avp(s6a::build_subscription_data_avp(&sub));
    if idr_flags != 0 {
        msg.add_avp(Avp::vendor_mandatory(
            avp::IDR_FLAGS,
            OGS_3GPP_VENDOR_ID,
            AvpData::Unsigned32(idr_flags),
        ));
    }
    msg
}

/// Send Cancel-Location-Request to the serving MME.
///
/// The CLR is transmitted on the MME's existing S6a connection. Fails if the
/// MME is not currently connected.
///
/// NOTE: performs blocking MongoDB I/O when `mme_host`/`mme_realm` are not
/// provided; call from a blocking-safe context.
pub fn hss_s6a_send_clr(
    imsi_bcd: &str,
    mme_host: Option<&str>,
    mme_realm: Option<&str>,
    cancellation_type: CancellationType,
) -> Result<(), String> {
    log::info!("[{imsi_bcd}] Sending Cancel-Location-Request (type={cancellation_type:?})");

    let (dest_host, dest_realm) = if let (Some(h), Some(r)) = (mme_host, mme_realm) {
        (h.to_string(), r.to_string())
    } else {
        lookup_serving_mme(imsi_bcd)?
    };

    let clr = build_clr_request(imsi_bcd, &dest_host, &dest_realm, cancellation_type, None);
    send_to_mme(&dest_host, clr)?;

    diam_stats().s6a.inc_tx_clr();
    log::debug!("[{imsi_bcd}] CLR sent to {dest_host}");
    Ok(())
}

/// Send Insert-Subscriber-Data-Request to the serving MME.
///
/// The IDR is transmitted on the MME's existing S6a connection. Fails if the
/// MME is not currently connected.
///
/// NOTE: performs blocking MongoDB I/O; call from a blocking-safe context.
pub fn hss_s6a_send_idr(imsi_bcd: &str, idr_flags: u32, subdata_mask: u32) -> Result<(), String> {
    log::info!(
        "[{imsi_bcd}] Sending Insert-Subscriber-Data-Request (flags={idr_flags:#x}, mask={subdata_mask:#x})"
    );

    use ogs_dbi::ogs_dbi_subscription_data;

    let (dest_host, dest_realm) = lookup_serving_mme(imsi_bcd)?;

    let supi = format!("imsi-{imsi_bcd}");
    let db_data = ogs_dbi_subscription_data(&supi)
        .map_err(|e| format!("Failed to get subscription data: {e}"))?;
    let subscription_data = subscription_data_from_db(&db_data);

    let idr = build_idr_request(
        imsi_bcd,
        &dest_host,
        &dest_realm,
        idr_flags,
        &subscription_data,
        subdata_mask,
    );
    send_to_mme(&dest_host, idr)?;

    diam_stats().s6a.inc_tx_idr();
    log::debug!("[{imsi_bcd}] IDR sent to {dest_host}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_crypt::milenage::{milenage_f1, milenage_f2345};

    #[test]
    fn test_cancellation_type_from_u32() {
        assert_eq!(
            CancellationType::from(0),
            CancellationType::MmeUpdateProcedure
        );
        assert_eq!(
            CancellationType::from(2),
            CancellationType::SubscriptionWithdrawal
        );
        assert_eq!(
            CancellationType::from(99),
            CancellationType::SubscriptionWithdrawal
        );
    }

    #[test]
    fn test_s6a_init_final() {
        assert!(hss_s6a_init().is_ok());
        hss_s6a_final();
    }

    #[test]
    fn test_fresh_rand_is_not_reused() {
        let a = fresh_rand();
        let b = fresh_rand();
        let c = fresh_rand();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, [0u8; 16]);
    }

    /// Construct a valid AUTS with f1*/f5* and verify process_resync extracts
    /// the exact SQN_MS (TS 33.102 6.3.5).
    #[test]
    fn test_process_resync_valid_auts() {
        let k = [0x46u8; 16];
        let opc = [0x8Eu8; 16];
        let rand = [0x23u8; 16];
        let sqn_ms: u64 = 0x0001_2345_6789;
        let sqn_bytes = sqn_to_bytes(sqn_ms);
        let amf_resync = [0x00u8, 0x00];

        // AUTS = (SQN_MS xor AK*) || MAC-S
        let (_res, _ck, _ik, _ak, ak_star) = milenage_f2345(&opc, &k, &rand).unwrap();
        let (_mac_a, mac_s) = milenage_f1(&opc, &k, &rand, &sqn_bytes, &amf_resync).unwrap();
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = sqn_bytes[i] ^ ak_star[i];
        }
        auts[6..14].copy_from_slice(&mac_s);

        let extracted = process_resync(&opc, &k, &rand, &auts).unwrap();
        assert_eq!(extracted, sqn_ms);
    }

    /// A tampered AUTS (bad MAC-S) must be rejected with
    /// AUTHENTICATION_DATA_UNAVAILABLE, not silently accepted.
    #[test]
    fn test_process_resync_tampered_auts_rejected() {
        let k = [0x46u8; 16];
        let opc = [0x8Eu8; 16];
        let rand = [0x23u8; 16];
        let auts = [0xFFu8; 14];

        let result = process_resync(&opc, &k, &rand, &auts);
        assert_eq!(result.unwrap_err(), S6aFailure::AuthDataUnavailable);
    }

    #[test]
    fn test_subscription_data_from_db_mapping() {
        use ogs_dbi::{OgsAmbr, OgsArp, OgsQos, OgsSession, OgsSliceData, OgsSubscriptionData};

        let db = OgsSubscriptionData {
            subscriber_status: 0,
            network_access_mode: 2,
            subscribed_rau_tau_timer: 12, // minutes
            access_restriction_data: 0x20,
            ambr: OgsAmbr {
                uplink: 50_000_000,
                downlink: 100_000_000,
            },
            slice: vec![OgsSliceData {
                session: vec![OgsSession {
                    name: Some("internet".to_string()),
                    session_type: 3, // IPv4v6
                    qos: OgsQos {
                        index: 9,
                        arp: OgsArp {
                            priority_level: 8,
                            pre_emption_capability: 0,
                            pre_emption_vulnerability: 1,
                        },
                        ..Default::default()
                    },
                    ambr: OgsAmbr {
                        uplink: 1_000_000,
                        downlink: 2_000_000,
                    },
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let sub = subscription_data_from_db(&db);
        assert_eq!(sub.network_access_mode, 2);
        assert_eq!(sub.subscribed_rau_tau_timer, 720); // seconds
        assert_eq!(sub.ambr_uplink, 50_000_000);
        assert_eq!(sub.ambr_downlink, 100_000_000);
        assert_eq!(sub.apn_configs.len(), 1);
        let apn = &sub.apn_configs[0];
        assert_eq!(apn.context_identifier, 1);
        assert_eq!(apn.service_selection, "internet");
        assert_eq!(apn.pdn_type, ogs_diameter::s6a::pdn_type::IPV4V6 as u8);
        assert_eq!(apn.qci, 9);
        assert_eq!(apn.arp_priority_level, 8);
        assert!(!apn.arp_pre_emption_capability);
        assert!(apn.arp_pre_emption_vulnerability);
    }

    fn make_air() -> DiameterMessage {
        ogs_diameter::s6a::create_air(
            "test-session-1",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            1,
        )
    }

    /// AIA built from vectors must round-trip the wire and parse back.
    #[test]
    fn test_build_aia_answer_wire_roundtrip() {
        let air = make_air();
        let resp = AirResponse {
            vectors: vec![
                EUtranVector {
                    rand: [1; 16],
                    xres: vec![2; 8],
                    autn: [3; 16],
                    kasme: [4; 32],
                },
                EUtranVector {
                    rand: [5; 16],
                    xres: vec![6; 8],
                    autn: [7; 16],
                    kasme: [8; 32],
                },
            ],
        };
        let aia = build_aia_answer(&air, &resp);
        assert!(aia.header.is_answer());
        assert!(!aia.header.is_error());

        let encoded = aia.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();
        assert_eq!(decoded.result_code(), Some(2001));

        let vectors = ogs_diameter::s6a::parse_authentication_info(&decoded);
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].rand, [1; 16]);
        assert_eq!(vectors[1].kasme, [8; 32]);
    }

    /// ULA Subscription-Data must be a real grouped AVP that survives the wire.
    #[test]
    fn test_build_ula_answer_wire_roundtrip() {
        let ulr = ogs_diameter::s6a::create_ulr(
            "test-session-2",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            0x22,
            1004,
        );
        let mut sub = ogs_diameter::s6a::SubscriptionData {
            network_access_mode: 2,
            subscribed_rau_tau_timer: 720,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            context_identifier: 1,
            all_apn_configs_included: true,
            ..Default::default()
        };
        sub.apn_configs.push(ogs_diameter::s6a::ApnConfiguration {
            context_identifier: 1,
            service_selection: "internet".to_string(),
            pdn_type: ogs_diameter::s6a::pdn_type::IPV4V6 as u8,
            qci: 9,
            arp_priority_level: 8,
            arp_pre_emption_capability: false,
            arp_pre_emption_vulnerability: true,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            charging_characteristics: None,
        });
        let resp = UlrResponse {
            subscription_data: sub.clone(),
        };

        let ula = build_ula_answer(&ulr, &resp);
        let encoded = ula.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        assert_eq!(decoded.result_code(), Some(2001));
        let sub_avp = decoded
            .find_avp(ogs_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .expect("Subscription-Data AVP");
        assert!(sub_avp.is_vendor_specific());
        let parsed = ogs_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed, sub);
    }

    #[test]
    fn test_build_pua_answer_has_pua_flags() {
        let mut pur =
            DiameterMessage::new_request(ogs_diameter::s6a::cmd::PURGE_UE, OGS_DIAM_S6A_APPLICATION_ID);
        pur.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("pur-session".to_string()),
        ));
        let resp = PurResponse {
            pua_flags: ogs_diameter::s6a::pua_flags::FREEZE_MTMSI,
        };
        let pua = build_pua_answer(&pur, &resp);

        let encoded = pua.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();
        let flags = decoded
            .find_vendor_avp(ogs_diameter::s6a::avp::PUA_FLAGS, OGS_3GPP_VENDOR_ID)
            .and_then(|a| a.as_u32());
        assert_eq!(flags, Some(ogs_diameter::s6a::pua_flags::FREEZE_MTMSI));
    }

    #[test]
    fn test_failure_answer_codes() {
        let air = make_air();

        // 3GPP error: Experimental-Result, no Result-Code, no E-bit
        let answer = build_failure_answer(&air, &S6aFailure::UserUnknown);
        assert_eq!(answer.result_code(), None);
        assert_eq!(
            ogs_diameter::s6a::experimental_result_code(&answer),
            Some(5001)
        );
        assert!(!answer.header.is_error());

        // Base permanent failure: Result-Code, no E-bit
        let answer = build_failure_answer(&air, &S6aFailure::MissingAvp);
        assert_eq!(answer.result_code(), Some(5005));
        assert!(!answer.header.is_error());

        // Protocol error: Result-Code + E-bit
        let answer = build_failure_answer(&air, &S6aFailure::UnsupportedCommand);
        assert_eq!(answer.result_code(), Some(3001));
        assert!(answer.header.is_error());

        // Resync failure: Experimental 4181
        let answer = build_failure_answer(&air, &S6aFailure::AuthDataUnavailable);
        assert_eq!(
            ogs_diameter::s6a::experimental_result_code(&answer),
            Some(4181)
        );
    }

    #[test]
    fn test_dispatch_s6a_air_without_db() {
        // Without DB the handler must produce a proper failure answer
        let air = make_air();
        let answer = dispatch_s6a_request(&air).unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 318);
        // DB unreachable -> UNABLE_TO_COMPLY (or USER_UNKNOWN if the driver
        // resolves the lookup); never silent success
        assert_ne!(answer.result_code(), Some(2001));
    }

    #[test]
    fn test_dispatch_s6a_missing_username() {
        let mut msg = DiameterMessage::new_request(318, OGS_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_air_missing_visited_plmn() {
        let mut msg = DiameterMessage::new_request(318, OGS_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_air_missing_requested_auth_info() {
        let mut msg = DiameterMessage::new_request(318, OGS_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        msg.add_avp(Avp::vendor_mandatory(
            ogs_diameter::s6a::avp::VISITED_PLMN_ID,
            OGS_3GPP_VENDOR_ID,
            AvpData::OctetString(bytes::Bytes::from_static(&[0x00, 0xF1, 0x10])),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_ulr_missing_mandatory_avps() {
        // ULR without RAT-Type / ULR-Flags / Visited-PLMN-Id -> 5005
        let mut msg = DiameterMessage::new_request(316, OGS_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_unknown_command() {
        let mut msg = DiameterMessage::new_request(999, OGS_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(3001));
        assert!(answer.header.is_error());
    }

    #[test]
    fn test_build_clr_request_mandatory_avps() {
        let clr = build_clr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            CancellationType::SubscriptionWithdrawal,
            Some(ogs_diameter::s6a::clr_flags::REATTACH_REQUIRED),
        );
        assert!(clr.header.is_request());
        assert_eq!(clr.header.command_code, 317);
        assert_ne!(clr.header.hop_by_hop_id, 0);
        assert_ne!(clr.header.end_to_end_id, 0);
        assert_eq!(clr.user_name(), Some("001010123456789"));
        assert_eq!(clr.destination_host(), Some("mme.example.com"));
        assert_eq!(clr.destination_realm(), Some("example.com"));
        let ct = clr
            .find_vendor_avp(ogs_diameter::s6a::avp::CANCELLATION_TYPE, OGS_3GPP_VENDOR_ID)
            .and_then(|a| a.as_i32());
        assert_eq!(ct, Some(2));
        let flags = clr
            .find_vendor_avp(ogs_diameter::s6a::avp::CLR_FLAGS, OGS_3GPP_VENDOR_ID)
            .and_then(|a| a.as_u32());
        assert_eq!(flags, Some(ogs_diameter::s6a::clr_flags::REATTACH_REQUIRED));
    }

    #[test]
    fn test_build_idr_request_carries_subscription_data() {
        let mut sub = ogs_diameter::s6a::SubscriptionData {
            ambr_uplink: 1000,
            ambr_downlink: 2000,
            ..Default::default()
        };
        sub.apn_configs.push(ogs_diameter::s6a::ApnConfiguration {
            context_identifier: 1,
            service_selection: "internet".to_string(),
            ..Default::default()
        });
        let idr = build_idr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            ogs_diameter::s6a::idr_flags::RAT_TYPE,
            &sub,
            OGS_DIAM_S6A_SUBDATA_ALL,
        );
        assert_eq!(idr.header.command_code, 319);
        // Subscription-Data must be present (M in IDR) and parse back
        let sub_avp = idr
            .find_avp(ogs_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .expect("Subscription-Data");
        let parsed = ogs_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed.ambr_uplink, 1000);
        assert_eq!(parsed.apn_configs.len(), 1);
    }

    #[test]
    fn test_build_idr_request_subdata_mask_filters() {
        let mut sub = ogs_diameter::s6a::SubscriptionData {
            ambr_uplink: 1000,
            ambr_downlink: 2000,
            subscribed_rau_tau_timer: 720,
            ..Default::default()
        };
        sub.apn_configs.push(ogs_diameter::s6a::ApnConfiguration::default());
        let idr = build_idr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            0,
            &sub,
            OGS_DIAM_S6A_SUBDATA_UEAMBR, // only the UE-AMBR
        );
        let sub_avp = idr
            .find_avp(ogs_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .unwrap();
        let parsed = ogs_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed.ambr_uplink, 1000);
        assert_eq!(parsed.subscribed_rau_tau_timer, 0);
        assert!(parsed.apn_configs.is_empty());
    }

    #[test]
    fn test_send_clr_requires_connected_peer() {
        // Explicit host/realm avoids the DB lookup; no peer registered -> Err
        let result = hss_s6a_send_clr(
            "123456789012345",
            Some("mme.unconnected.example.com"),
            Some("example.com"),
            CancellationType::SubscriptionWithdrawal,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no connected S6a peer"));
    }

    #[test]
    fn test_send_clr_transmits_to_registered_peer() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        register_mme_peer("mme.registered.example.com", tx);

        let result = hss_s6a_send_clr(
            "123456789012345",
            Some("mme.registered.example.com"),
            Some("example.com"),
            CancellationType::MmeUpdateProcedure,
        );
        assert!(result.is_ok());

        let sent = rx.try_recv().expect("CLR should be enqueued for the peer");
        assert_eq!(sent.header.command_code, 317);
        assert!(sent.header.is_request());
        assert_eq!(sent.user_name(), Some("123456789012345"));

        unregister_mme_peer("mme.registered.example.com");
    }

    #[test]
    fn test_send_idr_without_db_fails() {
        // IDR requires the subscriber DB; without it the call must error
        let result = hss_s6a_send_idr("123456789012345", 0, OGS_DIAM_S6A_SUBDATA_ALL);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_pur_without_db_fails() {
        let result = handle_pur("123456789012345", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_ulr_without_db_fails() {
        let result = handle_ulr(
            "123456789012345",
            &[0x00, 0xF1, 0x10],
            0,
            "mme.example.com",
            "example.com",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_air_without_db_fails() {
        let result = handle_air("123456789012345", &[0x00, 0xF1, 0x10], None, 1);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dispatch_async_offloads_blocking_work() {
        let air = make_air();
        let answer = dispatch_s6a_request_async(air).await.unwrap();
        assert!(answer.header.is_answer());
        assert_ne!(answer.result_code(), Some(2001));
    }

    /// Full S6a integration over real TCP: CER/CEA, AIR dispatched off the
    /// Diameter thread, and an HSS-initiated CLR actually transmitted to the
    /// connected MME peer and answered with a CLA.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_s6a_server_end_to_end_air_and_clr() {
        use ogs_diameter::config::DiameterConfig;
        use ogs_diameter::transport::{DiameterClient, DiameterListener};

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_cfg = DiameterConfig {
            diameter_id: "hss.e2e.example.org".to_string(),
            diameter_realm: "e2e.example.org".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        tokio::spawn(async move {
            let _ = hss_s6a_serve(listener, server_cfg).await;
        });

        // MME side: connect (CER/CEA)
        let client_cfg = DiameterConfig {
            diameter_id: "mme.e2e.example.org".to_string(),
            diameter_realm: "e2e.example.org".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        let mut client = DiameterClient::new(client_cfg, addr);
        client.connect().await.unwrap();

        // AIR -> answered (no DB: well-formed failure, never silence)
        let air = ogs_diameter::s6a::create_air(
            "e2e-session-1",
            "mme.e2e.example.org",
            "e2e.example.org",
            "e2e.example.org",
            "001010000000042",
            &[0x00, 0xF1, 0x10],
            1,
        );
        let answer = client.send_request(&air).await.unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 318);
        assert_ne!(answer.result_code(), Some(2001));

        // HSS-initiated CLR rides the same connection to the registered peer.
        // Registration happens on the server's Established event; retry briefly.
        let mut sent = Err("unsent".to_string());
        for _ in 0..50 {
            sent = hss_s6a_send_clr(
                "001010000000042",
                Some("mme.e2e.example.org"),
                Some("e2e.example.org"),
                CancellationType::SubscriptionWithdrawal,
            );
            if sent.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        sent.expect("CLR should be transmitted to the connected MME");

        let inbound = client
            .recv_inbound_request(std::time::Duration::from_secs(5))
            .await
            .unwrap()
            .expect("MME should receive the CLR");
        assert!(inbound.header.is_request());
        assert_eq!(inbound.header.command_code, 317);
        assert_eq!(inbound.user_name(), Some("001010000000042"));
        let ct = inbound
            .find_vendor_avp(ogs_diameter::s6a::avp::CANCELLATION_TYPE, OGS_3GPP_VENDOR_ID)
            .and_then(|a| a.as_i32());
        assert_eq!(ct, Some(CancellationType::SubscriptionWithdrawal as i32));

        // Answer with CLA; the server consumes it (stats path)
        let mut cla = DiameterMessage::new_answer(&inbound);
        if let Some(sid) = inbound.session_id() {
            cla.add_avp(Avp::mandatory(
                avp_code::SESSION_ID,
                AvpData::Utf8String(sid.to_string()),
            ));
        }
        cla.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(2001),
        ));
        client.send_answer(&cla).await.unwrap();
    }
}
