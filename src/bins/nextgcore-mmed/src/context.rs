//! MME Context Management
//!
//! Port of src/mme/mme-context.c, src/mme/mme-context.h - MME context with eNB list, UE list, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of served GUMMEI
pub const OGS_MAX_NUM_OF_SERVED_GUMMEI: usize = 8;
/// Maximum number of supported TA
pub const OGS_MAX_NUM_OF_SUPPORTED_TA: usize = 16;
/// Maximum number of PLMN per MME
pub const OGS_MAX_NUM_OF_PLMN_PER_MME: usize = 6;
/// Maximum number of algorithms
pub const OGS_MAX_NUM_OF_ALGORITHM: usize = 8;
/// Maximum number of sessions
pub const OGS_MAX_NUM_OF_SESS: usize = 4;
/// Maximum number of bearers
pub const OGS_MAX_NUM_OF_BEARER: usize = 8;
/// Maximum number of APN
pub const OGS_MAX_NUM_OF_APN: usize = 8;
/// Maximum number of TAI
pub const OGS_MAX_NUM_OF_TAI: usize = 16;
/// Maximum number of cell ID
pub const OGS_MAX_NUM_OF_CELL_ID: usize = 8;

/// Groups per MME (spec says 65535, using 256 for practical purposes)
pub const GRP_PER_MME: usize = 256;
/// Codes per MME (spec says 256)
pub const CODE_PER_MME: usize = 256;

/// Key length
pub const OGS_KEY_LEN: usize = 16;
/// RAND length
pub const OGS_RAND_LEN: usize = 16;
/// AUTN length
pub const OGS_AUTN_LEN: usize = 16;
/// MAX RES length
pub const OGS_MAX_RES_LEN: usize = 16;
/// SHA256 digest size
pub const OGS_SHA256_DIGEST_SIZE: usize = 32;
/// MAX IMSI length
pub const OGS_MAX_IMSI_LEN: usize = 15;
/// MAX IMSI BCD length
pub const OGS_MAX_IMSI_BCD_LEN: usize = 15;
/// MAX IMEISV length
pub const OGS_MAX_IMEISV_LEN: usize = 16;
/// MAX IMEISV BCD length
pub const OGS_MAX_IMEISV_BCD_LEN: usize = 16;
/// MAX MSISDN length
pub const OGS_MAX_MSISDN_LEN: usize = 15;
/// MAX MSISDN BCD length
pub const OGS_MAX_MSISDN_BCD_LEN: usize = 15;
/// Hash MME length
pub const OGS_HASH_MME_LEN: usize = 8;
/// Charging characteristics length
pub const OGS_CHRGCHARS_LEN: usize = 2;

/// Invalid UE S1AP ID
pub const INVALID_UE_S1AP_ID: u32 = 0xffffffff;
/// Invalid pool ID
pub const OGS_INVALID_POOL_ID: u64 = 0;
/// Minimum pool ID
pub const OGS_MIN_POOL_ID: u64 = 1;
/// Maximum pool ID
pub const OGS_MAX_POOL_ID: u64 = u64::MAX - 1;

/// NAS KSI no key available
pub const OGS_NAS_KSI_NO_KEY_IS_AVAILABLE: u8 = 7;

/// Minimum EPS bearer ID
pub const MIN_EPS_BEARER_ID: u8 = 5;
/// Maximum EPS bearer ID
pub const MAX_EPS_BEARER_ID: u8 = 15;

// ============================================================================
// Basic Types
// ============================================================================

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    /// MCC digit 1
    pub mcc1: u8,
    /// MCC digit 2
    pub mcc2: u8,
    /// MCC digit 3
    pub mcc3: u8,
    /// MNC digit 1
    pub mnc1: u8,
    /// MNC digit 2
    pub mnc2: u8,
    /// MNC digit 3 (0xf if 2-digit MNC)
    pub mnc3: u8,
}

impl PlmnId {
    /// Create a new PLMN ID
    pub fn new(mcc: &str, mnc: &str) -> Self {
        let mcc_bytes: Vec<u8> = mcc.chars().filter_map(|c| c.to_digit(10).map(|d| d as u8)).collect();
        let mnc_bytes: Vec<u8> = mnc.chars().filter_map(|c| c.to_digit(10).map(|d| d as u8)).collect();
        
        Self {
            mcc1: mcc_bytes.first().copied().unwrap_or(0),
            mcc2: mcc_bytes.get(1).copied().unwrap_or(0),
            mcc3: mcc_bytes.get(2).copied().unwrap_or(0),
            mnc1: mnc_bytes.first().copied().unwrap_or(0),
            mnc2: mnc_bytes.get(1).copied().unwrap_or(0),
            mnc3: mnc_bytes.get(2).copied().unwrap_or(0xf),
        }
    }

    /// Convert to BCD string
    pub fn to_bcd(&self) -> String {
        if self.mnc3 == 0xf {
            format!("{}{}{}{}{}", self.mcc1, self.mcc2, self.mcc3, self.mnc1, self.mnc2)
        } else {
            format!("{}{}{}{}{}{}", self.mcc1, self.mcc2, self.mcc3, self.mnc1, self.mnc2, self.mnc3)
        }
    }
}

/// EPS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct EpsTai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC (16 bits for EPS)
    pub tac: u16,
}

/// E-CGI (E-UTRAN Cell Global Identity)
#[derive(Debug, Clone, Default)]
pub struct ECgi {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// E-UTRAN Cell ID (28 bits)
    pub cell_id: u32,
}

/// RAI (Routing Area Identity)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Rai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// LAC (Location Area Code)
    pub lac: u16,
    /// RAC (Routing Area Code)
    pub rac: u8,
}

/// LAI (Location Area Identity)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Lai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// LAC (Location Area Code)
    pub lac: u16,
}

/// EPS GUTI
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct EpsGuti {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// MME Group ID
    pub mme_gid: u16,
    /// MME Code
    pub mme_code: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

/// IP address
#[derive(Debug, Clone, Default)]
pub struct IpAddr {
    /// IPv4 address
    pub ipv4: Option<[u8; 4]>,
    /// IPv6 address
    pub ipv6: Option<[u8; 16]>,
}

/// Bitrate
#[derive(Debug, Clone, Default)]
pub struct Bitrate {
    /// Downlink bitrate (bps)
    pub downlink: u64,
    /// Uplink bitrate (bps)
    pub uplink: u64,
}

/// QoS parameters
#[derive(Debug, Clone, Default)]
pub struct Qos {
    /// QCI (QoS Class Identifier)
    pub qci: u8,
    /// ARP (Allocation and Retention Priority)
    pub arp: Arp,
    /// MBR (Maximum Bit Rate)
    pub mbr: Bitrate,
    /// GBR (Guaranteed Bit Rate)
    pub gbr: Bitrate,
}

/// ARP (Allocation and Retention Priority)
#[derive(Debug, Clone, Default)]
pub struct Arp {
    /// Priority level (1-15)
    pub priority_level: u8,
    /// Pre-emption capability
    pub pre_emption_capability: u8,
    /// Pre-emption vulnerability
    pub pre_emption_vulnerability: u8,
}

/// PAA (PDN Address Allocation)
#[derive(Debug, Clone, Default)]
pub struct Paa {
    /// PDN type (use esm_build::PdnType)
    pub pdn_type: crate::esm_build::PdnType,
    /// IPv4 address
    pub addr: [u8; 4],
    /// IPv6 address
    pub addr6: [u8; 16],
}

/// Network name
#[derive(Debug, Clone, Default)]
pub struct NetworkName {
    /// Name string
    pub name: String,
    /// Coding scheme
    pub coding_scheme: u8,
    /// Add CI
    pub add_ci: bool,
}

/// UE network capability
#[derive(Debug, Clone, Default)]
pub struct UeNetworkCapability {
    /// EEA algorithms (bitmap)
    pub eea: u8,
    /// EIA algorithms (bitmap)
    pub eia: u8,
    /// UEA algorithms (bitmap)
    pub uea: u8,
    /// UIA algorithms (bitmap)
    pub uia: u8,
    /// Length
    pub length: u8,
}

/// MS network capability
#[derive(Debug, Clone, Default)]
pub struct MsNetworkCapability {
    /// GEA algorithms (bitmap)
    pub gea: u8,
    /// Length
    pub length: u8,
}

/// UE additional security capability
#[derive(Debug, Clone, Default)]
pub struct UeAdditionalSecurityCapability {
    /// 5G-EA algorithms (bitmap)
    pub nea: u8,
    /// 5G-IA algorithms (bitmap)
    pub nia: u8,
}

/// Session data
#[derive(Debug, Clone, Default)]
pub struct SessionData {
    /// APN name
    pub name: String,
    /// PDN type
    pub pdn_type: u8,
    /// QoS
    pub qos: Qos,
    /// AMBR
    pub ambr: Bitrate,
}

// ============================================================================
// TAI List Types (for served TAI)
// ============================================================================

/// TAI0 list (type 0 - list of TACs with same PLMN)
#[derive(Debug, Clone, Default)]
pub struct EpsTai0List {
    /// Type (0)
    pub type_: u8,
    /// Number of TACs
    pub num: u8,
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC list
    pub tac: Vec<u16>,
}

/// TAI1 list (type 1 - contiguous TACs)
#[derive(Debug, Clone, Default)]
pub struct EpsTai1List {
    /// Type (1)
    pub type_: u8,
    /// Number of TAIs
    pub num: u8,
    /// TAI list
    pub tai: Vec<EpsTai>,
}

/// TAI2 list (type 2 - list of TAIs)
#[derive(Debug, Clone, Default)]
pub struct EpsTai2List {
    /// Type (2)
    pub type_: u8,
    /// Number of TAIs
    pub num: u8,
    /// TAI list
    pub tai: Vec<EpsTai>,
}

/// Served TAI configuration
#[derive(Debug, Clone, Default)]
pub struct ServedTai {
    /// TAI0 list
    pub list0: EpsTai0List,
    /// TAI1 list
    pub list1: EpsTai1List,
    /// TAI2 list
    pub list2: EpsTai2List,
}

/// Served GUMMEI configuration
#[derive(Debug, Clone, Default)]
pub struct ServedGummei {
    /// Number of PLMN IDs
    pub num_of_plmn_id: usize,
    /// PLMN ID list
    pub plmn_id: Vec<PlmnId>,
    /// Number of MME GIDs
    pub num_of_mme_gid: usize,
    /// MME GID list
    pub mme_gid: Vec<u16>,
    /// Number of MME codes
    pub num_of_mme_code: usize,
    /// MME code list
    pub mme_code: Vec<u8>,
}

/// Access control entry
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    /// Reject cause
    pub reject_cause: i32,
    /// PLMN ID
    pub plmn_id: PlmnId,
}

// ============================================================================
// eNB Supported TA
// ============================================================================

/// Supported TA entry for eNB
#[derive(Debug, Clone, Default)]
pub struct SupportedTa {
    /// TAI
    pub tai: EpsTai,
}

// ============================================================================
// S1AP Cause
// ============================================================================

/// S1AP Cause group
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum S1apCauseGroup {
    #[default]
    Nothing,
    RadioNetwork,
    Transport,
    Nas,
    Protocol,
    Misc,
}

/// S1AP Cause
#[derive(Debug, Clone, Default)]
pub struct S1apCause {
    /// Cause group
    pub group: S1apCauseGroup,
    /// Cause value
    pub cause: i64,
}

// ============================================================================
// Handover Type
// ============================================================================

/// S1AP Handover Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandoverType {
    #[default]
    IntraLte,
    LteToUtran,
    LteToGeran,
    UtranToLte,
    GeranToLte,
    EpsTo5gs,
    FiveGsToEps,
}

// ============================================================================
// UE Context Release Action
// ============================================================================

/// UE context release action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UeCtxRelAction {
    #[default]
    Invalid,
    S1ContextRemove,
    S1RemoveAndUnlink,
    UeContextRemove,
    S1HandoverComplete,
    S1HandoverCancel,
    S1HandoverFailure,
    S1Paging,
}

// ============================================================================
// EPS Type
// ============================================================================

/// MME EPS type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmeEpsType {
    #[default]
    None,
    AttachRequest,
    TauRequest,
    ServiceRequest,
    ExtendedServiceRequest,
    DetachRequestFromUe,
    DetachRequestToUe,
}

/// Detach type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetachType {
    #[default]
    None,
    RequestFromUe,
    MmeExplicit,
    HssExplicit,
    MmeImplicit,
    HssImplicit,
}

// ============================================================================
// Paging Type
// ============================================================================

/// Paging type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PagingType {
    #[default]
    None,
    DownlinkDataNotification,
    CreateBearer,
    UpdateBearer,
    DeleteBearer,
    CsCallService,
    SmsService,
    DetachToUe,
}

// ============================================================================
// GTP Counter Type
// ============================================================================

/// GTP counter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GtpCounterType {
    #[default]
    None,
    CreateSessionByPathSwitch,
    DeleteSessionByPathSwitch,
    DeleteSessionByTau,
}

// ============================================================================
// SGW Relocation
// ============================================================================

/// SGW relocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SgwRelocation {
    #[default]
    WithoutRelocation,
    WithRelocation,
    HasAlreadyBeenRelocated,
}



// ============================================================================
// SGSN Route
// ============================================================================

/// SGSN route entry
#[derive(Debug, Clone, Default)]
pub struct MmeSgsnRoute {
    /// RAI (Routing Area Identity)
    pub rai: Rai,
    /// Cell ID
    pub cell_id: u16,
}

/// SGSN context
#[derive(Debug, Clone, Default)]
pub struct MmeSgsn {
    /// Pool ID
    pub id: u64,
    /// Route list
    pub route_list: Vec<MmeSgsnRoute>,
    /// Default route flag
    pub default_route: bool,
    /// GTP node address
    pub addr: Option<std::net::SocketAddr>,
}

// ============================================================================
// SGW Context
// ============================================================================

/// SGW context
#[derive(Debug, Clone, Default)]
pub struct MmeSgw {
    /// Pool ID
    pub id: u64,
    /// TAC list
    pub tac: Vec<u16>,
    /// E-Cell ID list
    pub e_cell_id: Vec<u32>,
    /// SGW UE list (pool IDs)
    pub sgw_ue_list: Vec<u64>,
    /// GTP node address
    pub addr: Option<std::net::SocketAddr>,
}

// ============================================================================
// PGW Context
// ============================================================================

/// PGW context
#[derive(Debug, Clone, Default)]
pub struct MmePgw {
    /// Pool ID
    pub id: u64,
    /// Socket address list
    pub sa_list: Vec<std::net::SocketAddr>,
    /// APN list
    pub apn: Vec<String>,
    /// TAC list
    pub tac: Vec<u16>,
    /// E-Cell ID list
    pub e_cell_id: Vec<u32>,
}

// ============================================================================
// VLR Context
// ============================================================================

/// VLR state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VlrState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
}

/// VLR context
#[derive(Debug, Clone, Default)]
pub struct MmeVlr {
    /// Pool ID
    pub id: u64,
    /// State
    pub state: VlrState,
    /// Max number of outbound streams
    pub max_num_of_ostreams: i32,
    /// Output stream ID generator
    pub ostream_id: u16,
    /// Socket address list
    pub sa_list: Vec<std::net::SocketAddr>,
    /// Local socket address list
    pub local_sa_list: Vec<std::net::SocketAddr>,
}

// ============================================================================
// CS Map Context
// ============================================================================

/// CS Map (TAI-LAI mapping)
#[derive(Debug, Clone, Default)]
pub struct MmeCsmap {
    /// Pool ID
    pub id: u64,
    /// TAI
    pub tai: EpsTai,
    /// LAI
    pub lai: Lai,
    /// VLR pool ID
    pub vlr_id: u64,
}

// ============================================================================
// HSS Map Context
// ============================================================================

/// HSS Map (PLMN to HSS mapping)
#[derive(Debug, Clone, Default)]
pub struct MmeHssmap {
    /// Pool ID
    pub id: u64,
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// Realm
    pub realm: String,
    /// Host
    pub host: String,
}

// ============================================================================
// Emergency Number
// ============================================================================

/// Emergency number entry
#[derive(Debug, Clone, Default)]
pub struct MmeEmerg {
    /// Pool ID
    pub id: u64,
    /// Service categories
    pub categories: u8,
    /// Emergency number digits
    pub digits: String,
}

// ============================================================================
// eNB Context
// ============================================================================

/// eNB state
#[derive(Debug, Clone, Default)]
pub struct EnbState {
    /// S1 setup success flag
    pub s1_setup_success: bool,
}

/// eNB context
#[derive(Debug, Clone, Default)]
pub struct MmeEnb {
    /// Pool ID
    pub id: u64,
    /// eNB ID presence flag
    pub enb_id_presence: bool,
    /// eNB ID (received from eNB)
    pub enb_id: u32,
    /// PLMN ID (received from eNB)
    pub plmn_id: PlmnId,
    /// State
    pub state: EnbState,
    /// Max number of outbound streams
    pub max_num_of_ostreams: i32,
    /// Output stream ID generator
    pub ostream_id: u16,
    /// Supported TA list
    pub supported_ta_list: Vec<EpsTai>,
    /// eNB UE list (pool IDs)
    pub enb_ue_list: Vec<u64>,
    /// Socket address
    pub addr: Option<std::net::SocketAddr>,
}

// ============================================================================
// eNB UE Context
// ============================================================================

/// Saved TAI and E-CGI for eNB UE
#[derive(Debug, Clone, Default)]
pub struct EnbUeSaved {
    /// TAI
    pub tai: EpsTai,
    /// E-CGI
    pub e_cgi: ECgi,
}

/// Release cause for eNB UE
#[derive(Debug, Clone, Default)]
pub struct EnbUeRelCause {
    /// Cause group
    pub group: S1apCauseGroup,
    /// Cause value
    pub cause: i64,
}

/// eNB UE context
#[derive(Debug, Clone, Default)]
pub struct EnbUe {
    /// Pool ID
    pub id: u64,
    /// Index
    pub index: u32,
    /// eNB UE S1AP ID (received from eNB)
    pub enb_ue_s1ap_id: u32,
    /// MME UE S1AP ID (assigned by MME)
    pub mme_ue_s1ap_id: u32,
    /// SCTP output stream ID for eNB
    pub enb_ostream_id: u16,
    /// Handover type
    pub handover_type: HandoverType,
    /// Source UE pool ID (for handover)
    pub source_ue_id: u64,
    /// Target UE pool ID (for handover)
    pub target_ue_id: u64,
    /// Saved TAI and E-CGI
    pub saved: EnbUeSaved,
    /// Release cause
    pub relcause: EnbUeRelCause,
    /// UE context release action
    pub ue_ctx_rel_action: UeCtxRelAction,
    /// Part of S1 reset requested
    pub part_of_s1_reset_requested: bool,
    /// Related eNB pool ID
    pub enb_id: u64,
    /// Related MME UE pool ID
    pub mme_ue_id: u64,
}

// ============================================================================
// SGW UE Context
// ============================================================================

/// SGW UE context
#[derive(Debug, Clone, Default)]
pub struct SgwUe {
    /// Pool ID
    pub id: u64,
    /// Source UE pool ID (for handover)
    pub source_ue_id: u64,
    /// Target UE pool ID (for handover)
    pub target_ue_id: u64,
    /// SGW S11 TEID (received from SGW)
    pub sgw_s11_teid: u32,
    /// Related SGW pool ID
    pub sgw_id: u64,
    /// Related MME UE pool ID
    pub mme_ue_id: u64,
}

// ============================================================================
// MME UE Memento (for context backup/restore)
// ============================================================================

/// MME UE memento for context backup/restore
#[derive(Debug, Clone, Default)]
pub struct MmeUeMemento {
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// MS network capability
    pub ms_network_capability: MsNetworkCapability,
    /// UE additional security capability
    pub ue_additional_security_capability: UeAdditionalSecurityCapability,
    /// Expected response (XRES)
    pub xres: [u8; OGS_MAX_RES_LEN],
    /// XRES length
    pub xres_len: u8,
    /// KASME (derived key from HSS)
    pub kasme: [u8; OGS_SHA256_DIGEST_SIZE],
    /// RAND (random challenge)
    pub rand: [u8; OGS_RAND_LEN],
    /// AUTN (authentication token)
    pub autn: [u8; OGS_AUTN_LEN],
    /// NAS integrity key
    pub knas_int: [u8; OGS_SHA256_DIGEST_SIZE / 2],
    /// NAS encryption key
    pub knas_enc: [u8; OGS_SHA256_DIGEST_SIZE / 2],
    /// Downlink NAS count
    pub dl_count: u32,
    /// Uplink NAS count
    pub ul_count: u32,
    /// KeNB (eNB key)
    pub kenb: [u8; OGS_SHA256_DIGEST_SIZE],
    /// Hash for MME
    pub hash_mme: [u8; OGS_HASH_MME_LEN],
    /// Nonce from UE
    pub nonceue: u32,
    /// Nonce from MME
    pub noncemme: u32,
    /// GPRS ciphering key sequence number
    pub gprs_ciphering_key_sequence_number: u8,
    /// Next hop key
    pub nh: [u8; OGS_SHA256_DIGEST_SIZE],
    /// Selected encryption algorithm
    pub selected_enc_algorithm: u8,
    /// Selected integrity algorithm
    pub selected_int_algorithm: u8,
}


// ============================================================================
// NAS EPS Info
// ============================================================================

/// NAS EPS KSI info
#[derive(Debug, Clone, Default)]
pub struct NasEpsKsi {
    /// TSC (Type of Security Context)
    pub tsc: u8,
    /// KSI (Key Set Identifier)
    pub ksi: u8,
}

/// NAS EPS info
#[derive(Debug, Clone, Default)]
pub struct NasEpsInfo {
    /// EPS type
    pub type_: MmeEpsType,
    /// MME KSI
    pub mme_ksi: NasEpsKsi,
    /// UE KSI
    pub ue_ksi: NasEpsKsi,
    /// Attach type
    pub attach_type: u8,
    /// Update type
    pub update_type: u8,
    /// Service type
    pub service_type: u8,
    /// Detach type
    pub detach_type: u8,
}

// ============================================================================
// Gn Interface Info
// ============================================================================

/// Gn interface info (for 2G/3G interworking)
#[derive(Debug, Clone, Default)]
pub struct GnInfo {
    /// MME Gn TEID
    pub mme_gn_teid: u32,
    /// SGSN Gn TEID
    pub sgsn_gn_teid: u32,
    /// SGSN Gn IP
    pub sgsn_gn_ip: IpAddr,
    /// SGSN Gn IP alternate
    pub sgsn_gn_ip_alt: IpAddr,
    /// GTP transaction ID
    pub gtp_xact_id: u64,
}

// ============================================================================
// GUTI/P-TMSI Info
// ============================================================================

/// GUTI/P-TMSI allocation info
#[derive(Debug, Clone, Default)]
pub struct TmsiInfo {
    /// M-TMSI value
    pub m_tmsi: Option<u32>,
    /// GUTI
    pub guti: EpsGuti,
    /// P-TMSI value
    pub p_tmsi: u32,
}

// ============================================================================
// Paging Info
// ============================================================================

/// Paging info
#[derive(Debug, Clone, Default)]
pub struct PagingInfo {
    /// Paging type
    pub type_: PagingType,
    /// Paging data (context-dependent)
    pub data: u64,
    /// Paging failed flag
    pub failed: bool,
}

// ============================================================================
// Timer Info
// ============================================================================

/// Timer with retry info
#[derive(Debug, Clone, Default)]
pub struct TimerWithRetry {
    /// Retry count
    pub retry_count: u32,
    /// Packet buffer (stored message)
    pub pkbuf: Option<Vec<u8>>,
}

// ============================================================================
// GTP Counter
// ============================================================================

/// GTP request/response counter
#[derive(Debug, Clone, Default)]
pub struct GtpCounter {
    /// Request count
    pub request: u8,
    /// Response count
    pub response: u8,
}

/// Maximum number of GTP counters
pub const MAX_NUM_OF_GTP_COUNTER: usize = 16;

// ============================================================================
// MME UE Context
// ============================================================================

/// MME UE context
#[derive(Debug, Clone, Default)]
pub struct MmeUe {
    /// Pool ID
    pub id: u64,
    /// NAS EPS info
    pub nas_eps: NasEpsInfo,
    /// TAU request presence mask
    pub tracking_area_update_request_presencemask: u64,
    /// TAU request EBCS value
    pub tracking_area_update_request_ebcs_value: u16,
    /// TAU accept procedure code
    pub tracking_area_update_accept_proc: i64,
    /// Detach type
    pub detach_type: DetachType,

    // UE Identity
    /// IMSI
    pub imsi: [u8; OGS_MAX_IMSI_LEN],
    /// IMSI length
    pub imsi_len: usize,
    /// IMSI BCD string
    pub imsi_bcd: String,
    /// IMEISV
    pub imeisv: [u8; OGS_MAX_IMEISV_LEN],
    /// IMEISV length
    pub imeisv_len: usize,
    /// Masked IMEISV
    pub masked_imeisv: [u8; OGS_MAX_IMEISV_LEN],
    /// Masked IMEISV length
    pub masked_imeisv_len: usize,
    /// IMEISV BCD string
    pub imeisv_bcd: String,
    /// MSISDN
    pub msisdn: [u8; OGS_MAX_MSISDN_LEN],
    /// MSISDN length
    pub msisdn_len: usize,
    /// MSISDN BCD string
    pub msisdn_bcd: String,
    /// Additional MSISDN
    pub a_msisdn: [u8; OGS_MAX_MSISDN_LEN],
    /// Additional MSISDN length
    pub a_msisdn_len: usize,
    /// Additional MSISDN BCD string
    pub a_msisdn_bcd: String,

    /// Gn interface info
    pub gn: GnInfo,
    /// Current TMSI info
    pub current: TmsiInfo,
    /// Next TMSI info
    pub next: TmsiInfo,

    /// MME S11 TEID
    pub mme_s11_teid: u32,
    /// VLR output stream ID
    pub vlr_ostream_id: u16,

    // UE Info
    /// eNB output stream ID
    pub enb_ostream_id: u16,
    /// TAI
    pub tai: EpsTai,
    /// E-CGI
    pub e_cgi: ECgi,
    /// UE location timestamp
    pub ue_location_timestamp: u64,
    /// Last visited PLMN ID
    pub last_visited_plmn_id: PlmnId,

    // Security Context
    /// Security context available flag
    pub security_context_available: bool,
    /// MAC failed flag
    pub mac_failed: bool,
    /// Can restore context flag
    pub can_restore_context: bool,
    /// Memento for context backup
    pub memento: MmeUeMemento,

    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// MS network capability
    pub ms_network_capability: MsNetworkCapability,
    /// UE additional security capability
    pub ue_additional_security_capability: UeAdditionalSecurityCapability,
    /// Expected response (XRES)
    pub xres: [u8; OGS_MAX_RES_LEN],
    /// XRES length
    pub xres_len: u8,
    /// KASME
    pub kasme: [u8; OGS_SHA256_DIGEST_SIZE],
    /// RAND
    pub rand: [u8; OGS_RAND_LEN],
    /// AUTN
    pub autn: [u8; OGS_AUTN_LEN],
    /// NAS integrity key
    pub knas_int: [u8; OGS_SHA256_DIGEST_SIZE / 2],
    /// NAS encryption key
    pub knas_enc: [u8; OGS_SHA256_DIGEST_SIZE / 2],
    /// Downlink NAS count
    pub dl_count: u32,
    /// Uplink NAS count
    pub ul_count: u32,
    /// KeNB
    pub kenb: [u8; OGS_SHA256_DIGEST_SIZE],
    /// Hash MME
    pub hash_mme: [u8; OGS_HASH_MME_LEN],
    /// Nonce UE
    pub nonceue: u32,
    /// Nonce MME
    pub noncemme: u32,
    /// GPRS ciphering key sequence number
    pub gprs_ciphering_key_sequence_number: u8,
    /// Next hop chaining counter
    pub nhcc: u8,
    /// Next hop key
    pub nh: [u8; OGS_SHA256_DIGEST_SIZE],
    /// Selected encryption algorithm
    pub selected_enc_algorithm: u8,
    /// Selected integrity algorithm
    pub selected_int_algorithm: u8,

    // HSS Info
    /// UE AMBR
    pub ambr: Bitrate,
    /// Network access mode
    pub network_access_mode: u32,
    /// Charging characteristics
    pub charging_characteristics: [u8; OGS_CHRGCHARS_LEN],
    /// Charging characteristics presence
    pub charging_characteristics_presence: bool,
    /// Context identifier (default APN)
    pub context_identifier: u32,
    /// Number of sessions from HSS
    pub num_of_session: usize,
    /// Session data from HSS
    pub session: Vec<SessionData>,

    // ESM Info
    /// Session list (pool IDs)
    pub sess_list: Vec<u64>,

    // Paging Info
    /// eNB UE pool ID
    pub enb_ue_id: u64,
    /// eNB UE holding pool ID
    pub enb_ue_holding_id: u64,
    /// Paging info
    pub paging: PagingInfo,

    /// SGW UE pool ID
    pub sgw_ue_id: u64,

    /// PDN connectivity request
    pub pdn_connectivity_request: Vec<u8>,

    // Timers
    /// T3413 timer
    pub t3413: TimerWithRetry,
    /// T3422 timer
    pub t3422: TimerWithRetry,
    /// T3450 timer
    pub t3450: TimerWithRetry,
    /// T3460 timer
    pub t3460: TimerWithRetry,
    /// T3470 timer
    pub t3470: TimerWithRetry,
    /// Mobile reachable timer
    pub t_mobile_reachable: TimerWithRetry,
    /// Implicit detach timer
    pub t_implicit_detach: TimerWithRetry,

    /// Service indicator
    pub service_indicator: u8,

    /// UE radio capability
    pub ue_radio_capability: Vec<u8>,
    /// S1AP transparent container
    pub container: Vec<u8>,

    /// GTP counters
    pub gtp_counter: [GtpCounter; MAX_NUM_OF_GTP_COUNTER],

    /// Bearer to modify list (pool IDs)
    pub bearer_to_modify_list: Vec<u64>,

    /// CS map pool ID
    pub csmap_id: u64,
    /// HSS map pool ID
    pub hssmap_id: u64,
}


// ============================================================================
// MME Session Context
// ============================================================================

/// Protocol Configuration Options from UE
#[derive(Debug, Clone, Default)]
pub struct UePco {
    /// Length
    pub length: u16,
    /// Buffer
    pub buffer: Vec<u8>,
}

/// MME session context
#[derive(Debug, Clone, Default)]
pub struct MmeSess {
    /// Pool ID
    pub id: u64,
    /// APN name
    pub apn: String,
    /// AMBR (Aggregate Maximum Bit Rate)
    pub ambr: Bitrate,
    /// UE requested PDN type
    pub ue_request_pdn_type: crate::esm_build::PdnType,
    /// Procedure Transaction Identity
    pub pti: u8,
    /// PGW S5C TEID
    pub pgw_s5c_teid: u32,
    /// PGW S5C IP
    pub pgw_s5c_ip: IpAddr,
    /// UE request type
    pub ue_request_type: u8,
    /// Bearer list (pool IDs)
    pub bearer_list: Vec<u64>,
    /// Related MME UE pool ID
    pub mme_ue_id: u64,
    /// Session data
    pub session: Option<SessionData>,
    /// PAA (PDN Address Allocation)
    pub paa: Paa,
    /// UE PCO
    pub ue_pco: UePco,
    /// UE Extended PCO
    pub ue_epco: UePco,
    /// PGW PCO
    pub pgw_pco: Vec<u8>,
    /// PGW Extended PCO
    pub pgw_epco: Vec<u8>,
}

// ============================================================================
// MME Bearer Context
// ============================================================================

/// Bearer transaction info
#[derive(Debug, Clone, Default)]
pub struct BearerXact {
    /// Transaction ID
    pub xact_id: u64,
}

/// Bearer update transaction list
#[derive(Debug, Clone, Default)]
pub struct BearerUpdateXact {
    /// Transaction list
    pub xact_list: Vec<u64>,
}

/// MME bearer context
#[derive(Debug, Clone, Default)]
pub struct MmeBearer {
    /// Pool ID
    pub id: u64,
    /// EPS Bearer ID
    pub ebi: u8,

    // S1-U tunnel info
    /// eNB S1-U TEID
    pub enb_s1u_teid: u32,
    /// eNB S1-U IP
    pub enb_s1u_ip: IpAddr,
    /// SGW S1-U TEID
    pub sgw_s1u_teid: u32,
    /// SGW S1-U IP
    pub sgw_s1u_ip: IpAddr,
    /// PGW S5-U TEID
    pub pgw_s5u_teid: u32,
    /// PGW S5-U IP
    pub pgw_s5u_ip: IpAddr,

    // Handover tunnel info
    /// Target S1-U TEID
    pub target_s1u_teid: u32,
    /// Target S1-U IP
    pub target_s1u_ip: IpAddr,

    // Indirect tunnel info
    /// eNB DL TEID
    pub enb_dl_teid: u32,
    /// eNB DL IP
    pub enb_dl_ip: IpAddr,
    /// eNB UL TEID
    pub enb_ul_teid: u32,
    /// eNB UL IP
    pub enb_ul_ip: IpAddr,
    /// SGW DL TEID
    pub sgw_dl_teid: u32,
    /// SGW DL IP
    pub sgw_dl_ip: IpAddr,
    /// SGW UL TEID
    pub sgw_ul_teid: u32,
    /// SGW UL IP
    pub sgw_ul_ip: IpAddr,

    /// QoS
    pub qos: Qos,
    /// TFT (Traffic Flow Template)
    pub tft: Vec<u8>,

    /// T3489 timer
    pub t3489: TimerWithRetry,

    /// Related MME UE pool ID
    pub mme_ue_id: u64,
    /// Related session pool ID
    pub sess_id: u64,

    /// Create transaction
    pub create: BearerXact,
    /// Delete transaction
    pub delete: BearerXact,
    /// Notify transaction
    pub notify: BearerXact,
    /// Update transactions
    pub update: BearerUpdateXact,
}

// ============================================================================
// Timer Configuration
// ============================================================================

/// Timer configuration
#[derive(Debug, Clone, Default)]
pub struct TimerConfig {
    /// T3402 timer value (seconds)
    pub t3402: u64,
    /// T3412 timer value (seconds)
    pub t3412: u64,
    /// T3423 timer value (seconds)
    pub t3423: u64,
}

// ============================================================================
// MME Context (Main)
// ============================================================================

/// Main MME context
#[derive(Debug, Default)]
pub struct MmeContext {
    /// Diameter configuration path
    pub diam_conf_path: Option<String>,

    /// S1AP port
    pub s1ap_port: u16,
    /// SGsAP port
    pub sgsap_port: u16,

    /// S1AP IPv4 server addresses
    pub s1ap_list: Vec<std::net::SocketAddr>,
    /// S1AP IPv6 server addresses
    pub s1ap_list6: Vec<std::net::SocketAddr>,

    /// SGW list
    pub sgw_list: Vec<u64>,
    /// Current SGW for round-robin
    pub sgw_index: usize,

    /// SGSN list
    pub sgsn_list: Vec<u64>,

    /// PGW list
    pub pgw_list: Vec<u64>,
    /// First PGW IPv4 address
    pub pgw_addr: Option<std::net::SocketAddr>,
    /// First PGW IPv6 address
    pub pgw_addr6: Option<std::net::SocketAddr>,

    /// eNB list
    pub enb_list: Vec<u64>,

    /// VLR list
    pub vlr_list: Vec<u64>,
    /// CS map list
    pub csmap_list: Vec<u64>,
    /// HSS map list
    pub hssmap_list: Vec<u64>,

    /// Emergency number list
    pub emerg_list: Vec<u64>,

    /// Served GUMMEI
    pub num_of_served_gummei: usize,
    pub served_gummei: Vec<ServedGummei>,

    /// Served TAI
    pub num_of_served_tai: usize,
    pub served_tai: Vec<ServedTai>,

    /// Access control
    pub default_reject_cause: i32,
    pub access_control: Vec<AccessControl>,

    /// Ciphering algorithm order
    pub ciphering_order: Vec<u8>,
    /// Integrity algorithm order
    pub integrity_order: Vec<u8>,

    /// Network short name
    pub short_name: NetworkName,
    /// Network full name
    pub full_name: NetworkName,

    /// MME name
    pub mme_name: Option<String>,

    /// Relative capacity
    pub relative_capacity: u8,

    /// MME UE S1AP ID generator
    pub mme_ue_s1ap_id: AtomicU32,

    /// MME UE list
    pub mme_ue_list: Vec<u64>,

    /// Hash tables
    pub enb_addr_hash: RwLock<HashMap<String, u64>>,
    pub enb_id_hash: RwLock<HashMap<u32, u64>>,
    pub imsi_ue_hash: RwLock<HashMap<String, u64>>,
    pub guti_ue_hash: RwLock<HashMap<EpsGuti, u64>>,
    pub mme_s11_teid_hash: RwLock<HashMap<u32, u64>>,
    pub mme_gn_teid_hash: RwLock<HashMap<u32, u64>>,

    /// Timer configuration
    pub time: TimerConfig,

    /// Emergency APN
    pub emergency_dnn: Option<String>,

    // Storage pools (using HashMap for simplicity)
    /// SGSN storage
    pub sgsn_pool: RwLock<HashMap<u64, MmeSgsn>>,
    /// SGW storage
    pub sgw_pool: RwLock<HashMap<u64, MmeSgw>>,
    /// PGW storage
    pub pgw_pool: RwLock<HashMap<u64, MmePgw>>,
    /// VLR storage
    pub vlr_pool: RwLock<HashMap<u64, MmeVlr>>,
    /// CS map storage
    pub csmap_pool: RwLock<HashMap<u64, MmeCsmap>>,
    /// HSS map storage
    pub hssmap_pool: RwLock<HashMap<u64, MmeHssmap>>,
    /// eNB storage
    pub enb_pool: RwLock<HashMap<u64, MmeEnb>>,
    /// Emergency storage
    pub emerg_pool: RwLock<HashMap<u64, MmeEmerg>>,
    /// eNB UE storage
    pub enb_ue_pool: RwLock<HashMap<u64, EnbUe>>,
    /// SGW UE storage
    pub sgw_ue_pool: RwLock<HashMap<u64, SgwUe>>,
    /// MME UE storage
    pub mme_ue_pool: RwLock<HashMap<u64, MmeUe>>,
    /// Session storage
    pub sess_pool: RwLock<HashMap<u64, MmeSess>>,
    /// Bearer storage
    pub bearer_pool: RwLock<HashMap<u64, MmeBearer>>,

    /// Pool ID counter
    pub pool_id_counter: AtomicU64,

    /// Initialized flag
    pub initialized: AtomicBool,
}


use std::sync::atomic::AtomicU64;

impl MmeContext {
    /// Create a new MME context
    pub fn new() -> Self {
        Self {
            s1ap_port: 36412,
            sgsap_port: 29118,
            relative_capacity: 255,
            mme_ue_s1ap_id: AtomicU32::new(1),
            pool_id_counter: AtomicU64::new(OGS_MIN_POOL_ID),
            initialized: AtomicBool::new(false),
            ..Default::default()
        }
    }

    /// Initialize the MME context
    pub fn init(&self) {
        self.initialized.store(true, Ordering::SeqCst);
    }

    /// Finalize the MME context
    pub fn final_(&self) {
        self.initialized.store(false, Ordering::SeqCst);
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate a new pool ID
    pub fn next_pool_id(&self) -> u64 {
        self.pool_id_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Generate a new MME UE S1AP ID
    pub fn next_mme_ue_s1ap_id(&self) -> u32 {
        let id = self.mme_ue_s1ap_id.fetch_add(1, Ordering::SeqCst);
        if id == INVALID_UE_S1AP_ID {
            self.mme_ue_s1ap_id.store(1, Ordering::SeqCst);
            1
        } else {
            id
        }
    }
}


// ============================================================================
// eNB Management
// ============================================================================

impl MmeContext {
    /// Add a new eNB
    pub fn enb_add(&self, addr: std::net::SocketAddr) -> u64 {
        let id = self.next_pool_id();
        let enb = MmeEnb {
            id,
            addr: Some(addr),
            ..Default::default()
        };
        self.enb_pool.write().unwrap().insert(id, enb);
        id
    }

    /// Remove an eNB
    pub fn enb_remove(&self, id: u64) -> bool {
        self.enb_pool.write().unwrap().remove(&id).is_some()
    }

    /// Find eNB by address
    pub fn enb_find_by_addr(&self, addr: &std::net::SocketAddr) -> Option<u64> {
        let key = addr.to_string();
        self.enb_addr_hash.read().unwrap().get(&key).copied()
    }

    /// Find eNB by eNB ID
    pub fn enb_find_by_enb_id(&self, enb_id: u32) -> Option<u64> {
        self.enb_id_hash.read().unwrap().get(&enb_id).copied()
    }

    /// Set eNB ID
    pub fn enb_set_enb_id(&self, id: u64, enb_id: u32) -> bool {
        if let Some(enb) = self.enb_pool.write().unwrap().get_mut(&id) {
            enb.enb_id = enb_id;
            enb.enb_id_presence = true;
            self.enb_id_hash.write().unwrap().insert(enb_id, id);
            true
        } else {
            false
        }
    }

    /// Get eNB by pool ID
    pub fn enb_find_by_id(&self, id: u64) -> Option<MmeEnb> {
        self.enb_pool.read().unwrap().get(&id).cloned()
    }
}


// ============================================================================
// eNB UE Management
// ============================================================================

impl MmeContext {
    /// Add a new eNB UE
    pub fn enb_ue_add(&self, enb_id: u64, enb_ue_s1ap_id: u32) -> u64 {
        let id = self.next_pool_id();
        let mme_ue_s1ap_id = self.next_mme_ue_s1ap_id();
        let enb_ue = EnbUe {
            id,
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            enb_id,
            mme_ue_id: OGS_INVALID_POOL_ID,
            ..Default::default()
        };
        self.enb_ue_pool.write().unwrap().insert(id, enb_ue);
        id
    }

    /// Remove an eNB UE
    pub fn enb_ue_remove(&self, id: u64) -> bool {
        self.enb_ue_pool.write().unwrap().remove(&id).is_some()
    }

    /// Find eNB UE by pool ID
    pub fn enb_ue_find_by_id(&self, id: u64) -> Option<EnbUe> {
        self.enb_ue_pool.read().unwrap().get(&id).cloned()
    }

    /// Find eNB UE by MME UE S1AP ID
    pub fn enb_ue_find_by_mme_ue_s1ap_id(&self, mme_ue_s1ap_id: u32) -> Option<u64> {
        self.enb_ue_pool.read().unwrap()
            .iter()
            .find(|(_, ue)| ue.mme_ue_s1ap_id == mme_ue_s1ap_id)
            .map(|(id, _)| *id)
    }
}

// ============================================================================
// SGW UE Management
// ============================================================================

impl MmeContext {
    /// Add a new SGW UE
    pub fn sgw_ue_add(&self, sgw_id: u64) -> u64 {
        let id = self.next_pool_id();
        let sgw_ue = SgwUe {
            id,
            sgw_id,
            mme_ue_id: OGS_INVALID_POOL_ID,
            ..Default::default()
        };
        self.sgw_ue_pool.write().unwrap().insert(id, sgw_ue);
        id
    }

    /// Remove an SGW UE
    pub fn sgw_ue_remove(&self, id: u64) -> bool {
        self.sgw_ue_pool.write().unwrap().remove(&id).is_some()
    }

    /// Find SGW UE by pool ID
    pub fn sgw_ue_find_by_id(&self, id: u64) -> Option<SgwUe> {
        self.sgw_ue_pool.read().unwrap().get(&id).cloned()
    }
}


// ============================================================================
// MME UE Management
// ============================================================================

impl MmeContext {
    /// Add a new MME UE
    pub fn mme_ue_add(&self, enb_ue_id: u64) -> u64 {
        let id = self.next_pool_id();
        let mme_ue = MmeUe {
            id,
            enb_ue_id,
            enb_ue_holding_id: OGS_INVALID_POOL_ID,
            sgw_ue_id: OGS_INVALID_POOL_ID,
            ..Default::default()
        };
        self.mme_ue_pool.write().unwrap().insert(id, mme_ue);
        id
    }

    /// Remove an MME UE
    pub fn mme_ue_remove(&self, id: u64) -> bool {
        if let Some(ue) = self.mme_ue_pool.write().unwrap().remove(&id) {
            // Remove from hash tables
            if !ue.imsi_bcd.is_empty() {
                self.imsi_ue_hash.write().unwrap().remove(&ue.imsi_bcd);
            }
            true
        } else {
            false
        }
    }

    /// Find MME UE by pool ID
    pub fn mme_ue_find_by_id(&self, id: u64) -> Option<MmeUe> {
        self.mme_ue_pool.read().unwrap().get(&id).cloned()
    }

    /// Find MME UE by IMSI
    pub fn mme_ue_find_by_imsi(&self, imsi_bcd: &str) -> Option<u64> {
        self.imsi_ue_hash.read().unwrap().get(imsi_bcd).copied()
    }

    /// Find MME UE by GUTI
    pub fn mme_ue_find_by_guti(&self, guti: &EpsGuti) -> Option<u64> {
        self.guti_ue_hash.read().unwrap().get(guti).copied()
    }

    /// Find MME UE by S11 local TEID
    pub fn mme_ue_find_by_s11_local_teid(&self, teid: u32) -> Option<u64> {
        self.mme_s11_teid_hash.read().unwrap().get(&teid).copied()
    }

    /// Set IMSI for MME UE
    pub fn mme_ue_set_imsi(&self, id: u64, imsi_bcd: &str) -> bool {
        if let Some(ue) = self.mme_ue_pool.write().unwrap().get_mut(&id) {
            ue.imsi_bcd = imsi_bcd.to_string();
            ue.imsi_len = imsi_bcd.len().min(OGS_MAX_IMSI_LEN);
            self.imsi_ue_hash.write().unwrap().insert(imsi_bcd.to_string(), id);
            true
        } else {
            false
        }
    }
}


// ============================================================================
// Session Management
// ============================================================================

impl MmeContext {
    /// Add a new session
    pub fn sess_add(&self, mme_ue_id: u64, pti: u8) -> u64 {
        let id = self.next_pool_id();
        let sess = MmeSess {
            id,
            pti,
            mme_ue_id,
            ..Default::default()
        };
        self.sess_pool.write().unwrap().insert(id, sess);
        id
    }

    /// Remove a session
    pub fn sess_remove(&self, id: u64) -> bool {
        self.sess_pool.write().unwrap().remove(&id).is_some()
    }

    /// Find session by pool ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<MmeSess> {
        self.sess_pool.read().unwrap().get(&id).cloned()
    }

    /// Find session by PTI
    pub fn sess_find_by_pti(&self, mme_ue_id: u64, pti: u8) -> Option<u64> {
        self.sess_pool.read().unwrap()
            .iter()
            .find(|(_, s)| s.mme_ue_id == mme_ue_id && s.pti == pti)
            .map(|(id, _)| *id)
    }
}

// ============================================================================
// Bearer Management
// ============================================================================

impl MmeContext {
    /// Add a new bearer
    pub fn bearer_add(&self, sess_id: u64, mme_ue_id: u64) -> u64 {
        let id = self.next_pool_id();
        let bearer = MmeBearer {
            id,
            sess_id,
            mme_ue_id,
            ..Default::default()
        };
        self.bearer_pool.write().unwrap().insert(id, bearer);
        id
    }

    /// Remove a bearer
    pub fn bearer_remove(&self, id: u64) -> bool {
        self.bearer_pool.write().unwrap().remove(&id).is_some()
    }

    /// Find bearer by pool ID
    pub fn bearer_find_by_id(&self, id: u64) -> Option<MmeBearer> {
        self.bearer_pool.read().unwrap().get(&id).cloned()
    }

    /// Find bearer by EBI
    pub fn bearer_find_by_ebi(&self, mme_ue_id: u64, ebi: u8) -> Option<u64> {
        self.bearer_pool.read().unwrap()
            .iter()
            .find(|(_, b)| b.mme_ue_id == mme_ue_id && b.ebi == ebi)
            .map(|(id, _)| *id)
    }
}


// ============================================================================
// SGW/PGW/VLR Management
// ============================================================================

impl MmeContext {
    /// Add a new SGW
    pub fn sgw_add(&self, addr: std::net::SocketAddr) -> u64 {
        let id = self.next_pool_id();
        let sgw = MmeSgw {
            id,
            addr: Some(addr),
            ..Default::default()
        };
        self.sgw_pool.write().unwrap().insert(id, sgw);
        id
    }

    /// Remove an SGW
    pub fn sgw_remove(&self, id: u64) -> bool {
        self.sgw_pool.write().unwrap().remove(&id).is_some()
    }

    /// Add a new PGW
    pub fn pgw_add(&self, addr: std::net::SocketAddr) -> u64 {
        let id = self.next_pool_id();
        let pgw = MmePgw {
            id,
            sa_list: vec![addr],
            ..Default::default()
        };
        self.pgw_pool.write().unwrap().insert(id, pgw);
        id
    }

    /// Remove a PGW
    pub fn pgw_remove(&self, id: u64) -> bool {
        self.pgw_pool.write().unwrap().remove(&id).is_some()
    }

    /// Add a new VLR
    pub fn vlr_add(&self, addr: std::net::SocketAddr) -> u64 {
        let id = self.next_pool_id();
        let vlr = MmeVlr {
            id,
            sa_list: vec![addr],
            ..Default::default()
        };
        self.vlr_pool.write().unwrap().insert(id, vlr);
        id
    }

    /// Remove a VLR
    pub fn vlr_remove(&self, id: u64) -> bool {
        self.vlr_pool.write().unwrap().remove(&id).is_some()
    }
}

// ============================================================================
// Association Management
// ============================================================================

impl MmeContext {
    /// Associate eNB UE with MME UE
    pub fn enb_ue_associate_mme_ue(&self, enb_ue_id: u64, mme_ue_id: u64) {
        if let Some(enb_ue) = self.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
            enb_ue.mme_ue_id = mme_ue_id;
        }
        if let Some(mme_ue) = self.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.enb_ue_id = enb_ue_id;
        }
    }

    /// Deassociate eNB UE from MME UE
    pub fn enb_ue_deassociate_mme_ue(&self, enb_ue_id: u64, mme_ue_id: u64) {
        if let Some(enb_ue) = self.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
            enb_ue.mme_ue_id = OGS_INVALID_POOL_ID;
        }
        if let Some(mme_ue) = self.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.enb_ue_id = OGS_INVALID_POOL_ID;
        }
    }

    /// Associate SGW UE with MME UE
    pub fn sgw_ue_associate_mme_ue(&self, sgw_ue_id: u64, mme_ue_id: u64) {
        if let Some(sgw_ue) = self.sgw_ue_pool.write().unwrap().get_mut(&sgw_ue_id) {
            sgw_ue.mme_ue_id = mme_ue_id;
        }
        if let Some(mme_ue) = self.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.sgw_ue_id = sgw_ue_id;
        }
    }
}


// ============================================================================
// Utility Functions
// ============================================================================

impl MmeContext {
    /// Find served TAI
    pub fn find_served_tai(&self, tai: &EpsTai) -> Option<usize> {
        for (idx, served) in self.served_tai.iter().enumerate() {
            // Check TAI0 list
            if served.list0.plmn_id == tai.plmn_id {
                if served.list0.tac.contains(&tai.tac) {
                    return Some(idx);
                }
            }
            // Check TAI2 list
            for t in &served.list2.tai {
                if t == tai {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Check if UE has indirect tunnel
    pub fn mme_ue_have_indirect_tunnel(&self, mme_ue_id: u64) -> bool {
        if let Some(mme_ue) = self.mme_ue_find_by_id(mme_ue_id) {
            for sess_id in &mme_ue.sess_list {
                if let Some(sess) = self.sess_find_by_id(*sess_id) {
                    for bearer_id in &sess.bearer_list {
                        if let Some(bearer) = self.bearer_find_by_id(*bearer_id) {
                            if bearer.enb_dl_teid != 0 || bearer.enb_ul_teid != 0 ||
                               bearer.sgw_dl_teid != 0 || bearer.sgw_ul_teid != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if UE has active EPS bearers
    pub fn mme_ue_have_active_eps_bearers(&self, mme_ue_id: u64) -> bool {
        if let Some(mme_ue) = self.mme_ue_find_by_id(mme_ue_id) {
            for sess_id in &mme_ue.sess_list {
                if let Some(sess) = self.sess_find_by_id(*sess_id) {
                    for bearer_id in &sess.bearer_list {
                        if let Some(bearer) = self.bearer_find_by_id(*bearer_id) {
                            if bearer.enb_s1u_teid != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Get session count for UE
    pub fn mme_sess_count(&self, mme_ue_id: u64) -> usize {
        if let Some(mme_ue) = self.mme_ue_find_by_id(mme_ue_id) {
            mme_ue.sess_list.len()
        } else {
            0
        }
    }
}

// ============================================================================
// Global Context Instance
// ============================================================================

use std::sync::OnceLock;

static MME_CONTEXT: OnceLock<MmeContext> = OnceLock::new();

/// Get the global MME context
pub fn mme_self() -> &'static MmeContext {
    MME_CONTEXT.get_or_init(MmeContext::new)
}

/// Initialize the global MME context
pub fn mme_context_init() {
    mme_self().init();
}

/// Finalize the global MME context
pub fn mme_context_final() {
    mme_self().final_();
}
