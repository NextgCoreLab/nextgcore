//! EMM Message Building
//!
//! Port of src/mme/emm-build.c - EMM message building functions

use crate::context::{MmeUe, PlmnId, EpsTai};

// ============================================================================
// EMM Cause Codes (3GPP TS 24.301)
// ============================================================================

/// EMM Cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmmCause {
    /// IMSI unknown in HSS
    ImsiUnknownInHss = 2,
    /// Illegal UE
    IllegalUe = 3,
    /// IMEI not accepted
    ImeiNotAccepted = 5,
    /// Illegal ME
    IllegalMe = 6,
    /// EPS services not allowed
    EpsServicesNotAllowed = 7,
    /// EPS services and non-EPS services not allowed
    EpsAndNonEpsServicesNotAllowed = 8,
    /// UE identity cannot be derived by the network
    UeIdentityCannotBeDerived = 9,
    /// Implicitly detached
    ImplicitlyDetached = 10,
    /// PLMN not allowed
    PlmnNotAllowed = 11,
    /// Tracking area not allowed
    TrackingAreaNotAllowed = 12,
    /// Roaming not allowed in this tracking area
    RoamingNotAllowedInTa = 13,
    /// EPS services not allowed in this PLMN
    EpsServicesNotAllowedInPlmn = 14,
    /// No suitable cells in tracking area
    NoSuitableCellsInTa = 15,
    /// MSC temporarily not reachable
    MscTemporarilyNotReachable = 16,
    /// Network failure
    NetworkFailure = 17,
    /// CS domain not available
    CsDomainNotAvailable = 18,
    /// ESM failure
    EsmFailure = 19,
    /// MAC failure
    MacFailure = 20,
    /// Synch failure
    SynchFailure = 21,
    /// Congestion
    Congestion = 22,
    /// UE security capabilities mismatch
    UeSecurityCapabilitiesMismatch = 23,
    /// Security mode rejected, unspecified
    SecurityModeRejectedUnspecified = 24,
    /// Not authorized for this CSG
    NotAuthorizedForCsg = 25,
    /// Non-EPS authentication unacceptable
    NonEpsAuthenticationUnacceptable = 26,
    /// Requested service option not authorized in this PLMN
    RequestedServiceOptionNotAuthorizedInPlmn = 35,
    /// CS service temporarily not available
    CsServiceTemporarilyNotAvailable = 39,
    /// No EPS bearer context activated
    NoEpsBearerContextActivated = 40,
    /// Severe network failure
    SevereNetworkFailure = 42,
    /// Semantically incorrect message
    SemanticallyIncorrectMessage = 95,
    /// Invalid mandatory information
    InvalidMandatoryInformation = 96,
    /// Message type non-existent or not implemented
    MessageTypeNonExistent = 97,
    /// Message type not compatible with protocol state
    MessageTypeNotCompatible = 98,
    /// Information element non-existent or not implemented
    InformationElementNonExistent = 99,
    /// Conditional IE error
    ConditionalIeError = 100,
    /// Message not compatible with protocol state
    MessageNotCompatible = 101,
    /// Protocol error, unspecified
    ProtocolErrorUnspecified = 111,
    /// Request accepted
    RequestAccepted = 0,
}

impl Default for EmmCause {
    fn default() -> Self {
        EmmCause::RequestAccepted
    }
}

// ============================================================================
// NAS EPS Message Types
// ============================================================================

/// NAS EPS message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NasEpsMessageType {
    /// Attach request
    AttachRequest = 0x41,
    /// Attach accept
    AttachAccept = 0x42,
    /// Attach complete
    AttachComplete = 0x43,
    /// Attach reject
    AttachReject = 0x44,
    /// Detach request
    DetachRequest = 0x45,
    /// Detach accept
    DetachAccept = 0x46,
    /// Tracking area update request
    TauRequest = 0x48,
    /// Tracking area update accept
    TauAccept = 0x49,
    /// Tracking area update complete
    TauComplete = 0x4a,
    /// Tracking area update reject
    TauReject = 0x4b,
    /// Extended service request
    ExtendedServiceRequest = 0x4c,
    /// Service reject
    ServiceReject = 0x4e,
    /// GUTI reallocation command
    GutiReallocationCommand = 0x50,
    /// GUTI reallocation complete
    GutiReallocationComplete = 0x51,
    /// Authentication request
    AuthenticationRequest = 0x52,
    /// Authentication response
    AuthenticationResponse = 0x53,
    /// Authentication reject
    AuthenticationReject = 0x54,
    /// Authentication failure
    AuthenticationFailure = 0x5c,
    /// Identity request
    IdentityRequest = 0x55,
    /// Identity response
    IdentityResponse = 0x56,
    /// Security mode command
    SecurityModeCommand = 0x5d,
    /// Security mode complete
    SecurityModeComplete = 0x5e,
    /// Security mode reject
    SecurityModeReject = 0x5f,
    /// EMM status
    EmmStatus = 0x60,
    /// EMM information
    EmmInformation = 0x61,
    /// Downlink NAS transport
    DownlinkNasTransport = 0x62,
    /// Uplink NAS transport
    UplinkNasTransport = 0x63,
    /// CS service notification
    CsServiceNotification = 0x64,
    /// Service request
    ServiceRequest = 0x4d,
}

// ============================================================================
// NAS Protocol Discriminator
// ============================================================================

/// NAS Protocol Discriminator
pub const NAS_PROTOCOL_DISCRIMINATOR_EMM: u8 = 0x07;
pub const NAS_PROTOCOL_DISCRIMINATOR_ESM: u8 = 0x02;

// ============================================================================
// Security Header Types
// ============================================================================

/// NAS Security Header Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityHeaderType {
    /// Plain NAS message
    PlainNas = 0,
    /// Integrity protected
    IntegrityProtected = 1,
    /// Integrity protected and ciphered
    IntegrityProtectedAndCiphered = 2,
    /// Integrity protected with new EPS security context
    IntegrityProtectedNewContext = 3,
    /// Integrity protected and ciphered with new EPS security context
    IntegrityProtectedAndCipheredNewContext = 4,
}

// ============================================================================
// Attach Types
// ============================================================================

/// EPS Attach Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AttachType {
    #[default]
    /// EPS attach
    EpsAttach = 1,
    /// Combined EPS/IMSI attach
    CombinedEpsImsiAttach = 2,
    /// EPS emergency attach
    EpsEmergencyAttach = 3,
}

// ============================================================================
// Identity Types
// ============================================================================

/// Identity Type 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityType2 {
    /// IMSI
    Imsi = 1,
    /// IMEI
    Imei = 2,
    /// IMEISV
    Imeisv = 3,
    /// TMSI
    Tmsi = 4,
}

// ============================================================================
// Detach Types
// ============================================================================

/// Detach Type (from UE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DetachTypeFromUe {
    /// EPS detach
    EpsDetach = 1,
    /// IMSI detach
    ImsiDetach = 2,
    /// Combined EPS/IMSI detach
    CombinedEpsImsiDetach = 3,
}

/// Detach Type (to UE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DetachTypeToUe {
    /// Re-attach required
    ReAttachRequired = 1,
    /// Re-attach not required
    ReAttachNotRequired = 2,
    /// IMSI detach
    ImsiDetach = 3,
}

// ============================================================================
// Update Types
// ============================================================================

/// EPS Update Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateType {
    /// TA updating
    TaUpdating = 0,
    /// Combined TA/LA updating
    CombinedTaLaUpdating = 1,
    /// Combined TA/LA updating with IMSI attach
    CombinedTaLaUpdatingWithImsiAttach = 2,
    /// Periodic updating
    PeriodicUpdating = 3,
}

// ============================================================================
// GPRS Timer
// ============================================================================

/// GPRS Timer value
#[derive(Debug, Clone, Default)]
pub struct GprsTimer {
    /// Timer unit (0=2s, 1=1min, 2=6min, 7=deactivated)
    pub unit: u8,
    /// Timer value (0-31)
    pub value: u8,
}

impl GprsTimer {
    /// Create timer from seconds
    pub fn from_sec(seconds: u32) -> Self {
        if seconds == 0 {
            return Self { unit: 7, value: 0 }; // Deactivated
        }
        
        // Try 2-second increments (unit 0)
        if seconds <= 62 {
            return Self { unit: 0, value: ((seconds + 1) / 2) as u8 };
        }
        
        // Try 1-minute increments (unit 1)
        let minutes = (seconds + 59) / 60;
        if minutes <= 31 {
            return Self { unit: 1, value: minutes as u8 };
        }
        
        // Try 6-minute increments (unit 2)
        let six_minutes = (seconds + 359) / 360;
        if six_minutes <= 31 {
            return Self { unit: 2, value: six_minutes as u8 };
        }
        
        // Maximum value
        Self { unit: 2, value: 31 }
    }
    
    /// Encode to byte
    pub fn encode(&self) -> u8 {
        (self.unit << 5) | (self.value & 0x1f)
    }
}

// ============================================================================
// NAS Message Buffer
// ============================================================================

/// NAS message buffer for building messages
#[derive(Debug, Clone, Default)]
pub struct NasBuffer {
    /// Message data
    pub data: Vec<u8>,
}

impl NasBuffer {
    /// Create new buffer
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(256) }
    }
    
    /// Write byte
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }
    
    /// Write 16-bit value (big endian)
    pub fn write_u16(&mut self, value: u16) {
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }
    
    /// Write 32-bit value (big endian)
    pub fn write_u32(&mut self, value: u32) {
        self.data.push((value >> 24) as u8);
        self.data.push((value >> 16) as u8);
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }
    
    /// Write bytes
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
    
    /// Write length-prefixed bytes
    pub fn write_lv(&mut self, bytes: &[u8]) {
        self.data.push(bytes.len() as u8);
        self.data.extend_from_slice(bytes);
    }
    
    /// Get data
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
    
    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ============================================================================
// EMM Message Building Functions
// ============================================================================

/// Build attach accept message
pub fn build_attach_accept(
    mme_ue: &MmeUe,
    esm_message: &[u8],
    t3412_value: u32,
    tai_list: &[EpsTai],
) -> Result<Vec<u8>, &'static str> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::AttachAccept as u8);
    
    // EPS attach result (4 bits) + spare (4 bits)
    let attach_result = AttachType::EpsAttach as u8;
    buf.write_u8(attach_result & 0x07);
    
    // T3412 value
    let timer = GprsTimer::from_sec(t3412_value);
    buf.write_u8(timer.encode());
    
    // TAI list
    if !tai_list.is_empty() {
        let tai_list_data = encode_tai_list(tai_list);
        buf.write_lv(&tai_list_data);
    } else {
        buf.write_u8(0); // Empty TAI list
    }
    
    // ESM message container
    buf.write_u16(esm_message.len() as u16);
    buf.write_bytes(esm_message);
    
    // Optional: GUTI (if available)
    if mme_ue.next.m_tmsi.is_some() {
        buf.write_u8(0x50); // GUTI IEI
        buf.write_u8(11);   // Length
        buf.write_u8(0xf6); // Odd/even + type
        // PLMN ID
        let plmn = encode_plmn_id(&mme_ue.next.guti.plmn_id);
        buf.write_bytes(&plmn);
        // MME Group ID
        buf.write_u16(mme_ue.next.guti.mme_gid);
        // MME Code
        buf.write_u8(mme_ue.next.guti.mme_code);
        // M-TMSI
        buf.write_u32(mme_ue.next.guti.m_tmsi);
    }
    
    Ok(buf.into_vec())
}

/// Build attach reject message
pub fn build_attach_reject(
    emm_cause: EmmCause,
    esm_message: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::AttachReject as u8);
    
    // EMM cause
    buf.write_u8(emm_cause as u8);
    
    // Optional: ESM message container
    if let Some(esm) = esm_message {
        buf.write_u8(0x78); // ESM message container IEI
        buf.write_u16(esm.len() as u16);
        buf.write_bytes(esm);
    }
    
    buf.into_vec()
}

/// Build identity request message
pub fn build_identity_request(identity_type: IdentityType2) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::IdentityRequest as u8);
    
    // Identity type (4 bits) + spare (4 bits)
    buf.write_u8(identity_type as u8);
    
    buf.into_vec()
}

/// Build authentication request message
pub fn build_authentication_request(
    ksi: u8,
    rand: &[u8; 16],
    autn: &[u8; 16],
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::AuthenticationRequest as u8);
    
    // NAS key set identifier (4 bits) + spare (4 bits)
    buf.write_u8(ksi & 0x07);
    
    // RAND
    buf.write_bytes(rand);
    
    // AUTN (length + value)
    buf.write_u8(16);
    buf.write_bytes(autn);
    
    buf.into_vec()
}

/// Build authentication reject message
pub fn build_authentication_reject() -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::AuthenticationReject as u8);
    
    buf.into_vec()
}

/// Build security mode command message
pub fn build_security_mode_command(
    mme_ue: &MmeUe,
    ksi: u8,
    selected_enc_algorithm: u8,
    selected_int_algorithm: u8,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header (integrity protected with new security context)
    buf.write_u8((SecurityHeaderType::IntegrityProtectedNewContext as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::SecurityModeCommand as u8);
    
    // Selected NAS security algorithms
    buf.write_u8((selected_enc_algorithm << 4) | selected_int_algorithm);
    
    // NAS key set identifier
    buf.write_u8(ksi & 0x07);
    
    // Replayed UE security capabilities
    let mut ue_sec_cap = Vec::new();
    ue_sec_cap.push(mme_ue.ue_network_capability.eea);
    ue_sec_cap.push(mme_ue.ue_network_capability.eia);
    if mme_ue.ue_network_capability.uea != 0 || mme_ue.ue_network_capability.uia != 0 {
        ue_sec_cap.push(mme_ue.ue_network_capability.uea);
        ue_sec_cap.push(mme_ue.ue_network_capability.uia & 0x7f);
    }
    buf.write_lv(&ue_sec_cap);
    
    // Optional: IMEISV request
    buf.write_u8(0xc0 | 0x01); // IEI + IMEISV requested
    
    // Optional: HashMME
    if !mme_ue.hash_mme.iter().all(|&b| b == 0) {
        buf.write_u8(0x4f); // HashMME IEI
        buf.write_u8(8);    // Length
        buf.write_bytes(&mme_ue.hash_mme);
    }
    
    buf.into_vec()
}

/// Build detach request message (to UE)
pub fn build_detach_request(
    _mme_ue: &MmeUe,
    detach_type: DetachTypeToUe,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::DetachRequest as u8);
    
    // Detach type (4 bits) + spare (4 bits)
    buf.write_u8(detach_type as u8);
    
    // Optional: EMM cause (if re-attach required)
    if detach_type == DetachTypeToUe::ReAttachRequired {
        buf.write_u8(0x53); // EMM cause IEI
        buf.write_u8(EmmCause::ImplicitlyDetached as u8);
    }
    
    buf.into_vec()
}

/// Build detach accept message
pub fn build_detach_accept(_mme_ue: &MmeUe) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::DetachAccept as u8);
    
    buf.into_vec()
}

/// Build TAU accept message
pub fn build_tau_accept(
    mme_ue: &MmeUe,
    t3412_value: u32,
    tai_list: &[EpsTai],
    eps_bearer_status: u16,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::TauAccept as u8);
    
    // EPS update result (4 bits) + spare (4 bits)
    buf.write_u8(0x00); // TA updated
    
    // Optional: T3412 value
    if t3412_value > 0 {
        buf.write_u8(0x5a); // T3412 IEI
        let timer = GprsTimer::from_sec(t3412_value);
        buf.write_u8(timer.encode());
    }
    
    // Optional: GUTI
    if mme_ue.next.m_tmsi.is_some() {
        buf.write_u8(0x50); // GUTI IEI
        buf.write_u8(11);   // Length
        buf.write_u8(0xf6); // Odd/even + type
        let plmn = encode_plmn_id(&mme_ue.next.guti.plmn_id);
        buf.write_bytes(&plmn);
        buf.write_u16(mme_ue.next.guti.mme_gid);
        buf.write_u8(mme_ue.next.guti.mme_code);
        buf.write_u32(mme_ue.next.guti.m_tmsi);
    }
    
    // Optional: TAI list
    if !tai_list.is_empty() {
        buf.write_u8(0x54); // TAI list IEI
        let tai_list_data = encode_tai_list(tai_list);
        buf.write_lv(&tai_list_data);
    }
    
    // Optional: EPS bearer context status
    if eps_bearer_status != 0 {
        buf.write_u8(0x57); // EPS bearer context status IEI
        buf.write_u8(2);    // Length
        buf.write_u16(eps_bearer_status);
    }
    
    buf.into_vec()
}

/// Build TAU reject message
pub fn build_tau_reject(emm_cause: EmmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::TauReject as u8);
    
    // EMM cause
    buf.write_u8(emm_cause as u8);
    
    buf.into_vec()
}

/// Build service reject message
pub fn build_service_reject(emm_cause: EmmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::ServiceReject as u8);
    
    // EMM cause
    buf.write_u8(emm_cause as u8);
    
    buf.into_vec()
}

/// Build CS service notification message
pub fn build_cs_service_notification(paging_identity: u8) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // EMM header (plain NAS - will be security encoded later)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::CsServiceNotification as u8);
    
    // Paging identity
    buf.write_u8(paging_identity);
    
    buf.into_vec()
}

/// Build EMM information message
pub fn build_emm_information(
    full_network_name: Option<&str>,
    short_network_name: Option<&str>,
    local_time_zone: Option<i8>,
    universal_time: Option<&[u8; 7]>,
    daylight_saving_time: Option<u8>,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // EMM header
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::EmmInformation as u8);
    
    // Optional: Full network name
    if let Some(name) = full_network_name {
        buf.write_u8(0x43); // Full name IEI
        let encoded = encode_network_name(name);
        buf.write_lv(&encoded);
    }
    
    // Optional: Short network name
    if let Some(name) = short_network_name {
        buf.write_u8(0x45); // Short name IEI
        let encoded = encode_network_name(name);
        buf.write_lv(&encoded);
    }
    
    // Optional: Local time zone
    if let Some(tz) = local_time_zone {
        buf.write_u8(0x46); // Local time zone IEI
        buf.write_u8(encode_time_zone(tz));
    }
    
    // Optional: Universal time and local time zone
    if let Some(time) = universal_time {
        buf.write_u8(0x47); // Universal time IEI
        buf.write_bytes(time);
    }
    
    // Optional: Daylight saving time
    if let Some(dst) = daylight_saving_time {
        buf.write_u8(0x49); // DST IEI
        buf.write_u8(1);    // Length
        buf.write_u8(dst);
    }
    
    buf.into_vec()
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode PLMN ID to 3 bytes
fn encode_plmn_id(plmn: &PlmnId) -> [u8; 3] {
    let mut bytes = [0u8; 3];
    bytes[0] = (plmn.mcc2 << 4) | plmn.mcc1;
    if plmn.mnc3 == 0x0f {
        bytes[1] = 0xf0 | plmn.mcc3;
    } else {
        bytes[1] = (plmn.mnc3 << 4) | plmn.mcc3;
    }
    bytes[2] = (plmn.mnc2 << 4) | plmn.mnc1;
    bytes
}

/// Encode TAI list
fn encode_tai_list(tai_list: &[EpsTai]) -> Vec<u8> {
    if tai_list.is_empty() {
        return vec![];
    }
    
    let mut buf = Vec::new();
    
    // Type 0 list: same PLMN, different TACs
    // For simplicity, encode as type 1 (list of TAIs)
    let num_tai = tai_list.len().min(16) as u8;
    buf.push(0x20 | (num_tai - 1)); // Type 1 + number of elements
    
    for tai in tai_list.iter().take(16) {
        let plmn = encode_plmn_id(&tai.plmn_id);
        buf.extend_from_slice(&plmn);
        buf.push((tai.tac >> 8) as u8);
        buf.push(tai.tac as u8);
    }
    
    buf
}

/// Encode network name (GSM 7-bit default alphabet)
fn encode_network_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // Extension bit (1) + coding scheme (000) + add CI (0) + spare bits (000)
    buf.push(0x80);
    
    // Simple ASCII encoding (not full GSM 7-bit)
    for c in name.chars().take(255) {
        buf.push(c as u8);
    }
    
    buf
}

/// Encode time zone
fn encode_time_zone(offset_quarters: i8) -> u8 {
    let abs_offset = offset_quarters.unsigned_abs();
    let bcd = ((abs_offset / 10) & 0x0f) | (((abs_offset % 10) & 0x0f) << 4);
    if offset_quarters < 0 {
        bcd | 0x08
    } else {
        bcd
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gprs_timer_from_sec() {
        // 0 seconds = deactivated
        let timer = GprsTimer::from_sec(0);
        assert_eq!(timer.unit, 7);
        
        // 10 seconds = 5 * 2s
        let timer = GprsTimer::from_sec(10);
        assert_eq!(timer.unit, 0);
        assert_eq!(timer.value, 5);
        
        // 120 seconds = 2 minutes
        let timer = GprsTimer::from_sec(120);
        assert_eq!(timer.unit, 1);
        assert_eq!(timer.value, 2);
        
        // 3600 seconds = 10 * 6min
        let timer = GprsTimer::from_sec(3600);
        assert_eq!(timer.unit, 2);
        assert_eq!(timer.value, 10);
    }

    #[test]
    fn test_build_identity_request() {
        let msg = build_identity_request(IdentityType2::Imsi);
        assert_eq!(msg.len(), 3);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::IdentityRequest as u8);
        assert_eq!(msg[2], IdentityType2::Imsi as u8);
    }

    #[test]
    fn test_build_authentication_request() {
        let rand = [0x01u8; 16];
        let autn = [0x02u8; 16];
        let msg = build_authentication_request(1, &rand, &autn);
        
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::AuthenticationRequest as u8);
        assert_eq!(msg[2], 1); // KSI
        assert_eq!(&msg[3..19], &rand);
        assert_eq!(msg[19], 16); // AUTN length
        assert_eq!(&msg[20..36], &autn);
    }

    #[test]
    fn test_build_authentication_reject() {
        let msg = build_authentication_reject();
        assert_eq!(msg.len(), 2);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::AuthenticationReject as u8);
    }

    #[test]
    fn test_build_attach_reject() {
        let msg = build_attach_reject(EmmCause::PlmnNotAllowed, None);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::AttachReject as u8);
        assert_eq!(msg[2], EmmCause::PlmnNotAllowed as u8);
    }

    #[test]
    fn test_build_tau_reject() {
        let msg = build_tau_reject(EmmCause::TrackingAreaNotAllowed);
        assert_eq!(msg.len(), 3);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::TauReject as u8);
        assert_eq!(msg[2], EmmCause::TrackingAreaNotAllowed as u8);
    }

    #[test]
    fn test_build_service_reject() {
        let msg = build_service_reject(EmmCause::Congestion);
        assert_eq!(msg.len(), 3);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::ServiceReject as u8);
        assert_eq!(msg[2], EmmCause::Congestion as u8);
    }

    #[test]
    fn test_encode_plmn_id() {
        let plmn = PlmnId::new("310", "410");
        let encoded = encode_plmn_id(&plmn);
        // MCC=310, MNC=410 -> bytes should be [0x13, 0xf0, 0x14]
        assert_eq!(encoded[0], 0x13); // MCC2=1, MCC1=3
        assert_eq!(encoded[1] & 0x0f, 0x00); // MCC3=0
    }

    #[test]
    fn test_encode_time_zone() {
        // UTC+0
        assert_eq!(encode_time_zone(0), 0x00);
        
        // UTC+5:30 = 22 quarters
        let tz = encode_time_zone(22);
        assert_eq!(tz & 0x08, 0); // Positive
        
        // UTC-5 = -20 quarters
        let tz = encode_time_zone(-20);
        assert_eq!(tz & 0x08, 0x08); // Negative
    }

    #[test]
    fn test_nas_buffer() {
        let mut buf = NasBuffer::new();
        buf.write_u8(0x01);
        buf.write_u16(0x0203);
        buf.write_u32(0x04050607);
        buf.write_bytes(&[0x08, 0x09]);
        
        let data = buf.into_vec();
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
    }
}
