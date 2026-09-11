//! EMM Message Building
//!
//! Port of src/mme/emm-build.c - EMM message building functions

use crate::context::{EpsTai, MmeUe, PlmnId};

// ============================================================================
// EMM Cause Codes (3GPP TS 24.301)
// ============================================================================

/// EMM Cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
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
    #[default]
    RequestAccepted = 0,
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
            return Self {
                unit: 0,
                value: seconds.div_ceil(2) as u8,
            };
        }

        // Try 1-minute increments (unit 1)
        let minutes = seconds.div_ceil(60);
        if minutes <= 31 {
            return Self {
                unit: 1,
                value: minutes as u8,
            };
        }

        // Try 6-minute increments (unit 2)
        let six_minutes = seconds.div_ceil(360);
        if six_minutes <= 31 {
            return Self {
                unit: 2,
                value: six_minutes as u8,
            };
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
        Self {
            data: Vec::with_capacity(256),
        }
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

/// The EPS attach result to signal, and whether the CS domain was refused
/// (TS 24.301 §9.9.3.10, §5.5.1.3.4.3).
///
/// A combined EPS/IMSI attach can only be ACCEPTED as combined if this MME actually
/// has an SGs association for the UE's tracking area — `csmap_id` is the same test
/// the Extended Service Request path already uses to refuse CS fallback, so this is
/// the tree's existing notion of "is there a VLR", not a new one.
///
/// When the UE asked for combined and there is no SGs association, §5.5.1.3.4.3 is
/// explicit: answer "EPS only" AND set the EMM cause to #18 "CS domain not
/// available". Answering EPS-only with no cause — which is what a hardcoded result
/// did — tells the UE the network declined without saying why, so it never falls back
/// to attaching to the CS domain over another access.
fn attach_result_for(mme_ue: &MmeUe) -> (u8, bool) {
    let combined_requested = mme_ue.nas_eps.attach_type == AttachType::CombinedEpsImsiAttach as u8;
    if !combined_requested {
        return (AttachType::EpsAttach as u8, false);
    }
    if mme_ue.csmap_id == crate::context::NEXTGCORE_INVALID_POOL_ID {
        log::info!(
            "[{}] combined EPS/IMSI attach requested with no SGs association: answering EPS \
             only with EMM cause #18 (TS 24.301 §5.5.1.3.4.3)",
            mme_ue.imsi_bcd
        );
        return (AttachType::EpsAttach as u8, true);
    }
    (AttachType::CombinedEpsImsiAttach as u8, false)
}

/// Build attach accept message
pub fn build_attach_accept(
    mme_ue: &MmeUe,
    esm_message: &[u8],
    t3412_value: u32,
    tai_list: &[EpsTai],
) -> Result<Vec<u8>, &'static str> {
    let mut buf = NasBuffer::new();

    // EMM header. The security header is deliberately NOT written here: every
    // caller passes this message through `nas_security::nas_eps_security_encode`,
    // which prepends the real 6-octet header with a computed MAC. Writing a
    // placeholder as well produced a message with two headers, the inner one
    // covered by the MAC (issue #44).
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::AttachAccept as u8);

    // EPS attach result (TS 24.301 §9.9.3.10): 1 = EPS only, 2 = combined EPS/IMSI.
    //
    // #46: this was the literal `AttachType::EpsAttach`, so a UE that asked for a
    // combined EPS/IMSI attach was always told EPS-only with no cause — which reads
    // to the UE as "the network chose not to", and leaves it with no reason to
    // attach to the CS domain separately.
    //
    // §9.9.3.11 has three attach TYPES and §9.9.3.10 only two RESULTS: an emergency
    // attach (type 3) is an EPS-only attach, so it answers 1.
    let (attach_result, cs_domain_refused) = attach_result_for(mme_ue);
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
        buf.write_u8(11); // Length
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

    // EMM cause (IEI 0x53, optional). Present only to say WHY a combined attach was
    // downgraded; a UE that asked for EPS-only gets no cause, because there is
    // nothing to explain.
    if cs_domain_refused {
        buf.write_u8(0x53);
        buf.write_u8(EmmCause::CsDomainNotAvailable as u8);
    }

    Ok(buf.into_vec())
}

/// Build attach reject message
pub fn build_attach_reject(emm_cause: EmmCause, esm_message: Option<&[u8]>) -> Vec<u8> {
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
pub fn build_authentication_request(ksi: u8, rand: &[u8; 16], autn: &[u8; 16]) -> Vec<u8> {
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

    // EMM header only; `nas_eps_security_encode` prepends the security header
    // with the new-context header type and the real MAC (issue #44).
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
        buf.write_u8(8); // Length
        buf.write_bytes(&mme_ue.hash_mme);
    }

    buf.into_vec()
}

/// Build detach request message (to UE)
pub fn build_detach_request(_mme_ue: &MmeUe, detach_type: DetachTypeToUe) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // EMM header only; `nas_eps_security_encode` prepends the security header
    // and the real MAC (issue #44).
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

    // EMM header only; `nas_eps_security_encode` prepends the security header
    // and the real MAC (issue #44).
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

    // EMM header only; `nas_eps_security_encode` prepends the security header
    // and the real MAC (issue #44).
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::TauAccept as u8);

    // EPS update result (4 bits) + spare (4 bits)
    // EPS update result (TS 24.301 §9.9.3.44). Hardcoded to 0 ("TA updated") before
    // #46, so a UE that asked for a combined TA/LA update was never told whether its
    // location area had been updated — and had no reason to think it had not.
    buf.write_u8(eps_update_result_for(mme_ue) & 0x07);

    // Optional: T3412 value
    if t3412_value > 0 {
        buf.write_u8(0x5a); // T3412 IEI
        let timer = GprsTimer::from_sec(t3412_value);
        buf.write_u8(timer.encode());
    }

    // Optional: GUTI
    if mme_ue.next.m_tmsi.is_some() {
        buf.write_u8(0x50); // GUTI IEI
        buf.write_u8(11); // Length
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
        buf.write_u8(2); // Length
        buf.write_u16(eps_bearer_status);
    }

    buf.into_vec()
}

/// The EPS update result to signal (TS 24.301 §9.9.3.44, §5.5.3.2.4).
///
/// TAU types (§9.9.3.45): 0 = TA updating, 1 = combined TA/LA updating,
/// 2 = combined with IMSI attach, 3 = periodic updating.
/// Update results (§9.9.3.44): 0 = TA updated, 1 = combined TA/LA updated.
///
/// A combined update can only be reported as combined if this MME has an SGs
/// association for the UE — same `csmap_id` test as the attach result and as the
/// Extended Service Request path. Reporting "combined TA/LA updated" without one
/// would claim a VLR update that never happened, which is worse than the
/// conservative answer: the UE would believe it is reachable for CS services it
/// cannot receive.
///
/// ISR (results 4 and 5) is deliberately never signalled: Idle-mode Signalling
/// Reduction requires an S3/S4 SGSN association, and this MME has none.
fn eps_update_result_for(mme_ue: &MmeUe) -> u8 {
    const TA_UPDATED: u8 = 0;
    const COMBINED_TA_LA_UPDATED: u8 = 1;

    let combined_requested = matches!(mme_ue.nas_eps.update_type, 1 | 2);
    if !combined_requested {
        return TA_UPDATED;
    }
    if mme_ue.csmap_id == crate::context::NEXTGCORE_INVALID_POOL_ID {
        log::info!(
            "[{}] combined TA/LA update requested with no SGs association: reporting \
             \"TA updated\" (TS 24.301 §5.5.3.2.4)",
            mme_ue.imsi_bcd
        );
        return TA_UPDATED;
    }
    COMBINED_TA_LA_UPDATED
}

/// The EPS bearer context status bitmap for a UE's active bearers
/// (TS 24.301 §9.9.2.1).
///
/// Bit N of the 16-bit value means EBI N is active. EBIs 0-4 are reserved
/// (TS 24.007 §11.2.3.1.5), so only 5-15 can ever be set.
///
/// Always passed as `0` before #46, and the builder omits the IE when it is zero — so
/// after a TAU the UE and the MME had no way to discover they disagreed about which
/// bearers exist, which is the whole purpose of the IE.
pub fn eps_bearer_context_status(ebis: impl IntoIterator<Item = u8>) -> u16 {
    let mut status = 0u16;
    for ebi in ebis {
        if (crate::context::MIN_EPS_BEARER_ID..=crate::context::MAX_EPS_BEARER_ID).contains(&ebi) {
            status |= 1 << ebi;
        } else {
            log::warn!("EBI {ebi} is outside the assignable range; omitted from the bearer status");
        }
    }
    status
}

/// Build GUTI Reallocation Command (TS 24.301 §5.4.1, §8.2.16).
///
/// The standalone GUTI reallocation procedure. `GutiReallocationCommand = 0x50` and
/// `GutiReallocationComplete = 0x51` existed as enum values with no builder and no
/// handler, so a GUTI could never be refreshed outside an attach or a TAU — which
/// means the temporary identity a UE presents was never rotated, and the IMSI
/// confidentiality the GUTI exists to provide degrades with every reuse.
///
/// The GUTI is taken from `next`, which is where [`crate::context::MmeContext::allocate_guti`]
/// stages it; `current` is promoted only when the UE acknowledges with 0x51.
pub fn build_guti_reallocation_command(mme_ue: &MmeUe, tai_list: &[EpsTai]) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u8(NasEpsMessageType::GutiReallocationCommand as u8);

    // GUTI (M, §9.9.3.12): the whole point of the message, so it is written
    // unconditionally rather than gated on `next.m_tmsi` the way the accepts are.
    buf.write_u8(11); // Length
    buf.write_u8(0xf6); // Odd/even + type = GUTI
    let plmn = encode_plmn_id(&mme_ue.next.guti.plmn_id);
    buf.write_bytes(&plmn);
    buf.write_u16(mme_ue.next.guti.mme_gid);
    buf.write_u8(mme_ue.next.guti.mme_code);
    buf.write_u32(mme_ue.next.guti.m_tmsi);

    // TAI list (O, IEI 0x54)
    if !tai_list.is_empty() {
        buf.write_u8(0x54);
        let tai_list_data = encode_tai_list(tai_list);
        buf.write_lv(&tai_list_data);
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

    // EMM header only; `nas_eps_security_encode` prepends the security header
    // and the real MAC (issue #44).
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
        buf.write_u8(1); // Length
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

/// Encode TAI list (TS 24.301 §9.9.3.33, partial tracking area identity list).
///
/// Octet 1 of each partial list: spare (bit 8) + type of list (bits 7-6) +
/// number of elements minus one (bits 5-1).
/// - Type "00": one PLMN, list of TACs (used when all TAIs share a PLMN)
/// - Type "10": explicit list of TAIs (used for mixed PLMNs)
fn encode_tai_list(tai_list: &[EpsTai]) -> Vec<u8> {
    if tai_list.is_empty() {
        return vec![];
    }

    let mut buf = Vec::new();
    let count = tai_list.len().min(16);
    let entries = &tai_list[..count];

    let first_plmn = encode_plmn_id(&entries[0].plmn_id);
    let same_plmn = entries
        .iter()
        .all(|tai| encode_plmn_id(&tai.plmn_id) == first_plmn);

    if same_plmn {
        // Type of list "00": one PLMN, non-consecutive TAC values
        buf.push((count as u8) - 1);
        buf.extend_from_slice(&first_plmn);
        for tai in entries {
            buf.push((tai.tac >> 8) as u8);
            buf.push(tai.tac as u8);
        }
    } else {
        // Type of list "10": explicit list of TAIs
        buf.push(0x40 | ((count as u8) - 1));
        for tai in entries {
            buf.extend_from_slice(&encode_plmn_id(&tai.plmn_id));
            buf.push((tai.tac >> 8) as u8);
            buf.push(tai.tac as u8);
        }
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

    // ================================================================
    // #46: the accept messages say what the negotiated procedure produced
    // ================================================================

    fn ue_with(attach_type: u8, csmap_id: u64) -> MmeUe {
        let mut ue = MmeUe {
            csmap_id,
            ..Default::default()
        };
        ue.nas_eps.attach_type = attach_type;
        ue
    }

    /// #46 criterion 8(c): a combined EPS/IMSI attach must yield a COMBINED result.
    ///
    /// The result was the literal `AttachType::EpsAttach`, so a UE asking for combined
    /// attach was always told EPS-only.
    #[test]
    fn a_combined_attach_with_an_sgs_association_yields_a_combined_result() {
        let ue = ue_with(AttachType::CombinedEpsImsiAttach as u8, 42);
        let msg = build_attach_accept(&ue, &[0x01], 600, &[]).expect("build");
        assert_eq!(
            msg[2] & 0x07,
            AttachType::CombinedEpsImsiAttach as u8,
            "a combined attach with a VLR must be accepted as combined"
        );
    }

    /// TS 24.301 §5.5.1.3.4.3: with no SGs association the MME answers EPS-only AND
    /// says why with EMM cause #18. Answering EPS-only silently — which a hardcoded
    /// result did — leaves the UE with no reason to attach to the CS domain elsewhere.
    #[test]
    fn a_combined_attach_without_an_sgs_association_is_eps_only_with_cause_18() {
        let ue = ue_with(
            AttachType::CombinedEpsImsiAttach as u8,
            crate::context::NEXTGCORE_INVALID_POOL_ID,
        );
        let msg = build_attach_accept(&ue, &[0x01], 600, &[]).expect("build");
        assert_eq!(msg[2] & 0x07, AttachType::EpsAttach as u8);
        let cause_iei = msg
            .windows(2)
            .position(|w| w[0] == 0x53)
            .expect("the EMM cause IE must be present");
        assert_eq!(
            msg[cause_iei + 1],
            EmmCause::CsDomainNotAvailable as u8,
            "the UE must be told the CS domain is unavailable, not just refused"
        );
    }

    /// An EPS-only attach gets no cause, because there is nothing to explain.
    #[test]
    fn an_eps_only_attach_carries_no_emm_cause() {
        let ue = ue_with(AttachType::EpsAttach as u8, 42);
        let msg = build_attach_accept(&ue, &[0x01], 600, &[]).expect("build");
        assert_eq!(msg[2] & 0x07, AttachType::EpsAttach as u8);
        assert!(
            !msg.windows(2).any(|w| w[0] == 0x53),
            "an unremarkable accept must not carry an EMM cause"
        );
    }

    /// TS 24.301 §9.9.3.10 has two attach RESULTS and §9.9.3.11 three TYPES: an
    /// emergency attach is an EPS-only attach, so it answers 1 rather than echoing 3.
    #[test]
    fn an_emergency_attach_is_answered_eps_only() {
        let ue = ue_with(AttachType::EpsEmergencyAttach as u8, 42);
        let msg = build_attach_accept(&ue, &[0x01], 600, &[]).expect("build");
        assert_eq!(msg[2] & 0x07, AttachType::EpsAttach as u8);
    }

    /// #46 criterion 8(b): T3412 is encoded from the value passed, not a literal 3600.
    ///
    /// The encoding is a GPRS Timer, so the assertion is against the encoded unit and
    /// value rather than the raw seconds — which is also what makes it catch a caller
    /// that passes the right number to the wrong parameter.
    #[test]
    fn the_attach_accept_encodes_the_t3412_it_is_given() {
        let ue = ue_with(AttachType::EpsAttach as u8, 42);
        let subscribed = build_attach_accept(&ue, &[0x01], 720, &[]).expect("build");
        let hardcoded = build_attach_accept(&ue, &[0x01], 3600, &[]).expect("build");
        assert_eq!(
            subscribed[3],
            GprsTimer::from_sec(720).encode(),
            "the accept must encode the timer it was given"
        );
        assert_ne!(
            subscribed[3], hardcoded[3],
            "720 s and 3600 s must not encode identically, or this test proves nothing"
        );
    }

    /// #46 criterion 8(d): a TAU accept with active bearers must carry a NONZERO EPS
    /// bearer context status, or the UE and the MME cannot resynchronise.
    #[test]
    fn a_tau_accept_with_active_bearers_carries_a_nonzero_bearer_status() {
        let ue = MmeUe::default();
        let status = eps_bearer_context_status([5u8, 6]);
        assert_ne!(status, 0, "two active bearers must set two bits");
        assert_eq!(status, (1 << 5) | (1 << 6));

        let msg = build_tau_accept(&ue, 600, &[], status);
        let iei = msg
            .windows(2)
            .position(|w| w[0] == 0x57)
            .expect("the EPS bearer context status IE must be present");
        assert_eq!(msg[iei + 1], 2, "the IE is two octets long");
        assert_eq!(u16::from_be_bytes([msg[iei + 2], msg[iei + 3]]), status);
    }

    /// EBIs 0-4 are reserved (TS 24.007 §11.2.3.1.5), so they can never appear in the
    /// bitmap — a bearer claiming one is a bug worth surfacing, not a bit to set.
    #[test]
    fn reserved_ebis_are_excluded_from_the_bearer_status() {
        assert_eq!(eps_bearer_context_status([0u8, 4, 16, 255]), 0);
        assert_eq!(eps_bearer_context_status([5u8]), 1 << 5);
        assert_eq!(eps_bearer_context_status(std::iter::empty()), 0);
    }

    /// #46 criterion 7: the EPS update result must follow the TAU type and the SGs
    /// outcome, not be a hardcoded "TA updated".
    #[test]
    fn the_eps_update_result_follows_the_tau_type_and_the_sgs_association() {
        // Plain TA updating, and periodic updating: TA updated.
        for update_type in [0u8, 3] {
            let mut ue = MmeUe {
                csmap_id: 42,
                ..Default::default()
            };
            ue.nas_eps.update_type = update_type;
            assert_eq!(build_tau_accept(&ue, 600, &[], 0)[2] & 0x07, 0);
        }
        // Combined, with a VLR: combined TA/LA updated.
        for update_type in [1u8, 2] {
            let mut ue = MmeUe {
                csmap_id: 42,
                ..Default::default()
            };
            ue.nas_eps.update_type = update_type;
            assert_eq!(
                build_tau_accept(&ue, 600, &[], 0)[2] & 0x07,
                1,
                "a combined update with a VLR must be reported as combined"
            );
        }
        // Combined, with no VLR: TA updated, because claiming the LA was updated
        // would tell the UE it is reachable for CS services it cannot receive.
        let mut ue = MmeUe {
            csmap_id: crate::context::NEXTGCORE_INVALID_POOL_ID,
            ..Default::default()
        };
        ue.nas_eps.update_type = 1;
        assert_eq!(build_tau_accept(&ue, 600, &[], 0)[2] & 0x07, 0);
    }

    /// #46 criterion 5: the GUTI Reallocation Command exists and carries the staged
    /// GUTI. `GutiReallocationCommand = 0x50` was an enum value with no builder, so a
    /// GUTI could never be refreshed outside an attach or a TAU.
    #[test]
    fn the_guti_reallocation_command_carries_the_staged_guti() {
        let mut ue = MmeUe::default();
        ue.next.m_tmsi = Some(0x0102_0304);
        ue.next.guti = crate::context::EpsGuti {
            plmn_id: PlmnId::new("999", "70"),
            mme_gid: 2,
            mme_code: 1,
            m_tmsi: 0x0102_0304,
        };

        let msg = build_guti_reallocation_command(&ue, &[]);
        assert_eq!(msg[0], NAS_PROTOCOL_DISCRIMINATOR_EMM);
        assert_eq!(msg[1], NasEpsMessageType::GutiReallocationCommand as u8);
        assert_eq!(msg[2], 11, "the GUTI IE is 11 octets of content");
        assert_eq!(msg[3], 0xf6, "odd/even indicator plus type = GUTI");
        // Content layout (TS 24.301 §9.9.3.12): 0xf6, PLMN (3), MME group id (2),
        // MME code (1), M-TMSI (4) — so the M-TMSI is the LAST four of the eleven.
        assert_eq!(
            u32::from_be_bytes([msg[10], msg[11], msg[12], msg[13]]),
            0x0102_0304,
            "the command must carry the GUTI that was staged"
        );
        assert_eq!(
            msg.len(),
            2 + 1 + 11,
            "header, length octet, and 11 of content"
        );
    }

    #[test]
    fn test_encode_tai_list_type0_single_plmn() {
        // TS 24.301 §9.9.3.33 type "00": one PLMN + list of TACs
        let plmn = PlmnId::new("310", "410");
        let tai_list = vec![
            EpsTai {
                plmn_id: plmn.clone(),
                tac: 0x0001,
            },
            EpsTai {
                plmn_id: plmn.clone(),
                tac: 0x1234,
            },
        ];
        let encoded = encode_tai_list(&tai_list);
        let plmn_bytes = encode_plmn_id(&plmn);
        // Octet 1: spare=0, type=00, number of elements = 2-1 = 1
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..4], &plmn_bytes);
        assert_eq!(&encoded[4..6], &[0x00, 0x01]);
        assert_eq!(&encoded[6..8], &[0x12, 0x34]);
        assert_eq!(encoded.len(), 8);
    }

    #[test]
    fn test_encode_tai_list_type2_mixed_plmn() {
        // TS 24.301 §9.9.3.33 type "10": explicit list of TAIs
        let plmn_a = PlmnId::new("310", "410");
        let plmn_b = PlmnId::new("001", "01");
        let tai_list = vec![
            EpsTai {
                plmn_id: plmn_a.clone(),
                tac: 0x0001,
            },
            EpsTai {
                plmn_id: plmn_b.clone(),
                tac: 0x0002,
            },
        ];
        let encoded = encode_tai_list(&tai_list);
        // Octet 1: spare=0, type=10, number of elements = 2-1 = 1
        assert_eq!(encoded[0], 0x41);
        assert_eq!(&encoded[1..4], &encode_plmn_id(&plmn_a));
        assert_eq!(&encoded[4..6], &[0x00, 0x01]);
        assert_eq!(&encoded[6..9], &encode_plmn_id(&plmn_b));
        assert_eq!(&encoded[9..11], &[0x00, 0x02]);
        assert_eq!(encoded.len(), 11);
    }

    #[test]
    fn test_encode_tai_list_empty_and_single() {
        assert!(encode_tai_list(&[]).is_empty());

        let tai_list = vec![EpsTai {
            plmn_id: PlmnId::new("310", "410"),
            tac: 0x0007,
        }];
        let encoded = encode_tai_list(&tai_list);
        // Single element type 0: header 0x00, PLMN, one TAC
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded.len(), 6);
        assert_eq!(&encoded[4..6], &[0x00, 0x07]);
    }

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
        assert_eq!(
            data,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
        );
    }
}
