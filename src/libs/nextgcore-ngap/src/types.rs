//! NGAP Higher-Level Message Types
//!
//! Strongly-typed representations of NGAP procedure messages per 3GPP TS 38.413.
//! These types abstract over the raw ProtocolIeContainer and provide a convenient API.

pub use nextgcore_asn1c::ngap::cause::Cause;
use nextgcore_asn1c::ngap::types::Criticality;

// ============================================================================
// NG Setup (Section 9.2.6)
// ============================================================================

/// NG Setup Request - sent by gNB to AMF (TS 38.413 Section 9.2.6.1)
#[derive(Debug, Clone)]
pub struct NgSetupRequest {
    /// Global RAN Node ID - identifies the gNB
    pub global_ran_node_id: GlobalRanNodeId,
    /// RAN Node Name (optional)
    pub ran_node_name: Option<String>,
    /// Supported TA List - TAIs supported by the gNB
    pub supported_ta_list: Vec<SupportedTaItem>,
    /// Default Paging DRX
    pub default_paging_drx: PagingDrx,
}

/// NG Setup Response - sent by AMF to gNB (TS 38.413 Section 9.2.6.2)
#[derive(Debug, Clone)]
pub struct NgSetupResponse {
    /// AMF Name
    pub amf_name: String,
    /// Served GUAMI List
    pub served_guami_list: Vec<ServedGuamiItem>,
    /// Relative AMF Capacity (0..255)
    pub relative_amf_capacity: u8,
    /// PLMN Support List
    pub plmn_support_list: Vec<PlmnSupportItem>,
}

/// NG Setup Failure - sent by AMF to gNB (TS 38.413 Section 9.2.6.3)
#[derive(Debug, Clone)]
pub struct NgSetupFailure {
    /// Cause of the failure
    pub cause: Cause,
    /// Time to wait before retrying (optional)
    pub time_to_wait: Option<TimeToWait>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

// ============================================================================
// NAS Transport (Section 8.6)
// ============================================================================

/// Initial UE Message - sent by gNB to AMF (TS 38.413 Section 9.2.5.1)
#[derive(Debug, Clone)]
pub struct InitialUeMessage {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
    /// User Location Information
    pub user_location_info: UserLocationInformation,
    /// RRC Establishment Cause
    pub rrc_establishment_cause: RrcEstablishmentCause,
    /// UE Context Request (optional)
    pub ue_context_request: Option<bool>,
    /// Allowed NSSAI (optional, IE id 0). Permitted in InitialUEMessage by the
    /// TS 38.413 ASN.1 (`InitialUEMessage-IEs` includes `id-AllowedNSSAI`), and
    /// sent by a gNB that wants the AMF to see the slice context it used for
    /// selection. Empty when the peer omits the IE.
    pub allowed_nssai: Vec<SNssai>,
}

/// Downlink NAS Transport - sent by AMF to gNB (TS 38.413 Section 9.2.5.2)
#[derive(Debug, Clone)]
pub struct DownlinkNasTransport {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
}

/// Uplink NAS Transport - sent by gNB to AMF (TS 38.413 Section 9.2.5.3)
#[derive(Debug, Clone)]
pub struct UplinkNasTransport {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
    /// User Location Information
    pub user_location_info: UserLocationInformation,
}

// ============================================================================
// Initial Context Setup (Section 9.2.2)
// ============================================================================

/// Initial Context Setup Request - sent by AMF to gNB (TS 38.413 Section 9.2.2.1)
#[derive(Debug, Clone)]
pub struct InitialContextSetupRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// GUAMI
    pub guami: Guami,
    /// Allowed NSSAI
    pub allowed_nssai: Vec<SNssai>,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
    /// Security Key (256 bits)
    pub security_key: [u8; 32],
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
    /// UE Aggregate Maximum Bit Rate (optional)
    pub ue_ambr: Option<UeAmbrInfo>,
}

/// Initial Context Setup Response - sent by gNB to AMF (TS 38.413 Section 9.2.2.2)
#[derive(Debug, Clone)]
pub struct InitialContextSetupResponse {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
}

/// Initial Context Setup Failure - sent by gNB to AMF (TS 38.413 Section 9.2.2.3)
#[derive(Debug, Clone)]
pub struct InitialContextSetupFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Cause
    pub cause: Cause,
}

// ============================================================================
// PDU Session Resource procedures (Section 9.2.1)
// ============================================================================

/// PDU Session Resource Setup Request - sent by AMF to gNB (TS 38.413 Section 9.2.1.1)
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetupRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Setup List
    pub pdu_session_list: Vec<PduSessionResourceSetupItem>,
    /// NAS-PDU (optional, for piggybacking)
    pub nas_pdu: Option<Vec<u8>>,
}

/// Single PDU Session Resource to set up
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetupItem {
    /// PDU Session ID (0..255)
    pub pdu_session_id: u8,
    /// NAS-PDU for this session (optional)
    pub nas_pdu: Option<Vec<u8>>,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// PDU Session Resource Setup Request Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Setup Response - sent by gNB to AMF (TS 38.413 Section 9.2.1.2)
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetupResponse {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Successfully setup sessions
    pub setup_list: Vec<PduSessionResourceSetupResponseItem>,
    /// Failed to setup sessions
    pub failed_list: Vec<PduSessionResourceFailedItem>,
}

/// Single successfully setup PDU session in response
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetupResponseItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Setup Response Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// Single failed PDU session
#[derive(Debug, Clone)]
pub struct PduSessionResourceFailedItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Setup Unsuccessful Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Modify Request - sent by AMF to gNB (TS 38.413 Section 9.2.1.3)
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Modify List
    pub pdu_session_list: Vec<PduSessionResourceModifyItem>,
}

/// Single PDU Session Resource to modify
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
    /// Modify Request Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Modify Response - sent by gNB to AMF
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyResponse {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Modified sessions
    pub modify_list: Vec<PduSessionResourceModifyResponseItem>,
    /// Failed sessions
    pub failed_list: Vec<PduSessionResourceFailedItem>,
}

/// Single modified PDU session in response
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyResponseItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Modify Response Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Release Command - sent by AMF to gNB (TS 38.413 Section 9.2.1.5)
#[derive(Debug, Clone)]
pub struct PduSessionResourceReleaseCommand {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
    /// PDU Session Resource to Release List
    pub pdu_session_list: Vec<PduSessionResourceReleaseItem>,
}

/// Single PDU Session Resource to release
#[derive(Debug, Clone)]
pub struct PduSessionResourceReleaseItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Release Command Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Release Response - sent by gNB to AMF
#[derive(Debug, Clone)]
pub struct PduSessionResourceReleaseResponse {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Released sessions
    pub released_list: Vec<PduSessionResourceReleasedItem>,
}

/// Single released PDU session in response
#[derive(Debug, Clone)]
pub struct PduSessionResourceReleasedItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Release Response Transfer (opaque)
    pub transfer: Vec<u8>,
}

// ============================================================================
// UE Context Release (Section 9.2.5)
// ============================================================================

/// UE Context Release Command - sent by AMF to gNB (TS 38.413 Section 9.2.5.4)
#[derive(Debug, Clone)]
pub struct UeContextReleaseCommand {
    /// UE NGAP IDs - can be AMF+RAN pair or AMF only
    pub ue_ngap_ids: UeNgapIds,
    /// Cause
    pub cause: Cause,
}

/// UE Context Release Complete - sent by gNB to AMF (TS 38.413 Section 9.2.5.5)
#[derive(Debug, Clone)]
pub struct UeContextReleaseComplete {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
}

/// UE Context Release Request - sent by gNB to AMF (TS 38.413 Section 9.2.5.3)
#[derive(Debug, Clone)]
pub struct UeContextReleaseRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Cause
    pub cause: Cause,
}

// ============================================================================
// Common Types
// ============================================================================

/// UE NGAP ID pair or AMF-only
#[derive(Debug, Clone)]
pub enum UeNgapIds {
    /// Both AMF and RAN UE NGAP IDs
    Pair {
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
    },
    /// AMF UE NGAP ID only
    AmfOnly { amf_ue_ngap_id: u64 },
}

/// Global RAN Node ID
///
/// `PartialEq`/`Eq` so the PWS Restart / Failure Indication types that carry it
/// can be compared in round-trip tests (TS 38.413 Section 9.2.8.5/.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRanNodeId {
    /// Global gNB ID
    GlobalGnbId {
        /// PLMN Identity (3 bytes)
        plmn_identity: [u8; 3],
        /// gNB ID value
        gnb_id: u32,
        /// gNB ID bit length (22..32)
        gnb_id_len: u8,
    },
    /// Global ng-eNB ID
    GlobalNgEnbId {
        /// PLMN Identity (3 bytes)
        plmn_identity: [u8; 3],
        /// ng-eNB ID value
        ng_enb_id: u32,
    },
}

/// Supported TA Item
#[derive(Debug, Clone)]
pub struct SupportedTaItem {
    /// TAC (3 bytes)
    pub tac: [u8; 3],
    /// Broadcast PLMN List
    pub broadcast_plmn_list: Vec<BroadcastPlmnItem>,
}

/// Broadcast PLMN Item
#[derive(Debug, Clone)]
pub struct BroadcastPlmnItem {
    /// PLMN Identity (3 bytes)
    pub plmn_identity: [u8; 3],
    /// TAI Slice Support List
    pub tai_slice_support_list: Vec<SNssai>,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, PartialEq)]
pub struct SNssai {
    /// SST (Slice/Service Type, 1 byte)
    pub sst: u8,
    /// SD (Slice Differentiator, 3 bytes, optional)
    pub sd: Option<[u8; 3]>,
}

/// Served GUAMI Item
#[derive(Debug, Clone)]
pub struct ServedGuamiItem {
    /// GUAMI
    pub guami: Guami,
    /// Backup AMF Name (optional)
    pub backup_amf_name: Option<String>,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone)]
pub struct Guami {
    /// PLMN Identity (3 bytes)
    pub plmn_identity: [u8; 3],
    /// AMF Region ID (8 bits)
    pub amf_region_id: u8,
    /// AMF Set ID (10 bits)
    pub amf_set_id: u16,
    /// AMF Pointer (6 bits)
    pub amf_pointer: u8,
}

/// PLMN Support Item
#[derive(Debug, Clone)]
pub struct PlmnSupportItem {
    /// PLMN Identity (3 bytes)
    pub plmn_identity: [u8; 3],
    /// Slice Support List
    pub slice_support_list: Vec<SNssai>,
}

/// Paging DRX values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum PagingDrx {
    V32 = 0,
    V64 = 1,
    #[default]
    V128 = 2,
    V256 = 3,
}

/// Time to Wait values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeToWait {
    V1s = 0,
    V2s = 1,
    V5s = 2,
    V10s = 3,
    V20s = 4,
    V60s = 5,
}

impl TimeToWait {
    pub fn seconds(&self) -> u32 {
        match self {
            TimeToWait::V1s => 1,
            TimeToWait::V2s => 2,
            TimeToWait::V5s => 5,
            TimeToWait::V10s => 10,
            TimeToWait::V20s => 20,
            TimeToWait::V60s => 60,
        }
    }
}

/// User Location Information
#[derive(Debug, Clone)]
pub enum UserLocationInformation {
    /// NR (New Radio) user location
    Nr {
        /// NR-CGI: PLMN Identity
        nr_cgi_plmn: [u8; 3],
        /// NR-CGI: NR Cell Identity (36 bits)
        nr_cell_identity: u64,
        /// TAI: PLMN Identity
        tai_plmn: [u8; 3],
        /// TAI: TAC (3 bytes)
        tai_tac: [u8; 3],
    },
}

/// RRC Establishment Cause
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum RrcEstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    #[default]
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    MoVideoCall = 6,
    MoSms = 7,
    MpsPriorityAccess = 8,
    McsPriorityAccess = 9,
    NotAvailable = 10,
}

/// UE Security Capabilities
#[derive(Debug, Clone)]
pub struct UeSecurityCapabilities {
    /// NR encryption algorithms (16 bits)
    pub nr_encryption_algorithms: u16,
    /// NR integrity protection algorithms (16 bits)
    pub nr_integrity_algorithms: u16,
    /// E-UTRA encryption algorithms (16 bits)
    pub eutra_encryption_algorithms: u16,
    /// E-UTRA integrity protection algorithms (16 bits)
    pub eutra_integrity_algorithms: u16,
}

/// UE Aggregate Maximum Bit Rate
#[derive(Debug, Clone)]
pub struct UeAmbrInfo {
    /// DL UE AMBR (bits/s)
    pub dl: u64,
    /// UL UE AMBR (bits/s)
    pub ul: u64,
}

/// Type of error reported per offending IE in CriticalityDiagnostics.
///
/// ASN.1 (TS 38.413 §9.3.1.3):
/// `TypeOfError ::= ENUMERATED { not-understood, missing, ... }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeOfError {
    /// The IE was present but could not be understood
    NotUnderstood,
    /// A mandatory/conditional IE was missing
    Missing,
}

/// One entry of the CriticalityDiagnostics IE list.
///
/// ASN.1 (TS 38.413 §9.3.1.3):
/// `CriticalityDiagnostics-IE-Item ::= SEQUENCE { iECriticality Criticality,
/// iE-ID ProtocolIE-ID, typeOfError TypeOfError, iE-Extensions OPTIONAL, ... }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeCriticalityDiagnostics {
    /// Criticality assigned to the offending IE
    pub ie_criticality: Criticality,
    /// Protocol IE-ID of the offending IE
    pub ie_id: u16,
    /// Whether the IE was not-understood or missing
    pub type_of_error: TypeOfError,
}

/// Criticality Diagnostics
///
/// ASN.1 (TS 38.413 §9.3.1.3): an extensible SEQUENCE with five OPTIONAL root
/// components; `iEsCriticalityDiagnostics` is a `SEQUENCE (SIZE(1..256)) OF`
/// [`IeCriticalityDiagnostics`]. An empty [`ies`](Self::ies) means the list is
/// absent on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CriticalityDiagnostics {
    /// Procedure Code (optional)
    pub procedure_code: Option<u8>,
    /// Triggering Message (optional)
    pub triggering_message: Option<u8>,
    /// Procedure Criticality (optional)
    pub procedure_criticality: Option<u8>,
    /// IEsCriticalityDiagnostics list (absent when empty)
    pub ies: Vec<IeCriticalityDiagnostics>,
}

// ============================================================================
// Handover Procedures (Section 9.2.3)
// ============================================================================

/// Handover Required - sent by source gNB to AMF (TS 38.413 Section 9.2.3.1)
#[derive(Debug, Clone)]
pub struct HandoverRequired {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Handover Type
    pub handover_type: HandoverType,
    /// Cause
    pub cause: Cause,
    /// Target ID
    pub target_id: TargetId,
    /// PDU Session Resource List HO Rqd (mandatory)
    pub pdu_session_list: Vec<PduSessionResourceItemHoRqd>,
    /// Source to Target Transparent Container
    pub source_to_target_container: Vec<u8>,
}

/// Handover Request - sent by AMF to target gNB (TS 38.413 Section 9.2.3.2)
#[derive(Debug, Clone)]
pub struct HandoverRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// Handover Type
    pub handover_type: HandoverType,
    /// Cause
    pub cause: Cause,
    /// UE Aggregate Maximum Bit Rate
    pub ue_ambr: UeAmbrInfo,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
    /// Security Context
    pub security_context: SecurityContext,
    /// PDU Session Resource Setup List
    pub pdu_session_list: Vec<PduSessionResourceSetupItemHoReq>,
    /// Allowed NSSAI
    pub allowed_nssai: Vec<SNssai>,
    /// Source to Target Transparent Container
    pub source_to_target_container: Vec<u8>,
    /// GUAMI
    pub guami: Guami,
}

/// Handover Request Acknowledge - sent by target gNB to AMF (TS 38.413 Section 9.2.3.3)
#[derive(Debug, Clone)]
pub struct HandoverRequestAcknowledge {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Admitted List
    pub admitted_list: Vec<PduSessionResourceAdmittedItemHoAck>,
    /// PDU Session Resource Failed to Setup List (optional)
    pub failed_list: Option<Vec<PduSessionResourceFailedItem>>,
    /// Target to Source Transparent Container
    pub target_to_source_container: Vec<u8>,
}

/// Handover Failure - sent by target gNB to AMF (TS 38.413 Section 9.2.3.4)
#[derive(Debug, Clone)]
pub struct HandoverFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// Cause
    pub cause: Cause,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// Handover Command - sent by AMF to source gNB (TS 38.413 Section 9.2.3.5)
#[derive(Debug, Clone)]
pub struct HandoverCommand {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Handover Type
    pub handover_type: HandoverType,
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
    /// PDU Session Resource Handover List
    pub pdu_session_list: Vec<PduSessionResourceHandoverItem>,
    /// PDU Session Resource To Release List (optional)
    pub release_list: Option<Vec<PduSessionResourceReleaseItem>>,
    /// Target to Source Transparent Container
    pub target_to_source_container: Vec<u8>,
}

/// Handover Preparation Failure - sent by AMF to source gNB (TS 38.413 Section 9.2.3.6)
#[derive(Debug, Clone)]
pub struct HandoverPreparationFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Cause
    pub cause: Cause,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// Handover Notify - sent by target gNB to AMF (TS 38.413 Section 9.2.3.7)
#[derive(Debug, Clone)]
pub struct HandoverNotify {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// User Location Information
    pub user_location_info: UserLocationInformation,
}

/// Handover Cancel - sent by source gNB to AMF (TS 38.413 Section 9.2.3.8)
#[derive(Debug, Clone)]
pub struct HandoverCancel {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Cause
    pub cause: Cause,
}

/// Handover Cancel Acknowledge - sent by AMF to source gNB (TS 38.413 Section 9.2.3.9)
#[derive(Debug, Clone)]
pub struct HandoverCancelAcknowledge {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// Path Switch Request - sent by target gNB to AMF (TS 38.413 Section 9.2.3.10)
#[derive(Debug, Clone)]
pub struct PathSwitchRequest {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Source AMF UE NGAP ID
    pub source_amf_ue_ngap_id: u64,
    /// User Location Information
    pub user_location_info: UserLocationInformation,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
    /// PDU Session Resource To Be Switched In Downlink List
    pub pdu_session_list: Vec<PduSessionResourceSwitchItem>,
    /// PDU Session Resource Failed To Setup List PS Req (optional)
    pub failed_list: Option<Vec<PduSessionResourceFailedItem>>,
}

/// Path Switch Request Acknowledge - sent by AMF to target gNB (TS 38.413 Section 9.2.3.11)
#[derive(Debug, Clone)]
pub struct PathSwitchRequestAcknowledge {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// UE Security Capabilities (optional)
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    /// Security Context
    pub security_context: SecurityContext,
    /// PDU Session Resource Switched List
    pub switched_list: Vec<PduSessionResourceSwitchedItem>,
    /// PDU Session Resource Released List (optional)
    pub released_list: Option<Vec<PduSessionResourceReleasedItem>>,
    /// Allowed NSSAI (mandatory per TS 38.413 Section 9.2.3.22)
    pub allowed_nssai: Vec<SNssai>,
}

/// Path Switch Request Failure - sent by AMF to target gNB (TS 38.413 Section 9.2.3.12)
#[derive(Debug, Clone)]
pub struct PathSwitchRequestFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// Cause (mandatory)
    pub cause: Cause,
    /// PDU Session Resource Released List PS Fail (optional)
    pub released_list: Option<Vec<PduSessionResourceReleasedItem>>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

// ============================================================================
// Paging Procedure (Section 9.2.7)
// ============================================================================

/// Paging - sent by AMF to gNB (TS 38.413 Section 9.2.7.1)
#[derive(Debug, Clone)]
pub struct Paging {
    /// UE Paging Identity
    pub ue_paging_identity: UePagingIdentity,
    /// Paging DRX (optional)
    pub paging_drx: Option<PagingDrx>,
    /// TAI List for Paging
    pub tai_list: Vec<TaiListItem>,
    /// Paging Priority (optional)
    pub paging_priority: Option<PagingPriority>,
    /// UE Radio Capability for Paging (optional)
    pub ue_radio_capability: Option<Vec<u8>>,
    /// Paging Origin (optional)
    pub paging_origin: Option<PagingOrigin>,
    /// Assistance Data for Paging (optional)
    pub assistance_data: Option<Vec<u8>>,
}

// ============================================================================
// Handover-related Common Types
// ============================================================================

/// Handover Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandoverType {
    Intra5gs = 0,
    FivegsToEps = 1,
    EpsTo5gs = 2,
}

/// Target ID
#[derive(Debug, Clone)]
pub enum TargetId {
    /// Target RAN Node ID
    TargetRanNodeId {
        /// Global RAN Node ID
        global_ran_node_id: GlobalRanNodeId,
        /// Selected TAI
        selected_tai: TaiListItem,
    },
    /// Target Global NG-eNB ID (for handover to EPS)
    TargetGlobalNgEnbId {
        /// PLMN Identity
        plmn_identity: [u8; 3],
        /// ng-eNB ID
        ng_enb_id: u32,
        /// Selected TAI
        selected_tai: TaiListItem,
    },
}

/// Security Context
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Next Hop Chaining Count
    pub next_hop_chaining_count: u8,
    /// Next Hop NH (32 bytes)
    pub next_hop: [u8; 32],
}

/// PDU Session Resource Item for Handover Request
#[derive(Debug, Clone)]
pub struct PduSessionResourceSetupItemHoReq {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// Handover Request Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Admitted Item for Handover Acknowledge
#[derive(Debug, Clone)]
pub struct PduSessionResourceAdmittedItemHoAck {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Handover Request Acknowledge Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Handover Item
#[derive(Debug, Clone)]
pub struct PduSessionResourceHandoverItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Handover Command Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Switch Item for Path Switch Request
#[derive(Debug, Clone)]
pub struct PduSessionResourceSwitchItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Path Switch Request Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Switched Item
#[derive(Debug, Clone)]
pub struct PduSessionResourceSwitchedItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Path Switch Request Acknowledge Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// TAI List Item for Paging
///
/// Also the `TAI` of the PWS warning-area and restart lists, so it derives
/// `PartialEq`/`Eq` for round-trip comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaiListItem {
    /// TAI: PLMN Identity
    pub tai_plmn: [u8; 3],
    /// TAI: TAC (3 bytes)
    pub tai_tac: [u8; 3],
}

/// UE Paging Identity
#[derive(Debug, Clone)]
pub enum UePagingIdentity {
    /// 5G-S-TMSI
    FiveGSTmsi {
        /// AMF Set ID (10 bits)
        amf_set_id: u16,
        /// AMF Pointer (6 bits)
        amf_pointer: u8,
        /// 5G-TMSI (32 bits)
        tmsi: u32,
    },
}

/// Paging Priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingPriority {
    Priolevel1 = 1,
    Priolevel2 = 2,
    Priolevel3 = 3,
    Priolevel4 = 4,
    Priolevel5 = 5,
    Priolevel6 = 6,
    Priolevel7 = 7,
    Priolevel8 = 8,
}

/// Paging Origin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingOrigin {
    Non3gpp = 0,
}

/// PDU Session Resource Item for Handover Required (TS 38.413 Section 9.2.3.1)
#[derive(Debug, Clone)]
pub struct PduSessionResourceItemHoRqd {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Handover Required Transfer (opaque)
    pub transfer: Vec<u8>,
}

// ============================================================================
// NG Reset (Section 8.7.4 / 9.2.6.11-12)
// ============================================================================

/// Reset Type - scope of an NG Reset (TS 38.413 Section 9.3.1.95)
#[derive(Debug, Clone, PartialEq)]
pub enum ResetType {
    /// Reset the whole NG interface
    NgInterface,
    /// Reset only the listed UE-associated logical NG-connections
    PartOfNgInterface(Vec<UeAssociatedLogicalNgConnectionItem>),
}

/// UE-associated Logical NG-connection Item (TS 38.413 Section 9.3.1.96)
#[derive(Debug, Clone, PartialEq)]
pub struct UeAssociatedLogicalNgConnectionItem {
    /// AMF UE NGAP ID (optional)
    pub amf_ue_ngap_id: Option<u64>,
    /// RAN UE NGAP ID (optional)
    pub ran_ue_ngap_id: Option<u32>,
}

/// NG Reset - sent by either AMF or NG-RAN node (TS 38.413 Section 9.2.6.11)
#[derive(Debug, Clone)]
pub struct NgReset {
    /// Cause (mandatory)
    pub cause: Cause,
    /// Reset Type (mandatory)
    pub reset_type: ResetType,
}

/// NG Reset Acknowledge (TS 38.413 Section 9.2.6.12)
#[derive(Debug, Clone)]
pub struct NgResetAcknowledge {
    /// UE-associated Logical NG-connection List (optional)
    pub connections: Option<Vec<UeAssociatedLogicalNgConnectionItem>>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

// ============================================================================
// Error Indication (Section 8.7.5 / 9.2.6.13)
// ============================================================================

/// Error Indication - sent by either peer (TS 38.413 Section 9.2.6.13)
#[derive(Debug, Clone)]
pub struct ErrorIndication {
    /// AMF UE NGAP ID (optional)
    pub amf_ue_ngap_id: Option<u64>,
    /// RAN UE NGAP ID (optional)
    pub ran_ue_ngap_id: Option<u32>,
    /// Cause (optional)
    pub cause: Option<Cause>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// Overload Start - sent by AMF to gNB (TS 38.413 Section 9.2.6.10).
///
/// All IEs are optional; the common deployment carries only a percentage
/// traffic reduction request via TrafficLoadReductionIndication (1..99).
#[derive(Debug, Clone, Default)]
pub struct OverloadStart {
    /// Traffic Load Reduction Indication (percentage 1..99, optional)
    pub traffic_load_reduction: Option<u8>,
}

/// Overload Stop - sent by AMF to gNB (TS 38.413 Section 9.2.6.11).
/// Carries only an optional OverloadStartNSSAIList, omitted here.
#[derive(Debug, Clone, Default)]
pub struct OverloadStop {}

// ============================================================================
// RAN Configuration Update (Section 8.7.2 / 9.2.6.7-9)
// ============================================================================

/// RAN Configuration Update - sent by gNB to AMF (TS 38.413 Section 9.2.6.7)
#[derive(Debug, Clone)]
pub struct RanConfigurationUpdate {
    /// RAN Node Name (optional)
    pub ran_node_name: Option<String>,
    /// Supported TA List (optional)
    pub supported_ta_list: Option<Vec<SupportedTaItem>>,
    /// Default Paging DRX (optional)
    pub default_paging_drx: Option<PagingDrx>,
    /// Global RAN Node ID (optional)
    pub global_ran_node_id: Option<GlobalRanNodeId>,
}

/// RAN Configuration Update Acknowledge (TS 38.413 Section 9.2.6.8)
#[derive(Debug, Clone)]
pub struct RanConfigurationUpdateAcknowledge {
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// RAN Configuration Update Failure (TS 38.413 Section 9.2.6.9)
#[derive(Debug, Clone)]
pub struct RanConfigurationUpdateFailure {
    /// Cause (mandatory)
    pub cause: Cause,
    /// Time to Wait (optional)
    pub time_to_wait: Option<TimeToWait>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

// ============================================================================
// AMF Configuration Update (Section 8.7.3 / 9.2.6.4-6)
// ============================================================================

/// AMF Configuration Update - sent by AMF to gNB (TS 38.413 Section 9.2.6.4)
///
/// TNL association add/remove/update lists are deliberately deferred (all
/// IEs of this message are optional per the spec table).
#[derive(Debug, Clone)]
pub struct AmfConfigurationUpdate {
    /// AMF Name (optional)
    pub amf_name: Option<String>,
    /// Served GUAMI List (optional)
    pub served_guami_list: Option<Vec<ServedGuamiItem>>,
    /// Relative AMF Capacity (optional)
    pub relative_amf_capacity: Option<u8>,
    /// PLMN Support List (optional)
    pub plmn_support_list: Option<Vec<PlmnSupportItem>>,
}

/// AMF Configuration Update Acknowledge (TS 38.413 Section 9.2.6.5)
#[derive(Debug, Clone)]
pub struct AmfConfigurationUpdateAcknowledge {
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// AMF Configuration Update Failure (TS 38.413 Section 9.2.6.6)
#[derive(Debug, Clone)]
pub struct AmfConfigurationUpdateFailure {
    /// Cause (mandatory)
    pub cause: Cause,
    /// Time to Wait (optional)
    pub time_to_wait: Option<TimeToWait>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

// ============================================================================
// AMF Status Indication (Section 8.7.6 / 9.2.6.10)
// ============================================================================

/// AMF Status Indication - sent by AMF to gNB (TS 38.413 Section 9.2.6.10)
#[derive(Debug, Clone)]
pub struct AmfStatusIndication {
    /// Unavailable GUAMI List (mandatory)
    pub unavailable_guami_list: Vec<UnavailableGuamiItem>,
}

/// Unavailable GUAMI Item (TS 38.413 Section 9.3.3.18)
#[derive(Debug, Clone)]
pub struct UnavailableGuamiItem {
    /// GUAMI
    pub guami: Guami,
    /// Timer Approach for GUAMI Removal (optional, ENUMERATED apply-timer)
    pub timer_approach_for_guami_removal: bool,
    /// Backup AMF Name (optional)
    pub backup_amf_name: Option<String>,
}

// ============================================================================
// PDU Session Resource Notify / Modify Indication (Sections 8.2.5 / 8.2.4)
// ============================================================================

/// PDU Session Resource Notify - sent by gNB to AMF (TS 38.413 Section 8.2.5)
///
/// At least one of `notify_list` / `released_list` shall be present.
#[derive(Debug, Clone)]
pub struct PduSessionResourceNotify {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Notify List (optional)
    pub notify_list: Vec<PduSessionResourceNotifyItem>,
    /// PDU Session Resource Released List Not (optional)
    pub released_list: Vec<PduSessionResourceReleasedItem>,
}

/// Single notified PDU session (TS 38.413 Section 9.2.1.16)
#[derive(Debug, Clone)]
pub struct PduSessionResourceNotifyItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// PDU Session Resource Notify Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// RAN Status Transfer, both directions (TS 38.413 Sections 8.4.7 / 8.4.8).
///
/// `UplinkRANStatusTransferIEs` and `DownlinkRANStatusTransferIEs` are the
/// **same three mandatory IEs** — AMF-UE-NGAP-ID, RAN-UE-NGAP-ID and the
/// RANStatusTransfer-TransparentContainer — so one type serves both. That is not
/// a shortcut: the AMF's whole job in this procedure is to hand the source gNB's
/// container to the target unchanged, and a single type makes the relay
/// impossible to get wrong by re-encoding.
#[derive(Debug, Clone)]
pub struct RanStatusTransfer {
    /// AMF UE NGAP ID (AMF-scoped, so identical on both legs)
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID — the *source* gNB's on the uplink leg, the *target* gNB's
    /// on the downlink leg
    pub ran_ue_ngap_id: u32,
    /// RANStatusTransfer-TransparentContainer as the **APER-encoded IE value
    /// bytes exactly as received**, not a decoded structure.
    ///
    /// It holds the per-DRB PDCP sequence-number and HFN status the target needs
    /// for lossless handover (TS 38.413 Section 9.3.1.31). Unlike the handover
    /// transparent containers, this one is an ASN.1 `SEQUENCE`, not an `OCTET
    /// STRING` — so it is kept as the raw IE value and re-emitted byte-for-byte
    /// rather than decoded and re-encoded. The AMF is a relay here: a
    /// decode/re-encode round trip would give it a way to corrupt state it has no
    /// stake in, and buys nothing, since the IE value encoding is identical in
    /// both directions.
    pub container: Vec<u8>,
}

/// PDU Session Resource Modify Indication - sent by gNB to AMF (TS 38.413 Section 8.2.4)
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyIndication {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Modify List Mod Ind (mandatory)
    pub modify_list: Vec<PduSessionResourceModifyIndicationItem>,
}

/// Single PDU session in Modify Indication
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyIndicationItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Modify Indication Transfer (opaque)
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Modify Confirm - sent by AMF to gNB (TS 38.413 Section 8.2.4)
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyConfirm {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Modify List Mod Cfm
    pub confirm_list: Vec<PduSessionResourceModifyConfirmItem>,
    /// PDU Session Resource Failed To Modify List Mod Cfm
    pub failed_list: Vec<PduSessionResourceFailedItem>,
}

/// Single confirmed PDU session in Modify Confirm
#[derive(Debug, Clone)]
pub struct PduSessionResourceModifyConfirmItem {
    /// PDU Session ID
    pub pdu_session_id: u8,
    /// Modify Confirm Transfer (opaque)
    pub transfer: Vec<u8>,
}

// ============================================================================
// NAS Non Delivery Indication (Section 8.6.5)
// ============================================================================

/// NAS Non Delivery Indication - sent by gNB to AMF (TS 38.413 Section 8.6.5)
#[derive(Debug, Clone)]
pub struct NasNonDeliveryIndication {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS-PDU that could not be delivered (mandatory)
    pub nas_pdu: Vec<u8>,
    /// Cause (mandatory)
    pub cause: Cause,
}

// ============================================================================
// PWS Procedures (TS 38.413 Section 8.12 / Section 9.2.8)
// ============================================================================
//
// Public Warning System: ETWS/CMAS warning broadcast. The AMF is the relay
// between a CBCF/PWS-IWF (over Namf_Communication NonUeN2MessageTransfer,
// TS 29.518 Section 5.2.2.4.1.3) and the NG-RAN.
//
// The four elementary procedures and their codes, quoted from
// 6g_docs/specs/38413-j30.txt:
//
//   id-PWSCancel             ProcedureCode ::= 32   (:59077)
//   id-PWSFailureIndication  ProcedureCode ::= 33   (:59079)
//   id-PWSRestartIndication  ProcedureCode ::= 34   (:59081)
//   id-WriteReplaceWarning   ProcedureCode ::= 51   (:59115)
//
// Note the ordering trap: in the (alphabetical) ASN.1 table Failure is 33 and
// Restart is 34, the OPPOSITE of the clause order (Restart is Section 9.2.8.5,
// Failure is Section 9.2.8.6). Reading the codes off the clause order swaps them.
//
// These types deliberately mirror TS 38.413's IE sets rather than the S1AP ones
// in `nextgcore-s1ap`, because TS 38.413 diverges in four places that matter on
// the wire: RepetitionPeriod's range, the E-UTRA/NR split in every area list,
// the NGAP-only WarningAreaCoordinates IE, and the 36-bit NR cell identity.

/// NR Cell Global Identity (TS 38.413 Section 9.3.1.7, ASN.1 at
/// `38413-j30.txt:52457`).
///
/// `NRCellIdentity` is a `BIT STRING (SIZE(36))` (`:52455`) — NOT the 28 bits of
/// E-UTRA, which is why the two CGI kinds cannot share one representation even
/// though they appear in the same CHOICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrCgi {
    /// PLMN Identity (3 octets, TS 23.003 encoding)
    pub plmn_identity: [u8; 3],
    /// NR Cell Identity, 36 significant bits (low 36 bits of this value used)
    pub nr_cell_identity: u64,
}

/// E-UTRA Cell Global Identity (TS 38.413 Section 9.3.1.9, ASN.1 at
/// `38413-j30.txt:47862`).
///
/// `EUTRACellIdentity` is a `BIT STRING (SIZE(28))` (`:47860`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EutraCgi {
    /// PLMN Identity (3 octets)
    pub plmn_identity: [u8; 3],
    /// E-UTRA Cell Identity, 28 significant bits
    pub eutra_cell_identity: u32,
}

/// Warning Area List (TS 38.413 Section 9.3.1.37), ASN.1 CHOICE at
/// `38413-j30.txt:58760`.
///
/// FOUR root alternatives plus `choice-Extensions`, where the S1AP counterpart
/// (`nextgcore_s1ap::types::WarningAreaList`) has three — the NR cell list is
/// new in NGAP. The CHOICE index order below is the ASN.1 declaration order and
/// is what goes on the wire.
///
/// Absent from a WRITE-REPLACE WARNING REQUEST means every cell the NG-RAN node
/// serves (TS 38.413 Section 8.12.1.2, `38413-j30.txt:9302`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningAreaList {
    /// `eUTRA-CGIListForWarning` (CHOICE index 0), `:47883`
    EutraCgiList(Vec<EutraCgi>),
    /// `nR-CGIListForWarning` (CHOICE index 1), `:52477`
    NrCgiList(Vec<NrCgi>),
    /// `tAIListForWarning` (CHOICE index 2), `:57154`
    TaiList(Vec<TaiListItem>),
    /// `emergencyAreaIDList` (CHOICE index 3), `:47704` — 3-octet Emergency Area IDs
    EmergencyAreaIdList(Vec<[u8; 3]>),
}

/// One TAI plus the cells within it that completed the broadcast
/// (`TAIBroadcastEUTRA-Item` / `TAIBroadcastNR-Item`, `:57027` / `:57049`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaiBroadcastItem<C> {
    /// The tracking area
    pub tai: TaiListItem,
    /// `completedCellsInTAI-*`: the cells in that TAI which broadcast
    pub completed_cells: Vec<C>,
}

/// One Emergency Area ID plus the cells within it that completed the broadcast
/// (`EmergencyAreaIDBroadcast*-Item`, `:47619` / `:47641`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyAreaBroadcastItem<C> {
    /// Emergency Area ID (3 octets, `EmergencyAreaID`, `:47614`)
    pub emergency_area_id: [u8; 3],
    /// `completedCellsInEAI-*`
    pub completed_cells: Vec<C>,
}

/// Broadcast Completed Area List (TS 38.413 Section 9.3.1.43), ASN.1 CHOICE at
/// `38413-j30.txt:45687`.
///
/// SIX root alternatives against the S1AP counterpart's three: TS 38.413 splits
/// every area kind into an E-UTRA and an NR form, because an AMF serves both
/// ng-eNBs and gNBs. CHOICE index order is the declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastCompletedAreaList {
    /// `cellIDBroadcastEUTRA` (index 0), `:46309`
    CellIdEutra(Vec<EutraCgi>),
    /// `tAIBroadcastEUTRA` (index 1), `:57024`
    TaiEutra(Vec<TaiBroadcastItem<EutraCgi>>),
    /// `emergencyAreaIDBroadcastEUTRA` (index 2), `:47616`
    EmergencyAreaEutra(Vec<EmergencyAreaBroadcastItem<EutraCgi>>),
    /// `cellIDBroadcastNR` (index 3), `:46329`
    CellIdNr(Vec<NrCgi>),
    /// `tAIBroadcastNR` (index 4), `:57046`
    TaiNr(Vec<TaiBroadcastItem<NrCgi>>),
    /// `emergencyAreaIDBroadcastNR` (index 5), `:47638`
    EmergencyAreaNr(Vec<EmergencyAreaBroadcastItem<NrCgi>>),
}

/// One cell that cancelled a broadcast, with how many times it had already
/// broadcast (`CellIDCancelled*-Item`, `:46349` / `:46371`).
///
/// The `numberOfBroadcasts` field is what distinguishes the CANCELLED area lists
/// from the COMPLETED ones: a cancel reports progress-at-cancellation, so the
/// CBC knows how much of the warning actually went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledCellItem<C> {
    /// The cell
    pub cgi: C,
    /// `NumberOfBroadcasts ::= INTEGER (0..65535)` (`:52604`)
    pub number_of_broadcasts: u16,
}

/// One TAI plus its cancelled cells (`TAICancelled*-Item`, `:57068` / `:57090`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaiCancelledItem<C> {
    /// The tracking area
    pub tai: TaiListItem,
    /// `cancelledCellsInTAI-*`
    pub cancelled_cells: Vec<CancelledCellItem<C>>,
}

/// One Emergency Area ID plus its cancelled cells
/// (`EmergencyAreaIDCancelled*-Item`, `:47663` / `:47685`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyAreaCancelledItem<C> {
    /// Emergency Area ID (3 octets)
    pub emergency_area_id: [u8; 3],
    /// `cancelledCellsInEAI-*`
    pub cancelled_cells: Vec<CancelledCellItem<C>>,
}

/// Broadcast Cancelled Area List (TS 38.413 Section 9.3.1.44), ASN.1 CHOICE at
/// `38413-j30.txt:45662`. Six root alternatives, same E-UTRA/NR split as
/// [`BroadcastCompletedAreaList`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastCancelledAreaList {
    /// `cellIDCancelledEUTRA` (index 0), `:46349`
    CellIdEutra(Vec<CancelledCellItem<EutraCgi>>),
    /// `tAICancelledEUTRA` (index 1), `:57068`
    TaiEutra(Vec<TaiCancelledItem<EutraCgi>>),
    /// `emergencyAreaIDCancelledEUTRA` (index 2), `:47660`
    EmergencyAreaEutra(Vec<EmergencyAreaCancelledItem<EutraCgi>>),
    /// `cellIDCancelledNR` (index 3), `:46371`
    CellIdNr(Vec<CancelledCellItem<NrCgi>>),
    /// `tAICancelledNR` (index 4), `:57090`
    TaiNr(Vec<TaiCancelledItem<NrCgi>>),
    /// `emergencyAreaIDCancelledNR` (index 5), `:47682`
    EmergencyAreaNr(Vec<EmergencyAreaCancelledItem<NrCgi>>),
}

/// The cells a PWS Restart Indication or PWS Failure Indication names
/// (`CHOICE Cell List for Restart`, Section 9.2.8.5, and `CHOICE PWS Failed Cell
/// List`, Section 9.2.8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PwsCellList {
    /// `>E-UTRA` (CHOICE index 0)
    Eutra(Vec<EutraCgi>),
    /// `>NR` (CHOICE index 1)
    Nr(Vec<NrCgi>),
}

/// WRITE-REPLACE WARNING REQUEST — AMF to NG-RAN node (TS 38.413
/// Section 9.2.8.1, IE table at `38413-j30.txt:15866`, ASN.1 at `:40897`).
///
/// Procedure code 51. Requests the start or overwrite of a warning broadcast.
///
/// In production this AMF does not *compose* one of these: TS 29.518
/// Section 5.2.2.4.1.3 has it FORWARD an opaque container supplied by the CBCF
/// (`29518-k00.txt:4152`, "The AMF shall forward the N2 Message Container"). The
/// builder exists so the AMF can validate and round-trip what it relays, and so
/// a test (or a simulated CBCF) can produce a conformant PDU — the same framing
/// [`crate::types::RanStatusTransfer`] uses for its uplink leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReplaceWarningRequest {
    /// Message Identifier (mandatory, `BIT STRING (SIZE(16))`, `:50676`).
    /// Identifies the warning message source and type (TS 23.041).
    pub message_identifier: u16,
    /// Serial Number (mandatory, `BIT STRING (SIZE(16))`, `:56301`)
    pub serial_number: u16,
    /// Warning Area List (optional). Absent = every cell the node serves
    /// (Section 8.12.1.2, `:9302`).
    pub warning_area_list: Option<WarningAreaList>,
    /// Repetition Period in seconds (mandatory).
    ///
    /// `RepetitionPeriod ::= INTEGER (0..131071)` (`:55881`) — NOT the S1AP
    /// `0..4095`. The range exceeds 64K, so PER uses the length-of-length form
    /// rather than two aligned octets; copying the S1AP encoder here would emit
    /// an undecodable IE.
    pub repetition_period: u32,
    /// Number of Broadcasts Requested (mandatory, `INTEGER (0..65535)`,
    /// `:52606`). 0 means broadcast until explicitly stopped.
    pub number_of_broadcasts_requested: u16,
    /// Warning Type (optional, `OCTET STRING (SIZE(2))`, `:58785`) — ETWS only
    pub warning_type: Option<[u8; 2]>,
    /// Warning Security Information (optional, `OCTET STRING (SIZE(50))`,
    /// `:58783`).
    ///
    /// Carried but never interpreted: Section 9.2.8.1's own IE table says "This
    /// IE is not used in the specification. If received, the IE is ignored."
    /// (`:15895-15899`). Encoded and decoded so a relayed container survives
    /// byte-exact.
    pub warning_security_info: Option<[u8; 50]>,
    /// Data Coding Scheme (optional, `BIT STRING (SIZE(8))`, `:47032`, TS 23.038)
    pub data_coding_scheme: Option<u8>,
    /// Warning Message Contents (optional, `OCTET STRING (SIZE(1..9600))`,
    /// `:58781`)
    pub warning_message_contents: Option<Vec<u8>>,
    /// Concurrent Warning Message Indicator (optional, `ENUMERATED { true, ... }`,
    /// `:46737`). `true` here means the IE is present.
    pub concurrent_warning_message_indicator: bool,
    /// Warning Area Coordinates (optional, `OCTET STRING (SIZE(1..1024))`,
    /// `:58758`). NGAP-only — no S1AP counterpart.
    pub warning_area_coordinates: Option<Vec<u8>>,
}

/// WRITE-REPLACE WARNING RESPONSE — NG-RAN node to AMF (TS 38.413
/// Section 9.2.8.2, IE table at `:15916`, ASN.1 at `:40954`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReplaceWarningResponse {
    /// Message Identifier (mandatory) — copied from the request
    pub message_identifier: u16,
    /// Serial Number (mandatory) — copied from the request
    pub serial_number: u16,
    /// Broadcast Completed Area List (optional): where the warning actually went
    pub broadcast_completed_area_list: Option<BroadcastCompletedAreaList>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// PWS CANCEL REQUEST — AMF to NG-RAN node (TS 38.413 Section 9.2.8.3, IE table
/// at `:15942`, ASN.1 at `:41000`). Procedure code 32.
///
/// Cancels a broadcast the NG-RAN node may still be running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwsCancelRequest {
    /// Message Identifier (mandatory)
    pub message_identifier: u16,
    /// Serial Number (mandatory)
    pub serial_number: u16,
    /// Warning Area List (optional). Absent = every cell (Section 8.12.2.2,
    /// `:9374`).
    pub warning_area_list: Option<WarningAreaList>,
    /// Cancel-All Warning Messages Indicator (optional, `ENUMERATED { true, ... }`,
    /// `:45892`). `true` here means the IE is present.
    pub cancel_all_warning_messages: bool,
}

/// PWS CANCEL RESPONSE — NG-RAN node to AMF (TS 38.413 Section 9.2.8.4, IE table
/// at `:15968`, ASN.1 at `:41036`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwsCancelResponse {
    /// Message Identifier (mandatory) — copied from the request
    pub message_identifier: u16,
    /// Serial Number (mandatory) — copied from the request
    pub serial_number: u16,
    /// Broadcast Cancelled Area List (optional): where cancellation succeeded,
    /// with each cell's broadcast count at the moment it stopped
    pub broadcast_cancelled_area_list: Option<BroadcastCancelledAreaList>,
    /// Criticality Diagnostics (optional)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// PWS RESTART INDICATION — NG-RAN node to AMF (TS 38.413 Section 9.2.8.5, IE
/// table at `:15995`, ASN.1 at `:41082`). Procedure code 34.
///
/// Tells the AMF that PWS information for some or all cells is available for
/// reloading from the CBC (Section 8.12.3, `:9430`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwsRestartIndication {
    /// CHOICE Cell List for Restart (mandatory)
    pub cell_list: PwsCellList,
    /// Global RAN Node ID (mandatory)
    pub global_ran_node_id: GlobalRanNodeId,
    /// TAI List for Restart (mandatory per the IE table's `>TAI` row;
    /// `EmergencyAreaIDListForRestart`'s range starts at 1 while this one's
    /// bound is `maxnoofTAIforRestart`)
    pub tai_list_for_restart: Vec<TaiListItem>,
    /// Emergency Area ID List for Restart (optional — the IE table gives its
    /// range as `0..maxnoofEAIforRestart`, so an empty list means absent)
    pub emergency_area_id_list_for_restart: Vec<[u8; 3]>,
}

/// PWS FAILURE INDICATION — NG-RAN node to AMF (TS 38.413 Section 9.2.8.6, IE
/// table at `:16064`, ASN.1 at `:41128`). Procedure code 33.
///
/// Tells the AMF that ongoing PWS operation has failed for one or more cells
/// (Section 8.12.4, `:9455`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwsFailureIndication {
    /// CHOICE PWS Failed Cell List (mandatory)
    pub failed_cell_list: PwsCellList,
    /// Global RAN Node ID (mandatory)
    pub global_ran_node_id: GlobalRanNodeId,
}
