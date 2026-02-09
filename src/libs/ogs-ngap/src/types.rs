//! NGAP Higher-Level Message Types
//!
//! Strongly-typed representations of NGAP procedure messages per 3GPP TS 38.413.
//! These types abstract over the raw ProtocolIeContainer and provide a convenient API.

use ogs_asn1c::ngap::cause::Cause;

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
    Pair { amf_ue_ngap_id: u64, ran_ue_ngap_id: u32 },
    /// AMF UE NGAP ID only
    AmfOnly { amf_ue_ngap_id: u64 },
}

/// Global RAN Node ID
#[derive(Debug, Clone)]
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
pub enum PagingDrx {
    V32 = 0,
    V64 = 1,
    V128 = 2,
    V256 = 3,
}

impl Default for PagingDrx {
    fn default() -> Self {
        PagingDrx::V128
    }
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
pub enum RrcEstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    MoVideoCall = 6,
    MoSms = 7,
    MpsPriorityAccess = 8,
    McsPriorityAccess = 9,
    NotAvailable = 10,
}

impl Default for RrcEstablishmentCause {
    fn default() -> Self {
        RrcEstablishmentCause::MoSignalling
    }
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

/// Criticality Diagnostics
#[derive(Debug, Clone)]
pub struct CriticalityDiagnostics {
    /// Procedure Code (optional)
    pub procedure_code: Option<u8>,
    /// Triggering Message (optional)
    pub triggering_message: Option<u8>,
    /// Procedure Criticality (optional)
    pub procedure_criticality: Option<u8>,
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
    /// PDU Session Resource List (optional)
    pub pdu_session_list: Option<Vec<PduSessionResourceSetupItem>>,
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
    /// Allowed NSSAI (optional)
    pub allowed_nssai: Option<Vec<SNssai>>,
}

/// Path Switch Request Failure - sent by AMF to target gNB (TS 38.413 Section 9.2.3.12)
#[derive(Debug, Clone)]
pub struct PathSwitchRequestFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// PDU Session Resource Released List (optional)
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
#[derive(Debug, Clone)]
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
