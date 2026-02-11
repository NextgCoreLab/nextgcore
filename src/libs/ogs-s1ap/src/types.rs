//! S1AP Message Types
//!
//! Strongly-typed representations of S1AP procedure messages per 3GPP TS 36.413.

use ogs_asn1c::ngap::cause::Cause;

/// S1 Setup Request - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct S1SetupRequest {
    /// Global eNB ID
    pub global_enb_id: GlobalEnbId,
    /// eNB Name (optional)
    pub enb_name: Option<String>,
    /// Supported TAs List
    pub supported_tas: Vec<SupportedTaItem>,
    /// Default Paging DRX
    pub default_paging_drx: PagingDrx,
}

/// S1 Setup Response - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct S1SetupResponse {
    /// MME Name
    pub mme_name: String,
    /// Served GUMMEIs
    pub served_gummeis: Vec<ServedGummeiItem>,
    /// Relative MME Capacity (0..255)
    pub relative_mme_capacity: u8,
}

/// S1 Setup Failure - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct S1SetupFailure {
    /// Cause
    pub cause: Cause,
    /// Time to wait (optional)
    pub time_to_wait: Option<TimeToWait>,
}

/// Initial UE Message - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct InitialUeMessage {
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
    /// TAI
    pub tai: Tai,
    /// EUTRAN-CGI
    pub eutran_cgi: EutranCgi,
    /// RRC Establishment Cause
    pub rrc_establishment_cause: RrcEstablishmentCause,
}

/// Downlink NAS Transport - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct DlNasTransport {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
}

/// Uplink NAS Transport - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct UlNasTransport {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
    /// EUTRAN-CGI
    pub eutran_cgi: EutranCgi,
    /// TAI
    pub tai: Tai,
}

/// Initial Context Setup Request - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct InitialContextSetupRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// UE Aggregate Maximum Bit Rate
    pub ue_ambr: UeAmbr,
    /// E-RAB to be Setup List
    pub erab_list: Vec<ErabToBeSetupItem>,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
    /// Security Key (256 bits)
    pub security_key: [u8; 32],
}

/// Initial Context Setup Response - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct InitialContextSetupResponse {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RAB Setup List
    pub erab_setup_list: Vec<ErabSetupItem>,
}

/// UE Context Release Command - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct UeContextReleaseCommand {
    /// UE S1AP IDs
    pub ue_s1ap_ids: UeS1apIds,
    /// Cause
    pub cause: Cause,
}

/// UE Context Release Complete - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct UeContextReleaseComplete {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
}

/// E-RAB Setup Request - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct ErabSetupRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RAB to be Setup List
    pub erab_list: Vec<ErabToBeSetupItem>,
}

/// E-RAB Setup Response - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct ErabSetupResponse {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RAB Setup List
    pub erab_setup_list: Vec<ErabSetupItem>,
    /// E-RAB Failed to Setup List (optional)
    pub erab_failed_list: Vec<ErabFailedItem>,
}

// ============================================================================
// Common Types
// ============================================================================

/// Global eNB ID
#[derive(Debug, Clone)]
pub struct GlobalEnbId {
    /// PLMN Identity (3 bytes)
    pub plmn_identity: [u8; 3],
    /// eNB ID (20 or 28 bits)
    pub enb_id: u32,
}

/// Supported TA Item
#[derive(Debug, Clone)]
pub struct SupportedTaItem {
    /// TAC (2 bytes)
    pub tac: u16,
    /// Broadcast PLMNs
    pub broadcast_plmns: Vec<[u8; 3]>,
}

/// Served GUMMEI Item
#[derive(Debug, Clone)]
pub struct ServedGummeiItem {
    /// Served PLMNs
    pub served_plmns: Vec<[u8; 3]>,
    /// Served Group IDs
    pub served_group_ids: Vec<u16>,
    /// Served MME Codes
    pub served_mmec_codes: Vec<u8>,
}

/// TAI (Tracking Area Identity)
#[derive(Debug, Clone)]
pub struct Tai {
    /// PLMN Identity
    pub plmn_identity: [u8; 3],
    /// TAC
    pub tac: u16,
}

/// EUTRAN-CGI (E-UTRAN Cell Global Identifier)
#[derive(Debug, Clone)]
pub struct EutranCgi {
    /// PLMN Identity
    pub plmn_identity: [u8; 3],
    /// Cell Identity (28 bits)
    pub cell_identity: u32,
}

/// UE S1AP IDs
#[derive(Debug, Clone)]
pub enum UeS1apIds {
    /// MME and eNB UE S1AP IDs
    Pair { mme_ue_s1ap_id: u32, enb_ue_s1ap_id: u32 },
    /// MME UE S1AP ID only
    MmeOnly { mme_ue_s1ap_id: u32 },
}

/// UE Aggregate Maximum Bit Rate
#[derive(Debug, Clone)]
pub struct UeAmbr {
    /// Downlink (bits/s)
    pub dl: u64,
    /// Uplink (bits/s)
    pub ul: u64,
}

/// UE Security Capabilities
#[derive(Debug, Clone)]
pub struct UeSecurityCapabilities {
    /// Encryption algorithms (16 bits)
    pub encryption_algorithms: u16,
    /// Integrity algorithms (16 bits)
    pub integrity_algorithms: u16,
}

/// E-RAB To Be Setup Item
#[derive(Debug, Clone)]
pub struct ErabToBeSetupItem {
    /// E-RAB ID (0..15)
    pub erab_id: u8,
    /// E-RAB Level QoS Parameters
    pub erab_qos: ErabLevelQosParameters,
    /// Transport Layer Address (IPv4 or IPv6)
    pub transport_layer_address: Vec<u8>,
    /// GTP-TEID
    pub gtp_teid: u32,
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
}

/// E-RAB Setup Item
#[derive(Debug, Clone)]
pub struct ErabSetupItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// Transport Layer Address
    pub transport_layer_address: Vec<u8>,
    /// GTP-TEID
    pub gtp_teid: u32,
}

/// E-RAB Failed Item
#[derive(Debug, Clone)]
pub struct ErabFailedItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// Cause
    pub cause: Cause,
}

/// E-RAB Level QoS Parameters
#[derive(Debug, Clone)]
pub struct ErabLevelQosParameters {
    /// QCI (QoS Class Identifier) 1..9
    pub qci: u8,
    /// Allocation and Retention Priority
    pub arp: AllocationRetentionPriority,
    /// GBR QoS Information (optional, for GBR bearers)
    pub gbr_qos_info: Option<GbrQosInformation>,
}

/// Allocation and Retention Priority
#[derive(Debug, Clone)]
pub struct AllocationRetentionPriority {
    /// Priority Level (1..15)
    pub priority_level: u8,
    /// Pre-emption Capability
    pub pre_emption_capability: bool,
    /// Pre-emption Vulnerability
    pub pre_emption_vulnerability: bool,
}

/// GBR QoS Information
#[derive(Debug, Clone)]
pub struct GbrQosInformation {
    /// E-RAB Maximum Bitrate DL
    pub erab_max_bitrate_dl: u64,
    /// E-RAB Maximum Bitrate UL
    pub erab_max_bitrate_ul: u64,
    /// E-RAB Guaranteed Bitrate DL
    pub erab_guaranteed_bitrate_dl: u64,
    /// E-RAB Guaranteed Bitrate UL
    pub erab_guaranteed_bitrate_ul: u64,
}

/// Paging DRX
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingDrx {
    V32 = 0,
    V64 = 1,
    V128 = 2,
    V256 = 3,
}

/// Time to Wait
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

/// RRC Establishment Cause
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RrcEstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
}
