//! S1AP Message Types
//!
//! Strongly-typed representations of S1AP procedure messages per 3GPP TS 36.413.

pub use nextgcore_asn1c::s1ap::cause::{
    Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport,
};

// ============================================================================
// S1 Setup (TS 36.413 §9.1.8.4-9.1.8.6)
// ============================================================================

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
    /// MME Name (optional)
    pub mme_name: Option<String>,
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

// ============================================================================
// NAS Transport (TS 36.413 §9.1.7)
// ============================================================================

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
    /// S-TMSI (optional, present for service request / paging response)
    pub s_tmsi: Option<STmsi>,
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

/// NAS Non Delivery Indication - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct NasNonDeliveryIndication {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS-PDU that could not be delivered
    pub nas_pdu: Vec<u8>,
    /// Cause
    pub cause: Cause,
}

// ============================================================================
// Initial Context Setup (TS 36.413 §9.1.4.1-9.1.4.3)
// ============================================================================

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
    /// E-RAB Failed to Setup List (optional, empty = absent)
    pub erab_failed_list: Vec<ErabFailedItem>,
}

/// Initial Context Setup Failure - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct InitialContextSetupFailure {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
}

// ============================================================================
// UE Context Release (TS 36.413 §9.1.4.5-9.1.4.7)
// ============================================================================

/// UE Context Release Request - sent by eNB to MME (eNB-initiated)
#[derive(Debug, Clone)]
pub struct UeContextReleaseRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
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

// ============================================================================
// E-RAB Management (TS 36.413 §9.1.3)
// ============================================================================

/// E-RAB Setup Request - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct ErabSetupRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// UE Aggregate Maximum Bit Rate (optional)
    pub ue_ambr: Option<UeAmbr>,
    /// E-RAB to be Setup List (NAS-PDU is mandatory per item here)
    pub erab_list: Vec<ErabToBeSetupItem>,
}

/// E-RAB Setup Response - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct ErabSetupResponse {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RAB Setup List (optional, empty = absent)
    pub erab_setup_list: Vec<ErabSetupItem>,
    /// E-RAB Failed to Setup List (optional, empty = absent)
    pub erab_failed_list: Vec<ErabFailedItem>,
}

/// E-RAB Modify Request - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct ErabModifyRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// UE Aggregate Maximum Bit Rate (optional)
    pub ue_ambr: Option<UeAmbr>,
    /// E-RAB to be Modified List
    pub erab_list: Vec<ErabToBeModifiedItem>,
}

/// E-RAB Modify Response - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct ErabModifyResponse {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Modified E-RAB IDs (optional, empty = absent)
    pub erab_modify_list: Vec<u8>,
    /// E-RAB Failed to Modify List (optional, empty = absent)
    pub erab_failed_list: Vec<ErabFailedItem>,
}

/// E-RAB Release Command - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct ErabReleaseCommand {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// UE Aggregate Maximum Bit Rate (optional)
    pub ue_ambr: Option<UeAmbr>,
    /// E-RAB to be Released List (E-RAB ID + cause per item)
    pub erab_list: Vec<ErabItem>,
    /// NAS-PDU (optional)
    pub nas_pdu: Option<Vec<u8>>,
}

/// E-RAB Release Response - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct ErabReleaseResponse {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Released E-RAB IDs (optional, empty = absent)
    pub erab_release_list: Vec<u8>,
    /// E-RAB Failed to Release List (optional, empty = absent)
    pub erab_failed_list: Vec<ErabFailedItem>,
}

// ============================================================================
// Paging (TS 36.413 §9.1.6)
// ============================================================================

/// Paging - sent by MME to eNB
#[derive(Debug, Clone)]
pub struct Paging {
    /// UE Identity Index Value (10 bits, IMSI mod 1024)
    pub ue_identity_index: u16,
    /// UE Paging Identity
    pub ue_paging_id: UePagingId,
    /// Paging DRX (optional)
    pub paging_drx: Option<PagingDrx>,
    /// CN Domain
    pub cn_domain: CnDomain,
    /// TAI List
    pub tai_list: Vec<Tai>,
}

/// UE Paging Identity
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UePagingId {
    /// S-TMSI
    STmsi(STmsi),
    /// IMSI (3..8 octets, TBCD)
    Imsi(Vec<u8>),
}

/// CN Domain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CnDomain {
    Ps = 0,
    Cs = 1,
}

// ============================================================================
// Reset (TS 36.413 §9.1.8.1-9.1.8.2)
// ============================================================================

/// Reset - sent by either node
#[derive(Debug, Clone)]
pub struct Reset {
    /// Cause
    pub cause: Cause,
    /// Reset Type
    pub reset_type: ResetType,
}

/// Reset Type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetType {
    /// Reset the whole S1 interface
    S1Interface,
    /// Reset only the listed UE-associated logical S1 connections
    PartOfS1Interface(Vec<UeAssociatedLogicalS1Connection>),
}

/// UE-associated logical S1 connection item
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UeAssociatedLogicalS1Connection {
    /// MME UE S1AP ID (optional)
    pub mme_ue_s1ap_id: Option<u32>,
    /// eNB UE S1AP ID (optional)
    pub enb_ue_s1ap_id: Option<u32>,
}

/// Reset Acknowledge - response to Reset
#[derive(Debug, Clone)]
pub struct ResetAcknowledge {
    /// UE-associated logical S1 connection list (optional, empty = absent)
    pub ue_associated_connections: Vec<UeAssociatedLogicalS1Connection>,
}

// ============================================================================
// Error Indication (TS 36.413 §9.1.8.3)
// ============================================================================

/// Error Indication - sent by either node
#[derive(Debug, Clone)]
pub struct ErrorIndication {
    /// MME UE S1AP ID (optional)
    pub mme_ue_s1ap_id: Option<u32>,
    /// eNB UE S1AP ID (optional)
    pub enb_ue_s1ap_id: Option<u32>,
    /// Cause (optional)
    pub cause: Option<Cause>,
    /// Criticality Diagnostics (optional, TS 36.413 §9.2.1.21)
    pub criticality_diagnostics: Option<CriticalityDiagnostics>,
}

/// Which part of a received IE was wrong (TS 36.413 §9.2.1.21).
///
/// ASN.1: `TypeOfError ::= ENUMERATED { not-understood, missing, ... }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeOfError {
    /// The IE was present but could not be interpreted
    NotUnderstood,
    /// A mandatory IE was absent
    Missing,
}

/// One offending IE inside [`CriticalityDiagnostics`].
///
/// ASN.1: `CriticalityDiagnostics-IE-Item ::= SEQUENCE { iECriticality,
/// iE-ID, typeOfError, iE-Extensions OPTIONAL, ... }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeCriticalityDiagnostics {
    /// Criticality the offending IE was received with
    pub ie_criticality: nextgcore_asn1c::s1ap::types::Criticality,
    /// Protocol IE id of the offending IE
    pub ie_id: u16,
    /// What was wrong with it
    pub type_of_error: TypeOfError,
}

/// Criticality Diagnostics (TS 36.413 §9.2.1.21).
///
/// Tells the peer *which* procedure and *which* IEs a protocol error was about,
/// so it can correct the message rather than only learning that something was
/// rejected. Structurally identical to the NGAP IE of the same name
/// (TS 38.413 §9.3.1.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CriticalityDiagnostics {
    /// Procedure the error was detected in
    pub procedure_code: Option<u8>,
    /// Which message of that procedure (initiating/successful/unsuccessful)
    pub triggering_message: Option<u8>,
    /// Criticality the procedure was received with
    pub procedure_criticality: Option<u8>,
    /// The offending IEs; an empty list means the field is absent on the wire
    pub ies: Vec<IeCriticalityDiagnostics>,
}

/// `TriggeringMessage ::= ENUMERATED { initiating-message, successful-outcome,
/// unsuccessful-outcome }` (TS 36.413 §9.2.1.21).
pub mod triggering_message {
    /// initiating-message(0)
    pub const INITIATING_MESSAGE: u8 = 0;
    /// successful-outcome(1)
    pub const SUCCESSFUL_OUTCOME: u8 = 1;
    /// unsuccessful-outcome(2)
    pub const UNSUCCESSFUL_OUTCOME: u8 = 2;
}

// ============================================================================
// Handover Signalling (TS 36.413 §9.1.5)
// ============================================================================

/// Handover Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandoverType {
    IntraLte = 0,
    LteToUtran = 1,
    LteToGeran = 2,
    UtranToLte = 3,
    GeranToLte = 4,
}

/// Handover Required - sent by source eNB to MME
#[derive(Debug, Clone)]
pub struct HandoverRequired {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Handover Type
    pub handover_type: HandoverType,
    /// Cause
    pub cause: Cause,
    /// Target ID
    pub target_id: TargetId,
    /// Source to Target Transparent Container
    pub source_to_target_container: Vec<u8>,
}

/// Handover Command - sent by MME to source eNB
#[derive(Debug, Clone)]
pub struct HandoverCommand {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Handover Type
    pub handover_type: HandoverType,
    /// E-RABs Subject to Data Forwarding List (optional, empty = absent)
    pub erab_subject_to_forwarding_list: Vec<ErabDataForwardingItem>,
    /// E-RABs to Release List (optional, empty = absent)
    pub erab_to_release_list: Vec<ErabItem>,
    /// Target to Source Transparent Container
    pub target_to_source_container: Vec<u8>,
}

/// Handover Preparation Failure - sent by MME to source eNB
#[derive(Debug, Clone)]
pub struct HandoverPreparationFailure {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
}

/// Handover Request - sent by MME to target eNB
#[derive(Debug, Clone)]
pub struct HandoverRequest {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// Handover Type
    pub handover_type: HandoverType,
    /// Cause
    pub cause: Cause,
    /// UE Aggregate Maximum Bit Rate
    pub ue_ambr: UeAmbr,
    /// E-RABs to be Setup List
    pub erab_list: Vec<ErabToBeSetupItemHoReq>,
    /// Source to Target Transparent Container
    pub source_to_target_container: Vec<u8>,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
    /// Security Context
    pub security_context: SecurityContext,
}

/// Handover Request Acknowledge - sent by target eNB to MME
#[derive(Debug, Clone)]
pub struct HandoverRequestAcknowledge {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RAB Admitted List
    pub erab_admitted_list: Vec<ErabAdmittedItem>,
    /// E-RAB Failed to Setup List (optional, empty = absent)
    pub erab_failed_list: Vec<ErabFailedItem>,
    /// Target to Source Transparent Container
    pub target_to_source_container: Vec<u8>,
}

/// Handover Failure - sent by target eNB to MME
#[derive(Debug, Clone)]
pub struct HandoverFailure {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
}

/// Handover Notify - sent by target eNB to MME
#[derive(Debug, Clone)]
pub struct HandoverNotify {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// EUTRAN-CGI
    pub eutran_cgi: EutranCgi,
    /// TAI
    pub tai: Tai,
}

/// Path Switch Request - sent by target eNB to MME (X2 handover)
#[derive(Debug, Clone)]
pub struct PathSwitchRequest {
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RABs to be Switched in Downlink List
    pub erab_switched_dl_list: Vec<ErabSwitchedItem>,
    /// Source MME UE S1AP ID
    pub source_mme_ue_s1ap_id: u32,
    /// EUTRAN-CGI
    pub eutran_cgi: EutranCgi,
    /// TAI
    pub tai: Tai,
    /// UE Security Capabilities
    pub ue_security_capabilities: UeSecurityCapabilities,
}

/// Path Switch Request Acknowledge - sent by MME to target eNB
#[derive(Debug, Clone)]
pub struct PathSwitchRequestAcknowledge {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// E-RABs to be Switched in Uplink List (optional, empty = absent)
    pub erab_switched_ul_list: Vec<ErabSwitchedItem>,
    /// Security Context
    pub security_context: SecurityContext,
}

/// Path Switch Request Failure - sent by MME to target eNB
#[derive(Debug, Clone)]
pub struct PathSwitchRequestFailure {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
}

/// Handover Cancel - sent by source eNB to MME
#[derive(Debug, Clone)]
pub struct HandoverCancel {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: Cause,
}

/// Handover Cancel Acknowledge - sent by MME to source eNB
#[derive(Debug, Clone)]
pub struct HandoverCancelAcknowledge {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
}

// ============================================================================
// UE Capability Info Indication (TS 36.413 §9.1.10)
// ============================================================================

/// UE Capability Info Indication - sent by eNB to MME
#[derive(Debug, Clone)]
pub struct UeCapabilityInfoIndication {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// UE Radio Capability (opaque RRC container)
    pub ue_radio_capability: Vec<u8>,
}

// ============================================================================
// Common Types
// ============================================================================

/// Global eNB ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalEnbId {
    /// PLMN Identity (3 bytes)
    pub plmn_identity: [u8; 3],
    /// eNB ID
    pub enb_id: EnbId,
}

/// eNB ID - CHOICE between macro (20 bits) and home (28 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnbId {
    /// Macro eNB ID (20 bits)
    Macro(u32),
    /// Home eNB ID (28 bits)
    Home(u32),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tai {
    /// PLMN Identity
    pub plmn_identity: [u8; 3],
    /// TAC
    pub tac: u16,
}

/// EUTRAN-CGI (E-UTRAN Cell Global Identifier)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EutranCgi {
    /// PLMN Identity
    pub plmn_identity: [u8; 3],
    /// Cell Identity (28 bits)
    pub cell_identity: u32,
}

/// S-TMSI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct STmsi {
    /// MME Code
    pub mmec: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

/// UE S1AP IDs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeS1apIds {
    /// MME and eNB UE S1AP IDs
    Pair {
        mme_ue_s1ap_id: u32,
        enb_ue_s1ap_id: u32,
    },
    /// MME UE S1AP ID only
    MmeOnly { mme_ue_s1ap_id: u32 },
}

/// UE Aggregate Maximum Bit Rate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeAmbr {
    /// Downlink (bits/s)
    pub dl: u64,
    /// Uplink (bits/s)
    pub ul: u64,
}

/// UE Security Capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeSecurityCapabilities {
    /// Encryption algorithms (16 bits)
    pub encryption_algorithms: u16,
    /// Integrity algorithms (16 bits)
    pub integrity_algorithms: u16,
}

/// Security Context (for handover)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    /// Next Hop Chaining Count (0..7)
    pub next_hop_chaining_count: u8,
    /// Next Hop parameter (NH, 256 bits)
    pub next_hop_parameter: [u8; 32],
}

/// Target ID for handover - CHOICE
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetId {
    /// Target eNB (intra-LTE handover)
    TargetEnbId {
        global_enb_id: GlobalEnbId,
        selected_tai: Tai,
    },
    /// Target RNC (LTE to UTRAN handover)
    TargetRncId {
        plmn_identity: [u8; 3],
        lac: u16,
        rac: Option<u8>,
        rnc_id: u16,
    },
    /// CGI (LTE to GERAN handover)
    Cgi {
        plmn_identity: [u8; 3],
        lac: u16,
        ci: u16,
        rac: Option<u8>,
    },
}

/// E-RAB To Be Setup Item (InitialContextSetup / E-RABSetup)
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
    /// NAS-PDU (optional in InitialContextSetup, mandatory in E-RABSetup)
    pub nas_pdu: Option<Vec<u8>>,
}

/// E-RAB To Be Setup Item for Handover Request
#[derive(Debug, Clone)]
pub struct ErabToBeSetupItemHoReq {
    /// E-RAB ID
    pub erab_id: u8,
    /// Transport Layer Address
    pub transport_layer_address: Vec<u8>,
    /// GTP-TEID
    pub gtp_teid: u32,
    /// E-RAB Level QoS Parameters
    pub erab_qos: ErabLevelQosParameters,
}

/// E-RAB To Be Modified Item
#[derive(Debug, Clone)]
pub struct ErabToBeModifiedItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// E-RAB Level QoS Parameters
    pub erab_qos: ErabLevelQosParameters,
    /// NAS-PDU
    pub nas_pdu: Vec<u8>,
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

/// E-RAB Switched Item (PathSwitchRequest DL / Acknowledge UL)
#[derive(Debug, Clone)]
pub struct ErabSwitchedItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// Transport Layer Address
    pub transport_layer_address: Vec<u8>,
    /// GTP-TEID
    pub gtp_teid: u32,
}

/// E-RAB Admitted Item (HandoverRequestAcknowledge)
#[derive(Debug, Clone)]
pub struct ErabAdmittedItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// Transport Layer Address
    pub transport_layer_address: Vec<u8>,
    /// GTP-TEID
    pub gtp_teid: u32,
    /// DL Transport Layer Address for data forwarding (optional)
    pub dl_transport_layer_address: Option<Vec<u8>>,
    /// DL GTP-TEID for data forwarding (optional)
    pub dl_gtp_teid: Option<u32>,
    /// UL Transport Layer Address for data forwarding (optional)
    pub ul_transport_layer_address: Option<Vec<u8>>,
    /// UL GTP-TEID for data forwarding (optional)
    pub ul_gtp_teid: Option<u32>,
}

/// E-RAB Data Forwarding Item (HandoverCommand)
#[derive(Debug, Clone)]
pub struct ErabDataForwardingItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// DL Transport Layer Address (optional)
    pub dl_transport_layer_address: Option<Vec<u8>>,
    /// DL GTP-TEID (optional)
    pub dl_gtp_teid: Option<u32>,
    /// UL Transport Layer Address (optional)
    pub ul_transport_layer_address: Option<Vec<u8>>,
    /// UL GTP-TEID (optional)
    pub ul_gtp_teid: Option<u32>,
}

/// E-RAB Item (generic E-RAB-List entry: ID + cause)
#[derive(Debug, Clone)]
pub struct ErabItem {
    /// E-RAB ID
    pub erab_id: u8,
    /// Cause
    pub cause: Cause,
}

/// E-RAB Failed Item (alias of ErabItem for failed lists)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationRetentionPriority {
    /// Priority Level (1..15)
    pub priority_level: u8,
    /// Pre-emption Capability
    pub pre_emption_capability: bool,
    /// Pre-emption Vulnerability
    pub pre_emption_vulnerability: bool,
}

/// GBR QoS Information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
