//! SBI Types and Constants
//!
//! This module defines the core types, enums, and constants for the SBI library,
//! matching the C implementation in lib/sbi/types.h

use serde::{Deserialize, Serialize};
use std::fmt;

/// SBI Service Types - matches ogs_sbi_service_type_e
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum SbiServiceType {
    Null = 0,
    NnrfNfm,
    NnrfDisc,
    NnrfOauth2,
    NudmSdm,
    NudmUecm,
    NudmUeau,
    NudmEe,
    NudmPp,
    NudmNiddau,
    NudmMt,
    NamfComm,
    NamfEvts,
    NamfMt,
    NamfLoc,
    NamfOam,
    NsmfPdusession,
    NsmfEventExposure,
    NsmfNidd,
    NausfAuth,
    NausfSorprotection,
    NausfUpuprotection,
    NnefPfdmanagement,
    NnefSmcontext,
    NnefEventexposure,
    NpcfAmPolicyControl,
    NpcfSmpolicycontrol,
    NpcfPolicyauthorization,
    NpcfBdtpolicycontrol,
    NpcfEventexposure,
    NpcfUePolicyControl,
    NsmsfSms,
    NnssfNsselection,
    NnssfNssaiavailability,
    NudrDr,
    NudrGroupIdMap,
    NlmfLoc,
    N5gEirEic,
    NbsfManagement,
    NchfSpendinglimitcontrol,
    NchfConvergedcharging,
    NchfOfflineonlycharging,
    NnwdafEventssubscription,
    NnwdafAnalyticsinfo,
    NgmlcLoc,
    NucmfProvisioning,
    NucmfUecapabilitymanagement,
    NhssSdm,
    NhssUecm,
    NhssUeau,
    NhssEe,
    NhssImsSdm,
    NhssImsUecm,
    NhssImsUeau,
    NseppTelescopic,
    NsorafSor,
    NspafSecuredPacket,
    NudsfDr,
    NnssaafNssaa,
}

impl SbiServiceType {
    /// Maximum number of service types
    pub const MAX_NUM: usize = 60;

    /// Convert service type to service name string
    pub fn to_name(&self) -> &'static str {
        match self {
            Self::Null => "",
            Self::NnrfNfm => "nnrf-nfm",
            Self::NnrfDisc => "nnrf-disc",
            Self::NnrfOauth2 => "nnrf-oauth2",
            Self::NudmSdm => "nudm-sdm",
            Self::NudmUecm => "nudm-uecm",
            Self::NudmUeau => "nudm-ueau",
            Self::NudmEe => "nudm-ee",
            Self::NudmPp => "nudm-pp",
            Self::NudmNiddau => "nudm-niddau",
            Self::NudmMt => "nudm-mt",
            Self::NamfComm => "namf-comm",
            Self::NamfEvts => "namf-evts",
            Self::NamfMt => "namf-mt",
            Self::NamfLoc => "namf-loc",
            Self::NamfOam => "namf-oam",
            Self::NsmfPdusession => "nsmf-pdusession",
            Self::NsmfEventExposure => "nsmf-event-exposure",
            Self::NsmfNidd => "nsmf-nidd",
            Self::NausfAuth => "nausf-auth",
            Self::NausfSorprotection => "nausf-sorprotection",
            Self::NausfUpuprotection => "nausf-upuprotection",
            Self::NnefPfdmanagement => "nnef-pfdmanagement",
            Self::NnefSmcontext => "nnef-smcontext",
            Self::NnefEventexposure => "nnef-eventexposure",
            Self::NpcfAmPolicyControl => "npcf-am-policy-control",
            Self::NpcfSmpolicycontrol => "npcf-smpolicycontrol",
            Self::NpcfPolicyauthorization => "npcf-policyauthorization",
            Self::NpcfBdtpolicycontrol => "npcf-bdtpolicycontrol",
            Self::NpcfEventexposure => "npcf-eventexposure",
            Self::NpcfUePolicyControl => "npcf-ue-policy-control",
            Self::NsmsfSms => "nsmsf-sms",
            Self::NnssfNsselection => "nnssf-nsselection",
            Self::NnssfNssaiavailability => "nnssf-nssaiavailability",
            Self::NudrDr => "nudr-dr",
            Self::NudrGroupIdMap => "nudr-group-id-map",
            Self::NlmfLoc => "nlmf-loc",
            Self::N5gEirEic => "n5g-eir-eic",
            Self::NbsfManagement => "nbsf-management",
            Self::NchfSpendinglimitcontrol => "nchf-spendinglimitcontrol",
            Self::NchfConvergedcharging => "nchf-convergedcharging",
            Self::NchfOfflineonlycharging => "nchf-offlineonlycharging",
            Self::NnwdafEventssubscription => "nnwdaf-eventssubscription",
            Self::NnwdafAnalyticsinfo => "nnwdaf-analyticsinfo",
            Self::NgmlcLoc => "ngmlc-loc",
            Self::NucmfProvisioning => "nucmf-provisioning",
            Self::NucmfUecapabilitymanagement => "nucmf-uecapabilitymanagement",
            Self::NhssSdm => "nhss-sdm",
            Self::NhssUecm => "nhss-uecm",
            Self::NhssUeau => "nhss-ueau",
            Self::NhssEe => "nhss-ee",
            Self::NhssImsSdm => "nhss-ims-sdm",
            Self::NhssImsUecm => "nhss-ims-uecm",
            Self::NhssImsUeau => "nhss-ims-ueau",
            Self::NseppTelescopic => "nsepp-telescopic",
            Self::NsorafSor => "nsoraf-sor",
            Self::NspafSecuredPacket => "nspaf-secured-packet",
            Self::NudsfDr => "nudsf-dr",
            Self::NnssaafNssaa => "nnssaaf-nssaa",
        }
    }

    /// Convert service name string to service type
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "nnrf-nfm" => Some(Self::NnrfNfm),
            "nnrf-disc" => Some(Self::NnrfDisc),
            "nnrf-oauth2" => Some(Self::NnrfOauth2),
            "nudm-sdm" => Some(Self::NudmSdm),
            "nudm-uecm" => Some(Self::NudmUecm),
            "nudm-ueau" => Some(Self::NudmUeau),
            "nudm-ee" => Some(Self::NudmEe),
            "nudm-pp" => Some(Self::NudmPp),
            "nudm-niddau" => Some(Self::NudmNiddau),
            "nudm-mt" => Some(Self::NudmMt),
            "namf-comm" => Some(Self::NamfComm),
            "namf-evts" => Some(Self::NamfEvts),
            "namf-mt" => Some(Self::NamfMt),
            "namf-loc" => Some(Self::NamfLoc),
            "namf-oam" => Some(Self::NamfOam),
            "nsmf-pdusession" => Some(Self::NsmfPdusession),
            "nsmf-event-exposure" => Some(Self::NsmfEventExposure),
            "nsmf-nidd" => Some(Self::NsmfNidd),
            "nausf-auth" => Some(Self::NausfAuth),
            "nausf-sorprotection" => Some(Self::NausfSorprotection),
            "nausf-upuprotection" => Some(Self::NausfUpuprotection),
            "nnef-pfdmanagement" => Some(Self::NnefPfdmanagement),
            "nnef-smcontext" => Some(Self::NnefSmcontext),
            "nnef-eventexposure" => Some(Self::NnefEventexposure),
            "npcf-am-policy-control" => Some(Self::NpcfAmPolicyControl),
            "npcf-smpolicycontrol" => Some(Self::NpcfSmpolicycontrol),
            "npcf-policyauthorization" => Some(Self::NpcfPolicyauthorization),
            "npcf-bdtpolicycontrol" => Some(Self::NpcfBdtpolicycontrol),
            "npcf-eventexposure" => Some(Self::NpcfEventexposure),
            "npcf-ue-policy-control" => Some(Self::NpcfUePolicyControl),
            "nsmsf-sms" => Some(Self::NsmsfSms),
            "nnssf-nsselection" => Some(Self::NnssfNsselection),
            "nnssf-nssaiavailability" => Some(Self::NnssfNssaiavailability),
            "nudr-dr" => Some(Self::NudrDr),
            "nudr-group-id-map" => Some(Self::NudrGroupIdMap),
            "nlmf-loc" => Some(Self::NlmfLoc),
            "n5g-eir-eic" => Some(Self::N5gEirEic),
            "nbsf-management" => Some(Self::NbsfManagement),
            "nchf-spendinglimitcontrol" => Some(Self::NchfSpendinglimitcontrol),
            "nchf-convergedcharging" => Some(Self::NchfConvergedcharging),
            "nchf-offlineonlycharging" => Some(Self::NchfOfflineonlycharging),
            "nnwdaf-eventssubscription" => Some(Self::NnwdafEventssubscription),
            "nnwdaf-analyticsinfo" => Some(Self::NnwdafAnalyticsinfo),
            "ngmlc-loc" => Some(Self::NgmlcLoc),
            "nucmf-provisioning" => Some(Self::NucmfProvisioning),
            "nucmf-uecapabilitymanagement" => Some(Self::NucmfUecapabilitymanagement),
            "nhss-sdm" => Some(Self::NhssSdm),
            "nhss-uecm" => Some(Self::NhssUecm),
            "nhss-ueau" => Some(Self::NhssUeau),
            "nhss-ee" => Some(Self::NhssEe),
            "nhss-ims-sdm" => Some(Self::NhssImsSdm),
            "nhss-ims-uecm" => Some(Self::NhssImsUecm),
            "nhss-ims-ueau" => Some(Self::NhssImsUeau),
            "nsepp-telescopic" => Some(Self::NseppTelescopic),
            "nsoraf-sor" => Some(Self::NsorafSor),
            "nspaf-secured-packet" => Some(Self::NspafSecuredPacket),
            "nudsf-dr" => Some(Self::NudsfDr),
            "nnssaaf-nssaa" => Some(Self::NnssaafNssaa),
            _ => None,
        }
    }
}

impl fmt::Display for SbiServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_name())
    }
}

/// NF Type enumeration - matches OpenAPI_nf_type_e
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NfType {
    Nrf,
    Udm,
    Amf,
    Smf,
    Ausf,
    Nef,
    Pcf,
    Smsf,
    Nssf,
    Udr,
    Lmf,
    Gmlc,
    FiveGEir,
    Sepp,
    Upf,
    N3iwf,
    Af,
    Udsf,
    Bsf,
    Chf,
    Nwdaf,
    Pcscf,
    Cbcf,
    Hss,
    Ucmf,
    Scp,
    Nssaaf,
    Mfaf,
    Mbsmf,
    Mbstf,
    Panf,
    Tsctsf,
    Easdf,
    Dccf,
    Nsacf,
    Pkmf,
    Mnpf,
    Smsf5G,
}

impl NfType {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Nrf => "NRF",
            Self::Udm => "UDM",
            Self::Amf => "AMF",
            Self::Smf => "SMF",
            Self::Ausf => "AUSF",
            Self::Nef => "NEF",
            Self::Pcf => "PCF",
            Self::Smsf => "SMSF",
            Self::Nssf => "NSSF",
            Self::Udr => "UDR",
            Self::Lmf => "LMF",
            Self::Gmlc => "GMLC",
            Self::FiveGEir => "5G_EIR",
            Self::Sepp => "SEPP",
            Self::Upf => "UPF",
            Self::N3iwf => "N3IWF",
            Self::Af => "AF",
            Self::Udsf => "UDSF",
            Self::Bsf => "BSF",
            Self::Chf => "CHF",
            Self::Nwdaf => "NWDAF",
            Self::Pcscf => "PCSCF",
            Self::Cbcf => "CBCF",
            Self::Hss => "HSS",
            Self::Ucmf => "UCMF",
            Self::Scp => "SCP",
            Self::Nssaaf => "NSSAAF",
            Self::Mfaf => "MFAF",
            Self::Mbsmf => "MBSMF",
            Self::Mbstf => "MBSTF",
            Self::Panf => "PANF",
            Self::Tsctsf => "TSCTSF",
            Self::Easdf => "EASDF",
            Self::Dccf => "DCCF",
            Self::Nsacf => "NSACF",
            Self::Pkmf => "PKMF",
            Self::Mnpf => "MNPF",
            Self::Smsf5G => "SMSF_5G",
        }
    }
}

/// URI Scheme - matches OpenAPI_uri_scheme_e
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum UriScheme {
    #[default]
    Http,
    Https,
}

impl UriScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl fmt::Display for UriScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// SBI Application Error Numbers - matches ogs_sbi_app_errno_e
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SbiAppError {
    N1SmError,
    N2SmError,
    SnssaiDenied,
    DnnDenied,
    PdutypeDenied,
    SscDenied,
    SubscriptionDenied,
    DnnNotSupported,
    PdutypeNotSupported,
    SscNotSupported,
    HomeRoutedRoamingRequired,
    OutOfLadnServiceArea,
    PrioritizedServicesOnly,
    PduSessionAnchorChange,
    TargetMmeCapability,
    NoEps5gsContinuity,
    UnableToPageUe,
    UeNotResponding,
    RejectedByUe,
    RejectedDueVplmnPolicy,
    HoTauInProgress,
    IntegrityProtectedMdrNotAcceptable,
    EbiExhausted,
    EbiRejectedLocalPolicy,
    EbiRejectedNoN26,
    DefaultEpsBearerInactive,
    HandoverResourceAllocationFailure,
    LateOverlappingRequest,
    DefaultEbiNotTransferred,
    NotSupportedWithIsmf,
    ServiceNotAuthorizedByNextHop,
    NoDataForwarding,
    SNssaiUnavailableDueToNsac,
    ExceededUeSliceDataRate,
    ExceededSliceDataRate,
    ContextNotFound,
    HigherPriorityRequestOngoing,
    UeInCmIdleState,
    InsufficientResourcesSlice,
    InsufficientResourcesSliceDnn,
    DnnCongestion,
    SNssaiCongestion,
    PeerNotResponding,
    NetworkFailure,
    UpfNotResponding,
    UeNotReachable,
}

impl SbiAppError {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::N1SmError => "N1_SM_ERROR",
            Self::N2SmError => "N2_SM_ERROR",
            Self::SnssaiDenied => "SNSSAI_DENIED",
            Self::DnnDenied => "DNN_DENIED",
            Self::PdutypeDenied => "PDUTYPE_DENIED",
            Self::SscDenied => "SSC_DENIED",
            Self::SubscriptionDenied => "SUBSCRIPTION_DENIED",
            Self::DnnNotSupported => "DNN_NOT_SUPPORTED",
            Self::PdutypeNotSupported => "PDUTYPE_NOT_SUPPORTED",
            Self::SscNotSupported => "SSC_NOT_SUPPORTED",
            Self::HomeRoutedRoamingRequired => "HOME_ROUTED_ROAMING_REQUIRED",
            Self::OutOfLadnServiceArea => "OUT_OF_LADN_SERVICE_AREA",
            Self::PrioritizedServicesOnly => "PRIORITIZED_SERVICES_ONLY",
            Self::PduSessionAnchorChange => "PDU_SESSION_ANCHOR_CHANGE",
            Self::TargetMmeCapability => "TARGET_MME_CAPABILITY",
            Self::NoEps5gsContinuity => "NO_EPS_5GS_CONTINUITY",
            Self::UnableToPageUe => "UNABLE_TO_PAGE_UE",
            Self::UeNotResponding => "UE_NOT_RESPONDING",
            Self::RejectedByUe => "REJECTED_BY_UE",
            Self::RejectedDueVplmnPolicy => "REJECTED_DUE_VPLMN_POLICY",
            Self::HoTauInProgress => "HO_TAU_IN_PROGRESS",
            Self::IntegrityProtectedMdrNotAcceptable => "INTEGRITY_PROTECTED_MDR_NOT_ACCEPTABLE",
            Self::EbiExhausted => "EBI_EXHAUSTED",
            Self::EbiRejectedLocalPolicy => "EBI_REJECTED_LOCAL_POLICY",
            Self::EbiRejectedNoN26 => "EBI_REJECTED_NO_N26",
            Self::DefaultEpsBearerInactive => "DEFAULT_EPS_BEARER_INACTIVE",
            Self::HandoverResourceAllocationFailure => "HANDOVER_RESOURCE_ALLOCATION_FAILURE",
            Self::LateOverlappingRequest => "LATE_OVERLAPPING_REQUEST",
            Self::DefaultEbiNotTransferred => "DEFAULT_EBI_NOT_TRANSFERRED",
            Self::NotSupportedWithIsmf => "NOT_SUPPORTED_WITH_ISMF",
            Self::ServiceNotAuthorizedByNextHop => "SERVICE_NOT_AUTHORIZED_BY_NEXT_HOP",
            Self::NoDataForwarding => "NO_DATA_FORWARDING",
            Self::SNssaiUnavailableDueToNsac => "S_NSSAI_UNAVAILABLE_DUE_TO_NSAC",
            Self::ExceededUeSliceDataRate => "EXCEEDED_UE_SLICE_DATA_RATE",
            Self::ExceededSliceDataRate => "EXCEEDED_SLICE_DATA_RATE",
            Self::ContextNotFound => "CONTEXT_NOT_FOUND",
            Self::HigherPriorityRequestOngoing => "HIGHER_PRIORITY_REQUEST_ONGOING",
            Self::UeInCmIdleState => "UE_IN_CM_IDLE_STATE",
            Self::InsufficientResourcesSlice => "INSUFFICIENT_RESOURCES_SLICE",
            Self::InsufficientResourcesSliceDnn => "INSUFFICIENT_RESOURCES_SLICE_DNN",
            Self::DnnCongestion => "DNN_CONGESTION",
            Self::SNssaiCongestion => "S_NSSAI_CONGESTION",
            Self::PeerNotResponding => "PEER_NOT_RESPONDING",
            Self::NetworkFailure => "NETWORK_FAILURE",
            Self::UpfNotResponding => "UPF_NOT_RESPONDING",
            Self::UeNotReachable => "UE_NOT_REACHABLE",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "N1_SM_ERROR" => Some(Self::N1SmError),
            "N2_SM_ERROR" => Some(Self::N2SmError),
            "SNSSAI_DENIED" => Some(Self::SnssaiDenied),
            "DNN_DENIED" => Some(Self::DnnDenied),
            "PDUTYPE_DENIED" => Some(Self::PdutypeDenied),
            "SSC_DENIED" => Some(Self::SscDenied),
            "SUBSCRIPTION_DENIED" => Some(Self::SubscriptionDenied),
            "DNN_NOT_SUPPORTED" => Some(Self::DnnNotSupported),
            "PDUTYPE_NOT_SUPPORTED" => Some(Self::PdutypeNotSupported),
            "SSC_NOT_SUPPORTED" => Some(Self::SscNotSupported),
            "HOME_ROUTED_ROAMING_REQUIRED" => Some(Self::HomeRoutedRoamingRequired),
            "OUT_OF_LADN_SERVICE_AREA" => Some(Self::OutOfLadnServiceArea),
            "PRIORITIZED_SERVICES_ONLY" => Some(Self::PrioritizedServicesOnly),
            "PDU_SESSION_ANCHOR_CHANGE" => Some(Self::PduSessionAnchorChange),
            "TARGET_MME_CAPABILITY" => Some(Self::TargetMmeCapability),
            "NO_EPS_5GS_CONTINUITY" => Some(Self::NoEps5gsContinuity),
            "UNABLE_TO_PAGE_UE" => Some(Self::UnableToPageUe),
            "UE_NOT_RESPONDING" => Some(Self::UeNotResponding),
            "REJECTED_BY_UE" => Some(Self::RejectedByUe),
            "REJECTED_DUE_VPLMN_POLICY" => Some(Self::RejectedDueVplmnPolicy),
            "HO_TAU_IN_PROGRESS" => Some(Self::HoTauInProgress),
            "INTEGRITY_PROTECTED_MDR_NOT_ACCEPTABLE" => Some(Self::IntegrityProtectedMdrNotAcceptable),
            "EBI_EXHAUSTED" => Some(Self::EbiExhausted),
            "EBI_REJECTED_LOCAL_POLICY" => Some(Self::EbiRejectedLocalPolicy),
            "EBI_REJECTED_NO_N26" => Some(Self::EbiRejectedNoN26),
            "DEFAULT_EPS_BEARER_INACTIVE" => Some(Self::DefaultEpsBearerInactive),
            "HANDOVER_RESOURCE_ALLOCATION_FAILURE" => Some(Self::HandoverResourceAllocationFailure),
            "LATE_OVERLAPPING_REQUEST" => Some(Self::LateOverlappingRequest),
            "DEFAULT_EBI_NOT_TRANSFERRED" => Some(Self::DefaultEbiNotTransferred),
            "NOT_SUPPORTED_WITH_ISMF" => Some(Self::NotSupportedWithIsmf),
            "SERVICE_NOT_AUTHORIZED_BY_NEXT_HOP" => Some(Self::ServiceNotAuthorizedByNextHop),
            "NO_DATA_FORWARDING" => Some(Self::NoDataForwarding),
            "S_NSSAI_UNAVAILABLE_DUE_TO_NSAC" => Some(Self::SNssaiUnavailableDueToNsac),
            "EXCEEDED_UE_SLICE_DATA_RATE" => Some(Self::ExceededUeSliceDataRate),
            "EXCEEDED_SLICE_DATA_RATE" => Some(Self::ExceededSliceDataRate),
            "CONTEXT_NOT_FOUND" => Some(Self::ContextNotFound),
            "HIGHER_PRIORITY_REQUEST_ONGOING" => Some(Self::HigherPriorityRequestOngoing),
            "UE_IN_CM_IDLE_STATE" => Some(Self::UeInCmIdleState),
            "INSUFFICIENT_RESOURCES_SLICE" => Some(Self::InsufficientResourcesSlice),
            "INSUFFICIENT_RESOURCES_SLICE_DNN" => Some(Self::InsufficientResourcesSliceDnn),
            "DNN_CONGESTION" => Some(Self::DnnCongestion),
            "S_NSSAI_CONGESTION" => Some(Self::SNssaiCongestion),
            "PEER_NOT_RESPONDING" => Some(Self::PeerNotResponding),
            "NETWORK_FAILURE" => Some(Self::NetworkFailure),
            "UPF_NOT_RESPONDING" => Some(Self::UpfNotResponding),
            "UE_NOT_REACHABLE" => Some(Self::UeNotReachable),
            _ => None,
        }
    }
}

impl fmt::Display for SbiAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_conversion() {
        assert_eq!(SbiServiceType::NnrfNfm.to_name(), "nnrf-nfm");
        assert_eq!(SbiServiceType::from_name("nnrf-nfm"), Some(SbiServiceType::NnrfNfm));
        assert_eq!(SbiServiceType::from_name("invalid"), None);
    }

    #[test]
    fn test_uri_scheme() {
        assert_eq!(UriScheme::Http.as_str(), "http");
        assert_eq!(UriScheme::Https.as_str(), "https");
        assert_eq!(UriScheme::Http.default_port(), 80);
        assert_eq!(UriScheme::Https.default_port(), 443);
    }

    #[test]
    fn test_app_error_conversion() {
        assert_eq!(SbiAppError::ContextNotFound.to_str(), "CONTEXT_NOT_FOUND");
        assert_eq!(SbiAppError::from_str("CONTEXT_NOT_FOUND"), Some(SbiAppError::ContextNotFound));
    }
}
