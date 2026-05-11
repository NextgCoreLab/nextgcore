//! NextGCore NAS Protocol Library
//!
//! This crate provides 5GS and EPS NAS message building and parsing as specified
//! in 3GPP TS 24.501 (5GS) and TS 24.301 (EPS).
//!
//! # Features
//!
//! - 5GS NAS (5GMM and 5GSM) message encoding/decoding
//! - EPS NAS (EMM and ESM) message encoding/decoding
//! - NAS security (integrity protection and ciphering)
//! - Common NAS types (PLMN, TAI, S-NSSAI, etc.)
//!
//! # Example
//!
//! ```rust
//! use ogs_nas::fiveg::{
//!     RegistrationRequest, RegistrationType, RegistrationTypeValue,
//!     MobileIdentity, FiveGGuti, build_5gmm_message, FiveGmmMessage,
//! };
//! use ogs_nas::common::types::{PlmnId, KeySetIdentifier};
//!
//! // Create a registration request
//! let mut request = RegistrationRequest::default();
//! request.registration_type = RegistrationType::new(false, RegistrationTypeValue::InitialRegistration);
//! request.ngksi = KeySetIdentifier::new(0, 7); // No key available
//! request.mobile_identity = MobileIdentity::FiveGGuti(FiveGGuti {
//!     plmn_id: PlmnId::new([0, 0, 1], [0, 1, 0], 2),
//!     amf_region_id: 1,
//!     amf_set_id: 1,
//!     amf_pointer: 0,
//!     tmsi: 0x12345678,
//! });
//!
//! // Build the message
//! let msg = FiveGmmMessage::RegistrationRequest(request);
//! let buf = build_5gmm_message(&msg);
//! ```

pub mod common;
pub mod eps;
pub mod error;
pub mod fiveg;

#[cfg(test)]
mod property_tests;

pub use error::{NasError, NasResult};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::common::security::{
        protect_nas_message, unprotect_nas_message, NasCount, NasSecurityContext,
    };
    pub use crate::common::types::{
        Abba, Dnn, EapMessage, GprsTimer, GprsTimer2, GprsTimer3, KeySetIdentifier, PlmnId,
        ProtocolDiscriminator, SNssai, SecurityAlgorithms, SecurityHeaderType, Tai,
        UeSecurityCapability,
    };
    pub use crate::eps::{
        build_emm_message,
        build_esm_message,
        parse_emm_message,
        parse_esm_message,
        AttachAccept,
        AttachComplete,
        AttachReject,
        AttachRequest,
        CsServiceNotification,
        DetachRequest,
        EmmCause,
        EmmInformation,
        EmmMessage,
        EmmStatus,
        EpsAttachResult,
        EpsAttachType,
        EpsAuthenticationFailure,
        EpsAuthenticationRequest,
        EpsAuthenticationResponse,
        EpsDownlinkNasTransport,
        EpsGuti,
        EpsIdentityRequest,
        EpsIdentityResponse,
        EpsMobileIdentity,
        EpsSecurityModeCommand,
        EpsSecurityModeComplete,
        EpsSecurityModeReject,
        EpsServiceReject,
        EpsServiceRequest,
        EpsUplinkNasTransport,
        // ESM
        EsmMessage,
        ExtendedServiceRequest,
        GutiReallocationCommand,
        TrackingAreaUpdateAccept,
        TrackingAreaUpdateReject,
        TrackingAreaUpdateRequest,
    };
    pub use crate::error::{NasError, NasResult};
    pub use crate::fiveg::{
        build_5gmm_message,
        build_5gsm_message,
        parse_5gmm_message,
        parse_5gsm_message,
        // 6G extension IEs
        AiMlCapability,
        AuthenticationFailure,
        AuthenticationReject,
        AuthenticationRequest,
        AuthenticationResponse,
        AuthenticationResult,
        ConfigurationUpdateCommand,
        ControlPlaneServiceRequest,
        DeregistrationRequestFromUe,
        DeregistrationRequestToUe,
        DlNasTransport,
        FiveGGuti,
        FiveGSTmsi,
        FiveGmmCause,
        FiveGmmMessage,
        FiveGmmStatus,
        // 5GSM
        FiveGsmMessage,
        FiveGsmStatus,
        IdentityRequest,
        IdentityResponse,
        IsacParameter,
        MobileIdentity,
        NetworkSliceSpecificAuthenticationCommand,
        NetworkSliceSpecificAuthenticationComplete,
        NetworkSliceSpecificAuthenticationResult,
        Notification,
        NotificationResponse,
        NtnAccessBarring,
        NtnTimingAdvance,
        PduSessionAuthenticationCommand,
        PduSessionAuthenticationComplete,
        PduSessionAuthenticationResult,
        PduSessionEstablishmentAccept,
        PduSessionEstablishmentReject,
        PduSessionEstablishmentRequest,
        PduSessionModificationCommand,
        PduSessionModificationCommandReject,
        PduSessionModificationReject,
        PduSessionModificationRequest,
        PduSessionReleaseCommand,
        PduSessionReleaseComplete,
        PduSessionReleaseReject,
        PduSessionReleaseRequest,
        RegistrationAccept,
        RegistrationComplete,
        RegistrationReject,
        RegistrationRequest,
        RegistrationType,
        RegistrationTypeValue,
        RemoteUeReport,
        RemoteUeReportResponse,
        SecurityModeCommand,
        SecurityModeComplete,
        SecurityModeReject,
        SemanticCommParameter,
        ServiceAccept,
        ServiceReject,
        ServiceRequest,
        SubThzBandParameter,
        Suci,
        UlNasTransport,
    };
}
