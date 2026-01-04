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

pub mod error;
pub mod common;
pub mod fiveg;
pub mod eps;

#[cfg(test)]
mod property_tests;

pub use error::{NasError, NasResult};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::error::{NasError, NasResult};
    pub use crate::common::types::{
        ProtocolDiscriminator,
        SecurityHeaderType,
        PlmnId,
        Tai,
        SNssai,
        GprsTimer,
        GprsTimer2,
        GprsTimer3,
        Dnn,
        KeySetIdentifier,
        SecurityAlgorithms,
        UeSecurityCapability,
        Abba,
        EapMessage,
    };
    pub use crate::common::security::{
        NasSecurityContext,
        NasCount,
        protect_nas_message,
        unprotect_nas_message,
    };
    pub use crate::fiveg::{
        FiveGmmMessage,
        RegistrationRequest,
        RegistrationAccept,
        RegistrationReject,
        AuthenticationRequest,
        AuthenticationResponse,
        SecurityModeCommand,
        SecurityModeComplete,
        RegistrationType,
        RegistrationTypeValue,
        MobileIdentity,
        FiveGGuti,
        FiveGSTmsi,
        Suci,
        FiveGmmCause,
        build_5gmm_message,
        parse_5gmm_message,
    };
    pub use crate::eps::{
        EmmMessage,
        AttachRequest,
        AttachAccept,
        EpsAttachType,
        EpsAttachResult,
        EpsMobileIdentity,
        EpsGuti,
        EmmCause,
        build_emm_message,
        parse_emm_message,
    };
}
