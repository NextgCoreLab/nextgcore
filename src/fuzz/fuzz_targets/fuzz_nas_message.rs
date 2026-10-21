//! NAS Message Fuzzer
//!
//! Exercises the real `nextgcore_nas` decoders (5GS NAS, TS 24.501, and EPS NAS,
//! TS 24.301: every message body and the plain/security headers) against
//! arbitrary bytes. The first byte selects the decoder, the rest is its input.
//! Before #587 this target carried its own hand-written parser and called nothing
//! in `nextgcore_nas`. No decoder may panic; malformed input is `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_nas_message

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nextgcore_nas::{eps, fiveg};

type Decoder = fn(&mut Bytes) -> bool;

const FIVEG: &[Decoder] = &[
    |b| fiveg::RegistrationRequest::decode(b).is_ok(),
    |b| fiveg::RegistrationAccept::decode(b).is_ok(),
    |b| fiveg::RegistrationReject::decode(b).is_ok(),
    |b| fiveg::RegistrationComplete::decode(b).is_ok(),
    |b| fiveg::DeregistrationRequestFromUe::decode(b).is_ok(),
    |b| fiveg::DeregistrationRequestToUe::decode(b).is_ok(),
    |b| fiveg::ServiceRequest::decode(b).is_ok(),
    |b| fiveg::ServiceAccept::decode(b).is_ok(),
    |b| fiveg::ServiceReject::decode(b).is_ok(),
    |b| fiveg::AuthenticationRequest::decode(b).is_ok(),
    |b| fiveg::AuthenticationResponse::decode(b).is_ok(),
    |b| fiveg::AuthenticationReject::decode(b).is_ok(),
    |b| fiveg::AuthenticationFailure::decode(b).is_ok(),
    |b| fiveg::AuthenticationResult::decode(b).is_ok(),
    |b| fiveg::IdentityRequest::decode(b).is_ok(),
    |b| fiveg::IdentityResponse::decode(b).is_ok(),
    |b| fiveg::SecurityModeCommand::decode(b).is_ok(),
    |b| fiveg::SecurityModeComplete::decode(b).is_ok(),
    |b| fiveg::SecurityModeReject::decode(b).is_ok(),
    |b| fiveg::FiveGmmStatus::decode(b).is_ok(),
    |b| fiveg::UlNasTransport::decode(b).is_ok(),
    |b| fiveg::DlNasTransport::decode(b).is_ok(),
    |b| fiveg::ConfigurationUpdateCommand::decode(b).is_ok(),
    |b| fiveg::Notification::decode(b).is_ok(),
    |b| fiveg::NotificationResponse::decode(b).is_ok(),
    |b| fiveg::ControlPlaneServiceRequest::decode(b).is_ok(),
    |b| fiveg::NetworkSliceSpecificAuthenticationCommand::decode(b).is_ok(),
    |b| fiveg::NetworkSliceSpecificAuthenticationComplete::decode(b).is_ok(),
    |b| fiveg::NetworkSliceSpecificAuthenticationResult::decode(b).is_ok(),
    |b| fiveg::PduSessionEstablishmentRequest::decode(b).is_ok(),
    |b| fiveg::PduSessionEstablishmentAccept::decode(b).is_ok(),
    |b| fiveg::PduSessionEstablishmentReject::decode(b).is_ok(),
    |b| fiveg::PduSessionModificationRequest::decode(b).is_ok(),
    |b| fiveg::PduSessionModificationCommand::decode(b).is_ok(),
    |b| fiveg::PduSessionModificationReject::decode(b).is_ok(),
    |b| fiveg::PduSessionModificationCommandReject::decode(b).is_ok(),
    |b| fiveg::PduSessionReleaseRequest::decode(b).is_ok(),
    |b| fiveg::PduSessionReleaseReject::decode(b).is_ok(),
    |b| fiveg::PduSessionReleaseCommand::decode(b).is_ok(),
    |b| fiveg::PduSessionReleaseComplete::decode(b).is_ok(),
    |b| fiveg::FiveGsmStatus::decode(b).is_ok(),
    |b| fiveg::PduSessionAuthenticationCommand::decode(b).is_ok(),
    |b| fiveg::PduSessionAuthenticationComplete::decode(b).is_ok(),
    |b| fiveg::PduSessionAuthenticationResult::decode(b).is_ok(),
    |b| fiveg::RemoteUeReport::decode(b).is_ok(),
    |b| fiveg::RemoteUeReportResponse::decode(b).is_ok(),
    |b| fiveg::FiveGsNasHeader::decode(b).is_ok(),
    |b| fiveg::FiveGsNasSmHeader::decode(b).is_ok(),
    |b| fiveg::FiveGsNasSecurityHeader::decode(b).is_ok(),
];

const EPS: &[Decoder] = &[
    |b| eps::AttachRequest::decode(b).is_ok(),
    |b| eps::AttachAccept::decode(b).is_ok(),
    |b| eps::AttachComplete::decode(b).is_ok(),
    |b| eps::AttachReject::decode(b).is_ok(),
    |b| eps::DetachRequest::decode(b).is_ok(),
    |b| eps::TrackingAreaUpdateRequest::decode(b).is_ok(),
    |b| eps::TrackingAreaUpdateAccept::decode(b).is_ok(),
    |b| eps::TrackingAreaUpdateReject::decode(b).is_ok(),
    |b| eps::EpsAuthenticationRequest::decode(b).is_ok(),
    |b| eps::EpsAuthenticationResponse::decode(b).is_ok(),
    |b| eps::EpsAuthenticationFailure::decode(b).is_ok(),
    |b| eps::EpsSecurityModeCommand::decode(b).is_ok(),
    |b| eps::EpsSecurityModeComplete::decode(b).is_ok(),
    |b| eps::EpsSecurityModeReject::decode(b).is_ok(),
    |b| eps::EpsIdentityRequest::decode(b).is_ok(),
    |b| eps::EpsIdentityResponse::decode(b).is_ok(),
    |b| eps::EmmStatus::decode(b).is_ok(),
    |b| eps::EpsServiceRequest::decode(b).is_ok(),
    |b| eps::ExtendedServiceRequest::decode(b).is_ok(),
    |b| eps::EpsServiceReject::decode(b).is_ok(),
    |b| eps::GutiReallocationCommand::decode(b).is_ok(),
    |b| eps::EmmInformation::decode(b).is_ok(),
    |b| eps::EpsDownlinkNasTransport::decode(b).is_ok(),
    |b| eps::EpsUplinkNasTransport::decode(b).is_ok(),
    |b| eps::CsServiceNotification::decode(b).is_ok(),
    |b| eps::PdnConnectivityRequest::decode(b).is_ok(),
    |b| eps::PdnConnectivityReject::decode(b).is_ok(),
    |b| eps::PdnDisconnectRequest::decode(b).is_ok(),
    |b| eps::PdnDisconnectReject::decode(b).is_ok(),
    |b| eps::ActivateDefaultEpsBearerContextRequest::decode(b).is_ok(),
    |b| eps::ActivateDefaultEpsBearerContextReject::decode(b).is_ok(),
    |b| eps::BearerResourceAllocationRequest::decode(b).is_ok(),
    |b| eps::BearerResourceAllocationReject::decode(b).is_ok(),
    |b| eps::BearerResourceModificationRequest::decode(b).is_ok(),
    |b| eps::BearerResourceModificationReject::decode(b).is_ok(),
    |b| eps::ActivateDedicatedEpsBearerContextRequest::decode(b).is_ok(),
    |b| eps::ActivateDedicatedEpsBearerContextReject::decode(b).is_ok(),
    |b| eps::ModifyEpsBearerContextRequest::decode(b).is_ok(),
    |b| eps::ModifyEpsBearerContextAccept::decode(b).is_ok(),
    |b| eps::ModifyEpsBearerContextReject::decode(b).is_ok(),
    |b| eps::DeactivateEpsBearerContextRequest::decode(b).is_ok(),
    |b| eps::EsmInformationResponse::decode(b).is_ok(),
    |b| eps::EsmStatus::decode(b).is_ok(),
    |b| eps::EpsNasEmmHeader::decode(b).is_ok(),
    |b| eps::EpsNasEsmHeader::decode(b).is_ok(),
    |b| eps::EpsNasSecurityHeader::decode(b).is_ok(),
];

fuzz_target!(|data: &[u8]| {
    if let Some((&sel, body)) = data.split_first() {
        let sel = sel as usize % (FIVEG.len() + EPS.len());
        let decode = if sel < FIVEG.len() {
            FIVEG[sel]
        } else {
            EPS[sel - FIVEG.len()]
        };
        let _ = decode(&mut Bytes::copy_from_slice(body));
    }
});
