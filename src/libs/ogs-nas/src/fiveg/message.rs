//! 5GS NAS messages
//!
//! Based on 3GPP TS 24.501

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::*;
use super::types::*;
use super::header::*;
use super::ie::*;

/// 5GMM message
#[derive(Debug, Clone, PartialEq)]
pub enum FiveGmmMessage {
    RegistrationRequest(RegistrationRequest),
    RegistrationAccept(RegistrationAccept),
    RegistrationReject(RegistrationReject),
    RegistrationComplete(RegistrationComplete),
    DeregistrationRequestFromUe(DeregistrationRequestFromUe),
    DeregistrationAcceptFromUe,
    DeregistrationRequestToUe(DeregistrationRequestToUe),
    DeregistrationAcceptToUe,
    ServiceRequest(ServiceRequest),
    ServiceAccept(ServiceAccept),
    ServiceReject(ServiceReject),
    AuthenticationRequest(AuthenticationRequest),
    AuthenticationResponse(AuthenticationResponse),
    AuthenticationReject(AuthenticationReject),
    AuthenticationFailure(AuthenticationFailure),
    AuthenticationResult(AuthenticationResult),
    IdentityRequest(IdentityRequest),
    IdentityResponse(IdentityResponse),
    SecurityModeCommand(SecurityModeCommand),
    SecurityModeComplete(SecurityModeComplete),
    SecurityModeReject(SecurityModeReject),
    FiveGmmStatus(FiveGmmStatus),
    UlNasTransport(UlNasTransport),
    DlNasTransport(DlNasTransport),
}

/// Registration Request message (TS 24.501 Section 8.2.6)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationRequest {
    /// 5GS registration type
    pub registration_type: RegistrationType,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
    /// Presence mask for optional IEs
    pub presencemask: u64,
    /// Non-current native NAS key set identifier
    pub non_current_native_ngksi: Option<KeySetIdentifier>,
    /// 5GMM capability
    pub gmm_capability: Option<FiveGmmCapability>,
    /// UE security capability
    pub ue_security_capability: Option<UeSecurityCapability>,
    /// Requested NSSAI
    pub requested_nssai: Option<Nssai>,
    /// Last visited registered TAI
    pub last_visited_tai: Option<Tai>,
    /// UE status
    pub ue_status: Option<u8>,
    /// Additional GUTI
    pub additional_guti: Option<MobileIdentity>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// Uplink data status
    pub uplink_data_status: Option<UplinkDataStatus>,
}

impl RegistrationRequest {
    /// Encode registration request to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // Registration type + ngKSI (1 byte)
        buf.put_u8((self.ngksi.encode() << 4) | self.registration_type.encode());
        // Mobile identity
        self.mobile_identity.encode(buf);
        // Optional IEs would be encoded here based on presencemask
    }

    /// Decode registration request from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }

        let first_byte = buf.get_u8();
        let registration_type = RegistrationType::decode(first_byte & 0x0F)?;
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let mobile_identity = MobileIdentity::decode(buf)?;

        let mut msg = Self {
            registration_type,
            ngksi,
            mobile_identity,
            ..Default::default()
        };

        // Decode optional IEs
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };

            match iei_type {
                0x10 => {
                    // 5GMM capability
                    buf.advance(1);
                    msg.gmm_capability = Some(FiveGmmCapability::decode(buf)?);
                }
                0x2E => {
                    // UE security capability
                    buf.advance(1);
                    msg.ue_security_capability = Some(UeSecurityCapability::decode(buf)?);
                }
                0x2F => {
                    // Requested NSSAI
                    buf.advance(1);
                    msg.requested_nssai = Some(Nssai::decode(buf)?);
                }
                0x52 => {
                    // Last visited registered TAI
                    buf.advance(1);
                    msg.last_visited_tai = Some(Tai::decode(buf)?);
                }
                0x40 => {
                    // Uplink data status
                    buf.advance(1);
                    msg.uplink_data_status = Some(UplinkDataStatus::decode(buf)?);
                }
                0x50 => {
                    // PDU session status
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                _ => {
                    // Skip unknown IE
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            buf.advance(len);
                        }
                    }
                }
            }
        }

        Ok(msg)
    }
}

/// Registration Accept message (TS 24.501 Section 8.2.7)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationAccept {
    /// 5GS registration result
    pub registration_result: RegistrationResult,
    /// Presence mask
    pub presencemask: u64,
    /// 5G-GUTI
    pub guti: Option<MobileIdentity>,
    /// Equivalent PLMNs
    pub equivalent_plmns: Option<Vec<PlmnId>>,
    /// TAI list
    pub tai_list: Option<TaiList>,
    /// Allowed NSSAI
    pub allowed_nssai: Option<Nssai>,
    /// Rejected NSSAI
    pub rejected_nssai: Option<Vec<u8>>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// T3512 value
    pub t3512_value: Option<GprsTimer3>,
    /// T3502 value
    pub t3502_value: Option<GprsTimer2>,
}

impl RegistrationAccept {
    /// Encode registration accept to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.registration_result.encode(buf);
        // Optional IEs
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x77); // IEI
            guti.encode(buf);
        }
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
        if let Some(ref allowed_nssai) = self.allowed_nssai {
            buf.put_u8(0x15); // IEI
            allowed_nssai.encode(buf);
        }
    }

    /// Decode registration accept from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let registration_result = RegistrationResult::decode(buf)?;
        let mut msg = Self {
            registration_result,
            ..Default::default()
        };

        // Decode optional IEs
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x77 => {
                    buf.advance(1);
                    msg.guti = Some(MobileIdentity::decode(buf)?);
                }
                0x54 => {
                    buf.advance(1);
                    msg.tai_list = Some(TaiList::decode(buf)?);
                }
                0x15 => {
                    buf.advance(1);
                    msg.allowed_nssai = Some(Nssai::decode(buf)?);
                }
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x5E => {
                    buf.advance(1);
                    msg.t3512_value = Some(GprsTimer3::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            buf.advance(len);
                        }
                    }
                }
            }
        }

        Ok(msg)
    }
}

/// Registration Reject message (TS 24.501 Section 8.2.8)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationReject {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// T3502 value
    pub t3502_value: Option<GprsTimer2>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl RegistrationReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F);
            t3346.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gmm_cause = buf.get_u8();
        let mut msg = Self { gmm_cause, ..Default::default() };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                0x16 => {
                    buf.advance(1);
                    msg.t3502_value = Some(GprsTimer2::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            buf.advance(len);
                        }
                    }
                }
            }
        }

        Ok(msg)
    }
}

/// Registration Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationComplete {
    /// SOR transparent container
    pub sor_transparent_container: Option<Vec<u8>>,
}

/// Deregistration Request from UE
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeregistrationRequestFromUe {
    /// De-registration type
    pub de_registration_type: DeRegistrationType,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
}

/// Deregistration Request to UE
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeregistrationRequestToUe {
    /// De-registration type
    pub de_registration_type: DeRegistrationType,
    /// 5GMM cause
    pub gmm_cause: Option<u8>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
}

/// Service Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceRequest {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// Service type
    pub service_type: ServiceType,
    /// 5G-S-TMSI
    pub s_tmsi: MobileIdentity,
    /// Uplink data status
    pub uplink_data_status: Option<UplinkDataStatus>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// Allowed PDU session status
    pub allowed_pdu_session_status: Option<AllowedPduSessionStatus>,
    /// NAS message container
    pub nas_message_container: Option<NasMessageContainer>,
}

/// Service Accept message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceAccept {
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// PDU session reactivation result
    pub pdu_session_reactivation_result: Option<u16>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
    /// T3448 value
    pub t3448_value: Option<GprsTimer2>,
}

/// Service Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceReject {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

/// Authentication Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationRequest {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// ABBA
    pub abba: Abba,
    /// Authentication parameter RAND
    pub rand: Option<AuthenticationRand>,
    /// Authentication parameter AUTN
    pub autn: Option<AuthenticationAutn>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl AuthenticationRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ngksi.encode());
        self.abba.encode(buf);
        if let Some(ref rand) = self.rand {
            buf.put_u8(0x21); // IEI
            buf.put_slice(rand);
        }
        if let Some(ref autn) = self.autn {
            buf.put_u8(0x20); // IEI
            buf.put_u8(16); // Length
            buf.put_slice(autn);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let abba = Abba::decode(buf)?;

        let mut msg = Self { ngksi, abba, ..Default::default() };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x21 => {
                    buf.advance(1);
                    let mut rand = [0u8; 16];
                    if buf.remaining() >= 16 {
                        buf.copy_to_slice(&mut rand);
                        msg.rand = Some(rand);
                    }
                }
                0x20 => {
                    buf.advance(1);
                    let len = buf.get_u8();
                    if buf.remaining() >= len as usize && len >= 16 {
                        let mut autn = [0u8; 16];
                        buf.copy_to_slice(&mut autn);
                        msg.autn = Some(autn);
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            buf.advance(len);
                        }
                    }
                }
            }
        }

        Ok(msg)
    }
}

/// Authentication Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationResponse {
    /// Authentication response parameter
    pub authentication_response_parameter: Option<AuthenticationResponseParameter>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

/// Authentication Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationReject {
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

/// Authentication Failure message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationFailure {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// Authentication failure parameter
    pub authentication_failure_parameter: Option<Vec<u8>>,
}

/// Authentication Result message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationResult {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// EAP message
    pub eap_message: EapMessage,
    /// ABBA
    pub abba: Option<Abba>,
}

/// Identity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityRequest {
    /// 5GS identity type
    pub identity_type: FiveGsIdentityType,
}

/// Identity Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityResponse {
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
}

/// Security Mode Command message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeCommand {
    /// Selected NAS security algorithms
    pub selected_nas_security_algorithms: SecurityAlgorithms,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// Replayed UE security capabilities
    pub replayed_ue_security_capabilities: UeSecurityCapability,
    /// IMEISV request
    pub imeisv_request: Option<u8>,
    /// Selected EPS NAS security algorithms
    pub selected_eps_nas_security_algorithms: Option<SecurityAlgorithms>,
    /// Additional 5G security information
    pub additional_5g_security_information: Option<u8>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
    /// ABBA
    pub abba: Option<Abba>,
    /// Replayed S1 UE security capabilities
    pub replayed_s1_ue_security_capabilities: Option<Vec<u8>>,
}

/// Security Mode Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeComplete {
    /// IMEISV
    pub imeisv: Option<MobileIdentity>,
    /// NAS message container
    pub nas_message_container: Option<NasMessageContainer>,
    /// Non-IMEISV PEI
    pub non_imeisv_pei: Option<MobileIdentity>,
}

/// Security Mode Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeReject {
    /// 5GMM cause
    pub gmm_cause: u8,
}

/// 5GMM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FiveGmmStatus {
    /// 5GMM cause
    pub gmm_cause: u8,
}

/// UL NAS Transport message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UlNasTransport {
    /// Payload container type
    pub payload_container_type: PayloadContainerType,
    /// Payload container
    pub payload_container: PayloadContainer,
    /// PDU session ID
    pub pdu_session_id: Option<PduSessionIdentity>,
    /// Old PDU session ID
    pub old_pdu_session_id: Option<PduSessionIdentity>,
    /// Request type
    pub request_type: Option<RequestType>,
    /// S-NSSAI
    pub s_nssai: Option<SNssai>,
    /// DNN
    pub dnn: Option<Dnn>,
}

/// DL NAS Transport message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DlNasTransport {
    /// Payload container type
    pub payload_container_type: PayloadContainerType,
    /// Payload container
    pub payload_container: PayloadContainer,
    /// PDU session ID
    pub pdu_session_id: Option<PduSessionIdentity>,
    /// Additional information
    pub additional_information: Option<Vec<u8>>,
    /// 5GMM cause
    pub gmm_cause: Option<u8>,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
}

/// Build a 5GMM message with header
pub fn build_5gmm_message(msg: &FiveGmmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        FiveGmmMessage::RegistrationRequest(_) => FiveGmmMessageType::RegistrationRequest,
        FiveGmmMessage::RegistrationAccept(_) => FiveGmmMessageType::RegistrationAccept,
        FiveGmmMessage::RegistrationReject(_) => FiveGmmMessageType::RegistrationReject,
        FiveGmmMessage::RegistrationComplete(_) => FiveGmmMessageType::RegistrationComplete,
        FiveGmmMessage::DeregistrationRequestFromUe(_) => FiveGmmMessageType::DeregistrationRequestFromUe,
        FiveGmmMessage::DeregistrationAcceptFromUe => FiveGmmMessageType::DeregistrationAcceptFromUe,
        FiveGmmMessage::DeregistrationRequestToUe(_) => FiveGmmMessageType::DeregistrationRequestToUe,
        FiveGmmMessage::DeregistrationAcceptToUe => FiveGmmMessageType::DeregistrationAcceptToUe,
        FiveGmmMessage::ServiceRequest(_) => FiveGmmMessageType::ServiceRequest,
        FiveGmmMessage::ServiceAccept(_) => FiveGmmMessageType::ServiceAccept,
        FiveGmmMessage::ServiceReject(_) => FiveGmmMessageType::ServiceReject,
        FiveGmmMessage::AuthenticationRequest(_) => FiveGmmMessageType::AuthenticationRequest,
        FiveGmmMessage::AuthenticationResponse(_) => FiveGmmMessageType::AuthenticationResponse,
        FiveGmmMessage::AuthenticationReject(_) => FiveGmmMessageType::AuthenticationReject,
        FiveGmmMessage::AuthenticationFailure(_) => FiveGmmMessageType::AuthenticationFailure,
        FiveGmmMessage::AuthenticationResult(_) => FiveGmmMessageType::AuthenticationResult,
        FiveGmmMessage::IdentityRequest(_) => FiveGmmMessageType::IdentityRequest,
        FiveGmmMessage::IdentityResponse(_) => FiveGmmMessageType::IdentityResponse,
        FiveGmmMessage::SecurityModeCommand(_) => FiveGmmMessageType::SecurityModeCommand,
        FiveGmmMessage::SecurityModeComplete(_) => FiveGmmMessageType::SecurityModeComplete,
        FiveGmmMessage::SecurityModeReject(_) => FiveGmmMessageType::SecurityModeReject,
        FiveGmmMessage::FiveGmmStatus(_) => FiveGmmMessageType::FiveGmmStatus,
        FiveGmmMessage::UlNasTransport(_) => FiveGmmMessageType::UlNasTransport,
        FiveGmmMessage::DlNasTransport(_) => FiveGmmMessageType::DlNasTransport,
    };

    // Encode header
    let header = FiveGsNasHeader::new_gmm(message_type);
    header.encode(&mut buf);

    // Encode message body
    match msg {
        FiveGmmMessage::RegistrationRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::RegistrationAccept(m) => m.encode(&mut buf),
        FiveGmmMessage::RegistrationReject(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationRequest(m) => m.encode(&mut buf),
        _ => {} // Other messages would be encoded here
    }

    buf
}

/// Parse a 5GMM message
pub fn parse_5gmm_message(buf: &mut Bytes) -> NasResult<FiveGmmMessage> {
    let header = FiveGsNasHeader::decode(buf)?;
    let message_type = FiveGmmMessageType::try_from(header.message_type)?;

    match message_type {
        FiveGmmMessageType::RegistrationRequest => {
            Ok(FiveGmmMessage::RegistrationRequest(RegistrationRequest::decode(buf)?))
        }
        FiveGmmMessageType::RegistrationAccept => {
            Ok(FiveGmmMessage::RegistrationAccept(RegistrationAccept::decode(buf)?))
        }
        FiveGmmMessageType::RegistrationReject => {
            Ok(FiveGmmMessage::RegistrationReject(RegistrationReject::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationRequest => {
            Ok(FiveGmmMessage::AuthenticationRequest(AuthenticationRequest::decode(buf)?))
        }
        _ => Err(NasError::InvalidMessageType(header.message_type)),
    }
}
