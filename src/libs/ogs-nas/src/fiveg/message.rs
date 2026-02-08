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

impl RegistrationComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref sor) = self.sor_transparent_container {
            buf.put_u8(0x73); // IEI
            buf.put_u16(sor.len() as u16);
            buf.put_slice(sor);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x73 => {
                    buf.advance(1);
                    if buf.remaining() < 2 {
                        break;
                    }
                    let len = buf.get_u16() as usize;
                    if buf.remaining() >= len {
                        msg.sor_transparent_container = Some(buf.copy_to_bytes(len).to_vec());
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl DeregistrationRequestFromUe {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ngksi.encode() << 4) | self.de_registration_type.encode());
        self.mobile_identity.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let first_byte = buf.get_u8();
        let de_registration_type = DeRegistrationType::decode(first_byte & 0x0F);
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let mobile_identity = MobileIdentity::decode(buf)?;
        Ok(Self { de_registration_type, ngksi, mobile_identity })
    }
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

impl DeregistrationRequestToUe {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.de_registration_type.encode());
        if let Some(cause) = self.gmm_cause {
            buf.put_u8(0x58); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let first_byte = buf.get_u8();
        let de_registration_type = DeRegistrationType::decode(first_byte & 0x0F);
        let mut msg = Self { de_registration_type, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x58 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gmm_cause = Some(buf.get_u8());
                    }
                }
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl ServiceRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ngksi.encode() << 4) | (self.service_type as u8 & 0x0F));
        self.s_tmsi.encode(buf);
        if let Some(ref uds) = self.uplink_data_status {
            buf.put_u8(0x40); // IEI
            uds.encode(buf);
        }
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref apss) = self.allowed_pdu_session_status {
            buf.put_u8(0x25); // IEI
            apss.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI
            nmc.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let first_byte = buf.get_u8();
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let service_type_val = first_byte & 0x0F;
        let service_type = match service_type_val {
            0 => ServiceType::Signalling,
            1 => ServiceType::Data,
            2 => ServiceType::MobileTerminatedServices,
            3 => ServiceType::EmergencyServices,
            4 => ServiceType::EmergencyServicesFallback,
            5 => ServiceType::HighPriorityAccess,
            6 => ServiceType::ElevatedSignalling,
            _ => ServiceType::UnusedFallback,
        };
        let s_tmsi = MobileIdentity::decode(buf)?;
        let mut msg = Self { ngksi, service_type, s_tmsi, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x40 => {
                    buf.advance(1);
                    msg.uplink_data_status = Some(UplinkDataStatus::decode(buf)?);
                }
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x25 => {
                    buf.advance(1);
                    msg.allowed_pdu_session_status = Some(AllowedPduSessionStatus::decode(buf)?);
                }
                0x71 => {
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl ServiceAccept {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(result) = self.pdu_session_reactivation_result {
            buf.put_u8(0x26); // IEI
            buf.put_u8(2); // Length
            buf.put_u16(result);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
        if let Some(ref t3448) = self.t3448_value {
            buf.put_u8(0x6B); // IEI
            t3448.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x26 => {
                    buf.advance(1);
                    if buf.remaining() >= 3 {
                        let _len = buf.get_u8();
                        msg.pdu_session_reactivation_result = Some(buf.get_u16());
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                0x6B => {
                    buf.advance(1);
                    msg.t3448_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl ServiceReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gmm_cause = buf.get_u8();
        let mut msg = Self { gmm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl AuthenticationResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref arp) = self.authentication_response_parameter {
            buf.put_u8(0x2D); // IEI
            arp.encode(buf);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x2D => {
                    buf.advance(1);
                    msg.authentication_response_parameter = Some(AuthenticationResponseParameter::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// Authentication Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationReject {
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl AuthenticationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// Authentication Failure message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationFailure {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// Authentication failure parameter
    pub authentication_failure_parameter: Option<Vec<u8>>,
}

impl AuthenticationFailure {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref afp) = self.authentication_failure_parameter {
            buf.put_u8(0x30); // IEI
            buf.put_u8(afp.len() as u8);
            buf.put_slice(afp);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gmm_cause = buf.get_u8();
        let mut msg = Self { gmm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x30 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.authentication_failure_parameter = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl AuthenticationResult {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ngksi.encode());
        self.eap_message.encode(buf);
        if let Some(ref abba) = self.abba {
            buf.put_u8(0x38); // IEI
            abba.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let eap_message = EapMessage::decode(buf)?;
        let mut msg = Self { ngksi, eap_message, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x38 => {
                    buf.advance(1);
                    msg.abba = Some(Abba::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// Identity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityRequest {
    /// 5GS identity type
    pub identity_type: FiveGsIdentityType,
}

impl IdentityRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.identity_type as u8 & 0x07);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let byte = buf.get_u8();
        let identity_type = match byte & 0x07 {
            1 => FiveGsIdentityType::Suci,
            2 => FiveGsIdentityType::FiveGGuti,
            3 => FiveGsIdentityType::Imei,
            4 => FiveGsIdentityType::FiveGSTmsi,
            5 => FiveGsIdentityType::Imeisv,
            6 => FiveGsIdentityType::MacAddress,
            7 => FiveGsIdentityType::Eui64,
            _ => FiveGsIdentityType::Suci,
        };
        Ok(Self { identity_type })
    }
}

/// Identity Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityResponse {
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
}

impl IdentityResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.mobile_identity.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mobile_identity = MobileIdentity::decode(buf)?;
        Ok(Self { mobile_identity })
    }
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

impl SecurityModeCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.selected_nas_security_algorithms.encode());
        buf.put_u8(self.ngksi.encode());
        self.replayed_ue_security_capabilities.encode(buf);
        if let Some(imeisv_req) = self.imeisv_request {
            buf.put_u8(0xE0 | (imeisv_req & 0x0F)); // IEI E- (half-byte)
        }
        if let Some(ref eps_algs) = self.selected_eps_nas_security_algorithms {
            buf.put_u8(0x57); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(eps_algs.encode());
        }
        if let Some(info) = self.additional_5g_security_information {
            buf.put_u8(0x36); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(info);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
        if let Some(ref abba) = self.abba {
            buf.put_u8(0x38); // IEI
            abba.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let selected_nas_security_algorithms = SecurityAlgorithms::decode(buf.get_u8());
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let replayed_ue_security_capabilities = UeSecurityCapability::decode(buf)?;
        let mut msg = Self {
            selected_nas_security_algorithms,
            ngksi,
            replayed_ue_security_capabilities,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0xE0 => {
                    buf.advance(1);
                    msg.imeisv_request = Some(iei & 0x0F);
                }
                0x57 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.selected_eps_nas_security_algorithms = Some(SecurityAlgorithms::decode(buf.get_u8()));
                    }
                }
                0x36 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.additional_5g_security_information = Some(buf.get_u8());
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                0x38 => {
                    buf.advance(1);
                    msg.abba = Some(Abba::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl SecurityModeComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref imeisv) = self.imeisv {
            buf.put_u8(0x77); // IEI
            imeisv.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI
            nmc.encode(buf);
        }
        if let Some(ref pei) = self.non_imeisv_pei {
            buf.put_u8(0x78); // IEI
            pei.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x77 => {
                    buf.advance(1);
                    msg.imeisv = Some(MobileIdentity::decode(buf)?);
                }
                0x71 => {
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.non_imeisv_pei = Some(MobileIdentity::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// Security Mode Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeReject {
    /// 5GMM cause
    pub gmm_cause: u8,
}

impl SecurityModeReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self { gmm_cause: buf.get_u8() })
    }
}

/// 5GMM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FiveGmmStatus {
    /// 5GMM cause
    pub gmm_cause: u8,
}

impl FiveGmmStatus {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self { gmm_cause: buf.get_u8() })
    }
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

impl UlNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.payload_container_type as u8 & 0x0F);
        self.payload_container.encode(buf);
        if let Some(psi) = self.pdu_session_id {
            buf.put_u8(0x12); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(psi);
        }
        if let Some(old_psi) = self.old_pdu_session_id {
            buf.put_u8(0x59); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(old_psi);
        }
        if let Some(ref rt) = self.request_type {
            buf.put_u8(0x80 | (*rt as u8 & 0x0F)); // IEI 8- (half-byte)
        }
        if let Some(ref snssai) = self.s_nssai {
            buf.put_u8(0x22); // IEI
            snssai.encode(buf);
        }
        if let Some(ref dnn) = self.dnn {
            buf.put_u8(0x25); // IEI
            dnn.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let pct_byte = buf.get_u8();
        let payload_container_type = match pct_byte & 0x0F {
            1 => PayloadContainerType::N1SmInformation,
            2 => PayloadContainerType::SmsContainer,
            3 => PayloadContainerType::LppMessage,
            4 => PayloadContainerType::SorTransparentContainer,
            5 => PayloadContainerType::UeParametersUpdateTransparentContainer,
            6 => PayloadContainerType::UePolicyContainer,
            7 => PayloadContainerType::UeParametersUpdateTransparentContainerForUeInitiated,
            8 => PayloadContainerType::MultiplePayloads,
            9 => PayloadContainerType::EventNotification,
            _ => PayloadContainerType::N1SmInformation,
        };
        let payload_container = PayloadContainer::decode(buf)?;
        let mut msg = Self { payload_container_type, payload_container, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0x12 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.old_pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x80 => {
                    buf.advance(1);
                    let rt = match iei & 0x0F {
                        1 => RequestType::InitialRequest,
                        2 => RequestType::ExistingPduSession,
                        3 => RequestType::InitialEmergencyRequest,
                        4 => RequestType::ExistingEmergencyPduSession,
                        5 => RequestType::ModificationRequest,
                        6 => RequestType::MaPduRequest,
                        _ => RequestType::InitialRequest,
                    };
                    msg.request_type = Some(rt);
                }
                0x22 => {
                    buf.advance(1);
                    msg.s_nssai = Some(SNssai::decode(buf)?);
                }
                0x25 => {
                    buf.advance(1);
                    msg.dnn = Some(Dnn::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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

impl DlNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.payload_container_type as u8 & 0x0F);
        self.payload_container.encode(buf);
        if let Some(psi) = self.pdu_session_id {
            buf.put_u8(0x12); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(psi);
        }
        if let Some(ref info) = self.additional_information {
            buf.put_u8(0x24); // IEI
            buf.put_u8(info.len() as u8);
            buf.put_slice(info);
        }
        if let Some(cause) = self.gmm_cause {
            buf.put_u8(0x58); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let pct_byte = buf.get_u8();
        let payload_container_type = match pct_byte & 0x0F {
            1 => PayloadContainerType::N1SmInformation,
            2 => PayloadContainerType::SmsContainer,
            3 => PayloadContainerType::LppMessage,
            4 => PayloadContainerType::SorTransparentContainer,
            5 => PayloadContainerType::UeParametersUpdateTransparentContainer,
            6 => PayloadContainerType::UePolicyContainer,
            7 => PayloadContainerType::UeParametersUpdateTransparentContainerForUeInitiated,
            8 => PayloadContainerType::MultiplePayloads,
            9 => PayloadContainerType::EventNotification,
            _ => PayloadContainerType::N1SmInformation,
        };
        let payload_container = PayloadContainer::decode(buf)?;
        let mut msg = Self { payload_container_type, payload_container, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x12 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x24 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.additional_information = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x58 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gmm_cause = Some(buf.get_u8());
                    }
                }
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
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
        FiveGmmMessage::RegistrationComplete(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationRequestFromUe(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationAcceptFromUe => {}
        FiveGmmMessage::DeregistrationRequestToUe(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationAcceptToUe => {}
        FiveGmmMessage::ServiceRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::ServiceAccept(m) => m.encode(&mut buf),
        FiveGmmMessage::ServiceReject(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationResponse(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationReject(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationFailure(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationResult(m) => m.encode(&mut buf),
        FiveGmmMessage::IdentityRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::IdentityResponse(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeCommand(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeComplete(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeReject(m) => m.encode(&mut buf),
        FiveGmmMessage::FiveGmmStatus(m) => m.encode(&mut buf),
        FiveGmmMessage::UlNasTransport(m) => m.encode(&mut buf),
        FiveGmmMessage::DlNasTransport(m) => m.encode(&mut buf),
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
        FiveGmmMessageType::RegistrationComplete => {
            Ok(FiveGmmMessage::RegistrationComplete(RegistrationComplete::decode(buf)?))
        }
        FiveGmmMessageType::DeregistrationRequestFromUe => {
            Ok(FiveGmmMessage::DeregistrationRequestFromUe(DeregistrationRequestFromUe::decode(buf)?))
        }
        FiveGmmMessageType::DeregistrationAcceptFromUe => {
            Ok(FiveGmmMessage::DeregistrationAcceptFromUe)
        }
        FiveGmmMessageType::DeregistrationRequestToUe => {
            Ok(FiveGmmMessage::DeregistrationRequestToUe(DeregistrationRequestToUe::decode(buf)?))
        }
        FiveGmmMessageType::DeregistrationAcceptToUe => {
            Ok(FiveGmmMessage::DeregistrationAcceptToUe)
        }
        FiveGmmMessageType::ServiceRequest => {
            Ok(FiveGmmMessage::ServiceRequest(ServiceRequest::decode(buf)?))
        }
        FiveGmmMessageType::ServiceAccept => {
            Ok(FiveGmmMessage::ServiceAccept(ServiceAccept::decode(buf)?))
        }
        FiveGmmMessageType::ServiceReject => {
            Ok(FiveGmmMessage::ServiceReject(ServiceReject::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationRequest => {
            Ok(FiveGmmMessage::AuthenticationRequest(AuthenticationRequest::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationResponse => {
            Ok(FiveGmmMessage::AuthenticationResponse(AuthenticationResponse::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationReject => {
            Ok(FiveGmmMessage::AuthenticationReject(AuthenticationReject::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationFailure => {
            Ok(FiveGmmMessage::AuthenticationFailure(AuthenticationFailure::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationResult => {
            Ok(FiveGmmMessage::AuthenticationResult(AuthenticationResult::decode(buf)?))
        }
        FiveGmmMessageType::IdentityRequest => {
            Ok(FiveGmmMessage::IdentityRequest(IdentityRequest::decode(buf)?))
        }
        FiveGmmMessageType::IdentityResponse => {
            Ok(FiveGmmMessage::IdentityResponse(IdentityResponse::decode(buf)?))
        }
        FiveGmmMessageType::SecurityModeCommand => {
            Ok(FiveGmmMessage::SecurityModeCommand(SecurityModeCommand::decode(buf)?))
        }
        FiveGmmMessageType::SecurityModeComplete => {
            Ok(FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::decode(buf)?))
        }
        FiveGmmMessageType::SecurityModeReject => {
            Ok(FiveGmmMessage::SecurityModeReject(SecurityModeReject::decode(buf)?))
        }
        FiveGmmMessageType::FiveGmmStatus => {
            Ok(FiveGmmMessage::FiveGmmStatus(FiveGmmStatus::decode(buf)?))
        }
        FiveGmmMessageType::UlNasTransport => {
            Ok(FiveGmmMessage::UlNasTransport(UlNasTransport::decode(buf)?))
        }
        FiveGmmMessageType::DlNasTransport => {
            Ok(FiveGmmMessage::DlNasTransport(DlNasTransport::decode(buf)?))
        }
        _ => Err(NasError::InvalidMessageType(header.message_type)),
    }
}

// =========================================================================
// 5GSM (5G Session Management) Messages - TS 24.501 Section 8.3
// =========================================================================

/// 5GSM message
#[derive(Debug, Clone, PartialEq)]
pub enum FiveGsmMessage {
    PduSessionEstablishmentRequest(PduSessionEstablishmentRequest),
    PduSessionEstablishmentAccept(PduSessionEstablishmentAccept),
    PduSessionEstablishmentReject(PduSessionEstablishmentReject),
    PduSessionModificationRequest(PduSessionModificationRequest),
    PduSessionModificationCommand(PduSessionModificationCommand),
    PduSessionModificationComplete,
    PduSessionModificationReject(PduSessionModificationReject),
    PduSessionModificationCommandReject(PduSessionModificationCommandReject),
    PduSessionReleaseRequest(PduSessionReleaseRequest),
    PduSessionReleaseReject(PduSessionReleaseReject),
    PduSessionReleaseCommand(PduSessionReleaseCommand),
    PduSessionReleaseComplete(PduSessionReleaseComplete),
    FiveGsmStatus(FiveGsmStatus),
}

/// PDU Session Establishment Request (TS 24.501 Section 8.3.1)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentRequest {
    /// Integrity protection maximum data rate
    pub integrity_protection_max_data_rate: [u8; 2],
    /// PDU session type
    pub pdu_session_type: Option<u8>,
    /// SSC mode
    pub ssc_mode: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
    /// SM PDU DN request container
    pub sm_pdu_dn_request_container: Option<Vec<u8>>,
}

impl PduSessionEstablishmentRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.integrity_protection_max_data_rate);
        if let Some(pst) = self.pdu_session_type {
            buf.put_u8(0x90 | (pst & 0x0F)); // IEI 9- (half-byte)
        }
        if let Some(ssc) = self.ssc_mode {
            buf.put_u8(0xA0 | (ssc & 0x0F)); // IEI A- (half-byte)
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let mut ipmdr = [0u8; 2];
        buf.copy_to_slice(&mut ipmdr);
        let mut msg = Self { integrity_protection_max_data_rate: ipmdr, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0x90 => {
                    buf.advance(1);
                    msg.pdu_session_type = Some(iei & 0x0F);
                }
                0xA0 => {
                    buf.advance(1);
                    msg.ssc_mode = Some(iei & 0x0F);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Establishment Accept (TS 24.501 Section 8.3.2)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentAccept {
    /// Selected PDU session type
    pub selected_pdu_session_type: u8,
    /// Selected SSC mode
    pub selected_ssc_mode: u8,
    /// Authorized QoS rules
    pub authorized_qos_rules: QosRules,
    /// Session AMBR
    pub session_ambr: SessionAmbr,
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// PDU address
    pub pdu_address: Option<PduAddress>,
    /// Authorized QoS flow descriptions
    pub authorized_qos_flow_descriptions: Option<QosFlowDescriptions>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
    /// DNN
    pub dnn: Option<Dnn>,
}

impl PduSessionEstablishmentAccept {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.selected_ssc_mode << 4) | (self.selected_pdu_session_type & 0x0F));
        self.authorized_qos_rules.encode(buf);
        self.session_ambr.encode(buf);
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref addr) = self.pdu_address {
            buf.put_u8(0x29); // IEI
            addr.encode(buf);
        }
        if let Some(ref qfd) = self.authorized_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
        if let Some(ref dnn) = self.dnn {
            buf.put_u8(0x25); // IEI
            dnn.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let type_byte = buf.get_u8();
        let selected_pdu_session_type = type_byte & 0x0F;
        let selected_ssc_mode = (type_byte >> 4) & 0x0F;
        let authorized_qos_rules = QosRules::decode(buf)?;
        let session_ambr = SessionAmbr::decode(buf)?;
        let mut msg = Self {
            selected_pdu_session_type,
            selected_ssc_mode,
            authorized_qos_rules,
            session_ambr,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x29 => {
                    buf.advance(1);
                    msg.pdu_address = Some(PduAddress::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.authorized_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x25 => {
                    buf.advance(1);
                    msg.dnn = Some(Dnn::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Establishment Reject (TS 24.501 Section 8.3.3)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionEstablishmentReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self { gsm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Request (TS 24.501 Section 8.3.7)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationRequest {
    /// Requested QoS rules
    pub requested_qos_rules: Option<QosRules>,
    /// Requested QoS flow descriptions
    pub requested_qos_flow_descriptions: Option<QosFlowDescriptions>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref qr) = self.requested_qos_rules {
            buf.put_u8(0x7A); // IEI
            qr.encode(buf);
        }
        if let Some(ref qfd) = self.requested_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7A => {
                    buf.advance(1);
                    msg.requested_qos_rules = Some(QosRules::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.requested_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Command (TS 24.501 Section 8.3.9)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationCommand {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Session AMBR
    pub session_ambr: Option<SessionAmbr>,
    /// Authorized QoS rules
    pub authorized_qos_rules: Option<QosRules>,
    /// Authorized QoS flow descriptions
    pub authorized_qos_flow_descriptions: Option<QosFlowDescriptions>,
}

impl PduSessionModificationCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref ambr) = self.session_ambr {
            buf.put_u8(0x2A); // IEI
            ambr.encode(buf);
        }
        if let Some(ref qr) = self.authorized_qos_rules {
            buf.put_u8(0x7A); // IEI
            qr.encode(buf);
        }
        if let Some(ref qfd) = self.authorized_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x2A => {
                    buf.advance(1);
                    msg.session_ambr = Some(SessionAmbr::decode(buf)?);
                }
                0x7A => {
                    buf.advance(1);
                    msg.authorized_qos_rules = Some(QosRules::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.authorized_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Reject (TS 24.501 Section 8.3.8)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self { gsm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Command Reject (TS 24.501 Section 8.3.10)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationCommandReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationCommandReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self { gsm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Request (TS 24.501 Section 8.3.12)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseRequest {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Reject (TS 24.501 Section 8.3.13)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self { gsm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Command (TS 24.501 Section 8.3.14)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseCommand {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self { gsm_cause, ..Default::default() };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Complete (TS 24.501 Section 8.3.15)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseComplete {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => {
                    buf.advance(1);
                    if buf.remaining() > 0 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len { buf.advance(len); }
                    }
                }
            }
        }
        Ok(msg)
    }
}

/// 5GSM Status message (TS 24.501 Section 8.3.16)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FiveGsmStatus {
    /// 5GSM cause
    pub gsm_cause: u8,
}

impl FiveGsmStatus {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self { gsm_cause: buf.get_u8() })
    }
}

/// Build a 5GSM message with header
pub fn build_5gsm_message(pdu_session_id: u8, pti: u8, msg: &FiveGsmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        FiveGsmMessage::PduSessionEstablishmentRequest(_) => FiveGsmMessageType::PduSessionEstablishmentRequest,
        FiveGsmMessage::PduSessionEstablishmentAccept(_) => FiveGsmMessageType::PduSessionEstablishmentAccept,
        FiveGsmMessage::PduSessionEstablishmentReject(_) => FiveGsmMessageType::PduSessionEstablishmentReject,
        FiveGsmMessage::PduSessionModificationRequest(_) => FiveGsmMessageType::PduSessionModificationRequest,
        FiveGsmMessage::PduSessionModificationCommand(_) => FiveGsmMessageType::PduSessionModificationCommand,
        FiveGsmMessage::PduSessionModificationComplete => FiveGsmMessageType::PduSessionModificationComplete,
        FiveGsmMessage::PduSessionModificationReject(_) => FiveGsmMessageType::PduSessionModificationReject,
        FiveGsmMessage::PduSessionModificationCommandReject(_) => FiveGsmMessageType::PduSessionModificationCommandReject,
        FiveGsmMessage::PduSessionReleaseRequest(_) => FiveGsmMessageType::PduSessionReleaseRequest,
        FiveGsmMessage::PduSessionReleaseReject(_) => FiveGsmMessageType::PduSessionReleaseReject,
        FiveGsmMessage::PduSessionReleaseCommand(_) => FiveGsmMessageType::PduSessionReleaseCommand,
        FiveGsmMessage::PduSessionReleaseComplete(_) => FiveGsmMessageType::PduSessionReleaseComplete,
        FiveGsmMessage::FiveGsmStatus(_) => FiveGsmMessageType::FiveGsmStatus,
    };

    let header = FiveGsNasHeader::new_gsm(pdu_session_id, pti, message_type);
    header.encode(&mut buf);

    match msg {
        FiveGsmMessage::PduSessionEstablishmentRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionEstablishmentAccept(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionEstablishmentReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationCommand(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationComplete => {}
        FiveGsmMessage::PduSessionModificationReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationCommandReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseCommand(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseComplete(m) => m.encode(&mut buf),
        FiveGsmMessage::FiveGsmStatus(m) => m.encode(&mut buf),
    }

    buf
}

/// Parse a 5GSM message
pub fn parse_5gsm_message(buf: &mut Bytes) -> NasResult<(u8, u8, FiveGsmMessage)> {
    let header = FiveGsNasSmHeader::decode(buf)?;
    let message_type = FiveGsmMessageType::try_from(header.message_type)?;

    let msg = match message_type {
        FiveGsmMessageType::PduSessionEstablishmentRequest => {
            FiveGsmMessage::PduSessionEstablishmentRequest(PduSessionEstablishmentRequest::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionEstablishmentAccept => {
            FiveGsmMessage::PduSessionEstablishmentAccept(PduSessionEstablishmentAccept::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionEstablishmentReject => {
            FiveGsmMessage::PduSessionEstablishmentReject(PduSessionEstablishmentReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionModificationRequest => {
            FiveGsmMessage::PduSessionModificationRequest(PduSessionModificationRequest::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionModificationCommand => {
            FiveGsmMessage::PduSessionModificationCommand(PduSessionModificationCommand::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionModificationComplete => {
            FiveGsmMessage::PduSessionModificationComplete
        }
        FiveGsmMessageType::PduSessionModificationReject => {
            FiveGsmMessage::PduSessionModificationReject(PduSessionModificationReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionModificationCommandReject => {
            FiveGsmMessage::PduSessionModificationCommandReject(PduSessionModificationCommandReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseRequest => {
            FiveGsmMessage::PduSessionReleaseRequest(PduSessionReleaseRequest::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseReject => {
            FiveGsmMessage::PduSessionReleaseReject(PduSessionReleaseReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseCommand => {
            FiveGsmMessage::PduSessionReleaseCommand(PduSessionReleaseCommand::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseComplete => {
            FiveGsmMessage::PduSessionReleaseComplete(PduSessionReleaseComplete::decode(buf)?)
        }
        FiveGsmMessageType::FiveGsmStatus => {
            FiveGsmMessage::FiveGsmStatus(FiveGsmStatus::decode(buf)?)
        }
        _ => return Err(NasError::InvalidMessageType(header.message_type)),
    };

    Ok((header.pdu_session_id, header.procedure_transaction_identity, msg))
}
