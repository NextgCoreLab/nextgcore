//! 5GS NAS message header
//!
//! Based on 3GPP TS 24.501

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::{ProtocolDiscriminator, SecurityHeaderType};

/// 5GS NAS header length (plain message)
pub const FIVEG_NAS_HEADER_LEN: usize = 2;

/// 5GS NAS security header length
pub const FIVEG_NAS_SECURITY_HEADER_LEN: usize = 7;

/// 5GMM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FiveGmmMessageType {
    RegistrationRequest = 0x41,
    RegistrationAccept = 0x42,
    RegistrationComplete = 0x43,
    RegistrationReject = 0x44,
    DeregistrationRequestFromUe = 0x45,
    DeregistrationAcceptFromUe = 0x46,
    DeregistrationRequestToUe = 0x47,
    DeregistrationAcceptToUe = 0x48,
    ServiceRequest = 0x4C,
    ServiceReject = 0x4D,
    ServiceAccept = 0x4E,
    ControlPlaneServiceRequest = 0x4F,
    ConfigurationUpdateCommand = 0x54,
    ConfigurationUpdateComplete = 0x55,
    AuthenticationRequest = 0x56,
    AuthenticationResponse = 0x57,
    AuthenticationReject = 0x58,
    AuthenticationFailure = 0x59,
    AuthenticationResult = 0x5A,
    IdentityRequest = 0x5B,
    IdentityResponse = 0x5C,
    SecurityModeCommand = 0x5D,
    SecurityModeComplete = 0x5E,
    SecurityModeReject = 0x5F,
    FiveGmmStatus = 0x64,
    Notification = 0x65,
    NotificationResponse = 0x66,
    UlNasTransport = 0x67,
    DlNasTransport = 0x68,
    NetworkSliceSpecificAuthenticationCommand = 0x69,
    NetworkSliceSpecificAuthenticationComplete = 0x6A,
    NetworkSliceSpecificAuthenticationResult = 0x6B,
}

impl TryFrom<u8> for FiveGmmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x41 => Ok(Self::RegistrationRequest),
            0x42 => Ok(Self::RegistrationAccept),
            0x43 => Ok(Self::RegistrationComplete),
            0x44 => Ok(Self::RegistrationReject),
            0x45 => Ok(Self::DeregistrationRequestFromUe),
            0x46 => Ok(Self::DeregistrationAcceptFromUe),
            0x47 => Ok(Self::DeregistrationRequestToUe),
            0x48 => Ok(Self::DeregistrationAcceptToUe),
            0x4C => Ok(Self::ServiceRequest),
            0x4D => Ok(Self::ServiceReject),
            0x4E => Ok(Self::ServiceAccept),
            0x4F => Ok(Self::ControlPlaneServiceRequest),
            0x54 => Ok(Self::ConfigurationUpdateCommand),
            0x55 => Ok(Self::ConfigurationUpdateComplete),
            0x56 => Ok(Self::AuthenticationRequest),
            0x57 => Ok(Self::AuthenticationResponse),
            0x58 => Ok(Self::AuthenticationReject),
            0x59 => Ok(Self::AuthenticationFailure),
            0x5A => Ok(Self::AuthenticationResult),
            0x5B => Ok(Self::IdentityRequest),
            0x5C => Ok(Self::IdentityResponse),
            0x5D => Ok(Self::SecurityModeCommand),
            0x5E => Ok(Self::SecurityModeComplete),
            0x5F => Ok(Self::SecurityModeReject),
            0x64 => Ok(Self::FiveGmmStatus),
            0x65 => Ok(Self::Notification),
            0x66 => Ok(Self::NotificationResponse),
            0x67 => Ok(Self::UlNasTransport),
            0x68 => Ok(Self::DlNasTransport),
            0x69 => Ok(Self::NetworkSliceSpecificAuthenticationCommand),
            0x6A => Ok(Self::NetworkSliceSpecificAuthenticationComplete),
            0x6B => Ok(Self::NetworkSliceSpecificAuthenticationResult),
            _ => Err(NasError::InvalidMessageType(value)),
        }
    }
}

/// 5GSM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FiveGsmMessageType {
    PduSessionEstablishmentRequest = 0xC1,
    PduSessionEstablishmentAccept = 0xC2,
    PduSessionEstablishmentReject = 0xC3,
    PduSessionAuthenticationCommand = 0xC5,
    PduSessionAuthenticationComplete = 0xC6,
    PduSessionAuthenticationResult = 0xC7,
    PduSessionModificationRequest = 0xC9,
    PduSessionModificationReject = 0xCA,
    PduSessionModificationCommand = 0xCB,
    PduSessionModificationComplete = 0xCC,
    PduSessionModificationCommandReject = 0xCD,
    PduSessionReleaseRequest = 0xD1,
    PduSessionReleaseReject = 0xD2,
    PduSessionReleaseCommand = 0xD3,
    PduSessionReleaseComplete = 0xD4,
    FiveGsmStatus = 0xD6,
    RemoteUeReport = 0xD9,
    RemoteUeReportResponse = 0xDA,
}

impl TryFrom<u8> for FiveGsmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xC1 => Ok(Self::PduSessionEstablishmentRequest),
            0xC2 => Ok(Self::PduSessionEstablishmentAccept),
            0xC3 => Ok(Self::PduSessionEstablishmentReject),
            0xC5 => Ok(Self::PduSessionAuthenticationCommand),
            0xC6 => Ok(Self::PduSessionAuthenticationComplete),
            0xC7 => Ok(Self::PduSessionAuthenticationResult),
            0xC9 => Ok(Self::PduSessionModificationRequest),
            0xCA => Ok(Self::PduSessionModificationReject),
            0xCB => Ok(Self::PduSessionModificationCommand),
            0xCC => Ok(Self::PduSessionModificationComplete),
            0xCD => Ok(Self::PduSessionModificationCommandReject),
            0xD1 => Ok(Self::PduSessionReleaseRequest),
            0xD2 => Ok(Self::PduSessionReleaseReject),
            0xD3 => Ok(Self::PduSessionReleaseCommand),
            0xD4 => Ok(Self::PduSessionReleaseComplete),
            0xD6 => Ok(Self::FiveGsmStatus),
            0xD9 => Ok(Self::RemoteUeReport),
            0xDA => Ok(Self::RemoteUeReportResponse),
            _ => Err(NasError::InvalidMessageType(value)),
        }
    }
}

/// 5GS NAS plain header (for 5GMM messages)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FiveGsNasHeader {
    /// Extended protocol discriminator
    pub extended_protocol_discriminator: u8,
    /// Security header type
    pub security_header_type: SecurityHeaderType,
    /// Message type
    pub message_type: u8,
}

impl FiveGsNasHeader {
    /// Create a new 5GMM header
    pub fn new_gmm(message_type: FiveGmmMessageType) -> Self {
        Self {
            extended_protocol_discriminator: ProtocolDiscriminator::FiveGsMobilityManagement as u8,
            security_header_type: SecurityHeaderType::PlainNas,
            message_type: message_type as u8,
        }
    }

    /// Create a new 5GSM header
    pub fn new_gsm(pdu_session_id: u8, pti: u8, message_type: FiveGsmMessageType) -> FiveGsNasSmHeader {
        FiveGsNasSmHeader {
            extended_protocol_discriminator: ProtocolDiscriminator::FiveGsSessionManagement as u8,
            pdu_session_id,
            procedure_transaction_identity: pti,
            message_type: message_type as u8,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.extended_protocol_discriminator);
        buf.put_u8(self.security_header_type as u8);
        buf.put_u8(self.message_type);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }

        let extended_protocol_discriminator = buf.get_u8();
        let security_header_type = SecurityHeaderType::try_from(buf.get_u8() & 0x0F)?;
        let message_type = buf.get_u8();

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_type,
        })
    }
}

/// 5GS NAS SM header (for 5GSM messages)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FiveGsNasSmHeader {
    /// Extended protocol discriminator
    pub extended_protocol_discriminator: u8,
    /// PDU session ID
    pub pdu_session_id: u8,
    /// Procedure transaction identity
    pub procedure_transaction_identity: u8,
    /// Message type
    pub message_type: u8,
}

impl FiveGsNasSmHeader {
    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.extended_protocol_discriminator);
        buf.put_u8(self.pdu_session_id);
        buf.put_u8(self.procedure_transaction_identity);
        buf.put_u8(self.message_type);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 4 {
            return Err(NasError::BufferTooShort { expected: 4, actual: buf.remaining() });
        }

        Ok(Self {
            extended_protocol_discriminator: buf.get_u8(),
            pdu_session_id: buf.get_u8(),
            procedure_transaction_identity: buf.get_u8(),
            message_type: buf.get_u8(),
        })
    }
}

/// 5GS NAS security header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FiveGsNasSecurityHeader {
    /// Extended protocol discriminator
    pub extended_protocol_discriminator: u8,
    /// Security header type
    pub security_header_type: SecurityHeaderType,
    /// Message authentication code
    pub message_authentication_code: [u8; 4],
    /// Sequence number
    pub sequence_number: u8,
}

impl FiveGsNasSecurityHeader {
    /// Encode security header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.extended_protocol_discriminator);
        buf.put_u8(self.security_header_type as u8);
        buf.put_slice(&self.message_authentication_code);
        buf.put_u8(self.sequence_number);
    }

    /// Decode security header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < FIVEG_NAS_SECURITY_HEADER_LEN {
            return Err(NasError::BufferTooShort {
                expected: FIVEG_NAS_SECURITY_HEADER_LEN,
                actual: buf.remaining(),
            });
        }

        let extended_protocol_discriminator = buf.get_u8();
        let security_header_type = SecurityHeaderType::try_from(buf.get_u8() & 0x0F)?;
        let mut message_authentication_code = [0u8; 4];
        buf.copy_to_slice(&mut message_authentication_code);
        let sequence_number = buf.get_u8();

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_authentication_code,
            sequence_number,
        })
    }
}
