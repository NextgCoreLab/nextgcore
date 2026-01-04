//! EPS NAS message header
//!
//! Based on 3GPP TS 24.301

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::SecurityHeaderType;

/// EPS NAS header length (plain EMM message)
pub const EPS_NAS_EMM_HEADER_LEN: usize = 2;

/// EPS NAS header length (ESM message)
pub const EPS_NAS_ESM_HEADER_LEN: usize = 3;

/// EPS NAS security header length
pub const EPS_NAS_SECURITY_HEADER_LEN: usize = 6;

/// EMM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmmMessageType {
    AttachRequest = 0x41,
    AttachAccept = 0x42,
    AttachComplete = 0x43,
    AttachReject = 0x44,
    DetachRequest = 0x45,
    DetachAccept = 0x46,
    TrackingAreaUpdateRequest = 0x48,
    TrackingAreaUpdateAccept = 0x49,
    TrackingAreaUpdateComplete = 0x4A,
    TrackingAreaUpdateReject = 0x4B,
    ExtendedServiceRequest = 0x4C,
    ServiceReject = 0x4E,
    GutiReallocationCommand = 0x50,
    GutiReallocationComplete = 0x51,
    AuthenticationRequest = 0x52,
    AuthenticationResponse = 0x53,
    AuthenticationReject = 0x54,
    IdentityRequest = 0x55,
    IdentityResponse = 0x56,
    AuthenticationFailure = 0x5C,
    SecurityModeCommand = 0x5D,
    SecurityModeComplete = 0x5E,
    SecurityModeReject = 0x5F,
    EmmStatus = 0x60,
    EmmInformation = 0x61,
    DownlinkNasTransport = 0x62,
    UplinkNasTransport = 0x63,
    CsServiceNotification = 0x64,
}

impl TryFrom<u8> for EmmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x41 => Ok(Self::AttachRequest),
            0x42 => Ok(Self::AttachAccept),
            0x43 => Ok(Self::AttachComplete),
            0x44 => Ok(Self::AttachReject),
            0x45 => Ok(Self::DetachRequest),
            0x46 => Ok(Self::DetachAccept),
            0x48 => Ok(Self::TrackingAreaUpdateRequest),
            0x49 => Ok(Self::TrackingAreaUpdateAccept),
            0x4A => Ok(Self::TrackingAreaUpdateComplete),
            0x4B => Ok(Self::TrackingAreaUpdateReject),
            0x4C => Ok(Self::ExtendedServiceRequest),
            0x4E => Ok(Self::ServiceReject),
            0x50 => Ok(Self::GutiReallocationCommand),
            0x51 => Ok(Self::GutiReallocationComplete),
            0x52 => Ok(Self::AuthenticationRequest),
            0x53 => Ok(Self::AuthenticationResponse),
            0x54 => Ok(Self::AuthenticationReject),
            0x55 => Ok(Self::IdentityRequest),
            0x56 => Ok(Self::IdentityResponse),
            0x5C => Ok(Self::AuthenticationFailure),
            0x5D => Ok(Self::SecurityModeCommand),
            0x5E => Ok(Self::SecurityModeComplete),
            0x5F => Ok(Self::SecurityModeReject),
            0x60 => Ok(Self::EmmStatus),
            0x61 => Ok(Self::EmmInformation),
            0x62 => Ok(Self::DownlinkNasTransport),
            0x63 => Ok(Self::UplinkNasTransport),
            0x64 => Ok(Self::CsServiceNotification),
            _ => Err(NasError::InvalidMessageType(value)),
        }
    }
}

/// ESM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EsmMessageType {
    ActivateDefaultEpsBearerContextRequest = 0xC1,
    ActivateDefaultEpsBearerContextAccept = 0xC2,
    ActivateDefaultEpsBearerContextReject = 0xC3,
    ActivateDedicatedEpsBearerContextRequest = 0xC5,
    ActivateDedicatedEpsBearerContextAccept = 0xC6,
    ActivateDedicatedEpsBearerContextReject = 0xC7,
    ModifyEpsBearerContextRequest = 0xC9,
    ModifyEpsBearerContextAccept = 0xCA,
    ModifyEpsBearerContextReject = 0xCB,
    DeactivateEpsBearerContextRequest = 0xCD,
    DeactivateEpsBearerContextAccept = 0xCE,
    PdnConnectivityRequest = 0xD0,
    PdnConnectivityReject = 0xD1,
    PdnDisconnectRequest = 0xD2,
    PdnDisconnectReject = 0xD3,
    BearerResourceAllocationRequest = 0xD4,
    BearerResourceAllocationReject = 0xD5,
    BearerResourceModificationRequest = 0xD6,
    BearerResourceModificationReject = 0xD7,
    EsmInformationRequest = 0xD9,
    EsmInformationResponse = 0xDA,
    EsmStatus = 0xE8,
}

impl TryFrom<u8> for EsmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xC1 => Ok(Self::ActivateDefaultEpsBearerContextRequest),
            0xC2 => Ok(Self::ActivateDefaultEpsBearerContextAccept),
            0xC3 => Ok(Self::ActivateDefaultEpsBearerContextReject),
            0xC5 => Ok(Self::ActivateDedicatedEpsBearerContextRequest),
            0xC6 => Ok(Self::ActivateDedicatedEpsBearerContextAccept),
            0xC7 => Ok(Self::ActivateDedicatedEpsBearerContextReject),
            0xC9 => Ok(Self::ModifyEpsBearerContextRequest),
            0xCA => Ok(Self::ModifyEpsBearerContextAccept),
            0xCB => Ok(Self::ModifyEpsBearerContextReject),
            0xCD => Ok(Self::DeactivateEpsBearerContextRequest),
            0xCE => Ok(Self::DeactivateEpsBearerContextAccept),
            0xD0 => Ok(Self::PdnConnectivityRequest),
            0xD1 => Ok(Self::PdnConnectivityReject),
            0xD2 => Ok(Self::PdnDisconnectRequest),
            0xD3 => Ok(Self::PdnDisconnectReject),
            0xD4 => Ok(Self::BearerResourceAllocationRequest),
            0xD5 => Ok(Self::BearerResourceAllocationReject),
            0xD6 => Ok(Self::BearerResourceModificationRequest),
            0xD7 => Ok(Self::BearerResourceModificationReject),
            0xD9 => Ok(Self::EsmInformationRequest),
            0xDA => Ok(Self::EsmInformationResponse),
            0xE8 => Ok(Self::EsmStatus),
            _ => Err(NasError::InvalidMessageType(value)),
        }
    }
}

/// EPS NAS EMM header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsNasEmmHeader {
    /// Security header type
    pub security_header_type: SecurityHeaderType,
    /// Protocol discriminator (always 0x07 for EMM)
    pub protocol_discriminator: u8,
    /// Message type
    pub message_type: u8,
}

impl EpsNasEmmHeader {
    /// Create a new EMM header
    pub fn new(message_type: EmmMessageType) -> Self {
        Self {
            security_header_type: SecurityHeaderType::PlainNas,
            protocol_discriminator: 0x07,
            message_type: message_type as u8,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(((self.security_header_type as u8) << 4) | (self.protocol_discriminator & 0x0F));
        buf.put_u8(self.message_type);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }

        let first_byte = buf.get_u8();
        let security_header_type = SecurityHeaderType::try_from((first_byte >> 4) & 0x0F)?;
        let protocol_discriminator = first_byte & 0x0F;
        let message_type = buf.get_u8();

        Ok(Self {
            security_header_type,
            protocol_discriminator,
            message_type,
        })
    }
}

/// EPS NAS ESM header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsNasEsmHeader {
    /// EPS bearer identity
    pub eps_bearer_identity: u8,
    /// Protocol discriminator (always 0x02 for ESM)
    pub protocol_discriminator: u8,
    /// Procedure transaction identity
    pub procedure_transaction_identity: u8,
    /// Message type
    pub message_type: u8,
}

impl EpsNasEsmHeader {
    /// Create a new ESM header
    pub fn new(eps_bearer_identity: u8, pti: u8, message_type: EsmMessageType) -> Self {
        Self {
            eps_bearer_identity,
            protocol_discriminator: 0x02,
            procedure_transaction_identity: pti,
            message_type: message_type as u8,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(((self.eps_bearer_identity & 0x0F) << 4) | (self.protocol_discriminator & 0x0F));
        buf.put_u8(self.procedure_transaction_identity);
        buf.put_u8(self.message_type);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }

        let first_byte = buf.get_u8();
        let eps_bearer_identity = (first_byte >> 4) & 0x0F;
        let protocol_discriminator = first_byte & 0x0F;
        let procedure_transaction_identity = buf.get_u8();
        let message_type = buf.get_u8();

        Ok(Self {
            eps_bearer_identity,
            protocol_discriminator,
            procedure_transaction_identity,
            message_type,
        })
    }
}

/// EPS NAS security header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsNasSecurityHeader {
    /// Security header type
    pub security_header_type: SecurityHeaderType,
    /// Protocol discriminator
    pub protocol_discriminator: u8,
    /// Message authentication code
    pub message_authentication_code: [u8; 4],
    /// Sequence number
    pub sequence_number: u8,
}

impl EpsNasSecurityHeader {
    /// Encode security header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(((self.security_header_type as u8) << 4) | (self.protocol_discriminator & 0x0F));
        buf.put_slice(&self.message_authentication_code);
        buf.put_u8(self.sequence_number);
    }

    /// Decode security header from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < EPS_NAS_SECURITY_HEADER_LEN {
            return Err(NasError::BufferTooShort {
                expected: EPS_NAS_SECURITY_HEADER_LEN,
                actual: buf.remaining(),
            });
        }

        let first_byte = buf.get_u8();
        let security_header_type = SecurityHeaderType::try_from((first_byte >> 4) & 0x0F)?;
        let protocol_discriminator = first_byte & 0x0F;
        let mut message_authentication_code = [0u8; 4];
        buf.copy_to_slice(&mut message_authentication_code);
        let sequence_number = buf.get_u8();

        Ok(Self {
            security_header_type,
            protocol_discriminator,
            message_authentication_code,
            sequence_number,
        })
    }
}
