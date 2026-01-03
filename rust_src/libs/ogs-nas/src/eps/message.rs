//! EPS NAS messages
//!
//! Based on 3GPP TS 24.301

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::*;
use super::types::*;
use super::header::*;

/// EMM message
#[derive(Debug, Clone, PartialEq)]
pub enum EmmMessage {
    AttachRequest(AttachRequest),
    AttachAccept(AttachAccept),
    AttachComplete(AttachComplete),
    AttachReject(AttachReject),
    DetachRequest(DetachRequest),
    DetachAccept,
    TrackingAreaUpdateRequest(TrackingAreaUpdateRequest),
    TrackingAreaUpdateAccept(TrackingAreaUpdateAccept),
    TrackingAreaUpdateReject(TrackingAreaUpdateReject),
    AuthenticationRequest(EpsAuthenticationRequest),
    AuthenticationResponse(EpsAuthenticationResponse),
    AuthenticationReject,
    AuthenticationFailure(EpsAuthenticationFailure),
    SecurityModeCommand(EpsSecurityModeCommand),
    SecurityModeComplete(EpsSecurityModeComplete),
    SecurityModeReject(EpsSecurityModeReject),
    IdentityRequest(EpsIdentityRequest),
    IdentityResponse(EpsIdentityResponse),
    EmmStatus(EmmStatus),
}

/// Attach Request message (TS 24.301 Section 8.2.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachRequest {
    /// EPS attach type
    pub eps_attach_type: EpsAttachType,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// EPS mobile identity
    pub eps_mobile_identity: EpsMobileIdentity,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
    /// Presence mask
    pub presencemask: u64,
    /// Old P-TMSI signature
    pub old_p_tmsi_signature: Option<[u8; 3]>,
    /// Additional GUTI
    pub additional_guti: Option<EpsMobileIdentity>,
    /// Last visited registered TAI
    pub last_visited_tai: Option<EpsTai>,
    /// DRX parameter
    pub drx_parameter: Option<[u8; 2]>,
}

impl AttachRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // EPS attach type + NAS key set identifier (1 byte)
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | self.eps_attach_type.encode());
        // EPS mobile identity
        self.eps_mobile_identity.encode(buf);
        // UE network capability
        self.ue_network_capability.encode(buf);
        // ESM message container
        self.esm_message_container.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }

        let first_byte = buf.get_u8();
        let eps_attach_type = EpsAttachType::decode(first_byte & 0x0F);
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let eps_mobile_identity = EpsMobileIdentity::decode(buf)?;
        let ue_network_capability = UeNetworkCapability::decode(buf)?;
        let esm_message_container = EsmMessageContainer::decode(buf)?;

        Ok(Self {
            eps_attach_type,
            nas_key_set_identifier,
            eps_mobile_identity,
            ue_network_capability,
            esm_message_container,
            ..Default::default()
        })
    }
}

/// Attach Accept message (TS 24.301 Section 8.2.1)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachAccept {
    /// EPS attach result
    pub eps_attach_result: EpsAttachResult,
    /// T3412 value
    pub t3412_value: GprsTimer,
    /// TAI list
    pub tai_list: EpsTaiList,
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
    /// Presence mask
    pub presencemask: u64,
    /// GUTI
    pub guti: Option<EpsMobileIdentity>,
    /// Location area identification
    pub lai: Option<Vec<u8>>,
    /// MS identity
    pub ms_identity: Option<Vec<u8>>,
    /// EMM cause
    pub emm_cause: Option<u8>,
    /// T3402 value
    pub t3402_value: Option<GprsTimer>,
    /// T3423 value
    pub t3423_value: Option<GprsTimer>,
    /// Equivalent PLMNs
    pub equivalent_plmns: Option<Vec<PlmnId>>,
}

impl AttachAccept {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_attach_result.encode());
        buf.put_u8(self.t3412_value.encode());
        self.tai_list.encode(buf);
        self.esm_message_container.encode(buf);
        // Optional IEs
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x50); // IEI
            guti.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }

        let eps_attach_result = EpsAttachResult::decode(buf.get_u8());
        let t3412_value = GprsTimer::decode(buf.get_u8());
        let tai_list = EpsTaiList::decode(buf)?;
        let esm_message_container = EsmMessageContainer::decode(buf)?;

        let mut msg = Self {
            eps_attach_result,
            t3412_value,
            tai_list,
            esm_message_container,
            ..Default::default()
        };

        // Decode optional IEs
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.guti = Some(EpsMobileIdentity::decode(buf)?);
                }
                0x53 => {
                    buf.advance(1);
                    msg.emm_cause = Some(buf.get_u8());
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

/// Attach Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachComplete {
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
}

/// Attach Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachReject {
    /// EMM cause
    pub emm_cause: u8,
    /// ESM message container
    pub esm_message_container: Option<EsmMessageContainer>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// T3402 value
    pub t3402_value: Option<GprsTimer2>,
}

/// Detach Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DetachRequest {
    /// Detach type
    pub detach_type: u8,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// EPS mobile identity
    pub eps_mobile_identity: EpsMobileIdentity,
}

/// Tracking Area Update Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateRequest {
    /// EPS update type
    pub eps_update_type: u8,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Old GUTI
    pub old_guti: EpsMobileIdentity,
    /// Presence mask
    pub presencemask: u64,
}

/// Tracking Area Update Accept message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateAccept {
    /// EPS update result
    pub eps_update_result: u8,
    /// Presence mask
    pub presencemask: u64,
    /// T3412 value
    pub t3412_value: Option<GprsTimer>,
    /// GUTI
    pub guti: Option<EpsMobileIdentity>,
    /// TAI list
    pub tai_list: Option<EpsTaiList>,
}

/// Tracking Area Update Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateReject {
    /// EMM cause
    pub emm_cause: u8,
}

/// EPS Authentication Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationRequest {
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Authentication parameter RAND
    pub rand: AuthenticationRand,
    /// Authentication parameter AUTN
    pub autn: AuthenticationAutn,
}

/// EPS Authentication Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationResponse {
    /// Authentication response parameter
    pub authentication_response_parameter: AuthenticationResponseParameter,
}

/// EPS Authentication Failure message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationFailure {
    /// EMM cause
    pub emm_cause: u8,
    /// Authentication failure parameter
    pub authentication_failure_parameter: Option<Vec<u8>>,
}

/// EPS Security Mode Command message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeCommand {
    /// Selected NAS security algorithms
    pub selected_nas_security_algorithms: SecurityAlgorithms,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Replayed UE security capabilities
    pub replayed_ue_security_capabilities: UeNetworkCapability,
    /// IMEISV request
    pub imeisv_request: Option<u8>,
    /// Replayed nonceUE
    pub replayed_nonce_ue: Option<[u8; 4]>,
    /// NonceMME
    pub nonce_mme: Option<[u8; 4]>,
}

/// EPS Security Mode Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeComplete {
    /// IMEISV
    pub imeisv: Option<Vec<u8>>,
}

/// EPS Security Mode Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeReject {
    /// EMM cause
    pub emm_cause: u8,
}

/// EPS Identity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsIdentityRequest {
    /// Identity type
    pub identity_type: u8,
}

/// EPS Identity Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsIdentityResponse {
    /// Mobile identity
    pub mobile_identity: EpsMobileIdentity,
}

/// EMM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmmStatus {
    /// EMM cause
    pub emm_cause: u8,
}

/// Build an EMM message with header
pub fn build_emm_message(msg: &EmmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        EmmMessage::AttachRequest(_) => EmmMessageType::AttachRequest,
        EmmMessage::AttachAccept(_) => EmmMessageType::AttachAccept,
        EmmMessage::AttachComplete(_) => EmmMessageType::AttachComplete,
        EmmMessage::AttachReject(_) => EmmMessageType::AttachReject,
        EmmMessage::DetachRequest(_) => EmmMessageType::DetachRequest,
        EmmMessage::DetachAccept => EmmMessageType::DetachAccept,
        EmmMessage::TrackingAreaUpdateRequest(_) => EmmMessageType::TrackingAreaUpdateRequest,
        EmmMessage::TrackingAreaUpdateAccept(_) => EmmMessageType::TrackingAreaUpdateAccept,
        EmmMessage::TrackingAreaUpdateReject(_) => EmmMessageType::TrackingAreaUpdateReject,
        EmmMessage::AuthenticationRequest(_) => EmmMessageType::AuthenticationRequest,
        EmmMessage::AuthenticationResponse(_) => EmmMessageType::AuthenticationResponse,
        EmmMessage::AuthenticationReject => EmmMessageType::AuthenticationReject,
        EmmMessage::AuthenticationFailure(_) => EmmMessageType::AuthenticationFailure,
        EmmMessage::SecurityModeCommand(_) => EmmMessageType::SecurityModeCommand,
        EmmMessage::SecurityModeComplete(_) => EmmMessageType::SecurityModeComplete,
        EmmMessage::SecurityModeReject(_) => EmmMessageType::SecurityModeReject,
        EmmMessage::IdentityRequest(_) => EmmMessageType::IdentityRequest,
        EmmMessage::IdentityResponse(_) => EmmMessageType::IdentityResponse,
        EmmMessage::EmmStatus(_) => EmmMessageType::EmmStatus,
    };

    // Encode header
    let header = EpsNasEmmHeader::new(message_type);
    header.encode(&mut buf);

    // Encode message body
    match msg {
        EmmMessage::AttachRequest(m) => m.encode(&mut buf),
        EmmMessage::AttachAccept(m) => m.encode(&mut buf),
        _ => {} // Other messages would be encoded here
    }

    buf
}

/// Parse an EMM message
pub fn parse_emm_message(buf: &mut Bytes) -> NasResult<EmmMessage> {
    let header = EpsNasEmmHeader::decode(buf)?;
    let message_type = EmmMessageType::try_from(header.message_type)?;

    match message_type {
        EmmMessageType::AttachRequest => {
            Ok(EmmMessage::AttachRequest(AttachRequest::decode(buf)?))
        }
        EmmMessageType::AttachAccept => {
            Ok(EmmMessage::AttachAccept(AttachAccept::decode(buf)?))
        }
        _ => Err(NasError::InvalidMessageType(header.message_type)),
    }
}
