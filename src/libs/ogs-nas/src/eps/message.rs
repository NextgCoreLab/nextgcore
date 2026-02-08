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

impl AttachComplete {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.esm_message_container.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let esm_message_container = EsmMessageContainer::decode(buf)?;
        Ok(Self { esm_message_container })
    }
}

impl AttachReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
        if let Some(ref esm) = self.esm_message_container {
            buf.put_u8(0x78); // IEI
            esm.encode(buf);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
        if let Some(ref t3402) = self.t3402_value {
            buf.put_u8(0x16); // IEI
            t3402.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let emm_cause = buf.get_u8();
        let mut msg = Self {
            emm_cause,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x78 => {
                    buf.advance(1);
                    msg.esm_message_container = Some(EsmMessageContainer::decode(buf)?);
                }
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                0x16 => {
                    buf.advance(1);
                    msg.t3402_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => break,
            }
        }

        Ok(msg)
    }
}

impl DetachRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | (self.detach_type & 0x07));
        self.eps_mobile_identity.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let first_byte = buf.get_u8();
        let detach_type = first_byte & 0x0F;
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let eps_mobile_identity = EpsMobileIdentity::decode(buf)?;
        Ok(Self {
            detach_type,
            nas_key_set_identifier,
            eps_mobile_identity,
        })
    }
}

impl TrackingAreaUpdateRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | (self.eps_update_type & 0x0F));
        self.old_guti.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let first_byte = buf.get_u8();
        let eps_update_type = first_byte & 0x0F;
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let old_guti = EpsMobileIdentity::decode(buf)?;
        Ok(Self {
            eps_update_type,
            nas_key_set_identifier,
            old_guti,
            ..Default::default()
        })
    }
}

impl TrackingAreaUpdateAccept {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_update_result & 0x07);
        // Optional IEs
        if let Some(t3412) = self.t3412_value {
            buf.put_u8(0x5A); // IEI
            buf.put_u8(t3412.encode());
        }
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x50); // IEI
            guti.encode(buf);
        }
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let eps_update_result = buf.get_u8() & 0x07;
        let mut msg = Self {
            eps_update_result,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x5A => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.t3412_value = Some(GprsTimer::decode(buf.get_u8()));
                    }
                }
                0x50 => {
                    buf.advance(1);
                    msg.guti = Some(EpsMobileIdentity::decode(buf)?);
                }
                0x54 => {
                    buf.advance(1);
                    msg.tai_list = Some(EpsTaiList::decode(buf)?);
                }
                _ => break,
            }
        }

        Ok(msg)
    }
}

impl TrackingAreaUpdateReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self {
            emm_cause: buf.get_u8(),
        })
    }
}

impl EpsAuthenticationRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nas_key_set_identifier.encode());
        // Spare half octet
        buf.put_slice(&self.rand);
        // AUTN with length
        buf.put_u8(16);
        buf.put_slice(&self.autn);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 34 {
            return Err(NasError::BufferTooShort { expected: 34, actual: buf.remaining() });
        }
        let nas_key_set_identifier = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let mut rand = [0u8; 16];
        buf.copy_to_slice(&mut rand);
        let _autn_len = buf.get_u8();
        let mut autn = [0u8; 16];
        buf.copy_to_slice(&mut autn);
        Ok(Self {
            nas_key_set_identifier,
            rand,
            autn,
        })
    }
}

impl EpsAuthenticationResponse {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.authentication_response_parameter.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let authentication_response_parameter = AuthenticationResponseParameter::decode(buf)?;
        Ok(Self {
            authentication_response_parameter,
        })
    }
}

impl EpsAuthenticationFailure {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
        if let Some(ref param) = self.authentication_failure_parameter {
            buf.put_u8(0x30); // IEI
            buf.put_u8(param.len() as u8);
            buf.put_slice(param);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let emm_cause = buf.get_u8();
        let mut msg = Self {
            emm_cause,
            ..Default::default()
        };

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
                _ => break,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeCommand {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.selected_nas_security_algorithms.encode());
        buf.put_u8(self.nas_key_set_identifier.encode());
        self.replayed_ue_security_capabilities.encode(buf);
        // Optional IEs
        if let Some(imeisv_req) = self.imeisv_request {
            buf.put_u8(0xC0 | (imeisv_req & 0x0F)); // Type 1 IE
        }
        if let Some(ref nonce) = self.replayed_nonce_ue {
            buf.put_u8(0x55); // IEI
            buf.put_u8(4); // Length
            buf.put_slice(nonce);
        }
        if let Some(ref nonce) = self.nonce_mme {
            buf.put_u8(0x56); // IEI
            buf.put_u8(4); // Length
            buf.put_slice(nonce);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let selected_nas_security_algorithms = SecurityAlgorithms::decode(buf.get_u8());
        let nas_key_set_identifier = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let replayed_ue_security_capabilities = UeNetworkCapability::decode(buf)?;

        let mut msg = Self {
            selected_nas_security_algorithms,
            nas_key_set_identifier,
            replayed_ue_security_capabilities,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0xC0..=0xCF => {
                    msg.imeisv_request = Some(buf.get_u8() & 0x0F);
                }
                0x55 => {
                    buf.advance(1);
                    if buf.remaining() >= 5 {
                        let _len = buf.get_u8();
                        let mut nonce = [0u8; 4];
                        buf.copy_to_slice(&mut nonce);
                        msg.replayed_nonce_ue = Some(nonce);
                    }
                }
                0x56 => {
                    buf.advance(1);
                    if buf.remaining() >= 5 {
                        let _len = buf.get_u8();
                        let mut nonce = [0u8; 4];
                        buf.copy_to_slice(&mut nonce);
                        msg.nonce_mme = Some(nonce);
                    }
                }
                _ => break,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeComplete {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref imeisv) = self.imeisv {
            buf.put_u8(0x23); // IEI
            buf.put_u8(imeisv.len() as u8);
            buf.put_slice(imeisv);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x23 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.imeisv = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => break,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self {
            emm_cause: buf.get_u8(),
        })
    }
}

impl EpsIdentityRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.identity_type & 0x07);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self {
            identity_type: buf.get_u8() & 0x07,
        })
    }
}

impl EpsIdentityResponse {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.mobile_identity.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mobile_identity = EpsMobileIdentity::decode(buf)?;
        Ok(Self { mobile_identity })
    }
}

impl EmmStatus {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        Ok(Self {
            emm_cause: buf.get_u8(),
        })
    }
}

/// ESM message
#[derive(Debug, Clone, PartialEq)]
pub enum EsmMessage {
    ActivateDefaultEpsBearerContextRequest(ActivateDefaultEpsBearerContextRequest),
    ActivateDefaultEpsBearerContextAccept,
    ActivateDefaultEpsBearerContextReject(ActivateDefaultEpsBearerContextReject),
    PdnConnectivityRequest(PdnConnectivityRequest),
    PdnConnectivityReject(PdnConnectivityReject),
    PdnDisconnectRequest(PdnDisconnectRequest),
    PdnDisconnectReject(PdnDisconnectReject),
    BearerResourceAllocationRequest(BearerResourceAllocationRequest),
    BearerResourceAllocationReject(BearerResourceAllocationReject),
    BearerResourceModificationRequest(BearerResourceModificationRequest),
    BearerResourceModificationReject(BearerResourceModificationReject),
    EsmInformationRequest,
    EsmInformationResponse(EsmInformationResponse),
    EsmStatus(EsmStatus),
}

/// PDN Connectivity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnConnectivityRequest {
    /// Request type
    pub request_type: u8,
    /// PDN type
    pub pdn_type: u8,
    /// EPS bearer identity
    pub eps_bearer_identity: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Connectivity Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnConnectivityReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Disconnect Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnDisconnectRequest {
    /// Linked EPS bearer identity
    pub linked_eps_bearer_identity: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Disconnect Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnDisconnectReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Activate Default EPS Bearer Context Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDefaultEpsBearerContextRequest {
    /// EPS QoS
    pub eps_qos: Vec<u8>,
    /// Access Point Name
    pub access_point_name: Vec<u8>,
    /// PDN address
    pub pdn_address: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Activate Default EPS Bearer Context Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDefaultEpsBearerContextReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Allocation Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceAllocationRequest {
    /// Linked EPS bearer identity
    pub linked_eps_bearer_identity: u8,
    /// Traffic flow aggregate
    pub traffic_flow_aggregate: Vec<u8>,
    /// Required traffic flow QoS
    pub required_traffic_flow_qos: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Allocation Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceAllocationReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Modification Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceModificationRequest {
    /// EPS bearer identity for packet filter
    pub eps_bearer_identity: u8,
    /// Traffic flow aggregate
    pub traffic_flow_aggregate: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Modification Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceModificationReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// ESM Information Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EsmInformationResponse {
    /// Access Point Name
    pub access_point_name: Option<Vec<u8>>,
    /// Protocol configuration options
    pub protocol_configuration_options: Option<Vec<u8>>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// ESM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EsmStatus {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
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
        EmmMessage::AttachComplete(m) => m.encode(&mut buf),
        EmmMessage::AttachReject(m) => m.encode(&mut buf),
        EmmMessage::DetachRequest(m) => m.encode(&mut buf),
        EmmMessage::DetachAccept => {},
        EmmMessage::TrackingAreaUpdateRequest(m) => m.encode(&mut buf),
        EmmMessage::TrackingAreaUpdateAccept(m) => m.encode(&mut buf),
        EmmMessage::TrackingAreaUpdateReject(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationRequest(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationResponse(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationReject => {},
        EmmMessage::AuthenticationFailure(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeCommand(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeComplete(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeReject(m) => m.encode(&mut buf),
        EmmMessage::IdentityRequest(m) => m.encode(&mut buf),
        EmmMessage::IdentityResponse(m) => m.encode(&mut buf),
        EmmMessage::EmmStatus(m) => m.encode(&mut buf),
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
        EmmMessageType::AttachComplete => {
            Ok(EmmMessage::AttachComplete(AttachComplete::decode(buf)?))
        }
        EmmMessageType::AttachReject => {
            Ok(EmmMessage::AttachReject(AttachReject::decode(buf)?))
        }
        EmmMessageType::DetachRequest => {
            Ok(EmmMessage::DetachRequest(DetachRequest::decode(buf)?))
        }
        EmmMessageType::DetachAccept => {
            Ok(EmmMessage::DetachAccept)
        }
        EmmMessageType::TrackingAreaUpdateRequest => {
            Ok(EmmMessage::TrackingAreaUpdateRequest(TrackingAreaUpdateRequest::decode(buf)?))
        }
        EmmMessageType::TrackingAreaUpdateAccept => {
            Ok(EmmMessage::TrackingAreaUpdateAccept(TrackingAreaUpdateAccept::decode(buf)?))
        }
        EmmMessageType::TrackingAreaUpdateReject => {
            Ok(EmmMessage::TrackingAreaUpdateReject(TrackingAreaUpdateReject::decode(buf)?))
        }
        EmmMessageType::AuthenticationRequest => {
            Ok(EmmMessage::AuthenticationRequest(EpsAuthenticationRequest::decode(buf)?))
        }
        EmmMessageType::AuthenticationResponse => {
            Ok(EmmMessage::AuthenticationResponse(EpsAuthenticationResponse::decode(buf)?))
        }
        EmmMessageType::AuthenticationReject => {
            Ok(EmmMessage::AuthenticationReject)
        }
        EmmMessageType::AuthenticationFailure => {
            Ok(EmmMessage::AuthenticationFailure(EpsAuthenticationFailure::decode(buf)?))
        }
        EmmMessageType::SecurityModeCommand => {
            Ok(EmmMessage::SecurityModeCommand(EpsSecurityModeCommand::decode(buf)?))
        }
        EmmMessageType::SecurityModeComplete => {
            Ok(EmmMessage::SecurityModeComplete(EpsSecurityModeComplete::decode(buf)?))
        }
        EmmMessageType::SecurityModeReject => {
            Ok(EmmMessage::SecurityModeReject(EpsSecurityModeReject::decode(buf)?))
        }
        EmmMessageType::IdentityRequest => {
            Ok(EmmMessage::IdentityRequest(EpsIdentityRequest::decode(buf)?))
        }
        EmmMessageType::IdentityResponse => {
            Ok(EmmMessage::IdentityResponse(EpsIdentityResponse::decode(buf)?))
        }
        EmmMessageType::EmmStatus => {
            Ok(EmmMessage::EmmStatus(EmmStatus::decode(buf)?))
        }
        _ => Err(NasError::InvalidMessageType(header.message_type)),
    }
}
