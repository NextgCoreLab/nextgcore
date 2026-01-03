//! PFCP Messages
//!
//! PFCP message structures and encoding/decoding as specified in 3GPP TS 29.244.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{PfcpError, PfcpResult};
use crate::header::{PfcpHeader, PfcpMessageType};
use crate::ie::{IeHeader, IeType, RawIe, encode_u8_ie, encode_u32_ie};
use crate::types::{NodeId, FSeid, PfcpCause, UpFunctionFeatures, CpFunctionFeatures};

/// Heartbeat Request message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub recovery_time_stamp: u32,
}

impl HeartbeatRequest {
    pub fn new(recovery_time_stamp: u32) -> Self {
        Self { recovery_time_stamp }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut recovery_time_stamp = 0u32;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::RecoveryTimeStamp as u16 {
                if ie.data.len() >= 4 {
                    let mut data = ie.data;
                    recovery_time_stamp = data.get_u32();
                }
            }
        }
        
        Ok(Self { recovery_time_stamp })
    }
}

/// Heartbeat Response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatResponse {
    pub recovery_time_stamp: u32,
}

impl HeartbeatResponse {
    pub fn new(recovery_time_stamp: u32) -> Self {
        Self { recovery_time_stamp }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut recovery_time_stamp = 0u32;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::RecoveryTimeStamp as u16 {
                if ie.data.len() >= 4 {
                    let mut data = ie.data;
                    recovery_time_stamp = data.get_u32();
                }
            }
        }
        
        Ok(Self { recovery_time_stamp })
    }
}

/// Association Setup Request message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationSetupRequest {
    pub node_id: NodeId,
    pub recovery_time_stamp: u32,
    pub up_function_features: Option<UpFunctionFeatures>,
    pub cp_function_features: Option<CpFunctionFeatures>,
}

impl AssociationSetupRequest {
    pub fn new(node_id: NodeId, recovery_time_stamp: u32) -> Self {
        Self {
            node_id,
            recovery_time_stamp,
            up_function_features: None,
            cp_function_features: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Node ID
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&node_id_buf);
        
        // Recovery Time Stamp
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
        
        // UP Function Features (optional)
        if let Some(features) = &self.up_function_features {
            let mut features_buf = BytesMut::new();
            features.encode(&mut features_buf);
            let header = IeHeader::new(IeType::UpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
        }
        
        // CP Function Features (optional)
        if let Some(features) = &self.cp_function_features {
            encode_u8_ie(buf, IeType::CpFunctionFeatures, features.encode());
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut recovery_time_stamp = 0u32;
        let mut up_function_features = None;
        let mut cp_function_features = None;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::RecoveryTimeStamp as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        recovery_time_stamp = data.get_u32();
                    }
                }
                t if t == IeType::UpFunctionFeatures as u16 => {
                    let mut data = ie.data;
                    up_function_features = Some(UpFunctionFeatures::decode(&mut data)?);
                }
                t if t == IeType::CpFunctionFeatures as u16 => {
                    if !ie.data.is_empty() {
                        cp_function_features = Some(CpFunctionFeatures::decode(ie.data[0]));
                    }
                }
                _ => {} // Skip unknown IEs
            }
        }
        
        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        
        Ok(Self {
            node_id,
            recovery_time_stamp,
            up_function_features,
            cp_function_features,
        })
    }
}


/// Association Setup Response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationSetupResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub recovery_time_stamp: u32,
    pub up_function_features: Option<UpFunctionFeatures>,
    pub cp_function_features: Option<CpFunctionFeatures>,
}

impl AssociationSetupResponse {
    pub fn new(node_id: NodeId, cause: PfcpCause, recovery_time_stamp: u32) -> Self {
        Self {
            node_id,
            cause,
            recovery_time_stamp,
            up_function_features: None,
            cp_function_features: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Node ID
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&node_id_buf);
        
        // Cause
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);
        
        // Recovery Time Stamp
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
        
        // UP Function Features (optional)
        if let Some(features) = &self.up_function_features {
            let mut features_buf = BytesMut::new();
            features.encode(&mut features_buf);
            let header = IeHeader::new(IeType::UpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
        }
        
        // CP Function Features (optional)
        if let Some(features) = &self.cp_function_features {
            encode_u8_ie(buf, IeType::CpFunctionFeatures, features.encode());
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = PfcpCause::RequestAccepted;
        let mut recovery_time_stamp = 0u32;
        let mut up_function_features = None;
        let mut cp_function_features = None;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = PfcpCause::try_from(ie.data[0])?;
                    }
                }
                t if t == IeType::RecoveryTimeStamp as u16 => {
                    if ie.data.len() >= 4 {
                        let mut data = ie.data;
                        recovery_time_stamp = data.get_u32();
                    }
                }
                t if t == IeType::UpFunctionFeatures as u16 => {
                    let mut data = ie.data;
                    up_function_features = Some(UpFunctionFeatures::decode(&mut data)?);
                }
                t if t == IeType::CpFunctionFeatures as u16 => {
                    if !ie.data.is_empty() {
                        cp_function_features = Some(CpFunctionFeatures::decode(ie.data[0]));
                    }
                }
                _ => {} // Skip unknown IEs
            }
        }
        
        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        
        Ok(Self {
            node_id,
            cause,
            recovery_time_stamp,
            up_function_features,
            cp_function_features,
        })
    }
}

/// Association Release Request message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationReleaseRequest {
    pub node_id: NodeId,
}

impl AssociationReleaseRequest {
    pub fn new(node_id: NodeId) -> Self {
        Self { node_id }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&node_id_buf);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::NodeId as u16 {
                let mut data = ie.data;
                node_id = Some(NodeId::decode(&mut data)?);
            }
        }
        
        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        Ok(Self { node_id })
    }
}

/// Association Release Response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationReleaseResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
}

impl AssociationReleaseResponse {
    pub fn new(node_id: NodeId, cause: PfcpCause) -> Self {
        Self { node_id, cause }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&node_id_buf);
        
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = PfcpCause::RequestAccepted;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = PfcpCause::try_from(ie.data[0])?;
                    }
                }
                _ => {}
            }
        }
        
        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        Ok(Self { node_id, cause })
    }
}


/// Session Establishment Request message (simplified)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEstablishmentRequest {
    pub node_id: NodeId,
    pub cp_f_seid: FSeid,
    // Additional fields would be added for full implementation
}

impl SessionEstablishmentRequest {
    pub fn new(node_id: NodeId, cp_f_seid: FSeid) -> Self {
        Self { node_id, cp_f_seid }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Node ID
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&node_id_buf);
        
        // CP F-SEID
        let mut fseid_buf = BytesMut::new();
        self.cp_f_seid.encode(&mut fseid_buf);
        let header = IeHeader::new(IeType::FSeid as u16, fseid_buf.len() as u16);
        header.encode(buf);
        buf.put_slice(&fseid_buf);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cp_f_seid = None;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::FSeid as u16 => {
                    let mut data = ie.data;
                    cp_f_seid = Some(FSeid::decode(&mut data)?);
                }
                _ => {} // Skip other IEs for now
            }
        }
        
        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cp_f_seid = cp_f_seid.ok_or_else(|| PfcpError::MissingMandatoryIe("CP F-SEID".to_string()))?;
        
        Ok(Self { node_id, cp_f_seid })
    }
}

/// Session Establishment Response message (simplified)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEstablishmentResponse {
    pub node_id: Option<NodeId>,
    pub cause: PfcpCause,
    pub up_f_seid: Option<FSeid>,
}

impl SessionEstablishmentResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self {
            node_id: None,
            cause,
            up_f_seid: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        // Node ID (optional)
        if let Some(node_id) = &self.node_id {
            let mut node_id_buf = BytesMut::new();
            node_id.encode(&mut node_id_buf);
            let header = IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&node_id_buf);
        }
        
        // Cause
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);
        
        // UP F-SEID (optional)
        if let Some(fseid) = &self.up_f_seid {
            let mut fseid_buf = BytesMut::new();
            fseid.encode(&mut fseid_buf);
            let header = IeHeader::new(IeType::FSeid as u16, fseid_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&fseid_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = PfcpCause::RequestAccepted;
        let mut up_f_seid = None;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = PfcpCause::try_from(ie.data[0])?;
                    }
                }
                t if t == IeType::FSeid as u16 => {
                    let mut data = ie.data;
                    up_f_seid = Some(FSeid::decode(&mut data)?);
                }
                _ => {}
            }
        }
        
        Ok(Self { node_id, cause, up_f_seid })
    }
}

/// Session Deletion Request message
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionDeletionRequest {
    // Empty - no IEs required
}

impl SessionDeletionRequest {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encode(&self, _buf: &mut BytesMut) {
        // No IEs to encode
    }

    pub fn decode(_buf: &mut Bytes) -> PfcpResult<Self> {
        Ok(Self {})
    }
}

/// Session Deletion Response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDeletionResponse {
    pub cause: PfcpCause,
}

impl SessionDeletionResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self { cause }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut cause = PfcpCause::RequestAccepted;
        
        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::Cause as u16 && !ie.data.is_empty() {
                cause = PfcpCause::try_from(ie.data[0])?;
            }
        }
        
        Ok(Self { cause })
    }
}


/// PFCP Message enum containing all message types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfcpMessage {
    HeartbeatRequest(HeartbeatRequest),
    HeartbeatResponse(HeartbeatResponse),
    AssociationSetupRequest(AssociationSetupRequest),
    AssociationSetupResponse(AssociationSetupResponse),
    AssociationReleaseRequest(AssociationReleaseRequest),
    AssociationReleaseResponse(AssociationReleaseResponse),
    SessionEstablishmentRequest(SessionEstablishmentRequest),
    SessionEstablishmentResponse(SessionEstablishmentResponse),
    SessionDeletionRequest(SessionDeletionRequest),
    SessionDeletionResponse(SessionDeletionResponse),
    // Additional message types would be added here
}

impl PfcpMessage {
    /// Get the message type
    pub fn message_type(&self) -> PfcpMessageType {
        match self {
            Self::HeartbeatRequest(_) => PfcpMessageType::HeartbeatRequest,
            Self::HeartbeatResponse(_) => PfcpMessageType::HeartbeatResponse,
            Self::AssociationSetupRequest(_) => PfcpMessageType::AssociationSetupRequest,
            Self::AssociationSetupResponse(_) => PfcpMessageType::AssociationSetupResponse,
            Self::AssociationReleaseRequest(_) => PfcpMessageType::AssociationReleaseRequest,
            Self::AssociationReleaseResponse(_) => PfcpMessageType::AssociationReleaseResponse,
            Self::SessionEstablishmentRequest(_) => PfcpMessageType::SessionEstablishmentRequest,
            Self::SessionEstablishmentResponse(_) => PfcpMessageType::SessionEstablishmentResponse,
            Self::SessionDeletionRequest(_) => PfcpMessageType::SessionDeletionRequest,
            Self::SessionDeletionResponse(_) => PfcpMessageType::SessionDeletionResponse,
        }
    }

    /// Encode the message body (without header)
    pub fn encode_body(&self, buf: &mut BytesMut) {
        match self {
            Self::HeartbeatRequest(msg) => msg.encode(buf),
            Self::HeartbeatResponse(msg) => msg.encode(buf),
            Self::AssociationSetupRequest(msg) => msg.encode(buf),
            Self::AssociationSetupResponse(msg) => msg.encode(buf),
            Self::AssociationReleaseRequest(msg) => msg.encode(buf),
            Self::AssociationReleaseResponse(msg) => msg.encode(buf),
            Self::SessionEstablishmentRequest(msg) => msg.encode(buf),
            Self::SessionEstablishmentResponse(msg) => msg.encode(buf),
            Self::SessionDeletionRequest(msg) => msg.encode(buf),
            Self::SessionDeletionResponse(msg) => msg.encode(buf),
        }
    }

    /// Decode message body based on message type
    pub fn decode_body(message_type: PfcpMessageType, buf: &mut Bytes) -> PfcpResult<Self> {
        match message_type {
            PfcpMessageType::HeartbeatRequest => {
                Ok(Self::HeartbeatRequest(HeartbeatRequest::decode(buf)?))
            }
            PfcpMessageType::HeartbeatResponse => {
                Ok(Self::HeartbeatResponse(HeartbeatResponse::decode(buf)?))
            }
            PfcpMessageType::AssociationSetupRequest => {
                Ok(Self::AssociationSetupRequest(AssociationSetupRequest::decode(buf)?))
            }
            PfcpMessageType::AssociationSetupResponse => {
                Ok(Self::AssociationSetupResponse(AssociationSetupResponse::decode(buf)?))
            }
            PfcpMessageType::AssociationReleaseRequest => {
                Ok(Self::AssociationReleaseRequest(AssociationReleaseRequest::decode(buf)?))
            }
            PfcpMessageType::AssociationReleaseResponse => {
                Ok(Self::AssociationReleaseResponse(AssociationReleaseResponse::decode(buf)?))
            }
            PfcpMessageType::SessionEstablishmentRequest => {
                Ok(Self::SessionEstablishmentRequest(SessionEstablishmentRequest::decode(buf)?))
            }
            PfcpMessageType::SessionEstablishmentResponse => {
                Ok(Self::SessionEstablishmentResponse(SessionEstablishmentResponse::decode(buf)?))
            }
            PfcpMessageType::SessionDeletionRequest => {
                Ok(Self::SessionDeletionRequest(SessionDeletionRequest::decode(buf)?))
            }
            PfcpMessageType::SessionDeletionResponse => {
                Ok(Self::SessionDeletionResponse(SessionDeletionResponse::decode(buf)?))
            }
            _ => Err(PfcpError::InvalidMessageType(message_type as u8)),
        }
    }
}

/// Build a complete PFCP message with header
pub fn build_message(
    message: &PfcpMessage,
    sequence_number: u32,
    seid: Option<u64>,
) -> BytesMut {
    let message_type = message.message_type();
    
    // Encode body first to get length
    let mut body = BytesMut::new();
    message.encode_body(&mut body);
    
    // Create header
    let mut header = if let Some(seid) = seid {
        PfcpHeader::new_with_seid(message_type, seid, sequence_number)
    } else {
        PfcpHeader::new(message_type, sequence_number)
    };
    
    // Set length (body length + remaining header bytes after length field)
    header.length = (body.len() + if header.seid_presence { 12 } else { 4 }) as u16;
    
    // Encode complete message
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    buf.put_slice(&body);
    
    buf
}

/// Parse a complete PFCP message
pub fn parse_message(buf: &mut Bytes) -> PfcpResult<(PfcpHeader, PfcpMessage)> {
    let header = PfcpHeader::decode(buf)?;
    
    // Calculate body length
    let body_len = header.length as usize - if header.seid_presence { 12 } else { 4 };
    
    if buf.remaining() < body_len {
        return Err(PfcpError::BufferTooShort {
            needed: body_len,
            available: buf.remaining(),
        });
    }
    
    let mut body = buf.copy_to_bytes(body_len);
    let message = PfcpMessage::decode_body(header.message_type, &mut body)?;
    
    Ok((header, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_request_encode_decode() {
        let msg = HeartbeatRequest::new(1234567890);
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        
        let mut bytes = buf.freeze();
        let decoded = HeartbeatRequest::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.recovery_time_stamp, 1234567890);
    }

    #[test]
    fn test_build_parse_heartbeat() {
        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(1234567890));
        let buf = build_message(&msg, 1, None);
        
        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();
        
        assert_eq!(header.message_type, PfcpMessageType::HeartbeatRequest);
        assert_eq!(header.sequence_number, 1);
        
        if let PfcpMessage::HeartbeatRequest(req) = decoded {
            assert_eq!(req.recovery_time_stamp, 1234567890);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_association_setup_request() {
        let node_id = NodeId::new_ipv4([192, 168, 1, 1]);
        let msg = AssociationSetupRequest::new(node_id.clone(), 1234567890);
        
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        
        let mut bytes = buf.freeze();
        let decoded = AssociationSetupRequest::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.recovery_time_stamp, 1234567890);
    }
}
