//! PFCP Messages
//!
//! PFCP message structures and encoding/decoding as specified in 3GPP TS 29.244.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{PfcpError, PfcpResult};
use crate::header::{PfcpHeader, PfcpMessageType};
use crate::ie::{IeHeader, IeType, RawIe, encode_u8_ie, encode_u32_ie};
use crate::types::{
    NodeId, FSeid, PfcpCause, UpFunctionFeatures, CpFunctionFeatures,
    CreatePdr, CreateFar, CreateQer, CreateUrr, CreateBar,
    UpdatePdr, UpdateFar, RemovePdr, RemoveFar,
    ReportType, UsageReportSrr, DownlinkDataReport,
};

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
            if ie.ie_type == IeType::RecoveryTimeStamp as u16
                && ie.data.len() >= 4 {
                    let mut data = ie.data;
                    recovery_time_stamp = data.get_u32();
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
            if ie.ie_type == IeType::RecoveryTimeStamp as u16
                && ie.data.len() >= 4 {
                    let mut data = ie.data;
                    recovery_time_stamp = data.get_u32();
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


/// Session Establishment Request message (TS 29.244 Section 7.5.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEstablishmentRequest {
    pub node_id: NodeId,
    pub cp_f_seid: FSeid,
    pub create_pdrs: Vec<CreatePdr>,
    pub create_fars: Vec<CreateFar>,
    pub create_qers: Vec<CreateQer>,
    pub create_urrs: Vec<CreateUrr>,
    pub create_bar: Option<CreateBar>,
}

impl SessionEstablishmentRequest {
    pub fn new(node_id: NodeId, cp_f_seid: FSeid) -> Self {
        Self {
            node_id,
            cp_f_seid,
            create_pdrs: Vec::new(),
            create_fars: Vec::new(),
            create_qers: Vec::new(),
            create_urrs: Vec::new(),
            create_bar: None,
        }
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

        // Create PDRs
        for pdr in &self.create_pdrs {
            let mut pdr_buf = BytesMut::new();
            pdr.encode(&mut pdr_buf);
            let header = IeHeader::new(IeType::CreatePdr as u16, pdr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&pdr_buf);
        }

        // Create FARs
        for far in &self.create_fars {
            let mut far_buf = BytesMut::new();
            far.encode(&mut far_buf);
            let header = IeHeader::new(IeType::CreateFar as u16, far_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&far_buf);
        }

        // Create QERs
        for qer in &self.create_qers {
            let mut qer_buf = BytesMut::new();
            qer.encode(&mut qer_buf);
            let header = IeHeader::new(IeType::CreateQer as u16, qer_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&qer_buf);
        }

        // Create URRs
        for urr in &self.create_urrs {
            let mut urr_buf = BytesMut::new();
            urr.encode(&mut urr_buf);
            let header = IeHeader::new(IeType::CreateUrr as u16, urr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&urr_buf);
        }

        // Create BAR
        if let Some(bar) = &self.create_bar {
            let mut bar_buf = BytesMut::new();
            bar.encode(&mut bar_buf);
            let header = IeHeader::new(IeType::CreateBar as u16, bar_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&bar_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cp_f_seid = None;
        let mut create_pdrs = Vec::new();
        let mut create_fars = Vec::new();
        let mut create_qers = Vec::new();
        let mut create_urrs = Vec::new();
        let mut create_bar = None;

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
                t if t == IeType::CreatePdr as u16 => {
                    let mut data = ie.data;
                    create_pdrs.push(CreatePdr::decode(&mut data)?);
                }
                t if t == IeType::CreateFar as u16 => {
                    let mut data = ie.data;
                    create_fars.push(CreateFar::decode(&mut data)?);
                }
                t if t == IeType::CreateQer as u16 => {
                    let mut data = ie.data;
                    create_qers.push(CreateQer::decode(&mut data)?);
                }
                t if t == IeType::CreateUrr as u16 => {
                    let mut data = ie.data;
                    create_urrs.push(CreateUrr::decode(&mut data)?);
                }
                t if t == IeType::CreateBar as u16 => {
                    let mut data = ie.data;
                    create_bar = Some(CreateBar::decode(&mut data)?);
                }
                _ => {}
            }
        }

        let node_id = node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cp_f_seid = cp_f_seid.ok_or_else(|| PfcpError::MissingMandatoryIe("CP F-SEID".to_string()))?;

        Ok(Self {
            node_id,
            cp_f_seid,
            create_pdrs,
            create_fars,
            create_qers,
            create_urrs,
            create_bar,
        })
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


/// Session Modification Request message (TS 29.244 Section 7.5.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionModificationRequest {
    pub cp_f_seid: Option<FSeid>,
    pub remove_pdrs: Vec<RemovePdr>,
    pub remove_fars: Vec<RemoveFar>,
    pub create_pdrs: Vec<CreatePdr>,
    pub create_fars: Vec<CreateFar>,
    pub create_qers: Vec<CreateQer>,
    pub create_urrs: Vec<CreateUrr>,
    pub create_bar: Option<CreateBar>,
    pub update_pdrs: Vec<UpdatePdr>,
    pub update_fars: Vec<UpdateFar>,
    pub pfcp_smreq_flags: Option<u8>,
}

impl Default for SessionModificationRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionModificationRequest {
    pub fn new() -> Self {
        Self {
            cp_f_seid: None,
            remove_pdrs: Vec::new(),
            remove_fars: Vec::new(),
            create_pdrs: Vec::new(),
            create_fars: Vec::new(),
            create_qers: Vec::new(),
            create_urrs: Vec::new(),
            create_bar: None,
            update_pdrs: Vec::new(),
            update_fars: Vec::new(),
            pfcp_smreq_flags: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(fseid) = &self.cp_f_seid {
            let mut fseid_buf = BytesMut::new();
            fseid.encode(&mut fseid_buf);
            let header = IeHeader::new(IeType::FSeid as u16, fseid_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&fseid_buf);
        }

        for rpdr in &self.remove_pdrs {
            let mut rpdr_buf = BytesMut::new();
            rpdr.encode(&mut rpdr_buf);
            let header = IeHeader::new(IeType::RemovePdr as u16, rpdr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&rpdr_buf);
        }

        for rfar in &self.remove_fars {
            let mut rfar_buf = BytesMut::new();
            rfar.encode(&mut rfar_buf);
            let header = IeHeader::new(IeType::RemoveFar as u16, rfar_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&rfar_buf);
        }

        for pdr in &self.create_pdrs {
            let mut pdr_buf = BytesMut::new();
            pdr.encode(&mut pdr_buf);
            let header = IeHeader::new(IeType::CreatePdr as u16, pdr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&pdr_buf);
        }

        for far in &self.create_fars {
            let mut far_buf = BytesMut::new();
            far.encode(&mut far_buf);
            let header = IeHeader::new(IeType::CreateFar as u16, far_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&far_buf);
        }

        for qer in &self.create_qers {
            let mut qer_buf = BytesMut::new();
            qer.encode(&mut qer_buf);
            let header = IeHeader::new(IeType::CreateQer as u16, qer_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&qer_buf);
        }

        for urr in &self.create_urrs {
            let mut urr_buf = BytesMut::new();
            urr.encode(&mut urr_buf);
            let header = IeHeader::new(IeType::CreateUrr as u16, urr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&urr_buf);
        }

        if let Some(bar) = &self.create_bar {
            let mut bar_buf = BytesMut::new();
            bar.encode(&mut bar_buf);
            let header = IeHeader::new(IeType::CreateBar as u16, bar_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&bar_buf);
        }

        for updr in &self.update_pdrs {
            let mut updr_buf = BytesMut::new();
            updr.encode(&mut updr_buf);
            let header = IeHeader::new(IeType::UpdatePdr as u16, updr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&updr_buf);
        }

        for ufar in &self.update_fars {
            let mut ufar_buf = BytesMut::new();
            ufar.encode(&mut ufar_buf);
            let header = IeHeader::new(IeType::UpdateFar as u16, ufar_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ufar_buf);
        }

        if let Some(flags) = self.pfcp_smreq_flags {
            encode_u8_ie(buf, IeType::PfcpSmreqFlags, flags);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut result = Self::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::FSeid as u16 => {
                    let mut data = ie.data;
                    result.cp_f_seid = Some(FSeid::decode(&mut data)?);
                }
                t if t == IeType::RemovePdr as u16 => {
                    let mut data = ie.data;
                    result.remove_pdrs.push(RemovePdr::decode(&mut data)?);
                }
                t if t == IeType::RemoveFar as u16 => {
                    let mut data = ie.data;
                    result.remove_fars.push(RemoveFar::decode(&mut data)?);
                }
                t if t == IeType::CreatePdr as u16 => {
                    let mut data = ie.data;
                    result.create_pdrs.push(CreatePdr::decode(&mut data)?);
                }
                t if t == IeType::CreateFar as u16 => {
                    let mut data = ie.data;
                    result.create_fars.push(CreateFar::decode(&mut data)?);
                }
                t if t == IeType::CreateQer as u16 => {
                    let mut data = ie.data;
                    result.create_qers.push(CreateQer::decode(&mut data)?);
                }
                t if t == IeType::CreateUrr as u16 => {
                    let mut data = ie.data;
                    result.create_urrs.push(CreateUrr::decode(&mut data)?);
                }
                t if t == IeType::CreateBar as u16 => {
                    let mut data = ie.data;
                    result.create_bar = Some(CreateBar::decode(&mut data)?);
                }
                t if t == IeType::UpdatePdr as u16 => {
                    let mut data = ie.data;
                    result.update_pdrs.push(UpdatePdr::decode(&mut data)?);
                }
                t if t == IeType::UpdateFar as u16 => {
                    let mut data = ie.data;
                    result.update_fars.push(UpdateFar::decode(&mut data)?);
                }
                t if t == IeType::PfcpSmreqFlags as u16 => {
                    if !ie.data.is_empty() {
                        result.pfcp_smreq_flags = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(result)
    }
}

/// Session Modification Response message (TS 29.244 Section 7.5.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionModificationResponse {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub created_pdrs: Vec<CreatedPdr>,
}

impl SessionModificationResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self {
            cause,
            offending_ie: None,
            created_pdrs: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(ie_type) = self.offending_ie {
            let header = IeHeader::new(IeType::OffendingIe as u16, 2);
            header.encode(buf);
            buf.put_u16(ie_type);
        }

        for cpdr in &self.created_pdrs {
            let mut cpdr_buf = BytesMut::new();
            cpdr.encode(&mut cpdr_buf);
            let header = IeHeader::new(IeType::CreatedPdr as u16, cpdr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&cpdr_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut cause = PfcpCause::RequestAccepted;
        let mut offending_ie = None;
        let mut created_pdrs = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = PfcpCause::try_from(ie.data[0])?;
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                t if t == IeType::CreatedPdr as u16 => {
                    let mut data = ie.data;
                    created_pdrs.push(CreatedPdr::decode(&mut data)?);
                }
                _ => {}
            }
        }

        Ok(Self { cause, offending_ie, created_pdrs })
    }
}

/// Created PDR - grouped IE in Session Establishment/Modification Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedPdr {
    pub pdr_id: u16,
    pub local_f_teid: Option<crate::types::FTeid>,
}

impl CreatedPdr {
    pub fn new(pdr_id: u16) -> Self {
        Self { pdr_id, local_f_teid: None }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let header = IeHeader::new(IeType::PdrId as u16, 2);
        header.encode(buf);
        buf.put_u16(self.pdr_id);

        if let Some(fteid) = &self.local_f_teid {
            let mut fteid_buf = BytesMut::new();
            fteid.encode(&mut fteid_buf);
            let header = IeHeader::new(IeType::FTeid as u16, fteid_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&fteid_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut pdr_id = 0u16;
        let mut local_f_teid = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::PdrId as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        pdr_id = data.get_u16();
                    }
                }
                t if t == IeType::FTeid as u16 => {
                    let mut data = ie.data;
                    local_f_teid = Some(crate::types::FTeid::decode(&mut data)?);
                }
                _ => {}
            }
        }

        Ok(Self { pdr_id, local_f_teid })
    }
}

/// Session Report Request message (TS 29.244 Section 7.5.8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReportRequest {
    pub report_type: ReportType,
    pub downlink_data_report: Option<DownlinkDataReport>,
    pub usage_reports: Vec<UsageReportSrr>,
}

impl SessionReportRequest {
    pub fn new(report_type: ReportType) -> Self {
        Self {
            report_type,
            downlink_data_report: None,
            usage_reports: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u8_ie(buf, IeType::ReportType, self.report_type.encode());

        if let Some(dldr) = &self.downlink_data_report {
            let mut dldr_buf = BytesMut::new();
            dldr.encode(&mut dldr_buf);
            let header = IeHeader::new(IeType::DownlinkDataReport as u16, dldr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&dldr_buf);
        }

        for ur in &self.usage_reports {
            let mut ur_buf = BytesMut::new();
            ur.encode(&mut ur_buf);
            let header = IeHeader::new(IeType::UsageReportSrr as u16, ur_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&ur_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut report_type = ReportType::default();
        let mut downlink_data_report = None;
        let mut usage_reports = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::ReportType as u16 => {
                    if !ie.data.is_empty() {
                        report_type = ReportType::decode(ie.data[0]);
                    }
                }
                t if t == IeType::DownlinkDataReport as u16 => {
                    let mut data = ie.data;
                    downlink_data_report = Some(DownlinkDataReport::decode(&mut data)?);
                }
                t if t == IeType::UsageReportSrr as u16 => {
                    let mut data = ie.data;
                    usage_reports.push(UsageReportSrr::decode(&mut data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            report_type,
            downlink_data_report,
            usage_reports,
        })
    }
}

/// Session Report Response message (TS 29.244 Section 7.5.9)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReportResponse {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub pfcp_srrsp_flags: Option<u8>,
}

impl SessionReportResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self {
            cause,
            offending_ie: None,
            pfcp_srrsp_flags: None,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(ie_type) = self.offending_ie {
            let header = IeHeader::new(IeType::OffendingIe as u16, 2);
            header.encode(buf);
            buf.put_u16(ie_type);
        }

        if let Some(flags) = self.pfcp_srrsp_flags {
            encode_u8_ie(buf, IeType::PfcpSrrspFlags, flags);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut cause = PfcpCause::RequestAccepted;
        let mut offending_ie = None;
        let mut pfcp_srrsp_flags = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = PfcpCause::try_from(ie.data[0])?;
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                t if t == IeType::PfcpSrrspFlags as u16 => {
                    if !ie.data.is_empty() {
                        pfcp_srrsp_flags = Some(ie.data[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self { cause, offending_ie, pfcp_srrsp_flags })
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
    SessionModificationRequest(SessionModificationRequest),
    SessionModificationResponse(SessionModificationResponse),
    SessionDeletionRequest(SessionDeletionRequest),
    SessionDeletionResponse(SessionDeletionResponse),
    SessionReportRequest(SessionReportRequest),
    SessionReportResponse(SessionReportResponse),
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
            Self::SessionModificationRequest(_) => PfcpMessageType::SessionModificationRequest,
            Self::SessionModificationResponse(_) => PfcpMessageType::SessionModificationResponse,
            Self::SessionDeletionRequest(_) => PfcpMessageType::SessionDeletionRequest,
            Self::SessionDeletionResponse(_) => PfcpMessageType::SessionDeletionResponse,
            Self::SessionReportRequest(_) => PfcpMessageType::SessionReportRequest,
            Self::SessionReportResponse(_) => PfcpMessageType::SessionReportResponse,
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
            Self::SessionModificationRequest(msg) => msg.encode(buf),
            Self::SessionModificationResponse(msg) => msg.encode(buf),
            Self::SessionDeletionRequest(msg) => msg.encode(buf),
            Self::SessionDeletionResponse(msg) => msg.encode(buf),
            Self::SessionReportRequest(msg) => msg.encode(buf),
            Self::SessionReportResponse(msg) => msg.encode(buf),
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
            PfcpMessageType::SessionModificationRequest => {
                Ok(Self::SessionModificationRequest(SessionModificationRequest::decode(buf)?))
            }
            PfcpMessageType::SessionModificationResponse => {
                Ok(Self::SessionModificationResponse(SessionModificationResponse::decode(buf)?))
            }
            PfcpMessageType::SessionDeletionRequest => {
                Ok(Self::SessionDeletionRequest(SessionDeletionRequest::decode(buf)?))
            }
            PfcpMessageType::SessionDeletionResponse => {
                Ok(Self::SessionDeletionResponse(SessionDeletionResponse::decode(buf)?))
            }
            PfcpMessageType::SessionReportRequest => {
                Ok(Self::SessionReportRequest(SessionReportRequest::decode(buf)?))
            }
            PfcpMessageType::SessionReportResponse => {
                Ok(Self::SessionReportResponse(SessionReportResponse::decode(buf)?))
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
    use crate::types::*;

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

    #[test]
    fn test_session_establishment_with_grouped_ies() {
        let node_id = NodeId::new_ipv4([10, 0, 0, 1]);
        let cp_f_seid = FSeid::new_ipv4(0x1234, [10, 0, 0, 1]);
        let mut msg = SessionEstablishmentRequest::new(node_id.clone(), cp_f_seid.clone());

        // Add a PDR
        let pdi = Pdi::new(SourceInterface::Access);
        let mut pdr = CreatePdr::new(1, 100, pdi);
        pdr.far_id = Some(1);
        msg.create_pdrs.push(pdr);

        // Add a FAR
        let mut far = CreateFar::new(1, ApplyAction::forward());
        far.forwarding_parameters = Some(ForwardingParameters::new(DestinationInterface::Core));
        msg.create_fars.push(far);

        // Add a QER
        let mut qer = CreateQer::new(1, GateStatus::both_open());
        qer.maximum_bitrate = Some(Bitrate::new(100_000_000, 200_000_000));
        msg.create_qers.push(qer);

        // Add a URR
        let mm = MeasurementMethod { volum: true, ..Default::default() };
        let rt = ReportingTriggers { volth: true, ..Default::default() };
        let urr = CreateUrr::new(1, mm, rt);
        msg.create_urrs.push(urr);

        // Add a BAR
        let mut bar = CreateBar::new(1);
        bar.downlink_data_notification_delay = Some(50);
        msg.create_bar = Some(bar);

        // Build full message with header
        let pfcp_msg = PfcpMessage::SessionEstablishmentRequest(msg);
        let buf = build_message(&pfcp_msg, 42, Some(0x1234));

        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();

        assert_eq!(header.message_type, PfcpMessageType::SessionEstablishmentRequest);
        assert!(header.seid_presence);

        if let PfcpMessage::SessionEstablishmentRequest(req) = decoded {
            assert_eq!(req.node_id, node_id);
            assert_eq!(req.cp_f_seid, cp_f_seid);
            assert_eq!(req.create_pdrs.len(), 1);
            assert_eq!(req.create_pdrs[0].pdr_id, 1);
            assert_eq!(req.create_pdrs[0].precedence, 100);
            assert_eq!(req.create_pdrs[0].far_id, Some(1));
            assert_eq!(req.create_fars.len(), 1);
            assert_eq!(req.create_fars[0].far_id, 1);
            assert!(req.create_fars[0].apply_action.forw);
            assert!(req.create_fars[0].forwarding_parameters.is_some());
            assert_eq!(req.create_qers.len(), 1);
            assert_eq!(req.create_qers[0].qer_id, 1);
            assert!(req.create_qers[0].gate_status.ul_gate);
            assert!(req.create_qers[0].maximum_bitrate.is_some());
            assert_eq!(req.create_urrs.len(), 1);
            assert_eq!(req.create_urrs[0].urr_id, 1);
            assert!(req.create_urrs[0].measurement_method.volum);
            assert!(req.create_urrs[0].reporting_triggers.volth);
            assert!(req.create_bar.is_some());
            assert_eq!(req.create_bar.unwrap().bar_id, 1);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_session_modification_request_round_trip() {
        let mut msg = SessionModificationRequest::new();

        // Remove old PDR and FAR
        msg.remove_pdrs.push(RemovePdr::new(1));
        msg.remove_fars.push(RemoveFar::new(1));

        // Create new PDR
        let pdi = Pdi::new(SourceInterface::Core);
        let pdr = CreatePdr::new(2, 200, pdi);
        msg.create_pdrs.push(pdr);

        // Create new FAR
        let far = CreateFar::new(2, ApplyAction::forward());
        msg.create_fars.push(far);

        // Update an existing PDR
        let mut updr = UpdatePdr::new(3);
        updr.precedence = Some(300);
        msg.update_pdrs.push(updr);

        // Update an existing FAR
        let mut ufar = UpdateFar::new(3);
        ufar.apply_action = Some(ApplyAction::buffer());
        msg.update_fars.push(ufar);

        let pfcp_msg = PfcpMessage::SessionModificationRequest(msg);
        let buf = build_message(&pfcp_msg, 100, Some(0xABCD));

        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();

        assert_eq!(header.message_type, PfcpMessageType::SessionModificationRequest);

        if let PfcpMessage::SessionModificationRequest(req) = decoded {
            assert_eq!(req.remove_pdrs.len(), 1);
            assert_eq!(req.remove_pdrs[0].pdr_id, 1);
            assert_eq!(req.remove_fars.len(), 1);
            assert_eq!(req.remove_fars[0].far_id, 1);
            assert_eq!(req.create_pdrs.len(), 1);
            assert_eq!(req.create_pdrs[0].pdr_id, 2);
            assert_eq!(req.create_fars.len(), 1);
            assert_eq!(req.create_fars[0].far_id, 2);
            assert_eq!(req.update_pdrs.len(), 1);
            assert_eq!(req.update_pdrs[0].pdr_id, 3);
            assert_eq!(req.update_pdrs[0].precedence, Some(300));
            assert_eq!(req.update_fars.len(), 1);
            assert_eq!(req.update_fars[0].far_id, 3);
            assert!(req.update_fars[0].apply_action.unwrap().buff);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_session_modification_response_round_trip() {
        let msg = SessionModificationResponse::new(PfcpCause::RequestAccepted);
        let pfcp_msg = PfcpMessage::SessionModificationResponse(msg);
        let buf = build_message(&pfcp_msg, 101, Some(0xABCD));

        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();

        assert_eq!(header.message_type, PfcpMessageType::SessionModificationResponse);
        if let PfcpMessage::SessionModificationResponse(resp) = decoded {
            assert_eq!(resp.cause, PfcpCause::RequestAccepted);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_session_report_request_round_trip() {
        let rt = ReportType { dldr: true, ..Default::default() };
        let mut msg = SessionReportRequest::new(rt);
        msg.downlink_data_report = Some(DownlinkDataReport::new(5));

        let pfcp_msg = PfcpMessage::SessionReportRequest(msg);
        let buf = build_message(&pfcp_msg, 200, Some(0x5678));

        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();

        assert_eq!(header.message_type, PfcpMessageType::SessionReportRequest);
        if let PfcpMessage::SessionReportRequest(req) = decoded {
            assert!(req.report_type.dldr);
            assert!(!req.report_type.usar);
            assert!(req.downlink_data_report.is_some());
            assert_eq!(req.downlink_data_report.unwrap().pdr_id, 5);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_session_report_response_round_trip() {
        let msg = SessionReportResponse::new(PfcpCause::RequestAccepted);
        let pfcp_msg = PfcpMessage::SessionReportResponse(msg);
        let buf = build_message(&pfcp_msg, 201, Some(0x5678));

        let mut bytes = buf.freeze();
        let (header, decoded) = parse_message(&mut bytes).unwrap();

        assert_eq!(header.message_type, PfcpMessageType::SessionReportResponse);
        if let PfcpMessage::SessionReportResponse(resp) = decoded {
            assert_eq!(resp.cause, PfcpCause::RequestAccepted);
        } else {
            panic!("Wrong message type");
        }
    }
}
