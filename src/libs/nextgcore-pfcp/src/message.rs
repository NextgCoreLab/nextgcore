//! PFCP Messages
//!
//! PFCP message structures and encoding/decoding as specified in 3GPP TS 29.244.

use crate::error::{PfcpError, PfcpResult};
use crate::header::{PfcpHeader, PfcpMessageType};
use crate::ie::{encode_u16_ie, encode_u32_ie, encode_u8_ie, IeHeader, IeType, RawIe};
use crate::types::{
    ApplicationIdsPfds, CpFunctionFeatures, CreateBar, CreateFar, CreatePdr, CreateQer, CreateUrr,
    DownlinkDataReport, FSeid, FqCsid, GracefulReleasePeriod, NodeId, NodeReportType,
    PfcpAssociationReleaseRequest, PfcpCause, PfcpSessionChangeInfo, PfdPartialFailureInformation,
    RemoveFar, RemovePdr, ReportType, UpFunctionFeatures, UpdateFar, UpdatePdr, UsageReportSrr,
    UserPlanePathFailureReport,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Heartbeat Request message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub recovery_time_stamp: u32,
}

impl HeartbeatRequest {
    pub fn new(recovery_time_stamp: u32) -> Self {
        Self {
            recovery_time_stamp,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut recovery_time_stamp = 0u32;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::RecoveryTimeStamp as u16 && ie.data.len() >= 4 {
                let mut data = ie.data;
                recovery_time_stamp = data.get_u32();
            }
        }

        Ok(Self {
            recovery_time_stamp,
        })
    }
}

/// Heartbeat Response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatResponse {
    pub recovery_time_stamp: u32,
}

impl HeartbeatResponse {
    pub fn new(recovery_time_stamp: u32) -> Self {
        Self {
            recovery_time_stamp,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u32_ie(buf, IeType::RecoveryTimeStamp, self.recovery_time_stamp);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut recovery_time_stamp = 0u32;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::RecoveryTimeStamp as u16 && ie.data.len() >= 4 {
                let mut data = ie.data;
                recovery_time_stamp = data.get_u32();
            }
        }

        Ok(Self {
            recovery_time_stamp,
        })
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
            let header =
                IeHeader::new(IeType::UpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
        }

        // CP Function Features (optional)
        if let Some(features) = &self.cp_function_features {
            let mut features_buf = BytesMut::new();
            features.encode(&mut features_buf);
            let header =
                IeHeader::new(IeType::CpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
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
                    cp_function_features = Some(CpFunctionFeatures::decode(&ie.data)?);
                }
                _ => {} // Skip unknown IEs
            }
        }

        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;

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
            let header =
                IeHeader::new(IeType::UpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
        }

        // CP Function Features (optional)
        if let Some(features) = &self.cp_function_features {
            let mut features_buf = BytesMut::new();
            features.encode(&mut features_buf);
            let header =
                IeHeader::new(IeType::CpFunctionFeatures as u16, features_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&features_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        // Cause is a Mandatory IE (TS 29.244 §7.4.4.2); track presence rather
        // than silently defaulting a missing Cause to "Request Accepted".
        let mut cause: Option<PfcpCause> = None;
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
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
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
                    cp_function_features = Some(CpFunctionFeatures::decode(&ie.data)?);
                }
                _ => {} // Skip unknown IEs
            }
        }

        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;

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

        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
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
        // Cause is a Mandatory IE (TS 29.244 §7.4.4.4).
        let mut cause: Option<PfcpCause> = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                _ => {}
            }
        }

        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;
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

        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cp_f_seid =
            cp_f_seid.ok_or_else(|| PfcpError::MissingMandatoryIe("CP F-SEID".to_string()))?;

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

/// Session Establishment Response message (TS 29.244 §7.5.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEstablishmentResponse {
    pub node_id: Option<NodeId>,
    pub cause: PfcpCause,
    pub up_f_seid: Option<FSeid>,
    /// Created PDR(s) carrying the UP-allocated local F-TEID(s); present when
    /// the request is accepted (§7.5.3.2).
    pub created_pdrs: Vec<CreatedPdr>,
}

impl SessionEstablishmentResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self {
            node_id: None,
            cause,
            up_f_seid: None,
            created_pdrs: Vec::new(),
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

        // Created PDR(s) (empty by default => no bytes emitted)
        for cpdr in &self.created_pdrs {
            let mut cpdr_buf = BytesMut::new();
            cpdr.encode(&mut cpdr_buf);
            let header = IeHeader::new(IeType::CreatedPdr as u16, cpdr_buf.len() as u16);
            header.encode(buf);
            buf.put_slice(&cpdr_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        // Cause is a Mandatory IE (TS 29.244 §7.5.3).
        let mut cause: Option<PfcpCause> = None;
        let mut up_f_seid = None;
        let mut created_pdrs = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::FSeid as u16 => {
                    let mut data = ie.data;
                    up_f_seid = Some(FSeid::decode(&mut data)?);
                }
                t if t == IeType::CreatedPdr as u16 => {
                    let mut data = ie.data;
                    created_pdrs.push(CreatedPdr::decode(&mut data)?);
                }
                _ => {}
            }
        }

        // Node ID is Mandatory (TS 29.244 §7.5.3).
        let node_id =
            node_id.ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?;
        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;

        // When the request is accepted, UP F-SEID is Conditional-Mandatory
        // (TS 29.244 §7.5.3): the UP function must return the allocated F-SEID.
        if cause == PfcpCause::RequestAccepted && up_f_seid.is_none() {
            return Err(PfcpError::MissingMandatoryIe("UP F-SEID".to_string()));
        }

        Ok(Self {
            node_id: Some(node_id),
            cause,
            up_f_seid,
            created_pdrs,
        })
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
        // Cause is a Mandatory IE (TS 29.244 §7.5.7).
        let mut cause: Option<PfcpCause> = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            if ie.ie_type == IeType::Cause as u16 && !ie.data.is_empty() {
                cause = Some(PfcpCause::try_from(ie.data[0])?);
            }
        }

        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;
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
        // Cause is a Mandatory IE (TS 29.244 §7.5.5).
        let mut cause: Option<PfcpCause> = None;
        let mut offending_ie = None;
        let mut created_pdrs = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
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

        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;
        Ok(Self {
            cause,
            offending_ie,
            created_pdrs,
        })
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
        Self {
            pdr_id,
            local_f_teid: None,
        }
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

        Ok(Self {
            pdr_id,
            local_f_teid,
        })
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
        // Cause is a Mandatory IE (TS 29.244 §7.5.9).
        let mut cause: Option<PfcpCause> = None;
        let mut offending_ie = None;
        let mut pfcp_srrsp_flags = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
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

        let cause = cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?;
        Ok(Self {
            cause,
            offending_ie,
            pfcp_srrsp_flags,
        })
    }
}

/// Node Report Request (TS 29.244 §7.4.5) — sent by the UP function on
/// detection of a user plane path failure (§5.10A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReportRequest {
    pub node_id: NodeId,
    pub node_report_type: NodeReportType,
    pub user_plane_path_failure_report: Option<UserPlanePathFailureReport>,
}

impl NodeReportRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16).encode(buf);
        buf.put_slice(&node_id_buf);

        let mut nrt_buf = BytesMut::new();
        self.node_report_type.encode(&mut nrt_buf);
        IeHeader::new(IeType::NodeReportType as u16, nrt_buf.len() as u16).encode(buf);
        buf.put_slice(&nrt_buf);

        if let Some(report) = &self.user_plane_path_failure_report {
            let mut report_buf = BytesMut::new();
            report.encode(&mut report_buf);
            IeHeader::new(IeType::UserPlanePathFailureReport as u16, report_buf.len() as u16)
                .encode(buf);
            buf.put_slice(&report_buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut node_report_type = None;
        let mut user_plane_path_failure_report = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::NodeReportType as u16 => {
                    node_report_type = Some(NodeReportType::decode(&ie.data)?);
                }
                t if t == IeType::UserPlanePathFailureReport as u16 => {
                    user_plane_path_failure_report =
                        Some(UserPlanePathFailureReport::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            node_report_type: node_report_type
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node Report Type".to_string()))?,
            user_plane_path_failure_report,
        })
    }
}

/// Node Report Response (TS 29.244 §7.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReportResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
}

impl NodeReportResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16).encode(buf);
        buf.put_slice(&node_id_buf);

        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(offending) = self.offending_ie {
            encode_u16_ie(buf, IeType::OffendingIe, offending);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = None;
        let mut offending_ie = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            cause: cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?,
            offending_ie,
        })
    }
}

/// PFCP Association Update Request (TS 29.244 §7.4.4.3, message type 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationUpdateRequest {
    pub node_id: NodeId,
    pub up_function_features: Option<UpFunctionFeatures>,
    pub cp_function_features: Option<CpFunctionFeatures>,
    pub pfcp_association_release_request: Option<PfcpAssociationReleaseRequest>,
    pub graceful_release_period: Option<GracefulReleasePeriod>,
}

impl AssociationUpdateRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16).encode(buf);
        buf.put_slice(&node_id_buf);

        if let Some(features) = &self.up_function_features {
            let mut fb = BytesMut::new();
            features.encode(&mut fb);
            IeHeader::new(IeType::UpFunctionFeatures as u16, fb.len() as u16).encode(buf);
            buf.put_slice(&fb);
        }
        if let Some(features) = &self.cp_function_features {
            let mut fb = BytesMut::new();
            features.encode(&mut fb);
            IeHeader::new(IeType::CpFunctionFeatures as u16, fb.len() as u16).encode(buf);
            buf.put_slice(&fb);
        }
        if let Some(rr) = &self.pfcp_association_release_request {
            let mut rb = BytesMut::new();
            rr.encode(&mut rb);
            IeHeader::new(IeType::PfcpAssociationReleaseRequest as u16, rb.len() as u16).encode(buf);
            buf.put_slice(&rb);
        }
        if let Some(grp) = &self.graceful_release_period {
            let mut gb = BytesMut::new();
            grp.encode(&mut gb);
            IeHeader::new(IeType::GracefulReleasePeriod as u16, gb.len() as u16).encode(buf);
            buf.put_slice(&gb);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut up_function_features = None;
        let mut cp_function_features = None;
        let mut pfcp_association_release_request = None;
        let mut graceful_release_period = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::UpFunctionFeatures as u16 => {
                    let mut data = ie.data;
                    up_function_features = Some(UpFunctionFeatures::decode(&mut data)?);
                }
                t if t == IeType::CpFunctionFeatures as u16 => {
                    cp_function_features = Some(CpFunctionFeatures::decode(&ie.data)?);
                }
                t if t == IeType::PfcpAssociationReleaseRequest as u16 => {
                    pfcp_association_release_request =
                        Some(PfcpAssociationReleaseRequest::decode(&ie.data)?);
                }
                t if t == IeType::GracefulReleasePeriod as u16 => {
                    graceful_release_period = Some(GracefulReleasePeriod::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            up_function_features,
            cp_function_features,
            pfcp_association_release_request,
            graceful_release_period,
        })
    }
}

/// PFCP Association Update Response (TS 29.244 §7.4.4.4, message type 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationUpdateResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub up_function_features: Option<UpFunctionFeatures>,
    pub cp_function_features: Option<CpFunctionFeatures>,
}

impl AssociationUpdateResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut node_id_buf = BytesMut::new();
        self.node_id.encode(&mut node_id_buf);
        IeHeader::new(IeType::NodeId as u16, node_id_buf.len() as u16).encode(buf);
        buf.put_slice(&node_id_buf);

        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(features) = &self.up_function_features {
            let mut fb = BytesMut::new();
            features.encode(&mut fb);
            IeHeader::new(IeType::UpFunctionFeatures as u16, fb.len() as u16).encode(buf);
            buf.put_slice(&fb);
        }
        if let Some(features) = &self.cp_function_features {
            let mut fb = BytesMut::new();
            features.encode(&mut fb);
            IeHeader::new(IeType::CpFunctionFeatures as u16, fb.len() as u16).encode(buf);
            buf.put_slice(&fb);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = None;
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
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::UpFunctionFeatures as u16 => {
                    let mut data = ie.data;
                    up_function_features = Some(UpFunctionFeatures::decode(&mut data)?);
                }
                t if t == IeType::CpFunctionFeatures as u16 => {
                    cp_function_features = Some(CpFunctionFeatures::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            cause: cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?,
            up_function_features,
            cp_function_features,
        })
    }
}

/// PFCP PFD Management Request (TS 29.244 §7.4.3.1, message type 3). Carries
/// zero or more Application ID's PFDs IEs (absence => delete all stored PFDs for
/// every Application ID, §6.2.5.3) plus an optional Node ID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PfdManagementRequest {
    pub application_ids_pfds: Vec<ApplicationIdsPfds>,
    pub node_id: Option<NodeId>,
}

impl PfdManagementRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        for app in &self.application_ids_pfds {
            let mut inner = BytesMut::new();
            app.encode(&mut inner);
            IeHeader::new(IeType::ApplicationIdsPfds as u16, inner.len() as u16).encode(buf);
            buf.put_slice(&inner);
        }
        if let Some(node_id) = &self.node_id {
            let mut nb = BytesMut::new();
            node_id.encode(&mut nb);
            IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
            buf.put_slice(&nb);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut application_ids_pfds = Vec::new();
        let mut node_id = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::ApplicationIdsPfds as u16 => {
                    application_ids_pfds.push(ApplicationIdsPfds::decode(&ie.data)?);
                }
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            application_ids_pfds,
            node_id,
        })
    }
}

/// PFCP PFD Management Response (TS 29.244 §7.4.3.2, message type 4). Mandatory
/// Cause, optional Offending IE / Node ID, and zero or more PFD Partial Failure
/// Information IEs (present on partial acceptance, §5.42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfdManagementResponse {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub node_id: Option<NodeId>,
    pub pfd_partial_failure_information: Vec<PfdPartialFailureInformation>,
}

impl PfdManagementResponse {
    pub fn new(cause: PfcpCause) -> Self {
        Self {
            cause,
            offending_ie: None,
            node_id: None,
            pfd_partial_failure_information: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(offending) = self.offending_ie {
            encode_u16_ie(buf, IeType::OffendingIe, offending);
        }

        if let Some(node_id) = &self.node_id {
            let mut nb = BytesMut::new();
            node_id.encode(&mut nb);
            IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
            buf.put_slice(&nb);
        }

        for info in &self.pfd_partial_failure_information {
            let mut inner = BytesMut::new();
            info.encode(&mut inner);
            IeHeader::new(
                IeType::PfdPartialFailureInformation as u16,
                inner.len() as u16,
            )
            .encode(buf);
            buf.put_slice(&inner);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut cause = None;
        let mut offending_ie = None;
        let mut node_id = None;
        let mut pfd_partial_failure_information = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::PfdPartialFailureInformation as u16 => {
                    pfd_partial_failure_information
                        .push(PfdPartialFailureInformation::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            cause: cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?,
            offending_ie,
            node_id,
            pfd_partial_failure_information,
        })
    }
}

/// PFCP Session Set Deletion Request (TS 29.244 §7.4.6.1, message type 14).
/// Node-level (no SEID): mandatory Node ID plus zero or more FQ-CSID IEs (the
/// six per-node-type slots all share IE type 65 and are disambiguated by the
/// Node Type field inside each FQ-CSID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetDeletionRequest {
    pub node_id: NodeId,
    pub fq_csids: Vec<FqCsid>,
}

impl SessionSetDeletionRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut nb = BytesMut::new();
        self.node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
        buf.put_slice(&nb);

        for fq in &self.fq_csids {
            let mut inner = BytesMut::new();
            fq.encode(&mut inner);
            IeHeader::new(IeType::FqCsid as u16, inner.len() as u16).encode(buf);
            buf.put_slice(&inner);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut fq_csids = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::FqCsid as u16 => {
                    fq_csids.push(FqCsid::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            fq_csids,
        })
    }
}

/// PFCP Session Set Deletion Response (TS 29.244 §7.4.6.2, message type 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetDeletionResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
}

impl SessionSetDeletionResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut nb = BytesMut::new();
        self.node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
        buf.put_slice(&nb);

        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(offending) = self.offending_ie {
            encode_u16_ie(buf, IeType::OffendingIe, offending);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = None;
        let mut offending_ie = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            cause: cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?,
            offending_ie,
        })
    }
}

/// PFCP Session Set Modification Request (TS 29.244 §7.4.7.1, message type 16).
/// Node-level: mandatory Node ID plus one or more PFCP Session Change Info
/// grouped IEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetModificationRequest {
    pub node_id: NodeId,
    pub pfcp_session_change_info: Vec<PfcpSessionChangeInfo>,
}

impl SessionSetModificationRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut nb = BytesMut::new();
        self.node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
        buf.put_slice(&nb);

        for info in &self.pfcp_session_change_info {
            let mut inner = BytesMut::new();
            info.encode(&mut inner);
            IeHeader::new(IeType::PfcpSessionChangeInfo as u16, inner.len() as u16).encode(buf);
            buf.put_slice(&inner);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut pfcp_session_change_info = Vec::new();

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::PfcpSessionChangeInfo as u16 => {
                    pfcp_session_change_info.push(PfcpSessionChangeInfo::decode(&ie.data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            pfcp_session_change_info,
        })
    }
}

/// PFCP Session Set Modification Response (TS 29.244 §7.4.7.2, message type 17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetModificationResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
}

impl SessionSetModificationResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut nb = BytesMut::new();
        self.node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(buf);
        buf.put_slice(&nb);

        encode_u8_ie(buf, IeType::Cause, self.cause as u8);

        if let Some(offending) = self.offending_ie {
            encode_u16_ie(buf, IeType::OffendingIe, offending);
        }
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let mut node_id = None;
        let mut cause = None;
        let mut offending_ie = None;

        while buf.remaining() >= IeHeader::LEN {
            let ie = RawIe::decode(buf)?;
            match ie.ie_type {
                t if t == IeType::NodeId as u16 => {
                    let mut data = ie.data;
                    node_id = Some(NodeId::decode(&mut data)?);
                }
                t if t == IeType::Cause as u16 => {
                    if !ie.data.is_empty() {
                        cause = Some(PfcpCause::try_from(ie.data[0])?);
                    }
                }
                t if t == IeType::OffendingIe as u16 => {
                    if ie.data.len() >= 2 {
                        let mut data = ie.data;
                        offending_ie = Some(data.get_u16());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            node_id: node_id
                .ok_or_else(|| PfcpError::MissingMandatoryIe("Node ID".to_string()))?,
            cause: cause.ok_or_else(|| PfcpError::MissingMandatoryIe("Cause".to_string()))?,
            offending_ie,
        })
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
    NodeReportRequest(NodeReportRequest),
    NodeReportResponse(NodeReportResponse),
    AssociationUpdateRequest(AssociationUpdateRequest),
    AssociationUpdateResponse(AssociationUpdateResponse),
    PfdManagementRequest(PfdManagementRequest),
    PfdManagementResponse(PfdManagementResponse),
    SessionSetDeletionRequest(SessionSetDeletionRequest),
    SessionSetDeletionResponse(SessionSetDeletionResponse),
    SessionSetModificationRequest(SessionSetModificationRequest),
    SessionSetModificationResponse(SessionSetModificationResponse),
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
            Self::NodeReportRequest(_) => PfcpMessageType::NodeReportRequest,
            Self::NodeReportResponse(_) => PfcpMessageType::NodeReportResponse,
            Self::AssociationUpdateRequest(_) => PfcpMessageType::AssociationUpdateRequest,
            Self::AssociationUpdateResponse(_) => PfcpMessageType::AssociationUpdateResponse,
            Self::PfdManagementRequest(_) => PfcpMessageType::PfdManagementRequest,
            Self::PfdManagementResponse(_) => PfcpMessageType::PfdManagementResponse,
            Self::SessionSetDeletionRequest(_) => PfcpMessageType::SessionSetDeletionRequest,
            Self::SessionSetDeletionResponse(_) => PfcpMessageType::SessionSetDeletionResponse,
            Self::SessionSetModificationRequest(_) => {
                PfcpMessageType::SessionSetModificationRequest
            }
            Self::SessionSetModificationResponse(_) => {
                PfcpMessageType::SessionSetModificationResponse
            }
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
            Self::NodeReportRequest(msg) => msg.encode(buf),
            Self::NodeReportResponse(msg) => msg.encode(buf),
            Self::AssociationUpdateRequest(msg) => msg.encode(buf),
            Self::AssociationUpdateResponse(msg) => msg.encode(buf),
            Self::PfdManagementRequest(msg) => msg.encode(buf),
            Self::PfdManagementResponse(msg) => msg.encode(buf),
            Self::SessionSetDeletionRequest(msg) => msg.encode(buf),
            Self::SessionSetDeletionResponse(msg) => msg.encode(buf),
            Self::SessionSetModificationRequest(msg) => msg.encode(buf),
            Self::SessionSetModificationResponse(msg) => msg.encode(buf),
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
            PfcpMessageType::AssociationSetupRequest => Ok(Self::AssociationSetupRequest(
                AssociationSetupRequest::decode(buf)?,
            )),
            PfcpMessageType::AssociationSetupResponse => Ok(Self::AssociationSetupResponse(
                AssociationSetupResponse::decode(buf)?,
            )),
            PfcpMessageType::AssociationReleaseRequest => Ok(Self::AssociationReleaseRequest(
                AssociationReleaseRequest::decode(buf)?,
            )),
            PfcpMessageType::AssociationReleaseResponse => Ok(Self::AssociationReleaseResponse(
                AssociationReleaseResponse::decode(buf)?,
            )),
            PfcpMessageType::SessionEstablishmentRequest => Ok(Self::SessionEstablishmentRequest(
                SessionEstablishmentRequest::decode(buf)?,
            )),
            PfcpMessageType::SessionEstablishmentResponse => Ok(
                Self::SessionEstablishmentResponse(SessionEstablishmentResponse::decode(buf)?),
            ),
            PfcpMessageType::SessionModificationRequest => Ok(Self::SessionModificationRequest(
                SessionModificationRequest::decode(buf)?,
            )),
            PfcpMessageType::SessionModificationResponse => Ok(Self::SessionModificationResponse(
                SessionModificationResponse::decode(buf)?,
            )),
            PfcpMessageType::SessionDeletionRequest => Ok(Self::SessionDeletionRequest(
                SessionDeletionRequest::decode(buf)?,
            )),
            PfcpMessageType::SessionDeletionResponse => Ok(Self::SessionDeletionResponse(
                SessionDeletionResponse::decode(buf)?,
            )),
            PfcpMessageType::SessionReportRequest => Ok(Self::SessionReportRequest(
                SessionReportRequest::decode(buf)?,
            )),
            PfcpMessageType::SessionReportResponse => Ok(Self::SessionReportResponse(
                SessionReportResponse::decode(buf)?,
            )),
            PfcpMessageType::NodeReportRequest => {
                Ok(Self::NodeReportRequest(NodeReportRequest::decode(buf)?))
            }
            PfcpMessageType::NodeReportResponse => {
                Ok(Self::NodeReportResponse(NodeReportResponse::decode(buf)?))
            }
            PfcpMessageType::AssociationUpdateRequest => Ok(Self::AssociationUpdateRequest(
                AssociationUpdateRequest::decode(buf)?,
            )),
            PfcpMessageType::AssociationUpdateResponse => Ok(Self::AssociationUpdateResponse(
                AssociationUpdateResponse::decode(buf)?,
            )),
            PfcpMessageType::PfdManagementRequest => Ok(Self::PfdManagementRequest(
                PfdManagementRequest::decode(buf)?,
            )),
            PfcpMessageType::PfdManagementResponse => Ok(Self::PfdManagementResponse(
                PfdManagementResponse::decode(buf)?,
            )),
            PfcpMessageType::SessionSetDeletionRequest => Ok(Self::SessionSetDeletionRequest(
                SessionSetDeletionRequest::decode(buf)?,
            )),
            PfcpMessageType::SessionSetDeletionResponse => Ok(Self::SessionSetDeletionResponse(
                SessionSetDeletionResponse::decode(buf)?,
            )),
            PfcpMessageType::SessionSetModificationRequest => {
                Ok(Self::SessionSetModificationRequest(
                    SessionSetModificationRequest::decode(buf)?,
                ))
            }
            PfcpMessageType::SessionSetModificationResponse => {
                Ok(Self::SessionSetModificationResponse(
                    SessionSetModificationResponse::decode(buf)?,
                ))
            }
            _ => Err(PfcpError::InvalidMessageType(message_type as u8)),
        }
    }
}

/// Build a complete PFCP message with header
pub fn build_message(message: &PfcpMessage, sequence_number: u32, seid: Option<u64>) -> BytesMut {
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

    // The PFCP length field counts every byte after the length field itself:
    // the mandatory header tail (SEID + sequence + spare = 12 bytes when a SEID
    // is present, sequence + spare = 4 bytes otherwise) plus the message body.
    // Reject lengths smaller than that tail before subtracting, so a crafted
    // short length cannot underflow (debug panic / release wrap).
    let header_tail = if header.seid_presence { 12 } else { 4 };
    let body_len = (header.length as usize)
        .checked_sub(header_tail)
        .ok_or(PfcpError::BufferTooShort {
            needed: header_tail,
            available: header.length as usize,
        })?;

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
    fn test_node_report_request_roundtrip() {
        let msg = NodeReportRequest {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            node_report_type: NodeReportType {
                upfr: true,
                ..Default::default()
            },
            user_plane_path_failure_report: Some(UserPlanePathFailureReport {
                remote_gtpu_peers: vec![RemoteGtpUPeer {
                    ipv4: Some([10, 45, 0, 7]),
                    ipv6: None,
                }],
            }),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = NodeReportRequest::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.node_report_type.upfr);
        assert_eq!(
            decoded.user_plane_path_failure_report.unwrap().remote_gtpu_peers[0].ipv4,
            Some([10, 45, 0, 7])
        );
    }

    #[test]
    fn test_node_report_request_missing_type_rejected() {
        // Node Report Type is mandatory.
        let mut buf = BytesMut::new();
        let node_id = NodeId::new_ipv4([1, 2, 3, 4]);
        let mut nb = BytesMut::new();
        node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut buf);
        buf.put_slice(&nb);
        assert!(matches!(
            NodeReportRequest::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_association_update_request_roundtrip() {
        let msg = AssociationUpdateRequest {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            up_function_features: None,
            cp_function_features: None,
            pfcp_association_release_request: Some(PfcpAssociationReleaseRequest {
                sarr: true,
                urss: false,
            }),
            graceful_release_period: Some(GracefulReleasePeriod {
                timer_value: 5,
                timer_unit: 1,
            }),
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = AssociationUpdateRequest::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.pfcp_association_release_request.unwrap().sarr);
        assert_eq!(decoded.graceful_release_period.unwrap().timer_value, 5);
    }

    #[test]
    fn test_association_update_response_roundtrip_via_dispatch() {
        let msg = PfcpMessage::AssociationUpdateResponse(AssociationUpdateResponse {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            cause: PfcpCause::RequestAccepted,
            up_function_features: None,
            cp_function_features: None,
        });
        assert_eq!(msg.message_type(), PfcpMessageType::AssociationUpdateResponse);
        let mut body = BytesMut::new();
        msg.encode_body(&mut body);
        let decoded = PfcpMessage::decode_body(
            PfcpMessageType::AssociationUpdateResponse,
            &mut body.freeze(),
        )
        .unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_node_report_response_roundtrip_via_dispatch() {
        let msg = PfcpMessage::NodeReportResponse(NodeReportResponse {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            cause: PfcpCause::RequestAccepted,
            offending_ie: None,
        });
        assert_eq!(msg.message_type(), PfcpMessageType::NodeReportResponse);
        let mut body = BytesMut::new();
        msg.encode_body(&mut body);
        let decoded =
            PfcpMessage::decode_body(PfcpMessageType::NodeReportResponse, &mut body.freeze())
                .unwrap();
        assert_eq!(decoded, msg);
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
    fn test_parse_message_undersized_length_errs() {
        // Craft a header (no SEID) whose length field is smaller than the 4-byte
        // mandatory header tail. Previously `length - 4` underflowed (debug panic
        // / release wrap); it must now return a graceful error.
        // Build a valid header first, then corrupt the length field.
        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(1));
        let buf = build_message(&msg, 1, None);
        let mut raw = buf.to_vec();
        // Length is the u16 at offsets [2..4]. Set it to 1 (< 4-byte tail).
        raw[2] = 0x00;
        raw[3] = 0x01;
        let mut bytes = Bytes::from(raw);
        let res = parse_message(&mut bytes);
        assert!(
            res.is_err(),
            "undersized PFCP length must error, got {res:?}"
        );
    }

    #[test]
    fn test_parse_message_undersized_length_with_seid_errs() {
        // Same check for the SEID-present path (12-byte tail).
        let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(1));
        let buf = build_message(&msg, 1, Some(0x1122334455667788));
        let mut raw = buf.to_vec();
        // Set length to 3 (< 12-byte tail).
        raw[2] = 0x00;
        raw[3] = 0x03;
        let mut bytes = Bytes::from(raw);
        let res = parse_message(&mut bytes);
        assert!(
            res.is_err(),
            "undersized PFCP length (SEID) must error, got {res:?}"
        );
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
        let mm = MeasurementMethod {
            volum: true,
            ..Default::default()
        };
        let rt = ReportingTriggers {
            volth: true,
            ..Default::default()
        };
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

        assert_eq!(
            header.message_type,
            PfcpMessageType::SessionEstablishmentRequest
        );
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

        assert_eq!(
            header.message_type,
            PfcpMessageType::SessionModificationRequest
        );

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

        assert_eq!(
            header.message_type,
            PfcpMessageType::SessionModificationResponse
        );
        if let PfcpMessage::SessionModificationResponse(resp) = decoded {
            assert_eq!(resp.cause, PfcpCause::RequestAccepted);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_session_report_request_round_trip() {
        let rt = ReportType {
            dldr: true,
            ..Default::default()
        };
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

    #[test]
    fn test_pfd_management_request_byte_vector() {
        // One Application ID's PFDs (app "app1", one PFD context, one PFD
        // Contents carrying a Flow Description), no Node ID. Verifies the full
        // nested TLV wire layout per TS 29.244 §7.4.3.1.
        let msg = PfdManagementRequest {
            application_ids_pfds: vec![ApplicationIdsPfds {
                application_id: ApplicationId::new(b"app1".to_vec()),
                pfd_contexts: vec![PfdContext {
                    pfd_contents: vec![PfdContents {
                        flow_description: Some(b"abc".to_vec()),
                        ..Default::default()
                    }],
                }],
            }],
            node_id: None,
        };
        let mut body = BytesMut::new();
        msg.encode(&mut body);
        assert_eq!(
            body.as_ref(),
            &[
                // Application ID's PFDs IE (type 58): len 23
                0x00, 0x3A, 0x00, 0x17, //
                // Application ID IE (type 24): len 4
                0x00, 0x18, 0x00, 0x04, b'a', b'p', b'p', b'1', //
                // PFD context IE (type 59): len 11
                0x00, 0x3B, 0x00, 0x0B, //
                // PFD Contents IE (type 61): len 7
                0x00, 0x3D, 0x00, 0x07, //
                0x01, 0x00, 0x00, 0x03, b'a', b'b', b'c',
            ]
        );
        let decoded = PfdManagementRequest::decode(&mut body.freeze()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_pfd_management_request_roundtrip_via_build_parse() {
        // Node-level procedure: no SEID. Round-trip through the header path.
        let msg = PfcpMessage::PfdManagementRequest(PfdManagementRequest {
            application_ids_pfds: vec![
                ApplicationIdsPfds {
                    application_id: ApplicationId::new(b"voip".to_vec()),
                    pfd_contexts: vec![PfdContext {
                        pfd_contents: vec![PfdContents {
                            flow_description: Some(b"permit out ip from any to any".to_vec()),
                            url: Some(b"http://example.com".to_vec()),
                            ..Default::default()
                        }],
                    }],
                },
                // Second app with no PFD context => delete-all for that app.
                ApplicationIdsPfds {
                    application_id: ApplicationId::new(b"video".to_vec()),
                    pfd_contexts: vec![],
                },
            ],
            node_id: Some(NodeId::new_ipv4([10, 45, 0, 1])),
        });
        let buf = build_message(&msg, 7, None);
        let (header, decoded) = parse_message(&mut buf.freeze()).unwrap();
        assert_eq!(header.message_type, PfcpMessageType::PfdManagementRequest);
        assert!(!header.seid_presence);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_pfd_management_request_empty_delete_all() {
        // An empty request (no IEs) means "delete all PFDs for all apps".
        let msg = PfdManagementRequest::default();
        let mut body = BytesMut::new();
        msg.encode(&mut body);
        assert!(body.is_empty());
        let decoded = PfdManagementRequest::decode(&mut body.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.application_ids_pfds.is_empty());
        assert!(decoded.node_id.is_none());
    }

    #[test]
    fn test_pfd_management_response_roundtrip_via_dispatch() {
        let msg = PfcpMessage::PfdManagementResponse(PfdManagementResponse {
            cause: PfcpCause::RequestAccepted,
            offending_ie: None,
            node_id: Some(NodeId::new_ipv4([10, 45, 0, 1])),
            pfd_partial_failure_information: Vec::new(),
        });
        assert_eq!(msg.message_type(), PfcpMessageType::PfdManagementResponse);
        let mut body = BytesMut::new();
        msg.encode_body(&mut body);
        let decoded =
            PfcpMessage::decode_body(PfcpMessageType::PfdManagementResponse, &mut body.freeze())
                .unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_pfd_management_response_partial_failure() {
        let msg = PfdManagementResponse {
            cause: PfcpCause::RuleCreationModificationFailure,
            offending_ie: Some(IeType::ApplicationIdsPfds as u16),
            node_id: None,
            pfd_partial_failure_information: vec![PfdPartialFailureInformation {
                application_id: ApplicationId::new(b"app1".to_vec()),
                failure_cause: PfcpCause::RuleCreationModificationFailure,
            }],
        };
        let mut body = BytesMut::new();
        msg.encode(&mut body);
        let decoded = PfdManagementResponse::decode(&mut body.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.pfd_partial_failure_information.len(), 1);
        assert_eq!(
            decoded.offending_ie,
            Some(IeType::ApplicationIdsPfds as u16)
        );
    }

    #[test]
    fn test_pfd_management_response_missing_cause_rejected() {
        // Cause is mandatory.
        let mut body = BytesMut::new();
        let node_id = NodeId::new_ipv4([1, 2, 3, 4]);
        let mut nb = BytesMut::new();
        node_id.encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut body);
        body.put_slice(&nb);
        assert!(matches!(
            PfdManagementResponse::decode(&mut body.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_set_deletion_request_full_message_bytes() {
        // Node-level (no SEID): Node ID 10.45.0.1 + one FQ-CSID (IPv4 10.45.0.1,
        // CSID 0x0102, Node Type PGW-C/SMF). Full wire image per TS 29.244
        // §7.4.6.1 / §8.2.43.
        let msg = PfcpMessage::SessionSetDeletionRequest(SessionSetDeletionRequest {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            fq_csids: vec![FqCsid::new_ipv4(
                [10, 45, 0, 1],
                vec![0x0102],
                FqCsidNodeType::PgwCSmf,
            )],
        });
        let buf = build_message(&msg, 1, None);
        assert_eq!(
            buf.as_ref(),
            &[
                // header: version 1 / no SEID, type 14, length 0x19=25, seq 1, spare
                0x20, 0x0E, 0x00, 0x19, 0x00, 0x00, 0x01, 0x00,
                // Node ID IE (type 60): len 5, IPv4 10.45.0.1
                0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x2D, 0x00, 0x01,
                // FQ-CSID IE (type 65): len 8
                0x00, 0x41, 0x00, 0x08, 0x01, 0x0A, 0x2D, 0x00, 0x01, 0x01, 0x02, 0x02,
            ]
        );
        let (header, decoded) = parse_message(&mut buf.freeze()).unwrap();
        assert_eq!(header.message_type, PfcpMessageType::SessionSetDeletionRequest);
        assert!(!header.seid_presence);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_session_set_deletion_request_roundtrip_multi_fq_csid() {
        let msg = SessionSetDeletionRequest {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            fq_csids: vec![
                FqCsid::new_ipv4([10, 45, 0, 1], vec![0x0001], FqCsidNodeType::PgwCSmf),
                FqCsid::new_ipv6([0x20; 16], vec![0x0002, 0x0003], FqCsidNodeType::PgwUSgwUUpf),
            ],
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = SessionSetDeletionRequest::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.fq_csids.len(), 2);
    }

    #[test]
    fn test_session_set_deletion_request_missing_node_id_rejected() {
        // Node ID is mandatory: encode only an FQ-CSID IE.
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        FqCsid::new_ipv4([1, 2, 3, 4], vec![0x0001], FqCsidNodeType::Mme).encode(&mut inner);
        IeHeader::new(IeType::FqCsid as u16, inner.len() as u16).encode(&mut buf);
        buf.put_slice(&inner);
        assert!(matches!(
            SessionSetDeletionRequest::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_set_deletion_response_via_dispatch() {
        let msg = PfcpMessage::SessionSetDeletionResponse(SessionSetDeletionResponse {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            cause: PfcpCause::RequestAccepted,
            offending_ie: None,
        });
        assert_eq!(msg.message_type(), PfcpMessageType::SessionSetDeletionResponse);
        let mut body = BytesMut::new();
        msg.encode_body(&mut body);
        let decoded = PfcpMessage::decode_body(
            PfcpMessageType::SessionSetDeletionResponse,
            &mut body.freeze(),
        )
        .unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_session_set_deletion_response_missing_cause_rejected() {
        let mut buf = BytesMut::new();
        let mut nb = BytesMut::new();
        NodeId::new_ipv4([1, 2, 3, 4]).encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut buf);
        buf.put_slice(&nb);
        assert!(matches!(
            SessionSetDeletionResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_set_modification_request_roundtrip() {
        let msg = PfcpMessage::SessionSetModificationRequest(SessionSetModificationRequest {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            pfcp_session_change_info: vec![PfcpSessionChangeInfo {
                pgw_c_smf_fq_csids: vec![FqCsid::new_ipv4(
                    [10, 45, 0, 1],
                    vec![0x0102],
                    FqCsidNodeType::PgwCSmf,
                )],
                group_ids: vec![GroupId::new(b"grp".to_vec())],
                cp_ip_addresses: vec![CpIpAddress {
                    ipv4: Some([10, 45, 0, 2]),
                    ipv6: None,
                }],
                alternative_smf_ip_address: AlternativeSmfIpAddress {
                    ipv4: Some([10, 45, 0, 3]),
                    ipv6: None,
                    ppe: false,
                },
            }],
        });
        let buf = build_message(&msg, 9, None);
        let (header, decoded) = parse_message(&mut buf.freeze()).unwrap();
        assert_eq!(
            header.message_type,
            PfcpMessageType::SessionSetModificationRequest
        );
        assert!(!header.seid_presence);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_session_set_modification_request_missing_node_id_rejected() {
        let info = PfcpSessionChangeInfo {
            pgw_c_smf_fq_csids: vec![],
            group_ids: vec![],
            cp_ip_addresses: vec![],
            alternative_smf_ip_address: AlternativeSmfIpAddress {
                ipv4: Some([1, 2, 3, 4]),
                ipv6: None,
                ppe: false,
            },
        };
        let mut buf = BytesMut::new();
        let mut inner = BytesMut::new();
        info.encode(&mut inner);
        IeHeader::new(IeType::PfcpSessionChangeInfo as u16, inner.len() as u16).encode(&mut buf);
        buf.put_slice(&inner);
        assert!(matches!(
            SessionSetModificationRequest::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_set_modification_response_via_dispatch() {
        let msg = PfcpMessage::SessionSetModificationResponse(SessionSetModificationResponse {
            node_id: NodeId::new_ipv4([10, 45, 0, 1]),
            cause: PfcpCause::RequestAccepted,
            offending_ie: Some(IeType::PfcpSessionChangeInfo as u16),
        });
        assert_eq!(
            msg.message_type(),
            PfcpMessageType::SessionSetModificationResponse
        );
        let mut body = BytesMut::new();
        msg.encode_body(&mut body);
        let decoded = PfcpMessage::decode_body(
            PfcpMessageType::SessionSetModificationResponse,
            &mut body.freeze(),
        )
        .unwrap();
        assert_eq!(decoded, msg);
    }

    // ----- pfcp-07: mandatory Cause enforcement in the six response decoders -----

    #[test]
    fn test_association_setup_response_with_cause_round_trip() {
        // (a) A valid response carrying Cause still decodes correctly.
        let msg = AssociationSetupResponse::new(
            NodeId::new_ipv4([10, 45, 0, 1]),
            PfcpCause::RequestAccepted,
            1234,
        );
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = AssociationSetupResponse::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.cause, PfcpCause::RequestAccepted);
    }

    #[test]
    fn test_association_setup_response_missing_cause_rejected() {
        // (b) Node ID present, Cause omitted -> Cause is mandatory.
        let mut buf = BytesMut::new();
        let mut nb = BytesMut::new();
        NodeId::new_ipv4([10, 45, 0, 1]).encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut buf);
        buf.put_slice(&nb);
        assert!(matches!(
            AssociationSetupResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_association_release_response_with_cause_round_trip() {
        let msg = AssociationReleaseResponse::new(
            NodeId::new_ipv4([10, 45, 0, 1]),
            PfcpCause::RequestAccepted,
        );
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = AssociationReleaseResponse::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_association_release_response_missing_cause_rejected() {
        let mut buf = BytesMut::new();
        let mut nb = BytesMut::new();
        NodeId::new_ipv4([10, 45, 0, 1]).encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut buf);
        buf.put_slice(&nb);
        assert!(matches!(
            AssociationReleaseResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_deletion_response_with_cause_round_trip() {
        let msg = SessionDeletionResponse::new(PfcpCause::RequestAccepted);
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let decoded = SessionDeletionResponse::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_session_deletion_response_missing_cause_rejected() {
        // Empty body -> no Cause IE.
        assert!(matches!(
            SessionDeletionResponse::decode(&mut BytesMut::new().freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_modification_response_missing_cause_rejected() {
        // Body carries only an Offending IE, no Cause.
        let mut buf = BytesMut::new();
        IeHeader::new(IeType::OffendingIe as u16, 2).encode(&mut buf);
        buf.put_u16(IeType::Cause as u16);
        assert!(matches!(
            SessionModificationResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_report_response_missing_cause_rejected() {
        // Empty body -> no Cause IE.
        assert!(matches!(
            SessionReportResponse::decode(&mut BytesMut::new().freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    // ----- pfcp-08: Session Establishment Response mandatory IEs -----

    #[test]
    fn test_session_establishment_response_accepted_round_trip() {
        // (a) Conformant accepted response (Node ID + UP F-SEID + Created PDR)
        // round-trips byte-identically.
        let mut resp = SessionEstablishmentResponse::new(PfcpCause::RequestAccepted);
        resp.node_id = Some(NodeId::new_ipv4([10, 45, 0, 1]));
        resp.up_f_seid = Some(FSeid::new_ipv4(0x1122, [10, 45, 0, 7]));
        let mut cpdr = CreatedPdr::new(1);
        cpdr.local_f_teid = Some(FTeid::new_ipv4(0x5566_7788, [10, 45, 0, 7]));
        resp.created_pdrs.push(cpdr);

        let mut buf = BytesMut::new();
        resp.encode(&mut buf);
        let bytes = buf.clone().freeze();
        let decoded = SessionEstablishmentResponse::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded.created_pdrs.len(), 1);
        assert_eq!(
            decoded.created_pdrs[0].local_f_teid.as_ref().unwrap().teid,
            0x5566_7788
        );
        // Re-encode is byte-identical to the original encoding.
        let mut buf2 = BytesMut::new();
        decoded.encode(&mut buf2);
        assert_eq!(buf2.freeze(), bytes);
    }

    #[test]
    fn test_session_establishment_response_missing_node_id_rejected() {
        // (b) Accepted response with Cause + UP F-SEID but no Node ID -> error.
        let mut buf = BytesMut::new();
        encode_u8_ie(&mut buf, IeType::Cause, PfcpCause::RequestAccepted as u8);
        let mut fb = BytesMut::new();
        FSeid::new_ipv4(0x1122, [10, 45, 0, 7]).encode(&mut fb);
        IeHeader::new(IeType::FSeid as u16, fb.len() as u16).encode(&mut buf);
        buf.put_slice(&fb);
        assert!(matches!(
            SessionEstablishmentResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_session_establishment_response_accepted_missing_up_fseid_rejected() {
        // Accepted response with Node ID + Cause but no UP F-SEID -> error.
        let mut buf = BytesMut::new();
        let mut nb = BytesMut::new();
        NodeId::new_ipv4([10, 45, 0, 1]).encode(&mut nb);
        IeHeader::new(IeType::NodeId as u16, nb.len() as u16).encode(&mut buf);
        buf.put_slice(&nb);
        encode_u8_ie(&mut buf, IeType::Cause, PfcpCause::RequestAccepted as u8);
        assert!(matches!(
            SessionEstablishmentResponse::decode(&mut buf.freeze()),
            Err(PfcpError::MissingMandatoryIe(_))
        ));
    }
}
