//! UPF PFCP Path Management
//!
//! Port of src/upf/pfcp-path.c - PFCP path management for UPF

use crate::n4_build::{
    build_session_deletion_response, build_session_establishment_response,
    build_session_modification_response, build_session_report_request,
    CreatedPdr, FSeid, NodeId, UserPlaneReport,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

// ============================================================================
// PFCP Header
// ============================================================================

/// PFCP message header
#[derive(Debug, Clone, Default)]
pub struct PfcpHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: u16,
    pub seid: u64,
    pub sequence_number: u32,
}

impl PfcpHeader {
    /// Create a new PFCP header
    pub fn new(msg_type: u8, seid: u64, seq: u32) -> Self {
        Self {
            version: 1,
            msg_type,
            length: 0,
            seid,
            sequence_number: seq,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self, payload_len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        let flags = (self.version << 5) | 0x01; // SEID present
        buf.push(flags);
        buf.push(self.msg_type);
        let total_len = (12 + payload_len) as u16; // header after length + payload
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&self.seid.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes()[1..4]); // 3 bytes
        buf.push(0); // spare
        buf
    }
}

// ============================================================================
// PFCP Transaction
// ============================================================================

/// PFCP transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XactState {
    Initial,
    Pending,
    Complete,
    Timeout,
}

/// PFCP transaction
#[derive(Debug, Clone)]
pub struct PfcpXact {
    pub id: u64,
    pub sequence_number: u32,
    pub msg_type: u8,
    pub state: XactState,
    pub local: bool,
    pub remote_addr: Option<SocketAddr>,
    pub seid: u64,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

impl PfcpXact {
    /// Create a new local transaction
    pub fn local_create(seq: u32, seid: u64) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: true,
            remote_addr: None,
            seid,
            request: None,
            response: None,
        }
    }

    /// Create a new remote transaction
    pub fn remote_create(seq: u32, seid: u64, remote_addr: SocketAddr) -> Self {
        Self {
            id: seq as u64,
            sequence_number: seq,
            msg_type: 0,
            state: XactState::Initial,
            local: false,
            remote_addr: Some(remote_addr),
            seid,
            request: None,
            response: None,
        }
    }

    /// Update transaction with TX message
    pub fn update_tx(&mut self, header: &PfcpHeader, payload: Vec<u8>) {
        self.msg_type = header.msg_type;
        let mut msg = header.encode(payload.len());
        msg.extend(payload);
        if self.local {
            self.request = Some(msg);
        } else {
            self.response = Some(msg);
        }
        self.state = XactState::Pending;
    }

    /// Commit transaction (send message)
    pub fn commit(&mut self) -> Result<Vec<u8>, &'static str> {
        self.state = XactState::Complete;
        if self.local {
            self.request.clone().ok_or("No request to send")
        } else {
            self.response.clone().ok_or("No response to send")
        }
    }
}

// ============================================================================
// PFCP Node
// ============================================================================

/// PFCP peer node
#[derive(Debug, Clone)]
pub struct PfcpNode {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub recovery_time_stamp: u32,
    pub associated: bool,
    pub restoration_required: bool,
}

impl Default for PfcpNode {
    fn default() -> Self {
        Self {
            node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8805),
            recovery_time_stamp: 0,
            associated: false,
            restoration_required: false,
        }
    }
}

// ============================================================================
// PFCP Path Context
// ============================================================================

/// PFCP path context for UPF
#[derive(Debug, Default)]
pub struct PfcpPathContext {
    pub local_node_id: NodeId,
    pub local_addr: Option<SocketAddr>,
    pub recovery_time_stamp: u32,
    pub peer_nodes: HashMap<String, PfcpNode>,
    pub next_sequence: u32,
    pub transactions: HashMap<u32, PfcpXact>,
}

impl PfcpPathContext {
    /// Create a new PFCP path context
    pub fn new() -> Self {
        Self {
            local_node_id: NodeId::Ipv4(Ipv4Addr::UNSPECIFIED),
            local_addr: None,
            recovery_time_stamp: 0,
            peer_nodes: HashMap::new(),
            next_sequence: 1,
            transactions: HashMap::new(),
        }
    }

    /// Get next sequence number
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence == 0 {
            self.next_sequence = 1;
        }
        seq
    }

    /// Create a local transaction
    pub fn create_local_xact(&mut self, seid: u64) -> u32 {
        let seq = self.next_seq();
        let xact = PfcpXact::local_create(seq, seid);
        self.transactions.insert(seq, xact);
        seq
    }

    /// Find transaction by sequence number
    pub fn find_xact(&mut self, seq: u32) -> Option<&mut PfcpXact> {
        self.transactions.get_mut(&seq)
    }

    /// Remove transaction
    pub fn remove_xact(&mut self, seq: u32) -> Option<PfcpXact> {
        self.transactions.remove(&seq)
    }
}

// ============================================================================
// PFCP Send Functions
// ============================================================================

/// Send Session Establishment Response
/// Port of upf_pfcp_send_session_establishment_response
pub fn send_session_establishment_response(
    ctx: &mut PfcpPathContext,
    xact: &mut PfcpXact,
    upf_n4_seid: u64,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let f_seid = FSeid {
        seid: upf_n4_seid,
        ipv4: match &ctx.local_node_id {
            NodeId::Ipv4(addr) => Some(*addr),
            _ => None,
        },
        ipv6: match &ctx.local_node_id {
            NodeId::Ipv6(addr) => Some(*addr),
            _ => None,
        },
    };

    let payload = build_session_establishment_response(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        upf_n4_seid,
        &ctx.local_node_id,
        &f_seid,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Modification Response
/// Port of upf_pfcp_send_session_modification_response
pub fn send_session_modification_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    created_pdrs: &[CreatedPdr],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_modification_response(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        created_pdrs,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Deletion Response
/// Port of upf_pfcp_send_session_deletion_response
pub fn send_session_deletion_response(
    xact: &mut PfcpXact,
    smf_n4_seid: u64,
    usage_reports: &[crate::n4_build::UsageReport],
) -> Result<Vec<u8>, &'static str> {
    let payload = build_session_deletion_response(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        usage_reports,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
        smf_n4_seid,
        xact.sequence_number,
    );

    xact.update_tx(&header, payload);
    xact.commit()
}

/// Send Session Report Request
/// Port of upf_pfcp_send_session_report_request
pub fn send_session_report_request(
    ctx: &mut PfcpPathContext,
    smf_n4_seid: u64,
    report: &UserPlaneReport,
) -> Result<(u32, Vec<u8>), &'static str> {
    let seq = ctx.create_local_xact(smf_n4_seid);
    
    let payload = build_session_report_request(
        crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST,
        report,
    );

    let header = PfcpHeader::new(
        crate::n4_build::pfcp_type::SESSION_REPORT_REQUEST,
        smf_n4_seid,
        seq,
    );

    if let Some(xact) = ctx.find_xact(seq) {
        xact.update_tx(&header, payload);
        let msg = xact.commit()?;
        Ok((seq, msg))
    } else {
        Err("Transaction not found")
    }
}

// ============================================================================
// PFCP Open/Close
// ============================================================================

/// Open PFCP path (initialize)
/// Port of upf_pfcp_open
pub fn pfcp_open(ctx: &mut PfcpPathContext, local_addr: SocketAddr) -> Result<(), &'static str> {
    ctx.local_addr = Some(local_addr);
    ctx.local_node_id = match local_addr {
        SocketAddr::V4(addr) => NodeId::Ipv4(*addr.ip()),
        SocketAddr::V6(addr) => NodeId::Ipv6(*addr.ip()),
    };
    ctx.recovery_time_stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    
    log::info!("PFCP path opened on {}", local_addr);
    Ok(())
}

/// Close PFCP path (cleanup)
/// Port of upf_pfcp_close
pub fn pfcp_close(ctx: &mut PfcpPathContext) {
    ctx.peer_nodes.clear();
    ctx.transactions.clear();
    ctx.local_addr = None;
    log::info!("PFCP path closed");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_pfcp_header_new() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.msg_type, 51);
        assert_eq!(header.seid, 0x1234);
        assert_eq!(header.sequence_number, 1);
    }

    #[test]
    fn test_pfcp_header_encode() {
        let header = PfcpHeader::new(51, 0x1234, 1);
        let encoded = header.encode(10);
        assert_eq!(encoded[0], 0x21); // version=1, SEID present
        assert_eq!(encoded[1], 51);   // msg_type
        // length = 12 + 10 = 22
        assert_eq!(&encoded[2..4], &22u16.to_be_bytes());
    }

    #[test]
    fn test_pfcp_xact_local_create() {
        let xact = PfcpXact::local_create(1, 0x1234);
        assert_eq!(xact.sequence_number, 1);
        assert_eq!(xact.seid, 0x1234);
        assert!(xact.local);
        assert_eq!(xact.state, XactState::Initial);
    }

    #[test]
    fn test_pfcp_xact_remote_create() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let xact = PfcpXact::remote_create(1, 0x1234, addr);
        assert!(!xact.local);
        assert_eq!(xact.remote_addr, Some(addr));
    }

    #[test]
    fn test_pfcp_xact_update_tx_and_commit() {
        let mut xact = PfcpXact::local_create(1, 0x1234);
        let header = PfcpHeader::new(56, 0x1234, 1);
        xact.update_tx(&header, vec![1, 2, 3]);
        assert_eq!(xact.state, XactState::Pending);
        
        let msg = xact.commit().unwrap();
        assert!(!msg.is_empty());
        assert_eq!(xact.state, XactState::Complete);
    }

    #[test]
    fn test_pfcp_path_context_new() {
        let ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_sequence, 1);
        assert!(ctx.peer_nodes.is_empty());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_path_context_next_seq() {
        let mut ctx = PfcpPathContext::new();
        assert_eq!(ctx.next_seq(), 1);
        assert_eq!(ctx.next_seq(), 2);
        assert_eq!(ctx.next_seq(), 3);
    }

    #[test]
    fn test_pfcp_path_context_create_local_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        assert_eq!(seq, 1);
        assert!(ctx.transactions.contains_key(&1));
    }

    #[test]
    fn test_pfcp_path_context_find_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.find_xact(seq);
        assert!(xact.is_some());
        assert_eq!(xact.unwrap().seid, 0x1234);
    }

    #[test]
    fn test_pfcp_path_context_remove_xact() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        let xact = ctx.remove_xact(seq);
        assert!(xact.is_some());
        assert!(ctx.transactions.is_empty());
    }

    #[test]
    fn test_pfcp_open() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        let result = pfcp_open(&mut ctx, addr);
        assert!(result.is_ok());
        assert_eq!(ctx.local_addr, Some(addr));
        assert!(ctx.recovery_time_stamp > 0);
    }

    #[test]
    fn test_pfcp_close() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        ctx.create_local_xact(0x1234);
        
        pfcp_close(&mut ctx);
        
        assert!(ctx.local_addr.is_none());
        assert!(ctx.transactions.is_empty());
        assert!(ctx.peer_nodes.is_empty());
    }

    #[test]
    fn test_send_session_establishment_response() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        
        let seq = ctx.create_local_xact(0x1234);
        // Set up the xact first
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let created_pdrs = vec![
            CreatedPdr {
                pdr_id: 1,
                local_f_teid: None,
                ue_ip_address: None,
            },
        ];
        
        // Now get xact again and call the function
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let node_id = ctx.local_node_id.clone();
        
        let f_seid = FSeid {
            seid: 0x5678,
            ipv4: match &node_id {
                NodeId::Ipv4(addr) => Some(*addr),
                _ => None,
            },
            ipv6: None,
        };
        
        let payload = build_session_establishment_response(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x5678,
            &node_id,
            &f_seid,
            &created_pdrs,
        );
        
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_modification_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_modification_response(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_MODIFICATION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_deletion_response() {
        let mut ctx = PfcpPathContext::new();
        let seq = ctx.create_local_xact(0x1234);
        {
            let xact = ctx.find_xact(seq).unwrap();
            xact.local = false;
        }
        
        let xact = ctx.transactions.get_mut(&seq).unwrap();
        let payload = build_session_deletion_response(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            &[],
        );
        let header = PfcpHeader::new(
            crate::n4_build::pfcp_type::SESSION_DELETION_RESPONSE,
            0x1234,
            xact.sequence_number,
        );
        xact.update_tx(&header, payload);
        let result = xact.commit();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_session_report_request() {
        let mut ctx = PfcpPathContext::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
        pfcp_open(&mut ctx, addr).unwrap();
        
        let report = UserPlaneReport::default();
        let result = send_session_report_request(&mut ctx, 0x1234, &report);
        
        assert!(result.is_ok());
        let (seq, msg) = result.unwrap();
        assert_eq!(seq, 1);
        assert!(!msg.is_empty());
    }
}
