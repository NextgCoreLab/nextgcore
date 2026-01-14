//! NextGCore PFCP Protocol Library
//!
//! This crate provides PFCP (Packet Forwarding Control Protocol) message building
//! and parsing as specified in 3GPP TS 29.244.
//!
//! PFCP is used for communication between the Control Plane (CP) and User Plane (UP)
//! functions in 5G and LTE networks.
//!
//! # Features
//!
//! - PFCP header encoding/decoding
//! - PFCP message types (Heartbeat, Association, Session management)
//! - Information Element (IE) encoding/decoding
//! - Type definitions for PFCP protocol structures
//!
//! # Example
//!
//! ```rust
//! use ogs_pfcp::message::{HeartbeatRequest, PfcpMessage, build_message};
//!
//! // Create a heartbeat request
//! let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(1234567890));
//!
//! // Build the complete message with header
//! let buf = build_message(&msg, 1, None);
//! ```

pub mod error;
pub mod header;
pub mod ie;
pub mod message;
pub mod types;

#[cfg(test)]
mod property_tests;

pub use error::{PfcpError, PfcpResult};
pub use header::{PfcpHeader, PfcpMessageType, PFCP_HEADER_LEN, PFCP_HEADER_LEN_WITH_SEID};
pub use types::PFCP_UDP_PORT;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::error::{PfcpError, PfcpResult};
    pub use crate::header::{PfcpHeader, PfcpMessageType};
    pub use crate::ie::{IeType, IeHeader, RawIe};
    pub use crate::message::{
        PfcpMessage,
        HeartbeatRequest,
        HeartbeatResponse,
        AssociationSetupRequest,
        AssociationSetupResponse,
        AssociationReleaseRequest,
        AssociationReleaseResponse,
        SessionEstablishmentRequest,
        SessionEstablishmentResponse,
        SessionDeletionRequest,
        SessionDeletionResponse,
        build_message,
        parse_message,
    };
    pub use crate::types::{
        PfcpCause,
        NodeId,
        NodeIdType,
        FSeid,
        FTeid,
        UeIpAddress,
        ApplyAction,
        OuterHeaderRemoval,
        OuterHeaderCreation,
        SourceInterface,
        DestinationInterface,
        GateStatus,
        Bitrate,
        VolumeThreshold,
        VolumeMeasurement,
        ReportingTriggers,
        ReportType,
        UpFunctionFeatures,
        CpFunctionFeatures,
    };
}
