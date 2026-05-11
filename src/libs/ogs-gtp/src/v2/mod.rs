//! GTPv2 Protocol Implementation
//!
//! This module implements GTPv2-C (Control Plane) as specified in 3GPP TS 29.274.

pub mod builder;
pub mod header;
pub mod ie;
pub mod message;
pub mod teid_pool;
pub mod types;

// Re-export header types
pub use header::{
    Gtp2Header, Gtp2MessageType, GTP2_TEID_LEN, GTP2_VERSION_0, GTP2_VERSION_1, GTPV2C_HEADER_LEN,
    GTPV2C_HEADER_LEN_NO_TEID,
};

// Re-export message types
pub use message::{
    CreateBearerRequest, CreateBearerResponse, CreateSessionRequest, CreateSessionResponse,
    DeleteBearerRequest, DeleteBearerResponse, DeleteSessionRequest, DeleteSessionResponse,
    DownlinkDataNotification, DownlinkDataNotificationAcknowledge, Gtp2Message,
    ModifyBearerRequest, ModifyBearerResponse, ReleaseAccessBearersRequest,
    ReleaseAccessBearersResponse,
};

// Re-export IE types
pub use ie::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2ApnRestrictionIe, Gtp2BearerQosIe, Gtp2EbiIe, Gtp2FTeidIe, Gtp2Ie,
    Gtp2IeType, Gtp2PaaIe, Gtp2PdnTypeIe, Gtp2RatTypeIe, Gtp2RecoveryIe, Gtp2SelectionModeIe,
    Gtp2ServingNetworkIe, Gtp2UliIe,
};
// Note: Gtp2CauseIe is in ie module, types module has a different Gtp2CauseIe
pub use ie::Gtp2CauseIe;

// Re-export types
pub use types::{
    Gtp2Ambr, Gtp2ApnRestriction, Gtp2Arp, Gtp2Cause, Gtp2DaylightSavingTime,
    Gtp2ExtensionHeaderType, Gtp2FTeid, Gtp2FTeidInterfaceType, Gtp2NodeType, Gtp2PduType,
    Gtp2PlmnId, Gtp2RatType, Gtp2SelectionMode, Gtp2UeTimeZone, Gtp2UliEcgi, Gtp2UliFlags,
    Gtp2UliTai, GTP2_F_TEID_HDR_LEN, GTP2_F_TEID_IPV4V6_LEN, GTP2_F_TEID_IPV4_LEN,
    GTP2_F_TEID_IPV6_LEN, GTP2_MAX_EXTENSION_HEADER_LEN, GTP2_MAX_INDIRECT_TUNNEL,
    GTP2_NUM_OF_EXTENSION_HEADER,
};

// Re-export builder functions and types
pub use builder::{
    build_create_session_request, build_delete_session_request, build_modify_bearer_request,
    Ambr as BuilderAmbr, FTeid as BuilderFTeid, Uli,
};

// Re-export TEID pool
pub use teid_pool::TeidPool;
