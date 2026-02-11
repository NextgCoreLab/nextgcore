//! GTPv2 Protocol Implementation
//!
//! This module implements GTPv2-C (Control Plane) as specified in 3GPP TS 29.274.

pub mod types;
pub mod header;
pub mod message;
pub mod ie;
pub mod builder;
pub mod teid_pool;

// Re-export header types
pub use header::{
    Gtp2Header, Gtp2MessageType, GTPV2C_HEADER_LEN, GTPV2C_HEADER_LEN_NO_TEID,
    GTP2_TEID_LEN, GTP2_VERSION_0, GTP2_VERSION_1,
};

// Re-export message types
pub use message::{
    Gtp2Message, CreateSessionRequest, CreateSessionResponse,
    ModifyBearerRequest, ModifyBearerResponse,
    DeleteSessionRequest, DeleteSessionResponse,
    CreateBearerRequest, CreateBearerResponse,
    DeleteBearerRequest, DeleteBearerResponse,
    ReleaseAccessBearersRequest, ReleaseAccessBearersResponse,
    DownlinkDataNotification, DownlinkDataNotificationAcknowledge,
};

// Re-export IE types
pub use ie::{
    Gtp2Ie, Gtp2IeType, Gtp2RecoveryIe, Gtp2EbiIe, Gtp2RatTypeIe,
    Gtp2ApnRestrictionIe, Gtp2SelectionModeIe, Gtp2PdnTypeIe,
    Gtp2FTeidIe, Gtp2BearerQosIe, Gtp2AmbrIe,
    Gtp2UliIe, Gtp2ServingNetworkIe, Gtp2ApnIe, Gtp2PaaIe,
};
// Note: Gtp2CauseIe is in ie module, types module has a different Gtp2CauseIe
pub use ie::Gtp2CauseIe;

// Re-export types
pub use types::{
    Gtp2Cause, Gtp2Ambr, Gtp2RatType, Gtp2PlmnId, Gtp2UliFlags,
    Gtp2FTeid, Gtp2Arp, Gtp2UeTimeZone, Gtp2UliTai, Gtp2UliEcgi,
    Gtp2ExtensionHeaderType, Gtp2PduType, Gtp2ApnRestriction,
    Gtp2SelectionMode, Gtp2NodeType, Gtp2FTeidInterfaceType,
    Gtp2DaylightSavingTime,
    GTP2_MAX_INDIRECT_TUNNEL, GTP2_NUM_OF_EXTENSION_HEADER,
    GTP2_MAX_EXTENSION_HEADER_LEN, GTP2_F_TEID_HDR_LEN,
    GTP2_F_TEID_IPV4_LEN, GTP2_F_TEID_IPV6_LEN, GTP2_F_TEID_IPV4V6_LEN,
};

// Re-export builder functions and types
pub use builder::{
    build_create_session_request, build_modify_bearer_request,
    build_delete_session_request, FTeid as BuilderFTeid, Uli, Ambr as BuilderAmbr
};

// Re-export TEID pool
pub use teid_pool::TeidPool;
