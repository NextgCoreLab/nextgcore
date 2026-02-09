//! Diameter error types

use thiserror::Error;

/// Diameter error type
#[derive(Error, Debug)]
pub enum DiameterError {
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Invalid AVP: {0}")]
    InvalidAvp(String),

    #[error("Missing mandatory AVP: {0}")]
    MissingAvp(String),

    #[error("Invalid AVP value: {0}")]
    InvalidAvpValue(String),

    #[error("Buffer too small: need {needed}, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    #[error("Unknown command code: {0}")]
    UnknownCommand(u32),

    #[error("Unknown application ID: {0}")]
    UnknownApplication(u32),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization rejected")]
    AuthorizationRejected,

    #[error("User unknown")]
    UserUnknown,

    #[error("Roaming not allowed")]
    RoamingNotAllowed,
}

/// Diameter result type
pub type DiameterResult<T> = Result<T, DiameterError>;

/// Diameter Result-Code values (RFC 6733)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultCode {
    // Informational (1xxx)
    MultiRoundAuth = 1001,

    // Success (2xxx)
    Success = 2001,
    LimitedSuccess = 2002,

    // Protocol Errors (3xxx)
    CommandUnsupported = 3001,
    UnableToDeliver = 3002,
    RealmNotServed = 3003,
    TooBusy = 3004,
    LoopDetected = 3005,
    RedirectIndication = 3006,
    ApplicationUnsupported = 3007,
    InvalidHdrBits = 3008,
    InvalidAvpBits = 3009,
    UnknownPeer = 3010,

    // Transient Failures (4xxx)
    AuthenticationRejected = 4001,
    OutOfSpace = 4002,
    ElectionLost = 4003,

    // Permanent Failures (5xxx)
    AvpUnsupported = 5001,
    UnknownSessionId = 5002,
    AuthorizationRejected = 5003,
    InvalidAvpValue = 5004,
    MissingAvp = 5005,
    ResourcesExceeded = 5006,
    ContradictingAvps = 5007,
    AvpNotAllowed = 5008,
    AvpOccursTooManyTimes = 5009,
    NoCommonApplication = 5010,
    UnsupportedVersion = 5011,
    UnableToComply = 5012,
    InvalidBitInHeader = 5013,
    InvalidAvpLength = 5014,
    InvalidMessageLength = 5015,
    InvalidAvpBitCombo = 5016,
    NoCommonSecurity = 5017,

    // 3GPP specific (5xxx)
    UserUnknown = 5030,
}

impl ResultCode {
    /// Check if result code indicates success
    pub fn is_success(&self) -> bool {
        let code = *self as u32;
        (2000..3000).contains(&code)
    }

    /// Check if result code indicates protocol error
    pub fn is_protocol_error(&self) -> bool {
        let code = *self as u32;
        (3000..4000).contains(&code)
    }

    /// Check if result code indicates transient failure
    pub fn is_transient_failure(&self) -> bool {
        let code = *self as u32;
        (4000..5000).contains(&code)
    }

    /// Check if result code indicates permanent failure
    pub fn is_permanent_failure(&self) -> bool {
        let code = *self as u32;
        (5000..6000).contains(&code)
    }
}

impl From<u32> for ResultCode {
    fn from(value: u32) -> Self {
        match value {
            1001 => ResultCode::MultiRoundAuth,
            2001 => ResultCode::Success,
            2002 => ResultCode::LimitedSuccess,
            3001 => ResultCode::CommandUnsupported,
            3002 => ResultCode::UnableToDeliver,
            3003 => ResultCode::RealmNotServed,
            3004 => ResultCode::TooBusy,
            3005 => ResultCode::LoopDetected,
            3006 => ResultCode::RedirectIndication,
            3007 => ResultCode::ApplicationUnsupported,
            3008 => ResultCode::InvalidHdrBits,
            3009 => ResultCode::InvalidAvpBits,
            3010 => ResultCode::UnknownPeer,
            4001 => ResultCode::AuthenticationRejected,
            4002 => ResultCode::OutOfSpace,
            4003 => ResultCode::ElectionLost,
            5001 => ResultCode::AvpUnsupported,
            5002 => ResultCode::UnknownSessionId,
            5003 => ResultCode::AuthorizationRejected,
            5004 => ResultCode::InvalidAvpValue,
            5005 => ResultCode::MissingAvp,
            5006 => ResultCode::ResourcesExceeded,
            5007 => ResultCode::ContradictingAvps,
            5008 => ResultCode::AvpNotAllowed,
            5009 => ResultCode::AvpOccursTooManyTimes,
            5010 => ResultCode::NoCommonApplication,
            5011 => ResultCode::UnsupportedVersion,
            5012 => ResultCode::UnableToComply,
            5013 => ResultCode::InvalidBitInHeader,
            5014 => ResultCode::InvalidAvpLength,
            5015 => ResultCode::InvalidMessageLength,
            5016 => ResultCode::InvalidAvpBitCombo,
            5017 => ResultCode::NoCommonSecurity,
            5030 => ResultCode::UserUnknown,
            _ => ResultCode::UnableToComply,
        }
    }
}
