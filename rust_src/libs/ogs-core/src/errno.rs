//! Error codes
//!
//! Exact port of lib/core/ogs-errno.h

/// Error code constants
pub const OGS_OK: i32 = 0;
pub const OGS_ERROR: i32 = -1;
pub const OGS_RETRY: i32 = -2;
pub const OGS_DONE: i32 = -3;
pub const OGS_TIMEUP: i32 = -4;

/// Error type enum
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OgsError {
    Ok = 0,
    Error = -1,
    Retry = -2,
    Done = -3,
    Timeup = -4,
}

impl From<i32> for OgsError {
    fn from(code: i32) -> Self {
        match code {
            0 => OgsError::Ok,
            -2 => OgsError::Retry,
            -3 => OgsError::Done,
            -4 => OgsError::Timeup,
            _ => OgsError::Error,
        }
    }
}

impl From<OgsError> for i32 {
    fn from(err: OgsError) -> Self {
        err as i32
    }
}

impl OgsError {
    pub fn is_ok(&self) -> bool {
        *self == OgsError::Ok
    }

    pub fn is_error(&self) -> bool {
        *self == OgsError::Error
    }

    pub fn is_retry(&self) -> bool {
        *self == OgsError::Retry
    }

    pub fn is_done(&self) -> bool {
        *self == OgsError::Done
    }

    pub fn is_timeup(&self) -> bool {
        *self == OgsError::Timeup
    }
}

impl Default for OgsError {
    fn default() -> Self {
        OgsError::Ok
    }
}
