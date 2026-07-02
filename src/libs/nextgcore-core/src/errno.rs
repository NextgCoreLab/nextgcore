//! Error codes
//!
//! Exact port of lib/core/nextgcore-errno.h

/// Error code constants
pub const NEXTGCORE_OK: i32 = 0;
pub const NEXTGCORE_ERROR: i32 = -1;
pub const NEXTGCORE_RETRY: i32 = -2;
pub const NEXTGCORE_DONE: i32 = -3;
pub const NEXTGCORE_TIMEUP: i32 = -4;

/// Error type enum
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NextgcoreError {
    #[default]
    Ok = 0,
    Error = -1,
    Retry = -2,
    Done = -3,
    Timeup = -4,
}

impl From<i32> for NextgcoreError {
    fn from(code: i32) -> Self {
        match code {
            0 => NextgcoreError::Ok,
            -2 => NextgcoreError::Retry,
            -3 => NextgcoreError::Done,
            -4 => NextgcoreError::Timeup,
            _ => NextgcoreError::Error,
        }
    }
}

impl From<NextgcoreError> for i32 {
    fn from(err: NextgcoreError) -> Self {
        err as i32
    }
}

impl NextgcoreError {
    pub fn is_ok(&self) -> bool {
        *self == NextgcoreError::Ok
    }

    pub fn is_error(&self) -> bool {
        *self == NextgcoreError::Error
    }

    pub fn is_retry(&self) -> bool {
        *self == NextgcoreError::Retry
    }

    pub fn is_done(&self) -> bool {
        *self == NextgcoreError::Done
    }

    pub fn is_timeup(&self) -> bool {
        *self == NextgcoreError::Timeup
    }
}
