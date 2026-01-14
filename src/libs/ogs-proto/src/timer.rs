//! Timer definitions for the protocol library

/// Timer name constants
pub const TIMER_NAME_NF_INSTANCE_REGISTRATION_INTERVAL: &str =
    "OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL";
pub const TIMER_NAME_NF_INSTANCE_HEARTBEAT_INTERVAL: &str =
    "OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL";
pub const TIMER_NAME_NF_INSTANCE_NO_HEARTBEAT: &str = "OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT";
pub const TIMER_NAME_NF_INSTANCE_VALIDITY: &str = "OGS_TIMER_NF_INSTANCE_VALIDITY";
pub const TIMER_NAME_SUBSCRIPTION_VALIDITY: &str = "OGS_TIMER_SUBSCRIPTION_VALIDITY";
pub const TIMER_NAME_SUBSCRIPTION_PATCH: &str = "OGS_TIMER_SUBSCRIPTION_PATCH";
pub const TIMER_NAME_SBI_CLIENT_WAIT: &str = "OGS_TIMER_SBI_CLIENT_WAIT";

/// Timer IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerId {
    /// Base timer (unused)
    Base,
    /// NF instance registration interval
    NfInstanceRegistrationInterval,
    /// NF instance heartbeat interval
    NfInstanceHeartbeatInterval,
    /// NF instance no heartbeat
    NfInstanceNoHeartbeat,
    /// NF instance validity
    NfInstanceValidity,
    /// Subscription validity
    SubscriptionValidity,
    /// Subscription patch
    SubscriptionPatch,
    /// SBI client wait
    SbiClientWait,
    /// Custom timer with ID
    Custom(i32),
}

impl TimerId {
    /// Get the numeric value of the timer ID
    pub fn as_i32(&self) -> i32 {
        match self {
            TimerId::Base => 0,
            TimerId::NfInstanceRegistrationInterval => 1,
            TimerId::NfInstanceHeartbeatInterval => 2,
            TimerId::NfInstanceNoHeartbeat => 3,
            TimerId::NfInstanceValidity => 4,
            TimerId::SubscriptionValidity => 5,
            TimerId::SubscriptionPatch => 6,
            TimerId::SbiClientWait => 7,
            TimerId::Custom(id) => *id,
        }
    }

    /// Create from numeric value
    pub fn from_i32(id: i32) -> Self {
        match id {
            0 => TimerId::Base,
            1 => TimerId::NfInstanceRegistrationInterval,
            2 => TimerId::NfInstanceHeartbeatInterval,
            3 => TimerId::NfInstanceNoHeartbeat,
            4 => TimerId::NfInstanceValidity,
            5 => TimerId::SubscriptionValidity,
            6 => TimerId::SubscriptionPatch,
            7 => TimerId::SbiClientWait,
            _ => TimerId::Custom(id),
        }
    }
}

/// Get timer name from timer ID
pub fn timer_get_name(timer_id: TimerId) -> &'static str {
    match timer_id {
        TimerId::Base => "OGS_TIMER_BASE",
        TimerId::NfInstanceRegistrationInterval => TIMER_NAME_NF_INSTANCE_REGISTRATION_INTERVAL,
        TimerId::NfInstanceHeartbeatInterval => TIMER_NAME_NF_INSTANCE_HEARTBEAT_INTERVAL,
        TimerId::NfInstanceNoHeartbeat => TIMER_NAME_NF_INSTANCE_NO_HEARTBEAT,
        TimerId::NfInstanceValidity => TIMER_NAME_NF_INSTANCE_VALIDITY,
        TimerId::SubscriptionValidity => TIMER_NAME_SUBSCRIPTION_VALIDITY,
        TimerId::SubscriptionPatch => TIMER_NAME_SUBSCRIPTION_PATCH,
        TimerId::SbiClientWait => TIMER_NAME_SBI_CLIENT_WAIT,
        TimerId::Custom(_) => "UNKNOWN_TIMER",
    }
}

/// Get timer name from numeric ID
pub fn timer_get_name_by_id(timer_id: i32) -> &'static str {
    timer_get_name(TimerId::from_i32(timer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_id_conversion() {
        assert_eq!(TimerId::NfInstanceRegistrationInterval.as_i32(), 1);
        assert_eq!(
            TimerId::from_i32(1),
            TimerId::NfInstanceRegistrationInterval
        );
    }

    #[test]
    fn test_timer_get_name() {
        assert_eq!(
            timer_get_name(TimerId::NfInstanceRegistrationInterval),
            TIMER_NAME_NF_INSTANCE_REGISTRATION_INTERVAL
        );
        assert_eq!(
            timer_get_name(TimerId::SbiClientWait),
            TIMER_NAME_SBI_CLIENT_WAIT
        );
    }

    #[test]
    fn test_timer_get_name_by_id() {
        assert_eq!(
            timer_get_name_by_id(1),
            TIMER_NAME_NF_INSTANCE_REGISTRATION_INTERVAL
        );
    }

    #[test]
    fn test_custom_timer() {
        let timer = TimerId::Custom(100);
        assert_eq!(timer.as_i32(), 100);
        assert_eq!(timer_get_name(timer), "UNKNOWN_TIMER");
    }
}
