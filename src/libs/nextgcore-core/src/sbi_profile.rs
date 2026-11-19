//! The process-wide SBI security profile switch, below every crate that needs it
//! (#2056).
//!
//! `nextgcore-sbi`'s `SbiProfile` is the API NFs use; it keeps its state HERE so
//! that a crate `nextgcore-sbi` itself depends on (`nextgcore-metrics`, whose
//! listeners must also be fatal under production) reads the same answer,
//! override included, rather than a second parse of the environment that could
//! drift from it.

use std::sync::atomic::{AtomicU8, Ordering};

/// The environment variable selecting the profile (see `nextgcore_sbi::security`).
pub const SBI_PROFILE_ENV: &str = "NEXTGCORE_SBI_PROFILE";

/// The values that select the development profile. Anything else, including the
/// variable being unset, is production.
pub const DEV_PROFILE_VALUES: &[&str] = &["dev", "development", "insecure", "local", "test"];

/// The programmatic override: `0` = consult [`SBI_PROFILE_ENV`], `1` = force dev,
/// `2` = force production.
pub static SBI_PROFILE_MODE: AtomicU8 = AtomicU8::new(0);

/// Whether `value` (the env value) selects the development profile.
pub fn is_dev_value(value: Option<&str>) -> bool {
    value
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| DEV_PROFILE_VALUES.contains(&v.as_str()))
}

/// Whether this process runs the production profile: the override first, then
/// [`SBI_PROFILE_ENV`]. Same answer as `nextgcore_sbi::security::SbiProfile::resolve()`.
pub fn is_production() -> bool {
    match SBI_PROFILE_MODE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => !is_dev_value(std::env::var(SBI_PROFILE_ENV).ok().as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_dev_values_are_dev() {
        for v in ["dev", " DEV ", "development", "insecure", "local", "test"] {
            assert!(is_dev_value(Some(v)), "{v}");
        }
        for v in [
            None,
            Some(""),
            Some("prod"),
            Some("production"),
            Some("devel"),
        ] {
            assert!(!is_dev_value(v), "{v:?}");
        }
    }
}
