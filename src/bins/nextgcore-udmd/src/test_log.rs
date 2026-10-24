//! Test-only logger that keeps every record, so a test can assert what was,
//! and was not, logged (#789 review: no callback token in a log line).
//!
//! Installed once per test binary. It replaces `env_logger::try_init` in this
//! crate's tests, so the two never race to be the process's logger.

use std::sync::{Mutex, Once};

static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Bound on kept records; the older half is dropped when it is reached.
const CAP: usize = 20_000;

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
        if records.len() >= CAP {
            records.drain(..CAP / 2);
        }
        records.push(format!(
            "{} {}: {}",
            record.level(),
            record.target(),
            record.args()
        ));
    }

    fn flush(&self) {}
}

/// Install the capturing logger (idempotent).
pub(crate) fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if log::set_boxed_logger(Box::new(Capture)).is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
        }
    });
}

/// Every captured record containing `needle` (a test's own SUPI, so records
/// from tests running in parallel are not mixed in).
pub(crate) fn captured(needle: &str) -> Vec<String> {
    RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|r| r.contains(needle))
        .cloned()
        .collect()
}
