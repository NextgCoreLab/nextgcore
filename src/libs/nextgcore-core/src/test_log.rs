//! Test-only logger that keeps every record, so a test can assert what was,
//! and was not, logged (#1026: no callback token in a log line). Enabled by the
//! `test-log` feature, which NF crates turn on in `[dev-dependencies]` only, so
//! it is never part of a daemon.
//!
//! Installed once per test binary with [`init`]. It replaces
//! `env_logger::try_init` in a crate's tests, so the two never race to be the
//! process's logger. When `RUST_LOG` is set, records are also teed to an
//! `env_logger` built from it (`is_test`, so the test harness captures them per
//! test), and `RUST_LOG=debug cargo test` output works as before.

use std::sync::{Mutex, Once, OnceLock};

static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Bound on kept records; the older half is dropped when it is reached.
const CAP: usize = 20_000;

struct Capture {
    tee: Option<env_logger::Logger>,
}

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        {
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
        if let Some(tee) = &self.tee {
            if tee.matches(record) {
                tee.log(record);
            }
        }
    }

    fn flush(&self) {
        if let Some(tee) = &self.tee {
            tee.flush();
        }
    }
}

/// Install the capturing logger (idempotent). Returns whether it is the
/// process's logger, which is false only if another logger was installed first.
pub fn init() -> bool {
    static ONCE: Once = Once::new();
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    ONCE.call_once(|| {
        let tee = std::env::var("RUST_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|spec| {
                env_logger::Builder::new()
                    .parse_filters(&spec)
                    .is_test(true)
                    .build()
            });
        let ok = log::set_boxed_logger(Box::new(Capture { tee })).is_ok();
        if ok {
            log::set_max_level(log::LevelFilter::Trace);
        }
        let _ = INSTALLED.set(ok);
    });
    *INSTALLED.get().unwrap_or(&false)
}

/// Every captured record containing `needle` (a test's own SUPI or instance
/// id, so records from tests running in parallel are not mixed in).
pub fn captured(needle: &str) -> Vec<String> {
    RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|r| r.contains(needle))
        .cloned()
        .collect()
}
