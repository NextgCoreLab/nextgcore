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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};

static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Bound on kept records; the older half is dropped when it is reached.
const CAP: usize = 20_000;

/// Active [`Watch`]es: id, needle, and the records that matched it (#1360).
///
/// [`RECORDS`] is shared by every test in the binary and evicts its older half
/// at [`CAP`]. `tracing`'s `log` feature forwards hyper/h2 trace events here, so
/// parallel tests can push 10 000 records between two polls. A test that reads
/// [`captured`] can then find nothing, even though its record was logged. That
/// was the #1360 flake. A watch keeps its own copy of each matching record,
/// outside the shared buffer, so eviction never reaches it.
static WATCHES: Mutex<Vec<(u64, String, Vec<String>)>> = Mutex::new(Vec::new());
/// Bound on the records one watch keeps. It is only reached by a runaway
/// logger, and the newest records are kept.
const WATCH_CAP: usize = 10_000;
static NEXT_WATCH: AtomicU64 = AtomicU64::new(0);

struct Capture {
    tee: Option<env_logger::Logger>,
}

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{} {}: {}", record.level(), record.target(), record.args());
        {
            let mut watches = WATCHES.lock().unwrap_or_else(|e| e.into_inner());
            for (_, needle, kept) in watches.iter_mut() {
                if line.contains(needle.as_str()) {
                    if kept.len() >= WATCH_CAP {
                        kept.drain(..WATCH_CAP / 2);
                    }
                    kept.push(line.clone());
                }
            }
        }
        {
            let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
            if records.len() >= CAP {
                records.drain(..CAP / 2);
            }
            records.push(line);
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

/// Keep every record containing `needle` from now until the watch drops, safe
/// from the shared buffer's eviction (#1360).
///
/// Prefer this to [`captured`] when a test asserts on a record that a
/// background task logs: a connection driver, an accept loop. Register the
/// watch BEFORE the action that logs. Records logged earlier are not in it.
/// Requires [`init`].
pub fn watch(needle: impl Into<String>) -> Watch {
    let id = NEXT_WATCH.fetch_add(1, Ordering::Relaxed);
    WATCHES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((id, needle.into(), Vec::new()));
    Watch { id }
}

/// A registered needle; see [`watch`]. Unregisters on drop.
#[derive(Debug)]
pub struct Watch {
    id: u64,
}

impl Watch {
    /// Every record that matched since the watch was registered, oldest first.
    pub fn records(&self) -> Vec<String> {
        WATCHES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(id, _, _)| *id == self.id)
            .map(|(_, _, kept)| kept.clone())
            .unwrap_or_default()
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        WATCHES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(id, _, _)| *id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1360: a record survives a full eviction cycle of the shared buffer
    /// when it is watched. Without the watch, `captured` loses it.
    #[test]
    fn a_watched_record_survives_eviction_of_the_shared_buffer() {
        assert!(init(), "premise: the capture logger");
        let needle = "test-log-1360-watched-record";
        let w = watch(needle);
        log::warn!("{needle}");
        for i in 0..CAP {
            log::trace!("test-log-1360 noise {i}");
        }
        assert!(
            captured(needle).is_empty(),
            "premise: the shared buffer evicted the record"
        );
        let kept = w.records();
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert!(kept[0].starts_with("WARN ") && kept[0].contains(needle));
    }

    /// A watch sees only what was logged while it was registered, and stops
    /// collecting once dropped.
    #[test]
    fn a_watch_is_scoped_to_its_lifetime() {
        assert!(init(), "premise: the capture logger");
        let needle = "test-log-1360-scoped";
        log::info!("{needle} before");
        let w = watch(needle);
        log::info!("{needle} during");
        let kept = w.records();
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert!(kept[0].ends_with("during"));
        drop(w);
        log::info!("{needle} after");
        assert!(
            WATCHES.lock().unwrap().iter().all(|(_, n, _)| n != needle),
            "the dropped watch is unregistered"
        );
    }
}
