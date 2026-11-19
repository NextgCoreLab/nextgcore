//! The UDM's durable state as an append-only log with compaction (#1896).
//!
//! #1836 wrote the whole state (every SDM subscription, UDR leg, queue and told
//! am-data) as one snapshot on every change, so a write cost, and held the state
//! lock for, time growing with the subscriber count. Here a change appends one
//! line holding only the records it changed, and is durable (`fdatasync`) before
//! the caller answers. Load replays the lines in order.
//!
//! # Format
//!
//! One line per write: `<fnv1a-64 of the JSON, 16 hex digits> <JSON>\n`, where
//! the JSON is an array of operations `{"t": <kind>, "k": <key>, "v": <value>}`
//! (no `v`: the record is deleted). A write is one line, so it is applied whole
//! or not at all.
//!
//! # Torn and corrupt
//!
//! A crash during an append can leave the last line without its newline: that
//! write was never acknowledged (the fsync comes before the answer), so on load
//! it is cut off and logged ([`Opened::torn`]). Any complete line whose checksum
//! or JSON does not hold is corruption: the open fails, the file is left as it
//! is, and the UDM does not start (as `nextgcore_core::state_store` does for a
//! snapshot). An append that failed part-way is cut off before the next append
//! ([`StateLog::append`]), so it cannot run into the next line.
//!
//! # Bounds
//!
//! - Compaction: once the log exceeds twice its size after the last compaction plus
//!   [`COMPACT_SLACK`], it is rewritten as one put per live record (temporary file,
//!   fsync, rename, directory fsync). Compaction costs O(live state) and runs at
//!   most once per that many appended bytes, so the cost per write stays flat
//!   (amortised), and the log, which is the load time, stays under
//!   2 x live + slack.
//! - Cap: an append that would take the log past [`MAX_LOG_BYTES`] is refused
//!   (the caller answers 500/503 and undoes the change), so a log whose
//!   compaction keeps failing cannot grow without bound.
//! - fsync policy: `fdatasync` after every append, before the caller answers;
//!   `fsync` of the temporary file and of the directory around a compaction or a
//!   migration rename.
//!
//! # Migration
//!
//! A file holding #1836's snapshot (one JSON document, starting with `{`) opens as
//! [`Opened::Legacy`]; the caller restores from it and compacts, which rewrites the
//! file in this format atomically. A crash before the rename leaves the snapshot,
//! migrated again at the next start.

use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The slack over twice the compacted size before the log is compacted.
pub const COMPACT_SLACK: u64 = 8 * 1024 * 1024;
/// The largest the log may grow; an append past it is refused.
pub const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;
/// The most operations a compacted line holds, so no line is unbounded.
const OPS_PER_COMPACTED_LINE: usize = 256;

/// FNV-1a, 64 bit: the per-line checksum (no cryptographic claim: it detects
/// a damaged line).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `ops` as one log line.
fn line(ops: &[Value]) -> Vec<u8> {
    let json = Value::Array(ops.to_vec()).to_string();
    format!("{:016x} {json}\n", fnv1a64(json.as_bytes())).into_bytes()
}

/// What opening the log found.
#[derive(Debug)]
pub enum Opened {
    /// The operations of every line, in order. `torn` is the length of a cut-off
    /// last line (0 when there was none).
    Log { ops: Vec<Value>, torn: usize },
    /// A #1836 snapshot document, to be migrated.
    Legacy(Value),
}

/// The append-only state log at one path.
#[derive(Debug)]
pub struct StateLog {
    path: PathBuf,
    /// The length of the log as last written whole.
    len: u64,
    /// The length right after the last compaction (or the open).
    base_len: u64,
    slack: u64,
    cap: u64,
}

fn fsync_dir(path: &Path) -> std::io::Result<()> {
    match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

impl StateLog {
    /// Open the log at `path`, reading what it holds. A missing file is an empty
    /// log. A torn last line is cut off (and the file truncated to the last whole
    /// line); a damaged whole line is an error, and nothing is changed.
    pub fn open(path: &Path) -> Result<(StateLog, Opened), String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(format!(
                    "state log {} could not be read: {e}",
                    path.display()
                ))
            }
        };
        let mut log = StateLog {
            path: path.to_path_buf(),
            len: bytes.len() as u64,
            base_len: bytes.len() as u64,
            slack: COMPACT_SLACK,
            cap: MAX_LOG_BYTES,
        };
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
            let doc = serde_json::from_slice(&bytes).map_err(|e| {
                format!(
                    "state file {} is not valid JSON ({e}); refusing to overwrite it",
                    path.display()
                )
            })?;
            return Ok((log, Opened::Legacy(doc)));
        }
        let whole = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let mut ops = Vec::new();
        // Every whole line ends with its newline; the split of what precedes the
        // last one yields exactly the lines.
        let lines = if whole == 0 {
            Vec::new()
        } else {
            bytes[..whole - 1].split(|b| *b == b'\n').collect()
        };
        for (n, raw) in lines.into_iter().enumerate() {
            let parsed = std::str::from_utf8(raw)
                .ok()
                .and_then(|s| s.split_once(' '))
                .filter(|(sum, json)| {
                    u64::from_str_radix(sum, 16).ok() == Some(fnv1a64(json.as_bytes()))
                })
                .and_then(|(_, json)| serde_json::from_str::<Value>(json).ok());
            match parsed {
                Some(Value::Array(line_ops)) => ops.extend(line_ops),
                _ => {
                    return Err(format!(
                        "state log {} line {} is damaged; refusing to start over it",
                        path.display(),
                        n + 1
                    ))
                }
            }
        }
        let torn = bytes.len() - whole;
        if torn > 0 {
            log::warn!(
                "state log {}: a torn last write ({torn} bytes, never acknowledged) is cut off",
                path.display()
            );
            let file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| format!("state log {}: {e}", path.display()))?;
            file.set_len(whole as u64)
                .and_then(|()| file.sync_all())
                .map_err(|e| {
                    format!("state log {}: cutting the torn write: {e}", path.display())
                })?;
            log.len = whole as u64;
            log.base_len = whole as u64;
        }
        Ok((log, Opened::Log { ops, torn }))
    }

    /// Append `ops` as one line and `fdatasync` it. Bytes past the last whole
    /// write (a failed append's) are cut off first. On any error nothing of this
    /// write remains. Returns whether the log is now due for compaction.
    pub fn append(&mut self, ops: &[Value]) -> Result<bool, String> {
        let bytes = line(ops);
        if self.len + bytes.len() as u64 > self.cap {
            return Err(format!(
                "state log {} is at its cap ({} bytes)",
                self.path.display(),
                self.cap
            ));
        }
        let err = |e: std::io::Error| format!("state log {}: {e}", self.path.display());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(err)?;
        let on_disk = file.metadata().map_err(err)?.len();
        if on_disk == 0 && self.len == 0 {
            // A new file: its directory entry must survive a crash too.
            fsync_dir(&self.path).map_err(err)?;
        }
        if on_disk != self.len {
            file.set_len(self.len).map_err(err)?;
        }
        let written = file.write_all(&bytes).and_then(|()| file.sync_data());
        if let Err(e) = written {
            // Best effort: the next append cuts it off in any case.
            let _ = file.set_len(self.len).and_then(|()| file.sync_data());
            return Err(err(e));
        }
        self.len += bytes.len() as u64;
        Ok(self.len > self.base_len.saturating_mul(2) + self.slack)
    }

    /// Rewrite the log as `ops` (one put per live record), atomically.
    pub fn compact(&mut self, ops: &[Value]) -> Result<(), String> {
        let err = |e: std::io::Error| format!("state log {} compaction: {e}", self.path.display());
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "state".to_string());
        let tmp = self.path.with_file_name(format!(".{name}.compact.tmp"));
        let mut len = 0u64;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(err)?;
            for chunk in ops.chunks(OPS_PER_COMPACTED_LINE) {
                let bytes = line(chunk);
                file.write_all(&bytes).map_err(err)?;
                len += bytes.len() as u64;
            }
            file.sync_all().map_err(err)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).map_err(err)?;
        fsync_dir(&self.path).map_err(err)?;
        self.len = len;
        self.base_len = len;
        Ok(())
    }

    /// The log's length as last written whole.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing is written yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Compaction slack and cap other than the defaults (tests).
    #[cfg(test)]
    pub fn set_bounds(&mut self, slack: u64, cap: u64) {
        self.slack = slack;
        self.cap = cap;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "udm-log-{tag}-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn put(k: &str, v: Value) -> Value {
        json!({"t": "sub", "k": k, "v": v})
    }

    fn ops_of(path: &Path) -> Vec<Value> {
        match StateLog::open(path).expect("opens").1 {
            Opened::Log { ops, .. } => ops,
            Opened::Legacy(_) => panic!("not a log"),
        }
    }

    /// **#1896, torn vs corrupt.** A last line cut short by a crash (no newline) is
    /// dropped, the file is truncated to the last whole line, and appending goes
    /// on cleanly. A whole line whose checksum does not hold fails the open and
    /// leaves the file untouched.
    ///
    /// REVERT-VERIFIED: with the torn tail not cut off, the open fails ("a torn
    /// last write is dropped"); with the checksum not checked, the damaged line
    /// opens ("a damaged line fails the start").
    #[test]
    fn a_torn_last_write_is_dropped_and_a_damaged_line_fails_the_start_1896() {
        let path = temp_path("torn");
        let (mut log, _) = StateLog::open(&path).expect("new");
        log.append(&[put("a", json!(1))]).expect("a");
        log.append(&[put("b", json!(2)), put("c", json!(3))])
            .expect("bc");
        let whole = std::fs::metadata(&path).expect("meta").len();
        let mut f = OpenOptions::new().append(true).open(&path).expect("open");
        f.write_all(b"0123456789abcdef [{\"t\":\"sub\",\"k\":\"d\"")
            .expect("torn");
        drop(f);

        let (mut log, opened) = StateLog::open(&path).expect("a torn last write is dropped");
        let Opened::Log { ops, torn } = opened else {
            panic!("log")
        };
        assert_eq!(
            ops,
            vec![put("a", json!(1)), put("b", json!(2)), put("c", json!(3))]
        );
        assert!(torn > 0);
        assert_eq!(
            std::fs::metadata(&path).expect("meta").len(),
            whole,
            "truncated"
        );
        log.append(&[put("d", json!(4))]).expect("d");
        assert_eq!(ops_of(&path).len(), 4, "appending goes on cleanly");

        // One byte of the first line's JSON changes: "v":1 becomes "v":7.
        let mut bytes = std::fs::read(&path).expect("read");
        let first_line_end = bytes.iter().position(|b| *b == b'\n').expect("nl");
        let digit = bytes[..first_line_end]
            .windows(5)
            .position(|w| w == b"\"v\":1")
            .expect("the value")
            + 4;
        bytes[digit] = b'7';
        std::fs::write(&path, &bytes).expect("write");
        let err = StateLog::open(&path).expect_err("a damaged line fails the start");
        assert!(err.contains("line 1"), "{err}");
        assert_eq!(std::fs::read(&path).expect("read"), bytes, "left as it is");
        let _ = std::fs::remove_file(&path);
    }

    /// **#1896, a failed append leaves nothing.** Bytes a failed append left past
    /// the last whole write (here written behind the log's back) are cut off by the
    /// next append, so they cannot run into its line, and the log replays clean.
    ///
    /// REVERT-VERIFIED: with the length check before the append skipped, the open
    /// fails on the merged line ("cut off before the next append").
    #[test]
    fn a_partial_write_is_cut_off_before_the_next_append_1896() {
        let path = temp_path("partial");
        let (mut log, _) = StateLog::open(&path).expect("new");
        log.append(&[put("a", json!(1))]).expect("a");
        let mut f = OpenOptions::new().append(true).open(&path).expect("open");
        f.write_all(b"00000000000000ff [{\"t\":").expect("partial");
        drop(f);
        log.append(&[put("b", json!(2))]).expect("b");
        let (_, opened) = StateLog::open(&path).expect("cut off before the next append");
        let Opened::Log { ops, torn } = opened else {
            panic!("log")
        };
        assert_eq!(
            (ops, torn),
            (vec![put("a", json!(1)), put("b", json!(2))], 0)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// **#1896, bounds.** Appends report the log due for compaction once it is past
    /// twice its compacted size plus the slack; compacting rewrites it to the live
    /// records, which replay to the same state. An append past the cap is refused
    /// and leaves the log as it was.
    ///
    /// REVERT-VERIFIED: with the trigger never reporting due, the log is never
    /// compacted ("compacted"); with the cap not checked, the over-cap append is
    /// written ("refused at the cap").
    #[test]
    fn the_log_is_compacted_and_capped_1896() {
        let path = temp_path("compact");
        let (mut log, _) = StateLog::open(&path).expect("new");
        log.set_bounds(1024, 64 * 1024);
        let mut compactions = 0;
        for n in 0..300 {
            let due = log
                .append(&[put(&format!("k{}", n % 10), json!(n))])
                .expect("append");
            if due {
                let live: Vec<Value> = (0..10)
                    .map(|k| {
                        let last = (0..=n).rev().find(|v| v % 10 == k).unwrap_or(k);
                        put(&format!("k{k}"), json!(last))
                    })
                    .filter(|op| op["v"].as_u64().is_some_and(|v| v <= n as u64))
                    .collect();
                log.compact(&live).expect("compact");
                compactions += 1;
            }
            assert!(log.len() <= 2 * 600 + 1024 + 200, "bounded: {}", log.len());
        }
        assert!(compactions > 0, "compacted");
        let mut state = std::collections::BTreeMap::new();
        for op in ops_of(&path) {
            state.insert(op["k"].as_str().expect("k").to_string(), op["v"].clone());
        }
        let want: std::collections::BTreeMap<String, Value> =
            (0..10).map(|k| (format!("k{k}"), json!(290 + k))).collect();
        assert_eq!(state, want, "replays to the same state");

        let before = std::fs::read(&path).expect("read");
        log.set_bounds(1024, log.len() + 10);
        assert!(
            log.append(&[put("big", json!("x".repeat(100)))]).is_err(),
            "refused at the cap"
        );
        assert_eq!(std::fs::read(&path).expect("read"), before);
        let _ = std::fs::remove_file(&path);
    }

    /// A #1836 snapshot document opens as legacy, for migration.
    #[test]
    fn a_snapshot_document_opens_as_legacy_1896() {
        let path = temp_path("legacy");
        std::fs::write(&path, b"{\"legs\":{}}").expect("write");
        assert!(matches!(
            StateLog::open(&path).expect("opens").1,
            Opened::Legacy(v) if v == json!({"legs": {}})
        ));
        std::fs::write(&path, b"{\"legs\":").expect("write");
        assert!(StateLog::open(&path).is_err(), "a damaged snapshot fails");
        let _ = std::fs::remove_file(&path);
    }

    /// A record shaped as the UDM writes it: an SDM subscription (`n`), its leg and
    /// its told am-data, each key fixed-width so every size is the same.
    fn records(n: usize) -> [Value; 3] {
        let supi = format!("imsi-00101{n:010}");
        [
            json!({"t": "sub", "k": format!("{n:036}"), "v": {
                "id": format!("{n:036}"), "supi": supi, "nfInstanceId": "amf-1896",
                "callbackReference": format!(
                    "http://amf.example:7777/namf-callback/v1/{supi}/sdmsubscription-notify/{n:032x}"),
                "monitoredResourceUris": [format!("/nudm-sdm/v2/{supi}/am-data")]}}),
            json!({"t": "leg", "k": supi, "v": {
                "subscriptionPath": format!("/nudr-dr/v2/subscription-data/subs-to-notify/{n:010}"),
                "token": format!("{n:032x}"),
                "callbackReference": format!(
                    "http://udm.example:7777/nudm-callback/v1/{supi}/udr-data-change/{n:032x}"),
                "expiry": "2026-11-19T12:00:00Z"}}),
            json!({"t": "told", "k": supi, "v": {"doc": {
                "gpsis": [format!("msisdn-{n:010}")],
                "subscribedUeAmbr": {"uplink": "100 Mbps", "downlink": "200 Mbps"},
                "nssai": {"defaultSingleNssais": [{"sst": 1}]}}, "seq": 0, "resync": false}}),
        ]
    }

    /// The bytes this process has passed to `write(2)` so far (Linux
    /// `/proc/self/io` `wchar`).
    fn written_so_far() -> u64 {
        std::fs::read_to_string("/proc/self/io")
            .ok()
            .and_then(|io| {
                io.lines()
                    .find_map(|l| l.strip_prefix("wchar: "))
                    .and_then(|n| n.trim().parse().ok())
            })
            .unwrap_or(0)
    }

    /// (log bytes per write, bytes written to disk over the writes, median µs per
    /// write, load ms) for a log holding `live` subscribers, measured over `writes`
    /// writes of one new subscriber each.
    fn measure(live: usize, writes: usize) -> (u64, u64, f64, f64) {
        let path = temp_path(&format!("load-{live}"));
        let (mut log, _) = StateLog::open(&path).expect("new");
        let base: Vec<Value> = (0..live).flat_map(records).collect();
        log.compact(&base).expect("base");
        let before = log.len();
        let wchar = written_so_far();
        let mut each: Vec<f64> = Vec::with_capacity(writes);
        for n in live..live + writes {
            let started = std::time::Instant::now();
            log.append(&records(n)[..1]).expect("append");
            each.push(started.elapsed().as_secs_f64() * 1e6);
        }
        let wrote = written_so_far().saturating_sub(wchar);
        // The median: one slow fsync on a busy host does not move it.
        each.sort_by(f64::total_cmp);
        let per_write_us = each[writes / 2];
        let bytes = (log.len() - before) / writes as u64;
        let started = std::time::Instant::now();
        let (_, opened) = StateLog::open(&path).expect("load");
        let load_ms = started.elapsed().as_secs_f64() * 1e3;
        let Opened::Log { ops, .. } = opened else {
            panic!("log")
        };
        assert_eq!(ops.len(), 3 * live + writes);
        let _ = std::fs::remove_file(&path);
        (bytes, wrote, per_write_us, load_ms)
    }

    /// **#1896 load bound.** With 10 000 subscribers (each an SDM subscription, a
    /// UDR leg and told am-data) a write appends exactly as many bytes as with 100,
    /// and the process writes about that much to disk (`wchar`): one record, not the
    /// state. The log of 10 000 loads within a bound. The time per write (one
    /// `fdatasync`) and #1836's whole-snapshot write at 10 000 are measured beside
    /// it for the PR, and printed (`--nocapture`). They are not asserted, because a
    /// busy host's fsync latency swamps them.
    ///
    /// REVERT-VERIFIED: with `append` rewriting the whole file each time (as
    /// #1836's snapshot did), the 10 000-subscriber writes put the whole log on
    /// disk each time ("flat").
    #[test]
    fn a_write_stays_flat_at_10k_subscribers_and_the_load_is_bounded_1896() {
        let writes = 100;
        let (bytes_100, wrote_100, us_100, load_100) = measure(100, writes);
        let (bytes_10k, wrote_10k, us_10k, load_10k) = measure(10_000, writes);
        // #1836: one whole-state snapshot per write, at 10 000.
        let doc = Value::Array((0..10_000).flat_map(records).collect());
        let path = temp_path("snapshot");
        let started = std::time::Instant::now();
        for _ in 0..5 {
            nextgcore_core::state_store::write_snapshot(&path, &doc).expect("snapshot");
        }
        let snapshot_us = started.elapsed().as_secs_f64() * 1e6 / 5.0;
        let snapshot_bytes = std::fs::metadata(&path).expect("meta").len();
        let _ = std::fs::remove_file(&path);
        eprintln!(
            "#1896 load: 100 subs: {bytes_100} B/write ({} B written), {us_100:.0} us/write, \
             load {load_100:.1} ms; 10k subs: {bytes_10k} B/write ({} B written), \
             {us_10k:.0} us/write, load {load_10k:.1} ms; #1836 snapshot at 10k: \
             {snapshot_bytes} B/write, {snapshot_us:.0} us/write",
            wrote_100 / writes as u64,
            wrote_10k / writes as u64,
        );
        assert_eq!(bytes_10k, bytes_100, "flat: the same bytes per write");
        assert!(bytes_10k < 1024, "one record: {bytes_10k} B");
        if cfg!(target_os = "linux") {
            // 100 records' worth, with room for whatever else this process wrote
            // meanwhile; the whole log at 10k is 12 MB per write.
            assert!(
                wrote_10k < 4 * 1024 * 1024,
                "flat: {wrote_10k} B written for {writes} writes at 10k"
            );
        }
        assert!(load_10k < 10_000.0, "10k loads in {load_10k:.0} ms");
    }
}
