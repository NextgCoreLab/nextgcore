//! Durable JSON snapshot store for NF runtime state (issue #66).
//!
//! Several NFs persist their long-lived runtime state — the NRF's NF registry,
//! the NSSF's slice configuration, the NSACF's slice quotas, the UDR's
//! subscriber registrations — as a full-store JSON snapshot rewritten on every
//! mutation, reloaded at boot. Before this module each of them carried its own
//! copy of that logic: `write_atomic`, `persist` and `load` were byte-identical
//! across nrfd, nssfd and udrd (bar the NF name in the log line), with a fourth
//! variant in nsacfd.
//!
//! That mattered for more than tidiness. All four shared one defect:
//!
//! **A corrupt snapshot was treated as "no state".** `load` logged a warning and
//! returned, leaving the store empty, and boot continued. The very next mutation
//! called `persist`, which rewrote the file from the now-empty snapshot — turning
//! a recoverable corruption into permanent, silent data loss. For the UDR that is
//! every subscriber's AMF and SMF registration; for the NRF, the whole NF
//! registry. The operator's evidence is destroyed by the process that failed to
//! read it.
//!
//! So [`StateStore`] distinguishes three cases, and the middle one is the point:
//!
//! | file | meaning | behaviour |
//! |---|---|---|
//! | absent | legitimate first boot | empty state, persisting enabled |
//! | present, valid | normal restart | state restored, persisting enabled |
//! | present, invalid | a human must look | state empty, **persisting REFUSED** |
//!
//! In the third case the store is *poisoned*: [`StateStore::persist`] returns an
//! error and writes nothing, so the unreadable file survives for inspection or
//! recovery. Callers that can fail startup should; those that cannot at least
//! cannot destroy anything.

use std::path::{Path, PathBuf};

/// What went wrong reading or writing a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    /// The file exists but could not be read.
    #[error("state file {path} could not be read: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file exists but does not hold valid JSON.
    #[error(
        "state file {path} is not valid JSON ({source}); refusing to overwrite it, because \
         rewriting it from empty state would destroy whatever is recoverable"
    )]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// Writing failed.
    #[error("state file {path} could not be written: {source}")]
    WriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A previous load failed, so writing is refused to preserve the file.
    #[error(
        "refusing to persist to {path}: its previous contents could not be read, and \
         overwriting them with the current (empty) state would make the loss permanent. \
         Move the file aside to start fresh."
    )]
    Poisoned { path: PathBuf },
}

/// The outcome of loading a snapshot.
#[derive(Debug)]
pub enum Loaded {
    /// No path configured, or the file does not exist yet. Not an error: this is
    /// a first boot, or persistence is disabled.
    Absent,
    /// A snapshot document was read.
    Snapshot(serde_json::Value),
}

/// A durable JSON snapshot file, or no persistence at all when `path` is `None`.
#[derive(Debug, Default)]
pub struct StateStore {
    path: Option<PathBuf>,
    /// Set when a load failed, which makes [`StateStore::persist`] refuse.
    poisoned: bool,
}

impl StateStore {
    /// A store with no persistence: loads are [`Loaded::Absent`] and persists are
    /// no-ops. This is the default for every NF that configures no state file, so
    /// the memory-only behaviour is preserved exactly.
    pub fn disabled() -> Self {
        Self {
            path: None,
            poisoned: false,
        }
    }

    /// A store backed by `path`.
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            poisoned: false,
        }
    }

    /// The configured path, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether this store persists anything.
    pub fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Whether a load failed and writes are therefore refused.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Read the snapshot.
    ///
    /// An absent file is [`Loaded::Absent`], not an error — that is a first boot.
    /// An unreadable or malformed file is an error **and poisons the store**, so
    /// a later [`StateStore::persist`] cannot overwrite it.
    pub fn load(&mut self) -> Result<Loaded, StateStoreError> {
        let Some(path) = self.path.clone() else {
            return Ok(Loaded::Absent);
        };
        // #2170: temporaries a crashed write left behind, before the first read.
        sweep_stale_temps(&path, STALE_TEMP_AGE);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Absent),
            Err(source) => {
                self.poisoned = true;
                return Err(StateStoreError::Unreadable { path, source });
            }
        };
        match serde_json::from_str(&content) {
            Ok(doc) => Ok(Loaded::Snapshot(doc)),
            Err(source) => {
                self.poisoned = true;
                Err(StateStoreError::Corrupt { path, source })
            }
        }
    }

    /// Write `doc` as the new snapshot, atomically.
    ///
    /// A no-op when no path is configured. Refused when a previous load failed.
    pub fn persist(&self, doc: &serde_json::Value) -> Result<(), StateStoreError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if self.poisoned {
            return Err(StateStoreError::Poisoned {
                path: path.to_path_buf(),
            });
        }
        write_atomic(path, doc).map_err(|source| StateStoreError::WriteFailed {
            path: path.to_path_buf(),
            source,
        })
    }

    /// #2151: take the snapshot and write it under one lock (this path's write
    /// lock), so concurrent persists publish in snapshot order: the file last
    /// written holds the newest snapshot. [`StateStore::persist`] of a document
    /// taken beforehand can publish an older snapshot over a newer one.
    ///
    /// `snapshot` runs with the path's write lock held: it must not persist,
    /// and its callers must hold no write guard it needs (the rule every
    /// `persist` here already documents).
    pub fn persist_with(
        &self,
        snapshot: impl FnOnce() -> serde_json::Value,
    ) -> Result<(), StateStoreError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if self.poisoned {
            return Err(StateStoreError::Poisoned {
                path: path.to_path_buf(),
            });
        }
        write_snapshot_with(path, snapshot)
    }
}

/// #2151: [`write_snapshot`] of the document `snapshot` returns, taken under
/// `path`'s write lock, so concurrent writers publish in snapshot order (see
/// [`StateStore::persist_with`]). The same contract as [`write_snapshot`].
pub fn write_snapshot_with(
    path: &Path,
    snapshot: impl FnOnce() -> serde_json::Value,
) -> Result<(), StateStoreError> {
    // #2170: group commit. Concurrent persists of one path share writes: each
    // caller is numbered; one at a time leads, takes the snapshot (after every
    // waiting caller's mutation, since each mutated before calling) and writes
    // it; every caller whose number that write covers returns its result. So a
    // caller still returns only once a durable write includes its change, in
    // snapshot order, but N concurrent callers cost about two writes, not N
    // queued ones (measured on #2170: p99 under 8 writers went from ~1 s to the
    // single-write cost).
    let group = commit_group(path);
    let (state, turn) = &*group;
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    st.requested += 1;
    let mine = st.requested;
    loop {
        if let Some(result) = st.take_result(mine) {
            return result.map_err(|e| StateStoreError::WriteFailed {
                path: path.to_path_buf(),
                source: std::io::Error::other(e),
            });
        }
        if !st.leading {
            st.leading = true;
            let covers = st.requested;
            drop(st);
            // #2181 (R42): if `snapshot` (or the write) panics, the guard ends
            // the lead on unwind (clears `leading`, fails every caller this
            // write covered, wakes the waiters), so the path is not wedged for
            // the rest of the process.
            let mut lead = LeadGuard {
                group: &group,
                covers,
                mine,
                done: false,
            };
            let written = {
                let lock = path_write_lock(path);
                let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
                let doc = snapshot();
                write_atomic_locked(path, &doc)
            };
            lead.finish(written.as_ref().map(|_| ()).map_err(|e| e.to_string()));
            return written.map_err(|source| StateStoreError::WriteFailed {
                path: path.to_path_buf(),
                source,
            });
        }
        st = turn.wait(st).unwrap_or_else(|e| e.into_inner());
    }
}

type CommitGroupRef = std::sync::Arc<(std::sync::Mutex<CommitGroup>, std::sync::Condvar)>;

/// #2181: ends a group-commit lead, normally ([`LeadGuard::finish`]) or, if
/// the leader unwinds, from `Drop`, recording a failure for the callers it
/// covered.
struct LeadGuard<'a> {
    group: &'a CommitGroupRef,
    covers: u64,
    mine: u64,
    done: bool,
}

impl LeadGuard<'_> {
    fn finish(&mut self, result: Result<(), String>) {
        self.done = true;
        let (state, turn) = &**self.group;
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.leading = false;
        st.record(self.covers, self.mine, result);
        turn.notify_all();
    }
}

impl Drop for LeadGuard<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.finish(Err(
                "the snapshot or its write panicked; nothing was written".to_string(),
            ));
        }
    }
}

/// #2170: the group-commit state of one path (see [`write_snapshot_with`]).
#[derive(Default)]
struct CommitGroup {
    /// Callers numbered so far.
    requested: u64,
    /// A caller is taking the snapshot and writing it.
    leading: bool,
    /// Writes whose covered callers have not all read their result yet:
    /// (first caller covered, last caller covered, result, callers yet to
    /// read). #2181: an entry is dropped only once every covered caller has
    /// read it, so a slow waiter always finds its own write's result.
    pending: std::collections::VecDeque<(u64, u64, Result<(), String>, u64)>,
    /// The last caller any write covered.
    flushed: u64,
}

impl CommitGroup {
    /// Record the write that covered every caller up to `covers`, led by
    /// `leader` (who takes its result directly, not from here).
    fn record(&mut self, covers: u64, leader: u64, result: Result<(), String>) {
        let from = self.flushed + 1;
        self.flushed = covers;
        let waiting =
            (covers + 1 - from).saturating_sub(u64::from((from..=covers).contains(&leader)));
        if waiting > 0 {
            self.pending.push_back((from, covers, result, waiting));
        }
    }

    /// The result of the write that covered caller `n`, once there is one,
    /// consumed: each covered caller reads it once.
    fn take_result(&mut self, n: u64) -> Option<Result<(), String>> {
        if n > self.flushed {
            return None;
        }
        let Some(at) = self
            .pending
            .iter()
            .position(|(from, to, _, _)| (*from..=*to).contains(&n))
        else {
            // Unreachable by construction; fail closed rather than report a
            // write that may not have happened.
            return Some(Err(
                "the result of this write is no longer known".to_string()
            ));
        };
        let entry = &mut self.pending[at];
        entry.3 -= 1;
        let result = entry.2.clone();
        if entry.3 == 0 {
            self.pending.remove(at);
        }
        Some(result)
    }
}

fn commit_group(
    path: &Path,
) -> std::sync::Arc<(std::sync::Mutex<CommitGroup>, std::sync::Condvar)> {
    type Groups = std::collections::HashMap<
        PathBuf,
        std::sync::Arc<(std::sync::Mutex<CommitGroup>, std::sync::Condvar)>,
    >;
    static GROUPS: std::sync::OnceLock<std::sync::Mutex<Groups>> = std::sync::OnceLock::new();
    GROUPS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(path.to_path_buf())
        .or_default()
        .clone()
}

/// #2151: [`write_snapshot`] of a document numbered `seq`, skipped when this
/// process has already written `path` with a later number. For a writer that
/// hands its write to another thread (nsacfd's blocking pool), so writes can
/// finish out of order: it numbers each snapshot as it takes it, under its own
/// lock, and the older one is not renamed over the newer. `Ok(false)` when
/// skipped.
pub fn write_snapshot_numbered(
    path: &Path,
    seq: u64,
    doc: &serde_json::Value,
) -> Result<bool, StateStoreError> {
    type Written = std::collections::HashMap<PathBuf, u64>;
    static WRITTEN: std::sync::OnceLock<std::sync::Mutex<Written>> = std::sync::OnceLock::new();
    let lock = path_write_lock(path);
    let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
    {
        let written = WRITTEN
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if written.get(path).is_some_and(|last| *last >= seq) {
            return Ok(false);
        }
    }
    write_atomic_locked(path, doc).map_err(|source| StateStoreError::WriteFailed {
        path: path.to_path_buf(),
        source,
    })?;
    WRITTEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(path.to_path_buf(), seq);
    Ok(true)
}

/// Read a snapshot from `path` without owning a [`StateStore`].
///
/// `Ok(None)` means the file does not exist — a first boot. An unreadable or
/// malformed file is an `Err`, and the caller **must not then write over it**:
/// rewriting from empty state is the data-loss path this module exists to close.
/// Callers that keep their own state struct should record the failure (see
/// [`write_snapshot`]'s contract) rather than proceeding as if the file were
/// absent.
pub fn read_snapshot(path: &Path) -> Result<Option<serde_json::Value>, StateStoreError> {
    match StateStore::new(Some(path.to_path_buf())).load()? {
        Loaded::Absent => Ok(None),
        Loaded::Snapshot(v) => Ok(Some(v)),
    }
}

/// Write `doc` to `path` as an atomic, fsynced, `0600` snapshot.
///
/// **Contract:** do not call this after [`read_snapshot`] returned an error for
/// the same path. There is no shared poison flag on this path — the caller owns
/// that decision — so calling it anyway overwrites the file whose contents could
/// not be read. Use [`StateStore`] if you want that guard enforced for you.
pub fn write_snapshot(path: &Path, doc: &serde_json::Value) -> Result<(), StateStoreError> {
    write_atomic(path, doc).map_err(|source| StateStoreError::WriteFailed {
        path: path.to_path_buf(),
        source,
    })
}

/// Write `doc` to `path` atomically: serialise, write to a sibling temporary
/// file, flush and fsync it, then rename over the target.
///
/// The fsync is what makes "atomic" mean durable rather than merely
/// well-ordered — without it a crash after the rename can leave the new name
/// pointing at unflushed content, which is exactly the corruption the caller is
/// trying to avoid. The parent directory is synced too, so the rename itself
/// survives.
///
/// The file is created `0600` on Unix. These snapshots hold subscriber
/// identifiers (the UDR's are keyed by IMSI), which is not something to leave
/// world-readable.
///
/// The temporary file is named from the full file name rather than via
/// `Path::with_extension`, which would *replace* an existing extension and so
/// map `udr.state` and `udr.json` in one directory onto the same `udr.tmp`.
///
/// #2148: concurrent writes of one path are safe. Each write has its own
/// temporary file (`.<name>.<pid>.<seq>.tmp`), so two writers never truncate
/// or interleave into one file, and one cannot rename the other's file away
/// before it is complete; and the writes of one path are serialised
/// ([`path_write_lock`]), so each rename publishes one writer's whole,
/// fsynced document.
fn write_atomic(path: &Path, doc: &serde_json::Value) -> std::io::Result<()> {
    let lock = path_write_lock(path);
    let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
    write_atomic_locked(path, doc)
}

/// [`write_atomic`], for a caller already holding `path`'s write lock.
fn write_atomic_locked(path: &Path, doc: &serde_json::Value) -> std::io::Result<()> {
    use std::io::Write;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let serialized = serde_json::to_vec_pretty(doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.{}.{seq}.tmp", std::process::id());
    let tmp = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    };

    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&serialized)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Durably record the rename itself.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

/// #2170: a temporary file older than this is a crashed write's, not one in
/// flight: a write holds its temporary for one serialise, write and fsync.
/// Another process sharing the directory (a rolling restart) may be mid-write,
/// so a fresh one is never touched.
///
/// The age is the file's mtime against this host's clock. On a network volume
/// whose clock is skewed from this host's, a fresh temporary can look old and
/// be swept; the worst case is that its writer's rename fails (ENOENT, a failed
/// persist), and the state file itself stays intact.
pub const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// #2170: remove the temporaries of `path` ([`write_atomic`]'s
/// `.<name>.<pid>.<seq>.tmp`, and the `.<name>.tmp` of before #2148) that are
/// older than `older_than`. Only this file's own temp-name pattern is matched,
/// never another file's. Returns how many were removed. Failures are logged
/// and skipped: a stale temporary is litter, not state.
pub fn sweep_stale_temps(path: &Path, older_than: std::time::Duration) -> usize {
    let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return 0;
    };
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let prefix = format!(".{file_name}.");
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(middle) = name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix("tmp"))
        else {
            continue;
        };
        // "" (the pre-#2148 `.<name>.tmp`) or "<pid>.<seq>." exactly.
        let ours = middle.is_empty()
            || middle
                .strip_suffix('.')
                .and_then(|m| m.split_once('.'))
                .is_some_and(|(pid, seq)| {
                    !pid.is_empty()
                        && !seq.is_empty()
                        && pid.bytes().all(|b| b.is_ascii_digit())
                        && seq.bytes().all(|b| b.is_ascii_digit())
                });
        if !ours {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= older_than);
        if !stale {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => log::warn!(
                "could not remove stale temporary {}: {e}",
                entry.path().display()
            ),
        }
    }
    if removed > 0 {
        log::info!(
            "removed {removed} stale temporary file(s) of {} left by an interrupted write",
            path.display()
        );
    }
    removed
}

/// #2148: the lock serialising the writes of `path` within this process.
/// Paths are compared as given; one store writes one path.
fn path_write_lock(path: &Path) -> std::sync::Arc<std::sync::Mutex<()>> {
    type Locks = std::collections::HashMap<PathBuf, std::sync::Arc<std::sync::Mutex<()>>>;
    static LOCKS: std::sync::OnceLock<std::sync::Mutex<Locks>> = std::sync::OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks.entry(path.to_path_buf()).or_default().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **#2151**: concurrent `persist_with`s publish in snapshot order. Eight
    /// threads each bump a shared generation and persist a snapshot of it
    /// (taking a varying time, as a real snapshot walking an NF's maps does)
    /// while a reader watches the file. The generation on disk never goes
    /// back, and ends at the last one. A snapshot taken outside the lock (`let
    /// doc = snap(); store.persist(&doc)`) can be renamed over a newer one.
    ///
    /// REVERT-VERIFIED: with `write_snapshot_with` taking the snapshot before
    /// the path lock, the reader sees the generation go back and `never goes
    /// back` fails.
    #[test]
    fn concurrent_persists_publish_in_snapshot_order_2151() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let dir = tmpdir("order-2151");
        let path = dir.join("nf.json");
        let generation = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                let (mut last, mut went_back) = (0u64, 0usize);
                while !done.load(Ordering::SeqCst) {
                    let g = std::fs::read(&path)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .and_then(|v| v["gen"].as_u64());
                    if let Some(g) = g {
                        if g < last {
                            went_back += 1;
                        }
                        last = last.max(g);
                    }
                }
                went_back
            })
        };
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let (path, generation) = (path.clone(), generation.clone());
                std::thread::spawn(move || {
                    let store = StateStore::new(Some(path));
                    for _ in 0..40 {
                        generation.fetch_add(1, Ordering::SeqCst);
                        store
                            .persist_with(|| {
                                let g = generation.load(Ordering::SeqCst);
                                let jitter = (g.wrapping_mul(2_654_435_761) >> 7) % 800;
                                std::thread::sleep(std::time::Duration::from_micros(jitter));
                                serde_json::json!({ "gen": g })
                            })
                            .expect("persist");
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer");
        }
        done.store(true, Ordering::SeqCst);
        let went_back = reader.join().expect("reader");
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(went_back, 0, "the generation on disk never goes back");
        assert_eq!(
            on_disk["gen"].as_u64(),
            Some(generation.load(Ordering::SeqCst)),
            "the newest snapshot is the one on disk"
        );
    }

    /// **#2170** (R42 on #2165): loading a store sweeps the temporaries a
    /// crashed write left behind, before the first read: this file's own
    /// stale `.<name>.<pid>.<seq>.tmp` and pre-#2148 `.<name>.tmp`. A fresh
    /// temporary (another process mid-write), a sibling file's and a
    /// look-alike that is not one of ours are kept.
    ///
    /// REVERT-VERIFIED: with the sweep call removed from `load`, the stale
    /// temporaries remain and the `swept` assertion fails.
    #[test]
    fn loading_sweeps_this_files_stale_temporaries_2170() {
        let dir = tmpdir("sweep-2170");
        let path = dir.join("nf.json");
        std::fs::write(&path, b"{\"v\":1}").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        let make = |name: &str, aged: bool| {
            let p = dir.join(name);
            let f = std::fs::File::create(&p).unwrap();
            if aged {
                f.set_modified(old).unwrap();
            }
            p
        };
        let stale = [
            make(".nf.json.4242.7.tmp", true),
            make(".nf.json.tmp", true),
        ];
        let kept = [
            make(".nf.json.4243.8.tmp", false),   // in flight elsewhere
            make(".other.json.4242.7.tmp", true), // a sibling store's
            make(".nf.json.backup.tmp", true),    // not our pattern
            make("nf.json.4242.7.tmp", true),     // not hidden: not ours
        ];
        let loaded = StateStore::new(Some(path.clone())).load().expect("load");
        let left = |p: &PathBuf| p.exists();
        let swept = stale.iter().filter(|p| !left(p)).count();
        let kept_all = kept.iter().all(left);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(loaded, Loaded::Snapshot(_)));
        assert_eq!(swept, 2, "swept");
        assert!(
            kept_all,
            "fresh, sibling and look-alike temporaries are kept"
        );
    }

    /// **#2170** (R42 on #2165) item 3: concurrent `persist_with`s of one path
    /// share writes (group commit). 8 threads × 20 persists each succeed, the
    /// file ends at the last generation, and far fewer snapshots are taken
    /// than persists made: a caller that arrives while a write is out is
    /// covered by the next one rather than queuing a write of its own.
    ///
    /// REVERT-VERIFIED: with `write_snapshot_with` back to one locked write
    /// per call, every persist takes its own snapshot and `coalesced` fails.
    #[test]
    fn concurrent_persists_share_writes_2170() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::sync::Arc;
        let dir = tmpdir("group-2170");
        let path = dir.join("nf.json");
        let generation = Arc::new(AtomicU64::new(0));
        let snapshots = Arc::new(AtomicUsize::new(0));
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let (path, generation, snapshots) =
                    (path.clone(), generation.clone(), snapshots.clone());
                std::thread::spawn(move || {
                    let store = StateStore::new(Some(path));
                    for _ in 0..20 {
                        generation.fetch_add(1, Ordering::SeqCst);
                        store
                            .persist_with(|| {
                                snapshots.fetch_add(1, Ordering::SeqCst);
                                let g = generation.load(Ordering::SeqCst);
                                serde_json::json!({ "gen": g, "pad": vec![g; 20_000] })
                            })
                            .expect("persist");
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer");
        }
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            on_disk["gen"].as_u64(),
            Some(generation.load(Ordering::SeqCst))
        );
        let taken = snapshots.load(Ordering::SeqCst);
        assert!(taken < 160, "coalesced: {taken} snapshots for 160 persists");
    }

    /// **#2181** (R42 on #2181): a snapshot that panics while its caller leads
    /// does not wedge the path. Its callers get an error (or the panic), none an
    /// `Ok`, and a later persist of the same path completes. Before, `leading`
    /// stayed set on unwind and every later persist waited forever.
    ///
    /// REVERT-VERIFIED: with the guard's `Drop` doing nothing, the later persist
    /// never completes and `a later persist completes` fails on its timeout.
    #[test]
    fn a_panicking_leader_does_not_wedge_the_path_2181() {
        use std::sync::mpsc;
        let dir = tmpdir("panic-2181");
        let path = dir.join("nf.json");
        // A slow, good write leads first, so the two panicking callers arrive
        // while it is out and one of them leads the next write, covering both.
        let slow = {
            let path = path.clone();
            std::thread::spawn(move || {
                StateStore::new(Some(path)).persist_with(|| {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    serde_json::json!({ "v": 0 })
                })
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Each reports Some(is_ok) when it returns, None when it panicked.
        let (done_tx, done_rx) = mpsc::channel();
        for _ in 0..2 {
            let (path, done_tx) = (path.clone(), done_tx.clone());
            std::thread::spawn(move || {
                let r = std::panic::catch_unwind(|| {
                    StateStore::new(Some(path)).persist_with(|| panic!("a poisoned lock"))
                });
                let _ = done_tx.send(r.ok().map(|r| r.is_ok()));
            });
        }
        assert!(slow.join().expect("slow writer").is_ok());
        for _ in 0..2 {
            // Either it led and panicked, or it was covered and got an error;
            // either way it returns, and never with Ok.
            let outcome = done_rx.recv_timeout(std::time::Duration::from_secs(5));
            assert!(
                matches!(outcome, Ok(None) | Ok(Some(false))),
                "a panicking or covered caller returns, and not with Ok: {outcome:?}"
            );
        }
        let (tx, rx) = mpsc::channel();
        {
            let path = path.clone();
            std::thread::spawn(move || {
                let r = StateStore::new(Some(path)).persist_with(|| serde_json::json!({ "v": 2 }));
                let _ = tx.send(r.is_ok());
            });
        }
        let later = rx.recv_timeout(std::time::Duration::from_secs(5));
        let on_disk = std::fs::read(&path).ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(later, Ok(true), "a later persist completes");
        let on_disk: serde_json::Value = serde_json::from_slice(&on_disk.unwrap()).unwrap();
        assert_eq!(on_disk["v"], 2);
    }

    /// **#2188** (R42 on #2181): the per-write result map drains. After 8
    /// threads × 40 concurrent persists of one path, every fifth of them led by a
    /// snapshot that panics, every result has been read and dropped and no lead
    /// is left open: the path's group holds nothing. A result kept for a caller
    /// that never reads it would grow without bound, silently.
    ///
    /// REVERT-VERIFIED: with `waiting` one too many (the leader counted among
    /// the callers still to read), entries are never drained and the `drained`
    /// assertion fails.
    #[test]
    fn the_group_commit_result_map_drains_2188() {
        let dir = tmpdir("drain-2188");
        let path = dir.join("nf.json");
        let writers: Vec<_> = (0..8u64)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..40u64 {
                        let panics = (w * 40 + i) % 5 == 0;
                        let path = path.clone();
                        let _ = std::panic::catch_unwind(move || {
                            StateStore::new(Some(path)).persist_with(|| {
                                if panics {
                                    panic!("a poisoned lock");
                                }
                                serde_json::json!({ "w": w, "i": i })
                            })
                        });
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer");
        }
        let group = commit_group(&path);
        let (pending, leading, requested, flushed) = {
            let st = group.0.lock().unwrap();
            (st.pending.len(), st.leading, st.requested, st.flushed)
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(requested, 320, "every persist was numbered");
        assert_eq!(flushed, requested, "every caller was covered by a write");
        assert!(!leading, "no lead is left open");
        assert_eq!(pending, 0, "drained: every result was read and dropped");
    }

    /// **#2170**: a write that fails fails every caller it covered, not just
    /// its leader: none returns `Ok` for a change that is not on disk.
    ///
    /// REVERT-VERIFIED: with `result_for` answering `Ok` for every covered
    /// caller, a waiting caller returns `Ok` and `every caller` fails.
    #[test]
    fn a_failed_shared_write_fails_every_caller_it_covered_2170() {
        let dir = tmpdir("group-fail-2170");
        // The parent "directory" is a file, so every write fails.
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("nf.json");
        let results: Vec<bool> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    StateStore::new(Some(path))
                        .persist_with(|| {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            serde_json::json!({ "v": 1 })
                        })
                        .is_err()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            results.iter().all(|failed| *failed),
            "every caller sees the failure"
        );
    }

    /// **#2151**: a numbered write older than one already written is skipped.
    #[test]
    fn an_older_numbered_snapshot_is_not_written_over_a_newer_2151() {
        let dir = tmpdir("numbered-2151");
        let path = dir.join("nsacf.json");
        assert_eq!(
            write_snapshot_numbered(&path, 2, &serde_json::json!({"n": 2})).ok(),
            Some(true)
        );
        assert_eq!(
            write_snapshot_numbered(&path, 1, &serde_json::json!({"n": 1})).ok(),
            Some(false)
        );
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(on_disk["n"], 2, "the newer one stays");
    }

    /// **#2148** (R42 on #2128): many threads persisting one path at once each
    /// succeed, and the file always holds one writer's whole document. With one
    /// fixed temporary file, two writers truncated and interleaved into it and
    /// one renamed it away under the other (ENOENT, or a torn snapshot).
    ///
    /// REVERT-VERIFIED: with the temporary name back to `.<name>.tmp` and the
    /// path lock removed, writes fail ("every persist succeeds") or the file
    /// holds a torn document.
    #[test]
    fn concurrent_persists_of_one_path_never_tear_2148() {
        let dir = tmpdir("concurrent-2148");
        let path = dir.join("nef.json");
        let writers: Vec<_> = (0..8u64)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = StateStore::new(Some(path.clone()));
                    let mut failures = Vec::new();
                    let mut torn = 0;
                    for round in 0..40u64 {
                        // Large enough that a write is many syscalls.
                        let doc = serde_json::json!({
                            "writer": w,
                            "round": round,
                            "pad": vec![format!("{w}-{round}"); 2000],
                        });
                        if let Err(e) = store.persist(&doc) {
                            failures.push(e.to_string());
                        }
                        match std::fs::read(&path)
                            .ok()
                            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        {
                            Some(v) if v["pad"].as_array().map(Vec::len) == Some(2000) => {}
                            _ => torn += 1,
                        }
                    }
                    (failures, torn)
                })
            })
            .collect();
        let mut failures = Vec::new();
        let mut torn = 0;
        for w in writers {
            let (f, t) = w.join().expect("writer");
            failures.extend(f);
            torn += t;
        }
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "every persist succeeds: {failures:?}");
        assert_eq!(torn, 0, "the file always holds one whole document");
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ngc-state-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    /// Issue #66: a store with no configured path behaves exactly as before —
    /// nothing is read, nothing is written. Every NF that configures no state
    /// file relies on this, so the memory-only default is preserved.
    #[test]
    fn disabled_store_reads_nothing_and_writes_nothing() {
        let mut s = StateStore::disabled();
        assert!(!s.is_enabled());
        assert!(matches!(s.load().expect("no path is fine"), Loaded::Absent));
        s.persist(&serde_json::json!({"a": 1}))
            .expect("persisting without a path is a no-op");
    }

    /// An absent file is a first boot, not an error — and a round trip restores
    /// the document unchanged.
    #[test]
    fn absent_then_round_trip() {
        let dir = tmpdir("roundtrip");
        let path = dir.join("nested").join("state.json");

        let mut s = StateStore::new(Some(path.clone()));
        assert!(matches!(s.load().expect("absent is ok"), Loaded::Absent));

        let doc = serde_json::json!({"registry": {"nf-1": {"nfType": "AMF"}}});
        s.persist(&doc).expect("write");
        assert!(path.is_file(), "parent directories are created");

        let mut reopened = StateStore::new(Some(path.clone()));
        match reopened.load().expect("valid snapshot") {
            Loaded::Snapshot(v) => assert_eq!(v, doc),
            Loaded::Absent => panic!("the snapshot just written must be found"),
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "snapshots hold subscriber identifiers and must not be world-readable"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Issue #66, the defect this module exists for.** A corrupt snapshot must
    /// not be overwritten from empty state.
    ///
    /// Every pre-existing copy of this logic logged a warning, returned, and let
    /// boot continue with an empty store — and the next mutation rewrote the file,
    /// making the loss permanent and destroying the operator's only evidence.
    ///
    /// Revert-verified: dropping the `poisoned` check from `persist` fails the
    /// "contents survive" assertion below.
    #[test]
    fn a_corrupt_snapshot_is_never_overwritten() {
        let dir = tmpdir("corrupt");
        let path = dir.join("state.json");
        // Truncated JSON: the likely real-world corruption (a partial write, a
        // container killed mid-rename, a half-mounted volume).
        let original = r#"{"registry": {"nf-1": {"nfTyp"#;
        std::fs::write(&path, original).expect("write");

        let mut s = StateStore::new(Some(path.clone()));
        let err = s.load().expect_err("corrupt input must be an error");
        assert!(
            matches!(err, StateStoreError::Corrupt { .. }),
            "got {err:?}"
        );
        assert!(s.is_poisoned());

        // The mutation that used to destroy the file is now refused...
        let err = s
            .persist(&serde_json::json!({}))
            .expect_err("persisting after a failed load must be refused");
        assert!(
            matches!(err, StateStoreError::Poisoned { .. }),
            "got {err:?}"
        );
        // ...and the recoverable contents are still there.
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            original,
            "the unreadable file must survive for inspection or recovery"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory where a file is expected is unreadable, not "absent" — so it
    /// poisons rather than silently starting empty.
    #[test]
    fn an_unreadable_path_poisons_rather_than_looking_absent() {
        let dir = tmpdir("unreadable");
        let path = dir.join("state-is-a-directory");
        std::fs::create_dir_all(&path).expect("mkdir");

        let mut s = StateStore::new(Some(path.clone()));
        let err = s.load().expect_err("a directory is not a snapshot");
        assert!(
            matches!(err, StateStoreError::Unreadable { .. }),
            "got {err:?}"
        );
        assert!(s.is_poisoned());
        assert!(s.persist(&serde_json::json!({})).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The temporary file must not collide between two state files that differ
    /// only by extension — `Path::with_extension`, which the previous copies
    /// used, maps `udr.state` and `udr.json` onto the same `udr.tmp`.
    #[test]
    fn temp_files_do_not_collide_between_sibling_state_files() {
        let dir = tmpdir("collide");
        let a = dir.join("udr.state");
        let b = dir.join("udr.json");

        StateStore::new(Some(a.clone()))
            .persist(&serde_json::json!({"which": "a"}))
            .expect("write a");
        StateStore::new(Some(b.clone()))
            .persist(&serde_json::json!({"which": "b"}))
            .expect("write b");

        let load = |p: &Path| -> serde_json::Value {
            match StateStore::new(Some(p.to_path_buf())).load().expect("load") {
                Loaded::Snapshot(v) => v,
                Loaded::Absent => panic!("{} should exist", p.display()),
            }
        };
        assert_eq!(load(&a)["which"], "a");
        assert_eq!(load(&b)["which"], "b", "sibling writes must not clobber");
        // No stray temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
