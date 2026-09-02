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
fn write_atomic(path: &Path, doc: &serde_json::Value) -> std::io::Result<()> {
    use std::io::Write;

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
    let tmp = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(format!(".{file_name}.tmp")),
        _ => PathBuf::from(format!(".{file_name}.tmp")),
    };

    {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&serialized)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
