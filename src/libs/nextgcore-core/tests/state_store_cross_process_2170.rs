//! #2170 (R42 on #2165): two PROCESSES persisting one state file at once, as
//! two NF instances sharing a state directory do across a rolling restart.
//! The in-process path lock (#2148) cannot serialise them; only the unique
//! per-write temporary name keeps each rename publishing one writer's whole
//! document. Every persist succeeds and every read is a whole document.
//!
//! The test re-executes its own binary as the second writer (env
//! `NGC_STATE_WRITER_2170`), so the two writers are separate processes.
//!
//! REVERT-VERIFIED: with the temporary name back to the fixed `.<name>.tmp`
//! (the path lock kept), the writers collide on one temporary file across the
//! processes: a persist fails (ENOENT) or a read is torn, and the test fails.

use nextgcore_core::state_store::StateStore;
use std::path::{Path, PathBuf};

const ENV: &str = "NGC_STATE_WRITER_2170";
const ROUNDS: u64 = 150;
const PAD: usize = 4000;

/// Persist ROUNDS large documents to `path`, reading back after each; the
/// count of failed persists and of torn reads.
fn write_and_check(path: &Path, writer: u64) -> (usize, usize) {
    let store = StateStore::new(Some(path.to_path_buf()));
    let (mut failed, mut torn) = (0, 0);
    for round in 0..ROUNDS {
        let doc = serde_json::json!({ "writer": writer, "round": round, "pad": vec![writer; PAD] });
        if store.persist(&doc).is_err() {
            failed += 1;
        }
        match std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            Some(v) if v["pad"].as_array().map(Vec::len) == Some(PAD) => {}
            _ => torn += 1,
        }
    }
    (failed, torn)
}

#[test]
fn two_processes_persisting_one_file_never_tear_2170() {
    if let Ok(path) = std::env::var(ENV) {
        // The second process.
        let (failed, torn) = write_and_check(Path::new(&path), 2);
        assert_eq!(
            (failed, torn),
            (0, 0),
            "second writer: failed persists, torn reads"
        );
        return;
    }
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "ngc-state-xproc-2170-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nf.json");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "two_processes_persisting_one_file_never_tear_2170",
            "--nocapture",
        ])
        .env(ENV, &path)
        .spawn()
        .expect("second writer");
    let (failed, torn) = write_and_check(&path, 1);
    let status = child
        .wait_with_output()
        .expect("second writer exits")
        .status;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        (failed, torn),
        (0, 0),
        "first writer: failed persists, torn reads"
    );
    assert!(
        status.success(),
        "the second writer saw failed persists or torn reads"
    );
}
