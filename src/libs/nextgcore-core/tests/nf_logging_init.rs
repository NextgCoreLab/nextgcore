//! Every NF daemon builds its logger with `nextgcore_core::log::nf_log_builder`
//! (or `nextgcore_app::init::nf_common_init`, which uses it), so `RUST_LOG`
//! works the same everywhere (#691).
//!
//! Before #691, 15 NFs used `env_logger::Builder::new().filter_level(..)`,
//! which never reads `RUST_LOG`, so the per-NF debug filters in
//! `docker/rust/docker-compose.yml` did nothing. This test reads the daemon
//! sources and fails when a new or edited NF builds its own logger again.

use std::fs;
use std::path::{Path, PathBuf};

/// Binaries that are not NF daemons. `nextgcore-webui` uses
/// `env_logger::init()`, which reads `RUST_LOG` itself.
const NOT_AN_NF: &[&str] = &["nextgcore-webui"];

/// Logger constructions that bypass the shared builder.
const FORBIDDEN: &[&str] = &[
    "env_logger::Builder::new(",
    "env_logger::Builder::from_env(",
];

/// Calls that build the shared logger.
const SHARED: &[&str] = &["nf_log_builder(", "nf_common_init("];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The file's code with `//` comment lines dropped, so prose can name the
/// forbidden calls.
fn code(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_nf_builds_its_logger_with_the_shared_builder() {
    let bins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bins");
    let mut crates: Vec<PathBuf> = fs::read_dir(&bins)
        .expect("src/bins")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    crates.sort();
    assert!(crates.len() >= 28, "found only {} bins", crates.len());

    let mut problems = Vec::new();
    for krate in &crates {
        let name = krate.file_name().unwrap().to_string_lossy().to_string();
        let mut files = Vec::new();
        rust_files(&krate.join("src"), &mut files);
        let mut uses_shared = false;
        for file in &files {
            let code = code(file);
            for bad in FORBIDDEN {
                if code.contains(bad) {
                    problems.push(format!(
                        "{}: `{bad}..)` ignores RUST_LOG or bypasses the shared \
                         behaviour; use nextgcore_core::log::nf_log_builder",
                        file.strip_prefix(&bins).unwrap_or(file).display()
                    ));
                }
            }
            uses_shared |= SHARED.iter().any(|s| code.contains(s));
        }
        if !uses_shared && !NOT_AN_NF.contains(&name.as_str()) {
            problems.push(format!(
                "{name}: never calls nextgcore_core::log::nf_log_builder (or \
                 nextgcore_app::init::nf_common_init)"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
