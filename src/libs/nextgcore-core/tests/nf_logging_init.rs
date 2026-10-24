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

/// The file's production code: comments, string and char literals blanked
/// out, and everything from the first inline `#[cfg(test)]` module on dropped.
/// So a call that appears only in prose, in a string, or in test code does not
/// count as the daemon building its logger (#788 review).
fn code(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    production_code(&text)
}

fn production_code(text: &str) -> String {
    let stripped = strip_comments_and_literals(text);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut end = lines.len();
    for (i, pair) in lines.windows(2).enumerate() {
        let next = pair[1].trim_start();
        if pair[0].trim() == "#[cfg(test)]" && next.starts_with("mod ") && next.ends_with('{') {
            end = i;
            break;
        }
    }
    lines[..end].join("\n")
}

/// Replace comments and string/char literals with spaces, keeping newlines.
fn strip_comments_and_literals(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let blank = |out: &mut String, s: &[u8]| {
        for &c in s {
            out.push(if c == b'\n' { '\n' } else { ' ' });
        }
    };
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(b.len(), |e| i + e);
                blank(&mut out, &b[i..end]);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
                blank(&mut out, &b[i..end]);
                i = end;
            }
            b'r' if matches!(b.get(i + 1), Some(b'"') | Some(b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                // Raw string r"..." / r#"..."#.
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    out.push('r');
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let end = src[j + 1..]
                    .find(&close)
                    .map_or(b.len(), |e| j + 1 + e + close.len());
                blank(&mut out, &b[i..end]);
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let end = (j + 1).min(b.len());
                blank(&mut out, &b[i..end]);
                i = end;
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') || (b.get(i + 1) == Some(&b'\\')) => {
                // A char literal ('x' or '\n'); a lifetime has no closing quote.
                let end = src[i + 1..].find('\'').map_or(b.len(), |e| i + 1 + e + 1);
                blank(&mut out, &b[i..end]);
                i = end;
            }
            _ => {
                let ch = src[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

#[test]
fn the_scan_ignores_strings_comments_and_test_code() {
    let src = "fn main() {\n    let s = \"nf_log_builder(\";\n    // nf_log_builder(\n    let r = r#\"env_logger::Builder::new()\"#;\n}\n#[cfg(test)]\nmod tests {\n    fn t() { nf_log_builder(\"info\"); }\n}\n";
    let stripped = production_code(src);
    assert!(!stripped.contains("nf_log_builder("), "{stripped}");
    assert!(!stripped.contains("Builder::new("), "{stripped}");
    let real = strip_comments_and_literals("let b = nextgcore_core::log::nf_log_builder(&l);");
    assert!(real.contains("nf_log_builder("));
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
