//! No log line prints authentication vectors, keys or sequence numbers.
//!
//! mmed logged RES / XRES at debug on a mismatch, ausfd logged the full RES* at
//! info on every 5G-AKA confirmation, amfd logged RAND / AUTN / RES* prefixes
//! and hssd logged SQN_HE / SQN_MS on re-synchronisation. Logs are shipped and
//! retained far more widely than the subscriber database, so none of this may
//! appear in them. This test reads every `src/bins` and `src/libs` source file
//! and fails on a `log` macro that interpolates one of those values.

use std::fs;
use std::path::{Path, PathBuf};

/// Identifiers that hold authentication material. Matched as whole words in a
/// macro's `{name}` interpolations and arguments (not in its literal text).
const SENSITIVE: &[&str] = &[
    "res",
    "res_star",
    "res_star_hex",
    "xres",
    "xres_star",
    "hxres_star",
    "kseaf",
    "kausf",
    "kasme",
    "kamf",
    "k_amf",
    "kgnb",
    "kenb",
    "knas_int",
    "knas_enc",
    "opc",
    "opc_hex",
    "k_hex",
    "ki",
    "ck",
    "ik",
    "autn",
    "rand",
    "auts",
    "sqn",
    "sqn_ms",
    "sqn_he",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The text inside `name!(` ... `)`, starting at byte `open` (just after `(`).
fn macro_body(src: &str, open: usize) -> &str {
    let bytes = src.as_bytes();
    let (mut depth, mut i, mut in_str) = (1usize, open, false);
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'\\' if in_str => i += 1,
            b'"' => in_str = !in_str,
            b'(' if !in_str => depth += 1,
            b')' if !in_str => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    &src[open..i.saturating_sub(1)]
}

/// `{name...}` interpolations plus everything outside string literals.
fn interpolated_and_args(body: &str) -> String {
    let mut out = String::new();
    let mut in_str = false;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_str => {
                chars.next();
            }
            '"' => in_str = !in_str,
            '{' if in_str => {
                let mut name = String::new();
                while let Some(&n) = chars.peek() {
                    if n.is_alphanumeric() || n == '_' || n == '.' {
                        name.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(' ');
                out.push_str(&name);
                out.push(' ');
            }
            _ if !in_str => out.push(c),
            _ => {}
        }
    }
    out
}

/// Drop every `path.to.value.len()`, which logs a length, not the value.
fn strip_len_calls(code: &str) -> String {
    let mut out = code.to_string();
    while let Some(at) = out.find(".len()") {
        let start = out[..at]
            .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
            .map_or(0, |i| i + 1);
        out.replace_range(start..at + ".len()".len(), " ");
    }
    out
}

fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect()
}

#[test]
fn no_log_macro_prints_authentication_material() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    assert!(files.len() > 100, "found only {} source files", files.len());

    let mut problems = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap_or_default();
        for mac in ["trace!(", "debug!(", "info!(", "warn!(", "error!("] {
            let mut from = 0;
            while let Some(at) = text[from..].find(mac) {
                let start = from + at;
                from = start + mac.len();
                let before = text[..start].chars().last().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' {
                    continue; // e.g. `my_info!(`
                }
                let body = macro_body(&text, from);
                let code = interpolated_and_args(body);
                // `x.len()` of a value says nothing about its content.
                let code = strip_len_calls(&code);
                let hits: Vec<&str> = words(&code)
                    .into_iter()
                    .filter(|w| SENSITIVE.contains(&w.to_ascii_lowercase().as_str()))
                    .collect();
                if !hits.is_empty() {
                    let line = text[..start].matches('\n').count() + 1;
                    problems.push(format!(
                        "{}:{line}: logs {hits:?}",
                        file.strip_prefix(&src).unwrap_or(file).display()
                    ));
                }
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
