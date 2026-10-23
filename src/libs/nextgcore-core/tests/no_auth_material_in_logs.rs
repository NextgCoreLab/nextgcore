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

/// Identifier tokens that name authentication material. An identifier is split
/// on `_` and `.` (`mme_ue.kasme`, `new_sqn_hex`, `xres_star_bytes`) and is
/// flagged when any token is one of these, so no growing word list is needed.
const SENSITIVE: &[&str] = &[
    "res", "xres", "hxres", "kseaf", "kausf", "kasme", "kamf", "kgnb", "kenb", "knas", "opc",
    "topc", "ki", "ck", "ik", "autn", "rand", "auts", "sqn", "nh",
];

/// A last token that makes the identifier a property of the material rather
/// than the material: `res_star.len()`, `xres_len`, `sqn_count`.
const EXEMPT_LAST: &[&str] = &[
    "len", "id", "count", "status", "code", "ok", "is_some", "is_none",
];

/// The log and print macros scanned. `print!`-style output reaches the same
/// container log as `log`.
const MACROS: &[&str] = &[
    "trace!(",
    "debug!(",
    "info!(",
    "warn!(",
    "error!(",
    "println!(",
    "eprintln!(",
    "print!(",
    "eprint!(",
];

/// Whether an identifier chain names authentication material.
fn is_sensitive(ident: &str) -> bool {
    let tokens: Vec<String> = ident
        .split(['.', '_'])
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let last_segment = ident
        .rsplit('.')
        .next()
        .unwrap_or(ident)
        .to_ascii_lowercase();
    if EXEMPT_LAST.contains(&last_segment.as_str())
        || tokens
            .last()
            .is_some_and(|t| EXEMPT_LAST.contains(&t.as_str()))
    {
        return false;
    }
    tokens.iter().any(|t| SENSITIVE.contains(&t.as_str()))
}

/// Identifier chains (`a.b_c`) in `code`.
fn identifiers(code: &str) -> Vec<&str> {
    code.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .map(|w| w.trim_matches('.'))
        .filter(|w| {
            w.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        })
        .collect()
}

/// Production code only: everything from the first inline `#[cfg(test)]`
/// module on is test code, where printing a published test vector is fine.
fn production(text: &str) -> &str {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim() == "#[cfg(test)]" {
            let rest = &text[at + line.len()..];
            if rest.trim_start().starts_with("mod ") {
                return &text[..at];
            }
        }
        at += line.len();
    }
    text
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| {
                ["target", "tests", "benches", "examples"].contains(&n.to_str().unwrap_or(""))
            }) {
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
            '{' if in_str && chars.peek() == Some(&'{') => {
                chars.next(); // `{{` is a literal brace, not an interpolation
            }
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

#[test]
fn no_log_macro_prints_authentication_material() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    assert!(files.len() > 100, "found only {} source files", files.len());

    let mut problems = Vec::new();
    for file in &files {
        let full = fs::read_to_string(file).unwrap_or_default();
        let text = production(&full);
        for mac in MACROS {
            let mut from = 0;
            while let Some(at) = text[from..].find(mac) {
                let start = from + at;
                from = start + mac.len();
                let before = text[..start].chars().last().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' {
                    continue; // e.g. `my_info!(`, or `eprintln!(` seen as `println!(`
                }
                let body = macro_body(text, from);
                let code = interpolated_and_args(body);
                let hits: Vec<&str> = identifiers(&code)
                    .into_iter()
                    .filter(|w| is_sensitive(w))
                    .collect();
                if !hits.is_empty() {
                    let line = text[..start].matches('\n').count() + 1;
                    problems.push(format!(
                        "{}:{line}: {mac} logs {hits:?}",
                        file.strip_prefix(&src).unwrap_or(file).display()
                    ));
                }
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn the_scanner_flags_material_and_not_its_properties() {
    for bad in [
        "sqn",
        "new_sqn",
        "new_sqn_hex",
        "mme_ue.kasme",
        "xres_star_bytes",
        "res",
        "ue.rand",
        "kasme_hex",
    ] {
        assert!(is_sensitive(bad), "{bad} must be flagged");
    }
    for ok in [
        "res_star.len",
        "xres_len",
        "sqn_count",
        "resync_auts.is_some",
        "supi",
        "operand",
        "random_id",
        "response",
        "k",
    ] {
        assert!(!is_sensitive(ok), "{ok} must not be flagged");
    }
    let body = "\"[{supi}] SQN advanced to {new_sqn_hex}\", rand_len";
    let code = interpolated_and_args(body);
    let hits: Vec<&str> = identifiers(&code)
        .into_iter()
        .filter(|w| is_sensitive(w))
        .collect();
    assert_eq!(
        hits,
        vec!["new_sqn_hex"],
        "literal text is not scanned, interpolations are"
    );
    let code = interpolated_and_args("\"{{NH, NCC=2}} {count}\"");
    assert!(
        identifiers(&code).into_iter().all(|w| !is_sensitive(w)),
        "`{{` is a literal brace"
    );
}
