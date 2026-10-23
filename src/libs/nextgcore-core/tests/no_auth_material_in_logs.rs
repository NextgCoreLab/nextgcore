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

/// A last segment or token that makes the identifier a property of the
/// material rather than the material: `res_star.len()`, `xres_len`,
/// `sqn_count`, `resync_auts.is_some()`.
const EXEMPT_LAST: &[&str] = &["len", "count", "is_some", "is_none"];

/// Last tokens that are exempt only after `res`, where `res` is an HTTP
/// response (`res_status`, `res_code`), never after a key name (`kseaf_id`).
const EXEMPT_AFTER_RES: &[&str] = &["status", "code", "ok", "id"];

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
    if let [.., prev, last] = tokens.as_slice() {
        if prev == "res" && EXEMPT_AFTER_RES.contains(&last.as_str()) {
            return false;
        }
    }
    // The permanent key K, alone or as a token (`k`, `k_hex`, `sub.k`): its
    // leak is unrecoverable, so a loop variable must not be called `k` in a
    // log line either.
    if tokens.iter().any(|t| t == "k") {
        return true;
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
        "res_status",
        "http.res_code",
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

/// Wire-message and counter types whose "sensitive-looking" fields are not
/// authentication material in the sense of this check: NAS AUTHENTICATION
/// REQUEST / RESPONSE values are sent in clear over the air interface, and a
/// NAS COUNT's `sqn` is a sequence number, not the AKA SQN.
const DEBUG_ALLOWED: &[&str] = &[
    "EpsAuthenticationRequest",
    "AuthenticationRequest",
    "AuthenticationResponseParameter",
    "NasCount",
    "UlCount",
    "ACRCompleteEventInfo",
    "TimeReport",
    // TUAK INSTANCE octet: `ck_256` / `ik_256` / `k_256` are key-LENGTH flags.
    "Instance",
];

/// Production structs that derive `Debug` and have a field naming
/// authentication material. Each must use a redacting manual `Debug` instead
/// (#861 review), so a future `{:?}` cannot print it.
#[test]
fn no_key_holding_struct_derives_debug() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    let mut problems = Vec::new();
    for file in &files {
        let full = fs::read_to_string(file).unwrap_or_default();
        let text = production(&full);
        let mut from = 0;
        while let Some(at) = text[from..].find("#[derive(") {
            let start = from + at;
            from = start + 9;
            let Some(close) = text[from..].find(")]") else {
                break;
            };
            let derives = &text[from..from + close];
            if !derives.split(',').any(|d| d.trim() == "Debug") {
                continue;
            }
            // The item the derive applies to, skipping further attributes.
            let rest = &text[from + close + 2..];
            let item = rest.trim_start();
            let item = item
                .lines()
                .skip_while(|l| {
                    l.trim_start().starts_with("#[") || l.trim_start().starts_with("///")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let Some(after_struct) = item
                .trim_start()
                .strip_prefix("pub struct ")
                .or_else(|| item.trim_start().strip_prefix("pub(crate) struct "))
                .or_else(|| item.trim_start().strip_prefix("struct "))
            else {
                continue;
            };
            let name: String = after_struct
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if DEBUG_ALLOWED.contains(&name.as_str()) {
                continue;
            }
            let Some(open) = after_struct.find('{') else {
                continue;
            };
            if after_struct[..open].contains(';') {
                continue; // tuple or unit struct
            }
            let body_start = open + 1;
            let mut depth = 1usize;
            let mut end = body_start;
            for (i, c) in after_struct[body_start..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
            let fields: Vec<&str> = after_struct[body_start..end]
                .lines()
                .filter_map(|l| {
                    let l = l.trim_start();
                    let l = l
                        .strip_prefix("pub(crate) ")
                        .or_else(|| l.strip_prefix("pub "))
                        .unwrap_or(l);
                    let (field, _) = l.split_once(':')?;
                    let field = field.trim();
                    (!field.is_empty() && field.chars().all(|c| c.is_alphanumeric() || c == '_'))
                        .then_some(field)
                })
                .collect();
            let bad: Vec<&str> = fields.into_iter().filter(|f| is_sensitive(f)).collect();
            if !bad.is_empty() {
                problems.push(format!(
                    "{}: struct {name} derives Debug but holds {bad:?}; give it a redacting Debug",
                    file.strip_prefix(&src).unwrap_or(file).display()
                ));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// Every manual `Debug` impl prints authentication material only as
/// `<redacted>` (#861 review): a `.field("kasme", &self.kasme)` in any
/// `impl std::fmt::Debug for ...` (or `impl fmt::Debug`) block fails. This
/// covers all the redacting impls at once, and any written later.
#[test]
fn manual_debug_impls_redact_authentication_material() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    let mut checked = 0;
    let mut problems = Vec::new();
    for file in &files {
        let full = fs::read_to_string(file).unwrap_or_default();
        let text = production(&full);
        let mut from = 0;
        while let Some(at) = text[from..].find("Debug for ") {
            let start = from + at;
            from = start + 10;
            let head = &text[text[..start].rfind('\n').map_or(0, |i| i + 1)..start];
            if !head.trim_start().starts_with("impl") {
                continue;
            }
            let name: String = text[from..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if DEBUG_ALLOWED.contains(&name.as_str()) {
                continue;
            }
            let Some(open) = text[from..].find('{') else {
                break;
            };
            let body_start = from + open + 1;
            let mut depth = 1usize;
            let mut end = body_start;
            for (i, c) in text[body_start..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
            let body = &text[body_start..end];
            checked += 1;
            let mut rest = body;
            while let Some(f) = rest.find(".field(\"") {
                rest = &rest[f + 8..];
                let Some(q) = rest.find('"') else { break };
                let field = &rest[..q];
                let args = &rest[q..rest.find(')').unwrap_or(rest.len())];
                // `use_opc`, `has_k`, `is_kasme_valid`: a flag, not the key.
                let flag = ["use_", "has_", "is_"].iter().any(|p| field.starts_with(p));
                if is_sensitive(field) && !flag && !args.contains("<redacted>") {
                    problems.push(format!(
                        "{}: Debug for {name} prints {field} unredacted",
                        file.strip_prefix(&src).unwrap_or(file).display()
                    ));
                }
            }
        }
    }
    assert!(checked > 20, "only {checked} Debug impls found");
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
