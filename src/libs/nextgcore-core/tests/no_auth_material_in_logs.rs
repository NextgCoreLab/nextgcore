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
/// NAS COUNT's `sqn` is a sequence number, not the AKA SQN. Matched by full
/// path (`<file under src/>::<Type>`), so a new type that reuses one of these
/// names elsewhere is still checked (#861 review).
const DEBUG_ALLOWED: &[&str] = &[
    "libs/nextgcore-nas/src/eps/message.rs::EpsAuthenticationRequest",
    "libs/nextgcore-nas/src/fiveg/message.rs::AuthenticationRequest",
    "libs/nextgcore-nas/src/common/types.rs::AuthenticationResponseParameter",
    "libs/nextgcore-nas/src/common/security.rs::NasCount",
    "bins/nextgcore-mmed/src/nas_security.rs::UlCount",
    // Charging: `acr_res` is the ACR result, not an AKA RES.
    "bins/nextgcore-eesd/src/acrevents.rs::ACRCompleteEventInfo",
    // LPP/NRPPa timing: `k` is the TS 38.133 Tc multiplier, not the key K.
    "bins/nextgcore-lmfd/src/codec_glue.rs::TimeReport",
    // TUAK INSTANCE octet: `ck_256` / `ik_256` / `k_256` are key-LENGTH flags.
    "libs/nextgcore-crypt/src/tuak.rs::Instance",
];

/// `[pub[(...)]] (struct|enum) Name` after a derive and its trailing attributes.
fn derived_item(rest: &str) -> Option<(&'static str, String, &str)> {
    let mut item = rest.trim_start();
    loop {
        if item.starts_with("#[") {
            item = item[item.find(']')? + 1..].trim_start();
        } else if item.starts_with("///") || item.starts_with("//") {
            item = item[item.find('\n')? + 1..].trim_start();
        } else {
            break;
        }
    }
    if let Some(after) = item.strip_prefix("pub") {
        item = after.trim_start();
        if item.starts_with('(') {
            item = item[item.find(')')? + 1..].trim_start();
        }
    }
    let (kind, after) = if let Some(a) = item.strip_prefix("struct ") {
        ("struct", a)
    } else if let Some(a) = item.strip_prefix("enum ") {
        ("enum", a)
    } else {
        return None;
    };
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    Some((kind, name.clone(), &after[name.len()..]))
}

/// `CamelCase` -> `camel_case`, so a tuple type or variant named for the
/// material (`Kasme(..)`, `PathSwitch { nh }` aside) is checked by its name.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The text between the `{`/`(` at `open` and its matching close.
fn balanced(text: &str, open: usize) -> &str {
    let (o, c) = match text.as_bytes()[open] {
        b'(' => ('(', ')'),
        _ => ('{', '}'),
    };
    let mut depth = 0usize;
    for (i, ch) in text[open..].char_indices() {
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return &text[open + 1..open + i];
            }
        }
    }
    &text[open + 1..]
}

/// Named fields (`[pub[(..)]] name: Type`) in a struct or enum body.
fn named_fields(body: &str) -> Vec<&str> {
    body.lines()
        .filter_map(|l| {
            let mut l = l.trim_start();
            if let Some(after) = l.strip_prefix("pub") {
                l = after.trim_start();
                if l.starts_with('(') {
                    l = &l[l.find(')')? + 1..];
                }
                l = l.trim_start();
            }
            let (field, rest) = l.split_once(':')?;
            if rest.starts_with(':') {
                return None; // a path, not a field
            }
            let field = field.trim();
            (!field.is_empty() && field.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .then_some(field)
        })
        .collect()
}

/// Production structs and enums that derive `Debug` and hold authentication
/// material: a named field, or a tuple struct / tuple variant named for it.
/// Each must use a redacting manual `Debug` instead (#861 review), so a future
/// `{:?}` cannot print it. Any visibility (`pub(super)` included), tuple
/// structs and enum variants are covered.
#[test]
fn no_key_holding_type_derives_debug() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    let mut problems = Vec::new();
    let mut seen = 0usize;
    for file in &files {
        let full = fs::read_to_string(file).unwrap_or_default();
        let text = production(&full);
        let rel = file
            .strip_prefix(&src)
            .unwrap_or(file)
            .display()
            .to_string();
        let mut from = 0;
        while let Some(at) = text[from..].find("#[derive(") {
            let start = from + at;
            from = start + 9;
            let Some(close) = text[from..].find(")]") else {
                break;
            };
            if !text[from..from + close]
                .split(',')
                .any(|d| d.trim() == "Debug")
            {
                continue;
            }
            let rest = &text[from + close + 2..];
            let Some((kind, name, after)) = derived_item(rest) else {
                continue;
            };
            seen += 1;
            if DEBUG_ALLOWED.contains(&format!("{rel}::{name}").as_str()) {
                continue;
            }
            let after_off = text.len() - after.len();
            let Some(open) = after.find(['{', '(', ';']) else {
                continue;
            };
            let mut bad: Vec<String> = Vec::new();
            match after.as_bytes()[open] {
                b';' => {}
                b'(' => {
                    // Tuple struct: judged by its name.
                    if is_sensitive(&snake(&name)) {
                        bad.push(name.clone());
                    }
                }
                _ => {
                    let body = balanced(text, after_off + open);
                    bad.extend(
                        named_fields(body)
                            .into_iter()
                            .filter(|f| is_sensitive(f))
                            .map(str::to_string),
                    );
                    if kind == "enum" {
                        // Tuple variants: `Kasme([u8; 32]),` judged by name.
                        for line in body.lines() {
                            let l = line.trim_start();
                            let v: String = l
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            if !v.is_empty()
                                && l[v.len()..].trim_start().starts_with('(')
                                && is_sensitive(&snake(&v))
                            {
                                bad.push(v);
                            }
                        }
                    }
                }
            }
            if !bad.is_empty() {
                problems.push(format!(
                    "{rel}::{name}: {kind} derives Debug but holds {bad:?}; give it a redacting Debug"
                ));
            }
        }
    }
    assert!(
        seen > 200,
        "only {seen} derived types found: the parser is broken"
    );
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// The parser above, on the shapes the #861 review named.
#[test]
fn derive_check_self_test() {
    let (kind, name, _) =
        derived_item("\n#[serde(x)]\n/// doc\npub(super) enum HandoverModifyKind {").unwrap();
    assert_eq!((kind, name.as_str()), ("enum", "HandoverModifyKind"));
    let (kind, name, _) = derived_item("pub struct Kasme(pub [u8; 32]);").unwrap();
    assert_eq!((kind, name.as_str()), ("struct", "Kasme"));
    assert!(is_sensitive(&snake("Kasme")));
    assert!(!is_sensitive(&snake("PathSwitch")));
    assert_eq!(
        named_fields("PathSwitch {\n    enb_id: u64,\n    nh: [u8; 32],\n    pub(crate) kasme: X,\n    x: a::b,\n}"),
        vec!["enb_id", "nh", "kasme", "x"]
    );
}

/// Whether `.field(label, value)` in a manual `Debug` prints authentication
/// material. Judged by the VALUE (#861 review): `field("x", &self.kasme)` and
/// `field("is_kasme_valid", &self.kasme)` leak whatever the label says. A
/// sensitive label is also a leak unless its value is redacted. The flag
/// exemption (`use_opc`, `has_k`, `is_kasme_valid`) applies to the value's
/// last segment, never to the label alone.
fn debug_field_leaks(label: &str, value: &str) -> bool {
    if value.contains("<redacted>") {
        return false;
    }
    let flag = |seg: &str| ["use_", "has_", "is_"].iter().any(|p| seg.starts_with(p));
    let value_leaks = identifiers(value).into_iter().any(|chain| {
        let last = chain.rsplit('.').next().unwrap_or(chain);
        !flag(last) && is_sensitive(chain)
    });
    let label_leaks = is_sensitive(label) && !flag(label) && !value.trim().is_empty();
    value_leaks || label_leaks
}

#[test]
fn debug_field_check_self_test() {
    for (label, value) in [
        ("kasme", " &self.kasme"),
        ("x", " &self.kasme"),
        ("is_kasme_valid", " &self.kasme"),
        ("k", " &self.k"),
        ("opaque", " &hex::encode(&self.opc)"),
        ("nh", " &self.next_hop"),
    ] {
        assert!(debug_field_leaks(label, value), "{label}: {value}");
    }
    for (label, value) in [
        ("kasme", " &\"<redacted>\""),
        ("use_opc", " &self.use_opc"),
        ("is_kasme_valid", " &self.is_kasme_valid"),
        ("imsi", " &self.imsi"),
    ] {
        assert!(!debug_field_leaks(label, value), "{label}: {value}");
    }
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
            let mut at = 0;
            while let Some(f) = body[at..].find(".field(") {
                let open = at + f + 6;
                at = open + 1;
                let args = balanced(body, open);
                let (label, value) = args.split_once(',').unwrap_or((args, ""));
                let label = label.trim().trim_matches('"');
                if debug_field_leaks(label, value) {
                    problems.push(format!(
                        "{}: Debug for {name} prints `{}` as {label:?} unredacted",
                        file.strip_prefix(&src).unwrap_or(file).display(),
                        value.trim()
                    ));
                }
            }
        }
    }
    assert!(checked > 20, "only {checked} Debug impls found");
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
