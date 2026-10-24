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

/// Production code only: every inline `#[cfg(test)] mod name { .. }` block is
/// blanked (offsets kept), since test code may print a published test vector.
/// Only blocks are removed: a one-line `#[cfg(test)] mod name;` declaration used
/// to end the scan of the whole file there, which hid most of smfd's, upfd's,
/// mmed's and mbsmfd's `main.rs` from every check in this file (#1047 review).
fn production(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        let line_start = at;
        at += line.len();
        if line.trim() != "#[cfg(test)]" {
            continue;
        }
        let rest = &text[at..];
        let item = rest.trim_start();
        let is_mod = ["mod ", "pub mod ", "pub(crate) mod ", "pub(super) mod "]
            .iter()
            .any(|p| item.starts_with(p));
        if !is_mod {
            continue;
        }
        let item_at = at + (rest.len() - item.len());
        let head_end = item.find(['{', ';']).map_or(text.len(), |i| item_at + i);
        if bytes.get(head_end) != Some(&b'{') {
            continue; // `mod name;`: its file is scanned (or skipped) on its own
        }
        let mut depth = 0usize;
        let mut end = text.len();
        for (i, b) in bytes[head_end..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = head_end + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        for b in &mut out[line_start..end] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// `text` with every `//` and `/* */` comment replaced by spaces, so byte
/// offsets are kept and a brace, colon or `#[derive(Debug)]` in a comment is
/// not parsed as code (#861 review: the token-based field parser would read
/// `a, b: c` in a doc comment as a field). String literals are skipped, so
/// `"http://x"` is not taken for a comment; `'"'` is a char, not a string.
fn blank_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let (mut i, mut in_str, mut block) = (0usize, false, 0usize);
    while i < b.len() {
        let c = b[i];
        if block > 0 {
            if c == b'*' && b.get(i + 1) == Some(&b'/') {
                block -= 1;
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                continue;
            }
            if c == b'/' && b.get(i + 1) == Some(&b'*') {
                block += 1;
            }
            if c != b'\n' {
                out[i] = b' ';
            }
            i += 1;
            continue;
        }
        if in_str {
            match c {
                b'\\' => i += 2,
                b'"' => {
                    in_str = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match c {
            b'\'' if b.get(i + 1) == Some(&b'"') && b.get(i + 2) == Some(&b'\'') => i += 3,
            b'"' => {
                in_str = true;
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                block = 1;
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
            }
            _ => i += 1,
        }
    }
    // A multi-byte character inside a comment has every byte blanked, and one
    // outside is untouched, so the result is still UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
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
            // A test module in its own file (`property_tests.rs`, `golden_tests.rs`,
            // `strict_peer_test.rs`), declared by a `#[cfg(test)] mod name;`.
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if stem.ends_with("tests") || stem.ends_with("_test") || stem == "tests" {
                continue;
            }
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
        let prod = production(&full);
        let text = prod.as_str();
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
    // `KAnonymity { k }`: the k of k-anonymity, a group size.
    "libs/nextgcore-dbi/src/federation.rs::AnonymizationMethod",
];

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

/// Named fields (`[pub[(..)]] name: Type`) in a struct or enum body, with the
/// text of each field's type. Token-based, not line-based (#861 review), so a
/// one-line struct variant (`Key { kseaf: [u8; 32] },`) is read too: a field
/// is an identifier followed by a single `:`, preceded by `{`, `,`, the start
/// of the body or a visibility.
fn named_fields_typed(body: &str) -> Vec<(&str, &str)> {
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b':' || b.get(i + 1) == Some(&b':') || (i > 0 && b[i - 1] == b':') {
            i += 1;
            continue;
        }
        // The identifier right before the colon.
        let mut end = i;
        while end > 0 && b[end - 1] == b' ' {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_') {
            start -= 1;
        }
        let name = &body[start..end];
        // What precedes it, skipping whitespace and a visibility.
        let mut before = body[..start].trim_end();
        if let Some(v) = before.strip_suffix(')') {
            if let Some(open) = v.rfind("pub(") {
                before = v[..open].trim_end();
            }
        } else if let Some(v) = before.strip_suffix("pub") {
            before = v.trim_end();
        }
        let field_position = before.is_empty() || before.ends_with(['{', ',']);
        if !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() && field_position {
            // The type runs to the next top-level `,` or the end of the body.
            let mut depth = 0i32;
            let mut stop = b.len();
            for (k, &c) in b.iter().enumerate().skip(i + 1) {
                match c {
                    b'<' | b'(' | b'[' | b'{' => depth += 1,
                    b'>' | b')' | b']' | b'}' => {
                        depth -= 1;
                        if depth < 0 {
                            stop = k;
                            break;
                        }
                    }
                    b',' if depth == 0 => {
                        stop = k;
                        break;
                    }
                    _ => {}
                }
            }
            out.push((name, body[i + 1..stop].trim()));
            i = stop;
            continue;
        }
        i += 1;
    }
    out
}

/// A `struct` or `enum` item of a production file.
struct Item<'a> {
    rel: String,
    kind: &'static str,
    name: String,
    derives_debug: bool,
    /// A tuple struct (`struct Kasme([u8; 32]);`).
    tuple: bool,
    /// Named fields with their type text (struct fields, or the fields of any
    /// struct-like variant).
    fields: Vec<(&'a str, &'a str)>,
    /// Tuple-variant names of an enum.
    tuple_variants: Vec<String>,
}

/// Whether the attributes in `region` derive `Debug`.
fn region_derives_debug(region: &str) -> bool {
    let mut from = 0;
    while let Some(at) = region[from..].find("#[derive(") {
        let open = from + at + 8;
        let list = balanced(region, open);
        if list.split(',').any(|d| d.trim() == "Debug") {
            return true;
        }
        from = open + 1;
    }
    false
}

/// Every `struct` / `enum` item in `text` (comments already blanked), with
/// any visibility.
fn items<'a>(rel: &str, text: &'a str) -> Vec<Item<'a>> {
    let mut out = Vec::new();
    for (kw, kind) in [("struct ", "struct"), ("enum ", "enum")] {
        let mut from = 0;
        while let Some(at) = text[from..].find(kw) {
            let p = from + at;
            from = p + kw.len();
            let line_start = text[..p].rfind('\n').map_or(0, |i| i + 1);
            let prefix = text[line_start..p].trim();
            let visibility = prefix.is_empty()
                || prefix == "pub"
                || (prefix.starts_with("pub(") && prefix.ends_with(')'));
            if !visibility {
                continue;
            }
            let after = &text[from..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // The attributes above: back to the previous item or block edge.
            let region_start = text[..line_start]
                .rfind(['}', ';', '{'])
                .map_or(0, |i| i + 1);
            let derives_debug = region_derives_debug(&text[region_start..line_start]);
            let Some(open_rel) = after.find(['{', '(', ';']) else {
                continue;
            };
            let open = from + open_rel;
            let mut item = Item {
                rel: rel.to_string(),
                kind,
                name,
                derives_debug,
                tuple: false,
                fields: Vec::new(),
                tuple_variants: Vec::new(),
            };
            match text.as_bytes()[open] {
                b';' => {}
                b'(' => item.tuple = true,
                _ => {
                    let body = balanced(text, open);
                    item.fields = named_fields_typed(body);
                    if kind == "enum" {
                        // Variants start the body or follow a top-level `,`.
                        let mut depth = 0i32;
                        let mut starts = vec![0usize];
                        for (k, c) in body.char_indices() {
                            match c {
                                '{' | '(' | '[' | '<' => depth += 1,
                                '}' | ')' | ']' | '>' => depth -= 1,
                                ',' if depth == 0 => starts.push(k + 1),
                                _ => {}
                            }
                        }
                        for st in starts {
                            let v = body[st..].trim_start();
                            let v = v
                                .strip_prefix("#[")
                                .map_or(v, |r| r[r.find(']').map_or(0, |i| i + 1)..].trim_start());
                            let name: String = v
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            if !name.is_empty() && v[name.len()..].trim_start().starts_with('(') {
                                item.tuple_variants.push(name);
                            }
                        }
                    }
                }
            }
            out.push(item);
        }
    }
    out
}

/// The type names a field's type text mentions (`Option<KeyBytes>` ->
/// `Option`, `KeyBytes`).
fn type_names(ty: &str) -> Vec<&str> {
    ty.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| w.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
        .collect()
}

/// Production structs and enums that derive `Debug` and hold authentication
/// material. Each must use a redacting manual `Debug` instead (#861 review),
/// so a future `{:?}` cannot print it. Three shapes:
///
/// 1. a named field naming the material, in a struct or in any enum variant,
///    one-line variants included (`Key { kseaf: [u8; 32] }`);
/// 2. a tuple struct or tuple variant named for it (`Kasme([u8; 32])`);
/// 3. a type whose own name says nothing (`struct KeyBytes([u8; 32])`) but
///    that is the TYPE of a field naming the material anywhere
///    (`kasme: KeyBytes`): its derived `Debug` prints the key wherever the
///    value goes, whatever the variable is called.
///
/// Any visibility (`pub(super)` included) is covered.
#[test]
fn no_key_holding_type_derives_debug() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    let texts: Vec<(String, String)> = files
        .iter()
        .map(|file| {
            let full = fs::read_to_string(file).unwrap_or_default();
            let rel = file
                .strip_prefix(&src)
                .unwrap_or(file)
                .display()
                .to_string();
            (rel, blank_comments(&production(&full)))
        })
        .collect();
    let all: Vec<Item> = texts
        .iter()
        .flat_map(|(rel, text)| items(rel, text))
        .collect();
    let problems = derive_problems(&all);
    let derived = all.iter().filter(|i| i.derives_debug).count();
    assert!(
        derived > 200,
        "only {derived} derived types found: the parser is broken"
    );
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// The findings of [`no_key_holding_type_derives_debug`] over `all`.
fn derive_problems(all: &[Item]) -> Vec<String> {
    let allowed = |i: &Item| DEBUG_ALLOWED.contains(&format!("{}::{}", i.rel, i.name).as_str());
    let mut problems = Vec::new();
    for item in all.iter().filter(|i| i.derives_debug && !allowed(i)) {
        let mut bad: Vec<String> = item
            .fields
            .iter()
            .filter(|(f, _)| is_sensitive(f))
            .map(|(f, _)| f.to_string())
            .collect();
        if item.tuple && is_sensitive(&snake(&item.name)) {
            bad.push(item.name.clone());
        }
        bad.extend(
            item.tuple_variants
                .iter()
                .filter(|v| is_sensitive(&snake(v)))
                .cloned(),
        );
        if !bad.is_empty() {
            problems.push(format!(
                "{}::{}: {} derives Debug but holds {bad:?}; give it a redacting Debug",
                item.rel, item.name, item.kind
            ));
        }
    }
    // Shape 3: a Debug-deriving type used as the type of a key-named field.
    for holder in all {
        for (field, ty) in holder.fields.iter().filter(|(f, _)| is_sensitive(f)) {
            for tn in type_names(ty) {
                for inner in all
                    .iter()
                    .filter(|i| i.name == tn && i.derives_debug && !allowed(i))
                {
                    problems.push(format!(
                        "{}::{}: derives Debug but is the type of {}::{}.{field}; give it a \
                         redacting Debug",
                        inner.rel, inner.name, holder.rel, holder.name
                    ));
                }
            }
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

/// The parser above, on the shapes the #861 reviews named.
#[test]
fn derive_check_self_test() {
    let src = blank_comments(
        r#"
/// A doc comment with a, kasme: field-looking text and a { brace.
#[derive(Clone)]
#[derive(
    Debug,
)]
pub(super) enum HandoverModifyKind {
    PathSwitch { enb_id: u64, nh: [u8; 32] },
    Key { kseaf: [u8; 32] },
    #[allow(dead_code)]
    Kasme([u8; 32]),
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct KeyBytes(pub [u8; 32]);

pub struct Holder {
    pub(crate) kasme: Option<KeyBytes>,
    note: &'static str,
}

#[derive(Debug)]
struct Fine { imsi: String, url: &'static str }
const URL: &str = "http://example/{x}";
"#,
    );
    let all = items("t.rs", &src);
    let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["KeyBytes", "Holder", "Fine", "HandoverModifyKind"]
    );
    let kind = all.iter().find(|i| i.name == "HandoverModifyKind").unwrap();
    assert!(kind.derives_debug, "multi-line derive");
    assert_eq!(
        kind.fields.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
        vec!["enb_id", "nh", "kseaf"],
        "one-line variants are read; the doc comment is not"
    );
    assert_eq!(kind.tuple_variants, vec!["Kasme", "Other"]);
    let holder = all.iter().find(|i| i.name == "Holder").unwrap();
    assert!(!holder.derives_debug);
    assert_eq!(
        holder.fields,
        vec![("kasme", "Option<KeyBytes>"), ("note", "&'static str")]
    );
    let problems = derive_problems(&all);
    assert_eq!(problems.len(), 2, "{problems:#?}");
    assert!(problems[0].starts_with("t.rs::HandoverModifyKind") && problems[0].contains("kseaf"));
    assert!(problems[0].contains("\"Kasme\"") && problems[0].contains("\"nh\""));
    assert!(problems[1].starts_with("t.rs::KeyBytes") && problems[1].contains("Holder.kasme"));
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
        let prod = production(&full);
        let text = prod.as_str();
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

/// Whether an identifier chain names a callback URI (#1018, #1047 review): its
/// last segment ends in `uri`/`url` and names a notification, callback or
/// status target (`notification_uri`, `notif_uri`, `sub.notify_uri`,
/// `dereg_callback_uri`, `amf_status_uri`, `nf_nssai_availability_uri`), ends in
/// `destination` (`notification_destination`), or is a bare `callback` /
/// `callback_reference`. A bare `uri` is not judged (it is mostly a request
/// URI); a local that holds a callback is bound under a callback-style name.
fn is_callback_uri(ident: &str) -> bool {
    let last = ident.rsplit('.').next().unwrap_or(ident);
    if !last.chars().any(|c| c.is_ascii_lowercase()) {
        return false; // a constant (`custom_header::CALLBACK`), not a URI value
    }
    let last = last.to_ascii_lowercase();
    if [
        "callback",
        "callback_reference",
        "callback_ref",
        "callback_uris",
    ]
    .contains(&last.as_str())
    {
        return true;
    }
    if last.ends_with("destination") {
        return true;
    }
    let uri_like = last.ends_with("uri") || last.ends_with("url");
    uri_like
        && [
            "notif",
            "notify",
            "callback",
            "dereg",
            "status",
            "availability",
        ]
        .iter()
        .any(|k| last.contains(k))
}

/// Byte spans of every `redact_*(..)` call in `code`.
fn redact_spans(code: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find("redact_") {
        let start = from + at;
        from = start + 7;
        let Some(open_rel) = code[start..].find('(') else {
            break;
        };
        let open = start + open_rel;
        if !code[start..open]
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let mut depth = 0i32;
        for (i, c) in code[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        spans.push((start, open + i + 1));
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    spans
}

/// The callback-URI identifiers a log macro body prints unredacted (#1047
/// review: judged per identifier, not per macro). An occurrence is redacted
/// when it sits inside a `redact_*(..)` call, or when it names a named
/// argument whose value is one (`notify_uri = redact_last_segment(&notify_uri)`,
/// which shadows the inline `{notify_uri}` capture).
fn unredacted_callback_uris(body: &str) -> Vec<String> {
    unredacted_callback_uris_with(body, &[])
}

/// [`unredacted_callback_uris`], also treating `tainted` locals (bound from a
/// callback URI, see [`tainted_bindings`]) as callback URIs.
fn unredacted_callback_uris_with(body: &str, tainted: &[&str]) -> Vec<String> {
    let code = interpolated_and_args(body);
    let spans = redact_spans(&code);
    let shadowed = |name: &str| {
        let mut from = 0;
        while let Some(at) = code[from..].find(name) {
            let start = from + at;
            from = start + name.len();
            let before_ok = code[..start]
                .chars()
                .last()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '.'));
            let after_ok = code[from..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let rest = code[from..].trim_start();
            if before_ok && after_ok && rest.starts_with('=') && !rest.starts_with("==") {
                let value = rest[1..].split(',').next().unwrap_or("");
                if value.contains("redact_") {
                    return true;
                }
            }
        }
        false
    };
    let mut out = Vec::new();
    let mut from = 0;
    for ident in identifiers(&code) {
        let Some(at) = code[from..].find(ident) else {
            continue;
        };
        let start = from + at;
        from = start + ident.len();
        if !is_callback_uri(ident) && !tainted.contains(&ident) {
            continue;
        }
        if spans.iter().any(|&(a, b)| a <= start && start < b) {
            continue;
        }
        if !ident.contains('.') && shadowed(ident) {
            continue;
        }
        out.push(ident.to_string());
    }
    out
}

/// Whether a string literal is a callback-URI JSON key (`"notifUri"`,
/// `"ucmfNotificationUri"`, `"smContextStatusUri"`, `"amfStatusUri"`,
/// `"nfNssaiAvailabilityUri"`, `"notificationDestination"`, ...).
fn is_callback_key(literal: &str) -> bool {
    let k = literal.to_ascii_lowercase();
    let named = ["notif", "callback", "status", "availability", "destination"]
        .iter()
        .any(|w| k.contains(w));
    named && (k.ends_with("uri") || k.ends_with("destination"))
}

/// Locals bound from a callback URI (#1047 review: a bare `uri` that holds one),
/// as `(name, scope start, scope end)` byte offsets in `text`: the binding to the
/// next `fn` item. A `let` whose value names a callback identifier
/// ([`is_callback_uri`]) or a callback JSON key ([`is_callback_key`]) and is not
/// itself redacted taints its name.
fn tainted_bindings(text: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("let ") {
        let start = from + at;
        from = start + 4;
        if text[..start]
            .chars()
            .last()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let rest = &text[from..];
        let Some(eq) = rest.find('=') else { break };
        let pattern = &rest[..eq];
        if pattern.contains(['\n', ';']) && pattern.lines().count() > 2 {
            continue;
        }
        let name: String = pattern
            .trim_start_matches("mut ")
            .trim_start_matches("Some(")
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() || name.starts_with("logged") || is_callback_uri(&name) {
            continue;
        }
        // The value ends at `;`, at the `{` of an `if let` / `while let` body,
        // or at a `let ... else`.
        let value_end = [";", "{", " else "]
            .iter()
            .filter_map(|t| rest[eq..].find(t))
            .min()
            .map_or(rest.len(), |i| eq + i);
        let value = &rest[eq + 1..value_end];
        if value.contains("redact_") {
            continue;
        }
        // A projection that is not the URI: a count, a presence test, or the
        // authority (host:port), which carries no path or query.
        let trimmed = value.trim_end().trim_end_matches('?');
        let projection = [
            ".len()",
            ".count()",
            ".is_some()",
            ".is_none()",
            ".is_empty()",
        ]
        .iter()
        .any(|p| trimmed.ends_with(p))
            || ["authority", "host"]
                .iter()
                .any(|f| value.contains(&format!("{f}(")))
            // ucmfd: `nf:{id}` or `uri:{authority}`, never a path.
            || value.contains("consumer_of(");
        if projection {
            continue;
        }
        // Any segment of a chain: `sub.notif_uri.clone()` reads one.
        let from_ident = identifiers(value)
            .into_iter()
            .any(|chain| chain.split('.').any(is_callback_uri));
        let from_key = value.split('"').skip(1).step_by(2).any(is_callback_key);
        if from_ident || from_key {
            let scope_end = text[from..]
                .find("\nfn ")
                .into_iter()
                .chain(text[from..].find(" fn "))
                .min()
                .map_or(text.len(), |i| from + i);
            out.push((name, start, scope_end));
        }
    }
    out
}

/// #1018: a log macro never interpolates a consumer-supplied callback URI
/// whole. A third party's callback URI may carry a secret anywhere in its path
/// or query (the AMF's own carry a bearer token, #940/#1026), so an NF that
/// calls or stores one logs it through `nextgcore_sbi::log_redact`. Judged per
/// identifier (#1047 review): one redacted argument does not excuse another.
#[test]
fn no_log_macro_prints_a_callback_uri_whole() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&src.join("bins"), &mut files);
    rust_files(&src.join("libs"), &mut files);
    let mut problems = Vec::new();
    for file in &files {
        let full = fs::read_to_string(file).unwrap_or_default();
        let blanked = blank_comments(&production(&full));
        let text = blanked.as_str();
        let taint = tainted_bindings(text);
        for mac in MACROS {
            let mut from = 0;
            while let Some(at) = text[from..].find(mac) {
                let start = from + at;
                from = start + mac.len();
                let before = text[..start].chars().last().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' {
                    continue;
                }
                let live: Vec<&str> = taint
                    .iter()
                    .filter(|(_, a, b)| *a < start && start < *b)
                    .map(|(n, _, _)| n.as_str())
                    .collect();
                let hits = unredacted_callback_uris_with(macro_body(text, from), &live);
                if !hits.is_empty() {
                    let line = text[..start].matches('\n').count() + 1;
                    problems.push(format!(
                        "{}:{line}: {mac} logs {hits:?} whole",
                        file.strip_prefix(&src).unwrap_or(file).display()
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "\n{}\n({} sites)",
        problems.join("\n"),
        problems.len()
    );
}

#[test]
fn the_callback_uri_scan_sees_its_shapes() {
    for flagged in [
        "notification_uri",
        "sub.notification_uri",
        "notif_uri",
        "event_notify_uri",
        "dereg_callback_uri",
        "callback",
        "s.callback_reference",
        "notify_url",
        // #1047 review: the shapes the first version missed.
        "amf_status_uri",
        "nf_nssai_availability_uri",
        "ucmf_notification_uri",
        "notification_destination",
        "sm_context_status_uri",
    ] {
        assert!(is_callback_uri(flagged), "{flagged}");
    }
    for fine in [
        "uri",
        "nrf_uri",
        "self_sbi_uri",
        "callbacks_sent",
        "notify_count",
        "api_root",
        "custom_header::CALLBACK",
        "CALLBACK",
        "logged_uri",
    ] {
        assert!(!is_callback_uri(fine), "{fine}");
    }
    // Judged per identifier: one redacted argument does not excuse another.
    assert_eq!(
        unredacted_callback_uris(
            "\"{} and {}\", redact_last_segment(&sub.notification_uri), sub.amf_status_uri"
        ),
        vec!["sub.amf_status_uri"]
    );
    // A shadowing named argument counts; an unrelated one does not.
    assert!(unredacted_callback_uris(
        "\"to {notify_uri}\", notify_uri = redact_last_segment(&notify_uri)"
    )
    .is_empty());
    assert_eq!(
        unredacted_callback_uris("\"to {notify_uri} {x}\", x = redact_last_segment(&y)"),
        vec!["notify_uri"]
    );
    // A bare local bound from a callback (#1047 review): field or JSON key.
    let src = "fn a() {\n    let uri = sub.notif_uri.clone();\n    let Some(cb) = json.get(\"ucmfNotificationUri\").and_then(f) else { return };\n    let logged = redact_last_segment(&sub.notif_uri);\n    let uri2 = format!(\"{base}/x\");\n}\nfn b() {}\n";
    let names: Vec<String> = tainted_bindings(src)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    assert_eq!(names, vec!["uri", "cb"]);
    // Not taints: a count, an authority, and an `if let` whose body names one.
    let src = "fn c() {\n    let n = subs.iter().filter_map(|s| s.notify_uri.as_deref()).count();\n    let a = uri_authority(&notification_uri);\n    if let Some(id) = &ctx_id {\n        let uri = c.dns_context_notify_uri(id);\n    }\n}\n";
    let names: Vec<String> = tainted_bindings(src)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    assert_eq!(names, vec!["uri"]);
    assert_eq!(
        unredacted_callback_uris_with("\"unusable notifUri {uri}\"", &["uri"]),
        vec!["uri"]
    );
    assert!(is_callback_key("smContextStatusUri") && is_callback_key("notificationDestination"));
    assert!(!is_callback_key("nfInstanceId") && !is_callback_key("apiRoot"));
}
