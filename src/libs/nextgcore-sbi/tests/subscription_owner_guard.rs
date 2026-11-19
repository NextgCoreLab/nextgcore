//! Every route that modifies or removes a subscription checks its caller through
//! `nextgcore_sbi::owner_binding` (#1865).
//!
//! #1809 bound nrfd's subscriptions to the consumer that created them; every
//! other NF let any caller that learned a subscription ID modify or cancel it.
//! #1865 lifted the check into `owner_binding` and adopted it in each NF. This
//! test reads every daemon's production sources and judges each **route arm**,
//! not each crate (R32 on #1936 M2: a crate-wide check let an unchecked route
//! into a crate that used the helper elsewhere):
//!
//! - a route arm is a `match` arm whose pattern names a `PATCH`, `PUT` or
//!   `DELETE` method literal;
//! - it is a subscription route when its pattern, or the pattern of the arm it
//!   is nested in, has a string literal naming `subscription` (any spelling:
//!   `subscriptions`, `sdm-subscriptions`, `events-subscription`);
//! - such an arm must reach an owner check: its own body, or a function it calls
//!   (transitively, within the crate), names `owner_binding::refuse_non_owner`,
//!   `owner_binding::non_owner_refusal` or a crate's own named check
//!   ([`OWN_CHECKS`]);
//! - otherwise it must be on [`ALLOWED`] with its reason, and an allowlist entry
//!   that matches nothing fails the test.
//!
//! Test code is removed by brace matching (every `#[cfg(test)]` item, wherever
//! it sits in the file), so a route placed after a test module is still judged.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Owner checks that are not `owner_binding`, per crate, with why.
const OWN_CHECKS: &[(&str, &str, &str)] = &[
    (
        "nextgcore-nrfd",
        "bind_subscription(",
        "#1809: RegistrantIdentity::bind_subscription (PR #1831), which also refuses \
         identities that disagree with INVALID_CLIENT (TS 29.510 Table 6.1.7.3-1)",
    ),
    (
        "nextgcore-nefd",
        "authenticated_client_id(",
        "#110: northbound AF subscriptions are bound to the authenticated SCS/AS; the AF \
         is not an NF with an NF Instance ID",
    ),
];

/// Subscription route arms that carry no owner check, as (crate, a substring of
/// the arm or its `file:line`, reason). Each must match at least one arm.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "nextgcore-bsfd",
        "/metrics.rs:",
        "a metric label table, not a route",
    ),
    (
        "nextgcore-nssfd",
        "/metrics.rs:",
        "a metric label table, not a route",
    ),
    (
        "nextgcore-udmd",
        "/metrics.rs:",
        "a metric label table, not a route",
    ),
    (
        "nextgcore-udmd",
        r#"Some(&["DELETE", "PATCH"])"#,
        "the Allow-header table for sdm-subscriptions, not a route",
    ),
    (
        "nextgcore-udmd",
        r#"send_not_implemented("sdm-subscriptions PATCH"#,
        "answers 501 and changes nothing",
    ),
    (
        "nextgcore-eesd",
        "No UE location subscription exists",
        "answers 404: no UE location subscription can be created",
    ),
    (
        "nextgcore-pcfd",
        r#"send_method_not_allowed_with_allow(method, uri, &["GET", "PUT", "DELETE"])"#,
        "answers 405 for an unsupported method and changes nothing",
    ),
    (
        "nextgcore-udrd",
        r#"Some("authentication-subscription")"#,
        "subscriber authentication data, not an event subscription; served to the UDM \
         only by its resource scope (#1811)",
    ),
    (
        "nextgcore-nwdafd",
        r#"["subscriptions", id] if m.role == Role::Anlf"#,
        "#1937: MLModelMonitor subscriptions (demo-feature gated) are not yet bound",
    ),
];

// ---------------------------------------------------------------- source model

/// `text` with every comment, string and char literal's CONTENT blanked to
/// spaces (delimiters kept), so braces and keywords can be matched on code
/// only. Same length and line structure as `text`.
fn code_only(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in out.iter_mut().take(to).skip(from) {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = text[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = text[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let end = text[j + 1..]
                    .find(&close)
                    .map_or(b.len(), |n| j + 1 + n + close.len());
                blank(&mut out, j + 1, end.saturating_sub(close.len()));
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
                blank(&mut out, i + 1, j.min(b.len()));
                i = j + 1;
            }
            b'\'' => {
                // A char literal ('x', '\n', '{'), not a lifetime ('a).
                let lit_end = if b.get(i + 1) == Some(&b'\\') {
                    text[i + 2..].find('\'').map(|n| i + 2 + n)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    None
                };
                match lit_end {
                    Some(end) => {
                        blank(&mut out, i + 1, end);
                        i = end + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The index just past the `}` matching the `{` at `open` in `code`.
fn matching_brace(code: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, &c) in code.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// `text` with every `#[cfg(test)]` item removed, wherever it sits (an item is
/// everything up to its matching `}` or its `;`), as (original, code-only)
/// strings of equal length, so literals can still be read from the first.
fn production(text: &str) -> (String, String) {
    // Non-ASCII bytes (only ever in comments and literals) become `~`, so byte
    // offsets and char offsets agree everywhere below.
    let ascii: String = text
        .bytes()
        .map(|c| if c.is_ascii() { c as char } else { '~' })
        .collect();
    let text = ascii.as_str();
    let code = code_only(text);
    let cb = code.as_bytes();
    let mut keep = vec![true; cb.len()];
    let mut from = 0;
    while let Some(n) = code[from..].find("#[cfg(test)]") {
        let start = from + n;
        let mut k = start + "#[cfg(test)]".len();
        while k < cb.len() && cb[k] != b'{' && cb[k] != b';' {
            k += 1;
        }
        let end = if k < cb.len() && cb[k] == b'{' {
            matching_brace(cb, k)
        } else {
            (k + 1).min(cb.len())
        };
        for flag in keep.iter_mut().take(end).skip(start) {
            *flag = false;
        }
        from = end;
    }
    let pick = |s: &str| -> String {
        s.bytes()
            .zip(&keep)
            .map(|(c, &k)| if k || c == b'\n' { c } else { b' ' })
            .map(char::from)
            .collect()
    };
    (pick(text), pick(&code))
}

/// Every `fn name` in `code` with its body (from `text`), for call tracing.
fn functions(text: &str, code: &str) -> Vec<(String, String, String)> {
    let cb = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(n) = code[from..].find("fn ") {
        let at = from + n;
        from = at + 3;
        if at > 0 && (cb[at - 1].is_ascii_alphanumeric() || cb[at - 1] == b'_') {
            continue;
        }
        let name: String = code[at + 3..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(open) = code[at..].find(['{', ';']).map(|k| at + k) else {
            continue;
        };
        if cb[open] == b';' {
            continue;
        }
        let end = matching_brace(cb, open);
        out.push((
            name,
            text[open..end].to_string(),
            code[open..end].to_string(),
        ));
    }
    out
}

/// Whether `body_code` calls `name(...)` (or `path::name(...)`).
fn calls(body_code: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(n) = body_code[from..].find(name) {
        let at = from + n;
        from = at + name.len();
        let before = body_code[..at].chars().next_back();
        let after = body_code[at + name.len()..].trim_start().chars().next();
        if !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') && after == Some('(') {
            return true;
        }
    }
    false
}

const CHECKS: &[&str] = &[
    "owner_binding::refuse_non_owner",
    "owner_binding::non_owner_refusal",
];

/// The names of the functions in a crate that reach an owner check.
fn checking_functions(fns: &[(String, String, String)], own: &[&str]) -> HashSet<String> {
    let direct = |body: &str| CHECKS.iter().chain(own).any(|m| body.contains(m));
    let mut set: HashSet<String> = fns
        .iter()
        .filter(|(_, b, _)| direct(b))
        .map(|(n, _, _)| n.clone())
        .collect();
    loop {
        let before = set.len();
        for (name, _, body_code) in fns {
            if !set.contains(name) && set.iter().any(|c| calls(body_code, c)) {
                set.insert(name.clone());
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

/// A subscription route arm: its line, its pattern with the enclosing arm's,
/// and its body.
#[derive(Debug)]
struct Arm {
    line: usize,
    context: String,
    body: String,
    body_code: String,
}

/// Whether a string literal in `pattern_text` names a subscription resource.
fn names_subscription(pattern_text: &str) -> bool {
    pattern_text
        .split('"')
        .skip(1)
        .step_by(2)
        .any(|lit| lit.to_ascii_lowercase().contains("subscription"))
}

const METHODS: &[&str] = &["\"PATCH\"", "\"PUT\"", "\"DELETE\""];

/// Every PATCH/PUT/DELETE match arm on a subscription resource in one file.
fn subscription_arms(text: &str, code: &str) -> Vec<Arm> {
    let lines: Vec<&str> = text.lines().collect();
    let code_lines: Vec<&str> = code.lines().collect();
    let indent = |s: &str| s.len() - s.trim_start().len();
    let mut offsets = Vec::with_capacity(lines.len());
    let mut off = 0;
    for l in text.split_inclusive('\n') {
        offsets.push(off);
        off += l.len();
    }
    let cb = code.as_bytes();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !METHODS.iter().any(|m| line.contains(m)) || code_lines[i].trim().is_empty() {
            continue;
        }
        // The arm's pattern runs to its `=>`, on this line or up to 3 more.
        let mut pattern = String::new();
        let mut arrow = None;
        for (j, l) in lines.iter().enumerate().skip(i).take(4) {
            if let Some(k) = code_lines[j].find("=>") {
                pattern.push_str(&l[..k]);
                arrow = Some(offsets[j] + k + 2);
                break;
            }
            pattern.push_str(l);
            pattern.push('\n');
        }
        let Some(arrow) = arrow else { continue };
        // A method literal used as a value (a request builder, a header) is
        // not a pattern.
        if !METHODS.iter().any(|m| pattern.contains(m)) {
            continue;
        }
        // The pattern of the arm this one is nested in.
        let my_indent = indent(line);
        let enclosing = (0..i)
            .rev()
            .find(|&j| {
                let c = code_lines[j].trim_end();
                indent(lines[j]) < my_indent
                    && c.contains("=>")
                    && (c.contains("=> match") || c.ends_with('{'))
            })
            .map(|j| lines[j].to_string())
            .unwrap_or_default();
        let context = format!("{enclosing}\n{pattern}");
        if !names_subscription(&context) {
            continue;
        }
        // The arm's body: a block, or the expression up to the arm's `,`.
        let mut k = arrow;
        while k < cb.len() && cb[k].is_ascii_whitespace() {
            k += 1;
        }
        let end = if cb.get(k) == Some(&b'{') {
            matching_brace(cb, k)
        } else {
            let mut depth = 0i32;
            let mut e = k;
            while e < cb.len() {
                match cb[e] {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    b',' if depth == 0 => break,
                    _ => {}
                }
                e += 1;
            }
            e
        };
        out.push(Arm {
            line: i + 1,
            context,
            body: text[k..end].to_string(),
            body_code: code[k..end].to_string(),
        });
    }
    out
}

/// The unchecked subscription arms in one crate, as (`file:line`, arm).
fn unchecked(files: &[(String, String)], own: &[&str]) -> Vec<(String, String)> {
    let prod: Vec<(String, String, String)> = files
        .iter()
        .map(|(name, text)| {
            let (t, c) = production(text);
            (name.clone(), t, c)
        })
        .collect();
    let fns: Vec<(String, String, String)> =
        prod.iter().flat_map(|(_, t, c)| functions(t, c)).collect();
    let checking = checking_functions(&fns, own);
    let mut out = Vec::new();
    for (name, text, code) in &prod {
        for arm in subscription_arms(text, code) {
            let ok = CHECKS.iter().chain(own).any(|m| arm.body.contains(m))
                || checking.iter().any(|f| calls(&arm.body_code, f));
            if !ok {
                out.push((
                    format!("{name}:{}", arm.line),
                    format!("{} => {}", arm.context.trim(), arm.body.trim()),
                ));
            }
        }
    }
    out
}

// ---------------------------------------------------------------- the tests

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn one(src: &str) -> Vec<(String, String)> {
    unchecked(&[("x.rs".to_string(), src.to_string())], &[])
}

/// REVERT-VERIFIED (R32 on #1936 M2): each of R32's evasions of the old
/// crate-wide guard is caught: (a) an unchecked DELETE beside checked ones,
/// (b) a singular `events-subscription` resource, (c) a PATCH-only route, (d)
/// a route placed after the file's first test module; the checked forms
/// (direct, through a wrapper, under a nested method match) pass.
#[test]
fn the_detector_judges_every_subscription_route_arm() {
    let checked = r#"
        fn del(r: &R) -> S { if let Some(x) = owner_binding::refuse_non_owner(o, r, "D") { return x; } ok() }
        fn wrapped(r: &R) -> S { del(r) }
        fn route(m: &str, r: &R) -> S {
            match (svc, res, m) {
                ("evts", "subscriptions", "DELETE") => del(r),
                ("evts", "subscriptions", "PATCH") => { wrapped(r) }
                (_, "contexts", "DELETE") => gone(),
                _ => nf(),
            }
        }
        fn nested(m: &str, r: &R) -> S {
            match parts {
                ["x", "v1", "subscriptions", id] => match m {
                    "PUT" => wrapped(r),
                    "DELETE" => del(r),
                    _ => nf(),
                },
                _ => nf(),
            }
        }
    "#;
    assert!(one(checked).is_empty(), "{:?}", one(checked));

    // (a) one unchecked arm in a file that checks elsewhere.
    let a = format!(
        "{checked}\nfn more(m: &str) -> S {{ match (m, x) {{ (\"DELETE\", Some(\"subscriptions\")) => S::with_status(204), _ => nf() }} }}"
    );
    assert_eq!(one(&a).len(), 1, "{:?}", one(&a));
    // (b) the singular spelling.
    let b = r#"fn r(m: &str) -> S { match (res, m) { ("events-subscription", "DELETE") => drop_it(), _ => nf() } }"#;
    assert_eq!(one(b).len(), 1, "{:?}", one(b));
    // (c) PATCH only, no DELETE anywhere.
    let c = r#"
        fn r(m: &str) -> S {
            match p {
                ["h", "subscriptions", id] => match m {
                    "PATCH" => edit(id),
                    _ => nf(),
                },
                _ => nf(),
            }
        }
    "#;
    assert_eq!(one(c).len(), 1, "{:?}", one(c));
    // (d) after a test module.
    let d = r#"
        #[cfg(test)]
        mod tests { fn t() { let _ = "subscriptions"; } }
        fn r(m: &str) -> S { match (res, m) { ("subscriptions", "DELETE") => drop_it(), _ => nf() } }
    "#;
    assert_eq!(one(d).len(), 1, "{:?}", one(d));
    // A route only in test code is not production.
    let t = r#"
        #[cfg(test)]
        mod tests { fn r(m: &str) -> S { match (res, m) { ("subscriptions", "DELETE") => drop_it(), _ => nf() } } }
    "#;
    assert!(one(t).is_empty(), "{:?}", one(t));
    // Braces and arrows in strings and comments do not confuse it.
    let s = r#"
        // ("subscriptions", "DELETE") => nope(),
        fn r(m: &str) -> S { let _ = "{ => }"; match (res, m) { ("subscriptions", "DELETE") => del(r), _ => nf() } }
        fn del(r: &R) -> S { owner_binding::refuse_non_owner(o, r, "x").unwrap_or_else(ok) }
    "#;
    assert!(one(s).is_empty(), "{:?}", one(s));
}

#[test]
fn every_subscription_route_checks_its_caller() {
    let bins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bins");
    let mut crates: Vec<PathBuf> = fs::read_dir(&bins)
        .expect("src/bins")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    crates.sort();

    let mut problems = Vec::new();
    let mut allowed_hits: HashMap<usize, usize> = HashMap::new();
    let mut judged = HashSet::new();
    for krate in &crates {
        let name = krate.file_name().unwrap().to_string_lossy().to_string();
        let mut paths = Vec::new();
        rust_files(&krate.join("src"), &mut paths);
        paths.sort();
        let files: Vec<(String, String)> = paths
            .iter()
            .map(|p| {
                (
                    p.strip_prefix(&bins).unwrap().display().to_string(),
                    fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
                )
            })
            .collect();
        if files.iter().any(|(_, t)| {
            let (pt, pc) = production(t);
            !subscription_arms(&pt, &pc).is_empty()
        }) {
            judged.insert(name.clone());
        }
        let own: Vec<&str> = OWN_CHECKS
            .iter()
            .filter(|(c, _, _)| *c == name)
            .map(|(_, m, _)| *m)
            .collect();
        for (at, arm) in unchecked(&files, &own) {
            let seen = format!("{at} {arm}");
            match ALLOWED
                .iter()
                .position(|(c, needle, _)| *c == name && seen.contains(needle))
            {
                Some(k) => *allowed_hits.entry(k).or_default() += 1,
                None => problems.push(format!("{at}: unchecked subscription route: {arm}")),
            }
        }
    }
    for (k, (c, needle, _)) in ALLOWED.iter().enumerate() {
        if !allowed_hits.contains_key(&k) {
            problems.push(format!(
                "ALLOWED ({c}, {needle:?}) matches no route; drop it"
            ));
        }
    }
    // The detector must keep seeing the converted NFs, or it has gone blind
    // and every route passes vacuously.
    for expected in [
        "amfd", "udmd", "smfd", "pcfd", "bsfd", "nwdafd", "tsctsf", "lmfd", "mbsmfd", "nsacfd",
        "eesd", "udrd", "ucmfd", "dccfd", "nssfd", "nrfd",
    ] {
        let expected = format!("nextgcore-{expected}");
        assert!(
            judged.contains(&expected),
            "the detector no longer sees {expected}'s subscription routes: {judged:?}"
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
