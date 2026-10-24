//! #915 follow-up: an async test lock or guard helper called without `.await`
//! compiles, because a future bound to `_guard` counts as used, but it takes no
//! lock and sets no environment. That is how four amfd tests ran with no SMF
//! environment set, and how #925 met #915 (#1058).
//!
//! **The rule: await right at the call.** `let _g = CONTEXT_GUARD.lock().await;`,
//! `let _env = SmfEnvGuard::acquire(port).await;`. Never bind the future and await
//! it later, and never hand it to a helper.
//!
//! What must be awaited is DERIVED, so a new lock or helper is covered without
//! touching this file:
//! - every tokio mutex static in amfd's sources (a `tokio::sync::Mutex` type or a
//!   `const_new(` initializer): its `.lock(..)` must be awaited (`.blocking_lock()`
//!   is the sync form and a different method);
//! - every `async fn` in amfd's sources that returns a guard (`...Guard...`) and
//!   every async method of a `*Guard` type (`SmfEnvGuard::acquire`): its call must
//!   be awaited.
//!
//! The scan covers amfd's `src`, and every workspace file that uses
//! `nextgcore_amfd::test_support` (smfd `eps_to_5gs.rs`, pcfd
//! `tests/strict_peer_updp.rs`, ...). Comments and string literals are blanked
//! first, so a doc example does not count.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `text` with comments and string/char literals replaced by spaces (offsets
/// kept), so `"CONTEXT_GUARD.lock()"` in a message or a doc example is not code.
fn code_only(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
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
            b'r' if (b.get(i + 1) == Some(&b'"')
                || (b.get(i + 1) == Some(&b'#') && b.get(i + 2) == Some(&b'"')))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
                let open = i + 1 + hashes + 1;
                let close_pat = format!("\"{}", "#".repeat(hashes));
                let end = text[open..]
                    .find(&close_pat)
                    .map_or(b.len(), |n| open + n + close_pat.len());
                blank(&mut out, i, end);
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(b.len());
                blank(&mut out, i, end);
                i = end;
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') && b.get(i + 1) != Some(&b'\\') => {
                blank(&mut out, i, i + 3);
                i += 3;
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn ident_at(text: &str, start: usize) -> String {
    text[start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// What must be awaited, derived from amfd's sources (already `code_only`):
/// tokio lock statics, and guard-returning async functions and `*Guard` async
/// methods (as call prefixes: `congestion_test_guard(`, `SmfEnvGuard::acquire(`).
fn derive(amfd_sources: &[String]) -> (Vec<String>, Vec<String>) {
    let mut locks: Vec<String> = Vec::new();
    let mut calls: Vec<String> = Vec::new();
    for text in amfd_sources {
        // `static NAME: <type> = <init>;`
        let mut from = 0;
        while let Some(at) = text[from..].find("static ") {
            let start = from + at + "static ".len();
            from = start;
            let name = ident_at(text, start);
            let Some(end) = text[start..].find(';') else {
                break;
            };
            let decl = &text[start..start + end];
            let tokio_lock = decl.contains("Mutex")
                && (decl.contains("tokio::sync::Mutex") || decl.contains("const_new("));
            if tokio_lock && !name.is_empty() && !locks.contains(&name) {
                locks.push(name);
            }
        }
        // `impl NAME {` blocks of `*Guard` types: their async methods.
        let mut from = 0;
        while let Some(at) = text[from..].find("impl ") {
            let start = from + at + "impl ".len();
            from = start;
            let ty = ident_at(text, start);
            if !ty.ends_with("Guard") || !text[start + ty.len()..].trim_start().starts_with('{') {
                continue;
            }
            let body_start = start + text[start..].find('{').unwrap_or(0);
            let mut depth = 0i32;
            let mut body_end = text.len();
            for (i, c) in text[body_start..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body_end = body_start + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let body = &text[body_start..body_end];
            let mut f = 0;
            while let Some(a) = body[f..].find("async fn ") {
                let s = f + a + "async fn ".len();
                f = s;
                let m = ident_at(body, s);
                let call = format!("{ty}::{m}(");
                if !m.is_empty() && !calls.contains(&call) {
                    calls.push(call);
                }
            }
        }
        // Free `async fn name(..) -> ...Guard...`.
        let mut from = 0;
        while let Some(at) = text[from..].find("async fn ") {
            let start = from + at + "async fn ".len();
            from = start;
            let name = ident_at(text, start);
            let Some(brace) = text[start..].find('{') else {
                continue;
            };
            let sig = &text[start..start + brace];
            let ret = sig.split("->").nth(1).unwrap_or("");
            if ret.contains("Guard") && !ret.contains("Self") {
                let call = format!("{name}(");
                if !name.is_empty() && !calls.contains(&call) {
                    calls.push(call);
                }
            }
        }
    }
    (locks, calls)
}

/// Un-awaited uses in `text` (already `code_only`), as `(offset, what)`:
/// `LOCK.lock(..)` (any whitespace before `.lock`) and `call(..)` whose
/// matching `)` is not followed by `.await`. A definition (`fn name(`) is not a
/// call, and a call prefixed by another identifier character is a different
/// function.
fn unawaited(text: &str, locks: &[String], calls: &[String]) -> Vec<(usize, String)> {
    unawaited_in(text, locks, calls, None)
}

/// The amfd test locks a file from another crate names bare: those it imports
/// with `use nextgcore_amfd::test_support::{..}`. Another crate's own lock of
/// the same name (udmd has its own std `CONTEXT_GUARD`) is not amfd's.
fn imported_amfd_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("use nextgcore_amfd::test_support::") {
        let start = from + at + "use nextgcore_amfd::test_support::".len();
        from = start;
        let end = text[start..].find(';').map_or(text.len(), |i| start + i);
        for name in text[start..end].split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// [`unawaited`]; `imported` is `Some` for a file of another crate, where a lock
/// counts only when it is qualified (`nextgcore_amfd::test_support::NAME`) or
/// imported, and amfd's crate-private guard helpers are not callable.
fn unawaited_in(
    text: &str,
    locks: &[String],
    calls: &[String],
    imported: Option<&[String]>,
) -> Vec<(usize, String)> {
    let closing = |open: usize| -> Option<usize> {
        let mut depth = 0i32;
        for (i, c) in text[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + i);
                    }
                }
                _ => {}
            }
        }
        None
    };
    let awaited = |close: usize| text[close + 1..].trim_start().starts_with(".await");
    let ident_char = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for lock in locks {
        let mut from = 0;
        while let Some(at) = text[from..].find(lock.as_str()) {
            let start = from + at;
            from = start + lock.len();
            if text[..start].ends_with(ident_char) || text[from..].starts_with(ident_char) {
                continue;
            }
            if let Some(imported) = imported {
                let qualified = text[..start].ends_with("nextgcore_amfd::test_support::");
                if !qualified && !imported.iter().any(|n| n == lock) {
                    continue;
                }
            }
            let after_name = &text[from..];
            let trimmed = after_name.trim_start();
            if !trimmed.starts_with(".lock(") {
                continue;
            }
            let open = from + (after_name.len() - trimmed.len()) + ".lock".len();
            if let Some(close) = closing(open) {
                if !awaited(close) {
                    out.push((start, format!("{lock}.lock()")));
                }
            }
        }
    }
    for call in calls.iter().filter(|_| imported.is_none()) {
        let mut from = 0;
        while let Some(at) = text[from..].find(call.as_str()) {
            let start = from + at;
            from = start + call.len();
            let before = &text[..start];
            if before.ends_with(ident_char) || before.trim_end().ends_with("fn") {
                continue;
            }
            if let Some(close) = closing(start + call.len() - 1) {
                if !awaited(close) {
                    out.push((start, call.trim_end_matches('(').to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_async_test_guard_is_awaited() {
    let amfd = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bins = amfd.parent().expect("src/bins");
    let mut amfd_files = Vec::new();
    rust_files(&amfd.join("src"), &mut amfd_files);
    let amfd_sources: Vec<String> = amfd_files
        .iter()
        .map(|f| code_only(&fs::read_to_string(f).expect("read")))
        .collect();
    let (locks, calls) = derive(&amfd_sources);
    for must in [
        "CONTEXT_GUARD",
        "SMF_ENV_LOCK",
        "UCMF_ENV_LOCK",
        "CONGESTION_TEST_LOCK",
        "EMERGENCY_POLICY_TEST_LOCK",
        "REACHABILITY_SWEEP_TEST_LOCK",
    ] {
        assert!(
            locks.iter().any(|l| l == must),
            "{must} not derived: {locks:?}"
        );
    }
    assert!(
        calls.iter().any(|c| c == "SmfEnvGuard::acquire("),
        "SmfEnvGuard::acquire not derived: {calls:?}"
    );

    // amfd's own sources, and every workspace file using its test_support.
    let mut files = amfd_files.clone();
    let mut others = Vec::new();
    rust_files(bins, &mut others);
    rust_files(&bins.join("../libs"), &mut others);
    let amfd_dir = amfd.canonicalize().unwrap_or_else(|_| amfd.to_path_buf());
    for f in others {
        let canon = f.canonicalize().unwrap_or_else(|_| f.clone());
        if canon.starts_with(&amfd_dir) {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap_or_default();
        if text.contains("nextgcore_amfd::test_support") {
            files.push(f);
        }
    }
    assert!(
        files.iter().any(|f| f.ends_with("strict_peer_updp.rs"))
            && files.iter().any(|f| f.ends_with("eps_to_5gs.rs")),
        "the cross-crate users are scanned"
    );

    let mut problems = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let text = code_only(&fs::read_to_string(file).expect("read"));
        let cross_crate = i >= amfd_files.len();
        let imported = imported_amfd_names(&text);
        let scope = cross_crate.then_some(imported.as_slice());
        for (at, what) in unawaited_in(&text, &locks, &calls, scope) {
            let line = text[..at].matches('\n').count() + 1;
            problems.push(format!(
                "{}:{line}: `{what}` is not awaited at the call, so it takes no lock",
                file.strip_prefix(bins).unwrap_or(file).display()
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn the_scan_derives_and_sees_its_shapes() {
    let lib = code_only(concat!(
        "pub static A_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());\n",
        "pub static B_LOCK: Mutex<()> = Mutex::const_new(());\n",
        "pub static STD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
        "struct XEnvGuard(u8);\n",
        "impl XEnvGuard {\n",
        "    async fn acquire(p: u16) -> Self { todo!() }\n",
        "    async fn with_other(p: u16) -> Self { todo!() }\n",
        "    fn sync_one() {}\n",
        "}\n",
        "pub(crate) async fn y_test_guard() -> tokio::sync::MutexGuard<'static, ()> { todo!() }\n",
        "async fn not_a_guard() -> u8 { 0 }\n",
    ));
    let (locks, calls) = derive(&[lib]);
    assert_eq!(locks, vec!["A_LOCK", "B_LOCK"]);
    assert_eq!(
        calls,
        vec![
            "XEnvGuard::acquire(",
            "XEnvGuard::with_other(",
            "y_test_guard("
        ]
    );

    let uses = code_only(concat!(
        "async fn t() {\n",
        "let _a = A_LOCK.lock().await;\n",
        "let _b = B_LOCK\n    .lock()\n    .unwrap_or_else(|e| e.into_inner());\n",
        "let _c = A_LOCK.blocking_lock();\n",
        "let _d = XEnvGuard::with_other(f(x));\n",
        "let _e = XEnvGuard::acquire(1)\n    .await;\n",
        "// let _f = A_LOCK.lock();\n",
        "let s = \"A_LOCK.lock()\";\n",
        "let _g = my_y_test_guard();\n",
        "}\n",
    ));
    let hits: Vec<String> = unawaited(&uses, &locks, &calls)
        .into_iter()
        .map(|(_, w)| w)
        .collect();
    assert_eq!(hits, vec!["B_LOCK.lock()", "XEnvGuard::with_other"]);

    // Another crate: its own `B_LOCK` is not amfd's; an imported or qualified one is.
    let other = code_only(concat!(
        "use nextgcore_amfd::test_support::{A_LOCK, init_context};\n",
        "fn t() {\n",
        "let _own = B_LOCK.lock().unwrap();\n",
        "let _x = A_LOCK.lock();\n",
        "let _y = nextgcore_amfd::test_support::B_LOCK.lock();\n",
        "}\n",
    ));
    let imported = imported_amfd_names(&other);
    let hits: Vec<String> = unawaited_in(&other, &locks, &calls, Some(&imported))
        .into_iter()
        .map(|(_, w)| w)
        .collect();
    assert_eq!(hits, vec!["A_LOCK.lock()", "B_LOCK.lock()"]);
}
