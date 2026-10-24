//! #915 follow-up: an async test-lock helper called without `.await` compiles,
//! because a future bound to `_guard` counts as used, but it takes no lock. That
//! is how four amfd tests ran with no SMF environment set, and one failed only
//! by luck. This scan fails any call of the helpers below, or `.lock()` on the
//! tokio test locks, that is not awaited, in production or test code.

use std::fs;
use std::path::{Path, PathBuf};

/// The async guard helpers that must be awaited.
const MUST_AWAIT: &[&str] = &[
    "SmfEnvGuard::acquire(",
    "UcmfEnvGuard::acquire(",
    "congestion_test_guard(",
    "emergency_policy_test_guard(",
];

/// The tokio-mutex test locks (`test_support`): `.lock()` on them must be
/// awaited (`.blocking_lock()` is the sync form, and is a different method).
const TOKIO_LOCKS: &[&str] = &["CONTEXT_GUARD", "SMF_ENV_LOCK", "UCMF_ENV_LOCK"];

/// Byte offsets of `NAME<ws>.lock(..)` calls on a [`TOKIO_LOCKS`] static that
/// are not followed by `.await`.
fn unawaited_locks(text: &str, name: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        from = start + name.len();
        let rest = &text[from..];
        let trimmed = rest.trim_start();
        let Some(after) = trimmed.strip_prefix(".lock(") else {
            continue;
        };
        let Some(close) = after.find(')') else {
            continue;
        };
        if !after[close + 1..].trim_start().starts_with(".await") {
            out.push(start);
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Byte offsets of un-awaited calls of `call` in `text`: the call's matching
/// `)` must be followed (after whitespace) by `.await`. A `fn` definition of
/// the helper is not a call.
fn unawaited(text: &str, call: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(call) {
        let start = from + at;
        from = start + call.len();
        let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
        if text[line_start..start].contains("fn ") {
            continue;
        }
        let open = start + call.len() - 1;
        let mut depth = 0i32;
        let mut close = None;
        for (i, c) in text[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { continue };
        if !text[close + 1..].trim_start().starts_with(".await") {
            out.push(start);
        }
    }
    out
}

#[test]
fn every_async_test_guard_is_awaited() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut problems = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read");
        for name in TOKIO_LOCKS {
            for at in unawaited_locks(&text, name) {
                let line = text[..at].matches('\n').count() + 1;
                problems.push(format!(
                    "{}:{line}: `{name}.lock()` is not awaited (tokio mutex since #643)",
                    file.strip_prefix(&src).unwrap_or(file).display()
                ));
            }
        }
        for call in MUST_AWAIT {
            for at in unawaited(&text, call) {
                let line = text[..at].matches('\n').count() + 1;
                problems.push(format!(
                    "{}:{line}: `{}..)` is not awaited, so it takes no lock",
                    file.strip_prefix(&src).unwrap_or(file).display(),
                    call.trim_end_matches('(').replace('\n', " ")
                ));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn the_scan_sees_an_unawaited_call() {
    let src = "async fn t() {\n    let _a = SmfEnvGuard::acquire(port).await;\n    let _b = SmfEnvGuard::acquire(port);\n    let _c = SmfEnvGuard::acquire(f(x))\n        .await;\n}\nasync fn acquire(port: u16) {}\n";
    let hits = unawaited(src, "SmfEnvGuard::acquire(");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(src[hits[0]..].starts_with("SmfEnvGuard::acquire(port);"));
    let locks = "let _a = crate::test_support::CONTEXT_GUARD.lock().await;\nlet _b = crate::test_support::CONTEXT_GUARD\n    .lock()\n    .unwrap_or_else(|e| e.into_inner());\nlet _c = CONTEXT_GUARD.blocking_lock();\n";
    assert_eq!(unawaited_locks(locks, "CONTEXT_GUARD").len(), 1);
}
