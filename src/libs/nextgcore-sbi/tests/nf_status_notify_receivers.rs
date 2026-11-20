//! #2172 / #2179 (SECURITY): every NFStatusNotify route applies
//! `nextgcore_sbi::nf_status_notify::refuse_notifier`.
//!
//! A receiver that acts on an NFStatusNotify without it lets any peer that can
//! reach the callback post a forged NF_DEREGISTERED or NF_PROFILE_CHANGED and
//! evict or redirect a healthy NF. This guard checks it **per route**:
//!
//! 1. Every router arm that matches an NFStatusNotify path is listed in
//!    [`ROUTES`], with the handler it dispatches to. An arm is a non-comment,
//!    non-test line that compares a path segment to `nf-status-notify` or
//!    `nfstatus-notify` (directly, or through a `const` holding such a path),
//!    or a slice-pattern arm naming one. A new arm that is not listed fails.
//! 2. The listed handler is called in that arm, and its body reaches the
//!    shared check: it calls `nf_status_notify::refuse_notifier` itself, or
//!    calls a function of the same crate that does (followed transitively).
//! 3. A receiver under another path is caught by what it must do to receive:
//!    any crate other than the sender (nrfd) that subscribes at
//!    `nnrf-nfm/v1/subscriptions` or builds an `nfStatusNotificationUri` must
//!    have a listed route.
//!
//! The scanner's own test plants both blind spots of #2172's per-crate guard
//! (a second, unchecked route in a receiver crate; a receiver under a renamed
//! path in another crate) and requires each to fail.

use std::collections::{BTreeSet, HashMap};

/// (crate, file under src/, a substring identifying the route arm, the handler
/// the arm calls).
const ROUTES: &[(&str, &str, &str, &str)] = &[
    (
        "nextgcore-amfd",
        "namf_server.rs",
        r#"parts[2] == "nf-status-notify""#,
        "handle_nf_status_notify_callback",
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        "*segment == nrf_collector::CALLBACK_SEGMENT",
        "handle_nf_status_notify_from",
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        r#"["nnwdaf-nfstatus-notify", "v1", "notify"]"#,
        "handle_nf_status_notify_from",
    ),
];

/// Lines that name an NFStatusNotify path and are NOT a route, with why:
/// (crate, file, a substring of the line).
const NOT_ROUTES: &[(&str, &str, &str)] = &[
    // The constants that hold the paths.
    (
        "nextgcore-amfd",
        "nrf_subscription.rs",
        "pub const NOTIFY_PATH",
    ),
    (
        "nextgcore-nwdafd",
        "nrf_collector.rs",
        "pub const CALLBACK_SEGMENT",
    ),
    // The nfStatusNotificationUri the NF subscribes with (built, not routed).
    ("nextgcore-amfd", "nrf_subscription.rs", "{NOTIFY_PATH}"),
    ("nextgcore-nwdafd", "nrf_collector.rs", "{CALLBACK_SEGMENT}"),
    // The OAuth2 callback exemptions, which let the route's token through the
    // bearer check and do not themselves serve anything.
    (
        "nextgcore-amfd",
        "namf_server.rs",
        "crate::nrf_subscription::NOTIFY_PATH)",
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        "route(nrf_collector::CALLBACK_SEGMENT)",
    ),
    // The 405 text inside the guarded nwdafd arm.
    (
        "nextgcore-nwdafd",
        "main.rs",
        r#"send_method_not_allowed(method, "nf-status-notify/{token}")"#,
    ),
    // Log-only arms of the ported state machines: no HTTP route dispatches an
    // SBI request to them (they are fed timer events only), and they act on nothing.
    (
        "nextgcore-bsfd",
        "bsf_sm.rs",
        r#"Some("nf-status-notify") =>"#,
    ),
    (
        "nextgcore-nssfd",
        "nssf_sm.rs",
        r#"Some("nf-status-notify") =>"#,
    ),
    (
        "nextgcore-seppd",
        "sepp_sm.rs",
        r#"Some("nf-status-notify") =>"#,
    ),
    (
        "nextgcore-udrd",
        "udr_sm.rs",
        r#"Some("nf-status-notify") =>"#,
    ),
];

/// The sender of NFStatusNotify, which builds the route rather than serving it.
const SENDERS: &[&str] = &["nextgcore-nrfd"];

const CHECK: &str = "nf_status_notify::refuse_notifier";

/// One crate's non-test source: (file name, text up to its test module).
type Sources = Vec<(String, String)>;

fn production_text(text: &str) -> &str {
    // Test modules sit at the end of each file in this tree.
    match text.find("#[cfg(test)]\nmod ") {
        Some(at) => &text[..at],
        None => text,
    }
}

fn read_crate(dir: &std::path::Path, out: &mut Sources) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                read_crate(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                out.push((name, production_text(&text).to_string()));
            }
        }
    }
}

fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

fn names_notify_path(s: &str) -> bool {
    s.contains("nf-status-notify") || s.contains("nfstatus-notify")
}

/// Every non-comment line of `sources` that names an NFStatusNotify path, as
/// (file, trimmed line), whatever its syntax: a string literal containing
/// `nf-status-notify` or `nfstatus-notify` (a match arm, a slice pattern, an
/// `==`, a `format!`), or a use of a `const` holding such a path (`NAME` in the
/// file that defines it, `module::NAME` anywhere; another module's const of the
/// same name is not). #2187 (R41): a nested `"nf-status-notify" => ...` arm is
/// such a line, so it is found without recognising match shapes.
fn path_mentions(sources: &Sources) -> Vec<(String, String)> {
    let consts: Vec<(String, String, String)> = sources
        .iter()
        .flat_map(|(file, t)| {
            code_lines(t)
                .filter_map(|l| {
                    let l = l.trim();
                    let rest = l
                        .strip_prefix("pub const ")
                        .or_else(|| l.strip_prefix("pub(crate) const "))
                        .or_else(|| l.strip_prefix("const "))?;
                    let (name, value) = rest.split_once(':')?;
                    let module = file.trim_end_matches(".rs").to_string();
                    names_notify_path(value)
                        .then(|| (file.clone(), module, name.trim().to_string()))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut out = Vec::new();
    for (file, text) in sources {
        for line in code_lines(text) {
            let l = line.trim();
            let uses_const = consts.iter().any(|(def_file, module, name)| {
                l.contains(&format!("{module}::{name}"))
                    || (def_file == file && contains_word(l, name))
            });
            if names_notify_path(l) || uses_const {
                out.push((file.clone(), l.to_string()));
            }
        }
    }
    out
}

fn contains_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

/// #2187: whether `line` names the NFStatusNotify subscription or its callback
/// in any spelling: `nfStatusNotificationUri`, `nf_status_notification_uri`
/// (a serde field renamed to camelCase), or an `NfStatusNotify` type.
fn names_status_subscription(line: &str) -> bool {
    let folded: String = line
        .chars()
        .filter(|c| *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    // The URI in any spelling; the type by its CamelCase name (a snake_case
    // `handle_nf_status_notify` helper with no route, as bsfd has, is not one).
    folded.contains("nfstatusnotificationuri")
        || line.contains("NfStatusNotify")
        || line.contains("nnrf-nfm/v1/subscriptions")
}

/// The functions defined in `sources`, name -> body text (to the closing
/// brace at the definition's indentation).
fn functions(sources: &Sources) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (_, text) in sources {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            let Some(at) = trimmed.find("fn ") else {
                continue;
            };
            let head = &trimmed[..at];
            let keywords_only = head
                .split_whitespace()
                .all(|w| ["pub", "pub(crate)", "async", "const", "unsafe"].contains(&w));
            if !keywords_only {
                continue;
            }
            let name: String = trimmed[at + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let indent = line.len() - trimmed.len();
            let close = format!("{}}}", " ".repeat(indent));
            let mut body = String::new();
            for l in &lines[i..] {
                body.push_str(l);
                body.push('\n');
                if *l == close {
                    break;
                }
            }
            out.entry(name).or_insert(body);
        }
    }
    out
}

/// Whether `name`'s body reaches the shared check, through functions of the
/// same crate.
fn reaches_check(fns: &HashMap<String, String>, name: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut todo = vec![name.to_string()];
    while let Some(f) = todo.pop() {
        if !seen.insert(f.clone()) {
            continue;
        }
        let Some(body) = fns.get(&f) else {
            continue;
        };
        if body.contains(CHECK) {
            return true;
        }
        for other in fns.keys() {
            if other != &f && body.contains(&format!("{other}(")) {
                todo.push(other.clone());
            }
        }
    }
    false
}

/// Every problem the guard finds in `crates` (name -> sources), for `routes`.
fn problems(
    crates: &[(String, Sources)],
    routes: &[(&str, &str, &str, &str)],
    not_routes: &[(&str, &str, &str)],
) -> Vec<String> {
    let mut out = Vec::new();
    for (name, sources) in crates {
        if SENDERS.contains(&name.as_str()) {
            continue;
        }
        let listed: Vec<_> = routes.iter().filter(|r| r.0 == name).collect();
        for (file, line) in path_mentions(sources) {
            let route = listed.iter().any(|r| r.1 == file && line.contains(r.2));
            let explained = not_routes
                .iter()
                .any(|(c, f, m)| c == name && *f == file && line.contains(m));
            if !route && !explained {
                out.push(format!(
                    "{name}/{file}: unlisted NFStatusNotify route arm `{line}`"
                ));
            }
        }
        let fns = functions(sources);
        for (_, file, marker, handler) in &listed {
            let Some((_, text)) = sources.iter().find(|(f, _)| f == file) else {
                out.push(format!("{name}/{file}: listed route file is missing"));
                continue;
            };
            let Some(at) = text.find(marker) else {
                out.push(format!("{name}/{file}: listed route `{marker}` is gone"));
                continue;
            };
            let arm: String = text[at..].lines().take(8).collect::<Vec<_>>().join("\n");
            if !arm.contains(&format!("{handler}(")) {
                out.push(format!(
                    "{name}/{file}: route `{marker}` does not call {handler}"
                ));
            }
            if !reaches_check(&fns, handler) {
                out.push(format!("{name}: {handler} never reaches {CHECK}"));
            }
        }
        let subscribes = sources
            .iter()
            .any(|(_, t)| code_lines(t).any(names_status_subscription));
        if subscribes && listed.is_empty() {
            out.push(format!(
                "{name}: subscribes to NF status at the NRF but has no listed, checked \
                 NFStatusNotify route"
            ));
        }
    }
    out
}

fn problems3(crates: &[(String, Sources)], routes: &[(&str, &str, &str, &str)]) -> Vec<String> {
    problems(crates, routes, &[])
}

fn tree() -> Vec<(String, Sources)> {
    let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is at <root>/libs/nextgcore-sbi")
        .join("bins");
    let mut crates: Vec<_> = std::fs::read_dir(&bins)
        .expect("bins/")
        .flatten()
        .map(|e| e.path())
        .collect();
    crates.sort();
    crates
        .into_iter()
        .map(|k| {
            let mut s = Vec::new();
            read_crate(&k.join("src"), &mut s);
            (k.file_name().unwrap().to_string_lossy().into_owned(), s)
        })
        .collect()
}

#[test]
fn every_nf_status_notify_route_checks_the_sender_2172() {
    assert_eq!(problems(&tree(), ROUTES, NOT_ROUTES), Vec::<String>::new());
}

/// #2179: the guard fails on each blind spot of the per-crate check: a second,
/// unchecked route inside a receiver crate, and a receiver under a renamed path
/// in a crate that subscribes at the NRF. And it passes the guarded shape.
#[test]
fn the_guard_catches_an_unlisted_route_and_a_renamed_receiver_2179() {
    let src = |files: &[(&str, &str)]| -> Sources {
        files
            .iter()
            .map(|(f, t)| (f.to_string(), t.to_string()))
            .collect()
    };
    let guarded = r#"
fn route(parts: &[&str]) {
    match parts[0] {
        "cb" if parts[2] == "nf-status-notify" => { on_notify(parts[3]) }
    }
}
fn on_notify(t: &str) { inner(t) }
fn inner(t: &str) { nextgcore_sbi::nf_status_notify::refuse_notifier(r, true, p); }
"#;
    let routes = [(
        "x-amfd",
        "server.rs",
        r#"parts[2] == "nf-status-notify""#,
        "on_notify",
    )];
    let one = |name: &str, file: &str, text: &str| vec![(name.to_string(), src(&[(file, text)]))];
    assert_eq!(
        problems3(&one("x-amfd", "server.rs", guarded), &routes),
        Vec::<String>::new(),
        "the guarded shape passes"
    );

    // A second route in the same crate, not listed: the per-crate guard passed it.
    let second = guarded.replace(
        "    }\n}\nfn on_notify",
        "        \"cb2\" if parts[2] == \"nf-status-notify-v2\" => { act(parts[3]) }\n    }\n}\nfn on_notify",
    );
    let found = problems3(&one("x-amfd", "server.rs", &second), &routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("unlisted NFStatusNotify route arm")),
        "a second route in a receiver crate fails: {found:?}"
    );

    // The listed handler no longer reaching the check fails.
    let unchecked = guarded.replace(
        "nextgcore_sbi::nf_status_notify::refuse_notifier(r, true, p);",
        "act();",
    );
    let found = problems3(&one("x-amfd", "server.rs", &unchecked), &routes);
    assert!(
        found.iter().any(|p| p.contains("never reaches")),
        "{found:?}"
    );

    // #2187 (R41): a nested match arm, the commonest router shape.
    let nested = guarded.replace(
        "    }\n}\nfn on_notify",
        "        \"cb3\" => match parts[2] { \"nf-status-notify\" => act(parts[3]), _ => {} },\n    }\n}\nfn on_notify",
    );
    let found = problems3(&one("x-amfd", "server.rs", &nested), &routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("unlisted NFStatusNotify route arm")),
        "a nested match arm fails: {found:?}"
    );

    // #2187 (R41): a renamed receiver built from a serde field and a split path.
    let serde = r#"
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Sub { nf_status_notification_uri: String }
fn uri(base: &str) -> String { format!("{base}/nrf-{}", "notify") }
"#;
    let found = problems3(&one("x-serdefd", "main.rs", serde), &routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("subscribes to NF status at the NRF")),
        "a camelCase serde field fails: {found:?}"
    );
    let typed = "fn on(n: NfStatusNotify) { act(n) }\n";
    let found = problems3(&one("x-typedfd", "main.rs", typed), &routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("subscribes to NF status at the NRF")),
        "an NfStatusNotify type fails: {found:?}"
    );

    // A receiver under a renamed path, in a crate that subscribes.
    let renamed = r#"
fn subscribe() { let body = json!({ "nfStatusNotificationUri": format!("{base}/nrf-notify") }); }
fn route(p: &str) { if p == "/nrf-notify" { act() } }
"#;
    let found = problems3(&one("x-newfd", "main.rs", renamed), &routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("subscribes to NF status at the NRF")),
        "a renamed receiver fails: {found:?}"
    );
}
