//! #2172 / #2179 (SECURITY): every NFStatusNotify route applies
//! `nextgcore_sbi::nf_status_notify::refuse_notifier`.
//!
//! A receiver that acts on an NFStatusNotify without it lets any peer that can
//! reach the callback post a forged NF_DEREGISTERED or NF_PROFILE_CHANGED and
//! evict or redirect a healthy NF. This guard checks it **per route**:
//!
//! 1. Every non-comment, non-test line that names an NFStatusNotify path (a
//!    string literal containing `nf-status-notify` or `nfstatus-notify`, or a
//!    use of a module-scoped `const` holding one), whatever its syntax, is
//!    listed: as a route arm in [`ROUTES`] with the handler it dispatches to,
//!    or in [`NOT_ROUTES`] with why it is not one. Both lists name the WHOLE
//!    trimmed line and its enclosing `fn`, and each entry must match exactly
//!    as many lines as it declares (a route: one), so an entry that went
//!    stale, that would also cover a new line, or whose line moved to another
//!    `fn` fails (#2187, R41). A new line that is not listed fails.
//! 2. A route is listed as its whole arm, from the line naming the path to the
//!    handler call, and the tree must match it line for line. Before the
//!    handler call the arm may only dispatch (no `;`, no call outside a match
//!    guard), so the guarded handler is the first thing the arm runs (#2187,
//!    R41: a side effect before it passed the old "called within 8 lines").
//!    The handler reaches the shared check: it calls
//!    `nf_status_notify::refuse_notifier` itself, or calls a function of the
//!    same crate that does (followed transitively). What the handler does
//!    BEFORE the check is not read here; the runtime backstops pin it.
//! 3. A receiver under another path is caught by what it must do to receive:
//!    any crate other than the sender (nrfd) that subscribes at
//!    `nnrf-nfm/v1/subscriptions` or builds an `nfStatusNotificationUri` (in
//!    any spelling) must have a listed route.
//!
//! The scanner's own test plants both blind spots of #2172's per-crate guard
//! (a second, unchecked route in a receiver crate; a receiver under a renamed
//! path in another crate), and R41's evasions on #2187 (a nested match arm; a
//! route that ends a call with the same const as an exempted line; an exempted
//! line duplicated; a stale entry; an exempted line moved into the router; a
//! side effect before the guarded call, with and without `;`; a line slipped
//! into a listed arm), and requires each to fail.
//!
//! **Known limits** (#2187, R41). This is a text scan, so a path that never
//! appears whole in one literal or one const is not found:
//! - a path joined at runtime from two consts that each hold a fragment
//!   (`[NS_HEAD, NS_TAIL].concat()` with `"nf-status"` and `"-notify"`);
//! - a `macro_rules!` route that splits the path across `concat!` pieces
//!   (`concat!("nf-", "status-", "notify")`);
//! - a receiver crate that neither names the path whole nor subscribes in a
//!   way item 3 recognises.
//!
//! None of these shapes exists in the tree. The runtime backstop for amfd is
//! `bins/nextgcore-amfd/tests/nf_status_notify_sender_backstop_2179.rs`: it
//! subscribes at a stand-in NRF, then sends a forged NFStatusNotify to every
//! `nfStatusNotificationUri` the subscriptions advertised, through amfd's
//! router under the production profile, and requires 403, with two SMFs cached
//! so an NRF control on the SMF subscription really evicts (and so a forged
//! one acting before the check would be seen). nwdafd's (#2215) is
//! `nf_status_sender_backstop_2215_tests` in its `main.rs`: the router takes
//! its SBI profile as an argument (`nwdaf_sbi_request_handler_with`), so the
//! test drives it under production while sibling tests hold the Dev override.

use std::collections::{BTreeSet, HashMap};

/// (crate, file under src/, the enclosing `fn`, the route arm, the handler the
/// arm calls). The arm is its whole trimmed code lines, from the line that
/// names the path (exactly one such line, in that `fn`) to the line that calls
/// the handler. The lines after the first must follow it exactly, and before
/// the handler call the arm may only dispatch: no `;` (so no statement runs
/// first) and no call outside a match guard (#2187, R41: an arm that acted on
/// the request before calling the guarded handler passed the old "called within
/// 8 lines" check).
type Route<'a> = (&'a str, &'a str, &'a str, &'a [&'a str], &'a str);

const ROUTES: &[Route] = &[
    (
        "nextgcore-amfd",
        "namf_server.rs",
        "namf_request_handler",
        &[
            r#"if parts.len() == 4 && parts[2] == "nf-status-notify" && method == "POST" =>"#,
            "{",
            "handle_nf_status_notify_callback(parts[3], &request).await",
        ],
        "handle_nf_status_notify_callback",
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        "nwdaf_sbi_request_handler_with",
        &[
            "if *segment == nrf_collector::CALLBACK_SEGMENT =>",
            "{",
            "match method {",
            r#""POST" if nrf_collector::holds_callback_token(token) => {"#,
            "nrf_collector::handle_nf_status_notify_from(&request, true, profile).await",
        ],
        "handle_nf_status_notify_from",
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        "nwdaf_sbi_request_handler_with",
        &[
            r#"["nnwdaf-nfstatus-notify", "v1", "notify"] => match method {"#,
            r#""POST" => nrf_collector::handle_nf_status_notify_from(&request, false, profile).await,"#,
        ],
        "handle_nf_status_notify_from",
    ),
];

/// Lines that name an NFStatusNotify path and are NOT a route, with why:
/// (crate, file, the enclosing `fn` or "" at module level, the whole trimmed
/// line, how many lines of that `fn` it is).
///
/// #2187 (R41): matched against the WHOLE trimmed line, not a substring, and
/// the number of lines it matches must be exactly the count given. A substring
/// entry such as `crate::nrf_subscription::NOTIFY_PATH)` also exempted a new
/// route `parts[2].starts_with(crate::nrf_subscription::NOTIFY_PATH) => ...`;
/// now any new line naming the path has to be listed deliberately, and an entry
/// that matches nothing (stale) or more lines than it declares fails. Pinned to
/// the enclosing `fn`, so an exempted line moved into a router is not the
/// listed one.
type NotRoute<'a> = (&'a str, &'a str, &'a str, &'a str, usize);

const NOT_ROUTES: &[NotRoute] = &[
    // The constants that hold the paths.
    (
        "nextgcore-amfd",
        "nrf_subscription.rs",
        "",
        r#"pub const NOTIFY_PATH: &str = "/namf-callback/v1/nf-status-notify";"#,
        1,
    ),
    (
        "nextgcore-nwdafd",
        "nrf_collector.rs",
        "",
        r#"pub const CALLBACK_SEGMENT: &str = "nf-status-notify";"#,
        1,
    ),
    // The nfStatusNotificationUri the NF subscribes with (built, not routed).
    (
        "nextgcore-amfd",
        "nrf_subscription.rs",
        "notification_uri",
        r#"format!("{}{NOTIFY_PATH}", advertised_sbi_base())"#,
        1,
    ),
    (
        "nextgcore-nwdafd",
        "nrf_collector.rs",
        "callback_path_for",
        r#"format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{token}")"#,
        1,
    ),
    // Locating the token segment in a configured callback URI (#2131).
    (
        "nextgcore-nwdafd",
        "nrf_collector.rs",
        "callback_uri_with_token",
        r#"let marker = format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/");"#,
        1,
    ),
    // Log text: a callback URI without the token segment is not subscribed.
    (
        "nextgcore-nwdafd",
        "nrf_collector.rs",
        "subscribe_nf_status",
        r#"{CALLBACK_SEGMENT}/ token segment, so its notifications could name no \"#,
        1,
    ),
    // The OAuth2 callback exemptions, which let the route's token through the
    // bearer check and do not themselves serve anything.
    (
        "nextgcore-amfd",
        "namf_server.rs",
        "oauth2_callback_exemptions",
        r#"format!("{}/{{token}}", crate::nrf_subscription::NOTIFY_PATH),"#,
        1,
    ),
    (
        "nextgcore-nwdafd",
        "main.rs",
        "oauth2_callback_exemptions_from",
        "route(nrf_collector::CALLBACK_SEGMENT),",
        1,
    ),
    // The 405 text inside the guarded nwdafd arm.
    (
        "nextgcore-nwdafd",
        "main.rs",
        "nwdaf_sbi_request_handler_with",
        r#"_ => send_method_not_allowed(method, "nf-status-notify/{token}"),"#,
        1,
    ),
    // Log-only arms of the ported state machines: no HTTP route dispatches an
    // SBI request to them (they are fed timer events only), and they act on nothing.
    (
        "nextgcore-bsfd",
        "bsf_sm.rs",
        "handle_nnrf_nfm_request",
        r#"Some("nf-status-notify") => match method {"#,
        1,
    ),
    (
        "nextgcore-nssfd",
        "nssf_sm.rs",
        "handle_nnrf_nfm_request",
        r#"Some("nf-status-notify") => match method {"#,
        1,
    ),
    (
        "nextgcore-seppd",
        "sepp_sm.rs",
        "handle_nnrf_nfm_request",
        r#"Some("nf-status-notify") => match method {"#,
        1,
    ),
    (
        "nextgcore-udrd",
        "udr_sm.rs",
        "handle_nnrf_nfm_request",
        r#"Some("nf-status-notify") => {"#,
        1,
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
/// (file, enclosing fn, trimmed line), whatever its syntax: a string literal containing
/// `nf-status-notify` or `nfstatus-notify` (a match arm, a slice pattern, an
/// `==`, a `format!`), or a use of a `const` holding such a path (`NAME` in the
/// file that defines it, `module::NAME` anywhere; another module's const of the
/// same name is not). #2187 (R41): a nested `"nf-status-notify" => ...` arm is
/// such a line, so it is found without recognising match shapes.
fn path_mentions(sources: &Sources) -> Vec<(String, String, String)> {
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
        let spans = fn_spans(text);
        for (at, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let l = line.trim();
            let uses_const = consts.iter().any(|(def_file, module, name)| {
                l.contains(&format!("{module}::{name}"))
                    || (def_file == file && contains_word(l, name))
            });
            if names_notify_path(l) || uses_const {
                out.push((file.clone(), enclosing_fn(&spans, at), l.to_string()));
            }
        }
    }
    out
}

/// Every `fn` in `text`: (first line, last line, name). A body ends at the
/// closing brace at the definition's indentation, or on its own line when the
/// definition opens and closes there.
fn fn_spans(text: &str) -> Vec<(usize, usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let Some(at) = trimmed.find("fn ") else {
            continue;
        };
        let keywords_only = trimmed[..at]
            .split_whitespace()
            .all(|w| ["pub", "pub(crate)", "async", "const", "unsafe"].contains(&w));
        let name: String = trimmed[at + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !keywords_only || name.is_empty() {
            continue;
        }
        let opens = line.matches('{').count();
        let end = if opens > 0 && opens == line.matches('}').count() {
            i
        } else {
            let close = format!("{}}}", " ".repeat(line.len() - trimmed.len()));
            (i..lines.len())
                .find(|&k| lines[k] == close)
                .unwrap_or(lines.len() - 1)
        };
        out.push((i, end, name));
    }
    out
}

/// The innermost `fn` of `spans` containing line `at`, or "" at module level.
fn enclosing_fn(spans: &[(usize, usize, String)], at: usize) -> String {
    spans
        .iter()
        .filter(|(start, end, _)| *start <= at && at <= *end)
        .max_by_key(|(start, _, _)| *start)
        .map_or_else(String::new, |(_, _, name)| name.clone())
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
        for (start, end, name) in fn_spans(text) {
            out.entry(name)
                .or_insert_with(|| lines[start..=end].join("\n") + "\n");
        }
    }
    out
}

/// Whether, in `arm` (its lines joined), the handler call is the first thing
/// that runs: before `handler(` there is no `;` and, outside match guards
/// (`if ... =>`), no call. The text before the arm's first `=>` is the pattern
/// line and is not looked at here (it is listed whole).
fn handler_runs_first(arm: &str, handler: &str) -> bool {
    let Some(call) = arm.find(&format!("{handler}(")) else {
        return false;
    };
    let after_pattern = arm[..call].find("=>").map_or(0, |at| at + 2);
    let mut prelude = arm[after_pattern..call].to_string();
    while let Some(at) = prelude.find(" if ") {
        let Some(len) = prelude[at..].find("=>") else {
            break;
        };
        prelude.replace_range(at..at + len + 2, " ");
    }
    !prelude.contains(';') && !prelude.contains('(')
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

/// Every problem the guard finds in `crates` (name -> sources), for `routes`
/// and `not_routes`. Both lists are matched against whole trimmed lines within
/// their enclosing `fn`, and each entry must match exactly as many lines as it
/// declares (a route: one).
fn problems(
    crates: &[(String, Sources)],
    routes: &[Route],
    not_routes: &[NotRoute],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut route_hits = vec![0usize; routes.len()];
    let mut not_route_hits = vec![0usize; not_routes.len()];
    for (name, sources) in crates {
        if SENDERS.contains(&name.as_str()) {
            continue;
        }
        for (file, func, line) in path_mentions(sources) {
            let at = |c: &str, f: &str, g: &str, l: &str| {
                c == name && f == file && g == func && l == line
            };
            let route = routes.iter().position(|r| at(r.0, r.1, r.2, r.3[0]));
            let not_route = not_routes.iter().position(|n| at(n.0, n.1, n.2, n.3));
            match (route, not_route) {
                (Some(i), _) => route_hits[i] += 1,
                (None, Some(i)) => not_route_hits[i] += 1,
                (None, None) => out.push(format!(
                    "{name}/{file}: unlisted NFStatusNotify route arm `{line}` in fn `{func}`"
                )),
            }
        }
        let listed: Vec<_> = routes.iter().filter(|r| r.0 == name).collect();
        let fns = functions(sources);
        for (_, file, _, arm, handler) in &listed {
            let Some((_, text)) = sources.iter().find(|(f, _)| f == file) else {
                out.push(format!("{name}/{file}: listed route file is missing"));
                continue;
            };
            let lines: Vec<&str> = code_lines(text).map(str::trim).collect();
            let Some(at) = lines.iter().position(|l| *l == arm[0]) else {
                continue; // reported below as matching no line
            };
            let found = lines.get(at..at + arm.len()).unwrap_or_default();
            if found != *arm {
                out.push(format!(
                    "{name}/{file}: route `{}` is no longer the listed arm: {found:?}",
                    arm[0]
                ));
            } else if !handler_runs_first(&arm.join("\n"), handler) {
                out.push(format!(
                    "{name}/{file}: in route `{}`, {handler} is not the arm's first statement",
                    arm[0]
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
    let counted = routes
        .iter()
        .zip(&route_hits)
        .map(|(r, n)| ((r.0, r.1, r.2, r.3[0]), 1, *n))
        .chain(
            not_routes
                .iter()
                .zip(&not_route_hits)
                .map(|(e, n)| ((e.0, e.1, e.2, e.3), e.4, *n)),
        );
    for ((name, file, func, line), declared, found) in counted {
        if found == 0 {
            out.push(format!(
                "{name}/{file}: stale entry, it matches no line in fn `{func}`: `{line}`"
            ));
        } else if found != declared {
            out.push(format!(
                "{name}/{file}: entry matches {found} lines, declared {declared}: `{line}`"
            ));
        }
    }
    out
}

fn problems3(crates: &[(String, Sources)], routes: &[Route]) -> Vec<String> {
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
    let arm: &[&str] = &[r#""cb" if parts[2] == "nf-status-notify" => { on_notify(parts[3]) }"#];
    let routes = [("x-amfd", "server.rs", "route", arm, "on_notify")];
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

    // #2187 (R41): a NOT_ROUTES entry matches its whole line, as many times as
    // it declares. The exempted line ends a call with the path const; a route
    // that does the same is a different line and is not exempted.
    let paths = "pub const NOTIFY_PATH: &str = \"/cb/v1/nf-status-notify\";\n";
    let exempt = r#"format!("{}/{{token}}", crate::paths::NOTIFY_PATH),"#;
    let exempting = |server: &str| {
        let server =
            format!("{server}fn exemptions() {{\n    vec![\n        {exempt}\n    ]\n}}\n");
        vec![(
            "x-amfd".to_string(),
            src(&[("paths.rs", paths), ("server.rs", &server)]),
        )]
    };
    let not_routes = [
        (
            "x-amfd",
            "paths.rs",
            "",
            r#"pub const NOTIFY_PATH: &str = "/cb/v1/nf-status-notify";"#,
            1,
        ),
        ("x-amfd", "server.rs", "exemptions", exempt, 1),
    ];
    assert_eq!(
        problems(&exempting(guarded), &routes, &not_routes),
        Vec::<String>::new(),
        "the guarded shape with its exemption passes"
    );
    let starts_with = guarded.replace(
        "    }\n}\nfn on_notify",
        "        \"cb4\" if parts[2].starts_with(crate::paths::NOTIFY_PATH) => act(parts[3]),\n    }\n}\nfn on_notify",
    );
    // R41's evasion exactly: the entry written as the substring the old
    // matcher took (`...NOTIFY_PATH)`) exempted this route too. Now an entry
    // names one whole line, so neither spelling of the entry exempts it.
    let as_substring = [
        not_routes[0],
        (
            "x-amfd",
            "server.rs",
            "exemptions",
            "crate::paths::NOTIFY_PATH)",
            1,
        ),
    ];
    for entries in [&not_routes, &as_substring] {
        let found = problems(&exempting(&starts_with), &routes, entries);
        assert!(
            found
                .iter()
                .any(|p| p.contains("unlisted NFStatusNotify route arm")
                    && p.contains("starts_with(crate::paths::NOTIFY_PATH)")),
            "a route ending a call with an exempted line's const fails ({:?}): {found:?}",
            entries[1].3
        );
    }
    let twice = vec![(
        "x-amfd".to_string(),
        src(&[
            ("paths.rs", paths),
            (
                "server.rs",
                &format!("{guarded}fn exemptions() {{\n    vec![\n        {exempt}\n        {exempt}\n    ]\n}}\n"),
            ),
        ]),
    )];
    let found = problems(&twice, &routes, &not_routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("entry matches 2 lines, declared 1")),
        "an exempted line written twice fails: {found:?}"
    );
    let gone = [
        not_routes[0],
        not_routes[1],
        (
            "x-amfd",
            "server.rs",
            "exemptions",
            "let gone = NOTIFY_PATH;",
            1,
        ),
    ];
    let found = problems(&exempting(guarded), &routes, &gone);
    assert!(
        found
            .iter()
            .any(|p| p.contains("stale entry, it matches no line")),
        "an entry that matches nothing fails: {found:?}"
    );

    // #2187 (R41, second round): an exempted line moved out of its `fn` into
    // the router is not the listed line, though the file still has one copy.
    let moved = vec![(
        "x-amfd".to_string(),
        src(&[
            ("paths.rs", paths),
            (
                "server.rs",
                &format!(
                    "{}fn exemptions() {{\n    vec![]\n}}\n",
                    guarded.replace(
                        "    }\n}\nfn on_notify",
                        &format!("        p if template_matches(p,\n            {exempt}\n        ) => act(p),\n    }}\n}}\nfn on_notify"),
                    )
                ),
            ),
        ]),
    )];
    let found = problems(&moved, &routes, &not_routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("unlisted NFStatusNotify route arm") && p.contains("in fn `route`")),
        "an exempted line moved into the router fails: {found:?}"
    );

    // #2187 (R41, second round): a side effect before the guarded call. Even
    // listed as the arm, the handler is then not the arm's first statement.
    let acting_arm: &[&str] =
        &[r#""cb" if parts[2] == "nf-status-notify" => { act(&parts); on_notify(parts[3]) }"#];
    let acting = guarded.replace(arm[0], acting_arm[0]);
    let found = problems3(
        &one("x-amfd", "server.rs", &acting),
        &[("x-amfd", "server.rs", "route", acting_arm, "on_notify")],
    );
    assert!(
        found
            .iter()
            .any(|p| p.contains("on_notify is not the arm's first statement")),
        "an arm acting before the guarded call fails: {found:?}"
    );
    // ...and a call with no `;` (a tuple whose second half is the handler).
    let tupled_arm: &[&str] =
        &[r#""cb" if parts[2] == "nf-status-notify" => { (act(&parts), on_notify(parts[3])).1 }"#];
    let found = problems3(
        &one(
            "x-amfd",
            "server.rs",
            &guarded.replace(arm[0], tupled_arm[0]),
        ),
        &[("x-amfd", "server.rs", "route", tupled_arm, "on_notify")],
    );
    assert!(
        found
            .iter()
            .any(|p| p.contains("on_notify is not the arm's first statement")),
        "a call before the guarded call fails: {found:?}"
    );
    // A multi-line arm with a line slipped in is no longer the listed arm.
    let multi = guarded.replace(
        arm[0],
        "\"cb\" if parts[2] == \"nf-status-notify\" => {\n            on_notify(parts[3])\n        }",
    );
    let multi_arm: &[&str] = &[
        r#""cb" if parts[2] == "nf-status-notify" => {"#,
        "on_notify(parts[3])",
    ];
    let multi_routes = [("x-amfd", "server.rs", "route", multi_arm, "on_notify")];
    assert_eq!(
        problems3(&one("x-amfd", "server.rs", &multi), &multi_routes),
        Vec::<String>::new(),
        "the multi-line guarded arm passes"
    );
    let slipped = multi.replace(
        "=> {\n            on_notify",
        "=> {\n            act(&parts);\n            on_notify",
    );
    let found = problems3(&one("x-amfd", "server.rs", &slipped), &multi_routes);
    assert!(
        found
            .iter()
            .any(|p| p.contains("is no longer the listed arm")),
        "a line slipped into a listed arm fails: {found:?}"
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
