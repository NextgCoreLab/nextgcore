//! #2056: a configured listener that cannot be bound is fatal at start-up under the
//! production SBI profile, and tolerated under dev.
//!
//! The fatal arm exits the process, so the scenario runs in a CHILD process: the
//! test re-executes this test binary, running only [`child_binds_a_taken_metrics_port`]
//! with the profile in the environment, and asserts on how it ended.

use std::process::Command;

const CHILD: &str = "NEXTGCORE_TEST_2056_CHILD";
const PORT_ENV: &str = "NEXTGCORE_TEST_2056_METRICS_PORT";

/// The child's body: a no-op unless the parent asked for it. Holds a port, points
/// the NF metrics listener at it and calls the shared `serve_nf_metrics`.
#[tokio::test]
async fn child_binds_a_taken_metrics_port() {
    let Ok(profile) = std::env::var(CHILD) else {
        return;
    };
    nextgcore_core::sbi_profile::SBI_PROFILE_MODE.store(
        if profile == "production" { 2 } else { 1 },
        std::sync::atomic::Ordering::Relaxed,
    );
    let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = taken.local_addr().unwrap().port();
    // SAFETY-free: this child process runs this one test only.
    std::env::set_var(PORT_ENV, port.to_string());
    let served =
        nextgcore_metrics::nf::serve_nf_metrics("TEST", PORT_ENV, std::sync::Arc::new(String::new))
            .await;
    assert!(served.is_none(), "the port was taken");
    println!("SURVIVED-2056");
    drop(taken);
}

fn run_child(profile: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_binds_a_taken_metrics_port", "--nocapture"])
        .env(CHILD, profile)
        .env_remove("NEXTGCORE_METRICS_BIND")
        .output()
        .expect("re-run this test binary")
}

#[test]
fn a_taken_metrics_port_is_fatal_at_startup_under_production_2056() {
    let out = run_child("production");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(nextgcore_metrics::nf::EXIT_LISTENER_BIND_FAILED),
        "stdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(stderr.contains("fatal at start-up"), "{stderr}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("SURVIVED-2056"));
}

#[test]
fn a_taken_metrics_port_is_tolerated_under_dev_2056() {
    let out = run_child("dev");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("SURVIVED-2056"));
}

/// The calls that bind a listener in an NF (#2088, R30 on #2073: not only metrics).
/// Metrics, NES and SLA (`serve_metrics`); TCP; SCTP (`SctpServer` matches the kernel
/// one too, and the NGAP, S1AP and SBc-AP servers that wrap them); Diameter, and the
/// two NF wrappers whose callers decide what a failure means (pcrfd Gx/Rx, hssd S6a).
/// UDP sockets (GTP-C, GTP-U, PFCP, N26) are not listed: they are not in #2056's
/// scope, and N26 is its documented exception.
const LISTENER_BINDS: &[&str] = &[
    "nes_energy::serve_metrics(",
    " serve_metrics(",
    "TcpListener::bind(",
    "SctpServer::bind(",
    "NgapTransport::bind(",
    "S1apServer::bind(",
    "SbcapServer::bind(",
    "DiameterListener::bind(",
    "pcrf_fd_listen(",
    "hss_s6a_bind(",
    "hss_s6a_run_server(",
];

/// `line` without its `//` comment (one outside a string literal). #2088 (R32): a
/// handler named only in a comment counted as a call.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\\' if in_str => {
                i += 2;
                continue;
            }
            b'"' => in_str = !in_str,
            b'/' if !in_str && bytes[i + 1] == b'/' => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The lines (0-based) of the listener call sites in `code`: any [`LISTENER_BINDS`]
/// call outside a comment, not a function's own definition.
fn listener_sites(code: &[&str]) -> Vec<usize> {
    code.iter()
        .map(|l| strip_comment(l))
        .enumerate()
        .filter(|(_, l)| !l.contains("fn ") && LISTENER_BINDS.iter().any(|call| l.contains(call)))
        .map(|(i, _)| i)
        .collect()
}

/// How many lines a call site's statement may run to its `?`.
const PROPAGATE_WINDOW: usize = 10;

/// How far after its call site a listener's bind-failure arm may call the handler.
/// The furthest today is mmed's, 24 lines.
const HANDLER_WINDOW: usize = 30;

/// How far back a `spawn(` is looked for around a site, and how far ahead the
/// receiving end of a bind-result channel.
const SPAWN_LOOKBACK: usize = 20;
const RECV_WINDOW: usize = 80;

/// Whether `line` is a match arm (or `if let`) that carries an error.
fn is_error_arm(line: &str) -> bool {
    let t = line.trim_start();
    ((t.starts_with("Err(") || t.starts_with("Ok(Err(")) && t.contains("=>"))
        || t.contains("if let Err(")
}

/// The end (exclusive) of the construct that starts at `at`: the next non-blank line
/// indented no deeper than it that does not continue it (a call's `)`, an `.await`, an
/// opening `{`).
fn block_end(code: &[&str], at: usize) -> usize {
    let base = indent(code[at]);
    (at + 1..code.len())
        .find(|&k| {
            let t = code[k].trim();
            !t.is_empty()
                && indent(code[k]) <= base
                && ![")", ".", "{"].iter().any(|c| t.starts_with(c))
        })
        .unwrap_or(code.len())
}

/// The lines of the arm starting at `at` (see [`block_end`]).
fn arm_body<'a>(code: &'a [&'a str], at: usize) -> &'a [&'a str] {
    &code[at..block_end(code, at)]
}

/// The error arms of the `match` (or the `if let Err`) whose head is at `head`: the
/// head itself when it is one, and the arms exactly one level in, within the head's own
/// block and before `limit`. Not nested ones (hssd's `if let Err` on its SERVE result,
/// inside the `Ok` arm, is not a bind error arm), nor whatever follows the block.
fn error_arms(code: &[&str], head: usize, limit: usize) -> Vec<usize> {
    let level = indent(code[head]) + 4;
    let end = limit.min(block_end(code, head));
    (head..end)
        .filter(|&k| is_error_arm(code[k]) && (k == head || indent(code[k]) == level))
        .collect()
}

/// Whether the site at `site` sits inside a `spawn(` block: a `?` there ends only the
/// spawned task, and the bind failure is swallowed (#2088, R32).
fn in_spawn(code: &[&str], site: usize) -> bool {
    let at = indent(code[site]);
    (site.saturating_sub(SPAWN_LOOKBACK)..site).any(|k| {
        code[k].contains("spawn(")
            && indent(code[k]) < at
            && (k + 1..site).all(|j| code[j].trim().is_empty() || indent(code[j]) > indent(code[k]))
    })
}

/// #2073 (R31 on #2063), #2088 (R30, R32): the listener call sites in `prod` whose OWN
/// bind failure is not fatal under production. Comments are stripped first. A site is
/// wired when either:
/// - it has error arms one level in (`Err(..) =>`, `Ok(Err(..)) =>`, or `if let Err(..)`
///   on the call), and EACH of them calls `listener_bind_failed(` in its own body, or
///   forwards the error with `.send(Err`. A forwarded error must reach a
///   `recv`/`recv_timeout` within [`RECV_WINDOW`] lines whose own error arms EACH call
///   the handler; or
/// - it has none, and its statement propagates the error with `?` within
///   [`PROPAGATE_WINDOW`] lines, outside any `spawn(` block (start-up fails); or it
///   calls `listener_bind_failed(` within [`HANDLER_WINDOW`] lines.
///
/// All of this must come before the next site, so a second, unwired listener in a file
/// whose first one is wired is still found.
///
/// A source guard is not complete, and these are its known limits:
/// - an ALIASED listener type (`use tokio::net::TcpListener as L; L::bind(..)`) is not
///   matched;
/// - a bind inside a helper whose caller swallows the `?` is credited to the helper's
///   `?`, unless the helper is listed in [`LISTENER_BINDS`] (as pcrfd's and hssd's are).
fn unwired_listener_sites(prod: &[&str]) -> Vec<usize> {
    let code: Vec<&str> = prod.iter().map(|l| strip_comment(l)).collect();
    let code = &code[..];
    let handler = |lines: &[&str]| lines.iter().any(|l| l.contains("listener_bind_failed("));
    let sites = listener_sites(code);
    sites
        .iter()
        .enumerate()
        .filter(|(n, &site)| {
            let next = sites.get(n + 1).copied().unwrap_or(code.len());
            let arms = error_arms(code, site, next);
            if !arms.is_empty() {
                let mut forwarded = false;
                for &arm in &arms {
                    let body = arm_body(code, arm);
                    if handler(body) {
                        continue;
                    }
                    if body.iter().any(|l| l.contains(".send(Err")) {
                        forwarded = true;
                        continue;
                    }
                    return true;
                }
                if forwarded {
                    let recv = (site + 1..(site + RECV_WINDOW).min(code.len())).find(|&k| {
                        code[k].contains("recv_timeout(") || code[k].contains(".recv()")
                    });
                    let Some(recv) = recv else {
                        return true;
                    };
                    let recv_arms = error_arms(code, recv, code.len());
                    return recv_arms.is_empty()
                        || recv_arms.iter().any(|&arm| !handler(arm_body(code, arm)));
                }
                return false;
            }
            let end = next.min(site + HANDLER_WINDOW).min(code.len());
            if handler(&code[site..end]) {
                return false;
            }
            let statement_end = next.min(site + PROPAGATE_WINDOW).min(code.len());
            let propagated = code[site..statement_end]
                .iter()
                .any(|l| l.contains("?;") || l.trim_end().ends_with('?'));
            !propagated || in_spawn(code, site)
        })
        .map(|(_, &site)| site)
        .collect()
}

/// #2073: the guard counts call sites, not files. A file with one wired listener and a
/// second, unwired one fails it; two wired ones and a single wired one pass.
///
/// REVERT-VERIFIED: with the check per file again (any handler call in the file covers
/// every site), this fails: the unwired second site is not reported.
#[test]
fn the_listener_guard_checks_each_call_site_2073() {
    let wired = [
        "    match nextgcore_metrics::nes_energy::serve_metrics(addr, render) {",
        "        Ok(_) => {}",
        "        Err(e) => nextgcore_metrics::nf::listener_bind_failed(\"X\", \"m\", addr, &e),",
        "    }",
    ];
    let unwired =
        ["    let _ = nextgcore_metrics::nes_energy::serve_metrics(addr2, render).await;"];
    let check = |parts: &[&[&str]]| {
        let lines: Vec<&str> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        (listener_sites(&lines).len(), unwired_listener_sites(&lines))
    };

    assert_eq!(check(&[&wired]), (1, vec![]));
    assert_eq!(check(&[&wired, &wired]), (2, vec![]));
    assert_eq!(
        check(&[&wired, &unwired]),
        (2, vec![4]),
        "the second, unwired site is found"
    );
    // The unwired one first: the wired one's handler, after it, does not cover it.
    assert_eq!(check(&[&unwired, &wired]), (2, vec![0]));

    // #2088: TCP, SCTP and Diameter binds are sites too. One whose error is
    // propagated with `?` is wired; an unwired Diameter bind is found.
    let propagated = [
        "    let listener = tokio::net::TcpListener::bind(addr)",
        "        .await",
        "        .context(\"bind failed\")?;",
    ];
    let unwired_diameter =
        ["    let _l = nextgcore_diameter::transport::DiameterListener::bind(addr).await;"];
    let definition = ["pub async fn hss_s6a_bind("];
    assert_eq!(check(&[&propagated]), (1, vec![]));
    assert_eq!(check(&[&propagated, &unwired_diameter]), (2, vec![3]));
    assert_eq!(
        check(&[&definition]),
        (0, vec![]),
        "a definition is not a call"
    );

    // #2088 (R32's plants on #2088):
    // (A) a `?` bind inside a spawned task: the task ends, the failure is swallowed.
    let spawned = [
        "    tokio::spawn(async move {",
        "        let l = tokio::net::TcpListener::bind(addr).await?;",
        "        serve(l).await;",
        "    });",
    ];
    assert_eq!(
        check(&[&spawned]),
        (1, vec![1]),
        "a `?` in a spawn is not propagation"
    );
    // (C) the handler named only in a comment.
    let commented = [
        "    if let Err(e) = nextgcore_metrics::nes_energy::serve_metrics(addr, r).await {",
        "        log::error!(\"{e}\"); // listener_bind_failed(\"X\", \"m\", addr, &e)",
        "    }",
    ];
    assert_eq!(
        check(&[&commented]),
        (1, vec![0]),
        "a comment is not a call"
    );
    // (D) a bind-result channel whose real bind-error arm is unwired, while the
    // timeout arm calls the handler.
    let channel = |bind_err_arm: &'static str| {
        vec![
            "        match nextgcore_hssd::hss_s6a_bind(listen_addr).await {",
            "            Ok(listener) => {",
            "                let _ = bound_tx.send(Ok(()));",
            "                if let Err(e) = nextgcore_hssd::serve(listener).await {",
            "                    log::error!(\"terminated: {e}\");",
            "                }",
            "            }",
            "            Err(e) => {",
            "                let _ = bound_tx.send(Err(e));",
            "            }",
            "        }",
            "    match bound_rx.recv_timeout(std::time::Duration::from_secs(10)) {",
            "        Ok(Ok(())) => {}",
            bind_err_arm,
            "        Err(e) => nextgcore_metrics::nf::listener_bind_failed(\"H\", \"S6a\", a, &e),",
            "    }",
        ]
    };
    let wired_channel = channel(
        "        Ok(Err(e)) => nextgcore_metrics::nf::listener_bind_failed(\"H\", \"S6a\", a, &e),",
    );
    let unwired_channel = channel("        Ok(Err(e)) => log::error!(\"S6a failed: {e}\"),");
    assert_eq!(
        check(&[&wired_channel]),
        (1, vec![]),
        "both receiving error arms are wired"
    );
    assert_eq!(
        check(&[&unwired_channel]),
        (1, vec![0]),
        "the receiving bind-error arm must call the handler itself"
    );
}

/// #2056: every NF that binds a metrics (or NES/SLA) listener itself, outside its
/// tests, sends a bind failure through `listener_bind_failed`, so none of them runs
/// on silently under production.
#[test]
fn every_nf_listener_bind_failure_goes_through_the_shared_handler_2056() {
    let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is at <root>/libs/nextgcore-metrics")
        .join("bins");
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
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
    let mut files = Vec::new();
    for nf in std::fs::read_dir(&bins).expect("bins/") {
        rust_files(&nf.expect("entry").path().join("src"), &mut files);
    }
    let mut checked = 0;
    let mut missing = Vec::new();
    {
        for f in files {
            // #2088: a whole-file test module (`#[cfg(test)] mod x;`), by the tree's
            // naming: `*tests.rs`, or anything under a `tests/` directory.
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.ends_with("tests.rs") || f.components().any(|c| c.as_os_str() == "tests") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            // Production code only: what precedes the file's first inline test
            // module (`#[cfg(test)]` then `mod <name> {`); a lone `#[cfg(test)]` item
            // earlier in the file does not end the production code.
            let lines: Vec<&str> = text.lines().collect();
            let end = lines
                .windows(2)
                .position(|w| {
                    let t = w[1].trim_start();
                    w[0].trim() == "#[cfg(test)]"
                        && ["mod ", "pub mod ", "pub(crate) mod ", "pub(super) mod "]
                            .iter()
                            .any(|m| t.starts_with(m))
                        && w[1].trim_end().ends_with('{')
                })
                .unwrap_or(lines.len());
            // #2073: each listener call site, not each file.
            let prod = &lines[..end];
            checked += listener_sites(prod).len();
            for site in unwired_listener_sites(prod) {
                missing.push(format!("{}:{}", f.display(), site + 1));
            }
        }
    }
    assert!(
        checked >= 8,
        "the guard found only {checked} sites; is it still checking?"
    );
    assert!(
        missing.is_empty(),
        "these NFs bind a listener whose failure is neither propagated nor sent through the \
         #2056 handler: {missing:?}"
    );
}

/// #2073: the N26 listeners of amfd and mmed, the one exception to the #2056 rule, say so
/// at their call sites, so the exception is a documented decision and not a site the
/// guard above merely does not look at.
///
/// REVERT-VERIFIED: with either call site's #2073 note removed, this fails.
#[test]
fn the_n26_listeners_are_the_documented_exception_2073() {
    let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is at <root>/libs/nextgcore-metrics")
        .join("bins");
    for (file, call) in [
        ("nextgcore-amfd/src/lib.rs", "n26_path::n26_open(n26_bind"),
        ("nextgcore-mmed/src/main.rs", "n26_path::n26_open()"),
    ] {
        let text = std::fs::read_to_string(bins.join(file)).expect(file);
        let at = text
            .find(call)
            .unwrap_or_else(|| panic!("{file}: the N26 call site"));
        // The note sits in the comment block just above the call.
        let note = text[..at].rfind("explicit exception to the #2056 production rule");
        assert!(
            note.is_some_and(|n| at - n < 4000),
            "{file}: the N26 bind failure is the #2056 exception and must say so at its call site"
        );
    }
}
