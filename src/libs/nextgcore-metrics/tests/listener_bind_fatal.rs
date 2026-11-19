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

/// The lines (0-based) of the listener call sites in `prod`: `serve_metrics(` from
/// `nes_energy`, or a bare `serve_metrics(` call.
fn listener_sites(prod: &[&str]) -> Vec<usize> {
    prod.iter()
        .enumerate()
        .filter(|(_, l)| l.contains("nes_energy::serve_metrics(") || l.contains(" serve_metrics("))
        .map(|(i, _)| i)
        .collect()
}

/// How far after its call site a listener's bind-failure arm may call the handler.
/// The furthest today is mmed's, 24 lines.
const HANDLER_WINDOW: usize = 30;

/// #2073 (R31 on #2063): the listener call sites in `prod` whose OWN bind failure does
/// not reach `listener_bind_failed(`. Each site needs a call to the handler after it,
/// within [`HANDLER_WINDOW`] lines and before the next site, so a second, unwired
/// listener in a file whose first one is wired is still found. #2056 checked each file,
/// so any one call anywhere in the file covered every listener in it.
fn unwired_listener_sites(prod: &[&str]) -> Vec<usize> {
    let sites = listener_sites(prod);
    sites
        .iter()
        .enumerate()
        .filter(|(n, &site)| {
            let next = sites.get(n + 1).copied().unwrap_or(prod.len());
            let end = next.min(site + HANDLER_WINDOW).min(prod.len());
            !prod[site..end]
                .iter()
                .any(|l| l.contains("listener_bind_failed("))
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
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            // Production code only: what precedes the file's first inline test
            // module (`#[cfg(test)]` then `mod <name> {`); a lone `#[cfg(test)]` item
            // earlier in the file does not end the production code.
            let lines: Vec<&str> = text.lines().collect();
            let end = lines
                .windows(2)
                .position(|w| {
                    w[0].trim() == "#[cfg(test)]"
                        && w[1].trim_start().starts_with("mod ")
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
        "these NFs bind a listener without the #2056 handler: {missing:?}"
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
