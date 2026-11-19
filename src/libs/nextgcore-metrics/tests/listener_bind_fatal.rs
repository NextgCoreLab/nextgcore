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
            let prod = lines[..end].join("\n");
            if prod.contains("nes_energy::serve_metrics(") || prod.contains(" serve_metrics(") {
                checked += 1;
                if !prod.contains("listener_bind_failed(") {
                    missing.push(f.display().to_string());
                }
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
