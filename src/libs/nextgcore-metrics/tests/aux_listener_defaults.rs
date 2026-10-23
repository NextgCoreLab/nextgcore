//! Every NF's auxiliary `/metrics` listener defaults to loopback (#837).
//!
//! The endpoint is unauthenticated and reveals per-session counters and
//! topology. smfd, upfd and sgwud used to bind it to `0.0.0.0` by default, as
//! did udmd (NES) and nsacfd (SLA observe) when enabled, so a bare-metal or
//! host-network deployment exposed it on every interface. Each now takes its
//! address from `nes_energy::metrics_bind_addr` (loopback unless
//! `NEXTGCORE_METRICS_BIND` overrides it). This test reads the daemon sources
//! and fails when a crate serves metrics without that helper, or spells a
//! wildcard bind in a file that serves them.

use nextgcore_metrics::nes_energy::{metrics_bind_addr_from, DEFAULT_METRICS_BIND};
use std::fs;
use std::path::{Path, PathBuf};

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

/// Non-comment code before the file's first inline `#[cfg(test)] mod ... {`
/// (the test module; a single cfg(test) item earlier in the file does not end
/// the production code).
fn production_code(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let lines: Vec<&str> = text.lines().collect();
    let mut end = lines.len();
    for (i, pair) in lines.windows(2).enumerate() {
        let next = pair[1].trim_start();
        if pair[0].trim() == "#[cfg(test)]" && next.starts_with("mod ") && next.ends_with('{') {
            end = i;
            break;
        }
    }
    lines[..end]
        .iter()
        .filter(|l| !l.trim_start().starts_with("//"))
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_default_metrics_bind_is_loopback() {
    assert!(DEFAULT_METRICS_BIND.is_loopback());
    assert!(metrics_bind_addr_from(None, 9090).ip().is_loopback());
}

#[test]
fn every_nf_metrics_listener_uses_the_loopback_default() {
    let bins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bins");
    let mut crates: Vec<PathBuf> = fs::read_dir(&bins)
        .expect("src/bins")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    crates.sort();

    let mut serving = Vec::new();
    let mut problems = Vec::new();
    for krate in &crates {
        let name = krate.file_name().unwrap().to_string_lossy().to_string();
        let mut files = Vec::new();
        rust_files(&krate.join("src"), &mut files);
        let mut serves = false;
        let mut uses_helper = false;
        for file in &files {
            let code = production_code(file);
            let serves_here =
                code.contains("serve_metrics(") || code.contains("serve_metrics_with(");
            serves |= serves_here;
            uses_helper |= code.contains("metrics_bind_addr(");
            if serves_here || code.contains("metrics_bind_addr(") {
                // A wildcard near metrics code. Protocol listeners in the same
                // file (S1AP, SBI, PFCP) must accept peers and are out of scope.
                let lines: Vec<&str> = code.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    let near_metrics = lines[i.saturating_sub(6)..(i + 7).min(lines.len())]
                        .iter()
                        .any(|l| l.to_ascii_lowercase().contains("metric"));
                    if !near_metrics {
                        continue;
                    }
                    for bad in [
                        "([0, 0, 0, 0]",
                        "\"0.0.0.0:",
                        "Ipv4Addr::UNSPECIFIED",
                        "Ipv6Addr::UNSPECIFIED",
                        "\"[::]:",
                        "([0u16; 8]",
                    ] {
                        if line.contains(bad) {
                            problems.push(format!(
                                "{}: `{bad}` next to metrics code; bind through \
                                 nes_energy::metrics_bind_addr",
                                file.strip_prefix(&bins).unwrap_or(file).display()
                            ));
                        }
                    }
                }
            }
        }
        if serves {
            serving.push(name.clone());
            if !uses_helper {
                problems.push(format!(
                    "{name}: serves /metrics without nes_energy::metrics_bind_addr"
                ));
            }
        }
    }
    // The five that serve one today; a new one is fine as long as it passes.
    for nf in [
        "nextgcore-mmed",
        "nextgcore-nsacfd",
        "nextgcore-sgwud",
        "nextgcore-smfd",
        "nextgcore-udmd",
        "nextgcore-upfd",
    ] {
        assert!(
            serving.iter().any(|s| s == nf),
            "{nf} no longer found serving /metrics"
        );
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
