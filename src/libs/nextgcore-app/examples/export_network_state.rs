//! Offline aggregate network-state export (issue #25, non-normative 6G
//! research). Merges the state files persisted by `nextgcore-nrfd
//! --state-file` and `nextgcore-nsacfd --state-file` into one
//! `NetworkStateSnapshot` JSON document. No listener, no live SBI calls.
//!
//! Usage:
//!   cargo run -p nextgcore-app --features 6g-extensions \
//!     --example export_network_state -- <nrf_state.json> <nsacf_state.json> [out.json]
//!
//! With no `out.json` the pretty JSON is written to stdout.

use std::path::PathBuf;
use std::process::ExitCode;

use nextgcore_app::NetworkStateSnapshot;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (nrf_path, nsacf_path, out_path) = match args.as_slice() {
        [_, nrf, nsacf] => (PathBuf::from(nrf), PathBuf::from(nsacf), None),
        [_, nrf, nsacf, out] => (
            PathBuf::from(nrf),
            PathBuf::from(nsacf),
            Some(PathBuf::from(out)),
        ),
        _ => {
            eprintln!("usage: export_network_state <nrf_state.json> <nsacf_state.json> [out.json]");
            return ExitCode::from(2);
        }
    };

    let snapshot = match NetworkStateSnapshot::from_persisted(&nrf_path, &nsacf_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("export_network_state: {e}");
            return ExitCode::FAILURE;
        }
    };
    let json = match serde_json::to_string_pretty(&snapshot) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("export_network_state: serialize failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    match out_path {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, format!("{json}\n")) {
                eprintln!("export_network_state: write {} failed: {e}", path.display());
                return ExitCode::FAILURE;
            }
            eprintln!(
                "wrote {} ({} NF registrations, {} slice quotas)",
                path.display(),
                snapshot.nf_registrations.len(),
                snapshot.slice_quotas.len()
            );
        }
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}
