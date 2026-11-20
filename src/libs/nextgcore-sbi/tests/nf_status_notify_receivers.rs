//! #2172 (SECURITY): every NFStatusNotify receiver applies
//! `nextgcore_sbi::nf_status_notify::refuse_notifier`.
//!
//! A receiver that acts on an NFStatusNotify without it lets any peer that can
//! reach the callback post a forged NF_DEREGISTERED or NF_PROFILE_CHANGED and
//! evict or redirect a healthy NF. This guard fails when an NF's source names an
//! NFStatusNotify route (`nf-status-notify`, `nfstatus-notify`) outside its
//! state-machine stubs without calling the shared check, and when the list of
//! receivers changes, so the PR that adds a receiver adds it here.
//!
//! Verified on 2026-11-20 for #2172: the HTTP NFStatusNotify receivers are amfd
//! (`/namf-callback/v1/nf-status-notify/{token}`) and nwdafd
//! (`/nnwdaf-callback/v1/nf-status-notify/{token}` and the token-less
//! `/nnwdaf-nfstatus-notify/v1/notify`). bsfd, nssfd, seppd, smfd and udrd name
//! one only in their `*_sm.rs` state machines, as log-only arms that no HTTP
//! route reaches (their routers have no NFStatusNotify route; the state
//! machines are fed timer events only). nrfd is the sender.

/// The NFs whose source calls the shared check.
const RECEIVERS: &[&str] = &["nextgcore-amfd", "nextgcore-nwdafd"];

/// The sender of NFStatusNotify, which builds the route rather than serving it.
const SENDERS: &[&str] = &["nextgcore-nrfd"];

fn sources(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push((path, text));
            }
        }
    }
}

fn bins() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is at <root>/libs/nextgcore-sbi")
        .join("bins")
}

#[test]
fn every_nf_status_notify_receiver_checks_the_sender_2172() {
    let mut receivers = Vec::new();
    let mut unguarded = Vec::new();
    let mut crates: Vec<_> = std::fs::read_dir(bins())
        .expect("bins/")
        .flatten()
        .map(|e| e.path())
        .collect();
    crates.sort();
    for krate in crates {
        let name = krate.file_name().unwrap().to_string_lossy().into_owned();
        let mut files = Vec::new();
        sources(&krate.join("src"), &mut files);
        let checks = files
            .iter()
            .any(|(_, t)| t.contains("nf_status_notify::refuse_notifier"));
        if checks {
            receivers.push(name.clone());
        }
        let routes = files.iter().any(|(path, text)| {
            let stub = path
                .file_name()
                .is_some_and(|f| f.to_string_lossy().ends_with("_sm.rs"));
            !stub && (text.contains("nf-status-notify") || text.contains("nfstatus-notify"))
        });
        if routes && !checks && !SENDERS.contains(&name.as_str()) {
            unguarded.push(name);
        }
    }
    assert_eq!(
        unguarded,
        Vec::<String>::new(),
        "these NFs name an NFStatusNotify route but never call \
         nextgcore_sbi::nf_status_notify::refuse_notifier"
    );
    assert_eq!(
        receivers, RECEIVERS,
        "the NFStatusNotify receivers changed: update RECEIVERS, and run each one's tests"
    );
}
