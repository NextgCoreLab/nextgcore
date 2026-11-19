//! Every NF that serves subscription management binds each subscription to its
//! creator through `nextgcore_sbi::owner_binding` (#1865).
//!
//! #1809 bound nrfd's subscriptions to the consumer that created them; every
//! other NF still let any caller that learned a subscription ID modify or
//! cancel it. #1865 lifted that check into `owner_binding` and adopted it in
//! each NF. This test reads the daemon sources and fails when a crate routes a
//! DELETE on a subscription resource without both halves of the binding: an
//! owner recorded at create (`owner_for_new_resource`) and the caller checked
//! before any side effect (`refuse_non_owner` or `non_owner_refusal`). A new subscription route in a
//! crate that never used the helper fails here, not in review.
//!
//! The detector is deliberately coarse (a crate, not a route): the per-NF
//! tests prove each route's check, this test proves no crate was skipped.
//! [`EXEMPT`] names the crates that bind ownership some other way or are
//! tracked elsewhere, each with its reason, and fails when an entry goes stale.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates exempt from the guard, with why. An entry that stops serving
/// subscriptions, or starts using the helper, must be removed.
const EXEMPT: &[(&str, &str)] = &[
    (
        "nextgcore-nrfd",
        "#1809: its own RegistrantIdentity::bind_subscription (PR #1831), which also \
         refuses identities that disagree with INVALID_CLIENT (TS 29.510 Table 6.1.7.3-1)",
    ),
    (
        "nextgcore-nefd",
        "#110: northbound AF subscriptions are bound to the authenticated SCS/AS \
         (authenticated_client_id), and the AF is not an NF with an NF Instance ID",
    ),
];

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

/// Non-comment code before the file's first inline `#[cfg(test)] mod ... {`.
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

/// Whether `code` names a subscription resource (`"subscriptions"`,
/// `"sdm-subscriptions"`, `.../subscriptions/...`) and routes a DELETE.
fn routes_subscription_delete(code: &str) -> bool {
    let names_subscriptions = code.contains("subscriptions\"") || code.contains("subscriptions/");
    names_subscriptions && code.contains("\"DELETE\"")
}

#[test]
fn the_detector_sees_a_subscription_delete_route() {
    assert!(routes_subscription_delete(
        r#"("nf-evts", "subscriptions", "DELETE") => del(id),"#
    ));
    assert!(routes_subscription_delete(
        r#"("sdm-subscriptions", id, "DELETE") => del(id),"#
    ));
    assert!(!routes_subscription_delete(r#"("contexts", "DELETE")"#));
    assert!(!routes_subscription_delete(r#"("subscriptions", "POST")"#));
}

#[test]
fn every_nf_serving_subscriptions_binds_them_to_their_creator() {
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
        let code: Vec<String> = files.iter().map(|f| production_code(f)).collect();
        if !code.iter().any(|c| routes_subscription_delete(c)) {
            if EXEMPT.iter().any(|(n, _)| *n == name) {
                problems.push(format!(
                    "{name}: exempt but serves no subscriptions; drop it"
                ));
            }
            continue;
        }
        serving.push(name.clone());
        let binds_at_create = code
            .iter()
            .any(|c| c.contains("owner_binding::owner_for_new_resource"));
        let checks_the_caller = code.iter().any(|c| {
            c.contains("owner_binding::refuse_non_owner")
                || c.contains("owner_binding::non_owner_refusal")
        });
        match (
            EXEMPT.iter().find(|(n, _)| *n == name),
            binds_at_create && checks_the_caller,
        ) {
            (Some(_), true) => problems.push(format!(
                "{name}: uses owner_binding now; remove it from EXEMPT"
            )),
            (Some(_), false) => {}
            (None, true) => {}
            (None, false) => problems.push(format!(
                "{name}: routes a subscription DELETE but does not bind subscriptions to \
                 their creator (owner_for_new_resource: {binds_at_create}, \
                 refuse_non_owner: {checks_the_caller}); see nextgcore_sbi::owner_binding"
            )),
        }
    }
    // The detector must keep seeing the NFs #1865 converted, or it has gone
    // blind and every crate passes vacuously.
    for expected in [
        "nextgcore-amfd",
        "nextgcore-udmd",
        "nextgcore-smfd",
        "nextgcore-pcfd",
        "nextgcore-bsfd",
        "nextgcore-nwdafd",
        "nextgcore-tsctsf",
        "nextgcore-lmfd",
        "nextgcore-mbsmfd",
        "nextgcore-nsacfd",
        "nextgcore-eesd",
        "nextgcore-udrd",
        "nextgcore-ucmfd",
        "nextgcore-dccfd",
        "nextgcore-nssfd",
    ] {
        assert!(
            serving.iter().any(|s| s == expected),
            "the detector no longer sees {expected}'s subscription routes: {serving:?}"
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
