//! #2065: the NFs whose behaviour `nextgcore_sbi::owner_binding` decides.
//!
//! A change to its identity rule (as #2065's production rule for a certificate
//! naming no NF type) must be checked against every one of them: run each crate's
//! tests. This list is that checklist; it fails when an NF starts or stops using
//! the module, so the list (and the PR that changes the rule) stays complete.

const CALLERS: &[&str] = &[
    "nextgcore-amfd",
    "nextgcore-ausfd", // `caller_identity_with` is the shared helper (#2132)
    "nextgcore-bsfd",
    "nextgcore-dccfd",
    "nextgcore-easdfd",
    "nextgcore-eesd",
    "nextgcore-lmfd",
    "nextgcore-mbsmfd",
    "nextgcore-nefd", // `authenticated_client_id_with` (#2132)
    "nextgcore-nsacfd",
    "nextgcore-nssfd",
    "nextgcore-nwdafd",
    "nextgcore-pcfd",
    "nextgcore-smfd",
    "nextgcore-tsctsf",
    "nextgcore-ucmfd",
    "nextgcore-udmd",
    "nextgcore-udrd",
];

fn mentions(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let path = e.path();
        if path.is_dir() {
            mentions(&path)
        } else {
            path.extension().is_some_and(|x| x == "rs")
                && std::fs::read_to_string(&path).is_ok_and(|t| t.contains("owner_binding"))
        }
    })
}

#[test]
fn the_owner_binding_callers_are_the_listed_ones_2065() {
    let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is at <root>/libs/nextgcore-sbi")
        .join("bins");
    let mut found: Vec<String> = std::fs::read_dir(&bins)
        .expect("bins/")
        .flatten()
        .filter(|e| mentions(&e.path().join("src")))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(
        found, CALLERS,
        "the NFs using owner_binding changed: update CALLERS, and run each one's tests"
    );
}
