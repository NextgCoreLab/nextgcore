//! #1312: no daemon reads a `metrics.server` block, so no shipped config may carry
//! one (a documented key with no effect). A metrics listener is set by its
//! environment variable (docs-book/src/observability.md).

use std::path::{Path, PathBuf};

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml")
        ) {
            out.push(path);
        }
    }
}

/// Whether `text` has a `metrics:` key whose block holds a `server:` key.
fn has_metrics_server(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    lines.iter().enumerate().any(|(i, line)| {
        let indent = line.len() - line.trim_start().len();
        line.trim() == "metrics:"
            && lines[i + 1..]
                .iter()
                .take_while(|l| l.trim().is_empty() || l.len() - l.trim_start().len() > indent)
                .any(|l| l.trim() == "server:")
    })
}

#[test]
fn no_shipped_config_carries_a_metrics_server_block() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    yaml_files(&root.join("docker/rust/configs"), &mut files);
    files.push(root.join("k8s/manifests/configmap.yaml"));
    files.push(root.join("deploy/helm/nextgcore/templates/configmap.yaml"));
    let offenders: Vec<_> = files
        .iter()
        .filter(|f| has_metrics_server(&std::fs::read_to_string(f).unwrap()))
        .collect();
    assert!(
        offenders.is_empty(),
        "metrics.server is read by no daemon: {offenders:?}"
    );
    assert!(has_metrics_server(
        "x:\n  metrics:\n    server:\n      - address: a\n"
    ));
}
