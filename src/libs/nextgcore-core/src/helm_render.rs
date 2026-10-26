//! The NF configs as the Helm chart renders them, for the shipped-config parse
//! tests (#1312, #1317 review): a config that does not parse fails startup
//! (#1313), so a Helm pod with an unparsable config would crash-loop.

use std::path::Path;
use std::process::Command;

/// Set to the path of a `helm template` output to parse that instead of running helm.
pub const HELM_RENDERED_ENV: &str = "NEXTGCORE_HELM_RENDERED";
/// Set (CI does) to fail, rather than skip, when helm is not installed.
pub const HELM_REQUIRED_ENV: &str = "NEXTGCORE_HELM_REQUIRED";

/// `helm template` of `deploy/helm/nextgcore` under `repo_root`, with the values CI
/// renders it with. `None` when helm is not installed and [`HELM_REQUIRED_ENV`] is
/// unset; panics on any other failure, since a chart that does not render is a bug.
pub fn render_chart(repo_root: &Path) -> Option<String> {
    if let Ok(path) = std::env::var(HELM_RENDERED_ENV) {
        return Some(
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{HELM_RENDERED_ENV}={path}: {e}")),
        );
    }
    let out = match Command::new("helm")
        .arg("template")
        .arg("t")
        .arg(repo_root.join("deploy/helm/nextgcore"))
        .args(["--set", "global.siteId=ci"])
        .output()
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            assert!(
                std::env::var_os(HELM_REQUIRED_ENV).is_none(),
                "{HELM_REQUIRED_ENV} is set but helm is not installed"
            );
            eprintln!("helm is not installed: the Helm-rendered configs are not checked");
            return None;
        }
        Err(e) => panic!("helm template: {e}"),
    };
    assert!(
        out.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("helm template output is UTF-8"))
}

/// The `file` entry (e.g. `bsf.yaml`) of the rendered ConfigMap that carries it.
pub fn config_in(rendered: &str, file: &str) -> Option<String> {
    serde_yaml::Deserializer::from_str(rendered).find_map(|doc| {
        let doc = <serde_yaml::Value as serde::Deserialize>::deserialize(doc).ok()?;
        (doc["kind"].as_str() == Some("ConfigMap"))
            .then(|| doc["data"][file].as_str().map(str::to_string))
            .flatten()
    })
}

/// The Helm-rendered `file` under `repo_root`; `None` when helm is not installed
/// (see [`render_chart`]). Panics when the chart renders no such config.
pub fn helm_rendered_config(repo_root: &Path, file: &str) -> Option<String> {
    let rendered = render_chart(repo_root)?;
    Some(config_in(&rendered, file).unwrap_or_else(|| panic!("the rendered chart has no {file}")))
}

#[cfg(test)]
mod tests {
    use super::config_in;

    #[test]
    fn the_entry_of_the_configmap_that_carries_it() {
        let rendered = "---\nkind: Service\ndata:\n  a.yaml: no\n---\nkind: ConfigMap\ndata:\n  a.yaml: |\n    a: 1\n";
        assert_eq!(config_in(rendered, "a.yaml").as_deref(), Some("a: 1\n"));
        assert_eq!(config_in(rendered, "b.yaml"), None);
    }
}
