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
    render_chart_with(repo_root, &[])
}

/// #2052: `helm template` as [`render_chart`] runs it, plus `extra` arguments
/// (e.g. `["--set", "global.sbiProfile=production"]`). Always runs helm:
/// [`HELM_RENDERED_ENV`] names one render, of the default values only. `None`
/// when helm is not installed and [`HELM_REQUIRED_ENV`] is unset.
pub fn render_chart_with(repo_root: &Path, extra: &[&str]) -> Option<String> {
    let out = match Command::new("helm")
        .arg("template")
        .arg("t")
        .arg(repo_root.join("deploy/helm/nextgcore"))
        .args(["--set", "global.siteId=ci"])
        .args(extra)
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

/// The env var `name` of container `container` in the rendered Deployment
/// `deployment` (#2052: e.g. the AMF's pinned `NEXTGCORE_AMF_INSTANCE_ID`).
pub fn deployment_env_in(
    rendered: &str,
    deployment: &str,
    container: &str,
    name: &str,
) -> Option<String> {
    serde_yaml::Deserializer::from_str(rendered).find_map(|doc| {
        let doc = <serde_yaml::Value as serde::Deserialize>::deserialize(doc).ok()?;
        if doc["kind"].as_str() != Some("Deployment")
            || doc["metadata"]["name"].as_str() != Some(deployment)
        {
            return None;
        }
        doc["spec"]["template"]["spec"]["containers"]
            .as_sequence()?
            .iter()
            .filter(|c| c["name"].as_str() == Some(container))
            .flat_map(|c| c["env"].as_sequence().cloned().unwrap_or_default())
            .find(|e| e["name"].as_str() == Some(name))
            .and_then(|e| e["value"].as_str().map(str::to_string))
    })
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

/// #2069: the configs of every ConfigMap in `rendered` (one or more YAML
/// documents), as `(configmap, file, text)`: each `data` entry whose key ends
/// in `.yaml`, in document order.
pub fn configs_in(rendered: &str) -> Vec<(String, String, String)> {
    serde_yaml::Deserializer::from_str(rendered)
        .filter_map(|doc| {
            let doc = <serde_yaml::Value as serde::Deserialize>::deserialize(doc).ok()?;
            if doc["kind"].as_str() != Some("ConfigMap") {
                return None;
            }
            let name = doc["metadata"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            Some((name, doc["data"].as_mapping()?.clone()))
        })
        .flat_map(|(name, data)| {
            data.into_iter().filter_map(move |(k, v)| {
                let file = k.as_str()?.to_string();
                let text = v.as_str()?.to_string();
                file.ends_with(".yaml").then(|| (name.clone(), file, text))
            })
        })
        .collect()
}

/// #2069: every `mcc:` and `mnc:` value in the YAML text `config`, as it is
/// WRITTEN: `("mcc", "\"001\"")` for `mcc: "001"`, `("mcc", "001")` for an
/// unquoted `mcc: 001`, in block or flow style. A YAML 1.1 reader (PyYAML,
/// helm's own values parser, the demo profile's post-render) takes the
/// unquoted `001` for the integer 1 and `070` for octal 56, so only the quoted
/// form names the PLMN for every reader.
pub fn plmn_scalars_in(config: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for line in config.lines() {
        let code = line.split(" #").next().unwrap_or_default();
        let mut found: Vec<(usize, &'static str)> = Vec::new();
        for key in ["mcc", "mnc"] {
            let tag = format!("{key}:");
            let mut from = 0;
            while let Some(i) = code[from..].find(&tag) {
                let at = from + i;
                let before = code[..at].chars().next_back();
                if before.is_none_or(|c| c == ' ' || c == '{' || c == ',' || c == '-') {
                    found.push((at, key));
                }
                from = at + tag.len();
            }
        }
        found.sort();
        for (at, key) in found {
            let rest = &code[at + key.len() + 1..];
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            out.push((key, rest[..end].trim().to_string()));
        }
    }
    out
}

/// #2069: the `(mcc, mnc)` of every map in the YAML `config` that carries an
/// `mcc` or `mnc` key, at any depth, as nextgcore's YAML parser (serde_yaml)
/// types them (`Null` for a missing one). Panics when `config` does not parse.
pub fn plmn_ids_in(config: &str) -> Vec<(serde_yaml::Value, serde_yaml::Value)> {
    fn walk(v: &serde_yaml::Value, out: &mut Vec<(serde_yaml::Value, serde_yaml::Value)>) {
        match v {
            serde_yaml::Value::Mapping(m) => {
                if m.contains_key("mcc") || m.contains_key("mnc") {
                    out.push((v["mcc"].clone(), v["mnc"].clone()));
                }
                m.values().for_each(|c| walk(c, out));
            }
            serde_yaml::Value::Sequence(s) => s.iter().for_each(|c| walk(c, out)),
            serde_yaml::Value::Tagged(t) => walk(&t.value, out),
            _ => {}
        }
    }
    let doc: serde_yaml::Value =
        serde_yaml::from_str(config).unwrap_or_else(|e| panic!("does not parse: {e}"));
    let mut out = Vec::new();
    walk(&doc, &mut out);
    out
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
    use serde_yaml::Value;

    #[test]
    fn the_entry_of_the_configmap_that_carries_it() {
        let rendered = "---\nkind: Service\ndata:\n  a.yaml: no\n---\nkind: ConfigMap\ndata:\n  a.yaml: |\n    a: 1\n";
        assert_eq!(config_in(rendered, "a.yaml").as_deref(), Some("a: 1\n"));
        assert_eq!(config_in(rendered, "b.yaml"), None);
    }

    /// #2052: the env var of the named Deployment's named container only.
    #[test]
    fn the_env_of_the_deployment_container_that_sets_it_2052() {
        let rendered = "---\nkind: Deployment\nmetadata: {name: b}\nspec: {template: {spec: \
            {containers: [{name: c, env: [{name: X, value: b}]}]}}}\n---\nkind: Deployment\n\
            metadata: {name: a}\nspec: {template: {spec: {containers: [{name: init, env: \
            [{name: X, value: i}]}, {name: c, env: [{name: Y, value: y}, {name: X, value: a}]}]}}}\n";
        assert_eq!(
            super::deployment_env_in(rendered, "a", "c", "X").as_deref(),
            Some("a")
        );
        assert_eq!(super::deployment_env_in(rendered, "a", "c", "Z"), None);
        assert_eq!(super::deployment_env_in(rendered, "z", "c", "X"), None);
    }

    /// #2069: every `.yaml` entry of every ConfigMap; the PLMN values of a
    /// config as written, block and flow style; and as serde_yaml types them.
    #[test]
    fn the_configs_and_their_plmn_ids_as_written_and_parsed_2069() {
        let rendered = "---\nkind: Service\ndata:\n  s.yaml: x\n---\nkind: ConfigMap\nmetadata: \
            {name: c}\ndata:\n  a.yaml: \"a: 1\"\n  init.js: x\n---\nkind: ConfigMap\ndata:\n  \
            b.yaml: \"b: 2\"\n";
        let s = |x: &str| x.to_string();
        assert_eq!(
            super::configs_in(rendered),
            vec![
                (s("c"), s("a.yaml"), s("a: 1")),
                (s(""), s("b.yaml"), s("b: 2"))
            ]
        );
        let config = "x:\n  serving:\n    - plmn_id: {mcc: \"001\", mnc: '01'}\n  tai:\n    \
            - plmn_id:\n        mcc: 001  # a comment\n        mnc: 070\n  other: {xmnc: 1, mnc: \"070\"}\n";
        assert_eq!(
            super::plmn_scalars_in(config),
            vec![
                ("mcc", s("\"001\"")),
                ("mnc", s("'01'")),
                ("mcc", s("001")),
                ("mnc", s("070")),
                ("mnc", s("\"070\"")),
            ]
        );
        assert_eq!(
            super::plmn_ids_in(config),
            vec![
                (Value::from("001"), Value::from("01")),
                (Value::from("001"), Value::from("070")),
                (Value::Null, Value::from("070")),
            ],
            "serde_yaml reads even an unquoted leading-zero scalar as a string; YAML 1.1 \
             readers do not"
        );
    }

    /// #2069: the PLMN values of `config` (`what`, for the message), as written:
    /// each a quoted string of exactly `mcc` or `mnc`; and how many.
    fn assert_quoted_plmn(what: &str, config: &str, mcc: &str, mnc: &str) -> usize {
        let scalars = super::plmn_scalars_in(config);
        for (key, raw) in &scalars {
            let want = if *key == "mcc" { mcc } else { mnc };
            assert!(
                [format!("\"{want}\""), format!("'{want}'")].contains(raw),
                "{what}: {key}: {raw} carries the exact digits {want}, quoted, so every YAML \
                 reader takes it for a string"
            );
        }
        scalars.len()
    }

    /// #2069: the chart renders global.plmn as quoted strings, so every NF
    /// config it renders carries the PLMN's exact digits, leading zeros and
    /// all, for any YAML reader, in the dev and the production profile:
    /// TS 23.003's test PLMN 001-01 and a 3-digit MNC 070 (TS 23.003 §2.2:
    /// MNC 070 is not MNC 70). The derived nrf.nf_set_allowlist entry (#2052)
    /// and the mongodb-init Job's seeded IMSI carry the same digits. amfd's and
    /// nrfd's #2069 tests feed these renders to the NFs' own parsers.
    ///
    /// REVERT-VERIFIED: with configmap.yaml's `nextgcore.plmnId` include put
    /// back to the unquoted `mcc: {{ .Values.global.plmn.mcc }}` (and mnc), the
    /// "carries the exact digits ..., quoted" assertion fails (`mcc: 001`).
    #[test]
    fn every_rendered_config_carries_the_plmn_digits_quoted_2069() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        for profile in ["dev", "production"] {
            for (mcc, mnc, imsi) in [
                ("001", "01", "001010000000001"),
                ("001", "070", "001070000000001"),
            ] {
                let args = [
                    format!("global.sbiProfile={profile}"),
                    format!("global.plmn.mcc={mcc}"),
                    format!("global.plmn.mnc={mnc}"),
                    format!("subscriber.imsi={imsi}"),
                ];
                let mut extra = Vec::new();
                for a in &args {
                    extra.extend(["--set-string", a.as_str()]);
                }
                let Some(rendered) = super::render_chart_with(&root, &extra) else {
                    return;
                };
                let case = format!("{profile}, PLMN {mcc}-{mnc}");
                let mut seen = Vec::new();
                for (_, file, text) in super::configs_in(&rendered) {
                    let n = assert_quoted_plmn(&format!("{case}: {file}"), &text, mcc, mnc);
                    for (m, n) in super::plmn_ids_in(&text) {
                        assert_eq!(
                            (m, n),
                            (Value::from(mcc), Value::from(mnc)),
                            "{case}: {file} parses to the exact digits"
                        );
                    }
                    seen.extend(std::iter::repeat_n(file.clone(), n));
                }
                assert_eq!(
                    seen.iter().filter(|f| *f == "nrf.yaml").count(),
                    2,
                    "{case}: nrf.yaml's serving PLMN; got {seen:?}"
                );
                assert_eq!(
                    seen.iter().filter(|f| *f == "amf.yaml").count(),
                    6,
                    "{case}: amf.yaml's guami, tai and plmn_support; got {seen:?}"
                );
                let nrf = super::config_in(&rendered, "nrf.yaml").expect("nrf.yaml");
                let set_id = format!("set001.region02.amfset.5gc.mnc{mnc:0>3}.mcc{mcc}");
                assert!(
                    nrf.contains(&format!("nf_set_id: {set_id}\n")),
                    "{case}: the derived AMF Set NF Set ID is {set_id}: {nrf}"
                );
                assert_eq!(
                    rendered.matches(&format!("imsi: \"{imsi}\"")).count(),
                    2,
                    "{case}: the mongodb-init Job seeds IMSI {imsi}"
                );
            }
        }
    }

    /// #2069: the static NF configs (the nextgcore-configs ConfigMaps of
    /// k8s/manifests and every deploy/eks overlay) write the PLMN quoted too:
    /// the demo profile's post-render (deploy/eks/profiles/demo/demo_toggles.py)
    /// re-reads them with PyYAML, a YAML 1.1 reader, and re-dumps them.
    ///
    /// REVERT-VERIFIED: with k8s/manifests/configmap.yaml's amf.yaml back to
    /// `mcc: 999`, the "carries the exact digits ..., quoted" assertion fails.
    #[test]
    fn the_static_nf_configs_write_the_plmn_quoted_2069() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut files = vec![root.join("k8s/manifests/configmap.yaml")];
        let mut dirs = vec![root.join("deploy/eks")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "yaml") {
                    files.push(path);
                }
            }
        }
        let mut checked = Vec::new();
        for path in files {
            let text = std::fs::read_to_string(&path).unwrap();
            for (cm, file, config) in super::configs_in(&text) {
                if cm != "nextgcore-configs" {
                    continue;
                }
                let what = format!("{}: {file}", path.display());
                if assert_quoted_plmn(&what, &config, "999", "70") > 0 {
                    checked.push(what);
                }
            }
        }
        assert!(
            checked
                .iter()
                .any(|w| w.contains("k8s/manifests/configmap.yaml: amf.yaml")),
            "k8s/manifests' amf.yaml is checked; got {checked:?}"
        );
        assert!(
            checked.len() >= 5,
            "k8s/manifests' nrf.yaml and amf.yaml, and the overlays' nrf.yaml: {checked:?}"
        );
    }
}
