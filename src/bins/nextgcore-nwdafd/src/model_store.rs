//! The MTLF's model version store (nextgsim#468).
//!
//! Every model this NWDAF provisions over `Nnwdaf_MLModelProvision` is kept as
//! an immutable, content-addressed version: its ONNX bytes, their sha256 and a
//! model manifest. A notification names one version, at
//!
//! ```text
//! {apiRoot}/nnwdaf-mlmodelprovision/v1/models/{event}/{sha256}
//! {apiRoot}/nnwdaf-mlmodelprovision/v1/models/{event}/{sha256}.manifest.json
//! ```
//!
//! so a URL can never start serving different bytes. That matters once the
//! model changes: TS 23.288 §6.2E.2 step 13 has the MTLF send the re-trained
//! model with a new `Nnwdaf_MLModelProvision_Notify`, and a consumer still
//! holding the old URL must get the old bytes, or a clean 404 once the version
//! is gone, never the new bytes under the old name (a spurious sha256 failure at
//! best, a silent model swap at worst). The path is ours: TS 29.520 defines
//! `mLModelUrl` as any `Uri`.
//!
//! The store follows the predictor. [`ModelStore::publish`] takes the active
//! predictor's linear form and returns the current version, adding one only when
//! the exported bytes differ from the newest. So a predictor swapped at runtime
//! is re-provisioned with no other wiring. Version numbers (`v1`, `v2`) are for
//! logs and the manifest only; they restart at 1 with the process, while the
//! sha256 addresses stay stable for the same bytes.
//!
//! The manifest is nextgsim#463's format (`ModelManifest`, which denies unknown
//! fields), so the same verifier logic applies: sha256, the default-domain
//! opset, graph inputs and outputs (read back from the bytes, not restated), and
//! a golden vector computed by running the served bytes through this NF's own
//! ONNX reader. TS 28.105 §6.4.1.1 leaves model loading out of scope, so the
//! manifest is non-normative.

use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::context::AnalyticsId;
use crate::ml_service::InferenceModel;

/// The suffix that turns an artefact URL into its manifest's URL.
pub const MANIFEST_SUFFIX: &str = ".manifest.json";

/// How many versions are kept. An evicted version's URLs answer 404.
pub const MAX_RETAINED_VERSIONS: usize = 8;

/// The manifest `id` (`mLModelId`) of the one model lineage nwdafd trains: its
/// load predictor. Stable across versions.
pub const MODEL_ID: &str = "nwdafd-load-predictor";

/// The per-element tolerance of the manifest's golden vector. The golden output
/// is computed from the served bytes, so only float rounding separates a
/// verifier's result from it.
pub const GOLDEN_TOLERANCE: f32 = 1e-5;

/// One provisioned model version.
#[derive(Debug, Clone)]
pub struct ModelVersion {
    /// 1 for the first model this process published, then 2, 3, ...
    pub version: u32,
    /// Lowercase hex sha256 of [`Self::bytes`]; the artefact's address.
    pub sha256: String,
    /// The ONNX `ModelProto`.
    pub bytes: Arc<[u8]>,
    /// The nextgsim#463 model manifest for these bytes.
    pub manifest: Value,
}

impl ModelVersion {
    /// The artefact URL a notification for `event` advertises.
    pub fn url(&self, base: &str, event: AnalyticsId) -> String {
        format!(
            "{}/nnwdaf-mlmodelprovision/v1/models/{}/{}",
            base.trim_end_matches('/'),
            event.as_str(),
            self.sha256
        )
    }
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Whether a path segment is a sha256 address (64 lowercase hex digits).
pub fn is_sha256_hex(segment: &str) -> bool {
    segment.len() == 64
        && segment
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The bounded, append-only list of versions; the newest is the active one.
#[derive(Debug, Default)]
pub struct ModelStore {
    versions: VecDeque<ModelVersion>,
    last_version: u32,
}

impl ModelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The version for the given linear form, publishing it if its bytes are
    /// not the newest version's. Returns the version and whether it is new.
    ///
    /// # Errors
    /// When the exported bytes do not read back (an internal fault: the
    /// exporter and the reader disagree), nothing is published.
    pub fn publish(
        &mut self,
        coefficients: &[f64],
        intercept: f64,
        producer: &str,
    ) -> Result<(ModelVersion, bool), String> {
        let bytes = crate::onnx_export::encode_linear_regressor(coefficients, intercept);
        let sha256 = sha256_hex(&bytes);
        if let Some(active) = self.versions.back() {
            if active.sha256 == sha256 {
                return Ok((active.clone(), false));
            }
        }
        let version = self.last_version + 1;
        let manifest = build_manifest(&bytes, &sha256, version, producer)?;
        let entry = ModelVersion {
            version,
            sha256,
            bytes: bytes.into(),
            manifest,
        };
        self.last_version = version;
        self.versions.push_back(entry.clone());
        while self.versions.len() > MAX_RETAINED_VERSIONS {
            self.versions.pop_front();
        }
        Ok((entry, true))
    }

    /// The newest version, if any was published.
    pub fn active(&self) -> Option<&ModelVersion> {
        self.versions.back()
    }

    /// A retained version by its sha256 address.
    pub fn get(&self, sha256: &str) -> Option<&ModelVersion> {
        self.versions.iter().find(|v| v.sha256 == sha256)
    }

    /// How many versions are retained.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether nothing was published yet.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

/// The manifest for `bytes`, in nextgsim#463's `ModelManifest` shape.
fn build_manifest(
    bytes: &[u8],
    sha256: &str,
    version: u32,
    producer: &str,
) -> Result<Value, String> {
    let sig = crate::onnx_model::signature(bytes)?;
    let model = crate::onnx_model::OnnxLinearRegressor::from_bytes(bytes, MODEL_ID)?;
    let (coefficients, _) = model
        .linear_form()
        .ok_or("exported model has no linear form")?;
    let width = coefficients.len();

    // A fixed, non-degenerate window; the golden output is what the served
    // bytes compute for it. `predict_series` clamps to [0, 1], which a general
    // ONNX runtime does not, so the input keeps the output inside that range.
    let input: Vec<f64> = (0..width).map(|i| 0.3 + 0.05 * i as f64).collect();
    let (output, _) = model
        .predict_series(&input)
        .ok_or("exported model does not predict on its own window")?;
    if !(0.0..1.0).contains(&output) {
        return Err(format!(
            "golden output {output} is clamped; the window is not representative"
        ));
    }

    let tensors = |list: &[crate::onnx_model::TensorSig]| -> Vec<Value> {
        list.iter()
            .map(|t| json!({ "name": t.name, "dtype": t.dtype, "shape": t.shape }))
            .collect()
    };
    Ok(json!({
        "id": MODEL_ID,
        "version": version.to_string(),
        "sha256": sha256,
        "opset": sig.default_opset.ok_or("exported model imports no default-domain opset")?,
        "inputs": tensors(&sig.inputs),
        "outputs": tensors(&sig.outputs),
        "golden": [{
            "input_shape": [1, width],
            "input": input.iter().map(|v| *v as f32).collect::<Vec<f32>>(),
            "output_shape": [1, 1],
            "output": [output as f32],
        }],
        "tolerance": GOLDEN_TOLERANCE,
        // TS 28.105 mLTrainingType.
        "training_type": if version == 1 { "INITIAL_TRAINING" } else { "RE_TRAINING" },
        "producer": producer,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_service::{InferenceModel, OlsLinearModel};

    fn ols() -> (Vec<f64>, f64) {
        OlsLinearModel.linear_form().expect("OLS is exportable")
    }

    #[test]
    fn same_bytes_are_one_version() {
        let mut store = ModelStore::new();
        let (c, i) = ols();
        let (v1, new) = store.publish(&c, i, "nwdaf-1").unwrap();
        assert!(new);
        assert_eq!(v1.version, 1);
        assert_eq!(v1.sha256, sha256_hex(&v1.bytes));
        let (again, new) = store.publish(&c, i, "nwdaf-1").unwrap();
        assert!(!new, "re-exporting the same predictor is not a new model");
        assert_eq!(again.sha256, v1.sha256);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_new_model_is_a_new_version_and_the_old_one_is_kept() {
        let mut store = ModelStore::new();
        let (c, i) = ols();
        let (v1, _) = store.publish(&c, i, "p").unwrap();
        let (v2, new) = store.publish(&[0.1, 0.2, 0.3, 0.4], 0.0, "p").unwrap();
        assert!(new);
        assert_eq!(v2.version, 2);
        assert_ne!(v1.sha256, v2.sha256);
        assert_eq!(store.active().unwrap().sha256, v2.sha256);
        assert_eq!(
            &*store.get(&v1.sha256).expect("v1 retained").bytes,
            &*v1.bytes,
            "v1's address still holds v1's bytes"
        );
        assert_eq!(v2.manifest["training_type"], "RE_TRAINING");
        assert_eq!(v1.manifest["training_type"], "INITIAL_TRAINING");
    }

    #[test]
    fn retention_is_bounded_and_evicts_the_oldest() {
        let mut store = ModelStore::new();
        let mut first = None;
        for k in 0..(MAX_RETAINED_VERSIONS + 2) {
            let (v, _) = store
                .publish(&[0.5, 0.5 - 0.01 * k as f64], 0.0, "p")
                .unwrap();
            first.get_or_insert(v.sha256);
        }
        assert_eq!(store.len(), MAX_RETAINED_VERSIONS);
        assert!(store.get(&first.unwrap()).is_none(), "oldest evicted");
        assert_eq!(
            store.active().unwrap().version as usize,
            MAX_RETAINED_VERSIONS + 2
        );
    }

    /// The manifest describes the bytes: everything in it is re-derived here
    /// from the artefact by an independent route.
    #[test]
    fn manifest_matches_the_bytes() {
        let mut store = ModelStore::new();
        let (c, i) = ols();
        let (v, _) = store.publish(&c, i, "nwdaf-x").unwrap();
        let m = &v.manifest;
        assert_eq!(m["id"], MODEL_ID);
        assert_eq!(m["version"], "1");
        assert_eq!(m["sha256"], v.sha256);
        assert_eq!(m["opset"], crate::onnx_export::DEFAULT_OPSET);
        assert_eq!(
            m["inputs"],
            json!([{ "name": "X", "dtype": "float32", "shape": [-1, c.len()] }])
        );
        assert_eq!(
            m["outputs"],
            json!([{ "name": "Y", "dtype": "float32", "shape": [-1, 1] }])
        );
        assert_eq!(m["producer"], "nwdaf-x");

        let g = &m["golden"][0];
        let input: Vec<f64> = g["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect();
        let expected = g["output"][0].as_f64().unwrap();
        // y = intercept + coef . window, with the bytes' f32 coefficients.
        let model = crate::onnx_model::OnnxLinearRegressor::from_bytes(&v.bytes, "t").unwrap();
        let (coef, icpt) = model.linear_form().unwrap();
        let y: f64 = icpt + coef.iter().zip(&input).map(|(a, b)| a * b).sum::<f64>();
        assert!(
            (y - expected).abs() <= f64::from(GOLDEN_TOLERANCE),
            "golden {expected} vs recomputed {y}"
        );
        // And it is the NWDAF's own prediction for that window.
        let (own, _) = OlsLinearModel.predict_series(&input).unwrap();
        assert!((own - expected).abs() < 1e-5, "{own} vs {expected}");
    }

    /// The nextgsim#463 `ModelManifest`, field for field, with its
    /// `deny_unknown_fields`. A key this manifest adds or renames fails here
    /// rather than at the AnLF.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Manifest463 {
        id: String,
        version: String,
        sha256: String,
        opset: i64,
        inputs: Vec<Tensor463>,
        outputs: Vec<Tensor463>,
        golden: Vec<Golden463>,
        tolerance: f32,
        #[serde(default)]
        inference_name: Option<String>,
        #[serde(default)]
        training_type: Option<String>,
        #[serde(default)]
        producer: Option<String>,
    }
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Tensor463 {
        name: String,
        dtype: String,
        shape: Vec<i64>,
    }
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Golden463 {
        input_shape: Vec<i64>,
        input: Vec<f32>,
        output_shape: Vec<i64>,
        output: Vec<f32>,
    }

    #[test]
    fn manifest_parses_as_a_463_model_manifest() {
        let mut store = ModelStore::new();
        let (c, i) = ols();
        let (v, _) = store.publish(&c, i, "p").unwrap();
        let parsed: Manifest463 =
            serde_json::from_value(v.manifest.clone()).expect("#463 ModelManifest shape");
        assert_eq!(parsed.sha256.len(), 64);
        assert_eq!(parsed.golden[0].input.len(), c.len());
        assert_eq!(parsed.golden[0].input_shape, vec![1, c.len() as i64]);
    }

    #[test]
    fn sha256_segments() {
        assert!(is_sha256_hex(&sha256_hex(b"x")));
        assert!(!is_sha256_hex("mlsub-1"));
        assert!(!is_sha256_hex(&sha256_hex(b"x").to_uppercase()));
        assert!(!is_sha256_hex(&sha256_hex(b"x")[..63]));
    }
}
