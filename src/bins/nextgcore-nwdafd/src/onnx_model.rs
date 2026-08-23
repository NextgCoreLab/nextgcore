//! ONNX-backed inference for the NWDAF prediction path (issue #26, feature
//! `onnx-model`, off by default).
//!
//! Zero-dependency by design: instead of pulling an ONNX runtime crate, this
//! is a hand-rolled reader for a **minimal, explicitly documented subset** of
//! the ONNX protobuf format — a single `ai.onnx.ml` `LinearRegressor` node
//! (`coefficients` + `intercepts` attributes), i.e. exactly the model class
//! sklearn's `skl2onnx` exports for `LinearRegression`. Anything else in the
//! graph is a hard error, never a silent approximation. Hand-rolled wire
//! codecs are this repo's house style (NAS/NGAP/LPP), and the lock stays
//! byte-identical (the pqc-tls precedent).
//!
//! The model maps the last `coefficients.len()` samples of the series to the
//! next value: `y = intercept + Σ coef[i]·window[i]`. `confidence` is the
//! R² of a backtest of the loaded model over the observed series (documented
//! semantics; an ONNX file itself carries no goodness-of-fit). The reader
//! accepts `AttributeProto.floats` in both the packed and the per-element
//! proto2 encodings (real exporter files use the latter); multi-output
//! models (`targets` > 1 / multiple intercepts) are rejected at load.

use crate::ml_service::InferenceModel;

/// Protobuf wire types used by the subset reader.
const WT_VARINT: u64 = 0;
const WT_I64: u64 = 1;
const WT_LEN: u64 = 2;
const WT_I32: u64 = 5;

/// A loaded `ai.onnx.ml` LinearRegressor.
#[derive(Debug, Clone)]
pub struct OnnxLinearRegressor {
    model_id: String,
    coefficients: Vec<f64>,
    intercept: f64,
}

impl OnnxLinearRegressor {
    /// Load from an `.onnx` file (see module doc for the supported subset).
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("failed to read ONNX model {}: {e}", path.display()))?;
        Self::from_bytes(&bytes, &format!("onnx:{}", path.display()))
    }

    /// Parse a serialized `ModelProto`. Errors on anything outside the
    /// single-LinearRegressor subset.
    pub fn from_bytes(bytes: &[u8], model_id: &str) -> Result<Self, String> {
        let mut graph: Option<&[u8]> = None;
        walk_fields(bytes, |field, payload| {
            if field == 7 {
                // ModelProto.graph
                if graph.is_some() {
                    return Err("duplicate ModelProto.graph field (split/merged \
                                ModelProto is outside the supported subset)"
                        .to_string());
                }
                graph = Some(payload.require_len()?);
            }
            Ok(())
        })?;
        let graph = graph.ok_or("ONNX ModelProto has no graph")?;

        let mut nodes: Vec<&[u8]> = Vec::new();
        walk_fields(graph, |field, payload| {
            if field == 1 {
                // GraphProto.node
                nodes.push(payload.require_len()?);
            }
            Ok(())
        })?;
        if nodes.is_empty() {
            return Err("ONNX graph has no nodes".to_string());
        }
        if nodes.len() > 1 {
            return Err(format!(
                "unsupported ONNX graph: {} nodes (subset supports exactly one \
                 ai.onnx.ml LinearRegressor node)",
                nodes.len()
            ));
        }

        let mut op_type = String::new();
        let mut attrs: Vec<&[u8]> = Vec::new();
        walk_fields(nodes[0], |field, payload| {
            match field {
                4 => op_type = payload.require_str()?,   // NodeProto.op_type
                5 => attrs.push(payload.require_len()?), // NodeProto.attribute
                _ => {}
            }
            Ok(())
        })?;
        if op_type != "LinearRegressor" {
            return Err(format!(
                "unsupported ONNX op {op_type:?}: this build supports only the \
                 ai.onnx.ml LinearRegressor subset (see docs/nwdaf-inference.md)"
            ));
        }

        let mut coefficients: Vec<f64> = Vec::new();
        let mut intercepts: Vec<f64> = Vec::new();
        for attr in attrs {
            let mut name = String::new();
            let mut floats: Vec<f64> = Vec::new();
            let mut int_value: Option<u64> = None;
            walk_fields(attr, |field, payload| {
                match field {
                    1 => name = payload.require_str()?, // AttributeProto.name
                    3 => {
                        // AttributeProto.i (e.g. the LinearRegressor `targets`
                        // attribute for multi-output models)
                        if let Payload::Varint(v) = payload {
                            int_value = Some(v);
                        }
                    }
                    7 => {
                        // AttributeProto.floats: packed (LEN) or unpacked (I32)
                        match payload {
                            Payload::Len(b) => {
                                if b.len() % 4 != 0 {
                                    return Err("packed floats not 4-byte aligned".into());
                                }
                                for chunk in b.chunks_exact(4) {
                                    floats.push(f64::from(f32::from_le_bytes(
                                        chunk.try_into().expect("chunks_exact(4)"),
                                    )));
                                }
                            }
                            Payload::I32(v) => {
                                floats.push(f64::from(f32::from_le_bytes(v.to_le_bytes())));
                            }
                            _ => return Err("unexpected wire type for floats".into()),
                        }
                    }
                    _ => {}
                }
                Ok(())
            })?;
            match name.as_str() {
                "coefficients" => coefficients = floats,
                "intercepts" => intercepts = floats,
                // Multi-output regressors ravel their coefficient matrix into
                // the same attribute; evaluating that as a longer lag window
                // would be silent garbage — hard-error per the module
                // contract.
                "targets" => {
                    if int_value.is_some_and(|t| t != 1) {
                        return Err(format!(
                            "unsupported LinearRegressor: targets={} (only \
                             single-output models are in the subset)",
                            int_value.unwrap_or(0)
                        ));
                    }
                }
                _ => {}
            }
        }
        if coefficients.is_empty() {
            return Err("LinearRegressor has no coefficients attribute".to_string());
        }
        if intercepts.len() > 1 {
            return Err(format!(
                "unsupported LinearRegressor: {} intercepts (multi-output \
                 models are outside the subset)",
                intercepts.len()
            ));
        }
        // [issue #26 review] A window wider than the engine's bounded sample
        // history could never fire — reject at load so the operator gets the
        // existing warn + safe default instead of a silent mean-fallback.
        if coefficients.len() > crate::analytics::MAX_SAMPLES {
            return Err(format!(
                "LinearRegressor input window ({} coefficients) exceeds the \
                 engine's history cap of {} samples — the model could never run",
                coefficients.len(),
                crate::analytics::MAX_SAMPLES
            ));
        }
        Ok(Self {
            model_id: model_id.to_string(),
            coefficients,
            intercept: intercepts.first().copied().unwrap_or(0.0),
        })
    }

    /// Apply the linear function to one input window (len == coefficients).
    fn apply(&self, window: &[f64]) -> f64 {
        self.intercept
            + self
                .coefficients
                .iter()
                .zip(window)
                .map(|(c, x)| c * x)
                .sum::<f64>()
    }
}

impl InferenceModel for OnnxLinearRegressor {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn linear_form(&self) -> Option<(Vec<f64>, f64)> {
        // Already a fixed-window linear model, so re-exporting it is lossless
        // apart from the f64 -> f32 narrowing ONNX's `floats` attribute imposes,
        // which the input file had already been through.
        Some((self.coefficients.clone(), self.intercept))
    }

    fn predict_series(&self, series: &[f64]) -> Option<(f64, f64)> {
        let n = self.coefficients.len();
        if n == 0 || series.len() < n {
            return None;
        }
        let prediction = self.apply(&series[series.len() - n..]).clamp(0.0, 1.0);

        // Backtest R² of the loaded model over the observed series: predict
        // each sample from the window preceding it. Fewer than 2 backtest
        // points → confidence 0.0 (unknown).
        let backtests: Vec<(f64, f64)> = (n..series.len())
            .map(|t| (self.apply(&series[t - n..t]), series[t]))
            .collect();
        if backtests.len() < 2 {
            return Some((prediction, 0.0));
        }
        let mean_actual = backtests.iter().map(|(_, a)| a).sum::<f64>() / backtests.len() as f64;
        let ss_tot: f64 = backtests
            .iter()
            .map(|(_, a)| (a - mean_actual).powi(2))
            .sum();
        let ss_res: f64 = backtests.iter().map(|(p, a)| (a - p).powi(2)).sum();
        let confidence = if ss_tot <= f64::EPSILON {
            if ss_res <= f64::EPSILON {
                1.0
            } else {
                0.0
            }
        } else {
            (1.0 - ss_res / ss_tot).clamp(0.0, 1.0)
        };
        Some((prediction, confidence))
    }
}

/// One decoded field payload.
enum Payload<'a> {
    Varint(u64),
    I64(u64),
    Len(&'a [u8]),
    I32(u32),
}

impl<'a> Payload<'a> {
    fn require_len(&self) -> Result<&'a [u8], String> {
        match self {
            Payload::Len(b) => Ok(b),
            _ => Err("expected length-delimited field".to_string()),
        }
    }

    fn require_str(&self) -> Result<String, String> {
        let b = self.require_len()?;
        String::from_utf8(b.to_vec()).map_err(|e| format!("invalid UTF-8 string field: {e}"))
    }
}

/// Walk every top-level field of a protobuf message, invoking `visit` with
/// the field number and payload; unknown fields are skipped structurally.
fn walk_fields<'a>(
    mut buf: &'a [u8],
    mut visit: impl FnMut(u64, Payload<'a>) -> Result<(), String>,
) -> Result<(), String> {
    while !buf.is_empty() {
        let (tag, rest) = read_varint(buf)?;
        let field = tag >> 3;
        let wire_type = tag & 0x7;
        buf = rest;
        let payload = match wire_type {
            WT_VARINT => {
                let (v, rest) = read_varint(buf)?;
                buf = rest;
                Payload::Varint(v)
            }
            WT_I64 => {
                if buf.len() < 8 {
                    return Err("truncated 64-bit field".to_string());
                }
                let v = u64::from_le_bytes(buf[..8].try_into().expect("len checked"));
                buf = &buf[8..];
                Payload::I64(v)
            }
            WT_LEN => {
                let (len, rest) = read_varint(buf)?;
                let len = usize::try_from(len).map_err(|_| "field length overflow")?;
                if rest.len() < len {
                    return Err("truncated length-delimited field".to_string());
                }
                buf = &rest[len..];
                Payload::Len(&rest[..len])
            }
            WT_I32 => {
                if buf.len() < 4 {
                    return Err("truncated 32-bit field".to_string());
                }
                let v = u32::from_le_bytes(buf[..4].try_into().expect("len checked"));
                buf = &buf[4..];
                Payload::I32(v)
            }
            other => return Err(format!("unsupported protobuf wire type {other}")),
        };
        visit(field, payload)?;
    }
    Ok(())
}

fn read_varint(buf: &[u8]) -> Result<(u64, &[u8]), String> {
    let mut value: u64 = 0;
    for (i, byte) in buf.iter().enumerate() {
        if i >= 10 {
            return Err("varint too long".to_string());
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, &buf[i + 1..]));
        }
    }
    Err("truncated varint".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- minimal protobuf ENCODER, test-only: builds known-good model bytes
    //    in source (no binary fixtures, per the never-commit-binaries rule) --

    fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
    }

    fn put_len_field(buf: &mut Vec<u8>, field: u64, payload: &[u8]) {
        put_varint(buf, (field << 3) | WT_LEN);
        put_varint(buf, payload.len() as u64);
        buf.extend_from_slice(payload);
    }

    fn attr_floats(name: &str, values: &[f32]) -> Vec<u8> {
        let mut attr = Vec::new();
        put_len_field(&mut attr, 1, name.as_bytes()); // AttributeProto.name
        let mut packed = Vec::new();
        for v in values {
            packed.extend_from_slice(&v.to_le_bytes());
        }
        put_len_field(&mut attr, 7, &packed); // AttributeProto.floats (packed)
        attr
    }

    fn model_bytes(op_type: &str, coefficients: &[f32], intercepts: &[f32]) -> Vec<u8> {
        let mut node = Vec::new();
        put_len_field(&mut node, 4, op_type.as_bytes()); // NodeProto.op_type
        put_len_field(&mut node, 7, b"ai.onnx.ml"); // NodeProto.domain
        put_len_field(&mut node, 5, &attr_floats("coefficients", coefficients));
        put_len_field(&mut node, 5, &attr_floats("intercepts", intercepts));
        let mut graph = Vec::new();
        put_len_field(&mut graph, 1, &node); // GraphProto.node
        let mut model = Vec::new();
        put_len_field(&mut model, 7, &graph); // ModelProto.graph
        model
    }

    #[test]
    fn parses_and_predicts_linear_regressor() {
        // y = 2·x[1] − x[0]: exact one-step extrapolation of any arithmetic
        // series, so the backtest R² must be 1.0 on a clean ramp.
        let bytes = model_bytes("LinearRegressor", &[-1.0, 2.0], &[0.0]);
        let m = OnnxLinearRegressor::from_bytes(&bytes, "onnx:test").unwrap();
        assert_eq!(m.model_id(), "onnx:test");
        let series = [0.1, 0.15, 0.2, 0.25, 0.3];
        let (pred, conf) = m.predict_series(&series).unwrap();
        assert!((pred - 0.35).abs() < 1e-6, "ramp extrapolation ({pred})");
        assert!((conf - 1.0).abs() < 1e-6, "perfect backtest ({conf})");
        // Window (2) longer than history → None.
        assert!(m.predict_series(&[0.4]).is_none());
    }

    #[test]
    fn rejects_unsupported_ops_and_malformed_bytes() {
        let gemm = model_bytes("Gemm", &[1.0], &[0.0]);
        let err = OnnxLinearRegressor::from_bytes(&gemm, "x").unwrap_err();
        assert!(err.contains("unsupported ONNX op"), "{err}");

        let empty_graph = {
            let mut model = Vec::new();
            put_len_field(&mut model, 7, &[]);
            model
        };
        assert!(OnnxLinearRegressor::from_bytes(&empty_graph, "x")
            .unwrap_err()
            .contains("no nodes"));

        let mut truncated = model_bytes("LinearRegressor", &[1.0], &[0.0]);
        truncated.truncate(truncated.len() - 3);
        assert!(OnnxLinearRegressor::from_bytes(&truncated, "x").is_err());

        assert!(OnnxLinearRegressor::from_bytes(&[], "x")
            .unwrap_err()
            .contains("no graph"));

        let no_coefs = model_bytes("LinearRegressor", &[], &[0.1]);
        assert!(OnnxLinearRegressor::from_bytes(&no_coefs, "x")
            .unwrap_err()
            .contains("no coefficients"));
    }

    fn attr_int(name: &str, v: u64) -> Vec<u8> {
        let mut attr = Vec::new();
        put_len_field(&mut attr, 1, name.as_bytes()); // AttributeProto.name
        put_varint(&mut attr, (3 << 3) | WT_VARINT); // AttributeProto.i
        put_varint(&mut attr, v);
        attr
    }

    fn attr_floats_unpacked(name: &str, values: &[f32]) -> Vec<u8> {
        let mut attr = Vec::new();
        put_len_field(&mut attr, 1, name.as_bytes());
        for v in values {
            // proto2 default (no [packed=true]): one I32 record per element —
            // the form real exporter files use.
            put_varint(&mut attr, (7 << 3) | WT_I32);
            attr.extend_from_slice(&v.to_le_bytes());
        }
        attr
    }

    fn model_from_attrs(op_type: &str, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut node = Vec::new();
        put_len_field(&mut node, 4, op_type.as_bytes());
        put_len_field(&mut node, 7, b"ai.onnx.ml");
        for a in attrs {
            put_len_field(&mut node, 5, a);
        }
        let mut graph = Vec::new();
        put_len_field(&mut graph, 1, &node);
        let mut model = Vec::new();
        put_len_field(&mut model, 7, &graph);
        model
    }

    #[test]
    fn unpacked_floats_parse_identically_to_packed() {
        let packed = model_bytes("LinearRegressor", &[-1.0, 2.0], &[0.0]);
        let unpacked = model_from_attrs(
            "LinearRegressor",
            &[
                attr_floats_unpacked("coefficients", &[-1.0, 2.0]),
                attr_floats_unpacked("intercepts", &[0.0]),
            ],
        );
        let a = OnnxLinearRegressor::from_bytes(&packed, "x").unwrap();
        let b = OnnxLinearRegressor::from_bytes(&unpacked, "x").unwrap();
        let series = [0.1, 0.15, 0.2, 0.25];
        assert_eq!(a.predict_series(&series), b.predict_series(&series));
    }

    #[test]
    fn rejects_multi_output_and_oversized_models() {
        // skl2onnx multi-output shape: raveled 2x3 coefficients + 2 intercepts
        // + targets=2 → hard error, never a silent 6-lag misread.
        let multi = model_from_attrs(
            "LinearRegressor",
            &[
                attr_floats("coefficients", &[0.1, 0.2, 0.3, 0.4, 0.5, 0.6]),
                attr_floats("intercepts", &[0.05, 0.9]),
                attr_int("targets", 2),
            ],
        );
        let err = OnnxLinearRegressor::from_bytes(&multi, "x").unwrap_err();
        assert!(err.contains("targets=2"), "{err}");

        // Two intercepts even without a targets attribute → rejected.
        let two_intercepts = model_bytes("LinearRegressor", &[1.0], &[0.1, 0.2]);
        assert!(OnnxLinearRegressor::from_bytes(&two_intercepts, "x")
            .unwrap_err()
            .contains("intercepts"));

        // targets=1 (single-output export) stays accepted.
        let single = model_from_attrs(
            "LinearRegressor",
            &[
                attr_floats("coefficients", &[-1.0, 2.0]),
                attr_floats("intercepts", &[0.0]),
                attr_int("targets", 1),
            ],
        );
        assert!(OnnxLinearRegressor::from_bytes(&single, "x").is_ok());

        // Window wider than the engine's 100-sample history cap → load error.
        let oversized = model_bytes("LinearRegressor", &[0.01f32; 101], &[0.0]);
        assert!(OnnxLinearRegressor::from_bytes(&oversized, "x")
            .unwrap_err()
            .contains("history cap"));

        // Duplicate ModelProto.graph → rejected, not last-wins.
        let mut dup = model_bytes("LinearRegressor", &[1.0], &[0.0]);
        let second = model_bytes("LinearRegressor", &[1.0], &[0.0]);
        dup.extend_from_slice(&second);
        assert!(OnnxLinearRegressor::from_bytes(&dup, "x")
            .unwrap_err()
            .contains("duplicate ModelProto.graph"));
    }

    /// Gated on the feature, not on the module: #109 ungated this module so the
    /// reader can verify what `onnx_export` writes, but loading an
    /// *operator-supplied file* via `onnx:<path>` is still the opt-in part, and
    /// `ml_service::load_model` refuses it without the feature.
    #[cfg(feature = "onnx-model")]
    #[test]
    fn load_model_via_ml_service_roundtrips_a_file() {
        let bytes = model_bytes("LinearRegressor", &[-1.0, 2.0], &[0.0]);
        let path = std::env::temp_dir().join(format!(
            "nextgcore-nwdafd-issue26-{}.onnx",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).expect("write model");
        let m = crate::ml_service::load_model(&format!("onnx:{}", path.display()))
            .expect("load via ml_service");
        assert!(m.model_id().starts_with("onnx:"));
        assert!(m.predict_series(&[0.1, 0.2, 0.3]).is_some());
        let _ = std::fs::remove_file(&path);
    }
}
