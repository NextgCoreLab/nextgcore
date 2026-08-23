//! ONNX export for the NWDAF's active prediction model (issue #109).
//!
//! The counterpart to [`crate::onnx_model`]'s reader: a zero-dependency writer
//! for the same minimal subset — a single `ai.onnx.ml` `LinearRegressor` node
//! with `coefficients` and `intercepts` attributes. Hand-rolled protobuf, in the
//! house style of the reader and of this repo's other wire codecs.
//!
//! ## Why this can be honest
//!
//! `Nnwdaf_MLModelProvision` (TS 29.520 §4.2.2.5) exists to hand a consumer a
//! model it can download and run. Before #109 the NWDAF advertised the service
//! and notified a fabricated URL that no route served, so a conformant AnLF got
//! a 404 — a facade.
//!
//! What makes a real export possible is that the default predictor's arithmetic
//! *is* a fixed-window linear model. `OlsLinearModel` re-fits ordinary least
//! squares over its window on every call and stores no coefficients, but OLS
//! extrapolation over a window of fixed width `n` is a fixed linear function of
//! that window (see [`crate::ml_service::ols_window_weights`]). So the bytes
//! served here reproduce the NWDAF's own prediction rather than approximating
//! it — verified by test against `OlsLinearModel::predict_series`.
//!
//! A model whose weights are *not* a fixed-window linear form (EWMA, whose
//! weights depend on the whole observed series) reports no linear form and is
//! never exported, rather than being truncated into something that would predict
//! differently from the NWDAF that served it.

/// Protobuf wire type for length-delimited fields.
const WT_LEN: u64 = 2;
/// Protobuf wire type for varint fields.
const WT_VARINT: u64 = 0;

/// The media type a model artefact is served with.
pub const ONNX_CONTENT_TYPE: &str = "application/octet-stream";

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

/// One `AttributeProto` carrying a packed `floats` list.
///
/// The reader accepts both the packed and the per-element proto2 encodings; the
/// packed form is written here because it is the more compact of the two.
fn attr_floats(name: &str, values: &[f64]) -> Vec<u8> {
    let mut attr = Vec::new();
    put_len_field(&mut attr, 1, name.as_bytes()); // AttributeProto.name
    let mut packed = Vec::with_capacity(values.len() * 4);
    for v in values {
        // ONNX AttributeProto.floats is float32; the reader widens back to f64.
        packed.extend_from_slice(&(*v as f32).to_le_bytes());
    }
    put_len_field(&mut attr, 7, &packed); // AttributeProto.floats
    attr
}

fn attr_int(name: &str, v: u64) -> Vec<u8> {
    let mut attr = Vec::new();
    put_len_field(&mut attr, 1, name.as_bytes()); // AttributeProto.name
    put_varint(&mut attr, (3 << 3) | WT_VARINT); // AttributeProto.i
    put_varint(&mut attr, v);
    attr
}

/// Serialize a single-output `ai.onnx.ml LinearRegressor` `ModelProto`.
///
/// `coefficients` are the weights applied to the last `coefficients.len()`
/// samples of the input series, oldest first — the same orientation the reader
/// expects. `targets: 1` is written explicitly so a consumer (and our own
/// reader, which rejects `targets != 1`) sees the model is single-output rather
/// than having to infer it.
pub fn encode_linear_regressor(coefficients: &[f64], intercept: f64) -> Vec<u8> {
    let mut node = Vec::new();
    put_len_field(&mut node, 4, b"LinearRegressor"); // NodeProto.op_type
    put_len_field(&mut node, 7, b"ai.onnx.ml"); // NodeProto.domain
    put_len_field(&mut node, 5, &attr_floats("coefficients", coefficients));
    put_len_field(&mut node, 5, &attr_floats("intercepts", &[intercept]));
    put_len_field(&mut node, 5, &attr_int("targets", 1));

    let mut graph = Vec::new();
    put_len_field(&mut graph, 1, &node); // GraphProto.node

    let mut model = Vec::new();
    put_len_field(&mut model, 7, &graph); // ModelProto.graph
    model
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_service::{ols_window_weights, InferenceModel, OlsLinearModel};
    use crate::onnx_model::OnnxLinearRegressor;

    /// The exported bytes must parse back through our own reader, and the
    /// resulting model must predict what the NWDAF itself predicts. This is the
    /// assertion that separates a real artefact from a merely well-formed one:
    /// a consumer that downloads this file and runs it gets the NWDAF's answer.
    #[test]
    fn exported_ols_model_reproduces_the_nwdaf_prediction() {
        let (coefficients, intercept) = OlsLinearModel
            .linear_form()
            .expect("the OLS baseline is exportable");
        let bytes = encode_linear_regressor(&coefficients, intercept);
        let parsed = OnnxLinearRegressor::from_bytes(&bytes, "onnx:exported").expect("round-trips");

        // Series long enough for the exported window, with varied shapes.
        let cases: [&[f64]; 5] = [
            &[0.1, 0.15, 0.2, 0.25, 0.3],
            &[0.9, 0.7, 0.5, 0.3, 0.1],
            &[0.5, 0.5, 0.5, 0.5, 0.5],
            &[0.2, 0.9, 0.1, 0.8, 0.3],
            &[0.05, 0.1, 0.2, 0.4, 0.8],
        ];
        for series in cases {
            let (expected, _) = OlsLinearModel
                .predict_series(series)
                .expect("baseline predicts");
            let (actual, _) = parsed.predict_series(series).expect("export predicts");
            assert!(
                (expected - actual).abs() < 1e-6,
                "exported model must reproduce the NWDAF's prediction for {series:?}: \
                 expected {expected}, got {actual}"
            );
        }
    }

    /// The closed-form weights must equal the OLS fit for every window width the
    /// baseline can use, not just the one that is exported.
    #[test]
    fn window_weights_match_the_ols_fit_for_every_width() {
        for n in 2..=5 {
            let weights = ols_window_weights(n);
            assert_eq!(weights.len(), n);
            // A flat series predicts itself, so the weights sum to 1.
            let sum: f64 = weights.iter().sum();
            assert!((sum - 1.0).abs() < 1e-9, "n={n} weights sum to {sum}");

            // A ramp 0,1,..,n-1 extrapolates to n.
            let ramp: Vec<f64> = (0..n).map(|i| i as f64).collect();
            let predicted: f64 = weights.iter().zip(&ramp).map(|(w, y)| w * y).sum();
            assert!(
                (predicted - n as f64).abs() < 1e-9,
                "n={n} ramp extrapolation gave {predicted}, expected {n}"
            );
        }
    }

    #[test]
    fn encoded_model_declares_single_output_and_the_ml_domain() {
        let bytes = encode_linear_regressor(&[-0.4, -0.1, 0.2, 0.5, 0.8], 0.0);
        // The reader rejects targets != 1 and non-LinearRegressor ops, so a
        // successful parse pins both.
        let parsed = OnnxLinearRegressor::from_bytes(&bytes, "x").expect("parses");
        assert_eq!(parsed.model_id(), "x");
        assert!(bytes.windows(10).any(|w| w == b"ai.onnx.ml"));
        assert!(!bytes.is_empty());
    }

    /// An intercept must survive the round trip, since a loaded ONNX model may
    /// carry a non-zero one even though the OLS export does not.
    #[test]
    fn intercept_round_trips() {
        let bytes = encode_linear_regressor(&[0.5, 0.5], 0.25);
        let parsed = OnnxLinearRegressor::from_bytes(&bytes, "x").expect("parses");
        // 0.25 + 0.5*0.1 + 0.5*0.1 = 0.35
        let (pred, _) = parsed.predict_series(&[0.1, 0.1]).expect("predicts");
        assert!((pred - 0.35).abs() < 1e-6, "got {pred}");
    }
}
