# NWDAF Analytics Inference (Design Note)

> **Non-normative 6G research.** NWDAF analytics are TS 23.288 / TS 29.520
> functionality; the ML-serving abstraction and model backends here are
> prototype-level — **no frozen Stage-3 specification covers model
> internals**. Research shape for education, not a conformance target.
> Tracking issue: [#26](https://github.com/NextgCoreLab/nextgcore/issues/26).

## The inference abstraction

`nextgcore-nwdafd`'s `ml_service` now defines a minimal load-by-id +
predict surface (issue #26):

```rust
pub trait InferenceModel: Send + Sync {
    fn model_id(&self) -> &str;
    fn predict_series(&self, series: &[f64]) -> Option<(f64, f64)>; // (prediction, confidence)
}
pub fn load_model(model_id: &str) -> Result<Box<dyn InferenceModel>, String>;
```

The `NF_LOAD` analytics path is wired through it end to end:
`nrf_collector` (samples from NRF NFStatusNotify) → `AnalyticsEngine`
(`compute_nf_load` calls the **active model**) → `Nnwdaf_AnalyticsInfo`
GET / EventsSubscription Notify (the emitted `confidence` member — the
TS 29.520 prediction-confidence Uinteger — is the model's output; the wire
shape is unchanged and stays spec-pure: the vendor `predictedLoad` key
removed in G2-1 stays removed, so the numeric prediction surfaces via the
engine API (`NfLoadAnalytics.predicted_load`), not as an invented wire
member).

## Models

| id | file needed | prediction | confidence semantics |
|---|---|---|---|
| `ols-linear` (default) | no | OLS fit over last ≤5 samples, one step ahead | R² of the fit (byte-identical to the pre-#26 inline math) |
| `ewma[:<alpha>]` | no | exponentially weighted moving average | `1 − mean abs one-step error` (heuristic) |
| `onnx:<path>` | yes | linear model applied to the last *n* samples | backtest R² of the loaded model over the observed series |

Selection: set `NWDAF_PREDICTION_MODEL` (e.g. `ewma:0.5`,
`onnx:/etc/nextgcore/nfload.onnx`) before starting `nextgcore-nwdafd`;
unset = `ols-linear`, behavior-identical to before issue #26. An invalid
value logs a warning and keeps the default.

## The ONNX backend (feature `onnx-model`, off by default)

Zero-dependency by design: a hand-rolled reader for a **minimal, explicitly
documented ONNX subset** — exactly one `ai.onnx.ml` `LinearRegressor` node
(`coefficients` + `intercepts`), the class `skl2onnx` exports for sklearn
`LinearRegression`. Anything else in the graph is a **hard error**, never a
silent approximation. Rationale: no C-linked runtime (repo rule), zero
Cargo.lock growth (the pqc-tls precedent), and hand-rolled wire codecs are
the house style. Test models are built as protobuf bytes in test source —
no binary fixtures (per the never-commit-binaries decision).

## Federation status

`federation.rs` keeps its **real, tested local FedAvg** aggregation
(`FlAggregationRound::aggregate`, element-wise mean) and peer registry as an
internal library; the genuinely dead scaffolding (`FederatedRequest`, the
never-touched `requests` map) was removed. Honesty note: nothing federates
over the wire — there is no cross-NWDAF protocol here.

## Verification

```sh
cargo test -p nextgcore-nwdafd                          # default: OLS baseline, no model file
cargo test -p nextgcore-nwdafd --features onnx-model    # + ONNX subset reader tests
NWDAF_PREDICTION_MODEL=ewma cargo run -p nextgcore-nwdafd   # live model swap
```
