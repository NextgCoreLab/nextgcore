//! Demo `d441e-model-retrain` (nextgsim#468), PR 4: the MTLF's retrain and the
//! demo's seeded series. Cargo feature `demo-d441e-model-retrain` and the
//! `demo:` block, off by default.
//!
//! # The retrain (MTLF, mode `retrain`)
//! TS 23.288 §6.2E.3.3 steps 8-9 (23288-k10 l.10572-10600): when the MTLF
//! considers a model degraded from the AnLFs' Analytics Accuracy Information,
//! it "re-trains the existing ML Model ... and notifies the NWDAF(s) containing
//! AnLF with the updated trained ML Model Information by invoking
//! Nnwdaf_MLModelProvision_Notify". How it decides is "an internal procedure"
//! (NOTE 2); here it is PR 3's rule: a live registration of the **active**
//! model whose rolling accuracy fell below its threshold
//! ([`crate::model_monitor::Monitor::retrain_requested`]).
//!
//! The MTLF's upkeep (every 5 s) then:
//!
//! 1. takes the newest [`REFIT_WINDOW`] points of its own series (the monitor's
//!    `series` instance, else the NF series with the most samples). The data is
//!    the MTLF's own collection (§6.2E.2 step 8: the MTLF "may collect new
//!    data ... from the data source NFs"); it does not fetch the AnLF's data;
//! 2. splits the lagged rows in time order: the oldest three quarters train,
//!    the newest quarter is held out;
//! 3. fits AR([`AR_ORDER`]) by least squares (a tiny ridge term keeps a
//!    periodic series' collinear lags solvable) on the training rows. The
//!    order is the window v1 was exported with, so the artefact keeps its
//!    `[N, 5]` input;
//! 4. reports the held-out MAE of the refit against the current model (the
//!    no-retrain baseline) and persistence (the last value), and asserts
//!    nothing about which is better;
//! 5. makes the refit, exactly as it would be served (float32), the NF_LOAD
//!    predictor. PR 1's store publishes it as the next version
//!    (`training_type: RE_TRAINING`) and the dispatcher notifies every
//!    subscription once (§6.2E.2 step 13). The shipped model is the one the
//!    held-out MAE was measured on: it is not refitted on the held-out rows.
//!
//! A model is retrained at most once: the refit has a new `modelUniqueId`, so
//! the old model is no longer the active one, the AnLF registers the new one
//! afresh, and its registration starts unlatched. A window too short to fit,
//! a refit identical to the served model, or one that cannot be published
//! leaves the served model in place and is retried on the next upkeep. Mode
//! `no-retrain` never refits.
//!
//! # The seeded series (both roles)
//! The demo's data source: one synthetic NF (`SERIES_NF_INSTANCE`, type AMF)
//! whose CPU load at step `k = unix_secs / step_secs` is a pure function of
//! `(seed, k)`. Two NWDAFs with the same `nwdaf.retrain_series` therefore see
//! the same series without talking to each other, whenever each started. Each
//! `cycle_steps`-step cycle is **calm** (`0.5 + 0.1 sin(2πk/60)`) for its first
//! `change_at_step` steps, then **alternating** (`0.5 ± 0.3`) for the rest,
//! with uniform noise of ±0.02 throughout. The change is scripted and
//! disclosed: both NWDAFs log it. v1 (the OLS extrapolator) follows the calm
//! part and scores about 0.64 on the alternating part; an AR refit on the
//! alternating part follows both.
//!
//! While the series runs, the AnLF judges its model on it and the MTLF
//! retrains on it, and on nothing else. It is also an NF_LOAD analytics target
//! like any other NF.
//!
//! # Honesty
//! The model is OLS/AR in a single `LinearRegressor`; "learned" means a least
//! squares refit on recent data. The series is synthetic.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::context::NwdafContext;
use crate::ml_service::InferenceModel;
use crate::model_monitor::Monitor;
use crate::model_retrain::DEMO_KEY;
use crate::onnx_model::OnnxLinearRegressor;

/// The AR order of a refit: v1's export window, so the input shape stays.
pub const AR_ORDER: usize = crate::ml_service::OLS_EXPORT_WINDOW;
/// The newest points of the series a refit sees.
pub const REFIT_WINDOW: usize = 48;
/// The fewest training rows a refit accepts (three per parameter).
pub const MIN_TRAIN_ROWS: usize = 3 * (AR_ORDER + 1);
/// The ridge term, per training row, on the centred normal equations.
pub const RIDGE: f64 = 1e-6;

/// The seeded series' NF instance id.
pub const SERIES_NF_INSTANCE: &str = "d441e000-0468-4000-8000-000000000468";
/// The NF type the seeded series is reported as.
pub const SERIES_NF_TYPE: &str = "AMF";

/// `nwdaf.retrain_series`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesConfig {
    pub seed: u64,
    pub step_secs: u64,
    pub cycle_steps: u64,
    pub change_at_step: u64,
}

impl Default for SeriesConfig {
    fn default() -> Self {
        Self {
            seed: 468,
            step_secs: 1,
            cycle_steps: 600,
            change_at_step: 120,
        }
    }
}

/// The two regimes of the seeded series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    Calm,
    Alternating,
}

impl Regime {
    pub fn as_str(self) -> &'static str {
        match self {
            Regime::Calm => "calm",
            Regime::Alternating => "alternating",
        }
    }
}

/// splitmix64: a fixed, well-mixed hash of `x`.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl SeriesConfig {
    /// The step of unix time `secs`.
    pub fn step_of(&self, secs: u64) -> u64 {
        secs / self.step_secs
    }

    pub fn regime(&self, k: u64) -> Regime {
        if k % self.cycle_steps < self.change_at_step {
            Regime::Calm
        } else {
            Regime::Alternating
        }
    }

    /// Uniform noise in [-1, 1) at step `k`.
    fn noise(&self, k: u64) -> f64 {
        let h = splitmix64(self.seed ^ splitmix64(k));
        (h >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0
    }

    /// The CPU load at step `k`, in 0..1.
    pub fn value(&self, k: u64) -> f64 {
        let base = match self.regime(k) {
            Regime::Calm => 0.5 + 0.1 * (2.0 * std::f64::consts::PI * (k % 60) as f64 / 60.0).sin(),
            Regime::Alternating => {
                if k.is_multiple_of(2) {
                    0.8
                } else {
                    0.2
                }
            }
        };
        (base + 0.02 * self.noise(k)).clamp(0.0, 1.0)
    }

    /// The first step at or after `k` where the regime changes.
    pub fn next_change(&self, k: u64) -> u64 {
        let phase = k % self.cycle_steps;
        let start = k - phase;
        if phase < self.change_at_step {
            start + self.change_at_step
        } else {
            start + self.cycle_steps
        }
    }
}

/// Parse `nwdaf.retrain_series`: absent = the defaults; `enabled: false` =
/// `None` (no series; judge and retrain on the real NF series). A malformed
/// block is an error.
pub fn series_config_from_root(root: &serde_yaml::Value) -> Result<Option<SeriesConfig>, String> {
    let mut cfg = SeriesConfig::default();
    let Some(block) = root.get("nwdaf").and_then(|n| n.get("retrain_series")) else {
        return Ok(Some(cfg));
    };
    let map = block
        .as_mapping()
        .ok_or("nwdaf.retrain_series must be a mapping")?;
    let mut enabled = true;
    for (k, v) in map {
        let key = k.as_str().unwrap_or("");
        let uint = || {
            v.as_u64().ok_or(format!(
                "nwdaf.retrain_series.{key} must be an unsigned integer"
            ))
        };
        match key {
            "enabled" => {
                enabled = v
                    .as_bool()
                    .ok_or("nwdaf.retrain_series.enabled must be a boolean")?
            }
            "seed" => cfg.seed = uint()?,
            "step_secs" => cfg.step_secs = uint()?,
            "cycle_steps" => cfg.cycle_steps = uint()?,
            "change_at_step" => cfg.change_at_step = uint()?,
            _ => return Err(format!("unknown key nwdaf.retrain_series.{k:?}")),
        }
    }
    if !(1..=3600).contains(&cfg.step_secs) {
        return Err("nwdaf.retrain_series.step_secs must be 1..3600".into());
    }
    if cfg.change_at_step == 0 || cfg.change_at_step >= cfg.cycle_steps {
        return Err("nwdaf.retrain_series.change_at_step must be 1..cycle_steps-1".into());
    }
    Ok(enabled.then_some(cfg))
}

/// Ingest steps `from..=to` of the series into `ctx` (at most the engine's
/// buffer, the newest). Returns the regime changes crossed, as
/// `(step, new regime)`.
pub fn ingest_steps(
    ctx: &NwdafContext,
    cfg: &SeriesConfig,
    from: u64,
    to: u64,
) -> Vec<(u64, Regime)> {
    let from = from.max(to.saturating_sub(crate::analytics::MAX_SAMPLES as u64 - 1));
    let mut changes = Vec::new();
    let mut engine = ctx.lock_engine();
    for k in from..=to {
        if k > 0 && cfg.regime(k) != cfg.regime(k - 1) {
            changes.push((k, cfg.regime(k)));
        }
        engine.ingest_nf_load(crate::analytics::NfLoadSample {
            nf_type: SERIES_NF_TYPE.to_string(),
            nf_instance_id: SERIES_NF_INSTANCE.to_string(),
            cpu_usage: cfg.value(k),
            mem_usage: 0.0,
            active_sessions: 0,
            timestamp: k * cfg.step_secs,
        });
    }
    changes
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Log the series (start-up).
pub fn announce(cfg: &SeriesConfig) {
    let k = cfg.step_of(unix_now());
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "seeded series nf={SERIES_NF_INSTANCE} seed={} step={}s: calm (0.5 + 0.1 sin) for steps \
         [0, {}) of every {}-step cycle, then alternating (0.5 +/- 0.3), noise +/-0.02; now step \
         {k} ({}), next regime change at step {} (unix {})",
        cfg.seed,
        cfg.step_secs,
        cfg.change_at_step,
        cfg.cycle_steps,
        cfg.regime(k).as_str(),
        cfg.next_change(k),
        cfg.next_change(k) * cfg.step_secs
    );
}

/// Feed the series into `ctx` for the life of the process: a full buffer of
/// history at once, then one sample per step.
pub fn spawn_series(cfg: SeriesConfig, ctx: Arc<RwLock<NwdafContext>>) {
    tokio::spawn(async move {
        let mut last: Option<u64> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(cfg.step_secs));
        loop {
            tick.tick().await;
            let now = cfg.step_of(unix_now());
            if last.is_some_and(|l| l >= now) {
                continue;
            }
            let from = last.map_or(0, |l| l + 1);
            let changes = {
                let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
                ingest_steps(&guard, &cfg, from, now)
            };
            // The history's changes are not news; the live ones are.
            if last.is_some() {
                for (k, r) in changes {
                    nextgcore_demo::demo_log!(
                        warn,
                        DEMO_KEY,
                        "seeded series: regime {} from step {k} (scripted regime change)",
                        r.as_str()
                    );
                }
            }
            last = Some(now);
        }
    });
}

// ── the refit ────────────────────────────────────────────────────────────────

/// A least-squares AR fit and its held-out evaluation.
#[derive(Debug, Clone)]
pub struct Refit {
    /// The NF instance whose series it was fitted on.
    pub instance: String,
    /// The model exactly as it is served (float32 coefficients).
    pub model: OnnxLinearRegressor,
    pub points: usize,
    pub train_rows: usize,
    pub holdout_rows: usize,
    /// Held-out MAE of the refit, of the model it replaces, and of persistence.
    pub mae_refit: f64,
    pub mae_current: f64,
    pub mae_persistence: f64,
}

/// Least-squares AR(`order`) on every lagged row of `series`: `(coefficients
/// for the last `order` samples oldest first, intercept)`. The intercept is not
/// penalised; the coefficients carry a ridge term of [`RIDGE`] per row.
pub fn fit_ar(series: &[f64], order: usize) -> Result<(Vec<f64>, f64), String> {
    if order == 0 || series.len() <= order {
        return Err(format!("{} points cannot fit AR({order})", series.len()));
    }
    let rows = series.len() - order;
    let mut xm = vec![0.0; order];
    let mut ym = 0.0;
    for t in order..series.len() {
        for (j, m) in xm.iter_mut().enumerate() {
            *m += series[t - order + j];
        }
        ym += series[t];
    }
    xm.iter_mut().for_each(|m| *m /= rows as f64);
    ym /= rows as f64;
    // Centred normal equations [A | b].
    let mut a = vec![vec![0.0; order + 1]; order];
    for t in order..series.len() {
        let x: Vec<f64> = (0..order).map(|j| series[t - order + j] - xm[j]).collect();
        let y = series[t] - ym;
        for i in 0..order {
            for j in 0..order {
                a[i][j] += x[i] * x[j];
            }
            a[i][order] += x[i] * y;
        }
    }
    for (i, row) in a.iter_mut().enumerate() {
        row[i] += RIDGE * rows as f64;
    }
    // Gaussian elimination with partial pivoting.
    for col in 0..order {
        let pivot = (col..order)
            .max_by(|&p, &q| a[p][col].abs().total_cmp(&a[q][col].abs()))
            .unwrap_or(col);
        if a[pivot][col].abs() < 1e-12 {
            return Err("the series does not determine an AR fit".into());
        }
        a.swap(col, pivot);
        for r in 0..order {
            if r != col {
                let f = a[r][col] / a[col][col];
                for c in col..=order {
                    a[r][c] -= f * a[col][c];
                }
            }
        }
    }
    let w: Vec<f64> = (0..order).map(|i| a[i][order] / a[i][i]).collect();
    let intercept = ym - w.iter().zip(&xm).map(|(w, m)| w * m).sum::<f64>();
    if !intercept.is_finite() || w.iter().any(|c| !c.is_finite()) {
        return Err("the AR fit is not finite".into());
    }
    Ok((w, intercept))
}

/// Mean absolute one-step error of `predict` over the targets `from..` of
/// `series`, each predicted from the samples before it. Targets a model
/// declines are skipped.
fn mae(series: &[f64], from: usize, predict: impl Fn(&[f64]) -> Option<f64>) -> f64 {
    let (mut sum, mut n) = (0.0, 0usize);
    for t in from..series.len() {
        if let Some(p) = predict(&series[..t]) {
            sum += (p - series[t]).abs();
            n += 1;
        }
    }
    if n == 0 {
        f64::NAN
    } else {
        sum / n as f64
    }
}

/// Refit on `window` (oldest first) of `instance`: train on the oldest three
/// quarters of the lagged rows, evaluate on the newest quarter against
/// `current` and persistence.
pub fn refit(
    window: &[f64],
    instance: &str,
    current: &dyn InferenceModel,
) -> Result<Refit, String> {
    let rows = window.len().saturating_sub(AR_ORDER);
    let holdout = (rows / 4).max(1);
    let train = rows.saturating_sub(holdout);
    if train < MIN_TRAIN_ROWS {
        return Err(format!(
            "{} points give {train} training rows; {MIN_TRAIN_ROWS} needed",
            window.len()
        ));
    }
    let split = AR_ORDER + train;
    let (coefficients, intercept) = fit_ar(&window[..split], AR_ORDER)?;
    let bytes = crate::onnx_export::encode_linear_regressor(&coefficients, intercept);
    let model = OnnxLinearRegressor::from_bytes(&bytes, "ar-refit")?;
    let mae_refit = mae(window, split, |s| model.predict_series(s).map(|p| p.0));
    let mae_current = mae(window, split, |s| current.predict_series(s).map(|p| p.0));
    let mae_persistence = mae(window, split, |s| s.last().copied());
    Ok(Refit {
        instance: instance.to_string(),
        model,
        points: window.len(),
        train_rows: train,
        holdout_rows: holdout,
        mae_refit,
        mae_current,
        mae_persistence,
    })
}

/// The MTLF's retrain bookkeeping (one per monitor).
#[derive(Debug, Default)]
pub struct RefitState {
    /// The `modelUniqueId`s whose deferral was logged.
    deferred: HashSet<u64>,
    refits: u64,
    last: Option<(f64, f64, f64)>,
}

/// What one [`refit_tick`] did.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing to retrain.
    Idle,
    /// A retrain is due but did not yield a new version: the data cannot fit
    /// one yet, the refit is the model already served, or it cannot be
    /// published. The served model is unchanged.
    Deferred(String),
    /// Retrained: the replaced version, the new one, the fit.
    Refitted {
        from: Box<crate::model_store::ModelVersion>,
        to: Box<crate::model_store::ModelVersion>,
        refit: Box<Refit>,
    },
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Log a deferral once per model.
fn defer(m: &Monitor, model_id: u64, why: String) -> Outcome {
    if lock(&m.refit).deferred.insert(model_id) {
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "retrain of modelId={model_id} deferred: {why}"
        );
    }
    Outcome::Deferred(why)
}

/// One retrain check on `ctx` (the MTLF's upkeep): if the active model is
/// below the threshold at a live registration (which mode `no-retrain` never
/// reports, [`Monitor::retrain_requested`]), refit it, make the refit the
/// predictor and publish it as the next version.
pub fn refit_tick(m: &Monitor, ctx: &RwLock<NwdafContext>) -> Outcome {
    let guard = ctx.read().unwrap_or_else(|p| p.into_inner());
    let Some(from) = guard.current_model_version() else {
        return Outcome::Idle;
    };
    let model_id = from.unique_id();
    if !m.retrain_requested(model_id) {
        return Outcome::Idle;
    }
    let fitted = {
        let engine = guard.lock_engine();
        match engine.nf_load_series(m.series.as_deref()) {
            Some((instance, series)) => {
                let window = &series[series.len().saturating_sub(REFIT_WINDOW)..];
                refit(window, &instance, engine.predictor())
            }
            None => Err("no series to retrain on".to_string()),
        }
    };
    match fitted {
        Ok(r) => apply(m, &guard, from, r),
        Err(e) => defer(m, model_id, e),
    }
}

/// Serve `refit` in place of `from` and publish it. A refit that is the
/// served model already, or that cannot be published, leaves `from` served.
pub fn apply(
    m: &Monitor,
    ctx: &NwdafContext,
    from: crate::model_store::ModelVersion,
    refit: Refit,
) -> Outcome {
    let model_id = from.unique_id();
    ctx.lock_engine()
        .set_predictor(Box::new(refit.model.clone()));
    let to = match ctx.current_model_version() {
        Some(to) if to.sha256 == from.sha256 => {
            return defer(
                m,
                model_id,
                format!("the refit is v{} itself", from.version),
            );
        }
        Some(to) => to,
        None => {
            // Keep serving (and advertising) the model that was.
            if let Ok(old) = OnnxLinearRegressor::from_bytes(&from.bytes, "restored") {
                ctx.lock_engine().set_predictor(Box::new(old));
            }
            return defer(
                m,
                model_id,
                format!("the refit cannot be published; keeping v{}", from.version),
            );
        }
    };
    {
        let mut st = lock(&m.refit);
        st.refits += 1;
        st.last = Some((refit.mae_refit, refit.mae_current, refit.mae_persistence));
    }
    nextgcore_demo::demo_log!(
        warn,
        DEMO_KEY,
        "retrain: AR({AR_ORDER}) least-squares refit of v{} (modelId={model_id}) on {} points of \
         nf={} ({} training rows, {} held out): held-out MAE {:.3} refit, {:.3} current model \
         (no-retrain), {:.3} persistence",
        from.version,
        refit.points,
        refit.instance,
        refit.train_rows,
        refit.holdout_rows,
        refit.mae_refit,
        refit.mae_current,
        refit.mae_persistence
    );
    nextgcore_demo::demo_log!(
        warn,
        DEMO_KEY,
        "retrain: model v{} published sha256={} modelId={} (replaces v{})",
        to.version,
        to.sha256,
        to.unique_id(),
        from.version
    );
    Outcome::Refitted {
        from: Box::new(from),
        to: Box::new(to),
        refit: Box::new(refit),
    }
}

/// This module's `/metrics` families.
pub fn render_metrics(out: &mut String, m: Option<&Monitor>) {
    use std::fmt::Write as _;
    let (refits, last) = m
        .map(|m| {
            let st = lock(&m.refit);
            (st.refits, st.last)
        })
        .unwrap_or((0, None));
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_model_refits_total",
        "counter",
        "Models this MTLF retrained after an accuracy drop (nextgsim#468)",
        refits,
    );
    if let Some((r, c, p)) = last {
        nextgcore_metrics::nf::write_header(
            out,
            "nwdaf_model_refit_holdout_mae",
            "gauge",
            "Held-out MAE of the last retrain: the refit, the replaced model, persistence (nextgsim#468)",
        );
        for (who, v) in [("refit", r), ("current", c), ("persistence", p)] {
            let _ = writeln!(out, "nwdaf_model_refit_holdout_mae{{model=\"{who}\"}} {v}");
        }
    }
}

#[cfg(test)]
mod tests;
