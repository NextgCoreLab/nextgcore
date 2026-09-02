//! NextGCore WebUI - Subscriber Management Dashboard
//!
//! Provides a web-based interface for managing 5G subscribers in the UDR/MongoDB backend.
//! Supports CRUD operations on subscriber profiles (IMSI, K, OPc, AMF, SQN, slice config).
//!
//! # Usage
//! ```bash
//! nextgcore-webui --db-uri mongodb://localhost:27017 --db-name nextgcore --port 3000
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::Parser;
use nextgcore_dbi::types::NEXTGCORE_DEFAULT_DB_NAME;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

/// Default MongoDB database, taken from nextgcore-dbi so the WebUI and the UDR
/// cannot disagree about where subscribers live.
const DEFAULT_DB_NAME: &str = NEXTGCORE_DEFAULT_DB_NAME;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "nextgcore-webui",
    about = "NextGCore Subscriber Management WebUI"
)]
struct Args {
    /// MongoDB connection URI
    #[arg(long, default_value = "mongodb://localhost:27017")]
    db_uri: String,

    /// MongoDB database name.
    ///
    /// Must match what the UDR reads. nextgcore-dbi falls back to "nextgcore"
    /// (mongoc.rs) and docs/assets/webui/mongo-init.js seeds "nextgcore"; this
    /// used to default to "open5gs", so provisioning through the standalone UI
    /// without an explicit --db-name landed in a database the UDR never reads
    /// and presented as "subscriber not found" after a successful create.
    #[arg(long, default_value = DEFAULT_DB_NAME)]
    db_name: String,

    /// HTTP listen port
    #[arg(short, long, default_value_t = 3000)]
    port: u16,

    /// Listen address.
    ///
    /// Issue #118: defaults to LOOPBACK, not `0.0.0.0`. This is a subscriber
    /// provisioning interface; binding every interface by default maximised the
    /// blast radius of any other weakness. An operator that wants it reachable
    /// must name the management address explicitly.
    #[arg(long, default_value = "127.0.0.1")]
    listen: String,

    /// File containing the bearer token required on every `/api` request
    /// (issue #118).
    ///
    /// A file rather than a flag value so the secret is not visible in `ps` or
    /// the shell history. `NEXTGCORE_WEBUI_API_TOKEN` is the alternative source.
    /// Leading/trailing whitespace is trimmed so a trailing newline in the file
    /// is not part of the token.
    #[arg(long)]
    api_token_file: Option<String>,

    /// TLS certificate chain, PEM (issue #118). Required with `--tls-key`.
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key, PEM (issue #118).
    #[arg(long)]
    tls_key: Option<String>,

    /// Run with NO authentication and NO TLS. Local development only.
    ///
    /// The insecure path is the explicit opt-in and secure is the default, never
    /// the other way round: this interface can read and write permanent
    /// subscriber key material.
    #[arg(long)]
    insecure_dev: bool,
}

/// Environment variable carrying the `/api` bearer token, as an alternative to
/// `--api-token-file`.
const API_TOKEN_ENV: &str = "NEXTGCORE_WEBUI_API_TOKEN";

/// Minimum accepted length for the `/api` bearer token.
///
/// Not a strength estimate — just a floor that rejects obviously-placeholder
/// values like `test` or `secret` that would otherwise pass for a credential.
const MIN_API_TOKEN_LEN: usize = 16;

/// Resolve the `/api` bearer token, or explain why startup must fail.
///
/// `Ok(None)` is returned ONLY for `--insecure-dev`. Otherwise a missing token is
/// a hard startup failure: a provisioning API that can read and write permanent
/// subscriber keys must not come up unauthenticated because a flag was forgotten
/// (TS 33.117 §4.2.3.2.4).
fn resolve_api_token(args: &Args) -> Result<Option<String>> {
    let from_file = match &args.api_token_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read --api-token-file {path}"))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    let token = from_file.or_else(|| {
        std::env::var(API_TOKEN_ENV)
            .ok()
            .map(|v| v.trim().to_string())
    });

    match token {
        Some(t) if t.len() >= MIN_API_TOKEN_LEN => Ok(Some(t)),
        Some(t) if t.is_empty() => anyhow::bail!(
            "the /api bearer token is empty; provide a real credential via \
             --api-token-file or {API_TOKEN_ENV}"
        ),
        Some(t) => anyhow::bail!(
            "the /api bearer token is {} characters; at least {MIN_API_TOKEN_LEN} are required",
            t.len()
        ),
        None if args.insecure_dev => Ok(None),
        None => anyhow::bail!(
            "refusing to start: the subscriber provisioning API would be \
             unauthenticated. Supply a bearer token via --api-token-file or \
             {API_TOKEN_ENV}, or pass --insecure-dev for local development only."
        ),
    }
}

/// Compare two secrets without leaking their common prefix length through timing.
///
/// Hand-written rather than pulling in a new workspace dependency for six lines.
/// The length comparison is deliberately NOT short-circuited into the loop: token
/// length is not the secret, and folding it in would make the loop bound depend on
/// the candidate.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Data models (mirrors Open5GS subscriber schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscriber {
    pub imsi: String,
    #[serde(default)]
    pub msisdn: Vec<String>,
    pub security: SecurityContext,
    #[serde(default)]
    pub ambr: Ambr,
    #[serde(default)]
    pub slice: Vec<SliceConfig>,
    #[serde(default)]
    pub status: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub k: String,
    #[serde(default)]
    pub opc: String,
    #[serde(default)]
    pub op: String,
    #[serde(default = "default_amf")]
    pub amf: String,
    /// AKA sequence number, a 48-bit counter (TS 33.102 6.3).
    ///
    /// i64, NOT String: this serialises to a BSON Int64, which is what the
    /// rest of the stack requires. nextgcore-dbi reads it with `get_i64`
    /// (subscription.rs) and advances it with `$inc` then a `$bit` 48-bit mask
    /// -- both numeric-only Mongo operators. While this was a String, a
    /// subscriber provisioned here read back as SQN 0 and the maintenance
    /// operators errored, so SQN_HE could never advance: AKA de-synchronised,
    /// AUTS re-sync failed repeatedly, and attach could block. The Node model
    /// (webui/server/models/subscriber.js) always used Schema.Types.Long.
    ///
    /// Deserialisation accepts a String too, so documents written by the older
    /// build still load instead of failing the whole read.
    #[serde(default, deserialize_with = "deserialize_sqn")]
    pub sqn: i64,
}

/// Accept Int64, Int32 or String for `sqn`.
///
/// Existing deployments already hold String values written by the previous
/// build; rejecting them would turn a legacy record into a failed read rather
/// than the recoverable one it is. A non-numeric string is the one case with
/// no sensible reading, so it is an error.
fn deserialize_sqn<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error as DeError, Unexpected, Visitor};
    use std::fmt;

    // A hand-written Visitor rather than an intermediate Value: this runs under
    // BOTH bson::from_document (the Mongo read path) and serde_json (the HTTP
    // request path), and an intermediate serde_json::Value cannot represent a
    // BSON Int64, which is exactly the type this field now stores.
    struct SqnVisitor;

    impl<'de> Visitor<'de> for SqnVisitor {
        type Value = i64;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an integer sqn, or a numeric string from a legacy document")
        }

        fn visit_i64<E: DeError>(self, v: i64) -> Result<i64, E> {
            Ok(v)
        }

        fn visit_i32<E: DeError>(self, v: i32) -> Result<i64, E> {
            Ok(i64::from(v))
        }

        fn visit_u64<E: DeError>(self, v: u64) -> Result<i64, E> {
            i64::try_from(v).map_err(|_| E::custom(format!("sqn {v} exceeds i64")))
        }

        fn visit_u32<E: DeError>(self, v: u32) -> Result<i64, E> {
            Ok(i64::from(v))
        }

        fn visit_f64<E: DeError>(self, v: f64) -> Result<i64, E> {
            // JSON numbers may arrive as f64. Accept only exact integers: a
            // fractional SQN is a client bug, not something to round silently.
            if v.fract() == 0.0 && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
                Ok(v as i64)
            } else {
                Err(E::custom(format!("sqn {v} is not an integer")))
            }
        }

        fn visit_str<E: DeError>(self, v: &str) -> Result<i64, E> {
            let t = v.trim();
            if t.is_empty() {
                return Ok(0);
            }
            t.parse::<i64>()
                .map_err(|_| E::invalid_value(Unexpected::Str(v), &self))
        }

        fn visit_unit<E: DeError>(self) -> Result<i64, E> {
            Ok(0)
        }

        fn visit_none<E: DeError>(self) -> Result<i64, E> {
            Ok(0)
        }

        fn visit_some<D2>(self, d: D2) -> Result<i64, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            d.deserialize_any(self)
        }
    }

    deserializer.deserialize_any(SqnVisitor)
}

fn default_amf() -> String {
    "8000".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ambr {
    #[serde(default)]
    pub downlink: BitrateValue,
    #[serde(default)]
    pub uplink: BitrateValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitrateValue {
    #[serde(default = "default_bitrate")]
    pub value: u64,
    #[serde(default = "default_unit")]
    pub unit: u8,
}

impl Default for BitrateValue {
    fn default() -> Self {
        Self {
            value: 1,
            unit: 3, // Gbps
        }
    }
}

fn default_bitrate() -> u64 {
    1
}
fn default_unit() -> u8 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceConfig {
    pub sst: u8,
    #[serde(default)]
    pub sd: Option<String>,
    #[serde(default = "default_slice_name")]
    pub default_indicator: bool,
    #[serde(default)]
    pub session: Vec<SessionConfig>,
}

fn default_slice_name() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub session_type: u8,
    #[serde(default)]
    pub ambr: Ambr,
    #[serde(default)]
    pub qos: QosConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QosConfig {
    #[serde(default = "default_qci")]
    pub index: u8,
    #[serde(default)]
    pub arp: ArpConfig,
}

fn default_qci() -> u8 {
    9
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpConfig {
    #[serde(default = "default_priority")]
    pub priority_level: u8,
    #[serde(default)]
    pub pre_emption_capability: u8,
    #[serde(default)]
    pub pre_emption_vulnerability: u8,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            priority_level: 8,
            pre_emption_capability: 1,
            pre_emption_vulnerability: 1,
        }
    }
}

fn default_priority() -> u8 {
    8
}

// ---------------------------------------------------------------------------
// Read-path projection (issue #118)
// ---------------------------------------------------------------------------

/// The subscriber shape this API is allowed to RETURN.
///
/// Issue #118: the provisioning API used to serialise [`Subscriber`] directly, so
/// every read handed back `security.k` and `security.opc` — the permanent
/// subscriber key and the OPc derived from the operator key — as cleartext JSON.
/// TS 33.501 makes `K` the root of the whole 5G AKA trust chain: disclosure
/// permanently compromises authentication for that SUPI, and there is no recovery
/// short of re-provisioning the SIM. The 8-character truncation in the embedded
/// dashboard HTML was cosmetic; the raw JSON carried the full values.
///
/// THIS IS A SEPARATE TYPE ON PURPOSE, not `#[serde(skip_serializing)]` on
/// [`SecurityContext`]. Those fields must still serialise on the way OUT of this
/// process to MongoDB (that is how provisioning works), so a skip attribute
/// would have to be undone for the DB path and could be re-broken by anyone
/// adding a field. A projection type cannot leak a field it does not have:
/// `k`/`op`/`opc` are absent from [`SecurityView`] entirely, so re-introducing the
/// leak requires deliberately adding them back.
///
/// Provisioning stays write-only for key material: create/update accept `k`/`opc`
/// and answer with this view, never an echo of what was submitted.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriberView {
    pub imsi: String,
    pub msisdn: Vec<String>,
    pub security: SecurityView,
    pub ambr: Ambr,
    pub slice: Vec<SliceConfig>,
    pub status: i32,
}

/// The non-secret part of a subscriber's security context.
///
/// `amf` is an authentication-management-field constant, not a secret, and `sqn`
/// is a replay counter the operator legitimately needs to see. `k`, `op` and
/// `opc` have no member here at all — see [`SubscriberView`].
#[derive(Debug, Clone, Serialize)]
pub struct SecurityView {
    pub amf: String,
    pub sqn: i64,
    /// Whether key material is provisioned for this subscriber.
    ///
    /// An operator still needs to distinguish "provisioned" from "not
    /// provisioned" after the keys stopped being echoed back; this answers that
    /// without revealing anything about the value.
    pub key_provisioned: bool,
}

impl From<&Subscriber> for SubscriberView {
    fn from(sub: &Subscriber) -> Self {
        Self {
            imsi: sub.imsi.clone(),
            msisdn: sub.msisdn.clone(),
            security: SecurityView {
                amf: sub.security.amf.clone(),
                sqn: sub.security.sqn,
                key_provisioned: !sub.security.k.is_empty(),
            },
            ambr: sub.ambr.clone(),
            slice: sub.slice.clone(),
            status: sub.status,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Reject a malformed subscriber before it reaches MongoDB.
///
/// Provisioning used to check only that `imsi` and `security.k` were non-empty.
/// Everything downstream then trusted the record, and
/// `nextgcore_ascii_to_hex` silently DROPS non-hex pairs and truncates -- so a
/// mistyped K was persisted wrong with no diagnostic and authentication simply
/// failed later for no visible reason. Catching it here is the cheap place.
///
/// Lengths follow TS 23.003 2.2 for the IMSI and the fixed widths the crypto
/// layer expects: K/OPc/OP are 16 bytes, AMF 2, SD 3.
fn validate_subscriber(sub: &Subscriber) -> Result<(), String> {
    fn is_hex(s: &str, want: usize, field: &str) -> Result<(), String> {
        if s.len() != want {
            return Err(format!(
                "{field} must be {want} hex characters, got {}",
                s.len()
            ));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("{field} must be hexadecimal"));
        }
        Ok(())
    }

    let imsi = sub.imsi.trim();
    if !(5..=15).contains(&imsi.len()) {
        return Err(format!(
            "imsi must be 5-15 digits (TS 23.003 2.2), got {}",
            imsi.len()
        ));
    }
    if !imsi.chars().all(|c| c.is_ascii_digit()) {
        return Err("imsi must be decimal digits only".to_string());
    }

    is_hex(&sub.security.k, 32, "security.k")?;
    // OPc and OP are each optional, but a supplied value must be well formed.
    // At least one is needed to derive an authentication vector.
    if !sub.security.opc.is_empty() {
        is_hex(&sub.security.opc, 32, "security.opc")?;
    }
    if !sub.security.op.is_empty() {
        is_hex(&sub.security.op, 32, "security.op")?;
    }
    if sub.security.opc.is_empty() && sub.security.op.is_empty() {
        return Err("one of security.opc or security.op is required".to_string());
    }
    is_hex(&sub.security.amf, 4, "security.amf")?;

    if sub.security.sqn < 0 {
        return Err("security.sqn must not be negative".to_string());
    }
    if sub.security.sqn as u64 > nextgcore_dbi::types::NEXTGCORE_MAX_SQN {
        return Err("security.sqn exceeds the 48-bit range (TS 33.102 6.3)".to_string());
    }

    for slice in &sub.slice {
        if let Some(sd) = slice.sd.as_deref() {
            if !sd.is_empty() {
                is_hex(sd, 6, "slice.sd")?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct AppState {
    db_uri: String,
    db_name: String,
    /// Bearer token every `/api` request must present (issue #118).
    ///
    /// `None` means `--insecure-dev`: authentication is disabled. Kept as an
    /// `Option` rather than an empty string so "no auth" cannot be reached by
    /// accident — an empty token would otherwise match an empty header.
    api_token: Option<String>,
}

type SharedState = Arc<AppState>;

/// Require a valid bearer token on every `/api` request (issue #118).
///
/// Before this the `/api/subscribers*` routes carried no authentication at all,
/// so anyone who could reach the listener could read and write subscriber
/// records. TS 33.117 §4.2.3.2.4 requires authentication on a management
/// interface handling sensitive data.
///
/// Fails closed: any missing, malformed or non-matching credential is 401 with a
/// `WWW-Authenticate` challenge, and the body never says which of those it was —
/// distinguishing "no such token" from "wrong token" is free information for an
/// attacker.
async fn require_api_token(
    State(state): State<SharedState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(expected) = state.api_token.as_deref() else {
        // --insecure-dev. Logged on every request, not just at startup, so an
        // unauthenticated deployment cannot quietly become the steady state.
        log::warn!(
            "INSECURE: serving {} {} with authentication disabled (--insecure-dev)",
            request.method(),
            request.uri().path()
        );
        return next.run(request).await;
    };

    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) if secret_eq(token, expected) => next.run(request).await,
        _ => {
            log::warn!(
                "rejected unauthenticated {} {}",
                request.method(),
                request.uri().path()
            );
            (
                StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    "Bearer realm=\"nextgcore-webui\"",
                )],
                "unauthorized",
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

/// Build the JSON response for one subscriber.
///
/// Issue #118: the ONLY place a single subscriber becomes a response body, so the
/// projection through [`SubscriberView`] cannot be bypassed by editing one handler.
/// Tested on the produced BYTES, not on the type, so reverting it is a test failure.
fn subscriber_response(sub: &Subscriber) -> Response {
    Json(SubscriberView::from(sub)).into_response()
}

/// Build the JSON response for a list of subscribers. See [`subscriber_response`].
fn subscriber_list_response(subs: &[Subscriber]) -> Response {
    let view: Vec<SubscriberView> = subs.iter().map(SubscriberView::from).collect();
    Json(view).into_response()
}

async fn list_subscribers(State(state): State<SharedState>) -> Response {
    match db_list_subscribers(&state.db_uri, &state.db_name) {
        // Issue #118: projected through SubscriberView, which has no k/op/opc
        // member, so the long-term key cannot leave over this API.
        Ok(subs) => subscriber_list_response(&subs),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_subscriber(State(state): State<SharedState>, Path(imsi): Path<String>) -> Response {
    match db_get_subscriber(&state.db_uri, &state.db_name, &imsi) {
        // Issue #118: key material is never returned — see SubscriberView.
        Ok(Some(sub)) => subscriber_response(&sub),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn create_subscriber(
    State(state): State<SharedState>,
    Json(sub): Json<Subscriber>,
) -> Response {
    if let Err(e) = validate_subscriber(&sub) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    match db_create_subscriber(&state.db_uri, &state.db_name, &sub) {
        // Issue #118: the 201 must not echo the submitted k/opc back either —
        // provisioning is write-only for key material.
        Ok(()) => (StatusCode::CREATED, subscriber_response(&sub)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_subscriber(
    State(state): State<SharedState>,
    Path(imsi): Path<String>,
    Json(mut sub): Json<Subscriber>,
) -> Response {
    // Issue #118, key-PRESERVING update. Once reads stopped echoing `k`/`opc`, no
    // client can round-trip them — including this daemon's own dashboard, which
    // used to prefill the edit form from the GET response. An update that omits
    // key material therefore means "leave the keys alone", not "blank them".
    //
    // Without this the edit path would submit an empty `k` and either 400 (best
    // case) or overwrite a provisioned key with nothing. Omission is now the
    // safe operation and re-keying requires explicitly supplying a new value.
    if sub.security.k.trim().is_empty() {
        match db_get_subscriber(&state.db_uri, &state.db_name, &imsi) {
            Ok(Some(existing)) => {
                sub.security.k = existing.security.k;
                // OP/OPc travel with K: a partial carry-over could pair a stored
                // K with a submitted OPc from a different credential set.
                if sub.security.opc.trim().is_empty() && sub.security.op.trim().is_empty() {
                    sub.security.opc = existing.security.opc;
                    sub.security.op = existing.security.op;
                }
            }
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    // Update validates too: an update writes the same document shape, so
    // skipping it here would leave a hole straight to the create-path defect.
    // Runs AFTER the carry-over so a key-preserving update still has to produce a
    // fully valid document.
    if let Err(e) = validate_subscriber(&sub) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    match db_update_subscriber(&state.db_uri, &state.db_name, &imsi, &sub) {
        // Issue #118: as for create — no echo of key material.
        Ok(true) => subscriber_response(&sub),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_subscriber(State(state): State<SharedState>, Path(imsi): Path<String>) -> Response {
    match db_delete_subscriber(&state.db_uri, &state.db_name, &imsi) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn subscriber_count(State(state): State<SharedState>) -> Response {
    match db_count_subscribers(&state.db_uri, &state.db_name) {
        Ok(count) => Json(serde_json::json!({ "count": count })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Database operations (using nextgcore-dbi patterns via direct MongoDB)
// ---------------------------------------------------------------------------

fn db_list_subscribers(uri: &str, db_name: &str) -> Result<Vec<Subscriber>> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let cursor = coll
        .find(mongodb::bson::doc! {}, None)
        .context("find failed")?;
    let mut subs = Vec::new();
    for doc_result in cursor {
        let doc = doc_result.context("cursor error")?;
        if let Ok(sub) = mongodb::bson::from_document::<Subscriber>(doc) {
            subs.push(sub);
        }
    }
    Ok(subs)
}

fn db_get_subscriber(uri: &str, db_name: &str, imsi: &str) -> Result<Option<Subscriber>> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    match coll.find_one(filter, None).context("find_one failed")? {
        Some(doc) => {
            let sub = mongodb::bson::from_document::<Subscriber>(doc)
                .context("deserialize subscriber")?;
            Ok(Some(sub))
        }
        None => Ok(None),
    }
}

fn db_create_subscriber(uri: &str, db_name: &str, sub: &Subscriber) -> Result<()> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let doc = mongodb::bson::to_document(sub).context("serialize subscriber")?;
    coll.insert_one(doc, None).context("insert failed")?;
    Ok(())
}

fn db_update_subscriber(uri: &str, db_name: &str, imsi: &str, sub: &Subscriber) -> Result<bool> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    let doc = mongodb::bson::to_document(sub).context("serialize subscriber")?;
    let result = coll
        .replace_one(filter, doc, None)
        .context("replace_one failed")?;
    Ok(result.modified_count > 0)
}

fn db_delete_subscriber(uri: &str, db_name: &str, imsi: &str) -> Result<bool> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    let result = coll.delete_one(filter, None).context("delete_one failed")?;
    Ok(result.deleted_count > 0)
}

fn db_count_subscribers(uri: &str, db_name: &str) -> Result<u64> {
    let client =
        mongodb::sync::Client::with_uri_str(uri).context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let count = coll
        .count_documents(mongodb::bson::doc! {}, None)
        .context("count failed")?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Embedded HTML dashboard
// ---------------------------------------------------------------------------

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextGCore - Subscriber Management</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-bottom:1px solid #334155;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
.header h1{font-size:1.5rem;font-weight:700;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .badge{background:#1e40af;color:#93c5fd;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.75rem}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.5rem}
.stat-card .label{color:#94a3b8;font-size:0.875rem;margin-bottom:0.5rem}
.stat-card .value{font-size:2rem;font-weight:700;color:#38bdf8}
.toolbar{display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap}
.toolbar input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:0.5rem 1rem;border-radius:6px;flex:1;min-width:200px}
.toolbar input:focus{outline:none;border-color:#38bdf8}
.btn{padding:0.5rem 1rem;border:none;border-radius:6px;cursor:pointer;font-weight:600;transition:all 0.2s}
.btn-primary{background:#2563eb;color:#fff}.btn-primary:hover{background:#1d4ed8}
.btn-danger{background:#dc2626;color:#fff}.btn-danger:hover{background:#b91c1c}
.btn-sm{padding:0.25rem 0.5rem;font-size:0.8rem}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
thead th{background:#334155;padding:0.75rem 1rem;text-align:left;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}
tbody td{padding:0.75rem 1rem;border-bottom:1px solid #1e293b}
tbody tr{border-bottom:1px solid #334155}
tbody tr:hover{background:#334155}
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.active{display:flex}
.modal{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:90%;max-width:600px;max-height:90vh;overflow-y:auto}
.modal h2{margin-bottom:1.5rem;color:#38bdf8}
.form-group{margin-bottom:1rem}
.form-group label{display:block;color:#94a3b8;font-size:0.875rem;margin-bottom:0.25rem}
.form-group input,.form-group select{width:100%;background:#0f172a;border:1px solid #334155;color:#e2e8f0;padding:0.5rem;border-radius:4px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.modal-actions{display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1.5rem}
.mono{font-family:'JetBrains Mono',monospace;font-size:0.85rem}
.empty{text-align:center;padding:3rem;color:#64748b}
</style>
</head>
<body>
<div class="header">
  <h1>NextGCore</h1>
  <span class="badge">Subscriber Management</span>
  <span class="badge" id="countBadge">Loading...</span>
</div>
<div class="container">
  <div class="stats" id="stats">
    <div class="stat-card"><div class="label">Total Subscribers</div><div class="value" id="totalCount">-</div></div>
    <div class="stat-card"><div class="label">Status</div><div class="value" style="font-size:1rem;color:#22c55e" id="dbStatus">Connecting...</div></div>
  </div>
  <div class="toolbar">
    <input type="text" id="searchInput" placeholder="Search by IMSI..." oninput="filterTable()">
    <button class="btn btn-primary" onclick="openAdd()">+ Add Subscriber</button>
  </div>
  <table>
    <thead><tr><th>IMSI</th><th>MSISDN</th><th>Key</th><th>SQN</th><th>AMF</th><th>Slices</th><th>Actions</th></tr></thead>
    <tbody id="subTable"></tbody>
  </table>
  <div class="empty" id="emptyMsg" style="display:none">No subscribers found. Click "+ Add Subscriber" to get started.</div>
</div>

<div class="modal-overlay" id="modal">
  <div class="modal">
    <h2 id="modalTitle">Add Subscriber</h2>
    <input type="hidden" id="editMode" value="add">
    <div class="form-group"><label>IMSI</label><input id="fImsi" class="mono" placeholder="001010000000001" maxlength="15"></div>
    <div class="form-group"><label>MSISDN (comma-separated)</label><input id="fMsisdn" placeholder="0000000001"></div>
    <div class="form-row">
      <div class="form-group"><label>K (hex, 32 chars)</label><input id="fK" class="mono" placeholder="blank on edit = keep stored key" maxlength="32"></div>
      <div class="form-group"><label>OPc (hex, 32 chars)</label><input id="fOPc" class="mono" placeholder="blank on edit = keep stored OPc" maxlength="32"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>AMF</label><input id="fAMF" class="mono" value="8000" maxlength="4"></div>
      <div class="form-group"><label>SQN</label><input id="fSQN" class="mono" value="" placeholder="auto"></div>
    </div>
    <h3 style="margin:1rem 0 0.5rem;color:#818cf8;font-size:0.95rem">Default Slice (SST/SD)</h3>
    <div class="form-row">
      <div class="form-group"><label>SST</label><input id="fSST" type="number" value="1" min="0" max="255"></div>
      <div class="form-group"><label>SD (hex, optional)</label><input id="fSD" class="mono" placeholder="000001"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>APN / DNN</label><input id="fDNN" value="internet"></div>
      <div class="form-group"><label>Session Type</label>
        <select id="fSessType"><option value="1">IPv4</option><option value="2">IPv6</option><option value="3">IPv4v6</option></select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>DL AMBR (Gbps)</label><input id="fDL" type="number" value="1" min="0"></div>
      <div class="form-group"><label>UL AMBR (Gbps)</label><input id="fUL" type="number" value="1" min="0"></div>
    </div>
    <div class="modal-actions">
      <button class="btn" style="background:#334155;color:#e2e8f0" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="saveSub()">Save</button>
    </div>
  </div>
</div>

<script>
const API='/api/subscribers';
let allSubs=[];

// Issue #118: /api requires a bearer token. Held in sessionStorage so it is gone
// when the tab closes and never written to localStorage or the URL.
function apiToken(){
  let t=sessionStorage.getItem('ngcToken');
  if(!t){t=prompt('API token for subscriber provisioning:')||'';if(t)sessionStorage.setItem('ngcToken',t)}
  return t;
}
function clearToken(){sessionStorage.removeItem('ngcToken')}
async function api(path,opts){
  const o=opts||{};
  o.headers=Object.assign({},o.headers||{},{'Authorization':'Bearer '+apiToken()});
  const r=await fetch(path,o);
  if(r.status===401){clearToken();throw new Error('Unauthorized - check the API token')}
  return r;
}

async function load(){
  try{
    const [subs,cnt]=await Promise.all([api(API).then(r=>r.json()),api(API+'/count').then(r=>r.json())]);
    allSubs=subs;
    document.getElementById('totalCount').textContent=cnt.count;
    document.getElementById('countBadge').textContent=cnt.count+' subscribers';
    document.getElementById('dbStatus').textContent='Connected';
    document.getElementById('dbStatus').style.color='#22c55e';
    renderTable(subs);
  }catch(e){
    document.getElementById('dbStatus').textContent='Error: '+e.message;
    document.getElementById('dbStatus').style.color='#ef4444';
  }
}

function renderTable(subs){
  const tb=document.getElementById('subTable');
  const em=document.getElementById('emptyMsg');
  if(!subs.length){tb.innerHTML='';em.style.display='block';return}
  em.style.display='none';
  tb.innerHTML=subs.map(s=>`<tr>
    <td class="mono">${s.imsi}</td>
    <td>${(s.msisdn||[]).join(', ')}</td>
    <td class="mono">${s.security.key_provisioned?'provisioned':'MISSING'}</td>
    <td class="mono">${s.security.sqn===undefined?'-':s.security.sqn}</td>
    <td class="mono">${s.security.amf||'8000'}</td>
    <td>${(s.slice||[]).map(sl=>'SST:'+sl.sst+(sl.sd?'/SD:'+sl.sd:'')).join(', ')||'-'}</td>
    <td><button class="btn btn-primary btn-sm" onclick='openEdit("${s.imsi}")'>Edit</button>
    <button class="btn btn-danger btn-sm" onclick='deleteSub("${s.imsi}")'>Delete</button></td>
  </tr>`).join('');
}

function filterTable(){
  const q=document.getElementById('searchInput').value.toLowerCase();
  renderTable(allSubs.filter(s=>s.imsi.toLowerCase().includes(q)));
}

function openAdd(){
  document.getElementById('editMode').value='add';
  document.getElementById('modalTitle').textContent='Add Subscriber';
  document.getElementById('fImsi').value='';document.getElementById('fImsi').disabled=false;
  document.getElementById('fMsisdn').value='';
  document.getElementById('fK').value='';document.getElementById('fOPc').value='';
  document.getElementById('fAMF').value='8000';document.getElementById('fSQN').value='';
  document.getElementById('fSST').value='1';document.getElementById('fSD').value='';
  document.getElementById('fDNN').value='internet';document.getElementById('fSessType').value='1';
  document.getElementById('fDL').value='1';document.getElementById('fUL').value='1';
  document.getElementById('modal').classList.add('active');
}

function openEdit(imsi){
  const s=allSubs.find(x=>x.imsi===imsi);if(!s)return;
  document.getElementById('editMode').value='edit';
  document.getElementById('modalTitle').textContent='Edit Subscriber';
  document.getElementById('fImsi').value=s.imsi;document.getElementById('fImsi').disabled=true;
  document.getElementById('fMsisdn').value=(s.msisdn||[]).join(',');
  // Issue #118: the API no longer returns k/opc, so these start EMPTY and an
  // empty submission leaves the stored keys untouched (key-preserving update).
  document.getElementById('fK').value='';document.getElementById('fOPc').value='';
  document.getElementById('fAMF').value=s.security.amf||'8000';document.getElementById('fSQN').value=s.security.sqn||'';
  const sl=(s.slice||[])[0]||{};
  document.getElementById('fSST').value=sl.sst||1;document.getElementById('fSD').value=sl.sd||'';
  const sess=(sl.session||[])[0]||{};
  document.getElementById('fDNN').value=sess.name||'internet';document.getElementById('fSessType').value=sess.session_type||1;
  const ambr=sess.ambr||{};
  document.getElementById('fDL').value=(ambr.downlink||{}).value||1;document.getElementById('fUL').value=(ambr.uplink||{}).value||1;
  document.getElementById('modal').classList.add('active');
}

function closeModal(){document.getElementById('modal').classList.remove('active')}

async function saveSub(){
  const mode=document.getElementById('editMode').value;
  const sub={
    imsi:document.getElementById('fImsi').value.trim(),
    msisdn:document.getElementById('fMsisdn').value.split(',').map(s=>s.trim()).filter(Boolean),
    security:{k:document.getElementById('fK').value.trim(),opc:document.getElementById('fOPc').value.trim(),
      amf:document.getElementById('fAMF').value.trim(),sqn:document.getElementById('fSQN').value.trim()},
    ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},status:0,
    slice:[{sst:parseInt(document.getElementById('fSST').value)||1,
      sd:document.getElementById('fSD').value.trim()||undefined,default_indicator:true,
      session:[{name:document.getElementById('fDNN').value.trim()||'internet',
        session_type:parseInt(document.getElementById('fSessType').value)||1,
        ambr:{downlink:{value:parseInt(document.getElementById('fDL').value)||1,unit:3},
              uplink:{value:parseInt(document.getElementById('fUL').value)||1,unit:3}},
        qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}]
  };
  if(!sub.imsi){alert('IMSI is required');return}
  // On add, K is mandatory. On edit, leaving K blank preserves the stored key.
  if(mode==='add'&&!sub.security.k){alert('K is required for a new subscriber');return}
  try{
    const h={'Content-Type':'application/json'};
    if(mode==='add'){await api(API,{method:'POST',headers:h,body:JSON.stringify(sub)})}
    else{await api(API+'/'+sub.imsi,{method:'PUT',headers:h,body:JSON.stringify(sub)})}
    closeModal();load();
  }catch(e){alert('Error: '+e.message)}
}

async function deleteSub(imsi){
  if(!confirm('Delete subscriber '+imsi+'?'))return;
  try{await api(API+'/'+imsi,{method:'DELETE'});load()}catch(e){alert('Error: '+e.message)}
}

load();
</script>
</body>
</html>
"##;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    log::info!("Starting NextGCore WebUI on {}:{}", args.listen, args.port);

    // Issue #118: resolve credentials BEFORE binding, so an unauthenticated
    // provisioning API never reaches the point of accepting a connection.
    let api_token = resolve_api_token(&args)?;
    let tls = resolve_tls(&args)?;

    let state: SharedState = Arc::new(AppState {
        db_uri: args.db_uri,
        db_name: args.db_name,
        api_token,
    });

    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", args.listen, args.port)
        .parse()
        .context("invalid listen address")?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind failed")?;

    match tls {
        Some(acceptor) => {
            log::info!("WebUI available at https://{addr}");
            serve_tls(listener, acceptor, app).await
        }
        None => {
            log::warn!(
                "INSECURE: serving the subscriber provisioning API over PLAINTEXT HTTP at \
                 http://{addr} (--insecure-dev). Key material and credentials cross the \
                 network in the clear."
            );
            axum::serve(listener, app).await.context("server error")
        }
    }
}

/// Build the provisioning router.
///
/// Split out of `main` so tests can drive the REAL router — including the auth
/// layer — instead of asserting against a hand-rolled copy of it.
///
/// Issue #118: `require_api_token` is layered on the `/api` routes only. `/` is
/// the dashboard shell, which carries no subscriber data and fetches everything
/// through `/api` with the operator's token.
fn build_router(state: SharedState) -> Router {
    let api = Router::new()
        .route(
            "/api/subscribers",
            get(list_subscribers).post(create_subscriber),
        )
        .route("/api/subscribers/count", get(subscriber_count))
        .route(
            "/api/subscribers/{imsi}",
            get(get_subscriber)
                .put(update_subscriber)
                .delete(delete_subscriber),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_api_token,
        ));

    Router::new()
        .route("/", get(serve_dashboard))
        .merge(api)
        // Issue #118: credentialed, so the previous `permissive()` (which allows
        // any origin) must not stay — a permissive CORS policy on a
        // token-authenticated provisioning API invites a hostile page to drive it
        // with a token the browser holds. Same-origin only; the dashboard this
        // binary serves is same-origin by construction.
        .layer(CorsLayer::new())
        .with_state(state)
}

/// Build a TLS acceptor, or `None` for `--insecure-dev`.
///
/// TS 33.117 §4.2.5.1: authentication material must not cross the network in
/// cleartext. Startup fails when TLS is neither configured nor explicitly waived,
/// and fails when only one of cert/key is given — a half-configured TLS setup
/// silently falling back to plaintext is exactly the outcome to avoid.
fn resolve_tls(args: &Args) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Ok(Some(build_tls_acceptor(cert, key)?)),
        (None, None) if args.insecure_dev => Ok(None),
        (None, None) => anyhow::bail!(
            "refusing to start: the subscriber provisioning API would serve key material \
             over plaintext HTTP. Supply --tls-cert and --tls-key, or pass --insecure-dev \
             for local development only."
        ),
        (Some(_), None) => anyhow::bail!("--tls-cert given without --tls-key"),
        (None, Some(_)) => anyhow::bail!("--tls-key given without --tls-cert"),
    }
}

/// Load a PEM certificate chain and private key into a rustls acceptor.
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<tokio_rustls::TlsAcceptor> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read --tls-cert {cert_path}"))?;
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificates from {cert_path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {cert_path}");
    }

    let key_pem =
        std::fs::read(key_path).with_context(|| format!("failed to read --tls-key {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .with_context(|| format!("failed to parse a private key from {key_path}"))?
        .with_context(|| format!("no private key found in {key_path}"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate/key pair")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Serve the router over TLS.
///
/// Hand-rolled because `axum::serve` takes a plaintext listener; this mirrors the
/// accept loop `nextgcore-sbi`'s server uses. A handshake failure is logged and
/// the connection dropped — one bad client must not take the listener down.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    app: Router,
) -> Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                log::warn!("accept failed: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let service = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("TLS handshake with {peer} failed: {e}");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        io,
                        hyper_util::service::TowerToHyperService::new(service),
                    )
                    .await
            {
                log::debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::{doc, Bson};

    fn good_subscriber() -> Subscriber {
        Subscriber {
            imsi: "999700000000001".to_string(),
            msisdn: vec![],
            security: SecurityContext {
                k: "465B5CE8B199B49FAA5F0A2EE238A6BC".to_string(),
                opc: "E8ED289DEBA952E4283B54E88E6D834D".to_string(),
                op: String::new(),
                amf: "8000".to_string(),
                sqn: 0,
            },
            ambr: Ambr::default(),
            slice: vec![],
            status: 0,
        }
    }

    /// The defect this issue is about: `$inc`/`$bit` are numeric-only Mongo
    /// operators, so `sqn` must land in BSON as an Int64. While it was a
    /// String the maintenance path errored and SQN_HE could never advance.
    #[test]
    fn sqn_serialises_as_bson_int64() {
        let mut sub = good_subscriber();
        sub.security.sqn = 42;
        let doc = mongodb::bson::to_document(&sub).expect("serialize");
        let security = doc.get_document("security").expect("security subdoc");
        match security.get("sqn") {
            Some(Bson::Int64(v)) => assert_eq!(*v, 42),
            other => panic!("sqn must serialise to BSON Int64, got {other:?}"),
        }
    }

    /// nextgcore-dbi reads the field with `get_i64`, so that exact call must
    /// succeed against what we write.
    #[test]
    fn stored_sqn_is_readable_via_get_i64() {
        let mut sub = good_subscriber();
        sub.security.sqn = 1_234_567;
        let doc = mongodb::bson::to_document(&sub).expect("serialize");
        let security = doc.get_document("security").expect("security subdoc");
        assert_eq!(security.get_i64("sqn").expect("get_i64"), 1_234_567);
    }

    /// Documents written by the previous build hold a String. They must still
    /// load: refusing them would turn a legacy record into a failed read.
    #[test]
    fn legacy_string_sqn_deserialises() {
        let legacy = doc! {
            "imsi": "999700000000001",
            "security": {
                "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                "opc": "E8ED289DEBA952E4283B54E88E6D834D",
                "amf": "8000",
                "sqn": "42",
            },
        };
        let sub: Subscriber = mongodb::bson::from_document(legacy).expect("legacy doc must load");
        assert_eq!(sub.security.sqn, 42);
    }

    #[test]
    fn int64_and_absent_sqn_deserialise() {
        let with_i64 = doc! {
            "imsi": "999700000000001",
            "security": {
                "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                "opc": "E8ED289DEBA952E4283B54E88E6D834D",
                "amf": "8000",
                "sqn": 99_i64,
            },
        };
        let sub: Subscriber = mongodb::bson::from_document(with_i64).expect("int64 doc");
        assert_eq!(sub.security.sqn, 99);

        let absent = doc! {
            "imsi": "999700000000001",
            "security": {
                "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                "opc": "E8ED289DEBA952E4283B54E88E6D834D",
                "amf": "8000",
            },
        };
        let sub: Subscriber = mongodb::bson::from_document(absent).expect("absent sqn defaults");
        assert_eq!(sub.security.sqn, 0);
    }

    /// An empty legacy string is "unset", not an error.
    #[test]
    fn empty_string_sqn_is_zero() {
        let d = doc! {
            "imsi": "999700000000001",
            "security": {
                "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                "opc": "E8ED289DEBA952E4283B54E88E6D834D",
                "amf": "8000",
                "sqn": "",
            },
        };
        let sub: Subscriber = mongodb::bson::from_document(d).expect("empty string sqn");
        assert_eq!(sub.security.sqn, 0);
    }

    /// A non-numeric string has no sensible reading, so it must not be
    /// silently coerced to 0 -- that would hide corruption.
    #[test]
    fn non_numeric_string_sqn_is_rejected() {
        let d = doc! {
            "imsi": "999700000000001",
            "security": {
                "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
                "opc": "E8ED289DEBA952E4283B54E88E6D834D",
                "amf": "8000",
                "sqn": "not-a-number",
            },
        };
        let r: Result<Subscriber, _> = mongodb::bson::from_document(d);
        assert!(r.is_err(), "a non-numeric sqn string must be an error");
    }

    /// The WebUI and the UDR must agree on which database holds subscribers.
    /// These drifted before: the WebUI defaulted to "open5gs" while dbi and the
    /// seed script used "nextgcore", so provisioning silently went nowhere.
    #[test]
    fn default_db_name_matches_dbi_fallback() {
        assert_eq!(DEFAULT_DB_NAME, "nextgcore");
        assert_eq!(
            DEFAULT_DB_NAME,
            nextgcore_dbi::types::NEXTGCORE_DEFAULT_DB_NAME
        );
        let args = Args::parse_from(["nextgcore-webui"]);
        assert_eq!(
            args.db_name,
            nextgcore_dbi::types::NEXTGCORE_DEFAULT_DB_NAME
        );
    }

    #[test]
    fn validation_accepts_a_good_subscriber() {
        assert!(validate_subscriber(&good_subscriber()).is_ok());
    }

    #[test]
    fn validation_rejects_malformed_imsi() {
        let mut sub = good_subscriber();
        sub.imsi = "9997".to_string();
        assert!(validate_subscriber(&sub).is_err(), "4-digit imsi");

        sub.imsi = "9997000000000012345".to_string();
        assert!(validate_subscriber(&sub).is_err(), "19-digit imsi");

        sub.imsi = "99970000000000X".to_string();
        assert!(validate_subscriber(&sub).is_err(), "non-digit imsi");
    }

    /// The case that motivated this: a mistyped key used to be persisted with
    /// the bad pairs dropped, and authentication then failed with no clue why.
    #[test]
    fn validation_rejects_malformed_key() {
        let mut sub = good_subscriber();
        sub.security.k = "465B5CE8B199B49FAA5F0A2EE238A6B".to_string(); // 31 chars
        assert!(validate_subscriber(&sub).is_err(), "31-char k");

        sub.security.k = "465B5CE8B199B49FAA5F0A2EE238A6ZZ".to_string(); // non-hex
        assert!(validate_subscriber(&sub).is_err(), "non-hex k");
    }

    #[test]
    fn validation_rejects_malformed_amf_and_requires_a_key_material() {
        let mut sub = good_subscriber();
        sub.security.amf = "800".to_string();
        assert!(validate_subscriber(&sub).is_err(), "3-char amf");

        let mut sub = good_subscriber();
        sub.security.opc = String::new();
        sub.security.op = String::new();
        assert!(
            validate_subscriber(&sub).is_err(),
            "neither opc nor op supplied"
        );
    }

    #[test]
    fn validation_bounds_sqn_to_48_bits() {
        let mut sub = good_subscriber();
        sub.security.sqn = nextgcore_dbi::types::NEXTGCORE_MAX_SQN as i64;
        assert!(validate_subscriber(&sub).is_ok(), "max 48-bit sqn is valid");

        sub.security.sqn = nextgcore_dbi::types::NEXTGCORE_MAX_SQN as i64 + 1;
        assert!(validate_subscriber(&sub).is_err(), "sqn beyond 48 bits");

        sub.security.sqn = -1;
        assert!(validate_subscriber(&sub).is_err(), "negative sqn");
    }

    #[test]
    fn validation_rejects_malformed_slice_sd() {
        let mut sub = good_subscriber();
        sub.slice = vec![SliceConfig {
            sst: 1,
            sd: Some("ZZZZZZ".to_string()),
            default_indicator: true,
            session: vec![],
        }];
        assert!(validate_subscriber(&sub).is_err(), "non-hex sd");
    }

    // =====================================================================
    // Issue #118: key material must never leave over the API, and /api must
    // be authenticated.
    // =====================================================================

    /// **The core #118 assertion.** The read projection cannot carry key
    /// material — asserted on the VALUES, not just the field names, so a nested
    /// or renamed leak is caught too.
    #[test]
    fn read_projection_never_carries_key_material() {
        let sub = good_subscriber();
        let k = sub.security.k.clone();
        let opc = sub.security.opc.clone();

        let json = serde_json::to_string(&SubscriberView::from(&sub)).expect("serialize view");

        // The values themselves must be absent. This is the assertion that
        // matters: field names can be renamed, the secret cannot be un-leaked.
        assert!(
            !json.contains(&k),
            "the permanent key K must not appear in an API response: {json}"
        );
        assert!(
            !json.contains(&opc),
            "OPc must not appear in an API response: {json}"
        );
        // Field names too, so a client cannot come to depend on them.
        for field in ["\"k\"", "\"opc\"", "\"op\""] {
            assert!(
                !json.contains(field),
                "{field} must not be a member of the API response: {json}"
            );
        }

        // What an operator legitimately still gets.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["imsi"], serde_json::json!(sub.imsi));
        assert_eq!(
            parsed["security"]["amf"],
            serde_json::json!(sub.security.amf)
        );
        assert_eq!(
            parsed["security"]["key_provisioned"],
            serde_json::json!(true),
            "provisioned-or-not is reported without revealing the value"
        );

        // A subscriber with no key reports so rather than lying.
        let mut keyless = good_subscriber();
        keyless.security.k = String::new();
        let json = serde_json::to_string(&SubscriberView::from(&keyless)).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed["security"]["key_provisioned"],
            serde_json::json!(false)
        );
    }

    /// **The assertion that actually guards the API surface.** The projection
    /// test above checks the TYPE; this checks the BYTES the handlers put on the
    /// wire, via the single builders every read path goes through. Reverting a
    /// handler to `Json(sub)` therefore fails a test rather than passing silently.
    #[tokio::test]
    async fn api_response_bytes_never_contain_key_material() {
        let sub = good_subscriber();
        let k = sub.security.k.clone();
        let opc = sub.security.opc.clone();

        async fn body_of(response: Response) -> String {
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("read body");
            String::from_utf8(bytes.to_vec()).expect("utf-8 body")
        }

        for (label, body) in [
            ("single", body_of(subscriber_response(&sub)).await),
            (
                "list",
                body_of(subscriber_list_response(std::slice::from_ref(&sub))).await,
            ),
        ] {
            assert!(
                !body.contains(&k),
                "the {label} response body must not contain K: {body}"
            );
            assert!(
                !body.contains(&opc),
                "the {label} response body must not contain OPc: {body}"
            );
            // ...and it is still a useful response.
            assert!(
                body.contains(&sub.imsi),
                "the {label} response must still identify the subscriber"
            );
            assert!(
                body.contains("key_provisioned"),
                "the {label} response should report provisioning state"
            );
        }
    }

    /// The `Subscriber` model itself must KEEP serialising key material — that is
    /// the MongoDB write path. This pins why the fix is a separate projection type
    /// rather than `#[serde(skip_serializing)]` on `SecurityContext`, which would
    /// have broken provisioning.
    #[test]
    fn the_db_model_still_serialises_key_material() {
        let sub = good_subscriber();
        let json = serde_json::to_string(&sub).expect("serialize model");
        assert!(
            json.contains(&sub.security.k),
            "the DB write path must still carry K, or provisioning cannot work"
        );
    }

    /// Issue #118: startup fails closed. An unauthenticated or plaintext
    /// provisioning API must not be reachable because a flag was forgotten.
    #[test]
    fn startup_refuses_to_run_insecure_by_default() {
        let base = || Args {
            db_uri: "mongodb://localhost:27017".to_string(),
            db_name: "nextgcore".to_string(),
            port: 3000,
            listen: "127.0.0.1".to_string(),
            api_token_file: None,
            tls_cert: None,
            tls_key: None,
            insecure_dev: false,
        };

        // The default listen address is loopback, not every interface.
        let parsed = Args::parse_from(["nextgcore-webui"]);
        assert_eq!(
            parsed.listen, "127.0.0.1",
            "the provisioning listener must not default to 0.0.0.0"
        );
        assert!(!parsed.insecure_dev, "insecure mode must be opt-in");

        // No token and no --insecure-dev → refuse to start.
        assert!(
            resolve_api_token(&base()).is_err(),
            "a missing API token must be a startup failure, not an open API"
        );
        // No TLS and no --insecure-dev → refuse to start.
        assert!(
            resolve_tls(&base()).is_err(),
            "missing TLS must be a startup failure"
        );

        // --insecure-dev is the ONLY way to get there.
        let mut dev = base();
        dev.insecure_dev = true;
        assert!(matches!(resolve_api_token(&dev), Ok(None)));
        assert!(matches!(resolve_tls(&dev), Ok(None)));

        // Half-configured TLS must not silently fall back to plaintext.
        let mut half = base();
        half.tls_cert = Some("/nonexistent/cert.pem".to_string());
        assert!(resolve_tls(&half).is_err(), "cert without key must fail");
        let mut half = base();
        half.tls_key = Some("/nonexistent/key.pem".to_string());
        assert!(resolve_tls(&half).is_err(), "key without cert must fail");

        // A placeholder-length token is not a credential.
        let dir = std::env::temp_dir();
        let short = dir.join(format!("ngc-webui-short-{}", std::process::id()));
        std::fs::write(&short, "secret").expect("write");
        let mut args = base();
        args.api_token_file = Some(short.to_string_lossy().into_owned());
        assert!(
            resolve_api_token(&args).is_err(),
            "a 6-character token must be rejected"
        );

        // A real token is accepted, and a trailing newline is not part of it.
        let good = dir.join(format!("ngc-webui-good-{}", std::process::id()));
        std::fs::write(&good, "0123456789abcdef0123456789abcdef\n").expect("write");
        let mut args = base();
        args.api_token_file = Some(good.to_string_lossy().into_owned());
        assert_eq!(
            resolve_api_token(&args).expect("valid token").as_deref(),
            Some("0123456789abcdef0123456789abcdef"),
        );

        let _ = std::fs::remove_file(short);
        let _ = std::fs::remove_file(good);
    }

    /// Constant-time comparison still has to be a CORRECT comparison.
    #[test]
    fn secret_eq_matches_only_equal_secrets() {
        assert!(secret_eq("0123456789abcdef", "0123456789abcdef"));
        assert!(!secret_eq("0123456789abcdef", "0123456789abcdee"));
        assert!(!secret_eq("0123456789abcdef", "0123456789abcde"));
        assert!(!secret_eq("", "x"));
        assert!(secret_eq("", ""));
    }

    // ── the auth layer, driven through the REAL router ────────────────────
    //
    // The 401 is produced by middleware BEFORE any handler runs, so these need
    // no MongoDB — which is exactly why the unauthenticated case is assertable
    // in CI while the DB-backed happy path is not.

    /// Send a raw HTTP/1.1 request and return the status line. Raw TCP rather
    /// than an HTTP client so no new dependency is added for two tests.
    fn http_status(port: u16, request: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        stream.flush().expect("flush");
        let mut buf = Vec::new();
        // Connection: close, so read_to_end terminates.
        let _ = stream.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    async fn serve_test_router(api_token: Option<String>) -> u16 {
        let state: SharedState = Arc::new(AppState {
            // Port 1 so any handler that DID run cannot reach a real database,
            // with the selection timeouts bounded: `db_*` uses the BLOCKING
            // mongodb::sync client from inside an async handler, so an
            // unreachable host with the 30 s default would stall the test.
            db_uri: "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=150&connectTimeoutMS=150"
                .to_string(),
            db_name: "nextgcore-test".to_string(),
            api_token,
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let app = build_router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // Let the accept loop reach the await point.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        port
    }

    /// **Acceptance criterion 1.** Every `/api/subscribers*` route rejects a
    /// request with no valid credential — including the write verbs, which is
    /// where an unauthenticated caller could otherwise overwrite key material.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unauthenticated_api_requests_are_rejected() {
        let port = serve_test_router(Some(TEST_TOKEN.to_string())).await;

        let cases = [
            "GET /api/subscribers",
            "GET /api/subscribers/count",
            "GET /api/subscribers/001010000000001",
            "POST /api/subscribers",
            "PUT /api/subscribers/001010000000001",
            "DELETE /api/subscribers/001010000000001",
        ];
        for case in cases {
            let request =
                format!("{case} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let status = http_status(port, &request);
            assert!(
                status.contains("401"),
                "{case} without a token must be 401, got {status:?}"
            );
        }

        // A wrong token is equally rejected...
        let status = http_status(
            port,
            "GET /api/subscribers HTTP/1.1\r\nHost: localhost\r\n\
             Authorization: Bearer wrong-token-wrong-token\r\nConnection: close\r\n\r\n",
        );
        assert!(
            status.contains("401"),
            "a wrong token must be 401: {status:?}"
        );

        // ...as is a non-Bearer scheme carrying the right secret.
        let status = http_status(
            port,
            &format!(
                "GET /api/subscribers HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Basic {TEST_TOKEN}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            status.contains("401"),
            "only the Bearer scheme is accepted: {status:?}"
        );

        // The CORRECT token passes the gate. It then fails at the unreachable
        // database (500), which is the proof it got past authentication — the
        // point is that it is NOT 401.
        let status = http_status(
            port,
            &format!(
                "GET /api/subscribers HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {TEST_TOKEN}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(
            !status.contains("401"),
            "the correct token must pass the auth layer, got {status:?}"
        );
    }

    /// The dashboard shell stays reachable without a token — it carries no
    /// subscriber data and fetches everything through the authenticated `/api`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dashboard_shell_is_not_behind_the_api_token() {
        let port = serve_test_router(Some(TEST_TOKEN.to_string())).await;
        let status = http_status(
            port,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert!(
            status.contains("200"),
            "the dashboard shell must still load, got {status:?}"
        );
    }

    /// The embedded dashboard must not have been left reading fields the API no
    /// longer returns, and must send the token on every call it makes.
    #[test]
    fn dashboard_matches_the_projected_api_shape() {
        let html = DASHBOARD_HTML;

        // It used to render `s.security.k.substring(0,8)` and prefill the edit
        // form from `s.security.k`, both of which would now throw on an undefined
        // field. Matched precisely: a bare `s.security.k` prefix-matches the
        // legitimate `s.security.key_provisioned`.
        assert!(
            !html.contains("s.security.k.substring"),
            "the dashboard must not render security.k -- the API no longer returns it"
        );
        assert!(
            !html.contains("value=s.security.k;"),
            "the edit form must not prefill K from the API response"
        );
        assert!(
            !html.contains("s.security.opc"),
            "the dashboard must not read security.opc"
        );
        assert!(
            html.contains("key_provisioned"),
            "the dashboard should show whether a key is provisioned"
        );

        // Every API call goes through the token-attaching helper, so none can
        // silently regress to a bare fetch of /api.
        assert!(
            !html.contains("fetch(API"),
            "API calls must go through api(), which attaches the bearer token"
        );
        assert!(html.contains("'Authorization':'Bearer '+apiToken()"));
    }
}

/// Issue #118: CI-enforced guards on the **shipped artefacts outside this crate**
/// — the legacy Node UI and the MongoDB init script.
///
/// WHY THESE ARE SOURCE-LEVEL ASSERTIONS. `webui/` has no test framework (no
/// `devDependencies`, no `test` script) and the CI workflow never installs Node or
/// runs anything under `webui/`, so a Node unit test would not be executed by any
/// gate. `cargo test --workspace` IS the gate, so these run there.
///
/// For a "this credential must not exist in the shipped artefact" property that is
/// arguably the better shape anyway: the risk is a default credential coming BACK,
/// and grepping the artefact catches that whether or not a server can be booted in
/// CI. What they cannot do is prove runtime behaviour — see the issue notes.
#[cfg(test)]
mod shipped_artefact_guards {
    /// Repository root, from this crate's manifest directory
    /// (`<root>/src/bins/nextgcore-webui`).
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("crate is at <root>/src/bins/nextgcore-webui")
            .to_path_buf()
    }

    fn read(relative: &str) -> String {
        let path = repo_root().join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    /// Read a JS file with comments stripped.
    ///
    /// These guards assert that dangerous *code* is absent, so they must not trip
    /// over prose that names the very pattern being forbidden — the comments
    /// explaining why `change-me` was removed necessarily contain the literal.
    /// Stripping is deliberately naive (no string-literal awareness); a false PASS
    /// is impossible, because stripping only ever removes text the assertions are
    /// searching for.
    fn read_code(relative: &str) -> String {
        let source = read(relative);
        let mut out = String::with_capacity(source.len());
        let mut rest = source.as_str();
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            match rest[start + 2..].find("*/") {
                Some(end) => rest = &rest[start + 2 + end + 2..],
                None => {
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out.lines()
            .map(|line| match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// No predefined credential may ship (TS 33.117 §4.2.3.4.2.2,
    /// TR 33.926 §5.3.6.8). The `admin`/`1423` account used to be created
    /// unconditionally by the Mongo init script — which the shipped
    /// docker-compose stack mounts — and again by a dev-mode auto-register.
    #[test]
    fn no_default_admin_credential_is_shipped() {
        let mongo_init = read_code("docs/assets/webui/mongo-init.js");
        // The bcrypt hash of "1423" that used to be inserted.
        assert!(
            !mongo_init.contains("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"),
            "mongo-init.js must not seed a default admin password hash"
        );
        assert!(
            !mongo_init.contains("db.accounts.insertOne"),
            "mongo-init.js must not insert any account; the first admin is an \
             explicit provisioning step"
        );

        let server = read_code("webui/server/index.js");
        assert!(
            !server.contains("Account.register(newAccount"),
            "the dev-mode auto-registration of a default admin must stay removed"
        );
        assert!(
            !server.contains("'1423'"),
            "no hardcoded password may remain in the server entry point"
        );
    }

    /// The JWT signing/verification secret must have no default. With
    /// `|| 'change-me'` in place an attacker could sign
    /// `{user:{roles:['admin']}}` themselves and pass the `/api/db` gate without
    /// any account at all.
    #[test]
    fn the_jwt_secret_has_no_shipped_default() {
        for file in [
            "webui/server/routes/auth.js",
            "webui/server/routes/index.js",
        ] {
            let source = read_code(file);
            assert!(
                !source.contains("'change-me'"),
                "{file} must not fall back to a well-known signing secret"
            );
            assert!(
                !source.contains("JWT_SECRET_KEY ||"),
                "{file} must not default JWT_SECRET_KEY to anything"
            );
            assert!(
                source.contains("loadJwtSecret()"),
                "{file} must resolve the secret through the fail-fast loader"
            );
        }

        // The loader itself refuses the historical default and requires a real
        // length, and does so at require time so the server cannot start.
        let loader = read_code("webui/server/lib/jwt-secret.js");
        assert!(
            loader.contains("'change-me'"),
            "the loader must reject 'change-me' by name"
        );
        assert!(
            loader.contains("throw new Error"),
            "a bad secret must throw, not warn"
        );
        assert!(
            loader.contains("MIN_LENGTH"),
            "a length floor must be enforced"
        );
    }

    /// The session cookie must not travel in cleartext or be script-readable
    /// (TS 33.117 §4.2.5.1). `httpOnly` used to sit on the session options object
    /// rather than inside `cookie`, where express-session reads it, so it had no
    /// effect; `secure` was absent entirely.
    #[test]
    fn the_session_cookie_is_hardened() {
        let server = read_code("webui/server/index.js");
        let cookie_block = server
            .split_once("cookie: {")
            .expect("a cookie configuration block")
            .1
            .split_once('}')
            .expect("a closed cookie block")
            .0;

        for attribute in ["httpOnly: true", "sameSite:", "secure:"] {
            assert!(
                cookie_block.contains(attribute),
                "the session cookie must set {attribute} -- block was: {cookie_block}"
            );
        }
        // Secure must be the default, with only an explicit opt-out.
        assert!(
            cookie_block.contains("WEBUI_INSECURE_DEV !== '1'"),
            "`secure` must default to true and require an explicit opt-out"
        );
    }
}
