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

    /// HTTP listen address
    #[arg(long, default_value = "0.0.0.0")]
    listen: String,
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
}

type SharedState = Arc<AppState>;

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

async fn list_subscribers(State(state): State<SharedState>) -> Response {
    match db_list_subscribers(&state.db_uri, &state.db_name) {
        Ok(subs) => Json(subs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_subscriber(State(state): State<SharedState>, Path(imsi): Path<String>) -> Response {
    match db_get_subscriber(&state.db_uri, &state.db_name, &imsi) {
        Ok(Some(sub)) => Json(sub).into_response(),
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
        Ok(()) => (StatusCode::CREATED, Json(sub)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_subscriber(
    State(state): State<SharedState>,
    Path(imsi): Path<String>,
    Json(sub): Json<Subscriber>,
) -> Response {
    // Update validates too: an update writes the same document shape, so
    // skipping it here would leave a hole straight to the create-path defect.
    if let Err(e) = validate_subscriber(&sub) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    match db_update_subscriber(&state.db_uri, &state.db_name, &imsi, &sub) {
        Ok(true) => Json(sub).into_response(),
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
    <thead><tr><th>IMSI</th><th>MSISDN</th><th>K</th><th>OPc</th><th>AMF</th><th>Slices</th><th>Actions</th></tr></thead>
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
      <div class="form-group"><label>K (hex, 32 chars)</label><input id="fK" class="mono" placeholder="465B5CE8B199B49FAA5F0A2EE238A6BC" maxlength="32"></div>
      <div class="form-group"><label>OPc (hex, 32 chars)</label><input id="fOPc" class="mono" placeholder="E8ED289DEBA952E4283B54E88E6183CA" maxlength="32"></div>
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

async function load(){
  try{
    const [subs,cnt]=await Promise.all([fetch(API).then(r=>r.json()),fetch(API+'/count').then(r=>r.json())]);
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
    <td class="mono">${s.security.k.substring(0,8)}...</td>
    <td class="mono">${(s.security.opc||'').substring(0,8)||'-'}...</td>
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
  document.getElementById('fK').value=s.security.k;document.getElementById('fOPc').value=s.security.opc||'';
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
  if(!sub.imsi||!sub.security.k){alert('IMSI and K are required');return}
  try{
    if(mode==='add'){await fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(sub)})}
    else{await fetch(API+'/'+sub.imsi,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(sub)})}
    closeModal();load();
  }catch(e){alert('Error: '+e.message)}
}

async function deleteSub(imsi){
  if(!confirm('Delete subscriber '+imsi+'?'))return;
  try{await fetch(API+'/'+imsi,{method:'DELETE'});load()}catch(e){alert('Error: '+e.message)}
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

    let state: SharedState = Arc::new(AppState {
        db_uri: args.db_uri,
        db_name: args.db_name,
    });

    let app = Router::new()
        .route("/", get(serve_dashboard))
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
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.listen, args.port)
        .parse()
        .context("invalid listen address")?;

    log::info!("WebUI available at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind failed")?;
    axum::serve(listener, app).await.context("server error")?;

    Ok(())
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
}
