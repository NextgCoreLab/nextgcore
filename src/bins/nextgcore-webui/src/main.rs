//! NextGCore WebUI - Subscriber Management Dashboard
//!
//! Provides a web-based interface for managing 5G subscribers in the UDR/MongoDB backend.
//! Supports CRUD operations on subscriber profiles (IMSI, K, OPc, AMF, SQN, slice config).
//!
//! # Usage
//! ```bash
//! nextgcore-webui --db-uri mongodb://localhost:27017 --db-name open5gs --port 3000
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "nextgcore-webui", about = "NextGCore Subscriber Management WebUI")]
struct Args {
    /// MongoDB connection URI
    #[arg(long, default_value = "mongodb://localhost:27017")]
    db_uri: String,

    /// MongoDB database name
    #[arg(long, default_value = "open5gs")]
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
    #[serde(default)]
    pub sqn: String,
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

fn default_bitrate() -> u64 { 1 }
fn default_unit() -> u8 { 3 }

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

fn default_slice_name() -> bool { true }

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

fn default_qci() -> u8 { 9 }

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

fn default_priority() -> u8 { 8 }

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

async fn get_subscriber(
    State(state): State<SharedState>,
    Path(imsi): Path<String>,
) -> Response {
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
    if sub.imsi.is_empty() || sub.security.k.is_empty() {
        return (StatusCode::BAD_REQUEST, "imsi and security.k are required").into_response();
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
    match db_update_subscriber(&state.db_uri, &state.db_name, &imsi, &sub) {
        Ok(true) => Json(sub).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_subscriber(
    State(state): State<SharedState>,
    Path(imsi): Path<String>,
) -> Response {
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
// Database operations (using ogs-dbi patterns via direct MongoDB)
// ---------------------------------------------------------------------------

fn db_list_subscribers(uri: &str, db_name: &str) -> Result<Vec<Subscriber>> {
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let cursor = coll.find(mongodb::bson::doc! {}).context("find failed")?;
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
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    match coll.find_one(filter).context("find_one failed")? {
        Some(doc) => {
            let sub = mongodb::bson::from_document::<Subscriber>(doc)
                .context("deserialize subscriber")?;
            Ok(Some(sub))
        }
        None => Ok(None),
    }
}

fn db_create_subscriber(uri: &str, db_name: &str, sub: &Subscriber) -> Result<()> {
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let doc = mongodb::bson::to_document(sub).context("serialize subscriber")?;
    coll.insert_one(doc).context("insert failed")?;
    Ok(())
}

fn db_update_subscriber(
    uri: &str,
    db_name: &str,
    imsi: &str,
    sub: &Subscriber,
) -> Result<bool> {
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    let doc = mongodb::bson::to_document(sub).context("serialize subscriber")?;
    let result = coll
        .replace_one(filter, doc)
        .context("replace_one failed")?;
    Ok(result.modified_count > 0)
}

fn db_delete_subscriber(uri: &str, db_name: &str, imsi: &str) -> Result<bool> {
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let filter = mongodb::bson::doc! { "imsi": imsi };
    let result = coll.delete_one(filter).context("delete_one failed")?;
    Ok(result.deleted_count > 0)
}

fn db_count_subscribers(uri: &str, db_name: &str) -> Result<u64> {
    let client = mongodb::sync::Client::with_uri_str(uri)
        .context("failed to connect to MongoDB")?;
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>("subscribers");

    let count = coll.count_documents(mongodb::bson::doc! {}).context("count failed")?;
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
        .route("/api/subscribers", get(list_subscribers).post(create_subscriber))
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

    log::info!("WebUI available at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.context("bind failed")?;
    axum::serve(listener, app)
        .await
        .context("server error")?;

    Ok(())
}
