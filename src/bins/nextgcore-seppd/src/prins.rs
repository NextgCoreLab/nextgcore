//! PRINS - PRotection of attributes at the Inter-PLMN N32 interface
//!
//! Implements N32-f message protection per TS 29.573 sec 6.3 and
//! TS 33.501 sec 13.2:
//!
//! - `DataToIntegrityProtectBlock` (metaData / requestLine / headers /
//!   payload with `encBlockIndex` references) travels as the JWE AAD
//! - `DataToIntegrityProtectAndCipherBlock` (`dataToEncrypt` array) is the
//!   JWE plaintext (alg="dir", enc="A256GCM")
//! - `modificationsBlock` is a chain of flattened JWS objects; the first
//!   entry is created by the sending SEPP over the JWE tag, each IPX
//!   modification appends a JWS whose payload references the previous tag
//! - decode/verify failures map onto `N32fErrorType` for the
//!   `/n32c-handshake/v1/n32f-error` report (TS 29.573 sec 6.1.5.4)
//!
//! Session keys are per-peer, established during the N32-c
//! exchange-params handshake (see `n32c_handler::derive_n32f_key_material`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::context::PlmnId;
use crate::jose::{self, b64url_decode, b64url_encode, FlatJwe, FlatJws, JoseError, JweEnc};
use crate::n32c_handler::{N32fDirection, N32fKeyMaterial, N32fRole};

// ============================================================================
// Asymmetric (ES256) identity key store (TS 33.501 §13.2.4.6)
//
// The SEPP has a single asymmetric identity used to sign the first
// modificationsBlock entry of every message it originates. Peer-SEPP and
// IPX public keys are registered by identity FQDN so received
// modificationsBlock entries can be verified against the correct key.
// ============================================================================

struct Es256KeyStore {
    /// This SEPP's own ES256 signing key (its asymmetric identity)
    local_signing_key: Option<Arc<SigningKey>>,
    /// Registered ES256 public keys of peers/IPX, keyed by identity FQDN
    verifying_keys: HashMap<String, VerifyingKey>,
}

fn es256_store() -> &'static RwLock<Es256KeyStore> {
    static STORE: OnceLock<RwLock<Es256KeyStore>> = OnceLock::new();
    STORE.get_or_init(|| {
        RwLock::new(Es256KeyStore {
            local_signing_key: None,
            verifying_keys: HashMap::new(),
        })
    })
}

/// Install this SEPP's own ES256 signing key (its asymmetric identity for
/// signing modificationsBlock entries). Loaded from PEM at startup.
pub fn set_local_signing_key(key: SigningKey) {
    if let Ok(mut store) = es256_store().write() {
        store.local_signing_key = Some(Arc::new(key));
    }
}

/// Get this SEPP's own ES256 signing key, if configured.
pub fn local_signing_key() -> Option<Arc<SigningKey>> {
    es256_store()
        .read()
        .ok()
        .and_then(|s| s.local_signing_key.clone())
}

/// Register a peer/IPX ES256 public key under its identity FQDN.
pub fn register_verifying_key(identity: impl Into<String>, key: VerifyingKey) {
    if let Ok(mut store) = es256_store().write() {
        store.verifying_keys.insert(identity.into(), key);
    }
}

/// Snapshot of all registered verifying keys (for building a PrinsContext).
pub fn all_verifying_keys() -> HashMap<String, VerifyingKey> {
    es256_store()
        .read()
        .map(|s| s.verifying_keys.clone())
        .unwrap_or_default()
}

/// Generate a fresh ES256 identity keypair, install the private half as this
/// SEPP's local signing key, and return the public key (for tests / when no
/// PEM key is provisioned). Self-signed asymmetric identity.
pub fn generate_local_identity() -> VerifyingKey {
    use p256::elliptic_curve::rand_core::OsRng;
    let sk = SigningKey::random(&mut OsRng);
    let vk = *sk.verifying_key();
    set_local_signing_key(sk);
    vk
}

// ============================================================================
// N32-f SEQ counters + anti-replay windows (TS 33.501 §13.2.4.4.1, sepp-02)
//
// Nonce = IV salt(8) || SEQ(32-bit). SEQ starts at 0 and increments per
// encryption, with a separate counter per IV salt (i.e. per (N32-f context,
// originator role, direction)). The receiver reads SEQ back from the JWE nonce
// and runs a sliding-window anti-replay check. These stores are keyed by the
// canonical N32-f context id (`kid`) so they persist across the per-message
// PrinsContext rebuilds (`build_prins_context`).
// ============================================================================

/// Store key for a (context, originator role, direction) sequence space.
fn seq_key(kid: &str, originator: N32fRole, dir: N32fDirection) -> String {
    format!("{kid}|{originator:?}|{dir:?}")
}

fn send_seq_counters() -> &'static RwLock<HashMap<String, Arc<AtomicU32>>> {
    static S: OnceLock<RwLock<HashMap<String, Arc<AtomicU32>>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Next SEQ for the (kid, originator, direction) sequence space (starts at 0).
/// Errors when the 32-bit space is exhausted (force rekey / new context).
fn next_send_seq(kid: &str, originator: N32fRole, dir: N32fDirection) -> Result<u32, JoseError> {
    let key = seq_key(kid, originator, dir);
    let counter = {
        let mut map = send_seq_counters()
            .write()
            .map_err(|_| JoseError::Crypto("N32-f SEQ store poisoned".into()))?;
        map.entry(key)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone()
    };
    let seq = counter.fetch_add(1, Ordering::SeqCst);
    if seq == u32::MAX {
        return Err(JoseError::Crypto(
            "N32-f SEQ space exhausted; rekey required".into(),
        ));
    }
    Ok(seq)
}

fn recv_replay_windows() -> &'static RwLock<HashMap<String, Arc<Mutex<ReplayWindow>>>> {
    static S: OnceLock<RwLock<HashMap<String, Arc<Mutex<ReplayWindow>>>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 64-entry sliding anti-replay window (IPsec/RFC 6479 style). `high` is the
/// largest accepted SEQ; bit `high - seq` of `bitmap` marks an accepted SEQ
/// within the window.
struct ReplayWindow {
    high: Option<u32>,
    bitmap: u64,
}

impl ReplayWindow {
    const WIDTH: u32 = 64;

    fn new() -> Self {
        Self {
            high: None,
            bitmap: 0,
        }
    }

    /// Accept `seq` if it is new and within the window, committing it; reject a
    /// duplicate or a SEQ older than the window.
    fn check_and_commit(&mut self, seq: u32) -> Result<(), String> {
        match self.high {
            None => {
                self.high = Some(seq);
                self.bitmap = 1; // bit 0 = the high water mark itself
                Ok(())
            }
            Some(high) if seq > high => {
                let shift = seq - high;
                self.bitmap = if shift >= Self::WIDTH {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.high = Some(seq);
                Ok(())
            }
            Some(high) => {
                let diff = high - seq;
                if diff >= Self::WIDTH {
                    return Err(format!(
                        "N32-f SEQ {seq} is older than the replay window (high {high})"
                    ));
                }
                let bit = 1u64 << diff;
                if self.bitmap & bit != 0 {
                    return Err(format!("N32-f SEQ {seq} replayed"));
                }
                self.bitmap |= bit;
                Ok(())
            }
        }
    }
}

// ============================================================================
// Data-type / protection-policy profiles (TS 29.573 sec 6.1.5.3.4)
// ============================================================================

/// Data-type profile defining which IEs to protect for a given API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeProfile {
    /// Profile identifier
    pub id: String,
    /// API service name this profile applies to
    pub service_name: String,
    /// IEs that must be encrypted (JSON paths into the body)
    pub encrypt_ies: Vec<IeDescriptor>,
}

/// Descriptor for an information element to protect
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IeDescriptor {
    /// Location: "BODY", "HEADER", or "URI_PARAM"
    pub location: String,
    /// RFC 6901 JSON Pointer into the body (e.g., "/supi", "/a/supi")
    pub path: String,
}

/// Modification policy: which IE paths an intermediary (or peer) is
/// allowed to modify via the modificationsBlock JSON-Patch operations.
#[derive(Debug, Clone, Default)]
pub struct ModificationPolicy {
    /// JSON paths that may be modified (empty = nothing may be modified)
    pub allowed_paths: Vec<String>,
}

/// PRINS security context for an established N32-f connection.
///
/// The symmetric `session_key` is used **only** for the JWE
/// (confidentiality + integrity of the protected payload). The
/// modificationsBlock JWS chain is signed/verified with *asymmetric* keys
/// (TS 33.501 §13.2.4.6): each SEPP/IPX signs its own entry with its
/// private key, and every entry is verified against the registered public
/// key for the entity that created it.
#[derive(Clone)]
pub struct PrinsContext {
    /// N32-f context ID allocated by the local SEPP (peer puts this into
    /// the metaData of messages it sends to us)
    pub local_context_id: String,
    /// N32-f context ID allocated by the peer SEPP (we put this into the
    /// metaData of messages we send to the peer)
    pub peer_context_id: String,
    /// The full N32-f key hierarchy (TS 33.501 §13.2.4.4.1): four A256GCM
    /// session keys + four IV salts, selected by role + direction. Reserved
    /// for the JWE only (never the modificationsBlock JWS).
    pub key_material: N32fKeyMaterial,
    /// This SEPP's N32-c role; selects which key set we use to PROTECT the
    /// messages we originate (the peer's role is its `opposite`).
    pub role: N32fRole,
    /// Key identifier (kid) for the session key
    pub kid: String,
    /// This SEPP's FQDN (JWS identity of locally created modification entries)
    pub local_fqdn: String,
    /// This SEPP's asymmetric (ES256) signing key, used to sign the first
    /// modificationsBlock entry. `None` => this SEPP cannot originate
    /// PRINS-protected messages with a signed modifications chain.
    pub local_signing_key: Option<Arc<SigningKey>>,
    /// Registered ES256 public keys of peers/IPX intermediaries, keyed by
    /// their identity FQDN (== the JWS `kid` / modificationsBlock identity).
    /// A modificationsBlock entry is rejected unless the signer's public
    /// key is registered here.
    pub peer_verifying_keys: HashMap<String, VerifyingKey>,
    /// Data-type profiles agreed during the N32-c handshake
    pub profiles: Vec<DataTypeProfile>,
    /// Modification policy agreed during the N32-c handshake
    pub modification_policy: ModificationPolicy,
    /// Negotiated JWE content-encryption profile (sepp-12): A128GCM or A256GCM.
    /// The session-key length follows it (16 vs 32 octets of `key_material`).
    pub jwe_enc: JweEnc,
    /// This SEPP's serving PLMN-IDs, stamped into the metaData of messages it
    /// originates (sepp-09). Empty => no PLMN stamped (backward compatible).
    pub local_plmn_ids: Vec<PlmnId>,
    /// PLMN-IDs bound to this N32-f context (the peer's serving PLMNs learned
    /// at handshake). On receive, the message's claimed sender PLMN-ID must be
    /// one of these (sepp-09). Empty => the consistency check is skipped.
    pub peer_plmn_ids: Vec<PlmnId>,
}

impl std::fmt::Debug for PrinsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrinsContext")
            .field("local_context_id", &self.local_context_id)
            .field("peer_context_id", &self.peer_context_id)
            .field("kid", &self.kid)
            .field("local_fqdn", &self.local_fqdn)
            .field("has_local_signing_key", &self.local_signing_key.is_some())
            .field(
                "registered_verifying_keys",
                &self.peer_verifying_keys.keys().collect::<Vec<_>>(),
            )
            .field("profiles", &self.profiles)
            .field("modification_policy", &self.modification_policy)
            .finish()
    }
}

impl PrinsContext {
    pub fn new(
        local_context_id: impl Into<String>,
        peer_context_id: impl Into<String>,
        key_material: N32fKeyMaterial,
        role: N32fRole,
        kid: impl Into<String>,
        local_fqdn: impl Into<String>,
    ) -> Self {
        let mut ctx = Self {
            local_context_id: local_context_id.into(),
            peer_context_id: peer_context_id.into(),
            key_material,
            role,
            kid: kid.into(),
            local_fqdn: local_fqdn.into(),
            local_signing_key: None,
            peer_verifying_keys: HashMap::new(),
            profiles: Vec::new(),
            modification_policy: ModificationPolicy::default(),
            jwe_enc: JweEnc::A256Gcm,
            local_plmn_ids: Vec::new(),
            peer_plmn_ids: Vec::new(),
        };
        ctx.add_default_profiles();
        ctx
    }

    /// The (session key, IV salt) this SEPP uses to PROTECT a message it
    /// originates in `direction` (selected by its own role).
    pub fn protect_key(&self, direction: N32fDirection) -> (&[u8; 32], &[u8; 8]) {
        self.key_material.select(self.role, direction)
    }

    /// The (session key, IV salt) this SEPP uses to UNPROTECT a message the
    /// peer originated in `direction` (selected by the peer's role).
    pub fn unprotect_key(&self, direction: N32fDirection) -> (&[u8; 32], &[u8; 8]) {
        self.key_material.select(self.role.opposite(), direction)
    }

    /// Allocate the next SEQ for a message this SEPP ORIGINATES in `direction`
    /// (sepp-02). SEQ starts at 0 and increments per encryption, with a
    /// separate counter per (N32-f context, originator role, direction) — i.e.
    /// per IV salt. Errors when the 32-bit SEQ space is exhausted (rekey).
    pub fn next_send_seq(&self, direction: N32fDirection) -> Result<u32, JoseError> {
        next_send_seq(&self.kid, self.role, direction)
    }

    /// Anti-replay check + commit for a received message the PEER originated in
    /// `direction` (sepp-02). Rejects a SEQ already seen or older than the
    /// sliding window. Must be called only AFTER the JWE AEAD authenticates the
    /// message, so a tampered message never advances the window.
    pub fn check_recv_seq(&self, direction: N32fDirection, seq: u32) -> Result<(), String> {
        let key = seq_key(&self.kid, self.role.opposite(), direction);
        let win = {
            let mut map = recv_replay_windows()
                .write()
                .map_err(|_| "N32-f replay-window store poisoned".to_string())?;
            map.entry(key)
                .or_insert_with(|| Arc::new(Mutex::new(ReplayWindow::new())))
                .clone()
        };
        let mut w = win
            .lock()
            .map_err(|_| "N32-f replay window poisoned".to_string())?;
        w.check_and_commit(seq)
    }

    /// Install this SEPP's asymmetric (ES256) signing key for originating
    /// PRINS-protected messages.
    pub fn with_signing_key(mut self, key: Arc<SigningKey>) -> Self {
        self.local_signing_key = Some(key);
        self
    }

    /// Register a peer/IPX ES256 public key under its identity FQDN. The
    /// modificationsBlock JWS for that identity is verified against it.
    pub fn register_verifying_key(&mut self, identity: impl Into<String>, key: VerifyingKey) {
        self.peer_verifying_keys.insert(identity.into(), key);
    }

    /// Add the default data-type profiles for common 5G APIs. These are this
    /// SEPP's **local protection-policy capability** (advertised in
    /// exchange-params); the runtime profile set actually used to protect
    /// messages is driven by the NEGOTIATED `dataTypeEncPolicy`
    /// (see `n32c_handler::negotiate_protection_policy` / `build_prins_context`).
    pub fn add_default_profiles(&mut self) {
        self.profiles = default_data_type_profiles();
    }

    /// Find applicable profile for a given service name
    pub fn find_profile(&self, service_name: &str) -> Option<&DataTypeProfile> {
        self.profiles
            .iter()
            .find(|p| p.service_name == service_name)
    }
}

/// This SEPP's default runtime data-type profiles: the projection of its local
/// protection-policy capability under the full local `dataTypeEncPolicy`. Used
/// as the local capability advertisement and as the fallback when no policy is
/// negotiated (single source of truth: `n32c_handler::local_protection_policy`).
pub fn default_data_type_profiles() -> Vec<DataTypeProfile> {
    let policy = crate::n32c_handler::local_protection_policy();
    let types = policy.data_type_enc_policy.clone().unwrap_or_default();
    crate::n32c_handler::profiles_from_protection_policy(&policy, &types)
}

// ============================================================================
// TS 29.573 sec 6.3 reformatted-message structures
// ============================================================================

/// Location of an IE within the reformatted HTTP message (TS 29.573
/// §6.1.5.3.6 / OpenAPI `IeLocation`). Shared by `RequestLine` (sepp-03) and
/// `HttpPayload` (sepp-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IeLocation {
    UriParam,
    Header,
    Body,
    MultipartBinary,
    UriPath,
}

/// PLMN-ID as carried in the reformatted message metaData (TS 29.573 `PlmnId`:
/// 3-digit `mcc`, 2-3-digit `mnc`). Used for the sepp-09 consistency check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlmnIdMeta {
    pub mcc: String,
    pub mnc: String,
}

impl PlmnIdMeta {
    /// Encode an internal `PlmnId` into the wire form (zero-padded mcc/mnc).
    fn from_plmn(p: &PlmnId) -> Self {
        let mnc = if p.mnc_len == 2 {
            format!("{:02}", p.mnc)
        } else {
            format!("{:03}", p.mnc)
        };
        Self {
            mcc: format!("{:03}", p.mcc),
            mnc,
        }
    }

    /// Whether this claimed PLMN-ID is one of `plmns` (numeric mcc/mnc compare).
    fn matches_any(&self, plmns: &[PlmnId]) -> bool {
        match (self.mcc.parse::<u16>(), self.mnc.parse::<u16>()) {
            (Ok(mcc), Ok(mnc)) => plmns.iter().any(|p| p.mcc == mcc && p.mnc == mnc),
            _ => false,
        }
    }
}

/// The literal stored in `authorizedIpxId` when no first-hop RI is authorized
/// (TS 29.573 §6.2.5.2.9: the field is mandatory; sepp-07).
const AUTHORIZED_IPX_ID_NONE: &str = "NULL";

/// metaData of the DataToIntegrityProtectBlock (TS 29.573 table 6.3.2-1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fMetaData {
    /// N32-f context ID allocated by the *receiving* SEPP
    pub n32f_context_id: String,
    /// Unique message ID (for n32f-error correlation)
    pub message_id: String,
    /// Identity of the first-hop IPX (TS 29.573 §6.2.5.2.9: mandatory, always
    /// serialized; "NULL" when no RI is authorized — sepp-07).
    #[serde(default = "default_authorized_ipx_id")]
    pub authorized_ipx_id: String,
    /// Sender (home/visited) PLMN-ID, for the receiving SEPP's PLMN-ID
    /// consistency check (sepp-09). Omitted when the originator serves no PLMN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_plmn_id: Option<PlmnIdMeta>,
}

fn default_authorized_ipx_id() -> String {
    AUTHORIZED_IPX_ID_NONE.to_string()
}

/// Request line of the original SBI request (TS 29.573 §6.2.5.2.6 `RequestLine`).
/// The SBI URL is split into scheme / authority / path / queryFragment on
/// protect and re-joined on unprotect; `protocolVersion` is fixed at "2".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLine {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    /// Request path, excluding any query/fragment.
    pub path: String,
    /// HTTP version token; always "2" for N32-f (HTTP/2).
    pub protocol_version: String,
    /// Query (and/or fragment) part of the URL, without the leading '?'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_fragment: Option<String>,
    /// Which IeLocations of the path/query are protected (TS 29.573).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_query_protect_ind: Option<Vec<IeLocation>>,
}

/// Encoded HTTP header value (TS 29.573 §6.2.5.2.7 `EncodedHttpHeaderValue`):
/// either the cleartext value (string) or a reference `{ "encBlockIndex": i }`
/// to an encrypted leaf in the `dataToEncrypt` array.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum EncodedHttpHeaderValue {
    /// Cleartext header value
    Plain(String),
    /// Reference into the cipher block's `dataToEncrypt`
    Encrypted {
        #[serde(rename = "encBlockIndex")]
        enc_block_index: usize,
    },
}

/// HTTP header carried in the integrity-protected block (TS 29.573 §6.2.5.2.7
/// `HttpHeader`): the field key is `header` and the value is an
/// `EncodedHttpHeaderValue` (sepp-06).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpHeader {
    pub header: String,
    pub value: EncodedHttpHeaderValue,
}

/// One HttpPayload element (TS 29.573 §6.2.5.2.8): a single leaf of the body
/// addressed by an RFC 6901 JSON Pointer `iePath`. A cleartext leaf carries
/// its JSON value; an encrypted leaf carries `{"encBlockIndex": i}` referencing
/// the `dataToEncrypt` array. A non-JSON body is a single `MULTIPART_BINARY`
/// element whose value is the base64url-encoded bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fPayloadElement {
    pub ie_path: String,
    pub ie_value_location: IeLocation,
    pub value: serde_json::Value,
}

/// DataToIntegrityProtectBlock (TS 29.573 §6.2.5.2.5): integrity-protected
/// (JWE AAD) but cleartext. Carries `requestLine` for a forwarded API request
/// and `statusLine` for a forwarded API response — the two are mutually
/// exclusive (exactly one present).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToIntegrityProtectBlock {
    pub meta_data: N32fMetaData,
    /// Request line of the forwarded HTTP API request (present for a request).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_line: Option<RequestLine>,
    /// Status line of the forwarded HTTP API response — a string, e.g. "200"
    /// (present for a response; TS 29.573 §6.2.5.2.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_line: Option<String>,
    #[serde(default)]
    pub headers: Vec<HttpHeader>,
    #[serde(default)]
    pub payload: Vec<N32fPayloadElement>,
}

/// DataToIntegrityProtectAndCipherBlock: the JWE plaintext
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToIntegrityProtectAndCipherBlock {
    pub data_to_encrypt: Vec<serde_json::Value>,
}

/// Payload of a modificationsBlock JWS entry (TS 29.573 sec 6.3.4)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModificationsBlockPayload {
    /// FQDN of the entity that created this entry
    pub identity: String,
    /// JSON-Patch (RFC 6902) operations against the clear payload
    #[serde(default)]
    pub operations: Vec<serde_json::Value>,
    /// The JWE Authentication Tag of the sending SEPP's JWE (TS 33.501
    /// §13.2.4.5.1 / TS 29.573 §6.2.5.2.10): EVERY modificationsBlock entry
    /// binds to this same tag for replay protection — entries are NOT chained
    /// to the previous JWS signature (RI ordering is the array order). sepp-08.
    pub tag: String,
}

/// The protected N32-f message (N32fReformattedReqMsg shape)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fReformattedMessage {
    /// FlatJweJson: AAD = DataToIntegrityProtectBlock,
    /// plaintext = DataToIntegrityProtectAndCipherBlock
    pub reformatted_data: FlatJwe,
    /// FlatJwsJson chain (first entry by the sending SEPP)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modifications_block: Vec<FlatJws>,
}

// ============================================================================
// n32f-error reporting (TS 29.573 sec 6.1.5.4, N32fErrorInfo)
// ============================================================================

/// N32-f error types (TS 29.573 table 6.1.5.4.x)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum N32fErrorType {
    #[serde(rename = "INTEGRITY_CHECK_FAILED")]
    IntegrityCheckFailed,
    #[serde(rename = "INTEGRITY_CHECK_ON_MODIFICATIONS_FAILED")]
    IntegrityCheckOnModificationsFailed,
    #[serde(rename = "MODIFICATIONS_INSTRUCTIONS_FAILED")]
    ModificationsInstructionsFailed,
    #[serde(rename = "DECIPHERING_FAILED")]
    DecipheringFailed,
    #[serde(rename = "MESSAGE_RECONSTRUCTION_FAILED")]
    MessageReconstructionFailed,
    #[serde(rename = "UNAVAILABLE_PRINS_CONTEXT")]
    UnavailablePrinsContext,
    #[serde(rename = "POLICY_MISMATCH")]
    PolicyMismatch,
}

/// N32fErrorInfo body POSTed to {apiRoot}/n32c-handshake/v1/n32f-error
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fErrorInfo {
    /// messageId of the failed N32-f message
    pub n32f_message_id: String,
    /// What failed
    pub n32f_error_type: N32fErrorType,
    /// Per-IPX modification failures (TS 29.573 §6.1.5.4).
    ///
    /// Issue #99: was `Vec<String>`. A conformant peer SEPP deserialises this as
    /// an array of `FailedModificationInfo` OBJECTS, so a list of bare strings
    /// could not be parsed at all -- and this report is emitted exactly when the
    /// N32 link is already failing, so the malformed shape destroyed
    /// diagnosability at the worst moment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_modification_list: Vec<FailedModificationInfo>,
    /// Reconstruction diagnostics (TS 29.573 §6.1.5.4). Was `Vec<String>`; see
    /// above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_details_list: Vec<N32fErrorDetail>,
    /// The N32-f context the failure relates to. Issue #99: absent before, so a
    /// peer holding several contexts could not tell which one failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n32f_context_id: Option<String>,
}

/// One IPX's modification failure (TS 29.573 §6.1.5.4 `FailedModificationInfo`,
/// `TS29573_N32_Handshake.yaml:503-533`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedModificationInfo {
    /// Identity of the IPX whose modification could not be applied.
    pub ipx_id: String,
    /// Why it failed.
    pub n32f_error_type: N32fErrorType,
}

/// One reconstruction diagnostic (TS 29.573 §6.1.5.4 `N32fErrorDetail`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fErrorDetail {
    /// The JSON attribute that could not be reconstructed.
    ///
    /// Optional and left unset by the current error path, which does not track
    /// which attribute failed. Omitted rather than fabricated -- an invented
    /// attribute name in a diagnostic report is worse than a missing one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// Human-readable reason the message could not be reconstructed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg_reconstruct_fail_reason: Option<String>,
}

/// Error raised while unprotecting an N32-f message; carries everything
/// needed to produce the spec-shaped n32f-error report.
#[derive(Debug, Clone)]
pub struct N32fUnprotectError {
    pub error_type: N32fErrorType,
    pub message_id: Option<String>,
    pub detail: String,
    pub failed_modifications: Vec<String>,
}

impl N32fUnprotectError {
    fn new(
        error_type: N32fErrorType,
        message_id: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            error_type,
            message_id,
            detail: detail.into(),
            failed_modifications: Vec::new(),
        }
    }

    /// Convert into the on-the-wire `N32fErrorInfo`.
    ///
    /// `n32f_context_id` is passed in rather than stored on the error: the error
    /// is raised deep in unprotection, which does not know the context, while the
    /// caller emitting the report always does (issue #99, criterion 4).
    pub fn to_error_info(&self, n32f_context_id: Option<&str>) -> N32fErrorInfo {
        N32fErrorInfo {
            n32f_message_id: self.message_id.clone().unwrap_or_else(|| "unknown".into()),
            n32f_error_type: self.error_type,
            // Issue #99: the stored strings are IPX identifiers, so each becomes
            // a FailedModificationInfo carrying this report's error type.
            failed_modification_list: self
                .failed_modifications
                .iter()
                .map(|ipx_id| FailedModificationInfo {
                    ipx_id: ipx_id.clone(),
                    n32f_error_type: self.error_type,
                })
                .collect(),
            error_details_list: vec![N32fErrorDetail {
                attribute: None,
                msg_reconstruct_fail_reason: Some(self.detail.clone()),
            }],
            n32f_context_id: n32f_context_id.map(str::to_string),
        }
    }
}

impl std::fmt::Display for N32fUnprotectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.error_type, self.detail)
    }
}

// ============================================================================
// Protect (sending SEPP)
// ============================================================================

/// Apply PRINS protection to an outgoing SBI request, producing the
/// N32fReformattedMessage per TS 29.573 sec 6.3.
pub fn protect_message(
    ctx: &PrinsContext,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<N32fReformattedMessage, JoseError> {
    let service_name = extract_service_name(url);
    let profile = ctx.find_profile(&service_name);

    let mut cipher_block = DataToIntegrityProtectAndCipherBlock::default();
    let mut payload_elements: Vec<N32fPayloadElement> = Vec::new();

    if let Some(body_bytes) = body {
        let parsed: Option<serde_json::Value> = serde_json::from_slice(body_bytes).ok();
        match parsed {
            Some(json) => {
                // Flatten the body into one HttpPayload per leaf (RFC 6901
                // pointers). Profile-designated IEs are moved into the cipher
                // block and referenced by `{encBlockIndex}`; everything else is
                // a cleartext leaf. The whole-body "$" element is gone.
                let encrypt_paths: std::collections::HashSet<&str> = profile
                    .map(|p| {
                        p.encrypt_ies
                            .iter()
                            .filter(|ie| ie.location == "BODY")
                            .map(|ie| ie.path.as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                flatten_body_leaves(
                    &json,
                    String::new(),
                    &encrypt_paths,
                    &mut cipher_block,
                    &mut payload_elements,
                );
                if payload_elements.is_empty() {
                    // Degenerate structureless body (e.g. `{}`): carry it whole
                    // so the receiver reproduces it byte-for-byte.
                    payload_elements.push(N32fPayloadElement {
                        ie_path: String::new(),
                        ie_value_location: IeLocation::Body,
                        value: json,
                    });
                }
            }
            None => {
                // Non-JSON body: single MULTIPART_BINARY element, base64url-encoded
                payload_elements.push(N32fPayloadElement {
                    ie_path: String::new(),
                    ie_value_location: IeLocation::MultipartBinary,
                    value: serde_json::Value::String(b64url_encode(body_bytes)),
                });
            }
        }
    }

    let integrity_block = DataToIntegrityProtectBlock {
        meta_data: N32fMetaData {
            // The receiver looks the context up by the ID *it* allocated
            n32f_context_id: ctx.peer_context_id.clone(),
            message_id: generate_message_id(),
            // sepp-07: mandatory; "NULL" when no first-hop RI is authorized.
            authorized_ipx_id: AUTHORIZED_IPX_ID_NONE.to_string(),
            // sepp-09: stamp this SEPP's serving PLMN-ID (if configured) so the
            // receiver can verify PLMN-ID consistency against the N32-f context.
            sender_plmn_id: ctx.local_plmn_ids.first().map(PlmnIdMeta::from_plmn),
        },
        request_line: Some(build_request_line(method, url)),
        status_line: None,
        // sepp-06: HttpHeader { header, value: EncodedHttpHeaderValue }. This
        // SEPP carries header values in the clear (integrity-protected).
        headers: headers
            .iter()
            .map(|(name, value)| HttpHeader {
                header: name.clone(),
                value: EncodedHttpHeaderValue::Plain(value.clone()),
            })
            .collect(),
        payload: payload_elements,
    };

    let aad_bytes =
        serde_json::to_vec(&integrity_block).map_err(|e| JoseError::Format(e.to_string()))?;
    let plaintext =
        serde_json::to_vec(&cipher_block).map_err(|e| JoseError::Format(e.to_string()))?;

    // The forwarded SBI request is an N32-f request: protect it with this
    // SEPP's request-direction session key + IV salt, selected by role from
    // the N32-f key hierarchy (TS 33.501 §13.2.4.4.1). sepp-02: the 96-bit GCM
    // nonce is `IV salt (8B) || SEQ (32-bit)`, the SEQ allocated from this
    // SEPP's per-salt request counter. sepp-12: the enc (A128/A256GCM) follows
    // the negotiated profile; the session key is its leading `key_len` octets.
    let (key, iv_salt) = ctx.protect_key(N32fDirection::Request);
    let seq = ctx.next_send_seq(N32fDirection::Request)?;
    let jwe = jose::jwe_encrypt_with_iv_salt(
        key,
        ctx.jwe_enc,
        iv_salt,
        seq,
        &plaintext,
        Some(&aad_bytes),
        Some(&ctx.kid),
    )?;

    // First modificationsBlock entry: signed by the sending SEPP over the
    // JWE tag (binds the chain to this exact protected message). Per
    // TS 33.501 §13.2.4.6 this uses the SEPP's *asymmetric* (ES256) key,
    // keyed (kid) by its identity FQDN so the receiver can locate the
    // public key. The symmetric session key is NOT used here.
    let signing_key = ctx.local_signing_key.as_ref().ok_or_else(|| {
        JoseError::Crypto("no local ES256 signing key for modificationsBlock".into())
    })?;
    let mods_payload = ModificationsBlockPayload {
        identity: ctx.local_fqdn.clone(),
        operations: Vec::new(),
        tag: jwe.tag.clone(),
    };
    let mods_bytes =
        serde_json::to_vec(&mods_payload).map_err(|e| JoseError::Format(e.to_string()))?;
    let jws = jose::jws_sign_es256(signing_key, &mods_bytes, Some(&ctx.local_fqdn))?;

    log::info!(
        "PRINS protect: {} {} ({} encrypted IEs, msg_id in AAD)",
        method,
        url,
        cipher_block.data_to_encrypt.len()
    );

    Ok(N32fReformattedMessage {
        reformatted_data: jwe,
        modifications_block: vec![jws],
    })
}

/// Apply PRINS protection to an outgoing SBI *response*, producing the
/// N32fReformattedMessage (N32fReformattedRspMsg shape) per TS 29.573 §6.3.
/// The receiving SEPP calls this after forwarding the reconstructed request to
/// the target NF, to protect that NF's HTTP response for return over N32-f.
/// The body is carried integrity-protected in the clear (response-IE
/// encryption is policy-driven and not applied here).
pub fn protect_response_message(
    ctx: &PrinsContext,
    status_code: u16,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<N32fReformattedMessage, JoseError> {
    let mut cipher_block = DataToIntegrityProtectAndCipherBlock::default();
    let mut payload_elements: Vec<N32fPayloadElement> = Vec::new();

    if let Some(body_bytes) = body {
        match serde_json::from_slice::<serde_json::Value>(body_bytes).ok() {
            Some(json) => {
                let no_encrypt: std::collections::HashSet<&str> = std::collections::HashSet::new();
                flatten_body_leaves(
                    &json,
                    String::new(),
                    &no_encrypt,
                    &mut cipher_block,
                    &mut payload_elements,
                );
                if payload_elements.is_empty() {
                    payload_elements.push(N32fPayloadElement {
                        ie_path: String::new(),
                        ie_value_location: IeLocation::Body,
                        value: json,
                    });
                }
            }
            None => {
                payload_elements.push(N32fPayloadElement {
                    ie_path: String::new(),
                    ie_value_location: IeLocation::MultipartBinary,
                    value: serde_json::Value::String(b64url_encode(body_bytes)),
                });
            }
        }
    }

    let integrity_block = DataToIntegrityProtectBlock {
        meta_data: N32fMetaData {
            n32f_context_id: ctx.peer_context_id.clone(),
            message_id: generate_message_id(),
            authorized_ipx_id: AUTHORIZED_IPX_ID_NONE.to_string(),
            sender_plmn_id: ctx.local_plmn_ids.first().map(PlmnIdMeta::from_plmn),
        },
        request_line: None,
        status_line: Some(status_code.to_string()),
        headers: headers
            .iter()
            .map(|(name, value)| HttpHeader {
                header: name.clone(),
                value: EncodedHttpHeaderValue::Plain(value.clone()),
            })
            .collect(),
        payload: payload_elements,
    };

    let aad_bytes =
        serde_json::to_vec(&integrity_block).map_err(|e| JoseError::Format(e.to_string()))?;
    let plaintext =
        serde_json::to_vec(&cipher_block).map_err(|e| JoseError::Format(e.to_string()))?;

    // Response direction: protect with this SEPP's response-direction session
    // key + IV salt (TS 33.501 §13.2.4.4.1); SEQ from the per-salt response
    // counter.
    let (key, iv_salt) = ctx.protect_key(N32fDirection::Response);
    let seq = ctx.next_send_seq(N32fDirection::Response)?;
    let jwe = jose::jwe_encrypt_with_iv_salt(
        key,
        ctx.jwe_enc,
        iv_salt,
        seq,
        &plaintext,
        Some(&aad_bytes),
        Some(&ctx.kid),
    )?;

    let signing_key = ctx.local_signing_key.as_ref().ok_or_else(|| {
        JoseError::Crypto("no local ES256 signing key for modificationsBlock".into())
    })?;
    let mods_payload = ModificationsBlockPayload {
        identity: ctx.local_fqdn.clone(),
        operations: Vec::new(),
        tag: jwe.tag.clone(),
    };
    let mods_bytes =
        serde_json::to_vec(&mods_payload).map_err(|e| JoseError::Format(e.to_string()))?;
    let jws = jose::jws_sign_es256(signing_key, &mods_bytes, Some(&ctx.local_fqdn))?;

    log::info!(
        "PRINS protect response: status={} ({} payload leaves)",
        status_code,
        integrity_block.payload.len()
    );

    Ok(N32fReformattedMessage {
        reformatted_data: jwe,
        modifications_block: vec![jws],
    })
}

// ============================================================================
// Unprotect (receiving SEPP)
// ============================================================================

/// Reconstructed SBI request after successful unprotection.
#[derive(Debug, Clone)]
pub struct ReconstructedRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub message_id: String,
}

/// Reconstructed SBI response after successful unprotection (the sending SEPP
/// recovers this from an N32fReformattedRspMsg to relay to the consumer NF).
#[derive(Debug, Clone)]
pub struct ReconstructedResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub message_id: String,
}

/// Core PRINS verify+decrypt+reassemble, shared by the request and response
/// unprotect paths. Returns the authenticated integrity block plus the
/// reconstructed headers/body and the messageId.
///
/// Verification order per TS 29.573: parse AAD (cleartext copy is needed for
/// the error report's messageId), verify the JWS modification chain,
/// AEAD-decrypt (which authenticates the AAD), apply allowed JSON-Patch
/// operations, then reassemble headers/body. `direction` selects the session
/// key and anti-replay counter: `Request` for a received N32-f request,
/// `Response` for a received N32-f response.
#[allow(clippy::type_complexity)]
fn unprotect_common(
    ctx: &PrinsContext,
    msg: &N32fReformattedMessage,
    direction: N32fDirection,
) -> Result<
    (
        DataToIntegrityProtectBlock,
        HashMap<String, String>,
        Option<Vec<u8>>,
        String,
    ),
    N32fUnprotectError,
> {
    // --- Parse the (not yet authenticated) AAD for metaData/messageId ---
    let aad_b64 = msg.reformatted_data.aad.as_ref().ok_or_else(|| {
        N32fUnprotectError::new(
            N32fErrorType::MessageReconstructionFailed,
            None,
            "missing JWE aad (DataToIntegrityProtectBlock)",
        )
    })?;
    let aad_bytes = b64url_decode(aad_b64).map_err(|e| {
        N32fUnprotectError::new(
            N32fErrorType::MessageReconstructionFailed,
            None,
            e.to_string(),
        )
    })?;
    let integrity_block: DataToIntegrityProtectBlock =
        serde_json::from_slice(&aad_bytes).map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::MessageReconstructionFailed,
                None,
                format!("bad DataToIntegrityProtectBlock: {e}"),
            )
        })?;
    let message_id = integrity_block.meta_data.message_id.clone();

    // The peer must address us by the context ID we allocated
    if integrity_block.meta_data.n32f_context_id != ctx.local_context_id {
        return Err(N32fUnprotectError::new(
            N32fErrorType::UnavailablePrinsContext,
            Some(message_id),
            format!(
                "unknown n32fContextId [{}]",
                integrity_block.meta_data.n32f_context_id
            ),
        ));
    }

    // --- Verify the JWS modification chain ---
    if msg.modifications_block.is_empty() {
        return Err(N32fUnprotectError::new(
            N32fErrorType::IntegrityCheckOnModificationsFailed,
            Some(message_id),
            "empty modificationsBlock",
        ));
    }
    let mut operations: Vec<serde_json::Value> = Vec::new();
    // sepp-08: every entry's `tag` must equal the JWE Authentication Tag
    // (TS 33.501 §13.2.4.5.1); entries are not chained to the prior signature.
    let jwe_tag = &msg.reformatted_data.tag;
    for (i, jws) in msg.modifications_block.iter().enumerate() {
        // Locate the signer's registered ES256 public key by the JWS `kid`
        // (== signer identity FQDN). An unregistered or non-ES256 entry is
        // rejected: the symmetric session key is NOT accepted for the
        // modificationsBlock (TS 33.501 §13.2.4.6).
        let (alg, kid) = jose::jws_peek_header(jws).map_err(|e| {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] header: {e}"),
            );
            err.failed_modifications.push(format!("entry-{i}"));
            err
        })?;
        if alg != "ES256" {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] uses non-asymmetric alg [{alg}]"),
            );
            err.failed_modifications
                .push(kid.unwrap_or_else(|| format!("entry-{i}")));
            return Err(err);
        }
        let signer_id = kid.ok_or_else(|| {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] missing signer kid"),
            );
            err.failed_modifications.push(format!("entry-{i}"));
            err
        })?;
        let verifying_key = ctx.peer_verifying_keys.get(&signer_id).ok_or_else(|| {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] signer [{signer_id}] has no registered key"),
            );
            err.failed_modifications.push(signer_id.clone());
            err
        })?;
        let payload_bytes = jose::jws_verify_es256(verifying_key, jws).map_err(|e| {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}]: {e}"),
            );
            err.failed_modifications.push(signer_id.clone());
            err
        })?;
        let payload: ModificationsBlockPayload =
            serde_json::from_slice(&payload_bytes).map_err(|e| {
                N32fUnprotectError::new(
                    N32fErrorType::IntegrityCheckOnModificationsFailed,
                    Some(message_id.clone()),
                    format!("modificationsBlock[{i}] payload: {e}"),
                )
            })?;
        // Bind the signed identity to the key used to verify it.
        if payload.identity != signer_id {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!(
                    "modificationsBlock[{i}] identity [{}] != kid [{signer_id}]",
                    payload.identity
                ),
            );
            err.failed_modifications.push(payload.identity.clone());
            return Err(err);
        }
        // sepp-08: each entry's tag MUST be the JWE Authentication Tag (replay
        // protection), not the previous entry's signature.
        if &payload.tag != jwe_tag {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] tag does not bind to the JWE Authentication Tag"),
            );
            err.failed_modifications.push(payload.identity.clone());
            return Err(err);
        }
        // Policy check on requested modifications
        for op in &payload.operations {
            let path = op.get("path").and_then(|p| p.as_str()).unwrap_or("");
            if !ctx
                .modification_policy
                .allowed_paths
                .iter()
                .any(|allowed| allowed == path)
            {
                let mut err = N32fUnprotectError::new(
                    N32fErrorType::PolicyMismatch,
                    Some(message_id.clone()),
                    format!("modification of [{path}] not permitted by policy"),
                );
                err.failed_modifications.push(payload.identity.clone());
                return Err(err);
            }
        }
        operations.extend(payload.operations.iter().cloned());
    }

    // --- AEAD decrypt; authenticates the AAD (integrity block) ---
    // The inbound message was originated by the PEER in `direction` (a request
    // or a response), so it is decrypted with the peer's session key for that
    // direction (selected by the peer's role). The IV is carried on the wire,
    // so only the key is needed here.
    let (key, _iv_salt) = ctx.unprotect_key(direction);
    let plaintext = jose::jwe_decrypt(key, &msg.reformatted_data).map_err(|e| {
        let error_type = match e {
            JoseError::Tampered => N32fErrorType::IntegrityCheckFailed,
            _ => N32fErrorType::DecipheringFailed,
        };
        N32fUnprotectError::new(error_type, Some(message_id.clone()), e.to_string())
    })?;
    let cipher_block: DataToIntegrityProtectAndCipherBlock = serde_json::from_slice(&plaintext)
        .map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::DecipheringFailed,
                Some(message_id.clone()),
                format!("bad DataToIntegrityProtectAndCipherBlock: {e}"),
            )
        })?;

    // --- sepp-02: anti-replay on the authenticated SEQ ---
    // The AEAD has authenticated the message; recover SEQ from the JWE nonce
    // (IV salt || SEQ) and reject a replayed or out-of-window SEQ. Run only
    // after a successful decrypt so a tampered message never advances the
    // window.
    let (_iv_salt, seq) = jose::jwe_iv_salt_and_seq(&msg.reformatted_data).ok_or_else(|| {
        N32fUnprotectError::new(
            N32fErrorType::IntegrityCheckFailed,
            Some(message_id.clone()),
            "malformed JWE nonce (expected IV salt(8) || SEQ(32-bit))",
        )
    })?;
    ctx.check_recv_seq(direction, seq).map_err(|reason| {
        N32fUnprotectError::new(
            N32fErrorType::IntegrityCheckFailed,
            Some(message_id.clone()),
            reason,
        )
    })?;

    // --- sepp-09: PLMN-ID consistency check ---
    // The sender's PLMN-ID (in the now-authenticated metaData) must be one of
    // the PLMN-IDs bound to this N32-f context (TS 33.501 §13.2.4.7). Skipped
    // when the message carries no PLMN-ID or no binding was established.
    if let Some(ref claimed) = integrity_block.meta_data.sender_plmn_id {
        if !ctx.peer_plmn_ids.is_empty() && !claimed.matches_any(&ctx.peer_plmn_ids) {
            return Err(N32fUnprotectError::new(
                N32fErrorType::PolicyMismatch,
                Some(message_id.clone()),
                format!(
                    "sender PLMN-ID {}-{} is not bound to the N32-f context",
                    claimed.mcc, claimed.mnc
                ),
            ));
        }
    }

    // --- Reassemble the original request ---
    // Each HttpPayload leaf is applied back to the rebuilt body at its RFC 6901
    // pointer; encrypted leaves resolve `{encBlockIndex}` from the cipher block.
    let mut body_json: Option<serde_json::Value> = None;
    let mut body_raw: Option<Vec<u8>> = None;

    for element in &integrity_block.payload {
        match element.ie_value_location {
            IeLocation::Body => {
                // Encrypted leaf: `{encBlockIndex}` ref; else cleartext value.
                let resolved = if let Some(idx) =
                    element.value.get("encBlockIndex").and_then(|v| v.as_u64())
                {
                    cipher_block
                        .data_to_encrypt
                        .get(idx as usize)
                        .cloned()
                        .ok_or_else(|| {
                            N32fUnprotectError::new(
                                N32fErrorType::MessageReconstructionFailed,
                                Some(message_id.clone()),
                                format!("encBlockIndex {idx} out of range"),
                            )
                        })?
                } else {
                    element.value.clone()
                };
                let root = body_json.get_or_insert(serde_json::Value::Null);
                set_at_json_pointer(root, &element.ie_path, resolved).map_err(|detail| {
                    N32fUnprotectError::new(
                        N32fErrorType::MessageReconstructionFailed,
                        Some(message_id.clone()),
                        format!("INVALID_JSON_POINTER [{}]: {detail}", element.ie_path),
                    )
                })?;
            }
            IeLocation::MultipartBinary => {
                let encoded = element.value.as_str().unwrap_or("");
                body_raw = Some(b64url_decode(encoded).map_err(|e| {
                    N32fUnprotectError::new(
                        N32fErrorType::MessageReconstructionFailed,
                        Some(message_id.clone()),
                        e.to_string(),
                    )
                })?);
            }
            // URI_PARAM / HEADER / URI_PATH IEs are not carried in the body
            // payload by this SEPP; ignore for body reconstruction.
            _ => {}
        }
    }

    // Apply policy-approved JSON-Patch replace operations from the chain
    if !operations.is_empty() {
        if let Some(ref mut json) = body_json {
            apply_json_patch_replaces(json, &operations).map_err(|detail| {
                N32fUnprotectError::new(
                    N32fErrorType::ModificationsInstructionsFailed,
                    Some(message_id.clone()),
                    detail,
                )
            })?;
        }
    }

    let body = match (body_json, body_raw) {
        (Some(json), _) => Some(serde_json::to_vec(&json).map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::MessageReconstructionFailed,
                Some(message_id.clone()),
                e.to_string(),
            )
        })?),
        (None, Some(raw)) => Some(raw),
        (None, None) => None,
    };

    // sepp-06: reconstruct each header from its EncodedHttpHeaderValue. A
    // cleartext value is used as-is; an `{encBlockIndex}` reference resolves to
    // the corresponding encrypted leaf in the cipher block.
    let mut headers: HashMap<String, String> = HashMap::new();
    for h in &integrity_block.headers {
        let value = match &h.value {
            EncodedHttpHeaderValue::Plain(s) => s.clone(),
            EncodedHttpHeaderValue::Encrypted { enc_block_index } => {
                let v = cipher_block
                    .data_to_encrypt
                    .get(*enc_block_index)
                    .ok_or_else(|| {
                        N32fUnprotectError::new(
                            N32fErrorType::MessageReconstructionFailed,
                            Some(message_id.clone()),
                            format!(
                                "header [{}] encBlockIndex {enc_block_index} out of range",
                                h.header
                            ),
                        )
                    })?;
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                }
            }
        };
        headers.insert(h.header.clone(), value);
    }

    Ok((integrity_block, headers, body, message_id))
}

/// Verify and remove PRINS protection from a received N32-f *request*
/// (N32fReformattedReqMsg), reconstructing the original SBI request.
pub fn unprotect_message(
    ctx: &PrinsContext,
    msg: &N32fReformattedMessage,
) -> Result<ReconstructedRequest, N32fUnprotectError> {
    let (integrity_block, headers, body, message_id) =
        unprotect_common(ctx, msg, N32fDirection::Request)?;
    let request_line = integrity_block.request_line.ok_or_else(|| {
        N32fUnprotectError::new(
            N32fErrorType::MessageReconstructionFailed,
            Some(message_id.clone()),
            "N32-f request message carries no requestLine",
        )
    })?;
    let url = join_request_line(&request_line);
    log::info!(
        "PRINS unprotect OK: {} {} (msg_id={})",
        request_line.method,
        url,
        message_id
    );
    Ok(ReconstructedRequest {
        method: request_line.method.clone(),
        url,
        headers,
        body,
        message_id,
    })
}

/// Verify and remove PRINS protection from a received N32-f *response*
/// (N32fReformattedRspMsg), reconstructing the original SBI response.
pub fn unprotect_response_message(
    ctx: &PrinsContext,
    msg: &N32fReformattedMessage,
) -> Result<ReconstructedResponse, N32fUnprotectError> {
    let (integrity_block, headers, body, message_id) =
        unprotect_common(ctx, msg, N32fDirection::Response)?;
    let status_line = integrity_block.status_line.ok_or_else(|| {
        N32fUnprotectError::new(
            N32fErrorType::MessageReconstructionFailed,
            Some(message_id.clone()),
            "N32-f response message carries no statusLine",
        )
    })?;
    // statusLine is a string; take the leading integer status code (e.g. "200"
    // or "200 OK").
    let status_code = status_line
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            N32fUnprotectError::new(
                N32fErrorType::MessageReconstructionFailed,
                Some(message_id.clone()),
                format!("malformed statusLine [{status_line}]"),
            )
        })?;
    log::info!("PRINS unprotect response OK: {status_code} (msg_id={message_id})");
    Ok(ReconstructedResponse {
        status_code,
        headers,
        body,
        message_id,
    })
}

/// Apply RFC 6902 "replace" operations (the only kind PRINS intermediaries
/// use against the cleartext body). Paths use JSON-Pointer (e.g. "/amount").
fn apply_json_patch_replaces(
    json: &mut serde_json::Value,
    operations: &[serde_json::Value],
) -> Result<(), String> {
    for op in operations {
        let kind = op.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "replace" {
            return Err(format!("unsupported JSON-Patch op [{kind}]"));
        }
        let path = op
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing path")?;
        let value = op.get("value").cloned().ok_or("missing value")?;
        let target = json
            .pointer_mut(path)
            .ok_or_else(|| format!("path [{path}] not found"))?;
        *target = value;
    }
    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Escape one RFC 6901 reference token (`~` -> `~0`, `/` -> `~1`).
fn rfc6901_escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Unescape one RFC 6901 reference token (`~1` -> `/`, `~0` -> `~`).
fn rfc6901_unescape(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Recursively flatten a JSON body into one `N32fPayloadElement` per leaf,
/// keyed by its RFC 6901 JSON Pointer. Objects are descended into; any value
/// whose pointer is in `encrypt_paths` is moved into `cipher_block` and emitted
/// as an `{encBlockIndex}` reference (without recursing into it); every other
/// non-object value is emitted as a cleartext leaf. Emission follows document
/// order so the receiver reproduces the body byte-for-byte.
fn flatten_body_leaves(
    value: &serde_json::Value,
    pointer: String,
    encrypt_paths: &std::collections::HashSet<&str>,
    cipher_block: &mut DataToIntegrityProtectAndCipherBlock,
    out: &mut Vec<N32fPayloadElement>,
) {
    if encrypt_paths.contains(pointer.as_str()) {
        let idx = cipher_block.data_to_encrypt.len();
        cipher_block.data_to_encrypt.push(value.clone());
        out.push(N32fPayloadElement {
            ie_path: pointer,
            ie_value_location: IeLocation::Body,
            value: serde_json::json!({ "encBlockIndex": idx }),
        });
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let child = format!("{pointer}/{}", rfc6901_escape(k));
                flatten_body_leaves(v, child, encrypt_paths, cipher_block, out);
            }
        }
        leaf => out.push(N32fPayloadElement {
            ie_path: pointer,
            ie_value_location: IeLocation::Body,
            value: leaf.clone(),
        }),
    }
}

/// Apply `value` at the RFC 6901 `pointer` in `root`, creating intermediate
/// objects as needed. An empty pointer replaces the whole document. A pointer
/// that is non-empty but does not start with '/' is rejected as malformed
/// (INVALID_JSON_POINTER).
fn set_at_json_pointer(
    root: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    if pointer.is_empty() {
        *root = value;
        return Ok(());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err("pointer must be empty or start with '/'".to_string());
    };
    let tokens: Vec<String> = rest.split('/').map(rfc6901_unescape).collect();
    let mut current = root;
    for token in &tokens[..tokens.len() - 1] {
        if !current.is_object() {
            *current = serde_json::json!({});
        }
        current = current
            .as_object_mut()
            .expect("coerced to object above")
            .entry(token.clone())
            .or_insert(serde_json::Value::Null);
    }
    let last = tokens.last().expect("pointer has at least one token");
    if !current.is_object() {
        *current = serde_json::json!({});
    }
    current
        .as_object_mut()
        .expect("coerced to object above")
        .insert(last.clone(), value);
    Ok(())
}

/// Split an SBI request URL into the `RequestLine` fields (scheme / authority /
/// path / queryFragment), fixing `protocolVersion` at "2" (TS 29.573
/// §6.2.5.2.6). Relative request targets (the common case) leave scheme and
/// authority empty. The query is everything after the first '?', stored without
/// the leading delimiter so [`join_request_line`] reproduces the URL exactly.
fn build_request_line(method: &str, url: &str) -> RequestLine {
    let (scheme, after_scheme) = match url.find("://") {
        Some(pos) => (url[..pos].to_string(), &url[pos + 3..]),
        None => (String::new(), url),
    };
    let (authority, path_and_query) = if scheme.is_empty() {
        (String::new(), after_scheme)
    } else {
        match after_scheme.find('/') {
            Some(p) => (after_scheme[..p].to_string(), &after_scheme[p..]),
            None => (after_scheme.to_string(), ""),
        }
    };
    let (path, query_fragment) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (path_and_query.to_string(), None),
    };
    RequestLine {
        method: method.to_string(),
        scheme,
        authority,
        path,
        protocol_version: "2".to_string(),
        query_fragment,
        path_query_protect_ind: None,
    }
}

/// Re-join a `RequestLine` into the original SBI request URL.
fn join_request_line(rl: &RequestLine) -> String {
    let mut url = String::new();
    if !rl.scheme.is_empty() {
        url.push_str(&rl.scheme);
        url.push_str("://");
        url.push_str(&rl.authority);
    } else if !rl.authority.is_empty() {
        url.push_str(&rl.authority);
    }
    url.push_str(&rl.path);
    if let Some(q) = &rl.query_fragment {
        url.push('?');
        url.push_str(q);
    }
    url
}

/// Extract service name from URL (e.g., "/nudm-sdm/v1/..." -> "nudm-sdm")
pub fn extract_service_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    path.trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Generate a unique message ID for n32f-error correlation
fn generate_message_id() -> String {
    use rand::Rng as _;
    let r: u64 = rand::rng().random();
    format!("{r:016x}")
}

/// Generate an N32-f context ID
pub fn generate_n32f_context_id() -> String {
    use rand::Rng as _;
    let r: u64 = rand::rng().random();
    format!("{r:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_FQDN: &str = "sepp.home.example.com";
    const RECEIVER_FQDN: &str = "sepp.visited.example.com";

    fn es256_keypair() -> (Arc<SigningKey>, VerifyingKey) {
        use p256::elliptic_curve::rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        (Arc::new(sk), vk)
    }

    /// Shared N32-f key material both peers derive from the same 64-octet
    /// master and canonical context ID (TS 33.501 §13.2.4.4.1).
    fn shared_material() -> N32fKeyMaterial {
        crate::n32c_handler::derive_n32f_key_material(&[0x42u8; 64], "ctx-local-1111-ctx-peer-2222")
    }

    /// Build a sender/receiver PrinsContext pair sharing the N32-f key
    /// hierarchy with MIRRORED roles (sender = initiator/parallel, receiver =
    /// responder/reverse), with the sender's ES256 signing key installed and
    /// its public key registered (under the sender FQDN) on the receiver.
    fn ctx_pair() -> (PrinsContext, PrinsContext) {
        let (sender_sk, sender_vk) = es256_keypair();
        let km = shared_material();
        // Unique kid per pair isolates the global SEQ-counter / replay-window
        // stores (keyed by kid) across tests (sepp-02).
        let kid = format!("kid-{}", generate_n32f_context_id());
        let sender = PrinsContext::new(
            "ctx-local-1111",
            "ctx-peer-2222",
            km.clone(),
            N32fRole::Initiator,
            kid.clone(),
            SENDER_FQDN,
        )
        .with_signing_key(sender_sk);
        let mut receiver = PrinsContext::new(
            "ctx-peer-2222",
            "ctx-local-1111",
            km,
            N32fRole::Responder,
            kid,
            RECEIVER_FQDN,
        );
        receiver.register_verifying_key(SENDER_FQDN, sender_vk);
        (sender, receiver)
    }

    fn sample_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "supi": "imsi-001010000000001",
            "pei": "imeisv-1234567890123456",
            "nssai": {"sst": 1}
        }))
        .unwrap()
    }

    #[test]
    fn protect_unprotect_roundtrip() {
        let (sender, receiver) = ctx_pair();
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &headers,
            Some(&sample_body()),
        )
        .unwrap();

        // SUPI/PEI must not appear in the cleartext AAD
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(!aad_str.contains("imsi-001010000000001"));
        assert!(!aad_str.contains("imeisv-1234567890123456"));
        // Non-sensitive IE stays cleartext
        assert!(aad_str.contains("nssai"));

        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.url, "/nudm-sdm/v1/supi");
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001010000000001");
        assert_eq!(body["pei"], "imeisv-1234567890123456");
        assert_eq!(body["nssai"]["sst"], 1);
        assert_eq!(rec.headers.get("content-type").unwrap(), "application/json");
    }

    /// N32-f response path (TS 29.573 §6.2.5.2.5): the receiving SEPP protects
    /// the target NF's HTTP response with statusLine + response-direction keys,
    /// and the sending SEPP recovers the original status/headers/body.
    #[test]
    fn protect_unprotect_response_roundtrip() {
        // Full bidirectional pair: the responder SEPP signs the response, the
        // initiator SEPP verifies it (reverse of the request direction).
        let (sender_sk, sender_vk) = es256_keypair();
        let (recv_sk, recv_vk) = es256_keypair();
        let km = shared_material();
        let kid = format!("kid-{}", generate_n32f_context_id());
        let mut sender = PrinsContext::new(
            "ctx-local-1111",
            "ctx-peer-2222",
            km.clone(),
            N32fRole::Initiator,
            kid.clone(),
            SENDER_FQDN,
        )
        .with_signing_key(sender_sk);
        sender.register_verifying_key(RECEIVER_FQDN, recv_vk);
        let mut receiver = PrinsContext::new(
            "ctx-peer-2222",
            "ctx-local-1111",
            km,
            N32fRole::Responder,
            kid,
            RECEIVER_FQDN,
        )
        .with_signing_key(recv_sk);
        receiver.register_verifying_key(SENDER_FQDN, sender_vk);

        // The receiving SEPP protects the target NF's HTTP response.
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let body = serde_json::to_vec(&serde_json::json!({
            "supi": "imsi-001010000000001",
            "authType": "5G_AKA"
        }))
        .unwrap();
        let msg = protect_response_message(&receiver, 200, &headers, Some(&body)).unwrap();

        // AAD carries statusLine (not requestLine).
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad).unwrap();
        assert_eq!(block.status_line.as_deref(), Some("200"));
        assert!(block.request_line.is_none());

        // The sending SEPP recovers the NF response.
        let rec = unprotect_response_message(&sender, &msg).unwrap();
        assert_eq!(rec.status_code, 200);
        let rbody: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(rbody["supi"], "imsi-001010000000001");
        assert_eq!(rbody["authType"], "5G_AKA");
        assert_eq!(rec.headers.get("content-type").unwrap(), "application/json");

        // A request-unprotect on a response message must fail (no requestLine).
        assert!(unprotect_message(&sender, &msg).is_err());
    }

    #[test]
    fn tampered_aad_detected_as_integrity_failure() {
        let (sender, receiver) = ctx_pair();
        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();

        // Tamper with a cleartext field inside the integrity block
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let mut block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad).unwrap();
        block.request_line.as_mut().unwrap().path = "/nudm-sdm/v1/EVIL".to_string();
        msg.reformatted_data.aad = Some(b64url_encode(&serde_json::to_vec(&block).unwrap()));

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let (sender, receiver) = ctx_pair();
        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let mut ct = b64url_decode(&msg.reformatted_data.ciphertext).unwrap();
        ct[0] ^= 0xff;
        msg.reformatted_data.ciphertext = b64url_encode(&ct);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
    }

    #[test]
    fn tampered_modifications_chain_detected() {
        let (sender, receiver) = ctx_pair();
        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();

        // Forge the modification entry payload without a valid signature
        msg.modifications_block[0].payload = b64url_encode(
            serde_json::to_vec(&ModificationsBlockPayload {
                identity: "evil-ipx".to_string(),
                operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":9})],
                tag: msg.reformatted_data.tag.clone(),
            })
            .unwrap()
            .as_slice(),
        );

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
        assert!(!err.failed_modifications.is_empty());
    }

    /// CORE C7 PROPERTY: a modificationsBlock entry forged with the *shared
    /// symmetric session key* (HS256) — which both peers know — must be
    /// rejected. Only the SEPP's asymmetric (ES256) key may sign its entry.
    #[test]
    fn symmetric_key_forged_first_entry_rejected() {
        let (sender, receiver) = ctx_pair();

        // Build a legitimately-encrypted message, then REPLACE the first
        // (asymmetric) entry with one forged using the shared session key.
        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();

        let forged_payload = ModificationsBlockPayload {
            identity: SENDER_FQDN.to_string(),
            operations: Vec::new(),
            tag: msg.reformatted_data.tag.clone(),
        };
        // Attacker knows the symmetric JWE session key (it's shared between
        // both peers) and forges an HS256 JWS — this is exactly the pre-fix
        // forgery. The request-direction session key is what both peers share.
        let shared_key = *receiver.unprotect_key(N32fDirection::Request).0;
        let forged = jose::jws_sign(
            &shared_key,
            &serde_json::to_vec(&forged_payload).unwrap(),
            Some(SENDER_FQDN),
        )
        .unwrap();
        msg.modifications_block[0] = forged;

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        // The HS256 alg is refused outright for the modificationsBlock.
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
        assert!(err.detail.contains("non-asymmetric") || err.detail.contains("ES256"));
    }

    /// An entry from an entity whose public key is NOT registered must be
    /// rejected even if the ES256 signature is internally valid.
    #[test]
    fn unregistered_signer_rejected() {
        let (sender, receiver) = ctx_pair(); // does not know "rogue-ipx"
        let (rogue_sk, _rogue_vk) = es256_keypair();

        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        // sepp-08: a chained entry binds to the JWE tag, not the prior signature.
        let jwe_tag = msg.reformatted_data.tag.clone();
        let payload = ModificationsBlockPayload {
            identity: "rogue-ipx.example.com".to_string(),
            operations: Vec::new(),
            tag: jwe_tag,
        };
        let jws = jose::jws_sign_es256(
            &rogue_sk,
            &serde_json::to_vec(&payload).unwrap(),
            Some("rogue-ipx.example.com"),
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
        assert!(err.detail.contains("no registered key"));
    }

    /// An entry whose JWS `kid` (verified-against key) disagrees with the
    /// signed `identity` in the payload is rejected (identity binding).
    #[test]
    fn identity_kid_mismatch_rejected() {
        let (sender, mut receiver) = ctx_pair();
        let (ipx_sk, ipx_vk) = es256_keypair();
        // Register the IPX key under its real identity...
        receiver.register_verifying_key("ipx-real.example.com", ipx_vk);

        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        // sepp-08: a chained entry binds to the JWE tag, not the prior signature.
        let jwe_tag = msg.reformatted_data.tag.clone();
        // ...but the payload claims a DIFFERENT identity than the kid.
        let payload = ModificationsBlockPayload {
            identity: "someone-else.example.com".to_string(),
            operations: Vec::new(),
            tag: jwe_tag,
        };
        let jws = jose::jws_sign_es256(
            &ipx_sk,
            &serde_json::to_vec(&payload).unwrap(),
            Some("ipx-real.example.com"),
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
        assert!(err.detail.contains("identity"));
    }

    #[test]
    fn modification_chain_with_valid_allowed_patch_applies() {
        let (sender, mut receiver) = ctx_pair();
        receiver.modification_policy.allowed_paths = vec!["/nssai/sst".to_string()];

        // An IPX intermediary has its own asymmetric keypair; the receiver
        // must have its public key registered under the IPX identity.
        let (ipx_sk, ipx_vk) = es256_keypair();
        let ipx_id = "ipx1.example.com";
        receiver.register_verifying_key(ipx_id, ipx_vk);

        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();

        // The IPX appends a chained entry signed with ITS OWN asymmetric key
        // (kid = its identity FQDN), referencing the previous entry's sig.
        // sepp-08: a chained entry binds to the JWE tag, not the prior signature.
        let jwe_tag = msg.reformatted_data.tag.clone();
        let patch_payload = ModificationsBlockPayload {
            identity: ipx_id.to_string(),
            operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":7})],
            tag: jwe_tag,
        };
        let jws = jose::jws_sign_es256(
            &ipx_sk,
            &serde_json::to_vec(&patch_payload).unwrap(),
            Some(ipx_id),
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let rec = unprotect_message(&receiver, &msg).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["nssai"]["sst"], 7);
        // Encrypted IEs still restored
        assert_eq!(body["supi"], "imsi-001010000000001");
    }

    #[test]
    fn modification_violating_policy_rejected() {
        let (sender, mut receiver) = ctx_pair(); // empty policy: nothing modifiable

        // The IPX's key is registered (so the entry verifies) but the empty
        // policy must still reject the requested modification.
        let (ipx_sk, ipx_vk) = es256_keypair();
        let ipx_id = "ipx1.example.com";
        receiver.register_verifying_key(ipx_id, ipx_vk);

        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        // sepp-08: a chained entry binds to the JWE tag, not the prior signature.
        let jwe_tag = msg.reformatted_data.tag.clone();
        let patch_payload = ModificationsBlockPayload {
            identity: ipx_id.to_string(),
            operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":7})],
            tag: jwe_tag,
        };
        let jws = jose::jws_sign_es256(
            &ipx_sk,
            &serde_json::to_vec(&patch_payload).unwrap(),
            Some(ipx_id),
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::PolicyMismatch);
    }

    #[test]
    fn wrong_session_key_detected() {
        let (sender, mut receiver) = ctx_pair();
        // Give the receiver a DIFFERENT key hierarchy (different master), so
        // its request-direction session key no longer matches the sender's.
        receiver.key_material =
            crate::n32c_handler::derive_n32f_key_material(&[0x43u8; 64], "other-ctx");

        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let err = unprotect_message(&receiver, &msg).unwrap_err();
        // The modificationsBlock JWS now uses the *asymmetric* key, so the
        // chain check passes; the wrong symmetric session key is caught at
        // the JWE AEAD step instead.
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
    }

    #[test]
    fn unknown_context_id_rejected() {
        let (sender, mut receiver) = ctx_pair();
        receiver.local_context_id = "ctx-other-9999".to_string();

        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::UnavailablePrinsContext);
    }

    #[test]
    fn non_json_body_roundtrip() {
        let (sender, receiver) = ctx_pair();
        let raw = b"\x00\x01binary payload\xff";
        let msg =
            protect_message(&sender, "PUT", "/nsmf-pdusession/v1/sm", &[], Some(raw)).unwrap();
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.body.unwrap(), raw);
    }

    /// **Issue #99, criterion 4.** `N32fErrorInfo` must match TS 29.573 §6.1.5.4:
    /// `failedModificationList` is an array of `FailedModificationInfo` OBJECTS,
    /// `errorDetailsList` an array of `N32fErrorDetail` objects, and
    /// `n32fContextId` is carried.
    ///
    /// Both lists were `Vec<String>` before, so a conformant peer SEPP could not
    /// deserialise the report at all -- and this is emitted precisely when the N32
    /// link is already failing, so the malformed shape destroyed diagnosability at
    /// the worst possible moment.
    #[test]
    fn n32f_error_info_round_trips_the_spec_shape() {
        let err = N32fUnprotectError {
            error_type: N32fErrorType::IntegrityCheckFailed,
            message_id: Some("msg-7".into()),
            detail: "aad mismatch".into(),
            failed_modifications: vec!["ipx-a.example.com".into(), "ipx-b.example.com".into()],
        };
        let info = err.to_error_info(Some("ctx-42"));
        let json = serde_json::to_value(&info).expect("serialise");

        // camelCase members, per the yaml.
        assert_eq!(json["n32fMessageId"], "msg-7");
        assert_eq!(json["n32fContextId"], "ctx-42");

        // failedModificationList: OBJECTS, not strings.
        let mods = json["failedModificationList"].as_array().expect("array");
        assert_eq!(mods.len(), 2);
        assert!(
            mods[0].is_object(),
            "FailedModificationInfo must be an object, got {}",
            mods[0]
        );
        assert_eq!(mods[0]["ipxId"], "ipx-a.example.com");
        assert!(
            mods[0].get("n32fErrorType").is_some(),
            "each entry carries its own n32fErrorType"
        );

        // errorDetailsList: objects with msgReconstructFailReason.
        let details = json["errorDetailsList"].as_array().expect("array");
        assert_eq!(details.len(), 1);
        assert!(details[0].is_object(), "N32fErrorDetail must be an object");
        assert_eq!(details[0]["msgReconstructFailReason"], "aad mismatch");
        assert!(
            details[0].get("attribute").is_none(),
            "attribute is omitted, not fabricated, when the failing attribute is unknown"
        );

        // Round trip: a peer's deserialise of our bytes yields the same value.
        let back: N32fErrorInfo = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, info);
    }

    #[test]
    fn error_info_serialization_is_spec_shaped() {
        let err = N32fUnprotectError {
            error_type: N32fErrorType::DecipheringFailed,
            message_id: Some("abc123".to_string()),
            detail: "tag mismatch".to_string(),
            failed_modifications: vec![],
        };
        let info = err.to_error_info(Some("ctx-under-test"));
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["n32fMessageId"], "abc123");
        assert_eq!(json["n32fErrorType"], "DECIPHERING_FAILED");
    }

    /// Cross-stack: two SEPP contexts with MIRRORED roles (initiator/parallel
    /// vs responder/reverse) sharing one key hierarchy encrypt->decrypt a
    /// message successfully, and the four session keys are per-direction
    /// distinct (TS 33.501 §13.2.4.4.1).
    #[test]
    fn cross_stack_mirrored_roles_roundtrip_distinct_keys() {
        let (sender, receiver) = ctx_pair();
        assert_eq!(sender.role, N32fRole::Initiator);
        assert_eq!(receiver.role, N32fRole::Responder);

        // Encrypt with the initiator's (parallel) request key; the responder
        // decrypts by selecting the peer's (initiator/parallel) request key.
        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let rec = unprotect_message(&receiver, &msg).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001010000000001");

        // The protect key the initiator used == the unprotect key the
        // responder used for that message.
        assert_eq!(
            sender.protect_key(N32fDirection::Request).0,
            receiver.unprotect_key(N32fDirection::Request).0
        );

        // The four session keys are pairwise distinct per (role, direction).
        let km = &sender.key_material;
        assert_ne!(km.parallel_req.0, km.reverse_req.0);
        assert_ne!(km.parallel_req.0, km.parallel_resp.0);
        assert_ne!(km.reverse_req.0, km.reverse_resp.0);
        assert_ne!(km.parallel_resp.0, km.reverse_resp.0);

        // Per-direction key separation: the initiator's request key (parallel)
        // differs from the responder's request key (reverse).
        assert_ne!(
            sender.protect_key(N32fDirection::Request).0,
            receiver.protect_key(N32fDirection::Request).0
        );
    }

    // ------------------------------------------------------------------
    // sepp-03: RequestLine (method/scheme/authority/path/protocolVersion)
    // ------------------------------------------------------------------

    /// A GET-with-query protects then unprotects back to the identical
    /// method+URL; the serialized RequestLine carries scheme/authority/path/
    /// protocolVersion:"2" and no `url`/"HTTP/2".
    #[test]
    fn request_line_roundtrips_get_with_query() {
        let (sender, receiver) = ctx_pair();
        let url = "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&limit=10";

        let msg = protect_message(&sender, "GET", url, &[], None).unwrap();

        // The reformatted RequestLine is spec-shaped, not the legacy url/proto.
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(aad_str.contains("\"scheme\""));
        assert!(aad_str.contains("\"authority\""));
        assert!(aad_str.contains("\"path\":\"/nnrf-disc/v1/nf-instances\""));
        assert!(aad_str.contains("\"protocolVersion\":\"2\""));
        assert!(aad_str.contains("\"queryFragment\":\"target-nf-type=AMF&limit=10\""));
        assert!(!aad_str.contains("\"url\""));
        assert!(!aad_str.contains("HTTP/2"));

        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.method, "GET");
        assert_eq!(rec.url, url, "URL must round-trip identically");
    }

    /// An absolute SBI URL round-trips through scheme/authority/path/query.
    #[test]
    fn request_line_roundtrips_absolute_url() {
        let (sender, receiver) = ctx_pair();
        let url = "https://nrf.example.com:8443/nnrf-disc/v1/nf-instances?nf-type=UDM";
        let msg = protect_message(&sender, "GET", url, &[], None).unwrap();
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(aad_str.contains("\"scheme\":\"https\""));
        assert!(aad_str.contains("\"authority\":\"nrf.example.com:8443\""));
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.url, url);
    }

    // ------------------------------------------------------------------
    // sepp-04: HttpPayload RFC 6901 leaf pointers + IeLocation enum
    // ------------------------------------------------------------------

    /// A nested body protects to leaf pointers `/a/supi` (encrypted ref) and
    /// `/x` (cleartext), and unprotects byte-identically.
    #[test]
    fn nested_body_flattens_to_leaf_pointers_and_roundtrips() {
        let (mut sender, receiver) = ctx_pair();
        // Designate the nested `/a/supi` IE for encryption on this service.
        sender.profiles = vec![DataTypeProfile {
            id: "myapi-profile".to_string(),
            service_name: "myapi".to_string(),
            encrypt_ies: vec![IeDescriptor {
                location: "BODY".to_string(),
                path: "/a/supi".to_string(),
            }],
        }];

        let body = serde_json::json!({ "a": { "supi": "imsi-1" }, "x": 1 });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let msg = protect_message(&sender, "POST", "/myapi/v1/r", &[], Some(&body_bytes)).unwrap();

        // AAD payload carries leaf pointers; the encrypted leaf is an
        // encBlockIndex ref and the SUPI value is absent from cleartext.
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad).unwrap();
        let enc = block
            .payload
            .iter()
            .find(|e| e.ie_path == "/a/supi")
            .expect("/a/supi leaf present");
        assert_eq!(enc.ie_value_location, IeLocation::Body);
        assert!(enc.value.get("encBlockIndex").is_some());
        let clear = block
            .payload
            .iter()
            .find(|e| e.ie_path == "/x")
            .expect("/x leaf present");
        assert_eq!(clear.value, serde_json::json!(1));
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(!aad_str.contains("imsi-1"), "SUPI must not be in cleartext");

        // Byte-identical reconstruction.
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.body.unwrap(), body_bytes);
    }

    /// A malformed (non-RFC-6901) iePath in an authenticated payload is
    /// rejected on unprotect with an INVALID_JSON_POINTER-style error.
    #[test]
    fn malformed_json_pointer_rejected_on_unprotect() {
        let (sender, receiver) = ctx_pair();
        // Hand-build a message whose AAD carries a malformed iePath, sealed
        // under the real session key (so it survives the AEAD check and
        // reaches reconstruction).
        let integrity_block = DataToIntegrityProtectBlock {
            meta_data: N32fMetaData {
                n32f_context_id: sender.peer_context_id.clone(),
                message_id: "deadbeefdeadbeef".to_string(),
                authorized_ipx_id: AUTHORIZED_IPX_ID_NONE.to_string(),
                sender_plmn_id: None,
            },
            request_line: Some(build_request_line("POST", "/nudm-sdm/v1/supi")),
            status_line: None,
            headers: vec![],
            payload: vec![N32fPayloadElement {
                ie_path: "not-a-pointer".to_string(),
                ie_value_location: IeLocation::Body,
                value: serde_json::json!(1),
            }],
        };
        let aad = serde_json::to_vec(&integrity_block).unwrap();
        let cipher = DataToIntegrityProtectAndCipherBlock::default();
        let plaintext = serde_json::to_vec(&cipher).unwrap();
        let (key, salt) = sender.protect_key(N32fDirection::Request);
        let jwe = jose::jwe_encrypt_with_iv_salt(
            key,
            sender.jwe_enc,
            salt,
            0,
            &plaintext,
            Some(&aad),
            Some(&sender.kid),
        )
        .unwrap();
        let signing_key = sender.local_signing_key.clone().unwrap();
        let mods_payload = ModificationsBlockPayload {
            identity: sender.local_fqdn.clone(),
            operations: vec![],
            tag: jwe.tag.clone(),
        };
        let mods_bytes = serde_json::to_vec(&mods_payload).unwrap();
        let jws =
            jose::jws_sign_es256(&signing_key, &mods_bytes, Some(&sender.local_fqdn)).unwrap();
        let msg = N32fReformattedMessage {
            reformatted_data: jwe,
            modifications_block: vec![jws],
        };

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::MessageReconstructionFailed);
        assert!(
            err.detail.contains("INVALID_JSON_POINTER"),
            "got: {}",
            err.detail
        );
    }

    /// `set_at_json_pointer` creates intermediates, replaces whole-document on
    /// empty pointer, and rejects a malformed pointer.
    #[test]
    fn set_at_json_pointer_behaviour() {
        let mut root = serde_json::Value::Null;
        set_at_json_pointer(&mut root, "/a/b", serde_json::json!(7)).unwrap();
        assert_eq!(root, serde_json::json!({ "a": { "b": 7 } }));

        let mut whole = serde_json::json!({ "x": 1 });
        set_at_json_pointer(&mut whole, "", serde_json::json!("scalar")).unwrap();
        assert_eq!(whole, serde_json::json!("scalar"));

        let mut bad = serde_json::Value::Null;
        assert!(set_at_json_pointer(&mut bad, "no-slash", serde_json::json!(1)).is_err());
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("/nudm-sdm/v1/supi"), "nudm-sdm");
        assert_eq!(
            extract_service_name("/nausf-auth/v1/ue-authentications"),
            "nausf-auth"
        );
        assert_eq!(extract_service_name(""), "");
    }

    // ------------------------------------------------------------------
    // sepp-02: nonce = IV salt || SEQ + receive-side replay window
    // ------------------------------------------------------------------

    /// Two messages under the same context+direction get SEQ 0 then 1 (same IV
    /// salt, incrementing SEQ), so the JWE nonces differ.
    #[test]
    fn protect_increments_seq_per_message() {
        let (sender, _receiver) = ctx_pair();
        let m0 = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let m1 = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let (s0, seq0) = jose::jwe_iv_salt_and_seq(&m0.reformatted_data).unwrap();
        let (s1, seq1) = jose::jwe_iv_salt_and_seq(&m1.reformatted_data).unwrap();
        assert_eq!(s0, s1, "same IV salt for the same (role, direction)");
        assert_eq!(seq0, 0, "SEQ starts at 0");
        assert_eq!(seq1, 1, "SEQ increments per encryption");
    }

    /// A replayed N32-f message (received twice) is rejected with
    /// IntegrityCheckFailed on the second receive (anti-replay window).
    #[test]
    fn replayed_message_rejected() {
        let (sender, receiver) = ctx_pair();
        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        // First receive succeeds and commits the SEQ.
        assert!(unprotect_message(&receiver, &msg).is_ok());
        // Replay of the identical message is rejected.
        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
        assert!(err.detail.contains("replay"), "got: {}", err.detail);
    }

    // ------------------------------------------------------------------
    // sepp-06: HttpHeader field `header` + EncodedHttpHeaderValue
    // ------------------------------------------------------------------

    /// Header JSON uses key `header`; a value routed to the encrypted block
    /// serializes as `{ "encBlockIndex": i }`.
    #[test]
    fn http_header_serialization_uses_header_key_and_encoded_value() {
        let plain = HttpHeader {
            header: "content-type".to_string(),
            value: EncodedHttpHeaderValue::Plain("application/json".to_string()),
        };
        let j = serde_json::to_value(&plain).unwrap();
        assert!(j.get("header").is_some(), "field key must be `header`");
        assert_eq!(j["header"], "content-type");
        assert_eq!(j["value"], "application/json");

        let enc = HttpHeader {
            header: "authorization".to_string(),
            value: EncodedHttpHeaderValue::Encrypted { enc_block_index: 2 },
        };
        let je = serde_json::to_value(&enc).unwrap();
        assert_eq!(je["value"], serde_json::json!({ "encBlockIndex": 2 }));
    }

    /// A header round-trips, and the reformatted AAD uses the `header` key
    /// (not `name`).
    #[test]
    fn header_roundtrips_and_aad_uses_header_key() {
        let (sender, receiver) = ctx_pair();
        let headers = vec![("x-custom".to_string(), "v1".to_string())];
        let msg = protect_message(&sender, "GET", "/nnrf-disc/v1/x", &headers, None).unwrap();
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(aad_str.contains("\"header\":\"x-custom\""));
        assert!(!aad_str.contains("\"name\":\"x-custom\""));
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.headers.get("x-custom").unwrap(), "v1");
    }

    /// An encrypted header value (`{encBlockIndex}`) is resolved from the
    /// cipher block on unprotect (sepp-06 reconstruction path).
    #[test]
    fn encrypted_header_value_resolved_on_unprotect() {
        let (sender, receiver) = ctx_pair();
        let mut cipher = DataToIntegrityProtectAndCipherBlock::default();
        cipher
            .data_to_encrypt
            .push(serde_json::json!("Bearer secret-token"));
        let integrity_block = DataToIntegrityProtectBlock {
            meta_data: N32fMetaData {
                n32f_context_id: sender.peer_context_id.clone(),
                message_id: "feedface".to_string(),
                authorized_ipx_id: AUTHORIZED_IPX_ID_NONE.to_string(),
                sender_plmn_id: None,
            },
            request_line: Some(build_request_line("GET", "/nudm-sdm/v1/supi")),
            status_line: None,
            headers: vec![HttpHeader {
                header: "authorization".to_string(),
                value: EncodedHttpHeaderValue::Encrypted { enc_block_index: 0 },
            }],
            payload: vec![],
        };
        let aad = serde_json::to_vec(&integrity_block).unwrap();
        let plaintext = serde_json::to_vec(&cipher).unwrap();
        let (key, salt) = sender.protect_key(N32fDirection::Request);
        let jwe = jose::jwe_encrypt_with_iv_salt(
            key,
            sender.jwe_enc,
            salt,
            0,
            &plaintext,
            Some(&aad),
            Some(&sender.kid),
        )
        .unwrap();
        let signing_key = sender.local_signing_key.clone().unwrap();
        let mods_payload = ModificationsBlockPayload {
            identity: sender.local_fqdn.clone(),
            operations: vec![],
            tag: jwe.tag.clone(),
        };
        let jws = jose::jws_sign_es256(
            &signing_key,
            &serde_json::to_vec(&mods_payload).unwrap(),
            Some(&sender.local_fqdn),
        )
        .unwrap();
        let msg = N32fReformattedMessage {
            reformatted_data: jwe,
            modifications_block: vec![jws],
        };
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(
            rec.headers.get("authorization").unwrap(),
            "Bearer secret-token"
        );
    }

    // ------------------------------------------------------------------
    // sepp-07: MetaData.authorizedIpxId always serialized, default "NULL"
    // ------------------------------------------------------------------
    #[test]
    fn metadata_authorized_ipx_id_defaults_to_null_and_roundtrips() {
        let (sender, receiver) = ctx_pair();
        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad).unwrap();
        assert_eq!(block.meta_data.authorized_ipx_id, "NULL");
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(
            aad_str.contains("\"authorizedIpxId\":\"NULL\""),
            "authorizedIpxId must always be serialized as NULL"
        );
        assert!(unprotect_message(&receiver, &msg).is_ok());
    }

    // ------------------------------------------------------------------
    // sepp-08: modificationsBlock tag binds to the JWE Authentication Tag
    // ------------------------------------------------------------------
    #[test]
    fn modifications_entries_bind_to_jwe_tag_not_chain() {
        let (sender, mut receiver) = ctx_pair();
        receiver.modification_policy.allowed_paths = vec!["/nssai/sst".to_string()];
        let (ipx_sk, ipx_vk) = es256_keypair();
        let ipx_id = "ipx-bind.example.com";
        receiver.register_verifying_key(ipx_id, ipx_vk);

        // A 2nd entry whose tag is the JWE tag (NOT the prior signature) passes.
        let mut msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let patch = ModificationsBlockPayload {
            identity: ipx_id.to_string(),
            operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":5})],
            tag: msg.reformatted_data.tag.clone(),
        };
        let jws = jose::jws_sign_es256(&ipx_sk, &serde_json::to_vec(&patch).unwrap(), Some(ipx_id))
            .unwrap();
        msg.modifications_block.push(jws);
        let rec = unprotect_message(&receiver, &msg).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["nssai"]["sst"], 5);

        // An entry carrying a WRONG tag is rejected.
        let mut msg2 = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let bad = ModificationsBlockPayload {
            identity: ipx_id.to_string(),
            operations: vec![],
            tag: "not-the-jwe-tag".to_string(),
        };
        let jws_bad =
            jose::jws_sign_es256(&ipx_sk, &serde_json::to_vec(&bad).unwrap(), Some(ipx_id))
                .unwrap();
        msg2.modifications_block.push(jws_bad);
        let err = unprotect_message(&receiver, &msg2).unwrap_err();
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
    }

    // ------------------------------------------------------------------
    // sepp-09: PLMN-ID consistency check on the received N32-f message
    // ------------------------------------------------------------------
    #[test]
    fn plmn_id_consistency_checked_on_receive() {
        // Matching PLMN: sender stamps 999-70, receiver binds 999-70 => OK.
        let (mut sender, mut receiver) = ctx_pair();
        sender.local_plmn_ids = vec![PlmnId::new(999, 70, 2)];
        receiver.peer_plmn_ids = vec![PlmnId::new(999, 70, 2)];
        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        assert!(unprotect_message(&receiver, &msg).is_ok());

        // Mismatching PLMN: sender stamps 999-70, receiver binds 001-01 => reject.
        let (mut sender2, mut receiver2) = ctx_pair();
        sender2.local_plmn_ids = vec![PlmnId::new(999, 70, 2)];
        receiver2.peer_plmn_ids = vec![PlmnId::new(1, 1, 2)];
        let msg2 = protect_message(
            &sender2,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        let err = unprotect_message(&receiver2, &msg2).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::PolicyMismatch);

        // No binding (receiver has no peer PLMNs) => check skipped (compat).
        let (mut sender3, receiver3) = ctx_pair();
        sender3.local_plmn_ids = vec![PlmnId::new(999, 70, 2)];
        let msg3 = protect_message(
            &sender3,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        assert!(unprotect_message(&receiver3, &msg3).is_ok());
    }

    // ------------------------------------------------------------------
    // sepp-12: PrinsContext negotiated to A128GCM round-trips
    // ------------------------------------------------------------------
    #[test]
    fn prins_roundtrip_under_a128gcm() {
        let (mut sender, mut receiver) = ctx_pair();
        sender.jwe_enc = JweEnc::A128Gcm;
        receiver.jwe_enc = JweEnc::A128Gcm; // enc is also read from the header
        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &[],
            Some(&sample_body()),
        )
        .unwrap();
        // The JWE header advertises A128GCM.
        let hdr = b64url_decode(&msg.reformatted_data.protected).unwrap();
        assert!(String::from_utf8(hdr).unwrap().contains("A128GCM"));
        let rec = unprotect_message(&receiver, &msg).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001010000000001");
    }
}
