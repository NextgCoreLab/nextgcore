//! Subscription Database Queries
//!
//! Provides functions for querying and updating subscriber data.
//! Ported from lib/dbi/subscription.c in the C implementation.

use mongodb::bson::{doc, Bson, Document};
use nextgcore_crypt::milenage::milenage_opc;
use serde::{Deserialize, Serialize};

use crate::mongoc::{get_subscriber_collection, DbiError, DbiResult};
use crate::types::*;

/// Authentication information from database
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct NextgcoreDbiAuthInfo {
    pub k: [u8; NEXTGCORE_KEY_LEN],
    pub use_opc: bool,
    pub opc: [u8; NEXTGCORE_KEY_LEN],
    pub op: [u8; NEXTGCORE_KEY_LEN],
    pub amf: [u8; NEXTGCORE_AMF_LEN],
    pub rand: [u8; NEXTGCORE_RAND_LEN],
    pub sqn: u64,
    /// Provisioned authentication method (TS 29.505 AuthMethod), e.g. "5G_AKA"
    /// or "EAP_AKA_PRIME". Empty for subscriber docs provisioned before this
    /// field existed; the UDR GET builder then defaults to "5G_AKA".
    pub authentication_method: String,
    /// TS 29.505 `algorithmId` (#115): which f1-f5* parameter set generates this
    /// subscriber's authentication vectors. Empty when not provisioned, which the UDM
    /// treats as MILENAGE — the behaviour every existing subscriber already has.
    pub algorithm_id: String,
    /// TUAK TOPc (TS 35.231 §6.1), 256-bit. Populated iff `use_topc`.
    pub topc: [u8; 32],
    /// TUAK TOP, 256-bit, from which TOPc is derived when only TOP is provisioned.
    pub top: [u8; 32],
    /// Whether `topc` holds usable material.
    ///
    /// The same shape as `use_opc`, and for the same reason: a consumer must be able to
    /// tell "no TUAK operator field provisioned" from "an all-zero one", because the
    /// second would silently authenticate against the wrong key rather than failing.
    pub use_topc: bool,
}

/// Manual `Debug` (no-auth-material-in-logs): the authentication material in
/// this type (k, opc, op, rand, sqn, topc, top) prints as `<redacted>`, so a future
/// `{:?}` in a log line cannot leak it.
impl std::fmt::Debug for NextgcoreDbiAuthInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("NextgcoreDbiAuthInfo");
        d.field("k", &"<redacted>");
        d.field("use_opc", &self.use_opc);
        d.field("opc", &"<redacted>");
        d.field("op", &"<redacted>");
        d.field("amf", &self.amf);
        d.field("rand", &"<redacted>");
        d.field("sqn", &"<redacted>");
        d.field("authentication_method", &self.authentication_method);
        d.field("algorithm_id", &self.algorithm_id);
        d.field("topc", &"<redacted>");
        d.field("top", &"<redacted>");
        d.field("use_topc", &self.use_topc);
        d.finish()
    }
}

/// Get authentication info for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier (e.g., "imsi-123456789012345")
///
/// # Returns
/// * `Ok(NextgcoreDbiAuthInfo)` with authentication data
/// * `Err(DbiError)` on failure
pub fn nextgcore_dbi_auth_info(supi: &str) -> DbiResult<NextgcoreDbiAuthInfo> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    #[cfg(any(test, feature = "test-helpers"))]
    if crate::test_store::active() {
        return crate::test_store::auth_info(supi);
    }

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    let security = document
        .get_document(NEXTGCORE_SECURITY_STRING)
        .map_err(|_| DbiError::FieldNotFound(NEXTGCORE_SECURITY_STRING.to_string()))?;

    Ok(parse_auth_info(security, supi))
}

/// Parses a subscriber's `security` sub-document into [`NextgcoreDbiAuthInfo`].
///
/// Split out of [`nextgcore_dbi_auth_info`] so the OPc-derivation invariant is
/// reachable in tests: that function reaches MongoDB, and its `test_store`
/// short-circuit returns a pre-built struct without ever running this parse.
pub(crate) fn parse_auth_info(security: &Document, supi: &str) -> NextgcoreDbiAuthInfo {
    let mut auth_info = NextgcoreDbiAuthInfo::default();
    let mut has_op = false;

    // Parse K
    if let Ok(k_str) = security.get_str(NEXTGCORE_K_STRING) {
        nextgcore_ascii_to_hex(k_str, &mut auth_info.k);
    }

    // Parse OPc
    if let Ok(opc_str) = security.get_str(NEXTGCORE_OPC_STRING) {
        auth_info.use_opc = true;
        nextgcore_ascii_to_hex(opc_str, &mut auth_info.opc);
    }

    // Parse OP
    if let Ok(op_str) = security.get_str(NEXTGCORE_OP_STRING) {
        nextgcore_ascii_to_hex(op_str, &mut auth_info.op);
        has_op = true;
    }

    // Derive OPc from (K, OP) when only OP was provisioned.
    //
    // OPc = OP XOR E_K(OP) (TS 33.102 Annex C.4). MILENAGE must be driven with
    // OPc, never with OP (TS 33.501 §6.1), and `encOpcKey` carries the OPc
    // (TS 29.505 §5.4.2.4).
    //
    // Deriving HERE rather than at each consumer makes `opc` an invariant of
    // this struct: whenever key material was provisioned at all, `opc` holds a
    // usable OPc and `use_opc` is true. That is what stops a consumer from
    // serving the raw OP by omitting a derivation step -- which is exactly the
    // bug this fixes: nextgcore-udrd emitted
    // `if use_opc { opc } else { op }` into encOpcKey, so an OP-only
    // subscriber authenticated with OP as its OPc and 5G-AKA failed.
    // nextgcore-hssd already derived correctly on all three Diameter paths
    // (swx_path.rs:259, cx_path.rs:173, s6a_path.rs:314); only the 5G path
    // skipped it. Those sites still work -- their `if use_opc` branch now
    // simply always takes the provisioned arm.
    //
    // An explicitly provisioned OPc is never overwritten: provisioning wins,
    // because deriving over operator-supplied material would silently discard
    // it. `op` stays populated for any other reader.
    if !auth_info.use_opc && has_op {
        match milenage_opc(&auth_info.k, &auth_info.op) {
            Ok(opc) => {
                auth_info.opc = opc;
                auth_info.use_opc = true;
            }
            Err(e) => {
                // Leave use_opc false rather than fall back to OP: a consumer
                // seeing no OPc fails authentication, which is the correct
                // outcome. Serving OP would authenticate against the wrong key.
                log::error!(
                    "OPc derivation from OP failed for {supi}: {e:?}. \
                     Authentication will fail for this subscriber -- \
                     provision opc directly, or fix the k/op values."
                );
            }
        }
    }

    // Parse AMF
    if let Ok(amf_str) = security.get_str(NEXTGCORE_AMF_STRING) {
        nextgcore_ascii_to_hex(amf_str, &mut auth_info.amf);
    }

    // Parse RAND
    if let Ok(rand_str) = security.get_str(NEXTGCORE_RAND_STRING) {
        nextgcore_ascii_to_hex(rand_str, &mut auth_info.rand);
    }

    // Parse SQN
    if let Ok(sqn) = security.get_i64(NEXTGCORE_SQN_STRING) {
        auth_info.sqn = sqn as u64;
    }

    // Parse authenticationMethod (TS 29.505 AuthMethod). Absent in legacy
    // subscriber docs -> left empty and defaulted by the UDR GET builder.
    if let Ok(m) = security.get_str(NEXTGCORE_AUTH_METHOD_STRING) {
        auth_info.authentication_method = m.to_string();
    }

    // #115: TS 29.505 algorithmId, opaque. Absent for every subscriber provisioned
    // before TUAK existed, which the UDM reads as MILENAGE.
    if let Ok(id) = security.get_str(NEXTGCORE_ALGORITHM_ID_STRING) {
        auth_info.algorithm_id = id.to_string();
    }

    // #115: the TUAK operator field. TOPc directly if provisioned, otherwise derived
    // from TOP and K — the same precedence as OPc/OP above, and for the same reason:
    // provisioning wins, because deriving over operator-supplied material would discard
    // it, and serving TOP where TOPc is wanted would authenticate against the wrong key.
    if let Ok(topc_str) = security.get_str(NEXTGCORE_TOPC_STRING) {
        nextgcore_ascii_to_hex(topc_str, &mut auth_info.topc);
        auth_info.use_topc = true;
    }
    if let Ok(top_str) = security.get_str(NEXTGCORE_TOP_STRING) {
        nextgcore_ascii_to_hex(top_str, &mut auth_info.top);
        if !auth_info.use_topc {
            match nextgcore_crypt::tuak::tuak_topc(&auth_info.top, &auth_info.k, 1) {
                Ok(topc) => {
                    auth_info.topc = topc;
                    auth_info.use_topc = true;
                }
                Err(e) => log::error!(
                    "TUAK TOPc derivation from TOP failed for {supi}: {e}. TUAK \
                     authentication will fail for this subscriber -- provision topc \
                     directly, or fix the k/top values."
                ),
            }
        }
    }

    auth_info
}

/// Update SQN for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
/// * `sqn` - New sequence number
pub fn nextgcore_dbi_update_sqn(supi: &str, sqn: u64) -> DbiResult<()> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    #[cfg(any(test, feature = "test-helpers"))]
    if crate::test_store::active() {
        return crate::test_store::update_sqn(supi, sqn);
    }

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };
    let update = doc! {
        "$set": {
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_SQN_STRING): sqn as i64
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Increment SQN for a subscriber (by 32, with 48-bit wrap)
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
pub fn nextgcore_dbi_increment_sqn(supi: &str) -> DbiResult<()> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    #[cfg(any(test, feature = "test-helpers"))]
    if crate::test_store::active() {
        return crate::test_store::inc_sqn(supi);
    }

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    // Increment by 32
    let update_inc = doc! {
        "$inc": {
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_SQN_STRING): 32_i64
        }
    };
    collection.update_one(query.clone(), update_inc, None)?;

    // Apply 48-bit mask using bitwise AND
    let update_bit = doc! {
        "$bit": {
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_SQN_STRING): {
                "and": NEXTGCORE_MAX_SQN as i64
            }
        }
    };
    collection.update_one(query, update_bit, None)?;

    Ok(())
}

/// Update IMEISV for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
/// * `imeisv` - IMEISV string
pub fn nextgcore_dbi_update_imeisv(supi: &str, imeisv: &str) -> DbiResult<()> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    log::debug!("SUPI type: {supi_type}, SUPI id: {supi_id}, imeisv: {imeisv}");

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };
    let update = doc! {
        "$set": {
            NEXTGCORE_IMEISV_STRING: imeisv
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Authentication credentials for provisioning a subscriber.
///
/// Used by the UDR `PUT
/// /subscription-data/{ueId}/authentication-data/authentication-subscription`
/// provisioning path (TS 29.505) to create or replace the stored
/// AuthenticationSubscription credentials.
#[derive(Clone, Default)]
pub struct NextgcoreDbiAuthProvision {
    /// Permanent key K as a hex string (32 hex chars)
    pub k_hex: String,
    /// OPc as a hex string, if provisioned
    pub opc_hex: Option<String>,
    /// OP as a hex string, if provisioned
    pub op_hex: Option<String>,
    /// Authentication Management Field as a hex string (4 hex chars)
    pub amf_hex: String,
    /// Initial sequence number
    pub sqn: u64,
    /// Authentication method (TS 29.505 AuthMethod), e.g. "5G_AKA" / "EAP_AKA_PRIME".
    pub auth_method: String,
    /// TS 29.505 `algorithmId` (#115), opaque and operator-specific.
    pub algorithm_id: Option<String>,
    /// TS 29.505 `encTopcKey`: TUAK TOPc as 64 hex characters.
    pub topc_hex: Option<String>,
    /// TUAK TOP as 64 hex characters, when TOPc is not provisioned directly.
    pub top_hex: Option<String>,
}

/// Manual `Debug` (no-auth-material-in-logs): the authentication material in
/// this type (k_hex, opc_hex, op_hex, sqn, topc_hex, top_hex) prints as `<redacted>`, so a future
/// `{:?}` in a log line cannot leak it.
impl std::fmt::Debug for NextgcoreDbiAuthProvision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("NextgcoreDbiAuthProvision");
        d.field("k_hex", &"<redacted>");
        d.field("opc_hex", &"<redacted>");
        d.field("op_hex", &"<redacted>");
        d.field("amf_hex", &self.amf_hex);
        d.field("sqn", &"<redacted>");
        d.field("auth_method", &self.auth_method);
        d.field("algorithm_id", &self.algorithm_id);
        d.field("topc_hex", &"<redacted>");
        d.field("top_hex", &"<redacted>");
        d.finish()
    }
}

/// Create or replace the authentication subscription for a subscriber.
///
/// Upserts the `security` sub-document of the subscriber document. Returns
/// `Ok(true)` when a new subscriber document was created (HTTP 201 path) and
/// `Ok(false)` when an existing document was updated (HTTP 204 path).
pub fn nextgcore_dbi_provision_auth_info(
    supi: &str,
    p: &NextgcoreDbiAuthProvision,
) -> DbiResult<bool> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    #[cfg(any(test, feature = "test-helpers"))]
    if crate::test_store::active() {
        return crate::test_store::provision_auth_info(supi, p);
    }

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    let mut set = doc! {
        format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_K_STRING): &p.k_hex,
        format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_AMF_STRING): &p.amf_hex,
        format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_SQN_STRING): p.sqn as i64,
        format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_AUTH_METHOD_STRING): &p.auth_method,
    };
    if let Some(opc) = &p.opc_hex {
        set.insert(
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_OPC_STRING),
            opc.as_str(),
        );
    }
    if let Some(op) = &p.op_hex {
        set.insert(
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_OP_STRING),
            op.as_str(),
        );
    }
    // #115
    if let Some(id) = &p.algorithm_id {
        set.insert(
            format!(
                "{}.{}",
                NEXTGCORE_SECURITY_STRING, NEXTGCORE_ALGORITHM_ID_STRING
            ),
            id.as_str(),
        );
    }
    if let Some(topc) = &p.topc_hex {
        set.insert(
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_TOPC_STRING),
            topc.as_str(),
        );
    }
    if let Some(top) = &p.top_hex {
        set.insert(
            format!("{}.{}", NEXTGCORE_SECURITY_STRING, NEXTGCORE_TOP_STRING),
            top.as_str(),
        );
    }

    let opts = mongodb::options::UpdateOptions::builder()
        .upsert(true)
        .build();
    let result = collection.update_one(query, doc! { "$set": set }, opts)?;
    Ok(result.upserted_id.is_some())
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_provision_auth_info`].
pub async fn nextgcore_dbi_provision_auth_info_async(
    supi: String,
    p: NextgcoreDbiAuthProvision,
) -> DbiResult<bool> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_provision_auth_info(&supi, &p))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Update MME information for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
/// * `mme_host` - MME host name
/// * `mme_realm` - MME realm
/// * `purge_flag` - Purge flag
pub fn nextgcore_dbi_update_mme(
    supi: &str,
    mme_host: &str,
    mme_realm: &str,
    purge_flag: bool,
) -> DbiResult<()> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    log::debug!(
        "SUPI type: {supi_type}, SUPI id: {supi_id}, mme_host: {mme_host}, mme_realm: {mme_realm}"
    );

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);

    let update = doc! {
        "$set": {
            NEXTGCORE_MME_HOST_STRING: mme_host,
            NEXTGCORE_MME_REALM_STRING: mme_realm,
            NEXTGCORE_MME_TIMESTAMP_STRING: timestamp,
            NEXTGCORE_PURGE_FLAG_STRING: purge_flag
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Get full subscription data for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
pub fn nextgcore_dbi_subscription_data(supi: &str) -> DbiResult<NextgcoreSubscriptionData> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    // #87: the mirror answers only when a test has provisioned identities or
    // subscriber documents, so enabling the store for the authentication tests
    // leaves every other handler's view of the subscriber DB unchanged. #1526: the
    // identity and the document are one subscriber, merged as Mongo's single
    // document would be (`test_store::subscription_data`).
    #[cfg(any(test, feature = "test-helpers"))]
    if crate::test_store::identities_active() || crate::test_store::documents_active() {
        return crate::test_store::subscription_data(supi);
    }

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    Ok(parse_subscription_document(&document))
}

/// The [`NextgcoreSubscriptionData`] of one `subscribers` document, shared by the
/// Mongo read and the test mirror's document store.
pub(crate) fn parse_subscription_document(document: &Document) -> NextgcoreSubscriptionData {
    let mut subscription_data = NextgcoreSubscriptionData::new();

    // Parse IMSI
    if let Ok(imsi) = document.get_str(NEXTGCORE_IMSI_STRING) {
        subscription_data.imsi = Some(imsi.to_string());
    }

    // Parse MSISDN array
    if let Ok(msisdn_array) = document.get_array(NEXTGCORE_MSISDN_STRING) {
        for msisdn_val in msisdn_array {
            if subscription_data.num_of_msisdn >= NEXTGCORE_MAX_NUM_OF_MSISDN {
                break;
            }
            if let Bson::String(bcd) = msisdn_val {
                let mut msisdn = NextgcoreMsisdn::default();
                msisdn.bcd = bcd.clone();
                nextgcore_bcd_to_buffer(bcd, &mut msisdn.buf);
                msisdn.len = msisdn.buf.len();
                subscription_data.msisdn.push(msisdn);
                subscription_data.num_of_msisdn += 1;
            }
        }
    }

    // Parse the External Identifier(s) (nextgsim#480): a string or an array.
    subscription_data.external_ids = parse_external_ids(document);

    // Parse access restriction data
    if let Ok(ard) = document.get_i32(NEXTGCORE_ACCESS_RESTRICTION_DATA_STRING) {
        subscription_data.access_restriction_data = ard;
    }

    // Parse subscriber status
    if let Ok(ss) = document.get_i32(NEXTGCORE_SUBSCRIBER_STATUS_STRING) {
        subscription_data.subscriber_status = ss;
    }

    // Parse operator determined barring
    if let Ok(odb) = document.get_i32(NEXTGCORE_OPERATOR_DETERMINED_BARRING_STRING) {
        subscription_data.operator_determined_barring = odb;
    }

    // Parse network access mode
    if let Ok(nam) = document.get_i32(NEXTGCORE_NETWORK_ACCESS_MODE_STRING) {
        subscription_data.network_access_mode = nam;
    }

    // Parse subscribed RAU/TAU timer
    if let Ok(timer) = document.get_i32(NEXTGCORE_SUBSCRIBED_RAU_TAU_TIMER_STRING) {
        subscription_data.subscribed_rau_tau_timer = timer;
    }

    // Parse AMBR
    if let Ok(ambr_doc) = document.get_document(NEXTGCORE_AMBR_STRING) {
        subscription_data.ambr = parse_ambr(ambr_doc);
    }

    // Parse subscribed 3GPP-Charging-Characteristics (#56). Read verbatim: this
    // layer does not know the S6a wire format, and validating here would reject a
    // value the S6a layer might still be able to use.
    if let Ok(cc) = document.get_str(NEXTGCORE_CHARGING_CHARACTERISTICS_STRING) {
        if !cc.trim().is_empty() {
            subscription_data.charging_characteristics = Some(cc.to_string());
        }
    }

    // #2260: the Ranging/SL privacy profile, a sub-document or its JSON text.
    subscription_data.ranging_sl_privacy = match document.get(NEXTGCORE_RANGING_SL_PRIVACY_STRING) {
        Some(mongodb::bson::Bson::Document(d)) => Some(
            mongodb::bson::Bson::Document(d.clone())
                .into_relaxed_extjson()
                .to_string(),
        ),
        Some(mongodb::bson::Bson::String(t)) if !t.trim().is_empty() => Some(t.clone()),
        _ => None,
    };

    // Parse slice array
    parse_subscribed_slices(document, &mut subscription_data);

    // Parse MME host
    if let Ok(mme_host) = document.get_str(NEXTGCORE_MME_HOST_STRING) {
        subscription_data.mme_host = Some(mme_host.to_string());
    }

    // Parse MME realm
    if let Ok(mme_realm) = document.get_str(NEXTGCORE_MME_REALM_STRING) {
        subscription_data.mme_realm = Some(mme_realm.to_string());
    }

    // Parse purge flag
    if let Ok(purge_flag) = document.get_bool(NEXTGCORE_PURGE_FLAG_STRING) {
        subscription_data.purge_flag = purge_flag;
    }

    subscription_data
}

// ============================================================================
// Async (non-blocking) wrappers
// ============================================================================
//
// The functions above call the *synchronous* MongoDB driver (`find_one`,
// `update_one`), which blocks the calling thread on network I/O. When invoked
// from an `async fn` running on a tokio worker thread (e.g. UDR/NSSF SBI
// handlers during the 5G-AKA auth flow), that blocks the whole runtime and
// stalls every other task on the thread (DANGER-ZONES B1: `nextgcore_mongoc()`
// reaches 18 modules).
//
// These wrappers offload the blocking call to `tokio::task::spawn_blocking`,
// mirroring `nextgcore_dbi_init_async` in mongoc.rs. They take owned `String` args so
// the closure is `'static`. Async call sites should prefer these; the sync
// versions remain for non-async contexts (FSM handlers, tests, EPC paths).

/// Async, non-blocking wrapper for [`nextgcore_dbi_auth_info`].
pub async fn nextgcore_dbi_auth_info_async(supi: String) -> DbiResult<NextgcoreDbiAuthInfo> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_auth_info(&supi))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_update_sqn`].
pub async fn nextgcore_dbi_update_sqn_async(supi: String, sqn: u64) -> DbiResult<()> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_update_sqn(&supi, sqn))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_increment_sqn`].
pub async fn nextgcore_dbi_increment_sqn_async(supi: String) -> DbiResult<()> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_increment_sqn(&supi))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_update_imeisv`].
pub async fn nextgcore_dbi_update_imeisv_async(supi: String, imeisv: String) -> DbiResult<()> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_update_imeisv(&supi, &imeisv))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_subscription_data`].
pub async fn nextgcore_dbi_subscription_data_async(
    supi: String,
) -> DbiResult<NextgcoreSubscriptionData> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_subscription_data(&supi))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_subscription_data_5g`].
pub async fn nextgcore_dbi_subscription_data_5g_async(
    supi: String,
) -> DbiResult<NextgcoreSubscriptionData> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_subscription_data_5g(&supi))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// Async, non-blocking wrapper for [`nextgcore_dbi_policy_subscription`].
pub async fn nextgcore_dbi_policy_subscription_async(
    supi: String,
) -> DbiResult<NextgcoreSubscriptionData> {
    tokio::task::spawn_blocking(move || nextgcore_dbi_policy_subscription(&supi))
        .await
        .unwrap_or_else(|e| {
            Err(DbiError::ParseError(format!(
                "spawn_blocking panicked: {e}"
            )))
        })
}

/// The subscriber document's External Identifiers (nextgsim#480).
///
/// `extid` may be one string or an array of strings: the identity lookup
/// `{extid: <value>}` matches either shape, so both are accepted here too.
/// Empty and non-string entries are skipped, and at most
/// [`NEXTGCORE_MAX_NUM_OF_EXTID`] are kept.
pub(crate) fn parse_external_ids(document: &Document) -> Vec<String> {
    let values: Vec<&Bson> = match document.get(NEXTGCORE_EXTID_STRING) {
        Some(Bson::Array(a)) => a.iter().collect(),
        Some(v @ Bson::String(_)) => vec![v],
        _ => Vec::new(),
    };
    values
        .into_iter()
        .filter_map(|v| match v {
            Bson::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        })
        .take(NEXTGCORE_MAX_NUM_OF_EXTID)
        .collect()
}

/// Parse AMBR from BSON document
fn parse_ambr(doc: &Document) -> NextgcoreAmbr {
    let mut ambr = NextgcoreAmbr::default();

    if let Ok(downlink_doc) = doc.get_document(NEXTGCORE_DOWNLINK_STRING) {
        let mut value = 0u64;
        let mut unit = 0u8;

        if let Ok(v) = downlink_doc.get_i32(NEXTGCORE_VALUE_STRING) {
            value = v as u64;
        }
        if let Ok(u) = downlink_doc.get_i32(NEXTGCORE_UNIT_STRING) {
            unit = u as u8;
        }

        for _ in 0..unit {
            value *= 1000;
        }
        ambr.downlink = value;
    }

    if let Ok(uplink_doc) = doc.get_document(NEXTGCORE_UPLINK_STRING) {
        let mut value = 0u64;
        let mut unit = 0u8;

        if let Ok(v) = uplink_doc.get_i32(NEXTGCORE_VALUE_STRING) {
            value = v as u64;
        }
        if let Ok(u) = uplink_doc.get_i32(NEXTGCORE_UNIT_STRING) {
            unit = u as u8;
        }

        for _ in 0..unit {
            value *= 1000;
        }
        ambr.uplink = value;
    }

    ambr
}

/// Parse QoS from BSON document
fn parse_qos(doc: &Document) -> NextgcoreQos {
    let mut qos = NextgcoreQos::default();

    if let Ok(index) = doc.get_i32(NEXTGCORE_INDEX_STRING) {
        qos.index = index as u8;
    }

    if let Ok(arp_doc) = doc.get_document(NEXTGCORE_ARP_STRING) {
        if let Ok(pl) = arp_doc.get_i32(NEXTGCORE_PRIORITY_LEVEL_STRING) {
            qos.arp.priority_level = pl as u8;
        }
        if let Ok(pec) = arp_doc.get_i32(NEXTGCORE_PRE_EMPTION_CAPABILITY_STRING) {
            qos.arp.pre_emption_capability = pec as u8;
        }
        if let Ok(pev) = arp_doc.get_i32(NEXTGCORE_PRE_EMPTION_VULNERABILITY_STRING) {
            qos.arp.pre_emption_vulnerability = pev as u8;
        }
    }

    qos
}

/// Parse a subscriber document's `slice` array into `data.slice` (at most
/// `NEXTGCORE_MAX_NUM_OF_SLICE`; entries without an `sst` are skipped). Shared by
/// the MongoDB reads and the test store's mirror, so both parse one shape.
pub(crate) fn parse_subscribed_slices(document: &Document, data: &mut NextgcoreSubscriptionData) {
    if let Ok(slice_array) = document.get_array(NEXTGCORE_SLICE_STRING) {
        for slice_val in slice_array {
            if data.num_of_slice >= NEXTGCORE_MAX_NUM_OF_SLICE {
                break;
            }
            if let Bson::Document(slice_doc) = slice_val {
                if let Some(slice_data) = parse_slice_data(slice_doc) {
                    data.slice.push(slice_data);
                    data.num_of_slice += 1;
                }
            }
        }
    }
}

/// The SD of a subscriber `slice` document (#1514).
///
/// `sd` is optional (TS 29.571 Table 5.4.4.2-1); an absent one means no SD is
/// associated with the SST, which this crate carries as the reserved value FFFFFF
/// (TS 23.003 clause 28.4.2, `NEXTGCORE_S_NSSAI_NO_SD_VALUE`). An `sd` that is not a
/// SD string (exactly 6 hex digits, TS 29.571 pattern `^[A-Fa-f0-9]{6}$`, #1547)
/// reads the same way. The subscription read and the session-data read
/// both go through here, so they agree on the same stored slice.
///
/// A present `sd` that does not parse is logged at WARN, once per read of the
/// slice: the slice then lists as SST-only, which is a different S-NSSAI from the
/// one the operator meant. The SUPI is not logged.
pub(crate) fn parse_slice_sd(slice_doc: &Document) -> NextgcoreUint24 {
    let no_sd = NextgcoreUint24::new(NEXTGCORE_S_NSSAI_NO_SD_VALUE);
    match slice_doc.get(NEXTGCORE_SD_STRING) {
        None => no_sd,
        Some(Bson::String(sd)) => NextgcoreUint24::from_hex_string(sd).unwrap_or_else(|| {
            log::warn!(
                "subscriber slice (sst {:?}): sd {sd:?} is not 6 hex digits (TS 29.571 \
                 Snssai.sd); read as no SD",
                slice_doc.get_i32(NEXTGCORE_SST_STRING).ok()
            );
            no_sd
        }),
        Some(other) => {
            log::warn!(
                "subscriber slice (sst {:?}): sd is a {:?}, not a string; read as no SD",
                slice_doc.get_i32(NEXTGCORE_SST_STRING).ok(),
                other.element_type()
            );
            no_sd
        }
    }
}

/// Parse slice data from BSON document
fn parse_slice_data(doc: &Document) -> Option<NextgcoreSliceData> {
    let mut slice_data = NextgcoreSliceData::default();

    // SST is required
    let sst = doc.get_i32(NEXTGCORE_SST_STRING).ok()?;
    slice_data.s_nssai.sst = sst as u8;

    // SD is optional (#1514). `NextgcoreSliceData::default()` leaves the SD at 0, which
    // `has_sd()` reads as a real SD of 000000, so the slice has to be told it has none.
    slice_data.s_nssai.sd = parse_slice_sd(doc);

    // Default indicator
    if let Ok(di) = doc.get_bool(NEXTGCORE_DEFAULT_INDICATOR_STRING) {
        slice_data.default_indicator = di;
    }

    // Parse sessions
    if let Ok(session_array) = doc.get_array(NEXTGCORE_SESSION_STRING) {
        for session_val in session_array {
            if slice_data.num_of_session >= NEXTGCORE_MAX_NUM_OF_SESS {
                break;
            }
            if let Bson::Document(session_doc) = session_val {
                let session = parse_session(session_doc);
                slice_data.session.push(session);
                slice_data.num_of_session += 1;
            }
        }
    }

    Some(slice_data)
}

/// Parse session from BSON document
fn parse_session(doc: &Document) -> NextgcoreSession {
    let mut session = NextgcoreSession::default();

    if let Ok(name) = doc.get_str(NEXTGCORE_NAME_STRING) {
        session.name = Some(name.to_string());
    }

    if let Ok(session_type) = doc.get_i32(NEXTGCORE_TYPE_STRING) {
        session.session_type = session_type;
    }

    if let Ok(lbo) = doc.get_bool(NEXTGCORE_LBO_ROAMING_ALLOWED_STRING) {
        session.lbo_roaming_allowed = lbo;
    }

    // #264. Absent leaves it `false` from `Default`, which is the additive migration:
    // every existing subscriber document lacks the key and keeps behaving as it did.
    if let Ok(default_dnn) = doc.get_bool(NEXTGCORE_DEFAULT_DNN_INDICATOR_STRING) {
        session.default_dnn_indicator = default_dnn;
    }

    if let Ok(qos_doc) = doc.get_document(NEXTGCORE_QOS_STRING) {
        session.qos = parse_qos(qos_doc);
    }

    if let Ok(ambr_doc) = doc.get_document(NEXTGCORE_AMBR_STRING) {
        session.ambr = parse_ambr(ambr_doc);
    }

    // Parse SMF IP
    if let Ok(smf_doc) = doc.get_document(NEXTGCORE_SMF_STRING) {
        if let Ok(ipv4_str) = smf_doc.get_str(NEXTGCORE_IPV4_STRING) {
            if let Ok(addr) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                session.smf_ip.ipv4 = true;
                session.smf_ip.addr = u32::from(addr);
            }
        }
        if let Ok(ipv6_str) = smf_doc.get_str(NEXTGCORE_IPV6_STRING) {
            if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                session.smf_ip.ipv6 = true;
                session.smf_ip.addr6 = addr.octets();
            }
        }
    }

    // Parse UE IP
    if let Ok(ue_doc) = doc.get_document(NEXTGCORE_UE_STRING) {
        if let Ok(ipv4_str) = ue_doc.get_str(NEXTGCORE_IPV4_STRING) {
            if let Ok(addr) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                session.ue_ip.ipv4 = true;
                session.ue_ip.addr = u32::from(addr);
            }
        }
        if let Ok(ipv6_str) = ue_doc.get_str(NEXTGCORE_IPV6_STRING) {
            if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                session.ue_ip.ipv6 = true;
                session.ue_ip.addr6 = addr.octets();
            }
        }
    }

    // Parse IPv4 framed routes
    if let Ok(routes_array) = doc.get_array(NEXTGCORE_IPV4_FRAMED_ROUTES_STRING) {
        for route_val in routes_array {
            if session.ipv4_framed_routes.len() >= NEXTGCORE_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                break;
            }
            if let Bson::String(ref route) = route_val {
                session.ipv4_framed_routes.push(route.clone());
            }
        }
    }

    // Parse IPv6 framed routes
    if let Ok(routes_array) = doc.get_array(NEXTGCORE_IPV6_FRAMED_ROUTES_STRING) {
        for route_val in routes_array {
            if session.ipv6_framed_routes.len() >= NEXTGCORE_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                break;
            }
            if let Bson::String(ref route) = route_val {
                session.ipv6_framed_routes.push(route.clone());
            }
        }
    }

    session
}

/// Get 5GS-specific subscription data for a subscriber (SUPI-based)
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier (e.g., "imsi-123456789012345")
///
/// # Returns
/// * `Ok(NextgcoreSubscriptionData)` with 5G subscription data
/// * `Err(DbiError)` on failure
pub fn nextgcore_dbi_subscription_data_5g(supi: &str) -> DbiResult<NextgcoreSubscriptionData> {
    // For 5G, we use the same base subscription data function
    // but could filter for 5G-specific fields
    let mut subscription_data = nextgcore_dbi_subscription_data(supi)?;

    // Mark as 5G subscription
    subscription_data.network_access_mode = 2; // Packet and circuit switched services allowed

    Ok(subscription_data)
}

/// Get policy subscription data for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
///
/// # Returns
/// * `Ok(NextgcoreSubscriptionData)` with policy-related subscription data
/// * `Err(DbiError)` on failure
pub fn nextgcore_dbi_policy_subscription(supi: &str) -> DbiResult<NextgcoreSubscriptionData> {
    let (supi_type, supi_id) = nextgcore_ue_id_key(supi)?;

    let collection = get_subscriber_collection()?;
    let query = doc! { supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    let mut subscription_data = NextgcoreSubscriptionData::new();

    // Parse policy-specific fields
    if let Ok(imsi) = document.get_str(NEXTGCORE_IMSI_STRING) {
        subscription_data.imsi = Some(imsi.to_string());
    }

    // Parse AMBR for policy enforcement
    if let Ok(ambr_doc) = document.get_document(NEXTGCORE_AMBR_STRING) {
        subscription_data.ambr = parse_ambr(ambr_doc);
    }

    // Parse slice data for policy rules
    parse_subscribed_slices(&document, &mut subscription_data);

    Ok(subscription_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNSUPPORTED_UE_IDS: [&str; 4] = ["$x-1", "a.b-1", "-001010000000001", "foo-1"];

    fn is_unsupported<T>(r: DbiResult<T>) -> bool {
        matches!(r, Err(DbiError::UnsupportedUeIdType(_)))
    }

    /// Every subscriber lookup and provisioning entry point resolves its
    /// identifier through `nextgcore_ue_id_key`, so an unsupported type prefix is
    /// refused before any store is consulted, whether or not one is configured.
    #[test]
    fn lookup_and_provisioning_reject_unsupported_ue_id_type() {
        let provision = NextgcoreDbiAuthProvision {
            k_hex: "465b5ce8b199b49faa5f0a2ee238a6bc".into(),
            opc_hex: None,
            op_hex: None,
            amf_hex: "8000".into(),
            sqn: 0,
            auth_method: "5G_AKA".into(),
            algorithm_id: None,
            topc_hex: None,
            top_hex: None,
        };
        for id in UNSUPPORTED_UE_IDS {
            assert!(
                is_unsupported(nextgcore_dbi_auth_info(id)),
                "auth_info {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_update_sqn(id, 1)),
                "update_sqn {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_increment_sqn(id)),
                "increment_sqn {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_update_imeisv(id, "0")),
                "update_imeisv {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_provision_auth_info(id, &provision)),
                "provision_auth_info {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_update_mme(id, "h", "r", false)),
                "update_mme {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_subscription_data(id)),
                "subscription_data {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_subscription_data_5g(id)),
                "subscription_data_5g {id}"
            );
            assert!(
                is_unsupported(nextgcore_dbi_policy_subscription(id)),
                "policy_subscription {id}"
            );
            assert!(
                is_unsupported(crate::session::nextgcore_dbi_session_data(
                    id, None, "internet"
                )),
                "session_data {id}"
            );
            assert!(
                is_unsupported(crate::ims::nextgcore_dbi_ims_data(id)),
                "ims_data {id}"
            );
        }
    }

    /// The supported types reach the store (or report its absence); they are
    /// never refused as unsupported.
    #[test]
    fn supported_ue_id_types_reach_the_lookup() {
        for id in [
            "imsi-999990000000901",
            "msisdn-999990000901",
            "extid-nobody901@example.org",
            "nai-nobody901@example.org",
        ] {
            assert!(
                !is_unsupported(nextgcore_dbi_auth_info(id)),
                "auth_info {id}"
            );
            assert!(
                !is_unsupported(nextgcore_dbi_subscription_data(id)),
                "subscription_data {id}"
            );
            assert!(
                !is_unsupported(nextgcore_dbi_policy_subscription(id)),
                "policy_subscription {id}"
            );
        }
    }

    /// **nextgsim#480**: the subscriber document's `extid` is read as the
    /// subscriber's External Identifiers, as one string or an array, so udrd can
    /// emit them as `extid-` GPSIs. Without it the field was never read and no
    /// `extid-` GPSI existed anywhere.
    #[test]
    fn parse_external_ids_reads_a_string_or_an_array() {
        let mut one = Document::new();
        one.insert(NEXTGCORE_EXTID_STRING, "ue013@fl.nextg");
        assert_eq!(parse_external_ids(&one), vec!["ue013@fl.nextg"]);

        let mut many = Document::new();
        many.insert(
            NEXTGCORE_EXTID_STRING,
            vec![
                Bson::String("a@realm".into()),
                Bson::Int32(7),
                Bson::String("  ".into()),
                Bson::String("b@realm".into()),
            ],
        );
        assert_eq!(
            parse_external_ids(&many),
            vec!["a@realm", "b@realm"],
            "non-string and blank entries are skipped"
        );

        let capped: Vec<Bson> = (0..NEXTGCORE_MAX_NUM_OF_EXTID + 3)
            .map(|i| Bson::String(format!("u{i}@realm")))
            .collect();
        let mut over = Document::new();
        over.insert(NEXTGCORE_EXTID_STRING, capped);
        assert_eq!(parse_external_ids(&over).len(), NEXTGCORE_MAX_NUM_OF_EXTID);

        assert!(parse_external_ids(&Document::new()).is_empty());
    }

    // ================================================================
    // #264: the per-DNN default marker survives the BSON round trip
    // ================================================================

    /// **#264**: `parse_session` reads `default_dnn_indicator` off the document.
    ///
    /// Provisioning it is useless if the parser drops it, and the drop would be silent:
    /// `udrd` would emit no `defaultDnnIndicator`, `smfd` would fall through to rule 2 or 3
    /// and refuse the DNN-less session, and the operator would see a refusal for a DNN they
    /// had flagged. Both `true` and the absent case are asserted, because absent-is-false is
    /// the migration story for every existing subscriber document.
    #[test]
    fn parse_session_reads_the_default_dnn_indicator() {
        let mut flagged = Document::new();
        flagged.insert(NEXTGCORE_NAME_STRING, "ims");
        flagged.insert(NEXTGCORE_DEFAULT_DNN_INDICATOR_STRING, true);
        assert!(
            parse_session(&flagged).default_dnn_indicator,
            "a provisioned default DNN must reach NextgcoreSession"
        );

        let mut unflagged = Document::new();
        unflagged.insert(NEXTGCORE_NAME_STRING, "internet");
        unflagged.insert(NEXTGCORE_DEFAULT_DNN_INDICATOR_STRING, false);
        assert!(
            !parse_session(&unflagged).default_dnn_indicator,
            "an explicit false must stay false"
        );

        let mut absent = Document::new();
        absent.insert(NEXTGCORE_NAME_STRING, "internet");
        assert!(
            !parse_session(&absent).default_dnn_indicator,
            "and an EXISTING document with no such key must default to false, which is what \
             makes #264 additive: every subscriber provisioned before it keeps behaving as it \
             did"
        );
        assert_eq!(
            parse_session(&absent).name.as_deref(),
            Some("internet"),
            "control: the rest of the session still parses, so the assertion above cannot \
             pass by the parse having failed"
        );
    }

    /// The SLICE-level default flag and the per-DNN one are different fields.
    ///
    /// They are one word apart in Mongo (`default_indicator` on the slice,
    /// `default_dnn_indicator` on the session) and answer different questions -- which slice
    /// a UE gets when it asks for none, versus which DNN inside that slice. A parser that
    /// read one key for both would look correct on any single-slice single-DNN subscriber,
    /// which is every subscriber in this tree's E2E.
    #[test]
    fn the_slice_default_and_the_dnn_default_are_not_the_same_key() {
        let mut session = Document::new();
        session.insert(NEXTGCORE_NAME_STRING, "internet");
        // The SLICE's key, on the SESSION document: must be ignored here.
        session.insert(NEXTGCORE_DEFAULT_INDICATOR_STRING, true);
        assert!(
            !parse_session(&session).default_dnn_indicator,
            "the slice-level `default_indicator` must not set the per-DNN flag"
        );
        assert_ne!(
            NEXTGCORE_DEFAULT_INDICATOR_STRING, NEXTGCORE_DEFAULT_DNN_INDICATOR_STRING,
            "and the two constants must stay distinct"
        );
    }

    /// **#1514**: a subscriber slice stored without an `sd` reads back as "no SD"
    /// (FFFFFF, TS 23.003 clause 28.4.2), not as SD 000000, so consumers render
    /// `{sst: 1}` and not `{sst: 1, sd: "000000"}`. A stored SD of 000000 is a real SD
    /// and keeps it; an unparseable `sd` reads as "no SD", as the session-data read does.
    #[test]
    fn a_slice_stored_without_an_sd_reads_back_as_no_sd() {
        let no_sd = parse_slice_data(&doc! { NEXTGCORE_SST_STRING: 1 }).expect("sst is set");
        assert_eq!(no_sd.s_nssai.sst, 1);
        assert_eq!(no_sd.s_nssai.sd.v, NEXTGCORE_S_NSSAI_NO_SD_VALUE);
        assert!(!no_sd.s_nssai.has_sd());
        assert_eq!(no_sd.s_nssai, NextgcoreSNssai::new(1, None));

        let zero_sd =
            parse_slice_data(&doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "000000" })
                .expect("sst is set");
        assert!(zero_sd.s_nssai.has_sd());
        assert_eq!(zero_sd.s_nssai, NextgcoreSNssai::new(1, Some(0)));

        let with_sd =
            parse_slice_data(&doc! { NEXTGCORE_SST_STRING: 2, NEXTGCORE_SD_STRING: "0A0b0C" })
                .expect("sst is set");
        assert_eq!(with_sd.s_nssai, NextgcoreSNssai::new(2, Some(0x0a0b0c)));

        // #1547: not exactly 6 hex digits, so not an SD, even where u32 parsing
        // would take it ("0100001" would have been SD 100001, a different slice).
        for bad in [
            "", "zz", "not-hex", "1", "+1", "+00001", "00001", "0100001", " 00001", "00001 ",
        ] {
            let bad_sd =
                parse_slice_data(&doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: bad })
                    .expect("sst is set");
            assert_eq!(
                bad_sd.s_nssai,
                NextgcoreSNssai::new(1, None),
                "an unparseable sd {bad:?} must read as no SD"
            );
        }
        // A non-string `sd` is not an SD either.
        let typed = parse_slice_data(&doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: 7 })
            .expect("sst is set");
        assert_eq!(typed.s_nssai, NextgcoreSNssai::new(1, None));
    }

    /// The session-data read and the subscription read agree on the SD of every stored
    /// shape (#1514). The session read never returns the SD; it uses it to match a
    /// requested S-NSSAI, where a slice with no SD matches any SD and one with an SD
    /// matches only that SD. So for each stored shape, the SD the subscription read
    /// returns predicts which requested SDs the session read matches.
    #[test]
    fn the_subscription_read_and_the_session_read_agree_on_the_sd() {
        let session = doc! { NEXTGCORE_NAME_STRING: "internet" };
        let shapes = [
            doc! { NEXTGCORE_SST_STRING: 1 },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "000000" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "000001" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "ffffff" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "x" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "1" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: "0000001" },
            doc! { NEXTGCORE_SST_STRING: 1, NEXTGCORE_SD_STRING: 7 },
        ];
        for shape in shapes {
            let subscribed = parse_slice_data(&shape).expect("sst is set").s_nssai;
            let mut slice = shape.clone();
            slice.insert(
                NEXTGCORE_SESSION_STRING,
                vec![Bson::Document(session.clone())],
            );
            let document = doc! { NEXTGCORE_SLICE_STRING: [Bson::Document(slice)] };
            for requested_sd in [0x000000, 0x000001, 0x0a0b0c] {
                let requested = NextgcoreSNssai::new(1, Some(requested_sd));
                let session_matches = crate::session::session_data_from_document(
                    &document,
                    "999990000001514",
                    Some(&requested),
                    "internet",
                )
                .is_ok();
                let predicted = !subscribed.has_sd() || subscribed.sd.v == requested_sd;
                assert_eq!(
                    session_matches, predicted,
                    "stored {shape:?}, requested SD {requested_sd:06x}: the subscription read \
                     says SD {:06x}",
                    subscribed.sd.v
                );
            }
        }
    }

    // 3GPP TS 35.208 Test Set 1, mirroring the constants in
    // nextgcore-crypt/src/milenage.rs so the expected OPc is anchored to the
    // published vectors rather than to our own output.
    const K1_HEX: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OP1_HEX: &str = "cdc202d5123e20f62b6d676ac72cb318";
    const OPC1_HEX: &str = "cd63cb71954a9f4e48a5994e37a02baf";

    fn security_doc(fields: &[(&str, &str)]) -> Document {
        let mut d = Document::new();
        for (k, v) in fields {
            d.insert(*k, *v);
        }
        d
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// OP-only provisioning must yield the DERIVED OPc, never the raw OP.
    ///
    /// This is the #86 defect: nextgcore-udrd emitted
    /// `if use_opc { opc } else { op }` into `encOpcKey`, so an OP-only
    /// subscriber had MILENAGE driven with OP where TS 33.501 §6.1 requires
    /// OPc, and 5G-AKA failed for that subscriber.
    #[test]
    fn test_op_only_derives_opc_and_never_serves_raw_op() {
        let doc = security_doc(&[(NEXTGCORE_K_STRING, K1_HEX), (NEXTGCORE_OP_STRING, OP1_HEX)]);
        let info = parse_auth_info(&doc, "imsi-001010000000001");

        assert!(
            info.use_opc,
            "use_opc must be set once OPc is derived, so consumers take the OPc arm"
        );
        assert_eq!(
            hex(&info.opc),
            OPC1_HEX,
            "opc must be the TS 35.208 Set-1 derived value OPc = OP XOR E_K(OP)"
        );
        assert_ne!(
            hex(&info.opc),
            OP1_HEX,
            "serving the raw OP as OPc is the authentication-breaking bug"
        );
        // The UDR's encOpcKey expression must now select the derived OPc.
        let served = if info.use_opc { &info.opc } else { &info.op };
        assert_eq!(hex(served), OPC1_HEX);
    }

    /// An explicitly provisioned OPc is served verbatim and never re-derived.
    #[test]
    fn test_provisioned_opc_is_not_rederived() {
        let doc = security_doc(&[
            (NEXTGCORE_K_STRING, K1_HEX),
            (NEXTGCORE_OPC_STRING, OPC1_HEX),
            // Both present: provisioning must win over derivation.
            (NEXTGCORE_OP_STRING, OP1_HEX),
        ]);
        let info = parse_auth_info(&doc, "imsi-001010000000002");

        assert!(info.use_opc);
        assert_eq!(
            hex(&info.opc),
            OPC1_HEX,
            "a provisioned OPc must pass through untouched"
        );
    }

    /// A record with neither OPc nor OP leaves use_opc false: there is nothing
    /// to derive from, and inventing key material would be worse than failing.
    #[test]
    fn test_no_key_material_leaves_use_opc_false() {
        let doc = security_doc(&[(NEXTGCORE_K_STRING, K1_HEX)]);
        let info = parse_auth_info(&doc, "imsi-001010000000003");
        assert!(!info.use_opc);
        assert_eq!(info.opc, [0u8; NEXTGCORE_KEY_LEN]);
    }

    /// `op` stays populated after derivation: it is no longer used for AKA, but
    /// zeroing it would be an unrelated behaviour change for other readers.
    #[test]
    fn test_op_is_retained_after_derivation() {
        let doc = security_doc(&[(NEXTGCORE_K_STRING, K1_HEX), (NEXTGCORE_OP_STRING, OP1_HEX)]);
        let info = parse_auth_info(&doc, "imsi-001010000000004");
        assert_eq!(hex(&info.op), OP1_HEX);
    }
}
