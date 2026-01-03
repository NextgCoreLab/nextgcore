//! Subscription Database Queries
//!
//! Provides functions for querying and updating subscriber data.
//! Ported from lib/dbi/subscription.c in the C implementation.

use mongodb::bson::{doc, Bson, Document};
use serde::{Deserialize, Serialize};

use crate::mongoc::{get_subscriber_collection, DbiError, DbiResult};
use crate::types::*;

/// Authentication information from database
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsDbiAuthInfo {
    pub k: [u8; OGS_KEY_LEN],
    pub use_opc: bool,
    pub opc: [u8; OGS_KEY_LEN],
    pub op: [u8; OGS_KEY_LEN],
    pub amf: [u8; OGS_AMF_LEN],
    pub rand: [u8; OGS_RAND_LEN],
    pub sqn: u64,
}

/// Get authentication info for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier (e.g., "imsi-123456789012345")
///
/// # Returns
/// * `Ok(OgsDbiAuthInfo)` with authentication data
/// * `Err(DbiError)` on failure
pub fn ogs_dbi_auth_info(supi: &str) -> DbiResult<OgsDbiAuthInfo> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    let security = document
        .get_document(OGS_SECURITY_STRING)
        .map_err(|_| DbiError::FieldNotFound(OGS_SECURITY_STRING.to_string()))?;

    let mut auth_info = OgsDbiAuthInfo::default();

    // Parse K
    if let Ok(k_str) = security.get_str(OGS_K_STRING) {
        ogs_ascii_to_hex(k_str, &mut auth_info.k);
    }

    // Parse OPc
    if let Ok(opc_str) = security.get_str(OGS_OPC_STRING) {
        auth_info.use_opc = true;
        ogs_ascii_to_hex(opc_str, &mut auth_info.opc);
    }

    // Parse OP
    if let Ok(op_str) = security.get_str(OGS_OP_STRING) {
        ogs_ascii_to_hex(op_str, &mut auth_info.op);
    }

    // Parse AMF
    if let Ok(amf_str) = security.get_str(OGS_AMF_STRING) {
        ogs_ascii_to_hex(amf_str, &mut auth_info.amf);
    }

    // Parse RAND
    if let Ok(rand_str) = security.get_str(OGS_RAND_STRING) {
        ogs_ascii_to_hex(rand_str, &mut auth_info.rand);
    }

    // Parse SQN
    if let Ok(sqn) = security.get_i64(OGS_SQN_STRING) {
        auth_info.sqn = sqn as u64;
    }

    Ok(auth_info)
}

/// Update SQN for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
/// * `sqn` - New sequence number
pub fn ogs_dbi_update_sqn(supi: &str, sqn: u64) -> DbiResult<()> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };
    let update = doc! {
        "$set": {
            format!("{}.{}", OGS_SECURITY_STRING, OGS_SQN_STRING): sqn as i64
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Increment SQN for a subscriber (by 32, with 48-bit wrap)
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
pub fn ogs_dbi_increment_sqn(supi: &str) -> DbiResult<()> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    // Increment by 32
    let update_inc = doc! {
        "$inc": {
            format!("{}.{}", OGS_SECURITY_STRING, OGS_SQN_STRING): 32_i64
        }
    };
    collection.update_one(query.clone(), update_inc, None)?;

    // Apply 48-bit mask using bitwise AND
    let update_bit = doc! {
        "$bit": {
            format!("{}.{}", OGS_SECURITY_STRING, OGS_SQN_STRING): {
                "and": OGS_MAX_SQN as i64
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
pub fn ogs_dbi_update_imeisv(supi: &str, imeisv: &str) -> DbiResult<()> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    log::debug!(
        "SUPI type: {}, SUPI id: {}, imeisv: {}",
        supi_type,
        supi_id,
        imeisv
    );

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };
    let update = doc! {
        "$set": {
            OGS_IMEISV_STRING: imeisv
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Update MME information for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
/// * `mme_host` - MME host name
/// * `mme_realm` - MME realm
/// * `purge_flag` - Purge flag
pub fn ogs_dbi_update_mme(
    supi: &str,
    mme_host: &str,
    mme_realm: &str,
    purge_flag: bool,
) -> DbiResult<()> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    log::debug!(
        "SUPI type: {}, SUPI id: {}, mme_host: {}, mme_realm: {}",
        supi_type,
        supi_id,
        mme_host,
        mme_realm
    );

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);

    let update = doc! {
        "$set": {
            OGS_MME_HOST_STRING: mme_host,
            OGS_MME_REALM_STRING: mme_realm,
            OGS_MME_TIMESTAMP_STRING: timestamp,
            OGS_PURGE_FLAG_STRING: purge_flag
        }
    };

    collection.update_one(query, update, None)?;
    Ok(())
}

/// Get full subscription data for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier
pub fn ogs_dbi_subscription_data(supi: &str) -> DbiResult<OgsSubscriptionData> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    let mut subscription_data = OgsSubscriptionData::new();

    // Parse IMSI
    if let Ok(imsi) = document.get_str(OGS_IMSI_STRING) {
        subscription_data.imsi = Some(imsi.to_string());
    }

    // Parse MSISDN array
    if let Ok(msisdn_array) = document.get_array(OGS_MSISDN_STRING) {
        for msisdn_val in msisdn_array {
            if subscription_data.num_of_msisdn >= OGS_MAX_NUM_OF_MSISDN {
                break;
            }
            if let Bson::String(bcd) = msisdn_val {
                let mut msisdn = OgsMsisdn::default();
                msisdn.bcd = bcd.clone();
                ogs_bcd_to_buffer(&bcd, &mut msisdn.buf);
                msisdn.len = msisdn.buf.len();
                subscription_data.msisdn.push(msisdn);
                subscription_data.num_of_msisdn += 1;
            }
        }
    }

    // Parse access restriction data
    if let Ok(ard) = document.get_i32(OGS_ACCESS_RESTRICTION_DATA_STRING) {
        subscription_data.access_restriction_data = ard;
    }

    // Parse subscriber status
    if let Ok(ss) = document.get_i32(OGS_SUBSCRIBER_STATUS_STRING) {
        subscription_data.subscriber_status = ss;
    }

    // Parse operator determined barring
    if let Ok(odb) = document.get_i32(OGS_OPERATOR_DETERMINED_BARRING_STRING) {
        subscription_data.operator_determined_barring = odb;
    }

    // Parse network access mode
    if let Ok(nam) = document.get_i32(OGS_NETWORK_ACCESS_MODE_STRING) {
        subscription_data.network_access_mode = nam;
    }

    // Parse subscribed RAU/TAU timer
    if let Ok(timer) = document.get_i32(OGS_SUBSCRIBED_RAU_TAU_TIMER_STRING) {
        subscription_data.subscribed_rau_tau_timer = timer;
    }

    // Parse AMBR
    if let Ok(ambr_doc) = document.get_document(OGS_AMBR_STRING) {
        subscription_data.ambr = parse_ambr(ambr_doc);
    }

    // Parse slice array
    if let Ok(slice_array) = document.get_array(OGS_SLICE_STRING) {
        for slice_val in slice_array {
            if subscription_data.num_of_slice >= OGS_MAX_NUM_OF_SLICE {
                break;
            }
            if let Bson::Document(slice_doc) = slice_val {
                if let Some(slice_data) = parse_slice_data(slice_doc) {
                    subscription_data.slice.push(slice_data);
                    subscription_data.num_of_slice += 1;
                }
            }
        }
    }

    // Parse MME host
    if let Ok(mme_host) = document.get_str(OGS_MME_HOST_STRING) {
        subscription_data.mme_host = Some(mme_host.to_string());
    }

    // Parse MME realm
    if let Ok(mme_realm) = document.get_str(OGS_MME_REALM_STRING) {
        subscription_data.mme_realm = Some(mme_realm.to_string());
    }

    // Parse purge flag
    if let Ok(purge_flag) = document.get_bool(OGS_PURGE_FLAG_STRING) {
        subscription_data.purge_flag = purge_flag;
    }

    Ok(subscription_data)
}

/// Parse AMBR from BSON document
fn parse_ambr(doc: &Document) -> OgsAmbr {
    let mut ambr = OgsAmbr::default();

    if let Ok(downlink_doc) = doc.get_document(OGS_DOWNLINK_STRING) {
        let mut value = 0u64;
        let mut unit = 0u8;

        if let Ok(v) = downlink_doc.get_i32(OGS_VALUE_STRING) {
            value = v as u64;
        }
        if let Ok(u) = downlink_doc.get_i32(OGS_UNIT_STRING) {
            unit = u as u8;
        }

        for _ in 0..unit {
            value *= 1000;
        }
        ambr.downlink = value;
    }

    if let Ok(uplink_doc) = doc.get_document(OGS_UPLINK_STRING) {
        let mut value = 0u64;
        let mut unit = 0u8;

        if let Ok(v) = uplink_doc.get_i32(OGS_VALUE_STRING) {
            value = v as u64;
        }
        if let Ok(u) = uplink_doc.get_i32(OGS_UNIT_STRING) {
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
fn parse_qos(doc: &Document) -> OgsQos {
    let mut qos = OgsQos::default();

    if let Ok(index) = doc.get_i32(OGS_INDEX_STRING) {
        qos.index = index as u8;
    }

    if let Ok(arp_doc) = doc.get_document(OGS_ARP_STRING) {
        if let Ok(pl) = arp_doc.get_i32(OGS_PRIORITY_LEVEL_STRING) {
            qos.arp.priority_level = pl as u8;
        }
        if let Ok(pec) = arp_doc.get_i32(OGS_PRE_EMPTION_CAPABILITY_STRING) {
            qos.arp.pre_emption_capability = pec as u8;
        }
        if let Ok(pev) = arp_doc.get_i32(OGS_PRE_EMPTION_VULNERABILITY_STRING) {
            qos.arp.pre_emption_vulnerability = pev as u8;
        }
    }

    qos
}

/// Parse slice data from BSON document
fn parse_slice_data(doc: &Document) -> Option<OgsSliceData> {
    let mut slice_data = OgsSliceData::default();

    // SST is required
    let sst = doc.get_i32(OGS_SST_STRING).ok()?;
    slice_data.s_nssai.sst = sst as u8;

    // SD is optional
    if let Ok(sd_str) = doc.get_str(OGS_SD_STRING) {
        if let Some(sd) = OgsUint24::from_hex_string(sd_str) {
            slice_data.s_nssai.sd = sd;
        }
    }

    // Default indicator
    if let Ok(di) = doc.get_bool(OGS_DEFAULT_INDICATOR_STRING) {
        slice_data.default_indicator = di;
    }

    // Parse sessions
    if let Ok(session_array) = doc.get_array(OGS_SESSION_STRING) {
        for session_val in session_array {
            if slice_data.num_of_session >= OGS_MAX_NUM_OF_SESS {
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
fn parse_session(doc: &Document) -> OgsSession {
    let mut session = OgsSession::default();

    if let Ok(name) = doc.get_str(OGS_NAME_STRING) {
        session.name = Some(name.to_string());
    }

    if let Ok(session_type) = doc.get_i32(OGS_TYPE_STRING) {
        session.session_type = session_type;
    }

    if let Ok(lbo) = doc.get_bool(OGS_LBO_ROAMING_ALLOWED_STRING) {
        session.lbo_roaming_allowed = lbo;
    }

    if let Ok(ref qos_doc) = doc.get_document(OGS_QOS_STRING) {
        session.qos = parse_qos(qos_doc);
    }

    if let Ok(ref ambr_doc) = doc.get_document(OGS_AMBR_STRING) {
        session.ambr = parse_ambr(ambr_doc);
    }

    // Parse SMF IP
    if let Ok(ref smf_doc) = doc.get_document(OGS_SMF_STRING) {
        if let Ok(ipv4_str) = smf_doc.get_str(OGS_IPV4_STRING) {
            if let Ok(addr) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                session.smf_ip.ipv4 = true;
                session.smf_ip.addr = u32::from(addr);
            }
        }
        if let Ok(ipv6_str) = smf_doc.get_str(OGS_IPV6_STRING) {
            if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                session.smf_ip.ipv6 = true;
                session.smf_ip.addr6 = addr.octets();
            }
        }
    }

    // Parse UE IP
    if let Ok(ref ue_doc) = doc.get_document(OGS_UE_STRING) {
        if let Ok(ipv4_str) = ue_doc.get_str(OGS_IPV4_STRING) {
            if let Ok(addr) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                session.ue_ip.ipv4 = true;
                session.ue_ip.addr = u32::from(addr);
            }
        }
        if let Ok(ipv6_str) = ue_doc.get_str(OGS_IPV6_STRING) {
            if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                session.ue_ip.ipv6 = true;
                session.ue_ip.addr6 = addr.octets();
            }
        }
    }

    // Parse IPv4 framed routes
    if let Ok(routes_array) = doc.get_array(OGS_IPV4_FRAMED_ROUTES_STRING) {
        for route_val in routes_array {
            if session.ipv4_framed_routes.len() >= OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                break;
            }
            if let Bson::String(ref route) = route_val {
                session.ipv4_framed_routes.push(route.clone());
            }
        }
    }

    // Parse IPv6 framed routes
    if let Ok(routes_array) = doc.get_array(OGS_IPV6_FRAMED_ROUTES_STRING) {
        for route_val in routes_array {
            if session.ipv6_framed_routes.len() >= OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                break;
            }
            if let Bson::String(ref route) = route_val {
                session.ipv6_framed_routes.push(route.clone());
            }
        }
    }

    session
}
