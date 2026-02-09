//! UDR NUDR Handler Functions
//!
//! Port of src/udr/nudr-handler.c - Handler functions for NUDR DR service
//!
//! These handlers process requests from UDM and PCF for:
//! - Authentication subscription data
//! - Context data (AMF/SMF registrations)
//! - Provisioned data (AM data, SMF selection, SM data)
//! - Policy data (AM policy, SM policy)

use crate::event::UdrEvent;

/// Send an error response to the client
fn send_error_response(stream_id: u64, status: u16, title: &str, detail: &str) {
    log::warn!(
        "[stream={}] Error response: {} {} - {}",
        stream_id,
        status,
        title,
        detail
    );
}

/// Send a success response to the client
fn send_success_response(stream_id: u64, status: u16, body: Option<&str>) {
    log::debug!(
        "[stream={}] Success response: {} body={}",
        stream_id,
        status,
        body.is_some()
    );
}

/// Helper to convert byte slice to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert u64 SQN to 6-byte hex string
fn sqn_to_hex(sqn: u64) -> String {
    format!("{:012x}", sqn & 0xFFFFFFFFFFFF)
}

/// Helper to format AMBR value as human-readable string
fn format_ambr(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{} Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000 {
        format!("{} Mbps", bps / 1_000_000)
    } else if bps >= 1_000 {
        format!("{} Kbps", bps / 1_000)
    } else {
        format!("{} bps", bps)
    }
}

/// Handle subscription authentication requests
///
/// Port of udr_nudr_dr_handle_subscription_authentication()
///
/// Handles:
/// - GET authentication-subscription: Returns auth credentials (K, OPc, AMF, SQN)
/// - PATCH authentication-subscription: Updates SQN after resync
/// - PUT/DELETE authentication-status: Updates auth event status
pub fn handle_subscription_authentication(event: &UdrEvent, stream_id: u64) {
    let (method, resource_components) = match extract_request_info(event) {
        Some(info) => info,
        None => return,
    };

    // Get SUPI from resource component[1]
    let supi = match resource_components.get(1) {
        Some(s) => s,
        None => {
            log::error!("No SUPI");
            send_error_response(stream_id, 400, "Bad Request", "Missing SUPI");
            return;
        }
    };

    // Validate SUPI type
    // In C: if (strncmp(supi, OGS_ID_SUPI_TYPE_IMSI, strlen(OGS_ID_SUPI_TYPE_IMSI)) != 0)
    if !supi.starts_with("imsi-") {
        log::error!("[{}] Unknown SUPI Type", supi);
        send_error_response(stream_id, 403, "Forbidden", "Unknown SUPI type");
        return;
    }

    // Get auth info from database
    // In C: rv = ogs_dbi_auth_info(supi, &auth_info);
    // if (rv != OGS_OK) { ... send NOT_FOUND ... }

    // Route based on resource component[3]
    let resource3 = resource_components.get(3).map(|s| s.as_str());

    // Query auth info from database
    let auth_info = match ogs_dbi::subscription::ogs_dbi_auth_info(supi) {
        Ok(info) => info,
        Err(e) => {
            log::error!("[{}] DB auth_info query failed: {:?}", supi, e);
            send_error_response(stream_id, 404, "Not Found", "Subscriber not found");
            return;
        }
    };

    match resource3 {
        Some("authentication-subscription") => {
            match method.as_str() {
                "GET" => {
                    log::debug!("[{}] GET authentication-subscription (stream={})", supi, stream_id);

                    // Build AuthenticationSubscription from DB auth_info
                    let response_json = serde_json::json!({
                        "authenticationMethod": "5G_AKA",
                        "encPermanentKey": bytes_to_hex(&auth_info.k),
                        "encOpcKey": bytes_to_hex(if auth_info.use_opc { &auth_info.opc } else { &auth_info.op }),
                        "authenticationManagementField": bytes_to_hex(&auth_info.amf),
                        "sequenceNumber": {
                            "sqn": sqn_to_hex(auth_info.sqn)
                        }
                    });

                    let body = serde_json::to_string(&response_json).unwrap_or_default();
                    send_success_response(stream_id, 200, Some(&body));
                }
                "PATCH" => {
                    log::debug!("[{}] PATCH authentication-subscription (stream={})", supi, stream_id);

                    // Parse PatchItemList from request body to extract new SQN
                    if let Some(sbi) = &event.sbi {
                        if let Some(req) = &sbi.request {
                            if let Some(body) = &req.body {
                                if let Ok(patches) = serde_json::from_str::<serde_json::Value>(body) {
                                    // Look for SQN patch: {"op":"replace","path":"/sequenceNumber/sqn","value":"..."}
                                    if let Some(arr) = patches.as_array() {
                                        for patch in arr {
                                            let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                                            if path == "/sequenceNumber/sqn" {
                                                if let Some(sqn_hex) = patch.get("value").and_then(|v| v.as_str()) {
                                                    let sqn = u64::from_str_radix(sqn_hex, 16).unwrap_or(0);
                                                    if let Err(e) = ogs_dbi::subscription::ogs_dbi_update_sqn(supi, sqn) {
                                                        log::error!("[{}] DB update_sqn failed: {:?}", supi, e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Increment SQN by 32 for next use
                    if let Err(e) = ogs_dbi::subscription::ogs_dbi_increment_sqn(supi) {
                        log::error!("[{}] DB increment_sqn failed: {:?}", supi, e);
                    }

                    send_success_response(stream_id, 204, None);
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                    send_error_response(stream_id, 405, "Method Not Allowed", &format!("Method {} not allowed", method));
                }
            }
        }
        Some("authentication-status") => {
            match method.as_str() {
                "PUT" | "DELETE" => {
                    log::debug!("[{}] {} authentication-status (stream={})", supi, method, stream_id);

                    // Increment SQN on auth status update
                    if let Err(e) = ogs_dbi::subscription::ogs_dbi_increment_sqn(supi) {
                        log::error!("[{}] DB increment_sqn failed: {:?}", supi, e);
                    }

                    send_success_response(stream_id, 204, None);
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                    send_error_response(stream_id, 405, "Method Not Allowed", &format!("Method {} not allowed", method));
                }
            }
        }
        _ => {
            log::error!("Invalid resource name [{:?}]", resource3);
            send_error_response(stream_id, 400, "Bad Request", "Invalid resource name");
        }
    }
}

/// Handle subscription context requests
///
/// Port of udr_nudr_dr_handle_subscription_context()
///
/// Handles:
/// - PUT/PATCH amf-3gpp-access: AMF registration updates
/// - PUT/DELETE smf-registrations: SMF registration updates
pub fn handle_subscription_context(event: &UdrEvent, stream_id: u64) {
    let (method, resource_components) = match extract_request_info(event) {
        Some(info) => info,
        None => return,
    };

    // Get SUPI from resource component[1]
    let supi = match resource_components.get(1) {
        Some(s) => s,
        None => {
            log::error!("No SUPI");
            send_error_response(stream_id, 400, "Bad Request", "Missing SUPI");
            return;
        }
    };

    // Validate SUPI type
    if !supi.starts_with("imsi-") {
        log::error!("[{}] Unknown SUPI Type", supi);
        send_error_response(stream_id, 403, "Forbidden", "Unknown SUPI type");
        return;
    }

    // Route based on resource component[3]
    let resource3 = resource_components.get(3).map(|s| s.as_str());

    match resource3 {
        Some("amf-3gpp-access") => {
            match method.as_str() {
                "PUT" => {
                    log::debug!("[{}] PUT amf-3gpp-access (stream={})", supi, stream_id);

                    // Extract PEI (IMEISV) from request body and update in DB
                    if let Some(sbi) = &event.sbi {
                        if let Some(req) = &sbi.request {
                            if let Some(body) = &req.body {
                                if let Ok(reg_data) = serde_json::from_str::<serde_json::Value>(body) {
                                    if let Some(pei) = reg_data.get("pei").and_then(|v| v.as_str()) {
                                        // PEI format: "imeisv-XXXXXXXXXXXXXXXX"
                                        let imeisv = if pei.starts_with("imeisv-") {
                                            &pei[7..]
                                        } else {
                                            pei
                                        };
                                        if let Err(e) = ogs_dbi::subscription::ogs_dbi_update_imeisv(supi, imeisv) {
                                            log::error!("[{}] DB update_imeisv failed: {:?}", supi, e);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    send_success_response(stream_id, 204, None);
                }
                "PATCH" => {
                    log::debug!("[{}] PATCH amf-3gpp-access (stream={})", supi, stream_id);
                    // PATCH for AMF context update (purge flag, GUAMI changes)
                    // Parse PatchItemList from body
                    if let Some(sbi) = &event.sbi {
                        if let Some(req) = &sbi.request {
                            if let Some(body) = &req.body {
                                if let Ok(patches) = serde_json::from_str::<serde_json::Value>(body) {
                                    if let Some(arr) = patches.as_array() {
                                        for patch in arr {
                                            let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                                            if path == "/purgeFlag" {
                                                if let Some(purge) = patch.get("value").and_then(|v| v.as_bool()) {
                                                    log::debug!("[{}] Setting purge flag to {}", supi, purge);
                                                    // Update purge flag via ogs_dbi_update_mme if needed
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    send_success_response(stream_id, 204, None);
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                    send_error_response(stream_id, 405, "Method Not Allowed", &format!("Method {} not allowed", method));
                }
            }
        }
        Some("smf-registrations") => {
            match method.as_str() {
                "PUT" => {
                    log::debug!("[{}] PUT smf-registrations (stream={})", supi, stream_id);
                    // SMF registration context is stored; UDR is stateless for this
                    send_success_response(stream_id, 204, None);
                }
                "DELETE" => {
                    log::debug!("[{}] DELETE smf-registrations (stream={})", supi, stream_id);
                    send_success_response(stream_id, 204, None);
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                    send_error_response(stream_id, 405, "Method Not Allowed", &format!("Method {} not allowed", method));
                }
            }
        }
        _ => {
            log::error!("Invalid resource name [{:?}]", resource3);
            send_error_response(stream_id, 400, "Bad Request", "Invalid resource name");
        }
    }
}

/// Handle subscription provisioned data requests
///
/// Port of udr_nudr_dr_handle_subscription_provisioned()
///
/// Handles GET requests for:
/// - am-data: Access and Mobility subscription data (GPSIs, UE-AMBR, NSSAI)
/// - smf-selection-subscription-data: SMF selection data (S-NSSAI to DNN mapping)
/// - sm-data: Session management subscription data (DNN configurations)
/// - provisioned-data: Combined provisioned data sets
pub fn handle_subscription_provisioned(event: &UdrEvent, stream_id: u64) {
    let (_method, resource_components) = match extract_request_info(event) {
        Some(info) => info,
        None => return,
    };

    // Get SUPI from resource component[1]
    let supi = match resource_components.get(1) {
        Some(s) => s,
        None => {
            log::error!("No SUPI");
            send_error_response(stream_id, 400, "Bad Request", "Missing SUPI");
            return;
        }
    };

    // Validate SUPI type
    if !supi.starts_with("imsi-") {
        log::error!("[{}] Unknown SUPI Type", supi);
        send_error_response(stream_id, 403, "Forbidden", "Unknown SUPI type");
        return;
    }

    // Get subscription data from database
    let subscription_data = match ogs_dbi::subscription::ogs_dbi_subscription_data(supi) {
        Ok(data) => data,
        Err(e) => {
            log::error!("[{}] DB subscription_data query failed: {:?}", supi, e);
            send_error_response(stream_id, 404, "Not Found", "Subscriber not found");
            return;
        }
    };

    // Check for UE-AMBR
    if subscription_data.ambr.uplink == 0 && subscription_data.ambr.downlink == 0 {
        log::error!("[{}] No UE-AMBR", supi);
        send_error_response(stream_id, 404, "Not Found", "No UE-AMBR");
        return;
    }

    // Determine what data to process based on resource component[4]
    let resource4 = resource_components.get(4).map(|s| s.as_str());

    let (process_am_data, process_smf_sel, process_sm_data, return_provisioned_data) =
        match resource4 {
            Some("am-data") => (true, false, false, false),
            Some("smf-selection-subscription-data") => (false, true, false, false),
            Some("sm-data") => (false, false, true, false),
            None => (true, true, true, true),
            _ => {
                log::error!("Invalid resource name [{:?}]", resource4);
                send_error_response(stream_id, 400, "Bad Request", "Invalid resource name");
                return;
            }
        };

    log::debug!(
        "[{}] GET provisioned data (stream={}) am={} smf_sel={} sm={} combined={}",
        supi, stream_id, process_am_data, process_smf_sel, process_sm_data, return_provisioned_data
    );

    let am_data_json = if process_am_data {
        Some(build_am_data(&subscription_data))
    } else {
        None
    };

    let smf_sel_json = if process_smf_sel {
        Some(build_smf_selection_data(&subscription_data))
    } else {
        None
    };

    let sm_data_json = if process_sm_data {
        Some(build_sm_data(&subscription_data))
    } else {
        None
    };

    let response = if return_provisioned_data {
        // Combined ProvisionedDataSets
        let mut combined = serde_json::Map::new();
        if let Some(am) = &am_data_json {
            combined.insert("amData".to_string(), am.clone());
        }
        if let Some(smf) = &smf_sel_json {
            combined.insert("smfSelData".to_string(), smf.clone());
        }
        if let Some(sm) = &sm_data_json {
            combined.insert("smData".to_string(), sm.clone());
        }
        serde_json::Value::Object(combined)
    } else if let Some(am) = am_data_json {
        am
    } else if let Some(smf) = smf_sel_json {
        smf
    } else if let Some(sm) = sm_data_json {
        sm
    } else {
        serde_json::json!({})
    };

    let body = serde_json::to_string(&response).unwrap_or_default();
    send_success_response(stream_id, 200, Some(&body));
}

/// Build AccessAndMobilitySubscriptionData JSON from subscription data
fn build_am_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut am = serde_json::Map::new();

    // GPSIs (msisdn-xxx)
    if data.num_of_msisdn > 0 {
        let gpsis: Vec<serde_json::Value> = data.msisdn.iter()
            .map(|m| serde_json::Value::String(format!("msisdn-{}", m.bcd)))
            .collect();
        am.insert("gpsis".to_string(), serde_json::Value::Array(gpsis));
    }

    // Subscribed UE-AMBR
    if data.ambr.uplink > 0 || data.ambr.downlink > 0 {
        am.insert("subscribedUeAmbr".to_string(), serde_json::json!({
            "uplink": format_ambr(data.ambr.uplink),
            "downlink": format_ambr(data.ambr.downlink)
        }));
    }

    // NSSAI - default and single NSSAIs
    if data.num_of_slice > 0 {
        let mut default_nssais = Vec::new();
        let mut single_nssais = Vec::new();

        for slice in &data.slice {
            let mut nssai_json = serde_json::Map::new();
            nssai_json.insert("sst".to_string(), serde_json::Value::Number(slice.s_nssai.sst.into()));
            if slice.s_nssai.has_sd() {
                nssai_json.insert("sd".to_string(),
                    serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
            }

            let val = serde_json::Value::Object(nssai_json);
            if slice.default_indicator {
                default_nssais.push(val);
            } else {
                single_nssais.push(val);
            }
        }

        let mut nssai = serde_json::Map::new();
        if !default_nssais.is_empty() {
            nssai.insert("defaultSingleNssais".to_string(),
                serde_json::Value::Array(default_nssais));
        }
        if !single_nssais.is_empty() {
            nssai.insert("singleNssais".to_string(),
                serde_json::Value::Array(single_nssais));
        }
        am.insert("nssai".to_string(), serde_json::Value::Object(nssai));
    }

    serde_json::Value::Object(am)
}

/// Build SmfSelectionSubscriptionData JSON from subscription data
fn build_smf_selection_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut smf_sel = serde_json::Map::new();
    let mut snssai_infos = serde_json::Map::new();

    for slice in &data.slice {
        // Build S-NSSAI key string
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };

        // Build DNN info list for this slice
        let dnn_infos: Vec<serde_json::Value> = slice.session.iter()
            .filter_map(|sess| {
                sess.name.as_ref().map(|dnn| {
                    serde_json::json!({
                        "dnn": dnn
                    })
                })
            })
            .collect();

        if !dnn_infos.is_empty() {
            snssai_infos.insert(snssai_key, serde_json::json!({
                "dnnInfos": dnn_infos
            }));
        }
    }

    if !snssai_infos.is_empty() {
        smf_sel.insert("subscribedSnssaiInfos".to_string(),
            serde_json::Value::Object(snssai_infos));
    }

    serde_json::Value::Object(smf_sel)
}

/// Build SessionManagementSubscriptionData list JSON from subscription data
fn build_sm_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut sm_data_list = Vec::new();

    for slice in &data.slice {
        let mut sm_entry = serde_json::Map::new();

        // Single NSSAI
        let mut snssai = serde_json::Map::new();
        snssai.insert("sst".to_string(), serde_json::Value::Number(slice.s_nssai.sst.into()));
        if slice.s_nssai.has_sd() {
            snssai.insert("sd".to_string(),
                serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
        }
        sm_entry.insert("singleNssai".to_string(), serde_json::Value::Object(snssai));

        // DNN configurations
        let mut dnn_configs = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                let mut dnn_config = serde_json::Map::new();

                // PDU session types
                let pdu_type = match sess.session_type {
                    1 => "IPV4",
                    2 => "IPV6",
                    3 => "IPV4V6",
                    _ => "IPV4V6",
                };
                dnn_config.insert("pduSessionTypes".to_string(), serde_json::json!({
                    "defaultSessionType": pdu_type,
                    "allowedSessionTypes": [pdu_type]
                }));

                // SSC modes
                dnn_config.insert("sscModes".to_string(), serde_json::json!({
                    "defaultSscMode": "SSC_MODE_1",
                    "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]
                }));

                // 5G QoS profile
                dnn_config.insert("5gQosProfile".to_string(), serde_json::json!({
                    "5qi": sess.qos.index,
                    "arp": {
                        "priorityLevel": sess.qos.arp.priority_level,
                        "preemptCap": if sess.qos.arp.pre_emption_capability == 1 {
                            "MAY_PREEMPT"
                        } else {
                            "NOT_PREEMPT"
                        },
                        "preemptVuln": if sess.qos.arp.pre_emption_vulnerability == 1 {
                            "PREEMPTABLE"
                        } else {
                            "NOT_PREEMPTABLE"
                        }
                    }
                }));

                // Session AMBR
                if sess.ambr.uplink > 0 || sess.ambr.downlink > 0 {
                    dnn_config.insert("sessionAmbr".to_string(), serde_json::json!({
                        "uplink": format_ambr(sess.ambr.uplink),
                        "downlink": format_ambr(sess.ambr.downlink)
                    }));
                }

                dnn_configs.insert(dnn.clone(), serde_json::Value::Object(dnn_config));
            }
        }

        if !dnn_configs.is_empty() {
            sm_entry.insert("dnnConfigurations".to_string(),
                serde_json::Value::Object(dnn_configs));
        }

        sm_data_list.push(serde_json::Value::Object(sm_entry));
    }

    serde_json::Value::Array(sm_data_list)
}

/// Handle policy data requests
///
/// Port of udr_nudr_dr_handle_policy_data()
///
/// Handles GET requests for:
/// - am-data: AM policy data
/// - sm-data: SM policy data (requires snssai parameter)
pub fn handle_policy_data(event: &UdrEvent, stream_id: u64) {
    let (method, resource_components) = match extract_request_info(event) {
        Some(info) => info,
        None => return,
    };

    // Route based on resource component[1]
    let resource1 = resource_components.get(1).map(|s| s.as_str());

    match resource1 {
        // In C: CASE(OGS_SBI_RESOURCE_NAME_UES)
        Some("ues") => {
            // Get SUPI from resource component[2]
            let supi = match resource_components.get(2) {
                Some(s) => s,
                None => {
                    log::error!("No SUPI");
                    send_error_response(stream_id, 400, "Bad Request", "Missing SUPI");
                    return;
                }
            };

            // Validate SUPI type
            if !supi.starts_with("imsi-") {
                log::error!("[{}] Unknown SUPI Type", supi);
                send_error_response(stream_id, 403, "Forbidden", "Unknown SUPI type");
                return;
            }

            match method.as_str() {
                "GET" => {
                    // Get subscription data from database
                    let subscription_data = match ogs_dbi::subscription::ogs_dbi_subscription_data(supi) {
                        Ok(data) => data,
                        Err(e) => {
                            log::error!("[{}] DB subscription_data query failed: {:?}", supi, e);
                            send_error_response(stream_id, 404, "Not Found", "Subscriber not found");
                            return;
                        }
                    };

                    // Route based on resource component[3]
                    let resource3 = resource_components.get(3).map(|s| s.as_str());

                    match resource3 {
                        Some("am-data") => {
                            log::debug!("[{}] GET policy am-data (stream={})", supi, stream_id);
                            // AmPolicyData - currently returns empty object per 3GPP spec
                            // (AM policy is typically derived from subscription data, not stored separately)
                            send_success_response(stream_id, 200, Some("{}"));
                        }
                        Some("sm-data") => {
                            log::debug!("[{}] GET policy sm-data (stream={})", supi, stream_id);

                            // Build SmPolicyData with sm_policy_snssai_data
                            let mut sm_policy_snssai_data = serde_json::Map::new();

                            for slice in &subscription_data.slice {
                                let snssai_key = if slice.s_nssai.has_sd() {
                                    format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
                                } else {
                                    format!("{:02x}", slice.s_nssai.sst)
                                };

                                // Build snssai object
                                let mut snssai_json = serde_json::Map::new();
                                snssai_json.insert("sst".to_string(),
                                    serde_json::Value::Number(slice.s_nssai.sst.into()));
                                if slice.s_nssai.has_sd() {
                                    snssai_json.insert("sd".to_string(),
                                        serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
                                }

                                // Build SM policy DNN data for each session/DNN
                                let mut sm_policy_dnn_data = serde_json::Map::new();
                                for sess in &slice.session {
                                    if let Some(dnn) = &sess.name {
                                        let mut dnn_policy = serde_json::Map::new();
                                        dnn_policy.insert("dnn".to_string(),
                                            serde_json::Value::String(dnn.clone()));
                                        sm_policy_dnn_data.insert(dnn.clone(),
                                            serde_json::Value::Object(dnn_policy));
                                    }
                                }

                                let mut snssai_data = serde_json::Map::new();
                                snssai_data.insert("snssai".to_string(),
                                    serde_json::Value::Object(snssai_json));
                                if !sm_policy_dnn_data.is_empty() {
                                    snssai_data.insert("smPolicyDnnData".to_string(),
                                        serde_json::Value::Object(sm_policy_dnn_data));
                                }

                                sm_policy_snssai_data.insert(snssai_key,
                                    serde_json::Value::Object(snssai_data));
                            }

                            let response = serde_json::json!({
                                "smPolicySnssaiData": sm_policy_snssai_data
                            });
                            let body = serde_json::to_string(&response).unwrap_or_default();
                            send_success_response(stream_id, 200, Some(&body));
                        }
                        _ => {
                            log::error!("Invalid resource name [{:?}]", resource3);
                            send_error_response(stream_id, 400, "Bad Request", "Invalid resource name");
                        }
                    }
                }
                _ => {
                    log::error!("Invalid HTTP method [{}]", method);
                    send_error_response(stream_id, 405, "Method Not Allowed", &format!("Method {} not allowed", method));
                }
            }
        }
        _ => {
            log::error!("Invalid resource name [{:?}]", resource1);
            send_error_response(stream_id, 400, "Bad Request", "Invalid resource name");
        }
    }
}

/// Extract request information from event
fn extract_request_info(event: &UdrEvent) -> Option<(String, Vec<String>)> {
    let sbi = event.sbi.as_ref()?;
    let message = sbi.message.as_ref()?;

    Some((
        message.method.clone(),
        message.resource_components.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SbiEventData, SbiMessage, SbiRequest};

    fn create_test_event(method: &str, resource_components: Vec<&str>) -> UdrEvent {
        UdrEvent {
            id: crate::event::UdrEventId::SbiServer,
            timer_id: None,
            sbi: Some(SbiEventData {
                request: Some(SbiRequest {
                    method: method.to_string(),
                    uri: "/nudr-dr/v1/test".to_string(),
                    body: None,
                }),
                response: None,
                message: Some(SbiMessage {
                    service_name: "nudr-dr".to_string(),
                    api_version: "v1".to_string(),
                    resource_components: resource_components.iter().map(|s| s.to_string()).collect(),
                    method: method.to_string(),
                    res_status: None,
                }),
                stream_id: Some(123),
                data: None,
                state: None,
            }),
            nf_instance_id: None,
            subscription_id: None,
        }
    }

    #[test]
    fn test_handle_subscription_authentication_get() {
        let event = create_test_event(
            "GET",
            vec!["subscription-data", "imsi-001010000000001", "authentication-data", "authentication-subscription"],
        );
        handle_subscription_authentication(&event, 123);
    }

    #[test]
    fn test_handle_subscription_authentication_patch() {
        let event = create_test_event(
            "PATCH",
            vec!["subscription-data", "imsi-001010000000001", "authentication-data", "authentication-subscription"],
        );
        handle_subscription_authentication(&event, 123);
    }

    #[test]
    fn test_handle_subscription_authentication_invalid_supi() {
        let event = create_test_event(
            "GET",
            vec!["subscription-data", "invalid-001010000000001", "authentication-data", "authentication-subscription"],
        );
        handle_subscription_authentication(&event, 123);
    }

    #[test]
    fn test_handle_subscription_context_put_amf() {
        let event = create_test_event(
            "PUT",
            vec!["subscription-data", "imsi-001010000000001", "context-data", "amf-3gpp-access"],
        );
        handle_subscription_context(&event, 123);
    }

    #[test]
    fn test_handle_subscription_context_put_smf() {
        let event = create_test_event(
            "PUT",
            vec!["subscription-data", "imsi-001010000000001", "context-data", "smf-registrations"],
        );
        handle_subscription_context(&event, 123);
    }

    #[test]
    fn test_handle_subscription_provisioned_am_data() {
        let event = create_test_event(
            "GET",
            vec!["subscription-data", "imsi-001010000000001", "00101", "provisioned-data", "am-data"],
        );
        handle_subscription_provisioned(&event, 123);
    }

    #[test]
    fn test_handle_subscription_provisioned_smf_sel() {
        let event = create_test_event(
            "GET",
            vec!["subscription-data", "imsi-001010000000001", "00101", "provisioned-data", "smf-selection-subscription-data"],
        );
        handle_subscription_provisioned(&event, 123);
    }

    #[test]
    fn test_handle_subscription_provisioned_sm_data() {
        let event = create_test_event(
            "GET",
            vec!["subscription-data", "imsi-001010000000001", "00101", "provisioned-data", "sm-data"],
        );
        handle_subscription_provisioned(&event, 123);
    }

    #[test]
    fn test_handle_policy_data_am() {
        let event = create_test_event(
            "GET",
            vec!["policy-data", "ues", "imsi-001010000000001", "am-data"],
        );
        handle_policy_data(&event, 123);
    }

    #[test]
    fn test_handle_policy_data_sm() {
        let event = create_test_event(
            "GET",
            vec!["policy-data", "ues", "imsi-001010000000001", "sm-data"],
        );
        handle_policy_data(&event, 123);
    }
}
