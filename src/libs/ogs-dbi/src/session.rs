//! Session Database Queries
//!
//! Provides functions for querying session data.
//! Ported from lib/dbi/session.c in the C implementation.

use mongodb::bson::{doc, Bson, Document};

use crate::mongoc::{get_subscriber_collection, DbiError, DbiResult};
use crate::types::*;

/// Get session data for a subscriber with specific S-NSSAI and DNN
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier (e.g., "imsi-123456789012345")
/// * `s_nssai` - Optional S-NSSAI to match
/// * `dnn` - Data Network Name to match
///
/// # Returns
/// * `Ok(OgsSessionData)` with session and PCC rules
/// * `Err(DbiError)` on failure
pub fn ogs_dbi_session_data(
    supi: &str,
    s_nssai: Option<&OgsSNssai>,
    dnn: &str,
) -> DbiResult<OgsSessionData> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    // Find matching session in slice array
    let slice_array = document
        .get_array(OGS_SLICE_STRING)
        .map_err(|_| DbiError::FieldNotFound(OGS_SLICE_STRING.to_string()))?;

    for slice_val in slice_array {
        if let Bson::Document(slice_doc) = slice_val {
            // Check SST presence
            let sst = match slice_doc.get_i32(OGS_SST_STRING) {
                Ok(s) => s as u8,
                Err(_) => {
                    log::error!("No SST");
                    continue;
                }
            };

            // Parse SD
            let sd = if let Ok(sd_str) = slice_doc.get_str(OGS_SD_STRING) {
                OgsUint24::from_hex_string(sd_str).unwrap_or(OgsUint24::new(OGS_S_NSSAI_NO_SD_VALUE))
            } else {
                OgsUint24::new(OGS_S_NSSAI_NO_SD_VALUE)
            };

            // Check S-NSSAI match
            if let Some(req_snssai) = s_nssai {
                if req_snssai.sst != sst {
                    continue;
                }
                if req_snssai.sd.v != OGS_S_NSSAI_NO_SD_VALUE
                    && sd.v != OGS_S_NSSAI_NO_SD_VALUE
                    && req_snssai.sd.v != sd.v
                {
                    continue;
                }
            }

            // Search sessions for matching DNN
            if let Ok(session_array) = slice_doc.get_array(OGS_SESSION_STRING) {
                for session_val in session_array {
                    if let Bson::Document(session_doc) = session_val {
                        if let Ok(name) = session_doc.get_str(OGS_NAME_STRING) {
                            if name.eq_ignore_ascii_case(dnn) {
                                // Found matching session
                                return parse_session_data(session_doc, dnn);
                            }
                        }
                    }
                }
            }
        }
    }

    log::error!(
        "Cannot find SUPI[{}] S_NSSAI[SST:{} SD:0x{:x}] DNN[{}] in DB",
        supi_id,
        s_nssai.map(|s| s.sst).unwrap_or(0),
        s_nssai.map(|s| s.sd.v).unwrap_or(0),
        dnn
    );

    Err(DbiError::SessionNotFound)
}

/// Parse session data from BSON document
fn parse_session_data(doc: &Document, dnn: &str) -> DbiResult<OgsSessionData> {
    let mut session_data = OgsSessionData::new();

    // Parse session name
    if let Ok(name) = doc.get_str(OGS_NAME_STRING) {
        session_data.session.name = Some(name.to_string());
    }

    // Parse session type
    if let Ok(session_type) = doc.get_i32(OGS_TYPE_STRING) {
        session_data.session.session_type = session_type;
    }

    // Parse LBO roaming allowed
    if let Ok(lbo) = doc.get_bool(OGS_LBO_ROAMING_ALLOWED_STRING) {
        session_data.session.lbo_roaming_allowed = lbo;
    }

    // Parse QoS
    if let Ok(qos_doc) = doc.get_document(OGS_QOS_STRING) {
        session_data.session.qos = parse_qos(qos_doc);
    }

    // Parse AMBR
    if let Ok(ambr_doc) = doc.get_document(OGS_AMBR_STRING) {
        session_data.session.ambr = parse_ambr(ambr_doc);
    }

    // Parse PCC rules
    if let Ok(pcc_rule_array) = doc.get_array(OGS_PCC_RULE_STRING) {
        let mut pcc_rule_index = 0;

        for pcc_rule_val in pcc_rule_array {
            if pcc_rule_index >= OGS_MAX_NUM_OF_PCC_RULE {
                break;
            }

            if let Bson::Document(pcc_rule_doc) = pcc_rule_val {
                let mut pcc_rule = parse_pcc_rule(pcc_rule_doc);

                // Generate rule names based on DNN and index
                // EPC: Charging-Rule-Name
                pcc_rule.name = Some(format!("{}-g{}", dnn, pcc_rule_index + 1));
                // 5GC: PCC-Rule-Id
                pcc_rule.id = Some(format!("{}-n{}", dnn, pcc_rule_index + 1));
                pcc_rule.precedence = (pcc_rule_index + 1) as i32;

                session_data.pcc_rule.push(pcc_rule);
                pcc_rule_index += 1;
            }
        }
        session_data.num_of_pcc_rule = pcc_rule_index;
    }

    Ok(session_data)
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

    // Parse MBR
    if let Ok(mbr_doc) = doc.get_document(OGS_MBR_STRING) {
        qos.mbr = parse_ambr(mbr_doc);
    }

    // Parse GBR
    if let Ok(gbr_doc) = doc.get_document(OGS_GBR_STRING) {
        qos.gbr = parse_ambr(gbr_doc);
    }

    qos
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

/// Parse PCC rule from BSON document
fn parse_pcc_rule(doc: &Document) -> OgsPccRule {
    let mut pcc_rule = OgsPccRule::default();

    // Parse QoS
    if let Ok(qos_doc) = doc.get_document(OGS_QOS_STRING) {
        pcc_rule.qos = parse_pcc_rule_qos(qos_doc);
    }

    // Parse flows
    if let Ok(flow_array) = doc.get_array(OGS_FLOW_STRING) {
        for flow_val in flow_array {
            if pcc_rule.num_of_flow >= OGS_MAX_NUM_OF_FLOW_IN_PCC_RULE {
                break;
            }

            if let Bson::Document(flow_doc) = flow_val {
                let mut flow = OgsFlow::default();

                if let Ok(direction) = flow_doc.get_i32(OGS_DIRECTION_STRING) {
                    flow.direction = direction;
                }

                if let Ok(description) = flow_doc.get_str(OGS_DESCRIPTION_STRING) {
                    flow.description = Some(description.to_string());
                }

                pcc_rule.flow.push(flow);
                pcc_rule.num_of_flow += 1;
            }
        }
    }

    pcc_rule
}

/// Parse PCC rule QoS from BSON document (includes MBR/GBR)
fn parse_pcc_rule_qos(doc: &Document) -> OgsQos {
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

    // Parse MBR
    if let Ok(mbr_doc) = doc.get_document(OGS_MBR_STRING) {
        qos.mbr = parse_ambr(mbr_doc);
    }

    // Parse GBR
    if let Ok(gbr_doc) = doc.get_document(OGS_GBR_STRING) {
        qos.gbr = parse_ambr(gbr_doc);
    }

    qos
}
