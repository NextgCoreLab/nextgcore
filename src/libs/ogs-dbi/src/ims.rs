//! IMS Database Queries
//!
//! Provides functions for querying IMS (IP Multimedia Subsystem) data.
//! Ported from lib/dbi/ims.c in the C implementation.

use mongodb::bson::{doc, Bson, Document};
use serde::{Deserialize, Serialize};

use crate::mongoc::{get_subscriber_collection, DbiError, DbiResult};
use crate::types::*;

/// MSISDN data structure for IMS queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsMsisdnData {
    pub imsi: OgsMsisdn,
    pub msisdn: Vec<OgsMsisdn>,
    pub num_of_msisdn: usize,
}

impl OgsMsisdnData {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Get MSISDN data by IMSI or MSISDN
///
/// # Arguments
/// * `imsi_or_msisdn_bcd` - IMSI or MSISDN in BCD format
///
/// # Returns
/// * `Ok(OgsMsisdnData)` with IMSI and MSISDN data
/// * `Err(DbiError)` on failure
pub fn ogs_dbi_msisdn_data(imsi_or_msisdn_bcd: &str) -> DbiResult<OgsMsisdnData> {
    let collection = get_subscriber_collection()?;

    // Query by either IMSI or MSISDN
    let query = doc! {
        "$or": [
            { "imsi": imsi_or_msisdn_bcd },
            { "msisdn": imsi_or_msisdn_bcd }
        ]
    };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(imsi_or_msisdn_bcd.to_string()))?;

    let mut msisdn_data = OgsMsisdnData::new();

    // Parse IMSI
    if let Ok(imsi_str) = document.get_str("imsi") {
        msisdn_data.imsi.bcd = imsi_str.to_string();
        ogs_bcd_to_buffer(&msisdn_data.imsi.bcd, &mut msisdn_data.imsi.buf);
        msisdn_data.imsi.len = msisdn_data.imsi.buf.len();
    }

    // Parse MSISDN array
    if let Ok(msisdn_array) = document.get_array("msisdn") {
        for msisdn_val in msisdn_array {
            if msisdn_data.num_of_msisdn >= OGS_MAX_NUM_OF_MSISDN {
                break;
            }
            if let Bson::String(bcd) = msisdn_val {
                let mut msisdn = OgsMsisdn::default();
                msisdn.bcd = bcd.clone();
                ogs_bcd_to_buffer(&bcd, &mut msisdn.buf);
                msisdn.len = msisdn.buf.len();
                msisdn_data.msisdn.push(msisdn);
                msisdn_data.num_of_msisdn += 1;
            }
        }
    }

    Ok(msisdn_data)
}

/// Get IMS data for a subscriber
///
/// # Arguments
/// * `supi` - Subscriber Permanent Identifier (e.g., "imsi-123456789012345")
///
/// # Returns
/// * `Ok(OgsImsData)` with IMS configuration
/// * `Err(DbiError)` on failure
pub fn ogs_dbi_ims_data(supi: &str) -> DbiResult<OgsImsData> {
    let supi_type = ogs_id_get_type(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;
    let supi_id = ogs_id_get_value(supi).ok_or_else(|| DbiError::InvalidSupi(supi.to_string()))?;

    let collection = get_subscriber_collection()?;
    let query = doc! { &supi_type: &supi_id };

    let document = collection
        .find_one(query, None)?
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;

    let mut ims_data = OgsImsData::new();

    // Parse MSISDN array
    if let Ok(msisdn_array) = document.get_array("msisdn") {
        for msisdn_val in msisdn_array {
            if ims_data.num_of_msisdn >= OGS_MAX_NUM_OF_MSISDN {
                break;
            }
            if let Bson::String(bcd) = msisdn_val {
                let mut msisdn = OgsMsisdn::default();
                msisdn.bcd = bcd.clone();
                ogs_bcd_to_buffer(&bcd, &mut msisdn.buf);
                msisdn.len = msisdn.buf.len();
                ims_data.msisdn.push(msisdn);
                ims_data.num_of_msisdn += 1;
            }
        }
    }

    // Parse IFC (Initial Filter Criteria) array
    if let Ok(ifc_array) = document.get_array("ifc") {
        for ifc_val in ifc_array {
            if ims_data.num_of_ifc >= OGS_MAX_NUM_OF_IFC {
                break;
            }
            if let Bson::Document(ifc_doc) = ifc_val {
                let ifc = parse_ifc(ifc_doc);
                ims_data.ifc.push(ifc);
                ims_data.num_of_ifc += 1;
            }
        }
    }

    Ok(ims_data)
}

/// Parse IFC (Initial Filter Criteria) from BSON document
fn parse_ifc(doc: &Document) -> OgsIfc {
    let mut ifc = OgsIfc::default();

    // Parse priority
    if let Ok(priority) = doc.get_i32("priority") {
        ifc.priority = priority;
    }

    // Parse application server
    if let Ok(as_doc) = doc.get_document("application_server") {
        if let Ok(server_name) = as_doc.get_str("server_name") {
            ifc.application_server.server_name = Some(server_name.to_string());
        }
        if let Ok(default_handling) = as_doc.get_i32("default_handling") {
            ifc.application_server.default_handling = default_handling;
        }
    }

    // Parse trigger point
    if let Ok(tp_doc) = doc.get_document("trigger_point") {
        ifc.trigger_point = parse_trigger_point(tp_doc);
    }

    ifc
}

/// Parse trigger point from BSON document
fn parse_trigger_point(doc: &Document) -> OgsTriggerPoint {
    let mut trigger_point = OgsTriggerPoint::default();

    // Parse condition type CNF
    if let Ok(condition_type_cnf) = doc.get_i32("condition_type_cnf") {
        trigger_point.condition_type_cnf = condition_type_cnf;
    }

    // Parse SPT (Service Point Trigger) array
    if let Ok(spt_array) = doc.get_array("spt") {
        for spt_val in spt_array {
            if trigger_point.num_of_spt >= OGS_MAX_NUM_OF_SPT {
                break;
            }
            if let Bson::Document(ref spt_doc) = spt_val {
                let spt = parse_spt(spt_doc);
                trigger_point.spt.push(spt);
                trigger_point.num_of_spt += 1;
            }
        }
    }

    trigger_point
}

/// Parse SPT (Service Point Trigger) from BSON document
fn parse_spt(doc: &Document) -> OgsSpt {
    let mut spt = OgsSpt::default();

    // Parse condition negated
    if let Ok(condition_negated) = doc.get_i32("condition_negated") {
        spt.condition_negated = condition_negated;
    }

    // Parse group
    if let Ok(group) = doc.get_i32("group") {
        spt.group = group;
    }

    // Parse method (sets type to OGS_SPT_HAS_METHOD)
    if let Ok(method) = doc.get_str("method") {
        spt.method = Some(method.to_string());
        spt.spt_type = OGS_SPT_HAS_METHOD;
    }

    // Parse session case (sets type to OGS_SPT_HAS_SESSION_CASE)
    if let Ok(session_case) = doc.get_i32("session_case") {
        spt.session_case = session_case;
        spt.spt_type = OGS_SPT_HAS_SESSION_CASE;
    }

    // Parse SIP header (sets type to OGS_SPT_HAS_SIP_HEADER)
    if let Ok(sip_header_doc) = doc.get_document("sip_header") {
        if let Ok(header) = sip_header_doc.get_str("header") {
            spt.header = Some(header.to_string());
        }
        if let Ok(content) = sip_header_doc.get_str("content") {
            spt.header_content = Some(content.to_string());
        }
        spt.spt_type = OGS_SPT_HAS_SIP_HEADER;
    }

    // Parse SDP line (sets type to OGS_SPT_HAS_SDP_LINE)
    if let Ok(sdp_line_doc) = doc.get_document("sdp_line") {
        if let Ok(line) = sdp_line_doc.get_str("line") {
            spt.sdp_line = Some(line.to_string());
        }
        if let Ok(content) = sdp_line_doc.get_str("content") {
            spt.sdp_line_content = Some(content.to_string());
        }
        spt.spt_type = OGS_SPT_HAS_SDP_LINE;
    }

    // Parse request URI (sets type to OGS_SPT_HAS_REQUEST_URI)
    if let Ok(request_uri) = doc.get_str("request_uri") {
        spt.request_uri = Some(request_uri.to_string());
        spt.spt_type = OGS_SPT_HAS_REQUEST_URI;
    }

    spt
}
