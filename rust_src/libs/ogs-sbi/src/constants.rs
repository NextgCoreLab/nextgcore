//! SBI Constants
//!
//! HTTP status codes, methods, content types, and other constants
//! matching the C implementation in lib/sbi/message.h

/// HTTP Ports
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;

/// HTTP Schemes
pub const HTTP_SCHEME: &str = "http";
pub const HTTPS_SCHEME: &str = "https";

/// HTTP Status Codes
pub mod status {
    pub const OK: u16 = 200;
    pub const CREATED: u16 = 201;
    pub const ACCEPTED: u16 = 202;
    pub const NO_CONTENT: u16 = 204;
    pub const SEE_OTHER: u16 = 303;
    pub const TEMPORARY_REDIRECT: u16 = 307;
    pub const PERMANENT_REDIRECT: u16 = 308;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    pub const NOT_ACCEPTABLE: u16 = 406;
    pub const REQUEST_TIMEOUT: u16 = 408;
    pub const CONFLICT: u16 = 409;
    pub const GONE: u16 = 410;
    pub const LENGTH_REQUIRED: u16 = 411;
    pub const PRECONDITION_FAILED: u16 = 412;
    pub const PAYLOAD_TOO_LARGE: u16 = 413;
    pub const URI_TOO_LONG: u16 = 414;
    pub const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
    pub const TOO_MANY_REQUESTS: u16 = 429;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    pub const NOT_IMPLEMENTED: u16 = 501;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
    pub const GATEWAY_TIMEOUT: u16 = 504;
}

/// HTTP Methods
pub mod method {
    pub const DELETE: &str = "DELETE";
    pub const GET: &str = "GET";
    pub const PATCH: &str = "PATCH";
    pub const POST: &str = "POST";
    pub const PUT: &str = "PUT";
    pub const OPTIONS: &str = "OPTIONS";
}

/// API Versions
pub mod api {
    pub const V1: &str = "v1";
    pub const V1_0_0: &str = "1.0.0";
    pub const V2: &str = "v2";
    pub const V2_0_0: &str = "2.0.0";
}

/// Resource Names
pub mod resource {
    pub const NF_INSTANCES: &str = "nf-instances";
    pub const SUBSCRIPTIONS: &str = "subscriptions";
    pub const NF_STATUS_NOTIFY: &str = "nf-status-notify";
    pub const UE_AUTHENTICATIONS: &str = "ue-authentications";
    pub const FIVE_G_AKA: &str = "5g-aka";
    pub const FIVE_G_AKA_CONFIRMATION: &str = "5g-aka-confirmation";
    pub const EAP_SESSION: &str = "eap-session";
    pub const AM_DATA: &str = "am-data";
    pub const SM_DATA: &str = "sm-data";
    pub const SMF_SELECT_DATA: &str = "smf-select-data";
    pub const UE_CONTEXT_IN_SMF_DATA: &str = "ue-context-in-smf-data";
    pub const NSSAI: &str = "nssai";
    pub const SMF_SELECTION_SUBSCRIPTION_DATA: &str = "smf-selection-subscription-data";
    pub const SDM_SUBSCRIPTIONS: &str = "sdm-subscriptions";
    pub const SECURITY_INFORMATION: &str = "security-information";
    pub const GENERATE_AUTH_DATA: &str = "generate-auth-data";
    pub const AUTH_EVENTS: &str = "auth-events";
    pub const REGISTRATIONS: &str = "registrations";
    pub const AMF_3GPP_ACCESS: &str = "amf-3gpp-access";
    pub const SMF_REGISTRATIONS: &str = "smf-registrations";
    pub const SUBSCRIPTION_DATA: &str = "subscription-data";
    pub const AUTHENTICATION_DATA: &str = "authentication-data";
    pub const AUTHENTICATION_SUBSCRIPTION: &str = "authentication-subscription";
    pub const AUTHENTICATION_STATUS: &str = "authentication-status";
    pub const CONTEXT_DATA: &str = "context-data";
    pub const PROVISIONED_DATA: &str = "provisioned-data";
    pub const POLICY_DATA: &str = "policy-data";
    pub const UES: &str = "ues";
    pub const SM_CONTEXTS: &str = "sm-contexts";
    pub const MODIFY: &str = "modify";
    pub const RELEASE: &str = "release";
    pub const PDU_SESSIONS: &str = "pdu-sessions";
    pub const VSMF_PDU_SESSIONS: &str = "vsmf-pdu-session";
    pub const SM_POLICY_NOTIFY: &str = "sm-policy-notify";
    pub const N1_N2_FAILURE_NOTIFY: &str = "n1-n2-failure-notify";
    pub const UE_CONTEXTS: &str = "ue-contexts";
    pub const N1_N2_MESSAGES: &str = "n1-n2-messages";
    pub const TRANSFER: &str = "transfer";
    pub const TRANSFER_UPDATE: &str = "transfer-update";
    pub const SM_CONTEXT_STATUS: &str = "sm-context-status";
    pub const AM_POLICY_NOTIFY: &str = "am-policy-notify";
    pub const DEREG_NOTIFY: &str = "dereg-notify";
    pub const SDM_SUBSCRIPTION_NOTIFY: &str = "sdmsubscription-notify";
    pub const POLICIES: &str = "policies";
    pub const SM_POLICIES: &str = "sm-policies";
    pub const DELETE: &str = "delete";
    pub const APP_SESSIONS: &str = "app-sessions";
    pub const NOTIFY: &str = "notify";
    pub const UPDATE: &str = "update";
    pub const TERMINATE: &str = "terminate";
    pub const NETWORK_SLICE_INFORMATION: &str = "network-slice-information";
    pub const PCF_BINDINGS: &str = "pcfBindings";
    pub const EXCHANGE_CAPABILITY: &str = "exchange-capability";
}

/// HTTP Headers
pub mod header {
    pub const SCHEME: &str = ":scheme";
    pub const AUTHORITY: &str = ":authority";
    pub const ACCEPT: &str = "Accept";
    pub const ACCEPT_ENCODING: &str = "Accept-Encoding";
    pub const USER_AGENT: &str = "User-Agent";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const LOCATION: &str = "Location";
    pub const EXPECT: &str = "Expect";
}

/// Content Types
pub mod content_type {
    pub const APPLICATION: &str = "application";
    pub const JSON: &str = "json";
    pub const PROBLEM_JSON: &str = "problem+json";
    pub const PATCH_JSON: &str = "json-patch+json";
    pub const THREEGPP_HAL_JSON: &str = "3gppHal+json";
    pub const FIVE_GNAS: &str = "vnd.3gpp.5gnas";
    pub const NGAP: &str = "vnd.3gpp.ngap";

    pub const APPLICATION_JSON: &str = "application/json";
    pub const APPLICATION_PROBLEM_JSON: &str = "application/problem+json";
    pub const APPLICATION_PATCH_JSON: &str = "application/json-patch+json";
    pub const APPLICATION_3GPP_HAL_JSON: &str = "application/3gppHal+json";
    pub const APPLICATION_5GNAS: &str = "application/vnd.3gpp.5gnas";
    pub const APPLICATION_NGAP: &str = "application/vnd.3gpp.ngap";

    pub const MULTIPART: &str = "multipart";
    pub const RELATED: &str = "related";
    pub const MULTIPART_RELATED: &str = "multipart/related";
}

/// Custom 3GPP Headers
pub mod custom_header {
    pub const PREFIX: &str = "3gpp-Sbi-";
    pub const MESSAGE_PRIORITY: &str = "3gpp-Sbi-Message-Priority";
    pub const CALLBACK: &str = "3gpp-Sbi-Callback";
    pub const TARGET_APIROOT: &str = "3gpp-Sbi-Target-apiRoot";
    pub const ROUTING_BINDING: &str = "3gpp-Sbi-Routing-Binding";
    pub const BINDING: &str = "3gpp-Sbi-Binding";
    pub const PRODUCER_ID: &str = "3gpp-Sbi-Producer-Id";
    pub const OCI: &str = "3gpp-Sbi-Oci";
    pub const CLIENT_CREDENTIALS: &str = "3gpp-Sbi-Client-Credentials";
    pub const NRF_URI: &str = "3gpp-Sbi-Nrf-Uri";
    pub const TARGET_NF_ID: &str = "3gpp-Sbi-Target-Nf-Id";
    pub const ACCESS_SCOPE: &str = "3gpp-Sbi-Access-Scope";
    pub const ACCESS_TOKEN: &str = "3gpp-Sbi-Access-Token";
    pub const SENDER_TIMESTAMP: &str = "3gpp-Sbi-Sender-Timestamp";
    pub const MAX_RSP_TIME: &str = "3gpp-Sbi-Max-Rsp-Time";
}

/// Discovery Custom Headers
pub mod discovery_header {
    pub const PREFIX: &str = "3gpp-Sbi-Discovery-";
    pub const TARGET_NF_TYPE: &str = "3gpp-Sbi-Discovery-target-nf-type";
    pub const REQUESTER_NF_TYPE: &str = "3gpp-Sbi-Discovery-requester-nf-type";
    pub const TARGET_NF_INSTANCE_ID: &str = "3gpp-Sbi-Discovery-target-nf-instance-id";
    pub const REQUESTER_NF_INSTANCE_ID: &str = "3gpp-Sbi-Discovery-requester-nf-instance-id";
    pub const SERVICE_NAMES: &str = "3gpp-Sbi-Discovery-service-names";
    pub const SNSSAIS: &str = "3gpp-Sbi-Discovery-snssais";
    pub const DNN: &str = "3gpp-Sbi-Discovery-dnn";
    pub const TAI: &str = "3gpp-Sbi-Discovery-tai";
    pub const TARGET_PLMN_LIST: &str = "3gpp-Sbi-Discovery-target-plmn-list";
    pub const REQUESTER_PLMN_LIST: &str = "3gpp-Sbi-Discovery-requester-plmn-list";
    pub const REQUESTER_FEATURES: &str = "3gpp-Sbi-Discovery-requester-features";
    pub const GUAMI: &str = "3gpp-Sbi-Discovery-guami";
    pub const HNRF_URI: &str = "3gpp-Sbi-Discovery-hnrf-uri";
}

/// Query Parameters
pub mod param {
    pub const TARGET_NF_TYPE: &str = "target-nf-type";
    pub const REQUESTER_NF_TYPE: &str = "requester-nf-type";
    pub const TARGET_NF_INSTANCE_ID: &str = "target-nf-instance-id";
    pub const REQUESTER_NF_INSTANCE_ID: &str = "requester-nf-instance-id";
    pub const SERVICE_NAMES: &str = "service-names";
    pub const TARGET_PLMN_LIST: &str = "target-plmn-list";
    pub const REQUESTER_PLMN_LIST: &str = "requester-plmn-list";
    pub const REQUESTER_FEATURES: &str = "requester-features";
    pub const NF_ID: &str = "nf-id";
    pub const NF_TYPE: &str = "nf-type";
    pub const LIMIT: &str = "limit";
    pub const DNN: &str = "dnn";
    pub const PLMN_ID: &str = "plmn-id";
    pub const SINGLE_NSSAI: &str = "single-nssai";
    pub const SNSSAI: &str = "snssai";
    pub const GUAMI: &str = "guami";
    pub const SNSSAIS: &str = "snssais";
    pub const TAI: &str = "tai";
    pub const SLICE_INFO_REQUEST_FOR_PDU_SESSION: &str = "slice-info-request-for-pdu-session";
    pub const FIELDS: &str = "fields";
    pub const DATASET_NAMES: &str = "dataset-names";
    pub const IPV4ADDR: &str = "ipv4Addr";
    pub const IPV6PREFIX: &str = "ipv6Prefix";
    pub const HOME_PLMN_ID: &str = "home-plmn-id";
    pub const HNRF_URI: &str = "hnrf-uri";
}

/// Maximum values
pub mod limits {
    pub const MAX_NUM_OF_RESOURCE_COMPONENT: usize = 8;
    pub const MAX_NUM_OF_PART: usize = 8;
    pub const MAX_NUM_OF_FIELDS: usize = 8;
    pub const MAX_NUM_OF_DATASET_NAMES: usize = 8;
}

/// Callback names
pub mod callback {
    pub const NSMF_PDUSESSION_UPDATE: &str = "Nsmf_PDUSession_Update";
    pub const NSMF_PDUSESSION_STATUS_NOTIFY: &str = "Nsmf_PDUSession_StatusNotify";
    pub const NUDM_SDM_NOTIFICATION: &str = "Nudm_SDM_Notification";
    pub const NUDM_UECM_DEREGISTRATION_NOTIFICATION: &str = "Nudm_UECM_DeregistrationNotification";
    pub const NUDM_UECM_PCSCF_RESTORATION_NOTIFICATION: &str = "Nudm_UECM_PCSCFRestorationNotification";
    pub const NNRF_NFMANAGEMENT_NF_STATUS_NOTIFY: &str = "Nnrf_NFManagement_NFStatusNotify";
    pub const NAMF_EVENTEXPOSURE_NOTIFY: &str = "Namf_EventExposure_Notify";
    pub const NPCF_UEPOLICYCONTROL_UPDATE_NOTIFY: &str = "Npcf_UEPolicyControl_UpdateNotify";
    pub const NNSSF_NSSAIAVAILABILITY_NOTIFICATION: &str = "Nnssf_NSSAIAvailability_Notification";
    pub const NAMF_COMMUNICATION_AMF_STATUS_CHANGE_NOTIFY: &str = "Namf_Communication_AMFStatusChangeNotify";
    pub const NGMLC_LOCATION_EVENT_NOTIFY: &str = "Ngmlc_Location_EventNotify";
    pub const NCHF_CONVERGEDCHARGING_NOTIFY: &str = "Nchf_ConvergedCharging_Notify";
    pub const NNSSAAF_NSSAA_RE_AUTHENTICATION: &str = "Nnssaaf_NSSAA_ReAuthentication";
    pub const NNSSAAF_NSSAA_REVOCATION: &str = "Nnssaaf_NSSAA_Revocation";
    pub const N5G_DDNMF_DISCOVERY_MONITOR_UPDATE_RESULT: &str = "N5g-ddnmf_Discovery_MonitorUpdateResult";
    pub const N5G_DDNMF_DISCOVERY_MATCH_INFORMATION: &str = "N5g-ddnmf_Discovery_MatchInformation";
    pub const NAMF_COMMUNICATION_ON_N1N2_TRANSFER_FAILURE: &str = "Namf_Communication_onN1N2TransferFailure";
}

/// Content IDs for multipart messages
pub mod content_id {
    pub const CONTENT_ID: &str = "Content-Id";
    pub const FIVE_GNAS_SM: &str = "5gnas-sm";
    pub const NGAP_SM: &str = "ngap-sm";
}

/// Patch paths
pub mod patch_path {
    pub const NF_STATUS: &str = "/nfStatus";
    pub const LOAD: &str = "/load";
    pub const PLMN_LIST: &str = "/plmnList";
    pub const VALIDITY_TIME: &str = "/validityTime";
}

/// Interface names
pub mod interface {
    pub const SEPP: &str = "sepp";
    pub const N32F: &str = "n32f";
}
