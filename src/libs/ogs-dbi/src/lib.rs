//! NextGCore Database Interface Library
//!
//! This crate provides MongoDB operations for subscriber data.
//! Ported from lib/dbi/ in the C implementation.

pub mod federation;
pub mod graphdb; // B4.4: Graph database support
pub mod ims;
pub mod mongoc;
pub mod session;
pub mod subscription;
pub mod tsdb; // B4.5: Time-series database support
pub mod types; // B4.7: Data federation (cross-operator sharing)

#[cfg(test)]
mod property_tests;

// Re-export the mongodb crate for consumers that need direct collection access
pub use mongodb;

// Re-export commonly used types
pub use federation::{
    AccessPolicy, AggregationFunction, AnonymizationMethod, ExchangeProtocol, FederatedQuery,
    FederatedResponse, FederationClient, FederationError, FederationResult, OperatorId, QueryType,
};
pub use graphdb::{
    CypherQuery, GraphDbClient, GraphDbError, GraphDbResult, GraphNode, GraphRelationship,
    NetworkTopology, PropertyValue,
};
pub use ims::{ogs_dbi_ims_data, ogs_dbi_msisdn_data, OgsMsisdnData};
pub use mongoc::{
    ogs_dbi_final, ogs_dbi_init, ogs_dbi_init_async, ogs_mongoc, ogs_mongoc_final, ogs_mongoc_init,
    DbiError, DbiResult, OgsDbi, OgsMongoc,
};
pub use session::ogs_dbi_session_data;
pub use subscription::{
    ogs_dbi_auth_info, ogs_dbi_auth_info_async, ogs_dbi_increment_sqn, ogs_dbi_increment_sqn_async,
    ogs_dbi_policy_subscription_async, ogs_dbi_subscription_data, ogs_dbi_subscription_data_5g_async,
    ogs_dbi_subscription_data_async, ogs_dbi_update_imeisv, ogs_dbi_update_imeisv_async,
    ogs_dbi_update_mme, ogs_dbi_update_sqn, ogs_dbi_update_sqn_async, OgsDbiAuthInfo,
};
pub use tsdb::{
    DataPoint, MetricStats, NetworkMetricsCollector, TimeSeries, Timestamp, TsDbClient, TsDbError,
    TsDbResult,
};
pub use types::*;
