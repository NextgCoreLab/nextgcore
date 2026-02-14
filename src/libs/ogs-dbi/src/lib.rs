//! NextGCore Database Interface Library
//!
//! This crate provides MongoDB operations for subscriber data.
//! Ported from lib/dbi/ in the C implementation.

pub mod types;
pub mod mongoc;
pub mod subscription;
pub mod session;
pub mod ims;
pub mod graphdb;  // B4.4: Graph database support
pub mod tsdb;     // B4.5: Time-series database support
pub mod federation;  // B4.7: Data federation (cross-operator sharing)

#[cfg(test)]
mod property_tests;

// Re-export the mongodb crate for consumers that need direct collection access
pub use mongodb;

// Re-export commonly used types
pub use types::*;
pub use mongoc::{
    OgsMongoc, OgsDbi, DbiError, DbiResult,
    ogs_mongoc, ogs_mongoc_init, ogs_mongoc_final,
    ogs_dbi_init, ogs_dbi_final,
};
pub use subscription::{
    OgsDbiAuthInfo, ogs_dbi_auth_info, ogs_dbi_update_sqn,
    ogs_dbi_increment_sqn, ogs_dbi_update_imeisv, ogs_dbi_update_mme,
    ogs_dbi_subscription_data,
};
pub use session::ogs_dbi_session_data;
pub use ims::{OgsMsisdnData, ogs_dbi_msisdn_data, ogs_dbi_ims_data};
pub use graphdb::{
    GraphDbClient, GraphNode, GraphRelationship, PropertyValue, CypherQuery,
    NetworkTopology, GraphDbError, GraphDbResult,
};
pub use tsdb::{
    TsDbClient, TimeSeries, DataPoint, Timestamp, NetworkMetricsCollector,
    TsDbError, TsDbResult, MetricStats,
};
pub use federation::{
    FederationClient, FederatedQuery, FederatedResponse, OperatorId,
    AccessPolicy, QueryType, AggregationFunction, AnonymizationMethod,
    ExchangeProtocol, FederationError, FederationResult,
};
