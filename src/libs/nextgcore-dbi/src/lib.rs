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
pub use ims::{nextgcore_dbi_ims_data, nextgcore_dbi_msisdn_data, NextgcoreMsisdnData};
pub use mongoc::{
    nextgcore_dbi_final, nextgcore_dbi_init, nextgcore_dbi_init_async, nextgcore_mongoc,
    nextgcore_mongoc_final, nextgcore_mongoc_init, DbiError, DbiResult, NextgcoreDbi,
    NextgcoreMongoc,
};
pub use session::nextgcore_dbi_session_data;
pub use subscription::{
    nextgcore_dbi_auth_info, nextgcore_dbi_auth_info_async, nextgcore_dbi_increment_sqn,
    nextgcore_dbi_increment_sqn_async, nextgcore_dbi_policy_subscription_async,
    nextgcore_dbi_subscription_data, nextgcore_dbi_subscription_data_5g_async,
    nextgcore_dbi_subscription_data_async, nextgcore_dbi_update_imeisv,
    nextgcore_dbi_update_imeisv_async, nextgcore_dbi_update_mme, nextgcore_dbi_update_sqn,
    nextgcore_dbi_update_sqn_async, NextgcoreDbiAuthInfo,
};
pub use tsdb::{
    DataPoint, MetricStats, NetworkMetricsCollector, TimeSeries, Timestamp, TsDbClient, TsDbError,
    TsDbResult,
};
pub use types::*;
