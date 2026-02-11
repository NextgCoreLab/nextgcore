//! NextGCore Application Framework Library
//!
//! This crate provides YAML configuration parsing, application initialization,
//! and context management for NextGCore network functions.
//!
//! Ported from lib/app/ in the C implementation.

pub mod yaml;
pub mod config;
pub mod context;
pub mod init;
pub mod intent;  // B3.2: Intent-based configuration translation
pub mod nf_hooks; // #197: Cross-NF AI/ML hooks, digital twin, energy, intent API

#[cfg(test)]
mod property_tests;

// Re-export commonly used types
pub use yaml::{OgsYamlDocument, OgsYamlIter, YamlError, YamlNodeType};
pub use config::{
    ConfigError, OgsGlobalConf, OgsLocalConf, OgsPlmnId, OgsSupiRange,
    ParameterConf, MaxConf, SockoptConf, PkbufConfig, TimeConf,
    ogs_time_from_sec, ogs_time_from_msec, parse_sockopt_config,
    OGS_MAX_NUM_OF_PLMN, OGS_MAX_NUM_OF_SLICE, OGS_MAX_NUM_OF_SESS,
    MAX_NUM_OF_UE, MAX_NUM_OF_PEER,
};
pub use context::{
    OgsApp, OgsAppContext, OgsLogTs, LoggerConf, PoolConf, MetricsConf,
    ogs_app, ogs_app_context_init, ogs_app_context_final,
    ogs_global_conf, ogs_local_conf,
};
pub use init::{
    InitError, CommandLineOptions, OgsAppInitializer,
    ogs_app_initialize, ogs_app_terminate, ogs_app_config_read,
};
pub use intent::{
    NetworkIntent, IntentTranslator, IntentError, IntentResult,
    IntentPriority, SliceIntent, QosIntent, SecurityIntent, EnergyIntent,
    AiMlIntent, DerivedConfig,
};

pub use nf_hooks::{
    AiMlHookPoint, AiMlHookAction, AiMlHook, AiMlHookRegistry,
    NfStateSnapshot, NfStatus, DigitalTwinExporter,
    NfEnergyState, EnergyRecommendation, EnergyCoordinator,
    CrossNfIntent, CrossNfIntentCategory, IntentStatus, CrossNfIntentCoordinator,
    // #214: Digital twin full state synchronization
    NfStateDelta, SnapshotHistoryEntry, DigitalTwinSyncManager,
    // #215: NF power profiling & optimization
    PowerComponent, ComponentPowerProfile, PowerOptimization, PowerAction, NfPowerProfiler,
};

// Macros are automatically exported via #[macro_export]
