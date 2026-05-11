//! NextGCore Application Framework Library
//!
//! This crate provides YAML configuration parsing, application initialization,
//! and context management for NextGCore network functions.
//!
//! Ported from lib/app/ in the C implementation.

pub mod config;
pub mod context;
pub mod init;
#[cfg(feature = "6g-extensions")]
pub mod intent; // B3.2: Intent-based configuration translation
#[cfg(feature = "6g-extensions")]
pub mod nf_hooks;
pub mod yaml; // #197: Cross-NF AI/ML hooks, digital twin, energy, intent API

#[cfg(test)]
mod property_tests;

// Re-export commonly used types
pub use config::{
    ogs_time_from_msec,
    ogs_time_from_sec,
    parse_sockopt_config,
    ConfigDrift,
    ConfigDriftDetector,
    ConfigError,
    DriftReport,
    // B3.4: Configuration drift detection
    DriftSeverity,
    MaxConf,
    OgsGlobalConf,
    OgsLocalConf,
    OgsPlmnId,
    OgsSupiRange,
    ParameterConf,
    PkbufConfig,
    SockoptConf,
    TimeConf,
    MAX_NUM_OF_PEER,
    MAX_NUM_OF_UE,
    OGS_MAX_NUM_OF_PLMN,
    OGS_MAX_NUM_OF_SESS,
    OGS_MAX_NUM_OF_SLICE,
};
pub use context::{
    ogs_app, ogs_app_context_final, ogs_app_context_init, ogs_global_conf, ogs_local_conf,
    LoggerConf, MetricsConf, OgsApp, OgsAppContext, OgsLogTs, PoolConf,
};
pub use init::{
    nf_common_init, ogs_app_config_read, ogs_app_initialize, ogs_app_terminate, CommandLineOptions,
    InitError, OgsAppInitializer,
};
#[cfg(feature = "6g-extensions")]
pub use intent::{
    AiMlIntent,
    DerivedConfig,
    EnergyIntent,
    IntentError,
    IntentLifecycleManager,
    IntentPriority,
    IntentResult,
    // B3.5: Intent lifecycle management
    IntentState,
    IntentTranslator,
    ManagedIntent,
    NetworkIntent,
    QosIntent,
    SecurityIntent,
    SliceIntent,
};
pub use yaml::{OgsYamlDocument, OgsYamlIter, YamlError, YamlNodeType};

#[cfg(feature = "6g-extensions")]
pub use nf_hooks::{
    AiMlHook,
    AiMlHookAction,
    AiMlHookPoint,
    AiMlHookRegistry,
    ComponentPowerProfile,
    CrossNfIntent,
    CrossNfIntentCategory,
    CrossNfIntentCoordinator,
    DeployedModel,
    DigitalTwinExporter,
    DigitalTwinSyncManager,
    EnergyCoordinator,
    EnergyRecommendation,
    IntentStatus,
    // B6.5: AI/ML model version registry
    ModelDeploymentStatus,
    ModelVersionRegistry,
    NfEnergyState,
    NfPowerProfiler,
    // #214: Digital twin full state synchronization
    NfStateDelta,
    NfStateSnapshot,
    NfStatus,
    PowerAction,
    // #215: NF power profiling & optimization
    PowerComponent,
    PowerOptimization,
    ScenarioResult,
    ScenarioSimulator,
    SnapshotHistoryEntry,
    // B6.6: Digital twin scenario simulator
    WhatIfScenario,
};

// Macros are automatically exported via #[macro_export]
