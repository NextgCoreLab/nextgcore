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
    nextgcore_time_from_msec,
    nextgcore_time_from_sec,
    parse_sockopt_config,
    ConfigDrift,
    ConfigDriftDetector,
    ConfigError,
    DriftReport,
    // B3.4: Configuration drift detection
    DriftSeverity,
    MaxConf,
    NextgcoreGlobalConf,
    NextgcoreLocalConf,
    NextgcorePlmnId,
    NextgcoreSupiRange,
    ParameterConf,
    PkbufConfig,
    SockoptConf,
    TimeConf,
    MAX_NUM_OF_PEER,
    MAX_NUM_OF_UE,
    NEXTGCORE_MAX_NUM_OF_PLMN,
    NEXTGCORE_MAX_NUM_OF_SESS,
    NEXTGCORE_MAX_NUM_OF_SLICE,
};
pub use context::{
    nextgcore_app, nextgcore_app_context_final, nextgcore_app_context_init, nextgcore_global_conf,
    nextgcore_local_conf, LoggerConf, MetricsConf, NextgcoreApp, NextgcoreAppContext,
    NextgcoreLogTs, PoolConf,
};
pub use init::{
    nextgcore_app_config_read, nextgcore_app_initialize, nextgcore_app_terminate, nf_common_init,
    CommandLineOptions, InitError, NextgcoreAppInitializer,
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
pub use yaml::{NextgcoreYamlDocument, NextgcoreYamlIter, YamlError, YamlNodeType};

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
