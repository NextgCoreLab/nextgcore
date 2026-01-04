//! Test context management
//!
//! Provides utilities for managing test context including NF lifecycle,
//! configuration, and cleanup.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use anyhow::Result;

use super::mongodb::MongoDbTestContainer;

/// Network function type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfType {
    // 5G Core NFs
    Nrf,
    Ausf,
    Udm,
    Udr,
    Pcf,
    Nssf,
    Bsf,
    Amf,
    Smf,
    Upf,
    Scp,
    Sepp,
    
    // EPC NFs
    Mme,
    Hss,
    Pcrf,
    Sgwc,
    Sgwu,
}

impl NfType {
    /// Get the default SBI port for this NF type
    pub fn default_sbi_port(&self) -> u16 {
        match self {
            NfType::Nrf => 7777,
            NfType::Ausf => 7778,
            NfType::Udm => 7779,
            NfType::Udr => 7780,
            NfType::Pcf => 7781,
            NfType::Nssf => 7782,
            NfType::Bsf => 7783,
            NfType::Amf => 7784,
            NfType::Smf => 7785,
            NfType::Upf => 7786,
            NfType::Scp => 7787,
            NfType::Sepp => 7788,
            NfType::Mme => 0,  // MME doesn't use SBI
            NfType::Hss => 0,  // HSS uses Diameter
            NfType::Pcrf => 0, // PCRF uses Diameter
            NfType::Sgwc => 0, // SGWC uses GTP-C
            NfType::Sgwu => 0, // SGWU uses GTP-U
        }
    }
    
    /// Get the NF name
    pub fn name(&self) -> &'static str {
        match self {
            NfType::Nrf => "NRF",
            NfType::Ausf => "AUSF",
            NfType::Udm => "UDM",
            NfType::Udr => "UDR",
            NfType::Pcf => "PCF",
            NfType::Nssf => "NSSF",
            NfType::Bsf => "BSF",
            NfType::Amf => "AMF",
            NfType::Smf => "SMF",
            NfType::Upf => "UPF",
            NfType::Scp => "SCP",
            NfType::Sepp => "SEPP",
            NfType::Mme => "MME",
            NfType::Hss => "HSS",
            NfType::Pcrf => "PCRF",
            NfType::Sgwc => "SGW-C",
            NfType::Sgwu => "SGW-U",
        }
    }
}

/// NF instance state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed(String),
}

/// NF instance information
#[derive(Debug, Clone)]
pub struct NfInstance {
    pub nf_type: NfType,
    pub state: NfState,
    pub sbi_addr: String,
    pub sbi_port: u16,
    pub config: HashMap<String, String>,
}

impl NfInstance {
    /// Create a new NF instance
    pub fn new(nf_type: NfType) -> Self {
        Self {
            nf_type,
            state: NfState::Stopped,
            sbi_addr: "127.0.0.1".to_string(),
            sbi_port: nf_type.default_sbi_port(),
            config: HashMap::new(),
        }
    }
    
    /// Get the SBI URL for this NF
    pub fn sbi_url(&self) -> String {
        format!("http://{}:{}", self.sbi_addr, self.sbi_port)
    }
    
    /// Check if the NF is running
    pub fn is_running(&self) -> bool {
        matches!(self.state, NfState::Running)
    }
}

/// Test context for managing integration test state
pub struct TestContext {
    /// MongoDB container (if needed)
    pub mongodb: Option<MongoDbTestContainer<'static>>,
    
    /// NF instances
    nf_instances: Arc<RwLock<HashMap<NfType, NfInstance>>>,
    
    /// Test configuration
    pub config: TestConfig,
}

/// Test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Timeout for NF startup
    pub nf_startup_timeout: Duration,
    
    /// Timeout for message exchange
    pub message_timeout: Duration,
    
    /// MongoDB connection string (if using external MongoDB)
    pub mongodb_uri: Option<String>,
    
    /// PLMN ID for tests
    pub plmn_id: PlmnId,
    
    /// TAC for tests
    pub tac: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            nf_startup_timeout: Duration::from_secs(30),
            message_timeout: Duration::from_secs(10),
            mongodb_uri: None,
            plmn_id: PlmnId::default(),
            tac: 1,
        }
    }
}

/// PLMN ID (MCC + MNC)
#[derive(Debug, Clone, Copy)]
pub struct PlmnId {
    pub mcc: u16,
    pub mnc: u16,
    pub mnc_len: u8,
}

impl Default for PlmnId {
    fn default() -> Self {
        Self {
            mcc: 001,
            mnc: 01,
            mnc_len: 2,
        }
    }
}

impl PlmnId {
    /// Create a new PLMN ID
    pub fn new(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        Self { mcc, mnc, mnc_len }
    }
    
    /// Convert to bytes (3 bytes)
    pub fn to_bytes(&self) -> [u8; 3] {
        let mcc_digit1 = (self.mcc / 100) as u8;
        let mcc_digit2 = ((self.mcc / 10) % 10) as u8;
        let mcc_digit3 = (self.mcc % 10) as u8;
        
        let mnc_digit1 = (self.mnc / 100) as u8;
        let mnc_digit2 = ((self.mnc / 10) % 10) as u8;
        let mnc_digit3 = (self.mnc % 10) as u8;
        
        if self.mnc_len == 2 {
            [
                (mcc_digit2 << 4) | mcc_digit1,
                0xF0 | mcc_digit3,
                (mnc_digit2 << 4) | mnc_digit1,
            ]
        } else {
            [
                (mcc_digit2 << 4) | mcc_digit1,
                (mnc_digit1 << 4) | mcc_digit3,
                (mnc_digit3 << 4) | mnc_digit2,
            ]
        }
    }
}

impl TestContext {
    /// Create a new test context
    pub fn new(config: TestConfig) -> Self {
        Self {
            mongodb: None,
            nf_instances: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Create a test context with default configuration
    pub fn default_context() -> Self {
        Self::new(TestConfig::default())
    }
    
    /// Register an NF instance
    pub async fn register_nf(&self, nf_type: NfType) -> Result<()> {
        let mut instances = self.nf_instances.write().await;
        instances.insert(nf_type, NfInstance::new(nf_type));
        log::info!("Registered NF: {}", nf_type.name());
        Ok(())
    }
    
    /// Get an NF instance
    pub async fn get_nf(&self, nf_type: NfType) -> Option<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances.get(&nf_type).cloned()
    }
    
    /// Update NF state
    pub async fn set_nf_state(&self, nf_type: NfType, state: NfState) -> Result<()> {
        let mut instances = self.nf_instances.write().await;
        if let Some(instance) = instances.get_mut(&nf_type) {
            instance.state = state;
            Ok(())
        } else {
            Err(anyhow::anyhow!("NF {} not registered", nf_type.name()))
        }
    }
    
    /// Start an NF (mock implementation for testing)
    pub async fn start_nf(&self, nf_type: NfType) -> Result<()> {
        self.set_nf_state(nf_type, NfState::Starting).await?;
        
        // In a real implementation, this would start the actual NF process
        // For now, we just mark it as running
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        self.set_nf_state(nf_type, NfState::Running).await?;
        log::info!("Started NF: {}", nf_type.name());
        Ok(())
    }
    
    /// Stop an NF
    pub async fn stop_nf(&self, nf_type: NfType) -> Result<()> {
        self.set_nf_state(nf_type, NfState::Stopping).await?;
        
        // In a real implementation, this would stop the actual NF process
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        self.set_nf_state(nf_type, NfState::Stopped).await?;
        log::info!("Stopped NF: {}", nf_type.name());
        Ok(())
    }
    
    /// Stop all NFs
    pub async fn stop_all_nfs(&self) -> Result<()> {
        let instances = self.nf_instances.read().await;
        let nf_types: Vec<NfType> = instances.keys().cloned().collect();
        drop(instances);
        
        for nf_type in nf_types {
            self.stop_nf(nf_type).await?;
        }
        
        Ok(())
    }
    
    /// Check if all required NFs are running
    pub async fn all_nfs_running(&self, required: &[NfType]) -> bool {
        let instances = self.nf_instances.read().await;
        required.iter().all(|nf_type| {
            instances.get(nf_type).map(|i| i.is_running()).unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_context_creation() {
        let ctx = TestContext::default_context();
        assert!(ctx.mongodb.is_none());
    }
    
    #[tokio::test]
    async fn test_nf_registration() {
        let ctx = TestContext::default_context();
        
        ctx.register_nf(NfType::Nrf).await.unwrap();
        ctx.register_nf(NfType::Amf).await.unwrap();
        
        let nrf = ctx.get_nf(NfType::Nrf).await;
        assert!(nrf.is_some());
        assert_eq!(nrf.unwrap().nf_type, NfType::Nrf);
    }
    
    #[tokio::test]
    async fn test_nf_lifecycle() {
        let ctx = TestContext::default_context();
        
        ctx.register_nf(NfType::Amf).await.unwrap();
        
        // Initially stopped
        let amf = ctx.get_nf(NfType::Amf).await.unwrap();
        assert_eq!(amf.state, NfState::Stopped);
        
        // Start
        ctx.start_nf(NfType::Amf).await.unwrap();
        let amf = ctx.get_nf(NfType::Amf).await.unwrap();
        assert_eq!(amf.state, NfState::Running);
        
        // Stop
        ctx.stop_nf(NfType::Amf).await.unwrap();
        let amf = ctx.get_nf(NfType::Amf).await.unwrap();
        assert_eq!(amf.state, NfState::Stopped);
    }
    
    #[test]
    fn test_plmn_id_to_bytes() {
        // Test MCC=001, MNC=01 (2-digit)
        // MCC digits: 0, 0, 1
        // MNC digits: 0, 0, 1 (but only 2 digits used: 0, 1)
        let plmn = PlmnId::new(001, 01, 2);
        let bytes = plmn.to_bytes();
        assert_eq!(bytes[0], 0x00); // MCC digit 2 (0) << 4 | MCC digit 1 (0)
        assert_eq!(bytes[1], 0xF1); // 0xF0 | MCC digit 3 (1)
        assert_eq!(bytes[2], 0x00); // MNC digit 2 (0) << 4 | MNC digit 1 (0)
    }
    
    #[test]
    fn test_nf_type_ports() {
        assert_eq!(NfType::Nrf.default_sbi_port(), 7777);
        assert_eq!(NfType::Amf.default_sbi_port(), 7784);
        assert_eq!(NfType::Mme.default_sbi_port(), 0); // MME doesn't use SBI
    }
}
