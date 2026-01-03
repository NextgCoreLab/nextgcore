//! NF Mock implementations for integration testing
//!
//! Provides mock implementations of network functions for testing
//! without requiring full NF deployment.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use async_trait::async_trait;
use anyhow::Result;

use super::{NfType, MessageType, CapturedMessage, MessageCapture};

/// Mock NF trait for implementing test doubles
#[async_trait]
pub trait MockNf: Send + Sync {
    /// Get the NF type
    fn nf_type(&self) -> NfType;
    
    /// Start the mock NF
    async fn start(&mut self) -> Result<()>;
    
    /// Stop the mock NF
    async fn stop(&mut self) -> Result<()>;
    
    /// Handle an incoming message
    async fn handle_message(&mut self, msg: CapturedMessage) -> Result<Option<CapturedMessage>>;
    
    /// Check if the mock is running
    fn is_running(&self) -> bool;
}

/// Mock NF response configuration
#[derive(Debug, Clone)]
pub struct MockResponse {
    /// Response message type
    pub msg_type: MessageType,
    
    /// Response delay (for simulating network latency)
    pub delay_ms: u64,
    
    /// Whether to fail the response
    pub should_fail: bool,
    
    /// Failure reason (if should_fail is true)
    pub failure_reason: Option<String>,
}

impl MockResponse {
    /// Create a successful response
    pub fn success(msg_type: MessageType) -> Self {
        Self {
            msg_type,
            delay_ms: 0,
            should_fail: false,
            failure_reason: None,
        }
    }
    
    /// Create a delayed response
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }
    
    /// Create a failure response
    pub fn failure(reason: &str) -> Self {
        Self {
            msg_type: MessageType::Unknown("failure".to_string()),
            delay_ms: 0,
            should_fail: true,
            failure_reason: Some(reason.to_string()),
        }
    }
}

/// Generic mock NF implementation
pub struct GenericMockNf {
    nf_type: NfType,
    running: bool,
    responses: HashMap<MessageType, MockResponse>,
    capture: Arc<RwLock<MessageCapture>>,
}

impl GenericMockNf {
    /// Create a new generic mock NF
    pub fn new(nf_type: NfType, capture: Arc<RwLock<MessageCapture>>) -> Self {
        Self {
            nf_type,
            running: false,
            responses: HashMap::new(),
            capture,
        }
    }
    
    /// Configure a response for a message type
    pub fn on_message(&mut self, request: MessageType, response: MockResponse) {
        self.responses.insert(request, response);
    }
}

#[async_trait]
impl MockNf for GenericMockNf {
    fn nf_type(&self) -> NfType {
        self.nf_type
    }
    
    async fn start(&mut self) -> Result<()> {
        self.running = true;
        log::info!("Started mock {}", self.nf_type.name());
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.running = false;
        log::info!("Stopped mock {}", self.nf_type.name());
        Ok(())
    }
    
    async fn handle_message(&mut self, msg: CapturedMessage) -> Result<Option<CapturedMessage>> {
        // Capture the incoming message
        {
            let mut capture = self.capture.write().await;
            capture.capture(msg.clone());
        }
        
        // Look up configured response
        if let Some(response) = self.responses.get(&msg.msg_type) {
            if response.should_fail {
                return Err(anyhow::anyhow!(
                    "Mock failure: {}",
                    response.failure_reason.as_deref().unwrap_or("unknown")
                ));
            }
            
            // Apply delay if configured
            if response.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(response.delay_ms)).await;
            }
            
            // Create response message
            let response_msg = CapturedMessage::new(
                response.msg_type.clone(),
                bytes::Bytes::new(),
                &msg.destination,
                &msg.source,
            );
            
            Ok(Some(response_msg))
        } else {
            Ok(None)
        }
    }
    
    fn is_running(&self) -> bool {
        self.running
    }
}

/// Mock AMF for 5G registration tests
pub struct MockAmf {
    inner: GenericMockNf,
    registered_ues: Arc<RwLock<HashMap<String, UeContext>>>,
}

/// UE context for mock AMF
#[derive(Debug, Clone)]
pub struct UeContext {
    pub supi: String,
    pub guti: Option<String>,
    pub security_context: Option<SecurityContext>,
    pub state: UeState,
}

/// UE state in mock AMF
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeState {
    Deregistered,
    RegistrationInitiated,
    Authenticated,
    SecurityModeComplete,
    Registered,
}

/// Security context for mock
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub kausf: Vec<u8>,
    pub kseaf: Vec<u8>,
    pub kamf: Vec<u8>,
}

impl MockAmf {
    /// Create a new mock AMF
    pub fn new(capture: Arc<RwLock<MessageCapture>>) -> Self {
        let mut inner = GenericMockNf::new(NfType::Amf, capture);
        
        // Configure default responses
        inner.on_message(
            MessageType::RegistrationRequest,
            MockResponse::success(MessageType::AuthenticationRequest),
        );
        inner.on_message(
            MessageType::AuthenticationResponse,
            MockResponse::success(MessageType::SecurityModeCommand),
        );
        inner.on_message(
            MessageType::SecurityModeComplete,
            MockResponse::success(MessageType::RegistrationAccept),
        );
        
        Self {
            inner,
            registered_ues: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get registered UE count
    pub async fn registered_ue_count(&self) -> usize {
        self.registered_ues.read().await.len()
    }
    
    /// Check if a UE is registered
    pub async fn is_ue_registered(&self, supi: &str) -> bool {
        let ues = self.registered_ues.read().await;
        ues.get(supi).map(|ue| ue.state == UeState::Registered).unwrap_or(false)
    }
}

#[async_trait]
impl MockNf for MockAmf {
    fn nf_type(&self) -> NfType {
        NfType::Amf
    }
    
    async fn start(&mut self) -> Result<()> {
        self.inner.start().await
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.inner.stop().await
    }
    
    async fn handle_message(&mut self, msg: CapturedMessage) -> Result<Option<CapturedMessage>> {
        // Handle registration state machine
        if msg.msg_type == MessageType::RegistrationRequest {
            if let Some(supi) = msg.get_string("supi") {
                let mut ues = self.registered_ues.write().await;
                ues.insert(supi.to_string(), UeContext {
                    supi: supi.to_string(),
                    guti: None,
                    security_context: None,
                    state: UeState::RegistrationInitiated,
                });
            }
        }
        
        self.inner.handle_message(msg).await
    }
    
    fn is_running(&self) -> bool {
        self.inner.is_running()
    }
}

/// Mock MME for 4G attach tests
pub struct MockMme {
    inner: GenericMockNf,
    attached_ues: Arc<RwLock<HashMap<String, EpsUeContext>>>,
}

/// EPS UE context for mock MME
#[derive(Debug, Clone)]
pub struct EpsUeContext {
    pub imsi: String,
    pub guti: Option<String>,
    pub state: EpsUeState,
}

/// EPS UE state in mock MME
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpsUeState {
    Detached,
    AttachInitiated,
    Authenticated,
    Attached,
}

impl MockMme {
    /// Create a new mock MME
    pub fn new(capture: Arc<RwLock<MessageCapture>>) -> Self {
        let mut inner = GenericMockNf::new(NfType::Mme, capture);
        
        // Configure default responses
        inner.on_message(
            MessageType::AttachRequest,
            MockResponse::success(MessageType::AuthenticationRequest),
        );
        inner.on_message(
            MessageType::AuthenticationResponse,
            MockResponse::success(MessageType::SecurityModeCommand),
        );
        inner.on_message(
            MessageType::SecurityModeComplete,
            MockResponse::success(MessageType::AttachAccept),
        );
        
        Self {
            inner,
            attached_ues: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get attached UE count
    pub async fn attached_ue_count(&self) -> usize {
        self.attached_ues.read().await.len()
    }
}

#[async_trait]
impl MockNf for MockMme {
    fn nf_type(&self) -> NfType {
        NfType::Mme
    }
    
    async fn start(&mut self) -> Result<()> {
        self.inner.start().await
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.inner.stop().await
    }
    
    async fn handle_message(&mut self, msg: CapturedMessage) -> Result<Option<CapturedMessage>> {
        self.inner.handle_message(msg).await
    }
    
    fn is_running(&self) -> bool {
        self.inner.is_running()
    }
}

/// Mock NRF for service discovery tests
pub struct MockNrf {
    inner: GenericMockNf,
    registered_nfs: Arc<RwLock<HashMap<String, NfProfile>>>,
}

/// NF profile for mock NRF
#[derive(Debug, Clone)]
pub struct NfProfile {
    pub nf_instance_id: String,
    pub nf_type: NfType,
    pub nf_status: String,
    pub ipv4_addresses: Vec<String>,
    pub sbi_port: u16,
}

impl MockNrf {
    /// Create a new mock NRF
    pub fn new(capture: Arc<RwLock<MessageCapture>>) -> Self {
        let inner = GenericMockNf::new(NfType::Nrf, capture);
        
        Self {
            inner,
            registered_nfs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register an NF profile
    pub async fn register_nf(&self, profile: NfProfile) {
        let mut nfs = self.registered_nfs.write().await;
        nfs.insert(profile.nf_instance_id.clone(), profile);
    }
    
    /// Get registered NF count
    pub async fn registered_nf_count(&self) -> usize {
        self.registered_nfs.read().await.len()
    }
}

#[async_trait]
impl MockNf for MockNrf {
    fn nf_type(&self) -> NfType {
        NfType::Nrf
    }
    
    async fn start(&mut self) -> Result<()> {
        self.inner.start().await
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.inner.stop().await
    }
    
    async fn handle_message(&mut self, msg: CapturedMessage) -> Result<Option<CapturedMessage>> {
        self.inner.handle_message(msg).await
    }
    
    fn is_running(&self) -> bool {
        self.inner.is_running()
    }
}

/// Mock test environment with multiple NFs
pub struct MockEnvironment {
    mocks: HashMap<NfType, Box<dyn MockNf>>,
    capture: Arc<RwLock<MessageCapture>>,
}

impl MockEnvironment {
    /// Create a new mock environment
    pub fn new() -> Self {
        Self {
            mocks: HashMap::new(),
            capture: Arc::new(RwLock::new(MessageCapture::new())),
        }
    }
    
    /// Get the message capture
    pub fn capture(&self) -> Arc<RwLock<MessageCapture>> {
        self.capture.clone()
    }
    
    /// Add a mock NF to the environment
    pub fn add_mock(&mut self, mock: Box<dyn MockNf>) {
        self.mocks.insert(mock.nf_type(), mock);
    }
    
    /// Create a mock AMF and add it
    pub fn with_amf(mut self) -> Self {
        let amf = MockAmf::new(self.capture.clone());
        self.mocks.insert(NfType::Amf, Box::new(amf));
        self
    }
    
    /// Create a mock MME and add it
    pub fn with_mme(mut self) -> Self {
        let mme = MockMme::new(self.capture.clone());
        self.mocks.insert(NfType::Mme, Box::new(mme));
        self
    }
    
    /// Create a mock NRF and add it
    pub fn with_nrf(mut self) -> Self {
        let nrf = MockNrf::new(self.capture.clone());
        self.mocks.insert(NfType::Nrf, Box::new(nrf));
        self
    }
    
    /// Start all mocks
    pub async fn start_all(&mut self) -> Result<()> {
        for mock in self.mocks.values_mut() {
            mock.start().await?;
        }
        Ok(())
    }
    
    /// Stop all mocks
    pub async fn stop_all(&mut self) -> Result<()> {
        for mock in self.mocks.values_mut() {
            mock.stop().await?;
        }
        Ok(())
    }
    
    /// Send a message to a mock NF
    pub async fn send_message(&mut self, to: NfType, msg: CapturedMessage) -> Result<Option<CapturedMessage>> {
        if let Some(mock) = self.mocks.get_mut(&to) {
            mock.handle_message(msg).await
        } else {
            Err(anyhow::anyhow!("Mock {} not found", to.name()))
        }
    }
}

impl Default for MockEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    
    #[tokio::test]
    async fn test_generic_mock_nf() {
        let capture = Arc::new(RwLock::new(MessageCapture::new()));
        let mut mock = GenericMockNf::new(NfType::Amf, capture.clone());
        
        mock.on_message(
            MessageType::RegistrationRequest,
            MockResponse::success(MessageType::AuthenticationRequest),
        );
        
        mock.start().await.unwrap();
        assert!(mock.is_running());
        
        let msg = CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::new(),
            "UE",
            "AMF",
        );
        
        let response = mock.handle_message(msg).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().msg_type, MessageType::AuthenticationRequest);
        
        mock.stop().await.unwrap();
        assert!(!mock.is_running());
    }
    
    #[tokio::test]
    async fn test_mock_environment() {
        let mut env = MockEnvironment::new()
            .with_amf()
            .with_nrf();
        
        env.start_all().await.unwrap();
        
        let msg = CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::new(),
            "UE",
            "AMF",
        );
        
        let response = env.send_message(NfType::Amf, msg).await.unwrap();
        assert!(response.is_some());
        
        env.stop_all().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_mock_response_delay() {
        let capture = Arc::new(RwLock::new(MessageCapture::new()));
        let mut mock = GenericMockNf::new(NfType::Amf, capture);
        
        mock.on_message(
            MessageType::RegistrationRequest,
            MockResponse::success(MessageType::AuthenticationRequest).with_delay(50),
        );
        
        mock.start().await.unwrap();
        
        let msg = CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::new(),
            "UE",
            "AMF",
        );
        
        let start = std::time::Instant::now();
        let _ = mock.handle_message(msg).await.unwrap();
        let elapsed = start.elapsed();
        
        assert!(elapsed.as_millis() >= 50);
    }
}
