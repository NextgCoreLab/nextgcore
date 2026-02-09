//! Service Communication Proxy (SCP) Routing Support (B8.3)
//!
//! Implements SCP routing logic for indirect communication between NFs.
//! Based on 3GPP TS 29.500 Section 6.10.

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiRequest, SbiResponse};
use crate::types::{NfType, SbiServiceType};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// SCP routing modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpRoutingMode {
    /// Direct routing to target NF
    Direct,
    /// Routing via SCP
    Indirect,
    /// Delegated routing (SCP selection by NRF)
    Delegated,
}

/// SCP routing binding
#[derive(Debug, Clone)]
pub struct ScpBinding {
    /// SCP instance ID
    pub scp_instance_id: String,
    /// SCP FQDN
    pub scp_fqdn: String,
    /// SCP IP address
    pub scp_addr: String,
    /// SCP port
    pub scp_port: u16,
    /// Routing mode
    pub mode: ScpRoutingMode,
    /// Validity time (seconds)
    pub validity: u64,
}

impl ScpBinding {
    /// Create a new SCP binding
    pub fn new(
        instance_id: String,
        fqdn: String,
        addr: String,
        port: u16,
    ) -> Self {
        Self {
            scp_instance_id: instance_id,
            scp_fqdn: fqdn,
            scp_addr: addr,
            scp_port: port,
            mode: ScpRoutingMode::Indirect,
            validity: 3600, // 1 hour default
        }
    }

    /// Get SCP URI
    pub fn uri(&self) -> String {
        format!("http://{}:{}", self.scp_addr, self.scp_port)
    }
}

/// SCP routing information
#[derive(Debug, Clone)]
pub struct ScpRoutingInfo {
    /// Target NF type
    pub target_nf_type: NfType,
    /// Target NF instance ID (if known)
    pub target_nf_instance_id: Option<String>,
    /// Target service type
    pub target_service: SbiServiceType,
    /// SCP binding
    pub scp_binding: ScpBinding,
}

/// SCP router
pub struct ScpRouter {
    /// SCP bindings by NF type
    bindings: Arc<RwLock<HashMap<NfType, Vec<ScpBinding>>>>,
    /// Default SCP binding
    default_scp: Arc<RwLock<Option<ScpBinding>>>,
    /// Enable SCP routing
    enabled: bool,
}

impl ScpRouter {
    /// Create a new SCP router
    pub fn new() -> Self {
        Self {
            bindings: Arc::new(RwLock::new(HashMap::new())),
            default_scp: Arc::new(RwLock::new(None)),
            enabled: true,
        }
    }

    /// Enable/disable SCP routing
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if SCP routing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add SCP binding for a specific NF type
    pub fn add_binding(&self, nf_type: NfType, binding: ScpBinding) {
        let mut bindings = self.bindings.write().unwrap();
        bindings.entry(nf_type).or_default().push(binding);
    }

    /// Remove SCP binding
    pub fn remove_binding(&self, nf_type: NfType, scp_instance_id: &str) {
        let mut bindings = self.bindings.write().unwrap();
        if let Some(nf_bindings) = bindings.get_mut(&nf_type) {
            nf_bindings.retain(|b| b.scp_instance_id != scp_instance_id);
        }
    }

    /// Set default SCP
    pub fn set_default_scp(&self, binding: ScpBinding) {
        let mut default_scp = self.default_scp.write().unwrap();
        *default_scp = Some(binding);
    }

    /// Get SCP binding for target NF type
    pub fn get_binding(&self, nf_type: NfType) -> Option<ScpBinding> {
        let bindings = self.bindings.read().unwrap();

        // Try to find binding for specific NF type
        if let Some(nf_bindings) = bindings.get(&nf_type) {
            if let Some(binding) = nf_bindings.first() {
                return Some(binding.clone());
            }
        }

        // Fall back to default SCP
        let default_scp = self.default_scp.read().unwrap();
        default_scp.clone()
    }

    /// Route request through SCP
    pub fn route_request(
        &self,
        mut request: SbiRequest,
        target_nf_type: NfType,
        target_service: SbiServiceType,
    ) -> SbiResult<(SbiRequest, ScpRoutingInfo)> {
        if !self.enabled {
            return Err(SbiError::Internal("SCP routing disabled".to_string()));
        }

        let binding = self.get_binding(target_nf_type)
            .ok_or_else(|| SbiError::Internal("No SCP binding found".to_string()))?;

        // Add 3gpp-Sbi-Target-apiRoot header
        let target_api_root = format!(
            "http://{}",
            request.header.uri.trim_start_matches('/')
        );
        request.http.headers.insert(
            "3gpp-Sbi-Target-apiRoot".to_string(),
            target_api_root,
        );

        // Update request URI to point to SCP
        let scp_uri = binding.uri();
        let new_uri = format!("{}{}", scp_uri, request.header.uri);
        request.header.uri = new_uri;

        let routing_info = ScpRoutingInfo {
            target_nf_type,
            target_nf_instance_id: None,
            target_service,
            scp_binding: binding,
        };

        Ok((request, routing_info))
    }

    /// Extract target from response (for delegated routing)
    pub fn extract_scp_from_response(&self, response: &SbiResponse) -> Option<ScpBinding> {
        // Check for 3gpp-Sbi-Routing-Binding header
        if let Some(binding_header) = response.http.headers.get("3gpp-Sbi-Routing-Binding") {
            // Parse binding header (simplified)
            // Format: scp=<scp-fqdn>;<instance-id>=<id>
            return self.parse_routing_binding(binding_header);
        }

        None
    }

    /// Parse routing binding header
    fn parse_routing_binding(&self, header: &str) -> Option<ScpBinding> {
        // Simplified parsing - in real implementation, parse according to 3GPP spec
        let parts: HashMap<&str, &str> = header
            .split(';')
            .filter_map(|part| {
                let mut kv = part.split('=');
                Some((kv.next()?, kv.next()?))
            })
            .collect();

        let fqdn = parts.get("scp")?.to_string();
        let instance_id = parts.get("instance-id")?.to_string();

        // Extract address and port from FQDN
        let (addr, port) = if fqdn.contains(':') {
            let mut parts = fqdn.splitn(2, ':');
            let addr = parts.next()?.to_string();
            let port = parts.next()?.parse().ok()?;
            (addr, port)
        } else {
            (fqdn.clone(), 80)
        };

        Some(ScpBinding::new(instance_id, fqdn, addr, port))
    }

    /// Clear all bindings
    pub fn clear_bindings(&self) {
        let mut bindings = self.bindings.write().unwrap();
        bindings.clear();
    }
}

impl Default for ScpRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Global SCP router instance
static mut GLOBAL_SCP_ROUTER: Option<ScpRouter> = None;
static ROUTER_INIT: std::sync::Once = std::sync::Once::new();

/// Get global SCP router
pub fn global_scp_router() -> &'static ScpRouter {
    #[allow(static_mut_refs)]
    unsafe {
        ROUTER_INIT.call_once(|| {
            GLOBAL_SCP_ROUTER = Some(ScpRouter::new());
        });
        GLOBAL_SCP_ROUTER.as_ref().unwrap()
    }
}

/// Initialize SCP router
pub fn init_scp_router() {
    let _ = global_scp_router();
}

/// SCP-specific errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScpError {
    #[error("SCP routing disabled")]
    ScpRoutingDisabled,

    #[error("No SCP binding found")]
    NoScpBinding,

    #[error("Invalid routing binding header")]
    InvalidRoutingBinding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_binding_creation() {
        let binding = ScpBinding::new(
            "scp-001".to_string(),
            "scp.example.com".to_string(),
            "10.0.0.1".to_string(),
            8080,
        );

        assert_eq!(binding.scp_instance_id, "scp-001");
        assert_eq!(binding.scp_fqdn, "scp.example.com");
        assert_eq!(binding.scp_addr, "10.0.0.1");
        assert_eq!(binding.scp_port, 8080);
        assert_eq!(binding.uri(), "http://10.0.0.1:8080");
    }

    #[test]
    fn test_scp_router_binding() {
        let router = ScpRouter::new();

        let binding = ScpBinding::new(
            "scp-001".to_string(),
            "scp.example.com".to_string(),
            "10.0.0.1".to_string(),
            8080,
        );

        router.add_binding(NfType::Amf, binding.clone());

        let retrieved = router.get_binding(NfType::Amf);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().scp_instance_id, "scp-001");
    }

    #[test]
    fn test_scp_router_default() {
        let router = ScpRouter::new();

        let default_binding = ScpBinding::new(
            "scp-default".to_string(),
            "default-scp.example.com".to_string(),
            "10.0.0.2".to_string(),
            8080,
        );

        router.set_default_scp(default_binding);

        // Should return default when no specific binding exists
        let retrieved = router.get_binding(NfType::Smf);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().scp_instance_id, "scp-default");
    }

    #[test]
    fn test_scp_router_enabled() {
        let mut router = ScpRouter::new();
        assert!(router.is_enabled());

        router.set_enabled(false);
        assert!(!router.is_enabled());

        router.set_enabled(true);
        assert!(router.is_enabled());
    }

    #[test]
    fn test_routing_mode() {
        let modes = vec![
            ScpRoutingMode::Direct,
            ScpRoutingMode::Indirect,
            ScpRoutingMode::Delegated,
        ];

        for mode in modes {
            let mut binding = ScpBinding::new(
                "test".to_string(),
                "test.com".to_string(),
                "1.2.3.4".to_string(),
                80,
            );
            binding.mode = mode;
            assert_eq!(binding.mode, mode);
        }
    }

    #[test]
    fn test_clear_bindings() {
        let router = ScpRouter::new();

        router.add_binding(
            NfType::Amf,
            ScpBinding::new(
                "scp-1".to_string(),
                "scp1.com".to_string(),
                "1.1.1.1".to_string(),
                80,
            ),
        );

        router.add_binding(
            NfType::Smf,
            ScpBinding::new(
                "scp-2".to_string(),
                "scp2.com".to_string(),
                "2.2.2.2".to_string(),
                80,
            ),
        );

        router.clear_bindings();

        assert!(router.get_binding(NfType::Amf).is_none());
        assert!(router.get_binding(NfType::Smf).is_none());
    }
}
