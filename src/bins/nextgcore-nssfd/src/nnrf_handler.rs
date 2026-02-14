//! NSSF NRF Handler
//!
//! Port of src/nssf/nnrf-handler.c - NRF discovery response handler

use crate::event::SbiMessage;

/// NF Profile from NRF discovery
#[derive(Debug, Clone)]
pub struct NfProfile {
    pub nf_instance_id: String,
    pub nf_type: String,
    pub nf_status: String,
    pub fqdn: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub nf_services: Vec<NfService>,
}

/// NF Service from NRF discovery
#[derive(Debug, Clone)]
pub struct NfService {
    pub service_instance_id: String,
    pub service_name: String,
    pub versions: Vec<String>,
    pub scheme: String,
    pub fqdn: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub port: Option<u16>,
}

/// Discovery result
#[derive(Debug)]
pub enum DiscoveryResult {
    /// Success with NF profiles
    Success(Vec<NfProfile>),
    /// Error with status code and message
    Error(u16, String),
}

/// Handle NF discover response from NRF
/// Port of nssf_nnrf_handle_nf_discover
pub fn nssf_nnrf_handle_nf_discover(
    sbi_xact_id: u64,
    _message: &SbiMessage,
    nf_profiles: Vec<NfProfile>,
) -> DiscoveryResult {
    if nf_profiles.is_empty() {
        log::warn!("No NF profiles found in discovery response");
        return DiscoveryResult::Error(404, "No NF profiles found".to_string());
    }

    log::debug!(
        "NF discover response: {} profiles found (xact_id={})",
        nf_profiles.len(),
        sbi_xact_id
    );

    for profile in &nf_profiles {
        log::debug!(
            "  NF Instance: {} (type={}, status={})",
            profile.nf_instance_id, profile.nf_type, profile.nf_status
        );
    }

    DiscoveryResult::Success(nf_profiles)
}

/// Select best NF instance from discovery results
pub fn select_nf_instance<'a>(profiles: &'a [NfProfile], service_name: &str) -> Option<&'a NfProfile> {
    // Find profile with the requested service
    for profile in profiles {
        if profile.nf_status != "REGISTERED" {
            continue;
        }

        for service in &profile.nf_services {
            if service.service_name == service_name {
                return Some(profile);
            }
        }
    }

    // If no profile with specific service, return first registered profile
    profiles.iter().find(|p| p.nf_status == "REGISTERED")
}

/// Build NRF URI from NF profile
pub fn build_nrf_uri(profile: &NfProfile, service_name: &str) -> Option<String> {
    // Find the service
    let service = profile.nf_services.iter().find(|s| s.service_name == service_name)?;

    let scheme = &service.scheme;
    let port = service.port.unwrap_or(if scheme == "https" { 443 } else { 80 });

    // Prefer FQDN, then IPv4, then IPv6
    let host = if let Some(ref fqdn) = service.fqdn {
        fqdn.clone()
    } else if let Some(ref fqdn) = profile.fqdn {
        fqdn.clone()
    } else if let Some(ipv4) = service.ipv4_addresses.first() {
        ipv4.clone()
    } else if let Some(ipv4) = profile.ipv4_addresses.first() {
        ipv4.clone()
    } else if let Some(ipv6) = service.ipv6_addresses.first() {
        format!("[{ipv6}]")
    } else if let Some(ipv6) = profile.ipv6_addresses.first() {
        format!("[{ipv6}]")
    } else {
        return None;
    };

    Some(format!("{scheme}://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_profile() -> NfProfile {
        NfProfile {
            nf_instance_id: "test-nf-instance".to_string(),
            nf_type: "NSSF".to_string(),
            nf_status: "REGISTERED".to_string(),
            fqdn: Some("nssf.example.com".to_string()),
            ipv4_addresses: vec!["10.0.0.1".to_string()],
            ipv6_addresses: vec![],
            nf_services: vec![NfService {
                service_instance_id: "service-1".to_string(),
                service_name: "nnssf-nsselection".to_string(),
                versions: vec!["v2".to_string()],
                scheme: "https".to_string(),
                fqdn: None,
                ipv4_addresses: vec![],
                ipv6_addresses: vec![],
                port: Some(443),
            }],
        }
    }

    #[test]
    fn test_select_nf_instance() {
        let profiles = vec![create_test_profile()];
        let selected = select_nf_instance(&profiles, "nnssf-nsselection");
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().nf_instance_id, "test-nf-instance");
    }

    #[test]
    fn test_select_nf_instance_not_found() {
        let profiles = vec![create_test_profile()];
        let selected = select_nf_instance(&profiles, "non-existent-service");
        // Should still return the profile as fallback
        assert!(selected.is_some());
    }

    #[test]
    fn test_build_nrf_uri() {
        let profile = create_test_profile();
        let uri = build_nrf_uri(&profile, "nnssf-nsselection");
        assert!(uri.is_some());
        let uri = uri.unwrap();
        assert!(uri.starts_with("https://"));
        assert!(uri.contains("nssf.example.com") || uri.contains("10.0.0.1"));
    }

    #[test]
    fn test_discovery_result_empty() {
        let message = SbiMessage::default();
        let result = nssf_nnrf_handle_nf_discover(1, &message, vec![]);
        match result {
            DiscoveryResult::Error(status, _) => {
                assert_eq!(status, 404);
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_discovery_result_success() {
        let message = SbiMessage::default();
        let profiles = vec![create_test_profile()];
        let result = nssf_nnrf_handle_nf_discover(1, &message, profiles);
        match result {
            DiscoveryResult::Success(profiles) => {
                assert_eq!(profiles.len(), 1);
            }
            _ => panic!("Expected success"),
        }
    }
}
