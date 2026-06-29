//! EES self-registration toward the Edge Configuration Server (ECS).
//!
//! TS 29.558 §9 `Eecs_EESRegistration`: the EES registers itself with the ECS
//! (reference point EDGE-6), NOT with the 5GC NRF — the EES is an Edge Enabler
//! Layer entity and has no `nfType` in TS 29.510. This module replaces the old
//! (incorrect) NRF self-registration as an `nfType "EES"` NF (eesd-01).
//!
//! Wire shape: `POST {ecsApiRoot}/eecs-eesregistration/v1/registrations`
//! (operationId `CreateEESRegistration`) with an `EESRegistration` body; the
//! ECS returns the resource at `registrations/{registrationId}` which is
//! refreshed periodically (PUT).
//!
//! No live ECS peer exists in this stack, so registration is gated behind the
//! `--ecs-uri` config: when unset, the request is built and logged but skipped
//! (the request SHAPE is still unit-tested). When set, the request is POSTed
//! via the existing `ogs-sbi` client and a refresh task is spawned.

use std::time::Duration;

use ogs_sbi::context::global_context;
use serde::{Deserialize, Serialize};

use crate::types::EndPoint;

/// API name + version prefix for the ECS-side EES registration service.
pub const ECS_API_PREFIX: &str = "eecs-eesregistration/v1";

/// Resource path (relative to the ECS apiRoot) of the EES registrations
/// collection.
pub fn ecs_registration_collection_path() -> String {
    format!("/{ECS_API_PREFIX}/registrations")
}

/// Resource path of an individual EES registration.
pub fn ecs_registration_resource_path(registration_id: &str) -> String {
    format!("/{ECS_API_PREFIX}/registrations/{registration_id}")
}

/// TS 29.558 §8 `EESProfile` (subset) — the EES's own description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EesProfile {
    /// EES identifier.
    pub ees_id: String,
    /// EES service endpoint(s).
    pub end_pt: EndPoint,
    /// Provider identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov_id: Option<String>,
    /// EAS application identifiers this EES serves (optional; populated as EASs
    /// register).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
}

/// TS 29.558 §8 `EESRegistration` (subset) — body of `CreateEESRegistration`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EesRegistration {
    /// EES profile (mandatory).
    pub ees_prof: EesProfile,
    /// Registration expiration time (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Build the `EESRegistration` body the EES POSTs to the ECS.
pub fn build_ees_registration(ees_id: &str, sbi_addr: &str, sbi_port: u16) -> EesRegistration {
    EesRegistration {
        ees_prof: EesProfile {
            ees_id: ees_id.to_string(),
            end_pt: EndPoint {
                ipv4_addrs: Some(vec![sbi_addr.to_string()]),
                port: Some(sbi_port as u32),
                ..Default::default()
            },
            prov_id: None,
            eas_ids: None,
        },
        exp_time: None,
        supp_feat: None,
    }
}

/// Parse "scheme://host:port[/path]" into ("host", port).
pub(crate) fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let host_port = without_scheme
        .split_once('/')
        .map(|(hp, _)| hp)
        .unwrap_or(without_scheme);
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// Start EES self-registration toward the ECS.
///
/// When `ecs_uri` is `None`, logs the built request and skips (no live ECS).
/// When `Some`, POSTs the `EESRegistration` and, on success, spawns a periodic
/// refresh task (PUT to the returned resource).
pub async fn start_ecs_registration(
    ecs_uri: Option<&str>,
    ees_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) {
    let registration = build_ees_registration(ees_id, sbi_addr, sbi_port);

    let Some(ecs_uri) = ecs_uri else {
        log::info!(
            "No --ecs-uri configured; skipping ECS self-registration. \
             Would POST {} with EESRegistration {{ eesId={ees_id} }}",
            ecs_registration_collection_path(),
        );
        return;
    };

    match register_once(ecs_uri, &registration).await {
        Ok(Some(registration_id)) => {
            log::info!("EES registered with ECS at {ecs_uri} (registrationId={registration_id})");
            spawn_refresh(ecs_uri.to_string(), registration, registration_id);
        }
        Ok(None) => {
            log::warn!("ECS registration accepted but returned no registrationId");
        }
        Err(e) => {
            log::warn!("ECS registration failed (will operate without ECS): {e}");
        }
    }
}

/// POST the `EESRegistration` to the ECS once; returns the assigned
/// `registrationId` (from the `Location` header or response body) on success.
async fn register_once(ecs_uri: &str, registration: &EesRegistration) -> Result<Option<String>, String> {
    let (host, port) = parse_host_port(ecs_uri).ok_or_else(|| "invalid --ecs-uri".to_string())?;
    let client = global_context().get_client(&host, port).await;
    let path = ecs_registration_collection_path();

    log::debug!("ECS registration: POST {path}");
    let response = client
        .post_json(&path, registration)
        .await
        .map_err(|e| format!("POST {path} failed: {e}"))?;

    match response.status {
        200 | 201 => Ok(extract_registration_id(&response)),
        s => Err(format!("ECS registration returned status {s}")),
    }
}

/// Extract the assigned registrationId from the `Location` header (last path
/// segment) or, failing that, the response body's `registrationId` field.
fn extract_registration_id(response: &ogs_sbi::message::SbiResponse) -> Option<String> {
    if let Some(loc) = response.http.get_header("location") {
        if let Some(id) = loc.trim_end_matches('/').rsplit('/').next() {
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    response
        .http
        .content
        .as_ref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|v| {
            v.get("registrationId")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
}

/// Spawn a periodic refresh task that PUTs the registration to keep it alive.
fn spawn_refresh(ecs_uri: String, registration: EesRegistration, registration_id: String) {
    tokio::spawn(async move {
        let path = ecs_registration_resource_path(&registration_id);
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let Some((host, port)) = parse_host_port(&ecs_uri) else {
                break;
            };
            let client = global_context().get_client(&host, port).await;
            match client.put_json(&path, &registration).await {
                Ok(r) if (200..300).contains(&r.status) => {
                    log::debug!("ECS registration refreshed (registrationId={registration_id})");
                }
                Ok(r) => log::warn!("ECS registration refresh returned status {}", r.status),
                Err(e) => log::warn!("ECS registration refresh failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eesd-01: the ECS registration request is built with the correct
    /// `eecs-eesregistration` path and a camelCase `EESRegistration` body.
    #[test]
    fn test_build_ees_registration_shape() {
        let reg = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        assert_eq!(reg.ees_prof.ees_id, "ees1.example.com");
        assert_eq!(reg.ees_prof.end_pt.port, Some(7814));
        assert_eq!(
            reg.ees_prof.end_pt.ipv4_addrs.as_deref(),
            Some(["10.0.0.5".to_string()].as_slice())
        );

        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"eesProf\""));
        assert!(json.contains("\"eesId\":\"ees1.example.com\""));
        assert!(json.contains("\"endPt\""));
        assert!(json.contains("\"ipv4Addrs\""));
    }

    #[test]
    fn test_ecs_registration_paths() {
        assert_eq!(
            ecs_registration_collection_path(),
            "/eecs-eesregistration/v1/registrations"
        );
        assert_eq!(
            ecs_registration_resource_path("abc-123"),
            "/eecs-eesregistration/v1/registrations/abc-123"
        );
    }

    #[test]
    fn test_ees_registration_roundtrip() {
        let reg = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        let json = serde_json::to_string(&reg).unwrap();
        let back: EesRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("http://ecs:8000"),
            Some(("ecs".to_string(), 8000))
        );
        assert_eq!(
            parse_host_port("https://ecs.example.com:443/edge"),
            Some(("ecs.example.com".to_string(), 443))
        );
        assert_eq!(
            parse_host_port("https://ecs.example.com"),
            Some(("ecs.example.com".to_string(), 443))
        );
    }

    #[test]
    fn test_extract_registration_id_from_location() {
        let resp = ogs_sbi::message::SbiResponse::with_status(201)
            .with_header("Location", "/eecs-eesregistration/v1/registrations/reg-42");
        assert_eq!(extract_registration_id(&resp), Some("reg-42".to_string()));
    }

    #[test]
    fn test_extract_registration_id_from_body() {
        let resp = ogs_sbi::message::SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({"registrationId": "reg-99"}))
            .unwrap();
        assert_eq!(extract_registration_id(&resp), Some("reg-99".to_string()));
    }
}
