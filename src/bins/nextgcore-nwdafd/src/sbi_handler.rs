//! NWDAF SBI Handler
//!
//! Implements Nnwdaf SBI services (TS 23.288):
//! - Nnwdaf_AnalyticsInfo: Analytics query and retrieval
//! - Nnwdaf_EventsSubscription: Analytics subscription management
//! - Nnwdaf_MLModelProvision: ML model training and deployment info

use crate::context::*;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{send_bad_request, send_not_found};

/// Handle Nnwdaf_AnalyticsInfo query
pub async fn handle_analytics_info_query(request: &SbiRequest) -> SbiResponse {
    log::info!("Analytics Info Query");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let analytics_type = data
        .get("analyticsId")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let analytics_id = match AnalyticsId::from_str(analytics_type) {
        Some(id) => id,
        None => {
            return send_bad_request(
                &format!("Invalid analytics type: {analytics_type}"),
                Some("INVALID_ANALYTICS_TYPE"),
            )
        }
    };

    let target_supi = data
        .get("targetOfAnalytics")
        .and_then(|v| v.get("supi"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let ctx = nwdaf_self();
    let models = if let Ok(context) = ctx.read() {
        context.get_deployed_models(analytics_id)
    } else {
        vec![]
    };

    let analytics_result = serde_json::json!({
        "analyticsId": analytics_type,
        "targetOfAnalytics": {
            "supi": target_supi,
        },
        "modelCount": models.len(),
        "models": models.iter().map(|m| {
            serde_json::json!({
                "modelId": m.model_id,
                "version": m.version,
                "accuracy": m.accuracy,
                "status": format!("{:?}", m.status),
            })
        }).collect::<Vec<_>>(),
        "analyticsReport": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "confidence": if !models.is_empty() { 0.85 } else { 0.0 },
        },
    });

    SbiResponse::with_status(200)
        .with_json_body(&analytics_result)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle analytics subscription creation
pub async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Analytics Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let analytics_type = data
        .get("analyticsId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let analytics_id = match AnalyticsId::from_str(analytics_type) {
        Some(id) => id,
        None => {
            return send_bad_request(
                &format!("Invalid analytics type: {analytics_type}"),
                Some("INVALID_ANALYTICS_TYPE"),
            )
        }
    };

    let notification_uri = data
        .get("notificationUri")
        .and_then(|v| v.as_str())
        .unwrap_or("http://localhost:8080/notify");

    let expiry_seconds = data
        .get("expiryTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let mut subscription = AnalyticsSubscription::new(
        subscription_id.clone(),
        analytics_id,
        notification_uri.to_string(),
        now + expiry_seconds,
    );

    if let Some(supi) = data
        .get("targetOfAnalytics")
        .and_then(|v| v.get("supi"))
        .and_then(|v| v.as_str())
    {
        subscription = subscription.with_target_supi(supi.to_string());
    }

    if let Some(snssai_obj) = data
        .get("targetOfAnalytics")
        .and_then(|v| v.get("snssai"))
    {
        if let (Some(sst), sd) = (
            snssai_obj.get("sst").and_then(|v| v.as_u64()),
            snssai_obj.get("sd").and_then(|v| v.as_u64()),
        ) {
            subscription = subscription.with_target_snssai(SNssai {
                sst: sst as u8,
                sd: sd.map(|v| v as u32),
            });
        }
    }

    let ctx = nwdaf_self();
    let result = if let Ok(context) = ctx.read() {
        context.add_subscription(subscription)
    } else {
        None
    };

    match result {
        Some(sub_id) => SbiResponse::with_status(201)
            .with_header(
                "Location",
                format!("/nnwdaf-eventssubscription/v1/subscriptions/{sub_id}"),
            )
            .with_json_body(&serde_json::json!({
                "subscriptionId": sub_id,
                "analyticsId": analytics_type,
                "notificationUri": notification_uri,
                "expiryTime": expiry_seconds,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request(
            "Failed to create subscription",
            Some("SUBSCRIPTION_FAILED"),
        ),
    }
}

/// Handle subscription retrieval
pub async fn handle_subscription_get(subscription_id: &str) -> SbiResponse {
    log::debug!("Get subscription: {subscription_id}");

    let ctx = nwdaf_self();
    let subscription = if let Ok(context) = ctx.read() {
        context.get_subscription(subscription_id)
    } else {
        None
    };

    match subscription {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "subscriptionId": sub.subscription_id,
                "analyticsId": sub.analytics_id.as_str(),
                "notificationUri": sub.notification_uri,
                "expiryTime": sub.expiry,
                "active": sub.active,
                "targetOfAnalytics": {
                    "supi": sub.target_supi,
                    "snssai": sub.target_snssai.as_ref().map(|s| serde_json::json!({
                        "sst": s.sst,
                        "sd": s.sd,
                    })),
                },
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Handle subscription deletion
pub async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("Delete subscription: {subscription_id}");

    let ctx = nwdaf_self();
    let removed = if let Ok(context) = ctx.read() {
        context.remove_subscription(subscription_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Handle ML model provisioning (registration)
pub async fn handle_model_provision(request: &SbiRequest) -> SbiResponse {
    log::info!("ML Model Provision");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let analytics_type = data
        .get("analyticsId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let analytics_id = match AnalyticsId::from_str(analytics_type) {
        Some(id) => id,
        None => {
            return send_bad_request(
                &format!("Invalid analytics type: {analytics_type}"),
                Some("INVALID_ANALYTICS_TYPE"),
            )
        }
    };

    let model_id = data
        .get("modelId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let version = data
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("v1.0");

    let final_model_id = if model_id.is_empty() {
        format!("model-{}", uuid::Uuid::new_v4())
    } else {
        model_id.to_string()
    };

    let mut model = MlModelInfo::new(final_model_id.clone(), analytics_id, version.to_string());

    if let Some(accuracy) = data.get("accuracy").and_then(|v| v.as_f64()) {
        model.accuracy = accuracy;
    }

    if let Some(samples) = data.get("trainingSamples").and_then(|v| v.as_u64()) {
        model.training_samples = samples as usize;
    }

    let ctx = nwdaf_self();
    let result = if let Ok(context) = ctx.read() {
        context.register_model(model)
    } else {
        None
    };

    match result {
        Some(mid) => SbiResponse::with_status(201)
            .with_header(
                "Location",
                format!("/nnwdaf-mlmodelprovision/v1/models/{mid}"),
            )
            .with_json_body(&serde_json::json!({
                "modelId": mid,
                "analyticsId": analytics_type,
                "version": version,
                "status": "TRAINING",
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request("Failed to register model", Some("MODEL_REGISTRATION_FAILED")),
    }
}

/// Handle ML model status retrieval
pub async fn handle_model_get(model_id: &str) -> SbiResponse {
    log::debug!("Get model: {model_id}");

    let ctx = nwdaf_self();
    let model = if let Ok(context) = ctx.read() {
        context.get_model(model_id)
    } else {
        None
    };

    match model {
        Some(m) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "modelId": m.model_id,
                "analyticsId": m.analytics_id.as_str(),
                "version": m.version,
                "accuracy": m.accuracy,
                "status": format!("{:?}", m.status),
                "trainingSamples": m.training_samples,
                "updatedAt": m.updated_at,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Model {model_id} not found"),
            Some("MODEL_NOT_FOUND"),
        ),
    }
}
