//! SBI Response Utilities
//!
//! Helper functions for sending SBI error responses in the BSF state machines.

use ogs_sbi::message::SbiResponse;
use ogs_sbi::server::{
    send_bad_request, send_forbidden, send_gateway_timeout, send_not_found,
    send_method_not_allowed,
};

/// Response queue for pending SBI responses
/// In a full implementation, this would be a channel to the HTTP server
static RESPONSE_QUEUE: std::sync::LazyLock<
    std::sync::Mutex<Vec<(u64, SbiResponse)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Send an error response for invalid API/service name
pub fn send_error_response(stream_id: u64, status: u16, detail: &str) {
    let response = match status {
        400 => send_bad_request(detail, Some("INVALID_REQUEST")),
        403 => send_forbidden(detail, Some("FORBIDDEN")),
        404 => send_not_found(detail, Some("NOT_FOUND")),
        504 => send_gateway_timeout(detail),
        _ => send_bad_request(detail, None),
    };

    log::debug!(
        "Sending error response (stream_id={stream_id}, status={status}): {detail}"
    );

    queue_sbi_response(stream_id, response);
}

/// Send a 405 Method Not Allowed response
#[allow(dead_code)]
pub fn send_method_not_allowed_response(stream_id: u64, method: &str, resource: &str) {
    let response = send_method_not_allowed(method, resource);

    log::debug!(
        "Sending 405 Method Not Allowed (stream_id={stream_id}): {method} {resource}"
    );

    queue_sbi_response(stream_id, response);
}

/// Send a 400 Bad Request response
#[allow(dead_code)]
pub fn send_bad_request_response(stream_id: u64, detail: &str) {
    send_error_response(stream_id, 400, detail);
}

/// Send a 403 Forbidden response
#[allow(dead_code)]
pub fn send_forbidden_response(stream_id: u64, detail: &str) {
    send_error_response(stream_id, 403, detail);
}

/// Send a 404 Not Found response
pub fn send_not_found_response(stream_id: u64, detail: &str) {
    send_error_response(stream_id, 404, detail);
}

/// Send a 504 Gateway Timeout response
pub fn send_gateway_timeout_response(stream_id: u64, detail: &str) {
    send_error_response(stream_id, 504, detail);
}

/// Queue an SBI response for delivery
///
/// In a real implementation, this would send the response through the HTTP server's
/// response channel. For now, we queue it for retrieval by the server.
fn queue_sbi_response(stream_id: u64, response: SbiResponse) {
    if let Ok(mut queue) = RESPONSE_QUEUE.lock() {
        queue.push((stream_id, response));
    }
}

/// Take a pending response from the queue (for testing/integration)
#[allow(dead_code)]
pub fn take_pending_response(stream_id: u64) -> Option<SbiResponse> {
    if let Ok(mut queue) = RESPONSE_QUEUE.lock() {
        if let Some(idx) = queue.iter().position(|(id, _)| *id == stream_id) {
            return Some(queue.remove(idx).1);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_error_response_400() {
        send_error_response(1, 400, "Test bad request");
        let response = take_pending_response(1);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 400);
    }

    #[test]
    fn test_send_error_response_404() {
        send_error_response(2, 404, "Test not found");
        let response = take_pending_response(2);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 404);
    }

    #[test]
    fn test_send_error_response_504() {
        send_error_response(3, 504, "Test gateway timeout");
        let response = take_pending_response(3);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 504);
    }

    #[test]
    fn test_send_not_found_response() {
        send_not_found_response(4, "Resource not found");
        let response = take_pending_response(4);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 404);
    }

    #[test]
    fn test_send_gateway_timeout_response() {
        send_gateway_timeout_response(5, "Timeout waiting for response");
        let response = take_pending_response(5);
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 504);
    }
}
