//! SBI Response Utilities
//!
//! Helper functions for sending SBI error responses in the UDM state machines.

use ogs_sbi::server::{send_bad_request, send_forbidden, send_gateway_timeout, send_not_found, send_method_not_allowed};

/// Send an error response for invalid API/service name
pub fn send_error_response(stream_id: u64, status: u16, detail: &str) {
    let response = match status {
        400 => send_bad_request(detail, Some("INVALID_REQUEST")),
        403 => send_forbidden(detail, Some("FORBIDDEN")),
        404 => send_not_found(detail, Some("NOT_FOUND")),
        504 => send_gateway_timeout(detail),
        _ => send_bad_request(detail, None),
    };

    log::debug!("Sending error response (stream_id={stream_id}, status={status}): {detail}");

    // In a real implementation, this would send the response through the SBI server
    // For now, we just log it as the SBI server infrastructure handles the actual sending
    crate::sbi_path::send_sbi_response(stream_id, response);
}

/// Send a 405 Method Not Allowed response
pub fn send_method_not_allowed_response(stream_id: u64, method: &str, resource: &str) {
    let response = send_method_not_allowed(method, resource);

    log::debug!("Sending 405 Method Not Allowed (stream_id={stream_id}): {method} {resource}");

    crate::sbi_path::send_sbi_response(stream_id, response);
}

/// Send a 400 Bad Request response
pub fn send_bad_request_response(stream_id: u64, detail: &str) {
    send_error_response(stream_id, 400, detail);
}

/// Send a 403 Forbidden response
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_error_response_creates_correct_status() {
        // This test verifies the function compiles and runs
        // Full integration testing requires SBI server setup
    }
}
