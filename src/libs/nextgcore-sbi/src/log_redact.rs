//! Redaction of callback URIs before they reach a log line (#940 review).
//!
//! Some callback URIs carry a bearer secret in their path: the AMF's NF status
//! notification URI (`.../nf-status-notify/{token}`, #940) and its UECM
//! deregistration callback (`.../dereg-notify/{token}`, #753). Anyone who reads
//! the log could use the token to forge a notification, and logs are shipped and
//! retained far more widely than the NF that holds the token.

/// Path segments whose NEXT segment is a callback token.
pub const CALLBACK_TOKEN_SEGMENTS: [&str; 2] = ["nf-status-notify", "dereg-notify"];

/// What a redacted segment is replaced with.
pub const REDACTED: &str = "<redacted>";

/// `uri` (an absolute URI or a path) with the segment after each
/// [`CALLBACK_TOKEN_SEGMENTS`] entry replaced by [`REDACTED`]. Everything else,
/// the query included, is kept.
pub fn redact_callback_tokens(uri: &str) -> String {
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (uri, None),
    };
    let mut out: Vec<&str> = Vec::new();
    let mut redact_next = false;
    for segment in path.split('/') {
        if redact_next && !segment.is_empty() {
            out.push(REDACTED);
        } else {
            out.push(segment);
        }
        redact_next = CALLBACK_TOKEN_SEGMENTS.contains(&segment);
    }
    let mut redacted = out.join("/");
    if let Some(q) = query {
        redacted.push('?');
        redacted.push_str(q);
    }
    redacted
}

/// A subscriber-supplied callback URI as it may be logged by the NF that calls
/// it: scheme and authority kept, the last path segment replaced by
/// [`REDACTED`], the query dropped. The NRF cannot know which part of a third
/// party's callback URI is secret; the last segment is where a per-subscription
/// token goes (TS 29.510 leaves `nfStatusNotificationUri` opaque).
pub fn redact_last_segment(uri: &str) -> String {
    let uri = uri.split(['?', '#']).next().unwrap_or(uri);
    let after_scheme = uri.find("://").map_or(0, |i| i + 3);
    let Some(path_at) = uri[after_scheme..].find('/').map(|i| i + after_scheme) else {
        return uri.to_string();
    };
    let path = uri[path_at..].trim_end_matches('/');
    match path.rfind('/') {
        Some(last) if last + 1 < path.len() => {
            format!("{}{}/{REDACTED}", &uri[..path_at], &path[..last])
        }
        _ => uri.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_tokens_are_redacted_and_the_rest_kept() {
        assert_eq!(
            redact_callback_tokens("/namf-callback/v1/nf-status-notify/0123abcd"),
            "/namf-callback/v1/nf-status-notify/<redacted>"
        );
        assert_eq!(
            redact_callback_tokens(
                "http://amf:7777/namf-callback/v1/imsi-001/dereg-notify/feed?x=1"
            ),
            "http://amf:7777/namf-callback/v1/imsi-001/dereg-notify/<redacted>?x=1"
        );
        assert_eq!(
            redact_callback_tokens("/namf-callback/v1/nf-status-notify"),
            "/namf-callback/v1/nf-status-notify"
        );
        assert_eq!(
            redact_callback_tokens("/nsmf-pdusession/v1/sm-contexts/1/modify"),
            "/nsmf-pdusession/v1/sm-contexts/1/modify"
        );
    }

    #[test]
    fn the_last_segment_of_a_subscriber_uri_is_redacted() {
        assert_eq!(
            redact_last_segment("http://10.0.0.1:7777/namf-callback/v1/nf-status-notify/s3cr3t"),
            "http://10.0.0.1:7777/namf-callback/v1/nf-status-notify/<redacted>"
        );
        assert_eq!(
            redact_last_segment("http://smf.example.com/notify?token=s3cr3t"),
            "http://smf.example.com/<redacted>"
        );
        assert_eq!(
            redact_last_segment("http://smf.example.com"),
            "http://smf.example.com"
        );
        assert_eq!(
            redact_last_segment("http://smf.example.com/"),
            "http://smf.example.com/"
        );
    }
}
