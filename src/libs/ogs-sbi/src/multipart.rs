//! Multipart/related Encoding and Decoding
//!
//! Implements the `multipart/related` payload format used to carry binary
//! N1 (NAS) and N2 (NGAP) message containers alongside the JSON body, per
//! TS 29.500 Section 6.1.2.3 and RFC 2387.
//!
//! The root body part is the JSON payload (`application/json`); each binary
//! part carries a `Content-Id` that the JSON references via RefToBinaryData
//! (e.g. `application/vnd.3gpp.5gnas` for N1, `application/vnd.3gpp.ngap`
//! for N2). Part header names are matched case-insensitively.

use bytes::Bytes;

use crate::constants::content_type;
use crate::error::{SbiError, SbiResult};
use crate::message::SbiPart;

/// A decoded multipart/related body: the JSON root part plus binary parts.
#[derive(Debug, Clone, Default)]
pub struct MultipartBody {
    /// The JSON root part content, if present
    pub json: Option<String>,
    /// Binary parts with their Content-Id / Content-Type
    pub parts: Vec<SbiPart>,
}

/// Generate a unique MIME boundary string.
///
/// Built from the current timestamp in nanoseconds; boundary characters are
/// restricted to the RFC 2046 bchars set.
pub fn generate_boundary() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_nanos();
    format!("=-nextgcore-{ns:x}")
}

/// Build the `Content-Type` header value advertising a multipart/related
/// body with a JSON root part.
pub fn content_type_with_boundary(boundary: &str) -> String {
    format!(
        "{}; boundary=\"{}\"; type=\"{}\"",
        content_type::MULTIPART_RELATED,
        boundary,
        content_type::APPLICATION_JSON
    )
}

/// Extract the boundary parameter from a `Content-Type` header value,
/// matching the parameter name case-insensitively and stripping quotes.
pub fn boundary_from_content_type(header_value: &str) -> Option<String> {
    for param in header_value.split(';').skip(1) {
        let (name, value) = param.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("boundary") {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Check whether a `Content-Type` header value denotes multipart/related,
/// case-insensitively.
pub fn is_multipart_related(header_value: &str) -> bool {
    header_value
        .get(..content_type::MULTIPART_RELATED.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(content_type::MULTIPART_RELATED))
}

/// Encode a JSON root part and binary parts into a multipart/related body.
///
/// Layout per part: dash-boundary CRLF, part headers, empty line, content.
/// The JSON root (when present) is emitted first; binary parts follow with
/// their `Content-Id` so the JSON RefToBinaryData references resolve.
pub fn encode(json: Option<&str>, parts: &[SbiPart], boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();

    if let Some(json) = json {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Type: {}\r\n\r\n", content_type::APPLICATION_JSON).as_bytes(),
        );
        body.extend_from_slice(json.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if let Some(ref content_id) = part.content_id {
            body.extend_from_slice(format!("Content-Id: {content_id}\r\n").as_bytes());
        }
        let part_type = part
            .content_type
            .as_deref()
            .unwrap_or(content_type::APPLICATION_5GNAS);
        body.extend_from_slice(format!("Content-Type: {part_type}\r\n\r\n").as_bytes());
        body.extend_from_slice(&part.data);
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// Decode a multipart/related body using the boundary from the
/// `Content-Type` header value.
///
/// The first `application/json` part becomes the JSON root; every other
/// part is returned as a binary [`SbiPart`] with its Content-Id preserved.
pub fn decode(content_type_value: &str, body: &[u8]) -> SbiResult<MultipartBody> {
    let boundary = boundary_from_content_type(content_type_value).ok_or_else(|| {
        SbiError::InvalidResponse(format!(
            "multipart/related without boundary parameter: {content_type_value}"
        ))
    })?;

    let mut result = MultipartBody::default();
    for raw_part in split_parts(body, &boundary) {
        let (headers, data) = parse_part(raw_part)?;
        let part_type = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.clone());
        let content_id = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Id"))
            .map(|(_, v)| v.clone());

        let is_json_root = result.json.is_none()
            && part_type
                .as_deref()
                .is_some_and(|t| {
                    t.get(..content_type::APPLICATION_JSON.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(content_type::APPLICATION_JSON))
                });

        if is_json_root {
            result.json = Some(String::from_utf8_lossy(&data).to_string());
        } else {
            result.parts.push(SbiPart {
                content_id,
                content_type: part_type,
                data,
            });
        }
    }

    Ok(result)
}

/// Split a multipart body into raw parts on the boundary delimiter.
///
/// A delimiter is `--boundary` at the start of the body or preceded by CRLF
/// (RFC 2046 Section 5.1.1); the close-delimiter `--boundary--` ends the
/// scan. Returned slices exclude the delimiter lines and the CRLF that
/// belongs to the following delimiter.
fn split_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    let mut part_start: Option<usize> = None;

    while cursor + delimiter.len() <= body.len() {
        let at_delimiter = body[cursor..].starts_with(delimiter)
            && (cursor == 0 || body[cursor.saturating_sub(2)..cursor] == *b"\r\n");
        if !at_delimiter {
            cursor += 1;
            continue;
        }

        // Close the current part (its content ends before the CRLF that
        // precedes this delimiter).
        if let Some(start) = part_start.take() {
            let end = cursor.saturating_sub(2).max(start);
            parts.push(&body[start..end]);
        }

        let after = cursor + delimiter.len();
        // Close-delimiter: `--boundary--` terminates the body.
        if body[after..].starts_with(b"--") {
            break;
        }
        // Skip transport padding up to and including the CRLF ending the
        // delimiter line; the next part starts right after it.
        let line_end = body[after..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| after + p + 2)
            .unwrap_or(body.len());
        part_start = Some(line_end);
        cursor = line_end;
    }

    // Unterminated body (no close-delimiter): keep what we have.
    if let Some(start) = part_start {
        parts.push(&body[start..]);
    }
    parts
}

/// Parse one raw part into its header list and content bytes.
fn parse_part(raw: &[u8]) -> SbiResult<(Vec<(String, String)>, Bytes)> {
    // Headers are separated from the content by an empty line (CRLF CRLF).
    // A part with no headers starts directly with CRLF.
    let (header_block, content) = if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if raw.starts_with(b"\r\n") {
        (&raw[..0], &raw[2..])
    } else {
        return Err(SbiError::InvalidResponse(
            "multipart part without header/content separator".to_string(),
        ));
    };

    let mut headers = Vec::new();
    for line in String::from_utf8_lossy(header_block).lines() {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    Ok((headers, Bytes::copy_from_slice(content)))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nas_part() -> SbiPart {
        // Binary content with NUL, CRLF and 0xFF bytes to prove the decoder
        // is byte-exact and not line-oriented.
        SbiPart::with_content(
            "5gnas-sm",
            content_type::APPLICATION_5GNAS,
            Bytes::from_static(&[0x2e, 0x00, 0x01, 0xff, 0x0d, 0x0a, 0x00, 0x21]),
        )
    }

    fn ngap_part() -> SbiPart {
        SbiPart::with_content(
            "ngap-sm",
            content_type::APPLICATION_NGAP,
            Bytes::from_static(&[0x00, 0x15, 0x40, 0x29, 0xff, 0xfe]),
        )
    }

    #[test]
    fn test_multipart_round_trip() {
        let json = r#"{"n1MessageContainer":{"n1MessageContent":{"contentId":"5gnas-sm"}}}"#;
        let parts = vec![nas_part(), ngap_part()];
        let boundary = generate_boundary();

        let body = encode(Some(json), &parts, &boundary);
        let content_type_value = content_type_with_boundary(&boundary);
        let decoded = decode(&content_type_value, &body).unwrap();

        assert_eq!(decoded.json.as_deref(), Some(json));
        assert_eq!(decoded.parts.len(), 2);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("5gnas-sm"));
        assert_eq!(
            decoded.parts[0].content_type.as_deref(),
            Some(content_type::APPLICATION_5GNAS)
        );
        assert_eq!(decoded.parts[0].data, nas_part().data);
        assert_eq!(decoded.parts[1].content_id.as_deref(), Some("ngap-sm"));
        assert_eq!(decoded.parts[1].data, ngap_part().data);
    }

    #[test]
    fn test_decode_mixed_case_part_headers() {
        // Peers may emit any casing inside part headers; decode must not care.
        let boundary = "boundary42";
        let body = format!(
            "--{boundary}\r\n\
             CONTENT-TYPE: Application/JSON\r\n\r\n\
             {{\"k\":1}}\r\n\
             --{boundary}\r\n\
             content-id: n1-msg\r\n\
             content-type: application/vnd.3gpp.5gnas\r\n\r\n\
             NAS\r\n\
             --{boundary}--\r\n"
        );
        let content_type_value =
            format!("Multipart/Related; BOUNDARY=\"{boundary}\"; type=\"application/json\"");

        let decoded = decode(&content_type_value, body.as_bytes()).unwrap();
        assert_eq!(decoded.json.as_deref(), Some("{\"k\":1}"));
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("n1-msg"));
        assert_eq!(decoded.parts[0].data.as_ref(), b"NAS");
    }

    #[test]
    fn test_decode_unquoted_boundary() {
        assert_eq!(
            boundary_from_content_type("multipart/related; boundary=abc; type=\"application/json\""),
            Some("abc".to_string())
        );
        assert_eq!(
            boundary_from_content_type("multipart/related; boundary=\"q b\""),
            Some("q b".to_string())
        );
        assert_eq!(boundary_from_content_type("application/json"), None);
    }

    #[test]
    fn test_decode_missing_boundary_is_error() {
        let err = decode("multipart/related", b"--x\r\n\r\nbody\r\n--x--").unwrap_err();
        assert!(matches!(err, SbiError::InvalidResponse(_)));
    }

    #[test]
    fn test_encode_without_json_root() {
        // N2-only containers have no JSON root part.
        let boundary = "b1";
        let body = encode(None, &[ngap_part()], boundary);
        let decoded = decode(&content_type_with_boundary(boundary), &body).unwrap();
        assert!(decoded.json.is_none());
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("ngap-sm"));
    }

    #[test]
    fn test_is_multipart_related() {
        assert!(is_multipart_related("multipart/related; boundary=x"));
        assert!(is_multipart_related("Multipart/Related; boundary=x"));
        assert!(!is_multipart_related("application/json"));
    }

    #[test]
    fn test_binary_part_containing_boundary_like_bytes() {
        // Content containing "--" sequences that are not preceded by CRLF
        // must not be mistaken for a delimiter.
        let part = SbiPart::with_content(
            "bin",
            content_type::APPLICATION_NGAP,
            Bytes::from_static(b"xx--bin--yy"),
        );
        let boundary = "bin";
        let body = encode(None, std::slice::from_ref(&part), boundary);
        let decoded = decode(&content_type_with_boundary(boundary), &body).unwrap();
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].data, part.data);
    }
}
