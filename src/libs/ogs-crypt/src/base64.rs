//! Base64 Encoding/Decoding
//!
//! Exact port of lib/crypt/ogs-base64.c

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to base64 string
pub fn encode(input: &[u8]) -> String {
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 2 < input.len() {
        output.push(ENCODE_TABLE[(input[i] >> 2) as usize]);
        output.push(ENCODE_TABLE[(((input[i] & 0x03) << 4) | (input[i + 1] >> 4)) as usize]);
        output.push(ENCODE_TABLE[(((input[i + 1] & 0x0f) << 2) | (input[i + 2] >> 6)) as usize]);
        output.push(ENCODE_TABLE[(input[i + 2] & 0x3f) as usize]);
        i += 3;
    }

    if i < input.len() {
        output.push(ENCODE_TABLE[(input[i] >> 2) as usize]);
        if i + 1 < input.len() {
            output.push(ENCODE_TABLE[(((input[i] & 0x03) << 4) | (input[i + 1] >> 4)) as usize]);
            output.push(ENCODE_TABLE[((input[i + 1] & 0x0f) << 2) as usize]);
        } else {
            output.push(ENCODE_TABLE[((input[i] & 0x03) << 4) as usize]);
            output.push(b'=');
        }
        output.push(b'=');
    }

    // SAFETY: output only contains ASCII characters from ENCODE_TABLE and '='
    unsafe { String::from_utf8_unchecked(output) }
}

/// Decode base64 string to bytes. Returns None if input is invalid.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut buf_len = 0;

    for &byte in input {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                buf[buf_len] = 0;
                buf_len += 1;
                if buf_len == 4 {
                    output.push((buf[0] << 2) | (buf[1] >> 4));
                    if input.iter().filter(|&&c| c == b'=').count() < 2 {
                        output.push((buf[1] << 4) | (buf[2] >> 2));
                    }
                    buf_len = 0;
                }
                continue;
            }
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        };

        buf[buf_len] = val;
        buf_len += 1;

        if buf_len == 4 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
            output.push((buf[1] << 4) | (buf[2] >> 2));
            output.push((buf[2] << 6) | buf[3]);
            buf_len = 0;
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn test_encode_hello() {
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_encode_hello_world() {
        assert_eq!(encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn test_decode_hello() {
        assert_eq!(decode("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(decode(&encode(data)).unwrap(), data);
    }

    #[test]
    fn test_roundtrip_binary() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }
}
