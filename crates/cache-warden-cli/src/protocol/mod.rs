//! Control-socket protocol v1: wire types, JSON Lines framing, TTL parsing.
//!
//! See `docs/decisions/DR-0009-control-socket-protocol-v1.md`.

pub mod duration;
pub mod wire;

pub use duration::parse_duration;
use wire::{Request, Response};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Encode raw secret bytes to the base64 form used on the wire.
pub fn encode_b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Decode a wire base64 string back to raw bytes.
pub fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(s)
}

/// Serialize a request to a single JSON line (no trailing newline).
pub fn encode_request(req: &Request) -> Result<String, serde_json::Error> {
    serde_json::to_string(req)
}

/// Serialize a response to a single JSON line (no trailing newline).
pub fn encode_response(resp: &Response) -> Result<String, serde_json::Error> {
    serde_json::to_string(resp)
}

/// Parse one JSON line into a [`Request`].
pub fn decode_request(line: &str) -> Result<Request, serde_json::Error> {
    serde_json::from_str(line)
}

/// Parse one JSON line into a [`Response`].
pub fn decode_response(line: &str) -> Result<Response, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrips_binary() {
        let bytes = vec![0u8, 1, 2, 255, 254, 0, b'\n'];
        let encoded = encode_b64(&bytes);
        assert_eq!(decode_b64(&encoded).unwrap(), bytes);
    }

    #[test]
    fn b64_carries_a_newline_safely() {
        // A value containing a newline must survive the JSON Lines framing.
        let bytes = b"line1\nline2\n".to_vec();
        let encoded = encode_b64(&bytes);
        assert!(!encoded.contains('\n'));
        assert_eq!(decode_b64(&encoded).unwrap(), bytes);
    }

    #[test]
    fn request_line_has_no_newline() {
        let line = encode_request(&Request::Ping).unwrap();
        assert!(!line.contains('\n'));
    }

    #[test]
    fn response_line_has_no_newline() {
        let line = encode_response(&Response::pong()).unwrap();
        assert!(!line.contains('\n'));
    }

    #[test]
    fn request_roundtrips_through_line_codec() {
        let req = Request::KvGet { key: "K".into() };
        let line = encode_request(&req).unwrap();
        assert_eq!(decode_request(&line).unwrap(), req);
    }

    #[test]
    fn ok_and_err_responses_decode_to_the_correct_arm() {
        // The untagged Response enum must not confuse ok/err.
        let ok_line = encode_response(&Response::get("AA==".into())).unwrap();
        assert!(decode_response(&ok_line).unwrap().is_ok());

        let err_line =
            encode_response(&Response::error(wire::ErrorKind::NotFound, "no such key")).unwrap();
        assert!(!decode_response(&err_line).unwrap().is_ok());
    }
}
