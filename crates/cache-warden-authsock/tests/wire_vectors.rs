//! Wire-format conformance vectors for the SSH agent protocol codec.
//!
//! These pin the on-the-wire byte layout (per draft-miller-ssh-agent, the same
//! framing authsock-warden implements) so the port is provably wire-compatible:
//! a length-prefixed message is `u32be(len) || type_byte || payload`, and every
//! variable-length field inside a payload is `u32be(field_len) || field_bytes`.

use bytes::BufMut;
use bytes::{Bytes, BytesMut};
use cache_warden_authsock::{AgentMessage, MessageType};

/// REQUEST_IDENTITIES on the wire: length 1, type byte 11, empty payload.
#[test]
fn request_identities_wire_bytes() {
    let msg = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
    let encoded = msg.encode();
    assert_eq!(&encoded[..], &[0x00, 0x00, 0x00, 0x01, 11]);
}

/// SUCCESS / FAILURE on the wire: length 1, the respective type byte.
#[test]
fn success_failure_wire_bytes() {
    assert_eq!(
        &AgentMessage::success().encode()[..],
        &[0x00, 0x00, 0x00, 0x01, 6]
    );
    assert_eq!(
        &AgentMessage::failure().encode()[..],
        &[0x00, 0x00, 0x00, 0x01, 5]
    );
}

/// An IdentitiesAnswer carrying one identity, byte-for-byte.
///
/// payload = u32be(count=1)
///         || u32be(key_blob_len=3) || "abc"
///         || u32be(comment_len=4)  || "note"
/// then framed with type byte 12 and a 4-byte total-length prefix.
#[test]
fn identities_answer_wire_bytes() {
    use cache_warden_authsock::Identity;

    let identities = vec![Identity::new(
        Bytes::from_static(b"abc"),
        "note".to_string(),
    )];
    let encoded = AgentMessage::build_identities_answer(&identities).encode();

    // payload = 4 (count) + 4 (klen) + 3 (key) + 4 (clen) + 4 (comment) = 19
    // total_len = 1 (type) + 19 = 20
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x14, // total length = 20
        12,   // SSH_AGENT_IDENTITIES_ANSWER
        0x00, 0x00, 0x00, 0x01, // count = 1
        0x00, 0x00, 0x00, 0x03, // key blob length = 3
        b'a', b'b', b'c', // key blob
        0x00, 0x00, 0x00, 0x04, // comment length = 4
        b'n', b'o', b't', b'e', // comment
    ];
    assert_eq!(&encoded[..], expected);

    // And the parser recovers the identity from the canonical bytes.
    let decoded = AgentMessage::decode(&encoded[4..]).unwrap();
    let parsed = decoded.parse_identities().unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(&parsed[0].key_blob[..], b"abc");
    assert_eq!(parsed[0].comment, "note");
}

/// A SIGN_REQUEST payload built from canonical bytes parses into the expected
/// fields, including the RSA-SHA2-256 flag (value 2).
#[test]
fn sign_request_wire_fields() {
    let mut payload = BytesMut::new();
    payload.put_slice(&[0x00, 0x00, 0x00, 0x03]); // key blob length = 3
    payload.put_slice(b"key");
    payload.put_slice(&[0x00, 0x00, 0x00, 0x05]); // data length = 5
    payload.put_slice(b"hello");
    payload.put_slice(&[0x00, 0x00, 0x00, 0x02]); // flags = SSH_AGENT_RSA_SHA2_256

    let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
    let fields = msg.parse_sign_request().unwrap();
    assert_eq!(&fields.key_blob[..], b"key");
    assert_eq!(&fields.data[..], b"hello");
    assert_eq!(fields.flags, 2);
}

/// A SIGN_RESPONSE wraps the signature blob with a single u32 length prefix.
#[test]
fn sign_response_wire_bytes() {
    let encoded = AgentMessage::sign_response(b"\x01\x02\x03").encode();
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x08, // total length = 1 (type) + 4 (len) + 3 (sig) = 8
        14,   // SSH_AGENT_SIGN_RESPONSE
        0x00, 0x00, 0x00, 0x03, // signature blob length = 3
        0x01, 0x02, 0x03, // signature blob
    ];
    assert_eq!(&encoded[..], expected);
}
