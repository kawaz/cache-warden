//! SSH agent protocol message types and parsing.

use crate::error::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ssh_key::{Fingerprint, HashAlg, PublicKey};

/// Maximum number of identities allowed in a single message.
/// This prevents malicious agents from causing excessive memory allocation.
const MAX_IDENTITIES: u32 = 10000;

/// Maximum size for a single key blob or comment (16 MB).
/// Prevents memory exhaustion from malicious length fields.
const MAX_BLOB_SIZE: u32 = 16 * 1024 * 1024;

/// Parsed SSH agent SIGN_REQUEST payload fields.
#[derive(Debug, Clone)]
pub struct SignRequestFields {
    /// Wire-format public key blob identifying the key to sign with.
    pub key_blob: Bytes,
    /// Bytes the agent is asked to sign.
    pub data: Bytes,
    /// Hash-algorithm selection flags (`SSH_AGENT_RSA_SHA2_256` etc.).
    pub flags: u32,
}

/// Read a size-prefixed (u32 big-endian length + bytes) field from `buf`,
/// enforcing `MAX_BLOB_SIZE` to prevent memory exhaustion.
fn read_size_prefixed(buf: &mut &[u8], label: &str) -> Result<Bytes> {
    if buf.remaining() < 4 {
        return Err(Error::InvalidMessage(format!("{label} length missing")));
    }
    let len_u32 = buf.get_u32();
    if len_u32 > MAX_BLOB_SIZE {
        return Err(Error::InvalidMessage(format!(
            "{label} size {len_u32} exceeds maximum allowed {MAX_BLOB_SIZE}"
        )));
    }
    let len = usize::try_from(len_u32).map_err(|_| {
        Error::InvalidMessage(format!(
            "{label} length {len_u32} cannot be converted to usize"
        ))
    })?;
    if buf.remaining() < len {
        return Err(Error::InvalidMessage(format!("{label} truncated")));
    }
    let bytes = Bytes::copy_from_slice(&buf[..len]);
    buf.advance(len);
    Ok(bytes)
}

/// SSH agent message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Requests from client
    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    RequestIdentities = 11,
    /// `SSH_AGENTC_SIGN_REQUEST`.
    SignRequest = 13,
    /// `SSH_AGENTC_ADD_IDENTITY`.
    AddIdentity = 17,
    /// `SSH_AGENTC_REMOVE_IDENTITY`.
    RemoveIdentity = 18,
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`.
    RemoveAllIdentities = 19,
    /// `SSH_AGENTC_ADD_ID_CONSTRAINED`.
    AddIdConstrained = 25,
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY`.
    AddSmartcardKey = 20,
    /// `SSH_AGENTC_REMOVE_SMARTCARD_KEY`.
    RemoveSmartcardKey = 21,
    /// `SSH_AGENTC_LOCK`.
    Lock = 22,
    /// `SSH_AGENTC_UNLOCK`.
    Unlock = 23,
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`.
    AddSmartcardKeyConstrained = 26,
    /// `SSH_AGENTC_EXTENSION`.
    Extension = 27,

    // Responses from agent
    /// `SSH_AGENT_FAILURE`.
    Failure = 5,
    /// `SSH_AGENT_SUCCESS`.
    Success = 6,
    /// `SSH_AGENT_IDENTITIES_ANSWER`.
    IdentitiesAnswer = 12,
    /// `SSH_AGENT_SIGN_RESPONSE`.
    SignResponse = 14,
    /// `SSH_AGENT_EXTENSION_FAILURE`.
    ExtensionFailure = 28,

    /// Any message-type byte not recognized above.
    Unknown = 0,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            11 => MessageType::RequestIdentities,
            13 => MessageType::SignRequest,
            17 => MessageType::AddIdentity,
            18 => MessageType::RemoveIdentity,
            19 => MessageType::RemoveAllIdentities,
            25 => MessageType::AddIdConstrained,
            20 => MessageType::AddSmartcardKey,
            21 => MessageType::RemoveSmartcardKey,
            22 => MessageType::Lock,
            23 => MessageType::Unlock,
            26 => MessageType::AddSmartcardKeyConstrained,
            27 => MessageType::Extension,
            5 => MessageType::Failure,
            6 => MessageType::Success,
            12 => MessageType::IdentitiesAnswer,
            14 => MessageType::SignResponse,
            28 => MessageType::ExtensionFailure,
            _ => MessageType::Unknown,
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        value as u8
    }
}

impl MessageType {
    /// Get the message type name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            // Client requests (SSH_AGENTC_*)
            MessageType::RequestIdentities => "SSH_AGENTC_REQUEST_IDENTITIES",
            MessageType::SignRequest => "SSH_AGENTC_SIGN_REQUEST",
            MessageType::AddIdentity => "SSH_AGENTC_ADD_IDENTITY",
            MessageType::RemoveIdentity => "SSH_AGENTC_REMOVE_IDENTITY",
            MessageType::RemoveAllIdentities => "SSH_AGENTC_REMOVE_ALL_IDENTITIES",
            MessageType::AddIdConstrained => "SSH_AGENTC_ADD_ID_CONSTRAINED",
            MessageType::AddSmartcardKey => "SSH_AGENTC_ADD_SMARTCARD_KEY",
            MessageType::RemoveSmartcardKey => "SSH_AGENTC_REMOVE_SMARTCARD_KEY",
            MessageType::Lock => "SSH_AGENTC_LOCK",
            MessageType::Unlock => "SSH_AGENTC_UNLOCK",
            MessageType::AddSmartcardKeyConstrained => "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED",
            MessageType::Extension => "SSH_AGENTC_EXTENSION",
            // Agent responses (SSH_AGENT_*)
            MessageType::Failure => "SSH_AGENT_FAILURE",
            MessageType::Success => "SSH_AGENT_SUCCESS",
            MessageType::IdentitiesAnswer => "SSH_AGENT_IDENTITIES_ANSWER",
            MessageType::SignResponse => "SSH_AGENT_SIGN_RESPONSE",
            MessageType::ExtensionFailure => "SSH_AGENT_EXTENSION_FAILURE",
            MessageType::Unknown => "UNKNOWN",
        }
    }
}

/// An SSH key identity from the agent.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Raw public key blob.
    pub key_blob: Bytes,
    /// Comment associated with the key.
    pub comment: String,
    /// Parsed public key (if parsing succeeded).
    pub public_key: Option<PublicKey>,
}

impl Identity {
    /// Parse an identity from key blob and comment.
    pub fn new(key_blob: Bytes, comment: String) -> Self {
        let public_key = PublicKey::from_bytes(&key_blob).ok();
        Self {
            key_blob,
            comment,
            public_key,
        }
    }

    /// Get the SHA-256 fingerprint of this key.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.public_key
            .as_ref()
            .map(|k| k.fingerprint(HashAlg::Sha256))
    }

    /// Get the key algorithm as a string.
    pub fn key_type(&self) -> Option<String> {
        self.public_key
            .as_ref()
            .map(|k| k.algorithm().as_str().to_string())
    }

    /// Get the key in OpenSSH format.
    pub fn to_openssh(&self) -> Option<String> {
        self.public_key
            .as_ref()
            .map(|k| k.to_openssh().unwrap_or_default())
    }
}

/// SSH agent protocol message.
#[derive(Debug, Clone)]
pub struct AgentMessage {
    /// Message type.
    pub msg_type: MessageType,
    /// Raw message payload (excluding the type byte).
    pub payload: Bytes,
}

impl AgentMessage {
    /// Create a new message.
    pub fn new(msg_type: MessageType, payload: Bytes) -> Self {
        Self { msg_type, payload }
    }

    /// Create a failure response.
    pub fn failure() -> Self {
        Self {
            msg_type: MessageType::Failure,
            payload: Bytes::new(),
        }
    }

    /// Create a success response.
    pub fn success() -> Self {
        Self {
            msg_type: MessageType::Success,
            payload: Bytes::new(),
        }
    }

    /// Parse identities from an IdentitiesAnswer message.
    pub fn parse_identities(&self) -> Result<Vec<Identity>> {
        if self.msg_type != MessageType::IdentitiesAnswer {
            return Err(Error::InvalidMessage(format!(
                "Expected IdentitiesAnswer, got {:?}",
                self.msg_type
            )));
        }

        let mut buf = &self.payload[..];
        if buf.remaining() < 4 {
            return Err(Error::InvalidMessage("Message too short".to_string()));
        }

        let count = buf.get_u32();

        if count > MAX_IDENTITIES {
            return Err(Error::InvalidMessage(format!(
                "Identity count {count} exceeds maximum allowed {MAX_IDENTITIES}"
            )));
        }

        let capacity = usize::try_from(count).map_err(|_| {
            Error::InvalidMessage(format!(
                "Identity count {count} cannot be converted to usize"
            ))
        })?;
        let mut identities = Vec::with_capacity(capacity);

        for _ in 0..count {
            let key_blob = read_size_prefixed(&mut buf, "Key blob")?;
            let comment_bytes = read_size_prefixed(&mut buf, "Comment")?;
            let comment = String::from_utf8_lossy(&comment_bytes).to_string();
            identities.push(Identity::new(key_blob, comment));
        }

        Ok(identities)
    }

    /// Build an IdentitiesAnswer message from a list of identities.
    ///
    /// # Panics
    /// Panics if the number of identities exceeds `u32::MAX` (practically impossible).
    pub fn build_identities_answer(identities: &[Identity]) -> Self {
        let mut payload = BytesMut::new();
        let count = u32::try_from(identities.len()).expect("identity count exceeds u32::MAX");
        payload.put_u32(count);

        for identity in identities {
            payload.put_u32(
                u32::try_from(identity.key_blob.len()).expect("key blob exceeds u32::MAX"),
            );
            payload.put_slice(&identity.key_blob);
            payload
                .put_u32(u32::try_from(identity.comment.len()).expect("comment exceeds u32::MAX"));
            payload.put_slice(identity.comment.as_bytes());
        }

        Self {
            msg_type: MessageType::IdentitiesAnswer,
            payload: payload.freeze(),
        }
    }

    /// Build a SignResponse from a pre-encoded signature blob.
    ///
    /// `signature_blob` is the SSH wire-format signature
    /// (`string(algorithm) + string(signature)`), produced by the signer.
    pub fn sign_response(signature_blob: &[u8]) -> Self {
        let mut payload = BytesMut::with_capacity(4 + signature_blob.len());
        payload
            .put_u32(u32::try_from(signature_blob.len()).expect("signature blob exceeds u32::MAX"));
        payload.put_slice(signature_blob);
        Self {
            msg_type: MessageType::SignResponse,
            payload: payload.freeze(),
        }
    }

    /// Parse the full SignRequest payload into routing key, signing input,
    /// and SSH agent flags.
    pub fn parse_sign_request(&self) -> Result<SignRequestFields> {
        if self.msg_type != MessageType::SignRequest {
            return Err(Error::InvalidMessage(format!(
                "Expected SignRequest, got {:?}",
                self.msg_type
            )));
        }

        let mut buf = &self.payload[..];
        let key_blob = read_size_prefixed(&mut buf, "Key blob")?;
        let data = read_size_prefixed(&mut buf, "Sign data")?;
        let flags = if buf.remaining() >= 4 {
            buf.get_u32()
        } else {
            0
        };
        Ok(SignRequestFields {
            key_blob,
            data,
            flags,
        })
    }

    /// Parse just the key blob from a SignRequest message.
    pub fn parse_sign_request_key(&self) -> Result<Bytes> {
        if self.msg_type != MessageType::SignRequest {
            return Err(Error::InvalidMessage(format!(
                "Expected SignRequest, got {:?}",
                self.msg_type
            )));
        }

        let mut buf = &self.payload[..];
        read_size_prefixed(&mut buf, "Key blob")
    }

    /// Encode the message to bytes (including the length prefix).
    pub fn encode(&self) -> Bytes {
        let total_len = 1 + self.payload.len();
        let mut buf = BytesMut::with_capacity(4 + total_len);
        buf.put_u32(u32::try_from(total_len).expect("message exceeds u32::MAX"));
        buf.put_u8(self.msg_type.into());
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Decode a message from bytes (excluding the length prefix).
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidMessage("Empty message".to_string()));
        }

        let msg_type = MessageType::from(data[0]);
        let payload = Bytes::copy_from_slice(&data[1..]);

        Ok(Self { msg_type, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        let types = [
            MessageType::RequestIdentities,
            MessageType::SignRequest,
            MessageType::IdentitiesAnswer,
            MessageType::Failure,
            MessageType::Success,
        ];

        for mt in types {
            let byte: u8 = mt.into();
            let back: MessageType = byte.into();
            assert_eq!(mt, back);
        }
    }

    #[test]
    fn test_message_type_unknown_byte() {
        // Any unmapped byte decodes to Unknown.
        assert_eq!(MessageType::from(99), MessageType::Unknown);
        assert_eq!(MessageType::from(0), MessageType::Unknown);
    }

    #[test]
    fn test_empty_identities_answer() {
        let msg = AgentMessage::build_identities_answer(&[]);
        assert_eq!(msg.msg_type, MessageType::IdentitiesAnswer);

        let identities = msg.parse_identities().unwrap();
        assert!(identities.is_empty());
    }

    #[test]
    fn test_failure_message() {
        let msg = AgentMessage::failure();
        assert_eq!(msg.msg_type, MessageType::Failure);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_success_message() {
        let msg = AgentMessage::success();
        assert_eq!(msg.msg_type, MessageType::Success);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_parse_sign_request_empty_payload() {
        let msg = AgentMessage::new(MessageType::SignRequest, Bytes::new());
        let result = msg.parse_sign_request_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length missing"));
    }

    #[test]
    fn test_parse_sign_request_zero_length_key() {
        let mut payload = BytesMut::new();
        payload.put_u32(0);
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let result = msg.parse_sign_request_key();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_sign_request_truncated_key() {
        let mut payload = BytesMut::new();
        payload.put_u32(100);
        payload.put_slice(&[0u8; 50]);
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let result = msg.parse_sign_request_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_parse_sign_request_oversized_key() {
        let mut payload = BytesMut::new();
        payload.put_u32(MAX_BLOB_SIZE + 1);
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let result = msg.parse_sign_request_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_parse_sign_request_wrong_message_type() {
        let msg = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let result = msg.parse_sign_request_key();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected SignRequest")
        );
    }

    #[test]
    fn test_parse_sign_request_fields() {
        // key_blob = "key", data = "data", flags = 2 (SSH_AGENT_RSA_SHA2_256).
        let mut payload = BytesMut::new();
        payload.put_u32(3);
        payload.put_slice(b"key");
        payload.put_u32(4);
        payload.put_slice(b"data");
        payload.put_u32(2);
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let fields = msg.parse_sign_request().unwrap();
        assert_eq!(&fields.key_blob[..], b"key");
        assert_eq!(&fields.data[..], b"data");
        assert_eq!(fields.flags, 2);
    }

    #[test]
    fn test_parse_sign_request_fields_missing_flags_defaults_zero() {
        // No trailing flags word -> flags default to 0.
        let mut payload = BytesMut::new();
        payload.put_u32(3);
        payload.put_slice(b"key");
        payload.put_u32(4);
        payload.put_slice(b"data");
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let fields = msg.parse_sign_request().unwrap();
        assert_eq!(fields.flags, 0);
    }

    #[test]
    fn test_parse_sign_request_fields_truncated_data() {
        // key_blob present, then a data length that overruns the buffer.
        let mut payload = BytesMut::new();
        payload.put_u32(3);
        payload.put_slice(b"key");
        payload.put_u32(100);
        payload.put_slice(&[0u8; 10]);
        let msg = AgentMessage::new(MessageType::SignRequest, payload.freeze());
        let result = msg.parse_sign_request();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_parse_identities_max_count() {
        let mut payload = BytesMut::new();
        payload.put_u32(MAX_IDENTITIES);
        let msg = AgentMessage::new(MessageType::IdentitiesAnswer, payload.freeze());
        let result = msg.parse_identities();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_identities_exceeds_max_count() {
        let mut payload = BytesMut::new();
        payload.put_u32(MAX_IDENTITIES + 1);
        let msg = AgentMessage::new(MessageType::IdentitiesAnswer, payload.freeze());
        let result = msg.parse_identities();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_parse_identities_too_short() {
        // Fewer than 4 bytes -> cannot read the count word.
        let msg = AgentMessage::new(MessageType::IdentitiesAnswer, Bytes::from_static(&[0, 1]));
        let result = msg.parse_identities();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_parse_identities_truncated_entry() {
        // count = 1, but the key blob is truncated.
        let mut payload = BytesMut::new();
        payload.put_u32(1);
        payload.put_u32(100);
        payload.put_slice(&[0u8; 10]);
        let msg = AgentMessage::new(MessageType::IdentitiesAnswer, payload.freeze());
        let result = msg.parse_identities();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_parse_identities_wrong_message_type() {
        let msg = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let result = msg.parse_identities();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected IdentitiesAnswer")
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = AgentMessage::new(MessageType::RequestIdentities, Bytes::new());
        let encoded = original.encode();
        // Skip the 4-byte length prefix.
        let decoded = AgentMessage::decode(&encoded[4..]).unwrap();
        assert_eq!(original.msg_type, decoded.msg_type);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn test_encode_length_prefix() {
        // Payload "ab" -> total_len = 1 (type) + 2 = 3, big-endian prefix.
        let msg = AgentMessage::new(MessageType::Success, Bytes::from_static(b"ab"));
        let encoded = msg.encode();
        assert_eq!(&encoded[..4], &[0, 0, 0, 3]);
        assert_eq!(encoded[4], u8::from(MessageType::Success));
        assert_eq!(&encoded[5..], b"ab");
    }

    #[test]
    fn test_identities_roundtrip() {
        let identities = vec![
            Identity::new(Bytes::from_static(b"\x00\x01\x02"), "key1".to_string()),
            Identity::new(Bytes::from_static(b"\x03\x04\x05"), "key2".to_string()),
        ];
        let msg = AgentMessage::build_identities_answer(&identities);
        let parsed = msg.parse_identities().unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].comment, "key1");
        assert_eq!(parsed[1].comment, "key2");
        assert_eq!(parsed[0].key_blob, Bytes::from_static(b"\x00\x01\x02"));
        assert_eq!(parsed[1].key_blob, Bytes::from_static(b"\x03\x04\x05"));
    }

    #[test]
    fn test_sign_response_roundtrip() {
        let sig = b"\xde\xad\xbe\xef";
        let msg = AgentMessage::sign_response(sig);
        assert_eq!(msg.msg_type, MessageType::SignResponse);
        let mut buf = &msg.payload[..];
        let blob = read_size_prefixed(&mut buf, "sig").unwrap();
        assert_eq!(&blob[..], sig);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_empty_data() {
        let result = AgentMessage::decode(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty message"));
    }

    #[test]
    fn test_decode_unknown_message_type() {
        // A single unknown type byte decodes into MessageType::Unknown.
        let decoded = AgentMessage::decode(&[99]).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Unknown);
        assert!(decoded.payload.is_empty());
    }
}
