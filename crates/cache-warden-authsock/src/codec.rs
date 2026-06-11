//! Length-prefixed async framing for SSH agent messages.

use crate::error::{Error, Result};
use crate::message::AgentMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size (16 MB, same as OpenSSH).
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Codec for reading and writing SSH agent messages over a byte stream.
///
/// The wire format is a 4-byte big-endian length prefix followed by that many
/// bytes (type byte + payload). The pure byte ⇔ message conversion lives on
/// [`AgentMessage`]; this codec only adds the framed async I/O.
pub struct AgentCodec;

impl AgentCodec {
    /// Read a single message from an async reader.
    ///
    /// Returns `Ok(None)` on a clean EOF (including a truncated length prefix),
    /// and an error on a zero/oversized length or a truncated body.
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<AgentMessage>> {
        // Read length prefix (4 bytes).
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(len_buf);
        if len == 0 {
            return Err(Error::InvalidMessage("Zero-length message".to_string()));
        }
        if len > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidMessage(format!(
                "Message too large: {len} bytes"
            )));
        }

        // Read message body.
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;

        let msg = AgentMessage::decode(&buf)?;
        Ok(Some(msg))
    }

    /// Write a single message to an async writer, flushing afterward.
    pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, msg: &AgentMessage) -> Result<()> {
        let encoded = msg.encode();
        writer.write_all(&encoded).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageType;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_zero_length_message() {
        let mut data = Cursor::new(vec![0u8, 0, 0, 0]);
        let result = AgentCodec::read(&mut data).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Zero-length"));
    }

    #[tokio::test]
    async fn test_read_message_too_large() {
        let mut data = Cursor::new(vec![0x01, 0x00, 0x00, 0x01]);
        let result = AgentCodec::read(&mut data).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_read_eof() {
        let mut data = Cursor::new(vec![]);
        let result = AgentCodec::read(&mut data).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_read_truncated_length() {
        let mut data = Cursor::new(vec![0u8, 0]);
        let result = AgentCodec::read(&mut data).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_read_truncated_body() {
        let mut data = Cursor::new(vec![0u8, 0, 0, 10, 1, 2, 3, 4, 5]);
        let result = AgentCodec::read(&mut data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_valid_request_identities() {
        let mut data = Cursor::new(vec![0u8, 0, 0, 1, 11]);
        let result = AgentCodec::read(&mut data).await.unwrap();
        assert!(result.is_some());
        let msg = result.unwrap();
        assert_eq!(msg.msg_type, MessageType::RequestIdentities);
    }

    #[tokio::test]
    async fn test_write_read_roundtrip() {
        let original = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());

        let mut buf = Vec::new();
        AgentCodec::write(&mut buf, &original).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = AgentCodec::read(&mut cursor).await.unwrap().unwrap();
        assert_eq!(original.msg_type, decoded.msg_type);
        assert_eq!(original.payload, decoded.payload);
    }

    #[tokio::test]
    async fn test_write_read_roundtrip_with_payload() {
        let original = AgentMessage::sign_response(b"\xde\xad\xbe\xef");

        let mut buf = Vec::new();
        AgentCodec::write(&mut buf, &original).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = AgentCodec::read(&mut cursor).await.unwrap().unwrap();
        assert_eq!(decoded.msg_type, MessageType::SignResponse);
        assert_eq!(original.payload, decoded.payload);
    }
}
