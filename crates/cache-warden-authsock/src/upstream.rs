//! Upstream SSH agent connection (port plan Iteration 2).
//!
//! An `[authsock.sockets.NAME].upstreams` entry names another agent socket (the
//! 1Password agent, a system `ssh-agent`, ...) whose keys this socket should
//! also offer. We never get the upstream's private material, so signing for an
//! upstream key is **forwarded**: the SIGN_REQUEST is relayed verbatim and the
//! upstream's SIGN_RESPONSE is returned.
//!
//! # Why a fresh connection per request
//!
//! Ported from authsock-warden, which opens a new connection for every
//! REQUEST_IDENTITIES / SIGN_REQUEST rather than caching one. A cached
//! connection to a volatile agent socket (the 1Password agent restarts on lock /
//! relaunch; the path can go stale) would have to detect and recover from a
//! half-open peer on every use. A short-lived connect-use-drop avoids that
//! entirely at the cost of one `connect()` per request — negligible against the
//! signing / TouchID latency that dominates. See the DESIGN note.
//!
//! # Defense
//!
//! The upstream is **not trusted**: its responses go back through the same
//! [`AgentCodec`] size / framing checks as any client input (max message size,
//! truncation, identity-count cap). A hostile or buggy upstream cannot smuggle
//! an oversized or malformed message past us.

use crate::codec::AgentCodec;
use crate::error::{Error, Result};
use crate::message::AgentMessage;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;

/// Connection timeout for reaching the upstream agent socket.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Request timeout (send + receive) for one upstream exchange.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A configured upstream agent socket. Cheap to clone; holds only the path.
#[derive(Debug, Clone)]
pub struct Upstream {
    socket_path: PathBuf,
}

impl Upstream {
    /// Create an upstream pointing at `socket_path`.
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// The configured socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Connect to the upstream agent, with a connect timeout.
    ///
    /// A connect failure (socket missing, peer gone, timeout) is an
    /// [`Error::Upstream`]: the caller skips this upstream and keeps serving the
    /// rest (graceful degradation, port plan Iteration 2).
    pub async fn connect(&self) -> Result<UpstreamConnection> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| {
                Error::Upstream(format!(
                    "connection to upstream agent at {} timed out after {CONNECT_TIMEOUT:?}",
                    self.socket_path.display()
                ))
            })?
            .map_err(|e| {
                Error::Upstream(format!(
                    "failed to connect to upstream agent at {}: {e}",
                    self.socket_path.display()
                ))
            })?;
        Ok(UpstreamConnection { stream })
    }
}

/// An open connection to an upstream agent for a single request/response.
#[derive(Debug)]
pub struct UpstreamConnection {
    stream: UnixStream,
}

impl UpstreamConnection {
    /// Send `msg` to the upstream and read its single response, with a request
    /// timeout. The response is decoded through [`AgentCodec`] so its size /
    /// framing are validated like any untrusted input.
    pub async fn send_receive(&mut self, msg: &AgentMessage) -> Result<AgentMessage> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.send_receive_inner(msg))
            .await
            .map_err(|_| {
                Error::Upstream(format!(
                    "request to upstream agent timed out after {REQUEST_TIMEOUT:?}"
                ))
            })?
    }

    async fn send_receive_inner(&mut self, msg: &AgentMessage) -> Result<AgentMessage> {
        let (mut reader, mut writer) = self.stream.split();
        // Every failure talking to an upstream is an Upstream error so callers
        // can degrade per-upstream uniformly. The underlying I/O error kind also
        // differs by OS for a peer that closed early (Linux reports EPIPE at
        // write time, macOS surfaces EOF at read time), so the wrapping keeps
        // the contract platform-independent.
        AgentCodec::write(&mut writer, msg)
            .await
            .map_err(|e| Error::Upstream(format!("write to upstream agent failed: {e}")))?;
        AgentCodec::read(&mut reader)
            .await
            .map_err(|e| Error::Upstream(format!("read from upstream agent failed: {e}")))?
            .ok_or_else(|| Error::Upstream("upstream agent closed connection".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageType;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn new_keeps_socket_path() {
        let up = Upstream::new("/tmp/some-agent.sock");
        assert_eq!(up.socket_path(), Path::new("/tmp/some-agent.sock"));
    }

    #[tokio::test]
    async fn connect_to_missing_socket_is_upstream_error() {
        let up = Upstream::new("/tmp/cache-warden-nonexistent-upstream-12345.sock");
        let err = up.connect().await.unwrap_err();
        assert!(matches!(err, Error::Upstream(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn connect_to_a_plain_file_is_upstream_error() {
        // A regular file is not a socket; connect must fail as Upstream, not panic.
        let dir = std::env::temp_dir();
        let file = dir.join("cache-warden-not-a-socket.tmp");
        std::fs::write(&file, b"x").unwrap();
        let up = Upstream::new(&file);
        let err = up.connect().await.unwrap_err();
        std::fs::remove_file(&file).ok();
        assert!(matches!(err, Error::Upstream(_)), "got {err:?}");
    }

    /// Spawn a one-shot fake agent on a temp socket that, for one connection,
    /// reads one message and writes `response`. Returns its socket path; the
    /// listener task ends after serving one connection.
    async fn fake_agent_once(response: AgentMessage) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let sock = short_sock_path("fa");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Read one framed message and discard it.
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).await.is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    let _ = stream.read_exact(&mut body).await;
                }
                let encoded = response.encode();
                let _ = stream.write_all(&encoded).await;
                let _ = stream.flush().await;
            }
        });
        (sock, handle)
    }

    /// A short, unique socket path under `/tmp` (kept well under the ~108-byte
    /// `sockaddr_un` limit; a path under macOS `$TMPDIR` would overflow it).
    fn short_sock_path(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(format!("/tmp/cw-{tag}-{}-{n}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn send_receive_returns_the_upstream_response() {
        let answer = AgentMessage::build_identities_answer(&[]);
        let (sock, handle) = fake_agent_once(answer).await;
        let up = Upstream::new(&sock);
        let mut conn = up.connect().await.unwrap();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = conn.send_receive(&req).await.unwrap();
        assert_eq!(resp.msg_type, MessageType::IdentitiesAnswer);
        handle.await.unwrap();
        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn send_receive_on_closed_connection_is_upstream_error() {
        // A fake agent that accepts then immediately closes without replying.
        let sock = short_sock_path("cl");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = tokio::spawn(async move {
            let _ = listener.accept().await; // accept then drop -> close
        });
        let up = Upstream::new(&sock);
        let mut conn = up.connect().await.unwrap();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let err = conn.send_receive(&req).await.unwrap_err();
        assert!(matches!(err, Error::Upstream(_)), "got {err:?}");
        handle.await.unwrap();
        std::fs::remove_file(&sock).ok();
    }
}
