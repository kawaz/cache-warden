//! Synchronous control-socket client used by the management subcommands.
//!
//! The management commands (`ping`, `status`, `kv ...`) are one-shot
//! request/response exchanges, so they use a plain blocking
//! [`std::os::unix::net::UnixStream`] — no async runtime is needed on the
//! client side (the daemon is the only async process). Each call connects,
//! writes one JSON request line, reads one JSON response line, and closes.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::mode::Mode;
use crate::protocol::wire::{OkPayload, Request, Response};
use crate::protocol::{decode_b64, decode_response, encode_request};
use crate::refs::{ResolveResult, ResolvedValue, Resolver};

/// Send one request to the daemon at `socket` and read one response.
///
/// Returns an error string (suitable for the CLI's top-level error path) if the
/// socket cannot be reached or the exchange fails.
pub fn round_trip(socket: &Path, req: &Request) -> Result<Response, String> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot connect to daemon at {} ({e}). Is `cache-warden run` started?",
            socket.display()
        )
    })?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("socket clone failed: {e}"))?;
    let line = encode_request(req).map_err(|e| format!("failed to encode request: {e}"))?;
    writer
        .write_all(line.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|e| format!("failed to send request: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    let n = reader
        .read_line(&mut response_line)
        .map_err(|e| format!("failed to read response: {e}"))?;
    if n == 0 {
        return Err("daemon closed the connection without responding".to_string());
    }
    decode_response(response_line.trim_end())
        .map_err(|e| format!("malformed response from daemon: {e}"))
}

/// A [`Resolver`] that resolves each key by a `kv.get` over the control socket
/// (DR-0013 / DR-0015). In reveal mode the value bytes are returned; in dry-run
/// mode `dry_run: true` is sent and the daemon's value-free `verified` reply
/// maps to [`ResolvedValue::Verified`] (the value never reaches this process).
pub struct SocketResolver<'a> {
    socket: &'a Path,
    mode: Mode,
}

impl<'a> SocketResolver<'a> {
    /// Build a resolver bound to `socket`, resolving in `mode`.
    pub fn new(socket: &'a Path, mode: Mode) -> Self {
        Self { socket, mode }
    }
}

impl Resolver for SocketResolver<'_> {
    fn resolve(&mut self, key: &str) -> ResolveResult {
        let req = Request::KvGet {
            key: key.to_string(),
            dry_run: self.mode.is_dry_run(),
        };
        match round_trip(self.socket, &req)? {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    let bytes = decode_b64(&value_b64)
                        .map_err(|e| format!("daemon returned invalid base64: {e}"))?;
                    Ok(ResolvedValue::Value(bytes))
                }
                OkPayload::GetVerified { .. } => Ok(ResolvedValue::Verified),
                other => Err(format!("unexpected response payload for kv.get: {other:?}")),
            },
            Response::Err(e) => Err(e.error.message),
        }
    }
}
