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

use crate::protocol::wire::{Request, Response};
use crate::protocol::{decode_response, encode_request};

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
