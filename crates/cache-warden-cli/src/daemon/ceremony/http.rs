//! A very small HTTP/1.1 server, for the ceremony page and its four endpoints.
//!
//! # Why not a framework
//!
//! What is served here is one static page and four JSON endpoints, on a
//! loopback listener, with TLS terminated outside the process (DR-0032: caddy
//! or `tailscale serve` in front, never TLS in the daemon). A web framework
//! would bring a dependency tree larger than the rest of cache-warden to do
//! that, and its generality — routing DSLs, extractors, middleware — is
//! surface this has no use for.
//!
//! The trade is deliberate and bounded: this parses a request line, a header
//! block, and a length-delimited body, and nothing else. There is no
//! keep-alive, no chunked encoding, no compression, no ranges. A request it
//! does not understand gets a status code, not a best effort.
//!
//! # What it refuses before reading a body
//!
//! Every limit here exists because the listener is reachable by anything on
//! the loopback interface: a request line or header block that grows without
//! bound, or a body that claims a length nobody would send, is refused before
//! it can be allocated.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// Longest request line plus header block accepted.
const MAX_HEAD: usize = 8 * 1024;
/// Largest body accepted. A WebAuthn registration response with a long
/// credential id and an attestation object is a few kilobytes; this is well
/// clear of that and nowhere near enough to be worth sending in a loop.
const MAX_BODY: usize = 64 * 1024;
/// How long one request may take to arrive. A connection that opens and then
/// says nothing holds a task; this bounds that without needing a reaper.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// One parsed request.
pub struct Request {
    /// The method, uppercase as sent.
    pub method: String,
    /// The path, without any query string.
    pub path: String,
    /// The body, empty when there was none.
    pub body: Vec<u8>,
    /// The `Origin` header, when the browser sent one.
    pub origin: Option<String>,
}

/// One response to write back.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// `Content-Type` value.
    pub content_type: &'static str,
    /// Body bytes.
    pub body: Vec<u8>,
    /// Extra headers, as complete `Name: value` lines.
    pub extra_headers: Vec<String>,
}

impl Response {
    /// A JSON response.
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Response {
            status,
            content_type: "application/json",
            body: body.to_string().into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    /// A plain-text status, for the cases a browser will never render.
    pub fn text(status: u16, message: &str) -> Self {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: message.as_bytes().to_vec(),
            extra_headers: Vec::new(),
        }
    }

    fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Error",
        }
    }

    /// Serialize, adding the headers every ceremony response carries.
    ///
    /// `no-store` on all of them: the page embeds nothing secret, but its
    /// endpoints return challenges and take PRF output, and a cached copy of
    /// any of it in a shared browser profile is a copy nobody asked for.
    fn encode(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nPragma: no-cache\r\n\
             X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
             Connection: close\r\n",
            self.status,
            self.reason(),
            self.content_type,
            self.body.len()
        );
        for header in &self.extra_headers {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// Read one request, hand it to `handle`, write the response, close.
///
/// Errors are answered with a status where one can be, and swallowed
/// otherwise: a malformed or hostile connection must not take the listener
/// down with it.
pub async fn serve_one<F>(mut stream: TcpStream, handle: F)
where
    F: FnOnce(Request) -> Response,
{
    let response = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
        Err(_) => Response::text(408, "the request did not arrive in time"),
        Ok(Err(status)) => status,
        Ok(Ok(request)) => handle(request),
    };
    let _ = stream.write_all(&response.encode()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// Read and parse one request, or produce the response that refuses it.
async fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    // Head first: read until the blank line that ends the header block.
    let head_end = loop {
        if let Some(at) = find_head_end(&buf) {
            break at;
        }
        if buf.len() > MAX_HEAD {
            return Err(Response::text(413, "the request head is too large"));
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return Err(Response::text(400, "the connection closed mid-request")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(Response::text(400, "the request could not be read")),
        }
    };

    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| Response::text(400, "the request head is not text"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Response::text(400, "no request line"))?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| Response::text(400, "no method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| Response::text(400, "no target"))?;
    // The query string is not used by any endpoint; dropping it here means no
    // handler has to remember that a path might carry one.
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(Response::text(413, "the request body is too large"));
    }

    let body_start = head_end + 4;
    let mut body = buf[body_start.min(buf.len())..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk).await {
            Ok(0) => return Err(Response::text(400, "the body was shorter than declared")),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(Response::text(400, "the body could not be read")),
        }
    }
    body.truncate(content_length);

    Ok(Request {
        method,
        path,
        body,
        origin: headers.get("origin").cloned(),
    })
}

/// Offset of the `\r\n\r\n` that ends the header block.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Drive one request through a real socket and return the raw response.
    async fn round_trip(raw: &[u8], handle: fn(Request) -> Response) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_one(stream, handle).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(raw).await.unwrap();
        client.flush().await.unwrap();
        // Close the write half: a real client's request ends, and leaving it
        // open would make every test here wait out the read timeout.
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        server.await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn echo(req: Request) -> Response {
        Response::json(
            200,
            serde_json::json!({
                "method": req.method,
                "path": req.path,
                "body": String::from_utf8_lossy(&req.body),
                "origin": req.origin,
            }),
        )
    }

    #[tokio::test]
    async fn a_request_is_parsed_into_its_parts() {
        let out = round_trip(
            b"POST /unlock/begin?x=1 HTTP/1.1\r\nHost: localhost\r\n\
              Origin: https://vault.example.test\r\nContent-Length: 5\r\n\r\nhello",
            echo,
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(out.contains(r#""method":"POST""#), "{out}");
        assert!(
            out.contains(r#""path":"/unlock/begin""#),
            "the query string is dropped: {out}"
        );
        assert!(out.contains(r#""body":"hello""#), "{out}");
        assert!(
            out.contains(r#""origin":"https://vault.example.test""#),
            "{out}"
        );
    }

    /// Every response is uncacheable. The endpoints hand out challenges and
    /// take key material; a copy left in a shared browser profile is a copy
    /// nobody asked for.
    #[tokio::test]
    async fn every_response_forbids_caching() {
        let out = round_trip(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", echo).await;
        assert!(out.contains("Cache-Control: no-store"), "{out}");
        assert!(out.contains("X-Content-Type-Options: nosniff"), "{out}");
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_rather_than_allocated() {
        let raw = format!(
            "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let out = round_trip(raw.as_bytes(), echo).await;
        assert!(out.starts_with("HTTP/1.1 413"), "{out}");
    }

    /// A header block that never ends must be cut off by the size limit
    /// rather than grown until the daemon runs out of memory. Just over the
    /// limit, so the whole thing still fits in the socket buffer and the test
    /// does not deadlock against a server that has stopped reading.
    #[tokio::test]
    async fn an_endless_header_block_is_refused() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        while raw.len() < MAX_HEAD + 512 {
            raw.extend_from_slice(b"X-Pad: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n");
        }
        // Deliberately never terminated.
        let out = round_trip(&raw, echo).await;
        assert!(out.starts_with("HTTP/1.1 413"), "{out}");
    }

    #[tokio::test]
    async fn a_truncated_request_is_refused_rather_than_half_handled() {
        let out = round_trip(b"GET / HTTP/1.1\r\n", echo).await;
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }

    /// A body shorter than its declared length is not silently accepted: a
    /// handler must never see a truncated payload as if it were whole.
    #[tokio::test]
    async fn a_body_shorter_than_declared_is_refused() {
        let out = round_trip(
            b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort",
            echo,
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }
}
