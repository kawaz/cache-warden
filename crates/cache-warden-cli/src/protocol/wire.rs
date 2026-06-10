//! Control-socket wire protocol v1 (JSON Lines).
//!
//! Each request is one JSON object on a single line; each response is one JSON
//! object on a single line (see `docs/decisions/DR-0009-control-socket-protocol-v1.md`).
//!
//! # Why JSON Lines
//!
//! The control socket is a low-volume management IPC, not a streaming data
//! plane. JSON Lines is trivially debuggable (`nc` / `socat` can drive it by
//! hand), serde already lives in the CLI crate (DR-0002 keeps it out of the
//! library), and there is no framing ambiguity for one-shot request/response.
//!
//! # Secret encoding
//!
//! Secret bytes are binary, so they are carried base64-encoded in fields named
//! with a `_b64` suffix ([`SetSource::value_b64`], [`GetOk::value_b64`]). Plain
//! JSON strings cannot represent arbitrary bytes; base64 keeps the wire binary
//! safe. Error messages never carry secret material.

use serde::{Deserialize, Serialize};

/// A request from the management client to the daemon.
///
/// The `cmd` field is the discriminant. Unknown commands are rejected by the
/// daemon with an [`ErrorKind::BadRequest`] response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Request {
    /// Liveness probe. The daemon replies with [`Response::Pong`].
    #[serde(rename = "ping")]
    Ping,
    /// Ask for daemon information and the (value-free) entry list.
    #[serde(rename = "status")]
    Status,
    /// Insert or replace a key.
    #[serde(rename = "kv.set")]
    KvSet {
        /// The key to set.
        key: String,
        /// Where the value comes from (literal bytes or an upstream command).
        source: SetSource,
        /// Soft TTL in seconds, or `None` for "never soft-expires".
        #[serde(default)]
        soft_ttl_secs: Option<u64>,
        /// Hard TTL in seconds, or `None` for "never hard-expires".
        #[serde(default)]
        hard_ttl_secs: Option<u64>,
    },
    /// Fetch a key's value (TTL-gated, with extend/regenerate as needed).
    #[serde(rename = "kv.get")]
    KvGet {
        /// The key to fetch.
        key: String,
    },
    /// Delete a key.
    #[serde(rename = "kv.del")]
    KvDel {
        /// The key to delete.
        key: String,
    },
    /// List all key names (no values, no state).
    #[serde(rename = "kv.list")]
    KvList,
}

/// The value source for a [`Request::KvSet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SetSource {
    /// A literal value supplied at set time, base64-encoded.
    #[serde(rename = "static")]
    Static {
        /// The secret value, base64-encoded (binary safe).
        value_b64: String,
    },
    /// An upstream command whose stdout produces the value.
    #[serde(rename = "command")]
    Command {
        /// The command line as already-split argv (program first).
        argv: Vec<String>,
    },
}

/// A response from the daemon to the management client.
///
/// Serialized with an `ok` boolean discriminant so a client can branch before
/// inspecting the rest. Success variants carry their payload inline; the
/// failure variant carries a structured [`WireError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    /// A successful response.
    Ok(OkResponse),
    /// A failed response.
    Err(ErrResponse),
}

/// The success arm of a [`Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkResponse {
    /// Always `true`.
    pub ok: bool,
    /// The command-specific success payload.
    #[serde(flatten)]
    pub payload: OkPayload,
}

/// The failure arm of a [`Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrResponse {
    /// Always `false`.
    pub ok: bool,
    /// The structured error (kind + redacted message).
    pub error: WireError,
}

/// Command-specific success payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OkPayload {
    /// Reply to [`Request::Ping`].
    Pong {
        /// Always `"pong"`; lets `untagged` disambiguate the empty-ish reply.
        pong: bool,
    },
    /// Reply to [`Request::Status`].
    Status {
        /// Daemon process id.
        pid: u32,
        /// Daemon version string.
        version: String,
        /// The control socket path the daemon is bound to.
        socket: String,
        /// The entries, value-free (name / state / remaining TTL).
        entries: Vec<EntryInfo>,
    },
    /// Reply to [`Request::KvGet`].
    Get {
        /// The fetched secret value, base64-encoded.
        value_b64: String,
    },
    /// Reply to [`Request::KvList`].
    List {
        /// The key names, sorted.
        keys: Vec<String>,
    },
    /// Reply to [`Request::KvDel`].
    Deleted {
        /// Whether a key was actually removed.
        deleted: bool,
    },
    /// Reply to [`Request::KvSet`] (acknowledgement, no payload).
    Set {
        /// Always `true`; lets `untagged` disambiguate from `Pong`.
        set: bool,
    },
}

/// Value-free description of a stored entry, for `status`.
///
/// Carries the name, lifecycle state, and remaining hard-TTL seconds — never
/// the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// The key name.
    pub name: String,
    /// The lifecycle state: `"active"` / `"soft_expired"` / `"hard_expired"`.
    pub state: String,
    /// Whether the entry's source can be regenerated after hard expiry.
    pub regenerable: bool,
}

/// A structured error returned in a failed [`Response`].
///
/// The `message` is human-readable and must never contain secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// The machine-readable error category.
    pub kind: ErrorKind,
    /// A human-readable, secret-free description.
    pub message: String,
}

/// Machine-readable error categories on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The request was malformed or used an unknown command/field.
    BadRequest,
    /// The named key does not exist.
    NotFound,
    /// Re-authentication was denied or unavailable.
    AuthFailed,
    /// A hard-expired static entry cannot be regenerated (re-set needed).
    NotRegenerable,
    /// The upstream source command failed during regeneration.
    UpstreamFailed,
    /// An internal daemon error (lock poisoned, etc.).
    Internal,
}

impl Response {
    /// Construct a `pong` success response.
    pub fn pong() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Pong { pong: true },
        })
    }

    /// Construct a `set` acknowledgement response.
    pub fn set_ack() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Set { set: true },
        })
    }

    /// Construct a `get` success response from base64-encoded value bytes.
    pub fn get(value_b64: String) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Get { value_b64 },
        })
    }

    /// Construct a `list` success response.
    pub fn list(keys: Vec<String>) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::List { keys },
        })
    }

    /// Construct a `del` success response.
    pub fn deleted(deleted: bool) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Deleted { deleted },
        })
    }

    /// Construct a `status` success response.
    pub fn status(pid: u32, version: String, socket: String, entries: Vec<EntryInfo>) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Status {
                pid,
                version,
                socket,
                entries,
            },
        })
    }

    /// Construct a failure response.
    pub fn error(kind: ErrorKind, message: impl Into<String>) -> Self {
        Response::Err(ErrResponse {
            ok: false,
            error: WireError {
                kind,
                message: message.into(),
            },
        })
    }

    /// Whether this is a success response (test helper).
    #[cfg(test)]
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_request(req: &Request) {
        let line = serde_json::to_string(req).unwrap();
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(&back, req);
    }

    fn roundtrip_response(resp: &Response) {
        let line = serde_json::to_string(resp).unwrap();
        let back: Response = serde_json::from_str(&line).unwrap();
        assert_eq!(&back, resp);
    }

    #[test]
    fn ping_request_uses_cmd_tag() {
        let line = serde_json::to_string(&Request::Ping).unwrap();
        assert_eq!(line, r#"{"cmd":"ping"}"#);
        roundtrip_request(&Request::Ping);
    }

    #[test]
    fn kv_set_static_roundtrips() {
        let req = Request::KvSet {
            key: "DB".into(),
            source: SetSource::Static {
                value_b64: "cHc=".into(),
            },
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""cmd":"kv.set""#));
        assert!(line.contains(r#""kind":"static""#));
        assert!(line.contains(r#""value_b64":"cHc=""#));
        roundtrip_request(&req);
    }

    #[test]
    fn kv_set_command_roundtrips() {
        let req = Request::KvSet {
            key: "TOK".into(),
            source: SetSource::Command {
                argv: vec!["op".into(), "read".into()],
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        roundtrip_request(&req);
    }

    #[test]
    fn kv_set_ttls_default_to_none_when_absent() {
        let line = r#"{"cmd":"kv.set","key":"K","source":{"kind":"static","value_b64":"AA=="}}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        match req {
            Request::KvSet {
                soft_ttl_secs,
                hard_ttl_secs,
                ..
            } => {
                assert_eq!(soft_ttl_secs, None);
                assert_eq!(hard_ttl_secs, None);
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn get_request_roundtrips() {
        roundtrip_request(&Request::KvGet { key: "K".into() });
        roundtrip_request(&Request::KvDel { key: "K".into() });
        roundtrip_request(&Request::KvList);
        roundtrip_request(&Request::Status);
    }

    #[test]
    fn pong_response_roundtrips_and_is_ok() {
        let resp = Response::pong();
        assert!(resp.is_ok());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""ok":true"#));
        roundtrip_response(&resp);
    }

    #[test]
    fn get_response_roundtrips() {
        roundtrip_response(&Response::get("cHc=".into()));
    }

    #[test]
    fn set_ack_response_roundtrips() {
        roundtrip_response(&Response::set_ack());
    }

    #[test]
    fn list_response_roundtrips() {
        roundtrip_response(&Response::list(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn deleted_response_roundtrips() {
        roundtrip_response(&Response::deleted(true));
        roundtrip_response(&Response::deleted(false));
    }

    #[test]
    fn status_response_roundtrips() {
        let resp = Response::status(
            42,
            "0.1.5".into(),
            "/tmp/x.sock".into(),
            vec![EntryInfo {
                name: "K".into(),
                state: "active".into(),
                regenerable: true,
            }],
        );
        roundtrip_response(&resp);
    }

    #[test]
    fn error_response_carries_kind_and_message() {
        let resp = Response::error(ErrorKind::NotFound, "no such key");
        assert!(!resp.is_ok());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""ok":false"#));
        assert!(line.contains(r#""kind":"not_found""#));
        roundtrip_response(&resp);
    }
}
