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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Opaque value-type metadata carried on `kv.set` / `kv.define` (DR-0016).
///
/// This mirrors the core's `ValueMeta`: an optional opaque type label plus an
/// opaque string→string parameter map. The daemon stores it on the value /
/// definition and the handler layer interprets `type == "otp"` (the core never
/// does). An empty `ValueMetaWire` (no type, no params) is the default for an
/// ordinary opaque value, and serializes to nothing extra on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueMetaWire {
    /// The opaque value-type label (e.g. `"otp"`), or absent for an untyped
    /// value.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    /// Opaque type-specific parameters (e.g. OTP `digits` / `period` /
    /// `algorithm`). Omitted on the wire when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

impl ValueMetaWire {
    /// Whether this carries no type and no parameters (the opaque default).
    pub fn is_empty(&self) -> bool {
        self.type_label.is_none() && self.params.is_empty()
    }
}

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
    /// Insert or replace a static key (literal value only; DR-0014 §1).
    ///
    /// `set` carries opaque bytes only: value *types* (otp) live on definitions
    /// (DR-0016), so there is no `meta` field here. Register a typed key with
    /// `kv.define` instead.
    #[serde(rename = "kv.set")]
    KvSet {
        /// The key to set.
        key: String,
        /// The literal value (base64-encoded). `set` is static-only since
        /// DR-0014; command sources are registered with `kv.define` instead.
        source: SetSource,
        /// Soft TTL in seconds, or `None` for "never soft-expires".
        #[serde(default)]
        soft_ttl_secs: Option<u64>,
        /// Hard TTL in seconds, or `None` for "never hard-expires".
        #[serde(default)]
        hard_ttl_secs: Option<u64>,
    },
    /// Register a command-source *definition* for a key (DR-0014 §1).
    ///
    /// Idempotent under exact match (same argv + TTL is a no-op); a mismatch is
    /// rejected with [`ErrorKind::BadRequest`]. No upstream runs at define time —
    /// the value is produced lazily on the first `kv.get`.
    #[serde(rename = "kv.define")]
    KvDefine {
        /// The key to define.
        key: String,
        /// The command line as already-split argv (program first). For `op://`
        /// sources the CLI has already expanded the URI into `["op", "read", ...]`.
        argv: Vec<String>,
        /// Soft TTL in seconds, or `None` for "never soft-expires".
        #[serde(default)]
        soft_ttl_secs: Option<u64>,
        /// Hard TTL in seconds, or `None` for "never hard-expires".
        #[serde(default)]
        hard_ttl_secs: Option<u64>,
        /// Opaque value-type metadata (DR-0016). Default empty. An otp definition
        /// carries `type = "otp"` + params here; it is stamped onto each value
        /// produced from the definition.
        #[serde(default, skip_serializing_if = "ValueMetaWire::is_empty")]
        meta: ValueMetaWire,
    },
    /// Fetch a key's value (TTL-gated, with extend/regenerate as needed).
    #[serde(rename = "kv.get")]
    KvGet {
        /// The key to fetch.
        key: String,
        /// When `true`, run the full retrieval chain (lazy generate / extend /
        /// regenerate / re-auth) but **do not** return the value: the response
        /// carries only success/failure and the entry state (DR-0015 §2/§6). The
        /// value never reaches the client process. Default `false` (reveal).
        #[serde(default)]
        dry_run: bool,
    },
    /// Delete a key's value, and (with `with_define`) its definition too.
    #[serde(rename = "kv.del")]
    KvDel {
        /// The key to delete.
        key: String,
        /// When `true`, also drop the registered definition so the key will not
        /// regenerate on a later get (DR-0014 §2). Default `false` = value only.
        #[serde(default)]
        with_define: bool,
    },
    /// List all key names (no values, no state).
    #[serde(rename = "kv.list")]
    KvList,
    /// Pin a key Active for `duration_secs`, suppressing soft/hard expiry until
    /// the deadline (re-auth required; DR-0011).
    #[serde(rename = "kv.pin")]
    KvPin {
        /// The key to pin.
        key: String,
        /// How long from now to hold the value Active, in seconds.
        duration_secs: u64,
    },
    /// Drop an active pin on a key, returning it to normal TTL evaluation
    /// (no re-auth; DR-0011).
    #[serde(rename = "kv.unpin")]
    KvUnpin {
        /// The key to unpin.
        key: String,
    },
}

/// The value source for a [`Request::KvSet`].
///
/// Static-only since DR-0014 §1: `kv.set` exists purely to inject a literal
/// value. Command sources are registered with `kv.define` (lazy regeneration),
/// not set eagerly. The enum keeps its `kind` tag so the wire stays
/// forward-compatible and a stray `{"kind":"command"}` is rejected as an unknown
/// variant rather than silently mis-parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SetSource {
    /// A literal value supplied at set time, base64-encoded.
    #[serde(rename = "static")]
    Static {
        /// The secret value, base64-encoded (binary safe).
        value_b64: String,
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
    /// Reply to a dry-run [`Request::KvGet`] (`dry_run: true`): the retrieval
    /// chain ran to completion but the value is **not** carried (DR-0015 §2/§6).
    /// `verified` is always `true`; it lets the `untagged` enum distinguish this
    /// value-free success from the value-carrying `Get`.
    GetVerified {
        /// Always `true`; marks a value-free dry-run success.
        verified: bool,
        /// The entry's lifecycle state after the chain completed (e.g.
        /// `"active"`), for diagnostics. Never the value.
        state: String,
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
    /// Reply to [`Request::KvDefine`] (acknowledgement, no payload).
    Defined {
        /// Always `true`; lets `untagged` disambiguate the reply.
        defined: bool,
    },
    /// Reply to [`Request::KvPin`] (acknowledgement with the resolved deadline).
    Pinned {
        /// Always `true`; lets `untagged` disambiguate the reply.
        pinned: bool,
        /// Seconds from now until the pin lapses (echoes the request duration).
        pin_remaining_secs: u64,
    },
    /// Reply to [`Request::KvUnpin`].
    Unpinned {
        /// Whether the key existed (the pin, if any, was dropped).
        unpinned: bool,
    },
}

/// Value-free description of a stored entry, for `status`.
///
/// Carries the name, lifecycle state, regenerability, whether a definition /
/// value is present, and (if pinned) the pin's remaining seconds — never the
/// value itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// The key name.
    pub name: String,
    /// The lifecycle state: `"active"` / `"soft_expired"` / `"hard_expired"`,
    /// or `"defined"` for a definition-only key whose value has not been
    /// produced yet (DR-0014 §6).
    pub state: String,
    /// Whether the entry's source can be regenerated after hard expiry. A
    /// definition-only key is regenerable (it has a command source).
    pub regenerable: bool,
    /// Whether a command-source definition is registered for this key (DR-0014).
    /// A definition-only key (no value yet) reports `true` here and `false` for
    /// [`Self::has_value`].
    pub defined: bool,
    /// Whether a value entry currently exists for this key (regardless of TTL
    /// state). `false` for a definition-only key. Never exposes the value.
    pub has_value: bool,
    /// Seconds until an active pin lapses, or `None` when the entry is not pinned
    /// (DR-0011). A pin already past its deadline reports `0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_remaining_secs: Option<u64>,
    /// The opaque value-type label (e.g. `"otp"`), or `None` for an untyped
    /// (opaque) entry (DR-0016). Value-free: the type, never the secret. Reported
    /// from the value's metadata, or the definition's for a definition-only key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
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
    /// The entry is hard-expired (destroyed) and the requested operation needs a
    /// live value (e.g. `kv.pin`).
    HardExpired,
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

    /// Construct a `define` acknowledgement response.
    pub fn defined_ack() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Defined { defined: true },
        })
    }

    /// Construct a `get` success response from base64-encoded value bytes.
    pub fn get(value_b64: String) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Get { value_b64 },
        })
    }

    /// Construct a value-free dry-run `get` success response (DR-0015 §2/§6):
    /// the chain completed but no value is carried, only the resulting state.
    pub fn get_verified(state: impl Into<String>) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::GetVerified {
                verified: true,
                state: state.into(),
            },
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

    /// Construct a `pin` success response carrying the remaining pin seconds.
    pub fn pinned(pin_remaining_secs: u64) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Pinned {
                pinned: true,
                pin_remaining_secs,
            },
        })
    }

    /// Construct an `unpin` success response.
    pub fn unpinned(unpinned: bool) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Unpinned { unpinned },
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
    fn kv_define_roundtrips_and_uses_cmd_tag() {
        let req = Request::KvDefine {
            key: "TOK".into(),
            argv: vec!["op".into(), "read".into(), "op://v/i/f".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            meta: Default::default(),
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""cmd":"kv.define""#), "{line}");
        assert!(
            line.contains(r#""argv":["op","read","op://v/i/f"]"#),
            "{line}"
        );
        roundtrip_request(&req);
    }

    #[test]
    fn kv_define_ttls_default_to_none_when_absent() {
        let line = r#"{"cmd":"kv.define","key":"K","argv":["echo","x"]}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        match req {
            Request::KvDefine {
                soft_ttl_secs,
                hard_ttl_secs,
                ..
            } => {
                assert_eq!(soft_ttl_secs, None);
                assert_eq!(hard_ttl_secs, None);
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_set_command_kind_is_rejected_as_unknown_variant() {
        // DR-0014: `kv.set` is static-only; a `{"kind":"command"}` source must no
        // longer parse (it routes to `kv.define` now).
        let line = r#"{"cmd":"kv.set","key":"K","source":{"kind":"command","argv":["op"]}}"#;
        assert!(serde_json::from_str::<Request>(line).is_err());
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
        roundtrip_request(&Request::KvGet {
            key: "K".into(),
            dry_run: false,
        });
        roundtrip_request(&Request::KvDel {
            key: "K".into(),
            with_define: false,
        });
        roundtrip_request(&Request::KvDel {
            key: "K".into(),
            with_define: true,
        });
        roundtrip_request(&Request::KvList);
        roundtrip_request(&Request::Status);
    }

    #[test]
    fn kv_del_with_define_defaults_to_false_when_absent() {
        let line = r#"{"cmd":"kv.del","key":"K"}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        match req {
            Request::KvDel { with_define, .. } => assert!(!with_define),
            _ => panic!("expected KvDel"),
        }
    }

    #[test]
    fn defined_ack_response_roundtrips() {
        let resp = Response::defined_ack();
        assert!(resp.is_ok());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""defined":true"#), "{line}");
        roundtrip_response(&resp);
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
    fn kv_get_dry_run_field_defaults_to_false_and_roundtrips() {
        // Absent dry_run defaults to false (backward-compatible wire).
        let line = r#"{"cmd":"kv.get","key":"K"}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        match req {
            Request::KvGet { dry_run, .. } => assert!(!dry_run),
            _ => panic!("expected KvGet"),
        }
        roundtrip_request(&Request::KvGet {
            key: "K".into(),
            dry_run: true,
        });
        let line = serde_json::to_string(&Request::KvGet {
            key: "K".into(),
            dry_run: true,
        })
        .unwrap();
        assert!(line.contains(r#""dry_run":true"#), "{line}");
    }

    #[test]
    fn get_verified_response_carries_no_value_and_roundtrips() {
        let resp = Response::get_verified("active");
        assert!(resp.is_ok());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""verified":true"#), "{line}");
        assert!(line.contains(r#""state":"active""#), "{line}");
        // Crucially, no value field of any sort.
        assert!(
            !line.contains("value_b64"),
            "dry-run must not carry a value"
        );
        roundtrip_response(&resp);
        // And it decodes back to the value-free arm, not the value-carrying Get.
        let back: Response = serde_json::from_str(&line).unwrap();
        match back {
            Response::Ok(OkResponse {
                payload: OkPayload::GetVerified { verified, state },
                ..
            }) => {
                assert!(verified);
                assert_eq!(state, "active");
            }
            other => panic!("expected GetVerified, got {other:?}"),
        }
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
            vec![
                EntryInfo {
                    name: "K".into(),
                    state: "active".into(),
                    regenerable: true,
                    defined: true,
                    has_value: true,
                    pin_remaining_secs: None,
                    value_type: None,
                },
                EntryInfo {
                    name: "P".into(),
                    state: "active".into(),
                    regenerable: false,
                    defined: false,
                    has_value: true,
                    pin_remaining_secs: Some(3600),
                    value_type: Some("otp".into()),
                },
            ],
        );
        roundtrip_response(&resp);
    }

    #[test]
    fn entry_info_omits_pin_field_when_absent() {
        // An unpinned entry must not serialize the pin field at all (skip_if).
        let info = EntryInfo {
            name: "K".into(),
            state: "active".into(),
            regenerable: false,
            defined: false,
            has_value: true,
            pin_remaining_secs: None,
            value_type: None,
        };
        let line = serde_json::to_string(&info).unwrap();
        assert!(!line.contains("pin_remaining_secs"), "{line}");
        assert!(
            !line.contains("value_type"),
            "untyped entry omits the field"
        );
    }

    #[test]
    fn kv_pin_unpin_requests_roundtrip() {
        roundtrip_request(&Request::KvPin {
            key: "K".into(),
            duration_secs: 28800,
        });
        roundtrip_request(&Request::KvUnpin { key: "K".into() });
        let line = serde_json::to_string(&Request::KvPin {
            key: "K".into(),
            duration_secs: 60,
        })
        .unwrap();
        assert!(line.contains(r#""cmd":"kv.pin""#));
        assert!(line.contains(r#""duration_secs":60"#));
    }

    #[test]
    fn pin_unpin_responses_roundtrip() {
        roundtrip_response(&Response::pinned(28800));
        roundtrip_response(&Response::unpinned(true));
        roundtrip_response(&Response::unpinned(false));
    }

    #[test]
    fn hard_expired_error_kind_serializes_snake_case() {
        let resp = Response::error(ErrorKind::HardExpired, "destroyed");
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""kind":"hard_expired""#), "{line}");
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
