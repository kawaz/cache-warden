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

/// A typed source spec carried on `kv.define` (DR-0018 §1).
///
/// The `source` field is the discriminant (`"command"` / `"op"`), and the
/// selected kind's table travels alongside it (`command` / `op`). This mirrors
/// the TOML config / defs grammar (`source = "command"` + `command.{...}`) on the
/// wire as `{"source":"command","command":{...}}`. The CLI sends it verbatim; the
/// daemon lowers it to an execution argv (DR-0018 §1 "lowering") while preserving
/// the typed origin in the definition's opaque source slot (DR-0018 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SourceSpecWire {
    /// `source = "command"`: run an argv (optionally in a cwd, with an env
    /// overlay). The execution primitive.
    Command {
        /// The `command` kind table.
        command: CommandSpecWire,
    },
    /// `source = "op"`: a 1Password `op://` reference (lowered to an `op read`
    /// argv at the daemon). The verbatim origin is preserved for `status`.
    Op {
        /// The `op` kind table.
        op: OpSpecWire,
    },
}

/// The `command` kind table (DR-0018 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpecWire {
    /// The command line as already-split argv (program first). Required.
    pub argv: Vec<String>,
    /// Working directory to spawn the command in. Omitted on the wire when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Environment overlay merged onto the daemon's environment (same-named keys
    /// override). Omitted on the wire when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// The `op` kind table (DR-0018 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpSpecWire {
    /// The `op://vault/item/field` reference. Required.
    pub uri: String,
    /// 1Password account (`op --account ...`). Omitted on the wire when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// Render a definition's opaque [`cache_warden::SourceMeta`] into a value-free,
/// human-readable origin string for the **`status` IPC response** (DR-0018 §3),
/// or `None` for an empty slot.
///
/// # Secret hygiene (why `command` does not show its argv here)
///
/// `status` is an IPC reply that crosses a process boundary. A `command` source's
/// argv can legitimately carry a literal secret (e.g. `printf %s <seed>`), so
/// surfacing it over the wire would leak it. The `op` source's `uri` is a
/// *reference* (never the fetched value), so it is safe to show. Therefore:
///
/// - `op` → the `op.uri` (with ` (account ACCOUNT)` appended when set).
/// - `command` → just `"command"` (the discriminant; never the argv).
/// - any other / future kind → `kind: <kind>` as a safe fallback.
///
/// `config show` deliberately reveals the argv (the config file is on-disk
/// plaintext the operator already owns); it uses [`source_meta_display_verbose`].
pub fn source_meta_display(meta: &cache_warden::SourceMeta) -> Option<String> {
    let kind = meta.kind()?;
    match kind {
        "op" => {
            let uri = meta.field("uri").unwrap_or("");
            Some(match meta.field("account") {
                Some(acct) => format!("{uri} (account {acct})"),
                None => uri.to_string(),
            })
        }
        "command" => Some("command".to_string()),
        other => Some(format!("kind: {other}")),
    }
}

/// Like [`source_meta_display`] but reveals a `command` source's argv. Used only
/// by `config show`, where the argv is read straight from the on-disk config the
/// operator owns (no new exposure). Never used on an IPC boundary.
pub fn source_meta_display_verbose(meta: &cache_warden::SourceMeta) -> Option<String> {
    match meta.kind()? {
        "command" => {
            // argv is newline-joined in the opaque slot; show it space-joined.
            let argv = meta.field("argv").unwrap_or("");
            Some(format!("command: {}", argv.replace('\n', " ")))
        }
        _ => source_meta_display(meta),
    }
}

impl SourceSpecWire {
    /// Validate the selected kind's required fields (DR-0018 §1).
    ///
    /// `command` requires a non-empty `argv`; `op` requires a non-empty `uri`.
    /// Returns a secret-free message naming the kind on violation.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            SourceSpecWire::Command { command } => {
                if command.argv.is_empty() {
                    return Err("source = \"command\" requires a non-empty `command.argv`".into());
                }
            }
            SourceSpecWire::Op { op } => {
                if op.uri.trim().is_empty() {
                    return Err("source = \"op\" requires a non-empty `op.uri`".into());
                }
                if !op.uri.starts_with("op://") {
                    return Err(format!(
                        "source = \"op\": `op.uri` must be an op:// reference (got {:?})",
                        op.uri
                    ));
                }
            }
        }
        Ok(())
    }

    /// Lower this typed source to the core execution primitive
    /// ([`cache_warden::ValueSource::Command`]) — the argv (+ cwd / env) the
    /// daemon actually runs (DR-0018 §1 "lowering").
    ///
    /// - `command` → the argv verbatim, with its cwd / env carried onto the
    ///   primitive.
    /// - `op` → `["op", "read", uri]`, plus `--account ACCOUNT` after `op` when an
    ///   account is set (matching the authsock `op_account` convention).
    pub fn lower(&self) -> cache_warden::ValueSource {
        match self {
            SourceSpecWire::Command { command } => cache_warden::ValueSource::command_with(
                command.argv.clone(),
                command.cwd.as_ref().map(std::path::PathBuf::from),
                command.env.clone(),
            ),
            SourceSpecWire::Op { op } => {
                let mut argv = vec!["op".to_string()];
                if let Some(acct) = &op.account {
                    argv.push("--account".to_string());
                    argv.push(acct.clone());
                }
                argv.push("read".to_string());
                argv.push(op.uri.clone());
                cache_warden::ValueSource::command(argv)
            }
        }
    }

    /// Reconstruct a typed source from the core's opaque
    /// [`cache_warden::SourceMeta`] slot (the inverse of [`Self::to_source_meta`]).
    ///
    /// Returns `None` when the slot is empty or its kind is unknown (e.g. an
    /// internal authsock op key that was registered without a typed origin), so a
    /// snapshot of such a definition is skipped rather than mis-rendered.
    pub fn from_source_meta(meta: &cache_warden::SourceMeta) -> Option<Self> {
        match meta.kind()? {
            "command" => {
                let argv: Vec<String> = match meta.field("argv") {
                    Some(s) if !s.is_empty() => s.split('\n').map(|s| s.to_string()).collect(),
                    _ => return None, // a command source always has a non-empty argv
                };
                let cwd = meta.field("cwd").map(|s| s.to_string());
                let env: BTreeMap<String, String> = meta
                    .field("env")
                    .map(|s| {
                        s.split('\n')
                            .filter_map(|line| {
                                line.split_once('=')
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(SourceSpecWire::Command {
                    command: CommandSpecWire { argv, cwd, env },
                })
            }
            "op" => {
                let uri = meta.field("uri")?.to_string();
                let account = meta.field("account").map(|s| s.to_string());
                Some(SourceSpecWire::Op {
                    op: OpSpecWire { uri, account },
                })
            }
            _ => None,
        }
    }

    /// Render this typed source into the core's opaque [`cache_warden::SourceMeta`]
    /// slot (DR-0018 §2): the discriminant plus the selected kind's verbatim
    /// fields. Only the chosen kind's fields are recorded.
    ///
    /// Multi-valued fields are rendered into deterministic, round-trippable string
    /// forms (newline-joined argv; `name=value` newline-joined env) so the opaque
    /// slot stays a flat string→string bag while still distinguishing every
    /// origin for the idempotency comparison.
    pub fn to_source_meta(&self) -> cache_warden::SourceMeta {
        match self {
            SourceSpecWire::Command { command } => {
                let mut fields = BTreeMap::new();
                fields.insert("argv".to_string(), command.argv.join("\n"));
                if let Some(cwd) = &command.cwd {
                    fields.insert("cwd".to_string(), cwd.clone());
                }
                if !command.env.is_empty() {
                    let rendered = command
                        .env
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    fields.insert("env".to_string(), rendered);
                }
                cache_warden::SourceMeta::with_kind("command", fields)
            }
            SourceSpecWire::Op { op } => {
                let mut fields = BTreeMap::new();
                fields.insert("uri".to_string(), op.uri.clone());
                if let Some(acct) = &op.account {
                    fields.insert("account".to_string(), acct.clone());
                }
                cache_warden::SourceMeta::with_kind("op", fields)
            }
        }
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
    /// Register a *typed source* definition for a key (DR-0014 §1 / DR-0018 §1).
    ///
    /// Idempotent under exact match (same typed source + TTL + value meta is a
    /// no-op); a mismatch is rejected with [`ErrorKind::BadRequest`]. No upstream
    /// runs at define time — the value is produced lazily on the first `kv.get`.
    ///
    /// The `source` carries the typed origin verbatim (`{"source":"command",
    /// "command":{...}}` or `{"source":"op","op":{...}}`); the daemon lowers it to
    /// an execution argv while preserving the typed form in the definition's
    /// opaque source slot (DR-0018 §2).
    #[serde(rename = "kv.define")]
    KvDefine {
        /// The key to define.
        key: String,
        /// The typed source spec (the discriminant + the selected kind's table).
        #[serde(flatten)]
        source: SourceSpecWire,
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
    /// A value-free, human-readable rendering of the definition's **typed source
    /// origin** (DR-0018 §2/§3): e.g. `op://vault/item/field` for an `op` source,
    /// or `command: op read …` for a `command` source. `None` for a value-only
    /// key (no definition) or a definition with no recorded typed origin. Never
    /// exposes the secret — for `op` it is the reference, never the fetched value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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

    /// A `command`-kind source spec from a plain argv (test helper).
    fn cmd_spec(argv: &[&str]) -> SourceSpecWire {
        SourceSpecWire::Command {
            command: CommandSpecWire {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: None,
                env: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn kv_define_command_roundtrips_and_uses_typed_source() {
        let req = Request::KvDefine {
            key: "TOK".into(),
            source: cmd_spec(&["op", "read", "op://v/i/f"]),
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            meta: Default::default(),
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""cmd":"kv.define""#), "{line}");
        assert!(line.contains(r#""source":"command""#), "{line}");
        assert!(
            line.contains(r#""argv":["op","read","op://v/i/f"]"#),
            "{line}"
        );
        roundtrip_request(&req);
    }

    #[test]
    fn kv_define_op_source_roundtrips() {
        let req = Request::KvDefine {
            key: "GH".into(),
            source: SourceSpecWire::Op {
                op: OpSpecWire {
                    uri: "op://vault/github/private_key".into(),
                    account: Some("my.1password.com".into()),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            meta: Default::default(),
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""source":"op""#), "{line}");
        assert!(
            line.contains(r#""uri":"op://vault/github/private_key""#),
            "{line}"
        );
        assert!(line.contains(r#""account":"my.1password.com""#), "{line}");
        roundtrip_request(&req);
    }

    #[test]
    fn kv_define_command_carries_cwd_and_env() {
        let mut env = BTreeMap::new();
        env.insert("K1".to_string(), "V1".to_string());
        let req = Request::KvDefine {
            key: "K".into(),
            source: SourceSpecWire::Command {
                command: CommandSpecWire {
                    argv: vec!["prog".into()],
                    cwd: Some("/tmp".into()),
                    env,
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            meta: Default::default(),
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""cwd":"/tmp""#), "{line}");
        assert!(line.contains(r#""K1":"V1""#), "{line}");
        roundtrip_request(&req);
    }

    #[test]
    fn kv_define_ttls_default_to_none_when_absent() {
        let line =
            r#"{"cmd":"kv.define","key":"K","source":"command","command":{"argv":["echo","x"]}}"#;
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
                    source: None,
                },
                EntryInfo {
                    name: "P".into(),
                    state: "active".into(),
                    regenerable: false,
                    defined: false,
                    has_value: true,
                    pin_remaining_secs: Some(3600),
                    value_type: Some("otp".into()),
                    source: None,
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
            source: None,
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
