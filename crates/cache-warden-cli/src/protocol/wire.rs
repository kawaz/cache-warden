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
        /// DR-0030 per-entry access guard: the caller's set-time
        /// declaration of what a subsequent `kv.get` must satisfy to
        /// receive the value. Empty = unguarded (the pre-DR-0030 default,
        /// preserved by `#[serde(default)]` so old daemons/clients keep
        /// interoperating). Only the declaration travels on the wire —
        /// the setter's identity snapshot and the ancestor `pinned`
        /// entity are resolved daemon-side from the connection's peer
        /// audit token (never trust caller-supplied process identities).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guard_constraints: Vec<GuardConstraintWire>,
        /// DR-0034 §4 compare-and-swap guard: write only if the entry is still
        /// at this version. `None` (the pre-DR-0034 default, and what an older
        /// client sends) means "write unconditionally", preserving the
        /// historical behaviour exactly.
        ///
        /// `0` is not "no version" — it means **"I expect this key not to
        /// exist"**, since versions start at 1. That makes a create race
        /// safely against another create rather than silently overwriting it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_version: Option<u64>,
        /// The token from a `kv.claim` on this key (DR-0034 §4).
        ///
        /// Required while a claim is active, ignored otherwise. It is what
        /// stops a caller whose claim lapsed — and who was replaced by someone
        /// else mid-refresh — from writing anyway: the version check alone
        /// cannot catch that, because nothing has written in between.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim_token: Option<String>,
        /// Store this entry in the encrypted vault, making cache-warden the
        /// source of truth for it (DR-0034 §5).
        ///
        /// `persist` and "cw-owned" are one property, not two: a persisted
        /// entry is one whose newest value exists only here, which is the
        /// whole reason it has to survive a restart. Combining it with an
        /// `op` source is rejected — that would leave cache-warden holding a
        /// stale copy of a value 1Password still considers authoritative.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persist: Option<bool>,
        /// Declare (or re-declare) the entry's owner principal
        /// (draft-DR-0033 §3a).
        ///
        /// Absent means **unchanged**, never "release": a credential written
        /// on every refresh would otherwise lose its protection the first
        /// time a caller forgot to repeat the declaration, silently and
        /// permanently (DR-0033 §3c). Releasing is [`Request::KvOwnerClear`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_by: Option<SignedByWire>,
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
    /// Take the refresh claim on a key (DR-0034 §4), so that only this caller
    /// contacts the upstream credential provider.
    ///
    /// Named to match `kv.pin` / `kv.unpin`: same "take a hold, release the
    /// hold" shape, same positional duration.
    ///
    /// The reply carries a token that must be presented to `kv.set` while the
    /// claim is active, and again to `kv.unclaim`. A key that is already
    /// claimed replies [`ErrorKind::AlreadyClaimed`] — the signal to wait for
    /// the new value rather than start a second refresh.
    #[serde(rename = "kv.claim")]
    KvClaim {
        /// The key to claim.
        key: String,
        /// Claim only if the entry is still at this version (DR-0034 §4). A
        /// claim taken from a stale read would be racing an update it has not
        /// seen.
        expected_version: u64,
        /// How long the claim holds before it lapses, in seconds. The lapse is
        /// a liveness backstop for a caller that dies mid-refresh; the token,
        /// not the expiry, is what makes the hold safe.
        duration_secs: u64,
    },
    /// Release a claim taken with `kv.claim` without writing a value
    /// (DR-0034 §4).
    ///
    /// For the caller that claimed, called the provider and got nothing worth
    /// storing. Releasing lets the next caller start at once instead of
    /// waiting out the expiry.
    #[serde(rename = "kv.unclaim")]
    KvUnclaim {
        /// The key to release.
        key: String,
        /// The token returned by the `kv.claim` being released. Required so a
        /// caller whose claim lapsed cannot cancel the claim that replaced it.
        claim_token: String,
    },
    /// Create the encrypted vault and mint its recovery code (DR-0034 §9).
    ///
    /// The recovery slot is created here and cannot be skipped: with
    /// cache-warden as the sole source of truth for what it holds, a vault
    /// with no recovery path is one lost passkey away from being gone.
    ///
    /// The reply carries the only copy of the recovery code. Refuses if a
    /// vault already exists rather than replacing it.
    #[serde(rename = "vault.init")]
    VaultInit,
    /// Open the vault so its entries become readable (DR-0034 §6).
    ///
    /// Explicit by design: the daemon never unlocks on its own, so an
    /// unattended start stays unattended and a `kv.get` cannot trigger a
    /// prompt storm.
    #[serde(rename = "vault.unlock")]
    VaultUnlock {
        /// The recovery code, as typed by the user, or absent to unlock with a
        /// passkey instead.
        ///
        /// Absent is the ordinary case (DR-0034 §9 keeps recovery off the
        /// default path): the reply then says where to complete the ceremony
        /// in a browser, since a PRF can only be evaluated there.
        ///
        /// When present it is plain text rather than the `_b64` treatment
        /// secrets get elsewhere: that convention exists for binary safety,
        /// and a recovery code is already ASCII. It is still credential
        /// material — the CLI reads it from stdin, never from argv, and no
        /// layer logs it.
        #[serde(default)]
        recovery_code: Option<String>,
    },
    /// Release an entry's owner principal (draft-DR-0033 §3c).
    ///
    /// Its own request rather than a flag on `kv.set`, which is where the
    /// declaration lives. A set always writes a value, and releasing
    /// ownership is not a write — routing it through one would force a caller
    /// who only wants to give up ownership to supply a value, and supplying
    /// the wrong one would destroy the credential they were trying to hand
    /// over. Permitted only to the current owner, like every other change to
    /// an owned entry.
    #[serde(rename = "kv.owner_clear")]
    KvOwnerClear {
        /// The entry to release.
        key: String,
    },
    /// Close the vault, wiping the data key (DR-0034 §6).
    #[serde(rename = "vault.lock")]
    VaultLock,
    /// Open a window for registering a passkey as a way to unlock the vault
    /// (DR-0034 §1c / §10).
    ///
    /// This does not register anything: it asks for local approval and, if
    /// given, tells the caller where to complete the ceremony in a browser.
    /// Each slot is another way into the vault, so adding one is gated on a
    /// human at this machine saying yes — the daemon puts the approval dialog
    /// on screen and refuses if it cannot.
    #[serde(rename = "vault.add_passkey")]
    VaultAddPasskey {
        /// A user-readable label for the slot ("laptop", "phone").
        label: String,
        /// Proceed without the local approval dialog.
        ///
        /// Exists so a machine with no working approver helper is not locked
        /// out of registering, and named to make that visible in every place
        /// it appears — a bypass nobody can use by accident, and that shows up
        /// in a shell history for what it is.
        #[serde(default)]
        allow_without_local_approval: bool,
    },
    /// Trigger a graceful restart (DR-0029): serialize the store's full state,
    /// verify the current binary's on-disk image, and hand the state to a
    /// freshly exec'd copy of this same process over a private socketpair —
    /// no re-fetch storm, same pid, same control socket path.
    ///
    /// No fields: the exec target is always this daemon's own
    /// `current_exe()`, captured once at startup (DR-0029 §3) — never a path
    /// supplied by the caller, which would reopen the very PATH-substitution
    /// attack the verification step exists to close.
    ///
    /// The daemon replies [`Response::restarting_ack`] only when it accepts
    /// the request (verification passed the point where it is safe to
    /// proceed); from there the connection — and every other listener — is
    /// torn down as part of the handoff, so a client normally observes the
    /// socket close rather than a second reply. A verification failure
    /// replies with [`ErrorKind::RestartAborted`] instead, and the current
    /// process keeps serving untouched.
    #[serde(rename = "daemon.restart_graceful")]
    RestartGraceful,
}

/// A single guard constraint declared by the CLI at `kv set` time (DR-0030).
///
/// Only the **declaration** travels here — the setter's peer identity and
/// (for `SameAncestor`) the pinned process entity are resolved on the
/// daemon side from the connection's peer audit token, never from
/// client-supplied fields. That asymmetry is deliberate: a wire client
/// cannot lie about who they are to the guard record.
///
/// Wire encoding: internally-tagged (`{"kind":"same-user"}`,
/// `{"kind":"same-shell"}`, `{"kind":"same-ancestor","name":"code"}`,
/// `{"kind":"command","name":"git"}`). Unknown `kind` values fail
/// deserialization rather than silently degrading — a guard is a
/// security-sensitive record and "quietly accept as no-op" is unsafe.
///
/// `command=` is the **weak** kind: the daemon matches by executable
/// basename or full-path equality, and anyone with write access to a
/// same-basename location can spoof it. The CLI `--help`, `kv list`
/// display and the approver dialog all label it as such.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GuardConstraintWire {
    /// Getter must match the setter's euid/ruid.
    SameUser,
    /// Setter's closest shell ancestor (organic zsh/bash/fish/sh/nu, per
    /// the daemon's built-in list; DR-0030 §1) is pinned; getter must
    /// have that same process entity in its ancestry chain.
    SameShell,
    /// Setter-side ancestor whose executable basename matches `name` is
    /// pinned; same evaluation rule as `SameShell`.
    SameAncestor {
        /// The ancestor basename to look up in the setter's chain (the
        /// value written after `=` on `--require-same-ancestor=NAME`).
        name: String,
    },
    /// Getter's chain must contain a process whose executable path
    /// matches `name` either by basename or by full-path equality.
    /// Weak — see the type doc.
    Command {
        /// Basename (`"git"`) or full path (`"/usr/bin/git"`) to look
        /// for in the getter's chain.
        name: String,
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

/// A `signed-by` declaration on the wire (draft-DR-0033 §6).
///
/// All three fields together, never a subset. "Any binary from this team" and
/// "any binary called this" are both far looser than a reader of the
/// declaration would assume, so the wire cannot express them.
///
/// Deliberately **not** part of `guard_constraints`: a guard is replaced
/// wholesale by each set, while an owner is inherited by one (DR-0033 §3c).
/// Two different lifetimes in one list would leave every reader to remember
/// which rule applies to which element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedByWire {
    /// Trust anchor: `apple-generic` or `apple`.
    pub anchor: String,
    /// Apple Developer Team Identifier.
    pub team_id: String,
    /// Signing identifier.
    pub identifier: String,
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
        /// macOS Full Disk Access state, probed by the daemon when this
        /// request arrives.
        ///
        /// Only the daemon can answer this: TCC attributes the probe to
        /// whichever process performs it, and the daemon — running from
        /// `CacheWarden.app` — is the process whose permission decides
        /// whether `op` launches quietly. A CLI on `PATH` probing on its own
        /// behalf would answer a different question entirely.
        ///
        /// Omitted on the wire when absent (non-macOS, or an older daemon
        /// that never probed), which a client renders as "not checked"
        /// rather than as a verdict.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        full_disk_access: Option<FdaStatusWire>,
        /// Encrypted vault state (DR-0034 §6), or absent when this daemon has
        /// no vault configured — which an older daemon also produces, and a
        /// client renders the same way: nothing at all.
        ///
        /// Reported here rather than behind a `vault.status` request so there
        /// is one place a client asks "what is this daemon doing", the same
        /// reasoning that put `full_disk_access` here.
        ///
        /// Boxed to keep [`Response`] small. `Status` is the largest payload
        /// by far, and `Response` is carried in the `Err` arm of several
        /// internal helpers — an unboxed field here makes every one of those
        /// results pay for a variant they never construct. `Box` is
        /// serde-transparent, so the wire format is unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<Box<VaultStatusWire>>,
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
    ///
    /// `keys` is the sorted name list (the historical payload). `entries` is a
    /// parallel value-free metadata array (same length, same order) carrying the
    /// same per-entry fields `status` exposes — for `kv list` clients that want
    /// to show backoff / pin / state hints next to the name (DR-0022 §3,
    /// DR-0009 minor extension). An older daemon may omit it; an older client
    /// simply ignores it.
    List {
        /// The key names, sorted.
        keys: Vec<String>,
        /// Per-key value-free metadata, parallel to `keys` and in the same
        /// order. Omitted on the wire when empty so an older daemon that does
        /// not populate it stays byte-compatible.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        entries: Vec<EntryInfo>,
    },
    /// Reply to [`Request::KvDel`].
    Deleted {
        /// Whether a key was actually removed.
        deleted: bool,
    },
    /// Reply to [`Request::KvSet`] (acknowledgement).
    ///
    /// DR-0030: `guard_applied` is a **positive ack** for the guard
    /// declaration — value-free kind labels (`"same-user"`, `"same-shell"`,
    /// `"same-ancestor"`, `"command"`) for every constraint the daemon
    /// actually attached to the entry (including any implicit
    /// `same-user` injected by the daemon's
    /// `[kv-policy] default-require-same-user`). Empty (or absent on an
    /// older daemon) means no guard was applied. The client uses the
    /// absence-when-declared case as a mismatched-version signal (a
    /// pre-DR-0030 daemon silently drops the wire declaration).
    Set {
        /// Always `true`; lets `untagged` disambiguate from `Pong`.
        set: bool,
        /// Kind labels of every applied guard constraint, in the order the
        /// daemon attached them (strong first: same-ancestor / same-shell
        /// / same-user, then the weak command kind). Omitted on the wire
        /// when empty so an older daemon's byte-compatible ack format
        /// stays valid — but that is *also* how a new client detects an
        /// old daemon that silently dropped its guard declaration.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guard_applied: Vec<String>,
        /// The entry's version after this write (DR-0034 §4), which is what a
        /// caller passes as the next `expected_version`.
        ///
        /// `Option` rather than a bare `u64` defaulting to zero, for the same
        /// reason `guard_applied` is a vector whose emptiness is meaningful: an
        /// older daemon omits the field entirely, and a client must be able to
        /// tell "this daemon does not do CAS" from "this entry is at version
        /// 0". Versions start at 1, so a zero default would have been a
        /// sentinel pretending to be a value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<u64>,
        /// The owner principal now on the entry, as an assembled requirement
        /// summary (draft-DR-0033 §6). Value-free.
        ///
        /// A **positive ack**, for the same reason `guard_applied` is one: a
        /// daemon too old to know this field drops it silently, and a caller
        /// that declared an owner and got no acknowledgement has just written
        /// a credential with none of the protection it asked for. Seeing the
        /// field absent is how the CLI knows to delete the value it just
        /// wrote rather than leave it exposed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_applied: Option<String>,
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
    /// Reply to [`Request::KvClaim`] (DR-0034 §4).
    Claimed {
        /// Always `true`; lets `untagged` disambiguate the reply.
        claimed: bool,
        /// The entry's current version — unchanged by the claim, since a claim
        /// alters no value. Echoed so the caller can pass it straight back as
        /// `kv.set`'s `expected_version`.
        version: u64,
        /// The capability to present on `kv.set` / `kv.unclaim` while this
        /// claim holds. Unguessable, but not a secret: it authorizes finishing
        /// or cancelling this refresh, nothing else.
        claim_token: String,
        /// Seconds until the claim lapses.
        claim_expires_in_secs: u64,
    },
    /// Reply to [`Request::KvUnclaim`].
    Unclaimed {
        /// Always `true`; lets `untagged` disambiguate the reply.
        unclaimed: bool,
    },
    /// Reply to [`Request::VaultInit`] (DR-0034 §9).
    VaultInitialized {
        /// Always `true`; lets `untagged` disambiguate the reply.
        initialized: bool,
        /// The new vault's permanent id, as lowercase hex.
        vault_id: String,
        /// The recovery code, in its grouped display form. **The only copy** —
        /// the daemon keeps no record of it, so a client that discards this
        /// without showing the user has destroyed the vault's only recovery
        /// path.
        recovery_code: String,
    },
    /// Reply to [`Request::VaultAddPasskey`]: where to finish the ceremony.
    CeremonyOpened {
        /// Always `true`; lets `untagged` disambiguate the reply.
        ceremony: bool,
        /// The URL to open in a browser.
        url: String,
        /// How long the window stays open, in seconds.
        expires_in_secs: u64,
    },
    /// Reply to [`Request::KvOwnerClear`].
    OwnerCleared {
        /// Always `true`; lets `untagged` disambiguate the reply.
        owner_cleared: bool,
    },
    /// Reply to [`Request::VaultUnlock`].
    VaultUnlocked {
        /// Always `true`; lets `untagged` disambiguate the reply.
        unlocked: bool,
        /// How many persisted entries became readable.
        entries_restored: usize,
    },
    /// Reply to [`Request::VaultLock`].
    VaultLocked {
        /// Always `true`; lets `untagged` disambiguate the reply.
        locked: bool,
    },
    /// Reply to an *accepted* [`Request::RestartGraceful`] (DR-0029). See that
    /// variant's doc for why a client should not expect a second response.
    Restarting {
        /// Always `true`; lets `untagged` disambiguate the reply.
        restarting: bool,
    },
}

/// The daemon's Full Disk Access state, reported on
/// [`OkPayload::Status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FdaStatusWire {
    /// Granted: `op` launches without a permission dialog.
    Granted,
    /// Not granted: macOS will ask the user on every `op` launch.
    NotGranted,
    /// This daemon never spawns `op` (no `op`-backed source in its config),
    /// so the permission would buy it nothing. Clients say nothing at all
    /// rather than reporting a state nobody needs to act on.
    NotApplicable,
    /// The permission is relevant but the state could not be established —
    /// today, a daemon running outside `CacheWarden.app`, which has no bundle
    /// identity for the permission to be granted to.
    Unknown,
}

/// Whether the vault is open, for [`OkPayload::Status`] (DR-0034 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultStateWire {
    /// Present on disk and open: persisted entries are readable.
    Unlocked,
    /// Present on disk but closed. Entries are listed but their values are
    /// not available until `vault.unlock`.
    Locked,
    /// Configured for, but not created yet — `vault.init` has not been run.
    NotInitialized,
}

/// Value-free vault state reported by `status` (DR-0034 §6/§7).
///
/// Everything here is already plaintext in the vault file's header (DR-0034
/// §7 draws that line deliberately): which vault this is, how many recipients
/// can open it, how many times its key has rotated. Entry names and values are
/// not — those live in [`EntryInfo`] and the sealed body respectively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatusWire {
    /// Open, closed, or not created yet.
    pub state: VaultStateWire,
    /// The vault's permanent id as lowercase hex, absent before it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    /// How many recipients can open the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<usize>,
    /// How many times the data key has been rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dek_generation: Option<u64>,
    /// Whether any slot was registered against a development-only WebAuthn RP
    /// (DR-0034 §7). A vault opens for *any* of its slots, so one such slot
    /// sets the strength of the whole vault; a client surfaces this as a
    /// warning rather than as a neutral fact.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dev_rp_slot: bool,
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
    /// Seconds until the fetch-failure backoff window lapses, or `None` when no
    /// backoff is active (DR-0022). When present and positive, re-fetch is
    /// suppressed for this many more seconds. Reported as `0` if the window has
    /// already elapsed but the record has not yet been evicted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff_until_secs: Option<u64>,
    /// DR-0030 per-entry access guard summary: one human label per
    /// attached constraint, strong-first, or `None` when the entry has
    /// no guard record. Each label is value-free — the constraint kind
    /// (and, for `same-ancestor`-family / `command`, the declared
    /// display name) with a `" (weak)"` suffix on `command` — but never
    /// setter identity, uid, or pid. A dialog / status renderer shows
    /// them verbatim; older daemons that do not populate it simply omit
    /// the field (`#[serde(default)]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_summary: Option<Vec<String>>,
    /// The entry's owner principal, as an assembled requirement summary
    /// (draft-DR-0033 §6), or `None` when it has none.
    ///
    /// Value-free, and setter-free: it names which signed identity may act on
    /// the entry, never who declared that. Shown so an operator can see at a
    /// glance which entries are owned and by what — the alternative being to
    /// discover it by being refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_summary: Option<String>,
    /// The entry's DR-0034 §4 CAS version, or `None` for an entry that has no
    /// version (and from a daemon that predates them). Value-free: a counter
    /// of how many times the value changed, never the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// Seconds until an active refresh claim lapses, or `None` when nothing
    /// holds the entry (DR-0034 §4). The token is deliberately **not** here —
    /// `status` and `kv list` are readable by anyone who can reach the socket,
    /// and handing out the token would let a bystander cancel or complete
    /// someone else's refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_expires_in_secs: Option<u64>,
    /// Whether this entry lives in the vault and the vault is closed
    /// (DR-0034 §6): it exists and is declared, but its value cannot be read
    /// until `vault.unlock`.
    ///
    /// A field of its own rather than another [`Self::state`] value, because
    /// the two are independent axes: `state` is the TTL lifecycle, and this is
    /// whether the value is reachable at all. Folding them together would
    /// force one enum to answer two questions and mean adding a variant to
    /// every combination later.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
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
    /// The entry's actual version, on [`ErrorKind::CasMismatch`] (DR-0034 §4).
    ///
    /// A typed field rather than a number embedded in `message`: the losing
    /// side of a compare-and-swap needs this value to retry, and making it
    /// parse the prose would freeze the wording into an API. `0` means the
    /// entry does not exist. Absent for every other error kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    /// Seconds until the holding claim lapses, on
    /// [`ErrorKind::AlreadyClaimed`] (DR-0034 §4) — how long a caller would
    /// wait if it chose to wait rather than give up. Absent for every other
    /// error kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_expires_in_secs: Option<u64>,
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
    /// A `kv.set` / `kv.claim` carrying `expected_version` lost a
    /// compare-and-swap: the entry is at a different version now (DR-0034 §4).
    /// **Nothing was written.** [`WireError::current_version`] carries the
    /// version actually found, to retry from.
    ///
    /// Deliberately distinct from `bad_request`: a CAS loss is a normal
    /// outcome of a race, not a malformed call, and a client that conflates
    /// the two would retry when it should re-read.
    CasMismatch,
    /// A `kv.claim` found an unlapsed claim already held (DR-0034 §4).
    /// [`WireError::claim_expires_in_secs`] says how long it holds.
    ///
    /// The caller should wait for the value the holder is fetching, **not**
    /// contact the provider itself — doing so is the double-refresh the claim
    /// exists to prevent.
    AlreadyClaimed,
    /// A `kv.set` on a claimed entry presented no claim token, or the wrong
    /// one (DR-0034 §4). The usual cause is a claim that lapsed and was taken
    /// over while this caller was still working.
    ClaimTokenMismatch,
    /// The entry lives in the encrypted vault and the vault is closed
    /// (DR-0034 §6). Run `cw vault unlock`; the value is intact.
    ///
    /// **Deliberately distinct from `auth_failed`.** They mean opposite
    /// things: this is "the key is in a locked drawer", that is "you are not
    /// allowed to have it". A client that conflated them would respond to a
    /// locked vault by re-running its authorization flow — which for an OAuth
    /// consumer means minting a **duplicate grant** for a credential it
    /// already holds.
    VaultLocked,
    /// The operation needs a vault and none exists yet (DR-0034 §9). Run
    /// `cw vault init`.
    ///
    /// Separate from `bad_request` so a client can name the one command that
    /// fixes it instead of reporting a malformed call.
    VaultNotInitialized,
    /// A `daemon.restart_graceful` request was rejected before touching any
    /// listener or socket (DR-0029): exec-target verification failed, a
    /// restart is already in progress, or graceful restart is unsupported on
    /// this platform. The current process is unaffected and keeps serving.
    RestartAborted,
}

impl Response {
    /// Construct a `pong` success response.
    pub fn pong() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Pong { pong: true },
        })
    }

    /// Construct a `set` acknowledgement response that reports the applied
    /// guard-constraint kinds (DR-0030 positive ack). Callers pass an
    /// empty vector for an unguarded set (pre-DR-0030 shape: the empty
    /// vector serializes without a `guard_applied` field via
    /// `skip_serializing_if`).
    ///
    /// Test-only since DR-0034 §4: production sets always know the entry's new
    /// version and use [`Self::set_ack_with_guard_and_version`]. This one is
    /// kept so the wire tests can still build the pre-DR-0034 ack shape and
    /// assert it stays byte-compatible.
    #[cfg(test)]
    pub fn set_ack_with_guard(guard_applied: Vec<String>) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Set {
                set: true,
                guard_applied,
                version: None,
                owner_applied: None,
            },
        })
    }

    /// [`Self::set_ack_with_guard`] plus the entry's new CAS version
    /// (DR-0034 §4).
    pub fn set_ack_with_guard_and_version(guard_applied: Vec<String>, version: u64) -> Self {
        Self::set_ack_full(guard_applied, version, None)
    }

    /// The full `set` acknowledgement: guard kinds, new version, and the
    /// owner principal now in force (draft-DR-0033 §6).
    pub fn set_ack_full(
        guard_applied: Vec<String>,
        version: u64,
        owner_applied: Option<String>,
    ) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Set {
                set: true,
                guard_applied,
                version: Some(version),
                owner_applied,
            },
        })
    }

    /// Construct a `kv.claim` success response (DR-0034 §4).
    pub fn claimed_ack(version: u64, claim_token: String, claim_expires_in_secs: u64) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Claimed {
                claimed: true,
                version,
                claim_token,
                claim_expires_in_secs,
            },
        })
    }

    /// Construct a `vault.init` success response (DR-0034 §9).
    pub fn vault_initialized(vault_id: String, recovery_code: String) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::VaultInitialized {
                initialized: true,
                vault_id,
                recovery_code,
            },
        })
    }

    /// Construct a `vault.unlock` success response.
    pub fn vault_unlocked(entries_restored: usize) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::VaultUnlocked {
                unlocked: true,
                entries_restored,
            },
        })
    }

    /// Construct a `vault.add_passkey` success response (DR-0034 §10).
    pub fn ceremony_opened(url: String, expires_in_secs: u64) -> Self {
        Self::Ok(OkResponse {
            ok: true,
            payload: OkPayload::CeremonyOpened {
                ceremony: true,
                url,
                expires_in_secs,
            },
        })
    }

    /// Construct a `kv.owner_clear` success response (draft-DR-0033 §3c).
    pub fn owner_cleared() -> Self {
        Self::Ok(OkResponse {
            ok: true,
            payload: OkPayload::OwnerCleared {
                owner_cleared: true,
            },
        })
    }

    /// Construct a `vault.lock` success response.
    pub fn vault_locked_ack() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::VaultLocked { locked: true },
        })
    }

    /// Construct a `kv.unclaim` success response.
    pub fn unclaimed_ack() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Unclaimed { unclaimed: true },
        })
    }

    /// Construct the failure response for a lost compare-and-swap
    /// (DR-0034 §4), carrying the version to retry from.
    pub fn cas_mismatch(current_version: u64) -> Self {
        let message = if current_version == 0 {
            "the entry does not exist; re-read it and retry with the version you find".to_string()
        } else {
            format!(
                "the entry changed since it was read (it is now at version {current_version}); \
                 re-read it and retry"
            )
        };
        Response::Err(ErrResponse {
            ok: false,
            error: WireError {
                kind: ErrorKind::CasMismatch,
                message,
                current_version: Some(current_version),
                claim_expires_in_secs: None,
            },
        })
    }

    /// Construct the failure response for a key someone else is already
    /// refreshing (DR-0034 §4).
    pub fn already_claimed(claim_expires_in_secs: u64) -> Self {
        Response::Err(ErrResponse {
            ok: false,
            error: WireError {
                kind: ErrorKind::AlreadyClaimed,
                message: format!(
                    "another refresh is already in progress for this key \
                     (for up to {claim_expires_in_secs}s); wait for the new value \
                     rather than refreshing it again"
                ),
                current_version: None,
                claim_expires_in_secs: Some(claim_expires_in_secs),
            },
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

    /// Construct a `list` success response with key names only (no metadata).
    ///
    /// Test helper — production callers use [`Self::list_with_entries`] so the
    /// reply also carries the parallel value-free metadata. Kept under
    /// `#[cfg(test)]` to avoid an unused-API dead-code warning in the binary.
    #[cfg(test)]
    pub fn list(keys: Vec<String>) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::List {
                keys,
                entries: Vec::new(),
            },
        })
    }

    /// Construct a `list` success response carrying both the key names and the
    /// parallel value-free metadata (one [`EntryInfo`] per key, same order).
    /// Used by the daemon so `cache-warden kv list` can render backoff / pin /
    /// state hints next to each name (DR-0022 §3).
    pub fn list_with_entries(keys: Vec<String>, entries: Vec<EntryInfo>) -> Self {
        debug_assert_eq!(
            keys.len(),
            entries.len(),
            "list_with_entries: keys and entries must be parallel"
        );
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::List { keys, entries },
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

    /// Construct an accepted `daemon.restart_graceful` acknowledgement
    /// (DR-0029). See [`Request::RestartGraceful`]'s doc for why a client
    /// should not wait on a second reply after this one. Constructed only
    /// on the macOS-only accept path of `graceful_restart::handle_request`
    /// (hence dead on other targets).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn restarting_ack() -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Restarting { restarting: true },
        })
    }

    /// Construct a `status` success response.
    pub fn status(
        pid: u32,
        version: String,
        socket: String,
        entries: Vec<EntryInfo>,
        full_disk_access: Option<FdaStatusWire>,
        vault: Option<VaultStatusWire>,
    ) -> Self {
        Response::Ok(OkResponse {
            ok: true,
            payload: OkPayload::Status {
                pid,
                version,
                socket,
                entries,
                full_disk_access,
                vault: vault.map(Box::new),
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
                current_version: None,
                claim_expires_in_secs: None,
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

    // ---- DR-0034 §4: CAS + claims ----

    /// The additive contract, in the direction that matters most: a `kv.set`
    /// line produced by a **pre-DR-0034 client** (no `expected_version`, no
    /// `claim_token`) must still parse, and must mean "write
    /// unconditionally". If these defaulted to anything else, upgrading the
    /// daemon would change what every existing client's writes do.
    #[test]
    fn a_pre_cas_kv_set_line_still_parses_as_an_unconditional_write() {
        let line = r#"{"cmd":"kv.set","key":"DB","source":{"kind":"static","value_b64":"cHc="}}"#;
        let req: Request = serde_json::from_str(line).expect("old line parses");
        match req {
            Request::KvSet {
                expected_version,
                claim_token,
                ..
            } => {
                assert_eq!(expected_version, None);
                assert_eq!(claim_token, None);
            }
            other => panic!("expected KvSet, got {other:?}"),
        }
    }

    /// …and the reverse: a `kv.set` that carries neither field must serialize
    /// without them, so an old daemon sees exactly the bytes it always saw.
    #[test]
    fn a_kv_set_without_cas_fields_serializes_to_the_old_bytes() {
        let req = Request::KvSet {
            key: "DB".into(),
            source: SetSource::Static {
                value_b64: "cHc=".into(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
            persist: None,
            signed_by: None,
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(!line.contains("expected_version"), "{line}");
        assert!(!line.contains("claim_token"), "{line}");
    }

    #[test]
    fn kv_set_carries_expected_version_and_claim_token_when_set() {
        let req = Request::KvSet {
            key: "NS/TOK".into(),
            source: SetSource::Static {
                value_b64: "cHc=".into(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: Some(7),
            claim_token: Some("abcdefghijklmnopqrstuv".into()),
            persist: None,
            signed_by: None,
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""expected_version":7"#), "{line}");
        assert!(
            line.contains(r#""claim_token":"abcdefghijklmnopqrstuv""#),
            "{line}"
        );
        roundtrip_request(&req);
    }

    /// Zero is a meaningful `expected_version` ("this key must not exist"), so
    /// it must survive the round trip rather than being elided as a default.
    #[test]
    fn expected_version_zero_is_carried_not_elided() {
        let req = Request::KvSet {
            key: "NS/NEW".into(),
            source: SetSource::Static {
                value_b64: "cHc=".into(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: Some(0),
            claim_token: None,
            persist: None,
            signed_by: None,
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""expected_version":0"#), "{line}");
        roundtrip_request(&req);
    }

    #[test]
    fn kv_claim_and_unclaim_use_their_command_tags() {
        let claim = Request::KvClaim {
            key: "NS/TOK".into(),
            expected_version: 3,
            duration_secs: 60,
        };
        let line = serde_json::to_string(&claim).unwrap();
        assert!(line.contains(r#""cmd":"kv.claim""#), "{line}");
        assert!(line.contains(r#""expected_version":3"#), "{line}");
        assert!(line.contains(r#""duration_secs":60"#), "{line}");
        roundtrip_request(&claim);

        let unclaim = Request::KvUnclaim {
            key: "NS/TOK".into(),
            claim_token: "abcdefghijklmnopqrstuv".into(),
        };
        let line = serde_json::to_string(&unclaim).unwrap();
        assert!(line.contains(r#""cmd":"kv.unclaim""#), "{line}");
        roundtrip_request(&unclaim);
    }

    /// The set ack's `version` is `Option` so its absence is readable as "this
    /// daemon does not do CAS" rather than as version 0 — the same
    /// old-daemon-detection trick `guard_applied` uses.
    #[test]
    fn a_set_ack_without_a_version_is_distinguishable_from_version_zero() {
        let old = r#"{"ok":true,"set":true}"#;
        let resp: Response = serde_json::from_str(old).expect("old ack parses");
        match resp {
            Response::Ok(OkResponse {
                payload: OkPayload::Set { version, .. },
                ..
            }) => assert_eq!(version, None, "absent means 'no CAS support'"),
            other => panic!("expected a Set ack, got {other:?}"),
        }

        let line = serde_json::to_string(&Response::set_ack_with_guard(Vec::new())).unwrap();
        assert_eq!(
            line, r#"{"ok":true,"set":true}"#,
            "byte-compatible with old"
        );
    }

    #[test]
    fn a_set_ack_with_a_version_carries_it() {
        let resp = Response::set_ack_with_guard_and_version(vec!["same-user".into()], 8);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""version":8"#), "{line}");
        assert!(line.contains(r#""guard_applied":["same-user"]"#), "{line}");
        roundtrip_response(&resp);
    }

    #[test]
    fn claim_and_unclaim_acks_round_trip() {
        let resp = Response::claimed_ack(3, "abcdefghijklmnopqrstuv".into(), 60);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""claimed":true"#), "{line}");
        assert!(line.contains(r#""version":3"#), "{line}");
        assert!(line.contains(r#""claim_expires_in_secs":60"#), "{line}");
        roundtrip_response(&resp);

        let resp = Response::unclaimed_ack();
        assert!(
            serde_json::to_string(&resp)
                .unwrap()
                .contains(r#""unclaimed":true"#)
        );
        roundtrip_response(&resp);
    }

    /// The CAS loser must be able to read the version to retry from as a
    /// number, without parsing the message text.
    #[test]
    fn a_cas_mismatch_carries_the_current_version_as_a_field() {
        let resp = Response::cas_mismatch(11);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""kind":"cas_mismatch""#), "{line}");
        assert!(line.contains(r#""current_version":11"#), "{line}");
        match serde_json::from_str::<Response>(&line).unwrap() {
            Response::Err(e) => {
                assert_eq!(e.error.current_version, Some(11));
                assert_eq!(e.error.claim_expires_in_secs, None);
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    /// Version 0 in a mismatch means "the entry does not exist", so it must be
    /// carried rather than skipped as a default-looking value.
    #[test]
    fn a_cas_mismatch_on_a_missing_entry_reports_version_zero() {
        let line = serde_json::to_string(&Response::cas_mismatch(0)).unwrap();
        assert!(line.contains(r#""current_version":0"#), "{line}");
    }

    #[test]
    fn an_already_claimed_error_carries_the_remaining_seconds() {
        let resp = Response::already_claimed(42);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""kind":"already_claimed""#), "{line}");
        assert!(line.contains(r#""claim_expires_in_secs":42"#), "{line}");
        roundtrip_response(&resp);
    }

    /// Every other error stays byte-identical to the pre-DR-0034 shape: the
    /// two structured fields are skipped when absent.
    #[test]
    fn an_ordinary_error_gains_no_new_fields_on_the_wire() {
        let line = serde_json::to_string(&Response::error(ErrorKind::NotFound, "nope")).unwrap();
        assert_eq!(
            line,
            r#"{"ok":false,"error":{"kind":"not_found","message":"nope"}}"#
        );
    }

    /// The new error kinds must serialize snake_case like every existing one.
    #[test]
    fn the_new_error_kinds_are_snake_case() {
        for (kind, want) in [
            (ErrorKind::CasMismatch, "cas_mismatch"),
            (ErrorKind::AlreadyClaimed, "already_claimed"),
            (ErrorKind::ClaimTokenMismatch, "claim_token_mismatch"),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{want}\""));
        }
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
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
            persist: None,
            signed_by: None,
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

    /// DR-0030 wire compat: a pre-DR-0030 client sending a `kv.set` line with
    /// no `guard_constraints` field must decode into an empty Vec, so old
    /// clients keep interoperating unchanged (`#[serde(default)]`).
    #[test]
    fn kv_set_guard_constraints_default_to_empty_when_absent() {
        let line = r#"{"cmd":"kv.set","key":"K","source":{"kind":"static","value_b64":"AA=="}}"#;
        let req: Request = serde_json::from_str(line).unwrap();
        match req {
            Request::KvSet {
                guard_constraints, ..
            } => assert!(guard_constraints.is_empty()),
            _ => panic!("expected KvSet"),
        }
    }

    /// A guarded kv.set request round-trips lossless-y through JSON with the
    /// four constraint kinds (same-user, same-shell, same-ancestor=NAME,
    /// command=NAME). Pins the internally-tagged wire encoding so a serde
    /// rename would surface here.
    #[test]
    fn kv_set_guard_constraints_roundtrip_all_kinds() {
        let req = Request::KvSet {
            key: "K".into(),
            source: SetSource::Static {
                value_b64: "AA==".into(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: vec![
                GuardConstraintWire::SameUser,
                GuardConstraintWire::SameShell,
                GuardConstraintWire::SameAncestor {
                    name: "code".into(),
                },
                GuardConstraintWire::Command { name: "git".into() },
            ],
            expected_version: None,
            claim_token: None,
            persist: None,
            signed_by: None,
        };
        let line = serde_json::to_string(&req).unwrap();
        // Encoding shape (kebab-case tag, spelled kinds).
        assert!(line.contains(r#""kind":"same-user""#), "{line}");
        assert!(line.contains(r#""kind":"same-shell""#), "{line}");
        assert!(
            line.contains(r#"{"kind":"same-ancestor","name":"code"}"#),
            "{line}"
        );
        assert!(
            line.contains(r#"{"kind":"command","name":"git"}"#),
            "{line}"
        );
        roundtrip_request(&req);
    }

    /// Unknown constraint `kind` is rejected at deserialize time rather than
    /// silently degrading to "no constraint" — a guard is security-sensitive
    /// enough that lenient parsing would be unsafe (DR-0030 §Security).
    #[test]
    fn kv_set_unknown_guard_kind_is_rejected() {
        let line = r#"{"cmd":"kv.set","key":"K","source":{"kind":"static","value_b64":"AA=="},"guard_constraints":[{"kind":"same-planet"}]}"#;
        assert!(serde_json::from_str::<Request>(line).is_err());
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
        roundtrip_response(&Response::set_ack_with_guard(Vec::new()));
        // A guarded ack round-trips lossless-ly and carries the labels.
        roundtrip_response(&Response::set_ack_with_guard(vec![
            "same-user".into(),
            "same-shell".into(),
        ]));
    }

    #[test]
    fn list_response_roundtrips() {
        roundtrip_response(&Response::list(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn list_without_entries_omits_field_for_backwards_compat() {
        // DR-0009 minor extension: an older daemon that returns only `keys`
        // must serialize without an `entries` field at all (skip_if_empty),
        // and a newer client must decode that into an empty entries array.
        let resp = Response::list(vec!["a".into()]);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains("entries"),
            "names-only list must omit `entries`: {line}"
        );
        let back: Response = serde_json::from_str(&line).unwrap();
        match back {
            Response::Ok(OkResponse {
                payload: OkPayload::List { keys, entries },
                ..
            }) => {
                assert_eq!(keys, vec!["a".to_string()]);
                assert!(entries.is_empty(), "absent entries decodes to empty");
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[test]
    fn list_with_entries_roundtrips_and_carries_backoff_until_secs() {
        // DR-0022 §3: kv.list reply can carry per-key value-free metadata,
        // including `backoff_until_secs`, parallel to `keys`.
        let info = EntryInfo {
            name: "default/K".into(),
            state: "defined".into(),
            regenerable: true,
            defined: true,
            has_value: false,
            pin_remaining_secs: None,
            value_type: None,
            source: None,
            backoff_until_secs: Some(3),
            guard_summary: None,
            owner_summary: None,
            version: None,
            claim_expires_in_secs: None,
            locked: false,
        };
        let resp = Response::list_with_entries(vec!["default/K".into()], vec![info.clone()]);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            line.contains(r#""backoff_until_secs":3"#),
            "entries must carry backoff_until_secs: {line}"
        );
        let back: Response = serde_json::from_str(&line).unwrap();
        match back {
            Response::Ok(OkResponse {
                payload: OkPayload::List { keys, entries },
                ..
            }) => {
                assert_eq!(keys, vec!["default/K".to_string()]);
                assert_eq!(entries, vec![info]);
            }
            other => panic!("expected List, got {other:?}"),
        }
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
                    backoff_until_secs: None,
                    guard_summary: None,
                    owner_summary: None,
                    version: None,
                    claim_expires_in_secs: None,
                    locked: false,
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
                    backoff_until_secs: None,
                    guard_summary: None,
                    owner_summary: None,
                    version: None,
                    claim_expires_in_secs: None,
                    locked: false,
                },
            ],
            Some(FdaStatusWire::NotGranted),
            None,
        );
        roundtrip_response(&resp);
    }

    /// The Full Disk Access field is optional on the wire in both directions:
    /// a daemon that has nothing to report omits it entirely (an older daemon
    /// never writes it at all), and a payload without it still decodes as a
    /// `status` reply. Its kebab-case strings are part of the schema, so pin
    /// them rather than trusting a round-trip with itself.
    #[test]
    fn status_full_disk_access_is_optional_and_its_strings_are_pinned() {
        let without = Response::status(1, "v".into(), "/s".into(), vec![], None, None);
        let line = serde_json::to_string(&without).expect("encode");
        assert!(!line.contains("full_disk_access"), "{line}");
        assert_eq!(
            serde_json::from_str::<Response>(&line).expect("decode"),
            without
        );

        for (state, expected) in [
            (FdaStatusWire::Granted, "granted"),
            (FdaStatusWire::NotGranted, "not-granted"),
            (FdaStatusWire::NotApplicable, "not-applicable"),
            (FdaStatusWire::Unknown, "unknown"),
        ] {
            let resp = Response::status(1, "v".into(), "/s".into(), vec![], Some(state), None);
            let line = serde_json::to_string(&resp).expect("encode");
            assert!(
                line.contains(&format!("\"full_disk_access\":\"{expected}\"")),
                "{line}"
            );
            assert_eq!(
                serde_json::from_str::<Response>(&line).expect("decode"),
                resp
            );
        }
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
            backoff_until_secs: None,
            guard_summary: None,
            owner_summary: None,
            version: None,
            claim_expires_in_secs: None,
            locked: false,
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

    // ---- daemon.restart_graceful (DR-0029) ----

    #[test]
    fn restart_graceful_request_uses_dotted_cmd_tag_and_no_fields() {
        let line = serde_json::to_string(&Request::RestartGraceful).unwrap();
        assert_eq!(line, r#"{"cmd":"daemon.restart_graceful"}"#);
        roundtrip_request(&Request::RestartGraceful);
    }

    #[test]
    fn restarting_ack_response_roundtrips_and_is_ok() {
        let resp = Response::restarting_ack();
        assert!(resp.is_ok());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""restarting":true"#), "{line}");
        roundtrip_response(&resp);
    }

    #[test]
    fn restart_aborted_error_kind_serializes_snake_case() {
        let resp = Response::error(ErrorKind::RestartAborted, "exec target verification failed");
        let line = serde_json::to_string(&resp).unwrap();
        assert!(line.contains(r#""kind":"restart_aborted""#), "{line}");
        roundtrip_response(&resp);
    }
}
