//! Pure request handling against the core [`Store`].
//!
//! [`handle_request`] is the daemon's brain, kept deliberately synchronous and
//! free of socket / async concerns so it can be unit-tested against the core
//! without a runtime. The async server (see [`crate::daemon::server`]) is the
//! only place that does I/O and locking; it locks the shared store and calls
//! this function.
//!
//! This is the "wire the core into the daemon's center" mandate of DR-0008:
//! every control-socket command maps onto a [`Store`] operation here.

use cache_warden::{
    Authenticator, CapError, Capability, Clock, DefineError, EntryState, ExtendAuthOutcome,
    PinAuthOutcome, ProcessInfo, RegenerateDefOutcome, RegenerateOutcome, SecretBytes, SourceRunner,
    Store, Ttl, ValueMeta, ValueSource,
};

use crate::otp_type;
use crate::protocol::wire::{
    EntryInfo, ErrorKind, Request, Response, SetSource, SourceSpecWire, ValueMetaWire,
};
use crate::protocol::{decode_b64, encode_b64};

/// Convert wire metadata into the core's opaque [`ValueMeta`].
pub fn meta_from_wire(meta: ValueMetaWire) -> ValueMeta {
    match meta.type_label {
        None if meta.params.is_empty() => ValueMeta::new(),
        Some(label) => ValueMeta::with_type(label, meta.params),
        // params without a type label: keep them under an empty type so nothing
        // is silently dropped (the core never interprets either).
        None => ValueMeta::with_type(String::new(), meta.params),
    }
}

/// Everything [`handle_request`] needs beyond the store: the authenticator, a
/// source runner for regeneration, the clock, the daemon's identity for
/// `status`, and the requester ancestry chain for auth attribution.
pub struct HandlerCtx<'a, A: ?Sized, R, C> {
    /// Re-authentication boundary, wired from config (DR-0010): a
    /// `CommandAuthenticator` when `[auth].command` is set, else `AllowAll`.
    /// `?Sized` so the server can pass a `&dyn Authenticator` trait object.
    pub auth: &'a A,
    /// Runs command sources during regeneration.
    pub runner: &'a R,
    /// Time source for TTL evaluation.
    pub clock: &'a C,
    /// Capability token for secret-handling store operations (DR-0024).
    pub store_cap: &'a Capability,
    /// OTP adapter for deriving TOTP codes from cached seeds (DR-0024 §8).
    pub otp_adapter: &'a crate::daemon::otp_adapter::OtpAdapter,
    /// Daemon process id (for `status`).
    pub pid: u32,
    /// Daemon version string (for `status`).
    pub version: &'a str,
    /// Control socket path (for `status`).
    pub socket: &'a str,
    /// The requesting peer's process ancestry chain, or `None` when it could
    /// not be determined. Forwarded into the core auth context for audit, and —
    /// for the key-level gate below — checked against `kv_process_policies`.
    pub requester: Option<&'a [ProcessInfo]>,
    /// Key-level process-access policies (DR-0012 key layer): a map from key name
    /// to its non-empty `allowed_processes` list, built from `[kv.*]` config at
    /// startup. A key absent from the map has no restriction. When a key is
    /// present, a `kv.get` is admitted only if the requester's ancestry passes
    /// [`cache_warden_authsock::chain_gate_passes`] (fail-closed on an unknown
    /// requester). Policy interpretation lives here in the handler/adapter layer,
    /// never in the core [`Store`] (DR-0004).
    pub kv_process_policies: &'a std::collections::BTreeMap<String, Vec<String>>,
}

/// Handle one request against `store`, producing the response to send back.
///
/// Never returns an `Err`: a malformed or failed operation is reported as a
/// failure [`Response`] so the daemon can always reply on the wire.
pub fn handle_request<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    req: Request,
) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match req {
        Request::Ping => Response::pong(),
        Request::Status => handle_status(store, ctx),
        // `kv.list` surfaces definition-only keys too (DR-0014 §6): use the union
        // `keys()` rather than `list()` (value entries only).
        Request::KvList => Response::list(store.keys().iter().map(|s| s.to_string()).collect()),
        Request::KvDel { key, with_define } => {
            let removed = if with_define {
                store.delete_with_definition(&key, ctx.store_cap).unwrap_or(false)
            } else {
                store.delete(&key, ctx.store_cap).unwrap_or(false)
            };
            Response::deleted(removed)
        }
        Request::KvSet {
            key,
            source,
            soft_ttl_secs,
            hard_ttl_secs,
        } => handle_set(store, ctx, key, source, soft_ttl_secs, hard_ttl_secs),
        Request::KvDefine {
            key,
            source,
            soft_ttl_secs,
            hard_ttl_secs,
            meta,
        } => handle_define(store, key, source, soft_ttl_secs, hard_ttl_secs, meta),
        Request::KvGet { key, dry_run } => handle_get(store, ctx, key, dry_run),
        Request::KvPin { key, duration_secs } => handle_pin(store, ctx, key, duration_secs),
        Request::KvUnpin { key } => match store.unpin(&key, ctx.store_cap) {
            Ok(true) => Response::unpinned(true),
            Ok(false) => Response::error(ErrorKind::NotFound, "no such key"),
            Err(CapError::KeyMismatch) | Err(CapError::Unknown) => {
                Response::error(ErrorKind::Internal, "capability mismatch")
            }
        },
    }
}

fn state_str(state: EntryState) -> &'static str {
    match state {
        EntryState::Active => "active",
        EntryState::SoftExpired => "soft_expired",
        EntryState::HardExpired => "hard_expired",
    }
}

fn handle_status<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>) -> Response
where
    A: ?Sized,
    C: Clock,
{
    // Collect names first to avoid holding an immutable borrow across the
    // mutable `state_of` calls. `keys()` is the union of value entries and
    // definitions, so definition-only keys are surfaced too (DR-0014 §6).
    let names: Vec<String> = store.keys().iter().map(|s| s.to_string()).collect();
    let now = ctx.clock.now();
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let has_value = store.has_value(&name);
        let defined = store.is_defined(&name);
        // A definition-only key (no value entry yet) has no lifecycle state; it
        // reports the synthetic `"defined"` state. Otherwise use the value's
        // real state.
        let state = match store.state_of(&name, ctx.clock) {
            Some(s) => state_str(s).to_string(),
            None if defined => "defined".to_string(),
            // Neither a value nor a definition: nothing to report (shouldn't
            // happen for a name `keys()` returned, but skip defensively).
            None => continue,
        };
        // A defined key is always command-backed (regenerable); for a value-only
        // entry, ask its source. Either presence implies regenerability here.
        let regenerable = defined
            || store
                .source_of(&name)
                .map(|s| s.is_regenerable())
                .unwrap_or(false);
        // Remaining pin seconds (None when not pinned; 0 once the deadline has
        // passed). Never exposes the value.
        let pin_remaining_secs = store
            .pin_deadline_of(&name)
            .map(|deadline| deadline.saturating_duration_since(now).as_secs());
        // The opaque value type (DR-0016) is a property of the key's definition,
        // so it is read from there (a typed key always has one). Never the secret.
        let value_type = store
            .definition_of(&name)
            .map(|d| d.meta())
            .and_then(|m| m.type_label())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string());
        // The typed source origin (DR-0018 §2/§3), value-free: for an `op`
        // source the reference (uri) is shown, never the fetched secret.
        let source = store
            .definition_of(&name)
            .and_then(|d| crate::protocol::wire::source_meta_display(d.source_meta()));
        // Remaining backoff seconds (DR-0022): how long until re-fetch is allowed.
        // Reported as seconds (ceiling), or None when no active backoff.
        let backoff_until_secs = store
            .failure_backoff_remaining(&name, ctx.clock)
            .map(|d| d.as_secs());
        entries.push(EntryInfo {
            name,
            state,
            regenerable,
            defined,
            has_value,
            pin_remaining_secs,
            value_type,
            source,
            backoff_until_secs,
        });
    }
    Response::status(
        ctx.pid,
        ctx.version.to_string(),
        ctx.socket.to_string(),
        entries,
    )
}

/// Enforce the composed-key shape at the protocol boundary (DR-0017 §1.5):
/// every key created via `kv.set` / `kv.define` must be `NS/KEY` with both
/// segments in `[A-Za-z0-9_]+`. This keeps "a key that cannot be referenced or
/// written into config" from ever existing. Internal daemon keys
/// (`__authsock_op:*`) never pass through this path, so they are unaffected.
fn validate_protocol_key(key: &str) -> Result<(), Response> {
    if crate::namespace::split_composed(key).is_some() {
        Ok(())
    } else {
        Err(Response::error(
            ErrorKind::BadRequest,
            format!(
                "invalid key {key:?}: must be NS/KEY with both segments matching \
                 [A-Za-z0-9_]+ (DR-0017)"
            ),
        ))
    }
}

fn handle_set<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    source: SetSource,
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
) -> Response
where
    A: ?Sized,
    R: SourceRunner,
    C: Clock,
{
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }
    let ttl = match Ttl::new(
        soft_ttl_secs.map(std::time::Duration::from_secs),
        hard_ttl_secs.map(std::time::Duration::from_secs),
    ) {
        Ok(t) => t,
        Err(e) => return Response::error(ErrorKind::BadRequest, e.to_string()),
    };

    let SetSource::Static { value_b64 } = source;
    let bytes = match decode_b64(&value_b64) {
        Ok(b) => b,
        Err(_) => {
            return Response::error(ErrorKind::BadRequest, "value_b64 is not valid base64");
        }
    };

    // `set` injects opaque bytes only — a value type (otp) lives on a definition
    // (DR-0016), so there is no seed validation here.
    store
        .set(
            key,
            ValueSource::Static,
            SecretBytes::new(bytes),
            ttl,
            ctx.store_cap,
            ctx.clock,
        )
        .ok();
    Response::set_ack()
}

/// Register a command-source definition (DR-0014 §1).
///
/// Idempotent under exact match; a conflicting redefinition is reported as
/// [`ErrorKind::BadRequest`] with a hint to `kv del --with-define` first. No
/// upstream runs here — the value is produced lazily on the first `kv.get`.
fn handle_define(
    store: &mut Store,
    key: String,
    source: SourceSpecWire,
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
    meta: ValueMetaWire,
) -> Response {
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }
    // Validate the selected kind's required fields (DR-0018 §1: a kind-specific
    // required check, e.g. `source = "command"` with no `command.argv`).
    if let Err(e) = source.validate() {
        return Response::error(ErrorKind::BadRequest, e);
    }
    let ttl = match Ttl::new(
        soft_ttl_secs.map(std::time::Duration::from_secs),
        hard_ttl_secs.map(std::time::Duration::from_secs),
    ) {
        Ok(t) => t,
        Err(e) => return Response::error(ErrorKind::BadRequest, e.to_string()),
    };

    // Lower the typed source to the execution primitive (argv + cwd/env) while
    // preserving the typed origin in the definition's opaque source slot so
    // status / persistence / idempotency see the typed form (DR-0018 §1/§2).
    let lowered = source.lower();
    let source_meta = source.to_source_meta();
    match store.define_with_meta(key, lowered, ttl, meta_from_wire(meta), source_meta) {
        Ok(()) => Response::defined_ack(),
        Err(DefineError::Conflict) => Response::error(
            ErrorKind::BadRequest,
            "a different definition already exists for this key; \
             delete it with `kv del KEY --with-define`, then re-define",
        ),
        // A command argv always builds a command source, so this is unreachable;
        // map defensively to a bad request rather than panicking.
        Err(DefineError::StaticNotDefinable) => Response::error(
            ErrorKind::BadRequest,
            "static sources cannot be defined; use `kv set` instead",
        ),
    }
}

/// Handle `kv.get`, running the full retrieval chain (lazy generate / extend /
/// regenerate / re-auth) exactly the same way for reveal and dry-run.
///
/// `dry_run` only changes the *shape of a success response*: the chain still
/// runs to completion (DR-0015 §2 — "verification must not be shallow"), but the
/// value is **not** carried back. Failures are reported identically in both
/// modes. The value-free conversion happens in one place ([`finish_get`]) so a
/// dry-run can never accidentally emit a value.
fn handle_get<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    dry_run: bool,
) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    // Key-level process-access gate (DR-0012 key layer). Applied *before* the
    // retrieval chain so a denied requester never triggers the source command or
    // a re-auth prompt. A key with no policy entry is unrestricted (the common
    // case); a restricted key admits only a requester whose ancestry names an
    // allowed basename, failing closed when the requester is unknown. The denial
    // is `auth_failed` and reveals nothing about the value — the key's existence
    // is already visible via `kv.list`, so it is not hidden. Only get is gated:
    // del / pin / unpin manage the entry's lifecycle, not value retrieval, so the
    // policy (which controls *reading the secret*) does not apply to them.
    if let Some(allowed) = ctx.kv_process_policies.get(&key)
        && !cache_warden_authsock::chain_gate_passes(ctx.requester, allowed)
    {
        return Response::error(
            ErrorKind::AuthFailed,
            "process not permitted to access this key",
        );
    }

    // Fast path: a live (Active) value.
    if store.get(&key, ctx.store_cap, ctx.clock).ok().flatten().is_some() {
        return finish_get(store, ctx, &key, dry_run, "active");
    }

    // Not directly readable. Decide why and try to recover.
    match store.state_of(&key, ctx.clock) {
        // No value entry. If a definition exists, lazily produce the value via
        // the regenerate path (re-auth gated inside get_or_regenerate); else the
        // key truly does not exist (DR-0014 §1).
        None => {
            if store.is_defined(&key) {
                lazy_generate(store, ctx, &key, dry_run)
            } else {
                Response::error(ErrorKind::NotFound, "no such key")
            }
        }
        Some(EntryState::Active) => {
            // Should not happen (get() returned None but state is Active); treat
            // as internal to avoid a silent inconsistency.
            Response::error(ErrorKind::Internal, "entry state changed during read")
        }
        Some(EntryState::SoftExpired) => {
            match store.extend_authenticated(&key, ctx.auth, ctx.requester, ctx.store_cap, ctx.clock) {
                Ok(()) => match store.get(&key, ctx.store_cap, ctx.clock).ok().flatten() {
                    Some(_) => finish_get(store, ctx, &key, dry_run, "active"),
                    None => Response::error(ErrorKind::Internal, "value gone after extend"),
                },
                Err(ExtendAuthOutcome::NotFound) => {
                    Response::error(ErrorKind::NotFound, "no such key")
                }
                Err(ExtendAuthOutcome::HardExpired) => {
                    // Raced into hard expiry between checks; fall through behavior
                    // is to report it; the client may retry to regenerate.
                    Response::error(ErrorKind::AuthFailed, "entry hard-expired during extend")
                }
                Err(ExtendAuthOutcome::AuthFailed(e)) => {
                    Response::error(ErrorKind::AuthFailed, e.to_string())
                }
                Err(ExtendAuthOutcome::CapMismatch) => {
                    Response::error(ErrorKind::Internal, "capability mismatch")
                }
            }
        }
        Some(EntryState::HardExpired) => {
            // A registered definition is the source of truth for regeneration
            // (it works even when the value entry's own source is static), so
            // prefer the definition path when one exists (DR-0014 §2).
            if store.is_defined(&key) {
                return lazy_generate(store, ctx, &key, dry_run);
            }
            match store.regenerate(&key, ctx.runner, ctx.auth, ctx.requester, ctx.store_cap, ctx.clock) {
                Ok(()) => match store.get(&key, ctx.store_cap, ctx.clock).ok().flatten() {
                    Some(_) => finish_get(store, ctx, &key, dry_run, "active"),
                    None => Response::error(ErrorKind::Internal, "value gone after regenerate"),
                },
                Err(RegenerateOutcome::NotFound) => {
                    Response::error(ErrorKind::NotFound, "no such key")
                }
                Err(RegenerateOutcome::NotRegenerable) => Response::error(
                    ErrorKind::NotRegenerable,
                    "static entry hard-expired; re-set it instead",
                ),
                Err(RegenerateOutcome::NotHardExpired) => Response::error(
                    ErrorKind::Internal,
                    "entry not hard-expired during regenerate",
                ),
                Err(RegenerateOutcome::RunFailed(e)) => {
                    Response::error(ErrorKind::UpstreamFailed, e.to_string())
                }
                Err(RegenerateOutcome::AuthFailed(e)) => {
                    Response::error(ErrorKind::AuthFailed, e.to_string())
                }
                Err(RegenerateOutcome::Backoff { retry_after }) => {
                    // A previous fetch failure is within its backoff window (DR-0022).
                    // Report UpstreamFailed so the client knows the upstream is unhealthy;
                    // the retry_after hint is included in the message.
                    Response::error(
                        ErrorKind::UpstreamFailed,
                        format!(
                            "backoff active after previous fetch failure; retry after {:.1}s",
                            retry_after.as_secs_f64()
                        ),
                    )
                }
                Err(RegenerateOutcome::CapMismatch) => {
                    Response::error(ErrorKind::Internal, "capability mismatch")
                }
            }
        }
    }
}

/// Build the success response for `key`'s **resident, readable** value, honoring
/// `dry_run` and the value's type (DR-0015 / DR-0016).
///
/// The caller has already confirmed `key` is Active and readable. This reads the
/// value once more (the only borrow), applies the value-type derivation, and
/// shapes the response:
///
/// - **opaque value**: returned (reveal) or hidden (dry-run) verbatim.
/// - **otp-typed value**: the stored *seed* is run through the [`OtpAdapter`]
///   (DR-0024 §8) and only the derived **code** is returned (reveal). The seed
///   itself **never** leaves the daemon (DR-0016 §3, write-only). In dry-run
///   nothing is returned either way.
///
/// A seed that cannot be interpreted as TOTP is an error — the code cannot be
/// produced — and the seed is never echoed (DR-0016 §5).
fn finish_get<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: &str,
    dry_run: bool,
    state: &str,
) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    // Check the value type before the cap-gated borrow: `definition_of` is cap-free
    // and tells us whether we need the OTP adapter path.
    let meta = store
        .definition_of(key)
        .map(|d| d.meta().clone())
        .unwrap_or_default();

    if otp_type::meta_is_otp(&meta) {
        // OTP path (DR-0024 §8): delegate to the OtpAdapter which performs a
        // 3-stage borrow (cap-gated read → meta → derive) without leaking the seed.
        return match ctx.otp_adapter.get_code(store, key, ctx.clock) {
            Ok(code) => {
                // The code is itself a value: dry-run masks it (DR-0016 §3 / DR-0015).
                if dry_run {
                    Response::get_verified(state)
                } else {
                    Response::get(encode_b64(code.as_bytes()))
                }
            }
            // Map adapter errors to the right ErrorKind without leaking the seed
            // (DR-0024 §Impl §4: cap mismatch is an internal adapter wiring bug,
            // value-gone is defensive, only a malformed seed is caller-visible).
            Err(crate::daemon::otp_adapter::OtpError::Cap(_)) => {
                eprintln!(
                    "cache-warden: otp adapter: cap rejected for key `{key}` (adapter wiring bug)"
                );
                Response::error(ErrorKind::Internal, "internal cap mismatch")
            }
            Err(crate::daemon::otp_adapter::OtpError::NoValue) => {
                Response::error(ErrorKind::Internal, "value gone before otp derive")
            }
            Err(e @ crate::daemon::otp_adapter::OtpError::Derive(_)) => {
                Response::error(ErrorKind::BadRequest, e.to_string())
            }
        };
    }

    // Opaque path: read the resident value once and copy it out, releasing the
    // mutable borrow of `store`. The copy is a brief in-daemon working buffer;
    // base64-encoded — it does not linger.
    let value = match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
        Some(secret) => secret.expose_secret().to_vec(),
        // Should not happen: the caller just confirmed readability. Be defensive.
        None => return Response::error(ErrorKind::Internal, "value gone before finish_get"),
    };

    // Opaque value: dry-run hides it, reveal returns it (DR-0015).
    if dry_run {
        Response::get_verified(state)
    } else {
        Response::get(encode_b64(&value))
    }
}

/// Produce `key`'s value from its registered definition (DR-0014 lazy path).
///
/// Runs the definition's command and re-authenticates inside
/// [`Store::get_or_regenerate`] (a single auth — callers must not pre-authenticate,
/// to avoid double prompting), then returns the freshly produced value. A
/// `ValueResident` outcome means the value became readable concurrently; fall
/// back to a plain get.
fn lazy_generate<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: &str,
    dry_run: bool,
) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match store.get_or_regenerate(key, ctx.runner, ctx.auth, ctx.requester, ctx.store_cap, ctx.clock) {
        Ok(()) => match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
            Some(_) => finish_get(store, ctx, key, dry_run, "active"),
            None => Response::error(ErrorKind::Internal, "value gone after lazy generation"),
        },
        Err(RegenerateDefOutcome::Undefined) => Response::error(ErrorKind::NotFound, "no such key"),
        // A usable value is resident after all; read it directly.
        Err(RegenerateDefOutcome::ValueResident) => match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
            Some(_) => finish_get(store, ctx, key, dry_run, "active"),
            None => Response::error(ErrorKind::Internal, "value resident but unreadable"),
        },
        Err(RegenerateDefOutcome::RunFailed(e)) => {
            Response::error(ErrorKind::UpstreamFailed, e.to_string())
        }
        Err(RegenerateDefOutcome::AuthFailed(e)) => {
            Response::error(ErrorKind::AuthFailed, e.to_string())
        }
        Err(RegenerateDefOutcome::Backoff { retry_after }) => {
            // A previous fetch failure is within its backoff window (DR-0022).
            Response::error(
                ErrorKind::UpstreamFailed,
                format!(
                    "backoff active after previous fetch failure; retry after {:.1}s",
                    retry_after.as_secs_f64()
                ),
            )
        }
        Err(RegenerateDefOutcome::CapMismatch) => {
            Response::error(ErrorKind::Internal, "capability mismatch")
        }
    }
}

/// Pin `key` Active for `duration_secs` (re-auth required; DR-0011).
///
/// The deadline is `clock.now() + duration_secs`. Pinning always prompts for
/// re-authentication (even from Active) because it relaxes expiry; the core
/// [`Store::pin_authenticated`] enforces that. A hard-expired or missing entry
/// is reported without applying any pin.
fn handle_pin<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    duration_secs: u64,
) -> Response
where
    A: Authenticator + ?Sized,
    C: Clock,
{
    let deadline = ctx
        .clock
        .now()
        .saturating_add(std::time::Duration::from_secs(duration_secs));
    match store.pin_authenticated(&key, deadline, ctx.auth, ctx.requester, ctx.store_cap, ctx.clock) {
        Ok(()) => Response::pinned(duration_secs),
        Err(PinAuthOutcome::NotFound) => Response::error(ErrorKind::NotFound, "no such key"),
        Err(PinAuthOutcome::HardExpired) => Response::error(
            ErrorKind::HardExpired,
            "entry is hard-expired (destroyed); cannot pin",
        ),
        Err(PinAuthOutcome::AuthFailed(e)) => Response::error(ErrorKind::AuthFailed, e.to_string()),
        Err(PinAuthOutcome::CapMismatch) => Response::error(ErrorKind::Internal, "capability mismatch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wire::{ErrorKind, OkPayload, Response};
    use cache_warden::{AllowAll, DenyAll, FakeClock, RunError, SecretBytes, SourceRunner};
    use std::time::Duration;

    const SOFT: u64 = 10;
    const HARD: u64 = 30;

    /// A runner returning a fixed value, counting runs.
    struct CountingRunner {
        value: Vec<u8>,
        runs: std::cell::Cell<usize>,
    }
    impl CountingRunner {
        fn new(v: &[u8]) -> Self {
            Self {
                value: v.to_vec(),
                runs: std::cell::Cell::new(0),
            }
        }
        fn runs(&self) -> usize {
            self.runs.get()
        }
    }
    impl SourceRunner for CountingRunner {
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
            self.runs.set(self.runs.get() + 1);
            Ok(SecretBytes::new(self.value.clone()))
        }
    }

    struct FailingRunner;
    impl SourceRunner for FailingRunner {
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
            Err(RunError::EmptyOutput)
        }
    }

    /// A shared empty key-policy table. Most tests have no key-level
    /// `allowed_processes`, so [`ctx`] points at this `&'static` map.
    fn empty_policies() -> &'static std::collections::BTreeMap<String, Vec<String>> {
        static EMPTY: std::sync::OnceLock<std::collections::BTreeMap<String, Vec<String>>> =
            std::sync::OnceLock::new();
        EMPTY.get_or_init(std::collections::BTreeMap::new)
    }

    fn ctx<'a, A, R>(
        auth: &'a A,
        runner: &'a R,
        clock: &'a FakeClock,
        cap: &'a cache_warden::Capability,
    ) -> HandlerCtx<'a, A, R, FakeClock> {
        // Leak a test-only OtpAdapter so it lives long enough for the HandlerCtx
        // (which is 'a). Using Box::leak here is fine in tests: each call allocates
        // a small object that lives until process exit, which is acceptable for
        // unit-test fixtures.
        let otp_adapter: &'static crate::daemon::otp_adapter::OtpAdapter =
            Box::leak(Box::new(crate::daemon::otp_adapter::OtpAdapter::new(cap.clone())));
        HandlerCtx {
            auth,
            runner,
            clock,
            store_cap: cap,
            otp_adapter,
            pid: 1234,
            version: "test",
            socket: "/tmp/test.sock",
            requester: None,
            kv_process_policies: empty_policies(),
        }
    }

    /// A resolved `ProcessInfo` with a basename, for building a fake requester
    /// ancestry chain in key-layer gate tests.
    fn proc(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from(format!("/usr/bin/{name}"))),
            start_time: Some(Duration::from_secs(pid as u64)),
        }
    }

    fn set_static(value: &[u8]) -> Request {
        Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(value),
            },
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
        }
    }

    /// A `command` typed source from a plain argv (test helper).
    fn cmd_spec(argv: &[&str]) -> SourceSpecWire {
        use crate::protocol::wire::CommandSpecWire;
        SourceSpecWire::Command {
            command: CommandSpecWire {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
            },
        }
    }

    fn define_cmd(key: &str, argv: &[&str]) -> Request {
        Request::KvDefine {
            key: key.into(),
            source: cmd_spec(argv),
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
            meta: Default::default(),
        }
    }

    /// An `op` typed source from a uri (+ optional account) — test helper.
    fn op_spec(uri: &str, account: Option<&str>) -> SourceSpecWire {
        use crate::protocol::wire::OpSpecWire;
        SourceSpecWire::Op {
            op: OpSpecWire {
                uri: uri.into(),
                account: account.map(|s| s.to_string()),
            },
        }
    }

    fn define_with(key: &str, source: SourceSpecWire) -> Request {
        Request::KvDefine {
            key: key.into(),
            source,
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
            meta: Default::default(),
        }
    }

    fn get_value(resp: &Response) -> Vec<u8> {
        match resp {
            Response::Ok(ok) => match &ok.payload {
                OkPayload::Get { value_b64 } => decode_b64(value_b64).unwrap(),
                _ => panic!("not a Get payload: {ok:?}"),
            },
            Response::Err(e) => panic!("expected ok, got error: {e:?}"),
        }
    }

    /// Read the `source` field of the single status entry for `key`.
    fn status_source_of<A, R>(
        store: &mut Store,
        c: &HandlerCtx<'_, A, R, FakeClock>,
        key: &str,
    ) -> Option<String>
    where
        A: Authenticator + ?Sized,
        R: SourceRunner,
    {
        let resp = handle_request(store, c, Request::Status);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Status { entries, .. } => entries
                    .into_iter()
                    .find(|e| e.name == key)
                    .and_then(|e| e.source),
                _ => panic!("not status"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn op_define_shows_uri_in_status_not_a_secret() {
        // DR-0018 §3: an op source's status `source` is its uri reference.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(
            handle_request(
                &mut store,
                &c,
                define_with(
                    "default/GH",
                    op_spec("op://vault/item/field", Some("acct.1password.com"))
                )
            )
            .is_ok()
        );
        let src = status_source_of(&mut store, &c, "default/GH").unwrap();
        assert_eq!(src, "op://vault/item/field (account acct.1password.com)");
    }

    #[test]
    fn command_define_status_source_hides_argv() {
        // DR-0018 §3 secret hygiene: a command source's status `source` is just
        // the discriminant (the argv may carry a secret, e.g. `printf %s <seed>`).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(
            handle_request(
                &mut store,
                &c,
                define_with("default/K", cmd_spec(&["printf", "%s", "SECRET_SEED"]))
            )
            .is_ok()
        );
        let src = status_source_of(&mut store, &c, "default/K").unwrap();
        assert_eq!(src, "command");
        // The status response as a whole must not leak the argv secret.
        let resp = handle_request(&mut store, &c, Request::Status);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(!line.contains("SECRET_SEED"), "status leaked argv: {line}");
    }

    #[test]
    fn op_redefine_identical_is_idempotent() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let def = || define_with("default/GH", op_spec("op://v/i/f", None));
        assert!(handle_request(&mut store, &c, def()).is_ok());
        // Exact same typed source + TTL is a no-op (DR-0018 §1 idempotency).
        assert!(handle_request(&mut store, &c, def()).is_ok());
    }

    #[test]
    fn redefine_changing_only_typed_source_conflicts() {
        // Idempotency compares the typed source origin (DR-0018 §2): switching the
        // same key from a command source to an op source is a conflict, even if
        // the lowered argv would coincide.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(
            handle_request(
                &mut store,
                &c,
                define_with("default/K", cmd_spec(&["op", "read", "op://v/i/f"]))
            )
            .is_ok()
        );
        let resp = handle_request(
            &mut store,
            &c,
            define_with("default/K", op_spec("op://v/i/f", None)),
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
    }

    fn err_kind(resp: &Response) -> ErrorKind {
        match resp {
            Response::Err(e) => e.error.kind,
            Response::Ok(_) => panic!("expected error, got ok"),
        }
    }

    #[test]
    fn ping_returns_pong() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let resp = handle_request(&mut store, &c, Request::Ping);
        assert!(resp.is_ok());
    }

    #[test]
    fn set_then_get_static_value() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);

        assert!(handle_request(&mut store, &c, set_static(b"hunter2")).is_ok());
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"hunter2");
    }

    fn dry_get(key: &str) -> Request {
        Request::KvGet {
            key: key.into(),
            dry_run: true,
        }
    }

    /// Assert a response is a value-free dry-run success (no value carried).
    fn assert_verified(resp: &Response) {
        match resp {
            Response::Ok(ok) => match &ok.payload {
                OkPayload::GetVerified { verified, .. } => assert!(*verified),
                other => panic!("expected GetVerified, got {other:?}"),
            },
            Response::Err(e) => panic!("expected verified ok, got error: {e:?}"),
        }
        // And the serialized form must never carry a value field.
        let line = serde_json::to_string(resp).unwrap();
        assert!(
            !line.contains("value_b64"),
            "dry-run leaked a value: {line}"
        );
    }

    #[test]
    fn dry_run_get_static_value_returns_verified_without_value() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(handle_request(&mut store, &c, set_static(b"hunter2")).is_ok());
        let resp = handle_request(&mut store, &c, dry_get("default/K"));
        assert_verified(&resp);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains("hunter2"),
            "dry-run leaked the value: {line}"
        );
    }

    #[test]
    fn dry_run_get_runs_full_lazy_chain() {
        // DR-0015 §2: dry-run is NOT shallow — a definition-only key is lazily
        // produced (the command runs) even though the value is not returned.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"from-cmd");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(handle_request(&mut store, &c, define_cmd("default/K", &["echo", "x"])).is_ok());
        assert_eq!(runner.runs(), 0);
        let resp = handle_request(&mut store, &c, dry_get("default/K"));
        assert_verified(&resp);
        assert_eq!(
            runner.runs(),
            1,
            "dry-run still runs the upstream (full chain)"
        );
    }

    #[test]
    fn dry_run_get_missing_key_is_not_found() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let resp = handle_request(&mut store, &c, dry_get("default/ghost"));
        assert_eq!(err_kind(&resp), ErrorKind::NotFound);
    }

    #[test]
    fn dry_run_get_auth_failure_is_reported_like_reveal() {
        // A dry-run still honors the auth gate (DR-0015 §2: TouchID effects).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, define_cmd("default/K", &["echo", "x"]));
        let resp = handle_request(&mut store, &c, dry_get("default/K"));
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn get_missing_key_is_not_found() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/ghost".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::NotFound);
    }

    #[test]
    fn define_defers_run_until_first_get() {
        // DR-0014: define registers but does not run; the first get lazily
        // produces the value (one run), and a second get is a cache hit (no run).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"from-cmd");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(handle_request(&mut store, &c, define_cmd("default/K", &["echo", "x"])).is_ok());
        assert_eq!(runner.runs(), 0, "define must not run the command");
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"from-cmd");
        assert_eq!(runner.runs(), 1, "first get runs once (lazy)");
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"from-cmd");
        assert_eq!(runner.runs(), 1, "second get is a cache hit");
    }

    #[test]
    fn define_idempotent_same_def_is_ok_conflict_is_bad_request() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(
            handle_request(
                &mut store,
                &c,
                define_cmd("default/K", &["op", "read", "a"])
            )
            .is_ok()
        );
        // Identical definition: idempotent no-op.
        assert!(
            handle_request(
                &mut store,
                &c,
                define_cmd("default/K", &["op", "read", "a"])
            )
            .is_ok()
        );
        // Different argv: conflict.
        let resp = handle_request(
            &mut store,
            &c,
            define_cmd("default/K", &["op", "read", "b"]),
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
    }

    #[test]
    fn define_empty_argv_is_bad_request() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        // An empty `command.argv` is a kind-specific required-field violation
        // (DR-0018 §1): source = "command" requires a non-empty argv.
        let req = Request::KvDefine {
            key: "default/K".into(),
            source: cmd_spec(&[]),
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            meta: Default::default(),
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
    }

    #[test]
    fn lazy_generate_is_denied_when_auth_fails() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, define_cmd("default/K", &["echo", "x"]));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn set_with_soft_exceeding_hard_is_bad_request() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let req = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: Some(100),
            hard_ttl_secs: Some(10),
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
    }

    #[test]
    fn invalid_base64_value_is_bad_request() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let req = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: "not!base64!".into(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
    }

    #[test]
    fn get_soft_expired_extends_via_authenticator() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(15)); // soft-expired
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"v", "AllowAll extends and returns value");
    }

    #[test]
    fn get_soft_expired_denied_is_auth_failed() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(15));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn get_hard_expired_defined_key_regenerates() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"fresh");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, define_cmd("default/K", &["echo"]));
        // First get lazily produces the value (run 1).
        assert_eq!(
            get_value(&handle_request(
                &mut store,
                &c,
                Request::KvGet {
                    key: "default/K".into(),
                    dry_run: false
                }
            )),
            b"fresh"
        );
        clock.advance(Duration::from_secs(HARD)); // hard-expired
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"fresh");
        assert_eq!(runner.runs(), 2, "first get ran once, regenerate ran once");
    }

    #[test]
    fn get_hard_expired_static_is_not_regenerable() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(HARD));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::NotRegenerable);
    }

    #[test]
    fn get_hard_expired_command_upstream_failure_is_reported() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        // Define + first get produces the value via a succeeding runner; then
        // swap to a failing runner so the post-hard-expiry regeneration fails.
        let ok_runner = CountingRunner::new(b"v");
        let c_ok = ctx(&AllowAll, &ok_runner, &clock, &cap);
        handle_request(&mut store, &c_ok, define_cmd("default/K", &["echo"]));
        // First get lazily produces the value.
        assert_eq!(
            get_value(&handle_request(
                &mut store,
                &c_ok,
                Request::KvGet {
                    key: "default/K".into(),
                    dry_run: false
                }
            )),
            b"v"
        );
        clock.advance(Duration::from_secs(HARD));
        let fail = FailingRunner;
        let c_fail = ctx(&AllowAll, &fail, &clock, &cap);
        let resp = handle_request(
            &mut store,
            &c_fail,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::UpstreamFailed);
    }

    #[test]
    fn list_returns_sorted_keys() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        for k in ["default/b", "default/a", "default/c"] {
            handle_request(
                &mut store,
                &c,
                Request::KvSet {
                    key: k.into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                },
            );
        }
        let resp = handle_request(&mut store, &c, Request::KvList);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::List { keys } => {
                    assert_eq!(keys, vec!["default/a", "default/b", "default/c"])
                }
                _ => panic!("not list"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn del_removes_and_reports() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvDel {
                key: "default/K".into(),
                with_define: false,
            },
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Deleted { deleted } => assert!(deleted),
                _ => panic!("not deleted"),
            },
            _ => panic!("expected ok"),
        }
        // Second delete reports false.
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvDel {
                key: "default/K".into(),
                with_define: false,
            },
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Deleted { deleted } => assert!(!deleted),
                _ => panic!("not deleted"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn status_lists_entries_without_values() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"secret-value"));
        let resp = handle_request(&mut store, &c, Request::Status);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains("secret-value"),
            "status must not leak values"
        );
        assert!(!line.contains(&encode_b64(b"secret-value")));
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Status { pid, entries, .. } => {
                    assert_eq!(pid, 1234);
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].name, "default/K");
                    assert_eq!(entries[0].state, "active");
                    assert_eq!(entries[0].pin_remaining_secs, None);
                }
                _ => panic!("not status"),
            },
            _ => panic!("expected ok"),
        }
    }

    // ---- kv.pin / kv.unpin (DR-0011) ----

    fn pin(key: &str, secs: u64) -> Request {
        Request::KvPin {
            key: key.into(),
            duration_secs: secs,
        }
    }

    #[test]
    fn pin_then_get_survives_soft_expiry() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        // Pin for 1000s; then let the soft window (10s) lapse.
        let resp = handle_request(&mut store, &c, pin("default/K", 1000));
        assert!(resp.is_ok(), "pin ok: {resp:?}");
        clock.advance(Duration::from_secs(SOFT + 5));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"v", "pinned value gettable past soft");
    }

    #[test]
    fn pin_denied_is_auth_failed() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        let resp = handle_request(&mut store, &c, pin("default/K", 1000));
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn pin_missing_key_is_not_found() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, pin("default/ghost", 100))),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn pin_hard_expired_is_rejected() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(HARD)); // hard-expired
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, pin("default/K", 1000))),
            ErrorKind::HardExpired
        );
    }

    #[test]
    fn unpin_returns_to_normal_and_missing_is_not_found() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        handle_request(&mut store, &c, pin("default/K", 1000));
        // Unpin then soft-expire: the value is gated again.
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvUnpin {
                key: "default/K".into(),
            },
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Unpinned { unpinned } => assert!(unpinned),
                _ => panic!("not unpinned"),
            },
            _ => panic!("expected ok"),
        }
        // Missing key unpin -> not found.
        assert_eq!(
            err_kind(&handle_request(
                &mut store,
                &c,
                Request::KvUnpin {
                    key: "default/ghost".into()
                }
            )),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn status_reports_pin_remaining_seconds() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));
        handle_request(&mut store, &c, pin("default/K", 1000));
        clock.advance(Duration::from_secs(100));
        let resp = handle_request(&mut store, &c, Request::Status);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Status { entries, .. } => {
                    assert_eq!(entries[0].pin_remaining_secs, Some(900));
                }
                _ => panic!("not status"),
            },
            _ => panic!("expected ok"),
        }
    }

    // ---- OTP value type: handler-side derivation (DR-0016) ----

    /// The RFC 6238 SHA1 seed in base32.
    const OTP_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn otp_wire_meta(params: &[(&str, &str)]) -> ValueMetaWire {
        ValueMetaWire {
            type_label: Some("otp".to_string()),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// An otp *definition* whose command (`printf SEED`) yields `seed` as the
    /// value. Value types live on definitions now (DR-0016), so this is the only
    /// way to register an otp key.
    fn define_otp_seed(key: &str, seed: &str, params: &[(&str, &str)]) -> Request {
        Request::KvDefine {
            key: key.into(),
            source: cmd_spec(&["printf", "%s", seed]),
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            meta: otp_wire_meta(params),
        }
    }

    #[test]
    fn otp_defined_seed_get_returns_code_not_seed() {
        // An otp definition: get derives a 6-digit code, never the seed (write-only).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        assert!(
            handle_request(
                &mut store,
                &c,
                define_otp_seed("default/OTP", OTP_SEED_B32, &[])
            )
            .is_ok()
        );

        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        let code = get_value(&resp);
        // Six ASCII digits.
        assert_eq!(code.len(), 6, "default otp digits");
        assert!(code.iter().all(|b| b.is_ascii_digit()), "code is digits");
        // The seed itself must never appear in the response.
        let line = serde_json::to_string(&resp).unwrap();
        assert!(!line.contains(OTP_SEED_B32), "seed must not leak: {line}");
        assert!(
            !line.contains(&encode_b64(OTP_SEED_B32.as_bytes())),
            "encoded seed must not leak"
        );
    }

    #[test]
    fn otp_digits_param_controls_code_length() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(
            &mut store,
            &c,
            define_otp_seed("default/OTP", OTP_SEED_B32, &[("digits", "8")]),
        );
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp).len(), 8);
    }

    #[test]
    fn otp_defined_seed_derives_code_via_lazy_chain() {
        // An otp *definition* (command source): the command yields the seed, and
        // get derives a code from it (the seed is never returned).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let define = Request::KvDefine {
            key: "default/OTP".into(),
            source: cmd_spec(&["printf", "%s", OTP_SEED_B32]),
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
            meta: otp_wire_meta(&[("digits", "8")]),
        };
        assert!(handle_request(&mut store, &c, define).is_ok());
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        let code = get_value(&resp);
        assert_eq!(code.len(), 8);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(!line.contains(OTP_SEED_B32), "seed must not leak");
    }

    #[test]
    fn otp_seed_from_otpauth_uri() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let uri = format!("otpauth://totp/Label?secret={OTP_SEED_B32}&digits=8");
        handle_request(&mut store, &c, define_otp_seed("default/OTP", &uri, &[]));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp).len(), 8, "digits read from the URI");
    }

    #[test]
    fn otp_dry_run_masks_the_code() {
        // dry-run never returns the value — code or seed (DR-0015 / DR-0016 §3).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(
            &mut store,
            &c,
            define_otp_seed("default/OTP", OTP_SEED_B32, &[]),
        );
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: true,
            },
        );
        assert_verified(&resp);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains(OTP_SEED_B32),
            "seed must not leak in dry-run"
        );
        assert!(!line.contains("value_b64"), "no value carried");
    }

    #[test]
    fn otp_bad_seed_is_bad_request_without_leaking() {
        // A seed that is neither base32 nor a URI: the lazy chain produces it, but
        // derivation fails at get time. The seed is not echoed.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let bad = "this-is-not-a-valid-otp-seed";
        assert!(handle_request(&mut store, &c, define_otp_seed("default/OTP", bad, &[])).is_ok());
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        let line = serde_json::to_string(&resp).unwrap();
        assert!(!line.contains(bad), "seed must not leak: {line}");
    }

    #[test]
    fn otp_type_appears_in_status_not_the_seed() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = cache_warden::CommandRunner::new();
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        // Define + produce the value so a value entry also exists.
        handle_request(
            &mut store,
            &c,
            define_otp_seed("default/OTP", OTP_SEED_B32, &[]),
        );
        handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/OTP".into(),
                dry_run: false,
            },
        );
        let resp = handle_request(&mut store, &c, Request::Status);
        match &resp {
            Response::Ok(ok) => match &ok.payload {
                OkPayload::Status { entries, .. } => {
                    assert_eq!(entries[0].value_type.as_deref(), Some("otp"));
                }
                _ => panic!("not status"),
            },
            _ => panic!("expected ok"),
        }
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains(OTP_SEED_B32),
            "status must not leak the seed"
        );
    }

    #[test]
    fn opaque_value_is_unchanged_by_otp_path() {
        // A non-otp value is returned verbatim (the derivation only triggers on
        // the otp type label).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"plain-secret"));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"plain-secret");
    }

    // ---- key-level process-access gate (DR-0012 key layer) ----

    /// Build a `ctx` with a key-policy table and a (possibly absent) requester
    /// ancestry chain, for exercising the key-layer gate on `kv.get`.
    fn ctx_gated<'a, A, R>(
        auth: &'a A,
        runner: &'a R,
        clock: &'a FakeClock,
        cap: &'a cache_warden::Capability,
        policies: &'a std::collections::BTreeMap<String, Vec<String>>,
        requester: Option<&'a [ProcessInfo]>,
    ) -> HandlerCtx<'a, A, R, FakeClock> {
        let otp_adapter: &'static crate::daemon::otp_adapter::OtpAdapter =
            Box::leak(Box::new(crate::daemon::otp_adapter::OtpAdapter::new(cap.clone())));
        HandlerCtx {
            auth,
            runner,
            clock,
            store_cap: cap,
            otp_adapter,
            pid: 1234,
            version: "test",
            socket: "/tmp/test.sock",
            requester,
            kv_process_policies: policies,
        }
    }

    fn policies(entries: &[(&str, &[&str])]) -> std::collections::BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn get_restricted_key_admits_matching_requester() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let pol = policies(&[("default/K", &["ssh"])]);
        let chain = [proc(100, "ssh"), proc(50, "zsh")];

        // Seed the value with an unrestricted ctx (set is not gated by the key
        // layer — only get is), then read it through the restricted gate.
        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c_set, set_static(b"hunter2"));

        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, Some(&chain));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"hunter2");
    }

    #[test]
    fn get_restricted_key_denies_non_matching_requester() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let pol = policies(&[("default/K", &["ssh"])]);
        let chain = [proc(100, "git"), proc(50, "zsh")];

        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c_set, set_static(b"hunter2"));

        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, Some(&chain));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        // Denied: the requester's ancestry has no allowed basename. The value is
        // not revealed; the key's existence is not hidden (it is visible via list).
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn get_restricted_key_with_unknown_requester_is_fail_closed() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let pol = policies(&[("default/K", &["ssh"])]);

        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c_set, set_static(b"hunter2"));

        // requester == None + a real restriction => fail-closed (denied).
        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, None);
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn get_unrestricted_key_admits_even_unknown_requester() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // K has no policy entry => no restriction (the common case).
        let pol = policies(&[("OTHER", &["ssh"])]);

        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, None);
        handle_request(&mut store, &c, set_static(b"hunter2"));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"hunter2");
    }

    #[test]
    fn dry_run_get_is_also_gated() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let pol = policies(&[("default/K", &["ssh"])]);
        let chain = [proc(100, "git")];

        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c_set, set_static(b"hunter2"));

        // A dry-run get of a restricted key by a non-matching requester is denied
        // exactly like a reveal get (the gate is applied before the chain runs).
        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, Some(&chain));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: true,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn restricted_key_get_denied_before_lazy_generation_runs() {
        // The gate must precede the (re-auth / command) retrieval chain: a denied
        // requester must not trigger the source command at all.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"generated");
        let pol = policies(&[("default/LAZY", &["ssh"])]);
        let chain = [proc(100, "git")];

        // Define LAZY (lazy: no value yet). A denied get must not run the command.
        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(
            &mut store,
            &c_set,
            define_cmd("default/LAZY", &["echo", "x"]),
        );

        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, Some(&chain));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/LAZY".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
        assert_eq!(
            runner.runs(),
            0,
            "denied get must not run the source command"
        );
    }

    #[test]
    fn mutating_commands_are_not_gated_by_the_key_layer() {
        // Only get is gated (取得制御が目的). del/pin/unpin are reachable even by a
        // requester that the key's allowed_processes would reject for a get. This
        // is a deliberate scope decision (DR-0012 key layer): the policy controls
        // *value retrieval*, not lifecycle management of the entry.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let pol = policies(&[("default/K", &["ssh"])]);
        let chain = [proc(100, "git")]; // would be denied for a get

        let c_set = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c_set, set_static(b"hunter2"));

        let c = ctx_gated(&AllowAll, &runner, &clock, &cap, &pol, Some(&chain));
        // del succeeds (not gated): the entry is removed.
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvDel {
                key: "default/K".into(),
                with_define: false,
            },
        );
        assert!(resp.is_ok(), "del is not gated by the key layer: {resp:?}");
    }
}
