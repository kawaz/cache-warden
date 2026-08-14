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

use cache_warden::RefreshClaim;
use cache_warden::{
    Authenticator, CapError, Capability, Clock, DeclaredAncestor, DefineError, EntryState,
    ExtendAuthOutcome, GuardConstraint, GuardRecord, GuardSetter, PinAuthOutcome, PinnedProcess,
    ProcessInfo, RegenerateDefOutcome, RegenerateOutcome, SecretBytes, SourceRunner, Store, Ttl,
    ValueMeta, ValueSource,
};
use cache_warden_vault::ClaimToken;

use crate::daemon::guard::{
    self as guard_eval, GetterAuditToken, GetterProcess, denied_kind_label,
};
use crate::otp_type;
use crate::protocol::wire::{
    EntryInfo, ErrorKind, GuardConstraintWire, Request, Response, SetSource, SourceSpecWire,
    ValueMetaWire,
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
    /// macOS Full Disk Access state (for `status`), probed by the server
    /// layer when a `status` request arrives and left `None` otherwise.
    ///
    /// Probed per request rather than cached at startup because the user can
    /// grant the permission at any time — a value sampled once would keep
    /// reporting the state the daemon booted with. It is *not* probed for
    /// other request kinds: an ungranted probe is a denied read that TCC
    /// records, and doing that on every `kv.get` would be noise.
    pub full_disk_access: Option<crate::protocol::wire::FdaStatusWire>,
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
    /// DR-0030 evaluator material for the current request (get) / setter
    /// snapshot (set): the requester's ancestry entries enriched with
    /// `unique_id` when the private macOS API succeeded. `None` on any
    /// platform / failure where the pid could not be walked at all.
    ///
    /// # TOCTOU boundary
    ///
    /// The enrichment is captured once by the connection dispatcher at
    /// **request receive time** (server-side), then handed here for the
    /// full duration of the handler. A parent that exits mid-evaluation
    /// simply collapses to a shorter chain in this snapshot, which the
    /// `guard::evaluate` short-circuit converts to `SameAncestor` denial —
    /// the fail-closed direction (DR-0030 §Security).
    pub guard_chain: Option<&'a [GetterProcess]>,
    /// DR-0030: the requester's `peer_audit_token` at request receive
    /// time, reduced to what the evaluator needs (euid/ruid). Race-free
    /// per the kernel's `LOCAL_PEERTOKEN` contract (`peer_audit_token`
    /// keys off the fd, not a pid), so this alone is safe to use without
    /// a re-check. `None` on non-macOS or if the `getsockopt` failed —
    /// the evaluator treats the missing case as `MissingContext` (fail-
    /// closed) whenever a `SameUser` constraint requires it.
    pub guard_audit_token: Option<GetterAuditToken>,
    /// DR-0030 daemon-wide guard policy (default-require-same-user,
    /// shell-names). Read at `handle_set` time to decide whether an
    /// unguarded set is silently upgraded to require `SameUser`, and to
    /// resolve `--require-same-shell` to a concrete pin.
    pub kv_policy: &'a crate::config::ResolvedKvPolicy,
    /// DR-0031 §8 approver-dialog integration: whether [`handle_get`] should
    /// evaluate the entry's guard record (the default, [`GuardCheckMode::Evaluate`])
    /// or skip that block because the server layer has already evaluated it,
    /// shown the dialog, and re-evaluated fail-closed under the current
    /// store lock ([`GuardCheckMode::AlreadyApproved`]).
    ///
    /// # Why a mode flag, not a separate entry point
    ///
    /// The retrieval chain below the guard block (soft-expired extend,
    /// hard-expired regenerate, lazy-generate) is exactly the same in
    /// either case — a second entry point would duplicate the entire tail
    /// of [`handle_get`]. The flag defaults to `Evaluate`, so every
    /// non-approver caller (all existing tests, all non-`kv.get` handler
    /// paths) is unaffected.
    ///
    /// The server layer is responsible for **only** setting
    /// `AlreadyApproved` after re-taking the store lock and re-evaluating
    /// the guard record (which may have changed while the human was
    /// deciding on the dialog) — see `server::run_request_with_dialog`.
    pub guard_check_mode: GuardCheckMode,
}

/// DR-0031 §8: whether [`handle_get`] should run the DR-0030 guard block or
/// skip it because a dialog approval has already cleared this get under the
/// current store lock. See [`HandlerCtx::guard_check_mode`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum GuardCheckMode {
    /// Normal path — evaluate the guard record if any (fail-closed on any
    /// denial). This is the default and the mode used by every non-approver
    /// caller.
    #[default]
    Evaluate,
    /// The server layer has already shown the approver dialog, received an
    /// `Approved` outcome, re-taken the store lock, and re-evaluated the
    /// guard record fail-closed. The handler must not re-evaluate the guard
    /// again (that would be redundant with the server-side re-check and
    /// would confusingly log a second `guard evaluation` line for a single
    /// user-approved get).
    AlreadyApproved,
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
        // `kv.list` surfaces definition-only keys too (DR-0014 §6): use the full
        // union via list_filtered (DR-0025), replacing the deprecated `keys()`.
        // The reply carries both the names (the historical payload) and the
        // parallel value-free metadata (DR-0022 §3 / DR-0009 minor extension)
        // so a client can show backoff / pin / state hints alongside each name.
        Request::KvList => handle_list(store, ctx),
        Request::KvDel { key, with_define } => {
            let removed = if with_define {
                store
                    .delete_with_definition(&key, ctx.store_cap)
                    .unwrap_or(false)
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
            guard_constraints,
            expected_version,
            claim_token,
        } => {
            // DR-0034 §4 arbitration runs before the write, and both checks
            // must reject without touching the store: a caller told "no" must
            // be able to rely on nothing having happened.
            //
            // Phase 5 note: DR-0033 §3d fixes the composition order as owner
            // authorization -> CAS check -> update. Owner authorization does
            // not exist yet, so these two checks currently sit at the front by
            // default rather than by arrangement. When it lands it must go
            // *above* this block — deciding whether a caller may write at all
            // has to precede telling them what version the key is at, or a
            // caller with no authorization still learns the key's state from
            // the mismatch reply.

            if let Some(expected) = expected_version {
                let current = store.version_of(&key);
                if current != expected {
                    return Response::cas_mismatch(current);
                }
            }
            if let Err(resp) = check_claim_fence(store, &key, claim_token.as_deref()) {
                return resp;
            }
            handle_set(
                store,
                ctx,
                key,
                source,
                soft_ttl_secs,
                hard_ttl_secs,
                guard_constraints,
            )
        }
        Request::KvClaim {
            key,
            expected_version,
            duration_secs,
        } => handle_claim(store, ctx, key, expected_version, duration_secs),
        Request::KvUnclaim { key, claim_token } => handle_unclaim(store, ctx, key, claim_token),
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
        // DR-0029: `server::run_request` always intercepts this variant
        // itself (dispatching to `graceful_restart::handle_request`, which
        // needs `Shared` — not available here) before this function is ever
        // called with it. This arm exists only so the match stays exhaustive
        // against a future new `Request` variant being added without a
        // matching update here; it is not expected to execute in practice.
        Request::RestartGraceful => Response::error(
            ErrorKind::Internal,
            "restart_graceful must be dispatched by run_request",
        ),
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
    let entries = collect_entry_infos(store, ctx.clock);
    Response::status(
        ctx.pid,
        ctx.version.to_string(),
        ctx.socket.to_string(),
        entries,
        ctx.full_disk_access,
    )
}

/// Handle `kv.list`: return both the sorted key names (historical payload) and
/// the parallel value-free metadata (DR-0022 §3 / DR-0009 minor extension).
///
/// Older clients keep reading `keys`; newer clients render hints from `entries`.
fn handle_list<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>) -> Response
where
    A: ?Sized,
    C: Clock,
{
    let entries = collect_entry_infos(store, ctx.clock);
    let keys: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    Response::list_with_entries(keys, entries)
}

/// Build a parallel [`EntryInfo`] vector for every key in the union of
/// `entries` + `definitions` (sorted), in the same order [`Store::list_filtered`]
/// returns them.
///
/// Shared between `status` and `kv.list` so both reflect the same value-free
/// view (state / pin / typed source / backoff). All metadata is read through
/// the immutable `Store` accessors (no zeroize side effect — DR-0025 §Impl).
/// A key whose entry+definition both vanish between the union call and the
/// per-key probe is dropped defensively.
fn collect_entry_infos<C: Clock>(store: &Store, clock: &C) -> Vec<EntryInfo> {
    let names: Vec<String> = store
        .list_filtered(|_| true)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let now = clock.now();
    let mut entries = Vec::with_capacity(names.len());
    // One wall-clock reading for the whole pass, so two entries in the same
    // reply cannot disagree about whether a claim is still active. Named
    // apart from the monotonic `now` this function already uses for TTLs —
    // the two are different clocks and must not be confused.
    let wall_now = now_epoch_ms();
    for name in names {
        let has_value = store.has_value(&name);
        let defined = store.is_defined(&name);
        let item_state = store.entry_state_pure(&name, clock);
        let state = match item_state {
            Some(s) => state_str(s).to_string(),
            None if defined => "defined".to_string(),
            None => continue,
        };
        let regenerable = defined
            || store
                .source_of(&name)
                .map(|s| s.is_regenerable())
                .unwrap_or(false);
        let pin_remaining_secs = store
            .pin_deadline_of(&name)
            .map(|deadline| deadline.saturating_duration_since(now).as_secs());
        let value_type = store
            .definition_of(&name)
            .map(|d| d.meta())
            .and_then(|m| m.type_label())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string());
        let source = store
            .definition_of(&name)
            .and_then(|d| crate::protocol::wire::source_meta_display(d.source_meta()));
        let backoff_until_secs = store
            .failure_backoff_remaining(&name, clock)
            .map(|d| d.as_secs());
        let guard_summary = store.guard_of(&name).map(summarize_guard_record);
        // Read both before `name` moves into the struct below.
        let version = match store.version_of(&name) {
            0 => None,
            v => Some(v),
        };
        let claim_expires_in_secs = store
            .refresh_claim_of(&name)
            .filter(|c| c.is_active_at(wall_now))
            .map(|c| c.remaining_ms(wall_now).div_ceil(1_000));
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
            guard_summary,
            // DR-0034 §4. Value-free: a change counter and a remaining
            // duration. The claim *token* is deliberately absent — `status`
            // and `kv list` are readable by anyone who can reach the socket,
            // and publishing the token would let a bystander complete or
            // cancel someone else's refresh.
            version,
            claim_expires_in_secs,
        });
    }
    entries
}

/// Enforce the composed-key shape at the protocol boundary (DR-0017 §1.5):
/// every key created via `kv.set` / `kv.define` must be `NS/KEY` with both
/// segments in `[A-Za-z0-9_]+`. This keeps "a key that cannot be referenced or
/// written into config" from ever existing. Internal daemon keys
/// (`authsock/op_*`) are composed inside the daemon and never pass through this
/// wire path, so they are unaffected.
///
/// This is the wire-adapter's **semantic** gate: it requires a full `NS/KEY`
/// (the core's own syntax gate is looser — it also accepts a bare `KEY` — because
/// namespace policy is an adapter concern, DR-0017 §1/§2).
fn validate_protocol_key(key: &str) -> Result<(), Response> {
    if crate::namespace::split_composed(key).is_some() {
        Ok(())
    } else {
        Err(Response::error(
            ErrorKind::BadRequest,
            format!(
                "invalid key {key:?}: must be NS/KEY with both segments matching \
                 [A-Za-z0-9_]+"
            ),
        ))
    }
}

/// Reject a `kv.set` / `kv.define` targeting a reserved namespace (DR-0018 §4.5).
///
/// The `authsock` namespace holds adapter-internal op keys the daemon composes
/// itself and serves only over the SSH agent protocol; an external write into it
/// is refused so it cannot be shadowed or seeded from the outside. Assumes the
/// key already passed [`validate_protocol_key`] (so `split_composed` succeeds).
fn reject_reserved_namespace_write(key: &str) -> Result<(), Response> {
    match crate::namespace::split_composed(key) {
        Some((ns, _)) if crate::namespace::is_reserved_namespace(ns) => Err(Response::error(
            ErrorKind::BadRequest,
            format!("namespace {ns:?} is reserved and cannot be written to"),
        )),
        _ => Ok(()),
    }
}

/// Reject a `kv.get` targeting a reserved namespace (DR-0018 §4.5, confidentiality
/// axis).
///
/// Symmetric to [`reject_reserved_namespace_write`]: the `authsock` namespace
/// holds op private-key PEM (`authsock/op_*`) the daemon composes itself and
/// serves only over the SSH agent protocol for SIGN. No legitimate wire path
/// reveals that PEM, so an external `kv.get` into the reserved namespace is
/// refused with the same explicit `BadRequest` as writes — interface symmetry
/// over existence-hiding, since the write bouncer already names the reservation.
///
/// Splits on the raw first `/` (not [`crate::namespace::split_composed`]) so the
/// namespace is caught even if the KEY segment is not a valid identifier: unlike
/// the write path, `kv.get` has no prior [`validate_protocol_key`] gate, so an
/// arbitrary caller-supplied key must be classified by its namespace alone.
fn reject_reserved_namespace_read(key: &str) -> Result<(), Response> {
    match key.split_once('/') {
        Some((ns, _)) if crate::namespace::is_reserved_namespace(ns) => Err(Response::error(
            ErrorKind::BadRequest,
            format!("namespace {ns:?} is reserved and cannot be read"),
        )),
        _ => Ok(()),
    }
}

fn handle_set<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    source: SetSource,
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
    guard_constraints: Vec<GuardConstraintWire>,
) -> Response
where
    A: ?Sized,
    R: SourceRunner,
    C: Clock,
{
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }
    if let Err(resp) = reject_reserved_namespace_write(&key) {
        return resp;
    }
    // DR-0030 §7: build the guard record *before* touching the store. If the
    // client declared any constraint, or the daemon's `default-require-same-
    // user` upgrades an unguarded set, we need the setter's peer identity
    // and (for the `same-ancestor` family) a pinnable process from the
    // setter's ancestry chain. A failure to gather any of that material
    // rejects the whole request without ever calling `store.set` — better a
    // loud "guard could not be constructed" than a silent unguarded write.
    let guard_plan = match plan_guard_record(&guard_constraints, ctx) {
        Ok(plan) => plan,
        Err(resp) => return resp,
    };
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
    // (DR-0016), so there is no seed validation here. The key already passed the
    // wire syntax gate, so a core InvalidKey cannot occur; a CapMismatch would be
    // an internal wiring bug (the handler always holds the store cap). Both are
    // reported defensively rather than swallowed.
    match store.set(
        key.clone(),
        ValueSource::Static,
        SecretBytes::new(bytes),
        ttl,
        ctx.store_cap,
        ctx.clock,
    ) {
        Ok(()) => {
            // DR-0030 §5 "全置換": the current set's declaration is the
            // whole guard state. When the plan produces a record we
            // install it; when it is `None` (no declared constraint and
            // no implicit `SameUser` upgrade) we drop any pre-existing
            // record so an unguarded set can never carry over a stale
            // guard from a previous guarded write on the same key.
            let guard_applied: Vec<String> = match guard_plan {
                Some(record) => {
                    let labels = record
                        .constraints
                        .iter()
                        .map(constraint_kind_label)
                        .map(str::to_string)
                        .collect();
                    // `set_guard` shares the same cap gate as `set`, so a
                    // mismatch here would be an internal wiring bug (we
                    // just used the same `ctx.store_cap` to set the
                    // value). MEDIUM-2 rollback: if `set_guard` fails we
                    // must not leave the value stored *without* the guard
                    // the caller declared. Best-effort delete the value
                    // we just wrote before surfacing the Internal error —
                    // better to lose the write entirely than to persist
                    // an unguarded value that was meant to be guarded.
                    // The `delete` result is deliberately discarded: a
                    // second cap mismatch is the same wiring bug, and
                    // the caller already sees Internal.
                    if store.set_guard(key.clone(), record, ctx.store_cap).is_err() {
                        let _ = store.delete(&key, ctx.store_cap);
                        return Response::error(ErrorKind::Internal, "capability mismatch (guard)");
                    }
                    labels
                }
                None => {
                    // No constraint on this set — drop any prior record
                    // ("last declaration wins"). Cap-guarded like above.
                    // LOW-b: symmetric with the `set_guard` branch — an
                    // Err here is the same internal wiring bug and must
                    // not be swallowed. We do NOT rollback the value in
                    // this branch: an unguarded set stores an unguarded
                    // value by design; failing to clear a stale prior
                    // guard leaves the entry *more* restrictive, not
                    // less, which is safe to surface as-is via Internal.
                    if store.clear_guard(&key, ctx.store_cap).is_err() {
                        return Response::error(ErrorKind::Internal, "capability mismatch (guard)");
                    }
                    Vec::new()
                }
            };
            // Every write advances the version, whether or not this caller
            // asked for a compare-and-swap. A write that left the counter
            // alone would be invisible to the CAS callers racing it, which is
            // precisely who the counter exists for.
            let version = match store.bump_version(key.clone(), ctx.store_cap) {
                Ok(v) => v,
                Err(_) => return Response::error(ErrorKind::Internal, "capability mismatch"),
            };
            // A completed write ends the refresh its claim was held for. The
            // fence above already established that this caller is entitled to
            // release it.
            if store.clear_refresh_claim(&key, ctx.store_cap).is_err() {
                return Response::error(ErrorKind::Internal, "capability mismatch (claim)");
            }
            Response::set_ack_with_guard_and_version(guard_applied, version)
        }
        Err(cache_warden::SetError::InvalidKey(e)) => {
            Response::error(ErrorKind::BadRequest, e.to_string())
        }
        Err(cache_warden::SetError::CapMismatch) => {
            Response::error(ErrorKind::Internal, "capability mismatch")
        }
    }
}

/// Longest refresh claim the daemon will grant, in seconds.
///
/// The expiry exists to reclaim a key from a caller that died mid-refresh, so
/// a duration long enough to defeat that reclamation defeats the mechanism: a
/// crashed holder would wedge the credential for as long as it asked for. An
/// hour is far beyond any honest provider round trip while still bounding the
/// damage, and a caller that genuinely needs longer can re-claim.
const MAX_CLAIM_SECS: u64 = 3600;

/// Wall-clock milliseconds since the Unix epoch.
///
/// Claims are compared against wall time, not the injected [`Clock`], because
/// a claim outlives the process that took it (DR-0034 §4) and a monotonic
/// reading taken by a dead process means nothing to its successor.
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether `supplied` is the token `held` by the active claim.
///
/// Both sides go through [`ClaimToken`] rather than being compared as raw
/// strings, for two reasons. The comparison is constant-time, so a caller
/// cannot narrow a token down byte by byte from response timing — the token is
/// not a secret, but it is the only thing standing between a bystander and
/// hijacking a credential refresh, and a variable-time `==` on it is the kind
/// of detail that gets copied somewhere it matters more. And parsing the
/// caller's string first means a malformed token is rejected as malformed
/// instead of falling through to a comparison that could never have matched.
fn claim_token_matches(held: &str, supplied: &str) -> bool {
    match (ClaimToken::parse(held), ClaimToken::parse(supplied)) {
        (Ok(a), Ok(b)) => a.matches(&b),
        // A stored token that no longer parses is a token nothing can match;
        // failing closed here beats falling back to a string compare.
        _ => false,
    }
}

/// Reject a write that does not satisfy an active claim (DR-0034 §4).
///
/// An **active** claim demands its own token; a lapsed one demands nothing,
/// because if nobody took over then the original caller's late write is the
/// only write and there is nothing to protect the key from.
///
/// Both refusals share one wire kind but carry different messages: "you did
/// not bring a token" and "your token is no longer the right one" call for
/// different next steps — wait or take the claim, versus re-read because
/// someone took over mid-refresh.
fn check_claim_fence(store: &Store, key: &str, token: Option<&str>) -> Result<(), Response> {
    let now = now_epoch_ms();
    let Some(active) = store.refresh_claim_of(key).filter(|c| c.is_active_at(now)) else {
        return Ok(());
    };
    match token {
        None => Err(Response::error(
            ErrorKind::ClaimTokenMismatch,
            "a refresh is already in progress for this key; wait for it to finish, or pass the token from your own `kv claim`",
        )),
        Some(t) if !claim_token_matches(active.token(), t) => Err(Response::error(
            ErrorKind::ClaimTokenMismatch,
            "this claim token is no longer the one holding the key: the claim lapsed and another caller took over. Re-read the key and claim again",
        )),
        Some(_) => Ok(()),
    }
}

/// Handle `kv.claim` (DR-0034 §4).
fn handle_claim<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    expected_version: u64,
    duration_secs: u64,
) -> Response
where
    A: ?Sized,
    R: SourceRunner,
    C: Clock,
{
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }
    // Claiming a key that holds nothing would record a claim nobody can ever
    // complete — and the store drops claims when values go away, so it would
    // simply vanish. Refuse plainly instead.
    if !store.has_value(&key) {
        return Response::error(ErrorKind::NotFound, "no value stored for this key");
    }

    if duration_secs == 0 || duration_secs > MAX_CLAIM_SECS {
        return Response::error(
            ErrorKind::BadRequest,
            format!(
                "claim duration must be between 1 and {MAX_CLAIM_SECS} seconds \
                 (a claim that outlives the caller has to expire for the key to be reclaimed)"
            ),
        );
    }

    let current = store.version_of(&key);
    if current != expected_version {
        return Response::cas_mismatch(current);
    }

    let now = now_epoch_ms();
    if let Some(active) = store.refresh_claim_of(&key).filter(|c| c.is_active_at(now)) {
        return Response::already_claimed(active.remaining_ms(now).div_ceil(1_000));
    }

    let token = ClaimToken::generate();
    let expires_at = now.saturating_add(duration_secs.saturating_mul(1_000));
    let claim = RefreshClaim::new(token.as_str(), now, expires_at);
    if store.set_refresh_claim(key, claim, ctx.store_cap).is_err() {
        return Response::error(ErrorKind::Internal, "capability mismatch (claim)");
    }
    Response::claimed_ack(current, token.as_str().to_string(), duration_secs)
}

/// Handle `kv.unclaim` (DR-0034 §4).
fn handle_unclaim<A, R, C>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, A, R, C>,
    key: String,
    claim_token: String,
) -> Response
where
    A: ?Sized,
    R: SourceRunner,
    C: Clock,
{
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }
    let now = now_epoch_ms();
    match store.refresh_claim_of(&key).filter(|c| c.is_active_at(now)) {
        // Nothing holds the key. Releasing is a no-op rather than an error, so
        // a caller retrying after a crash is not punished for it.
        None => {}
        Some(active) if !claim_token_matches(active.token(), &claim_token) => {
            return Response::error(
                ErrorKind::ClaimTokenMismatch,
                "this claim token is no longer the one holding the key, so releasing it would cancel someone else's refresh",
            );
        }
        Some(_) => {}
    }
    if store.clear_refresh_claim(&key, ctx.store_cap).is_err() {
        return Response::error(ErrorKind::Internal, "capability mismatch (claim)");
    }
    Response::unclaimed_ack()
}

/// The wire kind label surfaced in `Set { guard_applied }` and in
/// [`EntryInfo::guard_summary`] (via [`summarize_guard_record`]). Kept as
/// static strings for the ack (value-free by construction: only the
/// kind, never the pinned identity).
fn constraint_kind_label(c: &GuardConstraint) -> &'static str {
    match c {
        GuardConstraint::SameUser => "same-user",
        GuardConstraint::SameAncestor {
            declared: DeclaredAncestor::SameShell { .. },
            ..
        } => "same-shell",
        GuardConstraint::SameAncestor {
            declared: DeclaredAncestor::Named { .. },
            ..
        } => "same-ancestor",
        GuardConstraint::Command { .. } => "command",
    }
}

/// The display label surfaced in `EntryInfo::guard_summary` (`kv list` /
/// `status`). Same value-free rule as [`constraint_kind_label`], plus the
/// declared display name for the ancestor / command families and the
/// `" (weak)"` suffix on `command` (DR-0030 §1b: "weak (spoofable)"
/// documentation must appear alongside every command= surface).
pub(crate) fn summarize_guard_record(record: &GuardRecord) -> Vec<String> {
    let mut strong = Vec::new();
    let mut weak = Vec::new();
    for c in &record.constraints {
        match c {
            GuardConstraint::SameUser => strong.push("same-user".to_string()),
            GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell { shell_name },
                ..
            } => strong.push(format!("same-shell ({shell_name})")),
            GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::Named { name },
                ..
            } => strong.push(format!("same-ancestor ({name})")),
            GuardConstraint::Command { name } => weak.push(format!("command ({name}) (weak)")),
        }
    }
    // Strong-first display order (§F "強い順"): same-ancestor/same-shell/
    // same-user before command. The individual `strong` order preserves
    // record insertion (which the CLI parser dedups but does not reorder).
    strong.extend(weak);
    strong
}

/// Build the [`GuardRecord`] that should attach to this `kv.set`, or
/// [`None`] if the entry should end up unguarded. Returns an error
/// [`Response`] when material is missing — that path never mutates the
/// store, so a rejected guard-plan is a no-op set.
///
/// # Fail-closed contract
///
/// 1. A wire declaration containing any `same-user` (implicit or
///    explicit) requires `ctx.guard_audit_token`. Missing → reject.
/// 2. A `same-ancestor` / `same-shell` constraint requires
///    `ctx.guard_chain`. Missing → reject. When present, the pinnable
///    entity is looked up: no match → reject (`§7` "pin 対象が存在しない
///    宣言は成立しない"). The pinned identity is taken from the daemon's
///    observation (never from the wire).
/// 3. When `guard_constraints` is empty **and** `[kv-policy]
///    default-require-same-user = true`, a `SameUser` is injected
///    implicitly. The client sees this via the `guard_applied` ack.
/// 4. Otherwise an empty `guard_constraints` returns `Ok(None)` —
///    perfectly interoperable with pre-DR-0030 clients.
fn plan_guard_record<A, R, C>(
    declared: &[GuardConstraintWire],
    ctx: &HandlerCtx<'_, A, R, C>,
) -> Result<Option<GuardRecord>, Response>
where
    A: ?Sized,
{
    // Effective declaration = client's list, with an implicit SameUser
    // pushed on the front when the config asks for it and the client
    // sent nothing. We do not merge implicit + explicit: the moment the
    // client declared anything, their declaration is authoritative
    // (§5 "last declaration wins"), even if that declaration omits
    // same-user.
    let effective: Vec<GuardConstraintWire> = if declared.is_empty() {
        if ctx.kv_policy.default_require_same_user {
            vec![GuardConstraintWire::SameUser]
        } else {
            return Ok(None);
        }
    } else {
        declared.to_vec()
    };

    // Setter identity is taken from the connection's peer audit token
    // (§7). We only need it once, but declare fail-closed here so a
    // wire-declared guard against a `None` token is refused before we
    // start pinning ancestors.
    let setter = match ctx.guard_audit_token {
        Some(t) => GuardSetter {
            euid: t.euid,
            ruid: t.ruid,
        },
        None => {
            return Err(Response::error(
                ErrorKind::AuthFailed,
                "cannot construct guard record: peer audit token unavailable",
            ));
        }
    };

    // For any `SameAncestor`-family entry we need to pin from the
    // setter's chain. LOW-a: this is asymmetric with the getter side
    // and the asymmetry is deliberate:
    //
    // - Set side (here): `SameUser` needs only the peer audit token
    //   (validated above) — a missing chain is *not* fatal for a
    //   pure-`SameUser` declaration. The `same-ancestor` family calls
    //   `pin_ancestor` below, which returns `None` on an empty chain
    //   and rejects the set — that path is fail-closed.
    // - Get side (`handle_get`): a missing chain rejects unconditionally
    //   regardless of the record's constraint kinds, because the
    //   evaluator has *no* material to compare and cannot decide safely.
    //
    // The setter can prove identity with the audit token alone; the
    // getter evaluator cannot.
    let chain = ctx.guard_chain.unwrap_or(&[]);

    let mut constraints = Vec::with_capacity(effective.len());
    for wire in &effective {
        match wire {
            GuardConstraintWire::SameUser => {
                constraints.push(GuardConstraint::SameUser);
            }
            GuardConstraintWire::SameShell => {
                let pinned = match pin_ancestor(chain, |name| {
                    ctx.kv_policy.shell_names.iter().any(|s| s.as_str() == name)
                }) {
                    Some(p) => p,
                    None => {
                        return Err(Response::error(
                            ErrorKind::BadRequest,
                            "--require-same-shell: no shell (zsh/bash/fish/sh/nu \
                             or [kv-policy] shell-names) found in setter ancestry",
                        ));
                    }
                };
                constraints.push(GuardConstraint::SameAncestor {
                    declared: DeclaredAncestor::SameShell {
                        shell_name: pinned.name.clone(),
                    },
                    pinned,
                });
            }
            GuardConstraintWire::SameAncestor { name } => {
                let target = name.clone();
                let looks_like_path = target.starts_with('/');
                let pinned = match pin_ancestor(chain, |basename| {
                    if looks_like_path {
                        // Handled below (path-comparison branch).
                        false
                    } else {
                        basename == target
                    }
                }) {
                    Some(p) => Some(p),
                    None if looks_like_path => pin_ancestor_by_path(chain, &target),
                    None => None,
                };
                let pinned = match pinned {
                    Some(p) => p,
                    None => {
                        return Err(Response::error(
                            ErrorKind::BadRequest,
                            format!(
                                "--require-same-ancestor={target}: no matching entry \
                                 in setter ancestry"
                            ),
                        ));
                    }
                };
                constraints.push(GuardConstraint::SameAncestor {
                    declared: DeclaredAncestor::Named { name: target },
                    pinned,
                });
            }
            GuardConstraintWire::Command { name } => {
                // §7: command= is not identity-pinned at set time — it is
                // a name lookup performed against the *getter*'s chain at
                // evaluation. Just carry the declared name.
                constraints.push(GuardConstraint::Command { name: name.clone() });
            }
        }
    }

    Ok(Some(GuardRecord::new(constraints, setter)))
}

/// Walk `chain` (getter-most first, toward launchd) and return the first
/// entry whose basename satisfies `predicate`. Used to resolve
/// `--require-same-shell` and the basename form of
/// `--require-same-ancestor` against the setter's ancestry.
fn pin_ancestor(
    chain: &[GetterProcess],
    predicate: impl Fn(&str) -> bool,
) -> Option<PinnedProcess> {
    chain.iter().find_map(|g| {
        let basename = g.info.name()?;
        if predicate(basename) {
            Some(getter_to_pinned(g))
        } else {
            None
        }
    })
}

/// Path form of `--require-same-ancestor=/full/path`: match a chain
/// entry whose resolved executable path equals the declared path.
fn pin_ancestor_by_path(chain: &[GetterProcess], full_path: &str) -> Option<PinnedProcess> {
    let target = std::path::Path::new(full_path);
    chain.iter().find_map(|g| {
        let path = g.info.path.as_ref()?;
        if path == target {
            Some(getter_to_pinned(g))
        } else {
            None
        }
    })
}

// `denied_kind_label` lives in [`super::guard`] so the authsock SIGN_REQUEST
// path (which grew a symmetric guard gate in a subsequent block) reuses the
// same wire label without duplicating the match. DR-0030 §4's "no setter
// identity crosses back" rule is shared between the two entry points, so the
// label list belongs with the evaluator, not with either adapter.

fn getter_to_pinned(g: &GetterProcess) -> PinnedProcess {
    PinnedProcess {
        pid: g.info.pid,
        start_time: g.info.start_time,
        unique_id: g.unique_id,
        path: g.info.path.clone().unwrap_or_default(),
        name: g.info.name().unwrap_or_default().to_string(),
    }
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
    if let Err(resp) = reject_reserved_namespace_write(&key) {
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
        // The key already passed the wire syntax gate, so a core InvalidKey
        // cannot occur here; reported defensively rather than swallowed.
        Err(DefineError::InvalidKey(e)) => Response::error(ErrorKind::BadRequest, e.to_string()),
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
    // Reserved-namespace confidentiality gate (DR-0018 §4.5), applied *first* —
    // before the process-access gate and the retrieval chain — so a reserved key
    // is refused without ever running its source (no op private-key fetch, no
    // PEM). Symmetric to the write bouncer in `handle_set` / `handle_define`.
    if let Err(resp) = reject_reserved_namespace_read(&key) {
        return resp;
    }

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

    // DR-0030 evaluation order ③: per-entry guard, applied *before* the
    // retrieval chain so a denied requester never triggers regeneration /
    // TouchID / a re-auth prompt (same reason DR-0012 sits ahead of the
    // chain — the denial must be silent and cost-free). When the key has
    // no guard record `guard_of` returns `None` and this whole block
    // short-circuits.
    //
    // On a denial we do *not* surface which entity failed (setter identity
    // never crosses back to the getter side, §4). We record the kind in a
    // stderr line for structured triage; the wire message names the kind
    // but not the pinned identity. The `GuardEvalOutput` on the success
    // path is intentionally discarded here — it exists to feed the
    // approver dialog wire (draft-DR-0031 §4), whose adapter is a
    // subsequent block. Building it in-line still keeps the evaluator's
    // API stable across that later change.
    if matches!(ctx.guard_check_mode, GuardCheckMode::Evaluate)
        && let Some(record) = store.guard_of(&key)
    {
        let chain = match ctx.guard_chain {
            Some(c) => c,
            None => {
                eprintln!(
                    "cache-warden: kv.get denied for {key:?}: guard requires \
                     a requester chain but the peer could not be walked"
                );
                return Response::error(
                    ErrorKind::AuthFailed,
                    "access denied by entry guard (kind: missing-context)",
                );
            }
        };
        match guard_eval::evaluate(chain, ctx.guard_audit_token, record) {
            Ok(_eval) => {
                // Success: fall through to the retrieval chain below.
                // `_eval` (`GuardEvalOutput`) will feed the DR-0031
                // approver dialog wire once that adapter lands; for now
                // it is intentionally dropped so the evaluator's return
                // type stays stable across blocks.
            }
            Err(denied) => {
                let kind = denied_kind_label(denied.kind);
                eprintln!(
                    "cache-warden: kv.get denied for {key:?}: guard \
                     constraint {kind:?} failed"
                );
                return Response::error(
                    ErrorKind::AuthFailed,
                    format!("access denied by entry guard (kind: {kind})"),
                );
            }
        }
    }

    // Fast path: a live (Active) value.
    if store
        .get(&key, ctx.store_cap, ctx.clock)
        .ok()
        .flatten()
        .is_some()
    {
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
            match store.extend_authenticated(
                &key,
                ctx.auth,
                ctx.requester,
                ctx.store_cap,
                ctx.clock,
            ) {
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
            match store.regenerate(
                &key,
                ctx.runner,
                ctx.auth,
                ctx.requester,
                ctx.store_cap,
                ctx.clock,
            ) {
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

    // Opaque path: read the resident value and shape the response inside a
    // scope-limited closure (DR-0028). The raw bytes are base64-encoded within
    // `with_exposed`, so the plaintext never lives in an owned `Vec<u8>` working
    // buffer that would linger un-zeroized in process memory (DR-0007 / issue
    // 2026-06-14-finish-get-working-buffer-zeroize). Only the encoded response
    // value — which must go out on the wire anyway — leaves the closure.
    match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
        // dry-run hides the value, reveal returns it (DR-0015). The bytes are
        // exposed only on the reveal branch.
        Some(secret) => {
            if dry_run {
                Response::get_verified(state)
            } else {
                secret.with_exposed(|bytes| Response::get(encode_b64(bytes)))
            }
        }
        // Should not happen: the caller just confirmed readability. Be defensive.
        None => Response::error(ErrorKind::Internal, "value gone before finish_get"),
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
    match store.get_or_regenerate(
        key,
        ctx.runner,
        ctx.auth,
        ctx.requester,
        ctx.store_cap,
        ctx.clock,
    ) {
        Ok(()) => match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
            Some(_) => finish_get(store, ctx, key, dry_run, "active"),
            None => Response::error(ErrorKind::Internal, "value gone after lazy generation"),
        },
        Err(RegenerateDefOutcome::Undefined) => Response::error(ErrorKind::NotFound, "no such key"),
        // A usable value is resident after all; read it directly.
        Err(RegenerateDefOutcome::ValueResident) => {
            match store.get(key, ctx.store_cap, ctx.clock).ok().flatten() {
                Some(_) => finish_get(store, ctx, key, dry_run, "active"),
                None => Response::error(ErrorKind::Internal, "value resident but unreadable"),
            }
        }
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
    match store.pin_authenticated(
        &key,
        deadline,
        ctx.auth,
        ctx.requester,
        ctx.store_cap,
        ctx.clock,
    ) {
        Ok(()) => Response::pinned(duration_secs),
        Err(PinAuthOutcome::NotFound) => Response::error(ErrorKind::NotFound, "no such key"),
        Err(PinAuthOutcome::HardExpired) => Response::error(
            ErrorKind::HardExpired,
            "entry is hard-expired (destroyed); cannot pin",
        ),
        Err(PinAuthOutcome::AuthFailed(e)) => Response::error(ErrorKind::AuthFailed, e.to_string()),
        Err(PinAuthOutcome::CapMismatch) => {
            Response::error(ErrorKind::Internal, "capability mismatch")
        }
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

    /// A shared default `[kv-policy]` (`default-require-same-user = false`,
    /// built-in shell-names). Tests that need a different one build their
    /// own via [`ctx_with_policy`].
    fn default_policy() -> &'static crate::config::ResolvedKvPolicy {
        static POLICY: std::sync::OnceLock<crate::config::ResolvedKvPolicy> =
            std::sync::OnceLock::new();
        POLICY.get_or_init(|| crate::config::ResolvedKvPolicy {
            default_require_same_user: false,
            shell_names: crate::config::default_shell_names(),
        })
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
        let otp_adapter: &'static crate::daemon::otp_adapter::OtpAdapter = Box::leak(Box::new(
            crate::daemon::otp_adapter::OtpAdapter::new(cap.clone()),
        ));
        HandlerCtx {
            auth,
            runner,
            clock,
            store_cap: cap,
            otp_adapter,
            pid: 1234,
            version: "test",
            socket: "/tmp/test.sock",
            full_disk_access: None,
            requester: None,
            kv_process_policies: empty_policies(),
            guard_chain: None,
            guard_audit_token: None,
            kv_policy: default_policy(),
            guard_check_mode: GuardCheckMode::Evaluate,
        }
    }

    /// Build a HandlerCtx with an explicit DR-0030 guard material and
    /// policy. Used by the guard-integration tests below.
    fn ctx_with_guard<'a, A, R>(
        auth: &'a A,
        runner: &'a R,
        clock: &'a FakeClock,
        cap: &'a cache_warden::Capability,
        chain: Option<&'a [GetterProcess]>,
        token: Option<GetterAuditToken>,
        policy: &'a crate::config::ResolvedKvPolicy,
    ) -> HandlerCtx<'a, A, R, FakeClock> {
        let mut c = ctx(auth, runner, clock, cap);
        c.guard_chain = chain;
        c.guard_audit_token = token;
        c.kv_policy = policy;
        c
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
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
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

    fn err_msg(resp: &Response) -> String {
        match resp {
            Response::Err(e) => e.error.message.clone(),
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

    // ---- DR-0030 guard integration: handle_set / handle_get ----

    /// Build a fake `[kv-policy]` for a given `default-require-same-user`.
    fn policy_with_default_same_user(v: bool) -> crate::config::ResolvedKvPolicy {
        crate::config::ResolvedKvPolicy {
            default_require_same_user: v,
            shell_names: crate::config::default_shell_names(),
        }
    }

    /// Build a getter chain entry from a `ProcessInfo` + optional
    /// `unique_id` (test-only shape mirrors the daemon-side enrichment).
    fn gp(info: ProcessInfo, unique_id: Option<u64>) -> GetterProcess {
        GetterProcess { info, unique_id }
    }

    /// Extract the `guard_applied` list from a Set success response.
    fn set_guard_applied(resp: &Response) -> Vec<String> {
        match resp {
            Response::Ok(ok) => match &ok.payload {
                OkPayload::Set { guard_applied, .. } => guard_applied.clone(),
                other => panic!("expected Set payload, got {other:?}"),
            },
            Response::Err(e) => panic!("expected ok, got error: {e:?}"),
        }
    }

    /// A guarded `kv set` with `SameUser` builds the record and echoes the
    /// applied kinds in the positive ack (`guard_applied`); a subsequent
    /// get from a same-uid peer clears the guard gate. Fixes DR-0030 §7
    /// "setter identity is daemon-observed, not caller-supplied".
    #[test]
    fn set_with_same_user_guard_installs_record_and_acks() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let token = Some(GetterAuditToken {
            euid: 501,
            ruid: 501,
        });
        let policy = policy_with_default_same_user(false);
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            token,
            &policy,
        );
        let req = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"hunter2"),
            },
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
            guard_constraints: vec![GuardConstraintWire::SameUser],
            expected_version: None,
            claim_token: None,
        };
        let resp = handle_request(&mut store, &c, req);
        assert_eq!(set_guard_applied(&resp), vec!["same-user".to_string()]);
        // The core actually got a guard record installed.
        assert!(store.guard_of("default/K").is_some());

        // Same-uid getter passes.
        let get_ok = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&get_ok), b"hunter2");
    }

    /// A same-user-guarded entry denies a get whose peer's euid differs
    /// (fail-closed, DR-0030 §4). The denial does NOT run the retrieval
    /// chain — proven separately below via a definition-only key + a
    /// runner counter.
    #[test]
    fn get_denied_when_same_user_guard_uids_do_not_match() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // Setter had uid 501.
        let setter_chain = vec![gp(proc(100, "zsh"), None)];
        let setter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&setter_chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        let set_req = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"secret"),
            },
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
            guard_constraints: vec![GuardConstraintWire::SameUser],
            expected_version: None,
            claim_token: None,
        };
        assert!(handle_request(&mut store, &setter_ctx, set_req).is_ok());

        // Getter has a different euid.
        let getter_chain = vec![gp(proc(200, "zsh"), None)];
        let getter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&getter_chain),
            Some(GetterAuditToken {
                euid: 502,
                ruid: 502,
            }),
            default_policy(),
        );
        let resp = handle_request(
            &mut store,
            &getter_ctx,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
        assert!(
            err_msg(&resp).contains("same-user"),
            "denial names the failing kind: {:?}",
            err_msg(&resp)
        );
    }

    /// A subsequent set with an empty `guard_constraints` list drops the
    /// previously-installed guard: §5 "the last declaration wins".
    #[test]
    fn empty_set_clears_prior_guard_record() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        // Install a guard.
        assert!(
            handle_request(
                &mut store,
                &c,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"a"),
                    },
                    soft_ttl_secs: Some(SOFT),
                    hard_ttl_secs: Some(HARD),
                    guard_constraints: vec![GuardConstraintWire::SameUser],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );
        assert!(store.guard_of("default/K").is_some());

        // Empty declaration on the next set clears it.
        let resp = handle_request(&mut store, &c, set_static(b"b"));
        assert_eq!(set_guard_applied(&resp), Vec::<String>::new());
        assert!(store.guard_of("default/K").is_none());
    }

    /// `[kv-policy] default-require-same-user = true` promotes an
    /// unguarded set to `SameUser`. The ack surfaces the applied kind
    /// so the client can also observe the implicit upgrade.
    #[test]
    fn empty_set_upgraded_to_same_user_when_config_default_is_true() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let policy = policy_with_default_same_user(true);
        let chain = vec![gp(proc(1, "sh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            &policy,
        );
        let resp = handle_request(&mut store, &c, set_static(b"v"));
        assert_eq!(set_guard_applied(&resp), vec!["same-user".to_string()]);
        assert!(store.guard_of("default/K").is_some());
    }

    /// `--require-same-shell` with no shell in the setter's chain rejects
    /// the set (§7 "pin 対象が存在しない宣言は成立しない"). The value
    /// must not be stored.
    #[test]
    fn set_with_same_shell_but_no_shell_in_chain_is_rejected() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "git"), None), gp(proc(1, "launchd"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: encode_b64(b"v"),
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                guard_constraints: vec![GuardConstraintWire::SameShell],
                expected_version: None,
                claim_token: None,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        assert!(!store.has_value("default/K"), "value must not have landed");
    }

    /// `SameUser` declared but the daemon has no peer audit token
    /// (Linux / getsockopt failure): fail-closed reject the set, don't
    /// silently save an unguarded value.
    #[test]
    fn set_with_guard_but_no_audit_token_is_rejected() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            None, // audit token unavailable
            default_policy(),
        );
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: encode_b64(b"v"),
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                guard_constraints: vec![GuardConstraintWire::SameUser],
                expected_version: None,
                claim_token: None,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
        assert!(!store.has_value("default/K"));
    }

    /// A get against a guarded key with no requester chain fails-closed
    /// without touching the retrieval chain (proven by the value never
    /// being read: the response is AuthFailed, not the value).
    #[test]
    fn get_denied_when_guarded_and_requester_chain_missing() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // Install a guarded value.
        let setter_chain = vec![gp(proc(100, "zsh"), None)];
        let setter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&setter_chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        assert!(
            handle_request(
                &mut store,
                &setter_ctx,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                    guard_constraints: vec![GuardConstraintWire::SameUser],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );

        // Getter has NO chain.
        let getter_ctx = ctx(&AllowAll, &runner, &clock, &cap); // guard_chain: None
        let resp = handle_request(
            &mut store,
            &getter_ctx,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    /// A guarded, definition-backed key whose guard denies the getter
    /// must NOT run the source command (the whole point of gating the
    /// guard before the retrieval chain — no TouchID / no regeneration
    /// on a denied requester).
    #[test]
    fn guarded_definition_denial_does_not_run_the_source() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"regen");
        // Setter registers a command definition then a guarded set
        // (guard sits on the value the set produced).
        let setter_chain = vec![gp(proc(100, "zsh"), None)];
        let setter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&setter_chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        assert!(
            handle_request(
                &mut store,
                &setter_ctx,
                define_cmd("default/K", &["echo", "x"])
            )
            .is_ok()
        );
        assert!(
            handle_request(
                &mut store,
                &setter_ctx,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                    guard_constraints: vec![GuardConstraintWire::SameUser],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );
        // The set may have called `set` on the value which does not run
        // the runner; the runner count so far is 0.
        assert_eq!(runner.runs(), 0);
        // A denied getter must not trigger regeneration.
        let getter_chain = vec![gp(proc(200, "zsh"), None)];
        let getter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&getter_chain),
            Some(GetterAuditToken {
                euid: 999,
                ruid: 999,
            }),
            default_policy(),
        );
        let resp = handle_request(
            &mut store,
            &getter_ctx,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
        assert_eq!(runner.runs(), 0, "denied guard must not run source");
    }

    /// `kv list` surfaces a `guard_summary` for guarded entries — with a
    /// `(weak)` marker on `command=` entries and strong-first ordering
    /// (Task F requirement).
    #[test]
    fn kv_list_surfaces_guard_summary_with_weak_marker() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        // Both a strong (same-user) and a weak (command=) constraint.
        assert!(
            handle_request(
                &mut store,
                &c,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                    guard_constraints: vec![
                        GuardConstraintWire::Command { name: "git".into() },
                        GuardConstraintWire::SameUser,
                    ],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );
        let resp = handle_request(&mut store, &c, Request::KvList);
        let entries = match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::List { entries, .. } => entries,
                other => panic!("expected List, got {other:?}"),
            },
            other => panic!("expected List ok, got {other:?}"),
        };
        let e = entries
            .into_iter()
            .find(|e| e.name == "default/K")
            .expect("entry must be present");
        let summary = e.guard_summary.expect("guarded entry must carry summary");
        // Strong first, weak last; the weak `command` marker is present.
        assert_eq!(summary[0], "same-user", "strong-first: {summary:?}");
        assert!(summary.last().unwrap().contains("(weak)"), "{summary:?}");
        assert!(summary.iter().any(|s| s.contains("command (git)")));
    }

    // ---- MEDIUM-4: same-shell / same-ancestor E2E allow + deny ----
    //
    // The DR-0030 §5/§7 pin construction path: a `--require-same-shell`
    // (or `--require-same-ancestor=NAME`) set must extract a pinnable
    // process from the setter's chain, install the record with that
    // pinned identity, and let the same-entity getter pass while
    // denying a chain that has the same basename but a different
    // pid+start_time (= a *different* process instance). The tests here
    // exercise the pin construction on set and the pin-based
    // discrimination on get through `handle_request` end-to-end.

    /// same-shell allow: the same chain (same pid + start_time) passes.
    #[test]
    fn same_shell_guarded_set_then_get_from_same_chain_passes() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // Setter chain has an identifiable zsh at pid=100 / start=100s.
        let chain = vec![gp(proc(100, "zsh"), None)];
        let token = Some(GetterAuditToken {
            euid: 501,
            ruid: 501,
        });
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            token,
            default_policy(),
        );
        let set = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: encode_b64(b"v"),
                },
                soft_ttl_secs: Some(SOFT),
                hard_ttl_secs: Some(HARD),
                guard_constraints: vec![GuardConstraintWire::SameShell],
                expected_version: None,
                claim_token: None,
            },
        );
        // The set succeeds and the ack names the applied kind.
        assert_eq!(set_guard_applied(&set), vec!["same-shell".to_string()]);
        assert!(store.guard_of("default/K").is_some(), "guard installed");

        // Same chain (identical pid + start_time) reads successfully —
        // the pin extracted from setter matches the getter chain entry.
        let get_resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&get_resp), b"v");
    }

    /// same-shell deny: a chain whose zsh has a *different* start_time
    /// (same basename, but a *different* process instance — the pid
    /// reuse / instance-mismatch case from DR-0030 §Security) is
    /// denied. This proves the pin discriminates on pid + start_time,
    /// not just basename.
    #[test]
    fn same_shell_guarded_set_then_get_from_different_start_time_is_denied() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // Setter chain: zsh at pid=100 / start=100s (from `proc()`).
        let setter_chain = vec![gp(proc(100, "zsh"), None)];
        let token = Some(GetterAuditToken {
            euid: 501,
            ruid: 501,
        });
        let setter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&setter_chain),
            token,
            default_policy(),
        );
        assert!(
            handle_request(
                &mut store,
                &setter_ctx,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: Some(SOFT),
                    hard_ttl_secs: Some(HARD),
                    guard_constraints: vec![GuardConstraintWire::SameShell],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );

        // Getter chain: still a "zsh" at pid=100 but a *different*
        // start_time — a distinct process instance under pid reuse.
        let mut different = proc(100, "zsh");
        different.start_time = Some(Duration::from_secs(9999));
        let getter_chain = vec![gp(different, None)];
        let getter_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&getter_chain),
            token,
            default_policy(),
        );
        let resp = handle_request(
            &mut store,
            &getter_ctx,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
        assert!(
            err_msg(&resp).contains("same-ancestor"),
            "denial names the same-ancestor kind: {:?}",
            err_msg(&resp)
        );
    }

    /// --require-same-ancestor=/absolute/path form: pin resolution goes
    /// through `pin_ancestor_by_path` (not the basename branch), and a
    /// get from the same chain passes.
    #[test]
    fn same_ancestor_by_absolute_path_set_and_get_end_to_end() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        // `proc(200, "git")` places the executable at `/usr/bin/git`.
        let chain = vec![gp(proc(200, "git"), None), gp(proc(50, "zsh"), None)];
        let token = Some(GetterAuditToken {
            euid: 501,
            ruid: 501,
        });
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            token,
            default_policy(),
        );
        // A path with a leading `/` takes the pin_ancestor_by_path branch.
        let set = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: encode_b64(b"v"),
                },
                soft_ttl_secs: Some(SOFT),
                hard_ttl_secs: Some(HARD),
                guard_constraints: vec![GuardConstraintWire::SameAncestor {
                    name: "/usr/bin/git".to_string(),
                }],
                expected_version: None,
                claim_token: None,
            },
        );
        assert_eq!(set_guard_applied(&set), vec!["same-ancestor".to_string()]);
        assert!(store.guard_of("default/K").is_some());

        // Same chain: the getter finds the same entity → allow.
        let get_resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&get_resp), b"v");

        // A chain where the same basename is at a *different* absolute
        // path (`/opt/bin/git`) does NOT satisfy the pinned entity —
        // pid + start_time comparison rejects. This pins the path branch
        // as distinct from the basename branch.
        let other = ProcessInfo {
            pid: 900,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/opt/bin/git")),
            start_time: Some(Duration::from_secs(900)),
        };
        let other_chain = vec![gp(other, None), gp(proc(50, "zsh"), None)];
        let other_ctx = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&other_chain),
            token,
            default_policy(),
        );
        let deny = handle_request(
            &mut store,
            &other_ctx,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&deny), ErrorKind::AuthFailed);
    }

    // ---- MEDIUM-4 #4: set failures preserve the prior guard ----
    //
    // A `kv.set` that fails on wire-level validation (TTL out of range,
    // malformed base64) must not touch the store's guard record: the
    // prior guard on the same key stays intact. Otherwise a failed
    // set-with-bad-input could be a silent way to clear a guard.

    /// Bad TTL rejected: guard from a prior guarded set stays intact.
    #[test]
    fn set_with_bad_ttl_keeps_prior_guard_intact() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        // Install a guard first.
        assert!(
            handle_request(
                &mut store,
                &c,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"first"),
                    },
                    soft_ttl_secs: Some(SOFT),
                    hard_ttl_secs: Some(HARD),
                    guard_constraints: vec![GuardConstraintWire::SameUser],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );
        let before = store
            .guard_of("default/K")
            .cloned()
            .expect("guard installed by first set");

        // Second set: soft > hard is a Ttl::new BadRequest — but this
        // is caught *after* plan_guard_record. The guard planning path
        // must not have side effects on the store, and the failed set
        // must not clear the prior record either.
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: encode_b64(b"second"),
                },
                soft_ttl_secs: Some(1000),
                hard_ttl_secs: Some(1),
                guard_constraints: Vec::new(),
                expected_version: None,
                claim_token: None,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        let after = store
            .guard_of("default/K")
            .cloned()
            .expect("guard must survive failed set");
        assert_eq!(before, after, "prior guard record preserved verbatim");
    }

    /// Bad base64 rejected: guard from a prior guarded set stays intact.
    #[test]
    fn set_with_bad_base64_keeps_prior_guard_intact() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let chain = vec![gp(proc(100, "zsh"), None)];
        let c = ctx_with_guard(
            &AllowAll,
            &runner,
            &clock,
            &cap,
            Some(&chain),
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            default_policy(),
        );
        assert!(
            handle_request(
                &mut store,
                &c,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"first"),
                    },
                    soft_ttl_secs: Some(SOFT),
                    hard_ttl_secs: Some(HARD),
                    guard_constraints: vec![GuardConstraintWire::SameUser],
                    expected_version: None,
                    claim_token: None,
                },
            )
            .is_ok()
        );
        let before = store
            .guard_of("default/K")
            .cloned()
            .expect("guard installed");

        let resp = handle_request(
            &mut store,
            &c,
            Request::KvSet {
                key: "default/K".into(),
                source: SetSource::Static {
                    value_b64: "not!base64!".into(),
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                guard_constraints: Vec::new(),
                expected_version: None,
                claim_token: None,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        let after = store
            .guard_of("default/K")
            .cloned()
            .expect("guard must survive failed set");
        assert_eq!(before, after);
    }

    /// The positive ack is present when a guard was applied and empty
    /// (`Vec::new()`) when it was not: the shape used by the client to
    /// detect a mixed-version silent no-op (an old daemon replies with
    /// no `guard_applied` field ⇒ decodes to empty via
    /// `#[serde(default)]`; a new daemon with a guarded set decodes to
    /// a non-empty list).
    #[test]
    fn set_positive_ack_shape_distinguishes_guarded_from_unguarded() {
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        // Unguarded: guard_applied is empty (skip_serializing_if strips
        // it from the wire, matching the old-daemon shape).
        let resp = handle_request(&mut store, &c, set_static(b"v1"));
        assert!(set_guard_applied(&resp).is_empty());
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains("guard_applied"),
            "unguarded ack must omit guard_applied on the wire: {line}"
        );
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

    // ---- reserved-namespace bouncer (DR-0018 §4.5) ----

    #[test]
    fn set_into_reserved_authsock_namespace_is_bad_request() {
        // A wire `kv.set` targeting the reserved `authsock` namespace is refused:
        // that space holds daemon-internal op keys, never user writes. The store
        // must not gain the key.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let req = Request::KvSet {
            key: "authsock/op_itemABC".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
        assert!(
            !store.has_value("authsock/op_itemABC"),
            "reserved write must not land"
        );
    }

    #[test]
    fn define_into_reserved_authsock_namespace_is_bad_request() {
        // The same bouncer applies to `kv.define`: a user cannot register a
        // definition inside the reserved namespace (DR-0018 §4.5).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let resp = handle_request(
            &mut store,
            &c,
            define_cmd("authsock/op_itemABC", &["echo", "x"]),
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        assert!(
            !store.is_defined("authsock/op_itemABC"),
            "reserved define must not land"
        );
    }

    #[test]
    fn set_non_reserved_namespace_still_works() {
        // The bouncer is namespace-specific: an ordinary namespace is unaffected
        // (a key merely *containing* the reserved word as a KEY is fine too).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        // `default/authsock` = namespace `default`, key `authsock` — allowed.
        let req = Request::KvSet {
            key: "default/authsock".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
        };
        assert!(handle_request(&mut store, &c, req).is_ok());
        assert!(store.has_value("default/authsock"));
    }

    #[test]
    fn wire_get_into_reserved_authsock_namespace_is_bad_request() {
        // Confidentiality symmetry to the write bouncer (DR-0018 §4.5): the
        // `authsock` namespace holds op private-key PEM the daemon composes and
        // serves only over the SSH agent SIGN path. Even a value already resident
        // there (seeded directly here, as the daemon's own op composition does)
        // must never be revealed over a wire `kv.get`. The refusal is an explicit
        // BadRequest matching the write bouncer's shape (interface symmetry over
        // existence-hiding), and it names the reservation so the caller sees why.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let ttl = Ttl::new(
            Some(Duration::from_secs(SOFT)),
            Some(Duration::from_secs(HARD)),
        )
        .unwrap();
        store
            .set(
                "authsock/op_itemABC",
                ValueSource::Static,
                SecretBytes::new(b"PEM".to_vec()),
                ttl,
                &cap,
                &clock,
            )
            .unwrap();
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "authsock/op_itemABC".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        let msg = err_msg(&resp);
        assert!(msg.contains("reserved"), "must name the reservation: {msg}");
        assert!(msg.contains("authsock"), "must name the namespace: {msg}");
    }

    #[test]
    fn wire_get_reserved_namespace_does_not_run_the_source() {
        // The gate sits *before* the retrieval chain, so a definition-backed
        // reserved key is refused without ever running its source command — the op
        // private-key fetch (and thus the PEM) never happens. Proven by the
        // runner's run count staying at zero. The definition is registered
        // directly (the daemon's internal path), bypassing the write bouncer a
        // wire `kv.define` would hit.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"PEM");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let ttl = Ttl::new(None, None).unwrap();
        store
            .define(
                "authsock/op_itemABC",
                ValueSource::command(vec!["echo".into(), "PEM".into()]),
                ttl,
            )
            .unwrap();
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "authsock/op_itemABC".into(),
                dry_run: false,
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
        assert_eq!(runner.runs(), 0, "reserved get must not run the source");
    }

    #[test]
    fn wire_get_non_reserved_namespace_still_reads() {
        // Namespace-specific: the reserved *word* as an ordinary KEY is fine.
        // `default/authsock` = namespace `default`, key `authsock` — reads as
        // usual, confirming the gate keys off the namespace, not the substring.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let ttl = Ttl::new(
            Some(Duration::from_secs(SOFT)),
            Some(Duration::from_secs(HARD)),
        )
        .unwrap();
        store
            .set(
                "default/authsock",
                ValueSource::Static,
                SecretBytes::new(b"ok".to_vec()),
                ttl,
                &cap,
                &clock,
            )
            .unwrap();
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "default/authsock".into(),
                dry_run: false,
            },
        );
        assert_eq!(get_value(&resp), b"ok");
    }

    #[test]
    fn wire_del_into_reserved_authsock_namespace_still_works() {
        // Availability/rotation axis — distinct from confidentiality. `kv del` is
        // *not* gated on the reserved namespace: dropping a resident op key is how
        // a rotation clears the stale entry, and del reveals no value. A seeded
        // reserved value is removed successfully. This is the deliberate asymmetry
        // with the read/write bouncers (get/set/define blocked, del allowed).
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let ttl = Ttl::new(
            Some(Duration::from_secs(SOFT)),
            Some(Duration::from_secs(HARD)),
        )
        .unwrap();
        store
            .set(
                "authsock/op_itemABC",
                ValueSource::Static,
                SecretBytes::new(b"PEM".to_vec()),
                ttl,
                &cap,
                &clock,
            )
            .unwrap();
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvDel {
                key: "authsock/op_itemABC".into(),
                with_define: false,
            },
        );
        assert!(resp.is_ok(), "del on reserved ns must succeed (rotation)");
        assert!(
            !store.has_value("authsock/op_itemABC"),
            "reserved value must be removed by del"
        );
    }

    #[test]
    fn wire_list_still_names_reserved_keys() {
        // `kv.list` is value-free (key names + metadata only, DR-0022 §3), so it is
        // *not* gated: a reserved key's existence is already discoverable and no
        // secret leaks. Behavior is unchanged — the reserved key name still appears
        // in the listing.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let ttl = Ttl::new(
            Some(Duration::from_secs(SOFT)),
            Some(Duration::from_secs(HARD)),
        )
        .unwrap();
        store
            .set(
                "authsock/op_itemABC",
                ValueSource::Static,
                SecretBytes::new(b"PEM".to_vec()),
                ttl,
                &cap,
                &clock,
            )
            .unwrap();
        let resp = handle_request(&mut store, &c, Request::KvList);
        let keys = match &resp {
            Response::Ok(ok) => match &ok.payload {
                OkPayload::List { keys, .. } => keys.clone(),
                other => panic!("expected list payload, got {other:?}"),
            },
            Response::Err(e) => panic!("expected list ok, got error: {e:?}"),
        };
        assert!(
            keys.iter().any(|k| k == "authsock/op_itemABC"),
            "list must still name the reserved key (value-free): {keys:?}"
        );
    }

    #[test]
    fn set_non_ns_key_is_bad_request() {
        // The wire semantic gate still requires a full NS/KEY (DR-0017 §2): a bare
        // KEY on the wire is refused even though the core would accept it.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        let req = Request::KvSet {
            key: "BARE".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
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
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
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
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
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
                    guard_constraints: Vec::new(),
                    expected_version: None,
                    claim_token: None,
                },
            );
        }
        let resp = handle_request(&mut store, &c, Request::KvList);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::List { keys, entries } => {
                    assert_eq!(keys, vec!["default/a", "default/b", "default/c"]);
                    // The metadata array is parallel and same length (DR-0009 minor).
                    assert_eq!(entries.len(), keys.len());
                    assert!(
                        entries.iter().zip(keys.iter()).all(|(e, k)| &e.name == k),
                        "entries.name must align with keys"
                    );
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
        let otp_adapter: &'static crate::daemon::otp_adapter::OtpAdapter = Box::leak(Box::new(
            crate::daemon::otp_adapter::OtpAdapter::new(cap.clone()),
        ));
        HandlerCtx {
            auth,
            runner,
            clock,
            store_cap: cap,
            otp_adapter,
            pid: 1234,
            version: "test",
            socket: "/tmp/test.sock",
            full_disk_access: None,
            requester,
            kv_process_policies: policies,
            guard_chain: None,
            guard_audit_token: None,
            kv_policy: default_policy(),
            guard_check_mode: GuardCheckMode::Evaluate,
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

    // ---- DR-0022 §3: kv.list / status carry backoff_until_secs ----

    /// Build a store + cap with a non-zero failure-backoff window so the
    /// regenerate path will actually record a `failure_backoffs` entry.
    fn store_with_backoff(d: Duration) -> (Store, cache_warden::Capability) {
        let bundle = Store::builder().failure_backoff(d).build();
        (bundle.store, bundle.control_cap)
    }

    /// Trigger a fetch failure on `key` so the store records an active backoff
    /// window. Returns once the runner has been invoked once and failed.
    fn arm_backoff(
        store: &mut Store,
        c: &HandlerCtx<'_, impl Authenticator + ?Sized, impl SourceRunner, FakeClock>,
        key: &str,
    ) {
        // Register a definition whose runner will fail, then trigger a get so
        // get_or_regenerate runs it and records the backoff record on failure.
        let _ = handle_request(store, c, define_cmd(key, &["fail"]));
        let _ = handle_request(
            store,
            c,
            Request::KvGet {
                key: key.into(),
                dry_run: false,
            },
        );
    }

    #[test]
    fn status_reports_backoff_until_secs_when_active() {
        let clock = FakeClock::new();
        let (mut store, cap) = store_with_backoff(Duration::from_secs(5));
        let runner = FailingRunner;
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        arm_backoff(&mut store, &c, "default/K");

        let resp = handle_request(&mut store, &c, Request::Status);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Status { entries, .. } => {
                    let e = entries.into_iter().find(|e| e.name == "default/K").unwrap();
                    assert!(
                        e.backoff_until_secs.is_some_and(|s| s > 0),
                        "status must surface an active backoff window: {:?}",
                        e.backoff_until_secs
                    );
                }
                _ => panic!("not status"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn list_carries_parallel_entries_with_backoff_until_secs() {
        // DR-0022 §3 / DR-0009 minor extension: `kv.list` returns `keys` AND a
        // parallel `entries` array carrying value-free metadata so a client can
        // render backoff / pin / state hints next to each name.
        let clock = FakeClock::new();
        let (mut store, cap) = store_with_backoff(Duration::from_secs(5));
        let runner = FailingRunner;
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        arm_backoff(&mut store, &c, "default/K");

        let resp = handle_request(&mut store, &c, Request::KvList);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::List { keys, entries } => {
                    assert_eq!(keys, vec!["default/K".to_string()]);
                    assert_eq!(entries.len(), 1, "entries must be parallel to keys");
                    assert_eq!(entries[0].name, "default/K");
                    assert!(
                        entries[0].backoff_until_secs.is_some_and(|s| s > 0),
                        "kv.list entry must carry an active backoff: {:?}",
                        entries[0].backoff_until_secs
                    );
                }
                _ => panic!("not list"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn list_entries_have_none_backoff_when_inactive() {
        // No backoff window has been armed: the metadata slot is None, but the
        // entries array is still parallel + same length as keys.
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock, &cap);
        handle_request(&mut store, &c, set_static(b"v"));

        let resp = handle_request(&mut store, &c, Request::KvList);
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::List { keys, entries } => {
                    assert_eq!(keys.len(), 1);
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].name, keys[0]);
                    assert_eq!(entries[0].backoff_until_secs, None);
                }
                _ => panic!("not list"),
            },
            _ => panic!("expected ok"),
        }
    }

    // ---- DR-0034 §4: CAS + refresh claims ----
    //
    // The daemon owns the *policy* here (the core only stores the version and
    // the claim), so these drive `handle_request` end to end rather than
    // poking the store.
    mod refresh_arbitration {
        use super::*;

        fn set_req(key: &str, value: &[u8], expected: Option<u64>, token: Option<&str>) -> Request {
            Request::KvSet {
                key: key.into(),
                source: SetSource::Static {
                    value_b64: encode_b64(value),
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                guard_constraints: Vec::new(),
                expected_version: expected,
                claim_token: token.map(str::to_string),
            }
        }

        fn set_version(resp: &Response) -> Option<u64> {
            match resp {
                Response::Ok(ok) => match &ok.payload {
                    OkPayload::Set { version, .. } => *version,
                    other => panic!("expected a Set ack, got {other:?}"),
                },
                other => panic!("expected ok, got {other:?}"),
            }
        }

        fn err_kind(resp: &Response) -> ErrorKind {
            match resp {
                Response::Err(e) => e.error.kind,
                other => panic!("expected an error, got {other:?}"),
            }
        }

        fn claim_token_of(resp: &Response) -> String {
            match resp {
                Response::Ok(ok) => match &ok.payload {
                    OkPayload::Claimed { claim_token, .. } => claim_token.clone(),
                    other => panic!("expected a Claimed ack, got {other:?}"),
                },
                other => panic!("expected ok, got {other:?}"),
            }
        }

        /// Every write advances the version, including one that asked for no
        /// compare-and-swap. A write invisible to the counter would be
        /// invisible to the CAS callers racing it.
        #[test]
        fn an_unconditional_set_still_advances_the_version() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);

            let r = handle_request(&mut store, &c, set_req("default/K", b"a", None, None));
            assert_eq!(set_version(&r), Some(1));
            let r = handle_request(&mut store, &c, set_req("default/K", b"b", None, None));
            assert_eq!(set_version(&r), Some(2));
        }

        #[test]
        fn a_create_expecting_version_zero_succeeds_then_collides() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);

            let r = handle_request(&mut store, &c, set_req("default/K", b"a", Some(0), None));
            assert_eq!(set_version(&r), Some(1));

            // A second create against "must not exist" must lose.
            let r = handle_request(&mut store, &c, set_req("default/K", b"b", Some(0), None));
            assert_eq!(err_kind(&r), ErrorKind::CasMismatch);
        }

        /// The race the version exists for: two callers write from the same
        /// read, one wins, the loser is told where to retry from.
        #[test]
        fn only_one_of_two_writers_from_the_same_read_wins() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v1", None, None));

            let winner = handle_request(&mut store, &c, set_req("default/K", b"A", Some(1), None));
            let loser = handle_request(&mut store, &c, set_req("default/K", b"B", Some(1), None));

            assert_eq!(set_version(&winner), Some(2));
            match &loser {
                Response::Err(e) => {
                    assert_eq!(e.error.kind, ErrorKind::CasMismatch);
                    assert_eq!(
                        e.error.current_version,
                        Some(2),
                        "the loser must learn the version to retry from"
                    );
                }
                other => panic!("expected CasMismatch, got {other:?}"),
            }
        }

        /// A refused compare-and-swap must not have written. Checking the
        /// version rather than the value catches a partial apply too.
        #[test]
        fn a_refused_compare_and_swap_changes_nothing() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v1", None, None));

            let r = handle_request(
                &mut store,
                &c,
                set_req("default/K", b"loser", Some(99), None),
            );
            assert_eq!(err_kind(&r), ErrorKind::CasMismatch);
            assert_eq!(store.version_of("default/K"), 1, "version untouched");
        }

        #[test]
        fn claiming_reports_the_current_version_without_advancing_it() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));

            let r = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );
            assert!(!claim_token_of(&r).is_empty());
            assert_eq!(
                store.version_of("default/K"),
                1,
                "a claim alters no value, so it must not advance the version"
            );
        }

        #[test]
        fn a_second_claim_is_refused_while_the_first_holds() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            let claim = Request::KvClaim {
                key: "default/K".into(),
                expected_version: 1,
                duration_secs: 300,
            };
            handle_request(&mut store, &c, claim.clone());

            let r = handle_request(&mut store, &c, claim);
            match &r {
                Response::Err(e) => {
                    assert_eq!(e.error.kind, ErrorKind::AlreadyClaimed);
                    assert!(e.error.claim_expires_in_secs.is_some());
                }
                other => panic!("expected AlreadyClaimed, got {other:?}"),
            }
        }

        /// A zero-second claim is born lapsed, which is how the lapsed path is
        /// reached without waiting for wall-clock time.
        #[test]
        fn a_lapsed_claim_can_be_taken_over_and_does_not_fence_writes() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            let lapsed = Request::KvClaim {
                key: "default/K".into(),
                expected_version: 1,
                duration_secs: 0,
            };
            handle_request(&mut store, &c, lapsed);

            // Nobody holds it, so an untokened write goes through…
            let r = handle_request(&mut store, &c, set_req("default/K", b"late", Some(1), None));
            assert_eq!(set_version(&r), Some(2));
            // …and a fresh claim can be taken.
            let r = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 2,
                    duration_secs: 300,
                },
            );
            assert!(!claim_token_of(&r).is_empty());
        }

        #[test]
        fn a_write_during_an_active_claim_needs_that_claims_token() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            let held = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );
            let token = claim_token_of(&held);

            // No token at all.
            let r = handle_request(&mut store, &c, set_req("default/K", b"x", Some(1), None));
            assert_eq!(err_kind(&r), ErrorKind::ClaimTokenMismatch);
            // Someone else's token.
            let r = handle_request(
                &mut store,
                &c,
                set_req("default/K", b"x", Some(1), Some("AAAAAAAAAAAAAAAAAAAAAA")),
            );
            assert_eq!(err_kind(&r), ErrorKind::ClaimTokenMismatch);
            // The holder's token.
            let r = handle_request(
                &mut store,
                &c,
                set_req("default/K", b"fresh", Some(1), Some(&token)),
            );
            assert_eq!(set_version(&r), Some(2));
            assert!(
                store.refresh_claim_of("default/K").is_none(),
                "a completed write ends the refresh its claim was held for"
            );
        }

        #[test]
        fn unclaiming_frees_the_key_and_rejects_a_stale_token() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            let held = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );
            let token = claim_token_of(&held);

            let r = handle_request(
                &mut store,
                &c,
                Request::KvUnclaim {
                    key: "default/K".into(),
                    claim_token: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                },
            );
            assert_eq!(err_kind(&r), ErrorKind::ClaimTokenMismatch);

            let r = handle_request(
                &mut store,
                &c,
                Request::KvUnclaim {
                    key: "default/K".into(),
                    claim_token: token.clone(),
                },
            );
            assert!(matches!(r, Response::Ok(_)));
            assert!(store.refresh_claim_of("default/K").is_none());

            // Releasing again is a no-op, so a retry after a crash is not
            // punished.
            let r = handle_request(
                &mut store,
                &c,
                Request::KvUnclaim {
                    key: "default/K".into(),
                    claim_token: token,
                },
            );
            assert!(matches!(r, Response::Ok(_)));
        }

        /// The expiry is what reclaims a key from a caller that died
        /// mid-refresh, so a duration long enough to defeat that reclamation
        /// defeats the mechanism. Zero is refused for the opposite reason: a
        /// claim born lapsed grants nothing while looking like it did.
        #[test]
        fn an_out_of_range_claim_duration_is_refused() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));

            for bad in [0, MAX_CLAIM_SECS + 1, u64::MAX] {
                let r = handle_request(
                    &mut store,
                    &c,
                    Request::KvClaim {
                        key: "default/K".into(),
                        expected_version: 1,
                        duration_secs: bad,
                    },
                );
                assert_eq!(err_kind(&r), ErrorKind::BadRequest, "duration {bad}");
                assert!(
                    store.refresh_claim_of("default/K").is_none(),
                    "a refused claim must not be recorded"
                );
            }

            // The boundary itself is allowed.
            let r = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: MAX_CLAIM_SECS,
                },
            );
            assert!(!claim_token_of(&r).is_empty());
        }

        /// A malformed token must be refused as such rather than reaching a
        /// comparison it could never have won — and must never be treated as
        /// a match.
        #[test]
        fn a_malformed_claim_token_never_passes_the_fence() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );

            for bad in ["", "short", "!!!!!!!!!!!!!!!!!!!!!!", &"A".repeat(64)] {
                let r = handle_request(
                    &mut store,
                    &c,
                    set_req("default/K", b"x", Some(1), Some(bad)),
                );
                assert_eq!(err_kind(&r), ErrorKind::ClaimTokenMismatch, "token {bad:?}");
            }
        }

        /// The two refusals share a wire kind but must not share a message:
        /// "bring a token" and "your token is stale" call for different next
        /// steps.
        #[test]
        fn a_missing_token_and_a_wrong_token_are_explained_differently() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );

            let msg = |resp: &Response| match resp {
                Response::Err(e) => e.error.message.clone(),
                other => panic!("expected an error, got {other:?}"),
            };
            let absent = msg(&handle_request(
                &mut store,
                &c,
                set_req("default/K", b"x", Some(1), None),
            ));
            let wrong = msg(&handle_request(
                &mut store,
                &c,
                set_req("default/K", b"x", Some(1), Some("AAAAAAAAAAAAAAAAAAAAAA")),
            ));
            assert_ne!(absent, wrong);
            assert!(absent.contains("wait"), "{absent}");
            assert!(wrong.contains("took over"), "{wrong}");
        }

        #[test]
        fn claiming_a_key_with_no_value_is_refused() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            let r = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/NOPE".into(),
                    expected_version: 0,
                    duration_secs: 60,
                },
            );
            assert_eq!(err_kind(&r), ErrorKind::NotFound);
        }

        #[test]
        fn claiming_from_a_stale_read_is_refused() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"a", None, None));
            handle_request(&mut store, &c, set_req("default/K", b"b", None, None));

            let r = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 60,
                },
            );
            assert_eq!(err_kind(&r), ErrorKind::CasMismatch);
        }

        /// `status` reports the version and remaining claim time, and never
        /// the token — anyone who can reach the socket can read this reply.
        #[test]
        fn status_reports_version_and_claim_but_never_the_token() {
            let clock = FakeClock::new();
            let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
            let runner = CountingRunner::new(b"x");
            let c = ctx(&AllowAll, &runner, &clock, &cap);
            handle_request(&mut store, &c, set_req("default/K", b"v", None, None));
            let held = handle_request(
                &mut store,
                &c,
                Request::KvClaim {
                    key: "default/K".into(),
                    expected_version: 1,
                    duration_secs: 300,
                },
            );
            let token = claim_token_of(&held);

            let resp = handle_request(&mut store, &c, Request::Status);
            let line = serde_json::to_string(&resp).unwrap();
            assert!(line.contains(r#""version":1"#), "{line}");
            assert!(line.contains("claim_expires_in_secs"), "{line}");
            assert!(
                !line.contains(&token),
                "the claim token must never appear in a status reply"
            );
        }
    }
}
