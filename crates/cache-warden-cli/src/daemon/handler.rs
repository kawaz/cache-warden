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
    Authenticator, Clock, DefineError, EntryState, ExtendAuthOutcome, PinAuthOutcome, ProcessInfo,
    RegenerateDefOutcome, RegenerateOutcome, SecretBytes, SourceRunner, Store, Ttl, ValueSource,
};

use crate::protocol::wire::{EntryInfo, ErrorKind, Request, Response, SetSource};
use crate::protocol::{decode_b64, encode_b64};

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
    /// Daemon process id (for `status`).
    pub pid: u32,
    /// Daemon version string (for `status`).
    pub version: &'a str,
    /// Control socket path (for `status`).
    pub socket: &'a str,
    /// The requesting peer's process ancestry chain, or `None` when it could
    /// not be determined. Forwarded into the core auth context (DR-0006/0008:
    /// carried for audit, not interpreted as policy yet).
    pub requester: Option<&'a [ProcessInfo]>,
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
                store.delete_with_definition(&key)
            } else {
                store.delete(&key)
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
            argv,
            soft_ttl_secs,
            hard_ttl_secs,
        } => handle_define(store, key, argv, soft_ttl_secs, hard_ttl_secs),
        Request::KvGet { key } => handle_get(store, ctx, key),
        Request::KvPin { key, duration_secs } => handle_pin(store, ctx, key, duration_secs),
        Request::KvUnpin { key } => {
            if store.unpin(&key) {
                Response::unpinned(true)
            } else {
                Response::error(ErrorKind::NotFound, "no such key")
            }
        }
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
        entries.push(EntryInfo {
            name,
            state,
            regenerable,
            defined,
            has_value,
            pin_remaining_secs,
        });
    }
    Response::status(
        ctx.pid,
        ctx.version.to_string(),
        ctx.socket.to_string(),
        entries,
    )
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

    store.set(
        key,
        ValueSource::Static,
        SecretBytes::new(bytes),
        ttl,
        ctx.clock,
    );
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
    argv: Vec<String>,
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
) -> Response {
    if argv.is_empty() {
        return Response::error(ErrorKind::BadRequest, "command argv must not be empty");
    }
    let ttl = match Ttl::new(
        soft_ttl_secs.map(std::time::Duration::from_secs),
        hard_ttl_secs.map(std::time::Duration::from_secs),
    ) {
        Ok(t) => t,
        Err(e) => return Response::error(ErrorKind::BadRequest, e.to_string()),
    };

    match store.define(key, ValueSource::command(argv), ttl) {
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

fn handle_get<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>, key: String) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    // Fast path: a live (Active) value.
    if let Some(secret) = store.get(&key, ctx.clock) {
        return Response::get(encode_b64(secret.expose_secret()));
    }

    // Not directly readable. Decide why and try to recover.
    match store.state_of(&key, ctx.clock) {
        // No value entry. If a definition exists, lazily produce the value via
        // the regenerate path (re-auth gated inside get_or_regenerate); else the
        // key truly does not exist (DR-0014 §1).
        None => {
            if store.is_defined(&key) {
                lazy_generate(store, ctx, &key)
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
            match store.extend_authenticated(&key, ctx.auth, ctx.requester, ctx.clock) {
                Ok(()) => match store.get(&key, ctx.clock) {
                    Some(secret) => Response::get(encode_b64(secret.expose_secret())),
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
            }
        }
        Some(EntryState::HardExpired) => {
            // A registered definition is the source of truth for regeneration
            // (it works even when the value entry's own source is static), so
            // prefer the definition path when one exists (DR-0014 §2).
            if store.is_defined(&key) {
                return lazy_generate(store, ctx, &key);
            }
            match store.regenerate(&key, ctx.runner, ctx.auth, ctx.requester, ctx.clock) {
                Ok(()) => match store.get(&key, ctx.clock) {
                    Some(secret) => Response::get(encode_b64(secret.expose_secret())),
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
            }
        }
    }
}

/// Produce `key`'s value from its registered definition (DR-0014 lazy path).
///
/// Runs the definition's command and re-authenticates inside
/// [`Store::get_or_regenerate`] (a single auth — callers must not pre-authenticate,
/// to avoid double prompting), then returns the freshly produced value. A
/// `ValueResident` outcome means the value became readable concurrently; fall
/// back to a plain get.
fn lazy_generate<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>, key: &str) -> Response
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match store.get_or_regenerate(key, ctx.runner, ctx.auth, ctx.requester, ctx.clock) {
        Ok(()) => match store.get(key, ctx.clock) {
            Some(secret) => Response::get(encode_b64(secret.expose_secret())),
            None => Response::error(ErrorKind::Internal, "value gone after lazy generation"),
        },
        Err(RegenerateDefOutcome::Undefined) => Response::error(ErrorKind::NotFound, "no such key"),
        // A usable value is resident after all; read it directly.
        Err(RegenerateDefOutcome::ValueResident) => match store.get(key, ctx.clock) {
            Some(secret) => Response::get(encode_b64(secret.expose_secret())),
            None => Response::error(ErrorKind::Internal, "value resident but unreadable"),
        },
        Err(RegenerateDefOutcome::RunFailed(e)) => {
            Response::error(ErrorKind::UpstreamFailed, e.to_string())
        }
        Err(RegenerateDefOutcome::AuthFailed(e)) => {
            Response::error(ErrorKind::AuthFailed, e.to_string())
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
    match store.pin_authenticated(&key, deadline, ctx.auth, ctx.requester, ctx.clock) {
        Ok(()) => Response::pinned(duration_secs),
        Err(PinAuthOutcome::NotFound) => Response::error(ErrorKind::NotFound, "no such key"),
        Err(PinAuthOutcome::HardExpired) => Response::error(
            ErrorKind::HardExpired,
            "entry is hard-expired (destroyed); cannot pin",
        ),
        Err(PinAuthOutcome::AuthFailed(e)) => Response::error(ErrorKind::AuthFailed, e.to_string()),
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
        fn run(&self, _argv: &[String]) -> Result<SecretBytes, RunError> {
            self.runs.set(self.runs.get() + 1);
            Ok(SecretBytes::new(self.value.clone()))
        }
    }

    struct FailingRunner;
    impl SourceRunner for FailingRunner {
        fn run(&self, _argv: &[String]) -> Result<SecretBytes, RunError> {
            Err(RunError::EmptyOutput)
        }
    }

    fn ctx<'a, A, R>(
        auth: &'a A,
        runner: &'a R,
        clock: &'a FakeClock,
    ) -> HandlerCtx<'a, A, R, FakeClock> {
        HandlerCtx {
            auth,
            runner,
            clock,
            pid: 1234,
            version: "test",
            socket: "/tmp/test.sock",
            requester: None,
        }
    }

    fn set_static(value: &[u8]) -> Request {
        Request::KvSet {
            key: "K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(value),
            },
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
        }
    }

    fn define_cmd(key: &str, argv: &[&str]) -> Request {
        Request::KvDefine {
            key: key.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            soft_ttl_secs: Some(SOFT),
            hard_ttl_secs: Some(HARD),
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

    fn err_kind(resp: &Response) -> ErrorKind {
        match resp {
            Response::Err(e) => e.error.kind,
            Response::Ok(_) => panic!("expected error, got ok"),
        }
    }

    #[test]
    fn ping_returns_pong() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        let resp = handle_request(&mut store, &c, Request::Ping);
        assert!(resp.is_ok());
    }

    #[test]
    fn set_then_get_static_value() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);

        assert!(handle_request(&mut store, &c, set_static(b"hunter2")).is_ok());
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"hunter2");
    }

    #[test]
    fn get_missing_key_is_not_found() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvGet {
                key: "ghost".into(),
            },
        );
        assert_eq!(err_kind(&resp), ErrorKind::NotFound);
    }

    #[test]
    fn define_defers_run_until_first_get() {
        // DR-0014: define registers but does not run; the first get lazily
        // produces the value (one run), and a second get is a cache hit (no run).
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"from-cmd");
        let c = ctx(&AllowAll, &runner, &clock);
        assert!(handle_request(&mut store, &c, define_cmd("K", &["echo", "x"])).is_ok());
        assert_eq!(runner.runs(), 0, "define must not run the command");
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"from-cmd");
        assert_eq!(runner.runs(), 1, "first get runs once (lazy)");
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"from-cmd");
        assert_eq!(runner.runs(), 1, "second get is a cache hit");
    }

    #[test]
    fn define_idempotent_same_def_is_ok_conflict_is_bad_request() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        assert!(handle_request(&mut store, &c, define_cmd("K", &["op", "read", "a"])).is_ok());
        // Identical definition: idempotent no-op.
        assert!(handle_request(&mut store, &c, define_cmd("K", &["op", "read", "a"])).is_ok());
        // Different argv: conflict.
        let resp = handle_request(&mut store, &c, define_cmd("K", &["op", "read", "b"]));
        assert_eq!(err_kind(&resp), ErrorKind::BadRequest);
    }

    #[test]
    fn define_empty_argv_is_bad_request() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        let req = Request::KvDefine {
            key: "K".into(),
            argv: vec![],
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, req)),
            ErrorKind::BadRequest
        );
    }

    #[test]
    fn lazy_generate_is_denied_when_auth_fails() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock);
        handle_request(&mut store, &c, define_cmd("K", &["echo", "x"]));
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn set_with_soft_exceeding_hard_is_bad_request() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        let req = Request::KvSet {
            key: "K".into(),
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
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        let req = Request::KvSet {
            key: "K".into(),
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
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(15)); // soft-expired
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"v", "AllowAll extends and returns value");
    }

    #[test]
    fn get_soft_expired_denied_is_auth_failed() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(15));
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn get_hard_expired_defined_key_regenerates() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"fresh");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, define_cmd("K", &["echo"]));
        // First get lazily produces the value (run 1).
        assert_eq!(
            get_value(&handle_request(
                &mut store,
                &c,
                Request::KvGet { key: "K".into() }
            )),
            b"fresh"
        );
        clock.advance(Duration::from_secs(HARD)); // hard-expired
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"fresh");
        assert_eq!(runner.runs(), 2, "first get ran once, regenerate ran once");
    }

    #[test]
    fn get_hard_expired_static_is_not_regenerable() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(HARD));
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(err_kind(&resp), ErrorKind::NotRegenerable);
    }

    #[test]
    fn get_hard_expired_command_upstream_failure_is_reported() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        // Define + first get produces the value via a succeeding runner; then
        // swap to a failing runner so the post-hard-expiry regeneration fails.
        let ok_runner = CountingRunner::new(b"v");
        let c_ok = ctx(&AllowAll, &ok_runner, &clock);
        handle_request(&mut store, &c_ok, define_cmd("K", &["echo"]));
        // First get lazily produces the value.
        assert_eq!(
            get_value(&handle_request(
                &mut store,
                &c_ok,
                Request::KvGet { key: "K".into() }
            )),
            b"v"
        );
        clock.advance(Duration::from_secs(HARD));
        let fail = FailingRunner;
        let c_fail = ctx(&AllowAll, &fail, &clock);
        let resp = handle_request(&mut store, &c_fail, Request::KvGet { key: "K".into() });
        assert_eq!(err_kind(&resp), ErrorKind::UpstreamFailed);
    }

    #[test]
    fn list_returns_sorted_keys() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        for k in ["b", "a", "c"] {
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
                OkPayload::List { keys } => assert_eq!(keys, vec!["a", "b", "c"]),
                _ => panic!("not list"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn del_removes_and_reports() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        let resp = handle_request(
            &mut store,
            &c,
            Request::KvDel {
                key: "K".into(),
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
                key: "K".into(),
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
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
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
                    assert_eq!(entries[0].name, "K");
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
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        // Pin for 1000s; then let the soft window (10s) lapse.
        let resp = handle_request(&mut store, &c, pin("K", 1000));
        assert!(resp.is_ok(), "pin ok: {resp:?}");
        clock.advance(Duration::from_secs(SOFT + 5));
        let resp = handle_request(&mut store, &c, Request::KvGet { key: "K".into() });
        assert_eq!(get_value(&resp), b"v", "pinned value gettable past soft");
    }

    #[test]
    fn pin_denied_is_auth_failed() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&DenyAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        let resp = handle_request(&mut store, &c, pin("K", 1000));
        assert_eq!(err_kind(&resp), ErrorKind::AuthFailed);
    }

    #[test]
    fn pin_missing_key_is_not_found() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, pin("ghost", 100))),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn pin_hard_expired_is_rejected() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        clock.advance(Duration::from_secs(HARD)); // hard-expired
        assert_eq!(
            err_kind(&handle_request(&mut store, &c, pin("K", 1000))),
            ErrorKind::HardExpired
        );
    }

    #[test]
    fn unpin_returns_to_normal_and_missing_is_not_found() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        handle_request(&mut store, &c, pin("K", 1000));
        // Unpin then soft-expire: the value is gated again.
        let resp = handle_request(&mut store, &c, Request::KvUnpin { key: "K".into() });
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
                    key: "ghost".into()
                }
            )),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn status_reports_pin_remaining_seconds() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        let runner = CountingRunner::new(b"x");
        let c = ctx(&AllowAll, &runner, &clock);
        handle_request(&mut store, &c, set_static(b"v"));
        handle_request(&mut store, &c, pin("K", 1000));
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
}
