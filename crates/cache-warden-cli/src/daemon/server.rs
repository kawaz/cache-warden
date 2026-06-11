//! Tokio control-socket server for `cache-warden run`.
//!
//! Single process, single multi-thread runtime (DR-0008): one listener task on
//! the control socket plus one task per accepted connection. Shutdown is fanned
//! out over a `watch` channel triggered by SIGINT / SIGTERM (authsock-warden
//! precedent). The shared [`Store`] sits behind an `Arc<Mutex<_>>`; the core is
//! synchronous so the lock is held only for the duration of one request.
//!
//! The synchronous source-command execution that `regenerate` performs is moved
//! off the async worker with `spawn_blocking` (DR-0008): a regen can block on an
//! upstream prompt, which must not stall the runtime.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cache_warden::{
    AllowAll, Authenticator, CommandAuthenticator, CommandRunner, DefineError, ProcessInfo,
    ProcessInspector, SourceRunner, Store, SystemClock, SystemInspector, Ttl, ValueSource,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::handler::{self, HandlerCtx};
use super::peer::peer_pid;
use crate::config::{Config, KvDefinition};
use crate::protocol::wire::{ErrorKind, Request, Response};
use crate::protocol::{decode_request, encode_response};

/// Daemon version reported by `status`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The production source-command runner.
///
/// The core [`Store::regenerate`] calls [`SourceRunner::run`] synchronously
/// while the store lock is held, so the whole locked handler section runs on
/// the blocking pool (see [`handle_connection`]) — that satisfies DR-0008's
/// "isolate synchronous work" mandate without changing the core. Requests for
/// other keys still queue on the store lock during a long regeneration; finer
/// locking is deferred until that contention is real.
type Runner = CommandRunner;

/// Bind the control socket, removing a dead stale socket first.
///
/// If a socket file already exists at `path`, we try to connect to it: a
/// successful connect means another daemon is already live there, which is an
/// error (refuse to clobber a running peer). A failed connect means the socket
/// is stale (left by a crashed daemon); we remove it and bind fresh.
///
/// The socket is created with mode 0600 via a restrictive umask around `bind`
/// (closing the TOCTOU window where the path briefly has umask-default perms).
pub fn bind_control_socket(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another cache-warden daemon is already listening on {}",
                        path.display()
                    ),
                ));
            }
            Err(_) => {
                // Stale socket from a dead daemon; remove and rebind.
                std::fs::remove_file(path)?;
            }
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Restrictive umask so the socket is created 0600 with no TOCTOU window.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(path);
    unsafe {
        libc::umask(old_umask);
    }
    let listener = listener?;

    // Belt-and-suspenders: enforce 0600 explicitly in case the platform's bind
    // ignored the umask for the socket inode.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(listener)
}

/// The re-authentication boundary wired from config (DR-0010).
///
/// A `[auth].command` in the config produces a [`CommandAuthenticator`]; its
/// absence produces [`AllowAll`] (no re-auth). Boxed behind the trait so the
/// single `run_request` wiring point is config-driven, not hard-coded.
type Auth = Box<dyn Authenticator + Send + Sync>;

/// Build the authenticator from the resolved config (DR-0010).
///
/// `[auth].command` => a [`CommandAuthenticator`] that runs that argv on every
/// TTL-gated unlock; absent => [`AllowAll`] (cache fast, never prompt).
fn build_authenticator(config: &Config) -> Auth {
    match config.auth_command() {
        Some(argv) => Box::new(CommandAuthenticator::new(argv.to_vec())),
        None => Box::new(AllowAll),
    }
}

/// Shared daemon state handed to each connection task.
///
/// `pub(crate)` so the authsock listener (see [`crate::daemon::authsock`]) can
/// share the same `Store` / authenticator / runner / clock as the control
/// socket — both adapters sit in one process around one core (DR-0008).
pub(crate) struct Shared {
    pub(crate) store: Mutex<Store>,
    pub(crate) runner: Runner,
    pub(crate) auth: Auth,
    /// One process-lifetime monotonic clock. It must be shared across preload
    /// and every request: a fresh `SystemClock::new()` rebases its origin to
    /// "now", so per-request clocks would make every entry look freshly
    /// activated and defeat TTL evaluation entirely.
    pub(crate) clock: SystemClock,
    /// Persistence settings for online definitions, or `None` when
    /// `[daemon].persist-definitions` is off (DR-0014 §4). When `Some`, every
    /// `kv.define` / `kv.del --with-define` that changes the definition registry
    /// rewrites the state file atomically (0600), persisting **online**
    /// definitions only (config `[kv.*]` definitions are excluded — the config
    /// is their source of truth, not the state file).
    persist: Option<PersistSettings>,
    socket_path: String,
    pid: u32,
    /// Key-level process-access policies (DR-0012 key layer): key name → its
    /// non-empty `allowed_processes` list, built from `[kv.*]` config at startup.
    /// Held here (not in the core `Store`) because policy interpretation is an
    /// adapter/handler concern (DR-0004); the control handler reads it for the
    /// `kv.get` gate, and the authsock listener shares the same `Shared` so a
    /// SIGN_REQUEST resolving a KV key consults the same table.
    pub(crate) kv_process_policies: std::collections::BTreeMap<String, Vec<String>>,
}

/// Where and what to persist for online definitions (DR-0014 §4).
struct PersistSettings {
    /// The state file path (`$XDG_STATE_HOME/cache-warden/definitions.toml`).
    path: PathBuf,
    /// Names defined by the config `[kv.*]` section. These are **excluded** from
    /// the persisted file: the config is their source of truth, so writing them
    /// to the state file would leak config definitions into the online layer (and
    /// resurrect them as stale "online" definitions if persistence is later
    /// turned off). Only genuinely online definitions are persisted.
    config_names: std::collections::HashSet<String>,
}

#[cfg(test)]
impl Shared {
    /// Build a `Shared` directly for tests (no config / socket binding), using
    /// the production [`CommandRunner`]. The authsock unit tests use this to
    /// exercise the local-sign path against a real core.
    pub(crate) fn new_for_test(store: Store, auth: Auth, clock: SystemClock) -> Self {
        Self {
            store: Mutex::new(store),
            runner: CommandRunner::new(),
            auth,
            clock,
            persist: None,
            socket_path: String::new(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
        }
    }
}

/// Run the daemon in the foreground until SIGINT / SIGTERM, using `config`.
///
/// Binds `socket_path`, registers the config's `[kv.*]` command definitions
/// (running eagerly only the `preload = true` ones and those referenced by an
/// `[authsock.sockets.*].keys` list), serves the control socket, and removes
/// the socket file on clean shutdown.
///
/// `socket_path` is already resolved by the caller (CLI `--socket` > env >
/// `[daemon].socket` > built-in default); the daemon does not re-derive it.
pub async fn run(socket_path: PathBuf, config: Config) -> io::Result<()> {
    // Suppress core dumps before any secret enters the Store: a crash must not
    // write in-memory secrets (incl. mlocked pages, DR-0007) to disk. Fail-open
    // and consistent with the mlock policy — a failure warns but does not abort
    // (see `hardening::suppress_core_dumps`).
    if !super::hardening::suppress_core_dumps() {
        eprintln!(
            "cache-warden: warning: could not disable core dumps (RLIMIT_CORE); \
             a crash could leak in-memory secrets to a core file"
        );
    }

    // Refuse debugger attachment so a live process inspector cannot read
    // in-memory secrets (DR-0007), defeating the mlock + core-dump layers.
    // Opt-out via `[daemon].allow-debug-attach = true`; never weaken silently —
    // a single stderr warning is printed either way (opt-out or syscall refusal).
    if config.allow_debug_attach() {
        eprintln!(
            "cache-warden: warning: anti-debug hardening disabled \
             ([daemon].allow-debug-attach = true); a debugger can attach and read \
             in-memory secrets"
        );
    } else if !super::hardening::deny_debugger_attach() {
        eprintln!(
            "cache-warden: warning: could not refuse debugger attachment; \
             a debugger could attach and read in-memory secrets"
        );
    }

    let listener = bind_control_socket(&socket_path)?;

    let runner = CommandRunner::new();
    let clock = SystemClock::new();
    let mut store = Store::new();

    // Register `[kv.*]` command definitions before serving (DR-0014 §4). Each is
    // registered as a definition (lazy by default); a `preload = true` entry is
    // also run eagerly so its first `get` is a cache hit. A failed eager preload
    // is a warning, not fatal: the definition stays registered and the value
    // regenerates on the next `get`.
    //
    // Keys referenced by any `[authsock.sockets.*].keys` are force-eager
    // regardless of `preload`: the agent registry derives their public halves at
    // startup (REQUEST_IDENTITIES needs the PEM resident), and the socket
    // declaration itself is the intent — requiring a second `preload = true` on
    // the same key would be a silent-footgun (a forgotten flag would drop the
    // key from the agent; DR-0004's "never interrupt key use" invariant).
    let authsock_keys: std::collections::HashSet<String> = config
        .authsock_sockets()
        .iter()
        .flat_map(|s| s.keys.iter().cloned())
        .collect();
    let config_defs = config.kv_definitions();
    register_definitions(&mut store, &runner, &clock, &config_defs, &authsock_keys);

    // Restore persisted online definitions when `[daemon].persist-definitions`
    // is on (DR-0014 §4). The restore is a **config-priority merge**: a key the
    // config already defines wins, and a clashing persisted entry is dropped
    // with a warning. Keys the config does not define are restored as-is. When
    // persistence is off, the state file is neither read nor written (even if it
    // exists). After restoring we rewrite the file so it becomes the current
    // truth (dropping the entries that lost the merge from disk too).
    let persist = if config.persist_definitions() {
        let path = crate::defs::definitions_state_path();
        let config_names: std::collections::HashSet<String> =
            config_defs.iter().map(|d| d.name.clone()).collect();
        match crate::defs::load_definitions(&path) {
            Ok(persisted) => {
                restore_persisted_definitions(&mut store, persisted, &config_names);
            }
            Err(e) => {
                // A corrupt state file is non-fatal: warn and start without it
                // (the file is rewritten from the in-memory registry below).
                eprintln!("cache-warden: {e}; ignoring persisted definitions");
            }
        }
        let settings = PersistSettings { path, config_names };
        // Rewrite the file from the merged registry (online definitions only) so
        // disk == current truth: entries that lost the config-priority merge are
        // removed from disk, and any config keys that leaked into an older file
        // are dropped (config keys are never persisted).
        write_online_definitions(&settings, &store);
        Some(settings)
    } else {
        None
    };

    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        runner,
        auth: build_authenticator(&config),
        clock,
        persist,
        socket_path: socket_path.display().to_string(),
        pid: std::process::id(),
        kv_process_policies: config.kv_process_policies(),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server = tokio::spawn(serve(listener, Arc::clone(&shared), shutdown_rx.clone()));

    println!(
        "cache-warden daemon listening on {} (pid {}). Press Ctrl+C to stop.",
        shared.socket_path, shared.pid
    );

    // Start one SSH agent listener per `[authsock.sockets.*]` (port Iteration 1).
    // Each binds its own socket (same 0600 / stale-recovery / double-start guard
    // as the control socket) and shares this process's Store / auth / runner /
    // clock (DR-0008). A bind failure for one socket is logged and skipped; the
    // daemon and the other sockets stay up.
    // Resolve the github filter settings (durations pre-validated at parse).
    let github_settings = super::authsock::GithubSettings {
        cache_ttl: config
            .authsock_github()
            .cache_ttl_duration()
            .unwrap_or_else(|_| std::time::Duration::from_secs(3600)),
        timeout: config
            .authsock_github()
            .timeout_duration()
            .unwrap_or_else(|_| std::time::Duration::from_secs(10)),
    };
    let authsock_handles = super::authsock::spawn_listeners(
        &config.authsock_sockets(),
        &config.authsock_sources(),
        github_settings,
        Arc::clone(&shared),
        shutdown_rx,
    );

    wait_for_shutdown().await;
    let _ = shutdown_tx.send(true);
    let _ = server.await;
    for (path, handle) in authsock_handles {
        let _ = handle.await;
        // Clean up each agent socket file (best effort).
        let _ = std::fs::remove_file(&path);
    }

    // Clean up the control socket file (best effort).
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Register command-source definitions into `store` at startup (DR-0014 §4).
///
/// Every entry is registered as a definition (KEY ↔ command + TTL) — no upstream
/// runs unless the entry is eager, in which case the command is also run so the
/// first `get` is a cache hit. An entry is eager when `preload = true` **or**
/// when its name is in `force_eager` (keys referenced by an
/// `[authsock.sockets.*].keys` list: the agent registry needs the PEM resident at
/// startup to enumerate the public key, so the socket declaration implies
/// preload — no second flag required). A bad TTL bound skips the whole entry; a
/// failed eager run is a single secret-free stderr warning and leaves the
/// definition in place (the value regenerates on the next `get`). The daemon must
/// come up even if an upstream secret source is temporarily down.
fn register_definitions<R, C>(
    store: &mut Store,
    runner: &R,
    clock: &C,
    entries: &[KvDefinition],
    force_eager: &std::collections::HashSet<String>,
) where
    R: SourceRunner,
    C: cache_warden::Clock,
{
    for entry in entries {
        let ttl = match Ttl::new(
            entry.soft_ttl_secs.map(std::time::Duration::from_secs),
            entry.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cache-warden: definition `{}` skipped: {e}", entry.name);
                continue;
            }
        };

        // Register the definition so a later `get` can regenerate the value. A
        // conflict (the same name already defined differently) should not happen
        // at startup from a single config, but is reported defensively. The
        // opaque value-type metadata (DR-0016) rides along with the definition.
        let source = ValueSource::command(entry.command.clone());
        let meta = crate::daemon::handler::meta_from_wire(entry.meta.clone());
        match store.define_with_meta(entry.name.clone(), source.clone(), ttl, meta.clone()) {
            Ok(()) => {}
            Err(DefineError::Conflict) => {
                eprintln!(
                    "cache-warden: definition `{}` conflicts with an existing definition; skipped",
                    entry.name
                );
                continue;
            }
            Err(DefineError::StaticNotDefinable) => {
                // Unreachable: a command source is never static.
                eprintln!(
                    "cache-warden: definition `{}` skipped: static source",
                    entry.name
                );
                continue;
            }
        }

        // Lazy by default; `preload = true` or an authsock-referenced key runs
        // the command eagerly. The produced value is opaque bytes; the key's
        // type (otp) stays on the definition registered just above (DR-0016).
        if entry.preload || force_eager.contains(&entry.name) {
            match runner.run(&entry.command) {
                Ok(value) => {
                    store.set(entry.name.clone(), source, value, ttl, clock);
                }
                Err(e) => {
                    // The RunError Display is already secret-free (stderr redacted).
                    eprintln!("cache-warden: preload `{}` failed: {e}", entry.name);
                }
            }
        }
    }
}

/// Merge persisted online definitions into `store` under the config-priority
/// rule (DR-0014 §4).
///
/// For each persisted definition:
/// - if `config_names` already defines that key, the config wins: the persisted
///   entry is **dropped** with a secret-free stderr warning (this is what keeps
///   "I edited the config but the stale persisted def keeps winning" from
///   happening). It is also absent from the post-merge snapshot, so the caller's
///   rewrite removes it from disk.
/// - otherwise the persisted definition is registered. A bad TTL bound or a
///   conflict with an already-registered definition (should not happen since
///   config keys are filtered out first) is warned and skipped, never fatal.
fn restore_persisted_definitions(
    store: &mut Store,
    persisted: Vec<KvDefinition>,
    config_names: &std::collections::HashSet<String>,
) {
    for def in persisted {
        if config_names.contains(&def.name) {
            eprintln!(
                "cache-warden: persisted definition `{}` dropped (the config defines \
                 it; config wins)",
                def.name
            );
            continue;
        }
        let ttl = match Ttl::new(
            def.soft_ttl_secs.map(std::time::Duration::from_secs),
            def.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "cache-warden: persisted definition `{}` skipped: {e}",
                    def.name
                );
                continue;
            }
        };
        let source = ValueSource::command(def.command.clone());
        let meta = crate::daemon::handler::meta_from_wire(def.meta.clone());
        match store.define_with_meta(def.name.clone(), source, ttl, meta) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "cache-warden: persisted definition `{}` skipped: {e}",
                    def.name
                );
            }
        }
    }
}

/// The store's **online** definition registry: every definition minus the names
/// the config defines (DR-0014 §4).
///
/// Config `[kv.*]` definitions are the config's responsibility, not the state
/// file's, so they are excluded — persisting them would resurrect them as stale
/// "online" definitions if persistence is later turned off.
fn online_definitions(settings: &PersistSettings, store: &Store) -> Vec<KvDefinition> {
    crate::defs::snapshot_definitions(store)
        .into_iter()
        .filter(|d| !settings.config_names.contains(&d.name))
        .collect()
}

/// Atomically rewrite the state file from the store's online definitions,
/// warning (non-fatal) on failure. Used at startup to normalize the file.
fn write_online_definitions(settings: &PersistSettings, store: &Store) {
    if let Err(e) =
        crate::defs::save_definitions(&settings.path, &online_definitions(settings, store))
    {
        eprintln!(
            "cache-warden: warning: could not write persisted definitions {}: {e}",
            settings.path.display()
        );
    }
}

/// Persist the store's online definition registry if persistence is on.
///
/// Called from the request path after a definition-changing command
/// (`kv.define` / `kv.del --with-define`) succeeds. A write failure is returned
/// so the caller can surface it (an in-memory/disk divergence is the dangerous
/// case — DR-0014 §4); when persistence is off this is a no-op `Ok(())`.
fn persist_if_enabled(shared: &Shared, store: &Store) -> std::io::Result<()> {
    match &shared.persist {
        Some(settings) => {
            crate::defs::save_definitions(&settings.path, &online_definitions(settings, store))
        }
        None => Ok(()),
    }
}

/// The accept loop: serve connections until the shutdown signal flips.
async fn serve(
    listener: UnixListener,
    shared: Arc<Shared>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let shared = Arc::clone(&shared);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, shared).await {
                                // Connection-level I/O errors are non-fatal.
                                eprintln!("cache-warden: connection error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("cache-warden: accept error: {e}");
                    }
                }
            }
        }
    }
}

/// Handle one client connection: read request lines, reply per line.
///
/// One connection may carry multiple request/response lines (the client may
/// keep the socket open). Each line is one JSON request; we reply with one JSON
/// response line. The peer pid is resolved once at accept time.
async fn handle_connection(stream: UnixStream, shared: Arc<Shared>) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let peer = peer_pid(stream.as_raw_fd());

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        // Run the handler on the blocking pool: a regeneration can block for
        // minutes (the source command may wait on a user prompt), and that must
        // not pin an async worker (DR-0008's synchronous-work isolation).
        let shared_for_handler = Arc::clone(&shared);
        let response =
            tokio::task::spawn_blocking(move || dispatch(&shared_for_handler, peer, &line))
                .await
                .unwrap_or_else(|e| {
                    Response::error(ErrorKind::Internal, format!("handler panicked: {e}"))
                });
        let mut out = encode_response(&response).unwrap_or_else(|_| {
            r#"{"ok":false,"error":{"kind":"internal","message":"failed to encode response"}}"#
                .to_string()
        });
        out.push('\n');
        write_half.write_all(out.as_bytes()).await?;
        write_half.flush().await?;
    }
    Ok(())
}

/// Parse one request line, run it against the store, and produce a response.
///
/// Resolves the requester ancestry from `peer` (best effort) and runs the
/// synchronous handler under the store lock.
fn dispatch(shared: &Arc<Shared>, peer: Option<u32>, line: &str) -> Response {
    let req = match decode_request(line) {
        Ok(r) => r,
        Err(e) => {
            return Response::error(ErrorKind::BadRequest, format!("malformed request: {e}"));
        }
    };
    run_request(shared, peer, req)
}

/// Run a parsed request against the store under lock.
///
/// Factored out so it can be exercised directly in tests without socket I/O.
fn run_request(shared: &Arc<Shared>, peer: Option<u32>, req: Request) -> Response {
    // Resolve requester ancestry from the peer pid (best effort).
    let requester: Option<Vec<ProcessInfo>> = peer.and_then(|pid| {
        let inspector = SystemInspector::new();
        inspector.ancestry(pid).ok()
    });

    // DR-0010: the authenticator is wired from config (CommandAuthenticator when
    // `[auth].command` is set, else AllowAll), built once at startup.
    let auth: &dyn Authenticator = shared.auth.as_ref();

    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => return Response::error(ErrorKind::Internal, "store lock poisoned"),
    };

    // A command that can change the definition registry triggers a persist on
    // success (DR-0014 §4). Capture this before `req` is moved into the handler.
    let may_change_definitions = matches!(
        req,
        Request::KvDefine { .. }
            | Request::KvDel {
                with_define: true,
                ..
            }
    );

    let ctx = HandlerCtx {
        auth,
        runner: &shared.runner,
        clock: &shared.clock,
        pid: shared.pid,
        version: VERSION,
        socket: &shared.socket_path,
        requester: requester.as_deref(),
        kv_process_policies: &shared.kv_process_policies,
    };
    let response = handler::handle_request(&mut store, &ctx, req);

    // Persist the (possibly changed) definition registry while still holding the
    // store lock, so the on-disk file is a consistent snapshot of the registry
    // that just mutated (DR-0014 §4). The write is synchronous on the blocking
    // pool (the whole locked section already runs there, DR-0008); `define` /
    // `del --with-define` are low-frequency, so the added latency is acceptable.
    // A write failure becomes an Internal error response rather than silently
    // diverging the in-memory registry from disk (codex review: the divergence
    // is the dangerous failure mode).
    if may_change_definitions
        && matches!(response, Response::Ok(_))
        && let Err(e) = persist_if_enabled(shared, &store)
    {
        return Response::error(
            ErrorKind::Internal,
            format!("definition applied but could not be persisted: {e}"),
        );
    }
    response
}

/// Wait for SIGINT or SIGTERM (Unix); Ctrl+C only elsewhere.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wire::{OkPayload, SetSource};
    use crate::protocol::{decode_b64, encode_b64};
    use tempfile::tempdir;

    fn shared() -> Arc<Shared> {
        Arc::new(Shared {
            store: Mutex::new(Store::new()),
            runner: CommandRunner::new(),
            auth: Box::new(AllowAll),
            clock: SystemClock::new(),
            persist: None,
            socket_path: "/tmp/test.sock".into(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
        })
    }

    #[test]
    fn run_request_set_then_get() {
        let s = shared();
        let set = Request::KvSet {
            key: "K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        assert!(run_request(&s, None, set).is_ok());
        let resp = run_request(
            &s,
            None,
            Request::KvGet {
                key: "K".into(),
                dry_run: false,
            },
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => assert_eq!(decode_b64(&value_b64).unwrap(), b"v"),
                _ => panic!("not get"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn dispatch_malformed_line_is_bad_request() {
        let s = shared();
        let resp = dispatch(&s, None, "{not json");
        match resp {
            Response::Err(e) => assert_eq!(e.error.kind, ErrorKind::BadRequest),
            _ => panic!("expected error"),
        }
    }

    // ---- build_authenticator (config -> Authenticator) ----

    #[test]
    fn build_authenticator_without_command_allows() {
        let cfg = Config::parse("").unwrap();
        let auth = build_authenticator(&cfg);
        assert!(
            auth.authenticate(&cache_warden::AuthContext::extend("K"))
                .is_ok()
        );
    }

    #[test]
    fn build_authenticator_with_failing_command_denies() {
        // `[auth].command = ["false"]` => CommandAuthenticator that always denies.
        let cfg = Config::parse("[auth]\ncommand = [\"false\"]\n").unwrap();
        let auth = build_authenticator(&cfg);
        assert_eq!(
            auth.authenticate(&cache_warden::AuthContext::extend("K")),
            Err(cache_warden::AuthError::Denied)
        );
    }

    #[test]
    fn build_authenticator_with_passing_command_allows() {
        let cfg = Config::parse("[auth]\ncommand = [\"true\"]\n").unwrap();
        let auth = build_authenticator(&cfg);
        assert!(
            auth.authenticate(&cache_warden::AuthContext::extend("K"))
                .is_ok()
        );
    }

    // ---- register_definitions (DR-0014 §4) ----

    /// An empty force-eager set (no authsock-referenced keys).
    fn no_eager() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn definition_without_preload_is_lazy_no_value_yet() {
        // Default (preload = false): the definition is registered but the
        // command is NOT run, so no value is resident until the first get.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            command: vec!["printf".into(), "tok-value".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: false,
            meta: Default::default(),
        }];
        register_definitions(&mut store, &runner, &clock, &entries, &no_eager());
        assert!(store.is_defined("TOK"), "definition registered");
        assert!(!store.has_value("TOK"), "value not produced eagerly (lazy)");
    }

    #[test]
    fn definition_with_preload_runs_eagerly() {
        // preload = true keeps the old behaviour: run the command at startup so
        // the first get is a cache hit.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            command: vec!["printf".into(), "tok-value".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: true,
            meta: Default::default(),
        }];
        register_definitions(&mut store, &runner, &clock, &entries, &no_eager());
        let secret = store.get("TOK", &clock).expect("entry preloaded");
        assert_eq!(secret.expose_secret(), b"tok-value");
    }

    #[test]
    fn authsock_referenced_key_is_eager_even_without_preload() {
        // A key listed in an `[authsock.sockets.*].keys` must be resident at
        // startup (the agent registry derives its public key then), so it is
        // force-eager regardless of `preload` — no second flag required.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![
            KvDefinition {
                name: "AGENT_KEY".into(),
                command: vec!["printf".into(), "pem-bytes".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false, // not preloaded by flag…
                meta: Default::default(),
            },
            KvDefinition {
                name: "OTHER".into(),
                command: vec!["printf".into(), "other".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false,
                meta: Default::default(),
            },
        ];
        let eager: std::collections::HashSet<String> =
            ["AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(&mut store, &runner, &clock, &entries, &eager);
        // …but the authsock reference forces it resident.
        assert_eq!(
            store.get("AGENT_KEY", &clock).unwrap().expose_secret(),
            b"pem-bytes",
            "authsock-referenced key is eagerly materialized"
        );
        // The unreferenced key stays lazy.
        assert!(store.is_defined("OTHER"));
        assert!(!store.has_value("OTHER"), "unreferenced key stays lazy");
    }

    #[test]
    fn preload_failure_is_non_fatal_and_keeps_definition() {
        // A failed eager preload must not abort startup; the definition stays
        // registered (so a later get regenerates), and other entries still load.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![
            KvDefinition {
                name: "BAD".into(),
                command: vec!["this-binary-does-not-exist-cw-preload".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
            KvDefinition {
                name: "GOOD".into(),
                command: vec!["printf".into(), "ok".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
        ];
        register_definitions(&mut store, &runner, &clock, &entries, &no_eager());
        // BAD's eager run failed, but its definition survives for regeneration.
        assert!(
            store.is_defined("BAD"),
            "definition kept after failed preload"
        );
        assert!(
            store.get("BAD", &clock).is_none(),
            "no value after failed preload"
        );
        assert_eq!(
            store.get("GOOD", &clock).unwrap().expose_secret(),
            b"ok",
            "subsequent preload still runs"
        );
    }

    #[test]
    fn authsock_forced_eager_failure_is_non_fatal_and_keeps_definition() {
        // The force-eager path shares the preload failure contract: warn,
        // continue, keep the definition (the agent socket simply starts without
        // that key until the upstream recovers).
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![KvDefinition {
            name: "AGENT_KEY".into(),
            command: vec!["this-binary-does-not-exist-cw-preload".into()],
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: false,
            meta: Default::default(),
        }];
        let eager: std::collections::HashSet<String> =
            ["AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(&mut store, &runner, &clock, &entries, &eager);
        assert!(store.is_defined("AGENT_KEY"), "definition survives");
        assert!(!store.has_value("AGENT_KEY"), "no value after failed run");
    }

    // ---- restore_persisted_definitions (config-priority merge; DR-0014 §4) ----

    fn pdef(name: &str, argv: &[&str], soft: Option<u64>, hard: Option<u64>) -> KvDefinition {
        KvDefinition {
            name: name.into(),
            command: argv.iter().map(|s| s.to_string()).collect(),
            soft_ttl_secs: soft,
            hard_ttl_secs: hard,
            preload: false,
            meta: Default::default(),
        }
    }

    #[test]
    fn restore_registers_keys_not_in_config() {
        let mut store = Store::new();
        let config_names = std::collections::HashSet::new();
        restore_persisted_definitions(
            &mut store,
            vec![pdef("TOK", &["printf", "v"], Some(3600), Some(86400))],
            &config_names,
        );
        assert!(store.is_defined("TOK"), "persisted def restored");
        let d = store.definition_of("TOK").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["printf".to_string(), "v".to_string()]
        );
        assert_eq!(d.ttl().soft(), Some(std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn restore_drops_persisted_key_that_config_already_defines() {
        // Config wins: a clashing persisted entry must not overwrite the config
        // definition, even if its argv differs.
        let mut store = Store::new();
        let runner = CommandRunner::new();
        let clock = cache_warden::FakeClock::new();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &[pdef("DB", &["config-cmd"], None, None)],
            &no_eager(),
        );
        let config_names: std::collections::HashSet<String> =
            ["DB".to_string()].into_iter().collect();
        // Persisted DB has a DIFFERENT argv; it must be dropped, not applied.
        restore_persisted_definitions(
            &mut store,
            vec![pdef("DB", &["persisted-cmd"], None, None)],
            &config_names,
        );
        let d = store.definition_of("DB").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["config-cmd".to_string()],
            "config definition wins the merge"
        );
    }

    #[test]
    fn restore_skips_bad_ttl_without_aborting_others() {
        let mut store = Store::new();
        let config_names = std::collections::HashSet::new();
        // First entry has soft > hard (invalid Ttl); it must be skipped while the
        // second still registers.
        restore_persisted_definitions(
            &mut store,
            vec![
                pdef("BAD", &["echo"], Some(100), Some(10)),
                pdef("GOOD", &["echo"], None, None),
            ],
            &config_names,
        );
        assert!(!store.is_defined("BAD"), "invalid TTL entry skipped");
        assert!(store.is_defined("GOOD"), "subsequent entry still restored");
    }

    #[tokio::test]
    async fn bind_detects_double_start() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _l1 = bind_control_socket(&path).expect("first bind");
        // The first listener is live; a plain connect succeeds against it at the
        // kernel level, so the second bind must error AddrInUse.
        let err = bind_control_socket(&path).expect_err("second bind must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        // A leftover regular file (not a live socket) simulates a stale path.
        std::fs::write(&path, b"stale").unwrap();
        // connect() to a regular file fails => treated as stale => removed+bound.
        let _l = bind_control_socket(&path).expect("should rebind over stale");
        assert!(path.exists());
    }

    #[tokio::test]
    async fn bind_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _l = bind_control_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
