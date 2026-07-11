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

/// Errors that can terminate the daemon's `run` loop.
#[derive(Debug)]
pub enum ServerError {
    /// A shutdown signal arrived while the daemon was still starting up.
    ShutdownDuringStartup,
    /// An I/O error (bind failure, etc.).
    Io(std::io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShutdownDuringStartup => write!(f, "shutdown signal received during startup"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

use cache_warden::{
    AllowAll, Authenticator, Capability, CommandAuthenticator, CommandRunner, DefineError,
    ProcessInfo, ProcessInspector, SourceRunner, Store, StoreBuilder, SystemClock, SystemInspector,
    Ttl,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::graceful_restart;
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
    pub(crate) control_cap: Capability,
    pub(crate) authsock_cap: Capability,
    pub(crate) otp_adapter: crate::daemon::otp_adapter::OtpAdapter,
    pub(crate) runner: Runner,
    pub(crate) auth: Auth,
    /// One process-lifetime monotonic clock. It must be shared across preload
    /// and every request: a fresh `SystemClock::new()` rebases its origin to
    /// "now", so per-request clocks would make every entry look freshly
    /// activated and defeat TTL evaluation entirely.
    pub(crate) clock: SystemClock,
    /// Persistence settings for online definitions (DR-0014 §4). Empty (not
    /// set) when `[daemon].persist-definitions` is off; set once after startup
    /// completes. When set, every `kv.define` / `kv.del --with-define` that
    /// changes the definition registry rewrites the state file atomically
    /// (0600), persisting **online** definitions only (config `[kv.*]`
    /// definitions are excluded — the config is their source of truth, not the
    /// state file). Uses `OnceLock` so the slot can be filled after the `Arc`
    /// is handed to the serve loop (DR-0023 Phase 1: startup is non-blocking).
    persist: std::sync::OnceLock<PersistSettings>,
    socket_path: String,
    pid: u32,
    /// Key-level process-access policies (DR-0012 key layer): key name → its
    /// non-empty `allowed_processes` list, built from `[kv.*]` config at startup.
    /// Held here (not in the core `Store`) because policy interpretation is an
    /// adapter/handler concern (DR-0004); the control handler reads it for the
    /// `kv.get` gate, and the authsock listener shares the same `Shared` so a
    /// SIGN_REQUEST resolving a KV key consults the same table.
    pub(crate) kv_process_policies: std::collections::BTreeMap<String, Vec<String>>,
    /// This process's own exec path, resolved once at startup (DR-0029 §3):
    /// graceful restart always execs *this exact path*, never re-resolving
    /// `current_exe()` at restart time (which would let a `plist`/PATH change
    /// after startup silently redirect the handoff — DR-0029 §3's rationale).
    /// Empty when `current_exe()` failed at startup (rare); graceful restart
    /// then always fails its own verification step, leaving the daemon
    /// otherwise fully functional.
    ///
    /// Only read from `graceful_restart::handle_request`'s
    /// `#[cfg(target_os = "macos")]` branch, hence genuinely unread on every
    /// other target (found while cross-checking this bundle's HIGH-4
    /// non-macOS regression test against `.github/workflows/ci.yml`'s
    /// `ubuntu-latest` runner's `cargo clippy --workspace -- -D warnings` —
    /// a pre-existing issue independent of that test).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) exe_path: PathBuf,
    /// This process's own argv (`std::env::args()`, index 0 included),
    /// captured once at startup and re-used verbatim (minus argv[0], which
    /// [`graceful_restart`] replaces with [`Self::exe_path`] itself) when
    /// re-exec'ing for a graceful restart ("argv 継承", DR-0029 §1 step ⑥).
    /// See [`Self::exe_path`]'s doc for why this is macOS-only in practice.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) argv: Vec<String>,
    /// Coordinates a graceful restart (DR-0029) between the connection
    /// handler that receives `daemon.restart_graceful` and this module's
    /// [`run`] loop, which owns the actual fork/exec.
    pub(crate) restart: graceful_restart::RestartCoordinator,
    /// Tracks in-flight connections so a graceful restart can drain them
    /// (bounded wait, DR-0029 §4) before its accept loop stops and its
    /// listeners close. Not consulted by the normal SIGINT/SIGTERM shutdown
    /// path, which does not drain (pre-existing behaviour, unchanged).
    pub(crate) active_connections: ConnectionTracker,
}

/// A bounded-wait connection counter (DR-0029 §4's drain step).
///
/// Incremented when [`serve`] accepts a connection, decremented when
/// [`handle_connection`] returns. [`ConnectionTracker::wait_drained`] resolves
/// as soon as the count reaches zero, or after `deadline` elapses, whichever
/// is first — the design's "現行の全クライアントは per-request 接続 ...
/// deadline 超過分は切断してよい" (DR-0029 §4).
pub(crate) struct ConnectionTracker {
    count: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

impl ConnectionTracker {
    pub(crate) fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn inc(&self) {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn dec(&self) {
        // `fetch_sub` returns the *previous* value; `1` means the count just
        // reached zero, so wake anyone waiting in `wait_drained`.
        if self.count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// Wait for the count to reach zero, or for `deadline` to elapse —
    /// whichever comes first. Never panics or errors: a timed-out drain is
    /// an accepted outcome (DR-0029 §4), not a failure.
    async fn wait_drained(&self, deadline: std::time::Duration) {
        let drained = async {
            loop {
                if self.count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    return;
                }
                self.notify.notified().await;
            }
        };
        let _ = tokio::time::timeout(deadline, drained).await;
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
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
    pub(crate) fn new_for_test(
        store: Store,
        cap: Capability,
        auth: Auth,
        clock: SystemClock,
    ) -> Self {
        let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(cap.clone());
        Self {
            store: Mutex::new(store),
            control_cap: cap.clone(),
            authsock_cap: cap,
            otp_adapter,
            runner: CommandRunner::new(),
            auth,
            clock,
            persist: std::sync::OnceLock::new(),
            socket_path: String::new(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
            exe_path: PathBuf::new(),
            argv: Vec::new(),
            restart: graceful_restart::RestartCoordinator::new(),
            active_connections: ConnectionTracker::new(),
        }
    }
}

/// Headroom given to the graceful-restart receiving process's `Monotonic`
/// clock (DR-0029 bundle 2 review MEDIUM-6, see the `clock` construction in
/// [`run`]). Chosen generously (a full day) rather than matching some
/// expected restart cadence: the only cost of a larger value is the
/// (essentially free) `Instant` subtraction itself, while too small a value
/// re-opens the exact security gap this constant exists to close for any
/// entry whose TTL/age exceeds it. Falls back to zero headroom
/// (`SystemClock::new()`-equivalent) if the process/system has not been up
/// long enough to represent it — see [`SystemClock::with_epoch_offset`]'s doc.
const GRACEFUL_RESTART_CLOCK_HEADROOM: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// Run the daemon in the foreground until SIGINT / SIGTERM, using `config`.
///
/// Binds `socket_path`, registers the config's `[kv.*]` command definitions
/// (running eagerly only the `preload = true` ones and those referenced by an
/// `[authsock.sockets.*].keys` list), serves the control socket, and removes
/// the socket file on clean shutdown.
///
/// `socket_path` is already resolved by the caller (CLI `--socket` > env >
/// `[daemon].socket` > built-in default); the daemon does not re-derive it.
pub async fn run(socket_path: PathBuf, config: Config) -> Result<(), ServerError> {
    // Install the shutdown-signal notifier *first*, before the (potentially slow)
    // startup work below. The shutdown signals are already blocked process-wide
    // (`block_shutdown_signals`, called before the runtime started); a dedicated
    // `sigwait` thread consumes them. Spawning it up front means a SIGINT/SIGTERM
    // that arrives *during* startup is dequeued immediately and its notification
    // latched (tokio's `Notify` stores one permit), so the daemon still shuts
    // down promptly even if it is signalled before it finishes binding/preloading.
    #[cfg(unix)]
    let shutdown_notify = spawn_shutdown_notifier(socket_path.clone());

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

    // DR-0029 bundle 2 review MEDIUM-5: call `try_receive` (which, as a side
    // effect, also spawns the state-holder reaper —
    // `receive::reap_holder_in_background` — the moment it sees the handoff
    // env var) *before* `bind_control_socket` can fail and return early via
    // `?` below. Previously a bind failure (e.g. another process already
    // holds the path) skipped `try_receive` entirely on a real
    // graceful-restart handoff, leaving the old process's state-holder child
    // unreaped by this process (its kernel parent, post-`execve`) until this
    // process's own eventual exit. Calling it first guarantees the reaper
    // always starts as soon as this process has taken the handoff fd,
    // independent of whether the rest of startup goes on to succeed.
    //
    // `try_receive` reads and parses the snapshot (bounded by its own 60s
    // timeout); any failure — no env var, a malformed stream, a timeout —
    // falls back to `None` here, and the daemon proceeds exactly as a normal
    // cold start (empty store) from this point on.
    let incoming = graceful_restart::receive::try_receive();

    // Bind the control socket early so clients can connect (and answer `ping`)
    // while `preload = true` entries are running (DR-0023 Phase 1).
    let listener = bind_control_socket(&socket_path)?;

    let runner = CommandRunner::new();

    // DR-0029 bundle 2 review MEDIUM-6: a plain `SystemClock::new()` anchors
    // its `Monotonic` numbering to *this* construction, i.e. ~zero headroom.
    // `Store::import_snapshot`'s reconstruction clamps safely when headroom
    // runs out (see `epoch_ms_to_monotonic`'s doc), but "safely" here means an
    // old entry is treated as freshly loaded — extending a hard-TTL secret's
    // true residency past the config's intended maximum age. `incoming` above
    // already tells us whether this is a real handoff (not just whether the
    // env var was *present* — an already-consumed one), so the extra
    // headroom applies exactly when there is a snapshot to import.
    let clock = if incoming.is_some() {
        SystemClock::with_epoch_offset(GRACEFUL_RESTART_CLOCK_HEADROOM)
    } else {
        SystemClock::new()
    };

    // DR-0029 §3: this process's own exec path, resolved once here and never
    // re-derived at restart time (a later `current_exe()` call could be
    // fooled by a changed cwd / a `plist` pointed elsewhere in the meantime —
    // DR-0029 §3's rationale for pinning it to the startup value). Empty on
    // failure (rare); graceful restart's own verification step then always
    // rejects, everything else about the daemon is unaffected.
    let exe_path = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!(
            "cache-warden: warning: cannot resolve this process's own exec path ({e}); \
             `daemon restart --graceful` will be unavailable"
        );
        PathBuf::new()
    });
    let argv: Vec<String> = std::env::args().collect();

    let cold_bundle = || {
        StoreBuilder::new()
            .failure_backoff(config.fetch_failure_backoff())
            .build()
    };
    let (handoff_stream, bundle) = match incoming {
        Some(graceful_restart::receive::IncomingHandoff { stream, snapshot }) => {
            match Store::import_snapshot(
                StoreBuilder::new().failure_backoff(config.fetch_failure_backoff()),
                snapshot,
                &clock,
            ) {
                Ok(bundle) => (Some(stream), bundle),
                Err(e) => {
                    eprintln!(
                        "cache-warden: warning: graceful-restart handoff snapshot was rejected \
                         ({e}); falling back to a cold start"
                    );
                    // `stream` drops here (closes our end) — the ABORT
                    // signal the old process's state-holder is waiting on
                    // (DR-0029 §5).
                    (None, cold_bundle())
                }
            }
        }
        None => (None, cold_bundle()),
    };

    // Build `Shared` with the (possibly graceful-restart-imported) Store and
    // an empty `persist` OnceLock. The persist slot is filled from within the
    // blocking startup task after definitions are registered (DR-0023
    // Phase 1): OnceLock allows a single interior write after the Arc has
    // been handed to the serve loop, without needing a Mutex or rebuilding
    // the whole Shared struct.
    let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(bundle.otp_cap);
    let shared = Arc::new(Shared {
        store: Mutex::new(bundle.store),
        control_cap: bundle.control_cap,
        authsock_cap: bundle.authsock_cap,
        otp_adapter,
        runner,
        auth: build_authenticator(&config),
        clock,
        persist: std::sync::OnceLock::new(), // filled after startup by the blocking task
        socket_path: socket_path.display().to_string(),
        pid: std::process::id(),
        kv_process_policies: config.kv_process_policies(),
        exe_path,
        argv,
        restart: graceful_restart::RestartCoordinator::new(),
        active_connections: ConnectionTracker::new(),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start the accept loop immediately so clients can connect while preloading.
    let server = tokio::spawn(serve(listener, Arc::clone(&shared), shutdown_rx.clone()));

    println!(
        "cache-warden daemon listening on {} (pid {}). Press Ctrl+C to stop.",
        shared.socket_path, shared.pid
    );

    // Register `[kv.*]` command definitions on the blocking pool (DR-0023 Phase 1).
    //
    // Each entry is registered as a definition (lazy by default); a `preload = true`
    // entry is also run eagerly so its first `get` is a cache hit. A failed eager
    // preload is a warning, not fatal: the definition stays registered and the value
    // regenerates on the next `get`.
    //
    // Keys referenced by any `[authsock.sockets.*].keys` are force-eager regardless
    // of `preload`: the agent registry derives their public halves at startup
    // (REQUEST_IDENTITIES needs the PEM resident), and the socket declaration itself
    // is the intent — requiring a second `preload = true` on the same key would be a
    // silent-footgun (a forgotten flag would drop the key from the agent;
    // DR-0004's "never interrupt key use" invariant).
    //
    // `register_definitions` may call `runner.run()` for eager entries, which can
    // block for seconds (a secret source may prompt the user). Running it on the
    // blocking pool prevents stalling the tokio runtime. A concurrent `select!` on
    // the shutdown notify lets a SIGTERM received during startup abort the preload
    // immediately (DR-0023 Phase 1).
    let authsock_keys: std::collections::HashSet<String> = config
        .authsock_sockets()
        .iter()
        .flat_map(|s| s.keys.iter().cloned())
        .collect();
    let config_defs = config.kv_definitions();

    // Clone the Arc so the blocking closure can write into the shared Store and
    // fill the OnceLock persist slot.
    let shared_for_startup = Arc::clone(&shared);
    eprintln!("cache-warden: registering config definitions ...");
    let t0 = std::time::Instant::now();

    // Capture everything the blocking closure needs by value so the closure is
    // `'static`. `runner` is Copy. `config_defs` and `authsock_keys` are moved.
    let runner_for_task = runner; // Copy
    let config_defs_for_task = config_defs.clone();
    let authsock_keys_for_task = authsock_keys.clone();
    // Persist-related data also goes into the blocking task to keep all I/O
    // (file reads for restore, file writes for rewrite) off the async runtime.
    let persist_enabled = config.persist_definitions();
    let config_names_for_persist: std::collections::HashSet<String> = config_defs
        .iter()
        .map(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE))
        .collect();
    let blocking = tokio::task::spawn_blocking(move || {
        // Write config definitions directly into the shared Store while holding
        // its lock. The serve loop is already running but no client request can
        // observe a partial state: each request takes the same lock, so they
        // queue behind this startup write (DR-0008 invariant).
        let mut store = shared_for_startup
            .store
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // DR-0029 bundle 2: whatever already has a value at this point came
        // from a graceful-restart handoff import (run just before `Shared`
        // was built, below) — empty on every other startup. Computed fresh
        // here rather than threaded through from the import step so a cold
        // start (the overwhelmingly common case) pays nothing beyond an
        // empty-store scan.
        let already_loaded: std::collections::HashSet<String> = store
            .list_filtered(|r| r.entry().is_some())
            .into_iter()
            .map(String::from)
            .collect();

        // DR-0029 bundle 2 review CRITICAL fix: see `clear_config_owned_definitions`'s
        // doc. A no-op on a cold start (nothing is defined yet at this point).
        clear_config_owned_definitions(&mut store, &config_names_for_persist);

        register_definitions(
            &mut store,
            &runner_for_task,
            &shared_for_startup.clock,
            &config_defs_for_task,
            &authsock_keys_for_task,
            &already_loaded,
            &shared_for_startup.control_cap,
        );

        // Restore persisted online definitions (DR-0014 §4) inside the same
        // blocking task to keep all startup I/O off the async runtime.
        if persist_enabled {
            let path = crate::defs::definitions_state_path();
            match crate::defs::load_definitions(&path) {
                Ok(persisted) => {
                    // DR-0029 bundle 2 review HIGH-1 fix: see
                    // `purge_stale_import_definitions`'s doc. Computed
                    // *before* `restore_persisted_definitions` consumes
                    // `persisted` below.
                    let persisted_names: std::collections::HashSet<String> = persisted
                        .iter()
                        .map(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE))
                        .collect();
                    restore_persisted_definitions(&mut store, persisted, &config_names_for_persist);
                    purge_stale_import_definitions(
                        &mut store,
                        &config_names_for_persist,
                        &persisted_names,
                    );
                }
                Err(e) => {
                    eprintln!("cache-warden: {e}; ignoring persisted definitions");
                }
            }
            let settings = PersistSettings {
                path,
                config_names: config_names_for_persist,
            };
            write_online_definitions(&settings, &store);
            // Install into the OnceLock while still holding the store lock so
            // the serve loop never observes a window where the file is written
            // but `persist` is not yet set. The store lock is the gate: any
            // `kv.define` / `kv.del --with-define` request arriving now queues
            // behind this lock and will see `persist` set when it runs.
            let _ = shared_for_startup.persist.set(settings);
        }
        // store lock released here (MutexGuard dropped)
    });

    // Race the blocking startup work against a shutdown signal (DR-0023 Phase 1):
    // if SIGTERM arrives while preload is running, abort and exit cleanly.
    #[cfg(unix)]
    {
        match &shutdown_notify {
            Some(notify) => {
                tokio::select! {
                    res = blocking => {
                        res.map_err(|e| ServerError::Io(
                            io::Error::other(format!("startup task panicked: {e}"))
                        ))?;
                    }
                    _ = notify.notified() => {
                        // Shutdown signal arrived during startup. The blocking task
                        // is still running in the thread pool but we are not
                        // awaiting it — it will complete eventually (or be
                        // terminated when the process exits). The watchdog timer in
                        // spawn_shutdown_notifier bounds the total latency.
                        eprintln!("cache-warden: shutdown signal received during startup");
                        let _ = shutdown_tx.send(true);
                        let _ = server.await;
                        let _ = std::fs::remove_file(&socket_path);
                        return Err(ServerError::ShutdownDuringStartup);
                    }
                }
            }
            None => {
                // No shutdown notifier (extremely unlikely): run to completion.
                blocking.await.map_err(|e| {
                    ServerError::Io(io::Error::other(format!("startup task panicked: {e}")))
                })?;
            }
        }
    }
    #[cfg(not(unix))]
    blocking
        .await
        .map_err(|e| ServerError::Io(io::Error::other(format!("startup task panicked: {e}"))))?;

    eprintln!(
        "cache-warden: startup complete in {:.2}s",
        t0.elapsed().as_secs_f64()
    );

    // DR-0029 §5: if this startup imported a graceful-restart handoff, this
    // process is now fully up (definitions registered, control socket
    // bound) — send the two-phase-commit `COMMIT` frame so the old
    // process's state-holder zeroizes its buffer and exits cleanly instead
    // of waiting out its 60s timeout.
    if let Some(stream) = handoff_stream {
        graceful_restart::receive::send_commit(stream);
    }

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

    // Bind the authsock listeners immediately, seeded from the disk cache
    // (DR-0023 Phase 2): startup never blocks on `op`. `op item list` /
    // `op item get` are synchronous CLI calls that can hang for tens of seconds (a
    // launchd-context daemon whose biometric path never reaches the GUI session),
    // so instead of running discovery *before* binding, each socket binds from the
    // last-known keys in the disk cache and a background task refreshes them once
    // `op` is reachable. A cold first-ever start seeds nothing and the sockets bind
    // empty until the background discovery populates them. This removes the P1
    // symptom (`docs/issue/2026-06-13`): listeners no longer wait on `op`.
    let authsock_sources = config.authsock_sources();
    let authsock_sockets = config.authsock_sockets();
    let seed = super::authsock::seed_all_sources_from_cache(&authsock_sources);

    let super::authsock::ListenerSet {
        mut handles,
        discovery_targets,
        exe,
    } = super::authsock::spawn_listeners(
        &authsock_sockets,
        &authsock_sources,
        seed,
        github_settings,
        Arc::clone(&shared),
        shutdown_rx.clone(),
    );

    // Spawn the background op discovery (DR-0023 Phase 2): it runs the blocking
    // `op item list` off the async runtime, retries with a capped backoff until
    // the first success, and then hot-updates each socket's registry. It is
    // select-able with the shutdown channel, so a stop signal is honoured at once
    // even while discovery hangs (the sockets are already bound above, so there is
    // no startup block to interrupt). Pushed into `handles` so shutdown awaits it
    // like the github refresh task.
    if !authsock_sources.is_empty() && !discovery_targets.is_empty() {
        let refresh = tokio::spawn(super::authsock::op_discovery_refresh(
            discovery_targets,
            authsock_sources,
            exe,
            Arc::clone(&shared),
            shutdown_rx.clone(),
        ));
        handles.push((PathBuf::new(), refresh));
    }
    let authsock_handles = handles;

    // Race the normal SIGINT/SIGTERM path against a `daemon.restart_graceful`
    // request that has already been verified and prepared (DR-0029 bundle
    // 2). Both converge on the exact same cleanup below (drain, stop
    // accepting, close + unlink every listener) — reusing the existing
    // shutdown path *is* DR-0029 §1's "accept 停止 → drain → close +
    // unlink" step, not a second implementation of it. Only the very last
    // action (return `Ok(())` vs. fork/exec) differs.
    #[cfg(unix)]
    let restart_requested = tokio::select! {
        _ = wait_for_shutdown(shutdown_notify) => false,
        _ = shared.restart.wait() => true,
    };
    #[cfg(not(unix))]
    let restart_requested = {
        wait_for_shutdown().await;
        // Graceful restart's control-socket handler rejects every request on
        // this platform before it could ever call `shared.restart`'s signal
        // (see `graceful_restart::handle_request`'s non-macOS guard), so this
        // is always the outcome here.
        false
    };
    let _ = shutdown_tx.send(true);
    // DR-0029 §4: only the restart path drains — the pre-existing
    // SIGINT/SIGTERM shutdown behaviour (no drain wait) is unchanged.
    if restart_requested {
        shared
            .active_connections
            .wait_drained(RESTART_DRAIN_DEADLINE)
            .await;
    }
    let _ = server.await;
    for (path, handle) in authsock_handles {
        let _ = handle.await;
        // Clean up each agent socket file (best effort).
        let _ = std::fs::remove_file(&path);
    }

    // Clean up the control socket file (best effort).
    let _ = std::fs::remove_file(&socket_path);

    if restart_requested {
        // Every listener is now closed and unlinked (DR-0029 §1's fd-hygiene
        // requirement) — only now is it safe to fork the state-holder and
        // `execve` this process. Does not return on success; if it does
        // return, the fork/exec sequence itself failed at the very last
        // moment and there is nothing left to recover (the listeners are
        // already gone) — fall through to the normal clean-shutdown return
        // below and rely on the service manager to cold-restart this process.
        graceful_restart::execute_after_shutdown(&shared);
    }
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
///
/// `already_loaded` (DR-0029 bundle 2) is the set of composed keys that
/// already carry a value — populated from a graceful-restart handoff import
/// that ran just before this call, empty on every other startup (cold start,
/// or a handoff that failed and fell back to cold). A `preload` / force-eager
/// entry whose key is already in this set skips its eager run: the value
/// just arrived intact from the old process, so re-running the source here
/// would be exactly the re-fetch storm graceful restart exists to avoid.
fn register_definitions<R, C>(
    store: &mut Store,
    runner: &R,
    clock: &C,
    entries: &[KvDefinition],
    force_eager: &std::collections::HashSet<String>,
    already_loaded: &std::collections::HashSet<String>,
    cap: &Capability,
) where
    R: SourceRunner,
    C: cache_warden::Clock,
{
    for entry in entries {
        // The store key is the composed `NS/KEY` (DR-0017 §5: a pinned
        // `namespace` field is absolute; absent means the daemon-config
        // context, which is the default namespace).
        let full_key = entry.full_key(crate::namespace::DEFAULT_NAMESPACE);
        let ttl = match Ttl::new(
            entry.soft_ttl_secs.map(std::time::Duration::from_secs),
            entry.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cache-warden: definition `{full_key}` skipped: {e}");
                continue;
            }
        };

        // Register the definition so a later `get` can regenerate the value. A
        // conflict (the same name already defined differently) should not happen
        // at startup from a single config, but is reported defensively. The
        // typed source is lowered to the execution primitive while its typed
        // origin is preserved in the opaque source slot (DR-0018 §1/§2). The
        // opaque value-type metadata (DR-0016) rides along with the definition.
        let source = entry.source.lower();
        let source_meta = entry.source.to_source_meta();
        let meta = crate::daemon::handler::meta_from_wire(entry.meta.clone());
        match store.define_with_meta(
            full_key.clone(),
            source.clone(),
            ttl,
            meta.clone(),
            source_meta,
        ) {
            Ok(()) => {}
            Err(DefineError::Conflict) => {
                eprintln!(
                    "cache-warden: definition `{full_key}` conflicts with an existing definition; skipped"
                );
                continue;
            }
            Err(DefineError::StaticNotDefinable) => {
                // Unreachable: a command source is never static.
                eprintln!("cache-warden: definition `{full_key}` skipped: static source");
                continue;
            }
            Err(DefineError::InvalidKey(e)) => {
                // Unreachable from config: `full_key` is composed from a
                // charset-validated NS + KEY. Reported defensively.
                eprintln!("cache-warden: definition `{full_key}` skipped: {e}");
                continue;
            }
        }

        // Lazy by default; `preload = true` or an authsock-referenced key runs
        // the command eagerly. The produced value is opaque bytes; the key's
        // type (otp) stays on the definition registered just above (DR-0016).
        // `force_eager` holds composed keys (authsock `keys` are normalized at
        // config validation), so the comparison is composed-to-composed.
        if (entry.preload || force_eager.contains(&full_key)) && !already_loaded.contains(&full_key)
        {
            // Run the lowered execution primitive (argv + cwd/env; DR-0018 §1).
            let argv = source.command_argv().unwrap_or(&[]).to_vec();
            let cwd = source.command_cwd().map(|p| p.to_path_buf());
            let env = source.command_env().clone();
            match runner.run(&argv, cwd.as_deref(), &env) {
                Ok(value) => {
                    store
                        .set(full_key.clone(), source, value, ttl, cap, clock)
                        .ok();
                }
                Err(e) => {
                    // The RunError Display is already secret-free (stderr redacted).
                    eprintln!("cache-warden: preload `{full_key}` failed: {e}");
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
        let full_key = def.full_key(crate::namespace::DEFAULT_NAMESPACE);
        if config_names.contains(&full_key) {
            eprintln!(
                "cache-warden: persisted definition `{full_key}` dropped (the config defines \
                 it; config wins)"
            );
            continue;
        }
        let ttl = match Ttl::new(
            def.soft_ttl_secs.map(std::time::Duration::from_secs),
            def.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cache-warden: persisted definition `{full_key}` skipped: {e}");
                continue;
            }
        };
        let source = def.source.lower();
        let source_meta = def.source.to_source_meta();
        let meta = crate::daemon::handler::meta_from_wire(def.meta.clone());
        match store.define_with_meta(full_key.clone(), source, ttl, meta, source_meta) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("cache-warden: persisted definition `{full_key}` skipped: {e}");
            }
        }
    }
}

/// Clear any existing definition for every key in `config_names` (DR-0029
/// bundle 2 review CRITICAL fix), so `register_definitions`'s upcoming
/// `define_with_meta` call always inserts cleanly instead of ever hitting
/// `DefineError::Conflict`.
///
/// A graceful-restart handoff import can leave the store already carrying a
/// definition for a config-defined key (imported wholesale from the old
/// process's live registry, before this function or `register_definitions`
/// ever runs). `define_with_meta`'s idempotency is an *exact-match* rule
/// (DR-0014 §1): if that imported definition differs from the config's
/// current one at all (e.g. its TTL or argv changed since the old process
/// started), `register_definitions` would hit `Conflict` and skip
/// re-registering it — silently leaving the *stale* imported definition in
/// place, so a config edit would never take effect across a graceful
/// restart. Clearing it first (via [`Store::undefine`], which touches only
/// the definition — never the cached *value* or its failure-backoff record)
/// makes the config always win, exactly as it would on a cold start: the
/// cached value keeps serving uninterrupted, and the next regeneration
/// (`get_or_regenerate`) picks up the new TTL/argv from the
/// freshly-registered definition.
///
/// A no-op on a cold start (nothing is defined yet when this runs).
fn clear_config_owned_definitions(
    store: &mut Store,
    config_names: &std::collections::HashSet<String>,
) {
    for full_key in config_names {
        store.undefine(full_key);
    }
}

/// Remove any definition the store still carries that is neither a current
/// config definition nor a genuinely persisted online one (DR-0029 bundle 2
/// review HIGH-1 fix), returning the removed keys (for logging/testing).
///
/// A graceful-restart handoff import can leave the store carrying a
/// definition for a key the *old* process's config used to define but the
/// *current* config no longer does — an orphan that is neither a config
/// definition (excluded from [`online_definitions`]'s filter) nor ever
/// actually persisted as online. Left alone, such an orphan would still be
/// swept into `write_online_definitions`'s next write as if it *were*
/// genuinely online — resurrecting itself on every subsequent restart. Call
/// this only once `register_definitions` and `restore_persisted_definitions`
/// have both already run, so `expected` names (config ∪ the state file's own
/// persisted names, computed by the caller *before* the latter call
/// consumes its `persisted` argument) reflect every definition that is
/// supposed to still be there.
///
/// Every `kv.define` / `kv.del --with-define` synchronously rewrites the
/// state file (`persist_if_enabled`), so `persisted_names` is always in sync
/// as of the last successful mutation — the only reliable way to tell an
/// orphan apart from a genuinely online definition that just happens to also
/// ride along in the handoff snapshot. Callers gate this to the
/// `persist_enabled` branch only: without persistence there is no such
/// trustworthy record, and a lingering in-memory-only orphan is harmless (it
/// is never written to disk).
fn purge_stale_import_definitions(
    store: &mut Store,
    config_names: &std::collections::HashSet<String>,
    persisted_names: &std::collections::HashSet<String>,
) -> Vec<String> {
    let expected: std::collections::HashSet<&String> =
        config_names.iter().chain(persisted_names).collect();
    let stale: Vec<String> = store
        .list_filtered(|r| r.definition().is_some())
        .into_iter()
        .map(String::from)
        .filter(|k| !expected.contains(k))
        .collect();
    for key in &stale {
        store.undefine(key);
    }
    stale
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
        .filter(|d| {
            !settings
                .config_names
                .contains(&d.full_key(crate::namespace::DEFAULT_NAMESPACE))
        })
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
/// case — DR-0014 §4); when persistence is off (or startup has not yet completed)
/// this is a no-op `Ok(())`.
fn persist_if_enabled(shared: &Shared, store: &Store) -> std::io::Result<()> {
    match shared.persist.get() {
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
                        shared.active_connections.inc();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, Arc::clone(&shared)).await {
                                // Connection-level I/O errors are non-fatal.
                                eprintln!("cache-warden: connection error: {e}");
                            }
                            shared.active_connections.dec();
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
    // `ping` needs neither the store lock nor the requester ancestry (it just
    // returns a pong). Short-circuit before taking the lock so pings succeed
    // even while the startup blocking task holds the store lock (DR-0023 Phase 1).
    if matches!(req, Request::Ping) {
        return Response::pong();
    }
    // `daemon.restart_graceful` (DR-0029) is handled entirely by
    // `graceful_restart`, which takes the store lock itself only for the
    // brief snapshot-export step — it never goes through the generic
    // `handler::handle_request` dispatch below.
    if matches!(req, Request::RestartGraceful) {
        return graceful_restart::handle_request(shared);
    }

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
        store_cap: &shared.control_cap,
        otp_adapter: &shared.otp_adapter,
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

/// The set of signals that request a graceful daemon shutdown.
#[cfg(unix)]
const SHUTDOWN_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// How long the shutdown watchdog ([`spawn_shutdown_notifier`]) waits for the
/// graceful shutdown to complete before forcing `_exit`. Generous relative to
/// the sub-millisecond graceful path (so an only-moderately-loaded host still
/// shuts down cleanly), but short enough that a stop request is always honoured
/// promptly and well within a service manager's own SIGTERM→SIGKILL window.
#[cfg(unix)]
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a graceful restart waits for in-flight connections to finish
/// before its accept loop stops and its listeners close (DR-0029 §4). A
/// connection still open past this deadline is simply cut when this process
/// later `execve`s — accepted, not treated as a failure.
const RESTART_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Build a `sigset_t` containing the [`SHUTDOWN_SIGNALS`].
#[cfg(unix)]
fn shutdown_sigset() -> libc::sigset_t {
    // SAFETY: `sigemptyset` / `sigaddset` initialise and populate a `sigset_t` we
    // own exclusively for the duration of these calls; no other memory is touched.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in SHUTDOWN_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Block the shutdown signals (SIGINT / SIGTERM) in the calling thread so they
/// can be delivered *synchronously* via [`wait_for_shutdown`]'s `sigwait` thread
/// instead of through an asynchronous handler.
///
/// **Call this before the tokio runtime is built** (see `daemon_cmd`): a thread
/// that spawns children passes its signal mask on to them, so blocking on the
/// main thread first means every runtime worker — and the dedicated `sigwait`
/// thread — inherits the block. Any thread that does *not* block these signals
/// could take one via the kernel's default disposition and kill the process
/// before the cleanup path runs.
///
/// Design rationale: we deliberately avoid `tokio::signal` here. On macOS,
/// `ptrace(PT_DENY_ATTACH)` (the [`hardening::deny_debugger_attach`] layer,
/// DR-0007) makes tokio's asynchronous signal driver miss SIGTERM — the daemon
/// is then killed by the default disposition without removing its control socket
/// (regression covered by the `full_lifecycle_over_control_socket` e2e test). A
/// `sigwait`-on-a-dedicated-thread design is a synchronous kernel call that does
/// not depend on the async driver at all, so it is immune to the interaction —
/// and it has no startup race (blocking happens before the socket is even bound).
///
/// [`hardening::deny_debugger_attach`]: super::hardening::deny_debugger_attach
///
/// Returns `true` if the mask was updated, `false` if the libc call refused
/// (near-impossible for a valid signal set; the caller decides whether to warn).
#[cfg(unix)]
pub fn block_shutdown_signals() -> bool {
    let set = shutdown_sigset();
    // SAFETY: `pthread_sigmask` reads the `sigset_t` we own and updates only the
    // calling thread's signal mask; no memory we own is mutated.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    rc == 0
}

/// Unblock the shutdown signals (SIGINT / SIGTERM) in the calling thread,
/// restoring the kernel's default "terminate" disposition.
///
/// Used only on the degraded fallback path in [`wait_for_shutdown`]: if the
/// dedicated `sigwait` thread could not be spawned, the process would otherwise
/// be left with the signals blocked and *no* consumer — i.e. unkillable by
/// SIGINT/SIGTERM. Unblocking hands shutdown back to the OS default disposition
/// (an abrupt, cleanup-less termination, but reliably killable) rather than
/// relying on tokio's async signal driver, which is the very thing that is
/// broken on macOS under `ptrace(PT_DENY_ATTACH)` (see [`block_shutdown_signals`]).
#[cfg(unix)]
fn unblock_shutdown_signals() {
    let set = shutdown_sigset();
    // SAFETY: as in `block_shutdown_signals`, but unblocking.
    unsafe {
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

/// Spawn the dedicated thread that waits (synchronously, via `sigwait`) for a
/// shutdown signal and latches a [`tokio::sync::Notify`] when one arrives.
///
/// Call this *early* in [`run`], before the startup work, so a signal that
/// arrives during startup is consumed immediately (the signals are blocked
/// process-wide by [`block_shutdown_signals`], so until something `sigwait`s
/// them they only accumulate as pending — they are never lost, but nothing acts
/// on them). The returned `Notify` stores one permit, so an early signal is
/// observed the moment [`run`] reaches its `notified().await`.
///
/// We use a dedicated std thread + `sigwait` rather than `tokio::signal` because
/// tokio's asynchronous signal driver is unreliable on macOS once
/// `ptrace(PT_DENY_ATTACH)` has run (see [`block_shutdown_signals`]); `sigwait`
/// is a synchronous kernel call that does not depend on that driver.
///
/// Returns `None` if the thread could not be spawned (extremely unlikely), in
/// which case [`wait_for_shutdown`] falls back to tokio's async `ctrl_c`.
///
/// After delivering the notification the thread also arms a **shutdown
/// watchdog**: if the process has not exited within [`SHUTDOWN_GRACE`] it unlinks
/// the control socket and forces termination with `_exit`. The async graceful
/// path (flip `shutdown_tx`, drain the accept loop, unlink the sockets) normally
/// completes in well under a millisecond, so the watchdog never fires in
/// practice. It exists to bound the shutdown latency unconditionally: because
/// the shutdown signals are blocked process-wide, the kernel's default
/// "terminate" disposition no longer acts as a backstop, so a daemon wedged
/// mid-shutdown (or starved before it can drive the async shutdown to
/// completion) would otherwise never exit. The watchdog restores the guarantee
/// that a SIGINT/SIGTERM always stops the daemon promptly — and unlinks the
/// control socket first so the forced path still leaves a clean filesystem (any
/// `[authsock.sockets.*]` files rely on the next start's stale-socket recovery,
/// DR-0009).
///
/// `control_socket` is the path to remove on the forced path.
#[cfg(unix)]
fn spawn_shutdown_notifier(control_socket: PathBuf) -> Option<std::sync::Arc<tokio::sync::Notify>> {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let signalled = std::sync::Arc::clone(&notify);
    let spawned = std::thread::Builder::new()
        .name("cw-signal".to_owned())
        .spawn(move || {
            // Re-assert the block locally: `sigwait`'s contract requires the
            // waited-for signals to be blocked in the calling thread (they are
            // already, via inheritance, but being explicit is robust to how this
            // thread happens to be spawned).
            let _ = block_shutdown_signals();
            let set = shutdown_sigset();
            let mut sig: libc::c_int = 0;
            // Loop until `sigwait` reports a real delivery. It returns 0 on
            // success; on a spurious non-zero return we must NOT fall through and
            // notify (that would trigger shutdown without a signal). With our
            // fixed, valid signal set a non-zero return is not expected, so this
            // simply re-arms rather than acting on a phantom signal.
            loop {
                // SAFETY: `sigwait` reads the `sigset_t` we own and writes the
                // delivered signal number into `sig`, which we own. It blocks
                // until one of the (process-wide blocked) shutdown signals fires.
                let rc = unsafe { libc::sigwait(&set, &mut sig) };
                if rc == 0 {
                    break;
                }
            }
            signalled.notify_one();
            // Watchdog: bound the shutdown latency. If the graceful path has not
            // finished (i.e. the whole process has not exited) within the grace
            // window, clean up the control socket and force termination. If
            // graceful shutdown completes first the process exits and this thread
            // is torn down before the sleep returns, so the lines below are only
            // ever reached on a wedged/starved shutdown.
            std::thread::sleep(SHUTDOWN_GRACE);
            eprintln!(
                "cache-warden: graceful shutdown did not finish within {}s of the \
                 stop signal; forcing exit",
                SHUTDOWN_GRACE.as_secs()
            );
            let _ = std::fs::remove_file(&control_socket);
            // SAFETY: `_exit` takes no pointers and simply terminates the process.
            // Exit 0: a SIGINT/SIGTERM-initiated stop is an intentional shutdown,
            // so we report success (the warning above is the observability hook).
            unsafe { libc::_exit(0) };
        });
    match spawned {
        Ok(_) => Some(notify),
        Err(e) => {
            eprintln!(
                "cache-warden: warning: could not start signal thread ({e}); falling back to async Ctrl+C handling"
            );
            None
        }
    }
}

/// Wait for a shutdown signal: await the notifier installed by
/// [`spawn_shutdown_notifier`].
///
/// `None` means the `sigwait` thread could not be spawned. The signals are still
/// blocked process-wide (from before the runtime started), so there is no async
/// consumer left — we must *unblock* them to hand shutdown back to the kernel's
/// default disposition, then park. We do **not** await `tokio::signal::ctrl_c`
/// here: installing a tokio SIGINT handler would re-disarm the default
/// disposition and route through the async driver that is unreliable under
/// `ptrace(PT_DENY_ATTACH)` — the exact failure this whole design avoids. After
/// unblocking, an abrupt OS terminate is the (degraded but reliable) outcome.
#[cfg(unix)]
async fn wait_for_shutdown(notify: Option<std::sync::Arc<tokio::sync::Notify>>) {
    match notify {
        Some(notify) => notify.notified().await,
        None => {
            unblock_shutdown_signals();
            // Park forever; the unblocked SIGINT/SIGTERM now terminate the
            // process via the kernel default disposition.
            std::future::pending::<()>().await;
        }
    }
}

/// Wait for Ctrl+C on non-Unix platforms.
#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wire::{OkPayload, SetSource};
    use crate::protocol::{decode_b64, encode_b64};
    use tempfile::tempdir;

    fn shared() -> Arc<Shared> {
        let bundle = cache_warden::StoreBuilder::new().build();
        let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(bundle.otp_cap);
        Arc::new(Shared {
            store: Mutex::new(bundle.store),
            control_cap: bundle.control_cap,
            authsock_cap: bundle.authsock_cap,
            otp_adapter,
            runner: CommandRunner::new(),
            auth: Box::new(AllowAll),
            clock: SystemClock::new(),
            persist: std::sync::OnceLock::new(),
            socket_path: "/tmp/test.sock".into(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
            exe_path: PathBuf::new(),
            argv: Vec::new(),
            restart: graceful_restart::RestartCoordinator::new(),
            active_connections: ConnectionTracker::new(),
        })
    }

    #[test]
    fn run_request_set_then_get() {
        let s = shared();
        let set = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
        };
        assert!(run_request(&s, None, set).is_ok());
        let resp = run_request(
            &s,
            None,
            Request::KvGet {
                key: "default/K".into(),
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

    // ---- daemon.restart_graceful dispatch (DR-0029 bundle 2) ----

    #[test]
    fn restart_graceful_without_a_resolvable_exe_path_is_aborted() {
        // The `shared()` test helper leaves `exe_path` empty (no real daemon
        // binary behind this test `Shared`) — the request must be cleanly
        // rejected rather than attempt anything, on every platform. On
        // macOS this exercises `verify_exec_target`'s own rejection (fails at
        // `File::open("")`, before ever reaching the codesign check); on
        // every other platform `graceful_restart::handle_request`'s
        // early guard rejects it before touching the store at all.
        let s = shared();
        let resp = run_request(&s, None, Request::RestartGraceful);
        match resp {
            Response::Err(e) => assert_eq!(e.error.kind, ErrorKind::RestartAborted),
            other => panic!("expected RestartAborted, got {other:?}"),
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
        let cfg = Config::parse("[auth]\ntype = \"command\"\ncommand = [\"false\"]\n").unwrap();
        let auth = build_authenticator(&cfg);
        assert_eq!(
            auth.authenticate(&cache_warden::AuthContext::extend("K")),
            Err(cache_warden::AuthError::Denied)
        );
    }

    #[test]
    fn build_authenticator_with_passing_command_allows() {
        let cfg = Config::parse("[auth]\ntype = \"command\"\ncommand = [\"true\"]\n").unwrap();
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

    /// An empty `already_loaded` set (no graceful-restart handoff in play) —
    /// every pre-existing `register_definitions` test exercises the cold-start
    /// shape, where this is always empty (DR-0029 bundle 2).
    fn none_already_loaded() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn definition_without_preload_is_lazy_no_value_yet() {
        // Default (preload = false): the definition is registered but the
        // command is NOT run, so no value is resident until the first get.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "tok-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: false,
            meta: Default::default(),
        }];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        assert!(store.is_defined("default/TOK"), "definition registered");
        assert!(
            !store.has_value("default/TOK"),
            "value not produced eagerly (lazy)"
        );
    }

    #[test]
    fn definition_with_preload_runs_eagerly() {
        // preload = true keeps the old behaviour: run the command at startup so
        // the first get is a cache hit.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "tok-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: true,
            meta: Default::default(),
        }];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        let secret = store
            .get("default/TOK", &cap, &clock)
            .ok()
            .flatten()
            .expect("entry preloaded");
        secret.with_exposed(|b| assert_eq!(b, b"tok-value"));
    }

    #[test]
    fn authsock_referenced_key_is_eager_even_without_preload() {
        // A key listed in an `[authsock.sockets.*].keys` must be resident at
        // startup (the agent registry derives its public key then), so it is
        // force-eager regardless of `preload` — no second flag required.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![
            KvDefinition {
                name: "AGENT_KEY".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "pem-bytes".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false, // not preloaded by flag…
                meta: Default::default(),
            },
            KvDefinition {
                name: "OTHER".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "other".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false,
                meta: Default::default(),
            },
        ];
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &none_already_loaded(),
            &cap,
        );
        // …but the authsock reference forces it resident.
        store
            .get("default/AGENT_KEY", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"pem-bytes",
                    "authsock-referenced key is eagerly materialized"
                )
            });
        // The unreferenced key stays lazy.
        assert!(store.is_defined("default/OTHER"));
        assert!(
            !store.has_value("default/OTHER"),
            "unreferenced key stays lazy"
        );
    }

    #[test]
    fn preload_failure_is_non_fatal_and_keeps_definition() {
        // A failed eager preload must not abort startup; the definition stays
        // registered (so a later get regenerates), and other entries still load.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![
            KvDefinition {
                name: "BAD".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["this-binary-does-not-exist-cw-preload".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
            KvDefinition {
                name: "GOOD".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "ok".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
        ];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        // BAD's eager run failed, but its definition survives for regeneration.
        assert!(
            store.is_defined("default/BAD"),
            "definition kept after failed preload"
        );
        assert!(
            store
                .get("default/BAD", &cap, &clock)
                .ok()
                .flatten()
                .is_none(),
            "no value after failed preload"
        );
        store
            .get("default/GOOD", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| assert_eq!(b, b"ok", "subsequent preload still runs"));
    }

    #[test]
    fn authsock_forced_eager_failure_is_non_fatal_and_keeps_definition() {
        // The force-eager path shares the preload failure contract: warn,
        // continue, keep the definition (the agent socket simply starts without
        // that key until the upstream recovers).
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "AGENT_KEY".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["this-binary-does-not-exist-cw-preload".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: false,
            meta: Default::default(),
        }];
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &none_already_loaded(),
            &cap,
        );
        assert!(store.is_defined("default/AGENT_KEY"), "definition survives");
        assert!(
            !store.has_value("default/AGENT_KEY"),
            "no value after failed run"
        );
    }

    // ---- already_loaded (DR-0029 bundle 2: skip eager re-fetch on graceful restart) ----

    #[test]
    fn already_loaded_key_skips_eager_rerun_even_when_preload_is_true() {
        // Simulates a key that arrived with a value via a graceful-restart
        // handoff import (DR-0029 bundle 2), seeded directly via `store.set`
        // here rather than through a real import for test isolation.
        // `preload = true` must NOT re-run the source for it — doing so would
        // be exactly the re-fetch storm graceful restart exists to avoid.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "re-fetched-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: true,
            meta: Default::default(),
        }];
        store
            .set(
                "default/TOK".to_string(),
                cache_warden::ValueSource::Static,
                b"imported-value".to_vec().into(),
                cache_warden::Ttl::never(),
                &cap,
                &clock,
            )
            .unwrap();
        let already_loaded: std::collections::HashSet<String> =
            ["default/TOK".to_string()].into_iter().collect();

        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &already_loaded,
            &cap,
        );

        store
            .get("default/TOK", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"imported-value",
                    "already-loaded preload key must not be re-fetched"
                )
            });
    }

    #[test]
    fn already_loaded_key_skips_eager_rerun_for_force_eager_too() {
        // Same contract as the `preload` case above, but via the
        // authsock-referenced force-eager path.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "AGENT_KEY".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "re-fetched-pem".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: false,
            meta: Default::default(),
        }];
        store
            .set(
                "default/AGENT_KEY".to_string(),
                cache_warden::ValueSource::Static,
                b"imported-pem".to_vec().into(),
                cache_warden::Ttl::never(),
                &cap,
                &clock,
            )
            .unwrap();
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        let already_loaded = eager.clone();

        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &already_loaded,
            &cap,
        );

        store
            .get("default/AGENT_KEY", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"imported-pem",
                    "already-loaded force-eager key must not be re-fetched"
                )
            });
    }

    // ---- restore_persisted_definitions (config-priority merge; DR-0014 §4) ----

    fn cmd_src(argv: &[&str]) -> crate::protocol::wire::SourceSpecWire {
        use crate::protocol::wire::{CommandSpecWire, SourceSpecWire};
        SourceSpecWire::Command {
            command: CommandSpecWire {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
            },
        }
    }

    fn pdef(name: &str, argv: &[&str], soft: Option<u64>, hard: Option<u64>) -> KvDefinition {
        KvDefinition {
            name: name.into(),
            namespace: None,
            source: cmd_src(argv),
            soft_ttl_secs: soft,
            hard_ttl_secs: hard,
            preload: false,
            meta: Default::default(),
        }
    }

    #[test]
    fn restore_registers_keys_not_in_config() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        let config_names = std::collections::HashSet::new();
        restore_persisted_definitions(
            &mut store,
            vec![pdef("TOK", &["printf", "v"], Some(3600), Some(86400))],
            &config_names,
        );
        assert!(store.is_defined("default/TOK"), "persisted def restored");
        let d = store.definition_of("default/TOK").unwrap();
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
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CommandRunner::new();
        let clock = cache_warden::FakeClock::new();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &[pdef("DB", &["config-cmd"], None, None)],
            &no_eager(),
            &none_already_loaded(),
            &_cap,
        );
        let config_names: std::collections::HashSet<String> =
            ["default/DB".to_string()].into_iter().collect();
        // Persisted DB has a DIFFERENT argv; it must be dropped, not applied.
        restore_persisted_definitions(
            &mut store,
            vec![pdef("DB", &["persisted-cmd"], None, None)],
            &config_names,
        );
        let d = store.definition_of("default/DB").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["config-cmd".to_string()],
            "config definition wins the merge"
        );
    }

    // ---- clear_config_owned_definitions / purge_stale_import_definitions
    //      (DR-0029 bundle 2 review CRITICAL / HIGH-1 fixes) ----
    //
    // Symmetric to `restore_drops_persisted_key_that_config_already_defines`
    // above (config wins over a *persisted-file*-origin definition): these
    // cover config winning over an *import-origin* (graceful-restart
    // handoff) definition instead, the scenario `restore_persisted_definitions`
    // never had to handle because a persisted-file restore never carries a
    // co-resident value entry the way a handoff import does.

    #[test]
    fn clear_config_owned_definitions_lets_a_changed_config_definition_win_over_import() {
        // Simulate what a graceful-restart handoff import leaves behind:
        // a definition for `OLD` with the *old* argv/TTL, plus its cached
        // value already resident (imported wholesale, before either
        // `clear_config_owned_definitions` or `register_definitions` runs).
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let clock = cache_warden::FakeClock::new();
        store
            .define_with_meta(
                "default/OLD",
                cmd_src(&["old-cmd"]).lower(),
                Ttl::new(None, Some(std::time::Duration::from_secs(3600))).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        store
            .set(
                "default/OLD",
                cmd_src(&["old-cmd"]).lower(),
                cache_warden::SecretBytes::new(b"cached-value".to_vec()),
                Ttl::new(None, Some(std::time::Duration::from_secs(3600))).unwrap(),
                &cap,
                &clock,
            )
            .unwrap();

        let config_names: std::collections::HashSet<String> =
            ["default/OLD".to_string()].into_iter().collect();
        clear_config_owned_definitions(&mut store, &config_names);

        // The definition is gone (cleared)...
        assert!(
            !store.is_defined("default/OLD"),
            "clear_config_owned_definitions must remove the import-origin definition"
        );
        // ...but the cached *value* must survive untouched.
        store
            .get("default/OLD", &cap, &clock)
            .ok()
            .flatten()
            .expect("value must still be present")
            .with_exposed(|b| assert_eq!(b, b"cached-value", "cached value must be undisturbed"));

        // register_definitions (the CRITICAL fix's actual caller) can now
        // insert the *new* config definition cleanly — no Conflict, even
        // though its argv differs from what was just cleared.
        let runner = CommandRunner::new();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &[pdef("OLD", &["new-cmd"], None, Some(10))],
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        let d = store.definition_of("default/OLD").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["new-cmd".to_string()],
            "the new config definition must win over the cleared import-origin one"
        );
        // The cached value is still untouched by register_definitions too
        // (it only registers definitions; it does not touch existing values
        // for keys not in `already_loaded`... this key already has a value,
        // but register_definitions never overwrites an existing value on a
        // non-eager entry).
        store
            .get("default/OLD", &cap, &clock)
            .ok()
            .flatten()
            .expect("value must still be present after register_definitions")
            .with_exposed(|b| assert_eq!(b, b"cached-value"));
    }

    #[test]
    fn purge_stale_import_definitions_removes_orphaned_config_removed_key_but_keeps_persisted_online_one()
     {
        // Two import-origin definitions land in the store (as a handoff
        // import would leave them): `REMOVED_FROM_CONFIG` (used to be a
        // config key in the *old* process, no longer is) and `STILL_ONLINE`
        // (a genuinely online definition, created via `kv.define` at
        // runtime, unrelated to any config).
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        store
            .define_with_meta(
                "default/REMOVED_FROM_CONFIG",
                cmd_src(&["stale-cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        store
            .define_with_meta(
                "default/STILL_ONLINE",
                cmd_src(&["online-cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();

        // The *current* config no longer mentions either key (both look
        // identical to the reconciliation logic at this point); only the
        // state file's own persisted names distinguish them.
        let config_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let persisted_names: std::collections::HashSet<String> =
            ["default/STILL_ONLINE".to_string()].into_iter().collect();

        let stale = purge_stale_import_definitions(&mut store, &config_names, &persisted_names);

        assert_eq!(
            stale,
            vec!["default/REMOVED_FROM_CONFIG".to_string()],
            "only the orphaned (config-removed, never-persisted) key must be purged"
        );
        assert!(
            !store.is_defined("default/REMOVED_FROM_CONFIG"),
            "the orphaned definition must actually be gone"
        );
        assert!(
            store.is_defined("default/STILL_ONLINE"),
            "a genuinely persisted online definition must survive the purge"
        );
    }

    #[test]
    fn purge_stale_import_definitions_keeps_current_config_keys() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        store
            .define_with_meta(
                "default/STILL_CONFIGURED",
                cmd_src(&["cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        let config_names: std::collections::HashSet<String> =
            ["default/STILL_CONFIGURED".to_string()]
                .into_iter()
                .collect();
        let persisted_names = std::collections::HashSet::new();

        let stale = purge_stale_import_definitions(&mut store, &config_names, &persisted_names);

        assert!(
            stale.is_empty(),
            "a current config key must never be purged"
        );
        assert!(store.is_defined("default/STILL_CONFIGURED"));
    }

    #[test]
    fn restore_skips_bad_ttl_without_aborting_others() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
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
        assert!(
            !store.is_defined("default/BAD"),
            "invalid TTL entry skipped"
        );
        assert!(
            store.is_defined("default/GOOD"),
            "subsequent entry still restored"
        );
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
