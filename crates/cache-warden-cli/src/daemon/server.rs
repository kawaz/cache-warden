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
    AllowAll, Authenticator, CommandAuthenticator, CommandRunner, ProcessInfo, ProcessInspector,
    SourceRunner, Store, SystemClock, SystemInspector, Ttl, ValueSource,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::handler::{self, HandlerCtx};
use super::peer::peer_pid;
use crate::config::{Config, PreloadEntry};
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
    socket_path: String,
    pid: u32,
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
            socket_path: String::new(),
            pid: std::process::id(),
        }
    }
}

/// Run the daemon in the foreground until SIGINT / SIGTERM, using `config`.
///
/// Binds `socket_path`, preloads the config's `[kv.*]` command entries, serves
/// the control socket, and removes the socket file on clean shutdown.
///
/// `socket_path` is already resolved by the caller (CLI `--socket` > env >
/// `[daemon].socket` > built-in default); the daemon does not re-derive it.
pub async fn run(socket_path: PathBuf, config: Config) -> io::Result<()> {
    let listener = bind_control_socket(&socket_path)?;

    let runner = CommandRunner::new();
    let clock = SystemClock::new();
    let mut store = Store::new();

    // Preload `[kv.*]` command entries before serving. A failed preload is a
    // warning, not fatal: the daemon stays up and the entry is simply absent
    // until a later `kv set` (DR-0010).
    preload_entries(&mut store, &runner, &clock, &config.preload_entries());

    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        runner,
        auth: build_authenticator(&config),
        clock,
        socket_path: socket_path.display().to_string(),
        pid: std::process::id(),
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
    let authsock_handles = super::authsock::spawn_listeners(
        &config.authsock_sockets(),
        &config.authsock_sources(),
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

/// Preload command-source entries into `store` at startup (DR-0010).
///
/// Each entry's command is run once now so the first `get` is a cache hit. A
/// failure (spawn error, non-zero exit, bad TTL bounds) is reported as a single
/// stderr warning line — **never** including the command's output, and never
/// fatal: the entry is left unregistered and can be set later via `kv set`. The
/// daemon must come up even if an upstream secret source is temporarily down.
fn preload_entries<R, C>(store: &mut Store, runner: &R, clock: &C, entries: &[PreloadEntry])
where
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
                eprintln!("cache-warden: preload `{}` skipped: {e}", entry.name);
                continue;
            }
        };
        match runner.run(&entry.command) {
            Ok(value) => {
                let source = ValueSource::command(entry.command.clone());
                store.set(entry.name.clone(), source, value, ttl, clock);
            }
            Err(e) => {
                // The RunError Display is already secret-free (stderr redacted).
                eprintln!("cache-warden: preload `{}` failed: {e}", entry.name);
            }
        }
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

    let ctx = HandlerCtx {
        auth,
        runner: &shared.runner,
        clock: &shared.clock,
        pid: shared.pid,
        version: VERSION,
        socket: &shared.socket_path,
        requester: requester.as_deref(),
    };
    handler::handle_request(&mut store, &ctx, req)
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
            socket_path: "/tmp/test.sock".into(),
            pid: std::process::id(),
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
        let resp = run_request(&s, None, Request::KvGet { key: "K".into() });
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

    // ---- preload_entries ----

    #[test]
    fn preload_populates_command_entries() {
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![PreloadEntry {
            name: "TOK".into(),
            command: vec!["printf".into(), "tok-value".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
        }];
        preload_entries(&mut store, &runner, &clock, &entries);
        let secret = store.get("TOK", &clock).expect("entry preloaded");
        assert_eq!(secret.expose_secret(), b"tok-value");
    }

    #[test]
    fn preload_failure_is_non_fatal_and_leaves_entry_absent() {
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let mut store = Store::new();
        let entries = vec![
            PreloadEntry {
                name: "BAD".into(),
                command: vec!["this-binary-does-not-exist-cw-preload".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
            },
            PreloadEntry {
                name: "GOOD".into(),
                command: vec!["printf".into(), "ok".into()],
                soft_ttl_secs: None,
                hard_ttl_secs: None,
            },
        ];
        // Must not panic; the bad entry is skipped, the good one still loads.
        preload_entries(&mut store, &runner, &clock, &entries);
        assert!(store.get("BAD", &clock).is_none(), "failed preload absent");
        assert_eq!(
            store.get("GOOD", &clock).unwrap().expose_secret(),
            b"ok",
            "subsequent preload still runs"
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
