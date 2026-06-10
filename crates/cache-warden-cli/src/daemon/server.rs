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
    AllowAll, CommandRunner, ProcessInfo, ProcessInspector, Store, SystemClock, SystemInspector,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::handler::{self, HandlerCtx};
use super::peer::peer_pid;
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

/// Shared daemon state handed to each connection task.
struct Shared {
    store: Mutex<Store>,
    runner: Runner,
    socket_path: String,
    pid: u32,
}

/// Run the daemon in the foreground until SIGINT / SIGTERM.
///
/// Binds `socket_path`, serves the control socket, and removes the socket file
/// on clean shutdown.
pub async fn run(socket_path: PathBuf) -> io::Result<()> {
    let listener = bind_control_socket(&socket_path)?;

    let shared = Arc::new(Shared {
        store: Mutex::new(Store::new()),
        runner: CommandRunner::new(),
        socket_path: socket_path.display().to_string(),
        pid: std::process::id(),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server = tokio::spawn(serve(listener, Arc::clone(&shared), shutdown_rx));

    println!(
        "cache-warden daemon listening on {} (pid {}). Press Ctrl+C to stop.",
        shared.socket_path, shared.pid
    );

    wait_for_shutdown().await;
    let _ = shutdown_tx.send(true);
    let _ = server.await;

    // Clean up the socket file (best effort).
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
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

    let clock = SystemClock::new();
    let auth = AllowAll; // DR-0009: AllowAll wired now; TouchID in a later iteration.

    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => return Response::error(ErrorKind::Internal, "store lock poisoned"),
    };

    let ctx = HandlerCtx {
        auth: &auth,
        runner: &shared.runner,
        clock: &clock,
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
