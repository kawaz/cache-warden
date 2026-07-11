//! Daemon-side IPC client for the persistent `cache-warden-approver` GUI helper
//! (draft-DR-0031 §3/§4/§7/§8/§10).
//!
//! # Scope (Phase 1.6 Block 1: helper 常駐化)
//!
//! Owns the approver socket lifecycle *and* the single long-lived connection
//! to the spawned helper. The daemon binds a dedicated approver socket (§4:
//! separate from `control.sock` so a multi-second human approval never sits
//! behind `kv`/`status` queue traffic), spawns the helper as its client, and
//! authenticates the peer on `accept` (§Security). Every subsequent
//! `ApproveRequest`/`ApproveResponse` pair — one per approval prompt — is
//! multiplexed as JSON Lines over that same verified connection until the
//! daemon shuts down (§3 採用案 (b): daemon 起動時 1 回 spawn の常駐 helper,
//! rejected on-demand spawn's 100–300 ms latency).
//!
//! # Serialization (§8 二重 dialog 防止)
//!
//! Approvals are inherently a human-serial affair (one dialog on screen at a
//! time), so [`ApproverClient::request`] takes the internal state lock for the
//! entire send + receive cycle. There is no concurrent-request path in Phase
//! 1.6 — future work that wants overlapping prompts would need to revisit
//! this lock and the helper-side dialog state together.
//!
//! # Helper-death recovery (§7 逆方向)
//!
//! A dead helper — writes returning `BrokenPipe`, reads returning EOF — is
//! recycled once per request: the child is killed, a fresh helper is spawned
//! and re-verified, and the pending request is retried exactly once. Failure
//! on that retry surfaces to the caller (which fails guarded entries closed,
//! §9 `helper_down`). Unbounded respawn would hide a persistently-broken
//! helper as a slow success; a single retry is enough to survive a crashed
//! helper without masking a systemic failure.
//!
//! # Stale-response discipline
//!
//! Every response carries the request's `request_id` echoed back. If a
//! response arrives whose id does not match the pending request, it is
//! logged and discarded (a daemon-side timeout that fired while the helper
//! was still processing the previous prompt leaves a late-arriving response
//! on the pipe; consuming and dropping it prevents that stale reply from
//! being handed to the *next* request). The read loop keeps reading until it
//! sees the matching id or the outer per-request timeout fires.
//!
//! # Wire direction (§4 vs. this implementation)
//!
//! draft-DR-0031 §4's prose describes the helper as the listener. This
//! implementation binds/accepts on the **daemon** side and has the helper
//! **connect** instead — confirmed as the intended final direction (a
//! socketpair-shaped design where the daemon, which spawns the helper, also
//! owns the rendezvous point). The DR text itself is updated separately; this
//! module is not the place to carry that correction.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cache_warden_approver::wire::{ApproveRequest, ApproveResponse, WIRE_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use cache_warden_approver::CACHE_WARDEN_IDENTIFIER_PREFIX;

/// Bind the approver socket, removing a stale leftover first.
///
/// Mirrors `server::bind_control_socket`'s stale-detection (a successful
/// connect to an existing path means another listener is already live there —
/// refuse to clobber it; a failed connect means a crashed process's leftover
/// socket file — remove and rebind), on a separate socket path so approval
/// traffic never shares a queue with `control.sock` (§4).
#[allow(dead_code)] // Phase 1.6+: wired from daemon startup once guard integration lands
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another cache-warden-approver listener is already bound at {}",
                        path.display()
                    ),
                ));
            }
            Err(_) => {
                // Stale socket from a dead helper/daemon; remove and rebind.
                std::fs::remove_file(path)?;
            }
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Restrictive umask so the socket is created 0600 with no TOCTOU window
    // (same rationale as `server::bind_control_socket`).
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(path);
    unsafe {
        libc::umask(old_umask);
    }
    let listener = listener?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(listener)
}

/// Spawn the helper binary as the approver socket's client.
///
/// The daemon binds first (see [`bind`]) and only then spawns the helper
/// pointed at that path via `--socket` — the reverse of a listener racing its
/// own client into existence. This function does not wait for the helper to
/// actually connect; the caller's `accept_verified` does that.
///
/// `kill_on_drop`: the helper is a persistent process bound to the daemon's
/// lifetime — if the daemon side drops the `Child` without an explicit kill
/// (error path, cancelled future), an orphan helper would keep waiting on a
/// socket the daemon no longer owns. Killing it with the handle is always
/// the right disposal; [`ApproverClient::shutdown`] then removes the socket
/// file.
#[allow(dead_code)] // Phase 1.6+: wired from daemon startup once guard integration lands
pub fn spawn_helper(helper_path: &Path, socket_path: &Path) -> io::Result<Child> {
    Command::new(helper_path)
        .arg("--socket")
        .arg(socket_path)
        .kill_on_drop(true)
        .spawn()
}

/// Accept connections on `listener` until one passes peer code-signature
/// verification against this process's (draft-DR-0031 §Security), and return
/// that verified `UnixStream`. Fail-closed on any deviation: not-a-cache-
/// warden-family Identifier, wrong Team ID, signature validity failure,
/// cross-uid connection, missing audit token.
///
/// A rejected peer is logged and its stream dropped (the peer sees `EOF`),
/// and the loop **keeps accepting**: returning an error on the first bad
/// peer would let any same-uid process deny approvals wholesale by racing a
/// connect ahead of the legitimate helper (connect → get rejected → daemon
/// gives up → real helper finds the listener gone). The loop is unbounded
/// here by design — the caller's overall connect timeout bounds it.
///
/// **Non-macOS**: the underlying
/// [`macos_process_inspect::codesign::verify_peer`] shim uniformly rejects
/// (there is no `Security.framework` to answer the question), which is the
/// correct fail-closed default. The daemon is macOS-only in production —
/// this arm exists to keep the workspace's Linux CI build green.
#[allow(dead_code)] // Phase 1.6+: wired from daemon startup once guard integration lands
pub async fn accept_verified(listener: &UnixListener) -> io::Result<UnixStream> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        match macos_process_inspect::codesign::verify_peer(fd, CACHE_WARDEN_IDENTIFIER_PREFIX) {
            Ok(()) => return Ok(stream),
            Err(e) => {
                eprintln!(
                    "cache-warden: approver: rejecting peer that failed code-signature verification (still waiting for the real helper): {e}"
                );
            }
        }
    }
}

/// A live, verified helper connection: split I/O halves for concurrent write
/// (writer half) + read (reader half) usage plus the owning `Child`. `child`
/// is `Option` only so [`ApproverClient::shutdown`] and the recovery path in
/// [`ApproverClient::request`] can `take()` the handle to await the kill
/// without dropping the whole struct; a live connection always has `Some`.
struct HelperConn {
    /// The spawned helper process. `None` in test-only paths that connect a
    /// same-process fake task instead of forking a real binary (no process
    /// to kill on shutdown); production always has `Some`.
    child: Option<Child>,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl HelperConn {
    /// Kill the helper (if any) and await reaping. Silent on already-dead
    /// helpers: the recovery path calls this precisely because writes/reads
    /// hit EOF, and we do not care why the child is gone by the time we
    /// reach `wait`.
    async fn dispose(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
            let _ = c.wait().await;
        }
    }
}

/// Strategy for (re)establishing the helper connection. Split from
/// [`ApproverClient`] so the production path (real spawn + code-signature
/// verification) and the test path (in-process fake task + raw accept) share
/// the same request/reconnect state machine without either being able to
/// compile a shortcut around the other's discipline.
///
/// The `#[cfg(test)]` variant carries an `on_reconnect` callback that the
/// test uses to bring up the next fake helper task before the daemon side
/// awaits the accept — mirroring the production sequence "spawn helper →
/// accept" without launching a real process. `verified` toggles peer
/// code-signature verification: `true` exercises [`accept_verified`] as-is;
/// `false` accepts the fake peer raw (the test binary is ad-hoc signed and
/// would be rejected by design — see the Phase 1.5 anti-DoS test).
enum Connector {
    Real {
        helper_path: PathBuf,
        connect_timeout: Duration,
    },
    #[cfg(test)]
    Test {
        connect_timeout: Duration,
        verified: bool,
        on_reconnect:
            std::sync::Arc<dyn Fn(std::path::PathBuf) -> tokio::task::JoinHandle<()> + Send + Sync>,
    },
}

impl Connector {
    async fn spawn_and_accept(
        &self,
        listener: &UnixListener,
        socket_path: &Path,
    ) -> io::Result<HelperConn> {
        match self {
            Connector::Real {
                helper_path,
                connect_timeout,
            } => {
                let child = spawn_helper(helper_path, socket_path)?;
                let accept_fut = accept_verified(listener);
                let stream = match tokio::time::timeout(*connect_timeout, accept_fut).await {
                    Ok(r) => r?,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "helper did not connect within {connect_timeout:?} (accept timed out)"
                            ),
                        ));
                    }
                };
                let (rh, wh) = stream.into_split();
                Ok(HelperConn {
                    child: Some(child),
                    reader: BufReader::new(rh),
                    writer: wh,
                })
            }
            #[cfg(test)]
            Connector::Test {
                connect_timeout,
                verified,
                on_reconnect,
            } => {
                let _handle = on_reconnect(socket_path.to_path_buf());
                let accept_fut = async {
                    if *verified {
                        accept_verified(listener).await
                    } else {
                        let (s, _addr) = listener.accept().await?;
                        Ok(s)
                    }
                };
                let stream = match tokio::time::timeout(*connect_timeout, accept_fut).await {
                    Ok(r) => r?,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "helper did not connect within {connect_timeout:?} (accept timed out)"
                            ),
                        ));
                    }
                };
                let (rh, wh) = stream.into_split();
                Ok(HelperConn {
                    child: None,
                    reader: BufReader::new(rh),
                    writer: wh,
                })
            }
        }
    }
}

/// Owned inner state guarded by [`ApproverClient::inner`]'s mutex. `listener`
/// and `conn` share the mutex because reconnect swaps `conn` while `listener`
/// is only ever consulted from inside the same critical section (accept for
/// the freshly-spawned helper); a finer split would give no concurrency
/// (approval is human-serial, §8) at the cost of a second lock.
struct InnerState {
    listener: UnixListener,
    conn: Option<HelperConn>,
    connector: Connector,
}

/// Persistent daemon-side handle for the spawned `cache-warden-approver`
/// helper. Constructed once at daemon startup ([`ApproverClient::start`]),
/// dispatches every approval request through [`ApproverClient::request`],
/// and releases the helper + socket file with [`ApproverClient::shutdown`]
/// (Drop deliberately does *not* run this — an `async` cleanup on drop would
/// leak the child on cancellation paths; the daemon shutdown sequence calls
/// `shutdown` explicitly, see draft-DR-0029 graceful-restart integration).
#[allow(dead_code)] // Phase 1.6+: wired from daemon startup once guard integration lands
pub struct ApproverClient {
    inner: Mutex<InnerState>,
    socket_path: PathBuf,
    /// Latest verified helper's pid, updated on `start` and on every
    /// successful `spawn_and_accept` in the recovery path. Read by
    /// [`shutdown`](Self::shutdown) so it can `SIGKILL` the helper without
    /// first taking `inner` — a pending `request` holds `inner` for the
    /// whole approval lifetime (§8 "approval is human-serial"), and
    /// waiting on that lock would make graceful restart (§10 "helper must
    /// die before the daemon execs itself") block on human interaction.
    /// `0` (POSIX-invalid pid) is the "no live helper" sentinel.
    helper_pid: std::sync::atomic::AtomicU32,
}

/// Snapshot the helper's pid off a [`HelperConn`] for
/// [`ApproverClient::helper_pid`]. `0` means "no pid to record" — either the
/// test connector has no `Child`, or `tokio::process::Child::id` returned
/// `None` because the child was already reaped (a benign race; the caller's
/// next `spawn_and_accept` will refresh it).
fn helper_pid_of(conn: &HelperConn) -> u32 {
    conn.child.as_ref().and_then(|c| c.id()).unwrap_or(0)
}

#[allow(dead_code)] // Phase 1.6+: wired from daemon startup once guard integration lands
impl ApproverClient {
    /// Bind the socket, spawn the helper, and hold the verified connection
    /// open. Failures during any of these steps propagate — the daemon
    /// startup path is meant to fail fast if the helper cannot come up,
    /// rather than deferring the diagnosis to the first approval request
    /// (which would present as an unexplained approval timeout to a user).
    ///
    /// `connect_timeout` bounds the accept alone (helper failing to
    /// `connect()` back), not the request/response exchange — those get
    /// their own per-call timeout on [`request`](Self::request).
    pub async fn start(
        helper_path: PathBuf,
        socket_path: PathBuf,
        connect_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = bind(&socket_path)?;
        let connector = Connector::Real {
            helper_path,
            connect_timeout,
        };
        let conn = connector.spawn_and_accept(&listener, &socket_path).await?;
        let helper_pid = std::sync::atomic::AtomicU32::new(helper_pid_of(&conn));
        Ok(Self {
            inner: Mutex::new(InnerState {
                listener,
                conn: Some(conn),
                connector,
            }),
            socket_path,
            helper_pid,
        })
    }

    /// Send `request` on the persistent connection and wait for its matching
    /// response, bounded by `timeout`.
    ///
    /// Recovery: if the write or read fails in a way that signals a dead
    /// helper (BrokenPipe / UnexpectedEof / ConnectionReset /
    /// ConnectionAborted), the child is killed, a fresh helper is spawned
    /// and re-verified, and `request` is retried exactly once. A second
    /// failure surfaces to the caller.
    ///
    /// Stale-response filtering happens inline in [`do_exchange`]: a
    /// response whose `request_id` does not match the pending request is
    /// discarded (with a warning) and the loop keeps reading until either
    /// the matching id arrives or the outer `timeout` fires.
    pub async fn request(
        &self,
        request: &ApproveRequest,
        timeout: Duration,
    ) -> io::Result<ApproveResponse> {
        let mut guard = self.inner.lock().await;
        let InnerState {
            listener,
            conn,
            connector,
        } = &mut *guard;

        // 1st attempt on the current connection (if any).
        let first_err = match conn.as_mut() {
            Some(c) => match do_exchange(c, request, timeout).await {
                Ok(resp) => return Ok(resp),
                Err(e) => Some(e),
            },
            None => None,
        };

        // Only recover on connection-death shapes; other errors (InvalidData,
        // TimedOut on a live helper that simply took too long) belong to the
        // caller and are not retried — a stuck live helper is not a
        // reconnect candidate, and retrying an InvalidData reply just wastes
        // the next request on the same broken helper.
        if let Some(e) = &first_err
            && !is_conn_death(e)
        {
            return Err(first_err.unwrap());
        }

        // Kill and drop the dead connection (if any) before spawning the
        // replacement — a second helper connecting while the first still
        // holds the accepted socket would race the reconnect's `accept`.
        // Retire the pid from `helper_pid` before disposing so a concurrent
        // `shutdown` cannot mistakenly SIGKILL the freshly-spawned successor
        // before we store its pid below.
        if let Some(mut old) = conn.take() {
            self.helper_pid
                .store(0, std::sync::atomic::Ordering::Relaxed);
            old.dispose().await;
        }

        let new_conn = connector
            .spawn_and_accept(listener, &self.socket_path)
            .await?;
        self.helper_pid.store(
            helper_pid_of(&new_conn),
            std::sync::atomic::Ordering::Relaxed,
        );
        *conn = Some(new_conn);

        // Retry exactly once on the fresh connection. A second death here
        // surfaces to the caller (guarded entries then fail closed, §9).
        do_exchange(conn.as_mut().unwrap(), request, timeout).await
    }

    /// Kill the helper, drop the connection, and remove the socket file.
    /// Idempotent — a second call is a no-op. Called by the daemon shutdown
    /// path so the next daemon start's `bind` does not have to fall back to
    /// its stale-socket removal branch on a clean exit.
    ///
    /// The `SIGKILL` runs *before* taking `inner`: an in-flight
    /// [`request`](Self::request) is holding `inner` for the whole approval
    /// lifetime (§8 human-serial), and waiting on that lock would make
    /// graceful restart (§10 "helper must die before the daemon execs
    /// itself") block on human interaction — the very failure mode that
    /// motivates DR-0029's graceful-restart contract. Killing the helper's
    /// pid directly makes the pending request's `read`/`write` error out
    /// (BrokenPipe / EOF), releasing the lock so this function can finish
    /// the socket-file cleanup and return.
    pub async fn shutdown(&self) {
        let pid = self
            .helper_pid
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        if pid != 0 {
            // SAFETY: `pid` was captured under this daemon's ownership of
            // the helper process (spawned via `Command::spawn`, `Child`
            // kept in `InnerState`). This daemon is the only parent that
            // will reap the child (`tokio::process::Child::wait` inside
            // `HelperConn::dispose`), so between `Child::spawn` and the
            // `.wait()` below there is no window in which the pid could
            // be reused by an unrelated process. `SIGKILL` to a stale-but-
            // -not-yet-reaped pid is a harmless no-op on already-dead
            // processes.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
        let mut guard = self.inner.lock().await;
        if let Some(mut conn) = guard.conn.take() {
            conn.dispose().await;
        }
        // Best-effort: the socket path may already be gone (helper crashed
        // and someone else swept it, unit test tore it down). What matters
        // is that after shutdown the next `bind` on a live daemon does not
        // hit "another listener already bound at ..." — see `bind`'s
        // stale-detection path.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn is_conn_death(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

/// Send `request` over `conn`, then read responses until one matches
/// `request_id` (discarding earlier stale ids with a warning) or `timeout`
/// fires. A wire-version mismatch on any read is an immediate
/// `InvalidData` — a future breaking v2 helper's response must not be
/// half-parsed into v1 semantics.
async fn do_exchange(
    conn: &mut HelperConn,
    request: &ApproveRequest,
    timeout: Duration,
) -> io::Result<ApproveResponse> {
    let exchange = async {
        let mut line = serde_json::to_string(request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        conn.writer.write_all(line.as_bytes()).await?;
        conn.writer.flush().await?;

        loop {
            let mut resp_line = String::new();
            let n = conn.reader.read_line(&mut resp_line).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "helper closed the approver socket before responding",
                ));
            }
            let resp = serde_json::from_str::<ApproveResponse>(resp_line.trim_end())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if resp.v != WIRE_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unsupported approver wire version {} (daemon speaks {})",
                        resp.v, WIRE_VERSION
                    ),
                ));
            }
            if resp.request_id != request.request_id {
                // A daemon-side timeout on a previous request can leave a
                // late-arriving response on the pipe; drop it and keep
                // reading. Logging (not silently discarding) so the
                // condition is visible in daemon logs.
                eprintln!(
                    "cache-warden: approver: discarding stale response request_id={:?} while awaiting {:?}",
                    resp.request_id, request.request_id
                );
                continue;
            }
            return Ok(resp);
        }
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("helper did not respond within {timeout:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden_approver::wire::{
        AuditToken, Outcome, ProcessChainEntry, Requester, WIRE_VERSION,
    };
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::Mutex as TokioMutex;

    /// A minimal `ApproveRequest` for round-trip tests: no guard, single-entry
    /// chain. `wire.rs`'s own tests cover the fully-populated shape; this
    /// module only needs *a* valid request to exercise the persistent
    /// connection lifecycle.
    fn test_request(request_id: &str) -> ApproveRequest {
        ApproveRequest {
            v: WIRE_VERSION,
            request_id: request_id.to_string(),
            key: "ns/test-key".to_string(),
            operation: "get".to_string(),
            requester: Requester {
                chain: vec![ProcessChainEntry {
                    pid: 4242,
                    ppid: 1,
                    path: "/bin/zsh".to_string(),
                    start_time: 1,
                }],
                audit_token: AuditToken {
                    euid: 501,
                    ruid: 501,
                    egid: 20,
                    pid: 4242,
                    pid_version: 1,
                },
                responsible_bundle_id: None,
            },
            guard_eval: None,
            timeout_secs: 60,
        }
    }

    fn test_socket_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cache-warden-approver-test-{}-{}-{tag}.sock",
            std::process::id(),
            n
        ))
    }

    /// Build an `ApproverClient` wired to a test-only `Connector::Test` whose
    /// `on_reconnect` closure spawns a fresh fake-helper task each time the
    /// client reconnects. `spawn_fake` is called once for the initial
    /// connection and again for every recovery path.
    async fn client_with_fake_helper<F>(
        socket_path: std::path::PathBuf,
        spawn_fake: F,
    ) -> io::Result<ApproverClient>
    where
        F: Fn(std::path::PathBuf) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
    {
        let listener = bind(&socket_path)?;
        let connector = Connector::Test {
            connect_timeout: Duration::from_secs(5),
            verified: false,
            on_reconnect: Arc::new(spawn_fake),
        };
        let conn = connector.spawn_and_accept(&listener, &socket_path).await?;
        let helper_pid = std::sync::atomic::AtomicU32::new(helper_pid_of(&conn));
        Ok(ApproverClient {
            inner: Mutex::new(InnerState {
                listener,
                conn: Some(conn),
                connector,
            }),
            socket_path,
            helper_pid,
        })
    }

    /// A fake helper that processes N requests over one connection: reads a
    /// line, decodes an `ApproveRequest`, calls `make_response(req)` to
    /// derive the reply, writes it, and repeats. Exits cleanly on EOF or
    /// when `make_response` returns `None` (simulating an early close).
    fn spawn_scripted_helper(
        socket_path: std::path::PathBuf,
        make_response: Arc<dyn Fn(ApproveRequest) -> Option<Vec<u8>> + Send + Sync>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let stream = UnixStream::connect(&socket_path)
                .await
                .expect("fake helper connect");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            loop {
                let mut line = String::new();
                let n = match reader.read_line(&mut line).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                let req: ApproveRequest = match serde_json::from_str(line.trim_end()) {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let Some(bytes) = make_response(req) else {
                    break;
                };
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
                if write_half.flush().await.is_err() {
                    break;
                }
            }
        })
    }

    fn encode_response(resp: &ApproveResponse) -> Vec<u8> {
        let mut s = serde_json::to_string(resp).expect("encode");
        s.push('\n');
        s.into_bytes()
    }

    /// The core persistence property: N sequential `ApproveRequest`s all
    /// flow over the **same** verified connection to the helper — no rebind,
    /// no respawn between requests. Exercised by having the fake helper
    /// return `Approved` for every request it sees.
    #[tokio::test]
    async fn client_streams_multiple_requests_over_single_connection() {
        let socket_path = test_socket_path("persistent");
        let spawn_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let spawn_count_clone = spawn_count.clone();
        let client = client_with_fake_helper(socket_path.clone(), move |sp| {
            spawn_count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let make = Arc::new(|req: ApproveRequest| {
                Some(encode_response(&ApproveResponse {
                    v: WIRE_VERSION,
                    request_id: req.request_id,
                    outcome: Outcome::Approved,
                    biometric_kind: Some("TouchID".to_string()),
                }))
            });
            spawn_scripted_helper(sp, make)
        })
        .await
        .expect("start client");

        for id in ["r-1", "r-2", "r-3"] {
            let req = test_request(id);
            let resp = client
                .request(&req, Duration::from_secs(5))
                .await
                .unwrap_or_else(|e| panic!("request {id} failed: {e}"));
            assert_eq!(resp.request_id, id);
            assert_eq!(resp.outcome, Outcome::Approved);
        }
        // Only the initial spawn should have fired — no reconnect across the
        // three requests (that would signal we lost the persistent property).
        assert_eq!(
            spawn_count.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "helper must not be respawned between requests on the persistent path"
        );

        client.shutdown().await;
    }

    /// A response arriving with a `request_id` from a previous (already
    /// timed-out) request must be discarded — the client keeps reading
    /// until it sees the matching id. Otherwise a daemon-side timeout on
    /// request A followed by a late reply for A would poison request B.
    #[tokio::test]
    async fn client_discards_stale_response_and_matches_by_request_id() {
        let socket_path = test_socket_path("stale");
        // Fake helper: for every request received, reply first with a stale
        // id, then with the correct id. `do_exchange` should skip the stale
        // one and return the matching one.
        let make = Arc::new(|req: ApproveRequest| {
            let stale = encode_response(&ApproveResponse {
                v: WIRE_VERSION,
                request_id: "stale-from-prior-request".to_string(),
                outcome: Outcome::Approved,
                biometric_kind: None,
            });
            let good = encode_response(&ApproveResponse {
                v: WIRE_VERSION,
                request_id: req.request_id,
                outcome: Outcome::Approved,
                biometric_kind: Some("TouchID".to_string()),
            });
            let mut both = stale;
            both.extend_from_slice(&good);
            Some(both)
        });
        let make_clone = make.clone();
        let client = client_with_fake_helper(socket_path.clone(), move |sp| {
            spawn_scripted_helper(sp, make_clone.clone())
        })
        .await
        .expect("start client");

        let req = test_request("real-id");
        let resp = client
            .request(&req, Duration::from_secs(5))
            .await
            .expect("stale response must be skipped");
        assert_eq!(resp.request_id, "real-id");
        assert_eq!(resp.outcome, Outcome::Approved);

        client.shutdown().await;
    }

    /// After the fake helper closes its connection, the next request must
    /// trigger a reconnect (a fresh fake task spawned via `on_reconnect`)
    /// and succeed on the retry. Verifies the single-retry recovery path
    /// end-to-end without launching a real process.
    #[tokio::test]
    async fn client_reconnects_after_helper_dies_and_retries_request() {
        let socket_path = test_socket_path("recover");
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let client = client_with_fake_helper(socket_path.clone(), move |sp| {
            let n = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // 1st spawn: helper dies (returns `None` after reading one line
            // → loop breaks → connection dropped, giving the daemon EOF).
            // 2nd spawn: helper responds normally.
            let make: Arc<dyn Fn(ApproveRequest) -> Option<Vec<u8>> + Send + Sync> = if n == 0 {
                Arc::new(|_req: ApproveRequest| None)
            } else {
                Arc::new(|req: ApproveRequest| {
                    Some(encode_response(&ApproveResponse {
                        v: WIRE_VERSION,
                        request_id: req.request_id,
                        outcome: Outcome::Approved,
                        biometric_kind: Some("TouchID".to_string()),
                    }))
                })
            };
            spawn_scripted_helper(sp, make)
        })
        .await
        .expect("start client");

        let req = test_request("after-recovery");
        let resp = client
            .request(&req, Duration::from_secs(5))
            .await
            .expect("request must succeed after single reconnect");
        assert_eq!(resp.request_id, "after-recovery");
        assert_eq!(resp.outcome, Outcome::Approved);
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "on_reconnect must have been invoked twice (initial + one recovery)"
        );

        client.shutdown().await;
    }

    /// The helper may legitimately return `Outcome::Denied` (guard-fail path,
    /// draft-DR-0031 §Security) or `Outcome::PeerGone` (§7 peer exit before
    /// authentication). Both must reach the caller unchanged — the client
    /// does not branch on outcome (that is the guarded-get caller's job).
    /// Pinning this shape guards against a future refactor that would
    /// mistakenly treat non-Approved outcomes as errors.
    #[tokio::test]
    async fn client_passes_through_denied_and_peer_gone_outcomes() {
        for (tag, outcome) in [
            ("denied", Outcome::Denied),
            ("peer-gone", Outcome::PeerGone),
        ] {
            let socket_path = test_socket_path(tag);
            let make = Arc::new(move |req: ApproveRequest| {
                Some(encode_response(&ApproveResponse {
                    v: WIRE_VERSION,
                    request_id: req.request_id,
                    outcome,
                    biometric_kind: None,
                }))
            });
            let make_clone = make.clone();
            let client = client_with_fake_helper(socket_path.clone(), move |sp| {
                spawn_scripted_helper(sp, make_clone.clone())
            })
            .await
            .expect("start client");

            let req = test_request("pass-through");
            let resp = client
                .request(&req, Duration::from_secs(5))
                .await
                .expect("non-Approved outcome must be delivered, not turned into Err");
            assert_eq!(resp.outcome, outcome);

            client.shutdown().await;
        }
    }

    /// A wire-version mismatch on the response must fail as `InvalidData`,
    /// not be half-parsed into v1 semantics — a future breaking v2 helper
    /// paired with a v1 daemon must not have its outcome trusted.
    #[tokio::test]
    async fn client_rejects_unknown_wire_version() {
        let socket_path = test_socket_path("bad-version");
        let make = Arc::new(|req: ApproveRequest| {
            Some(encode_response(&ApproveResponse {
                v: WIRE_VERSION + 1,
                request_id: req.request_id,
                outcome: Outcome::Approved,
                biometric_kind: None,
            }))
        });
        let make_clone = make.clone();
        let client = client_with_fake_helper(socket_path.clone(), move |sp| {
            spawn_scripted_helper(sp, make_clone.clone())
        })
        .await
        .expect("start client");

        let req = test_request("v-mismatch");
        let err = client
            .request(&req, Duration::from_secs(5))
            .await
            .expect_err("wire version mismatch must fail loudly");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("wire version"),
            "error should name the version mismatch: {err}"
        );

        client.shutdown().await;
    }

    /// `shutdown` must remove the socket file so the next daemon start's
    /// `bind` does not have to fall back to its stale-socket removal branch
    /// on a clean exit — draft-DR-0031 residual issue "socket file の
    /// graceful shutdown 時 cleanup".
    #[tokio::test]
    async fn shutdown_removes_socket_file() {
        let socket_path = test_socket_path("cleanup");
        let make = Arc::new(|req: ApproveRequest| {
            Some(encode_response(&ApproveResponse {
                v: WIRE_VERSION,
                request_id: req.request_id,
                outcome: Outcome::Approved,
                biometric_kind: None,
            }))
        });
        let make_clone = make.clone();
        let client = client_with_fake_helper(socket_path.clone(), move |sp| {
            spawn_scripted_helper(sp, make_clone.clone())
        })
        .await
        .expect("start client");
        assert!(socket_path.exists(), "socket file created by bind");
        client.shutdown().await;
        assert!(
            !socket_path.exists(),
            "socket file must be gone after shutdown"
        );
    }

    /// Bind-then-spawn ordering pin: `Connector::spawn_and_accept` requires
    /// a bound listener; a fake helper that tries to `connect()` before the
    /// listener exists gets ECONNREFUSED / ENOENT. This is why `start`
    /// binds first *then* spawns/reconnects — if the order were reversed,
    /// the helper would race the listener into existence and hit the same
    /// pre-bind error. Documented as issue "bind→spawn 順序の test pin".
    #[tokio::test]
    async fn connect_before_bind_fails_which_is_why_start_binds_first() {
        let socket_path = test_socket_path("pre-bind");
        // No `bind` here — verify a client connect *before* bind fails.
        let err = UnixStream::connect(&socket_path)
            .await
            .expect_err("connect before bind must fail (no listener yet)");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ),
            "expected NotFound/ConnectionRefused, got {:?}",
            err.kind()
        );
    }

    /// A rejected peer must not make `accept_verified` give up (§Security
    /// anti-DoS): a same-uid impostor racing a connect ahead of the real
    /// helper gets its stream dropped (EOF) while the daemon keeps waiting.
    /// The test binary is ad-hoc signed → its own connection is rejected by
    /// `verify_peer` by design, which is exactly the impostor shape. Copied
    /// from Phase 1.5 to keep the anti-DoS contract pinned even after the
    /// module was reshaped for the persistent client.
    #[tokio::test]
    async fn accept_verified_keeps_waiting_after_rejecting_a_peer() {
        let socket_path = test_socket_path("reject-loop");
        let listener = bind(&socket_path).expect("bind");

        let impostor_socket = socket_path.clone();
        let impostor = tokio::spawn(async move {
            let stream = UnixStream::connect(&impostor_socket)
                .await
                .expect("impostor connect");
            let (read_half, _write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.expect("read");
            assert_eq!(n, 0, "rejected impostor must see EOF, not a request line");
        });

        let still_waiting =
            tokio::time::timeout(Duration::from_millis(500), accept_verified(&listener)).await;
        assert!(
            still_waiting.is_err(),
            "accept_verified must keep accepting after a rejection, not resolve"
        );

        impostor.await.expect("impostor task should not panic");
        let _ = std::fs::remove_file(&socket_path);
    }

    /// `spawn_helper`'s argv wiring, exercised with `/usr/bin/true` standing
    /// in for the real helper. Kept from Phase 1.4 so the spawn command
    /// shape is pinned even after the persistent-client refactor (the
    /// production path relies on `spawn_helper` inside `Connector::Real`).
    #[tokio::test]
    async fn spawn_helper_launches_the_given_command_with_socket_arg() {
        let socket_path = test_socket_path("spawn-true");
        let mut child = spawn_helper(Path::new("/usr/bin/true"), &socket_path).expect("spawn");
        let status = child.wait().await.expect("wait on spawned child");
        assert!(status.success());
    }

    /// Silence unused-import warning for `TokioMutex` — kept re-exported to
    /// mirror the module's `use` list in case a future test needs it.
    #[allow(dead_code)]
    fn _unused_import_reference() -> Option<TokioMutex<()>> {
        None
    }
}
