//! Daemon-side IPC client for the `cache-warden-approver` GUI helper
//! (draft-DR-0031 §3/§4/§7/§10).
//!
//! # Scope (Phase 1.4)
//!
//! Socket lifecycle only: bind the approver socket (a separate socket from
//! the control socket — draft-DR-0031 §4's rationale for not queuing a
//! multi-second human approval behind `kv`/`status` traffic), spawn the
//! helper as its client, accept its connection, and exchange one
//! `ApproveRequest` / `ApproveResponse` pair, the whole exchange (accept
//! included) bounded by a timeout.
//!
//! Nothing in `handler` calls into this module yet — that wiring (guard
//! evaluation → `request_approval` → `kv.get` outcome) is Phase 1.5. Every
//! public item below is `#[allow(dead_code)]` until then; the module is
//! exercised directly by this file's own tests in the meantime.
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
use std::path::Path;
use std::time::Duration;

use cache_warden_approver::wire::{ApproveRequest, ApproveResponse, WIRE_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};

use cache_warden_approver::CACHE_WARDEN_IDENTIFIER_PREFIX;

/// Bind the approver socket, removing a stale leftover first.
///
/// Mirrors `server::bind_control_socket`'s stale-detection (a successful
/// connect to an existing path means another listener is already live there —
/// refuse to clobber it; a failed connect means a crashed process's leftover
/// socket file — remove and rebind), on a separate socket path so approval
/// traffic never shares a queue with `control.sock` (§4).
#[allow(dead_code)] // Phase 1.5: wired from daemon startup once guard integration lands
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
/// actually connect; [`exchange`]'s `listener.accept()` does that.
///
/// `kill_on_drop`: the helper is a dialog whose only purpose is answering the
/// pending request — if the daemon side drops the `Child` (error path,
/// cancelled future), a surviving orphan dialog would prompt the user for an
/// approval nobody is waiting on. Killing it with the handle is always the
/// right disposal.
#[allow(dead_code)] // Phase 1.5: wired from daemon startup once guard integration lands
pub fn spawn_helper(helper_path: &Path, socket_path: &Path) -> io::Result<Child> {
    Command::new(helper_path)
        .arg("--socket")
        .arg(socket_path)
        .kill_on_drop(true)
        .spawn()
}

/// Send `request` on an **already-accepted** helper connection, wait for the
/// `ApproveResponse`, all bounded by `timeout`.
///
/// Deliberately separate from any accept / peer-verification step: the
/// production entry point [`request_approval`] runs peer authentication
/// (§Security) between `accept()` and this call, while tests that need to
/// exercise the wire round-trip with a fake same-process helper bypass
/// verification by driving this function directly on a
/// `tokio::spawn`-connected stream. Splitting the accept out of `exchange`
/// keeps the security check on the production path exclusively — no
/// bypass-flag parameter that could be flipped on by mistake.
///
/// **Private on purpose**: an unverified stream must never be handed to this
/// function outside [`request_approval`]'s accept-verify-exchange sequence.
/// Exposing it would offer future wiring a compiling shortcut around
/// §Security's peer authentication; the module's own tests reach it as a
/// child module.
#[allow(dead_code)] // Phase 1.5: wired from daemon startup once guard integration lands
async fn exchange_on_stream(
    stream: UnixStream,
    request: &ApproveRequest,
    timeout: Duration,
) -> io::Result<ApproveResponse> {
    let do_exchange = async {
        let (read_half, mut write_half) = stream.into_split();

        let mut line = serde_json::to_string(request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        write_half.write_all(line.as_bytes()).await?;
        write_half.flush().await?;

        let mut reader = BufReader::new(read_half);
        let mut resp_line = String::new();
        let n = reader.read_line(&mut resp_line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "helper closed the approver socket before sending a response",
            ));
        }
        let resp = serde_json::from_str::<ApproveResponse>(resp_line.trim_end())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // The version field is only worth carrying if someone rejects a
        // mismatch: a future helper speaking a breaking v2 must fail loudly
        // here, not be half-parsed into v1 semantics.
        if resp.v != WIRE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported approver wire version {} (daemon speaks {})",
                    resp.v, WIRE_VERSION
                ),
            ));
        }
        Ok(resp)
    };

    match tokio::time::timeout(timeout, do_exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("helper did not complete the approval exchange within {timeout:?}"),
        )),
    }
}

/// Accept one connection on `listener`, send `request`, wait for
/// `ApproveResponse` — the whole exchange (accept + send + receive) bounded
/// by `timeout`. **No peer authentication**, which is why this exists only
/// under `#[cfg(test)]`: the module's wire-round-trip tests spawn a fake
/// helper in-process (same code signature as the test binary itself —
/// ad-hoc — which the real security check would reject by design).
/// Production code has exactly one accept path, [`request_approval`], which
/// inserts §Security verification between `accept()` and
/// [`exchange_on_stream`]; keeping this variant out of the non-test build
/// means no compiling shortcut around that verification can ever be wired.
///
/// The bound covers `accept()` too, not just the response read: a helper
/// that crashes before connecting (bad binary path resolved late, codesign
/// kill, fail-fast exit on its side) would otherwise hang the daemon on
/// `accept()` forever, and the daemon has no other liveness signal at this
/// layer.
#[cfg(test)]
async fn exchange(
    listener: UnixListener,
    request: &ApproveRequest,
    timeout: Duration,
) -> io::Result<ApproveResponse> {
    let accept_and_exchange = async {
        let (stream, _addr) = listener.accept().await?;
        // Reuse `exchange_on_stream` for the send/recv/timeout logic, but
        // wrap it in a per-run inner timeout of `Duration::MAX` — the outer
        // `tokio::time::timeout` below is what enforces the caller's bound,
        // and layering a real inner one would race with it.
        exchange_on_stream(stream, request, Duration::MAX).await
    };
    match tokio::time::timeout(timeout, accept_and_exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("helper did not complete the approval exchange within {timeout:?}"),
        )),
    }
}

/// Accept connections on `listener` until one passes peer code-signature
/// verification against this process's (draft-DR-0031 §Security), and return
/// that verified `UnixStream` for [`exchange_on_stream`]. Fail-closed on any
/// deviation: not-a-cache-warden-family Identifier, wrong Team ID,
/// signature validity failure, cross-uid connection, missing audit token.
///
/// A rejected peer is logged and its stream dropped (the peer sees `EOF`),
/// and the loop **keeps accepting**: returning an error on the first bad
/// peer would let any same-uid process deny approvals wholesale by racing a
/// connect ahead of the legitimate helper (connect → get rejected → daemon
/// gives up → real helper finds the listener gone). The loop is unbounded
/// here by design — the caller's overall exchange timeout
/// ([`request_approval`]) is what bounds it.
///
/// **Non-macOS**: the underlying
/// [`macos_process_inspect::codesign::verify_peer`] shim uniformly rejects
/// (there is no `Security.framework` to answer the question), which is the
/// correct fail-closed default. The daemon is macOS-only in production —
/// this arm exists to keep the workspace's Linux CI build green.
#[allow(dead_code)] // Phase 1.5: wired from daemon startup once guard integration lands
pub async fn accept_verified(listener: &UnixListener) -> io::Result<UnixStream> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        // `as_raw_fd` on a `tokio::net::UnixStream` returns the connected
        // socket's fd for the duration of the stream (no dup/close race). Peer
        // verification only reads kernel state via `getsockopt(LOCAL_PEERTOKEN)`
        // + `SecCodeCopyGuestWithAttributes` — no I/O on the socket itself, so
        // it cannot conflict with the subsequent read/write halves.
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

/// Orchestrate one full approval round trip with the real helper binary:
/// bind, spawn, accept, exchange.
///
/// Returns the spawned [`Child`] alongside the response so the Phase 1.5
/// caller can hold it for the helper's process lifetime (draft-DR-0031 §3:
/// the daemon spawns and owns the helper, unlike an on-demand-per-request
/// child).
#[allow(dead_code)] // Phase 1.5: wired from daemon startup once guard integration lands
pub async fn request_approval(
    helper_path: &Path,
    socket_path: &Path,
    request: &ApproveRequest,
    timeout: Duration,
) -> io::Result<(Child, ApproveResponse)> {
    let listener = bind(socket_path)?;
    let child = spawn_helper(helper_path, socket_path)?;
    // Peer authentication (§Security) is inserted here — between accept and
    // the wire round-trip. Rejected peers don't abort the wait (see
    // `accept_verified`'s anti-DoS loop); the bound covers accept + verify +
    // send + recv, so "the real helper never showed up" — whether it never
    // connected or only impostors did — surfaces as `TimedOut` rather than
    // a hang or a premature failure.
    let accept_verify_exchange = async {
        let stream = accept_verified(&listener).await?;
        exchange_on_stream(stream, request, Duration::MAX).await
    };
    let response = match tokio::time::timeout(timeout, accept_verify_exchange).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("helper did not complete the approval exchange within {timeout:?}"),
            ));
        }
    };
    Ok((child, response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden_approver::wire::{AuditToken, ProcessChainEntry, Requester, WIRE_VERSION};
    use tokio::net::UnixStream;

    /// A minimal `ApproveRequest` for round-trip tests: no guard (the
    /// ungated-entry shape), single-entry chain. `wire.rs`'s own tests cover
    /// the fully-populated shape; this module only needs *a* valid request to
    /// exercise the socket lifecycle.
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

    /// A unique-per-test socket path in the OS temp dir, so parallel test
    /// runs (`cargo test` defaults to threaded parallelism) never collide on
    /// the same path. `std::process::id()` + a per-call counter is enough
    /// uniqueness for a test binary's own lifetime.
    fn test_socket_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cache-warden-approver-test-{}-{}-{tag}.sock",
            std::process::id(),
            n
        ))
    }

    /// Happy path: a fake helper task connects, reads the `ApproveRequest`
    /// line the daemon side sent, and replies with `Outcome::Approved`.
    /// Exercises `exchange` end-to-end (accept → send → recv) without
    /// spawning any real process (draft-DR-0031 Phase 1.4 forbids launching
    /// the real GUI/TouchID helper from a test).
    #[tokio::test]
    async fn exchange_round_trips_approved_outcome_with_fake_helper() {
        let socket_path = test_socket_path("approved");
        let listener = bind(&socket_path).expect("bind");

        let fake_helper_socket = socket_path.clone();
        let fake_helper = tokio::spawn(async move {
            let stream = UnixStream::connect(&fake_helper_socket)
                .await
                .expect("fake helper connect");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            let req: ApproveRequest =
                serde_json::from_str(line.trim_end()).expect("decode request");
            assert_eq!(req.key, "ns/test-key");

            let resp = ApproveResponse {
                v: WIRE_VERSION,
                request_id: req.request_id,
                outcome: cache_warden_approver::wire::Outcome::Approved,
                biometric_kind: Some("TouchID".to_string()),
            };
            let mut out = serde_json::to_string(&resp).expect("encode response");
            out.push('\n');
            write_half
                .write_all(out.as_bytes())
                .await
                .expect("write response");
            write_half.flush().await.expect("flush");
        });

        let request = test_request("req-approved");
        let response = exchange(listener, &request, Duration::from_secs(5))
            .await
            .expect("exchange should succeed");

        assert_eq!(response.request_id, "req-approved");
        assert_eq!(
            response.outcome,
            cache_warden_approver::wire::Outcome::Approved
        );
        assert_eq!(response.biometric_kind.as_deref(), Some("TouchID"));

        fake_helper
            .await
            .expect("fake helper task should not panic");
        let _ = std::fs::remove_file(&socket_path);
    }

    /// A connected-but-silent fake helper (reads the request, never replies)
    /// must make `exchange` time out rather than hang forever — the daemon's
    /// only defense against a stuck/crashed helper that accepted the
    /// connection but never evaluates policy (draft-DR-0031 §9's
    /// `helper_down` fallback depends on this bound existing).
    #[tokio::test]
    async fn exchange_times_out_when_helper_never_responds() {
        let socket_path = test_socket_path("timeout");
        let listener = bind(&socket_path).expect("bind");

        let fake_helper_socket = socket_path.clone();
        let fake_helper = tokio::spawn(async move {
            let stream = UnixStream::connect(&fake_helper_socket)
                .await
                .expect("fake helper connect");
            let (read_half, mut _write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            // Read the request so the daemon's write doesn't itself fail, then
            // simply never reply — the scenario under test.
            reader.read_line(&mut line).await.expect("read request");
            // Hold the connection open (but silent) until the test's timeout
            // fires and drops the listener/exchange future; nothing further
            // to do here.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let request = test_request("req-timeout");
        let err = exchange(listener, &request, Duration::from_millis(200))
            .await
            .expect_err("exchange should time out, not hang");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        fake_helper.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    /// No helper ever connects (spawn failed silently, helper crashed before
    /// `connect`, helper fail-fast-exited on its own error): `exchange`'s
    /// bound covers `accept()` too, so the daemon gets a `TimedOut` instead
    /// of hanging forever — at this layer the timeout is the daemon's only
    /// liveness signal about the helper.
    #[tokio::test]
    async fn exchange_times_out_when_no_helper_ever_connects() {
        let socket_path = test_socket_path("no-connect");
        let listener = bind(&socket_path).expect("bind");

        let request = test_request("req-no-connect");
        let err = exchange(listener, &request, Duration::from_millis(200))
            .await
            .expect_err("exchange should time out on accept, not hang");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let _ = std::fs::remove_file(&socket_path);
    }

    /// A response carrying an unknown wire version must be rejected as
    /// `InvalidData`, not half-parsed into v1 semantics — the `v` field only
    /// buys forward compatibility if a mismatch actually fails loudly (a
    /// future breaking v2 helper paired with a v1 daemon must not have its
    /// outcome trusted).
    #[tokio::test]
    async fn exchange_rejects_unknown_wire_version() {
        let socket_path = test_socket_path("bad-version");
        let listener = bind(&socket_path).expect("bind");

        let fake_helper_socket = socket_path.clone();
        let fake_helper = tokio::spawn(async move {
            let stream = UnixStream::connect(&fake_helper_socket)
                .await
                .expect("fake helper connect");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            let req: ApproveRequest =
                serde_json::from_str(line.trim_end()).expect("decode request");

            let resp = ApproveResponse {
                v: WIRE_VERSION + 1,
                request_id: req.request_id,
                outcome: cache_warden_approver::wire::Outcome::Approved,
                biometric_kind: Some("TouchID".to_string()),
            };
            let mut out = serde_json::to_string(&resp).expect("encode response");
            out.push('\n');
            write_half
                .write_all(out.as_bytes())
                .await
                .expect("write response");
            write_half.flush().await.expect("flush");
        });

        let request = test_request("req-bad-version");
        let err = exchange(listener, &request, Duration::from_secs(5))
            .await
            .expect_err("a wire-version mismatch must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("wire version"),
            "error should name the version mismatch: {err}"
        );

        fake_helper
            .await
            .expect("fake helper task should not panic");
        let _ = std::fs::remove_file(&socket_path);
    }

    /// A rejected peer must not make `accept_verified` give up: the anti-DoS
    /// contract (draft-DR-0031 §Security) is that a same-uid impostor racing
    /// a connect ahead of the real helper gets its stream dropped (EOF) while
    /// the daemon keeps waiting. The test binary is ad-hoc signed, so its own
    /// connection is rejected by `verify_peer` by design — exactly the
    /// impostor shape. `accept_verified` must still be pending after that
    /// rejection (observed via an outer timeout), not resolved with an error.
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
    /// in for the real helper (task's test-design requirement: "any command"
    /// substitution) — it exits 0 immediately without ever touching the
    /// socket. This never launches the real GUI/TouchID `cache-warden-approver`
    /// binary, and does not itself drive `exchange` (which needs an actual
    /// connecting peer; that is covered by the two tests above via a fake
    /// task, not a spawned process).
    #[tokio::test]
    async fn spawn_helper_launches_the_given_command_with_socket_arg() {
        let socket_path = test_socket_path("spawn-true");
        let mut child = spawn_helper(Path::new("/usr/bin/true"), &socket_path).expect("spawn");
        let status = child.wait().await.expect("wait on spawned child");
        assert!(status.success());
    }
}
