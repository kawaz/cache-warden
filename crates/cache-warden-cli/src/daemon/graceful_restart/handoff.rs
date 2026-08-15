//! Old-process side of a graceful-restart handoff (DR-0029 §1/§2/§5):
//! serialize the store, verify the exec target, prepare the socketpair, and
//! (macOS) fork the state-holder child + `execve` this process in place.
//!
//! [`prepare`] does everything that is still safe to fail out of (no listener
//! has been touched yet — a `prepare` failure just means "reply with an
//! error, current process keeps serving"). [`execute`] is the point of no
//! return: by the time [`super::execute_after_shutdown`] calls it, the
//! control socket and every `[authsock.sockets.*]` listener are already
//! closed and unlinked (DR-0029 §1's fd-hygiene requirement — see that
//! function's doc), so a failure here can only end in this process exiting
//! (relying on the service manager to cold-restart it), never in silently
//! resuming the old listeners.
//!
//! Everything in this module below `execute`'s non-macOS stub is reachable
//! only from `super::handle_request`'s `#[cfg(target_os = "macos")]` branch
//! (found while cross-checking this bundle's HIGH-4 non-macOS regression
//! test against `.github/workflows/ci.yml`'s `ubuntu-latest` runner, which
//! runs `cargo clippy --workspace -- -D warnings` — a pre-existing,
//! independent-of-that-test issue that would otherwise fail CI on every
//! non-macOS target): `#[allow(dead_code)]` there rather than gating this
//! whole module to `#[cfg(target_os = "macos")]`, since `PreparedHandoff`
//! and `execute`'s non-macOS stub must keep existing on every target (the
//! stub is a deliberate canary — see its own doc — for
//! `handle_request`'s early guard ever being bypassed by a future refactor).
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use super::verify::{self, VerifiedExe};

/// Bounds the socketpair's `SO_SNDTIMEO`/`SO_RCVTIMEO` (DR-0029 §1 step ④),
/// matching the timeout [`super::receive::HANDOFF_TIMEOUT`] uses on the
/// receiving side.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(60);

/// Everything [`execute`] needs, assembled by [`prepare`] while it is still
/// safe to abort (nothing has been torn down yet).
pub(crate) struct PreparedHandoff {
    verified: VerifiedExe,
    exe_path: PathBuf,
    /// The running process's own argv (`std::env::args()`, index 0 included)
    /// — re-used verbatim except for argv[0], which is replaced by
    /// `exe_path` itself (DR-0029 §1 step ⑥: "argv 継承").
    argv: Vec<String>,
    snapshot_bytes: Zeroizing<Vec<u8>>,
    /// The end this process's state-holder child keeps (DR-0029 calls this
    /// fd_a in the design doc's terms).
    holder_end: OwnedFd,
    /// The end that must survive this process's own `execve` into the new
    /// process (fd_b).
    new_end: OwnedFd,
}

/// Serialize the store, verify the exec target, and set up the socketpair —
/// everything that can still fail safely (DR-0029 §1 steps ①–④ in this
/// bundle's chosen order: serialize, then verify, then — by the time the
/// caller reaches [`execute`] — drain/fd-hygiene has already run in
/// [`crate::daemon::server::run`]'s shutdown path). Returns a plain string on
/// any failure (the caller turns it into a [`crate::protocol::wire::ErrorKind::RestartAborted`]
/// response; nothing has been touched, so the current process keeps serving
/// untouched).
///
/// Takes an already-exported [`cache_warden::StoreSnapshot`] rather than the
/// `Store` itself (DR-0029 bundle 2 review MEDIUM-7): the caller
/// (`graceful_restart::handle_request`) exports the snapshot while holding
/// the store lock and drops the guard immediately afterward, *before*
/// calling this function — so the (comparatively slow) serialize-to-bytes,
/// exec-target verification (file I/O, macOS codesign checks), and
/// socketpair setup below all run with the store unlocked, letting other
/// in-flight requests proceed instead of queuing behind this preparation.
pub(crate) fn prepare(
    mut snapshot: cache_warden::StoreSnapshot,
    dek: Option<&[u8]>,
    exe_path: &std::path::Path,
    argv: &[String],
) -> Result<PreparedHandoff, String> {
    // Declared before serializing, so the version the successor reads and the
    // frame it then waits for are decided by the same `dek` argument.
    if dek.is_some() {
        snapshot.declare_dek_frame();
    }
    let mut snapshot_bytes = snapshot
        .to_bytes()
        .map_err(|e| format!("cannot serialize store snapshot: {e}"))?;

    // DR-0034 §11: hand the vault's data key to the successor so an upgrade
    // does not make the user unlock again. The snapshot's version already
    // declares whether this frame follows (see `VERSION_PRE_DEK`), so writing
    // it here and declaring it there must agree — which is why both are driven
    // by the same `dek` argument.
    if let Some(key) = dek {
        cache_warden::StoreSnapshot::append_dek_frame(&mut snapshot_bytes, key);
    }

    // Step ②: verify the exec target (DR-0029 §3).
    let verified =
        verify::verify_exec_target(exe_path).map_err(|e| format!("exec target rejected: {e}"))?;

    // Step ④: socketpair, timeouts, CLOEXEC (fork/exec happens later, in
    // `execute`, after the caller has drained + closed + unlinked).
    let (holder_end, new_end) = create_socketpair().map_err(|e| e.to_string())?;
    set_send_recv_timeout(&holder_end, HANDOFF_TIMEOUT)
        .map_err(|e| format!("cannot set handoff socket timeout: {e}"))?;
    set_send_recv_timeout(&new_end, HANDOFF_TIMEOUT)
        .map_err(|e| format!("cannot set handoff socket timeout: {e}"))?;
    // `new_end` must survive this process's own execve; `holder_end` does
    // not (the holder child is a fork(), not an exec — CLOEXEC is
    // irrelevant to it — and the parent explicitly closes its own copy of
    // `holder_end` before exec regardless, see `execute`).
    clear_cloexec(&new_end).map_err(|e| format!("cannot clear CLOEXEC on handoff fd: {e}"))?;
    ignore_sigpipe();

    Ok(PreparedHandoff {
        verified,
        exe_path: exe_path.to_path_buf(),
        argv: argv.to_vec(),
        snapshot_bytes,
        holder_end,
        new_end,
    })
}

fn create_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [0, 0];
    // SAFETY: `fds` is a valid, exclusively-owned 2-element buffer for the
    // duration of this call.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fds[0]`/`fds[1]` are freshly created, open, valid fds that
    // nothing else in this process holds yet — `socketpair(2)` just handed
    // them to us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn set_send_recv_timeout(fd: &OwnedFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    for opt in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        // SAFETY: `fd` is a valid, open socket fd owned by the caller for the
        // duration of this call; `tv` is a valid, fully-initialized
        // `timeval` we own.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn clear_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid, open fd for the duration of both calls.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set `SIGPIPE` to `SIG_IGN` process-wide (DR-0029 §1 step ④). The
/// disposition survives both `fork()` (inherited unconditionally) and this
/// process's own later `execve()` (POSIX: an ignored disposition, unlike a
/// caught one, survives exec) — so it also carries into the new process.
/// That is intentional, not a side effect to correct: the holder's `write`
/// to a peer that has hung up must return `EPIPE` as a normal error (so its
/// zeroize-then-`_exit` path always runs), not kill it via the default
/// terminate-on-SIGPIPE disposition.
fn ignore_sigpipe() {
    // SAFETY: `signal` with `SIG_IGN` only changes this process's signal
    // disposition table; no memory we own is touched.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// The point of no return (DR-0029 §1 steps ⑤/⑥): fork the state-holder
/// child, then `execve` this process into `prepared.exe_path`. Every
/// listener is already closed + unlinked by the time the caller reaches this
/// (see [`super::execute_after_shutdown`]), so any failure from here on can
/// only end in this process exiting — never in resuming the torn-down
/// listeners.
///
/// Never returns on success (the process image is replaced). Returns if
/// `fork()` or `execve()` themselves failed, in which case the caller's only
/// remaining option is to let this process exit and rely on the service
/// manager (`KeepAlive=true`, DR-0019) to cold-restart it.
#[cfg(target_os = "macos")]
pub(crate) fn execute(prepared: PreparedHandoff) {
    let PreparedHandoff {
        verified,
        exe_path,
        argv,
        snapshot_bytes,
        holder_end,
        new_end,
    } = prepared;

    // DR-0029 §3 step 3: narrow the TOCTOU window as much as possible by
    // re-confirming identity immediately before the fork/exec sequence
    // begins (as close to `execve` as this bundle's structure allows).
    if let Err(e) = verify::reconfirm_identity(&exe_path, &verified) {
        eprintln!(
            "cache-warden: graceful restart aborted at the last moment ({e}); this process's \
             listeners are already closed — exiting and relying on the service manager to \
             cold-restart it"
        );
        return;
    }

    let buf_ptr = snapshot_bytes.as_ptr();
    let buf_len = snapshot_bytes.len();
    let holder_raw = holder_end.as_raw_fd();
    let new_raw = new_end.as_raw_fd();

    // SAFETY: `fork()` duplicates the address space. The parent (this
    // thread, continuing past this call) is **not** disturbed by the call
    // itself — fork() only creates a *child*; every one of this process's
    // own threads keeps running exactly as before (DR-0029 §1: "親は fork
    // 直後に execve するので親側の post-fork 制約はない"). The child
    // retains only this one calling thread and must restrict itself to
    // async-signal-safe operations (no allocation, no `println!`/`format!`,
    // no tokio) until `_exit` — see `holder_child_main`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        eprintln!(
            "cache-warden: graceful restart: fork() failed ({err}); this process's listeners \
             are already closed — exiting and relying on the service manager to cold-restart it"
        );
        return;
    }
    if pid == 0 {
        // ---- HOLDER CHILD: async-signal-safe code only from here on. ----
        holder_child_main(buf_ptr, buf_len, holder_raw, new_raw);
    }

    // ---- PARENT: hand off via exec. ----
    // Only the holder keeps `holder_end`; close our own copy of it before
    // exec (belt-and-suspenders — it would also just be a leaked fd in the
    // new process otherwise, since it is not the one we clear CLOEXEC on).
    drop(holder_end);
    // `new_end` must survive the exec below; forgetting it stops its
    // destructor from closing the fd out from under the about-to-happen
    // execve (CLOEXEC was already cleared on it in `prepare`).
    std::mem::forget(new_end);

    // DR-0029 bundle 2 review LOW (SIGPIPE inheritance asymmetry): `prepare`'s
    // `ignore_sigpipe` set SIGPIPE to `SIG_IGN` process-wide so the holder
    // child's `write` to a hung-up peer degrades to `EPIPE` instead of
    // killing it — and an ignored disposition survives `execve` (POSIX),
    // which is exactly what the holder (a `fork`, not an `exec`) needs and
    // already has by inheritance. The *parent*, about to `execve` into the
    // new process, has no such need: restoring `SIG_DFL` here — after the
    // holder has already forked off with its own independent copy of the
    // (still-`SIG_IGN`) disposition table — means the new process starts
    // with the same default SIGPIPE disposition a genuinely cold-started
    // daemon would have, instead of silently inheriting this bundle's
    // holder-specific workaround.
    // SAFETY: `signal` with `SIG_DFL` only changes this process's own signal
    // disposition table; no memory we own is touched. The holder child
    // already has its own independent copy (from `fork`) unaffected by this.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let mut argv_rest = argv;
    if !argv_rest.is_empty() {
        argv_rest.remove(0);
    }
    // `Command::exec` (`std::os::unix::process::CommandExt`) replaces this
    // process image via `execve`; it only returns on failure. `pid` (the
    // holder's) rides along via env so the *new* process — which `execve`
    // makes the same pid, and therefore still the holder's parent in the
    // kernel's process tree — can reap it (`receive::try_receive` spawns a
    // background `waitpid`) instead of leaving a zombie until this daemon's
    // own next exit.
    use std::os::unix::process::CommandExt as _;
    let err = std::process::Command::new(&exe_path)
        .args(&argv_rest)
        .env(super::receive::HANDOFF_FD_ENV, new_raw.to_string())
        .env(super::receive::HANDOFF_HOLDER_PID_ENV, pid.to_string())
        .exec();
    eprintln!(
        "cache-warden: graceful restart: execve({}) failed ({err}); this process's listeners \
         are already closed — exiting and relying on the service manager to cold-restart it",
        exe_path.display()
    );
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn execute(_prepared: PreparedHandoff) {
    // Graceful restart's fork/exec sequence (fork-safety, socketpair
    // two-phase commit, exec-target verification) is macOS-only for now.
    // `prepare` and the control-socket wiring build on every platform (so
    // `cache-warden daemon restart --graceful` at least fails with a clear
    // message rather than a missing command), but this function is only
    // reached after a request has already been accepted — which
    // `graceful_restart::handle_request` never does on a non-macOS target
    // (see that function's early `#[cfg(not(target_os = "macos"))]` guard).
    // This `unimplemented!` exists as a canary in case that guard is ever
    // bypassed by a future refactor.
    unimplemented!(
        "graceful restart is macOS-only; see \
         docs/issue/2026-07-09-linux-graceful-restart-fexecve-verification.md"
    );
}

/// The state-holder child's entire body (DR-0029 §1 step ⑤): async-signal-
/// safe operations only — no allocation, no `println!`/`format!`, no tokio.
/// Always terminates via `_exit`; never returns.
///
/// `buf_ptr`/`buf_len` describe the snapshot buffer [`prepare`] allocated
/// before `fork()` — still valid in this (copy-on-write) address space, and
/// exclusively used by this child from here on (the parent never touches it
/// again before `execve`/exiting). `holder_fd` is this child's end of the
/// socketpair; `new_fd` belonged to the soon-to-be-new-process and is closed
/// here immediately, as part of the close-everything-else sweep below (fd
/// hygiene inside the child must not depend on what the parent concurrently
/// does with its own copy).
// The holder child must never unwind: a panic between `fork` and `_exit`
// would run non-async-signal-safe unwind/Drop code inside the forked child.
// These lints turn the "async-signal-safe code only" discipline (enforced by
// review) into a compile-time gate for the most common panic sources. They
// cannot catch panics inside callees — keep the holder functions leaf-level
// (libc + core only) so the annotated bodies are the whole surface.
#[cfg(target_os = "macos")]
#[deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
fn holder_child_main(buf_ptr: *const u8, buf_len: usize, holder_fd: RawFd, new_fd: RawFd) -> ! {
    // DR-0029 bundle 2 review MEDIUM-1: close every fd except our own end of
    // the socketpair, as the very first action after fork — before
    // ptrace/mlock/anything else. Belt-and-suspenders against any fd this
    // child might hold beyond what the parent already closed (DR-0029 §1's
    // fd-hygiene step closes every listener before fork; this guards against
    // anything unaccounted for — a leaked fd from a linked library, stdio
    // inherited from a supervisor, etc.). `new_fd` is covered by this sweep
    // (it is simply "some fd that is not `holder_fd`"), superseding the
    // single `close(new_fd)` this bundle originally shipped with.
    //
    // `getdtablesize()` + a plain close loop — both async-signal-safe, no
    // allocation — rather than enumerating `/dev/fd` (would need `opendir`,
    // which mallocs) or the more targeted `closefrom(2)`/`close_range(2)`
    // (neither is declared in the `libc` crate for this target; adding a
    // hand-rolled FFI declaration for an optimization on top of an
    // already-bounded, already-safe loop was judged not worth the added
    // unsafe surface for this bundle).
    // SAFETY: `getdtablesize()` takes no arguments and cannot fail
    // meaningfully (a non-positive result just skips the loop below).
    let table_size = unsafe { libc::getdtablesize() };
    for fd in 0..table_size {
        if fd != holder_fd {
            // SAFETY: closing an fd this child does not otherwise reference
            // (`holder_fd` is excluded) is always valid, whether or not `fd`
            // is currently open — `close` on an already-closed fd just
            // returns `EBADF`, which we ignore (best-effort sweep, not a
            // fatal condition).
            unsafe {
                libc::close(fd);
            }
        }
    }
    let _ = new_fd; // already closed by the sweep above; kept as a documented parameter

    // DR-0007 precedent: refuse debugger attachment on this child too.
    // Fail-closed (DR-0029 bundle 2 review MEDIUM-2): unlike the main
    // daemon's own `hardening::deny_debugger_attach` (which only warns on
    // failure — a debugger *could* attach, but the daemon stays otherwise
    // functional), this child exists for the sole purpose of holding a
    // plaintext secret buffer in memory for up to 60s; if it cannot refuse
    // debugger attachment, that buffer must not be held at all. Exiting here
    // zeroizes the buffer and closes our end of the socketpair, which the
    // new process observes as EOF before ever getting a snapshot — exactly
    // the ABORT-and-degrade-to-cold-start path DR-0029 §5 already defines
    // for any other holder failure.
    // SAFETY: `ptrace(PT_DENY_ATTACH, ...)` only sets a flag on the calling
    // (this) process; no memory we own is read or written.
    let ptrace_rc = unsafe {
        libc::ptrace(
            libc::PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    if ptrace_rc != 0 {
        holder_explicit_bzero(buf_ptr as *mut u8, buf_len);
        // SAFETY: `holder_fd` is our own fd; closing it is always valid.
        unsafe {
            libc::close(holder_fd);
        }
        // SAFETY: `_exit` terminates immediately without running
        // destructors or unwinding — see the function's final `_exit` call
        // for why this is the only safe way for this child to stop.
        unsafe { libc::_exit(4) };
    }

    // Re-apply mlock: fork's inheritance of an mlock'd range is not
    // guaranteed, so reapply unconditionally rather than assume either way
    // (DR-0029 Q3). Fail-closed for the same reason as `PT_DENY_ATTACH`
    // above: a swappable plaintext secret buffer held for up to 60s is not
    // an acceptable degrade.
    // SAFETY: `buf_ptr`/`buf_len` describe the live snapshot buffer.
    let mlock_rc = unsafe { libc::mlock(buf_ptr as *const libc::c_void, buf_len) };
    if mlock_rc != 0 {
        holder_explicit_bzero(buf_ptr as *mut u8, buf_len);
        unsafe {
            libc::close(holder_fd);
        }
        unsafe { libc::_exit(5) };
    }

    let exit_code = holder_send_and_wait_commit(buf_ptr, buf_len, holder_fd);

    // Zeroize the buffer before exiting, on every exit path.
    holder_explicit_bzero(buf_ptr as *mut u8, buf_len);
    // SAFETY: `holder_fd` is our own fd; closing it is always valid.
    unsafe {
        libc::close(holder_fd);
    }
    // SAFETY: `_exit` terminates immediately without running destructors or
    // unwinding — the only safe way for this child to stop (a normal
    // `return`/panic could run non-async-signal-safe Drop/unwind code).
    unsafe { libc::_exit(exit_code) };
}

/// Write the whole buffer, then wait for the 6-byte `COMMIT` frame (DR-0029
/// §5). Returns the holder's exit code: `0` on COMMIT, `2` on a write/read
/// error or EOF (the new process aborted or never came up), `3` on a
/// send/receive timeout (`SO_SNDTIMEO`/`SO_RCVTIMEO`, set in `prepare`).
#[cfg(target_os = "macos")]
#[deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
fn holder_send_and_wait_commit(buf_ptr: *const u8, buf_len: usize, fd: RawFd) -> i32 {
    let mut sent = 0usize;
    while sent < buf_len {
        // SAFETY: writes `buf_len - sent` bytes starting at `buf_ptr +
        // sent`, within the buffer's bounds by the loop invariant.
        let n =
            unsafe { libc::write(fd, buf_ptr.add(sent) as *const libc::c_void, buf_len - sent) };
        if n > 0 {
            sent += n as usize;
            continue;
        }
        if n < 0 {
            // SAFETY: `__error()` returns this thread's errno location; we
            // only read it immediately after the failing call above.
            let err = unsafe { *libc::__error() };
            if err == libc::EINTR {
                continue;
            }
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                return 3;
            }
            return 2; // EPIPE (peer gone) or any other write error.
        }
        return 2; // n == 0 should not happen for write(2); treat as abort.
    }

    let mut commit = [0u8; 6];
    let mut got = 0usize;
    while got < commit.len() {
        // SAFETY: reads into `commit[got..]`, within bounds by the loop
        // invariant; `commit` is a stack array this function owns.
        let n = unsafe {
            libc::read(
                fd,
                commit.as_mut_ptr().add(got) as *mut libc::c_void,
                commit.len() - got,
            )
        };
        if n > 0 {
            got += n as usize;
            continue;
        }
        if n == 0 {
            return 2; // EOF before COMMIT.
        }
        // SAFETY: same as above.
        let err = unsafe { *libc::__error() };
        if err == libc::EINTR {
            continue;
        }
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            return 3;
        }
        return 2;
    }
    if &commit == b"COMMIT" { 0 } else { 2 }
}

/// Manual best-effort secure erase, async-signal-safe by construction: a
/// plain `write_volatile` loop (defeats dead-store elimination) followed by
/// a compiler fence. There is no `explicit_bzero`/`memset_s` binding
/// anywhere in this crate graph, and adding one only for this single
/// call site was judged not worth a new FFI surface for this bundle — noted
/// as a simplification in the delegation's final report.
#[cfg(target_os = "macos")]
#[deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
fn holder_explicit_bzero(ptr: *mut u8, len: usize) {
    // SAFETY: `ptr`/`len` describe the same buffer this child has been
    // reading from throughout, exclusively owned by this child at this
    // point (the fds are closed right after this call, and this function
    // never returns to code that reads the buffer again).
    unsafe {
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
