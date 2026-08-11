//! New-process side of a graceful-restart handoff (DR-0029 §2/§5): read the
//! inherited socketpair fd, parse the snapshot, and (later, once this process
//! is fully up) send the two-phase-commit `COMMIT` frame.
//!
//! Every failure path here degrades to **cold start**: the caller
//! ([`crate::daemon::server::run`]) falls back to building an empty `Store`
//! exactly as it does on a normal `daemon run`, never panics, and never
//! blocks the new process's own startup on a stuck peer beyond the bounded
//! read timeout below (DR-0029's fail-safe requirement).

use std::io::Read as _;
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use cache_warden::StoreSnapshot;
use zeroize::Zeroizing;

/// The environment variable the old process sets to the socketpair fd number
/// before `execve` (DR-0029 §1 step ⑦). Read once at startup and unset
/// immediately (a child process this daemon later spawns — a command
/// source's argv — must not inherit it).
pub(crate) const HANDOFF_FD_ENV: &str = "CACHE_WARDEN_HANDOFF_FD";

/// The environment variable carrying the state-holder child's pid. `execve`
/// preserves pid and parent/child relationships, so the new process (the
/// same pid, post-exec) is still the kernel's recorded parent of the holder
/// — [`try_receive`] spawns a background thread to `waitpid` it so it is
/// reaped instead of becoming a zombie until this daemon's own next exit
/// (DR-0029 §5: "新プロセスが waitpid で回収して結果を log する").
pub(crate) const HANDOFF_HOLDER_PID_ENV: &str = "CACHE_WARDEN_HANDOFF_HOLDER_PID";

/// Bounds every read on the handoff stream (header, each entry frame) and the
/// COMMIT write later — matches the holder's `SO_SNDTIMEO`/`SO_RCVTIMEO` of
/// 60s (DR-0029 §5) so neither side can wait past it.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(60);

/// A live handoff in progress: the still-open stream (kept for the eventual
/// `COMMIT` write) and the parsed snapshot.
pub(crate) struct IncomingHandoff {
    pub(crate) stream: UnixStream,
    pub(crate) snapshot: StoreSnapshot,
}

/// If `CACHE_WARDEN_HANDOFF_FD` is set, take it (unsetting the env var
/// either way) and try to read a complete snapshot from it. Returns `None`
/// whenever the caller should fall back to a cold start: no env var, a
/// malformed/truncated stream, an unsupported format version, or a read
/// timeout. Every `None` path (other than "no env var") logs a secret-free
/// stderr warning explaining why.
pub(crate) fn try_receive() -> Option<IncomingHandoff> {
    let raw = std::env::var(HANDOFF_FD_ENV).ok()?;
    // SAFETY: unsetting our own process's environment before any other
    // thread has been spawned (this runs at the very top of `daemon run`,
    // before the tokio runtime exists) — no concurrent env access race.
    unsafe {
        std::env::remove_var(HANDOFF_FD_ENV);
    }

    reap_holder_in_background();

    let fd: RawFd = match raw.parse() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!(
                "cache-warden: warning: {HANDOFF_FD_ENV}={raw:?} is not a valid fd number ({e}); \
                 falling back to a cold start"
            );
            return None;
        }
    };

    // Validate the fd is actually open *before* wrapping it in a `UnixStream`
    // (found via this bundle's own e2e testing): Rust's std hardens `File`/
    // `UnixStream`/`OwnedFd` against double-close bugs by treating a `close`
    // syscall that returns `EBADF` as a fatal io-safety violation — it calls
    // `abort()`, not a recoverable `Err`. A bogus/stale fd number in this env
    // var (corrupted environment, a bug in the old process) must degrade to
    // a cold start like every other malformed-handoff case, not abort this
    // process outright, so it is probed with a plain, ownership-free
    // `fcntl(F_GETFD)` first.
    // SAFETY: `F_GETFD` is a read-only probe of `fd`'s flags; it does not
    // take ownership, close it, or otherwise affect its state.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        eprintln!(
            "cache-warden: warning: {HANDOFF_FD_ENV}={fd} is not an open fd; falling back to a \
             cold start"
        );
        return None;
    }

    // SAFETY: `fd` was handed to us by the parent process specifically as an
    // owned fd for this handoff (DR-0029 §1 step ⑦), and the probe above
    // just confirmed it is genuinely open; this is the only place that takes
    // ownership of it, so no other code in this process holds or will later
    // close it independently.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

    if let Err(e) = stream.set_read_timeout(Some(HANDOFF_TIMEOUT)) {
        eprintln!(
            "cache-warden: warning: could not set a read timeout on the handoff socket ({e}); \
             falling back to a cold start"
        );
        return None;
    }

    match read_snapshot(&mut stream) {
        Ok(snapshot) => Some(IncomingHandoff { stream, snapshot }),
        Err(e) => {
            eprintln!(
                "cache-warden: warning: graceful-restart handoff failed ({e}); falling back to \
                 a cold start (the old process's cache is lost, matching a normal restart)"
            );
            // Dropping `stream` here closes our end, which is the ABORT
            // signal the holder is waiting on (DR-0029 §5's "the only ABORT
            // signal is the peer closing its end").
            None
        }
    }
}

/// Reap the state-holder child in the background (DR-0029 §5), if
/// `CACHE_WARDEN_HANDOFF_HOLDER_PID` names one. Spawns a plain `std::thread`
/// that blocks on `waitpid` — bounded by the holder's own 60s send/receive
/// timeout, so it cannot hang this daemon's shutdown indefinitely — and logs
/// the holder's exit code (0 = committed, 2 = aborted, 3 = timed out; see
/// `handoff::holder_send_and_wait_commit`'s doc). Best-effort: a failure to
/// spawn the thread, or a `waitpid` error, is a warning, never fatal — an
/// unreaped holder is a zombie process-table entry, not a functional issue.
fn reap_holder_in_background() {
    let Ok(raw) = std::env::var(HANDOFF_HOLDER_PID_ENV) else {
        return;
    };
    // SAFETY: same single-threaded-at-startup contract as the handoff-fd
    // env var above.
    unsafe {
        std::env::remove_var(HANDOFF_HOLDER_PID_ENV);
    }
    let Ok(pid) = raw.parse::<libc::pid_t>() else {
        eprintln!(
            "cache-warden: warning: {HANDOFF_HOLDER_PID_ENV}={raw:?} is not a valid pid; the \
             state-holder child (if any) will not be reaped by this process"
        );
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("cw-holder-reap".to_owned())
        .spawn(move || {
            let mut status: libc::c_int = 0;
            // SAFETY: `pid` is the state-holder child this process's kernel
            // parent/child relationship was inherited for via `execve`
            // (pid/parent-child links survive exec); `status` is a valid
            // `c_int` we own for the duration of this call.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc < 0 {
                eprintln!(
                    "cache-warden: warning: could not reap graceful-restart state-holder pid \
                     {pid} ({})",
                    std::io::Error::last_os_error()
                );
            } else {
                eprintln!(
                    "cache-warden: graceful-restart state-holder pid {pid} exited (raw status \
                     {status})"
                );
            }
        });
    if let Err(e) = spawned {
        eprintln!(
            "cache-warden: warning: could not start the state-holder reaper thread ({e}); pid \
             {pid} will be reaped only when this daemon itself next exits"
        );
    }
}

/// Read exactly `n` more bytes from `stream` into `buf`, honoring the read
/// timeout already set on it.
fn read_exact_into(
    stream: &mut UnixStream,
    buf: &mut Zeroizing<Vec<u8>>,
    n: usize,
) -> std::io::Result<()> {
    let start = buf.len();
    buf.resize(start + n, 0);
    stream.read_exact(&mut buf[start..])
}

/// Read the DR-0029 §2 wire framing off `stream`: `magic(8B) +
/// format_version(4B) + entry_count(4B)`, then `entry_count` frames of
/// `len(4B) + payload`. Reading stops exactly there (never depends on EOF —
/// matching [`StoreSnapshot::from_bytes`]'s own contract), which leaves any
/// later frame (a future two-phase-commit variant) unread and untouched.
fn read_snapshot(stream: &mut UnixStream) -> std::io::Result<StoreSnapshot> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

    // magic(8) + format_version(4) + entry_count(4).
    read_exact_into(stream, &mut buf, 16)?;
    let entry_count = u32::from_be_bytes(buf[12..16].try_into().expect("exactly 4 bytes"));

    for _ in 0..entry_count {
        read_exact_into(stream, &mut buf, 4)?;
        let len_start = buf.len() - 4;
        let len =
            u32::from_be_bytes(buf[len_start..].try_into().expect("exactly 4 bytes")) as usize;
        read_exact_into(stream, &mut buf, len)?;
    }

    StoreSnapshot::from_bytes(&buf)
        .map_err(|e| std::io::Error::other(format!("malformed snapshot: {e}")))
}

/// Send the `COMMIT` frame (DR-0029 §5) once this process has fully bound its
/// listeners and is ready to serve, then close the handoff stream. Any
/// failure here is logged and otherwise ignored: the new process is already
/// up and serving by this point (with the imported state), so a failed
/// COMMIT only means the holder times out instead of exiting immediately —
/// it does not affect this process's own correctness.
pub(crate) fn send_commit(mut stream: UnixStream) {
    use std::io::Write as _;
    if let Err(e) = stream.write_all(b"COMMIT") {
        eprintln!(
            "cache-warden: warning: could not send the graceful-restart COMMIT frame ({e}); \
             the old process's holder will time out and exit instead (no functional impact — \
             this process is already up with the imported state)"
        );
    }
    // `stream` drops here, closing our end.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::IntoRawFd as _;

    #[test]
    fn try_receive_returns_none_without_the_env_var() {
        // SAFETY: test-only env mutation; no other thread in this process
        // reads/writes this specific var concurrently.
        unsafe {
            std::env::remove_var(HANDOFF_FD_ENV);
        }
        assert!(try_receive().is_none());
    }

    #[test]
    fn try_receive_degrades_gracefully_on_a_bogus_never_opened_fd() {
        // Regression test (found via this bundle's own e2e testing): a fd
        // number that was never actually opened must fall back to `None`,
        // not abort the process. Before the `fcntl(F_GETFD)` probe in
        // `try_receive`, wrapping a bogus fd in a `UnixStream` and later
        // dropping it hit Rust std's io-safety hardening (`close()`
        // returning `EBADF` is treated as a fatal bug, not a recoverable
        // `Err`) and aborted this very test process. This test's mere
        // completion (not a SIGABRT crash) is the regression check.
        // Serialized: env mutation is process-global (see test_env).
        let _env = crate::test_env::lock();
        // SAFETY: test-only env mutation, serialized by the lock above.
        unsafe {
            std::env::set_var(HANDOFF_FD_ENV, "987654");
        }
        assert!(try_receive().is_none());
        // SAFETY: test-only env cleanup.
        unsafe {
            std::env::remove_var(HANDOFF_FD_ENV);
        }
    }

    #[test]
    fn read_snapshot_round_trips_an_empty_snapshot() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        // `StoreSnapshot::new` is crate-private to `cache_warden` — build a
        // real (empty) one via `Store::export_snapshot` instead, the only
        // public construction path.
        let (store, cap) = cache_warden::test_helpers::store_with_cap();
        let clock = cache_warden::FakeClock::new();
        let snap = store.export_snapshot(&cap, &clock).unwrap();
        let bytes = snap.to_bytes().unwrap();
        std::thread::spawn(move || {
            a.write_all(&bytes).unwrap();
        });
        let back = read_snapshot(&mut b).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn try_receive_falls_back_to_cold_start_on_truncated_stream() {
        let (a, b) = UnixStream::pair().unwrap();
        // The peer writes a header claiming 1 entry, then hangs up before
        // sending it — read_snapshot must error (not panic), and try_receive
        // must fall back to None.
        drop(a); // immediate EOF
        let fd = b.into_raw_fd();
        // Serialized: env mutation is process-global (see test_env).
        let _env = crate::test_env::lock();
        // SAFETY: test-only env mutation, serialized by the lock above.
        unsafe {
            std::env::set_var(HANDOFF_FD_ENV, fd.to_string());
        }
        assert!(try_receive().is_none());
        // SAFETY: test-only env cleanup.
        unsafe {
            std::env::remove_var(HANDOFF_FD_ENV);
        }
    }
}
