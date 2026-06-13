//! Hygiene for child processes the daemon spawns.
//!
//! The daemon blocks SIGINT/SIGTERM process-wide so it can consume them
//! synchronously (`sigwait`) for an orderly shutdown (see the CLI daemon
//! server). A signal mask is inherited across `fork` **and** `exec`, so every
//! command the daemon launches — a `[kv.*]` source command, a re-auth command,
//! the `op` CLI — would otherwise start with those signals blocked and could not
//! be terminated by SIGINT/SIGTERM (a wedged child could even outlive the daemon
//! as an unkillable orphan). [`spawn_with_clean_signal_mask`] restores the normal
//! disposition in the child between fork and exec.

use std::process::Command;

/// Arrange for `command`'s child to start with a clean (empty) signal mask.
///
/// Returns the same `&mut Command` for chaining. On non-Unix platforms this is a
/// no-op (signal masks are a POSIX concept).
///
/// Design rationale: we reset the *whole* mask rather than unblocking only
/// SIGINT/SIGTERM, so this stays correct if the daemon ever blocks additional
/// signals — a freshly `exec`'d program conventionally expects an empty mask.
#[cfg(unix)]
pub fn spawn_with_clean_signal_mask(command: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the forked child before `exec`. It calls only
    // async-signal-safe libc functions (`sigemptyset`, `pthread_sigmask`) on a
    // `sigset_t` it owns, mutating only the child's own signal mask.
    unsafe {
        command.pre_exec(|| {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            Ok(())
        });
    }
    command
}

/// No-op on non-Unix platforms (signal masks are POSIX-only).
#[cfg(not(unix))]
pub fn spawn_with_clean_signal_mask(command: &mut Command) -> &mut Command {
    command
}
