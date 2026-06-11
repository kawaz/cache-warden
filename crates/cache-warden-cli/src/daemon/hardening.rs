//! Process-wide startup hardening for the daemon (design §3 judgement 5).
//!
//! The daemon holds SSH private keys and other secrets in memory (mlocked, see
//! DR-0007). Two startup layers keep those secrets from leaking out of the live
//! process:
//!
//! - **(5a) Core-dump suppression** ([`suppress_core_dumps`]): if the process
//!   crashes, the OS may write a core dump to disk — a verbatim snapshot of
//!   process memory, including the secrets *and* the very pages DR-0007 pinned to
//!   keep off swap. We set `RLIMIT_CORE=0` so a crash cannot leak them to disk.
//! - **(5b) Debugger-attach refusal** ([`deny_debugger_attach`]): a debugger that
//!   attaches can read the address space live, bypassing both the mlock and the
//!   core-dump layer. We refuse attachment at startup. This is **opt-out** via
//!   `[daemon].allow-debug-attach` (development/profiling); opting out prints a
//!   single stderr warning so the weakened state is never silent.
//!
//! This is process-wide protection (not tied to any one secret value), so it
//! lives on the CLI/daemon side rather than in the core library — the core's
//! mlock is the responsibility of the `SecretBytes` *type*, whereas core-dump
//! suppression is the responsibility of the *process*. See the port plan §3
//! judgement 5: "実装の所属はデーモン起動時 (cli 側)".

/// Suppress core dumps for this process by setting `RLIMIT_CORE` to 0.
///
/// Returns `true` if the soft+hard core-dump limit is now 0, `false` if the
/// libc call refused (then the daemon continues anyway — see Design rationale).
///
/// Design rationale: **fail-open**, consistent with the mlock policy (DR-0007).
/// Core-dump suppression is one layer of defence-in-depth, not a hard
/// requirement. Refusing to start the daemon because `setrlimit` failed would be
/// worse than running with the (small, crash-only) residual risk: the daemon's
/// job is to keep SSH signing / 1Password integration available (DR-0004
/// invariant). A failure is surfaced as a single stderr warning so the operator
/// can notice the degraded state, mirroring DR-0007's `is_locked()` observability.
#[cfg(unix)]
pub fn suppress_core_dumps() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads a valid `rlimit` we own for the duration of the
    // call and only adjusts this process's resource limits; no memory we own is
    // mutated. Lowering RLIMIT_CORE is permitted for unprivileged processes.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    ret == 0
}

#[cfg(not(unix))]
pub fn suppress_core_dumps() -> bool {
    false
}

/// Refuse debugger attachment for this process (design §3 judgement 5b).
///
/// A debugger that attaches can read the daemon's address space — defeating the
/// mlock (DR-0007) and core-dump suppression layers by reading the secrets live
/// rather than from disk. This refuses attachment at startup, before any secret
/// enters the [`Store`](cache_warden::Store).
///
/// Platform mapping:
/// - **macOS**: `ptrace(PT_DENY_ATTACH, …)`. The kernel marks the process
///   `P_LNOATTACH`; any later `PTRACE_ATTACH` / `task_for_pid` from a debugger
///   fails (and a debugger attached *before* this call is killed).
/// - **Linux**: `prctl(PR_SET_DUMPABLE, 0)`. cache-warden already drops the core
///   dump via `RLIMIT_CORE=0` ([`suppress_core_dumps`]), so the dumpable flag is
///   used here purely for its *attach* side effect: a non-dumpable process
///   refuses unprivileged `PTRACE_ATTACH` (EPERM) and reparents
///   `/proc/<pid>/{mem,maps,…}` ownership to root, so an unprivileged peer can no
///   longer read the daemon's memory. This is the closest portable equivalent to
///   `PT_DENY_ATTACH` available without a platform-specific LSM/seccomp policy.
///   Note: this does not stop a *root* / `CAP_SYS_PTRACE` attacher — that is out
///   of scope (an attacker with root already owns the host).
/// - **other unix / non-unix**: no-op (returns `true`; nothing to refuse).
///
/// Returns `true` if the refusal was applied (or is a no-op on this platform),
/// `false` if the syscall refused.
///
/// Design rationale: **fail-open**, mirroring [`suppress_core_dumps`] and the
/// mlock policy (DR-0007). Anti-debug is one layer of defence-in-depth, not a
/// hard requirement; aborting the daemon because the syscall refused would break
/// DR-0004's "keep signing available" invariant for no security gain. A failure
/// is surfaced as a single stderr warning so the operator notices the degraded
/// state. `PT_DENY_ATTACH` should not fail in practice.
#[cfg(target_os = "macos")]
pub fn deny_debugger_attach() -> bool {
    // SAFETY: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` only sets a flag on the calling
    // process; it reads/writes no memory we own.
    let ret = unsafe {
        libc::ptrace(
            libc::PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    ret == 0
}

#[cfg(target_os = "linux")]
pub fn deny_debugger_attach() -> bool {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0, …)` only adjusts the calling process's
    // dumpable flag; no memory we own is read or written. The trailing args are
    // ignored for this option but must be passed for the variadic call.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    ret == 0
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub fn deny_debugger_attach() -> bool {
    // No portable attach-refusal primitive on other unices; treat as a no-op so
    // the caller's fail-open path does not warn spuriously.
    true
}

#[cfg(not(unix))]
pub fn deny_debugger_attach() -> bool {
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// After `suppress_core_dumps()`, `getrlimit(RLIMIT_CORE)` must report a soft
    /// limit of 0 — the kernel writes no core dump when the limit is 0.
    #[test]
    fn sets_core_limit_to_zero() {
        assert!(
            suppress_core_dumps(),
            "lowering RLIMIT_CORE to 0 should succeed for an unprivileged process"
        );

        let mut current = libc::rlimit {
            rlim_cur: u64::MAX as libc::rlim_t,
            rlim_max: u64::MAX as libc::rlim_t,
        };
        // SAFETY: `getrlimit` writes the current limits into a valid `rlimit` we own.
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut current) };
        assert_eq!(ret, 0, "getrlimit should succeed");
        assert_eq!(current.rlim_cur, 0, "soft core-dump limit must be 0");
    }

    /// On Linux, `deny_debugger_attach()` clears the dumpable flag, which is the
    /// observable that gates unprivileged `PTRACE_ATTACH` and `/proc/<pid>/mem`
    /// ownership. We can read it back in-process with `prctl(PR_GET_DUMPABLE)`.
    ///
    /// This mutates the test *process* (it becomes non-dumpable for the rest of
    /// the run), but that has no effect on the other unit tests here.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_clears_dumpable_flag() {
        assert!(
            deny_debugger_attach(),
            "PR_SET_DUMPABLE=0 should succeed for an unprivileged process"
        );
        // SAFETY: PR_GET_DUMPABLE takes no pointer args; the return value is the flag.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0, "process must be non-dumpable after deny");
    }

    /// On macOS, `PT_DENY_ATTACH` marks the *test process itself* as
    /// non-attachable. Running it inside the unit-test binary would (a) make the
    /// process refuse any later debugger/`lldb` attach for the rest of the run and
    /// (b) be killed outright if the test binary was itself launched under a
    /// debugger — which breaks `cargo test` under CI debuggers. The real-effect
    /// check lives in the child-process E2E (`tests/hardening_ptrace.rs`), so this
    /// only asserts the call shape and is `#[ignore]`d by default. Run manually
    /// with `cargo test -- --ignored macos_deny_attach_succeeds`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "PT_DENY_ATTACH mutates the test process; verified via child E2E instead"]
    fn macos_deny_attach_succeeds() {
        assert!(deny_debugger_attach(), "PT_DENY_ATTACH should succeed");
    }
}
