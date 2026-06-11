//! Process-wide startup hardening for the daemon (design §3 judgement 5a).
//!
//! The daemon holds SSH private keys and other secrets in memory (mlocked, see
//! DR-0007). If the process crashes, the OS may write a core dump to disk — a
//! verbatim snapshot of process memory, including those secrets *and* the very
//! pages DR-0007 pinned to keep off swap. We suppress core dumps at startup so a
//! crash cannot leak secrets to disk.
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
}
