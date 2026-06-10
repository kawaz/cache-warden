//! Thin, internal `mlock`/`munlock` wrappers used by [`super::SecretBytes`].
//!
//! These keep all `libc` usage out of the public API (DR-0006 / DR-0007): no
//! `libc` type ever crosses this module's boundary — callers only pass a raw
//! pointer + length and receive a `bool`.
//!
//! Both operations are best-effort. A zero-length region is a successful no-op
//! (some libc implementations reject `mlock(ptr, 0)`), and a failure to lock is
//! reported as `false` so the caller can fall back to an unlocked-but-usable
//! secret (fail-open; see DR-0007).

/// Pin `len` bytes starting at `ptr` in physical memory, suppressing swap.
///
/// Returns `true` on success, `false` if the OS refused (e.g. `RLIMIT_MEMLOCK`
/// exceeded) or the platform is unsupported. A zero-length region is `true`.
#[cfg(unix)]
pub(super) fn lock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: `ptr`/`len` describe a live, owned allocation (the SecretBytes
    // buffer) for the duration of the lock; mlock only marks pages resident.
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    ret == 0
}

/// Release a previous [`lock`] of the same region. Best-effort; ignored if the
/// region was never successfully locked.
#[cfg(unix)]
pub(super) fn unlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: same region previously passed to `lock`; munlock only clears the
    // resident mark and never reads/writes the bytes.
    let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
    ret == 0
}

#[cfg(not(unix))]
pub(super) fn lock(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
pub(super) fn unlock(_ptr: *const u8, _len: usize) -> bool {
    false
}
