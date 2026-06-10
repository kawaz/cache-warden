//! In-memory holder for a secret value.
//!
//! [`SecretBytes`] keeps raw secret bytes (API tokens, passwords, SSH keys, ...)
//! and guarantees the buffer is zeroized when the value is dropped or explicitly
//! purged. Its `Debug` / `Display` implementations redact the contents so that
//! a secret never leaks into logs, panic messages, or `{:?}` formatting.
//!
//! # Swap protection (`mlock`)
//!
//! The backing buffer is pinned in physical memory with `mlock(2)` on
//! construction so the plaintext is not paged out to swap (where it could
//! linger on disk past the process's lifetime, defeating zeroization). The pin
//! is released with `munlock(2)` just before the buffer is zeroized (on drop /
//! purge). See `docs/decisions/DR-0007-mlock-memory-pinning.md`.
//!
//! Pinning is **fail-open**: if `mlock` is rejected (e.g. `RLIMIT_MEMLOCK`
//! exhausted, or an unsupported platform), the secret is still stored and fully
//! usable — only the swap-protection layer is missing. [`SecretBytes::is_locked`]
//! reports whether the pin is currently in effect so a caller can surface the
//! degraded state.

use std::fmt;

use zeroize::Zeroize;

mod mlock;

/// Placeholder shown by [`SecretBytes`] `Debug` / `Display` instead of the
/// actual secret bytes.
const REDACTED: &str = "[REDACTED]";

/// A secret value held in memory.
///
/// The backing buffer is zeroized on drop and on [`SecretBytes::purge`].
///
/// # Why no `Clone`
///
/// `Clone` is deliberately **not** derived. Copying a secret silently
/// multiplies the number of plaintext copies in memory that must each be
/// zeroized, which is exactly the kind of accidental duplication this type
/// exists to prevent. When a caller genuinely needs an independent copy they
/// must opt in explicitly via [`SecretBytes::duplicate`].
///
/// Design rationale: making duplication explicit keeps the count of live
/// plaintext copies auditable; an implicit `Clone` would make leaks easy to
/// introduce by accident (e.g. via a derive on an enclosing struct).
///
/// # Immutability and `mlock`
///
/// The backing buffer is never grown after construction (there is no
/// `push`/`extend` API), so the allocation cannot be moved by a reallocation —
/// which is what keeps the `mlock` pin valid for the buffer's whole life. The
/// only mutations are construction (lock), [`SecretBytes::duplicate`] (the copy
/// gets its own pin), and [`SecretBytes::purge`] (unlock, then replace with an
/// empty, unpinned buffer). See `docs/decisions/DR-0007-mlock-memory-pinning.md`.
pub struct SecretBytes {
    data: Vec<u8>,
    /// Whether the current `data` allocation is pinned via `mlock`.
    locked: bool,
}

impl SecretBytes {
    /// Wrap owned bytes as a secret.
    ///
    /// The buffer is pinned in memory with `mlock` (best-effort; see the
    /// type-level note). Construction never fails: if pinning is refused the
    /// secret is stored unpinned and [`SecretBytes::is_locked`] returns `false`.
    pub fn new(data: Vec<u8>) -> Self {
        // An empty buffer has nothing to pin (and `mlock(ptr, 0)` is a no-op);
        // report it as unlocked so `is_locked` reflects a real pin.
        let locked = !data.is_empty() && mlock::lock(data.as_ptr(), data.len());
        Self { data, locked }
    }

    /// Length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the secret is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Borrow the raw secret bytes.
    ///
    /// This is the single, explicitly named accessor for the plaintext. Callers
    /// must name `expose_secret` so that secret access is greppable and obvious
    /// at the call site.
    pub fn expose_secret(&self) -> &[u8] {
        &self.data
    }

    /// Whether the backing buffer is currently pinned in memory via `mlock`.
    ///
    /// Returns `false` if pinning was refused at construction (fail-open) or
    /// after [`SecretBytes::purge`] (the empty buffer is not pinned). An empty
    /// secret is never pinned, so this is `false` for a zero-length value.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Produce an independent copy of the secret.
    ///
    /// This is the explicit opt-in for duplication (see the type-level note on
    /// why `Clone` is not derived). The copy is pinned independently of the
    /// original (it owns a separate allocation).
    pub fn duplicate(&self) -> Self {
        Self::new(self.data.clone())
    }

    /// Zeroize the backing buffer immediately, leaving an empty secret.
    ///
    /// Used when a value reaches its hard TTL and must be destroyed while the
    /// holder still lives. After this call [`SecretBytes::expose_secret`]
    /// returns an empty slice and [`SecretBytes::is_locked`] is `false`.
    pub fn purge(&mut self) {
        self.zeroize_buffer();
        // `zeroize` on a Vec sets the length to 0 but keeps the (now-zeroed)
        // capacity; shrink to release it so no stale capacity lingers.
        self.data = Vec::new();
    }

    /// Zeroize the current buffer in place, then unpin it (if pinned).
    ///
    /// Order matters: the bytes are wiped *while the pages are still pinned*,
    /// so plaintext can never be paged out between unpinning and wiping. The
    /// region (ptr/len) is captured up front because `Vec::zeroize` resets the
    /// length to 0 while keeping the same allocation — the captured pointer
    /// stays valid for the `munlock` that follows.
    fn zeroize_buffer(&mut self) {
        let (ptr, len) = (self.data.as_ptr(), self.data.len());
        self.data.zeroize();
        if self.locked {
            mlock::unlock(ptr, len);
            self.locked = false;
        }
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize_buffer();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the length (useful for debugging) but never the bytes.
        f.debug_struct("SecretBytes")
            .field("len", &self.data.len())
            .field("value", &REDACTED)
            .finish()
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&str> for SecretBytes {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_preserves_bytes() {
        let s = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(s.expose_secret(), &[1, 2, 3, 4]);
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
    }

    #[test]
    fn empty_secret_reports_empty() {
        let s = SecretBytes::new(Vec::new());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn from_str_wraps_utf8_bytes() {
        let s = SecretBytes::from("hunter2");
        assert_eq!(s.expose_secret(), b"hunter2");
    }

    #[test]
    fn duplicate_produces_independent_copy() {
        let s = SecretBytes::new(vec![9, 8, 7]);
        let d = s.duplicate();
        assert_eq!(d.expose_secret(), s.expose_secret());
        // Independent: dropping one must not affect the other.
        drop(s);
        assert_eq!(d.expose_secret(), &[9, 8, 7]);
    }

    #[test]
    fn purge_clears_contents() {
        let mut s = SecretBytes::from("topsecret");
        s.purge();
        assert!(s.is_empty());
        assert_eq!(s.expose_secret(), b"");
    }

    #[test]
    fn debug_redacts_secret_bytes() {
        let s = SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let out = format!("{s:?}");
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("len"));
        assert!(out.contains('4'));
        // No raw byte values, decimal or hex.
        assert!(!out.contains("222")); // 0xDE
        assert!(!out.contains("173")); // 0xAD
        assert!(!out.contains("DEAD"));
        assert!(!out.contains("dead"));
        assert!(!out.contains("BEEF"));
        assert!(!out.contains("beef"));
    }

    #[test]
    fn display_redacts_secret() {
        let s = SecretBytes::from("super-secret-token");
        let out = format!("{s}");
        assert_eq!(out, "[REDACTED]");
        assert!(!out.contains("super-secret-token"));
    }

    // Design rationale: SecretBytes must NOT implement Clone. This is enforced
    // structurally (no derive / impl); a compile-fail test would need a separate
    // harness. We document the invariant here and rely on `duplicate` being the
    // only duplication path.
    #[test]
    fn duplicate_is_the_only_explicit_copy_api() {
        let s = SecretBytes::from("x");
        let _ = s.duplicate();
    }

    // ---- mlock (swap protection) ----

    #[cfg(unix)]
    #[test]
    fn nonempty_secret_is_locked_on_unix() {
        // On the dev machine (macOS) and CI (Linux) a small allocation is well
        // within RLIMIT_MEMLOCK, so the pin succeeds. This exercises the
        // mlock-success path.
        let s = SecretBytes::from("pinned-token");
        assert!(
            s.is_locked(),
            "small secret should pin under default rlimit"
        );
        // Still fully usable.
        assert_eq!(s.expose_secret(), b"pinned-token");
    }

    #[test]
    fn empty_secret_is_never_locked() {
        let s = SecretBytes::new(Vec::new());
        assert!(!s.is_locked());
    }

    #[test]
    fn purge_releases_the_lock() {
        let mut s = SecretBytes::from("topsecret");
        s.purge();
        assert!(!s.is_locked(), "purge must unpin the buffer");
        assert!(s.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_pins_independently() {
        let s = SecretBytes::from("orig");
        let d = s.duplicate();
        // Both own separate, independently-pinned allocations.
        assert!(s.is_locked());
        assert!(d.is_locked());
        drop(s);
        // Dropping one unpins only its own buffer; the other is intact.
        assert!(d.is_locked());
        assert_eq!(d.expose_secret(), b"orig");
    }
}
