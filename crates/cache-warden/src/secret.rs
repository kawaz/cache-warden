//! In-memory holder for a secret value.
//!
//! [`SecretBytes`] keeps raw secret bytes (API tokens, passwords, SSH keys, ...)
//! and guarantees the buffer is zeroized when the value is dropped or explicitly
//! purged. Its `Debug` / `Display` implementations redact the contents so that
//! a secret never leaks into logs, panic messages, or `{:?}` formatting.

use std::fmt;

use zeroize::Zeroize;

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
pub struct SecretBytes {
    data: Vec<u8>,
}

impl SecretBytes {
    /// Wrap owned bytes as a secret.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
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

    /// Produce an independent copy of the secret.
    ///
    /// This is the explicit opt-in for duplication (see the type-level note on
    /// why `Clone` is not derived).
    pub fn duplicate(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }

    /// Zeroize the backing buffer immediately, leaving an empty secret.
    ///
    /// Used when a value reaches its hard TTL and must be destroyed while the
    /// holder still lives. After this call [`SecretBytes::expose_secret`]
    /// returns an empty slice.
    pub fn purge(&mut self) {
        self.data.zeroize();
        // `zeroize` on a Vec sets the length to 0 but keeps the (now-zeroed)
        // capacity; shrink to release it so no stale capacity lingers.
        self.data = Vec::new();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.data.zeroize();
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
}
