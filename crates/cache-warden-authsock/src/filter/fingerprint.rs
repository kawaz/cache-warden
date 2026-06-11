//! Fingerprint matching filter.
//!
//! Ported from authsock-warden `src/filter/fingerprint.rs`. Matches an
//! [`Identity`] by its SSH key fingerprint. The pattern is a prefix of the
//! `SHA256:` / `MD5:` fingerprint string, so a truncated fingerprint still
//! selects the key.

use crate::error::{Error, Result};
use crate::message::Identity;

/// Matcher for SSH key fingerprints.
#[derive(Debug, Clone)]
pub struct FingerprintMatcher {
    pattern: String,
}

impl FingerprintMatcher {
    /// Create a fingerprint matcher from a `SHA256:...` or `MD5:...` pattern.
    ///
    /// Returns an error if the pattern has neither prefix.
    pub fn new(pattern: &str) -> Result<Self> {
        if !pattern.starts_with("SHA256:") && !pattern.starts_with("MD5:") {
            return Err(Error::Filter(format!(
                "invalid fingerprint format: {pattern}. Expected SHA256:... or MD5:..."
            )));
        }
        Ok(Self {
            pattern: pattern.to_string(),
        })
    }

    /// The original pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Whether `identity`'s SHA-256 fingerprint starts with this pattern.
    pub fn matches(&self, identity: &Identity) -> bool {
        if let Some(fp) = identity.fingerprint() {
            let fp_str = fp.to_string();
            fp_str.starts_with(&self.pattern) || self.pattern == fp_str
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sha256_fingerprint() {
        let matcher = FingerprintMatcher::new("SHA256:abc123").unwrap();
        assert_eq!(matcher.pattern(), "SHA256:abc123");
    }

    #[test]
    fn test_valid_md5_fingerprint() {
        let matcher = FingerprintMatcher::new("MD5:ab:cd:ef").unwrap();
        assert_eq!(matcher.pattern(), "MD5:ab:cd:ef");
    }

    #[test]
    fn test_invalid_fingerprint() {
        let result = FingerprintMatcher::new("invalid");
        assert!(result.is_err());
    }
}
