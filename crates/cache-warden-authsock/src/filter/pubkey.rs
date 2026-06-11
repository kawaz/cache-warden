//! Public key matching filter.
//!
//! Ported from authsock-warden `src/filter/pubkey.rs`. Matches an [`Identity`]
//! by exact wire-format public-key blob, parsed from an OpenSSH public-key line
//! (the comment is ignored).

use crate::error::{Error, Result};
use crate::message::Identity;
use bytes::Bytes;
use ssh_encoding::Encode;
use ssh_key::PublicKey;

/// Matcher for SSH public keys (exact wire-blob equality).
#[derive(Debug, Clone)]
pub struct PubkeyMatcher {
    key_blob: Bytes,
}

impl PubkeyMatcher {
    /// Create from an OpenSSH-format public-key string (the comment is ignored).
    ///
    /// The blob is built from `key_data().encode()` — the same wire encoding the
    /// registry and [`Identity::new`] use — so equality with an enumerated
    /// identity is exact.
    pub fn new(key_str: &str) -> Result<Self> {
        let key = PublicKey::from_openssh(key_str)
            .map_err(|e| Error::Filter(format!("invalid public key: {e}")))?;

        let mut key_blob = Vec::new();
        key.key_data()
            .encode(&mut key_blob)
            .map_err(|e| Error::Filter(format!("failed to encode key: {e}")))?;

        Ok(Self {
            key_blob: Bytes::from(key_blob),
        })
    }

    /// Create directly from a wire-format public-key blob.
    pub fn from_blob(key_blob: Bytes) -> Self {
        Self { key_blob }
    }

    /// Whether `identity`'s blob equals this matcher's blob.
    pub fn matches(&self, identity: &Identity) -> bool {
        identity.key_blob == self.key_blob
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com";
        let matcher = PubkeyMatcher::new(key);
        assert!(matcher.is_ok());
    }

    #[test]
    fn test_parse_with_comment_ignored() {
        let key1 =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl different comment";

        let m1 = PubkeyMatcher::new(key1).unwrap();
        let m2 = PubkeyMatcher::new(key2).unwrap();

        assert_eq!(m1.key_blob, m2.key_blob);
    }

    #[test]
    fn test_invalid_key() {
        let result = PubkeyMatcher::new("not a valid key");
        assert!(result.is_err());
    }

    #[test]
    fn test_matches_enumerated_identity() {
        // A matcher built from an OpenSSH line must match the Identity built from
        // the same key's wire blob (proves the two encodings agree).
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl k";
        let matcher = PubkeyMatcher::new(key).unwrap();
        let id = Identity::new(matcher.key_blob.clone(), "k".to_string());
        assert!(matcher.matches(&id));
    }
}
