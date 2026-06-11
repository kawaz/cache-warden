//! Key type matching filter.
//!
//! Ported from authsock-warden `src/filter/keytype.rs`. Matches an [`Identity`]
//! by its key algorithm, accepting both the short form (`ed25519`, `rsa`) and the
//! full SSH algorithm name (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`, ...).

use crate::message::Identity;

/// Matcher for SSH key types.
#[derive(Debug, Clone)]
pub struct KeyTypeMatcher {
    key_type: String,
}

impl KeyTypeMatcher {
    /// Create a key-type matcher. Accepts both short forms (`ed25519`, `rsa`) and
    /// full algorithm names (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`).
    pub fn new(key_type: &str) -> Self {
        Self {
            key_type: Self::normalize(key_type),
        }
    }

    /// The normalized key type (e.g. `ed25519`, `rsa`, `ecdsa`).
    pub fn key_type(&self) -> &str {
        &self.key_type
    }

    /// Normalize an algorithm name / short form into a canonical key type.
    fn normalize(key_type: &str) -> String {
        let lower = key_type.to_lowercase();
        match lower.as_str() {
            "ssh-ed25519" | "ed25519" => "ed25519".to_string(),
            "ssh-rsa" | "rsa" => "rsa".to_string(),
            "ssh-dss" | "dsa" | "dss" => "dsa".to_string(),
            s if s.starts_with("ecdsa-sha2-") => "ecdsa".to_string(),
            "ecdsa" => "ecdsa".to_string(),
            s if s.starts_with("sk-ssh-ed25519") => "sk-ed25519".to_string(),
            "sk-ed25519" => "sk-ed25519".to_string(),
            s if s.starts_with("sk-ecdsa-sha2-") => "sk-ecdsa".to_string(),
            "sk-ecdsa" => "sk-ecdsa".to_string(),
            other => other.to_string(),
        }
    }

    /// Whether `identity`'s key type normalizes to the same canonical type.
    pub fn matches(&self, identity: &Identity) -> bool {
        if let Some(algo) = identity.key_type() {
            Self::normalize(&algo) == self.key_type
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(KeyTypeMatcher::normalize("ssh-ed25519"), "ed25519");
        assert_eq!(KeyTypeMatcher::normalize("ed25519"), "ed25519");
        assert_eq!(KeyTypeMatcher::normalize("SSH-RSA"), "rsa");
        assert_eq!(KeyTypeMatcher::normalize("ecdsa-sha2-nistp256"), "ecdsa");
        assert_eq!(KeyTypeMatcher::normalize("ssh-dss"), "dsa");
        assert_eq!(
            KeyTypeMatcher::normalize("sk-ssh-ed25519@openssh.com"),
            "sk-ed25519"
        );
    }

    #[test]
    fn test_key_type() {
        let matcher = KeyTypeMatcher::new("ed25519");
        assert_eq!(matcher.key_type(), "ed25519");

        let matcher = KeyTypeMatcher::new("ssh-rsa");
        assert_eq!(matcher.key_type(), "rsa");
    }
}
