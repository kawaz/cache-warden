//! Public-key registry: maps an SSH wire public-key blob to its core KV key.
//!
//! The SSH agent REQUEST_IDENTITIES exchange returns *public* keys without ever
//! touching private material. The registry holds exactly that value-free
//! mapping: for each managed key it stores the wire-format public-key blob (the
//! identifier the client sends in a SIGN_REQUEST), a comment, and the name of
//! the core [`cache_warden::Store`] entry that holds the private-key PEM.
//!
//! This is the adapter side of the DR-0004 "NotLoaded" gap (port plan §1.3 /
//! §3 decision 4): the public key is always known (enumerable for `ssh-add -l`)
//! while the secret value's residency is governed entirely by the core's TTL
//! state. The registry never reads or holds the private key — it only knows
//! *which* core key to ask.
//!
//! The public key is derived once at registration time from the private-key PEM
//! (so the operator only configures the private key); the PEM is borrowed for
//! that derivation and not retained.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::message::Identity;
use crate::signer::public_key_blob_from_pem;
use bytes::Bytes;

/// One registered key: its public blob, comment, and backing core KV key.
#[derive(Debug, Clone)]
pub struct RegisteredKey {
    /// Wire-format public-key blob (the SIGN_REQUEST / IDENTITIES identifier).
    pub key_blob: Bytes,
    /// Human-readable comment shown by `ssh-add -l` / `-L`.
    pub comment: String,
    /// Name of the core [`cache_warden::Store`] entry holding the private PEM.
    pub kv_key: String,
}

/// A registry of public keys keyed by their wire blob.
///
/// Lookups during SIGN_REQUEST are by the exact key blob the client sends, so
/// the map is keyed on the raw blob bytes. Insertion order is irrelevant;
/// `BTreeMap` keeps enumeration deterministic for stable `ssh-add -l` output.
#[derive(Debug, Default)]
pub struct PublicKeyRegistry {
    by_blob: BTreeMap<Vec<u8>, RegisteredKey>,
}

impl PublicKeyRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the key behind `kv_key`, deriving its public blob from `pem`.
    ///
    /// `pem` is the private-key PEM (OpenSSH or PKCS#8); only its *public* half
    /// is derived and stored. The PEM is borrowed for the duration of this call
    /// and never retained. The comment defaults to `kv_key` when the PEM carries
    /// no comment (PKCS#8 keys have none).
    ///
    /// Returns an error if the PEM cannot be parsed into a key whose public half
    /// is derivable.
    pub fn register_from_pem(&mut self, kv_key: impl Into<String>, pem: &str) -> Result<()> {
        let kv_key = kv_key.into();
        let (key_blob, pem_comment) = public_key_blob_from_pem(pem)?;
        // PKCS#8 keys carry no comment; fall back to the kv key name so
        // `ssh-add -l` still shows a meaningful label.
        let comment = pem_comment.unwrap_or_else(|| kv_key.clone());
        self.by_blob.insert(
            key_blob.clone(),
            RegisteredKey {
                key_blob: Bytes::from(key_blob),
                comment,
                kv_key,
            },
        );
        Ok(())
    }

    /// Look up the registered key whose public blob equals `key_blob`.
    pub fn lookup(&self, key_blob: &[u8]) -> Option<&RegisteredKey> {
        self.by_blob.get(key_blob)
    }

    /// All registered keys as SSH agent [`Identity`] values, for an
    /// IDENTITIES_ANSWER. Order is deterministic (sorted by blob).
    pub fn identities(&self) -> Vec<Identity> {
        self.by_blob
            .values()
            .map(|k| Identity::new(k.key_blob.clone(), k.comment.clone()))
            .collect()
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.by_blob.len()
    }

    /// Whether the registry holds no keys.
    pub fn is_empty(&self) -> bool {
        self.by_blob.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;

    /// Test PKCS#8 Ed25519 PEM (1Password DR-014 spec). FOR TESTS ONLY.
    const OP_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n";

    /// Public counterpart of `OP_PRIVATE_KEY_PEM`. FOR TESTS ONLY.
    const OP_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ";

    #[test]
    fn register_derives_public_blob_matching_the_openssh_public_key() {
        let mut reg = PublicKeyRegistry::new();
        reg.register_from_pem("GITHUB_KEY", OP_PRIVATE_KEY_PEM)
            .unwrap();
        assert_eq!(reg.len(), 1);

        // The derived blob must equal the wire blob of the known public key.
        let expected = ssh_key::PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        let mut expected_blob = Vec::new();
        expected.key_data().encode(&mut expected_blob).unwrap();

        let found = reg.lookup(&expected_blob).expect("blob registered");
        assert_eq!(found.kv_key, "GITHUB_KEY");
    }

    #[test]
    fn comment_defaults_to_kv_key_for_pkcs8() {
        // PKCS#8 keys carry no comment; the registry falls back to the kv key.
        let mut reg = PublicKeyRegistry::new();
        reg.register_from_pem("MY_KEY", OP_PRIVATE_KEY_PEM).unwrap();
        let id = &reg.identities()[0];
        assert_eq!(id.comment, "MY_KEY");
    }

    #[test]
    fn identities_round_trip_through_public_key_parsing() {
        let mut reg = PublicKeyRegistry::new();
        reg.register_from_pem("K", OP_PRIVATE_KEY_PEM).unwrap();
        let id = &reg.identities()[0];
        // The blob the registry emits must parse back into a public key.
        assert!(id.public_key.is_some(), "blob must be a valid public key");
        // ...and that public key must equal the known public key.
        let expected = ssh_key::PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        assert_eq!(
            id.public_key.as_ref().unwrap().key_data(),
            expected.key_data()
        );
    }

    #[test]
    fn lookup_miss_returns_none() {
        let reg = PublicKeyRegistry::new();
        assert!(reg.lookup(b"nonexistent").is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn register_rejects_garbage_pem() {
        let mut reg = PublicKeyRegistry::new();
        assert!(reg.register_from_pem("K", "not a key").is_err());
    }
}
