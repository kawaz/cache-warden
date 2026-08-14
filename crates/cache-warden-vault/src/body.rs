//! The vault body: what is actually encrypted (DR-0034 §1d).
//!
//! The body carries each entry's value **together with its authorization and
//! its version** — the guard record (DR-0030), the owner principal
//! (DR-0033) and the CAS version (DR-0034 §4) travel in the same sealed blob
//! as the secret they govern. DR-0034 §1d forbids the degraded restore where
//! a value comes back from cold start but its authorization does not; keeping
//! them in one structure means there is no partial-restore path to get wrong.
//!
//! # Encoding
//!
//! `serde_json`, matching the DR-0029 handoff snapshot. Both formats exist to
//! carry store state across a restart, and using one encoding for both keeps
//! them legible to the same tooling. The body is never seen in plaintext
//! outside this process, so compactness is not the deciding concern; being
//! able to read a decrypted body during an incident is.
//!
//! # Versioning
//!
//! [`BODY_VERSION`] is recorded inside the body, but the load-bearing
//! compatibility gate is the *header's* `format_version`
//! ([`crate::format::FORMAT_VERSION`]), which is refused outright when it is
//! newer than this build understands. That check happens before the body is
//! even decrypted, so a body written by a future build never reaches this
//! module's deserializer — which is what keeps "an older build silently drops
//! the fields it does not know and writes the vault back without them" from
//! being reachable at all. The in-body version is the finer-grained record for
//! diagnostics and for a future additive change within one header version.
//!
//! # Phase boundary
//!
//! [`VaultEntry::guard`] and [`VaultEntry::owner`] are typed placeholders. The
//! format reserves their place and round-trips their contents faithfully;
//! binding them to the core's `GuardRecord` and to DR-0033's owner principal
//! is phase 5's work. They are not `serde(skip)` or absent — a vault written
//! today and read after that phase must not have lost anything.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::claim::Claim;
use crate::error::VaultError;

/// Schema version of the body plaintext. See the module doc on why the
/// header's `format_version` is the gate that matters.
pub(crate) const BODY_VERSION: u32 = 1;

/// Where a value came from — a mirror of the core's `ValueSource`, kept here
/// so the core's domain type stays free of this format's concerns (the same
/// split the DR-0029 snapshot makes).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum VaultSource {
    /// A value supplied directly, with no way to regenerate it.
    Static,
    /// A value produced by running a command.
    Command {
        /// Argument vector, program first.
        argv: Vec<String>,
        /// Working directory, if pinned.
        cwd: Option<PathBuf>,
        /// Environment overlay.
        env: BTreeMap<String, String>,
    },
}

/// An entry's opaque value metadata — a mirror of the core's `ValueMeta`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct VaultValueMeta {
    /// The declared type name, if any.
    #[serde(default)]
    pub type_name: Option<String>,
    /// Type-specific parameters.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// How an entry's value is regenerated — a mirror of the core's `Definition`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VaultDefinition {
    /// The regeneration source.
    pub source: VaultSource,
    /// Soft TTL in milliseconds.
    #[serde(default)]
    pub soft_ttl_ms: Option<u64>,
    /// Hard TTL in milliseconds. A `cw-owned` entry carries none — DR-0034 §5
    /// exempts it, since an absolute lifetime on a refresh token would expire
    /// the only copy of the credential.
    #[serde(default)]
    pub hard_ttl_ms: Option<u64>,
    /// Opaque source metadata.
    #[serde(default)]
    pub source_meta_kind: Option<String>,
    /// Opaque source metadata fields.
    #[serde(default)]
    pub source_meta_fields: BTreeMap<String, String>,
}

/// Reserved place for the DR-0030 access guard record.
///
/// Phase 5 replaces the inner value with the core's `GuardRecord`. Until then
/// the contents are carried verbatim so nothing written by a later build is
/// lost on a round trip through this one.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GuardRecordSlot(pub serde_json::Value);

/// Reserved place for the DR-0033 owner principal. Same phase-5 note as
/// [`GuardRecordSlot`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwnerPrincipalSlot(pub serde_json::Value);

/// One persisted entry.
///
/// No derived `Debug`: [`VaultEntry::secret`] is plaintext, and a derive would
/// print it. The hand-written implementation below reports the shape and
/// redacts the value.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// The store key.
    pub key: String,
    /// The secret value. `Zeroizing` so a decrypted entry dropped without
    /// being consumed does not leave plaintext behind.
    pub secret: Zeroizing<Vec<u8>>,
    /// The entry's CAS version (DR-0034 §4): monotonic, persisted, and the
    /// basis of refresh arbitration.
    ///
    /// **Assigned by the vault, not by the caller.** Every successful write
    /// sets it to the previous value plus one, overwriting whatever the
    /// submitted entry carried. A caller-chosen version could be set backwards,
    /// and a version that can go backwards is worse than none at all: DR-0034
    /// §4 relies on monotonicity to keep a consumed refresh token from being
    /// treated as current again.
    pub cas_version: u64,
    /// An in-progress refresh holding this entry (DR-0034 §4), or `None` when
    /// no refresh is claimed.
    ///
    /// Persisted, so a claim survives the daemon restart it most needs to
    /// survive — an upgrade in the middle of a refresh. `#[serde(default)]`
    /// keeps a phase-1 body (written before claims existed) readable, which is
    /// why adding this needed no `format_version` bump.
    #[serde(default)]
    pub refresh_claim: Option<Claim>,
    /// Value metadata, if any.
    #[serde(default)]
    pub value_meta: Option<VaultValueMeta>,
    /// Regeneration definition, if any.
    #[serde(default)]
    pub definition: Option<VaultDefinition>,
    /// DR-0030 guard record. See [`GuardRecordSlot`].
    #[serde(default)]
    pub guard: Option<GuardRecordSlot>,
    /// DR-0033 owner principal. See [`OwnerPrincipalSlot`].
    #[serde(default)]
    pub owner: Option<OwnerPrincipalSlot>,
    /// When this entry was last written, in milliseconds since the Unix epoch.
    pub updated_at_epoch_ms: u64,
}

impl VaultEntry {
    /// A new entry at CAS version 1 with no metadata, definition, guard or
    /// owner.
    pub fn new(key: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            secret: Zeroizing::new(secret.into()),
            cas_version: 1,
            refresh_claim: None,
            value_meta: None,
            definition: None,
            guard: None,
            owner: None,
            updated_at_epoch_ms: crate::format::now_epoch_ms(),
        }
    }
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("key", &self.key)
            .field("secret_len", &self.secret.len())
            .field("secret", &"[REDACTED]")
            .field("cas_version", &self.cas_version)
            .field("claimed", &self.refresh_claim.is_some())
            .field("has_value_meta", &self.value_meta.is_some())
            .field("has_definition", &self.definition.is_some())
            .field("has_guard", &self.guard.is_some())
            .field("has_owner", &self.owner.is_some())
            .finish()
    }
}

/// The whole body plaintext.
#[derive(Serialize, Deserialize)]
pub(crate) struct VaultBody {
    pub(crate) body_version: u32,
    pub(crate) entries: Vec<VaultEntry>,
}

impl VaultBody {
    pub(crate) fn new(entries: Vec<VaultEntry>) -> Self {
        Self {
            body_version: BODY_VERSION,
            entries,
        }
    }

    /// Serialize into a self-zeroizing buffer.
    ///
    /// The buffer interleaves secret plaintext with framing in one allocation,
    /// so the whole thing is wiped on drop rather than trying to zero the
    /// secret sub-ranges (the same reasoning as the DR-0029 snapshot's wire
    /// buffer).
    ///
    /// The capacity is estimated up front rather than left to grow. A `Vec`
    /// that reallocates copies what it holds to a new allocation and frees the
    /// old one **without wiping it**, so every growth step during
    /// serialization would leave another copy of partially-serialized secret
    /// material in freed heap that nothing zeroizes. Reserving enough at the
    /// start removes those intermediate copies; it does not remove the ones
    /// `serde_json` makes internally, which is a known limit recorded in the
    /// crate documentation.
    pub(crate) fn to_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(self.estimated_len()));
        serde_json::to_writer(&mut *buf, self)
            .expect("the body schema is plain data and writing to a Vec cannot fail");
        buf
    }

    /// A generous upper estimate of the serialized length.
    ///
    /// Secret bytes dominate: `serde_json` renders each as a decimal in an
    /// array, costing up to four characters (`255,`). The per-entry constant
    /// covers the field names and the metadata, and the whole thing is
    /// deliberately over- rather than under-estimated — over-reserving wastes
    /// a little memory, under-reserving reintroduces the reallocation this
    /// exists to avoid.
    fn estimated_len(&self) -> usize {
        const PER_ENTRY_OVERHEAD: usize = 512;
        const ENVELOPE: usize = 64;
        self.entries
            .iter()
            .map(|e| e.key.len() + e.secret.len() * 4 + PER_ENTRY_OVERHEAD)
            .sum::<usize>()
            + ENVELOPE
    }

    pub(crate) fn from_plaintext(bytes: &[u8]) -> Result<Self, VaultError> {
        serde_json::from_slice(bytes).map_err(VaultError::MalformedBody)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_entry() -> VaultEntry {
        let mut env = BTreeMap::new();
        env.insert("OP_ACCOUNT".to_string(), "example".to_string());
        VaultEntry {
            key: "llm/refresh-token".to_string(),
            secret: Zeroizing::new(b"rt-abc123".to_vec()),
            cas_version: 7,
            refresh_claim: None,
            value_meta: Some(VaultValueMeta {
                type_name: Some("oauth-refresh-token".to_string()),
                params: BTreeMap::from([("issuer".to_string(), "example".to_string())]),
            }),
            definition: Some(VaultDefinition {
                source: VaultSource::Command {
                    argv: vec!["op".to_string(), "read".to_string()],
                    cwd: Some(PathBuf::from("/tmp")),
                    env,
                },
                soft_ttl_ms: Some(600_000),
                hard_ttl_ms: None,
                source_meta_kind: Some("op".to_string()),
                source_meta_fields: BTreeMap::from([("vault".to_string(), "Private".to_string())]),
            }),
            guard: Some(GuardRecordSlot(serde_json::json!({
                "constraints": [{"kind": "same-user"}],
                "setter_euid": 501
            }))),
            owner: Some(OwnerPrincipalSlot(serde_json::json!({
                "signed_by": "SHA256:abc"
            }))),
            updated_at_epoch_ms: 1_723_600_000_000,
        }
    }

    #[test]
    fn body_round_trips_every_field_of_a_fully_populated_entry() {
        let body = VaultBody::new(vec![full_entry()]);
        let bytes = body.to_plaintext();
        let back = VaultBody::from_plaintext(&bytes).expect("parses");
        assert_eq!(back.body_version, BODY_VERSION);
        let got = &back.entries[0];
        let want = full_entry();
        assert_eq!(got.key, want.key);
        assert_eq!(got.secret.as_slice(), want.secret.as_slice());
        assert_eq!(got.cas_version, 7);
        assert_eq!(got.value_meta, want.value_meta);
        assert_eq!(got.definition, want.definition);
        assert_eq!(got.updated_at_epoch_ms, want.updated_at_epoch_ms);
    }

    /// The DR-0034 §1d requirement in its narrowest form: the guard record and
    /// the owner principal survive a round trip byte-for-byte, so a value
    /// never comes back without the authorization that governs it.
    #[test]
    fn guard_and_owner_placeholders_survive_a_round_trip_unchanged() {
        let body = VaultBody::new(vec![full_entry()]);
        let back = VaultBody::from_plaintext(&body.to_plaintext()).expect("parses");
        let got = &back.entries[0];
        assert_eq!(got.guard, full_entry().guard);
        assert_eq!(got.owner, full_entry().owner);
    }

    #[test]
    fn a_new_entry_starts_at_cas_version_one_with_no_authorization() {
        let e = VaultEntry::new("k", b"v".to_vec());
        assert_eq!(e.cas_version, 1);
        assert!(e.guard.is_none());
        assert!(e.owner.is_none());
        assert!(e.definition.is_none());
    }

    #[test]
    fn optional_fields_absent_from_the_json_deserialize_as_none() {
        let json = br#"{"body_version":1,"entries":[
            {"key":"k","secret":[104,105],"cas_version":2,"updated_at_epoch_ms":5}
        ]}"#;
        let body = VaultBody::from_plaintext(json).expect("parses");
        let e = &body.entries[0];
        assert_eq!(e.secret.as_slice(), b"hi");
        assert_eq!(e.cas_version, 2);
        assert!(e.value_meta.is_none() && e.definition.is_none());
        assert!(e.guard.is_none() && e.owner.is_none());
    }

    #[test]
    fn from_plaintext_rejects_garbage_instead_of_panicking() {
        assert!(matches!(
            VaultBody::from_plaintext(b"not json"),
            Err(VaultError::MalformedBody(_))
        ));
    }

    #[test]
    fn debug_redacts_the_secret_value() {
        let out = format!("{:?}", full_entry());
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("llm/refresh-token"), "the key is not a secret");
        assert!(!out.contains("rt-abc123"));
    }
}
