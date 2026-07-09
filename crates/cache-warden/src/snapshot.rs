//! Graceful-restart state snapshot: serialize a running [`crate::Store`]'s
//! full state into a single buffer, and rebuild an equivalent store from it in
//! a fresh process (DR-0029 §2, Phase 1 / bundle 1).
//!
//! This module owns exactly two concerns:
//!
//! 1. **The in-memory shape** ([`StoreSnapshot`] / the private `Snapshot*`
//!    types): every key's value + definition + failure-backoff record, with
//!    TTL/pin/failure timestamps carried as wall-clock instants (see
//!    [`crate::clock::monotonic_to_epoch_ms`]) rather than the process-local
//!    [`crate::clock::Monotonic`] they started as.
//! 2. **The wire framing** ([`StoreSnapshot::to_bytes`] /
//!    [`StoreSnapshot::from_bytes`]): `magic(8B) + format_version(u32) +
//!    entry_count(u32)`, followed by `entry_count` frames of
//!    `len(u32) + serde_json payload`, per DR-0029 §2. Reading stops once
//!    `entry_count` entries have been read — it does not depend on EOF, so a
//!    stream that continues afterward (e.g. a two-phase-commit frame; DR-0029
//!    §5, bundle 2) is untouched by this reader.
//!
//! What is deliberately *not* here: the [`crate::Store`] traversal that builds
//! a [`StoreSnapshot`] from live entries, and the traversal that installs one
//! back into a fresh [`crate::Store`] — those live on `Store::export_snapshot`
//! / `Store::import_snapshot` in `store.rs`, alongside the private fields they
//! read/write. This module has no access to (and does not need) `Store`'s
//! internals.
//!
//! # Secret hygiene
//!
//! [`SnapshotValue::secret`] is a `Zeroizing<Vec<u8>>`: the one legitimate
//! plaintext copy `export_snapshot` must make (the live entry stays resident
//! in the running store; a copy is the only way to also hand it to a
//! [`StoreSnapshot`]) self-zeroizes if the snapshot is ever dropped before
//! being consumed (by `to_bytes` or `import_snapshot`), rather than lingering
//! in an unprotected `Vec<u8>`. None of the snapshot types derive `Debug` —
//! deriving it would print `secret`'s raw bytes, defeating the point.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::source::ValueSource;

/// Wire format version (DR-0029 §2 header). Bumped on any incompatible change
/// to the per-entry payload shape; `StoreSnapshot::from_bytes` /
/// `Store::import_snapshot` reject anything else rather than guess.
pub(crate) const FORMAT_VERSION: u32 = 1;

/// 8-byte magic prefix identifying a cache-warden handoff snapshot stream.
/// Not a security boundary (the DR-0029 channel is a private socketpair) —
/// just a cheap "is this even the right kind of stream" sanity check.
const MAGIC: [u8; 8] = *b"CWSNAP01";

/// The origin of a snapshotted value or definition, mirroring
/// [`crate::ValueSource`] for (de)serialization. A plain mirror rather than
/// deriving `Serialize`/`Deserialize` on `ValueSource` itself, so the core's
/// domain type stays free of a wire-format concern that only this one
/// snapshot feature needs.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum SnapshotSource {
    Static,
    Command {
        argv: Vec<String>,
        cwd: Option<PathBuf>,
        env: BTreeMap<String, String>,
    },
}

impl SnapshotSource {
    pub(crate) fn from_value_source(source: &ValueSource) -> Self {
        match source {
            ValueSource::Static => SnapshotSource::Static,
            ValueSource::Command { argv, cwd, env } => SnapshotSource::Command {
                argv: argv.clone(),
                cwd: cwd.clone(),
                env: env.clone(),
            },
        }
    }

    pub(crate) fn into_value_source(self) -> ValueSource {
        match self {
            SnapshotSource::Static => ValueSource::Static,
            SnapshotSource::Command { argv, cwd, env } => ValueSource::Command { argv, cwd, env },
        }
    }
}

/// A snapshotted **value** (a live, not-hard-expired [`crate::CacheEntry`]):
/// its source, TTL, secret bytes, and lifecycle timestamps as wall-clock
/// instants (milliseconds since the Unix epoch).
#[derive(Serialize, Deserialize)]
pub(crate) struct SnapshotValue {
    pub(crate) source: SnapshotSource,
    /// The one legitimate plaintext copy (see the module doc); zeroizes on
    /// drop if this snapshot is discarded before being consumed.
    pub(crate) secret: Zeroizing<Vec<u8>>,
    pub(crate) soft_ttl_ms: Option<u64>,
    pub(crate) hard_ttl_ms: Option<u64>,
    pub(crate) loaded_at_epoch_ms: u64,
    pub(crate) extended_at_epoch_ms: u64,
    pub(crate) pin_deadline_epoch_ms: Option<u64>,
}

/// A snapshotted **definition** (DR-0014): how a key's value is regenerated,
/// plus its opaque [`crate::ValueMeta`] / [`crate::SourceMeta`] slots. Holds
/// no secret — a definition never does.
#[derive(Serialize, Deserialize)]
pub(crate) struct SnapshotDefinition {
    pub(crate) source: SnapshotSource,
    pub(crate) soft_ttl_ms: Option<u64>,
    pub(crate) hard_ttl_ms: Option<u64>,
    pub(crate) value_meta_type: Option<String>,
    pub(crate) value_meta_params: BTreeMap<String, String>,
    pub(crate) source_meta_kind: Option<String>,
    pub(crate) source_meta_fields: BTreeMap<String, String>,
}

/// A snapshotted fetch-failure backoff record (DR-0022), as a wall-clock
/// instant + duration rather than a process-local [`crate::clock::Monotonic`].
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct SnapshotFailure {
    pub(crate) failed_at_epoch_ms: u64,
    pub(crate) retry_after_ms: u64,
}

/// One key's full snapshotted state: its value, its definition, and its
/// failure-backoff record, any combination of which may be present or absent
/// — mirroring the three independent maps [`crate::Store`] keeps them in
/// (DR-0014 / DR-0022).
#[derive(Serialize, Deserialize)]
pub(crate) struct SnapshotEntry {
    pub(crate) key: String,
    pub(crate) value: Option<SnapshotValue>,
    pub(crate) definition: Option<SnapshotDefinition>,
    pub(crate) failure: Option<SnapshotFailure>,
}

/// A serialized capture of a [`crate::Store`]'s full state (DR-0029 §2),
/// produced by `Store::export_snapshot` and consumed by
/// `Store::import_snapshot`. Opaque to callers outside this crate beyond its
/// byte-framing methods: there is deliberately no public accessor into
/// individual entries — a `StoreSnapshot` exists to travel from one `Store` to
/// another, not to be inspected in transit.
pub struct StoreSnapshot {
    format_version: u32,
    entries: Vec<SnapshotEntry>,
}

// Hand-written, secret-free: deriving `Debug` would recurse into
// `SnapshotEntry` -> `SnapshotValue::secret`, printing raw plaintext (the
// exact leak `SecretBytes`'s own custom `Debug` exists to prevent). Only the
// entry count and format version — never per-entry contents — are shown.
impl std::fmt::Debug for StoreSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSnapshot")
            .field("format_version", &self.format_version)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl StoreSnapshot {
    /// Build a fresh (current-version) snapshot from already-collected
    /// entries. Crate-internal: only `Store::export_snapshot` constructs one.
    pub(crate) fn new(entries: Vec<SnapshotEntry>) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            entries,
        }
    }

    /// Whether this snapshot's format version is one this build of the crate
    /// understands. `Store::import_snapshot` checks this before touching
    /// `entries` at all.
    pub(crate) fn is_supported_version(&self) -> bool {
        self.format_version == FORMAT_VERSION
    }

    pub(crate) fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Consume the snapshot, yielding its entries for `Store::import_snapshot`
    /// to install.
    pub(crate) fn into_entries(self) -> Vec<SnapshotEntry> {
        self.entries
    }

    /// The number of keys carried by this snapshot (value, definition, or
    /// both — see [`SnapshotEntry`]).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this snapshot carries no keys at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize into the DR-0029 §2 wire framing:
    /// `magic(8B) + format_version(u32, big-endian) + entry_count(u32,
    /// big-endian)`, followed by `entry_count` frames of
    /// `len(u32, big-endian) + serde_json(SnapshotEntry)`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ExportError> {
        let entry_count: u32 =
            self.entries
                .len()
                .try_into()
                .map_err(|_| ExportError::TooManyEntries {
                    count: self.entries.len(),
                })?;

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&entry_count.to_be_bytes());

        for entry in &self.entries {
            let payload = serde_json::to_vec(entry).map_err(ExportError::Serialize)?;
            let len: u32 = payload
                .len()
                .try_into()
                .map_err(|_| ExportError::EntryTooLarge {
                    key: entry.key.clone(),
                })?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&payload);
        }
        Ok(out)
    }

    /// Parse the DR-0029 §2 wire framing back into a [`StoreSnapshot`].
    ///
    /// Reads exactly `entry_count` length-prefixed frames — it does **not**
    /// depend on the buffer ending exactly there (trailing bytes, e.g. a
    /// two-phase-commit frame appended by a future caller, are left unread
    /// and do not cause an error). A truncated buffer, a corrupted length
    /// prefix, an unrecognized magic, or an unsupported `format_version` all
    /// return an [`ImportError`] rather than panicking — DR-0029's fail-safe
    /// requirement is that a corrupted handoff degrades to cold start, never
    /// a crash.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ImportError> {
        let mut cursor = bytes;

        let magic = take(&mut cursor, MAGIC.len()).ok_or(ImportError::Truncated)?;
        if magic != MAGIC {
            return Err(ImportError::BadMagic);
        }

        let format_version = u32::from_be_bytes(
            take(&mut cursor, 4)
                .ok_or(ImportError::Truncated)?
                .try_into()
                .expect("exactly 4 bytes"),
        );
        if format_version != FORMAT_VERSION {
            return Err(ImportError::UnsupportedVersion {
                got: format_version,
                supported: FORMAT_VERSION,
            });
        }

        let entry_count = u32::from_be_bytes(
            take(&mut cursor, 4)
                .ok_or(ImportError::Truncated)?
                .try_into()
                .expect("exactly 4 bytes"),
        );

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let len_bytes = take(&mut cursor, 4).ok_or(ImportError::Truncated)?;
            let len = u32::from_be_bytes(len_bytes.try_into().expect("exactly 4 bytes")) as usize;
            let payload = take(&mut cursor, len).ok_or(ImportError::Truncated)?;
            let entry: SnapshotEntry =
                serde_json::from_slice(payload).map_err(ImportError::Deserialize)?;
            entries.push(entry);
        }

        Ok(Self {
            format_version,
            entries,
        })
    }
}

/// Take the first `n` bytes off `*cursor`, advancing it past them. Returns
/// `None` (rather than panicking) if fewer than `n` bytes remain — the
/// primitive every truncation / corrupted-length-prefix check in
/// [`StoreSnapshot::from_bytes`] is built on.
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cursor.len() < n {
        return None;
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Some(head)
}

/// The current wall-clock instant, in milliseconds since the Unix epoch.
///
/// Used by `Store::export_snapshot` / `Store::import_snapshot` (not injected,
/// unlike the pure conversion functions in [`crate::clock`] — see that
/// module's doc for why those stay pure and testable while this one-shot wall
/// read does not need to be).
pub(crate) fn wall_now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
}

/// Error from [`StoreSnapshot::to_bytes`] / `Store::export_snapshot`.
#[derive(Debug)]
pub enum ExportError {
    /// The capability token does not match the store (DR-0024).
    CapMismatch,
    /// More entries than fit in a `u32` length field — unreachable in
    /// practice, kept as a defensive bound rather than a silent truncation.
    TooManyEntries {
        /// The actual entry count that overflowed `u32`.
        count: usize,
    },
    /// One entry's serialized JSON payload exceeded `u32::MAX` bytes.
    EntryTooLarge {
        /// The offending key.
        key: String,
    },
    /// `serde_json` failed to serialize an entry (should not happen for these
    /// plain-data types, but `serde_json::to_vec` is fallible).
    Serialize(serde_json::Error),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::CapMismatch => write!(f, "capability does not match this store"),
            ExportError::TooManyEntries { count } => {
                write!(
                    f,
                    "snapshot has {count} entries, which overflows a u32 entry count"
                )
            }
            ExportError::EntryTooLarge { key } => {
                write!(f, "entry {key:?} serialized to more than u32::MAX bytes")
            }
            ExportError::Serialize(e) => write!(f, "failed to serialize snapshot entry: {e}"),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExportError::Serialize(e) => Some(e),
            _ => None,
        }
    }
}

/// Error from [`StoreSnapshot::from_bytes`] / `Store::import_snapshot`.
///
/// Every variant is a **fail-safe** outcome (DR-0029 §"fail-safe の再定義"):
/// the caller is expected to fall back to a cold start, never to panic or
/// resurrect a partially-applied store.
#[derive(Debug)]
pub enum ImportError {
    /// The buffer ended before a length-prefixed field or frame could be read
    /// in full (a corrupted length prefix commonly manifests this way: it
    /// claims more bytes than the buffer actually has).
    Truncated,
    /// The 8-byte magic prefix did not match; this is not a cache-warden
    /// snapshot stream at all.
    BadMagic,
    /// The snapshot's `format_version` is not one this build understands.
    /// Per DR-0029 §2, compatibility is one-directional (new reads old), so
    /// this always means "too new" in practice.
    UnsupportedVersion {
        /// The version the snapshot declared.
        got: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// A key's TTL (soft/hard) failed [`crate::Ttl`]'s `soft <= hard`
    /// invariant on reconstruction — only reachable via corrupted or
    /// maliciously crafted snapshot bytes (a snapshot honestly produced by
    /// `Store::export_snapshot` always carries an already-valid `Ttl`).
    MalformedTtl {
        /// The offending key.
        key: String,
    },
    /// A key's definition claimed a `Static` source — only reachable via
    /// corrupted bytes (`Store::export_snapshot` only ever captures a
    /// definition's source, and DR-0014 guarantees a definition is always
    /// `Command`).
    MalformedDefinition {
        /// The offending key.
        key: String,
    },
    /// `serde_json` failed to deserialize an entry payload.
    Deserialize(serde_json::Error),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Truncated => write!(f, "snapshot stream ended unexpectedly (truncated)"),
            ImportError::BadMagic => write!(f, "not a cache-warden snapshot stream (bad magic)"),
            ImportError::UnsupportedVersion { got, supported } => write!(
                f,
                "unsupported snapshot format version {got} (this build supports {supported})"
            ),
            ImportError::MalformedTtl { key } => {
                write!(f, "entry {key:?} carries an invalid TTL (soft > hard)")
            }
            ImportError::MalformedDefinition { key } => {
                write!(f, "entry {key:?}'s definition carries a non-command source")
            }
            ImportError::Deserialize(e) => write!(f, "failed to deserialize snapshot entry: {e}"),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ImportError::Deserialize(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(key: &str) -> SnapshotEntry {
        SnapshotEntry {
            key: key.to_string(),
            value: Some(SnapshotValue {
                source: SnapshotSource::Static,
                secret: Zeroizing::new(b"hunter2".to_vec()),
                soft_ttl_ms: Some(10_000),
                hard_ttl_ms: Some(30_000),
                loaded_at_epoch_ms: 1_000,
                extended_at_epoch_ms: 1_000,
                pin_deadline_epoch_ms: None,
            }),
            definition: None,
            failure: None,
        }
    }

    // ---- to_bytes / from_bytes round trip ----

    #[test]
    fn empty_snapshot_round_trips() {
        let snap = StoreSnapshot::new(Vec::new());
        let bytes = snap.to_bytes().unwrap();
        let back = StoreSnapshot::from_bytes(&bytes).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.format_version(), FORMAT_VERSION);
    }

    #[test]
    fn snapshot_with_entries_round_trips_entry_count_and_payloads() {
        let snap = StoreSnapshot::new(vec![sample_entry("A"), sample_entry("B")]);
        let bytes = snap.to_bytes().unwrap();
        let back = StoreSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(back.len(), 2);
        let entries = back.into_entries();
        assert_eq!(entries[0].key, "A");
        assert_eq!(entries[1].key, "B");
        assert_eq!(
            entries[0].value.as_ref().unwrap().secret.as_slice(),
            b"hunter2"
        );
    }

    #[test]
    fn from_bytes_ignores_trailing_bytes_after_entry_count_frames() {
        // Reading stops once entry_count frames are read; extra trailing bytes
        // (e.g. a future two-phase-commit frame) must not cause an error.
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut bytes = snap.to_bytes().unwrap();
        bytes.extend_from_slice(b"COMMIT-ish-trailer");
        let back = StoreSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(back.len(), 1);
    }

    // ---- version rejection ----

    #[test]
    fn from_bytes_rejects_unsupported_format_version() {
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut bytes = snap.to_bytes().unwrap();
        // format_version occupies bytes [8..12) right after the 8-byte magic.
        bytes[8..12].copy_from_slice(&999u32.to_be_bytes());
        let err = StoreSnapshot::from_bytes(&bytes).unwrap_err();
        match err {
            ImportError::UnsupportedVersion { got, supported } => {
                assert_eq!(got, 999);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let snap = StoreSnapshot::new(Vec::new());
        let mut bytes = snap.to_bytes().unwrap();
        bytes[0] = b'X'; // corrupt the magic prefix
        assert!(matches!(
            StoreSnapshot::from_bytes(&bytes),
            Err(ImportError::BadMagic)
        ));
    }

    // ---- corrupted / truncated length prefixes ----

    #[test]
    fn from_bytes_rejects_truncated_header() {
        let bytes = &MAGIC[..6]; // not even a full magic prefix
        assert!(matches!(
            StoreSnapshot::from_bytes(bytes),
            Err(ImportError::Truncated)
        ));
    }

    #[test]
    fn from_bytes_rejects_a_length_prefix_that_overruns_the_buffer() {
        // A corrupted per-entry length prefix claiming far more bytes than are
        // actually present must error, not panic (index out of bounds) or
        // silently read garbage.
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut bytes = snap.to_bytes().unwrap();
        // The first entry's length prefix is the 4 bytes right after the
        // 12-byte header (magic + version + entry_count).
        bytes[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let err = StoreSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ImportError::Truncated));
    }

    #[test]
    fn from_bytes_rejects_entry_count_larger_than_actual_frames() {
        // Corrupt entry_count upward (claims 5 entries, only 1 is present):
        // the reader must fail with Truncated once frames run out, never panic.
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut bytes = snap.to_bytes().unwrap();
        bytes[8 + 4..8 + 4 + 4].copy_from_slice(&5u32.to_be_bytes());
        let err = StoreSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ImportError::Truncated));
    }

    #[test]
    fn from_bytes_of_empty_slice_is_truncated_not_a_panic() {
        assert!(matches!(
            StoreSnapshot::from_bytes(&[]),
            Err(ImportError::Truncated)
        ));
    }

    // ---- SnapshotSource conversion ----

    #[test]
    fn snapshot_source_round_trips_static() {
        let s = SnapshotSource::from_value_source(&ValueSource::Static);
        assert!(matches!(s.into_value_source(), ValueSource::Static));
    }

    #[test]
    fn snapshot_source_round_trips_command_with_cwd_and_env() {
        let mut env = BTreeMap::new();
        env.insert("K".to_string(), "V".to_string());
        let original = ValueSource::command_with(
            ["op".to_string(), "read".to_string()],
            Some(PathBuf::from("/tmp")),
            env,
        );
        let snap = SnapshotSource::from_value_source(&original);
        let back = snap.into_value_source();
        assert_eq!(back, original);
    }
}
