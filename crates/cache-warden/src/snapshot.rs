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
//!
//! [`StoreSnapshot::to_bytes`]'s wire buffer (and the per-entry JSON payload
//! it is built from) is likewise `Zeroizing<Vec<u8>>`: the serialized bytes
//! interleave secret plaintext with non-secret framing in one allocation, so
//! the whole buffer is zeroized on drop rather than trying to zero only the
//! secret sub-ranges. [`StoreSnapshot::from_bytes`] takes a borrowed `&[u8]`
//! and cannot zeroize it itself — the caller is expected to hold that buffer
//! in a `Zeroizing<Vec<u8>>` (or equivalent) for its whole lifetime.
//!
//! # Wire format compatibility (DR-0029 §2)
//!
//! Compatibility is one-directional: a newer build can read an older
//! snapshot ([`FORMAT_VERSION`] within `[MIN_SUPPORTED_VERSION,
//! FORMAT_VERSION]`, checked by [`StoreSnapshot::is_supported_version`] /
//! `StoreSnapshot::from_bytes`), never the reverse. `format_version` bumps
//! are **additive only** — a new field on [`SnapshotEntry`] /
//! [`SnapshotValue`] / [`SnapshotDefinition`] / [`SnapshotFailure`], added
//! with `#[serde(default)]` so an older snapshot missing it still
//! deserializes. A breaking change (removing or repurposing a field) must
//! never reuse an existing `format_version`; it requires a new wire format
//! (a different [`MAGIC`]) instead of stretching this one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::source::ValueSource;

/// Wire format version (DR-0029 §2 header). Bumped on any **additive** change
/// to the per-entry payload shape (a new field, added with
/// `#[serde(default)]`). `StoreSnapshot::from_bytes` / `Store::import_snapshot`
/// accept any version in `[MIN_SUPPORTED_VERSION, FORMAT_VERSION]` (see the
/// module doc's "Wire format compatibility" section) and reject anything
/// outside that range rather than guess.
pub(crate) const FORMAT_VERSION: u32 = 6;

/// Wire version that carries refresh state but **no trailing data-key frame**
/// (DR-0034 §11). Anything at or below this is a stream that ends with the
/// entry frames.
///
/// The distinction is what makes the trailing frame safe to read. A reader
/// cannot tell "there is no frame" from "the frame has not arrived yet" by
/// looking at the socket — both look like no bytes available — so presence is
/// decided by the version instead: [`FORMAT_VERSION`] means a frame follows
/// and the reader blocks for it, anything lower means the stream is over.
/// Guessing with a timeout would be the alternative, and a guess that fires
/// early silently downgrades a graceful restart to a locked one.
pub(crate) const VERSION_PRE_DEK: u32 = 3;

/// Wire version emitted when an entry carries an owner principal but no
/// data-key frame follows (draft-DR-0033 §7).
///
/// # Why this is 5 and not 4
///
/// Four is the number a build from the previous generation writes to mean
/// "a data-key frame follows", and its reader *blocks* for that frame. An
/// owner-carrying snapshot emitted as 4 would therefore be read by such a
/// build as a promise of bytes that never arrive — a handoff that hangs
/// rather than fails. Emitting 5 puts it outside that build's accepted range
/// (`[1..=4]`), so it is refused outright and the successor cold-starts,
/// which is what §7 asks for: an owner that cannot be carried takes the value
/// with it.
///
/// The reverse pairing is safe by the same arithmetic. A version 4 snapshot
/// from an older build, read here, is *not* treated as carrying a frame
/// ([`StoreSnapshot::declares_dek_frame`] compares against
/// [`FORMAT_VERSION`]), so this build does not block for one either; it
/// simply does not pick up the data key, and the vault starts locked. Locked
/// is recoverable, hanging is not.
///
/// # A structural note for whoever touches this next
///
/// One number is carrying two independent facts — which content generation
/// the entries belong to, and whether a trailing frame follows — and that is
/// what made this collision possible. Every future content bump has to be
/// checked against every past frame-presence meaning by hand. Separating the
/// two (a content version plus an explicit frame flag in the header) is the
/// fix; it is deliberately not being done here, because changing the header
/// shape in the same change that renumbers the versions would leave no
/// version of this file that is easy to reason about.
pub(crate) const VERSION_WITH_OWNER: u32 = 5;

/// The oldest `format_version` this build still knows how to read. Only
/// moves forward if a future format change is *breaking* (at which point the
/// old range becomes permanently unreadable and gets a new [`MAGIC`] instead
/// of a bumped [`FORMAT_VERSION`] — see the module doc).
pub(crate) const MIN_SUPPORTED_VERSION: u32 = 1;

/// Wire version that carries no per-entry access guard (DR-0030). Emitted by
/// [`StoreSnapshot::from_entries`] when no entry carries a guard record — a
/// current-generation build that started using guards would step up to
/// [`FORMAT_VERSION`], and older builds (which cannot enforce guards) will
/// then refuse to import rather than silently drop the declarations
/// (DR-0030 §3 "ダウングレード方向"). Guard-free workloads keep producing
/// v1 snapshots so older-build downgrade stays cold-startable.
pub(crate) const VERSION_PRE_GUARD: u32 = 1;

/// Wire version that carries guards but no refresh arbitration state
/// (DR-0034 §4). Emitted when entries carry guards but no version or claim,
/// so a build that predates DR-0034 can still import a guarded snapshot.
///
/// Same downgrade reasoning as [`VERSION_PRE_GUARD`], one generation later: a
/// snapshot carrying a CAS version or a claim steps up to [`FORMAT_VERSION`]
/// so an older build refuses it rather than importing and silently dropping
/// them. Dropping a version would reset the counter a compare-and-swap relies
/// on; dropping a claim would reopen the double-refresh window it exists to
/// close.
pub(crate) const VERSION_PRE_REFRESH: u32 = 2;

/// Whether `v` falls within the inclusive `[MIN_SUPPORTED_VERSION,
/// FORMAT_VERSION]` range this build accepts. Shared by
/// [`StoreSnapshot::is_supported_version`] and `StoreSnapshot::from_bytes`
/// (which must check it before a [`StoreSnapshot`] even exists to call the
/// method on).
fn version_is_supported(v: u32) -> bool {
    (MIN_SUPPORTED_VERSION..=FORMAT_VERSION).contains(&v)
}

/// 8-byte magic prefix identifying a cache-warden handoff snapshot stream.
/// Not a security boundary (the DR-0029 channel is a private socketpair) —
/// just a cheap "is this even the right kind of stream" sanity check.
const MAGIC: [u8; 8] = *b"CWSNAP01";

/// Marks the optional trailing data-key frame (DR-0034 §11). Distinct from
/// [`MAGIC`] so a reader scanning for it cannot mistake the stream header for
/// a frame.
const DEK_FRAME_MAGIC: [u8; 8] = *b"CWVDEK01";

/// Upper bound on `entry_count` used to size the initial `Vec::with_capacity`
/// allocation in [`StoreSnapshot::from_bytes`]. `entry_count` is attacker-
/// controlled (read straight off the wire before any per-entry frame is
/// validated), so capacity is clamped to this rather than trusting it
/// directly — a corrupted/crafted count of e.g. `u32::MAX` would otherwise
/// force an oversized allocation before the truncation check on the frames
/// themselves ever runs. The real entry count (bounded by how many frames
/// actually parse) is unaffected; this only bounds the *pre-allocation* size.
const MAX_SANE_ENTRIES: u32 = 65_536;

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
    // `#[serde(default)]` on every Option/BTreeMap field below is the
    // additive-compat template (see the module doc's "Wire format
    // compatibility" section): a *future* new field on this struct should
    // follow the same pattern so a bundle-2-or-later build can still
    // deserialize a snapshot produced by this (older) build, which never
    // wrote that field at all.
    #[serde(default)]
    pub(crate) soft_ttl_ms: Option<u64>,
    #[serde(default)]
    pub(crate) hard_ttl_ms: Option<u64>,
    pub(crate) loaded_at_epoch_ms: u64,
    pub(crate) extended_at_epoch_ms: u64,
    #[serde(default)]
    pub(crate) pin_deadline_epoch_ms: Option<u64>,
}

/// A snapshotted **definition** (DR-0014): how a key's value is regenerated,
/// plus its opaque [`crate::ValueMeta`] / [`crate::SourceMeta`] slots. Holds
/// no secret — a definition never does.
#[derive(Serialize, Deserialize)]
pub(crate) struct SnapshotDefinition {
    pub(crate) source: SnapshotSource,
    // See the `#[serde(default)]` note on `SnapshotValue` — same additive-
    // compat template applies here.
    #[serde(default)]
    pub(crate) soft_ttl_ms: Option<u64>,
    #[serde(default)]
    pub(crate) hard_ttl_ms: Option<u64>,
    #[serde(default)]
    pub(crate) value_meta_type: Option<String>,
    #[serde(default)]
    pub(crate) value_meta_params: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) source_meta_kind: Option<String>,
    #[serde(default)]
    pub(crate) source_meta_fields: BTreeMap<String, String>,
}

/// A snapshotted in-progress refresh claim (DR-0034 §4), mirroring
/// [`crate::RefreshClaim`] for the wire — the same mirror-rather-than-derive
/// split [`SnapshotGuard`] uses, so the domain type stays free of a
/// serialization concern.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SnapshotRefreshClaim {
    pub(crate) token: String,
    pub(crate) claimed_at_epoch_ms: u64,
    pub(crate) expires_at_epoch_ms: u64,
}

/// A snapshotted fetch-failure backoff record (DR-0022), as a wall-clock
/// instant + duration rather than a process-local [`crate::clock::Monotonic`].
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct SnapshotFailure {
    pub(crate) failed_at_epoch_ms: u64,
    pub(crate) retry_after_ms: u64,
}

/// The declared kind of a `same-ancestor`-family constraint on the wire
/// (mirror of the core's `guard::DeclaredAncestor`). Evaluation ignores
/// which variant this is — it exists so `kv list` / the approver dialog can
/// render `"same-shell (zsh)"` vs `"same-ancestor (code)"` without carrying
/// a parallel display hint on every entry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SnapshotDeclaredAncestor {
    /// Declared via `--require-same-shell` (sugar). Carries the pinned
    /// shell's basename purely for display.
    SameShell { shell_name: String },
    /// Declared via `--require-same-ancestor=NAME`.
    Named { name: String },
}

/// The pinned process entity carried inside a `same-ancestor`-family
/// constraint (mirror of `guard::PinnedProcess`).
///
/// `start_time_us` carries the process's kernel-reported start time in
/// **microseconds** since the system epoch — deliberately finer than the
/// snapshot's other TTL timestamps (which live at millisecond resolution).
/// macOS's `proc_pidbsdinfo` reports start_time at μs precision, and
/// `PinnedProcess::start_time == PinnedProcess::start_time` is the entity
/// pin's identity check (DR-0030 §Security): truncating to ms would round
/// two "same instant" reads to different values across a snapshot round-trip,
/// which would fail the equality after graceful restart and turn every
/// same-ancestor guard into a fail-closed denial. `start_time_us` /
/// `unique_id` are `#[serde(default)]` so a future field addition on the
/// same wire version stays additive.
#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotPinnedProcess {
    pub(crate) pid: u32,
    #[serde(default)]
    pub(crate) start_time_us: Option<u64>,
    #[serde(default)]
    pub(crate) unique_id: Option<u64>,
    pub(crate) path: PathBuf,
    pub(crate) name: String,
}

/// One constraint of a snapshotted [`SnapshotGuard`] (mirror of
/// `guard::GuardConstraint`). Uses an internally-tagged serde
/// representation so an unknown constraint kind fails deserialization
/// rather than silently degrading to "no constraint" — safer than
/// `#[serde(other)]` for a security-sensitive record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SnapshotConstraint {
    SameUser,
    SameAncestor {
        declared: SnapshotDeclaredAncestor,
        pinned: SnapshotPinnedProcess,
    },
    Command {
        name: String,
    },
}

/// A snapshotted per-entry access guard record (DR-0030). Carries the
/// AND-composed constraint list plus a small setter identity snapshot
/// (`euid` / `ruid`). Distinct wire types are used rather than a raw
/// `serde(default)` on the core's [`crate::GuardRecord`] to keep the core's
/// public API free of a wire-format concern (same pattern as
/// [`SnapshotSource`] for [`crate::ValueSource`]).
/// Public because it is the **one** serializable form of a guard record, and
/// both persistence paths need it: the graceful-restart snapshot and the
/// encrypted vault (DR-0034 §1d). A second mirror for the vault would be a
/// second place for the two to drift, and drift here means a guard that comes
/// back subtly different from the one that was stored.
#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotGuard {
    /// The constraints, in declaration order.
    pub constraints: Vec<SnapshotConstraint>,
    /// The setter's effective uid.
    pub setter_euid: u32,
    /// The setter's real uid.
    pub setter_ruid: u32,
}

/// One key's full snapshotted state: its value, its definition, its
/// failure-backoff record, and its DR-0030 access guard, any combination of
/// which may be present or absent — mirroring the four independent maps
/// [`crate::Store`] keeps them in (DR-0014 / DR-0022 / DR-0030).
#[derive(Serialize, Deserialize)]
pub(crate) struct SnapshotEntry {
    pub(crate) key: String,
    // See the `#[serde(default)]` note on `SnapshotValue` — same additive-
    // compat template applies here.
    #[serde(default)]
    pub(crate) value: Option<SnapshotValue>,
    #[serde(default)]
    pub(crate) definition: Option<SnapshotDefinition>,
    #[serde(default)]
    pub(crate) failure: Option<SnapshotFailure>,
    /// DR-0030 guard record; present only on snapshots produced by builds
    /// that speak wire format >= [`FORMAT_VERSION`]. `#[serde(default)]` lets
    /// an older v1 payload (which never wrote this field) deserialize into
    /// `None`, matching the additive-compat template.
    #[serde(default)]
    pub(crate) guard: Option<SnapshotGuard>,
    /// draft-DR-0033 owner principal.
    ///
    /// Carried like the guard and for the same reason: a value that survives a
    /// restart without the authorization that governed it is a value that
    /// quietly became public.
    #[serde(default)]
    pub(crate) owner: Option<crate::owner::OwnerPrincipal>,
    /// DR-0034 §4 CAS version. `None` means the key has no version (and is
    /// what an older snapshot, which never wrote the field, deserializes to).
    ///
    /// Carried independently of `value`, unlike `guard`: a version outlives
    /// the value it counted (see `Store::versions`), so pruning it to match a
    /// live value would reset the counter across a restart and reintroduce
    /// exactly the stale-writer race it exists to stop.
    #[serde(default)]
    pub(crate) version: Option<u64>,
    /// DR-0034 §4 in-progress refresh claim. Bound to the live value like
    /// `guard` is, and exported only alongside one.
    #[serde(default)]
    pub(crate) refresh_claim: Option<SnapshotRefreshClaim>,
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
    /// Build a fresh snapshot at the current [`FORMAT_VERSION`].
    ///
    /// Only meaningful for tests that pin the "newest version" behavior
    /// explicitly; `Store::export_snapshot` uses [`Self::from_entries`]
    /// instead so guard-free workloads keep emitting v1 payloads for older
    /// builds to consume.
    #[cfg(test)]
    pub(crate) fn new(entries: Vec<SnapshotEntry>) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            entries,
        }
    }

    /// Build a snapshot, choosing the wire version by content (DR-0030 §3
    /// "ダウングレード方向"): any entry with a [`SnapshotGuard`] forces
    /// [`FORMAT_VERSION`] so an older build refuses to import (rather than
    /// silently dropping the guard); otherwise the snapshot stays on
    /// [`VERSION_PRE_GUARD`] to keep guard-free downgrade paths working.
    /// Declare that a trailing data-key frame will follow the entry frames
    /// (DR-0034 §11), by stepping the version up to the one that means it.
    ///
    /// Call this only when the frame is actually going to be written: the
    /// reader trusts the version and **blocks** for the frame, so a snapshot
    /// that declares one and does not send it stalls the handoff.
    pub fn declare_dek_frame(&mut self) {
        self.format_version = FORMAT_VERSION;
    }

    pub(crate) fn from_entries(entries: Vec<SnapshotEntry>) -> Self {
        let any_refresh = entries
            .iter()
            .any(|e| e.version.is_some() || e.refresh_claim.is_some());
        let any_guarded = entries.iter().any(|e| e.guard.is_some());
        let any_owned = entries.iter().any(|e| e.owner.is_some());
        // Step up only as far as the content requires, so a workload that uses
        // none of these keeps producing snapshots an older build can import.
        let format_version = if any_owned {
            VERSION_WITH_OWNER
        } else if any_refresh {
            VERSION_PRE_DEK
        } else if any_guarded {
            VERSION_PRE_REFRESH
        } else {
            VERSION_PRE_GUARD
        };
        Self {
            format_version,
            entries,
        }
    }

    /// Whether this snapshot's format version is one this build of the crate
    /// understands (`[MIN_SUPPORTED_VERSION, FORMAT_VERSION]`, see the module
    /// doc). `Store::import_snapshot` checks this before touching `entries` at
    /// all.
    pub(crate) fn is_supported_version(&self) -> bool {
        version_is_supported(self.format_version)
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
    /// Append a trailing data-key frame to an already-serialized snapshot
    /// (DR-0034 §11).
    ///
    /// Sits *after* the entry frames on purpose. [`StoreSnapshot::from_bytes`]
    /// stops once it has read `entry_count` frames and never looks further, so
    /// a build that predates this frame simply does not see it — and a
    /// successor that does not learn the data key starts with the vault
    /// **locked**. That is the safe direction: the user runs `vault unlock`
    /// once, rather than a stale reader silently gaining access it should not
    /// have. It is the mirror image of the format-version rule, where dropping
    /// a field would lose authorization and so must be refused instead.
    ///
    /// The key travels the same private socketpair the entry secrets already
    /// do (DR-0029), so carrying it adds no new trust assumption.
    pub fn append_dek_frame(buf: &mut Zeroizing<Vec<u8>>, dek: &[u8]) {
        buf.extend_from_slice(&DEK_FRAME_MAGIC);
        buf.extend_from_slice(&(dek.len() as u32).to_be_bytes());
        buf.extend_from_slice(dek);
    }

    /// Whether this snapshot's version says a data-key frame follows the entry
    /// frames (DR-0034 §11). See [`VERSION_PRE_DEK`] for why presence is
    /// carried by the version rather than discovered from the stream.
    pub fn declares_dek_frame(&self) -> bool {
        self.format_version >= FORMAT_VERSION
    }

    /// Bytes a declared data-key frame occupies: magic, length, and a key.
    pub const DEK_FRAME_LEN: usize = DEK_FRAME_MAGIC.len() + 4 + 32;

    /// Read back a data-key frame appended by [`StoreSnapshot::append_dek_frame`].
    ///
    /// `bytes` is the whole handoff buffer. Returns `None` when no frame is
    /// present, when it is truncated, or when it is malformed — every one of
    /// which lands on "start locked", the fail-closed outcome.
    ///
    /// The frame is read at one fixed offset from the end, never searched for.
    /// Searching would let the magic be *found* inside the data preceding it —
    /// and that data is entry secrets, which an attacker who can get a chosen
    /// value into the store controls byte for byte. A planted `CWVDEK01`
    /// followed by 32 bytes of their choosing would then be read as the data
    /// key by the successor process. At a fixed offset there is nothing to
    /// plant: either the real frame is there or no frame is.
    pub fn read_dek_frame(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let start = bytes.len().checked_sub(Self::DEK_FRAME_LEN)?;
        if bytes[start..start + DEK_FRAME_MAGIC.len()] != DEK_FRAME_MAGIC {
            return None;
        }
        let len_at = start + DEK_FRAME_MAGIC.len();
        let len = u32::from_be_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
        // A key is 32 bytes; anything else is not one this build can use.
        if len != 32 {
            return None;
        }
        let body = bytes.get(len_at + 4..len_at + 4 + len)?;
        Some(Zeroizing::new(body.to_vec()))
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ExportError> {
        let entry_count: u32 =
            self.entries
                .len()
                .try_into()
                .map_err(|_| ExportError::TooManyEntries {
                    count: self.entries.len(),
                })?;

        // Zeroizing: the wire buffer interleaves secret plaintext (each
        // entry's serde_json payload may embed `SnapshotValue::secret`) with
        // non-secret framing in one allocation, so the whole buffer is
        // zeroized on drop rather than trying to zero only the secret
        // sub-ranges (see the module doc's "Secret hygiene" section).
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&entry_count.to_be_bytes());

        for entry in &self.entries {
            // The intermediate serialized payload also carries plaintext
            // (before it is copied into `out`), so it gets the same
            // Zeroizing treatment rather than existing as a bare `Vec<u8>`.
            let payload =
                Zeroizing::new(serde_json::to_vec(entry).map_err(ExportError::Serialize)?);
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
    ///
    /// `bytes` is a plain borrowed slice: this function has no way to zeroize
    /// it itself. The caller is expected to hold the underlying buffer in a
    /// `Zeroizing<Vec<u8>>` (or equivalent) for as long as it is alive, same
    /// as the buffer [`StoreSnapshot::to_bytes`] hands back (see the module
    /// doc's "Secret hygiene" section) — this function only protects the
    /// [`SnapshotEntry`] values it produces, not the wire bytes it read from.
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
        if !version_is_supported(format_version) {
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

        // `entry_count` is attacker-controlled and read before any frame is
        // validated; clamp the *pre-allocation* size rather than trusting it
        // directly (see `MAX_SANE_ENTRIES`'s doc). The loop below still reads
        // exactly `entry_count` frames — this only bounds how much memory is
        // reserved up front.
        let mut entries = Vec::with_capacity(entry_count.min(MAX_SANE_ENTRIES) as usize);
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
    /// invariant on reconstruction, **or** its reconstructed `extended_at`
    /// preceded its `loaded_at` — both only reachable via corrupted or
    /// maliciously crafted snapshot bytes (a snapshot honestly produced by
    /// `Store::export_snapshot` always carries an already-valid `Ttl` and
    /// `extended_at >= loaded_at`, since `CacheEntry::extend` only ever moves
    /// `extended_at` forward from `loaded_at`).
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
    /// A key failed the composed-key syntax check (DR-0017 §1.5,
    /// [`crate::key::validate_key_syntax`]) on import — only reachable via
    /// corrupted or maliciously crafted snapshot bytes (`Store::set` /
    /// `Store::define` already reject an invalid key before it could ever
    /// reach `Store::export_snapshot`).
    InvalidKey {
        /// The offending key.
        key: String,
    },
    /// The same key appeared more than once among the snapshot's entries —
    /// only reachable via corrupted or maliciously crafted snapshot bytes
    /// (`Store::export_snapshot` de-duplicates keys by construction). Import
    /// is rejected outright rather than silently letting the later entry win,
    /// so a crafted snapshot cannot smuggle in an ambiguous overwrite.
    DuplicateKey {
        /// The offending key.
        key: String,
    },
    /// `serde_json` failed to deserialize an entry payload. The `Display`
    /// text deliberately does not include the `serde_json` error detail
    /// (which can echo fragments of the malformed payload); callers that need
    /// it for diagnostics should consult [`std::error::Error::source`], not
    /// log the `Display` output.
    Deserialize(serde_json::Error),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Truncated => write!(f, "snapshot stream ended unexpectedly (truncated)"),
            ImportError::BadMagic => write!(f, "not a cache-warden snapshot stream (bad magic)"),
            ImportError::UnsupportedVersion { got, supported } => write!(
                f,
                "unsupported snapshot format version {got} (this build supports {min}..={supported})",
                min = MIN_SUPPORTED_VERSION,
            ),
            ImportError::MalformedTtl { key } => {
                write!(
                    f,
                    "entry {key:?} carries an invalid TTL (soft > hard, or extended_at < loaded_at)"
                )
            }
            ImportError::MalformedDefinition { key } => {
                write!(f, "entry {key:?}'s definition carries a non-command source")
            }
            ImportError::InvalidKey { key } => {
                write!(f, "entry {key:?} is not a syntactically valid store key")
            }
            ImportError::DuplicateKey { key } => {
                write!(f, "entry {key:?} appears more than once in the snapshot")
            }
            ImportError::Deserialize(_) => {
                write!(
                    f,
                    "failed to deserialize snapshot entry (malformed payload)"
                )
            }
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
        sample_entry_with_value(key, b"hunter2")
    }

    fn sample_entry_with_value(key: &str, secret: &[u8]) -> SnapshotEntry {
        SnapshotEntry {
            key: key.to_string(),
            value: Some(SnapshotValue {
                source: SnapshotSource::Static,
                secret: Zeroizing::new(secret.to_vec()),
                soft_ttl_ms: Some(10_000),
                hard_ttl_ms: Some(30_000),
                loaded_at_epoch_ms: 1_000,
                extended_at_epoch_ms: 1_000,
                pin_deadline_epoch_ms: None,
            }),
            definition: None,
            failure: None,
            guard: None,
            owner: None,
            version: None,
            refresh_claim: None,
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

    /// UnsupportedVersion's Display must show the **inclusive range** the
    /// build accepts (`MIN..=FORMAT`), not just the upper bound. Reporting
    /// only the top edge misleads a user diagnosing a downgrade attempt
    /// ("supported 2" reads as "v1 too old" when v1 is still supported); the
    /// range makes both boundaries observable.
    #[test]
    fn unsupported_version_display_names_both_range_bounds() {
        let err = ImportError::UnsupportedVersion {
            got: 999,
            supported: FORMAT_VERSION,
        };
        let msg = err.to_string();
        let expected = format!("{MIN_SUPPORTED_VERSION}..={FORMAT_VERSION}");
        assert!(
            msg.contains(&expected),
            "display should carry the inclusive range {expected:?}: {msg}"
        );
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

    // ---- DR-0034 §11 data-key frame ----

    #[test]
    fn a_dek_frame_round_trips_on_the_end_of_a_snapshot() {
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut bytes = snap.to_bytes().unwrap();
        let dek = [7u8; 32];
        StoreSnapshot::append_dek_frame(&mut bytes, &dek);

        // The entries still parse: the reader stops at entry_count and never
        // sees the frame.
        let back = StoreSnapshot::from_bytes(&bytes).expect("entries still parse");
        assert_eq!(back.len(), 1);
        assert_eq!(
            StoreSnapshot::read_dek_frame(&bytes).map(|k| k.to_vec()),
            Some(dek.to_vec())
        );
    }

    /// The fail-closed direction: a snapshot with no frame yields no key, and
    /// the successor starts with the vault locked rather than open.
    #[test]
    fn a_snapshot_without_a_dek_frame_yields_no_key() {
        let bytes = StoreSnapshot::new(vec![sample_entry("A")])
            .to_bytes()
            .unwrap();
        assert!(StoreSnapshot::read_dek_frame(&bytes).is_none());
    }

    #[test]
    fn a_truncated_or_malformed_dek_frame_yields_no_key() {
        let snap = StoreSnapshot::new(vec![sample_entry("A")]);
        let mut full = snap.to_bytes().unwrap();
        StoreSnapshot::append_dek_frame(&mut full, &[7u8; 32]);

        // Every truncation of the frame must decline rather than hand back a
        // partial key.
        for cut in 1..=32 {
            let short = &full[..full.len() - cut];
            assert!(
                StoreSnapshot::read_dek_frame(short).is_none(),
                "a frame short by {cut} bytes must not yield a key"
            );
        }
        // A frame declaring a length no key has.
        let mut wrong = snap.to_bytes().unwrap();
        StoreSnapshot::append_dek_frame(&mut wrong, &[1u8; 16]);
        assert!(StoreSnapshot::read_dek_frame(&wrong).is_none());
    }

    /// A secret's bytes are chosen by whoever set it. If the frame were
    /// searched for rather than read at a fixed offset, a value shaped like a
    /// frame would be picked up as the data key by the process being handed
    /// to — a caller feeding cache-warden a crafted value would be choosing
    /// the key that decrypts the vault.
    /// The version a build of the previous generation writes to mean "a
    /// data-key frame follows", and the top of the range it accepts.
    #[cfg(test)]
    const PREVIOUS_GENERATION_FRAME_VERSION: u32 = 4;

    /// Compile-time half of `the_owner_version_cannot_be_mistaken_for_a_frame_declaration`:
    /// an owner-carrying snapshot must not be emitted at a number the previous
    /// generation reads as a frame promise (it would block for bytes that
    /// never come), and must fall outside the range it accepts at all (so it
    /// is refused and the successor cold-starts, rather than imported with the
    /// owner silently dropped).
    #[cfg(test)]
    const _: () = assert!(VERSION_WITH_OWNER > PREVIOUS_GENERATION_FRAME_VERSION);

    /// The version collision this numbering exists to avoid, from both sides.
    ///
    /// Version 4 means "a data-key frame follows" to a build of the previous
    /// generation, whose reader blocks for it. So:
    ///
    /// - an owner-carrying snapshot must not be emitted as 4, or that build
    ///   hangs waiting for bytes that never come;
    /// - a version 4 snapshot read *here* must not be treated as carrying a
    ///   frame, or this build hangs on one written by that build.
    ///
    /// The outgoing direction is arithmetic on constants, so it is checked at
    /// compile time just above this; the incoming one needs a snapshot to ask,
    /// so it is checked here.
    #[test]
    fn the_owner_version_cannot_be_mistaken_for_a_frame_declaration() {
        // And a snapshot at the old frame version is read here as frameless,
        // so this build does not block for a frame either. The vault simply
        // starts locked — recoverable, where a hang is not.
        let mut old = StoreSnapshot::new(vec![sample_entry("A")]);
        old.format_version = PREVIOUS_GENERATION_FRAME_VERSION;
        assert!(
            !old.declares_dek_frame(),
            "a version this build does not know as its own frame version must not make it wait"
        );
    }

    /// An owner-free snapshot must not be pushed up to the owner version: a
    /// workload that uses none of this keeps producing snapshots older builds
    /// can still import.
    #[test]
    fn only_an_owner_carrying_snapshot_reaches_the_owner_version() {
        let plain = StoreSnapshot::from_entries(vec![sample_entry("A")]);
        assert!(
            plain.format_version() < VERSION_WITH_OWNER,
            "{}",
            plain.format_version()
        );

        let mut owned = sample_entry("A");
        owned.owner = Some(
            crate::OwnerPrincipal::declare("apple-generic", "3QMEVK549R", "com.example.gw")
                .unwrap(),
        );
        assert_eq!(
            StoreSnapshot::from_entries(vec![owned]).format_version(),
            VERSION_WITH_OWNER
        );
    }

    #[test]
    fn a_frame_planted_inside_a_secret_is_not_mistaken_for_the_real_one() {
        let mut planted = Vec::new();
        planted.extend_from_slice(b"CWVDEK01");
        planted.extend_from_slice(&32u32.to_be_bytes());
        planted.extend_from_slice(&[0xAAu8; 32]);
        let snap = StoreSnapshot::new(vec![sample_entry_with_value("A", &planted)]);

        let no_frame = snap.to_bytes().unwrap();
        assert!(
            StoreSnapshot::read_dek_frame(&no_frame).is_none(),
            "a snapshot with no data-key frame must start locked, whatever its entries contain"
        );

        // And with a real frame appended, the real one is what comes back.
        let mut with_frame = snap.to_bytes().unwrap();
        StoreSnapshot::append_dek_frame(&mut with_frame, &[7u8; 32]);
        assert_eq!(
            StoreSnapshot::read_dek_frame(&with_frame)
                .unwrap()
                .as_slice(),
            &[7u8; 32],
            "the trailing frame is the key, not the one hidden in the value"
        );
    }

    #[test]
    fn an_empty_buffer_does_not_panic_looking_for_a_frame() {
        assert!(StoreSnapshot::read_dek_frame(&[]).is_none());
        assert!(StoreSnapshot::read_dek_frame(b"short").is_none());
    }

    // ---- SnapshotSource conversion ----

    #[test]
    fn snapshot_source_round_trips_static() {
        let s = SnapshotSource::from_value_source(&ValueSource::Static);
        assert!(matches!(s.into_value_source(), ValueSource::Static));
    }

    // ---- DR-0030 guard serde compat ----

    /// A v1 (pre-DR-0030) `SnapshotEntry` payload with no `guard` key must
    /// deserialize into `guard: None` via `#[serde(default)]` — the
    /// additive-compat template requirement for new fields (module doc
    /// "Wire format compatibility").
    #[test]
    fn snapshot_entry_without_guard_key_deserializes_to_none() {
        // Legal v1 payload: value present, no guard field.
        let json = r#"{
          "key":"K",
          "value":{
            "source":"Static",
            "secret":[104,105],
            "soft_ttl_ms":10000,
            "hard_ttl_ms":30000,
            "loaded_at_epoch_ms":1000,
            "extended_at_epoch_ms":1000
          }
        }"#;
        let entry: SnapshotEntry = serde_json::from_str(json).expect("v1 payload deserializes");
        assert!(entry.guard.is_none(), "missing guard key -> None");
    }

    /// A guarded entry round-trips through JSON with each constraint kind
    /// intact. Pins the wire-tag encoding (`same-user` / `same-shell` /
    /// `same-ancestor` / `command`) and the pinned-process shape so a serde
    /// rename would surface here.
    #[test]
    fn snapshot_guard_all_constraint_kinds_roundtrip() {
        let guard = SnapshotGuard {
            constraints: vec![
                SnapshotConstraint::SameUser,
                SnapshotConstraint::SameAncestor {
                    declared: SnapshotDeclaredAncestor::SameShell {
                        shell_name: "zsh".into(),
                    },
                    pinned: SnapshotPinnedProcess {
                        pid: 42,
                        // Deliberately a sub-ms value (…_567 µs, i.e. not a
                        // whole millisecond): pins the "µs precision is
                        // preserved" invariant that a millisecond field would
                        // silently break by round-tripping through as_millis.
                        start_time_us: Some(1_700_000_001_234_567),
                        unique_id: Some(999),
                        path: PathBuf::from("/bin/zsh"),
                        name: "zsh".into(),
                    },
                },
                SnapshotConstraint::SameAncestor {
                    declared: SnapshotDeclaredAncestor::Named {
                        name: "code".into(),
                    },
                    pinned: SnapshotPinnedProcess {
                        pid: 84,
                        start_time_us: None,
                        unique_id: None,
                        path: PathBuf::from("/Applications/VSCode.app"),
                        name: "code".into(),
                    },
                },
                SnapshotConstraint::Command { name: "git".into() },
            ],
            setter_euid: 501,
            setter_ruid: 501,
        };
        let entry = SnapshotEntry {
            key: "guarded".into(),
            value: None,
            definition: None,
            failure: None,
            guard: Some(guard),
            owner: None,
            version: None,
            refresh_claim: None,
        };
        let snap = StoreSnapshot::from_entries(vec![entry]);
        // A guarded snapshot must bump past the pre-guard version (DR-0030
        // §3). It lands on VERSION_PRE_REFRESH rather than FORMAT_VERSION
        // because DR-0034 added a further generation for refresh state: a
        // guard-only snapshot must stay importable by a build that has guards
        // but not claims, so it steps up exactly one generation, not two.
        assert_eq!(snap.format_version(), VERSION_PRE_REFRESH);
        let bytes = snap.to_bytes().expect("serialize");
        let back = StoreSnapshot::from_bytes(&bytes).expect("deserialize");
        let round = back.into_entries().pop().unwrap();
        let guard = round.guard.expect("guard survived");
        assert_eq!(guard.constraints.len(), 4);
        // Weak-form assertions on each kind — the exact struct comparison
        // is covered by the round-trip; here we pin the discriminants.
        assert!(matches!(guard.constraints[0], SnapshotConstraint::SameUser));
        assert!(matches!(
            guard.constraints[1],
            SnapshotConstraint::SameAncestor {
                declared: SnapshotDeclaredAncestor::SameShell { .. },
                ..
            }
        ));
        assert!(matches!(
            guard.constraints[2],
            SnapshotConstraint::SameAncestor {
                declared: SnapshotDeclaredAncestor::Named { .. },
                ..
            }
        ));
        assert!(matches!(
            guard.constraints[3],
            SnapshotConstraint::Command { .. }
        ));
        // µs precision: the sub-ms tail of the pinned process's start_time_us
        // must survive the JSON round-trip byte-for-byte. A regression that
        // truncates to ms (e.g. `start_time.as_millis()` in the exporter)
        // would round …_567 down to …_234 and break DR-0030 §Security's entity
        // pin equality check after a graceful restart.
        if let SnapshotConstraint::SameAncestor { pinned, .. } = &guard.constraints[1] {
            assert_eq!(
                pinned.start_time_us,
                Some(1_700_000_001_234_567),
                "µs precision must round-trip; ms truncation would zero the sub-ms tail"
            );
        } else {
            panic!("expected the second constraint to be SameAncestor");
        }
    }

    /// `from_entries` picks the wire version by content: any entry carrying
    /// a `SnapshotGuard` bumps to `FORMAT_VERSION`; a guard-free set stays
    /// on `VERSION_PRE_GUARD` (DR-0030 §3 "ダウングレード方向").
    #[test]
    fn from_entries_selects_version_by_guard_presence() {
        let plain = StoreSnapshot::from_entries(vec![sample_entry("A")]);
        assert_eq!(plain.format_version(), VERSION_PRE_GUARD);
        let mut guarded_entry = sample_entry("B");
        guarded_entry.guard = Some(SnapshotGuard {
            constraints: vec![SnapshotConstraint::SameUser],
            setter_euid: 0,
            setter_ruid: 0,
        });
        let guarded = StoreSnapshot::from_entries(vec![guarded_entry]);
        assert_eq!(guarded.format_version(), VERSION_PRE_REFRESH);
    }

    /// The DR-0034 generation of the same rule: refresh state steps the
    /// version up, so a build that predates claims refuses the snapshot rather
    /// than importing it and dropping them.
    ///
    /// It lands on `VERSION_PRE_DEK`, one below the newest, for the same
    /// reason guards land one below that: the newest version means "a data-key
    /// frame follows", and a snapshot carrying no key must not claim one — a
    /// reader would block waiting for bytes nobody is going to send.
    #[test]
    fn from_entries_steps_up_again_for_refresh_state() {
        let mut versioned = sample_entry("A");
        versioned.version = Some(7);
        assert_eq!(
            StoreSnapshot::from_entries(vec![versioned]).format_version(),
            VERSION_PRE_DEK
        );

        let mut claimed = sample_entry("B");
        claimed.refresh_claim = Some(SnapshotRefreshClaim {
            token: "tok".into(),
            claimed_at_epoch_ms: 1,
            expires_at_epoch_ms: 2,
        });
        assert_eq!(
            StoreSnapshot::from_entries(vec![claimed]).format_version(),
            VERSION_PRE_DEK
        );
    }

    /// Only a snapshot that will actually carry a key declares one, and the
    /// declaration is what the reader trusts.
    #[test]
    fn only_a_snapshot_carrying_a_key_declares_a_dek_frame() {
        let plain = StoreSnapshot::from_entries(vec![sample_entry("A")]);
        assert!(!plain.declares_dek_frame());

        let mut with_key = StoreSnapshot::from_entries(vec![sample_entry("A")]);
        with_key.declare_dek_frame();
        assert!(with_key.declares_dek_frame());
        assert_eq!(with_key.format_version(), FORMAT_VERSION);
    }

    /// A version and a claim must survive the wire round trip: the version is
    /// what a compare-and-swap compares against after a restart, and a claim
    /// that lost its token would be one nobody could complete or release.
    #[test]
    fn refresh_state_round_trips_through_the_wire() {
        let mut e = sample_entry("A");
        e.version = Some(9);
        e.refresh_claim = Some(SnapshotRefreshClaim {
            token: "abcdefghijklmnopqrstuv".into(),
            claimed_at_epoch_ms: 1_700_000_000_000,
            expires_at_epoch_ms: 1_700_000_060_000,
        });
        let bytes = StoreSnapshot::from_entries(vec![e]).to_bytes().unwrap();
        let back = StoreSnapshot::from_bytes(&bytes).unwrap();
        let got = back.into_entries().pop().unwrap();
        assert_eq!(got.version, Some(9));
        let c = got.refresh_claim.expect("claim survived");
        assert_eq!(c.token, "abcdefghijklmnopqrstuv");
        assert_eq!(c.claimed_at_epoch_ms, 1_700_000_000_000);
        assert_eq!(c.expires_at_epoch_ms, 1_700_000_060_000);
    }

    /// A pre-DR-0034 payload has neither field; both must default to `None`
    /// rather than failing to deserialize.
    #[test]
    fn an_entry_without_refresh_fields_deserializes_to_none() {
        let json = r#"{"key":"K"}"#;
        let entry: SnapshotEntry = serde_json::from_str(json).expect("old payload parses");
        assert!(entry.version.is_none());
        assert!(entry.refresh_claim.is_none());
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
