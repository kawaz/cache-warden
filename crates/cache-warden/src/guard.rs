//! Per-entry access guard records (DR-0030).
//!
//! A guard is a plain-data record attached to a single `kv set` instance. It
//! answers "under what conditions may this entry be read?" declaratively: a
//! set-time list of [`GuardConstraint`]s (`same-user`, `same-ancestor` with an
//! entity pin, `command` by executable name) plus a small snapshot of the
//! setter's identity for symmetry with the constraint list.
//!
//! # Placement rationale
//!
//! This module holds **only the shape of the record**. Evaluation (checking
//! whether a getter's process context satisfies the constraints) lives in the
//! CLI/daemon layer (`cache-warden-cli::daemon::guard`), never in the core.
//! DR-0004 keeps chain interpretation out of the core: [`ProcessInfo`] is
//! surfaced as raw facts, and this record carries the *declaration*, not a
//! judgment. The same principle drives `[Store::failure_backoffs]` (data, no
//! policy) — the pattern here is identical.
//!
//! # Why a fourth [`Store`] map (not on [`CacheEntry`])
//!
//! An earlier alternative embedded a guard inside [`CacheEntry`], but a guard's
//! lifetime is "the set instance's declaration": it must be a *replaceable*
//! sibling of the value, not something whose evolution has to be threaded
//! through `CacheEntry::extend` / `pin` / `regenerate`. The same argument that
//! moved failure backoffs to their own map (DR-0022) applies here.
//!
//! [`ProcessInfo`]: crate::process::ProcessInfo
//! [`CacheEntry`]: crate::entry::CacheEntry
//! [`Store`]: crate::store::Store

use std::path::PathBuf;
use std::time::Duration;

/// A snapshot of one process pinned inside a `same-ancestor`-family constraint
/// (DR-0030 §1). Pid alone is reused by the kernel, so the entity is anchored
/// by pid + start_time (and, when the kernel exposes one, macOS's `unique_id`)
/// so a getter's evaluator can tell "the same process instance" from "a later
/// process that reused the pid".
///
/// The evaluator alone consumes these fields; the core stores them as opaque
/// facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedProcess {
    /// Process ID at the time of pinning.
    pub pid: u32,
    /// Process start time (offset since the system epoch), when the OS
    /// exposed one. `None` collapses this record to name-only comparison at
    /// evaluation time — fail-closed unless combined with `unique_id`.
    pub start_time: Option<Duration>,
    /// macOS `PROC_PIDUNIQIDENTIFIERINFO::unique_id` (finer than pid +
    /// start_time). `None` on other platforms or when the private API failed
    /// at set time; the evaluator falls back to start_time in that case.
    pub unique_id: Option<u64>,
    /// Full executable path at the time of pinning (empty [`PathBuf`] if the
    /// OS could not resolve it — a rare failure of `proc_pidpath`).
    pub path: PathBuf,
    /// Display name (typically the executable's basename). Kept alongside
    /// `path` so a dialog can print `"same-shell (zsh)"` without re-splitting
    /// the path at evaluation time.
    pub name: String,
}

/// The "declared kind" of a `same-ancestor`-family constraint.
///
/// Both variants land in the store as a [`GuardConstraint::SameAncestor`]
/// (their evaluation rule is identical: "the pinned entity must appear in the
/// getter's ancestry chain"). The variant only affects **display**: a
/// dialog / `kv list` renders `same-shell (zsh)` vs `same-ancestor (code)`
/// from this tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredAncestor {
    /// `--require-same-shell`: pin the closest shell in setter ancestry
    /// (sugar over [`DeclaredAncestor::Named`]).
    SameShell {
        /// The basename of the shell that was pinned (`"zsh"`, `"bash"`, …),
        /// for display in `kv list` / the approver dialog.
        shell_name: String,
    },
    /// `--require-same-ancestor=NAME`: pin the setter-side ancestor whose
    /// basename matches `name`.
    Named {
        /// The declared ancestor name as written on the CLI. Same string
        /// used for display.
        name: String,
    },
}

/// One access constraint on a guarded entry (DR-0030 §1).
///
/// Multiple constraints on a single record combine with **AND** at evaluation
/// time: the getter must satisfy every one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardConstraint {
    /// The getter's `euid` and `ruid` must equal the setter's recorded ones.
    /// Weak on its own inside a same-uid daemon (the socket already restricts
    /// to same-uid), but composes with the other constraints.
    SameUser,
    /// The getter's ancestry chain must contain the same process instance
    /// the setter pinned (pid + start_time + optional `unique_id`). Also
    /// carries a [`DeclaredAncestor`] tag purely for display — the evaluator
    /// treats `SameShell` and `Named` identically.
    SameAncestor {
        /// Whether this constraint was declared as `same-shell` (sugar) or
        /// as a name/path lookup. Evaluation ignores this; display uses it.
        declared: DeclaredAncestor,
        /// The process entity to look for in the getter's chain.
        pinned: PinnedProcess,
    },
    /// The getter's chain must contain a process whose executable path
    /// matches `name` either by basename or by full-path equality. Weak
    /// (spoofable by dropping a same-name binary in `$PATH`); documented as
    /// "weak" in help / dialog risk_note.
    Command {
        /// The basename or full path declared on the CLI
        /// (`--require-command=NAME`). Full path (starting with `/`) is
        /// matched literally; anything else is matched against the chain
        /// processes' basenames.
        name: String,
    },
}

/// A snapshot of the setter's identity, recorded at `kv set` time (DR-0030
/// §1b). Used by the evaluator to compare against the getter's audit token
/// when [`GuardConstraint::SameUser`] is in the record, and by the approver
/// dialog for the "who set this" display line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardSetter {
    /// Effective user id of the process that called `kv set`.
    pub euid: u32,
    /// Real user id of the same process. Both are recorded so a mid-transaction
    /// setuid/seteuid drift does not leave the record inconsistent.
    pub ruid: u32,
}

/// The per-entry guard record stored under a key inside
/// [`Store::access_guards`].
///
/// Constructed by the CLI/daemon layer from the incoming `kv set`
/// declaration and the connection's peer audit token, then handed to
/// [`Store::set_guard`] alongside the value. `Store::set` deliberately does
/// not touch this record — a set-with-no-guard call at the CLI layer is
/// expected to first call [`Store::clear_guard`] to drop any stale record
/// (so "the last declaration wins"; DR-0030 §5), which keeps the core
/// oblivious to CLI-side default policy (`default-require-same-user` etc.).
///
/// [`Store::access_guards`]: crate::store::Store
/// [`Store::set`]: crate::store::Store::set
/// [`Store::set_guard`]: crate::store::Store::set_guard
/// [`Store::clear_guard`]: crate::store::Store::clear_guard
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRecord {
    /// The AND-composed constraint list (DR-0030 §1). An empty vector is
    /// legal shape-wise but the evaluator treats it as fail-closed: the
    /// only path that would produce an empty list is a bug in the record's
    /// construction, and "silently pass" is the unsafe interpretation.
    pub constraints: Vec<GuardConstraint>,
    /// Setter identity snapshot (see [`GuardSetter`]).
    pub setter: GuardSetter,
}

impl GuardRecord {
    /// Construct a record. Prefer this over struct-literal construction so a
    /// future invariant (e.g. "at least one constraint") has a single choke
    /// point.
    pub fn new(constraints: Vec<GuardConstraint>, setter: GuardSetter) -> Self {
        Self {
            constraints,
            setter,
        }
    }
}
