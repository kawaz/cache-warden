//! Approver IPC wire schema (draft-DR-0031 §4): daemon ↔ helper, JSON Lines.
//!
//! # Why JSON Lines
//!
//! The daemon is Rust and the helper is a separate process (this crate's
//! `main.rs` bin, macOS-only AppKit code); JSON is the natural common ground
//! since a shared Rust type cannot cross the process boundary directly. One
//! JSON object per line — one line for the request, one line for the
//! response — keeps the framing unambiguous for a single-shot exchange (no
//! length-prefixing needed) and trivially inspectable by hand (`nc` / `socat`),
//! matching the control-socket wire's convention
//! (`cache-warden-cli::protocol::wire`). Approval requests are low-volume and
//! latency-tolerant (human TouchID interaction, seconds), so a streaming or
//! binary framing would add complexity with no payoff here.
//!
//! # Scope (Phase 1.4)
//!
//! This module defines the schema only. The daemon-side socket lifecycle
//! (bind / spawn / accept / send / receive-with-timeout) lives in
//! `cache-warden-cli::daemon::approver`; the helper-side connect / read /
//! write lives in this crate's `main.rs`.

use serde::{Deserialize, Serialize};

/// Wire protocol version carried on every [`ApproveRequest`] / [`ApproveResponse`].
///
/// The daemon and helper ship as one binary release (Phase 1.4 has no
/// independent versioning story yet), so this is a forward-compatibility
/// placeholder rather than a live negotiation — bump it when a breaking wire
/// change ships and something needs to tell old from new.
pub const WIRE_VERSION: u32 = 1;

/// The approval request (daemon → helper), one JSON object per line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApproveRequest {
    /// Protocol version (see [`WIRE_VERSION`]).
    pub v: u32,
    /// Opaque identifier for this request, echoed back on
    /// [`ApproveResponse::request_id`] so the daemon can match a reply to its
    /// pending request without relying on connection identity alone. Phase
    /// 1.4: the daemon mints a unique string (e.g. pid + monotonic nanos); no
    /// `uuid` crate dependency is added just for this.
    pub request_id: String,
    /// The target kv entry (namespace included).
    pub key: String,
    /// The operation being authorized: `"get"` | `"extend"` | `"regenerate"`
    /// | `"pin"`. Carried as a plain string — the daemon owns the set of
    /// valid operations; the helper only displays it, never branches on it.
    pub operation: String,
    /// The process requesting access.
    pub requester: Requester,
    /// DR-0030 guard evaluation result, or `None` when the entry has no guard
    /// (Phase 1 only fires this dialog for guarded entries — see draft-DR-0031
    /// §8 — so in practice this is always `Some` today, but the field stays
    /// optional for the ungated future case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_eval: Option<GuardEval>,
    /// Upper bound, in seconds, on how long the daemon will wait for
    /// [`ApproveResponse`] before giving up on this request. Carried on the
    /// wire for the helper's own future use (a Phase 2 in-dialog countdown);
    /// Phase 1.4 enforcement is entirely daemon-side
    /// (`cache-warden-cli::daemon::approver::exchange`'s
    /// `tokio::time::timeout`), the helper does not run its own timer yet.
    pub timeout_secs: u32,
}

/// The process requesting access to a kv entry (`ApproveRequest.requester`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    /// Ancestry chain, most-recent process first (the requester itself),
    /// walking toward `launchd`. Facts only — no policy interpretation (that
    /// already happened in DR-0030's guard evaluation, reflected in
    /// `guard_eval` below).
    pub chain: Vec<ProcessChainEntry>,
    /// The requester's audit token (peer credentials at connect time).
    pub audit_token: AuditToken,
    /// The TCC "responsible process" bundle id (DR-0020), when resolvable.
    /// Used to pick the requester icon shown in the dialog; a CLI launched
    /// without a resolvable responsible process (e.g. a shell-invoked `curl`)
    /// leaves this `None` and the helper falls back to walking `chain` for
    /// the topmost `.app` ancestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub responsible_bundle_id: Option<String>,
}

/// One process in a [`Requester::chain`].
///
/// Required plain fields rather than the core's `Option`-heavy
/// `cache_warden::ProcessInfo`: the daemon resolves "unknown" down to a
/// wire-safe default before this ever reaches the wire (`ppid: 0` matches the
/// existing launchd-at-top-of-tree convention already used by the core; an
/// unresolved `path` becomes `""`). The helper is a separate, display-only
/// consumer — it has no use for an `Option` it cannot meaningfully act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessChainEntry {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID (`0` for "unknown" / top of tree, matching
    /// `cache_warden::ProcessInfo`'s launchd convention).
    pub ppid: u32,
    /// Full path to the executable (`""` if unresolved).
    pub path: String,
    /// Process start time, Unix epoch nanoseconds (same unit as
    /// [`GuardEval::evaluated_at`], so the two are directly comparable).
    pub start_time: u64,
}

/// The requester's audit token (peer credentials), used for the display-only
/// "same-user" chip and, at the daemon's own peer-verification layer
/// (draft-DR-0031 §Security), for pid-reuse disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditToken {
    /// Effective user id.
    pub euid: u32,
    /// Real user id.
    pub ruid: u32,
    /// Effective group id.
    pub egid: u32,
    /// Process id (same value as the chain's leading `pid`, carried here too
    /// since the audit token is captured as one atomic unit at connect time).
    pub pid: u32,
    /// macOS audit token `pid_version` (generation counter): distinguishes a
    /// live process from a different, later process that reused the same pid.
    pub pid_version: u32,
}

/// DR-0030 guard evaluation result attached to a guarded entry's approval
/// request (`ApproveRequest.guard_eval`).
///
/// Structured (not a flat `Vec<String>` summary) so the dialog's detail
/// panel can show per-constraint strength / risk and the pinned setter/getter
/// identity (draft-DR-0031 §4 rationale: "codex review medium-4").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEval {
    /// Per-constraint evaluation, in the order DR-0030 evaluated them. All
    /// entries reaching the dialog have `matched: true` — a guard failure
    /// short-circuits to a denial before the dialog is ever shown (draft-DR-0031
    /// §Security: "guard 評価 → fail なら dialog 出さずに拒否").
    pub constraints: Vec<ConstraintEval>,
    /// The setter process identity pinned by a `same-ancestor`-family
    /// constraint, if any such constraint is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setter_pinned: Option<ProcessSnapshot>,
    /// The getter (requester) process that matched the pinned setter
    /// identity, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub getter_matched: Option<ProcessSnapshot>,
    /// When the guard was evaluated, Unix epoch nanoseconds.
    pub evaluated_at: u64,
}

/// A single DR-0030 constraint's evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEval {
    /// The constraint kind: `"same-user"` | `"same-shell"` | `"same-ancestor"`
    /// | `"command"`.
    pub kind: String,
    /// Whether the requester satisfied this constraint. Always `true` for a
    /// request that reaches the dialog (see [`GuardEval::constraints`] docs).
    pub matched: bool,
    /// Identification strength: `"strong"` | `"weak"`. Weak identifications
    /// (e.g. `command`, matched by argv rather than a pinned process
    /// identity) get a warning chip in the dialog.
    pub strength: String,
    /// Human-readable label for the dialog's detail panel, e.g.
    /// `"same-shell (zsh)"`.
    pub display_label: String,
    /// Warning text shown alongside a `strength: "weak"` constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_note: Option<String>,
}

/// A pinned process identity (setter or getter side of a `same-ancestor`
/// constraint), precise enough to survive pid-reuse comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// Process ID at the time of pinning.
    pub pid: u32,
    /// Process start time, Unix epoch nanoseconds.
    pub start_time: u64,
    /// macOS process unique id, when the platform exposes one (finer-grained
    /// than pid + start_time alone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_id: Option<u64>,
    /// Full executable path.
    pub path: String,
    /// Display name (typically the executable's basename).
    pub name: String,
}

/// The approval response (helper → daemon), one JSON object per line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveResponse {
    /// Protocol version (see [`WIRE_VERSION`]).
    pub v: u32,
    /// Echoes [`ApproveRequest::request_id`].
    pub request_id: String,
    /// The final disposition of this approval request.
    pub outcome: Outcome,
    /// Which biometric modality was evaluated, when relevant (`"TouchID"` |
    /// `"Watch"`). `None` for outcomes where no biometric evaluation ran
    /// (e.g. [`Outcome::Cancelled`] before the user touched the sensor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biometric_kind: Option<String>,
}

/// The final disposition of an approval request (`ApproveResponse.outcome`).
///
/// Serializes as a snake_case string (`"peer_gone"`, not a tagged object):
/// the daemon only branches on which variant it got, never on any payload, so
/// a plain string is the simplest wire shape (draft-DR-0031 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The user authenticated successfully.
    Approved,
    /// The daemon (or a future policy layer) rejected the request before or
    /// without asking the user. Phase 1.4: the helper itself never produces
    /// this — it is here for wire completeness with entries that can deny
    /// without a dialog (draft-DR-0031 §Security guard-fail path).
    Denied,
    /// The user dismissed the dialog (Cancel button, or window closed /
    /// terminated before authenticating).
    Cancelled,
    /// The requesting process exited while the dialog was open (Phase 2:
    /// kqueue `EVFILT_PROC`/`NOTE_EXIT` detection; not produced in Phase 1.4).
    PeerGone,
    /// The daemon's wait for a response expired
    /// (`cache-warden-cli::daemon::approver::exchange`'s
    /// `tokio::time::timeout`). Produced daemon-side, not by the helper.
    Timeout,
    /// `LAContext.evaluatePolicy` completed with a biometric failure (wrong
    /// finger, sensor error, etc. — not a user-initiated cancel).
    BiometricFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated `ApproveRequest` (every optional field `Some`, chain
    /// with 2 entries) round-trips through JSON without loss. This is the
    /// "guarded entry with a matched same-ancestor constraint" shape the
    /// dialog's detail panel needs (draft-DR-0031 §4/§5).
    #[test]
    fn approve_request_round_trips_with_all_optional_fields_populated() {
        let req = ApproveRequest {
            v: WIRE_VERSION,
            request_id: "req-1".to_string(),
            key: "ns/db-password".to_string(),
            operation: "get".to_string(),
            requester: Requester {
                chain: vec![
                    ProcessChainEntry {
                        pid: 12345,
                        ppid: 12000,
                        path: "/bin/zsh".to_string(),
                        start_time: 1_752_000_000_000_000_000,
                    },
                    ProcessChainEntry {
                        pid: 12000,
                        ppid: 1,
                        path: "/usr/bin/tmux".to_string(),
                        start_time: 1_752_000_000_000_000_000,
                    },
                ],
                audit_token: AuditToken {
                    euid: 501,
                    ruid: 501,
                    egid: 20,
                    pid: 12345,
                    pid_version: 7,
                },
                responsible_bundle_id: Some("com.mitchellh.ghostty".to_string()),
            },
            guard_eval: Some(GuardEval {
                constraints: vec![ConstraintEval {
                    kind: "same-ancestor".to_string(),
                    matched: true,
                    strength: "strong".to_string(),
                    display_label: "same-shell (zsh)".to_string(),
                    risk_note: None,
                }],
                setter_pinned: Some(ProcessSnapshot {
                    pid: 12345,
                    start_time: 1_752_000_000_000_000_000,
                    unique_id: Some(999),
                    path: "/bin/zsh".to_string(),
                    name: "zsh".to_string(),
                }),
                getter_matched: Some(ProcessSnapshot {
                    pid: 12345,
                    start_time: 1_752_000_000_000_000_000,
                    unique_id: Some(999),
                    path: "/bin/zsh".to_string(),
                    name: "zsh".to_string(),
                }),
                evaluated_at: 1_752_000_000_500_000_000,
            }),
            timeout_secs: 60,
        };
        let line = serde_json::to_string(&req).expect("serialize");
        assert!(!line.contains('\n'), "wire line must not embed a newline");
        let decoded: ApproveRequest = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(decoded, req);
    }

    /// The minimal shape — no guard, no responsible_bundle_id — omits those
    /// keys entirely rather than serializing `null` (`skip_serializing_if`),
    /// keeping the common (ungated entry) case's wire payload small.
    #[test]
    fn approve_request_omits_all_optional_fields_when_none() {
        let req = ApproveRequest {
            v: WIRE_VERSION,
            request_id: "req-2".to_string(),
            key: "ns/plain".to_string(),
            operation: "get".to_string(),
            requester: Requester {
                chain: vec![ProcessChainEntry {
                    pid: 1,
                    ppid: 0,
                    path: String::new(),
                    start_time: 0,
                }],
                audit_token: AuditToken {
                    euid: 501,
                    ruid: 501,
                    egid: 20,
                    pid: 1,
                    pid_version: 0,
                },
                responsible_bundle_id: None,
            },
            guard_eval: None,
            timeout_secs: 60,
        };
        let line = serde_json::to_string(&req).expect("serialize");
        assert!(!line.contains("guard_eval"));
        assert!(!line.contains("responsible_bundle_id"));
        assert!(!line.contains("risk_note"));
        let decoded: ApproveRequest = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(decoded, req);
    }

    /// `ApproveResponse` with `biometric_kind: None` (the Cancelled path)
    /// omits the key rather than emitting `null`.
    #[test]
    fn approve_response_omits_biometric_kind_when_none() {
        let resp = ApproveResponse {
            v: WIRE_VERSION,
            request_id: "req-3".to_string(),
            outcome: Outcome::Cancelled,
            biometric_kind: None,
        };
        let line = serde_json::to_string(&resp).expect("serialize");
        assert!(!line.contains("biometric_kind"));
        let decoded: ApproveResponse = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(decoded, resp);
    }

    /// `Outcome`'s snake_case wire form is a fixed part of the schema (a
    /// change here is a breaking wire change) — pin every variant's literal
    /// string rather than relying on `serde_json` round-trip alone (a
    /// round-trip test would not catch e.g. an accidental rename that still
    /// round-trips with itself).
    #[test]
    fn outcome_snake_case_strings_are_pinned() {
        let cases = [
            (Outcome::Approved, "\"approved\""),
            (Outcome::Denied, "\"denied\""),
            (Outcome::Cancelled, "\"cancelled\""),
            (Outcome::PeerGone, "\"peer_gone\""),
            (Outcome::Timeout, "\"timeout\""),
            (Outcome::BiometricFailed, "\"biometric_failed\""),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire string");
            let decoded: Outcome = serde_json::from_str(expected).expect("deserialize");
            assert_eq!(decoded, variant);
        }
    }
}
