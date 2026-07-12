//! Daemon-side adapter that maps the DR-0030 guard evaluator's output onto
//! the DR-0031 approver-wire schema (`cache_warden_approver::wire`).
//!
//! # Why an adapter
//!
//! The daemon-internal `guard::GuardEvalOutput` (etc.) is versioned with the
//! evaluator; the wire schema is versioned with the helper. Keeping the
//! translation in one place — this module — lets the two evolve
//! independently. The three specific reconciliations DR-0031 §4's own
//! addendum flagged all live here:
//!
//! 1. `start_time` types: the evaluator carries `Option<Duration>` (a
//!    core [`ProcessInfo`] type); the wire uses `u64` epoch nanoseconds.
//!    `None` collapses to `0`, matching the existing "`ppid: 0` = unknown"
//!    convention on [`ProcessChainEntry`] (see wire.rs docs).
//! 2. `ConstraintEval::strength` is a plain `&'static str` (`"strong"` /
//!    `"weak"`) — DR-0030 §1's two-value axis. The wire carries a
//!    `String` for that, so we just copy verbatim. The DR-0031 §4 addendum
//!    flags a future "same-user re-declaration" nuance as Block 3b work; we
//!    do not attempt it here.
//! 3. `setter_pinned` is singular on both sides — the first same-ancestor-
//!    family constraint wins, which the evaluator already enforces
//!    ([`GuardEvalOutput::setter_pinned`]'s doc).
//!
//! # `Approver` trait
//!
//! Test isolation. The production side is [`ApproverClient`] (a real Unix-
//! socket connection to a spawned helper); tests need to inject an outcome
//! without launching a real process. Rather than teach every gated path to
//! know about [`Connector::Test`] or accept an `Option<Arc<ApproverClient>>`
//! that a test would have to fake with a real helper, the [`Approver`] trait
//! lets a same-crate fake ([`FakeApprover`]) implement the exact call the
//! server layer awaits: one method, `request`, returning a boxed future.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cache_warden_approver::wire::{
    ApproveRequest, ApproveResponse, AuditToken as WireAuditToken,
    ConstraintEval as WireConstraintEval, GuardEval as WireGuardEval, ProcessChainEntry,
    ProcessSnapshot as WireProcessSnapshot, Requester, WIRE_VERSION,
};

use super::approver::ApproverClient;
use super::guard::{ConstraintEval, GetterProcess, GuardEvalOutput, SetterPin};

/// The dialog side of the approver IPC, abstracted so a test can inject a
/// deterministic outcome without spawning a real GUI helper.
///
/// Production impl: [`ApproverClient`] (see [`super::approver`]).
/// Test impl: [`FakeApprover`].
pub trait Approver: Send + Sync {
    /// Send `request` and await the matching response, bounded by `timeout`.
    fn request<'a>(
        &'a self,
        request: ApproveRequest,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<ApproveResponse>> + Send + 'a>>;
    /// DR-0031 §10 graceful-restart integration: kill the helper before the
    /// daemon execs itself so an orphan does not linger with a socket the
    /// new daemon will bind over. Idempotent — a second call is a no-op.
    fn shutdown<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

impl Approver for ApproverClient {
    fn request<'a>(
        &'a self,
        request: ApproveRequest,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<ApproveResponse>> + Send + 'a>> {
        Box::pin(async move { ApproverClient::request(self, &request, timeout).await })
    }
    fn shutdown<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { ApproverClient::shutdown(self).await })
    }
}

/// Duration → epoch nanoseconds `u64`. Saturates at [`u64::MAX`] (a genuine
/// 2554-AD timestamp, more headroom than the platform's own clock resolution
/// ever produces at the time this ships).
pub fn duration_to_epoch_ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// `Option<Duration>` → `u64`, with `None` collapsing to `0` (the wire's
/// documented "unknown" sentinel — same shape as [`ProcessChainEntry::ppid`]
/// `= 0`).
pub fn maybe_duration_to_ns(d: Option<Duration>) -> u64 {
    d.map(duration_to_epoch_ns).unwrap_or(0)
}

/// Convert the daemon-observed requester chain into its wire form. Unknown
/// `ppid` / `start_time` / `path` collapse to the wire's neutral values
/// (`0` / `0` / `""`) — [`ProcessChainEntry`]'s doc calls this out.
pub fn to_wire_chain(chain: &[GetterProcess]) -> Vec<ProcessChainEntry> {
    chain
        .iter()
        .map(|g| ProcessChainEntry {
            pid: g.info.pid,
            ppid: g.info.ppid.unwrap_or(0),
            path: g
                .info
                .path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            start_time: maybe_duration_to_ns(g.info.start_time),
        })
        .collect()
}

/// Convert the peer audit token into its wire form. Non-macOS builds get an
/// `AuditToken` only via the stub `peer_audit_token` (which always returns
/// `None`), so this function is unreachable there in practice but stays
/// compiled to keep the wire adapter's surface uniform across platforms.
///
/// The kernel's `pid_version` is signed (`i32`) — the token exposes it as
/// such; the wire uses `u32` for symmetry with the other `u32` id fields.
/// The bit pattern is preserved via `as u32` (the version counter is only
/// ever consumed for equality checks, not arithmetic).
pub fn to_wire_audit_token(t: &macos_process_inspect::AuditToken) -> WireAuditToken {
    WireAuditToken {
        euid: t.euid(),
        ruid: t.ruid(),
        egid: t.egid(),
        pid: t.pid().unwrap_or(0),
        pid_version: t.pid_version() as u32,
    }
}

/// Convert `GuardEvalOutput` (the daemon-internal evaluator success shape)
/// into its wire form.
///
/// `evaluated_at` is stamped *at wire-build time* with `SystemTime::now()`.
/// This is deliberate: the evaluator's own evaluation instant is not carried
/// on `GuardEvalOutput` (it is a pure function; time is a wire-adapter
/// concern), and the dialog needs a timestamp for display in the detail
/// panel. A `SystemTime` failure (clock before UNIX epoch — vanishingly
/// rare) collapses to `0`.
pub fn to_wire_guard_eval(output: &GuardEvalOutput) -> WireGuardEval {
    WireGuardEval {
        constraints: output.constraints.iter().map(to_wire_constraint).collect(),
        setter_pinned: output.setter_pinned.as_ref().map(to_wire_snapshot),
        getter_matched: output.getter_matched.as_ref().map(to_wire_snapshot),
        evaluated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(duration_to_epoch_ns)
            .unwrap_or(0),
    }
}

fn to_wire_constraint(c: &ConstraintEval) -> WireConstraintEval {
    WireConstraintEval {
        kind: c.kind.to_string(),
        // Every constraint that reaches this adapter matched (a denial
        // short-circuits before the dialog ever fires — DR-0031 §Security).
        matched: true,
        strength: c.strength.to_string(),
        display_label: c.display_label.clone(),
        risk_note: c.risk_note.map(str::to_string),
    }
}

fn to_wire_snapshot(p: &SetterPin) -> WireProcessSnapshot {
    WireProcessSnapshot {
        pid: p.pid,
        start_time: maybe_duration_to_ns(p.start_time),
        unique_id: p.unique_id,
        path: p.path.to_string_lossy().into_owned(),
        name: p.name.clone(),
    }
}

/// Build the fully-populated [`ApproveRequest`] the dialog needs.
///
/// `full_audit_token` is optional so a non-macOS build / a getsockopt failure
/// collapses to an all-zero wire audit token (still delivered — the helper
/// then falls back to the requester chain for display). `responsible_bundle_id`
/// is `None` in Phase 3a: DR-0031 §4 documents the fallback (helper walks the
/// chain for a `.app` ancestor), and threading TCC through here is Block 3b.
#[allow(clippy::too_many_arguments)]
pub fn build_approve_request(
    request_id: String,
    key: String,
    operation: &str,
    chain: &[GetterProcess],
    full_audit_token: Option<&macos_process_inspect::AuditToken>,
    responsible_bundle_id: Option<String>,
    guard_eval: &GuardEvalOutput,
    timeout_secs: u32,
) -> ApproveRequest {
    let audit_token = full_audit_token
        .map(to_wire_audit_token)
        .unwrap_or(EMPTY_AUDIT_TOKEN);
    ApproveRequest {
        v: WIRE_VERSION,
        request_id,
        key,
        operation: operation.to_string(),
        requester: Requester {
            chain: to_wire_chain(chain),
            audit_token,
            responsible_bundle_id,
        },
        guard_eval: Some(to_wire_guard_eval(guard_eval)),
        timeout_secs,
    }
}

/// The all-zero fill for an audit token we could not resolve. Kept as a
/// named constant so the "no token available" wire shape is greppable from
/// both the adapter and any future consumer that wants to detect it (e.g. a
/// helper UI that greys out the `same-user` chip when no uids are known).
const EMPTY_AUDIT_TOKEN: WireAuditToken = WireAuditToken {
    euid: 0,
    ruid: 0,
    egid: 0,
    pid: 0,
    pid_version: 0,
};

/// A deterministic `Approver` for tests: returns the configured `outcome` on
/// every call, echoing `request_id` back. `biometric_kind` follows the same
/// rule as `ApproverClient`'s real replies (Some on `Approved`, None
/// otherwise) so a test that grep's the wire pins the same shape as production.
#[cfg(test)]
#[allow(dead_code)]
pub struct FakeApprover {
    pub outcome: cache_warden_approver::wire::Outcome,
    /// Number of times `request` has been called (`AtomicUsize` so a test
    /// can `assert_eq!(fake.calls(), 1)` without needing `&mut`).
    pub call_count: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[allow(dead_code)]
impl FakeApprover {
    pub fn new(outcome: cache_warden_approver::wire::Outcome) -> Self {
        Self {
            outcome,
            call_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    pub fn calls(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
impl Approver for FakeApprover {
    fn request<'a>(
        &'a self,
        request: ApproveRequest,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<ApproveResponse>> + Send + 'a>> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let outcome = self.outcome;
        Box::pin(async move {
            Ok(ApproveResponse {
                v: WIRE_VERSION,
                request_id: request.request_id,
                outcome,
                biometric_kind: match outcome {
                    cache_warden_approver::wire::Outcome::Approved => Some("TouchID".to_string()),
                    _ => None,
                },
            })
        })
    }
    fn shutdown<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden::{DeclaredAncestor, ProcessInfo};
    use std::path::PathBuf;

    /// Sub-microsecond Duration values must round-trip through
    /// `duration_to_epoch_ns` (`as_nanos` gives a `u128` — the `try_from`
    /// narrowing is where a naive `as u64` would silently truncate on a
    /// future far-future value; the sub-μs path exercises the low end).
    #[test]
    fn duration_conversion_preserves_sub_microsecond_precision() {
        assert_eq!(duration_to_epoch_ns(Duration::from_nanos(1)), 1);
        assert_eq!(duration_to_epoch_ns(Duration::from_nanos(999)), 999);
        assert_eq!(
            duration_to_epoch_ns(Duration::from_nanos(1_234_567_890)),
            1_234_567_890
        );
    }

    /// `None` (unknown start_time / unknown ppid material) becomes `0` — the
    /// wire's documented sentinel. Explicit test so a future "helpfully"
    /// changing the fallback to e.g. `u64::MAX` is caught.
    #[test]
    fn unknown_start_time_collapses_to_zero_sentinel() {
        assert_eq!(maybe_duration_to_ns(None), 0);
    }

    /// A chain entry with every field unknown wires as pid + all-zeros/empty,
    /// not as an error — the helper is display-only and must be robust to
    /// partial resolution (`macos-process-inspect` can succeed on pid but
    /// fail per-field). Pins the collapse rules on one shape.
    #[test]
    fn to_wire_chain_collapses_all_unknowns_to_wire_neutrals() {
        let chain = vec![GetterProcess {
            info: ProcessInfo {
                pid: 42,
                ppid: None,
                path: None,
                start_time: None,
            },
            unique_id: None,
        }];
        let wire = to_wire_chain(&chain);
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].pid, 42);
        assert_eq!(wire[0].ppid, 0);
        assert_eq!(wire[0].path, "");
        assert_eq!(wire[0].start_time, 0);
    }

    /// A fully-resolved `GuardEvalOutput` round-trips into a wire
    /// `GuardEval` with every constraint's kind/strength/label preserved
    /// and the setter/getter snapshots populated. The `evaluated_at`
    /// stamp is only asserted to be non-zero (it is `SystemTime::now()`).
    #[test]
    fn to_wire_guard_eval_populates_all_fields() {
        let pin = SetterPin {
            pid: 55,
            start_time: Some(Duration::from_secs(1_700_000_000)),
            unique_id: Some(999),
            path: PathBuf::from("/bin/zsh"),
            name: "zsh".to_string(),
        };
        let output = GuardEvalOutput {
            constraints: vec![
                ConstraintEval {
                    kind: "same-user",
                    strength: "strong",
                    display_label: "same-user".to_string(),
                    risk_note: None,
                },
                ConstraintEval {
                    kind: "command",
                    strength: "weak",
                    display_label: "command (git)".to_string(),
                    risk_note: Some("weak"),
                },
            ],
            setter_pinned: Some(pin.clone()),
            getter_matched: Some(pin),
        };
        let wire = to_wire_guard_eval(&output);
        assert_eq!(wire.constraints.len(), 2);
        assert_eq!(wire.constraints[0].kind, "same-user");
        assert_eq!(wire.constraints[0].strength, "strong");
        assert!(wire.constraints[0].matched);
        assert_eq!(wire.constraints[1].kind, "command");
        assert_eq!(wire.constraints[1].strength, "weak");
        assert_eq!(wire.constraints[1].risk_note.as_deref(), Some("weak"));
        let sp = wire.setter_pinned.as_ref().expect("setter_pinned set");
        assert_eq!(sp.pid, 55);
        assert_eq!(sp.unique_id, Some(999));
        assert_eq!(sp.path, "/bin/zsh");
        assert!(wire.evaluated_at > 0, "evaluated_at stamped");
        // Silence unused import warning on non-macOS where `DeclaredAncestor`
        // is not otherwise referenced by this test.
        let _ = DeclaredAncestor::Named { name: "".into() };
    }
}
