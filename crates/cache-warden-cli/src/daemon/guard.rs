//! DR-0030 per-entry access guard evaluator.
//!
//! The core (`cache-warden`) stores a [`GuardRecord`] as plain data (DR-0004:
//! chain interpretation stays out of the core); this module is the CLI/daemon-
//! side judge that decides whether a getter's process context satisfies the
//! record.
//!
//! # Pure function surface
//!
//! [`evaluate`] takes fully-resolved inputs — the getter's ancestry chain,
//! its peer audit token, the guard record — and returns a
//! [`GuardEvalOutput`] or a [`GuardDenied`]. It does **not** call
//! `proc_pidinfo` / `getsockopt` itself: material acquisition is the
//! handler's job (which lets tests drive it with in-memory chains, and lets
//! the daemon capture the material atomically at get-request-receive time
//! for the DR-0030 §Security TOCTOU note).
//!
//! # Fail-closed
//!
//! Any of the following denies (`GuardDenied`), never falls through to "allow":
//! - Empty getter chain (no attribution material to compare).
//! - `same-user` constraint with any mismatch between setter and getter uids.
//! - `same-ancestor` constraint whose pinned entity is absent from the chain
//!   (including entities disambiguated by `unique_id` when both sides have it,
//!   or `start_time` when they do not).
//! - `command` constraint whose declared name is absent from the chain.
//! - A record whose constraint list is empty (an anomaly — the handler should
//!   drop the record with `clear_guard` when it decides "no constraints", so a
//!   record with `constraints.is_empty()` reaching here is a bug and denying
//!   is safe).
//!
//! # Wire alignment
//!
//! [`GuardEvalOutput`] and its inner [`ConstraintEval`] / [`SetterPin`] are
//! internal; the daemon's approver adapter maps them to
//! `cache_warden_approver::wire::{GuardEval, ConstraintEval, ProcessSnapshot}`
//! at dialog-request time (draft-DR-0031 §4). Keeping the daemon-internal
//! type separate lets the evaluator stay agnostic to that wire schema's
//! versioning.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cache_warden::{DeclaredAncestor, GuardConstraint, GuardRecord, PinnedProcess, ProcessInfo};

/// A getter-side process fact bundled with its optional macOS `unique_id`
/// (from `macos-process-inspect::unique_id`). The evaluator consumes this
/// rather than raw [`ProcessInfo`] so callers can attach the private-API
/// unique id where available; a getter chain with no unique_ids collapses
/// to start_time comparison (which is DR-0030 §Security's documented
/// fallback).
#[derive(Debug, Clone)]
pub struct GetterProcess {
    /// The plain kernel facts (pid / ppid / path / start_time).
    pub info: ProcessInfo,
    /// The macOS `PROC_PIDUNIQIDENTIFIERINFO::unique_id`, when the private
    /// API succeeded for this pid. `None` on non-macOS or on a
    /// per-pid failure.
    pub unique_id: Option<u64>,
}

/// The getter's peer credentials (from
/// `macos-process-inspect::peer_audit_token(fd)`), reduced to what the
/// evaluator needs. Kept independent of the crate's `AuditToken` so a test
/// can drive it without a real socketpair.
#[derive(Debug, Clone, Copy)]
pub struct GetterAuditToken {
    /// Effective user id of the connecting process.
    pub euid: u32,
    /// Real user id of the same process.
    pub ruid: u32,
}

/// Successful evaluation output — every constraint in the record matched.
/// The daemon threads this into `ApproveRequest.guard_eval` when the
/// approver dialog is shown (draft-DR-0031 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardEvalOutput {
    /// Per-constraint result, in the order they appeared on the record. All
    /// entries have `matched: true` by the "reach-this-branch" invariant —
    /// a single failure returns [`GuardDenied`] instead.
    pub constraints: Vec<ConstraintEval>,
    /// The setter identity carried by the record's *first*
    /// `same-ancestor`-family constraint, if any. `None` otherwise. Copied
    /// straight from the record for dialog display; the getter side is
    /// filled in by [`ConstraintEval::getter_matched`].
    pub setter_pinned: Option<SetterPin>,
    /// The getter process in the chain that matched `setter_pinned` (same
    /// entity by pid + start_time [+ unique_id]). `None` if `setter_pinned`
    /// is `None`.
    pub getter_matched: Option<SetterPin>,
}

/// One constraint's evaluation. Kind and strength are set from the record
/// (evaluation logic does not upgrade strength).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintEval {
    /// A short kind label (`"same-user"` / `"same-shell"` /
    /// `"same-ancestor"` / `"command"`).
    pub kind: &'static str,
    /// `"strong"` for `same-user` / `same-ancestor` (identity-pinned);
    /// `"weak"` for `command` (spoofable by dropping a same-basename
    /// binary). Documented on the wire schema and the CLI `--help`.
    pub strength: &'static str,
    /// Human-readable label for dialog display (e.g. `"same-shell (zsh)"`,
    /// `"same-ancestor (code)"`, `"command (git)"`).
    pub display_label: String,
    /// Warning text shown alongside a `weak` constraint. `None` for strong
    /// ones. Static string — the note is a property of the constraint kind,
    /// not of the specific match.
    pub risk_note: Option<&'static str>,
}

/// A pinned process identity in [`GuardEvalOutput`]. Mirrors `PinnedProcess`
/// but travels alongside the evaluation result rather than as core data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetterPin {
    /// Process ID at pin / match time.
    pub pid: u32,
    /// Process start time, if the OS exposed one. `None` collapses match
    /// to name-only comparison (which is not enough on its own — the
    /// evaluator only accepts it when the pinned side also lacks start_time
    /// and the sides carry no unique_id).
    pub start_time: Option<Duration>,
    /// macOS unique_id when the private API succeeded on both sides.
    pub unique_id: Option<u64>,
    /// Full executable path (empty [`PathBuf`] if the OS could not resolve
    /// it — carried through for display, not for identity).
    pub path: PathBuf,
    /// Display name (basename).
    pub name: String,
}

/// Constraint kinds that can appear in a [`GuardDenied`]'s reason. Only the
/// **kind** is exposed, per DR-0030 §4: the setter-side identity is *never*
/// returned to the getter — that would let a getter probe who set a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedKind {
    /// The record's constraint list was empty (record present but declares
    /// no constraint — a construction-side bug, not a getter-triggerable
    /// condition, but denied fail-closed rather than passed).
    EmptyRecord,
    /// The evaluator had nothing to compare against (empty getter chain or
    /// a missing audit token that a `same-user` constraint required).
    MissingContext,
    /// `same-user`: setter/getter uid mismatch.
    SameUser,
    /// `same-ancestor` / `same-shell`: pinned entity is not in the getter's
    /// ancestry chain (including "chain empty" or "pinned side has no
    /// disambiguation material and the fallback failed").
    SameAncestor,
    /// `command`: no chain process matched the declared name.
    Command,
}

/// A denial reason returned when [`evaluate`] fails closed. Carries only the
/// kind (DR-0030 §4: setter identity never leaks to the get side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardDenied {
    /// Which constraint kind failed. Multiple failures short-circuit at
    /// the first one — the daemon logs this as a structured field
    /// (`tracing::warn!(kind=?, …)`).
    pub kind: DeniedKind,
}

impl GuardDenied {
    /// Shorthand constructor.
    const fn of(kind: DeniedKind) -> Self {
        Self { kind }
    }
}

/// The risk note attached to a `command=` constraint on the dialog / logs
/// (issue受け入れ条件: "weak (spoofable)" を明示). Kept as a const so a
/// future rewording is a one-line change.
const COMMAND_RISK_NOTE: &str = "weak: matches by executable basename or full path; any process that can be spawned under \
     the same name in the requester's ancestry chain will pass";

/// Evaluate `record` against the getter context. Returns a
/// [`GuardEvalOutput`] on full pass, [`GuardDenied`] otherwise.
///
/// `getter_chain` is the ancestry chain as returned by
/// `macos-process-inspect::ancestry` (most-recent first, walking toward
/// `launchd`) at the moment the daemon received the `kv.get` request. That
/// timestamp is DR-0030 §Security's TOCTOU boundary: a mid-evaluation
/// parent exit collapses to "chain shorter than pinned entity", which
/// denies — the fail-closed direction.
///
/// `getter_audit_token` is the peer's audit token; it is optional so a
/// non-macOS / non-socket caller (test harness) can pass `None`. A `None`
/// token combined with a `SameUser` constraint denies.
pub fn evaluate(
    getter_chain: &[GetterProcess],
    getter_audit_token: Option<GetterAuditToken>,
    record: &GuardRecord,
) -> Result<GuardEvalOutput, GuardDenied> {
    if record.constraints.is_empty() {
        return Err(GuardDenied::of(DeniedKind::EmptyRecord));
    }
    if getter_chain.is_empty() {
        return Err(GuardDenied::of(DeniedKind::MissingContext));
    }

    let mut constraints = Vec::with_capacity(record.constraints.len());
    let mut setter_pinned: Option<SetterPin> = None;
    let mut getter_matched: Option<SetterPin> = None;

    for c in &record.constraints {
        match c {
            GuardConstraint::SameUser => {
                let token =
                    getter_audit_token.ok_or(GuardDenied::of(DeniedKind::MissingContext))?;
                if token.euid != record.setter.euid || token.ruid != record.setter.ruid {
                    return Err(GuardDenied::of(DeniedKind::SameUser));
                }
                constraints.push(ConstraintEval {
                    kind: "same-user",
                    strength: "strong",
                    display_label: "same-user".to_string(),
                    risk_note: None,
                });
            }
            GuardConstraint::SameAncestor { declared, pinned } => {
                let matched_getter = find_in_chain(getter_chain, pinned)
                    .ok_or(GuardDenied::of(DeniedKind::SameAncestor))?;
                let (kind_label, display) = match declared {
                    DeclaredAncestor::SameShell { shell_name } => {
                        ("same-shell", format!("same-shell ({shell_name})"))
                    }
                    DeclaredAncestor::Named { name } => {
                        ("same-ancestor", format!("same-ancestor ({name})"))
                    }
                };
                constraints.push(ConstraintEval {
                    kind: kind_label,
                    strength: "strong",
                    display_label: display,
                    risk_note: None,
                });
                // The first same-ancestor-family constraint's pin fills the
                // dialog's setter/getter identity slots. Subsequent ones
                // (unusual but legal) still evaluate but don't overwrite the
                // display anchor — one dialog can only show one identity
                // pair meaningfully.
                if setter_pinned.is_none() {
                    setter_pinned = Some(pinned_to_snapshot(pinned));
                    getter_matched = Some(getter_to_snapshot(matched_getter));
                }
            }
            GuardConstraint::Command { name } => {
                if !command_matches_chain(getter_chain, name) {
                    return Err(GuardDenied::of(DeniedKind::Command));
                }
                constraints.push(ConstraintEval {
                    kind: "command",
                    strength: "weak",
                    display_label: format!("command ({name})"),
                    risk_note: Some(COMMAND_RISK_NOTE),
                });
            }
        }
    }

    Ok(GuardEvalOutput {
        constraints,
        setter_pinned,
        getter_matched,
    })
}

/// Look up `pinned` in the getter's chain by "same process entity"
/// semantics (DR-0030 §Security):
/// - If both sides expose `unique_id`, that alone identifies the process
///   (finer than pid + start_time).
/// - Otherwise fall back to pid + start_time equality. When either side lacks
///   a start_time (a rare `proc_pidinfo` failure), the match is denied —
///   fail-closed, see `same_process_entity` for the pid-reuse attack this
///   closes.
fn find_in_chain<'a>(
    chain: &'a [GetterProcess],
    pinned: &PinnedProcess,
) -> Option<&'a GetterProcess> {
    chain.iter().find(|g| same_process_entity(g, pinned))
}

fn same_process_entity(getter: &GetterProcess, pinned: &PinnedProcess) -> bool {
    if let (Some(a), Some(b)) = (getter.unique_id, pinned.unique_id) {
        return a == b;
    }
    if getter.info.pid != pinned.pid {
        return false;
    }
    match (getter.info.start_time, pinned.start_time) {
        (Some(a), Some(b)) => a == b,
        // DR-0030 §Security: both disambiguation channels failed — no
        // start_time on either side and no unique_id on either side. Pid
        // alone is reused by the kernel, so accepting the match here would
        // allow this attack: setter's shell records pid=P with start_time
        // unavailable; the shell exits; the kernel later allocates the same
        // pid P to a fresh, unrelated zsh whose ancestry contains this pid
        // (e.g. any other user shell of the same basename). Basename equality
        // does not close that window — it is precisely the case an attacker
        // would trivially satisfy by running the same shell. Deny.
        _ => false,
    }
}

/// Whether any process in `chain` satisfies the declared `command` name.
/// `name` is matched literally against the full path if it starts with `/`,
/// against the basename otherwise (DR-0030 §1 "NAME or /PATH").
fn command_matches_chain(chain: &[GetterProcess], name: &str) -> bool {
    let looks_like_path = name.starts_with('/');
    chain.iter().any(|g| {
        if looks_like_path {
            g.info
                .path
                .as_ref()
                .map(|p| p == Path::new(name))
                .unwrap_or(false)
        } else {
            g.info.name().map(|b| b == name).unwrap_or(false)
        }
    })
}

fn pinned_to_snapshot(p: &PinnedProcess) -> SetterPin {
    SetterPin {
        pid: p.pid,
        start_time: p.start_time,
        unique_id: p.unique_id,
        path: p.path.clone(),
        name: p.name.clone(),
    }
}

fn getter_to_snapshot(g: &GetterProcess) -> SetterPin {
    SetterPin {
        pid: g.info.pid,
        start_time: g.info.start_time,
        unique_id: g.unique_id,
        path: g.info.path.clone().unwrap_or_default(),
        name: g.info.name().unwrap_or_default().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden::GuardSetter;
    use std::path::PathBuf;
    use std::time::Duration;

    // --- helpers ---

    fn gp(
        pid: u32,
        ppid: Option<u32>,
        path: &str,
        start_secs: u64,
        uniq: Option<u64>,
    ) -> GetterProcess {
        GetterProcess {
            info: ProcessInfo {
                pid,
                ppid,
                path: Some(PathBuf::from(path)),
                start_time: Some(Duration::from_secs(start_secs)),
            },
            unique_id: uniq,
        }
    }

    fn setter(euid: u32, ruid: u32) -> GuardSetter {
        GuardSetter { euid, ruid }
    }

    fn pinned(pid: u32, path: &str, start_secs: Option<u64>, uniq: Option<u64>) -> PinnedProcess {
        PinnedProcess {
            pid,
            start_time: start_secs.map(Duration::from_secs),
            unique_id: uniq,
            path: PathBuf::from(path),
            name: PathBuf::from(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }

    // --- same-user pass/fail ---

    /// same-user と setter identity 一致 → pass。同一 uid で set / get した
    /// 場合の典型パスであり、guard の最も緩い constraint が単独で成立する
    /// ことを固定する (DR-0030 §1 "same-user" 意味論)。
    #[test]
    fn same_user_pass_when_uids_match_setter() {
        let record = GuardRecord::new(vec![GuardConstraint::SameUser], setter(501, 501));
        let chain = vec![gp(100, Some(1), "/bin/zsh", 10, None)];
        let out = evaluate(
            &chain,
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            &record,
        )
        .unwrap();
        assert_eq!(out.constraints.len(), 1);
        assert_eq!(out.constraints[0].kind, "same-user");
        assert_eq!(out.constraints[0].strength, "strong");
        assert!(
            out.setter_pinned.is_none(),
            "same-user alone pins no process"
        );
    }

    /// same-user constraint で euid ずれ → deny。ruid だけ合致でも許さない
    /// (両方一致が仕様、DR-0030 §1)。
    #[test]
    fn same_user_deny_on_euid_mismatch() {
        let record = GuardRecord::new(vec![GuardConstraint::SameUser], setter(501, 501));
        let chain = vec![gp(100, Some(1), "/bin/zsh", 10, None)];
        let err = evaluate(
            &chain,
            Some(GetterAuditToken {
                euid: 502,
                ruid: 501,
            }),
            &record,
        )
        .unwrap_err();
        assert_eq!(err.kind, DeniedKind::SameUser);
    }

    /// same-user constraint + audit token 取得不能 → fail-closed。DR-0030
    /// §Security の TOCTOU 節と整合: 素材が無ければ拒否側に倒す。
    #[test]
    fn same_user_deny_when_audit_token_missing() {
        let record = GuardRecord::new(vec![GuardConstraint::SameUser], setter(501, 501));
        let chain = vec![gp(100, Some(1), "/bin/zsh", 10, None)];
        let err = evaluate(&chain, None, &record).unwrap_err();
        assert_eq!(err.kind, DeniedKind::MissingContext);
    }

    // --- same-ancestor pass/fail + pinning modes ---

    /// same-ancestor 実体 pin: pid + start_time が chain 中で一致する
    /// → pass、setter_pinned/getter_matched が dialog 用に埋まる。
    #[test]
    fn same_ancestor_pass_by_pid_and_start_time() {
        let pin = pinned(50, "/bin/zsh", Some(1_700_000_000), None);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell {
                    shell_name: "zsh".to_string(),
                },
                pinned: pin.clone(),
            }],
            setter(501, 501),
        );
        let chain = vec![
            gp(100, Some(50), "/usr/bin/git", 1_700_000_050, None),
            gp(50, Some(1), "/bin/zsh", 1_700_000_000, None),
        ];
        let out = evaluate(&chain, None, &record).unwrap();
        assert_eq!(out.constraints[0].kind, "same-shell");
        assert_eq!(out.constraints[0].display_label, "same-shell (zsh)");
        assert_eq!(out.setter_pinned.as_ref().unwrap().pid, 50);
        assert_eq!(out.getter_matched.as_ref().unwrap().pid, 50);
    }

    /// same-ancestor: pid は一致するが start_time が違う → 別 process 実体、
    /// deny。pid 再利用 (start_time で見分ける) を防ぐ DR-0030 §Security の
    /// 実体 pin 仕様。
    #[test]
    fn same_ancestor_deny_on_pid_reuse_start_time_mismatch() {
        let pin = pinned(50, "/bin/zsh", Some(1_700_000_000), None);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::Named { name: "zsh".into() },
                pinned: pin,
            }],
            setter(501, 501),
        );
        // Chain has pid 50 but with a *different* start_time (reuse).
        let chain = vec![gp(50, Some(1), "/bin/zsh", 1_700_999_999, None)];
        let err = evaluate(&chain, None, &record).unwrap_err();
        assert_eq!(err.kind, DeniedKind::SameAncestor);
    }

    /// unique_id 両側取得できた場合は start_time 縮退なしで unique_id で
    /// 一致判定できる (start_time が違っても unique_id が同じなら pass)。
    /// これは private API の性質: `unique_id` はより厳格な kernel counter。
    #[test]
    fn same_ancestor_unique_id_wins_over_start_time() {
        let pin = pinned(50, "/bin/zsh", Some(1_700_000_000), Some(999));
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell {
                    shell_name: "zsh".into(),
                },
                pinned: pin,
            }],
            setter(501, 501),
        );
        // start_time is wildly different, but unique_id matches -> same entity.
        let chain = vec![gp(50, Some(1), "/bin/zsh", 999_999_999, Some(999))];
        let out = evaluate(&chain, None, &record).unwrap();
        assert_eq!(out.constraints[0].strength, "strong");
    }

    /// unique_id 片側だけ取得できた場合は start_time 縮退で判定 (両方揃わ
    /// ないと unique_id は使わない、DR-0030 §Security)。
    #[test]
    fn same_ancestor_unique_id_only_used_when_both_sides_have_it() {
        let pin = pinned(50, "/bin/zsh", Some(1_700_000_000), Some(999));
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell {
                    shell_name: "zsh".into(),
                },
                pinned: pin,
            }],
            setter(501, 501),
        );
        // Getter side missing unique_id — must fall back to start_time (which
        // still matches here), so this passes.
        let chain = vec![gp(50, Some(1), "/bin/zsh", 1_700_000_000, None)];
        let out = evaluate(&chain, None, &record).unwrap();
        assert_eq!(out.constraints.len(), 1);
    }

    /// chain 中に pinned pid が居ない → deny (chain 短縮による deny の代表)。
    #[test]
    fn same_ancestor_deny_when_pinned_pid_absent_from_chain() {
        let pin = pinned(99, "/bin/zsh", Some(10), None);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::Named { name: "zsh".into() },
                pinned: pin,
            }],
            setter(501, 501),
        );
        let chain = vec![gp(100, Some(1), "/bin/zsh", 10, None)];
        let err = evaluate(&chain, None, &record).unwrap_err();
        assert_eq!(err.kind, DeniedKind::SameAncestor);
    }

    // --- command basename / full-path ---

    /// command=NAME (basename): chain 中の basename が一致 → pass。weak
    /// ラベル + risk_note が付くことも同時に固定 (issue 受け入れ条件)。
    #[test]
    fn command_matches_by_basename_with_weak_label() {
        let record = GuardRecord::new(
            vec![GuardConstraint::Command { name: "git".into() }],
            setter(501, 501),
        );
        let chain = vec![
            gp(100, Some(50), "/opt/homebrew/bin/git", 1, None),
            gp(50, Some(1), "/bin/zsh", 1, None),
        ];
        let out = evaluate(&chain, None, &record).unwrap();
        assert_eq!(out.constraints[0].kind, "command");
        assert_eq!(out.constraints[0].strength, "weak");
        assert!(out.constraints[0].risk_note.is_some());
    }

    /// command=/full/path: `/` で始まる場合 basename ではなく full path
    /// 完全一致 (DR-0030 §1 "NAME or /PATH")。
    #[test]
    fn command_full_path_requires_exact_match() {
        let record = GuardRecord::new(
            vec![GuardConstraint::Command {
                name: "/opt/homebrew/bin/git".into(),
            }],
            setter(501, 501),
        );
        // Chain has git at a different path — full-path constraint denies.
        let chain = vec![gp(100, Some(50), "/usr/bin/git", 1, None)];
        assert_eq!(
            evaluate(&chain, None, &record).unwrap_err().kind,
            DeniedKind::Command
        );
        // But chain-with-matching-path passes.
        let chain = vec![gp(100, Some(50), "/opt/homebrew/bin/git", 1, None)];
        assert!(evaluate(&chain, None, &record).is_ok());
    }

    // --- AND composition / short-circuit ---

    /// 全 constraint 成立 → pass、AND 合成が意味論通り (DR-0030 §1)。
    #[test]
    fn and_composition_all_pass() {
        let pin = pinned(50, "/bin/zsh", Some(1), None);
        let record = GuardRecord::new(
            vec![
                GuardConstraint::SameUser,
                GuardConstraint::SameAncestor {
                    declared: DeclaredAncestor::SameShell {
                        shell_name: "zsh".into(),
                    },
                    pinned: pin,
                },
                GuardConstraint::Command { name: "git".into() },
            ],
            setter(501, 501),
        );
        let chain = vec![
            gp(100, Some(50), "/usr/bin/git", 2, None),
            gp(50, Some(1), "/bin/zsh", 1, None),
        ];
        let out = evaluate(
            &chain,
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            &record,
        )
        .unwrap();
        assert_eq!(out.constraints.len(), 3);
    }

    /// 1 個でも fail → 全体 fail、後続 constraint は評価しない (short-circuit)。
    /// deny.kind は最初に落ちた kind を返すことも固定。
    #[test]
    fn and_composition_first_failure_short_circuits() {
        let pin = pinned(999, "/bin/zsh", Some(1), None); // Not in chain.
        let record = GuardRecord::new(
            vec![
                GuardConstraint::SameAncestor {
                    declared: DeclaredAncestor::Named { name: "zsh".into() },
                    pinned: pin,
                },
                GuardConstraint::SameUser, // would also fail (uid mismatch below)
            ],
            setter(501, 501),
        );
        let chain = vec![gp(100, Some(1), "/bin/zsh", 1, None)];
        let err = evaluate(
            &chain,
            Some(GetterAuditToken {
                euid: 999,
                ruid: 999,
            }),
            &record,
        )
        .unwrap_err();
        // Short-circuit: same-ancestor failed first, so that is the reported kind.
        assert_eq!(err.kind, DeniedKind::SameAncestor);
    }

    // --- fail-closed edge cases ---

    /// record.constraints が空 = 「制約なし record」= 構築ミス → EmptyRecord
    /// で deny (fail-closed)。handler が clear_guard を呼ぶべき場面で record
    /// が残ってしまった時の安全側挙動を固定。
    #[test]
    fn empty_constraint_list_denies_as_empty_record() {
        let record = GuardRecord::new(vec![], setter(501, 501));
        let chain = vec![gp(100, Some(1), "/bin/zsh", 1, None)];
        let err = evaluate(
            &chain,
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            &record,
        )
        .unwrap_err();
        assert_eq!(err.kind, DeniedKind::EmptyRecord);
    }

    /// 両側 start_time 無し + 両側 unique_id 無し → DR-0030 §Security 規定の
    /// fail-closed。同じ basename の別プロセスが後から同 pid を割り当てられた
    /// 場合 (setter shell exit → pid 再利用 → 同名別 zsh) の攻撃窓を basename
    /// 一致で埋めるのは不十分なので deny 側に倒す。旧実装は basename が一致
    /// すれば allow していたが、それは同名シェルを起動できるだけで通る誤配線。
    #[test]
    fn same_ancestor_deny_when_both_sides_lack_start_time_and_unique_id() {
        let pin = pinned(50, "/bin/zsh", None, None);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell {
                    shell_name: "zsh".into(),
                },
                pinned: pin,
            }],
            setter(501, 501),
        );
        // Chain has a same-pid + same-basename entry but no start_time — the
        // exact "impostor after pid reuse" shape.
        let chain = vec![GetterProcess {
            info: ProcessInfo {
                pid: 50,
                ppid: Some(1),
                path: Some(PathBuf::from("/bin/zsh")),
                start_time: None,
            },
            unique_id: None,
        }];
        let err = evaluate(&chain, None, &record).unwrap_err();
        assert_eq!(err.kind, DeniedKind::SameAncestor);
    }

    /// One side has start_time, the other doesn't → deny (already covered
    /// by the `_ => false` arm, but pinned here explicitly so a future refactor
    /// that "helpfully" falls back to name-only cannot silently reopen the
    /// attack window).
    #[test]
    fn same_ancestor_deny_on_asymmetric_start_time_availability() {
        let pin = pinned(50, "/bin/zsh", Some(1_700_000_000), None);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::Named { name: "zsh".into() },
                pinned: pin,
            }],
            setter(501, 501),
        );
        // Getter lacks start_time even though the pin has one.
        let chain = vec![GetterProcess {
            info: ProcessInfo {
                pid: 50,
                ppid: Some(1),
                path: Some(PathBuf::from("/bin/zsh")),
                start_time: None,
            },
            unique_id: None,
        }];
        let err = evaluate(&chain, None, &record).unwrap_err();
        assert_eq!(err.kind, DeniedKind::SameAncestor);
    }

    /// getter chain が空 → MissingContext。requester 属性が取れない状況を
    /// pass 側に倒さない (DR-0030 §4 fail-closed)。
    #[test]
    fn empty_chain_denies_missing_context() {
        let record = GuardRecord::new(vec![GuardConstraint::SameUser], setter(501, 501));
        let err = evaluate(
            &[],
            Some(GetterAuditToken {
                euid: 501,
                ruid: 501,
            }),
            &record,
        )
        .unwrap_err();
        assert_eq!(err.kind, DeniedKind::MissingContext);
    }
}
