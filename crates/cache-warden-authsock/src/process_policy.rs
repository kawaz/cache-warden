//! Socket-level process access policy (port plan Iteration 5).
//!
//! A `[authsock.sockets.*]` may carry an `allowed_processes` list. When set, the
//! daemon resolves the connecting peer's process ancestry (the chain produced by
//! [`cache_warden::ProcessInspector::ancestry`]: index 0 is the immediate
//! requester, then each successive parent toward `init`/`launchd`) and admits the
//! connection only when **some** process in that chain is named in the list. This
//! is the policy *interpretation* half of process authentication — the generic
//! "what is process N / what is its ancestry" half lives in the core
//! ([`cache_warden::ProcessInfo`] / [`cache_warden::ProcessInspector`]); per
//! DR-0004 the matching against an allow-list belongs to this adapter layer.
//!
//! # Semantics (ported from authsock-warden `ProcessChain::matches_any`)
//!
//! - **Empty allow-list = no restriction**: every process is admitted, and the
//!   ancestry is never even resolved. This is a load-bearing invariant — a config
//!   that leaves `allowed_processes` empty (the common case) must behave exactly
//!   as it did before this iteration.
//! - **Match = OR over the whole chain, exact executable basename**: the chain is
//!   admitted when any one of its processes has a [`cache_warden::ProcessInfo::name`]
//!   (the executable path's basename) equal to an entry in the list. Matching is a
//!   plain string equality — no globs, no regexes (authsock-warden parity).
//! - **A process whose name is `None` (unresolved path) is skipped**: it can never
//!   match, so it neither admits nor blocks on its own. authsock-warden fabricated
//!   a `pid:<N>` placeholder name for such processes; an exact-equality match
//!   against a `name` list treats that placeholder and a skipped `None` identically
//!   (a `pid:<N>` token is never a real executable basename), so the two are
//!   equivalent.

use cache_warden::ProcessInfo;

/// Whether a process `chain` is allowed by the socket's `allowed` list.
///
/// Returns `true` when `allowed` is empty (no restriction). Otherwise returns
/// `true` iff some [`ProcessInfo`] in `chain` has a resolved
/// [`ProcessInfo::name`] that exactly equals an entry in `allowed`. Processes
/// with an unresolved name (`name() == None`) are skipped. See the module docs
/// for the full semantics and the authsock-warden lineage.
pub fn chain_allowed(chain: &[ProcessInfo], allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    chain.iter().any(|info| match info.name() {
        Some(name) => allowed.iter().any(|a| a == name),
        None => false,
    })
}

/// Whether a request whose requester ancestry is `requester` passes the `allowed`
/// gate, **failing closed** when the requester is unidentifiable.
///
/// This is the chain-oriented gate used by both control-socket and authsock
/// layers once the requester's ancestry has already been resolved (the
/// pid-oriented socket-connect gate that resolves ancestry itself is layered on
/// top of this). Semantics:
///
/// - `allowed` empty → admitted unconditionally (no restriction; the requester is
///   not even consulted, so an unattributable caller is still admitted — the
///   "no policy" behaviour is preserved exactly).
/// - `allowed` non-empty + `requester == None` → **denied** (fail-closed): a
///   restriction is set but we cannot identify who is asking, so we refuse
///   (DR-0012). This is the load-bearing difference from authsock-warden, which
///   failed *open* here.
/// - `allowed` non-empty + `requester == Some(chain)` → [`chain_allowed`].
///
/// The "empty == unrestricted" branch is only reachable for the *omitted/empty*
/// config case; a key with a real restriction always carries a non-empty list, so
/// the gate never collapses to "allow all" mid-evaluation (the warden footgun
/// where an empty intersection turned into `matches_any(&[]) == true`).
pub fn chain_gate_passes(requester: Option<&[ProcessInfo]>, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    match requester {
        Some(chain) => chain_allowed(chain, allowed),
        None => false, // fail-closed: a restricted key with an unknown requester.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    /// A `ProcessInfo` with a resolved executable path (so `name()` is `Some`).
    fn named(pid: u32, ppid: Option<u32>, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            path: Some(PathBuf::from(format!("/usr/bin/{name}"))),
            start_time: Some(Duration::from_secs(pid as u64)),
        }
    }

    /// A `ProcessInfo` with no path, so `name()` is `None` (skipped in matching).
    fn unnamed(pid: u32, ppid: Option<u32>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            path: None,
            start_time: None,
        }
    }

    fn allow(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_allow_list_admits_everything() {
        // Even an empty chain is admitted: no restriction means no resolution.
        assert!(chain_allowed(&[], &[]));
        let chain = vec![named(100, Some(1), "evil")];
        assert!(chain_allowed(&chain, &[]));
    }

    #[test]
    fn immediate_requester_match_admits() {
        // The connecting process itself (index 0) is named in the list.
        let chain = vec![named(100, Some(50), "ssh"), named(50, Some(1), "zsh")];
        assert!(chain_allowed(&chain, &allow(&["ssh"])));
    }

    #[test]
    fn ancestor_match_admits() {
        // ssh -> git -> zsh; the list names an *ancestor* (git), not the leaf.
        let chain = vec![
            named(100, Some(50), "ssh"),
            named(50, Some(10), "git"),
            named(10, Some(1), "zsh"),
        ];
        assert!(chain_allowed(&chain, &allow(&["git"])));
        // A more distant ancestor (zsh) also admits.
        assert!(chain_allowed(&chain, &allow(&["zsh"])));
    }

    #[test]
    fn no_process_in_chain_matches_is_denied() {
        let chain = vec![named(100, Some(50), "ssh"), named(50, Some(1), "zsh")];
        // None of the chain's names appear in the list.
        assert!(!chain_allowed(&chain, &allow(&["jj", "git"])));
    }

    #[test]
    fn unnamed_process_is_skipped_not_a_match() {
        // A name-less process never matches, even against any list.
        let chain = vec![unnamed(100, Some(1))];
        assert!(!chain_allowed(&chain, &allow(&["ssh"])));
    }

    #[test]
    fn unnamed_process_does_not_block_a_named_ancestor() {
        // The leaf has no resolvable name, but a named ancestor (git) is allowed:
        // the unnamed leaf is skipped, the ancestor admits.
        let chain = vec![unnamed(100, Some(50)), named(50, Some(1), "git")];
        assert!(chain_allowed(&chain, &allow(&["git"])));
    }

    #[test]
    fn matches_against_a_multi_entry_list() {
        let chain = vec![named(100, Some(1), "jj")];
        // Any one of several allowed names admits.
        assert!(chain_allowed(&chain, &allow(&["ssh", "git", "jj"])));
        assert!(!chain_allowed(&chain, &allow(&["ssh", "git"])));
    }

    #[test]
    fn match_is_exact_basename_no_substring_no_glob() {
        let chain = vec![named(100, Some(1), "ssh-agent")];
        // "ssh" must not match "ssh-agent" (no substring / prefix matching).
        assert!(!chain_allowed(&chain, &allow(&["ssh"])));
        // The exact basename does match.
        assert!(chain_allowed(&chain, &allow(&["ssh-agent"])));
    }

    #[test]
    fn empty_chain_with_nonempty_list_is_denied() {
        // A restriction is set but the chain is empty (e.g. ancestry came back
        // empty): nothing can match, so it is denied (fail-closed at the caller).
        assert!(!chain_allowed(&[], &allow(&["ssh"])));
    }

    // ---- chain_gate_passes (DR-0012 key layer + socket layer share) ----

    #[test]
    fn gate_empty_list_admits_even_unknown_requester() {
        // No restriction: an unattributable requester (None) is still admitted.
        assert!(chain_gate_passes(None, &[]));
        let chain = vec![named(100, Some(1), "evil")];
        assert!(chain_gate_passes(Some(&chain), &[]));
    }

    #[test]
    fn gate_nonempty_list_with_unknown_requester_is_fail_closed() {
        // A restriction is set but the requester is unidentifiable: deny.
        assert!(!chain_gate_passes(None, &allow(&["ssh"])));
    }

    #[test]
    fn gate_nonempty_list_admits_when_ancestor_matches() {
        let chain = vec![named(100, Some(50), "ssh"), named(50, Some(1), "zsh")];
        assert!(chain_gate_passes(Some(&chain), &allow(&["ssh"])));
        assert!(chain_gate_passes(Some(&chain), &allow(&["zsh"])));
    }

    #[test]
    fn gate_nonempty_list_denies_when_no_ancestor_matches() {
        let chain = vec![named(100, Some(50), "ssh"), named(50, Some(1), "zsh")];
        assert!(!chain_gate_passes(Some(&chain), &allow(&["git", "jj"])));
    }

    #[test]
    fn gate_nonempty_list_with_empty_chain_is_denied() {
        // Requester resolved to an empty chain (degenerate): a real restriction
        // can never match, so it is denied — never collapses to allow-all.
        assert!(!chain_gate_passes(Some(&[]), &allow(&["ssh"])));
    }
}
