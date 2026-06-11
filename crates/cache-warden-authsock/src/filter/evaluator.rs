//! Filter evaluation engine (OR of AND).
//!
//! Ported from authsock-warden `src/filter/evaluator.rs`. A [`FilterGroup`] is a
//! set of rules ANDed together; a [`FilterEvaluator`] is a set of groups ORed
//! together. An empty evaluator (no groups) matches everything — an unfiltered
//! socket sees all keys.
//!
//! The upstream `ensure_loaded` / `reload` methods were `async` only because of
//! the `github` filter's network fetch; with `github` deferred, the only
//! reloadable filter left (`keyfile`) is synchronous, so [`FilterEvaluator::reload`]
//! is synchronous here.

use crate::error::Result;
use crate::filter::{Filter, FilterRule, GithubMatcher};
use crate::message::Identity;

/// A group of rules that are ANDed together.
#[derive(Debug, Clone, Default)]
pub struct FilterGroup {
    rules: Vec<FilterRule>,
}

impl FilterGroup {
    /// Parse one AND group from a list of rule tokens.
    pub fn parse(filter_strs: &[String]) -> Result<Self> {
        let rules = filter_strs
            .iter()
            .map(|s| FilterRule::parse(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }

    /// Whether `identity` passes every rule in the group (an empty group passes).
    pub fn matches(&self, identity: &Identity) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        self.rules.iter().all(|r| r.matches(identity))
    }

    /// The rules in this group.
    pub fn rules(&self) -> &[FilterRule] {
        &self.rules
    }
}

/// Evaluator for filter groups (ORed together).
#[derive(Debug, Clone, Default)]
pub struct FilterEvaluator {
    groups: Vec<FilterGroup>,
}

impl FilterEvaluator {
    /// Build an evaluator from already-parsed groups.
    pub fn new(groups: Vec<FilterGroup>) -> Self {
        Self { groups }
    }

    /// Parse an OR-of-AND evaluator from groups of rule tokens.
    pub fn parse(filter_groups: &[Vec<String>]) -> Result<Self> {
        let groups = filter_groups
            .iter()
            .map(|g| FilterGroup::parse(g))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { groups })
    }

    /// Whether `identity` passes any group (an empty evaluator passes all).
    pub fn matches(&self, identity: &Identity) -> bool {
        if self.groups.is_empty() {
            return true;
        }
        self.groups.iter().any(|g| g.matches(identity))
    }

    /// Retain only the identities that pass this evaluator (order preserved).
    pub fn filter_identities(&self, identities: Vec<Identity>) -> Vec<Identity> {
        identities.into_iter().filter(|i| self.matches(i)).collect()
    }

    /// Number of OR groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the evaluator has no groups (matches everything).
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// The OR groups.
    pub fn groups(&self) -> &[FilterGroup] {
        &self.groups
    }

    /// Whether every rule can be judged from the key blob alone (no comment).
    ///
    /// `true` when no rule anywhere is comment-dependent (see
    /// [`Filter::needs_comment`]), so the evaluator yields a correct verdict even
    /// for an identity whose comment is unknown. An empty (match-all) evaluator
    /// is trivially blob-only.
    ///
    /// The upstream sign fallback relies on this: a blob signed without a prior
    /// enumeration has no comment, so a non-blob-only filter must fail closed
    /// there rather than judge against an empty comment (which would let a
    /// `not-comment=...` rule wrongly admit a hidden key).
    pub fn is_blob_only(&self) -> bool {
        self.groups
            .iter()
            .flat_map(|g| g.rules())
            .all(|r| !r.filter.needs_comment())
    }

    /// Every `github=<user>` matcher across all groups.
    ///
    /// The daemon collects these at startup and on each refresh tick to fetch /
    /// re-fetch each user's published key set (the fetch is async; the matcher's
    /// own [`GithubMatcher::matches`] stays synchronous on the hot path). Because
    /// a matcher is cheaply cloneable and shares its cache, the daemon may keep a
    /// clone and still update the same cache the evaluator reads from.
    pub fn github_matchers(&self) -> Vec<&GithubMatcher> {
        self.groups
            .iter()
            .flat_map(|g| g.rules())
            .filter_map(|r| match &r.filter {
                Filter::Github(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    /// Re-read every reloadable filter (currently only `keyfile`).
    ///
    /// `github` is **not** reloaded here: its key set is refreshed asynchronously
    /// by the daemon (a blocking `curl` must not run on this synchronous path).
    pub fn reload(&self) -> Result<()> {
        for group in &self.groups {
            for rule in group.rules() {
                if let Filter::Keyfile(m) = &rule.filter {
                    m.reload()?;
                }
            }
        }
        Ok(())
    }

    /// Secret-free descriptions of every group's rules (for diagnostics).
    pub fn descriptions(&self) -> Vec<Vec<String>> {
        self.groups
            .iter()
            .map(|g| g.rules().iter().map(|r| r.description()).collect())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_identity(comment: &str) -> Identity {
        Identity::new(Bytes::new(), comment.to_string())
    }

    #[test]
    fn test_empty_evaluator() {
        let evaluator = FilterEvaluator::default();
        assert!(evaluator.is_empty());
        assert!(evaluator.matches(&make_identity("any")));
    }

    #[test]
    fn test_single_rule() {
        let evaluator = FilterEvaluator::parse(&[vec!["comment=test".to_string()]]).unwrap();
        assert!(evaluator.matches(&make_identity("test")));
        assert!(!evaluator.matches(&make_identity("other")));
    }

    #[test]
    fn test_multiple_rules_and() {
        let evaluator = FilterEvaluator::parse(&[vec![
            "comment=*@work*".to_string(),
            "not-comment=*@work.bad*".to_string(),
        ]])
        .unwrap();

        assert!(evaluator.matches(&make_identity("user@work.good")));
        assert!(!evaluator.matches(&make_identity("user@work.bad")));
        assert!(!evaluator.matches(&make_identity("user@home")));
    }

    #[test]
    fn empty_evaluator_is_blob_only() {
        assert!(FilterEvaluator::default().is_blob_only());
    }

    #[test]
    fn blob_derived_filters_are_blob_only() {
        let evaluator = FilterEvaluator::parse(&[vec![
            "type=ed25519".to_string(),
            "SHA256:abc123".to_string(),
        ]])
        .unwrap();
        assert!(evaluator.is_blob_only());
    }

    #[test]
    fn any_comment_rule_makes_it_not_blob_only() {
        // Positive comment rule.
        assert!(
            !FilterEvaluator::parse(&[vec!["comment=github*".to_string()]])
                .unwrap()
                .is_blob_only()
        );
        // Negated comment rule — the one that must fail closed on the upstream
        // fallback (otherwise an empty comment would wrongly admit a hidden key).
        assert!(
            !FilterEvaluator::parse(&[vec!["not-comment=secret*".to_string()]])
                .unwrap()
                .is_blob_only()
        );
        // Comment hidden inside one OR group taints the whole evaluator.
        assert!(
            !FilterEvaluator::parse(&[
                vec!["type=ed25519".to_string()],
                vec!["comment=work*".to_string()],
            ])
            .unwrap()
            .is_blob_only()
        );
    }

    #[test]
    fn github_filter_is_blob_only() {
        // The github form judges by published-blob membership, never by comment,
        // so a github-only socket stays blob-only (upstream sign fallback can
        // still evaluate it from the blob alone).
        let evaluator = FilterEvaluator::parse(&[vec!["github=kawaz".to_string()]]).unwrap();
        assert!(evaluator.is_blob_only());
    }

    #[test]
    fn github_matchers_are_collected_across_groups() {
        let evaluator = FilterEvaluator::parse(&[
            vec!["github=kawaz".to_string()],
            vec!["type=ed25519".to_string(), "github=kawaz123".to_string()],
        ])
        .unwrap();
        let matchers = evaluator.github_matchers();
        assert_eq!(matchers.len(), 2);
        let users: Vec<_> = matchers.iter().map(|m| m.user()).collect();
        assert!(users.contains(&"kawaz"));
        assert!(users.contains(&"kawaz123"));
    }

    #[test]
    fn no_github_matchers_when_none_present() {
        let evaluator = FilterEvaluator::parse(&[vec!["type=ed25519".to_string()]]).unwrap();
        assert!(evaluator.github_matchers().is_empty());
    }

    #[test]
    fn test_filter_identities() {
        let evaluator = FilterEvaluator::parse(&[vec!["comment=*@work*".to_string()]]).unwrap();
        let identities = vec![
            make_identity("user@work"),
            make_identity("user@home"),
            make_identity("admin@work"),
        ];

        let filtered = evaluator.filter_identities(identities);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].comment, "user@work");
        assert_eq!(filtered[1].comment, "admin@work");
    }

    #[test]
    fn test_or_logic() {
        let evaluator = FilterEvaluator::parse(&[
            vec!["comment=*@work*".to_string()],
            vec!["comment=admin*".to_string()],
        ])
        .unwrap();

        assert!(evaluator.matches(&make_identity("user@work")));
        assert!(evaluator.matches(&make_identity("admin@home")));
        assert!(!evaluator.matches(&make_identity("user@home")));
    }

    #[test]
    fn test_and_or_combined() {
        let evaluator = FilterEvaluator::parse(&[
            vec![
                "comment=*kawaz*".to_string(),
                "comment=*ed25519*".to_string(),
            ],
            vec!["comment=*syun*".to_string()],
        ])
        .unwrap();

        assert!(evaluator.matches(&make_identity("kawaz-ed25519")));
        assert!(evaluator.matches(&make_identity("syun-key")));
        assert!(!evaluator.matches(&make_identity("kawaz-rsa")));
        assert!(!evaluator.matches(&make_identity("other")));
    }
}
