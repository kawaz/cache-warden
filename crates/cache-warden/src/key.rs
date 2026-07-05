//! Store-key syntax validation, enforced at every write entry point.
//!
//! The core store holds a flat map from a composed key to a cache entry. DR-0017
//! defines the shape those composed keys may take: `[A-Za-z0-9_]+` segments
//! joined by `/`, either a bare `KEY` or a namespaced `NS/KEY`. This module
//! enforces that **syntax** — the character set and the one-or-two-segment shape
//! — inside `Store::set` / `Store::define` / `Store::define_with_meta`, so no
//! caller (adapter or otherwise) can insert a key the grammar forbids. Before
//! this gate the character-set rule lived only at the CLI / wire boundary
//! (`validate_cli_key` / `validate_protocol_key`), which an in-process adapter
//! could bypass by calling the core directly with a raw string (the
//! `__authsock_op:<id>` key that carried a `/`-charset-violating `:` was exactly
//! that bypass).
//!
//! # Syntax, not semantics
//!
//! The core enforces the composed-key **grammar** and nothing else. It does not
//! know which namespaces exist, which are reserved, or whether a bare `KEY`
//! should be rejected in favour of an explicit namespace — those are namespace
//! *semantics* that stay in the adapter layer (the wire/CLI handlers reject a
//! bare `KEY` and the reserved `authsock` namespace). Accepting one *or* two
//! segments here is deliberate: the core is a generic KV whose own tests key on
//! bare identifiers (`"K"`, `"GITHUB_KEY"`), while the daemon adapter composes
//! every externally reachable key into `NS/KEY`.

/// A key rejected by [`validate_key_syntax`] for violating the composed-key
/// grammar (DR-0027): the character set (`[A-Za-z0-9_]`) or the one-or-two
/// `/`-joined segment shape.
///
/// Carries the offending key so a caller can render an actionable message. The
/// key text is not a secret (it is a name, never a value), so echoing it is
/// safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidKey {
    key: String,
}

impl InvalidKey {
    /// The key text that failed validation.
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl std::fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid key {:?}: must be one or two [A-Za-z0-9_]+ segments joined by `/` \
             (KEY or NS/KEY) (DR-0017)",
            self.key
        )
    }
}

impl std::error::Error for InvalidKey {}

/// Whether `seg` is a single valid identifier segment: a non-empty run of
/// `[A-Za-z0-9_]`. Shared by both segment positions (KEY and NS use the same
/// charset — DR-0017 §1.5).
fn is_identifier_segment(seg: &str) -> bool {
    !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Validate a composed store key's syntax (DR-0017 §1.5): one or two
/// `[A-Za-z0-9_]+` segments joined by a single `/` (`KEY` or `NS/KEY`).
///
/// Rejects the empty string, any non-`[A-Za-z0-9_/]` byte (`:` / whitespace /
/// control / `.` / `-`), an empty segment (leading/trailing/doubled `/`), and
/// three or more segments. On success the key is guaranteed to round-trip
/// through `split('/')` unambiguously and to be writable into TOML as a bare key.
pub fn validate_key_syntax(key: &str) -> Result<(), InvalidKey> {
    let mut segments = key.split('/');
    // A composed key is exactly one or two identifier segments. Peeling three
    // items off the iterator distinguishes 1 / 2 / ≥3 segments in one pass.
    let ok = match (segments.next(), segments.next(), segments.next()) {
        // Exactly one segment (a bare KEY).
        (Some(only), None, _) => is_identifier_segment(only),
        // Exactly two segments (NS/KEY).
        (Some(ns), Some(key), None) => is_identifier_segment(ns) && is_identifier_segment(key),
        // Zero segments is impossible (`split` always yields at least one item);
        // three or more segments is a too-deep key.
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(InvalidKey {
            key: key.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- accepted keys: one or two identifier segments (DR-0017 §1.5) ----

    #[test]
    fn accepts_a_bare_single_segment_key() {
        // The core is a generic KV; a bare identifier is a legal store key. The
        // daemon adapter composes NS/KEY on top, but the core does not require it
        // (its own value tests key on bare names like "K" / "GITHUB_KEY").
        for ok in [
            "K",
            "DB_PASSWORD",
            "a",
            "_x",
            "A1",
            "GITHUB_KEY",
            "op_itemABC",
        ] {
            assert!(validate_key_syntax(ok).is_ok(), "{ok:?} must be accepted");
        }
    }

    #[test]
    fn accepts_a_two_segment_ns_key() {
        // The composed `NS/KEY` form every externally reachable key takes.
        for ok in ["default/K", "projA/DB_PASSWORD", "authsock/op_itemABC"] {
            assert!(validate_key_syntax(ok).is_ok(), "{ok:?} must be accepted");
        }
    }

    // ---- rejected keys: charset / shape violations ----

    #[test]
    fn rejects_the_colon_pseudo_prefix() {
        // The exact bypass this gate closes: the old internal op key name
        // `__authsock_op:<item_id>` carries a `:`, which is outside the charset.
        // A core write must refuse it so no adapter can smuggle it in.
        let err = validate_key_syntax("__authsock_op:itemABC").unwrap_err();
        assert_eq!(err.key(), "__authsock_op:itemABC");
    }

    #[test]
    fn rejects_empty_and_whitespace_and_control() {
        // Empty (no segment), embedded space, tab, and a control byte are all
        // outside `[A-Za-z0-9_]` — none can name a referenceable key.
        for bad in ["", "a b", "a\tb", "a\nb", "a\0b"] {
            assert!(
                validate_key_syntax(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_dot_and_dash_removed_from_the_charset() {
        // DR-0017 §1.5 removed `.` (TOML dotted-key footgun) and `-` (inject
        // terminator ambiguity) from the identifier charset.
        for bad in ["a.b", "a-b", "default/a.b", "a-b/K"] {
            assert!(
                validate_key_syntax(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_empty_segments_from_stray_slashes() {
        // Leading, trailing, and doubled slashes all produce an empty segment,
        // which is not a valid identifier.
        for bad in ["/K", "K/", "/", "a//b", "ns/"] {
            assert!(
                validate_key_syntax(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_three_or_more_segments() {
        // DR-0017 namespaces are a single segment; `a/b/c` is too deep.
        for bad in ["a/b/c", "ns/key/extra", "a/b/c/d"] {
            assert!(
                validate_key_syntax(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_unicode_outside_ascii_alphanumeric() {
        // The charset is ASCII `[A-Za-z0-9_]`; multibyte identifiers are refused.
        for bad in ["日本語", "café", "ключ"] {
            assert!(
                validate_key_syntax(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}
