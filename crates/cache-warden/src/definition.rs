//! The value-source definition registry, held separately from cached values.
//!
//! A [`Definition`] binds a key to *how* its value is (re)produced — a command
//! [`ValueSource`] plus the [`Ttl`] freshly loaded values should carry — without
//! holding any secret value itself. Definitions are plain configuration data
//! (DR-0014): they are not secrets, so they live in their own registry beside
//! the value store rather than as an extra [`crate::EntryState`]. This is the
//! same call DR-0004 made when it declined to add a `NotLoaded` value state to
//! the core.
//!
//! # Why definitions are command-only
//!
//! A definition exists to drive **lazy / regenerating** value production: when a
//! key's value is absent or hard-expired, the [`crate::Store`] re-runs the
//! definition's command (re-auth included) to materialize a fresh value. A
//! [`ValueSource::Static`] has nothing to re-run — its bytes are gone once the
//! value hard-expires — so a static "definition" could never lazily produce a
//! value. Defining a static source is therefore rejected
//! ([`DefineError::StaticNotDefinable`]); static values are supplied through
//! `set` and live only in the value store (DR-0014 §2).
//!
//! # Idempotency (DR-0014 §1)
//!
//! `define` is idempotent under an **exact-match** rule: re-defining a key with
//! the identical source argv *and* TTL is a no-op, while any mismatch is a hard
//! error ([`DefineError::Conflict`]). The "command is canonical, silently
//! overwrite" alternative was rejected because two scripts using the same key
//! with different definitions would clobber each other invisibly; surfacing the
//! clash as an error forces the user to resolve it explicitly (delete the
//! definition, then re-define).

use crate::entry::Ttl;
use crate::meta::{SourceMeta, ValueMeta};
use crate::source::ValueSource;

/// A key's value-source definition: how to (re)produce its value, plus the TTL
/// freshly produced values are loaded with. Holds no secret value.
///
/// A definition may also carry opaque [`ValueMeta`] (a value-type label +
/// parameters; DR-0016): the core stores it and copies it onto each freshly
/// produced value, but never interprets it. The metadata participates in the
/// exact-match idempotency rule (a definition that differs only in its type
/// metadata is a *different* definition, so a redefine conflicts).
///
/// A definition additionally carries an opaque [`SourceMeta`] (DR-0018 §2): the
/// **typed source origin** it was defined from (`source = "command"` / `"op"` +
/// the selected kind's fields). This is a *second* opaque slot, orthogonal to
/// `ValueMeta` (value type vs. source type are independent axes). The execution
/// primitive stays the lowered [`ValueSource::Command`]; this slot preserves the
/// original typed form for `status`, persistence, and idempotency. Like
/// `ValueMeta`, it participates in the exact-match idempotency rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    source: ValueSource,
    ttl: Ttl,
    meta: ValueMeta,
    source_meta: SourceMeta,
}

impl Definition {
    /// Build a definition from a command source and a TTL (no type metadata).
    ///
    /// Returns [`DefineError::StaticNotDefinable`] if `source` is
    /// [`ValueSource::Static`]: only regenerable (command) sources can back a
    /// lazily produced value (see the module note).
    pub fn new(source: ValueSource, ttl: Ttl) -> Result<Self, DefineError> {
        match source {
            ValueSource::Command { .. } => Ok(Self {
                source,
                ttl,
                meta: ValueMeta::new(),
                source_meta: SourceMeta::new(),
            }),
            ValueSource::Static => Err(DefineError::StaticNotDefinable),
        }
    }

    /// Attach opaque value-type metadata to this definition (builder style;
    /// DR-0016).
    ///
    /// The core stores it verbatim and copies it onto each value produced from
    /// this definition; it never interprets the contents.
    pub fn with_meta(mut self, meta: ValueMeta) -> Self {
        self.meta = meta;
        self
    }

    /// Attach the opaque typed-source-origin slot to this definition (builder
    /// style; DR-0018 §2).
    ///
    /// The core stores it verbatim for `status` / persistence / idempotency and
    /// never interprets it.
    pub fn with_source_meta(mut self, source_meta: SourceMeta) -> Self {
        self.source_meta = source_meta;
        self
    }

    /// The value source this definition (re)runs to produce a value.
    pub fn source(&self) -> &ValueSource {
        &self.source
    }

    /// The TTL freshly produced values are loaded with.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Borrow this definition's opaque value-type metadata (DR-0016). Value-free.
    pub fn meta(&self) -> &ValueMeta {
        &self.meta
    }

    /// Borrow this definition's opaque typed-source-origin slot (DR-0018 §2).
    /// Value-free.
    pub fn source_meta(&self) -> &SourceMeta {
        &self.source_meta
    }
}

/// Error from [`crate::Store::define`].
#[derive(Debug, PartialEq, Eq)]
pub enum DefineError {
    /// A definition already exists under this key with a different source or
    /// TTL. `define` is idempotent only for an *exact* match (DR-0014 §1);
    /// mismatches must be resolved by the user (delete the definition, then
    /// re-define) rather than being silently overwritten.
    Conflict,
    /// A [`ValueSource::Static`] was supplied. Definitions are command-only
    /// because a static source has nothing to re-run to lazily produce a value;
    /// use `set` for static values (DR-0014 §2).
    StaticNotDefinable,
}

impl std::fmt::Display for DefineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefineError::Conflict => write!(
                f,
                "a different definition already exists for this key; \
                 delete it (with --with-define) before redefining"
            ),
            DefineError::StaticNotDefinable => {
                write!(f, "static sources cannot be defined; use set instead")
            }
        }
    }
}

impl std::error::Error for DefineError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ttl() -> Ttl {
        Ttl::new(Some(Duration::from_secs(10)), Some(Duration::from_secs(30))).unwrap()
    }

    fn cmd() -> ValueSource {
        ValueSource::command(["op".into(), "read".into(), "op://v/i/f".into()])
    }

    #[test]
    fn new_accepts_command_source() {
        let d = Definition::new(cmd(), ttl()).unwrap();
        assert_eq!(d.source(), &cmd());
        assert_eq!(d.ttl(), ttl());
    }

    #[test]
    fn new_rejects_static_source() {
        let err = Definition::new(ValueSource::Static, ttl()).unwrap_err();
        assert_eq!(err, DefineError::StaticNotDefinable);
    }

    #[test]
    fn equal_definitions_compare_equal() {
        // Drives the exact-match idempotency rule in the store.
        let a = Definition::new(cmd(), ttl()).unwrap();
        let b = Definition::new(cmd(), ttl()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn differing_argv_or_ttl_compare_unequal() {
        let base = Definition::new(cmd(), ttl()).unwrap();
        let other_argv = Definition::new(
            ValueSource::command(["op".into(), "read".into(), "op://other".into()]),
            ttl(),
        )
        .unwrap();
        assert_ne!(base, other_argv);

        let other_ttl = Definition::new(
            cmd(),
            Ttl::new(Some(Duration::from_secs(5)), Some(Duration::from_secs(30))).unwrap(),
        )
        .unwrap();
        assert_ne!(base, other_ttl);
    }

    #[test]
    fn source_meta_participates_in_equality() {
        use crate::meta::SourceMeta;
        // Two definitions identical but for their typed source origin are
        // *different* definitions (DR-0018 §2: source_meta is part of identity).
        let op = SourceMeta::with_kind("op", [("uri".to_string(), "op://v/i/f".to_string())]);
        let with = Definition::new(cmd(), ttl())
            .unwrap()
            .with_source_meta(op.clone());
        let without = Definition::new(cmd(), ttl()).unwrap();
        assert_ne!(with, without);

        let same = Definition::new(cmd(), ttl()).unwrap().with_source_meta(op);
        assert_eq!(with, same);
    }

    #[test]
    fn source_meta_defaults_to_empty() {
        let d = Definition::new(cmd(), ttl()).unwrap();
        assert!(d.source_meta().is_empty());
    }
}
