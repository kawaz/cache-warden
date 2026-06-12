//! An opaque, core-uninterpreted metadata slot for definitions.
//!
//! [`ValueMeta`] is a small, deliberately *generic* attribute bag the core
//! attaches to a [`Definition`](crate::Definition) and **never interprets**. It
//! exists so an adapter layer can tag a *key* with a value *type* and its
//! type-specific parameters (DR-0016: the OTP value type tags a definition
//! `type = "otp"` with `digits` / `period` / `algorithm`), while the core stays
//! unaware of what any of it means.
//!
//! The type lives on the definition, not on the cached value: a typed key is
//! always definition-backed (DR-0016), so the value entry stays opaque bytes and
//! type detection reads the definition registry.
//!
//! # Design rationale: why a generic bag, not OTP fields
//!
//! DR-0016 §2 mandates that the core knows nothing about OTP — no TOTP logic,
//! not even the vocabulary. So instead of adding `otp_digits` etc. to the core,
//! the core gets the *minimal generic* shape that can carry any future derived
//! type: an optional opaque `type` label plus an opaque string→string parameter
//! map. The handler layer (in the CLI crate) is the only place that reads
//! `type == "otp"` and the parameter strings. Adding a new derived type later
//! needs **no** core change — it reuses this same slot.
//!
//! The map is `BTreeMap` so serialization (definition persistence, `status`) is
//! deterministic. Values are plain `String`s: the core does not parse them.

use std::collections::BTreeMap;

/// An opaque type label + parameter bag attached to a definition.
///
/// The core treats every field as inert data: it stores, clones, compares, and
/// hands it back, but never reads its meaning. An empty `ValueMeta`
/// ([`ValueMeta::is_empty`]) is the "no type metadata" default an ordinary
/// (opaque) definition carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueMeta {
    /// An opaque value-type label (e.g. `"otp"`), or `None` for an untyped
    /// (opaque) value. The core never interprets it.
    type_label: Option<String>,
    /// Opaque type-specific parameters (e.g. OTP `digits` / `period` /
    /// `algorithm`), keyed by name. The core never interprets keys or values.
    params: BTreeMap<String, String>,
}

impl ValueMeta {
    /// An empty metadata slot (no type, no params) — the default for an opaque
    /// value.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a metadata slot with a type label and parameters.
    pub fn with_type(
        type_label: impl Into<String>,
        params: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            type_label: Some(type_label.into()),
            params: params.into_iter().collect(),
        }
    }

    /// The opaque type label, if any.
    pub fn type_label(&self) -> Option<&str> {
        self.type_label.as_deref()
    }

    /// Borrow one opaque parameter by name.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Iterate the opaque parameters in deterministic (key-sorted) order.
    pub fn params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether this slot carries no type and no parameters (the opaque default).
    pub fn is_empty(&self) -> bool {
        self.type_label.is_none() && self.params.is_empty()
    }
}

/// An opaque, core-uninterpreted slot for a definition's **typed source origin**
/// (DR-0018 §2).
///
/// This is the *second* opaque slot on a [`Definition`](crate::Definition),
/// orthogonal to [`ValueMeta`]: [`ValueMeta`] records the value *type* (e.g.
/// `otp`), whereas [`SourceMeta`] records the typed *source* it was defined from
/// (`source = "command"` with `command.cwd` / `command.env`, or `source = "op"`
/// with `op.uri` / `op.account`). The core stores, clones, compares, and hands it
/// back, but **never interprets it**: the execution primitive stays the
/// lowered [`ValueSource::Command`](crate::ValueSource), while this slot preserves
/// the original typed form for `status`, persistence, and idempotency.
///
/// # Why a second slot, not reuse `ValueMeta`
///
/// DR-0018 §2: the value type and the source type are *independent axes* (an otp
/// value can come from either a `command` or an `op` source). Folding both into
/// one bag would conflate them and make the idempotency comparison ambiguous. A
/// dedicated slot keeps each axis pure.
///
/// # Idempotency
///
/// The slot participates in `define`'s exact-match rule (DR-0018 §1): two
/// definitions that differ only in their typed source origin are *different*
/// definitions. Only the **selected** kind's fields are recorded (an unselected
/// kind table in config is ignored, so it never reaches this slot), so comparing
/// the slots compares exactly "the discriminant + the chosen kind's verbatim
/// fields".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMeta {
    /// The source discriminant (`"command"` / `"op"` / a future vendor kind), or
    /// `None` for a source defined without a typed origin (e.g. an authsock op
    /// key registered internally). The core never interprets it.
    kind: Option<String>,
    /// The selected kind's verbatim fields, keyed by name (e.g. `op.uri` →
    /// `"uri"`, `command.cwd` → `"cwd"`). Multi-valued fields (argv, env) are
    /// rendered into deterministic string forms by the adapter layer; the core
    /// never parses them.
    fields: BTreeMap<String, String>,
}

impl SourceMeta {
    /// An empty source-origin slot (no kind, no fields) — the default for a
    /// definition with no typed source origin recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a source-origin slot with a discriminant and its verbatim fields.
    pub fn with_kind(
        kind: impl Into<String>,
        fields: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            kind: Some(kind.into()),
            fields: fields.into_iter().collect(),
        }
    }

    /// The opaque source discriminant, if any.
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Borrow one opaque field by name.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// Iterate the opaque fields in deterministic (key-sorted) order.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether this slot carries no kind and no fields (the default).
    pub fn is_empty(&self) -> bool {
        self.kind.is_none() && self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty_and_untyped() {
        let m = ValueMeta::new();
        assert!(m.is_empty());
        assert_eq!(m.type_label(), None);
        assert_eq!(m.params().count(), 0);
    }

    #[test]
    fn with_type_carries_label_and_params() {
        let m = ValueMeta::with_type(
            "otp",
            [
                ("digits".to_string(), "6".to_string()),
                ("period".to_string(), "30".to_string()),
            ],
        );
        assert!(!m.is_empty());
        assert_eq!(m.type_label(), Some("otp"));
        assert_eq!(m.param("digits"), Some("6"));
        assert_eq!(m.param("period"), Some("30"));
        assert_eq!(m.param("missing"), None);
    }

    #[test]
    fn params_iterate_key_sorted() {
        let m = ValueMeta::with_type(
            "otp",
            [
                ("period".to_string(), "30".to_string()),
                ("algorithm".to_string(), "sha1".to_string()),
                ("digits".to_string(), "6".to_string()),
            ],
        );
        let keys: Vec<&str> = m.params().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["algorithm", "digits", "period"]);
    }

    #[test]
    fn type_label_without_params_is_allowed() {
        let m = ValueMeta::with_type("otp", []);
        assert_eq!(m.type_label(), Some("otp"));
        assert_eq!(m.params().count(), 0);
        assert!(!m.is_empty());
    }

    #[test]
    fn equality_is_structural() {
        let a = ValueMeta::with_type("otp", [("digits".to_string(), "6".to_string())]);
        let b = ValueMeta::with_type("otp", [("digits".to_string(), "6".to_string())]);
        let c = ValueMeta::with_type("otp", [("digits".to_string(), "8".to_string())]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- SourceMeta (DR-0018 §2) ----

    #[test]
    fn source_meta_default_is_empty() {
        let m = SourceMeta::new();
        assert!(m.is_empty());
        assert_eq!(m.kind(), None);
        assert_eq!(m.fields().count(), 0);
    }

    #[test]
    fn source_meta_with_kind_carries_discriminant_and_fields() {
        let m = SourceMeta::with_kind(
            "op",
            [
                ("uri".to_string(), "op://v/i/f".to_string()),
                ("account".to_string(), "my.1password.com".to_string()),
            ],
        );
        assert!(!m.is_empty());
        assert_eq!(m.kind(), Some("op"));
        assert_eq!(m.field("uri"), Some("op://v/i/f"));
        assert_eq!(m.field("account"), Some("my.1password.com"));
        assert_eq!(m.field("missing"), None);
    }

    #[test]
    fn source_meta_fields_iterate_key_sorted() {
        let m = SourceMeta::with_kind(
            "command",
            [
                ("env".to_string(), "K=V".to_string()),
                ("cwd".to_string(), "/tmp".to_string()),
                ("argv".to_string(), "prog".to_string()),
            ],
        );
        let keys: Vec<&str> = m.fields().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["argv", "cwd", "env"]);
    }

    #[test]
    fn source_meta_equality_is_structural() {
        let a = SourceMeta::with_kind("op", [("uri".to_string(), "op://a".to_string())]);
        let b = SourceMeta::with_kind("op", [("uri".to_string(), "op://a".to_string())]);
        let c = SourceMeta::with_kind("op", [("uri".to_string(), "op://b".to_string())]);
        // Same kind, different verbatim field => different definition origin.
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Different discriminant => different.
        let d = SourceMeta::with_kind("command", [("uri".to_string(), "op://a".to_string())]);
        assert_ne!(a, d);
    }
}
