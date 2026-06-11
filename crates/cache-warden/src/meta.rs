//! An opaque, core-uninterpreted metadata slot for values and definitions.
//!
//! [`ValueMeta`] is a small, deliberately *generic* attribute bag the core
//! attaches to a cached value (or a definition) and **never interprets**. It
//! exists so an adapter layer can tag an entry with a value *type* and its
//! type-specific parameters (DR-0016: the OTP value type tags entries `type =
//! "otp"` with `digits` / `period` / `algorithm`), while the core stays unaware
//! of what any of it means.
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

/// An opaque type label + parameter bag attached to a value or definition.
///
/// The core treats every field as inert data: it stores, clones, compares, and
/// hands it back, but never reads its meaning. An empty `ValueMeta`
/// ([`ValueMeta::is_empty`]) is the "no type metadata" default an ordinary
/// (opaque) value carries.
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
}
