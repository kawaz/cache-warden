//! KV namespace resolution and the `NS/KEY` composition rules (DR-0017).
//!
//! A namespace is a CLI / protocol-layer concept: the daemon's core store stays
//! flat, and every key that crosses the protocol is the **composed**
//! `NS/KEY` form. Both segments share one identifier charset (`[A-Za-z0-9_]+`,
//! DR-0017 §1.5), so the composition is always unambiguous (`/` is not in the
//! charset) and every composed key can be written into TOML as a quoted key
//! and referenced as `cache-warden://NS/KEY`.
//!
//! The default namespace is resolved once per invocation from the same kind of
//! precedence chain as the dry-run polarity (DR-0015 §4 / DR-0017 §4):
//!
//! 1. an explicit `--namespace NS` flag (highest),
//! 2. the `CACHE_WARDEN_NAMESPACE` environment variable,
//! 3. the config `[cli].namespace`,
//! 4. the built-in `"default"`.

/// The built-in default namespace (DR-0017 §1).
pub const DEFAULT_NAMESPACE: &str = "default";

/// `true` if `s` is a valid KEY / NS identifier: `[A-Za-z0-9_]+` (DR-0017 §1.5).
pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Validate one identifier (a KEY or a NS segment), naming `what` in the error.
///
/// The error spells out the accepted charset so a rejected key is
/// self-explanatory. A `/` inside a CLI KEY gets a more specific steer from the
/// kv parsers (use `--namespace`), so this generic message is the fallback.
pub fn validate_identifier(s: &str, what: &str) -> Result<(), String> {
    if is_valid_identifier(s) {
        Ok(())
    } else {
        Err(format!(
            "invalid {what} {s:?}: must be non-empty and contain only [A-Za-z0-9_] (DR-0017)"
        ))
    }
}

/// Compose a namespace and a key into the internal flat key `NS/KEY`.
///
/// Both parts must already be validated identifiers; composition itself never
/// fails.
pub fn compose(ns: &str, key: &str) -> String {
    format!("{ns}/{key}")
}

/// Split a composed `NS/KEY` into its parts, or `None` if `s` is not a valid
/// composed key (exactly one `/`, both sides valid identifiers).
pub fn split_composed(s: &str) -> Option<(&str, &str)> {
    let (ns, key) = s.split_once('/')?;
    if is_valid_identifier(ns) && is_valid_identifier(key) {
        Some((ns, key))
    } else {
        None
    }
}

/// Qualify a reference key against a context namespace (DR-0017 §3): an
/// already-qualified `NS/KEY` is absolute (returned as-is), an unqualified
/// `KEY` resolves into the context namespace.
pub fn qualify(reference_key: &str, ctx_ns: &str) -> String {
    if reference_key.contains('/') {
        reference_key.to_string()
    } else {
        compose(ctx_ns, reference_key)
    }
}

/// Extract a single `--namespace NS` / `--namespace=NS` flag from `args`,
/// returning the value (if any) and the remaining args with it removed.
///
/// Scanning stops at the first standalone `--` (everything after it is
/// positional; the separator is preserved for the downstream parser). Giving
/// the flag twice with different values is a usage error (same convention as
/// the mode flags); repeating the same value is harmless.
pub fn take_namespace_flag(args: &[String]) -> Result<(Option<String>, Vec<String>), String> {
    let mut ns: Option<String> = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            rest.extend(args[i..].iter().cloned());
            break;
        }
        let value = if a == "--namespace" {
            let v = args
                .get(i + 1)
                .ok_or("--namespace requires a NS argument")?;
            i += 2;
            Some(v.clone())
        } else if let Some(v) = a.strip_prefix("--namespace=") {
            i += 1;
            Some(v.to_string())
        } else {
            rest.push(a.clone());
            i += 1;
            None
        };
        if let Some(v) = value {
            validate_identifier(&v, "namespace")?;
            match &ns {
                None => ns = Some(v),
                Some(prev) if *prev == v => {} // same value twice: harmless
                Some(prev) => {
                    return Err(format!(
                        "--namespace given twice with different values ({prev:?} vs {v:?})"
                    ));
                }
            }
        }
    }
    Ok((ns, rest))
}

/// Resolve the effective namespace from the precedence chain (DR-0017 §4):
/// flag > `CACHE_WARDEN_NAMESPACE` env > config `[cli].namespace` > `"default"`.
///
/// `env` is the raw environment value (see [`env_namespace`]); `config` is the
/// parsed `[cli].namespace`. Each tier is validated so a typo'd namespace fails
/// loudly instead of silently creating a junk namespace.
pub fn resolve_namespace(
    flag: Option<String>,
    env: Option<String>,
    config: Option<String>,
) -> Result<String, String> {
    if let Some(ns) = flag {
        validate_identifier(&ns, "namespace")?;
        return Ok(ns);
    }
    if let Some(ns) = env {
        validate_identifier(&ns, "namespace (CACHE_WARDEN_NAMESPACE)")?;
        return Ok(ns);
    }
    if let Some(ns) = config {
        validate_identifier(&ns, "namespace ([cli].namespace)")?;
        return Ok(ns);
    }
    Ok(DEFAULT_NAMESPACE.to_string())
}

/// Read `CACHE_WARDEN_NAMESPACE`, treating unset / empty as "not given"
/// (defer to the next tier).
pub fn env_namespace() -> Option<String> {
    match std::env::var("CACHE_WARDEN_NAMESPACE") {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    // ---- identifier charset (DR-0017 §1.5) ----

    #[test]
    fn identifier_accepts_alnum_underscore() {
        for ok in ["DB_PASSWORD", "a", "_x", "A1", "default", "projA_2"] {
            assert!(is_valid_identifier(ok), "{ok:?} must be valid");
        }
    }

    #[test]
    fn identifier_rejects_dot_dash_slash_empty_and_unicode() {
        for bad in ["", "a.b", "a-b", "a/b", "a b", "a:b", "日本語", "--weird"] {
            assert!(!is_valid_identifier(bad), "{bad:?} must be invalid");
        }
    }

    #[test]
    fn validate_identifier_names_the_what_in_the_error() {
        let err = validate_identifier("a.b", "KEY").unwrap_err();
        assert!(err.contains("KEY"), "msg: {err}");
        assert!(err.contains("A-Za-z0-9_"), "msg: {err}");
    }

    // ---- compose / split / qualify ----

    #[test]
    fn compose_and_split_round_trip() {
        let k = compose("projA", "DB");
        assert_eq!(k, "projA/DB");
        assert_eq!(split_composed(&k), Some(("projA", "DB")));
    }

    #[test]
    fn split_composed_rejects_malformed() {
        for bad in ["plain", "a/b/c", "/k", "ns/", "a.b/c", "a/b.c", ""] {
            assert_eq!(split_composed(bad), None, "{bad:?} must not split");
        }
    }

    #[test]
    fn qualify_unqualified_uses_context_qualified_is_absolute() {
        // DR-0017 §3: `bar` in ctx `foo` -> foo/bar; `hoge/fuga` stays as-is.
        assert_eq!(qualify("bar", "foo"), "foo/bar");
        assert_eq!(qualify("hoge/fuga", "foo"), "hoge/fuga");
    }

    // ---- --namespace flag ----

    #[test]
    fn take_namespace_flag_space_and_equals_forms() {
        let (ns, rest) = take_namespace_flag(&s(&["--namespace", "projA", "K"])).unwrap();
        assert_eq!(ns.as_deref(), Some("projA"));
        assert_eq!(rest, s(&["K"]));

        let (ns, rest) = take_namespace_flag(&s(&["K", "--namespace=projB"])).unwrap();
        assert_eq!(ns.as_deref(), Some("projB"));
        assert_eq!(rest, s(&["K"]));
    }

    #[test]
    fn take_namespace_flag_absent_is_none() {
        let (ns, rest) = take_namespace_flag(&s(&["K"])).unwrap();
        assert_eq!(ns, None);
        assert_eq!(rest, s(&["K"]));
    }

    #[test]
    fn take_namespace_flag_validates_charset() {
        assert!(take_namespace_flag(&s(&["--namespace", "a/b"])).is_err());
        assert!(take_namespace_flag(&s(&["--namespace", "a.b"])).is_err());
        assert!(take_namespace_flag(&s(&["--namespace"])).is_err());
    }

    #[test]
    fn take_namespace_flag_conflicting_values_error() {
        assert!(take_namespace_flag(&s(&["--namespace", "a", "--namespace", "b"])).is_err());
        // The same value twice is harmless.
        let (ns, _) = take_namespace_flag(&s(&["--namespace", "a", "--namespace", "a"])).unwrap();
        assert_eq!(ns.as_deref(), Some("a"));
    }

    #[test]
    fn take_namespace_flag_stops_at_double_dash() {
        let (ns, rest) = take_namespace_flag(&s(&["--", "--namespace", "x"])).unwrap();
        assert_eq!(ns, None);
        assert_eq!(rest, s(&["--", "--namespace", "x"]));
    }

    // ---- precedence chain (DR-0017 §4) ----

    #[test]
    fn resolve_namespace_flag_wins_then_env_then_config_then_default() {
        let r = |f: Option<&str>, e: Option<&str>, c: Option<&str>| {
            resolve_namespace(
                f.map(String::from),
                e.map(String::from),
                c.map(String::from),
            )
        };
        assert_eq!(r(Some("f"), Some("e"), Some("c")).unwrap(), "f");
        assert_eq!(r(None, Some("e"), Some("c")).unwrap(), "e");
        assert_eq!(r(None, None, Some("c")).unwrap(), "c");
        assert_eq!(r(None, None, None).unwrap(), DEFAULT_NAMESPACE);
    }

    #[test]
    fn resolve_namespace_validates_every_tier() {
        assert!(resolve_namespace(Some("a/b".into()), None, None).is_err());
        assert!(resolve_namespace(None, Some("a.b".into()), None).is_err());
        assert!(resolve_namespace(None, None, Some("a-b".into())).is_err());
    }
}
