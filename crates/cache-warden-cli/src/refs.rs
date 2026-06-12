//! Secret reference syntax and resolution shared by `run` and `inject`
//! (DR-0013 / DR-0015 / DR-0017).
//!
//! A reference is `cache-warden://[NS/]KEY` where both `NS` and `KEY` match
//! `[A-Za-z0-9_]+` (the identifier charset of DR-0017 §1.5). The scheme is the
//! only one accepted — there are no short aliases (DR-0013). An **unqualified**
//! `KEY` resolves into the caller's context namespace; a **qualified** `NS/KEY`
//! is absolute (DR-0017 §3). Resolution is a **single pass**: a resolved value
//! is treated as opaque bytes and never re-scanned for further references (no
//! recursive expansion, DR-0013).
//!
//! This module is pure: it detects references, decides whole-value matches (the
//! `run` env rule), performs substring replacement (the `inject` rule), builds
//! masked placeholders (dry-run), and de-duplicates keys — all without touching
//! a socket. The caller injects a resolver closure, so the same logic is unit
//! tested with a fake resolver and reused with the real control-socket client.

use std::collections::BTreeMap;

use crate::mode::Mode;
use crate::namespace::qualify;

/// The reference scheme prefix.
pub const SCHEME: &str = "cache-warden://";

/// `true` if `c` is a reference identifier char (`[A-Za-z0-9_]`, DR-0017 §1.5).
/// The same charset applies to every position of NS and KEY, so a reference
/// always ends at the first char outside it (predictable termination for
/// inject's substring scan).
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Consume a maximal `[NS/]KEY` run at the start of `t`, returning its byte
/// length, or `None` if `t` does not start with an identifier char.
///
/// At most one `/` is consumed (single-segment NS, DR-0017 §1), and only when
/// an identifier char follows it — `KEY/` at the end of a run leaves the `/`
/// outside the reference. The charset is pure ASCII, so scanning bytes is
/// exact even on binary input.
fn match_reference_key(t: &[u8]) -> Option<usize> {
    let seg = |t: &[u8]| t.iter().take_while(|b| is_key_char(**b as char)).count();
    let first = seg(t);
    if first == 0 {
        return None;
    }
    let rest = &t[first..];
    if rest.first() == Some(&b'/') {
        let second = seg(&rest[1..]);
        if second > 0 {
            return Some(first + 1 + second);
        }
    }
    Some(first)
}

/// If `s` is *exactly* one reference (`cache-warden://[NS/]KEY` and nothing
/// else), return the (possibly qualified) key. Used for the `run` env
/// whole-value rule (DR-0013): only an env value that is entirely a reference
/// is resolved.
pub fn whole_value_key(s: &str) -> Option<&str> {
    let rest = s.strip_prefix(SCHEME)?;
    match match_reference_key(rest.as_bytes()) {
        Some(len) if len == rest.len() => Some(rest),
        _ => None,
    }
}

/// `true` if `s` merely *contains* a reference substring (used for the argv
/// warning in `run`: a reference-looking token in argv is passed verbatim but
/// warned about, since argv is not an injection face).
pub fn contains_reference(s: &str) -> bool {
    find_references(s).into_iter().next().is_some()
}

/// One located reference within a byte template: its key (possibly `NS/KEY`
/// qualified) and byte span `[start, end)` (the span covers the whole
/// `cache-warden://[NS/]KEY` text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The reference key as written (unqualified `KEY` or qualified `NS/KEY`).
    pub key: String,
    /// Byte offset where `cache-warden://` begins.
    pub start: usize,
    /// Byte offset just past the last key char.
    pub end: usize,
}

/// Find every reference in `s`, left to right, non-overlapping (single pass —
/// the scan does not look inside a key for a nested scheme). The result drives
/// both `inject` substring replacement and the argv warning detector.
///
/// `s` is treated as text here (str), which is sufficient: the scheme and the
/// key charset are ASCII, so byte offsets equal char-boundary offsets and the
/// surrounding bytes (binary payload) are irrelevant to where a reference ends.
pub fn find_references(s: &str) -> Vec<Located> {
    find_references_bytes(s.as_bytes())
}

/// Find every reference directly over a raw byte template, left to right,
/// non-overlapping. This scans bytes so it is correct on **binary** input: a
/// lossy UTF-8 conversion would shift offsets (a stray `0xff` becomes a 3-byte
/// replacement char), so byte offsets from a lossy view do not map back to the
/// original template.
///
/// The scheme and key charset are ASCII, so a reference can only occur in ASCII
/// regions; non-ASCII bytes simply never match and are skipped one at a time.
pub fn find_references_bytes(template: &[u8]) -> Vec<Located> {
    let scheme = SCHEME.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < template.len() {
        if template[i..].starts_with(scheme) {
            let key_start = i + scheme.len();
            match match_reference_key(&template[key_start..]) {
                Some(len) => {
                    let end = key_start + len;
                    out.push(Located {
                        key: String::from_utf8_lossy(&template[key_start..end]).into_owned(),
                        start: i,
                        end,
                    });
                    i = end;
                }
                None => {
                    // Scheme not followed by a valid key char: skip past it.
                    i = key_start;
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Build the dry-run mask for a key: `<cache-warden:KEY:masked>` on success or
/// `<cache-warden:KEY:failed>` on failure (DR-0015 §3). The mask reveals only
/// the key name, never the value, and cannot be mistaken for a real reference
/// (`cache-warden://KEY`) or a real value.
pub fn mask(key: &str, ok: bool) -> String {
    let tag = if ok { "masked" } else { "failed" };
    format!("<cache-warden:{key}:{tag}>")
}

/// The result of resolving one key.
///
/// `Ok` carries the resolved bytes (reveal) or is value-free (dry-run, where the
/// daemon never sent a value). `Err` carries a secret-free message.
pub type ResolveResult = Result<ResolvedValue, String>;

/// A successfully resolved value — present (reveal) or absent (dry-run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedValue {
    /// The real value bytes (reveal mode).
    Value(Vec<u8>),
    /// The value was verified but not carried back (dry-run mode).
    Verified,
}

/// A resolver maps a key to its [`ResolveResult`]. The real one is the control
/// socket client; tests inject a fake.
pub trait Resolver {
    /// Resolve one key. The implementation is responsible for issuing the
    /// `kv.get` (reveal) or dry-run `kv.get` and translating the response.
    fn resolve(&mut self, key: &str) -> ResolveResult;
}

/// A blanket impl so a closure `FnMut(&str) -> ResolveResult` is a [`Resolver`].
impl<F> Resolver for F
where
    F: FnMut(&str) -> ResolveResult,
{
    fn resolve(&mut self, key: &str) -> ResolveResult {
        self(key)
    }
}

/// Resolve a set of reference keys exactly once each (dedup), returning a map
/// keyed by the **qualified** (`NS/KEY`) form.
///
/// Each reference key is qualified against `ctx_ns` first (DR-0017 §3:
/// unqualified keys resolve into the context namespace, qualified ones are
/// absolute), so `bar` and `foo/bar` under ctx `foo` are the same entry and
/// resolve a single time even if referenced many times (DR-0013: avoid
/// repeated TouchID prompts). The order of resolution is the sorted key order
/// (deterministic).
pub fn resolve_all<R: Resolver>(
    keys: &[String],
    ctx_ns: &str,
    resolver: &mut R,
) -> BTreeMap<String, ResolveResult> {
    let mut unique: Vec<String> = keys.iter().map(|k| qualify(k, ctx_ns)).collect();
    unique.sort();
    unique.dedup();
    let mut map = BTreeMap::new();
    for key in unique {
        let r = resolver.resolve(&key);
        map.insert(key, r);
    }
    map
}

/// Render `template`'s references into bytes, given a resolution map (keyed by
/// **qualified** `NS/KEY`, see [`resolve_all`]), the mode, and the context
/// namespace (DR-0013 substring rule + DR-0015 dry-run masking + DR-0017 §3).
///
/// - **Reveal**: each reference is replaced by its resolved bytes. If any key
///   failed, returns `Err` listing the failures (fail-closed: the caller emits
///   nothing — DR-0013).
/// - **DryRun**: each reference is replaced by its mask
///   (`<cache-warden:NS/KEY:masked|failed>`). The mask always shows the
///   **resolved absolute key** — an unqualified reference is displayed as what
///   it resolved to, making the namespace resolution visible (DR-0017 §5).
///   Never fails-closed: the whole template is rendered, but failures are
///   collected so the caller can exit non-zero (DR-0015 §3).
///
/// The return carries the rendered bytes and the list of failed (qualified)
/// keys (empty on full success). `template` is bytes for binary safety;
/// references are located by scanning the raw bytes
/// ([`find_references_bytes`]).
pub fn render_template(
    template: &[u8],
    resolved: &BTreeMap<String, ResolveResult>,
    mode: Mode,
    ctx_ns: &str,
) -> Result<RenderedTemplate, Vec<String>> {
    // Locate references directly over the raw bytes (a lossy text view would
    // shift offsets on binary input — see [`find_references_bytes`]).
    let locs = find_references_bytes(template);

    let mut out: Vec<u8> = Vec::with_capacity(template.len());
    let mut cursor = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for loc in &locs {
        // Copy the literal bytes before this reference.
        out.extend_from_slice(&template[cursor..loc.start]);
        let qkey = qualify(&loc.key, ctx_ns);
        match resolved.get(&qkey) {
            Some(Ok(ResolvedValue::Value(bytes))) => {
                if mode.is_dry_run() {
                    // Defensive: a dry-run map should not carry values, but mask
                    // anyway so a value can never leak into a dry-run output.
                    out.extend_from_slice(mask(&qkey, true).as_bytes());
                } else {
                    out.extend_from_slice(bytes);
                }
            }
            Some(Ok(ResolvedValue::Verified)) => {
                out.extend_from_slice(mask(&qkey, true).as_bytes());
            }
            Some(Err(_)) | None => {
                failures.push(qkey.clone());
                if mode.is_dry_run() {
                    out.extend_from_slice(mask(&qkey, false).as_bytes());
                } else {
                    // Reveal: copy the original reference text so the failed
                    // span is identifiable, but we will fail-closed below.
                    out.extend_from_slice(&template[loc.start..loc.end]);
                }
            }
        }
        cursor = loc.end;
    }
    out.extend_from_slice(&template[cursor..]);

    if !mode.is_dry_run() && !failures.is_empty() {
        // Reveal fail-closed: do not hand back a partially-resolved output.
        failures.sort();
        failures.dedup();
        return Err(failures);
    }
    failures.sort();
    failures.dedup();
    Ok(RenderedTemplate {
        bytes: out,
        failures,
    })
}

/// The output of [`render_template`]: the rendered bytes plus the (possibly
/// empty) set of keys that failed (only non-empty in dry-run; reveal fails
/// closed via `Err`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedTemplate {
    /// The rendered bytes (real values in reveal, masks in dry-run).
    pub bytes: Vec<u8>,
    /// Keys that failed to resolve (dry-run only; sorted, deduped).
    pub failures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(bytes: &[u8]) -> ResolveResult {
        Ok(ResolvedValue::Value(bytes.to_vec()))
    }

    // ---- whole_value_key ----

    #[test]
    fn whole_value_key_matches_exact_reference() {
        assert_eq!(
            whole_value_key("cache-warden://DB_PASSWORD"),
            Some("DB_PASSWORD")
        );
        assert_eq!(whole_value_key("cache-warden://_x"), Some("_x"));
        // Qualified NS/KEY form (DR-0017 §3).
        assert_eq!(whole_value_key("cache-warden://projA/DB"), Some("projA/DB"));
    }

    #[test]
    fn whole_value_key_rejects_partial_or_surrounded() {
        assert_eq!(whole_value_key("prefix cache-warden://K"), None);
        assert_eq!(whole_value_key("cache-warden://K suffix"), None);
        assert_eq!(whole_value_key("cache-warden://"), None);
        assert_eq!(whole_value_key("literal"), None);
        // `.` / `-` are no longer key chars (DR-0017 §1.5).
        assert_eq!(whole_value_key("cache-warden://.bad"), None);
        assert_eq!(whole_value_key("cache-warden://-bad"), None);
        assert_eq!(whole_value_key("cache-warden://a.b"), None);
        assert_eq!(whole_value_key("cache-warden://a-b"), None);
        // Hierarchy / dangling slash are not whole-value references.
        assert_eq!(whole_value_key("cache-warden://a/b/c"), None);
        assert_eq!(whole_value_key("cache-warden://a/"), None);
        assert_eq!(whole_value_key("cache-warden:///k"), None);
    }

    // ---- find_references ----

    #[test]
    fn find_references_locates_each_span() {
        let s = "DSN=cache-warden://USER:cache-warden://PW@host";
        let locs = find_references(s);
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].key, "USER");
        assert_eq!(&s[locs[0].start..locs[0].end], "cache-warden://USER");
        assert_eq!(locs[1].key, "PW");
        assert_eq!(&s[locs[1].start..locs[1].end], "cache-warden://PW");
    }

    #[test]
    fn find_references_consumes_single_ns_qualifier() {
        // One NS segment is part of the reference (DR-0017 §3); a second `/`
        // ends it (single-segment NS).
        let locs = find_references("cache-warden://projA/DB/tail");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "projA/DB");

        // A trailing `/` without an identifier after it stays outside.
        let locs = find_references("cache-warden://KEY/ rest");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "KEY");
    }

    #[test]
    fn find_references_dash_terminates_key() {
        // `-` left the charset (DR-0017 §1.5): `PW-suffix` reads as key `PW`
        // followed by the literal `-suffix` (predictable termination).
        let locs = find_references("cache-warden://PW-suffix");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "PW");
    }

    #[test]
    fn find_references_ignores_scheme_without_key() {
        assert!(find_references("cache-warden:// not a ref").is_empty());
        assert!(find_references("cache-warden://").is_empty());
    }

    #[test]
    fn find_references_no_recursive_rescan() {
        // Single-pass: the first key run is consumed once. `Acache` ends at the
        // `-` (no longer a key char), and no second scheme exists after it.
        let locs = find_references("cache-warden://Acache-warden://B");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "Acache");
    }

    #[test]
    fn find_references_bytes_offsets_are_correct_on_binary() {
        // A lone 0xff before the reference must not shift the located offsets.
        let template = b"\xff\x00cache-warden://K\xfftail".to_vec();
        let locs = find_references_bytes(&template);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "K");
        assert_eq!(&template[locs[0].start..locs[0].end], b"cache-warden://K");
    }

    #[test]
    fn contains_reference_detects_embedded() {
        assert!(contains_reference("x cache-warden://K y"));
        assert!(!contains_reference("no refs here"));
        assert!(!contains_reference("cache-warden:// bare"));
    }

    // ---- mask ----

    #[test]
    fn mask_renders_masked_and_failed() {
        assert_eq!(mask("DB", true), "<cache-warden:DB:masked>");
        assert_eq!(mask("DB", false), "<cache-warden:DB:failed>");
    }

    // ---- resolve_all (dedup + qualification) ----

    #[test]
    fn resolve_all_resolves_each_key_once() {
        let keys = vec!["B".to_string(), "A".to_string(), "B".to_string()];
        let mut count = 0;
        let mut resolver = |k: &str| {
            count += 1;
            v(format!("val-{k}").as_bytes())
        };
        let map = resolve_all(&keys, "default", &mut resolver);
        assert_eq!(count, 2, "B is resolved once despite two references");
        assert_eq!(map.len(), 2);
        // The map is keyed by the qualified form; the resolver saw it too.
        assert_eq!(map["default/A"], v(b"val-default/A"));
        assert_eq!(map["default/B"], v(b"val-default/B"));
    }

    #[test]
    fn resolve_all_unqualified_and_qualified_same_key_dedup() {
        // `bar` under ctx `foo` and the explicit `foo/bar` are the same entry:
        // one resolution (DR-0017 §3).
        let keys = vec!["bar".to_string(), "foo/bar".to_string()];
        let mut count = 0;
        let mut resolver = |k: &str| {
            count += 1;
            v(format!("val-{k}").as_bytes())
        };
        let map = resolve_all(&keys, "foo", &mut resolver);
        assert_eq!(count, 1, "qualified and unqualified collapse to one");
        assert_eq!(map["foo/bar"], v(b"val-foo/bar"));
    }

    // ---- render_template: reveal ----

    #[test]
    fn render_reveal_substitutes_values() {
        let mut map = BTreeMap::new();
        map.insert("default/USER".to_string(), v(b"alice"));
        map.insert("default/PW".to_string(), v(b"s3cr3t"));
        let out = render_template(
            b"dsn=cache-warden://USER:cache-warden://PW@h",
            &map,
            Mode::Reveal,
            "default",
        )
        .unwrap();
        assert_eq!(out.bytes, b"dsn=alice:s3cr3t@h");
        assert!(out.failures.is_empty());
    }

    #[test]
    fn render_reveal_qualified_reference_is_absolute() {
        // A `hoge/fuga` reference resolves to hoge/fuga even under ctx `foo`.
        let mut map = BTreeMap::new();
        map.insert("hoge/fuga".to_string(), v(b"abs"));
        let out =
            render_template(b"x=cache-warden://hoge/fuga", &map, Mode::Reveal, "foo").unwrap();
        assert_eq!(out.bytes, b"x=abs");
    }

    #[test]
    fn render_reveal_is_binary_safe() {
        let mut map = BTreeMap::new();
        map.insert("default/K".to_string(), v(&[0u8, 159, 146, 150]));
        let template = b"\x00\xffcache-warden://K\x00".to_vec();
        let out = render_template(&template, &map, Mode::Reveal, "default").unwrap();
        assert_eq!(out.bytes, vec![0u8, 0xff, 0, 159, 146, 150, 0]);
    }

    #[test]
    fn render_reveal_fails_closed_on_any_failure() {
        let mut map = BTreeMap::new();
        map.insert("default/OK".to_string(), v(b"ok"));
        map.insert("default/BAD".to_string(), Err("not found".to_string()));
        let err = render_template(
            b"cache-warden://OK cache-warden://BAD",
            &map,
            Mode::Reveal,
            "default",
        )
        .unwrap_err();
        assert_eq!(err, vec!["default/BAD".to_string()]);
    }

    // ---- render_template: dry-run ----

    #[test]
    fn render_dry_run_masks_show_resolved_absolute_key() {
        // The mask displays the resolved absolute key, so an unqualified
        // reference shows what it resolved to (DR-0017 §5).
        let mut map = BTreeMap::new();
        map.insert("projA/OK".to_string(), Ok(ResolvedValue::Verified));
        map.insert("projA/BAD".to_string(), Err("nope".to_string()));
        let out = render_template(
            b"a=cache-warden://OK b=cache-warden://BAD",
            &map,
            Mode::DryRun,
            "projA",
        )
        .unwrap();
        assert_eq!(
            out.bytes,
            b"a=<cache-warden:projA/OK:masked> b=<cache-warden:projA/BAD:failed>"
        );
        assert_eq!(out.failures, vec!["projA/BAD".to_string()]);
    }

    #[test]
    fn render_dry_run_masks_even_if_a_value_leaked_into_map() {
        // Defense in depth: if a Value somehow appears in a dry-run map, it must
        // still be masked, never emitted.
        let mut map = BTreeMap::new();
        map.insert("default/K".to_string(), v(b"should-not-appear"));
        let out = render_template(b"cache-warden://K", &map, Mode::DryRun, "default").unwrap();
        assert_eq!(out.bytes, b"<cache-warden:default/K:masked>");
        assert!(!String::from_utf8_lossy(&out.bytes).contains("should-not-appear"));
    }
}
