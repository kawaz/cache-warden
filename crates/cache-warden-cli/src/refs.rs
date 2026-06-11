//! Secret reference syntax and resolution shared by `run` and `inject`
//! (DR-0013 / DR-0015).
//!
//! A reference is `cache-warden://KEY` where `KEY` matches
//! `[A-Za-z0-9_][A-Za-z0-9_.-]*` (env-variable-ish names; the leading char is an
//! alphanumeric or `_`). The scheme is the only one accepted — there are no
//! short aliases (DR-0013). Resolution is a **single pass**: a resolved value is
//! treated as opaque bytes and never re-scanned for further references (no
//! recursive expansion, DR-0013).
//!
//! This module is pure: it detects references, decides whole-value matches (the
//! `run` env rule), performs substring replacement (the `inject` rule), builds
//! masked placeholders (dry-run), and de-duplicates keys — all without touching
//! a socket. The caller injects a resolver closure, so the same logic is unit
//! tested with a fake resolver and reused with the real control-socket client.

use std::collections::BTreeMap;

use crate::mode::Mode;

/// The reference scheme prefix.
pub const SCHEME: &str = "cache-warden://";

/// `true` if `c` may start a reference key (`[A-Za-z0-9_]`).
fn is_key_start(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `true` if `c` may continue a reference key (`[A-Za-z0-9_.-]`).
fn is_key_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// If `s` is *exactly* one reference (`cache-warden://KEY` and nothing else),
/// return the KEY. Used for the `run` env whole-value rule (DR-0013): only an
/// env value that is entirely a reference is resolved.
pub fn whole_value_key(s: &str) -> Option<&str> {
    let rest = s.strip_prefix(SCHEME)?;
    if rest.is_empty() {
        return None;
    }
    let mut chars = rest.chars();
    let first = chars.next()?;
    if !is_key_start(first) {
        return None;
    }
    if chars.all(is_key_continue) {
        Some(rest)
    } else {
        None
    }
}

/// `true` if `s` merely *contains* a reference substring (used for the argv
/// warning in `run`: a reference-looking token in argv is passed verbatim but
/// warned about, since argv is not an injection face).
pub fn contains_reference(s: &str) -> bool {
    find_references(s).into_iter().next().is_some()
}

/// One located reference within a byte template: its key and byte span
/// `[start, end)` (the span covers the whole `cache-warden://KEY` text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The reference key.
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
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with(SCHEME) {
            let key_start = i + SCHEME.len();
            // Consume a maximal valid key.
            let tail = &s[key_start..];
            let mut chars = tail.char_indices();
            let mut end_rel = match chars.next() {
                Some((_, c)) if is_key_start(c) => c.len_utf8(),
                _ => {
                    // `cache-warden://` not followed by a valid key char: not a
                    // reference. Advance past the scheme to avoid rescanning it.
                    i = key_start;
                    continue;
                }
            };
            for (idx, c) in chars {
                if is_key_continue(c) {
                    end_rel = idx + c.len_utf8();
                } else {
                    break;
                }
            }
            let end = key_start + end_rel;
            out.push(Located {
                key: s[key_start..end].to_string(),
                start: i,
                end,
            });
            i = end;
        } else {
            // Advance by one UTF-8 char.
            let step = s[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            i += step;
        }
    }
    out
}

/// Find every reference directly over a raw byte template, left to right,
/// non-overlapping. Unlike [`find_references`] (which works on a `str`), this
/// scans bytes so it is correct on **binary** input: a lossy UTF-8 conversion
/// would shift offsets (a stray `0xff` becomes a 3-byte replacement char), so
/// byte offsets from a lossy view do not map back to the original template.
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
            let mut j = key_start;
            // First key char must be a start char.
            if j < template.len() && is_key_start(template[j] as char) {
                j += 1;
                while j < template.len() && is_key_continue(template[j] as char) {
                    j += 1;
                }
                out.push(Located {
                    key: String::from_utf8_lossy(&template[key_start..j]).into_owned(),
                    start: i,
                    end: j,
                });
                i = j;
            } else {
                // Scheme not followed by a valid key char: skip past the scheme.
                i = key_start;
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

/// Resolve a set of keys exactly once each (dedup), returning a key→result map.
///
/// Each distinct key is resolved a single time even if referenced many times
/// (DR-0013: avoid repeated TouchID prompts). The order of resolution is the
/// sorted key order (deterministic); the `BTreeMap` return is keyed by name.
pub fn resolve_all<R: Resolver>(
    keys: &[String],
    resolver: &mut R,
) -> BTreeMap<String, ResolveResult> {
    let mut unique: Vec<&String> = keys.iter().collect();
    unique.sort();
    unique.dedup();
    let mut map = BTreeMap::new();
    for key in unique {
        let r = resolver.resolve(key);
        map.insert(key.clone(), r);
    }
    map
}

/// Render `template`'s references into bytes, given a resolution map and a mode
/// (DR-0013 substring rule + DR-0015 dry-run masking).
///
/// - **Reveal**: each reference is replaced by its resolved bytes. If any key
///   failed, returns `Err` listing the failures (fail-closed: the caller emits
///   nothing — DR-0013).
/// - **DryRun**: each reference is replaced by its mask
///   (`<cache-warden:KEY:masked|failed>`). Never fails-closed: the whole
///   template is rendered, but `failed` is `true` if any key failed so the
///   caller can exit non-zero (DR-0015 §3).
///
/// The return carries the rendered bytes and the list of failed keys (empty on
/// full success). `template` is bytes for binary safety; references are located
/// by scanning the raw bytes ([`find_references_bytes`]).
pub fn render_template(
    template: &[u8],
    resolved: &BTreeMap<String, ResolveResult>,
    mode: Mode,
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
        match resolved.get(&loc.key) {
            Some(Ok(ResolvedValue::Value(bytes))) => {
                if mode.is_dry_run() {
                    // Defensive: a dry-run map should not carry values, but mask
                    // anyway so a value can never leak into a dry-run output.
                    out.extend_from_slice(mask(&loc.key, true).as_bytes());
                } else {
                    out.extend_from_slice(bytes);
                }
            }
            Some(Ok(ResolvedValue::Verified)) => {
                out.extend_from_slice(mask(&loc.key, true).as_bytes());
            }
            Some(Err(_)) | None => {
                failures.push(loc.key.clone());
                if mode.is_dry_run() {
                    out.extend_from_slice(mask(&loc.key, false).as_bytes());
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
        assert_eq!(whole_value_key("cache-warden://a.b-c_1"), Some("a.b-c_1"));
        assert_eq!(whole_value_key("cache-warden://_x"), Some("_x"));
    }

    #[test]
    fn whole_value_key_rejects_partial_or_surrounded() {
        assert_eq!(whole_value_key("prefix cache-warden://K"), None);
        assert_eq!(whole_value_key("cache-warden://K suffix"), None);
        assert_eq!(whole_value_key("cache-warden://"), None);
        assert_eq!(whole_value_key("literal"), None);
        // A leading `.` / `-` is not a valid key start.
        assert_eq!(whole_value_key("cache-warden://.bad"), None);
        assert_eq!(whole_value_key("cache-warden://-bad"), None);
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
    fn find_references_stops_key_at_first_invalid_char() {
        // `/` after the key ends it (it's not in the key charset).
        let locs = find_references("cache-warden://A/b");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "A");
    }

    #[test]
    fn find_references_ignores_scheme_without_key() {
        assert!(find_references("cache-warden:// not a ref").is_empty());
        assert!(find_references("cache-warden://").is_empty());
    }

    #[test]
    fn find_references_no_recursive_rescan() {
        // A key char run is consumed once; the result does not re-find a nested
        // scheme inside an already-consumed key (there is none here, but assert
        // single-pass behavior on adjacent refs).
        let locs = find_references("cache-warden://Acache-warden://B");
        // The first key greedily consumes letters; `:` ends it, but `cache-warden`
        // chars are valid key chars, so the whole run up to `:` is one key.
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].key, "Acache-warden");
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

    // ---- resolve_all (dedup) ----

    #[test]
    fn resolve_all_resolves_each_key_once() {
        let keys = vec!["B".to_string(), "A".to_string(), "B".to_string()];
        let mut count = 0;
        let mut resolver = |k: &str| {
            count += 1;
            v(format!("val-{k}").as_bytes())
        };
        let map = resolve_all(&keys, &mut resolver);
        assert_eq!(count, 2, "B is resolved once despite two references");
        assert_eq!(map.len(), 2);
        assert_eq!(map["A"], v(b"val-A"));
        assert_eq!(map["B"], v(b"val-B"));
    }

    // ---- render_template: reveal ----

    #[test]
    fn render_reveal_substitutes_values() {
        let mut map = BTreeMap::new();
        map.insert("USER".to_string(), v(b"alice"));
        map.insert("PW".to_string(), v(b"s3cr3t"));
        let out = render_template(
            b"dsn=cache-warden://USER:cache-warden://PW@h",
            &map,
            Mode::Reveal,
        )
        .unwrap();
        assert_eq!(out.bytes, b"dsn=alice:s3cr3t@h");
        assert!(out.failures.is_empty());
    }

    #[test]
    fn render_reveal_is_binary_safe() {
        let mut map = BTreeMap::new();
        map.insert("K".to_string(), v(&[0u8, 159, 146, 150]));
        let template = b"\x00\xffcache-warden://K\x00".to_vec();
        let out = render_template(&template, &map, Mode::Reveal).unwrap();
        assert_eq!(out.bytes, vec![0u8, 0xff, 0, 159, 146, 150, 0]);
    }

    #[test]
    fn render_reveal_fails_closed_on_any_failure() {
        let mut map = BTreeMap::new();
        map.insert("OK".to_string(), v(b"ok"));
        map.insert("BAD".to_string(), Err("not found".to_string()));
        let err = render_template(b"cache-warden://OK cache-warden://BAD", &map, Mode::Reveal)
            .unwrap_err();
        assert_eq!(err, vec!["BAD".to_string()]);
    }

    // ---- render_template: dry-run ----

    #[test]
    fn render_dry_run_masks_all_and_never_fails_closed() {
        let mut map = BTreeMap::new();
        map.insert("OK".to_string(), Ok(ResolvedValue::Verified));
        map.insert("BAD".to_string(), Err("nope".to_string()));
        let out = render_template(
            b"a=cache-warden://OK b=cache-warden://BAD",
            &map,
            Mode::DryRun,
        )
        .unwrap();
        assert_eq!(
            out.bytes,
            b"a=<cache-warden:OK:masked> b=<cache-warden:BAD:failed>"
        );
        assert_eq!(out.failures, vec!["BAD".to_string()]);
    }

    #[test]
    fn render_dry_run_masks_even_if_a_value_leaked_into_map() {
        // Defense in depth: if a Value somehow appears in a dry-run map, it must
        // still be masked, never emitted.
        let mut map = BTreeMap::new();
        map.insert("K".to_string(), v(b"should-not-appear"));
        let out = render_template(b"cache-warden://K", &map, Mode::DryRun).unwrap();
        assert_eq!(out.bytes, b"<cache-warden:K:masked>");
        assert!(!String::from_utf8_lossy(&out.bytes).contains("should-not-appear"));
    }
}
