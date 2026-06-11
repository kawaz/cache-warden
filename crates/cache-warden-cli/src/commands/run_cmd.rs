//! `cache-warden run`: resolve secret references in the environment, then exec
//! a command (DR-0013 run + DR-0015 dry-run).
//!
//! `run [--env NAME=VALUE]... [--defs FILE]... -- CMD [ARGS...]` builds the
//! child's environment from the inherited env plus `--env` overrides, resolves
//! every env value that is **entirely** a reference (whole-value rule, op-run
//! compatible), and `exec`s `CMD` so no parent lingers holding secrets. argv is
//! never an injection face: a reference-looking token in `ARGS` is passed
//! verbatim with one stderr warning (DR-0013). In reveal mode it is fail-closed
//! (no exec if any reference fails). In dry-run mode the env is filled with
//! masks and the child is still exec'd — unless a reference failed, in which
//! case it exits non-zero without exec'ing (so a failed verification is visible).

use std::path::PathBuf;

use crate::mode::Mode;
use crate::refs::{self, ResolvedValue, Resolver};

/// Parsed `run` arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// `--env NAME=VALUE` overrides, in order (later wins on duplicate NAME).
    pub envs: Vec<(String, String)>,
    /// `--defs FILE` definition files to register before resolving.
    pub defs: Vec<PathBuf>,
    /// The command argv after `--` (program first; never empty after parse).
    pub command: Vec<String>,
}

/// Parse `run`'s flags and the `-- CMD [ARGS...]` tail into [`RunArgs`].
///
/// The mode flags and `--socket` are removed by the caller before this runs.
/// Everything after the first `--` is the command, taken verbatim (so the child
/// may legitimately receive its own `--flags`). A missing `--` or an empty
/// command is a usage error.
pub fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut out = RunArgs::default();
    let mut i = 0;
    let mut saw_sep = false;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                out.command = args[i + 1..].to_vec();
                saw_sep = true;
                break;
            }
            "--env" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--env requires a NAME=VALUE argument")?;
                out.envs.push(parse_env_assignment(v)?);
                i += 2;
            }
            s if s.starts_with("--env=") => {
                out.envs
                    .push(parse_env_assignment(s.strip_prefix("--env=").unwrap())?);
                i += 1;
            }
            "--defs" => {
                let v = args.get(i + 1).ok_or("--defs requires a FILE argument")?;
                out.defs.push(PathBuf::from(v));
                i += 2;
            }
            s if s.starts_with("--defs=") => {
                out.defs
                    .push(PathBuf::from(s.strip_prefix("--defs=").unwrap()));
                i += 1;
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `run`: {s}"));
            }
            other => {
                return Err(format!(
                    "`run` requires `-- CMD [ARGS...]`; unexpected argument {other:?} before `--`"
                ));
            }
        }
    }
    if !saw_sep {
        return Err(
            "`run` requires a `--` separator before the command (run ... -- CMD)".to_string(),
        );
    }
    if out.command.is_empty() {
        return Err("`run` requires a command after `--` (run ... -- CMD [ARGS...])".to_string());
    }
    Ok(out)
}

/// Split one `NAME=VALUE` string. `NAME` must be non-empty and contain no `=`.
fn parse_env_assignment(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.to_string(), value.to_string())),
        _ => Err(format!("--env expects NAME=VALUE (got {s:?})")),
    }
}

/// The fully resolved child environment plus any argv warning, ready to exec.
#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedEnv {
    /// The complete `NAME=VALUE` environment for the child (whole-value
    /// references already substituted / masked).
    pub vars: Vec<(String, String)>,
    /// Keys that failed to resolve (non-empty only in dry-run; reveal fails via
    /// `Err`). The caller exits non-zero when this is non-empty.
    pub failures: Vec<String>,
}

/// Build the child environment by resolving whole-value references (DR-0013).
///
/// `inherited` is the parent env (typically `std::env::vars`), `overrides` are
/// the `--env` assignments (later entries win, and `--env` wins over inherited).
/// Only an env value that is **entirely** `cache-warden://KEY` is resolved;
/// every other value is passed through literally. In reveal mode a value
/// containing a NUL is rejected (env cannot carry NUL) and a failed reference
/// fails the whole call (fail-closed). In dry-run mode references become masks
/// and the call never fails-closed (failures are collected).
pub fn resolve_env<R: Resolver>(
    inherited: &[(String, String)],
    overrides: &[(String, String)],
    mode: Mode,
    resolver: &mut R,
) -> Result<ResolvedEnv, String> {
    // Merge inherited + overrides into a last-wins ordered list. `--env` after
    // inherited means an override replaces the inherited value for the same NAME
    // (DR-0013: `--env` wins over inherited).
    let mut merged: Vec<(String, String)> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (name, value) in inherited.iter().chain(overrides.iter()) {
        if let Some(&pos) = index.get(name) {
            merged[pos].1 = value.clone();
        } else {
            index.insert(name.clone(), merged.len());
            merged.push((name.clone(), value.clone()));
        }
    }

    // Collect the distinct keys that are whole-value references and resolve them
    // once each (dedup, DR-0013).
    let keys: Vec<String> = merged
        .iter()
        .filter_map(|(_, v)| refs::whole_value_key(v).map(|k| k.to_string()))
        .collect();
    let resolved = refs::resolve_all(&keys, resolver);

    let mut vars: Vec<(String, String)> = Vec::with_capacity(merged.len());
    let mut failures: Vec<String> = Vec::new();
    for (name, value) in merged {
        match refs::whole_value_key(&value) {
            None => vars.push((name, value)), // literal, pass through
            Some(key) => match resolved.get(key) {
                Some(Ok(ResolvedValue::Value(bytes))) if !mode.is_dry_run() => {
                    if bytes.contains(&0) {
                        return Err(format!(
                            "value for {name} (cache-warden://{key}) contains a NUL byte and cannot be placed in the environment"
                        ));
                    }
                    let s = String::from_utf8(bytes.clone()).map_err(|_| {
                        format!(
                            "value for {name} (cache-warden://{key}) is not valid UTF-8 and cannot be placed in the environment"
                        )
                    })?;
                    vars.push((name, s));
                }
                Some(Ok(ResolvedValue::Value(_))) | Some(Ok(ResolvedValue::Verified)) => {
                    // dry-run: mask regardless of whether a value leaked in.
                    vars.push((name, refs::mask(key, true)));
                }
                Some(Err(_)) | None => {
                    failures.push(key.to_string());
                    if mode.is_dry_run() {
                        vars.push((name, refs::mask(key, false)));
                    } else {
                        // reveal: keep the reference so the failing NAME is named
                        // in the fail-closed error below.
                        vars.push((name, value));
                    }
                }
            },
        }
    }

    if !mode.is_dry_run() && !failures.is_empty() {
        failures.sort();
        failures.dedup();
        return Err(format!(
            "{} reference(s) failed to resolve: {}",
            failures.len(),
            failures.join(", ")
        ));
    }
    failures.sort();
    failures.dedup();
    Ok(ResolvedEnv { vars, failures })
}

/// Detect reference-looking tokens in the command argv (DR-0013): argv is not an
/// injection face, so such a token is passed verbatim but warrants one warning.
/// Returns the offending tokens (empty when none).
pub fn argv_reference_tokens(command: &[String]) -> Vec<String> {
    command
        .iter()
        .filter(|a| refs::contains_reference(a))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::{ResolveResult, ResolvedValue};

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    fn ok(bytes: &[u8]) -> ResolveResult {
        Ok(ResolvedValue::Value(bytes.to_vec()))
    }

    // ---- parse_run ----

    #[test]
    fn parse_run_splits_flags_and_command() {
        let a = parse_run(&s(&[
            "--env", "FOO=bar", "--defs", "d.toml", "--", "echo", "hi", "--x",
        ]))
        .unwrap();
        assert_eq!(a.envs, vec![("FOO".to_string(), "bar".to_string())]);
        assert_eq!(a.defs, vec![PathBuf::from("d.toml")]);
        assert_eq!(a.command, s(&["echo", "hi", "--x"]));
    }

    #[test]
    fn parse_run_requires_separator_and_command() {
        assert!(parse_run(&s(&["echo"])).is_err()); // no `--`
        assert!(parse_run(&s(&["--"])).is_err()); // empty command
        assert!(parse_run(&s(&["--env", "A=b"])).is_err()); // no `--`
    }

    #[test]
    fn parse_run_env_equals_form() {
        let a = parse_run(&s(&["--env=A=b", "--", "true"])).unwrap();
        assert_eq!(a.envs, vec![("A".to_string(), "b".to_string())]);
    }

    #[test]
    fn parse_run_rejects_bad_env() {
        assert!(parse_run(&s(&["--env", "noequals", "--", "true"])).is_err());
        assert!(parse_run(&s(&["--env", "=novalue", "--", "true"])).is_err());
    }

    #[test]
    fn parse_run_value_after_sep_is_verbatim() {
        // A reference-looking token after `--` is kept verbatim (the warning is
        // emitted at run time, not parse time).
        let a = parse_run(&s(&["--", "prog", "cache-warden://X"])).unwrap();
        assert_eq!(a.command, s(&["prog", "cache-warden://X"]));
    }

    // ---- resolve_env ----

    #[test]
    fn resolve_env_substitutes_whole_value_only() {
        let inherited = vec![
            ("DB".to_string(), "cache-warden://DB_PW".to_string()),
            ("MIX".to_string(), "x cache-warden://NO y".to_string()),
            ("LIT".to_string(), "literal".to_string()),
        ];
        let mut resolver = |k: &str| ok(format!("secret-{k}").as_bytes());
        let r = resolve_env(&inherited, &[], Mode::Reveal, &mut resolver).unwrap();
        let map: std::collections::HashMap<_, _> = r.vars.into_iter().collect();
        assert_eq!(map["DB"], "secret-DB_PW");
        // Embedded reference is NOT substituted (whole-value rule).
        assert_eq!(map["MIX"], "x cache-warden://NO y");
        assert_eq!(map["LIT"], "literal");
    }

    #[test]
    fn resolve_env_override_wins_over_inherited() {
        let inherited = vec![("TOK".to_string(), "inherited".to_string())];
        let overrides = vec![("TOK".to_string(), "cache-warden://TOK".to_string())];
        let mut resolver = |_k: &str| ok(b"from-ref");
        let r = resolve_env(&inherited, &overrides, Mode::Reveal, &mut resolver).unwrap();
        let map: std::collections::HashMap<_, _> = r.vars.into_iter().collect();
        assert_eq!(map["TOK"], "from-ref");
        // Only one TOK in the output.
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn resolve_env_dedupes_repeated_keys() {
        let inherited = vec![
            ("A".to_string(), "cache-warden://K".to_string()),
            ("B".to_string(), "cache-warden://K".to_string()),
        ];
        let mut count = 0;
        let mut resolver = |_k: &str| {
            count += 1;
            ok(b"v")
        };
        resolve_env(&inherited, &[], Mode::Reveal, &mut resolver).unwrap();
        assert_eq!(count, 1, "K resolved once for both A and B");
    }

    #[test]
    fn resolve_env_reveal_fails_closed_on_failure() {
        let inherited = vec![("A".to_string(), "cache-warden://BAD".to_string())];
        let mut resolver = |_k: &str| -> ResolveResult { Err("no".into()) };
        let err = resolve_env(&inherited, &[], Mode::Reveal, &mut resolver).unwrap_err();
        assert!(err.contains("BAD"), "err: {err}");
    }

    #[test]
    fn resolve_env_rejects_nul_in_value() {
        let inherited = vec![("A".to_string(), "cache-warden://K".to_string())];
        let mut resolver = |_k: &str| ok(b"a\0b");
        let err = resolve_env(&inherited, &[], Mode::Reveal, &mut resolver).unwrap_err();
        assert!(err.contains("NUL"), "err: {err}");
    }

    #[test]
    fn resolve_env_dry_run_masks_and_collects_failures() {
        let inherited = vec![
            ("OK".to_string(), "cache-warden://OK".to_string()),
            ("BAD".to_string(), "cache-warden://BAD".to_string()),
        ];
        let mut resolver = |k: &str| -> ResolveResult {
            if k == "BAD" {
                Err("no".into())
            } else {
                Ok(ResolvedValue::Verified)
            }
        };
        let r = resolve_env(&inherited, &[], Mode::DryRun, &mut resolver).unwrap();
        let map: std::collections::HashMap<_, _> = r.vars.clone().into_iter().collect();
        assert_eq!(map["OK"], "<cache-warden:OK:masked>");
        assert_eq!(map["BAD"], "<cache-warden:BAD:failed>");
        assert_eq!(r.failures, vec!["BAD".to_string()]);
    }

    // ---- argv_reference_tokens ----

    #[test]
    fn argv_reference_tokens_flags_offending_args() {
        let cmd = s(&["prog", "cache-warden://X", "plain", "a=cache-warden://Y"]);
        let toks = argv_reference_tokens(&cmd);
        assert_eq!(toks, s(&["cache-warden://X", "a=cache-warden://Y"]));
    }

    #[test]
    fn argv_reference_tokens_none_when_clean() {
        assert!(argv_reference_tokens(&s(&["echo", "hello"])).is_empty());
    }
}
