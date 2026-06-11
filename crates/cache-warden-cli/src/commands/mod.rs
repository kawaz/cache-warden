//! CLI subcommands: the daemon group (`daemon run`) and the management client
//! (`kv`, `status`, `ping`).
//!
//! Argument parsing is hand-rolled (DR-0002 keeps the dependency surface small;
//! no clap). The parse step is a pure function ([`parse_kv_set`] etc. and the
//! socket resolver) so it can be unit-tested without touching a socket.

pub mod client;
pub mod config_cmd;
pub mod daemon_cmd;
pub mod inject_cmd;
pub mod run_cmd;

use std::path::PathBuf;

use crate::protocol::wire::{Request, SetSource, ValueMetaWire};
use crate::protocol::{decode_b64, encode_b64, parse_duration};
use crate::totp::OtpAlgorithm;

/// Extract the value-type flags (`--type` and the `--otp-*` parameters) from
/// `args`, returning the resulting [`ValueMetaWire`] and the remaining args with
/// those flags removed (DR-0016 §1). Shared by `kv set` and `kv define`.
///
/// - `--type otp` selects the OTP value type (the only type today). Any other
///   `--type` value is rejected.
/// - `--otp-digits N` / `--otp-period DUR-ish-seconds` / `--otp-algorithm
///   sha1|sha256|sha512` set the otp parameters. They are only meaningful with
///   `--type otp`; using one without it is an error (a silent no-op would hide a
///   mistake). The parameters are carried as opaque strings — the daemon's
///   handler layer interprets them, not the core.
/// - `--otp-algorithm` is validated here so a typo fails at the CLI.
pub fn take_otp_flags(args: &[String]) -> Result<(ValueMetaWire, Vec<String>), String> {
    let mut type_label: Option<String> = None;
    let mut digits: Option<String> = None;
    let mut period: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut rest = Vec::new();

    // Helper: read the value for a flag given either `--flag VALUE` or
    // `--flag=VALUE`, advancing the index appropriately.
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let take = |inline: Option<&str>, name: &str| -> Result<String, String> {
            match inline {
                Some(v) => Ok(v.to_string()),
                None => args
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| format!("{name} requires an argument")),
            }
        };
        if a == "--type" || a.starts_with("--type=") {
            let inline = a.strip_prefix("--type=");
            let v = take(inline, "--type")?;
            type_label = Some(v);
            i += if inline.is_some() { 1 } else { 2 };
        } else if a == "--otp-digits" || a.starts_with("--otp-digits=") {
            let inline = a.strip_prefix("--otp-digits=");
            digits = Some(take(inline, "--otp-digits")?);
            i += if inline.is_some() { 1 } else { 2 };
        } else if a == "--otp-period" || a.starts_with("--otp-period=") {
            let inline = a.strip_prefix("--otp-period=");
            period = Some(take(inline, "--otp-period")?);
            i += if inline.is_some() { 1 } else { 2 };
        } else if a == "--otp-algorithm" || a.starts_with("--otp-algorithm=") {
            let inline = a.strip_prefix("--otp-algorithm=");
            algorithm = Some(take(inline, "--otp-algorithm")?);
            i += if inline.is_some() { 1 } else { 2 };
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }

    // Validate the chosen type. Only `otp` exists today.
    let has_otp_params = digits.is_some() || period.is_some() || algorithm.is_some();
    match type_label.as_deref() {
        None => {
            if has_otp_params {
                return Err(
                    "--otp-digits / --otp-period / --otp-algorithm require `--type otp`"
                        .to_string(),
                );
            }
            Ok((ValueMetaWire::default(), rest))
        }
        Some("otp") => {
            // Validate the numeric / algorithm params at the CLI so a typo fails
            // here rather than reaching the daemon.
            if let Some(d) = &digits {
                let n: u32 = d
                    .parse()
                    .map_err(|_| format!("--otp-digits must be a number, got {d:?}"))?;
                if !(1..=9).contains(&n) {
                    return Err(format!("--otp-digits must be between 1 and 9, got {n}"));
                }
            }
            if let Some(pp) = &period {
                let n: u64 = pp
                    .parse()
                    .map_err(|_| format!("--otp-period must be a number of seconds, got {pp:?}"))?;
                if n == 0 {
                    return Err("--otp-period must be greater than zero".to_string());
                }
            }
            if let Some(al) = &algorithm {
                // Validates and normalizes (lowercases) the label.
                OtpAlgorithm::parse(al).map_err(|e| e.to_string())?;
            }
            let mut params = std::collections::BTreeMap::new();
            if let Some(d) = digits {
                params.insert("digits".to_string(), d);
            }
            if let Some(pp) = period {
                params.insert("period".to_string(), pp);
            }
            if let Some(al) = algorithm {
                // Store the normalized lowercase label.
                params.insert(
                    "algorithm".to_string(),
                    OtpAlgorithm::parse(&al).unwrap().label().to_string(),
                );
            }
            Ok((
                ValueMetaWire {
                    type_label: Some("otp".to_string()),
                    params,
                },
                rest,
            ))
        }
        Some(other) => Err(format!(
            "unknown --type {other:?} (the only value type is `otp`)"
        )),
    }
}

/// Default control socket path: `$XDG_STATE_HOME/cache-warden/control.sock`,
/// falling back to `~/.local/state/cache-warden/control.sock`.
pub fn default_socket_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".local/state")
        });
    base.join("cache-warden").join("control.sock")
}

/// Extract `--socket PATH` (or `--socket=PATH`) from `args`, returning the
/// explicitly-requested socket path (if the flag was given) and the remaining
/// args with the flag removed.
///
/// Returning `Option` (rather than eagerly falling back to the default) lets the
/// caller apply the full precedence chain — CLI `--socket` > `[daemon].socket`
/// in config > the built-in default (DR-0010). See [`resolve_socket`].
pub fn take_socket_flag(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>), String> {
    let mut socket: Option<PathBuf> = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--socket" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| "--socket requires a PATH argument".to_string())?;
            socket = Some(PathBuf::from(v));
            i += 2;
        } else if let Some(v) = a.strip_prefix("--socket=") {
            socket = Some(PathBuf::from(v));
            i += 1;
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    Ok((socket, rest))
}

/// Resolve the control socket path by precedence (DR-0010):
///
/// 1. `cli_socket` — an explicit `--socket PATH` (highest priority).
/// 2. `config_socket` — `[daemon].socket` from the config file.
/// 3. [`default_socket_path`] — `$XDG_STATE_HOME/cache-warden/control.sock`
///    (with the `~/.local/state` fallback).
pub fn resolve_socket(cli_socket: Option<PathBuf>, config_socket: Option<PathBuf>) -> PathBuf {
    cli_socket
        .or(config_socket)
        .unwrap_or_else(default_socket_path)
}

/// Parse the arguments to `kv set <KEY> ...` into a [`Request::KvSet`].
///
/// Grammar (static-only since DR-0014):
/// `<KEY> (--value V | --value-stdin) [--soft-ttl D] [--hard-ttl D]`
///
/// `stdin` provides the bytes for `--value-stdin`; it is read only when that
/// flag is present (kept as a parameter so the parse is testable). Command
/// sources moved to `kv define` (see [`parse_kv_define`]).
pub fn parse_kv_set(
    args: &[String],
    stdin: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> Result<Request, String> {
    // Pull out the value-type flags first (DR-0016); the rest is the existing
    // static-set grammar.
    let (meta, args) = take_otp_flags(args)?;
    let args = args.as_slice();

    let mut key: Option<String> = None;
    let mut value: Option<Vec<u8>> = None;
    let mut value_stdin = false;
    let mut soft_ttl_secs: Option<u64> = None;
    let mut hard_ttl_secs: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--value" => {
                let v = args.get(i + 1).ok_or("--value requires an argument")?;
                value = Some(v.clone().into_bytes());
                i += 2;
            }
            s if s.starts_with("--value=") => {
                value = Some(s.strip_prefix("--value=").unwrap().as_bytes().to_vec());
                i += 1;
            }
            "--value-stdin" => {
                value_stdin = true;
                i += 1;
            }
            "--soft-ttl" => {
                let v = args.get(i + 1).ok_or("--soft-ttl requires an argument")?;
                soft_ttl_secs = Some(parse_duration(v).map_err(|e| e.to_string())?.as_secs());
                i += 2;
            }
            s if s.starts_with("--soft-ttl=") => {
                soft_ttl_secs = Some(
                    parse_duration(s.strip_prefix("--soft-ttl=").unwrap())
                        .map_err(|e| e.to_string())?
                        .as_secs(),
                );
                i += 1;
            }
            "--hard-ttl" => {
                let v = args.get(i + 1).ok_or("--hard-ttl requires an argument")?;
                hard_ttl_secs = Some(parse_duration(v).map_err(|e| e.to_string())?.as_secs());
                i += 2;
            }
            s if s.starts_with("--hard-ttl=") => {
                hard_ttl_secs = Some(
                    parse_duration(s.strip_prefix("--hard-ttl=").unwrap())
                        .map_err(|e| e.to_string())?
                        .as_secs(),
                );
                i += 1;
            }
            "--command" => {
                return Err(
                    "`--command` was removed from `kv set`; use `kv define KEY --command ...`"
                        .to_string(),
                );
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv set`: {s}"));
            }
            other => {
                if key.is_none() {
                    key = Some(other.to_string());
                    i += 1;
                } else {
                    return Err(format!("unexpected argument: {other}"));
                }
            }
        }
    }

    let key = key.ok_or("kv set requires a KEY")?;

    // Exactly one value source must be chosen.
    let chosen = [value.is_some(), value_stdin]
        .iter()
        .filter(|b| **b)
        .count();
    if chosen == 0 {
        return Err("kv set requires one of --value or --value-stdin".to_string());
    }
    if chosen > 1 {
        return Err("kv set accepts only one of --value, --value-stdin".to_string());
    }

    let bytes = if value_stdin {
        stdin().map_err(|e| format!("failed to read stdin: {e}"))?
    } else {
        value.unwrap()
    };
    let source = SetSource::Static {
        value_b64: encode_b64(&bytes),
    };

    Ok(Request::KvSet {
        key,
        source,
        soft_ttl_secs,
        hard_ttl_secs,
        meta,
    })
}

/// Expand a `--source URI` into a command argv (DR-0014 §3).
///
/// Only `op://` is built in: it maps to `["op", "read", "<URI>"]`. Any other
/// scheme is an "unsupported source scheme" error. (Future vendor schemes are a
/// config-driven follow-up; the table lives outside the core.)
pub fn expand_source_uri(uri: &str) -> Result<Vec<String>, String> {
    if uri.starts_with("op://") {
        Ok(vec!["op".to_string(), "read".to_string(), uri.to_string()])
    } else {
        let scheme = uri.split("://").next().unwrap_or(uri);
        Err(format!(
            "unsupported source scheme `{scheme}` in --source {uri:?} (only op:// is built in)"
        ))
    }
}

/// Parse the arguments to `kv define <KEY> ...` into a [`Request::KvDefine`].
///
/// Grammar (DR-0014 §1):
/// `<KEY> (--command ARGV... | --source URI) [--soft-ttl D] [--hard-ttl D]`
///
/// `--command` and `--source` are mutually exclusive and exactly one is
/// required. A `--source op://...` URI is expanded into `["op", "read", URI]`
/// at parse time (see [`expand_source_uri`]); the daemon only ever sees argv.
pub fn parse_kv_define(args: &[String]) -> Result<Request, String> {
    // Pull the value-type flags from the part *before* `--command` (everything
    // after `--command` is the literal argv and must not be scanned for our
    // flags). `--source` is a single token so it is safe to scan the whole arg
    // list when there is no `--command`.
    let cmd_pos = args.iter().position(|a| a == "--command");
    let (head, tail): (&[String], &[String]) = match cmd_pos {
        Some(p) => (&args[..p], &args[p..]),
        None => (args, &[]),
    };
    let (meta, head_rest) = take_otp_flags(head)?;
    // Reassemble: the otp-stripped head, then the untouched `--command ...` tail.
    let mut reassembled: Vec<String> = head_rest;
    reassembled.extend_from_slice(tail);
    let args = reassembled.as_slice();

    let mut key: Option<String> = None;
    let mut command: Option<Vec<String>> = None;
    let mut source: Option<Vec<String>> = None;
    let mut soft_ttl_secs: Option<u64> = None;
    let mut hard_ttl_secs: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--command" => {
                // Everything after --command is the argv (consumes the rest).
                let argv: Vec<String> = args[i + 1..].to_vec();
                if argv.is_empty() {
                    return Err("--command requires at least a program".to_string());
                }
                command = Some(argv);
                i = args.len();
            }
            "--source" => {
                let v = args.get(i + 1).ok_or("--source requires a URI argument")?;
                source = Some(expand_source_uri(v)?);
                i += 2;
            }
            s if s.starts_with("--source=") => {
                source = Some(expand_source_uri(s.strip_prefix("--source=").unwrap())?);
                i += 1;
            }
            "--soft-ttl" => {
                let v = args.get(i + 1).ok_or("--soft-ttl requires an argument")?;
                soft_ttl_secs = Some(parse_duration(v).map_err(|e| e.to_string())?.as_secs());
                i += 2;
            }
            s if s.starts_with("--soft-ttl=") => {
                soft_ttl_secs = Some(
                    parse_duration(s.strip_prefix("--soft-ttl=").unwrap())
                        .map_err(|e| e.to_string())?
                        .as_secs(),
                );
                i += 1;
            }
            "--hard-ttl" => {
                let v = args.get(i + 1).ok_or("--hard-ttl requires an argument")?;
                hard_ttl_secs = Some(parse_duration(v).map_err(|e| e.to_string())?.as_secs());
                i += 2;
            }
            s if s.starts_with("--hard-ttl=") => {
                hard_ttl_secs = Some(
                    parse_duration(s.strip_prefix("--hard-ttl=").unwrap())
                        .map_err(|e| e.to_string())?
                        .as_secs(),
                );
                i += 1;
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv define`: {s}"));
            }
            other => {
                if key.is_none() {
                    key = Some(other.to_string());
                    i += 1;
                } else {
                    return Err(format!("unexpected argument: {other}"));
                }
            }
        }
    }

    let key = key.ok_or("kv define requires a KEY")?;

    let argv = match (command, source) {
        (Some(_), Some(_)) => {
            return Err("kv define accepts only one of --command or --source".to_string());
        }
        (Some(argv), None) | (None, Some(argv)) => argv,
        (None, None) => {
            return Err("kv define requires one of --command ARGV... or --source URI".to_string());
        }
    };

    // DR-0016 §5: `--type otp` with an `op://...?attribute=otp` source is a
    // structural error — `?attribute=otp` makes op compute a 30s code, so caching
    // it (a TTL'd, already-dead value) and then deriving from it is doubly wrong.
    // An otp seed must point at the seed field (plain `op://vault/item/field`).
    if crate::otp_type::is_otp(&meta)
        && argv
            .iter()
            .any(|a| a.to_ascii_lowercase().contains("attribute=otp"))
    {
        return Err(
            "`--type otp` with an `?attribute=otp` source is invalid: that returns a \
             computed 30s code, not the seed. Point the source at the seed field \
             (plain op://vault/item/field) instead"
                .to_string(),
        );
    }

    Ok(Request::KvDefine {
        key,
        argv,
        soft_ttl_secs,
        hard_ttl_secs,
        meta,
    })
}

/// The two shapes of a `kv define` invocation (DR-0014 §1 / §4).
///
/// Either a **single** definition (`<KEY> --command ... | --source URI`) or a
/// **batch** of definition files (`--defs FILE` repeatable). The two are
/// mutually exclusive: a `--defs` cannot be mixed with `--command` / `--source`
/// / a positional KEY (one form registers one key, the other registers a file's
/// worth at once).
#[derive(Debug, PartialEq, Eq)]
pub enum DefinePlan {
    /// One definition, built into a ready-to-send request.
    Single(Request),
    /// One or more defs files to load and register in bulk (DR-0014 §4).
    Defs(Vec<PathBuf>),
}

/// Parse the arguments to `kv define ...` into a [`DefinePlan`].
///
/// Grammar:
/// - single: `<KEY> (--command ARGV... | --source URI) [--soft-ttl D] [--hard-ttl D]`
/// - batch:  `--defs FILE [--defs FILE]...`
///
/// `--defs` is repeatable and never mixes with the single-definition flags
/// (`--command` / `--source` / a positional KEY): the two are different modes
/// (DR-0014 §4). There is no automatic discovery — only the explicit files
/// given here are loaded.
pub fn parse_kv_define_plan(args: &[String]) -> Result<DefinePlan, String> {
    // Detect the batch mode by the presence of any `--defs` flag, then collect
    // every `--defs FILE` while rejecting any single-definition flag / KEY mixed
    // in (so the user gets a clear "pick one mode" error, not a half-applied
    // command).
    let uses_defs = args
        .iter()
        .any(|a| a == "--defs" || a.starts_with("--defs="));
    if !uses_defs {
        return parse_kv_define(args).map(DefinePlan::Single);
    }

    let mut files: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--defs" => {
                let v = args.get(i + 1).ok_or("--defs requires a FILE argument")?;
                files.push(PathBuf::from(v));
                i += 2;
            }
            s if s.starts_with("--defs=") => {
                files.push(PathBuf::from(s.strip_prefix("--defs=").unwrap()));
                i += 1;
            }
            "--command" | "--source" => {
                return Err(
                    "`kv define --defs FILE` registers a whole file at once; it cannot be \
                     combined with --command / --source (use one or the other)"
                        .to_string(),
                );
            }
            s if s.starts_with("--source=") => {
                return Err(
                    "`kv define --defs FILE` cannot be combined with --source (use one or \
                     the other)"
                        .to_string(),
                );
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv define --defs`: {s}"));
            }
            other => {
                return Err(format!(
                    "`kv define --defs FILE` takes no positional KEY (got {other:?}); \
                     the keys come from the file(s)"
                ));
            }
        }
    }

    if files.is_empty() {
        return Err("--defs requires a FILE argument".to_string());
    }
    Ok(DefinePlan::Defs(files))
}

/// Parse `kv get|unpin <KEY>` into the corresponding [`Request`].
pub fn parse_kv_single_key(verb: &str, args: &[String]) -> Result<Request, String> {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if let Some(bad) = args.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown option for `kv {verb}`: {bad}"));
    }
    if positional.len() != 1 {
        return Err(format!("kv {verb} requires exactly one KEY"));
    }
    let key = positional[0].clone();
    match verb {
        "get" => Ok(Request::KvGet {
            key,
            dry_run: false,
        }),
        "unpin" => Ok(Request::KvUnpin { key }),
        _ => Err(format!("unknown kv subcommand: {verb}")),
    }
}

/// Parse `kv del <KEY> [--with-define]` into a [`Request::KvDel`].
pub fn parse_kv_del(args: &[String]) -> Result<Request, String> {
    let mut key: Option<String> = None;
    let mut with_define = false;
    for a in args {
        match a.as_str() {
            "--with-define" => with_define = true,
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv del`: {s}"));
            }
            other => {
                if key.is_some() {
                    return Err(format!("unexpected argument: {other}"));
                }
                key = Some(other.to_string());
            }
        }
    }
    let key = key.ok_or("kv del requires exactly one KEY")?;
    Ok(Request::KvDel { key, with_define })
}

/// Parse `kv pin <KEY> <DURATION>` into a [`Request::KvPin`].
///
/// `DURATION` uses the same grammar as the TTL flags (`1h` / `30m` / `45s` /
/// bare seconds); it is the time from now until the pin lapses.
pub fn parse_kv_pin(args: &[String]) -> Result<Request, String> {
    if let Some(bad) = args.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown option for `kv pin`: {bad}"));
    }
    let positional: Vec<&String> = args.iter().collect();
    if positional.len() != 2 {
        return Err(
            "kv pin requires exactly a KEY and a DURATION (e.g. `kv pin DB 8h`)".to_string(),
        );
    }
    let key = positional[0].clone();
    let duration_secs = parse_duration(positional[1])
        .map_err(|e| e.to_string())?
        .as_secs();
    Ok(Request::KvPin { key, duration_secs })
}

/// Render a successful kv-get response by writing the decoded value to stdout.
///
/// Returns the raw bytes so callers (and tests) can verify; writing is done by
/// the caller to keep this pure-ish.
pub fn decode_get_value(value_b64: &str) -> Result<Vec<u8>, String> {
    decode_b64(value_b64).map_err(|e| format!("daemon returned invalid base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::decode_b64;

    fn no_stdin() -> std::io::Result<Vec<u8>> {
        panic!("stdin should not be read")
    }

    #[test]
    fn default_socket_uses_xdg_state_home() {
        // SAFETY: single-threaded test; we restore via tempenv-style save/clear.
        let saved = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", "/tmp/xdgstate") };
        let p = default_socket_path();
        assert_eq!(p, PathBuf::from("/tmp/xdgstate/cache-warden/control.sock"));
        match saved {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }

    #[test]
    fn socket_flag_space_and_equals_forms() {
        let (p, rest) =
            take_socket_flag(&["--socket".into(), "/x.sock".into(), "ping".into()]).unwrap();
        assert_eq!(p, Some(PathBuf::from("/x.sock")));
        assert_eq!(rest, vec!["ping".to_string()]);

        let (p, rest) = take_socket_flag(&["--socket=/y.sock".into(), "status".into()]).unwrap();
        assert_eq!(p, Some(PathBuf::from("/y.sock")));
        assert_eq!(rest, vec!["status".to_string()]);
    }

    #[test]
    fn socket_flag_absent_is_none() {
        let (p, rest) = take_socket_flag(&["ping".into()]).unwrap();
        assert_eq!(p, None);
        assert_eq!(rest, vec!["ping".to_string()]);
    }

    #[test]
    fn socket_flag_missing_value_errors() {
        assert!(take_socket_flag(&["--socket".into()]).is_err());
    }

    #[test]
    fn resolve_socket_precedence_cli_over_config_over_default() {
        // CLI wins outright.
        assert_eq!(
            resolve_socket(
                Some(PathBuf::from("/cli.sock")),
                Some(PathBuf::from("/cfg.sock"))
            ),
            PathBuf::from("/cli.sock")
        );
        // No CLI -> config.
        assert_eq!(
            resolve_socket(None, Some(PathBuf::from("/cfg.sock"))),
            PathBuf::from("/cfg.sock")
        );
        // Neither -> the built-in default.
        assert_eq!(resolve_socket(None, None), default_socket_path());
    }

    #[test]
    fn kv_set_value_inline() {
        let req = parse_kv_set(&["DB".into(), "--value".into(), "pw".into()], no_stdin).unwrap();
        match req {
            Request::KvSet {
                key,
                source: SetSource::Static { value_b64 },
                ..
            } => {
                assert_eq!(key, "DB");
                assert_eq!(decode_b64(&value_b64).unwrap(), b"pw");
            }
            _ => panic!("expected KvSet static"),
        }
    }

    #[test]
    fn kv_set_value_stdin_reads_bytes() {
        let req = parse_kv_set(&["K".into(), "--value-stdin".into()], || {
            Ok(b"from-stdin".to_vec())
        })
        .unwrap();
        match req {
            Request::KvSet {
                source: SetSource::Static { value_b64 },
                ..
            } => assert_eq!(decode_b64(&value_b64).unwrap(), b"from-stdin"),
            _ => panic!("expected static from stdin"),
        }
    }

    #[test]
    fn kv_set_command_is_rejected_with_define_hint() {
        let err =
            parse_kv_set(&["K".into(), "--command".into(), "op".into()], no_stdin).unwrap_err();
        assert!(err.contains("kv define"), "msg: {err}");
    }

    #[test]
    fn kv_define_command_consumes_rest_as_argv() {
        let req = parse_kv_define(&[
            "TOK".into(),
            "--soft-ttl".into(),
            "1h".into(),
            "--command".into(),
            "op".into(),
            "read".into(),
            "op://v/i".into(),
        ])
        .unwrap();
        match req {
            Request::KvDefine {
                key,
                argv,
                soft_ttl_secs,
                ..
            } => {
                assert_eq!(key, "TOK");
                assert_eq!(argv, vec!["op", "read", "op://v/i"]);
                assert_eq!(soft_ttl_secs, Some(3600));
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_define_source_op_expands_to_op_read() {
        let req = parse_kv_define(&[
            "TOK".into(),
            "--source".into(),
            "op://vault/item/field".into(),
        ])
        .unwrap();
        match req {
            Request::KvDefine { argv, .. } => {
                assert_eq!(argv, vec!["op", "read", "op://vault/item/field"]);
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_define_source_non_op_scheme_is_rejected() {
        let err =
            parse_kv_define(&["K".into(), "--source".into(), "vault://x/y".into()]).unwrap_err();
        assert!(err.contains("unsupported source scheme"), "msg: {err}");
        assert!(err.contains("vault"), "msg: {err}");
    }

    #[test]
    fn kv_define_command_and_source_are_mutually_exclusive() {
        let err = parse_kv_define(&[
            "K".into(),
            "--source".into(),
            "op://a/b".into(),
            "--command".into(),
            "echo".into(),
            "x".into(),
        ])
        .unwrap_err();
        assert!(err.contains("only one"), "msg: {err}");
    }

    #[test]
    fn kv_define_requires_a_source() {
        let err = parse_kv_define(&["K".into()]).unwrap_err();
        assert!(err.contains("requires one of"), "msg: {err}");
    }

    #[test]
    fn kv_define_requires_key() {
        assert!(parse_kv_define(&["--source".into(), "op://a/b".into()]).is_err());
    }

    #[test]
    fn kv_define_empty_command_is_rejected() {
        assert!(parse_kv_define(&["K".into(), "--command".into()]).is_err());
    }

    // ---- kv define --defs (batch; DR-0014 §4) ----

    #[test]
    fn define_plan_single_without_defs_is_a_single_request() {
        let plan =
            parse_kv_define_plan(&["TOK".into(), "--source".into(), "op://v/i/f".into()]).unwrap();
        match plan {
            DefinePlan::Single(Request::KvDefine { key, argv, .. }) => {
                assert_eq!(key, "TOK");
                assert_eq!(argv, vec!["op", "read", "op://v/i/f"]);
            }
            other => panic!("expected Single KvDefine, got {other:?}"),
        }
    }

    #[test]
    fn define_plan_collects_repeated_defs_files() {
        let plan =
            parse_kv_define_plan(&["--defs".into(), "a.toml".into(), "--defs=b.toml".into()])
                .unwrap();
        assert_eq!(
            plan,
            DefinePlan::Defs(vec![PathBuf::from("a.toml"), PathBuf::from("b.toml")])
        );
    }

    #[test]
    fn define_plan_defs_with_command_is_rejected() {
        let err = parse_kv_define_plan(&[
            "--defs".into(),
            "a.toml".into(),
            "--command".into(),
            "echo".into(),
        ])
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_with_source_is_rejected() {
        let err = parse_kv_define_plan(&[
            "--defs".into(),
            "a.toml".into(),
            "--source".into(),
            "op://a/b".into(),
        ])
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_with_positional_key_is_rejected() {
        let err =
            parse_kv_define_plan(&["KEY".into(), "--defs".into(), "a.toml".into()]).unwrap_err();
        assert!(err.contains("no positional KEY"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_missing_file_arg_is_rejected() {
        assert!(parse_kv_define_plan(&["--defs".into()]).is_err());
    }

    #[test]
    fn kv_set_ttls_parse() {
        let req = parse_kv_set(
            &[
                "K".into(),
                "--value".into(),
                "v".into(),
                "--soft-ttl".into(),
                "30m".into(),
                "--hard-ttl".into(),
                "86400".into(),
            ],
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet {
                soft_ttl_secs,
                hard_ttl_secs,
                ..
            } => {
                assert_eq!(soft_ttl_secs, Some(1800));
                assert_eq!(hard_ttl_secs, Some(86400));
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn kv_set_requires_a_source() {
        assert!(parse_kv_set(&["K".into()], no_stdin).is_err());
    }

    #[test]
    fn kv_set_rejects_multiple_sources() {
        let err = parse_kv_set(
            &[
                "K".into(),
                "--value".into(),
                "v".into(),
                "--value-stdin".into(),
            ],
            no_stdin,
        )
        .unwrap_err();
        assert!(err.contains("only one"));
    }

    #[test]
    fn kv_set_requires_key() {
        assert!(parse_kv_set(&["--value".into(), "v".into()], no_stdin).is_err());
    }

    #[test]
    fn kv_set_rejects_unknown_option() {
        assert!(parse_kv_set(&["K".into(), "--bogus".into()], no_stdin).is_err());
    }

    #[test]
    fn kv_get_parses() {
        assert_eq!(
            parse_kv_single_key("get", &["K".into()]).unwrap(),
            Request::KvGet {
                key: "K".into(),
                dry_run: false,
            }
        );
    }

    #[test]
    fn kv_del_parses_value_only_by_default() {
        assert_eq!(
            parse_kv_del(&["K".into()]).unwrap(),
            Request::KvDel {
                key: "K".into(),
                with_define: false,
            }
        );
    }

    #[test]
    fn kv_del_with_define_flag_sets_with_define() {
        assert_eq!(
            parse_kv_del(&["K".into(), "--with-define".into()]).unwrap(),
            Request::KvDel {
                key: "K".into(),
                with_define: true,
            }
        );
        // Flag order does not matter.
        assert_eq!(
            parse_kv_del(&["--with-define".into(), "K".into()]).unwrap(),
            Request::KvDel {
                key: "K".into(),
                with_define: true,
            }
        );
    }

    #[test]
    fn kv_del_requires_a_key_and_rejects_unknown_options() {
        assert!(parse_kv_del(&[]).is_err());
        assert!(parse_kv_del(&["K".into(), "--bogus".into()]).is_err());
        assert!(parse_kv_del(&["A".into(), "B".into()]).is_err());
    }

    #[test]
    fn kv_get_requires_exactly_one_key() {
        assert!(parse_kv_single_key("get", &[]).is_err());
        assert!(parse_kv_single_key("get", &["a".into(), "b".into()]).is_err());
    }

    #[test]
    fn kv_get_rejects_options() {
        assert!(parse_kv_single_key("get", &["K".into(), "--x".into()]).is_err());
    }

    #[test]
    fn kv_unpin_parses_single_key() {
        assert_eq!(
            parse_kv_single_key("unpin", &["K".into()]).unwrap(),
            Request::KvUnpin { key: "K".into() }
        );
    }

    #[test]
    fn kv_pin_parses_key_and_duration() {
        let req = parse_kv_pin(&["DB".into(), "8h".into()]).unwrap();
        assert_eq!(
            req,
            Request::KvPin {
                key: "DB".into(),
                duration_secs: 28800,
            }
        );
        // Bare seconds and m/s suffixes via the shared duration parser.
        assert_eq!(
            parse_kv_pin(&["K".into(), "90".into()]).unwrap(),
            Request::KvPin {
                key: "K".into(),
                duration_secs: 90,
            }
        );
    }

    #[test]
    fn kv_pin_requires_key_and_duration() {
        assert!(parse_kv_pin(&["DB".into()]).is_err());
        assert!(parse_kv_pin(&[]).is_err());
        assert!(parse_kv_pin(&["DB".into(), "8h".into(), "extra".into()]).is_err());
    }

    #[test]
    fn kv_pin_rejects_bad_duration() {
        assert!(parse_kv_pin(&["DB".into(), "8days".into()]).is_err());
    }

    #[test]
    fn kv_pin_rejects_options() {
        assert!(parse_kv_pin(&["DB".into(), "8h".into(), "--x".into()]).is_err());
    }

    // ---- value-type flags (DR-0016) ----

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn otp_flags_absent_yield_empty_meta() {
        let (meta, rest) = take_otp_flags(&s(&["KEY", "--value", "x"])).unwrap();
        assert!(meta.is_empty());
        assert_eq!(rest, s(&["KEY", "--value", "x"]));
    }

    #[test]
    fn type_otp_with_params_is_collected_and_validated() {
        let (meta, rest) = take_otp_flags(&s(&[
            "--type",
            "otp",
            "--otp-digits",
            "8",
            "--otp-period",
            "60",
            "--otp-algorithm",
            "SHA256",
            "KEY",
        ]))
        .unwrap();
        assert_eq!(meta.type_label.as_deref(), Some("otp"));
        assert_eq!(meta.params.get("digits").map(String::as_str), Some("8"));
        assert_eq!(meta.params.get("period").map(String::as_str), Some("60"));
        // Algorithm label is normalized to lowercase.
        assert_eq!(
            meta.params.get("algorithm").map(String::as_str),
            Some("sha256")
        );
        // The non-otp args pass through untouched.
        assert_eq!(rest, s(&["KEY"]));
    }

    #[test]
    fn otp_flags_accept_equals_form() {
        let (meta, _rest) = take_otp_flags(&s(&["--type=otp", "--otp-digits=6", "KEY"])).unwrap();
        assert_eq!(meta.type_label.as_deref(), Some("otp"));
        assert_eq!(meta.params.get("digits").map(String::as_str), Some("6"));
    }

    #[test]
    fn otp_params_without_type_otp_are_rejected() {
        let err = take_otp_flags(&s(&["--otp-digits", "8", "KEY"])).unwrap_err();
        assert!(err.contains("require `--type otp`"), "msg: {err}");
    }

    #[test]
    fn unknown_type_is_rejected() {
        let err = take_otp_flags(&s(&["--type", "magic", "KEY"])).unwrap_err();
        assert!(err.contains("unknown --type"), "msg: {err}");
    }

    #[test]
    fn bad_otp_digits_value_is_rejected() {
        assert!(take_otp_flags(&s(&["--type", "otp", "--otp-digits", "x"])).is_err());
        assert!(take_otp_flags(&s(&["--type", "otp", "--otp-digits", "0"])).is_err());
        assert!(take_otp_flags(&s(&["--type", "otp", "--otp-digits", "10"])).is_err());
    }

    #[test]
    fn bad_otp_algorithm_is_rejected() {
        assert!(take_otp_flags(&s(&["--type", "otp", "--otp-algorithm", "md5"])).is_err());
    }

    #[test]
    fn kv_set_with_type_otp_attaches_meta() {
        let req = parse_kv_set(
            &s(&[
                "OTP",
                "--type",
                "otp",
                "--otp-digits",
                "8",
                "--value",
                "SEED",
            ]),
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet { key, meta, .. } => {
                assert_eq!(key, "OTP");
                assert_eq!(meta.type_label.as_deref(), Some("otp"));
                assert_eq!(meta.params.get("digits").map(String::as_str), Some("8"));
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn kv_define_with_type_otp_attaches_meta() {
        let req = parse_kv_define(&s(&[
            "OTP",
            "--type",
            "otp",
            "--source",
            "op://vault/item/field",
        ]))
        .unwrap();
        match req {
            Request::KvDefine {
                key, argv, meta, ..
            } => {
                assert_eq!(key, "OTP");
                assert_eq!(argv, s(&["op", "read", "op://vault/item/field"]));
                assert_eq!(meta.type_label.as_deref(), Some("otp"));
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_define_otp_with_attribute_otp_source_is_rejected() {
        // DR-0016 §5: caching a `?attribute=otp` computed code is structurally
        // wrong; the define must error.
        let err = parse_kv_define(&s(&[
            "OTP",
            "--type",
            "otp",
            "--source",
            "op://vault/item/field?attribute=otp",
        ]))
        .unwrap_err();
        assert!(err.contains("attribute=otp"), "msg: {err}");
    }

    #[test]
    fn kv_define_otp_command_argv_is_not_scanned_for_otp_flags() {
        // A literal `--otp-digits` inside the command argv must NOT be consumed as
        // our flag (everything after --command is the literal program argv).
        let req = parse_kv_define(&s(&[
            "OTP",
            "--type",
            "otp",
            "--command",
            "myprog",
            "--otp-digits",
            "8",
        ]))
        .unwrap();
        match req {
            Request::KvDefine { argv, meta, .. } => {
                // The `--otp-digits 8` stayed in the command argv.
                assert_eq!(argv, s(&["myprog", "--otp-digits", "8"]));
                // The otp meta came only from the `--type otp` before --command;
                // no digits param was set from the argv.
                assert_eq!(meta.type_label.as_deref(), Some("otp"));
                assert!(meta.params.get("digits").is_none());
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn non_otp_set_still_works_unchanged() {
        let req = parse_kv_set(&s(&["K", "--value", "v"]), no_stdin).unwrap();
        match req {
            Request::KvSet { meta, .. } => assert!(meta.is_empty()),
            _ => panic!("expected KvSet"),
        }
    }
}
