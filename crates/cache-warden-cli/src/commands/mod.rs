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
pub mod op_private_key;
pub mod run_cmd;

use std::path::PathBuf;

use crate::protocol::wire::{Request, SetSource, ValueMetaWire};
use crate::protocol::{decode_b64, encode_b64, parse_duration};
use crate::totp::OtpAlgorithm;

/// Extract the value-type flags (`--type` and the `--otp-*` parameters) from
/// `args`, returning the resulting [`ValueMetaWire`] and the remaining args with
/// those flags removed (DR-0016 §1). Used by `kv define` only — a value type
/// implies a regenerable definition, so `kv set` rejects these flags.
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
        if a == "--" {
            // Everything after `--` is positional; a `--socket` there is a
            // value, never our flag. Keep the separator for downstream parsers.
            rest.extend(args[i..].iter().cloned());
            break;
        }
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

/// Split `args` at the first standalone `--` separator (POSIX-style).
///
/// The head may contain options; everything **after** the `--` is positional
/// and must never be interpreted as an option (defensive scripting:
/// `kv del -- "$key"` is safe even when `$key` starts with `--`). The separator
/// itself is dropped. Shared by every kv leaf parser so the rule is uniform.
///
/// Known intersection (accepted, see `parse_kv_define`): `kv define --command`
/// consumes the rest of the argv, so a `--command` appearing *before* any `--`
/// swallows it — a key that needs `--` cannot be combined with a `--command`
/// source. No practical loss.
pub fn split_double_dash(args: &[String]) -> (&[String], &[String]) {
    match args.iter().position(|a| a == "--") {
        Some(p) => (&args[..p], &args[p + 1..]),
        None => (args, &[]),
    }
}

/// Validate a CLI KEY argument (DR-0017 §1.5 / §2): the identifier charset is
/// `[A-Za-z0-9_]+`, and a `/` (an attempted `ns/key` embedding) gets a specific
/// steer to `--namespace` — the namespace travels on the flag, never inside the
/// KEY argument.
pub fn validate_cli_key(key: &str, verb: &str) -> Result<(), String> {
    if key.contains('/') {
        return Err(format!(
            "`kv {verb}` KEY must not contain `/` (got {key:?}); \
             select the namespace with `--namespace NS` instead (DR-0017)"
        ));
    }
    crate::namespace::validate_identifier(key, "KEY")
}

/// Parse the arguments to `kv set ...` into a [`Request::KvSet`].
///
/// Grammar:
/// `kv set [--soft-ttl D] [--hard-ttl D] [--] KEY [VALUE]`
///
/// `ns` is the already-resolved namespace (DR-0017 §4: the `--namespace` flag
/// is taken by the dispatcher); the request key is the composed `NS/KEY`.
/// `VALUE` is positional. When omitted, the bytes are read from stdin (binary
/// safe) — but only if stdin is **not** a TTY (`stdin_is_tty`): refusing to
/// read from a terminal turns a forgotten VALUE into an immediate error instead
/// of a silent hang. `stdin` provides the bytes (kept as a parameter so the
/// parse is testable).
///
/// The old `--value V` / `--value-stdin` flags are rejected with a steer to the
/// positional form. Command sources moved to `kv define` (see
/// [`parse_kv_define`]); value types (`--type otp` / `--otp-*`) live on
/// definitions too (DR-0016). `kv set` injects opaque bytes only.
pub fn parse_kv_set(
    args: &[String],
    ns: &str,
    stdin_is_tty: bool,
    stdin: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> Result<Request, String> {
    let (head, tail) = split_double_dash(args);

    let mut positional: Vec<String> = Vec::new();
    let mut soft_ttl_secs: Option<u64> = None;
    let mut hard_ttl_secs: Option<u64> = None;

    let mut i = 0;
    while i < head.len() {
        match head[i].as_str() {
            "--soft-ttl" => {
                let v = head.get(i + 1).ok_or("--soft-ttl requires an argument")?;
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
                let v = head.get(i + 1).ok_or("--hard-ttl requires an argument")?;
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
            s if s == "--value" || s == "--value-stdin" || s.starts_with("--value=") => {
                return Err(format!(
                    "`{}` was removed: the value is positional now. Use \
                     `kv set KEY VALUE`, or omit VALUE and pipe the bytes on stdin \
                     (`... | kv set KEY`)",
                    s.split('=').next().unwrap_or(s)
                ));
            }
            "--command" => {
                return Err(
                    "`--command` was removed from `kv set`; use `kv define KEY --command ...`"
                        .to_string(),
                );
            }
            "--type" | "--otp-digits" | "--otp-period" | "--otp-algorithm" => {
                return Err(format!(
                    "`{}` is not valid on `kv set`; value types (otp) live on \
                     definitions. Register it with `kv define KEY --type otp ...` instead",
                    head[i]
                ));
            }
            s if s.starts_with("--type=")
                || s.starts_with("--otp-digits=")
                || s.starts_with("--otp-period=")
                || s.starts_with("--otp-algorithm=") =>
            {
                let flag = s.split('=').next().unwrap_or(s);
                return Err(format!(
                    "`{flag}` is not valid on `kv set`; value types (otp) live on \
                     definitions. Register it with `kv define KEY --type otp ...` instead"
                ));
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv set`: {s}"));
            }
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }
    positional.extend(tail.iter().cloned());

    let mut it = positional.into_iter();
    let key = it.next().ok_or("kv set requires a KEY")?;
    let value = it.next();
    if let Some(extra) = it.next() {
        return Err(format!("unexpected argument: {extra}"));
    }
    validate_cli_key(&key, "set")?;

    let bytes = match value {
        Some(v) => v.into_bytes(),
        None => {
            if stdin_is_tty {
                return Err(
                    "kv set requires a VALUE (or pipe the bytes on stdin); refusing to \
                     read stdin from a terminal. Use `kv set KEY VALUE` or \
                     `... | kv set KEY`"
                        .to_string(),
                );
            }
            stdin().map_err(|e| format!("failed to read stdin: {e}"))?
        }
    };
    let source = SetSource::Static {
        value_b64: encode_b64(&bytes),
    };

    Ok(Request::KvSet {
        key: crate::namespace::compose(ns, &key),
        source,
        soft_ttl_secs,
        hard_ttl_secs,
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
/// `ns` is the already-resolved namespace (DR-0017 §4); the request key is the
/// composed `NS/KEY`. `--command` and `--source` are mutually exclusive and
/// exactly one is required. A `--source op://...` URI is expanded into
/// `["op", "read", URI]` at parse time (see [`expand_source_uri`]); the daemon
/// only ever sees argv.
pub fn parse_kv_define(args: &[String], ns: &str) -> Result<Request, String> {
    // Two consume-the-rest markers can appear: `--command` (rest = literal
    // argv) and `--` (rest = positionals). Whichever comes **first** wins:
    //
    // - `--command` first: everything after it (a later `--` included) belongs
    //   to the command argv. This is the documented intersection of the two
    //   rules — a key that itself needs `--` cannot be combined with a
    //   `--command` source (use `--source`, or rename the key). Accepted as a
    //   non-loss (see `split_double_dash`).
    // - `--` first: everything after it is positional; a later `--command`
    //   token is a plain positional, never our flag.
    let cmd_pos = args.iter().position(|a| a == "--command");
    let dd_pos = args.iter().position(|a| a == "--");
    let command_first = match (cmd_pos, dd_pos) {
        (Some(c), Some(d)) => c < d,
        (Some(_), None) => true,
        _ => false,
    };

    let (head, cmd_tail, positional_tail): (&[String], &[String], &[String]) = if command_first {
        let p = cmd_pos.unwrap();
        (&args[..p], &args[p..], &[])
    } else {
        let (h, t) = split_double_dash(args);
        (h, &[], t)
    };

    // Pull the value-type flags from the option head only (never from the
    // command argv or the positionals after `--`).
    let (meta, head_rest) = take_otp_flags(head)?;
    // Reassemble: the otp-stripped head, then the untouched `--command ...` tail.
    let mut reassembled: Vec<String> = head_rest;
    reassembled.extend_from_slice(cmd_tail);
    let args = reassembled.as_slice();

    let mut positional: Vec<String> = Vec::new();
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
                positional.push(other.to_string());
                i += 1;
            }
        }
    }
    positional.extend(positional_tail.iter().cloned());

    let mut it = positional.into_iter();
    let key = it.next().ok_or("kv define requires a KEY")?;
    if let Some(extra) = it.next() {
        return Err(format!("unexpected argument: {extra}"));
    }
    validate_cli_key(&key, "define")?;

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
        key: crate::namespace::compose(ns, &key),
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
pub fn parse_kv_define_plan(args: &[String], ns: &str) -> Result<DefinePlan, String> {
    // Detect the batch mode by the presence of any `--defs` flag, then collect
    // every `--defs FILE` while rejecting any single-definition flag / KEY mixed
    // in (so the user gets a clear "pick one mode" error, not a half-applied
    // command). A `--defs` after a consume-the-rest marker (`--command` or
    // `--`) is not our flag, so only scan the option head for the mode switch.
    let scan_end = args
        .iter()
        .position(|a| a == "--command" || a == "--")
        .unwrap_or(args.len());
    let uses_defs = args[..scan_end]
        .iter()
        .any(|a| a == "--defs" || a.starts_with("--defs="));
    if !uses_defs {
        return parse_kv_define(args, ns).map(DefinePlan::Single);
    }

    // Batch mode takes no positionals at all, so a `--` separator (whose only
    // purpose is to introduce positionals) is rejected like a positional KEY.
    let (args, tail) = split_double_dash(args);
    if let Some(first) = tail.first() {
        return Err(format!(
            "`kv define --defs FILE` takes no positional KEY (got {first:?}); \
             the keys come from the file(s)"
        ));
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

/// Parse `kv get|unpin [--] <KEY>` into the corresponding [`Request`].
///
/// `ns` is the already-resolved namespace (DR-0017 §4); the request key is the
/// composed `NS/KEY`.
pub fn parse_kv_single_key(verb: &str, args: &[String], ns: &str) -> Result<Request, String> {
    let (head, tail) = split_double_dash(args);
    if let Some(bad) = head.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown option for `kv {verb}`: {bad}"));
    }
    let positional: Vec<&String> = head.iter().chain(tail.iter()).collect();
    if positional.len() != 1 {
        return Err(format!("kv {verb} requires exactly one KEY"));
    }
    validate_cli_key(positional[0], verb)?;
    let key = crate::namespace::compose(ns, positional[0]);
    match verb {
        "get" => Ok(Request::KvGet {
            key,
            dry_run: false,
        }),
        "unpin" => Ok(Request::KvUnpin { key }),
        _ => Err(format!("unknown kv subcommand: {verb}")),
    }
}

/// Parse `kv del [--with-define] [--] <KEY>` into a [`Request::KvDel`].
///
/// `ns` is the already-resolved namespace (DR-0017 §4); the request key is the
/// composed `NS/KEY`.
pub fn parse_kv_del(args: &[String], ns: &str) -> Result<Request, String> {
    let (head, tail) = split_double_dash(args);
    let mut positional: Vec<String> = Vec::new();
    let mut with_define = false;
    for a in head {
        match a.as_str() {
            "--with-define" => with_define = true,
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `kv del`: {s}"));
            }
            other => positional.push(other.to_string()),
        }
    }
    positional.extend(tail.iter().cloned());

    let mut it = positional.into_iter();
    let key = it.next().ok_or("kv del requires exactly one KEY")?;
    if let Some(extra) = it.next() {
        return Err(format!("unexpected argument: {extra}"));
    }
    validate_cli_key(&key, "del")?;
    Ok(Request::KvDel {
        key: crate::namespace::compose(ns, &key),
        with_define,
    })
}

/// Parse `kv pin [--] <KEY> <DURATION>` into a [`Request::KvPin`].
///
/// `DURATION` uses the same grammar as the TTL flags (`1h` / `30m` / `45s` /
/// bare seconds); it is the time from now until the pin lapses.
pub fn parse_kv_pin(args: &[String], ns: &str) -> Result<Request, String> {
    let (head, tail) = split_double_dash(args);
    if let Some(bad) = head.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown option for `kv pin`: {bad}"));
    }
    let positional: Vec<&String> = head.iter().chain(tail.iter()).collect();
    if positional.len() != 2 {
        return Err(
            "kv pin requires exactly a KEY and a DURATION (e.g. `kv pin DB 8h`)".to_string(),
        );
    }
    validate_cli_key(positional[0], "pin")?;
    let key = crate::namespace::compose(ns, positional[0]);
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
    fn socket_flag_stops_at_double_dash() {
        // A `--socket` after `--` is positional data, never our flag; the
        // separator itself is preserved for the downstream parser.
        let (p, rest) = take_socket_flag(&s(&["--", "--socket", "/x.sock"])).unwrap();
        assert_eq!(p, None);
        assert_eq!(rest, s(&["--", "--socket", "/x.sock"]));

        // Before the `--` it still counts.
        let (p, rest) = take_socket_flag(&s(&["--socket", "/x.sock", "--", "K"])).unwrap();
        assert_eq!(p, Some(PathBuf::from("/x.sock")));
        assert_eq!(rest, s(&["--", "K"]));
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
    fn kv_set_positional_key_and_value() {
        let req = parse_kv_set(&["DB".into(), "pw".into()], "default", false, no_stdin).unwrap();
        match req {
            Request::KvSet {
                key,
                source: SetSource::Static { value_b64 },
                ..
            } => {
                assert_eq!(key, "default/DB");
                assert_eq!(decode_b64(&value_b64).unwrap(), b"pw");
            }
            _ => panic!("expected KvSet static"),
        }
    }

    #[test]
    fn kv_set_value_omitted_reads_piped_stdin() {
        // No VALUE positional + stdin is a pipe: the bytes come from stdin
        // (binary safe).
        let req = parse_kv_set(&["K".into()], "default", false, || {
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
    fn kv_set_value_omitted_on_a_tty_is_an_error() {
        // No VALUE + stdin is a TTY: refuse immediately (a silent hang waiting
        // for terminal input would look like a freeze).
        let err = parse_kv_set(&["K".into()], "default", true, no_stdin).unwrap_err();
        assert!(
            err.contains("VALUE") && err.contains("pipe"),
            "must steer to passing VALUE or piping: {err}"
        );
    }

    #[test]
    fn kv_set_value_flags_are_rejected_with_steer() {
        // `--value` / `--value-stdin` were replaced by the positional VALUE /
        // piped stdin; the error steers to the new form.
        for flags in [
            vec!["K", "--value", "v"],
            vec!["K", "--value=v"],
            vec!["K", "--value-stdin"],
        ] {
            let err = parse_kv_set(&s(&flags), "default", false, no_stdin).unwrap_err();
            assert!(
                err.contains("kv set KEY VALUE") || err.contains("kv set KEY"),
                "expected steer to the positional form, got: {err}"
            );
        }
    }

    #[test]
    fn kv_set_rejects_extra_positionals() {
        let err = parse_kv_set(&s(&["K", "v", "extra"]), "default", false, no_stdin).unwrap_err();
        assert!(err.contains("unexpected argument"), "msg: {err}");
    }

    #[test]
    fn kv_set_command_is_rejected_with_define_hint() {
        let err = parse_kv_set(
            &["K".into(), "--command".into(), "op".into()],
            "default",
            false,
            no_stdin,
        )
        .unwrap_err();
        assert!(err.contains("kv define"), "msg: {err}");
    }

    // ---- `--` separator: everything after it is positional (all kv leaves) ----

    #[test]
    fn kv_set_double_dash_makes_option_like_args_positional() {
        // `kv set -- k --value-stdin` sets KEY=k, VALUE="--value-stdin".
        let req = parse_kv_set(
            &s(&["--", "k", "--value-stdin"]),
            "default",
            false,
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet {
                key,
                source: SetSource::Static { value_b64 },
                ..
            } => {
                assert_eq!(key, "default/k");
                assert_eq!(decode_b64(&value_b64).unwrap(), b"--value-stdin");
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn kv_set_options_before_double_dash_still_apply() {
        let req = parse_kv_set(
            &s(&["--soft-ttl", "30m", "--", "K", "v"]),
            "default",
            false,
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet {
                key, soft_ttl_secs, ..
            } => {
                assert_eq!(key, "default/K");
                assert_eq!(soft_ttl_secs, Some(1800));
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn kv_get_double_dash_key_stays_positional() {
        // A `--`-protected key is never parsed as an option; a plain key after
        // `--` works exactly like one before it.
        assert_eq!(
            parse_kv_single_key("get", &s(&["--", "K"]), "default").unwrap(),
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            }
        );
        // An option-looking token after `--` is *positional* (defensive
        // scripting): it fails KEY charset validation (DR-0017 §1.5), not as an
        // "unknown option".
        let err = parse_kv_single_key("get", &s(&["--", "--weird-key"]), "default").unwrap_err();
        assert!(
            err.contains("KEY"),
            "charset error, not a flag error: {err}"
        );
        assert!(
            !err.contains("unknown option"),
            "must not be flag-misparsed: {err}"
        );
    }

    #[test]
    fn kv_unpin_double_dash_key_stays_positional() {
        assert_eq!(
            parse_kv_single_key("unpin", &s(&["--", "K"]), "default").unwrap(),
            Request::KvUnpin {
                key: "default/K".into(),
            }
        );
    }

    #[test]
    fn kv_del_double_dash_key_stays_positional() {
        // Options before `--` still apply; the key after it is never an option.
        assert_eq!(
            parse_kv_del(&s(&["--with-define", "--", "K"]), "default").unwrap(),
            Request::KvDel {
                key: "default/K".into(),
                with_define: true,
            }
        );
    }

    #[test]
    fn kv_pin_double_dash_key_stays_positional() {
        assert_eq!(
            parse_kv_pin(&s(&["--", "K", "8h"]), "default").unwrap(),
            Request::KvPin {
                key: "default/K".into(),
                duration_secs: 28800,
            }
        );
    }

    #[test]
    fn kv_define_double_dash_key_stays_positional() {
        let req = parse_kv_define(&s(&["--source", "op://v/i/f", "--", "K"]), "default").unwrap();
        match req {
            Request::KvDefine { key, argv, .. } => {
                assert_eq!(key, "default/K");
                assert_eq!(argv, s(&["op", "read", "op://v/i/f"]));
            }
            _ => panic!("expected KvDefine"),
        }
    }

    // ---- KEY charset enforcement (DR-0017 §1.5 / §2) ----

    #[test]
    fn kv_key_charset_is_enforced_at_parse_time() {
        // `.` and `-` left the charset; unicode and empty were never valid.
        for bad in ["a.b", "a-b", "--weird-key", "日本語"] {
            assert!(
                parse_kv_set(&s(&["--", bad, "v"]), "default", false, no_stdin).is_err(),
                "set must reject {bad:?}"
            );
            assert!(
                parse_kv_single_key("get", &s(&["--", bad]), "default").is_err(),
                "get must reject {bad:?}"
            );
            assert!(
                parse_kv_del(&s(&["--", bad]), "default").is_err(),
                "del must reject {bad:?}"
            );
        }
    }

    #[test]
    fn kv_key_with_slash_steers_to_namespace_flag() {
        // DR-0017 §2: `ns/key` embedding in the KEY argument is rejected with a
        // steer to --namespace (the only namespace-selection path on the CLI).
        for (verb, err) in [
            (
                "set",
                parse_kv_set(&s(&["projA/DB", "v"]), "default", false, no_stdin).unwrap_err(),
            ),
            (
                "get",
                parse_kv_single_key("get", &s(&["projA/DB"]), "default").unwrap_err(),
            ),
            (
                "del",
                parse_kv_del(&s(&["projA/DB"]), "default").unwrap_err(),
            ),
            (
                "pin",
                parse_kv_pin(&s(&["projA/DB", "8h"]), "default").unwrap_err(),
            ),
            (
                "define",
                parse_kv_define(&s(&["projA/DB", "--source", "op://v/i/f"]), "default")
                    .unwrap_err(),
            ),
        ] {
            assert!(
                err.contains("--namespace"),
                "kv {verb} must steer to --namespace: {err}"
            );
        }
    }

    #[test]
    fn kv_define_command_before_double_dash_consumes_everything() {
        // Known intersection (documented): `--command` consumes the rest of the
        // argv, so a `--` after it belongs to the command, not to our parser.
        let req = parse_kv_define(&s(&["K", "--command", "prog", "--", "x"]), "default").unwrap();
        match req {
            Request::KvDefine { argv, .. } => {
                assert_eq!(argv, s(&["prog", "--", "x"]));
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_define_command_after_double_dash_is_positional() {
        // `--` first: a later `--command` is a positional (here: an unexpected
        // second positional after KEY).
        let err = parse_kv_define(
            &s(&["--source", "op://v/i/f", "--", "K", "--command"]),
            "default",
        )
        .unwrap_err();
        assert!(err.contains("unexpected argument"), "msg: {err}");
    }

    #[test]
    fn kv_define_command_consumes_rest_as_argv() {
        let req = parse_kv_define(
            &[
                "TOK".into(),
                "--soft-ttl".into(),
                "1h".into(),
                "--command".into(),
                "op".into(),
                "read".into(),
                "op://v/i".into(),
            ],
            "default",
        )
        .unwrap();
        match req {
            Request::KvDefine {
                key,
                argv,
                soft_ttl_secs,
                ..
            } => {
                assert_eq!(key, "default/TOK");
                assert_eq!(argv, vec!["op", "read", "op://v/i"]);
                assert_eq!(soft_ttl_secs, Some(3600));
            }
            _ => panic!("expected KvDefine"),
        }
    }

    #[test]
    fn kv_define_source_op_expands_to_op_read() {
        let req = parse_kv_define(
            &[
                "TOK".into(),
                "--source".into(),
                "op://vault/item/field".into(),
            ],
            "default",
        )
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
        let err = parse_kv_define(
            &["K".into(), "--source".into(), "vault://x/y".into()],
            "default",
        )
        .unwrap_err();
        assert!(err.contains("unsupported source scheme"), "msg: {err}");
        assert!(err.contains("vault"), "msg: {err}");
    }

    #[test]
    fn kv_define_command_and_source_are_mutually_exclusive() {
        let err = parse_kv_define(
            &[
                "K".into(),
                "--source".into(),
                "op://a/b".into(),
                "--command".into(),
                "echo".into(),
                "x".into(),
            ],
            "default",
        )
        .unwrap_err();
        assert!(err.contains("only one"), "msg: {err}");
    }

    #[test]
    fn kv_define_requires_a_source() {
        let err = parse_kv_define(&["K".into()], "default").unwrap_err();
        assert!(err.contains("requires one of"), "msg: {err}");
    }

    #[test]
    fn kv_define_requires_key() {
        assert!(parse_kv_define(&["--source".into(), "op://a/b".into()], "default").is_err());
    }

    #[test]
    fn kv_define_empty_command_is_rejected() {
        assert!(parse_kv_define(&["K".into(), "--command".into()], "default").is_err());
    }

    // ---- kv define --defs (batch; DR-0014 §4) ----

    #[test]
    fn define_plan_single_without_defs_is_a_single_request() {
        let plan = parse_kv_define_plan(
            &["TOK".into(), "--source".into(), "op://v/i/f".into()],
            "default",
        )
        .unwrap();
        match plan {
            DefinePlan::Single(Request::KvDefine { key, argv, .. }) => {
                assert_eq!(key, "default/TOK");
                assert_eq!(argv, vec!["op", "read", "op://v/i/f"]);
            }
            other => panic!("expected Single KvDefine, got {other:?}"),
        }
    }

    #[test]
    fn define_plan_collects_repeated_defs_files() {
        let plan = parse_kv_define_plan(
            &["--defs".into(), "a.toml".into(), "--defs=b.toml".into()],
            "default",
        )
        .unwrap();
        assert_eq!(
            plan,
            DefinePlan::Defs(vec![PathBuf::from("a.toml"), PathBuf::from("b.toml")])
        );
    }

    #[test]
    fn define_plan_defs_with_command_is_rejected() {
        let err = parse_kv_define_plan(
            &[
                "--defs".into(),
                "a.toml".into(),
                "--command".into(),
                "echo".into(),
            ],
            "default",
        )
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_with_source_is_rejected() {
        let err = parse_kv_define_plan(
            &[
                "--defs".into(),
                "a.toml".into(),
                "--source".into(),
                "op://a/b".into(),
            ],
            "default",
        )
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_with_positional_key_is_rejected() {
        let err =
            parse_kv_define_plan(&["KEY".into(), "--defs".into(), "a.toml".into()], "default")
                .unwrap_err();
        assert!(err.contains("no positional KEY"), "msg: {err}");
    }

    #[test]
    fn define_plan_defs_missing_file_arg_is_rejected() {
        assert!(parse_kv_define_plan(&["--defs".into()], "default").is_err());
    }

    #[test]
    fn kv_set_ttls_parse() {
        let req = parse_kv_set(
            &s(&["K", "v", "--soft-ttl", "30m", "--hard-ttl", "86400"]),
            "default",
            false,
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
    fn kv_set_value_may_follow_options() {
        // Positional args are not position-locked: options may come first.
        let req = parse_kv_set(
            &s(&["--soft-ttl", "30m", "K", "v"]),
            "default",
            false,
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet {
                key,
                source: SetSource::Static { value_b64 },
                ..
            } => {
                assert_eq!(key, "default/K");
                assert_eq!(decode_b64(&value_b64).unwrap(), b"v");
            }
            _ => panic!("expected KvSet"),
        }
    }

    #[test]
    fn kv_set_requires_key() {
        assert!(parse_kv_set(&[], "default", false, no_stdin).is_err());
        assert!(parse_kv_set(&s(&["--soft-ttl", "30m"]), "default", false, no_stdin).is_err());
    }

    #[test]
    fn kv_set_rejects_unknown_option() {
        assert!(parse_kv_set(&["K".into(), "--bogus".into()], "default", false, no_stdin).is_err());
    }

    #[test]
    fn kv_get_parses() {
        assert_eq!(
            parse_kv_single_key("get", &["K".into()], "default").unwrap(),
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            }
        );
    }

    #[test]
    fn kv_del_parses_value_only_by_default() {
        assert_eq!(
            parse_kv_del(&["K".into()], "default").unwrap(),
            Request::KvDel {
                key: "default/K".into(),
                with_define: false,
            }
        );
    }

    #[test]
    fn kv_del_with_define_flag_sets_with_define() {
        assert_eq!(
            parse_kv_del(&["K".into(), "--with-define".into()], "default").unwrap(),
            Request::KvDel {
                key: "default/K".into(),
                with_define: true,
            }
        );
        // Flag order does not matter.
        assert_eq!(
            parse_kv_del(&["--with-define".into(), "K".into()], "default").unwrap(),
            Request::KvDel {
                key: "default/K".into(),
                with_define: true,
            }
        );
    }

    #[test]
    fn kv_del_requires_a_key_and_rejects_unknown_options() {
        assert!(parse_kv_del(&[], "default").is_err());
        assert!(parse_kv_del(&["K".into(), "--bogus".into()], "default").is_err());
        assert!(parse_kv_del(&["A".into(), "B".into()], "default").is_err());
    }

    #[test]
    fn kv_get_requires_exactly_one_key() {
        assert!(parse_kv_single_key("get", &[], "default").is_err());
        assert!(parse_kv_single_key("get", &["a".into(), "b".into()], "default").is_err());
    }

    #[test]
    fn kv_get_rejects_options() {
        assert!(parse_kv_single_key("get", &["K".into(), "--x".into()], "default").is_err());
    }

    #[test]
    fn kv_unpin_parses_single_key() {
        assert_eq!(
            parse_kv_single_key("unpin", &["K".into()], "default").unwrap(),
            Request::KvUnpin {
                key: "default/K".into()
            }
        );
    }

    #[test]
    fn kv_pin_parses_key_and_duration() {
        let req = parse_kv_pin(&["DB".into(), "8h".into()], "default").unwrap();
        assert_eq!(
            req,
            Request::KvPin {
                key: "default/DB".into(),
                duration_secs: 28800,
            }
        );
        // Bare seconds and m/s suffixes via the shared duration parser.
        assert_eq!(
            parse_kv_pin(&["K".into(), "90".into()], "default").unwrap(),
            Request::KvPin {
                key: "default/K".into(),
                duration_secs: 90,
            }
        );
    }

    #[test]
    fn kv_pin_requires_key_and_duration() {
        assert!(parse_kv_pin(&["DB".into()], "default").is_err());
        assert!(parse_kv_pin(&[], "default").is_err());
        assert!(parse_kv_pin(&["DB".into(), "8h".into(), "extra".into()], "default").is_err());
    }

    #[test]
    fn kv_pin_rejects_bad_duration() {
        assert!(parse_kv_pin(&["DB".into(), "8days".into()], "default").is_err());
    }

    #[test]
    fn kv_pin_rejects_options() {
        assert!(parse_kv_pin(&["DB".into(), "8h".into(), "--x".into()], "default").is_err());
    }

    // ---- value-type flags (DR-0016) ----

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn otp_flags_absent_yield_empty_meta() {
        // Foreign flags pass through untouched (only --type/--otp-* are taken).
        let (meta, rest) = take_otp_flags(&s(&["KEY", "--soft-ttl", "1h"])).unwrap();
        assert!(meta.is_empty());
        assert_eq!(rest, s(&["KEY", "--soft-ttl", "1h"]));
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
    fn kv_set_rejects_type_otp_and_steers_to_define() {
        // DR-0016: value types live on definitions; `kv set` is opaque-only.
        for flags in [
            vec!["OTP", "--type", "otp", "SEED"],
            vec!["OTP", "--type=otp", "SEED"],
            vec!["OTP", "--otp-digits", "8", "SEED"],
            vec!["OTP", "--otp-period=30", "SEED"],
            vec!["OTP", "--otp-algorithm", "sha256", "SEED"],
        ] {
            let err = parse_kv_set(&s(&flags), "default", false, no_stdin).unwrap_err();
            assert!(
                err.contains("kv define"),
                "expected steer to `kv define`, got: {err}"
            );
        }
    }

    #[test]
    fn kv_define_with_type_otp_attaches_meta() {
        let req = parse_kv_define(
            &s(&["OTP", "--type", "otp", "--source", "op://vault/item/field"]),
            "default",
        )
        .unwrap();
        match req {
            Request::KvDefine {
                key, argv, meta, ..
            } => {
                assert_eq!(key, "default/OTP");
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
        let err = parse_kv_define(
            &s(&[
                "OTP",
                "--type",
                "otp",
                "--source",
                "op://vault/item/field?attribute=otp",
            ]),
            "default",
        )
        .unwrap_err();
        assert!(err.contains("attribute=otp"), "msg: {err}");
    }

    #[test]
    fn kv_define_otp_command_argv_is_not_scanned_for_otp_flags() {
        // A literal `--otp-digits` inside the command argv must NOT be consumed as
        // our flag (everything after --command is the literal program argv).
        let req = parse_kv_define(
            &s(&[
                "OTP",
                "--type",
                "otp",
                "--command",
                "myprog",
                "--otp-digits",
                "8",
            ]),
            "default",
        )
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
    fn plain_set_still_works_unchanged() {
        let req = parse_kv_set(&s(&["K", "v"]), "default", false, no_stdin).unwrap();
        match req {
            Request::KvSet { key, source, .. } => {
                assert_eq!(key, "default/K");
                assert!(matches!(source, SetSource::Static { .. }));
            }
            _ => panic!("expected KvSet"),
        }
    }
}
