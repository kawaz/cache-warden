//! CLI subcommands: the daemon (`run`) and the management client (`kv`,
//! `status`, `ping`).
//!
//! Argument parsing is hand-rolled (DR-0002 keeps the dependency surface small;
//! no clap). The parse step is a pure function ([`parse_kv_set`] etc. and the
//! socket resolver) so it can be unit-tested without touching a socket.

pub mod client;
pub mod config_cmd;

use std::path::PathBuf;

use crate::protocol::wire::{Request, SetSource};
use crate::protocol::{decode_b64, encode_b64, parse_duration};

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
/// Grammar:
/// `<KEY> (--value V | --value-stdin | --command ARGV...) [--soft-ttl D] [--hard-ttl D]`
///
/// `stdin` provides the bytes for `--value-stdin`; it is read only when that
/// flag is present (kept as a parameter so the parse is testable).
pub fn parse_kv_set(
    args: &[String],
    stdin: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> Result<Request, String> {
    let mut key: Option<String> = None;
    let mut value: Option<Vec<u8>> = None;
    let mut value_stdin = false;
    let mut command: Option<Vec<String>> = None;
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
            "--command" => {
                // Everything after --command is the argv.
                let argv: Vec<String> = args[i + 1..].to_vec();
                if argv.is_empty() {
                    return Err("--command requires at least a program".to_string());
                }
                command = Some(argv);
                i = args.len(); // consume the rest
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
    let sources = [value.is_some(), value_stdin, command.is_some()];
    let chosen = sources.iter().filter(|b| **b).count();
    if chosen == 0 {
        return Err("kv set requires one of --value, --value-stdin, or --command".to_string());
    }
    if chosen > 1 {
        return Err("kv set accepts only one of --value, --value-stdin, --command".to_string());
    }

    let source = if let Some(argv) = command {
        SetSource::Command { argv }
    } else {
        let bytes = if value_stdin {
            stdin().map_err(|e| format!("failed to read stdin: {e}"))?
        } else {
            value.unwrap()
        };
        SetSource::Static {
            value_b64: encode_b64(&bytes),
        }
    };

    Ok(Request::KvSet {
        key,
        source,
        soft_ttl_secs,
        hard_ttl_secs,
    })
}

/// Parse `kv get|del <KEY>` into the corresponding [`Request`].
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
        "get" => Ok(Request::KvGet { key }),
        "del" => Ok(Request::KvDel { key }),
        _ => Err(format!("unknown kv subcommand: {verb}")),
    }
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
            Request::KvSet { key, source, .. } => {
                assert_eq!(key, "DB");
                match source {
                    SetSource::Static { value_b64 } => {
                        assert_eq!(decode_b64(&value_b64).unwrap(), b"pw")
                    }
                    _ => panic!("expected static"),
                }
            }
            _ => panic!("expected KvSet"),
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
    fn kv_set_command_consumes_rest_as_argv() {
        let req = parse_kv_set(
            &[
                "TOK".into(),
                "--soft-ttl".into(),
                "1h".into(),
                "--command".into(),
                "op".into(),
                "read".into(),
                "op://v/i".into(),
            ],
            no_stdin,
        )
        .unwrap();
        match req {
            Request::KvSet {
                source: SetSource::Command { argv },
                soft_ttl_secs,
                ..
            } => {
                assert_eq!(argv, vec!["op", "read", "op://v/i"]);
                assert_eq!(soft_ttl_secs, Some(3600));
            }
            _ => panic!("expected command"),
        }
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
    fn kv_get_and_del_parse() {
        assert_eq!(
            parse_kv_single_key("get", &["K".into()]).unwrap(),
            Request::KvGet { key: "K".into() }
        );
        assert_eq!(
            parse_kv_single_key("del", &["K".into()]).unwrap(),
            Request::KvDel { key: "K".into() }
        );
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
}
