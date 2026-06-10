//! The `cache-warden config` subcommand: inspect and edit the config (DR-0010).
//!
//! - `config show` — print the effective configuration (source path, control
//!   socket, re-auth command, preload entries). The config schema cannot hold
//!   secret values (DR-0010), so there is nothing to redact.
//! - `config path` — print the resolved config file path, or the search order
//!   when no file exists yet.
//! - `config edit` — open the config in `$EDITOR` (creating the directory and
//!   an empty file first if needed).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, LoadedConfig};

/// Dispatch a `config` subcommand.
pub fn run(args: Vec<String>, loaded: &LoadedConfig) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    let tail = if args.is_empty() { &[][..] } else { &args[1..] };
    match sub {
        "show" => {
            ensure_no_extra(tail, "config show")?;
            print!("{}", render_show(loaded));
            Ok(())
        }
        "path" => {
            ensure_no_extra(tail, "config path")?;
            print!("{}", render_path());
            Ok(())
        }
        "edit" => {
            ensure_no_extra(tail, "config edit")?;
            edit()
        }
        "" => Err("config requires a subcommand: show | path | edit".to_string()),
        other => Err(format!("unknown config subcommand: {other}")),
    }
}

fn ensure_no_extra(tail: &[String], who: &str) -> Result<(), String> {
    if tail.is_empty() {
        Ok(())
    } else {
        Err(format!("`{who}` takes no arguments: {tail:?}"))
    }
}

/// Render the effective configuration for `config show`.
///
/// Pure (no I/O) so it is unit-testable. The output is informational text, not
/// a re-parseable config dump.
pub fn render_show(loaded: &LoadedConfig) -> String {
    let mut out = String::new();
    match &loaded.path {
        Some(p) => out.push_str(&format!("config: {}\n", p.display())),
        None => out.push_str("config: (none found; using defaults)\n"),
    }

    match loaded.config.socket_path() {
        Some(p) => out.push_str(&format!("socket: {} (from [daemon].socket)\n", p.display())),
        None => out.push_str(&format!(
            "socket: {} (default)\n",
            super::default_socket_path().display()
        )),
    }

    match loaded.config.auth_command() {
        Some(argv) => out.push_str(&format!("auth command: {argv:?}\n")),
        None => out.push_str("auth command: (none; no re-authentication)\n"),
    }

    let entries = loaded.config.preload_entries();
    if entries.is_empty() {
        out.push_str("preload entries: (none)\n");
    } else {
        out.push_str("preload entries:\n");
        for e in entries {
            let soft = e
                .soft_ttl_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "-".to_string());
            let hard = e
                .hard_ttl_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "  {}: command={:?} soft-ttl={soft} hard-ttl={hard}\n",
                e.name, e.command
            ));
        }
    }
    out
}

/// Render the `config path` output: the resolved file, or the search order.
pub fn render_path() -> String {
    match config::find_config_file() {
        Some(p) => format!("{}\n", p.display()),
        None => {
            let mut out = String::from("no config file found; searched (in order):\n");
            for p in config::config_search_paths() {
                out.push_str(&format!("  {}\n", p.display()));
            }
            out
        }
    }
}

/// The path `config edit` should open: an existing config, or the preferred
/// (highest-priority) creation location.
fn edit_target() -> PathBuf {
    config::find_config_file()
        .or_else(|| config::config_search_paths().into_iter().next())
        .unwrap_or_else(|| PathBuf::from("cache-warden-config.toml"))
}

/// Open the config in `$EDITOR` (or `$VISUAL`), creating the file if absent.
fn edit() -> Result<(), String> {
    let target = edit_target();
    create_if_absent(&target)?;

    let editor = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .ok_or("no $EDITOR (or $VISUAL) set")?;

    let status = Command::new(&editor)
        .arg(&target)
        .status()
        .map_err(|e| format!("failed to launch editor {editor:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("editor exited with status {status}"))
    }
}

/// Create `path` (and its parent dir) as an empty file if it does not exist.
fn create_if_absent(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create config dir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, b"").map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn loaded(text: &str, path: Option<PathBuf>) -> LoadedConfig {
        LoadedConfig {
            path,
            config: Config::parse(text).unwrap(),
        }
    }

    #[test]
    fn show_defaults_reports_no_config_and_no_auth() {
        let l = loaded("", None);
        let out = render_show(&l);
        assert!(out.contains("config: (none found"));
        assert!(out.contains("auth command: (none"));
        assert!(out.contains("preload entries: (none)"));
        assert!(out.contains("(default)"));
    }

    #[test]
    fn show_renders_auth_command_and_socket_source() {
        let l = loaded(
            r#"[daemon]
socket = "/run/cw.sock"

[auth]
command = ["reauth"]
"#,
            Some(PathBuf::from("/etc/cache-warden/config.toml")),
        );
        let out = render_show(&l);
        assert!(out.contains("config: /etc/cache-warden/config.toml"));
        assert!(out.contains("socket: /run/cw.sock (from [daemon].socket)"));
        assert!(out.contains(r#"auth command: ["reauth"]"#));
    }

    #[test]
    fn show_lists_preload_entries() {
        let l = loaded(
            r#"[kv.DB]
command = ["op", "read", "op://v/i"]
soft-ttl = "1h"
hard-ttl = "24h"
"#,
            None,
        );
        let out = render_show(&l);
        assert!(out.contains("preload entries:"));
        assert!(out.contains("DB: command="));
        assert!(out.contains("soft-ttl=3600s"));
        assert!(out.contains("hard-ttl=86400s"));
    }

    #[test]
    fn run_rejects_unknown_subcommand() {
        let l = loaded("", None);
        assert!(run(vec!["bogus".into()], &l).is_err());
    }

    #[test]
    fn run_requires_a_subcommand() {
        let l = loaded("", None);
        assert!(run(vec![], &l).is_err());
    }

    #[test]
    fn show_rejects_extra_args() {
        let l = loaded("", None);
        assert!(run(vec!["show".into(), "extra".into()], &l).is_err());
    }
}
