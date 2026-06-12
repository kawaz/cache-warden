//! The `cache-warden daemon` group: daemon lifecycle commands.
//!
//! The daemon is isolated under its own group so that lifecycle operations
//! (which start a long-lived process) are not visible at the top level next to
//! the everyday client commands (`kv get`, `status`, ...). Mistyping a daemon
//! command there could spawn a second daemon by accident.
//!
//! Implemented:
//! - `daemon run [--socket PATH]` — start the in-process daemon in the
//!   foreground (DR-0008). Exposed as [`run_foreground`].
//! - `daemon register [--socket PATH] [--label NAME] [--print]` — generate and
//!   install the launchd / systemd service definition (DR-0019). [`register`].
//! - `daemon unregister [--label NAME]` — stop + remove it (DR-0019).
//!   [`unregister`].
//! - `daemon status` — service registration / running state (distinct from the
//!   top-level `status`, which lists cache entries; DR-0019). [`status`].
//!
//! Subcommand routing and `--help` / no-arg handling live in the dispatcher
//! (`main.rs`); these functions are the leaf actions.

use std::path::PathBuf;

use crate::commands::service;
use crate::config::Config;

/// Start the in-process daemon in the foreground (`daemon run`).
///
/// `socket` is the already-resolved control socket path (DR-0010 precedence is
/// applied by the caller); `config` is the loaded daemon configuration that the
/// daemon needs to bind, preload, and serve. Subcommand routing and help/usage
/// handling live in the dispatcher (`main.rs`); this function is the leaf action.
pub fn run_foreground(args: &[String], socket: PathBuf, config: Config) -> Result<(), String> {
    if !args.is_empty() {
        return Err(format!(
            "`daemon run` takes no positional arguments: {args:?}"
        ));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start runtime: {e}"))?;
    rt.block_on(crate::daemon::server::run(socket, config))
        .map_err(|e| format!("daemon error: {e}"))
}

/// Parsed flags for `daemon register` (DR-0019 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterArgs {
    /// `--socket PATH`: bake `--socket PATH` into the service start command so
    /// the service binds the operator's chosen control socket. `None` = omit
    /// (the daemon resolves the default at runtime).
    pub socket: Option<String>,
    /// `--label NAME`: the service label. `None` = the per-OS default.
    pub label: Option<String>,
    /// `--print`: render the definition to stdout instead of installing
    /// (dry-run / audit).
    pub print: bool,
}

/// Parse `daemon register` flags (DR-0019 §1):
/// `[--socket PATH] [--label NAME] [--print]`.
///
/// Pure so the parse is unit-tested without touching the service manager.
/// `--socket` is normally stripped by the top-level parser (it is the global
/// socket flag, valid after any command); this parser still accepts it as a
/// belt-and-suspenders fallback. The register-time socket is baked verbatim into
/// the service start command (DR-0019 §2: explicit beats the resolved default).
pub fn parse_register_args(args: &[String]) -> Result<RegisterArgs, String> {
    let mut out = RegisterArgs::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--socket" {
            let v = args.get(i + 1).ok_or("--socket requires a PATH argument")?;
            out.socket = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--socket=") {
            out.socket = Some(v.to_string());
            i += 1;
        } else if a == "--label" {
            let v = args.get(i + 1).ok_or("--label requires a NAME argument")?;
            out.label = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--label=") {
            out.label = Some(v.to_string());
            i += 1;
        } else if a == "--print" {
            out.print = true;
            i += 1;
        } else {
            return Err(format!("unknown option for `daemon register`: {a}"));
        }
    }
    Ok(out)
}

/// Parsed flags for `daemon unregister` (DR-0019 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnregisterArgs {
    /// `--label NAME`: the service label to remove. `None` = the per-OS default.
    pub label: Option<String>,
}

/// Parse `daemon unregister` flags (DR-0019 §1): `[--label NAME]`.
pub fn parse_unregister_args(args: &[String]) -> Result<UnregisterArgs, String> {
    let mut out = UnregisterArgs::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--label" {
            let v = args.get(i + 1).ok_or("--label requires a NAME argument")?;
            out.label = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--label=") {
            out.label = Some(v.to_string());
            i += 1;
        } else {
            return Err(format!("unknown option for `daemon unregister`: {a}"));
        }
    }
    Ok(out)
}

/// Build the [`service::ServiceDefinition`] for a `daemon register` invocation
/// (DR-0019 §2). Split out from [`register`] so the construction (label / argv /
/// baked config) is unit-testable without a backend.
///
/// - `exe`: the running binary's absolute path (`current_exe()`).
/// - `args`: the parsed register flags.
/// - `config_path`: the register-time resolved config file (`LoadedConfig.path`),
///   baked in as `CACHE_WARDEN_CONFIG` when present.
/// - `log_path`: the launchd log target (ignored by systemd).
fn build_definition(
    exe: &str,
    args: &RegisterArgs,
    config_path: Option<&str>,
    log_path: Option<String>,
) -> service::ServiceDefinition {
    let label = args
        .label
        .clone()
        .unwrap_or_else(|| service::default_label().to_string());
    service::ServiceDefinition::for_daemon(
        exe,
        &label,
        args.socket.as_deref(),
        config_path,
        log_path,
    )
}

/// Execute `daemon register` (DR-0019 §1/§2/§3).
///
/// `config_path` is the register-time resolved config file path (the dispatcher
/// passes `LoadedConfig.path`); it is baked into the definition so the service
/// runs with the same config that was in effect at register time. `cli_socket`
/// is the explicitly-requested `--socket` from the top-level parser (stripped
/// before `args` reaches here); it is baked into the service start command. A
/// `--socket` that reaches `args` (the fallback parse path) takes precedence.
/// With `--print`, the definition is written to stdout and nothing is installed.
pub fn register(
    args: &[String],
    config_path: Option<PathBuf>,
    cli_socket: Option<&str>,
) -> Result<(), String> {
    let mut parsed = parse_register_args(args)?;
    // The global `--socket` (already stripped from `args`) is the usual source;
    // a `--socket` left in `args` (fallback) wins if present.
    if parsed.socket.is_none() {
        parsed.socket = cli_socket.map(str::to_string);
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot resolve own binary path: {e}"))?
        .to_string_lossy()
        .into_owned();
    let cfg = config_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let def = build_definition(&exe, &parsed, cfg.as_deref(), service::default_log_path());

    let backend = service::backend()?;

    if parsed.print {
        // --print: render only, install nothing (audit / dry-run).
        print!("{}", backend.render_definition(&def));
        return Ok(());
    }

    backend.register(&def)?;
    println!(
        "registered {} ({})",
        def.label,
        backend.definition_path(&def.label).display()
    );

    // Linux linger hint (DR-0019 §3): a `systemd --user` service stops at logout
    // unless lingering is enabled. Warn (do not auto-enable: it may need admin).
    #[cfg(target_os = "linux")]
    if service::linger_enabled() == Some(false) {
        eprintln!(
            "cache-warden: hint: `systemd --user` services stop at logout without lingering; \
             run `loginctl enable-linger` to keep the daemon running (DR-0019)"
        );
    }
    Ok(())
}

/// Execute `daemon unregister` (DR-0019 §1): stop + unload + delete the
/// definition. A not-registered label is a no-op (idempotent).
pub fn unregister(args: &[String]) -> Result<(), String> {
    let parsed = parse_unregister_args(args)?;
    let label = parsed
        .label
        .unwrap_or_else(|| service::default_label().to_string());
    let backend = service::backend()?;
    backend.unregister(&label)?;
    println!("unregistered {label}");
    Ok(())
}

/// Execute `daemon status` (DR-0019 §1): print the service registration /
/// running state as a one-screen table.
pub fn status(args: &[String]) -> Result<(), String> {
    // `daemon status` takes only an optional `--label`.
    let parsed = parse_unregister_args(args).map_err(|e| {
        // Reuse the unregister flag parser (same `--label` grammar) but reword
        // the "unknown option" message for this subcommand.
        e.replace("daemon unregister", "daemon status")
    })?;
    let label = parsed
        .label
        .unwrap_or_else(|| service::default_label().to_string());
    let backend = service::backend()?;
    let st = backend.status(&label)?;
    print!("{}", st.render(&label));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::parse("").unwrap()
    }

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn run_foreground_rejects_positional_args() {
        let err = run_foreground(&["extra".into()], PathBuf::from("/x.sock"), cfg()).unwrap_err();
        assert!(err.contains("takes no positional arguments"));
    }

    // ---- register flag parsing (DR-0019 §1) ----

    #[test]
    fn register_args_parse_all_flags_both_forms() {
        let a = parse_register_args(&s(&["--socket", "/tmp/x.sock", "--label", "L", "--print"]))
            .unwrap();
        assert_eq!(a.socket.as_deref(), Some("/tmp/x.sock"));
        assert_eq!(a.label.as_deref(), Some("L"));
        assert!(a.print);

        let b = parse_register_args(&s(&["--socket=/y.sock", "--label=M"])).unwrap();
        assert_eq!(b.socket.as_deref(), Some("/y.sock"));
        assert_eq!(b.label.as_deref(), Some("M"));
        assert!(!b.print);
    }

    #[test]
    fn register_args_empty_is_all_defaults() {
        assert_eq!(parse_register_args(&[]).unwrap(), RegisterArgs::default());
    }

    #[test]
    fn register_args_reject_unknown_and_missing_values() {
        assert!(parse_register_args(&s(&["--bogus"])).is_err());
        assert!(parse_register_args(&s(&["--socket"])).is_err());
        assert!(parse_register_args(&s(&["--label"])).is_err());
    }

    #[test]
    fn unregister_args_parse_label() {
        assert_eq!(
            parse_unregister_args(&s(&["--label", "L"]))
                .unwrap()
                .label
                .as_deref(),
            Some("L")
        );
        assert_eq!(
            parse_unregister_args(&s(&["--label=M"]))
                .unwrap()
                .label
                .as_deref(),
            Some("M")
        );
        assert_eq!(
            parse_unregister_args(&[]).unwrap(),
            UnregisterArgs::default()
        );
        assert!(parse_unregister_args(&s(&["--bogus"])).is_err());
    }

    // ---- definition construction (DR-0019 §2) ----

    #[test]
    fn build_definition_defaults_label_and_bakes_config() {
        let args = RegisterArgs {
            socket: Some("/tmp/x.sock".into()),
            label: None,
            print: false,
        };
        let def = build_definition(
            "/bin/cache-warden",
            &args,
            Some("/home/k/.config/cache-warden/config.toml"),
            None,
        );
        assert_eq!(def.label, service::default_label());
        assert_eq!(
            def.program_args,
            vec![
                "/bin/cache-warden",
                "daemon",
                "run",
                "--socket",
                "/tmp/x.sock"
            ]
        );
        assert_eq!(
            def.env.get("CACHE_WARDEN_CONFIG").map(String::as_str),
            Some("/home/k/.config/cache-warden/config.toml")
        );
    }

    #[test]
    fn build_definition_uses_explicit_label_and_omits_absent_config() {
        let args = RegisterArgs {
            socket: None,
            label: Some("com.example.alt".into()),
            print: false,
        };
        let def = build_definition("/bin/cw", &args, None, None);
        assert_eq!(def.label, "com.example.alt");
        assert_eq!(def.program_args, vec!["/bin/cw", "daemon", "run"]);
        assert!(!def.env.contains_key("CACHE_WARDEN_CONFIG"));
    }
}
