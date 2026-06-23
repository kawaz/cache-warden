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

use std::path::{Path, PathBuf};

use stable_which::{Candidate, PathTag, ScoringPolicy, resolve_stable_path};

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
    // Block the shutdown signals (SIGINT / SIGTERM) on this thread *before* the
    // runtime spawns its worker threads, so every worker — and the dedicated
    // `sigwait` thread — inherits the block. The daemon then consumes those
    // signals synchronously via `sigwait` (see `server::wait_for_shutdown`)
    // rather than through tokio's async signal driver, which is unreliable on
    // macOS once `ptrace(PT_DENY_ATTACH)` has run (`server::block_shutdown_signals`).
    #[cfg(unix)]
    if !crate::daemon::server::block_shutdown_signals() {
        eprintln!(
            "cache-warden: warning: could not block shutdown signals; \
             SIGINT/SIGTERM handling may be degraded"
        );
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Belt-and-suspenders: re-block on every worker thread explicitly, so a
        // worker can never take a shutdown signal via the default disposition
        // (which would kill the process before the socket-cleanup path runs)
        // even if mask inheritance ever changes.
        .on_thread_start(|| {
            #[cfg(unix)]
            {
                let _ = crate::daemon::server::block_shutdown_signals();
            }
        })
        .build()
        .map_err(|e| format!("failed to start runtime: {e}"))?;
    match rt.block_on(crate::daemon::server::run(socket, config)) {
        Ok(()) => Ok(()),
        Err(crate::daemon::server::ServerError::ShutdownDuringStartup) => {
            // A shutdown signal arrived while the daemon was still starting up.
            // This is an intentional, clean exit — force immediate process
            // termination via _exit so the tokio runtime does not wait for the
            // still-running startup blocking task (which may block for many
            // seconds — e.g. a preload command with a long timeout). The
            // watchdog in spawn_shutdown_notifier would eventually do the same,
            // but exiting here first is cleaner and faster (DR-0023 Phase 1).
            // SAFETY: `_exit` immediately terminates the process. All required
            // cleanup (control socket removal, shutdown_tx send) already ran
            // inside `server::run` before returning this variant.
            #[cfg(unix)]
            unsafe {
                libc::_exit(0);
            }
            #[cfg(not(unix))]
            Ok(())
        }
        Err(e) => Err(format!("daemon error: {e}")),
    }
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
    /// `--executable PATH`: an explicit override for the binary path baked into
    /// the service definition (DR-0019 §2.5; warden-compatible). `None` = resolve
    /// the running binary via `stable-which`. When set, the path is used as-is
    /// (only existence-validated) — the operator takes responsibility for its
    /// stability.
    pub executable: Option<String>,
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
        } else if a == "--executable" {
            let v = args
                .get(i + 1)
                .ok_or("--executable requires a PATH argument")?;
            out.executable = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--executable=") {
            out.executable = Some(v.to_string());
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

/// Whether a `stable-which` resolution settled on a *non-stable* path (DR-0019
/// §2.5): the best candidate is still a dev build output (`target/release`) or an
/// ephemeral/temp location, i.e. no stable PATH symlink points at this binary.
///
/// Pure (operates on the candidate's tags) so the warn branch is unit-testable
/// without a filesystem. A `true` result means `register` should warn but still
/// proceed with the dev path (DR-0019 §2.5: do not block development).
fn is_unstable_resolution(tags: &[PathTag]) -> bool {
    tags.iter()
        .any(|t| matches!(t, PathTag::BuildOutput | PathTag::Ephemeral))
}

/// The outcome of resolving the binary path to bake into the service definition
/// (DR-0019 §2.5): the program path plus the enclosing `.app` bundle (macOS TCC
/// layer) if any, and a human-facing warning when the path is unstable.
#[derive(Debug)]
struct ResolvedExe {
    /// The path to bake as `ProgramArguments[0]` / `ExecStart`.
    program: String,
    /// The enclosing `.app` bundle, when the resolved binary lives in one
    /// (`<bundle>.app/Contents/MacOS/<binary>`). Drives `AssociatedBundleIdentifiers`.
    app_bundle: Option<PathBuf>,
    /// A stderr warning to emit (dev/ephemeral path with no stable candidate).
    warning: Option<String>,
}

/// Resolve the binary path to bake into the service definition (DR-0019 §2.5).
///
/// - `explicit`: an `--executable PATH` override. Used as-is (existence-checked
///   only); the operator owns its stability (warden-compatible).
/// - otherwise: `stable_which::resolve_stable_path(current_exe, SameBinary)`
///   picks the most stable PATH symlink that points at the same binary. A
///   dev/ephemeral-only result is kept but flagged with a warning.
///
/// The resolved path is canonicalized to detect a `.app/Contents/MacOS/` bundle
/// (the macOS TCC layer); when found, the `.app` bundle path is returned so the
/// caller can set `AssociatedBundleIdentifiers`. On macOS the canonical in-bundle
/// path is used as the program path (stable across `brew upgrade`).
fn resolve_program_exe(
    current_exe: PathBuf,
    explicit: Option<&str>,
) -> Result<ResolvedExe, String> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("--executable path does not exist: {p}"));
        }
        let (program, app_bundle) = with_app_layer(&path, p.to_string());
        return Ok(ResolvedExe {
            program,
            app_bundle,
            warning: None,
        });
    }

    let candidate: Candidate = resolve_stable_path(&current_exe, ScoringPolicy::SameBinary)
        .map_err(|e| format!("cannot resolve a stable binary path: {e}"))?;
    let warning = if is_unstable_resolution(&candidate.tags) {
        Some(format!(
            "cache-warden: warning: no stable install path found for the daemon binary; \
             baking the development path {} into the service (it will break on `cargo clean` \
             / rebuild). Install via Homebrew or pass `--executable PATH` for a stable path \
             (DR-0019).",
            candidate.path.display()
        ))
    } else {
        None
    };
    let (program, app_bundle) = with_app_layer(
        &candidate.path,
        candidate.path.to_string_lossy().into_owned(),
    );
    Ok(ResolvedExe {
        program,
        app_bundle,
        warning,
    })
}

/// Apply the macOS `.app` layer to a resolved path (DR-0019 §2.5): canonicalize
/// it and, if it sits at `<bundle>.app/Contents/MacOS/<binary>`, return the
/// canonical in-bundle program path plus the `.app` bundle directory. Otherwise
/// return `fallback` unchanged with no bundle (bare binary / Linux).
fn with_app_layer(path: &Path, fallback: String) -> (String, Option<PathBuf>) {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(app) = service::app_bundle_path(&canonical) {
        (canonical.to_string_lossy().into_owned(), Some(app))
    } else {
        (fallback, None)
    }
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
///
/// - `app_bundle`: the enclosing `.app` bundle of the resolved binary, when any.
///   `Some(_)` sets `AssociatedBundleIdentifiers = label` so TCC anchors on the
///   Bundle ID (DR-0019 §2.5, DR-0020 §1); `None` (bare binary / Linux) omits it.
fn build_definition(
    exe: &str,
    args: &RegisterArgs,
    config_path: Option<&str>,
    log_path: Option<String>,
    app_bundle: Option<&Path>,
) -> service::ServiceDefinition {
    let label = args
        .label
        .clone()
        .unwrap_or_else(|| service::default_label().to_string());
    let mut def = service::ServiceDefinition::for_daemon(
        exe,
        &label,
        args.socket.as_deref(),
        config_path,
        log_path,
    );
    if app_bundle.is_some() {
        // The Bundle ID baked into AssociatedBundleIdentifiers is the service
        // label (the reverse-DNS id that also names the plist). DR-0020 §1.
        def.associated_bundle_identifiers = Some(label);
    }
    def
}

/// Return `true` when the config has at least one `op`-sourced kv entry or
/// `op`-kind authsock source, indicating that Full Disk Access is needed for
/// `op` CLI invocations at runtime.
#[cfg(target_os = "macos")]
fn has_op_sources(config: &Config) -> bool {
    let has_kv_op = config
        .kv
        .values()
        .any(|entry| entry.source.as_deref() == Some("op"));
    let has_authsock_op = config
        .authsock
        .sources
        .values()
        .any(|src| src.kind.as_str() == "op");
    has_kv_op || has_authsock_op
}

/// Execute `daemon register` (DR-0019 §1/§2/§3).
///
/// `config` is the loaded configuration (used to check whether the FDA setup
/// flow is needed). `config_path` is the register-time resolved config file
/// path (the dispatcher passes `LoadedConfig.path`); it is baked into the
/// definition so the service runs with the same config that was in effect at
/// register time. `cli_socket` is the explicitly-requested `--socket` from the
/// top-level parser (stripped before `args` reaches here); it is baked into
/// the service start command. A `--socket` that reaches `args` (the fallback
/// parse path) takes precedence. With `--print`, the definition is written to
/// stdout and nothing is installed.
pub fn register(
    args: &[String],
    config: Config,
    config_path: Option<PathBuf>,
    cli_socket: Option<&str>,
) -> Result<(), String> {
    let mut parsed = parse_register_args(args)?;
    // The global `--socket` (already stripped from `args`) is the usual source;
    // a `--socket` left in `args` (fallback) wins if present.
    if parsed.socket.is_none() {
        parsed.socket = cli_socket.map(str::to_string);
    }
    let current_exe =
        std::env::current_exe().map_err(|e| format!("cannot resolve own binary path: {e}"))?;
    let resolved = resolve_program_exe(current_exe, parsed.executable.as_deref())?;
    if let Some(w) = &resolved.warning {
        eprintln!("{w}");
    }
    let cfg = config_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let def = build_definition(
        &resolved.program,
        &parsed,
        cfg.as_deref(),
        service::default_log_path(),
        resolved.app_bundle.as_deref(),
    );

    let backend = service::backend()?;

    if parsed.print {
        // --print: render only, install nothing (audit / dry-run).
        print!("{}", backend.render_definition(&def));
        return Ok(());
    }

    // macOS FDA setup flow: if the config uses op sources, the daemon needs
    // Full Disk Access so that `op` can run from a launchd agent. Walk the
    // user through the System Settings grant flow when FDA is not yet set.
    #[cfg(target_os = "macos")]
    {
        if has_op_sources(&config) {
            let self_check_args = &["internal", "fda-check", "--raw"];
            match macos_tcc::current_app_bundle() {
                Some(app_path) => {
                    // Try up to 3 times in case the first probe fails transiently.
                    let mut fda_state = macos_tcc::AuthState::Unknown;
                    for _ in 0..3 {
                        match macos_tcc::check_via_app_bundle(
                            macos_tcc::Permission::FullDiskAccess,
                            &app_path,
                            self_check_args,
                        ) {
                            Ok(state) => {
                                fda_state = state;
                                break;
                            }
                            Err(_) => {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                        }
                    }
                    if fda_state != macos_tcc::AuthState::Granted {
                        eprintln!("cache-warden: Full Disk Access の設定が必要です。");
                        eprintln!(
                            "cache-warden は 1Password CLI (op) を使ってシークレットを取得するため、"
                        );
                        eprintln!("フルディスクアクセスの権限が必要です。");
                        eprintln!("フルディスクアクセスの設定画面を開きます...");
                        let _ = macos_tcc::open_settings(macos_tcc::Permission::FullDiskAccess);
                        eprintln!("「CacheWarden」を ON にしてから Enter キーを押すか、");
                        eprintln!(
                            "設定が完了するまでお待ちください。(スキップするには Enter を押してください)"
                        );
                        let outcome = macos_tcc::wait_for_grant(
                            macos_tcc::Permission::FullDiskAccess,
                            &app_path,
                            self_check_args,
                            macos_tcc::WaitOpts::default(),
                        );
                        match outcome {
                            macos_tcc::WaitOutcome::Granted => {
                                eprintln!("cache-warden: Full Disk Access が許可されました。");
                                // Close System Settings.
                                let _ = std::process::Command::new("osascript")
                                    .args(["-e", "tell application \"System Settings\" to quit"])
                                    .output();
                            }
                            macos_tcc::WaitOutcome::UserSkipped
                            | macos_tcc::WaitOutcome::TimedOut => {
                                eprintln!(
                                    "cache-warden: 警告: Full Disk Access なしで続行します。\
                                     op コマンドが失敗する可能性があります。"
                                );
                            }
                        }
                    }
                }
                None => {
                    eprintln!(
                        "cache-warden: warning: not running from a .app bundle; \
                         skipping FDA check (run from /Applications/CacheWarden.app \
                         for the FDA setup flow)"
                    );
                }
            }
        }
    }
    // Suppress unused-variable warning on non-macOS.
    #[cfg(not(target_os = "macos"))]
    let _ = &config;

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
            executable: None,
        };
        let def = build_definition(
            "/bin/cache-warden",
            &args,
            Some("/home/k/.config/cache-warden/config.toml"),
            None,
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
            executable: None,
        };
        let def = build_definition("/bin/cw", &args, None, None, None);
        assert_eq!(def.label, "com.example.alt");
        assert_eq!(def.program_args, vec!["/bin/cw", "daemon", "run"]);
        assert!(!def.env.contains_key("CACHE_WARDEN_CONFIG"));
        // No .app bundle → no AssociatedBundleIdentifiers.
        assert!(def.associated_bundle_identifiers.is_none());
    }

    // ---- --executable flag parsing (DR-0019 §2.5) ----

    #[test]
    fn register_args_parse_executable_both_forms() {
        let a =
            parse_register_args(&s(&["--executable", "/opt/homebrew/bin/cache-warden"])).unwrap();
        assert_eq!(
            a.executable.as_deref(),
            Some("/opt/homebrew/bin/cache-warden")
        );
        let b = parse_register_args(&s(&[
            "--executable=/Applications/CacheWarden.app/Contents/MacOS/cache-warden",
        ]))
        .unwrap();
        assert_eq!(
            b.executable.as_deref(),
            Some("/Applications/CacheWarden.app/Contents/MacOS/cache-warden")
        );
    }

    #[test]
    fn register_args_executable_requires_value() {
        assert!(parse_register_args(&s(&["--executable"])).is_err());
    }

    // ---- unstable-resolution warning branch (DR-0019 §2.5) ----

    #[test]
    fn unstable_resolution_flags_build_output_and_ephemeral() {
        // A dev build output / ephemeral path → unstable → warn.
        assert!(is_unstable_resolution(&[
            PathTag::Input,
            PathTag::BuildOutput
        ]));
        assert!(is_unstable_resolution(&[PathTag::Ephemeral]));
    }

    #[test]
    fn unstable_resolution_clears_for_stable_path() {
        // A stable PATH symlink that is the same binary → no warning.
        assert!(!is_unstable_resolution(&[
            PathTag::InPathEnv(0),
            PathTag::SameCanonical
        ]));
        // ManagedBy / Shim are "warning-ish" for stability but still a real
        // install path, not a dev artifact → no warn branch here.
        assert!(!is_unstable_resolution(&[PathTag::ManagedBy(
            "mise".into()
        )]));
        assert!(!is_unstable_resolution(&[PathTag::Shim]));
    }

    // ---- --executable: bundle id wiring via build_definition (DR-0019 §2.5) ----

    #[test]
    fn build_definition_sets_bundle_id_when_app_bundle_present() {
        let args = RegisterArgs {
            socket: None,
            label: None,
            print: false,
            executable: None,
        };
        let bundle = PathBuf::from("/Applications/CacheWarden.app");
        let def = build_definition(
            "/Applications/CacheWarden.app/Contents/MacOS/cache-warden",
            &args,
            None,
            None,
            Some(bundle.as_path()),
        );
        // AssociatedBundleIdentifiers is the label (reverse-DNS id).
        assert_eq!(
            def.associated_bundle_identifiers.as_deref(),
            Some(service::default_label())
        );
    }

    // ---- resolve_program_exe with explicit --executable (DR-0019 §2.5) ----

    #[test]
    fn resolve_program_exe_explicit_existing_path_used_as_is() {
        // An explicit, existing, non-.app path is baked verbatim with no bundle.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_string_lossy().into_owned();
        let r = resolve_program_exe(PathBuf::from("/unused"), Some(&p)).unwrap();
        // A bare temp file is not a .app → no bundle, no warning.
        assert!(r.app_bundle.is_none());
        assert!(r.warning.is_none());
        // The program path is the explicit path (possibly canonicalized if it
        // happened to be a symlink; here it is a plain file so it stays as-is).
        assert_eq!(r.program, p);
    }

    #[test]
    fn resolve_program_exe_explicit_missing_path_errors() {
        let err = resolve_program_exe(
            PathBuf::from("/unused"),
            Some("/no/such/cache-warden-binary-xyz"),
        )
        .unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }
}
