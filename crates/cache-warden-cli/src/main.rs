//! cache-warden CLI: the daemon group (`daemon run`) and its management client.
//!
//! Hand-rolled argument dispatch (no clap; DR-0002 keeps dependencies small).
//! `daemon run` starts the in-process daemon (DR-0008); the other subcommands
//! are one-shot control-socket clients (see [`commands::client`]).

use std::io::Read as _;
use std::path::PathBuf;
use std::process;

mod commands;
mod config;
mod daemon;
mod defs;
mod help;
mod mode;
mod namespace;
mod otp_type;
mod protocol;
mod refs;
mod totp;

use commands::client;
use protocol::wire::{OkPayload, Response};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = "cache-warden";

/// Print a response for a client command, returning an exit code.
///
/// Success payloads are rendered for human use (the secret value of `get` is
/// written raw to stdout); a failure response is printed to stderr.
fn render_response(resp: Response) -> Result<(), String> {
    match resp {
        Response::Ok(ok) => {
            match ok.payload {
                OkPayload::Pong { .. } => println!("pong"),
                OkPayload::Set { .. } => println!("ok"),
                OkPayload::Defined { .. } => println!("defined"),
                OkPayload::Deleted { deleted } => {
                    println!("{}", if deleted { "deleted" } else { "not found" })
                }
                OkPayload::Pinned {
                    pin_remaining_secs, ..
                } => println!("pinned for {pin_remaining_secs}s"),
                OkPayload::Unpinned { unpinned } => {
                    println!("{}", if unpinned { "unpinned" } else { "not found" })
                }
                OkPayload::List { keys } => {
                    for k in keys {
                        println!("{k}");
                    }
                }
                OkPayload::Get { value_b64 } => {
                    let bytes = commands::decode_get_value(&value_b64)?;
                    use std::io::Write as _;
                    std::io::stdout()
                        .write_all(&bytes)
                        .map_err(|e| e.to_string())?;
                }
                // A value-free dry-run get is dispatched by `dispatch_kv_get`,
                // not this generic renderer; surface it defensively if it ever
                // reaches here (e.g. a future caller wires it through).
                OkPayload::GetVerified { state, .. } => {
                    println!("verified ({state}); no value (dry-run)");
                }
                OkPayload::Status {
                    pid,
                    version,
                    socket,
                    entries,
                } => {
                    println!("daemon: {NAME} {version} (pid {pid})");
                    println!("socket: {socket}");
                    if entries.is_empty() {
                        println!("entries: (none)");
                    } else {
                        println!("entries:");
                        for e in entries {
                            let attrs = format_entry_attrs(&e);
                            println!("  {} [{}] ({})", e.name, e.state, attrs.join(", "));
                        }
                    }
                }
            }
            Ok(())
        }
        Response::Err(e) => Err(format!(
            "{}: {}",
            error_kind_str(&e.error.kind),
            e.error.message
        )),
    }
}

fn error_kind_str(kind: &protocol::wire::ErrorKind) -> &'static str {
    use protocol::wire::ErrorKind::*;
    match kind {
        BadRequest => "bad request",
        NotFound => "not found",
        AuthFailed => "auth failed",
        NotRegenerable => "not regenerable",
        HardExpired => "hard expired",
        UpstreamFailed => "upstream failed",
        Internal => "internal error",
    }
}

/// Run a client command (connect, exchange one request/response, render).
fn run_client(socket: &std::path::Path, req: &protocol::wire::Request) -> Result<(), String> {
    let resp = client::round_trip(socket, req)?;
    render_response(resp)
}

/// A CLI failure: either a plain message (printed as `cache-warden: <msg>`) or
/// a usage error that should print the offending level's help to stderr.
///
/// Both exit non-zero. The distinction controls *what* is shown: a leaf command
/// invoked without its required arguments is a usage error and prints that
/// leaf's full help (so the user sees the accepted flags inline); other failures
/// just print their message.
enum CliError {
    /// Plain message; rendered as `cache-warden: <msg>`.
    Message(String),
    /// `<msg>` followed by the given level's help, both to stderr. The help is
    /// held as a constructor (not a built [`help::HelpSpec`]) so the error stays
    /// small and is only rendered on the failure path.
    Usage {
        msg: String,
        help: fn() -> help::HelpSpec,
    },
}

impl From<String> for CliError {
    fn from(msg: String) -> Self {
        CliError::Message(msg)
    }
}

/// A leaf-command parse result, lifting a `Result<_, String>` into a usage error
/// carrying that leaf's help page.
fn or_usage<T>(r: Result<T, String>, help: fn() -> help::HelpSpec) -> Result<T, CliError> {
    r.map_err(|msg| CliError::Usage { msg, help })
}

fn run() -> Result<(), CliError> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // No arguments at the top level: show help, exit 0 — the same contract as
    // every other group level (kv / config / daemon).
    if args.is_empty() {
        println!("{}", help::top().render());
        return Ok(());
    }

    // Top-level --version takes precedence (a bare `--version` is not "help").
    if args[0] == "--version" {
        println!("{NAME} {VERSION}");
        return Ok(());
    }
    // Top-level --help (only when it leads; deeper `--help` is handled per level).
    if args[0] == "--help" {
        println!("{}", help::top().render());
        return Ok(());
    }

    let command = args[0].clone();
    let tail = &args[1..];

    // Hidden internal subcommand: the daemon re-executes its own binary with
    // this to fetch an op item's private-key PEM (it calls op with --format json
    // and prints the extracted `.value`). Dispatched before config loading and
    // socket resolution, which it does not need. Never shown in help.
    if command == cache_warden_authsock::OP_PRIVATE_KEY_SUBCOMMAND {
        return commands::op_private_key::run(tail).map_err(CliError::Message);
    }

    // Resolve --socket (anywhere in the tail) once; None means "not on the CLI".
    let (cli_socket, rest) = commands::take_socket_flag(tail)?;

    // Load the config (or defaults) up front: every command needs the resolved
    // socket, and `daemon run` / `config` need the rest of it (DR-0010).
    let loaded = config::load().map_err(|e| e.to_string())?;
    // `daemon register` bakes the *explicitly requested* socket into the service
    // definition (not the resolved default), so keep the pre-resolution CLI value
    // for it before `resolve_socket` consumes it.
    let cli_socket_for_daemon = cli_socket.clone();
    let socket = commands::resolve_socket(cli_socket, loaded.config.socket_path());

    match command.as_str() {
        "daemon" => dispatch_daemon(
            &rest,
            socket,
            loaded.config,
            loaded.path,
            cli_socket_for_daemon,
        ),
        "config" => dispatch_config(&rest, &loaded),
        "ping" => Ok(run_client(&socket, &protocol::wire::Request::Ping)?),
        "status" => dispatch_status(&rest, &socket, &loaded.config),
        "kv" => dispatch_kv(&rest, &socket, &loaded.config),
        "run" => dispatch_run(&rest, &socket, &loaded.config),
        "inject" => dispatch_inject(&rest, &socket, &loaded.config),
        "--help" | "--version" => unreachable!("handled above"),
        other => Err(CliError::Message(format!(
            "unknown command: {other} (try `{NAME} --help`)"
        ))),
    }
}

/// Dispatch the `daemon` group.
///
/// `config_path` is the resolved config file the run-time loader found
/// (`LoadedConfig.path`); `daemon register` bakes it into the service definition
/// so the installed service uses the same config in effect at register time
/// (DR-0019 §2). `cli_socket` is the *explicitly requested* `--socket` (already
/// stripped from `rest` by the top-level parser, like every other command); only
/// `register` consumes it, baking it into the service start command. A `None`
/// means no `--socket` was given, so the service resolves the default at runtime.
fn dispatch_daemon(
    rest: &[String],
    socket: PathBuf,
    config: config::Config,
    config_path: Option<PathBuf>,
    cli_socket: Option<PathBuf>,
) -> Result<(), CliError> {
    // Group help: no subcommand, or a `--help` anywhere => stdout, exit 0.
    if rest.is_empty() {
        println!("{}", help::daemon().render());
        return Ok(());
    }
    if rest[0] == "--help" {
        println!("{}", help::daemon().render());
        return Ok(());
    }
    let tail = &rest[1..];
    match rest[0].as_str() {
        "run" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_run().render());
                return Ok(());
            }
            or_usage(
                commands::daemon_cmd::run_foreground(tail, socket, config),
                help::daemon_run,
            )
        }
        "register" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_register().render());
                return Ok(());
            }
            let sock = cli_socket.map(|p| p.to_string_lossy().into_owned());
            or_usage(
                commands::daemon_cmd::register(tail, config_path, sock.as_deref()),
                help::daemon_register,
            )
        }
        "unregister" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_unregister().render());
                return Ok(());
            }
            or_usage(
                commands::daemon_cmd::unregister(tail),
                help::daemon_unregister,
            )
        }
        "status" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_status().render());
                return Ok(());
            }
            or_usage(commands::daemon_cmd::status(tail), help::daemon_status)
        }
        other => Err(CliError::Message(format!(
            "unknown daemon subcommand: {other} (try `{NAME} daemon --help`)"
        ))),
    }
}

/// Dispatch the `config` group.
fn dispatch_config(rest: &[String], loaded: &config::LoadedConfig) -> Result<(), CliError> {
    if rest.is_empty() {
        println!("{}", help::config().render());
        return Ok(());
    }
    if rest[0] == "--help" {
        println!("{}", help::config().render());
        return Ok(());
    }
    let sub = rest[0].as_str();
    let tail = &rest[1..];
    let leaf_help: fn() -> help::HelpSpec = match sub {
        "show" => help::config_show,
        "path" => help::config_path,
        "edit" => help::config_edit,
        other => {
            return Err(CliError::Message(format!(
                "unknown config subcommand: {other} (try `{NAME} config --help`)"
            )));
        }
    };
    if help::wants_help(tail) {
        println!("{}", leaf_help().render());
        return Ok(());
    }
    or_usage(commands::config_cmd::run(sub, tail, loaded), leaf_help)
}

/// Resolve the reveal/dry-run mode from CLI flags (`mode_flag`), the
/// `CACHE_WARDEN_DRY_RUN` env var, and `[cli].default-mode` (DR-0015 §4).
fn resolve_cli_mode(
    mode_flag: Option<mode::ModeFlag>,
    config: &config::Config,
) -> Result<mode::Mode, String> {
    let env = mode::env_dry_run_is_set()?;
    Ok(mode::resolve_mode(
        mode_flag,
        env,
        config.cli_default_mode(),
    ))
}

/// Dispatch `cache-warden status [--namespace NS] [--all]`
/// (DR-0017 §2).
///
/// Entries are namespace-filtered client-side exactly like `kv list`: by
/// default only the current namespace is shown (names with the `NS/` prefix
/// stripped); `--all` shows every entry under its composed `NS/KEY`
/// name (internal daemon keys included, verbatim).
fn dispatch_status(
    rest: &[String],
    socket: &std::path::Path,
    config: &config::Config,
) -> Result<(), CliError> {
    let (ns_flag, rest) = namespace::take_namespace_flag(rest).map_err(CliError::Message)?;
    let ns =
        namespace::resolve_namespace(ns_flag, namespace::env_namespace(), config.cli_namespace())
            .map_err(CliError::Message)?;
    let mut all = false;
    for a in &rest {
        match a.as_str() {
            "--all" => all = true,
            other => {
                return Err(CliError::Message(format!(
                    "unknown argument for `status`: {other}"
                )));
            }
        }
    }

    let resp = client::round_trip(socket, &protocol::wire::Request::Status)?;
    let resp = match resp {
        Response::Ok(mut ok) => {
            if let OkPayload::Status { entries, .. } = &mut ok.payload {
                let prefix = format!("{ns}/");
                entries.retain(|e| all || e.name.starts_with(&prefix));
                if !all {
                    for e in entries.iter_mut() {
                        if let Some(stripped) = e.name.strip_prefix(&prefix) {
                            e.name = stripped.to_string();
                        }
                    }
                }
            }
            Response::Ok(ok)
        }
        err => err,
    };
    Ok(render_response(resp)?)
}

/// Dispatch the `kv` group.
fn dispatch_kv(
    rest: &[String],
    socket: &std::path::Path,
    config: &config::Config,
) -> Result<(), CliError> {
    if rest.is_empty() {
        println!("{}", help::kv().render());
        return Ok(());
    }
    if rest[0] == "--help" {
        println!("{}", help::kv().render());
        return Ok(());
    }
    let sub = rest[0].as_str();
    let kv_args = &rest[1..];

    let leaf_help: fn() -> help::HelpSpec = match sub {
        "define" => help::kv_define,
        "set" => help::kv_set,
        "get" => help::kv_get,
        "del" => help::kv_del,
        "list" => help::kv_list,
        "pin" => help::kv_pin,
        "unpin" => help::kv_unpin,
        other => {
            return Err(CliError::Message(format!(
                "unknown kv subcommand: {other} (try `{NAME} kv --help`)"
            )));
        }
    };
    if help::wants_help(kv_args) {
        println!("{}", leaf_help().render());
        return Ok(());
    }

    // Resolve the namespace once for every kv verb (DR-0017 §4):
    // --namespace flag > CACHE_WARDEN_NAMESPACE > [cli].namespace > "default".
    let (ns_flag, kv_args) = or_usage(namespace::take_namespace_flag(kv_args), leaf_help)?;
    let ns = or_usage(
        namespace::resolve_namespace(ns_flag, namespace::env_namespace(), config.cli_namespace()),
        leaf_help,
    )?;
    let kv_args = kv_args.as_slice();

    // `define` has two modes (single vs. `--defs` batch), so it is dispatched
    // specially before the single-request path below.
    if sub == "define" {
        let plan = or_usage(commands::parse_kv_define_plan(kv_args, &ns), leaf_help)?;
        return match plan {
            commands::DefinePlan::Single(req) => Ok(run_client(socket, &req)?),
            commands::DefinePlan::Defs(files) => run_define_defs(socket, &files, &ns),
        };
    }

    // `get` carries the reveal/dry-run polarity, so it is dispatched specially:
    // it strips the mode flags, resolves the mode, and renders a masked output
    // in dry-run (DR-0015).
    if sub == "get" {
        return dispatch_kv_get(kv_args, socket, config, &ns);
    }

    // `list` filters / renders namespace-aware, so it is dispatched specially.
    if sub == "list" {
        return dispatch_kv_list(kv_args, socket, &ns);
    }

    let req = match sub {
        "set" => or_usage(
            commands::parse_kv_set(
                kv_args,
                &ns,
                std::io::IsTerminal::is_terminal(&std::io::stdin()),
                || {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    Ok(buf)
                },
            ),
            leaf_help,
        )?,
        "del" => or_usage(commands::parse_kv_del(kv_args, &ns), leaf_help)?,
        "unpin" => or_usage(
            commands::parse_kv_single_key("unpin", kv_args, &ns),
            leaf_help,
        )?,
        "pin" => or_usage(commands::parse_kv_pin(kv_args, &ns), leaf_help)?,
        _ => unreachable!("leaf_help match covers all known subcommands"),
    };
    Ok(run_client(socket, &req)?)
}

/// Dispatch `kv list [--all]` (DR-0017 §2).
///
/// The daemon returns every (composed) key; the namespace view is a client-side
/// concern. By default only the current namespace's keys are shown, with the
/// `NS/` prefix stripped. `--all` lists every key in its composed
/// `NS/KEY` form (internal daemon keys, which have no namespace, appear only
/// here, verbatim).
fn dispatch_kv_list(
    kv_args: &[String],
    socket: &std::path::Path,
    ns: &str,
) -> Result<(), CliError> {
    let mut all = false;
    for a in kv_args {
        match a.as_str() {
            "--all" => all = true,
            other => {
                return Err(CliError::Usage {
                    msg: format!("unknown argument for `kv list`: {other}"),
                    help: help::kv_list,
                });
            }
        }
    }
    let resp = client::round_trip(socket, &protocol::wire::Request::KvList)?;
    match resp {
        Response::Ok(ok) => match ok.payload {
            OkPayload::List { keys } => {
                for k in filter_ns_keys(keys, ns, all) {
                    println!("{k}");
                }
                Ok(())
            }
            other => Err(CliError::Message(format!(
                "unexpected response payload for kv.list: {other:?}"
            ))),
        },
        resp @ Response::Err(_) => Ok(render_response(resp)?),
    }
}

/// Apply the namespace view to a list of composed keys (DR-0017 §2): with
/// `all`, every key passes through verbatim (`NS/KEY` form); otherwise only
/// keys in `ns` remain, with the prefix stripped.
fn filter_ns_keys(keys: Vec<String>, ns: &str, all: bool) -> Vec<String> {
    if all {
        return keys;
    }
    let prefix = format!("{ns}/");
    keys.into_iter()
        .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string))
        .collect()
}

/// Register every definition in one or more `--defs` files in bulk (DR-0014 §4).
///
/// Each file is parsed (a parse error for a file is fatal for that file but does
/// not stop the others), then every definition is sent as a `kv.define`. A
/// per-key conflict (an existing different definition) is collected, **not**
/// fatal to the rest: all keys are attempted, and the failures are reported
/// together at the end with a non-zero exit. This keeps one clashing key from
/// taking the rest of a batch registration down with it.
fn run_define_defs(
    socket: &std::path::Path,
    files: &[PathBuf],
    ctx_ns: &str,
) -> Result<(), CliError> {
    let mut failures: Vec<String> = Vec::new();
    let mut ok_count = 0usize;

    for file in files {
        let defs = match defs::parse_defs_file(file) {
            Ok(d) => d,
            Err(e) => {
                // A whole unreadable / invalid file is one failure; keep going so
                // a second `--defs` still applies.
                failures.push(e);
                continue;
            }
        };
        for def in defs {
            // The defs context namespace is the `--namespace` of this
            // invocation; a per-entry `namespace` field is absolute (DR-0017 §5).
            let full_key = def.full_key(ctx_ns);
            let req = protocol::wire::Request::KvDefine {
                key: full_key.clone(),
                source: def.source.clone(),
                soft_ttl_secs: def.soft_ttl_secs,
                hard_ttl_secs: def.hard_ttl_secs,
                meta: def.meta.clone(),
            };
            match client::round_trip(socket, &req) {
                Ok(Response::Ok(_)) => ok_count += 1,
                Ok(Response::Err(e)) => {
                    failures.push(format!("{}: {}", full_key, e.error.message));
                }
                Err(e) => {
                    // A transport error (daemon down) is not per-key; surface it
                    // immediately rather than repeating it for every key.
                    return Err(CliError::Message(e));
                }
            }
        }
    }

    if failures.is_empty() {
        println!("defined {ok_count}");
        Ok(())
    } else {
        // Report every failure together (stderr), then exit non-zero. The ok
        // count goes to stdout so a partial success is still visible.
        if ok_count > 0 {
            println!("defined {ok_count}");
        }
        let mut msg = format!("{} definition(s) failed:", failures.len());
        for f in &failures {
            msg.push_str(&format!("\n  {f}"));
        }
        Err(CliError::Message(msg))
    }
}

/// Dispatch `kv get <KEY> [--dry-run|--reveal]` (DR-0015).
///
/// In reveal mode the raw value is written to stdout (the existing behaviour).
/// In dry-run mode the full retrieval chain runs on the daemon but no value is
/// returned; the client prints the mask (`<cache-warden:KEY:masked>` on success,
/// `<cache-warden:KEY:failed>` + non-zero exit on failure — DR-0015 §3).
fn dispatch_kv_get(
    kv_args: &[String],
    socket: &std::path::Path,
    config: &config::Config,
    ns: &str,
) -> Result<(), CliError> {
    let (mode_flag, rest) = or_usage(mode::take_mode_flag(kv_args), help::kv_get)?;
    let mode = or_usage(resolve_cli_mode(mode_flag, config), help::kv_get)?;
    let req = or_usage(
        commands::parse_kv_single_key("get", &rest, ns),
        help::kv_get,
    )?;
    let key = match &req {
        protocol::wire::Request::KvGet { key, .. } => key.clone(),
        _ => unreachable!("parse_kv_single_key(\"get\") returns KvGet"),
    };
    let req = protocol::wire::Request::KvGet {
        key: key.clone(),
        dry_run: mode.is_dry_run(),
    };

    let resp = client::round_trip(socket, &req)?;
    use protocol::wire::{OkPayload, Response};
    match resp {
        Response::Ok(ok) => match ok.payload {
            OkPayload::Get { value_b64 } => {
                let bytes = commands::decode_get_value(&value_b64)?;
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(&bytes)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            OkPayload::GetVerified { .. } => {
                // dry-run success: print the masked value (key name only).
                println!("{}", refs::mask(&key, true));
                Ok(())
            }
            other => Err(CliError::Message(format!(
                "unexpected response payload for kv get: {other:?}"
            ))),
        },
        Response::Err(e) => {
            // dry-run reports the failure as a masked `failed` token on stdout
            // before exiting non-zero (DR-0015 §3); reveal just errors out.
            if mode.is_dry_run() {
                println!("{}", refs::mask(&key, false));
            }
            Err(CliError::Message(format!(
                "{}: {}",
                error_kind_str(&e.error.kind),
                e.error.message
            )))
        }
    }
}

/// Register every definition from one or more `--defs` files, returning a fatal
/// error string if any file is unreadable / any definition conflicts. Shared by
/// `run` / `inject` (the `kv define --defs` batch path uses [`run_define_defs`],
/// which reports per-file success counts; here a failure is simply fatal because
/// `run` / `inject` must not proceed with a half-applied definition set).
fn register_defs(
    socket: &std::path::Path,
    files: &[std::path::PathBuf],
    ctx_ns: &str,
) -> Result<(), String> {
    use protocol::wire::{Request, Response};
    for file in files {
        let defs = defs::parse_defs_file(file)?;
        for def in defs {
            let req = Request::KvDefine {
                key: def.full_key(ctx_ns),
                source: def.source.clone(),
                soft_ttl_secs: def.soft_ttl_secs,
                hard_ttl_secs: def.hard_ttl_secs,
                meta: def.meta.clone(),
            };
            match client::round_trip(socket, &req)? {
                Response::Ok(_) => {}
                Response::Err(e) => {
                    return Err(format!("{}: {}", def.name, e.error.message));
                }
            }
        }
    }
    Ok(())
}

/// Dispatch `cache-warden run [...] -- CMD [ARGS...]` (DR-0013 / DR-0015).
fn dispatch_run(
    rest: &[String],
    socket: &std::path::Path,
    config: &config::Config,
) -> Result<(), CliError> {
    if help::wants_help(rest) {
        println!("{}", help::run_cmd().render());
        return Ok(());
    }
    let (mode_flag, rest) = or_usage(mode::take_mode_flag(rest), help::run_cmd)?;
    let mode = or_usage(resolve_cli_mode(mode_flag, config), help::run_cmd)?;
    let (ns_flag, rest) = or_usage(namespace::take_namespace_flag(&rest), help::run_cmd)?;
    let ns = or_usage(
        namespace::resolve_namespace(ns_flag, namespace::env_namespace(), config.cli_namespace()),
        help::run_cmd,
    )?;
    let parsed = or_usage(commands::run_cmd::parse_run(&rest), help::run_cmd)?;

    // Register any --defs before resolving (so a lazily-defined key exists).
    // The defs context namespace is this invocation's namespace (DR-0017 §5).
    register_defs(socket, &parsed.defs, &ns)?;

    // Warn (once per token) that argv references are NOT injected (DR-0013).
    for tok in commands::run_cmd::argv_reference_tokens(&parsed.command) {
        eprintln!(
            "{NAME}: warning: {tok:?} looks like a secret reference but argv is not an injection face (it is passed verbatim); use --env NAME=cache-warden://KEY instead"
        );
    }

    let inherited: Vec<(String, String)> = std::env::vars().collect();
    let mut resolver = client::SocketResolver::new(socket, mode);
    let resolved =
        commands::run_cmd::resolve_env(&inherited, &parsed.envs, mode, &ns, &mut resolver)?;

    // dry-run fail-closed-but-evaluated: if a reference failed, do not exec; exit
    // non-zero after summarizing (DR-0015 §3). Reveal fail-closed already
    // produced an Err above (no exec).
    if mode.is_dry_run() && !resolved.failures.is_empty() {
        return Err(CliError::Message(format!(
            "dry-run: {} reference(s) failed to resolve: {}",
            resolved.failures.len(),
            resolved.failures.join(", ")
        )));
    }

    exec_command(&parsed.command, &resolved.vars)
}

/// Replace the current process image with `command`, using `vars` as the entire
/// environment (DR-0013: exec so no parent lingers holding secrets). Only
/// returns on failure: not-found → 127, other exec error → 126 (shell
/// convention).
fn exec_command(command: &[String], vars: &[(String, String)]) -> Result<(), CliError> {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    cmd.envs(vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    // `exec` only returns if it failed.
    let err = cmd.exec();
    let code = if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    };
    eprintln!("{NAME}: cannot exec {:?}: {err}", command[0]);
    process::exit(code);
}

/// Dispatch `cache-warden inject [...]` (DR-0013 / DR-0015).
fn dispatch_inject(
    rest: &[String],
    socket: &std::path::Path,
    config: &config::Config,
) -> Result<(), CliError> {
    if help::wants_help(rest) {
        println!("{}", help::inject_cmd().render());
        return Ok(());
    }
    let (mode_flag, rest) = or_usage(mode::take_mode_flag(rest), help::inject_cmd)?;
    let mode = or_usage(resolve_cli_mode(mode_flag, config), help::inject_cmd)?;
    let (ns_flag, rest) = or_usage(namespace::take_namespace_flag(&rest), help::inject_cmd)?;
    let ns = or_usage(
        namespace::resolve_namespace(ns_flag, namespace::env_namespace(), config.cli_namespace()),
        help::inject_cmd,
    )?;
    let parsed = or_usage(commands::inject_cmd::parse_inject(&rest), help::inject_cmd)?;

    register_defs(socket, &parsed.defs, &ns)?;

    // Read the template (stdin or --in FILE), binary safe.
    let template: Vec<u8> = match &parsed.in_file {
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::Message(format!("failed to read stdin: {e}")))?;
            buf
        }
        Some(path) => std::fs::read(path)
            .map_err(|e| CliError::Message(format!("cannot read {}: {e}", path.display())))?,
    };

    let mut resolver = client::SocketResolver::new(socket, mode);
    let rendered = commands::inject_cmd::render(&template, mode, &ns, &mut resolver)?;

    // Write the (fully rendered) output: stdout or 0600 --out FILE.
    commands::inject_cmd::write_output(parsed.out_file.as_deref(), &rendered.bytes)
        .map_err(|e| CliError::Message(format!("failed to write output: {e}")))?;

    // dry-run: a non-empty failure set means exit non-zero after writing
    // (DR-0015 §3). Reveal already failed-closed inside `render`.
    if !rendered.failures.is_empty() {
        return Err(CliError::Message(format!(
            "dry-run: {} reference(s) failed to resolve: {}",
            rendered.failures.len(),
            rendered.failures.join(", ")
        )));
    }
    Ok(())
}

/// Build the attribute list for a status entry (value-free: regenerability,
/// definition presence, value presence, active pin, active backoff).
///
/// Extracted for unit-testability. Called once per entry inside
/// [`render_response`].
fn format_entry_attrs(e: &protocol::wire::EntryInfo) -> Vec<String> {
    let mut attrs: Vec<String> = Vec::new();
    attrs.push(
        if e.regenerable {
            "regenerable"
        } else {
            "static"
        }
        .to_string(),
    );
    if let Some(t) = &e.value_type {
        attrs.push(format!("type {t}"));
    }
    // The typed source origin (DR-0018 §3): value-free
    // (an op source shows its uri, never the secret).
    if let Some(src) = &e.source {
        attrs.push(format!("source {src}"));
    }
    if e.defined {
        attrs.push("defined".to_string());
    }
    attrs.push(
        if e.has_value {
            "value present"
        } else {
            "no value"
        }
        .to_string(),
    );
    if let Some(secs) = e.pin_remaining_secs {
        attrs.push(format!("pinned {secs}s"));
    }
    // Fetch-failure backoff (DR-0022): when active, show remaining seconds so
    // the user knows re-fetch is suppressed and for how long.
    if let Some(secs) = e.backoff_until_secs.filter(|&s| s > 0) {
        attrs.push(format!("backoff: {secs}s"));
    }
    attrs
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(CliError::Message(e)) => {
            if !e.is_empty() {
                eprintln!("{NAME}: {e}");
            }
            process::exit(1);
        }
        Err(CliError::Usage { msg, help }) => {
            if !msg.is_empty() {
                eprintln!("{NAME}: {msg}");
            }
            eprintln!("{}", help().render());
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::wire::EntryInfo;

    fn base_entry() -> EntryInfo {
        EntryInfo {
            name: "default/K".into(),
            state: "active".into(),
            regenerable: false,
            defined: false,
            has_value: true,
            pin_remaining_secs: None,
            value_type: None,
            source: None,
            backoff_until_secs: None,
        }
    }

    #[test]
    fn format_entry_attrs_no_backoff_omits_backoff_field() {
        let e = base_entry();
        let attrs = format_entry_attrs(&e);
        let joined = attrs.join(", ");
        assert!(
            !joined.contains("backoff"),
            "no backoff_until_secs must not show backoff: {joined}"
        );
    }

    #[test]
    fn format_entry_attrs_backoff_zero_omits_backoff_field() {
        let mut e = base_entry();
        e.backoff_until_secs = Some(0);
        let attrs = format_entry_attrs(&e);
        let joined = attrs.join(", ");
        assert!(
            !joined.contains("backoff"),
            "backoff_until_secs=0 (expired) must not show backoff: {joined}"
        );
    }

    #[test]
    fn format_entry_attrs_backoff_active_shows_remaining_seconds() {
        let mut e = base_entry();
        e.backoff_until_secs = Some(3);
        let attrs = format_entry_attrs(&e);
        let joined = attrs.join(", ");
        assert!(
            joined.contains("backoff: 3s"),
            "backoff_until_secs=3 must show 'backoff: 3s': {joined}"
        );
    }

    #[test]
    fn format_entry_attrs_pin_and_backoff_both_shown() {
        let mut e = base_entry();
        e.pin_remaining_secs = Some(60);
        e.backoff_until_secs = Some(5);
        let attrs = format_entry_attrs(&e);
        let joined = attrs.join(", ");
        assert!(joined.contains("pinned 60s"), "pin must be shown: {joined}");
        assert!(
            joined.contains("backoff: 5s"),
            "backoff must be shown: {joined}"
        );
    }
}
