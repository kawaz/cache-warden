//! cache-warden CLI: the daemon group (`daemon run`) and its management client.
//!
//! Command routing lives here; the argument grammar of each level lives in
//! [`cli`] (clap) and its help text in [`help`]. `daemon run` starts the
//! in-process daemon (DR-0008); the other subcommands are one-shot
//! control-socket clients (see [`commands::client`]).

use std::io::Read as _;
use std::path::PathBuf;
use std::process;

mod cli;
mod commands;
mod config;
mod daemon;
mod defs;
mod fda;
mod help;
mod mode;
mod namespace;
mod otp_type;
mod protocol;
mod refs;
#[cfg(test)]
mod test_env;
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
                OkPayload::CeremonyOpened {
                    url,
                    expires_in_secs,
                    ..
                } => {
                    // The URL goes to stdout on its own line so it can be
                    // piped into a browser opener; the context goes to stderr
                    // so it stays out of that pipe.
                    eprintln!(
                        "open this in a browser within {expires_in_secs}s to register the passkey:"
                    );
                    println!("{url}");
                }
                OkPayload::Set { version, .. } => match version {
                    // The version is what a caller passes back as the next
                    // `--expected-version`, so it is worth showing.
                    Some(v) => println!("ok (version {v})"),
                    None => println!("ok"),
                },
                OkPayload::Claimed {
                    version,
                    claim_token,
                    claim_expires_in_secs,
                    ..
                } => {
                    // The token goes to stdout on its own line so a shell can
                    // capture it with `$(...)`; the human-readable context goes
                    // to stderr so it does not end up in that capture.
                    eprintln!("claimed key at version {version} for {claim_expires_in_secs}s");
                    println!("{claim_token}");
                }
                OkPayload::Unclaimed { .. } => println!("unclaimed"),
                OkPayload::VaultInitialized {
                    vault_id,
                    recovery_code,
                    ..
                } => {
                    // The code goes to stdout on its own line so it can be
                    // redirected to a file or a password manager; everything
                    // else — including the warning that it is shown once — is
                    // context and goes to stderr.
                    eprintln!("vault {vault_id} created.");
                    println!("{recovery_code}");
                    eprintln!("\n{}", cache_warden_vault::RECOVERY_STORAGE_GUIDANCE);
                }
                OkPayload::VaultUnlocked {
                    entries_restored, ..
                } => println!("unlocked ({entries_restored} entries available)"),
                OkPayload::VaultLocked { .. } => println!("locked"),
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
                OkPayload::List { keys, .. } => {
                    // Generic renderer (no namespace view, no metadata view):
                    // names only. The namespace-aware `kv list` renderer in
                    // `dispatch_kv_list` consumes `entries` directly.
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
                // DR-0029: dispatched specially by `dispatch_daemon`'s
                // `restart` leaf (it also handles the no-reply / socket-close
                // outcome that a *successful* graceful restart produces);
                // surfaced defensively if it ever reaches here.
                OkPayload::Restarting { .. } => {
                    println!("restart accepted");
                }
                OkPayload::Status {
                    vault: _,
                    pid,
                    version,
                    socket,
                    entries,
                    // Reported by `daemon status`, not by the top-level
                    // entry listing this arm renders.
                    full_disk_access: _,
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
        RestartAborted => "restart aborted",
        CasMismatch => "version conflict",
        AlreadyClaimed => "already being refreshed",
        ClaimTokenMismatch => "claim token mismatch",
        VaultLocked => "vault locked",
        VaultNotInitialized => "no vault",
    }
}

/// Run a client command (connect, exchange one request/response, render).
fn run_client(socket: &std::path::Path, req: &protocol::wire::Request) -> Result<(), String> {
    let resp = client::round_trip(socket, req)?;
    render_response(resp)
}

/// Same as [`run_client`], but tailored to `kv.set` calls carrying a
/// DR-0030 guard declaration: the daemon response **must** carry a
/// non-empty `guard_applied` list. If it does not — because we are
/// talking to an old daemon that predates DR-0030 and silently
/// dropped the `guard_constraints` field — this rejects with an
/// explanatory error rather than pretending the set succeeded.
///
/// A successful reply with `guard_applied` populated is echoed to
/// stdout in the compact form `ok (guard: <labels>)` so the operator
/// sees which constraints actually landed (matching the CLI's
/// value-free, single-line style for management verbs).
fn run_client_expect_guard_ack(
    socket: &std::path::Path,
    req: &protocol::wire::Request,
) -> Result<(), String> {
    let mut send = |r: &protocol::wire::Request| client::round_trip(socket, r);
    expect_guard_ack_with_sender(req, &mut send)
}

/// Testable core of [`run_client_expect_guard_ack`]. Same contract
/// (a `kv.set` whose ack must carry a non-empty `guard_applied`),
/// but with the transport factored out as a callable so a unit test
/// can drive it with a canned request/response history.
///
/// # Old-daemon silent-drop recovery
///
/// If the ack has `guard_applied` empty despite the request declaring
/// guard constraints, the value was already accepted by the old
/// daemon **unguarded** — merely surfacing an error would leave the
/// entry stored *without* the requested guard. So we issue a
/// best-effort `KvDel` for the same key over the same transport
/// (with_define: false — a define, if any, is untouched) before
/// returning the error, and the error message reports whether that
/// auto-cleanup succeeded so the operator knows if a manual `kv del`
/// is still required.
fn expect_guard_ack_with_sender<F>(
    req: &protocol::wire::Request,
    send: &mut F,
) -> Result<(), String>
where
    F: FnMut(&protocol::wire::Request) -> Result<protocol::wire::Response, String>,
{
    use protocol::wire::{OkPayload, Request, Response};
    let resp = send(req)?;
    match resp {
        Response::Ok(ok) => match ok.payload {
            OkPayload::Set { guard_applied, .. } => {
                if guard_applied.is_empty() {
                    // Extract the key from the original request so the
                    // auto-delete targets exactly what we just wrote.
                    let key = match req {
                        Request::KvSet { key, .. } => key.clone(),
                        _ => {
                            return Err(
                                "internal error: expect_guard_ack invoked with a non-KvSet request"
                                    .to_string(),
                            );
                        }
                    };
                    let del_req = Request::KvDel {
                        key: key.clone(),
                        with_define: false,
                    };
                    let cleanup = match send(&del_req) {
                        Ok(Response::Ok(_)) => {
                            format!("the unguarded value at {key:?} was auto-deleted")
                        }
                        Ok(Response::Err(e)) => format!(
                            "the unguarded value at {key:?} could NOT be auto-deleted \
                             ({}: {}); run `cache-warden kv del {key}` immediately",
                            error_kind_str(&e.error.kind),
                            e.error.message
                        ),
                        Err(e) => format!(
                            "the unguarded value at {key:?} could NOT be auto-deleted \
                             ({e}); run `cache-warden kv del {key}` immediately"
                        ),
                    };
                    return Err(format!(
                        "daemon accepted the set but did not report any applied guard \
                         constraints; you likely have an old cache-warden daemon that \
                         does not enforce per-entry access guards, so the value was \
                         stored WITHOUT the requested guard. {cleanup}. Restart the \
                         daemon with a matching version \
                         (`cache-warden daemon restart --graceful` or a service restart) \
                         before relying on --require-* flags."
                    ));
                }
                println!("ok (guard: {})", guard_applied.join(", "));
                Ok(())
            }
            other => Err(format!("unexpected daemon response for kv.set: {other:?}")),
        },
        Response::Err(e) => Err(format!(
            "{}: {}",
            error_kind_str(&e.error.kind),
            e.error.message
        )),
    }
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

    // Hidden internal subcommands, dispatched on the raw argv before anything
    // else: the daemon re-executes its own binary with these (an op item's
    // private-key PEM fetch; the `internal` helper group, e.g. `fda-check` for
    // TCC authorization probing). They need neither config nor a socket, and
    // their own arguments must reach them untouched. Never shown in help.
    if args[0] == cache_warden_authsock::OP_PRIVATE_KEY_SUBCOMMAND {
        return commands::op_private_key::run(&args[1..]).map_err(CliError::Message);
    }
    if args[0] == "internal" {
        let code = dispatch_internal(&args[1..]);
        if code != 0 {
            process::exit(code);
        }
        return Ok(());
    }

    // Resolve the global `--socket` from the *whole* argv, so it may lead
    // (`cache-warden --socket P kv get K`) as well as follow the command
    // (`cache-warden kv get K --socket P`). None means "not on the CLI".
    let (cli_socket, args) = commands::take_socket_flag(&args)?;
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
    let rest: Vec<String> = args[1..].to_vec();

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
        "vault" => dispatch_vault(&rest, &socket),
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
            // Only the flag parse is a usage error (the operator mistyped a
            // flag): show the leaf help for that. Everything `register()`
            // does afterwards — resolving the binary path, launchd/systemd
            // calls — is a runtime/environment failure and must not carry a
            // help dump, which would bury the real cause under an unrelated
            // flag list.
            let parsed = or_usage(
                commands::daemon_cmd::parse_register_args(tail),
                help::daemon_register,
            )?;
            let sock = cli_socket.map(|p| p.to_string_lossy().into_owned());
            commands::daemon_cmd::register(parsed, config, config_path, sock.as_deref())
                .map_err(CliError::Message)
        }
        "unregister" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_unregister().render());
                return Ok(());
            }
            let parsed = or_usage(
                commands::daemon_cmd::parse_unregister_args(tail),
                help::daemon_unregister,
            )?;
            commands::daemon_cmd::unregister(parsed).map_err(CliError::Message)
        }
        "status" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_status().render());
                return Ok(());
            }
            // `daemon status` reuses the `unregister` flag grammar (`--label`
            // only); reword the "unknown option" message for this subcommand.
            let parsed = or_usage(
                commands::daemon_cmd::parse_unregister_args(tail)
                    .map_err(|e| e.replace("daemon unregister", "daemon status")),
                help::daemon_status,
            )?;
            commands::daemon_cmd::status(parsed, &config, &socket).map_err(CliError::Message)
        }
        "restart" => {
            if help::wants_help(tail) {
                println!("{}", help::daemon_restart().render());
                return Ok(());
            }
            let parsed = or_usage(
                commands::daemon_cmd::parse_restart_args(tail),
                help::daemon_restart,
            )?;
            if parsed.graceful {
                commands::daemon_cmd::restart_graceful(&socket).map_err(CliError::Message)
            } else {
                unreachable!("parse_restart_args rejects a non-graceful restart")
            }
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
    let cmd = cli::status();
    let m = cmd
        .clone()
        .try_get_matches_from(&rest)
        .map_err(|e| CliError::Message(cli::parse_error(&cmd, "status", e)))?;
    let all = m.get_count("all") > 0;

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
        "claim" => help::kv_claim,
        "unclaim" => help::kv_unclaim,
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
        "claim" => or_usage(commands::parse_kv_claim(kv_args, &ns), leaf_help)?,
        "unclaim" => or_usage(commands::parse_kv_unclaim(kv_args, &ns), leaf_help)?,
        _ => unreachable!("leaf_help match covers all known subcommands"),
    };
    // DR-0030 positive-ack contract: a `kv.set` that declared guard
    // constraints must come back with a non-empty `guard_applied` list.
    // An old daemon that silently drops the wire declaration has no such
    // field, `#[serde(default)]` decodes to `Vec::new()`, and the client
    // must treat that as an error (never as a successful unguarded write).
    if let protocol::wire::Request::KvSet {
        guard_constraints, ..
    } = &req
        && !guard_constraints.is_empty()
    {
        return Ok(run_client_expect_guard_ack(socket, &req)?);
    }
    Ok(run_client(socket, &req)?)
}

/// Dispatch the `vault` group (DR-0034 §6/§9).
///
/// No namespace and no config of its own: a vault belongs to the daemon, not
/// to a KV namespace.
fn dispatch_vault(rest: &[String], socket: &std::path::Path) -> Result<(), CliError> {
    if rest.is_empty() || rest[0] == "--help" {
        println!("{}", help::vault().render());
        return Ok(());
    }
    let sub = rest[0].as_str();
    let tail = &rest[1..];
    let leaf_help: fn() -> help::HelpSpec = match sub {
        "init" => help::vault_init,
        "unlock" => help::vault_unlock,
        "add-passkey" => help::vault_add_passkey,
        "lock" => help::vault_lock,
        "status" => help::vault_status,
        other => {
            return Err(CliError::Message(format!(
                "unknown vault subcommand: {other} (try `{NAME} vault --help`)"
            )));
        }
    };
    if help::wants_help(tail) {
        println!("{}", leaf_help().render());
        return Ok(());
    }

    // `status` renders a view of the ordinary `status` reply (there is no
    // `vault.status` request), so it is dispatched on its own.
    if sub == "status" {
        return dispatch_vault_status(tail, socket);
    }

    let req = match sub {
        "init" => or_usage(commands::vault_cmd::parse_vault_init(tail), leaf_help)?,
        "lock" => or_usage(commands::vault_cmd::parse_vault_lock(tail), leaf_help)?,
        "add-passkey" => or_usage(
            commands::vault_cmd::parse_vault_add_passkey(tail),
            leaf_help,
        )?,
        "unlock" => or_usage(
            commands::vault_cmd::parse_vault_unlock(
                tail,
                std::io::IsTerminal::is_terminal(&std::io::stdin()),
                || {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    Ok(line)
                },
            ),
            leaf_help,
        )?,
        _ => unreachable!("leaf_help match covers all known subcommands"),
    };
    Ok(run_client(socket, &req)?)
}

/// Dispatch `vault status` (DR-0034 §6): ask for the daemon status and render
/// only its vault section.
fn dispatch_vault_status(tail: &[String], socket: &std::path::Path) -> Result<(), CliError> {
    or_usage(
        commands::vault_cmd::parse_vault_status(tail),
        help::vault_status,
    )?;
    let resp = client::round_trip(socket, &protocol::wire::Request::Status)?;
    match resp {
        Response::Ok(ok) => match ok.payload {
            OkPayload::Status { vault, .. } => {
                print!(
                    "{}",
                    commands::vault_cmd::render_vault_status(vault.as_deref())
                );
                Ok(())
            }
            other => Err(CliError::Message(format!(
                "unexpected response payload for status: {other:?}"
            ))),
        },
        resp @ Response::Err(_) => Ok(render_response(resp)?),
    }
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
    let cmd = cli::kv_list();
    let all = match cmd.clone().try_get_matches_from(kv_args) {
        Ok(m) => m.get_count("all") > 0,
        Err(e) => {
            return Err(CliError::Usage {
                msg: cli::parse_error(&cmd, "kv list", e),
                help: help::kv_list,
            });
        }
    };
    let resp = client::round_trip(socket, &protocol::wire::Request::KvList)?;
    match resp {
        Response::Ok(ok) => match ok.payload {
            OkPayload::List { keys, entries } => {
                render_kv_list(keys, entries, ns, all);
                Ok(())
            }
            other => Err(CliError::Message(format!(
                "unexpected response payload for kv.list: {other:?}"
            ))),
        },
        resp @ Response::Err(_) => Ok(render_response(resp)?),
    }
}

/// Render `kv list` output with the namespace view (DR-0017 §2) and, when the
/// daemon supplied per-key metadata, an inline backoff hint after each name
/// (DR-0022 §3).
///
/// `entries` is the parallel value-free metadata (one per key, same order) when
/// the daemon is new enough to populate it, or empty when it is not — in the
/// latter case we degrade to the historical name-only output, no error.
fn render_kv_list(keys: Vec<String>, entries: Vec<protocol::wire::EntryInfo>, ns: &str, all: bool) {
    let prefix = format!("{ns}/");
    let parallel = keys.len() == entries.len();
    for (i, k) in keys.iter().enumerate() {
        // Apply the namespace view: filter + strip the prefix unless --all.
        let display_name: String = if all {
            k.clone()
        } else if let Some(stripped) = k.strip_prefix(&prefix) {
            stripped.to_string()
        } else {
            continue;
        };
        // Backoff hint comes from the parallel `entries` slot (if present).
        // We only emit it when the daemon supplied metadata and the backoff is
        // active (> 0 seconds remaining), keeping unaffected keys quiet.
        let mut suffixes: Vec<String> = Vec::new();
        if parallel {
            if let Some(s) = entries[i].backoff_until_secs.filter(|&s| s > 0) {
                suffixes.push(format!("backoff: {s}s"));
            }
            // DR-0030 per-entry access guard: surface a summary of the
            // installed constraints (strong-first, weak marker on `command=`)
            // so the user can see at a glance what will gate `kv get`.
            if let Some(g) = entries[i].guard_summary.as_ref().filter(|g| !g.is_empty()) {
                suffixes.push(format!("guard: {}", g.join(", ")));
            }
        }
        if suffixes.is_empty() {
            println!("{display_name}");
        } else {
            println!("{display_name}  {}", suffixes.join("  "));
        }
    }
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
    // DR-0030 per-entry access guard: strong-first summary labels with a
    // `(weak)` marker on `command=`. Only shown when the daemon populated
    // the field (older daemons omit it, so `None` = "guard status unknown"
    // — surface nothing rather than misleadingly claim "no guard").
    if let Some(g) = e.guard_summary.as_ref().filter(|g| !g.is_empty()) {
        attrs.push(format!("guard: {}", g.join(", ")));
    }
    attrs
}

/// Dispatch `cache-warden internal <subcommand>` without loading config.
///
/// Returns an exit code: 0 on success, 1 on error.
fn dispatch_internal(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("cache-warden internal: missing subcommand");
        eprintln!("Available: fda-check");
        return 1;
    }
    match args[0].as_str() {
        "fda-check" => match commands::internal_cmd::fda_check(&args[1..]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("cache-warden internal fda-check: {e}");
                1
            }
        },
        other => {
            eprintln!("cache-warden internal: unknown subcommand: {other}");
            1
        }
    }
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

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

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
            guard_summary: None,
            version: None,
            claim_expires_in_secs: None,
            locked: false,
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

    /// DR-0030: an entry whose daemon populated `guard_summary` gets a
    /// `guard: <labels>` attr in status; `None` (older daemon) omits
    /// the attr entirely rather than misleadingly asserting no guard.
    #[test]
    fn format_entry_attrs_shows_guard_summary_when_populated() {
        let mut e = base_entry();
        e.guard_summary = Some(vec!["same-user".into(), "command (git) (weak)".into()]);
        let attrs = format_entry_attrs(&e);
        let joined = attrs.join(", ");
        assert!(
            joined.contains("guard: same-user, command (git) (weak)"),
            "{joined}"
        );

        let mut e2 = base_entry();
        e2.guard_summary = None;
        let attrs2 = format_entry_attrs(&e2);
        assert!(
            !attrs2.iter().any(|a| a.starts_with("guard:")),
            "None (unknown) must not surface a guard attr: {attrs2:?}"
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

    // ---- render_kv_list (DR-0022 §3, DR-0017 §2 namespace view) ----
    //
    // `render_kv_list` writes straight to stdout; we exercise its decision logic
    // indirectly by recreating the same selection rules in a pure helper. The
    // CLI integration paths (tests/cli/*) cover the actual stdout shape; here we
    // only pin down the *backoff hint vs name-only* decision boundary, which is
    // the part most likely to silently regress.
    fn select_kv_list_line(
        key: &str,
        entry: Option<&protocol::wire::EntryInfo>,
        ns: &str,
        all: bool,
    ) -> Option<String> {
        let prefix = format!("{ns}/");
        let name = if all {
            key.to_string()
        } else {
            key.strip_prefix(&prefix)?.to_string()
        };
        let hint = entry
            .and_then(|e| e.backoff_until_secs)
            .filter(|&s| s > 0)
            .map(|s| format!("  backoff: {s}s"))
            .unwrap_or_default();
        Some(format!("{name}{hint}"))
    }

    #[test]
    fn kv_list_strips_namespace_prefix_by_default() {
        let line = select_kv_list_line("default/K", None, "default", false);
        assert_eq!(line, Some("K".to_string()));
    }

    #[test]
    fn kv_list_all_keeps_composed_name() {
        let line = select_kv_list_line("default/K", None, "default", true);
        assert_eq!(line, Some("default/K".to_string()));
    }

    #[test]
    fn kv_list_filters_out_other_namespaces_unless_all() {
        let line = select_kv_list_line("other/K", None, "default", false);
        assert_eq!(line, None, "other-namespace keys hidden without --all");
    }

    #[test]
    fn kv_list_renders_backoff_hint_when_active() {
        let mut e = base_entry();
        e.name = "default/K".into();
        e.backoff_until_secs = Some(3);
        let line = select_kv_list_line("default/K", Some(&e), "default", false);
        assert_eq!(line.as_deref(), Some("K  backoff: 3s"));
    }

    #[test]
    fn kv_list_omits_backoff_hint_when_zero_or_absent() {
        let mut e = base_entry();
        e.name = "default/K".into();
        e.backoff_until_secs = Some(0);
        let line = select_kv_list_line("default/K", Some(&e), "default", false);
        assert_eq!(line.as_deref(), Some("K"));

        e.backoff_until_secs = None;
        let line = select_kv_list_line("default/K", Some(&e), "default", false);
        assert_eq!(line.as_deref(), Some("K"));
    }

    // ---- daemon register: usage vs runtime-failure classification ----
    //
    // `or_usage` must wrap only the *parse* of `daemon register`'s flags: a
    // bad/missing flag value is the operator's mistake and should show the
    // leaf help so they see the accepted flags. Everything `register()` does
    // afterwards (resolving the binary path, launchd/systemd calls) is a
    // runtime/environment failure and must not carry a help dump — that would
    // bury the real cause under an unrelated flag list.

    #[test]
    fn daemon_register_parse_failure_is_usage_error() {
        let config = config::Config::parse("").unwrap();
        // `--socket` with no value is a parse error.
        let rest = s(&["register", "--socket"]);
        let err =
            dispatch_daemon(&rest, PathBuf::from("/tmp/x.sock"), config, None, None).unwrap_err();
        match err {
            CliError::Usage { msg, .. } => {
                assert!(msg.contains("--socket requires a PATH argument"), "{msg}");
            }
            CliError::Message(msg) => panic!("parse failure must stay a usage error: {msg}"),
        }
    }

    // ---- expect_guard_ack_with_sender: old-daemon silent-drop recovery ----
    //
    // The HIGH review finding: a `kv.set` whose ack has `guard_applied`
    // empty (an old daemon that silently dropped the guard declaration)
    // already stored the value on the daemon side WITHOUT the requested
    // guard. Just surfacing an error leaves that value resident. The
    // client must issue a best-effort `KvDel` for the same key over the
    // same transport before returning the error, and the error message
    // must tell the operator whether that cleanup succeeded.

    use protocol::wire::{ErrorKind, Request as WireRequest, Response as WireResponse};

    fn guarded_set_req() -> WireRequest {
        WireRequest::KvSet {
            key: "default/K".into(),
            source: protocol::wire::SetSource::Static {
                value_b64: String::new(),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: vec![protocol::wire::GuardConstraintWire::SameUser],
            expected_version: None,
            claim_token: None,
            persist: None,
        }
    }

    /// A recording sender: pushes each request into `history`, then pops
    /// the next canned response from `queue`. Panics if the queue runs dry
    /// (unexpected extra send) or a leftover response remains (unsent).
    fn make_sender<'a>(
        history: &'a std::cell::RefCell<Vec<WireRequest>>,
        queue: &'a std::cell::RefCell<std::collections::VecDeque<WireResponse>>,
    ) -> impl FnMut(&WireRequest) -> Result<WireResponse, String> + 'a {
        move |req: &WireRequest| {
            history.borrow_mut().push(req.clone());
            match queue.borrow_mut().pop_front() {
                Some(resp) => Ok(resp),
                None => Err("recording sender: no more canned responses".to_string()),
            }
        }
    }

    /// Ack empty (= old daemon that silently dropped `guard_constraints`)
    /// must trigger a best-effort `KvDel` for the same key, and the
    /// returned error must report the auto-delete success in its message.
    #[test]
    fn expect_guard_ack_empty_triggers_kv_del_and_reports_auto_deleted() {
        let history = std::cell::RefCell::new(Vec::new());
        let queue = std::cell::RefCell::new(std::collections::VecDeque::from(vec![
            // First: the KvSet ack — empty `guard_applied` (old daemon).
            WireResponse::set_ack_with_guard(Vec::new()),
            // Second: the auto-delete succeeds.
            WireResponse::deleted(true),
        ]));
        let mut send = make_sender(&history, &queue);

        let req = guarded_set_req();
        let err = expect_guard_ack_with_sender(&req, &mut send).unwrap_err();

        // The sender saw two calls: the original KvSet, then a KvDel for
        // the same key with `with_define: false`.
        let hist = history.borrow();
        assert_eq!(hist.len(), 2, "sender must be called twice: {hist:?}");
        assert!(matches!(hist[0], WireRequest::KvSet { .. }));
        match &hist[1] {
            WireRequest::KvDel { key, with_define } => {
                assert_eq!(key, "default/K", "delete targets the same key");
                assert!(!with_define, "delete must not remove the definition");
            }
            other => panic!("second request must be KvDel, got {other:?}"),
        }

        // The error message reports the auto-delete success and names the
        // old-daemon cause + the restart hint.
        assert!(
            err.contains("auto-deleted"),
            "error names cleanup success: {err}"
        );
        assert!(
            err.contains("old cache-warden daemon"),
            "error names cause: {err}"
        );
        assert!(err.contains("restart"), "error names remediation: {err}");
    }

    /// Ack empty + `KvDel` fails: the error must name the failure and
    /// tell the operator to `kv del` manually. The best-effort cleanup
    /// itself does NOT change the error's terminal shape (still Err).
    #[test]
    fn expect_guard_ack_empty_with_failing_del_hints_manual_cleanup() {
        let history = std::cell::RefCell::new(Vec::new());
        let queue = std::cell::RefCell::new(std::collections::VecDeque::from(vec![
            WireResponse::set_ack_with_guard(Vec::new()),
            // Second: the auto-delete errors out (e.g. daemon dropped
            // the connection between the two exchanges).
            WireResponse::error(ErrorKind::Internal, "boom"),
        ]));
        let mut send = make_sender(&history, &queue);

        let req = guarded_set_req();
        let err = expect_guard_ack_with_sender(&req, &mut send).unwrap_err();

        // The delete WAS attempted (2 sends), but the message now steers
        // the operator to run `cache-warden kv del <key>` themselves.
        assert_eq!(history.borrow().len(), 2);
        assert!(
            err.contains("could NOT be auto-deleted"),
            "error surfaces the cleanup failure: {err}"
        );
        assert!(
            err.contains("cache-warden kv del default/K"),
            "error tells operator the manual remediation: {err}"
        );
    }

    /// Ack non-empty (= a matching-version daemon actually applied the
    /// guard): the client succeeds without any auto-delete side effect.
    #[test]
    fn expect_guard_ack_populated_is_success_with_no_side_effect() {
        let history = std::cell::RefCell::new(Vec::new());
        let queue = std::cell::RefCell::new(std::collections::VecDeque::from(vec![
            WireResponse::set_ack_with_guard(vec!["same-user".to_string()]),
        ]));
        let mut send = make_sender(&history, &queue);

        let req = guarded_set_req();
        expect_guard_ack_with_sender(&req, &mut send).expect("populated ack is success");

        assert_eq!(
            history.borrow().len(),
            1,
            "no auto-delete when guard was applied"
        );
    }

    /// A wire error response is surfaced verbatim (formatted through
    /// `error_kind_str`), no side effects.
    #[test]
    fn expect_guard_ack_wire_error_is_surfaced_verbatim() {
        let history = std::cell::RefCell::new(Vec::new());
        let queue =
            std::cell::RefCell::new(std::collections::VecDeque::from(vec![WireResponse::error(
                ErrorKind::BadRequest,
                "value_b64 is not valid base64",
            )]));
        let mut send = make_sender(&history, &queue);

        let req = guarded_set_req();
        let err = expect_guard_ack_with_sender(&req, &mut send).unwrap_err();
        assert!(err.contains("bad request"), "surfaces the kind: {err}");
        assert!(
            err.contains("value_b64"),
            "surfaces the daemon message: {err}"
        );
        assert_eq!(history.borrow().len(), 1, "no auto-delete on wire error");
    }

    #[test]
    fn daemon_register_runtime_failure_is_message_not_usage() {
        let config = config::Config::parse("").unwrap();
        // A well-formed `--executable` pointing at a path that does not exist
        // parses fine; it fails inside register()'s binary resolution, well
        // past the parse step, and must not carry the leaf help dump.
        let rest = s(&[
            "register",
            "--executable",
            "/no/such/cache-warden-binary-xyz",
        ]);
        let err =
            dispatch_daemon(&rest, PathBuf::from("/tmp/x.sock"), config, None, None).unwrap_err();
        match err {
            CliError::Message(msg) => assert!(msg.contains("does not exist"), "{msg}"),
            CliError::Usage { msg, .. } => {
                panic!("runtime failure must not dump the leaf help: {msg}")
            }
        }
    }
}
