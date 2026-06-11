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
mod help;
mod protocol;

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
                            // Build a value-free attribute list: regenerability,
                            // whether a definition is registered, whether a value
                            // is resident, and any active pin (never the value).
                            let mut attrs: Vec<String> = Vec::new();
                            attrs.push(
                                if e.regenerable {
                                    "regenerable"
                                } else {
                                    "static"
                                }
                                .to_string(),
                            );
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

    // Resolve --socket (anywhere in the tail) once; None means "not on the CLI".
    let (cli_socket, rest) = commands::take_socket_flag(tail)?;

    // Load the config (or defaults) up front: every command needs the resolved
    // socket, and `daemon run` / `config` need the rest of it (DR-0010).
    let loaded = config::load().map_err(|e| e.to_string())?;
    let socket = commands::resolve_socket(cli_socket, loaded.config.socket_path());

    match command.as_str() {
        "daemon" => dispatch_daemon(&rest, socket, loaded.config),
        "config" => dispatch_config(&rest, &loaded),
        "ping" => Ok(run_client(&socket, &protocol::wire::Request::Ping)?),
        "status" => Ok(run_client(&socket, &protocol::wire::Request::Status)?),
        "kv" => dispatch_kv(&rest, &socket),
        "--help" | "--version" => unreachable!("handled above"),
        other => Err(CliError::Message(format!(
            "unknown command: {other} (try `{NAME} --help`)"
        ))),
    }
}

/// Dispatch the `daemon` group.
fn dispatch_daemon(
    rest: &[String],
    socket: PathBuf,
    config: config::Config,
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
    match rest[0].as_str() {
        "run" => {
            let tail = &rest[1..];
            if help::wants_help(tail) {
                println!("{}", help::daemon_run().render());
                return Ok(());
            }
            or_usage(
                commands::daemon_cmd::run_foreground(tail, socket, config),
                help::daemon_run,
            )
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

/// Dispatch the `kv` group.
fn dispatch_kv(rest: &[String], socket: &std::path::Path) -> Result<(), CliError> {
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

    let req = match sub {
        "define" => or_usage(commands::parse_kv_define(kv_args), leaf_help)?,
        "set" => or_usage(
            commands::parse_kv_set(kv_args, || {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                Ok(buf)
            }),
            leaf_help,
        )?,
        "get" => or_usage(commands::parse_kv_single_key("get", kv_args), leaf_help)?,
        "del" => or_usage(commands::parse_kv_del(kv_args), leaf_help)?,
        "unpin" => or_usage(commands::parse_kv_single_key("unpin", kv_args), leaf_help)?,
        "pin" => or_usage(commands::parse_kv_pin(kv_args), leaf_help)?,
        "list" => {
            if !kv_args.is_empty() {
                return Err(CliError::Usage {
                    msg: format!("`kv list` takes no arguments: {kv_args:?}"),
                    help: help::kv_list,
                });
            }
            protocol::wire::Request::KvList
        }
        _ => unreachable!("leaf_help match covers all known subcommands"),
    };
    Ok(run_client(socket, &req)?)
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
