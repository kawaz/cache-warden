//! cache-warden CLI: the daemon (`run`) and its management client.
//!
//! Hand-rolled argument dispatch (no clap; DR-0002 keeps dependencies small).
//! `run` starts the in-process daemon (DR-0008); the other subcommands are
//! one-shot control-socket clients (see [`commands::client`]).

use std::io::Read as _;
use std::process;

mod commands;
mod config;
mod daemon;
mod protocol;

use commands::client;
use protocol::wire::{OkPayload, Response};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = "cache-warden";

fn print_help(to_stderr: bool) {
    let help_text = format!(
        "\
{NAME} {VERSION}
Secure secret cache: a TTL-managed, zeroize-backed key/value cache for secrets.

Usage:
    {NAME} <COMMAND> [OPTIONS]

Commands:
    run                Start the daemon in the foreground
    ping               Check that the daemon is alive
    status             Show daemon info and the (value-free) entry list
    kv set <KEY> ...   Cache a value (static or command source)
    kv get <KEY>       Fetch a cached value
    kv del <KEY>       Delete a cached value
    kv list            List cached key names
    config show        Show the effective configuration
    config path        Show the config file path (or the search order)
    config edit        Open the config in $EDITOR

`kv set` options:
    --value V          Use the literal string V as the value
    --value-stdin      Read the value from stdin (binary safe)
    --command ARGV...  Run ARGV; its stdout is the value (regenerable)
    --soft-ttl DUR     Soft TTL (re-auth to extend). e.g. 1h, 30m, 45s, 86400
    --hard-ttl DUR     Hard TTL (value zeroized at expiry)

Global options:
    --socket PATH      Control socket path. Precedence:
                       --socket > [daemon].socket in config >
                       $XDG_STATE_HOME/cache-warden/control.sock
    --help             Show this help message
    --version          Show version

Environment:
    CACHE_WARDEN_CONFIG  Explicit config file path (highest config priority)
    XDG_CONFIG_HOME      Base dir for the config file
                         ($XDG_CONFIG_HOME/cache-warden/config.toml)
    XDG_STATE_HOME       Base dir for the default control socket path
    EDITOR / VISUAL      Editor launched by `config edit`"
    );
    if to_stderr {
        eprintln!("{help_text}");
    } else {
        println!("{help_text}");
    }
}

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
                OkPayload::Deleted { deleted } => {
                    println!("{}", if deleted { "deleted" } else { "not found" })
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
                            let regen = if e.regenerable {
                                "regenerable"
                            } else {
                                "static"
                            };
                            println!("  {} [{}] ({})", e.name, e.state, regen);
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
        UpstreamFailed => "upstream failed",
        Internal => "internal error",
    }
}

/// Run a client command (connect, exchange one request/response, render).
fn run_client(socket: &std::path::Path, req: &protocol::wire::Request) -> Result<(), String> {
    let resp = client::round_trip(socket, req)?;
    render_response(resp)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        print_help(true);
        process::exit(1);
    }

    // Top-level --help / --version take precedence.
    if args[0] == "--help" {
        print_help(false);
        return Ok(());
    }
    if args[0] == "--version" {
        println!("{NAME} {VERSION}");
        return Ok(());
    }

    let command = args[0].clone();
    let tail = &args[1..];

    // Resolve --socket (anywhere in the tail) once; None means "not on the CLI".
    let (cli_socket, rest) = commands::take_socket_flag(tail)?;

    // Load the config (or defaults) up front: every command needs the resolved
    // socket, and `run` / `config` need the rest of it (DR-0010).
    let loaded = config::load().map_err(|e| e.to_string())?;
    let socket = commands::resolve_socket(cli_socket, loaded.config.socket_path());

    match command.as_str() {
        "run" => {
            if !rest.is_empty() {
                return Err(format!("`run` takes no positional arguments: {:?}", rest));
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start runtime: {e}"))?;
            rt.block_on(daemon::server::run(socket, loaded.config))
                .map_err(|e| format!("daemon error: {e}"))
        }
        "config" => commands::config_cmd::run(rest, &loaded),
        "ping" => run_client(&socket, &protocol::wire::Request::Ping),
        "status" => run_client(&socket, &protocol::wire::Request::Status),
        "kv" => {
            let sub = rest
                .first()
                .cloned()
                .ok_or("kv requires a subcommand: set | get | del | list")?;
            let kv_args = &rest[1..];
            let req = match sub.as_str() {
                "set" => commands::parse_kv_set(kv_args, || {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    Ok(buf)
                })?,
                "get" => commands::parse_kv_single_key("get", kv_args)?,
                "del" => commands::parse_kv_single_key("del", kv_args)?,
                "list" => {
                    if !kv_args.is_empty() {
                        return Err(format!("`kv list` takes no arguments: {kv_args:?}"));
                    }
                    protocol::wire::Request::KvList
                }
                other => return Err(format!("unknown kv subcommand: {other}")),
            };
            run_client(&socket, &req)
        }
        "--help" | "--version" => unreachable!("handled above"),
        other => Err(format!("unknown command: {other} (try `{NAME} --help`)")),
    }
}

fn main() {
    if let Err(e) = run() {
        if !e.is_empty() {
            eprintln!("{NAME}: {e}");
        }
        process::exit(1);
    }
}
