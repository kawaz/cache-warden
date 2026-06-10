//! The `cache-warden daemon` group: daemon lifecycle commands.
//!
//! The daemon is isolated under its own group so that lifecycle operations
//! (which start a long-lived process) are not visible at the top level next to
//! the everyday client commands (`kv get`, `status`, ...). Mistyping a daemon
//! command there could spawn a second daemon by accident.
//!
//! Implemented:
//! - `daemon run [--socket PATH]` — start the in-process daemon in the
//!   foreground (DR-0008).
//!
//! Planned (not yet wired; see the design CLI taxonomy):
//! - `daemon register` / `daemon unregister` — launchd/systemd service install.
//! - `daemon status` — process and service-registration state (distinct from the
//!   top-level `status`, which lists cache entries).

use std::path::PathBuf;

use crate::config::Config;

const NAME: &str = "cache-warden";

/// Print the `daemon` group help.
fn print_help(to_stderr: bool) {
    let help_text = format!(
        "\
{NAME} daemon
Manage the cache-warden daemon process.

Usage:
    {NAME} daemon <COMMAND> [OPTIONS]

Commands:
    run                Start the daemon in the foreground

`daemon run` options:
    --socket PATH      Control socket path. Precedence:
                       --socket > [daemon].socket in config >
                       $XDG_STATE_HOME/cache-warden/control.sock

Global options:
    --help             Show this help message"
    );
    if to_stderr {
        eprintln!("{help_text}");
    } else {
        println!("{help_text}");
    }
}

/// Dispatch a `daemon` subcommand.
///
/// `socket` is the already-resolved control socket path (DR-0010 precedence is
/// applied by the caller); `config` is the loaded daemon configuration that
/// `daemon run` needs to bind, preload, and serve.
pub fn run(args: &[String], socket: PathBuf, config: Config) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    let tail = if args.is_empty() { &[][..] } else { &args[1..] };
    match sub {
        "" => {
            // No subcommand: show the group help (kawaz CLI preference).
            print_help(false);
            Ok(())
        }
        "--help" => {
            print_help(false);
            Ok(())
        }
        "run" => run_daemon(tail, socket, config),
        other => Err(format!(
            "unknown daemon subcommand: {other} (try `{NAME} daemon --help`)"
        )),
    }
}

/// Start the in-process daemon in the foreground (`daemon run`).
fn run_daemon(args: &[String], socket: PathBuf, config: Config) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::parse("").unwrap()
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = run(&["bogus".into()], PathBuf::from("/x.sock"), cfg()).unwrap_err();
        assert!(err.contains("unknown daemon subcommand"));
    }

    #[test]
    fn run_rejects_positional_args() {
        let err = run(
            &["run".into(), "extra".into()],
            PathBuf::from("/x.sock"),
            cfg(),
        )
        .unwrap_err();
        assert!(err.contains("takes no positional arguments"));
    }

    #[test]
    fn no_subcommand_prints_help_ok() {
        // No subcommand resolves to help and succeeds (does not start a daemon).
        assert!(run(&[], PathBuf::from("/x.sock"), cfg()).is_ok());
    }
}
