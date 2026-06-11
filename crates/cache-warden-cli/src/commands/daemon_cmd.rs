//! The `cache-warden daemon` group: daemon lifecycle commands.
//!
//! The daemon is isolated under its own group so that lifecycle operations
//! (which start a long-lived process) are not visible at the top level next to
//! the everyday client commands (`kv get`, `status`, ...). Mistyping a daemon
//! command there could spawn a second daemon by accident.
//!
//! Implemented:
//! - `daemon run [--socket PATH]` — start the in-process daemon in the
//!   foreground (DR-0008). Exposed as [`run_foreground`]; subcommand routing and
//!   `--help` / no-arg handling live in the dispatcher (`main.rs`).
//!
//! Planned (not yet wired; see the design CLI taxonomy):
//! - `daemon register` / `daemon unregister` — launchd/systemd service install.
//! - `daemon status` — process and service-registration state (distinct from the
//!   top-level `status`, which lists cache entries).

use std::path::PathBuf;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::parse("").unwrap()
    }

    #[test]
    fn run_foreground_rejects_positional_args() {
        let err = run_foreground(&["extra".into()], PathBuf::from("/x.sock"), cfg()).unwrap_err();
        assert!(err.contains("takes no positional arguments"));
    }
}
