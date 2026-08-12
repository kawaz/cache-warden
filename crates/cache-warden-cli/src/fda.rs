//! Full Disk Access: who needs it, and how each surface probes for it.
//!
//! macOS makes the daemon (not `op`) the responsible process when it spawns
//! the 1Password CLI, so reaching 1Password's application-support data needs
//! Full Disk Access granted to `CacheWarden.app`. Without it the user gets a
//! system permission dialog on every `op` launch — which is exactly the
//! papercut cache-warden exists to remove (DR-0020,
//! `.claude/rules/daemon-notarized-binary.md`).
//!
//! Three surfaces ask "does this config even need FDA?" — `daemon register`'s
//! setup flow, the daemon's own startup check, and `daemon status` — so
//! [`has_op_sources`] lives here rather than being re-derived per call site.
//!
//! # Who may probe
//!
//! TCC attributes a probe to the process that performs it, so only code
//! running *inside* the app bundle can ask a meaningful question:
//! [`check_in_process`] is for the daemon. A CLI on `PATH` (Homebrew / cargo
//! build) has a different identity, and probing there would answer about a
//! process nobody cares about — which is why `daemon status` asks the running
//! daemon over the control socket instead, and `daemon register` re-launches
//! the installed bundle (`macos_tcc::check_via_app_bundle` with
//! [`SELF_CHECK_ARGS`]) to run the probe under the right identity.

#![cfg(target_os = "macos")]

use crate::config::{CommandTable, Config};

/// The argv `check_via_app_bundle` passes to the re-launched bundle so it
/// performs the probe and writes the result file instead of starting a daemon.
pub const SELF_CHECK_ARGS: &[&str] = &["internal", "fda-check", "--raw"];

/// Return `true` when running this config can make the daemon spawn the `op`
/// CLI — the only reason cache-warden needs Full Disk Access.
///
/// Three ways a config gets there:
///
/// - a `[kv.*]` entry with `source = "op"`,
/// - an `[authsock.sources.*]` of kind `op`,
/// - a `[kv.*]` **command** source whose program is `op` (the documented
///   `argv = ["op", "read", "op://…"]` shape).
///
/// The command case is matched on the program's basename only, so anything
/// that reaches `op` through another program — a wrapper script, `env op …`,
/// `sh -c "op read …"` — reads as a false negative here. Such a config falls
/// back to the per-launch system dialog, the same as before any of this
/// existed; there is no static way to see through the intermediate program.
pub fn has_op_sources(config: &Config) -> bool {
    let has_kv_op = config
        .kv
        .values()
        .any(|entry| entry.source.as_deref() == Some("op"));
    let has_authsock_op = config
        .authsock
        .sources
        .values()
        .any(|src| src.kind.as_str() == "op");
    has_kv_op || has_authsock_op || config.kv.values().any(command_source_runs_op)
}

/// `true` when a `[kv.*]` entry is a command source whose program is `op`.
///
/// The `command` table is held as a raw `toml::Value` (so the bare-array form
/// can be rejected with a friendly error at validation time), so it is
/// re-parsed here; an unparseable table is simply not a match — reporting the
/// schema error is validation's job, not this probe's.
fn command_source_runs_op(entry: &crate::config::KvEntryConfig) -> bool {
    if entry.source.as_deref() != Some("command") {
        return false;
    }
    let Some(raw) = entry.command.clone() else {
        return false;
    };
    let Ok(table) = raw.try_into::<CommandTable>() else {
        return false;
    };
    table
        .argv
        .as_ref()
        .and_then(|argv| argv.first())
        .map(|program| {
            std::path::Path::new(program)
                .file_name()
                .is_some_and(|name| name == "op")
        })
        .unwrap_or(false)
}

/// Probe Full Disk Access in-process (for code running inside the bundle).
pub fn check_in_process() -> macos_tcc::AuthState {
    macos_tcc::check(macos_tcc::Permission::FullDiskAccess)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        Config::parse(toml).expect("config parses")
    }

    #[test]
    fn op_kv_source_needs_fda() {
        assert!(has_op_sources(&cfg(
            "[kv.token]\nsource = \"op\"\nop.uri = \"op://v/i/f\"\n"
        )));
    }

    #[test]
    fn command_source_invoking_op_needs_fda() {
        assert!(has_op_sources(&cfg(
            "[kv.token]\nsource = \"command\"\ncommand.argv = [\"op\", \"read\", \"op://v/i/f\"]\n"
        )));
        // Absolute path to the same program counts — the match is on the
        // basename, not the literal string.
        assert!(has_op_sources(&cfg(
            "[kv.token]\nsource = \"command\"\ncommand.argv = [\"/opt/homebrew/bin/op\", \"read\", \"op://v/i/f\"]\n"
        )));
    }

    #[test]
    fn ordinary_command_source_does_not_need_fda() {
        assert!(!has_op_sources(&cfg(
            "[kv.token]\nsource = \"command\"\ncommand.argv = [\"/usr/bin/security\", \"find-generic-password\"]\n"
        )));
        // A program whose name merely starts with "op" is not `op`.
        assert!(!has_op_sources(&cfg(
            "[kv.token]\nsource = \"command\"\ncommand.argv = [\"openssl\", \"rand\", \"-hex\", \"16\"]\n"
        )));
    }

    #[test]
    fn empty_config_needs_nothing() {
        assert!(!has_op_sources(&cfg("")));
    }
}
