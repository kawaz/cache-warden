//! CLI help behaviour at every level (the dispatcher's help/usage routing).
//!
//! These pin the contract that unit tests on the pure renderer cannot reach:
//! *where* help goes (stdout vs stderr) and *which* exit code each shape uses.
//!
//!   - any `--help`        => help to stdout, exit 0
//!   - group with no sub   => group help to stdout, exit 0 (top / kv / config / daemon)
//!   - leaf missing args   => `<msg>` + leaf help to stderr, exit 1
//!   - unknown subcommand  => one-line error to stderr, exit 1 (no help dump)
//!
//! Run against the real binary so the wiring (arg split, `--socket` removal,
//! per-level routing) is exercised end to end.

use std::process::{Command, Output};

/// Invoke the built `cache-warden` binary with `args`. A bogus `--socket` keeps
/// any command that *would* reach the daemon from touching a real socket; help
/// and usage paths short-circuit before any connection attempt.
fn cw(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .args(args)
        .env("CACHE_WARDEN_CONFIG", "/nonexistent/cw-help-test.toml")
        .output()
        .expect("spawn cache-warden")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---- --help at every level: stdout, exit 0 ------------------------------

#[test]
fn help_flag_goes_to_stdout_exit_zero_at_every_level() {
    for args in [
        &["--help"][..],
        &["daemon", "--help"][..],
        &["daemon", "run", "--help"][..],
        &["daemon", "register", "--help"][..],
        &["daemon", "unregister", "--help"][..],
        &["daemon", "status", "--help"][..],
        &["kv", "--help"][..],
        &["kv", "define", "--help"][..],
        &["kv", "set", "--help"][..],
        &["kv", "get", "--help"][..],
        &["kv", "del", "--help"][..],
        &["kv", "pin", "--help"][..],
        &["run", "--help"][..],
        &["inject", "--help"][..],
        &["config", "--help"][..],
        &["config", "show", "--help"][..],
    ] {
        let o = cw(args);
        assert!(o.status.success(), "{args:?} should exit 0");
        assert!(stdout(&o).contains("Usage:"), "{args:?} help to stdout");
        assert!(stderr(&o).is_empty(), "{args:?} nothing on stderr");
    }
}

#[test]
fn top_help_lists_commands_not_per_flag_detail() {
    let o = cw(&["--help"]);
    let out = stdout(&o);
    assert!(out.contains("Commands:"));
    assert!(out.contains("Environment:"));
    // The per-flag `kv set` detail lives in `kv set --help`, not here.
    assert!(!out.contains("ps / shell history"));
    assert!(!out.contains("Hold the value Active"));
}

#[test]
fn kv_set_help_carries_options_and_kv_pin_carries_detail() {
    let set_help = stdout(&cw(&["kv", "set", "--help"]));
    // Positional VALUE + pipe guidance (no --value/--value-stdin flags).
    assert!(set_help.contains("KEY [VALUE]"));
    assert!(!set_help.contains("--value-stdin"));
    assert!(stdout(&cw(&["kv", "pin", "--help"])).contains("Hold the value Active"));
}

#[test]
fn kv_define_help_carries_command_and_source() {
    let out = stdout(&cw(&["kv", "define", "--help"]));
    assert!(out.contains("--command ARGV..."));
    assert!(out.contains("--source URI"));
    assert!(out.contains("lazily"));
}

#[test]
fn daemon_group_help_lists_service_subcommands() {
    // DR-0019: register / unregister / status are now real subcommands.
    let out = stdout(&cw(&["daemon"]));
    assert!(out.contains("register"));
    assert!(out.contains("unregister"));
    assert!(out.contains("status"));
}

#[test]
fn daemon_register_help_carries_flags() {
    let out = stdout(&cw(&["daemon", "register", "--help"]));
    assert!(out.contains("--socket PATH"));
    assert!(out.contains("--label NAME"));
    assert!(out.contains("--print"));
}

#[test]
fn kv_top_help_lists_define_subcommand() {
    let out = stdout(&cw(&["kv"]));
    assert!(out.contains("define"));
}

#[test]
fn top_help_lists_run_and_inject() {
    let out = stdout(&cw(&["--help"]));
    assert!(out.contains("run -- CMD"));
    assert!(out.contains("inject"));
}

#[test]
fn dry_run_is_visible_in_every_value_verb_help() {
    // DR-0015 §5: an agent reading help must discover --dry-run on get/run/inject.
    for args in [
        &["kv", "get", "--help"][..],
        &["run", "--help"][..],
        &["inject", "--help"][..],
    ] {
        let out = stdout(&cw(args));
        assert!(out.contains("--dry-run"), "{args:?} mentions --dry-run");
        assert!(out.contains("--reveal"), "{args:?} mentions --reveal");
        // Default-reveal + side-effect note are called out (DR-0015 §5).
        assert!(
            out.to_lowercase().contains("reveal"),
            "{args:?} explains the default is reveal"
        );
        assert!(
            out.contains("side effect") || out.contains("side-effect") || out.contains("re-auth"),
            "{args:?} warns dry-run has side effects: {out}"
        );
    }
}

// ---- group with no subcommand: stdout, exit 0 ---------------------------

#[test]
fn group_without_subcommand_prints_help_to_stdout_exit_zero() {
    for (args, marker) in [
        (&["kv"][..], "cache-warden kv"),
        (&["config"][..], "cache-warden config"),
        (&["daemon"][..], "cache-warden daemon"),
    ] {
        let o = cw(args);
        assert!(o.status.success(), "{args:?} should exit 0");
        let out = stdout(&o);
        assert!(out.contains(marker), "{args:?} prints its group help");
        assert!(out.contains("Commands:"), "{args:?} lists subcommands");
        assert!(stderr(&o).is_empty(), "{args:?} nothing on stderr");
    }
}

// ---- top level with no args: help on stdout, exit 0 (same as groups) ----

#[test]
fn top_level_without_args_prints_help_to_stdout_exit_zero() {
    let o = cw(&[]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("Usage:"));
    assert!(stderr(&o).is_empty());
}

// ---- leaf missing required args: stderr, exit 1 -------------------------

#[test]
fn leaf_missing_args_prints_message_and_help_to_stderr_exit_one() {
    let o = cw(&["kv", "get"]); // missing KEY
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).is_empty(), "no help on stdout for a usage error");
    let err = stderr(&o);
    assert!(err.contains("kv get requires exactly one KEY"));
    assert!(err.contains("cache-warden kv get"), "leaf help shown");
    assert!(err.contains("Usage:"));
}

#[test]
fn kv_set_removed_value_flag_shows_kv_set_help_on_stderr() {
    // `--value` was replaced by the positional VALUE: the error steers to the
    // new form and the leaf help accompanies it on stderr.
    let o = cw(&["kv", "set", "K", "--value", "v"]);
    assert_eq!(o.status.code(), Some(1));
    let err = stderr(&o);
    assert!(
        err.contains("kv set KEY VALUE"),
        "steers to new form: {err}"
    );
    assert!(err.contains("Usage:"), "kv set help accompanies error");
    assert!(err.contains("cache-warden kv set"), "leaf help shown");
}

// ---- unknown subcommand: one-line error, no help dump -------------------

#[test]
fn unknown_subcommand_is_a_one_line_error_without_help_dump() {
    let o = cw(&["kv", "bogus"]);
    assert_eq!(o.status.code(), Some(1));
    let err = stderr(&o);
    assert!(err.contains("unknown kv subcommand: bogus"));
    assert!(
        !err.contains("Usage:"),
        "no full help for a typo'd subcommand"
    );
}

#[test]
fn unknown_top_command_is_a_one_line_error() {
    let o = cw(&["bogus"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("unknown command: bogus"));
    assert!(!stderr(&o).contains("Usage:"));
}

// ---- --version --------------------------------------------------------

#[test]
fn version_flag_prints_version_exit_zero() {
    let o = cw(&["--version"]);
    assert!(o.status.success());
    assert!(stdout(&o).starts_with("cache-warden "));
}
