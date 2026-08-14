//! Argument grammars for every CLI level, expressed as [`clap::Command`] trees.
//!
//! Each level (the top-level dispatch, the `daemon` / `kv` / `config` groups,
//! and every leaf) has one builder here, so the accepted flags of a command live
//! in exactly one place. The leaf builders are consumed by the pure parse
//! functions in [`crate::commands`], which turn an [`clap::ArgMatches`] into a
//! protocol request; the dispatch builder is consumed by `main.rs`.
//!
//! Two deliberate departures from clap's defaults:
//!
//! - **Help and version stay ours.** `help.rs` renders the section layout the
//!   CLI contract pins (subcommands → level options → global options →
//!   environment), which clap's generator cannot reproduce, so every level here
//!   sets `disable_help_flag` / `disable_version_flag` and the dispatcher routes
//!   `--help` itself.
//! - **Errors are re-worded into the CLI's own vocabulary** by
//!   [`parse_error`], so a mistyped flag reads `unknown option for `kv set`:
//!   --bogus` at every level instead of clap's phrasing.

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, Command};

/// A grammar shell shared by every level: argv without a binary name (the
/// dispatcher has already peeled the command path off), and no clap-generated
/// help / version (see the module docs).
fn level(name: &'static str) -> Command {
    Command::new(name)
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
}

/// The global `--socket PATH` option (DR-0010).
///
/// Marked `global` so it parses at *any* depth: `cache-warden --socket P kv get
/// K` and `cache-warden kv get K --socket P` are the same invocation.
fn socket_arg() -> Arg {
    Arg::new("socket")
        .long("socket")
        .value_name("PATH")
        .num_args(1)
        .global(true)
}

/// Re-word a clap parse failure in the CLI's own error vocabulary.
///
/// `cmd` is the grammar that rejected the argv and `verb` names the level for the
/// operator (`kv set`, `daemon register`, ...). An undeclared long option becomes
/// `unknown option for `<verb>`: --x`; a surplus positional becomes `unexpected
/// argument: x` — including one that is *shaped* like an option, because a
/// declared flag reaching this path arrived where only positionals are accepted
/// (after a `--` separator), so it is data, not a typo. A flag given without its
/// value names the value it wanted (`--socket requires a PATH argument`).
pub fn parse_error(cmd: &Command, verb: &str, e: clap::Error) -> String {
    let invalid = e.get(ContextKind::InvalidArg).map(render_context);
    match e.kind() {
        ErrorKind::UnknownArgument | ErrorKind::TooManyValues | ErrorKind::InvalidSubcommand => {
            match invalid {
                Some(arg) if is_undeclared_long_option(cmd, &arg) => {
                    format!(
                        "unknown option for `{verb}`: {}{}",
                        arg_name(&arg),
                        literal_value_steer(cmd)
                    )
                }
                Some(arg) => format!("unexpected argument: {arg}"),
                None => format!("invalid arguments for `{verb}`"),
            }
        }
        ErrorKind::InvalidValue | ErrorKind::WrongNumberOfValues => match invalid {
            // clap renders the offender as `--socket <PATH>`; both halves are
            // exactly what the message needs.
            Some(arg) => match split_arg_and_value_name(&arg) {
                Some((long, value_name)) => format!("{long} requires a {value_name} argument"),
                None => format!("{} requires an argument", arg_name(&arg)),
            },
            None => format!("a required value is missing for `{verb}`"),
        },
        _ => {
            // Anything else (a missing required positional, a conflict) already
            // reads well enough in clap's own words; strip the `error: ` prefix
            // so it composes with the `cache-warden: ` lead the caller adds.
            let msg = e.to_string();
            let first = msg.lines().next().unwrap_or("").trim();
            first
                .strip_prefix("error: ")
                .unwrap_or(first)
                .trim()
                .to_string()
        }
    }
}

/// Flatten an error-context value to a plain string.
fn render_context(v: &ContextValue) -> String {
    match v {
        ContextValue::String(s) => s.clone(),
        ContextValue::Strings(v) => v.join(", "),
        other => format!("{other}"),
    }
}

/// The bare flag name from a clap-rendered arg (`--socket <PATH>` -> `--socket`).
fn arg_name(rendered: &str) -> &str {
    rendered.split_whitespace().next().unwrap_or(rendered)
}

/// Split a clap-rendered arg into `(long, VALUE_NAME)`, or `None` when it
/// carries no value placeholder.
fn split_arg_and_value_name(rendered: &str) -> Option<(&str, &str)> {
    let (long, rest) = rendered.split_once(" <")?;
    let value_name = rest.trim_end_matches("...").trim_end_matches('>');
    Some((long, value_name))
}

/// The remediation clause appended to an unknown-option error: how to pass the
/// token as data instead.
///
/// Only levels that actually take a positional get it. On `kv set` the token in
/// question may well be a value the operator meant literally (a PEM, a password
/// starting `--`), and `--` is the way to say so. On a level with no positionals
/// (`inject`, `daemon register`, `kv list`) the advice would be false — nothing
/// after a `--` would be accepted there — so it is omitted. A `last`-only
/// positional (`run`'s command argv) is already reached *through* a `--`, so it
/// does not count either.
fn literal_value_steer(cmd: &Command) -> &'static str {
    let takes_data = cmd.get_positionals().any(|a| !a.is_last_set());
    if takes_data {
        " (to pass it as a literal value, put it after a `--` separator)"
    } else {
        ""
    }
}

/// Whether `rendered` is an option-shaped token that this grammar does not
/// declare (so reporting it as an unknown option is accurate).
fn is_undeclared_long_option(cmd: &Command, rendered: &str) -> bool {
    let name = arg_name(rendered);
    match name.strip_prefix("--") {
        None => false,
        Some(bare) => !long_options(cmd).iter().any(|k| k == bare),
    }
}

/// Every long option name this grammar accepts (without the `--`).
fn long_options(cmd: &Command) -> Vec<String> {
    cmd.get_arguments()
        .filter_map(|a| a.get_long().map(|l| l.to_string()))
        .collect()
}

/// Reject a long-option-shaped token that a value-accepting positional would
/// otherwise swallow.
///
/// Design rationale: `kv set KEY VALUE` must accept a hyphen-leading VALUE (a
/// PEM body starts `-----BEGIN`), which means the VALUE positional allows
/// hyphen values — and that makes clap accept a *mistyped flag* in the same slot
/// as a literal value, silently caching `--requre-same-user` as the secret.
/// A long option and a PEM are distinguishable by shape: an option's `--` is
/// followed by an alphanumeric (`--bogus`), a PEM's by another dash
/// (`-----BEGIN`). So a token matching the option shape whose name this grammar
/// does not declare is reported as an unknown option, and everything else
/// reaches the positional. `head` must be the argv *before* any `--` separator:
/// after it, every token is positional by contract, hyphens and all.
pub fn reject_unknown_long_options(
    cmd: &Command,
    head: &[String],
    verb: &str,
) -> Result<(), String> {
    let known = long_options(cmd);
    for tok in head {
        let Some(rest) = tok.strip_prefix("--") else {
            continue;
        };
        // `--` itself, and `---anything` (a PEM fence, a delimiter), are not
        // option shapes.
        if !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let name = rest.split('=').next().unwrap_or(rest);
        if !known.iter().any(|k| k == name) {
            return Err(format!(
                "unknown option for `{verb}`: --{name}{}",
                literal_value_steer(cmd)
            ));
        }
    }
    Ok(())
}

// ---- shared leaf options ------------------------------------------------

/// `--soft-ttl DUR` / `--hard-ttl DUR`, shared by `kv set` and `kv define`.
fn ttl_args() -> [Arg; 2] {
    [
        Arg::new("soft-ttl")
            .long("soft-ttl")
            .value_name("DUR")
            .num_args(1),
        Arg::new("hard-ttl")
            .long("hard-ttl")
            .value_name("DUR")
            .num_args(1),
    ]
}

/// The value-type flags (DR-0016), accepted on `kv define` and rejected with a
/// steer on `kv set` (which is why both leaves declare them).
fn otp_args() -> [Arg; 4] {
    [
        Arg::new("type").long("type").value_name("TYPE").num_args(1),
        Arg::new("otp-digits")
            .long("otp-digits")
            .value_name("N")
            .num_args(1),
        Arg::new("otp-period")
            .long("otp-period")
            .value_name("SEC")
            .num_args(1),
        Arg::new("otp-algorithm")
            .long("otp-algorithm")
            .value_name("ALGO")
            .num_args(1),
    ]
}

/// `--namespace NS` (DR-0017 §4), accepted by every kv leaf plus `run` /
/// `inject` / `status`.
fn namespace_arg() -> Arg {
    Arg::new("namespace")
        .long("namespace")
        .value_name("NS")
        .num_args(1)
        .action(ArgAction::Append)
}

/// `--dry-run` / `--reveal` (DR-0015 §4) for the three value-emitting verbs.
fn mode_args() -> [Arg; 2] {
    [
        Arg::new("dry-run").long("dry-run").action(ArgAction::Count),
        Arg::new("reveal").long("reveal").action(ArgAction::Count),
    ]
}

/// `--expected-version N` (DR-0034 §4), shared by `kv set` (optional there) and
/// `kv claim` (where the wire field is not optional, so the parse insists on it).
///
/// The value stays a `String` here — like every other valued option at this
/// layer — so a non-numeric argument is reported by
/// [`crate::commands::parse_kv_set`]'s own wording rather than clap's.
fn expected_version_arg() -> Arg {
    Arg::new("expected-version")
        .long("expected-version")
        .value_name("N")
        .num_args(1)
}

/// `--claim-token TOKEN` (DR-0034 §4), shared by `kv set` and `kv unclaim`.
fn claim_token_arg() -> Arg {
    Arg::new("claim-token")
        .long("claim-token")
        .value_name("TOKEN")
        .num_args(1)
}

/// `--defs FILE`, repeatable, shared by `kv define` / `run` / `inject`.
fn defs_arg() -> Arg {
    Arg::new("defs")
        .long("defs")
        .value_name("FILE")
        .num_args(1)
        .action(ArgAction::Append)
}

// ---- kv leaves ----------------------------------------------------------

/// `kv set [OPTIONS] [--] KEY [VALUE]` (DR-0030 guard flags included).
///
/// `VALUE` allows hyphen values so a PEM body needs no `--` separator; the
/// mistyped-flag hazard that opens is closed by [`reject_unknown_long_options`].
/// The flags removed in earlier iterations (`--value`, `--command`, the `--otp-*`
/// family) stay declared but hidden so the parser can answer them with a steer
/// to their replacement instead of a bare "unknown option".
pub fn kv_set() -> Command {
    level("set")
        .arg(Arg::new("KEY"))
        .arg(Arg::new("VALUE").allow_hyphen_values(true))
        .arg(namespace_arg())
        .args(ttl_args())
        .arg(
            Arg::new("require-same-user")
                .long("require-same-user")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("require-same-shell")
                .long("require-same-shell")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("require-same-ancestor")
                .long("require-same-ancestor")
                .value_name("NAME")
                .num_args(1)
                .action(ArgAction::Append)
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new("require-command")
                .long("require-command")
                .value_name("NAME")
                .num_args(1)
                .action(ArgAction::Append)
                .allow_hyphen_values(true),
        )
        .arg(expected_version_arg())
        .arg(claim_token_arg())
        // Retired grammar, kept declared for the steer (see the doc above).
        .arg(Arg::new("value").long("value").num_args(1).hide(true))
        .arg(
            Arg::new("value-stdin")
                .long("value-stdin")
                .action(ArgAction::SetTrue)
                .hide(true),
        )
        .arg(
            Arg::new("command")
                .long("command")
                .num_args(0..)
                .allow_hyphen_values(true)
                .hide(true),
        )
        .args(otp_args().map(|a| a.hide(true)))
        .arg(socket_arg())
}

/// `kv define (<KEY> (--command ARGV... | --source URI) | --defs FILE...)`.
///
/// `--command` takes every remaining token verbatim (`num_args(1..)` plus hyphen
/// values), which is what makes a later `--` part of the child's argv rather
/// than our separator — the documented intersection of the two consume-the-rest
/// rules.
///
/// The value-type flags (`--type` / `--otp-*`) are absent on purpose: they are
/// lifted off the option head by [`crate::commands::take_otp_flags`] before this
/// grammar sees the argv, so each flag is still declared in exactly one place.
pub fn kv_define() -> Command {
    level("define")
        .arg(Arg::new("KEY"))
        .arg(namespace_arg())
        .arg(
            Arg::new("command")
                .long("command")
                .value_name("ARGV")
                .num_args(1..)
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new("command-cwd")
                .long("command-cwd")
                .value_name("PATH")
                .num_args(1),
        )
        .arg(
            Arg::new("command-env")
                .long("command-env")
                .value_name("NAME=VALUE")
                .num_args(1)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("source")
                .long("source")
                .value_name("URI")
                .num_args(1),
        )
        .arg(defs_arg())
        .args(ttl_args())
        .arg(socket_arg())
}

/// `kv get [--namespace NS] <KEY> [--dry-run | --reveal]`.
pub fn kv_get() -> Command {
    level("get")
        .arg(Arg::new("KEY"))
        .arg(namespace_arg())
        .args(mode_args())
        .arg(socket_arg())
}

/// `kv unpin [--namespace NS] <KEY>`.
pub fn kv_unpin() -> Command {
    level("unpin")
        .arg(Arg::new("KEY"))
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `kv del [--namespace NS] <KEY> [--with-define]`.
pub fn kv_del() -> Command {
    level("del")
        .arg(Arg::new("KEY"))
        .arg(
            Arg::new("with-define")
                .long("with-define")
                .action(ArgAction::Count),
        )
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `kv pin [--namespace NS] <KEY> <DUR>`.
pub fn kv_pin() -> Command {
    level("pin")
        .arg(Arg::new("KEY"))
        .arg(Arg::new("DUR"))
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `kv claim [--namespace NS] <KEY> <DUR> --expected-version N` (DR-0034 §4).
///
/// Same shape as `kv pin`: a KEY, a positional duration, and the hold is taken
/// for that long. `--expected-version` is not marked `required` in the grammar
/// so its absence is reported in the CLI's own words by
/// [`crate::commands::parse_kv_claim`], the way a missing KEY / DUR already is.
pub fn kv_claim() -> Command {
    level("claim")
        .arg(Arg::new("KEY"))
        .arg(Arg::new("DUR"))
        .arg(expected_version_arg())
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `kv unclaim [--namespace NS] <KEY> --claim-token TOKEN` (DR-0034 §4).
pub fn kv_unclaim() -> Command {
    level("unclaim")
        .arg(Arg::new("KEY"))
        .arg(claim_token_arg())
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `kv list [--namespace NS] [--all]`.
pub fn kv_list() -> Command {
    level("list")
        .arg(Arg::new("all").long("all").action(ArgAction::Count))
        .arg(namespace_arg())
        .arg(socket_arg())
}

/// `status [--namespace NS] [--all]` (the entry listing, not `daemon status`).
pub fn status() -> Command {
    level("status")
        .arg(Arg::new("all").long("all").action(ArgAction::Count))
        .arg(namespace_arg())
        .arg(socket_arg())
}

// ---- run / inject ------------------------------------------------------

/// `run [OPTIONS] -- CMD [ARGS...]`.
///
/// `last(true)` on the command argv is what makes the `--` separator mandatory:
/// a token before it cannot reach the positional, so `run echo` fails as a usage
/// error instead of silently exec'ing.
pub fn run_cmd() -> Command {
    level("run")
        .arg(
            Arg::new("env")
                .long("env")
                .value_name("NAME=VALUE")
                .num_args(1)
                .action(ArgAction::Append),
        )
        .arg(defs_arg())
        .arg(namespace_arg())
        .args(mode_args())
        .arg(
            Arg::new("CMD")
                .num_args(0..)
                .allow_hyphen_values(true)
                .last(true),
        )
        .arg(socket_arg())
}

/// `inject [OPTIONS]` (no positionals: the template travels on stdin / `--in`).
pub fn inject_cmd() -> Command {
    level("inject")
        .arg(Arg::new("in").long("in").value_name("FILE").num_args(1))
        .arg(Arg::new("out").long("out").value_name("FILE").num_args(1))
        .arg(defs_arg())
        .arg(namespace_arg())
        .args(mode_args())
        .arg(socket_arg())
}

// ---- daemon leaves -----------------------------------------------------

/// `daemon run` (no flags of its own beyond the global socket).
pub fn daemon_run() -> Command {
    level("run").arg(socket_arg())
}

/// `daemon register [--socket PATH] [--label NAME] [--executable PATH] [--print]`.
pub fn daemon_register() -> Command {
    level("register")
        .arg(
            Arg::new("label")
                .long("label")
                .value_name("NAME")
                .num_args(1),
        )
        .arg(
            Arg::new("executable")
                .long("executable")
                .value_name("PATH")
                .num_args(1),
        )
        .arg(Arg::new("print").long("print").action(ArgAction::Count))
        .arg(socket_arg())
}

/// `daemon unregister [--label NAME]`, also the grammar of `daemon status`.
pub fn daemon_unregister() -> Command {
    level("unregister")
        .arg(
            Arg::new("label")
                .long("label")
                .value_name("NAME")
                .num_args(1),
        )
        .arg(socket_arg())
}

/// `daemon restart --graceful` (DR-0029).
pub fn daemon_restart() -> Command {
    level("restart")
        .arg(
            Arg::new("graceful")
                .long("graceful")
                .action(ArgAction::Count),
        )
        .arg(socket_arg())
}

// ---- hidden internal helpers -------------------------------------------
//
// Not user-facing (the daemon re-executes its own binary with these), so they
// carry no help page — but their grammar belongs here with the rest so no
// hand-rolled scanner survives anywhere in the CLI.

/// `<op-private-key-subcommand> <ITEM_ID> [--account ACCOUNT]`.
pub fn op_private_key() -> Command {
    level("op-private-key").arg(Arg::new("ITEM_ID")).arg(
        Arg::new("account")
            .long("account")
            .value_name("ACCOUNT")
            .num_args(1),
    )
}

/// `internal fda-check --raw --result-file PATH`.
///
/// `--help` is declared as an ordinary flag (the shell sets `disable_help_flag`)
/// because this level prints its own one-screen usage rather than a help page.
pub fn internal_fda_check() -> Command {
    level("fda-check")
        .arg(Arg::new("raw").long("raw").action(ArgAction::Count))
        .arg(
            Arg::new("result-file")
                .long("result-file")
                .value_name("PATH")
                .num_args(1),
        )
        .arg(Arg::new("help").long("help").action(ArgAction::Count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    /// The global `--socket` parses ahead of a subcommand as well as after it —
    /// the position independence the flag's documentation always claimed.
    #[test]
    fn socket_is_accepted_before_and_after_the_positional() {
        for args in [
            s(&["--socket", "/x.sock", "K"]),
            s(&["K", "--socket=/x.sock"]),
        ] {
            let m = kv_get().try_get_matches_from(&args).unwrap();
            assert_eq!(
                m.get_one::<String>("socket").map(String::as_str),
                Some("/x.sock"),
                "{args:?}"
            );
            assert_eq!(m.get_one::<String>("KEY").map(String::as_str), Some("K"));
        }
    }

    /// A hyphen-leading VALUE (a PEM body) reaches the positional without a `--`
    /// separator, while a mistyped long option in the same slot is still caught.
    #[test]
    fn value_slot_takes_a_pem_but_not_a_mistyped_flag() {
        let cmd = kv_set();
        let head = s(&["K", "-----BEGIN OPENSSH PRIVATE KEY-----"]);
        reject_unknown_long_options(&cmd, &head, "kv set").expect("a PEM is not an option");

        let err = reject_unknown_long_options(&cmd, &s(&["K", "--requre-same-user"]), "kv set")
            .unwrap_err();
        assert!(
            err.contains("unknown option for `kv set`: --requre-same-user"),
            "{err}"
        );
        // The operator may have meant it literally, so the message says how.
        assert!(err.contains("put it after a `--` separator"), "{err}");

        // A declared option is left for clap to parse (and its `=VALUE` form too).
        reject_unknown_long_options(&cmd, &s(&["--soft-ttl=1h", "K", "v"]), "kv set").unwrap();
    }

    #[test]
    fn parse_error_names_the_unknown_option_and_the_missing_value() {
        let cmd = kv_set();
        let err = cmd
            .clone()
            .try_get_matches_from(s(&["--bogus", "K"]))
            .unwrap_err();
        assert_eq!(
            parse_error(&cmd, "kv set", err),
            "unknown option for `kv set`: --bogus \
             (to pass it as a literal value, put it after a `--` separator)"
        );

        // A level with no positionals must NOT suggest `--`: nothing after it
        // would be accepted there, so the advice would send the operator in
        // circles.
        let cmd = inject_cmd();
        let err = cmd
            .clone()
            .try_get_matches_from(s(&["--bogus"]))
            .unwrap_err();
        assert_eq!(
            parse_error(&cmd, "inject", err),
            "unknown option for `inject`: --bogus"
        );

        // A *declared* flag that lands where only positionals are accepted is
        // data, not a typo: it is reported as a surplus argument.
        let cmd = kv_define();
        let err = cmd
            .clone()
            .try_get_matches_from(s(&["--source", "op://v/i/f", "--", "K", "--command"]))
            .unwrap_err();
        assert_eq!(
            parse_error(&cmd, "kv define", err),
            "unexpected argument: --command"
        );

        let cmd = daemon_register();
        let err = cmd
            .clone()
            .try_get_matches_from(s(&["--socket"]))
            .unwrap_err();
        assert_eq!(
            parse_error(&cmd, "daemon register", err),
            "--socket requires a PATH argument"
        );
    }

    /// `--command` swallows the rest of the line, `--` included, so a command
    /// source and a `--`-protected KEY cannot be combined (documented, accepted).
    #[test]
    fn define_command_consumes_the_remaining_argv() {
        let m = kv_define()
            .try_get_matches_from(s(&["K", "--command", "prog", "--", "x"]))
            .unwrap();
        let argv: Vec<String> = m.get_many::<String>("command").unwrap().cloned().collect();
        assert_eq!(argv, s(&["prog", "--", "x"]));
    }

    /// `run` requires its `--` separator: a bare command word is a usage error.
    #[test]
    fn run_requires_the_double_dash_separator() {
        assert!(run_cmd().try_get_matches_from(s(&["echo"])).is_err());
        let m = run_cmd()
            .try_get_matches_from(s(&["--", "echo", "--x"]))
            .unwrap();
        let argv: Vec<String> = m.get_many::<String>("CMD").unwrap().cloned().collect();
        assert_eq!(argv, s(&["echo", "--x"]));
    }
}
