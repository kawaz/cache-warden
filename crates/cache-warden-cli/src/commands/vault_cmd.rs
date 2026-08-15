//! The `vault` group: create the encrypted vault, open it, close it, and show
//! its state (DR-0034 §6/§9).
//!
//! Everything here is a pure function over argv (plus, for `unlock`, an
//! injected stdin reader), so the whole surface — including the rule that the
//! recovery code never comes from the command line — is unit-testable without
//! a socket or a terminal.

use crate::protocol::wire::{Request, VaultStateWire, VaultStatusWire};

/// Shown before reading the recovery code when stdin is a terminal, so an
/// interactive run does not look like a hang.
const RECOVERY_PROMPT: &str =
    "Paste this vault's recovery code and press Enter (spaces, hyphens and case are ignored):";

/// Apply a vault leaf's grammar for its flags alone (none of them takes a
/// positional), reporting a mistyped flag in the CLI's own words.
fn parse_flags_only(
    cmd: clap::Command,
    verb: &str,
    args: &[String],
) -> Result<clap::ArgMatches, String> {
    cmd.clone()
        .try_get_matches_from(args)
        .map_err(|e| crate::cli::parse_error(&cmd, verb, e))
}

/// Parse `vault init` (DR-0034 §9).
pub fn parse_vault_init(args: &[String]) -> Result<Request, String> {
    parse_flags_only(crate::cli::vault_init(), "vault init", args)?;
    Ok(Request::VaultInit)
}

/// Parse `vault lock` (DR-0034 §6).
pub fn parse_vault_lock(args: &[String]) -> Result<Request, String> {
    parse_flags_only(crate::cli::vault_lock(), "vault lock", args)?;
    Ok(Request::VaultLock)
}

/// Parse `vault status` (DR-0034 §6). No request of its own: the state travels
/// on the ordinary `status` reply, which the caller then renders with
/// [`render_vault_status`].
pub fn parse_vault_status(args: &[String]) -> Result<(), String> {
    parse_flags_only(crate::cli::vault_status(), "vault status", args).map(|_| ())
}

/// Parse `vault unlock` (DR-0034 §6/§9).
///
/// Without `--recovery` this asks for a passkey unlock, and the daemon answers
/// with the URL of the ceremony page. That is the default because DR-0034 §9
/// keeps the recovery code *off* the everyday path: it is the one credential
/// whose loss cannot be recovered from, and a code pasted routinely is a code
/// that ends up somewhere convenient.
///
/// With `--recovery` the code is read from stdin. `stdin_is_tty` decides only
/// whether the prompt is shown — the code is read from stdin either way, so
/// `pbpaste | cache-warden vault unlock --recovery` and an interactive paste
/// take the same path. `read_line` supplies the bytes (kept as a parameter so
/// the parse is testable).
///
/// A code given as an argument is refused rather than accepted: argv is
/// visible in `ps` and lands in the shell history, and a credential that has
/// leaked there is one the vault can no longer count on.
pub fn parse_vault_unlock(
    args: &[String],
    stdin_is_tty: bool,
    read_line: impl FnOnce() -> std::io::Result<String>,
) -> Result<Request, String> {
    for a in args {
        if !a.starts_with('-') {
            return Err(format!(
                "`vault unlock` takes no arguments (got {a:?}): a recovery code is read \
                 from stdin so it never reaches `ps` or your shell history. Run \
                 `cache-warden vault unlock --recovery` and paste it, or pipe it in \
                 (`... | cache-warden vault unlock --recovery`)"
            ));
        }
    }
    let matches = parse_flags_only(crate::cli::vault_unlock(), "vault unlock", args)?;
    if !matches.get_flag("recovery") {
        return Ok(Request::VaultUnlock {
            recovery_code: None,
        });
    }

    if stdin_is_tty {
        eprintln!("{RECOVERY_PROMPT}");
    }
    let line = read_line().map_err(|e| format!("failed to read the recovery code: {e}"))?;
    let recovery_code = line.trim().to_string();
    if recovery_code.is_empty() {
        return Err(
            "no recovery code was given on stdin. Run `cache-warden vault unlock --recovery` \
             and paste the code, or pipe it in (`... | cache-warden vault unlock --recovery`)"
                .to_string(),
        );
    }
    Ok(Request::VaultUnlock {
        recovery_code: Some(recovery_code),
    })
}

/// Parse `vault add-passkey` (DR-0034 §1c / §10).
pub fn parse_vault_add_passkey(args: &[String]) -> Result<Request, String> {
    let matches = parse_flags_only(crate::cli::vault_add_passkey(), "vault add-passkey", args)?;
    let label = matches
        .get_one::<String>("label")
        .cloned()
        .unwrap_or_else(|| "passkey".to_string());
    Ok(Request::VaultAddPasskey {
        label,
        allow_without_local_approval: matches.get_flag("allow-without-local-approval"),
    })
}

/// Render the vault section of a `status` reply for `vault status` (DR-0034
/// §6/§7).
///
/// `None` means the daemon reported no vault at all — either none is
/// configured, or it predates the field. Only header-level facts are shown
/// (which vault, how many keys open it, how many times its key rotated); entry
/// names and values are not in this reply and are not this command's subject.
pub fn render_vault_status(vault: Option<&VaultStatusWire>) -> String {
    let Some(v) = vault else {
        return "vault: not configured\n\
                This daemon stores nothing on disk. Add a [vault] section to its config and \
                restart it to keep entries across restarts.\n"
            .to_string();
    };
    let mut out = String::new();
    match v.state {
        VaultStateWire::Unlocked => out.push_str("vault: unlocked\n"),
        VaultStateWire::Locked => out.push_str("vault: locked\n"),
        VaultStateWire::NotInitialized => out.push_str("vault: not created yet\n"),
    }

    // The header facts, each shown only when the daemon reported it (a vault
    // that does not exist yet has none of them).
    let rows: Vec<(&str, String)> = [
        v.vault_id.as_ref().map(|id| ("id", id.clone())),
        v.slots.map(|n| ("can be opened by", format!("{n} key(s)"))),
        v.dek_generation.map(|g| ("key rotations", g.to_string())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let label_width = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, value) in &rows {
        out.push_str(&format!(
            "  {label}:{pad} {value}\n",
            pad = " ".repeat(label_width - label.len())
        ));
    }

    match v.state {
        VaultStateWire::Unlocked => {
            out.push_str("Persisted values are readable until `cache-warden vault lock`.\n");
        }
        VaultStateWire::Locked => out.push_str(
            "Persisted values are not readable until `cache-warden vault unlock`; \
             they are intact.\n",
        ),
        VaultStateWire::NotInitialized => out.push_str(
            "Run `cache-warden vault init` to create it — it prints a recovery code, once.\n",
        ),
    }

    // A vault opens for *any* of its keys, so one development key sets the
    // strength of the whole vault (DR-0034 §7). That is a warning, not a fact
    // to list among the others.
    if v.dev_rp_slot {
        out.push_str(
            "warning: one of this vault's keys was registered for development use. Any single \
             key opens the whole vault, so the vault is only as strong as that one. Keep \
             development in its own vault (a separate [vault] profile).\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    fn status(state: VaultStateWire) -> VaultStatusWire {
        VaultStatusWire {
            state,
            vault_id: Some("3f2a9c".into()),
            slots: Some(2),
            dek_generation: Some(1),
            dev_rp_slot: false,
        }
    }

    #[test]
    fn init_and_lock_take_no_arguments_beyond_the_global_socket() {
        assert_eq!(parse_vault_init(&s(&[])).unwrap(), Request::VaultInit);
        assert_eq!(
            parse_vault_init(&s(&["--socket", "/x.sock"])).unwrap(),
            Request::VaultInit
        );
        assert_eq!(parse_vault_lock(&s(&[])).unwrap(), Request::VaultLock);
        parse_vault_status(&s(&[])).unwrap();

        let err = parse_vault_init(&s(&["--bogus"])).unwrap_err();
        assert!(
            err.contains("unknown option for `vault init`: --bogus"),
            "{err}"
        );
    }

    /// The recovery code comes from stdin, and the parse says so rather than
    /// silently accepting a code that already leaked into `ps` / the history.
    #[test]
    fn unlock_refuses_a_code_in_argv_and_names_stdin() {
        let err = parse_vault_unlock(&s(&["ABCD-EFGH"]), false, || {
            panic!("stdin must not be read when argv already carries a code")
        })
        .unwrap_err();
        assert!(err.contains("takes no arguments"), "{err}");
        assert!(err.contains("shell history"), "names the reason: {err}");
        assert!(err.contains("pipe it in"), "names the remedy: {err}");
    }

    #[test]
    fn unlock_reads_the_code_from_stdin_and_trims_it() {
        let req = parse_vault_unlock(&s(&["--recovery"]), false, || {
            Ok("  3f2a 9c1d \n".to_string())
        })
        .unwrap();
        match req {
            Request::VaultUnlock { recovery_code } => {
                assert_eq!(recovery_code.as_deref(), Some("3f2a 9c1d"))
            }
            other => panic!("expected VaultUnlock, got {other:?}"),
        }
    }

    /// DR-0034 §9 keeps the recovery code off the everyday path, so a bare
    /// `vault unlock` must ask for a passkey — and must not read stdin at all,
    /// since there is no code to read.
    #[test]
    fn unlock_without_the_flag_asks_for_a_passkey_and_never_reads_stdin() {
        let req = parse_vault_unlock(&s(&[]), false, || {
            panic!("stdin must not be read for a passkey unlock")
        })
        .unwrap();
        assert!(matches!(
            req,
            Request::VaultUnlock {
                recovery_code: None
            }
        ));
    }

    #[test]
    fn add_passkey_defaults_its_label_and_keeps_the_bypass_off() {
        let req = parse_vault_add_passkey(&s(&[])).unwrap();
        match req {
            Request::VaultAddPasskey {
                label,
                allow_without_local_approval,
            } => {
                assert_eq!(label, "passkey");
                assert!(
                    !allow_without_local_approval,
                    "the approval gate must be on unless it is explicitly waived"
                );
            }
            other => panic!("expected VaultAddPasskey, got {other:?}"),
        }
    }

    #[test]
    fn add_passkey_carries_a_label_and_an_explicit_bypass() {
        let req =
            parse_vault_add_passkey(&s(&["--label", "laptop", "--allow-without-local-approval"]))
                .unwrap();
        match req {
            Request::VaultAddPasskey {
                label,
                allow_without_local_approval,
            } => {
                assert_eq!(label, "laptop");
                assert!(allow_without_local_approval);
            }
            other => panic!("expected VaultAddPasskey, got {other:?}"),
        }
    }

    #[test]
    fn unlock_with_empty_stdin_is_a_usage_error_not_an_empty_code() {
        let err =
            parse_vault_unlock(&s(&["--recovery"]), false, || Ok("\n".to_string())).unwrap_err();
        assert!(err.contains("no recovery code"), "{err}");
        // It must not have been sent as an empty code.
        assert!(err.contains("vault unlock"), "{err}");
    }

    #[test]
    fn unlock_surfaces_a_stdin_read_failure() {
        let err = parse_vault_unlock(&s(&["--recovery"]), false, || {
            Err(std::io::Error::other("pipe went away"))
        })
        .unwrap_err();
        assert!(err.contains("failed to read the recovery code"), "{err}");
    }

    #[test]
    fn status_render_names_the_state_and_the_next_step() {
        let unlocked = render_vault_status(Some(&status(VaultStateWire::Unlocked)));
        assert!(unlocked.starts_with("vault: unlocked\n"), "{unlocked}");
        assert!(unlocked.contains("id:"), "{unlocked}");
        assert!(
            unlocked.contains("can be opened by: 2 key(s)"),
            "{unlocked}"
        );
        assert!(unlocked.contains("key rotations:"), "{unlocked}");
        assert!(unlocked.contains("vault lock"), "{unlocked}");

        let locked = render_vault_status(Some(&status(VaultStateWire::Locked)));
        assert!(locked.starts_with("vault: locked\n"), "{locked}");
        // Locked says the values survive, and how to get at them.
        assert!(locked.contains("vault unlock"), "{locked}");
        assert!(locked.contains("intact"), "{locked}");

        let fresh = render_vault_status(Some(&VaultStatusWire {
            state: VaultStateWire::NotInitialized,
            vault_id: None,
            slots: None,
            dek_generation: None,
            dev_rp_slot: false,
        }));
        assert!(fresh.contains("not created yet"), "{fresh}");
        assert!(fresh.contains("vault init"), "{fresh}");
        assert!(!fresh.contains("id:"), "nothing to report yet: {fresh}");
    }

    /// No vault field at all: say the daemon has none rather than inventing a
    /// state for it.
    #[test]
    fn status_render_without_a_vault_says_so() {
        let out = render_vault_status(None);
        assert!(out.contains("not configured"), "{out}");
        assert!(out.contains("[vault]"), "points at the config: {out}");
    }

    /// A development key sets the strength of the whole vault, so it is a
    /// warning rather than one more listed fact (DR-0034 §7).
    #[test]
    fn status_render_warns_about_a_development_key() {
        let mut v = status(VaultStateWire::Unlocked);
        v.dev_rp_slot = true;
        let out = render_vault_status(Some(&v));
        assert!(out.contains("warning:"), "{out}");
        assert!(out.contains("development"), "{out}");

        let quiet = render_vault_status(Some(&status(VaultStateWire::Unlocked)));
        assert!(!quiet.contains("warning:"), "no warning otherwise: {quiet}");
    }
}
