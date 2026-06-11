//! Reveal vs. dry-run mode resolution (DR-0015 §4).
//!
//! Three verbs (`kv get` / `run` / `inject`) share one polarity: by default they
//! **reveal** real values, but a context can flip the default to **dry-run**
//! (mask values, run the full chain, never emit a secret). The polarity is
//! resolved once from a fixed precedence:
//!
//! 1. an explicit `--reveal` / `--dry-run` flag (highest),
//! 2. the `CACHE_WARDEN_DRY_RUN` environment variable,
//! 3. the config `[cli].default-mode`,
//! 4. the built-in default (reveal).
//!
//! `--reveal` and `--dry-run` together is a usage error. The flag parsing lives
//! in [`take_mode_flag`] (pure, testable); [`resolve_mode`] applies the rest of
//! the chain.

/// The resolved output polarity for a value-emitting verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Emit real values (the default).
    Reveal,
    /// Run the full chain but emit only masked values (no secret reaches the
    /// client process). Verifies the wiring without exposing the value.
    DryRun,
}

impl Mode {
    /// `true` when this mode is [`Mode::DryRun`].
    pub fn is_dry_run(self) -> bool {
        matches!(self, Mode::DryRun)
    }
}

/// An explicit mode flag taken from the CLI, before precedence is applied.
///
/// `None` means neither flag was given (defer to env / config / default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeFlag {
    /// `--reveal` was given.
    Reveal,
    /// `--dry-run` was given.
    DryRun,
}

/// Extract a single `--reveal` / `--dry-run` flag from `args`, returning the
/// chosen flag (if any) and the remaining args with it removed.
///
/// Giving both flags (in any order, even repeated) is a usage error: the two
/// express opposite intents and silently picking one would hide a mistake.
pub fn take_mode_flag(args: &[String]) -> Result<(Option<ModeFlag>, Vec<String>), String> {
    let mut flag: Option<ModeFlag> = None;
    let mut rest = Vec::new();
    for a in args {
        let next = match a.as_str() {
            "--reveal" => Some(ModeFlag::Reveal),
            "--dry-run" => Some(ModeFlag::DryRun),
            _ => {
                rest.push(a.clone());
                continue;
            }
        };
        match (flag, next) {
            (None, n) => flag = n,
            (Some(prev), Some(cur)) if prev == cur => {} // same flag twice: harmless
            (Some(_), _) => {
                return Err(
                    "--reveal and --dry-run cannot be combined (they request opposite modes)"
                        .to_string(),
                );
            }
        }
    }
    Ok((flag, rest))
}

/// Resolve the effective [`Mode`] from the precedence chain (DR-0015 §4):
/// flag > `CACHE_WARDEN_DRY_RUN` env > config `[cli].default-mode` > reveal.
///
/// `env_dry_run` is the truthiness of `CACHE_WARDEN_DRY_RUN` (see
/// [`env_dry_run_is_set`]); `config_default` is the parsed `[cli].default-mode`
/// (`None` when the config did not set it).
pub fn resolve_mode(
    flag: Option<ModeFlag>,
    env_dry_run: Option<bool>,
    config_default: Option<Mode>,
) -> Mode {
    if let Some(f) = flag {
        return match f {
            ModeFlag::Reveal => Mode::Reveal,
            ModeFlag::DryRun => Mode::DryRun,
        };
    }
    if let Some(env) = env_dry_run {
        return if env { Mode::DryRun } else { Mode::Reveal };
    }
    config_default.unwrap_or(Mode::Reveal)
}

/// Interpret the `CACHE_WARDEN_DRY_RUN` environment variable.
///
/// Returns `None` when the variable is unset or empty (defer to the next tier),
/// `Some(true)` for a truthy value (`1` / `true` / `yes` / `on`,
/// case-insensitive), and `Some(false)` for an explicit falsey value
/// (`0` / `false` / `no` / `off`). Any other non-empty value is an error so a
/// typo (`CACHE_WARDEN_DRY_RUN=ture`) is surfaced, not silently treated as off.
pub fn env_dry_run_is_set() -> Result<Option<bool>, String> {
    match std::env::var_os("CACHE_WARDEN_DRY_RUN") {
        None => Ok(None),
        Some(v) => {
            let s = v.to_string_lossy();
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            match t.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Ok(Some(true)),
                "0" | "false" | "no" | "off" => Ok(Some(false)),
                other => Err(format!(
                    "CACHE_WARDEN_DRY_RUN must be a boolean (1/0/true/false/yes/no/on/off), got {other:?}"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn take_mode_flag_picks_reveal_and_dry_run() {
        let (f, rest) = take_mode_flag(&args(&["--reveal", "X"])).unwrap();
        assert_eq!(f, Some(ModeFlag::Reveal));
        assert_eq!(rest, vec!["X".to_string()]);

        let (f, rest) = take_mode_flag(&args(&["A", "--dry-run", "B"])).unwrap();
        assert_eq!(f, Some(ModeFlag::DryRun));
        assert_eq!(rest, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn take_mode_flag_absent_is_none() {
        let (f, rest) = take_mode_flag(&args(&["A", "B"])).unwrap();
        assert_eq!(f, None);
        assert_eq!(rest, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn take_mode_flag_same_flag_twice_is_ok() {
        let (f, _) = take_mode_flag(&args(&["--dry-run", "--dry-run"])).unwrap();
        assert_eq!(f, Some(ModeFlag::DryRun));
    }

    #[test]
    fn take_mode_flag_both_flags_is_error() {
        assert!(take_mode_flag(&args(&["--reveal", "--dry-run"])).is_err());
        assert!(take_mode_flag(&args(&["--dry-run", "--reveal"])).is_err());
    }

    #[test]
    fn resolve_mode_flag_wins_over_env_and_config() {
        assert_eq!(
            resolve_mode(Some(ModeFlag::Reveal), Some(true), Some(Mode::DryRun)),
            Mode::Reveal
        );
        assert_eq!(
            resolve_mode(Some(ModeFlag::DryRun), Some(false), Some(Mode::Reveal)),
            Mode::DryRun
        );
    }

    #[test]
    fn resolve_mode_env_wins_over_config() {
        assert_eq!(
            resolve_mode(None, Some(true), Some(Mode::Reveal)),
            Mode::DryRun
        );
        assert_eq!(
            resolve_mode(None, Some(false), Some(Mode::DryRun)),
            Mode::Reveal
        );
    }

    #[test]
    fn resolve_mode_config_when_no_flag_or_env() {
        assert_eq!(resolve_mode(None, None, Some(Mode::DryRun)), Mode::DryRun);
        assert_eq!(resolve_mode(None, None, Some(Mode::Reveal)), Mode::Reveal);
    }

    #[test]
    fn resolve_mode_builtin_default_is_reveal() {
        assert_eq!(resolve_mode(None, None, None), Mode::Reveal);
    }
}
