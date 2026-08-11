//! Internal subcommands: invoked by the daemon itself for subprocess helpers.
//!
//! These are not shown in the top-level help and are not intended for direct
//! user invocation. Their grammar lives in [`crate::cli`] like every other
//! level; only the usage text is local (a one-screen block, not a help page).

use macos_tcc::{AuthState, Permission, check};

/// Usage text for `cache-warden internal fda-check`.
fn usage() -> &'static str {
    "Usage: cache-warden internal fda-check --raw --result-file PATH

Check whether Full Disk Access has been granted.

Flags:
  --raw              Print \"ok\" or \"fail\" to stdout (required).
  --result-file PATH Write \"ok\\n\" or \"fail\\n\" to PATH (required).
  --help             Print this message and exit.
"
}

/// Execute `cache-warden internal fda-check`.
///
/// Writes the result to `--result-file` and prints it to stdout when `--raw`
/// is set. Both flags are required.
pub fn fda_check(args: &[String]) -> Result<(), String> {
    let cmd = crate::cli::internal_fda_check();
    let m = cmd.clone().try_get_matches_from(args).map_err(|e| {
        format!(
            "{}\n{}",
            crate::cli::parse_error(&cmd, "internal fda-check", e),
            usage()
        )
    })?;

    if m.get_count("help") > 0 {
        print!("{}", usage());
        return Ok(());
    }
    if m.get_count("raw") == 0 {
        return Err(format!("--raw is required\n{}", usage()));
    }
    let path = m
        .get_one::<String>("result-file")
        .ok_or_else(|| format!("--result-file is required\n{}", usage()))?;

    let state = check(Permission::FullDiskAccess);
    let result_str = if state == AuthState::Granted {
        "ok\n"
    } else {
        "fail\n"
    };

    std::fs::write(path, result_str).map_err(|e| e.to_string())?;
    println!("{}", result_str.trim());

    Ok(())
}
