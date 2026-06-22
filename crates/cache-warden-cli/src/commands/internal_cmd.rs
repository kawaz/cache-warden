//! Internal subcommands: invoked by the daemon itself for subprocess helpers.
//!
//! These are not shown in the top-level help and are not intended for direct
//! user invocation. The arg parser is hand-rolled (DR-0002).

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
    let mut raw = false;
    let mut result_file: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        let a = &args[i];
        if a == "--help" {
            print!("{}", usage());
            return Ok(());
        } else if a == "--raw" {
            raw = true;
            i += 1;
        } else if a == "--result-file" {
            let v = args
                .get(i + 1)
                .ok_or("--result-file requires a PATH argument")?;
            result_file = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--result-file=") {
            result_file = Some(v.to_string());
            i += 1;
        } else {
            return Err(format!(
                "unknown option for `internal fda-check`: {a}\n{}",
                usage()
            ));
        }
    }

    if !raw {
        return Err(format!("--raw is required\n{}", usage()));
    }
    let path = result_file.ok_or_else(|| format!("--result-file is required\n{}", usage()))?;

    let state = check(Permission::FullDiskAccess);
    let result_str = if state == AuthState::Granted {
        "ok\n"
    } else {
        "fail\n"
    };

    std::fs::write(&path, result_str).map_err(|e| e.to_string())?;
    println!("{}", result_str.trim());

    Ok(())
}
