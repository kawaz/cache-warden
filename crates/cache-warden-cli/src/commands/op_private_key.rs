//! The hidden `__authsock-op-private-key` internal subcommand.
//!
//! The authsock daemon registers each op-sourced key as a core command source
//! whose argv re-executes cache-warden's own binary with this subcommand (see
//! [`cache_warden_authsock::private_key_argv`]). At sign time the core runs that
//! argv and captures stdout as the private-key PEM.
//!
//! # Why this exists (not `op item get` directly)
//!
//! The core captures stdout verbatim. Real op (2.34.0) quotes a multi-line field
//! in plain output, so calling op directly would feed a quoted, non-PEM string to
//! the signer (SSH_AGENT_FAILURE). This subcommand calls op with `--format json`
//! and extracts `.value`, emitting the plain PEM — the JSON extraction the warden
//! did, relocated to a child process so the core's command-source model is
//! untouched.
//!
//! # Secret hygiene
//!
//! The PEM never leaves [`cache_warden_authsock::fetch_op_private_key`]'s
//! zeroizing buffers except as the bytes written to stdout; no diagnostic ever
//! includes the PEM or any field value (only the item id and an error category).

use std::io::Write as _;

use cache_warden_authsock::{RealOpClient, fetch_op_private_key, validate_item_id};

const NAME: &str = "cache-warden";

/// Run `__authsock-op-private-key <ITEM_ID> [--account ACCOUNT]`.
///
/// Writes the PEM to stdout on success. On any failure, prints a single
/// secret-free diagnostic line to stderr (item id + error category) and returns
/// an `Err` so the process exits non-zero — which the daemon's command runner
/// maps to SSH_AGENT_FAILURE, unchanged. The stderr line is what closes the
/// "agent refused with nothing in the log" diagnostic gap.
pub fn run(args: &[String]) -> Result<(), String> {
    let (item_id, account) = parse_args(args)?;

    // Re-validate at this trust boundary (the discovery layer already validated,
    // but a cached / replayed id should never reach op unchecked).
    if let Err(e) = validate_item_id(&item_id) {
        eprintln!("{NAME}: op private key: invalid item id `{item_id}` ({e})");
        return Err(format!("invalid item id: {item_id}"));
    }

    let client = match &account {
        Some(a) => RealOpClient::with_account(a.clone()),
        None => RealOpClient::new(),
    };

    let pem = match fetch_op_private_key(&client, &item_id) {
        Ok(pem) => pem,
        Err(e) => {
            // `e` (Error::KeyStore) is secret-free: it carries op's stderr
            // (which op does not write secrets to) or a JSON-parse category,
            // never the PEM value. Emit one diagnostic line for the daemon log.
            eprintln!("{NAME}: op private key fetch failed for item `{item_id}`: {e}");
            return Err(format!("op private key fetch failed for item {item_id}"));
        }
    };

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&pem)
        .and_then(|()| stdout.flush())
        .map_err(|e| {
            eprintln!("{NAME}: op private key: failed to write PEM for item `{item_id}`");
            format!("failed to write PEM: {e}")
        })
}

/// Parse `<ITEM_ID> [--account ACCOUNT]` (hand-rolled, DR-0002: no clap).
///
/// The item id is the sole positional; `--account` takes the next token. Unknown
/// flags or a missing item id / account value are errors.
fn parse_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut item_id: Option<String> = None;
    let mut account: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--account" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| "--account requires a value".to_string())?;
                account = Some(v.clone());
                i += 2;
            }
            flag if flag.starts_with("--") => {
                return Err(format!("unknown flag for op private key fetch: {flag}"));
            }
            positional => {
                if item_id.is_some() {
                    return Err(format!("unexpected extra argument: {positional}"));
                }
                item_id = Some(positional.to_string());
                i += 1;
            }
        }
    }
    let item_id = item_id.ok_or_else(|| "missing item id".to_string())?;
    Ok((item_id, account))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_item_id_only() {
        let (id, acc) = parse_args(&["itemABC".to_string()]).unwrap();
        assert_eq!(id, "itemABC");
        assert_eq!(acc, None);
    }

    #[test]
    fn parse_item_id_with_account() {
        let (id, acc) = parse_args(&[
            "itemABC".to_string(),
            "--account".to_string(),
            "kawaz.1password.com".to_string(),
        ])
        .unwrap();
        assert_eq!(id, "itemABC");
        assert_eq!(acc.as_deref(), Some("kawaz.1password.com"));
    }

    #[test]
    fn parse_account_before_item_id() {
        // Order independence: --account may precede the positional.
        let (id, acc) = parse_args(&[
            "--account".to_string(),
            "acc".to_string(),
            "itemABC".to_string(),
        ])
        .unwrap();
        assert_eq!(id, "itemABC");
        assert_eq!(acc.as_deref(), Some("acc"));
    }

    #[test]
    fn parse_missing_item_id_is_error() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["--account".to_string(), "acc".to_string()]).is_err());
    }

    #[test]
    fn parse_account_without_value_is_error() {
        assert!(parse_args(&["itemABC".to_string(), "--account".to_string()]).is_err());
    }

    #[test]
    fn parse_unknown_flag_is_error() {
        assert!(parse_args(&["itemABC".to_string(), "--reveal".to_string()]).is_err());
    }

    #[test]
    fn parse_extra_positional_is_error() {
        assert!(parse_args(&["a".to_string(), "b".to_string()]).is_err());
    }
}
