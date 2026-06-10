//! Lightweight human duration parsing for TTL arguments.
//!
//! Parses TTL strings used on the CLI and the control socket wire. To avoid
//! pulling in a dependency for such a small need, the grammar is intentionally
//! tiny: either a bare integer number of seconds (`86400`) or a single
//! magnitude with an `h` / `m` / `s` suffix (`1h`, `30m`, `45s`). Compound
//! forms (`1h30m`) are deliberately not supported.

use std::time::Duration;

/// Error returned when a TTL string cannot be parsed.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseDurationError {
    /// The offending input (no secret material — TTLs are not secret).
    pub input: String,
}

impl std::fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid duration `{}`: expected an integer number of seconds or a value with an h/m/s suffix (e.g. 1h, 30m, 86400)",
            self.input
        )
    }
}

impl std::error::Error for ParseDurationError {}

/// Parse a TTL string into a [`Duration`].
///
/// Accepts a bare integer (seconds) or a single magnitude with an `h`/`m`/`s`
/// suffix. The number must be a non-negative integer; fractional values are
/// rejected.
pub fn parse_duration(input: &str) -> Result<Duration, ParseDurationError> {
    let err = || ParseDurationError {
        input: input.to_string(),
    };
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(err());
    }

    let (digits, multiplier) = match trimmed.as_bytes().last() {
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 3600),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'0'..=b'9') => (trimmed, 1),
        _ => return Err(err()),
    };

    let n: u64 = digits.parse().map_err(|_| err())?;
    let secs = n.checked_mul(multiplier).ok_or_else(err)?;
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_integer_is_seconds() {
        assert_eq!(parse_duration("86400").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("0").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn hours_minutes_seconds_suffixes() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(parse_duration("  1h ").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    #[test]
    fn rejects_unknown_suffix() {
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn rejects_fractional() {
        assert!(parse_duration("1.5h").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn error_message_does_not_leak_anything_unexpected() {
        let e = parse_duration("1d").unwrap_err();
        assert!(e.to_string().contains("1d"));
    }
}
