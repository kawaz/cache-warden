//! The OTP value-type interpretation layer (DR-0016 §2/§3).
//!
//! This bridges the core's *opaque* [`ValueMeta`] (the core knows nothing about
//! OTP) and the [`crate::totp`] derivation primitives. It is the **only** place
//! that reads `type == "otp"` and the otp parameter strings — the daemon handler
//! calls in here on each `kv.get` of an otp-typed key to turn the stored seed
//! into a short-lived code (the seed itself never leaves the daemon: write-only,
//! DR-0016 §3).
//!
//! # Parameter encoding
//!
//! An otp [`ValueMeta`] carries `type = "otp"` plus opaque string params
//! `digits` / `period` / `algorithm`. They are stored exactly as the CLI sent
//! them (the CLI already layered explicit flags over any otpauth:// URI values,
//! DR-0016 §1), so this layer only has to read them back.

use cache_warden::ValueMeta;

use crate::protocol::wire::ValueMetaWire;
use crate::totp::{self, OtpAlgorithm, OtpOverrides, OtpParams};

/// The reserved type label for the OTP value type.
pub const OTP_TYPE: &str = "otp";

/// Whether a wire metadata block declares the otp type.
pub fn is_otp(meta: &ValueMetaWire) -> bool {
    meta.type_label.as_deref() == Some(OTP_TYPE)
}

/// Whether a core metadata slot declares the otp type.
pub fn meta_is_otp(meta: &ValueMeta) -> bool {
    meta.type_label() == Some(OTP_TYPE)
}

/// Read the otp parameter overrides stored in a core [`ValueMeta`].
///
/// Each of `digits` / `period` / `algorithm` is taken from the params map if
/// present (the CLI has already applied flag-over-URI precedence at set/define
/// time, so we just read the stored values back). An absent param means "use the
/// otpauth URI's value, then the default" — handled by [`totp::resolve_seed`].
fn overrides_from_meta(meta: &ValueMeta) -> Result<OtpOverrides, String> {
    let digits = match meta.param("digits") {
        None => None,
        Some(s) => Some(
            s.parse::<u32>()
                .map_err(|_| "otp digits is not a number".to_string())?,
        ),
    };
    let period = match meta.param("period") {
        None => None,
        Some(s) => Some(
            s.parse::<u64>()
                .map_err(|_| "otp period is not a number".to_string())?,
        ),
    };
    let algorithm = match meta.param("algorithm") {
        None => None,
        Some(s) => Some(OtpAlgorithm::parse(s).map_err(|e| e.to_string())?),
    };
    Ok(OtpOverrides {
        digits,
        period,
        algorithm,
    })
}

/// Validate that `seed` is a usable otp seed under `meta`, without deriving a
/// code (used at `kv set --type otp` time to fail a bad seed early; DR-0016 §5).
///
/// The seed bytes are never echoed into the returned error.
pub fn validate_seed(seed: &[u8], meta: &ValueMetaWire) -> Result<(), String> {
    let core = meta_from_wire_for_validation(meta);
    resolve(seed, &core).map(|_| ())
}

/// Derive the current TOTP code for `seed` under `meta`, as an ASCII digit
/// string (DR-0016 §3). The seed is consumed only here; the caller returns the
/// code, never the seed.
///
/// Uses the real wall-clock time (TOTP is a function of the wall clock, not the
/// TTL monotonic clock). On a bad seed / params, returns a secret-free message.
pub fn derive_code(seed: &[u8], meta: &ValueMeta) -> Result<String, String> {
    let (key, params) = resolve(seed, meta)?;
    let now = unix_now();
    totp::totp(&key, now, &params).map_err(|e| e.to_string())
}

/// Resolve `seed` + `meta` into (key bytes, effective params).
fn resolve(seed: &[u8], meta: &ValueMeta) -> Result<(Vec<u8>, OtpParams), String> {
    // The seed is text (raw base32 or an otpauth:// URI). It is stored as bytes;
    // interpret as UTF-8 (a seed is always ASCII-ish). A non-UTF-8 seed cannot be
    // a valid base32 / URI seed anyway.
    let seed_str = std::str::from_utf8(seed).map_err(|_| {
        "otp seed is not valid text (expected base32 or otpauth:// URI)".to_string()
    })?;
    let overrides = overrides_from_meta(meta)?;
    let resolved = totp::resolve_seed(seed_str, &overrides).map_err(|e| e.to_string())?;
    Ok((resolved.key, resolved.params))
}

/// Build a throwaway core [`ValueMeta`] from a wire block, for seed validation
/// at set time (we only need the params, not to store it).
fn meta_from_wire_for_validation(meta: &ValueMetaWire) -> ValueMeta {
    ValueMeta::with_type(OTP_TYPE, meta.params.clone())
}

/// The current Unix time in seconds (wall clock).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        // Before 1970 is impossible on any sane host; clamp to 0 defensively.
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn wire_otp(params: &[(&str, &str)]) -> ValueMetaWire {
        ValueMetaWire {
            type_label: Some(OTP_TYPE.to_string()),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn core_otp(params: &[(&str, &str)]) -> ValueMeta {
        ValueMeta::with_type(
            OTP_TYPE,
            params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn is_otp_detects_the_type_label() {
        assert!(is_otp(&wire_otp(&[])));
        assert!(meta_is_otp(&core_otp(&[])));
        assert!(!is_otp(&ValueMetaWire::default()));
        assert!(!meta_is_otp(&ValueMeta::new()));
    }

    #[test]
    fn derive_code_from_raw_base32_seed() {
        // RFC 6238 SHA1 seed; at a fixed time we get a deterministic 6-digit code.
        let seed = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = derive_code(seed, &core_otp(&[])).unwrap();
        assert_eq!(code.len(), 6, "default digits");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn derive_code_honors_digit_param() {
        let seed = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = derive_code(seed, &core_otp(&[("digits", "8")])).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn derive_code_from_otpauth_uri_seed() {
        let seed = b"otpauth://totp/L?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        let code = derive_code(seed, &core_otp(&[])).unwrap();
        assert_eq!(code.len(), 8, "digits read from the URI");
    }

    #[test]
    fn bad_seed_is_error_without_echo() {
        let seed = b"this is not a base32 seed !!!";
        let err = derive_code(seed, &core_otp(&[])).unwrap_err();
        assert!(
            !err.contains("this is not"),
            "must not echo the seed: {err}"
        );
    }

    #[test]
    fn validate_seed_accepts_good_and_rejects_bad() {
        assert!(validate_seed(b"GEZDGNBVGY3TQOJQ", &wire_otp(&[])).is_ok());
        assert!(validate_seed(b"!!!not base32!!!", &wire_otp(&[])).is_err());
    }

    #[test]
    fn bad_algorithm_param_is_error() {
        let err = derive_code(b"GEZDGNBVGY3TQOJQ", &core_otp(&[("algorithm", "md5")])).unwrap_err();
        assert!(err.to_lowercase().contains("algorithm"), "{err}");
    }
}
