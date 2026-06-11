//! RFC 4226 (HOTP) / RFC 6238 (TOTP) one-time-code derivation (DR-0016).
//!
//! This module is the **derivation view** of the OTP value type: given a seed
//! (the long-lived secret cache-warden stores) plus the current time, it
//! produces the short-lived numeric code. It lives in the CLI crate, not the
//! core library, because the core deliberately knows nothing about OTP (DR-0016
//! §2): it stores the seed as opaque bytes + TTL, and the daemon's handler layer
//! calls into here to derive a code on each `kv.get` of an otp-typed key.
//!
//! # What is derived vs. stored
//!
//! - **Stored** (in the core, as a normal cached value): the *seed* — either a
//!   raw base32 secret or an `otpauth://` URI carrying it. Write-only (DR-0016
//!   §3): once cached, the seed never leaves the daemon.
//! - **Derived** (here, on every get): the numeric code, ~30 s lived. The code
//!   is what the client receives.
//!
//! # Algorithm
//!
//! HOTP (RFC 4226): `HMAC-H(K, counter)` → dynamic-truncate to a 31-bit integer
//! → `mod 10^digits`. TOTP (RFC 6238): `counter = floor(unix_time / period)`,
//! then HOTP. `H` is SHA1 (default), SHA256, or SHA512.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// The HMAC hash variant a TOTP seed uses (RFC 6238 `algorithm`).
///
/// Defaults to [`OtpAlgorithm::Sha1`] (the RFC 6238 default and what virtually
/// every authenticator app emits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpAlgorithm {
    /// HMAC-SHA1 (RFC 6238 default).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl OtpAlgorithm {
    /// Parse an algorithm label (case-insensitive: `sha1` / `sha256` / `sha512`).
    pub fn parse(s: &str) -> Result<Self, OtpError> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(OtpAlgorithm::Sha1),
            "sha256" => Ok(OtpAlgorithm::Sha256),
            "sha512" => Ok(OtpAlgorithm::Sha512),
            other => Err(OtpError::BadAlgorithm(other.to_string())),
        }
    }

    /// The canonical lowercase label (`sha1` / `sha256` / `sha512`).
    pub fn label(self) -> &'static str {
        match self {
            OtpAlgorithm::Sha1 => "sha1",
            OtpAlgorithm::Sha256 => "sha256",
            OtpAlgorithm::Sha512 => "sha512",
        }
    }
}

/// The derivation parameters of an OTP seed (RFC 6238): digit count, time step,
/// and hash variant. The seed bytes themselves are passed separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtpParams {
    /// Number of decimal digits in the code (RFC 6238 `digits`, default 6).
    pub digits: u32,
    /// Time step in seconds (RFC 6238 `period`, default 30).
    pub period: u64,
    /// HMAC hash variant (RFC 6238 `algorithm`, default SHA1).
    pub algorithm: OtpAlgorithm,
}

impl Default for OtpParams {
    fn default() -> Self {
        Self {
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha1,
        }
    }
}

/// An error deriving (or describing) a one-time code.
///
/// # Redaction
///
/// None of these variants carry the seed bytes: a malformed seed reports *that*
/// it was unparseable, never its content (DR-0016 §5 — "never leak the value").
#[derive(Debug, PartialEq, Eq)]
pub enum OtpError {
    /// The seed is neither valid base32 nor a parseable `otpauth://` URI.
    UnparseableSeed,
    /// An `otpauth://` URI was structurally invalid (e.g. missing `secret`).
    BadUri(String),
    /// An unknown `algorithm` label.
    BadAlgorithm(String),
    /// `digits` was outside the supported range (1..=9; a 31-bit truncation
    /// cannot represent 10 decimal digits reliably).
    BadDigits(u32),
    /// `period` was zero (would divide by zero computing the counter).
    BadPeriod,
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpError::UnparseableSeed => write!(
                f,
                "otp seed is neither valid base32 nor a parseable otpauth:// URI"
            ),
            OtpError::BadUri(why) => write!(f, "invalid otpauth:// URI: {why}"),
            OtpError::BadAlgorithm(a) => {
                write!(
                    f,
                    "unknown otp algorithm {a:?} (use sha1 / sha256 / sha512)"
                )
            }
            OtpError::BadDigits(d) => {
                write!(f, "unsupported otp digits {d} (must be 1..=9)")
            }
            OtpError::BadPeriod => write!(f, "otp period must be greater than zero"),
        }
    }
}

impl std::error::Error for OtpError {}

/// Compute the HOTP code for `counter` from `key` under `params` (RFC 4226).
///
/// This is the primitive both the RFC 4226 vectors and TOTP build on. Returns
/// the zero-padded decimal string of `digits` length.
pub fn hotp(key: &[u8], counter: u64, params: &OtpParams) -> Result<String, OtpError> {
    if params.digits == 0 || params.digits > 9 {
        return Err(OtpError::BadDigits(params.digits));
    }
    let msg = counter.to_be_bytes();
    let digest = match params.algorithm {
        OtpAlgorithm::Sha1 => hmac_digest::<Hmac<Sha1>>(key, &msg),
        OtpAlgorithm::Sha256 => hmac_digest::<Hmac<Sha256>>(key, &msg),
        OtpAlgorithm::Sha512 => hmac_digest::<Hmac<Sha512>>(key, &msg),
    };
    let code = dynamic_truncate(&digest, params.digits);
    Ok(format!("{code:0width$}", width = params.digits as usize))
}

/// Compute the TOTP code for `unix_time` (seconds) from `key` (RFC 6238).
pub fn totp(key: &[u8], unix_time: u64, params: &OtpParams) -> Result<String, OtpError> {
    if params.period == 0 {
        return Err(OtpError::BadPeriod);
    }
    let counter = unix_time / params.period;
    hotp(key, counter, params)
}

/// HMAC over `msg` with `key`, returned as the raw digest bytes.
///
/// `M` is the concrete `Hmac<ShaN>` MAC for the chosen variant; the bound is on
/// the MAC itself (`Mac` + `KeyInit`) so we avoid wrestling with the hash trait
/// hierarchy.
fn hmac_digest<M>(key: &[u8], msg: &[u8]) -> Vec<u8>
where
    M: Mac + hmac::digest::KeyInit,
{
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 4226 §5.3 dynamic truncation: select a 4-byte window at the offset named
/// by the low nibble of the last digest byte, mask the high bit, then reduce
/// modulo `10^digits`.
fn dynamic_truncate(digest: &[u8], digits: u32) -> u32 {
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    bin % 10u32.pow(digits)
}

// ---- base32 (RFC 4648, no padding required) ----

/// Decode an RFC 4648 base32 string (the otpauth `secret` encoding) to bytes.
///
/// Case-insensitive; surrounding whitespace and `=` padding are tolerated.
/// Returns `None` on any non-alphabet character so the caller can fall back to
/// other seed interpretations.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf = 0u64;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let mut seen = false;
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let up = c.to_ascii_uppercase() as u8;
        let val = ALPHABET.iter().position(|&a| a == up)? as u64;
        seen = true;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if !seen {
        return None;
    }
    Some(out)
}

/// Parameter overrides supplied explicitly on the CLI (`--otp-digits` etc.).
///
/// Each is `Some` only when the user passed the flag. When deriving a code these
/// take precedence over anything read from an `otpauth://` URI, which in turn
/// takes precedence over the built-in defaults (DR-0016 §1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtpOverrides {
    /// Explicit `--otp-digits`, if given.
    pub digits: Option<u32>,
    /// Explicit `--otp-period`, if given.
    pub period: Option<u64>,
    /// Explicit `--otp-algorithm`, if given.
    pub algorithm: Option<OtpAlgorithm>,
}

/// A resolved OTP seed: the raw secret bytes plus the effective parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSeed {
    /// The decoded secret key bytes (never logged).
    pub key: Vec<u8>,
    /// The effective parameters after layering overrides over URI/defaults.
    pub params: OtpParams,
}

/// Resolve a stored seed string into key bytes + effective [`OtpParams`].
///
/// The seed may be either:
///
/// - an **`otpauth://` URI** (`otpauth://totp/Label?secret=BASE32&...`): the
///   `secret` is base32-decoded and `algorithm` / `digits` / `period` are read
///   from the query (missing ones fall back to defaults), or
/// - a **raw base32 secret** (`JBSWY3DP...`): decoded directly, parameters come
///   from `overrides` / defaults only.
///
/// `overrides` always win over values parsed from the URI (DR-0016 §1). A seed
/// that is neither a parseable URI nor valid base32 is [`OtpError::UnparseableSeed`];
/// the seed content is never echoed into the error (DR-0016 §5).
pub fn resolve_seed(seed: &str, overrides: &OtpOverrides) -> Result<ResolvedSeed, OtpError> {
    let trimmed = seed.trim();
    let (key, uri_params) = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        parse_otpauth_uri(trimmed)?
    } else {
        let key = base32_decode(trimmed).ok_or(OtpError::UnparseableSeed)?;
        if key.is_empty() {
            return Err(OtpError::UnparseableSeed);
        }
        (key, UriParams::default())
    };

    // Precedence: explicit override > URI value > built-in default.
    let defaults = OtpParams::default();
    let params = OtpParams {
        digits: overrides
            .digits
            .or(uri_params.digits)
            .unwrap_or(defaults.digits),
        period: overrides
            .period
            .or(uri_params.period)
            .unwrap_or(defaults.period),
        algorithm: overrides
            .algorithm
            .or(uri_params.algorithm)
            .unwrap_or(defaults.algorithm),
    };
    // Validate the resolved params up front so a bad combination fails before
    // the seed is ever used (and the error names the bad field, not the seed).
    if params.digits == 0 || params.digits > 9 {
        return Err(OtpError::BadDigits(params.digits));
    }
    if params.period == 0 {
        return Err(OtpError::BadPeriod);
    }
    Ok(ResolvedSeed { key, params })
}

/// Parameters as (optionally) present in an `otpauth://` URI query.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct UriParams {
    digits: Option<u32>,
    period: Option<u64>,
    algorithm: Option<OtpAlgorithm>,
}

/// Parse an `otpauth://totp/...?secret=...` URI into (key bytes, URI params).
///
/// Only the `secret` parameter is required; `algorithm` / `digits` / `period`
/// are optional. The label path and `issuer` are ignored (they are cosmetic).
/// HOTP URIs (`otpauth://hotp/...`) are rejected — this iteration is TOTP-only
/// (DR-0016 Consequences: HOTP is out of scope).
fn parse_otpauth_uri(uri: &str) -> Result<(Vec<u8>, UriParams), OtpError> {
    // Split scheme://type/label?query — we only need the type and the query.
    let rest = uri
        .get("otpauth://".len()..)
        .ok_or_else(|| OtpError::BadUri("not an otpauth:// URI".into()))?;
    // `rest` = "totp/Label?query" (or "totp/Label" with no query).
    let kind = rest.split(['/', '?']).next().unwrap_or("");
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(OtpError::BadUri(format!(
            "only totp is supported, got {kind:?}"
        )));
    }
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut secret: Option<Vec<u8>> = None;
    let mut params = UriParams::default();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => {
                let bytes = base32_decode(&v)
                    .filter(|b| !b.is_empty())
                    .ok_or_else(|| OtpError::BadUri("secret is not valid base32".into()))?;
                secret = Some(bytes);
            }
            "algorithm" => params.algorithm = Some(OtpAlgorithm::parse(&v)?),
            "digits" => {
                params.digits = Some(
                    v.parse()
                        .map_err(|_| OtpError::BadUri(format!("digits {v:?} is not a number")))?,
                );
            }
            "period" => {
                params.period = Some(
                    v.parse()
                        .map_err(|_| OtpError::BadUri(format!("period {v:?} is not a number")))?,
                );
            }
            // Cosmetic / unknown params (issuer, label noise) are ignored.
            _ => {}
        }
    }

    let key = secret.ok_or_else(|| OtpError::BadUri("missing secret parameter".into()))?;
    Ok((key, params))
}

/// Minimal percent-decoding for URI query values (`%XX` and `+` → space).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(digits: u32, algo: OtpAlgorithm) -> OtpParams {
        OtpParams {
            digits,
            period: 30,
            algorithm: algo,
        }
    }

    // ---- RFC 4226 Appendix D: HOTP vectors (SHA1, secret "12345678901234567890") ----

    #[test]
    fn rfc4226_hotp_vectors() {
        let key = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(key, counter as u64, &p(6, OtpAlgorithm::Sha1)).unwrap();
            assert_eq!(&got, want, "HOTP counter {counter}");
        }
    }

    // ---- RFC 6238 Appendix B: TOTP vectors (8 digits) ----
    //
    // The RFC uses a different ASCII seed per algorithm (the seed is repeated /
    // truncated to the hash block size): 20 bytes for SHA1, 32 for SHA256, 64
    // for SHA512.

    fn seed_sha1() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }
    fn seed_sha256() -> Vec<u8> {
        b"12345678901234567890123456789012".to_vec()
    }
    fn seed_sha512() -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
    }

    #[test]
    fn rfc6238_totp_sha1_vectors() {
        // (unix_time, expected 8-digit code) from RFC 6238 Appendix B.
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, want) in cases {
            let got = totp(&seed_sha1(), t, &p(8, OtpAlgorithm::Sha1)).unwrap();
            assert_eq!(got, want, "SHA1 T={t}");
        }
    }

    #[test]
    fn rfc6238_totp_sha256_vectors() {
        let cases = [
            (59u64, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];
        for (t, want) in cases {
            let got = totp(&seed_sha256(), t, &p(8, OtpAlgorithm::Sha256)).unwrap();
            assert_eq!(got, want, "SHA256 T={t}");
        }
    }

    #[test]
    fn rfc6238_totp_sha512_vectors() {
        let cases = [
            (59u64, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];
        for (t, want) in cases {
            let got = totp(&seed_sha512(), t, &p(8, OtpAlgorithm::Sha512)).unwrap();
            assert_eq!(got, want, "SHA512 T={t}");
        }
    }

    #[test]
    fn totp_uses_period_to_form_counter() {
        // Two times in the same 30s window yield the same code; the next window
        // differs.
        let s = seed_sha1();
        let a = totp(&s, 30, &p(6, OtpAlgorithm::Sha1)).unwrap();
        let b = totp(&s, 59, &p(6, OtpAlgorithm::Sha1)).unwrap();
        let c = totp(&s, 60, &p(6, OtpAlgorithm::Sha1)).unwrap();
        assert_eq!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn default_params_are_6_digits_30s_sha1() {
        let d = OtpParams::default();
        assert_eq!(d.digits, 6);
        assert_eq!(d.period, 30);
        assert_eq!(d.algorithm, OtpAlgorithm::Sha1);
    }

    #[test]
    fn hotp_rejects_bad_digit_counts() {
        let key = b"12345678901234567890";
        assert_eq!(
            hotp(key, 0, &p(0, OtpAlgorithm::Sha1)),
            Err(OtpError::BadDigits(0))
        );
        assert_eq!(
            hotp(key, 0, &p(10, OtpAlgorithm::Sha1)),
            Err(OtpError::BadDigits(10))
        );
    }

    #[test]
    fn totp_rejects_zero_period() {
        let key = b"12345678901234567890";
        let params = OtpParams {
            digits: 6,
            period: 0,
            algorithm: OtpAlgorithm::Sha1,
        };
        assert_eq!(totp(key, 59, &params), Err(OtpError::BadPeriod));
    }

    // ---- algorithm parsing ----

    #[test]
    fn algorithm_parse_is_case_insensitive() {
        assert_eq!(OtpAlgorithm::parse("SHA1").unwrap(), OtpAlgorithm::Sha1);
        assert_eq!(OtpAlgorithm::parse("sha256").unwrap(), OtpAlgorithm::Sha256);
        assert_eq!(OtpAlgorithm::parse("Sha512").unwrap(), OtpAlgorithm::Sha512);
        assert!(OtpAlgorithm::parse("md5").is_err());
    }

    #[test]
    fn algorithm_label_round_trips() {
        for a in [
            OtpAlgorithm::Sha1,
            OtpAlgorithm::Sha256,
            OtpAlgorithm::Sha512,
        ] {
            assert_eq!(OtpAlgorithm::parse(a.label()).unwrap(), a);
        }
    }

    // ---- base32 ----

    #[test]
    fn base32_decodes_known_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        // base32("12345678901234567890") = the RFC 6238 SHA1 seed.
        assert_eq!(
            base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
    }

    #[test]
    fn base32_is_case_insensitive_and_tolerates_padding_and_spaces() {
        let a = base32_decode("JBSWY3DP").unwrap();
        let b = base32_decode("jbswy3dp").unwrap();
        let c = base32_decode("JBSW Y3DP====").unwrap();
        assert_eq!(a, b"Hello");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn base32_rejects_non_alphabet() {
        assert!(base32_decode("0189!@#").is_none());
        assert!(base32_decode("").is_none());
    }

    // ---- seed resolution: raw base32 ----

    fn no_overrides() -> OtpOverrides {
        OtpOverrides::default()
    }

    #[test]
    fn resolve_raw_base32_seed_uses_defaults() {
        let r = resolve_seed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &no_overrides()).unwrap();
        assert_eq!(r.key, b"12345678901234567890");
        assert_eq!(r.params, OtpParams::default());
        // And it derives the RFC 6238 SHA1 6-digit code at T=59.
        let code = totp(&r.key, 59, &OtpParams::default()).unwrap();
        // 8-digit RFC vector at T=59 is 94287082; 6-digit is its last 6.
        assert_eq!(code, "287082");
    }

    #[test]
    fn resolve_raw_base32_applies_overrides() {
        let ov = OtpOverrides {
            digits: Some(8),
            period: Some(60),
            algorithm: Some(OtpAlgorithm::Sha256),
        };
        let r = resolve_seed("GEZDGNBVGY3TQOJQ", &ov).unwrap();
        assert_eq!(r.params.digits, 8);
        assert_eq!(r.params.period, 60);
        assert_eq!(r.params.algorithm, OtpAlgorithm::Sha256);
    }

    #[test]
    fn resolve_unparseable_seed_is_error_without_echo() {
        let err = resolve_seed("not valid base32 !!!", &no_overrides()).unwrap_err();
        assert_eq!(err, OtpError::UnparseableSeed);
        assert!(!err.to_string().contains("not valid base32"));
    }

    // ---- seed resolution: otpauth:// URI ----

    #[test]
    fn resolve_otpauth_uri_reads_params() {
        let uri = "otpauth://totp/ACME:alice@acme.com\
                   ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
                   &issuer=ACME&algorithm=SHA256&digits=8&period=60";
        let r = resolve_seed(uri, &no_overrides()).unwrap();
        assert_eq!(r.key, b"12345678901234567890");
        assert_eq!(r.params.digits, 8);
        assert_eq!(r.params.period, 60);
        assert_eq!(r.params.algorithm, OtpAlgorithm::Sha256);
    }

    #[test]
    fn resolve_otpauth_uri_defaults_when_params_absent() {
        let uri = "otpauth://totp/Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let r = resolve_seed(uri, &no_overrides()).unwrap();
        assert_eq!(r.params, OtpParams::default());
    }

    #[test]
    fn explicit_overrides_win_over_uri_params() {
        // URI says digits=8, but the explicit --otp-digits 6 wins (DR-0016 §1).
        let uri = "otpauth://totp/Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&algorithm=SHA512";
        let ov = OtpOverrides {
            digits: Some(6),
            period: None,
            algorithm: Some(OtpAlgorithm::Sha1),
        };
        let r = resolve_seed(uri, &ov).unwrap();
        assert_eq!(r.params.digits, 6, "override beats URI digits");
        assert_eq!(
            r.params.algorithm,
            OtpAlgorithm::Sha1,
            "override beats URI algo"
        );
        // period not overridden, not in URI -> default.
        assert_eq!(r.params.period, 30);
    }

    #[test]
    fn otpauth_uri_missing_secret_is_bad_uri() {
        let err = resolve_seed("otpauth://totp/Label?digits=6", &no_overrides()).unwrap_err();
        assert!(matches!(err, OtpError::BadUri(_)));
    }

    #[test]
    fn otpauth_hotp_is_rejected() {
        // HOTP (counter-based) is out of scope this iteration (DR-0016).
        let err = resolve_seed(
            "otpauth://hotp/Label?secret=GEZDGNBVGY3TQOJQ&counter=0",
            &no_overrides(),
        )
        .unwrap_err();
        assert!(matches!(err, OtpError::BadUri(_)));
    }

    #[test]
    fn otpauth_uri_bad_secret_base32_is_bad_uri() {
        let err = resolve_seed("otpauth://totp/L?secret=0!8", &no_overrides()).unwrap_err();
        assert!(matches!(err, OtpError::BadUri(_)));
    }

    #[test]
    fn resolve_then_totp_end_to_end() {
        // A full chain: a real-ish otpauth URI -> derive a code at a fixed time.
        let uri = "otpauth://totp/Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        let r = resolve_seed(uri, &no_overrides()).unwrap();
        let code = totp(&r.key, 59, &r.params).unwrap();
        assert_eq!(code, "94287082");
    }
}
