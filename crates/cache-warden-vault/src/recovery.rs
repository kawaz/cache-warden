//! The recovery code: the vault's mandatory last-resort credential
//! (DR-0034 §9).
//!
//! A recovery code is 256 bits drawn from the OS CSPRNG, rendered for humans
//! in Crockford Base32. It is generated, never chosen — a user-picked
//! passphrase would turn the slot KEK derivation into a password-hashing
//! problem (memory-hard KDF, parameter tuning, upgrade path) that HKDF is not
//! built for, and would make the vault's weakest slot as weak as the phrase.
//!
//! # Why Crockford Base32
//!
//! This string gets written on paper and typed back in months later, possibly
//! from a photograph, possibly by someone reading it aloud. Crockford Base32
//! is built for exactly that: its alphabet omits `I`, `L`, `O` and `U`, so the
//! `1`/`I`/`l` and `0`/`O` confusions that dominate hand-transcription cannot
//! occur, and it defines *decoding* aliases so a code typed with `I` for `1`
//! or `O` for `0` still decodes rather than being rejected. Case is ignored
//! and separators are ignored, so line breaks and hyphens added by whoever
//! copied it down are harmless.
//!
//! Bech32 was the alternative. It carries a BCH checksum that can point at the
//! position of a typo, which is genuinely better error reporting — but it is
//! designed around an address format (human-readable prefix, separator,
//! 6-character checksum) whose ergonomics are tuned for a different problem,
//! and adopting it here means importing that structure for the checksum alone.
//! Plain base64 and hex were not considered seriously: base64 is
//! case-sensitive with three ambiguous character pairs, and hex costs 64
//! characters to carry 52 characters' worth of information.
//!
//! There is deliberately **no checksum**. A well-formed code that opens no
//! slot — whether it was mistyped or simply belongs to a different vault —
//! surfaces as [`crate::VaultError::NoMatchingSlot`], with nothing to tell the
//! two apart. Only malformed input (wrong length, character outside the
//! alphabet, non-zero padding) is caught here as
//! [`crate::VaultError::MalformedRecoveryCode`]. A checksum would separate
//! "you typed it wrong" from "wrong vault", but only by defining a bespoke
//! framing on top of the encoding, and DR-0034 does not specify one. Adding it
//! is a candidate follow-up, not something to invent here.

use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, random_key};
use crate::error::VaultError;

/// Crockford Base32 digits, in value order.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters per encoded code: 256 bits at 5 bits per character, rounded up.
const CODE_CHARS: usize = 52;

/// Characters per display group. Short groups are easier to check off against
/// a written copy than one 52-character run.
const GROUP_LEN: usize = 4;

/// Guidance shown to the user when a vault is initialized (DR-0034 §9).
///
/// The DR is explicit that independent storage cannot be enforced, only
/// advised — so this is the advice, kept in one place rather than retyped by
/// each front end.
pub const RECOVERY_STORAGE_GUIDANCE: &str = "\
Write this recovery code down and store it somewhere other than your passkeys.
It is the only way back into this vault if every passkey is lost, and it is
shown once. Keeping it in the same password manager as your passkeys means a
single compromised or lost account takes both — store it on paper, or in a
separate offline location.";

/// The 256-bit secret behind a recovery code.
///
/// Holds the raw secret and renders it on demand. `Debug` redacts, and there
/// is no `Display`: the encoded form leaves this type only through
/// [`RecoveryCode::render`], whose return value is itself zeroized on drop, so
/// a recovery code cannot end up in a log line by accident.
pub struct RecoveryCode {
    secret: Zeroizing<[u8; KEY_LEN]>,
}

impl RecoveryCode {
    /// Generate a fresh code.
    pub(crate) fn generate() -> Self {
        Self {
            secret: random_key(),
        }
    }

    /// Parse a code as typed by a user.
    ///
    /// Case, spaces, hyphens and newlines are ignored, and the Crockford
    /// decoding aliases (`I`/`i`/`L`/`l` → `1`, `O`/`o` → `0`) are applied, so
    /// a code transcribed by hand normally parses on the first try.
    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let mut digits = Vec::with_capacity(CODE_CHARS);
        for ch in input.chars() {
            match ch {
                '-' | ' ' | '\t' | '\n' | '\r' => continue,
                _ => digits.push(digit_value(ch).ok_or(VaultError::MalformedRecoveryCode)?),
            }
        }
        if digits.len() != CODE_CHARS {
            return Err(VaultError::MalformedRecoveryCode);
        }

        // 52 digits carry 260 bits; the 256-bit secret occupies the leading
        // bits and the trailing 4 must be zero. Rejecting a non-zero tail
        // keeps the encoding injective — otherwise many distinct strings would
        // decode to the same secret.
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        let mut acc: u16 = 0;
        let mut bits = 0u32;
        let mut out = 0usize;
        for d in digits {
            acc = (acc << 5) | u16::from(d);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                if out < KEY_LEN {
                    secret[out] = (acc >> bits) as u8;
                    out += 1;
                }
            }
        }
        let tail_mask = (1u16 << bits) - 1;
        if acc & tail_mask != 0 {
            return Err(VaultError::MalformedRecoveryCode);
        }
        Ok(Self { secret })
    }

    /// Render the code for display, grouped for transcription.
    ///
    /// The returned `String` is zeroized when dropped. Show it once, then let
    /// it go — this crate keeps no copy beyond the [`RecoveryCode`] itself.
    pub fn render(&self) -> Zeroizing<String> {
        let mut out = String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP_LEN);
        let mut acc: u16 = 0;
        let mut bits = 0u32;
        let mut written = 0usize;
        let mut emit = |out: &mut String, value: u8| {
            if written > 0 && written.is_multiple_of(GROUP_LEN) {
                out.push('-');
            }
            out.push(ALPHABET[value as usize] as char);
            written += 1;
        };
        for &byte in self.secret.iter() {
            acc = (acc << 8) | u16::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                emit(&mut out, ((acc >> bits) & 0x1f) as u8);
            }
        }
        if bits > 0 {
            // Pad the final partial group with zero bits, matching what
            // `parse` requires of the tail.
            emit(&mut out, ((acc << (5 - bits)) & 0x1f) as u8);
        }
        Zeroizing::new(out)
    }

    /// The raw secret, as the input keying material for a slot's KEK.
    pub(crate) fn secret(&self) -> &[u8] {
        self.secret.as_ref()
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}

/// The value of one Crockford Base32 character, applying the decoding aliases
/// (`I`/`L` → `1`, `O` → `0`). `U` is not in the alphabet and has no alias.
fn digit_value(ch: char) -> Option<u8> {
    let up = ch.to_ascii_uppercase();
    match up {
        'I' | 'L' => Some(1),
        'O' => Some(0),
        _ => ALPHABET
            .iter()
            .position(|&a| a == up as u8)
            .map(|p| p as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_code_round_trips_through_its_rendered_form() {
        let code = RecoveryCode::generate();
        let rendered = code.render();
        let back = RecoveryCode::parse(&rendered).expect("its own output parses");
        assert_eq!(back.secret(), code.secret());
    }

    #[test]
    fn rendered_codes_are_52_digits_in_groups_of_four() {
        let rendered = RecoveryCode::generate().render();
        let digits: String = rendered.chars().filter(|c| *c != '-').collect();
        assert_eq!(digits.len(), CODE_CHARS);
        assert_eq!(rendered.matches('-').count(), CODE_CHARS / GROUP_LEN - 1);
        assert!(digits.chars().all(|c| ALPHABET.contains(&(c as u8))));
    }

    /// The transcription case the alphabet exists for: someone reads the code
    /// off paper in lowercase, types `O` where a `0` was printed and `l` where
    /// a `1` was, and drops the hyphens. It must still decode to the same
    /// secret.
    #[test]
    fn parse_accepts_hand_transcription_variations() {
        let code = RecoveryCode::generate();
        let canonical = code.render();
        let mangled: String = canonical
            .chars()
            .filter(|c| *c != '-')
            .map(|c| match c {
                '0' => 'o',
                '1' => 'l',
                other => other.to_ascii_lowercase(),
            })
            .collect();
        let back = RecoveryCode::parse(&mangled).expect("aliased, lowercased input parses");
        assert_eq!(back.secret(), code.secret());
    }

    #[test]
    fn parse_ignores_whitespace_and_line_breaks() {
        let code = RecoveryCode::generate();
        let spaced = code.render().replace('-', " \n ");
        assert_eq!(
            RecoveryCode::parse(&spaced).expect("parses").secret(),
            code.secret()
        );
    }

    #[test]
    fn parse_rejects_a_code_of_the_wrong_length() {
        let short = "0".repeat(CODE_CHARS - 1);
        assert!(matches!(
            RecoveryCode::parse(&short),
            Err(VaultError::MalformedRecoveryCode)
        ));
        let long = "0".repeat(CODE_CHARS + 1);
        assert!(matches!(
            RecoveryCode::parse(&long),
            Err(VaultError::MalformedRecoveryCode)
        ));
    }

    /// `U` is excluded from Crockford's alphabet and has no decoding alias, so
    /// it is a genuine error rather than something to silently map.
    #[test]
    fn parse_rejects_characters_outside_the_alphabet() {
        let mut s = "0".repeat(CODE_CHARS);
        s.replace_range(0..1, "U");
        assert!(matches!(
            RecoveryCode::parse(&s),
            Err(VaultError::MalformedRecoveryCode)
        ));
        s.replace_range(0..1, "$");
        assert!(matches!(
            RecoveryCode::parse(&s),
            Err(VaultError::MalformedRecoveryCode)
        ));
    }

    /// 52 digits carry 4 bits more than the secret needs. Accepting a non-zero
    /// tail would make many strings decode to one secret; the encoding stays
    /// one-to-one instead.
    #[test]
    fn parse_rejects_a_non_zero_padding_tail() {
        let code = RecoveryCode::generate();
        let digits: Vec<char> = code.render().chars().filter(|c| *c != '-').collect();
        let last = digits[CODE_CHARS - 1];
        let value = digit_value(last).unwrap();
        // Flip the lowest padding bit; the leading 4 bits of the digit (which
        // carry real key material) are untouched.
        let flipped = ALPHABET[(value ^ 1) as usize] as char;
        let mut tampered: String = digits.into_iter().collect();
        tampered.replace_range(CODE_CHARS - 1..CODE_CHARS, &flipped.to_string());
        assert!(matches!(
            RecoveryCode::parse(&tampered),
            Err(VaultError::MalformedRecoveryCode)
        ));
    }

    #[test]
    fn two_generated_codes_differ() {
        assert_ne!(
            *RecoveryCode::generate().render(),
            *RecoveryCode::generate().render()
        );
    }

    /// The whole point of having no `Display`: a recovery code must not be
    /// printable by accident.
    #[test]
    fn debug_redacts_the_secret() {
        let code = RecoveryCode::generate();
        let rendered = code.render();
        let debug = format!("{code:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(rendered.as_str()));
    }

    #[test]
    fn guidance_names_the_separate_storage_requirement() {
        assert!(RECOVERY_STORAGE_GUIDANCE.contains("passkeys"));
        assert!(RECOVERY_STORAGE_GUIDANCE.contains("once"));
    }
}
