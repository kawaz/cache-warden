//! The three cryptographic operations the vault is built from (DR-0034 §2):
//! slot KEK derivation, ECIES key wrapping to a slot's public key, and AEAD
//! seal/open.
//!
//! Nothing here invents a construction. Every step is HKDF-SHA256 for key
//! derivation and XChaCha20-Poly1305 for encryption, both from RustCrypto,
//! composed in the standard way. Nonces come from the OS CSPRNG on every call
//! — there is no counter to get wrong, which is why XChaCha's 192-bit nonce
//! was chosen over ChaCha20-Poly1305's 96-bit one (a 192-bit random nonce has
//! negligible collision probability across any number of rewrites this format
//! will ever see).
//!
//! # Domain separation
//!
//! Every derived key binds the context it is used in into the HKDF `info`
//! string, so key material from one slot, one vault, or one purpose can never
//! be replayed as another (the rule DR-0034 §2 takes from the passkey-PRF
//! findings). The two purpose labels are [`KEK_INFO_LABEL`] and
//! [`DEK_WRAP_INFO_LABEL`]; they are byte-pinned by the format tests.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::format::{SlotId, VaultId};

/// Length of every symmetric key in this format (XChaCha20-Poly1305 key size
/// and HKDF-SHA256 output length).
pub(crate) const KEY_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 nonce.
pub(crate) const NONCE_LEN: usize = 24;

/// Length of the AEAD authentication tag; ciphertext is always plaintext plus
/// this much.
pub(crate) const TAG_LEN: usize = 16;

/// Length of an X25519 public key / of the ephemeral key in a wrapped DEK.
pub(crate) const PUBKEY_LEN: usize = 32;

/// HKDF `info` purpose label for a slot's key-encryption key (DR-0034 §2).
pub(crate) const KEK_INFO_LABEL: &[u8] = b"cw-vault-slot-kek";

/// HKDF `info` purpose label for the ECIES key that wraps the DEK to a slot's
/// public key. A separate label from [`KEK_INFO_LABEL`] so the two keys are
/// independent even when they cover the same slot.
pub(crate) const DEK_WRAP_INFO_LABEL: &[u8] = b"cw-vault-dek-wrap";

/// A 32-byte symmetric key that wipes itself on drop.
///
/// The unlocked DEK is additionally held in the core's mlock-pinned
/// [`cache_warden::SecretBytes`] (DR-0007) once it reaches
/// [`crate::UnlockedVault`]; this type covers the short-lived derived keys
/// (KEKs, ECIES wrap keys) that exist only for the duration of one operation.
pub(crate) type SymKey = Zeroizing<[u8; KEY_LEN]>;

/// Fill `buf` from the OS CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// A fresh random 32-byte key (DEK, or the input secret behind a recovery
/// code).
pub(crate) fn random_key() -> SymKey {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(k.as_mut());
    k
}

/// A fresh random XChaCha20-Poly1305 nonce.
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    fill_random(&mut n);
    n
}

/// Derive a slot's key-encryption key (DR-0034 §2).
///
/// ```text
/// KEK = HKDF-SHA256(ikm  = input secret (PRF output / recovery secret),
///                   salt = slot.salt,
///                   info = vault_id ‖ format_version ‖ slot_id ‖ "cw-vault-slot-kek")
/// ```
///
/// The input secret is never used as an AEAD key directly. Passing it through
/// HKDF with the vault id, format version and slot id in `info` means the same
/// passkey PRF output produces unrelated keys for different vaults, different
/// slots, and different format generations.
pub(crate) fn derive_kek(
    input_secret: &[u8],
    salt: &[u8],
    vault_id: VaultId,
    format_version: u32,
    slot_id: SlotId,
) -> SymKey {
    let mut info = Vec::with_capacity(16 + 4 + 16 + KEK_INFO_LABEL.len());
    info.extend_from_slice(vault_id.as_bytes());
    info.extend_from_slice(&format_version.to_be_bytes());
    info.extend_from_slice(slot_id.as_bytes());
    info.extend_from_slice(KEK_INFO_LABEL);

    let hk = Hkdf::<Sha256>::new(Some(salt), input_secret);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Encrypt `plaintext` under `key` with `aad` authenticated but not encrypted.
///
/// Returns `nonce ‖ ciphertext‖tag`. The nonce travels with the ciphertext
/// because every call generates a fresh one.
pub(crate) fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // XChaCha20-Poly1305 encryption is infallible for any plaintext that
        // fits in memory; the Result exists for the trait, not for a reachable
        // failure mode.
        .expect("XChaCha20-Poly1305 encryption cannot fail for an in-memory plaintext");

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Reverse of [`seal`]. `sealed` is `nonce ‖ ciphertext‖tag`.
///
/// `stage` names the decryption step for [`VaultError::DecryptFailed`]; it is
/// diagnostic only (see that variant's note on why every step shares one
/// error).
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    sealed: &[u8],
    stage: &'static str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::DecryptFailed { stage });
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::DecryptFailed { stage })
}

/// A DEK wrapped to one slot's X25519 public key (DR-0034 §1b `wrapped_dek`).
///
/// Standard ECIES: a fresh ephemeral X25519 key pair per wrap, HKDF-SHA256
/// over the shared secret to get the wrapping key, then AEAD. The ephemeral
/// public key travels with the ciphertext so the recipient can redo the
/// exchange with its private key.
///
/// This is the structure that makes DR-0034 §1c work: producing one of these
/// needs the recipient's **public** key only, so DEK rotation and slot
/// addition re-wrap for every remaining slot without any other slot's
/// credential — no second passkey ceremony, no other device present.
#[derive(Clone)]
pub(crate) struct WrappedDek {
    /// The wrap's ephemeral X25519 public key.
    pub(crate) ephemeral_pub: [u8; PUBKEY_LEN],
    /// `nonce ‖ ciphertext‖tag` over the DEK.
    pub(crate) sealed: Vec<u8>,
}

/// Derive the ECIES wrapping key for one (ephemeral, recipient) pair.
///
/// Both public keys go into the HKDF `info` alongside the vault and slot ids:
/// binding the transcript means a wrap made for one slot cannot be relabelled
/// as another slot's wrap and still decrypt.
fn derive_wrap_key(
    shared: &[u8; 32],
    vault_id: VaultId,
    slot_id: SlotId,
    ephemeral_pub: &[u8; PUBKEY_LEN],
    recipient_pub: &[u8; PUBKEY_LEN],
) -> SymKey {
    let mut info = Vec::with_capacity(DEK_WRAP_INFO_LABEL.len() + 16 + 16 + 32 + 32);
    info.extend_from_slice(DEK_WRAP_INFO_LABEL);
    info.extend_from_slice(vault_id.as_bytes());
    info.extend_from_slice(slot_id.as_bytes());
    info.extend_from_slice(ephemeral_pub);
    info.extend_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Wrap `dek` to `recipient_pub`. Public-key operation only.
pub(crate) fn wrap_dek(
    dek: &[u8; KEY_LEN],
    recipient_pub: &[u8; PUBKEY_LEN],
    vault_id: VaultId,
    slot_id: SlotId,
    aad: &[u8],
) -> Result<WrappedDek, VaultError> {
    let recipient = PublicKey::from(*recipient_pub);
    // Fresh per wrap; the exchange consumes it, so it cannot be reused even
    // by mistake.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(VaultError::NonContributoryExchange);
    }

    let wrap_key = derive_wrap_key(
        shared.as_bytes(),
        vault_id,
        slot_id,
        &ephemeral_pub,
        recipient_pub,
    );
    Ok(WrappedDek {
        ephemeral_pub,
        sealed: seal(&wrap_key, aad, dek),
    })
}

/// Reverse of [`wrap_dek`], using the slot's private key.
pub(crate) fn unwrap_dek(
    wrapped: &WrappedDek,
    recipient_secret: &StaticSecret,
    vault_id: VaultId,
    slot_id: SlotId,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let recipient_pub = PublicKey::from(recipient_secret).to_bytes();
    let ephemeral = PublicKey::from(wrapped.ephemeral_pub);
    let shared = recipient_secret.diffie_hellman(&ephemeral);
    if !shared.was_contributory() {
        return Err(VaultError::NonContributoryExchange);
    }

    let wrap_key = derive_wrap_key(
        shared.as_bytes(),
        vault_id,
        slot_id,
        &wrapped.ephemeral_pub,
        &recipient_pub,
    );
    open(&wrap_key, aad, &wrapped.sealed, "wrapped DEK")
}

/// A fresh X25519 recipient key pair for a new slot.
pub(crate) fn generate_recipient() -> (StaticSecret, [u8; PUBKEY_LEN]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (VaultId, SlotId) {
        (
            VaultId::from_bytes([7u8; 16]),
            SlotId::from_bytes([9u8; 16]),
        )
    }

    #[test]
    fn seal_open_round_trips_with_matching_aad() {
        let key = [1u8; KEY_LEN];
        let sealed = seal(&key, b"header", b"plaintext");
        let out = open(&key, b"header", &sealed, "test").expect("opens");
        assert_eq!(out.as_slice(), b"plaintext");
    }

    /// The AAD is what binds the body to its header (DR-0034 §1a). If a
    /// different AAD still opened the ciphertext, every header-tampering
    /// defence in the format would be decorative.
    #[test]
    fn open_rejects_a_different_aad() {
        let key = [1u8; KEY_LEN];
        let sealed = seal(&key, b"header", b"plaintext");
        assert!(matches!(
            open(&key, b"tampered", &sealed, "test"),
            Err(VaultError::DecryptFailed { .. })
        ));
    }

    #[test]
    fn open_rejects_a_different_key() {
        let sealed = seal(&[1u8; KEY_LEN], b"", b"plaintext");
        assert!(matches!(
            open(&[2u8; KEY_LEN], b"", &sealed, "test"),
            Err(VaultError::DecryptFailed { .. })
        ));
    }

    /// A truncated blob must be a clean authentication failure, not a panic
    /// from slicing past the end.
    #[test]
    fn open_rejects_a_blob_too_short_to_hold_a_nonce_and_tag() {
        assert!(matches!(
            open(&[1u8; KEY_LEN], b"", &[0u8; 8], "test"),
            Err(VaultError::DecryptFailed { .. })
        ));
    }

    /// Nonce reuse under a fixed key is the one catastrophic misuse of this
    /// AEAD. Every `seal` must draw a fresh nonce, so sealing the same
    /// plaintext under the same key twice must never produce equal bytes.
    #[test]
    fn seal_never_reuses_a_nonce_for_the_same_key_and_plaintext() {
        let key = [1u8; KEY_LEN];
        let a = seal(&key, b"", b"same plaintext");
        let b = seal(&key, b"", b"same plaintext");
        assert_ne!(
            &a[..NONCE_LEN],
            &b[..NONCE_LEN],
            "each seal must draw a fresh nonce from the OS CSPRNG"
        );
        assert_ne!(a, b, "nonce reuse would make the ciphertexts identical too");
    }

    /// Domain separation, the property DR-0034 §2 buys by putting the ids in
    /// `info`: the same input secret and salt must yield unrelated KEKs when
    /// any of vault id / format version / slot id differs.
    #[test]
    fn kek_differs_per_vault_per_version_and_per_slot() {
        let (vault, slot) = ids();
        let secret = b"prf output";
        let salt = [3u8; 32];
        let base = derive_kek(secret, &salt, vault, 1, slot);
        let other_vault = derive_kek(secret, &salt, VaultId::from_bytes([8u8; 16]), 1, slot);
        let other_version = derive_kek(secret, &salt, vault, 2, slot);
        let other_slot = derive_kek(secret, &salt, vault, 1, SlotId::from_bytes([10u8; 16]));
        assert_ne!(*base, *other_vault);
        assert_ne!(*base, *other_version);
        assert_ne!(*base, *other_slot);
    }

    #[test]
    fn kek_is_deterministic_for_identical_inputs() {
        let (vault, slot) = ids();
        let salt = [3u8; 32];
        assert_eq!(
            *derive_kek(b"prf output", &salt, vault, 1, slot),
            *derive_kek(b"prf output", &salt, vault, 1, slot)
        );
    }

    #[test]
    fn kek_differs_per_salt() {
        let (vault, slot) = ids();
        assert_ne!(
            *derive_kek(b"prf output", &[3u8; 32], vault, 1, slot),
            *derive_kek(b"prf output", &[4u8; 32], vault, 1, slot)
        );
    }

    #[test]
    fn wrapped_dek_round_trips_to_its_recipient() {
        let (vault, slot) = ids();
        let (secret, public) = generate_recipient();
        let dek = [42u8; KEY_LEN];
        let wrapped = wrap_dek(&dek, &public, vault, slot, b"aad").expect("wraps");
        let out = unwrap_dek(&wrapped, &secret, vault, slot, b"aad").expect("unwraps");
        assert_eq!(out.as_slice(), &dek);
    }

    #[test]
    fn wrapped_dek_does_not_open_for_a_different_recipient() {
        let (vault, slot) = ids();
        let (_, public) = generate_recipient();
        let (other_secret, _) = generate_recipient();
        let wrapped = wrap_dek(&[42u8; KEY_LEN], &public, vault, slot, b"aad").expect("wraps");
        assert!(unwrap_dek(&wrapped, &other_secret, vault, slot, b"aad").is_err());
    }

    /// The slot id is in the wrap key's `info`, so a wrap lifted out of one
    /// slot and pasted into another does not decrypt even for the same
    /// recipient key — the transcript binding described on `derive_wrap_key`.
    #[test]
    fn wrapped_dek_is_bound_to_its_slot_id() {
        let (vault, slot) = ids();
        let (secret, public) = generate_recipient();
        let wrapped = wrap_dek(&[42u8; KEY_LEN], &public, vault, slot, b"aad").expect("wraps");
        let other_slot = SlotId::from_bytes([11u8; 16]);
        assert!(unwrap_dek(&wrapped, &secret, vault, other_slot, b"aad").is_err());
    }

    /// Two wraps of the same DEK to the same recipient must differ: a fresh
    /// ephemeral key per wrap is what keeps rotation from leaking that the
    /// DEK stayed the same.
    #[test]
    fn each_wrap_uses_a_fresh_ephemeral_key() {
        let (vault, slot) = ids();
        let (_, public) = generate_recipient();
        let dek = [42u8; KEY_LEN];
        let a = wrap_dek(&dek, &public, vault, slot, b"").expect("wraps");
        let b = wrap_dek(&dek, &public, vault, slot, b"").expect("wraps");
        assert_ne!(a.ephemeral_pub, b.ephemeral_pub);
        assert_ne!(a.sealed, b.sealed);
    }

    /// A low-order public key would drive every wrap to the same all-zero
    /// shared secret. Reject rather than derive a key an attacker can predict.
    #[test]
    fn wrap_rejects_a_low_order_public_key() {
        let (vault, slot) = ids();
        let low_order = [0u8; PUBKEY_LEN];
        assert!(matches!(
            wrap_dek(&[42u8; KEY_LEN], &low_order, vault, slot, b""),
            Err(VaultError::NonContributoryExchange)
        ));
    }

    /// The two HKDF purpose labels are part of the wire format: they decide
    /// what key a given secret derives to, so changing one makes every
    /// existing vault undecryptable. Pinned as bytes so such a change has to
    /// be deliberate.
    #[test]
    fn hkdf_purpose_labels_are_byte_pinned() {
        assert_eq!(KEK_INFO_LABEL, b"cw-vault-slot-kek");
        assert_eq!(DEK_WRAP_INFO_LABEL, b"cw-vault-dek-wrap");
        assert_ne!(KEK_INFO_LABEL, DEK_WRAP_INFO_LABEL);
    }

    /// A KEK derived for one purpose must not equal the key another purpose
    /// would derive from the same inputs.
    #[test]
    fn the_two_purpose_labels_derive_different_keys_from_one_secret() {
        let hk = Hkdf::<Sha256>::new(None, b"same secret");
        let mut a = [0u8; KEY_LEN];
        let mut b = [0u8; KEY_LEN];
        hk.expand(KEK_INFO_LABEL, &mut a).unwrap();
        hk.expand(DEK_WRAP_INFO_LABEL, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn random_key_is_not_all_zero_and_differs_per_call() {
        let a = random_key();
        let b = random_key();
        assert_ne!(*a, [0u8; KEY_LEN]);
        assert_ne!(*a, *b);
    }
}
