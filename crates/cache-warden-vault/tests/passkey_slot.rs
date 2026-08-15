//! Passkey slots end to end, from a ceremony to an unlocked vault
//! (DR-0034 §1c / §2).
//!
//! The ceremony is driven by a software authenticator, which is what makes
//! this runnable without a browser or a fingerprint. What it exercises is the
//! real key schedule: the salt this vault generated, the PRF output that
//! authenticator produces for it, and the derivation from that output down to
//! the data key.

use cache_warden_vault::{LockedVault, SlotKind, UnlockedVault, VaultEntry, VaultError};
use cache_warden_webauthn::{Algorithm, SoftAuthenticator};

mod support;
use support::new_vault;

/// Register `auth` as a passkey slot, returning the id it was given.
fn add_passkey(
    vault: &mut UnlockedVault,
    auth: &SoftAuthenticator,
    label: &str,
) -> cache_warden_vault::SlotId {
    let salt = UnlockedVault::new_passkey_salt();
    let prf = auth.prf_output(&salt);
    vault
        .add_passkey_slot(
            &prf,
            salt,
            "vault.example.test",
            auth.credential_id(),
            vec![1, 2, 3],
            label,
        )
        .expect("adds the slot")
}

#[test]
fn a_registered_passkey_opens_the_vault_it_was_registered_against() {
    let (_dir, mut vault, _code) = new_vault();
    vault
        .upsert(
            VaultEntry::new("default/RT", b"refresh-token".to_vec()),
            None,
        )
        .expect("stores an entry");

    let auth = SoftAuthenticator::new(Algorithm::Es256);
    let slot_id = add_passkey(&mut vault, &auth, "laptop");

    // The salt has to survive to the next unlock — it is what the ceremony
    // evaluates, and it lives in the header for exactly that reason.
    let path = vault.path().to_path_buf();
    let locked = vault.lock().expect("locks");
    let slot = locked
        .slots()
        .iter()
        .find(|s| s.id() == slot_id)
        .expect("the slot is in the header");
    assert_eq!(slot.kind(), SlotKind::PasskeyPrf);
    assert_eq!(slot.credential_id(), auth.credential_id());
    assert_eq!(slot.rp_id(), "vault.example.test");
    let salt = slot.prf_salt().to_vec();
    drop(locked);

    // A fresh process: nothing is held but the file and the authenticator.
    let locked = LockedVault::open(&path).expect("reopens");
    let unlocked = locked
        .unlock_with_prf_output(&auth.prf_output(&salt))
        .expect("the registered passkey opens it");
    assert_eq!(
        unlocked.entry("default/RT").map(|e| e.secret.to_vec()),
        Some(b"refresh-token".to_vec())
    );
}

/// Slot separation: a salt is per slot, so the same authenticator registered
/// twice produces two independent keys. Neither slot's PRF output may open the
/// other, or registering a second device would silently weaken the first.
#[test]
fn two_slots_from_one_authenticator_have_independent_keys() {
    let (_dir, mut vault, _code) = new_vault();
    let auth = SoftAuthenticator::new(Algorithm::Es256);

    let salt_a = UnlockedVault::new_passkey_salt();
    let salt_b = UnlockedVault::new_passkey_salt();
    assert_ne!(salt_a, salt_b, "each slot gets its own salt");

    vault
        .add_passkey_slot(
            &auth.prf_output(&salt_a),
            salt_a,
            "vault.example.test",
            auth.credential_id(),
            vec![1],
            "first",
        )
        .expect("adds");
    let path = vault.path().to_path_buf();
    drop(vault);

    // The output for a salt no slot holds opens nothing.
    let locked = LockedVault::open(&path).expect("reopens");
    assert!(matches!(
        locked.unlock_with_prf_output(&auth.prf_output(&salt_b)),
        Err(VaultError::NoMatchingSlot)
    ));

    // And the one it does hold still works.
    let locked = LockedVault::open(&path).expect("reopens");
    locked
        .unlock_with_prf_output(&auth.prf_output(&salt_a))
        .expect("the registered salt opens it");
}

/// A different authenticator cannot open a slot, however well it knows the
/// salt — the salt is public and the PRF output is not.
#[test]
fn another_authenticator_cannot_open_the_slot() {
    let (_dir, mut vault, _code) = new_vault();
    let auth = SoftAuthenticator::new(Algorithm::Es256);
    let salt = UnlockedVault::new_passkey_salt();
    vault
        .add_passkey_slot(
            &auth.prf_output(&salt),
            salt,
            "vault.example.test",
            auth.credential_id(),
            vec![1],
            "mine",
        )
        .expect("adds");
    let path = vault.path().to_path_buf();
    drop(vault);

    let impostor = SoftAuthenticator::new(Algorithm::Es256);
    let locked = LockedVault::open(&path).expect("reopens");
    assert!(matches!(
        locked.unlock_with_prf_output(&impostor.prf_output(&salt)),
        Err(VaultError::NoMatchingSlot)
    ));
}

/// The two kinds of credential do not cross: a recovery code is not a PRF
/// output and must not be tried as one, or a vault would report the wrong
/// reason for a failure and, worse, the two kinds' rate limits would not mean
/// what they say (DR-0034 §9 keeps recovery on a separate, limited path).
#[test]
fn a_recovery_code_does_not_open_a_passkey_slot_or_the_reverse() {
    let (_dir, mut vault, code) = new_vault();
    let auth = SoftAuthenticator::new(Algorithm::Es256);
    let salt = UnlockedVault::new_passkey_salt();
    vault
        .add_passkey_slot(
            &auth.prf_output(&salt),
            salt,
            "vault.example.test",
            auth.credential_id(),
            vec![1],
            "laptop",
        )
        .expect("adds");
    let path = vault.path().to_path_buf();
    drop(vault);

    // The recovery code's own rendered form, offered as if it were a PRF
    // output: the passkey path must not open for it.
    let locked = LockedVault::open(&path).expect("reopens");
    assert!(matches!(
        locked.unlock_with_prf_output(code.render().as_bytes()),
        Err(VaultError::NoMatchingSlot)
    ));

    // Both real credentials still work, each on its own path.
    let locked = LockedVault::open(&path).expect("reopens");
    locked
        .unlock_with_recovery_code(&code)
        .expect("the recovery code opens the recovery slot");
    let locked = LockedVault::open(&path).expect("reopens");
    locked
        .unlock_with_prf_output(&auth.prf_output(&salt))
        .expect("the passkey opens the passkey slot");
}

/// A slot that cannot name its credential could never be used: unlock needs
/// the id to address it and the key to verify what it signs.
#[test]
fn a_passkey_slot_without_its_credential_is_refused() {
    let (_dir, mut vault, _code) = new_vault();
    let salt = UnlockedVault::new_passkey_salt();
    assert!(
        vault
            .add_passkey_slot(&[0u8; 32], salt, "rp", Vec::new(), vec![1], "no id")
            .is_err()
    );
    assert!(
        vault
            .add_passkey_slot(&[0u8; 32], salt, "rp", vec![1], Vec::new(), "no key")
            .is_err()
    );
}

/// Removing a passkey rotates the data key (DR-0034 §1c), so the removed
/// credential is not merely unlisted — it cannot open even a copy of the file
/// taken while it was still valid.
#[test]
fn removing_a_passkey_slot_rotates_the_data_key() {
    let (_dir, mut vault, code) = new_vault();
    let auth = SoftAuthenticator::new(Algorithm::Es256);
    let salt = UnlockedVault::new_passkey_salt();
    let slot_id = vault
        .add_passkey_slot(
            &auth.prf_output(&salt),
            salt,
            "vault.example.test",
            auth.credential_id(),
            vec![1],
            "old laptop",
        )
        .expect("adds");
    let generation_before = vault.dek_generation();

    vault.remove_slot(slot_id).expect("removes");
    assert!(
        vault.dek_generation() > generation_before,
        "removal must rotate"
    );
    let path = vault.path().to_path_buf();
    drop(vault);

    let locked = LockedVault::open(&path).expect("reopens");
    assert!(matches!(
        locked.unlock_with_prf_output(&auth.prf_output(&salt)),
        Err(VaultError::NoMatchingSlot)
    ));
    // The recovery slot was re-wrapped for the new key, so it still opens.
    let locked = LockedVault::open(&path).expect("reopens");
    locked
        .unlock_with_recovery_code(&code)
        .expect("still opens");
}
