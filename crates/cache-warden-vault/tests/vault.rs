//! End-to-end behaviour of the vault (DR-0034 §1 / §3 / §9).
//!
//! Everything here goes through a real file on a real filesystem. The
//! properties under test — that a rotation actually revokes, that a tampered
//! header stops decryption, that a commit is durable and leaves no debris —
//! are properties of bytes on disk, and testing them against an in-memory
//! stand-in would only prove the stand-in agrees with itself.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cache_warden_vault::{
    GuardRecordSlot, LockedVault, OwnerPrincipalSlot, RecoveryCode, SlotKind, UnlockedVault,
    VaultEntry, VaultError, storage,
};

mod support;
use support::new_vault;

fn entry(key: &str, secret: &str) -> VaultEntry {
    VaultEntry::new(key, secret.as_bytes().to_vec())
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn reopen(path: &Path, code: &RecoveryCode) -> Result<UnlockedVault, VaultError> {
    LockedVault::open(path)?.unlock_with_recovery_code(code)
}

// ---- round trip ----

#[test]
fn an_entry_written_before_locking_comes_back_after_unlocking() {
    let (_dir, mut vault, code) = new_vault();
    let path = vault.path().to_path_buf();

    vault
        .upsert(entry("llm/refresh-token", "rt-abc123"), None)
        .expect("commits");
    let locked = vault.lock().expect("locks");
    drop(locked);

    let vault = reopen(&path, &code).expect("unlocks");
    let got = vault.entry("llm/refresh-token").expect("entry survived");
    assert_eq!(got.secret.as_slice(), b"rt-abc123");
    assert_eq!(got.cas_version, 1);
}

/// DR-0034 §1d: a value must never come back without the authorization that
/// governs it. Phase 1 cannot yet interpret the guard record or the owner
/// principal — but it must already carry them, and the CAS version, across a
/// lock/unlock cycle intact, or vaults written now would reach phase 5 having
/// silently dropped them.
///
/// The version is checked by writing twice and reopening: a durable version is
/// only meaningful if it survives the restart, and asserting on a value the
/// vault derived (2, from two writes) rather than one the test chose proves the
/// stored number is the real counter.
#[test]
fn authorization_and_version_travel_with_the_value() {
    let (_dir, mut vault, code) = new_vault();
    let path = vault.path().to_path_buf();

    let mut e = entry("llm/refresh-token", "rt-abc123");
    e.guard = Some(GuardRecordSlot(serde_json::json!({
        "constraints": [{"kind": "same-user"}]
    })));
    e.owner = Some(OwnerPrincipalSlot(serde_json::json!({
        "signed_by": "SHA256:deadbeef"
    })));
    vault.upsert(e.clone(), None).expect("commits");
    vault.upsert(e.clone(), None).expect("commits again");
    drop(vault);

    let vault = reopen(&path, &code).expect("unlocks");
    let got = vault.entry("llm/refresh-token").expect("entry survived");
    assert_eq!(got.cas_version, 2, "two writes, and the count is durable");
    assert_eq!(got.guard, e.guard);
    assert_eq!(got.owner, e.owner);
}

/// The version belongs to the vault, not to whoever submits an entry.
///
/// A caller that could choose the version could set it backwards, and DR-0034
/// §4 leans on monotonicity to keep a spent refresh token from looking current
/// again. So a submitted version is overwritten rather than honoured — this
/// pins that, because "the field round-trips verbatim" was true in phase 1 and
/// is deliberately no longer true.
#[test]
fn a_caller_supplied_version_is_ignored_and_the_vault_assigns_its_own() {
    let (_dir, mut vault, _code) = new_vault();

    let mut e = entry("k", "v");
    e.cas_version = 999;
    vault.upsert(e, None).expect("commits");
    assert_eq!(vault.entry("k").unwrap().cas_version, 1);

    let mut e2 = entry("k", "v2");
    e2.cas_version = 0;
    vault.upsert(e2, None).expect("commits");
    assert_eq!(vault.entry("k").unwrap().cas_version, 2);
}

#[test]
fn entries_can_be_replaced_and_deleted() {
    let (_dir, mut vault, code) = new_vault();
    let path = vault.path().to_path_buf();

    vault.upsert(entry("a", "one"), None).expect("commits");
    vault.upsert(entry("b", "two"), None).expect("commits");
    vault
        .upsert(entry("a", "one-updated"), None)
        .expect("commits");
    assert_eq!(vault.len(), 2);
    assert_eq!(vault.keys().collect::<Vec<_>>(), vec!["a", "b"]);

    assert!(vault.delete("b").expect("commits"));
    assert!(
        !vault.delete("b").expect("no-op"),
        "deleting twice is not an error"
    );
    drop(vault);

    let vault = reopen(&path, &code).expect("unlocks");
    assert_eq!(vault.len(), 1);
    assert_eq!(vault.entry("a").unwrap().secret.as_slice(), b"one-updated");
    assert!(vault.entry("b").is_none());
}

#[test]
fn a_locked_vault_shows_its_metadata_but_not_its_entries() {
    let (_dir, mut vault, _code) = new_vault();
    vault
        .upsert(entry("secret-name", "value"), None)
        .expect("commits");
    let vault_id = vault.vault_id();
    let path = vault.path().to_path_buf();
    drop(vault);

    let locked = LockedVault::open(&path).expect("opens without any credential");
    assert_eq!(locked.vault_id(), vault_id);
    assert_eq!(locked.dek_generation(), 1);
    assert_eq!(locked.slots().len(), 1);
    assert_eq!(locked.slots()[0].kind(), SlotKind::Recovery);
    assert!(!locked.has_dev_rp_slot());

    // DR-0034 §7's privacy line: the file reveals which credential opens it,
    // never what it holds. The entry name is in the sealed body.
    let raw = fs::read(&path).unwrap();
    assert!(
        !raw.windows(11).any(|w| w == b"secret-name"),
        "entry names must not appear in the plaintext header"
    );
    assert!(!raw.windows(5).any(|w| w == b"value"));
}

// ---- credentials ----

#[test]
fn a_recovery_code_from_another_vault_does_not_unlock_this_one() {
    let (_dir_a, vault_a, _code_a) = new_vault();
    let (_dir_b, _vault_b, code_b) = new_vault();
    let path = vault_a.path().to_path_buf();
    drop(vault_a);

    assert!(matches!(
        reopen(&path, &code_b),
        Err(VaultError::NoMatchingSlot)
    ));
}

#[test]
fn a_mistyped_recovery_code_does_not_unlock() {
    let (_dir, vault, code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    // Change one digit of the real code.
    let rendered = code.render();
    let mut wrong: String = rendered.chars().filter(|c| *c != '-').collect();
    let first = wrong.remove(0);
    wrong.insert(0, if first == 'Z' { 'Y' } else { 'Z' });
    let wrong = RecoveryCode::parse(&wrong).expect("still well-formed");

    assert!(matches!(
        reopen(&path, &wrong),
        Err(VaultError::NoMatchingSlot)
    ));
}

#[test]
fn open_expecting_rejects_a_different_vault_at_the_same_path() {
    let (_dir_a, vault_a, _code) = new_vault();
    let (_dir_b, vault_b, code_b) = new_vault();
    let expected = vault_a.vault_id();
    let path_b = vault_b.path().to_path_buf();
    drop(vault_a);
    drop(vault_b);

    assert!(matches!(
        LockedVault::open_expecting(&path_b, expected),
        Err(VaultError::VaultIdMismatch)
    ));
    // The same file opens fine when the caller expects the vault it actually is.
    let locked = LockedVault::open(&path_b).unwrap();
    let id = locked.vault_id();
    drop(locked);
    assert!(
        LockedVault::open_expecting(&path_b, id)
            .unwrap()
            .unlock_with_recovery_code(&code_b)
            .is_ok()
    );
}

// ---- header tampering (DR-0034 §1a: the whole header is the body's AAD) ----

/// `dek_generation` is not an input to any slot's key derivation, so nothing
/// but the AAD stops it from being wound back. Winding it back is how an
/// attacker would try to pass off an old body as current; the header AAD is
/// what turns that into a decryption failure.
#[test]
fn rewriting_the_dek_generation_breaks_decryption() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut bytes = fs::read(&path).unwrap();
    // dek_generation: 8 bytes at offset 28.
    bytes[35] = bytes[35].wrapping_add(1);
    fs::write(&path, &bytes).unwrap();

    match reopen(&path, &code) {
        Err(VaultError::DecryptFailed { .. }) => {}
        other => panic!(
            "a rewritten generation must fail decryption, got {other:?}",
            other = other.map(|_| ()).err()
        ),
    }
}

/// A slot's label takes part in no key derivation at all — it is pure
/// metadata. It is still covered, because the AAD is *every* header byte
/// rather than a chosen subset. This is the test that would fail if someone
/// later "optimized" the AAD down to the security-relevant fields.
#[test]
fn editing_a_slots_label_breaks_decryption() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut bytes = fs::read(&path).unwrap();
    let at = find(&bytes, b"recovery code").expect("the default label is in the header");
    bytes[at] = b'R';
    fs::write(&path, &bytes).unwrap();

    assert!(matches!(
        reopen(&path, &code),
        Err(VaultError::DecryptFailed { .. })
    ));
}

/// Transplanting another vault's slot into this header does not create a way
/// in: the slot's KEK is derived over *this* vault's id, so neither code
/// opens the grafted slot.
#[test]
fn a_slot_transplanted_from_another_vault_opens_for_neither_code() {
    let (_dir_a, vault_a, code_a) = new_vault();
    let (_dir_b, vault_b, code_b) = new_vault();
    let path_a = vault_a.path().to_path_buf();
    let path_b = vault_b.path().to_path_buf();
    drop(vault_a);
    drop(vault_b);

    let a = fs::read(&path_a).unwrap();
    let b = fs::read(&path_b).unwrap();
    // Both vaults were initialized identically, so their single slots have
    // the same layout and length.
    let slot_len = first_slot_len(&a);
    assert_eq!(slot_len, first_slot_len(&b));

    let mut grafted = a.clone();
    grafted[SLOT_START..SLOT_START + slot_len]
        .copy_from_slice(&b[SLOT_START..SLOT_START + slot_len]);
    fs::write(&path_a, &grafted).unwrap();

    assert!(matches!(
        reopen(&path_a, &code_b),
        Err(VaultError::NoMatchingSlot),
    ));
    assert!(matches!(
        reopen(&path_a, &code_a),
        Err(VaultError::NoMatchingSlot),
    ));
}

#[test]
fn a_truncated_vault_file_is_an_error_not_a_panic() {
    let (_dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    let bytes = fs::read(&path).unwrap();
    for cut in [0, 8, 12, 44, bytes.len() - 1] {
        fs::write(&path, &bytes[..cut]).unwrap();
        assert!(
            LockedVault::open(&path).is_err(),
            "a {cut}-byte file must not open"
        );
    }
}

// ---- slots: addition, removal, rotation (DR-0034 §1b / §1c) ----

#[test]
fn a_second_recovery_slot_opens_the_same_vault_and_the_first_still_works() {
    let (_dir, mut vault, first_code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();

    let (second_id, second_code) = vault.add_recovery_slot("backup").expect("adds a slot");
    assert_eq!(vault.slots().len(), 2);
    // Adding a recipient does not rotate: no existing credential is disturbed.
    assert_eq!(vault.dek_generation(), 1);
    drop(vault);

    for code in [&first_code, &second_code] {
        let v = reopen(&path, code).expect("both codes open the vault");
        assert_eq!(v.entry("k").unwrap().secret.as_slice(), b"v");
        assert_eq!(v.slots().len(), 2);
    }
    assert!(
        LockedVault::open(&path)
            .unwrap()
            .slots()
            .iter()
            .any(|s| s.id() == second_id && s.label() == "backup")
    );
}

/// The core revocation property (DR-0034 §1c). Removing a slot rotates the
/// DEK, so the removed credential is not merely delisted — it cannot decrypt
/// the file that exists afterwards.
#[test]
fn removing_a_slot_rotates_the_dek_so_the_removed_code_stops_working() {
    let (_dir, mut vault, original_code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();

    let (_kept_id, kept_code) = vault.add_recovery_slot("kept").expect("adds a slot");
    let doomed_id = vault.slots()[0].id();

    vault.remove_slot(doomed_id).expect("removes and rotates");
    assert_eq!(vault.slots().len(), 1);
    assert_eq!(
        vault.dek_generation(),
        2,
        "removal must bump the generation, i.e. must have rotated"
    );
    drop(vault);

    assert!(
        matches!(
            reopen(&path, &original_code),
            Err(VaultError::NoMatchingSlot)
        ),
        "the removed code must no longer open the vault"
    );
    let v = reopen(&path, &kept_code).expect("the remaining code still opens it");
    assert_eq!(v.entry("k").unwrap().secret.as_slice(), b"v");
}

/// Rotation re-wraps for every remaining slot using **public keys only**
/// (DR-0034 §1b). The proof: unlock with slot A, remove slot C, and find that
/// slot B — whose recovery code was never supplied to this process — still
/// opens the rotated file. If re-wrapping needed B's credential, B would have
/// been locked out.
#[test]
fn rotation_rewraps_for_slots_whose_credentials_were_never_supplied() {
    let (_dir, mut vault, code_a) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();

    let (_b_id, code_b) = vault.add_recovery_slot("b").expect("adds b");
    let (c_id, code_c) = vault.add_recovery_slot("c").expect("adds c");
    drop(vault);

    // Re-open using A's code alone. B's and C's secrets are not involved.
    let mut vault = reopen(&path, &code_a).expect("unlocks with A");
    vault
        .remove_slot(c_id)
        .expect("removes c, rotating the DEK");
    assert_eq!(vault.dek_generation(), 2);
    drop(vault);

    let v = reopen(&path, &code_b).expect("B still opens the rotated vault");
    assert_eq!(v.entry("k").unwrap().secret.as_slice(), b"v");
    assert!(matches!(
        reopen(&path, &code_c),
        Err(VaultError::NoMatchingSlot)
    ));
}

#[test]
fn an_explicit_rotation_keeps_every_slot_working() {
    let (_dir, mut vault, code_a) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    let (_id, code_b) = vault.add_recovery_slot("b").expect("adds b");

    vault.rotate_dek().expect("rotates");
    assert_eq!(vault.dek_generation(), 2);
    drop(vault);

    for code in [&code_a, &code_b] {
        assert_eq!(
            reopen(&path, code)
                .expect("opens after rotation")
                .entry("k")
                .unwrap()
                .secret
                .as_slice(),
            b"v"
        );
    }
}

#[test]
fn the_last_slot_cannot_be_removed() {
    let (_dir, mut vault, code) = new_vault();
    let only = vault.slots()[0].id();
    assert!(matches!(vault.remove_slot(only), Err(VaultError::LastSlot)));
    // And the refusal left the vault exactly as it was.
    assert_eq!(vault.slots().len(), 1);
    assert_eq!(vault.dek_generation(), 1);
    let path = vault.path().to_path_buf();
    drop(vault);
    assert!(reopen(&path, &code).is_ok());
}

#[test]
fn removing_an_unknown_slot_is_an_error_and_changes_nothing() {
    let (_dir, mut vault, _code) = new_vault();
    let (_id, _code_b) = vault.add_recovery_slot("b").expect("adds b");
    let stranger = {
        let (_d, other, _c) = new_vault();
        other.slots()[0].id()
    };
    assert!(matches!(
        vault.remove_slot(stranger),
        Err(VaultError::SlotNotFound)
    ));
    assert_eq!(vault.slots().len(), 2);
    assert_eq!(vault.dek_generation(), 1);
}

// ---- durability and placement (DR-0034 §3 / §7) ----

#[test]
fn the_vault_file_is_created_and_kept_at_0600() {
    let (_dir, mut vault, _code) = new_vault();
    assert_eq!(mode_of(vault.path()), 0o600);
    vault.upsert(entry("k", "v"), None).expect("commits");
    assert_eq!(mode_of(vault.path()), 0o600, "a rewrite must not loosen it");
    assert_eq!(
        mode_of(vault.path().parent().unwrap()),
        0o700,
        "the state directory is 0700"
    );
}

#[test]
fn a_committed_vault_leaves_no_temporary_files() {
    let (dir, mut vault, _code) = new_vault();
    vault.upsert(entry("a", "1"), None).expect("commits");
    vault.upsert(entry("b", "2"), None).expect("commits");
    vault.rotate_dek().expect("rotates");

    let names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec![format!("vault-{}.cwv", storage::DEFAULT_PROFILE)],
        "only the vault itself should remain"
    );
}

/// A crash between writing the temporary file and renaming it leaves the
/// temporary behind and the vault untouched. That is the whole point of
/// write-then-rename: the reader never sees a partial file, and the leftover
/// is inert.
#[test]
fn a_leftover_temporary_file_does_not_affect_the_vault() {
    let (dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    let before = fs::read(&path).unwrap();
    drop(vault);

    // Stand in for a crash after `write_and_sync` and before `rename`.
    let stray = dir.path().join(".vault-default.cwv.tmp-0123456789abcdef");
    fs::write(&stray, b"a half-written vault that never got renamed").unwrap();

    assert_eq!(fs::read(&path).unwrap(), before, "the vault is untouched");
    let mut vault = reopen(&path, &code).expect("the vault still opens");
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"v");

    // And a subsequent commit succeeds alongside the leftover.
    vault.upsert(entry("k2", "v2"), None).expect("commits");
    drop(vault);
    let vault = reopen(&path, &code).expect("opens");
    assert_eq!(vault.len(), 2);
}

#[test]
fn separate_profiles_are_separate_vaults() {
    let dir = tempfile::TempDir::new().unwrap();
    let prod = storage::vault_path(dir.path(), storage::DEFAULT_PROFILE);
    let dev = storage::vault_path(dir.path(), "dev");
    let (prod_vault, prod_code) = UnlockedVault::initialize(&prod).expect("initializes");
    let (dev_vault, _dev_code) = UnlockedVault::initialize(&dev).expect("initializes");

    assert_ne!(prod, dev);
    assert_ne!(prod_vault.vault_id(), dev_vault.vault_id());
    drop(prod_vault);
    drop(dev_vault);

    // A production code must not open the development vault.
    assert!(matches!(
        reopen(&dev, &prod_code),
        Err(VaultError::NoMatchingSlot)
    ));
}

/// The exclusive-create refusal is only worth having if the existing vault
/// survives it. This is the failure the check-then-act version could produce:
/// a second `initialize` racing the first and leaving an empty vault where the
/// only copy of someone's credentials used to be.
#[test]
fn a_refused_initialize_leaves_the_existing_vault_fully_intact() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    let vault_id = vault.vault_id();
    let before = fs::read(&path).unwrap();
    drop(vault);

    let err = UnlockedVault::initialize(&path).expect_err("must refuse");
    match err {
        VaultError::Io { source, .. } => {
            assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists);
        }
        other => panic!("expected an AlreadyExists io error, got {other}"),
    }

    assert_eq!(fs::read(&path).unwrap(), before, "not one byte may change");
    let reopened = reopen(&path, &code).expect("the original vault still opens");
    assert_eq!(reopened.vault_id(), vault_id);
    assert_eq!(reopened.entry("k").unwrap().secret.as_slice(), b"v");
}

#[test]
fn trailing_bytes_after_the_body_are_rejected() {
    let (_dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"smuggled");
    fs::write(&path, &bytes).unwrap();

    assert!(matches!(
        LockedVault::open(&path),
        Err(VaultError::Malformed { .. })
    ));
}

/// An oversized file must be refused from its metadata, before it is read.
/// The file here is sparse, so it costs no disk — which is also why an
/// attacker could plant one cheaply.
#[test]
fn an_implausibly_large_file_is_refused_without_being_read() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = storage::vault_path(dir.path(), storage::DEFAULT_PROFILE);
    fs::create_dir_all(dir.path()).unwrap();
    let f = fs::File::create(&path).unwrap();
    f.set_len(128 * 1024 * 1024).unwrap();
    drop(f);

    assert!(matches!(
        LockedVault::open(&path),
        Err(VaultError::FileTooLarge { .. })
    ));
}

/// Mutations write before they install, so a commit that cannot happen leaves
/// the in-memory vault exactly as it was. Without that ordering the vault
/// would carry a change the file does not have, and the next successful commit
/// would silently persist it.
#[test]
fn a_failed_commit_leaves_the_vault_unchanged_in_memory() {
    let (dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    let before = fs::read(&path).unwrap();

    // A read-only directory blocks the temporary file the commit needs.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    assert!(
        vault.upsert(entry("k2", "v2"), None).is_err(),
        "the commit fails"
    );
    assert_eq!(vault.len(), 1, "the entry must not be in memory either");
    assert!(vault.entry("k2").is_none());

    assert!(vault.delete("k").is_err(), "the commit fails");
    assert!(
        vault.entry("k").is_some(),
        "the delete must not have applied"
    );

    let generation = vault.dek_generation();
    let slot_count = vault.slots().len();
    assert!(vault.rotate_dek().is_err(), "the commit fails");
    assert_eq!(vault.dek_generation(), generation, "no rotation in memory");
    assert_eq!(vault.slots().len(), slot_count);

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before, "the file is untouched");

    // The vault is still usable, and its in-memory DEK still matches the file.
    vault
        .upsert(entry("k3", "v3"), None)
        .expect("commits once writable again");
    drop(vault);
    let reopened = reopen(&path, &code).expect("opens");
    assert_eq!(reopened.len(), 2);
    assert!(reopened.entry("k").is_some() && reopened.entry("k3").is_some());
    assert!(reopened.entry("k2").is_none());
}

/// A slot removal that cannot commit must not leave the rotation applied in
/// memory — otherwise the next successful write would persist a DEK rotation
/// and a slot removal the caller was told had failed.
#[test]
fn a_failed_slot_removal_does_not_leave_a_rotation_in_memory() {
    let (dir, mut vault, code_a) = new_vault();
    let (b_id, code_b) = vault.add_recovery_slot("b").expect("adds b");
    vault.upsert(entry("k", "v"), None).expect("commits");

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(vault.remove_slot(b_id).is_err(), "the commit fails");
    assert_eq!(vault.slots().len(), 2, "the slot must still be there");
    assert_eq!(vault.dek_generation(), 1, "no rotation in memory");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let path = vault.path().to_path_buf();
    vault.upsert(entry("k2", "v2"), None).expect("commits");
    drop(vault);

    // B was never actually removed, so B's code must still work.
    for code in [&code_a, &code_b] {
        let v = reopen(&path, code).expect("both codes still open the vault");
        assert_eq!(v.dek_generation(), 1);
        assert_eq!(v.slots().len(), 2);
        assert_eq!(v.len(), 2);
    }
}

// ---- helpers ----

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Byte offset of the first slot: magic(8) + version(4) + vault_id(16) +
/// generation(8) + aead(2) + kdf(2) + slot_count(4).
const SLOT_START: usize = 44;

/// Length of the first slot, walked forward through its length prefixes.
fn first_slot_len(bytes: &[u8]) -> usize {
    // id(16) + kind(2) + pubkey(32) + salt(32) + created_at(8)
    let mut at = SLOT_START + 16 + 2 + 32 + 32 + 8;
    let skip_blob = |at: &mut usize| {
        let len = u32::from_be_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4 + len;
    };
    skip_blob(&mut at); // wrapped_privkey
    at += 32; // the wrapped DEK's ephemeral public key
    skip_blob(&mut at); // wrapped_dek
    skip_blob(&mut at); // rp_id
    skip_blob(&mut at); // credential_id
    skip_blob(&mut at); // label
    at - SLOT_START
}
