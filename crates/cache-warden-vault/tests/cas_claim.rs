//! Compare-and-swap writes and refresh claims (DR-0034 §4).
//!
//! The properties here are about *arbitration* — who wins when two callers act
//! on one entry — so every test drives two callers against the same file rather
//! than asserting on a single happy path.
//!
//! Timing is deterministic throughout. A claim's lapse is exercised with a
//! zero-length TTL (born lapsed) rather than by sleeping, so these tests have
//! no wall-clock dependency and cannot go flaky on a loaded machine. The
//! expiry boundary arithmetic itself is pinned by unit tests on `Claim`.

use std::time::Duration;

use cache_warden_vault::{
    ClaimToken, LockedVault, RecoveryCode, UnlockedVault, VaultEntry, VaultError,
};

mod support;
use support::new_vault;

fn entry(key: &str, secret: &str) -> VaultEntry {
    VaultEntry::new(key, secret.as_bytes().to_vec())
}

fn reopen(path: &std::path::Path, code: &RecoveryCode) -> UnlockedVault {
    LockedVault::open(path)
        .expect("opens")
        .unlock_with_recovery_code(code)
        .expect("unlocks")
}

const LONG: Duration = Duration::from_secs(300);
const LAPSED: Duration = Duration::from_secs(0);

// ---- CAS ----

#[test]
fn a_create_uses_version_zero_and_lands_at_version_one() {
    let (_dir, mut vault, _code) = new_vault();
    let v = vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    assert_eq!(v, 1);
    assert_eq!(vault.entry("k").unwrap().cas_version, 1);
}

#[test]
fn a_create_that_expects_no_entry_loses_to_an_entry_that_already_exists() {
    let (_dir, mut vault, _code) = new_vault();
    vault
        .upsert_cas(entry("k", "first"), 0, None)
        .expect("creates");

    match vault.upsert_cas(entry("k", "second"), 0, None) {
        Err(VaultError::CasMismatch { current }) => assert_eq!(current, 1),
        other => panic!("expected CasMismatch, got {other:?}"),
    }
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"first");
}

#[test]
fn each_successful_write_advances_the_version_by_exactly_one() {
    let (_dir, mut vault, _code) = new_vault();
    assert_eq!(vault.upsert_cas(entry("k", "a"), 0, None).unwrap(), 1);
    assert_eq!(vault.upsert_cas(entry("k", "b"), 1, None).unwrap(), 2);
    assert_eq!(vault.upsert_cas(entry("k", "c"), 2, None).unwrap(), 3);
}

/// The race the whole mechanism exists for: two callers read the same version
/// and both write back. Exactly one may win, and the loser must learn the
/// version it needs to retry from.
#[test]
fn when_two_callers_write_from_the_same_read_only_one_wins() {
    let (_dir, mut vault, _code) = new_vault();
    vault
        .upsert_cas(entry("token", "v1"), 0, None)
        .expect("creates");

    let seen_by_both = vault.entry("token").unwrap().cas_version;

    let winner = vault.upsert_cas(entry("token", "v2-from-A"), seen_by_both, None);
    let loser = vault.upsert_cas(entry("token", "v2-from-B"), seen_by_both, None);

    assert_eq!(winner.expect("A wins"), 2);
    match loser {
        Err(VaultError::CasMismatch { current }) => {
            assert_eq!(current, 2, "the loser is told where to retry from");
        }
        other => panic!("expected CasMismatch for B, got {other:?}"),
    }
    assert_eq!(
        vault.entry("token").unwrap().secret.as_slice(),
        b"v2-from-A",
        "the loser's value must not have overwritten the winner's"
    );
}

/// A CAS loser must cost nothing on disk. The check runs before any encoding
/// or filesystem work, so a busy loop of losers cannot rewrite the vault.
#[test]
fn a_version_mismatch_does_not_touch_the_file() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let path = vault.path().to_path_buf();
    let before = std::fs::read(&path).unwrap();

    for stale in [0, 5, 99] {
        assert!(vault.upsert_cas(entry("k", "loser"), stale, None).is_err());
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a rejected CAS must not rewrite the vault"
    );
}

#[test]
fn the_version_survives_lock_and_unlock() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert_cas(entry("k", "a"), 0, None).expect("creates");
    vault.upsert_cas(entry("k", "b"), 1, None).expect("updates");
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut vault = reopen(&path, &code);
    assert_eq!(vault.entry("k").unwrap().cas_version, 2);
    // And the counter keeps going from where it was, rather than restarting.
    assert_eq!(vault.upsert_cas(entry("k", "c"), 2, None).unwrap(), 3);
}

// ---- claims ----

#[test]
fn claiming_returns_a_token_and_does_not_advance_the_version() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");

    let token = vault.claim_refresh("k", 1, LONG).expect("claims");
    assert_eq!(
        vault.entry("k").unwrap().cas_version,
        1,
        "a claim changes no value, so it must not advance the value's version"
    );
    assert!(vault.active_claim("k").is_some());
    assert!(vault.active_claim("k").unwrap().token.matches(&token));
}

#[test]
fn a_second_claim_is_refused_while_the_first_is_active() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let first = vault.claim_refresh("k", 1, LONG).expect("claims");

    match vault.claim_refresh("k", 1, LONG) {
        Err(VaultError::AlreadyClaimed {
            expires_at_epoch_ms,
        }) => assert!(expires_at_epoch_ms > 0),
        other => panic!("expected AlreadyClaimed, got {other:?}"),
    }
    // The original claim is untouched by the refused attempt.
    assert!(vault.active_claim("k").unwrap().token.matches(&first));
}

#[test]
fn a_lapsed_claim_can_be_taken_over() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let lapsed = vault.claim_refresh("k", 1, LAPSED).expect("claims");
    assert!(vault.active_claim("k").is_none(), "born lapsed");

    let fresh = vault.claim_refresh("k", 1, LONG).expect("takes over");
    assert!(!fresh.matches(&lapsed), "the takeover mints a new token");
    assert!(vault.active_claim("k").unwrap().token.matches(&fresh));
}

#[test]
fn claiming_from_a_stale_read_is_refused() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "a"), 0, None).expect("creates");
    vault.upsert_cas(entry("k", "b"), 1, None).expect("updates");

    match vault.claim_refresh("k", 1, LONG) {
        Err(VaultError::CasMismatch { current }) => assert_eq!(current, 2),
        other => panic!("expected CasMismatch, got {other:?}"),
    }
}

#[test]
fn claiming_a_missing_entry_says_so() {
    let (_dir, mut vault, _code) = new_vault();
    assert!(matches!(
        vault.claim_refresh("nope", 0, LONG),
        Err(VaultError::EntryNotFound)
    ));
}

// ---- the fence: writing while a claim is active ----

#[test]
fn a_write_with_the_holders_token_succeeds_and_releases_the_claim() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");

    let v = vault
        .upsert_cas(entry("k", "refreshed"), 1, Some(&token))
        .expect("the holder may write");
    assert_eq!(v, 2);
    assert!(
        vault.active_claim("k").is_none(),
        "a completed write ends the refresh the claim was held for"
    );
    assert!(vault.entry("k").unwrap().refresh_claim.is_none());
}

#[test]
fn a_write_without_a_token_is_refused_while_a_claim_is_active() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let _token = vault.claim_refresh("k", 1, LONG).expect("claims");

    match vault.upsert_cas(entry("k", "sneaky"), 1, None) {
        Err(VaultError::ClaimRequired { .. }) => {}
        other => panic!("expected ClaimRequired, got {other:?}"),
    }
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"v");
}

/// The exact hole the token exists to close (DR-0034 §4): A claims and stalls,
/// A's claim lapses, B takes over, then A wakes up and writes. Nothing has
/// written in the meantime, so A's version check *passes* — only the token
/// stops it.
#[test]
fn a_revived_caller_whose_claim_lapsed_cannot_write_over_the_new_holder() {
    let (_dir, mut vault, _code) = new_vault();
    vault
        .upsert_cas(entry("k", "v1"), 0, None)
        .expect("creates");

    // A claims, then stalls long enough to lapse.
    let token_a = vault.claim_refresh("k", 1, LAPSED).expect("A claims");
    // B takes over the lapsed claim and starts its own refresh.
    let token_b = vault.claim_refresh("k", 1, LONG).expect("B takes over");

    // A wakes up. The version is still 1 — nobody has written — so a
    // version-only check would let A through.
    assert_eq!(vault.entry("k").unwrap().cas_version, 1);
    match vault.upsert_cas(entry("k", "stale-from-A"), 1, Some(&token_a)) {
        Err(VaultError::ClaimTokenMismatch) => {}
        other => panic!("expected ClaimTokenMismatch, got {other:?}"),
    }
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"v1");

    // B, the actual holder, completes normally.
    vault
        .upsert_cas(entry("k", "fresh-from-B"), 1, Some(&token_b))
        .expect("B writes");
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"fresh-from-B");
}

#[test]
fn a_write_after_the_claim_lapsed_with_nobody_taking_over_is_allowed() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LAPSED).expect("claims");

    // Nothing holds the entry, so there is nothing to protect it from: the
    // late write is the only write.
    vault
        .upsert_cas(entry("k", "late"), 1, Some(&token))
        .expect("allowed");
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"late");
}

#[test]
fn an_unrelated_token_never_helps() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let _held = vault.claim_refresh("k", 1, LONG).expect("claims");

    let stranger = {
        let (_d, mut other, _c) = new_vault();
        other.upsert_cas(entry("k", "v"), 0, None).expect("creates");
        other.claim_refresh("k", 1, LONG).expect("claims")
    };
    assert!(matches!(
        vault.upsert_cas(entry("k", "x"), 1, Some(&stranger)),
        Err(VaultError::ClaimTokenMismatch)
    ));
}

// ---- releasing ----

#[test]
fn releasing_frees_the_entry_for_the_next_caller() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");

    vault.release_claim("k", &token).expect("releases");
    assert!(vault.active_claim("k").is_none());
    // The next caller can start immediately rather than waiting out the expiry.
    vault.claim_refresh("k", 1, LONG).expect("re-claims");
}

#[test]
fn releasing_does_not_advance_the_version_or_change_the_value() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");
    vault.release_claim("k", &token).expect("releases");

    let e = vault.entry("k").unwrap();
    assert_eq!(e.cas_version, 1);
    assert_eq!(e.secret.as_slice(), b"v");
}

#[test]
fn a_stale_holder_cannot_cancel_the_claim_that_replaced_it() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token_a = vault.claim_refresh("k", 1, LAPSED).expect("A claims");
    let token_b = vault.claim_refresh("k", 1, LONG).expect("B takes over");

    assert!(matches!(
        vault.release_claim("k", &token_a),
        Err(VaultError::ClaimTokenMismatch)
    ));
    assert!(
        vault.active_claim("k").unwrap().token.matches(&token_b),
        "B still holds it"
    );
}

/// A caller that crashed after releasing and retries the release must not be
/// punished for it.
#[test]
fn releasing_an_unclaimed_entry_is_a_no_op() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");
    vault.release_claim("k", &token).expect("releases");
    vault
        .release_claim("k", &token)
        .expect("releasing again is fine");
}

#[test]
fn releasing_a_missing_entry_says_so() {
    let (_dir, mut vault, _code) = new_vault();
    // Any well-formed token will do: the entry is missing, so the lookup fails
    // before the token is ever consulted.
    let some_token = ClaimToken::parse(&"A".repeat(22)).expect("well-formed");
    assert!(matches!(
        vault.release_claim("nope", &some_token),
        Err(VaultError::EntryNotFound)
    ));
}

// ---- durability ----

/// A claim must survive the restart it most needs to survive: an upgrade in the
/// middle of a refresh. If it vanished, both the pre-restart caller and a fresh
/// one would call the provider (DR-0034 §4).
#[test]
fn a_claim_survives_lock_and_unlock() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut vault = reopen(&path, &code);
    assert!(
        vault.active_claim("k").is_some(),
        "the claim must outlive the process that took it"
    );
    // A fresh caller is still locked out…
    assert!(matches!(
        vault.claim_refresh("k", 1, LONG),
        Err(VaultError::AlreadyClaimed { .. })
    ));
    // …and the original holder's token still works across the restart.
    vault
        .upsert_cas(entry("k", "refreshed"), 1, Some(&token))
        .expect("the holder completes after the restart");
}

/// A vault written before claims existed has no `refresh_claim` field at all.
/// It must still open — the field was added without a format version bump, so
/// nothing else protects this.
#[test]
fn an_entry_written_without_a_claim_field_reads_back_unclaimed() {
    let (_dir, mut vault, code) = new_vault();
    vault.upsert(entry("k", "v"), None).expect("commits");
    let path = vault.path().to_path_buf();
    drop(vault);

    let vault = reopen(&path, &code);
    assert!(vault.entry("k").unwrap().refresh_claim.is_none());
    assert!(vault.active_claim("k").is_none());
}

// ---- the fence applies to the unconditional write too ----

/// The asymmetry that would have reopened the hole: `upsert_cas` fenced on an
/// active claim but plain `upsert` did not, so the protection was optional by
/// choosing the other method. A plain set is the natural mapping for a caller
/// that did not ask for compare-and-swap, which makes it exactly the door a
/// refresh in flight would be walked through.
#[test]
fn an_unconditional_upsert_is_fenced_by_an_active_claim() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let token = vault.claim_refresh("k", 1, LONG).expect("claims");

    match vault.upsert(entry("k", "sneaky"), None) {
        Err(VaultError::ClaimRequired { .. }) => {}
        other => panic!("expected ClaimRequired, got {other:?}"),
    }
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"v");
    assert_eq!(
        vault.entry("k").unwrap().cas_version,
        1,
        "no write happened"
    );

    // A stranger's token is refused just as it is on the CAS path.
    let stranger = {
        let (_d, mut other, _c) = new_vault();
        other.upsert_cas(entry("k", "v"), 0, None).expect("creates");
        other.claim_refresh("k", 1, LONG).expect("claims")
    };
    assert!(matches!(
        vault.upsert(entry("k", "x"), Some(&stranger)),
        Err(VaultError::ClaimTokenMismatch)
    ));

    // The holder's token lets it through, and completing releases the claim.
    let v = vault
        .upsert(entry("k", "refreshed"), Some(&token))
        .expect("the holder may write");
    assert_eq!(v, 2);
    assert!(vault.active_claim("k").is_none());
}

#[test]
fn an_unconditional_upsert_is_unaffected_by_a_lapsed_claim() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    vault.claim_refresh("k", 1, LAPSED).expect("claims");

    // Nobody holds the entry, so there is nothing to fence against.
    vault.upsert(entry("k", "late"), None).expect("allowed");
    assert_eq!(vault.entry("k").unwrap().secret.as_slice(), b"late");
}

#[test]
fn an_unconditional_upsert_on_an_unclaimed_entry_still_advances_the_version() {
    let (_dir, mut vault, _code) = new_vault();
    assert_eq!(vault.upsert(entry("k", "a"), None).expect("creates"), 1);
    assert_eq!(vault.upsert(entry("k", "b"), None).expect("updates"), 2);
}

// ---- graceful-restart data key (DR-0034 §11) ----

/// The successor of a graceful restart inherits the data key and comes up
/// already open, so an upgrade does not cost the user an unlock.
#[test]
fn a_handed_off_data_key_opens_the_vault_without_a_credential() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let path = vault.path().to_path_buf();
    let dek = vault.export_dek();
    drop(vault);

    let reopened = LockedVault::open(&path)
        .expect("opens")
        .unlock_with_dek(&dek)
        .expect("the inherited key opens it");
    assert_eq!(reopened.entry("k").unwrap().secret.as_slice(), b"v");
    assert_eq!(reopened.dek_generation(), 1);
}

/// A key that does not match must not open the vault: a mangled handoff has to
/// degrade to "stays locked", never to "opens with garbage".
#[test]
fn a_wrong_or_malformed_data_key_does_not_open_the_vault() {
    let (_dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    let (_d2, other, _c) = new_vault();
    let foreign = other.export_dek();

    assert!(
        LockedVault::open(&path)
            .unwrap()
            .unlock_with_dek(&foreign)
            .is_err(),
        "another vault's key must not open this one"
    );
    for wrong_len in [0usize, 16, 31, 33, 64] {
        assert!(
            LockedVault::open(&path)
                .unwrap()
                .unlock_with_dek(&vec![0u8; wrong_len])
                .is_err(),
            "a {wrong_len}-byte key must be refused"
        );
    }
}

/// Rotating the key invalidates a copy taken before the rotation — the
/// inherited key is not a way around revocation.
#[test]
fn a_data_key_captured_before_a_rotation_no_longer_opens_the_vault() {
    let (_dir, mut vault, _code) = new_vault();
    vault.upsert_cas(entry("k", "v"), 0, None).expect("creates");
    let stale = vault.export_dek();
    vault.rotate_dek().expect("rotates");
    let path = vault.path().to_path_buf();
    drop(vault);

    assert!(
        LockedVault::open(&path)
            .unwrap()
            .unlock_with_dek(&stale)
            .is_err()
    );
}
