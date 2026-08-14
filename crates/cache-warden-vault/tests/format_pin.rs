//! Byte-level pins on the vault header (DR-0034 §1a).
//!
//! These assertions exist to make a breaking format change *loud*. Every
//! constant here is baked into files already written to disk: change the magic
//! and no existing vault is recognized, change an algorithm id and every
//! existing vault decodes to the wrong cipher, move a field and every offset
//! after it shifts. None of that produces a compile error, and the failure at
//! runtime is "your credentials are gone".
//!
//! A change that breaks one of these tests is not necessarily wrong — it needs
//! [`cache_warden_vault::FORMAT_VERSION`] bumped and a migration decided
//! alongside it. The tests exist so that decision cannot be skipped by
//! accident.

use cache_warden_vault::{
    AeadAlg, FORMAT_VERSION, KdfAlg, LockedVault, MIN_SUPPORTED_VERSION, SlotKind, UnlockedVault,
};

mod support;
use support::new_vault;

/// Field offsets in the header, as documented in `format.rs`.
const OFF_MAGIC: usize = 0;
const OFF_FORMAT_VERSION: usize = 8;
const OFF_VAULT_ID: usize = 12;
const OFF_DEK_GENERATION: usize = 28;
const OFF_AEAD_ALG: usize = 36;
const OFF_KDF_ALG: usize = 38;
const OFF_SLOT_COUNT: usize = 40;
const OFF_FIRST_SLOT: usize = 44;

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn be64(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[test]
fn header_fields_sit_at_their_documented_offsets_with_their_documented_values() {
    let (dir, vault, _code) = new_vault();

    let bytes = std::fs::read(vault.path()).expect("the vault file exists");

    assert_eq!(&bytes[OFF_MAGIC..OFF_MAGIC + 8], b"CWVAULT\0", "magic");
    assert_eq!(be32(&bytes, OFF_FORMAT_VERSION), 1, "format_version v1");
    assert_eq!(
        be32(&bytes, OFF_FORMAT_VERSION),
        FORMAT_VERSION,
        "a new vault is written at the current format version"
    );
    assert_eq!(
        &bytes[OFF_VAULT_ID..OFF_VAULT_ID + 16],
        vault.vault_id().as_bytes(),
        "vault_id is stored verbatim"
    );
    assert_eq!(
        be64(&bytes, OFF_DEK_GENERATION),
        1,
        "a fresh vault starts at DEK generation 1"
    );
    assert_eq!(be16(&bytes, OFF_AEAD_ALG), 1, "XChaCha20-Poly1305 is id 1");
    assert_eq!(be16(&bytes, OFF_KDF_ALG), 1, "HKDF-SHA256 is id 1");
    assert_eq!(
        be32(&bytes, OFF_SLOT_COUNT),
        1,
        "initialization creates exactly the mandatory recovery slot"
    );
    // The first slot's kind follows its 16-byte id.
    assert_eq!(
        be16(&bytes, OFF_FIRST_SLOT + 16),
        2,
        "recovery slots are kind 2"
    );

    drop(dir);
}

/// Both slot kind ids are pinned at the byte level, including `passkey-prf`,
/// which phase 1 cannot yet create.
///
/// Pinning the one this build never writes is the point: phase 4 starts
/// writing kind 1, and if the reader had drifted in the meantime, every vault
/// that phase produces would be unreadable by anything already deployed. The
/// id is exercised by patching a real vault's kind byte to 1 and checking the
/// reader agrees — `open` parses the header without decrypting, so a slot this
/// build cannot use is still one it must describe correctly.
#[test]
fn slot_kind_ids_are_byte_pinned() {
    let (_dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut bytes = std::fs::read(&path).unwrap();
    let kind_at = OFF_FIRST_SLOT + 16;
    assert_eq!(be16(&bytes, kind_at), 2, "recovery is kind 2");

    bytes[kind_at..kind_at + 2].copy_from_slice(&1u16.to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let locked = LockedVault::open(&path).expect("a passkey slot parses");
    assert_eq!(
        locked.slots()[0].kind(),
        SlotKind::PasskeyPrf,
        "wire id 1 must decode as passkey-prf"
    );

    // An id belonging to neither kind is refused rather than skipped: an
    // unrecognized slot is still a recipient that can open the vault.
    bytes[kind_at..kind_at + 2].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        LockedVault::open(&path),
        Err(cache_warden_vault::VaultError::UnknownSlotKind { id: 3 })
    ));
}

#[test]
fn algorithm_enums_name_exactly_the_v1_algorithms() {
    assert_eq!(AeadAlg::XChaCha20Poly1305, AeadAlg::XChaCha20Poly1305);
    assert_eq!(KdfAlg::HkdfSha256, KdfAlg::HkdfSha256);
    let (_dir, vault, _code) = new_vault();
    let locked = vault.lock().expect("locks");
    assert_eq!(locked.aead_alg(), AeadAlg::XChaCha20Poly1305);
    assert_eq!(locked.kdf_alg(), KdfAlg::HkdfSha256);
}

#[test]
fn the_supported_version_range_is_a_single_version_in_v1() {
    assert_eq!(MIN_SUPPORTED_VERSION, 1);
    assert_eq!(FORMAT_VERSION, 1);
}

/// The header a reader sees must be byte-identical to the one the writer
/// sealed against, or the body will not open. Re-reading an untouched file and
/// finding the same bytes is the weakest form of that check, and the one that
/// catches a non-deterministic encoder.
#[test]
fn writing_the_same_state_twice_produces_identical_headers() {
    let (_dir, mut vault, _code) = new_vault();
    let first = std::fs::read(vault.path()).unwrap();
    // Rewrite without changing anything observable in the header.
    vault
        .upsert(cache_warden_vault::VaultEntry::new("k", b"v".to_vec()))
        .expect("commits");
    let second = std::fs::read(vault.path()).unwrap();

    let header_len = OFF_FIRST_SLOT + slot_len(&first);
    assert_eq!(
        first[..header_len],
        second[..header_len],
        "the header must not drift when only the body changes"
    );
    // And the body did change, or the comparison above proved nothing.
    assert_ne!(first[header_len..], second[header_len..]);
}

/// Length of the single slot in a freshly initialized vault, derived from the
/// blob length prefixes rather than hard-coded, since the wrapped blobs'
/// sizes are a property of the AEAD.
fn slot_len(bytes: &[u8]) -> usize {
    let mut at = OFF_FIRST_SLOT;
    at += 16 + 2 + 32 + 32 + 8; // id, kind, pubkey, salt, created_at
    let take_blob = |at: &mut usize| {
        let len = be32(bytes, *at) as usize;
        *at += 4 + len;
    };
    take_blob(&mut at); // wrapped_privkey
    at += 32; // dek ephemeral pub
    take_blob(&mut at); // wrapped_dek
    take_blob(&mut at); // rp_id
    take_blob(&mut at); // credential_id
    take_blob(&mut at); // label
    at - OFF_FIRST_SLOT
}

/// DR-0034 §1a's downgrade rule, at the file level: a vault written by a build
/// with a newer format must be refused outright. Reading it leniently is what
/// leads to this build rewriting it later without the guard records and owner
/// principals it could not represent.
#[test]
fn a_vault_claiming_a_newer_format_version_is_refused() {
    let (_dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[OFF_FORMAT_VERSION..OFF_FORMAT_VERSION + 4]
        .copy_from_slice(&(FORMAT_VERSION + 1).to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();

    match LockedVault::open(&path) {
        Err(cache_warden_vault::VaultError::UnsupportedVersion { got }) => {
            assert_eq!(got, FORMAT_VERSION + 1);
        }
        Err(other) => panic!("expected UnsupportedVersion, got {other}"),
        Ok(_) => panic!("a newer format version must not be readable"),
    }
}

/// The error text must tell the reader what to do about it. "Unsupported
/// version 2" alone invites the reaction that breaks the vault: run an older
/// build and let it rewrite the file.
#[test]
fn the_downgrade_error_says_to_upgrade_rather_than_rewrite() {
    let err = cache_warden_vault::VaultError::UnsupportedVersion { got: 99 };
    let msg = err.to_string();
    assert!(msg.contains("99"));
    assert!(msg.contains("upgrade"), "{msg}");
}

#[test]
fn initialize_refuses_to_overwrite_an_existing_vault() {
    let (dir, vault, _code) = new_vault();
    let path = vault.path().to_path_buf();
    drop(vault);
    assert!(
        UnlockedVault::initialize(&path).is_err(),
        "a second initialize at the same path must not clobber the first"
    );
    drop(dir);
}
