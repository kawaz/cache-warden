//! cache-warden's encrypted persistent vault (DR-0034).
//!
//! cache-warden's founding assumption is that secrets never reach the disk:
//! values live in mlock-pinned memory, are zeroized on drop, and survive a
//! restart only through the DR-0029 same-process handoff. OAuth refresh tokens
//! break that assumption. They rotate, so the newest one exists *only* inside
//! cache-warden — losing it to a crash or an upgrade does not degrade to a
//! slower cold start, it degrades to the user re-authenticating by hand. That
//! makes persistence necessary, and persistence without encryption
//! unacceptable. This crate is the encryption.
//!
//! # The shape of it
//!
//! A vault is one file: a plaintext header listing **slots**, and one
//! AEAD-sealed body holding every entry.
//!
//! Each slot is an X25519 recipient — an age-style construction. The body is
//! encrypted once under a data encryption key (DEK), and the DEK is wrapped
//! separately to each slot's public key. A slot's private key is in turn
//! encrypted under a key derived from whatever credential opens that slot: a
//! passkey PRF output, or a recovery code.
//!
//! That indirection buys the property the whole design rests on: **changing
//! who can open the vault needs public keys only**. Adding a recipient, or
//! removing one and rotating the DEK so the removal actually revokes
//! something, never requires the other slots' credentials. Removing a lost
//! laptop does not mean gathering every remaining device to re-encrypt.
//!
//! # Getting in and out
//!
//! ```no_run
//! use cache_warden_vault::{
//!     LockedVault, RECOVERY_STORAGE_GUIDANCE, UnlockedVault, VaultEntry, storage,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = storage::default_state_dir().expect("no HOME");
//! let path = storage::vault_path(&dir, storage::DEFAULT_PROFILE);
//!
//! // Initialization always mints a recovery code, and shows it once.
//! let (mut vault, code) = UnlockedVault::initialize(&path)?;
//! println!("{}\n\n{}", code.render().as_str(), RECOVERY_STORAGE_GUIDANCE);
//!
//! // Every mutation is durable before it returns.
//! vault.upsert(VaultEntry::new("llm/refresh-token", b"rt-...".to_vec()), None)?;
//! drop(vault); // wipes the DEK
//!
//! // Later, in a fresh process: the header reads without any credential…
//! let locked = LockedVault::open(&path)?;
//! println!("{} slot(s)", locked.slots().len());
//! // …the entries do not.
//! let vault = locked.unlock_with_recovery_code(&code)?;
//! assert!(vault.entry("llm/refresh-token").is_some());
//! # Ok(())
//! # }
//! ```
//!
//! # What this phase covers
//!
//! The format, the key schedule, the durable commit, and the slot operations —
//! everything that can be settled without a WebAuthn ceremony. A vault is
//! opened by its recovery code alone.
//!
//! [`SlotKind::PasskeyPrf`] is defined by the format and parsed, but no
//! passkey slot can be created yet: producing a PRF output needs the browser
//! ceremony from DR-0032/§10, which is a later phase. The key schedule it will
//! use is already here and already tested — a PRF output substitutes directly
//! for the recovery secret as HKDF input keying material.
//!
//! Likewise [`VaultEntry::cas_version`], [`VaultEntry::guard`] and
//! [`VaultEntry::owner`] are durable from the start but not yet interpreted:
//! the compare-and-swap transitions are phase 2, and binding the guard and
//! owner records to the core's types is phase 5. They are persisted now
//! because DR-0034 §1d forbids an entry's value coming back from cold start
//! without the authorization that governs it — a format that had to grow a
//! place for them later would have vaults in the field that never carried
//! them.
//!
//! # What it does not defend against
//!
//! Stated plainly, because DR-0034 §6/§7 states them plainly:
//!
//! - **An open vault.** While a vault is unlocked the DEK is in this
//!   process's memory. An attacker who can read that memory reads everything;
//!   the encryption is worth exactly nothing against them. This is the same
//!   exposure every in-memory secret in cache-warden already has.
//! - **Old copies of the file.** `rename` does not erase what it replaced, and
//!   backups keep what they captured. Rotating the DEK protects future
//!   contents, not a copy someone already took. Genuine revocation of a
//!   credential is done at the service that issued it.
//! - **Intermediate copies made during serialization.** The body's plaintext
//!   buffer is zeroized, but `serde_json` allocates its own scratch on the way
//!   there, and freed heap is not wiped. Fragments of a secret can therefore
//!   outlive a lock in memory the process has released but not returned to the
//!   OS. Closing this needs a serializer that writes only into buffers the
//!   caller controls; the buffer this crate does own is pre-sized so it never
//!   reallocates, which removes the copies that were avoidable.
//! - **Rolling the file back.** An attacker who can write to the file can
//!   restore an older version of it. They could equally decrypt that older
//!   version offline, so this grants no new disclosure; the damage is to
//!   consistency, and DR-0034 §3a's re-authentication contract is what
//!   catches it.

#![deny(missing_docs)]

mod body;
mod claim;
mod crypto;
mod error;
mod format;
mod recovery;
pub mod storage;
mod vault;

pub use body::{
    GuardRecordSlot, OwnerPrincipalSlot, VaultDefinition, VaultEntry, VaultSource, VaultValueMeta,
};
pub use claim::{Claim, ClaimToken};
pub use error::VaultError;
pub use format::{
    AeadAlg, FORMAT_VERSION, KdfAlg, MIN_SUPPORTED_VERSION, Slot, SlotId, SlotKind, VaultId,
};
pub use recovery::{RECOVERY_STORAGE_GUIDANCE, RecoveryCode};
pub use vault::{LockedVault, UnlockedVault};
