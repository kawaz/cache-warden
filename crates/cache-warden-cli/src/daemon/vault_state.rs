//! The daemon's view of the encrypted vault (DR-0034 §5/§6/§7).
//!
//! # Three states, one of which is not a failure
//!
//! [`VaultState`] is deliberately a three-way enum rather than an
//! `Option<UnlockedVault>`. "No vault has been created yet" and "a vault
//! exists but is closed" call for different answers — `cw vault init` versus
//! `cw vault unlock` — and collapsing them into one absent case would leave
//! the daemon telling a user to run the wrong command.
//!
//! # Locked is a working state, not an outage
//!
//! DR-0034 §6 rejects unlocking on first access: a daemon that prompted
//! whenever a key was read would either hang an unattended start, storm the
//! user with prompts, or busy-retry. So the daemon starts locked and *stays*
//! locked until told otherwise, and runs degraded in the meantime — persisted
//! entries are listed, their declarations are visible, and only reading their
//! values fails, with [`VaultLocked`](crate::protocol::wire::ErrorKind::VaultLocked)
//! rather than an authorization error.
//!
//! # What is knowable while locked
//!
//! Entry *names* live in the sealed body (DR-0034 §7 draws the line there
//! deliberately: a reader of the file learns which credential opens the vault,
//! never what is inside). So while locked the daemon cannot enumerate the
//! vault's contents at all.
//!
//! The names it reports instead come from the **configuration** — the
//! `[kv.NAME] persist = true` declarations, which are plaintext on disk
//! already. The consequence is worth stating plainly: an entry persisted at
//! runtime through `kv set --persist`, with no config declaration, is
//! invisible while the vault is closed. It reappears on unlock with its value
//! intact; it simply cannot be listed before then, because nothing outside the
//! ciphertext knows it exists.

use std::path::{Path, PathBuf};

use cache_warden_vault::{LockedVault, RecoveryCode, UnlockedVault, VaultError, VaultId, storage};

use crate::protocol::wire::{VaultStateWire, VaultStatusWire};

/// Why `vault.init` could not create a vault.
#[derive(Debug)]
pub enum VaultInitError {
    /// A vault is already present at this path. Distinguished from any other
    /// filesystem failure so the reply can say "you already have one" rather
    /// than reporting an IO error the user cannot act on.
    AlreadyExists,
    /// Creation failed for some other reason.
    Vault(VaultError),
}

impl std::fmt::Display for VaultInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultInitError::AlreadyExists => write!(
                f,
                "a vault already exists here; `vault unlock` it, or move it aside to start over \
                 (its contents cannot be recovered without its recovery code)"
            ),
            VaultInitError::Vault(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultInitError {}

/// Why `vault.unlock` could not open the vault.
///
/// Separate from [`VaultError`] because "there is nothing here to open" is not
/// a cryptographic outcome, and the two want opposite handling: a failed
/// unlock must say as little as possible (a prober learns nothing from a wrong
/// code), while a missing vault should say exactly what to run.
#[derive(Debug)]
pub enum VaultUnlockError {
    /// No vault exists at this path yet. `vault init` creates one.
    NotInitialized,
    /// The vault is there but did not open: the code did not match a slot, or
    /// the file could not be read.
    Vault(VaultError),
}

impl std::fmt::Display for VaultUnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultUnlockError::NotInitialized => {
                write!(f, "no vault has been created yet; run `vault init`")
            }
            VaultUnlockError::Vault(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultUnlockError {}

/// Where the daemon's vault lives and what state it is in.
pub enum VaultState {
    /// Configured for, but not created. Every operation that needs the vault
    /// reports this so the user is pointed at `cw vault init` specifically.
    NotInitialized {
        /// Where `vault.init` will create it.
        path: PathBuf,
    },
    /// On disk, closed. The header is readable (which is what `status`
    /// reports); the entries are not.
    Locked {
        /// The parsed vault file.
        vault: Box<LockedVault>,
    },
    /// Open. Entries are readable and writes go through to disk.
    Unlocked {
        /// The open vault.
        vault: Box<UnlockedVault>,
    },
}

impl VaultState {
    /// Read whatever is at `path` and classify it.
    ///
    /// A missing file is [`VaultState::NotInitialized`], not an error: a
    /// daemon whose user has not run `vault init` yet must still start.
    /// A file that is present but unreadable *is* an error — refusing to start
    /// beats starting with a vault the user believes is protecting something.
    pub fn open_at(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        match LockedVault::open(&path) {
            Ok(vault) => Ok(VaultState::Locked {
                vault: Box::new(vault),
            }),
            Err(VaultError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok(VaultState::NotInitialized { path })
            }
            Err(e) => Err(e),
        }
    }

    /// Where this vault does (or will) live.
    pub fn path(&self) -> &Path {
        match self {
            VaultState::NotInitialized { path } => path,
            VaultState::Locked { vault } => vault.path(),
            VaultState::Unlocked { vault } => vault.path(),
        }
    }

    /// Whether persisted values are currently readable.
    pub fn is_unlocked(&self) -> bool {
        matches!(self, VaultState::Unlocked { .. })
    }

    /// The open vault, or `None` in either closed state.
    pub fn unlocked(&self) -> Option<&UnlockedVault> {
        match self {
            VaultState::Unlocked { vault } => Some(vault),
            _ => None,
        }
    }

    /// The open vault, mutably.
    pub fn unlocked_mut(&mut self) -> Option<&mut UnlockedVault> {
        match self {
            VaultState::Unlocked { vault } => Some(vault),
            _ => None,
        }
    }

    /// Whether any slot was registered against a development-only WebAuthn RP
    /// (DR-0034 §7).
    ///
    /// Readable in both on-disk states because it comes from the plaintext
    /// header — which is the point: the warning has to be available at startup,
    /// before anyone has unlocked anything.
    pub fn has_dev_rp_slot(&self) -> bool {
        match self {
            VaultState::NotInitialized { .. } => false,
            VaultState::Locked { vault } => vault.has_dev_rp_slot(),
            VaultState::Unlocked { vault } => vault.has_dev_rp_slot(),
        }
    }

    /// Create the vault, returning its recovery code (DR-0034 §9).
    ///
    /// Leaves the vault **open**: the caller just proved possession of the
    /// recovery code by generating it, and making them immediately unlock with
    /// the string still on their screen would be ceremony for its own sake.
    pub fn init(&mut self) -> Result<(VaultId, RecoveryCode), VaultInitError> {
        let path = match self {
            VaultState::NotInitialized { path } => path.clone(),
            // Refusing here rather than letting `UnlockedVault::initialize`
            // discover it lets the caller distinguish "already there" from any
            // other filesystem failure without matching on an io error kind.
            _ => return Err(VaultInitError::AlreadyExists),
        };
        let (vault, code) = UnlockedVault::initialize(&path).map_err(VaultInitError::Vault)?;
        let id = vault.vault_id();
        *self = VaultState::Unlocked {
            vault: Box::new(vault),
        };
        Ok((id, code))
    }

    /// Open the vault with a recovery code.
    ///
    /// Unlocking an already-open vault is a no-op rather than an error: the
    /// caller asked for a state the vault is already in.
    pub fn unlock(&mut self, code: &RecoveryCode) -> Result<(), VaultUnlockError> {
        let path = match self {
            VaultState::Unlocked { .. } => return Ok(()),
            VaultState::NotInitialized { .. } => return Err(VaultUnlockError::NotInitialized),
            VaultState::Locked { vault } => vault.path().to_path_buf(),
        };
        // Re-open from disk rather than consuming the held `LockedVault`: on a
        // failed unlock this state must stay exactly as it was, and moving out
        // of `self` to try would leave nothing to put back.
        let locked = LockedVault::open(&path).map_err(VaultUnlockError::Vault)?;
        let vault = locked
            .unlock_with_recovery_code(code)
            .map_err(VaultUnlockError::Vault)?;
        *self = VaultState::Unlocked {
            vault: Box::new(vault),
        };
        Ok(())
    }

    /// Open the vault with a passkey's PRF output (DR-0034 §2).
    ///
    /// The same shape as [`VaultState::unlock`] and for the same reasons: the
    /// file is re-read rather than the held handle consumed, so a ceremony
    /// that produces the wrong key material leaves this state exactly as it
    /// was.
    pub fn unlock_with_prf_output(&mut self, prf_output: &[u8]) -> Result<(), VaultUnlockError> {
        let path = match self {
            VaultState::Unlocked { .. } => return Ok(()),
            VaultState::NotInitialized { .. } => return Err(VaultUnlockError::NotInitialized),
            VaultState::Locked { vault } => vault.path().to_path_buf(),
        };
        let locked = LockedVault::open(&path).map_err(VaultUnlockError::Vault)?;
        let vault = locked
            .unlock_with_prf_output(prf_output)
            .map_err(VaultUnlockError::Vault)?;
        *self = VaultState::Unlocked {
            vault: Box::new(vault),
        };
        Ok(())
    }

    /// Close the vault, wiping the data key.
    ///
    /// A no-op when it is not open, so `cw vault lock` is safe to run blindly.
    pub fn lock(&mut self) -> Result<(), VaultError> {
        if let VaultState::Unlocked { .. } = self {
            let path = self.path().to_path_buf();
            // Replacing the value drops the `UnlockedVault`, which zeroizes the
            // data key (DR-0034 §6).
            *self = VaultState::open_at(path)?;
        }
        Ok(())
    }

    /// The value-free state for `status` (DR-0034 §6).
    pub fn status_wire(&self) -> VaultStatusWire {
        match self {
            VaultState::NotInitialized { .. } => VaultStatusWire {
                state: VaultStateWire::NotInitialized,
                vault_id: None,
                slots: None,
                dek_generation: None,
                dev_rp_slot: false,
            },
            VaultState::Locked { vault } => VaultStatusWire {
                state: VaultStateWire::Locked,
                vault_id: Some(vault.vault_id().to_string()),
                slots: Some(vault.slots().len()),
                dek_generation: Some(vault.dek_generation()),
                dev_rp_slot: vault.has_dev_rp_slot(),
            },
            VaultState::Unlocked { vault } => VaultStatusWire {
                state: VaultStateWire::Unlocked,
                vault_id: Some(vault.vault_id().to_string()),
                slots: Some(vault.slots().len()),
                dek_generation: Some(vault.dek_generation()),
                dev_rp_slot: vault.has_dev_rp_slot(),
            },
        }
    }
}

/// Resolve the vault path from the `[vault]` configuration.
///
/// An explicit `path` wins; otherwise the profile names a file in the standard
/// state directory. Distinct profiles are distinct files, which is how a
/// development vault is kept out of the production one (DR-0034 §7).
pub fn resolve_path(path: Option<&str>, profile: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = path {
        return Some(PathBuf::from(p));
    }
    let dir = storage::default_state_dir()?;
    Some(storage::vault_path(
        dir,
        profile.unwrap_or(storage::DEFAULT_PROFILE),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_not_initialized_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-default.cwv");
        let state = VaultState::open_at(&path).expect("a missing vault must not fail startup");
        assert!(matches!(state, VaultState::NotInitialized { .. }));
        assert_eq!(state.path(), path);
        assert!(!state.is_unlocked());
        assert_eq!(state.status_wire().state, VaultStateWire::NotInitialized);
    }

    /// A file that exists but does not parse must stop the daemon. Starting
    /// anyway would present a working daemon to a user who believes their
    /// credentials are being protected by something that is not readable.
    #[test]
    fn a_corrupt_file_is_an_error_not_a_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-default.cwv");
        std::fs::write(&path, b"not a vault").unwrap();
        assert!(VaultState::open_at(&path).is_err());
    }

    #[test]
    fn init_leaves_the_vault_open_and_reports_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
        let (id, _code) = state.init().expect("initializes");
        assert!(state.is_unlocked());
        let w = state.status_wire();
        assert_eq!(w.state, VaultStateWire::Unlocked);
        assert_eq!(w.vault_id.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(w.slots, Some(1), "the mandatory recovery slot");
        assert_eq!(w.dek_generation, Some(1));
        assert!(!w.dev_rp_slot);
    }

    #[test]
    fn init_refuses_when_a_vault_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
        state.init().expect("initializes");
        assert!(state.init().is_err(), "must not replace a live vault");
    }

    #[test]
    fn lock_then_unlock_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.cwv");
        let mut state = VaultState::open_at(&path).unwrap();
        let (_id, code) = state.init().expect("initializes");

        state.lock().expect("locks");
        assert!(!state.is_unlocked());
        assert_eq!(state.status_wire().state, VaultStateWire::Locked);

        state.unlock(&code).expect("unlocks");
        assert!(state.is_unlocked());
    }

    /// A failed unlock must leave the state exactly as it was, so a mistyped
    /// code costs a retry and nothing else.
    #[test]
    fn a_failed_unlock_leaves_the_vault_locked_and_usable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.cwv");
        let mut state = VaultState::open_at(&path).unwrap();
        let (_id, code) = state.init().expect("initializes");
        state.lock().expect("locks");

        let (_d2, other) = {
            let d2 = tempfile::tempdir().unwrap();
            let mut s2 = VaultState::open_at(d2.path().join("o.cwv")).unwrap();
            let (_i, c) = s2.init().unwrap();
            (d2, c)
        };
        assert!(state.unlock(&other).is_err(), "wrong code must fail");
        assert_eq!(state.status_wire().state, VaultStateWire::Locked);
        // Still openable with the right one.
        state.unlock(&code).expect("the real code still works");
    }

    #[test]
    fn locking_twice_and_unlocking_twice_are_both_no_ops() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
        let (_id, code) = state.init().expect("initializes");
        state.unlock(&code).expect("already open: no-op");
        state.lock().expect("locks");
        state.lock().expect("already closed: no-op");
    }

    /// "Nothing to open" and "that code is wrong" call for different replies,
    /// so they must not arrive as the same error.
    #[test]
    fn unlocking_a_vault_that_does_not_exist_says_so_rather_than_blaming_the_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
        let (_d2, code) = {
            let d2 = tempfile::tempdir().unwrap();
            let mut s2 = VaultState::open_at(d2.path().join("o.cwv")).unwrap();
            let (_i, c) = s2.init().unwrap();
            (d2, c)
        };
        assert!(matches!(
            state.unlock(&code),
            Err(VaultUnlockError::NotInitialized)
        ));
    }

    #[test]
    fn unlocking_a_vault_that_does_not_exist_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
        let (_d2, code) = {
            let d2 = tempfile::tempdir().unwrap();
            let mut s2 = VaultState::open_at(d2.path().join("o.cwv")).unwrap();
            let (_i, c) = s2.init().unwrap();
            (d2, c)
        };
        assert!(state.unlock(&code).is_err());
    }

    #[test]
    fn an_explicit_path_wins_over_the_profile() {
        assert_eq!(
            resolve_path(Some("/tmp/x.cwv"), Some("dev")),
            Some(PathBuf::from("/tmp/x.cwv"))
        );
    }

    #[test]
    fn distinct_profiles_resolve_to_distinct_files() {
        let a = resolve_path(None, Some("default"));
        let b = resolve_path(None, Some("dev"));
        if let (Some(a), Some(b)) = (a, b) {
            assert_ne!(a, b, "dev and production vaults must not share a file");
        }
    }
}
