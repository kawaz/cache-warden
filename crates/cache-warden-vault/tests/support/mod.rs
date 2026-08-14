//! Shared fixture for the vault integration tests.

use cache_warden_vault::{RecoveryCode, UnlockedVault, storage};
use tempfile::TempDir;

/// A freshly initialized vault in a throwaway state directory.
///
/// The `TempDir` is returned so the caller keeps it alive — dropping it
/// deletes the vault out from under the test.
pub fn new_vault() -> (TempDir, UnlockedVault, RecoveryCode) {
    let dir = TempDir::new().expect("temp dir");
    let path = storage::vault_path(dir.path(), storage::DEFAULT_PROFILE);
    let (vault, code) = UnlockedVault::initialize(&path).expect("initializes");
    (dir, vault, code)
}
