//! Where the vault lives and how it is replaced (DR-0034 §3 / §7).
//!
//! # Durability
//!
//! [`commit`] performs the write-then-rename sequence DR-0034 §3 specifies:
//! write the full new file to a temporary name in the same directory,
//! `fsync` it, `rename` over the vault, then `fsync` the **directory** so the
//! rename itself is durable. `rename(2)` within one filesystem is atomic, so a
//! crash at any point leaves either the complete old file or the complete new
//! one — never a half-written vault.
//!
//! The directory `fsync` is the step that is easy to omit and expensive to
//! omit: without it the rename can still be in the filesystem's log when power
//! is lost, and the vault reverts to its previous contents while the caller
//! has already been told the write succeeded. That is precisely the failure
//! DR-0034 §3 forbids ("the set ack is returned after fsync completes"), so
//! `commit` returns only once both syncs have.
//!
//! # Placement and permissions
//!
//! `$XDG_STATE_HOME/cache-warden/` (falling back to `~/.local/state/`), with
//! the directory at `0700` and the file at `0600`. Permissions are not the
//! security boundary — the file's contents are encrypted, and DR-0034 §7 puts
//! at-rest theft in scope for the cryptography, not for the mode bits — but
//! there is no reason to hand a local attacker the header metadata (which
//! passkey opens this vault) for free.
//!
//! Development and production vaults are separate files (DR-0034 §7). The
//! profile in the file name is what separates them on disk; the `vault_id` in
//! the header is what proves which vault a given file actually is, so a dev
//! vault copied over the production path is detectable rather than merely
//! unlikely.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::crypto::fill_random;
use crate::error::VaultError;
use crate::format::MAX_FILE_LEN;

/// Mode for the vault file.
pub(crate) const FILE_MODE: u32 = 0o600;

/// Mode for the directory holding vaults.
pub(crate) const DIR_MODE: u32 = 0o700;

/// The profile name used when a caller does not choose one.
pub const DEFAULT_PROFILE: &str = "default";

/// The directory vaults live in: `$XDG_STATE_HOME/cache-warden`, or
/// `$HOME/.local/state/cache-warden` when `XDG_STATE_HOME` is unset or
/// relative.
///
/// Returns `None` only when neither `XDG_STATE_HOME` nor `HOME` yields an
/// absolute path — a caller in that situation must be told to name a path
/// explicitly rather than have one guessed for it.
pub fn default_state_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("cache-warden"));
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(".local/state/cache-warden"))
}

/// The vault file for `profile` inside `dir`.
///
/// Distinct profiles are distinct files, which is how a development vault is
/// kept out of the production one (DR-0034 §7).
pub fn vault_path(dir: impl AsRef<Path>, profile: &str) -> PathBuf {
    dir.as_ref().join(format!("vault-{profile}.cwv"))
}

/// Create the vault's parent directory at [`DIR_MODE`] if it is missing, and
/// tighten it if it exists with group or world bits set.
///
/// Tightening an existing directory rather than merely warning is deliberate:
/// the directory is cache-warden's own state directory, and a caller who has
/// asked to write a vault into it has already decided it is cache-warden's to
/// manage.
fn ensure_dir(dir: &Path) -> Result<(), VaultError> {
    match fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
                    .map_err(|e| VaultError::io(dir, e))?;
            }
            Ok(())
        }
        Ok(_) => Err(VaultError::io(
            dir,
            std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "vault directory path exists but is not a directory",
            ),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| VaultError::io(dir, e))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
                .map_err(|e| VaultError::io(dir, e))
        }
        Err(e) => Err(VaultError::io(dir, e)),
    }
}

/// A temporary path beside `path`, distinct on every call.
///
/// The random suffix means two concurrent commits cannot pick the same
/// temporary name and clobber each other's in-progress write; the leading dot
/// keeps it out of casual directory listings.
fn temp_path(path: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    fill_random(&mut suffix);
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_string());
    path.with_file_name(format!(".{name}.tmp-{hex}"))
}

/// Atomically replace the file at `path` with `contents` (DR-0034 §3).
///
/// Returns once the new contents **and** the rename are durable. A failure at
/// any step removes the temporary file, so a failed commit leaves the previous
/// vault untouched and no debris behind.
pub(crate) fn commit(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(dir)?;

    let tmp = temp_path(path);
    let result = write_and_sync(&tmp, contents).and_then(|()| {
        fs::rename(&tmp, path).map_err(|e| VaultError::io(path, e))?;
        // The rename is not durable until the directory entry is.
        let dir_handle = File::open(dir).map_err(|e| VaultError::io(dir, e))?;
        dir_handle.sync_all().map_err(|e| VaultError::io(dir, e))
    });

    if result.is_err() {
        // Best effort: the commit already failed, and a missing temp file is
        // the desired end state either way.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Write `contents` to a freshly created file at `tmp` and `fsync` it.
///
/// `create_new` makes the create fail rather than truncate if the name somehow
/// exists, so a commit can never overwrite another commit's in-progress
/// temporary. The mode is set at open time so the file is never momentarily
/// readable by others.
fn write_and_sync(tmp: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(tmp)
        .map_err(|e| VaultError::io(tmp, e))?;
    f.write_all(contents).map_err(|e| VaultError::io(tmp, e))?;
    f.sync_all().map_err(|e| VaultError::io(tmp, e))
}

/// Create the file at `path`, failing if anything is already there.
///
/// Used to bring a vault into existence (as opposed to [`commit`], which
/// replaces one that exists). The distinction matters: `commit`'s
/// `rename` replaces whatever it lands on, so building a new vault on top of
/// it would have to be guarded by a separate existence check — and a check
/// followed by a rename is a race, in which two processes both see no vault,
/// both build one, and the second silently destroys the first along with the
/// only copy of its contents.
///
/// `create_new` closes that structurally: the file is created by the same
/// syscall that fails if it already exists (`O_CREAT | O_EXCL`, atomic in the
/// kernel), so exactly one caller can win regardless of timing. No check, no
/// window.
///
/// A new vault has an empty body, so the partial-write exposure `commit`'s
/// write-then-rename exists to prevent does not apply here: an interrupted
/// creation leaves a file that fails to parse, and the vault it might
/// otherwise have clobbered was never there.
pub(crate) fn create_new(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(dir)?;

    // The create is kept separate from everything after it, and the cleanup
    // below is reachable only once it has succeeded. If the open fails because
    // a vault is already there, this returns without the path ever being
    // touched — cleaning up on that failure would delete the very file the
    // exclusive create exists to protect.
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|e| VaultError::io(path, e))?;

    let result = f
        .write_all(contents)
        .and_then(|()| f.sync_all())
        .map_err(|e| VaultError::io(path, e))
        .and_then(|()| {
            // The new directory entry is not durable until the directory is.
            let dir_handle = File::open(dir).map_err(|e| VaultError::io(dir, e))?;
            dir_handle.sync_all().map_err(|e| VaultError::io(dir, e))
        });
    if result.is_err() {
        // This file exists only because the create above succeeded, so
        // removing it cannot destroy anyone else's vault.
        let _ = fs::remove_file(path);
    }
    result
}

/// Read a vault file whole.
///
/// The size is checked from the file's metadata first: `path` is attacker-
/// writable in the threat model where it matters, and `fs::read` would size
/// its buffer from that metadata without any bound.
pub(crate) fn read(path: &Path) -> Result<Vec<u8>, VaultError> {
    let meta = fs::metadata(path).map_err(|e| VaultError::io(path, e))?;
    if meta.len() > MAX_FILE_LEN {
        return Err(VaultError::FileTooLarge { len: meta.len() });
    }
    fs::read(path).map_err(|e| VaultError::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn commit_writes_contents_at_0600_in_a_0700_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state/cache-warden");
        let path = vault_path(&dir, DEFAULT_PROFILE);
        commit(&path, b"contents").expect("commits");
        assert_eq!(fs::read(&path).unwrap(), b"contents");
        assert_eq!(mode_of(&path), FILE_MODE);
        assert_eq!(mode_of(&dir), DIR_MODE);
    }

    #[test]
    fn commit_replaces_existing_contents_and_keeps_the_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = vault_path(tmp.path(), DEFAULT_PROFILE);
        commit(&path, b"first").expect("commits");
        commit(&path, b"second").expect("commits");
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(mode_of(&path), FILE_MODE);
    }

    /// A successful commit must leave nothing beside the vault. A lingering
    /// temporary file is a plaintext-adjacent artifact and a hint that the
    /// rename never happened.
    #[test]
    fn commit_leaves_no_temporary_file_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let path = vault_path(tmp.path(), DEFAULT_PROFILE);
        commit(&path, b"first").expect("commits");
        commit(&path, b"second").expect("commits");
        let names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("vault-{DEFAULT_PROFILE}.cwv")]);
    }

    #[test]
    fn each_commit_picks_a_distinct_temporary_name() {
        let path = Path::new("/tmp/vault-default.cwv");
        assert_ne!(temp_path(path), temp_path(path));
        assert!(
            temp_path(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".vault-default.cwv.tmp-")
        );
    }

    #[test]
    fn ensure_dir_tightens_a_group_readable_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("loose");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_dir(&dir).expect("tightens");
        assert_eq!(mode_of(&dir), DIR_MODE);
    }

    #[test]
    fn ensure_dir_rejects_a_path_that_is_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("not-a-dir");
        fs::write(&path, b"").unwrap();
        assert!(ensure_dir(&path).is_err());
    }

    #[test]
    fn vault_path_separates_profiles() {
        assert_ne!(vault_path("/state", "default"), vault_path("/state", "dev"));
        assert_eq!(
            vault_path("/state", "dev"),
            PathBuf::from("/state/vault-dev.cwv")
        );
    }
}
