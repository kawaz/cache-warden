//! Exec-target verification (DR-0029 §3): the checks that must pass before
//! the daemon is willing to `execve` a candidate binary in place of itself.
//!
//! Every failure here means "abort the handoff, current process keeps
//! serving" (DR-0029's fail-safe requirement: verification runs *before* any
//! listener is touched, so a rejected candidate leaves nothing to clean up).

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Why a candidate exec target failed verification.
#[derive(Debug)]
pub(crate) enum VerifyError {
    /// The candidate path could not be opened.
    Open(io::Error),
    /// `fstat`/`stat` on the (candidate or its parent) failed.
    Stat(io::Error),
    /// The candidate is writable by a group or user other than its owner.
    WorldOrGroupWritable,
    /// The candidate is not owned by this process's own uid.
    NotOwnedBySelf { file_uid: u32, self_uid: u32 },
    /// The candidate's parent directory is writable by others (a sibling
    /// process could replace the file out from under a same-uid check).
    ParentOthersWritable(PathBuf),
    /// The re-open immediately before `execve` (DR-0029 §3 step 3) resolved
    /// to a different (dev, ino) than the file already verified — the
    /// narrowed TOCTOU window caught a swap. Only [`reconfirm_identity`]
    /// constructs this, and its sole caller is the macOS-only
    /// `handoff::execute`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    IdentityChangedSinceVerification,
    /// macOS codesign self-consistency check failed (see
    /// [`super::codesign`]).
    #[cfg(target_os = "macos")]
    Codesign(super::codesign::CodesignError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Open(e) => write!(f, "cannot open exec target: {e}"),
            VerifyError::Stat(e) => write!(f, "cannot stat exec target: {e}"),
            VerifyError::WorldOrGroupWritable => {
                write!(f, "exec target is writable by group or other")
            }
            VerifyError::NotOwnedBySelf { file_uid, self_uid } => write!(
                f,
                "exec target is owned by uid {file_uid}, not this process's uid {self_uid}"
            ),
            VerifyError::ParentOthersWritable(p) => write!(
                f,
                "exec target's parent directory {} is writable by others",
                p.display()
            ),
            VerifyError::IdentityChangedSinceVerification => write!(
                f,
                "exec target changed between verification and exec (TOCTOU guard tripped)"
            ),
            #[cfg(target_os = "macos")]
            VerifyError::Codesign(e) => write!(f, "codesign verification failed: {e}"),
        }
    }
}

/// A verified exec target: the still-open fd (kept open so its identity
/// cannot change again unnoticed) plus the (dev, ino) pair
/// [`reconfirm_identity`] re-checks immediately before `execve`.
pub(crate) struct VerifiedExe {
    /// Kept open for the lifetime of the handoff — never read from again,
    /// just held (hence `#[allow(dead_code)]`: nothing reads this field, its
    /// only job is to keep the fd — and the inode it names — alive) so the
    /// kernel cannot recycle the inode out from under us between
    /// verification and exec.
    #[allow(dead_code)]
    pub(crate) file: File,
    /// Read only by [`reconfirm_identity`], whose sole caller is the
    /// macOS-only `handoff::execute` (hence dead on other targets).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) dev: u64,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) ino: u64,
}

/// Verify `path` (DR-0029 §3) before it may be handed to `execve`:
///
/// 1. Open read-only, `fstat` the fd (owner = this process's uid,
///    non-world/group-writable).
/// 2. The immediate parent directory must not be others-writable (the
///    concrete protection `/Applications`-style install layouts rely on).
/// 3. macOS: codesign self-consistency ([`super::codesign`]) — a no-op on
///    other platforms.
///
/// Does **not** perform the final pre-exec re-open ([`reconfirm_identity`]):
/// that happens later, right before the `execve` call, to narrow the TOCTOU
/// window as much as possible.
pub(crate) fn verify_exec_target(path: &Path) -> Result<VerifiedExe, VerifyError> {
    let file = File::open(path).map_err(VerifyError::Open)?;
    let meta = file.metadata().map_err(VerifyError::Stat)?;

    // SAFETY: `getuid()` takes no arguments and cannot fail.
    let self_uid = unsafe { libc::getuid() };
    if meta.uid() != self_uid {
        return Err(VerifyError::NotOwnedBySelf {
            file_uid: meta.uid(),
            self_uid,
        });
    }
    // S_IWGRP (0o020) | S_IWOTH (0o002): writable by anyone but the owner.
    if meta.mode() & 0o022 != 0 {
        return Err(VerifyError::WorldOrGroupWritable);
    }

    if let Some(parent) = path.parent() {
        let pmeta = std::fs::metadata(parent).map_err(VerifyError::Stat)?;
        // S_IWOTH only for the parent: a group-writable parent owned by a
        // trusted group (e.g. `admin`) is a normal install layout; the
        // concrete attack this closes is "any local user can replace the
        // file", which is the others-writable bit.
        if pmeta.mode() & 0o002 != 0 {
            return Err(VerifyError::ParentOthersWritable(parent.to_path_buf()));
        }
    }

    // DR-0029 §3's full requirement also asks for the parent *chain* up to
    // root, not just the immediate parent above — but only as a warning
    // (fail-open), since only the immediate parent lets an attacker replace
    // the candidate file directly; this walk is belt-and-suspenders.
    warn_on_writable_ancestor_chain(path);

    #[cfg(target_os = "macos")]
    super::codesign::verify_self_consistency(path).map_err(VerifyError::Codesign)?;

    let dev = meta.dev();
    let ino = meta.ino();
    Ok(VerifiedExe { file, dev, ino })
}

/// DR-0029 §3 (full requirement): warn — never abort — if any ancestor
/// directory *above* the immediate parent (which [`verify_exec_target`]
/// already fail-closed-rejects on its own, see [`VerifyError::ParentOthersWritable`])
/// is writable by others.
///
/// A world-writable directory further up the chain (e.g. a badly-permissioned
/// `/opt` or a shared mount point) does not let an attacker replace the
/// candidate file directly — that requires write access to its *immediate*
/// parent, already a fail-closed check — but a sufficiently privileged local
/// attacker could still rename/relocate an ancestor directory itself. DR-0029
/// §3 treats this as a lower-severity concern than the immediate parent
/// (worth surfacing to the operator, not worth blocking a graceful restart
/// over — "never block development" precedent, DR-0019 §2.5), so this only
/// emits a stderr warning per offending ancestor and always returns.
fn warn_on_writable_ancestor_chain(path: &Path) {
    // Start from the *grandparent*: `verify_exec_target` already fail-closed-
    // checks the immediate parent just above.
    let mut ancestor = path.parent().and_then(Path::parent);
    while let Some(dir) = ancestor {
        match std::fs::metadata(dir) {
            Ok(meta) if meta.mode() & 0o002 != 0 => {
                eprintln!(
                    "cache-warden: warning: graceful-restart exec target {} has an \
                     others-writable ancestor directory {} — a local attacker able to \
                     rename/relocate that directory could still tamper with the install \
                     layout (DR-0029 §3); continuing (the immediate parent directory is \
                     the fail-closed boundary, checked separately)",
                    path.display(),
                    dir.display()
                );
            }
            Ok(_) => {}
            Err(_) => {
                // Cannot stat further up (permission denied, a race, or an
                // oddly unreadable mount point) — nothing more to check.
                break;
            }
        }
        ancestor = dir.parent();
    }
}

/// DR-0029 §3 step 3: immediately before `execve`, re-open `path` and confirm
/// its (dev, ino) still matches `expected` (the file [`verify_exec_target`]
/// already validated). Narrows the TOCTOU window to the handful of
/// instructions between this call and the `execve` syscall — macOS has
/// neither `fexecve` nor `execveat(AT_EMPTY_PATH)` to close it completely
/// (see the research doc's §4.1 vs. macOS gap; this is the "縮小 (narrow)"
/// mitigation DR-0029 §3 settles for, not full closure).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn reconfirm_identity(path: &Path, expected: &VerifiedExe) -> Result<(), VerifyError> {
    let meta = std::fs::metadata(path).map_err(VerifyError::Stat)?;
    if meta.dev() != expected.dev || meta.ino() != expected.ino {
        return Err(VerifyError::IdentityChangedSinceVerification);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn verify_exec_target_accepts_a_normal_owned_non_writable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        // The dev build running this test is unsigned, so the macOS codesign
        // branch takes its documented fail-open dev path (owner+perms only,
        // a warning, and success) rather than rejecting — see
        // `codesign::verify_self_consistency`'s doc.
        let verified = verify_exec_target(&path).expect("should verify");
        assert!(verified.ino > 0);
    }

    #[test]
    fn verify_exec_target_rejects_world_writable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o706)).unwrap();
        assert!(matches!(
            verify_exec_target(&path),
            Err(VerifyError::WorldOrGroupWritable)
        ));
    }

    #[test]
    fn verify_exec_target_rejects_group_writable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o760)).unwrap();
        assert!(matches!(
            verify_exec_target(&path),
            Err(VerifyError::WorldOrGroupWritable)
        ));
    }

    #[test]
    fn verify_exec_target_rejects_others_writable_parent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            verify_exec_target(&path),
            Err(VerifyError::ParentOthersWritable(_))
        ));
    }

    #[test]
    fn verify_exec_target_rejects_missing_file() {
        assert!(matches!(
            verify_exec_target(Path::new("/no/such/cache-warden-verify-test-binary")),
            Err(VerifyError::Open(_))
        ));
    }

    #[test]
    fn reconfirm_identity_accepts_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let verified = verify_exec_target(&path).unwrap();
        assert!(reconfirm_identity(&path, &verified).is_ok());
    }

    #[test]
    fn reconfirm_identity_rejects_a_swapped_file() {
        // Simulate the TOCTOU attack this guards against: the path is
        // replaced (unlink + recreate, a different inode) between
        // verification and the pre-exec re-check.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"original").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let verified = verify_exec_target(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"swapped").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            reconfirm_identity(&path, &verified),
            Err(VerifyError::IdentityChangedSinceVerification)
        ));
    }
}
