//! macOS codesign self-consistency check (DR-0029 §3).
//!
//! Verifies that a candidate exec target carries the *same signing identity*
//! (Team Identifier + signing Identifier) as this process's own running code
//! image — the machine-checkable form of "a signed upgrade of myself, not an
//! arbitrary substitute". Judged fail-closed when this process is itself
//! signed; fail-open (owner/perms only, with a stderr warning) when this
//! process is unsigned (a local dev build) — see [`verify_self_consistency`].
//!
//! # Scope of this check (DR-0029 bundle 2 review MEDIUM-3)
//!
//! This module verifies **identity**, not **integrity**:
//! `SecCodeCopySigningInformation` reads signing *metadata* (which Team /
//! which Identifier signed the candidate) — it does not itself re-validate
//! the candidate's on-disk signature against its content the way
//! `codesign --verify` or `SecStaticCodeCheckValidity` would. A candidate
//! whose *metadata* claims the right identity but whose bytes were tampered
//! with after signing is not caught here.
//!
//! Actual tamper detection for the exec target is bounded but real: macOS
//! enforces code-signing validity **on-demand at `execve` time** for any
//! signed binary (`amfid`/the kernel's code-signing subsystem). A binary
//! whose signature does not validate against its current bytes is killed by
//! the kernel with `SIGKILL` the moment `execve` would otherwise succeed —
//! which, for this bundle, happens *after* every listener is already closed
//! and unlinked (see `handoff::execute`'s doc), so the failure mode is "this
//! process dies and the service manager cold-restarts it" (DR-0019
//! `KeepAlive=true`), not "an unverified binary silently runs in place of
//! this daemon". This module's identity check and the kernel's on-exec
//! integrity enforcement are complementary, not redundant: identity narrows
//! *which* signed binary may receive the handoff at all; the kernel
//! guarantees *that* binary's bytes match its own signature at the moment
//! it actually runs.
//!
//! # Why the extra raw FFI
//!
//! The `security-framework` / `security-framework-sys` crates expose
//! `SecCode` / `SecStaticCode` / `SecRequirement` and `check_validity`
//! (validate against a caller-*supplied* requirement string), but neither
//! exposes `SecCodeCopySigningInformation` or the `kSecCodeInfo*` dictionary
//! keys needed to read back an arbitrary code object's own Team Identifier /
//! Identifier — which is what a *dynamic* self-vs-candidate comparison needs
//! (there is no requirement string to hand `check_validity` until we already
//! know our own identity). These three items are part of Apple's stable,
//! documented Code Signing Services API (`Security.framework`, available
//! since macOS 10.6); the framework is already linked transitively via
//! `security-framework-sys`'s build script, so no new linker flags are
//! needed — only the missing symbol declarations.

use std::path::Path;

use core_foundation::base::TCFType;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::dictionary::CFDictionaryRef;
use security_framework::base::Error as SfError;
use security_framework::os::macos::code_signing::{Flags, SecCode, SecStaticCode};

/// `kSecCSSigningInformation` (`CSCommon.h`): ask
/// `SecCodeCopySigningInformation` for the signing-identity fields
/// (Team Identifier / Identifier), not just the internal/default set.
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

mod extra_ffi {
    //! The three Security.framework symbols not exposed by
    //! `security-framework-sys` (see the module doc). Declared exactly as
    //! Apple's `SecCode.h` / `CSCommon.h` headers specify.
    use core_foundation_sys::dictionary::CFDictionaryRef;
    use core_foundation_sys::string::CFStringRef;

    unsafe extern "C" {
        /// `CFDictionary` key for a code object's signing identifier
        /// (bundle id / executable identifier), as a `CFString`.
        pub(super) static kSecCodeInfoIdentifier: CFStringRef;
        /// `CFDictionary` key for a code object's Team Identifier (the
        /// Apple Developer Program Team ID), as a `CFString`, or absent for
        /// unsigned / non-Developer-ID code.
        pub(super) static kSecCodeInfoTeamIdentifier: CFStringRef;

        /// `OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code,
        /// SecCSFlags flags, CFDictionaryRef *information)`. Apple's header
        /// types `code` as `SecStaticCodeRef`, but documents that a
        /// `SecCodeRef` (e.g. from `SecCodeCopySelf`) is also accepted — so
        /// this declares it as an untyped `*mut c_void` and callers cast
        /// whichever concrete ref they hold.
        pub(super) fn SecCodeCopySigningInformation(
            code: *mut core::ffi::c_void,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32; // OSStatus
    }
}

/// Why the codesign self-consistency check failed (fail-closed path only —
/// the fail-open dev path never returns an error, see
/// [`verify_self_consistency`]'s doc).
#[derive(Debug)]
pub(crate) enum CodesignError {
    /// Could not construct a `SecStaticCode` for the candidate path.
    CandidateCodeObject(SfError),
    /// `SecCodeCopySigningInformation` failed for the candidate.
    CandidateSigningInfo { status: i32 },
    /// `SecCodeCopySigningInformation` failed for this running process
    /// (only reachable once self is known to be signed — see the doc).
    SelfSigningInfo { status: i32 },
    /// The candidate has no Team Identifier at all (self is signed, so a
    /// candidate with none cannot match).
    CandidateUnsigned,
    /// Team Identifiers differ.
    TeamIdentifierMismatch {
        self_id: String,
        candidate_id: String,
    },
    /// Signing Identifiers differ (same team, different app/target).
    IdentifierMismatch {
        self_id: String,
        candidate_id: String,
    },
}

impl std::fmt::Display for CodesignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodesignError::CandidateCodeObject(e) => {
                write!(f, "cannot open candidate as a code object: {e}")
            }
            CodesignError::CandidateSigningInfo { status } => write!(
                f,
                "cannot read candidate signing information (OSStatus {status})"
            ),
            CodesignError::SelfSigningInfo { status } => write!(
                f,
                "cannot read this process's own signing information (OSStatus {status})"
            ),
            CodesignError::CandidateUnsigned => {
                write!(f, "candidate is unsigned but this process is signed")
            }
            CodesignError::TeamIdentifierMismatch {
                self_id,
                candidate_id,
            } => write!(
                f,
                "team identifier mismatch: self={self_id:?} candidate={candidate_id:?}"
            ),
            CodesignError::IdentifierMismatch {
                self_id,
                candidate_id,
            } => write!(
                f,
                "signing identifier mismatch: self={self_id:?} candidate={candidate_id:?}"
            ),
        }
    }
}

/// This process's own (team_id, identifier), or `None` when this process is
/// unsigned (ad-hoc / local dev build — `SecCodeCopySigningInformation`
/// succeeds but carries no `kSecCodeInfoTeamIdentifier`/`kSecCodeInfoIdentifier`
/// pair we can trust as a signing identity).
fn self_signing_identity() -> Result<Option<(String, String)>, CodesignError> {
    let code = SecCode::for_self(Flags::NONE).map_err(CodesignError::CandidateCodeObject)?;
    // SAFETY: `code.as_concrete_TypeRef()` is a live, retained `SecCodeRef`
    // for the duration of this call (owned by `code`, which outlives it);
    // `SecCodeCopySigningInformation` accepts a `SecCodeRef` in addition to
    // its documented `SecStaticCodeRef` (see `extra_ffi`'s doc). On success
    // (OSStatus 0) it writes a +1-retained `CFDictionaryRef` into
    // `dict_ref`, which is wrapped under the create rule below; on failure
    // it leaves `dict_ref` untouched (still null) and nothing is released.
    let dict_ref = unsafe {
        let mut dict_ref: CFDictionaryRef = std::ptr::null();
        let status = extra_ffi::SecCodeCopySigningInformation(
            code.as_concrete_TypeRef() as *mut core::ffi::c_void,
            K_SEC_CS_SIGNING_INFORMATION,
            &mut dict_ref,
        );
        if status != 0 {
            return Err(CodesignError::SelfSigningInfo { status });
        }
        dict_ref
    };
    Ok(extract_identity(dict_ref))
}

/// The candidate binary's (team_id, identifier), or `None` if it carries no
/// Team Identifier at all (unsigned / ad-hoc).
fn candidate_signing_identity(path: &Path) -> Result<Option<(String, String)>, CodesignError> {
    let url = CFURL::from_path(path, false)
        .ok_or_else(|| CodesignError::CandidateCodeObject(SfError::from(-1)))?;
    let code =
        SecStaticCode::from_path(&url, Flags::NONE).map_err(CodesignError::CandidateCodeObject)?;
    // SAFETY: same contract as in `self_signing_identity`, for the
    // candidate's `SecStaticCodeRef`.
    let dict_ref = unsafe {
        let mut dict_ref: CFDictionaryRef = std::ptr::null();
        let status = extra_ffi::SecCodeCopySigningInformation(
            code.as_concrete_TypeRef() as *mut core::ffi::c_void,
            K_SEC_CS_SIGNING_INFORMATION,
            &mut dict_ref,
        );
        if status != 0 {
            return Err(CodesignError::CandidateSigningInfo { status });
        }
        dict_ref
    };
    Ok(extract_identity(dict_ref))
}

/// Pull `(kSecCodeInfoTeamIdentifier, kSecCodeInfoIdentifier)` out of a
/// signing-information dictionary. `None` when the Team Identifier key is
/// absent (unsigned / ad-hoc code never carries one — the Identifier alone,
/// which even ad-hoc code has, is not a trustworthy signal by itself).
fn extract_identity(dict_ref: CFDictionaryRef) -> Option<(String, String)> {
    // SAFETY: `dict_ref` is a +1-retained `CFDictionaryRef` handed to us by
    // `SecCodeCopySigningInformation` on success (see the two call sites
    // above); wrapping it under the create rule takes ownership of that
    // retain count, and it is released when `dict` drops at the end of this
    // function.
    let dict: CFDictionary<CFString, CFString> =
        unsafe { CFDictionary::wrap_under_create_rule(dict_ref) };
    // SAFETY: the static key constants are valid, process-lifetime
    // `CFStringRef`s owned by Security.framework (a "get" rule value — never
    // released by us).
    let team_key = unsafe { CFString::wrap_under_get_rule(extra_ffi::kSecCodeInfoTeamIdentifier) };
    let id_key = unsafe { CFString::wrap_under_get_rule(extra_ffi::kSecCodeInfoIdentifier) };

    let team_id = dict.find(team_key)?.to_string();
    let identifier = dict.find(id_key).map(|v| v.to_string()).unwrap_or_default();
    Some((team_id, identifier))
}

/// Verify that `candidate_path` carries the same signing identity as this
/// running process (DR-0029 §3).
///
/// - **This process is signed** (has a Team Identifier): fail-closed. The
///   candidate must exist as a valid code object, be signed, and match both
///   the Team Identifier and the signing Identifier — any other outcome is
///   an error and the handoff must abort.
/// - **This process is unsigned** (ad-hoc / local dev build — no Team
///   Identifier): fail-open. Identity comparison is not possible (there is
///   nothing to compare against), so this prints a single stderr warning and
///   returns `Ok(())` — the caller's owner/permission checks
///   ([`super::verify::verify_exec_target`]) are the only guard in this mode.
///   Mirrors DR-0019 §2.5's "never block development" precedent.
pub(crate) fn verify_self_consistency(candidate_path: &Path) -> Result<(), CodesignError> {
    verify_against(self_signing_identity()?, candidate_path)
}

/// The injectable core of [`verify_self_consistency`] (DR-0029 bundle 2
/// review MEDIUM-3): takes `self_identity` as a plain parameter instead of
/// calling [`self_signing_identity`] itself, so tests can exercise the
/// fail-closed comparison logic against a real candidate on disk with a
/// **fake** signed "self" — without needing the test binary itself to carry
/// a real Team Identifier (which `cargo test` builds never do; see the
/// `self_signing_identity_does_not_error_on_an_unsigned_test_binary` test's
/// doc). [`verify_self_consistency`] is the only real caller, always passing
/// the true `self_signing_identity()?` result.
fn verify_against(
    self_identity: Option<(String, String)>,
    candidate_path: &Path,
) -> Result<(), CodesignError> {
    let Some((self_team, self_id)) = self_identity else {
        eprintln!(
            "cache-warden: warning: this process is not code-signed; skipping the codesign \
             self-consistency check for graceful restart (owner/permission checks still apply). \
             A signed (Developer ID / notarized) build enforces a strict identity match here."
        );
        return Ok(());
    };

    let candidate = candidate_signing_identity(candidate_path)?;
    let Some((candidate_team, candidate_id)) = candidate else {
        return Err(CodesignError::CandidateUnsigned);
    };

    if self_team != candidate_team {
        return Err(CodesignError::TeamIdentifierMismatch {
            self_id: self_team,
            candidate_id: candidate_team,
        });
    }
    if self_id != candidate_id {
        return Err(CodesignError::IdentifierMismatch {
            self_id,
            candidate_id,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signing_identity_does_not_error_on_an_unsigned_test_binary() {
        // `cargo test` builds an unsigned binary in CI/dev; the call must
        // still succeed (returning `None`), never error.
        let result = self_signing_identity();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_self_consistency_fail_opens_for_an_unsigned_self() {
        // This test binary itself is unsigned in dev/CI, so the fail-open
        // dev path applies regardless of what `candidate_path` even is.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate");
        std::fs::write(&path, b"not a real binary").unwrap();
        assert!(verify_self_consistency(&path).is_ok());
    }

    // ---- verify_against fail-closed paths (DR-0029 bundle 2 review MEDIUM-3) ----
    //
    // `verify_self_consistency` cannot be driven into its fail-closed branch
    // from `cargo test`: `self_signing_identity()` reads *this already-loaded
    // process's* code signature, which is unsigned for a `cargo test`
    // binary — re-signing the file on disk afterward has no effect on it
    // (`SecCode::for_self` answers from the process's load-time identity,
    // not a fresh disk read). `verify_against` exists precisely so these
    // tests can supply a fake signed "self" identity directly and exercise
    // the real comparison logic against a genuine candidate on disk.

    #[test]
    fn verify_against_rejects_an_unsigned_candidate_when_self_is_signed() {
        // No real signing capability needed for this one: any plain file is
        // (from Security.framework's perspective) a validly-constructible
        // but unsigned code object, so `candidate_signing_identity` returns
        // `Ok(None)` for it — hitting `CandidateUnsigned` below. Runs
        // unconditionally in CI/dev (unlike the two tests further down).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate");
        std::fs::write(&path, b"not a real binary").unwrap();
        let fake_self = Some(("FAKETEAM1234".to_string(), "com.example.fake".to_string()));
        let result = verify_against(fake_self, &path);
        assert!(
            result.is_err(),
            "an unsigned candidate must be rejected once self is signed, got {result:?}"
        );
    }

    /// Best-effort scan of `/Applications/*.app` for one signed with a Team
    /// Identifier. Used only by the two `#[ignore]`d tests below, which are
    /// manual-environment tests (see their doc): a minimal CI image with no
    /// installed apps legitimately has nothing to find here.
    fn any_installed_app_with_team_id() -> Option<(std::path::PathBuf, String, String)> {
        let entries = std::fs::read_dir("/Applications").ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "app").unwrap_or(true) {
                continue;
            }
            if let Ok(Some((team, id))) = candidate_signing_identity(&path) {
                return Some((path, team, id));
            }
        }
        None
    }

    /// Best-effort scan for two `/Applications/*.app` entries signed by the
    /// *same* Team Identifier but with different signing Identifiers (e.g.
    /// two apps from the same developer account) — used only by the
    /// `#[ignore]`d Identifier-mismatch test below.
    fn two_installed_apps_sharing_a_team_id()
    -> Option<((std::path::PathBuf, String), (std::path::PathBuf, String))> {
        use std::collections::HashMap;
        let mut by_team: HashMap<String, Vec<(std::path::PathBuf, String)>> = HashMap::new();
        let entries = std::fs::read_dir("/Applications").ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "app").unwrap_or(true) {
                continue;
            }
            if let Ok(Some((team, id))) = candidate_signing_identity(&path) {
                by_team.entry(team).or_default().push((path, id));
            }
        }
        by_team
            .into_values()
            .find(|apps| apps.len() >= 2 && apps[0].1 != apps[1].1)
            .map(|mut apps| {
                let b = apps.pop().unwrap();
                let a = apps.pop().unwrap();
                (a, b)
            })
    }

    #[test]
    #[ignore = "manual: needs at least one Team-Identifier-signed app in /Applications \
                (true on a normal Mac with GUI apps installed, not a minimal CI image); \
                run with `cargo test -p cache-warden-cli -- --ignored codesign`"]
    fn verify_against_rejects_a_team_identifier_mismatch() {
        let Some((app_path, real_team, _real_id)) = any_installed_app_with_team_id() else {
            panic!("no Team-Identifier-signed app found under /Applications to use as a candidate");
        };
        // A fake self identity whose team is guaranteed not to match a real
        // installed app's team (Apple Developer Team IDs are exactly 10
        // alphanumeric characters; this literal is deliberately a different
        // shape/value from any of them).
        let fake_self = Some(("NOTAREALTEAMID".to_string(), "com.example.fake".to_string()));
        assert_ne!(
            fake_self.as_ref().unwrap().0,
            real_team,
            "test setup sanity check"
        );
        let result = verify_against(fake_self, &app_path);
        assert!(
            matches!(result, Err(CodesignError::TeamIdentifierMismatch { .. })),
            "expected TeamIdentifierMismatch against {}, got {result:?}",
            app_path.display()
        );
    }

    #[test]
    #[ignore = "manual: needs two apps in /Applications signed by the same team but with \
                different identifiers (true when at least one developer has published \
                more than one app on this Mac); run with \
                `cargo test -p cache-warden-cli -- --ignored codesign`"]
    fn verify_against_rejects_an_identifier_mismatch_with_a_matching_team() {
        let Some(((path_a, id_a), (path_b, _id_b))) = two_installed_apps_sharing_a_team_id() else {
            panic!("no pair of same-team, different-identifier apps found under /Applications");
        };
        // Use app A's own real (team, identifier) as the fake "self" —
        // guarantees the team matches app B (same team by construction of
        // the pair above) while the identifier does not (app B's own
        // identifier differs from app A's by construction).
        let self_identity = candidate_signing_identity(&path_a)
            .expect("app A must still be readable")
            .expect("app A must still be signed");
        assert_eq!(self_identity.1, id_a, "test setup sanity check");
        let result = verify_against(Some(self_identity), &path_b);
        assert!(
            matches!(result, Err(CodesignError::IdentifierMismatch { .. })),
            "expected IdentifierMismatch between {} and {}, got {result:?}",
            path_a.display(),
            path_b.display()
        );
    }
}
