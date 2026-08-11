//! Code signature identity for the current process and Unix-socket peers
//! (draft-DR-0031 §Security).
//!
//! Two facts about a running process's code signature are exposed here:
//!
//! - [`self_identity`]: this process's own `(Team Identifier, Identifier)` as
//!   recorded in its load-time signature — `None` on either component when the
//!   process is ad-hoc / unsigned (a `cargo test` binary always is; a
//!   Developer-ID-signed release build has both).
//! - [`peer_identity`] + [`verify_peer`]: the same fields for the process on
//!   the other end of an accepted `AF_UNIX` connection, obtained by asking
//!   the kernel (`SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)`)
//!   for the live peer's `SecCode` and then reading its signing information.
//!
//! # Scope: identity match plus dynamic validity, not integrity re-hash
//!
//! [`verify_peer`] performs `SecCodeCheckValidity` on the peer's live SecCode
//! against a requirement string built from *this* process's Team Identifier
//! (`anchor apple generic and certificate leaf[subject.OU] = "<TEAM>"`). That
//! call is a **dynamic** signature check on the running peer: it re-evaluates
//! the peer's on-disk signature against its currently-mapped code pages and
//! rejects a peer whose signature does not validate against the requirement.
//! It is not a fresh re-hash of every page — the kernel already enforces
//! signature validity on `execve` for any signed binary (`amfid`), so a peer
//! whose bytes were tampered with after signing would have been `SIGKILL`ed by
//! the kernel before it could ever connect. This module's check narrows
//! *which* signed identity may connect at all; the kernel is what guarantees
//! that identity's bytes are its own.
//!
//! # Fail-closed on ad-hoc self, always
//!
//! [`verify_peer`] refuses to succeed when this process itself has no Team
//! Identifier (ad-hoc / unsigned). There is no comparison to make in that
//! case — allowing a fallback path would introduce a distinct verification
//! mode whose sole purpose is to be more permissive than the real one, which
//! is exactly the attack surface the "identity match" design chose to close.
//! Dev builds are expected to be signed with the same Developer ID as
//! release builds (draft-DR-0031 §Security 2026-07-12 ruling).
//!
//! # Why the extra raw FFI for `SecCodeCopySigningInformation`
//!
//! `security-framework` exposes `SecCode`, `SecRequirement`,
//! `SecCode::check_validity`, and `SecCode::copy_guest_with_attribues`, which
//! covers construction and requirement matching. It does **not** expose
//! `SecCodeCopySigningInformation` nor the `kSecCodeInfo*` dictionary keys
//! needed to read a SecCode's own Team Identifier / Identifier back out —
//! which is what a runtime "self vs peer" identity comparison needs (the
//! self-identity string has to be discovered before a requirement can be
//! built at all). These three symbols are part of Apple's stable, documented
//! Code Signing Services API (`Security.framework`, macOS 10.6+); the
//! framework is already linked transitively via `security-framework-sys`, so
//! only the missing symbol declarations are added here. This mirrors the
//! same-shaped FFI extension already living in
//! `cache-warden-cli::daemon::graceful_restart::codesign` (DR-0029 §3).

use std::os::unix::io::RawFd;

/// A code object's signing identity: Apple Developer Team Identifier and
/// signing Identifier (bundle id / executable identifier).
///
/// Both fields are `Option` because ad-hoc / unsigned code lacks a Team
/// Identifier entirely, and the Identifier alone is not a trustworthy signal
/// (ad-hoc code has one, but it is caller-controlled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentity {
    /// Apple Developer Team Identifier (`kSecCodeInfoTeamIdentifier`), or
    /// `None` when the code has no Team Identifier (ad-hoc / unsigned).
    pub team_id: Option<String>,
    /// Signing Identifier (`kSecCodeInfoIdentifier`), or `None` when the
    /// signing-information dictionary lacked the key. In practice ad-hoc
    /// code carries an Identifier; a fully unsigned binary may not.
    pub identifier: Option<String>,
}

/// Why a code signature identity call failed.
#[derive(Debug)]
pub enum CodesignError {
    /// This process itself is not code-signed (has no Team Identifier), so a
    /// same-identity peer verification cannot succeed — see the module doc's
    /// "fail-closed on ad-hoc self" note.
    SelfUnsigned,
    /// This process is signed but its own signing-information dictionary
    /// could not be read (`SecCodeCopySigningInformation` failed).
    SelfSigningInfo { status: i32 },
    /// The kernel had no audit token to report for this socket fd (not a
    /// socket, no connected peer, non-macOS build, ...).
    PeerTokenUnavailable,
    /// The peer's effective uid differs from this process's — refused before
    /// spending any signature-verification work on it.
    EuidMismatch { self_euid: u32, peer_euid: u32 },
    /// `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` could not
    /// resolve the audit token to a live SecCode (peer already exited, or
    /// the token does not correspond to any kernel-known process).
    PeerCodeObject { status: i32 },
    /// The peer's signature failed dynamic validation against the requirement
    /// built from this process's Team Identifier (`SecCodeCheckValidity`).
    PeerRequirementUnsatisfied { status: i32 },
    /// The peer's signing-information dictionary could not be read.
    PeerSigningInfo { status: i32 },
    /// The peer is signed but carries no Team Identifier (matched the
    /// requirement's anchor+OU chain only because that itself is
    /// impossible without a team id — this variant is defensive: reachable
    /// only if a future Security.framework change decoupled the two).
    PeerUnsigned,
    /// The peer's signature carries no signing Identifier at all, so the
    /// required prefix cannot be checked. Distinct from
    /// [`CodesignError::PeerIdentifierPrefixMismatch`] because the two point
    /// at different problems: a missing identifier means the peer's signature
    /// is shaped unlike anything this project produces (every cache-warden
    /// binary is signed with an explicit identifier), while a mismatch means a
    /// real, differently-named app from the same team.
    PeerIdentifierMissing { required_prefix: String },
    /// The peer's signing Identifier does not start with the required prefix
    /// (e.g. `com.github.kawaz.cache-warden`) — same Team ID, different app
    /// family.
    PeerIdentifierPrefixMismatch {
        required_prefix: String,
        peer_identifier: String,
    },
    /// The peer's Team Identifier differs from this process's (defensive:
    /// `SecCodeCheckValidity` against a `subject.OU = "<self_team>"`
    /// requirement should have already rejected this case).
    TeamIdentifierMismatch {
        self_team: String,
        peer_team: String,
    },
}

impl std::fmt::Display for CodesignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodesignError::SelfUnsigned => f.write_str(
                "this process has no Team Identifier (ad-hoc / unsigned); peer verification \
                 cannot succeed by design (see module doc)",
            ),
            CodesignError::SelfSigningInfo { status } => write!(
                f,
                "cannot read this process's own signing information (OSStatus {status})"
            ),
            CodesignError::PeerTokenUnavailable => {
                f.write_str("no audit token available for the socket peer")
            }
            CodesignError::EuidMismatch {
                self_euid,
                peer_euid,
            } => write!(
                f,
                "peer euid {peer_euid} does not match this process's euid {self_euid}"
            ),
            CodesignError::PeerCodeObject { status } => write!(
                f,
                "cannot resolve peer audit token to a live SecCode (OSStatus {status})"
            ),
            CodesignError::PeerRequirementUnsatisfied { status } => write!(
                f,
                "peer signature does not satisfy the required Team Identifier (OSStatus {status})"
            ),
            CodesignError::PeerSigningInfo { status } => write!(
                f,
                "cannot read peer signing information (OSStatus {status})"
            ),
            CodesignError::PeerUnsigned => {
                f.write_str("peer signing information carries no Team Identifier")
            }
            CodesignError::PeerIdentifierMissing { required_prefix } => write!(
                f,
                "peer signature carries no signing identifier to match against the \
                 required prefix {required_prefix:?}"
            ),
            CodesignError::PeerIdentifierPrefixMismatch {
                required_prefix,
                peer_identifier,
            } => write!(
                f,
                "peer signing identifier {peer_identifier:?} does not start with the \
                 required prefix {required_prefix:?}"
            ),
            CodesignError::TeamIdentifierMismatch {
                self_team,
                peer_team,
            } => write!(
                f,
                "peer Team Identifier {peer_team:?} does not match this process's {self_team:?}"
            ),
        }
    }
}

impl std::error::Error for CodesignError {}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use super::{CodesignError, SigningIdentity};
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::dictionary::CFDictionaryRef;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };
    use std::os::unix::io::RawFd;
    use std::str::FromStr;

    /// `kSecCSSigningInformation` (`CSCommon.h`): ask
    /// `SecCodeCopySigningInformation` for the signing-identity fields
    /// (Team Identifier / Identifier), not just the default set.
    const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

    mod extra_ffi {
        //! The three `Security.framework` symbols not exposed by
        //! `security-framework-sys` (see the module doc). Declared exactly
        //! as Apple's `SecCode.h` / `CSCommon.h` headers specify.
        use core_foundation_sys::dictionary::CFDictionaryRef;
        use core_foundation_sys::string::CFStringRef;

        unsafe extern "C" {
            /// `CFDictionary` key for a code object's signing identifier
            /// (bundle id / executable identifier), as a `CFString`.
            pub(super) static kSecCodeInfoIdentifier: CFStringRef;
            /// `CFDictionary` key for a code object's Team Identifier, as a
            /// `CFString`, or absent for unsigned / non-Developer-ID code.
            pub(super) static kSecCodeInfoTeamIdentifier: CFStringRef;

            /// `OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code,
            /// SecCSFlags flags, CFDictionaryRef *information)`. The header
            /// types `code` as `SecStaticCodeRef` but documents that a
            /// `SecCodeRef` (e.g. from `SecCodeCopySelf` or
            /// `SecCodeCopyGuestWithAttributes`) is also accepted — declared
            /// here as an untyped `*mut c_void` so callers cast whichever
            /// concrete ref they hold.
            pub(super) fn SecCodeCopySigningInformation(
                code: *mut core::ffi::c_void,
                flags: u32,
                information: *mut CFDictionaryRef,
            ) -> i32; // OSStatus
        }
    }

    /// Read `(kSecCodeInfoTeamIdentifier, kSecCodeInfoIdentifier)` out of a
    /// signing-information dictionary retained by
    /// `SecCodeCopySigningInformation`.
    fn extract_identity(dict_ref: CFDictionaryRef) -> SigningIdentity {
        // SAFETY: `dict_ref` is a +1-retained `CFDictionaryRef` handed to us
        // by `SecCodeCopySigningInformation` on success; wrapping it under
        // the create rule takes ownership of that retain and drops it when
        // `dict` goes out of scope.
        let dict: CFDictionary<CFString, CFString> =
            unsafe { CFDictionary::wrap_under_create_rule(dict_ref) };
        // SAFETY: the static key constants are process-lifetime `CFStringRef`s
        // owned by Security.framework (a "get" rule value — never released
        // by us).
        let team_key =
            unsafe { CFString::wrap_under_get_rule(extra_ffi::kSecCodeInfoTeamIdentifier) };
        let id_key = unsafe { CFString::wrap_under_get_rule(extra_ffi::kSecCodeInfoIdentifier) };

        SigningIdentity {
            team_id: dict.find(team_key).map(|v| v.to_string()),
            identifier: dict.find(id_key).map(|v| v.to_string()),
        }
    }

    /// Copy the signing information out of an already-constructed `SecCode`.
    fn signing_info(code: &SecCode) -> Result<SigningIdentity, i32> {
        // SAFETY: `code.as_concrete_TypeRef()` is a live retained `SecCodeRef`
        // owned by `code`. `SecCodeCopySigningInformation` accepts a
        // `SecCodeRef` in addition to its documented `SecStaticCodeRef` (see
        // `extra_ffi`'s doc). On success it writes a +1-retained dict into
        // the out slot; on failure the slot is left null.
        let dict_ref = unsafe {
            let mut dict_ref: CFDictionaryRef = std::ptr::null();
            let status = extra_ffi::SecCodeCopySigningInformation(
                code.as_concrete_TypeRef() as *mut core::ffi::c_void,
                K_SEC_CS_SIGNING_INFORMATION,
                &mut dict_ref,
            );
            if status != 0 {
                return Err(status);
            }
            dict_ref
        };
        Ok(extract_identity(dict_ref))
    }

    pub(super) fn self_identity() -> Result<SigningIdentity, CodesignError> {
        // `SecCode::for_self` on macOS is essentially infallible under normal
        // conditions (the kernel always answers about the current process),
        // so the SfError case is folded into the same "cannot read own
        // signing info" bucket.
        let code = SecCode::for_self(Flags::NONE)
            .map_err(|e| CodesignError::SelfSigningInfo { status: e.code() })?;
        signing_info(&code).map_err(|status| CodesignError::SelfSigningInfo { status })
    }

    pub(super) fn peer_identity(fd: RawFd) -> Result<SigningIdentity, CodesignError> {
        let token =
            super::super::peer_audit_token(fd).ok_or(CodesignError::PeerTokenUnavailable)?;
        let token_bytes = token.raw_bytes();
        let data = CFData::from_buffer(&token_bytes);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let peer_code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|e| CodesignError::PeerCodeObject { status: e.code() })?;
        signing_info(&peer_code).map_err(|status| CodesignError::PeerSigningInfo { status })
    }

    pub(super) fn verify_peer(
        fd: RawFd,
        required_identifier_prefix: &str,
    ) -> Result<(), CodesignError> {
        // 1. Self identity: cheapest and gates everything else. Ad-hoc self
        //    can never satisfy the "same identity as me" contract.
        let self_id = self_identity()?;
        let self_team = self_id.team_id.ok_or(CodesignError::SelfUnsigned)?;

        // 2. Peer audit token: also a cheap kernel lookup. Feeds both the
        //    euid pre-check and the SecCode resolution.
        let token =
            super::super::peer_audit_token(fd).ok_or(CodesignError::PeerTokenUnavailable)?;

        // 3. euid pre-check: `SecCodeCheckValidity` is expensive; a
        //    cross-uid connection is uniformly a reject regardless of
        //    signature and never worth spending it on. The kernel resolves
        //    the peer's euid at `getsockopt` time, so this is race-free
        //    against pid reuse in the same way `peer.rs` documents.
        // SAFETY: `getuid`/`geteuid` are always-safe, argumentless system
        // calls exposed by libc.
        let self_euid = unsafe { libc::geteuid() };
        if token.euid() != self_euid {
            return Err(CodesignError::EuidMismatch {
                self_euid,
                peer_euid: token.euid(),
            });
        }

        // 4. Resolve the audit token to a live peer SecCode. This asks the
        //    kernel — the code-signing root of trust — to identify the
        //    guest, so a peer that already exited returns
        //    `PeerCodeObject`, not a stale disk read.
        let token_bytes = token.raw_bytes();
        let data = CFData::from_buffer(&token_bytes);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let peer_code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|e| CodesignError::PeerCodeObject { status: e.code() })?;

        // 5. Dynamic validity + Team Identifier requirement in one call.
        //    `anchor apple generic` restricts to code signed under Apple's
        //    root CA hierarchy (the same anchor a Developer ID Application
        //    certificate chains to); `certificate leaf[subject.OU] = "<team>"`
        //    pins the Team Identifier the peer must have been signed with.
        //    The identifier prefix is not encoded here (Apple's Code Signing
        //    Requirement Language does allow wildcards in string matches per
        //    TN2206, but that path is verified in Rust below to keep the
        //    check on ground that this module's test suite can pin down
        //    without shelling out to `csreq`).
        let requirement_string =
            format!("anchor apple generic and certificate leaf[subject.OU] = \"{self_team}\"");
        let requirement = SecRequirement::from_str(&requirement_string).map_err(|e| {
            // The requirement literal is fixed shape — parse failure would
            // mean Security.framework changed the requirement DSL under us.
            // Surface it in the same bucket as a validity failure for
            // simplicity; a real user hitting this needs to look at OSStatus
            // regardless.
            CodesignError::PeerRequirementUnsatisfied { status: e.code() }
        })?;
        peer_code
            .check_validity(Flags::NONE, &requirement)
            .map_err(|e| CodesignError::PeerRequirementUnsatisfied { status: e.code() })?;

        // 6. Read the peer's signing identity for the prefix + defensive
        //    Team Identifier equality check. `check_validity` above already
        //    matched the Team via the requirement string, but the equality
        //    check pins the invariant so a future requirement-string edit
        //    that drops the OU predicate cannot silently reintroduce a hole.
        let peer_id =
            signing_info(&peer_code).map_err(|status| CodesignError::PeerSigningInfo { status })?;
        let peer_team = peer_id.team_id.ok_or(CodesignError::PeerUnsigned)?;
        if peer_team != self_team {
            return Err(CodesignError::TeamIdentifierMismatch {
                self_team,
                peer_team,
            });
        }
        let peer_identifier =
            peer_id
                .identifier
                .ok_or_else(|| CodesignError::PeerIdentifierMissing {
                    required_prefix: required_identifier_prefix.to_string(),
                })?;
        if !peer_identifier.starts_with(required_identifier_prefix) {
            return Err(CodesignError::PeerIdentifierPrefixMismatch {
                required_prefix: required_identifier_prefix.to_string(),
                peer_identifier,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// non-macOS shim: everything reports "unavailable"
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{CodesignError, SigningIdentity};
    use std::os::unix::io::RawFd;

    pub(super) fn self_identity() -> Result<SigningIdentity, CodesignError> {
        // On non-macOS there is no Security.framework to answer the
        // question — report unsigned so any downstream call defaults to
        // fail-closed. This crate keeps compiling on Linux CI (`peer.rs`
        // has the same shim) without pulling Security.framework in.
        Ok(SigningIdentity {
            team_id: None,
            identifier: None,
        })
    }

    pub(super) fn peer_identity(_fd: RawFd) -> Result<SigningIdentity, CodesignError> {
        Err(CodesignError::PeerTokenUnavailable)
    }

    pub(super) fn verify_peer(
        _fd: RawFd,
        _required_identifier_prefix: &str,
    ) -> Result<(), CodesignError> {
        // No `SecCodeCheckValidity` off macOS — the daemon and helper are
        // both macOS-only in production; a non-macOS build cannot make a
        // meaningful assertion here.
        Err(CodesignError::SelfUnsigned)
    }
}

// ---------------------------------------------------------------------------
// public API — same shape on every platform
// ---------------------------------------------------------------------------

/// This process's own code signature identity, or a `SigningIdentity` with
/// both fields `None` when this build is ad-hoc / unsigned (typical for
/// `cargo test` and local dev builds). See the module doc.
pub fn self_identity() -> Result<SigningIdentity, CodesignError> {
    imp::self_identity()
}

/// The signature identity of the process on the other end of the connected
/// socket at `fd`, resolved by asking the kernel about the peer's audit
/// token. Returns `PeerTokenUnavailable` off macOS or when the kernel has no
/// audit token to report (not a socket, no peer, ...).
pub fn peer_identity(fd: RawFd) -> Result<SigningIdentity, CodesignError> {
    imp::peer_identity(fd)
}

/// Verify that the socket peer at `fd` was signed by the same Apple
/// Developer Team Identifier as this process, that its signature dynamically
/// validates against that Team Identifier under Apple's code-signing anchor,
/// and that its signing Identifier starts with `required_identifier_prefix`.
///
/// This is the full "same identity as me, cache-warden family" gate used by
/// the daemon → helper and helper → daemon peer authentication (draft-DR-0031
/// §Security). Fail-closed on every deviation: ad-hoc self (see the module
/// doc), euid mismatch, missing audit token, expired peer, unsigned peer,
/// signature invalid, wrong team, missing or non-matching identifier.
///
/// The peer verification order is: self identity (cheapest and gates
/// everything else), peer audit token, euid pre-check, live peer SecCode,
/// `SecCodeCheckValidity` against `anchor apple generic and certificate
/// leaf[subject.OU] = "<self_team>"`, defensive Team Identifier equality,
/// signing Identifier prefix.
pub fn verify_peer(fd: RawFd, required_identifier_prefix: &str) -> Result<(), CodesignError> {
    imp::verify_peer(fd, required_identifier_prefix)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `self_identity` on the `cargo test` binary — which is unsigned in
    /// dev/CI — must return `Ok` with `team_id: None`. The graceful-restart
    /// codesign module has the same "no error on unsigned" contract; this
    /// pins it independently for `macos_process_inspect::codesign`.
    #[test]
    fn self_identity_does_not_error_on_an_unsigned_test_binary() {
        let id = self_identity().expect("self_identity should not error");
        // The test binary is ad-hoc; a Team Identifier must not be
        // fabricated. On non-macOS the shim also returns None.
        assert!(
            id.team_id.is_none(),
            "an ad-hoc / unsigned test binary must not report a Team Identifier, got {id:?}"
        );
    }

    /// The "no identifier at all" and "identifier from another app family"
    /// rejections must read as different problems — they are: the first says
    /// the peer is not shaped like anything this project signs, the second
    /// says it is a different app under the same Team ID. An operator
    /// grepping syslog for signs of a same-uid impostor acts on them
    /// differently, and collapsing both into one message (an
    /// `unwrap_or_default()` on the identifier reports a missing identifier
    /// as the empty-string prefix mismatch) is what this pins against.
    #[test]
    fn missing_and_mismatched_peer_identifier_report_differently() {
        let missing = CodesignError::PeerIdentifierMissing {
            required_prefix: "com.github.kawaz.cache-warden".to_string(),
        }
        .to_string();
        let mismatch = CodesignError::PeerIdentifierPrefixMismatch {
            required_prefix: "com.github.kawaz.cache-warden".to_string(),
            peer_identifier: "com.example.other".to_string(),
        }
        .to_string();
        assert!(
            missing.contains("no signing identifier"),
            "missing-identifier message should say the identifier is absent: {missing}"
        );
        assert!(
            mismatch.contains("com.example.other"),
            "mismatch message should name the peer's identifier: {mismatch}"
        );
        assert_ne!(missing, mismatch);
    }

    /// `verify_peer` against oneself (both ends of a `socketpair` inside the
    /// same ad-hoc test process) must fail with `SelfUnsigned` — never
    /// succeed — because this process has no Team Identifier to compare the
    /// peer against. This pins the "fail-closed on ad-hoc self" invariant:
    /// a refactor that silently accepted "self has no team, so any peer is
    /// fine" would let this test through and defeat the whole point of the
    /// design.
    #[test]
    #[cfg(target_os = "macos")]
    fn verify_peer_on_ad_hoc_self_socketpair_is_fail_closed() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let result = verify_peer(a.as_raw_fd(), "com.github.kawaz.cache-warden");
        assert!(
            matches!(result, Err(CodesignError::SelfUnsigned)),
            "ad-hoc self must fail-close with SelfUnsigned, got {result:?}"
        );
    }

    /// Non-macOS shim: `verify_peer` uniformly rejects. Pins that the shim
    /// does not accidentally return `Ok(())` on a Linux CI build (which
    /// would compile away the entire security check for those targets).
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verify_peer_off_macos_is_fail_closed() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let result = verify_peer(a.as_raw_fd(), "com.github.kawaz.cache-warden");
        assert!(result.is_err(), "off-macos verify_peer must fail-close");
    }

    /// Positive-path e2e (both ends signed with the same Developer ID as
    /// this build): kept for manual verification because a normal
    /// `cargo test` invocation runs against an ad-hoc test binary that
    /// cannot possibly satisfy the check. Manual steps:
    ///
    /// 1. Build the workspace normally: `cargo build --workspace`.
    /// 2. Sign the resulting `macos-process-inspect` test binary (found
    ///    under `target/debug/deps/macos_process_inspect-*`) with the
    ///    same Developer ID Application identity used by
    ///    cache-warden-approver — e.g.
    ///    `codesign -s "Developer ID Application: <NAME> (<TEAM>)"
    ///     --identifier com.github.kawaz.cache-warden.test.macos_process_inspect
    ///     target/debug/deps/macos_process_inspect-<hash>`.
    /// 3. Rerun that test binary directly (not via `cargo test`, which
    ///    rebuilds and strips signatures) with `--ignored codesign_e2e`.
    ///
    /// The reason this cannot be automated in `cargo test` is that
    /// `SecCode::for_self` reads the live process's load-time signing
    /// identity — signing the file on disk *after* the process has loaded
    /// has no effect on it. Any automation would have to launch a fresh
    /// signed child process, which is exactly what the real
    /// daemon↔helper integration test in `cache-warden-cli` will cover.
    #[test]
    #[ignore = "manual: requires a Developer-ID-signed test binary; \
                see the test's doc for the codesign step. Not runnable in CI."]
    #[cfg(target_os = "macos")]
    fn codesign_e2e_signed_self_verifies_signed_self_socketpair() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        // The prefix `com.github.kawaz.cache-warden` is the family root;
        // the manual codesign step above uses a child identifier under
        // that prefix.
        verify_peer(a.as_raw_fd(), "com.github.kawaz.cache-warden")
            .expect("signed-self ↔ signed-self via socketpair must verify");
    }
}
