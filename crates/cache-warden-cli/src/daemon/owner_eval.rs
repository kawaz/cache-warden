//! Deciding whether the caller is an entry's owner (draft-DR-0033 §1).
//!
//! # The peer, and only the peer
//!
//! What gets evaluated is the process on the other end of the control socket.
//! Not its parent, not anything in its ancestry. DR-0030's `same-ancestor`
//! walks a chain because it is asking a question about *sessions* — did this
//! come from the same place as that. This asks a question about *identity* —
//! is this that program — and the chain is the wrong instrument for it: any
//! rule that accepted a match somewhere up the tree would accept every binary
//! anyone launched from a signed Terminal.
//!
//! # A token, not a pid
//!
//! Identity is resolved from the audit token captured when the connection
//! arrived. A pid would be a name that the kernel may reassign between the
//! moment it is read and the moment it is checked, which is precisely the
//! window an attacker needs. The token names one process for as long as that
//! process exists, and no longer.
//!
//! # Failing closed, including on this platform
//!
//! Every path that cannot reach a definite yes is a no: no token, no
//! signature, an unparseable requirement, a platform with no code signing at
//! all. An entry with an owner is an entry someone asked to be strict about;
//! degrading to permissive when the check is unavailable would answer a
//! question nobody asked.

use cache_warden::OwnerPrincipal;
use macos_process_inspect::AuditToken;

/// Why a caller is not the owner.
///
/// The distinctions here are for the daemon's own log. **None of them reaches
/// the caller** — the wire says only that ownership was not satisfied
/// (DR-0030 §4, inherited by DR-0033 §6). A caller that could tell "wrong
/// team" from "unsigned" from "no such owner" would have an oracle for
/// probing what a key is protected by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerDenied {
    /// The connection carried no audit token, so there is no process to
    /// identify.
    NoPeerToken,
    /// The peer's signature does not satisfy the owner's requirement — the
    /// ordinary denial, covering unsigned, differently-signed, and expired
    /// peers alike.
    RequirementUnsatisfied(String),
    /// The requirement this build assembled is not valid Requirement
    /// Language.
    ///
    /// Separate from [`OwnerDenied::RequirementUnsatisfied`] because it is a
    /// bug here, not a caller failing a check — and one that would otherwise
    /// hide as a permanent, ordinary-looking refusal of everyone. The wire
    /// still says only that ownership was not satisfied; the difference is
    /// visible in the log, where it can be acted on.
    RequirementMalformed,
    /// This build cannot evaluate code signatures at all.
    Unsupported,
}

impl std::fmt::Display for OwnerDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnerDenied::NoPeerToken => f.write_str("the caller could not be identified"),
            OwnerDenied::RequirementUnsatisfied(why) => {
                write!(
                    f,
                    "the caller's code signature does not match the owner ({why})"
                )
            }
            OwnerDenied::RequirementMalformed => {
                f.write_str("the owner requirement this build assembled is malformed (a bug)")
            }
            OwnerDenied::Unsupported => {
                f.write_str("code signatures cannot be evaluated on this platform")
            }
        }
    }
}

/// Decides whether a caller satisfies an owner principal.
///
/// A trait so the decision can be replaced in tests. Every rule that composes
/// around it — first use establishing ownership, inheritance across updates,
/// the order authorization runs in relative to compare-and-swap — is logic
/// worth testing deterministically, and none of it should need two
/// differently-signed binaries and a socket between them to exercise.
pub trait OwnerVerifier: Send + Sync {
    /// `Ok(())` when `token` identifies a process satisfying `owner`.
    fn satisfies(
        &self,
        token: Option<&AuditToken>,
        owner: &OwnerPrincipal,
    ) -> Result<(), OwnerDenied>;

    /// The signing flags of the process `token` names, when they can be read
    /// (draft-DR-0033 §5 / Open Q1).
    ///
    /// Used at declaration time to warn about a peer whose own hardening is
    /// off. Returning `None` is always acceptable: the answer is advisory.
    fn signing_flags(&self, _token: Option<&AuditToken>) -> Option<u32> {
        None
    }
}

/// The real verifier: asks the kernel.
pub struct CodeSignatureVerifier;

impl OwnerVerifier for CodeSignatureVerifier {
    fn satisfies(
        &self,
        token: Option<&AuditToken>,
        owner: &OwnerPrincipal,
    ) -> Result<(), OwnerDenied> {
        if cfg!(not(target_os = "macos")) {
            return Err(OwnerDenied::Unsupported);
        }
        let token = token.ok_or(OwnerDenied::NoPeerToken)?;
        // The requirement is assembled from the principal's structured fields
        // every time rather than stored as a string. Nothing between here and
        // the declaration can have edited it.
        macos_process_inspect::codesign::verify_audit_token_against(token, &owner.requirement())
            .map_err(|e| match e {
                // A requirement this code assembled did not parse. That is not
                // a caller failing a check — it is this build emitting invalid
                // Requirement Language, and it would deny every caller
                // forever while looking exactly like an ordinary refusal.
                // Loud in the log, indistinguishable on the wire.
                macos_process_inspect::codesign::CodesignError::RequirementUnparseable {
                    status,
                } => {
                    eprintln!(
                        "cache-warden: BUG: the owner requirement assembled for a signed-by \
                         declaration is not valid Requirement Language (OSStatus {status}); \
                         every caller will be refused until this is fixed"
                    );
                    OwnerDenied::RequirementMalformed
                }
                other => OwnerDenied::RequirementUnsatisfied(other.to_string()),
            })
    }

    fn signing_flags(&self, token: Option<&AuditToken>) -> Option<u32> {
        macos_process_inspect::codesign::signing_flags(token?).ok()
    }
}

/// What a declaration-time hardening check found (DR-0033 §5).
///
/// The premises under which signed-by means anything: code injected into a
/// process runs under that process's signature, so a peer without hardened
/// runtime is a peer whose identity says nothing about what is executing
/// inside it.
///
/// **Advisory only.** DR-0033 Open Q1 was settled at "warn when declaring,
/// never refuse when evaluating": the flags are readable, but which legitimate
/// programs run without them is not yet known, and turning an unknown into a
/// refusal would break callers to protect them from a risk they may have
/// already accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// Hardened runtime is on.
    pub runtime: bool,
    /// Library validation is on.
    pub library_validation: bool,
}

impl Hardening {
    /// Read the caller's hardening, or `None` if it could not be read.
    pub fn of(verifier: &dyn OwnerVerifier, token: Option<&AuditToken>) -> Option<Self> {
        let flags = verifier.signing_flags(token)?;
        Some(Hardening {
            runtime: flags & macos_process_inspect::codesign::CS_RUNTIME != 0,
            library_validation: flags & macos_process_inspect::codesign::CS_REQUIRE_LV != 0,
        })
    }

    /// A warning for a declaration made by a process missing either premise,
    /// or `None` when both are present.
    pub fn warning(&self) -> Option<&'static str> {
        match (self.runtime, self.library_validation) {
            (true, true) => None,
            (false, false) => Some(
                "neither hardened runtime nor library validation is enabled on the declaring \
                 process: code injected into it would run under its signature, so an owner \
                 requirement naming it is weaker than it looks",
            ),
            (false, true) => Some(
                "hardened runtime is not enabled on the declaring process: code injected into \
                 it would run under its signature",
            ),
            (true, false) => Some(
                "library validation is not enabled on the declaring process: it can load \
                 libraries signed by others, which then run under its signature",
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Verifiers with fixed answers, for testing everything built on top of
    //! the decision without needing two signed binaries and a socket.

    use super::*;

    /// Accepts every caller.
    pub struct AlwaysOwner;

    impl OwnerVerifier for AlwaysOwner {
        fn satisfies(&self, _: Option<&AuditToken>, _: &OwnerPrincipal) -> Result<(), OwnerDenied> {
            Ok(())
        }
    }

    /// Rejects every caller.
    pub struct NeverOwner;

    impl OwnerVerifier for NeverOwner {
        fn satisfies(&self, _: Option<&AuditToken>, _: &OwnerPrincipal) -> Result<(), OwnerDenied> {
            Err(OwnerDenied::RequirementUnsatisfied("test verifier".into()))
        }
    }

    /// Accepts exactly one principal — the shape that matters for the rules
    /// built on top: one caller is the owner, another is not, and which is
    /// which does not change mid-test.
    pub struct OnlyPrincipal(pub OwnerPrincipal);

    impl OwnerVerifier for OnlyPrincipal {
        fn satisfies(
            &self,
            _: Option<&AuditToken>,
            owner: &OwnerPrincipal,
        ) -> Result<(), OwnerDenied> {
            if owner == &self.0 {
                Ok(())
            } else {
                Err(OwnerDenied::RequirementUnsatisfied(
                    "different principal".into(),
                ))
            }
        }
    }

    /// Reports fixed signing flags, for the declaration-time warning.
    pub struct WithFlags(pub u32);

    impl OwnerVerifier for WithFlags {
        fn satisfies(&self, _: Option<&AuditToken>, _: &OwnerPrincipal) -> Result<(), OwnerDenied> {
            Ok(())
        }
        fn signing_flags(&self, _: Option<&AuditToken>) -> Option<u32> {
            Some(self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn principal(identifier: &str) -> OwnerPrincipal {
        OwnerPrincipal::declare("apple-generic", "3QMEVK549R", identifier).unwrap()
    }

    /// The real verifier has no token to work with in a unit test, and must
    /// say no rather than assume.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_verifier_refuses_a_caller_it_cannot_identify() {
        assert_eq!(
            CodeSignatureVerifier.satisfies(None, &principal("com.example.gw")),
            Err(OwnerDenied::NoPeerToken)
        );
    }

    /// Off macOS the platform check comes before everything else — the
    /// verifier says "unsupported", never "no token".
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_real_verifier_refuses_every_caller_off_macos() {
        assert_eq!(
            CodeSignatureVerifier.satisfies(None, &principal("com.example.gw")),
            Err(OwnerDenied::Unsupported)
        );
    }

    /// Against a live process — this one, which is ad-hoc signed — an
    /// Apple-anchored requirement cannot hold. This is the real code path,
    /// not a fake: an unsigned caller is refused by the kernel's own answer.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unsigned_caller_does_not_satisfy_an_owner() {
        use std::os::unix::io::AsRawFd as _;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let token = macos_process_inspect::peer_audit_token(a.as_raw_fd()).unwrap();
        assert!(matches!(
            CodeSignatureVerifier.satisfies(Some(&token), &principal("com.example.gw")),
            Err(OwnerDenied::RequirementUnsatisfied(_))
        ));
    }

    #[test]
    fn a_test_verifier_can_admit_one_principal_and_refuse_another() {
        let v = OnlyPrincipal(principal("com.example.gw"));
        assert_eq!(v.satisfies(None, &principal("com.example.gw")), Ok(()));
        assert!(v.satisfies(None, &principal("com.example.other")).is_err());
    }

    /// DR-0033 §5: both premises present means no warning; anything missing
    /// says which, because the two failures have different remedies.
    #[test]
    fn hardening_warns_about_exactly_what_is_missing() {
        use macos_process_inspect::codesign::{CS_REQUIRE_LV, CS_RUNTIME};

        let both = Hardening::of(&WithFlags(CS_RUNTIME | CS_REQUIRE_LV), None).unwrap();
        assert_eq!(both.warning(), None);

        let no_runtime = Hardening::of(&WithFlags(CS_REQUIRE_LV), None).unwrap();
        assert!(no_runtime.warning().unwrap().contains("hardened runtime"));

        let no_lv = Hardening::of(&WithFlags(CS_RUNTIME), None).unwrap();
        assert!(no_lv.warning().unwrap().contains("library validation"));

        let neither = Hardening::of(&WithFlags(0), None).unwrap();
        assert!(neither.warning().unwrap().contains("neither"));
    }

    /// A verifier that cannot read flags must not be mistaken for one
    /// reporting "nothing enabled" — the warning is advisory, and inventing
    /// one from missing data would train people to ignore it.
    #[test]
    fn unreadable_flags_produce_no_warning_rather_than_a_false_one() {
        assert_eq!(Hardening::of(&AlwaysOwner, None), None);
        assert!(NeverOwner.signing_flags(None).is_none());
    }
}
