//! Re-authentication boundary for TTL-gated secret access.
//!
//! When an entry's *soft* TTL elapses (or a hard-expired command source is
//! regenerated), the core must re-establish that the user is present and
//! authorized before the value is handed back. The real mechanism (TouchID /
//! `LocalAuthentication`, upstream `op` re-prompts, ...) is platform-specific
//! and lives in a later iteration; the core depends only on this [`Authenticator`]
//! trait so the domain stays pure and testable.
//!
//! # Where authentication is required (DESIGN-ja "value ライフサイクル")
//!
//! The design figure assigns re-authentication to two transitions:
//!
//! - **soft TTL expiry → extend**: a still-resident value is stale; re-auth
//!   refreshes it back to Active *without* going upstream.
//! - **hard TTL expiry → regenerate** (command sources only): the value was
//!   zeroized; the upstream command is re-run *and* the user re-authenticates
//!   before the freshly fetched value becomes Active.
//!
//! Both gates live in the [`crate::Store`] layer. The low-level
//! [`crate::CacheEntry::extend`] is deliberately *auth-free* (it only moves the
//! state machine); the [`crate::Store`] layer is the single place that demands
//! authentication. This layering keeps the state machine independently testable
//! and concentrates the "who must authenticate, and when" policy in one spot.

/// What an [`Authenticator`] is being asked to authorize.
///
/// Carries the human-meaningful reason for the prompt so a real implementation
/// (e.g. a TouchID dialog) can show *why* the user is being asked. It never
/// carries the secret value itself.
///
/// # Requester (who is asking)
///
/// [`AuthContext::requester`] optionally carries the process ancestry chain of
/// the process that triggered the unlock (as produced by
/// [`crate::ProcessInspector::ancestry`]: index 0 is the immediate requester,
/// then each successive parent toward `init`/`launchd`). A real
/// [`Authenticator`] can fold this into the prompt — e.g. "Allow **ssh** (via
/// git) to use key `GITHUB_TOKEN`?" — so the human sees *who* wants the secret,
/// not just *which* secret.
///
/// `None` means the requester is unknown: the call originated **in-process**
/// (the embedding daemon asked on its own behalf, with no external peer), or the
/// adapter chose not to attach process facts. This is distinct from "an empty
/// chain": there is no `Some(vec![])` convention — absence of a requester is
/// always `None`.
///
/// This is descriptive context only. Whether a given chain is *allowed* to touch
/// a key (policy interpretation) stays in the adapter layer (DR-0004); the core
/// neither matches nor enforces process identity here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    /// The key whose value is being unlocked.
    pub key: String,
    /// The operation that triggered the prompt.
    pub operation: AuthOperation,
    /// The requesting process's ancestry chain, or `None` for an in-process /
    /// unattributed call. See the type-level "Requester" note.
    pub requester: Option<Vec<crate::process::ProcessInfo>>,
}

impl AuthContext {
    /// Re-auth to extend a soft-expired entry under `key`, requester unknown.
    pub fn extend(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            operation: AuthOperation::Extend,
            requester: None,
        }
    }

    /// Re-auth to regenerate a hard-expired command entry under `key`,
    /// requester unknown.
    pub fn regenerate(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            operation: AuthOperation::Regenerate,
            requester: None,
        }
    }

    /// Attach the requesting process's ancestry chain.
    ///
    /// Builder style: `AuthContext::extend("K").with_requester(chain)`. Passing
    /// the chain produced by [`crate::ProcessInspector::ancestry`] lets an
    /// [`Authenticator`] name the requester in its prompt.
    pub fn with_requester(mut self, requester: Vec<crate::process::ProcessInfo>) -> Self {
        self.requester = Some(requester);
        self
    }
}

/// The lifecycle transition that demands re-authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOperation {
    /// Extend a soft-expired entry back to Active.
    Extend,
    /// Regenerate a hard-expired command entry upstream.
    Regenerate,
}

/// Re-authenticates the user before a TTL-gated value is unlocked.
///
/// The real implementation (TouchID, etc.) arrives in a later iteration. The
/// core only relies on this trait so tests can substitute a fake.
pub trait Authenticator {
    /// Authorize the operation described by `ctx`.
    ///
    /// Returns `Ok(())` to allow the caller to proceed, or [`AuthError`] to deny.
    fn authenticate(&self, ctx: &AuthContext) -> Result<(), AuthError>;
}

/// Reason an [`Authenticator`] declined to authorize an operation.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The user actively rejected the prompt (cancel / failed biometric).
    Denied,
    /// The authentication mechanism was unavailable or errored out.
    Unavailable {
        /// Human-readable detail (must not contain secret material).
        message: String,
    },
}

impl AuthError {
    /// Construct an [`AuthError::Unavailable`] with a message.
    pub fn unavailable(message: impl Into<String>) -> Self {
        AuthError::Unavailable {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Denied => write!(f, "re-authentication denied"),
            AuthError::Unavailable { message } => {
                write!(f, "re-authentication unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// An [`Authenticator`] that always approves. For tests and "no re-auth" setups.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl Authenticator for AllowAll {
    fn authenticate(&self, _ctx: &AuthContext) -> Result<(), AuthError> {
        Ok(())
    }
}

/// An [`Authenticator`] that always denies (with [`AuthError::Denied`]). For tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAll;

impl Authenticator for DenyAll {
    fn authenticate(&self, _ctx: &AuthContext) -> Result<(), AuthError> {
        Err(AuthError::Denied)
    }
}

/// A test [`Authenticator`] that records every call and replies with a fixed
/// verdict.
///
/// Lets a test assert *whether* and *with what context* authentication was
/// requested, which is how the layering ("Store gates, entry does not") is
/// verified.
#[derive(Debug)]
pub struct RecordingAuthenticator {
    allow: bool,
    calls: std::cell::RefCell<Vec<AuthContext>>,
}

impl RecordingAuthenticator {
    /// A recorder that approves every request.
    pub fn allowing() -> Self {
        Self {
            allow: true,
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// A recorder that denies every request.
    pub fn denying() -> Self {
        Self {
            allow: false,
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// The contexts passed to [`Authenticator::authenticate`], in call order.
    pub fn calls(&self) -> Vec<AuthContext> {
        self.calls.borrow().clone()
    }

    /// How many times authentication was requested.
    pub fn call_count(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl Authenticator for RecordingAuthenticator {
    fn authenticate(&self, ctx: &AuthContext) -> Result<(), AuthError> {
        self.calls.borrow_mut().push(ctx.clone());
        if self.allow {
            Ok(())
        } else {
            Err(AuthError::Denied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_authorizes() {
        let a = AllowAll;
        assert!(a.authenticate(&AuthContext::extend("K")).is_ok());
    }

    #[test]
    fn deny_all_rejects_with_denied() {
        let a = DenyAll;
        assert_eq!(
            a.authenticate(&AuthContext::extend("K")),
            Err(AuthError::Denied)
        );
    }

    #[test]
    fn recording_authenticator_records_contexts_in_order() {
        let a = RecordingAuthenticator::allowing();
        a.authenticate(&AuthContext::extend("A")).unwrap();
        a.authenticate(&AuthContext::regenerate("B")).unwrap();
        assert_eq!(a.call_count(), 2);
        let calls = a.calls();
        assert_eq!(calls[0], AuthContext::extend("A"));
        assert_eq!(calls[1], AuthContext::regenerate("B"));
    }

    #[test]
    fn recording_denier_records_then_denies() {
        let a = RecordingAuthenticator::denying();
        assert_eq!(
            a.authenticate(&AuthContext::extend("X")),
            Err(AuthError::Denied)
        );
        assert_eq!(a.call_count(), 1);
    }

    #[test]
    fn auth_context_constructors_set_operation() {
        assert_eq!(AuthContext::extend("k").operation, AuthOperation::Extend);
        assert_eq!(
            AuthContext::regenerate("k").operation,
            AuthOperation::Regenerate
        );
    }

    #[test]
    fn auth_error_displays_without_leaking() {
        assert!(AuthError::Denied.to_string().contains("denied"));
        let u = AuthError::unavailable("no biometric hardware");
        assert!(u.to_string().contains("no biometric hardware"));
    }

    #[test]
    fn auth_context_requester_defaults_to_none() {
        assert_eq!(AuthContext::extend("k").requester, None);
        assert_eq!(AuthContext::regenerate("k").requester, None);
    }

    #[test]
    fn auth_context_with_requester_attaches_chain() {
        use crate::process::ProcessInfo;
        let chain = vec![ProcessInfo {
            pid: 42,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/usr/bin/ssh")),
            start_time: None,
        }];
        let ctx = AuthContext::extend("GITHUB_TOKEN").with_requester(chain.clone());
        assert_eq!(ctx.requester.as_deref(), Some(chain.as_slice()));
        // The immediate requester is at index 0; an Authenticator can name it.
        assert_eq!(ctx.requester.unwrap()[0].name(), Some("ssh"));
    }
}
