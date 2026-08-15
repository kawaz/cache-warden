//! Entry ownership by code-signing identity (draft-DR-0033).
//!
//! # An owner is not another guard constraint
//!
//! DR-0030's constraints (`same-user`, `same-ancestor`, `command=`) partition
//! one uid's processes against *mistakes* — a misrouted request, a wrong
//! script. None of them survives a same-uid attacker, because none is built on
//! anything the attacker cannot also produce: a name can be reused, a path can
//! be planted, an ancestry can be arranged.
//!
//! An owner principal is built on a code signature, which the OS verifies and
//! an attacker cannot forge without the signing key. That difference is what
//! makes it worth authorizing *writes* and *deletes* with, not just reads —
//! and DR-0033 §3 does exactly that, because a principal that only gated reads
//! could be taken over by whoever set the key first.
//!
//! # The requirement is assembled here, never accepted from a caller
//!
//! A code-signing requirement is a policy written in Apple's Requirement
//! Language, and its failure mode is asymmetric: a misspelling does not error,
//! it evaluates — usually to something weaker than intended. `anchor apple
//! generic` mistyped is a requirement that still parses and still matches
//! things. So callers supply three structured fields and this module builds
//! the string (DR-0033 §2). There is no escape hatch to pass a requirement
//! through verbatim; adding one would reintroduce exactly the accident the
//! structure exists to prevent.

use serde::{Deserialize, Serialize};

/// The trust anchor a principal's signature must chain to.
///
/// An enum rather than a string because these are the only two answers that
/// mean anything, and an unrecognized third would have to become either an
/// error or a silently weaker requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAnchor {
    /// Apple's generic anchor: what a Developer ID or App Store signature
    /// chains to. The ordinary choice for third-party software.
    AppleGeneric,
    /// Apple's own anchor: only software Apple itself signed.
    Apple,
}

impl SigningAnchor {
    /// Parse the wire / CLI spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "apple-generic" => Some(SigningAnchor::AppleGeneric),
            "apple" => Some(SigningAnchor::Apple),
            _ => None,
        }
    }

    /// The spelling this anchor is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningAnchor::AppleGeneric => "apple-generic",
            SigningAnchor::Apple => "apple",
        }
    }
}

/// Why a declared principal was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerDeclError {
    /// The anchor is not one this build knows.
    UnknownAnchor(String),
    /// A field was empty.
    Empty(&'static str),
    /// A field contained a character that has meaning inside a requirement
    /// string, or is otherwise not plausibly part of a team id or identifier.
    IllegalCharacter {
        /// Which field.
        field: &'static str,
        /// The offending character.
        ch: char,
    },
    /// A field was longer than anything Apple issues.
    TooLong {
        /// Which field.
        field: &'static str,
        /// The cap it exceeded.
        max: usize,
    },
}

impl std::fmt::Display for OwnerDeclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnerDeclError::UnknownAnchor(a) => write!(
                f,
                "unknown signing anchor {a:?}: use \"apple-generic\" for Developer ID or App \
                 Store signatures, or \"apple\" for software Apple itself signed"
            ),
            OwnerDeclError::Empty(field) => {
                write!(f, "the {field} of a signed-by declaration cannot be empty")
            }
            OwnerDeclError::IllegalCharacter { field, ch } => write!(
                f,
                "the {field} of a signed-by declaration cannot contain {ch:?}: it goes into a \
                 code-signing requirement, where such a character would change what the \
                 requirement means"
            ),
            OwnerDeclError::TooLong { field, max } => {
                write!(
                    f,
                    "the {field} of a signed-by declaration is limited to {max} characters"
                )
            }
        }
    }
}

impl std::error::Error for OwnerDeclError {}

/// Longest accepted team id. Apple issues ten characters; the cap is a
/// sanity bound rather than a format claim.
const MAX_TEAM_ID: usize = 64;
/// Longest accepted signing identifier. Bundle-id shaped in practice.
const MAX_IDENTIFIER: usize = 255;

/// The principal that owns an entry: one code-signing identity.
///
/// All three fields are required together (DR-0033 §6). "Any binary from this
/// team" and "any binary with this identifier" are both looser than they look
/// to whoever reads the declaration later, so neither is expressible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPrincipal {
    /// The anchor the signature must chain to.
    pub anchor: SigningAnchor,
    /// The Apple Developer Team Identifier.
    pub team_id: String,
    /// The signing identifier (bundle id shaped).
    pub identifier: String,
}

impl OwnerPrincipal {
    /// Validate a declaration and build the principal.
    ///
    /// Everything that could change the meaning of the assembled requirement
    /// is rejected here rather than escaped, so there is exactly one shape of
    /// requirement this code can ever produce.
    pub fn declare(anchor: &str, team_id: &str, identifier: &str) -> Result<Self, OwnerDeclError> {
        let anchor = SigningAnchor::parse(anchor)
            .ok_or_else(|| OwnerDeclError::UnknownAnchor(anchor.to_string()))?;
        check_field("team id", team_id, MAX_TEAM_ID, is_team_id_char)?;
        check_field("identifier", identifier, MAX_IDENTIFIER, is_identifier_char)?;
        Ok(OwnerPrincipal {
            anchor,
            team_id: team_id.to_string(),
            identifier: identifier.to_string(),
        })
    }

    /// The code-signing requirement this principal means.
    ///
    /// Both predicates are load-bearing. The anchor alone would admit anything
    /// signed under Apple's hierarchy — which is most software on the machine.
    /// The identifier alone would admit anyone who signed their own binary
    /// with the same name, ad-hoc or otherwise. Together they name one team's
    /// one program.
    pub fn requirement(&self) -> String {
        let anchor = match self.anchor {
            SigningAnchor::AppleGeneric => "anchor apple generic",
            SigningAnchor::Apple => "anchor apple",
        };
        format!(
            "{anchor} and certificate leaf[subject.OU] = \"{}\" and identifier \"{}\"",
            self.team_id, self.identifier
        )
    }

    /// A one-line description for `kv list` and diagnostics.
    ///
    /// Value-free by construction: a principal is public policy, not a secret.
    /// What is deliberately absent is any *setter* identity — who declared it
    /// stays unreported, as DR-0030 §4 requires of every guard surface.
    pub fn summary(&self) -> String {
        format!(
            "{} team={} identifier={}",
            self.anchor.as_str(),
            self.team_id,
            self.identifier
        )
    }
}

fn check_field(
    field: &'static str,
    value: &str,
    max: usize,
    allowed: fn(char) -> bool,
) -> Result<(), OwnerDeclError> {
    if value.is_empty() {
        return Err(OwnerDeclError::Empty(field));
    }
    if value.len() > max {
        return Err(OwnerDeclError::TooLong { field, max });
    }
    if let Some(ch) = value.chars().find(|c| !allowed(*c)) {
        return Err(OwnerDeclError::IllegalCharacter { field, ch });
    }
    Ok(())
}

/// Team identifiers Apple issues are alphanumeric.
fn is_team_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Signing identifiers are bundle-id shaped: alphanumerics and a few
/// separators. Notably **not** a quote, a backslash, or whitespace — those are
/// what would let a declaration escape the string literal it is placed in.
fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declaration_assembles_the_requirement_it_means() {
        let p = OwnerPrincipal::declare("apple-generic", "3QMEVK549R", "com.example.gateway")
            .expect("a well-formed declaration");
        assert_eq!(
            p.requirement(),
            "anchor apple generic and certificate leaf[subject.OU] = \"3QMEVK549R\" \
             and identifier \"com.example.gateway\""
        );
    }

    #[test]
    fn the_apple_anchor_is_its_own_requirement() {
        let p = OwnerPrincipal::declare("apple", "APPLE00000", "com.apple.something").unwrap();
        assert!(
            p.requirement().starts_with("anchor apple and"),
            "{}",
            p.requirement()
        );
    }

    /// The whole reason declarations are structured: a requirement is a policy
    /// whose typos evaluate rather than error. Anything that could terminate
    /// the string literal or add a clause has to be refused before it reaches
    /// the requirement, not escaped inside it.
    #[test]
    fn nothing_that_could_rewrite_the_requirement_gets_in() {
        for hostile in [
            "com.example\" or anchor trusted",
            "com.example\\",
            "com.example and identifier \"x",
            "com example",
            "com.example\n",
        ] {
            assert!(
                OwnerPrincipal::declare("apple-generic", "3QMEVK549R", hostile).is_err(),
                "identifier {hostile:?} must be refused"
            );
        }
        for hostile in ["3QMEVK549R\"", "3QME VK549", "3QMEVK-549R"] {
            assert!(
                OwnerPrincipal::declare("apple-generic", hostile, "com.example.gateway").is_err(),
                "team id {hostile:?} must be refused"
            );
        }
    }

    /// A misspelled anchor must be an error, never a weaker requirement.
    #[test]
    fn an_unknown_anchor_is_refused_rather_than_interpreted() {
        for spelling in ["apple generic", "apple-Generic", "generic", "", "trusted"] {
            assert!(
                matches!(
                    OwnerPrincipal::declare(spelling, "3QMEVK549R", "com.example.gateway"),
                    Err(OwnerDeclError::UnknownAnchor(_))
                ),
                "anchor {spelling:?} must be refused"
            );
        }
    }

    #[test]
    fn an_empty_field_is_refused() {
        assert!(matches!(
            OwnerPrincipal::declare("apple-generic", "", "com.example.gateway"),
            Err(OwnerDeclError::Empty("team id"))
        ));
        assert!(matches!(
            OwnerPrincipal::declare("apple-generic", "3QMEVK549R", ""),
            Err(OwnerDeclError::Empty("identifier"))
        ));
    }

    /// The summary is for `kv list` and logs. It says which identity owns the
    /// entry and nothing about who declared it (DR-0030 §4).
    #[test]
    fn the_summary_names_the_principal_and_no_one_else() {
        let p =
            OwnerPrincipal::declare("apple-generic", "3QMEVK549R", "com.example.gateway").unwrap();
        let summary = p.summary();
        assert!(summary.contains("3QMEVK549R"), "{summary}");
        assert!(summary.contains("com.example.gateway"), "{summary}");
        assert!(summary.contains("apple-generic"), "{summary}");
    }

    #[test]
    fn a_principal_round_trips_through_serde() {
        let p =
            OwnerPrincipal::declare("apple-generic", "3QMEVK549R", "com.example.gateway").unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<OwnerPrincipal>(&json).unwrap(), p);
        assert!(
            json.contains("apple-generic"),
            "the anchor is kebab-cased: {json}"
        );
    }
}
