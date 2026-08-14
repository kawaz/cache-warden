//! Errors surfaced by the vault.
//!
//! Every variant is fail-closed: a vault that cannot be parsed, cannot be
//! authenticated, or declares a format this build does not understand is
//! refused outright. Nothing here degrades to "open it anyway with the parts
//! that still parse" — DR-0034 §1d requires that an entry whose accompanying
//! authorization cannot be restored is not restored at all, and the same
//! discipline applies one level up to the file as a whole.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::format::{FORMAT_VERSION, MIN_SUPPORTED_VERSION};

/// Anything that can go wrong opening, unlocking, or committing a vault.
#[derive(Debug)]
pub enum VaultError {
    /// The file does not start with the vault magic — it is not a vault file.
    BadMagic,
    /// The file's `format_version` is outside `[MIN_SUPPORTED_VERSION,
    /// FORMAT_VERSION]`.
    ///
    /// A version *above* [`FORMAT_VERSION`] is the downgrade case DR-0034 §1a
    /// rejects: this build would silently drop the fields it does not know
    /// about (guard records, owner principals, CAS versions) the next time it
    /// wrote the file back, quietly deleting authorization. Refusing to read
    /// is the only safe response.
    UnsupportedVersion {
        /// The version the file declared.
        got: u32,
    },
    /// The file declared an AEAD or KDF algorithm id this build does not
    /// implement. Distinct from [`VaultError::UnsupportedVersion`] because a
    /// same-version file can still name an algorithm added later.
    UnsupportedAlgorithm {
        /// Which algorithm field carried the unknown id.
        field: &'static str,
        /// The unrecognized id.
        id: u16,
    },
    /// A slot declared a `kind` this build does not know. Fail-closed rather
    /// than skipping the slot: an unknown slot is still a recipient that can
    /// decrypt the vault, and silently hiding it from `slots()` would make
    /// "who can open this vault" a lie.
    UnknownSlotKind {
        /// The unrecognized kind id.
        id: u16,
    },
    /// The file ended before a declared field or length-prefixed blob could be
    /// read in full (truncation, or a corrupted length prefix claiming more
    /// bytes than exist).
    Truncated,
    /// A length-prefixed field declared a size beyond what this build will
    /// allocate for it. Bounds an attacker-controlled length read off disk
    /// before any authentication has happened.
    FieldTooLarge {
        /// Which field carried the oversized length.
        field: &'static str,
        /// The declared length.
        len: u64,
    },
    /// The file is larger than any structurally legal vault, as reported by
    /// its metadata. Checked before the file is read so an oversized file
    /// planted at the vault path cannot force a large allocation.
    FileTooLarge {
        /// The file's size in bytes.
        len: u64,
    },
    /// A fixed-width field held a structurally invalid value (a UTF-8 string
    /// that is not UTF-8, a slot count of zero, a duplicate slot id).
    Malformed {
        /// What was wrong, in terms of the format, not the parser.
        reason: &'static str,
    },
    /// AEAD authentication failed.
    ///
    /// Deliberately one variant for every decryption step (slot private key,
    /// wrapped DEK, body). The three are indistinguishable to an attacker
    /// probing a vault, and the honest user-facing meaning is the same: the
    /// key material supplied does not match this file, or the file has been
    /// altered since it was written. `stage` names the step for diagnostics
    /// without implying the caller can act differently on each.
    DecryptFailed {
        /// Which decryption step failed.
        stage: &'static str,
    },
    /// No slot in the vault matches the credential supplied to unlock.
    NoMatchingSlot,
    /// A compare-and-swap write was refused: the entry's version is not the
    /// one the caller expected, so something else wrote in between (DR-0034
    /// §4). No write happened — the caller re-reads and decides.
    CasMismatch {
        /// The entry's actual version. `0` means the entry does not exist.
        current: u64,
    },
    /// A refresh is already claimed on this entry and has not lapsed
    /// (DR-0034 §4). The caller should wait for the value rather than call the
    /// provider itself.
    AlreadyClaimed {
        /// When the holding claim lapses, in milliseconds since the Unix epoch.
        expires_at_epoch_ms: u64,
    },
    /// The entry has an active claim and the write did not present a claim
    /// token. Take the claim (or wait for the holder) rather than writing
    /// around it.
    ClaimRequired {
        /// When the holding claim lapses, in milliseconds since the Unix epoch.
        expires_at_epoch_ms: u64,
    },
    /// A claim token was presented but is not the one the active claim holds.
    ///
    /// The usual cause is the exact race the token exists to catch: this
    /// caller's claim lapsed, another caller took it, and this write arrived
    /// late (DR-0034 §4).
    ClaimTokenMismatch,
    /// A claim token was not a well-formed token at all (wrong length, or a
    /// character outside base64url).
    MalformedClaimToken,
    /// The named entry does not exist in this vault.
    EntryNotFound,
    /// The requested slot id is not present in this vault.
    SlotNotFound,
    /// Removing this slot would leave the vault with no recipients at all,
    /// making it permanently unopenable. DR-0034 §9 makes a recovery slot
    /// mandatory at initialization for the same reason.
    LastSlot,
    /// The recovery code could not be decoded (wrong length, or a character
    /// outside the Crockford Base32 alphabet).
    MalformedRecoveryCode,
    /// The file's `vault_id` did not match the one the caller expected —
    /// the file at this path is a different vault (a restored backup, a
    /// development vault dropped into the production path).
    VaultIdMismatch,
    /// An X25519 exchange produced a non-contributory (all-zero) shared
    /// secret, meaning a slot public key was a low-order point. Only reachable
    /// from a crafted file; refusing beats deriving a wrap key everyone knows.
    NonContributoryExchange,
    /// The body plaintext decrypted correctly but did not parse as the entry
    /// schema.
    MalformedBody(serde_json::Error),
    /// Filesystem failure, with the path it happened on.
    Io {
        /// The path being operated on.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

impl VaultError {
    /// Attach `path` to an [`io::Error`].
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        VaultError::Io {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::BadMagic => write!(f, "not a cache-warden vault file (bad magic)"),
            VaultError::UnsupportedVersion { got } => write!(
                f,
                "vault format version {got} is not supported by this build \
                 (supports {MIN_SUPPORTED_VERSION}..={FORMAT_VERSION}); \
                 upgrade cache-warden rather than letting an older build rewrite the vault"
            ),
            VaultError::UnsupportedAlgorithm { field, id } => {
                write!(f, "vault declares unknown {field} {id}")
            }
            VaultError::UnknownSlotKind { id } => {
                write!(f, "vault contains a slot of unknown kind {id}")
            }
            VaultError::Truncated => write!(f, "vault file ended unexpectedly (truncated)"),
            VaultError::FieldTooLarge { field, len } => {
                write!(
                    f,
                    "vault field {field} declares an implausible length {len}"
                )
            }
            VaultError::FileTooLarge { len } => write!(
                f,
                "the file at this path is {len} bytes, larger than any valid vault"
            ),
            VaultError::Malformed { reason } => write!(f, "malformed vault file: {reason}"),
            VaultError::DecryptFailed { stage } => write!(
                f,
                "could not decrypt vault {stage}: wrong key material, or the file was altered"
            ),
            VaultError::NoMatchingSlot => {
                write!(f, "no slot in this vault matches the credential supplied")
            }
            VaultError::CasMismatch { current } => {
                if *current == 0 {
                    write!(
                        f,
                        "the entry does not exist; re-read it and retry with the version you find"
                    )
                } else {
                    write!(
                        f,
                        "the entry changed since it was read (it is now at version {current}); \
                         re-read it and retry"
                    )
                }
            }
            VaultError::AlreadyClaimed { .. } => write!(
                f,
                "another refresh is already in progress for this entry; \
                 wait for the new value rather than refreshing it again"
            ),
            VaultError::ClaimRequired { .. } => write!(
                f,
                "a refresh is in progress for this entry; \
                 present that claim's token to write, or wait for it to finish"
            ),
            VaultError::ClaimTokenMismatch => write!(
                f,
                "this claim token is not the one currently holding the entry: \
                 the claim lapsed and another caller took it. Re-read and claim again"
            ),
            VaultError::MalformedClaimToken => write!(
                f,
                "claim token is not well-formed: expected 22 base64url characters"
            ),
            VaultError::EntryNotFound => write!(f, "no such entry in this vault"),
            VaultError::SlotNotFound => write!(f, "no such slot in this vault"),
            VaultError::LastSlot => write!(
                f,
                "refusing to remove the only remaining slot: the vault would become unopenable. \
                 Add a replacement slot first"
            ),
            VaultError::MalformedRecoveryCode => write!(
                f,
                "recovery code is not well-formed: expected 52 Crockford Base32 characters \
                 (case, spaces and hyphens are ignored)"
            ),
            VaultError::VaultIdMismatch => write!(
                f,
                "the file at this path holds a different vault than expected (vault_id mismatch)"
            ),
            VaultError::NonContributoryExchange => write!(
                f,
                "malformed vault file: a slot public key is a low-order point"
            ),
            // The serde error text can echo fragments of decrypted plaintext,
            // so it stays out of Display and is reachable only via `source`.
            VaultError::MalformedBody(_) => {
                write!(f, "vault contents did not parse as the entry schema")
            }
            VaultError::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultError::MalformedBody(e) => Some(e),
            VaultError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
