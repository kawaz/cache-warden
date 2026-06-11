//! Error types for the authsock adapter.

use thiserror::Error;

/// Error type for the authsock adapter.
///
/// Variants are introduced alongside the features that need them. The protocol
/// codec needs `Io` / `InvalidMessage`; the signer and public-key registry add
/// `KeyStore` for private-key parsing / signing and public-key derivation
/// failures.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error while reading from / writing to a connection.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A malformed or out-of-bounds SSH agent protocol message.
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// A key store / crypto failure: private-key parsing, signing, or
    /// public-key derivation. The message is deliberately secret-free (it never
    /// embeds key material) so it is safe to surface in logs.
    #[error("Key store error: {0}")]
    KeyStore(String),
}

/// Result type alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
