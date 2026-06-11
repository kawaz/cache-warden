//! Error types for the authsock adapter.

use thiserror::Error;

/// Error type for the authsock adapter.
///
/// Only the variants exercised by the protocol codec are defined here. Further
/// variants (SSH key parsing, policy, key store, ...) are introduced alongside
/// the features that need them in later port iterations.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error while reading from / writing to a connection.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A malformed or out-of-bounds SSH agent protocol message.
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// Result type alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
