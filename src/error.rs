//! Error type and process exit codes.
//!
//! Every variant carries only owned `String` messages that this crate builds
//! deliberately, so a secret can never be captured by accident through a
//! `#[from]` conversion.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Categories of failure the CLI can report, each mapped to a stable exit code.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bad arguments or values that clap could not reject on its own.
    #[error("{0}")]
    Usage(String),
    /// Missing or invalid configuration.
    #[error("{0}")]
    Config(String),
    /// The credential store could not be read or written.
    #[error("{0}")]
    Credential(String),
    /// The server rejected our credentials.
    #[error("{0}")]
    Auth(String),
    /// The requested reminder or collection does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The resource changed on the server since we read it.
    #[error("{0}")]
    Conflict(String),
    /// Transport, DNS, or TLS failure.
    #[error("{0}")]
    Network(String),
    /// The server answered, but not in a way we can use.
    #[error("{0}")]
    Server(String),
    /// Local I/O failure.
    #[error("{0}")]
    Io(String),
}

/// Exit codes. Stable contract for scripts and agents.
pub mod exit {
    /// Unexpected internal failure.
    pub const FAILURE: i32 = 1;
    /// Invalid arguments or values (matches clap's own usage exit code).
    pub const USAGE: i32 = 2;
    /// Configuration missing or invalid.
    pub const CONFIG: i32 = 3;
    /// Credential store unavailable, locked, or empty.
    pub const CREDENTIAL: i32 = 4;
    /// Server rejected the credentials.
    pub const AUTH: i32 = 5;
    /// Reminder or collection not found.
    pub const NOT_FOUND: i32 = 6;
    /// Concurrent modification detected.
    pub const CONFLICT: i32 = 7;
    /// Network, DNS, or TLS failure.
    pub const NETWORK: i32 = 8;
    /// Unusable server response.
    pub const SERVER: i32 = 9;
}

impl Error {
    /// Process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => exit::USAGE,
            Error::Config(_) => exit::CONFIG,
            Error::Credential(_) => exit::CREDENTIAL,
            Error::Auth(_) => exit::AUTH,
            Error::NotFound(_) => exit::NOT_FOUND,
            Error::Conflict(_) => exit::CONFLICT,
            Error::Network(_) => exit::NETWORK,
            Error::Server(_) => exit::SERVER,
            Error::Io(_) => exit::FAILURE,
        }
    }

    /// Short machine-readable tag, used by `--json` error envelopes.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Usage(_) => "usage",
            Error::Config(_) => "config",
            Error::Credential(_) => "credential",
            Error::Auth(_) => "auth",
            Error::NotFound(_) => "not_found",
            Error::Conflict(_) => "conflict",
            Error::Network(_) => "network",
            Error::Server(_) => "server",
            Error::Io(_) => "io",
        }
    }

    /// Convenience constructor for usage errors.
    pub fn usage(message: impl fmt::Display) -> Self {
        Error::Usage(message.to_string())
    }

    /// Convenience constructor for configuration errors.
    pub fn config(message: impl fmt::Display) -> Self {
        Error::Config(message.to_string())
    }

    /// Convenience constructor for credential errors.
    pub fn credential(message: impl fmt::Display) -> Self {
        Error::Credential(message.to_string())
    }

    /// Convenience constructor for server-protocol errors.
    pub fn server(message: impl fmt::Display) -> Self {
        Error::Server(message.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_and_stable() {
        let cases = [
            (Error::Usage("x".into()), 2),
            (Error::Config("x".into()), 3),
            (Error::Credential("x".into()), 4),
            (Error::Auth("x".into()), 5),
            (Error::NotFound("x".into()), 6),
            (Error::Conflict("x".into()), 7),
            (Error::Network("x".into()), 8),
            (Error::Server("x".into()), 9),
            (Error::Io("x".into()), 1),
        ];
        for (err, code) in cases {
            assert_eq!(err.exit_code(), code, "{err:?}");
        }
    }

    #[test]
    fn kinds_are_snake_case_tags() {
        assert_eq!(Error::NotFound("x".into()).kind(), "not_found");
        assert_eq!(Error::Auth("x".into()).kind(), "auth");
    }
}
