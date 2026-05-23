//! Session protocol frames carried over the (future) iroh bi-stream.

use serde::{Deserialize, Serialize};

use crate::grant::Grant;

/// One framed message on a capability-scoped session.
///
/// Placeholder: there is no transport yet — the iroh wiring and the actual
/// stdio bridge land in a later step.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Frame {
    /// Opening frame: the dialer presents its grant for verification.
    Handshake {
        /// The grant proving the dialer may open this session.
        grant: Grant,
    },
    /// A chunk of the child process's stdin.
    Stdin(Vec<u8>),
    /// A chunk of the child process's stdout.
    Stdout(Vec<u8>),
    /// A chunk of the child process's stderr.
    Stderr(Vec<u8>),
    /// The child process's exit code.
    Exit(i32),
}
