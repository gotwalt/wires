//! Call records a responder publishes about the CLIs it runs.
//!
//! Every call a `wires serve --audit-topic …` responder handles produces
//! [`AuditRecord`]s on that channel: a [`Started`](AuditRecord::Started) once
//! the caller is authorized, a [`Finished`](AuditRecord::Finished) when the
//! child exits, or a lone [`Denied`](AuditRecord::Denied) when the caller is
//! turned away. The **responder** writes them, stamping the caller id iroh
//! authenticated — not anything the caller claimed — and each record rides a
//! [`TopicEnvelope`](crate::TopicEnvelope) signed by the responder's key and
//! hash-linked to its previous record. So the log can't be forged by the
//! agent, isn't held by a gateway, and any member of the channel can observe
//! it without access to either end of the call.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::Principal;
use crate::invoke::{Argv, ToolName};

/// Correlates a call's [`Started`](AuditRecord::Started) and
/// [`Finished`](AuditRecord::Finished) records. 16 random bytes, hex on the
/// wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CallId([u8; 16]);

impl CallId {
    /// A fresh random call id.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 32 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::BadKeyLength)?))
    }
}

impl TryFrom<String> for CallId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::from_hex(&s)
    }
}

impl From<CallId> for String {
    fn from(c: CallId) -> String {
        c.hex()
    }
}

/// BLAKE3 digest of a call's complete stdout, hex on the wire. Lets an
/// observer check a result someone later presents without the log carrying
/// the output itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OutputDigest([u8; 32]);

impl OutputDigest {
    /// Wrap a finished BLAKE3 hash.
    pub fn from_hash(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for OutputDigest {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::BadKeyLength)?))
    }
}

impl From<OutputDigest> for String {
    fn from(d: OutputDigest) -> String {
        d.hex()
    }
}

/// One entry in a responder's call log. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditRecord {
    /// The caller passed every gate and the child is being spawned.
    Started {
        /// Pairs this record with its `Finished`.
        call: CallId,
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The caller's IdP identity, when the responder verified one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
        /// The exposed tool that ran.
        tool: ToolName,
        /// The caller-supplied arguments.
        argv: Argv,
        /// The roster version the caller was admitted under, when enforced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        roster_version: Option<u64>,
        /// Unix milliseconds at authorization.
        at_ms: i64,
    },
    /// The child exited (or was killed when the caller hung up).
    Finished {
        /// Pairs this record with its `Started`.
        call: CallId,
        /// The child's exit code (`-1` if killed by a signal).
        exit: i32,
        /// Wall time from spawn to exit.
        duration_ms: u64,
        /// Bytes the child wrote to stdout.
        stdout_bytes: u64,
        /// Bytes the child wrote to stderr.
        stderr_bytes: u64,
        /// BLAKE3 of the complete stdout.
        stdout_digest: OutputDigest,
    },
    /// The caller was refused before anything ran.
    Denied {
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The tool it asked for, if it got as far as naming one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<ToolName>,
        /// The same reason the caller was sent.
        reason: String,
        /// Unix milliseconds at refusal.
        at_ms: i64,
    },
}
