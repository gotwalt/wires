//! Node identity and the byte-newtypes that ride on it.
//!
//! Per the project convention, no public API exposes a bare `[u8; N]` or
//! `Vec<u8>`: every identifier or opaque blob is a newtype so the type system
//! tells a node id apart from a signature.

use serde::{Deserialize, Serialize};

/// An Ed25519 public key — a node's address on the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

/// A detached signature over a signed payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

/// A node's signing identity (holds the secret key).
///
/// Placeholder: references the `ed25519-dalek` type so the dependency links;
/// key generation and signing land in a later step.
pub struct NodeIdentity {
    #[allow(dead_code)]
    signing_key: ed25519_dalek::SigningKey,
}
