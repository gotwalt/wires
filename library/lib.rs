//! `library`: shared types for the wires session layer.
//!
//! The module layout mirrors `docs/new_plan.md`'s "Shared mechanics":
//!
//! - [`identity`] — the Ed25519 [`NodeIdentity`] and the [`NodeId`] / [`Signature`]
//!   byte-newtypes.
//! - [`grant`] — root-signed, identity-bound, scoped, expiring [`Grant`]s.
//! - [`membership`] — root-signed, offline-verifiable [`Membership`] proof that a
//!   node belongs to a fabric (scope-independent identity).
//! - [`roster`] — the root-signed, versioned [`Roster`] commitment: the
//!   [`RosterHead`], the Merkle [`InclusionProof`], and offline verification.
//! - [`ticket`] — the base64 [`CapabilityTicket`] a dialer presents (the address).
//! - [`policy`] — [`check_accept`] and [`check_inclusion`], the responder's gates.
//! - [`session`] — the [`Frame`] wire codec (the async transport lands later).
//! - [`error`] — the crate [`Error`] and [`Result`].
//!
//! Multiway topics (`docs/phase2-topics.md`) build on the same pieces:
//!
//! - [`topic`] — the derived [`TopicId`] and the unsigned [`TopicTicket`].
//! - [`fabric_key`] — the [`FabricKey`] minted per roster commit and its
//!   root-signed, member-sealed [`SealedFabricKey`].
//! - [`envelope`] — the signed, encrypted, hash-linked [`TopicEnvelope`].
//! - [`chain`] — [`classify_link`], the per-publisher chain truth table.
//! - [`admission`] — the [`AdmitFrame`] codec and [`check_topic_admission`],
//!   the roster gate in front of the gossip mesh.
//! - [`replay`] — the [`ReplayFrame`] codec for peer-symmetric catch-up.
//!
//! # Example: mint a capability, pack a ticket, accept it
//!
//! ```
//! use library::{check_accept, CapabilityTicket, Crl, Grant, NodeIdentity, Scope};
//!
//! // The fabric root, the agent being granted access, and the tool node.
//! let root = NodeIdentity::generate();
//! let agent = NodeIdentity::generate();
//! let target = NodeIdentity::generate().node_id();
//!
//! // Root mints a non-transferable grant binding the agent to a scope.
//! let scope = Scope::new("tools.rg");
//! let grant = Grant::mint(&root, agent.node_id(), scope.clone(), i64::MAX).unwrap();
//!
//! // Pack it into a ticket (the address the dialer presents) and round-trip it.
//! let ticket = CapabilityTicket::new(target, scope, grant.clone());
//! let decoded = CapabilityTicket::decode(&ticket.encode().unwrap()).unwrap();
//! assert_eq!(decoded, ticket);
//!
//! // The responder accepts only when the authenticated caller is the subject.
//! assert!(check_accept(&grant, root.node_id(), agent.node_id(), 0, &Crl::new()).is_ok());
//! ```

pub mod admission;
pub mod chain;
pub mod envelope;
pub mod error;
pub mod fabric_key;
pub mod grant;
pub mod identity;
pub mod membership;
pub mod policy;
pub mod replay;
pub mod roster;
pub mod session;
pub mod ticket;
pub mod topic;

mod codec;

pub use admission::{Admission, AdmitFrame, TOPIC_ADMIT_ALPN, check_topic_admission};
pub use chain::{ChainState, LinkStatus, classify_link, next_prev_hash};
pub use envelope::{Ciphertext, ENVELOPE_V1, MessageHash, Seq, TopicEnvelope};
pub use error::{Error, Result};
pub use fabric_key::{FabricKey, SEALED_KEY_V1, SealedBox, SealedFabricKey};
pub use grant::{AlgorithmId, Grant, Scope};
pub use identity::{NodeId, NodeIdentity, Signature};
pub use membership::{MEMBERSHIP_V1, Membership};
pub use policy::{Crl, check_accept, check_inclusion, check_roster_inclusion};
pub use replay::{ReplayFrame, TOPIC_REPLAY_ALPN};
pub use roster::{
    InclusionProof, MerkleRoot, MerkleStep, ROSTER_HEAD_V1, Roster, RosterHead, RosterVersion, Side,
};
pub use session::{Chunk, Frame};
pub use ticket::CapabilityTicket;
pub use topic::{TopicId, TopicPeer, TopicTicket};

/// Crate version, surfaced so the binaries have something concrete to call
/// while the real surface is still being built out.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
