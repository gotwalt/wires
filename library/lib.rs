//! `library`: shared types for the wires session layer.
//!
//! The module layout mirrors the shared mechanics of `docs/committed-roster.md`:
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
//! Remote CLIs with an observable call log build on both:
//!
//! - [`invoke`] — the [`Invocation`] (tool + [`Argv`]) a dialer asks a
//!   multi-tool responder to run.
//! - [`audit`] — the [`AuditRecord`]s a responder publishes about each call.
//! - [`idp`] — [`IdentityClaim`]: an IdP-signed ID token bound to a node key,
//!   and [`verify_claim`], which every reader runs against the issuer's [`Jwks`].
//! - [`record`] — [`ChannelRecord`], how both ride a topic as message text.
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
//!
//! # Example: commit a roster, publish to a topic, read it back
//!
//! The multiway path in one pass — commit the member set, mint and seal the
//! fabric key, derive the topic, then seal, admit, verify, chain-check, and
//! open a message. Every step here is pure; the async/iroh half lives in the
//! `wires` binary.
//!
//! ```
//! use library::{
//!     check_topic_admission, classify_link, next_prev_hash, FabricKey, LinkStatus,
//!     NodeIdentity, Roster, RosterVersion, SealedFabricKey, Seq, TopicEnvelope, TopicId,
//! };
//!
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let alice = NodeIdentity::from_seed([2u8; 32]);
//! let bob = NodeIdentity::from_seed([3u8; 32]);
//!
//! // The root commits the member set; each member gets an inclusion proof.
//! let mut roster = Roster::new(root.node_id());
//! roster.insert(alice.node_id());
//! roster.insert(bob.node_id());
//! let (head, proofs) = roster.commit(&root, 0, i64::MAX).unwrap();
//! let proof_of = |who| proofs.iter().find(|(m, _)| *m == who).unwrap().1.clone();
//!
//! // Bob admits Alice: her proof recomputes the root of a head he trusts.
//! // Neither side takes the other's word for who is calling — `caller` is the
//! // key iroh authenticated, never a wire field.
//! let admission =
//!     check_topic_admission(&head, &head, &proof_of(alice.node_id()), root.node_id(), alice.node_id(), 0)
//!         .unwrap();
//! assert_eq!(admission.version, head.version);
//! assert_eq!(admission.adopt, None); // same head — nothing new to persist
//!
//! // That commit mints one fabric key, sealed to each member individually.
//! let key = FabricKey::generate();
//! let for_bob = SealedFabricKey::seal(&root, bob.node_id(), head.version, &key).unwrap();
//! let bobs_key = for_bob.open(&bob, root.node_id()).unwrap();
//!
//! // Alice publishes. The topic id is derived, not registered: Bob computes
//! // the identical id from the same fabric and name.
//! let topic = TopicId::derive(root.node_id(), "ops");
//! let genesis = TopicEnvelope::seal(
//!     &alice,
//!     topic,
//!     Seq::ZERO,
//!     next_prev_hash(None),
//!     head.version,
//!     &key,
//!     1_700_000_000,
//!     b"ship it",
//! )
//! .unwrap();
//!
//! // Bob ingests: verify the signature, classify the chain link, then decrypt.
//! assert!(genesis.verify().is_ok());
//! assert_eq!(classify_link(&genesis, None, None).unwrap(), LinkStatus::Ok);
//! assert_eq!(genesis.open(&bobs_key).unwrap(), b"ship it");
//!
//! // A member removed by the next commit keeps its signing key, but the key
//! // that commit mints is never sealed to it — confidentiality loss is
//! // immediate, not "eventually, once the mesh notices".
//! let evicted = NodeIdentity::from_seed([4u8; 32]);
//! assert!(SealedFabricKey::seal(&root, bob.node_id(), RosterVersion(2), &key)
//!     .unwrap()
//!     .open(&evicted, root.node_id())
//!     .is_err());
//! ```

pub mod admission;
pub mod audit;
pub mod chain;
pub mod envelope;
pub mod error;
pub mod fabric_key;
pub mod grant;
pub mod identity;
pub mod idp;
pub mod invoke;
pub mod membership;
pub mod policy;
pub mod record;
pub mod replay;
pub mod roster;
pub mod session;
pub mod ticket;
pub mod topic;

mod codec;
#[cfg(test)]
mod idp_vectors;

pub use admission::{
    Admission, AdmitFrame, MAX_ADMIT_FRAME, TOPIC_ADMIT_ALPN, adopt_if_newer, check_topic_admission,
};
pub use audit::{AuditRecord, CallId, OutputDigest, OutputHasher};
pub use chain::{ChainState, LinkStatus, classify_link, next_prev_hash};
pub use envelope::{
    Ciphertext, ENVELOPE_NONCE_CONTEXT, ENVELOPE_V1, MessageHash, MessageNonce, Seq, TopicEnvelope,
};
pub use error::{Error, IdTokenError, Result};
pub use fabric_key::{FabricKey, SEALED_KEY_CONTEXT, SEALED_KEY_V1, SealedBox, SealedFabricKey};
pub use grant::{AlgorithmId, Grant, Scope};
pub use identity::{NodeId, NodeIdentity, Signature};
pub use idp::{
    Audience, CLOCK_SKEW_SECS, IdToken, IdentityClaim, Issuer, Jwk, Jwks, OIDC_NONCE_CONTEXT,
    OidcNonce, Principal, verify_claim,
};
pub use invoke::{Argv, Invocation, MAX_ARGS, MAX_ARGV_BYTES, MAX_TOOL_NAME, ToolName};
pub use membership::{MEMBERSHIP_V1, Membership};
pub use policy::{Crl, check_accept, check_inclusion, check_roster_inclusion};
pub use record::{ChannelRecord, RECORD_V1};
pub use replay::{MAX_REPLAY_FRAME, ReplayFrame, TOPIC_REPLAY_ALPN};
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
