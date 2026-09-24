//! `library`: shared types for the wires session layer.
//!
//! # Layout
//!
//! The source tree is grouped by concern, three folders beside the crate-wide
//! [`error`] (and the private canonical-JSON `codec`):
//!
//! - `membership/` — who is in: identities, memberships, the accept gate,
//!   and the invite token.
//! - `calls/` — remote CLI calls: the session frames, invocations, audit
//!   records and the host's call log, pushes, and IdP identity.
//! - `services/` — the admin-signed state: roles, the service registry, the
//!   signed [`State`], policy evaluation, and state sync.
//!
//! The folders are a filing system, not a namespace: every module is still
//! declared here at the crate root (`library::state`, `library::session`, …),
//! and the re-exports below are the public surface.
//!
//! - [`identity`] — the Ed25519 [`NodeIdentity`], the [`NodeId`] / [`Signature`]
//!   byte-newtypes, and the [`AlgorithmId`] every signed object carries.
//! - [`membership`] — root-signed, offline-verifiable [`Membership`] proof that a
//!   node belongs to a fabric.
//! - [`policy`] — [`check_inclusion`], the host's credential gate.
//! - [`invite`] — the [`Invite`] token `wires join` installs.
//! - [`session`] — the [`Frame`] wire codec, opened by a [`Hello`] (the async
//!   transport is in `wires`).
//! - [`invoke`] — the [`Invocation`] (service + [`Argv`]) a caller asks a host
//!   to run.
//! - [`audit`] — the [`AuditRecord`]s a host keeps about each call (and each
//!   push).
//! - [`call_log`] — the host's own signed, hash-linked [`LogEntry`] log of
//!   those records, and [`verify_chain`].
//! - [`push`] — a host's [`PushMessage`] to a caller, and the [`InboxFrame`]
//!   codec both delivery paths speak.
//! - [`idp`] — [`IdentityClaim`]: an IdP-signed ID token bound to a node key,
//!   and [`verify_claim`], which a host runs against the issuer's [`Jwks`].
//! - [`role`] — [`RoleName`], [`Matcher`], [`EmailPattern`]: role definitions.
//! - [`registry`] — [`ServiceName`] and the registry entry [`Service`].
//! - [`state`] — the admin-signed, versioned [`State`] / [`SignedState`].
//! - [`access`] — [`authorize`] and [`allowed_services`] over that state.
//! - [`sync`] — the [`StateFrame`] push/pull protocol on [`STATE_ALPN`].
//! - [`error`] — the crate [`Error`] and [`Result`].
//!
//! # Example: sign a state, check a caller
//!
//! Every step is pure; the async/iroh half lives in the `wires` binary.
//!
//! ```
//! use library::{
//!     Matcher, Membership, NodeIdentity, Principal, RoleName, Service, ServiceName, State,
//!     StateVersion, authorize, check_inclusion,
//! };
//!
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]);
//! let alice = NodeIdentity::from_seed([3u8; 32]);
//!
//! // The admin signs who is in, which members host, the roles, and the
//! // service registry — one versioned document.
//! let analyst = RoleName::new("analyst").unwrap();
//! let orders = ServiceName::new("orders-db").unwrap();
//! let mut s = State::new(root.node_id());
//! s.version = StateVersion(1);
//! s.not_after = i64::MAX;
//! s.members.extend([host.node_id(), alice.node_id()]);
//! s.hosts.insert(host.node_id());
//! s.roles.insert(
//!     analyst.clone(),
//!     vec![Matcher { email: Some("*@example.com".parse().unwrap()), ..Default::default() }],
//! );
//! s.services.insert(
//!     orders.clone(),
//!     Service {
//!         description: "Read-only SQL".into(),
//!         allow: vec![analyst.clone()],
//!         hosts: vec![host.node_id()],
//!         readers: vec![],
//!     },
//! );
//! let signed = s.sign(&root).unwrap();
//!
//! // A host checks the caller's membership credential (bound to the key iroh
//! // authenticated), then the registry, against its verified copy.
//! signed.verify(root.node_id()).unwrap();
//! let membership = Membership::mint(&root, alice.node_id(), 0, i64::MAX).unwrap();
//! check_inclusion(&membership, root.node_id(), alice.node_id(), 0).unwrap();
//! let who = Principal {
//!     issuer: "https://idp.example.com".into(),
//!     subject: "alice".into(),
//!     email: Some("alice@example.com".into()),
//!     org: None,
//!     groups: vec![],
//!     not_after: i64::MAX,
//!     claims: Default::default(),
//! };
//! assert_eq!(authorize(&signed.state, alice.node_id(), Some(&who), &orders), Ok(analyst));
//! // Without a verified identity, the registry refuses (and says why).
//! assert!(authorize(&signed.state, alice.node_id(), None, &orders).is_err());
//! ```

pub mod error;

// membership/ — who is in.
#[path = "membership/identity.rs"]
pub mod identity;
#[path = "membership/invite.rs"]
pub mod invite;
#[path = "membership/membership.rs"]
pub mod membership;
#[path = "membership/policy.rs"]
pub mod policy;

// calls/ — remote CLI calls.
#[path = "calls/audit.rs"]
pub mod audit;
#[path = "calls/call_log.rs"]
pub mod call_log;
#[path = "calls/idp.rs"]
pub mod idp;
#[path = "calls/invoke.rs"]
pub mod invoke;
#[path = "calls/push.rs"]
pub mod push;
#[path = "calls/session.rs"]
pub mod session;

// services/ — the admin-signed state and the service registry.
#[path = "services/access.rs"]
pub mod access;
#[path = "services/registry.rs"]
pub mod registry;
#[path = "services/role.rs"]
pub mod role;
#[path = "services/state.rs"]
pub mod state;
#[path = "services/sync.rs"]
pub mod sync;

mod codec;
#[cfg(test)]
#[path = "calls/idp_vectors.rs"]
mod idp_vectors;

pub use access::{Grant, Refusal, allowed_services, authorize, role_admits};
pub use audit::{
    AuditRecord, CallId, OutputDigest, OutputHasher, PushOutcome, STDIN_HEAD_MAX, StdinCapture,
    stdin_head,
};
pub use call_log::{
    CALL_LOG_CONTEXT, CALL_LOG_V1, ChainBreak, ChainPoint, EntryHash, LogEntry, LogSeq, Retention,
    verify_chain,
};
pub use error::{Error, IdTokenError, Result};
pub use identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
pub use idp::{
    Audience, CLOCK_SKEW_SECS, IdToken, IdentityClaim, Issuer, Jwk, Jwks, OIDC_NONCE_CONTEXT,
    OidcNonce, Principal, verify_claim,
};
pub use invite::{INVITE_V2, Invite};
pub use invoke::{Argv, Invocation, MAX_ARGS, MAX_ARGV_BYTES, MAX_TOOL_NAME, ToolName};
pub use membership::{MEMBERSHIP_V1, Membership};
pub use policy::check_inclusion;
pub use push::{
    INBOX_ALPN, InboxFrame, MAX_BATCH, MAX_INBOX_FRAME, MAX_INBOX_HELLO, MAX_PUSH_BODY,
    MAX_SUBJECT, PushBody, PushId, PushMessage, Subject,
};
pub use registry::{Service, ServiceName};
pub use role::{EmailPattern, MAX_ROLE_NAME, MEMBER_ROLE, Matcher, RoleName};
pub use session::{Chunk, Frame, Hello, HelloAck};
pub use state::{STATE_CONTEXT, STATE_V1, SignedState, State, StateVersion};
pub use sync::{MAX_STATE_FRAME, STATE_ALPN, StateFrame};

/// Crate version, surfaced so the binaries have something concrete to call
/// while the real surface is still being built out.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
