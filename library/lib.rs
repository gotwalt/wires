//! `library`: shared types for the wires session layer.
//!
//! # Layout
//!
//! The source tree is grouped by concern, three folders beside the crate-wide
//! [`error`] (and the private canonical-JSON `codec`):
//!
//! - `membership/` — who is in: identities, memberships (badges), the
//!   accept gate, and the invite token.
//! - `calls/` — remote CLI calls: the session frames, invocations, audit
//!   records and the host's call log, pushes, and IdP identity.
//! - `services/` — the admin-signed policy (card 36): roles, the service
//!   registry, policy evaluation; the items, the signed head and signed
//!   service entries, updates, views, and freshness.
//! - `directory/` — the directory's request and subscription frames.
//!
//! The folders are a filing system, not a namespace: every module is still
//! declared here at the crate root (`library::signed_policy`, `library::session`, …),
//! and the re-exports below are the public surface.
//!
//! - [`identity`] — the Ed25519 [`NodeIdentity`], the [`NodeId`] / [`Signature`]
//!   byte-newtypes, and the [`AlgorithmId`] every signed object carries.
//! - [`membership`] — root-signed, offline-verifiable [`Membership`] proof that a
//!   node belongs to a fabric.
//! - [`policy`] — [`check_inclusion`] and [`check_admitted`]: a node is
//!   admitted by its badge and not being banned.
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
//! - [`access`] — [`authorize`] and [`allowed_services`] over the policy.
//! - [`item`] — the policy's leaves: [`Item`] (role, service, ban, issuer,
//!   settings) and its [`ItemKey`].
//! - [`entry`] — a service's [`SignedEntry`], signed by the root on its own.
//! - [`head`] — the root-signed [`PolicyHead`] / [`SignedPolicyHead`] over
//!   an [`ItemsHash`], and the [`StateVersion`] that orders them.
//! - [`signed_policy`] — the whole [`Policy`] and [`SignedPolicy`], and the
//!   views cut from it.
//! - [`policy_update`] — the [`PolicyUpdate`] that moves a whole policy to a
//!   newer head.
//! - [`view`] — a caller's [`View`] and the [`ViewUpdate`] that moves it.
//! - [`fresh`] — a directory's signed [`Fresh`] timestamp.
//! - [`directory`] — the [`DirectoryRequest`] / [`SubRequest`] frames on
//!   [`DIRECTORY_ALPN`] and [`DIRECTORY_SUB_ALPN`].
//! - [`error`] — the crate [`Error`] and [`Result`].
//!
//! # Example: sign a policy, check a caller
//!
//! Every step is pure; the async/iroh half lives in the `wires` binary.
//!
//! ```
//! use library::{
//!     Audience, Issuer, IssuerConfig, Matcher, Membership, NodeIdentity, Policy, Principal,
//!     RoleName, Service, ServiceName, StateVersion, authorize, check_admitted,
//! };
//!
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let host = NodeIdentity::from_seed([2u8; 32]);
//! let alice = NodeIdentity::from_seed([3u8; 32]);
//!
//! // The admin signs the trusted IdPs, the roles, the service registry
//! // (which hosts run each) and the bans: one versioned policy. No node
//! // list: a node is admitted by its root-signed badge.
//! let analyst = RoleName::new("analyst").unwrap();
//! let orders = ServiceName::new("orders-db").unwrap();
//! let mut s = Policy::new(root.node_id());
//! s.version = StateVersion(1);
//! s.not_after = i64::MAX;
//! s.issuers.insert(
//!     Issuer::new("https://accounts.google.com"),
//!     IssuerConfig { client_id: Audience::new("cli"), audiences: vec![Audience::new("cli")] },
//! );
//! s.roles.insert(
//!     analyst.clone(),
//!     vec![Matcher {
//!         email: Some("*@example.com".parse().unwrap()),
//!         ..Matcher::new("https://accounts.google.com")
//!     }],
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
//! // A host checks the caller's badge (bound to the key iroh authenticated)
//! // and the bans, then the registry, against its verified copy.
//! signed.verify(root.node_id()).unwrap();
//! let policy = signed.to_policy().unwrap();
//! let badge = Membership::mint(&root, alice.node_id(), 0, i64::MAX).unwrap();
//! check_admitted(&badge, root.node_id(), &policy, alice.node_id(), 0).unwrap();
//! let who = Principal {
//!     issuer: "https://accounts.google.com".into(),
//!     subject: "alice".into(),
//!     email: Some("alice@example.com".into()),
//!     org: None,
//!     groups: vec![],
//!     not_after: i64::MAX,
//! };
//! assert_eq!(authorize(&policy, alice.node_id(), Some(&who), &orders), Ok(analyst));
//! // Without a verified identity, the registry refuses (and says why).
//! assert!(authorize(&policy, alice.node_id(), None, &orders).is_err());
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

// services/ — the admin-signed policy: the registry, roles, evaluation, and
// the head, items, signed entries and freshness a directory serves (card 36).
#[path = "services/access.rs"]
pub mod access;
#[path = "services/registry.rs"]
pub mod registry;
#[path = "services/role.rs"]
pub mod role;

#[path = "services/entry.rs"]
pub mod entry;
#[path = "services/fresh.rs"]
pub mod fresh;
#[path = "services/head.rs"]
pub mod head;
#[path = "services/item.rs"]
pub mod item;
#[path = "services/policy_update.rs"]
pub mod policy_update;
#[path = "services/signed_policy.rs"]
pub mod signed_policy;
#[path = "services/view.rs"]
pub mod view;

// directory/ — the directory's protocols.
#[path = "directory/frames.rs"]
pub mod directory;

mod codec;
#[cfg(test)]
#[path = "calls/idp_vectors.rs"]
mod idp_vectors;

pub use access::{Grant, Refusal, allowed_services, authorize, role_admits};
pub use audit::{AuditRecord, CallId, OutputDigest, OutputHasher, PushOutcome, StdinCapture};
pub use call_log::{
    CALL_LOG_CONTEXT, CALL_LOG_V1, ChainBreak, ChainPoint, EntryHash, LogEntry, LogSeq, Retention,
    verify_chain,
};
pub use codec::B64;
pub use directory::{
    DIRECTORY_ALPN, DIRECTORY_SUB_ALPN, DirectoryAnswer, DirectoryRequest, MAX_DIRECTORY_FRAME,
    MAX_SMALL_DIRECTORY_FRAME, PUBLISH_BODY_PREFIX, SubFrame, SubRequest, SubscriptionKind,
};
pub use entry::{ENTRY_CONTEXT, ENTRY_V1, SignedEntry};
pub use error::{Error, IdTokenError, Result};
pub use fresh::{FRESH_CONTEXT, FRESH_V1, Fresh};
pub use head::{
    HeadHash, ITEMS_CONTEXT, ItemsHash, POLICY_HEAD_CONTEXT, POLICY_V3, PolicyHead,
    SignedPolicyHead, StateVersion,
};
pub use identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
pub use idp::{
    Audience, CLOCK_SKEW_SECS, GOOGLE_ISSUER, IdToken, IdentityClaim, Issuer, Jwk, Jwks,
    OIDC_NONCE_CONTEXT, OidcNonce, Principal, verify_claim,
};
pub use invite::{INVITE_MAX_DIRECTORIES, INVITE_V4, Invite, LoginSettings, PublicClientSecret};
pub use invoke::{Argv, Invocation, MAX_ARGS, MAX_ARGV_BYTES};
pub use item::{
    Ban, DEFAULT_BEAT_SECS, DEFAULT_FRESH_SECS, FreshnessMode, IssuerConfig, Item, ItemKey,
    Settings,
};
pub use membership::{MEMBERSHIP_V1, Membership};
pub use policy::{check_admitted, check_inclusion};
pub use policy_update::PolicyUpdate;
pub use push::{
    INBOX_ALPN, InboxFrame, MAX_BATCH, MAX_INBOX_FRAME, MAX_INBOX_HELLO, MAX_PUSH_BODY,
    MAX_SUBJECT, PushBody, PushId, PushMessage, Subject,
};
pub use registry::{MAX_SERVICE_NAME, Service, ServiceName};
pub use role::{EmailPattern, MAX_ROLE_NAME, Matcher, RoleName};
pub use session::{Chunk, Frame, Hello, HelloAck};
pub use signed_policy::{Policy, SignedPolicy};
pub use view::{View, ViewEntry, ViewUpdate};
