//! IdP identity bound to a wires node key, carried as metadata on a channel.
//!
//! A node key says *which machine* is calling; an organization wants to know
//! *which person*. `wires login` closes that gap without a wires-run identity
//! service: it runs an ordinary OIDC authorization-code flow against the
//! user's IdP (Google, Okta, Entra…) with the request `nonce` set to
//! [`OidcNonce::for_node`] of the node's own key. The IdP signs an ID token
//! containing that nonce, so the token itself proves "the holder of node key
//! *K* authenticated as *alice@corp*".
//!
//! The node then publishes an [`IdentityClaim`] — its node id plus the raw ID
//! token — on the channel (see [`ChannelRecord`](crate::ChannelRecord)).
//! Anyone who reads it (a responder deciding whether to run a tool, an
//! observer rendering an audit log) verifies the IdP's signature against the
//! issuer's published keys **themselves** and derives the [`Principal`]. No
//! party has to trust a wires attestor, and two organizations with two IdPs
//! can share one channel — that is the federation story.
//!
//! Verification (JWKS fetch/caching, signature, `iss`/`aud`/`exp`/`nonce`
//! checks) lands with the IdP lane; this module fixes the types it works on.

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// Domain-separation context for [`OidcNonce::for_node`].
pub const OIDC_NONCE_CONTEXT: &str = "wires oidc-nonce v1";

/// A raw OIDC ID token: a compact JWS (`header.payload.signature`), exactly as
/// the IdP issued it. Opaque until verified.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdToken(String);

impl IdToken {
    /// Wrap a compact-JWS string. No validation happens here — an `IdToken`
    /// is untrusted input until verified.
    pub fn new(jws: impl Into<String>) -> Self {
        Self(jws.into())
    }

    /// The compact JWS.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The OIDC `nonce` that binds an ID token to one node key.
///
/// Deterministic in the node id, so a verifier recomputes it from the claim's
/// `node` and compares it to the token's `nonce` claim — a token minted for
/// one key cannot be replayed as another's.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OidcNonce(String);

impl OidcNonce {
    /// The nonce for `node`: base64url (no padding) of
    /// `blake3::derive_key(OIDC_NONCE_CONTEXT, node bytes)`.
    pub fn for_node(node: &NodeId) -> Self {
        let _ = node;
        todo!("IdP lane: derive the nonce per the doc comment")
    }

    /// The nonce string as sent in the authorization request.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who a verified ID token says the node's holder is.
///
/// Only ever produced by verification, never deserialized off the wire as a
/// trusted value — the wire carries the token, and each reader derives this.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Principal {
    /// The token's `iss` (e.g. `https://accounts.google.com`).
    pub issuer: String,
    /// The token's `sub`: the IdP's stable user id.
    pub subject: String,
    /// The `email` claim, when present and `email_verified` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The Google Workspace hosted domain (`hd`) or equivalent org claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Group memberships, when the IdP asserts them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// The token's `exp`, Unix seconds: the claim is stale after this.
    pub not_after: i64,
}

/// "Node *K* is held by the person this ID token names" — published on a
/// channel for every reader to verify independently.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// The node key the token was minted for (its `nonce` must equal
    /// [`OidcNonce::for_node`] of this id).
    pub node: NodeId,
    /// The IdP-signed ID token.
    pub id_token: IdToken,
}
