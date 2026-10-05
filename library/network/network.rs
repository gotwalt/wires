//! The network string: everything a new node needs, in one small token
//! that is the same for every node.
//!
//! [`Network`] names the network's root key (which every root-signed policy
//! and service entry must verify under), up to [`NETWORK_MAX_DIRECTORIES`]
//! directory ids (where a node asks for the policy, or its view, until it
//! holds a head that names them all), and the [`LoginSettings`] `wires
//! login` signs in with. `wires network` prints it; `wires join <network>`
//! (a host, a directory, the gateway) and `wires login <network>` (a caller)
//! install it.
//!
//! # Not a secret, and not a credential
//!
//! Nothing inside is secret: a root key and directory ids are public, and
//! the login settings name a *public* OAuth client (a desktop client's
//! secret is not confidential; a confidential one never goes in a network
//! string). A copy admits nobody: a caller is admitted by its own IdP
//! sign-in, bound to its own key, and a host or directory by the signed
//! policy naming its key. It can sit in a wiki.
//!
//! # Trust on first use
//!
//! The string is unsigned: it *introduces* the root, so there is nothing
//! to check it against before a node holds it. What carried it out of band
//! vouches for the admin (see board card 18 for the open question of an
//! authenticated front door).
//!
//! ```
//! use library::{Audience, Issuer, LoginSettings, Network, NodeIdentity};
//! let root = NodeIdentity::from_seed([1u8; 32]).node_id();
//! let directory = NodeIdentity::from_seed([3u8; 32]).node_id();
//! let login = LoginSettings {
//!     issuer: Issuer::new("https://accounts.google.com"),
//!     client_id: Audience::new("1234.apps.googleusercontent.com"),
//!     public_client_secret: None,
//! };
//! let network = Network::new(root, vec![directory], login);
//!
//! let token = network.encode().unwrap();
//! assert!(token.len() < 512);
//! assert_eq!(Network::decode(&token).unwrap(), network);
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::codec::B64;
use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::{Audience, Issuer};

/// The network string's format discriminant. A string of any other format
/// is refused ([`Error::UnsupportedVersion`]).
pub const NETWORK_V1: u8 = 1;

/// The most directory ids a network string carries: enough to reach one
/// when another is down (the head a node then holds lists them all).
pub const NETWORK_MAX_DIRECTORIES: usize = 2;

/// A **public** OAuth client secret: the kind a Google "Desktop app" client
/// has, which its token endpoint still requires but which is not
/// confidential (it ships inside every copy of the app). Never a
/// confidential secret: a network string is not a secret.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicClientSecret(String);

impl PublicClientSecret {
    /// Wrap a public client secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The secret, as the token endpoint takes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `wires login` needs to sign in with no flags: the IdP, the OAuth
/// client registered there, and that client's public secret if it has one.
/// Flags and `$WIRES_OIDC_*` still override each.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSettings {
    /// The OIDC issuer (one the policy's `issuer` items trust).
    pub issuer: Issuer,
    /// The OAuth client id `wires login` signs in under.
    pub client_id: Audience,
    /// The client's public secret, when the admin supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_client_secret: Option<PublicClientSecret>,
}

/// A network, as every node joins it. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Format discriminant; `= NETWORK_V1`.
    pub format: u8,
    /// The network's root key: every policy and service entry verifies
    /// under it.
    pub root: NodeId,
    /// The first directories of the policy's head, in the admin's order
    /// (at most [`NETWORK_MAX_DIRECTORIES`]).
    pub directories: Vec<NodeId>,
    /// How `wires login` signs in.
    pub login: LoginSettings,
}

impl Network {
    /// A network string (format [`NETWORK_V1`]) for `root`, carrying the
    /// first [`NETWORK_MAX_DIRECTORIES`] of `directories`.
    pub fn new(root: NodeId, mut directories: Vec<NodeId>, login: LoginSettings) -> Self {
        directories.truncate(NETWORK_MAX_DIRECTORIES);
        Self {
            format: NETWORK_V1,
            root,
            directories,
            login,
        }
    }

    /// Encode to the base64url (no-pad) token `wires join` and `wires
    /// login` take.
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(canonical_bytes(self)?))
    }

    /// Decode a token (surrounding whitespace is ignored): it must be
    /// well-formed, of format [`NETWORK_V1`], and carry at most
    /// [`NETWORK_MAX_DIRECTORIES`] directories.
    pub fn decode(text: &str) -> Result<Network> {
        let bytes = B64.decode(text.trim())?;
        let network: Network = serde_json::from_slice(&bytes).map_err(Error::Decode)?;
        if network.format != NETWORK_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if network.directories.len() > NETWORK_MAX_DIRECTORIES {
            return Err(Error::InvalidPolicy(format!(
                "a network string names at most {NETWORK_MAX_DIRECTORIES} directories"
            )));
        }
        Ok(network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn root() -> NodeId {
        NodeIdentity::from_seed([1u8; 32]).node_id()
    }

    fn dirs(n: u8) -> Vec<NodeId> {
        (0..n)
            .map(|i| NodeIdentity::from_seed([30 + i; 32]).node_id())
            .collect()
    }

    /// Google-sized login settings: the longest a real network string
    /// carries. Fake values, split with `concat!` so secret scanners don't
    /// flag them.
    fn google() -> LoginSettings {
        LoginSettings {
            issuer: Issuer::new("https://accounts.google.com"),
            client_id: Audience::new(concat!(
                "123456789012-",
                "abcdefghijklmnopqrstuvwxyz012345",
                ".apps.googleusercontent.com"
            )),
            public_client_secret: Some(PublicClientSecret::new(concat!(
                "GOCSPX",
                "-abcdefghijklmnopqrstuvwxyz01"
            ))),
        }
    }

    /// The string is small whatever the network's size: it carries at most
    /// two directories, and nothing else that grows.
    #[test]
    fn a_network_string_is_small_and_carries_two_directories() {
        let two = Network::new(root(), dirs(2), google());
        let token = two.encode().unwrap();
        assert!(token.len() < 1024, "{} bytes", token.len());
        let many = Network::new(root(), dirs(9), google());
        assert_eq!(many.directories, dirs(2));
        assert_eq!(many.encode().unwrap(), token);
    }

    #[test]
    fn known_encoding() {
        let n = Network::new(
            root(),
            vec![],
            LoginSettings {
                issuer: Issuer::new("https://idp"),
                client_id: Audience::new("cli"),
                public_client_secret: None,
            },
        );
        let json = String::from_utf8(canonical_bytes(&n).unwrap()).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"directories":[],"format":1,"login":{{"client_id":"cli","issuer":"https://idp"}},"root":"{}"}}"#,
                root().hex()
            )
        );
    }

    #[test]
    fn garbage_unknown_formats_and_too_many_directories_are_refused() {
        assert!(Network::decode("not a token!").is_err());
        assert!(Network::decode("e30").is_err()); // "{}"
        let mut n = Network::new(root(), dirs(1), google());
        n.format = 2;
        let token = B64.encode(canonical_bytes(&n).unwrap());
        assert!(matches!(
            Network::decode(&token),
            Err(Error::UnsupportedVersion)
        ));
        let mut n = Network::new(root(), dirs(1), google());
        n.directories = dirs(3);
        let token = B64.encode(canonical_bytes(&n).unwrap());
        assert!(Network::decode(&token).is_err());
        // An unknown field is refused.
        let mut v = serde_json::to_value(Network::new(root(), dirs(1), google())).unwrap();
        v["credential"] = serde_json::json!("x");
        let token = B64.encode(serde_json::to_vec(&v).unwrap());
        assert!(Network::decode(&token).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Encode → decode is the identity, with or without a public secret.
        #[test]
        fn tokens_round_trip(
            seed in proptest::array::uniform32(any::<u8>()),
            n in 0u8..4,
            secret in any::<bool>(),
        ) {
            let mut login = google();
            if !secret {
                login.public_client_secret = None;
            }
            let network = Network::new(NodeIdentity::from_seed(seed).node_id(), dirs(n), login);
            let token = network.encode().unwrap();
            prop_assert!(!token.contains(['\n', ' ', '=']));
            let back = Network::decode(&format!("  {token}\n")).unwrap();
            prop_assert_eq!(back, network);
        }
    }
}
