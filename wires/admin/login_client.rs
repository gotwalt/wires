//! The login settings an invite carries (card 37): which IdP and OAuth
//! client a joiner's `wires login` signs in with, so it needs no flags.
//!
//! The issuer and its client id come from the signed policy's `issuer`
//! items. Two things don't, and live in the admin's keystore instead
//! (`login-client.json`, [`LoginClient`]):
//!
//! - **which** trusted issuer invites name, when the policy trusts several:
//!   the one `init` trusted, or the last one `wires issuer set --login`
//!   marked; when that one is no longer trusted, the first the policy lists
//!   (in issuer order);
//! - each issuer's **public** client secret, when the admin gave one
//!   (`--public-client-secret`): a Google "Desktop app" client has one its
//!   token endpoint still requires, and it is not confidential. It stays out
//!   of the signed policy, which every host holds and no host needs it for.
//!   A confidential secret must never be given here: an invite is not a
//!   secret.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use library::{Issuer, LoginSettings, Policy, PublicClientSecret};
use serde::{Deserialize, Serialize};

use super::keystore::{Keystore, write_text_mode};

/// The file under the admin's `$WIRES_HOME`.
pub(crate) const LOGIN_CLIENT_FILE: &str = "login-client.json";

/// `login-client.json`. See the module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginClient {
    /// The issuer invites name (when the policy still trusts it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<Issuer>,
    /// Each issuer's public client secret, where the admin gave one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) public_client_secrets: BTreeMap<Issuer, PublicClientSecret>,
}

impl LoginClient {
    /// Load from `ks` (missing is empty).
    pub(crate) fn load(ks: &Keystore) -> Result<Self> {
        let path = ks.path(LOGIN_CLIENT_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Save to `ks` (`0600`).
    pub(crate) fn save(&self, ks: &Keystore) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        write_text_mode(
            &ks.path(LOGIN_CLIENT_FILE),
            &format!("{text}\n"),
            Some(0o600),
        )
    }

    /// Record `issuer`'s public secret (if given) and, with `login`, make
    /// it the issuer invites name; save.
    pub(crate) fn record(
        ks: &Keystore,
        issuer: &Issuer,
        secret: Option<&str>,
        login: bool,
    ) -> Result<()> {
        let mut me = Self::load(ks)?;
        if let Some(secret) = secret.map(str::trim).filter(|s| !s.is_empty()) {
            me.public_client_secrets
                .insert(issuer.clone(), PublicClientSecret::new(secret));
        }
        if login {
            me.issuer = Some(issuer.clone());
        }
        me.save(ks)
    }

    /// The login settings an invite under `policy` carries: the marked
    /// issuer if the policy still trusts it, else its first trusted issuer;
    /// that issuer's client id; its public secret, if any. `None` when the
    /// policy trusts no issuer.
    pub(crate) fn settings(&self, policy: &Policy) -> Option<LoginSettings> {
        let (issuer, config) = self
            .issuer
            .as_ref()
            .and_then(|i| policy.issuers.get_key_value(i))
            .or_else(|| policy.issuers.iter().next())?;
        Some(LoginSettings {
            issuer: issuer.clone(),
            client_id: config.client_id.clone(),
            public_client_secret: self.public_client_secrets.get(issuer).cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Audience, IssuerConfig, NodeIdentity};

    fn policy(issuers: &[(&str, &str)]) -> Policy {
        let mut p = Policy::new(NodeIdentity::from_seed([1; 32]).node_id());
        for (iss, client) in issuers {
            p.issuers.insert(
                Issuer::new(*iss),
                IssuerConfig {
                    client_id: Audience::new(*client),
                    audiences: vec![Audience::new(*client)],
                },
            );
        }
        p
    }

    #[test]
    fn invites_name_the_marked_issuer_else_the_first() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        let p = policy(&[
            ("https://b.example", "b-client"),
            ("https://a.example", "a-client"),
        ]);
        // Nothing marked: the first in issuer order.
        let s = LoginClient::load(&ks).unwrap().settings(&p).unwrap();
        assert_eq!(s.issuer.as_str(), "https://a.example");
        assert_eq!(s.client_id.as_str(), "a-client");
        assert_eq!(s.public_client_secret, None);
        // Marked, with a public secret.
        LoginClient::record(&ks, &Issuer::new("https://b.example"), Some("pub"), true).unwrap();
        let s = LoginClient::load(&ks).unwrap().settings(&p).unwrap();
        assert_eq!(s.issuer.as_str(), "https://b.example");
        assert_eq!(s.client_id.as_str(), "b-client");
        assert_eq!(s.public_client_secret.unwrap().as_str(), "pub");
        // The marked issuer is no longer trusted: the first again.
        let p = policy(&[("https://a.example", "a-client")]);
        let s = LoginClient::load(&ks).unwrap().settings(&p).unwrap();
        assert_eq!(s.issuer.as_str(), "https://a.example");
        // No issuer at all: no settings.
        assert!(LoginClient::default().settings(&policy(&[])).is_none());
    }
}
