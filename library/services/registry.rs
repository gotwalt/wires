//! The service registry: what callers address by name, who may call it, and
//! which hosts implement it.
//!
//! A [`Service`] is an entry in the admin-signed [`Policy`](crate::Policy):
//! only the admin binds a [`ServiceName`] to a host, which is what closes
//! tool-name squatting. Callers never pick a host; they pick a service, and
//! the caller resolves it to one of [`Service::hosts`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::role::RoleName;

/// Longest accepted [`ServiceName`], in bytes.
pub const MAX_SERVICE_NAME: usize = 64;

/// A service's name: an ASCII lowercase letter, then lowercase letters,
/// digits, `_` or `-`, at most [`MAX_SERVICE_NAME`] bytes, so it is safe
/// verbatim as an MCP tool name, a CLI word and a log field.
///
/// ```
/// use library::ServiceName;
/// let s = ServiceName::new("orders-db").unwrap();
/// assert_eq!(s.as_str(), "orders-db");
/// assert!(ServiceName::new("Orders DB").is_err());
/// assert!(ServiceName::new("").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// Validate and wrap a service name; [`Error::InvalidServiceName`] if it
    /// breaks the rules in the type docs.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let mut chars = name.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok =
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if first_ok && rest_ok && name.len() <= MAX_SERVICE_NAME {
            Ok(Self(name))
        } else {
            Err(Error::InvalidServiceName)
        }
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<ServiceName> for String {
    fn from(s: ServiceName) -> String {
        s.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One registry entry. Every field is required in the signed encoding (no
/// signed optionals — see `docs/protocol.md` §1); "none" is an empty value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// What the service does, for callers and their agents (may be empty).
    pub description: String,
    /// The roles that may call it, tried in order; the first that admits the
    /// caller is the one recorded. Empty: nobody (default deny). Each must be
    /// defined in [`Policy::roles`](crate::Policy::roles).
    pub allow: Vec<RoleName>,
    /// The hosts that implement it, in the admin's preference order. Each
    /// must be in [`Policy::hosts`](crate::Policy::hosts). Empty: registered
    /// but not served anywhere yet.
    pub hosts: Vec<NodeId>,
    /// Roles whose members may read this service's call records besides the
    /// caller's own. Empty: only the host operator and each
    /// caller for their own calls.
    pub readers: Vec<RoleName>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules() {
        for ok in [
            "a",
            "db_query",
            "rg",
            "psql-ro",
            "x9",
            &"a".repeat(MAX_SERVICE_NAME),
        ] {
            assert!(ServiceName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "9lives",
            "_x",
            "A",
            "db query",
            "db.query",
            &"a".repeat(MAX_SERVICE_NAME + 1),
        ] {
            assert!(ServiceName::new(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<ServiceName>("\"ok\"").is_ok());
        assert!(serde_json::from_str::<ServiceName>("\"UP\"").is_err());
    }

    #[test]
    fn service_rejects_unknown_fields() {
        let json = r#"{"description":"","allow":[],"hosts":[],"readers":[],"x":1}"#;
        assert!(serde_json::from_str::<Service>(json).is_err());
    }
}
