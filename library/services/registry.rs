//! The service registry: what callers address by name, who may call it, and
//! which hosts implement it (card 27).
//!
//! A [`Service`] is an entry in the admin-signed [`State`](crate::State):
//! only the admin binds a [`ServiceName`] to a host, which is what closes
//! tool-name squatting. Callers never pick a host; they pick a service, and
//! the caller resolves it to one of [`Service::hosts`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::invoke::ToolName;
use crate::role::RoleName;

/// A service's name: the same rules as [`ToolName`] (ASCII lowercase letter,
/// then lowercase letters, digits, `_` or `-`, at most [`MAX_TOOL_NAME`](crate::MAX_TOOL_NAME)
/// bytes), so it is safe verbatim as an MCP tool name, a CLI word and a log
/// field.
///
/// ```
/// use library::{ServiceName, ToolName};
/// let s = ServiceName::new("orders-db").unwrap();
/// assert_eq!(ToolName::from(s.clone()).as_str(), "orders-db");
/// assert!(ServiceName::new("Orders DB").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// Validate and wrap a service name; [`Error::InvalidServiceName`] if it
    /// breaks the rules in the type docs.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let tool = ToolName::new(name).map_err(|_| Error::InvalidServiceName)?;
        Ok(Self(tool.as_str().to_string()))
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

/// The session's [`Invocation`](crate::Invocation) still names a
/// [`ToolName`]; a service name always is one (same rules).
impl From<ServiceName> for ToolName {
    fn from(s: ServiceName) -> ToolName {
        ToolName::new(s.0).expect("a ServiceName is a valid ToolName")
    }
}

/// And back: a tool name always is a valid service name.
impl From<ToolName> for ServiceName {
    fn from(t: ToolName) -> ServiceName {
        ServiceName(t.as_str().to_string())
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
    /// defined in [`State::roles`](crate::State::roles).
    pub allow: Vec<RoleName>,
    /// The hosts that implement it, in the admin's preference order. Each
    /// must be in [`State::hosts`](crate::State::hosts). Empty: registered
    /// but not served anywhere yet.
    pub hosts: Vec<NodeId>,
    /// Roles whose members may read this service's call records besides the
    /// caller's own (card 26b). Empty: only the host operator and each
    /// caller for their own calls.
    pub readers: Vec<RoleName>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoke::MAX_TOOL_NAME;
    use proptest::prelude::*;

    #[test]
    fn rejects_bad_names() {
        assert!(ServiceName::new("").is_err());
        assert!(ServiceName::new("9lives").is_err());
        assert!(ServiceName::new("a".repeat(MAX_TOOL_NAME + 1)).is_err());
        assert!(serde_json::from_str::<ServiceName>("\"UP\"").is_err());
    }

    #[test]
    fn service_rejects_unknown_fields() {
        let json = r#"{"description":"","allow":[],"hosts":[],"readers":[],"x":1}"#;
        assert!(serde_json::from_str::<Service>(json).is_err());
    }

    proptest! {
        #[test]
        fn service_and_tool_names_agree(s in "[a-z][a-z0-9_-]{0,63}") {
            let svc = ServiceName::new(s.clone()).unwrap();
            let tool = ToolName::from(svc.clone());
            prop_assert_eq!(tool.as_str(), s.as_str());
            prop_assert_eq!(ServiceName::from(ToolName::from(svc.clone())), svc);
        }
    }
}
