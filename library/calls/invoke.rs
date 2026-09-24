//! What a caller asks a host to run.
//!
//! A host implements the services its signed state assigns to it
//! (`host.json`). The caller names one of them with a [`ToolName`] (the
//! service name, under the same rules as a
//! [`ServiceName`](crate::ServiceName)) and supplies the per-call arguments as
//! an [`Argv`]; together they form the [`Invocation`] carried in a
//! [`Frame::Invoke`](crate::Frame::Invoke) sent right after the `Hello`.
//!
//! The host never passes the caller's arguments to a shell: the service's
//! own argv is fixed in `host.json` and the caller's [`Argv`] is *appended*
//! to it, element by element. Both newtypes validate on
//! construction and on deserialization, so a value of either type is always
//! within the limits below.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Longest accepted [`ToolName`], in bytes.
pub const MAX_TOOL_NAME: usize = 64;

/// Most arguments an [`Argv`] may carry.
pub const MAX_ARGS: usize = 256;

/// Largest total size of an [`Argv`] (sum of argument lengths), in bytes.
pub const MAX_ARGV_BYTES: usize = 64 * 1024;

/// The name a responder exposes a CLI under (e.g. `db_query`).
///
/// ASCII lowercase letter first, then lowercase letters, digits, `_` or `-`,
/// at most [`MAX_TOOL_NAME`] bytes — safe to use verbatim as an MCP tool name,
/// a CLI word, and a log field.
///
/// ```
/// use library::ToolName;
/// assert_eq!(ToolName::new("db_query").unwrap().as_str(), "db_query");
/// assert!(ToolName::new("Db Query").is_err());
/// assert!(ToolName::new("").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolName(String);

impl ToolName {
    /// Validate and wrap a tool name; [`Error::InvalidToolName`] if it breaks
    /// the rules in the type docs.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let mut chars = name.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok =
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if first_ok && rest_ok && name.len() <= MAX_TOOL_NAME {
            Ok(Self(name))
        } else {
            Err(Error::InvalidToolName)
        }
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ToolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ToolName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<ToolName> for String {
    fn from(t: ToolName) -> String {
        t.0
    }
}

/// The caller-supplied arguments for one call, appended to the exposed
/// command's fixed argv. Never interpreted by a shell.
///
/// At most [`MAX_ARGS`] arguments totalling [`MAX_ARGV_BYTES`], none
/// containing a NUL byte (which no `execve` argument can carry).
///
/// ```
/// use library::Argv;
/// let argv = Argv::new(vec!["-c".into(), "select 1".into()]).unwrap();
/// assert_eq!(argv.as_slice(), ["-c", "select 1"]);
/// assert!(Argv::new(vec!["a\0b".into()]).is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct Argv(Vec<String>);

impl Argv {
    /// Validate and wrap an argument list; [`Error::InvalidArgv`] if it breaks
    /// the limits in the type docs.
    pub fn new(args: Vec<String>) -> Result<Self> {
        let total: usize = args.iter().map(String::len).sum();
        if args.len() > MAX_ARGS || total > MAX_ARGV_BYTES || args.iter().any(|a| a.contains('\0'))
        {
            return Err(Error::InvalidArgv);
        }
        Ok(Self(args))
    }

    /// The arguments, in order.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl TryFrom<Vec<String>> for Argv {
    type Error = Error;
    fn try_from(v: Vec<String>) -> Result<Self> {
        Self::new(v)
    }
}

impl From<Argv> for Vec<String> {
    fn from(a: Argv) -> Vec<String> {
        a.0
    }
}

/// One call: which exposed tool to run, and with what extra arguments.
///
/// Unsigned by design — it travels inside a session whose peer iroh has
/// already authenticated, and the responder authorizes it against that peer's
/// credentials, never against anything the invocation claims.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Invocation {
    /// The exposed tool to run.
    pub tool: ToolName,
    /// Arguments appended to the tool's fixed argv.
    #[serde(default)]
    pub argv: Argv,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn tool_name_rules() {
        for ok in ["a", "db_query", "rg", "psql-ro", "x9"] {
            assert!(ToolName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "9x",
            "_x",
            "A",
            "db query",
            "db.query",
            &"a".repeat(MAX_TOOL_NAME + 1),
        ] {
            assert!(ToolName::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tool_name_deserialize_validates() {
        assert!(serde_json::from_str::<ToolName>("\"ok\"").is_ok());
        assert!(serde_json::from_str::<ToolName>("\"Not Ok\"").is_err());
    }

    #[test]
    fn argv_limits() {
        assert!(Argv::new(vec!["x".into(); MAX_ARGS]).is_ok());
        assert!(Argv::new(vec!["x".into(); MAX_ARGS + 1]).is_err());
        assert!(Argv::new(vec!["x".repeat(MAX_ARGV_BYTES + 1)]).is_err());
        assert!(serde_json::from_str::<Argv>(r#"["a\u0000"]"#).is_err());
    }

    proptest! {
        #[test]
        fn invocation_json_round_trips(
            tool in "[a-z][a-z0-9_-]{0,20}",
            args in proptest::collection::vec("[^\u{0}]{0,16}", 0..8),
        ) {
            let inv = Invocation { tool: ToolName::new(tool).unwrap(), argv: Argv::new(args).unwrap() };
            let json = serde_json::to_string(&inv).unwrap();
            prop_assert_eq!(serde_json::from_str::<Invocation>(&json).unwrap(), inv);
        }
    }
}
