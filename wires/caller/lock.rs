//! Locked caller mode: `wires call` and `wires mcp` can't be steered off the
//! operator's configuration (card 20).
//!
//! A sandboxed agent that may run `wires call` can still pass `wires call`'s
//! own flags (`docs/agent-sandbox.md`): `--tools-file`, `--node-seed-file`,
//! `--membership-file`, `--relay-url`, … would let it point the caller at
//! another tools map or relay, or feed local files in as credentials. Locked
//! mode is turned on by the **operator**, never by the agent:
//!
//! - `WIRES_LOCKED=1` in the sandbox's environment (any value except unset,
//!   empty, `0`, `false`, `no` or `off` turns it on: fail closed), or
//! - `"locked": true` in `$WIRES_HOME/tools.json`. Only that default file is
//!   read for this, never a `--tools-file`.
//!
//! Once on, every [`CredArgs`] flag is refused with an error naming it
//! ([`OVERRIDE_FLAGS`]); the shaping flags (`--jq`, `--head`, `--max-bytes`),
//! the tool name and its arguments are untouched.
//!
//! **stdin.** `wires call`'s stdin can carry working-directory files to the
//! host (`wires call t -- x < secrets.txt` passes Claude Code's permission
//! check), so in locked mode a call whose stdin holds data is refused before
//! dialing, unless the operator also sets `WIRES_LOCKED_STDIN=allow`. A
//! terminal, or a stdin that is empty, is fine; the remote side gets EOF.
//! `wires mcp` is not affected: its tools' `stdin` field is text inside the
//! MCP client's request, which `wires mcp` never reads from a file.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::caller::call::CredArgs;
use crate::caller::tools::{ToolsConfig, resolve_path};

/// The environment variable that turns locked mode on.
pub const LOCKED_ENV: &str = "WIRES_LOCKED";

/// The environment variable that, set to `allow`, lets a locked `wires call`
/// forward its stdin.
pub const LOCKED_STDIN_ENV: &str = "WIRES_LOCKED_STDIN";

/// Exit code of a `wires call` refused by locked mode (a usage error, like a
/// bad `--jq` filter): nothing was dialed.
pub const EXIT_LOCKED: i32 = 2;

/// Every flag locked mode refuses: exactly the long names of [`CredArgs`]
/// (a unit test keeps the two in step, so a new credential flag is refused
/// until someone decides otherwise).
pub const OVERRIDE_FLAGS: &[&str] = &[
    "--tools-file",
    "--node-seed",
    "--node-seed-file",
    "--membership",
    "--membership-file",
    "--inclusion-proof",
    "--inclusion-proof-file",
    "--relay-url",
];

/// How long a locked `wires call` waits for the first byte of a non-terminal
/// stdin before treating it as empty (a harness may hold stdin open without
/// ever writing). Nothing read later is forwarded either way.
const STDIN_PEEK: Duration = Duration::from_millis(300);

/// Whether a locked `wires call` forwards its stdin.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StdinPolicy {
    /// Refuse a call whose stdin holds data (the default).
    Refuse,
    /// Forward stdin as usual (`WIRES_LOCKED_STDIN=allow`).
    Allow,
}

/// The caller's mode: open (every flag works) or locked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lock {
    /// No lock: flags and stdin behave as documented.
    Open,
    /// Locked: override flags are refused; stdin per the policy.
    Locked {
        /// What to do with `wires call`'s stdin.
        stdin: StdinPolicy,
    },
}

/// A flag (or stdin) locked mode refused. The message names it and says how
/// the lock was turned on, so an agent can tell it isn't a typo.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Refused {
    /// An override flag was passed.
    Flag(&'static str),
    /// `wires call`'s stdin held data and the operator didn't allow it.
    Stdin,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Flag(flag) => write!(
                f,
                "{flag} is not allowed in locked mode (set by the operator: {LOCKED_ENV}=1 or \
                 \"locked\" in tools.json); only --jq, --head, --max-bytes, the tool name and \
                 its arguments are"
            ),
            Self::Stdin => write!(
                f,
                "stdin is not forwarded in locked mode (it can carry local files to the host); \
                 pass the input as arguments instead (the operator can set \
                 {LOCKED_STDIN_ENV}=allow)"
            ),
        }
    }
}

impl std::error::Error for Refused {}

impl Lock {
    /// The mode given the raw values of [`LOCKED_ENV`] and
    /// [`LOCKED_STDIN_ENV`] and the default `tools.json`'s `locked` field:
    /// `(None, None, false)` is open; `(Some("1"), None, false)` is locked
    /// and refuses stdin; `(Some("0"), Some("allow"), true)` is locked with
    /// stdin allowed. (`//wires` is a binary, so no doctest runs here; the
    /// unit tests pin these.)
    pub fn from_sources(env_locked: Option<&str>, env_stdin: Option<&str>, config: bool) -> Self {
        let env_on = env_locked.is_some_and(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "no" | "off"
            )
        });
        if !(env_on || config) {
            return Self::Open;
        }
        let stdin = match env_stdin.map(str::trim) {
            Some("allow") => StdinPolicy::Allow,
            _ => StdinPolicy::Refuse,
        };
        Self::Locked { stdin }
    }

    /// The mode of this process: the environment, plus `locked` in
    /// `$WIRES_HOME/tools.json` (never a `--tools-file`). A default file that
    /// can't be parsed is an error, not "open".
    pub fn detect() -> Result<Self> {
        let config = ToolsConfig::load(&resolve_path(None)?)?;
        let env = |k| std::env::var(k).ok();
        Ok(Self::from_sources(
            env(LOCKED_ENV).as_deref(),
            env(LOCKED_STDIN_ENV).as_deref(),
            config.locked,
        ))
    }

    /// Refuse the first override flag set in `creds`, if locked.
    pub fn check(&self, creds: &CredArgs) -> std::result::Result<(), Refused> {
        match self {
            Self::Open => Ok(()),
            Self::Locked { .. } => match overrides(creds).first() {
                Some(flag) => Err(Refused::Flag(flag)),
                None => Ok(()),
            },
        }
    }

    /// Whether `wires call` must check its stdin before dialing.
    pub fn refuses_stdin(&self) -> bool {
        matches!(
            self,
            Self::Locked {
                stdin: StdinPolicy::Refuse
            }
        )
    }
}

/// The override flags set in `creds`, in [`OVERRIDE_FLAGS`] order.
fn overrides(creds: &CredArgs) -> Vec<&'static str> {
    let CredArgs {
        tools_file,
        node_seed,
        node_seed_file,
        membership,
        membership_file,
        inclusion_proof,
        inclusion_proof_file,
        relay_url,
    } = creds;
    let set = [
        tools_file.is_some(),
        node_seed.is_some(),
        node_seed_file.is_some(),
        membership.is_some(),
        membership_file.is_some(),
        inclusion_proof.is_some(),
        inclusion_proof_file.is_some(),
        relay_url.is_some(),
    ];
    OVERRIDE_FLAGS
        .iter()
        .zip(set)
        .filter_map(|(flag, on)| on.then_some(*flag))
        .collect()
}

/// For a locked `wires call` that refuses stdin: `Ok` if the process's stdin
/// is a terminal or holds no data, else [`Refused::Stdin`].
pub async fn check_process_stdin() -> std::result::Result<(), Refused> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    check_stdin(tokio::io::stdin(), STDIN_PEEK).await
}

/// `Ok` if `input` reaches EOF (or an error, or nothing within `wait`)
/// before yielding a byte; [`Refused::Stdin`] if it yields one.
pub async fn check_stdin<R: AsyncRead + Unpin>(
    mut input: R,
    wait: Duration,
) -> std::result::Result<(), Refused> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(wait, input.read(&mut byte)).await {
        Ok(Ok(n)) if n > 0 => Err(Refused::Stdin),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::call::CallArgs;
    use crate::caller::mcp::McpArgs;
    use clap::{Args, CommandFactory, Parser};
    use proptest::prelude::*;

    const LOCKED: Lock = Lock::Locked {
        stdin: StdinPolicy::Refuse,
    };

    #[derive(Parser)]
    struct CallCli {
        #[command(flatten)]
        call: CallArgs,
    }

    #[derive(Parser)]
    struct McpCli {
        #[command(flatten)]
        mcp: McpArgs,
    }

    fn call(argv: &[&str]) -> CallArgs {
        CallCli::try_parse_from(std::iter::once("call").chain(argv.iter().copied()))
            .unwrap()
            .call
    }

    fn mcp(argv: &[&str]) -> McpArgs {
        McpCli::try_parse_from(std::iter::once("mcp").chain(argv.iter().copied()))
            .unwrap()
            .mcp
    }

    #[test]
    fn override_flags_are_exactly_the_credential_flags() {
        let cmd = CredArgs::augment_args(clap::Command::new("x"));
        let mut declared: Vec<String> = cmd
            .get_arguments()
            .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
            .collect();
        declared.sort();
        let mut listed: Vec<String> = OVERRIDE_FLAGS.iter().map(|s| s.to_string()).collect();
        listed.sort();
        assert_eq!(declared, listed);
        // And they are the only flags `call` takes besides shaping.
        let mut call_flags: Vec<String> = CallCli::command()
            .get_arguments()
            .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
            .filter(|l| !OVERRIDE_FLAGS.contains(&l.as_str()))
            .collect();
        call_flags.sort();
        // `--verbose` only names the host that answered: it steers nothing.
        assert_eq!(call_flags, ["--head", "--jq", "--max-bytes", "--verbose"]);
    }

    #[test]
    fn every_override_flag_is_refused_by_name_in_call_and_mcp() {
        for flag in OVERRIDE_FLAGS {
            let a = call(&[flag, "v", "gh", "--", "pr", "list"]);
            let err = LOCKED.check(&a.creds).unwrap_err();
            assert_eq!(err, Refused::Flag(flag));
            assert!(
                err.to_string()
                    .starts_with(&format!("{flag} is not allowed"))
            );
            // After the tool name, too (before its own args begin).
            let a = call(&["gh", flag, "v", "--", "pr"]);
            assert_eq!(LOCKED.check(&a.creds), Err(Refused::Flag(flag)), "{flag}");
            let m = mcp(&[flag, "v"]);
            assert_eq!(LOCKED.check(&m.creds), Err(Refused::Flag(flag)), "{flag}");
            // Unlocked, the same flag is fine.
            assert_eq!(Lock::Open.check(&a.creds), Ok(()));
        }
    }

    #[test]
    fn shaping_flags_tool_and_args_are_accepted_when_locked() {
        let a = call(&[
            "--jq",
            ".[].title",
            "gh",
            "--head",
            "5",
            "--max-bytes",
            "100",
            "--",
            "pr",
            "list",
            "--relay-url",
            "x",
            "--tools-file",
            "y",
        ]);
        assert_eq!(LOCKED.check(&a.creds), Ok(()));
        assert_eq!(a.args[2], "--relay-url", "remote argv, not ours");
        assert_eq!(
            LOCKED.check(&call(&["eacc34e0/db_query", "select 1"]).creds),
            Ok(())
        );
        assert_eq!(LOCKED.check(&mcp(&[]).creds), Ok(()));
    }

    #[test]
    fn lock_sources() {
        use StdinPolicy::*;
        let locked = |stdin| Lock::Locked { stdin };
        for off in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("No"),
            Some(" off "),
        ] {
            assert_eq!(
                Lock::from_sources(off, Some("allow"), false),
                Lock::Open,
                "{off:?}"
            );
            assert_eq!(
                Lock::from_sources(off, None, true),
                locked(Refuse),
                "{off:?}"
            );
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            assert_eq!(Lock::from_sources(Some(on), None, false), locked(Refuse));
        }
        assert_eq!(
            Lock::from_sources(Some("1"), Some("allow"), false),
            locked(Allow)
        );
        assert_eq!(
            Lock::from_sources(Some("1"), Some("yes"), false),
            locked(Refuse)
        );
        assert!(locked(Refuse).refuses_stdin());
        assert!(!locked(Allow).refuses_stdin() && !Lock::Open.refuses_stdin());
    }

    #[tokio::test]
    async fn stdin_with_data_is_refused_and_empty_or_idle_stdin_is_not() {
        let wait = Duration::from_millis(50);
        assert_eq!(check_stdin(&b""[..], wait).await, Ok(()));
        assert_eq!(check_stdin(&b"x"[..], wait).await, Err(Refused::Stdin));
        // A writer that holds the pipe open and never writes: not data.
        let (_writer, reader) = tokio::io::duplex(8);
        assert_eq!(check_stdin(reader, wait).await, Ok(()));
    }

    #[test]
    fn locked_in_tools_json_parses_and_is_omitted_when_false() {
        let c: ToolsConfig = serde_json::from_str(r#"{"locked":true,"tools":[]}"#).unwrap();
        assert!(c.locked);
        let c: ToolsConfig = serde_json::from_str(r#"{"tools":[]}"#).unwrap();
        assert!(!c.locked);
        assert!(!serde_json::to_string(&c).unwrap().contains("locked"));
    }

    proptest! {
        /// Any value of `WIRES_LOCKED` outside the "off" words locks; only
        /// `allow` opens stdin.
        #[test]
        fn unknown_values_fail_closed(v in "[a-zA-Z0-9]{1,8}", s in "[a-z]{0,8}") {
            let off = matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off");
            let lock = Lock::from_sources(Some(&v), Some(&s), false);
            prop_assert_eq!(lock == Lock::Open, off);
            if !off {
                prop_assert_eq!(lock.refuses_stdin(), s != "allow");
            }
        }
    }
}
