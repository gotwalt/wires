//! Locked caller mode: a sandboxed agent's `wires call` can't carry local
//! files to a host on its stdin (card 20).
//!
//! `wires call`'s stdin can carry working-directory files to the host
//! (`wires call t -- x < secrets.txt` passes Claude Code's permission check,
//! `docs/agent-sandbox.md`). The **operator** turns locked mode on, never the
//! agent, with `WIRES_LOCKED=1` in the sandbox's environment (any value except
//! unset, empty, `0`, `false`, `no` or `off` turns it on: fail closed). Then a
//! call whose stdin holds data is refused before dialing, with
//! [`EXIT_LOCKED`]. A terminal, or a stdin that is empty, is fine; the remote
//! side gets EOF. `wires mcp` is not affected: its tools' `stdin` field is
//! text inside the MCP client's request, which `wires mcp` never reads from a
//! file.
//!
//! Nothing else needs locking: a caller's commands take no flag that points
//! them at another key, relay or keystore. Locked mode is only as strong as
//! the agent's inability to set its own environment: `WIRES_LOCKED` itself,
//! and `WIRES_HOME`, `XDG_CONFIG_HOME` and `HOME` (which pick the keystore),
//! are read from it. Run the agent
//! where the operator, not the agent, sets them (`docs/agent-sandbox.md`).

use std::io::IsTerminal;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The environment variable that turns locked mode on.
pub const LOCKED_ENV: &str = "WIRES_LOCKED";

/// Exit code of a `wires call` refused by locked mode (a usage error, like a
/// bad `--jq` filter): nothing was dialed.
pub const EXIT_LOCKED: i32 = 2;

/// How long a locked `wires call` waits for the first byte of a non-terminal
/// stdin before treating it as empty (a harness may hold stdin open without
/// ever writing). Nothing read later is forwarded either way.
const STDIN_PEEK: Duration = Duration::from_millis(300);

/// `wires call`'s stdin held data in locked mode. The message says why and
/// what to do instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StdinRefused;

impl std::fmt::Display for StdinRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stdin is not forwarded in locked mode (set by the operator: {LOCKED_ENV}=1; stdin \
             can carry local files to the host); pass the input as arguments instead"
        )
    }
}

impl std::error::Error for StdinRefused {}

/// Whether locked mode is on, given the raw value of [`LOCKED_ENV`]: `None`
/// and the "off" words (`0`, `false`, `no`, `off`, empty; any case) are
/// off, anything else is on.
pub fn is_locked(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

/// Whether this process runs in locked mode ([`LOCKED_ENV`]).
pub fn detect() -> bool {
    is_locked(std::env::var(LOCKED_ENV).ok().as_deref())
}

/// For a locked `wires call`: `Ok` if the process's stdin is a terminal or
/// holds no data, else [`StdinRefused`].
pub async fn check_process_stdin() -> Result<(), StdinRefused> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    check_stdin(tokio::io::stdin(), STDIN_PEEK).await
}

/// `Ok` if `input` reaches EOF (or an error, or nothing within `wait`)
/// before yielding a byte; [`StdinRefused`] if it yields one.
pub async fn check_stdin<R: AsyncRead + Unpin>(
    mut input: R,
    wait: Duration,
) -> Result<(), StdinRefused> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(wait, input.read(&mut byte)).await {
        Ok(Ok(n)) if n > 0 => Err(StdinRefused),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn off_words_are_off_and_anything_else_is_on() {
        for off in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("No"),
            Some(" off "),
        ] {
            assert!(!is_locked(off), "{off:?}");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            assert!(is_locked(Some(on)), "{on}");
        }
    }

    #[tokio::test]
    async fn stdin_with_data_is_refused_and_empty_or_idle_stdin_is_not() {
        let wait = Duration::from_millis(50);
        assert_eq!(check_stdin(&b""[..], wait).await, Ok(()));
        assert_eq!(check_stdin(&b"x"[..], wait).await, Err(StdinRefused));
        // A writer that holds the pipe open and never writes: not data.
        let (_writer, reader) = tokio::io::duplex(8);
        assert_eq!(check_stdin(reader, wait).await, Ok(()));
    }

    #[test]
    fn the_refusal_names_the_lock_and_the_next_step() {
        let said = StdinRefused.to_string();
        assert!(
            said.contains(LOCKED_ENV) && said.contains("instead"),
            "{said}"
        );
    }

    proptest! {
        /// Any value of `WIRES_LOCKED` that isn't an "off" word locks (every
        /// off word starts with `0`, `f`, `n` or `o`, so none is generated).
        #[test]
        fn unknown_values_fail_closed(v in "[1-9a-eg-mp-zA-EG-MP-Z][a-zA-Z0-9]{0,7}") {
            prop_assert!(is_locked(Some(&v)));
        }
    }
}
