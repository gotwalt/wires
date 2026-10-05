//! The host's one log line per call: an ordinary `tracing` event at `info`
//! in `serve`'s own output, and nothing else (`docs/protocol.md` §5).
//!
//! - **`call finished`**, when an admitted call ends ([`CallTrace::finish`]):
//!   the service, the caller's node, the person's issuer, subject and email,
//!   the role that admitted them, the exit code, `duration_ms`, and
//!   `bytes_out` (the bytes of stdout and stderr sent to the caller).
//! - **`call refused`**, when a caller with a verified identity is refused
//!   after admission ([`refused`]): the same fields that are known by then
//!   (no role, exit, duration or bytes), and the reason it was sent. An
//!   admitted caller with no verified identity is traced at `debug`; a peer
//!   that isn't admitted at all is the transport's throttled trace.
//!
//! No argv, no stdin, nothing signed and no file of its own: an operator who
//! wants a record points a log collector at `serve`'s output.

use std::time::Instant;

use library::{NodeId, Principal, RoleName, ServiceName};

/// One admitted call, from the gate's decision to its exit. See the module
/// docs.
#[derive(Debug)]
pub(crate) struct CallTrace {
    /// The iroh-authenticated caller.
    caller: NodeId,
    /// The person the host verified for this call, if any.
    principal: Option<Principal>,
    /// The service called.
    service: ServiceName,
    /// The policy's role that admitted the caller.
    role: RoleName,
    /// When the gate admitted the call.
    started: Instant,
}

impl CallTrace {
    /// Start timing a call the gate admitted.
    pub(crate) fn start(
        caller: NodeId,
        principal: Option<Principal>,
        service: ServiceName,
        role: RoleName,
    ) -> Self {
        Self {
            caller,
            principal,
            service,
            role,
            started: Instant::now(),
        }
    }

    /// Write the call's `call finished` line: it exited with `exit` after
    /// sending `bytes_out` bytes of stdout and stderr to the caller.
    pub(crate) fn finish(self, exit: i32, bytes_out: u64) {
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (issuer, subject, email) = person(self.principal.as_ref());
        tracing::info!(
            service = %self.service,
            caller = %self.caller.hex(),
            issuer,
            subject,
            email,
            role = %self.role,
            exit,
            duration_ms,
            bytes_out,
            "call finished"
        );
    }
}

/// Write the `call refused` line for an admitted `caller` refused with
/// `reason` (asking for `service`, when it named one). At `info` when the
/// host verified `principal` for it; at `debug` when it has none.
pub(crate) fn refused(
    caller: NodeId,
    principal: Option<&Principal>,
    service: Option<&ServiceName>,
    reason: &str,
) {
    let service = service.map_or("", ServiceName::as_str);
    let Some(principal) = principal else {
        tracing::debug!(
            service = %service,
            caller = %caller.hex(),
            reason,
            "call refused (no verified identity)"
        );
        return;
    };
    let (issuer, subject, email) = person(Some(principal));
    tracing::info!(
        service = %service,
        caller = %caller.hex(),
        issuer,
        subject,
        email,
        reason,
        "call refused"
    );
}

/// The person's issuer, subject and email, each empty when unknown.
fn person(principal: Option<&Principal>) -> (&str, &str, &str) {
    principal.map_or(("", "", ""), |p| {
        (
            p.issuer.as_str(),
            p.subject.as_str(),
            p.email.as_deref().unwrap_or(""),
        )
    })
}

/// Capture what the host traces while a test runs.
#[cfg(test)]
pub(crate) mod capture {
    use std::sync::{Arc, Mutex};

    /// A writer the test subscriber appends every formatted line to.
    #[derive(Clone, Default)]
    pub(crate) struct Lines(Arc<Mutex<Vec<u8>>>);

    impl Lines {
        /// Everything written so far.
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        /// The lines that contain `needle`.
        pub(crate) fn matching(&self, needle: &str) -> Vec<String> {
            self.text()
                .lines()
                .filter(|l| l.contains(needle))
                .map(str::to_string)
                .collect()
        }
    }

    impl std::io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Lines {
        type Writer = Lines;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Trace to the returned [`Lines`] (every level, no colour) on this
    /// thread until the guard drops. A current-thread runtime keeps a
    /// session's tasks on this thread, so their events are captured too.
    pub(crate) fn lines() -> (Lines, tracing::subscriber::DefaultGuard) {
        let lines = Lines::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(lines.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (lines, tracing::subscriber::set_default(subscriber))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;

    fn alice() -> Principal {
        Principal {
            issuer: "https://idp.example".into(),
            subject: "alice-sub".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: vec![],
            not_after: i64::MAX,
        }
    }

    fn node() -> NodeId {
        NodeIdentity::from_seed([3u8; 32]).node_id()
    }

    #[test]
    fn a_finished_call_is_one_info_line_with_its_fields() {
        let (lines, _guard) = capture::lines();
        let trace = CallTrace::start(
            node(),
            Some(alice()),
            ServiceName::new("orders-db").unwrap(),
            RoleName::new("analyst").unwrap(),
        );
        trace.finish(3, 42);
        let found = lines.matching("call finished");
        assert_eq!(found.len(), 1, "{}", lines.text());
        let line = &found[0];
        for field in [
            " INFO ",
            "service=orders-db",
            &format!("caller={}", node().hex()),
            "issuer=\"https://idp.example\"",
            "subject=\"alice-sub\"",
            "email=\"alice@example.com\"",
            "role=analyst",
            "exit=3",
            "duration_ms=",
            "bytes_out=42",
        ] {
            assert!(line.contains(field), "{field} missing from {line}");
        }
    }

    #[test]
    fn an_identified_refusal_is_one_info_line_with_the_reason() {
        let (lines, _guard) = capture::lines();
        refused(
            node(),
            Some(&alice()),
            Some(&ServiceName::new("payroll").unwrap()),
            "you are not in a role that may call payroll",
        );
        let found = lines.matching("call refused");
        assert_eq!(found.len(), 1, "{}", lines.text());
        let line = &found[0];
        for field in [
            " INFO ",
            "service=payroll",
            "subject=\"alice-sub\"",
            "email=\"alice@example.com\"",
            "reason=\"you are not in a role that may call payroll\"",
        ] {
            assert!(line.contains(field), "{field} missing from {line}");
        }
        for absent in ["exit=", "bytes_out=", "role="] {
            assert!(!line.contains(absent), "{absent} in {line}");
        }
    }

    #[test]
    fn a_refusal_without_an_identity_is_only_debug() {
        let (lines, _guard) = capture::lines();
        refused(node(), None, None, "no ID token presented");
        let found = lines.matching("call refused");
        assert_eq!(found.len(), 1, "{}", lines.text());
        assert!(found[0].contains("DEBUG"), "{}", found[0]);
    }
}
