//! How `wires watch` shows a [`ChannelRecord`] to a human.
//!
//! A topic message is text. Most of it is conversation and prints as-is; the
//! rest is machine-written metadata — a responder's call log
//! ([`AuditRecord`]) or a node's IdP claim ([`IdentityClaim`]) — which prints
//! as one compact line each, after the same `HH:MM:SS <sender8>` prefix a chat
//! line gets (the sender of an audit record is the responder that wrote it):
//!
//! ```text
//! ▶ 3fa2 alice@corp (a1b2…) db_query "select count(*) from orders"
//! ■ 3fa2 exit 0 · 41 ms · stdin "select customer, sum(total) …" · 3.1 KiB out · blake3 9c1e…
//! ✗ a1b2… db_query denied: membership rejected: revoked
//! 🪪 identity a1b2c3d4 is alice@corp (verified by https://accounts.google.com)
//! ⇢ 9c1e → alice@corp (a1b2…) [analyst] "build-41" delivered
//! ```
//!
//! A `⇢` is one milestone of a host's push to a caller (card 23): `queued`,
//! `delivered`, `fetched`, `expired`, `dropped` or `denied` (with the
//! reason); the first four hex characters of its id pair the milestones.
//!
//! The first four hex characters of the [`CallId`](library::CallId) pair a
//! `▶` with its `■`. A caller is shown by its verified principal's email when
//! the responder stamped one, else by its short node id. A `■` quotes the
//! head of the call's stdin (whitespace collapsed, cut at
//! [`STDIN_PREVIEW_CHARS`]) when the caller sent any; `--json` carries the
//! full captured head.
//!
//! Every string that came off the wire (arguments, refusal reasons, emails)
//! is escaped before it reaches the terminal: a record is written by a
//! channel member, and a member must not be able to smuggle a newline (a
//! forged second line) or an escape sequence into an observer's screen.
//!
//! An identity claim is shown with the verdict *this reader* reached on it
//! (see [`crate::host::identity`]): the verified principal, `(expired)`, or the
//! precise reason it did not verify.

use library::{AuditRecord, ChannelRecord, IdentityClaim, NodeId, Principal};

use crate::channel::idp_view::describe_identity;
use crate::host::identity::Verdict;

/// How many hex characters of a node id or digest a record line shows.
const SHORT_HEX: usize = 4;

/// How many characters of a call's stdin a `■` line quotes.
pub const STDIN_PREVIEW_CHARS: usize = 80;

/// One human line for `record` (no clock/sender prefix — the caller adds it).
///
/// `identity` is the verdict on an identity claim, when the reader checked
/// it; it is ignored for every other record.
pub fn record_line(record: &ChannelRecord, identity: Option<&Verdict>) -> String {
    match record {
        ChannelRecord::Audit(audit) => audit_line(audit),
        ChannelRecord::Identity(claim) => identity_line(claim, identity),
        ChannelRecord::Rekey(rekey) => rekey_line(rekey),
        ChannelRecord::Host(ann) => host_line(ann),
    }
}

/// One human line for a host announcement (card 15): the tools every member
/// may see, and how many sealed entries it carries. Only what any member can
/// read — who the entries are for, and what they say, is not on the line (a
/// member runs `wires tools` for its own view).
pub fn host_line(ann: &library::HostAnnouncement) -> String {
    let open: Vec<String> = ann
        .open
        .iter()
        .flat_map(|l| l.tools.iter().map(|t| escape(t.name.as_str())))
        .collect();
    let open = if open.is_empty() {
        "none open".to_string()
    } else {
        format!("open: {}", open.join(", "))
    };
    let n = ann.sealed.len();
    format!(
        "📣 announces tools ({open}; {n} sealed entr{})",
        if n == 1 { "y" } else { "ies" }
    )
}

/// What a `📣` line is about: an announcement's content, without what every
/// heartbeat changes anyway (its time, and fresh ciphertext in each sealed
/// entry). Two announcements with the same summary render the same line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSummary {
    /// The open listing: tools, descriptions, dial hints.
    open: Option<library::HostListing>,
    /// How many sealed entries (≈ how many members may use more).
    sealed: usize,
    /// The heartbeat it promises.
    heartbeat_ms: u64,
}

impl HostSummary {
    /// The summary of `ann`.
    pub fn of(ann: &library::HostAnnouncement) -> Self {
        Self {
            open: ann.open.clone(),
            sealed: ann.sealed.len(),
            heartbeat_ms: ann.heartbeat_ms,
        }
    }
}

/// The last [`HostSummary`] a watch showed per host, so an unchanged
/// heartbeat does not print another `📣` line (card 21: an overnight watch
/// was a wall of them).
#[derive(Debug, Default)]
pub struct ShownHosts(std::sync::Mutex<std::collections::BTreeMap<NodeId, HostSummary>>);

impl ShownHosts {
    /// Whether `ann` from `host` says something the last one shown did not
    /// (always, for a host's first). Remembers it either way.
    pub fn is_news(&self, host: NodeId, ann: &library::HostAnnouncement) -> bool {
        let summary = HostSummary::of(ann);
        let mut shown = self.0.lock().unwrap_or_else(|e| e.into_inner());
        shown.insert(host, summary.clone()).as_ref() != Some(&summary)
    }
}

/// One human line for an admin's re-key: the roster version it moves to and
/// how many members' credentials it carries. Only public facts — the sealed
/// keys are not the reader's to show. Whether it verified is not this line's
/// business: the resident node adopts a re-key only after
/// [`Rekey::verify`](library::Rekey::verify), whatever it prints.
pub fn rekey_line(rekey: &library::Rekey) -> String {
    let n = rekey.entries.len();
    format!(
        "🔑 re-key to roster version {} ({n} member{})",
        rekey.head.version.0,
        if n == 1 { "" } else { "s" }
    )
}

/// One human line for a call-log entry.
pub fn audit_line(record: &AuditRecord) -> String {
    match record {
        AuditRecord::Started {
            call,
            caller,
            principal,
            tool,
            argv,
            role,
            ..
        } => {
            let role = role
                .as_deref()
                .map(|r| format!(" [{}]", escape(r)))
                .unwrap_or_default();
            let mut line = format!(
                "▶ {} {}{role} {tool}",
                short_hex(&call.hex()),
                caller_label(*caller, principal.as_ref())
            );
            for arg in argv.as_slice() {
                line.push(' ');
                line.push_str(&quote_arg(arg));
            }
            line
        }
        AuditRecord::Finished {
            call,
            exit,
            duration_ms,
            stdout_bytes,
            stdout_digest,
            stdin_bytes,
            stdin_head,
            ..
        } => {
            let stdin = stdin_head
                .as_deref()
                .map(|head| format!("stdin {} · ", stdin_preview(head, *stdin_bytes)))
                .unwrap_or_default();
            format!(
                "■ {} exit {exit} · {duration_ms} ms · {stdin}{} out · blake3 {}…",
                short_hex(&call.hex()),
                human_bytes(*stdout_bytes),
                short_hex(&stdout_digest.hex())
            )
        }
        AuditRecord::Push {
            id,
            to,
            principal,
            role,
            subject,
            outcome,
            reason,
            body,
            ..
        } => {
            let role = role
                .as_deref()
                .map(|r| format!(" [{}]", escape(r)))
                .unwrap_or_default();
            let mut line = format!(
                "⇢ {} → {}{role} {:?} {}",
                short_hex(&id.hex()),
                caller_label(*to, principal.as_ref()),
                subject.as_str(),
                outcome.as_str()
            );
            if let Some(reason) = reason {
                line.push_str(&format!(": {}", escape(reason)));
            }
            if let Some(body) = body {
                line.push_str(&format!(" · body {}", stdin_preview(body.as_str(), 0)));
            }
            line
        }
        AuditRecord::Denied {
            caller,
            tool,
            reason,
            ..
        } => match tool {
            Some(tool) => format!(
                "✗ {} {tool} denied: {}",
                short_node(*caller),
                escape(reason)
            ),
            None => format!("✗ {} denied: {}", short_node(*caller), escape(reason)),
        },
    }
}

/// One human line for an IdP identity claim, given this reader's verdict on
/// it ([`describe_identity`]), or `(not checked)` when it has none. Every
/// wire-derived string is escaped.
pub fn identity_line(claim: &IdentityClaim, verdict: Option<&Verdict>) -> String {
    match verdict {
        Some(verdict) => format!("🪪 {}", escape(&describe_identity(claim, verdict))),
        None => format!(
            "🪪 {} claims identity (not checked)",
            short_node(claim.node)
        ),
    }
}

/// A caller as a record line names it: `alice@corp (a1b2…)` when the
/// responder verified a principal with an email, else just `a1b2…`.
pub fn caller_label(caller: NodeId, principal: Option<&Principal>) -> String {
    match principal.and_then(|p| p.email.as_deref()) {
        Some(email) => format!("{} ({})", escape(email), short_node(caller)),
        None => short_node(caller),
    }
}

/// The first [`SHORT_HEX`] hex characters of a node id, with an ellipsis.
pub fn short_node(node: NodeId) -> String {
    format!("{}…", short_hex(&node.hex()))
}

/// A byte count for humans: `512 B`, `3.1 KiB`, `2.0 MiB`, `1.5 GiB`.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A call's stdin as a `■` line quotes it: whitespace runs collapsed to one
/// space, at most [`STDIN_PREVIEW_CHARS`] characters, ` …` when anything was
/// left out (by this cut, or because `stdin_bytes` is more than the head
/// holds), and double-quoted with escapes so it stays on one line.
pub fn stdin_preview(head: &str, stdin_bytes: u64) -> String {
    let collapsed = head.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut preview: String = collapsed.chars().take(STDIN_PREVIEW_CHARS).collect();
    if preview.len() < collapsed.len() || stdin_bytes > head.len() as u64 {
        preview.truncate(preview.trim_end().len());
        preview.push_str(" …");
    }
    format!("{preview:?}")
}

/// The leading [`SHORT_HEX`] characters of a hex string.
fn short_hex(hex: &str) -> &str {
    &hex[..SHORT_HEX.min(hex.len())]
}

/// An argument as a shell user would read it: bare when it is a plain word,
/// double-quoted with escapes when it is empty or holds whitespace, quotes,
/// shell metacharacters, or anything non-printable.
fn quote_arg(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | ',' | '+' | '@')
        });
    if plain {
        arg.to_string()
    } else {
        format!("{arg:?}")
    }
}

/// `s` with every control character escaped, so it stays on one line and
/// cannot drive the terminal.
fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let escaped: Vec<char> = if c.is_control() {
                c.escape_default().collect()
            } else {
                vec![c]
            };
            escaped
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::{Argv, CallId, IdToken, NodeIdentity, OutputHasher, ToolName};
    use proptest::prelude::*;

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn call() -> CallId {
        CallId::from_hex("3fa20000000000000000000000000000").unwrap()
    }

    fn principal(email: Option<&str>) -> Principal {
        Principal {
            issuer: "https://accounts.google.com".into(),
            subject: "1234".into(),
            email: email.map(str::to_string),
            org: Some("corp".into()),
            groups: vec![],
            not_after: 0,
            claims: Default::default(),
        }
    }

    /// A push line names the recipient as the host verified it, the role, the
    /// subject and what happened; a reason or a logged body follows, escaped.
    #[test]
    fn a_push_line_says_who_what_and_how_it_went() {
        use library::{PushBody, PushId, PushOutcome, Subject};
        let push = |outcome, reason: Option<&str>, body: Option<&str>| AuditRecord::Push {
            id: PushId::from_hex("9c1e0000000000000000000000000000").unwrap(),
            to: node(2),
            principal: Some(principal(Some("alice@corp"))),
            role: Some("analyst".into()),
            subject: Subject::new("build-41").unwrap(),
            outcome,
            reason: reason.map(str::to_string),
            body: body.map(|b| PushBody::new(b).unwrap()),
            at_ms: 0,
        };
        let to = short_node(node(2));
        assert_eq!(
            audit_line(&push(PushOutcome::Delivered, None, None)),
            format!("⇢ 9c1e → alice@corp ({to}) [analyst] \"build-41\" delivered")
        );
        assert_eq!(
            audit_line(&push(PushOutcome::Denied, Some("not in\nthe roster"), None)),
            format!(
                "⇢ 9c1e → alice@corp ({to}) [analyst] \"build-41\" denied: not in\\nthe roster"
            )
        );
        let with_body = audit_line(&push(PushOutcome::Queued, None, Some("failed:\n test")));
        assert!(
            with_body.ends_with(" queued · body \"failed: test\""),
            "{with_body}"
        );
    }

    /// A host announcement shows only what every member may read.
    #[test]
    fn a_host_line_names_open_tools_and_counts_sealed_entries() {
        use library::{
            HostAnnouncement, HostListing, ListedTool, NodeIdentity, SealedListing, ToolName,
        };
        let host = NodeIdentity::from_seed([1u8; 32]).node_id();
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let secret = HostListing {
            tools: vec![ListedTool {
                name: ToolName::new("db_query").unwrap(),
                description: String::new(),
            }],
            ..HostListing::default()
        };
        let entry = SealedListing::seal(host, 1, &member, &secret).unwrap();
        let ann = HostAnnouncement::new(host, 1, 0, None, vec![entry.clone()]);
        assert_eq!(
            host_line(&ann),
            "📣 announces tools (none open; 1 sealed entry)"
        );
        let open = HostListing {
            tools: vec![ListedTool {
                name: ToolName::new("status").unwrap(),
                description: String::new(),
            }],
            ..HostListing::default()
        };
        let ann = HostAnnouncement::new(host, 1, 0, Some(open), vec![entry.clone(), entry]);
        let line = record_line(&ChannelRecord::Host(ann), None);
        assert_eq!(line, "📣 announces tools (open: status; 2 sealed entries)");
        assert!(!line.contains("db_query"));
    }

    /// A heartbeat that changes nothing a `📣` line shows is not news; a
    /// change in the open tools, the sealed count or the dial hints is.
    #[test]
    fn only_a_changed_announcement_is_news() {
        use library::{HostAnnouncement, HostListing, ListedTool, SealedListing};
        let host = node(1);
        let member = NodeIdentity::from_seed([2u8; 32]).node_id();
        let open = HostListing {
            tools: vec![ListedTool {
                name: ToolName::new("status").unwrap(),
                description: String::new(),
            }],
            ..HostListing::default()
        };
        let entry = |at| SealedListing::seal(host, at, &member, &open).unwrap();
        let ann = |at, sealed: Vec<SealedListing>, open: &HostListing| {
            HostAnnouncement::new(host, at, 600_000, Some(open.clone()), sealed)
        };
        let shown = ShownHosts::default();
        assert!(shown.is_news(host, &ann(1, vec![entry(1)], &open)), "first");
        // A heartbeat: new time, freshly sealed entry, same content.
        assert!(!shown.is_news(host, &ann(2, vec![entry(2)], &open)));
        // Another host's first announcement is news of its own.
        assert!(shown.is_news(node(9), &ann(2, vec![entry(2)], &open)));
        // One entry fewer (a member removed or expired).
        assert!(shown.is_news(host, &ann(3, vec![], &open)));
        assert!(!shown.is_news(host, &ann(4, vec![], &open)));
        // The host moved.
        let moved = HostListing {
            addrs: vec!["127.0.0.1:9".parse().unwrap()],
            ..open.clone()
        };
        assert!(shown.is_news(host, &ann(5, vec![], &moved)));
    }

    #[test]
    fn started_with_a_principal_names_the_email_and_the_node() {
        let caller = node(7);
        let line = audit_line(&AuditRecord::Started {
            call: call(),
            caller,
            principal: Some(principal(Some("alice@corp"))),
            tool: ToolName::new("db_query").unwrap(),
            argv: Argv::new(vec!["select count(*) from orders".into()]).unwrap(),
            roster_version: Some(2),
            role: Some("analyst".into()),
            at_ms: 0,
        });
        assert_eq!(
            line,
            format!(
                "▶ 3fa2 alice@corp ({}…) [analyst] db_query \"select count(*) from orders\"",
                &caller.hex()[..4]
            )
        );
    }

    #[test]
    fn started_without_a_principal_names_the_node() {
        let caller = node(7);
        let line = audit_line(&AuditRecord::Started {
            call: call(),
            caller,
            principal: None,
            tool: ToolName::new("stdio").unwrap(),
            argv: Argv::new(vec!["-n".into(), "".into(), "a b".into()]).unwrap(),
            roster_version: None,
            role: None,
            at_ms: 0,
        });
        assert_eq!(
            line,
            format!("▶ 3fa2 {}… stdio -n \"\" \"a b\"", &caller.hex()[..4])
        );
    }

    #[test]
    fn a_principal_without_an_email_falls_back_to_the_node() {
        assert_eq!(
            caller_label(node(1), Some(&principal(None))),
            short_node(node(1))
        );
    }

    #[test]
    fn finished_line_has_exit_time_size_and_digest() {
        let mut h = OutputHasher::new();
        h.update(&vec![b'x'; 3174]);
        let digest = h.finish();
        let line = audit_line(&AuditRecord::Finished {
            call: call(),
            exit: 0,
            duration_ms: 41,
            stdout_bytes: h.bytes(),
            stderr_bytes: 0,
            stdout_digest: digest,
            stdin_bytes: 0,
            stdin_digest: library::OutputDigest::empty(),
            stdin_head: None,
        });
        assert_eq!(
            line,
            format!(
                "■ 3fa2 exit 0 · 41 ms · 3.1 KiB out · blake3 {}…",
                &digest.hex()[..4]
            )
        );
    }

    #[test]
    fn finished_line_quotes_the_head_of_stdin() {
        let sql = "select customer,\n       sum(total)\n  from orders\n group by customer\n order by 2 desc\n limit 10;\n";
        let mut stdin = library::StdinCapture::new();
        stdin.update(sql.as_bytes());
        let digest = OutputHasher::new().finish();
        let line = audit_line(&AuditRecord::Finished {
            call: call(),
            exit: 0,
            duration_ms: 8,
            stdout_bytes: 92,
            stderr_bytes: 0,
            stdout_digest: digest,
            stdin_bytes: stdin.bytes(),
            stdin_digest: stdin.digest(),
            stdin_head: stdin.head(),
        });
        assert_eq!(
            line,
            format!(
                "■ 3fa2 exit 0 · 8 ms · stdin \"select customer, sum(total) from orders group by customer order by 2 desc limit …\" · 92 B out · blake3 {}…",
                &digest.hex()[..4]
            )
        );
    }

    #[test]
    fn stdin_preview_cuts_long_and_partial_input() {
        let long = "word ".repeat(40);
        let preview = stdin_preview(&long, long.len() as u64);
        assert!(preview.ends_with(" …\""), "{preview}");
        assert!(
            preview.chars().count() <= STDIN_PREVIEW_CHARS + 4,
            "{preview}"
        );
        // A short head, but the call sent more than the head holds.
        assert_eq!(stdin_preview("abc", 10_000), "\"abc …\"");
        assert_eq!(stdin_preview("abc", 3), "\"abc\"");
        // Quotes and control characters are escaped, never raw.
        assert_eq!(stdin_preview("a\"b\u{1b}c", 5), "\"a\\\"b\\u{1b}c\"");
    }

    #[test]
    fn denied_line_with_and_without_a_tool() {
        let caller = node(9);
        let short = format!("{}…", &caller.hex()[..4]);
        let with = audit_line(&AuditRecord::Denied {
            caller,
            tool: Some(ToolName::new("db_query").unwrap()),
            reason: "membership rejected: revoked".into(),
            at_ms: 0,
        });
        assert_eq!(
            with,
            format!("✗ {short} db_query denied: membership rejected: revoked")
        );
        let without = audit_line(&AuditRecord::Denied {
            caller,
            tool: None,
            reason: "roster inclusion rejected".into(),
            at_ms: 0,
        });
        assert_eq!(
            without,
            format!("✗ {short} denied: roster inclusion rejected")
        );
    }

    #[test]
    fn identity_line_shows_the_verdict() {
        use crate::caller::jwks::VerifyError;
        let claim = IdentityClaim {
            node: node(3),
            id_token: IdToken::new("a.b.c"),
        };
        let short8 = &node(3).hex()[..8];
        let record = ChannelRecord::Identity(claim);
        assert_eq!(
            record_line(&record, None),
            format!("🪪 {}… claims identity (not checked)", &node(3).hex()[..4])
        );
        let mut p = principal(Some("alice@corp"));
        p.org = None;
        assert_eq!(
            record_line(&record, Some(&Ok(p.clone()))),
            format!("🪪 identity {short8} is alice@corp (verified by https://accounts.google.com)")
        );
        assert_eq!(
            record_line(&record, Some(&Err(VerifyError::Expired(p)))),
            format!("🪪 identity {short8} is alice@corp (expired)")
        );
        let line = record_line(&record, Some(&Err(VerifyError::Unavailable("down".into()))));
        assert!(
            line.contains("UNVERIFIED: issuer keys unavailable: down"),
            "{line}"
        );
    }

    /// A verified email is still attacker-influenced text (anyone can set up
    /// an IdP account); it cannot break the line.
    #[test]
    fn a_hostile_email_cannot_break_the_identity_line() {
        let claim = IdentityClaim {
            node: node(3),
            id_token: IdToken::new("a.b.c"),
        };
        let line = identity_line(
            &claim,
            Some(&Ok(principal(Some("a@b\n12:00:00 forged\u{1b}[2J")))),
        );
        assert!(!line.chars().any(char::is_control), "{line:?}");
    }

    #[test]
    fn a_hostile_reason_cannot_break_the_line() {
        let line = audit_line(&AuditRecord::Denied {
            caller: node(2),
            tool: None,
            reason: "ok\n12:00:00 deadbeef ▶ forged\u{1b}[2J".into(),
            at_ms: 0,
        });
        assert!(!line.contains('\n'));
        assert!(!line.contains('\u{1b}'));
    }

    #[test]
    fn human_bytes_examples() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(3174), "3.1 KiB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    proptest! {
        #[test]
        fn any_stdin_renders_on_one_line(head in "(?s).{0,120}", extra in 0u64..10) {
            let line = audit_line(&AuditRecord::Finished {
                call: call(),
                exit: 0,
                duration_ms: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_digest: OutputHasher::new().finish(),
                stdin_bytes: head.len() as u64 + extra,
                stdin_digest: OutputHasher::new().finish(),
                stdin_head: Some(head),
            });
            prop_assert!(!line.chars().any(char::is_control), "{line:?}");
        }

        #[test]
        fn any_argv_renders_on_one_line(
            args in proptest::collection::vec("[^\u{0}]{0,12}", 0..6),
            role in proptest::option::of("(?s).{0,12}"),
        ) {
            let line = audit_line(&AuditRecord::Started {
                call: call(),
                caller: node(4),
                principal: None,
                tool: ToolName::new("t").unwrap(),
                argv: Argv::new(args).unwrap(),
                roster_version: None,
                role,
                at_ms: 0,
            });
            prop_assert!(!line.chars().any(char::is_control), "{line:?}");
        }
    }
}
