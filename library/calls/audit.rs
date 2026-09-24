//! Call records a host keeps about the services it runs.
//!
//! Every call a `wires serve` host handles produces [`AuditRecord`]s: a
//! [`Started`](AuditRecord::Started) once the caller is authorized, a
//! [`Finished`](AuditRecord::Finished) when the child exits, or a lone
//! [`Denied`](AuditRecord::Denied) when the caller is turned away (plus a
//! [`Push`](AuditRecord::Push) per push milestone). The **host** writes them,
//! stamping the caller id iroh authenticated — not anything the caller
//! claimed — into its own signed, hash-linked [`call_log`](crate::call_log).
//! So the log can't be forged by the agent, isn't held by a gateway, and a
//! reader the registry names can check it without access to either end of
//! the call.

use serde::{Deserialize, Serialize};

use crate::codec::hex_id;
use crate::head::StateVersion;
use crate::identity::NodeId;
use crate::idp::Principal;
use crate::invoke::Argv;
use crate::push::{PushBody, PushId, Subject};
use crate::registry::ServiceName;
use crate::role::RoleName;

hex_id! {
    /// Correlates a call's [`Started`](AuditRecord::Started) and
    /// [`Finished`](AuditRecord::Finished) records. 16 random bytes, hex on
    /// the wire.
    pub struct CallId([u8; 16]);
}

impl CallId {
    /// A fresh random call id.
    pub fn generate() -> Self {
        Self(rand::random())
    }
}

hex_id! {
    /// BLAKE3 digest of a call's complete stdout (or stdin), hex on the wire.
    /// Lets an observer check a result someone later presents without the
    /// log carrying the output itself.
    pub struct OutputDigest([u8; 32]);
}

impl OutputDigest {
    /// Wrap a finished BLAKE3 hash.
    pub fn from_hash(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// The digest of zero bytes.
    ///
    /// ```
    /// use library::{OutputDigest, OutputHasher};
    /// assert_eq!(OutputDigest::empty(), OutputHasher::new().finish());
    /// ```
    pub fn empty() -> Self {
        Self::from_hash(blake3::hash(b""))
    }
}

/// Streaming BLAKE3 over a call's stdout, finished into an [`OutputDigest`].
///
/// The host feeds it every chunk the child writes, in order, and keeps
/// the byte count alongside so a [`Finished`](AuditRecord::Finished) record
/// needs no second pass over output it never buffers.
///
/// ```
/// use library::OutputHasher;
/// let mut chunked = OutputHasher::new();
/// chunked.update(b"hello ");
/// chunked.update(b"world");
/// let mut whole = OutputHasher::new();
/// whole.update(b"hello world");
/// assert_eq!(chunked.bytes(), 11);
/// assert_eq!(chunked.finish(), whole.finish());
/// ```
#[derive(Clone, Debug, Default)]
pub struct OutputHasher {
    /// The running hash.
    hasher: blake3::Hasher,
    /// Bytes fed so far.
    bytes: u64,
}

impl OutputHasher {
    /// An empty hasher (digest of zero bytes).
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next chunk of output.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
    }

    /// Total bytes fed so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The digest of everything fed so far (the hasher stays usable).
    pub fn finish(&self) -> OutputDigest {
        OutputDigest::from_hash(self.hasher.finalize())
    }
}

/// The most bytes of a call's stdin a [`Finished`](AuditRecord::Finished)
/// record quotes in `stdin_head` (4 KiB).
///
/// Enough to show an observer the SQL statement or prompt an agent piped in —
/// the part of a call a skeptic most wants to see — without turning the
/// call log into a copy of every payload. The full input is still pinned by
/// `stdin_digest`.
pub(crate) const STDIN_HEAD_MAX: usize = 4096;

/// What a host records about the stdin a caller sent: every byte hashed
/// and counted, and the first 4 KiB kept for quoting.
///
/// ```
/// use library::{OutputHasher, StdinCapture};
/// let mut stdin = StdinCapture::new();
/// stdin.update(b"select 1;");
/// stdin.update(b"\n");
/// assert_eq!(stdin.bytes(), 10);
/// assert_eq!(stdin.head().as_deref(), Some("select 1;\n"));
/// let mut whole = OutputHasher::new();
/// whole.update(b"select 1;\n");
/// assert_eq!(stdin.digest(), whole.finish());
/// assert_eq!(StdinCapture::new().head(), None);
/// ```
#[derive(Clone, Debug, Default)]
pub struct StdinCapture {
    /// Hash and count of everything fed.
    hasher: OutputHasher,
    /// The first [`STDIN_HEAD_MAX`] bytes fed.
    head: Vec<u8>,
}

impl StdinCapture {
    /// Nothing captured yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next chunk of stdin.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        let room = STDIN_HEAD_MAX.saturating_sub(self.head.len());
        self.head.extend_from_slice(&chunk[..room.min(chunk.len())]);
    }

    /// Total bytes fed.
    pub fn bytes(&self) -> u64 {
        self.hasher.bytes()
    }

    /// BLAKE3 of everything fed.
    pub fn digest(&self) -> OutputDigest {
        self.hasher.finish()
    }

    /// The captured head as quotable text: lossy UTF-8, cut on a char
    /// boundary (a character the 4 KiB cap split is dropped); `None` when
    /// nothing was fed.
    pub fn head(&self) -> Option<String> {
        stdin_head(&self.head)
    }
}

/// The quotable text of a stdin prefix: lossy UTF-8, at most
/// [`STDIN_HEAD_MAX`] bytes, cut on a char boundary; `None` when empty.
///
/// A multi-byte character split by the capture limit is dropped rather than
/// shown as a replacement character, and invalid bytes elsewhere become
/// `U+FFFD` (which can grow the text, so the byte cap is applied after
/// decoding).
fn stdin_head(prefix: &[u8]) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let prefix = &prefix[..prefix.len().min(STDIN_HEAD_MAX)];
    // An incomplete sequence at the very end is a character the cut split.
    let whole = match std::str::from_utf8(prefix) {
        Err(e) if e.error_len().is_none() => &prefix[..e.valid_up_to()],
        _ => prefix,
    };
    let mut text = String::from_utf8_lossy(whole).into_owned();
    if text.len() > STDIN_HEAD_MAX {
        let mut cut = STDIN_HEAD_MAX;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    Some(text)
}

/// One entry in a host's call log. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditRecord {
    /// The caller passed every gate and the child is being spawned.
    Started {
        /// Pairs this record with its `Finished`.
        call: CallId,
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The caller's IdP identity, when the host verified one. Its
        /// issuer and subject name the person whose call this is: what a
        /// reader's "mine" matches (the node is not the boundary).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
        /// The service that ran.
        service: ServiceName,
        /// The caller-supplied arguments.
        argv: Argv,
        /// The policy version the caller was admitted under.
        state_version: StateVersion,
        /// The role in the signed policy that admitted the caller.
        role: RoleName,
        /// Unix milliseconds at authorization.
        at_ms: i64,
    },
    /// The child exited (or was killed when the caller hung up).
    Finished {
        /// Pairs this record with its `Started`.
        call: CallId,
        /// The child's exit code (`-1` if killed by a signal).
        exit: i32,
        /// Wall time from spawn to exit.
        duration_ms: u64,
        /// Bytes the child wrote to stdout.
        stdout_bytes: u64,
        /// Bytes the child wrote to stderr.
        stderr_bytes: u64,
        /// BLAKE3 of the complete stdout.
        stdout_digest: OutputDigest,
        /// Bytes the caller sent on stdin.
        stdin_bytes: u64,
        /// BLAKE3 of the complete stdin (the empty digest when there was
        /// none).
        stdin_digest: OutputDigest,
        /// The first 4 KiB of stdin as text (see [`StdinCapture::head`]);
        /// `None` when stdin was empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin_head: Option<String>,
    },
    /// A push to a caller reached a milestone: queued, delivered,
    /// fetched, expired, dropped or refused. One record per milestone per
    /// message; the subject is recorded, the body only when the host opts in
    /// (`host.json` `"push": {"log_body": true}`).
    Push {
        /// The message; pairs its milestones.
        id: PushId,
        /// The recipient's node.
        to: NodeId,
        /// The recipient's IdP identity the push was admitted for, when the
        /// host verified one: whose push this is (a reader's "mine").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
        /// The `push.allow` role that admitted the recipient.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        /// The message's subject.
        subject: Subject,
        /// What happened.
        outcome: PushOutcome,
        /// Why, for [`PushOutcome::Denied`] and [`PushOutcome::Dropped`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// The body, only when the host logs bodies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<PushBody>,
        /// The call whose per-call push capability sent it (a service
        /// pushing back to its caller); `None` for the host operator's push.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call: Option<CallId>,
        /// Unix milliseconds of the milestone.
        at_ms: i64,
    },
    /// The caller was refused before anything ran.
    Denied {
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The caller's verified IdP identity (issuer and subject, not only
        /// the email), when the host had verified one by the time it
        /// refused: whose refusal this is, which is what a reader's "mine"
        /// matches. `None` for a refusal before any identity was checked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
        /// The service it asked for, if it got as far as naming one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<ServiceName>,
        /// The same reason the caller was sent.
        reason: String,
        /// Unix milliseconds at refusal.
        at_ms: i64,
    },
}

/// What happened to a push, as its [`AuditRecord::Push`] says.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    /// Accepted and held for the recipient (its receiver didn't answer).
    Queued,
    /// Handed to the recipient's resident receiver, which acknowledged it.
    Delivered,
    /// The recipient fetched it (`wires inbox`) and acknowledged it.
    Fetched,
    /// Its time-to-live ran out before the recipient took it.
    Expired,
    /// Pushed out of a full queue by a newer message.
    Dropped,
    /// Refused: the current signed policy bans the recipient, or it holds no
    /// role in `push.allow` (at send, delivery or fetch time).
    Denied,
}

impl PushOutcome {
    /// The word a record line shows (`queued`, `delivered`, …).
    ///
    /// ```
    /// assert_eq!(library::PushOutcome::Fetched.as_str(), "fetched");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Delivered => "delivered",
            Self::Fetched => "fetched",
            Self::Expired => "expired",
            Self::Dropped => "dropped",
            Self::Denied => "denied",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A push record carries the subject, and the body only when set; it
    /// round-trips through JSON either way.
    #[test]
    fn a_push_record_logs_the_subject_and_the_body_only_when_asked() {
        let node = crate::NodeIdentity::from_seed([1u8; 32]).node_id();
        let push = |body: Option<&str>| AuditRecord::Push {
            id: PushId::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
            to: node,
            principal: None,
            role: Some("analyst".into()),
            subject: Subject::new("build-41").unwrap(),
            outcome: PushOutcome::Queued,
            reason: None,
            body: body.map(|b| PushBody::new(b).unwrap()),
            call: None,
            at_ms: 1,
        };
        let without = serde_json::to_string(&push(None)).unwrap();
        assert!(without.contains(r#""kind":"push""#), "{without}");
        assert!(without.contains(r#""outcome":"queued""#), "{without}");
        assert!(!without.contains("body"), "{without}");
        let with = serde_json::to_string(&push(Some("failed"))).unwrap();
        assert!(with.contains(r#""body":"failed""#), "{with}");
        assert!(
            !without.contains("call"),
            "an operator push names no call: {without}"
        );
        let mut by_call = push(None);
        let AuditRecord::Push { call, .. } = &mut by_call else {
            unreachable!()
        };
        let id = CallId::generate();
        *call = Some(id);
        let json = serde_json::to_string(&by_call).unwrap();
        assert!(
            json.contains(&format!(r#""call":"{}""#, id.hex())),
            "{json}"
        );
        for record in [push(None), push(Some("failed")), by_call] {
            let json = serde_json::to_string(&record).unwrap();
            assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), record);
        }
    }

    /// A refusal names the person (issuer and subject), not only the email,
    /// so a reader's "mine" can match it; one before any identity names none.
    #[test]
    fn a_refusal_records_the_principals_issuer_and_subject() {
        let node = crate::NodeIdentity::from_seed([1u8; 32]).node_id();
        let who = Principal {
            issuer: "https://idp.example".into(),
            subject: "sub-alice".into(),
            email: Some("alice@example.com".into()),
            org: None,
            groups: vec![],
            not_after: 9,
        };
        let denied = |principal| AuditRecord::Denied {
            caller: node,
            principal,
            service: None,
            reason: "no".into(),
            at_ms: 1,
        };
        let json = serde_json::to_string(&denied(Some(who.clone()))).unwrap();
        assert!(json.contains(r#""issuer":"https://idp.example""#), "{json}");
        assert!(json.contains(r#""subject":"sub-alice""#), "{json}");
        assert_eq!(
            serde_json::from_str::<AuditRecord>(&json).unwrap(),
            denied(Some(who))
        );
        let anonymous = serde_json::to_string(&denied(None)).unwrap();
        assert!(!anonymous.contains("principal"), "{anonymous}");
    }

    fn finished(stdin: Option<&[u8]>) -> AuditRecord {
        let mut capture = StdinCapture::new();
        if let Some(bytes) = stdin {
            capture.update(bytes);
        }
        AuditRecord::Finished {
            call: CallId::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
            exit: 0,
            duration_ms: 8,
            stdout_bytes: 2,
            stderr_bytes: 0,
            stdout_digest: OutputDigest::from_hash(blake3::hash(b"1\n")),
            stdin_bytes: capture.bytes(),
            stdin_digest: capture.digest(),
            stdin_head: capture.head(),
        }
    }

    #[test]
    fn an_absent_stdin_head_is_omitted() {
        let json = serde_json::to_string(&finished(None)).unwrap();
        assert!(
            !json.contains("stdin_head"),
            "an absent head is omitted: {json}"
        );
        let json = serde_json::to_string(&finished(Some(b"select 1"))).unwrap();
        assert!(json.contains(r#""stdin_head":"select 1""#), "{json}");
    }

    /// `Started` names the service, the state version and the role that
    /// admitted the caller.
    #[test]
    fn started_records_the_service_version_and_role() {
        let node = crate::NodeIdentity::from_seed([1u8; 32]).node_id();
        let started = AuditRecord::Started {
            call: CallId::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
            caller: node,
            principal: None,
            service: ServiceName::new("db_query").unwrap(),
            argv: Argv::default(),
            state_version: StateVersion(7),
            role: RoleName::new("analyst").unwrap(),
            at_ms: 1,
        };
        let json = serde_json::to_string(&started).unwrap();
        for field in [
            r#""service":"db_query""#,
            r#""state_version":7"#,
            r#""role":"analyst""#,
        ] {
            assert!(json.contains(field), "{field} in {json}");
        }
        assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), started);
    }

    #[test]
    fn stdin_head_caps_and_splits_on_a_char_boundary() {
        assert_eq!(stdin_head(b""), None);
        assert_eq!(stdin_head(b"hi").as_deref(), Some("hi"));
        // "é" is two bytes; a prefix that ends inside it drops the half.
        assert_eq!(stdin_head(&"é".as_bytes()[..1]).as_deref(), Some(""));
        let long = "x".repeat(STDIN_HEAD_MAX + 10);
        assert_eq!(stdin_head(long.as_bytes()).unwrap().len(), STDIN_HEAD_MAX);
        // A 3-byte char straddling the cap is dropped, not half-kept.
        let mut s = "a".repeat(STDIN_HEAD_MAX - 1);
        s.push('€');
        let mut capture = StdinCapture::new();
        capture.update(s.as_bytes());
        assert_eq!(capture.head().unwrap(), "a".repeat(STDIN_HEAD_MAX - 1));
        assert_eq!(capture.bytes(), s.len() as u64);
        // Invalid bytes are replaced, and the cap still holds after decoding.
        let bad = vec![0xffu8; STDIN_HEAD_MAX];
        let head = stdin_head(&bad).unwrap();
        assert!(head.len() <= STDIN_HEAD_MAX);
        assert!(head.chars().all(|c| c == '\u{fffd}'));
    }

    proptest! {
        #[test]
        fn stdin_head_is_a_bounded_prefix(
            text in ".{0,1500}",
            chunks in proptest::collection::vec(0usize..600, 0..8),
        ) {
            let bytes = text.as_bytes();
            let mut capture = StdinCapture::new();
            let mut at = 0;
            for size in chunks {
                let end = (at + size).min(bytes.len());
                capture.update(&bytes[at..end]);
                at = end;
            }
            capture.update(&bytes[at..]);
            prop_assert_eq!(capture.bytes(), bytes.len() as u64);
            prop_assert_eq!(capture.digest(), OutputDigest::from_hash(blake3::hash(bytes)));
            match capture.head() {
                None => prop_assert!(text.is_empty()),
                Some(head) => {
                    prop_assert!(head.len() <= STDIN_HEAD_MAX);
                    prop_assert!(text.starts_with(&head), "valid UTF-8 is quoted verbatim");
                    if text.len() <= STDIN_HEAD_MAX {
                        prop_assert_eq!(head, text);
                    } else {
                        prop_assert!(head.len() > STDIN_HEAD_MAX - 4);
                    }
                }
            }
        }

        #[test]
        fn finished_round_trips_for_any_stdin(
            stdin in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..5000)),
        ) {
            let record = finished(stdin.as_deref());
            let json = serde_json::to_string(&record).unwrap();
            prop_assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), record);
        }

        #[test]
        fn chunking_does_not_change_the_digest(
            data in proptest::collection::vec(any::<u8>(), 0..2048),
            cut in 0usize..2048,
        ) {
            let cut = cut.min(data.len());
            let mut h = OutputHasher::new();
            h.update(&data[..cut]);
            h.update(&data[cut..]);
            prop_assert_eq!(h.bytes(), data.len() as u64);
            prop_assert_eq!(h.finish(), OutputDigest::from_hash(blake3::hash(&data)));
        }
    }
}
