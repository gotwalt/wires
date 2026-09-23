//! Call records a responder publishes about the CLIs it runs.
//!
//! Every call a `wires serve --audit-topic …` responder handles produces
//! [`AuditRecord`]s on that channel: a [`Started`](AuditRecord::Started) once
//! the caller is authorized, a [`Finished`](AuditRecord::Finished) when the
//! child exits, or a lone [`Denied`](AuditRecord::Denied) when the caller is
//! turned away. The **responder** writes them, stamping the caller id iroh
//! authenticated — not anything the caller claimed — and each record rides a
//! [`TopicEnvelope`](crate::TopicEnvelope) signed by the responder's key and
//! hash-linked to its previous record. So the log can't be forged by the
//! agent, isn't held by a gateway, and any member of the channel can observe
//! it without access to either end of the call.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::Principal;
use crate::invoke::{Argv, ToolName};

/// Correlates a call's [`Started`](AuditRecord::Started) and
/// [`Finished`](AuditRecord::Finished) records. 16 random bytes, hex on the
/// wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CallId([u8; 16]);

impl CallId {
    /// A fresh random call id.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 32 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::BadKeyLength)?))
    }
}

impl TryFrom<String> for CallId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::from_hex(&s)
    }
}

impl From<CallId> for String {
    fn from(c: CallId) -> String {
        c.hex()
    }
}

/// BLAKE3 digest of a call's complete stdout, hex on the wire. Lets an
/// observer check a result someone later presents without the log carrying
/// the output itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OutputDigest([u8; 32]);

impl OutputDigest {
    /// Wrap a finished BLAKE3 hash.
    pub fn from_hash(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// The digest of zero bytes: what an empty stream hashes to, and what a
    /// record written before a digest field existed is read as.
    ///
    /// ```
    /// use library::{OutputDigest, OutputHasher};
    /// assert_eq!(OutputDigest::empty(), OutputHasher::new().finish());
    /// ```
    pub fn empty() -> Self {
        Self::from_hash(blake3::hash(b""))
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for OutputDigest {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::BadKeyLength)?))
    }
}

impl From<OutputDigest> for String {
    fn from(d: OutputDigest) -> String {
        d.hex()
    }
}

/// Streaming BLAKE3 over a call's stdout, finished into an [`OutputDigest`].
///
/// The responder feeds it every chunk the child writes, in order, and keeps
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
/// record quotes in `stdin_head`.
///
/// Enough to show an observer the SQL statement or prompt an agent piped in —
/// the part of a call a skeptic most wants to see — without turning the
/// channel into a copy of every payload. The full input is still pinned by
/// `stdin_digest`.
pub const STDIN_HEAD_MAX: usize = 4096;

/// What a responder records about the stdin a caller sent: every byte hashed
/// and counted, and the first [`STDIN_HEAD_MAX`] bytes kept for quoting.
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

    /// The captured head as text (see [`stdin_head`]); `None` when nothing
    /// was fed.
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
///
/// ```
/// use library::stdin_head;
/// assert_eq!(stdin_head(b""), None);
/// assert_eq!(stdin_head(b"hi").as_deref(), Some("hi"));
/// // "é" is two bytes; a prefix that ends inside it drops the half.
/// assert_eq!(stdin_head(&"é".as_bytes()[..1]).as_deref(), Some(""));
/// ```
pub fn stdin_head(prefix: &[u8]) -> Option<String> {
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

/// One entry in a responder's call log. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditRecord {
    /// The caller passed every gate and the child is being spawned.
    Started {
        /// Pairs this record with its `Finished`.
        call: CallId,
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The caller's IdP identity, when the responder verified one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<Principal>,
        /// The exposed tool that ran.
        tool: ToolName,
        /// The caller-supplied arguments.
        argv: Argv,
        /// The roster version the caller was admitted under, when enforced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        roster_version: Option<u64>,
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
        /// Bytes the caller sent on stdin. `0` in records written before
        /// stdin was recorded.
        #[serde(default)]
        stdin_bytes: u64,
        /// BLAKE3 of the complete stdin (the empty digest when there was
        /// none, or in records written before stdin was recorded).
        #[serde(default = "OutputDigest::empty")]
        stdin_digest: OutputDigest,
        /// The first [`STDIN_HEAD_MAX`] bytes of stdin as text (see
        /// [`stdin_head`]); `None` when stdin was empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin_head: Option<String>,
    },
    /// The caller was refused before anything ran.
    Denied {
        /// The iroh-authenticated caller.
        caller: NodeId,
        /// The tool it asked for, if it got as far as naming one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<ToolName>,
        /// The same reason the caller was sent.
        reason: String,
        /// Unix milliseconds at refusal.
        at_ms: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_hasher_is_the_digest_of_nothing() {
        let h = OutputHasher::new();
        assert_eq!(h.bytes(), 0);
        assert_eq!(h.finish(), OutputDigest::from_hash(blake3::hash(b"")));
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
    fn finished_round_trips_with_and_without_stdin() {
        for record in [finished(None), finished(Some(b"select 1"))] {
            let json = serde_json::to_string(&record).unwrap();
            assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), record);
        }
        let json = serde_json::to_string(&finished(None)).unwrap();
        assert!(
            !json.contains("stdin_head"),
            "an absent head is omitted: {json}"
        );
    }

    /// A record from a responder that predates stdin recording still parses,
    /// and reads as "no stdin".
    #[test]
    fn an_old_finished_record_still_parses() {
        let old = format!(
            r#"{{"kind":"finished","call":"0123456789abcdef0123456789abcdef","exit":0,"duration_ms":8,"stdout_bytes":2,"stderr_bytes":0,"stdout_digest":"{}"}}"#,
            OutputDigest::from_hash(blake3::hash(b"1\n")).hex()
        );
        let parsed: AuditRecord = serde_json::from_str(&old).unwrap();
        assert_eq!(parsed, finished(None));
    }

    #[test]
    fn stdin_head_caps_and_splits_on_a_char_boundary() {
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
