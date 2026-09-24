//! Push to callers (board card 23): a host sends a message to a caller it
//! verified, addressed by the caller's **key**, not an address.
//!
//! A host queues each [`PushMessage`] per recipient and delivers it one of
//! two ways, both over the inbox ALPN [`INBOX_ALPN`] and both carried in
//! [`InboxFrame`]s:
//!
//! - **direct**: the host dials the recipient's receiver (a running `wires
//!   inbox --wait`) by node id, says [`Hello`](InboxFrame::Hello) with its own
//!   credentials, and sends [`Deliver`](InboxFrame::Deliver); the receiver
//!   stores what it accepts and answers [`Ack`](InboxFrame::Ack).
//! - **fetch**: the recipient dials the host (`wires inbox`, no receiver
//!   needed), says `Hello` and [`Fetch`](InboxFrame::Fetch) —
//!   optionally holding the stream open up to `wait_ms` for a message to
//!   arrive — and the host answers `Deliver` (possibly empty); the recipient
//!   stores and `Ack`s, and only acknowledged messages leave the host's queue.
//!   The recipient's `Hello` carries its IdP ID token, so a host learns a
//!   logged-in recipient's identity (and so its roles) by the fetch alone.
//!
//! Either side may answer [`Denied`](InboxFrame::Denied) with a reason
//! instead.
//!
//! Delivery is **at least once**: a lost `Ack` means the same message comes
//! again, so a receiver de-duplicates by [`PushId`]. The message's `from` is
//! never taken on the sender's word — a receiver checks it equals the
//! iroh-authenticated peer — and its `to` must be the receiver itself.
//!
//! # Wire format
//!
//! Each frame is a 4-byte big-endian length `N`, then `N` bytes of canonical
//! JSON, internally tagged by `type`:
//!
//! ```json
//! {"type":"fetch","wait_ms":25000}
//! {"type":"deliver","messages":[{"id":"…","from":"…","to":"…","subject":"build-41",
//!   "body":"failed: test_orders_total","at_ms":1790150645000,"expires_ms":1790237045000}]}
//! {"type":"ack","ids":["…"]}
//! ```
//!
//! A frame is at most [`MAX_INBOX_FRAME`] bytes and a `Deliver` at most
//! [`MAX_BATCH`] messages, both checked before anything is allocated for the
//! body.
//!
//! ```
//! use library::{InboxFrame, NodeIdentity, PushBody, PushId, PushMessage, Subject};
//!
//! let host = NodeIdentity::from_seed([1u8; 32]).node_id();
//! let alice = NodeIdentity::from_seed([2u8; 32]).node_id();
//! let msg = PushMessage {
//!     id: PushId::generate(),
//!     from: host,
//!     to: alice,
//!     subject: Subject::new("build-41").unwrap(),
//!     body: PushBody::new("failed: test_orders_total").unwrap(),
//!     at_ms: 1_000,
//!     expires_ms: 2_000,
//! };
//! assert!(!msg.is_expired(1_999));
//! assert!(msg.is_expired(2_000));
//!
//! let frame = InboxFrame::Deliver { messages: vec![msg] };
//! let bytes = frame.encode().unwrap();
//! let (back, used) = InboxFrame::decode(&bytes).unwrap().unwrap();
//! assert_eq!(back, frame);
//! assert_eq!(used, bytes.len());
//! // Half a frame is "not yet", never an error.
//! assert!(InboxFrame::decode(&bytes[..bytes.len() / 2]).unwrap().is_none());
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::{canonical_bytes, hex_id, length_prefixed, prefix_len, split_frame};
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::idp::IdToken;
use crate::membership::Membership;

/// The ALPN of the inbox protocol: a host's fetch endpoint and a waiting
/// caller's receiver both speak it.
pub const INBOX_ALPN: &[u8] = b"wires/inbox/2";

/// Longest [`Subject`], in bytes.
pub const MAX_SUBJECT: usize = 128;

/// Largest [`PushBody`], in bytes. A push is a notification ("build 41
/// failed: …"), not a file transfer; what it points at is fetched with a call.
pub const MAX_PUSH_BODY: usize = 16 * 1024;

/// Most messages one [`InboxFrame::Deliver`] carries. A longer queue goes in
/// several frames.
pub const MAX_BATCH: usize = 32;

/// Largest encoded [`InboxFrame`], length prefix excluded: a full batch of
/// full messages with room for JSON escaping (a body of control characters
/// can grow sixfold), and far below "exhaust memory" — the prefix is read
/// before the peer is authorized.
pub const MAX_INBOX_FRAME: usize = 4 * 1024 * 1024;

/// Largest [`InboxFrame::Hello`] or [`InboxFrame::Fetch`] a peer reads
/// before it knows who is asking: a membership and an ID token fit in a few
/// KiB, so a peer that isn't admitted can't make it buffer the
/// [`MAX_INBOX_FRAME`] a delivery may need.
pub const MAX_INBOX_HELLO: usize = 64 * 1024;

hex_id! {
    /// A push message's id: 16 random bytes, hex on the wire. What a receiver
    /// de-duplicates by.
    ///
    /// ```
    /// use library::PushId;
    /// let id = PushId::generate();
    /// assert_eq!(PushId::from_hex(&id.hex()).unwrap(), id);
    /// assert!(PushId::from_hex("abc").is_err());
    /// ```
    #[derive(PartialOrd, Ord)]
    pub struct PushId([u8; 16]);
}

impl PushId {
    /// A fresh random id.
    pub fn generate() -> Self {
        Self(rand::random())
    }
}

/// A push's one-line subject (`build-41`): 1–[`MAX_SUBJECT`] bytes, no
/// control characters, not only whitespace. It is what the host's call log
/// records by default, so it must render on one line.
///
/// ```
/// use library::Subject;
/// assert_eq!(Subject::new("build-41").unwrap().as_str(), "build-41");
/// assert!(Subject::new("").is_err());
/// assert!(Subject::new("two\nlines").is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Subject(String);

impl Subject {
    /// Validate and wrap a subject.
    pub fn new(subject: impl Into<String>) -> Result<Self> {
        let subject = subject.into();
        if subject.trim().is_empty() {
            return Err(Error::InvalidPush("the subject is empty"));
        }
        if subject.len() > MAX_SUBJECT {
            return Err(Error::InvalidPush("the subject is longer than 128 bytes"));
        }
        if subject.chars().any(char::is_control) {
            return Err(Error::InvalidPush("the subject holds a control character"));
        }
        Ok(Self(subject))
    }

    /// The subject as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Subject {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<Subject> for String {
    fn from(s: Subject) -> String {
        s.0
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A push's body: UTF-8 text of at most [`MAX_PUSH_BODY`] bytes (it may be
/// empty, and may span lines). **Untrusted input** to whoever reads it — a
/// receiver shows it after the verified sender, never as instructions.
///
/// ```
/// use library::{PushBody, MAX_PUSH_BODY};
/// assert!(PushBody::new("").is_ok());
/// assert!(PushBody::new("x".repeat(MAX_PUSH_BODY + 1)).is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PushBody(String);

impl PushBody {
    /// Validate and wrap a body.
    pub fn new(body: impl Into<String>) -> Result<Self> {
        let body = body.into();
        if body.len() > MAX_PUSH_BODY {
            return Err(Error::InvalidPush("the body is larger than 16 KiB"));
        }
        Ok(Self(body))
    }

    /// The body as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PushBody {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<PushBody> for String {
    fn from(b: PushBody) -> String {
        b.0
    }
}

/// One message a host pushes to one caller. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PushMessage {
    /// De-duplication key.
    pub id: PushId,
    /// The host that sent it. A receiver refuses a message whose `from` is
    /// not the peer it authenticated.
    pub from: NodeId,
    /// The recipient. A receiver refuses a message addressed to anyone else.
    pub to: NodeId,
    /// One line, recorded in the host's call log.
    pub subject: Subject,
    /// The text; recorded in the call log only when the host opts in.
    pub body: PushBody,
    /// The host's clock when it accepted the push (unix ms).
    pub at_ms: i64,
    /// When the host gives up on it (unix ms).
    pub expires_ms: i64,
}

impl PushMessage {
    /// Whether the message's time-to-live has run out at `now_ms`.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }
}

/// One frame of the inbox protocol. See the module docs for the flows.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboxFrame {
    /// The dialer's opening frame: its fabric membership and, from a
    /// recipient that has logged in, its IdP ID token (nonce-bound to its
    /// node key). The dialer's identity is the key iroh authenticated; these
    /// only prove it is a member, and who it signed in as.
    Hello {
        /// The dialer's membership.
        membership: Membership,
        /// The dialer's ID token, when it holds one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<IdToken>,
    },
    /// Recipient → host, after `Hello`: send me what is queued for me,
    /// waiting up to `wait_ms` for something to arrive when nothing is.
    Fetch {
        /// How long the host may hold the stream open for a first message
        /// (it caps this); `0` answers at once.
        #[serde(default)]
        wait_ms: u64,
    },
    /// Messages, host → recipient (after a recipient's `Fetch`, or after the
    /// host's own `Hello` on a direct delivery). May be empty.
    Deliver {
        /// At most [`MAX_BATCH`].
        messages: Vec<PushMessage>,
    },
    /// The recipient stored these (or already had them): the host may forget
    /// them.
    Ack {
        /// The ids stored.
        ids: Vec<PushId>,
    },
    /// Refused, with the reason; the sender closes after it.
    Denied {
        /// Why.
        reason: String,
    },
}

impl InboxFrame {
    /// Encode as a length-prefixed canonical-JSON frame. Refuses a frame
    /// [`decode`](Self::decode) would refuse.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let body = canonical_bytes(self)?;
        if body.len() > MAX_INBOX_FRAME {
            return Err(Error::InvalidPush("the frame is larger than 4 MiB"));
        }
        length_prefixed(&body)
    }

    /// Decode the first frame in `buf`: `Ok(None)` until a whole frame has
    /// arrived, `Ok(Some((frame, consumed)))` once it has. A length prefix
    /// over [`MAX_INBOX_FRAME`] is refused before the body is looked at, and
    /// so is a `Deliver` of more than [`MAX_BATCH`] messages. Never panics.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        Self::length(buf)?;
        let Some((body, end)) = split_frame(buf) else {
            return Ok(None);
        };
        let frame: Self = serde_json::from_slice(body).map_err(Error::Decode)?;
        frame.check()?;
        Ok(Some((frame, end)))
    }

    /// The body length the prefix at the start of `buf` announces, once
    /// the four prefix bytes are there; an error when it is over
    /// [`MAX_INBOX_FRAME`] (a reader allocates nothing for it).
    pub fn length(buf: &[u8]) -> Result<Option<usize>> {
        let Some(len) = prefix_len(buf) else {
            return Ok(None);
        };
        if len > MAX_INBOX_FRAME {
            return Err(Error::InvalidPush("the frame is larger than 4 MiB"));
        }
        Ok(Some(len))
    }

    /// The limits the types can't say on their own.
    fn check(&self) -> Result<()> {
        match self {
            Self::Deliver { messages } if messages.len() > MAX_BATCH => Err(Error::InvalidPush(
                "a deliver frame carries more than 32 messages",
            )),
            Self::Ack { ids } if ids.len() > MAX_BATCH => {
                Err(Error::InvalidPush("an ack frame carries more than 32 ids"))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use proptest::prelude::*;

    fn node(seed: u8) -> NodeId {
        NodeIdentity::from_seed([seed; 32]).node_id()
    }

    fn message(subject: &str, body: &str) -> PushMessage {
        PushMessage {
            id: PushId::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
            from: node(1),
            to: node(2),
            subject: Subject::new(subject).unwrap(),
            body: PushBody::new(body).unwrap(),
            at_ms: 1_790_150_645_000,
            expires_ms: 1_790_237_045_000,
        }
    }

    /// The wire shape is pinned: a receiver written against the Notes'
    /// example must parse what a host sends.
    #[test]
    fn a_fetch_and_a_deliver_have_the_documented_shape() {
        let fetch = InboxFrame::Fetch { wait_ms: 25_000 }.encode().unwrap();
        assert_eq!(&fetch[4..], br#"{"type":"fetch","wait_ms":25000}"#);
        let deliver = InboxFrame::Deliver {
            messages: vec![message("build-41", "failed")],
        }
        .encode()
        .unwrap();
        let text = std::str::from_utf8(&deliver[4..]).unwrap();
        assert!(text.starts_with(r#"{"messages":[{"at_ms":1790150645000,"body":"failed","expires_ms":1790237045000,"from":""#), "{text}");
        let tail = format!(
            r#""subject":"build-41","to":"{}"}}],"type":"deliver"}}"#,
            node(2).hex()
        );
        assert!(text.ends_with(&tail), "{text}");
        // A fetch without `wait_ms` means "answer now".
        let bare = br#"{"type":"fetch"}"#;
        let mut framed = (bare.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(bare);
        assert_eq!(
            InboxFrame::decode(&framed).unwrap().unwrap().0,
            InboxFrame::Fetch { wait_ms: 0 }
        );
    }

    #[test]
    fn subjects_are_one_bounded_line() {
        assert!(Subject::new("a".repeat(MAX_SUBJECT)).is_ok());
        assert!(Subject::new("a".repeat(MAX_SUBJECT + 1)).is_err());
        for bad in ["", "   ", "a\tb", "a\u{1b}[31m", "a\rb"] {
            assert!(Subject::new(bad).is_err(), "{bad:?}");
        }
        // Enforced on the wire too, not only by the constructor.
        let raw = serde_json::json!({
            "id": "0123456789abcdef0123456789abcdef", "from": node(1), "to": node(2),
            "subject": "two\nlines", "body": "", "at_ms": 0, "expires_ms": 1
        });
        assert!(serde_json::from_value::<PushMessage>(raw).is_err());
    }

    #[test]
    fn an_oversized_prefix_is_refused_before_the_body_arrives() {
        let mut buf = ((MAX_INBOX_FRAME + 1) as u32).to_be_bytes().to_vec();
        buf.push(b'{');
        assert!(InboxFrame::decode(&buf).is_err());
        assert!(InboxFrame::length(&buf[..3]).unwrap().is_none());
    }

    #[test]
    fn a_batch_is_bounded_both_ways() {
        let many = InboxFrame::Deliver {
            messages: vec![message("s", "b"); MAX_BATCH + 1],
        };
        assert!(many.encode().is_err());
        // A peer that builds one by hand is refused at decode.
        let body = canonical_bytes(&many).unwrap();
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        assert!(InboxFrame::decode(&framed).is_err());
        let full = InboxFrame::Deliver {
            messages: vec![message("s", &"x".repeat(MAX_PUSH_BODY)); MAX_BATCH],
        };
        assert!(full.encode().is_ok(), "a full batch of full bodies fits");
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for body in [&b"{}"[..], b"null", b"{\"type\":\"nope\"}", b"\xff\xfe"] {
            let mut framed = (body.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(body);
            assert!(InboxFrame::decode(&framed).is_err(), "{body:?}");
        }
    }

    fn subject() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 _.:-]{1,64}".prop_filter("not blank", |s| !s.trim().is_empty())
    }

    fn frame() -> impl Strategy<Value = InboxFrame> {
        let msg = (
            any::<[u8; 16]>(),
            subject(),
            ".{0,200}",
            any::<i64>(),
            any::<i64>(),
        )
            .prop_map(|(id, subject, body, at_ms, expires_ms)| PushMessage {
                id: PushId(id),
                from: node(1),
                to: node(2),
                subject: Subject::new(subject).unwrap(),
                body: PushBody::new(body).unwrap(),
                at_ms,
                expires_ms,
            });
        prop_oneof![
            any::<u64>().prop_map(|wait_ms| InboxFrame::Fetch { wait_ms }),
            proptest::collection::vec(msg, 0..=MAX_BATCH)
                .prop_map(|messages| InboxFrame::Deliver { messages }),
            proptest::collection::vec(any::<[u8; 16]>(), 0..=MAX_BATCH).prop_map(|ids| {
                InboxFrame::Ack {
                    ids: ids.into_iter().map(PushId).collect(),
                }
            }),
            ".{0,100}".prop_map(|reason| InboxFrame::Denied { reason }),
        ]
    }

    proptest! {
        #[test]
        fn frames_round_trip_and_split_anywhere(f in frame(), cut in any::<usize>()) {
            let bytes = f.encode().unwrap();
            let (back, used) = InboxFrame::decode(&bytes).unwrap().unwrap();
            prop_assert_eq!(&back, &f);
            prop_assert_eq!(used, bytes.len());
            // Any strict prefix is "not yet"; a frame followed by more bytes
            // decodes and says where it ended.
            let cut = cut % bytes.len();
            prop_assert!(InboxFrame::decode(&bytes[..cut]).unwrap().is_none());
            let mut two = bytes.clone();
            two.extend_from_slice(&bytes);
            prop_assert_eq!(InboxFrame::decode(&two).unwrap().unwrap().1, bytes.len());
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = InboxFrame::decode(&data);
        }

        #[test]
        fn push_ids_round_trip(id in any::<[u8; 16]>()) {
            let id = PushId(id);
            prop_assert_eq!(PushId::from_hex(&id.hex()).unwrap(), id);
        }
    }
}
