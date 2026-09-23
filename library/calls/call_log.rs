//! The host's own call log: every [`AuditRecord`] a host writes, signed by the
//! host's node key and hash-linked to the one before it (card 26a).
//!
//! A host appends each record it produces to a local, append-only log. Each
//! [`LogEntry`] carries:
//!
//! - a host-assigned, dense, 0-based [`LogSeq`];
//! - the [`EntryHash`] of the previous entry ([`EntryHash::ZERO`] for seq 0);
//! - the host's [`NodeId`] and the Unix-millisecond time it was logged;
//! - the record itself;
//! - the host's Ed25519 [`Signature`] over all of the above.
//!
//! The signature makes each entry unforgeable by anyone but the host, and the
//! hash link makes the *sequence* tamper-evident: [`verify_chain`] reports a
//! flipped byte ([`ChainBreak::BadSignature`]), a missing entry
//! ([`ChainBreak::Gap`]), a substituted entry ([`ChainBreak::BrokenLink`]) and
//! two different entries for one slot ([`ChainBreak::Fork`]).
//!
//! **What this does not prove.** A host can still withhold or truncate its own
//! history (records are not replicated at write time; see card 22). Rewrites
//! are detectable only against a copy someone already holds — a subscriber's
//! [`ChainPoint`] or an OTel export — which is why [`verify_chain`] takes the
//! reader's last known point.
//!
//! Retention ([`Retention`]) prunes whole entries from the front, so a pruned
//! log starts at some `seq > 0` whose `prev` can't be checked; a reader that
//! held the earlier point still can.
//!
//! ```
//! use library::{
//!     verify_chain, AuditRecord, ChainBreak, LogEntry, NodeIdentity,
//! };
//!
//! let host = NodeIdentity::from_seed([7u8; 32]);
//! let denied = |at_ms| AuditRecord::Denied {
//!     caller: NodeIdentity::from_seed([8u8; 32]).node_id(),
//!     tool: None,
//!     reason: "not a member".into(),
//!     at_ms,
//! };
//!
//! let first = LogEntry::next(&host, None, 10, denied(10)).unwrap();
//! let second = LogEntry::next(&host, Some(first.point().unwrap()), 20, denied(20)).unwrap();
//! let tip = verify_chain(host.node_id(), None, &[first.clone(), second.clone()]).unwrap();
//! assert_eq!(tip, Some(second.point().unwrap()));
//!
//! // Drop the first entry and hand a reader that held it only the second:
//! // fine. Hand it a log that skips an entry: a gap.
//! let third = LogEntry::next(&host, Some(second.point().unwrap()), 30, denied(30)).unwrap();
//! assert!(matches!(
//!     verify_chain(host.node_id(), None, &[first, third]),
//!     Err(ChainBreak::Gap { .. })
//! ));
//! ```

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::identity::{NodeId, NodeIdentity, Signature};

/// The entry format version, signed into every entry.
pub const CALL_LOG_V1: u8 = 1;

/// Domain separation for the bytes a host signs, so an entry signature can
/// never be replayed as a signature over anything else the node key signs.
pub const CALL_LOG_CONTEXT: &[u8] = b"wires/call-log/v1\0";

/// A host-assigned position in its call log: dense and 0-based.
///
/// ```
/// use library::LogSeq;
/// assert_eq!(LogSeq(4).next(), LogSeq(5));
/// assert_eq!(LogSeq::GENESIS.to_string(), "0");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogSeq(pub u64);

impl LogSeq {
    /// The first entry's sequence number.
    pub const GENESIS: LogSeq = LogSeq(0);

    /// The sequence number after this one.
    pub fn next(self) -> LogSeq {
        LogSeq(self.0 + 1)
    }
}

impl fmt::Display for LogSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// BLAKE3 over an entry's signed bytes and its signature: what the next entry
/// links back to. Lowercase hex on the wire.
///
/// ```
/// use library::EntryHash;
/// let h = EntryHash::from_hex(&"ab".repeat(32)).unwrap();
/// assert_eq!(EntryHash::from_hex(&h.hex()).unwrap(), h);
/// assert!(EntryHash::ZERO.is_zero());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntryHash([u8; 32]);

impl EntryHash {
    /// The `prev` of the genesis entry, and only of it.
    pub const ZERO: EntryHash = EntryHash([0u8; 32]);

    /// Whether this is [`EntryHash::ZERO`].
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Borrow the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::BadKeyLength)?))
    }
}

impl TryFrom<String> for EntryHash {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::from_hex(&s)
    }
}

impl From<EntryHash> for String {
    fn from(h: EntryHash) -> String {
        h.hex()
    }
}

/// A verified position in a host's log: the sequence number and the hash of
/// the entry there. A reader's high-water mark, and the anchor
/// [`verify_chain`] continues from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainPoint {
    /// The entry's sequence number.
    pub seq: LogSeq,
    /// The entry's [`LogEntry::hash`].
    pub hash: EntryHash,
}

/// One signed, hash-linked entry in a host's call log. See the module docs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    /// The entry format version ([`CALL_LOG_V1`]).
    pub v: u8,
    /// The host that wrote (and signed) the entry.
    pub host: NodeId,
    /// The entry's position in the host's log.
    pub seq: LogSeq,
    /// The hash of the entry at `seq - 1` ([`EntryHash::ZERO`] at seq 0).
    pub prev: EntryHash,
    /// Unix milliseconds when the host logged it (what retention ages by).
    pub at_ms: i64,
    /// The call record.
    pub record: AuditRecord,
    /// The host's signature over [`CALL_LOG_CONTEXT`] and the canonical JSON
    /// of every other field.
    pub sig: Signature,
}

/// The signed part of an entry: every field but the signature.
#[derive(Serialize)]
struct SignedBody<'a> {
    v: u8,
    host: &'a NodeId,
    seq: LogSeq,
    prev: &'a EntryHash,
    at_ms: i64,
    record: &'a AuditRecord,
}

/// The exact bytes a host signs for an entry.
fn signing_bytes(
    v: u8,
    host: &NodeId,
    seq: LogSeq,
    prev: &EntryHash,
    at_ms: i64,
    record: &AuditRecord,
) -> Result<Vec<u8>> {
    let body = canonical_bytes(&SignedBody {
        v,
        host,
        seq,
        prev,
        at_ms,
        record,
    })?;
    let mut bytes = CALL_LOG_CONTEXT.to_vec();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

impl LogEntry {
    /// Sign `record` as entry `seq` of `host`'s log, linked to `prev`.
    ///
    /// Prefer [`LogEntry::next`], which derives `seq` and `prev` from the
    /// log's tip.
    pub fn sign(
        host: &NodeIdentity,
        seq: LogSeq,
        prev: EntryHash,
        at_ms: i64,
        record: AuditRecord,
    ) -> Result<Self> {
        let id = host.node_id();
        let bytes = signing_bytes(CALL_LOG_V1, &id, seq, &prev, at_ms, &record)?;
        Ok(Self {
            v: CALL_LOG_V1,
            host: id,
            seq,
            prev,
            at_ms,
            record,
            sig: host.sign(&bytes),
        })
    }

    /// The entry after `tip` (the genesis entry when `tip` is `None`).
    pub fn next(
        host: &NodeIdentity,
        tip: Option<ChainPoint>,
        at_ms: i64,
        record: AuditRecord,
    ) -> Result<Self> {
        let (seq, prev) = match tip {
            Some(t) => (t.seq.next(), t.hash),
            None => (LogSeq::GENESIS, EntryHash::ZERO),
        };
        Self::sign(host, seq, prev, at_ms, record)
    }

    /// Check the version and the signature against [`LogEntry::host`].
    pub fn verify(&self) -> Result<()> {
        if self.v != CALL_LOG_V1 {
            return Err(Error::UnsupportedVersion);
        }
        self.host.verify(&self.signing_bytes()?, &self.sig)
    }

    /// The bytes [`LogEntry::sig`] covers.
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(
            self.v,
            &self.host,
            self.seq,
            &self.prev,
            self.at_ms,
            &self.record,
        )
    }

    /// BLAKE3 over the signed bytes and the signature: the link the next
    /// entry carries as its `prev`.
    pub fn hash(&self) -> Result<EntryHash> {
        let mut h = blake3::Hasher::new();
        h.update(&self.signing_bytes()?);
        h.update(self.sig.as_bytes());
        Ok(EntryHash(*h.finalize().as_bytes()))
    }

    /// This entry as a [`ChainPoint`].
    pub fn point(&self) -> Result<ChainPoint> {
        Ok(ChainPoint {
            seq: self.seq,
            hash: self.hash()?,
        })
    }
}

/// Why [`verify_chain`] rejected a log. Every variant names the `seq` of the
/// offending entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ChainBreak {
    /// The entry was written by a different host than the one being checked.
    #[error("entry {seq} was written by another host")]
    WrongHost {
        /// The entry's sequence number.
        seq: LogSeq,
    },
    /// The entry's signature doesn't verify, or its version is unknown: it
    /// was altered after signing (or never signed by this host).
    #[error("entry {seq} does not verify (tampered or foreign)")]
    BadSignature {
        /// The entry's sequence number.
        seq: LogSeq,
    },
    /// The entry could not be re-encoded to check it.
    #[error("entry {seq} is malformed")]
    Malformed {
        /// The entry's sequence number.
        seq: LogSeq,
    },
    /// A seq-0 entry whose `prev` isn't [`EntryHash::ZERO`].
    #[error("entry 0 does not start a chain")]
    BadGenesis {
        /// Always [`LogSeq::GENESIS`].
        seq: LogSeq,
    },
    /// The sequence jumped: entries after `after` and before `seq` are
    /// missing.
    #[error("gap: entries after {after} and before {seq} are missing")]
    Gap {
        /// The last entry held.
        after: LogSeq,
        /// The entry that arrived instead of `after + 1`.
        seq: LogSeq,
    },
    /// The entry's `prev` doesn't match the hash of the entry before it:
    /// the predecessor was substituted, or this entry belongs to another
    /// history.
    #[error("entry {seq} does not link to the entry before it")]
    BrokenLink {
        /// The entry's sequence number.
        seq: LogSeq,
    },
    /// Two different entries claim the same slot.
    #[error("fork: two different entries at {seq}")]
    Fork {
        /// The contested sequence number.
        seq: LogSeq,
    },
    /// An entry for a slot before the anchor that this check has no hash
    /// for, so it can't be told apart from a fork.
    #[error("entry {seq} is out of order")]
    OutOfOrder {
        /// The entry's sequence number.
        seq: LogSeq,
    },
}

/// Verify `entries` as a contiguous run of `host`'s log, continuing from
/// `after` (the last point the reader already verified), and return the new
/// tip (`after` itself when `entries` is empty).
///
/// Each entry must be `host`'s, carry a valid signature, and link to its
/// predecessor. With no `after`, a seq-0 first entry must be a genesis
/// (`prev` zero) and a later first entry — the front of a pruned log — is
/// accepted as the start. An exact repeat of an entry already verified in
/// this run (or of `after`) is skipped, so overlapping batches are fine; a
/// *different* entry for a verified slot is a [`ChainBreak::Fork`].
///
/// ```
/// use library::{verify_chain, AuditRecord, ChainBreak, LogEntry, LogSeq, NodeIdentity};
///
/// let host = NodeIdentity::from_seed([1u8; 32]);
/// let rec = |r: &str| AuditRecord::Denied {
///     caller: host.node_id(), tool: None, reason: r.into(), at_ms: 0,
/// };
/// let a = LogEntry::next(&host, None, 0, rec("a")).unwrap();
/// let b = LogEntry::next(&host, Some(a.point().unwrap()), 0, rec("b")).unwrap();
/// // Another b for the same slot, signed by the same key: a fork.
/// let b2 = LogEntry::next(&host, Some(a.point().unwrap()), 0, rec("b'")).unwrap();
/// assert_eq!(
///     verify_chain(host.node_id(), None, &[a, b, b2]),
///     Err(ChainBreak::Fork { seq: LogSeq(1) })
/// );
/// ```
pub fn verify_chain(
    host: NodeId,
    after: Option<ChainPoint>,
    entries: &[LogEntry],
) -> std::result::Result<Option<ChainPoint>, ChainBreak> {
    let mut tip = after;
    // Hashes verified in this run, by offset from `first` (dense).
    let mut first: Option<LogSeq> = None;
    let mut seen: Vec<EntryHash> = Vec::new();
    for entry in entries {
        let seq = entry.seq;
        if entry.host != host {
            return Err(ChainBreak::WrongHost { seq });
        }
        if entry.v != CALL_LOG_V1 {
            return Err(ChainBreak::BadSignature { seq });
        }
        let bytes = entry
            .signing_bytes()
            .map_err(|_| ChainBreak::Malformed { seq })?;
        if host.verify(&bytes, &entry.sig).is_err() {
            return Err(ChainBreak::BadSignature { seq });
        }
        let hash = entry.hash().map_err(|_| ChainBreak::Malformed { seq })?;
        match tip {
            None => {
                if seq == LogSeq::GENESIS && !entry.prev.is_zero() {
                    return Err(ChainBreak::BadGenesis { seq });
                }
            }
            Some(t) if seq == t.seq.next() => {
                if entry.prev != t.hash {
                    return Err(ChainBreak::BrokenLink { seq });
                }
            }
            Some(t) if seq > t.seq => {
                return Err(ChainBreak::Gap { after: t.seq, seq });
            }
            Some(t) => {
                // A slot already verified: a repeat, or a fork.
                let held = if seq == t.seq {
                    Some(t.hash)
                } else {
                    first
                        .filter(|f| seq >= *f)
                        .and_then(|f| seen.get((seq.0 - f.0) as usize).copied())
                };
                match held {
                    Some(h) if h == hash => continue,
                    Some(_) => return Err(ChainBreak::Fork { seq }),
                    None => return Err(ChainBreak::OutOfOrder { seq }),
                }
            }
        }
        first.get_or_insert(seq);
        seen.push(hash);
        tip = Some(ChainPoint { seq, hash });
    }
    Ok(tip)
}

/// How long a host keeps log entries. Default: 30 days.
///
/// ```
/// use std::time::Duration;
/// use library::Retention;
/// let r = Retention::default();
/// assert_eq!(r.max_age(), Duration::from_secs(30 * 24 * 3600));
/// let day_ms = 24 * 3600 * 1000;
/// assert!(r.keeps(40 * day_ms, 40 * day_ms - 29 * day_ms));
/// assert!(!r.keeps(40 * day_ms, 40 * day_ms - 31 * day_ms));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Retention(Duration);

impl Retention {
    /// The default retention, in days.
    pub const DEFAULT_DAYS: u64 = 30;

    /// Keep entries for `max_age`.
    pub fn new(max_age: Duration) -> Self {
        Self(max_age)
    }

    /// How long entries are kept.
    pub fn max_age(&self) -> Duration {
        self.0
    }

    /// Whether an entry logged at `at_ms` is still kept at `now_ms`.
    pub fn keeps(&self, now_ms: i64, at_ms: i64) -> bool {
        let age = i128::from(now_ms) - i128::from(at_ms);
        age <= self.0.as_millis() as i128
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self(Duration::from_secs(Self::DEFAULT_DAYS * 24 * 3600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{CallId, OutputHasher};
    use crate::invoke::{Argv, ToolName};
    use proptest::prelude::*;

    fn host() -> NodeIdentity {
        NodeIdentity::from_seed([3u8; 32])
    }

    fn caller() -> NodeId {
        NodeIdentity::from_seed([4u8; 32]).node_id()
    }

    fn record(i: u64) -> AuditRecord {
        match i % 3 {
            0 => AuditRecord::Started {
                call: CallId::from_hex(&format!("{i:032x}")).unwrap(),
                caller: caller(),
                principal: None,
                tool: ToolName::new("db_query").unwrap(),
                argv: Argv::new(vec![format!("arg{i}")]).unwrap(),
                roster_version: None,
                role: Some("analyst".into()),
                at_ms: i as i64,
            },
            1 => AuditRecord::Finished {
                call: CallId::from_hex(&format!("{i:032x}")).unwrap(),
                exit: 0,
                duration_ms: i,
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_digest: OutputHasher::new().finish(),
                stdin_bytes: 0,
                stdin_digest: OutputHasher::new().finish(),
                stdin_head: None,
            },
            _ => AuditRecord::Denied {
                caller: caller(),
                tool: None,
                reason: format!("no {i}"),
                at_ms: i as i64,
            },
        }
    }

    fn chain(n: u64) -> Vec<LogEntry> {
        let host = host();
        let mut out: Vec<LogEntry> = Vec::new();
        for i in 0..n {
            let tip = out.last().map(|e| e.point().unwrap());
            out.push(LogEntry::next(&host, tip, 1000 + i as i64, record(i)).unwrap());
        }
        out
    }

    /// Known answer: the signed bytes are the context tag and the canonical
    /// JSON body, byte for byte, so another implementation can reproduce them.
    #[test]
    fn signing_bytes_known_answer() {
        let e = LogEntry::sign(
            &host(),
            LogSeq(2),
            EntryHash::ZERO,
            5,
            AuditRecord::Denied {
                caller: caller(),
                tool: None,
                reason: "r".into(),
                at_ms: 1,
            },
        )
        .unwrap();
        let expected = format!(
            "wires/call-log/v1\0{{\"at_ms\":5,\"host\":\"{h}\",\"prev\":\"{z}\",\"record\":{{\"at_ms\":1,\"caller\":\"{c}\",\"kind\":\"denied\",\"reason\":\"r\"}},\"seq\":2,\"v\":1}}",
            h = host().node_id().hex(),
            z = "0".repeat(64),
            c = caller().hex(),
        );
        assert_eq!(e.signing_bytes().unwrap(), expected.as_bytes());
        e.verify().unwrap();
        // Ed25519 is deterministic: the same entry signs the same way.
        let again = LogEntry::sign(&host(), LogSeq(2), EntryHash::ZERO, 5, e.record.clone());
        assert_eq!(again.unwrap(), e);
    }

    #[test]
    fn genesis_and_linking() {
        let c = chain(3);
        assert_eq!(c[0].seq, LogSeq::GENESIS);
        assert!(c[0].prev.is_zero());
        assert_eq!(c[1].prev, c[0].hash().unwrap());
        assert_eq!(c[2].seq, LogSeq(2));
        assert_eq!(
            verify_chain(host().node_id(), None, &c).unwrap(),
            Some(c[2].point().unwrap())
        );
        assert_eq!(verify_chain(host().node_id(), None, &[]).unwrap(), None);
    }

    #[test]
    fn entry_json_round_trips_and_rejects_unknown_fields() {
        let e = &chain(1)[0];
        let json = serde_json::to_string(e).unwrap();
        let back: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, e);
        back.verify().unwrap();
        let extra = json.replacen('{', r#"{"x":1,"#, 1);
        assert!(serde_json::from_str::<LogEntry>(&extra).is_err());
    }

    #[test]
    fn tampering_is_a_bad_signature() {
        let mut c = chain(3);
        if let AuditRecord::Finished { exit, .. } = &mut c[1].record {
            *exit = 1;
        }
        assert_eq!(
            verify_chain(host().node_id(), None, &c),
            Err(ChainBreak::BadSignature { seq: LogSeq(1) })
        );
    }

    #[test]
    fn another_hosts_entries_are_refused() {
        let c = chain(1);
        let other = NodeIdentity::from_seed([9u8; 32]).node_id();
        assert_eq!(
            verify_chain(other, None, &c),
            Err(ChainBreak::WrongHost { seq: LogSeq(0) })
        );
    }

    #[test]
    fn a_missing_entry_is_a_gap() {
        let c = chain(4);
        let holed = [c[0].clone(), c[1].clone(), c[3].clone()];
        assert_eq!(
            verify_chain(host().node_id(), None, &holed),
            Err(ChainBreak::Gap {
                after: LogSeq(1),
                seq: LogSeq(3)
            })
        );
    }

    #[test]
    fn a_substituted_predecessor_breaks_the_link() {
        let c = chain(3);
        // A validly signed but different entry 1 (the host key re-signing
        // history): entry 2 no longer links to it.
        let forged = LogEntry::next(&host(), Some(c[0].point().unwrap()), 1, record(99)).unwrap();
        let rewritten = [c[0].clone(), forged, c[2].clone()];
        assert_eq!(
            verify_chain(host().node_id(), None, &rewritten),
            Err(ChainBreak::BrokenLink { seq: LogSeq(2) })
        );
    }

    #[test]
    fn a_rewrite_is_a_fork_against_the_readers_anchor() {
        let c = chain(3);
        let anchor = c[1].point().unwrap();
        let forged = LogEntry::next(&host(), Some(c[0].point().unwrap()), 1, record(99)).unwrap();
        assert_eq!(
            verify_chain(host().node_id(), Some(anchor), &[forged]),
            Err(ChainBreak::Fork { seq: LogSeq(1) })
        );
        // The genuine entry again is just a repeat.
        assert_eq!(
            verify_chain(host().node_id(), Some(anchor), &c[1..]).unwrap(),
            Some(c[2].point().unwrap())
        );
        // Something before the anchor this run never saw: out of order.
        assert_eq!(
            verify_chain(host().node_id(), Some(anchor), &c[..1]),
            Err(ChainBreak::OutOfOrder { seq: LogSeq(0) })
        );
    }

    #[test]
    fn a_nonzero_genesis_prev_is_refused() {
        let bad = LogEntry::sign(&host(), LogSeq(0), EntryHash([1u8; 32]), 0, record(0)).unwrap();
        assert_eq!(
            verify_chain(host().node_id(), None, &[bad]),
            Err(ChainBreak::BadGenesis { seq: LogSeq(0) })
        );
    }

    #[test]
    fn a_pruned_log_verifies_from_its_first_entry() {
        let c = chain(5);
        assert_eq!(
            verify_chain(host().node_id(), None, &c[2..]).unwrap(),
            Some(c[4].point().unwrap())
        );
        // And from a reader's anchor, continuing exactly where it left off.
        assert_eq!(
            verify_chain(host().node_id(), Some(c[1].point().unwrap()), &c[2..]).unwrap(),
            Some(c[4].point().unwrap())
        );
    }

    #[test]
    fn an_unknown_version_does_not_verify() {
        let mut e = chain(1).remove(0);
        e.v = 2;
        assert!(e.verify().is_err());
        assert_eq!(
            verify_chain(host().node_id(), None, &[e]),
            Err(ChainBreak::BadSignature { seq: LogSeq(0) })
        );
    }

    #[test]
    fn retention_is_inclusive_and_saturating() {
        let r = Retention::new(Duration::from_millis(10));
        assert!(r.keeps(20, 10));
        assert!(!r.keeps(21, 10));
        assert!(r.keeps(0, 5), "a future entry is kept");
        assert!(!r.keeps(i64::MAX, i64::MIN));
    }

    proptest! {
        /// Any chain verifies; its tip is the last entry.
        #[test]
        fn any_chain_verifies(n in 1u64..24) {
            let c = chain(n);
            prop_assert_eq!(
                verify_chain(host().node_id(), None, &c).unwrap(),
                Some(c.last().unwrap().point().unwrap())
            );
        }

        /// Split anywhere, verified in two batches with the first's tip as the
        /// anchor, a chain gives the same tip — and repeating the anchor is harmless.
        #[test]
        fn batches_compose(n in 2u64..20, cut in 0usize..20, overlap in 0usize..2) {
            let c = chain(n);
            let cut = cut.min(c.len());
            let tip = verify_chain(host().node_id(), None, &c[..cut]).unwrap();
            let from = if tip.is_some() { cut.saturating_sub(overlap) } else { cut };
            let whole = verify_chain(host().node_id(), None, &c).unwrap();
            prop_assert_eq!(verify_chain(host().node_id(), tip, &c[from..]).unwrap(), whole);
        }

        /// Flipping any byte of any entry's serialized form is detected (or
        /// makes it unparseable).
        #[test]
        fn any_flipped_byte_is_detected(n in 1u64..6, which in 0usize..6, pos in any::<usize>(), bit in 0u8..8) {
            let c = chain(n);
            let which = which % c.len();
            let mut json = serde_json::to_vec(&c[which]).unwrap();
            let pos = pos % json.len();
            json[pos] ^= 1 << bit;
            let Ok(tampered) = serde_json::from_slice::<LogEntry>(&json) else {
                return Ok(());
            };
            if tampered == c[which] {
                // e.g. a hex digit's case flipped: same value, not tampering.
                return Ok(());
            }
            let mut c2 = c.clone();
            c2[which] = tampered;
            prop_assert!(verify_chain(host().node_id(), None, &c2).is_err());
        }

        /// Dropping any interior entry is a gap.
        #[test]
        fn any_dropped_entry_is_a_gap(n in 3u64..16, drop in 1usize..15) {
            let mut c = chain(n);
            let drop = 1 + drop % (c.len() - 2);
            c.remove(drop);
            let is_gap = matches!(
                verify_chain(host().node_id(), None, &c),
                Err(ChainBreak::Gap { .. })
            );
            prop_assert!(is_gap);
        }
    }
}
